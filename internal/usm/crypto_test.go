package usm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

type rfc3414A3 struct {
	Password  string `json:"password"`
	EngineID  string `json:"engineID"`
	MD5Ku     string `json:"md5Ku"`
	MD5Kul    string `json:"md5Kul"`
	SHA1Ku    string `json:"sha1Ku"`
	SHA1Kul   string `json:"sha1Kul"`
	SHA256Ku  string `json:"sha256Ku"`
	SHA256Kul string `json:"sha256Kul"`
}

func TestRFC3414PasswordToKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata/usm/rfc3414-a3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v rfc3414A3
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	engine, err := hex.DecodeString(v.EngineID)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte(v.Password)

	md5Ku := passwordToKey(authMD5.new, pass)
	if got := hex.EncodeToString(md5Ku); got != v.MD5Ku {
		t.Fatalf("MD5 Ku %s want %s", got, v.MD5Ku)
	}
	md5Kul := localizeKey(authMD5.new, md5Ku, engine)
	if got := hex.EncodeToString(md5Kul); got != v.MD5Kul {
		t.Fatalf("MD5 Kul %s want %s", got, v.MD5Kul)
	}

	sha1Ku := passwordToKey(authSHA1.new, pass)
	if got := hex.EncodeToString(sha1Ku); got != v.SHA1Ku {
		t.Fatalf("SHA1 Ku %s want %s", got, v.SHA1Ku)
	}
	sha1Kul := localizeKey(authSHA1.new, sha1Ku, engine)
	if got := hex.EncodeToString(sha1Kul); got != v.SHA1Kul {
		t.Fatalf("SHA1 Kul %s want %s", got, v.SHA1Kul)
	}

	sha256Ku := passwordToKey(authSHA256.new, pass)
	if got := hex.EncodeToString(sha256Ku); got != v.SHA256Ku {
		t.Fatalf("SHA-256 Ku %s want %s", got, v.SHA256Ku)
	}
	sha256Kul, err := Localize(model.AuthSHA256, pass, engine)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sha256Kul); got != v.SHA256Kul {
		t.Fatalf("SHA-256 Kul %s want %s", got, v.SHA256Kul)
	}
}

func TestLocalizeRejectsUnsupported(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 8)
	_, err := Localize("sha384", []byte("maplesyrup"), id)
	if !isUSMAlg(err) {
		t.Fatalf("sha384: %v", err)
	}
	_, err = Localize(model.AuthSHA256, []byte("maplesyrup"), id)
	if err != nil {
		t.Fatal(err)
	}
}

func isUSMAlg(err error) bool {
	e, ok := domainerr.As(err)
	return ok && e.Code == domainerr.CodeUSMAlgUnsupported
}

func TestDESAESRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	plain := []byte("scopedPDU-bytes-for-usm-priv")

	ct, err := encrypt(model.PrivDES, key, 1, 10, salt, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(model.PrivDES, key, 1, 10, salt, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("DES %q", got)
	}

	ct, err = encrypt(model.PrivAES128, key, 1, 10, salt, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err = decrypt(model.PrivAES128, key, 1, 10, salt, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("AES %q", got)
	}
}

func TestDecryptBadInput(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 16)
	salt := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	if _, err := decrypt(model.PrivDES, key, 1, 1, salt, []byte("short")); err == nil {
		t.Fatal("DES short ciphertext")
	}
	if _, err := decrypt(model.PrivAES128, key, 1, 1, salt, nil); err == nil {
		t.Fatal("AES empty ciphertext")
	}
}
