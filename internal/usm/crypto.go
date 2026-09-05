package usm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // CBC-DES is RFC 3414 USM; 1.0 allowlist.
	"crypto/hmac"
	"crypto/md5"  // HMAC-MD5-96 is RFC 3414 USM; 1.0 allowlist.
	"crypto/sha1" // HMAC-SHA-96 is RFC 3414 USM; 1.0 allowlist.
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/hilather/go-lab-snmp/internal/model"
)

const passwordToKeyBytes = 1048576 // RFC 3414 A.2 1 MiB expansion

type authAlg struct {
	new func() hash.Hash
	mac int
}

type privAlg struct {
	kind string
}

var (
	authMD5    = authAlg{new: md5.New, mac: 12}
	authSHA1   = authAlg{new: sha1.New, mac: 12}
	authSHA256 = authAlg{new: sha256.New, mac: 24}
	privDES    = privAlg{kind: model.PrivDES}
	privAES128 = privAlg{kind: model.PrivAES128}
)

func passwordToKey(newH func() hash.Hash, passphrase []byte) []byte {
	h := newH()
	var buf [64]byte
	idx := 0
	for n := 0; n < passwordToKeyBytes; n += 64 {
		for i := 0; i < 64; i++ {
			buf[i] = passphrase[idx]
			idx++
			if idx == len(passphrase) {
				idx = 0
			}
		}
		_, _ = h.Write(buf[:])
	}
	return h.Sum(nil)
}

func localizeKey(newH func() hash.Hash, ku, engineID []byte) []byte {
	h := newH()
	_, _ = h.Write(ku)
	_, _ = h.Write(engineID)
	_, _ = h.Write(ku)
	return h.Sum(nil)
}

func hmacMAC(proto string, key, whole []byte) ([]byte, error) {
	alg, err := lookupAuth(proto)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(alg.new, key)
	_, _ = mac.Write(whole)
	sum := mac.Sum(nil)
	if len(sum) < alg.mac {
		return nil, fmt.Errorf("usm: HMAC shorter than truncated MAC")
	}
	return sum[:alg.mac], nil
}

func macLen(proto string) (int, error) {
	alg, err := lookupAuth(proto)
	if err != nil {
		return 0, err
	}
	return alg.mac, nil
}

func encrypt(proto string, privKey []byte, boots, etime int32, salt, plain []byte) ([]byte, error) {
	switch proto {
	case model.PrivDES:
		return encryptDES(privKey, salt, plain)
	case model.PrivAES128:
		return encryptAES(privKey, boots, etime, salt, plain)
	default:
		return nil, fmt.Errorf("usm: priv protocol is not supported in 1.0")
	}
}

func decrypt(proto string, privKey []byte, boots, etime int32, salt, cipherText []byte) ([]byte, error) {
	switch proto {
	case model.PrivDES:
		return decryptDES(privKey, salt, cipherText)
	case model.PrivAES128:
		return decryptAES(privKey, boots, etime, salt, cipherText)
	default:
		return nil, fmt.Errorf("usm: priv protocol is not supported in 1.0")
	}
}

func encryptDES(privKey, salt, plain []byte) ([]byte, error) {
	block, iv, err := desBlock(privKey, salt)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, des.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

func decryptDES(privKey, salt, cipherText []byte) ([]byte, error) {
	block, iv, err := desBlock(privKey, salt)
	if err != nil {
		return nil, err
	}
	if len(cipherText) == 0 || len(cipherText)%des.BlockSize != 0 {
		return nil, fmt.Errorf("usm: DES ciphertext length")
	}
	plain := make([]byte, len(cipherText))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, cipherText)
	return pkcs7Unpad(plain, des.BlockSize)
}

func desBlock(privKey, salt []byte) (cipher.Block, []byte, error) {
	if len(privKey) < 16 {
		return nil, nil, fmt.Errorf("usm: DES key too short")
	}
	if len(salt) != 8 {
		return nil, nil, fmt.Errorf("usm: DES salt must be 8 octets")
	}
	block, err := des.NewCipher(privKey[:8])
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, 8)
	for i := 0; i < 8; i++ {
		iv[i] = privKey[8+i] ^ salt[i]
	}
	return block, iv, nil
}

func encryptAES(privKey []byte, boots, etime int32, salt, plain []byte) ([]byte, error) {
	block, iv, err := aesBlock(privKey, boots, etime, salt)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, plain)
	return out, nil
}

func decryptAES(privKey []byte, boots, etime int32, salt, cipherText []byte) ([]byte, error) {
	block, iv, err := aesBlock(privKey, boots, etime, salt)
	if err != nil {
		return nil, err
	}
	if len(cipherText) == 0 {
		return nil, fmt.Errorf("usm: AES ciphertext empty")
	}
	plain := make([]byte, len(cipherText))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, cipherText)
	return plain, nil
}

func aesBlock(privKey []byte, boots, etime int32, salt []byte) (cipher.Block, []byte, error) {
	if len(privKey) < 16 {
		return nil, nil, fmt.Errorf("usm: AES key too short")
	}
	if len(salt) != 8 {
		return nil, nil, fmt.Errorf("usm: AES salt must be 8 octets")
	}
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(etime))
	copy(iv[8:], salt)
	return block, iv, nil
}

func pkcs7Pad(b []byte, block int) []byte {
	n := block - (len(b) % block)
	if n == 0 {
		n = block
	}
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 || len(b)%block != 0 {
		return nil, fmt.Errorf("usm: DES padding")
	}
	n := int(b[len(b)-1])
	if n < 1 || n > block || n > len(b) {
		return nil, fmt.Errorf("usm: DES padding")
	}
	return b[:len(b)-n], nil
}
