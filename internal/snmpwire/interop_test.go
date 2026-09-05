package snmpwire

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// parseNetSNMPDump extracts the first "Sending N bytes" hex dump from snmp* -d output.
func parseNetSNMPDump(dump []byte) ([]byte, error) {
	sending := regexp.MustCompile(`(?i)Sending\s+(\d+)\s+bytes`)
	loc := sending.FindSubmatchIndex(dump)
	rest := dump
	want := -1
	if loc != nil {
		rest = dump[loc[0]:]
		n, err := strconv.Atoi(string(dump[loc[2]:loc[3]]))
		if err == nil {
			want = n
		}
	}
	var out []byte
	for _, line := range bytes.Split(rest, []byte("\n")) {
		b, ok := parseNetSNMPHexLine(line)
		if !ok {
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, b...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no packet dump")
	}
	if want > 0 && len(out) < want {
		return nil, fmt.Errorf("dump has %d bytes, sending claimed %d", len(out), want)
	}
	if want > 0 && len(out) > want {
		out = out[:want]
	}
	return out, nil
}

func parseNetSNMPHexLine(line []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(line))
	if s == "" {
		return nil, false
	}
	if i := strings.Index(s, ":"); i >= 0 && i <= 8 {
		prefix := strings.ReplaceAll(s[:i], " ", "")
		if isHex(prefix) {
			s = strings.TrimSpace(s[i+1:])
		}
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, false
	}
	out := make([]byte, 0, len(fields))
	for _, f := range fields {
		if len(f) != 2 || !isHex(f) {
			// net-snmp xdump appends a 16-char ASCII column after the hex.
			break
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			break
		}
		out = append(out, byte(v))
	}
	return out, len(out) > 0
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func TestParseNetSNMPDump(t *testing.T) {
	want, err := Encode(Message{
		Version:   VersionV1,
		Community: []byte("public"),
		PDU: &PDU{
			Type:      PDUGet,
			RequestID: 1,
			VarBinds:  []VarBind{vb(sysDescr(), Null())},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dumps := []string{
		`
Sending 40 bytes to UDP: [127.0.0.1]:1->[0.0.0.0]:0
0000: 30 26 02 01  00 04 06 70  75 62 6C 69  63 A0 19 02
0010: 01 01 02 01  00 02 01 00  30 0E 30 0C  06 08 2B 06
0020: 01 02 01 01  01 00 05 00

Timeout: No Response from 127.0.0.1:1.
`,
		// Real snmpget -d xdump: hex then 16-character ASCII column.
		`
Sending 40 bytes to UDP: [127.0.0.1]:1->[0.0.0.0]:0
0000: 30 26 02 01  00 04 06 70  75 62 6C 69  63 A0 19 02   0&.....public...
0016: 01 01 02 01  00 02 01 00  30 0E 30 0C  06 08 2B 06   ........0.0...+.
0032: 01 02 01 01  01 00 05 00                           ........

Timeout: No Response from 127.0.0.1:1.
`,
	}
	for i, dump := range dumps {
		got, err := parseNetSNMPDump([]byte(dump))
		if err != nil {
			t.Fatalf("dump %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("dump %d: %x\nwant %x", i, got, want)
		}
	}
}

func TestNetSNMPDumpInterop(t *testing.T) {
	if _, err := exec.LookPath("snmpget"); err != nil {
		t.Skip("snmpget not installed")
	}
	dest := "udp:127.0.0.1:1"
	cases := []struct {
		name string
		bin  string
		args []string
		ver  Version
		pdu  PDUType
	}{
		{"v1-get", "snmpget", []string{"-d", "-v", "1", "-c", "public", "-t", "0.1", "-r", "0", dest, "sysDescr.0"}, VersionV1, PDUGet},
		{"v1-getnext", "snmpgetnext", []string{"-d", "-v", "1", "-c", "public", "-t", "0.1", "-r", "0", dest, "sysDescr.0"}, VersionV1, PDUGetNext},
		{"v1-set", "snmpset", []string{"-d", "-v", "1", "-c", "private", "-t", "0.1", "-r", "0", dest, "ifAdminStatus.1", "i", "1"}, VersionV1, PDUSet},
		{"v1-trap", "snmptrap", []string{"-d", "-v", "1", "-c", "public", dest, "10.20.0.3.4.1.8072", "127.0.0.1", "0", "0", "0"}, VersionV1, PDUTrapV1},
		{"v2c-get", "snmpget", []string{"-d", "-v", "2c", "-c", "public", "-t", "0.1", "-r", "0", dest, "sysDescr.0"}, VersionV2c, PDUGet},
		{"v2c-getnext", "snmpgetnext", []string{"-d", "-v", "2c", "-c", "public", "-t", "0.1", "-r", "0", dest, "sysDescr.0"}, VersionV2c, PDUGetNext},
		{"v2c-getbulk", "snmpbulkget", []string{"-d", "-v", "2c", "-c", "public", "-t", "0.1", "-r", "0", "-Cn0", "-Cr5", dest, "sysDescr.0"}, VersionV2c, PDUGetBulk},
		{"v2c-set", "snmpset", []string{"-d", "-v", "2c", "-c", "private", "-t", "0.1", "-r", "0", dest, "ifAdminStatus.1", "i", "1"}, VersionV2c, PDUSet},
		{"v2c-trap", "snmptrap", []string{"-d", "-v", "2c", "-c", "public", dest, "", "10.20.0.3.10.0.0.1.5.1"}, VersionV2c, PDUTrapV2},
		{"v2c-inform", "snmpinform", []string{"-d", "-v", "2c", "-c", "public", "-t", "0.1", "-r", "0", dest, "", "10.20.0.3.10.0.0.1.5.1"}, VersionV2c, PDUInform},
		{"v3-get", "snmpget", []string{"-d", "-v", "3", "-l", "noAuthNoPriv", "-u", "alice", "-t", "0.1", "-r", "0", dest, "sysDescr.0"}, VersionV3, PDUGet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.LookPath(tc.bin); err != nil {
				t.Skipf("%s not installed", tc.bin)
			}
			raw := captureNetSNMP(t, tc.bin, tc.args...)
			m, err := Decode(raw)
			if err != nil {
				t.Fatalf("decode net-snmp packet: %v\n%x", err, raw)
			}
			if m.Version != tc.ver {
				t.Fatalf("version %s want %s", m.Version, tc.ver)
			}
			p := m.RequestPDU()
			if tc.ver == VersionV3 && m.Priv() {
				t.Fatal("unexpected priv on noAuthNoPriv capture")
			}
			if p == nil {
				t.Fatal("missing PDU")
			}
			if p.Type != tc.pdu {
				t.Fatalf("pdu %s want %s", p.Type, tc.pdu)
			}
			enc, err := Encode(m)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Decode(enc)
			if err != nil {
				t.Fatal(err)
			}
			if !again.Equal(m) {
				t.Fatal("encode(decode(net-snmp)) semantic mismatch")
			}
		})
	}
}

func captureNetSNMP(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run()
	raw, err := parseNetSNMPDump(buf.Bytes())
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, buf.Bytes())
	}
	return raw
}
