package observability

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelInfo)
	l.Log(Record{Event: EventStateApply, Component: "app", Result: "ok"})
	s := buf.String()
	if !strings.Contains(s, `"event":"state.apply"`) {
		t.Fatal(s)
	}
	if !strings.Contains(s, `"timestamp"`) {
		t.Fatal("catalog field timestamp missing:", s)
	}
	if strings.Contains(s, `"time":`) {
		t.Fatal("slog time key leaked:", s)
	}
	if strings.Contains(s, `"msg":`) {
		t.Fatal("msg key leaked:", s)
	}
	if strings.Contains(s, "client_ip") || strings.Contains(s, "Authorization") || strings.Contains(s, "community") {
		t.Fatal(s)
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelError)
	l.Log(Record{Event: EventSNMPPDU, Component: "snmpagent", Result: "ok"})
	if buf.Len() != 0 {
		t.Fatalf("error level must drop info: %s", buf.String())
	}
	l.SetLevel(LevelDebug)
	l.Log(Record{Event: EventSNMPPDU, Component: "snmpagent", Result: "ok"})
	if !strings.Contains(buf.String(), `"event":"snmp.pdu"`) {
		t.Fatal(buf.String())
	}
}
