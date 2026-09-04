package config

import "testing"

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"apiVersion":"labsnmp.dev/v1alpha1","kind":"LabSNMP","metadata":{"name":"x"},"spec":{}}`))
	f.Add([]byte("apiVersion: labsnmp.dev/v1alpha1\nkind: LabSNMP\nmetadata:\n  name: x\nspec: {}\n"))
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("[:"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}
		_, _ = Decode(data)
		_, _ = Load(data)
	})
}

func TestFuzzDecodeSmoke(t *testing.T) {
	t.Chdir(repoRoot(t))
	seeds := [][]byte{
		[]byte(`{"apiVersion":"labsnmp.dev/v1alpha1","kind":"LabSNMP","metadata":{"name":"x"},"spec":{}}`),
		[]byte("apiVersion: labsnmp.dev/v1alpha1\nkind: LabSNMP\nmetadata:\n  name: x\nspec: {}\n"),
		[]byte(""),
		[]byte("{"),
		[]byte(mustLoad(t, "valid", "defaults.yaml")),
		[]byte(mustLoad(t, "invalid", "unknown-field.yaml")),
		[]byte(mustLoad(t, "invalid", "reserved-key.yaml")),
	}
	for _, s := range seeds {
		_, _ = Decode(s)
		_, _ = Load(s)
	}
}
