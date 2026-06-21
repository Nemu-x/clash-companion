// Package testvectors helps tests load the language-neutral golden vectors from the
// repository's vectors/ directory regardless of the package's working directory.
package testvectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Dir locates the repo-root vectors/ directory by walking up from the working dir.
func Dir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		cand := filepath.Join(dir, "vectors")
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("testvectors: could not locate vectors/ directory")
		}
		dir = parent
	}
}

// Load reads vectors/<file> and JSON-decodes it into v.
func Load(t *testing.T, file string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(Dir(t), file))
	if err != nil {
		t.Fatalf("read vector %s: %v", file, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode vector %s: %v", file, err)
	}
}
