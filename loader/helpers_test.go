package loader_test

import (
	"os"
	"testing"
	"time"
)

func writeFileImpl(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

func touch(path string, t time.Time) {
	if err := os.Chtimes(path, t, t); err != nil {
		panic(err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}
