package loader_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
	"github.com/lechandonga/zero-trust-policy-engine-go/loader"
	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// 业务：文件加载 —— 缺文件、空文件、坏 JSON、未知字段均给出可区分原因码。
func TestLoadFile_Errors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, path, body, wantCode string
	}{
		{"文件不存在", filepath.Join(dir, "missing.json"), "__SKIP__", policy.CodeFileRead},
		{"空文件", filepath.Join(dir, "empty.json"), "   \n ", policy.CodeSyntax},
		{"JSON 语法错", filepath.Join(dir, "bad.json"), "{not-json", policy.CodeSyntax},
		{"未知字段", filepath.Join(dir, "unknown.json"),
			`{"version":"1.0.0","nope":1,"rules":[]}`, policy.CodeSyntax},
	}
	for _, tc := range cases {
		if tc.body != "" && tc.body != "__SKIP__" {
			if err := writeFile(tc.path, tc.body); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(tc.name, func(t *testing.T) {
			_, err := loader.LoadFile(tc.path)
			le, ok := policy.AsLoadError(err)
			if !ok || le.Code != tc.wantCode {
				t.Fatalf("期望原因码 %s，got %v", tc.wantCode, err)
			}
			t.Logf("业务[文件加载] 用例=%-10s 原因码=%s 信息=%q", tc.name, le.Code, le.Message)
		})
	}
}

// 业务：轮询热更新器 —— 文件变化时发布新版本；文件损坏时回调报错且旧版本继续服务。
func TestReloader(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	if err := writeFile(p, `{
	  "version":"1.0.0",
	  "rules":[{"id":"a","effect":"allow","subjects":["u"],"actions":["read"],"resources":["r"]}]
	}`); err != nil {
		t.Fatal(err)
	}

	e := engine.New()
	rl := loader.NewReloader(e, p, 50*time.Millisecond)
	var applied, failed int64
	rl.OnResult(func(r loader.ReloadResult) {
		if r.Err != nil {
			atomic.AddInt64(&failed, 1)
		}
		if r.Applied {
			atomic.AddInt64(&applied, 1)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	go rl.Run(ctx, nil)

	waitFor(t, func() bool { return e.CurrentVersion() == "1.0.0" })
	t.Logf("业务[轮询热更] 初始版本 1.0.0 已发布")

	if err := writeFile(p, `{
	  "version":"2.0.0",
	  "rules":[
	    {"id":"a","effect":"allow","subjects":["u"],"actions":["read"],"resources":["r"]},
	    {"id":"b","effect":"deny","priority":5,"subjects":["u"],"actions":["read"],"resources":["r"]}
	  ]
	}`); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	touch(p, future)

	waitFor(t, func() bool { return e.CurrentVersion() == "2.0.0" })
	t.Logf("业务[轮询热更] 检测到文件变化，原子切换至 2.0.0")

	if err := writeFile(p, `{broken`); err != nil {
		t.Fatal(err)
	}
	touch(p, time.Now().Add(4*time.Second))

	waitFor(t, func() bool { return rl.LastError() != nil })
	if e.CurrentVersion() != "2.0.0" {
		t.Fatalf("损坏文件不得改变当前版本，got %s", e.CurrentVersion())
	}
	le, ok := policy.AsLoadError(rl.LastError())
	if !ok {
		t.Fatalf("热更失败应暴露结构化错误，got %v", rl.LastError())
	}
	t.Logf("业务[轮询热更] 损坏文件被拒绝，原因码=%s，服务版本仍为 2.0.0", le.Code)

	cancel()
	if atomic.LoadInt64(&applied) < 2 {
		t.Fatalf("期望至少 2 次成功发布回调（初次+v2），got %d", applied)
	}
	if atomic.LoadInt64(&failed) < 1 {
		t.Fatalf("期望至少 1 次失败回调，got %d", failed)
	}
}

func writeFile(path, body string) error {
	return writeFileImpl(path, body)
}
