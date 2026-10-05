package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
	"github.com/lechandonga/zero-trust-policy-engine-go/loader"
	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

const v1Policy = `{
  "version": "1.0.0",
  "rules": [
    {"id":"allow-read","effect":"allow","priority":10,"subjects":["u1"],"actions":["read"],"resources":["doc/x"]}
  ]
}`

// v2 增加对 doc/x 的显式 deny：同一请求结论应发生可解释的翻转。
const v2Policy = `{
  "version": "2.0.0",
  "rules": [
    {"id":"allow-read","effect":"allow","priority":10,"subjects":["u1"],"actions":["read"],"resources":["doc/x"]},
    {"id":"deny-doc-x","effect":"deny","priority":20,"subjects":["u1"],"actions":["read"],"resources":["doc/x"]}
  ]
}`

// v3 故意写坏：JSON 语法错误，必须加载失败并保留 v2。
const v3Broken = `{ "version": "3.0.0", "rules": [ BROKEN`

// v4 非法 effect：校验失败，同样保留 v2。
const v4Invalid = `{
  "version": "4.0.0",
  "rules": [
    {"id":"bad","effect":"maybe","subjects":["u1"],"actions":["read"],"resources":["doc/x"]}
  ]
}`

// v5 版本回退到 0.9.0：应被拒绝，保留 v2。
const v5Downgrade = `{
  "version": "0.9.0",
  "rules": [
    {"id":"allow-read","effect":"allow","priority":10,"subjects":["u1"],"actions":["read"],"resources":["doc/x"]}
  ]
}`

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// 保证 mtime 轮询能观察到变化。
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, name), future, future); err != nil {
		t.Fatal(err)
	}
}

// 业务：热更新原子性 —— 加载失败保留旧版本，不允许版本回退/重复。
func TestHotReload_FailureKeepsOldVersion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	writePolicy(t, dir, "policy.json", v1Policy)

	e := engine.New(engine.WithHistoryLimit(8))
	if v, err := loader.LoadAndApply(e, p); err != nil || v != "1.0.0" {
		t.Fatalf("初始加载失败: v=%s err=%v", v, err)
	}
	writePolicy(t, dir, "policy.json", v2Policy)
	if _, err := loader.LoadAndApply(e, p); err != nil {
		t.Fatalf("v2 应成功: %v", err)
	}

	req := &policy.Request{Subject: "u1", Action: "read", Resource: "doc/x"}
	before := e.Evaluate(req)
	if before.Allowed || before.MatchedRuleID != "deny-doc-x" || before.PolicyVersion != "2.0.0" {
		t.Fatalf("v2 下应拒绝，got %+v", before)
	}
	t.Logf("业务[热更新] 用例=v2生效 决策 deny 命中=%s 版本=%s", before.MatchedRuleID, before.PolicyVersion)

	bad := []struct{ name, body string }{
		{"语法损坏 v3", v3Broken},
		{"非法 effect v4", v4Invalid},
		{"版本回退 v5", v5Downgrade},
	}
	for _, b := range bad {
		writePolicy(t, dir, "policy.json", b.body)
		_, err := loader.LoadAndApply(e, p)
		if err == nil {
			t.Fatalf("%s 必须加载失败", b.name)
		}
		le, ok := policy.AsLoadError(err)
		if !ok {
			t.Fatalf("%s 应返回结构化 LoadError，got %T", b.name, err)
		}
		after := e.Evaluate(req)
		if e.CurrentVersion() != "2.0.0" || after.PolicyVersion != "2.0.0" ||
			after.Allowed || after.MatchedRuleID != "deny-doc-x" {
			t.Fatalf("%s 后旧版本必须继续完整服务，got version=%s dec=%+v",
				b.name, e.CurrentVersion(), after)
		}
		t.Logf("业务[热更新] 用例=%-14s 拒绝原因码=%s，当前版本仍为=%s 决策稳定",
			b.name, le.Code, e.CurrentVersion())
	}

	// 相同版本重复发布也必须被拒绝。
	doc := &policy.Document{Version: "2.0.0", Rules: []policy.Rule{{
		ID: "x", Effect: "allow", Subjects: []string{"u1"}, Actions: []string{"read"}, Resources: []string{"doc/x"}}}}
	err := e.Load(doc)
	if le, ok := policy.AsLoadError(err); !ok || le.Code != policy.CodeVersionSame {
		t.Fatalf("重复版本应返回 %s，got %v", policy.CodeVersionSame, err)
	}
	t.Logf("业务[热更新] 用例=重复版本 拒绝原因码=%s", policy.CodeVersionSame)
}

// 业务：历史复现 —— 决策可按当时版本重放，版本间结论变化可解释。
func TestHotReload_ReplayAndExplain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	e := engine.New(engine.WithHistoryLimit(8))

	writePolicy(t, dir, "policy.json", v1Policy)
	if _, err := loader.LoadAndApply(e, p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Millisecond)
	writePolicy(t, dir, "policy.json", v2Policy)
	if _, err := loader.LoadAndApply(e, p); err != nil {
		t.Fatal(err)
	}

	req := &policy.Request{Subject: "u1", Action: "read", Resource: "doc/x"}
	d1, err := e.Replay("1.0.0", req)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := e.Replay("2.0.0", req)
	if err != nil {
		t.Fatal(err)
	}
	if !d1.Allowed || d1.MatchedRuleID != "allow-read" {
		t.Fatalf("按 v1 复现应为 allow/allow-read，got %+v", d1)
	}
	if d2.Allowed || d2.MatchedRuleID != "deny-doc-x" {
		t.Fatalf("按 v2 复现应为 deny/deny-doc-x，got %+v", d2)
	}
	t.Logf("业务[历史复现] v1: allow(rule=allow-read) | v2: deny(rule=deny-doc-x)")

	expl, err := e.ExplainChange("1.0.0", "2.0.0", req)
	if err != nil {
		t.Fatal(err)
	}
	if !expl.Changed || expl.Summary == "" {
		t.Fatalf("应检测到结论变化并给出解释: %+v", expl)
	}
	t.Logf("业务[历史复现] 变化解释: %s", expl.Summary)

	if _, err := e.Replay("9.9.9", req); err == nil {
		t.Fatalf("未保留的版本复现应报错")
	}
}

// 业务：并发评估 x 热更新竞态 —— 任何在途请求只看到完整的某一个版本。
func TestHotReload_ConcurrentRace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	e := engine.New(engine.WithHistoryLimit(20))
	writePolicy(t, dir, "policy.json", v1Policy)
	if _, err := loader.LoadAndApply(e, p); err != nil {
		t.Fatal(err)
	}

	req := &policy.Request{Subject: "u1", Action: "read", Resource: "doc/x"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var observed sync.Map // version -> allow 状态必须恒定
	var badObserved int64

	var readers sync.WaitGroup
	for w := 0; w < 16; w++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				d := e.Evaluate(req)
				// 1.0.0 下该请求恒 allow，2.0.0 起恒 deny；
				// 若观察到同一版本出现两种结论，说明出现了半新半旧状态。
				want := d.PolicyVersion == "1.0.0"
				if d.Allowed != want ||
					(d.Allowed && d.MatchedRuleID != "allow-read") ||
					(!d.Allowed && d.PolicyVersion != "1.0.0" && d.MatchedRuleID != "deny-doc-x") {
					atomic.AddInt64(&badObserved, 1)
				}
				observed.Store(fmt.Sprintf("%s/%t/%s", d.PolicyVersion, d.Allowed, d.MatchedRuleID), struct{}{})
			}
		}()
	}

	// 更新者交替发布 v2 与写入坏文件（坏文件绝不能改变当前版本）。
	time.Sleep(50 * time.Millisecond)
	writePolicy(t, dir, "policy.json", v2Policy)
	if _, err := loader.LoadAndApply(e, p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	writePolicy(t, dir, "policy.json", v3Broken)
	if _, err := loader.LoadAndApply(e, p); err == nil {
		t.Fatal("坏文件必须加载失败")
	}
	time.Sleep(50 * time.Millisecond)

	cancel()
	readers.Wait()

	if got := atomic.LoadInt64(&badObserved); got != 0 {
		t.Fatalf("观察到 %d 个与版本不一致的决策（疑似半新半旧）", got)
	}
	var combos []string
	observed.Range(func(k, _ any) bool {
		combos = append(combos, k.(string))
		return true
	})
	t.Logf("业务[并发竞态] 16 读协程 x 更新协程，仅观察到完整版本组合: %v（无混合状态）", combos)

	// 最终版本必须停留在 v2。
	if e.CurrentVersion() != "2.0.0" {
		t.Fatalf("坏文件更新后版本应保持 2.0.0，got %s", e.CurrentVersion())
	}
}
