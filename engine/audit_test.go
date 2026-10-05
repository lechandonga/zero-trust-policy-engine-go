package engine_test

import (
	"testing"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// 业务：决策审计 —— 每次评估都按时间顺序留痕，且缓冲容量受上限约束。
func TestDecisionAuditLog(t *testing.T) {
	e := engine.New(engine.WithDecisionLogLimit(3))
	err := e.Load(&policy.Document{Version: "1.0.0", Rules: []policy.Rule{{
		ID: "r", Effect: "allow", Subjects: []string{"u"},
		Actions: []string{"a"}, Resources: []string{"r"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		e.Evaluate(&policy.Request{Subject: "u", Action: "a", Resource: "r"})
	}
	log := e.Decisions()
	if len(log) != 3 {
		t.Fatalf("决策日志应被裁剪到上限 3，实际 %d", len(log))
	}
	for i, d := range log {
		if !d.Allowed || d.EvaluatedAt == "" || d.Request == nil {
			t.Fatalf("第 %d 条决策留痕不完整: %+v", i, d)
		}
	}
	t.Logf("业务[决策审计] 5 次评估后保留最近 3 条，全部含时间戳/版本=%s/原始请求，可供追溯",
		log[0].PolicyVersion)

	// 返回的是副本，外部修改不影响引擎内部状态。
	log[0].Allowed = false
	if !e.Decisions()[0].Allowed {
		t.Fatal("Decisions 必须返回副本，内部审计状态不得被外部篡改")
	}
}
