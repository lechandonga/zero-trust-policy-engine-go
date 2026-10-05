package engine_test

import (
	"testing"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
	"github.com/lechandonga/zero-trust-policy-engine-go/loader"
	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

func loadEngine(t *testing.T, path string) *engine.Engine {
	t.Helper()
	doc, err := loader.LoadFile(path)
	if err != nil {
		t.Fatalf("加载测试策略失败: %v", err)
	}
	e := engine.New(engine.WithHistoryLimit(8))
	if err := e.Load(doc); err != nil {
		t.Fatalf("发布测试策略失败: %v", err)
	}
	return e
}

// 业务：访问评估 —— 明确 allow/deny、deny 压过 allow、glob 资源、默认拒绝。
func TestEvaluate_Decisions(t *testing.T) {
	e := loadEngine(t, "../testdata/policies/v1.json")

	cases := []struct {
		name       string
		req        *policy.Request
		wantAllow  bool
		wantReason string
		wantRule   string
	}{
		{
			name: "管理员读审计桶-放行",
			req: &policy.Request{Subject: "user:alice", Action: "read",
				Resource: "bucket/audit/2026-10.log"},
			wantAllow: true, wantReason: policy.ReasonAllowMatch, wantRule: "allow-admin-read",
		},
		{
			name: "CI 内网部署 sandbox-放行(** 跨路径)",
			req: &policy.Request{Subject: "svc:ci", Action: "deploy",
				Resource:   "env/sandbox/team-a/service",
				Attributes: map[string]interface{}{"network": "internal"}},
			wantAllow: true, wantReason: policy.ReasonAllowMatch, wantRule: "allow-ci-deploy",
		},
		{
			name: "CI 外网部署-条件不满足转默认拒绝",
			req: &policy.Request{Subject: "svc:ci", Action: "deploy",
				Resource:   "env/sandbox/x",
				Attributes: map[string]interface{}{"network": "external"}},
			wantAllow: false, wantReason: policy.ReasonDenyMatch, wantRule: "deny-all-external",
		},
		{
			name: "CI 缺 network 属性-不得因属性缺失放行",
			req: &policy.Request{Subject: "svc:ci", Action: "deploy",
				Resource: "env/sandbox/x"},
			wantAllow: false, wantReason: policy.ReasonDenyDefault,
		},
		{
			name: "管理员写生产-高优先级 deny 压过任何 allow",
			req: &policy.Request{Subject: "user:alice", Action: "deploy",
				Resource: "env/prod/billing"},
			wantAllow: false, wantReason: policy.ReasonDenyMatch, wantRule: "deny-prod-write",
		},
		{
			name: "通配策略下未命中任何规则-默认拒绝",
			req: &policy.Request{Subject: "user:ghost", Action: "read",
				Resource: "bucket/audit/x"},
			wantAllow: false, wantReason: policy.ReasonDenyDefault,
		},
		{
			name: "已知主体但无规则命中-默认拒绝",
			req: &policy.Request{Subject: "svc:ci", Action: "delete",
				Resource:   "env/sandbox/x",
				Attributes: map[string]interface{}{"network": "internal"}},
			wantAllow: false, wantReason: policy.ReasonDenyDefault,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(tc.req)
			if d.Allowed != tc.wantAllow || d.ReasonCode != tc.wantReason ||
				(tc.wantRule != "" && d.MatchedRuleID != tc.wantRule) {
				t.Fatalf("结论不符: got allow=%v reason=%s rule=%s msg=%s; want allow=%v reason=%s rule=%s",
					d.Allowed, d.ReasonCode, d.MatchedRuleID, d.Message,
					tc.wantAllow, tc.wantReason, tc.wantRule)
			}
			t.Logf("业务[访问评估] 用例=%-34s allow=%-5v 原因码=%-22s 命中规则=%s 版本=%s",
				tc.name, d.Allowed, d.ReasonCode, dash(d.MatchedRuleID), d.PolicyVersion)
		})
	}
}

// 业务：异常输入 —— 空主体/动作/资源、nil 请求、无策略引擎，均安全拒绝、不 panic。
func TestEvaluate_AbnormalInputs(t *testing.T) {
	e := loadEngine(t, "../testdata/policies/v1.json")
	badCases := []struct {
		name string
		req  *policy.Request
	}{
		{"nil 请求", nil},
		{"主体为空", &policy.Request{Action: "read", Resource: "bucket/audit/x"}},
		{"动作为空", &policy.Request{Subject: "user:alice", Resource: "bucket/audit/x"}},
		{"资源为空", &policy.Request{Subject: "user:alice", Action: "read"}},
		{"属性类型怪异但类型合法", &policy.Request{
			Subject: "svc:ci", Action: "deploy", Resource: "env/sandbox/x",
			Attributes: map[string]interface{}{"network": 12345}}},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(tc.req)
			if d.Allowed {
				t.Fatalf("异常输入绝不能放行: %+v", d)
			}
			t.Logf("业务[异常输入] 用例=%-20s 安全拒绝 原因码=%s 信息=%q", tc.name, d.ReasonCode, d.Message)
		})
	}

	t.Run("没有加载任何策略时默认拒绝", func(t *testing.T) {
		empty := engine.New()
		d := empty.Evaluate(&policy.Request{Subject: "u", Action: "a", Resource: "r"})
		if d.Allowed || d.ReasonCode != policy.ReasonDenyDefault || d.PolicyVersion != "" {
			t.Fatalf("空引擎应默认拒绝且无版本号: %+v", d)
		}
		t.Logf("业务[异常输入] 用例=无策略引擎 默认拒绝，原因码=%s", d.ReasonCode)
	})

	t.Run("策略不含通配主体时，未知主体返回专门原因码", func(t *testing.T) {
		ee := engine.New()
		err := ee.Load(&policy.Document{Version: "9.0.0", Rules: []policy.Rule{{
			ID: "r", Effect: "allow", Subjects: []string{"known:u"},
			Actions: []string{"read"}, Resources: []string{"doc"}}}})
		if err != nil {
			t.Fatal(err)
		}
		d := ee.Evaluate(&policy.Request{Subject: "stranger", Action: "read", Resource: "doc"})
		if d.Allowed || d.ReasonCode != policy.ReasonDenyUnknownSbj {
			t.Fatalf("期望 DENY_UNKNOWN_SUBJECT，got %+v", d)
		}
		t.Logf("业务[异常输入] 用例=非通配策略-未知主体 原因码=%s", d.ReasonCode)
	})

	t.Run("评估中不得 panic（含 nil attributes map 访问）", func(t *testing.T) {
		d := e.Evaluate(&policy.Request{Subject: "svc:ci", Action: "deploy", Resource: "env/sandbox/x"})
		if d.Allowed {
			t.Fatalf("缺属性的条件规则不应放行")
		}
		t.Logf("业务[异常输入] 用例=nil 属性表 未 panic，原因码=%s", d.ReasonCode)
	})
}

// 业务：冲突取舍稳定可复现 —— deny > priority > rule id，与遍历顺序无关。
func TestConflictResolution_Stable(t *testing.T) {
	doc := &policy.Document{Version: "2.0.0", Rules: []policy.Rule{
		{ID: "allow-very-high", Effect: "allow", Priority: 99,
			Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"}},
		{ID: "aaa-deny-mid", Effect: "deny", Priority: 5,
			Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"}},
	}}
	e := engine.New()
	if err := e.Load(doc); err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(&policy.Request{Subject: "u", Action: "a", Resource: "r"})
	if d.Allowed || d.MatchedRuleID != "aaa-deny-mid" {
		t.Fatalf("deny 必须压过任意优先级 allow，got %+v", d)
	}
	t.Logf("业务[冲突取舍] 用例=deny-vs-allow 稳定拒绝，命中=%s，候选=%v（deny 优先）",
		d.MatchedRuleID, d.Candidates)

	// 同为 allow 时 priority 高者胜。
	doc2 := &policy.Document{Version: "2.0.1", Rules: []policy.Rule{
		{ID: "low", Effect: "allow", Priority: 1,
			Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r/*"}},
		{ID: "high", Effect: "allow", Priority: 9,
			Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r/**"}},
	}}
	e2 := engine.New()
	if err := e2.Load(doc2); err != nil {
		t.Fatal(err)
	}
	d2 := e2.Evaluate(&policy.Request{Subject: "u", Action: "a", Resource: "r/deep/x"})
	if !d2.Allowed || d2.MatchedRuleID != "high" {
		t.Fatalf("同 effect 时高 priority 应胜出，got %+v", d2)
	}
	t.Logf("业务[冲突取舍] 用例=同effect-按priority 命中=%s 候选=%v", d2.MatchedRuleID, d2.Candidates)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
