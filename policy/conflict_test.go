package policy_test

import (
	"testing"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

func rule(id string, effect policy.Effect, priority int) policy.Rule {
	return policy.Rule{
		ID: id, Effect: effect, Priority: priority,
		Subjects:  []string{"group:eng"},
		Actions:   []string{"read"},
		Resources: []string{"bucket/data/*"},
	}
}

// 业务：策略冲突检测 —— 重复规则与同优先级矛盾规则必须被拦截，
// 且检测结果与规则在文件中的书写顺序无关。
func TestDetectConflicts(t *testing.T) {
	t.Run("相同选择器+相同effect 判为重复", func(t *testing.T) {
		rep := policy.DetectConflicts([]policy.Rule{rule("a", "allow", 1), rule("b", "allow", 1)})
		if len(rep.Duplicates) != 1 {
			t.Fatalf("期望 1 条重复，实际 %d", len(rep.Duplicates))
		}
		if rep.Duplicates[0].Code != policy.CodeDuplicateRule {
			t.Fatalf("原因码错误: %s", rep.Duplicates[0].Code)
		}
		t.Logf("业务[冲突检测] 用例=重复规则 命中 %s (a<->b)", rep.Duplicates[0].Code)
	})

	t.Run("相同选择器+相反effect+同优先级 判为矛盾", func(t *testing.T) {
		rep := policy.DetectConflicts([]policy.Rule{rule("a", "allow", 5), rule("b", "deny", 5)})
		if len(rep.Conflicts) != 1 {
			t.Fatalf("期望 1 条矛盾，实际 %d", len(rep.Conflicts))
		}
		if rep.Conflicts[0].Code != policy.CodeConflictingRule {
			t.Fatalf("原因码错误: %s", rep.Conflicts[0].Code)
		}
		t.Logf("业务[冲突检测] 用例=同优先级矛盾 命中 %s，提示必须用 priority 区分", rep.Conflicts[0].Code)
	})

	t.Run("相反effect但优先级不同 视为可解决，不报错", func(t *testing.T) {
		rep := policy.DetectConflicts([]policy.Rule{rule("a", "allow", 1), rule("b", "deny", 10)})
		if rep.HasErrors() {
			t.Fatalf("可由优先级解决的冲突不应报错: %+v", rep)
		}
		t.Logf("业务[冲突检测] 用例=优先级可区分 允许加载（运行期 deny(p=10) 胜出）")
	})

	t.Run("检测结果与文件顺序无关", func(t *testing.T) {
		r1 := policy.DetectConflicts([]policy.Rule{rule("a", "allow", 1), rule("b", "deny", 1)})
		r2 := policy.DetectConflicts([]policy.Rule{rule("b", "deny", 1), rule("a", "allow", 1)})
		if len(r1.Conflicts) != 1 || len(r2.Conflicts) != 1 {
			t.Fatalf("两种顺序都应各检出 1 条矛盾")
		}
		if r1.Conflicts[0].RuleID != r2.Conflicts[0].RuleID ||
			r1.Conflicts[0].OtherID != r2.Conflicts[0].OtherID {
			t.Fatalf("冲突报告应按 id 稳定排序: %+v vs %+v", r1.Conflicts[0], r2.Conflicts[0])
		}
		t.Logf("业务[冲突检测] 用例=顺序无关 两种书写顺序下报告均为 %s<->%s",
			r1.Conflicts[0].RuleID, r1.Conflicts[0].OtherID)
	})

	t.Run("选择器不同不算冲突", func(t *testing.T) {
		x := rule("a", "allow", 1)
		y := rule("b", "deny", 1)
		y.Actions = []string{"write"}
		if rep := policy.DetectConflicts([]policy.Rule{x, y}); rep.HasErrors() {
			t.Fatalf("动作不同的规则互不冲突: %+v", rep)
		}
		t.Logf("业务[冲突检测] 用例=选择器不同 正常共存，运行期按请求匹配裁决")
	})
}
