package policy_test

import (
	"strings"
	"testing"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// 业务：策略加载与校验 —— 字段非法必须被拒绝，并返回可区分的原因码。
func TestDocumentValidation_InvalidFields(t *testing.T) {
	cases := []struct {
		name     string
		doc      policy.Document
		wantCode string
	}{
		{
			name:     "版本为空",
			doc:      policy.Document{Rules: []policy.Rule{{ID: "r1", Effect: "allow", Subjects: []string{"u"}, Actions: []string{"read"}, Resources: []string{"x"}}}},
			wantCode: policy.CodeVersionEmpty,
		},
		{
			name:     "没有任何规则",
			doc:      policy.Document{Version: "1.0.0"},
			wantCode: policy.CodeNoRules,
		},
		{
			name: "规则 id 为空",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{Effect: "allow", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"}},
			}},
			wantCode: policy.CodeInvalidRule,
		},
		{
			name: "effect 非法",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{ID: "r1", Effect: "maybe", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"}},
			}},
			wantCode: policy.CodeInvalidEffect,
		},
		{
			name: "subjects 含空白项",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{ID: "r1", Effect: "allow", Subjects: []string{"  "}, Actions: []string{"a"}, Resources: []string{"r"}},
			}},
			wantCode: policy.CodeInvalidRule,
		},
		{
			name: "actions 为空",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{ID: "r1", Effect: "deny", Subjects: []string{"u"}, Resources: []string{"r"}},
			}},
			wantCode: policy.CodeInvalidRule,
		},
		{
			name: "条件运算符未知",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{ID: "r1", Effect: "allow", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"},
					Conditions: []policy.Condition{{Key: "k", Op: "regex"}}},
			}},
			wantCode: policy.CodeInvalidCondition,
		},
		{
			name: "eq 条件缺少 values",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{ID: "r1", Effect: "allow", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"},
					Conditions: []policy.Condition{{Key: "k", Op: "eq"}}},
			}},
			wantCode: policy.CodeInvalidCondition,
		},
		{
			name: "规则 id 重复",
			doc: policy.Document{Version: "1.0.0", Rules: []policy.Rule{
				{ID: "r1", Effect: "allow", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"}},
				{ID: "r1", Effect: "allow", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"}},
			}},
			wantCode: policy.CodeDuplicateRule,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.doc.Validate()
			if err == nil {
				t.Fatalf("期望校验失败(%s)，实际通过", tc.wantCode)
			}
			le, ok := policy.AsLoadError(err)
			if !ok {
				t.Fatalf("期望 *LoadError，实际 %T: %v", err, err)
			}
			if !containsCode(le, tc.wantCode) {
				t.Fatalf("期望原因码包含 %s，实际 %s; %v", tc.wantCode, le.Code, le.Details)
			}
			t.Logf("业务[加载校验] 用例=%-18s 正确拒绝，原因码=%s 明细=%d 条", tc.name, tc.wantCode, len(le.Details))
		})
	}
}

// 业务：合法文档应通过校验。
func TestDocumentValidation_Valid(t *testing.T) {
	doc := policy.Document{Version: "1.0.0", Rules: []policy.Rule{
		{ID: "r1", Effect: "allow", Subjects: []string{"u"}, Actions: []string{"a"}, Resources: []string{"r"},
			Conditions: []policy.Condition{{Key: "env", Op: "in", Values: []interface{}{"prod", "stg"}}}},
	}}
	if err := doc.Validate(); err != nil {
		t.Fatalf("合法文档不应报错: %v", err)
	}
	t.Logf("业务[加载校验] 用例=合法文档 通过校验")
}

func containsCode(le *policy.LoadError, code string) bool {
	if le.Code == code {
		return true
	}
	for _, d := range le.Details {
		if d.Code == code {
			return true
		}
	}
	if strings.Contains(le.Error(), code) {
		return true
	}
	return false
}
