package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Effect 是规则的裁决效果。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// ConditionOp 是规则属性条件支持的运算符。
type ConditionOp string

const (
	OpEq          ConditionOp = "eq"
	OpNotEq       ConditionOp = "ne"
	OpIn          ConditionOp = "in"
	OpNotIn       ConditionOp = "nin"
	OpExists      ConditionOp = "exists"
	OpNotExists   ConditionOp = "not_exists"
	OpPrefix      ConditionOp = "prefix"
	OpSuffix      ConditionOp = "suffix"
	OpGreaterThan ConditionOp = "gt"
	OpLessThan    ConditionOp = "lt"
)

// Rule 描述一条零信任访问规则。
type Rule struct {
	ID          string      `json:"id"`
	Description string      `json:"description,omitempty"`
	Effect      Effect      `json:"effect"`
	Subjects    []string    `json:"subjects"`
	Actions     []string    `json:"actions"`
	Resources   []string    `json:"resources"`
	Conditions  []Condition `json:"conditions,omitempty"`
	Priority    int         `json:"priority,omitempty"`
}

// Condition 描述基于请求属性的判定条件。
type Condition struct {
	Key    string        `json:"key"`
	Op     ConditionOp   `json:"op"`
	Values []interface{} `json:"values,omitempty"`
}

// Document 是策略文件的完整结构。
type Document struct {
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules"`
}

// Request 是一次访问请求。
type Request struct {
	Subject    string                 `json:"subject"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Decision 是一次评估的完整结论，可用于审计与复现。
type Decision struct {
	Allowed       bool     `json:"allowed"`
	ReasonCode    string   `json:"reason_code"`
	PolicyVersion string   `json:"policy_version"`
	MatchedRuleID string   `json:"matched_rule_id,omitempty"`
	Effect        string   `json:"effect,omitempty"`
	Message       string   `json:"message"`
	Candidates    []string `json:"candidates,omitempty"`
	EvaluatedAt   string   `json:"evaluated_at"`
	Request       *Request `json:"request"`
}

// 原因码：对调用方可区分、可预期。
const (
	ReasonAllowMatch     = "ALLOW_MATCH"
	ReasonDenyMatch      = "DENY_MATCH"
	ReasonDenyDefault    = "DENY_DEFAULT"
	ReasonDenyMalformed  = "DENY_MALFORMED_REQUEST"
	ReasonDenyUnknownSbj = "DENY_UNKNOWN_SUBJECT"
)

// Validate 对文档做静态校验（规则间冲突由 ValidateConflicts 负责）。
func (d *Document) Validate() error {
	if strings.TrimSpace(d.Version) == "" {
		return newLoadError(CodeVersionEmpty, "policy version must not be empty", nil)
	}
	if len(d.Rules) == 0 {
		return newLoadError(CodeNoRules, fmt.Sprintf("policy %s must contain at least one rule", d.Version), nil)
	}
	seen := make(map[string]struct{}, len(d.Rules))
	var errs []LoadErrorDetail
	for i := range d.Rules {
		r := &d.Rules[i]
		errs = append(errs, validateRule(r)...)
		if _, dup := seen[r.ID]; dup {
			errs = append(errs, LoadErrorDetail{RuleID: r.ID, Code: CodeDuplicateRule, Message: "duplicate rule id"})
		}
		seen[r.ID] = struct{}{}
	}
	if len(errs) > 0 {
		return newLoadError(CodeInvalidRule, "one or more rules are invalid", errs)
	}
	return nil
}

func validateRule(r *Rule) []LoadErrorDetail {
	var errs []LoadErrorDetail
	add := func(code, msg string) {
		errs = append(errs, LoadErrorDetail{RuleID: r.ID, Code: code, Message: msg})
	}
	if strings.TrimSpace(r.ID) == "" {
		add(CodeInvalidRule, "rule id must not be empty")
	}
	switch r.Effect {
	case EffectAllow, EffectDeny:
	default:
		add(CodeInvalidEffect, fmt.Sprintf("effect must be %q or %q, got %q", EffectAllow, EffectDeny, r.Effect))
	}
	if len(r.Subjects) == 0 || hasBlank(r.Subjects) {
		add(CodeInvalidRule, "subjects must be non-empty and contain no blank entries")
	}
	if len(r.Actions) == 0 || hasBlank(r.Actions) {
		add(CodeInvalidRule, "actions must be non-empty and contain no blank entries")
	}
	if len(r.Resources) == 0 || hasBlank(r.Resources) {
		add(CodeInvalidRule, "resources must be non-empty and contain no blank entries")
	}
	for i := range r.Conditions {
		c := &r.Conditions[i]
		if strings.TrimSpace(c.Key) == "" {
			add(CodeInvalidCondition, "condition key must not be empty")
			continue
		}
		if !knownOps[c.Op] {
			add(CodeInvalidCondition, fmt.Sprintf("condition %q uses unsupported op %q", c.Key, c.Op))
			continue
		}
		if needsValue[c.Op] && len(c.Values) == 0 {
			add(CodeInvalidCondition, fmt.Sprintf("condition %q op %q requires at least one value", c.Key, c.Op))
		}
		for _, v := range c.Values {
			switch v.(type) {
			case string, bool, float64, int, int64, nil:
			default:
				add(CodeInvalidCondition, fmt.Sprintf("condition %q contains unsupported value type %T", c.Key, v))
			}
		}
	}
	return errs
}

var knownOps = map[ConditionOp]bool{
	OpEq: true, OpNotEq: true, OpIn: true, OpNotIn: true,
	OpExists: true, OpNotExists: true, OpPrefix: true, OpSuffix: true,
	OpGreaterThan: true, OpLessThan: true,
}

var needsValue = map[ConditionOp]bool{
	OpEq: true, OpNotEq: true, OpIn: true, OpNotIn: true,
	OpPrefix: true, OpSuffix: true, OpGreaterThan: true, OpLessThan: true,
}

func hasBlank(xs []string) bool {
	for _, x := range xs {
		if strings.TrimSpace(x) == "" {
			return true
		}
	}
	return false
}

// canonicalKey 返回规则选择器的稳定签名，用于重复/矛盾检测。
// 当 subject/action/resource 集合与条件集合完全一致时，两条规则不可区分。
func (r *Rule) canonicalKey() string {
	return joinSet(r.Subjects) + "|" + joinSet(r.Actions) + "|" + joinSet(r.Resources) + "|" + canonicalConditions(r.Conditions)
}

func joinSet(xs []string) string {
	cp := append([]string(nil), xs...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

func canonicalConditions(cs []Condition) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		vs := make([]string, 0, len(c.Values))
		for _, v := range c.Values {
			vs = append(vs, fmt.Sprintf("%v", v))
		}
		sort.Strings(vs)
		parts = append(parts, c.Key+string(c.Op)+"["+strings.Join(vs, ",")+"]")
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
