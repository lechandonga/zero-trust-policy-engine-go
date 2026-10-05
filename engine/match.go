package engine

import (
	"fmt"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// matches 判断请求是否命中规则的选择器与全部条件。
func (cr *compiledRule) matches(req *policy.Request) bool {
	if !anyMatcher(cr.subjects, req.Subject) {
		return false
	}
	if !anyMatcher(cr.actions, req.Action) {
		return false
	}
	resourceHit := false
	for _, rp := range cr.resources {
		if rp.match(req.Resource) {
			resourceHit = true
			break
		}
	}
	if !resourceHit {
		return false
	}
	for i := range cr.rule.Conditions {
		if !evalCondition(&cr.rule.Conditions[i], req.Attributes) {
			return false
		}
	}
	return true
}

func anyMatcher(ms []stringMatcher, s string) bool {
	for _, m := range ms {
		if m(s) {
			return true
		}
	}
	return false
}

// evalCondition 对单条属性条件求值。
// 属性缺失时：exists 返回 false，not_exists 返回 true，其余运算一律 false。
// 这意味着“需要某属性才能放行”的 allow 规则不会因属性缺失而误放行。
func evalCondition(c *policy.Condition, attrs map[string]interface{}) bool {
	val, present := attrs[c.Key]
	switch c.Op {
	case policy.OpExists:
		return present
	case policy.OpNotExists:
		return !present
	case policy.OpIn:
		if !present {
			return false
		}
		return anyValueEquals(c.Values, val)
	case policy.OpNotIn:
		if !present {
			return false
		}
		return !anyValueEquals(c.Values, val)
	case policy.OpEq:
		if !present {
			return false
		}
		return len(c.Values) > 0 && compareValue(c.Values[0], val) == 0
	case policy.OpNotEq:
		if !present {
			return false
		}
		return len(c.Values) > 0 && compareValue(c.Values[0], val) != 0
	case policy.OpPrefix:
		s, ok := val.(string)
		return ok && present && len(c.Values) > 0 && hasString(c.Values) &&
			hasPrefixAny(s, c.Values)
	case policy.OpSuffix:
		s, ok := val.(string)
		return ok && present && len(c.Values) > 0 && hasSuffixAny(s, c.Values)
	case policy.OpGreaterThan, policy.OpLessThan:
		if !present {
			return false
		}
		cmp, ok := numericCompare(val, c.Values[0])
		if !ok {
			return false
		}
		if c.Op == policy.OpGreaterThan {
			return cmp > 0
		}
		return cmp < 0
	default:
		return false
	}
}

func anyValueEquals(values []interface{}, v interface{}) bool {
	for _, want := range values {
		if compareValue(want, v) == 0 {
			return true
		}
	}
	return false
}

func hasString(vs []interface{}) bool {
	for _, v := range vs {
		if _, ok := v.(string); ok {
			return true
		}
	}
	return false
}

func hasPrefixAny(s string, vs []interface{}) bool {
	for _, v := range vs {
		if p, ok := v.(string); ok && startsWith(s, p) {
			return true
		}
	}
	return false
}

func hasSuffixAny(s string, vs []interface{}) bool {
	for _, v := range vs {
		if p, ok := v.(string); ok && endsWith(s, p) {
			return true
		}
	}
	return false
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// compareValue 按 JSON 标量语义比较；类型不同即视为不等，不做隐式转换。
// 返回 -1/0/1；不可比较的类型组合返回 1（视为不同）。
func compareValue(a, b interface{}) int {
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return strCompare(av, bv)
		}
	case bool:
		if bv, ok := b.(bool); ok {
			if av == bv {
				return 0
			}
			if !av {
				return -1
			}
			return 1
		}
	case float64:
		if bv, ok := b.(float64); ok {
			return numCompare(av, bv)
		}
	case int:
		if bv, ok := b.(int); ok {
			return numCompare(float64(av), float64(bv))
		}
	case int64:
		if bv, ok := b.(int64); ok {
			return numCompare(float64(av), float64(bv))
		}
	case nil:
		if b == nil {
			return 0
		}
	}
	return 1
}

func strCompare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func numCompare(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func numericCompare(a, b interface{}) (int, bool) {
	af, aok := toFloat64(a)
	bf, bok := toFloat64(b)
	if !aok || !bok {
		return 0, false
	}
	return numCompare(af, bf), true
}

func toFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		return 0, false
	}
}

func describeRequestValidationError(req *policy.Request) string {
	if req == nil {
		return "request is nil"
	}
	if req.Subject == "" {
		return "request subject must not be empty"
	}
	if req.Action == "" {
		return fmt.Sprintf("request action must not be empty (subject=%s)", req.Subject)
	}
	if req.Resource == "" {
		return fmt.Sprintf("request resource must not be empty (subject=%s action=%s)", req.Subject, req.Action)
	}
	return ""
}
