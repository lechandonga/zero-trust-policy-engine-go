package engine

import (
	"fmt"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// ChangeExplanation 解释同一请求在两个策略版本之间的结论变化。
type ChangeExplanation struct {
	Resource    string
	FromVersion string
	ToVersion   string
	Changed     bool
	FromAllowed bool
	ToAllowed   bool
	FromRuleID  string
	ToRuleID    string
	FromReason  string
	ToReason    string
	Summary     string
}

// ExplainChange 用两个历史版本复现同一请求，并生成人类可读的变化解释。
func (e *Engine) ExplainChange(fromVersion, toVersion string, req *policy.Request) (*ChangeExplanation, error) {
	from, err := e.Replay(fromVersion, req)
	if err != nil {
		return nil, fmt.Errorf("replay from-version: %w", err)
	}
	to, err := e.Replay(toVersion, req)
	if err != nil {
		return nil, fmt.Errorf("replay to-version: %w", err)
	}
	c := &ChangeExplanation{
		Resource:    req.Resource,
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Changed: from.Allowed != to.Allowed || from.MatchedRuleID != to.MatchedRuleID ||
			from.ReasonCode != to.ReasonCode,
		FromAllowed: from.Allowed,
		ToAllowed:   to.Allowed,
		FromRuleID:  from.MatchedRuleID,
		ToRuleID:    to.MatchedRuleID,
		FromReason:  from.ReasonCode,
		ToReason:    to.ReasonCode,
	}
	switch {
	case !c.Changed:
		c.Summary = fmt.Sprintf("decision unchanged between %s and %s (%s)",
			fromVersion, toVersion, from.ReasonCode)
	case !from.Allowed && to.Allowed:
		c.Summary = fmt.Sprintf("request %q flipped DENY(%s, rule=%s) -> ALLOW(rule=%s) due to policy %s -> %s",
			req.Resource, from.ReasonCode, dash(from.MatchedRuleID), dash(to.MatchedRuleID),
			fromVersion, toVersion)
	case from.Allowed && !to.Allowed:
		c.Summary = fmt.Sprintf("request %q flipped ALLOW(rule=%s) -> DENY(%s, rule=%s) due to policy %s -> %s",
			req.Resource, dash(from.MatchedRuleID), to.ReasonCode, dash(to.MatchedRuleID),
			fromVersion, toVersion)
	default:
		c.Summary = fmt.Sprintf("decision reason changed: %s -> %s between %s and %s",
			from.ReasonCode, to.ReasonCode, fromVersion, toVersion)
	}
	return c, nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
