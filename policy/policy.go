package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Effect is the outcome a rule produces when it matches.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule matches requests by subject/resource/action sets. "*" matches anything.
type Rule struct {
	ID        string   `json:"id"`
	Effect    Effect   `json:"effect"`
	Subjects  []string `json:"subjects"`
	Resources []string `json:"resources"`
	Actions   []string `json:"actions"`
	Priority  int      `json:"priority"`
}

// PolicySet is an immutable, fully validated snapshot of a policy version.
type PolicySet struct {
	Version  string   `json:"version"`
	Subjects []string `json:"subjects"` // known subject registry; empty disables the check
	Rules    []Rule   `json:"rules"`
}

// ValidationKind distinguishes load-time rejection causes.
type ValidationKind string

const (
	KindInvalidField     ValidationKind = "invalid_field"
	KindDuplicateRuleID  ValidationKind = "duplicate_rule_id"
	KindConflictingRules ValidationKind = "conflicting_rules"
)

// ValidationError describes a single policy validation failure.
type ValidationError struct {
	Kind    ValidationKind
	RuleIDs []string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s (rules: %s)", e.Kind, e.Message, strings.Join(e.RuleIDs, ","))
}

// Validate checks the whole set; any error means the set must not be activated.
func (p *PolicySet) Validate() error {
	if strings.TrimSpace(p.Version) == "" {
		return &ValidationError{Kind: KindInvalidField, Message: "version must not be empty"}
	}
	for i := range p.Subjects {
		if strings.TrimSpace(p.Subjects[i]) == "" {
			return &ValidationError{Kind: KindInvalidField, Message: "subject entries must not be empty"}
		}
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if err := validateRule(r); err != nil {
			return err
		}
		if seen[r.ID] {
			return &ValidationError{Kind: KindDuplicateRuleID, RuleIDs: []string{r.ID},
				Message: "duplicate rule id"}
		}
		seen[r.ID] = true
	}
	// Pairwise conflict detection: overlapping match space with different
	// effects is contradictory and must be rejected instead of silently
	// resolved at evaluation time.
	for i := 0; i < len(p.Rules); i++ {
		for j := i + 1; j < len(p.Rules); j++ {
			a, b := p.Rules[i], p.Rules[j]
			if a.Effect != b.Effect && rulesOverlap(a, b) {
				return &ValidationError{
					Kind:    KindConflictingRules,
					RuleIDs: []string{a.ID, b.ID},
					Message: fmt.Sprintf("rules with effects %q/%q overlap on match space", a.Effect, b.Effect),
				}
			}
		}
	}
	return nil
}

func validateRule(r *Rule) error {
	bad := func(msg string) error {
		return &ValidationError{Kind: KindInvalidField, RuleIDs: []string{r.ID}, Message: msg}
	}
	if strings.TrimSpace(r.ID) == "" {
		return bad("rule id must not be empty")
	}
	if r.Effect != EffectAllow && r.Effect != EffectDeny {
		return bad(fmt.Sprintf("effect must be %q or %q, got %q", EffectAllow, EffectDeny, r.Effect))
	}
	if len(r.Subjects) == 0 || len(r.Resources) == 0 || len(r.Actions) == 0 {
		return bad("subjects, resources and actions must each contain at least one entry")
	}
	for _, list := range [][]string{r.Subjects, r.Resources, r.Actions} {
		for _, v := range list {
			if strings.TrimSpace(v) == "" {
				return bad("match entries must not be empty")
			}
		}
	}
	return nil
}

func setOverlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == "*" || y == "*" || x == y {
				return true
			}
		}
	}
	return false
}

func rulesOverlap(a, b Rule) bool {
	return setOverlaps(a.Subjects, b.Subjects) &&
		setOverlaps(a.Resources, b.Resources) &&
		setOverlaps(a.Actions, b.Actions)
}

func matchAny(set []string, v string) bool {
	for _, s := range set {
		if s == "*" || s == v {
			return true
		}
	}
	return false
}

// Matches reports whether the rule matches a fully populated request.
func (r *Rule) Matches(subject, resource, action string) bool {
	return matchAny(r.Subjects, subject) && matchAny(r.Resources, resource) && matchAny(r.Actions, action)
}

// KnownSubject reports whether the subject is registered. An empty registry
// disables the check (all subjects considered known).
func (p *PolicySet) KnownSubject(subject string) bool {
	if len(p.Subjects) == 0 {
		return true
	}
	for _, s := range p.Subjects {
		if s == subject {
			return true
		}
	}
	return false
}

// matchingRules returns all matching rules in a deterministic order:
// deny first, then higher priority, then lexicographic rule id. The result
// never depends on file order or map iteration order.
func (p *PolicySet) matchingRules(subject, resource, action string) []Rule {
	var out []Rule
	for _, r := range p.Rules {
		if r.Matches(subject, resource, action) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Effect == EffectDeny) != (b.Effect == EffectDeny) {
			return a.Effect == EffectDeny
		}
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.ID < b.ID
	})
	return out
}

var ErrNoPolicyLoaded = errors.New("no policy version loaded")
