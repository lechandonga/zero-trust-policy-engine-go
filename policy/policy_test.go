package policy

import (
	"errors"
	"strings"
	"testing"
)

func validSet() *PolicySet {
	return &PolicySet{
		Version:  "v1",
		Subjects: []string{"alice", "bob"},
		Rules: []Rule{
			{ID: "r1", Effect: EffectAllow, Subjects: []string{"alice"}, Resources: []string{"doc"}, Actions: []string{"read"}},
			{ID: "r2", Effect: EffectDeny, Subjects: []string{"bob"}, Resources: []string{"*"}, Actions: []string{"delete"}},
		},
	}
}

func TestValidateAcceptsValidSet(t *testing.T) {
	if err := validSet().Validate(); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
}

func TestValidateInvalidFields(t *testing.T) {
	cases := map[string]func(*PolicySet){
		"empty version":   func(p *PolicySet) { p.Version = " " },
		"empty rule id":   func(p *PolicySet) { p.Rules[0].ID = "" },
		"bad effect":      func(p *PolicySet) { p.Rules[0].Effect = "maybe" },
		"empty subjects":  func(p *PolicySet) { p.Rules[0].Subjects = nil },
		"empty match val": func(p *PolicySet) { p.Rules[0].Actions = []string{" "} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validSet()
			mutate(p)
			err := p.Validate()
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Kind != KindInvalidField {
				t.Fatalf("want invalid_field, got %v", err)
			}
		})
	}
}

func TestValidateDuplicateRuleID(t *testing.T) {
	p := validSet()
	p.Rules = append(p.Rules, Rule{ID: "r1", Effect: EffectAllow,
		Subjects: []string{"bob"}, Resources: []string{"x"}, Actions: []string{"read"}})
	var ve *ValidationError
	if err := p.Validate(); !errors.As(err, &ve) || ve.Kind != KindDuplicateRuleID {
		t.Fatalf("want duplicate_rule_id, got %v", err)
	}
}

func TestValidateConflictingRules(t *testing.T) {
	p := validSet()
	// Overlaps r1 (alice/doc/read) but with opposite effect.
	p.Rules = append(p.Rules, Rule{ID: "r3", Effect: EffectDeny,
		Subjects: []string{"alice"}, Resources: []string{"doc"}, Actions: []string{"read"}})
	var ve *ValidationError
	err := p.Validate()
	if !errors.As(err, &ve) || ve.Kind != KindConflictingRules {
		t.Fatalf("want conflicting_rules, got %v", err)
	}
	if len(ve.RuleIDs) != 2 {
		t.Fatalf("conflict should name both rules, got %v", ve.RuleIDs)
	}
}

func TestValidateWildcardConflict(t *testing.T) {
	p := validSet()
	p.Rules = append(p.Rules, Rule{ID: "r3", Effect: EffectDeny,
		Subjects: []string{"*"}, Resources: []string{"doc"}, Actions: []string{"read"}})
	var ve *ValidationError
	if err := p.Validate(); !errors.As(err, &ve) || ve.Kind != KindConflictingRules {
		t.Fatalf("wildcard overlap should conflict, got %v", err)
	}
}

func TestMatchingOrderIsDeterministic(t *testing.T) {
	mk := func(id string, eff Effect, prio int) Rule {
		return Rule{ID: id, Effect: eff, Priority: prio, Subjects: []string{"*"}, Resources: []string{"*"}, Actions: []string{"*"}}
	}
	// Same rules, different file order: resolution must be identical.
	a := &PolicySet{Version: "v1", Rules: []Rule{mk("b-allow", EffectAllow, 5), mk("a-deny", EffectDeny, 1), mk("c-allow", EffectAllow, 9)}}
	b := &PolicySet{Version: "v1", Rules: []Rule{mk("c-allow", EffectAllow, 9), mk("a-deny", EffectDeny, 1), mk("b-allow", EffectAllow, 5)}}
	ra, rb := a.matchingRules("s", "r", "x"), b.matchingRules("s", "r", "x")
	if len(ra) != 3 || ra[0].ID != "a-deny" || ra[1].ID != "c-allow" || ra[2].ID != "b-allow" {
		t.Fatalf("unexpected order: %v", ra)
	}
	for i := range ra {
		if ra[i].ID != rb[i].ID {
			t.Fatalf("order depends on file order: %v vs %v", ra, rb)
		}
	}
}

func TestEngineLoadParseError(t *testing.T) {
	e := &Engine{}
	if err := e.Load(strings.NewReader(`{"version":`)); err == nil {
		t.Fatal("expected parse error")
	}
}
