package policy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func loadOrFail(t *testing.T, e *Engine, jsonDoc string) {
	t.Helper()
	if err := e.Load(strings.NewReader(jsonDoc)); err != nil {
		t.Fatalf("load: %v", err)
	}
}

const docV1 = `{
  "version": "v1",
  "subjects": ["alice", "bob"],
  "rules": [
    {"id":"allow-alice","effect":"allow","subjects":["alice"],"resources":["doc"],"actions":["read"],"priority":1},
    {"id":"deny-delete","effect":"deny","subjects":["*"],"resources":["*"],"actions":["delete"],"priority":1}
  ]
}`

// v2 flips alice's read from allow to deny, so version switches are observable.
const docV2 = `{
  "version": "v2",
  "subjects": ["alice", "bob"],
  "rules": [
    {"id":"deny-alice","effect":"deny","subjects":["alice"],"resources":["doc"],"actions":["read"],"priority":1},
    {"id":"deny-delete","effect":"deny","subjects":["*"],"resources":["*"],"actions":["delete"],"priority":1}
  ]
}`

func TestEvaluateAllowAndDenyByRule(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)

	d := e.Evaluate(Request{Subject: "alice", Resource: "doc", Action: "read"})
	if !d.Allow || d.Reason != ReasonAllowedByRule || d.MatchedRuleID != "allow-alice" || d.PolicyVersion != "v1" {
		t.Fatalf("unexpected allow decision: %+v", d)
	}
	d = e.Evaluate(Request{Subject: "alice", Resource: "doc", Action: "delete"})
	if d.Allow || d.Reason != ReasonDeniedByRule || d.MatchedRuleID != "deny-delete" {
		t.Fatalf("unexpected deny decision: %+v", d)
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)
	d := e.Evaluate(Request{Subject: "bob", Resource: "doc", Action: "read"})
	if d.Allow || d.Reason != ReasonDeniedDefault {
		t.Fatalf("want default deny, got %+v", d)
	}
}

func TestEvaluateNoPolicyLoaded(t *testing.T) {
	e := &Engine{}
	d := e.Evaluate(Request{Subject: "alice", Resource: "doc", Action: "read"})
	if d.Allow || d.Reason != ReasonDeniedNoPolicy {
		t.Fatalf("want no-policy deny, got %+v", d)
	}
}

func TestEvaluateMalformedRequests(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)
	cases := map[string]Request{
		"missing subject":  {Resource: "doc", Action: "read"},
		"missing resource": {Subject: "alice", Action: "read"},
		"missing action":   {Subject: "alice", Resource: "doc"},
		"all empty":        {},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			d := e.Evaluate(req)
			if d.Allow || d.Reason != ReasonDeniedMissingAttr {
				t.Fatalf("want missing-attribute deny, got %+v", d)
			}
		})
	}
}

func TestEvaluateUnknownSubject(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)
	d := e.Evaluate(Request{Subject: "mallory", Resource: "doc", Action: "read"})
	if d.Allow || d.Reason != ReasonDeniedUnknownSubj {
		t.Fatalf("want unknown-subject deny, got %+v", d)
	}
}

func TestFailedReloadKeepsOldVersion(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)

	bad := []string{
		`{"version":"v2","rules":[{"id":"x","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]}]}`, // duplicate-free but...
		`not json`,
		`{"version":"v3","rules":[{"id":"a","effect":"allow","subjects":["*"],"resources":["*"],"actions":["*"]},{"id":"b","effect":"deny","subjects":["*"],"resources":["*"],"actions":["*"]}]}`,
	}
	_ = bad[0] // first doc is actually valid; use only invalid ones below
	for _, doc := range bad[1:] {
		if err := e.Load(strings.NewReader(doc)); err == nil {
			t.Fatalf("expected load failure for %s", doc)
		}
		if e.Version() != "v1" {
			t.Fatalf("failed reload changed version to %q", e.Version())
		}
		d := e.Evaluate(Request{Subject: "alice", Resource: "doc", Action: "read"})
		if !d.Allow || d.PolicyVersion != "v1" {
			t.Fatalf("old version not serving after failed reload: %+v", d)
		}
	}
}

func TestVersionSwitchExplainsDecisionChange(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)
	req := Request{Subject: "alice", Resource: "doc", Action: "read"}
	before := e.Evaluate(req)
	loadOrFail(t, e, docV2)
	after := e.Evaluate(req)
	if !before.Allow || after.Allow {
		t.Fatalf("expected allow->deny across versions, got %v -> %v", before.Allow, after.Allow)
	}
	if before.PolicyVersion != "v1" || after.PolicyVersion != "v2" ||
		before.MatchedRuleID != "allow-alice" || after.MatchedRuleID != "deny-alice" {
		t.Fatalf("decisions not attributable to versions: %+v / %+v", before, after)
	}
}

// TestHotReloadRace hammers Evaluate from many goroutines while flipping the
// policy between v1 and v2. Every decision must be attributable to exactly
// one complete version: v1 allows alice, v2 denies her; no mixed state may
// ever appear. Run with -race.
func TestHotReloadRace(t *testing.T) {
	e := &Engine{}
	loadOrFail(t, e, docV1)
	req := Request{Subject: "alice", Resource: "doc", Action: "read"}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan string, 1024)

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				d := e.Evaluate(req)
				switch d.PolicyVersion {
				case "v1":
					if !d.Allow || d.MatchedRuleID != "allow-alice" {
						errs <- fmt.Sprintf("inconsistent v1 decision: %+v", d)
					}
				case "v2":
					if d.Allow || d.MatchedRuleID != "deny-alice" {
						errs <- fmt.Sprintf("inconsistent v2 decision: %+v", d)
					}
				default:
					errs <- fmt.Sprintf("decision from unknown version: %+v", d)
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		doc := docV1
		if i%2 == 1 {
			doc = docV2
		}
		if err := e.Load(strings.NewReader(doc)); err != nil {
			t.Fatalf("reload: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
}
