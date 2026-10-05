package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

// ReasonCode explains a decision in a machine-readable way.
type ReasonCode string

const (
	ReasonAllowedByRule     ReasonCode = "ALLOWED_BY_RULE"
	ReasonDeniedByRule      ReasonCode = "DENIED_BY_RULE"
	ReasonDeniedDefault     ReasonCode = "DENIED_DEFAULT"
	ReasonDeniedMissingAttr ReasonCode = "DENIED_MISSING_ATTRIBUTE"
	ReasonDeniedUnknownSubj ReasonCode = "DENIED_UNKNOWN_SUBJECT"
	ReasonDeniedInvalidReq  ReasonCode = "DENIED_INVALID_REQUEST"
	ReasonDeniedNoPolicy    ReasonCode = "DENIED_NO_POLICY_LOADED"
)

// Request is a single access request.
type Request struct {
	Subject  string `json:"subject"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// Decision is the explainable outcome of evaluating one request.
type Decision struct {
	Allow         bool       `json:"allow"`
	Reason        ReasonCode `json:"reason"`
	MatchedRuleID string     `json:"matched_rule_id,omitempty"`
	PolicyVersion string     `json:"policy_version"`
	Explanation   string     `json:"explanation"`
}

// Engine serves evaluations from an atomically swapped, immutable PolicySet.
// The zero value is ready to use and denies everything until Load succeeds.
type Engine struct {
	current atomic.Pointer[PolicySet]
}

// Load parses and fully validates a policy document. The new version is
// swapped in atomically only if the entire document is valid; on any error
// the previously active version keeps serving untouched.
func (e *Engine) Load(r io.Reader) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var set PolicySet
	if err := dec.Decode(&set); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	if err := set.Validate(); err != nil {
		return err
	}
	e.current.Store(&set)
	return nil
}

// Version returns the currently active policy version, or "" if none.
func (e *Engine) Version() string {
	if p := e.current.Load(); p != nil {
		return p.Version
	}
	return ""
}

// Evaluate decides a single request against one consistent policy snapshot.
// It never panics and never blocks; any malformed input results in a deny.
func (e *Engine) Evaluate(req Request) (d Decision) {
	defer func() {
		if r := recover(); r != nil {
			d = Decision{Allow: false, Reason: ReasonDeniedInvalidReq,
				Explanation: fmt.Sprintf("internal error during evaluation: %v", r)}
		}
	}()

	set := e.current.Load()
	if set == nil {
		return Decision{Allow: false, Reason: ReasonDeniedNoPolicy,
			Explanation: "no policy version is active; default deny"}
	}
	d.PolicyVersion = set.Version

	if strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.Resource) == "" ||
		strings.TrimSpace(req.Action) == "" {
		d.Allow, d.Reason = false, ReasonDeniedMissingAttr
		d.Explanation = "subject, resource and action are all required; default deny"
		return d
	}
	if !set.KnownSubject(req.Subject) {
		d.Allow, d.Reason = false, ReasonDeniedUnknownSubj
		d.Explanation = fmt.Sprintf("subject %q is not in the known-subject registry", req.Subject)
		return d
	}

	matched := set.matchingRules(req.Subject, req.Resource, req.Action)
	if len(matched) == 0 {
		d.Allow, d.Reason = false, ReasonDeniedDefault
		d.Explanation = "no rule matched; default deny"
		return d
	}
	top := matched[0]
	d.MatchedRuleID = top.ID
	if top.Effect == EffectDeny {
		d.Allow, d.Reason = false, ReasonDeniedByRule
		d.Explanation = fmt.Sprintf("denied by rule %q (deny rules take precedence)", top.ID)
		return d
	}
	d.Allow, d.Reason = true, ReasonAllowedByRule
	d.Explanation = fmt.Sprintf("allowed by rule %q", top.ID)
	return d
}
