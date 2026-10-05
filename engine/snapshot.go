package engine

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// compiledRule 是编译后、对评估只读的规则形态。
type compiledRule struct {
	rule      policy.Rule
	subjects  []stringMatcher
	actions   []stringMatcher
	resources []resourcePattern
}

type stringMatcher func(string) bool

type resourcePattern struct {
	raw   string
	match func(string) bool
}

// Snapshot 是某个版本策略的完整不可变视图。
// 一旦构建完成，其内容在整个生命周期内不会再被修改，
// 因此并发评估无需加锁即可安全共享。
type Snapshot struct {
	Version    string
	rules      []compiledRule
	subjectSet map[string]struct{}
}

// RuleCount 返回快照内规则数量（供 CLI 校验输出使用）。
func (s *Snapshot) RuleCount() int { return len(s.rules) }

// Compile 在全部静态校验与冲突检测通过后，把文档编译为不可变快照。
func Compile(doc *policy.Document) (*Snapshot, error) {
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	report := policy.DetectConflicts(doc.Rules)
	if report.HasErrors() {
		var details []policy.LoadErrorDetail
		details = append(details, report.Duplicates...)
		details = append(details, report.Conflicts...)
		return nil, policy.NewLoadError(policy.CodeConflictingRule,
			"policy contains duplicate or contradictory rules", details)
	}

	snap := &Snapshot{
		Version:    doc.Version,
		subjectSet: make(map[string]struct{}),
	}
	// 按评估兜底顺序预排序规则，使匹配结果与文件书写顺序完全无关：
	// priority 降序 -> rule id 升序。effect 不参与这里的顺序，
	// deny 优先在裁决阶段独立执行（双重保证）。
	rules := append([]policy.Rule(nil), doc.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
	for i := range rules {
		r := rules[i]
		cr := compiledRule{
			rule:     r,
			subjects: compileMatchers(r.Subjects),
			actions:  compileMatchers(r.Actions),
		}
		for _, res := range r.Resources {
			cr.resources = append(cr.resources, resourcePattern{
				raw:   res,
				match: compileResource(res),
			})
		}
		snap.rules = append(snap.rules, cr)
		for _, s := range r.Subjects {
			snap.subjectSet[s] = struct{}{}
		}
	}
	return snap, nil
}

// compileMatchers 把主体/动作列表编译成精确或 glob 匹配器。
func compileMatchers(xs []string) []stringMatcher {
	ms := make([]stringMatcher, 0, len(xs))
	for _, x := range xs {
		if !strings.ContainsAny(x, "*?") {
			literal := x
			ms = append(ms, func(s string) bool { return s == literal })
			continue
		}
		pattern := x
		ms = append(ms, func(s string) bool {
			ok, err := filepath.Match(pattern, s)
			return err == nil && ok
		})
	}
	return ms
}

// compileResource 支持精确匹配与 glob（* 不跨路径分隔符，** 跨分隔符）。
// 形如 "bucket/*/obj" 或 "repo/**"。其余字符按字面量处理。
func compileResource(pattern string) func(string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return func(s string) bool { return s == pattern }
	}
	// 使用标准库 Match 的语义，但允许 ** 跨 '/'（转成逐个 filepath.Match 分段校验）。
	return func(s string) bool {
		return globMatch(pattern, s)
	}
}

// globMatch 实现 ** 跨分隔符的 glob；单段 * 不匹配 '/'。
func globMatch(pattern, name string) bool {
	ps := strings.Split(pattern, "/")
	ns := strings.Split(name, "/")
	return matchSegments(ps, ns)
}

func matchSegments(p, n []string) bool {
	for len(p) > 0 {
		seg := p[0]
		if seg == "**" {
			if len(p) == 1 {
				return true
			}
			for k := 0; k <= len(n); k++ {
				if matchSegments(p[1:], n[k:]) {
					return true
				}
			}
			return false
		}
		if len(n) == 0 {
			return false
		}
		ok, err := filepath.Match(seg, n[0])
		if err != nil || !ok {
			return false
		}
		p = p[1:]
		n = n[1:]
	}
	return len(n) == 0
}
