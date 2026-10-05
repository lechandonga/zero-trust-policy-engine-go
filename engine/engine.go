// Package engine 实现本地零信任访问决策引擎：
// 不可变策略快照 + 原子版本切换 + 默认拒绝的并发安全评估。
package engine

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lechandonga/zero-trust-policy-engine-go/policy"
)

// Engine 持有当前生效的策略快照以及历史版本，评估与热更新可并发进行。
type Engine struct {
	current atomic.Pointer[Snapshot]

	mu         sync.RWMutex
	history    map[string]*Snapshot
	maxHistory int

	decMu        sync.Mutex
	decisions    []policy.Decision
	maxDecisions int
	now          func() time.Time
}

// Option 配置引擎。
type Option func(*Engine)

// WithHistoryLimit 设置保留的历史策略版本数量（含当前版本）。
func WithHistoryLimit(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.maxHistory = n
		}
	}
}

// WithDecisionLogLimit 设置保留的历史决策条数。
func WithDecisionLogLimit(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.maxDecisions = n
		}
	}
}

// New 创建空引擎。没有任何策略时，所有请求按默认拒绝处理。
func New(opts ...Option) *Engine {
	e := &Engine{
		history:      make(map[string]*Snapshot),
		maxHistory:   10,
		maxDecisions: 1024,
		now:          time.Now,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Load 原子地加载新版本：编译失败时保留旧版本继续服务，不出现半生效状态。
// 版本号必须单调前进（不允许空、重复或回退）。
func (e *Engine) Load(doc *policy.Document) error {
	snap, err := Compile(doc)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if old := e.current.Load(); old != nil {
		switch {
		case snap.Version == old.Version:
			return policy.NewLoadError(policy.CodeVersionSame,
				fmt.Sprintf("policy version %q is already active; bump the version to publish changes", snap.Version), nil)
		case compareVersions(snap.Version, old.Version) <= 0:
			return policy.NewLoadError(policy.CodeVersionDowngrade,
				fmt.Sprintf("refusing to downgrade policy: current=%q incoming=%q", old.Version, snap.Version), nil)
		}
	}

	// 快照完全构建完毕后才放入 map 并原子切换：读者要么看到整个旧版本，
	// 要么看到整个新版本，不会看到混合状态。
	e.history[snap.Version] = snap
	e.current.Store(snap)
	e.trimHistoryLocked()
	return nil
}

func (e *Engine) trimHistoryLocked() {
	if len(e.history) <= e.maxHistory {
		return
	}
	versions := make([]string, 0, len(e.history))
	for v := range e.history {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})
	drop := len(versions) - e.maxHistory
	for _, v := range versions[:drop] {
		if e.current.Load() != e.history[v] {
			delete(e.history, v)
		}
	}
}

// CurrentVersion 返回当前生效的策略版本；无策略时返回空串。
func (e *Engine) CurrentVersion() string {
	if s := e.current.Load(); s != nil {
		return s.Version
	}
	return ""
}

// SnapshotVersion 暴露指定版本快照是否仍保留在本地。
func (e *Engine) SnapshotVersion(version string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.history[version]
	return ok
}

// Evaluate 使用当前版本策略评估请求。任何异常输入都得到确定的拒绝结论。
func (e *Engine) Evaluate(req *policy.Request) policy.Decision {
	snap := e.current.Load()
	dec := e.evaluateWith(snap, req)
	e.recordDecision(dec)
	return dec
}

// Replay 使用历史版本复现同一请求的决策，用于审计与“结论变化”解释。
func (e *Engine) Replay(version string, req *policy.Request) (policy.Decision, error) {
	e.mu.RLock()
	snap, ok := e.history[version]
	e.mu.RUnlock()
	if !ok {
		return policy.Decision{}, fmt.Errorf("policy version %q is not retained locally", version)
	}
	dec := e.evaluateWith(snap, req)
	// 复现不写入决策日志，避免污染真实审计流。
	return dec, nil
}

// Decisions 返回已记录决策的副本，按评估时间顺序。
func (e *Engine) Decisions() []policy.Decision {
	e.decMu.Lock()
	defer e.decMu.Unlock()
	out := make([]policy.Decision, len(e.decisions))
	copy(out, e.decisions)
	return out
}

func (e *Engine) recordDecision(dec policy.Decision) {
	e.decMu.Lock()
	defer e.decMu.Unlock()
	e.decisions = append(e.decisions, dec)
	if len(e.decisions) > e.maxDecisions {
		e.decisions = e.decisions[len(e.decisions)-e.maxDecisions:]
	}
}

func (e *Engine) evaluateWith(snap *Snapshot, req *policy.Request) policy.Decision {
	base := policy.Decision{
		Allowed:     false,
		EvaluatedAt: e.now().UTC().Format(time.RFC3339Nano),
		Request:     req,
	}
	if snap != nil {
		base.PolicyVersion = snap.Version
	}

	if msg := describeRequestValidationError(req); msg != "" {
		base.ReasonCode = policy.ReasonDenyMalformed
		base.Message = msg
		return base
	}
	if snap == nil {
		base.ReasonCode = policy.ReasonDenyDefault
		base.Message = "no policy loaded; default deny"
		return base
	}

	var candidateIDs []string
	var allow, deny *compiledRule
	for i := range snap.rules {
		cr := &snap.rules[i]
		if !cr.matches(req) {
			continue
		}
		candidateIDs = append(candidateIDs, cr.rule.ID)
		// 确定性取舍（再次显式保证，不依赖任何遍历顺序）：
		// 1) deny 永远压过 allow；
		// 2) 同 effect 内 priority 更高者胜；
		// 3) priority 相同时 rule id 字典序更小者胜。
		switch cr.rule.Effect {
		case policy.EffectDeny:
			if deny == nil || higherPriority(&cr.rule, &deny.rule) {
				deny = cr
			}
		case policy.EffectAllow:
			if allow == nil || higherPriority(&cr.rule, &allow.rule) {
				allow = cr
			}
		}
	}

	if deny != nil {
		base.ReasonCode = policy.ReasonDenyMatch
		base.MatchedRuleID = deny.rule.ID
		base.Effect = string(policy.EffectDeny)
		base.Candidates = candidateIDs
		base.Message = fmt.Sprintf("explicitly denied by rule %s (deny overrides allow)", deny.rule.ID)
		return base
	}
	if allow != nil {
		base.Allowed = true
		base.ReasonCode = policy.ReasonAllowMatch
		base.MatchedRuleID = allow.rule.ID
		base.Effect = string(policy.EffectAllow)
		base.Candidates = candidateIDs
		base.Message = fmt.Sprintf("allowed by rule %s", allow.rule.ID)
		return base
	}

	// 主体在策略中从未出现过，给出更精确的可解释原因码；仍属拒绝。
	if _, known := snap.subjectSet[req.Subject]; !known {
		if _, wildcard := snap.subjectSet["*"]; wildcard {
			base.ReasonCode = policy.ReasonDenyDefault
			base.Message = "no rule matched; default deny"
			return base
		}
		base.ReasonCode = policy.ReasonDenyUnknownSbj
		base.Message = fmt.Sprintf("subject %q is not referenced by any rule; default deny", req.Subject)
		return base
	}
	base.ReasonCode = policy.ReasonDenyDefault
	base.Message = "no rule matched; default deny"
	return base
}

func higherPriority(a, b *policy.Rule) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return a.ID < b.ID
}

// compareVersions 对语义化版本号做数值比较；非法格式按字符串字典序比较。
func compareVersions(a, b string) int {
	an, aok := parseSemver(a)
	bn, bok := parseSemver(b)
	if aok && bok {
		for i := 0; i < 3; i++ {
			if an[i] != bn[i] {
				if an[i] < bn[i] {
					return -1
				}
				return 1
			}
		}
		return 0
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	i := 0
	for part := 0; part < 3; part++ {
		n := 0
		start := i
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			n = n*10 + int(v[i]-'0')
			i++
		}
		if i == start {
			return out, false
		}
		out[part] = n
		if part < 2 {
			if i >= len(v) || v[i] != '.' {
				return out, false
			}
			i++
		}
	}
	return out, i == len(v)
}
