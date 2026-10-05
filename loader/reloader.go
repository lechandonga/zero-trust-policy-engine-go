package loader

import (
	"context"
	"sync"
	"time"

	"github.com/lechandonga/zero-trust-policy-engine-go/engine"
)

// ReloadResult 描述一次热更新的结果。
type ReloadResult struct {
	Path       string
	OldVersion string
	NewVersion string
	Applied    bool
	Err        error
	CheckedAt  time.Time
}

// Reloader 周期性检查策略文件，内容变化时原子发布新版本。
// 文件损坏或新版本校验失败时，引擎继续使用旧版本服务，
// 失败通过返回结果/回调暴露给运维，不会被静默吞掉。
type Reloader struct {
	engine   *engine.Engine
	path     string
	interval time.Duration

	mu       sync.Mutex
	lastSize int64
	lastMod  time.Time
	lastErr  error
	onResult func(ReloadResult)
}

// NewReloader 创建轮询式热更新器。interval 建议 1s~30s。
func NewReloader(e *engine.Engine, path string, interval time.Duration) *Reloader {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Reloader{engine: e, path: path, interval: interval}
}

// OnResult 注册每次检查（成功、跳过、失败）的观测回调。
func (r *Reloader) OnResult(fn func(ReloadResult)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onResult = fn
}

// LastError 返回最近一次更新检查的错误（若有）。
func (r *Reloader) LastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// Run 阻塞运行直到 ctx 取消。
// 首次加载完成（无论成败）后向 ready 发送一次信号。
func (r *Reloader) Run(ctx context.Context, ready chan<- ReloadResult) {
	first := r.Reload()
	if ready != nil {
		ready <- first
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Reload()
		}
	}
}

// Reload 执行一次显式检查：仅当文件的修改时间或大小变化时才重新解析发布。
func (r *Reloader) Reload() ReloadResult {
	res := ReloadResult{Path: r.path, CheckedAt: time.Now().UTC()}
	res.OldVersion = r.engine.CurrentVersion()

	info, statErr := statFile(r.path)
	if statErr != nil {
		r.fail(&res, statErr)
		return res
	}
	r.mu.Lock()
	unchanged := info.ModTime().Equal(r.lastMod) && info.Size() == r.lastSize
	r.mu.Unlock()
	if unchanged {
		res.NewVersion = res.OldVersion
		return res
	}

	v, err := LoadAndApply(r.engine, r.path)
	if err != nil {
		r.fail(&res, err)
		return res
	}

	r.mu.Lock()
	r.lastMod = info.ModTime()
	r.lastSize = info.Size()
	r.lastErr = nil
	cb := r.onResult
	r.mu.Unlock()

	res.Applied = true
	res.NewVersion = v
	if cb != nil {
		cb(res)
	}
	return res
}

func (r *Reloader) fail(res *ReloadResult, err error) {
	res.Err = err
	res.NewVersion = res.OldVersion
	r.mu.Lock()
	r.lastErr = err
	cb := r.onResult
	r.mu.Unlock()
	if cb != nil {
		cb(*res)
	}
}
