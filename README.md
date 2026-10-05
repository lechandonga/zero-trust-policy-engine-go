# Zero-Trust Policy Engine (Go)

一个本地零信任访问决策引擎：从本地文件加载策略，对访问请求给出**可预期、可解释**的放行/拒绝结论，支持策略冲突检测、原子热更新与默认拒绝兜底。

## 策略模型

策略以 JSON 文件维护（见 `examples/policy.json`）：

```json
{
  "version": "v1",
  "subjects": ["alice", "bob"],
  "rules": [
    {"id": "allow-alice", "effect": "allow",
     "subjects": ["alice"], "resources": ["doc"], "actions": ["read"],
     "priority": 10}
  ]
}
```

- `version`：策略版本号，每条决策都会带上它，用于复现与审计。
- `subjects`：已知主体注册表；为空则不启用主体校验。未注册主体一律拒绝（`DENIED_UNKNOWN_SUBJECT`）。
- `rules[]`：规则按 `subjects / resources / actions` 三个集合匹配，`"*"` 为通配符；`effect` 只能是 `allow` 或 `deny`；`priority` 用于同效果规则间的确定性排序。

## 加载与校验

`Engine.Load` 先完整解析并校验整个文档，**全部通过才原子切换**；任何失败都拒绝加载并保留旧版本继续服务，绝不出现"只生效一半"的状态。拒绝原因可区分（`policy.ValidationError.Kind`）：

- `invalid_field`：字段非法（空 version/规则 id、非法 effect、空匹配集合等）。
- `duplicate_rule_id`：规则 id 重复。
- `conflicting_rules`：两条规则匹配空间相交但效果相反（矛盾规则不得静默生效）。

## 评估语义

每条决策返回 `Decision{allow, reason, matched_rule_id, policy_version, explanation}`：

| 原因码 | 含义 |
| --- | --- |
| `ALLOWED_BY_RULE` | 命中 allow 规则，`matched_rule_id` 指明是哪条 |
| `DENIED_BY_RULE` | 命中 deny 规则 |
| `DENIED_DEFAULT` | 无任何规则命中，默认拒绝兜底 |
| `DENIED_MISSING_ATTRIBUTE` | subject/resource/action 缺失或为空白 |
| `DENIED_UNKNOWN_SUBJECT` | 主体不在注册表中 |
| `DENIED_INVALID_REQUEST` | 请求格式异常（进程不会崩溃或卡住） |
| `DENIED_NO_POLICY_LOADED` | 尚未加载任何策略版本 |

**冲突取舍稳定可复现**：命中多条规则时按 `deny 优先 → priority 降序 → 规则 id 字典序` 排序取首条，与文件顺序、遍历顺序无关（有单测验证）。

## 热更新约定

- 当前策略集是不可变快照，通过 `atomic.Pointer` 整体切换；并发评估各自看到**某个完整版本**，更新期间不会出现半新半旧。
- 热更新失败只记录日志并保留旧版本（见 `main.go` 的 `watchLoop`）。
- 决策中的 `policy_version` + `matched_rule_id` 使历史决策可按当时版本复现；版本切换前后同一请求结论变化可直接对比两条决策解释（见 `TestVersionSwitchExplainsDecisionChange`）。

## 使用

```bash
# 评估一批请求（JSONL，每行一个 {"subject","resource","action"}）
go run . -policy examples/policy.json -requests examples/requests.jsonl

# 热更新模式：每 2s 重读策略文件，失败保留旧版本
go run . -policy examples/policy.json -watch 2s
```

## 验证方法

```bash
CGO_ENABLED=1 go test -race -v ./...
```

测试按业务分组，`-v` 日志可见各场景覆盖情况：

- **策略校验**（`policy/policy_test.go`）：合法集、非法字段（5 个子用例）、重复规则 id、显式/通配符冲突、匹配顺序确定性。
- **请求评估**（`policy/engine_test.go`）：allow/deny 命中、默认拒绝、无策略、属性缺失（4 个子用例）、未知主体、解析失败。
- **热更新**（`policy/engine_test.go`）：失败重载保留旧版本、版本切换前后结论可解释、`TestHotReloadRace` 在 `-race` 下用 8 个 goroutine 并发评估 + 200 次版本翻转，断言每条决策都可归因于某一个完整版本。
