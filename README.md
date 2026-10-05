# 本地零信任访问决策引擎（Go）

用本地 JSON 策略文件模拟策略下发与鉴权的零信任决策引擎。核心保证：

- **默认拒绝（Default Deny）**：无策略、无规则命中、主体未知、属性缺失、请求畸形，一律拒绝。
- **失败安全的加载**：字段非法、规则重复、规则矛盾都给出**可区分的原因码**且拒绝生效；新版本加载失败时旧版本完整继续服务，不存在“只生效一半”。
- **确定性的冲突取舍**：`deny 优先 → priority 高者优先 → rule id 字典序`，结论与文件书写顺序、map 遍历顺序无关。
- **原子热更新 + 历史可复现**：不可变快照 + 原子指针切换；在途并发请求只看到完整的某一版本；历史决策可按当时版本 `Replay`，版本间变化可用 `ExplainChange` 解释。
- **异常输入不崩溃**：`nil` 请求、空字段、`nil` 属性表、坏 JSON 均产生结构化拒绝结论。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `policy/` | 策略/请求/决策模型、字段校验、重复与矛盾检测、结构化加载错误码 |
| `engine/` | 不可变快照编译、评估裁决、冲突优先级、版本管理、历史复现与变化解释 |
| `loader/` | 本地文件读取解析、原子发布、轮询式热更新器 |
| `cmd/zte/` | CLI：`validate` / `eval` / `serve --watch` |
| `testdata/` | 示例策略与请求 |
| `docs/DESIGN.md` | 策略模型、冲突解决、默认拒绝语义、热更新约定的详细设计 |

## 策略模型

策略文件是一个版本化 JSON 文档：

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "id": "allow-admin-read",
      "effect": "allow",
      "priority": 10,
      "subjects": ["group:admins"],
      "actions": ["read"],
      "resources": ["bucket/audit/*"],
      "conditions": [
        {"key": "network", "op": "eq", "values": ["internal"]}
      ]
    }
  ]
}
```

- `version`：语义化版本（`MAJOR.MINOR.PATCH`），必须**单调递增**；重复发布或回退被拒绝。
- `subjects` / `actions`：精确值或 `filepath.Match` 风格 glob（如 `group:*`）。
- `resources`：按 `/` 分段的路径，`*` 不跨 `/`，`**` 跨任意层级。
- `conditions`：`eq/ne/in/nin/exists/not_exists/prefix/suffix/gt/lt`；属性缺失时除 `exists/not_exists` 外一律判定为不满足，因此依赖属性的 allow 不会误放行。

完整字段与错误码见 `docs/DESIGN.md`。

## 快速开始

```bash
# 1. 校验策略（含冲突检测）
go run ./cmd/zte validate --policy testdata/policies/v1.json

# 2. 单次评估（退出码：0 允许，2 拒绝，1 加载/系统错误）
go run ./cmd/zte eval --policy testdata/policies/v1.json \
  --request testdata/requests/allow.json

# 3. 常驻评估 + 热更新（stdin 每行一个 JSON 请求；坏 JSON 也输出拒绝决策，不中断服务）
go run ./cmd/zte serve --policy policy.json --watch --interval 5s
```

输出的 `Decision` 包含：结论 `allowed`、原因码 `reason_code`、命中规则 `matched_rule_id`、
参与匹配的候选规则 `candidates`、策略版本 `policy_version`、时间戳与原始请求。

### 在代码中使用

```go
e := engine.New(engine.WithHistoryLimit(10))
doc, _ := loader.LoadFile("policy.json")
if err := e.Load(doc); err != nil {
    // err 可转为 *policy.LoadError，按 Code 区分告警
}
d := e.Evaluate(&policy.Request{Subject: "u", Action: "read", Resource: "doc/x",
    Attributes: map[string]any{"network": "internal"}})

// 热更新（失败自动保留旧版本）
loader.LoadAndApply(e, "policy.json")

// 按历史版本复现与解释
old, _ := e.Replay("1.0.0", req)
change, _ := e.ExplainChange("1.0.0", "2.0.0", req)
```

## 原因码速查

决策原因码：`ALLOW_MATCH`、`DENY_MATCH`、`DENY_DEFAULT`、
`DENY_MALFORMED_REQUEST`、`DENY_UNKNOWN_SUBJECT`。

加载原因码：`POLICY_FILE_READ_ERROR`、`POLICY_SYNTAX_ERROR`、`POLICY_VERSION_EMPTY`、
`POLICY_VERSION_DOWNGRADE`、`POLICY_VERSION_REDUNDANT`、`POLICY_NO_RULES`、
`RULE_INVALID`、`RULE_INVALID_EFFECT`、`RULE_INVALID_CONDITION`、
`RULE_DUPLICATE`、`RULE_CONFLICT`。

## 验证

```bash
make test      # go test -race -v（带业务分组日志）
make vet
make build
```

测试覆盖的业务与日志约定见 `docs/DESIGN.md` 的“验证方法”一节。
