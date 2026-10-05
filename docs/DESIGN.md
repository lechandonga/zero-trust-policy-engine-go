# 设计说明：策略模型、冲突解决、默认拒绝与热更新约定

## 1. 架构与数据流

```
本地策略文件(JSON)
      │ loader.LoadFile        读文件 / 解析（拒绝未知字段、串联 JSON）
      ▼
policy.Document ──Validate──── 字段级校验（版本、effect、选择器、条件运算符/值类型）
      │
      ▼ engine.Compile ─────── DetectConflicts（重复 RULE_DUPLICATE / 矛盾 RULE_CONFLICT）
engine.Snapshot（不可变：编译好的匹配器 + 排序后的规则）
      │
      ▼ atomic.Pointer[Snapshot]（Load：版本单调检查通过后整体替换）
Engine.Evaluate ────────────── 只读当前快照，输出 Decision
      │
      ├─ Decisions()           进程内决策审计环形缓冲
      └─ Replay / ExplainChange 用保留的历史快照复现并解释版本差异
```

关键结构：

- `policy.Document/Rule/Condition/Request/Decision`：对外数据模型（`policy/types.go`）。
- `engine.Snapshot`：某版本策略的**不可变**视图（`engine/snapshot.go`）。构建完成后不再被任何代码修改。
- `engine.Engine`：`atomic.Pointer[Snapshot]` 指向当前版本；`history map` 保留最近 N 个版本快照用于复现。
- `loader.Reloader`：按文件 `mtime+size` 轮询，变更时调用 `LoadAndApply`，结果通过 `OnResult` 回调暴露。

## 2. 策略模型

### 2.1 字段

| 字段 | 约束 |
| --- | --- |
| `version` | 必填，非空；建议语义化 `MAJOR.MINOR.PATCH`；同一引擎内必须单调递增 |
| `rules[]` | 至少 1 条 |
| `rule.id` | 必填非空、文档内唯一 |
| `rule.effect` | 仅允许 `allow` / `deny` |
| `rule.subjects` / `actions` / `resources` | 非空数组且无空白项 |
| `rule.priority` | 整数，越大优先级越高，默认 0 |
| `rule.conditions[]` | 见下；`key` 非空，`op` 必须受支持 |

### 2.2 匹配语义

- 主体、动作：精确匹配，或 Go `path.Match` 风格 glob（`*`、`?`），如 `group:admin*`。
- 资源：按 `/` 分段。`*` 与 `?` **不跨越 `/`**；`**` 匹配任意数量（含 0 个）路径段。
  例：`env/sandbox/**` 匹配 `env/sandbox/a/b/c`，而 `env/*` 不匹配该资源。
- 条件（对请求 `attributes` 求值）：
  - `eq` / `ne`：与第一个 value 严格相等/不等；
  - `in` / `nin`：属性值是否在 values 集合中；
  - `exists` / `not_exists`：属性是否存在；
  - `prefix` / `suffix`：字符串前缀/后缀；
  - `gt` / `lt`：数值比较（JSON 数字以 float64 解码，兼容 int/int64）。
  - **类型不匹配即 false，不做隐式转换**（如 `"123"` 与数字 `123` 不相等）。

## 3. 默认拒绝语义

评估按以下顺序短路，任何一步失败都产生确定的拒绝：

1. 请求为 `nil`、subject/action/resource 为空 → `DENY_MALFORMED_REQUEST`。
2. 引擎从未加载任何策略 → `DENY_DEFAULT`（`policy_version` 为空）。
3. 收集全部命中规则；属性缺失时，除 `exists/not_exists` 外的条件均为 false，
   依赖该属性的 allow **不会**误放行。
4. 命中 deny → `DENY_MATCH`；否则命中 allow → `ALLOW_MATCH`。
5. 没有任何规则命中：
   - 策略中不含通配主体且该主体从未被任何规则引用 → `DENY_UNKNOWN_SUBJECT`；
   - 其他情况 → `DENY_DEFAULT`。

“允许”只可能由显式 `ALLOW_MATCH` 产生，代码中不存在任何默认放行分支。
引擎评估对 map/nil 访问全部做防御处理，异常输入不会 panic；CLI 的坏 JSON 按行隔离，
输出拒绝决策后继续处理后续请求，不出现死循环。

## 4. 冲突解决（加载期 + 运行期双重保证）

### 4.1 加载期：重复与矛盾直接拒绝

对每条规则计算**规范签名**：排序后的 subjects 集合 + actions 集合 + resources 集合 +
排序后的条件集合（key/op/values）。检测仅基于签名和 id 排序，**与文件顺序无关**：

- 签名相同且 effect 相同 → `RULE_DUPLICATE`（规则重复，不得静默生效）。
- 签名相同、effect 相反、`priority` 相同 → `RULE_CONFLICT`（无法确定性取舍，要求作者显式设置不同优先级）。
- 签名相同、effect 相反但优先级不同 → 允许加载，由运行期规则裁决。

### 4.2 运行期：确定性裁决顺序

同一请求命中多条规则时，取舍顺序固定为：

1. **Deny Overrides**：只要存在命中的 deny，结果必为拒绝（无论 allow 的优先级多高）。
2. **Priority**：同一 effect 内 `priority` 数值大者胜。
3. **Rule ID**：priority 仍相同时，id 字典序小者胜。

编译期规则还会按 `priority desc, id asc` 预排序，裁决阶段独立执行上述比较，
形成双重保证；结论不依赖规则书写顺序，也不依赖 Go map 遍历顺序。
`Decision.candidates` 记录全部命中规则 id，便于审计“为什么是这条”。

## 5. 热更新约定

1. **先编译后切换**：`Engine.Load` 先完成解析、字段校验、冲突检测和快照构建；
   任一步失败直接返回 `*policy.LoadError`，**绝不触碰当前指针**，旧版本继续完整服务。
2. **原子发布**：校验全部通过后才把快照放入历史表并执行一次 `atomic.Store`。
   评估方通过 `atomic.Load` 取快照指针，因此一次评估从头到尾使用同一个不可变快照，
   绝不会出现规则半新半旧（竞态测试 `TestHotReload_ConcurrentRace` 验证）。
3. **版本单调**：新版本号必须大于当前版本（semver 数值比较，非法格式退化为字典序）。
   相同版本 → `POLICY_VERSION_REDUNDANT`；更小版本 → `POLICY_VERSION_DOWNGRADE`。
4. **轮询器**：`loader.Reloader` 仅在文件 `mtime` 或 `size` 变化时重新加载；
   成功/失败都通过 `OnResult` 回调和 `LastError()` 显式暴露，不静默吞错。
   建议“写临时文件 + rename”发布策略文件，保证读者看到的是完整文件。
5. **历史复现**：引擎保留最近 N 个版本快照（`WithHistoryLimit`，默认 10）。
   - `Replay(version, req)`：按指定版本重放请求；
   - `ExplainChange(v1, v2, req)`：输出结构化变化解释（如
     `flipped ALLOW(rule=allow-read) -> DENY(DENY_MATCH, rule=deny-doc-x) due to policy 1.0.0 -> 2.0.0`）。
   复现结果不写入实时决策日志，避免污染审计流。

### 加载错误码（可区分，不静默）

| Code | 触发场景 |
| --- | --- |
| `POLICY_FILE_READ_ERROR` | 文件不存在/不可读 |
| `POLICY_SYNTAX_ERROR` | 空文件、JSON 语法错、字段类型错、未知字段、多个 JSON 文档 |
| `POLICY_VERSION_EMPTY` | 版本为空 |
| `POLICY_NO_RULES` | 规则数组为空 |
| `RULE_INVALID` | id/subjects/actions/resources 为空或含空白项 |
| `RULE_INVALID_EFFECT` | effect 不是 allow/deny |
| `RULE_INVALID_CONDITION` | 条件 key 为空、op 未知、缺 values、值类型不支持 |
| `RULE_DUPLICATE` | 同签名同 effect 的重复规则 |
| `RULE_CONFLICT` | 同签名相反 effect 且等优先级 |
| `POLICY_VERSION_REDUNDANT` | 重复发布相同版本 |
| `POLICY_VERSION_DOWNGRADE` | 新版本号不大于当前版本 |

## 6. 验证方法

### 6.1 自动化测试

```bash
make test          # = CGO_ENABLED=1 go test -race -v ./...
```

测试日志按业务打标签（`业务[加载校验]`、`业务[冲突检测]`、`业务[访问评估]`、
`业务[异常输入]`、`业务[冲突取舍]`、`业务[热更新]`、`业务[历史复现]`、
`业务[并发竞态]`、`业务[文件加载]`、`业务[轮询热更]`），每个用例输出：
用例名、allow 结论、原因码、命中规则、策略版本。覆盖矩阵：

| 业务 | 代表用例 |
| --- | --- |
| 加载校验 | 版本为空、无规则、id 空、effect 非法、选择器空白、未知条件运算符、缺 values、id 重复、合法文档 |
| 冲突检测 | 重复规则、同优先级矛盾、不同优先级可解决、**书写顺序无关**、选择器不同不冲突 |
| 访问评估 | 显式 allow、glob/`**` 匹配、属性条件满足/不满足、高优先级 deny 压过 allow、默认拒绝 |
| 异常输入 | nil 请求、空 subject/action/resource、nil 属性表、属性类型不匹配、空引擎、未知主体 |
| 冲突取舍 | deny-vs-allow 稳定拒绝；同 effect 按 priority/id 稳定取胜 |
| 热更新 | 坏 JSON / 非法 effect / 版本回退 / 重复版本均被拒绝且旧版本继续服务 |
| 历史复现 | v1 allow 与 v2 deny 可分别重放；`ExplainChange` 给出翻转解释；未保留版本报错 |
| 并发竞态 | 16 读协程持续评估期间发布新版本与坏文件，`-race` 下仅出现完整版本组合、无混合状态 |
| 文件加载 | 缺文件/空文件/坏 JSON/未知字段原因码区分 |
| 轮询热更 | 初次发布、变更切换、损坏文件拒绝并保留旧版本、回调计数 |

### 6.2 手工验证

```bash
# 校验冲突策略（任选一种坏文件观察原因码）
go run ./cmd/zte validate --policy testdata/policies/v1.json

# 允许（退出码 0）与拒绝（退出码 2）
go run ./cmd/zte eval --policy testdata/policies/v1.json --request testdata/requests/allow.json
go run ./cmd/zte eval --policy testdata/policies/v1.json --request testdata/requests/deny-prod.json

# 热更新：运行中替换文件内容并 bump version，观察 stderr 的 [reload] 行与结论翻转
go run ./cmd/zte serve --policy policy.json --watch --interval 1s
```
