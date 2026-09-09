# v0.11.0 静态扫描校准

本次针对 Dify 二开工作流复核中出现的能力误识别、风险越级和遗漏数据路径进行调整。扫描仍完全确定性，不执行工作流、工具或攻击输入，不调用模型裁决。

## 已实现

| 问题 | 当前判定 |
|---|---|
| `codeListInput`、`query` 字段被当成执行代码/SQL | Python AST 追踪实际调用和参数；字段名不能独立证明执行 |
| `json.loads`、`json.dumps`、`html.escape`、`urllib.parse.quote` 被报执行漏洞 | 普通解析、序列化和编码不赋予命令执行能力 |
| f-string 中转义 JSON 大括号被当作模板代码 | 区分 Python 字符串与 DSL 模板占位符；真正动态代码继续告警 |
| 别名、辅助函数、循环、容器写入导致漏检 | 有界参数传播到解释器、进程调用和 SQL 源参数；未知语言/导入/反射保留覆盖缺口 |
| 参数化 SQL 与字符串拼 SQL 混淆 | SQL 源参数与绑定值分开；仅绑定值动态不报 SQL 拼接 |
| 固定 argv 被视为 shell 注入 | 区分固定可执行文件的数据参数、动态程序名、解释器 `-c` 和 `shell=True` |
| 固定域名的动态路径/查询参数被报动态 Host | 判断 URL authority；部署环境基地址仅留运行时覆盖项；完整动态 URL 保留待核验风险 |
| 工具说明出现 memory 就判持久记忆 | 按实际 `keep_conversation` 常量、动态配置和可信注册契约区分 none/session/persistent/unknown；忽略参数 Schema 默认值 |
| 多个下游 LLM 重复承担同一记忆问题 | 持久记忆控制域优先归到源节点，保留各路径证据；未证明隔离缺失时不确认跨用户漏洞 |
| 任意 POST、权限查询、if/else 自动升级高风险 | 高后果控制须匹配具体能力；展示分支不自动升级；控制链使用控制边，不拼接虚拟变量数据边 |
| 直接绑定身份字段就确认越权 | 用户绑定为待核验风险，系统上下文绑定为覆盖项；服务端对象授权未知不等于缺失 |
| 只因 `jsonschema`/`fail_closed` 出现在注释而跳过解析风险 | 注释和输出类型声明不证明验证；自定义验证器豁免必须由操作员注册且精确绑定代码 SHA-256 |
| 固定代码拼装及 Jinja 别名中的间接注入遗漏 | 保留输入经代码返回值进入 system/developer 的血缘，识别 `prompt_config.jinja2_variables` |
| 原生 Code 可控执行被直接称为宿主机严重风险 | 保留 HIGH 执行告警；仅凭 DSL 不推断沙箱逃逸或宿主权限 |

## 二开接口注册

将接口契约放在操作员管理的 `config/internal-baseline.yml`，不要放进待扫描 DSL。匹配支持 `url`、`method`、`tool_name`、`provider_id`、`plugin_unique_identifier` 和 `code_sha256`；`match_fields` 为同时满足的精确约束。具体接口条目优先于通用 HTTP 条目，同优先级按配置顺序匹配第一个。

以下是独立示例，域名不可用于生产。请合并到已有 `tool_registry`，保留原基线字段：

```yaml
tool_registry:
  - match_field: url
    match_type: exact
    match: https://service.invalid/query
    match_fields: {method: POST}
    effect: read_only
    capabilities: [DATABASE_READ]
    trusted_source: true
    definition_version: reviewed-api-v1
    integrity_control: operator-reviewed-api-contract

  - match_field: url
    match_type: exact
    match: https://service.invalid/save-and-enable
    match_fields: {method: POST}
    effect: deferred_execution
    capabilities: [DATABASE_EXECUTION]
    execution_fields:
      DATABASE_EXECUTION: [body]
    trusted_source: true
    definition_version: reviewed-scheduler-v1
    integrity_control: operator-reviewed-api-contract
```

`deferred_execution` 用于保存并启用 SQL/脚本任务的接口；应只登记真实会触发执行的接口，不能把任意配置保存都当成执行。`execution_fields` 是解析后真实参数名；以整个 body 登记属于保守粒度，复杂嵌套 JSON 需专门适配。`memory_mode` 也可由版本化注册契约明确设定。

`strict_parser_contract: true` 仅对同时精确绑定 `code_sha256` 的可信条目生效。哈希输入为 UTF-8 编码的 `"\n".join([code, script, source])`，缺失字段取空字符串。代码一旦改变，原豁免不再匹配。审查必须确认类型、枚举、未知/重复字段处理、失败关闭和返回契约，不能仅凭使用了验证库登记为严格解析器。DSL 自带 `_scanner_registry` 会被丢弃。

## 真实样本重扫口径

原文件已移动到本机桌面的“测小智”目录。以下使用本地规则直接运行、未加载部署基线，前后四个可比较文件 SHA-256 相同。数字是聚合告警数，不是真实漏洞数或误报率；不能与照片中不同引擎版本直接相减。

| 工作流 | 中危及以上非覆盖项：原→现 | 已确认高危/严重：原→现 |
|---|---:|---:|
| 多功能 | 14 → 4 | 5 → 0 |
| 权限问题 | 4 → 5 | 0 → 0 |
| 数据池无效 | 2 → 2 | 1 → 0 |
| 数据画布 | 1 → 1 | 0 → 0 |

“多功能”保留的是生产者—消费者类型不一致、两处派生路由和会话输入边界；移除了普通代码操作导致的执行/授权误报。“权限问题”新增识别 Jinja 高权限提示词引用，并不要求所有工作流告警数下降。“数据池无效”的身份绑定仍需核验，只是不再把未知服务端授权报告成已确认越权。

“是否关系型”修正后的文件本次有 2 项中危非覆盖告警、0 项已确认高危/严重，分别涉及提示词角色绑定和模型返回解析契约。历史输入文件不一致，未计算降低比例。

本次对 5 个可解析 DSL 完成了禁用模型的正式扫描，HTML 与未执行输入测试簇保存在工作区 `outputs/semantic-optimized-20260908`。自愈、账务、判断的现有文件仍无法完整解析；UI 识别文件在原路径和已找到的搬移目录中不可用。这四个工作流的已知代码模式已纳入脱敏回归，但不能据此宣称完成了四个工作流的完整复扫或给出准确漏洞总数。

## 验证与限制

本轮验证结果：86 项单元测试通过（原 65 项，加 21 项语义回归）；29 个企业验收场景全部通过。验收中的危险样例预期为 FAIL，表示扫描器成功阻断，不是测试失败。

新增正反例覆盖普通 JSON/HTML/URL 处理、真实执行、SQL 参数绑定、未知能力、URL 部位、实际记忆设置、注册表篡改、身份绑定、控制边、Jinja 别名和嵌套类型。原企业验收集的安全工作流、审批旁路、敏感数据外泄等预期保持，不以修改旧验收预期来隐藏退化。

运行方式：

```powershell
python -X utf8 -m unittest discover -s skills/agent-workflow-security-scan/tests -p 'test*.py'
python -X utf8 skills/agent-workflow-security-scan/scripts/validate_enterprise_suite.py --output build/semantic-enterprise-validation
```

当前 Python 分析是有界、保守的调用/参数摘要，不是完整解释器或跨模块、字段、路径敏感的程序证明。复杂别名、闭包、反射、不可满足分支、未知执行器与 JavaScript 仍有覆盖限制。没有把未知情况写成安全，也没有宣称实现通用污点分析器。

固定初始 Host 不证明重定向、DNS 重绑定、代理、Host 头或工具内部二次取 URL 安全。私有接口的实际业务副作用、平台 IAM、插件会话隔离、沙箱权限及模型攻击是否成功，需要版本匹配的运行时证据。补这些证据后可继续收敛；未执行测试簇不能确认攻击成功或证明不存在漏检。

参考设计与来源见 [upstream-research.md](upstream-research.md)。本次没有安装、复制或调用第三方扫描服务，也没有上传行内 DSL。
