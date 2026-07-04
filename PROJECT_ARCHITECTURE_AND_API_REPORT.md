# 项目架构与 API 分析报告

> 生成日期: 2026-07-03 | 项目名称: VulnSleuth (SCG Multi-Model Audit Backend)

---

## 1. 项目概述

### 1.1 核心目标

VulnSleuth 是一个**多模型智能合约漏洞检测系统**的后端服务。它接收 Solidity 智能合约源码，通过多模型联合推理（LSTM 专项漏洞检测 + DeepSVDD 异常检测 + GCN 跨合约风险分析 + 静态规则 + RAG 知识库 + LLM 推理），自动生成安全审计报告，并支持 Slither 工具验证。

### 1.2 核心技术栈

| 层级 | 技术 | 说明 |
|---|---|---|
| Web 框架 | **FastAPI** + Uvicorn | 异步 REST API 服务 |
| 深度学习 | **TensorFlow 2.20** | LSTM 漏洞检测模型 + DeepSVDD 异常检测模型 |
| 图神经网络 | **PyTorch** + **ANTLR 4.7.2** | GCN 跨合约风险检测（子进程调用） |
| 数据库 | **PostgreSQL** (Supabase) | 用户/会话/任务/报告持久化，psycopg 驱动 |
| LLM | **DeepSeek v4-pro** (OpenAI兼容API) | 漏洞推理与验证智能体 |
| 静态分析 | **Slither** | 漏洞验证工具（子进程调用） |
| Solidity 编译 | **solc** / **solcjs** (Node.js) | 多版本 Solidity 编译与 EVM 字节码提取 |
| 构建工具 | npm (solc 包), pip | 依赖管理 |
| 安全 | PBKDF2-HMAC-SHA256 | 密码哈希，Token 用 SHA-256 哈希存储 |

---

## 2. 核心目录结构

```
vlunsleuth/
├── backend/                          # 核心后端 Python 包
│   ├── api/
│   │   ├── app.py                    # FastAPI 应用入口（路由定义 + 任务管理）
│   │   └── security.py               # 密码哈希、Token 生成/验证
│   ├── router/
│   │   └── workflow_router.py        # 工作流编排：模式→模型选择→Agent 链
│   ├── schemas/
│   │   ├── analysis_input.py         # SourceFile/FunctionUnit/ContractUnit/AnalysisInput
│   │   ├── audit_request.py          # AuditRequest（审计任务请求体）
│   │   ├── evidence.py               # ModelEvidence / RiskVector
│   │   └── finding.py                # Finding / Warning / AuditReport
│   ├── preprocessing/
│   │   ├── source_loader.py          # 源码加载（.sol / .zip / 目录）
│   │   ├── solidity_parser.py        # 自研 Solidity 解析器（合约/函数/调用图提取）
│   │   ├── feature_extractor.py      # 静态特征提取 + 构建 AnalysisInput
│   │   ├── bytecode_embedding.py     # EVM 字节码编译 + 反汇编 + Tokenizer 编码
│   │   └── solcjs_multi_compile.js   # Node.js 多版本 Solidity 编译脚本
│   ├── model_adapters/
│   │   ├── base.py                   # DetectionModel 抽象基类
│   │   ├── registry.py               # 模型适配器注册表
│   │   ├── executor.py               # 适配器执行调度器
│   │   ├── lstm_adapter.py           # LSTM 4 类漏洞检测适配器
│   │   ├── deepsvdd_adapter.py       # DeepSVDD 异常检测适配器
│   │   ├── gcn_adapter.py            # GCN 跨合约风险检测适配器
│   │   └── null_adapter.py           # 空适配器（占位）
│   ├── evidence/
│   │   └── evidence_center.py        # 证据中心：收集/分组/汇总所有模型证据
│   ├── function_risk/
│   │   ├── risk_score.py             # 多维度风险评分引擎（R_func + R_selected + R_warning）
│   │   └── reasoning_gate.py         # 推理门控：筛选高价值函数送 LLM 推理
│   ├── agents/
│   │   ├── llm_client.py             # LLM API 客户端（OpenAI 兼容 + 占位回退）
│   │   ├── llm_reasoning_service.py  # LLM 推理服务（构建 Prompt + 解析响应）
│   │   ├── reasoning_localization_agent.py  # 发现与警告构建器
│   │   └── slither_verification_agent.py    # Slither 验证 + LLM 验证智能体
│   ├── rag/
│   │   ├── jsonl_knowledge_store.py  # JSONL 知识库检索（Token 匹配）
│   │   └── knowledge_context.py      # 知识上下文构建器
│   ├── persistence/
│   │   └── supabase_store.py         # PostgreSQL 持久化层（7 张表）
│   ├── reporting/
│   │   └── markdown_report.py        # Markdown 审计报告生成器（中文）
│   └── run_audit.py                  # CLI 入口 + 审计 Pipeline 主流程
│
├── LG-DeepSVDD/                      # LSTM + DeepSVDD 模型资产
│   ├── pretrain/semantic features/LSTM/
│   │   ├── tok.pickle                # Keras Tokenizer
│   │   └── outputs/*.h5              # 4 个 LSTM 漏洞检测模型
│   └── DeepSVDD/outputs/models/*     # DeepSVDD 编码器模型
│
├── cross-contract_detection/         # GCN 跨合约检测子项目
│   └── cross-contract_detection/
│       ├── detect_sol_copy_gradient_ranked_v3.py  # GCN 检测入口脚本
│       └── detecting/BFS_EA_RGCN(SG)/BFS_EA_RGCN.pkl  # 训练好的 GCN 模型
│
├── md/                               # 项目设计文档
├── dataset/knowledge/                # RAG 知识库 JSONL
├── package.json                      # Node.js solc 编译器依赖
├── requirements-backend.txt          # Python 依赖
├── .env                              # 环境变量（数据库/LLM 配置）
└── backend_outputs/                  # 运行时输出目录（审计结果/上传文件）
```

---

## 3. 系统架构与数据流

### 3.1 逻辑分层

```
┌─────────────────────────────────────────────────────────────────┐
│                       API 接入层 (FastAPI)                        │
│  认证/授权 ─ 任务 CRUD ─ 文件上传 ─ 报告下载 ─ 状态查询             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ AuditRequest
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     路由/工作流层 (workflow_router)                │
│  模式 → 模型选择: full_audit / known_full_scan /                   │
│                  unknown_risk_scan / cross_contract_scan           │
│  Agent 链: reasoning → verification → repair → report             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   审计 Pipeline (run_audit)                        │
│                                                                   │
│  ① 源码加载 (source_loader)                                       │
│     .sol / .zip / dir → List[SourceFile]                         │
│                                                                   │
│  ② 预处理 (preprocessing)                                         │
│     Solidity 解析 → 合约/函数/调用图 → 静态特征 → 字节码编译           │
│     → AnalysisInput                                              │
│                                                                   │
│  ③ 多模型推理 (model_adapters)                                     │
│     ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│     │  LSTM    │  │ DeepSVDD │  │   GCN    │  │  STATIC  │       │
│     │ 4 类漏洞 │  │ 异常检测 │  │ 跨合约   │  │ 规则引擎 │       │
│     └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│          └──────────────┴──────────────┴─────────────┘            │
│                           │                                       │
│                           ▼                                       │
│  ④ 证据汇聚 (evidence_center)                                      │
│     统合所有模型输出 → ModelEvidence[]                              │
│                                                                   │
│  ⑤ RAG 知识检索 (rag)                                             │
│     JSONL 知识库 Token 匹配 → KnowledgeContext                     │
│                                                                   │
│  ⑥ 风险评分 (function_risk)                                        │
│     ┌─────────────┐  ┌─────────────┐                              │
│     │ R_func (7维)│  │ R_selected  │                              │
│     │ 加权综合评分│  │ 漏洞专项评分│                              │
│     └──────┬──────┘  └──────┬──────┘                              │
│            └────────┬───────┘                                     │
│                     ▼                                             │
│  ⑦ 推理门控 (reasoning_gate)                                       │
│     R_func ≥ 0.35 或 R_selected ≥ 0.45 → 送 LLM 推理              │
│                                                                   │
│  ⑧ LLM 推理与定位 (agents)                                         │
│     构建 Findings + Warnings（含语义守卫过滤）                       │
│                                                                   │
│  ⑨ 验证 (verification) ─ 可选                                     │
│     Slither 静态验证 + LLM 验证智能体                               │
│                                                                   │
│  ⑩ 报告生成 (reporting)                                            │
│     JSON + Markdown 审计报告                                       │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    持久化层 (persistence)                          │
│  PostgreSQL (Supabase): scg_users / scg_sessions /                │
│  scg_contracts / scg_audit_tasks / scg_audit_events /             │
│  scg_audit_reports / scg_audit_artifacts                          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 任务生命周期状态机

```
created → queued → running → succeeded
                           → failed
  ↓          ↓         ↓
cancelled  cancelled  cancelling → cancelled
                         (interrupted: 进程重启)
```

### 3.3 风险评分模型 (R_func)

```
R_func = 0.25 × A_f (异常分) + 0.15 × G_f (GCN分) + 0.20 × S_f (静态分)
       + 0.15 × B_f (业务敏感度) + 0.15 × K_f (知识库匹配)
       + 0.10 × C_f (多源一致性) - 0.20 × P_f (防护措施)
```

### 3.4 语义守卫 (Semantic Guards)

系统在 `risk_score.py` 中实现了强语义守卫 (`semantic_category_allowed`)，对不同漏洞类型有严格的必要条件约束：

| 漏洞类型 | 必要条件 |
|---|---|
| VULN_REENTRANCY | 非只读 + 有状态更新 + 有低级调用/转账 |
| VULN_UNCHECKED_LOW_LEVEL_CALLS | 非只读 + 有低级调用 + 未检查返回值 |
| VULN_TIMESTAMP | 有 timestamp 依赖 |
| VULN_DELEGATECALL | 非只读 + 有 delegatecall |
| VULN_CROSS_CONTRACT_RISK | 有外部调用 |
| VULN_UNKNOWN_ANOMALY | 始终允许 |

---

## 4. API 接口字典

### 4.1 健康检查

| 方法 | 路径 | 说明 | 认证 |
|---|---|---|---|
| `GET` | `/api/v1/health` | 服务健康检查，返回状态、Worker 数、任务统计、数据库状态 | 无 |

### 4.2 认证模块 `/api/v1/auth`

| 方法 | 路径 | 说明 | 请求参数 | 认证 |
|---|---|---|---|---|
| `POST` | `/api/v1/auth/register` | 注册新用户 | `username`(≥3字符), `password`(≥8字符), `display_name`(可选) | 无 |
| `POST` | `/api/v1/auth/login` | 用户登录 | `username`, `password` | 无 |
| `GET` | `/api/v1/auth/me` | 获取当前用户信息 | — | Bearer Token |
| `POST` | `/api/v1/auth/logout` | 注销当前会话 | — | Bearer Token |

### 4.3 审计任务 `/api/v1/audits`

| 方法 | 路径 | 说明 | 关键参数 | 认证 |
|---|---|---|---|---|
| `POST` | `/api/v1/audits` | 创建审计任务（本地路径） | JSON Body: `source_path`, `mode`, `target_vulnerabilities[]`, `need_verification`, `need_repair`, `background_risk_screening`, `background_screening_action`, `async_run` | 可选 |
| `POST` | `/api/v1/audits/upload` | 上传文件并创建审计任务 | FormData: `file`(.sol/.zip), `mode`, `target_vulnerabilities[]`, `need_verification`, `need_repair`, `background_risk_screening`, `background_screening_action`, `async_run` | 可选 |
| `GET` | `/api/v1/audits` | 分页列出审计任务 | Query: `status`(逗号分隔), `limit`(≤200), `offset` | 可选 |
| `GET` | `/api/v1/audits/{task_id}` | 获取任务详情与状态 | — | 按用户隔离 |
| `GET` | `/api/v1/audits/{task_id}/events` | 获取任务状态变迁历史 | — | 按用户隔离 |
| `POST` | `/api/v1/audits/{task_id}/cancel` | 取消进行中的任务 | — | 按用户隔离 |
| `POST` | `/api/v1/audits/{task_id}/retry` | 重试已终止的任务 | `async_run` | 按用户隔离 |
| `DELETE` | `/api/v1/audits/{task_id}` | 删除已终止的任务 | `delete_upload`(是否同时删除上传文件) | 按用户隔离 |

### 4.4 审计报告

| 方法 | 路径 | 说明 | 认证 |
|---|---|---|---|
| `GET` | `/api/v1/audits/{task_id}/report` | 获取 JSON 格式报告（Response Body） | 按用户隔离 |
| `GET` | `/api/v1/audits/{task_id}/report.json` | 下载 JSON 报告文件 | 按用户隔离 |
| `GET` | `/api/v1/audits/{task_id}/report.md` | 下载 Markdown 报告文件 | 按用户隔离 |
| `GET` | `/api/v1/audits/{task_id}/artifacts` | 列出任务生成的所有产物文件 | 按用户隔离 |

### 4.5 审计模式 (mode) 枚举

| 模式值 | 含义 |
|---|---|
| `full_audit` | 全面审计：LSTM_ALL + DeepSVDD + GCN + 推理 + 验证 + 修复 |
| `known_full_scan` | 已知漏洞全扫描：仅 LSTM_ALL |
| `unknown_risk_scan` | 未知风险扫描：DeepSVDD + LSTM_ALL |
| `cross_contract_scan` | 跨合约专项扫描：仅 GCN |

### 4.6 响应结构

**Auth 注册/登录响应:**
```json
{
  "user": {"id": "uuid", "username": "str", "display_name": "str|null", "created_at": "iso8601", "updated_at": "iso8601"},
  "access_token": "urlsafe_base64_43chars",
  "token_type": "bearer"
}
```

**任务列表响应:**
```json
{
  "tasks": [{
    "task_id": "TASK-20260703-HHMMSS-xxxxxxxx",
    "status": "created|queued|running|cancelling|succeeded|failed|cancelled|interrupted",
    "progress": 0-100,
    "can_cancel": true/false,
    "can_retry": true/false,
    "can_delete": true/false,
    "status_url": "/api/v1/audits/{task_id}",
    "artifacts_url": "...", "events_url": "...", "cancel_url": "...", "retry_url": "...",
    "report_url": "...(仅 succeeded 状态)", /* ... */
  }],
  "total": 0, "limit": 50, "offset": 0,
  "status_counts": {"created": 1, "succeeded": 5}
}
```

---

## 5. 核心数据模型

### 5.1 数据库表设计 (PostgreSQL / Supabase)

#### scg_users
| 字段 | 类型 | 说明 |
|---|---|---|
| id | UUID PK | 用户唯一标识 |
| username | TEXT UNIQUE NOT NULL | 用户名 |
| display_name | TEXT | 显示名称 |
| password_hash | TEXT NOT NULL | PBKDF2-HMAC-SHA256 密码哈希 |
| password_salt | TEXT NOT NULL | 密码盐值 |
| password_iterations | INTEGER NOT NULL | 哈希迭代次数 (260,000) |
| created_at / updated_at | TIMESTAMPTZ | 时间戳 |

#### scg_sessions
| 字段 | 类型 | 说明 |
|---|---|---|
| id | UUID PK | 会话 ID |
| user_id | UUID FK → scg_users | 关联用户 |
| token_hash | TEXT UNIQUE NOT NULL | Token 的 SHA-256 哈希 |
| expires_at | TIMESTAMPTZ | 过期时间 (7天) |
| created_at | TIMESTAMPTZ | 创建时间 |

#### scg_contracts
| 字段 | 类型 | 说明 |
|---|---|---|
| id | UUID PK | 合约记录 ID |
| task_id | TEXT UNIQUE | 关联任务 ID |
| user_id | UUID FK → scg_users | 上传用户 |
| source_kind | TEXT | 来源类型 (path/upload) |
| filename | TEXT | 文件名 |
| source_path | TEXT | 源文件路径 |
| sha256 | TEXT | 文件 SHA-256 |
| size_bytes | BIGINT | 文件大小 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### scg_audit_tasks
| 字段 | 类型 | 说明 |
|---|---|---|
| task_id | TEXT PK | 任务 ID |
| user_id | UUID FK → scg_users | 所属用户 |
| contract_id | UUID FK → scg_contracts | 关联合约 |
| status | TEXT NOT NULL | 任务状态 |
| progress | INTEGER | 进度百分比 |
| request | JSONB | 原始请求参数 |
| summary | JSONB | 审计摘要 |
| error / traceback | TEXT | 错误信息 |
| report_json_path / report_markdown_path | TEXT | 报告路径 |
| cancel_requested | BOOLEAN | 是否请求取消 |
| created_at / started_at / updated_at / finished_at | TIMESTAMPTZ | 各阶段时间戳 |
| record | JSONB NOT NULL | 完整任务记录快照 |

#### scg_audit_events
| 字段 | 类型 | 说明 |
|---|---|---|
| id | BIGSERIAL PK | 自增 ID |
| task_id | TEXT FK → scg_audit_tasks | 关联任务 |
| event_time / event_type / message | — | 事件详情 |
| payload | JSONB | 事件负载 |

#### scg_audit_reports
| 字段 | 类型 | 说明 |
|---|---|---|
| id | UUID PK | 报告 ID |
| task_id | TEXT UNIQUE FK | 关联任务 |
| report_json | JSONB NOT NULL | 完整 JSON 报告 |
| report_markdown | TEXT | Markdown 报告全文 |
| summary | JSONB | 报告摘要（findings/warnings 计数等） |

#### scg_audit_artifacts
| 字段 | 类型 | 说明 |
|---|---|---|
| id | UUID PK | 产物 ID |
| task_id | TEXT FK | 关联任务 |
| name / path | TEXT | 文件名与路径 |
| size_bytes | BIGINT | 文件大小 |
| artifact_type | TEXT | 产物类型 (json/md) |
| download_url | TEXT | 下载链接 |

### 5.2 核心内存数据模型 (Python Dataclass)

#### AnalysisInput (审计输入)
```
SourceFile[] → ContractUnit[] → FunctionUnit[]
  ├── source_path, contract_name, name, signature
  ├── start_line, end_line, code
  ├── visibility, mutability, modifiers
  ├── internal_calls[], external_calls[]
  └── features: {dangerous_apis, state_update, static_score, ...}
```

#### ModelEvidence (模型证据)
```
evidence_id, model_id, scope, contract_name, function_signature
function_id, vulnerability_id, raw_score, calibrated_confidence
label, location_candidates[], feature_evidence[], metadata
```

#### RiskVector (风险向量)
```
function_id, contract_name, function_signature
anomaly_score, gcn_score, static_score, business_score
knowledge_score, consistency_score, protection_score
r_func (综合风险分)
selected_scores{}, warning_scores{}  (按漏洞类型)
```

#### Finding (漏洞发现)
```
finding_id, scope, status (suspected/confirmed/rejected/inconclusive)
contract_name, function_signature, vulnerability_id
severity (high/medium/low), confidence, summary
evidence[], knowledge[], location[]
verification_plan{slither, llm_verification}
repair_suggestion{strategy, patch_pattern, post_fix_checks}
```

#### Warning (范围外警告)
```
warning_id, scope, status (screening_warning/rejected_false_positive/anomaly_warning)
contract_name, function_signature, target_vulnerability
score, summary, recommended_action{}
```

#### AuditReport (最终报告)
```
task_id, mode, workflow{}
risk_vectors[], findings[], warnings[]
metadata{evidence_center, reasoning_gate, registered_adapters, adapter_results, verification}
```

### 5.3 检测模型与漏洞类型映射

| 模型家族 | 模型 ID | 检测漏洞类型 |
|---|---|---|
| LSTM | LSTM_REENTRANCY | VULN_REENTRANCY (重入) |
| LSTM | LSTM_TIMESTAMP | VULN_TIMESTAMP (时间戳依赖) |
| LSTM | LSTM_DELEGATECALL | VULN_DELEGATECALL (不安全委托调用) |
| LSTM | LSTM_UNCHECKED_LOW_LEVEL_CALLS | VULN_UNCHECKED_LOW_LEVEL_CALLS (未检查低级调用) |
| DeepSVDD | DEEPSVDD_REENTRANCY_ANOMALY | VULN_UNKNOWN_ANOMALY (行为异常) |
| GCN | GCN_CROSS_CONTRACT | VULN_CROSS_CONTRACT_RISK (跨合约风险) |
| Static | STATIC_RULES | 全部类型 (静态规则引擎) |
| RAG | RAG_KNOWLEDGE | 全部类型 (知识库语义匹配) |

### 5.4 漏洞类型标签层次

```
supported_vulnerabilities:
├── VULN_REENTRANCY          (重入漏洞)
├── VULN_TIMESTAMP            (时间戳依赖)
├── VULN_DELEGATECALL         (不安全 delegatecall)
├── VULN_UNCHECKED_LOW_LEVEL_CALLS  (未检查低级调用)
├── VULN_CROSS_CONTRACT_RISK  (跨合约调用风险)
└── VULN_UNKNOWN_ANOMALY      (未知行为异常)
```

---

## 6. 关键架构决策与要点

1. **多模型融合评分**: 系统采用加权线性组合 (`R_func`) 融合 6 类独立信号源（异常、图、静态、业务、知识、一致性），减去防护措施带来的安全偏移。

2. **双模式推理**: LSTM/DeepSVDD 在可用 TensorFlow 时执行真实 .h5 模型推理，否则回退到基于静态特征的确定性打分。

3. **推理门控**: 并非所有函数都送 LLM 推理——`ReasoningGate` 根据风险分、项目规模动态选择候选函数（小项目 ≤10，中项目 ≤20，大项目 ≤10% 且 ≤50）。

4. **语义守卫**: 对每种漏洞类型强制执行必要条件检查，不满足则自动降级为 `rejected_false_positive` 警告——防止 LLM 幻觉产生不可信的漏洞标签。

5. **GCN 子进程隔离**: GCN 检测通过独立 Python 子进程执行（需要 ANTLR 4.7.2 + PyTorch），与主进程的 TensorFlow 环境隔离。

6. **双重验证机制**: 漏洞发现后先经 Slither 工具验证匹配，再经 LLM 验证智能体综合判断——两者均未命中也不能单独排除漏洞。

7. **无状态 API + 任务持久化**: 任务状态同时维护在内存（ThreadPoolExecutor）和磁盘（status.json），进程重启时自动恢复并标记中断任务。
