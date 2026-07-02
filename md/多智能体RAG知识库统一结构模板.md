# 多智能体 RAG 知识库统一结构模板

本文档定义一个面向智能合约漏洞检测多智能体系统的统一知识结构模板。目标是让 Detection Agent、Function Scoring Agent、Reasoning Agent、Localization Agent、Verification Agent、Repair Agent 和 Report Agent 能够共享同一套知识库，同时按各自任务检索不同类型的增强知识。

核心原则：

- 所有知识统一外层 schema，便于向量库过滤、检索、排序和溯源。
- 不同 Agent 需要的差异化知识放入 `content` 字段。
- 真实案例、标准知识、派生知识都使用同一外层结构。
- 字段缺失时使用 `null`、`unknown` 或空数组，不要编造。

## 1. 知识类型

建议将知识分为以下类型：

```text
real_case
vulnerability_reason
localization
cross_contract_relation
verification
repair
report_reference
```

各类型含义如下：

| knowledge_type | 用途 | 主要服务对象 |
| --- | --- | --- |
| `real_case` | 真实漏洞案例、benchmark 原始样本 | Detection、Report |
| `vulnerability_reason` | 漏洞原因、触发条件、攻击语义 | Reasoning |
| `localization` | 漏洞位置、危险语句、关键变量 | Localization、Report |
| `cross_contract_relation` | 跨合约调用、继承、接口、资产流和权限流 | Cross-contract Reasoning、Verification |
| `verification` | 验证步骤、误报排除、PoC 条件 | Verification |
| `repair` | 修复策略、补丁模式、安全模板 | Repair、Report |
| `report_reference` | 报告生成所需的描述、影响、修复建议 | Report |

## 2. 知识来源类型

建议使用 `source_type` 区分知识可信来源：

```text
benchmark_case
standard_knowledge
derived_from_case
rule_generated
llm_generated
manual
```

含义如下：

| source_type | 含义 |
| --- | --- |
| `benchmark_case` | DAppSCAN、ScaBench 等数据集原始案例 |
| `standard_knowledge` | SWC Registry、CWE、安全规范等标准知识 |
| `derived_from_case` | 从真实案例中抽取或总结出的增强知识 |
| `rule_generated` | 静态规则、解析器或模板生成的知识 |
| `llm_generated` | LLM 辅助总结、改写或补全的知识 |
| `manual` | 人工整理或确认的知识 |

## 3. 统一外层 Schema

所有知识条目都建议使用以下外层结构：

```json
{
  "knowledge_id": "string",
  "knowledge_type": "real_case | vulnerability_reason | localization | cross_contract_relation | verification | repair | report_reference",
  "source_type": "benchmark_case | standard_knowledge | derived_from_case | rule_generated | llm_generated | manual",
  "dataset": "DAppSCAN | ScaBench | SWC Registry | Custom",
  "case_id": "string | null",

  "swc_id": "SWC-107 | SWC-104 | unknown | null",
  "cwe_id": "CWE-841 | unknown | null",
  "vulnerability_name": "Reentrancy | Unchecked Low Level Calls | unknown",
  "risk_level": "critical | high | medium | low | info | unknown",

  "language": "Solidity",
  "chain": "Ethereum | BSC | Polygon | unknown",
  "compiler_version": "string | unknown | null",

  "project_name": "string | null",
  "source_file": "string | null",
  "contract_name": "string | null",
  "function_name": "string | null",
  "modifier_name": "string | null",

  "start_line": "number | null",
  "end_line": "number | null",
  "vulnerable_lines": ["number"],

  "agent_targets": [
    "detection",
    "function_scoring",
    "reasoning",
    "localization",
    "verification",
    "repair",
    "report"
  ],

  "retrieval": {
    "primary_query_text": "string",
    "keywords": ["string"],
    "code_symbols": ["string"],
    "dangerous_apis": ["string"],
    "semantic_tags": [
      "external_call",
      "state_update",
      "access_control",
      "cross_contract_call"
    ]
  },

  "relations": {
    "related_knowledge_ids": ["string"],
    "parent_case_id": "string | null",
    "related_contracts": ["string"],
    "related_functions": ["string"],
    "called_functions": ["string"],
    "caller_functions": ["string"],
    "inheritance": ["string"],
    "imports": ["string"],
    "external_calls": [
      {
        "source_contract": "string",
        "source_function": "string",
        "target_contract": "string | unknown",
        "target_function": "string | unknown",
        "call_expression": "string",
        "relation_type": "external_call | delegatecall | library_call | interface_call | token_transfer"
      }
    ]
  },

  "evidence": {
    "raw_code": "string | null",
    "function_code": "string | null",
    "context_code": "string | null",
    "annotation": "string | null",
    "audit_description": "string | null",
    "ground_truth": "string | null"
  },

  "content": {},

  "quality": {
    "confidence": "high | medium | low | unknown",
    "is_ground_truth": true,
    "needs_human_review": false,
    "derivation_method": "raw_dataset | static_rule | parser | llm_assisted | manual",
    "derivation_notes": "string | null"
  },

  "storage": {
    "embedding_text": "string",
    "metadata_version": "v1.0",
    "created_at": "YYYY-MM-DD",
    "updated_at": "YYYY-MM-DD"
  }
}
```

## 4. 字段说明

### 4.1 基础标识字段

| 字段 | 说明 |
| --- | --- |
| `knowledge_id` | 知识条目唯一 ID |
| `knowledge_type` | 知识类型，用于 Agent 过滤 |
| `source_type` | 知识来源类型，用于可信度判断 |
| `dataset` | 来源数据集或知识源 |
| `case_id` | 原始案例 ID，多条派生知识可共享同一个 `case_id` |

### 4.2 漏洞标签字段

| 字段 | 说明 |
| --- | --- |
| `swc_id` | SWC 编号，如 `SWC-107` |
| `cwe_id` | CWE 编号，如 `CWE-841` |
| `vulnerability_name` | 漏洞名称 |
| `risk_level` | 风险等级 |

### 4.3 代码定位字段

| 字段 | 说明 |
| --- | --- |
| `project_name` | 项目或审计对象名称 |
| `source_file` | 源文件路径 |
| `contract_name` | 合约名 |
| `function_name` | 函数名 |
| `modifier_name` | modifier 名称 |
| `start_line` | 起始行 |
| `end_line` | 结束行 |
| `vulnerable_lines` | 漏洞关键行 |

### 4.4 检索字段

`retrieval` 字段用于构造向量文本和关键词过滤：

| 字段 | 说明 |
| --- | --- |
| `primary_query_text` | 主要用于 embedding 的语义文本 |
| `keywords` | 漏洞关键词 |
| `code_symbols` | 变量名、函数名、合约名等符号 |
| `dangerous_apis` | 危险 API，如 `call`、`delegatecall` |
| `semantic_tags` | 语义标签，如外部调用、状态更新、权限控制 |

### 4.5 关系字段

`relations` 字段用于跨知识条目和跨合约推理：

| 字段 | 说明 |
| --- | --- |
| `related_knowledge_ids` | 相关知识 ID |
| `parent_case_id` | 所属原始案例 ID |
| `related_contracts` | 相关合约 |
| `related_functions` | 相关函数 |
| `called_functions` | 当前函数调用的函数 |
| `caller_functions` | 调用当前函数的函数 |
| `inheritance` | 继承关系 |
| `imports` | import 依赖 |
| `external_calls` | 外部合约调用关系 |

### 4.6 证据字段

`evidence` 字段保存可回溯证据：

| 字段 | 说明 |
| --- | --- |
| `raw_code` | 原始代码 |
| `function_code` | 函数代码 |
| `context_code` | 函数上下文、调用依赖代码 |
| `annotation` | SWC 注释、审计标注等 |
| `audit_description` | 审计报告描述 |
| `ground_truth` | benchmark ground truth |

### 4.7 质量字段

`quality` 字段用于控制知识可信度：

| 字段 | 说明 |
| --- | --- |
| `confidence` | 知识置信度 |
| `is_ground_truth` | 是否为原始真实标签 |
| `needs_human_review` | 是否需要人工复核 |
| `derivation_method` | 知识生成方法 |
| `derivation_notes` | 生成说明 |

## 5. 不同知识类型的 Content 模板

### 5.1 real_case

用于保存 DAppSCAN、ScaBench 等真实案例或 benchmark 原始样本。

```json
{
  "content": {
    "case_summary": "真实漏洞案例摘要",
    "vulnerable_code": "漏洞代码",
    "fixed_code": "修复代码，如果没有则为 null",
    "label": "vulnerable | safe | unknown",
    "raw_label": "数据集原始标签",
    "raw_metadata": {}
  }
}
```

### 5.2 vulnerability_reason

用于解释漏洞为什么成立，主要服务 Reasoning Agent。

```json
{
  "content": {
    "cause": "漏洞产生原因",
    "trigger_conditions": ["触发条件1", "触发条件2"],
    "dangerous_patterns": ["危险模式1", "危险模式2"],
    "attack_scenario": "攻击者如何利用该漏洞",
    "security_property_violated": "违反的安全属性",
    "similar_case_explanation": "与真实案例的相似原因"
  }
}
```

### 5.3 localization

用于说明漏洞位置、关键变量和危险语句，主要服务 Localization Agent 和 Report Agent。

```json
{
  "content": {
    "vulnerability_location_summary": "漏洞位置说明",
    "source_variables": ["输入变量或状态变量"],
    "sink_statements": ["危险语句"],
    "tainted_variables": ["受污染变量"],
    "critical_statements": [
      {
        "line": 123,
        "code": "msg.sender.call{value: amount}(\"\");",
        "role": "external_call | state_update | access_check | input_validation"
      }
    ],
    "localization_reason": "为什么这些行是漏洞关键位置"
  }
}
```

### 5.4 cross_contract_relation

用于描述跨合约调用、继承、接口调用、资产流和权限依赖。

```json
{
  "content": {
    "relation_summary": "跨合约关系说明",
    "call_chain": [
      {
        "from_contract": "Vault",
        "from_function": "withdraw",
        "to_contract": "Token",
        "to_function": "transfer",
        "call_type": "external_call"
      }
    ],
    "state_dependency": ["依赖的状态变量"],
    "permission_dependency": ["权限依赖"],
    "asset_flow": ["资金或 Token 流向"],
    "cross_contract_risk": "跨合约风险说明"
  }
}
```

### 5.5 verification

用于保存验证漏洞是否成立的规则、步骤和误报排除条件。

```json
{
  "content": {
    "verification_goal": "验证目标",
    "static_checks": ["静态检查规则1", "静态检查规则2"],
    "dynamic_checks": ["动态验证步骤1", "动态验证步骤2"],
    "poc_requirements": ["PoC 需要满足的条件"],
    "false_positive_checks": ["误报排除条件"],
    "expected_vulnerable_behavior": "漏洞存在时的表现",
    "expected_safe_behavior": "安全实现的表现"
  }
}
```

### 5.6 repair

用于保存修复策略、补丁模式、安全代码模板和修复后检查项。

```json
{
  "content": {
    "repair_strategy": "修复策略",
    "patch_pattern": "修复模式",
    "safe_code_template": "安全代码模板",
    "unsafe_code_pattern": "不安全代码模式",
    "recommended_changes": [
      {
        "location": "函数名或行号",
        "before": "修改前代码",
        "after": "修改后代码",
        "reason": "修改原因"
      }
    ],
    "side_effects": ["可能副作用"],
    "post_fix_checks": ["修复后需要验证的点"]
  }
}
```

### 5.7 report_reference

用于报告生成，保存可直接组织为审计报告的描述信息。

```json
{
  "content": {
    "title": "报告标题",
    "summary": "漏洞摘要",
    "impact": "安全影响",
    "affected_components": ["受影响合约或函数"],
    "recommendation": "修复建议",
    "reference_cases": ["相关真实案例 ID"],
    "report_language": "zh | en"
  }
}
```

## 6. 真实案例如何落库

对于 DAppSCAN、ScaBench 等真实案例，建议先保存原始事实，再逐步生成增强知识。

原始案例保存为：

```json
{
  "knowledge_type": "real_case",
  "source_type": "benchmark_case",
  "dataset": "ScaBench",
  "case_id": "scabench_0001",
  "content": {
    "case_summary": "unknown",
    "vulnerable_code": "...",
    "fixed_code": null,
    "label": "vulnerable",
    "raw_label": "...",
    "raw_metadata": {}
  }
}
```

随后从同一案例派生出多条增强知识：

```text
scabench_0001_real_case
scabench_0001_reason
scabench_0001_localization
scabench_0001_cross_contract
scabench_0001_verification
scabench_0001_repair
```

这些知识通过 `case_id` 和 `relations.parent_case_id` 关联：

```json
{
  "case_id": "scabench_0001",
  "relations": {
    "parent_case_id": "scabench_0001",
    "related_knowledge_ids": [
      "scabench_0001_reason",
      "scabench_0001_localization",
      "scabench_0001_verification"
    ]
  }
}
```

注意：

- `real_case` 是数据集原始事实。
- `vulnerability_reason` 通常是从案例和标准知识中总结出来的。
- `localization` 可以来自数据集标注、SWC 注释或静态解析。
- `cross_contract_relation` 通常来自 Solidity 解析和调用图分析。
- `verification` 可能来自规则模板、人工经验或 LLM 辅助总结。
- `repair` 如果数据集没有补丁，不要标记为 ground truth。

## 7. 多智能体检索策略

不同 Agent 应按 `knowledge_type` 和 `agent_targets` 过滤知识。

| Agent | 推荐检索 knowledge_type |
| --- | --- |
| Detection Agent | `real_case`, `vulnerability_reason` |
| Function Scoring Agent | `real_case`, `localization`, `vulnerability_reason` |
| Reasoning Agent | `vulnerability_reason`, `real_case`, `cross_contract_relation` |
| Localization Agent | `localization`, `real_case`, `cross_contract_relation` |
| Cross-contract Agent | `cross_contract_relation`, `localization` |
| Verification Agent | `verification`, `vulnerability_reason`, `cross_contract_relation` |
| Repair Agent | `repair`, `verification`, `real_case` |
| Report Agent | `report_reference`, `localization`, `repair`, `real_case` |

示例检索策略：

```text
Reasoning Agent:
  filter knowledge_type in ["vulnerability_reason", "real_case"]
  filter swc_id if available
  retrieve by function code + risky API + semantic tags

Localization Agent:
  filter knowledge_type in ["localization", "cross_contract_relation"]
  retrieve by function code + variable names + called functions

Verification Agent:
  filter knowledge_type in ["verification", "vulnerability_reason"]
  retrieve by suspected vulnerability type + critical statements

Repair Agent:
  filter knowledge_type in ["repair"]
  retrieve by swc_id + unsafe pattern + function context
```

## 8. Deep Lake / Qdrant 存储建议

### 8.1 向量文本

`storage.embedding_text` 应该拼接最适合语义检索的信息，而不是直接塞完整 JSON。

推荐格式：

```text
Knowledge Type: vulnerability_reason
SWC: SWC-107
Vulnerability: Reentrancy
Contract: Vault
Function: withdraw
Dangerous APIs: call, external call before state update
Cause: External call is executed before balance update, allowing recursive re-entry.
Evidence Code:
...
```

### 8.2 Metadata

向量数据库 metadata 建议保留这些字段用于过滤：

```json
{
  "knowledge_id": "string",
  "knowledge_type": "string",
  "source_type": "string",
  "dataset": "string",
  "case_id": "string",
  "swc_id": "string",
  "vulnerability_name": "string",
  "risk_level": "string",
  "contract_name": "string",
  "function_name": "string",
  "source_file": "string",
  "start_line": 0,
  "end_line": 0,
  "agent_targets": "[\"reasoning\", \"verification\"]",
  "confidence": "high",
  "is_ground_truth": true
}
```

### 8.3 原文保存

Deep Lake / Qdrant 中的 `text` 字段建议保存：

```text
storage.embedding_text
```

完整 JSON 可以保存到：

```text
metadata.full_json
```

或单独保存到本地 JSONL 文件：

```text
dataset/knowledge/multi_agent_knowledge.jsonl
```

向量库只保存必要 metadata 和 embedding text，避免 metadata 过大影响性能。

## 9. 命名规范

推荐知识 ID：

```text
{dataset}_{case_id}_{knowledge_type}
```

示例：

```text
dappscan_000001_real_case
dappscan_000001_reason
dappscan_000001_localization
dappscan_000001_cross_contract
dappscan_000001_verification
dappscan_000001_repair
```

如果一个案例中有多个漏洞函数：

```text
dappscan_000001_withdraw_reason
dappscan_000001_withdraw_localization
dappscan_000001_deposit_reason
```

## 10. 落库流程

推荐流程：

```text
DAppSCAN / ScaBench / SWC Registry
        ↓
Solidity Parser + SWC Annotation Extractor
        ↓
Case Normalizer
        ↓
Knowledge Builder
        ↓
生成 real_case / reason / localization / cross_contract / verification / repair
        ↓
JSONL 原始知识文件
        ↓
Deep Lake / Qdrant 向量库
        ↓
Multi-Agent RAG Retriever
```

具体步骤：

1. 收集 `.sol`、审计描述、SWC 标注、benchmark 标签。
2. 解析合约、函数、modifier、状态变量、import、继承关系。
3. 为每个真实样本生成 `real_case`。
4. 从 SWC 注释、规则和案例代码派生 `vulnerability_reason`。
5. 从行号、危险语句、变量流派生 `localization`。
6. 从调用图、继承图、外部调用派生 `cross_contract_relation`。
7. 从漏洞类型和代码模式派生 `verification`。
8. 从修复模板和安全模式派生 `repair`。
9. 生成 `storage.embedding_text`。
10. 写入 JSONL，并同步写入 Deep Lake / Qdrant。

## 11. 最小可用版本

如果一开始信息不完整，最小可用条目只需要：

```json
{
  "knowledge_id": "scabench_0001_real_case",
  "knowledge_type": "real_case",
  "source_type": "benchmark_case",
  "dataset": "ScaBench",
  "case_id": "scabench_0001",
  "swc_id": "unknown",
  "vulnerability_name": "unknown",
  "source_file": "path/to/file.sol",
  "contract_name": "unknown",
  "function_name": "unknown",
  "agent_targets": ["detection", "reasoning", "localization", "report"],
  "retrieval": {
    "primary_query_text": "contract/function code and raw label",
    "keywords": [],
    "code_symbols": [],
    "dangerous_apis": [],
    "semantic_tags": []
  },
  "relations": {
    "related_knowledge_ids": [],
    "parent_case_id": "scabench_0001",
    "related_contracts": [],
    "related_functions": [],
    "called_functions": [],
    "caller_functions": [],
    "inheritance": [],
    "imports": [],
    "external_calls": []
  },
  "evidence": {
    "raw_code": "...",
    "function_code": null,
    "context_code": null,
    "annotation": null,
    "audit_description": null,
    "ground_truth": "vulnerable"
  },
  "content": {
    "case_summary": "unknown",
    "vulnerable_code": "...",
    "fixed_code": null,
    "label": "vulnerable",
    "raw_label": "vulnerable",
    "raw_metadata": {}
  },
  "quality": {
    "confidence": "high",
    "is_ground_truth": true,
    "needs_human_review": false,
    "derivation_method": "raw_dataset",
    "derivation_notes": null
  },
  "storage": {
    "embedding_text": "ScaBench real vulnerable smart contract case ...",
    "metadata_version": "v1.0",
    "created_at": "2026-07-01",
    "updated_at": "2026-07-01"
  }
}
```

结论：

统一 schema 是为了让多个智能体稳定协作；真实案例也使用统一结构，但只填写已有事实。增强知识可以后续逐步生成，并通过 `case_id`、`parent_case_id` 和 `related_knowledge_ids` 与原始案例关联。
