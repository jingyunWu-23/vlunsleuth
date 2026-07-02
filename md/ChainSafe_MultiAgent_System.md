# ChainSafeFort + 多智能体 + 安全知识库智能合约漏洞检测框架（完整方案总结）

## 1. 总体概述

本方案构建一个基于
ChainSafeFort、漏洞安全知识库和异构多智能体协同的分层智能合约漏洞检测与定位框架。

核心目标包括： - 漏洞检测（已知 + 未知 + 跨合约） - 不良实践识别 -
漏洞语义定位 - 攻击路径推理 - 修复建议生成 - 成本感知的分层审计

------------------------------------------------------------------------

## 2. 系统核心结构

### 2.1 总体流程

    用户合约输入
    ↓
    合约预处理与结构提取
    ↓
    ChainSafeFort 风险预筛（LSTM / GCN / VAE）
    ↓
    风险评分与审计成本评估
    ↓
    安全知识库 RAG 检索
    ↓
    异构多智能体协同分析
    ↓
    漏洞定位与证据融合
    ↓
    分层审计报告输出

------------------------------------------------------------------------

## 3. ChainSafeFort 在系统中的作用

### 3.1 VAE 异常样本生成

-   生成少样本漏洞变体
-   扩充知识库
-   用于未知漏洞检测

### 3.2 LSTM 单合约检测

-   opcode 序列建模
-   输出漏洞类型与置信度
-   提供函数级风险预筛

### 3.3 GCN 跨合约检测

-   构建跨合约语法语义图
-   捕捉调用关系与状态依赖
-   输出跨合约风险路径

------------------------------------------------------------------------

## 4. 安全知识库设计

知识库包含六大类：

### 4.1 不良实践（Bad Practice）

-   unchecked call return value
-   tx.origin 使用
-   delegatecall 风险
-   block.timestamp 依赖

### 4.2 真实漏洞案例

-   Reentrancy
-   Price Manipulation
-   Access Control
-   Flashloan Attack

### 4.3 生成异常样本

-   ChainSafeFort VAE 生成
-   标记可信度

### 4.4 跨合约攻击案例

-   DeFi 组合攻击
-   跨链桥攻击
-   状态同步错误

### 4.5 静态验证规则

-   CEI 顺序检查
-   权限检查规则
-   数据流分析规则

### 4.6 修复知识

-   ReentrancyGuard
-   TWAP / Oracle
-   权限控制模板

------------------------------------------------------------------------

## 5. 多智能体系统设计

### 5.1 检测型 Agent（非 LLM）

  Agent            功能
  ---------------- ----------------
  LSTM Agent       单合约漏洞检测
  GCN Agent        跨合约漏洞检测
  VAE Agent        异常样本生成
  静态分析 Agent   代码结构与定位
  RAG Agent        知识检索

------------------------------------------------------------------------

### 5.2 推理型 Agent（LLM）

  Agent              功能
  ------------------ ------------------
  漏洞推理 Agent     是否构成真实漏洞
  跨合约分析 Agent   状态与调用链分析
  验证 Agent         证据一致性检查
  修复建议 Agent     修复方案生成
  报告 Agent         审计报告输出

------------------------------------------------------------------------

## 6. 漏洞定位机制

定位来源包括：

### 6.1 静态分析（核心）

-   行号定位
-   函数边界
-   AST / CFG / DFG

### 6.2 LSTM 粗定位

-   opcode window 分段分析
-   高风险函数识别

### 6.3 GCN 跨合约定位

-   高风险节点/边
-   跨合约调用路径

### 6.4 多智能体语义验证

-   攻击路径验证
-   根因分析

------------------------------------------------------------------------

## 7. 风险分层输出

  等级      含义
  --------- -------------------------
  Level 1   Bad Practice
  Level 2   Vulnerability Candidate
  Level 3   Verified Vulnerability
  Level 4   Cross-contract Risk

------------------------------------------------------------------------

## 8. 成本感知审计机制

### 风险评分：

RiskScore = AssetValue × Exploitability × Impact × Confidence

### 分层策略：

-   低风险：静态 + LSTM
-   中风险：GCN + RAG
-   高风险：多智能体推理
-   极高风险：PoC + 人工复核

------------------------------------------------------------------------

## 9. SCALM 的定位（非直接集成）

本系统不直接集成 SCALM，而是借鉴其：

-   RAG 检索机制
-   Step-Back Prompting
-   安全语义抽象

用于构建自有知识库与推理机制。

------------------------------------------------------------------------

## 10. 核心创新点

### 10.1 生成样本增强知识库

-   VAE 扩充漏洞样本

### 10.2 异构多智能体协同

-   LSTM / GCN + LLM Agent

### 10.3 定位 + 检测 + 验证三层结构

-   不仅检测，还能定位与验证

### 10.4 成本感知分层审计

-   控制 LLM 使用成本

------------------------------------------------------------------------

## 11. 总结

本系统融合： - ChainSafeFort（深度学习检测） - 自建安全语义知识库 -
异构多智能体系统 - 静态分析与RAG机制

实现智能合约漏洞的： 检测 + 定位 + 解释 + 验证 + 修复建议一体化框架。

------------------------------------------------------------------------

## 12. 非大语言模型 Agent 输出格式化函数

为了让 LSTM、DeepSVDD、GCN、静态分析等非大语言模型 Agent 能够稳定地与 LLM Agent 交互，所有普通模型 Agent 的输出应统一封装为结构化 JSON 证据包。

普通模型不应只输出自然语言结论，例如“存在漏洞”，而应输出检测目标、风险类型、概率或异常分数、阈值、模型版本、证据来源和置信度。

统一格式化函数如下：

```python
def format_model_evidence(
    agent_id,
    model_name,
    risk_type,
    target,
    label,
    confidence,
    probability=None,
    score=None,
    threshold=None,
    evidence=None,
    metadata=None
):
    return {
        "message_type": "model_evidence",
        "agent_id": agent_id,
        "agent_type": "detector",
        "model": {
            "name": model_name,
            "version": metadata.get("model_version") if metadata else None
        },
        "target": target,
        "risk": {
            "risk_type": risk_type,
            "label": label,
            "probability": probability,
            "score": score,
            "threshold": threshold,
            "confidence": confidence
        },
        "evidence": evidence or {},
        "metadata": metadata or {}
    }
```

### 12.1 LSTM Agent 输出示例

```python
format_model_evidence(
    agent_id="lstm_reentrancy_agent",
    model_name="LSTM",
    risk_type="reentrancy",
    target={
        "contract": "Bank.sol",
        "function": "withdraw"
    },
    label="vulnerable",
    confidence="high",
    probability=0.87,
    threshold=0.5,
    evidence={
        "feature_source": "opcode_sequence",
        "sequence_length": 500,
        "output_field": "vulnerability_probability"
    },
    metadata={
        "model_version": "lstm_scg_reentrancy_gen1000"
    }
)
```

### 12.2 DeepSVDD Agent 输出示例

```python
format_model_evidence(
    agent_id="deepsvdd_agent",
    model_name="DeepSVDD",
    risk_type="unknown_anomaly",
    target={
        "contract": "Bank.sol"
    },
    label="anomaly",
    confidence="medium",
    score=0.214,
    threshold=0.196,
    evidence={
        "feature_source": "lstm_hidden_feature",
        "distance_to_normal_center": 0.214,
        "interpretation": "semantic feature deviates from normal contract distribution"
    },
    metadata={
        "model_version": "svdd_scg_reentrancy_gen1000"
    }
)
```

### 12.3 设计原则

所有非 LLM Agent 的输出都应先经过 `format_model_evidence()` 统一封装，再交给 LLM Agent。

这样可以保证：

- LLM Agent 能稳定解析不同模型的输出；
- 检测证据可追踪；
- 概率、阈值、异常分数、模型版本可复核；
- 后续报告 Agent 可以直接引用结构化证据；
- 多智能体之间的协同更加清晰。

推荐后续在代码中单独建立：

```text
agents/message_schema.py
```

并在其中实现：

```text
format_model_evidence()
format_reasoning_request()
format_reasoning_result()
format_verification_result()
format_final_report_section()
```
