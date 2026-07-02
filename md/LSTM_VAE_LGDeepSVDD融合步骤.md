# LSTM + VAE + LG-DeepSVDD 融合修改步骤

本文档说明如何按照报告中的思路，将 SCG 项目中的 VAE 智能合约漏洞样本生成模块，与 `LG-DeepSVDD` 中的 LSTM/DeepSVDD 漏洞检测模块融合起来，用生成的异常合约样本缓解正常合约与漏洞合约样本不平衡的问题。

核心思想不是把 VAE 和 LSTM 的网络结构直接拼接，而是在数据层完成融合：

```text
真实合约 opcode/embedding
        +
VAE 生成的漏洞合约 embedding
        ↓
构造平衡后的训练集
        ↓
训练或微调 LG-DeepSVDD 中的 LSTM
        ↓
提取 LSTM 语义特征
        ↓
送入 DeepSVDD 做异常/未知漏洞检测
```

## 第 1 步：统一数据格式

### 目的

确保真实合约样本和 VAE 生成样本可以被同一个 LSTM 模型读取。

当前 SCG 中 VAE 生成的数据主要保存在：

```text
dataset/embedding/generated_contract/
```

真实合约 embedding 主要保存在：

```text
dataset/embedding/smart_contract/
```

每一行表示一个合约样本，长度通常为 500，对应 opcode/token 序列。

### 需要关注的文件

```text
dataset/embedding/smart_contract/normal.csv
dataset/embedding/smart_contract/reentrancy.csv
dataset/embedding/smart_contract/timestamp.csv
dataset/embedding/smart_contract/delegatecall.csv
dataset/embedding/smart_contract/SBunchecked_low_level_calls.csv
dataset/embedding/generated_contract/generated_reentrancy_with_sem.csv
dataset/embedding/generated_contract/generated_timestamp_with_sem.csv
dataset/embedding/generated_contract/generated_delegatecall_with_sem.csv
dataset/embedding/generated_contract/generated_SBunchecked_low_level_calls_with_sem.csv
dataset/embedding/generated_contract/generated_unknown_with_sem.csv
```

### 修改建议

建议让 `LG-DeepSVDD` 直接读取 SCG 已经生成好的 embedding CSV，而不是继续从 `simpleOpcode` 文本重新 tokenizer。

这样可以避免两个项目 tokenizer 不一致导致的语义错位问题。例如：SCG 中 token id `12` 和 LG-DeepSVDD 中 token id `12` 未必代表同一个 opcode。

### 验证方式

检查每个 CSV 是否满足：

```text
每行一个合约样本
每行长度约为 500
真实样本和生成样本列数一致
```

可以用 pandas 检查：

```python
import pandas as pd

normal = pd.read_csv("dataset/embedding/smart_contract/normal.csv")
generated = pd.read_csv("dataset/embedding/generated_contract/generated_reentrancy_with_sem.csv", index_col=0)

print(normal.shape)
print(generated.shape)
```

## 第 2 步：在 LG-DeepSVDD 中新增融合数据加载函数

### 目的

把正常合约、真实漏洞合约、VAE 生成漏洞合约拼成新的训练集，用于降低样本不平衡。

### 需要修改的文件

```text
LG-DeepSVDD/tools.py
```

### 新增函数建议

可以新增一个函数，例如：

```python
def get_lstm_dataset_with_generated(vul_type, generated_num):
    """
    vul_type: 漏洞类型，如 reentrancy、timestamp、delegatecall
    generated_num: 使用多少条 VAE 生成样本
    """
```

函数逻辑：

```text
1. 读取 normal.csv，标签设为 0
2. 读取指定真实漏洞 csv，标签设为 1
3. 读取 generated_<vul_type>_with_sem.csv，取前 generated_num 条，标签设为 1
4. 拼接为完整数据集
5. 划分 train、val、test
6. 返回 X_train, X_val, X_test, y_train, y_val, y_test
```

### 标签设计

已知漏洞二分类实验：

```text
normal                         -> 0
真实漏洞 vul_type              -> 1
generated_vul_type_with_sem    -> 1
```

未知漏洞检测实验：

```text
normal                         -> 0
已知真实漏洞集合               -> 1
generated_unknown_with_sem      -> 1
```

### 验证方式

调用函数后检查：

```text
X_train.shape
X_val.shape
X_test.shape
y_train 中 0/1 数量
y_test 中 0/1 数量
```

重点确认 `generated_num` 增大后，训练集中漏洞样本数量确实增加。

## 第 3 步：修改 LSTM 训练入口

### 目的

让 `LG-DeepSVDD` 中的 LSTM 使用融合后的训练集，而不是只使用原始数据集。

### 需要修改的文件

```text
LG-DeepSVDD/pretrain/semantic features/LSTM/train_lstm.py
```

### 原始逻辑

原来脚本主要从类似下面的文件读取数据：

```text
../../../data/dataset/final2.csv
```

然后再使用 LG-DeepSVDD 自己的 tokenizer 编码。

### 修改逻辑

改为调用第 2 步新增的数据加载函数：

```python
from tools import get_lstm_dataset_with_generated

X_train, X_val, X_test, y_train, y_val, y_test = get_lstm_dataset_with_generated(
    vul_type="reentrancy",
    generated_num=3000
)
```

如果直接读取的是 embedding CSV，则不需要再执行 `getsequence()` tokenizer 编码，`X_train` 本身已经是模型可输入的序列矩阵。

### 参数统一

建议统一为：

```python
max_len = 500
max_words = 128
```

原因是 SCG 中 VAE 生成模型的词表大小通常按 128 设置，而 LG-DeepSVDD 原始 LSTM 中部分代码使用 `max_words = 64`。如果不统一，可能导致生成样本中超过 64 的 token id 被错误处理。

### 实验方式

分别测试不同生成样本数量：

```text
generated_num = 0
generated_num = 500
generated_num = 1000
generated_num = 3000
generated_num = 5000
```

记录每次的：

```text
Precision
Recall
F1-score
```

这样可以直接证明 VAE 生成样本是否缓解了样本不平衡问题。

## 第 4 步：修改 LSTM 特征提取脚本

### 目的

让 LSTM 不仅用于分类，还能为 DeepSVDD 提取语义特征。

### 需要修改的文件

```text
LG-DeepSVDD/pretrain/semantic features/LSTM/get_lstm_features.py
```

### 原始逻辑

该脚本加载训练好的 LSTM 模型，例如：

```python
model = load_model("lstm5.h5")
```

然后通过子模型提取中间层特征：

```python
sub_model1 = tf.keras.Model(inputs=model.input, outputs=model.get_layer("LSTM").output)
```

### 修改逻辑

增加对 SCG 生成样本的读取和特征提取，例如：

```text
dataset/embedding/generated_contract/generated_reentrancy_with_sem.csv
dataset/embedding/generated_contract/generated_unknown_with_sem.csv
```

输出建议保存为：

```text
LG-DeepSVDD/data/dataset/features/lstm/lstm_reentrancy_generated.csv
LG-DeepSVDD/data/dataset/features/lstm/lstm_timestamp_generated.csv
LG-DeepSVDD/data/dataset/features/lstm/lstm_delegatecall_generated.csv
LG-DeepSVDD/data/dataset/features/lstm/lstm_unknown_generated.csv
```

### 注意事项

如果输入已经是 embedding/token id 矩阵，就不要再调用 tokenizer。

如果输入仍然是 opcode 文本，才需要：

```python
getsequence(opcode, filepath)
```

### 验证方式

检查输出特征文件：

```text
行数 = 输入样本数
列数 = LSTM 隐藏层维度，例如 64 或 128
```

## 第 5 步：修改 DeepSVDD 检测入口

### 目的

让 DeepSVDD 使用融合后的 LSTM 语义特征进行异常检测或未知漏洞检测。

### 需要修改的文件

```text
LG-DeepSVDD/DeepSVDD/svdd_main.py
```

### 原始逻辑

原来可能读取：

```python
datan = pd.read_csv("../data/dataset/features/fused2/5normal.csv").iloc[:, 1:].values
```

### 修改逻辑

改为读取第 4 步生成的 LSTM 特征文件。

已知漏洞检测可以使用：

```text
normal_lstm_features.csv
reentrancy_lstm_features.csv
reentrancy_generated_lstm_features.csv
```

未知漏洞检测可以使用：

```text
normal_lstm_features.csv
known_vulnerability_lstm_features.csv
unknown_generated_lstm_features.csv
```

### 推荐实验设计

DeepSVDD 一般适合用正常样本学习正常边界：

```text
训练：normal 特征
测试：normal + 真实漏洞 + VAE 生成漏洞 + 未知漏洞
```

如果要体现报告中“生成异常样本辅助未知漏洞检测”的思路，可以做两组对比：

```text
实验 A：只用真实样本训练 LSTM，再提取特征送入 DeepSVDD
实验 B：真实样本 + VAE 生成样本训练 LSTM，再提取特征送入 DeepSVDD
```

对比指标：

```text
Precision
Recall
F1-score
AUC
```

## 第 6 步：做对比实验并记录结果

### 目的

证明 VAE 生成样本确实降低了样本不平衡对检测结果的影响。

### 推荐实验表格

| 漏洞类型 | 生成样本数 | Precision | Recall | F1-score |
| --- | ---: | ---: | ---: | ---: |
| reentrancy | 0 |  |  |  |
| reentrancy | 500 |  |  |  |
| reentrancy | 1000 |  |  |  |
| reentrancy | 3000 |  |  |  |
| reentrancy | 5000 |  |  |  |
| timestamp | 0 |  |  |  |
| timestamp | 500 |  |  |  |
| delegatecall | 0 |  |  |  |
| delegatecall | 500 |  |  |  |

### 预期结论写法

如果结果符合预期，可以在报告或论文中写：

```text
随着 VAE 生成异常合约样本数量增加，LSTM 对漏洞合约的召回率和 F1-score 有明显提升，说明生成样本能够缓解异常合约数量不足导致的样本不平衡问题。
```

如果生成样本过多导致 F1 下降，可以写：

```text
当生成样本数量超过一定阈值后，模型性能出现下降，说明生成样本与真实样本仍存在分布差异。因此需要选择合适的生成样本比例。
```

## 最小可跑通版本

如果时间有限，可以先只完成前三步：

```text
1. 统一数据格式
2. 新增融合数据加载函数
3. 修改 LSTM 训练入口
```

然后直接比较：

```text
generated_num = 0
generated_num = 500
generated_num = 1000
generated_num = 3000
generated_num = 5000
```

对应的 LSTM 检测 F1-score。

这个版本已经可以支撑报告中的核心论点：

```text
VAE 生成异常智能合约样本，可以扩充漏洞样本数量，降低样本不平衡对 LSTM 漏洞检测结果的影响。
```

## 文件修改优先级

优先级从高到低：

```text
1. LG-DeepSVDD/tools.py
2. LG-DeepSVDD/pretrain/semantic features/LSTM/train_lstm.py
3. LG-DeepSVDD/pretrain/semantic features/LSTM/get_lstm_features.py
4. LG-DeepSVDD/DeepSVDD/svdd_main.py
5. SCG 的 VAE 训练和生成脚本
```

如果已有 VAE 生成样本和 `.pt` 权重，SCG 的 VAE 脚本可以暂时不改，直接使用已有生成结果。

