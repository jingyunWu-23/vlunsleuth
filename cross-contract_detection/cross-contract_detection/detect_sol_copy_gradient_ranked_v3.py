# Copy runner for one Solidity file -> AST JSON -> Graph/Edge -> BFS_EA_RGCN prediction.
# Original files are unchanged.

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable
from torch.nn.parameter import Parameter

class Graph():
    def __init__(self, num_nodes, edge_pairs, features, label, node_degs):
        self.num_nodes = num_nodes
        self.edge_pairs = edge_pairs
        self.features = features
        self.label = label
        self.node_degs = node_degs  # 邻接点数量

    def __str__(self):
        return ('nodes: %d  edge_pairs: %d features: %d' % (self.num_nodes, len(self.edge_pairs), len(self.features)))


# In[3]:

class deal():
    def getGraph(self, filename):
        f = open(filename)
        row = f.readline().strip().split()
        nodes, label = [int(w) for w in row]
        node_features = []
        edge_pairs = []
        node_degs = []
        for j in range(nodes):
            row = f.readline().strip().split()
            node_deg = int(row[0]) + 1
            row, attr = [int(w) for w in row[1:int(row[0]) + 1]], np.array([float(w) for w in row[int(row[0]) + 1:]])
            if attr is not None:
                node_features.append(attr)
            if node_deg is not None:
                node_degs.append(node_deg)
            if row is not None:
                for k in row:
                    edge = [j, k]
                    edge_pairs.append(edge)
        g = Graph(nodes, edge_pairs, node_features, label, node_degs)
        return g

    # In[4]:

    def getGraphList(self, files):
        glist = []
        for file in files:
            graph = self.getGraph(file)
            glist.append(graph)
        return glist

    # In[5]:

    def getEdgeList(self, files, k):
        EdgeList = []
        for file in files:
            li = np.loadtxt(file)
            EdgeList.append(li)
        EdgeList = self.processEdgeList(EdgeList, k)
        return EdgeList

    def processEdgeList(self, edges, k):
        newList = []
        for item in edges:
            # print(item.shape[0])
            if item.shape[0] >= k:
                newList.append(item[:k, :].tolist())
            else:
                t = np.zeros((k - item.shape[0], 100))
                newList.append(np.concatenate((item, t)).tolist())
        return torch.FloatTensor(np.array(newList))

    def getEdgeNum(self, files):
        EdgeNum = []
        for file in files:
            li = np.loadtxt(file)
            EdgeNum.append(li.shape[0])
        return EdgeNum

    # In[6]:

    # te = getEdgeList(train_edge_data[:5],99)
    # te = torch.FloatTensor(te)
    # mo = Edge_Attention(2,100)
    # a = mo(te)
    # encoder_layer = nn.TransformerEncoderLayer(d_model=100, nhead=2)
    # src = torch.rand(10, 32, 512)
    # out = encoder_layer(te)

    # In[7]:

    # a = [1,2,3,4]
    # b = [1,2,6,4]
    # (np.array(a)+np.array(b))/2

    # In[8]:

    def merge_Graph(self, graph_list):
        prefix_sum = []
        node_features = []
        node_degs = []
        node_labels = []
        total_num_edges = 0
        total_num_nodes = 0
        edge_pairs = []
        graph_sizes = []
        for i in range(len(graph_list)):
            prefix_sum.append(graph_list[i].num_nodes)
            if i != 0:
                prefix_sum[i] += prefix_sum[i - 1]
            node_features.extend(graph_list[i].features)
            node_degs.extend(graph_list[i].node_degs)
            node_labels.append(graph_list[i].label)
            total_num_edges += len(graph_list[i].edge_pairs)
            total_num_nodes += graph_list[i].num_nodes
            graph_sizes.append(graph_list[i].num_nodes)
            edge_pairs.append(graph_list[i].edge_pairs)
        # create batch_graph
        n2n_idxes = torch.LongTensor(2, total_num_edges)
        n2n_vals = torch.FloatTensor(total_num_edges)

        for i in range(len(graph_list)):
            prefix_sum[len(graph_list) - i - 1] = prefix_sum[len(graph_list) - i - 2]
        prefix_sum[0] = 0

        for i in range(total_num_edges):
            n2n_vals[i] = 1

        j = 0
        for i in range(len(graph_list)):
            for item in edge_pairs[i]:
                n2n_idxes[0][j] = item[0] + prefix_sum[i]
                n2n_idxes[1][j] = item[1] + prefix_sum[i]

                #             if item[0]+prefix_sum[i] > total_num_nodes:
                #                 print('item0',item[0],prefix_sum[i],total_num_nodes)
                #             if item[1]+prefix_sum[i] > total_num_nodes:
                #                 print('item1',item[1],prefix_sum[i],total_num_nodes)

                #             if item[0]+prefix_sum[i] < 0:
                #                 print('item0',item[0],prefix_sum[i],'position: ',i)
                #             if item[1]+prefix_sum[i] < 0 :
                #                 print('item1',item[1],prefix_sum[i],'position: ',i)

                j += 1
        #     print(j,total_num_edges)
        #     print(n2n_idxes[:,3000:])
        #     print(node_features)
        n2n = torch.sparse.FloatTensor(n2n_idxes, n2n_vals, torch.Size([total_num_nodes, total_num_nodes]))
        node_features = torch.FloatTensor(node_features)
        node_degs = 1 / torch.LongTensor(node_degs)
        degs_index = torch.LongTensor(2, total_num_nodes)

        for i in range(total_num_nodes):
            degs_index[0, i] = i
            degs_index[1, i] = i
        node_degs = torch.sparse.FloatTensor(degs_index, node_degs, torch.Size([total_num_nodes, total_num_nodes]))

        return n2n, node_features, node_degs, graph_sizes

    # In[9]:

    def getInverse(self, adjs):
        Dres = []
        for a in adjs:
            length = a.size()[0]
            D = np.zeros((length, length))
            for item, i in zip(a, range(length)):
                if item.sum() != 0:
                    D[i, i] = 1 / item.sum()
            Dres.append(D)
        return torch.tensor(np.array(Dres, dtype=np.float32)).cuda()


# In[10]:


class GraphConvolution(nn.Module):
    """
    Simple GCN layer, similar to https://arxiv.org/abs/1609.02907
    """

    def __init__(self, in_features, out_features, activation=None, bias=True):
        super(GraphConvolution, self).__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.activation = activation
        self.weight = Parameter(torch.FloatTensor(in_features, out_features))
        if bias:
            self.bias = Parameter(torch.FloatTensor(out_features))
        else:
            self.register_parameter('bias', None)
        self.reset_parameters()

    def reset_parameters(self):
        stdv = 1. / math.sqrt(self.weight.size(1))
        self.weight.data.uniform_(-stdv, stdv)
        if self.bias is not None:
            self.bias.data.uniform_(-stdv, stdv)

    def forward(self, features, adj, degs):
        support = torch.mm(features, self.weight)
        output = torch.mm(adj, support)
        output = torch.mm(degs, output)
        if self.activation != None:
            output = self.activation(output)
        if self.bias is not None:
            return output + self.bias
        else:
            return output

    def __repr__(self):
        return self.__class__.__name__ + ' (' + str(self.in_features) + ' -> ' + str(self.out_features) + ')'


# In[11]:


class Edge_Attention(nn.Module):
    def __init__(self, head, feature_length):
        super(Edge_Attention, self).__init__()
        self.head = head
        self.feature_length = feature_length
        self.Attention = nn.TransformerEncoderLayer(d_model=feature_length, nhead=head, batch_first=True)

    def forward(self, edges):
        return self.Attention(edges)


# In[12]:


# te = getGraphList(train_graph_data[:5])
# n2n,node_features,node_degs,graph_sizes = merge_Graph(te)
# mo = res_GCN(100,32,1,5,99)
# temp = mo(node_features,n2n,node_degs,graph_sizes)
# temp.shape


# In[13]:


class res_GCN(nn.Module):
    def __init__(self, nfeat, nhid, nclass, n_layers, k):
        super(res_GCN, self).__init__()

        self.k = k
        self.n_layers = n_layers
        self.nhid = nhid
        self.nclass = nclass
        self.layers = nn.ModuleList()
        self.total_latent_dim = nhid * n_layers + nclass
        # 输入层
        self.layers.append(GraphConvolution(nfeat, nhid, activation=torch.tanh))
        # 隐层
        for i in range(n_layers - 1):
            self.layers.append(GraphConvolution(nhid, nhid, activation=torch.tanh))
        # 输出层
        self.layers.append(GraphConvolution(nhid, nclass))

    def forward(self, features, graphs, degs, graph_sizes):

        # def a res GCNN here
        feature_list = []
        for i, layer in enumerate(self.layers):
            if i != 0 and i != len(self.layers) - 1:
                features = layer(features, graphs, degs) + features
                feature_list.append(features)
            else:
                features = layer(features, graphs, degs)
                feature_list.append(features)
        #         sort pooling with k row remains

        res = ''
        for i, item in enumerate(feature_list):
            if i == 0:
                res = item
            else:
                res = torch.cat((res, item), 1)

        #         res = features

        #         print(len(feature_list),res.shape)
        sort_channel = res[:, -1]
        batch_sortpooling_graphs = torch.zeros(len(graph_sizes), self.k, self.total_latent_dim)
        if torch.cuda.is_available() and isinstance(features.data, torch.cuda.FloatTensor):
            batch_sortpooling_graphs = batch_sortpooling_graphs.cuda()

        batch_sortpooling_graphs = Variable(batch_sortpooling_graphs)
        accum_count = 0
        for i in range(len(graph_sizes)):
            to_sort = sort_channel[accum_count: accum_count + graph_sizes[i]]
            k = self.k if self.k <= graph_sizes[i] else graph_sizes[i]
            _, topk_indices = to_sort.topk(k)
            topk_indices += accum_count
            sortpooling_graph = res.index_select(0, topk_indices)
            if k < self.k:
                to_pad = torch.zeros(self.k - k, self.total_latent_dim)
                if torch.cuda.is_available() and isinstance(features.data, torch.cuda.FloatTensor):
                    to_pad = to_pad.cuda()

                to_pad = Variable(to_pad)
                sortpooling_graph = torch.cat((sortpooling_graph, to_pad), 0)
            batch_sortpooling_graphs[i] = sortpooling_graph
            accum_count += graph_sizes[i]

        return batch_sortpooling_graphs


# In[14]:


12 * 32


# In[15]:


class Classifier(nn.Module):
    def __init__(self, classNum, dropout_rate, nfeat, nhid, nclass, n_layers, k, head, features_length):
        super(Classifier, self).__init__()
        self.classNum = classNum
        self.dropout_rate = dropout_rate
        self.resGCNN = res_GCN(nfeat, nhid, nclass, n_layers, k)
        self.edgeAttention = Edge_Attention(head, features_length)

        #         self.layer_norm1 = nn.LayerNorm()
        self.layer_norm2 = nn.LayerNorm(features_length)
        self.cov1 = nn.Conv1d(in_channels=2, out_channels=16, kernel_size=nhid * n_layers + nclass,
                              stride=nhid * n_layers + nclass)
        self.maxpool = nn.MaxPool1d(kernel_size=2, stride=2)
        self.dropout1 = nn.Dropout(p=self.dropout_rate)
        self.cov2 = nn.Conv1d(in_channels=16, out_channels=32, kernel_size=4, stride=4)
        self.dropout2 = nn.Dropout(p=self.dropout_rate)

        dense = int(k / 2 / 4)

        self.denseLayer1 = nn.Linear(dense * 32, 512)
        self.dropout3 = nn.Dropout(p=self.dropout_rate)
        self.denseLayer2 = nn.Linear(512, 128)
        self.dropout4 = nn.Dropout(p=self.dropout_rate)
        self.outputLayer = nn.Linear(128, classNum)

    def forward(self, features, graphs, degs, graph_sizes, edges):
        gcn = self.resGCNN(features, graphs, degs, graph_sizes)
        #         gcn = self.layer_norm1(gcn)
        e_attention = self.edgeAttention(edges)
        e_attention = self.layer_norm2(e_attention)
        #         print(gcn.shape,e_attention.shape)

        gcn = gcn.view(len(graph_sizes), 1, -1)
        e_attention = e_attention.view(len(graph_sizes), 1, -1)

        #         print(,gcn.shape,e_attention.shape)
        res = torch.cat((gcn, e_attention), 1)

        #         res = res.view(len(graph_sizes),1,-1)
        #        1d convolution layer
        res = F.relu(self.cov1(res))
        res = self.dropout1(res)
        res = self.maxpool(res)
        res = F.relu(self.cov2(res))
        res = F.relu(res)
        res = self.dropout2(res)
        #         Dense Layer
        res = res.view(len(graph_sizes), -1)
        res = F.relu(self.denseLayer1(res))
        res = self.dropout3(res)
        res = F.relu(self.denseLayer2(res))
        res = self.dropout4(res)
        output = self.outputLayer(res)
        return output.flatten()


# In[16]:


# a = torch.tensor([[0,1],[1,0]])
# a = a.unsqueeze(0)
# a.repeat((3,1,1))


# In[17]:


# res = torch.randn(801,100)
# a = torch.tensor([[-0.9950, -0.6175, -0.1253,  1.3536],
#         [ 0.1208, -0.4237, -1.1313,  0.9022],
#         [-1.1995, -0.0699, -0.4396,  1.999]])
# # a,_  = torch.sort(a,dim=0,descending=True)
# key = [row[-1].item() for row in res]
# key = np.array(key)
# key = np.argsort(key,axis=-1,kind = 'quicksort')
# key = np.flipud(key)
# res = [list(res[i]) for i in key[:5]]
# res = torch.tensor(res)
# print(res.size())
# res = res.view(-1,1,5*100)
# print(res.size())


SORT_K = 200
THRESHOLD = 0.45


def mask_comments_preserve_length(source: str) -> str:
    """Mask comments so keyword scanning keeps original character offsets."""
    chars = list(source)
    i = 0
    in_string = None
    while i < len(chars):
        ch = chars[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_string = ch
            i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "/":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i < len(chars) and chars[i] not in "\r\n":
                chars[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "*":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i + 1 < len(chars) and not (chars[i] == "*" and chars[i + 1] == "/"):
                if chars[i] not in "\r\n":
                    chars[i] = " "
                i += 1
            if i + 1 < len(chars):
                chars[i] = chars[i + 1] = " "
                i += 2
            continue
        i += 1
    return "".join(chars)


def line_number_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def match_brace(source: str, open_brace: int):
    masked = mask_comments_preserve_length(source)
    depth = 0
    in_string = None
    i = open_brace
    while i < len(masked):
        ch = masked[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def find_function_slices(source: str):
    """Find Solidity function bodies with offsets for function-level localization."""
    masked = mask_comments_preserve_length(source)
    functions = []
    for match in re.finditer(r"\b(function|constructor|fallback|receive)\b", masked):
        start = match.start()
        kind = match.group(1)
        if kind == "function":
            after_keyword = masked[match.end():]
            name_match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", after_keyword)
            if name_match:
                name = name_match.group(1)
            else:
                open_paren_match = re.match(r"\s*\(", after_keyword)
                open_paren = match.end() + open_paren_match.end() - 1 if open_paren_match else None
                close_paren = match_brace_like(masked, open_paren, "(", ")") if open_paren is not None else None
                params = masked[open_paren + 1:close_paren].strip() if close_paren is not None else ""
                name = "fallback_old_style" if params == "" else "anonymous_function"
        else:
            name = kind
        cursor = match.end()
        paren_depth = 0
        open_brace = None
        while cursor < len(masked):
            ch = masked[cursor]
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(paren_depth - 1, 0)
            elif ch == ";" and paren_depth == 0:
                break
            elif ch == "{" and paren_depth == 0:
                open_brace = cursor
                break
            cursor += 1
        if open_brace is None:
            continue
        close_brace = match_brace(source, open_brace)
        if close_brace is None:
            continue
        functions.append({
            "name": name,
            "start": start,
            "open_brace": open_brace,
            "close_brace": close_brace,
            "start_line": line_number_at(source, start),
            "end_line": line_number_at(source, close_brace),
        })
    return functions


def match_brace_like(source: str, open_index: int, open_char: str, close_char: str):
    depth = 0
    in_string = None
    i = open_index
    while i < len(source):
        ch = source[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_string = ch
        elif ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def mask_other_function_bodies(source: str, functions, keep_index: int) -> str:
    chars = list(source)
    for index, item in enumerate(functions):
        if index == keep_index:
            continue
        for pos in range(item["open_brace"] + 1, item["close_brace"]):
            if chars[pos] not in "\r\n":
                chars[pos] = " "
    return "".join(chars)


def mask_current_function_body(source: str, functions, remove_index: int) -> str:
    chars = list(source)
    item = functions[remove_index]
    for pos in range(item["open_brace"] + 1, item["close_brace"]):
        if chars[pos] not in "\r\n":
            chars[pos] = " "
    return "".join(chars)


def rule_score_for_source(function_source: str):
    masked = mask_comments_preserve_length(function_source).lower()
    rules = [
        ("delegatecall", r"\bdelegatecall\b", 0.70),
        ("call.value", r"\bcall\s*\.\s*value\b", 0.65),
        (".call(", r"\.\s*call\s*\(", 0.60),
        (".send(", r"\.\s*send\s*\(", 0.35),
        (".transfer(", r"\.\s*transfer\s*\(", 0.35),
        ("selfdestruct", r"\bselfdestruct\b|\bsuicide\b", 0.45),
        ("tx.origin", r"\btx\s*\.\s*origin\b", 0.40),
        ("assembly", r"\bassembly\b", 0.40),
        ("payable", r"\bpayable\b", 0.20),
        ("msg.value", r"\bmsg\s*\.\s*value\b", 0.25),
    ]
    hits = []
    score = 0.0
    for name, pattern, weight in rules:
        if re.search(pattern, masked):
            hits.append(name)
            score += weight
    return min(score, 1.0), hits


def min_max_normalize(values):
    if not values:
        return []
    min_value = min(values)
    max_value = max(values)
    if max_value == min_value:
        return [0.0 for _ in values]
    return [(value - min_value) / (max_value - min_value) for value in values]


def safe_file_part(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value.strip("._") or "function"


def score_source_variant(
    source: str,
    source_path: Path,
    ast_path: Path,
    output_root: Path,
    parser_root: str,
    semantic_graph_root: Path,
    model,
):
    import sg_pipeline_copy as sg_pipeline

    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source, encoding="utf-8")
    sg_pipeline.parse_solidity_to_ast(source_path, ast_path, parser_root)
    generated = sg_pipeline.generate_detection_files_from_ast(
        ast_json_path=ast_path,
        output_root=output_root,
        label=0,
        semantic_graph_root=semantic_graph_root,
    )
    score, _ = predict_graph_edge(
        model,
        Path(generated["graph_path"]),
        Path(generated["edge_path"]),
    )
    return score, generated


def positive_contribution_normalize(values):
    positives = [value for value in values if value > 0]
    if not positives:
        return [0.0 for _ in values]
    min_value = min(positives)
    max_value = max(positives)
    if max_value == min_value:
        return [1.0 if value > 0 else 0.0 for value in values]
    return [
        ((value - min_value) / (max_value - min_value)) if value > 0 else 0.0
        for value in values
    ]


def source_slice_by_lines(source: str, start_line, end_line):
    if start_line is None or end_line is None:
        return ""
    lines = source.splitlines()
    start = max(int(start_line) - 1, 0)
    end = min(int(end_line), len(lines))
    if start >= end:
        return ""
    return "\n".join(lines[start:end])



def normalize_positive_scores(values, eps: float = 1e-30):
    """Normalize positive saliency-like scores to [0, 1] without amplifying all-zero values."""
    numeric = [float(value) for value in values]
    positives = [value for value in numeric if value > eps]
    if not positives:
        return [0.0 for _ in numeric]
    max_value = max(positives)
    if max_value <= eps:
        return [0.0 for _ in numeric]
    return [max(0.0, value) / max_value for value in numeric]


def get_source_line(source: str, line):
    if line is None:
        return ""
    try:
        line_no = int(line)
    except (TypeError, ValueError):
        return ""
    lines = source.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def localization_role_and_score(rule_score: float, model_score_norm: float):
    """Rank functions for downstream audit agents.

    `model_score_norm` reflects how important a function is to the trained model's
    graph-level decision.  A high value can mean either a real risk point or an
    important context structure such as an interface, ERC20 transfer routine, or
    ownership initializer.  `rule_score` reflects direct audit-sensitive syntax
    inside the function.

    Therefore the final ranking is tiered:
      1. risk_candidate: rule hits exist, audit first;
      2. context_candidate: no rule hits but model gradient is high, use as context;
      3. low_priority: neither rule nor model evidence is strong.
    """
    if rule_score > 0:
        return "risk_candidate", 0, 0.70 * rule_score + 0.30 * model_score_norm
    if model_score_norm >= 0.60:
        return "context_candidate", 1, 0.60 * model_score_norm
    return "low_priority", 2, 0.30 * model_score_norm


def localization_label(role: str, final_score: float, rule_score: float, model_score_norm: float):
    if role == "risk_candidate":
        if rule_score >= 0.60 or final_score >= 0.55:
            return "重点关注"
        return "候选参考"
    if role == "context_candidate":
        return "上下文参考"
    return "低优先级"


def localize_by_function(
    sol_path: Path,
    graph_path: Path,
    edge_path: Path,
    mapping_root: Path,
    model,
    full_score: float,
    top_k: int,
    detail_top_n: int = 5,
):
    """Fast coarse localization using true gradient saliency.

    No function ablation, node ablation, or edge ablation is performed here.
    The function runs one forward pass and one backward pass, scores graph nodes
    with input-gradient saliency, transfers BFS-edge gradient saliency back to
    the source/destination nodes, then aggregates node scores to function level.
    """
    source = sol_path.read_text(encoding="utf-8")
    mapping_root = Path(mapping_root)
    node_mapping = json.loads((mapping_root / "node_mapping.json").read_text(encoding="utf-8"))
    edge_mapping = json.loads((mapping_root / "bfs_edge_mapping.json").read_text(encoding="utf-8"))
    function_mapping = json.loads((mapping_root / "function_mapping.json").read_text(encoding="utf-8"))
    node_by_row = {item["row_id"]: item for item in node_mapping}

    gradient_score, node_saliency, edge_saliency = compute_gradient_saliency(model, graph_path, edge_path)

    # The model has both a GCN branch and a BFS-edge attention branch.  If we only
    # look at input node gradients, important information learned by the edge branch
    # may be invisible.  Therefore, edge-gradient saliency is projected back to
    # src/dst nodes. This is still gradient explanation, not edge ablation.
    edge_to_node_saliency = [0.0 for _ in node_saliency]
    for edge in edge_mapping:
        bfs_row = edge.get("bfs_row")
        if bfs_row is None or not (0 <= int(bfs_row) < len(edge_saliency)):
            continue
        edge_score = float(edge_saliency[int(bfs_row)])
        for key in ("src_row", "dst_row"):
            node_row = edge.get(key)
            if node_row is not None and 0 <= int(node_row) < len(edge_to_node_saliency):
                edge_to_node_saliency[int(node_row)] += 0.5 * edge_score

    combined_node_saliency = [
        float(node_saliency[i]) + float(edge_to_node_saliency[i])
        for i in range(len(node_saliency))
    ]

    results = []
    for item in function_mapping:
        node_rows = item.get("node_rows", []) or []
        valid_node_rows = [int(row) for row in node_rows if 0 <= int(row) < len(combined_node_saliency)]
        node_scores = [float(combined_node_saliency[row]) for row in valid_node_rows]
        top_scores = sorted(node_scores, reverse=True)[:detail_top_n]
        function_node_score = float(sum(top_scores) / len(top_scores)) if top_scores else 0.0
        function_node_max = float(max(node_scores)) if node_scores else 0.0

        # Aggregate edge-gradient scores for this function as an auxiliary model signal.
        valid_edge_rows = [
            int(row) for row in (item.get("bfs_edge_rows", []) or [])
            if 0 <= int(row) < len(edge_saliency)
        ]
        edge_scores = [float(edge_saliency[row]) for row in valid_edge_rows]
        top_edge_scores = sorted(edge_scores, reverse=True)[:detail_top_n]
        function_edge_score = float(sum(top_edge_scores) / len(top_edge_scores)) if top_edge_scores else 0.0

        function_source = source_slice_by_lines(source, item.get("start_line"), item.get("end_line"))
        rule_score, rule_hits = rule_score_for_source(function_source)

        results.append({
            "function": item.get("function_name"),
            "contract": item.get("contract_name"),
            "start_line": item.get("start_line"),
            "end_line": item.get("end_line"),
            "gradient_score": gradient_score,
            "function_node_score": function_node_score,
            "function_node_max": function_node_max,
            "function_edge_score": function_edge_score,
            "rule_score": rule_score,
            "rule_hits": rule_hits,
            "node_rows": node_rows,
            "bfs_edge_rows": item.get("bfs_edge_rows", []) or [],
            "node_count": item.get("node_count", 0),
            "edge_count": item.get("edge_count", 0),
            "source": function_source,
        })

    node_norms = normalize_positive_scores([row["function_node_score"] for row in results])
    edge_norms = normalize_positive_scores([row["function_edge_score"] for row in results])
    for row, node_norm, edge_norm in zip(results, node_norms, edge_norms):
        row["node_score_norm"] = node_norm
        row["edge_score_norm"] = edge_norm
        model_score_norm = 0.70 * node_norm + 0.30 * edge_norm
        row["model_score_norm"] = model_score_norm

        # Do not mix direct risk evidence and structural context evidence in one
        # flat score.  Risk candidates are audited first; high-gradient functions
        # without rule hits are retained as context for the audit agent.
        role, priority, final_score = localization_role_and_score(row["rule_score"], model_score_norm)
        row["role"] = role
        row["priority"] = priority
        row["final_score"] = final_score
        row["label"] = localization_label(role, final_score, row["rule_score"], model_score_norm)

    results.sort(key=lambda row: (row.get("priority", 9), -row.get("final_score", 0.0), -row.get("model_score_norm", 0.0)))
    detail_targets = results if top_k == 0 else results[:top_k]

    for row in detail_targets:
        node_details = []
        for node_row in row.get("node_rows", []):
            if not (0 <= int(node_row) < len(combined_node_saliency)):
                continue
            node_meta = node_by_row.get(int(node_row), {})
            line = node_meta.get("start_line")
            node_details.append({
                "node_row": int(node_row),
                "node_type": node_meta.get("node_type"),
                "token": node_meta.get("token"),
                "function": node_meta.get("function_name"),
                "line": line,
                "node_input_score": float(node_saliency[int(node_row)]),
                "edge_to_node_score": float(edge_to_node_saliency[int(node_row)]),
                "node_score": float(combined_node_saliency[int(node_row)]),
                "source_line": get_source_line(source, line),
            })
        node_details.sort(key=lambda item: item["node_score"], reverse=True)
        row["top_nodes"] = node_details[:detail_top_n]

        # Keep terminal and JSON focused on node-gradient localization.  No edge
        # ablation is run. Edge gradients are only projected to nodes above.
        row["top_bfs_edges"] = []

    # Write the full ranked list for downstream audit agents.  The terminal still
    # prints only Top-K to stay readable.
    output_results = results
    display_results = results if top_k == 0 else results[:top_k]
    location_json = mapping_root / "function_node_gradient_localization.json"
    location_json.write_text(json_dumps_localization(output_results), encoding="utf-8")
    return function_mapping, display_results, location_json

def json_dumps_localization(results) -> str:
    import json

    return json.dumps(results, ensure_ascii=False, indent=2)


def load_model(model_path: Path):
    try:
        model = torch.load(str(model_path), map_location="cpu", weights_only=False)
    except TypeError:
        model = torch.load(str(model_path), map_location="cpu")
    patch_legacy_transformer_layers(model)
    return model


def patch_legacy_transformer_layers(model):
    """Patch PyTorch-version fields missing from old pickled Transformer layers."""
    for module in model.modules():
        if isinstance(module, nn.TransformerEncoderLayer):
            if not hasattr(module, "activation_relu_or_gelu"):
                activation_name = getattr(getattr(module, "activation", None), "__name__", "")
                module.activation_relu_or_gelu = 2 if activation_name == "gelu" else 1
            if not hasattr(module, "norm_first"):
                module.norm_first = False


def predict_graph_edge(model, graph_path: Path, edge_path: Path, threshold: float = THRESHOLD):
    model.eval()
    helper = deal()
    with torch.no_grad():
        graphs, features, node_degs, graph_sizes = helper.merge_Graph(helper.getGraphList([str(graph_path)]))
        edges = helper.getEdgeList([str(edge_path)], SORT_K)
        output = model(
            Variable(features),
            Variable(graphs),
            Variable(node_degs),
            graph_sizes,
            Variable(edges),
        )
        score = torch.sigmoid(output).reshape(-1)[0].item()
        prediction = 1 if score >= threshold else 0
    return score, prediction



def compute_gradient_saliency(model, graph_path: Path, edge_path: Path):
    """One forward + one backward pass; return node and BFS-edge gradient saliency.

    Important: do NOT wrap `features` or `edges` with `Variable(...)` here.
    In current PyTorch, `Variable(tensor)` creates a detached tensor with
    requires_grad=False unless explicitly told otherwise, so gradients would
    be lost and every node/edge score would become exactly 0.

    The backward target is the raw vulnerability logit instead of sigmoid(score),
    which usually gives stronger gradients for explanation.
    """
    model.eval()
    helper = deal()
    graphs, features, node_degs, graph_sizes = helper.merge_Graph(helper.getGraphList([str(graph_path)]))
    edges = helper.getEdgeList([str(edge_path)], SORT_K)

    # Make input tensors leaf tensors so .grad will be populated after backward().
    features = features.clone().detach().requires_grad_(True)
    edges = edges.clone().detach().requires_grad_(True)

    model.zero_grad(set_to_none=True)

    with torch.enable_grad():
        output = model(
            features,
            graphs,
            node_degs,
            graph_sizes,
            edges,
        )
        logit = output.reshape(-1)[0]
        score_tensor = torch.sigmoid(logit)
        logit.backward()

    feature_grad = features.grad
    edge_grad = edges.grad

    if feature_grad is None:
        feature_grad = torch.zeros_like(features)
    if edge_grad is None:
        edge_grad = torch.zeros_like(edges)

    # Gradient × input saliency.  This gives one scalar importance value per
    # graph node and per BFS edge row.
    node_saliency = torch.sum(torch.abs(feature_grad * features), dim=1)
    edge_saliency = torch.sum(torch.abs(edge_grad[0] * edges[0]), dim=1)

    return (
        score_tensor.item(),
        node_saliency.detach().cpu().numpy().tolist(),
        edge_saliency.detach().cpu().numpy().tolist(),
    )

def predict_graph_edge_with_masks(
    model,
    graph_path: Path,
    edge_path: Path,
    node_rows=None,
    bfs_edge_rows=None,
    threshold: float = THRESHOLD,
):
    model.eval()
    helper = deal()
    node_rows = node_rows or []
    bfs_edge_rows = bfs_edge_rows or []
    with torch.no_grad():
        graphs, features, node_degs, graph_sizes = helper.merge_Graph(helper.getGraphList([str(graph_path)]))
        edges = helper.getEdgeList([str(edge_path)], SORT_K)
        if node_rows:
            valid_node_rows = [row for row in node_rows if 0 <= row < features.shape[0]]
            if valid_node_rows:
                features = features.clone()
                features[valid_node_rows, :] = 0
        if bfs_edge_rows:
            valid_edge_rows = [row for row in bfs_edge_rows if 0 <= row < edges.shape[1]]
            if valid_edge_rows:
                edges = edges.clone()
                edges[0, valid_edge_rows, :] = 0
        output = model(
            Variable(features),
            Variable(graphs),
            Variable(node_degs),
            graph_sizes,
            Variable(edges),
        )
        score = torch.sigmoid(output).reshape(-1)[0].item()
        prediction = 1 if score >= threshold else 0
    return score, prediction


def default_project_root() -> Path:
    return Path(__file__).resolve().parent


def main() -> int:
    project_root = default_project_root()
    parser = argparse.ArgumentParser(
        description="Copy pipeline: Solidity source -> AST JSON -> Graph/Edge files -> BFS_EA_RGCN detection."
    )
    parser.add_argument("--sol", required=True, help="Input Solidity .sol file.")
    parser.add_argument(
        "--output-root",
        default=str(project_root / "generated_copy"),
        help="Directory for generated AST/Graph/Edge files.",
    )
    parser.add_argument(
        "--model",
        default=str(project_root / "detecting" / "BFS_EA_RGCN(SG)" / "BFS_EA_RGCN.pkl"),
        help="Path to BFS_EA_RGCN.pkl.",
    )
    parser.add_argument(
        "--parser-root",
        default=str(project_root / "detecting" / "Utils" / "python-solidity-parser-master"),
        help="Path to the bundled python-solidity-parser-master directory.",
    )
    parser.add_argument("--threshold", type=float, default=THRESHOLD)
    parser.add_argument(
        "--locate",
        action="store_true",
        help="Enable coarse function-level localization after whole-contract detection.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="How many highest-scoring functions to print when --locate is enabled. Use 0 for all.",
    )
    args = parser.parse_args()

    sol_path = Path(args.sol).resolve()
    output_root = Path(args.output_root).resolve() / sol_path.stem
    ast_json_path = output_root / "AST" / f"{sol_path.name}.json"
    model_path = Path(args.model).resolve()
    semantic_graph_root = project_root / "Data" / "SemanticGraph"

    if not sol_path.exists():
        raise FileNotFoundError(f"Solidity file not found: {sol_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    sys.path.insert(0, str(project_root))
    import sg_pipeline_copy as sg_pipeline

    sg_pipeline.parse_solidity_to_ast(sol_path, ast_json_path, args.parser_root)
    generated = sg_pipeline.generate_detection_files_from_ast(
        ast_json_path=ast_json_path,
        output_root=output_root,
        label=0,
        semantic_graph_root=semantic_graph_root,
    )

    model = load_model(model_path)
    score, prediction = predict_graph_edge(
        model,
        Path(generated["graph_path"]),
        Path(generated["edge_path"]),
        threshold=args.threshold,
    )

    print("=== Cross-contract detection copy pipeline ===")
    print(f"sol: {sol_path}")
    print(f"ast_json: {ast_json_path}")
    print(f"graph_file: {generated['graph_path']}")
    print(f"edge_file: {generated['edge_path']}")
    print(f"feature_mode: {generated['feature_mode']}")
    print(f"node_types: {generated['node_type_count']}")
    print(f"graph_nodes: {generated['graph_node_count']}")
    print(f"score: {score:.6f}")
    print(f"threshold: {args.threshold:.6f}")
    print("result: 存在漏洞" if prediction == 1 else "result: 正常")
    if args.locate:
        functions, location_results, location_json = localize_by_function(
            sol_path=sol_path,
            graph_path=Path(generated["graph_path"]),
            edge_path=Path(generated["edge_path"]),
            mapping_root=Path(generated["function_mapping_path"]).parent,
            model=model,
            full_score=score,
            top_k=args.top_k,
        )
        print("=== Risk-prioritized node-gradient localization v3 ===")
        print(f"functions_found: {len(functions)}")
        print(f"localization_json: {location_json}")
        if not functions:
            print("localization_result: no function body found")
        for rank, item in enumerate(location_results, 1):
            if "error" in item:
                print(
                    f"#{rank} {item['function']} lines {item['start_line']}-{item['end_line']} "
                    f"error: {item['error']}"
                )
                continue
            rule_hits = ",".join(item["rule_hits"]) if item["rule_hits"] else "-"
            print(
                f"#{rank} {item['contract']}.{item['function']} "
                f"lines {item['start_line']}-{item['end_line']} "
                f"final_score: {item['final_score']:.6f} "
                f"model_score_norm: {item['model_score_norm']:.6f} "
                f"function_node_score: {item['function_node_score']:.3e} "
                f"function_edge_score: {item['function_edge_score']:.3e} "
                f"node_score_norm: {item['node_score_norm']:.6f} "
                f"edge_score_norm: {item['edge_score_norm']:.6f} "
                f"rule_score: {item['rule_score']:.6f} "
                f"rule_hits: {rule_hits} "
                f"role: {item.get('role', '-')} "
                f"priority: {item.get('priority', '-')} "
                f"node_count: {item['node_count']} "
                f"label: {item['label']}"
            )
            for node in item.get("top_nodes", []):
                print(
                    f"  node node_row: {node['node_row']} "
                    f"node_type: {node['node_type']} "
                    f"token: {node['token']} "
                    f"function: {node['function']} "
                    f"line: {node['line']} "
                    f"node_score: {node['node_score']:.3e} "
                    f"input_score: {node['node_input_score']:.3e} "
                    f"edge_to_node: {node['edge_to_node_score']:.3e} "
                    f"source: {node.get('source_line', '')[:80]}"
                )
            for edge in item.get("top_bfs_edges", []):
                print(
                    f"  edge bfs_row: {edge['bfs_row']} "
                    f"src_row: {edge['src_row']} "
                    f"dst_row: {edge['dst_row']} "
                    f"src_node_type: {edge['src_node_type']} "
                    f"dst_node_type: {edge['dst_node_type']} "
                    f"function: {edge['function']} "
                    f"line: {edge['line']} "
                    f"edge_contribution: {edge['edge_contribution']:.6f}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
