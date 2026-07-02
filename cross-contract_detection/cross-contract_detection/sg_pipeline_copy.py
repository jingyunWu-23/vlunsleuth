# Auto-extracted copy of cross-contract_detection/Data/SemanticGraph/SG.ipynb.
# This file is a working copy; the original notebook is unchanged.

import json
import os
import sys
from pathlib import Path
from queue import Queue

import numpy as np

# ---- Extracted from SG.ipynb cell 3 ----
class VertexNode(object):
    #图的顶点
    def __init__(self,data,token,index,metadata=None):
        self.data = data
        self.token = token
        self.index = index
        self.metadata = metadata or {}
    def __str__(self):
        return self.data
# ENTRY = VertexNode('enter',0,0)
# index = 1
# graph = {ENTRY:[]}

current_context = {
    "ast_type": None,
    "contract_name": None,
    "function_name": None,
    "start_line": None,
    "end_line": None,
    "start_column": None,
    "end_column": None,
}


def loc_fields(ast_node):
    loc = ast_node.get("loc") if isinstance(ast_node, dict) else None
    if not isinstance(loc, dict):
        return {}
    start = loc.get("start") or {}
    end = loc.get("end") or {}
    return {
        "start_line": start.get("line"),
        "end_line": end.get("line"),
        "start_column": start.get("column"),
        "end_column": end.get("column"),
    }


def update_context_from_ast(ast_node, contract_name=None, function_name=None):
    if not isinstance(ast_node, dict):
        return
    current_context["ast_type"] = ast_node.get("type") or current_context.get("ast_type")
    if contract_name is not None:
        current_context["contract_name"] = contract_name
    if function_name is not None:
        current_context["function_name"] = function_name
    for key, value in loc_fields(ast_node).items():
        if value is not None:
            current_context[key] = value


def current_node_metadata(data, token, node_index):
    return {
        "node_index": node_index,
        "node_type": str(data),
        "token": int(token),
        "data": str(data),
        "ast_type": current_context.get("ast_type"),
        "contract_name": current_context.get("contract_name"),
        "function_name": current_context.get("function_name"),
        "start_line": current_context.get("start_line"),
        "end_line": current_context.get("end_line"),
        "start_column": current_context.get("start_column"),
        "end_column": current_context.get("end_column"),
    }

# ---- Extracted from SG.ipynb cell 4 ----
def getNodeToken(keyword):
    global token_ind
    global keys
    global tokens
    if keyword in keys:
        return tokens[keyword]
    else:
        keys.append(keyword)
        tokens[keyword] = token_ind
        token_ind += 1
        return tokens[keyword]

def addNode(start,data,token):
    global index
    nnode = VertexNode(data,token,index,current_node_metadata(data, token, index))
    graph[start].append(nnode)
    graph[nnode] = []
    index += 1
    return start,nnode

def addEdge(start,end):
    graph[start].append(end)

def addDataFlow(g):
    nodes = list(g.keys())
    for node1,i in zip(nodes,range(len(nodes))):
        key = node1.data[:3]
        if key == 'num' or key == 'str':
            for node2 in nodes[i+1:]:
                if node1.data == node2.data:
                    addEdge(node1,node2)

# ---- Extracted from SG.ipynb cell 6 ----
def StateVariableDeclaration(start,end,b):
    if b['variables'] != []:
#         token = getNodeToken('variables')
#         start1,end1 = addNode(end0,'variables',token)  # start1 == end0  end1 was the new node just generated
        for item in b['variables']:
            processVariables(start,end,item)
        if b['initialValue'] != None:
            processInitialValue(start,end,b)

def EventDefinition(start,end,b):
    if '}' in b['type']:
        print(3,b['type'])
    if b['parameters'] != None and b['parameters']['parameters'] != []:
        processParameters(start,end,b['parameters'])
#         res.append(b['parameters']['type'])
#         if '}' in b['parameters']['type']:
#             print(4,b['parameters']['type'])
#         tt = processParameters(b['parameters']['parameters'])

def FunctionDefinition(start,end,b):
    previous = current_context.copy()
    function_name = b.get('name') or "fallback_old_style"
    update_context_from_ast(b, function_name=function_name)
    try:
        processStr(start,end,b,'name')
        
        if b['parameters']['parameters'] != []:
#         res.append(b['parameters']['type'])
#         if '}' in b['parameters']['type']:
#             print(5,b['parameters']['type'])
            processParameters(start,end,b['parameters'])
            
        if b['returnParameters'] != [] and b['returnParameters']!=None:
#         res.append(b['returnParameters']['type'])
#         if '}' in b['returnParameters']['type']:
#             print(6,b['returnParameters']['type'])
            processParameters(start,end,b['returnParameters'])

        if b['body'] != []:
            processBodyblockstatement(start,end,b['body'])
    finally:
        current_context.update(previous)


def ModifierDefinition(start,end,b):
 
    if b['parameters'] != [] and b['parameters']['parameters'] != []:
        processParameters(start,end,b['parameters'])
    if b['body'] != []:
        processBodyblockstatement(start,end,b['body'])

def UsingForDeclaration(start,end,b):

#     print(b)
    if 'typeName' in b.keys() and  b['typeName'] != '*':
        processTypeName(start,end,b['typeName'])
    token = getNodeToken(b['libraryName'])
    addNode(end,b['libraryName'],token)
    if '}' in b['libraryName']:
        print(9,b['libraryName'])

def StructDefinition(start,end,b):
    processStr(start,end,b,'name')
    
    if b['members'] != [] and b['members'] != None: 
        start1,end1 = start,end
        for item in b['members']:
            start1,end1 = processVariables(start1,end1,item)

def EnumDefinition(start,end,b):

    processStr(start,end,b,'name')
    if b['members'] != [] and b['members'] != None: 
        start1,end1 = start,end
        for item in b['members']:
            start1,end1 = processVariables(start1,end1,item)
#             res.append(item['type'])
#             if '}' in item['type']:
#                 print(12,':',item['type'])

# ---- Extracted from SG.ipynb cell 7 ----
def processVariables(start,end,b):
    update_context_from_ast(b)
    token = getNodeToken('variables')
    start0,end0 = addNode(end,'variables',token)
    
    token = getNodeToken(b['type'])
    addNode(end0,b['type'],token)
        
    processStr(start0,end0,b,'name')
#     if 'name' in b.keys():
#         temp = 'str'
#         if b['name'] not in strs:
#             strs.append(b['name'])
#             temp = 'str'+str(len(strs)+1)
#         else:
#             temp = 'str'+str(strs.index(b['name'])+1)
                
#         token = 2  #num == 1, str == 2
#         addNode(end0,temp,token)
             
    if 'typeName' in b.keys() and  b['typeName'] != '*':
#         print(b['typeName'])
#         token = getNodeToken('typeName')
#         start2,end2 = addNode(end,'typeName',token)
        processTypeName(start0,end0,b['typeName'])
    
    if 'expression' in b.keys():
        if b['expression'] != None:
    #         token = getNodeToken('expression')
    #         start1,end1 = addNode(end,'expression',token)
            processExpression(start0,end0,b['expression'])
    return start0,end0
    
    
def processTypeName(start,end,b):
    token = getNodeToken('typeName')
    start0,end0 = addNode(end,'typeName',token)
    
#     keywords = ['keyType','valueType','baseTypeName','length','parameterTypes','returnTypes']
#     if b != []:
#         for key in b.keys():
#             if key != 'namePath':
#                 if key != 'keyType' and key != 'valueType' and key!='baseTypeName' and key != 'length' and key !='parameterTypes' and key !='returnTypes':
#                     if b[key] != None and '}' in b[key]:
#                         print(32,':',key,':',b[key])
#                     if b[key] != None:
#                         token = getNodeToken(b[key])
#                         addNode(end0,b[key],token)
#                 else:
# #                     if key == 'length' and b[key] == None:
# #                         print('')
# #                         token = getNodeToken(b[key])
# #                         addNode(end0,b[key],token)
                        
#                     if key == 'length' and b[key] != None:
#                         processExpression(start0,end0,b[key])
                        
#                     elif key == 'parameterTypes' and b[key] != []:
# #                         print(1111,b[key])  #printtag
#                         if type(b[key]) == list:
#                             for item in b[key]:
#                                 processVariables(start0,end0,item)

#                     elif key == 'returnTypes' and b[key] != []:
# #                         print(2222,b[key])  #printtag
#                         if type(b[key]) == list:
#                             for item in b[key]:
#                                 processVariables(start0,end0,item)

#                     else:
#                         if b[key] != None:
#                             processTypeName(start0,end0,b[key])
                        
def processParameters(start,end,b):
    token = getNodeToken(b['type'])
    start0,end0 = addNode(end,b['type'],token)
    for item in b['parameters']:
        if '}' in item['type']:
            print(26,':',item['type'])
        processVariables(start0,end0,item)
        
def processStr(start,end,b,key):
    if key in b.keys():
        temp = 'str'
        if b[key] not in strs:
            strs.append(b[key])
            temp = 'str'+str(len(strs)+1)
        else:
            temp = 'str'+str(strs.index(b[key])+1)
                
        token = getNodeToken(temp)
        addNode(end,temp,token)

def processNum(start,end,b,key):
    if key in b.keys():
        temp = 'num'
        if b[key] not in nums:
            nums.append(b[key])
            temp = 'num'+str(len(nums)+1)
        else:
            temp = 'num'+str(nums.index(b[key])+1)
                
        token = getNodeToken(temp)
        addNode(end,temp,token)

def processInitialValue(start,end,b):
    token = getNodeToken('initialValue')
    start0,end0 = addNode(end,'initialValue',token)
            
    token = getNodeToken(b['initialValue']['type'])
    addNode(end0,b['initialValue']['type'],token)
    
    if 'name' in b['initialValue'].keys():
        temp = 'str'
        if b['initialValue']['name'] not in strs:
            strs.append(b['initialValue']['name'])
            temp = 'str'+str(len(strs)+1)
        else:
            temp = 'str'+str(strs.index(b['initialValue']['name'])+1)
                
        token = getNodeToken(temp)
        addNode(end0,temp,token)
                    
    elif 'number' in b['initialValue'].keys():
        temp = 'num'
        if b['initialValue']['number'] not in nums:
            nums.append(b['initialValue']['number'])
            temp = 'num'+str(len(nums)+1)
        else:
            temp = 'num'+str(nums.index(b['initialValue']['number'])+1)
                
        token = getNodeToken(temp)
        addNode(end0,temp,token)
        
def processBodyblockstatement(start,end,b):
    update_context_from_ast(b)
    token = getNodeToken(b['type'])
    start0,end0 = addNode(end,b['type'],token)
    
#     if '}' in b['type']:
#         print(34,':',b['type'])
    
    if b['type'] == 'InLineAssemblyStatement':
        for item in b['body']['operations']:
            processExpression(start0,end0,item)
            
    elif b['type'] == 'VariableDeclarationStatement':
        if b['variables'] != None and b['variables'] != []:
            start1,end1 = start0,end0
            for item in b['variables']:
                start1,end1 = processVariables(start1,end1,item)
        if b['initialValue'] != None:
            processInitialValue(start0,end0,b)
            
    elif b['type'] == 'ExpressionStatement':
        if b['expression'] != None:
            processExpression(start0,end0,b['expression'])
        
    elif b['type'] == 'IfStatement':
        token = getNodeToken('condition')
        start1,end1 = addNode(end0,'condition',token)
        start2,end2 = start1,end1
        processExpression(start1,end1,b['condition'])
        if b['TrueBody'] != None and b['TrueBody'] != ';':
            token = getNodeToken('TrueBody')
            start2,end2 = addNode(end1,'TrueBody',token)
            processBodyblockstatement(start2,end2,b['TrueBody'])
            
        if b['FalseBody'] != None and b['FalseBody'] != ';':
            token = getNodeToken('FalseBody')
            start3,end3 = addNode(end2,'FalseBody',token)
            processBodyblockstatement(start3,end3,b['FalseBody'])
            
    elif b['type'] == 'EmitStatement':
        processExpression(start0,end0,b['eventCall'])
        
    elif b['type'] == 'Identifier':
        processExpression(start0,end0,b)
        
    elif b['type'] == 'BooleanLiteral':
        processExpression(start0,end0,b)
        
    elif b['type'] == 'IndexAccess':
        processExpression(start0,end0,b)
    
    elif b['type'] == 'UnaryOperation':
        processExpression(start0,end0,b)
        
    elif b['type'] == 'FunctionCall':
        processExpression(start0,end0,b)
        
    elif b['type'] == 'MemberAccess':
        processExpression(start0,end0,b['expression'])
        
    elif b['type'] == 'ForStatement':
        start1,end1 = start0,end0
        start2,end2 = start0,end0
        start3,end3 = start0,end0
        if b['initExpression'] != None:
            token = getNodeToken('initExpression')
            start1,end1 = addNode(end0,'initExpression',token)
            processBodyblockstatement(start1,end1,b['initExpression'])
        if b['conditionExpression'] != None:
            token = getNodeToken('conditionExpression')
            start2,end2 = addNode(end1,'conditionExpression',token)
            processExpression(start2,end2,b['conditionExpression'])
        if b['loopExpression'] != None:
            token = getNodeToken('loopExpression')
            start3,end3 = addNode(end2,'loopExpression',token)
            processBodyblockstatement(start3,end3,b['loopExpression'])
            
        if b['body'] != []:
#             print(b['body'])
#             print(b['body']['type'])
#             print(b['body'],'*********')
            token = getNodeToken('body')
            start4,end4 = addNode(end3,'body',token)
            processBodyblockstatement(start4,end4,b['body'])
#             b = b['body']['statements']
#             tt = []
#             for item in b:
#                 if item != None and item != ';':
#                     tt = processBodyblockstatement(item)
#                 res.extend(tt)
                
    elif b['type'] == 'WhileStatement':
        token = getNodeToken('condition')
        start1,end1 = addNode(end0,'condition',token)
        processExpression(start1,end1,b['condition'])
        if b['body'] != []:
            token = getNodeToken('body')
            start2,end2 = addNode(end1,'body',token)
            processBodyblockstatement(start2,end2,b['body'])
                
    elif b['type'] == 'TupleExpression':
        start1,end1 = start0,end0
        for item in b['components']:
            if item != None:
                #增加 processExpression reutrn start,end.
                start1,end1 = processExpression(start1,end1,item)
            
    elif b['type'] == 'Conditional':
        token = getNodeToken('condition')
        start1,end1 = addNode(end0,'condition',token)
        processExpression(start1,end1,b['condition'])
        
        if b['TrueExpression'] != None:
            token = getNodeToken('TrueExpression')
            start2,end2 = addNode(end1,'TrueExpression',token)
            processExpression(start2,end2,b['TrueExpression'])
            
        if b['FalseExpression'] != None:
            token = getNodeToken('FalseExpression')
            start3,end3 = addNode(end2,'FalseExpression',token)
            processExpression(start3,end3,b['FalseExpression'])
            
    elif b['type'] == 'NumberLiteral':
        processNum(start,end,b,'number')
        
    elif b['type'] == 'StringLiteral':
        processStr(start,end,b,'value')
    
    elif b['type'] == 'DoWhileStatement':
        token = getNodeToken('condition')
        start1,end1 = addNode(end0,'condition',token)
        processExpression(start1,end1,b['condition'])
        if b['body'] != []:
            token = getNodeToken('body')
            start2,end2 = addNode(end1,'body',token)
            processBodyblockstatement(start2,end2,b['body'])
#             b = b['body']['statements']
#             tt = []
#             for item in b:
#                 if item != None and item != ';':
#                     tt = processBodyblockstatement(item)
#                 res.extend(tt)
    elif b['type'] == 'Block':
        if b['statements'] != [] and b['statements'] != None:
            b = b['statements']
            start1,end1 = start0,end0
            for item in b:
                if item != None and item != ';':
                    start1,end1 = processBodyblockstatement(start1,end1,item)
    return start0,end0

def processExpression(start,end,b):
    update_context_from_ast(b)
    token = getNodeToken(b['type'])
    start0,end0 = addNode(end,b['type'],token)
#     if '}' in b['type']:
#         print(13,':',b['type'])
    if b['type'] == 'AssemblyExpression':
        if 'functionName' in b.keys():
            processStr(start0,end0,b,'functionName')
        if  'arguments' in b.keys() and b['arguments'] != []:
            token = getNodeToken('arguments')
            start1,end1 = addNode(end0,'arguments',token)
            for item in b['arguments']:
#                 if item['type'] == 'AssemblyExpression':
                start1,end1 = processExpression(start1,end1,item)
                    
    elif b['type'] == 'AssemblyLocalDefinition':
        if b['names'] != []:
            token = getNodeToken('names')
            start1,end1 = addNode(end0,'names',token)
            for item in b['names']:
                processExpression(start1,end1,item)
        if b['expression'] != None:
            processExpression(start0,end0,b['expression'])
        
    elif b['type'] == 'AssemblySwitch':
        processExpression(start0,end0,b['expression'])
        
        processStr(start0,end0,b,'functionName')
        
        if 'arguments' in b.keys() and b['arguments'] != []:
            token = getNodeToken('arguments')
            start1,end1 = addNode(end0,'arguments',token)
            for item in b['arguments']:
                start1,end1 = processExpression(start1,end1,item)
            start1,end1 = start0,end0
            for item in b['cases']:
                start1,end1 = processExpression(start1,end1,item)
            
    elif b['type'] == 'AssemblyCase':
        if b['block'] != None:
            processExpression(start0,end0,b['block'])
        if b['value'] != None:
            processExpression(start0,end0,b['value'])
            
    elif b['type'] == 'AssemblyBlock':
        if b['operations'] != None:
            start1,end1 = start0,end0
            for item in b['operations']:
                start1,end1 = processExpression(start1,end1,item)
                
    elif b['type'] == 'AssemblyAssignment':
        if b['names'] != []:
            start1,end1 = start0,end0
            for item in b['names']:
                if item != None:
                    start1,end1 = processExpression(start1,end1,item)
                    
    elif b['type'] == 'BinaryOperation':
        token = getNodeToken(b['operator'])
        start1,end1 = addNode(end0,b['operator'],token)
        if '}' in b['operator']:
            print(16,':',b['operator'])
            
        token = getNodeToken('left')
        start2,end2 = addNode(end1,'left',token)
        processExpression(start2,end2,b['left'])
        
        token = getNodeToken('right')
        start3,end3 = addNode(end1,'right',token)
        processExpression(start3,end3,b['right'])
                    
    elif b['type'] == 'Identifier':
        processStr(start,end,b,'name')
        
    elif b['type'] == 'MemberAccess':
#         processExpression(start0,end0,b['expression'])
        processStr(start0,end0,b,'memberName')
        
    elif b['type'] == 'FunctionCall':
        processExpression(start0,end0,b['expression'])
        if b['names'] != None:
            token = getNodeToken('names')
            start1,end1 = addNode(end0,'names',token)
#             print('hello',b['names'])
            for item in b['names']:
                if type(item) != str:
                    processExpression(start1,end1,item)
                    

        if 'typeName' in b.keys() and b['typeName'] != None:
            processTypeName(start0,end0,b['typeName'])
        
        if b['arguments'] != None:
            token = getNodeToken('arguments')
            start1,end1 = addNode(end0,'arguments',token)
            for item in b['arguments']:
                start1,end1 = processExpression(start1,end1,item)
        
    elif b['type'] == 'ElementaryTypeNameExpression':
        if 'typeName' in b.keys() and  b['typeName'] != '*':
            processTypeName(start0,end0,b['typeName'])
        
    elif b['type'] == 'BooleanLiteral':
        if b['value'] not in booleanLiteral:
            booleanLiteral.append(b['value'])
        token = getNodeToken(str(b['value']))
        addNode(end,str(b['value']),token)
    
    elif b['type'] == 'UnaryOperation':
        token = getNodeToken(b['operator'])
        start1,end1 = addNode(end,b['operator'],token)
        if '}' in b['operator']:
            print(21,':',b['operator'])
        processExpression(start1,end1,b['subExpression'])
        
    elif b['type'] == 'IndexAccess':
        token = getNodeToken('base')
        start1,end1 = addNode(end0,'base',token)
        processExpression(start1,end1,b['base'])
        
        token = getNodeToken('index')
        start2,end2 = addNode(end1,'index',token)
        processExpression(start2,end2,b['index'])
        
    elif b['type'] == 'NumberLiteral':
        processNum(start,end,b,'number')
        
    elif b['type'] == 'TupleExpression':
        start1,end1 = start0,end0
        for item in b['components']:
            if item != None:
                start1,end1 = processBodyblockstatement(start1,end1,item)
        
    elif b['type'] == 'StringLiteral':   
        processNum(start,end,b,'value')
    
    elif b['type'] == 'DecimalNumber':
        processNum(start,end,b,'value')
         
    return start0,end0

# ---- Extracted from SG.ipynb cell 8 ----
def getParseResult(path,file):
    if os.path.getsize(path+file) != 0:
        f = open(path+file)
        jsonfile = json.load(f)
        return jsonfile

Contractsubkeywords = ['StateVariableDeclaration','EventDefinition','FunctionDefinition','ModifierDefinition','UsingForDeclaration','StructDefinition','EnumDefinition']
def processJsonFile(parseresult):
    if parseresult['children'][0] != None:
        start1 = ENTRY
        end1 = ENTRY
        for i in range(1,len(parseresult['children'])):
            if parseresult['children'][i] != None:
                a = parseresult['children'][i]
                previous = current_context.copy()
                update_context_from_ast(a, contract_name=a.get('name'))
                token = getNodeToken(a['type'])
                start1,end1 = addNode(end1,a['type'],token)
                if 'subNodes' in a.keys():
                    b = a['subNodes']
                    for item in b:
                        update_context_from_ast(item)
                        t = item['type']
                        if t == 'StateVariableDeclaration':
                            StateVariableDeclaration(start1,end1,item)
                        elif t == 'EventDefinition':
                            EventDefinition(start1,end1,item)
                        elif t == 'FunctionDefinition':
                            FunctionDefinition(start1,end1,item)
                        elif t == 'ModifierDefinition':
                            ModifierDefinition(start1,end1,item)
                        elif t == 'UsingForDeclaration':
                            UsingForDeclaration(start1,end1,item)
                        elif t == 'StructDefinition':
                            StructDefinition(start1,end1,item)
                        elif t == 'EnumDefinition':
                            EnumDefinition(start1,end1,item)
                current_context.update(previous)
    addDataFlow(graph)
    return graph

# ---- Extracted from SG.ipynb cell 9 ----
keys = ['ENTRY']
tokens = {"ENTRY": 0}
nums = []
strs = []
token_ind = 1
ENTRY = VertexNode('enter',0,0)
index = 1
graph = {ENTRY:[]}

# ---- Extracted from SG.ipynb cell 10 ----
def vertexnode2dict(node):
    t = {'data':'','token':'','index':''}
    t['data'] = node.data
    t['token'] = node.token
    t['index'] = node.index
    return str(t)

def write2file(file,graph):
    path = './graph_vlunerable/'
    f = open(path+file,'w')
    dic = {}
    for node in graph.keys():
        li = graph[node]
        t = vertexnode2dict(node)
        dic[t] = []
        for item in li:
            temp = vertexnode2dict(item)
            dic[t].append(temp)
    j = json.dumps(dic)
    f.write(j)
    f.close()

# ---- Extracted from SG.ipynb cell 11 ----
# f = open('./tokens.json','w')
# f.write(json.dumps(tokens))
# f.close()
functioncall = []
booleanLiteral = []

# ---- Extracted from SG.ipynb cell 12 ----
def processMain():
    i = 1
    Graph = []
    Graph1 = []
    global graph
    global index
    global nums
    global strs
    for file in files:
        nums = []
        strs = []
        index = 1
#         if i % 1000 == 0:
#             print(i/1000,'\n')
#         else:
#             print(i,end='')
#             print(" ")
        i = i+1
        graph = {ENTRY:[]}
        if os.path.getsize(path+file) != 0:
            parseresult = getParseResult(path,file)
            processJsonFile(parseresult)
#             write2file(file,graph)
            
            
            Graph.append(graph)
    for file in files1:
        nums = []
        strs = []
        index = 1
#         if i % 1000 == 0:
#             print(i/1000,'\n')
#         else:
#             print('.',end='')
#         i = i+1
        graph = {ENTRY:[]}
        if os.path.getsize(path1+file) != 0:
            parseresult = getParseResult(path1,file)
            processJsonFile(parseresult)
#             write2file(file,graph)
            
            
            Graph1.append(graph)
    return Graph,Graph1

# ---- Extracted from SG.ipynb cell 20 ----
def getEdgeNums(g):
    edgenum = 0
    for item in g.keys():
        edgenum += len(g[item])
    return edgenum
from queue import Queue

# ---- Extracted from SG.ipynb cell 21 ----
def BFS():
    directory = ['Edge_no_v','Edge_v']
    graph_type = [Graph,Graph1]
    file_type = [files,files1]
    for dname,gtype,ftype in zip(directory,graph_type,file_type):
        for g,fname in zip(gtype,ftype):
            Q = Queue()
            feat = []
            visit = {}
            for i in g.keys():
                visit[i] = 0
            Q.put(list(g.keys())[0])
            visit[list(g.keys())[0]] = 1
            while(Q.empty() == False):
                temp = Q.queue[0]
                for item in g[temp]:
                    if visit[item] == 0:
                        Q.put(item)
                        feat.append((np.array(featues_vec[temp.token])+np.array(featues_vec[item.token]))/2)
                        visit[item] = 1
                Q.get()
#             f = open('./BFS_Edges/'+dname+'/'+fname[0:-9]+'.txt','a')
#             for i in feat:
#                 f.write(str(i))
#                 f.write(' ')
#             f.close()
            np.savetxt('./BFS_Edges/'+dname+'/'+fname[0:-9]+'.txt',np.array(feat),fmt='%.17f')  

def dfs(g,i,feat,visit):
    for item in g[i]:
        if visit[item] == 0:
            feat.append((np.array(featues_vec[i.token])+np.array(featues_vec[item.token]))/2)
            dfs(g,item,feat,visit)
            visit[item] = 1
            
def DFS():
    directory = ['Edge_no_v','Edge_v']
    graph_type = [Graph,Graph1]
    file_type = [files,files1]
    for dname,gtype,ftype in zip(directory,graph_type,file_type):
        for g,fname in zip(gtype,ftype):
            S = []
            feat = []
            visit = {}
            for i in g.keys():
                visit[i] = 0
            dfs(g,list(g.keys())[0],feat,visit)
#             f = open('./SG/DFS_Edges/'+dname+'/'+fname[0:-9]+'.txt','a')
#             for i in feat:
#                 f.write(str(i))
#                 f.write(' ')
#             f.close()
            np.savetxt('./DFS_Edges/'+dname+'/'+fname[0:-9]+'.txt',np.array(feat),fmt='%.17f')   


# ---- Copy-friendly pipeline helpers ----
def reset_state():
    """Reset notebook globals before building a graph for one input."""
    global keys, tokens, nums, strs, token_ind, ENTRY, index, graph, current_context
    keys = ['ENTRY']
    tokens = {"ENTRY": 0}
    nums = []
    strs = []
    token_ind = 1
    ENTRY = VertexNode('enter', 0, 0)
    index = 1
    graph = {ENTRY: []}
    current_context = {
        "ast_type": None,
        "contract_name": None,
        "function_name": None,
        "start_line": None,
        "end_line": None,
        "start_column": None,
        "end_column": None,
    }


def parse_solidity_to_ast(sol_path, ast_json_path, parser_root):
    """Parse a Solidity file to the AST JSON shape consumed by SG.ipynb."""
    sol_path = Path(sol_path).resolve()
    ast_json_path = Path(ast_json_path).resolve()
    parser_root = Path(parser_root).resolve()
    if str(parser_root) not in sys.path:
        sys.path.insert(0, str(parser_root))
    from solidity_parser import parser

    ast_json_path.parent.mkdir(parents=True, exist_ok=True)
    ast_data = parser.parse_file(str(sol_path), loc=True)
    ast_json_path.write_text(json.dumps(ast_data, ensure_ascii=False, indent=2), encoding="utf-8")
    return ast_json_path


def graph_stem_from_ast_name(ast_name):
    if ast_name.endswith(".sol.json"):
        return ast_name[:-9]
    return Path(ast_name).stem


def build_graph_from_ast_json(ast_json_path):
    """Build the in-memory semantic graph from one AST JSON file."""
    reset_state()
    parseresult = json.loads(Path(ast_json_path).read_text(encoding="utf-8"))
    processJsonFile(parseresult)
    return graph


def load_feature_matrix(semantic_graph_root):
    """Load SG/word2vec node vectors generated by word2vec.ipynb."""
    semantic_graph_root = Path(semantic_graph_root)
    word_index_path = semantic_graph_root / "SG" / "word_index_SG.txt"
    word_vectors_path = semantic_graph_root / "SG" / "word_vectors_SG.txt"
    missing = [str(path) for path in (word_index_path, word_vectors_path) if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing word2vec feature file(s). Run word2vec.ipynb first: " + ", ".join(missing)
        )
    feature_matrix = np.zeros((len(tokens), 100), dtype=np.float32)
    word_index = np.loadtxt(str(word_index_path), dtype=np.int32)
    word_vectors = np.loadtxt(str(word_vectors_path))
    word_index = np.atleast_1d(word_index)
    word_vectors = np.atleast_2d(word_vectors)
    for token_id, vector_index in zip(word_index, range(len(word_index))):
        if 0 <= int(token_id) < feature_matrix.shape[0] and vector_index < word_vectors.shape[0]:
            feature_matrix[int(token_id)] = word_vectors[vector_index]
    return feature_matrix


def write_graph_file(semantic_graph, graph_path, label, feature_matrix):
    graph_path = Path(graph_path)
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    with graph_path.open("w", encoding="utf-8") as file:
        file.write(f"{len(semantic_graph)} {int(label)}\n")
        for item in semantic_graph.keys():
            row = [len(semantic_graph[item])]
            row.extend(li.index for li in semantic_graph[item])
            row.extend(feature_matrix[item.token])
            file.write(" ".join(str(value) for value in row))
            file.write("\n")
    return graph_path


def build_node_mapping(semantic_graph):
    mapping = []
    row_by_node = {}
    for row_id, item in enumerate(semantic_graph.keys()):
        row_by_node[item] = row_id
        meta = dict(getattr(item, "metadata", {}) or {})
        mapping.append({
            "row_id": row_id,
            "node_index": item.index,
            "node_type": meta.get("node_type", item.data),
            "token": meta.get("token", item.token),
            "data": meta.get("data", item.data),
            "ast_type": meta.get("ast_type"),
            "contract_name": meta.get("contract_name"),
            "function_name": meta.get("function_name"),
            "start_line": meta.get("start_line"),
            "end_line": meta.get("end_line"),
            "start_column": meta.get("start_column"),
            "end_column": meta.get("end_column"),
        })
    return mapping, row_by_node


def write_bfs_edge_file(semantic_graph, edge_path, feature_matrix, row_by_node=None):
    edge_path = Path(edge_path)
    edge_path.parent.mkdir(parents=True, exist_ok=True)
    queue = Queue()
    features = []
    edge_mapping = []
    visit = {node: 0 for node in semantic_graph.keys()}
    first_node = list(semantic_graph.keys())[0]
    queue.put(first_node)
    visit[first_node] = 1
    while not queue.empty():
        temp = queue.queue[0]
        for item in semantic_graph[temp]:
            if visit[item] == 0:
                queue.put(item)
                features.append((np.array(feature_matrix[temp.token]) + np.array(feature_matrix[item.token])) / 2)
                if row_by_node is not None:
                    src_meta = getattr(temp, "metadata", {}) or {}
                    dst_meta = getattr(item, "metadata", {}) or {}
                    start_line = dst_meta.get("start_line") or src_meta.get("start_line")
                    end_line = dst_meta.get("end_line") or src_meta.get("end_line")
                    edge_mapping.append({
                        "bfs_row": len(edge_mapping),
                        "src_row": row_by_node.get(temp),
                        "dst_row": row_by_node.get(item),
                        "src_function": src_meta.get("function_name"),
                        "dst_function": dst_meta.get("function_name"),
                        "start_line": start_line,
                        "end_line": end_line,
                        "src_node_type": src_meta.get("node_type", temp.data),
                        "dst_node_type": dst_meta.get("node_type", item.data),
                    })
                visit[item] = 1
        queue.get()
    if len(features) == 0:
        features = np.zeros((2, 100), dtype=np.float32)
    else:
        features = np.atleast_2d(np.array(features, dtype=np.float32))
        if features.shape[0] == 1:
            features = np.vstack([features, np.zeros((1, 100), dtype=np.float32)])
    np.savetxt(str(edge_path), features, fmt="%.17f")
    return edge_path, edge_mapping


def build_function_mapping(node_mapping, edge_mapping):
    groups = {}
    for item in node_mapping:
        function_name = item.get("function_name")
        if not function_name:
            continue
        key = (
            item.get("contract_name") or "",
            function_name,
        )
        group = groups.setdefault(key, {
            "contract_name": item.get("contract_name"),
            "function_name": function_name,
            "start_line": item.get("start_line"),
            "end_line": item.get("end_line"),
            "node_rows": [],
            "bfs_edge_rows": [],
        })
        group["node_rows"].append(item["row_id"])
        if item.get("start_line") is not None:
            if group["start_line"] is None or item["start_line"] < group["start_line"]:
                group["start_line"] = item["start_line"]
        if item.get("end_line") is not None:
            if group["end_line"] is None or item["end_line"] > group["end_line"]:
                group["end_line"] = item["end_line"]

    for edge in edge_mapping:
        function_name = edge.get("dst_function") or edge.get("src_function")
        if not function_name:
            continue
        candidates = [
            group for group in groups.values()
            if group["function_name"] == function_name
        ]
        if not candidates:
            continue
        line = edge.get("start_line")
        target = candidates[0]
        for group in candidates:
            if line is not None and group.get("start_line") is not None and group.get("end_line") is not None:
                if group["start_line"] <= line <= group["end_line"]:
                    target = group
                    break
        target["bfs_edge_rows"].append(edge["bfs_row"])

    result = []
    for group in groups.values():
        group["node_rows"] = sorted(set(group["node_rows"]))
        group["bfs_edge_rows"] = sorted(set(group["bfs_edge_rows"]))
        group["node_count"] = len(group["node_rows"])
        group["edge_count"] = len(group["bfs_edge_rows"])
        result.append(group)
    result.sort(key=lambda item: (
        item.get("start_line") if item.get("start_line") is not None else 10**9,
        item.get("function_name") or "",
    ))
    return result


def generate_detection_files_from_ast(ast_json_path, output_root, label=0, semantic_graph_root=None):
    """Generate one Graph file and one BFS Edge file from an AST JSON file."""
    ast_json_path = Path(ast_json_path).resolve()
    output_root = Path(output_root).resolve()
    semantic_graph_root = Path(semantic_graph_root or Path(__file__).resolve().parent / "Data" / "SemanticGraph")
    semantic_graph = build_graph_from_ast_json(ast_json_path)
    feature_matrix = load_feature_matrix(semantic_graph_root)
    stem = graph_stem_from_ast_name(ast_json_path.name)
    graph_path = output_root / "Graph_input" / f"{stem}.txt"
    edge_path = output_root / "BFS_Edges" / "Edge_input" / f"{stem}.txt"
    mapping_root = output_root / "Mapping"
    write_graph_file(semantic_graph, graph_path, label, feature_matrix)
    node_mapping, row_by_node = build_node_mapping(semantic_graph)
    _, edge_mapping = write_bfs_edge_file(semantic_graph, edge_path, feature_matrix, row_by_node=row_by_node)
    function_mapping = build_function_mapping(node_mapping, edge_mapping)
    mapping_root.mkdir(parents=True, exist_ok=True)
    (mapping_root / "node_mapping.json").write_text(
        json.dumps(node_mapping, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (mapping_root / "bfs_edge_mapping.json").write_text(
        json.dumps(edge_mapping, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (mapping_root / "function_mapping.json").write_text(
        json.dumps(function_mapping, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_root / "nodes-SG.json").write_text(json.dumps(tokens, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "graph_path": graph_path,
        "edge_path": edge_path,
        "node_mapping_path": mapping_root / "node_mapping.json",
        "edge_mapping_path": mapping_root / "bfs_edge_mapping.json",
        "function_mapping_path": mapping_root / "function_mapping.json",
        "feature_mode": "notebook-word2vec",
        "node_type_count": len(tokens),
        "graph_node_count": len(semantic_graph),
    }
