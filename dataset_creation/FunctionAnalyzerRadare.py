# SAFE TEAM
#
#函数分析雷达
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
#
import json
import r2pipe
import networkx as nx
from dataset_creation.BlockFeaturesExtractor import BlockFeaturesExtractor

# import BlockFeaturesExtractor

class Dict2Obj(object):
    """
    Turns a dictionary into a class
    """

    # ----------------------------------------------------------------------
    def __init__(self, dictionary):
        """Constructor"""
        for key in dictionary:
            setattr(self, key, dictionary[key])

class RadareFunctionAnalyzer:

    def __init__(self, filename, use_symbol):
        self.r2 = r2pipe.open(filename, flags=['-2'])
        self.filename = filename
        self.arch, _ = self.get_arch()
        self.use_symbol = use_symbol

    def __enter__(self):
        return self

    @staticmethod
    def filter_reg(op):#对寄存器操作数的处理
        return op["value"]

    @staticmethod
    def filter_imm(op): #对内存操作数的处理
        imm = int(op["value"])
        if -int(5000) <= imm <= int(5000): #对正负5000的立即数进行处理
            ret = str(hex(op["value"]))
        else:
            ret = str('HIMM')#替换为HIMM
        return ret

    @staticmethod
    def filter_mem(op):#对内存操作数的处理
        if "base" not in op: #'mov qword [rbp + 0x10], rcx'  base为rbp
            op["base"] = 0

        if op["base"] == 0: #base为0的情况如'lea rdx, [rax*4]'
            r = "[" + "MEM" + "]"#这种情况有:1.'lea rdx, [rax*4]'(处理第二个操作数)2.'mov rax, qword fs:[0x28]'(段加偏移)
        else:
            #'add byte [rbp + rax], cl'这种情况下base为rbp,disp为0,index为rax
            reg_base = str(op["base"])#地址为rbp
            disp = str(op["disp"])  #disp为偏移的十进制(上面例子中的0x10,也就是16),对于负数取它的补码
            scale = str(op["scale"])#scale规模,应该是指令中含有的寄存器种类的数量
            if scale=="2":#我添加的为了调试方便没有实际意义,为了能够看到scale为2的情况
                a=1
                a+=1
            r = '[' + reg_base + "*" + scale + "+" + disp + ']'
        return r

    @staticmethod
    def filter_memory_references(i):#过滤内存引用
        inst = "" + i["mnemonic"]##取出助记符

        for op in i["opex"]["operands"]: #每个操作数的属性
            if op["type"] == 'reg':
                inst += " " + RadareFunctionAnalyzer.filter_reg(op) #对寄存器的处理,直接返回 op['value'],是具体的操作数值(如esp)
            elif op["type"] == 'imm':
                inst += " " + RadareFunctionAnalyzer.filter_imm(op)#操作数为立即数并且不在正负5000范围内的操作数将进行替换替换为HIMM字符
            elif op["type"] == 'mem':
                inst += " " + RadareFunctionAnalyzer.filter_mem(op)##指令变为[base*scale+disp] base为基地址寄存器,scale为规模,disp为偏移量(十进制)  (如果是rax+rbx+0x10会变为rax*2+16)
                #base为0的情况=有:1.'lea rdx, [rax*4]'(处理第二个操作数)2.'mov rax, qword fs:[0x28]'(段加偏移),如果base==0,地址将会变成[MEM]
            if len(i["opex"]["operands"]) > 1:
                inst = inst + ","
        if "," in inst:#处理两个操作数的指令
            inst = inst[:-1]#去掉最后一个逗号,
        inst = inst.replace(" ", "_")

        return str(inst)

    @staticmethod
    def get_callref(my_function, depth):
        calls = {}
        if 'callrefs' in my_function and depth > 0:
            for cc in my_function['callrefs']:
                if cc["type"] == "C":
                    calls[cc['at']] = cc['addr']
        return calls


    def process_instructions(self, instructions):
        filtered_instructions = []
        for insn in instructions: #取出每一条指令(包括指令的很多属性)
            #operands = []
            if 'opex' not in insn:#opex里面存放指令操作数数组
                continue
            #for op in insn['opex']['operands']:
            #    operands.append(Dict2Obj(op))
            #insn['operands'] = operands
            stringized = RadareFunctionAnalyzer.filter_memory_references(insn)#对指令进行一些处理,主要是对地址的处理,进行了一些替换
            if "x86" in self.arch: #添加架构标识 #UNK_为未知,并没有处理mips指令(mips为UNK开头)
                stringized = "X_" + stringized
            elif "arm" in self.arch:
                stringized = "A_" + stringized
            else:
                stringized = "UNK_" + stringized
            filtered_instructions.append(stringized)
        return filtered_instructions

    def process_block(self, block): #对一个block的处理
        bytes = ""
        disasm = []
        for op in block['ops']:
            if 'disasm' in op:
                disasm.append(op['disasm']) #里面存放一个块中每一条汇编指令
                bytes += str(op['bytes'])#存放每一条汇编指令的字节码

        self.r2.cmd("s " + str(block['offset']))
        print("ops size= "+str(len(block['ops'])))
        instructions = json.loads(self.r2.cmd("aoj " + str(len(block['ops']))))#一个块中所有指令以及对指令的描述
        string_addresses = [s['vaddr'] for s in json.loads(self.r2.cmd("izzj"))]#列出字符串,取出字符串地址(vaddr)
        bfe = BlockFeaturesExtractor(self.arch, instructions, block['ops'], string_addresses)
        annotations = bfe.getFeatures()#获取指令的统计信息(如有多少个字符串)
        filtered_instructions = self.process_instructions(instructions)#对包含地址的指令进行了一些替换,添加了一个架构的开头

        return disasm, bytes, annotations, filtered_instructions
        #disasm存放所有汇编指令 bytes存放所有字节码  annotations存放指令的统计信息(如有多少move指令) filtered_instructions对原始指令包含的地址进行了一些替换,添加了一个架构开头

    def function_to_cfg(self, func):#获取图的信息,参数为函数开始地址
        if self.use_symbol:
            s = 'vaddr'
        else:
            s = 'offset'

        self.r2.cmd('s ' + str(func[s])) #跳转到起始地址
        try:
            cfg = json.loads(self.r2.cmd('agfj ' + str(func[s])))#图命令ag  agfj打印表示图形的JSON字符串。包括反汇编
        except:
            cfg = []

        my_cfg = nx.DiGraph()#创建空的有向图
        acfg = nx.DiGraph()
        lstm_cfg = nx.DiGraph()

        if len(cfg) == 0:
            return my_cfg, acfg, lstm_cfg
        else:
            cfg = cfg[0]
#'blocks': [{'offset': 340, 'size': 23, 'jump': 383, 'fail': 363, 'trace': {'count': 3337, 'times': 1}, 'colorize': 0, 'ops': [{'offset': 340, 'esil': 'rbp,8,rsp,-,=[8],8,rsp,-=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 412, 'size': 1, 'opcode': 'push rbp', 'disasm': 'push rbp', 'bytes': '55', 'family': 'cpu', 'type': 'rpush', 'reloc': False, 'type_num': 268435468, 'type2_num': 0, 'flags': ['section..text_0', 'sym.av_malloc_array', 'sym..text', 'rip'], 'comment': 'WzAwXSAtci14IHNlY3Rpb24gc2l6ZSAxNzg0MCBuYW1lZCAudGV4dF8w', 'xrefs': [{'addr': 2557, 'type': 'CALL'}, {'addr': 2589, 'type': 'CALL'}, {'addr': 2621, 'type': 'CALL'}, {'addr': 2653, 'type': 'CALL'}, {'addr': 7939, 'type': 'CALL'}]}, {'offset': 341, 'esil': 'rsp,rbp,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 410, 'size': 3, 'opcode': 'mov rbp, rsp', 'disasm': 'mov rbp, rsp', 'bytes': '4889e5', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 9, 'type2_num': 0}, {'offset': 344, 'val': 32, 'esil': '32,rsp,-=,63,$o,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'sub rsp, 0x20', 'disasm': 'sub rsp, 0x20', 'bytes': '4883ec20', 'family': 'cpu', 'type': 'sub', 'reloc': False, 'type_num': 18, 'type2_num': 0}, {'offset': 348, 'esil': 'rcx,0x10,rbp,+,=[8]', 'refptr': True, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'mov qword [rbp + 0x10], rcx', 'disasm': 'mov qword [rbp + 0x10], rcx', 'bytes': '48894d10', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 268435465, 'type2_num': 0}, {'offset': 352, 'esil': 'rdx,0x18,rbp,+,=[8]', 'refptr': True, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'mov qword [rbp + 0x18], rdx', 'disasm': 'mov qword [rbp + 0x18], rdx', 'bytes': '48895518', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 268435465, 'type2_num': 0}, {'offset': 356, 'val': 0, 'esil': '0,0x18,rbp,+,[8],==,$z,zf,:=,64,$b,cf,:=,$p,pf,:=,63,$s,sf,:=,63,$o,of,:=', 'refptr': True, 'fcn_addr': 340, 'fcn_last': 408, 'size': 5, 'opcode': 'cmp qword [rbp + 0x18], 0', 'disasm': 'cmp qword [rbp + 0x18], 0', 'bytes': '48837d1800', 'family': 'cpu', 'type': 'cmp', 'reloc': False, 'type_num': 268435471, 'type2_num': 0}, {'offset': 361, 'esil': 'zf,?{,383,rip,=,}', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 411, 'size': 2, 'opcode': 'je 0x17f', 'disasm': 'je 0x17f', 'bytes': '7414', 'family': 'cpu', 'type': 'cjmp', 'reloc': False, 'type_num': 2147483649, 'type2_num': 0, 'jump': 383, 'fail': 363, 'refs': [{'addr': 383, 'type': 'CODE'}]}]}, {'offset': 363, 'size': 20, 'jump': 390, 'fail': 383, 'trace': {'count': 3343, 'times': 1}, 'colorize': 0, 'ops': [{'offset': 363, 'ptr': 2147483647, 'val': 2147483647, 'esil': '2147483647,rax,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 408, 'size': 5, 'opcode': 'mov eax, 0x7fffffff', 'disasm': 'mov eax, 0x7fffffff', 'bytes': 'b8ffffff7f', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 9, 'type2_num': 0}, {'offset': 368, 'val': 0, 'esil': '0,rdx,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 408, 'size': 5, 'opcode': 'mov edx, 0', 'disasm': 'mov edx, 0', 'bytes': 'ba00000000', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 9, 'type2_num': 0}, {'offset': 373, 'esil': '0x18,rbp,+,[8],rax,%,rdx,=,0x18,rbp,+,[8],rax,/,rax,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'div qword [rbp + 0x18]', 'disasm': 'div qword [rbp + 0x18]', 'bytes': '48f77518', 'family': 'cpu', 'type': 'div', 'reloc': False, 'type_num': 21, 'type2_num': 0}, {'offset': 377, 'esil': 'rax,0x10,rbp,+,[8],==,$z,zf,:=,64,$b,cf,:=,$p,pf,:=,63,$s,sf,:=,63,$o,of,:=', 'refptr': True, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'cmp qword [rbp + 0x10], rax', 'disasm': 'cmp qword [rbp + 0x10], rax', 'bytes': '48394510', 'family': 'cpu', 'type': 'cmp', 'reloc': False, 'type_num': 268435471, 'type2_num': 0}, {'offset': 381, 'esil': 'cf,?{,390,rip,=,}', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 411, 'size': 2, 'opcode': 'jb 0x186', 'disasm': 'jb 0x186', 'bytes': '7207', 'family': 'cpu', 'type': 'cjmp', 'reloc': False, 'type_num': 2147483649, 'type2_num': 0, 'jump': 390, 'fail': 383, 'refs': [{'addr': 390, 'type': 'CODE'}]}]}, {'offset': 383, 'size': 7, 'jump': 407, 'trace': {'count': 3347, 'times': 1}, 'colorize': 0, 'ops': [{'offset': 383, 'val': 0, 'esil': '0,rax,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 408, 'size': 5, 'opcode': 'mov eax, 0', 'disasm': 'mov eax, 0', 'bytes': 'b800000000', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 9, 'type2_num': 0, 'xrefs': [{'addr': 361, 'type': 'CODE'}]}, {'offset': 388, 'esil': '0x197,rip,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 411, 'size': 2, 'opcode': 'jmp 0x197', 'disasm': 'jmp 0x197', 'bytes': 'eb11', 'family': 'cpu', 'type': 'jmp', 'reloc': False, 'type_num': 1, 'type2_num': 0, 'jump': 407, 'refs': [{'addr': 407, 'type': 'CODE'}]}]}, {'offset': 390, 'size': 17, 'jump': 407, 'trace': {'count': 3348, 'times': 1}, 'colorize': 0, 'ops': [{'offset': 390, 'esil': '0x10,rbp,+,[8],rax,=', 'refptr': True, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'mov rax, qword [rbp + 0x10]', 'disasm': 'mov rax, qword [rbp + 0x10]', 'bytes': '488b4510', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 9, 'type2_num': 0, 'xrefs': [{'addr': 381, 'type': 'CODE'}]}, {'offset': 394, 'esil': '0x18,rbp,+,[8],rax,*=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 408, 'size': 5, 'opcode': 'imul rax, qword [rbp + 0x18]', 'disasm': 'imul rax, qword [rbp + 0x18]', 'bytes': '480faf4518', 'family': 'cpu', 'type': 'mul', 'reloc': False, 'type_num': 20, 'type2_num': 0}, {'offset': 399, 'esil': 'rax,rcx,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 410, 'size': 3, 'opcode': 'mov rcx, rax', 'disasm': 'mov rcx, rax', 'bytes': '4889c1', 'family': 'cpu', 'type': 'mov', 'reloc': False, 'type_num': 9, 'type2_num': 0}, {'offset': 402, 'esil': '407,rip,8,rsp,-=,rsp,=[],rip,=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 408, 'size': 5, 'opcode': 'call 0x197', 'disasm': 'call av_malloc', 'bytes': 'e800000000', 'family': 'cpu', 'type': 'call', 'reloc': True, 'type_num': 3, 'type2_num': 0, 'jump': 407, 'fail': 407, 'refs': [{'addr': 407, 'type': 'CALL'}]}]}, {'offset': 407, 'size': 6, 'trace': {'count': 3351, 'times': 1}, 'colorize': 0, 'ops': [{'offset': 407, 'val': 32, 'esil': '32,rsp,+=,63,$o,of,:=,63,$s,sf,:=,$z,zf,:=,63,$c,cf,:=,$p,pf,:=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 409, 'size': 4, 'opcode': 'add rsp, 0x20', 'disasm': 'add rsp, 0x20', 'bytes': '4883c420', 'family': 'cpu', 'type': 'add', 'reloc': False, 'type_num': 17, 'type2_num': 0, 'xrefs': [{'addr': 388, 'type': 'CODE'}, {'addr': 402, 'type': 'CALL'}]}, {'offset': 411, 'esil': 'rsp,[8],rbp,=,8,rsp,+=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 412, 'size': 1, 'opcode': 'pop rbp', 'disasm': 'pop rbp', 'bytes': '5d', 'family': 'cpu', 'type': 'pop', 'reloc': False, 'type_num': 14, 'type2_num': 0}, {'offset': 412, 'esil': 'rsp,[8],rip,=,8,rsp,+=', 'refptr': False, 'fcn_addr': 340, 'fcn_last': 412, 'size': 1, 'opcode': 'ret', 'disasm': 'ret', 'bytes': 'c3', 'family': 'cpu', 'type': 'ret', 'reloc': False, 'type_num': 5, 'type2_num': 0}]}]
        for block in cfg['blocks']:
            # disasm存放所有汇编指令 bytes存放所有字节码  annotations存放指令的统计信息(如有多少move指令) filtered_instructions对原始指令包含的地址进行了一些替换,添加了一个架构开头
            #对一个块的处理
            disasm, block_bytes, annotations, filtered_instructions = self.process_block(block)
            # 创建了三个图,第一个my_cfg存放汇编指令的指令和字节码
            #acfg存放指令的统计信息(如move指令有多少)
            #lstm_cfg里面存放内容为对原始指令包含的地址进行了一些替换,添加了一个架构开头
            my_cfg.add_node(block['offset'], asm=block_bytes, label=disasm)
            acfg.add_node(block['offset'], features=annotations)
            lstm_cfg.add_node(block['offset'], features=filtered_instructions)

        ##对于一个条件跳转指令,如果跳转会跳转到的地址会放在jump里面,如果不跳转下一次要运行的地址会放到fail里面
        #对于两种情况构建成边就可以构建成有向图(如果加上跳转信息就是带权有向图,但是这里没有加上权值)
        for block in cfg['blocks']:
            if 'jump' in block:#jmp表示跳转到哪里
                if block['jump'] in my_cfg.nodes: #图里面包含每个
                    my_cfg.add_edge(block['offset'],block['jump'])#块跳转到哪里添加一个边
                    acfg.add_edge(block['offset'], block['jump'])
                    lstm_cfg.add_edge(block['offset'], block['jump'])
            if 'fail' in block:
                if block['fail'] in my_cfg.nodes: #fail表示如果不跳会运行到的地方
                    my_cfg.add_edge(block['offset'],block['fail'])
                    acfg.add_edge(block['offset'], block['fail'])
                    lstm_cfg.add_edge(block['offset'], block['fail'])


        between = nx.betweenness_centrality(acfg)#介数中心性:每个节点的介数中心性是所有最短路径穿过该节点的次数
        #cfg图的介数中间性应该是每个定点的介数中心性
        for n in acfg.nodes(data=True):
            d = n[1]['features']#里面存放之前放进去的指令的统计信息(如move指令有多少)
            d['offspring'] = len(nx.descendants(acfg, n[0]))#返回从定点n[0]在acfg中所有可以到达的顶点。（查看图的连通性）
            d['betweenness'] = between[n[0]]#n[0]是顶点的首地址（这里是id），between是字典，存放所有顶点的首地址和它对应的介数中心性
            n[1]['features'] = d

        return my_cfg, acfg, lstm_cfg

    def get_arch(self):
        try:
            info = json.loads(self.r2.cmd('ij'))
            if 'bin' in info:
                arch = info['bin']['arch']
                bits = info['bin']['bits']
        except:
            print("Error loading file")
            arch = None
            bits = None
        return arch, bits

    def find_functions(self):
        self.r2.cmd('aaa') #使用aflj~{}命令可以以json格式的方式输出aflj输出的内容方便阅读
        try:
            function_list = json.loads(self.r2.cmd('aflj'))#好像是一些调用的函数的信息(不包含调用的系统函数和库函数)
        except:
            function_list = []
        return function_list

    def find_functions_by_symbols(self):
        self.r2.cmd('aa')  ##aa进行分析
        try:
            symbols = json.loads(self.r2.cmd('isj')) #输出文件的符号信息包括段信息和函数信息
            """
            is输出结果为
nth paddr       vaddr              bind   type size lib name
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0    0x00000000 0x00000000         LOCAL  FILE 4        .file
0    0x000006ac 0x000006ac         LOCAL  UNK  4        pixfmt_rgb24
0    0x0000012c 0x0000012c         LOCAL  FUNC 4        decode_frame 这两个是用户定义的函数
0    0x0000049f 0x0000049f         LOCAL  FUNC 4        decode_init
0    0x0000012c 0x0000012c         LOCAL  SECT 4        .text        这些是编译器生成的段名
0    0x000005cc 0x000005cc         LOCAL  SECT 4        .data
0    0x00000000 0x00000000         LOCAL  SECT 4        .bss
0    0x000006ac 0x000006ac         LOCAL  SECT 4        .rdata
0    0x000006fc 0x000006fc         LOCAL  SECT 4        .xdata
0    0x00000714 0x00000714         LOCAL  SECT 4        .pdata
0    0x0000072c 0x0000072c         LOCAL  UNK  4        .rdata$zzz
0    0x000005cc 0x000005cc         GLOBAL UNK  4        ff_eightbps_decoder  这个是导出函数,type并不是函数
0    ---------- 0xffffffffffffffff NONE   FUNC 4        imp.ff_get_buffer    下面是调用的系统函数
0    ---------- 0xffffffffffffffff NONE   FUNC 4        imp.av_packet_get_side_data
0    ---------- 0xffffffffffffffff NONE   FUNC 4        imp.memcpy
0    ---------- 0xffffffffffffffff NONE   FUNC 4        imp.ff_get_format
0    ---------- 0xffffffffffffffff NONE   FUNC 4        imp.av_log

            """
            fcn_symb = [s for s in symbols if s['type'] == 'FUNC'] #取出来所有的函数包括用户定义的函数和系统函数
        except:
            fcn_symb = []
        return fcn_symb

    def analyze(self):
        if self.use_symbol:
            function_list = self.find_functions_by_symbols() #获取所有用户定义函数和调用的系统函数(或者库函数)
        else:# use_symbol=0的时候,应该是没有符号表
            function_list = self.find_functions()

        result = {}
        for my_function in function_list:
            if self.use_symbol:
                address = my_function['vaddr']
            else:
                address = my_function['offset']#取偏移或者地址

            try:
                cfg, acfg, lstm_cfg = self.function_to_cfg(my_function) #获取cfg图的信息
                result[my_function['name']] = {'cfg': cfg, "acfg": acfg, "lstm_cfg": lstm_cfg, "address": address}
            except:
                print("Error in functions: {} from {}".format(my_function['name'], self.filename))
                pass
        return result

    def close(self):
        self.r2.quit()

    def __exit__(self, exc_type, exc_value, traceback):
        self.r2.quit()



