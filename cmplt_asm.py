import idaapi
import idautils
import idc
from sets import Set
import re
import networkx as nx
import hashlib

                
def get_apis(output_file, func_addr, endEA, asmplus_filename):    
        
        apis = []      
        instr = func_addr

        #reg apis + instruction
        while instr <endEA:
            s = idc.GetDisasm(instr)
            start = s.find("[")
            end = s.find("]")
            substring = s[start:end]
            substring = substring[1:]
            apis.append(substring)
            instr = idc.NextHead(instr)           
      
        #name apis      
        calls = 0
        flags = GetFunctionFlags(func_addr)               
        # list of addresses        
        dism_addr = list(FuncItems(func_addr))                
        for instr in range(func_addr, endEA+1):           
            tmp_api_address = ""
            if idaapi.is_call_insn(instr):
                for xref in XrefsFrom(instr, idaapi.XREF_FAR):
                    if xref.to == None:
                        calls += 1
                        continue
                    tmp_api_address = xref.to
                    break
                if tmp_api_address == "":
                    calls += 1
                    continue
                api_flags = GetFunctionFlags(tmp_api_address)
                if api_flags & idaapi.FUNC_LIB == True or api_flags & idaapi.FUNC_THUNK:
                    tmp_api_name = NameEx(0, tmp_api_address)
                    if tmp_api_name:
                        apis.append(tmp_api_name)                     
                else:
                    calls += 1
 
                       
        print >> output_file,"   ++++++ API Features ++++++" 
        while '' in apis:
            apis.remove('')       
        print >> output_file, "    APIs: ", ';'.join(map(str, apis))  
        

#------------------------------------------------------------------------------------------------------------------------                
def get_instr(output_file, func_addr, endEA, asmplus_filename):    
     
        instr = func_addr
        mnemonic = []

        # Instruction features
        while instr <endEA:
            mnem = idc.GetMnem (instr)  #Instruction features
            mnemonic.append(mnem)
            instr = idc.NextHead(instr)           
 
        print >> output_file,"   ++++++ Instruction Features ++++++"            
        print >> output_file, "    Insts: ", ';'.join(map(str, mnemonic))  

#------------------------------------------------------------------------------------------------------------------------

def get_struc(output_file, block, nx_graph, asmplus_filename):
      
    cnt_offspring = 0 
        
    nx_graph.add_node(block.startEA)
    for pred in block.preds():
        nx_graph.add_edge(pred.startEA, block.startEA)
                       
    for succ in block.succs():
        nx_graph.add_edge((block.startEA), (succ.startEA))
        cnt_offspring = cnt_offspring + 1
        #print >> output_file, succ.startEA
            
    betweenness = nx.betweenness_centrality(nx_graph) 
    
    print >> output_file,"   ++++++ Structural Features ++++++" 
    print >> output_file, "    Num offspring: " , cnt_offspring
        
    if block.startEA in betweenness:
        print >> output_file, "    Betweenness: " ,betweenness[block.startEA]
   
#------------------------------------------------------------------------------------------------------------------------ 
def BB_extract(output_file, func, asmplus_filename):
    
    f = idaapi.FlowChart(idaapi.get_func(func))
    nx_graph = nx.DiGraph()
    
    for block in f:  
        cnt_offspring = 0
        print >> output_file, "Basic Block Addr: %#x" % (block.startEA)
               
        get_instr(output_file, block.startEA, block.endEA, asmplus_filename)
        print >> output_file, " "
        get_struc(output_file, block, nx_graph, asmplus_filename)
        print >> output_file, " "
        get_apis(output_file, block.startEA, block.endEA, asmplus_filename)
             
        
        print >> output_file, " "
        
#------------------------------------------------------------------------------------------------------------------------         

def controller():
    funcs_id = dict()  
    callees = dict()
    func_num = 0
    func_id = 0
    cg_adjmat = []
    info_filename = idc.AskFile(1, "*.*", "Extract Binary File Info")


    basename = idc.GetInputFile()
    
    #md5
    BLOCK_SIZE = 65536 
    file = basename
    file_hash = hashlib.md5() 
    with open(file, 'rb') as f: 
        fb = f.read(BLOCK_SIZE)            
        while len(fb) > 0:       
            file_hash.update(fb) 
            fb = f.read(BLOCK_SIZE) 

    file_name = file_hash.hexdigest()
    
    info_filename = file_name + ".exe" +  ".txt"    
    asm_filename = file_name + ".asm"  
    asmplus_filename = file_name + ".asmplus"    
    idc.GenerateFile(idc.OFILE_ASM, file_name + ".asm", 0, idc.BADADDR, 0)
    idc.GenerateFile(idc.OFILE_LST, file_name + ".asmplus", 0, idc.BADADDR, 0)
         
    output_file = open(info_filename,'w')        
    asm_file = open(asm_filename,'r')
    asmplus_file = open(asm_filename,'r')
    
    
    funcs = idautils.Functions()
    funcs_iterator = idautils.Functions()
    
     
    for f in funcs:        
        func_name = GetFunctionName(f)              
        BB_extract(output_file, f, asmplus_filename)    

    
    output_file.close()
    asm_file.close()
    asmplus_file()
        
        
# end of controller
#------------------------------------------------------------------------------------------------------------------------      

q = None
f = None
idc.Wait()
controller()

