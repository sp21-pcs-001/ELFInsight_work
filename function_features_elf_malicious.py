import idaapi
import idautils
import idc
from sets import Set
import hashlib


def block_split(output_file, startEA, endEA):
    curName = GetFunctionName(startEA);
    dem = idc.Demangle(curName, idc.GetLongPrm(INF_SHORT_DN));
    if dem != None:
        curName = dem;
    
    first=startEA
    h = idautils.Heads(startEA, endEA)
    for i in h:
        mnem = idc.GetMnem(i)
        if mnem == "call" and i != endEA:
            first=idc.NextHead(i, endEA+1)

#------------------------------------------------------------------------------------------------------------------------

def function_extract(output_file, func, cg_adjmat, funcs_id, callees, asm_filename):
    func_name = GetFunctionName(func)
    function_start_phrase = func_name + " proc near" 
    function_end_phrase = func_name + " endp" 

    #print >> output_file, "+++++++++++++++++++++++++++++"
    #print >> output_file, "Function Name: %s" % (func_name)
    #print >> output_file, "     Function ID: %s" % (funcs_id[func_name])
    #print >> output_file, "     Function Starting Address: %#x" % (func)
    #print >> output_file, "     Function Ending Address: %#x" % (FindFuncEnd(func))
    #print >> output_file, ""

    cnt = 0
    f = idaapi.FlowChart(idaapi.get_func(func))
    cfg_adjmat = []
    
    for block in f:
        block_split(output_file, block.startEA, block.endEA)
      
        print >> output_file,func,block.startEA,func_name,"0","FunctionSymbol"

#------------------------------------------------------------------------------------------------------------------------        
                
def controller():
    funcs_id = dict()  # to store functions and their IDs 
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
    
    info_filename = file_name + ".exe" + "_function" + ".txt"    
    asm_filename = file_name + ".asm"  
    asmplus_filename = file_name + ".asmplus"    
    idc.GenerateFile(idc.OFILE_ASM, file_name + ".asm", 0, idc.BADADDR, 0)
    idc.GenerateFile(idc.OFILE_LST, file_name + ".asmplus", 0, idc.BADADDR, 0)
         
    output_file = open(info_filename,'w')        
    asm_file = open(asm_filename,'r')
    asmplus_file = open(asm_filename,'r')
    
    
    
    funcs = idautils.Functions()
    funcs_iterator = idautils.Functions()
    
    # scan all functions to extract number of functions and add them to the funcs_id
    for i in funcs_iterator:
        func_name = GetFunctionName(i)
        funcs_id.update({func_name:func_id})
        func_num += 1
        func_id += 1
        cg_adjmat.append([])
        
    for f in funcs:        
        func_name = GetFunctionName(f)              
        function_extract(output_file, f, cg_adjmat, funcs_id, callees, asm_filename) 
        
    output_file.close()
    asm_file.close()
    asmplus_file()
  

#------------------------------------------------------------------------------------------------------------------------      

q = None
f = None
idc.Wait()
controller()

