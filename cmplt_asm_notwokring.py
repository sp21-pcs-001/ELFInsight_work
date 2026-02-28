import idaapi
import idautils
import idc
from sets import Set
import re
import networkx as nx
import hashlib

                


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
    
#    info_filename = file_name + ".exe" +  ".txt"    
    asm_filename = file_name + ".asm"  
    asmplus_filename = file_name + ".asmplus"    
    idc.GenerateFile(idc.OFILE_ASM, file_name + ".asm", 0, idc.BADADDR, 0)
    idc.GenerateFile(idc.OFILE_LST, file_name + ".asmplus", 0, idc.BADADDR, 0)
         
#    output_file = open(info_filename,'w')        
    asm_file = open(asm_filename,'r')
    asmplus_file = open(asm_filename,'r')
    
    
#    funcs = idautils.Functions()
#    funcs_iterator = idautils.Functions()
    
     
#    for f in funcs:        
#        func_name = GetFunctionName(f)              
#        BB_extract(output_file, f, asmplus_filename)    

    
#    output_file.close()
    asm_file.close()
    asmplus_file()
        
        
# end of controller
#------------------------------------------------------------------------------------------------------------------------      

q = None
f = None
idc.Wait()
controller()

