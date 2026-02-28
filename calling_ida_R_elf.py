#!/usr/bin/python3
import os
from subprocess import getstatusoutput
import hashlib

def get_dr_binja():

    i = 0
    with os.scandir('/home/firmfuzz/Downloads/caimp/from_debian_mips') as root_dir:
    #with os.scandir('/home/deepreflect/Desktop/Benign') as root_dir:
        for path in root_dir:
            if path.is_file():
                if path.name.endswith(""):
                    #file = "/home/deepreflect/Desktop/Virus/" +  path.name
                    print (path.name)
    		     #file_hash = hashlib.md5() 
    		     #file_name = file_hash.hexdigest()
                    i += 1
                   #wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe 
                   ## #extract_command = '"C:\\IDA 7.0\\ida64.exe" -B -c -A -S"C:\\function_features.py"' + " " +  '"' + "C:\\Binary\\" +  path.name + '"'


                    #extract_command = '/usr/bin/wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe -B -c -A -S"/home/deepreflect/Desktop/elf_malicious/zabi-extracted/"' + " " +  '"' + "/home/deepreflect/Desktop/Virus/" +  path.name + '"'
                    extract_command = '/usr/bin/wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe -B -c -A -S"/home/firmfuzz/Downloads/idascr/cmplt_asm.py"' + " " +  '"' + "/home/firmfuzz/Downloads/caimp/extracted/" +  path.name + '"'
##for  cmplt.py
##                    extract_command = '/usr/bin/wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe -B -c -A -S"/home/deepreflect/Desktop/cmplt.py"' + " " +  '"' + "/home/deepreflect/Desktop/dataset/" +  path.name + '"'
 ##for function_feature.py
 #                    extract_command = '/usr/bin/wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe -B -c -A -S"/home/deepreflect/Desktop/function_features.py"' + " " +  '"' + "/home/deepreflect/Desktop/dataset/" +  path.name + '"'
 
 ##for print basic block
#                    extract_command = '/usr/bin/wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe -B -c -A -S"/home/deepreflect/Desktop/print_basic_blocks.py"' + " " +  '"' + "/home/deepreflect/Desktop/dataset/" +  path.name + '"'
                   #extract_command = '"C:\\IDA 7.0\\ida64.exe" -B -c -A -S"C:\\cmplt.py"' + " " +  '"' + "C:\\Binary\\" +  path.name + '"'

                    print (extract_command)
                    #exit()
                    print ("------------------++++++++++++-")
                    print(f"Full path is: {path} and just the name is: {path.name}")
                    r, output = getstatusoutput(extract_command)
                    print (r) 
                    print ("-----------------------")
                    print (output)
                    print(f" Raw features of {i} file are extracted.")
                    exit()
                   
                else:
                    print ("-----IGNORE------------------")
                    print(f"Full path is: {path} and just the name is: {path.name}")

                    
                
    print(f"{i} files scanned successfully.")
    
   
def _main():
    get_dr_binja()


if __name__ == '__main__':
    _main()


     
