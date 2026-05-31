
import sys
import os
import argparse
import re
import numpy as np
import time

self_type = dict()
def set_type():
    global self_type
    # Get labels
    for root,dirs,files in os.walk('type'):
        for f in files:
            #set_type1 = open('C:\\Users\\usr\\Desktop\\set_type.txt', 'a')
            k = root.split('/')[-1]
            #set_type1.write(k)
            if k not in self_type:
                self_type[k] = dict()

            fn = os.path.join(root,f)
            label = f

            with open(fn,'r') as fr:
                for line in fr:
                    line = line.strip('\n')
                    self_type[k][line] = label

                    if fn.split('/')[-2] == 'api':
                        self_type[k][line+'A'] = label
                        self_type[k][line+'W'] = label

# Create DR feature vector
class DR:
    def __init__(self, addr, inst, offspring, betweenness, api):
        self.entry_addr = int(addr,16)  
       

        self.inst = inst.split(';')

        self.offspring = int(offspring)
        self.betweenness = float(betweenness)

        self.api = api.split(';')


    def get_type(self):
        global self_type
        #get_type1 = open('C:\\Users\\usr\\Desktop\\get_type.txt', 'a')

        # Initialize variables
        self.arithmetic = 0
        self.branch = 0
        self.comparison = 0
        self.conditional_control_flow = 0
        self.data_movement = 0
        self.register = 0
        self.memory = 0

        self.api_file = 0
        self.api_configuration = 0
        self.api_data_type = 0
        self.api_encrytion = 0
        self.api_memory = 0
        self.api_network = 0
        self.api_notification = 0
        self.api_openssl= 0
        self.api_process = 0
        self.api_register= 0
        self.api_structure = 0
        self.api_time = 0



        # Count parsed labels
        for i in self.inst:
            #get_type1.write(str(self.inst))
            if i in self_type['inst'].keys():
                #get_type1.write(str(self_type['inst'].keys()))
                if self_type['inst'][i] == 'arithmetic':
                    self.arithmetic += 1
                elif self_type['inst'][i] == 'branch':
                    self.branch += 1
                elif self_type['inst'][i] == 'comparison':
                    self.comparison += 1
                elif self_type['inst'][i] == 'conditional-control-flow':
                    self.conditional_control_flow += 1
                elif self_type['inst'][i] == 'data-movement':
                    self.data_movement += 1
                elif self_type['inst'][i] == 'register':
                    self.register += 1
                elif self_type['inst'][i] == 'memory':
                    self.memory += 1

                else:
                    sys.stderr.write('Error. Unknown instruction type: {0}: {1}\n'.format(i,self_type['inst'][i]))

        for i in self.api:
            #get_type1.write(str(self.api))
            if i in self_type['api'].keys():
                if self_type['api'][i] == 'file':
                    self.api_file += 1
                elif self_type['api'][i] == 'configuration':
                    self.api_configuration += 1
                elif self_type['api'][i] == 'encryption':
                    self.api_encrytion += 1
                elif self_type['api'][i] == 'data-type':
                    self.api_data_type += 1
                elif self_type['api'][i] == 'memory':
                    self.api_memory += 1
                elif self_type['api'][i] == 'network':
                    self.api_network += 1
               # elif self_type['api'][i] == 'notification':
               #     self.api_notification += 1
               # elif self_type['api'][i] == 'openssl':
               #     self.api_openssl += 1
                elif self_type['api'][i] == 'process':
                    self.api_process += 1
                elif self_type['api'][i] == 'register':
                    self.api_register += 1
                elif self_type['api'][i] == 'structure':
                    self.api_structure += 1
                elif self_type['api'][i] == 'time':
                    self.api_time += 1

                else:
                    sys.stderr.write('Error. Unknown api type: {0}: {1}\n'.format(i,self_type['api'][i]))



    def __str__(self):
        rv = 'Basic Block Addr: {0}\n'.format(hex(self.entry_addr))
        rv += '    ++++++ Instruction Features ++++++\n'
        rv += '    Insts: {0}\n'.format(';'.join(self.inst))
        rv += '\n'
        rv += '    ++++++ Structural Features ++++++\n'
        rv += '    Num offspring: {0}\n'.format(self.offspring)
        rv += '    Betweenness: {0}\n'.format(self.betweenness)
        rv += '\n'
        rv += '    ++++++ API Features ++++++\n'
        rv += '    APIs: {0}\n'.format(';'.join(self.api))
        return rv

    def __repr__(self):
        return '<DR for {0}>'.format(hex(self.entry_addr))

# Dump features to output file
def dump(output,dr):
    #dump_file = open('C:\\Users\\usr\\Desktop\\dump_file.txt', 'a')

    # Get folder of features file
    # Create it if it doesn't exist
    root = os.path.dirname(output)
    #dump_file.write( root + '\n' )

    if not os.path.exists(root):
        os.makedirs(root)

    # Create numpy array
    array = np.array([], dtype=float)

    # For each basic block
    for bb in sorted(dr, key=lambda x:x.entry_addr):
        a = np.array([], dtype=float)

        # [0] Entry address
        a = np.append(a,bb.entry_addr)

        # [1] Offspring
        a = np.append(a,bb.offspring)
        # [2] Betweenness
        a = np.append(a,bb.betweenness)



        # [3] Arithmetic - basic math (functionality)
        a = np.append(a,bb.arithmetic)
        # [4] Arithmetic - logical operations (programmatic / control flow)
        a = np.append(a,bb.branch)
        a = np.append(a,bb.comparison)
        # [5] Arithmetic - bit shifting (efficency)
        a = np.append(a,bb.conditional_control_flow)

        
        # [7] Transfer - register operations
        a = np.append(a,bb.data_movement)
        # [8] Transfer - port operations
        
       
        a = np.append(a,bb.register)
       
        a = np.append(a,bb.memory)
        a = np.append(a,bb.api_file)

        

        # [9] API - dll
        a = np.append(a,bb.api_configuration)
        # [10] API - file
        
        # [11] API - network
        
        a = np.append(a,bb.api_data_type)
        # [12] API - object
        a = np.append(a,bb.api_encrytion)
        a = np.append(a,bb.api_file)
        # [13] API - process
        a = np.append(a,bb.api_memory)
        # [14] API - registry
        a = np.append(a,bb.api_network)
        # [15] API - service
      #  a = np.append(a,bb.api_notification)
      #  a = np.append(a,bb.api_openssl)
        a = np.append(a,bb.api_process)
        a = np.append(a,bb.api_register)

        if len(array) == 0:
            array = np.array([a])
        else:
            array = np.vstack((array,a))

    #dump_file.write(array)
    # Output numpy array
    np.save(output, array)

# Gets DR contents from preprocessed file
def extract(fn):
    rv = list()
    #fn_file = open('C:\\Users\\usr\\Desktop\\fn_file.txt', 'a')
    #fn_file.write(fn + '\n' )
    # Read all contents from file
    with open(fn,'r') as fr:
        content = fr.read()
        #fn_file.write(content + '\n' )

    # Create pattern
    pattern = r''
    pattern += r'Basic Block Addr: (.*)\n'
    pattern += r'.*\n'
    pattern += r'.*Insts: (.*)\n'
    pattern += r'.*\n'
    pattern += r'.*\n'
    pattern += r'.*Num offspring: (.*)\n'
    pattern += r'.*Betweenness: (.*)\n'
    pattern += r'.*\n'
    pattern += r'.*\n'
    pattern += r'.*APIs: (.*)\n'

    # Parse DR features
    match = re.findall(pattern, content, re.MULTILINE)
    for m in match:
        addr,inst,offspring,betweenness,api = m
        #fn_file.write(inst + '\n' )
        dr = DR(addr,inst,offspring,betweenness,api)
        dr.get_type()
        rv.append(dr)

    return rv

def _main():
    #output1 = "C:\\Binary\\Train extract raw npy\\"

    i = 0
    #with os.scandir('C:\Binary\Train extract raw') as root_dir:
    with os.scandir('/home/cyberlab/Documents/15nov2025_improvded_extraction_malware/testing_malicious_elf_arm/elf_compiled/') as root_dir:
        for path in root_dir:
            if path.is_file():
                if path.name.endswith(".exe.txt"): 
                    i += 1
                    fn = "/home/cyberlab/Documents/15nov2025_improvded_extraction_malware/testing_malicious_elf_arm/elf_compiled/" +  path.name
                    ##fn = "C:\\Binary\\Train extract raw\\" +  path.name
                    #output = "C:\\Binary\\Train extract raw npy\\" +  path.name
                    output = "/home/cyberlab/Documents/15nov2025_improvded_extraction_malware/testing_malicious_elf_arm/elf_compiled/" +  path.name
                    temp = "/home/cyberlab/Documents/15nov2025_improvded_extraction_malware/testing_malicious_elf_arm/elf_compiled/" +  path.name + ".npy"
                    print ("----------------TEMP------------------")
                    print (temp)
                    print ("\n")
                    
                    #print (extract_command)
                    print (fn)
                    print ("------------------++++++++++++-")
                    print(f"Full path is: {path} and just the name is: {path.name}")
                    print(f" NPY conversion for {i} file is completed.")
                    if os.path.isfile(temp):   ##delete if file generate
                        print("File exists")
                        print ("---IGNORE----\n")
                    else:
                    # # Set types from files
                        set_type()


                    # Get dr contents
                        rv = extract(fn)


                    # Output feature vector
                        dump(output,rv)

                else:
                    print ("-----IGNORE------------------")
                    print(f"Full path is: {path} and just the name is: {path.name}")

                    
                
    print(f"{i} files scanned successfully.")


_main()
