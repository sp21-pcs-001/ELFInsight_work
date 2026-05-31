#!/usr/bin/python3
import os
from subprocess import getstatusoutput
import hashlib


def get_dr_binja():

    i = 0
    ii = 0
    iii = 0
    count = 0
    with os.scandir('/home/deepreflect/Desktop/testing_malicious_elf_arm/elf_compiled/') as root_dir:
        # with os.scandir('/home/deepreflect/Desktop/Benign') as root_dir:
        for path in root_dir:
            if path.is_file():
                if path.name.endswith(".exe.txt"):
                    continue
                if path.name.endswith(".til"):
                    continue
                if path.name.endswith(".nam"):
                    continue
                if path.name.endswith(".id0"):
                    continue
                if path.name.endswith(".id1"):
                    continue
                if path.name.endswith(".asm"):
                    continue
                if path.name.endswith(".asmplus"):
                    continue
                if path.name.endswith(".elf"):
                    file = "/home/deepreflect/Desktop/testing_malicious_elf_arm/elf_compiled/" + ""+path.name
                    print("FileName is", file)
                    #print (file)
                    md5_hash = hashlib.md5()
                    a_file = open(file, "rb")
                    content = a_file.read()
                    md5_hash.update(content)
                    digest = md5_hash.hexdigest()
                    count  +=1
                    print(digest)
                    print(f"---ELF file count is: {count}--")
                    file_exe = "/home/deepreflect/Desktop/testing_malicious_elf_arm/elf_compiled" + \
                        ""+digest+".exe.txt"  # for exe
                    # file_exe = "/home/deepreflect/Desktop/Virus/" +""+digest+".exe_function.txt"  #for function

                    if os.path.isfile(file_exe):
                       #     print (".EXE.TXT of File exist")
                        ignore = 0
                        ii += 1
                        print(
                            f" RAW  feature File Exisits for {ii}  ELF files.")
                    else:
                       # print (" \nRAW Feature File not exist\n")
                        print("\n--ELF-\n")

                        ignore = 1
                        iii += 1
                        print(
                            f" RAW  feature File NOT Exisits for {iii}  ELF files.")

                    i += 1
                   # wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe
                   # extract_command = '"C:\\IDA 7.0\\ida64.exe" -B -c -A -S"C:\\function_features.py"' + " " +  '"' + "C:\\Binary\\" +  path.name + '"'

                    if ignore:
                        extract_command = '/usr/bin/wine /root/.wine/drive_c/Program\ Files/IDA\ 7.0/ida64.exe -B -c -A -S"/home/deepreflect/Desktop/testing_malicious_elf_arm/cmplt_elf_malicious.py"' + \
                            " " + '"' + "/home/deepreflect/Desktop/testing_malicious_elf_arm/elf_compiled/" + path.name + '"'
                        print(extract_command)
                        print("------------------++++++++++++-")
                        print(
                            f"INNER: Full path is: {path} and just the name is: {path.name}")
                        r, output = getstatusoutput(extract_command)
                        print(r)
                        print("-----------------------")
                        print(output)
                        print(f" Raw features of {iii} file are extracted.")
                    else:
                        print("Already content generated for Raw files or Functions")
                else:
                    print("-----IGNORE------------------")
                    print(
                        f"Man OUTEr:Full path is: {path} and just the name is: {path.name}")

    print(f"{i} files scanned successfully.")
    print(f" NEW Raw features of {iii} file are extracted.")


def _main():
    get_dr_binja(folder)


if __name__ == '__main__':
    _main()
