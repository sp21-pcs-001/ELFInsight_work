import idaapi
import idautils
import idc
import hashlib


def controller():
    basename = idc.GetInputFile()

    # Generate MD5 hash of the file for naming
    BLOCK_SIZE = 65536
    file_hash = hashlib.md5()
    with open(basename, 'rb') as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(BLOCK_SIZE)

    file_name = file_hash.hexdigest()

    # Only generate the .asm file
    asm_filename = file_name + ".asm"
    idc.GenerateFile(idc.OFILE_ASM, asm_filename, 0, idc.BADADDR, 0)

    print("ASM file generated: " + asm_filename)


# Entry point
idc.Wait()
controller()
