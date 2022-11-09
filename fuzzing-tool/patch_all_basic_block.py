import os
from struct import pack, unpack
import shutil

def patch_bb(target, bb_file):
    print("Patch all basic block")
    d = os.path.dirname(target)
    output_dir = os.path.join(d, "patch")

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    output_file = os.path.join(output_dir, os.path.basename(target))
    shutil.copyfile(target, output_file)

    f = open(bb_file, "rb")
    fa = open(output_file, "r+b")
    rva_size = unpack("<I", f.read(4))[0]
    fname_sz = unpack("<I", f.read(4))[0]
    fname = f.read(fname_sz)

    count = 0

    while True:
        data = f.read(12)
        if len(data) < 12:
            break

        voff, foff, instr_sz = unpack("<III", data)
        instr = f.read(instr_sz)
        fa.seek(foff)
        fa.write(b"\xcc" * instr_sz)

        count += 1

    f.close()
    fa.close()

    print ("patch {} basic block of {}".format(count, fname))


#patch_bb("E:\\Fuzzing\\Target\\sum", "E:\\Fuzzing\\Target\\sum-bb.txt")