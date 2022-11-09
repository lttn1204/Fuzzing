import os
from struct import pack, unpack
def get_all_basic_block(ida_path,file_path):
    dump_basic_block_script = "dumb_basic_block.py"
    command = 'wine {} -A -c -S{} {}'.format(ida_path, os.path.abspath(dump_basic_block_script), file_path)
    print(command)
    os.system(command)
