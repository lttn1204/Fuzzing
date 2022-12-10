import os

def get_all_basic_block(ida_path,file_path):
    dump_basic_block_script = "dumb_basic_block.py"
    command = 'wine {} -A -c -S{} {}'.format(ida_path, os.path.abspath(dump_basic_block_script), file_path)
    print(command)
    os.system(command)

ida_path = "/home/lttn/Fuzzing/IDA7.7/IDA7.7/ida.exe"
file_path = "/home/lttn/Fuzzing/Target/base64"
#get_all_basic_block(ida_path,file_path)