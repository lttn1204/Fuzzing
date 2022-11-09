from get_all_basic_block import get_all_basic_block
from patch_all_basic_block import patch_bb

ida_path = "/home/lttn/Fuzzing/IDA7.7/IDA7.7/ida64.exe"
file_path = "/home/lttn/Fuzzing/Target/imgread"
#get_all_basic_block(ida_path,file_path)
patch_bb(file_path,file_path+"-bb.txt")

