from get_all_basic_block import get_all_basic_block
from patch_all_basic_block import patch_bb
from mutator_for_get_info import info_mutator
from tracer import PythonPtraceTracer
from common import calculate_coverage_similaty_and_frequency_difference

ida_path = "/home/lttn/Fuzzing/IDA7.7/IDA7.7/ida64.exe"
file_path = "/home/lttn/Fuzzing/Target/imgread"
input_length = 2
#get_all_basic_block(ida_path,file_path)
#patch_bb(file_path,file_path+"-bb.txt")


info_mutate_seed={}

length_seed=input_length
original_seed=bytes([i%256 for i in range(length_seed)])
w=open("tmp","wb")
w.write(original_seed)
w.close()
tracer = PythonPtraceTracer(["/home/lttn/Fuzzing/Target/patch/imgread", "tmp"], "/home/lttn/Fuzzing/Target/imgread-bb.txt")
original_info=tracer.trace()
print(original_info)
generator_input=info_mutator(original_seed)

info_per_bytes={}

while True:
    new_value=next(generator_input.get_next_input())
    idx=generator_input.idx
    if generator_input.is_new_idx:
        coverage_similaty=[]
        frequency_difference=[]
        for value in range(256):
            tmp1,tmp2=calculate_coverage_similaty_and_frequency_difference(original_info,info_per_bytes[value])
            coverage_similaty.append(tmp1)
            frequency_difference.append(tmp2)
        info_per_bytes={}
        info_mutate_seed[idx-1]={}
        info_mutate_seed[idx-1]["coverage_similaty"]=coverage_similaty
        info_mutate_seed[idx-1]["frequency_difference"]=frequency_difference
        generator_input.is_new_idx=False
        print(idx)
        print(info_mutate_seed)

    w=open("tmp","wb")
    w.write(new_value)
    w.close()
    tracer = PythonPtraceTracer(["/home/lttn/Fuzzing/Target/patch/imgread", "tmp"], "/home/lttn/Fuzzing/Target/imgread-bb.txt")
    edge_info=tracer.trace()
    #info_mutate_seed[generator_input.idx][generator_input.value]=num_bb_trigger
    info_per_bytes[generator_input.value]=edge_info

    if generator_input.is_done:
        coverage_similaty=[]
        frequency_difference=[]
        for value in range(256):
            tmp1,tmp2=calculate_coverage_similaty_and_frequency_difference(original_info,info_per_bytes[value])
            coverage_similaty.append(tmp1)
            frequency_difference.append(tmp2)
        info_per_bytes={}
        info_mutate_seed[idx-1]={}
        info_mutate_seed[idx-1]["coverage_similaty"]=coverage_similaty
        info_mutate_seed[idx-1]["frequency_difference"]=frequency_difference
        generator_input.is_new_idx=False
        print(info_mutate_seed)


print(info_mutate_seed)




