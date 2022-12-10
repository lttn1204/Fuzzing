from get_all_basic_block import get_all_basic_block
from patch_all_basic_block import patch_bb
from mutator_for_get_info import info_mutator
from tracer import PythonPtraceTracer
from common import *

ida_path = "/home/lttn/Fuzzing/IDA7.7/IDA7.7/ida.exe"
file_path = "/home/lttn/Fuzzing/Target/base64"
input_length = 15
#get_all_basic_block(ida_path,file_path)
patch_bb(file_path,file_path+"-bb.txt")
'''
info_mutate_seed={}

length_seed=input_length+1
original_seed=bytes([i%256 for i in range(length_seed)])
w=open("tmp","wb")
w.write(original_seed)
w.close()
tracer = PythonPtraceTracer(["/home/lttn/Fuzzing/Target/patch/base64", "tmp"], "/home/lttn/Fuzzing/Target/base64-bb.txt")
original_info=tracer.trace()
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
            alpha=(max(coverage_similaty)+min(coverage_similaty))/2
            frequency_difference.append(tmp2)
        info_per_bytes={}
        info_mutate_seed[idx-1]={}
        info_mutate_seed[idx-1]["coverage_similaty"]=coverage_similaty
        info_mutate_seed[idx-1]["frequency_difference"]=frequency_difference
        info_mutate_seed[idx-1]["alpha"]=alpha
        generator_input.is_new_idx=False

    w=open("tmp","wb")
    w.write(new_value)
    w.close()
    tracer = PythonPtraceTracer(["/home/lttn/Fuzzing/Target/patch/base64", "tmp"], "/home/lttn/Fuzzing/Target/base64-bb.txt")
    edge_info=tracer.trace()

    info_per_bytes[generator_input.value]=edge_info

    if generator_input.is_done:
        print("catch done")
        coverage_similaty=[]
        frequency_difference=[]
        for value in range(256):
            tmp1,tmp2=calculate_coverage_similaty_and_frequency_difference(original_info,info_per_bytes[value])
            coverage_similaty.append(tmp1)
            alpha=(max(coverage_similaty)+min(coverage_similaty))/2
            frequency_difference.append(tmp2)
        info_per_bytes={}
        info_mutate_seed[idx-1]={}
        info_mutate_seed[idx-1]["coverage_similaty"]=coverage_similaty
        info_mutate_seed[idx-1]["frequency_difference"]=frequency_difference
        info_mutate_seed[idx-1]["alpha"]=alpha
        generator_input.is_new_idx=False
        
        break
print(info_mutate_seed)

######### group field
assertion_field=[]
raw_data_field=[]
enumeration_field=[]
loop_count_field=[]
offset_field=[]
size_field=[]
id_field=[]


i=0
length_seed=input_length-1
while i<length_seed:
    done=0
    for j in range(length_seed-1,i,-1):
        if check_same_field(i,j,info_mutate_seed):
            id_field.append([i,j+1])
            i=j+1
            done=1
            break
    if done==0:
        id_field.append([i])
        i+=1

print(id_field)
########################## Identification field

for offsets in id_field:
    if len(offsets)!=1:
        if assertion_field_identification(offsets[0],offsets[1]+1,info_mutate_seed):
            assertion_field.append(offsets)
        elif raw_data_field_identification(offsets[0],offsets[1]+1,info_mutate_seed):
            raw_data_field.append(offsets)
        elif enumeration_field_indentification(offsets[0],offsets[1]+1,info_mutate_seed):
            enumeration_field.append(offsets)
        elif loop_count_field_indentification(offsets[0],offsets[1]+1,info_mutate_seed):
            loop_count_field.append(offsets)
        elif offset_field_indentification(offsets[0],offsets[1]+1,info_mutate_seed):
            offset_field.append(offsets)
        elif size_field_indentification(offsets[0],offsets[1]+1,info_mutate_seed):
            size_field.append(offsets)

print(f"assertion: {len(assertion_field)}")
print(f"raw data: {len(raw_data_field)}")
print(f"enumeration: {len(enumeration_field)}")
print(f"loop count: {len(loop_count_field)}")
print(f"offset: {len(offset_field)}")
print(f"size: {len(size_field)}")
'''






