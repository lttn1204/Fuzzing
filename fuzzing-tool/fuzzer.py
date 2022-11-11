from get_all_basic_block import get_all_basic_block
from patch_all_basic_block import patch_bb
from mutator_for_get_info import info_mutator
from tracer import PythonPtraceTracer

ida_path = "/home/lttn/Fuzzing/IDA7.7/IDA7.7/ida64.exe"
file_path = "/home/lttn/Fuzzing/Target/imgread"
input_path= "/home/lttn/Fuzzing/Target/i"
#get_all_basic_block(ida_path,file_path)
#patch_bb(file_path,file_path+"-bb.txt")

info_mutate_seed={}
generator_input=info_mutator(input_path)

while True:
    new_value=next(generator_input.get_next_input())
    idx=generator_input.idx
    if generator_input.is_new_idx:
        info_mutate_seed[idx]={}
        generator_input.is_new_idx=False
        if idx!=0:
            max_value=max(info_mutate_seed[idx-1].values())
            for i  in info_mutate_seed[idx-1]:
                info_mutate_seed[idx-1][i]/=max_value

    w=open("tmp","wb")
    w.write(new_value)
    w.close()
    tracer = PythonPtraceTracer(["/home/lttn/Fuzzing/Target/patch/imgread", "tmp"], "/home/lttn/Fuzzing/Target/imgread-bb.txt")
    num_bb=tracer.trace()
    info_mutate_seed[generator_input.idx][generator_input.value]=num_bb

    if generator_input.is_done:
        if idx!=0:
            max_value=max(info_mutate_seed[idx].values())
            for i  in info_mutate_seed[idx]:
                info_mutate_seed[idx][i]/=max_value
            break

    print(info_mutate_seed)

print(info_mutate_seed)




