from get_all_basic_block import get_all_basic_block
from patch_all_basic_block import patch_bb
from mutator_for_get_info import info_mutator
from tracer import PythonPtraceTracer
from common import *
import shutil
from radamsa_mutator import Radamsa_mutator
ida_path = "/home/lttn/Fuzzing/IDA7.7/IDA7.7/ida64.exe"
file_path = "/home/lttn/Fuzzing/Target/csawctf2021_password"
input_length=2
get_all_basic_block(ida_path,file_path)
patch_bb(file_path,file_path+"-bb.txt")
mutator=Radamsa_mutator("/home/lttn/radamsa/bin/radamsa")
seed_input="/home/lttn/Fuzzing/fuzzing-tool/input"
mutated_input="/home/lttn/Fuzzing/fuzzing-tool/tmp"
save_bb=[]
file_to_fuzz="/home/lttn/Fuzzing/Target/patch/csawctf2021_password"
bb_file_to_fuzz="/home/lttn/Fuzzing/Target/csawctf2021_password-bb.txt"

print("AAAAAAAAAA")
#tracer = PythonPtraceTracer([file_to_fuzz,"/home/lttn/Fuzzing/fuzzing-tool/inp"], bb_file_to_fuzz)
#a=tracer.trace()
print("BBBBBBBBBBBBBBBBBBB")
def read():
    a=open(mutated_input,"rb").read()
    print(a)


while True:
    mutator.mutate(seed_input)
    print("intofuzz")
    tracer = PythonPtraceTracer([file_to_fuzz,mutated_input], bb_file_to_fuzz)
    res=tracer.trace()
    print("into")
    new_path=False
    read()
    for block in res:
        if block not in save_bb:
            new_path=True
            save_bb.append(block)
    if new_path:
        shutil.copy(mutated_input,seed_input)
        new_path=False
        




'''
self.exec_stage=""
self.exec_stage = ""
self.testcase_list = []
self.patch_to_binary = False



def set_fuzz_stage(self, stage):
    self.exec_stage = stage
    with open(os.path.join(self.output, "exec-stage"), "w") as fp:
        fp.write(stage)

 def save_crash(self, trace, crash_info=""):
    crash_idx = len(self.crash_list)
    crash = Crash(crash_idx, trace, crash_info)
    if not self.is_unique_crash(crash):
        return False
    self.save_case_to_file("crash", crash_idx, trace, crash_info)
    self.crash_list.append(crash)
    return True

def save_dos(self, trace, exec_time=-1):
    idx = len(self.dos_list)
    dos = Dos(idx, trace, exec_time)

    if self.patch_to_binary or self.is_unique_dos(dos):
        self.save_case_to_file("dos", idx, trace, "exec-time: {}".format(exec_time))
        self.dos_list.append(dos)
        return True
    else:
        return False


while True:
    self.total_exec_count = 0
    # seed = random.choice(self.testcase_list)
    for i in range(len(self.testcase_list)):
        if self.exec_stage == "loading-testcase":
            #self.load_testcase(self.import_case_dir)
            self.set_fuzz_stage("fuzz")

        if self.patch_to_binary:
            cur_seed = random.choice(self.testcase_list)
        else:
                

        seed_path = "{}/trapfuzz-testcase-{}.bin".format(
            self.output, cur_seed.idx)
        for i in range(cur_seed.exec_count):  # per case fuzz count
            if self.fuzzer_status == "stop":
                self.stop_fuzz()
                return

            run_time = time.time()
            m_info = None
            while True:
                try:
                    m_info = self.cur_mutator.mutate(seed_path, self.input_path_read_by_target)
                    break
                except:
                    # print "mutate file error, wait for retry..."
                    pass
                time.sleep(0.5)
            self.current_file = seed_path

            try:
                ret = self.exec_testcase(self.patch_to_binary)
            except Exception as e:
                print e
                self.stop_fuzz()
                return

            delta = time.time() - run_time

            if ret.status == ExecStatus.NORMAL:
                if self.has_new_path(ret.trace):
                    self.last_new_path_found = self.logger.get_current_time()
                    if self.patch_to_binary:
                        ret.trace = []

                    test_case = self.save_testcase(ret.trace)

                    cur_seed.found_path()
            elif ret.status == ExecStatus.DOS:
                cur_seed.found_dos()
                self.last_dos_found = self.logger.get_current_time()
                if self.save_dos(ret.trace, delta):
                    return 

                self.logger.log("found a dos, seed index: {}".format(cur_seed.idx))
                break
            else:
                self.last_crash_found = self.logger.get_current_time()
                cur_seed.found_crash()
                if self.save_crash(ret.trace, ret.crash_info):
                    return 

                self.logger.log("found a crash, seed index: {}".format(cur_seed.idx))


            if self.total_exec_count % 10 == 0:
                self.cur_mutator = random.choice(self.mutator_list)
                self.exec_speed = round(float(self.total_exec_count) / self.total_exec_time, 1)
                self.avg_run_time = round(float(self.total_exec_time) / self.total_exec_count, 1)
                self.logger.log("[trapfuzzer] run {}, speed:{}/min, avg_run_time:{}s, path count:{}".format(
                    self.total_exec_count, self.exec_speed * 60, self.avg_run_time, len(self.testcase_list)))
'''








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
'''
'''
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








