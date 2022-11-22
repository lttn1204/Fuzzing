from enum import Enum
import hashlib
import datetime
import json
import re


class ExecStatus(Enum):
    NORMAL = 0xd0
    CRASH = NORMAL + 1
    ABORT = NORMAL + 2
    DOS = NORMAL + 3


class TraceInfo:
    def __init__(self, module_name, bb_list):
        self.module_name = module_name
        self.bb_list = bb_list

    def to_dict(self):
        ret = {}
        ret['module_name'] = self.module_name
        ret['bb_list'] = self.bb_list
        return ret

    def to_json(self):
        return json.dumps(self.to_dict())


class ExecResult:
    def __init__(self, trace=[], status="", crash_info=""):
        self.trace = trace  # TraceInfo list
        self.status = status
        self.crash_info = crash_info

    def is_crash(self):
        if self.status == 0xd0:
            return True
        else:
            return False

    def to_json(self):
        ret = {}
        ret['status'] = self.status.value
        ret['crash_info'] = self.crash_info
        ret['trace'] = []

        for ti in self.trace:
            ret['trace'].append(ti.to_dict())

        return json.dumps(ret)

    def load_json(self, data):
        data = json.loads(data)
        self.status = ExecStatus(data['status'])

        self.crash_info = data['crash_info']
        self.trace = []

        for t in data['trace']:
            self.trace.append(TraceInfo(t['module_name'], t['bb_list']))

    def __str__(self):
        return "status: {}, crash_info: {}".format(self.status, self.crash_info)

'''
class Testcase:
    def __init__(self, idx, bb_executed):
        self.idx = idx
        self.trace = bb_executed
        self.base_exec_count = 50
        self.exec_count = self.base_exec_count
        self.path_found = 0  # new path found by this case
        self.dos_count = 0

        self.crash_count = 0

        self.seed_id = 0
        self.seed_hash = ""

        self.inc_ratio = 0.1
        self.dec_ratio = 0.1

    def get_trace(self):
        return self.trace

    def get_trace_count(self):
        count = 0
        for ti in self.trace:
            count += len(ti.bb_list)
        return count

    def is_contain_by(self, seed):
        for i in range(self.trace):
            a = set(self.trace[i].bb_list)
            b = set(seed.trace[i].bb_list)
            if not b.issuperset(a):
                return False
        return True

    def found_crash(self):
        self.crash_count += 1

    def found_dos(self):
        self.exec_count = int(self.exec_count * self.dec_ratio)
        if self.exec_count == 0:
            self.exec_count = 1
        self.dos_count += 1

    def found_path(self):
        self.path_found += 1
        self.exec_count = int(self.base_exec_count + self.base_exec_count * self.path_found * self.inc_ratio)

    def __str__(self):
        data = "idx: {}, crash found: {}, dos found: {}, path found: {}, bb count: {}, exec count: {}".format(
            self.idx, self.crash_count, self.dos_count, self.path_found, self.get_trace_count(), self.exec_count)
        return data
'''

class Crash:
    def __init__(self, idx, trace, crash_info=""):
        self.idx = idx
        self.trace = trace
        self.crash_info = crash_info

        data = ""
        for ti in trace:
            data += "{}\n".format(ti.module_name)
            data += ','.join(['{:X}'.format(x) for x in ti.bb_list])
            data += '\n'

        crash_hash = self.parse_crash_hash(crash_info)

        if crash_hash:
            self.trace_hash = crash_hash[:18]  # max depth is 6
        else:
            self.trace_hash = hashlib.md5(data + crash_info).hexdigest()

    def parse_crash_hash(self, crash_info):
        pc = None
        try:
            d = re.findall("crash-hash: (.*?) ", crash_info)
            if len(d) > 0:
                return d[0]

            d = re.findall("eip=(.*?) ", crash_info)
            if len(d) > 0:
                return d[0][-3:]

            d = re.findall("rip\s+(.*?) ", crash_info)
            if len(d) > 0:
                return d[0][-3:]

            d = re.findall("eip\s+(.*?) ", crash_info)
            if len(d) > 0:
                return d[0][-3:]
        except Exception as e:
            print ("get_crash_hash_from_crash_info failed")
            print (e)
            print (crash_info)
        return pc


class Dos:
    def __init__(self, idx, trace, exec_time=-1):
        self.idx = idx
        self.trace = trace

        data = ""

        for ti in trace:
            data += "{}\n".format(ti.module_name)
            data += ','.join(['{:X}'.format(x) for x in ti.bb_list])
            data += '\n'

        self.trace_hash = hashlib.md5(data).hexdigest()


class CustomLogger:
    def __init__(self):
        pass
        
    def get_current_time(self):
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def log(self, s):
        data = "[{}] {}".format(self.get_current_time(), s)
        print(data)


class EdgeInfo:
    def __init__(self,from_bb,to_bb):
        if from_bb>to_bb:
            from_bb,to_bb=to_bb,from_bb
        self.from_bb=from_bb
        self.to_bb=to_bb
        self.value=1
    def __gt__(self,other):
        if self.from_bb > other.from_bb:
            return True
        elif self.from_bb==other.from_bb:
            if self.to_bb>other.to_bb:
                return True
        return False
    def __lt__(self,other):
        if self.from_bb < other.from_bb:
            return True
        elif self.from_bb==other.from_bb:
            if self.to_bb<other.to_bb:
                return True
        return False
    def __eq__(self,other):
        if self.from_bb == other.from_bb and self.to_bb==other.to_bb:
            return True
        return False
    def __str__(self):
        print(f"{self.from_bb} - {self.to_bb}: {self.value}")


def gen_original_seed(length):
    arr=[]
    for i in range(length):
        arr.append(i%256)
    return bytes(arr)

def calculate_coverage_similaty_and_frequency_difference(edges1,edges2):
    numerator_cs=0
    denominator_cs=0
    numerator_fd=0
    denominator_fd=0
    for edge in edges1:
        if edge in edges2:
            tmp=edges1[edges1.index(edge)].value+edges2[edges2.index(edge)].value
            numerator_cs+=tmp
            denominator_cs+=tmp
            if edges1[edges1.index(edge)].value==edges2[edges2.index(edge)].value:
                numerator_fd+=1
        else:
                denominator_fd+=1
                denominator_cs+=edges1[edges1.index(edge)].value

    for edge in edges2:
        if edge not in edges1:
            denominator_fd+=1
            denominator_cs+=edges2[edges2.index(edge)].value

    if denominator_cs==0:
        denominator_cs=1
    if denominator_fd==0:
        denominator_fd=1
    return numerator_cs/denominator_cs, numerator_fd/denominator_fd

def check_same_field(begin_offset, end_offset, info_mutate_seed):
    init_value=min(info_mutate_seed[begin_offset]["coverage_similaty"])
    for offset in range(begin_offset+1,end_offset):
        if min(info_mutate_seed[offset]["coverage_similaty"])!=init_value:
            return False
    return True

def check_exit_value_1_and_other_lessthan_alpha(offset,info_mutate_seed,alpha):#for assertion_field_identification
    count=0
    for i in range(256):
        if info_mutate_seed[offset]["coverage_similaty"][i]==1:
            count+=1
            if count>1:
                return False
        else:
            if info_mutate_seed[offset]["coverage_similaty"][i]>alpha:
                return False
    return True
 
def assertion_field_identification(begin_offset, end_offset, info_mutate_seed,alpha):
    for x in range(begin_offset,end_offset):
        if check_exit_value_1_and_other_lessthan_alpha(x,info_mutate_seed,alpha)==False:
            return False
    return True

def check_all_value_is_1(offset,info_mutate_seed): #for raw_data_field_identification
    for i in range(256):
        if info_mutate_seed[offset]["coverage_similaty"][i]!=1:
            return False
    return True


def raw_data_field_identification(begin_offset, end_offset, info_mutate_seed,alpha):
    for offset in range(begin_offset,end_offset):
        if check_all_value_is_1(offset,info_mutate_seed)==False:
            return False
    return True

def check_for_identy_subpace_for_enumeration(offset,info_mutate_seed,i,j,alpha):#for identy_subpace_for_enumeration
    for k in range(i,256):
        if k<j:
            if info_mutate_seed[offset]["coverage_similaty"][k]<alpha:
                return False
        else:
            if info_mutate_seed[offset]["coverage_similaty"][k]<alpha:
                return False
    return True

def identy_subpace_for_enumeration(offset,info_mutate_seed,alpha): #for enumeration_field_indentification
    for i in range(1,256):
        for j in range(i+1,256):
        if check_for_identy_subpace_for_enumeration:
            return True
    return False

def enumeration_field_indentification(begin_offset, end_offset, info_mutate_seed,alpha):
    for x in range(begin_offset,end_offset):
        if identy_subpace_for_enumeration(offset,info_mutate_seed,alpha):
            return True
    return False


def variance_coverae_similaty(offset,info_mutate_seed):#for loop_count_field_indentification
    init_value=info_mutate_seed[offset]['coverage_similaty'][0]
    res=0
    for i in range(1,256):
        res+=abs(init_value-info_mutate_seed[offset]['coverage_similaty'][i])
    return res/255


def average_frequency_difference(offset,info_mutate_seed):#for loop_count_field_indentification
    return sum(info_mutate_seed[offset]["frequency_difference"])/len(info_mutate_seed[offset]["frequency_difference"])

def loop_count_field_indentification(begin_offset, end_offset, info_mutate_seed,alpha):
    beta=7.355
    for x in range(begin_offset,end_offset):
        if variance_coverae_similaty(x,info_mutate_seed)<beta and average_frequency_difference(offset,info_mutate_seed)>1:
            return True
    return False



def check_u_v_difference(offset,info_mutate_seed,index):#for identy_subpace
    for i in range(1,index):
        for j in range(i,index):
            if info_mutate_seed[offset]["coverage_similaty"][i]!=info_mutate_seed[offset]["coverage_similaty"][j]:
                return True
    return False

def check_other_value_lt_alpha(offset,info_mutate_seed,index,alpha):#for identy_subpace
    for i in range(index):
        if info_mutate_seed[offset]["coverage_similaty"][i]>alpha:
            return False
    retunr True

def identy_subpace(offset,info_mutate_seed,alpha): #for offset_field_indentification and size_field_indentification
    for i in range(3,256):
        if check_u_v_difference and check_other_value_lt_alpha(offset,info_mutate_seed,index,alpha):
            return True
    return False


def check_value_index0_lt_alpha(offset,info_mutate_seed,alpha):#for offset_field_indentification and size_field_indentification
    return info_mutate_seed[offset]["coverage_similaty"][0]>alpha

def offset_field_indentification(begin_offset, end_offset, info_mutate_seed,alpha):
    for x in range(begin_offset,end_offset):
        if check_value_index0_lt_alpha(x,info_mutate_seed,alpha) and identy_subpace(x,info_mutate_seed,alpha):
            return True
    return False

def size_field_indentification(begin_offset, end_offset, info_mutate_seed,alpha):
    for x in range(begin_offset,end_offset):
        if not check_value_index0_lt_alpha(x,info_mutate_seed,alpha) and identy_subpace(x,info_mutate_seed,alpha):
            return True
    return False



