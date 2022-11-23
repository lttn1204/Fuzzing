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

def check_exit_value_1_and_other_lessthan_alpha(offset,info_mutate_seed):#for assertion_field_identification
    count=0
    for i in range(256):
        if info_mutate_seed[offset]["coverage_similaty"][i]==1:
            count+=1
            if count>1:
                return False
        else:
            if info_mutate_seed[offset]["coverage_similaty"][i]>info_mutate_seed[offset]["alpha"]:
                return False
    return True
 
def assertion_field_identification(begin_offset, end_offset, info_mutate_seed):
    for x in range(begin_offset,end_offset):
        if check_exit_value_1_and_other_lessthan_alpha(x,info_mutate_seed)==False:
            return False
    return True

def check_all_value_is_1(offset,info_mutate_seed): #for raw_data_field_identification
    for i in range(256):
        if info_mutate_seed[offset]["coverage_similaty"][i]!=1:
            return False
    return True


def raw_data_field_identification(begin_offset, end_offset, info_mutate_seed):
    for offset in range(begin_offset,end_offset):
        if check_all_value_is_1(offset,info_mutate_seed)==False:
            return False
    return True

def check_for_identy_subpace_for_enumeration(offset,info_mutate_seed,i,j):#for identy_subpace_for_enumeration
    for k in range(i,256):
        if k<j:
            if info_mutate_seed[offset]["coverage_similaty"][k]<info_mutate_seed[offset]["alpha"]:
                return False
        else:
            if info_mutate_seed[offset]["coverage_similaty"][k]>info_mutate_seed[offset]["alpha"]:
                return False
    return True

def identy_subpace_for_enumeration(offset,info_mutate_seed): #for enumeration_field_indentification
    for i in range(1,256):
        for j in range(i+1,256):
            if check_for_identy_subpace_for_enumeration(offset,info_mutate_seed,i,j):
                return True
    return False

def enumeration_field_indentification(begin_offset, end_offset, info_mutate_seed):
    for x in range(begin_offset,end_offset):
        if identy_subpace_for_enumeration(x,info_mutate_seed):
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

def loop_count_field_indentification(begin_offset, end_offset, info_mutate_seed):
    beta=7.355
    for x in range(begin_offset,end_offset):
        if variance_coverae_similaty(x,info_mutate_seed)<beta and average_frequency_difference(x,info_mutate_seed)>1:
            return True
    return False



def check_u_v_difference(offset,info_mutate_seed,index):#for identy_subpace
    for i in range(1,index):
        for j in range(i,index):
            if info_mutate_seed[offset]["coverage_similaty"][i]!=info_mutate_seed[offset]["coverage_similaty"][j]:
                return True
    return False

def check_other_value_lt_alpha(offset,info_mutate_seed,index):#for identy_subpace
    for i in range(index):
        if info_mutate_seed[offset]["coverage_similaty"][i]>info_mutate_seed[offset]["alpha"]:
            return False
    return True

def identy_subpace(offset,info_mutate_seed): #for offset_field_indentification and size_field_indentification
    for i in range(3,256):
        if check_u_v_difference(offset,info_mutate_seed,i) and check_other_value_lt_alpha(offset,info_mutate_seed,i):
            return True
    return False


def check_value_index0_lt_alpha(offset,info_mutate_seed):#for offset_field_indentification and size_field_indentification
    return info_mutate_seed[offset]["coverage_similaty"][0]>info_mutate_seed[offset]["alpha"]

def offset_field_indentification(begin_offset, end_offset, info_mutate_seed):
    for x in range(begin_offset,end_offset):
        if check_value_index0_lt_alpha(x,info_mutate_seed) and identy_subpace(x,info_mutate_seed):
            return True
    return False

def size_field_indentification(begin_offset, end_offset, info_mutate_seed):
    for x in range(begin_offset,end_offset):
        if not check_value_index0_lt_alpha(x,info_mutate_seed) and identy_subpace(x,info_mutate_seed):
            return True
    return False



