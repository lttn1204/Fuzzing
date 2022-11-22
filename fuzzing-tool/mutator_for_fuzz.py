import os
from itertools import *
import random


# Assertion_field_identification
#array_profile: Coverage similaty value of field (2-dimensional arrays with sub array is Coverage similaty of 1 byte)
class Mutator:
    def __init__(self,seed,info)
        self.seed=open(seed,"rb").read()
        self.info=info
        sefl.Assertion_field={}
        sefl.Raw_data_field={}
        sefl.Enumeration_field={}
        sefl.Loop_count_field={}
        sefl.Offset_field={}
        sefl.Size_field={}s

    def Assertion_field_identification(field,array_profile,midrange_value):
        for array_value in array_profile:
            if array_value.count(1)!=1:
                return False
            tmp_count=0
            for value in array_value:
                if value<midrange_value:
                t   mp_count+=1
            if tmp_count<254:
                return False
        return True

    # Raw data identification 
    #array_profile: Coverage similaty value of field (2-dimensional arrays with sub array is Coverage similaty of 1 byte)
    def Raw_data_field_identification(field,array_profile,midrange_value):
        for array_value in array_profile:
            for value in array_value:
                if value<1:
                    return False
        return True

    #Identification Enumeration field
    #array_profile: Coverage similaty value of field (2-dimensional arrays with sub array is Coverage similaty of 1 byte)
    def Enumeration_field_identification(field,array_profile,midrange_value):
        for array_value in array_profile:
            tmp_value_count=0
            tmp_len_count=0
            for value in array_value:
                f value>midrange_value:
                    tmp_value_count+=midrange_value
                    tmp_len_count+=1
            if tmp_len_count>1 or tmp_value_count<8:
                return True
        return False

    #Funtion for Loop_count_field_identification
    def Variance(arr):
        result=0
        tmp=arr[0]
        for i in arr[1:]:
            result+=abs(tmp-i)
        return result

    #Funtion for Loop_count_field_identification
    def Average(arr):
        result=sum(arr)
        return result//len(arr)

    #Identification Loop count  field
    #array_profile_FS: Coverage similaty value of field (2-dimensional arrays with sub array is Coverage similaty of 1 byte)
    #array_profile_FD frequency difference value of field (2-dimensional arrays with sub array is frequency difference of 1 byte)
    def Loop_count_field_identification(field,array_profile_FS,array_profile_FD,midrange_value,beta_value):
        check=0
        for i in range(len(array_profile_FS)):
            if Variance(array_profile_FS[i])<beta_value and Average(array_profile_FD[i])>1:
                return True

    #Funtion for Offset_field_identification and Size_field_identification
    def check_all_value_bigger_than_t(t,array,midrange_value):
        for i in range(t+1,256):
            if array[i]<midrange_value:
                return False
        return True
    #Sub Funtion for Offset_field_identification and Size_field_identification

    def Search_u_and_v_for_t(t,array_value,midrange_value):
        for u in range(t):
            for v in range(t):
                if u!=v and array_value[u]!=array_value[v]:
                    return True
        return False

    #Identification Offset field
    #array_profile_FS: Coverage similaty value of field (2-dimensional arrays with sub array is Coverage similaty of 1 byte)
    def Offset_field_identification(field,array_profile,midrange_value):
        for array_value in array_profile:
            if array_value[0]<midrange_value:
                return False
            for t in range(256):
                if not check_all_value_bigger_than_t(t,array_value,midrange_value) or not Search_u_and_v_for_t(t,array_value,midrange_value):
                    return False
        return True

    #Identification Size field
    #array_profile_FS: Coverage similaty value of field (2-dimensional arrays with sub array is Coverage similaty of 1 byte)
    #Seem like Offset_field_identification but in byte 0 coverage similaty must be 0
    def Size_field_identification(field,array_profile,midrange_value):
        for array_value in array_profile:
            if array_value[0]!=0:
                return False
            for t in range(256):
                if check_all_value_bigger_than_t(t,array_value,midrange_value) and Search_u_and_v_for_t(t,array_value,midrange_value):
                    return True
        return False

    #return value "decimal" from sequence of bytes
    def Parse_value_from_bytes():
        return 0

    #return sequence bytes from deciaml value
    def Parse_bytes_from_value():
        return 0

    #For assertion field random mutation
    #Random mutation
    def Assertion_field_mutaion(begin_index,end_index,seed,number_of_mutation):
        result=[]
        store=[seed[0:begin_index],seed[end_index:]]
        size=begin_index-end_index
        original_value=Parse_value_from_bytes(seed[begin_index:end_index])
        for i in range(number_of_mutation):
            mutation_value=original_value+random.randint(number_of_mutation*2,number_of_mutation*10)
            mutation_bytes=Parse_bytes_from_value(mutation_value)
        r   esult.append(store[0]+mutation_bytes+store[1])
        return result 

    def Enumeration_field_mutaion():
        return 0

    def Loop_count_field_mutaion():
        return 0

    def Offset_field_mutaion(begin_index,end_index,seed,max_len,max_value):
        result=[]
        store=[seed[0:begin_index],seed[end_index:]]
        arr_for_max_value=[bytes([x]) for x in range(max_value)]
        append_len=max_len-(begin_index-end_index)
        for i in product(arr_for_max_value,repeat=max_len):
            value=b''.join(i)
            value=value.strip(b'\x00')
            #For Size field mutation append bytes in the end of field
            random_append=os.urandm(len(value))
            mutation_value=store[0]+seed[begin_index:end_index]+value+random_append+store[1]
            result.append(mutation_value)
    
    # Mutaion Size Field
    def Size_field_mutaion(begin_index,end_index,seed,max_len,max_value):
        result=[]
        store=[seed[0:begin_index],seed[end_index:]]
        arr_for_max_value=[bytes([x]) for x in range(max_value)]
        append_len=max_len-(begin_index-end_index)
        for i in product(arr_for_max_value,repeat=max_len):
            value=b''.join(i)
            value=value.strip(b'\x00')
            #For Size field mutation append bytes in the end of field
            random_append=os.urandm(len(value))
            mutation_value=store[0]+seed[begin_index:end_index]+random_append+store[1]+value
            result.append(mutation_value)

    # Do not mutation raw data field
    def Raw_data_field_mutaion():
        pass

