from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.process_event import ProcessExit
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from ptrace.debugger.memory_mapping import readProcessMappings
from signal import SIGTRAP, SIGINT, SIGSEGV, SIGABRT,SIGKILL
import os
from common import *
import logging
import struct
import shutil

class PythonPtraceTracer():
    def __init__(self, args=[], bbfile=""):
        self.bbinfo = self.load_bb_file(bbfile)
        self.dbg = PtraceDebugger()
        self.target_args = args
        self.pid=0
        self.filename=""
        self.input=open(args[-1],'rb').read()

    def create_and_attach_process(self, args):
        env = None
        args[0] = locateProgram(args[0])
        pid = createChild(args, True, env)
        self.pid=pid
        return self.dbg.addProcess(pid, True)

    def load_bb_file(self, bbfile):
        bb_info = {}
        bb = {}
        bb['full_path'] = ""
        fp = open(bbfile, "rb")

        file_rva_size = struct.unpack("<I", fp.read(4))[0]
        bb['rva_size'] = file_rva_size
        fname_sz = struct.unpack("<I", fp.read(4))[0]
        fname = fp.read(fname_sz).strip(b"\x00")

        while True:
            data = fp.read(12)
            if len(data) < 12:
                break
            voff, foff, instr_sz = struct.unpack("<III", data)
            instr = fp.read(instr_sz)
            bb[voff] = {}
            bb[voff]['faddr'] = foff
            bb[voff]['origin_byte'] = instr
        fp.close()

        bb_info[fname] = bb
        return bb_info



    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):
        info = self.bbinfo
        image_base_info={}
        process = self.create_and_attach_process(self.target_args)
        previous_block_info={}
        status = ExecStatus.NORMAL
        crash_info = ""
        edge_trace = []
        bb_list=[]
        while True:
            process.cont()
            try:
                signal = process.waitSignals()
            except ProcessExit:
                print("Catch ProcessExit!")
                break

            if signal.signum == SIGTRAP:
                print("Catch Trap!")
                map_mem = readProcessMappings(process)
                #print(map_mem)
                for fname in self.bbinfo:
                    self.filename=fname
                    #print(f"fname: {fname}" )
                    for m in map_mem:
                        #print(f"m: {m}")
                        #print(f"m.pathname: {m.pathname}")
                        if m.pathname and fname.decode() in m.pathname:
                            #print("dooooo")
                            #print(f"m.start: {m.start}")
                            #print(f"m.pathname: {m.pathname}")
                            #info[b'image_base'] = m.start
                            image_base_info.update({'image_base':m.start})
                            #image_base_info.update({'full_path':m.pathname})
                            #info[b'full_path'] = m.pathname
                            break
                
                ip = process.getInstrPointer()
                trap_addr = ip - 1
                offset = trap_addr - image_base_info['image_base']
                obyte = info[fname][offset]['origin_byte']
                '''
                if len(previous_block_info)!=0:
                    process.writeBytes(previous_block_info["trap_addr"],previous_block_info["obyte"])
                    edge=EdgeInfo(offset,previous_block_info["offset"])
                    if edge not in edge_trace:
                        edge_trace.append(edge)
                    else:
                        edge_trace[edge_trace.index(edge)].value+=1'''
                    
                process.writeBytes(trap_addr, obyte)
                process.setInstrPointer(trap_addr)
                '''previous_block_info["trap_addr"]=trap_addr
                previous_block_info["obyte"]=obyte
                previous_block_info["offset"]=offset'''
                edge_trace.append(offset)
                print(edge_trace)

            elif signal.signum == SIGSEGV:
                print(b"Catch SIGSEGV, Input: "+self.input)
                status = ExecStatus.CRASH
                #self.dbg.deleteProcess(process)
                process.terminate()
                return []
            elif signal.signum == SIGABRT:
                print(b"Catch SIGABRT Input: "+self.input)
                status = ExecStatus.ABORT
                #self.dbg.deleteProcess()
                process.terminate()
                return []
            else:
                print(b"Catch Signals:"+signal+b"Input: "+self.input)
                process.terminate()
                return []
                
        #self.dbg.deleteProcess(process)
        process.terminate()
        #self.dbg.quit()
        #process.detach()
        #del process
        #os.kill(self.pid,SIGKILL)
        return edge_trace

if __name__ == '__main__':
    file_to_fuzz="/home/lttn/Fuzzing/Target/patch/csawctf2020_roppity"
    bb_file_to_fuzz="/home/lttn/Fuzzing/Target/csawctf2020_roppity-bb.txt"
    tracer = PythonPtraceTracer([file_to_fuzz,"/home/lttn/Fuzzing/fuzzing-tool/input"], bb_file_to_fuzz)
    print("hehe")
    a=tracer.trace()
    print(a)
    c=0
    arr=[]
    for edge in a:
        c+=1
        arr.append([edge.from_bb,edge.to_bb])
    print(c)
    print(arr)


    #["/home/lttn/Downloads/lava/lava/bins/base64","/home/lttn/Downloads/lava/lava/bins/input"]