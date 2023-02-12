import os

class Radamsa_mutator():
    def __init__(self,radamsa_path):
        self.radamsa_path=radamsa_path
    def mutate(self,input_path):
        self.input_path=input_path
        self.head, self.tail = os.path.split(input_path)
        self.output_path=self.head+"/tmp"
        os.system(self.radamsa_path+" "+self.input_path+" -o "+self.output_path)
        

