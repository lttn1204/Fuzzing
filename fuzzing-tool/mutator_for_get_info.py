class info_mutator():
    def __init__(self,seed):
        self.seed=open(seed,"rb").read()
        self.count=0
        self.idx=0
        self.is_done=False
        self.value=0
        self.is_new_idx=True

    def get_next_input(self):
        self.count+=1
        if self.count==256 and self.idx==len(self.seed)-1:
            self.is_done=True
        if self.count==257:
            self.is_new_idx=True
            self.count=0
            self.idx+=1
        self.seed=list(self.seed)
        self.value=(self.seed[self.idx]+1)%256
        self.seed[self.idx]=(self.seed[self.idx]+1)%256
        yield bytes(self.seed)
        
        
            
        


