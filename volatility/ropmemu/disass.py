from capstone import *
from capstone.x86 import *
import volatility.debug as debug

class Disass:    
    def __init__(self, dump):
        self.md = self.init_capstone()    
        self.md.detail = True
        self.branch = [X86_GRP_JUMP, X86_GRP_INT, X86_GRP_CALL, X86_GRP_RET, X86_GRP_IRET, X86_GRP_VM]
        # Volatility interaction
        self.dump = dump
        self.total_content = ""
        self.total_size = ""
        self.gadget_instructions = []
        self.current_instruction = ""
        self.ret = 0

    # x86 support only - TODO: be more generic
    def get_cap_arch(self):
        return CS_ARCH_X86

    # x86-64 - TODO: be more generic
    def get_cap_mode(self):
        return CS_MODE_64

    def init_capstone(self):
        return Cs(self.get_cap_arch(), self.get_cap_mode())

    #TODO: be more generic
    def get_buf_size(self):
        return 64
    
    def get_gadget_data(self, address):
        debug.debug("[get_gadget_data] - address: %x" % address)
        return self.dump.read(address, self.get_buf_size())

    def get_gadget(self, address, state): 
        def is_capstone_branch(ins):
            for m in ins.groups:
                if m in self.branch: return True
            return False  
        address = int(address, 16)
        debug.debug("[get_gadget] address: %x" % address)
        data = self.get_gadget_data(address)
        gadget = []
        final_addr = address
        for ins in self.md.disasm(data, address):
            instr = "%s %s" % (ins.mnemonic, ins.op_str)
            final_addr += ins.size
            if state == 0: print "\t | 0x%x \t| %s " % (ins.address, instr)
            gadget.append((str(ins.bytes), ins.size))
            self.gadget_instructions.append(instr)
            if is_capstone_branch(ins): break
        if "ret" in instr: self.ret = (final_addr - ins.size)
        return gadget
 
    def get_gadget_content(self):
        self.total_content = ""
        self.total_size = ""
        for i in self.gadget:
            content, size = i[0], i[1]
            self.total_content += content
            self.total_size += size

    def dis(self, content, addr):
        addr = int(addr, 16)
        i = self.md.disasm(content, addr).next()
        instr = "%s %s" % (i.mnemonic, i.op_str)
        return instr
