from unicorn import *
from unicorn.x86_const import *
import volatility.debug as debug
import volatility.plugins.ropmemu.disass as disass
from collections import OrderedDict


regs_to_code = {
          "EAX"    : UC_X86_REG_EAX,
          "EBP"    : UC_X86_REG_EBP,
          "EBX"    : UC_X86_REG_EBX,
          "ECX"    : UC_X86_REG_ECX,
          "EDI"    : UC_X86_REG_EDI,
          "EDX"    : UC_X86_REG_EDX,
          "EFLAGS" : UC_X86_REG_EFLAGS,
          "ESI"    : UC_X86_REG_ESI,
          "RAX"    : UC_X86_REG_RAX,
          "RBP"    : UC_X86_REG_RBP,
          "RBX"    : UC_X86_REG_RBX,
          "RCX"    : UC_X86_REG_RCX,
          "RDI"    : UC_X86_REG_RDI,
          "RDX"    : UC_X86_REG_RDX,
          "RSI"    : UC_X86_REG_RSI,
          "RSP"    : UC_X86_REG_RSP,
          "RIP"    : UC_X86_REG_RIP,
          "ESP"    : UC_X86_REG_ESP,
          "EIP"    : UC_X86_REG_EIP,
          "R8"     : UC_X86_REG_R8,
          "R9"     : UC_X86_REG_R9,
          "R10"    : UC_X86_REG_R10,
          "R11"    : UC_X86_REG_R11,
          "R12"    : UC_X86_REG_R12,
          "R13"    : UC_X86_REG_R13,
          "R14"    : UC_X86_REG_R14,
          "R15"    : UC_X86_REG_R15
          }

code_to_regs = {
      UC_X86_REG_EAX    :         "EAX",
      UC_X86_REG_EBP    :         "EBP",
      UC_X86_REG_EBX    :         "EBX",
      UC_X86_REG_ECX    :         "ECX",
      UC_X86_REG_EDI    :         "EDI",
      UC_X86_REG_EDX    :         "EDX",
      UC_X86_REG_EFLAGS :         "EFLAGS",
      UC_X86_REG_ESI    :         "ESI",
      UC_X86_REG_RAX    :         "RAX",
      UC_X86_REG_RBP    :         "RBP",
      UC_X86_REG_RBX    :         "RBX",
      UC_X86_REG_RCX    :         "RCX",
      UC_X86_REG_RDI    :         "RDI",
      UC_X86_REG_RDX    :         "RDX",
      UC_X86_REG_RSI    :         "RSI",
      UC_X86_REG_RSP    :         "RSP",
      UC_X86_REG_RIP    :         "RIP",
      UC_X86_REG_ESP    :         "ESP",
      UC_X86_REG_EIP    :         "EIP",
      UC_X86_REG_R8     :         "R8" ,
      UC_X86_REG_R9     :         "R9" ,
      UC_X86_REG_R10    :         "R10",
      UC_X86_REG_R11    :         "R11",
      UC_X86_REG_R12    :         "R12",
      UC_X86_REG_R13    :         "R13",
      UC_X86_REG_R14    :         "R14",
      UC_X86_REG_R15    :         "R15"
      }

all_my_registers = [UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_EDX, 
        UC_X86_REG_EFLAGS, UC_X86_REG_ESI, UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDI,
        UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
        UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_RSP, UC_X86_REG_ESP, UC_X86_REG_RIP, UC_X86_REG_EIP]

all_my_regs32 = [UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_EDX, 
        UC_X86_REG_EFLAGS, UC_X86_REG_ESI]


class Emulator:
    '''Unicorn Emulator'''
    ### Constructor - TODO: be more generic
    def __init__(self, dump, code, stack, gcounter):
        self.gcounter = gcounter
        code = int(code, 16)
        stack = int(stack, 16)
        self.fix = 2**64
        self.mask = 0xFFFFFFFFFFFFF000
        self.mappings = []
        self.unicorn_code = code
        self.unicorn_stack = stack
        # shadow stack for this emulator instance
        self.shadow = OrderedDict()
        debug.debug("[emulator] - init unicorn...")
        # Volatility interaction
        self.dump = dump
        self.current_ip = code
        # TODO: support other archs and modes
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        #size = 128 * 1024 * 1024
        size = 1 * 4096
        # unicorn code
        self.mu.mem_map(code & self.mask, size)
        self.mappings.append((code, size))
        #size = 256 * 1024 * 1024 
        size = 10 * 4096
        # unicorn generic stack
        self.mu.mem_map(stack & self.mask, size)
        self.mappings.append((stack, size))
        self.set_hooks()
        self.branch_point = []


    ### Writing and mapping methods
    def mapped(self, address):
        debug.debug("[mapped] - checking address: %x" % address)
        for addr, s in self.mappings:
            if address >= addr and address <= (addr + s):
                return True
        return False

    def mmap(self, address):
        size = 32 * 1024
        debug.debug("[mmap] - mapping: (%x, %x)" % (address, size))
        address_page = address & self.mask
        debug.debug("[mmap] - addr_page: %x" % address_page)
        self.mu.mem_map(address_page, size)
        self.mappings.append((address_page, size))

    def write_data(self, address, content):
        address = int(address, 16)
        if not self.mapped(address):
            self.mmap(address)
        debug.debug("[write_data] - at address: %x" % address)
        debug.debug(repr(content))
        self.mu.mem_write(address, content)

    ### Emulation
    def emu(self, size):
        ip = int(self.get_ip(), 16)
        debug.debug("[emu] - (%x, %x)" % (ip, size))
        try:
            self.mu.emu_start(ip, ip + size, timeout=10000, count=1)
        except UcError as e:
            debug.debug("Error %s" % e)

            
    ### Hooks
    def set_hooks(self):
        debug.debug("[emulator] - setting hooks...")
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.mu.hook_add(UC_HOOK_MEM_READ, self.hook_mem_access)
        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)
               
    # callback for tracing memory access (READ or WRITE)
    def hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE: 
            debug.debug("[hook_mem_access] - write operation - %x %x %x" % (address, size, value))
            self.shadow[hex(address).strip("L")] = hex(value).strip("L")
        else:
            debug.debug("[hook_mem_access] - read operation - %x %x %x" % (address, size, value))
        return True

    # callback for tracing invalid memory access (READ or WRITE)
    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        debug.debug("[hook_mem_invalid] - address: %x" % address)
        if access == UC_MEM_WRITE_UNMAPPED:
            debug.debug(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
            self.shadow[hex(address).strip("L")] = hex(value).strip("L")
        else:
            debug.debug(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
        return True

    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        debug.debug("[hook_mem_fetch_unmapped] - address: (%lx, %x) " % (address, size))
        # update ip
        next_ip = self.unicorn_code + size
        self.mu.reg_write(UC_X86_REG_RIP, next_ip) 
        D = disass.Disass(self.dump)
        # for the format - always deal with strings - internally int
        address = hex(address).strip("L")
        # we need to disass to get instructions/content
        D.get_gadget(address, 1)
        self.mu.mem_write(next_ip, D.total_content)
        self.set_ip(address) 
        return True


    ### Registers
    def reset_regs(self):
        for index in all_my_registers:
            self.mu.reg_write(index, 0x0)

    def set_registers(self, registers):
        debug.debug("[set_registers]")
        if not registers:
            self.reset_regs()
            return
        for reg_index, reg_value in registers.items():
            self.mu.reg_write(regs_to_code[reg_index], long(str(reg_value), 16))
            debug.debug("%s: %x" % (reg_index, int(reg_value, 16)))

    def dump_registers(self):
        regs = OrderedDict()
        for index in all_my_registers:
            r_value = self.mu.reg_read(index)
            if r_value < 0: r_value += 2**64
            r_value = hex(r_value).strip("L")
            regs[code_to_regs[index]] = r_value
        return regs

    def show_registers(self):
        print "[--- registers ---]"
        print "RIP: %x" % (self.mu.reg_read(UC_X86_REG_RIP))
        print "RSP: %x" % (self.mu.reg_read(UC_X86_REG_RSP))
        print "RBP: %x" % (self.mu.reg_read(UC_X86_REG_RBP))
        print "RAX: %x" % (self.mu.reg_read(UC_X86_REG_RAX))
        print "RBX: %x" % self.mu.reg_read(UC_X86_REG_RBX)
        print "RCX: %x" % self.mu.reg_read(UC_X86_REG_RCX)
        print "RDX: %x" % self.mu.reg_read(UC_X86_REG_RDX)
        print "RSI: %x" % self.mu.reg_read(UC_X86_REG_RSI)
        print "RDI: %x" % self.mu.reg_read(UC_X86_REG_RDI)
        print "R8:  %x" % self.mu.reg_read(UC_X86_REG_R8)
        print "R9:  %x" % self.mu.reg_read(UC_X86_REG_R9)
        print "R10: %x" % self.mu.reg_read(UC_X86_REG_R10)
        print "R11: %x" % self.mu.reg_read(UC_X86_REG_R11)
        print "R12: %x" % self.mu.reg_read(UC_X86_REG_R12)
        print "R13: %x" % self.mu.reg_read(UC_X86_REG_R13)
        print "R14: %x" % self.mu.reg_read(UC_X86_REG_R14)
        print "R15: %x" % self.mu.reg_read(UC_X86_REG_R15)
        print "EFLAGS: %x" % self.mu.reg_read(UC_X86_REG_EFLAGS) 

    # input: string
    def set_sp(self, sp):
        sp = int(sp, 16)
        self.mu.reg_write(UC_X86_REG_RSP, sp)

    # input: string
    def set_ip(self, ip):
        ip = int(ip, 16)
        self.mu.reg_write(UC_X86_REG_RIP, ip)
    
    # output: string
    def get_sp(self):
        sp = (self.mu.reg_read(UC_X86_REG_RSP) + self.fix)
        return hex(sp).strip("L")
        
    # output: string
    def get_ip(self):
        rip = (self.mu.reg_read(UC_X86_REG_RIP) + self.fix)
        return hex(rip).strip("L")


    # Multipath
    def clear_zf(self):
        eflags_cur = self.mu.reg_read(UC_X86_REG_EFLAGS)
        eflags = eflags_cur & ~(1 << 6)
        #eflags = 0xc0d0
        print "[clear_zf] - eflags from %x to %x" % (eflags_cur, eflags)
        if eflags != eflags_cur:
            print "[clear_zf] - writing new eflags..."
            self.mu.reg_write(UC_X86_REG_EFLAGS, eflags)

    def set_zf(self):
        eflags_cur = self.mu.reg_read(UC_X86_REG_EFLAGS)
        eflags = eflags_cur | (1 << 6)
        #eflags = 0xFFFFFFFF
        print "[set_zf] - eflags from %x to %x" % (eflags_cur, eflags)
        if eflags != eflags_cur:
            print "[set_zf] - writing new eflags..."
            self.mu.reg_write(UC_X86_REG_EFLAGS, eflags)

    def handle_zf(self, zf): 
        print "[handle_zf] - ZF " , zf 
        #key = "%s-%s" % (hex(self.pre_sp - 0x08).strip("L"), self.gcounter)
        key = "%s-%s"  % (self.get_sp(), self.gcounter) 
        self.branch_point.append(key)
        self.branch_point.append(zf)
        if zf == 0: self.clear_zf()
        else: self.set_zf()

    def multipath(self):
        #print "-"*11
        sp = self.get_sp() 
        print "[multipath] - %s" % self.current_txt_instr
        print "[multipath] - sp: " , sp
        rsp = self.mu.reg_read(UC_X86_REG_RSP)
        print "RSP " , hex(rsp)
        data = str(self.mu.mem_read(self.current_sp, 0x40)) 
        #print repr(data)
        if len(self.zflags.keys()) == 1 and self.zflags.keys()[0] == "default":
            #print "[multipath] - handling ZF (%s) - default" % self.zflags.values()[0]
            self.handle_zf(int(self.zflags.values()[0], 16)) 
        else:
            if sp in self.zflags.keys():
                #print "[multipath] - handling ZF (%s) for SP %s" % (self.zflags[sp], sp)
                self.handle_zf(int(self.zflags[sp]))
