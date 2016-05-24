# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Mariano `emdel` Graziano
@license:      GNU General Public License 2.0 or later
@contact:      magrazia@cisco.com
@organization: Cisco Systems, Inc.
"""


import volatility.commands as commands
import volatility.utils as utils
from collections import OrderedDict
import os, struct, json, gzip, subprocess, base64
from capstone import *
from capstone.x86 import *
import volatility.debug as debug

REG_SUFFIXS = {}
REG_SUFFIXS['x64'] = ['b', 'w', 'd']
MATH_OPS = ['+', '-', '*', '/']

GPRS = {}
GPRS['x64'] = ['RAX', 'RBX', 'RCX', 'RDX', 'RBP', 'RSP', 'RIP', 'RSI', 'RDI',
               'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
GPRS['x86'] = ['EAX', 'EBX', 'ECX', 'EDX', 'EBP', 'ESP', 'EIP', 'ESI', 'EDI']

class unchain(commands.Command):
    '''unchain: Volatility Plugin in the ROPMEMU framework.
       It's a chain extractor and shaper. Run dust.sh on the output.
    ''' 
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        self._config.add_option('BIN', short_option = 'B', default = None, help = 'Filename for the dumped chain', action = 'store', type = 'str')
        self._config.add_option('MODE', short_option = 'm', default = 'x64', help = 'Modes: x86 and x64', action = 'store', type = 'str') 
        self._config.add_option('IJSON', short_option = 'i', default = None, help = 'JSON Trace Input file', action = 'store', type = 'str')
        self._config.add_option('GLIMIT', short_option = 'G', default = None, help = 'Gadget Limit Number', action = 'store', type = 'int') 
        self._config.add_option('CLEAN', short_option = 'C',  dest="clean", default = False, action="store_true", help="Clean /tmp files")  
        self._config.add_option('DB', short_option = 'D', default = None, action="store", help="Filename for the opcode DB", type = 'str')
        self._config.add_option('SGADGET', short_option = 'S', default = -1, action="store", help="Starting gadget for emulation", type = 'int') 
        self._config.add_option('IDB', short_option = 'I', default = None, action="store", help="Input opcodes DB", type = 'str')
        self.dump_fd = 0
        self.gid = 0
        self.md = None
        self.WHITELIST_INSTRUCTIONS = ['mov', 'pop', 'add', 'sub', 'xor', 'pushf']
        self.BLACKLIST_INSTRUCTIONS = ['ret', 'call', 'leave']
        self.GREYLIST_INSTRUCTIONS = []
        self.trace = OrderedDict()
        self.opcodes_db = OrderedDict()
        self.NASM = '/usr/bin/nasm'
        self.branch = [X86_GRP_JUMP, X86_GRP_INT, X86_GRP_CALL, X86_GRP_RET, X86_GRP_IRET, X86_GRP_VM]

    def get_buf_size(self):
        if self._config.MODE == 'x64': return 64
        else: return 32

    def get_word_size(self):
        if self._config.MODE == 'x64': return 0x08
        else: return 0x04

    def get_unpack_format(self):
        if self._config.MODE == 'x64': return '<Q'
        else: return '<I'
 
    def is_reg(self, o):
        if o in GPRS[self.mode]: return True
        return False

    # TODO: Pay attention. Not always 0x... 
    # TODO: Abstract disass library
    def is_constant(self, o): 
        if o.startswith('0x'): return True
        return False

    # TODO
    def is_mem(self, o): 
        return False

    def check_arg(self, arg): 
        ''' 1: reg, 2: const, 3: mem '''
        if self.is_reg(arg):
            return 1

        if self.is_constant(arg):
            return 2

        if self.is_mem(arg):
            return 3
        return None   
 
    # We support only x86 arch
    def get_cap_arch(self):
        return CS_ARCH_X86

    # We support two x86 modes: x86 and x64
    def get_cap_mode(self):
        if self._config.MODE == 'x64': return CS_MODE_64
        else: return CS_MODE_32

    def init_capstone(self):
        return Cs(self.get_cap_arch(), self.get_cap_mode())

    def get_json_trace(self):
        SUPPORTED_EXT = ['json', 'gz']
        ext = self._config.IJSON.split('.')[-1]
        if ext.lower() not in SUPPORTED_EXT: 
            self.trace = None
            return
        print "[+] Getting %s" % self._config.IJSON
        if ext.lower() == 'gz':
            gf = gzip.open(self._config.IJSON)
            self.trace = json.loads(gf.read(), object_pairs_hook = OrderedDict)
            gf.close()
        else:
            jf = open(self._config.IJSON)
            self.trace = json.load(jf, object_pairs_hook = OrderedDict)
            jf.close()

    def sanitize_capstone_mov(self, ins):
        if 'qword ptr' in ins:
            return ins.replace(' qword ptr', '')
        else: return ins

    def get_chain_instruction(self, chain_ins):
        ins = chain_ins[1]
        if ins.startswith('mov'):
            ins = self.sanitize_capstone_mov(ins)
        return ins

    def is_in_trace(self, chain_ptr, chain_gnum, c_ins):
        for trace_key1, trace_c1 in self.trace.items():
            trace_ptr, trace_gnum = trace_key1.split('-')
            if trace_ptr != chain_ptr: continue
            for trace_key2, trace_c2 in trace_c1.items():
                if c_ins in [tk.lower() for tk in trace_c2.keys()]:
                    debug.debug("%s %s %s %s %s" % (chain_ptr, chain_gnum, trace_ptr, trace_gnum, c_ins))
                    return True
        return False

    def get_trace_asm(self):
        '''Debugging function'''
        debug.debug("Trace ASM")
        gnum = 0 
        stop = 0 
        for k1, v1 in self.trace.items():
            if self._config.GLIMIT:
                if gnum > self._config.GLIMIT: stop = 1 
            gnum += 1
            if stop == 1: break
            for k2, v2 in v1.items():
                for k3, v3 in v2.items():
                    print k3.lower() 

    def is_trace_sync(self, ptr, num, instr): 
        for trace_key1, trace_c1 in self.trace.items():
            trace_ptr, trace_gnum = trace_key1.split('-')
            if trace_ptr != ptr: continue
            for trace_key2, trace_c2 in trace_c1.items():
                if instr in [tk.lower() for tk in trace_c2.keys()]:
                    debug.debug("%s %s %s %s %s" % (ptr, num, trace_ptr, trace_gnum, instr))
                    if num == trace_gnum:
                        return True
        return False

    def get_instruction_context(self, gadget, instruction):
        for k1, v1 in gadget.items():
            for k2, v2 in v1.items():
                if k2.lower() == instruction:
                    return v2
        return None

    def get_context_from_trace(self, gkey, instruction):
        ptr, num = gkey.split('-')
        if self.is_in_trace(ptr, num, instruction):
            if self.is_trace_sync(ptr, num, instruction):
                return self.get_instruction_context(self.trace[gkey], instruction)
        return None

    # TODO: Fix this stupid upper/lower issue due to distorm/capstone usage 
    def get_reg_value(self, hw_context, pop_operand):
        return hw_context[pop_operand.upper()]

    def mov_from_pop(self, instruction, gkey):
        hw_context = self.get_context_from_trace(gkey, instruction)
        if hw_context:
            pop_operand = instruction.split(' ')[-1]
            value = self.get_reg_value(hw_context, pop_operand)
            new_instr = "mov %s, %s" % (pop_operand, value)
            return new_instr 

    def get_bits_directive(self):
        if self._config.MODE == 'x64': return "[BITS 64]"
        else: return "[BITS 32]"

    def create_tmp_file(self, new_instr, cnt):
        # http://www.nasm.us/doc/nasmdoc7.html
        if not os.path.exists("/tmp/ropmemu"):
            os.makedirs("/tmp/ropmemu")
        filename = "%s_%d%s" % ("/tmp/ropmemu/ropmemu", cnt, ".asm")
        fd = open(filename, "w")
        bits = self.get_bits_directive()
        fd.write("%s\n" % bits)
        fd.write("%s" % new_instr)
        fd.close()

    def get_nasm(self, cnt):
        progname = "%s_%d" % ("/tmp/ropmemu/ropmemu", cnt)
        h = open(progname)
        return h.read()

    def get_nasm_hex(self, buf):
        content = ''
        for x in xrange(0, len(buf)):
            content += "".join(hex(ord(str(buf[x])))[2:4])
        return content

    def rm_nasm_files(self):
        print "[+] Removing /tmp files"
        for r, d, f in os.walk("/tmp/ropmemu"):
            # removing files
            for i in f:
                os.remove(os.path.join('/tmp/ropmemu', i))
        # removing empty dir
        os.rmdir("/tmp/ropmemu")    

    def invoke_nasm(self, cnt):
        # http://stackoverflow.com/questions/26504930/recieving-32-bit-registers-from-64-bit-nasm-code
        filename = "%s_%d%s" % ("/tmp/ropmemu/ropmemu", cnt, ".asm")
        progname = "%s_%d" % ("/tmp/ropmemu/ropmemu", cnt)
        pargs = [self.NASM, '-O0', '-f', 'bin', filename, '-o', progname]     
        if not subprocess.call(pargs):
            buf = self.get_nasm(cnt)
            if self._config.DEBUG: buf_hex = self.get_nasm_hex(buf)
            return buf 
   
    def get_opcodes(self, new_instr, cnt):
        self.create_tmp_file(new_instr, cnt)
        return self.invoke_nasm(cnt)   

    def is_nasm(self):
        if os.path.exists(self.NASM): return True
        else: return False

    def is_capstone_branch(self, ins):
        for m in ins.groups:
            if m in self.branch:
                return True
        return False

    # call reg -> jmp addr | jmp reg -> jmp val
    def shape_rop_jmpcall(self, instruction, hw_context):
        reg = instruction.split()[1]
        val = hw_context[instruction.upper()][reg.upper()]
        new_instruction = "%s %s" % ("jmp", val)
        debug.debug("From %s to %s" % (instruction, new_instruction))
        return new_instruction

    def check_branch_instruction(self, instruction, hw_context):
        if instruction.startswith('call'):
            return self.shape_rop_jmpcall(instruction, hw_context)
        elif instruction.startswith('jmp'):
            return self.shape_rop_jmpcall(instruction, hw_context)

    def build_mov_from_pop(self, instruction, reg, hw_context):
        val = hw_context[instruction][reg.upper()] 
        new_instr = "mov %s, %s" % (reg, val)
        return new_instr

    def get_nasm_size_fmt(self):
        if self._config.MODE == 'x64': return "qword"
        else: return "dword"

    # TODO: Think about a clever method
    def sanitize_reg(self, op):
        ''' Register sanitiziation, e.g. 'R8D' -> R8'''
        for x in REG_SUFFIXS[self._config.MODE]:
            if op.endswith(x):
                return op[:-1]
        if self._config.MODE == 'x64':
            if op.startswith('e'):
                x64_op = "%s%s" % ('r', op[1:])
                return x64_op 
        return op 

    def upper_capstone(self, instr):
        return instr.upper().replace("0X", "0x")

    def get_size(self):
        if self.mode == 'x64': return 0x08
        elif self.mode == 'x86': return 0x04
        else: raise

    def read_value(self, addr):
        print "[read_value] - " , addr
        if self._config.MODE == 'x64':
            raw = self._addrspace.read(addr, self.get_size())
            return struct.unpack('<Q', raw)[0]
        elif self._config._MODE == 'x86': 
            raw = self._addrspace.read(addr, self.get_size())
            return struct.unpack('<I', raw)[0]
        else:
            raise RuntimeError("Mode not supported.")
 
    def expand_mov(self, instruction, dst, src, hw_context):
        if src.startswith('['):
            # TODO: Have a real parser. /!\ eval() is dangerous
            expression = src[1:-1]
            args = expression
            exp = 0
            for op in MATH_OPS:
                if op in expression:
                    math = op
                    exp = 1
                    args = expression.split(op)
                    break
            if exp == 1:
                arg1 = args[0]
                arg2 = args[1]
                arg2_type = self.check_arg(self.upper_capstone(arg2))
                if arg2_type == 1: 
                    arg2 = hw_context[self.upper_capstone(instruction)][self.upper_capstone(arg2)]
                arg1_type = self.check_arg(self.upper_capstone(arg1))
                if arg1_type == 1:
                    arg1 = hw_context[self.upper_capstone(instruction)][self.upper_capstone(arg1)]
                solve = "%s%s%s" % (arg1, math, arg2)
                mem_addr = "%x" % eval(solve)
                val = hex(self.read_value(int(mem_addr, 16))).strip('L')
            else:
                # It's from the trace, we have already read the value, so it's
                # the correct one.
                val = hw_context[self.upper_capstone(instruction)][self.upper_capstone(args)]
        else:
            #val = hw_context[self.upper_capstone(instruction)][self.upper_capstone(src)]
            val = hw_context[instruction][src.upper()]
        fmt = self.get_nasm_size_fmt()
        if dst.startswith('['):
            # we need to append a new instruction
            prev_instruction = "mov %s, %s" % (src, val)
            new_instruction = "%s\nmov %s %s, %s" % (prev_instruction, fmt, dst, src)
            return new_instruction
        new_instruction = "mov %s %s, %s" % (fmt, dst, val)
        return new_instruction

    def check_normal_instruction(self, instruction, hw_context):
        if instruction == "pushf": return instruction
        mnemonic, operands = instruction.split(' ', 1)
        ops = operands.split(',')
        if mnemonic == 'pop':
            return self.build_mov_from_pop(instruction, ops[0], hw_context)
        elif mnemonic == 'mov':
           #src = self.sanitize_reg(instruction.split(',')[1].strip().upper())
           src = self.sanitize_reg(instruction.split(',')[1].strip())
           dst_raw = instruction.split(',')[0].split()[-1].strip()
           dst = dst_raw
           if not dst_raw.startswith('['):
               #dst = self.sanitize_reg(dst_raw.upper())
               dst = self.sanitize_reg(dst_raw)
           return self.expand_mov(instruction, dst, src, hw_context) 
        return None        

    def add_get_opcodes(self, new_instr, instruction, cnt): 
            if new_instr not in self.opcodes_db:
                self.opcodes_db[new_instr] = None
                opcodes = self.get_opcodes(new_instr, cnt)
                # For the DB project - b64 based
                self.opcodes_db[new_instr] = base64.b64encode(opcodes)
                debug.debug("%s (%s) -- %s" % (new_instr, instruction, self.get_nasm_hex(opcodes)))
                return opcodes
            opcodes = base64.b64decode(self.opcodes_db[new_instr])
            debug.debug("%s (%s) -- %s" % (new_instr, instruction, self.get_nasm_hex(opcodes)))
            return opcodes

    def append_mnemonic_instruction_lists(self, instruction):
        mnemonic = instruction.split()[0]
        if mnemonic != "jmp" and mnemonic.startswith("j"):
            self.GREYLIST_INSTRUCTIONS.append(mnemonic)
            return True
        self.BLACKLIST_INSTRUCTIONS.append(mnemonic)
        return False

    def check_trace_instruction(self, address, instruction, hw_context, cnt):
        print "[INPUT] %s) %s" % (str(cnt), instruction)
        if instruction.split()[0] in self.BLACKLIST_INSTRUCTIONS: return None 
        if instruction.split()[0] in self.WHITELIST_INSTRUCTIONS:
            new_instr = self.check_normal_instruction(instruction, hw_context)
            if not new_instr:
                new_instr = instruction 
            print "[OUTPUT] " , new_instr
            opcodes = self.add_get_opcodes(new_instr, instruction, cnt)
            return opcodes       
        #self.serialize_opcodes() 
        addr = int(address, 16)
        data = self._addrspace.read(addr, self.get_buf_size())
        print "---[NEW  " , instruction
        if not data: 
            print "[-] Something went wrong. Missing instruction: %s" % instruction
            return
        for ins in self.md.disasm(data, addr):
            if self.is_capstone_branch(ins):
                if not self.append_mnemonic_instruction_lists(instruction): return None
                new_instruction = self.check_branch_instruction(instruction, hw_context)
                print "[OUTPUT] %s" % new_instruction
                opcodes = self.get_opcodes(new_instruction, cnt)
                print self.get_nasm_hex(opcodes)
                debug.debug("%s -- %s" % (new_instruction, self.get_nasm_hex(opcodes)))
                return opcodes

    def init_chain_dump(self):
        name = "%s" % self._config.BIN
        print "[+] Creating %s" % name
        self.dump_fd = open(name, 'wb')

    def stop_chain_dump(self):
        self.dump_fd.close()
        if self._config.CLEAN: self.rm_nasm_files()

    def append_opcodes_dump(self, opcodes):
        self.dump_fd.write(opcodes)

    def init_opcodes_db(self):
        if self._config.IDB:
            idb_fd = open(self._config.IDB)
            self.opcodes_db = json.load(idb_fd, object_pairs_hook = OrderedDict)
            idb_fd.close()

    def follow_trace(self):
        cnt = 0
        self.init_chain_dump()
        self.init_opcodes_db()
        for trace_key1, trace_c1 in self.trace.items(): 
            trace_ptr, trace_gnum = trace_key1.split('-')
            if self._config.GLIMIT and int(trace_gnum) >= self._config.GLIMIT: break
            if int(trace_gnum) < self._config.SGADGET: continue
            self.gid += 1
            for trace_key2, trace_c2 in trace_c1.items():
                for tk in trace_c2.keys():
                    cnt += 1
                    opcodes = self.check_trace_instruction(trace_key2, tk.lower(), trace_c2, cnt)
                    if opcodes: self.append_opcodes_dump(opcodes)
                    else: debug.debug("[-] Skipping instructions... %s" % tk.lower())
        self.stop_chain_dump()                    
    
    def serialize_opcodes(self): 
        if self._config.DB:
            db_name = "%s_%s_%d.json" % (self._config.DB, "dechain", self._config.GLIMIT)
        if self._config.IDB:
            db_name = self._config.IDB
        fd = open(db_name, 'w')
        print "\n[+] Dumping %s" % db_name
        json.dump(self.opcodes_db, fd, indent = 2)
        fd.close()

    def calculate(self):
        if not self.is_nasm():
            debug.error("Please install nasm")

        if not self._config.IJSON:
            debug.error("Please provide the input JSON trace")
       
        self._addrspace = utils.load_as(self._config)

        self.md = self.init_capstone()
        self.md.detail = True

        print "[+] From gadget: %s" % self._config.SGADGET
        print "[+] To gadget: %s" % self._config.GLIMIT

        self.get_json_trace()
        self.follow_trace()

        if self._config.DEBUG:
            self.get_trace_asm()
          
        if self._config.DB or self._config.IDB:
            self.serialize_opcodes()

    def render_text(self, outfd, data):
        outfd.write("\n")
