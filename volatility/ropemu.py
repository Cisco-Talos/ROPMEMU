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
import volatility.debug as debug
import volatility.plugins.ropmemu.emulator as emu
import volatility.plugins.ropmemu.disass as disass
from collections import OrderedDict
import struct, json, gzip


class ropemu(commands.Command):
    ''' ropemu: Volatility plugin in the ROPMEMU framework
        Based on Unicon and Capstone to emulate, explore and extract 
        ROP chains from physical memory dumps 
    '''
    def __init__(self, config, *args, **kwargs):        
        commands.Command.__init__(self, config, *args, **kwargs)
        self._config.add_option('NUMBER', short_option = 'n', default = 1, help = 'Number of gadgets to emulate', action = 'store', type = 'int')
        self._config.add_option('GNUMBER', short_option = 'G', default = 1, help = 'Initial gadget number', action = 'store', type = 'int')
        self._config.add_option('IP_IN', short_option = 'I', default = None, help = 'Initial IP', action = 'store', type = 'str')
        self._config.add_option('SP_IN', short_option = 'S', default = None, help = 'Initial SP', action = 'store', type = 'str')
        self._config.add_option('JSON_OUT', short_option = 'o', default = None, help = 'JSON output file', action = 'store', type = 'str')
        self._config.add_option('JSON_IN', short_option = 'i', default = None, help = 'JSON input file', action = 'store', type = 'str')
        self._config.add_option('REPLAY', short_option = 'R', help = 'Emulation in replay mode', action = 'store_true')
        self._config.add_option('SSTACK_OUT', short_option = 't', default = None, help = 'Shadow stack output file', action = 'store', type = 'str')
        self._config.add_option('SSTACK_IN', short_option = 'T', default = None, help = 'Shadow stack input file', action = 'store', type = 'str')
        self._config.add_option('CONTINUE', short_option = 'C',  dest="continue", default = False, action="store_true", help="Continue emulation - No boundary checks")
        self._config.add_option('APIs', short_option = 'a', default = None, help = 'File containing symbols - nm format', action = 'store', type = 'str')
        self._config.add_option('MULTIPATH', short_option = 'M', default = None, help = 'Specify EFLAGS value to perform multipath emulation', action = 'store', type = 'str')
        self.d = 0
        self.e = 0
        self.locality_threshold = 0x1000
        self.gadget = []
        self.shadow_stack = OrderedDict()
        self.replay_context = OrderedDict()
        self.trace = OrderedDict()
        self.shadow_stack_keys = []
        self.gcounter = 1
        self.stop = 0
        self.ret_found = 0
        self.ret_addr = 0
        self.hybrid = 0
        self.pre_sp = 0
        self.post_sp = 0
        self.max_replay_gadget = 0
        self.current_fkey = ""
        self.current_skey = ""
        self.current_tkey = ""
        self.hw_context = OrderedDict()
        self.syscalls = []
        self.symbols = OrderedDict()
        self.syscall_found = 0
        self.zflags = OrderedDict()
        self.current_instr = ""
        self.branch_points = OrderedDict()
        self.loop_detection = OrderedDict()
        self.loop_threshold = 10

    def handle_first_gadget(self, regs):
        ip = regs["RIP"]
        sp = regs["RSP"]
        self.e.reset_regs()
        self.e.set_registers(regs)
        self.e.set_sp(sp)
        self.e.set_ip(ip)

        for ins_info in self.gadget:
            sp = self.e.get_sp()     
            ip = self.e.get_ip()
            regs = self.e.dump_registers()

            # prepare hw_context for the current ip
            self.prepare_hw_context_ip(ip)
            content, size = ins_info[0], ins_info[1]
            
            # prepare hw_context for the current instr
            self.prepare_hw_context_instr(content, ip)
            self.pre_sp = int(sp, 16)
            
            # code
            self.e.write_data(ip, content)
            
            # stack
            stack = self._addrspace.read(int(sp, 16), self.d.get_buf_size())
            if sp in self.shadow_stack_keys: 
                debug.debug("[calculate - first gadget] RSP in the shadow_stack... getting stack %s" % sp)
                stack = self.get_from_shadow(sp)
            self.e.write_data(sp, stack) 

            # emulation
            #print self.e.show_registers()
            self.e.emu(size)
            #print self.e.show_registers()
            self.set_hw_context() 
            self.stack()
            sp = self.e.get_sp()     
            self.post_sp = int(sp, 16)
            debug.debug("[calculate] - pre_sp: %x -> post_sp: %x (delta: 0x%x)" % (self.pre_sp, self.post_sp, (self.post_sp- self.pre_sp)))
            if (self.post_sp - self.pre_sp) > self.locality_threshold or (self.post_sp - self.pre_sp) < -self.locality_threshold:
                print "[+] Chain boundary"
                print "[+] SP from %x to %x" % (self.pre_sp, self.post_sp)
                if not self._config.CONTINUE:
                    self.stop = 1
                    break

        self.gcounter += 1
        self.gadget = []
        debug.debug("Final context: ")
        debug.debug(self.e.dump_registers())

    def prepare_hw_context_gadget(self, counter, sp):
        fkey = "%s-%s" % (sp, counter)
        self.current_fkey = fkey
        if fkey not in self.hw_context:
            self.hw_context[fkey] = OrderedDict()

    def prepare_hw_context_ip(self, ip): 
        skey = "%s" % ip
        self.current_skey = skey
        fkey = self.current_fkey
        if skey not in self.hw_context[fkey]:
            self.hw_context[fkey][skey] = OrderedDict()

    def prepare_hw_context_instr(self, content, ip):
        api_name = self.is_api(ip)
        if api_name: self.syscalls.append(api_name)
       
        if api_name:
            self.syscall_found = 1
            print "-"*11
            print "[*] Symbol found: %s" % api_name
            print "-"*11
            self.handle_api() 
            self.gadget = []

        tkey = self.d.dis(content, ip)
        self.current_tkey = tkey
        skey = self.current_skey
        fkey = self.current_fkey
        if tkey not in self.hw_context[fkey][skey]:
            self.hw_context[fkey][skey][tkey] = OrderedDict()

    def set_hw_context(self):
        fkey = self.current_fkey
        skey = self.current_skey
        tkey = self.current_tkey
        self.hw_context[fkey][skey][tkey] = self.e.dump_registers()
    
    def serialize(self, content, tag, label):
        filename = "%s_%s.json" % (tag, label)
        print "\n[+] %s generated" % filename
        h = open(filename, "w") 
        json.dump(content, h, indent = 2) 
        h.close()
    
    def load_json_trace(self):
        filename = self._config.JSON_IN
        print "[+] Loading hardware context from: %s" % filename
        SUPPORTED_EXT = ['json', 'gz']
        ext = filename.split('.')[-1]
        all_hwcontext = OrderedDict()
        if ext.lower() not in SUPPORTED_EXT:
            print "[-] Extension not supported for the trace."
            raise RuntimeError("Extension not supported!")
        if ext.lower() == 'gz':
            gf = gzip.open(filename)
            self.hw_context = json.loads(gf.read(), object_pairs_hook = OrderedDict)
            gf.close()
            return
        fd_ijson = open(filename, 'r')
        all_hwcontext = json.load(fd_ijson, object_pairs_hook = OrderedDict)
        self.trace = all_hwcontext
        gaddr = self._config.SP_IN
        gnumber = self._config.GNUMBER
        key = "%s-%s" % (gaddr, str(gnumber))
        self.init_hw_context(key, all_hwcontext)
        fd_ijson.close()

    def init_hw_context(self, key, hwcontext):
        ref_addr, ref_num = key.split("-")
        found = 0 
        for k in hwcontext.keys():
            addr, num = k.split("-")
            if int(num) < int(ref_num): continue
            if found == 0: self.first_key = k 
            found = 1 
        self.hw_context[self.first_key] = hwcontext[self.first_key]

    def find_right_state(self, ip, sp):
        debug.debug("[find_right_state]")
        for k1, v1 in self.trace.items():
            for k2, v2 in v1.items():
                for k3, v3 in v2.items():
                    if v3["RIP"] == ip and v3["RSP"] == sp:
                        debug.debug("[find_right_state] - FOUND")
                        return self.trace[k1][k2][k3]

    def get_max_replay_gadget(self):
        debug.debug(("[get_max_replay_gadget]"))
        k1, v1 = self.trace.items()[-1]
        return int(k1.split("-")[1])

    def replay_mode(self):
        min_num = self._config.GNUMBER
        max_num = self._config.NUMBER
        counter = min_num
        print "[+] Replay from gadget %d to %d" % (min_num, max_num)
        for k1, v1 in self.trace.items():
            current_num = int(k1.split("-")[1])
            if current_num < min_num or current_num > max_num: continue
            print "[+] Gadget %d at %s" % (counter, k1)
            self.replay_context[k1] = self.trace[k1]
            for k2, v2 in v1.items():
                for k3, v3 in v2.items():
                    print "\t | %s \t| %s " % (k2, k3)
            counter += 1

    def replay_max(self):
        min_num = self._config.GNUMBER
        max_num = self.max_replay_gadget
        counter = min_num
        print "[+] Replay from gadget %d to %d" % (min_num, max_num)
        for k1, v1 in self.trace.items():
            current_num = int(k1.split("-")[1])
            if current_num < min_num or current_num > max_num: continue
            print "[+] Gadget %d at %s" % (counter, k1)
            self.replay_context[k1] = self.trace[k1]
            for k2, v2 in v1.items():
                for k3, v3 in v2.items():
                    print "\t | %s \t| %s " % (k2, k3)
            counter += 1

    def get_max_context(self):
        debug.debug(("[get_max_context]"))
        k1, v1 = self.trace.items()[-1]
        k2, v2 = v1.items()[-1]
        k3, v3 = v2.items()[-1]
        return v3

    def stack(self):
        for sp_addr, sp_entry in self.e.shadow.items():
            self.shadow_stack[sp_addr] = sp_entry
        self.shadow_stack_keys = self.shadow_stack.keys()

    def get_from_shadow(self, sp):
        debug.debug("[get_from_shadow]")
        stack = ""
        ind_s = self.shadow_stack_keys.index(sp)
        ind_e = ind_s + 0x20
        if ind_e > len(self.shadow_stack_keys):
            ind_e = len(self.shadow_stack_keys)
        for x in xrange(ind_s, ind_e):
            shadow_entry = self.shadow_stack_keys[x]
            shadow_content = int(self.shadow_stack[shadow_entry], 16)
            if shadow_content < 0: shadow_content += self.e.fix
            shadow_packed = struct.pack("<Q", shadow_content)
            stack += str(shadow_packed)
        return stack

    def load_shadow_stack(self):
        filename = self._config.SSTACK_IN
        print "[+] Loading shadow stack from: %s" % filename
        SUPPORTED_EXT = ['json', 'gz']
        ext = filename.split('.')[-1]
        if ext.lower() not in SUPPORTED_EXT: 
            print "[-] Extension not supported."
            raise RuntimeError("Extension not supported!")
        if ext.lower() == 'gz':
            gf = gzip.open(filename)
            self.shadow_stack = json.loads(gf.read(), object_pairs_hook = OrderedDict)
            gf.close()
            return
        fd_ijson = open(filename, 'r') 
        self.shadow_stack = json.load(fd_ijson, object_pairs_hook = OrderedDict)

    def get_symbols(self):
        print "[+] Symbols file: %s" % self._config.APIs
        h = open(self._config.APIs)
        for line in h.readlines():
            l = line.strip()
            sym_addr, sym_type, sym_name = l.split()
            if sym_type not in ['t', 'T']: continue
            self.symbols[sym_addr] = sym_name

    def is_api(self, ip):
        debug.debug("[is_api] - %s -> %s" % (ip, ip[2:]))
        if ip[2:] in self.symbols.keys(): return self.symbols[ip[2:]]
        return None 

    def handle_api(self):
        # injecting a ret instruction
        debug.debug("[+] Injecting a RET instruction...")
        print "[handle_api] - current_sp: " , self.e.get_sp()
        print "[handle_api] - current_ip: " , self.e.get_ip()
        print "[handle_api] - injecting ret instruction..."
        self.e.mu.mem_write(self.e.unicorn_code, "\xc3")
        if self.ret_found == 1 and self.ret_addr != 0:
            self.d.get_gadget(hex(self.ret_addr).strip("L"), 1)
            self.e.mu.reg_write(emu.regs_to_code["RIP"], self.ret_addr)
            return
        raise ValueError("ret_addr missing! Something went wrong.")

    def check_loop(self, sp, zf):
        debug.debug("[loop_detection]")
        # loop detection block
        if sp not in self.loop_detection:
            self.loop_detection[sp] = 0
        self.loop_detection[sp] += 1
        if self.loop_detection[sp] > self.loop_threshold:
            # reset
            self.loop_detection[sp] = 0
            # check and flip
            print "[loop_detection] ", sp, zf
            key = "%s-%s" % (sp, self.gcounter)
            if key not in self.branch_points: self.branch_points[key] = []
            if zf == 0: 
                self.e.set_zf()
                self.branch_points[key].append(1)
            elif zf == 1: 
                self.e.clear_zf()
                self.branch_points[key].append(0)
            else: raise RuntimeError("ZF value not supported.")

    def multipath(self):
        sp = self.e.get_sp() 
        print "[multipath] - %s" % self.current_instr
        print "[multipath] - sp: " , sp
        if len(self.zflags.keys()) == 1 and self.zflags.keys()[0] == "default":
            #print "[multipath] - handling ZF (%s) - default" % self.zflags.values()[0]
            zf = int(self.zflags.values()[0], 16)
            self.e.handle_zf(zf)
            self.check_loop(sp, zf)
        else:
            if sp in self.zflags.keys():
                #print "[multipath] - handling ZF (%s) for SP %s" % (self.zflags[sp], sp)
                zf = int(self.zflags[sp])
                self.e.handle_zf(zf)
                self.check_loop(sp, zf)

    def store_branch_points(self):
        key, zf = self.e.branch_point[0], self.e.branch_point[1]
        if key not in self.branch_points:
            self.branch_points[key] = []
        self.branch_points[key].append(zf)

    def calculate(self):
        if not self._config.IP_IN or not self._config.SP_IN:
            debug.error("[-] Please specify both IP_IN and SP_IN")

        if not self._config.JSON_OUT:
            debug.error("Please specify the JSON output file")

        if self._config.GNUMBER > self._config.NUMBER:
            debug.error("Plase don't be silly!")

        if self._config.APIs:
            self.get_symbols()

        # Feeding SP:ZF for multipath
        if self._config.MULTIPATH:
            for path in self._config.MULTIPATH.split(','):
                if not path: continue
                sp, zf = path.split(':')
                self.zflags[sp] = zf

        self.gcounter = self._config.GNUMBER

        ip = self._config.IP_IN
        sp = self._config.SP_IN
        print "[+] Initial IP: %s" % ip
        print "[+] Initial SP: %s" % sp 

        # Load JSON trace context
        if self._config.JSON_IN:
            self.load_json_trace()
            self.max_replay_gadget = self.get_max_replay_gadget()
            print "[+] Max replay gadget: %d" % self.max_replay_gadget
        
        # Load shadow stack
        if self._config.SSTACK_IN:
            self.load_shadow_stack() 
            self.shadow_stack_keys = self.shadow_stack.keys()
            
        if self._config.NUMBER > self.max_replay_gadget:
            # Volatility - address space for the dump
            self._addrspace = utils.load_as(self._config)

        # full replay mode
        if self._config.NUMBER <= self.max_replay_gadget and self._config.REPLAY:
            print "[+] Full replay mode" 
            self.replay_mode()
            self.serialize(self.replay_context, self._config.JSON_OUT, "hwcontext_replay")
            return

        if self._config.NUMBER > self.max_replay_gadget and self._config.REPLAY:
            print "[+] Hybrid mode"
            self.hybrid = 1
            # replay as much as we can
            self.replay_max()
            # get the regs to start the full emulation
            regs = self.get_max_context()
            sp = regs["RSP"]
            ip = regs["RIP"]
            print "[+] Full emulation with IP: %s and  SP: %s" % (ip, sp)
            self.gcounter = self.max_replay_gadget + 1

        # disassembler and emulator
        self.e = emu.Emulator(self._addrspace, ip, sp, self.gcounter) 
        self.d = disass.Disass(self._addrspace)
        D = self.d
        E = self.e
       
        if self.hybrid == 0:
            regs = OrderedDict()
            # init ip and sp
            regs["RSP"] = sp
            regs["RIP"] = ip

        print "[+] Gadget %d at %s" % (self.gcounter, sp)

        # prepare hw_context for the current gadget
        self.prepare_hw_context_gadget(self.gcounter, sp)

        # split in gadgets
        self.gadget = D.get_gadget(ip, 0)
        if D.ret != 0: 
            self.ret_addr = D.ret
            self.ret_found = 1

        # unicorn registers initialization
        if self._config.JSON_IN:
            regs = self.find_right_state(ip, sp)

        debug.debug("[+] Initial context:")
        debug.debug(regs)

        # first gadget 
        self.handle_first_gadget(regs)
        regs = E.dump_registers()
        
        ip = regs["RIP"]
        sp = regs["RSP"]
       
        # core
        while(self.gcounter <= self._config.NUMBER and self.stop == 0):
            # gadget block
            sp = E.get_sp()     
            print "[+] Gadget %d at %s" % (self.gcounter, sp) 
            # prepare hw_context for the current gadget
            self.prepare_hw_context_gadget(self.gcounter, sp)
            ip = E.get_ip()
            self.gadget = D.get_gadget(ip, 0)
            if D.ret != 0: 
                self.ret_addr = D.ret
                self.ret_found = 1

            # instructions loop
            for i in self.gadget:
                # get current sp and ip
                sp = E.get_sp()     
                ip = E.get_ip()
                regs = E.dump_registers()

                # prepare hw_context for the current ip
                self.prepare_hw_context_ip(ip)

                # debug - print registers
                debug.debug(regs)
                # debug - show ip and sp
                debug.debug("pre set ip: %s" % ip)
                debug.debug("pre set sp: %s" % sp)
                self.pre_sp = int(sp, 16)
               
                # manually invoke __del__ 
                E.mu.__del__()

                # create the disassembler and emulator
                self.e = emu.Emulator(self._addrspace, ip, sp, self.gcounter) 
                self.d = disass.Disass(self._addrspace)
                D = self.d
                E = self.e

                # init ip and sp - special cases
                E.set_registers(regs)
                E.set_ip(ip)
                E.set_sp(sp)

                sp = E.get_sp()     
                ip = E.get_ip()
                # debug - show sp and ip
                debug.debug("post set IP: %s" % ip)
                debug.debug("post set SP: %s" % sp)
                
                content, size = i[0], i[1]
                self.current_instr = self.d.dis(content, "0x1000") 

                # debug - content and size
                debug.debug("[main] - Pre emulation SP: %s" % sp)
                debug.debug("- code content: %s" % content.encode("hex"))
                debug.debug("- size: %d" % size)

                # code
                E.write_data(ip, content)
                
                # stack
                stack = self._addrspace.read(int(sp, 16), D.get_buf_size())
                if sp in self.shadow_stack_keys: 
                    debug.debug("[calculate] RSP in the shadow_stack... getting stack %s" % sp)
                    stack = self.get_from_shadow(sp)
                E.write_data(sp, stack)
                debug.debug("- stack: %s" % stack.encode("hex"))

                # prepare hw_context for the current instr
                self.prepare_hw_context_instr(content, ip)
                if self.syscall_found == 1: size = 1
                
                # multipath
                if "pushf" in self.current_instr and self._config.MULTIPATH: 
                    print "update"
                    print self.loop_detection
                    self.multipath()

                # emulation
                #E.show_registers()
                E.emu(size)
                #E.show_registers()
                debug.debug("[main] - Post emulation SP: %s" % E.get_sp())
                # set the current hw_context post emulation (the registers)
                self.set_hw_context()
                self.stack()
                if len(E.branch_point) > 0:
                    print "Branch Point:"
                    print E.branch_point
                    self.store_branch_points()
                sp = E.get_sp()     
                self.post_sp = int(sp, 16)
                debug.debug("[calculate] - pre_sp: %x -> post_sp: %x (delta: 0x%x)" % (self.pre_sp, self.post_sp, (self.post_sp- self.pre_sp)))
                if (self.post_sp - self.pre_sp) > self.locality_threshold or (self.post_sp - self.pre_sp) < -self.locality_threshold:
                    print "[+] Chain boundary"
                    print "[+] SP from %x to %x" % (self.pre_sp, self.post_sp)
                    if not self._config.CONTINUE:
                        self.stop = 1
                        break
                if self.syscall_found == 1: 
                    self.syscall_found = 0
                    break
            self.gcounter += 1
            self.gadget = []

        self.serialize(self.hw_context, self._config.JSON_OUT, "hwcontext")
        if self._config.SSTACK_OUT:
            self.serialize(self.shadow_stack, self._config.SSTACK_OUT, "sstack") 
       
        if len(self.syscalls) > 0: 
            print "\n[+] Syscalls:"
            print self.syscalls

        if len(self.branch_points.keys()) > 0: 
            print "\n[+] Branch points:"
            print self.branch_points
            print self.loop_detection
        
    def render_text(self, outfd, data):
        outfd.write("\n")

