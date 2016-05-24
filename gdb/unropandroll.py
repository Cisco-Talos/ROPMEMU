#
# Simple GDB Python script to unroll a ROP chain
# Input: Number of instructions, Output filename, System.map, Mode
#
# Mariano `emdel` Graziano
#

import gdb, json, os
from collections import OrderedDict

#
# References:
#     * 0vercl0k: http://download.tuxfamily.org/overclokblog/Hi%20GDB%2c%20this%20is%20python/0vercl0k_Hi%20GDB%2c%20this%20is%20python.pdf
#     * delroth: http://blog.lse.epita.fr/articles/10-pythongdb-tutorial-for-reverse-enginee
#     * pollux: https://www.wzdftpd.net/blog/index.php?post/2010/12/20/Python-scripts-in-GDB
#
class UnRopAndRoll(gdb.Command):
    ''' Usage: unrop <number of instructions> <filename> <System.map> <mode>'''

    def __init__(self):
        gdb.Command.__init__(self, "unrop", gdb.COMMAND_OBSCURE)
        self.long_int = gdb.lookup_type('unsigned long long')
        self.hw_context = OrderedDict()


    def unroll(self, counter, symbols, mode, zflags):
        # TODO: Add proper gadget granularity - Capstone based
        chain = OrderedDict()
        finish = 0
        eflags = 0
        # pagination off
        gdb.execute("set pagination off")
        try: 
            for x in range(1, counter):
                if finish == 1: x -= 1
                rip_val_raw = gdb.parse_and_eval('$rip').cast(self.long_int)
                rip_val = int(rip_val_raw) & 0xffffffffffffffff
                if hex(rip_val).strip("L")[2:] in symbols.keys(): 
                    print("--> %x:%s" % (rip_val, symbols[hex(rip_val).strip("L")[2:]]))
                    print("--> instr %d invoking 'finish'" % x)
                    gdb.execute('finish')
                    finish = 1
                    continue
            
                rip_val_str = "0x%x" % rip_val
                disass = gdb.execute('x/i %s' % rip_val_str, to_string = True).split(':')
                instructions = disass[1].strip()
                
                if instructions.startswith('pushf'):
                    print("-"*11)
                    rsp_val_raw = gdb.parse_and_eval('$rsp').cast(self.long_int)
                    rsp_val = int(rsp_val_raw) & 0xffffffffffffffff
                    print("[+] Getting SP: " , hex(rsp_val).strip("L"))
                    print("[+] EFLAGS:")
                    print(gdb.execute('i r $eflags', to_string = True))
                    cur_eflags_raw = gdb.execute('i r $eflags', to_string = True)
                    cur_eflags = cur_eflags_raw.split()[1]
                    if len(list(zflags.keys())) == 1 and list(zflags.keys())[0] == "default": 
                        if zflags["default"] == "0": 
                            print("[+] Clear ZF...")
                            eflags = hex(int(cur_eflags, 16) & ~(1 << 6)).strip("L") 
                            gdb.execute('set $eflags = %s' % eflags)
                            print(gdb.execute('i r $eflags', to_string = True))
                        elif zflags["default"] == "1":
                            print("[+] Set ZF...")            
                            eflags = hex(int(cur_eflags, 16) | (1 << 6)).strip("L")
                            gdb.execute('set $eflags = %s' % eflags)
                            print(gdb.execute('i r $eflags', to_string = True))
                        else:
                            print("[-] Error ZF value not supported")
                    else:
                        if hex(rsp_val).strip("L") in [s for s in list(zflags.keys())]:
                            if zflags[hex(rsp_val).strip("L")] == "0":
                                print("[+] Clear ZF...")
                                eflags = hex(int(cur_eflags, 16) & ~(1 << 6)).strip("L") 
                                gdb.execute('set $eflags = %s' % eflags)
                                print(gdb.execute('i r $eflags', to_string = True))
                            elif zflags[hex(rsp_val).strip("L")] == "1":
                                print("[+] Set ZF...")
                                eflags = hex(int(cur_eflags, 16) | (1 << 6)).strip("L")
                                gdb.execute('set $eflags = %s' % eflags)
                                print(gdb.execute('i r $eflags', to_string = True))
                            else:
                                print("[-] Error ZF value not supported")
                
                key = "%x-%d" % (rip_val, x)
                if key not in chain:
                    chain[key] = instructions 
                if mode == 1:
                    registers = gdb.execute('i r', to_string = True)
                    gadget = "%s-%d" % ("Unknown", x)
                    self.parse_registers(gadget, disass[1].strip(), registers)
                gdb.execute('si')
        except Exception as e:
            print("[--- Exception ---]")
            print(e)
            return chain
        return chain


    def parse_registers(self, gadget, instruction, registers):
        if gadget not in self.hw_context:
            self.hw_context[gadget] = OrderedDict()
        if instruction not in self.hw_context[gadget]:
            self.hw_context[gadget][instruction] = OrderedDict()
        regs = registers.split('\n')
        for reg in regs:
            r = reg.strip()
            raw = r.split()
            if raw:
                rname = raw[0]
                if rname.startswith('r') or (rname.startswith('e') and len(rname) > 2):
                    rval = raw[1]
                    self.hw_context[gadget][instruction][rname.upper()] = rval


    def save_chain(self, chain, filename, mode): 
        print("[+] Generating %s" % filename)
        print("-"*30)
        fd = open(filename, "w")
        if mode == 0:
            for k, i in chain.items():
                info = "%s %s\n" % (k, i)
                print(info)
                fd.write(info)
            print("-"*30)
        else:
            json.dump(self.hw_context, fd, indent = 2)
        fd.close() 


    def parse_sysmap(self, sysmap):
        if not os.path.exists(sysmap): return None
        symbols = OrderedDict()
        fd = open(sysmap)
        for line in fd.readlines():
            l = line.strip()
            sym_addr, sym_type, sym_name = l.split()
            if sym_type not in ['t', 'T']: continue
            if sym_addr not in symbols:
                symbols[sym_addr] = sym_name
        return symbols


    def invoke(self, args, from_tty):
        print("--[ ROPMEMU framework - GDB utils ]--\n")
        if len(args.split()) != 5: 
            print("+-------------------------------------------------------------------------------------")
            print("| Usage: unrop <num_of_instrs> <output_file> <System.map> <mode> <multipath>")
            print("| Mode: 0 Normal txt trace - 1: JSON output with registers")
            print("| Multipath: NULL, default:0, default:1 - sp1:zf,sp2:zf - Pushf based")
            print("+-------------------------------------------------------------------------------------")
            return

        if not str(args.split()[0]).isdigit(): return
        if not str(args.split()[3]).isdigit(): return
        
        num_instrs = int(args.split()[0])
        mode = int(args.split()[3])
        print("[+] Processing %d instructions" % num_instrs)

        symbols = self.parse_sysmap(args.split()[2])
        if not symbols:
            print("[-] It was impossible to load the symbols...")
            return

        multipath = args.split()[4]
        print("[+] Multipath configuration: %s\n" % multipath)
        zflags = "NULL"
        if multipath != "NULL": zflags = OrderedDict()
        for m in multipath.split(','):
            if not m: continue
            sp, zf = m.split(':')
            zflags[sp] = zf

        chain = self.unroll(num_instrs, symbols, mode, zflags)
        self.save_chain(chain, args.split()[1], mode)


UnRopAndRoll()
