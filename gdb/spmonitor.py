#
# Simple GDB Python script to monitor 
# the sp deltas and assess the stack 
# emulation.
#
# Mariano `emdel` Graziano
#

import gdb, os
from collections import OrderedDict

#
# References:
#     * 0vercl0k: http://download.tuxfamily.org/overclokblog/Hi%20GDB%2c%20this%20is%20python/0vercl0k_Hi%20GDB%2c%20this%20is%20python.pdf
#     * delroth: http://blog.lse.epita.fr/articles/10-pythongdb-tutorial-for-reverse-enginee
#     * pollux: https://www.wzdftpd.net/blog/index.php?post/2010/12/20/Python-scripts-in-GDB
#
class SPMonitor(gdb.Command):
    ''' Usage: spmonitor <number of instructions> <filename> <System.map>'''

    def __init__(self):
        gdb.Command.__init__(self, "spmonitor", gdb.COMMAND_OBSCURE)
        self.long_int = gdb.lookup_type('unsigned long long')

    def space_normalizer(self, instruction):
        c = 0 
        norm_instr = ""
        for i in instruction:
            if i == " ":
                c += 1
                if c != 1: continue
            char = i
            if i == ",": char = "%s " % i 
            norm_instr += char
        return norm_instr

    def sanitize_mov(self, instr):
        if "QWORDPTR" in instr:
            return instr.replace("QWORDPTR", "")
        return instr

    def get_sp(self):
        rsp_raw = gdb.parse_and_eval('$rsp').cast(self.long_int)
        return int(rsp_raw) & 0xffffffffffffffff

    def get_ip(self):
        rip_val_raw = gdb.parse_and_eval('$rip').cast(self.long_int)
        return int(rip_val_raw) & 0xffffffffffffffff

    def spmonitor(self, counter, symbols):
        deltas = []
        finish = 0
        
        # pagination off
        gdb.execute("set pagination off")

        for x in range(1, counter):
            if finish == 1:
                x -= 1
            
            # getting sp before emulation
            sp_before = self.get_sp()
              
            # syscalls check
            rip_val = self.get_ip()
            rip_val_str = "0x%x" % rip_val
            disass = gdb.execute('x/i %s' % rip_val_str, to_string = True).split(':') 
            instr = disass[1].strip()
            instr_clean = self.space_normalizer(instr)
            if instr.startswith("mov"): instr_clean = self.sanitize_mov(instr_clean)
            if hex(rip_val).strip("L")[2:] in symbols.keys(): 
                print("--> %x:%s" % (rip_val, symbols[hex(rip_val).strip("L")[2:]]))
                print("--> instr %d invoking 'finish'" % x)
                gdb.execute('finish')
                finish = 1
                continue
        
            # to sync with ropemu 
            gdb.execute('si')
    
            # getting sp after emulation
            sp_after = self.get_sp()
            
            # delta
            delta = hex(sp_after - sp_before).strip("L")
            
            # format instr, sp, sp_pre, sp_after, delta
            deltas.append((instr_clean, hex(sp_before).strip("L"), hex(sp_after).strip("L"), delta))
        return deltas

    def save_deltas(self, deltas, filename): 
        print("[+] Generating %s" % filename)
        print("-"*30)
        fd = open(filename, "w")
        for d in deltas:
            info = "%s | %s | %s | %s\n" % (d[0], d[1], d[2], d[3])
            print(info)
            fd.write(info)
        print("-"*30)
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
        if len(args.split()) != 3: 
            print("+--------------------------------------------------------------------+")
            print("| Usage: spmonitor <num_of_instrs> <output_file> <System.map>        |")
            print("+--------------------------------------------------------------------+")
            return

        if not str(args.split()[0]).isdigit(): return
        
        num_instrs = int(args.split()[0])
        print("[+] Processing %d instructions" % num_instrs)

        symbols = self.parse_sysmap(args.split()[2])
        if not symbols:
            print("[-] It was impossible to load the symbols...")
            return

        deltas = self.spmonitor(num_instrs, symbols)
        self.save_deltas(deltas, args.split()[1])


SPMonitor()

