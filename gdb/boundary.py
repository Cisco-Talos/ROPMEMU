#
# GDB Python to detect chain's boundaries
# Input: System.map
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
class BOUNDARY(gdb.Command):
    ''' Usage: unrop <System.map> '''

    def __init__(self):
        gdb.Command.__init__(self, "boundary", gdb.COMMAND_OBSCURE)
        self.long_int = gdb.lookup_type('unsigned long long')
        self.THRESHOLD = 0x1000

    def boundary(self, symbols):
        '''
        Usage: 
            a) run chuckgetcopyptr
            b) set a breakpoint on POP RSP: 0xffffffff81423f82
            c) once the breakpoint is triggered run this script
        '''
        print("[+] Chasing the dispatcher chain...")
        finish = 0
        x = 0
        rsp_val_raw = gdb.parse_and_eval('$rsp').cast(self.long_int)
        rsp_val = int(rsp_val_raw) & 0xffffffffffffffff
        rsp_val_str = "0x%x" % rsp_val
        last_sp = rsp_val_str
        try: 
           while True:
                # stack pointer check
                x += 1
                rsp_val_raw = gdb.parse_and_eval('$rsp').cast(self.long_int)
                rsp_val = int(rsp_val_raw) & 0xffffffffffffffff
                rsp_val_str = "0x%x" % rsp_val
                print("%d) %s - %s" % (x, rsp_val_str, last_sp))
                if rsp_val - int(last_sp, 16) > self.THRESHOLD:
                    print("[+] last_sp: %s - current_sp: %s" % (last_sp, rsp_val_str))
                    print("[+] %d instructions executed!" % x)
                    break
                # we do not want to step into in a function call.
                rip_val_raw = gdb.parse_and_eval('$rip').cast(self.long_int)
                rip_val = int(rip_val_raw) & 0xffffffffffffffff
                rip_val_str = "0x%x" % rip_val
                if hex(rip_val).strip("L")[2:] in symbols.keys(): 
                    print(">>> %s:%s" % (rip_val_str, symbols[hex(rip_val).strip("L")[2:]]))
                    print(">>> instr %d invoking 'finish'" % x)
                    gdb.execute('finish')
                    continue
                last_sp = rsp_val_str
                gdb.execute('si')
        except Exception as why:
            print("[--- Exception ---]")
            print(why)
            print("[--- Exception ---]")
            return

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
        if len(args.split()) != 1: 
            print("+------------------------------")
            print("| Usage: boundary <System.map> ")
            print("+------------------------------")
            return

        symbols = self.parse_sysmap(args.split()[0])
        if not symbols:
            print("[-] It was impossible to load the symbols...")
            return

        self.boundary(symbols)


BOUNDARY()

