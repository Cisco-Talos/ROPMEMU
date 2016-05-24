#
# Simple GDB Python script to get the initial 
# pointer of the Copy Chain.
# Note: Script ad-hoc for Chuck.
#
# Mariano `emdel` Graziano
#

import gdb

#
# References:
#     * 0vercl0k: http://download.tuxfamily.org/overclokblog/Hi%20GDB%2c%20this%20is%20python/0vercl0k_Hi%20GDB%2c%20this%20is%20python.pdf
#     * delroth: http://blog.lse.epita.fr/articles/10-pythongdb-tutorial-for-reverse-engineering---part-.html
#     * pollux: https://www.wzdftpd.net/blog/index.php?post/2010/12/20/Python-scripts-in-GDB
#
class ChuckGetCopyPtr(gdb.Breakpoint):
    ''' Usage: chuckgetcopyptr'''

    def __init__(self):
        self.long_int = gdb.lookup_type('unsigned long long') 
        print("--[ ROPMEMU framework - GDB utils ]--\n")
        print("[+] Patching...")
        # necessary patch to make Chuck work
        self.patch = "set *(unsigned long long*)0xffffffff81352d33 = 0xc310c48348"
        gdb.execute("%s" % self.patch)
        # set the breakpoint
        print("[+] Setting the breakpoint...")
        self.msr_gadget_addr = "*0xffffffff810039a0"
        self.sysenter_esp = 0x175
        super(ChuckGetCopyPtr, self).__init__(self.msr_gadget_addr, gdb.BP_BREAKPOINT)
        # Continue
        print("[+] Back to the VM")
        gdb.execute("c")


    def stop(self):  
        rcx_val_raw = gdb.parse_and_eval('$rcx').cast(self.long_int)
        rcx_val = int(rcx_val_raw) & 0xffffffffffffffff
 
        fix = 2**64
        if rcx_val == self.sysenter_esp:
            print("[+] Reading RAX...")
            rax_val_raw = gdb.parse_and_eval('$rax').cast(self.long_int)
            rax_val = int(rax_val_raw) & 0xffffffffffffffff

            print("[+] Copy Chain initial ptr: %x " % rax_val)

            rax_val_str = "0x%x" % rax_val
            print("-----")
            memory_raw = gdb.execute("x/10g %s" % rax_val_str, to_string = True)
            content = memory_raw.split('\n')
            for row in content:
                if row:
                    data = row.split('\t')
                    print("%s\t%s\t%s" % (data[0], hex(int(data[1]) + fix), hex(int(data[2]) + fix)))
            print("-----")
  
            return True

        return False


ChuckGetCopyPtr()

