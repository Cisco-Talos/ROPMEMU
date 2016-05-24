# ROPMEMU framework
#
# Script to extract the syscalls from the JSON traces
#

import sys, json, gzip, os
from collections import OrderedDict

def get_json_trace(trace_name):
    SUPPORTED_EXT = ['json', 'gz']
    trace = OrderedDict()
    ext = trace_name.split('.')[-1]
    if ext.lower() not in SUPPORTED_EXT: 
        return None
    if ext.lower() == 'gz':
        gf = gzip.open(trace_name)
        trace = json.loads(gf.read(), object_pairs_hook = OrderedDict)
        gf.close()
        return trace
    else:
        jf = open(trace_name)
        trace = json.load(jf, object_pairs_hook = OrderedDict)
        jf.close()
        return trace

def find_calls(trace, symbols):
    syscalls = []
    for gn, gv in trace.items():
        for ptr, iv in gv.items():
            for instr, regs in iv.items():
                ip = regs["RIP"]
                if ip[2:] in symbols.keys():
                    syscalls.append((gn, symbols[ip[2:]]))
    return syscalls
    
def parse_sysmap(sysmap):
    if not os.path.exists(sysmap): return None
    symbols = OrderedDict()
    fd = open(sysmap)
    for line in fd.readlines():
        l = line.strip()
        sym_addr, sym_type, sym_name = l.split()
        if sym_type not in ['t', 'T']: continue
        if sym_addr not in symbols:
            symbols[sym_addr] = sym_name
    fd.close()
    return symbols

def main(): 
    if len(sys.argv) != 3:
        print "Usage: %s %s %s" % (sys.argv[0], "<trace>", "<system.map>")
        sys.exit(1)
    
    print "[-- ROPMEMU framework - systracer --]\n"
    trace = get_json_trace(sys.argv[1])
    sysmap = parse_sysmap(sys.argv[2]) 
    syscalls = find_calls(trace, sysmap)
    print "- Syscalls: %d" % len(syscalls)
    print "- List:"
    for s in syscalls:
        print "\t%s %s" % (s[0], s[1])
    

main()
