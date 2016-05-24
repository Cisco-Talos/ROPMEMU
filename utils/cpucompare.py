# ROPMEMU framework
#
# cpucompare: script to compare the CPU state,
# i.e. the registers.
#


import sys, json
from collections import OrderedDict


def load_trace(name):
    h = open(name)
    json_trace = OrderedDict()
    json_trace = json.load(h, object_pairs_hook = OrderedDict)
    h.close()
    return json_trace

def get_gadget_emu(trace, index):
    for k, v in trace.items():
        gadget, number = k.split('-')
        if number == index:
            print "[+] emu instruction: %s" % v[v.keys()[-1]].keys()[0]
            return v

def get_registers_emu(gadget_emu):
    return gadget_emu.values()[1].values() 

def get_gadget_unrop(data, index):
    for k, v in data.items():
        gadget, number = k.split('-')
        if number == index:
            return v

def get_registers_unrop(gadget_unrop):
    print "[+] Unrop instruction: %s" % gadget_unrop.keys()[0]
    return gadget_unrop.values() 

def cpu_compare(registers_emu, registers_unrop):
    print "\n[+] Results:"
    for k, v in registers_emu[0].items():
        reg_emu = k
        val_emu = v
        if reg_emu in registers_unrop[0].keys():
            val_unrop = [c for r, c in registers_unrop[0].items() if r == reg_emu][0]
            if val_unrop != val_emu:
                print "\t - Mismatch %s %s %s" % (reg_emu, val_emu, val_unrop)
            else:
                print "\t - Match %s %s %s" % (reg_emu, val_emu, val_unrop)

def main():
    if len(sys.argv) != 5:
        print "[-] Usage: %s %s %s %s %s" % (sys.argv[0], "<jsontrace>", "<unropout>", "<gadget_num_emu>", "<gadget_num_unrop>")
        sys.exit(1)

    print "[-- ROPMEMU framework -- cpucompare --]\n"
    # load file from jsondisass
    emu_trace = OrderedDict()
    emu_trace = load_trace(sys.argv[1])

    # load file from unrop
    unrop_trace = OrderedDict()
    unrop_trace = load_trace(sys.argv[2])    

    # get emu info
    gadget_emu = get_gadget_emu(emu_trace, sys.argv[3])
    #print gadget_emu
    registers_emu = get_registers_emu(gadget_emu)
    #print registers_emu

    # get unrop info
    gadget_unrop = get_gadget_unrop(unrop_trace, sys.argv[4])
    #print gadget_unrop
    registers_unrop = get_registers_unrop(gadget_unrop)
    #print registers_unrop

    # compare
    cpu_compare(registers_emu, registers_unrop)


main()
