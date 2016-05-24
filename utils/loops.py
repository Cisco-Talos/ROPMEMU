# ROPMEMU framework
# 
# Loop checker and optmizer.
#

import sys, argparse, subprocess
from capstone import *
from collections import OrderedDict


SIGN_FIX = 2**64
MODE = ""
SETREGS = OrderedDict()
SETREGS["x64"] = {
                "rax" : [], 
                "rbx" : [], 
                "rcx" : [], 
                "rdx" : [], 
                "rbp" : [], 
                "rsp" : [], 
                "rip" : [], 
                "rsi" : [], 
                "rdi" : [],
                "r8"  : [], 
                "r9"  : [],
                "r10" : [], 
                "r11" : [], 
                "r12" : [], 
                "r13" : [], 
                "r14" : [], 
                "r15" : []
                }
SETREGS['x86'] = {
                "eax" : [], 
                "ebx" : [], 
                "ecx" : [],
                "edx" : [],
                "ebp" : [],
                "esp" : [],
                "eip" : [],
                "esi" : [],
                "edi" : []
                }

MEMSETS = OrderedDict()
MEMSETS["x64"] = {
                "rax" : [], 
                "rbx" : [], 
                "rcx" : [], 
                "rdx" : [], 
                "rbp" : [], 
                "rsp" : [], 
                "rip" : [], 
                "rsi" : [], 
                "rdi" : [],
                "r8"  : [], 
                "r9"  : [],
                "r10" : [], 
                "r11" : [], 
                "r12" : [], 
                "r13" : [], 
                "r14" : [], 
                "r15" : []
                }
MEMSETS['x86'] = {
                "eax" : [], 
                "ebx" : [], 
                "ecx" : [],
                "edx" : [],
                "ebp" : [],
                "esp" : [],
                "eip" : [],
                "esi" : [],
                "edi" : []
                }

CHAIN = OrderedDict()
OPCODES = OrderedDict()
SETS = OrderedDict()
SETS["x64"] = OrderedDict()
SETS["x86"] = OrderedDict()
DEBUG = 0
PATTERNS = []
LAST = 0
NASM = "/usr/bin/nasm"


def load_bin(name):
    h = open(name)
    return h.read()

def get_cap_arch():
    return CS_ARCH_X86

def get_cap_mode(mode):
    if mode == "x64": return CS_MODE_64
    else: return CS_MODE_32

def init_capstone(mode):
    return Cs(get_cap_arch(), get_cap_mode(mode))

def sign_fix(op):
    if "-0x" in op:
        return hex(int(op, 16) + SIGN_FIX).strip("L")
    return op

def is_set_reg(mne, op1, op2):
    if "mov" in mne and op1 in SETREGS[MODE].keys() and (op2.startswith("0x") or op2 == "0"):
        return True
    return False

def is_mem_set(mne, op1, op2):
    if "mov" in mne and op1.split()[-1].startswith("[") and op1.split()[-1].endswith("]") and op2 in SETREGS[MODE].keys():
       return True
    return False

def check_instruction(c, instruction, mne, op1, op2, filter):
    if filter in mne:
        print instruction
    else: 
        if DEBUG: print instruction
    if is_set_reg(mne, op1, op2):
        if DEBUG: print "\t - setting %s in %s :)" % (op2, op1)
        SETREGS[MODE][op1].append(c)
        if c not in SETS[MODE]: 
            SETS[MODE][c] = (str(op1), str(op2))
    elif is_mem_set(mne, op1, op2):
        if DEBUG: print "\t -%d) mem_set %s in %s :)" % (c, op2, op1)
        MEMSETS[MODE][op1.split()[-1][1:-1]].append((c, str(op2)))

def unroll_bin(md, data, res):
    c = 0
    for i in md.disasm(data, 0):
        c += 1
        if c < res.begin: continue
        if c > res.end: break
        op1, op2_raw = i.op_str.split(",", 1)
        op2 = sign_fix(op2_raw)
        instruction = "%s %s, %s" % (i.mnemonic, op1, op2.strip())
        if c not in CHAIN:
            CHAIN[c] = instruction
            OPCODES[c] = i.bytes
        check_instruction(c, instruction, i.mnemonic, op1, op2.strip(), res.filter)

def is_src_reg_set(reg, num):
    if num+1 in SETREGS[MODE][reg]:
        return True
    return False

def is_dst_mem(dst, src, num):
    for entry in MEMSETS[MODE][dst]:
        if entry[1] != src: continue
        if entry[0] < num: continue
        if entry[0] - num > 0 and entry[0] - num <= 3: return True
    return False

def save_pattern(reg, num):
    PATTERNS.append((reg, num))

def loop_collect():
    for reg, nums in SETREGS[MODE].items():
        if len(nums) == 0: continue
        print "[+] %s under analysis" % reg
        memvals = MEMSETS[MODE][reg]
        if len(memvals) != 0:
            print "\t * possible relation: %s-%s" % (reg, memvals[0][1])
            if DEBUG:
                print "\t * INFO:"
                print "\t\t -> " , nums
                print "\t\t -> " , memvals
                print "\t * flow reconstruction..."
            for n in nums:
                if DEBUG: 
                    print "\t\t -> set %s at %s" % (reg, n)
                    if is_src_reg_set(memvals[0][1], n): print "\t\t -> set %s at %s" % (memvals[0][1], n+1)
                if is_dst_mem(reg, memvals[0][1], n):
                    if DEBUG: print "\t\t -> dst memset! " , n
                    save_pattern(reg, n)

def find_main_loop():
    sumregs = OrderedDict()
    for p in PATTERNS:
        if p[0] not in sumregs:
            sumregs[p[0]] = 1
        else: sumregs[p[0]] += 1
    if DEBUG: print sumregs
    val = max(sumregs.values())
    return [k for k, v in sumregs.items() if v == val]

def split_regions(addresses):
    last_a = addresses[0]
    ranges = []
    start = addresses[0]
    for a in addresses:
        if DEBUG: print last_a, a
        if (int(a, 16) - int(last_a, 16)) > 0x1000:
            ranges.append((start, last_a))
            start = a
        last_a = a
    ranges.append((start, a))
    return ranges

def loop_analyze():
    addresses = []
    reg = find_main_loop()
    print "[+] Main loop with: %s" % reg[0]
    for p in PATTERNS:
        if SETS[MODE][p[1]][0] != reg[0]: continue
        addresses.append(SETS[MODE][p[1]][1])
    regions = split_regions(addresses)
    print "[+] Detected ranges:"
    for r in regions:
        print "\t%s - %s" % (r[0], r[1])
    return regions, reg[0]

def print_info(filename):
    print "[+] Mode: %s" % MODE
    print "[+] Filename: %s" % filename

def get_instrnum_from_addr(addr, reg):
    for num, vals in SETS[MODE].items():
        if vals[0] == reg and vals[1] == addr: return num 
    return None

def zoom(num):
    C = 30
    print "-"*30
    for x in xrange(num, num+C):
        print CHAIN[x] 
    print "-"*30

def find_next_pattern(reg, start_num):
    return PATTERNS[PATTERNS.index((reg, start_num)) + 1]

def get_nasm_size_fmt():
    if MODE == 'x64': return "qword"
    else: return "dword"

def sanitize_template(template):
    temp = []
    for t in template:
        if 'qword ptr' in t:
            temp.append(t.replace(' qword ptr', ''))
        else: temp.append(t)
    return temp

# TODO: Be more generic - At the moment it needs to be tuned 
#       a little bit everytime. Create more templates and specify 
#       them from the command line.
def generate_asm_loop(template, start_addr, end_addr, label):
    temp = sanitize_template(template)
    skeleton = "mov %s rax, %s\n" % (get_nasm_size_fmt(), start_addr)
    skeleton += "mov %s rbx, %s\n" % (get_nasm_size_fmt(), end_addr)
    skeleton += "loop_%d:\n" % label
    skeleton += "pop rdx"
    skeleton += "\n"
    skeleton += temp[-1]
    skeleton += "\n"
    skeleton += "add rax, 0x08\n"
    skeleton += "cmp rax, rbx\n"
    skeleton += "jne loop_%d\n" % label
    print skeleton
    return skeleton

def get_bits_directive():
    if MODE == 'x64': return "[BITS 64]"
    else: return "[BITS 32]"

def create_tmp_file(asm_loop, snum, enum):
    filename = "/tmp/loops_%s-%s.asm" % (snum, enum)
    print "[+] Generating %s" % filename
    fd = open(filename, "w")
    bits = get_bits_directive()
    fd.write("%s\n" % bits)
    fd.write("%s" % asm_loop)
    fd.close()
    return filename

def get_nasm_hex(buf):
    content = ''
    for x in xrange(0, len(buf)):
        content += "".join(hex(ord(str(buf[x])))[2:4])
    return content

def get_nasm(progname):
    h = open(progname)
    return h.read()

def invoke_nasm(filename):
    # http://stackoverflow.com/questions/26504930/recieving-32-bit-registers-from-64-bit-nasm-code
    progname = filename.split(".")[0]
    print "[+] Generating %s" % progname
    pargs = [NASM, '-O0', '-f', 'bin', filename, '-o', progname]
    if not subprocess.call(pargs):
        buf = get_nasm(progname)
        if DEBUG: print get_nasm_hex(buf)
        return buf

def get_template(reg, start_num, end_num, start_addr, end_addr, label):
    next_num = find_next_pattern(reg, start_num)[1] 
    template = []
    print "-"*30
    for x in xrange(start_num, next_num):
        template.append(CHAIN[x])
        print CHAIN[x]
    print "-"*30
    asm_loop = generate_asm_loop(template, start_addr, end_addr, label)
    # Quick solution
    filename = create_tmp_file(asm_loop, start_num, end_num)
    buf = invoke_nasm(filename)
    return buf

def write_until(fo, start, end):
    print "[+] Write from %d to %d" % (start, end)
    for x in xrange(start, end):
        fo.write(OPCODES[x])

def write_loop(fo, buf):
    fo.write(buf)

def get_loop_delta(start_num, reg):
    next_num = find_next_pattern(reg, start_num)[1]
    return next_num - start_num

def write_intel_prologue(fo):
    if MODE == "x64":
        prologue = "push rbp\n"
        prologue += "mov rbp, rsp\n"
    else:
        prologue = "push ebp\n"
        prologue += "mov ebp, esp\n"
    print "-"*30
    print prologue
    pname = create_tmp_file(prologue, 0, 2)
    pbuf = invoke_nasm(pname)
    fo.write(pbuf)

def write_intel_epilogue(fo):
    epilogue = "leave\n"
    epilogue += "ret\n"
    print "-"*30
    print epilogue
    ename = create_tmp_file(epilogue, LAST, 2)
    ebuf = invoke_nasm(ename)
    fo.write(ebuf)

def open_outbin(outbin):
    print "[+] Generating %s" % outbin
    fo = open(outbin, "wb")
    write_intel_prologue(fo)
    return fo

def apply_template(buf, snum, enum, outbin, reg, fo):
    print "[+] Apply template..."
    write_loop(fo, buf)
    delta = get_loop_delta(snum, reg)
    print "[+] Delta: %d" % delta 
    print "[+] Enum + delta: %d" % (enum+delta) 
    return (enum+delta)

def apply_loop(regions, reg, outbin):
    cnt = 0
    fo = open_outbin(outbin)
    n = 1
    for region in regions:
        cnt += 1
        start_addr = region[0]
        end_addr = region[1]
        # focus only on big ranges
        if (int(end_addr, 16) - int(start_addr, 16)) < 0x1000: continue
        print "[+] Compressing loop (%s, %s)" % (start_addr, end_addr)
        snum = get_instrnum_from_addr(start_addr, reg)
        enum = get_instrnum_from_addr(end_addr, reg)
        if snum >= n:
            print "[+] Inserting instructions from %d to %d" % (n, snum)
            write_until(fo, n, snum)
        print "[+] Loop from instruction %s to %s" % (snum, enum)
        if DEBUG:
            zoom(snum)
            zoom(enum)
        buf = get_template(reg, snum, enum, start_addr, end_addr, cnt)
        n = apply_template(buf, snum, enum, outbin, reg, fo)
    write_until(fo, n, LAST)
    write_intel_epilogue(fo)
    fo.close()

def main():
    global MODE, LAST, DEBUG
    parser = argparse.ArgumentParser(description = 'ROPMEMU framework - loops')
    parser.add_argument("-b", "--begin", action = "store", type = int,
                        dest = "begin", default = 1, help = "From instruction X") 
    parser.add_argument("-e", "--end", action = "store", type = int,
                        dest = "end", default = 10, help = "To instruction Y") 
    parser.add_argument("-f", "--file", action = "store", type = str,
                        dest = "filename", default = None, help = "Bin file")  
    parser.add_argument("-m", "--mode", action = "store", type = str,
                        dest = "mode", default = "x64", help = "Disass mode (x64/x86")   

    parser.add_argument("-F", "--filter", action = "store", type = str,
                        dest = "filter", default = " ", help = "Filter")   
    parser.add_argument("-d", "--debug", action = "store_true",
                        dest = "debug", default = False, help = "Debug mode/Verbose")   
    parser.add_argument("-o", "--output", action = "store", type = str,
                        dest = "outbin", default = None, help = "Output bin")  
    res = parser.parse_args()
   
    if not res.filename or not res.outbin:
        print "[-] Please specify a filename and an output bin"
        parser.print_help()
        sys.exit(1)
    
    print "[-- ROPMEMU framework - loops --]\n"

    if res.debug:
        DEBUG = 1

    LAST = res.end

    data = load_bin(res.filename)
    if not data:
        print "[-] Something went wrong."
        sys.exit(1)

    md = init_capstone(res.mode)
    md.detail = True
    MODE = res.mode
    print_info(res.filename)

    unroll_bin(md, data, res)
    loop_collect()
    regions, mainreg = loop_analyze()
    apply_loop(regions, mainreg, res.outbin)

    if DEBUG:
        print "SETREGS: " , SETREGS[MODE]
        print "MEMSETS: " , MEMSETS[MODE]
        print "PATTERNS: " , PATTERNS
        print "SETS: " , SETS[MODE]

main()
