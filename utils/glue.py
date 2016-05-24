# ROPMEMU framework
# 
# Glue - Connect all the raw bins.
#

import sys, argparse, subprocess, os, json
from capstone import *
from collections import OrderedDict

SIGN_FIX = 2**64
MODE = ""
OUTBIN = ""
NASM = "/usr/bin/nasm"
PATHS = OrderedDict()
HEAD = ""
SINK = ""
PLUGGED = []
LEAVES = []
LEAVE_OFFSET = ""
PAYLOAD = ""

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

def get_bits_directive():
    if MODE == 'x64': return "[BITS 64]"
    else: return "[BITS 32]"

def get_nasm_hex(buf):
    print "--- GET NASM HEX ---"
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
    pargs = [NASM, '-O0', '-f', 'bin', filename, '-o', progname]
    if not subprocess.call(pargs):
        buf = get_nasm(progname)
        return buf

def write_until(fo, start, end):
    print "[+] Write from %d to %d" % (start, end)
    for x in xrange(start, end):
        fo.write(OPCODES[x])

def write_intel_prologue(fo):
    if MODE == "x64":
        prologue = "push rbp\n"
        prologue += "mov rbp, rsp\n"
    else:
        prologue = "push ebp\n"
        prologue += "mov ebp, esp\n"
    pname = create_tmp_file("prologue", prologue)
    pbuf = invoke_nasm(pname)
    fo.write(pbuf)

def write_intel_epilogue(fo):
    epilogue = "leave\n"
    epilogue += "ret\n"
    ename = create_tmp_file("epilogue", epilogue)
    ebuf = invoke_nasm(ename)
    fo.write(ebuf)

def iterate(metadata, l):
    process = []
    for item in metadata[l]:
        ite, zf = item.split('^')
        print "\t Child: %s - ZF: %s" % (ite, zf)
        if zf == "F": continue
        process.append(ite) 
    return process

def glue(md, metadata):
    global HEAD, SINK
    for k, values in metadata.items():
        if k == "0": 
            head = values[0].split('^')[0]
            print "- Head: %s" % head
            break
    HEAD = head
    for k, values in metadata.items():
        if k == "0": continue
        for val in values:
            v, zf = val.split('^')
            if zf == "F" and v not in LEAVES: LEAVES.append(v)
    print "- Leaves: " , LEAVES
    if len(LEAVES) == 1: 
        SINK = LEAVES[0]
        print "- Sink: %s" % LEAVES[0]
    total = len(metadata.keys()) - 1
    layer = 0
    children = [x.split('^')[0] for x in metadata[head]]
    new = []
    new_children = []
    visited = []
    visited.append(head)
    append_until(md, head, metadata)
    PLUGGED.append(head)
    while layer < total:
        for c in children:
            if c in visited: continue
            append_until(md, c, metadata)
            visited.append(c)
            new = iterate(metadata, c)
            for n in new: new_children.append(n)
        layer += 1
        children = new_children
        new_children = []
    if SINK:
        sink_label = generate_label(SINK)
        print "- Plugging sink: %s" % sink_label
        sink_bin = PATHS[SINK]
        plug_block(sink_bin, md, sink_label)
    # TODO: Handle the generic case of N leaves

def init_bin():
    return open(OUTBIN, 'wb')

def get_children(block, metadata):
    return metadata[block]

def get_zchild(children):
    for child in children:
        c, zf = child.split("^")
        if zf == "0": return c
    return None

def get_ochild(children):
    for child in children:
        c, zf = child.split("^")
        if zf == "1": return c
    return None

def get_fchild(children):
    for child in children:
        c, zf = child.split("^")
        if zf == "F": return c
    return None

def get_data(block):
    return open(PATHS[block]).read()

def disass_until(fd, md, data):
    for i in md.disasm(data, 0):
        if "pushf" not in i.mnemonic: 
            fd.write(i.bytes)
        else: return

def generate_label(child):
    return "%s_%s" % ("label", child)

def plug_block(child_bin, md, label):
    global PAYLOAD
    if label.split("_")[1] != HEAD: PAYLOAD += "%s:\n" % label
    for j in md.disasm(open(child_bin).read(), 0):
        if len(j.op_str.split(",", 2)) > 1:
            op1, op2_raw = j.op_str.split(",", 1)
            op2 = sign_fix(op2_raw)
            mne = j.mnemonic
            instruction = "%s %s, %s" % (mne, op1, op2.strip()) 
            if instruction.startswith("mov"):
                instruction = sanitize_capstone_mov(instruction)
                if instruction.startswith("movabs"):
                    instruction = instruction.replace("movabs", "mov")
        else: 
            if j.op_str: 
                instruction = "%s %s" % (j.mnemonic, j.op_str)
            else: instruction = "%s" % j.mnemonic
        PAYLOAD += "%s\n" % instruction 

def append_until(md, block, metadata):
    global PAYLOAD
    fchild = None
    zchild = None
    ochild = None
    print "- Under analysis: %s" % block
    children = get_children(block, metadata)
    zchild = get_zchild(children)
    ochild = get_ochild(children)
    if not zchild and not ochild:
        fchild = get_fchild(children)
    #data = get_data(block)
    #disass_until(fd, md, data)
    current_bin = PATHS[block]
    current_label = generate_label(block)
    print "- Current label: %s" % current_label
    plug_block(current_bin, md, current_label)
    # pushf case
    if not fchild:
        zlabel = generate_label(zchild)
        olabel = generate_label(ochild)
        if zlabel: PAYLOAD += "jz %s\n" % zlabel
        if ochild: PAYLOAD += "jmp %s\n" % olabel
        if zchild and zlabel not in PLUGGED: 
            print "\t - Plugging child: %s" % zlabel
            PLUGGED.append(zlabel)
            zchild_bin = retrieve_zchild(block, metadata)
            plug_block(zchild_bin, md, zlabel)
        if ochild and olabel not in PLUGGED: 
            print "\t - Plugging child: %s" % olabel
            PLUGGED.append(olabel)
            ochild_bin = retrieve_ochild(block, metadata)
            plug_block(ochild_bin, md, olabel)
        return
    flabel = generate_label(fchild)
    PAYLOAD += "jmp %s\n" % flabel
    if fchild not in LEAVES:
        print "\t - Plugging leaf: %s" % flabel
        PLUGGED.append(flabel)
        fchild_bin = retrieve_fchild(block, metadata)
        plug_block(fchild_bin, md, flabel)

def sanitize_capstone_mov(instruction):
    if 'qword ptr' in instruction:
        return instruction.replace(' qword ptr', '')
    else: return instruction

def create_tmp_file(label, skeleton):
    filename = "/tmp/label_%s.asm" % label
    print "::::::::::::: Generating %s" % filename
    fd = open(filename, "w")
    bits = get_bits_directive()
    fd.write("%s\n" % bits)
    fd.write("%s" % skeleton)
    fd.close()
    return filename 

def retrieve_zchild(block, metadata):
    for c in metadata[block]:
        label, zf = c.split('^')
        if zf == "0": return PATHS[label]

def retrieve_ochild(block, metadata):
    for c in metadata[block]:
        label, zf = c.split('^')
        if zf == "1": return PATHS[label]

def retrieve_fchild(block, metadata):
    for c in metadata[block]:
        label, zf = c.split('^')
        if zf == "F": return PATHS[label]

def fix_payload():
    head = ""
    end = 0
    blocks = OrderedDict()
    final = ""
    for line in PAYLOAD.split("\n"):
        if line.startswith("label_"):
            end = 1
            cur_key = line
            if line not in blocks:
                blocks[cur_key] = ""
            blocks[cur_key] = ""
        if end != 0: blocks[cur_key] += "%s\n" % line
        if end == 0: head += "%s\n" % line
    final += head
    for k in blocks.keys():
        final += blocks[k]
    return final

def main():
    global MODE, OUTBIN
    parser = argparse.ArgumentParser(description = '[-- ROPMEMU framework - glue --]')
    parser.add_argument("-d", "--dir", action = "store", type = str,
                        dest = "dir", default = None, help = "Directory containing the binary blobs") 
    parser.add_argument("-m", "--mode", action = "store", type = str,
                        dest = "mode", default = "x64", help = "Disass mode (x64/x86")  
    parser.add_argument("-j", "--jmeta", action = "store", type = str,
                        dest = "jmeta", default = None, help = "Chain JSON metadata") 
    parser.add_argument("-o", "--output", action = "store", type = str,
                        dest = "outbin", default = None, help = "Output bin")  
    res = parser.parse_args()
   
    if not res.dir or not res.outbin or not res.jmeta:
        print "[-] Please specify: <directory,metadata,outname>"
        parser.print_help()
        sys.exit(1)

    md = init_capstone(res.mode)
    md.detail = True
    MODE = res.mode
    OUTBIN = res.outbin
    print ":: Info: "
    print "::: Mode: %s" % MODE
    print "::: Directory: %s" % res.dir
    print "::: Metadata: %s" % res.jmeta
    print "::: Output: %s" % res.outbin   

    for r, d, f in os.walk(res.dir):
        if d: continue
        root = r
        for t in f:
            binname = os.path.join(root, t)
            basename = os.path.basename(binname)
            name = basename.split('.')[0].split('_')[0]
            PATHS[name] = binname 
   
    metadata = get_json_trace(res.jmeta) 
    print "\n:: Analysis:"
    glue(md, metadata)
    payload = fix_payload()
    fd = init_bin()
    write_intel_prologue(fd)
    pname = create_tmp_file("glue", payload)   
    pbuf = invoke_nasm(pname)
    fd.write(pbuf)
    fd.close()

main()
