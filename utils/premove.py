# ROPMEMU framework
#
# premove: remove pushf blocks from the json traces generated
#          by blocks.py. It parses only the serialized traces 
#          that we pass through jfil parameter.
#

import sys, json, os, gzip, hashlib
from collections import OrderedDict
import pygraphviz as graph

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

def get_pushf(trace, name):
    for gn, gv in trace.items():
        for ptr, iv in gv.items():
            for instr, regs in iv.items():
                if "pushf" in instr:
                    n = os.path.basename(name).split(".")[0]
                    info = (n, gn, ptr, instr)
                    return info

def premove(traces):    
    pushfs = [] 
    for trace in traces:
        t = get_json_trace(trace)
        info = get_pushf(t, trace)
        if info: pushfs.append(info)
    return pushfs 

def get_path(paths, block):
    for path in paths:
        p = os.path.basename(path).split('.')[0]
        if p != block: continue
        return path

def get_until(trace, limit):
    block = []
    cnt = 0
    found = 0
    for gn, gv in trace.items():
        for ptr, iv in gv.items():
            for instr, regs in iv.items():
                cnt += 1
                block.append(instr)
                if limit not in instr: continue
                found = 1
        if found == 1:
            return (cnt, gn, gv, ptr, instr, block)

def get_block_hash(instructions):
    return hashlib.md5(''.join(instructions)).hexdigest()

#info = [cnt, gn, gv, ptr, instr, block
def strip_trace(trace, info):
    ref_gn = int(info[1].split('-')[1])
    payload = OrderedDict()
    for gn, gv in trace.items():
        cur_gn = int(gn.split('-')[1]) 
        if cur_gn <= ref_gn: continue
        payload[gn] = gv 
    return payload

def get_instructions(trace):
    instructions = []
    for gn, gv in trace.items():
        for ptr, iv in gv.items():
            for instr, regs in iv.items():
                instructions.append(instr)
    return instructions

def save_new_trace(label, old_name, s_trace):
    dir = os.path.dirname(old_name) 
    name = "%s%s" % (label, ".json")
    filename = os.path.join(dir, name)
    print "\t + Dumping %s" % filename
    o = open(filename, 'w')
    json.dump(s_trace, o, indent = 2)
    o.close()

def find_children(heads, metadata, paths):
    remap = OrderedDict()
    for h in heads:
        parent = h[0]
        for meta in metadata.keys():
            if meta == "0": continue
            if parent == meta:
                print "[+] Parent: %s" % parent
                for child in metadata[parent]:
                    c, zf = child.split("^")
                    print "\t - Child: %s ZF: %s" % (c, zf)
                    filename = get_path(paths, c)
                    if not os.path.exists(filename): continue 
                    trace = get_json_trace(filename)
                    print "\t - Child @: %s" % filename
                    info = get_until(trace, limit="leave")
                    block_hash = get_block_hash(info[5])
                    print "\t - Hash pushf block: %s - Until: %s" % (block_hash, info[1])
                    len_tot = len(trace.keys())
                    s_trace = strip_trace(trace, info)
                    len_new = len(s_trace)               
                    print "\t - Before: %d - After: %d - Diff: %d" % (len_tot, len_new, (len_tot - len_new))
                    new_trace_hash = get_block_hash(get_instructions(s_trace))
                    print "\t + Creating %s" % new_trace_hash
                    print "\t - Removing %s" % filename
                    os.remove(filename)
                    save_new_trace(new_trace_hash, filename, s_trace)
                    old_file = os.path.basename(filename).split('.')[0]
                    remap[old_file] = new_trace_hash
    return remap

def remove_block(heads, metadata, paths):
    return find_children(heads, metadata, paths)

def fix_metadata(remap, metadata):
    print metadata
    for old, new in remap.items():
        for key, values in metadata.items():
            if old == key:
                print "\t - Fix key: %s -> %s" % (key, new)
                metadata[new] = values
                print "\t\t - Removed key %s" % key
                del metadata[key]
            for val in values:
                v, zf = val.split('^')
                if v == old:
                    print "\t - Fix value: %s -> %s - ZF: %s" % (old, new, zf)
                    new_val = "%s^%s" % (new, zf)
                    metadata[key].remove(val)
                    print "\t\t - Removed %s" % val
                    print "\t\t - Added %s" % new_val
                    metadata[key].append(new_val)
    return metadata

def visualization(metadata, filename):
    print "--- VISUALIZATION ---"
    g = graph.AGraph(directed=True)
    for k, v in metadata.items(): 
        for x in xrange(len(v)):
            node, zf = v[x].split('^')
            g.add_edge(k, node, len="2.1", label=zf, rankdir="LR") 
            #print "adding %s -> %s" % (k, node)
    filename = os.path.basename(filename)
    g.layout(prog='dot')
    picture = "%s-%s.png" % (filename, "image")
    print "[+] Generating %s" % picture
    g.draw(picture)

def serialize(information):
    print "--- SERIALIZE ---"
    filename = "%s%s" % ("premove-metadata", ".json")
    h = open(filename, 'w')
    json.dump(information, h, indent = 2)
    print "[+] Dumping %s" % filename
    h.close()

def main():
    if len(sys.argv) != 4:
        print "[-] Usage: %s %s %s %s" % (sys.argv[0], "<jlist>", "<metadata>", "<dir>")
        sys.exit(1)
    j = open(sys.argv[1])
    md5_list = set(json.load(j))
    j.close()
    print md5_list
    print "[+] Loaded %d labels" % len(md5_list)
    dirtytraces = []
    read = []
    print "[+] Getting traces..."
    for r, d, f in os.walk(sys.argv[3]):
        if d: continue
        root = r
        for t in f:
            tracename = os.path.join(root, t)
            basename = os.path.basename(tracename)
            name = basename.split('.')[0]
            if name in md5_list and name not in read:
                dirtytraces.append(tracename)
                read.append(name)
    print "[+] Got %d traces" % len(dirtytraces)
    heads = premove(dirtytraces)
    print "[+] Pass pushf-block..."
    m = open(sys.argv[2])
    metadata = json.load(m)
    m.close()
    remap = remove_block(heads, metadata, dirtytraces)
    print "[+] Fix metadata..."
    metadata = fix_metadata(remap, metadata)
    visualization(metadata, "premove")
    serialize(metadata)

main()
