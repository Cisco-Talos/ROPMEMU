# ROPMEMU framework
# 
# blocks - Input: JSON traces
#          Output: a) Several JSON traces containing the basic blocks of the future CFG. 
#                  b) Metadata information on how to glue the blocks for the CFG
#                  c) Graphs showing the steps and the final version
#
#          TODO: Be more generic - More testing - Alpha - PoC
#

import sys, os, json, gzip, hashlib
from collections import OrderedDict
import pygraphviz as graph

def get_json_trace(trace_name):
    SUPPORTED_EXT = ['json', 'gz']
    trace = OrderedDict()
    ext = trace_name.split('.')[-1]
    if ext.lower() not in SUPPORTED_EXT: 
        return None
    print "[+] Getting %s" % trace_name
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

def get_block_hash(instructions):
    return hashlib.md5(''.join(instructions)).hexdigest()

def visualization(metadata, filename):
    print "--- VISUALIZATION ---"
    g = graph.AGraph(directed=True)
    for k, v in metadata.items(): 
        for x in xrange(len(v)):
            node, zf = v[x].split('^')
            g.add_edge(k, node, len="2.1", label=zf, rankdir="LR") 
    filename = os.path.basename(filename)
    g.layout(prog='dot')
    picture = "%s-%s.png" % (filename, "image")
    print "[+] Generating %s" % picture
    g.draw(picture)

def generate_json_blocks(json_blocks, trace_name, dirname):
    tname = os.path.basename(trace_name).split('.')[0]
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    dirtrace = os.path.join(dirname, tname)
    if not os.path.exists(dirtrace):
        os.makedirs(dirtrace)
    for k, v in json_blocks.items():
        filejson = "%s%s" % (os.path.join(dirtrace, k), ".json")
        print "[+] Generating %s" % filejson
        fw = open(filejson, 'w')
        json.dump(json_blocks[k], fw, indent = 2)
        fw.close()

def find_zf(trace, gn):
    gadgets = trace.keys()
    index = gadgets.index(gn)
    next_key = gadgets[index + 1]
    next_ptr = trace[next_key].keys()[1]
    regs = trace[next_key][next_ptr].values()[0]
    for k, v in regs.items():
        if k == 'RCX': 
            return v

def get_zf(zeta):
    return ((int(zeta, 16) >> 6) & 1)

def find_blocks(trace, trace_name, dirname):
    print "--- FIND BLOCKS ---"
    instructions = []
    md5_blocks = []
    payload = OrderedDict()
    metadata = OrderedDict()
    json_blocks = OrderedDict()
    last_block = 0
    last_gn = 0
    for gn, gv in trace.items():
        payload[gn] = gv
        for ptr, iv in gv.items():
            for instr, regs in iv.items():
                if "pushf" not in instr: instructions.append(instr)
                else:
                    instructions.append(instr)
                    try: 
                        zeta = find_zf(trace, last_gn)
                        zeta = str(get_zf(zeta))
                    except: 
                        zeta = "NULL"
                    if zeta.startswith("0x0"): zeta = "0"
                    elif zeta.startswith("0xf"): zeta = "1"
                    block_md5 = get_block_hash(instructions)
                    if block_md5 not in md5_blocks: md5_blocks.append(block_md5)
                    instructions = []
                    json_blocks[block_md5] = payload
                    payload = OrderedDict()
                    print "- %s - Block ID: %s - ZF: %s" % (gn, block_md5, zeta)
                    meta = "%s^%s" % (block_md5, zeta)
                    if last_block not in metadata: metadata[last_block] = []
                    metadata[last_block].append(meta)
                    last_block = block_md5
                    last_gn = gn
    block_md5 = get_block_hash(instructions)
    json_blocks[block_md5] = payload
    if block_md5 not in md5_blocks: md5_blocks.append(block_md5)
    try: 
        zeta = find_zf(trace, last_gn)
        zeta = str(get_zf(zeta))
    except: 
        zeta = "NULL"
    if zeta.startswith("0x0"): zeta = "0"
    elif zeta.startswith("0xf"): zeta = "1"
    meta = "%s^%s" % (block_md5, zeta)
    if last_block not in metadata: metadata[last_block] = []
    metadata[last_block].append(meta)
    print "- %s - Block ID: %s - ZF: %s" % (gn, block_md5, zeta)
    print "--- METADATA ---"
    print metadata
    generate_json_blocks(json_blocks, trace_name, dirname) 
    visualization(metadata, trace_name)
    return md5_blocks, metadata

def merge(all_metadata):
    final_meta = OrderedDict()
    for trace1, meta1 in all_metadata.items():    
        for k, v in meta1.items():
            if k not in final_meta: final_meta[k] = []
            for e in v: final_meta[k].append(e)
    print final_meta
    # TODO: Parameter for the visualization filename
    visualization(final_meta, "first")
    return final_meta

def get_main_trace(blocks, name):
    for k in blocks.keys():
        if name in blocks[k]: return k

def get_instructions(jtrace):
    instructions = []
    for k1, values in jtrace.items():
        for k2, val in values.items():
            for k3, va in val.items(): instructions.append(k3)
    return instructions

def follow_instructions(ins1, ins2):
    x = 0
    match = 0
    instructions = []
    print "\t + Baseline %d %d instructions" % (len(ins1), len(ins2))
    while True:
        x -= 1
        if ins1[x] == ins2[x]: 
            match += 1
            instructions.append(ins1[x])
        else: 
            print "\t + Mismatch after %d matches" % (match)
            break
    hash_block = get_block_hash(instructions)
    print "\t + Matched block hash: %s" % hash_block
    return match 

def overlap(blocks, meta, dir):
    print "---[ OVERLAP ]---"
    meta_clean = OrderedDict()
    for k, v in meta.items():
        for e in v:
            if k not in meta_clean:
                meta_clean[k] = []
            if e not in meta_clean[k]: meta_clean[k].append(e)
    print meta_clean
    visualization(meta_clean, "clean")
    filenames = OrderedDict()
    print "[+] Getting blocks..."
    for k, v in meta_clean.items():
        for e in v:
            name, zf = e.split('^')
            block_name = "%s%s" % (name, ".json")
            key = get_main_trace(blocks, name)
            trace = os.path.basename(key).split('.')[0]
            filename =  os.path.join(dir, trace, block_name)
            filenames[name] = filename
    print "[+] Getting leaves..."
    keys = meta_clean.keys()
    values = [v.split('^')[0] for val in meta_clean.values() for v in val]
    leaves = [v for v in values if v not in keys]
    print "[+] Getting overlaps..."
    n_instructions = OrderedDict()
    for l1 in leaves:
        for l2 in leaves[leaves.index(l1)+1:]:
            l1_filename = filenames[l1] 
            l2_filename = filenames[l2]
            t1 = get_json_trace(l1_filename)
            t2 = get_json_trace(l2_filename)
            ins1 = get_instructions(t1)
            ins2 = get_instructions(t2)
            if l1 not in n_instructions: n_instructions[l1] = len(ins1)
            if l2 not in n_instructions: n_instructions[l2] = len(ins2)
            overlap_key = "%s-%s" % (l1, l2)
            match = follow_instructions(ins1, ins2)
            n_instructions[overlap_key] = match
    refine(filenames, n_instructions, dir, meta_clean)

def refine(filenames, n_instructions, dirname, meta_clean):
    print "--- REFINEMENT ---"
    split = OrderedDict()
    for block, counter in n_instructions.items():
        args = block.split('-')
        if len(args) > 1:
            print "+ Refine blocks %s and %s" % (args[0], args[1])
            if args[0] not in split: split[args[0]] = []
            if args[1] not in split: split[args[1]] = []
            info = "%s:%s" % (args[1], n_instructions[args[0]] - counter)
            split[args[0]].append(info)
            info = "%s:%s" % (args[0], n_instructions[args[1]] - counter)
            split[args[1]].append(info)
    print split
    print "[+] Split again..."
    payload = OrderedDict()
    instructions = []
    new_blocks = OrderedDict()
    md5_blocks = OrderedDict()
    snippets = OrderedDict()
    cnt = 0
    out = 0
    for ref in split.keys():
        tracename = filenames[ref]
        trace = get_json_trace(tracename)
        indexes = set([int(x.split(':')[1]) for x in split[ref]])
        for i in indexes:
            for gn, gv in trace.items():
                payload[gn] = gv
                for ptr, iv in gv.items():
                    for instr, regs in iv.items():
                        cnt += 1
                        instructions.append(instr)
                        if cnt == i:
                            md5 = get_block_hash(instructions)
                            print "\t - New different block %s - %d instructions" % (md5, len(instructions))
                            new_blocks[md5] = payload
                            if ref not in md5_blocks:
                                md5_blocks[ref] = []
                            md5_blocks[ref].append(md5)
                            instructions = []
                            payload = OrderedDict()
                            if ref not in snippets: snippets[ref] = []
                            snippets[ref].append(md5)
            print "\t - Generating new overlapping block..."
            md5 = get_block_hash(instructions)
            print "\t - MD5 %s - Added %d instructions" % (md5, len(instructions))
            if ref not in md5_blocks: md5_blocks[ref] = []
            meta = "%s:%s" % (md5, len(instructions))
            md5_blocks[ref].append(meta)
            new_blocks[md5] = payload
            instructions = []
            payload = OrderedDict()
            cnt = 0
            generate_json_blocks(new_blocks, tracename, dirname)
            new_blocks = OrderedDict()
            if ref not in snippets: snippets[ref] = []
            snippets[ref].append(md5)
    print md5_blocks
    print "[+] Final cut..."
    nums = OrderedDict()
    new_blocks = OrderedDict()
    additions = OrderedDict()
    for k, l in md5_blocks.items():
        for e in l:
            if len(e.split(':')) > 1:
                name, num = e.split(':')
                if k not in nums: nums[k] = OrderedDict()
                if name not in nums[k]: nums[k][name] = num
        minimum = min([int(b) for a, b in nums[k].items()])
        for name, n in nums[k].items():
            if int(n) == minimum: continue
            delta = int(n) - minimum
            print "- Delta %d (n %d minimum %d) - Key: %s - Name: %s " % (delta, int(n), minimum, k, name)
            jname = "%s%s" % (name, ".json")
            path = os.path.join(dirname, k, jname)
            parent = os.path.basename(path).split(".")[0]
            t = get_json_trace(path)
            z = 0
            instructions = []
            payload = OrderedDict()
            for gn, gv in t.items():
                payload[gn] = gv
                for ptr, iv in gv.items():
                    for instr, regs in iv.items():
                        z += 1
                        instructions.append(instr)
                        if z == delta:
                            md5 = get_block_hash(instructions)
                            print "\t - New block %s - %d instructions" % (md5, len(instructions))
                            new_blocks[md5] = payload
                            if name not in additions: additions[name] = []
                            additions[name].append(md5)
                            instructions = []
                            payload = OrderedDict()
                            instructions.append(instr)
                            if parent not in snippets: snippets[parent] = []
                            snippets[parent].append(md5)
            print "\t - Generating main block... - stats - total instr %d" % z
            md5 = get_block_hash(instructions)
            print "\t - MD5 %s - Added %d instructions" % (md5, len(instructions))
            additions[name].append(md5)
            new_blocks[md5] = payload
            instructions = []
            payload = OrderedDict()
            if parent not in snippets: snippets[parent] = []
            snippets[parent].append(md5)
            z = 0
            generate_json_blocks(new_blocks, name, dirname)
    final_visualization(snippets, meta_clean, additions, filenames, dirname)

def final_visualization(snippets, meta_clean, additions, filenames, dirname):
    print "--- FINAL VIZ ---"
    print meta_clean
    print snippets
    clean = OrderedDict()
    for k, v in snippets.items():
        if k in additions.keys(): continue
        if k not in clean: clean[k] = []
        for e in v: 
            if e not in clean[k]: 
                if e not in additions.keys(): clean[k].append(e)
                else:
                    for a in additions[e]:
                        if a not in clean[k]: clean[k].append(a)
    print clean
    # get only the real gems
    instructions = OrderedDict()
    relation = OrderedDict()
    for k, v in clean.items():
        k_instr = get_instructions_number(k, filenames, clean, dirname)
        print "key: %s instructions: %s" % (k, k_instr)
        instructions[k] = k_instr 
        if k not in relation: relation[k] = []
        for e in v:
            v_instr = get_instructions_number(e, filenames, clean, dirname)
            print "\t keys: %s instructions: %s" % (e, v_instr)
            instructions[e] = v_instr
            if e not in relation[k]: relation[k].append(e)
    print "*-"*11
    print relation
    print instructions
    sink = find_sink(relation)
    # now find the block sum with sink == # instruction of parent
    # and visualize
    mods = OrderedDict()
    for parent, children in relation.items():
        print "Parent: %s (%s)" % (parent, instructions[parent])
        for c in children: 
            if c == sink: continue
            print "\t Checking %s (%s)" % (c, instructions[c])
            if int(int(instructions[sink]) + int(instructions[c])) <= int(instructions[parent]) \
            and int(int(instructions[sink]) + int(instructions[c])) >= int(instructions[parent]) - 5 :
                print "\t\t - Found: %s (%s) sink %s (%s)" % (c, instructions[c], sink, instructions[sink])
                mods[parent] = (c, sink)
    print "EOF"
    print mods
    print meta_clean
    print "first meta pass"
    for k, mod in mods.items():
        for m, clean in meta_clean.items():
            for c in clean:
                if c.split('^')[0] == k:
                    print "--> to change " , c
                    new_val = mods[k][0]
                    old_val, zf = c.split('^')
                    new_meta = "%s^%s" % (new_val, zf)
                    print "new meta --> " , new_meta
                    meta_clean[m].remove(c)
                    meta_clean[m].append(new_meta)
    print meta_clean
    print "second meta pass"
    for children in mods.values():
        new_key = children[0]
        new_value = children[1]
        new_val = "%s^%s" % (new_value, "F")
        meta_clean[new_key] = []
        meta_clean[new_key].append(new_val)
    visualization(meta_clean, "final")
    save_metadata(meta_clean)

def save_metadata(meta_clean):
    save = []
    for key, friends in meta_clean.items():
        if key == "0": continue
        save.append(key)
        for friend in friends:
            f = friend.split('^')[0]
            if f not in save: save.append(f)
    # TODO: Add label from the CLI parameters
    serialize(save, label="block-list")
    serialize(meta_clean, label="metadata")

def serialize(data, label):
    print "--- SERIALIZE ---"
    filename = "%s%s" % (label, ".json")
    h = open(filename, 'w')
    json.dump(data, h, indent = 2)
    print "[+] Dumping %s" % filename
    h.close()

def find_sink(relation):
    print "--- SINK ---"
    rel_values = [e for r in relation.values() for e in r]
    for r in set(rel_values):
        if len(relation.keys()) == rel_values.count(r):
            print "sink found: %s" % r
            return r

def get_instructions_number(key, filenames, clean, dirname):
    clean_values = [e for c in clean.values() for e in c]
    if key in filenames.keys():
        path = filenames[key]
        t = get_json_trace(path)
        return instructions_number(t)
    else:
        if key in clean_values:
            parent_key = get_parent(key, clean)
            name = "%s%s" % (key, ".json")
            filename = os.path.join(dirname, parent_key, name)
            t = get_json_trace(filename)
            return instructions_number(t)

def get_parent(key, clean):
    for k, v in clean.items():
        if key in v: return k
    return None

def instructions_number(t):
    counter = 0
    for gn, gv in t.items():
        for ptr, iv in gv.items():
            for instr, regs in iv.items():
                counter += 1
    return counter 

def main():
    if len(sys.argv) != 3:
        print "[-] Usage: %s %s %s" % (sys.argv[0], "<trace1,trace2,...,traceN>", "<blocksdir>")
        sys.exit(1)
    
    all_blocks_md5 = OrderedDict()
    all_metadata = OrderedDict()

    for trace_name in sys.argv[1].split(','):
        if not trace_name: continue
        trace = get_json_trace(trace_name)
        if not trace: continue
        md5_blocks, metadata = find_blocks(trace, trace_name, sys.argv[2])
        print "-"*11
        if trace_name not in all_blocks_md5:
            all_blocks_md5[trace_name] = []
            all_blocks_md5[trace_name] = md5_blocks
            all_metadata[trace_name] = OrderedDict()
            all_metadata[trace_name] = metadata
        print

    final_meta = merge(all_metadata)
    overlap(all_blocks_md5, final_meta, sys.argv[2])

main()

