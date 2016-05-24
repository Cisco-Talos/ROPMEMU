# ROPMEMU framework
#
# tcollect: it collects the necessary and final 
#           traces. Run it after `blocks`
#

import sys, json, os, shutil

def main():
    if len(sys.argv) != 4:
        print "[-] Usage: %s %s %s %s" % (sys.argv[0], "<jlist>", "<dir>", "<new_dir>")
        sys.exit(1)

    j = open(sys.argv[1])
    md5_list = json.load(j)
    j.close()
    clean_list = []
    
    for m in md5_list:
        if m == 0: continue
        if m not in clean_list: clean_list.append(m)
    
    print "[+] Loaded %d labels" % len(clean_list)
    paths = []
    added = []
    
    for r, d, f in os.walk(sys.argv[2]):
        if d: continue
        root = r
        for t in f:
            tracename = os.path.join(root, t)
            basename = os.path.basename(tracename)
            name = basename.split('.')[0]
            if name in clean_list and name not in added: 
                added.append(name)
                paths.append(tracename)

    dirname = sys.argv[3]
    if not os.path.exists(dirname):
        os.makedirs(dirname) 
    
    for p in paths:
        label = os.path.basename(p)
        destination = os.path.join(dirname, label)
        print destination
        shutil.copyfile(p, destination)

main()
