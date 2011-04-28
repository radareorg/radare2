#!/usr/bin/env python
# Auto-generate radare syscall profile for OpenBSD from syscall.h
# (c) Edd Barrett 2011

import sys
import copy

f = open("/usr/include/sys/syscall.h", "r")

rec = { "name" : None, "args" : None }
recs = {}

for line in f:
    if line.startswith("/* syscall:"):
        # extract syscall name
        openq = line.find('"')
        closeq = line.find('"', openq + 1)
        rec["name"] = line[openq+1:closeq]

        # extract number of args
        args = line.find("args:")
        args = args + len("args: ")
        rec["args"] = line[args:].count('"') / 2
    elif line.startswith("#define"):

        if "SYS_MAXSYSCALL" in line:
            continue

        # extract syscall number
        sp = line.split("\t")
        callnum = sp[2].rstrip()

        # check required info is there
        for i in rec:
            if i == None:
                print("missing info for %s" % str(rec))
                sys.exit(1)
            
        recs[int(callnum)] = (copy.copy(rec))
        rec = { "name" : None, "args" : None }
f.close()


out = open("openbsd.c", "w")
out.write("#include \"r_syscall.h\"\n\n/* syscall-openbsd */\n")
out.write("RSyscallItem syscalls_openbsd_x86[] = {\n")

keys = recs.keys()
for call in keys:
    out.write("  { \"%s\", 0x80, \"%d\", \"%d\" },\n" % 
            (recs[call]["name"], call, recs[call]["args"]))

out.write("};")
out.close()
