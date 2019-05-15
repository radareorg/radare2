import sys

if len(sys.argv)!=2:
    print "Usage:"
    print "   First run 'dumpbin /exports your_file.dll/.lib > your_file_dumpbin.txt'"
    print "   Then run '%s your_file_dumpbin.txt > your_file.sdb.txt'" % (sys.argv[0],)
    print "   Note: this script will strip away function signatures, so overloaded C++ methods will all have the same name"
    sys.exit(1)

d = open(sys.argv[1]).read().split("\n")
for l in d:
    ls = l.split(None, 1)
    if len(ls)!=2:
        continue
    ordinal = ls[0]
    desc = ls[1]
    desc = desc.split("(", 1)
    if len(desc) <= 1:
        sys.stderr.write("Warning, skipping line: " + l + "\n")
        continue
    rawname = desc[0].strip()
    desc = desc[1].strip()
    if desc[-1] != ')':
        sys.stderr.write("Warning, skipping line: " + l + "\n")
        continue
    fulldesc = desc[:-1].strip()
    desc = fulldesc
    if desc.endswith('const'):
        desc = desc[:-len('const')]
    desc = desc.split('(', 1)
    pre = desc[0].strip()
    post = ""
    if len(desc)>1:
        desc = desc[1]
        desc = desc.split(')')
        if len(desc)>1:
            post = desc[-1].strip()
    if post != "":
        sys.stderr.write("Warning, skipping line: " + l + "\n")
        continue
    desc = pre
    i = len(desc) - 1
    deep = 0
    while i >= 0:
        if desc[i] == ">":
            deep += 1
        if desc[i] == "<":
            deep -= 1
        if desc[i] != " ":
            i -= 1
            continue
        if deep > 0:
            i -= 1
            continue
        break
    desc = desc[i+1:]
    print ordinal+"="+desc
