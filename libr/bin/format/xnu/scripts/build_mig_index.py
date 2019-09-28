#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys, re, json

header = """ /*
 * This file is generated in this way:
 *
 * python2 build_mig_index.py ~/xnu-4570.51.1/bsd/kern/trace_codes traps.json > mig_index.h
 *
 *
 * The traps.json file is generated from any dyld cache using the machtraps.py r2pipe script.
 *
 */
"""

def convert (trace_codes, trap_json):
    data = {}
    with open(trace_codes, 'r') as f:
        for line in f:
            splitted = re.compile('\s+').split(line.rstrip('\n'))
            name = splitted[1]
            code = int(splitted[0], 0)
            klass = code & 0xff000000
            if klass == 0xff000000: # MIG
                name = name.replace('MSG_', '')
                num = (code & 0x00ffffff) >> 2
                data[num] = name

    with open(trap_json, 'r') as f:
        traps = json.loads(f.read())
        for routine in traps:
            num = routine['num']
            if num in data:
                continue
            data[num] = routine['name']

    result = []
    for num in data:
        result.append((num, data[num]))

    result.sort(key = lambda x: x[0])

    print header
    print '#ifndef R_MIG_INDEX_H'
    print '#define R_MIG_INDEX_H\n'

    print '#define R_MIG_INDEX_LEN %d\n' % (len(data) * 2)

    print 'static const char * mig_index[R_MIG_INDEX_LEN] = {'
    for pair in result:
        print '\t"%d", "%s",' % pair
    print '};\n'

    print '#endif'


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'usage %s bsd/kern/trace_codes traps.json' % sys.argv[0]
    else:
        convert(sys.argv[1], sys.argv[2])

