#!/usr/bin/env python

""" Generate the linker file that keeps symbols of bundled static libs out of libr's exports """

import subprocess
import sys

nm, fmt, output = sys.argv[1:4]
syms = set()
for lib in sys.argv[4:]:
	out = subprocess.run([nm, '-g', '--defined-only', lib], capture_output=True, text=True, check=True).stdout
	for line in out.splitlines():
		parts = line.split()
		if len(parts) == 3 and parts[1] not in ('U', 'w', 'v'):
			syms.add(parts[2])

with open(output, 'w') as f:
	if fmt == 'darwin':
		f.write(''.join(s + '\n' for s in sorted(syms)))
	else:
		f.write('{\n  global: *;\n  local:\n')
		f.write(''.join('    ' + s + ';\n' for s in sorted(syms)))
		f.write('};\n')
