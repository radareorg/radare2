#!/usr/bin/env python
# args [sdbpath] [input] [output]
import os
import sys
import subprocess


try:
	sdb_exe = sys.argv[1]
	_input = sys.argv[2]
	_output = sys.argv[3]
	_tmpfile = _input + ".tmp"
	with open(_input) as lines:
		res = ""
		for line in lines:
			# E.g. in linux-x86-64.sdb.txt:
			# accept=0x80,43,3,
			# And in linux-arm-64.sdb.txt:
			# accept=0,202
			kv = line.rstrip().split("=", 1)
			if kv[0] == "_":
				res += line
			else:
				vv = kv[1].split(",")
				res += vv[0] + "." + vv[1] + "=" + kv[0] + "\n"
				# Can't just append the original line, because
				# r_syscall_item_new_from_string splits it by commas
				# and wants at least 3 items in the result, whereas
				# original lines, at least in some archs, have only
				# two items. For compatibitity with gen.sh, always
				# have at least 4 items.
				vv.extend([ '' for i in range(4 - len(vv)) ])
				res += kv[0] + "=" + ",".join(vv) + "\n"
		with open(_tmpfile, "w") as file:
			file.write(res)
	subprocess.call([sdb_exe, _output, "==", _tmpfile])
except Exception as e:
	print(e)
	print("Usage: gen.py [sdb_exe] [input] [output]")

