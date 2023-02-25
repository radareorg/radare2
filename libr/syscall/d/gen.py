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
			kv = line.rstrip().split("=", 1)
			if kv[0] == "_":
				res += line
			else:
				vv = kv[1].split(",")
				res += vv[0] + "." + vv[1] + "=" + kv[0] + "\n"
				res += line
		with open(_tmpfile, "w") as file:
			file.write(res)
	subprocess.call([sdb_exe, _output, "==", _tmpfile])
except Exception as e:
	print(e)
	print("Usage: gen.py [sdb_exe] [input] [output]")

