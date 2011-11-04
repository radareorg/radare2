import sys
try:
	from r_core import RCore
except:
	from r2.r_core import RCore

core = RCore()
core.file_open("/bin/ls", False, 0)
core.cmd0("pd 8");
#
core.cons.flush()
