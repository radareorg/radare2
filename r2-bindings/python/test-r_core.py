from r2.r_core import *
from r2.r_cons import *

core = RCore()
core.file_open("/bin/ls", False, 0)
core.cmd0("pd 8");

RCons.flush()
