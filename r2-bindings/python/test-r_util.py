#!/usr/bin/python

from r2.r_core import *

b = RBuffer ()
print dir(b)


rs = RSystem()
str = rs.cmd_str ("ls", "")
#str = RSystem.cmd_str ("ls", "")
print "((%s))"%str
