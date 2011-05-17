#!/usr/bin/python

from r_bp import *

a = RBreakpoint ()
a.use ('x86')
a.add_hw (0x8048000, 10, 0)
a.add_sw (0x8048000, 10, 0)
a.list (False)
