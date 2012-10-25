#!/usr/bin/python2

from r2.r_core import RBreakpoint

a = RBreakpoint ()
a.use ('x86')
a.add_hw (0x8048000, 10, 0)
a.add_sw (0x8048000, 10, 0)
a.list (False)
