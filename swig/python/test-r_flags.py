#!/usr/bin/python
import r2.r_flags
f=r2.r_flags.RFlag()
f.set("hello", 10, 20, 0);
f.set("world", 30, 40, 0);
f.list(False)
p=f.get("hello")
print "name: %s"%p.name
print "offs: 0x%x"%p.offset
