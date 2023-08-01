# anal/d

This directory contains k=v files that are compiled into sdb databases or gperf
structures and this is used for the code analysis and type propagation logic.

## Files of interest

* spec.sdb.txt = format modifiers like %p %d %s its used for type propagation
* types.sdb.txt = basic C-like types
* $os-$bits.sdb.txt = os-arch-bits structs and enums
