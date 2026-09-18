the 'ls' in this directory shows repeatd snprintf symbols, they all have the same vaddr, paddr, not sure about the haddr, but i assume the c++ awful linker shit crap here and its confusing users. it is worth avoiding dupped symbols for perf reasons or is this a bug in the parser? analyze the bug and solve it.

the ls comes from termux. and i bet theres a binary in test/bins, so we may write an r2r with another binary that lives in there to confirm the bug is gone
