Brainfuck support for r2
========================

Plugins for brainfuck:
  - `asm.bf` - brainfuck assembler and disassembler
  - `debug.bf` - debugger using bfvm
  - `anal.bf` - code analysis for brainfuck
  - `bp.bf` - breakpoints support (experimental)

To debug a brainfuck program:

    r2 -D bf bfdbg:///tmp/bf

    > dc    # continue
    > x@scr # show screen buffer contents

The debugger creates virtual sections for code, data, screen and input.

TODO 
----
- add support for comments, ignore invalid instructions as nops
- enhance io and debugger plugins to generate sections and set arch opts

Hello World
===========

```
>+++++++++[<++++++++>-]<.>+++++++[<++++>-]<+.+++++++..+++.[-]
>++++++++[<++++>-] <.>+++++++++++[<++++++++>-]<-.--------.+++
.------.--------.[-]>++++++++[<++++>- ]<+.[-]++++++++++.
```

```
$ cat << EOF
>+++++++++[<++++++++>-]<.>+++++++[<++++>-]<+.+++++++..+++.[-]>++++++++[<++++>-] <.>+++++++++++[<++++++++>-]<-.--------.+++.------.--------.[-]>++++++++[<++++>- ]<+.[-]++++++++++.
EOF
```
