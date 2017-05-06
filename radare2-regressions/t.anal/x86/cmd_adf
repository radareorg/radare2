#!/bin/sh

for a in . .. ../.. ; do [ -e $a/tests.sh ] && . $a/tests.sh ; done

NAME='adf analysis on an obfuscated executable'
BROKEN=1
FILE=../../bins/pe/cmd_adf_sample0.exe
ARGS=
CMDS='
e asm.arch=x86
e asm.bits=32
e asm.os=linux
e asm.lines=false
e asm.linesout=false
e asm.bytes=false
e asm.indentspace=0
e asm.jmphints=false
e asm.xrefs=false
e asm.functions=false
e asm.fcncalls=false
e asm.fcnlines=false
e scr.utf8=false
e anal.afterjmp=false
e anal.calls=false
e anal.cjmpref=false
e anal.jmpabove=true
e anal.jmpref=true
e anal.split=true
aaa
adf @ sym.testObf27.exe_VirtMe
.adf @ sym.testObf27.exe_VirtMe
adf @ 0x00560e67
.adf @ 0x00560e67
pd 4 @ 0x00560e67
'
EXPECT='0x00560e67      push esi
0x00560e68      jmp 0x560e7d
0x00560e6d hex length=16 delta=0
0x00560e6d  51e5 d61d 31ea ce05 063b d4d4 1b00 8596  Q...1....;......

0x00560e7d      pop esi
'
run_test
