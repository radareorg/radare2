#!/usr/bin/r2 - -qi
# Usage:
#   r2 -qi all68k - > all68k.txt
#

e scr.color=0
e asm.arch=m68k
e asm.nbytes=16

(mmm,woa 01 @!1,255.(nnn))
(nnn,pd 1,woa 01 @$$+1!1)
255.(mmm)
