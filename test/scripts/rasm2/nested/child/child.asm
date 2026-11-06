.set R2_ASM_NESTED 1
.if R2_ASM_NESTED
.byte 2
.include leaf.asm
.endif
.byte 4