#if 0
ut32 gpr[13]
ut32 sp -- r13
ut32 lr -- r14
ut32 pc -- r15
ut32 cpsr -- program status
--> ut32[17]
// TODO: add
MMX: NEON
	ut128 v[32] // or 16 in arm32
	ut32 fpsr;
	ut32 fpcr;
VFP: FPU
	ut32 r[64]
	ut32 fpscr
#endif
return strdup (
"=PC	r15\n"
"=LR	r14\n"
"=SP	r13\n"
"=BP	fp\n"
"=A0	r0\n"
"=A1	r1\n"
"=A2	r2\n"
"=A3	r3\n"
"gpr	r0	.32	0	0\n"
"gpr	r1	.32	4	0\n"
"gpr	r2	.32	8	0\n"
"gpr	r3	.32	12	0\n"
"gpr	r4	.32	16	0\n"
"gpr	r5	.32	20	0\n"
"gpr	r6	.32	24	0\n"
"gpr	r7	.32	28	0\n"
"gpr	r8	.32	32	0\n"
"gpr	r9	.32	36	0\n"
"gpr	r10	.32	40	0\n"
"gpr	r11	.32	44	0\n"
"gpr	r12	.32	48	0\n"
"gpr	r13	.32	52	0\n"
"gpr	r14	.32	56	0\n"
"gpr	r15	.32	60	0\n"
"gpr	cpsr	.32	64	0\n"
"gpr	nf	.1	.512	0	sign\n" // msb bit of last op
"gpr	zf	.1	.513	0	zero\n" // set if last op is 0
"gpr	cf	.1	.514	0	carry\n" // set if last op carries
"gpr	vf	.1	.515	0	overflow\n" // set if overflows
"gpr	thumb	.1	.517	0	thumb\n"
);
