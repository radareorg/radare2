return strdup (
"=SP	r13\n"
"=LR	r14\n"
"=PC	r15\n"
"=A0	r0\n"
"=A1	r1\n"
"=A2	r2\n"
"=A3	r3\n"
"=ZF	zf\n"
"=SF	nf\n"
"=OF	vf\n"
"=CF	cf\n"
"=SN	or0\n"
"gpr	lr	.32	56	0\n" // r14
"gpr	pc	.32	60	0\n" // r15
"gpr	cpsr	.32	64	0	____tfiae_________________qvczn\n" // CSPR
"gpr	or0	.32	68	0\n" // r17 aka ORIG_r0
// cpsr is at .512
"gpr	tf	.1	64.5	0	thumb\n"
"gpr	ef	.1	64.9	0	endian\n"
// ...
"gpr	jf	.1	64.24	0	java\n"
// ...
"gpr	qf	.1	64.27	0	sticky_overflow\n" // +27
"gpr	vf	.1	64.28	0	overflow\n" // +28
"gpr	cf	.1	64.29	0	carry\n" // +29
"gpr	zf	.1	64.30	0	zero\n" // +30
"gpr	nf	.1	64.31	0	negative\n" // +31
// if-then-counter
"gpr	itc	.4	64.10	0	if_then_count\n" // +10
"gpr	gef	.4	64.16	0	great_or_equal\n" // +16

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
"gpr	r16	.32	64	0\n"
"gpr	r17	.32	68	0\n"
);
