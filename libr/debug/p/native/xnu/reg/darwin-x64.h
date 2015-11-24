return strdup (
"=PC	rip\n"
"=SP	rsp\n"
"=BP	rbp\n"
"=A0	rax\n"
"=A1	rbx\n"
"=A2	rcx\n"
"=A3	rdx\n"
"=ZF	zf\n"
"=OF	of\n"
"=SF	sf\n"
"=CF	cf\n"
"gpr	rax	.64	0	0\n"
"gpr	eax	.32	0	0\n"
"gpr	ax	.16	0	0\n"
"gpr	ah	.8	1	0\n"
"gpr	al	.8	0	0\n"
"gpr	rbx	.64	8	0\n"
"gpr	ebx	.32	8	0\n"
"gpr	bx	.16	8	0\n"
"gpr	bh	.8	9	0\n"
"gpr	bl	.8	8	0\n"
"gpr	rcx	.64	8	0\n"
"gpr	ecx	.32	16	0\n"
"gpr	cx	.16	16	0\n"
"gpr	ch	.8	17	0\n"
"gpr	cl	.8	16	0\n"
"gpr	rdx	.64	24	0\n"
"gpr	edx	.32	24	0\n"
"gpr	dx	.16	24	0\n"
"gpr	dh	.8	25	0\n"
"gpr	dl	.8	24	0\n"
"gpr	rdi	.64	32	0\n"
"gpr	edi	.32	32	0\n"
"gpr	rsi	.64	40	0\n"
"gpr	esi	.32	40	0\n"
"gpr	rbp	.64	48	0\n"
"gpr	rsp	.64	56	0\n"
"gpr	r8	.64	64	0\n"
"gpr	r9	.64	72	0\n"
"gpr	r10	.64	80	0\n"
"gpr	r11	.64	88	0\n"
"gpr	r12	.64	96	0\n"
"gpr	r13	.64	104	0\n"
"gpr	r14	.64	112	0\n"
"gpr	r15	.64	120	0\n"
"gpr	rip	.64	128	0\n"
"gpr	eflags	.32	136	0	c1p.a.zstido.n.rv\n"
"gpr	rflags	.64	136	0	c1p.a.zstido.n.rv\n"
"gpr	cf	.1	.1152	0	carry\n"
"gpr	pf	.1	.1154	0	parity\n"
"gpr	af	.1	.1156	0	adjust\n"
"gpr	zf	.1	.1158	0	zero\n"
"gpr	sf	.1	.1159	0	sign\n"
"gpr	tf	.1	.1160	0	trap\n"
"gpr	if	.1	.1161	0	interrupt\n"
"gpr	df	.1	.1162	0	direction\n"
"gpr	of	.1	.1163	0	overflow\n"
"seg	cs	.64	136	0\n"
"seg	fs	.64	144	0\n"
"seg	gs	.64	152	0\n"

"drx	dr0	.64	0	0\n"
"drx	dr1	.64	8	0\n"
"drx	dr2	.64	16	0\n"
"drx	dr3	.64	24	0\n"
"drx 	dr4	.64	32	0\n"
"drx	dr5 	.64	40	0\n"
"drx	dr6	.64	48	0\n"
"drx	dr7	.64	56	0\n"
);


/*_STRUCT_X86_DEBUG_STATE64
{
	__uint64_t	dr0;
	__uint64_t	dr1;
	__uint64_t	dr2;
	__uint64_t	dr3;
	__uint64_t	dr4;
	__uint64_t	dr5;
	__uint64_t	dr6;
	__uint64_t	dr7;
};
*/
