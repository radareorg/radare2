// 32bit host debugging 32bit target
return strdup (
"=PC	eip\n"
"=SP	esp\n"
"=BP	ebp\n"
"=A0	eax\n"
"=A1	ebx\n"
"=A2	ecx\n"
"=A3	edx\n"
"=SN	oeax\n"
"gpr	eax	.32	24	0\n"
"gpr	ax	.16	24	0\n"
"gpr	ah	.8	25	0\n"
"gpr	al	.8	24	0\n"
"gpr	ebx	.32	0	0\n"
"gpr	bx	.16	0	0\n"
"gpr	bh	.8	1	0\n"
"gpr	bl	.8	0	0\n"
"gpr	ecx	.32	4	0\n"
"gpr	cx	.16	4	0\n"
"gpr	ch	.8	5	0\n"
"gpr	cl	.8	4	0\n"
"gpr	edx	.32	8	0\n"
"gpr	dx	.16	8	0\n"
"gpr	dh	.8	9	0\n"
"gpr	dl	.8	8	0\n"
"gpr	esi	.32	12	0\n"
"gpr	si	.16	12	0\n"
"gpr	edi	.32	16	0\n"
"gpr	di	.16	16	0\n"
"gpr	esp	.32	60	0\n"
"gpr	sp	.16	60	0\n"
"gpr	ebp	.32	20	0\n"
"gpr	bp	.16	20	0\n"
"gpr	eip	.32	48	0\n"
"gpr	ip	.16	48	0\n"
"seg@gpr	xfs	.32	36	0\n"
"seg@gpr	xgs	.32	40	0\n"
"seg@gpr	xcs	.32	52	0\n"
"seg@gpr	cs	.16	52	0\n"
"seg@gpr	xss	.32	52	0\n"
"gpr	eflags	.32	56	0	c1p.a.zstido.n.rv\n"
"gpr	flags	.16	56	0\n"
"gpr	cf	.1	.448	0	carry\n"
"gpr	pf	.1	.450	0	parity\n"
"gpr	af	.1	.452	0	adjust\n"
"gpr	zf	.1	.454	0	zero\n"
"gpr	sf	.1	.455	0	sign\n"
"gpr	tf	.1	.456	0	trap\n"
"gpr	if	.1	.457	0	interrupt\n"
"gpr	df	.1	.458	0	direction\n"
"gpr	of	.1	.459	0	overflow\n"
"gpr	oeax	.32	44	0\n"
"drx	dr0	.32	0	0\n"
"drx	dr1	.32	4	0\n"
"drx	dr2	.32	8	0\n"
"drx	dr3	.32	12	0\n"
//"drx	dr4	.32	16	0\n"
//"drx	dr5	.32	20	0\n"
"drx	dr6	.32	24	0\n"
"drx	dr7	.32	28	0\n"
/*struct user_fpxregs_struct
{
  unsigned short int cwd;
  unsigned short int swd;
  unsigned short int twd;
  unsigned short int fop;
  long int fip;
  long int fcs;
  long int foo;
  long int fos;
  long int mxcsr;
  long int reserved;
  long int st_space[32];   // 8*16 bytes for each FP-reg = 128 bytes
  long int xmm_space[32];  // 8*16 bytes for each XMM-reg = 128 bytes
  long int padding[56];
};*/
"fpu	cwd	.16	0	0\n"
"fpu	swd	.16	2	0\n"
"fpu	twd	.16	4	0\n"
"fpu	fop	.16	6	0\n"
"fpu	fip	.32	8	0\n"
"fpu	fcs	.32	12	0\n"
"fpu	foo	.32	16	0\n"
"fpu	fos	.32	20	0\n"
"fpu	mxcsr	.32	24	0\n"

"fpu	st0	.64	32	0\n"
"fpu	st1	.64	48	0\n"
"fpu	st2	.64	64	0\n"
"fpu	st3	.64	80	0\n"
"fpu	st4	.64	96	0\n"
"fpu	st5	.64	112	0\n"
"fpu	st6	.64	128	0\n"
"fpu	st7	.64	144	0\n"

"fpu	xmm0h	.64	160	0\n"
"fpu	xmm0l	.64	168	0\n"

"fpu	xmm1h	.64	176	0\n"
"fpu	xmm1l	.64	184	0\n"

"fpu	xmm2h	.64	192	0\n"
"fpu	xmm2l	.64	200	0\n"

"fpu	xmm3h	.64	208	0\n"
"fpu	xmm3l	.64	216	0\n"

"fpu	xmm4h	.64	224	0\n"
"fpu	xmm4l	.64	232	0\n"

"fpu	xmm5h	.64	240	0\n"
"fpu	xmm5l	.64	248	0\n"

"fpu	xmm6h	.64	256	0\n"
"fpu	xmm6l	.64	264	0\n"

"fpu	xmm7h	.64	272	0\n"
"fpu	xmm7l	.64	280	0\n"
"fpu	x86	.64	288	0\n"

);

