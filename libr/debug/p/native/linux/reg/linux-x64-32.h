// 64bit host debugging 32bit binary
return strdup (
"=PC	eip\n"
"=SP	esp\n"
"=BP	ebp\n"
"=A0	eax\n"
"=A1	ebx\n"
"=A2	ecx\n"
"=A3	edx\n"
"=ZF	zf\n"
"=SF	sf\n"
"=OF	of\n"
"=CF	cf\n"
"=SN	oeax\n"
"gpr	eip	.32	128	0\n"
"gpr	ip	.16	128	0\n"
"gpr	oeax	.32	120	0\n"
"gpr	eax	.32	80	0\n"
"gpr	ax	.16	80	0\n"
"gpr	ah	.8	81	0\n"
"gpr	al	.8	80	0\n"
"gpr	ebx	.32	40	0\n"
"gpr	bx	.16	40	0\n"
"gpr	bh	.8	41	0\n"
"gpr	bl	.8	40	0\n"
"gpr	ecx	.32	88	0\n"
"gpr	cx	.16	88	0\n"
"gpr	ch	.8	89	0\n"
"gpr	cl	.8	88	0\n"
"gpr	edx	.32	96	0\n"
"gpr	dx	.16	96	0\n"
"gpr	dh	.8	97	0\n"
"gpr	dl	.8	96	0\n"
"gpr	esp	.32	152	0\n"
"gpr	sp	.16	152	0\n"
"gpr	ebp	.32	32	0\n"
"gpr	bp	.16	32	0\n"
"gpr	esi	.32	104	0\n"
"gpr	si	.16	104	0\n"
"gpr	edi	.32	112	0\n"
"gpr	di	.16	112	0\n"
"seg	xfs	.32	200	0\n"
"seg	xgs	.32	208	0\n"
"seg	xcs	.32	136	0\n"
"seg	cs	.16	136	0\n"
"seg	xss	.32	160	0\n"
"gpr	flags	.16	144	0\n"
"gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
"gpr	rflags	.64	144	0	c1p.a.zstido.n.rv\n"
"gpr	cf	.1	.1152	0	carry\n"
"gpr	pf	.1	.1154	0	parity\n"
"gpr	af	.1	.1156	0	adjust\n"
"gpr	zf	.1	.1158	0	zero\n"
"gpr	sf	.1	.1159	0	sign\n"
"gpr	tf	.1	.1160	0	trap\n"
"gpr	if	.1	.1161	0	interrupt\n"
"gpr	df	.1	.1162	0	direction\n"
"gpr	of	.1	.1163	0	overflow\n"
#if 0
"drx	dr0	.64	0	0\n"
"drx	dr1	.64	8	0\n"
"drx	dr2	.64	16	0\n"
"drx	dr3	.64	24	0\n"
// dr4 32
// dr5 40
"drx	dr6	.64	48	0\n"
"drx	dr7	.64	56	0\n"
#endif
"drx	dr0	.32	0	0\n"
"drx	dr1	.32	4	0\n"
"drx	dr2	.32	8	0\n"
"drx	dr3	.32	12	0\n"
//"drx	dr4	.32	16	0\n"
//"drx	dr5	.32	20	0\n"
"drx	dr6	.32	24	0\n"
"drx	dr7	.32	28	0\n"

/*0030 struct user_fpregs_struct
0031 {
0032   __uint16_t        cwd;
0033   __uint16_t        swd;
0034   __uint16_t        ftw;
0035   __uint16_t        fop;
0036   __uint64_t        rip;
0037   __uint64_t        rdp;
0038   __uint32_t        mxcsr;
0039   __uint32_t        mxcr_mask;
0040   __uint32_t        st_space[32];   // 8*16 bytes for each FP-reg = 128 bytes
0041   __uint32_t        xmm_space[64];  // 16*16 bytes for each XMM-reg = 256 bytes
0042   __uint32_t        padding[24];
0043 };
*/

"fpu    cwd .16 0   0\n"
"fpu    swd .16 2   0\n"
"fpu    ftw .16 4   0\n"
"fpu    fop .16 6   0\n"
"fpu    frip .64 8   0\n"
"fpu    frdp .64 16  0\n"
"fpu    mxcsr .32 24  0\n"
"fpu    mxcr_mask .32 28  0\n"

"fpu    st0 .64 32  0\n"
"fpu    st1 .64 48  0\n"
"fpu    st2 .64 64  0\n"
"fpu    st3 .64 80  0\n"
"fpu    st4 .64 96  0\n"
"fpu    st5 .64 112  0\n"
"fpu    st6 .64 128  0\n"
"fpu    st7 .64 144  0\n"

"fpu    xmm0h .64 160  0\n"
"fpu    xmm0l .64 168  0\n"

"fpu    xmm1h .64 176  0\n"
"fpu    xmm1l .64 184  0\n"

"fpu    xmm2h .64 192  0\n"
"fpu    xmm2l .64 200  0\n"

"fpu    xmm3h .64 208  0\n"
"fpu    xmm3l .64 216  0\n"

"fpu    xmm4h .64 224  0\n"
"fpu    xmm4l .64 232  0\n"

"fpu    xmm5h .64 240  0\n"
"fpu    xmm5l .64 248  0\n"

"fpu    xmm6h .64 256  0\n"
"fpu    xmm6l .64 264  0\n"

"fpu    xmm7h .64 272  0\n"
"fpu    xmm7l .64 280  0\n"
"fpu    x64-32 .64 288  0\n"

);

