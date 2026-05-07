static char *get_reg_profile(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->config, NULL);
	int bits = as->config->bits;
	switch (bits) {
	case 16:
	case 32:
	case 64:
		break;
	default:
		if (R_SYS_BITS_CHECK (bits, 64)) {
			bits = 64;
		} else {
			bits = 32;
		}
		break;
	}
	const char *p = NULL;
	switch (bits) {
	case 16: p =
		"=PC	ip\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"=R0	ax\n"
		"=A0	ax\n"
		"=A1	bx\n"
		"=A2	cx\n"
		"=A3	dx\n"
		"=A4	si\n"
		"=A5	di\n"
		"=SN	ah\n"
		"=TR	fs\n" // can be %gs too, but well thats can be overriden with the cc abi scripts
		"gpr	ip	.16	48	0\n"
		"gpr	ax	.16	24	0\n"
		"gpr	ah	.8	25	0\n"
		"gpr	al	.8	24	0\n"
		"gpr	bx	.16	0	0\n"
		"gpr	bh	.8	1	0\n"
		"gpr	bl	.8	0	0\n"
		"gpr	cx	.16	4	0\n"
		"gpr	ch	.8	5	0\n"
		"gpr	cl	.8	4	0\n"
		"gpr	dx	.16	8	0\n"
		"gpr	dh	.8	9	0\n"
		"gpr	dl	.8	8	0\n"
		"gpr	sp	.16	60	0\n"
		"gpr	bp	.16	20	0\n"
		"gpr	si	.16	12	0\n"
		"gpr	di	.16	16	0\n"
		"seg	cs	.16	52	0\n"
		"seg	ss	.16	54	0\n"
		"seg	ds	.16	56	0\n"
		"seg	es	.16	58	0\n"
		"gpr	flags	.16	56	0\n"
		"flg	cf	.1	.448	0\n"
		"flg	pf	.1	.449	0\n"
		"flg	af	.1	.450	0\n"
		"flg	zf	.1	.451	0\n"
		"flg	sf	.1	.452	0\n"
		"flg	tf	.1	.453	0\n"
		"flg	if	.1	.454	0\n"
		"flg	df	.1	.455	0\n"
		"flg	of	.1	.456	0\n"
		"flg	rf	.1	.457	0\n";
#if 0
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n"
#endif
		break;
	case 32: p =
		"=PC	eip\n"
		"=SP	esp\n"
		"=BP	ebp\n"
		"=R0	eax\n"
		"=A0	eax\n"
		"=A1	ebx\n"
		"=A2	ecx\n"
		"=A3	edx\n"
		"=A4	esi\n"
		"=A5	edi\n"
		"=SN	eax\n"
		"gpr	eiz	.32	?	0\n"
		"gpr	oeax	.32	44	0\n"
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
		"seg	xfs	.32	36	0\n"
		"seg	xgs	.32	40	0\n"
		"seg	xcs	.32	52	0\n"
		"seg	cs	.16	52	0\n"
		"seg	xss	.32	52	0\n"
		"flg	eflags	.32	.448	0	c1p.a.zstido.n.rv\n"
		"flg	flags	.16	.448	0\n"
		"flg	cf	.1	.448	0\n"
		"flg	pf	.1	.450	0\n"
		"flg	af	.1	.452	0\n"
		"flg	zf	.1	.454	0\n"
		"flg	sf	.1	.455	0\n"
		"flg	tf	.1	.456	0\n"
		"flg	if	.1	.457	0\n"
		"flg	df	.1	.458	0\n"
		"flg	of	.1	.459	0\n"
		"flg	nt	.1	.462	0\n"
		"flg	rf	.1	.464	0\n"
		"flg	vm	.1	.465	0\n"
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n"
		"vec128@fpu    xmm0  .128 160  4\n"
		"vec64@fpu    xmm0l .64 160  0\n"
		"vec64@fpu    xmm0h .64 168  0\n"

		"vec128@fpu    xmm1  .128 176  4\n"
		"fpu    xmm1l .64 176  0\n"
		"fpu    xmm1h .64 184  0\n"

		"vec128@fpu    xmm2  .128 192  4\n"
		"fpu    xmm2l .64 192  0\n"
		"fpu    xmm2h .64 200  0\n"

		"vec128@fpu    xmm3  .128 208  4\n"
		"fpu    xmm3l .64 208  0\n"
		"fpu    xmm3h .64 216  0\n"

		"vec128@fpu    xmm4  .128 224  4\n"
		"fpu    xmm4l .64 224  0\n"
		"fpu    xmm4h .64 232  0\n"

		"vec128@fpu    xmm5  .128 240  4\n"
		"fpu    vec1285l .64 240  0\n"
		"fpu    vec1285h .64 248  0\n"

		"vec128@fpu    xmm6  .128 256  4\n"
		"fpu    vec1286l .64 256  0\n"
		"fpu    vec1286h .64 264  0\n"

		"vec128@fpu    xmm7  .128 272  4\n"
		"fpu    xmm7l .64 272  0\n"
		"fpu    xmm7h .64 280  0\n";

		break;
	case 64:
	{
#if 0
		const char *cc = "cdecl"; // r_anal_cc_default (anal); // R2_590
		const char *args_prof = cc && !strcmp (cc, "ms")
		? // Microsoft x64 CC
		"# RAX     return value\n"
		"# RCX     argument 1\n"
		"# RDX     argument 2\n"
		"# R8      argument 3\n"
		"# R9      argument 4\n"
		"# R10-R11 syscall/sysret\n"
		"# R12-R15 GP preserved\n"
		"# RSI     preserved source\n"
		"# RDI     preserved destination\n"
		"# RSP     stack pointer\n"
		"=PC	rip\n"
		"=SP	rsp\n"
		"=R0	rax\n"
		"=F0	xmm0\n"
		"=BP	rbp\n"
		"=A0	rcx\n"
		"=A1	rdx\n"
		"=A2	r8\n"
		"=A3	r9\n"
		"=SN	rax\n"
		 : // System V AMD64 ABI
#endif
		// R2_590 - this info shouldnt be used as a calling convention if anal.cc is set
		const char *args_prof =
		"=PC	rip\n"
		"=SP	rsp\n"
		"=BP	rbp\n"
		"=R0	rax\n"
		"=A0	rdi\n"
		"=A1	rsi\n"
		"=A2	rdx\n"
		"=A3	rcx\n"
		"=A4	r8\n"
		"=A5	r9\n"
		"=A6	r10\n"
		"=A7	r11\n"
		"=SN	rax\n";
		char *prof = r_str_newf ("%s%s", args_prof,
		 "gpr	rax	.64	80	0\n"
		 "gpr	eax	.32	80	0\n"
		 "gpr	ax	.16	80	0\n"
		 "gpr	al	.8	80	0\n"
		 "gpr	ah	.8	81	0\n"
		 "gpr	rbx	.64	40	0\n"
		 "gpr	ebx	.32	40	0\n"
		 "gpr	bx	.16	40	0\n"
		 "gpr	bl	.8	40	0\n"
		 "gpr	bh	.8	41	0\n"
		 "gpr	rcx	.64	88	0\n"
		 "gpr	ecx	.32	88	0\n"
		 "gpr	cx	.16	88	0\n"
		 "gpr	cl	.8	88	0\n"
		 "gpr	ch	.8	89	0\n"
		 "gpr	rdx	.64	96	0\n"
		 "gpr	edx	.32	96	0\n"
		 "gpr	dx	.16	96	0\n"
		 "gpr	dl	.8	96	0\n"
		 "gpr	dh	.8	97	0\n"
		 "gpr	rsi	.64	104	0\n"
		 "gpr	esi	.32	104	0\n"
		 "gpr	si	.16	104	0\n"
		 "gpr	sil	.8	104	0\n"
		 "gpr	rdi	.64	112	0\n"
		 "gpr	edi	.32	112	0\n"
		 "gpr	di	.16	112	0\n"
		 "gpr	dil	.8	112	0\n"
		 "gpr	r8	.64	72	0\n"
		 "gpr	r8d	.32	72	0\n"
		 "gpr	r8w	.16	72	0\n"
		 "gpr	r8b	.8	72	0\n"
		 "gpr	r9	.64	64	0\n"
		 "gpr	r9d	.32	64	0\n"
		 "gpr	r9w	.16	64	0\n"
		 "gpr	r9b	.8	64	0\n"
		 "gpr	r10	.64	56	0\n"
		 "gpr	r10d	.32	56	0\n"
		 "gpr	r10w	.16	56	0\n"
		 "gpr	r10b	.8	56	0\n"
		 "gpr	r11	.64	48	0\n"
		 "gpr	r11d	.32	48	0\n"
		 "gpr	r11w	.16	48	0\n"
		 "gpr	r11b	.8	48	0\n"
		 "gpr	r12	.64	24	0\n"
		 "gpr	r12d	.32	24	0\n"
		 "gpr	r12w	.16	24	0\n"
		 "gpr	r12b	.8	24	0\n"
		 "gpr	r13	.64	16	0\n"
		 "gpr	r13d	.32	16	0\n"
		 "gpr	r13w	.16	16	0\n"
		 "gpr	r13b	.8	16	0\n"
		 "gpr	r14	.64	8	0\n"
		 "gpr	r14d	.32	8	0\n"
		 "gpr	r14w	.16	8	0\n"
		 "gpr	r14b	.8	8	0\n"
		 "gpr	r15	.64	0	0\n"
		 "gpr	r15d	.32	0	0\n"
		 "gpr	r15w	.16	0	0\n"
		 "gpr	r15b	.8	0	0\n"
		 "gpr	rip	.64	128	0\n"
		 "gpr	rbp	.64	32	0\n"
		 "gpr	ebp	.32	32	0\n"
		 "gpr	bp	.16	32	0\n"
		 "gpr	bpl	.8	32	0\n"
		 "seg	cs	.64	136	0\n"
		 "flg	rflags	.64	144	0	c1p.a.zstido.n.rv\n"
		 "flg	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
		 "flg	cf	.1	144.0	0	carry\n"
		 "flg	pf	.1	144.2	0	parity\n"
		 //"gpr	cf	.1	.1152	0	carry\n"
		 //"gpr	pf	.1	.1154	0	parity\n"
		 "flg	af	.1	144.4	0	adjust\n"
		 "flg	zf	.1	144.6	0	zero\n"
		 "flg	sf	.1	144.7	0	sign\n"
		 "flg	tf	.1	.1160	0	trap\n"
		 "flg	if	.1	.1161	0	interrupt\n"
		 "flg	df	.1	.1162	0	direction\n"
		 "flg	of	.1	.1163	0	overflow\n"

		 "gpr	riz	.64	?	0\n"
		 "gpr	rsp	.64	152	0\n"
		 "gpr	esp	.32	152	0\n"
		 "gpr	sp	.16	152	0\n"
		 "gpr	spl	.8	152	0\n"
		 "seg	ss	.64	160	0\n"
		 "seg	fs_base	.64	168	0\n"
		 "seg	gs_base	.64	176	0\n"
		 "seg	ds	.64	184	0\n"
		 "seg	es	.64	192	0\n"
		 "seg	fs	.64	200	0\n"
		 "seg	gs	.64	208	0\n"
		 "drx	dr0	.64	0	0\n"
		 "drx	dr1	.64	8	0\n"
		 "drx	dr2	.64	16	0\n"
		 "drx	dr3	.64	24	0\n"
		 // dr4 32
		 // dr5 40
		 "drx	dr6	.64	48	0\n"
		 "drx	dr7	.64	56	0\n"

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

		 "vec128@fpu    xmm0  .128 160  4\n"
		 "fpu    xmm0l .64 160  0\n"
		 "fpu    xmm0h .64 168  0\n"

		 "vec128@fpu    xmm1  .128 176  4\n"
		 "fpu    xmm1l .64 176  0\n"
		 "fpu    xmm1h .64 184  0\n"

		 "vec128@fpu    xmm2  .128 192  4\n"
		 "fpu    xmm2l .64 192  0\n"
		 "fpu    xmm2h .64 200  0\n"

		 "vec128@fpu    xmm3  .128 208  4\n"
		 "fpu    xmm3l .64 208  0\n"
		 "fpu    xmm3h .64 216  0\n"

		 "vec128@fpu    xmm4  .128 224  4\n"
		 "fpu    xmm4l .64 224  0\n"
		 "fpu    xmm4h .64 232  0\n"

		 "vec128@fpu    xmm5  .128 240  4\n"
		 "fpu    xmm5l .64 240  0\n"
		 "fpu    xmm5h .64 248  0\n"

		 "vec128@fpu    xmm6  .128 256  4\n"
		 "fpu    xmm6l .64 256  0\n"
		 "fpu    xmm6h .64 264  0\n"

		 "vec128@fpu    xmm7  .128 272  4\n"
		 "fpu    xmm7l .64 272  0\n"
		 "fpu    xmm7h .64 280  0\n"
		 "fpu    x64   .64 288  0\n");
		return prof;
	}
	}
	return (R_STR_ISNOTEMPTY (p))? strdup (p): NULL;
}
