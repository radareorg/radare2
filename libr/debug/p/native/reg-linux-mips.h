// XXX wtf
#if 0
	reg      name    usage
	---+-----------+-------------
	0        zero   always zero
	1         at    reserved for assembler
	2-3     v0-v1   expression evaluation, result of function
	4-7     a0-a3   arguments for functions
	8-15    t0-t7   temporary (not preserved across calls)
	16-23   s0-s7   saved temporary (preserved across calls)
	24-25   t8-t9   temporary (not preserved across calls)
	26-27   k0-k1   reserved for OS kernel
	28      gp      points to global area
	29      sp      stack pointer
	30      fp      frame pointer
	31      ra      return address
#if 0
16 /* 0 - 31 are integer registers, 32 - 63 are fp registers.  */
PC = 272
17 #define FPR_BASE        32
18 #define PC              64
19 #define CAUSE           65
20 #define BADVADDR        66
21 #define MMHI            67
22 #define MMLO            68
23 #define FPC_CSR         69
24 #define FPC_EIR         70
#endif

#endif
	return strdup (
	"=pc	pc\n"
	"=sp	sp\n"
	"=bp	fp\n"
	"=a0	a0\n"
	"=a1	a1\n"
	"=a2	a2\n"
	"=a3	a3\n"
	"gpr	zero	.64	0	0\n"
	// XXX DUPPED CAUSES FAILURE "gpr	at	.32	8	0\n"
	"gpr	at	.64	8	0\n"
	"gpr	v0	.64	16	0\n"
	"gpr	v1	.64	24	0\n"
	/* args */
	"gpr	a0	.64	32	0\n"
	"gpr	a1	.64	40	0\n"
	"gpr	a2	.64	48	0\n"
	"gpr	a3	.64	56	0\n"
	/* tmp */
	"gpr	t0	.64	64	0\n"
	"gpr	t1	.64	72	0\n"
	"gpr	t2	.64	80	0\n"
	"gpr	t3	.64	88	0\n"
	"gpr	t4	.64	96	0\n"
	"gpr	t5	.64	104	0\n"
	"gpr	t6	.64	112	0\n"
	"gpr	t7	.64	120	0\n"
	/* saved */
	"gpr	s0	.64	128	0\n"
	"gpr	s1	.64	136	0\n"
	"gpr	s2	.64	144	0\n"
	"gpr	s3	.64	152	0\n"
	"gpr	s4	.64	160	0\n"
	"gpr	s5	.64	168	0\n"
	"gpr	s6	.64	176	0\n"
	"gpr	s7	.64	184	0\n"
	"gpr	s8	.64	192	0\n"
	"gpr	s9	.64	200	0\n"
	/* special */
	"gpr	k0	.64	208	0\n"
	"gpr	k1	.64	216	0\n"
	"gpr	gp	.64	224	0\n"
	"gpr	sp	.64	232	0\n"
	"gpr	fp	.64	240	0\n"
	"gpr	ra	.64	248	0\n"
	/* extra */
	"gpr	pc	.64	272	0\n"
	);
