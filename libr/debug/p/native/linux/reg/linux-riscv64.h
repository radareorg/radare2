return strdup (
	"=PC	pc\n"
	"=SP	sp\n"
	"=BP	bp\n"
	"=R0	a0\n"
	"=R1	a1\n"
	"=A0	a0\n"
	"=A1	a1\n"
	"=A2	a2\n"
	"=A3	a3\n"
	"=A4	a4\n"
	"gpr	pc	.64	0	0\n" // program counter
	"gpr	ra	.64	8	0\n" // RA - return address
	"gpr	sp	.64	16	0\n" // SP stack pointer
	"gpr	gp	.64	24	0\n" // GP global pointer
	"gpr	tp	.64	32	0\n" // TP thread pointer
	"gpr	t0	.64	40	0\n" // FP frame pointer -- BP
	"gpr	t1	.64	48	0\n"
	"gpr	t2	.64	56	0\n"
	"gpr	s0	.64	64	0\n"
	"gpr	s1	.64	72	0\n"
	"gpr	a0	.64	80	0\n"
	"gpr	a1	.64	88	0\n"
	"gpr	a2	.64	96	0\n"
	"gpr	a3	.64	104	0\n"
	"gpr	a4	.64	112	0\n"
	"gpr	a5	.64	120	0\n"
	/* saved */
	"gpr	a6	.64	128	0\n"
	"gpr	a7	.64	136	0\n"
	"gpr	s2	.64	144	0\n"
	"gpr	s3	.64	152	0\n"
	"gpr	s4	.64	160	0\n"
	"gpr	s5	.64	168	0\n"
	"gpr	s6	.64	176	0\n"
	"gpr	s7	.64	184	0\n"
	/* tmp */
	"gpr	s8	.64	192	0\n"
	"gpr	s10	.64	200	0\n"
	/* special */
	"gpr	s11	.64	208	0\n"
	"gpr	t3	.64	216	0\n"
	"gpr	t4	.64	224	0\n"
	"gpr	t5	.64	232	0\n"
	"gpr	t6	.64	240	0\n"
	);
