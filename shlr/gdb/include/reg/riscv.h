return strdup (
	"=PC	pc\n"
	"=SP	sp\n" // ABI: stack pointer
	"=LR	ra\n" // ABI: return address
	"=BP	s0\n" // ABI: frame pointer
	"=A0	a0\n"
	"=A1	a1\n"
	"=A2	a2\n"
	"=A3	a3\n"
	"=A4	a4\n"
	"=A5	a5\n"
	"=A6	a6\n"
	"=A7	a7\n"
	"=R0	a0\n"
	"=R1	a1\n"
	"=SN	a7\n" // ABI: syscall numer
	"gpr	zero	.32	0	0\n" // seems to be allocated in the arena too
	// RV64I regs (ABI names)
	// From user-Level ISA Specification, section 2.1 and 4.1
	// "zero" has been left out as it ignores writes and always reads as zero
	"gpr	ra	.64	8	0\n" // =x1
	"gpr	sp	.64	16	0\n" // =x2
	"gpr	gp	.64	24	0\n" // =x3
	"gpr	tp	.64	32	0\n" // =x4
	"gpr	t0	.64	40	0\n" // =x5
	"gpr	t1	.64	48	0\n" // =x6
	"gpr	t2	.64	56	0\n" // =x7
	"gpr	s0	.64	64	0\n" // =x8 // fp
	"gpr	s1	.64	72	0\n" // =x9
	"gpr	a0	.64	80	0\n" // =x10
	"gpr	a1	.64	88	0\n" // =x11
	"gpr	a2	.64	96	0\n" // =x12
	"gpr	a3	.64	104	0\n" // =x13
	"gpr	a4	.64	112	0\n" // =x14
	"gpr	a5	.64	120	0\n" // =x15
	"gpr	a6	.64	128	0\n" // =x16
	"gpr	a7	.64	136	0\n" // =x17
	"gpr	s2	.64	144	0\n" // =x18
	"gpr	s3	.64	152	0\n" // =x19
	"gpr	s4	.64	160	0\n" // =x20
	"gpr	s5	.64	168	0\n" // =x21
	"gpr	s6	.64	176	0\n" // =x22
	"gpr	s7	.64	184	0\n" // =x23
	"gpr	s8	.64	192	0\n" // =x24
	"gpr	s9	.64	200	0\n" // =x25
	"gpr	s10	.64	208	0\n" // =x26
	"gpr	s11	.64	216	0\n" // =x27
	"gpr	t3	.64	224	0\n" // =x28
	"gpr	t4	.64	232	0\n" // =x29
	"gpr	t5	.64	240	0\n" // =x30
	"gpr	t6	.64	248	0\n" // =x31
	"gpr	pc	.64	248	0\n"
);
