return strdup (
	"=PC	pc\n"
	"=SP	x2\n"
	"=BP	x4\n"
	"=R0	a10\n"
	"=R1	a11\n"
	"=A0	a10\n"
	"=A1	a11\n"
	"=A2	a12\n"
	"=A3	a13\n"
	"=A4	a14\n"
	"gpr	x0	.64	?	0\n" // always zero
	"gpr	x1	.64	8	0\n" // RA - return address
	"gpr	x2	.64	16	0\n" // SP stack pointer
	"gpr	x3	.64	24	0\n" // GP global pointer
	"gpr	x4	.64	32	0\n" // TP thread pointer
	"gpr	x5	.64	40	0\n" // FP frame pointer -- BP
	"gpr	x6	.64	48	0\n"
	"gpr	x7	.64	56	0\n"
	/* tmp */
	"gpr	x8	.64	64	0\n"
	"gpr	x9	.64	72	0\n"
	"gpr	x10	.64	80	0\n"
	"gpr	x11	.64	88	0\n"
	"gpr	x12	.64	96	0\n"
	"gpr	x13	.64	104	0\n"
	"gpr	x14	.64	112	0\n"
	"gpr	x15	.64	120	0\n"
	/* saved */
	"gpr	x16	.64	128	0\n"
	"gpr	x17	.64	136	0\n"
	"gpr	x18	.64	144	0\n"
	"gpr	x19	.64	152	0\n"
	"gpr	x20	.64	160	0\n"
	"gpr	x21	.64	168	0\n"
	"gpr	x22	.64	176	0\n"
	"gpr	x23	.64	184	0\n"
	/* tmp */
	"gpr	x24	.64	192	0\n"
	"gpr	x25	.64	200	0\n"
	/* special */
	"gpr	x26	.64	208	0\n"
	"gpr	x27	.64	216	0\n"
	"gpr	x28	.64	224	0\n"
	"gpr	x29	.64	232	0\n"
	"gpr	x30	.64	240	0\n"
	"gpr	x31	.64	248	0\n"
	);
