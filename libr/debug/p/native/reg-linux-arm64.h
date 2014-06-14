return strdup (
"=pc	pc\n"
"=sp	sp\n" // XXX
"=a0	x0\n"
"=a1	x1\n"
"=a2	x2\n"
"=a3	x3\n"
"=zf	zf\n"
"=sf	nf\n"
"=of	vf\n"
"=cf	cf\n"
"=sn	ox0\n"
"gpr	x0	.64	0	0\n" // x0
"gpr	x1	.64	8	0\n" // x0
"gpr	x2	.64	16	0\n" // x0
"gpr	x3	.64	24	0\n" // x0
"gpr	x4	.64	32	0\n" // x0
"gpr	x5	.64	40	0\n" // x0
"gpr	x6	.64	48	0\n" // x0
"gpr	x7	.64	56	0\n" // x0
"gpr	x8	.64	64	0\n" // x0
"gpr	x9	.64	72	0\n" // x0
"gpr	x10	.64	80	0\n" // x0
"gpr	x11	.64	88	0\n" // x0
"gpr	x12	.64	96	0\n" // x0
"gpr	x13	.64	104	0\n" // x0
"gpr	x14	.64	112	0\n" // x0
"gpr	x15	.64	120	0\n" // x0
"gpr	x16	.64	128	0\n" // x0
"gpr	x17	.64	136	0\n" // x0
"gpr	x18	.64	144	0\n" // x0
"gpr	x19	.64	152	0\n" // x0
"gpr	x20	.64	160	0\n" // x0
"gpr	x21	.64	168	0\n" // x0
"gpr	x22	.64	176	0\n" // x0
"gpr	x23	.64	184	0\n" // x0
"gpr	x24	.64	192	0\n" // x0
"gpr	x25	.64	200	0\n" // x0
"gpr	x26	.64	208	0\n" // x0
"gpr	x27	.64	216	0\n" // x0
"gpr	x28	.64	224	0\n" // x0
"gpr	x29	.64	232	0\n" // x0
"gpr	x30	.64	240	0\n" // x0
"gpr	pc	.64	248	0\n" // x0
"gpr	pstate	.64	256	0\n" // x0
"gpr	ox0	.64	264	0\n" // x0
"gpr	snr	.64	272	0\n" // x0

// probably wrong
"gpr	nf	.1	.256	0	sign\n" // msb bit of last op
"gpr	zf	.1	.257	0	zero\n" // set if last op is 0
"gpr	cf	.1	.258	0	carry\n" // set if last op carries
"gpr	vf	.1	.515	0	overflow\n" // set if overflows
);
