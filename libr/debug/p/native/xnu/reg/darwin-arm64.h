#if 0
        __ut64    __x[29];  /* General purpose registers x0-x28 */
        __ut64    __fp;             /* Frame pointer x29 */ //// 232
        __ut64    __lr;             /* Link register x30 */
        __ut64    __sp;             /* Stack pointer x31 */
        __ut64    __pc;             /* Program counter */
        __uint32_t    __cpsr;   /* Current program status register */
#endif
return strdup (
"=PC	pc\n"
"=SN	x16\n"
"=SP	sp\n" // XXX
"=BP	x30\n" // XXX
"=A0	x0\n"
"=A1	x1\n"
"=A2	x2\n"
"=A3	x3\n"
"=ZF	zf\n"
"=SF	nf\n"
"=OF	vf\n"
"=CF	cf\n"
"gpr	x0	.64	0	0\n"
"gpr	x1	.64	8	0\n"
"gpr	x2	.64	16	0\n"
"gpr	x3	.64	24	0\n"
"gpr	x4	.64	32	0\n"
"gpr	x5	.64	40	0\n"
"gpr	x6	.64	48	0\n"
"gpr	x7	.64	56	0\n"
"gpr	x8	.64	64	0\n"
"gpr	x9	.64	72	0\n"
"gpr	x10	.64	80	0\n"
"gpr	x11	.64	88	0\n"
"gpr	x12	.64	96	0\n"
"gpr	x13	.64	104	0\n"
"gpr	x14	.64	112	0\n"
"gpr	x15	.64	120	0\n"
"gpr	x16	.64	128	0\n"
"gpr	x17	.64	136	0\n"
"gpr	x18	.64	144	0\n"
"gpr	x19	.64	152	0\n"
"gpr	x20	.64	160	0\n"
"gpr	x21	.64	168	0\n"
"gpr	x22	.64	176	0\n"
"gpr	x23	.64	184	0\n"
"gpr	x24	.64	192	0\n"
"gpr	x25	.64	200	0\n"
"gpr	x26	.64	208	0\n"
"gpr	x27	.64	216	0\n"
"gpr	x28	.64	224	0\n"
"gpr	x29	.64	232	0\n"
"gpr	x30	.64	240	0\n"
// "gpr	x31	.64	248	0\n" // LR
// words (32bit lower part of x
"gpr	w0	.32	0	0\n" // w0
"gpr	w1	.32	8	0\n" // w0
"gpr	w2	.32	16	0\n" // w0
"gpr	w3	.32	24	0\n" // w0
"gpr	w4	.32	32	0\n" // w0
"gpr	w5	.32	40	0\n" // w0
"gpr	w6	.32	48	0\n" // w0
"gpr	w7	.32	56	0\n" // w0
"gpr	w8	.32	64	0\n" // w0
"gpr	w9	.32	72	0\n" // w0
"gpr	w10	.32	80	0\n" // w0
"gpr	w11	.32	88	0\n" // w0
"gpr	w12	.32	96	0\n" // w0
"gpr	w13	.32	104	0\n" // w0
"gpr	w14	.32	112	0\n" // w0
"gpr	w15	.32	120	0\n" // w0
"gpr	w16	.32	128	0\n" // w0
"gpr	w17	.32	136	0\n" // w0
"gpr	w18	.32	144	0\n" // w0
"gpr	w19	.32	152	0\n" // w0
"gpr	w20	.32	160	0\n" // w0
"gpr	w21	.32	168	0\n" // w0
"gpr	w22	.32	176	0\n" // w0
"gpr	w23	.32	184	0\n" // w0
"gpr	w24	.32	192	0\n" // w0
"gpr	w25	.32	200	0\n" // w0
"gpr	w26	.32	208	0\n" // w0
"gpr	w27	.32	216	0\n" // w0
"gpr	w28	.32	224	0\n" // w0
"gpr	w29	.32	232	0\n" // w0
"gpr	w30	.32	240	0\n" // w0
"gpr	xzr	.64	?	0\n" // w0
"gpr	wzr	.32	?	0\n" // w0
"gpr	zr	.64	?	0\n" // w0
"gpr	tmp	.64	?	0\n" // tmp - imaginary register used by esil
// special registers
"gpr	fp	.64	232	0\n" // FP
"gpr	lr	.64	240	0\n" // LR X30
"gpr	sp	.64	248	0\n" // SP
"gpr	pc	.64	256	0\n" // PC
"gpr	pstate	.64	264	0   _____tfiae_____________j__qvczn\n" // x0
"gpr	vf	.1	264.28	0	overflow\n" // set if overflows
"gpr	cf	.1	264.29	0	carry\n" // set if last op carries
"gpr	zf	.1	264.30	0	zero\n" // set if last op is 0
"gpr	nf	.1	264.31	0	sign\n" // msb bit of last op
);

