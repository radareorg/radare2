#if 0
        __ut64    __x[29];  /* General purpose registers x0-x28 */
        __ut64    __fp;             /* Frame pointer x29 */
        __ut64    __lr;             /* Link register x30 */
        __ut64    __sp;             /* Stack pointer x31 */
        __ut64    __pc;             /* Program counter */
        __uint32_t    __cpsr;   /* Current program status register */
#endif
	return strdup (
	"=pc	pc\n"
	"=sp	sp\n" // XXX
	"=bp	x30\n" // XXX
	"=a0	x0\n"
	"=a1	x1\n"
	"=a2	x2\n"
	"=a3	x3\n"
 	"=zf	zf\n"
 	"=sf	nf\n"
 	"=of	vf\n"
 	"=cf	cf\n"
	"gpr	x0	.64	0	0\n" // r14
	"gpr	x1	.64	8	0\n" // r14
	"gpr	x2	.64	16	0\n" // r14
	"gpr	x3	.64	24	0\n" // r14
	"gpr	x4	.64	32	0\n" // r14
	"gpr	x5	.64	40	0\n" // r14
	"gpr	x6	.64	48	0\n" // r14
	"gpr	x7	.64	56	0\n" // r14
	"gpr	x8	.64	64	0\n" // r14
	"gpr	x9	.64	72	0\n" // r14
	"gpr	x10	.64	80	0\n" // r14
	"gpr	x11	.64	88	0\n" // r14
	"gpr	x12	.64	96	0\n" // r14
	"gpr	x13	.64	104	0\n" // r14
	"gpr	x14	.64	112	0\n" // r14
	"gpr	x15	.64	120	0\n" // r14
	"gpr	x16	.64	128	0\n" // r14
	"gpr	x17	.64	136	0\n" // r14
	"gpr	x18	.64	144	0\n" // r14
	"gpr	x19	.64	152	0\n" // r14
	"gpr	x20	.64	160	0\n" // r14
	"gpr	x21	.64	168	0\n" // r14
	"gpr	x22	.64	176	0\n" // r14
	"gpr	x23	.64	184	0\n" // r14
	"gpr	x24	.64	192	0\n" // r14
	"gpr	x25	.64	200	0\n" // r14
	"gpr	x26	.64	208	0\n" // r14
	"gpr	x27	.64	216	0\n" // r14
	"gpr	x28	.64	224	0\n" // r14
	"gpr	x29	.64	232	0\n" // r14
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
	// TODO complete w list ...
	// special registers
	"gpr	fp	.64	240	0\n" // r15
	"gpr	lr	.64	248	0\n" // r15
	"gpr	sp	.64	256	0\n" // r15
	"gpr	pc	.64	264	0\n" // r15
	"gpr	cpsr	.32	272	0\n" // r16
	// TODO flags
	"gpr	nf	.1	.2176	0	sign\n" // XXX wrong offset
	);

