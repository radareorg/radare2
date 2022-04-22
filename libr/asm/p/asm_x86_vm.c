/* radare2 - LGPL - Copyright 2018 - wargio */

/*
	"Missing" vm ops:

	0F 01 C0 vmxoff
	0F 01 C1 vmcall
	0F 01 C2 vmlaunch
	0F 01 C3 vmresume
	0F 01 C4 vmxon
	0F 78 /r vmread r/m32,r32
	0F 79 /r vmwrite r32,r/m32
	0F C7 /6 m64 vmptrld m64
	0F C7 /7 m64 vmptrst m64
	66 0F C7 /6 m64 vmclear m64
	0F A6 /r xbts r32,r/m32
	0F A7 /r ibts r/m32,r32
	0F 37 getsec
	F0 FA clx
	F0 FB stx
	? smret
	? smcall
	? skinit
	? stgi

*/

#define VPCEXT2(y,x) ((y)[2]==(x))

void decompile_vm(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	r_strf_buffer (64);
	const char *buf_asm = "invalid";
	if (len > 3 && buf[0] == 0x0F && buf[1] == 0x3F && (VPCEXT2 (buf, 0x01) || VPCEXT2 (buf, 0x05) || VPCEXT2 (buf, 0x07) || VPCEXT2 (buf, 0x0D) || VPCEXT2 (buf, 0x10))) {
		if (a->config->syntax == R_ASM_SYNTAX_ATT) {
			buf_asm = r_strf ("vpcext $0x%x, $0x%x", buf[3], buf[2]);
		} else {
			buf_asm = r_strf ("vpcext %xh, %xh", buf[2], buf[3]);
		}
		op->size = 4;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x00) {
		/* 0F C6 28 00 00 vmgetinfo */
		buf_asm ="vmgetinfo";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x01) {
		/* 0F C6 28 00 01 vmsetinfo */
		buf_asm ="vmsetinfo";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x02) {
		/* 0F C6 28 00 02 vmdxdsbl */
		buf_asm ="vmdxdsbl";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x03) {
		/* 0F C6 28 00 03 vmdxenbl */
		buf_asm ="vmdxenbl";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x01 && buf[4] == 0x00) {
		/* 0F C6 28 01 00 vmcpuid */
		buf_asm ="vmcpuid";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x01 && buf[4] == 0x01) {
		/* 0F C6 28 01 01 vmhlt */
		buf_asm ="vmhlt";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x01 && buf[4] == 0x02) {
		/* 0F C6 28 01 02 vmsplaf */
		buf_asm ="vmsplaf";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x00) {
		/* 0F C6 28 02 00 vmpushfd */
		buf_asm ="vmpushfd";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x01) {
		/* 0F C6 28 02 01 vmpopfd */
		buf_asm ="vmpopfd";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x02) {
		/* 0F C6 28 02 02 vmcli */
		buf_asm ="vmcli";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x03) {
		/* 0F C6 28 02 03 vmsti */
		buf_asm ="vmsti";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x04) {
		/* 0F C6 28 02 04 vmiretd */
		buf_asm ="vmiretd";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x00) {
		/* 0F C6 28 03 00 vmsgdt */
		buf_asm ="vmsgdt";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x01) {
		/* 0F C6 28 03 01 vmsidt */
		buf_asm ="vmsidt";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x02) {
		/* 0F C6 28 03 02 vmsldt */
		buf_asm ="vmsldt";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x03) {
		/* 0F C6 28 03 03 vmstr */
		buf_asm ="vmstr";
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x04 && buf[4] == 0x00) {
		/* 0F C6 28 04 00 vmsdte */
		buf_asm ="vmsdte";
		op->size = 5;
	}
	r_asm_op_set_asm (op, buf_asm);
}

#undef VPCEXT2
