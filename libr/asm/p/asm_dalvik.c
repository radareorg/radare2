/* radare - LGPL3 - Copyright 2009-2011 */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <dalvik/opcode.h>

static int pc;

static int disassemble(RAsm *a, RAsmAop *aop, ut8 *buf, ut64 len) {
	int i = (int) buf[0];
	int size = 0;
	int vA, vB, vC;
	char str[1024];

	if (opcodes[i].len <= len) {
		strcpy (aop->buf_asm, opcodes[i].name);
		size = opcodes[i].len;
		switch (opcodes[i].fmt) {
		case fmtop: break;
		case fmtopvAvB:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			sprintf (str, " v%i, v%i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAvBBBB:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, v%i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAAAvBBBB: // buf[1] seems useless :/
			vA = (buf[3]<<8) | buf[2];
			vB = (buf[5]<<8) | buf[4];
			sprintf (str, " v%i, v%i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAA:
			vA = (int) buf[1];
			sprintf (str, " v%i", vA);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAcB:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			sprintf (str, " v%i, %#x", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAcBBBB:
			vA = (int) buf[1];
			short sB = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, %#04hx", vA, sB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAcBBBBBBBB:
			vA = (int) buf[1];
			vB = buf[5]|(buf[4]<<8)|(buf[3]<<16)|(buf[2]<<24);
			sprintf (str, " v%i, %#08x", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAcBBBB0000:
			vA = (int) buf[1];
			vB = 0|(buf[3]<<16)|(buf[2]<<24);
			sprintf (str, " v%i, %#08x", vA, vB);
			if (buf[0] == 19) strcat (str, "00000000"); // const-wide/high16
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAcBBBBBBBBBBBBBBBB:
			vA = (int) buf[1];
			long long int lB = buf[9]|(buf[8]<<8)|(buf[7]<<16)|(buf[6]<<24)|
				((long long int)buf[5]<<32)|((long long int)buf[4]<<40)|
				((long long int)buf[3]<<48)|((long long int)buf[2]<<56);
			sprintf (str, " v%i, 0x%llx", vA, lB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAvBBvCC:
			vA = (int) buf[1];
			vB = (int) buf[2];
			vC = (int) buf[3];
			sprintf (str, " v%i, v%i, v%i", vA, vB, vC);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAvBBcCC:
			vA = (int) buf[1];
			vB = (int) buf[2];
			vC = (int) buf[3];
			sprintf (str, " v%i, v%i, %#x", vA, vB, vC);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAvBcCCCC:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			vC = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, v%i, %#x", vA, vB, vC);
			strcat (aop->buf_asm, str);
			break;
		case fmtoppAA:
			vA = pc + (int) buf[1];
			sprintf (str, " %i", vA);
			strcat (aop->buf_asm, str);
			break;
		case fmtoppAAAA:
			vA = pc + (int) (buf[3] <<8 | buf[2]);
			sprintf (str, " %i", vA);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAApBBBB: //FIXME: pc increments each disas.
			vA = pc + (int) buf[1];
			vB = pc + (int) (buf[3] <<8 | buf[2]);
			sprintf (str, " v%i, %i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtoppAAAAAAAA: //FIXME: Remove pc use
			vA = pc + (int) (buf[5]|(buf[4]<<8)|(buf[3]<<16)|(buf[2]<<24));
			sprintf (str, " %#08x", vA);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAvBpCCCC:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			vC = pc + (int) (buf[3] <<8 | buf[2]);
			sprintf (str, " v%i, v%i, %i", vA, vB, vC);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAApBBBBBBBB:
			vA = (int) buf[1];
			vB = (int) (buf[5]|(buf[4]<<8)|(buf[3]<<16)|(buf[2]<<24));
			sprintf (str, " v%i, %i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtoptinlineI:
			vA = (int) (buf[1] & 0x0f);
			vB = (buf[3]<<8) | buf[2];
			switch (vA) {
				case 1:
					sprintf (str, " {v%i}", buf[4] & 0x0f);
					break;
				case 2:
					sprintf (str, " {v%i, v%i}", buf[4]&0x0f, (buf[4]&0xf0)>>4);
					break;
				case 3:
					sprintf (str, " {v%i, v%i, v%i}", buf[4]&0x0f,
							(buf[4]&0xf0)>>4, buf[5]&0x0f);
					break;
				case 4:
					sprintf (str, " {v%i, v%i, v%i, v%i}", buf[4]&0x0f,
							(buf[4]&0xf0)>>4, buf[5]&0x0f, (buf[5]&0xf0)>>4);
					break;
				default:
					sprintf (str, " {}");
			}
			strcat (aop->buf_asm, str);
			sprintf (str, ", [%04x]", vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtoptinlineIR:
		case fmtoptinvokeVSR:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			vC = (buf[5]<<8) | buf[4];
			sprintf (str, " {v%i..v%i}, [%04x]", vC, vC+vA-1, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtoptinvokeVS:
			vA = (int) (buf[1] & 0xf0)>>4;
			vB = (buf[3]<<8) | buf[2];
			switch (vA) {
				case 1:
					sprintf (str, " {v%i}", buf[4] & 0x0f);
					break;
				case 2:
					sprintf (str, " {v%i, v%i}", buf[4]&0x0f, (buf[4]&0xf0)>>4);
					break;
				case 3:
					sprintf (str, " {v%i, v%i, v%i}", buf[4]&0x0f,
							(buf[4]&0xf0)>>4, buf[5]&0x0f);
					break;
				case 4:
					sprintf (str, " {v%i, v%i, v%i, v%i}", buf[4]&0x0f,
							(buf[4]&0xf0)>>4, buf[5]&0x0f, (buf[5]&0xf0)>>4);
					break;
				default:
					sprintf (str, " {}");
			}
			strcat (aop->buf_asm, str);
			sprintf (str, ", [%04x]", vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAtBBBB:
			//FIXME: strings & class & fieldmust be a dex(r_bin) section
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			if (buf[0] == 0x1a)
				sprintf (str, " v%i, strings+%i", vA, vB);
			else if (buf[0] == 0x1c || buf[0] == 0x1f || buf[0] == 0x22)
				sprintf (str, " v%i, class+%i", vA, vB);
			else
				sprintf (str, " v%i, field+%i", vA, vB);

			strcat (aop->buf_asm, str);
			break;
		case fmtoptopvAvBoCCCC: //FIXME: obj must be a dex(r_bin) section
			vA = (buf[1] & 0x0f);
			vB = (buf[1] & 0xf0)>>4;
			vC = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, v%i, [obj+%04x]", vA, vB, vC);
			strcat (aop->buf_asm, str);
			break;
		case fmtopAAtBBBB: //FIXME: thing must be a dex(r_bin) section
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, thing+%i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAvBtCCCC: //FIXME: class & field must be a dex section
			vA = (buf[1] & 0x0f);
			vB = (buf[1] & 0xf0)>>4;
			vC = (buf[3]<<8) | buf[2];
			if (buf[0] == 0x20 || buf[0] == 0x23) //instance-of & new-array
				sprintf (str, " v%i, v%i, class+%i", vA, vB, vC);
			else
				sprintf (str, " v%i, v%i, field+%i", vA, vB, vC);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvAAtBBBBBBBB: //FIXME: string must be a dex(r_bin) section
			vA = (int) buf[1];
			vB = (int) (buf[5]|(buf[4]<<8)|(buf[3]<<16)|(buf[2]<<24));
			sprintf (str, " v%i, string+%i", vA, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvCCCCmBBBB: //FIXME: class must be a dex(r_bin) section
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			vC = (buf[5]<<8) | buf[4];
			if (buf[0] == 0x25) // filled-new-array/range
				sprintf (str, " {v%i..v%i}, class+%i", vC, vC+vA-1, vB);
			else
				sprintf (str, " {v%i..v%i}, method+%i", vC, vC+vA-1, vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtopvXtBBBB: //FIXME: class & method must be a dex(r_bin) section
			vA = (int) (buf[1] & 0xf0)>>4;
			vB = (buf[3]<<8) | buf[2];
			switch (vA) {
				case 1:
					sprintf (str, " {v%i}", buf[4] & 0x0f);
					break;
				case 2:
					sprintf (str, " {v%i, v%i}", buf[4]&0x0f, (buf[4]&0xf0)>>4);
					break;
				case 3:
					sprintf (str, " {v%i, v%i, v%i}", buf[4]&0x0f,
							(buf[4]&0xf0)>>4, buf[5]&0x0f);
					break;
				case 4:
					sprintf (str, " {v%i, v%i, v%i, v%i}", buf[4]&0x0f,
							(buf[4]&0xf0)>>4, buf[5]&0x0f, (buf[5]&0xf0)>>4);
					break;
				default:
					sprintf (str, " {}");
			}
			strcat (aop->buf_asm, str);
			if (buf[0] == 0x24) // filled-new-array
				sprintf (str, ", class+%i", vB);
			else
				sprintf (str, ", method+%i", vB);
			strcat (aop->buf_asm, str);
			break;
		case fmtoptinvokeI: // Any opcode has this formats
		case fmtoptinvokeIR:
		case fmt00:
		default:
			strcpy (aop->buf_asm, "invalid ");
			size = 2;
		}
		aop->inst_len = size;
	} else {
		strcpy (aop->buf_asm, "invalid ");
		aop->inst_len = len;
		size = len;
	}
	if (size) pc++;
	return size;
}

//TODO
static int assemble(RAsm *a, RAsmAop *aop, const char *buf) {
	int i;
	char *p = strchr (buf,' ');
	if (p) *p = 0;
	for (i=0; i<256; i++)
		if (!strcmp (opcodes[i].name, buf)) {
			r_mem_copyendian (aop->buf, (void*)&i, 4, a->big_endian);
			aop->inst_len = opcodes[i].len;
			return aop->inst_len;
		}
	return 0;
}

static int init (void *user) {
	pc = 0;
	return R_TRUE;
}

RAsmPlugin r_asm_plugin_dalvik = {
	.name = "dalvik",
	.arch = "dalvik",
	.desc = "Dalvik (Android VM) disassembly plugin",
	.bits = (int[]){ 32, 64, 0 },
	.init = &init,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_dalvik
};
#endif
