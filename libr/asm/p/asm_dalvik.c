/* radare - LGPL - Copyright 2009-2014 - earada, pancake */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <dalvik/opcode.h>

static int dalvik_disassemble (RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int i = (int) buf[0];
	int vA, vB, vC;
	char str[1024], *strasm;
	ut64 offset;
	int size = dalvik_opcodes[i].len;
	int payload = 0;

	if (buf[0] == 0x00) { /* nop */
		switch (buf[1]) {
		case 0x01: /* packed-switch-payload */
			// ushort size
			// int first_key
			// int[size] = relative offsets
			{
				unsigned short array_size = buf[2]|(buf[3]<<8);
				int first_key = buf[4]|(buf[5]<<8)|(buf[6]<<16)|(buf[7]<<24);

				sprintf (op->buf_asm, "packed-switch-payload %d, %d",
					array_size, first_key);
				size = 8;
				payload = 2 * (array_size*2);
				len = 0;
			}
			break;
		case 0x02: /* sparse-switch-payload */
			// ushort size
			// int[size] keys
			// int[size] relative offsets
			{
				unsigned short array_size = buf[2]|(buf[3]<<8);
				sprintf (op->buf_asm, "sparse-switch-payload %d",
					array_size);
				size = 4;
				payload = 2 * (array_size*4);
				len = 0;
			}
			break;
		case 0x03: /* fill-array-data-payload */
			// element_width = 2 bytes ushort little endian
			// size = 4 bytes uint
			// ([size*element_width+1)/2)+4
			{
				unsigned short elem_width = buf[2] | (buf[3]<<8);
				unsigned int array_size = buf[4]|(buf[5]<<8)|(buf[6]<<16)|(buf[7]<<24);
				sprintf (op->buf_asm, "fill-array-data-payload %d, %d",
					elem_width, array_size);
				size = 8;
				payload = 2 * ((array_size * elem_width+1)/2);
				len = 0;
			}
			break;
		default:
			/* nop */
			break;
		}
	}
	strasm = NULL;
	if (size <= len) {
		strncpy (op->buf_asm, dalvik_opcodes[i].name, sizeof (op->buf_asm) - 1);
		strasm = strdup (op->buf_asm);
		size = dalvik_opcodes[i].len;
		switch (dalvik_opcodes[i].fmt) {
		case fmtop: break;
		case fmtopvAvB:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			sprintf (str, " v%i, v%i", vA, vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAvBBBB:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, v%i", vA, vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAAAvBBBB: // buf[1] seems useless :/
			vA = (buf[3]<<8) | buf[2];
			vB = (buf[5]<<8) | buf[4];
			sprintf (str, " v%i, v%i", vA, vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAA:
			vA = (int) buf[1];
			sprintf (str, " v%i", vA);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAcB:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			sprintf (str, " v%i, %#x", vA, vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAcBBBB:
			vA = (int) buf[1];
			short sB = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, %#04hx", vA, sB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAcBBBBBBBB:
			vA = (int) buf[1];
			vB = buf[5]|(buf[4]<<8)|(buf[3]<<16)|(buf[2]<<24);
			sprintf (str, " v%i, %#08x", vA, vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAcBBBB0000:
			vA = (int) buf[1];
			vB = 0|(buf[3]<<16)|(buf[2]<<24);
			sprintf (str, " v%i, %#08x", vA, vB);
			if (buf[0] == 19)
				strcat (str, "00000000"); // const-wide/high16
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAcBBBBBBBBBBBBBBBB:
			vA = (int) buf[1];
			long long int lB = buf[9]|(buf[8]<<8)|(buf[7]<<16)|(buf[6]<<24)|
				((long long int)buf[5]<<32)|((long long int)buf[4]<<40)|
				((long long int)buf[3]<<48)|((long long int)buf[2]<<56);
			sprintf (str, " v%i, 0x%"PFMT64x, vA, lB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAvBBvCC:
			vA = (int) buf[1];
			vB = (int) buf[2];
			vC = (int) buf[3];
			sprintf (str, " v%i, v%i, v%i", vA, vB, vC);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAvBBcCC:
			vA = (int) buf[1];
			vB = (int) buf[2];
			vC = (int) buf[3];
			sprintf (str, " v%i, v%i, %#x", vA, vB, vC);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAvBcCCCC:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			vC = (buf[3]<<8) | buf[2];
			sprintf (str, " v%i, v%i, %#x", vA, vB, vC);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoppAA:
			vA = (char) buf[1];
			sprintf (str, " %i", vA*2); // vA : word -> byte
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoppAAAA:
			vA = (short) (buf[3] <<8 | buf[2]);
			sprintf (str, " %i", vA*2); // vA: word -> byte
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAApBBBB:
			vA = (int) buf[1];
			vB = (int) (buf[3] <<8 | buf[2]);
			sprintf (str, " v%i, %i", vA, vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoppAAAAAAAA:
			vA = (int) (buf[2]|(buf[3]<<8)|(buf[4]<<16)|(buf[5]<<24));
			sprintf (str, " %#08x", vA*2); // vA: word -> byte
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAvBpCCCC:
			vA = buf[1] & 0x0f;
			vB = (buf[1] & 0xf0)>>4;
			vC = (int) (buf[3] <<8 | buf[2]);
			sprintf (str, " v%i, v%i, %i", vA, vB, vC);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAApBBBBBBBB:
			vA = (int) buf[1];
			vB = (int) (buf[2]|(buf[3]<<8)|(buf[4]<<16)|(buf[5]<<24));
			sprintf (str, " v%i,%s%i ; 0x%08"PFMT64x,
				vA, vB>0?" +":" ", vB*2, a->pc + (vB*2));
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoptinlineI:
			vA = (int) (buf[1] & 0x0f);
			vB = (buf[3]<<8) | buf[2];
			*str = 0;
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
			strasm = r_str_concat (strasm, str);
			sprintf (str, ", [%04x]", vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoptinlineIR:
		case fmtoptinvokeVSR:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			vC = (buf[5]<<8) | buf[4];
			sprintf (str, " {v%i..v%i}, [%04x]", vC, vC+vA-1, vB);
			strasm = r_str_concat (strasm, str);
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
			strasm = r_str_concat (strasm, str);
			sprintf (str, ", [%04x]", vB);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAtBBBB:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			if (buf[0] == 0x1a) {
				offset = R_ASM_GET_OFFSET(a, 's', vB);
				if (offset == -1)
					sprintf (str, " v%i, string+%i", vA, vB);
				else
					sprintf (str, " v%i, 0x%"PFMT64x, vA, offset);
			} else if (buf[0] == 0x1c || buf[0] == 0x1f || buf[0] == 0x22) {
				offset = R_ASM_GET_OFFSET(a, 'c', vB);
				if (offset == -1)
					sprintf (str, " v%i, class+%i", vA, vB);
				else
					sprintf (str, " v%i, 0x%"PFMT64x, vA, offset);
			} else {
				offset = R_ASM_GET_OFFSET(a, 'f', vB);
				if (offset == -1)
					sprintf (str, " v%i, field+%i", vA, vB);
				else
					sprintf (str, " v%i, 0x%"PFMT64x, vA, offset);
			}
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoptopvAvBoCCCC:
			vA = (buf[1] & 0x0f);
			vB = (buf[1] & 0xf0)>>4;
			vC = (buf[3]<<8) | buf[2];
			offset = R_ASM_GET_OFFSET(a, 'o', vC);
			if (offset == -1)
				sprintf (str, " v%i, v%i, [obj+%04x]", vA, vB, vC);
			else
				sprintf (str, " v%i, v%i, [0x%"PFMT64x"]", vA, vB, offset);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopAAtBBBB:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			offset = R_ASM_GET_OFFSET(a, 't', vB);
			if (offset == -1)
				sprintf (str, " v%i, thing+%i", vA, vB);
			else
				sprintf (str, " v%i, 0x%"PFMT64x, vA, offset);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAvBtCCCC:
			vA = (buf[1] & 0x0f);
			vB = (buf[1] & 0xf0)>>4;
			vC = (buf[3]<<8) | buf[2];
			if (buf[0] == 0x20 || buf[0] == 0x23) { //instance-of & new-array
				offset = R_ASM_GET_OFFSET(a, 'c', vC);
				if (offset == -1)
					sprintf (str, " v%i, v%i, class+%i", vA, vB, vC);
				else
					sprintf (str, " v%i, v%i, 0x%"PFMT64x, vA, vB, offset);
			} else {
				offset = R_ASM_GET_OFFSET(a, 'f', vC);
				if (offset == -1)
					sprintf (str, " v%i, v%i, field+%i", vA, vB, vC);
				else
					sprintf (str, " v%i, v%i, 0x%"PFMT64x, vA, vB, offset);
			}
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvAAtBBBBBBBB:
			vA = (int) buf[1];
			vB = (int) (buf[5]|(buf[4]<<8)|(buf[3]<<16)|(buf[2]<<24));
			offset = R_ASM_GET_OFFSET(a, 's', vB);
			if (offset == -1)
				sprintf (str, " v%i, string+%i", vA, vB);
			else
				sprintf (str, " v%i, 0x%"PFMT64x, vA, offset);
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvCCCCmBBBB:
			vA = (int) buf[1];
			vB = (buf[3]<<8) | buf[2];
			vC = (buf[5]<<8) | buf[4];
			if (buf[0] == 0x25) { // filled-new-array/range
				offset = R_ASM_GET_OFFSET(a, 'c', vB);
				if (offset == -1)
					sprintf (str, " {v%i..v%i}, class+%i", vC, vC+vA-1, vB);
				else
					sprintf (str, " {v%i..v%i}, 0x%"PFMT64x, vC, vC+vA-1, offset);
			} else {
				offset = R_ASM_GET_OFFSET(a, 'm', vB);
				if (offset == -1)
					sprintf (str, " {v%i..v%i}, method+%i", vC, vC+vA-1, vB);
				else
					sprintf (str, " {v%i..v%i}, 0x%"PFMT64x, vC, vC+vA-1, offset);
			}
			strasm = r_str_concat (strasm, str);
			break;
		case fmtopvXtBBBB:
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
			strasm = r_str_concat (strasm, str);
			if (buf[0] == 0x24) { // filled-new-array
				offset = R_ASM_GET_OFFSET(a, 'c', vB);
				if (offset == -1)
					sprintf (str, ", class+%i", vB);
				else
					sprintf (str, ", 0x%"PFMT64x, offset);
			} else {
				offset = R_ASM_GET_OFFSET(a, 'm', vB);
				if (offset == -1)
					sprintf (str, ", method+%i", vB);
				else
					sprintf (str, ", 0x%"PFMT64x, offset);

			}
			strasm = r_str_concat (strasm, str);
			break;
		case fmtoptinvokeI: // Any opcode has this formats
		case fmtoptinvokeIR:
		case fmt00:
		default:
			strcpy (op->buf_asm, "invalid ");
			free (strasm);
			strasm = NULL;
			size = 2;
		}
		if (strasm) {
			strncpy (op->buf_asm, strasm, sizeof (op->buf_asm)-1);
			op->buf_asm[sizeof (op->buf_asm)-1] = 0;
		} else {
			op->buf_asm[0] = 0;
		}
	} else if (len>0) {
		strcpy (op->buf_asm, "invalid ");
		op->size = len;
		size = len;
	}
	op->payload = payload;
	size += payload; // XXX
	// align to 2
	op->size = size;
	return size;
}

//TODO
static int dalvik_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int i;
	char *p = strchr (buf,' ');
	if (p) *p = 0;
	// TODO: use a hashtable here
	for (i=0; i<256; i++)
		if (!strcmp (dalvik_opcodes[i].name, buf)) {
			r_mem_copyendian (op->buf, (void*)&i, 4, a->big_endian);
			op->size = dalvik_opcodes[i].len;
			return op->size;
		}
	return 0;
}

static int init (void *user) {
	return R_TRUE;
}

RAsmPlugin r_asm_plugin_dalvik = {
	.name = "dalvik",
	.arch = "dalvik",
	.license = "LGPL3",
	.desc = "AndroidVM Dalvik",
	.bits = 32|64,
	.init = &init,
	.fini = NULL,
	.disassemble = &dalvik_disassemble,
	.assemble = &dalvik_assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_dalvik
};
#endif
