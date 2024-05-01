#include <r_util.h>
#include "gmtdisas.h"
#include "ins.h"

static uint32_t prog_mode = 0;
// static uint32_t prog_mode = PROG_MODE_IONAME;

static int Get_IOreg_Name(uint32_t add, char *text) {
	if (!(prog_mode & PROG_MODE_IONAME)) {
		return -1;
	}
	for (int i=0; i<ioreg_cnt; i++) {
		if ( (ioregtable+i)->add == add ) {
			strcpy (text, (ioregtable+i)->name);
			return 0;
		}
	}
	return -1;
}

char *stm8_disasm(ut64 pc, const ut8 *data, int size, unsigned int *type, ut64 *jump, int *len) {
	datablock _block = {
		.start_add = pc,
		.ext_offset = 0,
		.size = size,
		.line_index = 0,
		.data = data
	};
	datablock *block = &_block;
	RStrBuf *sb = r_strbuf_new ("");
	int cnt, n, add, err;
	instruction ins;
	int oc[6];
	char ioname[36];

	cnt = 0;
	add = block->start_add;

	while (cnt < block->size) {
		oc[0] = *(block->data + cnt);
		oc[1] = -1;
		oc[2] = -1;
		oc[3] = -1;
		oc[4] = -1;
		oc[5] = -1;

		err  = 0;
		n    = 1;

		switch (oc[0]) {
		case 0x72:
			oc[1] = *(block->data + cnt + 1);
			ins = ins_table_72[oc[1]];
			n = 2;
			break;
		case 0x90:
			oc[1] = *(block->data + cnt + 1);
			ins = ins_table_90[oc[1]];
			n = 2;
			break;
		case 0x91:
			oc[1] = *(block->data + cnt + 1);
			if ((oc[1] >= 0x60) && (oc[1] <= 0xDF)) {
				ins = ins_table_91_0x60[oc[1] - 0x60];
			} else {
				err = 1;
			}
			n = 2;
			break;
		case 0x92:
			oc[1] = *(block->data + cnt + 1);
			if ((oc[1] >= 0x30) && (oc[1] <= 0xDF)) {
				ins = ins_table_92_0x30[oc[1] - 0x30];
			} else {
				err = 1;
			}
			n = 2;
			break;
		default:
			oc[1] = oc[0];
			oc[0] = -1;
			ins = ins_table[oc[1]];
		}

		if (err || !ins.size) {
			*len = 0;
			return NULL;
			r_strbuf_appendf (sb, ".byte 0x%02x", oc[1]);
			ins.size = 1;
		} else {
			if (ins.type) {
				*type = ins.type;
			}
			r_strbuf_appendf (sb, "%s", ins.text);

			if (n == 1) {
				for (; n < ins.size; n++)
					oc[n+1] = *(block->data + cnt + n);
			} else {
				for (; n < ins.size; n++)
					oc[n] = *(block->data + cnt + n);
			}
			switch (ins.des) {
			case STM8_NONE:
				break;
			case STM8_REG_A:
				r_strbuf_appendf (sb, " a");
				break;
			case STM8_REG_XL:
				r_strbuf_appendf (sb, " xl");
				break;
			case STM8_REG_YL:
				r_strbuf_appendf (sb, " yl");
				break;
			case STM8_REG_XH:
				r_strbuf_appendf (sb, " xh");
				break;
			case STM8_REG_YH:
				r_strbuf_appendf (sb, " yh");
				break;
			case STM8_REG_CC:
				r_strbuf_appendf (sb, " cc");
				break;
			case STM8_REG_X:
				r_strbuf_appendf (sb, " x");
				break;
			case STM8_REG_Y:
				r_strbuf_appendf (sb, " y");
				break;
			case STM8_REG_SP:
				r_strbuf_appendf (sb, " sp");
				break;
			case STM8_IMM_BYTE_2:
				r_strbuf_appendf (sb, " 0x%02x", oc[2]);
				break;
			case STM8_IMM_WORD_23:
				r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
				break;
			case STM8_PTR_X:
				r_strbuf_appendf (sb, " (x)");
				break;
			case STM8_PTR_Y:
				r_strbuf_appendf (sb, " (y)");
				break;
			case SHORTMEM_2:
				r_strbuf_appendf (sb, " 0x%02x", oc[2]);
				break;
			case SHORTMEM_3:
				r_strbuf_appendf (sb, " 0x%02x", oc[3]);
				break;
			case LONGMEM_23:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[2]<<8 | oc[3];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+1) ) {
						ioname[0] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
						*jump = (oc[2] <<8)|oc[3];
					}
				} else {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
					*jump = (oc[2] <<8)|oc[3];
				}
				break;
			case LONGMEM_34:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[3]<<8 | oc[4];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+1) ) {
						ioname[0] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, " 0x%02x%02x", oc[3], oc[4]);
					}
				} else {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[3], oc[4]);
				}
				break;
			case LONGMEM_45:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[4]<<8 | oc[5];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+1) ) {
						ioname[0] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, " 0x%02x%02x", oc[4], oc[5]);
					}
				} else {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[4], oc[5]);
				}
				break;
			case EXTMEM_234:
				r_strbuf_appendf (sb, " 0x%02x%02x%02x", oc[2], oc[3], oc[4]);
				break;
			case SHORTOFF_2:
				(oc[2] & 0x80) ? (n = oc[2] - 0x100) : (n = oc[2]);
#if 0
				r_strbuf_appendf (sb, " .%+-4i ;(0x%06X)",
						(prog_mode & PROG_MODE_REL0) ? (n+ins.size) : n,
						add + ins.size + n);
#else
				r_strbuf_appendf (sb, " 0x%08x", add + ins.size + n);
#endif
				*jump = add + ins.size + n;
				break;
			case SHORTOFF_4:
				(oc[4] & 0x80) ? (n = oc[4] - 0x100) : (n = oc[4]);
#if 0
				r_strbuf_appendf (sb, " .%+-4i ;(0x%06X)",
						(prog_mode & PROG_MODE_REL0) ? (n+ins.size) : n,
						add + ins.size + n);
#else
				r_strbuf_appendf (sb, " 0x%08x", add + ins.size + n);
#endif
				*jump = add + ins.size + n;
				break;
			case SHORTOFF_X_2:
				r_strbuf_appendf (sb, " (0x%02x, x)", oc[2]);
				break;
			case SHORTOFF_Y_2:
				r_strbuf_appendf (sb, " (0x%02x, y)", oc[2]);
				break;
			case SHORTOFF_SP_2:
				r_strbuf_appendf (sb, " (0x%02x, sp)", oc[2]);
				break;
			case LONGOFF_X_23:
				r_strbuf_appendf (sb, " (0x%02x%02x, x)", oc[2], oc[3]);
				break;
			case LONGOFF_Y_23:
				r_strbuf_appendf (sb, " (0x%02x%02x, y)", oc[2], oc[3]);
				break;
			case EXTOFF_X_234:
				r_strbuf_appendf (sb, " (0x%02x%02x%02x, x)", oc[2], oc[3], oc[4]);
				break;
			case EXTOFF_Y_234:
				r_strbuf_appendf (sb, " (0x%02x%02x%02x, y)", oc[2], oc[3], oc[4]);
				break;
			case SHORTPTR_2:
				r_strbuf_appendf (sb, " [0x%02x]", oc[2]);
				break;
			case LONGPTR_23:
				r_strbuf_appendf (sb, " [0x%02x%02x]", oc[2], oc[3]);
				break;
			case SHORTPTR_OFF_X_2:
				r_strbuf_appendf (sb, " ([0x%02x], x)", oc[2]);
				break;
			case SHORTPTR_OFF_Y_2:
				r_strbuf_appendf (sb, " ([0x%02x], y)", oc[2]);
				break;
			case LONGPTR_OFF_X_23:
				r_strbuf_appendf (sb, " ([0x%02x%02x], x)", oc[2], oc[3]);
				break;
			case LONGPTR_OFF_Y_23:
				r_strbuf_appendf (sb, " ([0x%02x%02x], y)", oc[2], oc[3]);
				break;
			case LONGMEM_BIT_123:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[2]<<8 | oc[3];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+1) ) {
						ioname[0] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
					}
				} else {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
				}
				r_strbuf_appendf (sb, ", %d", (oc[1] & 0x0F)>>1);
				break;
			}
			switch (ins.src) {
			case STM8_NONE:
				break;
			case STM8_REG_A:
				r_strbuf_appendf (sb, ", a");
				break;
			case STM8_REG_XL:
				r_strbuf_appendf (sb, ", xl");
				break;
			case STM8_REG_YL:
				r_strbuf_appendf (sb, ", yl");
				break;
			case STM8_REG_XH:
				r_strbuf_appendf (sb, ", xh");
				break;
			case STM8_REG_YH:
				r_strbuf_appendf (sb, ", yh");
				break;
			case STM8_REG_CC:
				r_strbuf_appendf (sb, ", CC");
				break;
			case STM8_REG_X:
				r_strbuf_appendf (sb, ", x");
				break;
			case STM8_REG_Y:
				r_strbuf_appendf (sb, ", y");
				break;
			case STM8_REG_SP:
				r_strbuf_appendf (sb, ", sp");
				break;
			case STM8_IMM_BYTE_2:
				r_strbuf_appendf (sb, ", 0x%02x", oc[2]);
				break;
			case STM8_IMM_WORD_23:
				r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
				break;
			case STM8_PTR_X:
				r_strbuf_appendf (sb, ", (x)");
				break;
			case STM8_PTR_Y:
				r_strbuf_appendf (sb, ", (y)");
				break;
			case SHORTMEM_2:
				r_strbuf_appendf (sb, ", 0x%02x", oc[2]);
				break;
			case SHORTMEM_3:
				r_strbuf_appendf (sb, ", 0x%02x", oc[3]);
				break;
			case LONGMEM_23:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[2]<<8 | oc[3];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+2) ) {
						ioname[0] = ',';
						ioname[1] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
					}
				} else {
					r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
				}
				break;
			case LONGMEM_34:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[3]<<8 | oc[4];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+2) ) {
						ioname[0] = ',';
						ioname[1] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, ", 0x%02x%02x", oc[3], oc[4]);
					}
				} else {
					r_strbuf_appendf (sb, ", 0x%02x%02x", oc[3], oc[4]);
				}
				break;
			case LONGMEM_45:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[4]<<8 | oc[5];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname+2) ) {
						ioname[0] = ',';
						ioname[1] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, ", 0x%02x%02x", oc[4], oc[5]);
					}
				} else {
					r_strbuf_appendf (sb, ", 0x%02x%02x", oc[4], oc[5]);
				}
				break;
			case EXTMEM_234:
				r_strbuf_appendf (sb, ", 0x%02x%02x%02x", oc[2], oc[3], oc[4]);
				break;
			case SHORTOFF_2:
				(oc[2] & 0x80) ? (n = oc[2] - 0x100) : (n = oc[2]);
#if 0
				r_strbuf_appendf (sb, ", .%+-4i ;(0x%06X)",
						(prog_mode & PROG_MODE_REL0) ? (n+ins.size) : n,
						add + ins.size + n);
#else
				r_strbuf_appendf (sb, ", 0x%08x", add + ins.size + n);
#endif
				*jump = add + ins.size + n;
				break;
			case SHORTOFF_4:
				(oc[4] & 0x80) ? (n = oc[4] - 0x100) : (n = oc[4]);
#if 0
				r_strbuf_appendf (sb, ", .%+-4i ;(0x%06X)",
						(prog_mode & PROG_MODE_REL0) ? (n+ins.size) : n,
						add + ins.size + n);
#else
				r_strbuf_appendf (sb, ", 0x%08x", add + ins.size + n);
#endif
				*jump = add + ins.size + n;
				break;
			case SHORTOFF_X_2:
				r_strbuf_appendf (sb, ", (0x%02x, x)", oc[2]);
				break;
			case SHORTOFF_Y_2:
				r_strbuf_appendf (sb, ", (0x%02x, y)", oc[2]);
				break;
			case SHORTOFF_SP_2:
				r_strbuf_appendf (sb, ", (0x%02x, sp)", oc[2]);
				break;
			case LONGOFF_X_23:
				r_strbuf_appendf (sb, ", (0x%02x%02x, x)", oc[2], oc[3]);
				break;
			case LONGOFF_Y_23:
				r_strbuf_appendf (sb, ", (0x%02x%02x, y)", oc[2], oc[3]);
				break;
			case EXTOFF_X_234:
				r_strbuf_appendf (sb, ", (0x%02x%02x%02x, x)", oc[2], oc[3], oc[4]);
				break;
			case EXTOFF_Y_234:
				r_strbuf_appendf (sb, ", (0x%02x%02x%02x, y)", oc[2], oc[3], oc[4]);
				break;
			case SHORTPTR_2:
				r_strbuf_appendf (sb, ", [0x%02x]", oc[2]);
				break;
			case LONGPTR_23:
				r_strbuf_appendf (sb, ", [0x%02x%02x]", oc[2], oc[3]);
				break;
			case SHORTPTR_OFF_X_2:
				r_strbuf_appendf (sb, ", ([0x%02x], x)", oc[2]);
				break;
			case SHORTPTR_OFF_Y_2:
				r_strbuf_appendf (sb, ", ([0x%02x], y)", oc[2]);
				break;
			case LONGPTR_OFF_X_23:
				r_strbuf_appendf (sb, ", ([0x%02x%02x], x)", oc[2], oc[3]);
				break;
			case LONGPTR_OFF_Y_23:
				r_strbuf_appendf (sb, ", ([0x%02x%02x], y)", oc[2], oc[3]);
				break;
			case LONGMEM_BIT_123:
				if (prog_mode & PROG_MODE_IONAME) {
					n = oc[2]<<8 | oc[3];
					if ( (n>=0x5000) && (n<0x5800) && !Get_IOreg_Name(n, ioname + 2) ) {
						ioname[0] = ',';
						ioname[1] = ' ';
						r_strbuf_appendf (sb, "%s", ioname);
					} else {
						r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
					}
				} else {
					r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
				}
				r_strbuf_appendf (sb, ", %d", (oc[1] & 0x0F)>>1);
				break;
			}
		}
		cnt += ins.size;
		add += ins.size;
		break;
	}
	*len = cnt;
	return r_strbuf_drain (sb);
}

#if 0
int main(int argc, char **argv) {
	const uint8_t *data = (const unsigned char *)"\x23\x44\xa8\x55";
	char *s = stm8_disasm (0, data, 4);
	printf ("(%s)\n", s);
	free (s);

	return 0;
}
#endif
