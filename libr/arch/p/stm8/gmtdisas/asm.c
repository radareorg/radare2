// Evolved from https://github.com/volbus/gmtdisas

#include <r_util.h>
#include "ins.inc.c"

typedef struct {
	uint32_t start_add;
	uint32_t ext_offset;
	uint32_t size;
	uint32_t line_index;
	const ut8 *data;
} datablock;

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
	int n, err, oc[6];
	instruction ins;

	int cnt = 0;
	int add = block->start_add;

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
			ins.size = 1;
			return NULL;
		} else {
			if (ins.type) {
				*type = ins.type;
			}
			r_strbuf_appendf (sb, "%s", ins.text);

			if (n == 1) {
				for (; n < ins.size; n++) {
					oc[n + 1] = *(block->data + cnt + n);
				}
			} else {
				for (; n < ins.size; n++) {
					oc[n] = *(block->data + cnt + n);
				}
			}
			const bool noderef = ins.des & NODEREF;
			int des = ins.des;
			if (noderef) {
				des &= 0xff;
			}
			switch (des) {
			case STM8_NONE:
				break;
			case STM8_REG_A:
				r_strbuf_append (sb, " a");
				break;
			case STM8_REG_XL:
				r_strbuf_append (sb, " xl");
				break;
			case STM8_REG_YL:
				r_strbuf_append (sb, " yl");
				break;
			case STM8_REG_XH:
				r_strbuf_append (sb, " xh");
				break;
			case STM8_REG_YH:
				r_strbuf_append (sb, " yh");
				break;
			case STM8_REG_CC:
				r_strbuf_append (sb, " cc");
				break;
			case STM8_REG_X:
				r_strbuf_append (sb, " x");
				break;
			case STM8_REG_Y:
				r_strbuf_append (sb, " y");
				break;
			case STM8_REG_SP:
				r_strbuf_append (sb, " sp");
				break;
			case STM8_IMM_BYTE_2:
				r_strbuf_appendf (sb, " 0x%02x", oc[2]);
				break;
			case STM8_IMM_WORD_23:
				r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
				break;
			case STM8_PTR_X:
				r_strbuf_append (sb, " [x]");
				break;
			case STM8_PTR_Y:
				r_strbuf_append (sb, " [y]");
				break;
			case SHORTMEM_2:
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%02x", oc[2]);
				} else {
					r_strbuf_appendf (sb, " [0x%02x]", oc[2]);
				}
				break;
			case SHORTMEM_3:
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%02x", oc[3]);
				} else {
					r_strbuf_appendf (sb, " [0x%02x]", oc[3]);
				}
				break;
			case LONGMEM_23: // ioreg
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[2], oc[3]);
				} else {
					r_strbuf_appendf (sb, " [0x%02x%02x]", oc[2], oc[3]);
				}
				*jump = (oc[2] <<8) | oc[3];
				break;
			case LONGMEM_34: // ioreg
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[3], oc[4]);
				} else {
					r_strbuf_appendf (sb, " [0x%02x%02x]", oc[3], oc[4]);
				}
				break;
			case LONGMEM_45: // ioreg
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%02x%02x", oc[4], oc[5]);
				} else {
					r_strbuf_appendf (sb, " [0x%02x%02x]", oc[4], oc[5]);
				}
				break;
			case EXTMEM_234:
				r_strbuf_appendf (sb, " [0x%02x%02x%02x]", oc[2], oc[3], oc[4]);
				if (*type == R_ANAL_OP_TYPE_SWI) {
					*jump = (oc[2] <<16) | oc[3]<<8 | oc[4];
				}
				break;
			case SHORTOFF_2:
				(oc[2] & 0x80) ? (n = oc[2] - 0x100) : (n = oc[2]);
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%08x", add + ins.size + n);
				} else {
					r_strbuf_appendf (sb, " [0x%08x]", add + ins.size + n);
				}
				*jump = add + ins.size + n;
				break;
			case SHORTOFF_4:
				(oc[4] & 0x80) ? (n = oc[4] - 0x100) : (n = oc[4]);
				r_strbuf_appendf (sb, " [0x%08x]", add + ins.size + n);
				*jump = add + ins.size + n;
				break;
			case SHORTOFF_X_2:
				r_strbuf_appendf (sb, " [x + 0x%02x]", oc[2]);
				break;
			case SHORTOFF_Y_2:
				r_strbuf_appendf (sb, " [y + 0x%02x]", oc[2]);
				break;
			case SHORTOFF_SP_2:
				r_strbuf_appendf (sb, " [sp + 0x%02x]", oc[2]);
				break;
			case LONGOFF_X_23:
				r_strbuf_appendf (sb, " [x + 0x%02x%02x]", oc[2], oc[3]);
				break;
			case LONGOFF_Y_23:
				r_strbuf_appendf (sb, " [y + 0x%02x%02x]", oc[2], oc[3]);
				break;
			case EXTOFF_X_234:
				r_strbuf_appendf (sb, " [x + 0x%02x%02x%02x]", oc[2], oc[3], oc[4]);
				break;
			case EXTOFF_Y_234:
				r_strbuf_appendf (sb, " [y + 0x%02x%02x%02x]", oc[2], oc[3], oc[4]);
				break;
			case SHORTPTR_2:
				if (noderef) {
					r_strbuf_appendf (sb, " 0x%02x", oc[2]);
				} else {
					r_strbuf_appendf (sb, " [0x%02x]", oc[2]);
				}
				break;
			case LONGPTR_23:
				r_strbuf_appendf (sb, " [0x%02x%02x]", oc[2], oc[3]);
				break;
			case SHORTPTR_OFF_X_2:
				r_strbuf_appendf (sb, " x + [0x%02x]", oc[2]);
				break;
			case SHORTPTR_OFF_Y_2:
				r_strbuf_appendf (sb, " y + [0x%02x]", oc[2]);
				break;
			case LONGPTR_OFF_X_23:
				r_strbuf_appendf (sb, " x + [0x%02x%02x]", oc[2], oc[3]);
				break;
			case LONGPTR_OFF_Y_23:
				r_strbuf_appendf (sb, " y + [0x%02x%02x]", oc[2], oc[3]);
				break;
			case LONGMEM_BIT_123:
				// ioreg
				r_strbuf_appendf (sb, " [0x%02x%02x]", oc[2], oc[3]);
				r_strbuf_appendf (sb, ", %d", (oc[1] & 0x0F)>>1);
				break;
			}
			int src = ins.src;
			if (src & NODEREF) {
				src &= 0xff;
			}
			switch (src) {
			case STM8_NONE:
				break;
			case STM8_REG_A:
				r_strbuf_append (sb, ", a");
				break;
			case STM8_REG_XL:
				r_strbuf_append (sb, ", xl");
				break;
			case STM8_REG_YL:
				r_strbuf_append (sb, ", yl");
				break;
			case STM8_REG_XH:
				r_strbuf_append (sb, ", xh");
				break;
			case STM8_REG_YH:
				r_strbuf_append (sb, ", yh");
				break;
			case STM8_REG_CC:
				r_strbuf_append (sb, ", cc");
				break;
			case STM8_REG_X:
				r_strbuf_append (sb, ", x");
				break;
			case STM8_REG_Y:
				r_strbuf_append (sb, ", y");
				break;
			case STM8_REG_SP:
				r_strbuf_append (sb, ", sp");
				break;
			case STM8_IMM_BYTE_2:
				r_strbuf_appendf (sb, ", 0x%02x", oc[2]);
				break;
			case STM8_IMM_WORD_23:
				r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
				break;
			case STM8_PTR_X:
				r_strbuf_append (sb, ", [x]");
				break;
			case STM8_PTR_Y:
				r_strbuf_append (sb, ", [y]");
				break;
			case SHORTMEM_2:
				r_strbuf_appendf (sb, ", [0x%02x]", oc[2]);
				break;
			case SHORTMEM_3:
				r_strbuf_appendf (sb, ", [0x%02x]", oc[3]);
				break;
			case LONGMEM_23:
				r_strbuf_appendf (sb, ", [0x%02x%02x]", oc[2], oc[3]);
				break;
			case LONGMEM_34:
				// ioreg
				r_strbuf_appendf (sb, ", [0x%02x%02x]", oc[3], oc[4]);
				break;
			case LONGMEM_45:
				// ioreg
				r_strbuf_appendf (sb, ", [0x%02x%02x]", oc[4], oc[5]);
				break;
			case EXTMEM_234:
				r_strbuf_appendf (sb, ", [0x%02x%02x%02x]", oc[2], oc[3], oc[4]);
				break;
			case SHORTOFF_2:
				(oc[2] & 0x80) ? (n = oc[2] - 0x100) : (n = oc[2]);
				r_strbuf_appendf (sb, ", 0x%08x", add + ins.size + n);
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
				r_strbuf_appendf (sb, ", [x + 0x%02x]", oc[2]);
				break;
			case SHORTOFF_Y_2:
				r_strbuf_appendf (sb, ", [y + 0x%02x]", oc[2]);
				break;
			case SHORTOFF_SP_2:
				r_strbuf_appendf (sb, ", [sp + 0x%02x]", oc[2]);
				break;
			case LONGOFF_X_23:
				r_strbuf_appendf (sb, ", [x + 0x%02x%02x]", oc[2], oc[3]);
				break;
			case LONGOFF_Y_23:
				r_strbuf_appendf (sb, ", [y + 0x%02x%02x]", oc[2], oc[3]);
				break;
			case EXTOFF_X_234:
				r_strbuf_appendf (sb, ", [x + 0x%02x%02x%02x]", oc[2], oc[3], oc[4]);
				break;
			case EXTOFF_Y_234:
				r_strbuf_appendf (sb, ", [y + 0x%02x%02x%02x]", oc[2], oc[3], oc[4]);
				break;
			case SHORTPTR_2:
				r_strbuf_appendf (sb, ", [0x%02x]", oc[2]);
				break;
			case LONGPTR_23:
				if (noderef) {
					r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
				} else {
					r_strbuf_appendf (sb, ", [0x%02x%02x]", oc[2], oc[3]);
				}
				break;
			case SHORTPTR_OFF_X_2:
				r_strbuf_appendf (sb, ", [0x%02x] + x", oc[2]);
				break;
			case SHORTPTR_OFF_Y_2:
				r_strbuf_appendf (sb, ", ([0x%02x] + y]", oc[2]);
				break;
			case LONGPTR_OFF_X_23:
				r_strbuf_appendf (sb, ", [0x%02x%02x] + x]", oc[2], oc[3]);
				break;
			case LONGPTR_OFF_Y_23:
				r_strbuf_appendf (sb, ", ([0x%02x%02x], y)", oc[2], oc[3]);
				break;
			case LONGMEM_BIT_123:
				// ioreg
				r_strbuf_appendf (sb, ", 0x%02x%02x", oc[2], oc[3]);
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
