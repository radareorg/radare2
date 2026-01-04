/* sorbo '07 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "dis.h"

static struct state _state;

#include <r_types.h>
#include <r_util/r_assert.h>
#include <r_util/r_str.h>
#include <r_util/r_strbuf.h>

static inline struct state *get_state(void) {
	memset (&_state, 0, sizeof (struct state));
	return &_state;
}

static uint16_t i2u16(struct instruction *in) {
	return *((uint16_t *)in);
}

static void decode_unknown(struct state *s, struct directive *d) {
	snprintf (d->d_asm, sizeof (d->d_asm), "DC 0x%04x", i2u16 (&d->d_inst));
}

static int decode_fixed(struct state *s, struct directive *d) {
	const char *op = NULL;
	*d->d_asm = '\0';
	switch (i2u16 (&d->d_inst)) {
	case INST_NOP:
		if (s->s_prefix) {
			return 0;
		}
		s->s_nop++;
		op = "nop";
		break;
	case INST_BRK:
		op = "brk";
		break;
	case INST_SLEEP:
		op = "sleep";
		break;
	case INST_SIF:
		op = "sif";
		break;
	case INST_BC:
		op = "bc";
		break;
	case INST_BRXL:
		op = "brxl";
		break;
	case INST_U:
		op = "";
		s->s_u = 1;
		break;
	case INST_RTS:
		op = "rts";
		break;
	}
	if (op) {
		r_str_ncpy (d->d_asm, op, sizeof (d->d_asm));
	}
	return d->d_asm[0] != 0;
}

static char *regname(int reg) {
	if (reg < 0 || reg > REG_Y) {
		return NULL;
	}
	static const char *const regnames[] = { "AH", "AL", "X", "Y" };
	return (char *)regnames[reg];
}

static int get_num(int num, int shift) {
	char x = (char) ((num >> shift) & 0xff);
	return (int) (x << shift);
}

static int get_operand(struct state *s, struct directive *d) {
	int total = get_num (d->d_inst.in_operand, 0);
	if (s->s_prefix) {
		total += get_num (s->s_prefix_val, 8);
	}
	if (s->s_prefix == 2) {
		total += get_num (s->s_prefix_val, 16);
	}
	return total;
}

static int decode_known(struct state *s, struct directive *d) {
	char *op = NULL;
	char *regn = NULL;
	int reg = 0;
	int ptr = 1;
	int idx = 1;
	int imm = 0;
	int rel = 0;
		int fmtsz;
	int branch = 0;
	struct instruction *in = &d->d_inst;
	//	int operand;
	char *sign = "";
	int rti = 0;

	switch (in->in_opcode) {
	case 0:
		if (in->in_reg == 0 && in->in_mode == 0) {
			if (s->s_prefix == 0) {
				s->s_prefix_val = 0;
			}
			s->s_prefix++;

			if (s->s_prefix == 2) {
				s->s_prefix_val <<= 8;
			}
			s->s_prefix_val |= in->in_operand << 8;

			r_str_ncpy (d->d_asm, "", sizeof (d->d_asm));
			return 1;
		}

		switch (i2u16 (in) & 0xf) {
		case 1:
			op = "st";
			regn = "FLAGS";
			break;
		case 2:
			op = "st";
			regn = "UX";
			break;
		case 3:
			op = "st";
			regn = "UY";
			break;
		case 5:
			op = "ld";
			regn = "FLAGS";
			break;
		case 6:
			op = "ld";
			regn = "UX";
			break;
		case 7:
			op = "ld";
			regn = "UY";
			break;
		case 0xa:
			op = "st";
			regn = "XH";
			break;
		case 0xd:
			op = "rti";
			regn = "";
			rti = 1;
			break;
		case 0xe:
			op = "ld";
			regn = "XH";
			break;
		}
		break;

	case 1:
		op = "ld";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 2:
		if (in->in_mode == DATA_MODE_IMMEDIATE) {
			op = "print";
			imm = 1;
			reg = 1;
		} else {
			op = "st";
			reg = 1;
			ptr = 1;
			idx = 1;
		}
		break;
	case 3:
		op = "add";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 4:
		op = "addc";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 5:
		op = "sub";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 6:
		op = "subc";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 7:
		op = "nadd";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 8:
		op = "cmp";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0x9:
		switch (in->in_reg) {
		case 0:
			if (s->s_u) {
				op = "umult";
			} else {
				op = "smult";
			}
			imm = 1;
			s->s_u = 0;
			idx = 1;
			ptr = 1;
			break;
		case 1:
			if (s->s_u) {
				op = "udiv";
			} else {
				op = "sdiv";
			}
			s->s_u = 0;
			imm = 1;
			break;
		case 2:
			op = "tst";
			imm = 1;
			ptr = 1;
			idx = 1;
			break;
		case 3:
			branch = 1;
			op = "bsr";
			ptr = 1;
			idx = 1;
			if (in->in_mode == ADDR_MODE_RELATIVE) {
				rel = 1;
			}
			break;
		}
		break;
	case 0xa:
		switch (in->in_reg) {
		case 0:
			op = "asl";
			imm = 1;
			break;
		case 1:
			if (s->s_u) {
				op = "lsr";
			} else {
				op = "asr";
			}
			s->s_u = 0;
			imm = 1;
			idx = 1;
			ptr = 1;
			break;
		case 2:
			op = "rol";
			imm = 1;
			break;
		case 3:
			op = "ror";
			imm = 1;
			break;
		}
		break;

	case 0xb:
		op = "or";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0xc:
		op = "and";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0xd:
		op = "xor";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0xe:
		branch = 1;
		if (in->in_mode == ADDR_MODE_RELATIVE) {
			rel = 1;
		}
		switch (in->in_reg) {
		case 0:
			op = "bra";
			ptr = 1;
			idx = 1;
			break;

		case 1:
			op = "blt"; /* yummy */
			break;
		case 2:
			op = "bpl";
			break;
		case 3:
			op = "bmi";
			break;
		}
		break;
	case 0xf:
		branch = 1;
		if (in->in_mode == ADDR_MODE_RELATIVE) {
			rel = 1;
		}
		switch (in->in_reg) {
		case 0:
			op = "bne";
			break;
		case 1:
			op = "beq";
			break;
		case 2:
			op = "bcc";
			break;
		case 3:
			op = "bcs";
			break;
		}
		break;
	}

	if (!op) {
		return 0;
	}

	if (ptr && in->in_mode == DATA_MODE_IMMEDIATE) {
		ptr = 0;
	}

	if (branch && in->in_mode == ADDR_MODE_X_RELATIVE) {
		ptr = 0;
	}

	if (idx && (! (in->in_mode & 2))) {
		idx = 0;
	}

	if (regn) {
		ptr = 1;
		idx = 1;
		reg = 1;
	}

	RStrBuf sb;
	r_strbuf_init (&sb);
	r_strbuf_setf (&sb, "%s", op);

	if (reg) {
		char *r = regn;
		if (!r) {
			r = regname (in->in_reg);
		}
		if (r && !rti) {
			r_strbuf_appendf (&sb, " %s,", r);
		}
	}
	if (ptr) {
		r_strbuf_append (&sb, "@");
		rel = 0;
	} else if (imm) {
		r_strbuf_append (&sb, "#");
	}
	if (idx && ptr) {
		r_strbuf_append (&sb, "(");
	}

	d->d_prefix = s->s_prefix;
//	d->d_operand = get_operand (s, d);
	if ((branch && idx) || rti) {
		d->d_operand = get_operand (s, d);
		if (d->d_operand < 0) {
			d->d_operand *= -1;
			sign = "-";
		}
	} else {
		d->d_operand = s->s_prefix_val | in->in_operand;
		if (d->d_operand & 0x80) {
			if (d->d_prefix) {
				if (!rel) {
					d->d_operand -= 0x100;
				}
			} else {
				d->d_operand |= 0xff00;
			}
		}
	}
	fmtsz = 4;
	if (d->d_operand & 0xff0000) {
		fmtsz += 2;
	}

	// can be cleaned, no need to fmtsz
	r_strbuf_appendf (&sb, "%s0x%.*X", sign, fmtsz, d->d_operand);

	if (idx) {
		char *r = in->in_mode == DATA_MODE_INDEXED_X? "X": "Y";
		if (regn) {
			r = "Y";
		}
		r_strbuf_appendf (&sb, ", %s", r);
		if (ptr) {
			r_strbuf_append (&sb, ")");
		}
	}

	// Copy the result back to d->d_asm
	const char *result = r_strbuf_get (&sb);
	if (result) {
		r_str_ncpy (d->d_asm, result, sizeof (d->d_asm));
	}
	r_strbuf_fini (&sb);

#if 0
	/* XXX quirks */
	if (!rel && in->in_mode == DATA_MODE_IMMEDIATE
	&& ((d->d_operand & 0xff00) == 0x7F00) && d->d_operand & 0x80) {
		s->s_ff_quirk = 1;
	}

	if (rel && !s->s_prefix && d->d_operand == 0x7F) {
		if (s->s_nopd) {
			R_LOG_WARN ("w00t");
			r_str_ncpy (s->s_nopd->d_asm, "nop", sizeof (s->s_nopd->d_asm));
		}
		R_LOG_WARN ("fucking up a branch %x", d->d_off);
		decode_unknown (s, d);
	}
#endif
	return 1;
}

static void xap_decode(struct state *s, struct directive *d) {
	int prefix = s->s_prefix;
	if (!decode_fixed (s, d)) {
		if (!decode_known (s, d)) {
			decode_unknown (s, d);
		}
	}
	if (s->s_prefix == prefix) {
		s->s_prefix_val = s->s_prefix = 0;
	}
}

static int read_bin(struct state *s, struct directive *d) {
	memcpy (&d->d_inst, s->s_buf, sizeof (d->d_inst));
	d->d_off = s->s_off++;
	return 1;
}

static inline struct directive *next_inst(struct state *s) {
	int rd;
	struct directive *d = malloc (sizeof (*d));
	if (!d) {
		perror ("malloc()");
		return NULL;
	}
	memset (d, 0, sizeof (*d));
	{
		rd = read_bin (s, d);
	}
	if (!rd) {
		free (d);
		return NULL;
	}

	return d;
}

