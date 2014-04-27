/* sorbo '07 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
//#include <err.h>
#include <string.h>
//#include <assert.h>
#define assert(x) if (!(x)) { eprintf("assert ##x##\n"); return; }
#include <stdarg.h>
#include <stdint.h>
#include "dis.h"

static struct state _state;

#include <r_types.h>

static inline struct state *get_state(void) {
	memset (&_state, 0, sizeof (struct state));
	return &_state;
}

static uint16_t i2u16(struct instruction *in) {
	return *((uint16_t*)in);
}

#if 0
static void output(struct state *s, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cons_printf(fmt, ap);
	//vfprintf(s->s_out, fmt, ap);
	va_end(ap);
}
#endif

static void decode_unknown(struct state *s, struct directive *d) {
#if 0
	printf("Opcode 0x%x reg %d mode %d operand 0x%x",
	       in->in_opcode, in->in_reg, in->in_mode, in->in_operand);
#endif
	sprintf(d->d_asm, "DC 0x%4x", i2u16(&d->d_inst));
}

static int decode_fixed(struct state *s, struct directive *d) {
	*d->d_asm='\0';
	switch (i2u16 (&d->d_inst)) {
	case INST_NOP:
		if (s->s_prefix)
			return 0;
		s->s_nop++;
		strcpy(d->d_asm, "nop");
		break;
	case INST_BRK: strcpy(d->d_asm, "brk"); break;
	case INST_SLEEP: strcpy(d->d_asm, "sleep"); break;
	case INST_SIF: strcpy(d->d_asm, "sif"); break;
	case INST_BC: strcpy(d->d_asm, "bc"); break;
	case INST_BRXL: strcpy(d->d_asm, "brxl"); break;
	case INST_U: strcpy(d->d_asm, ""); s->s_u = 1; break;
	case INST_RTS: strcpy(d->d_asm, "rts"); break;
	}
	return d->d_asm[0]!=0;
}

static char *regname(int reg) {
	switch (reg) {
	case REG_AH: return "AH";
	case REG_AL: return "AL";
	case REG_X: return "X";
	case REG_Y: return "Y";
	}
	return NULL;
}

static int get_num(int num, int shift) {
	char x = (char) ((num >> shift) & 0xff);
	return (int)(x<<shift);
}

static int get_operand(struct state *s, struct directive *d) {
	int total = get_num(d->d_inst.in_operand, 0);
	if (s->s_prefix)
		total += get_num(s->s_prefix_val, 8);
	if (s->s_prefix == 2)
		total += get_num(s->s_prefix_val, 16);
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
	char fmt[16];
	char tmp[128];
	int fmtsz;
	int branch = 0;
	struct instruction *in = &d->d_inst;
//	int operand;
	char *sign = "";
	int rti = 0;

	switch (in->in_opcode) {
	case 0:
		if (in->in_reg == 0 && in->in_mode == 0) {
			if (s->s_prefix == 0)
				s->s_prefix_val = 0;
			s->s_prefix++;

			if (s->s_prefix == 2)
				s->s_prefix_val <<= 8;
#if 0
			/* XXX we need to look ahead more to see if we're
			 * getting a branch instruction */
			if (s->s_nopd && in->in_operand == 0x80)
				strcpy(s->s_nopd->d_asm, "");
#endif
			s->s_prefix_val |= in->in_operand << 8;

			strcpy(d->d_asm, "");
			return 1;
		}

		switch (i2u16(in) & 0xf) {
		case 1:
			op	= "st";
			regn	= "FLAGS";
			break;
		case 2:
			op	= "st";
			regn	= "UX";
			break;
		case 3:
			op	= "st";
			regn	= "UY";
			break;
		case 5:
			op	= "ld";
			regn	= "FLAGS";
			break;
		case 6:
			op	= "ld";
			regn	= "UX";
			break;
		case 7:
			op	= "ld";
			regn	= "UY";
			break;
		case 0xa:
			op	= "st";
			regn	= "XH";
			break;
		case 0xd:
			op	= "rti";
			regn	= "";
			rti	= 1;
			break;
		case 0xe:
			op	= "ld";
			regn	= "XH";
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
			if (s->s_u) op = "umult";
			else op = "smult";
			imm = 1;
			s->s_u = 0;
			idx = 1;
			ptr = 1;
			break;
		case 1:
			if (s->s_u) op = "udiv";
			else op = "sdiv";
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
			if (in->in_mode == ADDR_MODE_RELATIVE)
				rel = 1;
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
			if (s->s_u) op = "lsr";
			else op = "asr";
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
		if (in->in_mode == ADDR_MODE_RELATIVE)
			rel = 1;
		switch (in->in_reg) {
		case 0:
			op = "bra";
			ptr = 1;
			idx = 1;
#if 0
			if (s->s_nopd) {
				op = "bra2"; /* XXX need bra3 support */
				strcpy(s->s_nopd->d_asm, "");
			}
#endif
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
		if (in->in_mode == ADDR_MODE_RELATIVE)
			rel = 1;
		switch (in->in_reg) {
		case 0: op = "bne"; break;
		case 1: op = "beq"; break;
		case 2: op = "bcc"; break;
		case 3: op = "bcs"; break;
		}
		break;
	}

	if (!op) return 0;

	if (ptr && in->in_mode == DATA_MODE_IMMEDIATE)
		ptr = 0;

	if (branch && in->in_mode == ADDR_MODE_X_RELATIVE)
		ptr = 0;

	if (idx && (!(in->in_mode & 2)))
		idx = 0;

	if (regn) {
		ptr = 1;
		idx = 1;
		reg = 1;
	}

	sprintf (d->d_asm, "%s ", op);
	if (reg) {
		char *r = regn;
		if (!r) r = regname(in->in_reg);
		if (r && !rti) {
			strcat (d->d_asm, r);
			strcat (d->d_asm, ", ");
		}
	}
	if (ptr) {
		strcat(d->d_asm, "@");
		rel = 0;
	} else if (imm) strcat(d->d_asm, "#");
	if (idx && ptr) strcat(d->d_asm, "(");

	d->d_prefix = s->s_prefix;
//	d->d_operand = get_operand(s, d);
#if 1
	if ((branch && idx) || rti) {
		d->d_operand = get_operand(s, d);
		if (d->d_operand < 0) {
			d->d_operand *= -1;
			sign = "-";
		}	
	} else {
		d->d_operand = s->s_prefix_val | in->in_operand;
		if (d->d_operand & 0x80) {
			if (d->d_prefix) {
				if (!rel) d->d_operand -= 0x100;
			} else d->d_operand |= 0xff00;
		}
	}
#endif
#if 0
	operand = d->d_operand;
	if (operand < 0)
		operand *= -1;
#endif
	fmtsz = 4;
	if (d->d_operand & 0xff0000)
		fmtsz += 2;

	// can be cleaned, no need to fmtsz
	snprintf (fmt, sizeof (fmt), "%s0x%%.%dX", sign, fmtsz);
	snprintf (tmp, sizeof (tmp), fmt, d->d_operand);
	strcat (d->d_asm, tmp);

	if (idx) {
		char *r = in->in_mode == DATA_MODE_INDEXED_X ? "X" : "Y";
		if (regn) r = "Y";
		snprintf(tmp, sizeof(tmp), ", %s", r);
		strcat(d->d_asm, tmp);
		if (ptr)
			strcat(d->d_asm, ")");
	}

#if 0
	/* XXX quirks */
	if (!rel && in->in_mode == DATA_MODE_IMMEDIATE
	    && ((d->d_operand & 0xff00) == 0x7F00) && d->d_operand & 0x80)
		s->s_ff_quirk = 1;

	if (rel && !s->s_prefix && d->d_operand == 0x7F) {
		if (s->s_nopd) {
			printf("w00t\n");
			strcpy(s->s_nopd->d_asm, "nop");
		}
		printf("Warning: fucking up a branch %x\n", d->d_off);
		decode_unknown(s, d);
	}
#endif
	return 1;
}

static void csr_decode(struct state *s, struct directive *d) {
	int prefix = s->s_prefix;
	if (!decode_fixed (s, d))
		if (!decode_known (s, d))
			decode_unknown (s, d);
	if (s->s_prefix == prefix)
		s->s_prefix_val = s->s_prefix = 0;
}

static int read_bin(struct state *s, struct directive *d) {
	memcpy(&d->d_inst, s->s_buf, sizeof(d->d_inst));
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
#if 0
	if (s->s_format)
		rd = read_text(s, d);
	else
#endif
	rd = read_bin (s, d);
	if (!rd) {
		free (d);
		return NULL;
	}

	return d;
}

#if 0
static void own(struct state *s)
{
	struct directive *d;
	struct directive *last = &s->s_dirs;
	struct label *l;
	int flush = 0;
	char fname[128];
	char *fnamep;

	snprintf(fname, sizeof(fname), "%s", s->s_fname);
	fnamep = strchr(fname, '.');
	if (fnamep)
		*fnamep = 0;
	output(s, "\tMODULE %s\n"
	          "\t.CODE\n"
		  "\t.LARGE\n"
	          "\n", fname);

	/* decode instructions */
	s->s_off = 0;
	while ((d = next_inst(s))) {
		csr_decode(s, d);

		if (s->s_ff_quirk) {
			strcpy(last->d_asm, "DC\t0x8000");

			sprintf(d->d_asm, "DC\t0x%.4x", i2u16(&d->d_inst));
			s->s_ff_quirk = 0;
		}

		if (s->s_nopd) {
			last->d_next = s->s_nopd;
			last = s->s_nopd;
			s->s_nopd = NULL;
			s->s_nop = 0;
		}

		if (s->s_nop) {
			assert(s->s_nopd == NULL);
			s->s_nopd = d;
		} else {
			last->d_next = d;
			last = d;
		}

#if 1
		if (flush++ > 10000) {
			printf("@0x%.6x\r", d->d_off);
			fflush(stdout);
			flush = 0;
		}
#endif
	}
	if (s->s_nopd)
		last->d_next = s->s_nopd;
	printf("\n");

	/* print them */
	d = s->s_dirs.d_next;
	l = s->s_labels.l_next;
	while (d) {

		/* print any labels first */
		while (l) {
			if (l->l_off > d->d_off)
				break;

			print_label(s, l);
			l = l->l_next;
		}

		add_comment(s, d);
		output(s, "\t%s\n", d->d_asm);

		d = d->d_next;
	}
	if (l) {
		print_label(s, l);
		assert(l->l_next == NULL);
	}

	output(s, "\n\tENDMOD\n");
}
#endif
