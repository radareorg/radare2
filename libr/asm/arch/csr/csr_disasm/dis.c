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

#include <r_types.h>

static struct state *get_state(void)
{
	return &_state;
}

static uint16_t i2u16(struct instruction *in)
{
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

static void decode_unknown(struct state *s, struct directive *d)
{
#if 0
	printf("Opcode 0x%x reg %d mode %d operand 0x%x",
	       in->in_opcode, in->in_reg, in->in_mode, in->in_operand);
#endif
	sprintf(d->d_asm, "DC\t0x%4x", i2u16(&d->d_inst));
}

static int decode_fixed(struct state *s, struct directive *d)
{
	switch (i2u16(&d->d_inst)) {
	case INST_NOP:
		if (s->s_prefix)
			return 0;
		
		s->s_nop++;
		strcpy(d->d_asm, "nop");
		return 1;

	case INST_BRK:
		strcpy(d->d_asm, "brk");
		return 1;

	case INST_SLEEP:
		strcpy(d->d_asm, "sleep");
		return 1;

	case INST_SIF:
		strcpy(d->d_asm, "sif");
		return 1;

	case INST_BC:
		strcpy(d->d_asm, "bc");
		return 1;

	case INST_BRXL:
		strcpy(d->d_asm, "brxl");
		return 1;

	case INST_U:
		strcpy(d->d_asm, "");
		s->s_u = 1;
		return 1;

	case INST_RTS:
		strcpy(d->d_asm, "rts");
		return 1;
	}

	return 0;
}

static char *regname(int reg)
{
	switch (reg) {
	case REG_AH:
		return "AH";
		break;

	case REG_AL:
		return "AL";
		break;
	
	case REG_X:
		return "X";
		break;

	case REG_Y:
		return "Y";
		break;

	default:
		return NULL;
	}
}

static int get_num(int num, int shift)
{
	int tmp;
	char x;

	x = (char) ((num >> shift) & 0xff);
	tmp = x;
	tmp <<= shift;

	return tmp;
}

static int get_operand(struct state *s, struct directive *d)
{
	int total = 0;

	total += get_num(d->d_inst.in_operand, 0);

	if (s->s_prefix)
		total += get_num(s->s_prefix_val, 8);

	if (s->s_prefix == 2)
		total += get_num(s->s_prefix_val, 16);

	return total;
}

#if 0
static int label_off(struct directive *d)
{
#if 1
//	int off = get_operand(d);
	int off = d->d_operand;

	int lame = off & 0x80;

	/* XXX WTF? */
	if (!d->d_prefix) {
		off = (char) (off &0xff);
	} else if (d->d_prefix == 1) {
		off = (short) (off & 0xffff);

		if (lame)
			off -= 0x100;

	} else {
		off = (int) (off & 0xffffff);

		if (off & 0x800000)
			off |= 0xff000000;

		if (off & 0x8000)
			off -= 0x10000;

		if (lame)
			off -= 0x100;
	}
#endif
//	int off = d->d_operand;

	return d->d_off + off;
}
#endif

#if 0
static void label_add_ref(struct label *l, struct directive *d)
{
	struct directive **ptr = l->l_refs;

	while (*ptr) {
		assert((unsigned long) ptr - (unsigned long) l->l_refs <
		       sizeof(l->l_refs));
		
		ptr++;
	}
	*ptr = d;
	l->l_refc++;
}
#endif

#if 0
/* XXX slow */
static struct label *find_label_add(struct state *s, struct directive *d)
{
	int off = label_off(d);
	struct label *ptr = s->s_labels.l_next;
	struct label *slot = &s->s_labels;

	/* find */
	while (ptr) {
		if (ptr->l_off == off)
			return ptr;

		if (ptr->l_off > off)
			break;
		
		slot = ptr;
		ptr = ptr->l_next;
	}

	/* add */
	ptr = malloc(sizeof(*ptr));
	if (!ptr) {
		perror("malloc()");
		return NULL;
	}
	memset(ptr, 0, sizeof(*ptr));
	sprintf(ptr->l_name, "0x%x", off); //L%d", s->s_labelno++);
	ptr->l_off = off;

	ptr->l_next = slot->l_next;
	slot->l_next = ptr;

	return ptr;
}

static void add_label(struct state *s, struct directive *d)
{
	struct label *l;

	l = find_label_add(s, d);
	assert(l);

	label_add_ref(l, d);
	strcat(d->d_asm, l->l_name);
}
#endif

static int decode_known(struct state *s, struct directive *d)
{
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
			if (s->s_u)
				op = "umult";
			else
				op = "smult";
			imm = 1;
			s->s_u = 0;
			idx = 1;
			ptr = 1;
			break;

		case 1:
			if (s->s_u)
				op = "udiv";
			else
				op = "sdiv";
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
			if (s->s_u)
				op = "lsr";
			else
				op = "asr";
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

	if (!op)
		return 0;

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

	sprintf(d->d_asm, "%s ", op);
	if (reg) {
		char *r = regn;

		if (!r)
			r = regname(in->in_reg);

		if (!rti) {
			strcat(d->d_asm, r);
			strcat(d->d_asm, ", ");
		}
	}
	if (ptr) {
		strcat(d->d_asm, "@");
		rel = 0;
	} else if (imm)
		strcat(d->d_asm, "#");
	if (idx && ptr)
		strcat(d->d_asm, "(");

	d->d_prefix = s->s_prefix;
//	d->d_operand = get_operand(s, d);
#if 1
	if ((branch && idx) || rti) {
		d->d_operand = get_operand(s, d);
		if (d->d_operand < 0) {
			d->d_operand *= -1;
			sign = "-";
		}	
	}
	else {
		d->d_operand = s->s_prefix_val | in->in_operand;
		if (d->d_operand & 0x80) {
			if (d->d_prefix) {
				if (!rel)
					d->d_operand -= 0x100;
			} else
				d->d_operand |= 0xff00;
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
	snprintf(fmt, sizeof(fmt), "%s0x%%.%dX", sign, fmtsz);
	snprintf(tmp, sizeof(tmp), fmt, d->d_operand);

#if 0
	if (rel) {
		//add_label(s, d);
		/* XXX prefix */
		if (s->s_nopd && strcmp(s->s_nopd->d_asm, "")) {
			/* lets be conservative for now */
			if (d->d_operand == 0x7F
			    || d->d_operand == 0x7E)
				strcpy(s->s_nopd->d_asm, "");
			else
				printf("\nWarning: nop before branch at %x\n",
				       d->d_off);
		}
	} else
#endif

		strcat(d->d_asm, tmp);

	if (idx) {
		char *r = in->in_mode == DATA_MODE_INDEXED_X ? "X" : "Y";

		if (regn)
			r = "Y";

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

void csr_decode(struct state *s, struct directive *d)
{
	int prefix = s->s_prefix;

	if (decode_fixed(s, d))
		goto out;

	if (decode_known(s, d))
		goto out;

	decode_unknown(s, d);

out:
	if (s->s_prefix == prefix)
		s->s_prefix_val = s->s_prefix = 0;
}

#if 0
static void add_tabs(struct state *s, struct directive *d)
{
	int outlen = 0;
	int len;
	char *ptr = d->d_asm;
	int pos;
	int wanted = 8*4;

	len = strlen(ptr);
	for (pos = 0; pos < len; pos++, ptr++) {
		if (*ptr == '\t') {
			outlen += 8 - (pos % 8);
		} else
			outlen++;
	}

	wanted -= outlen;
	assert(wanted > 0);

	pos = wanted / 8;
	if (wanted % 8)
		pos++;

	while (pos--)
		strcat(d->d_asm, " ");
}
#endif

#if 0
static void add_comment(struct state *s, struct directive *d)
{
	char tmp[128];

	add_tabs(s, d);

	snprintf(tmp, sizeof(tmp), "; @0x%x 0x%x", d->d_off,
		 *((uint16_t*)&d->d_inst));

	strcat(d->d_asm, tmp);
}

static int read_text(struct state *s, struct directive *d)
{
	char tmp[128];
	char *x;
	unsigned int inst;
	uint16_t *p;

	while ((x = fgets(tmp, sizeof(tmp), s->s_in))) {
		if (tmp[0] == '@')
			break;
	}
	if (!x)
		return 0;

	if (sscanf(tmp, "@0x%x 0x%x", &d->d_off, &inst)
	    != 2)
		return 0;

	p = (uint16_t*) &d->d_inst;
	*p = (uint16_t) inst;

	return 1;
}
#endif

static int read_bin(struct state *s, struct directive *d)
{
	//int rd;

	memcpy(&d->d_inst, s->s_buf, sizeof(d->d_inst));
#if 0
	rd = fread(&d->d_inst, sizeof(d->d_inst), 1, s->s_in);
	if (rd == -1)
		err(1, "read()");
	if (rd == 0)
		return 0;
#endif

	d->d_off = s->s_off++;

	return 1;
}

struct directive *next_inst(struct state *s)
{
	struct directive *d;
	int rd;

	d = malloc(sizeof(*d));
	if (!d) {
		perror("malloc()");
		return NULL;
	}
	memset(d, 0, sizeof(*d));

#if 0
	if (s->s_format)
		rd = read_text(s, d);
	else
#endif
		rd = read_bin(s, d);

	if (!rd) {
		free(d);
		return NULL;
	}

	return d;
}

#if 0
static void print_label(struct state *s, struct label *l)
{
	output(s, "\n%s:\t\t\t\t\t; refs: %d\n",
	       l->l_name, l->l_refc);
}
#endif

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

// XXX lot of memory leaks
int arch_csr_disasm(char *str, unsigned char *buf, u64 seek)
{
	struct state *s = get_state();
	struct directive *d;
	memset(s, 0, sizeof(*s));
	s->s_buf = buf;
	s->s_off = seek;
	s->s_out = NULL;
	d = next_inst(s);
	if (d == NULL)
		return 0;

	csr_decode(s, d);
#if 0
	if (s->s_ff_quirk) {
		sprintf(d->d_asm, "DC\t0x%x", i2u16(&d->d_inst));
		s->s_ff_quirk = 0;
	}
#endif
	strcpy(str, d->d_asm);
	return 0;
}
#if 0
static int main(int argc, char *argv[])
{
	struct state *s = get_state();
	struct directive *d;
	char tmp[128];
	int i = 0;
	unsigned char buf[128];

	memset(s, 0, sizeof(*s));
memcpy(buf, "\xFF\x27\x00\x10", 4);
s->s_buf = &buf;

#if 0
	if (argc < 2) {
		printf("Usage: %s <file> [format]\n", argv[0]);
		exit(1);
	}

	if (argc > 2)
		s->s_format = atoi(argv[2]);

	s->s_fname = argv[1];

	if ((s->s_in = fopen(s->s_fname, "r")) == NULL)
		err(1, "fopen()");

	snprintf(tmp, sizeof(tmp), "%s.xap", s->s_fname);
	s->s_out = fopen(tmp, "w");
	if (!s->s_out)
		err(1, "fopen()");
#endif
	s->s_off = 0;
	s->s_out = -1;
for(i=0;i<2;i++) {
	d = next_inst(s);
	decode(s, d);
	if (s->s_ff_quirk) {
		//strcpy(last->d_asm, "DC\tH'8000");
		sprintf(d->d_asm, "DC\t0x%x", i2u16(&d->d_inst));
		s->s_ff_quirk = 0;
	}
	printf("ASM : %s\n", d->d_asm);
}

#if 0
	own(s);

	fclose(s->s_in);
	fclose(s->s_out);
#endif

	exit(0);
}
#endif
