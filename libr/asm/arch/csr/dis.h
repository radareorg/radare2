#ifndef _INCLUDE_CSR_DIS_H_
#define _INCLUDE_CSR_DIS_H_

#include <r_types.h>

#define __packed __attribute__((__packed__))

struct instruction {
	ut16	in_mode:2,
			in_reg:2,
			in_opcode:4,
			in_operand:8;
#if __sun
#warning XXX related to sunstudio :O
};
#else
} __packed;
#endif

struct directive {
	struct instruction	d_inst;
	int			d_operand;
	int			d_prefix;
	unsigned int		d_off;
	char			d_asm[128];
	struct directive	*d_next;
};

struct label {
	char			l_name[128];
	unsigned int		l_off;
	struct directive	*l_refs[666];
	int			l_refc;
	struct label		*l_next;
};

struct state {
	int			s_prefix;
	unsigned int		s_prefix_val;
	FILE			*s_in;
	unsigned int		s_off;
	char			*s_fname;
	int			s_u;
	unsigned int		s_labelno;
	const unsigned char *	s_buf;
	struct directive	s_dirs;
	struct label		s_labels;
	FILE			*s_out;
	int			s_format;
	int			s_nop;
	struct directive	*s_nopd;
	int			s_ff_quirk;
};

#define MODE_MASK	3
#define REG_SHIFT	2
#define REG_MASK	3
#define OPCODE_SHIFT	4
#define OPCODE_MASK	0xF
#define OPERAND_SHIFT	8

#define INST_NOP	0x0000
#define INST_BRK	0x0004
#define INST_SLEEP	0x0008
#define INST_U		0x0009
#define INST_SIF	0x000C
#define INST_RTS	0x00E2
#define INST_BRXL	0xfe09
#define INST_BC		0xff09

#define REG_AH		0
#define REG_AL		1
#define REG_X		2
#define REG_Y		3

#define DATA_MODE_IMMEDIATE	0
#define DATA_MODE_DIRECT	1
#define DATA_MODE_INDEXED_X	2
#define DATA_MODE_INDEXED_Y	3

#define ADDR_MODE_RELATIVE	0
#define ADDR_MODE_X_RELATIVE	2

static void csr_decode(struct state *s, struct directive *d);

#endif
