/* radare - LGPL - Copyright 2022 - jmaselbas */

#include "kvx.h"
#include "kvx-reg.h"
#include <stdio.h>
#include <string.h>
#include <r_anal.h>

const opc_t kv3_opc[] = {
#include "kv3.opc"
};
#define KV3_OPC_COUNT R_ARRAY_SIZE(kv3_opc)

int kvx_instr_print(insn_t *insn, ut64 offset, char *buf, size_t len) {
	const char *fmt = insn->opc->format;
	operand_t opr;
	int i = 0;
	int n, w;

	/* print mnemonic */
	w = snprintf (buf, len, "%s%s", insn->opc->mnemonic, fmt[0] != '\0' ? " " : "");
	n = R_MIN (w, len);

	/* append operands */
	while (n < (len - 1) && *fmt != '\0') {
		if (fmt[0] == '%' && fmt[1] == 's') {
			/* decode each operand in order */
			if (i < R_ARRAY_SIZE (insn->opc->decode) && insn->opc->decode[i]) {
				insn->opc->decode[i] (&opr, insn->value);
				if (opr.type == KVX_OPER_TYPE_IMM)
					w = snprintf (buf + n, len - n, "0x%" PFMT64x, (ut64)opr.imm);
				else if (opr.type == KVX_OPER_TYPE_OFF)
					w = snprintf (buf + n, len - n, "0x%" PFMT64x, (ut64)opr.imm + offset);
				else if (opr.type == KVX_OPER_TYPE_REG)
					w = snprintf (buf + n, len - n, "%s", opr.reg);
				else
					w = 0;
				n += R_MIN (w, len - n);

				i++;
				/* advance after the format '%s' */
				fmt += 2;
			}
		} else {
			/* simple copy */
			buf[n] = fmt[0];
			fmt++;
			n++;
		}
	}
	if (!insn->rem) {
		w = snprintf (buf + n, len - n, " ;;");
		n += R_MIN (w, len - n);
	}
	buf[n] = 0;

	return n;
}

ut64 kvx_instr_jump(insn_t *insn, ut64 offset) {
	operand_t opr;
	int i;

	for (i = 0; i < 4 && insn->opc->decode[i]; i++) {
		insn->opc->decode[i] (&opr, insn->value);
		if (opr.type == KVX_OPER_TYPE_OFF) {
			return opr.imm + offset;
		}
	}
	return offset;
}

static const int immx_to_bundle_issue[] = {
	[IMMX_ISSUE_ALU0] = BUNDLE_ISSUE_ALU0,
	[IMMX_ISSUE_ALU1] = BUNDLE_ISSUE_ALU1,
	[IMMX_ISSUE_MAU] = BUNDLE_ISSUE_MAU,
	[IMMX_ISSUE_LSU] = BUNDLE_ISSUE_LSU,
};

static inline int kvx_steering(ut32 x) {
	return (((x) & 0x60000000) >> 29);
}

static inline int kvx_extension(ut32 x) {
	return (((x) & 0x18000000) >> 27);
}

static inline int kvx_has_parallel_bit(ut32 x) {
	return (((x) & 0x80000000) == 0x80000000);
}

static inline int kvx_is_tca_opcode(ut32 x) {
	unsigned major = ((x)>>24) & 0x1F;
	return (major > 1) && (major < 8);
}

static inline int kvx_is_nop_opcode(ut32 x) {
	return ((x)<<1) == 0xFFFFFFFE;
}

static inline int kvx_opc_match(const opc_t *opc, insn_t *insn) {
	int i;

	if (opc->len != insn->len)
		return 0;

	for (i = 0; i < insn->len; i++) {
		if ((insn->value[i] & opc->mask[i]) != opc->value[i])
			return 0;
	}

	return 1;
}

static int disassemble_bundle(bundle_t *bundle, const ut32 *words, int count) {
	bool used[KVX_MAX_BUNDLE_ISSUE] = {0};
	insn_t *insn;
	ut32 word;
	int issue, immx, extension;
	int bcu = 0;
	int i;

	for (i = 0; i < count; i++) {
		extension = 0;
		word = words[i];
		switch (kvx_steering (word)) {
		case STEERING_BCU:
			if (i == 0 && !kvx_is_tca_opcode (word)) {
				bcu = 1;
				issue = BUNDLE_ISSUE_BCU;
			} else if ((i == 0 && kvx_is_tca_opcode (word))
				|| (i == 1 && bcu && kvx_is_tca_opcode (word))) {
				issue = BUNDLE_ISSUE_TCA;
			} else {
				immx = kvx_extension (word);
				issue = immx_to_bundle_issue[immx];
				extension = 1;
			}
			break;
		case STEERING_ALU:
			if (!used[BUNDLE_ISSUE_ALU0]) {
				issue = BUNDLE_ISSUE_ALU0;
			} else if (!used[BUNDLE_ISSUE_ALU1]) {
				issue = BUNDLE_ISSUE_ALU1;
			} else if (!used[BUNDLE_ISSUE_MAU]) {
				issue = BUNDLE_ISSUE_MAU;
			} else if (!used[BUNDLE_ISSUE_LSU]) {
				issue = BUNDLE_ISSUE_LSU;
			} else {
				/* too many ALUs */
				goto error;
			}
			break;
		case STEERING_MAU:
			issue = BUNDLE_ISSUE_MAU;
			break;
		case STEERING_LSU:
			issue = BUNDLE_ISSUE_LSU;
			break;
		}

		insn = &bundle->issue[issue];

		if (!used[issue]) {
			used[issue] = 1;
			insn->len = 0;
		} else if (!extension && used[issue]) {
			/* issue already used */
			goto error;
		} else if (extension && !used[issue]) {
			/* missing issue */
			goto error;
		}
		if (insn->len == KVX_MAX_SYLLABLES) {
			/* too many syllables */
			goto error;
		}
		insn->value[insn->len] = word;
		insn->len++;
	}

	for (issue = 0; issue < KVX_MAX_BUNDLE_ISSUE; issue++) {
		if (!used[issue])
			continue;
		insn = &bundle->issue[issue];

		insn->opc = NULL;
		for (i = 0; i < KV3_OPC_COUNT; i++) {
			if (kvx_opc_match (&kv3_opc[i], insn)) {
				insn->opc = &kv3_opc[i];
				break;
			}
		}
	}

	count = 0;
	for (issue = KVX_MAX_BUNDLE_ISSUE - 1; issue >= 0; issue--) {
		if (!used[issue])
			continue;
		insn = &bundle->issue[issue];
		insn->rem = count++;
	}

	return 0;
error:
	return -1;
}

static int read_bundle(ut32 *words, const ut8 *buf, int len) {
	int count = 0;
	ut32 word;

	while (len >= sizeof (ut32) && count < KVX_MAX_BUNDLE_WORDS) {
		word = r_read_le32 (buf);
		words[count] = word;
		count++;

		if (!kvx_has_parallel_bit (word)) {
			break;
		}

		buf += sizeof (ut32);
		len -= sizeof (ut32);
	}

	if (count == KVX_MAX_BUNDLE_WORDS && kvx_has_parallel_bit (word)) {
		/* this is wrong */
	}

	return count;
}

insn_t *kvx_next_insn(bundle_t *bundle, ut64 addr, const ut8 *buf, int len) {
	ut32 words[KVX_MAX_BUNDLE_WORDS];
	ut64 start;
	int count, issue = KVX_MAX_BUNDLE_ISSUE;
	int ret;

	if (bundle->addr <= addr && addr < (bundle->addr + bundle->size)) {
		start = bundle->addr;
		issue = 0;
		for (issue = 0; issue < KVX_MAX_BUNDLE_ISSUE; issue++) {
			if (addr == start) {
				break;
			}
			start += bundle->issue[issue].len * sizeof (ut32);
		}
		while (issue < KVX_MAX_BUNDLE_ISSUE && bundle->issue[issue].len == 0) {
			issue++;
		}
	}

	if (issue == KVX_MAX_BUNDLE_ISSUE) {
		memset (bundle, 0, sizeof (*bundle));
		issue = 0;

		count = read_bundle (words, buf, len);
		if (count == 0)
			return NULL;

		bundle->addr = addr;
		bundle->size = count * sizeof (ut32);
		ret = disassemble_bundle (bundle, words, count);
		if (ret)
			return NULL;
	}

	while (issue < KVX_MAX_BUNDLE_ISSUE && bundle->issue[issue].len == 0) {
		issue++;
	}

	if (issue < KVX_MAX_BUNDLE_ISSUE) {
		return &bundle->issue[issue];
	}

	return NULL;
}
