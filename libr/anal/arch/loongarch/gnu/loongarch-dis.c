/* radare - LGPL - Copyright 2021-2022 - junchao82@qq.com;zhaojunchao@loongson.cn love lanhy*/

#include <r_util.h>
#include "loongarch-private.h"
#include "disas-asm.h"

#define INSNLEN 4

static R_TH_LOCAL RStrBuf *args_buf = NULL;

static const char * const *loongarch_r_disname = loongarch_r_lp64_name;
static const char * const *loongarch_f_disname = loongarch_f_normal_name;
static const char * const *loongarch_c_disname = loongarch_c_normal_name;
static const char * const *loongarch_cr_disname = loongarch_cr_normal_name;
static const char * const *loongarch_v_disname = loongarch_v_normal_name;
static const char * const *loongarch_x_disname = loongarch_x_normal_name;

static const struct loongarch_opcode * get_loongarch_opcode_by_binfmt (insn_t insn) {
	const struct loongarch_opcode *it;
	struct loongarch_ase *ase;
	size_t i;
	for (ase = loongarch_ASEs; ase->enabled; ase++) {
		if (!*ase->enabled || (ase->include && !*ase->include) || (ase->exclude && *ase->exclude)) {
			continue;
		}
		if (!ase->opc_htab_inited) {
			for (it = ase->opcodes; it->mask; it++) {
				if (!ase->opc_htab[LARCH_INSN_OPC (it->match)] && !it->macro) {
					ase->opc_htab[LARCH_INSN_OPC (it->match)] = it;
				}
			}
			for (i = 0; i < 16; i++) {
				if (!ase->opc_htab[i]) {
					ase->opc_htab[i] = it;
				}
			}
			ase->opc_htab_inited = 1;
		}

		it = ase->opc_htab[LARCH_INSN_OPC(insn)];
		for (; it->name; it++) {
			if ((insn & it->mask) == it->match
					&& it->mask
					&& !(it->include && !*it->include)
					&& !(it->exclude && *it->exclude)) {
				return it;
			}
		}
	}
	return NULL;
}

static R_TH_LOCAL bool need_comma = false;

static int32_t dis_one_arg(char esc1, char esc2, const char *bit_field, const char *arg ATTRIBUTE_UNUSED, void *context) {
	struct disassemble_info *info = context;
	insn_t insn = *(insn_t *) info->private_data;
	int32_t imm, u_imm, abs_imm;
	if (esc1) {
		if (need_comma) {
			r_strbuf_append (args_buf, ",");
		}
		need_comma = true;
		imm = loongarch_decode_imm (bit_field, insn, 1);
		u_imm = loongarch_decode_imm (bit_field, insn, 0);
	}

	switch (esc1) {
	case 'r':
		r_strbuf_appendf (args_buf, " %s", loongarch_r_disname[u_imm]);
		break;
	case 'f':
		r_strbuf_appendf (args_buf, " %s", loongarch_f_disname[u_imm]);
		break;
	case 'c':

		switch (esc2) {
			case 'r':
				r_strbuf_appendf (args_buf, " %s", loongarch_cr_disname[u_imm]);
				break;
			default:
				r_strbuf_appendf (args_buf, " %s", loongarch_c_disname[u_imm]);
		}
		break;
	case 'v':
		r_strbuf_appendf (args_buf, " %s", loongarch_v_disname[u_imm]);
		break;
	case 'x':
		r_strbuf_appendf (args_buf, " %s", loongarch_x_disname[u_imm]);
		break;
	case 'u':
		r_strbuf_appendf (args_buf, " 0x%x", u_imm);
		break;
	case 's':
		if (imm == 0) {
			r_strbuf_appendf (args_buf, " %d", imm);
		} else {
			abs_imm = abs (imm);
			r_strbuf_appendf (args_buf, " ");
			if (abs_imm != imm) {
				r_strbuf_appendf (args_buf, "-");
			}
			r_strbuf_appendf (args_buf, "0x%x", abs_imm);
		}
		if (esc2 == 'b') {
			info->insn_type = dis_branch;
			info->target += imm;
		}
		break;
	case '\0':
		need_comma = false;
		break;
	}
	return 0;
}

/* Print the loongarch instruction at address MEMADDR in debugged memory,
   on using INFO.  Returns length of the instruction, in bytes, which is
   always INSNLEN. */

static int do_print_insn_loongarch (int insn, struct disassemble_info *info) {
	const fprintf_ftype infprintf = info->fprintf_func;
	void *is = info->stream;
	const struct loongarch_opcode *opc = get_loongarch_opcode_by_binfmt (insn);

	if (!opc) {
		info->insn_type = dis_noninsn;
		infprintf (is, "0x%08x", insn);
		return INSNLEN;
	}

	args_buf = r_strbuf_new("");
	info->bytes_per_line = 4;
	info->insn_info_valid = 1;
	info->bytes_per_chunk = INSNLEN;
	info->display_endian = info->endian;
	info->insn_info_valid = 1;
	info->branch_delay_insns = 0;
	info->data_size = 0;
	info->insn_type = dis_nonbranch;
	info->target = 0;
	info->target2 = 0;
	info->insn_type = dis_nonbranch;

	infprintf (is, "%s", opc->name);

	{
		char *fake_args = (char *)malloc(strlen (opc->format) + 1);
		const char *fake_arg_strs[MAX_ARG_NUM_PLUS_2];
		strcpy (fake_args, opc->format);
		if (0 < loongarch_split_args_by_comma (fake_args, fake_arg_strs)) {
			infprintf (is, " ");
		}
		info->private_data = &insn;
		loongarch_foreach_args (opc->format, fake_arg_strs, dis_one_arg, info);
		free (fake_args);
	}
	infprintf (is, "%s", args_buf->buf);

	if (info->insn_type == dis_branch || info->insn_type == dis_condbranch) {
		infprintf (is, " #");
	}
	if (info->insn_type == dis_branch || info->insn_type == dis_condbranch) {
		/* infprintf (is, " "); */
		/* info->print_address_func (info->target, info); */
	}
	r_strbuf_free (args_buf);
	return INSNLEN;
}

int print_insn_loongarch (bfd_vma memaddr, struct disassemble_info *info) {
	bfd_byte buffer[INSNLEN] = {0};
	int status = (*info->read_memory_func) (memaddr, buffer, INSNLEN, info);
	if (status) {
		(*info->memory_error_func) (status, memaddr, info);
		return -1;
	}
	return do_print_insn_loongarch (bfd_getl32 (buffer), info);
}
