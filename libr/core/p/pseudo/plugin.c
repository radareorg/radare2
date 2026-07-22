/* radare - LGPL - Copyright 2015-2026 - pancake, phix33 */

#include <r_core.h>
#include "pseudo.h"

static RCoreHelpMessage help_msg_pdc = {
	"Usage: pdc[acjlot*]", "", "experimental, unreliable and hacky pseudo-decompiler",
	"pdc", "", "pseudo decompile function in current offset",
	"pdc*", "", "emit decompiled lines as CCu comment commands",
	"pdca", "", "side by side comparing assembly and pseudo",
	"pdcc", "", "pseudo-decompile with C helpers around",
	"pdcl", "", "linear pseudo-decompilation scrolling across functions",
	"pdco", "", "show associated offset next to pseudecompiled output",
	"pdcj", "", "in json format for codemeta annotations (used by frontends like iaito)",
	"pdct", "", "dump the structuring region AST (decompiler debug)",
	NULL
};

static ut64 find_nextop(RCore *core, ut64 addr) {
	RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
	size_t opsz = 1;
	if (op && (int)op->size > 0) {
		opsz = op->size;
	} else {
		const int minopsz = r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE);
		if (minopsz > 1) {
			opsz = minopsz;
		}
	}
	if (UT64_MAX - (ut64)opsz < addr) {
		return UT64_MAX;
	}
	return addr + opsz;
}

// problematic for non-linear functions
// TODO: resort all lines from the decompiler by offset and then use that as guide
static ut64 find_endfunc(RCore *core, ut64 addr) {
	ut64 res = UT64_MAX;
	RList *funcs = r_anal_get_functions_in (core->anal, addr);
	if (funcs) {
		RAnalFunction *f = (RAnalFunction *)r_list_get_n (funcs, 0);
		if (f) {
			res = r_anal_function_max_addr (f);
		}
		r_list_free (funcs);
	}
	return res;
}

static ut64 find_nextfunc(RCore *core, ut64 addr, int range) {
	while (range-- > 0) {
		RAnalFunction *f = r_anal_get_function_at (core->anal, addr);
		if (f) {
			return addr;
		}
		addr = find_nextop (core, addr);
	}
	return UT64_MAX;
}

static void linear_pseudo(RCore *core, const char *arg) {
	int rows = (int)r_num_math (core->num, arg);
	int h;
	r_cons_get_size (core->cons, &h);
	if (rows < 1) {
		rows = h;
	}
	char *offpos = NULL;
	int lines = 0;
	RStrBuf *sb = r_strbuf_new ("");
	ut64 nextaddr = UT64_MAX;
	ut64 initial_addr = core->addr;
	ut64 addr = initial_addr;
repeat:;
	offpos = NULL;
	char *cur = r_core_cmd_str (core, "pdco");
	if (cur) {
		// we have a function, but we need to find the
		// current offset inside the output of the decompiler
		int retries = 10;
	repeat_inside:;
		char *off = r_str_newf ("0x%08" PFMT64x, addr);
		offpos = strstr (cur, off);
		if (!offpos) {
			addr = find_nextop (core, addr);
			if (retries > 0) {
				retries--;
				free (off);
				off = r_str_newf ("0x%08" PFMT64x, addr);
				goto repeat_inside;
			}
			R_FREE (cur);
		}
		R_FREE (off);
	}
	if (offpos) {
		while (offpos > cur) {
			if (*offpos == '\n') {
				offpos++;
				break;
			}
			offpos--;
		}
		r_strbuf_append (sb, offpos);
		lines += r_str_char_count (offpos, '\n');
		ut64 eof = find_endfunc (core, addr);
		if (eof != UT64_MAX) {
			nextaddr = find_nextop (core, eof);
		}
	} else {
		nextaddr = addr;
	}
	free (cur);
	cur = NULL;
	ut64 nextfunc = find_nextfunc (core, nextaddr, 128);
	if (lines < rows) {
#undef ATSTR
#define ATSTR "@e:asm.lines=0@e:asm.pseudo=true@e:asm.bytes=0@e:emu.str=true"
		if (nextfunc == UT64_MAX) {
			char *res = r_core_cmd_strf (core, "pd %d @0x%08" PFMT64x "" ATSTR, rows - lines, addr);
			r_strbuf_append (sb, res);
			free (res);
		} else {
			char *res = r_core_cmd_strf (core, "pD %" PFMT64d " @0x%08" PFMT64x "" ATSTR, nextfunc - addr, addr);
			r_strbuf_append (sb, res);
			lines += r_str_char_count (res, '\n');
			free (res);
			addr = nextfunc;
			r_core_seek (core, nextfunc, true);
			goto repeat;
		}
#undef ATSTR
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (core->cons, s);
	free (s);
	r_core_seek (core, initial_addr, true);
}

static RCmdResult pseudo_help(RCmdContext *ctx, char sub) {
	RCore *core = ctx->user;
	const bool color = core->print->flags & R_PRINT_FLAGS_COLOR;
	if (sub) {
		char subhelp[5] = "pdc";
		subhelp[3] = sub;
		if (r_cons_cmd_help_match (ctx->cons, help_msg_pdc, color, subhelp, 0, true) > 0) {
			return (RCmdResult) { 0 };
		}
	}
	r_cons_cmd_help (ctx->cons, help_msg_pdc, color);
	return (RCmdResult) { 0 };
}

static RCmdResult pseudo_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	if (r_cmd_ctx_help (ctx)) {
		const bool row = r_strs_len (ctx->subcmd) == 2;
		return pseudo_help (ctx, row? r_cmd_ctx_mode (ctx, "acjlot*"): 0);
	}
	const char *tail = ctx->subcmd.a;
	if (r_strs_lastch (ctx->subcmd) == 'l') {
		linear_pseudo (core, tail + 1);
		return (RCmdResult) { 0 };
	}
	const bool ok = pdc_decompile (core, tail);
	return (RCmdResult) { .status = ok? 0: 1 };
}

static bool plugin_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	RCmd *cmd = core->rcmd;
	if (!r_cmd_register (cmd, "pdc", pseudo_callback, NULL)) {
		return false;
	}
	return true;
}

static bool plugin_fini(RCorePluginSession *cps) {
	R_RETURN_VAL_IF_FAIL (cps && cps->core && cps->core->rcmd, false);
	r_cmd_unregister (cps->core->rcmd, "pdc");
	return true;
}

RCorePlugin r_core_plugin_pseudo = {
	.meta = {
		.name = "pseudo",
		.desc = "pdc pseudo decompiler",
		.license = "LGPL-3.0-only",
		.author = "pancake",
	},
	.init = plugin_init,
	.fini = plugin_fini,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_pseudo,
	.version = R2_VERSION
};
#endif
