/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_CORE_CMD_PDC_INC_C
#define R_CORE_CMD_PDC_INC_C

static void pdc_block_free(HtUPKv *kv) {
	r_strbuf_free (kv->value);
}

R_IPI HtUP *r_core_pdc_blocks(RCore *core, RAnalFunction *fcn) {
	char *output = r_core_cmd_strf (core, "pdcj @e:cmd.bbgraph= @ 0x%"PFMT64x, fcn->addr);
	RJson *json = output? r_json_parsedup (output): NULL;
	free (output);
	const char *text = json && json->type == R_JSON_OBJECT? r_json_get_str (json, "code"): NULL;
	const RJson *annotations = text? r_json_get (json, "annotations"): NULL;
	if (!annotations || annotations->type != R_JSON_ARRAY) {
		r_json_free (json);
		R_LOG_ERROR ("Decompiler did not produce annotated code");
		return NULL;
	}
	RCodeMeta *code = r_codemeta_new (text);
	const size_t length = strlen (text);
	const RJson *annotation;
	for (annotation = annotations->children.first; annotation; annotation = annotation->next) {
		if (annotation->type != R_JSON_OBJECT || !r_str_eq (r_json_get_str (annotation, "type"), "offset")) {
			continue;
		}
		const RJson *start = r_json_get (annotation, "start");
		const RJson *end = r_json_get (annotation, "end");
		const RJson *offset = r_json_get (annotation, "offset");
		if (start && end && offset && start->type == R_JSON_INTEGER && end->type == R_JSON_INTEGER
				&& offset->type == R_JSON_INTEGER && start->num.u_value < end->num.u_value && end->num.u_value <= length) {
			RCodeMetaItem item = { .start = start->num.u_value, .end = end->num.u_value,
				.type = R_CODEMETA_TYPE_OFFSET, .offset.offset = offset->num.u_value };
			r_codemeta_add_item (code, &item);
		}
	}
	r_json_free (json);
	HtUP *bodies = ht_up_new (NULL, pdc_block_free, NULL);
	RVecCodeMetaOffset *offsets = r_codemeta_line_offsets (code);
	if (bodies && offsets) {
		char *line = code->code;
		ut64 *offset;
		R_VEC_FOREACH (offsets, offset) {
			char *end = strchr (line, '\n');
			size_t size = end? end + 1 - line: strlen (line);
			RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, *offset);
			if (bb) {
				RStrBuf *body = ht_up_find (bodies, bb->addr, NULL);
				if (!body) {
					body = r_strbuf_new (NULL);
					if (!ht_up_insert (bodies, bb->addr, body)) {
						r_strbuf_free (body);
						body = NULL;
					}
				}
				if (body) {
					r_strbuf_append_n (body, line, size);
				}
			}
			line += size;
		}
	}
	RVecCodeMetaOffset_free (offsets);
	r_codemeta_free (code);
	return bodies;
}

static inline bool pdc_names_pseudo(const char *decompiler) {
	return !*decompiler || !strcmp (decompiler, "pdc") || !strcmp (decompiler, "pd:c");
}

static RCmdResult pdc_router_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *rest = ctx->subcmd.a;
	const char *configured = r_str_trim_head_ro (r_config_get (core->config, "cmd.pdc"));
	if (pdc_names_pseudo (configured)) {
		return (RCmdResult) { .status = r_core_cmdf (core, "pd:c%s", rest) != 0 };
	}
	char *decompiler = strdup (configured);
	RConfigHold *hc = r_config_hold_new (core->config);
	r_config_hold (hc, "asm.addr.relto", "asm.addr.base", "cmd.pdc", NULL);
	r_config_set (core->config, "asm.addr.relto", "");
	r_config_set_i (core->config, "asm.addr.base", 16);
	// a pdc reached from the configured command must land on pseudo, not back here
	r_config_set (core->config, "cmd.pdc", "");
	if (strstr (decompiler, "!*") || strstr (decompiler, "#!")) {
		if (!strcmp (rest, "*")) {
			rest = " -r2";
		} else if (!strcmp (rest, "=")) {
			rest = " -a";
		}
	}
	if (!strcmp (decompiler, "pdd") && !strcmp (rest, "j")) {
		rest = "A";
	}
	const bool failed = r_core_cmdf (core, "%s%s", decompiler, rest) != 0;
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	free (decompiler);
	return (RCmdResult) { .status = failed };
}

static RCmdResult pdc_block_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	if (r_cmdctx_help (ctx)) {
		r_cons_println (core->cons, "Usage: pdcb\nDecompile the current basic block using cmd.pdc (without importing comments)");
		return (RCmdResult) { 0 };
	}
	if (!r_strs_empty (ctx->subcmd) || r_cmdctx_argc (ctx)) {
		return (RCmdResult) { .status = 1 };
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
	RAnalBlock *bb = fcn? r_anal_function_bbget_in (core->anal, fcn, core->addr): NULL;
	if (!bb) {
		R_LOG_ERROR ("No basic block at 0x%"PFMT64x, core->addr);
		return (RCmdResult) { .status = 1 };
	}
	HtUP *blocks = r_core_pdc_blocks (core, fcn);
	if (!blocks) {
		return (RCmdResult) { .status = 1 };
	}
	RStrBuf *body = ht_up_find (blocks, bb->addr, NULL);
	if (body) {
		r_cons_print (core->cons, r_strbuf_get (body));
	}
	ht_up_free (blocks);
	return (RCmdResult) { 0 };
}

static bool r_core_cmd_pdc_init(RCmd *cmd) {
	return r_cmd_register (cmd, "pdc", pdc_router_callback, NULL)
		&& r_cmd_register (cmd, "pdcb", pdc_block_callback, NULL);
}

#endif
