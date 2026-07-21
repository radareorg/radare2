/* radare - LGPL3 - Copyright 2023-2026 - condret */

#define R_LOG_ORIGIN agD

#include <r_core.h>

static char *_get_title(void *data, void *user) {
	return r_str_newf ("0x%"PFMT64x,
			((RAnalBlock *)(((RGraphNode *)data)->data))->addr);
}

static char *_get_body(void *data, void *user) {
	RAnalBlock *bb = (RAnalBlock *)((RGraphNode *)data)->data;
	RCore *core = (RCore *)user;
	ut64 bbsize = bb->size;
	const int graph_bb_maxsize = r_config_get_i (core->config, "graph.bb.maxsize");
	const bool truncated = graph_bb_maxsize > 0 && bbsize > (ut64)graph_bb_maxsize;
	if (truncated) {
		bbsize = graph_bb_maxsize;
	}
	char *body = r_core_cmd_strf (core, "pD 0x%"PFMT64x" @ 0x%"PFMT64x, bbsize, bb->addr);
	if (truncated && body) {
		char *tmp = r_str_newf ("%s\n...", body);
		free (body);
		body = tmp;
	}
	return body;
}

static RCoreHelpMessage help_msg_agD = {
	"Usage:", "agD[format]", "Show the current function dominator tree",
	"agD", "", "print the dominator tree as ASCII art",
	"agDd", "", "print the dominator tree as Graphviz dot",
	"agDj", "", "print the dominator tree as JSON",
	"agDv", "", "show the dominator tree in interactive visual mode",
	NULL
};

static void agD_help(RCmdContext *ctx) {
	RCore *core = ctx->user;
	r_cons_cmd_help (ctx->cons, help_msg_agD, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static RCmdResult agD_invalid(RCmdContext *ctx) {
	agD_help (ctx);
	return (RCmdResult) { .status = 2 };
}

static RCmdResult r_cmd_agD_call(RCmdContext *ctx, RStrs input) {
	RCore *core = ctx->user;
	const size_t argc = RVecRStrs_length (&ctx->args);
	char sub = r_strs_at (input, 3);
	if (sub == '?' && !r_strs_at (input, 4) && !argc) {
		agD_help (ctx);
		return (RCmdResult) { 0 };
	}
	if (sub && isspace ((ut8)sub)) {
		sub = 0;
	}
	if (argc || (sub && !strchr ("dvj", sub))
			|| (sub && r_strs_at (input, 4) && !isspace ((ut8)r_strs_at (input, 4)))) {
		return agD_invalid (ctx);
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_ANY);
	if (!fcn) {
		R_LOG_ERROR ("no fcn here");
		return (RCmdResult) { .status = 1 };
	}
	RGraphNode *node = NULL;
	RGraph *fcn_graph = r_anal_function_get_graph (fcn, &node, core->addr);
	if (!fcn_graph || !node) {
		r_graph_free (fcn_graph);
		R_LOG_ERROR ("no fcn_graph/node here");
		return (RCmdResult) { .status = 1 };
	}
	RGraph *fcn_dtgraph = r_graph_dom_tree (fcn_graph, node);
	const bool o_asm_lines = r_config_get_b (core->config, "asm.lines");
	const bool o_asm_address = r_config_get_b (core->config, "asm.addr");
	const bool o_asm_bytes = r_config_get_b (core->config, "asm.bytes");
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_b (core->config, "asm.addr", false);
	r_config_set_b (core->config, "asm.bytes", false);
	RAGraphTransitionCBs agtcbs = {&_get_title, &_get_body};
	RAGraph *dtagraph = r_agraph_new_from_graph (core, fcn_dtgraph, &agtcbs, core);
	/* restore asm.* options asap */
	r_config_set_b (core->config, "asm.lines", o_asm_lines);
	r_config_set_b (core->config, "asm.addr", o_asm_address);
	r_config_set_b (core->config, "asm.bytes", o_asm_bytes);
	if (!dtagraph) {
		r_graph_free (fcn_dtgraph);
		r_graph_free (fcn_graph);
		R_LOG_ERROR ("cannot build agraph");
		return (RCmdResult) { .status = 1 };
	}
	dtagraph->can->color = r_config_get_b (core->config, "scr.color");
	switch (sub) {
	case 'v':
		/* open interactive visual graph for dom tree (mode 3) */
		r_core_visual_graph (core, dtagraph, NULL, 3);
		r_core_cmd0 (core, "reset");
		break;
	case 'd':
		{
			/* print graphviz/dot from the dominance graph */
			r_cons_printf (ctx->cons, "digraph code {\n");
			RListIter *it;
			RGraphNode *node;
			r_list_foreach (fcn_dtgraph->nodes, it, node) {
				char *title = _get_title (node->data, NULL);
				char *body = _get_body (node->data, core);
				r_cons_printf (ctx->cons, "  \"n%d\" [label=\"%s\\n%s\"];\n",
						node->idx, title? title: "", body? body: "");
				if (title) { free (title); }
				if (body) { free (body); }
			}
			r_list_foreach (fcn_dtgraph->nodes, it, node) {
				RGraphNode **it2;
				R_VEC_FOREACH (&node->out_nodes, it2) {
					r_cons_printf (ctx->cons, "  \"n%d\" -> \"n%d\";\n", node->idx, (*it2)->idx);
				}
			}
			r_cons_printf (ctx->cons, "}\n");
			break;
		}
	case 'j':
		{
			PJ *pj = pj_new ();
			if (pj) {
				r_agraph_print_json (dtagraph, pj);
				r_cons_printf (ctx->cons, "%s\n", pj_string (pj));
				pj_free (pj);
			}
			break;
		}
	default:
		/* fallback: print ascii graph as before */
		r_agraph_print (dtagraph, core);
		break;
	}
	r_agraph_free (dtagraph);
	r_graph_free (fcn_dtgraph);
	r_graph_free (fcn_graph);
	return (RCmdResult) { 0 };
}

static bool plugin_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (!core) {
		return true;
	}
	RCmd *cmd = core->rcmd;
	if (!r_cmd_register (cmd, "agD", r_cmd_agD_call, NULL)) {
		return false;
	}
	cps->data = cmd;
	return true;
}

static bool plugin_fini(RCorePluginSession *cps) {
	if (cps->data) {
		r_cmd_unregister (cps->data, "agD");
	}
	return true;
}

RCorePlugin r_core_plugin_agD = {
	.meta = {
		.name = "agD",
		.desc = "agD core plugin",
		.license = "LGPL-3.0-only",
		.author = "condret",
	},
	.init = plugin_init,
	.fini = plugin_fini,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_agD,
	.version = R2_VERSION
};
#endif
