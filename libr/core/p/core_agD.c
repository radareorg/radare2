/* radare - LGPL3 - Copyright 2023-2025 - condret */

#include <r_core.h>

static char *_get_title(void *data, void *user) {
	return r_str_newf ("0x%"PFMT64x,
			((RAnalBlock *)(((RGraphNode *)data)->data))->addr);
}

static char *_get_body(void *data, void *user) {
	RAnalBlock *bb = (RAnalBlock *)((RGraphNode *)data)->data;
	RCore *core = (RCore *)user;
	return r_core_cmd_strf (core, "pD 0x%"PFMT64x" @ 0x%"PFMT64x, bb->size, bb->addr);
}

static bool r_cmd_agD_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (!core) {
		return false;
	}
	if (!r_str_startswith (input, "agD")) {
		return false;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_ANY);
	if (!fcn) {
		R_LOG_ERROR ("core_agD: no fcn here");
		return true;
	}
	RGraphNode *node = NULL;
	RGraph *fcn_graph = r_anal_function_get_graph (fcn, &node, core->addr);
	if (!fcn_graph || !node) {
		R_LOG_ERROR ("core_agD: no fcn_graph/node here");
		return true;
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
		R_LOG_ERROR ("core_agD: cannot build agraph");
		return true;
	}
	dtagraph->can->color = r_config_get_b (core->config, "scr.color");
	/* Support subcommands similar to agf: v (visual), d (graphviz/dot), j (json) */
	char sub = input[3];
	if (sub == '?') {
		r_cons_printf (core->cons, "agD subcommands:\n");
		r_cons_printf (core->cons, "  agD        : print dom tree (ascii)\n");
		r_cons_printf (core->cons, "  agDv       : open dom tree in visual interactive mode\n");
		r_cons_printf (core->cons, "  agDd      : print graphviz/dot output\n");
		r_cons_printf (core->cons, "  agDj      : print json output\n");
		r_agraph_free (dtagraph);
		r_graph_free (fcn_dtgraph);
		r_graph_free (fcn_graph);
		r_cons_flush (core->cons);
		return true;
	}
	switch (sub) {
	case 'v':
		/* open interactive visual graph for dom tree (mode 3) */
		r_core_visual_graph (core, dtagraph, NULL, 3);
		r_core_cmd0 (core, "reset");
		break;
	case 'd':
		{
			/* print graphviz/dot from the dominance graph */
			r_cons_printf (core->cons, "digraph code {\n");
			RListIter *it;
			RGraphNode *node;
			int idx = 0;
			HtPPOptions pointer_options = {0};
			HtPP *map = ht_pp_new_opt (&pointer_options);
			r_list_foreach (fcn_dtgraph->nodes, it, node) {
				char *title = _get_title (node->data, NULL);
				char *body = _get_body (node->data, core);
				r_cons_printf (core->cons, "  \"n%d\" [label=\"%s\\n%s\"];\n",
						idx, title? title: "", body? body: "");
				if (title) { free (title); }
				if (body) { free (body); }
				ht_pp_insert (map, node, (void *)(size_t)idx);
				idx++;
			}
			r_list_foreach (fcn_dtgraph->nodes, it, node) {
				RListIter *it2;
				RGraphNode *n2;
				r_list_foreach (node->out_nodes, it2, n2) {
					bool found;
					int i1 = (int)(size_t) ht_pp_find (map, node, &found);
					int i2 = (int)(size_t) ht_pp_find (map, n2, &found);
					r_cons_printf (core->cons, "  \"n%d\" -> \"n%d\";\n", i1, i2);
				}
			}
			ht_pp_free (map);
			r_cons_printf (core->cons, "}\n");
			break;
		}
	case 'j':
		{
			PJ *pj = pj_new ();
			if (pj) {
				r_agraph_print_json (dtagraph, pj);
				r_cons_printf (core->cons, "%s\n", pj_string (pj));
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
	r_cons_flush (core->cons);
	return true;
}

RCorePlugin r_core_plugin_agD = {
	.meta = {
		.name = "agD",
		.desc = "agD core plugin",
		.license = "LGPL-3.0-only",
		.author = "condret",
	},
	.call = r_cmd_agD_call,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_agD,
	.version = R2_VERSION
};
#endif
