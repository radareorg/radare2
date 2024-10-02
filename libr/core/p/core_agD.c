/* radare - LGPL3 - Copyright 2023 - condret */

#include <r_core.h>
#include <r_config.h>
#include <r_cons.h>
#include <r_anal.h>
#include <r_util.h>

static char *_get_title(void *data, void *user) {
	return r_str_newf ("0x%"PFMT64x,
		((RAnalBlock *)(((RGraphNode *)data)->data))->addr);
}

static char *_get_body(void *data, void *user) {
	RAnalBlock *bb = (RAnalBlock *)((RGraphNode *)data)->data;
	RCore *core = (RCore *)user;
	return r_core_cmd_strf (core, "pD 0x%"PFMT64x" @ 0x%"PFMT64x, bb->size, bb->addr);
}

static int r_cmd_agD_call(void *user, const char *input) {
	RCore *core = (RCore *)user;
	if (!core) {
		return false;
	}
	if (!r_str_startswith (input, "agD")) {
		return false;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_ANY);
	if (!fcn) {
		R_LOG_ERROR ("core_agD: no fcn here");
		return true;
	}
	RGraphNode *node = NULL;
	RGraph *fcn_graph = r_anal_function_get_graph (fcn, &node, core->offset);
	if (!fcn_graph || !node) {
		R_LOG_ERROR ("core_agD: no fcn_graph/node here");
		return true;
	}
	RGraph *fcn_dtgraph = r_graph_dom_tree (fcn_graph, node);
	const bool o_asm_lines = r_config_get_b (core->config, "asm.lines");
	const bool o_asm_offset = r_config_get_b (core->config, "asm.offset");
	const bool o_asm_bytes = r_config_get_b (core->config, "asm.bytes");
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_b (core->config, "asm.offset", false);
	r_config_set_b (core->config, "asm.bytes", false);
	RAGraphTransitionCBs agtcbs = {&_get_title, &_get_body};
	RAGraph *dtagraph = r_agraph_new_from_graph (fcn_dtgraph, &agtcbs, core);
	r_config_set_b (core->config, "asm.lines", o_asm_lines);
	r_config_set_b (core->config, "asm.offset", o_asm_offset);
	r_config_set_b (core->config, "asm.bytes", o_asm_bytes);
	dtagraph->can->color = r_config_get_b (core->config, "scr.color");
	r_agraph_print (dtagraph);
	r_agraph_free (dtagraph);
	r_graph_free (fcn_dtgraph);
	r_graph_free (fcn_graph);
	r_cons_flush ();
	return true;
}

RCorePlugin r_core_plugin_agD = {
#if R2_VERSION_NUMBER > 50808
	.meta = {
		.name = "agD",
		.desc = "agD core plugin",
		.license = "LGPL3",
		.author = "condret",
	},
#else
	.name = "agD",
	.desc = "agD core plugin",
	.license = "LGPL3",
	.author = "condret",
#endif
	.call = r_cmd_agD_call,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_agD,
	.version = R2_VERSION
};
#endif
