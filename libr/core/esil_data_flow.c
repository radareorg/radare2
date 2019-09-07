/* radare - LGPL - Copyright 2019 - condret */

#include <r_core.h>
#include <r_anal.h>
#include <r_util.h>

R_API void r_core_anal_esil_graph(RCore *core, const char *expr) {
	RAnalEsilDFG * edf = r_anal_esil_dfg_expr(core->anal, expr);
	RListIter *iter, *ator;
	RGraphNode *node, *edon;
	r_list_foreach (r_graph_get_nodes (edf->flow), iter, node) {
		const RAnalEsilDFGNode *enode = (RAnalEsilDFGNode *)node->data;
		char *esc_str = r_str_escape (r_strbuf_get (enode->content));
		if (enode->generative) {
			r_cons_printf ("\"agn %d generative:%s\"\n", enode->idx, esc_str);
		} else {
			r_cons_printf ("\"agn %d %s\"\n", enode->idx, esc_str);
		}
		free (esc_str);
	}

	r_list_foreach (r_graph_get_nodes (edf->flow), iter, node) {
		const RAnalEsilDFGNode *enode = (RAnalEsilDFGNode *)node->data;
		r_list_foreach (r_graph_get_neighbours (edf->flow, node), ator, edon) {
			const RAnalEsilDFGNode *edone = (RAnalEsilDFGNode *)edon->data;
			r_cons_printf ("age %d %d\n", enode->idx, edone->idx);
		}
	}

	r_anal_esil_dfg_free(edf);
}
