/* radare - LGPL - Copyright 2019 - condret */

#include <r_core.h>
#include <r_anal.h>
#include <r_util.h>

R_API void r_core_anal_esil_graph(RCore *core, const char *expr) {
	RAnalEsilDFG * edf = r_anal_esil_dfg_expr(core->anal, NULL, expr);
	RListIter *iter, *ator;
	RGraphNode *node, *edon;
	RStrBuf *buf = r_strbuf_new ("");
	r_list_foreach (r_graph_get_nodes (edf->flow), iter, node) {
		const RAnalEsilDFGNode *enode = (RAnalEsilDFGNode *)node->data;
		char *esc_str = r_str_escape (r_strbuf_get (enode->content));
		r_strbuf_set (buf, esc_str);
		if (enode->type == R_ANAL_ESIL_DFG_BLOCK_GENERATIVE) {
			r_strbuf_prepend (buf, "generative:");
		}
		char *b64_buf = r_base64_encode_dyn (r_strbuf_get (buf), buf->len);
		r_cons_printf ("agn %d base64:%s\n", enode->idx, b64_buf);
		free (b64_buf);
		free (esc_str);
	}
	r_strbuf_free (buf);

	r_list_foreach (r_graph_get_nodes (edf->flow), iter, node) {
		const RAnalEsilDFGNode *enode = (RAnalEsilDFGNode *)node->data;
		r_list_foreach (r_graph_get_neighbours (edf->flow, node), ator, edon) {
			const RAnalEsilDFGNode *edone = (RAnalEsilDFGNode *)edon->data;
			r_cons_printf ("age %d %d\n", enode->idx, edone->idx);
		}
	}

	r_anal_esil_dfg_free(edf);
}
