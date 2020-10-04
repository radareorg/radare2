#include <r_core.h>
#include <r_util/r_graph_drawable.h>

R_API void r_graph_free_node_info(void *ptr) {
	if (!ptr) {
		return;
	}
	RGraphNodeInfo *info = ptr;
	free (info->body);
	free (info->title);
	free (info);
}

R_API RGraphNodeInfo *r_graph_create_node_info(const char *title, const char *body, ut64 offset) {
	RGraphNodeInfo *data = R_NEW0 (RGraphNodeInfo);
	if (data) {
		data->title = R_STR_DUP (title);
		data->body = R_STR_DUP (body);
		data->offset = offset;
	}
	return data;
}

R_API RGraphNode *r_graph_add_node_info(RGraph *graph, const char *title, const char *body, ut64 offset) {
	r_return_val_if_fail (graph, NULL);
	RGraphNodeInfo *data = r_graph_create_node_info (title, body, offset);
	if (!data) {
		return NULL;
	}
	RGraphNode *node = r_graph_add_nodef (graph, data, r_graph_free_node_info);
	if (!node) {
		r_graph_free_node_info (data);
	}
	return node;
}

R_API char *r_graph_drawable_to_dot(RGraph /*RGraphNodeInfo*/ *graph, const char *node_properties, const char *edge_properties) {
	RList *nodes = graph->nodes;
	RListIter *it, *itt;
	RGraphNode *node = NULL, *target = NULL;
	RStrBuf buf;
	r_strbuf_init (&buf);
	r_strbuf_appendf (&buf,
		"digraph code {\nrankdir=LR;\noutputorder=edgesfirst\ngraph [bgcolor=azure];\n"
		"edge [arrowhead=normal, color=\"#3030c0\" style=bold weight=2 %s];\n"
		"node [fillcolor=white, style=filled shape=box "
		"fontsize=\"8\" %s];\n",
		edge_properties? edge_properties: "",
		node_properties? node_properties: "");

	r_list_foreach (nodes, it, node) {
		RGraphNodeInfo *print_node = (RGraphNodeInfo *)node->data;
		const char *body = print_node->body;
		if (!body || !*body) {
			r_strbuf_appendf (&buf, "%d [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
				node->idx, print_node->title, print_node->title);
		} else {
			r_strbuf_appendf (&buf, "%d [URL=\"%s\", color=\"lightgray\", label=\"%s\\n%s\"]\n",
				node->idx, print_node->title, print_node->title, body);
		}
		r_list_foreach (node->out_nodes, itt, target) {
			r_strbuf_appendf (&buf, "%d -> %d\n", node->idx, target->idx);
		}
	}
	r_strbuf_append (&buf, "}\n");
	return r_strbuf_drain_nofree (&buf);
}

R_API void r_graph_drawable_to_json(RGraph /*RGraphNodeInfo*/ *graph, PJ *pj, bool use_offset) {
	RList *nodes = graph->nodes, *neighbours = NULL;
	RListIter *it, *itt;
	RGraphNode *node = NULL, *neighbour = NULL;
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_k (pj, "nodes");
	pj_a (pj);

	r_list_foreach (nodes, it, node) {
		RGraphNodeInfo *print_node = (RGraphNodeInfo *)node->data;
		pj_o (pj);
		pj_ki (pj, "id", node->idx);
		if (print_node->title) {
			pj_ks (pj, "title", print_node->title);
		}
		if (print_node->body) {
			pj_ks (pj, "body", print_node->body);
		}
		if (use_offset) {
			pj_kn (pj, "offset", print_node->offset);
		}
		pj_k (pj, "out_nodes");
		pj_a (pj);
		neighbours = node->out_nodes;
		r_list_foreach (neighbours, itt, neighbour) {
			pj_i (pj, neighbour->idx);
		}
		pj_end (pj);
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
}
