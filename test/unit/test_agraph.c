#include <r_core.h>
#include <r_anal.h>
#include <r_agraph.h>
#include <r_util.h>
#include "minunit.h"

static char *_graph_node_info_get_title(void *data, void *user) {
	RGraphNodeInfo *info = (RGraphNodeInfo *)data;
	return (info && info->title)? strdup (info->title): NULL;
}

static char *_graph_node_info_get_body(void *data, void *user) {
	RGraphNodeInfo *info = (RGraphNodeInfo *)data;
	return (info && info->body)? strdup (info->body): NULL;
}

bool test_graph_to_agraph(void) {
	RCore *core = r_core_new ();
	r_core_cmd0 (core, "ac A");
	r_core_cmd0 (core, "ac B");
	r_core_cmd0 (core, "ac C");
	r_core_cmd0 (core, "ac D");
	r_core_cmd0 (core, "acb B A");
	r_core_cmd0 (core, "acb C A");
	r_core_cmd0 (core, "acb D B");
	r_core_cmd0 (core, "acb D C");

	RGraph *graph = r_anal_class_get_inheritance_graph (core->anal);
	mu_assert_notnull (graph, "Couldn't create the graph");
	mu_assert_eq (graph->nodes->length, 4, "Wrong node count");

	RAGraphTransitionCBs cbs = {
		.get_title = _graph_node_info_get_title,
		.get_body = _graph_node_info_get_body
	};
	RAGraph *agraph = r_agraph_new_from_graph (core, graph, &cbs, NULL);
	mu_assert_notnull (agraph, "Couldn't create the graph");
	mu_assert_eq (agraph->graph->nodes->length, 4, "Wrong node count");

	RListIter *iter;
	RGraphNode *node;
	int i = 0;
	ls_foreach (agraph->graph->nodes, iter, node) {
		RANode *info = node->data;
		switch (i++) {
		case 0:
			mu_assert_streq (info->title, "A", "Wrong node name");
			mu_assert_eq (RVecGraphNodePtr_length (&node->out_nodes), 2, "Wrong node out-nodes");
			{
				RGraphNode **iter;
				RGraphNode *out_node;
				int i = 0;
				R_VEC_FOREACH (&node->out_nodes, iter) {
					out_node = *iter;
					RANode *info = out_node->data;
					switch (i++) {
					case 0:
						mu_assert_streq (info->title, "B", "Wrong node name");
						break;
					case 1:
						mu_assert_streq (info->title, "C", "Wrong node name");
						break;
					}
				}
			}
			break;
		case 1:
			mu_assert_streq (info->title, "B", "Wrong node name");
			mu_assert_eq (RVecGraphNodePtr_length (&node->out_nodes), 1, "Wrong node out-nodes");
			mu_assert_eq (RVecGraphNodePtr_length (&node->in_nodes), 1, "Wrong node in-nodes");
			{
				RGraphNode **iter;
				RGraphNode *out_node;
				int i = 0;
				R_VEC_FOREACH (&node->out_nodes, iter) {
					out_node = *iter;
					RANode *info = out_node->data;
					switch (i++) {
					case 0:
						mu_assert_streq (info->title, "D", "Wrong node name");
						break;
					}
				}
			}
			break;
		case 2:
			mu_assert_streq (info->title, "C", "Wrong node name");
			mu_assert_eq (RVecGraphNodePtr_length (&node->out_nodes), 1, "Wrong node out-nodes");
			mu_assert_eq (RVecGraphNodePtr_length (&node->in_nodes), 1, "Wrong node in-nodes");
			{
				RGraphNode **iter;
				RGraphNode *out_node;
				int i = 0;
				R_VEC_FOREACH (&node->out_nodes, iter) {
					out_node = *iter;
					RANode *info = out_node->data;
					switch (i++) {
					case 0:
						mu_assert_streq (info->title, "D", "Wrong node name");
						break;
					}
				}
			}
			break;
		case 3:
			mu_assert_streq (info->title, "D", "Wrong node name");
			mu_assert_eq (RVecGraphNodePtr_length (&node->in_nodes), 2, "Wrong node in-nodes");
			break;
		default:
			break;
		}
	}
	char *rendered = r_agraph_tostring (agraph, core);
	mu_assert_notnull (rendered, "Couldn't render the graph");
	mu_assert_notnull (strstr (rendered, "A"), "Missing rendered node");
	free (rendered);
	r_core_free (core);
	r_graph_free (graph);
	r_agraph_free (agraph);
	mu_end;
}

static bool graph_nodes_overlap(const RAGraph *graph) {
	RListIter *first, *second;
	RGraphNode *first_node, *second_node;
	r_list_foreach (graph->graph->nodes, first, first_node) {
		const RANode *a = first_node->data;
		for (second = first->n; second; second = second->n) {
			second_node = second->data;
			const RANode *b = second_node->data;
			if (a->x < b->x + b->w && b->x < a->x + a->w
					&& a->y < b->y + b->h && b->y < a->y + a->h) {
				return true;
			}
		}
	}
	return false;
}

static bool graph_edges_cross_nodes(const RAGraph *graph, char *rendered) {
	size_t count;
	size_t *lines = r_str_split_lines (rendered, &count);
	if (!lines) {
		return true;
	}
	RListIter *iter;
	RGraphNode *node;
	bool crosses = false;
	r_list_foreach (graph->graph->nodes, iter, node) {
		const RANode *a = node->data;
		int x, y;
		for (y = 1; y < a->h - 1 && !crosses; y++) {
			int row = a->y + graph->can->sy + y;
			if (row < 0 || row >= count) {
				continue;
			}
			const char *line = rendered + lines[row];
			size_t length = strlen (line);
			for (x = 1; x < a->w - 1; x++) {
				int column = a->x + graph->can->sx + x;
				if (column >= 0 && column < length && strchr ("|-.'`", line[column])) {
					crosses = true;
					break;
				}
			}
		}
	}
	free (lines);
	return crosses;
}

bool test_agraph_layout_spacing(void) {
	RCore *core = r_core_new ();
	RAGraph *graph = core->graph;
	graph->dummy = true;
	graph->can->linemode = 1;
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", false);
	graph->need_reload_nodes = false;
	const int widths[] = {51, 26, 58, 18, 25, 37, 26, 57};
	const int edges[][2] = {
		{0, 4}, {1, 3}, {2, 5}, {3, 1}, {3, 4}, {4, 2},
		{4, 6}, {5, 6}, {6, 1}, {6, 7}, {7, 0}, {7, 2}
	};
	RANode *nodes[8];
	int i, layout, pass;
	for (i = 0; i < R_ARRAY_SIZE (nodes); i++) {
		char title[8];
		snprintf (title, sizeof (title), "n%d", i);
		char *body = r_str_repeat ("x", widths[i]);
		mu_assert_notnull (body, "Couldn't create the node body");
		nodes[i] = r_agraph_add_node (graph, title, body, NULL);
		free (body);
	}
	for (i = 0; i < R_ARRAY_SIZE (edges); i++) {
		r_agraph_add_edge (graph, nodes[edges[i][0]], nodes[edges[i][1]], false);
	}
	for (layout = 0; layout < 2; layout++) {
		graph->layout = layout;
		for (pass = 0; pass < 2; pass++) {
			char *rendered = r_agraph_tostring (graph, core);
			mu_assert_notnull (rendered, "Couldn't render the graph");
			mu_assert_false (graph_nodes_overlap (graph), "Nodes or dummy edge corridors overlap");
			mu_assert_false (graph_edges_cross_nodes (graph, rendered), "Edges cross node interiors");
			free (rendered);
		}
	}
	r_core_free (core);
	mu_end;
}

bool test_agraph_horizontal_heights(void) {
	RCore *core = r_core_new ();
	RAGraph *graph = core->graph;
	graph->need_reload_nodes = false;
	graph->layout = 1;
	r_agraph_add_node (graph, "short", "x", NULL);
	r_agraph_add_node (graph, "tall", "x\nx\nx\nx\nx\nx\nx\nx\nx\nx", NULL);
	r_agraph_add_node (graph, "medium", "x\nx\nx\nx", NULL);
	r_agraph_get_sdb (graph);
	mu_assert_false (graph_nodes_overlap (graph), "Horizontal nodes with different heights overlap");
	r_core_free (core);
	mu_end;
}

bool test_agraph_horizontal_incoming_ports(void) {
	RCore *core = r_core_new ();
	RAGraph *graph = core->graph;
	graph->need_reload_nodes = false;
	graph->layout = 1;
	graph->can->linemode = 1;
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", false);
	RANode *root = r_agraph_add_node (graph, "root", "", NULL);
	RANode *targets[6];
	int i;
	for (i = 0; i < R_ARRAY_SIZE (targets); i++) {
		char title[8];
		snprintf (title, sizeof (title), "n%d", i);
		targets[i] = r_agraph_add_node (graph, title, "", NULL);
		r_agraph_add_edge (graph, root, targets[i], false);
	}
	char *rendered = r_agraph_tostring (graph, core);
	mu_assert_notnull (rendered, "Couldn't render the graph");
	size_t count;
	size_t *lines = r_str_split_lines (rendered, &count);
	mu_assert_notnull (lines, "Couldn't split the rendered graph");
	for (i = 0; i < R_ARRAY_SIZE (targets); i++) {
		RANode *target = targets[i];
		int row = target->y + graph->can->sy + R_EDGES_X_INC - 1;
		int column = target->x + graph->can->sx - 1;
		mu_assert_true (row >= 0 && row < count, "Incoming port outside canvas");
		const char *line = rendered + lines[row];
		mu_assert_true (column >= 0 && column < strlen (line), "Missing incoming edge");
		mu_assert_eq (line[column], '-', "Edge misses the target's sole incoming port");
	}
	free (lines);
	free (rendered);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_graph_to_agraph);
	mu_run_test (test_agraph_layout_spacing);
	mu_run_test (test_agraph_horizontal_heights);
	mu_run_test (test_agraph_horizontal_incoming_ports);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
