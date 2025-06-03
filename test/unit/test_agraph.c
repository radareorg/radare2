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
	RAGraph *agraph = r_agraph_new_from_graph (core->cons, graph, &cbs, NULL);
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
			mu_assert_eq (node->out_nodes->length, 2, "Wrong node out-nodes");
			{
				RListIter *iter;
				RGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
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
			mu_assert_eq (node->out_nodes->length, 1, "Wrong node out-nodes");
			mu_assert_eq (node->in_nodes->length, 1, "Wrong node in-nodes");
			{
				RListIter *iter;
				RGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
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
			mu_assert_eq (node->out_nodes->length, 1, "Wrong node out-nodes");
			mu_assert_eq (node->in_nodes->length, 1, "Wrong node in-nodes");
			{
				RListIter *iter;
				RGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
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
			mu_assert_eq (node->in_nodes->length, 2, "Wrong node in-nodes");
			break;
		default:
			break;
		}
	}
	r_core_free (core);
	r_graph_free (graph);
	r_agraph_free (agraph);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_graph_to_agraph);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
