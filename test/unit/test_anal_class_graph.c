#include <r_core.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_util/r_graph_drawable.h>
#include "minunit.h"

bool test_inherit_graph_creation() {
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

	RListIter *iter;
	RGraphNode *node;
	int i = 0;
	ls_foreach (graph->nodes, iter, node) {
		RGraphNodeInfo *info = node->data;
		switch (i++) {
		case 0:
			mu_assert_streq (info->title, "A", "Wrong node name");
			mu_assert_eq (node->out_nodes->length, 2, "Wrong node out-nodes");
			{
				RListIter *iter;
				RGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
					RGraphNodeInfo *info = out_node->data;
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
					RGraphNodeInfo *info = out_node->data;
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
					RGraphNodeInfo *info = out_node->data;
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
	mu_end;
}

int all_tests() {
	mu_run_test (test_inherit_graph_creation);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
