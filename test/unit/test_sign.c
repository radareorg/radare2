#include <r_anal.h>
#include <r_sign.h>

#include "minunit.h"

static bool check_var_n(RList *vars, int n, RAnalVarProt *ans) {
	RAnalVarProt *test = r_list_get_n (vars, n);
	if (strcmp (test->name, ans->name)) {
		return false;
	}
	if (strcmp (test->type, ans->type)) {
		return false;
	}
	if (test->isarg != ans->isarg) {
		return false;
	}
	if (test->kind != ans->kind) {
		return false;
	}
	return true;
}

static bool test_anal_sign_get_set(void) {
	RAnal *anal = r_anal_new ();

	RSignItem *item = r_sign_item_new ();
	item->name = strdup ("sym.mahboi");
	item->realname = strdup ("sym.Mah.Boi");
	item->comment = strdup ("This peace is what all true warriors strive for");

	item->bytes = R_NEW0 (RSignBytes);
	item->bytes->size = 4;
	item->bytes->bytes = (ut8 *)strdup ("\xde\xad\xbe\xef");
	item->bytes->mask = (ut8 *)strdup ("\xc0\xff\xee\x42");

	item->graph = R_NEW0 (RSignGraph);
	item->graph->bbsum = 42;
	item->graph->cc = 123;
	item->graph->ebbs = 13;
	item->graph->edges = 12;
	item->graph->nbbs = 11;

	item->addr = 0x1337;

	item->refs = r_list_newf (free);
	r_list_append (item->refs, strdup ("gwonam"));
	r_list_append (item->refs, strdup ("link"));

	item->xrefs = r_list_newf (free);
	r_list_append (item->xrefs, strdup ("king"));
	r_list_append (item->xrefs, strdup ("ganon"));

	item->vars = r_anal_var_deserialize ("tr16:arg16:int *,ts42:arg42:int64_t, fb13:var_13:char **");

	item->types = strdup ("char * sym.mahboi (int arg0, uint32_t die)");

	item->hash = R_NEW0 (RSignHash);
	item->hash->bbhash = strdup ("7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851");

	r_sign_add_item (anal, item);
	r_sign_item_free (item);

	r_spaces_set (&anal->zign_spaces, "koridai");
	r_sign_add_comment (anal, "sym.boring", "gee it sure is boring around here");

	// --
	r_spaces_set (&anal->zign_spaces, NULL);
	item = r_sign_get_item (anal, "sym.mahboi");
	mu_assert_notnull (item, "get item");

	mu_assert_streq (item->name, "sym.mahboi", "name");
	mu_assert_streq (item->realname, "sym.Mah.Boi", "realname");
	mu_assert_streq (item->comment, "This peace is what all true warriors strive for", "comment");
	mu_assert_notnull (item->bytes, "bytes");
	mu_assert_eq (item->bytes->size, 4, "bytes size");
	mu_assert_memeq (item->bytes->bytes, (ut8 *)"\xde\xad\xbe\xef", 4, "bytes bytes");
	mu_assert_memeq (item->bytes->mask, (ut8 *)"\xc0\xff\xee\x42", 4, "bytes mask");
	mu_assert_notnull (item->graph, "graph");
	mu_assert_eq (item->graph->bbsum, 42, "graph bbsum");
	mu_assert_eq (item->graph->cc, 123, "graph cc");
	mu_assert_eq (item->graph->ebbs, 13, "graph ebbs");
	mu_assert_eq (item->graph->edges, 12, "graph edges");
	mu_assert_eq (item->graph->nbbs, 11, "graph nbbs");
	mu_assert_eq (item->addr, 0x1337, "addr");
	mu_assert_notnull (item->refs, "refs");
	mu_assert_eq (r_list_length (item->refs), 2, "refs count");
	mu_assert_streq (r_list_get_n (item->refs, 0), "gwonam", "ref");
	mu_assert_streq (r_list_get_n (item->refs, 1), "link", "ref");
	mu_assert_notnull (item->xrefs, "xrefs");
	mu_assert_eq (r_list_length (item->xrefs), 2, "xrefs count");
	mu_assert_streq (r_list_get_n (item->xrefs, 0), "king", "xref");
	mu_assert_streq (r_list_get_n (item->xrefs, 1), "ganon", "xref");

	// vars
	RAnalVarProt v;
	mu_assert_notnull (item->vars, "vars");
	mu_assert_eq (r_list_length (item->vars), 3, "vars count");
	v = (RAnalVarProt){ .isarg = true, .kind = 'r', .name = "arg16", .type = "int *" };
	mu_assert ("var[0]", check_var_n (item->vars, 0, &v));
	v = (RAnalVarProt){ .isarg = true, .kind = 's', .name = "arg42", .type = "int64_t" };
	mu_assert ("var[1]", check_var_n (item->vars, 1, &v));
	v = (RAnalVarProt){ .isarg = false, .kind = 'b', .name = "var_13", .type = "char **" };
	mu_assert ("var[2]", check_var_n (item->vars, 2, &v));

	mu_assert_streq (item->types, "char * sym.mahboi (int arg0, uint32_t die)", "types");
	mu_assert_notnull (item->hash, "hash");
	mu_assert_streq (item->hash->bbhash, "7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851", "hash val");
	r_sign_item_free (item);
	r_spaces_set (&anal->zign_spaces, "koridai");
	item = r_sign_get_item (anal, "sym.boring");
	mu_assert_notnull (item, "get item in space");
	mu_assert_streq (item->comment, "gee it sure is boring around here", "item in space comment");
	r_sign_item_free (item);

	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_anal_sign_get_set);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
