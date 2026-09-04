#include <r_core.h>
#include "minunit.h"

typedef struct {
	int missing_eligible_calls;
	int negative_eligible_calls;
	int low_decompile_calls;
	int selected_decompile_calls;
	int tied_decompile_calls;
	RCodeMeta *returned;
} DecompilerTestContext;

typedef struct {
	bool enabled;
	bool fail;
	int eligible_calls;
	int decompile_calls;
	bool view_ok;
	ut64 last_function_addr;
	char *last_function_name;
} CoreDecompilerTestContext;

typedef struct {
	int calls;
	bool view_ok;
	bool image_view_ok;
	bool advisory_edge_ok;
	bool owned_bounded_image;
	bool exact_string_copy_ok;
	bool truncation_refused;
	ut64 function_addr;
	ut64 revision_identity;
	int bits;
	ut32 endian;
	ut8 first_byte;
	char *arch_id;
	char *cpu_id;
	char *calling_convention;
	char *function_name;
} SnapshotProbe;

typedef struct {
	int calls;
	bool copied_decoder_block;
	bool decoder_topology_ok;
	ut8 first_byte;
} AnalyzedSnapshotProbe;

typedef struct {
	size_t count;
	ut64 owner_addr;
	ut64 switch_addr;
} SwitchOwnershipProbe;

static DecompilerTestContext *decompiler_ctx;
static CoreDecompilerTestContext *core_decompiler_ctx;




static bool switch_ownership_probe(RAnalFunction *fcn, RAnalBlock *block,
		RAnalSwitchOp *switch_op, void *user) {
	(void)fcn;
	SwitchOwnershipProbe *probe = user;
	probe->count++;
	probe->owner_addr = block->addr;
	probe->switch_addr = switch_op->jump_addr;
	return true;
}


static void snapshot_probe_fini(SnapshotProbe *probe) {
	free (probe->arch_id);
	free (probe->cpu_id);
	free (probe->calling_convention);
	free (probe->function_name);
	memset (probe, 0, sizeof (*probe));
}

static RCore *snapshot_core_new(size_t bytes) {
	RCore *core = r_core_new ();
	if (!core) {
		return NULL;
	}
	char *uri = r_str_newf ("malloc://%zu", bytes);
	RIODesc *desc = uri? r_io_open_at (core->io, uri, R_PERM_RWX, 0, 0): NULL;
	free (uri);
	if (!desc) {
		r_core_free (core);
		return NULL;
	}
	return core;
}

static RAnalFunction *snapshot_function_new(RCore *core, const char *name, ut64 addr, ut64 size) {
	RAnalFunction *fcn = r_anal_create_function (
		core->anal, name, addr, R_ANAL_FCN_TYPE_FCN, NULL);
	if (!fcn) {
		return NULL;
	}
	RAnalBlock *block = r_anal_create_block (core->anal, addr, size);
	if (!block) {
		return NULL;
	}
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	return fcn;
}

static int missing_score(RAnal *anal) {
	DecompilerTestContext *ctx = anal->user;
	ctx->missing_eligible_calls++;
	return 100;
}

static int negative_score(RAnal *anal) {
	DecompilerTestContext *ctx = anal->user;
	ctx->negative_eligible_calls++;
	return -1;
}

static int low_score(RAnal *anal) {
	(void)anal;
	return 1;
}

static int high_score(RAnal *anal) {
	(void)anal;
	return 10;
}

static RCodeMeta *low_decompile(RAnal *anal, RAnalFunction *fcn) {
	(void)anal;
	(void)fcn;
	decompiler_ctx->low_decompile_calls++;
	return NULL;
}

static RCodeMeta *selected_decompile(RAnal *anal, RAnalFunction *fcn) {
	(void)anal;
	(void)fcn;
	decompiler_ctx->selected_decompile_calls++;
	decompiler_ctx->returned = r_codemeta_new ("selected provider");
	return decompiler_ctx->returned;
}

static RCodeMeta *tied_decompile(RAnal *anal, RAnalFunction *fcn) {
	(void)anal;
	(void)fcn;
	decompiler_ctx->tied_decompile_calls++;
	return NULL;
}

static int core_decompiler_score(RAnal *anal) {
	(void)anal;
	core_decompiler_ctx->eligible_calls++;
	return core_decompiler_ctx->enabled? 10: -1;
}

static RCodeMeta *core_decompile(RAnal *anal, RAnalFunction *fcn) {
	(void)anal;
	core_decompiler_ctx->decompile_calls++;
	core_decompiler_ctx->view_ok = fcn != NULL;
	if (!fcn) {
		return NULL;
	}
	core_decompiler_ctx->last_function_addr = fcn->addr;
	free (core_decompiler_ctx->last_function_name);
	core_decompiler_ctx->last_function_name = strdup (r_str_get (fcn->name));
	if (!core_decompiler_ctx->last_function_name) {
		return NULL;
	}
	return core_decompiler_ctx->fail? NULL: r_codemeta_new (core_decompiler_ctx->last_function_name);
}

static RAnal *test_anal_new(DecompilerTestContext *ctx) {
	RAnal *anal = r_anal_new ();
	if (anal) {
		r_list_purge (anal->libstore->plugins);
		r_anal_set_user_ptr (anal, ctx);
		decompiler_ctx = ctx;
	}
	return anal;
}

static bool test_decompiler_provider_filters_plugins(void) {
	DecompilerTestContext ctx = { 0 };
	RAnal *anal = test_anal_new (&ctx);
	mu_assert_notnull (anal, "create analysis context");
	RAnalPlugin missing_callback = {
		.eligible = missing_score,
	};
	RAnalPlugin ineligible = {
		.eligible = negative_score,
		.decompile = tied_decompile,
	};
	mu_assert_true (r_anal_plugin_add (anal, &missing_callback), "add plugin without callback");
	mu_assert_true (r_anal_plugin_add (anal, &ineligible), "add ineligible decompiler");
	mu_assert_null (r_anal_decompiler_provider (anal), "no eligible decompiler provider");
	mu_assert_eq (ctx.missing_eligible_calls, 0, "ignore eligibility for missing callback");
	mu_assert_eq (ctx.negative_eligible_calls, 1, "check negative eligibility");
	r_anal_free (anal);
	mu_end;
}

static bool test_decompiler_provider_priority_is_stable(void) {
	DecompilerTestContext ctx = { 0 };
	RAnal *anal = test_anal_new (&ctx);
	mu_assert_notnull (anal, "create analysis context");
	RAnalPlugin low = {
		.eligible = low_score,
		.decompile = low_decompile,
	};
	RAnalPlugin first_high = {
		.eligible = high_score,
		.decompile = selected_decompile,
	};
	RAnalPlugin second_high = {
		.eligible = high_score,
		.decompile = tied_decompile,
	};
	mu_assert_true (r_anal_plugin_add (anal, &low), "add lower-scored decompiler");
	mu_assert_true (r_anal_plugin_add (anal, &first_high), "add first high-scored decompiler");
	mu_assert_true (r_anal_plugin_add (anal, &second_high), "add tied high-scored decompiler");
	mu_assert_ptreq (r_anal_decompiler_provider (anal), &first_high,
		"first registered provider wins highest-score tie");
	r_anal_free (anal);
	mu_end;
}

static bool test_decompile_invokes_provider_once_and_returns_owned_result(void) {
	DecompilerTestContext ctx = { 0 };
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	RAnal *anal = core->anal;
	r_list_purge (anal->libstore->plugins);
	decompiler_ctx = &ctx;
	RAnalPlugin low = {
		.eligible = low_score,
		.decompile = low_decompile,
	};
	RAnalPlugin selected = {
		.eligible = high_score,
		.decompile = selected_decompile,
	};
	RAnalPlugin tied = {
		.eligible = high_score,
		.decompile = tied_decompile,
	};
	mu_assert_true (r_anal_plugin_add (anal, &low), "add lower-scored decompiler");
	mu_assert_true (r_anal_plugin_add (anal, &selected), "add selected decompiler");
	mu_assert_true (r_anal_plugin_add (anal, &tied), "add tied decompiler");
	mu_assert_notnull (r_io_open_at (core->io, "malloc://1", R_PERM_R, 0, 0x1000),
		"open immutable test bytes");
	RAnalFunction *fcn = r_anal_create_function (
		anal, "selected", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create function");
	RAnalBlock *block = r_anal_create_block (anal, 0x1000, 1);
	mu_assert_notnull (block, "create function block");
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	RCodeMeta *result = r_anal_decompile (anal, fcn);
	mu_assert_notnull (result, "decompiler result");
	mu_assert_ptreq (result, ctx.returned, "return caller-owned callback allocation unchanged");
	mu_assert_streq (result->code, "selected provider", "decompiler result contents");
	mu_assert_eq (ctx.selected_decompile_calls, 1, "selected callback called once");
	mu_assert_eq (ctx.low_decompile_calls, 0, "lower-scored callback not called");
	mu_assert_eq (ctx.tied_decompile_calls, 0, "later tied callback not called");
	r_codemeta_free (result);
	ctx.returned = NULL;
	decompiler_ctx = NULL;
	r_core_free (core);
	mu_end;
}

static bool test_core_pdd_routes_analysis_decompiler(void) {
	CoreDecompilerTestContext ctx = {
		.enabled = true,
	};
	core_decompiler_ctx = &ctx;
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");
	r_list_purge (core->anal->libstore->plugins);
	r_config_set_i (core->config, "scr.color", 0);
	RAnalPlugin provider = {
		.eligible = core_decompiler_score,
		.decompile = core_decompile,
	};
	mu_assert_true (r_anal_plugin_add (core->anal, &provider), "add core decompiler provider");
	RAnalFunction *current = r_anal_create_function (core->anal, "current", 0x1000,
		R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *named = r_anal_create_function (core->anal, "named", 0x2000,
		R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *addressed = r_anal_create_function (core->anal, "addressed", 0x3000,
		R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (current, "create current function");
	mu_assert_notnull (named, "create named function");
	mu_assert_notnull (addressed, "create addressed function");
	mu_assert_notnull (r_io_open_at (core->io, "malloc://12289", R_PERM_R, 0, 0x1000),
		"open immutable function bytes");
	RAnalBlock *current_block = r_anal_create_block (core->anal, 0x1000, 1);
	RAnalBlock *named_block = r_anal_create_block (core->anal, 0x2000, 1);
	RAnalBlock *addressed_block = r_anal_create_block (core->anal, 0x3000, 1);
	mu_assert_notnull (current_block, "create current function block");
	mu_assert_notnull (named_block, "create named function block");
	mu_assert_notnull (addressed_block, "create addressed function block");
	r_anal_function_add_block (current, current_block);
	r_anal_function_add_block (named, named_block);
	r_anal_function_add_block (addressed, addressed_block);
	r_unref (current_block);
	r_unref (named_block);
	r_unref (addressed_block);

	char *out = r_core_cmd_str (core, "pdd?");
	mu_assert_notnull (out, "capture pdd help");
	mu_assert_eq (ctx.eligible_calls, 0, "pdd help does not query provider");
	mu_assert_eq (ctx.decompile_calls, 0, "pdd help does not invoke provider");
	mu_assert_eq (core->rc, 0, "pdd help succeeds");
	free (out);

	core->addr = current->addr;
	out = r_core_cmd_str (core, "pdd");
	mu_assert_streq (out, "current\n", "pdd resolves current function");
	mu_assert_eq (ctx.decompile_calls, 1, "current function invokes provider once");
	mu_assert_true (ctx.view_ok, "provider opens borrowed snapshot view");
	mu_assert_eq (ctx.last_function_addr, current->addr, "current snapshot address");
	mu_assert_streq (ctx.last_function_name, "current", "current snapshot name");
	mu_assert_eq (core->rc, 0, "current function decompilation succeeds");
	free (out);

	out = r_core_cmd_str (core, "pdd named");
	mu_assert_streq (out, "named\n", "pdd resolves function name");
	mu_assert_eq (ctx.decompile_calls, 2, "named function invokes provider once");
	mu_assert_eq (ctx.last_function_addr, named->addr, "named snapshot address");
	mu_assert_streq (ctx.last_function_name, "named", "named snapshot name");
	mu_assert_eq (core->rc, 0, "named function decompilation succeeds");
	free (out);

	out = r_core_cmd_str (core, "pdd 0x3000");
	mu_assert_streq (out, "addressed\n", "pdd resolves function address");
	mu_assert_eq (ctx.decompile_calls, 3, "addressed function invokes provider once");
	mu_assert_eq (ctx.last_function_addr, addressed->addr, "addressed snapshot address");
	mu_assert_streq (ctx.last_function_name, "addressed", "addressed snapshot name");
	mu_assert_eq (core->rc, 0, "addressed function decompilation succeeds");
	free (out);

	int function_count = r_list_length (core->anal->fcns);
	out = r_core_cmd_str (core, "pdd 0x4000");
	mu_assert_notnull (out, "capture missing-function output");
	mu_assert_eq (ctx.decompile_calls, 3,
		"missing function does not invoke the provider");
	mu_assert_eq (r_list_length (core->anal->fcns), function_count,
		"decompile lookup does not start function analysis");
	mu_assert_eq (core->rc, 1, "missing function returns one");
	free (out);

	ctx.fail = true;
	out = r_core_cmd_str (core, "pdd named");
	mu_assert_notnull (out, "capture failed provider output");
	mu_assert_eq (ctx.decompile_calls, 4, "failed provider invoked once");
	mu_assert_eq (core->rc, 1, "provider failure returns one");
	free (out);

	ctx.enabled = false;
	ctx.fail = false;
	int decompile_calls = ctx.decompile_calls;
	mu_assert_true (sdb_set (core->sdb, "fallbackcmd.pdd", "?e pdd-fallback", 0),
		"set pdd fallback command");
	out = r_core_cmd_str (core, "pdd named");
	mu_assert_streq (out, "pdd-fallback\n", "missing provider uses pdd fallback");
	mu_assert_eq (ctx.decompile_calls, decompile_calls, "fallback does not invoke provider");
	mu_assert_eq (core->rc, 1, "missing provider preserves fallback failure status");
	free (out);

	core_decompiler_ctx = NULL;
	free (ctx.last_function_name);
	r_core_free (core);
	mu_end;
}




static int all_tests(void) {
	mu_run_test (test_decompiler_provider_filters_plugins);
	mu_run_test (test_decompiler_provider_priority_is_stable);
	mu_run_test (test_decompile_invokes_provider_once_and_returns_owned_result);
	mu_run_test (test_core_pdd_routes_analysis_decompiler);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
