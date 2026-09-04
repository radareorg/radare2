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
	RAnal *anal;
	RCodeMeta *result;
} InvokeDecompilerContext;

typedef struct {
	int calls;
	bool image_ok;
	bool advisory_edge_ok;
	bool owned_bounded_image;
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

static bool snapshot_probe(const RAnalFunctionSnapshot *snapshot, void *user) {
	SnapshotProbe *probe = user;
	probe->calls++;
	probe->function_addr = snapshot->function_addr;
	probe->revision_identity = snapshot->revision_identity;
	probe->bits = snapshot->bits;
	probe->endian = snapshot->endian;
	probe->owned_bounded_image = snapshot->capabilities
		& R_ANAL_FUNCTION_SNAPSHOT_CAP_OWNED_BOUNDED_FUNCTION_IMAGE;
	const RAnalFunctionImageSnapshot *image = &snapshot->image;
	const RAnalSnapshotBlock *block = image->num_blocks == 1? &image->blocks[0]: NULL;
	probe->image_ok = block && block->addr == snapshot->function_addr
		&& block->size == 1 && block->bytes;
	if (probe->image_ok) {
		probe->first_byte = block->bytes[0];
	}
	probe->advisory_edge_ok = probe->image_ok && block->num_successors == 1
		&& block->successors[0].kind == R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT
		&& block->successors[0].target_addr == 2 && block->successors[0].external
		&& image->num_external_exits == 1 && image->external_exits[0] == 2;
	free (probe->function_name);
	free (probe->arch_id);
	free (probe->cpu_id);
	free (probe->calling_convention);
	probe->function_name = strdup (r_str_get (snapshot->function_name));
	probe->arch_id = strdup (r_str_get (snapshot->arch_id));
	probe->cpu_id = strdup (r_str_get (snapshot->cpu_id));
	probe->calling_convention = strdup (
		r_str_get (snapshot->function_interface.calling_convention));
	return probe->image_ok;
}

static bool analyzed_snapshot_probe(const RAnalFunctionSnapshot *snapshot, void *user) {
	AnalyzedSnapshotProbe *probe = user;
	const RAnalFunctionImageSnapshot *image = &snapshot->image;
	probe->calls++;
	size_t i;
	for (i = 0; i < image->num_blocks; i++) {
		const RAnalSnapshotBlock *block = &image->blocks[i];
		if (block->addr == snapshot->function_addr && block->size > 0) {
			probe->copied_decoder_block = block->bytes != NULL;
			if (probe->copied_decoder_block) {
				probe->first_byte = block->bytes[0];
			}
			probe->decoder_topology_ok = image->num_blocks == 3
				&& image->num_external_exits == 0 && block->num_successors == 2
				&& block->successors[0].target_addr == snapshot->function_addr + 3
				&& block->successors[0].kind == R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT
				&& block->successors[1].target_addr == snapshot->function_addr + 2
				&& block->successors[1].kind == R_ANAL_SNAPSHOT_SUCCESSOR_FALLTHROUGH;
			return probe->copied_decoder_block && probe->decoder_topology_ok;
		}
	}
	return false;
}

static bool switch_ownership_probe(RAnalFunction *fcn, RAnalBlock *block,
		RAnalSwitchOp *switch_op, void *user) {
	(void)fcn;
	SwitchOwnershipProbe *probe = user;
	probe->count++;
	probe->owner_addr = block->addr;
	probe->switch_addr = switch_op->jump_addr;
	return true;
}

static bool snapshot_view_probe(const RAnalFunctionSnapshot *snapshot, void *user) {
	int *calls = user;
	(*calls)++;
	return snapshot->image.num_blocks > 0;
}

// Every probe below is now take, read, free: the snapshot belongs to the
// caller and nothing is held while it is read.
static bool core_snapshot_probe(RCore *core, ut64 addr,
		bool (*probe)(const RAnalFunctionSnapshot *, void *), void *user,
		const char **reason) {
	RAnalFunctionSnapshot *snapshot = r_core_function_snapshot_take (core, addr, reason);
	if (!snapshot) {
		return false;
	}
	const bool result = probe (snapshot, user);
	r_anal_function_snapshot_free (snapshot);
	return result;
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

static RCodeMeta *low_decompile(const RAnalFunctionSnapshot *snapshot) {
	(void)snapshot;
	decompiler_ctx->low_decompile_calls++;
	return NULL;
}

static RCodeMeta *selected_decompile(const RAnalFunctionSnapshot *snapshot) {
	(void)snapshot;
	decompiler_ctx->selected_decompile_calls++;
	decompiler_ctx->returned = r_codemeta_new ("selected provider");
	return decompiler_ctx->returned;
}

static RCodeMeta *tied_decompile(const RAnalFunctionSnapshot *snapshot) {
	(void)snapshot;
	decompiler_ctx->tied_decompile_calls++;
	return NULL;
}

static int core_decompiler_score(RAnal *anal) {
	(void)anal;
	core_decompiler_ctx->eligible_calls++;
	return core_decompiler_ctx->enabled? 10: -1;
}

static RCodeMeta *core_decompile(const RAnalFunctionSnapshot *snapshot) {
	core_decompiler_ctx->decompile_calls++;
	core_decompiler_ctx->view_ok = snapshot != NULL;
	if (!snapshot) {
		return NULL;
	}
	core_decompiler_ctx->last_function_addr = snapshot->function_addr;
	free (core_decompiler_ctx->last_function_name);
	core_decompiler_ctx->last_function_name = strdup (r_str_get (snapshot->function_name));
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
	InvokeDecompilerContext invoke = {
		.anal = anal,
	};
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_take (
		invoke.anal, fcn->addr, NULL);
	mu_assert_notnull (snapshot, "take snapshot for the provider");
	invoke.result = r_anal_decompile (invoke.anal, snapshot);
	r_anal_function_snapshot_free (snapshot);
	mu_assert_notnull (invoke.result, "invoke snapshot provider");
	RCodeMeta *result = invoke.result;
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
	mu_assert_true (ctx.view_ok, "provider reads the snapshot it was handed");
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

static bool test_core_snapshot_transaction_owns_lifetime_and_rejects_untrusted_io(void) {
	RCore *core = snapshot_core_new (2);
	mu_assert_notnull (core, "create snapshot core");
	RAnalFunction *fcn = snapshot_function_new (core, "owned", 0, 1);
	mu_assert_notnull (fcn, "create backed snapshot function");
	RArchConfig *active_config = core->anal->arch && core->anal->arch->session
		? core->anal->arch->session->config: core->anal->config;
	mu_assert_notnull (active_config, "get active analyzer config");
	r_arch_config_set_cpu (active_config, "snapshot-baseline");
	const ut8 nop = 0x90;
	mu_assert_eq (r_io_write_at (core->io, 0, &nop, 1), 1, "write real snapshot byte");
	RAnalBlock *source_block = r_list_first (fcn->bbs);
	mu_assert_notnull (source_block, "get source block");
	source_block->jump = 2;
	SnapshotProbe probe = {0};
	mu_assert_true (core_snapshot_probe (
		core, fcn->addr, snapshot_probe, &probe, NULL), "visit opaque snapshot");
	mu_assert_eq (probe.calls, 1, "callback runs exactly once");
	mu_assert_true (probe.owned_bounded_image, "snapshot owns bounded exact-read bytes");
	mu_assert_true (probe.image_ok, "snapshot owns the block bytes it captured");
	mu_assert_eq (probe.first_byte, nop, "probe observes the copied source byte");
	mu_assert_true (probe.advisory_edge_ok, "snapshot carries the advisory source edge");
	mu_assert_eq (probe.function_addr, fcn->addr, "snapshot preserves function address");
	mu_assert_streq (probe.cpu_id, "snapshot-baseline", "snapshot owns active CPU id");
	mu_assert_streq (probe.function_name, "owned", "callback deep-copies borrowed name");
	ut64 first_revision = probe.revision_identity;

	// The snapshot is the caller's: it survives the capture and keeps reading
	// the state it captured, whatever the analysis does next.
	RAnalFunctionSnapshot *held = r_core_function_snapshot_take (core, fcn->addr, NULL);
	mu_assert_notnull (held, "hold a snapshot past its capture");
	mu_assert_true (r_anal_function_rename (fcn, "renamed"), "rename live function");
	r_arch_config_set_cpu (active_config, "snapshot-mutated");
	mu_assert_streq (held->function_name, "owned", "held snapshot outlives the rename");
	mu_assert_streq (held->cpu_id, "snapshot-baseline",
		"held snapshot outlives the machine-tuple change");
	mu_assert_eq (held->image.blocks[0].bytes[0], nop, "held snapshot owns its bytes");
	r_anal_function_snapshot_free (held);
	mu_assert_streq (probe.function_name, "owned", "copied probe data outlives the snapshot");
	mu_assert_streq (probe.cpu_id, "snapshot-baseline", "copied machine tuple outlives the snapshot");
	mu_assert_true (core_snapshot_probe (
		core, fcn->addr, snapshot_probe, &probe, NULL), "visit renamed snapshot");
	mu_assert_eq (probe.calls, 2, "second transaction invokes callback once");
	mu_assert_streq (probe.function_name, "renamed", "next transaction sees live rename");
	mu_assert_streq (probe.cpu_id, "snapshot-mutated", "next transaction sees machine tuple mutation");
	mu_assert_neq (probe.revision_identity, first_revision,
		"machine tuple mutation changes diagnostic identity");

	RIOPlugin debug_plugin = *core->io->desc->plugin;
	RIOPlugin *saved_plugin = core->io->desc->plugin;
	debug_plugin.isdbg = true;
	core->io->desc->plugin = &debug_plugin;
	mu_assert_false (core_snapshot_probe (
		core, fcn->addr, snapshot_probe, &probe, NULL), "debug IO is rejected");
	mu_assert_eq (probe.calls, 2, "debug refusal does not invoke callback");
	core->io->desc->plugin = saved_plugin;
	snapshot_probe_fini (&probe);
	r_core_free (core);

	core = snapshot_core_new (1);
	mu_assert_notnull (core, "create short-read core");
	fcn = snapshot_function_new (core, "short", 0, 2);
	mu_assert_notnull (fcn, "create short-read function");
	probe = (SnapshotProbe) {0};
	mu_assert_false (core_snapshot_probe (
		core, fcn->addr, snapshot_probe, &probe, NULL), "short exact read is rejected");
	mu_assert_eq (probe.calls, 0, "short-read refusal does not invoke callback");
	r_core_free (core);

	core = snapshot_core_new (1);
	mu_assert_notnull (core, "create limit core");
	fcn = snapshot_function_new (core, "oversized", 0, 16 * 1024 * 1024 + 1);
	mu_assert_notnull (fcn, "create oversized function image");
	probe = (SnapshotProbe) {0};
	mu_assert_false (core_snapshot_probe (
		core, fcn->addr, snapshot_probe, &probe, NULL), "source-byte limit is rejected");
	mu_assert_eq (probe.calls, 0, "limit refusal does not invoke callback");
	r_core_free (core);
	mu_end;
}

static bool test_core_snapshot_transaction_captures_analyzed_real_bytes(void) {
	const ut64 addr = 0x1000;
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create analysis core");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://4",
		R_PERM_RWX, 0, addr), "open executable analysis map");
	const ut8 bytes[] = { 0x75, 0x01, 0xc3, 0xc3 };
	mu_assert_true (r_io_write_at (core->io, addr, bytes, sizeof (bytes)),
		"write decoded function bytes");
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 32);
	r_config_set_b (core->config, "anal.esil", false);
	mu_assert_true (r_core_anal_fcn (core, addr, UT64_MAX,
		R_ANAL_REF_TYPE_NULL, 1), "analyze function from real bytes");
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	mu_assert_notnull (fcn, "decoder analysis creates function");
	mu_assert_true (!r_list_empty (fcn->bbs), "decoder analysis creates CFG block");
	AnalyzedSnapshotProbe probe = {0};
	mu_assert_true (core_snapshot_probe (core, addr,
		analyzed_snapshot_probe, &probe, NULL), "capture analyzed function snapshot");
	mu_assert_eq (probe.calls, 1, "analyzed snapshot callback runs once");
	mu_assert_true (probe.copied_decoder_block,
		"analyzed snapshot copies decoder-created block bytes");
	mu_assert_true (probe.decoder_topology_ok,
		"analyzed snapshot exposes decoder-created branch and fallthrough topology");
	mu_assert_eq (probe.first_byte, bytes[0],
		"analyzed snapshot preserves first decoded byte");
	r_core_free (core);
	mu_end;
}

static bool test_overlapped_walk_keeps_one_switch_owner(void) {
	const ut64 addr = 0x1000;
	const char *hex =
		"554889e54883fe040f82990000004889f148c1e9024883f901750431c0eb644883e1fe31c066662e0f1f8400000000004469"
		"0407512d9ecc41c1c00f4569c09335871b4131d041c1c00d438d148081c2646b54e64469440704512d9ecc41c1c00f4569c0"
		"9335871b4131d041c1c00d438d148081c2646b54e64883c0084883c1fe75ad40f6c604741e690407512d9eccc1c00f69c093"
		"35871b31d0c1c00d8d148081c2646b54e64889f04883e0fc4189f04183e00331c94c8d0d5e0000004f6304814d01c841ffe0"
		"0fb64c0702c1e110440fb644070141c1e0084409c10fb6040731c869c0512d9eccc1c00f69c09335871b31c231d689f0c1e8"
		"1031f069c06bcaeb8589c1c1e90d31c169c935aeb2c289c8c1e81031c85dc30f1f00d8ffffffc1ffffffb4ffffffacffffff";
	size_t bytes_size = 0;
	ut8 *bytes = r_hex_str2bin_dup (hex, &bytes_size);
	mu_assert_notnull (bytes, "decode overlapping-switch fixture");
	mu_assert_eq (bytes_size, 300, "fixture contains function and jump table");
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create overlapping-switch analysis core");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://300",
		R_PERM_RWX, 0, addr), "open overlapping-switch analysis map");
	mu_assert_true (r_io_write_at (core->io, addr, bytes, bytes_size),
		"write overlapping-switch fixture");
	free (bytes);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	r_config_set_b (core->config, "anal.jmptbl", true);
	r_config_set_b (core->config, "anal.esil", false);
	(void)r_core_anal_fcn (core, addr, UT64_MAX,
		R_ANAL_REF_TYPE_NULL, 256);
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	mu_assert_notnull (fcn, "analysis creates overlapping-switch function");
	SwitchOwnershipProbe ownership = {0};
	mu_assert_true (r_anal_function_switches_foreach (
		fcn, switch_ownership_probe, &ownership), "enumerate switch owners");
	mu_assert_eq (ownership.count, 1, "one block owns the discovered switch");
	mu_assert_eq (ownership.owner_addr, addr + 167,
		"the indirect-jump block owns the discovered switch");
	mu_assert_eq (ownership.switch_addr, addr + 197,
		"switch ownership names the indirect jump");
	int snapshot_calls = 0;
	const char *reason = NULL;
	mu_assert_true (core_snapshot_probe (
		core, addr, snapshot_view_probe, &snapshot_calls, &reason),
		"capture coherent snapshot after overlapping analysis");
	mu_assert_null (reason, "coherent snapshot has no refusal reason");
	mu_assert_eq (snapshot_calls, 1, "coherent snapshot callback runs once");
	r_core_free (core);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_decompiler_provider_filters_plugins);
	mu_run_test (test_decompiler_provider_priority_is_stable);
	mu_run_test (test_decompile_invokes_provider_once_and_returns_owned_result);
	mu_run_test (test_core_pdd_routes_analysis_decompiler);
	mu_run_test (test_core_snapshot_transaction_owns_lifetime_and_rejects_untrusted_io);
	mu_run_test (test_core_snapshot_transaction_captures_analyzed_real_bytes);
	mu_run_test (test_overlapped_walk_keeps_one_switch_owner);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
