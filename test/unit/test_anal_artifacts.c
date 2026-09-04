#include <r_core.h>
#include <r_anal_priv.h>
#include "minunit.h"

static RCore *artifact_test_core_new(void) {
	RCore *core = r_core_new ();
	if (!core) {
		return NULL;
	}
	if (!r_io_open_at (core->io, "malloc://65536", R_PERM_R | R_PERM_W, 0, 0)) {
		r_core_free (core);
		return NULL;
	}
	return core;
}

static bool artifact_test_prepare_function(RCore *core, RAnalFunction *function,
		ut64 *revision) {
	RAnalBlock *block = r_anal_create_block (core->anal, function->addr, 16);
	if (!block) {
		return false;
	}
	r_anal_function_add_block (function, block);
	r_unref (block);
	return r_core_function_context_hash (core, function->addr, revision, NULL);
}

static bool refs_have(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	if (!refs) {
		return false;
	}
	bool found = false;
	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		if (ref->at == from && ref->addr == to) {
			found = true;
			break;
		}
	}
	RVecAnalRef_free (refs);
	return found;
}

static bool refs_have_type(RAnal *anal, ut64 from, ut64 to, RAnalRefType type) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	if (!refs) {
		return false;
	}
	bool found = false;
	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		if (ref->at == from && ref->addr == to && ref->type == type) {
			found = true;
			break;
		}
	}
	RVecAnalRef_free (refs);
	return found;
}

typedef struct {
	const RAnalRef *refs;
	size_t ref_count;
	bool success;
	bool mutate_function;
	int calls;
} ArtifactDataRefsProducer;

typedef struct {
	ArtifactDataRefsProducer producer_a;
	ArtifactDataRefsProducer producer_b;
} ArtifactDataRefsContext;

static bool artifact_data_refs_emit(RAnalFunction *function, RVecAnalRef **out,
		ArtifactDataRefsProducer *producer) {
	*out = NULL;
	producer->calls++;
	if (producer->mutate_function) {
		r_anal_function_bump_dirty_epoch (function);
	}
	if (!producer->ref_count) {
		return producer->success;
	}
	RVecAnalRef *refs = RVecAnalRef_new ();
	if (!refs || !RVecAnalRef_reserve (refs, producer->ref_count)) {
		RVecAnalRef_free (refs);
		return false;
	}
	size_t i;
	for (i = 0; i < producer->ref_count; i++) {
		RVecAnalRef_push_back (refs, &producer->refs[i]);
	}
	*out = refs;
	return producer->success;
}

static bool artifact_data_refs_a(RAnal *anal, RAnalFunction *function, RVecAnalRef **out) {
	ArtifactDataRefsContext *ctx = anal->user;
	return artifact_data_refs_emit (function, out, &ctx->producer_a);
}

static bool artifact_data_refs_b(RAnal *anal, RAnalFunction *function, RVecAnalRef **out) {
	ArtifactDataRefsContext *ctx = anal->user;
	return artifact_data_refs_emit (function, out, &ctx->producer_b);
}

bool test_plugin_data_refs_preserve_producer_ownership(void) {
	RCore *core = artifact_test_core_new ();
	mu_assert_notnull (core, "create plugin data-ref core");
	r_list_purge (core->anal->libstore->plugins);
	RAnalFunction *function = r_anal_create_function (
		core->anal, "plugin_data_refs", 0xb000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create plugin data-ref function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (core, function, &revision),
		"prepare plugin data-ref function");

	const RAnalRef refs_a[] = {
		{ .at = 0xb004, .addr = 0xc000, .type = R_ANAL_REF_TYPE_DATA },
		{ .at = 0xb008, .addr = 0xc010, .type = R_ANAL_REF_TYPE_DATA },
	};
	const RAnalRef refs_b[] = {
		{ .at = 0xb004, .addr = 0xc000, .type = R_ANAL_REF_TYPE_DATA },
		{ .at = 0xb00c, .addr = 0xc020, .type = R_ANAL_REF_TYPE_DATA },
	};
	const RAnalRef stale_a[] = {
		{ .at = 0xb010, .addr = 0xc030, .type = R_ANAL_REF_TYPE_DATA },
	};
	const RAnalRef stale_b[] = {
		{ .at = 0xb014, .addr = 0xc040, .type = R_ANAL_REF_TYPE_DATA },
	};
	ArtifactDataRefsContext ctx = {
		.producer_a = {
			.refs = refs_a,
			.ref_count = R_ARRAY_SIZE (refs_a),
			.success = true,
		},
		.producer_b = {
			.refs = refs_b,
			.ref_count = R_ARRAY_SIZE (refs_b),
			.success = true,
		},
	};
	r_anal_set_user_ptr (core->anal, &ctx);
	RAnalPlugin plugin_a = {
		.meta = { .name = "test_datarefs_a" },
		.get_data_refs = artifact_data_refs_a,
	};
	RAnalPlugin plugin_b = {
		.meta = { .name = "test_datarefs_b" },
		.get_data_refs = artifact_data_refs_b,
	};
	mu_assert_true (r_anal_plugin_add (core->anal, &plugin_a), "register producer A");
	mu_assert_true (r_anal_plugin_add (core->anal, &plugin_b), "register producer B");
	mu_assert_true (r_anal_xrefs_set (
		core->anal, refs_b[1].at, refs_b[1].addr, refs_b[1].type),
		"seed unowned overlap with producer B");

	ut64 epoch = r_anal_function_dirty_epoch (function);
	r_core_anal_plugin_data_refs (core);
	mu_assert_eq (r_anal_function_dirty_epoch (function), epoch + 1,
		"authoritative multi-provider commit bumps function epoch once");
	mu_assert_true (refs_have (core->anal, refs_a[0].at, refs_a[0].addr),
		"producer overlap is visible");
	mu_assert_true (refs_have (core->anal, refs_a[1].at, refs_a[1].addr),
		"producer A edge is visible");
	mu_assert_true (refs_have (core->anal, refs_b[1].at, refs_b[1].addr),
		"producer B edge is visible");

	epoch = r_anal_function_dirty_epoch (function);
	r_core_anal_plugin_data_refs (core);
	mu_assert_eq (r_anal_function_dirty_epoch (function), epoch,
		"identical multi-provider rerun is idempotent");

	ctx.producer_a.refs = NULL;
	ctx.producer_a.ref_count = 0;
	ctx.producer_b.success = false;
	r_core_anal_plugin_data_refs (core);
	mu_assert_false (refs_have (core->anal, refs_a[1].at, refs_a[1].addr),
		"authoritative empty removes producer A edge");
	mu_assert_true (refs_have (core->anal, refs_a[0].at, refs_a[0].addr),
		"producer B refusal preserves shared edge");
	mu_assert_true (refs_have (core->anal, refs_b[1].at, refs_b[1].addr),
		"producer B refusal preserves its edge");

	ctx.producer_b.success = true;
	ctx.producer_b.refs = NULL;
	ctx.producer_b.ref_count = 0;
	r_core_anal_plugin_data_refs (core);
	mu_assert_false (refs_have (core->anal, refs_a[0].at, refs_a[0].addr),
		"last authoritative owner removes shared edge");
	mu_assert_true (refs_have (core->anal, refs_b[1].at, refs_b[1].addr),
		"identical unowned edge survives producer B clear");

	ctx.producer_a.refs = refs_a;
	ctx.producer_a.ref_count = R_ARRAY_SIZE (refs_a);
	ctx.producer_b.refs = refs_b;
	ctx.producer_b.ref_count = R_ARRAY_SIZE (refs_b);
	r_core_anal_plugin_data_refs (core);
	mu_assert_true (refs_have (core->anal, refs_a[1].at, refs_a[1].addr),
		"restore producer A owner state");
	mu_assert_true (refs_have (core->anal, refs_a[0].at, refs_a[0].addr),
		"restore shared owner state");
	const int calls_a_before_exclusion = ctx.producer_a.calls;
	const int calls_b_before_exclusion = ctx.producer_b.calls;
	mu_assert_notnull (r_config_set (core->config, "anal.plugins.datarefs", "test_datarefs_b"),
		"select only producer B");
	r_core_anal_plugin_data_refs (core);
	mu_assert_eq (ctx.producer_a.calls, calls_a_before_exclusion,
		"excluded producer A is not called");
	mu_assert_eq (ctx.producer_b.calls, calls_b_before_exclusion + 1,
		"selected producer B is called");
	mu_assert_false (refs_have (core->anal, refs_a[1].at, refs_a[1].addr),
		"excluding producer A retires its old set");
	mu_assert_true (refs_have (core->anal, refs_a[0].at, refs_a[0].addr),
		"selected producer B preserves shared edge");
	mu_assert_true (refs_have (core->anal, refs_b[1].at, refs_b[1].addr),
		"producer exclusion preserves identical unowned edge");

	mu_assert_notnull (r_config_set (core->config, "anal.plugins.datarefs",
		"test_datarefs_a,test_datarefs_b"), "reselect both producers");
	r_core_anal_plugin_data_refs (core);
	mu_assert_true (refs_have (core->anal, refs_a[1].at, refs_a[1].addr),
		"reselected producer A restores its owner state");
	mu_assert_true (r_anal_xref_del (core->anal, refs_b[1].at, refs_b[1].addr),
		"remove unowned overlap after survival check");
	mu_assert_true (refs_have (core->anal, refs_b[1].at, refs_b[1].addr),
		"producer B owner remains after removing unowned contributor");

	ctx.producer_a.refs = stale_a;
	ctx.producer_a.ref_count = R_ARRAY_SIZE (stale_a);
	ctx.producer_b.refs = stale_b;
	ctx.producer_b.ref_count = R_ARRAY_SIZE (stale_b);
	ctx.producer_b.mutate_function = true;
	r_core_anal_plugin_data_refs (core);
	mu_assert_true (refs_have (core->anal, refs_a[1].at, refs_a[1].addr),
		"stale callback batch preserves producer A state");
	mu_assert_true (refs_have (core->anal, refs_a[0].at, refs_a[0].addr),
		"stale callback batch preserves producer B overlap");
	mu_assert_true (refs_have (core->anal, refs_b[1].at, refs_b[1].addr),
		"stale callback batch preserves producer B owner state");
	mu_assert_false (refs_have (core->anal, stale_a[0].at, stale_a[0].addr),
		"stale callback batch does not publish producer A output");
	mu_assert_false (refs_have (core->anal, stale_b[0].at, stale_b[0].addr),
		"stale callback batch does not publish producer B output");
	mu_assert_eq (ctx.producer_a.calls, 7, "producer A called for every selected collection");
	mu_assert_eq (ctx.producer_b.calls, 8, "producer B called for every selected collection");
	r_anal_set_user_ptr (core->anal, NULL);
	r_core_free (core);
	mu_end;
}

bool test_owned_artifacts_replace_all_stores_atomically(void) {
	RCore *core = artifact_test_core_new ();
	mu_assert_notnull (core, "create core");
	RAnalFunction *function = r_anal_create_function (
		core->anal, "artifact_owner", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (core, function, &revision),
		"capture source revision");
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x1004,
		"user: keep"), "seed foreign comment");
	mu_assert_notnull (r_spaces_set (&core->anal->meta_spaces, "alternate"),
		"select alternate comment space");
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x1004,
		"alternate: untouched"), "seed alternate-space comment");
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x1006,
		"alternate: only"), "seed alternate-only comment");
	mu_assert_true (r_anal_xrefs_set (core->anal, 0x1008, 0x2000, R_ANAL_REF_TYPE_DATA),
		"seed unowned xref");
	RFlagItem *unrelated_flag = r_flag_set (core->flags, "foreign.unrelated", 0x4000, 4);
	mu_assert_notnull (unrelated_flag, "seed unrelated flag");

	RCoreAnalArtifactComment comments[] = {
		{
			.addr = 0x1004,
			.prefix = "sla:",
			.text = "sla: semantic one",
		},
		{
			.addr = 0x1006,
			.prefix = "sla:",
			.text = "sla: default-space projection",
		},
	};
	RCoreAnalArtifactFlag flags[] = {{
		.name = "sla.taint.1000",
		.addr = 0x1000,
		.size = 1,
	}};
	RAnalRef refs_a[] = {
		{ .at = 0x1008, .addr = 0x2000, .type = R_ANAL_REF_TYPE_DATA },
		{ .at = 0x100c, .addr = 0x2010, .type = R_ANAL_REF_TYPE_DATA },
	};
	RAnalRef refs_b[] = {{
		.at = 0x100c,
		.addr = 0x2010,
		.type = R_ANAL_REF_TYPE_DATA,
	}};
	ut64 initial_epoch = r_anal_function_dirty_epoch (function);
	RCoreAnalArtifactReplacement replacements[] = {
		{
			.provider_id = "sla",
			.domain_id = "semantic",
			.scope_id = function->addr,
			.expected_function_epoch = initial_epoch,
			.expected_type_epoch = core->anal->type_dirty_epoch,
			.expected_snapshot_revision = revision,
			.comments = comments,
			.comment_count = R_ARRAY_SIZE (comments),
			.flags = flags,
			.flag_count = R_ARRAY_SIZE (flags),
			.xrefs = refs_a,
			.xref_count = R_ARRAY_SIZE (refs_a),
		},
		{
			.provider_id = "other",
			.domain_id = "dataref",
			.scope_id = function->addr,
			.expected_function_epoch = initial_epoch,
			.expected_type_epoch = core->anal->type_dirty_epoch,
			.expected_snapshot_revision = revision,
			.xrefs = refs_b,
			.xref_count = R_ARRAY_SIZE (refs_b),
		},
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (
		core, replacements, R_ARRAY_SIZE (replacements));
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK, "replace succeeds");
	mu_assert_eq (result.replaced, 2, "both owner sets replaced");
	mu_assert_eq (result.revision, 1, "one artifact revision published");
	mu_assert_eq (r_anal_function_dirty_epoch (function), initial_epoch + 1,
		"function epoch published once");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x1004),
		"alternate: untouched", "alternate comment space remains untouched");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x1006),
		"alternate: only", "alternate-only comment remains untouched");
	r_spaces_set (&core->anal->meta_spaces, NULL);
	mu_assert_streq (r_meta_get_string_in_space (core->anal, R_META_TYPE_COMMENT, NULL, 0x1004),
		"user: keep\nsla: semantic one", "foreign comment line preserved");
	mu_assert_streq (r_meta_get_string_in_space (core->anal, R_META_TYPE_COMMENT, NULL, 0x1006),
		"sla: default-space projection", "default-space projection is independent");
	RFlagItem *flag = r_flag_get (core->flags, "sla.taint.1000");
	mu_assert_notnull (flag, "owned flag exists");
	mu_assert_eq (flag->addr, 0x1000, "owned flag address");
	mu_assert_ptreq (r_flag_get (core->flags, "foreign.unrelated"), unrelated_flag,
		"transaction preserves unrelated flag identity");
	mu_assert_true (refs_have (core->anal, 0x1008, 0x2000), "unowned overlap visible");
	mu_assert_true (refs_have (core->anal, 0x100c, 0x2010), "shared owned xref visible");
	RCoreAnalArtifactFlag updated_flag = {
		.name = "sla.taint.1000",
		.addr = 0x1002,
		.size = 2,
	};
	revision = 0;
	mu_assert_true (r_core_function_context_hash (core, function->addr, &revision, NULL),
		"recapture before flag update");
	RCoreAnalArtifactReplacement update = replacements[0];
	update.expected_function_epoch = r_anal_function_dirty_epoch (function);
	update.expected_type_epoch = core->anal->type_dirty_epoch;
	update.expected_snapshot_revision = revision;
	update.flags = &updated_flag;
	update.flag_count = 1;
	result = r_core_anal_artifacts_replace (core, &update, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK, "owned flag update succeeds");
	mu_assert_ptreq (r_flag_get (core->flags, "sla.taint.1000"), flag,
		"owned flag update preserves public item identity");
	mu_assert_eq (flag->addr, 0x1002, "owned flag address updated in place");
	mu_assert_eq (flag->size, 2, "owned flag size updated in place");

	RCoreAnalArtifactReplacement clear_a = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = core->anal->type_dirty_epoch,
	};
	revision = 0;
	mu_assert_true (r_core_function_context_hash (core, function->addr, &revision, NULL),
		"recapture after replace");
	clear_a.expected_snapshot_revision = revision;
	result = r_core_anal_artifacts_replace (core, &clear_a, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK, "owner clear succeeds");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x1004),
		"user: keep", "owner clear preserves foreign comment");
	mu_assert_null (r_flag_get (core->flags, "sla.taint.1000"), "owner flag cleared");
	mu_assert_true (refs_have (core->anal, 0x1008, 0x2000), "unowned xref survives owner clear");
	mu_assert_true (refs_have (core->anal, 0x100c, 0x2010), "other owner xref survives");

	RCoreAnalArtifactReplacement clear_b = {
		.provider_id = "other",
		.domain_id = "dataref",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = core->anal->type_dirty_epoch,
	};
	revision = 0;
	mu_assert_true (r_core_function_context_hash (core, function->addr, &revision, NULL),
		"recapture before second clear");
	clear_b.expected_snapshot_revision = revision;
	result = r_core_anal_artifacts_replace (core, &clear_b, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK, "second owner clear succeeds");
	mu_assert_false (refs_have (core->anal, 0x100c, 0x2010), "last owner removes xref");
	r_core_free (core);
	mu_end;
}

bool test_owned_artifacts_accept_function_at_address_zero(void) {
	RCore *core = artifact_test_core_new ();
	mu_assert_notnull (core, "create core");
	RAnalFunction *function = r_anal_create_function (
		core->anal, "artifact_zero", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create address-zero function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (core, function, &revision),
		"capture address-zero source revision");
	RCoreAnalArtifactComment comment = {
		.addr = 4,
		.prefix = "sla:",
		.text = "sla: address zero",
	};
	RCoreAnalArtifactReplacement replacement = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = 0,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = core->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
		.comments = &comment,
		.comment_count = 1,
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"address-zero owner scope is valid");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 4),
		"sla: address zero", "address-zero projection published");
	r_core_free (core);
	mu_end;
}

bool test_function_delete_retires_owned_artifacts(void) {
	RCore *core = artifact_test_core_new ();
	mu_assert_notnull (core, "create core");
	RAnalFunction *function = r_anal_create_function (
		core->anal, "artifact_delete", 0xb000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (core, function, &revision),
		"capture delete source revision");
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0xb004,
		"user: keep"), "seed foreign comment");
	mu_assert_true (r_anal_xrefs_set (
		core->anal, 0xb008, 0xc000, R_ANAL_REF_TYPE_DATA),
		"seed overlapping unowned xref");
	RCoreAnalArtifactComment comment = {
		.addr = 0xb004,
		.prefix = "sla:",
		.text = "sla: delete with function",
	};
	RCoreAnalArtifactFlag flag = {
		.name = "sla.delete.b000",
		.addr = 0xb000,
		.size = 1,
	};
	RAnalRef refs[] = {
		{ .at = 0xb008, .addr = 0xc000, .type = R_ANAL_REF_TYPE_DATA },
		{ .at = 0xb00c, .addr = 0xc010, .type = R_ANAL_REF_TYPE_DATA },
	};
	RCoreAnalArtifactReplacement replacement = {
		.provider_id = "sla",
		.domain_id = "delete",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = r_anal_types_dirty_epoch (core->anal),
		.expected_snapshot_revision = revision,
		.comments = &comment,
		.comment_count = 1,
		.flags = &flag,
		.flag_count = 1,
		.xrefs = refs,
		.xref_count = R_ARRAY_SIZE (refs),
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (
		core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"publish owned delete fixture");
	mu_assert_true (r_anal_function_delete (core->anal, function),
		"function deletion retires owner scope");
	mu_assert_null (r_anal_get_function_at (core->anal, 0xb000),
		"function removed");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0xb004),
		"user: keep", "foreign comment survives function deletion");
	mu_assert_null (r_flag_get (core->flags, "sla.delete.b000"),
		"owned flag removed with function");
	mu_assert_true (refs_have (core->anal, 0xb008, 0xc000),
		"overlapping unowned xref survives function deletion");
	mu_assert_false (refs_have (core->anal, 0xb00c, 0xc010),
		"owner-only xref removed with function");
	r_core_free (core);
	mu_end;
}

bool test_owned_artifacts_project_round_trip_preserves_ownership(void) {
	char *project_path = r_file_temp ("r2-artifact-owner");
	mu_assert_notnull (project_path, "create project path");
	RCore *source = artifact_test_core_new ();
	mu_assert_notnull (source, "create source core");
	RAnalFunction *function = r_anal_create_function (
		source->anal, "artifact_project", 0x5000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create project function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (source, function, &revision),
		"capture project source revision");
	RCoreAnalArtifactComment comment = {
		.addr = 0x5004,
		.prefix = "sla:",
		.text = "sla: persisted owner",
	};
	RCoreAnalArtifactFlag flag = {
		.name = "sla.persisted.5000",
		.addr = 0x5000,
		.size = 1,
	};
	RAnalRef xrefs[] = {
		{
			.at = 0x5008,
			.addr = 0x6000,
			.type = R_ANAL_REF_TYPE_DATA,
		},
		{
			.at = 0x500c,
			.addr = 0x6010,
			.type = R_ANAL_REF_TYPE_DATA,
		},
	};
	mu_assert_true (r_anal_xrefs_set (source->anal, 0x5008, 0x6000, R_ANAL_REF_TYPE_DATA),
		"seed overlapping unowned xref");
	RCoreAnalArtifactReplacement replacement = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = source->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
		.comments = &comment,
		.comment_count = 1,
		.flags = &flag,
		.flag_count = 1,
		.xrefs = xrefs,
		.xref_count = R_ARRAY_SIZE (xrefs),
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (source, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"publish source artifact set");
	mu_assert_eq (r_core_cmdf (source, "prj save %s", project_path), 0,
		"save owner-aware project");
	r_core_free (source);

	RCore *loaded = artifact_test_core_new ();
	mu_assert_notnull (loaded, "create load core");
	mu_assert_eq (r_core_cmdf (loaded, "prj load %s", project_path), 0,
		"load owner-aware project");
	mu_assert_streq (r_meta_get_string (loaded->anal, R_META_TYPE_COMMENT, 0x5004),
		"sla: persisted owner", "owned comment restored");
	mu_assert_notnull (r_flag_get (loaded->flags, "sla.persisted.5000"),
		"owned flag restored");
	mu_assert_true (refs_have (loaded->anal, 0x5008, 0x6000), "owned xref restored");
	mu_assert_true (refs_have (loaded->anal, 0x500c, 0x6010), "owned-only xref restored");

	function = r_anal_get_function_at (loaded->anal, 0x5000);
	mu_assert_notnull (function, "project function restored");
	memset (&revision, 0, sizeof (revision));
	mu_assert_true (r_core_function_context_hash (loaded, function->addr, &revision, NULL), "capture restored source revision");
	RCoreAnalArtifactReplacement clear = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = loaded->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
	};
	result = r_core_anal_artifacts_replace (loaded, &clear, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"clear restored owner set");
	mu_assert_null (r_meta_get_string (loaded->anal, R_META_TYPE_COMMENT, 0x5004),
		"restored owned comment clears");
	mu_assert_null (r_flag_get (loaded->flags, "sla.persisted.5000"),
		"restored owned flag clears");
	mu_assert_true (refs_have (loaded->anal, 0x5008, 0x6000),
		"overlapping unowned contributor survives owner clear");
	mu_assert_false (refs_have (loaded->anal, 0x500c, 0x6010),
		"restored owned-only xref clears");
	r_core_free (loaded);
	r_file_rm (project_path);
	free (project_path);
	mu_end;
}

bool test_legacy_project_artifacts_remain_unowned(void) {
	char *project_path = r_file_temp ("r2-artifact-legacy");
	mu_assert_notnull (project_path, "create legacy project path");
	RCore *source = artifact_test_core_new ();
	mu_assert_notnull (source, "create legacy source core");
	RAnalFunction *function = r_anal_create_function (
		source->anal, "artifact_legacy", 0x7000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create legacy function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (source, function, &revision),
		"capture legacy source revision");
	mu_assert_true (r_meta_set_string (source->anal, R_META_TYPE_COMMENT, 0x7004,
		"sla: legacy unowned"), "seed legacy comment");
	mu_assert_true (r_anal_xrefs_set (source->anal, 0x7008, 0x8000, R_ANAL_REF_TYPE_DATA),
		"seed legacy xref");
	mu_assert_eq (r_core_cmdf (source, "prj save %s", project_path), 0,
		"save legacy-shaped project");
	r_core_free (source);
	size_t project_size = 0;
	ut8 *project_bytes = (ut8 *)r_file_slurp (project_path, &project_size);
	mu_assert_notnull (project_bytes, "read saved project");
	mu_assert_true (project_size >= 8, "project header present");
	r_write_le32 (project_bytes + 4, 5);
	mu_assert_true (r_file_dump (project_path, project_bytes, project_size, false),
		"mark project as legacy v5");
	free (project_bytes);

	RCore *loaded = artifact_test_core_new ();
	mu_assert_notnull (loaded, "create legacy load core");
	function = r_anal_create_function (
		loaded->anal, "stale_owner", 0x7000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create stale pre-open function");
	memset (&revision, 0, sizeof (revision));
	mu_assert_true (artifact_test_prepare_function (loaded, function, &revision),
		"capture stale pre-open revision");
	RCoreAnalArtifactComment stale_comment = {
		.addr = 0x7004,
		.prefix = "sla:",
		.text = "sla: stale prior session",
	};
	RAnalRef stale_xref = {
		.at = 0x7010,
		.addr = 0x8010,
		.type = R_ANAL_REF_TYPE_DATA,
	};
	RCoreAnalArtifactReplacement stale_owner = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = loaded->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
		.comments = &stale_comment,
		.comment_count = 1,
		.xrefs = &stale_xref,
		.xref_count = 1,
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (
		loaded, &stale_owner, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"seed stale prior-session ownership");
	r_config_set_b (loaded->config, "scr.interactive", false);
	mu_assert_eq (r_core_cmdf (loaded, "prj open %s", project_path), 0,
		"open legacy project from a clean ownership session");
	function = r_anal_get_function_at (loaded->anal, 0x7000);
	mu_assert_notnull (function, "legacy function restored");
	memset (&revision, 0, sizeof (revision));
	mu_assert_true (r_core_function_context_hash (loaded, function->addr, &revision, NULL), "capture legacy restored revision");
	RCoreAnalArtifactReplacement clear = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = loaded->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
	};
	result = r_core_anal_artifacts_replace (loaded, &clear, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"empty owner clear succeeds on legacy state");
	mu_assert_streq (r_meta_get_string (loaded->anal, R_META_TYPE_COMMENT, 0x7004),
		"sla: legacy unowned", "legacy comment is not adopted by prefix");
	mu_assert_true (refs_have (loaded->anal, 0x7008, 0x8000),
		"legacy xref is not adopted without provenance");
	mu_assert_false (refs_have (loaded->anal, 0x7010, 0x8010),
		"project open removes prior-session owned xrefs");
	r_core_free (loaded);
	r_file_rm (project_path);
	free (project_path);
	mu_end;
}

bool test_owned_artifacts_reject_stale_and_foreign_conflicts(void) {
	RCore *core = artifact_test_core_new ();
	mu_assert_notnull (core, "create core");
	RAnalFunction *function = r_anal_create_function (
		core->anal, "artifact_conflict", 0x3000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (core, function, &revision),
		"capture source revision");
	mu_assert_notnull (r_flag_set (core->flags, "foreign.flag", 0x3010, 4),
		"seed foreign flag");
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x3004,
		"user: unchanged"), "seed foreign comment");
	ut64 epoch = r_anal_function_dirty_epoch (function);
	RCoreAnalArtifactFlag flag = {
		.name = "foreign.flag",
		.addr = 0x3000,
		.size = 1,
	};
	RCoreAnalArtifactComment comment = {
		.addr = 0x3004,
		.prefix = "sla:",
		.text = "sla: must not publish",
	};
	RCoreAnalArtifactReplacement replacement = {
		.provider_id = "sla",
		.domain_id = "semantic",
		.scope_id = function->addr,
		.expected_function_epoch = epoch,
		.expected_type_epoch = core->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
		.comments = &comment,
		.comment_count = 1,
		.flags = &flag,
		.flag_count = 1,
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_CONFLICT,
		"foreign flag collision rejects whole replacement");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3004),
		"user: unchanged", "failed batch leaves comment unchanged");
	mu_assert_eq (r_flag_get (core->flags, "foreign.flag")->addr, 0x3010,
		"failed batch leaves flag unchanged");
	mu_assert_eq (r_anal_function_dirty_epoch (function), epoch,
		"failed batch leaves function epoch unchanged");

	replacement.flags = NULL;
	replacement.flag_count = 0;
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x3004,
		"sla: foreign note"), "seed prefix collision");
	result = r_core_anal_artifacts_replace (core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_CONFLICT,
		"first ownership claim cannot adopt a foreign prefix line");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3004),
		"sla: foreign note", "prefix collision leaves foreign line unchanged");
	mu_assert_true (r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x3004,
		"user: unchanged"), "restore foreign comment");
	replacement.expected_function_epoch = epoch + 1;
	result = r_core_anal_artifacts_replace (core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_STALE_SOURCE,
		"stale source epoch refuses");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3004),
		"user: unchanged", "stale batch leaves comment unchanged");
	r_core_free (core);
	mu_end;
}

bool test_owned_artifacts_reject_mismatched_xref_types(void) {
	RCore *core = artifact_test_core_new ();
	mu_assert_notnull (core, "create core");
	RAnalFunction *function = r_anal_create_function (
		core->anal, "artifact_xref_conflict", 0x9000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (function, "create function");
	ut64 revision = 0;
	mu_assert_true (artifact_test_prepare_function (core, function, &revision),
		"capture source revision");
	mu_assert_true (r_anal_xrefs_set (core->anal, 0x9004, 0xa000, R_ANAL_REF_TYPE_DATA),
		"seed unowned data xref");
	RAnalRef xrefs[] = {
		{
			.at = 0x9004,
			.addr = 0xa000,
			.type = R_ANAL_REF_TYPE_CALL,
		},
		{
			.at = 0x9008,
			.addr = 0xa010,
			.type = R_ANAL_REF_TYPE_DATA,
		},
	};
	RCoreAnalArtifactReplacement replacement = {
		.provider_id = "sla",
		.domain_id = "xref-conflict",
		.scope_id = function->addr,
		.expected_function_epoch = r_anal_function_dirty_epoch (function),
		.expected_type_epoch = core->anal->type_dirty_epoch,
		.expected_snapshot_revision = revision,
		.xrefs = xrefs,
		.xref_count = R_ARRAY_SIZE (xrefs),
	};
	RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_CONFLICT,
		"owned type cannot differ from unowned contributor");
	mu_assert_true (refs_have_type (core->anal, 0x9004, 0xa000,
		R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ), "failed owner claim preserves unowned type");

	xrefs[0].type = R_ANAL_REF_TYPE_DATA;
	result = r_core_anal_artifacts_replace (core, &replacement, 1);
	mu_assert_eq (result.status, R_CORE_ANAL_ARTIFACT_REPLACE_OK,
		"same-type owned and unowned contributors can overlap");
	mu_assert_false (r_anal_xrefs_set (
		core->anal, 0x9008, 0xa010, R_ANAL_REF_TYPE_CALL),
		"unowned insert cannot differ from owned contributor");
	mu_assert_true (refs_have_type (core->anal, 0x9008, 0xa010,
		R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ), "rejected insert preserves owned type");
	mu_assert_false (r_anal_xrefs_set (
		core->anal, 0x9004, 0xa000, R_ANAL_REF_TYPE_CALL),
		"unowned update cannot differ from owned contributor");
	mu_assert_true (refs_have_type (core->anal, 0x9004, 0xa000,
		R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ), "rejected update preserves shared type");
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_plugin_data_refs_preserve_producer_ownership);
	mu_run_test (test_owned_artifacts_replace_all_stores_atomically);
	mu_run_test (test_owned_artifacts_reject_stale_and_foreign_conflicts);
	mu_run_test (test_owned_artifacts_reject_mismatched_xref_types);
	mu_run_test (test_owned_artifacts_accept_function_at_address_zero);
	mu_run_test (test_function_delete_retires_owned_artifacts);
	mu_run_test (test_owned_artifacts_project_round_trip_preserves_ownership);
	mu_run_test (test_legacy_project_artifacts_remain_unowned);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
