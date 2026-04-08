#include <r_debug.h>
#include <r_reg.h>
#include <r_util.h>
#include "minunit.h"

static Sdb *ref_db(void) {
	Sdb *db = sdb_new0 ();

	sdb_num_set (db, "maxcnum", 1, 0);
	sdb_num_set (db, "next_checkpoint_id", 2, 0);
	sdb_num_set (db, "current_checkpoint_id", 1, 0);
	sdb_bool_set (db, "linear_history_valid", true, 0);

	Sdb *registers_db = sdb_ns (db, "registers", true);
	sdb_set (registers_db, "0x100", "[{\"cnum\":0,\"data\":1094861636},{\"cnum\":1,\"data\":3735928559}]", 0);

	Sdb *memory_sdb = sdb_ns (db, "memory", true);
	sdb_set (memory_sdb, "0x7ffffffff000", "[{\"cnum\":0,\"data\":170},{\"cnum\":1,\"data\":187}]", 0);
	sdb_set (memory_sdb, "0x7ffffffff001", "[{\"cnum\":0,\"data\":0},{\"cnum\":1,\"data\":1}]", 0);

	Sdb *checkpoints_sdb = sdb_ns (db, "checkpoints", true);
	sdb_set (checkpoints_sdb, "0x1", "{"
		"\"id\":1,"
		"\"cnum\":0,"
		"\"resume_bp_addr\":4201677,"
		"\"parent\":null,"
		"\"label\":\"root\","
		"\"registers\":["
			"{\"arena\":0,\"bytes\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"size\":16},"
			"{\"arena\":1,\"bytes\":\"AQEBAQEBAQEBAQEBAQEBAQ==\",\"size\":16},"
			"{\"arena\":2,\"bytes\":\"AgICAgICAgICAgICAgICAg==\",\"size\":16},"
			"{\"arena\":3,\"bytes\":\"AwMDAwMDAwMDAwMDAwMDAw==\",\"size\":16},"
			"{\"arena\":4,\"bytes\":\"BAQEBAQEBAQEBAQEBAQEBA==\",\"size\":16},"
			"{\"arena\":5,\"bytes\":\"BQUFBQUFBQUFBQUFBQUFBQ==\",\"size\":16},"
			"{\"arena\":6,\"bytes\":\"BgYGBgYGBgYGBgYGBgYGBg==\",\"size\":16},"
			"{\"arena\":7,\"bytes\":\"BwcHBwcHBwcHBwcHBwcHBw==\",\"size\":16},"
			"{\"arena\":8,\"bytes\":\"CAgICAgICAgICAgICAgICA==\",\"size\":16},"
			"{\"arena\":9,\"bytes\":\"CQkJCQkJCQkJCQkJCQkJCQ==\",\"size\":16}"
		"],"
		"\"snaps\":["
			"{\"name\":\"[stack]\",\"addr\":8796092882944,\"addr_end\":8796092883200,\"size\":256,\"data\":\"8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8A==\",\"perm\":7,\"user\":0,\"shared\":true}"
		"]"
		"}", 0);

	return db;
}

static RDebugSession *ref_session(void) {
	RDebugSession *session = r_debug_session_new ();
	RDebugCheckpoint checkpoint = {0};
	RDebugSnap *snap;
	size_t i;
	if (!session) {
		return NULL;
	}

	r_debug_session_add_reg_change (session, 0, 0x100, 0x41424344);
	r_debug_session_add_mem_change (session, 0x7ffffffff000, 0xaa);
	r_debug_session_add_mem_change (session, 0x7ffffffff001, 0x00);
	session->maxcnum++;
	session->cnum++;
	r_debug_session_add_reg_change (session, 0, 0x100, 0xdeadbeef);
	r_debug_session_add_mem_change (session, 0x7ffffffff000, 0xbb);
	r_debug_session_add_mem_change (session, 0x7ffffffff001, 0x01);

	checkpoint.id = 1;
	checkpoint.parent_id = UT64_MAX;
	checkpoint.cnum = 0;
	checkpoint.label = strdup ("root");
	checkpoint.resume_bp_addr = 0x401ccd;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *arena = r_reg_arena_new (0x10);
		if (arena) {
			memset (arena->bytes, i, arena->size);
			checkpoint.arena[i] = arena;
		}
	}
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	snap = R_NEW0 (RDebugSnap);
	if (snap) {
		snap->name = strdup ("[stack]");
		snap->addr = 0x7fffffde000;
		snap->addr_end = 0x7fffffde100;
		snap->size = 0x100;
		snap->perm = 7;
		snap->user = 0;
		snap->shared = true;
		snap->data = malloc (snap->size);
		memset (snap->data, 0xf0, snap->size);
		r_list_append (checkpoint.snaps, snap);
	}
	RVecDebugCheckpoint_push_back (session->checkpoints, &checkpoint);
	ht_up_insert (session->checkpoint_index, checkpoint.id, (void *)1);
	session->current_checkpoint_id = checkpoint.id;
	session->next_checkpoint_id = 2;
	session->linear_history_valid = true;

	return session;
}

static void diff_cb(const SdbDiff *diff, void *user) {
	char buf[2048];
	if (sdb_diff_format (buf, sizeof (buf), diff) < 0) {
		return;
	}
	printf ("%s\n", buf);
}

static bool compare_registers_cb(void *user, const ut64 key, const void *value) {
	RDebugChangeReg *actual_reg;
	RDebugChangeReg *expected_reg;
	HtUP *ref = user;
	RVecDebugChangeReg *actual_vreg = (RVecDebugChangeReg *)value;
	RVecDebugChangeReg *expected_vreg = ht_up_find (ref, key, NULL);

	mu_assert ("vreg not found", expected_vreg);
	mu_assert_eq (RVecDebugChangeReg_length (actual_vreg), RVecDebugChangeReg_length (expected_vreg), "vreg length");

	ut64 i = 0;
	for (actual_reg = R_VEC_START_ITER (actual_vreg); actual_reg != R_VEC_END_ITER (actual_vreg); actual_reg++, i++) {
		expected_reg = RVecDebugChangeReg_at (expected_vreg, i);
		mu_assert_eq (actual_reg->cnum, expected_reg->cnum, "cnum");
		mu_assert_eq (actual_reg->data, expected_reg->data, "data");
	}
	return true;
}

static bool compare_memory_cb(void *user, const ut64 key, const void *value) {
	RDebugChangeMem *actual_mem;
	RDebugChangeMem *expected_mem;
	HtUP *ref = user;
	RVecDebugChangeMem *actual_vmem = (RVecDebugChangeMem *)value;
	RVecDebugChangeMem *expected_vmem = ht_up_find (ref, key, NULL);

	mu_assert ("vmem not found", expected_vmem);
	mu_assert_eq (RVecDebugChangeMem_length (actual_vmem), RVecDebugChangeMem_length (expected_vmem), "vmem length");

	ut64 i = 0;
	for (actual_mem = R_VEC_START_ITER (actual_vmem); actual_mem != R_VEC_END_ITER (actual_vmem); actual_mem++, i++) {
		expected_mem = RVecDebugChangeMem_at (expected_vmem, i);
		mu_assert_eq (actual_mem->cnum, expected_mem->cnum, "cnum");
		mu_assert_eq (actual_mem->data, expected_mem->data, "data");
	}
	return true;
}

static bool arena_eq(RRegArena *actual, RRegArena *expected) {
	mu_assert ("arena null", actual && expected);
	mu_assert_eq (actual->size, expected->size, "arena size");
	mu_assert_memeq (actual->bytes, expected->bytes, expected->size, "arena bytes");
	return true;
}

static bool snap_eq(RDebugSnap *actual, RDebugSnap *expected) {
	mu_assert ("snap null", actual && expected);
	mu_assert_streq (actual->name, expected->name, "snap name");
	mu_assert_eq (actual->addr, expected->addr, "snap addr");
	mu_assert_eq (actual->addr_end, expected->addr_end, "snap addr_end");
	mu_assert_eq (actual->size, expected->size, "snap size");
	mu_assert_eq (actual->perm, expected->perm, "snap perm");
	mu_assert_eq (actual->user, expected->user, "snap user");
	mu_assert_eq (actual->shared, expected->shared, "snap shared");
	mu_assert_memeq (actual->data, expected->data, expected->size, "snap data");
	return true;
}

static bool test_session_save(void) {
	Sdb *expected = ref_db ();
	Sdb *actual = sdb_new0 ();
	RDebugSession *session = ref_session ();
	r_debug_session_serialize (session, actual);

	mu_assert ("save", sdb_diff (expected, actual, diff_cb, NULL));

	sdb_free (actual);
	sdb_free (expected);
	r_debug_session_free (session);
	mu_end;
}

static bool test_session_load(void) {
	RDebugSession *ref = ref_session ();
	RDebugSession *session = r_debug_session_new ();
	Sdb *db = ref_db ();
	RDebugCheckpoint *chkpt;
	RDebugCheckpoint *ref_chkpt;
	size_t chkpt_idx;
	size_t i;

	r_debug_session_deserialize (session, db);

	mu_assert_eq (session->maxcnum, ref->maxcnum, "maxcnum");
	mu_assert_eq (session->next_checkpoint_id, ref->next_checkpoint_id, "next_checkpoint_id");
	mu_assert_eq (session->current_checkpoint_id, ref->current_checkpoint_id, "current_checkpoint_id");
	mu_assert_eq ((int)session->linear_history_valid, (int)ref->linear_history_valid, "linear_history_valid");
	ht_up_foreach (session->registers, compare_registers_cb, ref->registers);
	ht_up_foreach (session->memory, compare_memory_cb, ref->memory);
	mu_assert_eq (RVecDebugCheckpoint_length (session->checkpoints), RVecDebugCheckpoint_length (ref->checkpoints), "checkpoints length");

	chkpt_idx = 0;
	R_VEC_FOREACH (session->checkpoints, chkpt) {
		int snap_idx;
		ref_chkpt = RVecDebugCheckpoint_at (ref->checkpoints, chkpt_idx++);
		mu_assert_eq (chkpt->id, ref_chkpt->id, "checkpoint id");
		mu_assert_eq (chkpt->parent_id, ref_chkpt->parent_id, "checkpoint parent");
		mu_assert_eq (chkpt->cnum, ref_chkpt->cnum, "checkpoint cnum");
		mu_assert_eq (chkpt->resume_bp_addr, ref_chkpt->resume_bp_addr, "checkpoint resume bp addr");
		mu_assert_streq (chkpt->label, ref_chkpt->label, "checkpoint label");
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			arena_eq (chkpt->arena[i], ref_chkpt->arena[i]);
		}
		mu_assert_eq ((int)r_list_length (chkpt->snaps), (int)r_list_length (ref_chkpt->snaps), "snaps length");
		for (snap_idx = 0; snap_idx < (int)r_list_length (chkpt->snaps); snap_idx++) {
			RDebugSnap *actual_snap = r_list_get_n (chkpt->snaps, snap_idx);
			RDebugSnap *expected_snap = r_list_get_n (ref_chkpt->snaps, snap_idx);
			snap_eq (actual_snap, expected_snap);
		}
	}
	mu_assert ("checkpoint lookup", r_debug_session_checkpoint_get (session, 1) != NULL);
	mu_assert ("missing checkpoint lookup", r_debug_session_checkpoint_get (session, 999) == NULL);

	sdb_free (db);
	r_debug_session_free (session);
	r_debug_session_free (ref);
	mu_end;
}

static bool test_session_branch_roundtrip(void) {
	RDebugSession *ref = r_debug_session_new ();
	RDebugSession *session = r_debug_session_new ();
	Sdb *db = sdb_new0 ();
	RDebugCheckpoint root = {0};
	RDebugCheckpoint branch = {0};
	RDebugCheckpoint *root_chkpt;
	RDebugCheckpoint *branch_chkpt;

	mu_assert ("ref session", ref != NULL);
	mu_assert ("session", session != NULL);
	mu_assert ("db", db != NULL);

	root.id = 1;
	root.parent_id = UT64_MAX;
	root.cnum = 0;
	root.label = strdup ("root");
	root.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	RVecDebugCheckpoint_push_back (ref->checkpoints, &root);

	branch.id = 2;
	branch.parent_id = 1;
	branch.cnum = 0;
	branch.label = strdup ("branch");
	branch.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	RVecDebugCheckpoint_push_back (ref->checkpoints, &branch);

	ht_up_insert (ref->checkpoint_index, 1, (void *)1);
	ht_up_insert (ref->checkpoint_index, 2, (void *)2);
	ref->current_checkpoint_id = 2;
	ref->next_checkpoint_id = 3;
	ref->linear_history_valid = false;

	r_debug_session_serialize (ref, db);
	r_debug_session_deserialize (session, db);

	mu_assert_eq (RVecDebugCheckpoint_length (session->checkpoints), 2, "branched checkpoints length");
	root_chkpt = r_debug_session_checkpoint_get (session, 1);
	branch_chkpt = r_debug_session_checkpoint_get (session, 2);
	mu_assert ("root checkpoint", root_chkpt != NULL);
	mu_assert ("branch checkpoint", branch_chkpt != NULL);
	mu_assert_eq (root_chkpt->cnum, 0, "root cnum");
	mu_assert_eq (branch_chkpt->cnum, 0, "branch cnum");
	mu_assert_eq (branch_chkpt->parent_id, 1, "branch parent");
	mu_assert_streq (branch_chkpt->label, "branch", "branch label");
	mu_assert_eq (session->current_checkpoint_id, 2, "current checkpoint id");
	mu_assert_eq (session->next_checkpoint_id, 3, "next checkpoint id");
	mu_assert_eq ((int)session->linear_history_valid, false, "linear history valid");

	sdb_free (db);
	r_debug_session_free (session);
	r_debug_session_free (ref);
	mu_end;
}

static bool test_session_deserialize_sorts_checkpoints_by_cnum_then_id(void) {
	RDebugSession *session = r_debug_session_new ();
	Sdb *db = sdb_new0 ();
	Sdb *checkpoints_sdb;
	RDebugCheckpoint *first;
	RDebugCheckpoint *second;

	mu_assert ("session", session != NULL);
	mu_assert ("db", db != NULL);

	sdb_num_set (db, "next_checkpoint_id", 3, 0);
	sdb_num_set (db, "current_checkpoint_id", 2, 0);
	sdb_bool_set (db, "linear_history_valid", false, 0);
	mu_assert ("memory ns", sdb_ns (db, "memory", true) != NULL);
	mu_assert ("registers ns", sdb_ns (db, "registers", true) != NULL);
	checkpoints_sdb = sdb_ns (db, "checkpoints", true);
	mu_assert ("checkpoints ns", checkpoints_sdb != NULL);
	sdb_set (checkpoints_sdb, "0x2", "{\"id\":2,\"cnum\":0,\"parent\":1,\"label\":\"second\",\"registers\":[],\"snaps\":[]}", 0);
	sdb_set (checkpoints_sdb, "0x1", "{\"id\":1,\"cnum\":0,\"parent\":null,\"label\":\"first\",\"registers\":[],\"snaps\":[]}", 0);

	r_debug_session_deserialize (session, db);
	mu_assert_eq (RVecDebugCheckpoint_length (session->checkpoints), 2, "checkpoints length");
	first = RVecDebugCheckpoint_at (session->checkpoints, 0);
	second = RVecDebugCheckpoint_at (session->checkpoints, 1);
	mu_assert ("first checkpoint", first != NULL);
	mu_assert ("second checkpoint", second != NULL);
	mu_assert_eq (first->id, 1, "sorted first id");
	mu_assert_eq (second->id, 2, "sorted second id");
	mu_assert_eq (session->current_checkpoint_id, 2, "current checkpoint id");

	sdb_free (db);
	r_debug_session_free (session);
	mu_end;
}

static bool test_session_delete_leaf_checkpoint(void) {
	RDebugSession *session = r_debug_session_new ();
	RDebugCheckpoint root = {0};
	RDebugCheckpoint leaf = {0};
	RDebug dbg = {0};

	mu_assert ("session", session != NULL);

	root.id = 1;
	root.parent_id = UT64_MAX;
	root.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	leaf.id = 2;
	leaf.parent_id = 1;
	leaf.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	RVecDebugCheckpoint_push_back (session->checkpoints, &root);
	RVecDebugCheckpoint_push_back (session->checkpoints, &leaf);
	ht_up_insert (session->checkpoint_index, 1, (void *)1);
	ht_up_insert (session->checkpoint_index, 2, (void *)2);
	session->current_checkpoint_id = 1;
	dbg.session = session;

	mu_assert ("delete leaf", r_debug_session_delete (&dbg, 2));
	mu_assert_eq (RVecDebugCheckpoint_length (session->checkpoints), 1, "checkpoint count after delete");
	mu_assert ("leaf removed", r_debug_session_checkpoint_get (session, 2) == NULL);

	r_debug_session_free (session);
	mu_end;
}

static bool test_session_delete_rejects_current_or_parent(void) {
	RDebugSession *session = r_debug_session_new ();
	RDebugCheckpoint root = {0};
	RDebugCheckpoint leaf = {0};
	RDebug dbg = {0};

	mu_assert ("session", session != NULL);

	root.id = 1;
	root.parent_id = UT64_MAX;
	root.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	leaf.id = 2;
	leaf.parent_id = 1;
	leaf.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	RVecDebugCheckpoint_push_back (session->checkpoints, &root);
	RVecDebugCheckpoint_push_back (session->checkpoints, &leaf);
	ht_up_insert (session->checkpoint_index, 1, (void *)1);
	ht_up_insert (session->checkpoint_index, 2, (void *)2);
	dbg.session = session;

	session->current_checkpoint_id = 1;
	mu_assert ("reject current delete", !r_debug_session_delete (&dbg, 1));
	session->current_checkpoint_id = 2;
	mu_assert ("reject parent delete", !r_debug_session_delete (&dbg, 1));

	r_debug_session_free (session);
	mu_end;
}

static bool test_checkpoint_restore_preserves_resume_breakpoint_addr(void) {
	RDebugSession *session = r_debug_session_new ();
	RDebugCheckpoint checkpoint = {0};
	RDebug dbg = {0};

	mu_assert ("session", session != NULL);

	checkpoint.id = 1;
	checkpoint.parent_id = UT64_MAX;
	checkpoint.resume_bp_addr = 0x401dd0;
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	RVecDebugCheckpoint_push_back (session->checkpoints, &checkpoint);
	ht_up_insert (session->checkpoint_index, 1, (void *)1);
	dbg.session = session;
	dbg.reg = r_reg_new ();
	mu_assert ("debug reg", dbg.reg != NULL);

	dbg.reason.bp_addr = 0;
	mu_assert ("restore checkpoint", r_debug_session_restore (&dbg, 1));
	mu_assert_eq (dbg.reason.bp_addr, (ut64)0x401dd0, "resume breakpoint restored");

	r_reg_free (dbg.reg);
	r_debug_session_free (session);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_session_save);
	mu_run_test (test_session_load);
	mu_run_test (test_session_branch_roundtrip);
	mu_run_test (test_session_deserialize_sorts_checkpoints_by_cnum_then_id);
	mu_run_test (test_session_delete_leaf_checkpoint);
	mu_run_test (test_session_delete_rejects_current_or_parent);
	mu_run_test (test_checkpoint_restore_preserves_resume_breakpoint_addr);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
