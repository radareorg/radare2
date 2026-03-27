#include <r_debug.h>
#include <r_util.h>
#include <r_reg.h>
#include "minunit.h"

#if HAVE_PTY && ((__linux__ && !__ANDROID__) || defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__))
#define TEST_DEBUG_SESSION_HAVE_OPENPTY 1
#else
#define TEST_DEBUG_SESSION_HAVE_OPENPTY 0
#endif

#if TEST_DEBUG_SESSION_HAVE_OPENPTY
#if __linux__ && !__ANDROID__
#include <pty.h>
#include <utmp.h>
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <util.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <libutil.h>
#endif
#include <termios.h>
#include <unistd.h>
#endif

static void replay_pair_free(HtUPKv *kv) {
	r_debug_replay_stream_free ((RDebugReplayStream *)kv->value);
}

static bool checkpoint_add_replay(RDebugCheckpoint *checkpoint, int fd, const char *label, const ut8 *bytes, ut64 len, ut64 consumed) {
	RDebugReplayStream *stream;
	R_RETURN_VAL_IF_FAIL (checkpoint && checkpoint->replay, false);
	stream = R_NEW0 (RDebugReplayStream);
	if (!stream) {
		return false;
	}
	stream->fd = fd;
	stream->consumed = consumed;
	if (R_STR_ISNOTEMPTY (label)) {
		stream->label = strdup (label);
	}
	stream->data = r_buf_new_with_bytes (bytes, len);
	if (!stream->data) {
		r_debug_replay_stream_free (stream);
		return false;
	}
	ht_up_insert (checkpoint->replay, (ut64)(ut32)fd, stream);
	return true;
}

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
			"],"
			"\"replay\":["
				"{\"fd\":3,\"consumed\":1,\"label\":\"seed\",\"hex\":\"4142\",\"size\":2}"
			"]"
		"}", 0);

	return db;
}

static RDebugSession *ref_session(void) {
	size_t i;
	RDebugSession *s = r_debug_session_new ();
	if (!s) {
		return NULL;
	}
	// Registers & Memory
	r_debug_session_add_reg_change (s, 0, 0x100, 0x41424344);
	r_debug_session_add_mem_change (s, 0x7ffffffff000, 0xaa);
	r_debug_session_add_mem_change (s, 0x7ffffffff001, 0x00);
	s->maxcnum++;
	s->cnum++;

	r_debug_session_add_reg_change (s, 0, 0x100, 0xdeadbeef);
	r_debug_session_add_mem_change (s, 0x7ffffffff000, 0xbb);
	r_debug_session_add_mem_change (s, 0x7ffffffff001, 0x01);

	// Checkpoints
	RDebugCheckpoint checkpoint = {0};
	checkpoint.id = 1;
	checkpoint.parent_id = UT64_MAX;
	checkpoint.cnum = 0;
	checkpoint.label = strdup ("root");
	checkpoint.replay = ht_up_new (NULL, replay_pair_free, NULL);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = r_reg_arena_new (0x10);
		if (a) {
			memset (a->bytes, i, a->size);
			checkpoint.arena[i] = a;
		}
	}
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	RDebugSnap *snap = R_NEW0 (RDebugSnap);
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
	checkpoint_add_replay (&checkpoint, 3, "seed", (const ut8 *)"AB", 2, 1);
	RVecDebugCheckpoint_push_back (s->checkpoints, &checkpoint);
	ht_up_insert (s->checkpoint_index, checkpoint.id, (void *)1);
	s->current_checkpoint_id = checkpoint.id;
	s->next_checkpoint_id = 2;
	s->linear_history_valid = true;

	return s;
}

static void diff_cb(const SdbDiff *diff, void *user) {
	char buf[2048];
	if (sdb_diff_format (buf, sizeof (buf), diff) < 0) {
		return;
	}
	printf ("%s\n", buf);
}

static bool test_session_save(void) {
	Sdb *expected = ref_db ();
	Sdb *actual = sdb_new0 ();
	RDebugSession *s = ref_session ();
	r_debug_session_serialize (s, actual);

	mu_assert ("save", sdb_diff (expected, actual, diff_cb, NULL));

	sdb_free (actual);
	sdb_free (expected);
	r_debug_session_free (s);
	mu_end;
}

static bool compare_registers_cb(void *user, const ut64 key, const void *value) {
	RDebugChangeReg *actual_reg, *expected_reg;
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
	RDebugChangeMem *actual_mem, *expected_mem;
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

static bool replay_stream_eq(RDebugReplayStream *actual, RDebugReplayStream *expected) {
	mu_assert ("replay null", actual && expected);
	mu_assert_eq (actual->fd, expected->fd, "replay fd");
	mu_assert_eq (actual->consumed, expected->consumed, "replay consumed");
	mu_assert_streq (actual->label, expected->label, "replay label");
	ut64 actual_size = r_buf_size (actual->data);
	ut64 expected_size = r_buf_size (expected->data);
	mu_assert_eq (actual_size, expected_size, "replay size");
	ut8 *actual_bytes = malloc (actual_size);
	ut8 *expected_bytes = malloc (expected_size);
	mu_assert ("replay bytes alloc", actual_bytes && expected_bytes);
	mu_assert_eq ((int)r_buf_read_at (actual->data, 0, actual_bytes, actual_size), (int)actual_size, "actual replay read");
	mu_assert_eq ((int)r_buf_read_at (expected->data, 0, expected_bytes, expected_size), (int)expected_size, "expected replay read");
	mu_assert_memeq (actual_bytes, expected_bytes, expected_size, "replay bytes");
	free (actual_bytes);
	free (expected_bytes);
	return true;
}

static bool test_session_load(void) {
	RDebugSession *ref = ref_session ();
	RDebugSession *s = r_debug_session_new ();
	Sdb *db = ref_db ();
	r_debug_session_deserialize (s, db);

	mu_assert_eq (s->maxcnum, ref->maxcnum, "maxcnum");
	mu_assert_eq (s->next_checkpoint_id, ref->next_checkpoint_id, "next_checkpoint_id");
	mu_assert_eq (s->current_checkpoint_id, ref->current_checkpoint_id, "current_checkpoint_id");
	mu_assert_eq ((int)s->linear_history_valid, (int)ref->linear_history_valid, "linear_history_valid");
	// Registers
	ht_up_foreach (s->registers, compare_registers_cb, ref->registers);
	// Memory
	ht_up_foreach (s->memory, compare_memory_cb, ref->memory);
	// Checkpoints
	size_t i, chkpt_idx;
	RDebugCheckpoint *chkpt, *ref_chkpt;
	mu_assert_eq (RVecDebugCheckpoint_length (s->checkpoints), RVecDebugCheckpoint_length (ref->checkpoints), "checkpoints length");
	chkpt_idx = 0;
	R_VEC_FOREACH (s->checkpoints, chkpt) {
			ref_chkpt = RVecDebugCheckpoint_at (ref->checkpoints, chkpt_idx++);
			mu_assert_eq (chkpt->id, ref_chkpt->id, "checkpoint id");
			mu_assert_eq (chkpt->parent_id, ref_chkpt->parent_id, "checkpoint parent");
			mu_assert_eq (chkpt->cnum, ref_chkpt->cnum, "checkpoint cnum");
			mu_assert_streq (chkpt->label, ref_chkpt->label, "checkpoint label");
			// Registers
			for (i = 0; i < R_REG_TYPE_LAST; i++) {
			arena_eq (chkpt->arena[i], ref_chkpt->arena[i]);
		}
		// Snaps
		mu_assert_eq ((int)r_list_length (chkpt->snaps), (int)r_list_length (ref_chkpt->snaps), "snaps length");
		int snap_idx;
		for (snap_idx = 0; snap_idx < (int)r_list_length (chkpt->snaps); snap_idx++) {
			RDebugSnap *actual_snap = r_list_get_n (chkpt->snaps, snap_idx);
			RDebugSnap *expected_snap = r_list_get_n (ref_chkpt->snaps, snap_idx);
			snap_eq (actual_snap, expected_snap);
		}
		RDebugReplayStream *actual_stream = ht_up_find (chkpt->replay, 3, NULL);
		RDebugReplayStream *expected_stream = ht_up_find (ref_chkpt->replay, 3, NULL);
		replay_stream_eq (actual_stream, expected_stream);

	}
	mu_assert ("checkpoint lookup", r_debug_session_checkpoint_get (s, 1) != NULL);
	mu_assert ("missing checkpoint lookup", r_debug_session_checkpoint_get (s, 999) == NULL);

	sdb_free (db);
	r_debug_session_free (s);
	r_debug_session_free (ref);
	mu_end;
}

static bool test_session_branch_roundtrip(void) {
	RDebugSession *ref = r_debug_session_new ();
	RDebugSession *s = r_debug_session_new ();
	Sdb *db = sdb_new0 ();
	RDebugCheckpoint root = {0};
	RDebugCheckpoint branch = {0};
	RDebugCheckpoint *root_chkpt;
	RDebugCheckpoint *branch_chkpt;
	mu_assert ("ref session", ref != NULL);
	mu_assert ("session", s != NULL);
	mu_assert ("db", db != NULL);

	root.id = 1;
	root.parent_id = UT64_MAX;
	root.cnum = 0;
	root.label = strdup ("root");
	root.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	root.replay = ht_up_new (NULL, replay_pair_free, NULL);
	mu_assert ("root replay", root.replay != NULL);
	mu_assert ("root replay data", checkpoint_add_replay (&root, 0, "stdin", (const ut8 *)"AA", 2, 0));
	RVecDebugCheckpoint_push_back (ref->checkpoints, &root);

	branch.id = 2;
	branch.parent_id = 1;
	branch.cnum = 0;
	branch.label = strdup ("branch");
	branch.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	branch.replay = ht_up_new (NULL, replay_pair_free, NULL);
	mu_assert ("branch replay", branch.replay != NULL);
	mu_assert ("branch replay data", checkpoint_add_replay (&branch, 0, "stdin", (const ut8 *)"AB", 2, 1));
	RVecDebugCheckpoint_push_back (ref->checkpoints, &branch);

	ht_up_insert (ref->checkpoint_index, 1, (void *)1);
	ht_up_insert (ref->checkpoint_index, 2, (void *)2);
	ref->current_checkpoint_id = 2;
	ref->next_checkpoint_id = 3;
	ref->linear_history_valid = false;

	r_debug_session_serialize (ref, db);
	r_debug_session_deserialize (s, db);

	mu_assert_eq (RVecDebugCheckpoint_length (s->checkpoints), 2, "branched checkpoints length");
	root_chkpt = r_debug_session_checkpoint_get (s, 1);
	branch_chkpt = r_debug_session_checkpoint_get (s, 2);
	mu_assert ("root checkpoint", root_chkpt != NULL);
	mu_assert ("branch checkpoint", branch_chkpt != NULL);
	mu_assert_eq (root_chkpt->cnum, 0, "root cnum");
	mu_assert_eq (branch_chkpt->cnum, 0, "branch cnum");
	mu_assert_eq (branch_chkpt->parent_id, 1, "branch parent");
	mu_assert_streq (branch_chkpt->label, "branch", "branch label");
	mu_assert_eq (s->current_checkpoint_id, 2, "current checkpoint id");
	mu_assert_eq (s->next_checkpoint_id, 3, "next checkpoint id");
	mu_assert_eq ((int)s->linear_history_valid, false, "linear history valid");
	replay_stream_eq (ht_up_find (root_chkpt->replay, 0, NULL), ht_up_find (RVecDebugCheckpoint_at (ref->checkpoints, 0)->replay, 0, NULL));
	replay_stream_eq (ht_up_find (branch_chkpt->replay, 0, NULL), ht_up_find (RVecDebugCheckpoint_at (ref->checkpoints, 1)->replay, 0, NULL));

	sdb_free (db);
	r_debug_session_free (s);
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
	sdb_set (checkpoints_sdb, "0x2", "{\"id\":2,\"cnum\":0,\"parent\":1,\"label\":\"second\",\"registers\":[],\"snaps\":[],\"replay\":[]}", 0);
	sdb_set (checkpoints_sdb, "0x1", "{\"id\":1,\"cnum\":0,\"parent\":null,\"label\":\"first\",\"registers\":[],\"snaps\":[],\"replay\":[]}", 0);

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

static bool test_session_replay_clear(void) {
	RDebugSession *session = r_debug_session_new ();
	RDebugCheckpoint checkpoint = {0};
	RDebugReplayStream *stream;
	mu_assert ("session", session != NULL);

	checkpoint.id = 1;
	checkpoint.parent_id = UT64_MAX;
	checkpoint.replay = ht_up_new (NULL, replay_pair_free, NULL);
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	mu_assert ("checkpoint replay", checkpoint.replay != NULL);
	mu_assert ("checkpoint snaps", checkpoint.snaps != NULL);
	RVecDebugCheckpoint_push_back (session->checkpoints, &checkpoint);
	ht_up_insert (session->checkpoint_index, 1, (void *)1);

	mu_assert ("append replay fd0", r_debug_session_checkpoint_replay_append (session, 1, 0, (const ut8 *)"AB", 2, "stdin"));
	mu_assert ("append replay fd3", r_debug_session_checkpoint_replay_append (session, 1, 3, (const ut8 *)"CD", 2, "aux"));
	mu_assert ("clear one replay fd", r_debug_session_checkpoint_replay_clear (session, 1, 0));
	mu_assert ("fd0 cleared", ht_up_find (RVecDebugCheckpoint_at (session->checkpoints, 0)->replay, 0, NULL) == NULL);
	stream = ht_up_find (RVecDebugCheckpoint_at (session->checkpoints, 0)->replay, 3, NULL);
	mu_assert ("fd3 preserved", stream != NULL);
	mu_assert_eq (stream->fd, 3, "fd3 stream fd");
	mu_assert_eq (stream->consumed, 0, "fd3 stream consumed");
	mu_assert_streq (stream->label, "aux", "fd3 stream label");
	mu_assert_eq (r_buf_size (stream->data), 2, "fd3 stream size");
	mu_assert ("clear missing replay fd fails", !r_debug_session_checkpoint_replay_clear (session, 1, 0));
	mu_assert ("clear all replay fds", r_debug_session_checkpoint_replay_clear (session, 1, -1));
	mu_assert ("fd3 cleared by clear-all", ht_up_find (RVecDebugCheckpoint_at (session->checkpoints, 0)->replay, 3, NULL) == NULL);

	r_debug_session_free (session);
	mu_end;
}

static bool test_session_replay_apply(void) {
#if TEST_DEBUG_SESSION_HAVE_OPENPTY
	RDebugSession *session = r_debug_session_new ();
	mu_assert ("session", session != NULL);
	RDebugCheckpoint checkpoint = {0};
	checkpoint.id = 1;
	checkpoint.parent_id = UT64_MAX;
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	checkpoint.replay = ht_up_new (NULL, replay_pair_free, NULL);
	mu_assert ("checkpoint replay", checkpoint.replay != NULL);
	RVecDebugCheckpoint_push_back (session->checkpoints, &checkpoint);
	ht_up_insert (session->checkpoint_index, 1, (void *)1);
	mu_assert ("append replay", r_debug_session_checkpoint_replay_append (session, 1, 3, (const ut8 *)"AB", 2, "stdout"));

	RDebug dbg = {0};
	dbg.session = session;
	dbg.replay_bindings = ht_up_new (NULL, NULL, NULL);
	mu_assert ("replay bindings", dbg.replay_bindings != NULL);

	int master = -1;
	int slave = -1;
	mu_assert ("openpty", openpty (&master, &slave, NULL, NULL, NULL) == 0);
	struct termios tio;
	mu_assert ("tcgetattr", tcgetattr (slave, &tio) == 0);
	cfmakeraw (&tio);
	mu_assert ("tcsetattr", tcsetattr (slave, TCSANOW, &tio) == 0);
	const char *slave_name = ttyname (slave);
	mu_assert ("slave tty", slave_name != NULL);
	mu_assert ("bind replay pty", r_debug_replay_binding_add_pty (&dbg, 3, master, slave_name));

	mu_assert ("apply replay", r_debug_session_checkpoint_replay_apply (&dbg, 1, 3));
	ut8 buf[2] = {0};
	mu_assert_eq ((int)read (slave, buf, sizeof (buf)), 2, "read replay bytes");
	mu_assert_memeq (buf, "AB", 2, "pty replay bytes");
	RDebugReplayStream *stream = ht_up_find (RVecDebugCheckpoint_at (session->checkpoints, 0)->replay, 3, NULL);
	mu_assert_eq (stream->consumed, 2, "replay consumed");

	close (slave);
	r_debug_replay_bindings_reset (&dbg);
	r_debug_session_free (session);
	mu_end;
#else
	mu_end;
#endif
}

int all_tests(void) {
	mu_run_test (test_session_save);
	mu_run_test (test_session_load);
	mu_run_test (test_session_branch_roundtrip);
	mu_run_test (test_session_deserialize_sorts_checkpoints_by_cnum_then_id);
	mu_run_test (test_session_replay_clear);
	mu_run_test (test_session_replay_apply);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
