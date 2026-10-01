#include <r_core.h>
#include "minunit.h"
#if R2__UNIX__
#include <sys/stat.h>
static struct stat sandbox_stdout;
#endif

static int test_user_fgets(RCons *cons, char *buf, int len) {
	(void)cons;
	if (len > 0) {
		*buf = '\0';
	}
	return 0;
}

bool test_cmd_str_issue_18799(void) {
	RCore *core = r_core_new ();
	char *output = r_core_cmd_str (core, "pd 1 @e:asm.hints=false");
	mu_assert ("command output leaked to stdout", strlen (output) > 0);
	free (output);
	r_core_free (core);
	mu_end;
}

bool test_multiple_cores_share_terminal(void) {
	RCore *first = r_core_new ();
	RCore *second = r_core_new ();
	mu_assert ("different console instances", first->cons != second->cons);
	mu_assert_notnull (first->cons->terminal, "first core console is attached");
	mu_assert_notnull (second->cons->terminal, "second core console is attached");

	char *first_output = r_core_cmd_str (first, "?e first");
	char *second_output = r_core_cmd_str (second, "?e second");
	mu_assert_streq_free (first_output, "first\n", "first core output");
	mu_assert_streq_free (second_output, "second\n", "second core output");

	r_core_free (first);
	mu_assert_ptreq (r_cons_singleton (), second->cons, "freeing first core preserves second");
	r_core_free (second);
	mu_assert_false (r_cons_is_initialized (), "freeing both cores clears current console");
	mu_end;
}

bool test_echo_context_binding_and_depth(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create core");

	RCoreBind bind = { 0 };
	r_core_bind (core, &bind);
	char *output = bind.cmdStr (bind.core, "echo \"bound value\"");
	mu_assert_streq_free (output, "bound value\n", "binding reaches registered echo");
	output = r_core_cmd_str (core, "?e \"adapter value\"");
	mu_assert_streq_free (output, "adapter value\n", "?e uses context echo");

	r_config_set_i (core->config, "cmd.depth", 2);
	output = r_core_cmd_str (core, "e cmd.depth=1; echo $(echo nested)");
	mu_assert_streq_free (output, "nested\n", "active root keeps its own depth budget");
	output = r_core_cmd_str (core, "echo $(echo hidden)");
	mu_assert_streq_free (output, "", "next root observes the reduced limit");
	output = r_core_cmd_str (core, "echo after");
	mu_assert_streq_free (output, "after\n", "depth failure does not poison later roots");

	r_config_set_i (core->config, "cmd.depth", 2);
	output = r_core_cmd_str (core, "echo $(echo visible)");
	mu_assert_streq_free (output, "visible\n", "one nested context fits depth two");
	r_core_free (core);
	mu_end;
}

bool test_prompt_utf8_ellipsis_width(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	core->cons->force_columns = 16;
	core->cons->force_rows = 1;
	core->cons->user_fgets = test_user_fgets;

	r_config_set_b (core->config, "scr.prompt.code", false);
	r_config_set_b (core->config, "scr.prompt.file", false);
	r_config_set_b (core->config, "scr.prompt.prj", false);
	r_config_set_b (core->config, "scr.prompt.flag", false);
	r_config_set_b (core->config, "scr.prompt.sect", false);
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", true);
	r_config_set (core->config, "cmd.prompt", "");
	r_config_set (core->config, "scr.prompt.format", "");

	mu_assert_true (r_core_prompt (core, false), "Prompt should render");
	char *prompt = r_line_get_prompt (core->cons->line);
	mu_assert_streq (prompt, "[0x0000…]> ", "Prompt should budget ellipsis by display width");

	free (prompt);
	r_core_free (core);
	mu_end;
}

bool test_prompt_format_preserves_trailing_escaped_space(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	char *prompt = r_core_prompt_format (core, "R2\\s");
	mu_assert_notnull (prompt, "Prompt format should render");
	mu_assert_streq (prompt, "R2 ", "Trailing escaped space should be preserved");

	free (prompt);
	r_core_free (core);
	mu_end;
}

bool test_prompt_format_preserves_trailing_escaped_newline(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	char *prompt = r_core_prompt_format (core, "R2\\n");
	mu_assert_notnull (prompt, "Prompt format should render");
	mu_assert_streq (prompt, "R2\n", "Trailing escaped newline should be preserved");

	free (prompt);
	r_core_free (core);
	mu_end;
}

bool test_autocomplete_find_prefers_exact_match(void) {
	RCoreAutocomplete *root = R_NEW0 (RCoreAutocomplete);
	RCoreAutocomplete *oe = r_core_autocomplete_add (root, "oe", R_CORE_AUTOCMPLT_FILE, true);
	RCoreAutocomplete *o = r_core_autocomplete_add (root, "o", R_CORE_AUTOCMPLT_FILE, true);
	RCoreAutocomplete *open = r_core_autocomplete_add (root, "open", R_CORE_AUTOCMPLT_FILE, true);
	mu_assert_notnull (oe, "Couldn't add oe autocomplete");
	mu_assert_notnull (o, "Couldn't add o autocomplete");
	mu_assert_notnull (open, "Couldn't add open autocomplete");

	mu_assert_ptreq (r_core_autocomplete_find (root, "o", false), o, "Prefix lookup should prefer exact command matches");
	mu_assert_ptreq (r_core_autocomplete_find (root, "op", false), open, "Prefix lookup should still find longer matches");

	r_core_autocomplete_free (root);
	mu_end;
}

bool test_o_autocomplete_uses_file_completion(void) {
	char *dir = r_file_temp ("r2-ac");
	mu_assert_notnull (dir, "Couldn't create temporary path");
	mu_assert_true (r_sys_mkdir (dir), "Couldn't create temporary directory");

	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");

	RLineCompletion completion = {0};
	r_line_completion_init (&completion, 16);

	RLineBuffer buf = {0};
	char *cmd = r_str_newf ("o %s", dir);
	mu_assert_notnull (cmd, "Couldn't create autocomplete command");
	r_str_ncpy (buf.data, cmd, sizeof (buf.data));
	buf.length = strlen (buf.data);
	buf.index = buf.length;

	r_core_autocomplete (core, &completion, &buf, R_LINE_PROMPT_DEFAULT);

	char *expected = r_str_newf ("%s%s", dir, R_SYS_DIR);
	mu_assert_notnull (expected, "Couldn't create expected completion");
	bool found = false;
	char **it;
	R_VEC_FOREACH (&completion.args, it) {
		if (!strcmp (*it, expected)) {
			found = true;
			break;
		}
	}

	free (expected);
	free (cmd);
	r_line_completion_clear (&completion);
	RVecCString_fini (&completion.args);
	r_core_free (core);
	r_file_rm (dir);
	free (dir);
	mu_assert_true (found, "o <path> should use file completion");
	mu_end;
}

static RCmdResult autocomplete_context_handler(RCmdContext *ctx) {
	(void)ctx;
	return (RCmdResult) { 0 };
}

bool test_registered_command_autocomplete(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	mu_assert_true (r_cmd_register (core->rcmd, "ctxcomplete", autocomplete_context_handler, NULL),
		"register contextual command");
	RLineCompletion completion = { 0 };
	r_line_completion_init (&completion, 16);
	RLineBuffer buf = { 0 };
	r_str_ncpy (buf.data, "ctxcom", sizeof (buf.data));
	buf.length = strlen (buf.data);
	buf.index = buf.length;
	r_core_autocomplete (core, &completion, &buf, R_LINE_PROMPT_DEFAULT);
	bool found = false;
	char **it;
	R_VEC_FOREACH (&completion.args, it) {
		if (!strcmp (*it, "ctxcomplete")) {
			found = true;
			break;
		}
	}
	r_line_completion_clear (&completion);
	RVecCString_fini (&completion.args);
	r_core_free (core);
	mu_assert_true (found, "registered contextual command is autocompleted");
	mu_end;
}

bool test_foreach_instruction_bounds(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (r_core_file_open (core, "malloc://512", R_PERM_RW, 0), "open test buffer");
	RAnalFunction *fcn = r_anal_create_function (core->anal, "test", 0x100, 0, NULL);
	RAnalBlock *bb = r_anal_create_block (core->anal, 0x100, 12);
	r_anal_function_add_block (fcn, bb);
	bb->ninstr = 3;
	r_anal_bb_set_offset (bb, 1, 4);
	r_anal_bb_set_offset (bb, 2, 8);
	// Spare capacity is not a zero-terminated list of instruction offsets.
	bb->op_pos[2] = 12;
	r_core_seek (core, 0x100, true);

	char *output = r_core_cmd_str (core, "?v $$ @@i; ?v $$ @@Fi");
	ut64 addr = core->addr;
	bb->ninstr = 0;
	char *empty = r_core_cmd_str (core, "?v $$ @@i");
	r_unref (bb);
	r_core_free (core);
	mu_assert_streq_free (output, "0x100\n0x104\n0x108\n0x100\n0x104\n0x108\n",
		"both iterators visit only the recorded instructions");
	mu_assert_streq_free (empty, "", "empty blocks have no instructions to visit");
	mu_assert_eq (addr, 0x100, "iteration restores the seek");
	mu_end;
}

bool test_type_format_export_newlines(void) {
	RCore *core = r_core_new ();
	Sdb *types = core->anal->sdb_types;
	sdb_set (types, "evil", "type", 0);
	const char *formats[] = { "d value\nf injected", "d value\rf injected" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (formats); i++) {
		sdb_set (types, "type.evil", formats[i], 0);
		char *output = r_core_cmd_str (core, "t evil");
		mu_assert_streq_free (output, "", "reject multiline format export");
		output = r_core_cmd_str (core, "ts* evil");
		mu_assert_streq_free (output, "", "reject multiline named format export");
		output = r_core_cmd_str (core, ".t evil");
		mu_assert_streq_free (output, "", "reject multiline format execution");
		mu_assert_null (r_flag_get (core->flags, "injected"), "type format must not execute a second command");
	}
	sdb_set (types, "evil\nf injected\n#", "type", 0);
	sdb_set (types, "type.evil\nf injected\n#", "d value", 0);
	char *output = r_core_cmd_str (core, "'ts* evil\nf injected\n#");
	mu_assert_streq_free (output, "", "reject multiline format name");
	r_core_free (core);
	mu_end;
}

static void *sandbox_capture_mutation(void *user) {
	return r_core_cmd_str_pipe (user, "!mutate");
}

static int sandbox_probe(void *user, const char *input) {
	RCore *core = user;
	if (!strcmp (input, "nested")) {
		char *output = r_sandbox_run (R_SANDBOX_GRAIN_ALL, sandbox_capture_mutation, core);
		r_cons_print (core->cons, output);
		free (output);
	} else if (!strcmp (input, "mutate")) {
		r_sandbox_disable (true);
		r_sandbox_enable (true);
		r_sandbox_grain (R_SANDBOX_GRAIN_ALL);
		r_sandbox_disable (false);
	}
#if R2__UNIX__
	if (!strcmp (input, "descriptor")) {
		struct stat current;
		bool unchanged = !fstat (STDOUT_FILENO, &current)
			&& current.st_dev == sandbox_stdout.st_dev && current.st_ino == sandbox_stdout.st_ino;
		r_cons_printf (core->cons, "%s\n", r_str_bool (unchanged));
		return 0;
	}
#endif
	r_cons_printf (core->cons, "%s\n", r_str_bool (r_sandbox_check (R_SANDBOX_GRAIN_EXEC)));
	return 0;
}

typedef struct {
	RCore *core;
	char *output;
	char *nested;
	char *descriptor;
	bool enabled;
	int grain;
} SandboxCaptureProbe;

static void *sandbox_capture_probe(void *user) {
	SandboxCaptureProbe *probe = user;
	probe->output = r_core_cmd_str_pipe (probe->core, "!probe");
	probe->nested = r_core_cmd_str_pipe (probe->core, "!nested");
#if R2__UNIX__
	probe->descriptor = r_core_cmd_str_pipe (probe->core, "!descriptor");
#endif
	probe->enabled = r_sandbox_enable (false);
	probe->grain = r_sandbox_grain (R_SANDBOX_GRAIN_ALL);
	return user;
}

bool test_cmd_str_pipe_sandbox(void) {
	RCore *core = r_core_new ();
#if R2__UNIX__
	char *shell_output = r_core_cmd_str_pipe (core, "!!echo CAPTURED");
	mu_assert_streq_free (shell_output, "CAPTURED\n", "unsandboxed capture includes shell output");
	mu_assert_eq (fstat (STDOUT_FILENO, &sandbox_stdout), 0, "snapshot output descriptor");
#endif
	r_cmd_add (core->rcmd, "!", sandbox_probe);
	char *output = r_core_cmd_str_pipe (core, "!probe");
	mu_assert_streq_free (output, "true\n", "unsandboxed capture permits execution");
	mu_assert_false (r_sandbox_enable (false), "capture preserves disabled sandbox");

	int old_grain = r_sandbox_grain (R_SANDBOX_GRAIN_ENVIRON);
	SandboxCaptureProbe probe = { .core = core };
	void *result = r_sandbox_run (R_SANDBOX_GRAIN_NONE, sandbox_capture_probe, &probe);
	bool restored_enabled = r_sandbox_enable (false);
	int restored_grain = r_sandbox_grain (old_grain);
	r_core_free (core);
	mu_assert_ptreq (result, &probe, "scope returns the callback result");
	mu_assert_streq_free (probe.output, "false\n", "capture preserves execution restriction");
	mu_assert_streq_free (probe.nested, "false\nfalse\n", "nested capture cannot disable or weaken the sandbox");
#if R2__UNIX__
	mu_assert_streq_free (probe.descriptor, "true\n", "restricted capture does not redirect stdout");
#endif
	mu_assert_true (probe.enabled, "capture preserves enabled sandbox");
	mu_assert_eq (probe.grain, R_SANDBOX_GRAIN_NONE, "scope refuses increased permissions");
	mu_assert_false (restored_enabled, "scope restores disabled sandbox");
	mu_assert_eq (restored_grain, R_SANDBOX_GRAIN_ENVIRON, "scope restores nondefault grain");
	mu_end;
}

bool test_cmd_str_pipe_sandbox_exec(const char *command, const char *expected) {
#if R2__UNIX__ && !LIBC_HAVE_PLEDGE && !HAVE_CAPSICUM && !LIBC_HAVE_PRIV_SET
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "io.va", false);
	mu_assert_notnull (r_core_file_open (core, "malloc://4", R_PERM_RW, 0), "open pipeline input");
	const ut8 bytes[] = { 0, 'a', 0, 'b' };
	mu_assert_true (r_core_write_at (core, 0, bytes, sizeof (bytes)), "write binary pipeline input");
	char *input = r_core_cmd_str (core, "p8 4");
	mu_assert_streq_free (input, "00610062\n", "pipeline fixture contains leading and embedded NULs");
	int old_grain = r_sandbox_grain (R_SANDBOX_GRAIN_ALL);
	r_sandbox_enable (true);
	char *output = r_core_cmd_str_pipe (core, command);
	bool enabled = r_sandbox_enable (false);
	r_sandbox_grain (old_grain);
	r_sandbox_disable (true);
	r_sandbox_disable (true);
	r_core_free (core);
	mu_assert_streq_free (output, expected, "capture includes permitted external command output");
	mu_assert_true (enabled, "capture preserves the enabled sandbox");
#endif
	mu_end;
}

#if !LIBC_HAVE_PLEDGE && !HAVE_CAPSICUM && !LIBC_HAVE_PRIV_SET
static int sandbox_capture_calls;

static int sandbox_enable_probe(void *user, const char *input) {
	sandbox_capture_calls++;
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_sandbox_enable (true);
	return 0;
}
#endif

bool test_cmd_str_pipe_capture_failure(void) {
#if !LIBC_HAVE_PLEDGE && !HAVE_CAPSICUM && !LIBC_HAVE_PRIV_SET
	RCore *core = r_core_new ();
	r_cmd_add (core->rcmd, "!", sandbox_enable_probe);
	int old_grain = r_sandbox_grain (R_SANDBOX_GRAIN_ALL);
	sandbox_capture_calls = 0;
	char *output = r_core_cmd_str_pipe (core, "!enable");
	bool capture_failed = !output;
	free (output);
	bool enabled = r_sandbox_enable (false);
	int resulting_grain = r_sandbox_grain (old_grain);
	r_sandbox_disable (true);
	r_sandbox_disable (true);
	r_core_free (core);
	mu_assert_true (capture_failed, "command enabling sandbox prevents reading capture file");
	mu_assert_eq (sandbox_capture_calls, 1, "capture failure never replays a command");
	mu_assert_true (enabled, "capture failure preserves the command's sandbox change");
	mu_assert_eq (resulting_grain, R_SANDBOX_GRAIN_NONE, "capture failure preserves the command's grain");
#endif
	mu_end;
}

static void *sandbox_mutation_probe(void *user) {
	int *grain = user;
	r_sandbox_disable (true);
	r_sandbox_enable (true);
	r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	r_sandbox_disable (false);
	*grain = r_sandbox_grain (R_SANDBOX_GRAIN_ALL);
	return user;
}

typedef struct {
	int before;
	int narrower;
	int broader;
	int after;
	bool exec;
	bool environ_allowed;
} SandboxPolicyProbe;

static void *sandbox_policy_probe(void *user) {
	SandboxPolicyProbe *probe = user;
	probe->before = r_sandbox_grain (R_SANDBOX_GRAIN_ALL);
	r_sandbox_run (R_SANDBOX_GRAIN_ENVIRON | R_SANDBOX_GRAIN_DISK, sandbox_mutation_probe, &probe->narrower);
	r_sandbox_run (R_SANDBOX_GRAIN_ALL, sandbox_mutation_probe, &probe->broader);
	probe->after = r_sandbox_grain (R_SANDBOX_GRAIN_NONE);
	probe->exec = r_sandbox_check (R_SANDBOX_GRAIN_EXEC);
	probe->environ_allowed = r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON);
	return user;
}

static void *sandbox_combined_check(void *user) {
	bool *denied = user;
	*denied = !r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK);
	return user;
}

static void *sandbox_disjoint_probe(void *user) {
	return r_sandbox_run (R_SANDBOX_GRAIN_DISK, sandbox_combined_check, user);
}

bool test_sandbox_scope_policy(void) {
	int old_grain = r_sandbox_grain (R_SANDBOX_GRAIN_FILES);
	int requested = R_SANDBOX_GRAIN_EXEC | R_SANDBOX_GRAIN_ENVIRON;
	SandboxPolicyProbe probe = { 0 };
	void *result = r_sandbox_run (requested, sandbox_policy_probe, &probe);
	int all = R_SANDBOX_GRAIN_NONE;
	r_sandbox_run (R_SANDBOX_GRAIN_ALL, sandbox_mutation_probe, &all);
	bool disjoint_denied = false;
	r_sandbox_run (R_SANDBOX_GRAIN_FILES, sandbox_disjoint_probe, &disjoint_denied);
	bool restored_enabled = r_sandbox_enable (false);
	int restored_grain = r_sandbox_grain (old_grain);
	mu_assert_ptreq (result, &probe, "scope returns callback result");
	mu_assert_eq (probe.before, requested, "disabled base grain does not restrict scope");
	mu_assert_eq (probe.narrower, R_SANDBOX_GRAIN_ENVIRON, "nested partial scopes intersect permissions");
	mu_assert_eq (probe.broader, requested, "nested all cannot grant permissions");
	mu_assert_eq (probe.after, requested, "nested scope restores outer policy");
	mu_assert_true (probe.exec && probe.environ_allowed, "granted permissions remain usable");
	mu_assert_eq (all, (int)R_SANDBOX_GRAIN_ALL, "all-permissions scope remains immutable");
	mu_assert_true (disjoint_denied, "disjoint scopes deny combined alternative permissions");
	mu_assert_false (restored_enabled, "scope mutations do not enable the base sandbox");
	mu_assert_eq (restored_grain, R_SANDBOX_GRAIN_FILES, "scope mutations preserve disabled base grain");
	mu_end;
}

bool test_sandbox_scope_restoration(void) {
#if !LIBC_HAVE_PLEDGE && !HAVE_CAPSICUM && !LIBC_HAVE_PRIV_SET
	int old_grain = r_sandbox_grain (R_SANDBOX_GRAIN_ENVIRON);
	r_sandbox_enable (true);
	SandboxPolicyProbe probe = { 0 };
	r_sandbox_run (R_SANDBOX_GRAIN_EXEC | R_SANDBOX_GRAIN_ENVIRON, sandbox_policy_probe, &probe);
	bool enabled_restored = r_sandbox_enable (false);
	bool grain_restored = r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)
		&& !r_sandbox_check (R_SANDBOX_GRAIN_EXEC);
	r_sandbox_disable (true);
	int disabled_grain = R_SANDBOX_GRAIN_NONE;
	r_sandbox_run (R_SANDBOX_GRAIN_EXEC, sandbox_mutation_probe, &disabled_grain);
	bool disabled_restored = !r_sandbox_enable (false);
	bool restore_slot_preserved = r_sandbox_disable (false);
	int restored_grain = r_sandbox_grain (old_grain);
	r_sandbox_disable (true);
	r_sandbox_disable (true);
	mu_assert_eq (probe.before, R_SANDBOX_GRAIN_ENVIRON, "scope intersects enabled base permissions");
	mu_assert_eq (probe.broader, R_SANDBOX_GRAIN_ENVIRON, "nested all cannot bypass the base policy");
	mu_assert_false (probe.exec, "scope cannot grant execution denied by base");
	mu_assert_true (probe.environ_allowed, "scope retains permissions granted by base and request");
	mu_assert_true (enabled_restored, "scope restores an already enabled sandbox");
	mu_assert_true (grain_restored, "scope preserves an enabled sandbox's grain");
	mu_assert_true (disabled_restored, "scope preserves a temporarily disabled sandbox");
	mu_assert_true (restore_slot_preserved, "scope preserves the disable/restore slot");
	mu_assert_eq (restored_grain, R_SANDBOX_GRAIN_ENVIRON, "scope preserves the disabled grain");
	mu_assert_eq (disabled_grain, R_SANDBOX_GRAIN_EXEC, "temporarily disabled base does not restrict scope");
#endif
	mu_end;
}

#if WANT_THREADS
typedef struct {
	RThreadSemaphore *ready;
	RThreadSemaphore *resume;
	bool restricted;
	bool restored;
} SandboxThreadProbe;

static void *sandbox_thread_scope(void *user) {
	SandboxThreadProbe *probe = user;
	r_th_sem_post (probe->ready);
	r_th_sem_wait (probe->resume);
	probe->restricted = r_sandbox_enable (false) && r_sandbox_check (R_SANDBOX_GRAIN_EXEC)
		&& !r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)
		&& r_sandbox_grain (R_SANDBOX_GRAIN_ALL) == R_SANDBOX_GRAIN_EXEC;
	return user;
}

static RThreadFunctionRet sandbox_thread_probe(RThread *thread) {
	SandboxThreadProbe *probe = thread->user;
	r_sandbox_run (R_SANDBOX_GRAIN_EXEC, sandbox_thread_scope, probe);
	probe->restored = !r_sandbox_enable (false);
	return R_TH_STOP;
}
#endif

bool test_sandbox_scope_threads(void) {
#if WANT_THREADS
	SandboxThreadProbe probe = { r_th_sem_new (0), r_th_sem_new (0), false, false };
	mu_assert_notnull (probe.ready, "create ready semaphore");
	mu_assert_notnull (probe.resume, "create resume semaphore");
	RThread *thread = r_th_new (sandbox_thread_probe, &probe, 0);
	mu_assert_notnull (thread, "create sandbox thread");
	r_th_start (thread);
	r_th_sem_wait (probe.ready);
	bool unaffected = !r_sandbox_enable (false) && r_sandbox_check (R_SANDBOX_GRAIN_EXEC);
	int main_grain = R_SANDBOX_GRAIN_ALL;
	r_sandbox_run (R_SANDBOX_GRAIN_NONE, sandbox_mutation_probe, &main_grain);
	r_th_sem_post (probe.resume);
	r_th_wait (thread);
	r_th_free (thread);
	r_th_sem_free (probe.ready);
	r_th_sem_free (probe.resume);
	mu_assert_true (unaffected, "one thread's sandbox does not restrict another");
	mu_assert_eq (main_grain, R_SANDBOX_GRAIN_NONE, "concurrent scopes keep different permissions");
	mu_assert_true (probe.restricted, "another thread's callback does not relax the scope");
	mu_assert_true (probe.restored, "worker restores its own sandbox state");
#endif
	mu_end;
}

#if R2__UNIX__ && !__wasi__
typedef struct {
	const char *path;
	bool readable;
	bool writes_denied;
} SandboxFileProbe;

static void *sandbox_file_probe(void *user) {
	SandboxFileProbe *probe = user;
	int fd = r_sandbox_open (probe->path, O_RDONLY, 0);
	if (fd >= 0) {
		ut8 bytes[4];
		probe->readable = r_sandbox_read (fd, bytes, sizeof (bytes)) == sizeof (bytes)
			&& !memcmp (bytes, "data", sizeof (bytes));
		r_sandbox_close (fd);
	}
	const int modes[] = { O_WRONLY, O_RDWR, O_RDONLY | O_TRUNC, O_WRONLY | O_TRUNC,
		O_RDONLY | O_APPEND, O_WRONLY | O_APPEND, O_CREAT | O_WRONLY };
	probe->writes_denied = true;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (modes); i++) {
		fd = r_sandbox_open (probe->path, modes[i], 0600);
		if (fd >= 0) {
			probe->writes_denied = false;
			r_sandbox_close (fd);
		}
	}
	return user;
}
#endif

bool test_sandbox_scope_readonly_file(void) {
#if R2__UNIX__ && !__wasi__
	char *cwd = r_sys_getdir ();
	char *path = NULL;
	int fd = r_file_mkstemp ("r2-sandbox", &path);
	mu_assert ("create sandbox file fixture", fd >= 0);
	close (fd);
	mu_assert_true (r_file_dump (path, (const ut8 *)"data", 4, false), "write sandbox file fixture");
	char *directory = r_file_dirname (path);
	SandboxFileProbe probe = { .path = r_file_basename (path) };
	bool changed_directory = r_sys_chdir (directory);
	if (changed_directory) {
		r_sandbox_run (R_SANDBOX_GRAIN_DISK, sandbox_file_probe, &probe);
	}
	bool restored_directory = r_sys_chdir (cwd);
	char *contents = r_file_slurp (path, NULL);
	r_file_rm (path);
	free (directory);
	free (path);
	free (cwd);
	mu_assert_true (changed_directory && restored_directory, "restore working directory after file scope");
	mu_assert_true (probe.readable, "disk permission permits relative file reads");
	mu_assert_true (probe.writes_denied, "sandbox rejects write, truncate and append access");
	mu_assert_streq_free (contents, "data", "denied opens leave file contents unchanged");
#endif
	mu_end;
}

bool test_project_name_script_format(void) {
#if R2__UNIX__ && !__wasi__
	const char *scripts[] = {
		"# r2 rdb project file\n'e prj.name = saved_name\n",
		"# r2 rdb project file\n'e prj.name = saved_name",
		"# r2 rdb project file\n\"e prj.name = ignored\"\n''e prj.name = ignored\n'e prj.name = saved_name\n"
	};
	char *dir = r_file_temp ("r2-project-name");
	mu_assert_true (r_sys_mkdir (dir), "create project name fixture");
	char *script = r_file_new (dir, "rc.r2", NULL);
	RCore *core = r_core_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (scripts); i++) {
		mu_assert_true (r_file_dump (script, (const ut8 *)scripts[i], -1, false), "write project name fixture");
		char *name = r_core_project_name (core, script);
		mu_assert_streq_free (name, "saved_name", "read only the generated project name format");
	}
	r_core_free (core);
	r_file_rm_rf (dir);
	free (script);
	free (dir);
#endif
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_type_format_export_newlines);
	mu_run_test (test_foreach_instruction_bounds);
	mu_run_test (test_cmd_str_issue_18799);
	mu_run_test (test_multiple_cores_share_terminal);
	mu_run_test (test_echo_context_binding_and_depth);
	mu_run_test (test_prompt_utf8_ellipsis_width);
	mu_run_test (test_prompt_format_preserves_trailing_escaped_space);
	mu_run_test (test_prompt_format_preserves_trailing_escaped_newline);
	mu_run_test (test_autocomplete_find_prefers_exact_match);
	mu_run_test (test_o_autocomplete_uses_file_completion);
	mu_run_test (test_registered_command_autocomplete);
	mu_run_test (test_cmd_str_pipe_sandbox);
	mu_run_test_named (test_cmd_str_pipe_sandbox_exec, "test_cmd_str_pipe_sandbox_exec_shell", "!!echo CAPTURED", "CAPTURED\n");
	mu_run_test_named (test_cmd_str_pipe_sandbox_exec, "test_cmd_str_pipe_sandbox_exec_pipe", "?e input | tr a-z A-Z", "INPUT\n");
	mu_run_test_named (test_cmd_str_pipe_sandbox_exec, "test_cmd_str_pipe_sandbox_exec_binary", "pr 4 | tr '\\000' X", "XaXb");
	mu_run_test (test_cmd_str_pipe_capture_failure);
	mu_run_test (test_sandbox_scope_policy);
	mu_run_test (test_sandbox_scope_restoration);
	mu_run_test (test_sandbox_scope_threads);
	mu_run_test (test_sandbox_scope_readonly_file);
	mu_run_test (test_project_name_script_format);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
