/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#if __WINDOWS__
struct r2r_subprocess_t {
	int ret;
	RStrBuf out;
	RStrBuf err;
};

R_API bool r2r_subprocess_init() { return true; }
R_API void r2r_subprocess_fini() {}

R_API R2RSubprocess *r2r_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
	(void)file, (void)args, (void)args_size, (void)envvars, (void)envvals, (void)env_size;
	eprintf ("TODO: implement r2r_subprocess API for windows\n");
	exit (1);
}

R_API void r2r_subprocess_wait(R2RSubprocess *proc) {}
R_API void r2r_subprocess_free(R2RSubprocess *proc) {}
#else

#include <errno.h>
#include <sys/wait.h>

struct r2r_subprocess_t {
	pid_t pid;
	int stdout_fd;
	int stderr_fd;
	int killpipe[2];
	int ret;
	RStrBuf out;
	RStrBuf err;
};

static RPVector subprocs;
static RThreadLock *subprocs_mutex;

static void subprocs_lock(sigset_t *old_sigset) {
	sigset_t block_sigset;
	sigemptyset (&block_sigset);
	sigaddset (&block_sigset, SIGWINCH);
	r_signal_sigmask (SIG_BLOCK, &block_sigset, old_sigset);
	r_th_lock_enter (subprocs_mutex);
}

static void subprocs_unlock(sigset_t *old_sigset) {
	r_th_lock_leave (subprocs_mutex);
	r_signal_sigmask (SIG_SETMASK, old_sigset, NULL);
}

static void handle_sigchld() {
	while (true) {
		int wstat;
		pid_t pid = waitpid (-1, &wstat, WNOHANG);
		if (pid <= 0)
			return;

		void **it;
		R2RSubprocess *proc = NULL;
		r_pvector_foreach (&subprocs, it) {
			R2RSubprocess *p = *it;
			if (p->pid == pid) {
				proc = p;
				break;
			}
		}
		if (!proc) {
			continue;
		}

		if (WIFEXITED (wstat)) {
			proc->ret = WEXITSTATUS (wstat);
		} else {
			proc->ret = -1;
		}
		ut8 r = 0;
		write (proc->killpipe[1], &r, 1);
	}
}

R_API bool r2r_subprocess_init() {
	r_pvector_init(&subprocs, NULL);
	subprocs_mutex = r_th_lock_new (false);
	if (!subprocs_mutex) {
		return false;
	}
	if (r_sys_signal (SIGCHLD, handle_sigchld) < 0) {
		return false;
	}
	return true;
}

R_API void r2r_subprocess_fini() {
	r_pvector_clear (&subprocs);
	r_th_lock_free (subprocs_mutex);
}

R_API R2RSubprocess *r2r_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
	char **argv = calloc (args_size + 2, sizeof (char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)file;
	if (args_size) {
		memcpy (argv + 1, args, sizeof (char *) * args_size);
	}
	// done by calloc: argv[args_size + 1] = NULL;

	R2RSubprocess *proc = R_NEW0 (R2RSubprocess);
	if (!proc) {
		goto error;
	}
	proc->killpipe[0] = proc->killpipe[1] = -1;
	proc->ret = -1;
	r_strbuf_init (&proc->out);
	r_strbuf_init (&proc->err);

	if (pipe (proc->killpipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(proc->killpipe[1], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}

	int stdout_pipe[2] = { -1, -1 };
	if (pipe (stdout_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}
	proc->stdout_fd = stdout_pipe[0];

	int stderr_pipe[2] = { -1, -1 };
	if (pipe (stderr_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}
	proc->stderr_fd = stderr_pipe[0];

	sigset_t old_sigset;
	subprocs_lock (&old_sigset);
	proc->pid = r_sys_fork ();
	if (proc->pid == -1) {
		// fail
		subprocs_unlock (&old_sigset);
		perror ("fork");
		free (proc);
		free (argv);
		return NULL;
	} else if (proc->pid == 0) {
		// child
		while ((dup2(stdout_pipe[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
		close (stdout_pipe[1]);
		close (stdout_pipe[0]);
		while ((dup2(stderr_pipe[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
		close (stderr_pipe[1]);
		close (stderr_pipe[0]);

		size_t i;
		for (i = 0; i < env_size; i++) {
			setenv (envvars[i], envvals[i], 1);
		}
		execvp (file, argv);
		perror ("exec");
		goto error;
	}
	free (argv);

	// parent
	close (stdout_pipe[1]);
	close (stderr_pipe[1]);

	r_pvector_push (&subprocs, proc);

	subprocs_unlock (&old_sigset);

	return proc;
error:
	free (argv);
	if (proc->killpipe[0] == -1) {
		close (proc->killpipe[0]);
	}
	if (proc->killpipe[1] == -1) {
		close (proc->killpipe[1]);
	}
	free (proc);
	if (stderr_pipe[0] == -1) {
		close (stderr_pipe[0]);
	}
	if (stderr_pipe[1] == -1) {
		close (stderr_pipe[1]);
	}
	if (stdout_pipe[0] == -1) {
		close (stdout_pipe[0]);
	}
	if (stdout_pipe[1] == -1) {
		close (stdout_pipe[1]);
	}
	return NULL;
}

R_API void r2r_subprocess_wait(R2RSubprocess *proc) {
	int r;
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;
	while (!stdout_eof || !stderr_eof || !child_dead) {
		fd_set rfds;
		FD_ZERO (&rfds);
		int nfds = 0;
		if (!stdout_eof) {
			FD_SET (proc->stdout_fd, &rfds);
			if (proc->stdout_fd > nfds) {
				nfds = proc->stdout_fd;
			}
		}
		if (!stderr_eof) {
			FD_SET (proc->stderr_fd, &rfds);
			if (proc->stderr_fd > nfds) {
				nfds = proc->stderr_fd;
			}
		}
		if (!child_dead) {
			FD_SET (proc->killpipe[0], &rfds);
			if (proc->killpipe[0] > nfds) {
				nfds = proc->killpipe[0];
			}
		}
		nfds++;
		r = select (nfds, &rfds, NULL, NULL, NULL);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}

		if (FD_ISSET (proc->stdout_fd, &rfds)) {
			char buf[0x500];
			ssize_t sz = read (proc->stdout_fd, buf, sizeof (buf));
			if (sz < 0) {
				perror ("read");
			} else if (sz == 0) {
				stdout_eof = true;
			} else {
				r_strbuf_append_n (&proc->out, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->stderr_fd, &rfds)) {
			char buf[0x500];
			ssize_t sz = read (proc->stderr_fd, buf, sizeof (buf));
			if (sz < 0) {
				perror ("read");
				continue;
			} else if (sz == 0) {
				stderr_eof = true;
			} else {
				r_strbuf_append_n (&proc->err, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->killpipe[0], &rfds)) {
			child_dead = true;
		}
	}
	if (r < 0) {
		perror ("select");
	}
}

R_API void r2r_subprocess_free(R2RSubprocess *proc) {
	if (!proc) {
		return;
	}
	sigset_t old_sigset;
	subprocs_lock (&old_sigset);
	r_pvector_remove_data (&subprocs, proc);
	subprocs_unlock (&old_sigset);
	r_strbuf_fini (&proc->out);
	r_strbuf_fini (&proc->err);;
	close (proc->killpipe[0]);;
	close (proc->killpipe[1]);
	close (proc->stdout_fd);
	close (proc->stderr_fd);
	free (proc);
}
#endif

R_API void r2r_process_output_free(R2RProcessOutput *out) {
	if (!out) {
		return;
	}
	free (out->out);
	free (out->err);
	free (out);
}

static R2RProcessOutput *run_r2_test(R2RRunConfig *config, const char *cmds, const char *file, RList *extra_args, bool load_plugins) {
	RPVector args;
	r_pvector_init (&args, NULL);
	r_pvector_push (&args, "-escr.utf8=0");
	r_pvector_push (&args, "-escr.color=0");
	r_pvector_push (&args, "-escr.interactive=0");
	r_pvector_push (&args, "-N");
	r_pvector_push (&args, "-Qc");
	r_pvector_push (&args, (void *)cmds);
	r_pvector_push (&args, (void *)file);
	RListIter *it;
	void *extra_arg;
	r_list_foreach (extra_args, it, extra_arg) {
		r_pvector_push (&args, extra_arg);
	}

	const char *envvars[] = {
		"R2_NOPLUGINS"
	};
	const char *envvals[] = {
		"1"
	};
	size_t env_size = load_plugins ? 0 : 1;
	R2RSubprocess *proc = r2r_subprocess_start (config->r2_cmd, args.v.a, r_pvector_len (&args), envvars, envvals, env_size);
	r2r_subprocess_wait (proc);
	R2RProcessOutput *out = R_NEW (R2RProcessOutput);
	if (out) {
		out->out = r_strbuf_drain_nofree (&proc->out);
		out->err = r_strbuf_drain_nofree (&proc->err);
		out->ret = proc->ret;
	}
	r2r_subprocess_free (proc);
	return out;
}

R_API R2RProcessOutput *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test) {
	RList *extra_args = test->args.value ? r_str_split_duplist (test->args.value, " ") : NULL;
	R2RProcessOutput *out = run_r2_test (config, test->cmds.value, test->file.value, extra_args, test->load_plugins);
	r_list_free (extra_args);
	return out;
}

R_API bool r2r_check_cmd_test(R2RProcessOutput *out, R2RCmdTest *test) {
	if (out->ret != 0 || !out->out || !out->err) {
		return false;
	}
	const char *expect_out = test->expect.value;
	if (expect_out && strcmp (out->out, expect_out) != 0) {
		return false;
	}
	const char *expect_err = test->expect_err.value;
	if (expect_err && strcmp (out->err, expect_err) != 0) {
		return false;
	}
	return true;
}

R_API R2RProcessOutput *r2r_run_json_test(R2RRunConfig *config, R2RJsonTest *test) {
	return run_r2_test (config, test->cmd, "--", NULL, test->load_plugins); // TODO: file?
}

R_API bool r2r_check_json_test(R2RProcessOutput *out, R2RJsonTest *test) {
	if (out->ret != 0 || !out->out || !out->err) {
		return false;
	}
	// TODO: check json
	return true;
}

R_API R2RAsmTestOutput *r2r_run_asm_test(R2RRunConfig *config, R2RAsmTest *test) {
	R2RAsmTestOutput *out = R_NEW0 (R2RAsmTestOutput);
	if (!out) {
		return NULL;
	}

	RPVector args;
	r_pvector_init (&args, NULL);

	if (test->arch) {
		r_pvector_push (&args, "-a");
		r_pvector_push (&args, (void *)test->arch);
	}

	if (test->cpu) {
		r_pvector_push (&args, "-c");
		r_pvector_push (&args, (void *)test->cpu);
	}

	char bits[0x20];
	if (test->bits) {
		snprintf (bits, sizeof (bits), "%d", test->bits);
		r_pvector_push (&args, "-b");
		r_pvector_push (&args, bits);
	}

	if (test->mode & R2R_ASM_TEST_MODE_BIG_ENDIAN) {
		r_pvector_push (&args, "-e");
	}

	char offset[0x20];
	if (test->offset) {
		r_snprintf (offset, sizeof (offset), "0x%"PFMT64x, test->offset);
		r_pvector_push (&args, "-o");
		r_pvector_push (&args, offset);
	}

	RStrBuf cmd_buf;
	r_strbuf_init (&cmd_buf);
	if (test->mode & R2R_ASM_TEST_MODE_ASSEMBLE) {
		r_pvector_push (&args, test->disasm);
		R2RSubprocess *proc = r2r_subprocess_start (config->rasm2_cmd, args.v.a, r_pvector_len (&args), NULL, NULL, 0);
		r2r_subprocess_wait (proc);
		if (proc->ret != 0) {
			goto rip;
		}
		char *hex = r_strbuf_get (&proc->out);
		size_t hexlen = strlen (hex);
		if (!hexlen) {
			goto rip;
		}
		ut8 *bytes = malloc (hexlen);
		int byteslen = r_hex_str2bin (hex, bytes);
		if (byteslen <= 0) {
			free (bytes);
			goto rip;
		}
		out->bytes = bytes;
		out->bytes_size = (size_t)byteslen;
rip:
		r_pvector_pop (&args);
		r2r_subprocess_free (proc);
	}
	if (test->mode & R2R_ASM_TEST_MODE_DISASSEMBLE) {
		char *hex = r_hex_bin2strdup (test->bytes, test->bytes_size);
		if (!hex) {
			goto beach;
		}
		r_pvector_push (&args, "-d");
		r_pvector_push (&args, hex);
		R2RSubprocess *proc = r2r_subprocess_start (config->rasm2_cmd, args.v.a, r_pvector_len (&args), NULL, NULL, 0);
		r2r_subprocess_wait (proc);
		if (proc->ret == 0) {
			char *disasm = r_strbuf_drain_nofree (&proc->out);
			r_str_trim (disasm);
			out->disasm = disasm;
		}
		r_pvector_pop (&args);
		r_pvector_pop (&args);
		r2r_subprocess_free (proc);
	}

beach:
	r_pvector_clear (&args);
	r_strbuf_fini (&cmd_buf);
	return out;
}

R_API bool r2r_check_asm_test(R2RAsmTestOutput *out, R2RAsmTest *test) {
	if (test->mode & R2R_ASM_TEST_MODE_ASSEMBLE) {
		if (!out->bytes || !test->bytes || out->bytes_size != test->bytes_size) {
			return false;
		}
		if (memcmp (out->bytes, test->bytes, test->bytes_size) != 0) {
			return false;
		}
	}
	if (test->mode & R2R_ASM_TEST_MODE_DISASSEMBLE) {
		if (!out->disasm || !test->disasm) {
			return false;
		}
		if (strcmp (out->disasm, test->disasm) != 0) {
			return false;
		}
	}
	return true;
}

R_API void r2r_asm_test_output_free(R2RAsmTestOutput *out) {
	if (!out) {
		return;
	}
	free (out->disasm);
	free (out->bytes);
	free (out);
}

R_API char *r2r_test_name(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		if (test->cmd_test->name.value) {
			return strdup (test->cmd_test->name.value);
		}
		return strdup ("<unnamed>");
	case R2R_TEST_TYPE_ASM:
		return r_str_newf ("<asm> %s", test->asm_test->disasm ? test->asm_test->disasm : "");
	case R2R_TEST_TYPE_JSON:
		return r_str_newf ("<json> %s", test->json_test->cmd ? test->json_test->cmd: "");
	}
	return NULL;
}

R_API bool r2r_test_broken(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		return test->cmd_test->broken.value;
	case R2R_TEST_TYPE_ASM:
		return test->asm_test->mode & R2R_ASM_TEST_MODE_BROKEN ? true : false;
	case R2R_TEST_TYPE_JSON:
		return test->json_test->broken;
	}
	return false;
}

R_API R2RTestResultInfo *r2r_run_test(R2RRunConfig *config, R2RTest *test) {
	R2RTestResultInfo *ret = R_NEW0 (R2RTestResultInfo);
	if (!ret) {
		return NULL;
	}
	ret->test = test;
	bool success = false;
	switch (test->type) {
	case R2R_TEST_TYPE_CMD: {
		R2RCmdTest *cmd_test = test->cmd_test;
		R2RProcessOutput *out = r2r_run_cmd_test (config, cmd_test);
		success = r2r_check_cmd_test (out, cmd_test);
		ret->proc_out = out;
		break;
	}
	case R2R_TEST_TYPE_ASM: {
		R2RAsmTest *asm_test = test->asm_test;
		R2RAsmTestOutput *out = r2r_run_asm_test (config, asm_test);
		success = r2r_check_asm_test (out, asm_test);
		ret->asm_out = out;
		break;
	}
	case R2R_TEST_TYPE_JSON: {
		R2RJsonTest *json_test = test->json_test;
		R2RProcessOutput *out = r2r_run_json_test (config, json_test);
		success = r2r_check_json_test (out, json_test);
		ret->proc_out = out;
		break;
	}
	}
	bool broken = r2r_test_broken (test);
	if (!success) {
		ret->result = broken ? R2R_TEST_RESULT_BROKEN : R2R_TEST_RESULT_FAILED;
	} else {
		ret->result = broken ? R2R_TEST_RESULT_FIXED : R2R_TEST_RESULT_OK;
	}
	return ret;
}

R_API void r2r_test_result_info_free(R2RTestResultInfo *result) {
	if (!result) {
		return;
	}
	if (result->test) {
		switch (result->test->type) {
		case R2R_TEST_TYPE_CMD:
		case R2R_TEST_TYPE_JSON:
			r2r_process_output_free (result->proc_out);
			break;
		case R2R_TEST_TYPE_ASM:
			r2r_asm_test_output_free (result->asm_out);
			break;
		}
	}
	free (result);
}
