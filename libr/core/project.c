/* radare - LGPL - Copyright 2010-2026 - pancake, rhl */

// R2R db/cmd/projects

#include <r_core.h>
#include <rvc.h>
// required to make spp use RStrBuf instead of SStrBuf
#define USE_R2 1
#include <spp/spp.h>

// project apis to be used from cmd_project.c
// TODO: Use .zrp as in zipped radare project

static bool is_valid_project_name(const char *name) {
	char *filtered = strdup (name);
	if (!filtered || r_str_filter_file (filtered) || r_str_len_utf8 (name) >= 64) {
		free (filtered);
		return false;
	}
	free (filtered);
	const char *const extension = r_str_endswith (name, ".zip")? r_str_last (name, ".zip"): NULL;
	for (; *name && name != extension; name++) {
		if (isdigit (*name) || islower (*name) || *name == '_') {
			continue;
		}
		return false;
	}
	return true;
}

static char *get_project_script_path(RCore *core, const char *file) {
	if (!core || !file || !*file) {
		return NULL;
	}
	char *prjfile;
	if (r_file_is_abspath (file)) {
		prjfile = strdup (file);
	} else {
		if (!is_valid_project_name (file)) {
			return NULL;
		}
		prjfile = r_file_abspath (r_config_get (core->config, "dir.projects"));
		prjfile = r_str_append (prjfile, R_SYS_DIR);
		prjfile = r_str_append (prjfile, file);
		if (!r_file_exists (prjfile) || r_file_is_directory (prjfile)) {
			prjfile = r_str_append (prjfile, R_SYS_DIR "rc.r2");
		}
	}
	char *data = r_file_slurp (prjfile, NULL);
	if (data? !r_str_startswith (data, "# r2 rdb project file"): r_file_exists (prjfile)) {
		R_FREE (prjfile);
	}
	free (data);
	return prjfile;
}

static bool project_path_is_within_projects_dir(RCore *core, const char *path) {
	char *pdir = r_file_abspath (r_config_get (core->config, "dir.projects"));
	char *ppath = r_file_abspath (path);
	char *prefix = (pdir && ppath) ? r_str_newf ("%s%s", pdir, R_SYS_DIR) : NULL;
	bool inside = prefix ? r_str_startswith (ppath, prefix) : false;
	free (prefix);
	free (pdir);
	free (ppath);
	return inside;
}

R_API bool r_core_is_project(RCore *core, const char *name) {
	bool ret = false;
	if (R_STR_ISNOTEMPTY (name) && *name != '.') {
		char *path = get_project_script_path (core, name);
		if (!path) {
			return false;
		}
		if (r_str_endswith (path, R_SYS_DIR "rc.r2") && r_file_exists (path)) {
			ret = true;
		} else {
			path = r_str_append (path, ".d");
			if (r_file_is_directory (path)) {
				ret = true;
			}
		}
		free (path);
	}
	return ret;
}

R_API void r_core_project_cat(RCore *core, const char *name) {
	r_core_return_value (core, R_CMD_RC_FAILURE);
	char *path = get_project_script_path (core, name);
	if (path) {
		char *data = r_file_slurp (path, NULL);
		if (data) {
			r_cons_println (core->cons, data);
			free (data);
			r_core_return_value (core, R_CMD_RC_SUCCESS);
		}
		free (path);
	}
}

R_API int r_core_project_list(RCore *core, int mode) {
	RListIter *iter;
	char *foo, *path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	if (!path) {
		return 0;
	}
	PJ *pj = mode == 'j'? r_core_pj_new (core): NULL;
	if (mode == 'j' && !pj) {
		free (path);
		return 0;
	}
	if (pj) {
		pj_a (pj);
	}
	RList *list = r_sys_dir (path);
	r_list_foreach (list, iter, foo) {
		if (r_core_is_project (core, foo)) {
			if (pj) {
				pj_s (pj, foo);
			} else {
				r_cons_println (core->cons, foo);
			}
		}
	}
	if (pj) {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
	r_list_free (list);
	free (path);
	return 0;
}

R_API int r_core_project_delete(RCore *core, const char *prjfile) {
	RCons *cons = core->cons;
	if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK)) {
		R_LOG_ERROR ("Cannot delete project in sandbox mode");
		return 0;
	}
	char *path = get_project_script_path (core, prjfile);
	if (!path) {
		R_LOG_ERROR ("Invalid project name '%s'", prjfile);
		return false;
	}
	if (!project_path_is_within_projects_dir (core, path)) {
		R_LOG_ERROR ("Refusing to delete project outside dir.projects");
		free (path);
		return false;
	}
	if (r_core_is_project (core, prjfile)) {
		char *prj_dir = r_file_dirname (path);
		if (!prj_dir) {
			R_LOG_ERROR ("Cannot resolve directory");
			free (path);
			return false;
		}
		bool must_rm = true;
		if (r_config_get_b (core->config, "scr.interactive")) {
			R_LOG_INFO ("Removing: %s", prj_dir);
			must_rm = r_cons_yesno (cons, 'y', "Confirm project deletion? (Y/n)");
		}
		if (must_rm) {
			r_file_rm_rf (prj_dir);
		}
		free (prj_dir);
	}
	free (path);
	return 0;
}

R_API void r_core_project_execute_cmds(RCore *core, const char *prjfile) {
	char *str = r_core_project_notes_file (core, prjfile);
	char *data = r_file_slurp (str, NULL);
	free (str);
	R_RETURN_IF_FAIL (data);
	char *expanded = spp_eval_str (NULL, data);
	free (data);
	R_RETURN_IF_FAIL (expanded);
	data = expanded;
	char *save_ptr = NULL;
	char *bol = r_str_tok_r (data, "\n", &save_ptr);
	while (bol) {
		if (bol[0] == ':') {
			r_core_cmd0 (core, bol + 1);
		}
		bol = r_str_tok_r (NULL, "\n", &save_ptr);
	}
	free (data);
}

typedef struct {
	RCore *core;
	char *prj_name;
	char *rc_path;
} ProjectState;

// extract the binary file path from the "o " line in the project rc script data
static char *project_extract_file(const char *rc_data) {
	const char *line = strstr (rc_data, "\no \"");
	if (line) {
		line += 4; // skip \no "
		const char *end = strchr (line, '"');
		if (end) {
			return r_str_ndup (line, end - line);
		}
	}
	return NULL;
}

typedef struct {
	RCore *core;
	const char *data;
} ProjectScript;

static void *project_run_script(void *user) {
	ProjectScript *script = user;
	return r_core_cmd_lines (script->core, script->data)? user: NULL;
}

static bool r_core_project_load(RCore *core, const char *prj_name, const char *rcpath) {
	if (!core || R_STR_ISEMPTY (prj_name) || !rcpath) {
		return false;
	}
	const bool sandbox = r_sandbox_enable (false);
	const bool cfg_fortunes = r_config_get_b (core->config, "cfg.fortunes");
	const bool scr_interactive = r_cons_is_interactive (core->cons);
	const bool scr_prompt = r_config_get_b (core->config, "scr.prompt");
	char *prj_path = r_file_dirname (rcpath);
	bool ret = false;
	if (!sandbox && r_config_get_b (core->config, "prj.new")) {
		char *prj_bin = prj_path? r_file_new (prj_path, "prj.bin", NULL): NULL;
		bool exists = prj_bin && r_file_exists (prj_bin);
		if (exists) {
			ret = r_core_cmdf (core, "prj load %s", prj_bin) != -1;
		} else {
			R_LOG_WARN ("Binary project '%s' not found; falling back to legacy script", prj_bin? prj_bin: "prj.bin");
		}
		free (prj_bin);
		if (exists) {
			goto loaded;
		}
	}

	char *rc_data = r_file_slurp (rcpath, NULL);
	if (!rc_data || !r_str_startswith (rc_data, "# r2 rdb project file")) {
		R_LOG_ERROR ("Cannot read project script '%s'", rcpath);
		free (rc_data);
		free (prj_path);
		return false;
	}
	char *prj_file = sandbox? NULL: project_extract_file (rc_data);
	if (prj_file && !strstr (prj_file, "://") && !r_file_exists (prj_file)) {
		R_LOG_ERROR ("File associated with the project is missing: %s", prj_file);
		if (r_config_get_b (core->config, "prj.prompt") && scr_interactive) {
			char *prompt = r_str_newf ("New path for '%s': ", prj_file);
			char *new_path = r_cons_input (core->cons, prompt);
			free (prompt);
			if (R_STR_ISNOTEMPTY (new_path)) {
				char *old_o_line = r_str_newf ("o \"%s\"", prj_file);
				char *new_o_line = r_str_newf ("o \"%s\"", new_path);
				rc_data = r_str_replace (rc_data, old_o_line, new_o_line, 0);
				free (old_o_line);
				free (new_o_line);
			}
			free (new_path);
		}
	}
	free (prj_file);
	if (sandbox) {
		char *line = rc_data, *out = rc_data;
		while (*line) {
			char *next = strchr (line, '\n');
			size_t len = next? next + 1 - line: strlen (line);
			// Reuse the current binary instead of replaying generated I/O commands.
			if (*line != 'o' && !r_str_startswith (line, "'e prj.name = ")) {
				memmove (out, line, len);
				out += len;
			}
			line += len;
		}
		*out = 0;
		if (core->prj->rvc) {
			rvc_close (core->prj->rvc, false);
			core->prj->rvc = NULL;
		}
	}
	ProjectScript script = { core, rc_data };
	ret = r_config_get_b (core->config, "prj.sandbox")
		? r_sandbox_run (R_SANDBOX_GRAIN_DISK | R_SANDBOX_GRAIN_FILES, project_run_script, &script) != NULL
		: r_core_cmd_lines (core, rc_data);
	free (rc_data);
loaded:
	r_config_set_b (core->config, "cfg.fortunes", cfg_fortunes);
	r_config_set_b (core->config, "scr.interactive", scr_interactive);
	r_config_set_b (core->config, "scr.prompt", scr_prompt);
	r_config_bump (core->config, "asm.arch");
	if (ret) {
		r_config_set (core->config, "prj.name", prj_name);
		ret = !strcmp (r_config_get (core->config, "prj.name"), prj_name);
	}
	if (ret) {
		free (core->prj->path);
		core->prj->path = prj_path;
		prj_path = NULL;
		if (!sandbox) {
			core->prj->rvc = rvc_open (core->prj->path, RVC_TYPE_GIT);
			if (r_config_get_b (core->config, "prj.history")) {
				char *file = r_file_new (core->prj->path, "history", NULL);
				r_line_hist_free (core->cons->line);
				r_line_hist_load (core->cons->line, file);
				free (file);
			}
		}
	}
	free (prj_path);
	return ret;
}

static RThreadFunctionRet project_load_background(RThread *th) {
	ProjectState *ps = th->user;
	r_core_project_load (ps->core, ps->prj_name, ps->rc_path);
	free (ps->prj_name);
	free (ps->rc_path);
	free (ps);
	return R_TH_STOP;
}

R_API RThread *r_core_project_load_bg(RCore *core, const char *prj_name, const char *rc_path) {
	R_RETURN_VAL_IF_FAIL (core && rc_path, NULL);
	ProjectState *ps = R_NEW0 (ProjectState);
	ps->core = core;
	ps->prj_name = r_core_project_name (core, R_STR_ISNOTEMPTY (prj_name)? prj_name: rc_path);
	ps->rc_path = strdup (rc_path);
	RThread *th = r_th_new (project_load_background, ps, false);
	if (th) {
		r_th_start (th);
		char thname[32] = {0};
		size_t thlen = R_MIN (strlen (r_str_get (prj_name)), sizeof (thname) - 1);
		r_str_ncpy (thname, r_str_get (prj_name), thlen);
		r_th_setname (th, thname);
	}
	return th;
}

R_API bool r_core_project_open(RCore *core, const char *prj_path) {
	R_RETURN_VAL_IF_FAIL (core && !R_STR_ISEMPTY (prj_path), false);
	const bool sandbox = r_sandbox_enable (false);
	if (sandbox && !core->io->desc) {
		R_LOG_ERROR ("Open a binary before loading a sandboxed project");
		return false;
	}
	char *prj_name = r_core_project_name (core, prj_path);
	char *prj_script = get_project_script_path (core, prj_path);
	bool ret = false;
	if (!prj_name || !prj_script) {
		R_LOG_ERROR ("Invalid project name '%s'", prj_path);
		goto beach;
	}
	if (!sandbox) {
		if (r_project_is_loaded (core->prj) && r_config_get_b (core->config, "scr.interactive")
				&& !r_cons_yesno (core->cons, 'y', "Close current session? (Y/n)")) {
			goto beach;
		}
		r_config_set (core->config, "prj.name", "");
		r_core_cmd0 (core, "o--");
	}
	ret = r_core_project_load (core, prj_name, prj_script);
	if (ret) {
		r_core_project_undirty (core);
	}
beach:
	free (prj_name);
	free (prj_script);
	return ret;
}

static char *get_project_name(const char *prj_script) {
	const char *prefix = "'e prj.name = ";
	char buf[1024];
	char *file = NULL;
	FILE *fd = r_sandbox_fopen (prj_script, "r");
	if (fd) {
		while (fgets (buf, sizeof (buf), fd)) {
			if (!r_str_startswith (buf, prefix)) {
				continue;
			}
			file = r_str_trim_dup (buf + strlen (prefix));
			break;
		}
		fclose (fd);
	} else {
		R_LOG_ERROR ("Cannot open project info (%s)", prj_script);
	}
	return file;
}

R_API char *r_core_project_name(RCore *core, const char *prjfile) {
	if (*prjfile != '/') {
		return strdup (prjfile);
	}
	char *prj = get_project_script_path (core, prjfile);
	if (!prj) {
		R_LOG_ERROR ("Invalid project name '%s'", prjfile);
		return NULL;
	}
	char *file = get_project_name (prj);
	free (prj);
	if (R_STR_ISEMPTY (file)) {
		free (file);
		file = strdup (prjfile);
		char *slash = (char *)r_str_lchr (file, R_SYS_DIR[0]);
		if (slash) {
			*slash = 0;
			slash = (char *)r_str_lchr (file, R_SYS_DIR[0]);
			if (slash) {
				char *res = strdup (slash + 1);
				free (file);
				file = res;
			} else {
				R_FREE (file);
			}
		} else {
			R_FREE (file);
		}
	}
	return file;
}

static void flush(RCore *core, RStrBuf *sb) {
	char *s = r_cons_drain (core->cons, NULL);
	if (s) {
		r_strbuf_append (sb, s);
		free (s);
	}
}

static bool project_save_script(RCore *core, const char *file, int opts, const char *prj_name) {
	RConfig *config = prj_name? r_config_clone (core->config): core->config;
	if (!config) {
		return false;
	}
	if (prj_name) {
		r_config_set_setter (config, "prj.name", NULL);
		if (!r_config_set (config, "prj.name", prj_name)
				|| strcmp (r_config_get (config, "prj.name"), prj_name)) {
			r_config_free (config);
			return false;
		}
	}
	r_cons_push (core->cons);
	char *ohl = NULL;
	char *hl = core->cons->highlight;
	if (hl) {
		ohl = strdup (hl);
		r_cons_highlight (core->cons, NULL);
	}
	RStrBuf *sb = r_strbuf_new ("");
	const bool was_interactive = core->cons->context->is_interactive;
	core->cons->context->is_interactive = false;
	RCons *cons = core->cons;
	r_cons_printf (cons, "# r2 rdb project file\n");
	// new behaviour to project load routine (see io maps below).
	if (opts & R_CORE_PRJ_EVAL) {
		r_cons_printf (core->cons, "# eval\n");
		char *res = r_config_list (config, NULL, 'r');
		r_cons_println (core->cons, res);
		free (res);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_IO_MAPS) {
		r_core_cmd (core, "o*", 0);
		r_core_cmd (core, "om*", 0);
		r_cons_printf (cons, "o=%d\n", core->io->desc->fd);
		flush (core, sb);
	}
	r_core_cmd0 (core, "tcc*");
	if (opts & R_CORE_PRJ_FCNS) {
		r_cons_printf (cons, "# functions\n");
		r_cons_printf (cons, "fs functions\n");
		r_core_cmd (core, "afl*", 0);
		flush (core, sb);
	}
	{
		r_cons_printf (cons, "# registers\n");
		r_core_cmd (core, "ar*", 0);
		flush (core, sb);
		r_core_cmd (core, "arR", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_FLAGS) {
		r_cons_printf (cons, "# flags\n");
		r_flag_space_push (core->flags, NULL);
		char *s = r_flag_list (core->flags, true, NULL);
		r_cons_printf (cons, "%s", s);
		free (s);
		r_flag_space_pop (core->flags);
		flush (core, sb);
		r_core_cmd (core, "fz*", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_META) {
		r_cons_printf (cons, "# meta\n");
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 1, NULL, NULL);
		flush (core, sb);
		r_core_cmd (core, "fv*", 0);
		flush (core, sb);
		r_core_cmd (core, "ano*@@@F", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_XREFS) {
		r_core_cmd (core, "ax*", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_FLAGS) {
		r_core_cmd (core, "f.**", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_DBG_BREAK) {
		r_core_cmd (core, "db*", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_ANAL_HINTS) {
		r_core_cmd (core, "ah*", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_ANAL_TYPES) {
		r_cons_println (cons, "# types");
		r_core_cmd (core, "t*", 0);
		flush (core, sb);
	}
	if (opts & R_CORE_PRJ_ANAL_MACROS) {
		r_cons_println (cons, "# macros");
		r_core_cmd (core, "(*", 0);
		r_cons_println (cons, "# aliases");
		r_core_cmd (core, "$*", 0);
		flush (core, sb);
	}
	r_core_cmd (core, "wc*", 0);
	if (opts & R_CORE_PRJ_ANAL_SEEK) {
		r_cons_printf (cons, "# seek\n" "s 0x%08" PFMT64x "\n", core->addr);
		flush (core, sb);
	}
	core->cons->context->is_interactive = was_interactive;
	flush (core, sb);
	if (ohl) {
		r_cons_highlight (cons, ohl);
		free (ohl);
	}
	if (prj_name) {
		r_config_free (config);
	}
	char *s = r_strbuf_drain (sb);
	r_cons_pop (core->cons);
	if (!s) {
		return false;
	}
	char *filename = r_str_word_get_first (file);
	bool ret = true;
	if (!strcmp (filename, "/dev/stdout")) {
		r_cons_printf (core->cons, "%s\n", s);
	} else {
		ret = r_file_dump (filename, (const ut8*)s, strlen (s), 0);
		if (!ret) {
			R_LOG_ERROR ("Cannot save file");
		}
	}
	free (s);
	free (filename);
	return ret;
}

R_API bool r_core_project_save_script(RCore *core, const char *file, int opts) {
	R_RETURN_VAL_IF_FAIL (core && file, false);
	return R_STR_ISNOTEMPTY (file) && project_save_script (core, file, opts, NULL);
}

static void r_core_project_zip(RCore *core, const char *prj_dir) {
	char *cwd = r_sys_getdir ();
	const char *prj_name = r_file_basename (prj_dir);
	if (r_sys_chdir (prj_dir)) {
		if (!strchr (prj_name, '\'')) {
			r_sys_chdir ("..");
			char *zipfile = r_str_newf ("%s.zip", prj_name);
			r_file_rm (zipfile);
			// XXX use the ZIP api instead!
			char *ezip = r_str_escape_sh (zipfile);
			char *ename = r_str_escape_sh (prj_name);
			r_sys_cmdf ("zip -r \"%s\" \"%s\"", ezip, ename);
			free (ezip);
			free (ename);
			free (zipfile);
		} else {
			R_LOG_WARN ("Command injection attempt?");
		}
	} else {
		R_LOG_ERROR ("Cannot chdir %s", prj_dir);
	}
	r_sys_chdir (cwd);
	free (cwd);
}

R_API bool r_core_project_save(RCore *core, const char *prj_name) {
	R_RETURN_VAL_IF_FAIL (R_STR_ISNOTEMPTY (prj_name), false);
	bool scr_null = false;
	bool ret = true;

	if (r_config_get_b (core->config, "cfg.debug")) {
		R_LOG_ERROR ("radare2 does not support projects on debugged bins");
		return false;
	}
	if (!core->io->desc) {
		R_LOG_ERROR ("Open a binary before saving a project");
		return false;
	}
	char *script_path = get_project_script_path (core, prj_name);
	if (!script_path) {
		R_LOG_ERROR ("Invalid project name '%s'", prj_name);
		return false;
	}
	char *prj_dir = r_str_endswith (script_path, R_SYS_DIR "rc.r2")
		? r_file_dirname (script_path)
		: r_str_newf ("%s.d", script_path);
	if (!prj_dir) {
		prj_dir = strdup (prj_name);
	}
	if (r_core_is_project (core, prj_name) && strcmp (prj_name, r_config_get (core->config, "prj.name"))) {
		R_LOG_ERROR ("A project with this name already exists. Use P-%s to delete it", prj_name);
		free (script_path);
		free (prj_dir);
		return false;
	}
	if (!r_sys_mkdirp (prj_dir)) {
		free (script_path);
		free (prj_dir);
		return false;
	}
	if (r_config_get_b (core->config, "scr.null")) {
		r_config_set_b (core->config, "scr.null", false);
		scr_null = true;
	}

	if (!project_save_script (core, script_path, R_CORE_PRJ_ALL, prj_name)) {
		R_LOG_ERROR ("Cannot open '%s' project name", prj_name);
		ret = false;
		goto beach;
	}
	const bool sandbox = r_sandbox_enable (false);
	if (sandbox && core->prj->rvc) {
		rvc_close (core->prj->rvc, false);
		core->prj->rvc = NULL;
	}
	r_config_set (core->config, "prj.name", prj_name);
	if (strcmp (r_config_get (core->config, "prj.name"), prj_name)) {
		ret = false;
		goto beach;
	}
	if (sandbox) {
		goto saved;
	}
	if (r_config_get_b (core->config, "prj.new")) {
		char *prj_file = r_file_new (prj_dir, "prj.bin", NULL);
		r_file_rm (prj_file);
		r_core_cmdf (core, "prj save %s", prj_file);
		if (!r_file_exists (prj_file)) {
			// the binary project is an optional artifact, the rc.r2 script is already saved
			R_LOG_WARN ("Cannot create binary project '%s', the project script was saved", prj_file);
		}
		free (prj_file);
	}

	if (r_config_get_b (core->config, "prj.files")) {
		char *bin_file = r_core_project_name (core, prj_name);
		char *cur_filename = r_core_cmd_str (core, "o.");
		r_str_trim (cur_filename);
		const char *cur_filename2 = r_file_basename (cur_filename);
		char *prj_bin_dir = r_str_newf ("%s" R_SYS_DIR "bin", prj_dir);
		char *prj_bin_file = r_str_newf ("%s" R_SYS_DIR "%s", prj_bin_dir, cur_filename2);
		r_sys_mkdirp (prj_bin_dir);
		if (!r_file_copy (cur_filename, prj_bin_file)) {
			R_LOG_WARN ("prj.files: Cannot copy '%s' into '%s'", cur_filename, prj_bin_file);
		}
		free (prj_bin_file);
		free (prj_bin_dir);
		free (cur_filename);
		free (bin_file);
	}
	if (core->prj->rvc || r_config_get_b (core->config, "prj.vc")) {
		// version control is a secondary step, a failure here must not
		// discard the project script that was already saved on disk
		// assume that if the repo is not loaded, the repo doesn't exist
		if (!core->prj->rvc) {
			core->prj->rvc = rvc_open (prj_dir, RVC_TYPE_GIT);
		}
		if (!core->prj->rvc) {
			R_LOG_WARN ("Cannot initialize the version control repository, project saved without versioning");
		} else {
			RList *paths = r_list_new ();
			if (paths && r_list_append (paths, prj_dir)) {
				const char *author = r_config_get (core->config, "cfg.user");
				const char *message = r_config_get (core->config, "prj.vc.message");
				if (rvc_commit (core->prj->rvc, message, author, paths)) {
					rvc_save (core->prj->rvc);
				} else {
					// commit fails when there's nothing new to commit, which is not a save error
					R_LOG_WARN ("Nothing to commit or version control commit failed, project saved anyway");
				}
			}
			r_list_free (paths);
		}
	}
	if (r_config_get_b (core->config, "prj.history")) {
		char *history = r_core_cmd_str (core, "!!");
		char *file = r_file_new (prj_dir, "history", NULL);
		r_file_dump (file, (const ut8*)history, -1, false);
		free (file);
		free (history);
	}
	if (r_config_get_b (core->config, "prj.zip")) {
		r_core_project_zip (core, prj_dir);
	}
saved:
	free (core->prj->path);
	core->prj->path = prj_dir;
	prj_dir = NULL;
beach:
	if (scr_null) {
		r_config_set_b (core->config, "scr.null", true);
	}
	free (script_path);
	free (prj_dir);
	if (ret) {
		r_core_project_undirty (core);
	}
	return ret;
}

// dirty bits

R_API char *r_core_project_notes_file(RCore *core, const char *prj_name) {
	const char *prjdir = r_config_get (core->config, "dir.projects");
	char *prjpath = r_file_abspath (prjdir);
	char *notes_txt = r_file_new (prjpath, prj_name, "notes.txt", NULL);
	char *link = notes_txt? r_file_readlink (notes_txt): NULL;
	char *ndir = notes_txt? r_file_dirname (notes_txt): NULL;
	if ((link && strcmp (link, notes_txt)) || !ndir || !project_path_is_within_projects_dir (core, ndir)) {
		R_FREE (notes_txt);
	}
	free (ndir);
	free (link);
	free (prjpath);
	return notes_txt;
}

R_API bool r_core_project_is_dirty(RCore *core) {
	return !R_DIRTY_CHECK (core->config) && !R_DIRTY_CHECK (core->anal) && !R_DIRTY_CHECK (core->flags);
}

R_API void r_core_project_undirty(RCore *core) {
	R_CRITICAL_ENTER (core);
	core->config->is_dirty = false;
	core->anal->is_dirty = false;
	core->flags->is_dirty = false;
	R_CRITICAL_LEAVE (core);
}
