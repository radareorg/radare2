/* radare - LGPL - Copyright 2010-2025 - pancake, rhl */

// R2R db/cmd/projects

#include <r_core.h>
#include <rvc.h>
// required to make spp use RStrBuf instead of SStrBuf
#define USE_R2 1
#include <spp/spp.h>

// project apis to be used from cmd_project.c
// TODO: Use .zrp as in zipped radare project

static bool is_valid_project_name(const char *name) {
	if (r_str_len_utf8 (name) >= 64) {
		return false;
	}
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
	R_RETURN_VAL_IF_FAIL (core && file, NULL);
	if (!*file) {
		return NULL;
	}
	const char *magic = "# r2 rdb project file";
	char *data, *prjfile;
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
	data = r_file_slurp (prjfile, NULL);
	if (data) {
		if (!r_str_startswith (data, magic)) {
			R_FREE (prjfile);
		}
	}
	free (data);
	return prjfile;
}

static int make_projects_directory(RCore *core) {
	char *prjdir = r_file_abspath (r_config_get (core->config, "dir.projects"));
	int ret = r_sys_mkdirp (prjdir);
	if (!ret) {
		R_LOG_ERROR ("Cannot mkdir dir.projects");
	}
	free (prjdir);
	return ret;
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
	PJ *pj = NULL;
	RListIter *iter;

	char *foo, *path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	if (!path) {
		return 0;
	}
	RList *list = r_sys_dir (path);
	switch (mode) {
	case 'j':
		pj = r_core_pj_new (core);
		if (!pj) {
			break;
		}
		pj_a (pj);
		r_list_foreach (list, iter, foo) {
			// todo. escape string
			if (r_core_is_project (core, foo)) {
				pj_s (pj, foo);
			}
		}
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
		break;
	default:
		r_list_foreach (list, iter, foo) {
			if (r_core_is_project (core, foo)) {
				r_cons_println (core->cons, foo);
			}
		}
		break;
	}
	r_list_free (list);
	free (path);
	return 0;
}

R_API int r_core_project_delete(RCore *core, const char *prjfile) {
	RCons *cons = core->cons;
	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("Cannot delete project in sandbox mode");
		return 0;
	}
	char *path = get_project_script_path (core, prjfile);
	if (!path) {
		R_LOG_ERROR ("Invalid project name '%s'", prjfile);
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

static bool load_project_rop(RCore *core, const char *prjfile) {
	R_RETURN_VAL_IF_FAIL (core && R_STR_ISNOTEMPTY (prjfile), false);
	char *path, *db = NULL, *path_ns;
	bool found = 0;
	SdbListIter *it;
	SdbNs *ns;

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	Sdb *nop_db = sdb_ns (rop_db, "nop", false);
	Sdb *mov_db = sdb_ns (rop_db, "mov", false);
	Sdb *const_db = sdb_ns (rop_db, "const", false);
	Sdb *arithm_db = sdb_ns (rop_db, "arithm", false);
	Sdb *arithmct_db = sdb_ns (rop_db, "arithm_ct", false);

	char *rc_path = get_project_script_path (core, prjfile);
	char *prj_dir = r_file_dirname (rc_path);
	R_FREE (rc_path);
	if (r_str_endswith (prjfile, R_SYS_DIR "rc.r2")) {
		path = strdup (prjfile);
		path[strlen (path) - 3] = 0;
	} else if (r_file_fexists ("%s%s%src.r2", R_SYS_DIR, prj_dir, prjfile)) {
		path = r_str_newf ("%s%s%s", R_SYS_DIR, prj_dir, prjfile);
	} else {
		if (*prjfile == R_SYS_DIR[0]) {
			db = r_str_newf ("%s.d", prjfile);
			if (!db) {
				free (prj_dir);
				return false;
			}
			path = strdup (db);
		} else {
			db = r_str_newf ("%s" R_SYS_DIR "%s.d", prj_dir, prjfile);
			if (!db) {
				free (prj_dir);
				return false;
			}
			path = r_file_abspath (db);
		}
	}
	if (!path) {
		free (db);
		free (prj_dir);
		return false;
	}
	if (rop_db) {
		ls_foreach (core->sdb->ns, it, ns) {
			if (ns->sdb == rop_db) {
				ls_delete (core->sdb->ns, it);
				found = true;
				break;
			}
		}
	}
	if (!found) {
		sdb_free (rop_db);
	}
	rop_db = sdb_new (path, "rop", 0);
	if (!rop_db) {
		free (db);
		free (path);
		free (prj_dir);
		return false;
	}
	sdb_ns_set (core->sdb, "rop", rop_db);

	path_ns = r_str_newf ("%s" R_SYS_DIR "rop", prj_dir);
	if (!r_file_exists (path_ns)) {
		path_ns = r_str_append (path_ns, ".sdb");
	}
	nop_db = sdb_new (path_ns, "nop", 0);
	sdb_ns_set (rop_db, "nop", nop_db);

	mov_db = sdb_new (path_ns, "mov", 0);
	sdb_ns_set (rop_db, "mov", mov_db);

	const_db = sdb_new (path_ns, "const", 0);
	sdb_ns_set (rop_db, "const", const_db);

	arithm_db = sdb_new (path_ns, "arithm", 0);
	sdb_ns_set (rop_db, "arithm", arithm_db);

	arithmct_db = sdb_new (path_ns, "arithm_ct", 0);
	sdb_ns_set (rop_db, "arithm_ct", arithmct_db);

	free (path);
	free (path_ns);
	free (db);
	free (prj_dir);
	return true;
}

R_API void r_core_project_execute_cmds(RCore *core, const char *prjfile) {
	char *str = r_core_project_notes_file (core, prjfile);
	char *data = r_file_slurp (str, NULL);
	free (str);
	R_RETURN_IF_FAIL (data);
	Output out;
	out.fout = NULL;
	out.cout = r_strbuf_new (NULL);
	r_strbuf_init (out.cout);
	struct Proc proc;
	spp_proc_set (&proc, "spp", 1);
	spp_eval (data, &out);
	free (data);
	data = strdup (r_strbuf_get (out.cout));
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

static bool r_core_project_load(RCore *core, const char *prj_name, const char *rcpath) {
	R_RETURN_VAL_IF_FAIL (core, false);
	if (R_STR_ISEMPTY (prj_name)) {
		prj_name = r_core_project_name (core, rcpath);
	}
	if (r_project_is_loaded (core->prj)) {
		R_LOG_INFO ("o--;e prj.name=");
	//	return false;
	}
	if (!r_project_open (core->prj, prj_name, rcpath)) {
		return false;
	}
	const bool cfg_fortunes = r_config_get_b (core->config, "cfg.fortunes");
	const bool scr_interactive = r_cons_is_interactive (core->cons);
	const bool scr_prompt = r_config_get_b (core->config, "scr.prompt");
	(void) load_project_rop (core, prj_name);
	const bool sandy = r_config_get_b (core->config, "prj.sandbox");
	bool ret = false;
	if (sandy) {
		// enable sandbox (only allow file access, no network or program exec)
		// projects can also tweak the cmd. eval vars to run code after the project is loaded
		// users must be careful on that.
		int oldgrain = r_sandbox_grain (R_SANDBOX_GRAIN_DISK | R_SANDBOX_GRAIN_FILES);
		r_sandbox_enable (true);
		ret = r_core_cmd_file (core, rcpath);
		r_sandbox_disable (true);
		r_sandbox_grain (oldgrain);
	} else {
		ret = r_core_cmd_file (core, rcpath);
	}
	char *prj_path = r_file_dirname (rcpath);
	if (prj_path) {
		//check if the project uses git
		Rvc *vc = rvc_open (prj_path, RVC_TYPE_GIT);
		core->prj->rvc = vc;
	} else {
		R_LOG_ERROR ("Failed to load rvc");
	}
	if (r_config_get_b (core->config, "prj.history")) {
		char *file = r_file_new (prj_path, "history", NULL);
		r_line_hist_free (core->cons->line); // R2_600 - hist_reset ?
		r_line_hist_load (core->cons->line, file);
		free (file);
	}
	free (prj_path);
	r_config_set_b (core->config, "cfg.fortunes", cfg_fortunes);
	r_config_set_b (core->config, "scr.interactive", scr_interactive);
	r_config_set_b (core->config, "scr.prompt", scr_prompt);
	r_config_bump (core->config, "asm.arch");
	r_config_set (core->config, "prj.name", prj_name);
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
	ProjectState *ps = R_NEW0 (ProjectState);
	ps->core = core;
	ps->prj_name = strdup (prj_name);
	ps->rc_path = strdup (rc_path);
	RThread *th = r_th_new (project_load_background, ps, false);
	if (th) {
		r_th_start (th);
		char thname[32] = {0};
		size_t thlen = R_MIN (strlen (prj_name), sizeof (thname) - 1);
		r_str_ncpy (thname, prj_name, thlen);
		r_th_setname (th, thname);
	}
	return th;
}

R_API bool r_core_project_open(RCore *core, const char *prj_path) {
	RCons *cons = core->cons;
	R_RETURN_VAL_IF_FAIL (core && !R_STR_ISEMPTY (prj_path), false);
	bool interactive = r_config_get_b (core->config, "scr.interactive");
	bool close_current_session = true;
	bool ask_for_closing = true;
	if (r_project_is_loaded (core->prj)) {
		R_LOG_ERROR ("There's a project already opened");
		ask_for_closing = false;
		bool ccs = interactive? r_cons_yesno (cons, 'y', "Close current session? (Y/n)"): true;
		if (!ccs) {
			R_LOG_ERROR ("Project not loaded");
			return false;
		}
		r_core_cmd0 (core, "o--");
		r_core_cmd0 (core, "P-");
	}
	char *prj_name = r_core_project_name (core, prj_path);
	char *prj_script = get_project_script_path (core, prj_path);
	if (!prj_script) {
		R_LOG_ERROR ("Invalid project name '%s'", prj_path);
		return false;
	}
	if (ask_for_closing && r_project_is_loaded (core->prj)) {
		if (r_cons_is_interactive (core->cons)) {
			close_current_session = interactive
				? r_cons_yesno (cons, 'y', "Close current session? (Y/n)")
				: true;
		}
	}
	if (close_current_session) {
		r_config_set (core->config, "prj.name", "");
		r_core_cmd0 (core, "o--");
	}
	/* load sdb stuff in here */
	bool ret = r_core_project_load (core, prj_name, prj_script);
	free (prj_name);
	free (prj_script);
	if (ret) {
		r_core_project_undirty (core);
	}
	return ret;
}

static char *get_project_name(const char *prj_script) {
	char buf[1024];
	char *file = NULL;
	FILE *fd = r_sandbox_fopen (prj_script, "r");
	if (fd) {
		for (;;) {
			if (!fgets (buf, sizeof (buf), fd)) {
				break;
			}
			if (feof (fd)) {
				break;
			}
			if (r_str_startswith (buf, "\"\"e prj.name = ")) {
				file = strdup (buf + strlen ("\"\"e prj.name"));
				break;
			}
			if (r_str_startswith (buf, "\"e prj.name = ")) {
				// if (!strncmp (buf, "\"e prj.name = ", 14))
				buf[strlen (buf) - 2] = 0; // remove trailing '"'
				file = strdup (buf + 14);
				break;
			}
			if (r_str_startswith (buf, "'e prj.name = ")) {
				file = strdup (buf + strlen ("'e prj.name"));
				break;
			}
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
	char * s = r_cons_drain (core->cons);
	if (s) {
		r_strbuf_append (sb, s);
		free (s);
	}
}

R_API bool r_core_project_save_script(RCore *core, const char *file, int opts) {
	R_RETURN_VAL_IF_FAIL (core && file, false);
	if (R_STR_ISEMPTY (file)) {
		return false;
	}

	char *filename = r_str_word_get_first (file);
	char *ohl = NULL;
	char *hl = core->cons->highlight;
	if (hl) {
		ohl = strdup (hl);
		r_cons_highlight (core->cons, NULL);
	}
	RStrBuf *sb = r_strbuf_new ("");
	core->cons->context->is_interactive = false;
	RCons *cons = core->cons;
	r_cons_printf (cons, "# r2 rdb project file\n");
	// new behaviour to project load routine (see io maps below).
	if (opts & R_CORE_PRJ_EVAL) {
		r_cons_printf (core->cons, "# eval\n");
		char *res = r_config_list (core->config, NULL, 'r');
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
		r_core_cmd (core, "fV*", 0);
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
	core->cons->context->is_interactive = true;
	flush (core, sb);
	char *s = r_strbuf_drain (sb);
	if (!strcmp (filename, "/dev/stdout")) {
		r_cons_printf (cons, "%s\n", s);
	} else {
		if (!r_file_dump (filename, (const ut8*)s, strlen (s), 0)) {
			R_LOG_ERROR ("Cannot save file");
		}
	}
	free (s);

	if (ohl) {
		r_cons_highlight (cons, ohl);
		free (ohl);
	}
	free (filename);

	return true;
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
			r_sys_cmdf ("zip -r %s %s", zipfile, prj_name);
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
	SdbListIter *it;
	SdbNs *ns;

	if (r_config_get_b (core->config, "cfg.debug")) {
		R_LOG_ERROR ("radare2 does not support projects on debugged bins");
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
	if (r_file_exists (script_path)) {
		if (r_file_is_directory (script_path)) {
			R_LOG_ERROR ("Structural error: rc.r2 shouldnt be a directory");
		}
	}
	if (!prj_dir) {
		prj_dir = strdup (prj_name);
	}
	if (r_core_is_project (core, prj_name) && strcmp (prj_name, r_config_get (core->config, "prj.name"))) {
		R_LOG_ERROR ("A project with this name already exists. Use P-%s to delete it", prj_name);
		free (script_path);
		free (prj_dir);
		return false;
	}
	if (!r_file_is_directory (prj_dir)) {
		r_sys_mkdirp (prj_dir);
	}
	if (r_config_get_b (core->config, "scr.null")) {
		r_config_set_b (core->config, "scr.null", false);
		scr_null = true;
	}
	make_projects_directory (core);

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	if (rop_db) {
		/* set filepath for all the rop sub-dbs */
		ls_foreach (rop_db->ns, it, ns) {
			char *rop_path = r_str_newf ("%s" R_SYS_DIR "rop.d" R_SYS_DIR "%s", prj_dir, ns->name);
			sdb_file (ns->sdb, rop_path);
			sdb_sync (ns->sdb);
			free (rop_path);
		}
	}

	r_config_set (core->config, "prj.name", prj_name);
	if (!r_core_project_save_script (core, script_path, R_CORE_PRJ_ALL)) {
		R_LOG_ERROR ("Cannot open '%s' project name", prj_name);
		ret = false;
		r_config_set (core->config, "prj.name", "");
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
		// assume that if the repo is not loaded, the repo doesn't exist
		if (!core->prj->rvc) {
			core->prj->rvc = rvc_open (prj_dir, RVC_TYPE_GIT);
			if (!core->prj->rvc) {
				R_LOG_WARN ("Cannot initialize git repositorty");
				free (prj_dir);
				free (script_path);
				return false;
			}
		}
		RList *paths = r_list_new ();
		if (paths) {
			if (r_list_append (paths, prj_dir)) {
				const char *author = r_config_get (core->config, "cfg.user");
				const char *message = r_config_get (core->config, "prj.vc.message");
				if (!rvc_commit (core->prj->rvc, message, author, paths)) {
					r_list_free (paths);
					free (prj_dir);
					free (script_path);
					return false;
				}
				rvc_save (core->prj->rvc);
			} else {
				r_list_free (paths);
				free (prj_dir);
				free (script_path);
				return false;
			}
		} else {
			free (prj_dir);
			free (script_path);
			return false;
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
	// LEAK : not always in heap free (prj_name);
	free (core->prj->path);
	core->prj->path = prj_dir;
	if (scr_null) {
		r_config_set_b (core->config, "scr.null", true);
	}
	free (script_path);
	r_config_set (core->config, "prj.name", prj_name);
	r_core_project_undirty (core);
	return ret;
}

// dirty bits

R_API char *r_core_project_notes_file(RCore *core, const char *prj_name) {
	const char *prjdir = r_config_get (core->config, "dir.projects");
	char *prjpath = r_file_abspath (prjdir);
	char *notes_txt = r_file_new (prjpath, prj_name, "notes.txt", NULL);
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
