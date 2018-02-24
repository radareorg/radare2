/* radare - LGPL - Copyright 2010-2017 - pancake, maijin */

#include <r_types.h>
#include <r_list.h>
#include <r_flag.h>
#include <r_core.h>
#include <spp/spp.h>

#if 0
static void __section_list_for_projects (RIO *io, RPrint *print) {
	int i = 0;
	SdbListIter *iter;
	RIOSection *s;

	if (!io || !io->sections || !print || !print->cb_printf) {
		return;
	}
	ls_foreach (io->sections, iter, s) {	
		print->cb_printf ("[%02d] 0x%08"PFMT64x" %s va=0x%08"PFMT64x
			" sz=0x%04"PFMT64x" vsz=0x%04"PFMT64x" %s",
			i, s->paddr, r_str_rwx_i (s->flags), s->vaddr,
			s->size, s->vsize, s->name);
		if (s->arch && s->bits) {
			print->cb_printf ("  ; %s %d", r_sys_arch_str (s->arch),
				s->bits);
		}
		print->cb_printf ("\n");
		i++;
	}
}
#endif

static bool is_valid_project_name(const char *name) {
	int i;
	if (r_str_endswith (name, ".zip")) {
		return false;
	}
	for (i = 0; name[i]; i++) {
		switch (name[i]) {
		case '\\': // for w32
		case '.':
		case '_':
		case ':':
		case '-':
			continue;
		}
		if (name[i] >= 'a' && name[i] <= 'z') {
			continue;
		}
		if (name[i] >= 'A' && name[i] <= 'Z') {
			continue;
		}
		if (IS_DIGIT (name[i])) {
			continue;
		}
		return false;
	}
	return true;
}

static char *projectScriptPath(RCore *core, const char *file) {
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
			prjfile = r_str_append (prjfile, R_SYS_DIR "rc");
		}
	}
	data = r_file_slurp (prjfile, NULL);
	if (data) {
		if (strncmp (data, magic, strlen (magic))) {
			R_FREE (prjfile);
		}
	}
	free (data);
	return prjfile;
}

static int projectInit(RCore *core) {
	char *prjdir = r_file_abspath (r_config_get (core->config, "dir.projects"));
	int ret = r_sys_mkdirp (prjdir);
	if (!ret) {
		eprintf ("Cannot mkdir dir.projects\n");
	}
	free (prjdir);
	return ret;
}

R_API bool r_core_is_project(RCore *core, const char *name) {
	bool ret = false;
	if (name && *name && *name != '.') {
		char *path = projectScriptPath (core, name);
		if (!path) {
			return false;
		}
		if (r_str_endswith (path, R_SYS_DIR "rc") && r_file_exists (path)) {
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

R_API int r_core_project_cat(RCore *core, const char *name) {
	char *path = projectScriptPath (core, name);
	if (path) {
		char *data = r_file_slurp (path, NULL);
		if (data) {
			r_cons_println (data);
			free (data);
		}
	}
	free (path);
	return 0;
}

R_API int r_core_project_list(RCore *core, int mode) {
	RListIter *iter;
	RList *list;
	bool isfirst = true;

	char *foo, *path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	if (!path) {
		return 0;
	}
	list = r_sys_dir (path);
	switch (mode) {
	case 'j':
		r_cons_printf ("[");
		r_list_foreach (list, iter, foo) {
			// todo. escape string
			if (r_core_is_project (core, foo)) {
				r_cons_printf ("%s\"%s\"",
					isfirst? "": ",", foo);
				isfirst = false;
			}
		}
		r_cons_printf ("]\n");
		break;
	default:
		r_list_foreach (list, iter, foo) {
			if (r_core_is_project (core, foo)) {
				r_cons_println (foo);
			}
		}
		break;
	}
	r_list_free (list);
	free (path);
	return 0;
}

R_API int r_core_project_delete(RCore *core, const char *prjfile) {
	char *path;
	if (r_sandbox_enable (0)) {
		eprintf ("Cannot delete project in sandbox mode\n");
		return 0;
	}
	path = projectScriptPath (core, prjfile);
	if (!path) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	if (r_core_is_project (core, prjfile)) {
		// rm project file
		r_file_rm (path);
		eprintf ("rm %s\n", path);
		path = r_str_append (path, ".d");
		if (r_file_is_directory (path)) {
			char *f;
			RListIter *iter;
			RList *files = r_sys_dir (path);
			r_list_foreach (files, iter, f) {
				char *filepath = r_str_append (strdup (path), R_SYS_DIR);
				filepath = r_str_append (filepath, f);
				if (!r_file_is_directory (filepath)) {
					eprintf ("rm %s\n", filepath);
					r_file_rm (filepath);
				}
				free (filepath);
			}
			r_file_rm (path);
			eprintf ("rm %s\n", path);
			r_list_free (files);
		}
		// TODO: remove .d directory (BEWARE OF ROOT RIMRAFS!)
		// TODO: r_file_rmrf (path);
	}
	free (path);
	return 0;
}

static bool projectLoadRop(RCore *core, const char *prjfile) {
	char *path, *db = NULL, *path_ns;
	bool found = 0;
	SdbListIter *it;
	SdbNs *ns;

	if (!prjfile || !*prjfile) {
		return false;
	}

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	Sdb *nop_db = sdb_ns (rop_db, "nop", false);
	Sdb *mov_db = sdb_ns (rop_db, "mov", false);
	Sdb *const_db = sdb_ns (rop_db, "const", false);
	Sdb *arithm_db = sdb_ns (rop_db, "arithm", false);
	Sdb *arithmct_db = sdb_ns (rop_db, "arithm_ct", false);

	char *rcPath = projectScriptPath (core, prjfile);
	char *prjDir = r_file_dirname (rcPath);

	if (r_str_endswith (prjfile, R_SYS_DIR "rc")) {
		// XXX
		eprintf ("ENDS WITH\n");
		path = strdup (prjfile);
		path[strlen (path) - 3] = 0;
	} else if (r_file_fexists ("%s" R_SYS_DIR "rc", prjDir, prjfile)) {
		path = r_str_newf ("%s" R_SYS_DIR, prjDir, prjfile);
	} else {
		if (*prjfile == R_SYS_DIR[0]) {
			db = r_str_newf ("%s.d", prjfile);
			if (!db) {
				free (prjDir);
				free (rcPath);
				return false;
			}
			path = strdup (db);
		} else {
			db = r_str_newf ("%s" R_SYS_DIR "%s.d", prjDir, prjfile);
			if (!db) {
				free (prjDir);
				free (rcPath);
				return false;
			}
			path = r_file_abspath (db);
		}
	}
	if (!path) {
		free (db);
		free (prjDir);
		free (rcPath);
		return false;
	}
	if (rop_db) {
		ls_foreach (core->sdb->ns, it, ns){
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
		free (prjDir);
		free (rcPath);
		return false;
	}
	sdb_ns_set (core->sdb, "rop", rop_db);

	path_ns = r_str_newf ("%s" R_SYS_DIR "rop", prjDir);
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
	free (prjDir);
	free (rcPath);
	return true;
}

R_API void r_core_project_execute_cmds(RCore *core, const char *prjfile) {
	char *str = r_core_project_notes_file (core, prjfile);
	char *data = r_file_slurp (str, NULL);
	if (!data) {
		free (str);
		return;
	}
	Output out;
	out.fout = NULL;
	out.cout = r_strbuf_new (NULL);
	r_strbuf_init (out.cout);
	struct Proc proc;
	spp_proc_set (&proc, "spp", 1);
	spp_eval (data, &out);
	free (data);
	data = strdup (r_strbuf_get (out.cout));
	char *bol = strtok (data, "\n");
	while (bol) {
		if (bol[0] == ':') {
			r_core_cmd0 (core, bol + 1);
		}
		bol = strtok (NULL, "\n");
	}
	free (data);
	free (str);
}

/*** vvv thready ***/

typedef struct {
	RCore *core;
	char *prjName;
	char *rcPath;
} ProjectState;

static int projectLoadBackground(RThread *th) {
	ProjectState *ps = th->user;
	r_core_project_load (ps->core, ps->prjName, ps->rcPath);
	free (ps->prjName);
	free (ps->rcPath);
	free (ps);
	return 0;
}

R_API RThread *r_core_project_load_bg(RCore *core, const char *prjName, const char *rcPath) {
	ProjectState *ps = R_NEW (ProjectState);
	ps->core = core;
	ps->prjName = strdup (prjName);
	ps->rcPath = strdup (rcPath);
	RThread *th = r_th_new (projectLoadBackground, ps, false);
	r_th_start (th, true);
	return th;
}

/*** ^^^ thready ***/

R_API bool r_core_project_open(RCore *core, const char *prjfile, bool thready) {
	int askuser = 1;
	int ret, close_current_session = 1;
	char *oldbin;
	const char *newbin;
	ut64 mapaddr = 0;
	if (!prjfile || !*prjfile) {
		return false;
	}
	char *prj = projectScriptPath (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	char *filepath = r_core_project_info (core, prj);
	// eprintf ("OPENING (%s) from %s\n", prj, r_config_get (core->config, "file.path"));
	/* if it is not an URI */
	if (!filepath) {
		eprintf ("Cannot retrieve information for project '%s'\n", prj);
		free (prj);
		return false;
	}

	if (!filepath[0]) {
		goto cookiefactory;
	}
	if (!strstr (filepath, "://")) {
		/* check if path exists */
		if (!r_file_exists (filepath)) {
			eprintf ("Cannot find file '%s'\n", filepath);
			free (prj);
			free (filepath);
			return false;
		}
	}
 cookiefactory:
	;
	const char *file_path = r_config_get (core->config, "file.path");
	if (!file_path || !*file_path) {
		file_path = r_config_get (core->config, "file.lastpath");
	}
	oldbin = strdup (file_path);
	if (!strcmp (prjfile, r_config_get (core->config, "prj.name"))) {
		// eprintf ("Reloading project\n");
		askuser = 0;
#if 0
		free (prj);
		free (filepath);
		return false;
#endif
	}
	if (askuser) {
		if (r_config_get_i (core->config, "scr.interactive")) {
			close_current_session = r_cons_yesno ('y', "Close current session? (Y/n)");
		}
	}
	if (close_current_session) {
		// delete
		r_core_file_close_fd (core, -1);
		r_io_close_all (core->io);
		r_anal_purge (core->anal);
		r_flag_unset_all (core->flags);
		r_bin_file_delete_all (core->bin);
		// open new file
		// TODO: handle read/read-write mode
		r_io_desc_init (core->io);
		if (filepath[0]) {
			/* Old-style project without embedded on commands to open all files.  */
			if (!r_core_file_open (core, filepath, 0, 0)) {
				eprintf ("Cannot open file '%s'\n", filepath);
				ret = false;
				goto beach;
			}
		}
	}

	if (filepath[0] && close_current_session && r_config_get_i (core->config, "file.info")) {
		mapaddr = r_config_get_i (core->config, "file.offset");
		(void)r_core_bin_load (core, filepath, mapaddr? mapaddr: UT64_MAX);
	}
	if (thready) {
		(void) r_core_project_load_bg (core, prjfile, prj);
		ret = true;
	} else {
		/* load sdb stuff in here */
		ret = r_core_project_load (core, prjfile, prj);
	}
	if (filepath[0]) {
		newbin = r_config_get (core->config, "file.path");
		if (!newbin || !*newbin) {
			newbin = r_config_get (core->config, "file.lastpath");
		}
		if (strcmp (oldbin, newbin)) {
			eprintf ("WARNING: file.path changed: %s => %s\n", oldbin, newbin);
		}
	}
beach:
	free (oldbin);
	free (filepath);
	free (prj);
	return ret;
}

R_API char *r_core_project_info(RCore *core, const char *prjfile) {
	FILE *fd;
	char buf[256], *file = NULL;
	char *prj = projectScriptPath (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return NULL;
	}
	fd = r_sandbox_fopen (prj, "r");
	if (fd) {
		for (;;) {
			fgets (buf, sizeof (buf), fd);
			if (feof (fd)) {
				break;
			}
			if (!strncmp (buf, "\"e file.path = ", 15)) {
				buf[strlen (buf) - 2] = 0;
				file = r_str_new (buf + 15);
				break;
			}
			if (!strncmp (buf, "\"e file.lastpath = ", 19)) {
				buf[strlen (buf) - 2] = 0;
				file = r_str_new (buf + 19);
				break;
			}
			// TODO: deprecate before 1.0
			if (!strncmp (buf, "e file.path = ", 14)) {
				buf[strlen (buf) - 1] = 0;
				file = r_str_new (buf + 14);
				break;
			}
		}
		fclose (fd);
	} else {
		eprintf ("Cannot open project info (%s)\n", prj);
	}
#if 0
	if (file) {
		r_cons_printf ("Project: %s\n", prj);
		r_cons_printf ("FilePath: %s\n", file);
	}
#endif
	free (prj);
	return file;
}

static int fdc;		//this is a ugly, remove it, when we have $fd

static bool store_files_and_maps (RCore *core, RIODesc *desc, ut32 id) {
	RList *maps = NULL;
	RListIter *iter;
	RIOMap *map;
	if (desc) {
		r_cons_printf ("ofs %s %s\n", desc->uri, r_str_rwx_i (desc->flags));
		if ((maps = r_io_map_get_for_fd (core->io, id))) {
			r_list_foreach (maps, iter, map) {
				r_cons_printf ("om %d 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x" %s%s%s\n", fdc,
					map->itv.addr, map->itv.size, map->delta, r_str_rwx_i(map->flags),
					map->name ? " " : "", map->name ? map->name : "");
			}
			r_list_free (maps);
		}
		fdc++;
	}
	return true;
}

static bool simpleProjectSaveScript(RCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold;

	if (!file || * file == '\0') {
		return false;
	}

	filename = r_str_word_get_first (file);
	fd = r_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		free (filename);
		return false;
	}

	hl = r_cons_singleton ()->highlight;
	if (hl) {
		ohl = strdup (hl);
		r_cons_highlight (NULL);
	}

	fdold = r_cons_singleton ()->fdout;
	r_cons_singleton ()->fdout = fd;
	r_cons_singleton ()->is_interactive = false;

	r_str_write (fd, "# r2 rdb project file\n");

	if (opts & R_CORE_PRJ_EVAL) {
		r_str_write (fd, "# eval\n");
		r_config_list (core->config, NULL, true);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_META) {
		r_str_write (fd, "# meta\n");
		r_meta_list (core->anal, R_META_TYPE_ANY, 1);
		r_cons_flush ();
		r_core_cmd (core, "fV*", 0);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_XREFS) {
		r_str_write (fd, "# xrefs\n");
		r_core_cmd (core, "ax*", 0);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_FCNS) {
		r_str_write (fd, "# functions\n");
		r_core_cmd (core, "afl*", 0);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_FLAGS) {
		r_str_write (fd, "# flags\n");
		r_core_cmd (core, "f.**", 0);
		r_cons_flush ();
	}

	r_cons_singleton ()->fdout = fdold;
	r_cons_singleton ()->is_interactive = true;

	if (ohl) {
		r_cons_highlight (ohl);
		free (ohl);
	}

	close (fd);
	free (filename);

	return true;
}

static bool projectSaveScript(RCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold, tmp;

	if (!file || *file == '\0') {
		return false;
	}

	filename = r_str_word_get_first (file);
	fd = r_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		free (filename);
		return false;
	}

	hl = r_cons_singleton ()->highlight;
	if (hl) {
		ohl = strdup (hl);
		r_cons_highlight (NULL);
	}

	fdold = r_cons_singleton ()->fdout;
	r_cons_singleton ()->fdout = fd;
	r_cons_singleton ()->is_interactive = false;

	r_str_write (fd, "# r2 rdb project file\n");

	if (opts & R_CORE_PRJ_FLAGS) {
		r_str_write (fd, "# flags\n");
		tmp = core->flags->space_idx;
		core->flags->space_idx = -1;
		r_flag_list (core->flags, true, NULL);
		core->flags->space_idx = tmp;
		r_cons_flush ();
	}
	// Set file.path and file.lastpath to empty string to signal
	// new behaviour to project load routine (see io maps below).
	r_config_set (core->config, "file.path", "");
	r_config_set (core->config, "file.lastpath", "");
	if (opts & R_CORE_PRJ_EVAL) {
		r_str_write (fd, "# eval\n");
		r_config_list (core->config, NULL, true);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_IO_MAPS && core->io && core->io->files) {
		fdc = 3;
		r_id_storage_foreach (core->io->files, (RIDStorageForeachCb)store_files_and_maps, core);
		r_cons_flush ();
	}
	{
		r_core_cmd (core, "fz*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_SECTIONS) {
		r_str_write (fd, "# sections\n");
		r_core_cmd (core, "S*", 0);
		// __section_list_for_projects (core->io, core->print);
		// r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_META) {
		r_str_write (fd, "# meta\n");
		r_meta_list (core->anal, R_META_TYPE_ANY, 1);
		r_cons_flush ();
		r_core_cmd (core, "fV*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_XREFS) {
		r_core_cmd (core, "ax*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_FCNS) {
		r_core_cmd (core, "afl*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_FLAGS) {
		r_core_cmd (core, "f.**", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_DBG_BREAK) {
		r_core_cmd (core, "db*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_HINTS) {
		r_core_cmd (core, "ah*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_TYPES) {
		r_str_write (fd, "# types\n");
		r_core_cmd (core, "t*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_MACROS) {
		r_str_write (fd, "# macros\n");
		r_core_cmd (core, "(*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_SEEK) {
		r_cons_printf ("# seek\n"
			"s 0x%08"PFMT64x "\n", core->offset);
		r_cons_flush ();
	}

	r_cons_singleton ()->fdout = fdold;
	r_cons_singleton ()->is_interactive = true;

	if (ohl) {
		r_cons_highlight (ohl);
		free (ohl);
	}

	close (fd);
	free (filename);

	return true;
}

// TODO: rename to r_core_project_save_script
R_API bool r_core_project_save_rdb(RCore *core, const char *file, int opts) {
	return projectSaveScript (core, file, opts);
}

#define TRANSITION 1

R_API bool r_core_project_save(RCore *core, const char *prjName) {
	bool scr_null = false;
	bool ret = true;
	char *scriptPath, *prjDir;
	SdbListIter *it;
	SdbNs *ns;
	char *oldPrjName = NULL;

	if (!prjName || !*prjName) {
		return false;
	}
	scriptPath = projectScriptPath (core, prjName);
	if (!scriptPath) {
		eprintf ("Invalid project name '%s'\n", prjName);
		return false;
	}
	if (r_str_endswith (scriptPath, R_SYS_DIR "rc")) {
		/* new project format */
		prjDir = r_file_dirname (scriptPath);
	} else {
		prjDir = r_str_newf ("%s.d", scriptPath);
	}
	if (r_file_exists (scriptPath)) {
		if (r_file_is_directory (scriptPath)) {
			eprintf ("WTF. rc is a directory?\n");
		}
		if (r_str_endswith (prjDir, ".d")) {
			eprintf ("Upgrading project...\n");
#if TRANSITION
			r_file_rm (scriptPath);
			r_sys_mkdirp (prjDir);
			eprintf ("Please remove: rm -rf %s %s.d\n", prjName, prjName);
			char *rc = r_str_newf ("%s" R_SYS_DIR "rc", prjDir);
			if (!rc) {
				free (prjDir);
				free (scriptPath);
				return false;
			}
			free (scriptPath);
			scriptPath = rc;
			free (prjDir);
			prjDir = r_file_dirname (scriptPath);
#endif
		}
	}
	if (!prjDir) {
		prjDir = strdup (prjName);
	}
	if (!r_file_exists (prjDir)) {
		r_sys_mkdirp (prjDir);
	}
	if (r_config_get_i (core->config, "scr.null")) {
		r_config_set_i (core->config, "scr.null", false);
		scr_null = true;
	}
	projectInit (core);

	r_anal_project_save (core->anal, prjDir);

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	if (rop_db) {
		/* set filepath for all the rop sub-dbs */
		ls_foreach (rop_db->ns, it, ns) {
			char *rop_path = r_str_newf ("%s" R_SYS_DIR "rop.d" R_SYS_DIR "%s", prjDir, ns->name);
			sdb_file (ns->sdb, rop_path);
			sdb_sync (ns->sdb);
			free (rop_path);
		}
	}

	const char *oldPrjNameC = r_config_get (core->config, "prj.name");
	if (oldPrjNameC) {
		oldPrjName = strdup (oldPrjNameC);
	}
	r_config_set (core->config, "prj.name", prjName);
	if (r_config_get_i (core->config, "prj.simple")) {
		if (!simpleProjectSaveScript (core, scriptPath, R_CORE_PRJ_ALL ^ R_CORE_PRJ_XREFS)) {
			eprintf ("Cannot open '%s' for writing\n", prjName);
			ret = false;
		}
	} else {
		if (!projectSaveScript (core, scriptPath, R_CORE_PRJ_ALL ^ R_CORE_PRJ_XREFS)) {
			eprintf ("Cannot open '%s' for writing\n", prjName);
			ret = false;
		}
	}

	if (r_config_get_i (core->config, "prj.files")) {
		eprintf ("TODO: prj.files: support copying more than one file into the project directory\n");
		char *binFile = r_core_project_info (core, prjName);
		const char *binFileName = r_file_basename (binFile);
		char *prjBinDir = r_str_newf ("%s" R_SYS_DIR "bin", prjDir);
		char *prjBinFile = r_str_newf ("%s" R_SYS_DIR "%s", prjBinDir, binFileName);
		r_sys_mkdirp (prjBinDir);
		if (!r_file_copy (binFile, prjBinFile)) {
			eprintf ("Warning: Cannot copy '%s' into '%s'\n", binFile, prjBinFile);
		}
		free (prjBinFile);
		free (prjBinDir);
		free (binFile);
	}
	if (r_config_get_i (core->config, "prj.git")) {
		char *cwd = r_sys_getdir ();
		char *gitDir = r_str_newf ("%s" R_SYS_DIR ".git", prjDir);
		if (r_sys_chdir (prjDir)) {
			if (!r_file_is_directory (gitDir)) {
				r_sys_cmd ("git init");
			}
			r_sys_cmd ("git add * ; git commit -a");
		} else {
			eprintf ("Cannot chdir %s\n", prjDir);
		}
		r_sys_chdir (cwd);
		free (gitDir);
		free (cwd);
	}
	if (r_config_get_i (core->config, "prj.zip")) {
		char *cwd = r_sys_getdir ();
		const char *prjName = r_file_basename (prjDir);
		if (r_sys_chdir (prjDir)) {
			if (!strchr (prjName, '\'')) {
				r_sys_chdir ("..");
				r_sys_cmdf ("rm -f '%s.zip'; zip -r '%s'.zip '%s'",
					prjName, prjName, prjName);
			} else {
				eprintf ("Command injection attempt?\n");
			}
		} else {
			eprintf ("Cannot chdir %s\n", prjDir);
		}
		r_sys_chdir (cwd);
		free (cwd);
	}
	// LEAK : not always in heap free (prjName);
	free (prjDir);
	if (scr_null) {
		r_config_set_i (core->config, "scr.null", true);
	}
	if (!ret) {
		// reset prj.name on fail
		r_config_set (core->config, "prj.name", oldPrjName);
	}
	free (scriptPath);
	free (oldPrjName);
	return ret;
}

R_API char *r_core_project_notes_file(RCore *core, const char *prjName) {
	char *notes_txt;
	const char *prjdir = r_config_get (core->config, "dir.projects");
	char *prjpath = r_file_abspath (prjdir);
	notes_txt = r_str_newf ("%s"R_SYS_DIR "%s"R_SYS_DIR "notes.txt", prjpath, prjName);
	free (prjpath);
	return notes_txt;
}

#define DB core->anal->sdb_xrefs

static bool projectLoadXrefs(RCore *core, const char *prjName) {
	char *path, *db;

	if (!prjName || !*prjName) {
		return false;
	}
	const char *prjdir = r_config_get (core->config, "dir.projects");

	if (prjName[0] == R_SYS_DIR[0]) {
		db = r_str_newf ("%s", prjName);
		if (!db) {
			return false;
		}
		path = strdup (db);
	} else {
		db = r_str_newf ("%s" R_SYS_DIR "%s", prjdir, prjName);
		if (!db) {
			return false;
		}
		path = r_file_abspath (db);
	}

	if (!path) {
		free (db);
		return false;
	}
	if (!r_file_is_directory (db)) {
		db = r_str_append (db, ".d");
	}

	if (!sdb_ns_unset (core->anal->sdb, NULL, DB)) {
		sdb_free (DB);
	}
	const char *xrefs_path = r_file_fexists ("%s" R_SYS_DIR "xrefs.sdb", path)
	                         ? "xrefs.sdb": "xrefs";
	DB = sdb_new (path, xrefs_path, 0);
	if (!DB) {
		free (db);
		free (path);
		return false;
	}
	sdb_ns_set (core->anal->sdb, "xrefs", DB);
	free (path);

	free (db);
	return true;
}

R_API bool r_core_project_load(RCore *core, const char *prjName, const char *rcpath) {
	const bool cfg_fortunes = r_config_get_i (core->config, "cfg.fortunes");
	const bool scr_interactive = r_config_get_i (core->config, "scr.interactive");
	const bool scr_prompt = r_config_get_i (core->config, "scr.prompt");
	(void) projectLoadRop (core, prjName);
	(void) projectLoadXrefs (core, prjName);
	bool ret = r_core_cmd_file (core, rcpath);
	r_config_set_i (core->config, "cfg.fortunes", cfg_fortunes);
	r_config_set_i (core->config, "scr.interactive", scr_interactive);
	r_config_set_i (core->config, "scr.prompt", scr_prompt);
	r_config_bump (core->config, "asm.arch");
	return ret;
}

