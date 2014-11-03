/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static char *r_core_project_file(RCore *core, const char *file) {
	if (*file != '/') {
		char *ret = r_file_abspath (r_config_get (
			core->config, "dir.projects"));
		ret = r_str_concat (ret, "/");
		return r_str_concat (ret, file);
	}
	return strdup (file);
}

static int r_core_project_init(RCore *core) {
	char *prjdir = r_file_abspath (r_config_get (
		core->config, "dir.projects"));
	int ret = r_sys_rmkdir (prjdir);
	if (!ret) eprintf ("Cannot mkdir dir.projects\n");
	free (prjdir);
	return ret;
}

R_API int r_core_project_open(RCore *core, const char *prjfile) {
	int ret;
	char *prj;
	if (!prjfile || !*prjfile)
		return R_FALSE;
	prj = r_core_project_file (core, prjfile);
	ret = r_core_cmd_file (core, prj);
	r_anal_project_load (core->anal, prjfile);
	free (prj);
	return ret;
}

R_API char *r_core_project_info(RCore *core, const char *prjfile) {
	char buf[256], *file = NULL, *prj = r_core_project_file (core, prjfile);
	FILE *fd = prj? r_sandbox_fopen (prj, "r"): NULL;
	for (;fd;) {
		fgets (buf, sizeof (buf), fd);
		if (feof (fd))
			break;
		if (!memcmp (buf, "\"e file.path = ", 15)) {
			buf[strlen(buf)-2]=0;
			file = r_str_new (buf+15);
			break;
		}
		// TODO: deprecate before 1.0
		if (!memcmp (buf, "e file.path = ", 14)) {
			buf[strlen(buf)-1]=0;
			file = r_str_new (buf+14);
			break;
		}
	}
	if (fd) fclose (fd);
	r_cons_printf ("%s\n", prj);
	if (file) r_cons_printf ("FilePath: %s\n", file);
	free (prj);
	return file;
}

R_API int r_core_project_save(RCore *core, const char *file) {
	int fd, fdold, tmp, ret = R_TRUE;
	char *prj;

	if (file == NULL || *file == '\0')
		return R_FALSE;

	prj = r_core_project_file (core, file);
	if (r_file_is_directory (prj)) {
		eprintf ("Error: Target is a directory\n");
		free (prj);
		return R_FALSE;
	}
	r_core_project_init (core);
	r_anal_project_save (core->anal, prj);
	fd = r_sandbox_open (prj, O_BINARY|O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (fd != -1) {
		fdold = r_cons_singleton ()->fdout;
		r_cons_singleton ()->fdout = fd;
		r_cons_singleton ()->is_interactive = R_FALSE;
		r_str_write (fd, "# r2 rdb project file\n");
		r_str_write (fd, "# flags\n");
		tmp = core->flags->space_idx;
		core->flags->space_idx = -1;
		r_flag_list (core->flags, R_TRUE);
		core->flags->space_idx = tmp;
		r_cons_flush ();
		r_str_write (fd, "# eval\n");
		// TODO: r_str_writef (fd, "e asm.arch=%s", r_config_get ("asm.arch"));
		r_config_list (core->config, NULL, R_TRUE);
		r_cons_flush ();
		r_str_write (fd, "# sections\n");
		r_io_section_list (core->io, core->offset, 1);
		r_cons_flush ();
		r_str_write (fd, "# meta\n");
		r_meta_list (core->anal, R_META_TYPE_ANY, 1);
		r_cons_flush ();
		 {
			char buf[1024];
			snprintf (buf, sizeof (buf), "%s.d/xrefs", prj);
			sdb_file (core->anal->sdb_xrefs, buf);
			sdb_sync (core->anal->sdb_xrefs);
		 }
		r_core_cmd (core, "ax*", 0);
		r_cons_flush ();
		r_core_cmd (core, "af*", 0);
		r_cons_flush ();
		r_core_cmd (core, "ah*", 0);
		r_cons_flush ();
		r_cons_printf ("# seek\n"
			"s 0x%08"PFMT64x"\n", core->offset);
		r_cons_flush ();
		close (fd);
		r_cons_singleton ()->fdout = fdold;
		r_cons_singleton ()->is_interactive = R_TRUE;
	} else {
		eprintf ("Cannot open '%s' for writing\n", prj);
		ret = R_FALSE;
	}
	free (prj);
	return ret;
}
