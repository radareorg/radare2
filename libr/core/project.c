/* radare - LGPL - Copyright 2010-2013 - pancake */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static char *r_core_project_file(const char *file) {
	char buf[128];
	if (!strchr (file, '/')) {
		snprintf (buf, sizeof (buf), ".radare2/rdb/%s", file);
		return r_str_home (buf);
	}
	return strdup (file);
}

static int r_core_project_init() {
	int ret;
	char *str = r_str_home (".radare2");
	if (str && (ret = r_sys_mkdir (str))) {
		if (!ret) {
			free (str);
			str = r_str_home (".radare2/plugins");
			ret = r_sys_mkdir (str);
			if (ret) eprintf ("Cannot create ~/.radare2/plugins\n");
		}
	}
	str = r_str_home (".radare2/rdb");
	ret = r_sys_mkdir (str);
	free (str);
	return ret;
}

R_API int r_core_project_open(RCore *core, const char *prjfile) {
	int ret;
	char *prj = r_core_project_file (prjfile);
	ret = r_core_cmd_file (core, prj);
// prj += .sdb/asm
// r_asm_project_open (core->assembler, prj);
	free (prj);
	return ret;
}

R_API char *r_core_project_info(RCore *core, const char *prjfile) {
	char buf[256], *file = NULL, *prj = r_core_project_file (prjfile);
	FILE *fd = prj? r_sandbox_fopen (prj, "r"): NULL;
	for (;fd;) {
		fgets (buf, sizeof (buf), fd);
		if (feof (fd))
			break;
		if (!memcmp (buf, "e file.path = ", 14)) {
			buf[strlen(buf)-1]=0;
			file = r_str_new (buf+14);
			break;
		}
	}
	fclose (fd);
	r_cons_printf ("Project : %s\n", prj);
	if (file) r_cons_printf ("FilePath: %s\n", file);
	free (prj);
	return file;
}

R_API int r_core_project_save(RCore *core, const char *file) {
	int fd, fdold, tmp, ret = R_TRUE;
	char *prj;

	if (file == NULL || *file == '\0')
		return R_FALSE;

	prj = r_core_project_file (file);
	r_core_project_init ();
	fd = r_sandbox_open (prj, O_BINARY|O_RDWR|O_CREAT, 0644);
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
		r_meta_list (core->anal->meta, R_META_TYPE_ANY, 1);
		r_cons_flush ();
		r_core_cmd (core, "ar*", 0);
		r_cons_flush ();
		r_core_cmd (core, "af*", 0);
		r_cons_flush ();
		r_core_cmd (core, "ah*", 0);
		r_cons_flush ();
		r_str_write (fd, "# seek\n");
		r_str_writef (fd, "s 0x%08"PFMT64x, core->offset);
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
