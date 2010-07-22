/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static char *r_core_project_file(const char *file) {
	char buf[128];
	snprintf (buf, sizeof (buf), ".radare2/rdb/%s", file);
	return r_str_home (buf);
}

//TODO: Don't try mkdir rdb if mdkir .radare2 fails. (Maybe R_TRUFAE??)
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
	free (prj);
	return ret;
}

R_API char *r_core_project_info(RCore *core, const char *prjfile) {
	char buf[256], *file = NULL;
	char *prj = r_core_project_file (prjfile);
	FILE *fd;
	if (prj && (fd = fopen (prj, "r"))) {
		for (;;) {
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
	}
	r_cons_printf ("Project : %s\n", prj);
	if (file)
		r_cons_printf ("FilePath: %s\n", file);
	free (prj);
	return file;
}

R_API int r_core_project_save(RCore *core, const char *file) {
	int fd, tmp, ret = R_TRUE;
	char *prj;

	if (file == NULL || *file == '\0')
		return R_FALSE;

	prj = r_core_project_file (file);
	r_core_project_init ();
	fd = open (prj, O_RDWR|O_CREAT, 0644);
	if (fd != -1) {
		r_cons_singleton ()->fdout = fd;
		r_str_write (fd, "# r2 rdb project file\n");
		//--
		r_str_write (fd, "# flags\n");
		tmp = core->flags->space_idx;
		core->flags->space_idx = -1;
		r_flag_list (core->flags, R_TRUE);
		core->flags->space_idx = tmp;
		r_cons_flush ();
		//--
		r_str_write (fd, "# eval\n");
		// TODO: r_str_writef (fd, "e asm.arch=%s", r_config_get ("asm.arch"));
		r_config_list (core->config, NULL, R_TRUE);
		r_cons_flush ();
		r_cons_singleton ()->fdout = 1;
		close (fd);
	} else {
		eprintf ("Cannot open '%s' for writing\n", prj);
		ret = R_FALSE;
	}
	free (prj);
	return ret;
}
