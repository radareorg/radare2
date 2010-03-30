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

static int r_core_project_init() {
	int ret;
	char *str, buf[128];
	str = r_str_home (".radare2");
	ret = r_sys_mkdir (str);
	free (str);
	if (ret) {
		str = r_str_home (".radare2/rdb");
		ret = r_sys_mkdir (str);
		free (str);
	}
	return ret;
}

R_API int r_core_project_open(RCore *core, const char *file) {
	int ret;
	char *prj = r_core_project_file (file);
	ret = r_core_cmd_file (core, prj);
	free (prj);
	return ret;
}

R_API int r_core_project_save(RCore *core, const char *file) {
	int ret = R_TRUE;
	char *prj = r_core_project_file (file);
	int fd;
	r_core_project_init ();
	fd = open (prj, O_RDWR|O_CREAT, 0644);
	if (fd != -1) {
		r_cons_singleton ()->fdout = fd;
		write (fd, "# r2 rdb project file\n", 22);
		r_flag_list (&core->flags, R_TRUE);
		r_cons_flush ();
		r_cons_singleton ()->fdout = 1;
		close (fd);
	} else {
		eprintf ("Cannot open '%s' for writing\n", file);
		ret = R_FALSE;
	}
	free (prj);
	return ret;
}
