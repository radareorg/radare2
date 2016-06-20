/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_userconf.h>
#include <r_debug.h>

int procfs_pid_slurp(int pid, char *prop, char *out, size_t len) {
	int fd, ret = -1;
	ssize_t nr;

	char *filename = r_str_newf ("/proc/%d/%s", pid, prop);
	if (!filename) {
		return -1;
	}
	fd = r_sandbox_open (filename, O_RDONLY, 0);
	if (fd == -1) {
		free (filename);
		return -1;
	}
	nr = read (fd, out, len);
	out[len - 1] = 0;
	if (nr > 0) {
		out[nr - 1] = '\0';  /* terminate at newline */
		ret = 0;
	} else if (nr < 0) {
		r_sys_perror ("read");
	} else {
		eprintf ("proc_pid_slurp: got EOF reading from \"%s\"\n", filename);
	}
	close (fd);
	free (filename);
	return ret;
}
