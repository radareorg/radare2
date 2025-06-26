#if 0
#include <stdio.h>

int pids_cmdline(int pid, char *cmdline) {
	sprintf (cmdline, "/proc/%d/cmdline", pid);
	int fd = open (cmdline, O_RDONLY);
	cmdline[0] = '\0';
	if (fd != -1) {
		// TODO: check return value
		read (fd, cmdline, 1024);
		cmdline[1024] = '\0';
		close (fd);
	}
	return 0;
}

static const char *process_state(const char ch) {
	if (ch == 'S') {
		return "sleeping";
	}
	if (ch == 'T') {
		return "stopped";
	}
	return "running";
}

// XXX. sscanf can be vulnerable
int pids_sons_of_r(int pid, int recursive, int limit) {
	int tmp, n = 0;
	char tmp3[8];
	char buf[128];
	char tmp2[1024];
	struct dirent *file;

	if (pid < 1) {
	       return false;
	}
	DIR *dh = opendir ("/proc/");
	if (!dh) {
		return false;
	}
	while ((file = (struct dirent *)readdir (dh))) {
		int p = atoi (file->d_name);
		if (!p) {
			continue;
		}
		snprintf (buf, sizeof (buf), "/proc/%s/stat", file->d_name);
		FILE *fd = fopen (buf, "r");
		if (fd) {
			int mola = 0;
			fscanf (fd, "%d %s %s %d", &tmp, tmp2, tmp3, &mola);
			if (mola == pid) {
				pids_cmdline (p, tmp2);
				const char *state = process_state (tmp3[0]);
				eprintf (" `- %d : %s (%s)\n", p, tmp2, state);
				n++;
				if (recursive < limit) {
					n += pids_sons_of_r (p, recursive + 1, limit);
				}
			}
		}
		fclose (fd);
	}
	closedir (dh);
	return n;
}
#endif
