/* radare2 - Copyleft 2011 - pancake<nopcode.org> */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static char *_arg0 = NULL;
static char *_arg1 = NULL;
static char *_arg2 = NULL;
static char *_arg3 = NULL;
static char *_program = NULL;
static char *_stdin = NULL;
static char *_stdout = NULL;
static char *_stderr = NULL;
static char *_chdir = NULL;
static char *_chroot = NULL;
static char *_preload = NULL;
static char *_setuid = NULL;
static char *_seteuid = NULL;
static char *_setgid = NULL;
static char *_setegid = NULL;
static char *_input = NULL;

static void parseline (char *b) {
	char *e = strchr (b, '=');
	if (!e) return;
	if (*b=='#') return;
	*e++=0;
	if (!strcmp (b, "program")) _program = strdup (e);
	else if (!strcmp (b, "stdout")) _stdout = strdup (e);
	else if (!strcmp (b, "stdin")) _stdin = strdup (e);
	else if (!strcmp (b, "input")) _input = strdup (e);
	else if (!strcmp (b, "chdir")) _chdir = strdup (e);
	else if (!strcmp (b, "chroot")) _chroot = strdup (e);
	else if (!strcmp (b, "preload")) _preload = strdup (e);
	else if (!strcmp (b, "setuid")) _setuid = strdup (e);
	else if (!strcmp (b, "seteuid")) _seteuid = strdup (e);
	else if (!strcmp (b, "setgid")) _setgid = strdup (e);
	else if (!strcmp (b, "setegid")) _setegid = strdup (e);
	else if (!strcmp (b, "arg0")) _arg0 = strdup (e);
	else if (!strcmp (b, "arg1")) _arg1 = strdup (e);
	else if (!strcmp (b, "arg2")) _arg2 = strdup (e);
	else if (!strcmp (b, "arg3")) _arg3 = strdup (e);
	else if (!strcmp (b, "setenv")) {
		char *v = strchr (e, '=');
		if (v) {
			*v++=0;
			setenv (e, v, 1);
		}
	}
}

static void parseinput (char *s) {
	if (!*s) return;
	while (*s++) {
		if (s[0]=='\\' && s[1]=='n') {
			*s = '\n';
			strcpy (s+1, s+2);
		}
	}
}

static int runfile () {
	int ret;
	if (!_program) {
		printf ("No program rule defined\n");
		return 1;
	}
	if (_stdin) {
		int f = open (_stdin, O_RDONLY);
		close (0);
		dup2 (f, 0);
	}
	if (_stdout) {
		int f = open (_stdout, O_RDONLY);
		close (1);
		dup2 (f, 1);
	}
	if (_stderr) {
		int f = open (_stderr, O_RDONLY);
		close (2);
		dup2 (f, 2);
	}
	if (_chdir) chdir (_chdir);
	if (_chroot) chdir (_chroot);
	if (_setuid) setuid (atoi (_setuid));
	if (_seteuid) seteuid (atoi (_seteuid));
	if (_setgid) setgid (atoi (_setgid));
	if (_input) {
		int f2[2];
		pipe (f2);
		close (0);
		dup2 (f2[0], 0);
		parseinput (_input);
		write (f2[1], _input, strlen (_input));
	}
	if (_preload) {
#if __APPLE__
		setenv ("DYLD_PRELOAD", _preload, 1);
#else
		setenv ("LD_PRELOAD", _preload, 1);
#endif
	}
	ret = execl (_program, _program, _arg0, NULL);
	printf ("RETURN VALUE = %d\n", ret);
	return 0;
}

int main(int argc, char **argv) {
	FILE *fd;
	char *file, buf[1024];
	if (argc==1) {
		printf ("Usage: rarun2 script\n");
		return 1;
	}
	file = argv[1];
	fd = fopen (file, "r");
	if (!fd) {
		fprintf (stderr, "Cannot open %s\n", file);
		return 1;
	}
	for (;;) {
		fgets (buf, sizeof (buf)-1, fd);
		if (feof (fd)) break;
		buf[strlen (buf)-1] = 0;
		parseline (buf);
	}
	fclose (fd);
	return runfile ();
}
