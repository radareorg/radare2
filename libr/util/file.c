/* radare - LGPL - Copyright 2007-2020 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <r_lib.h>
#if __UNIX__
#include <sys/time.h>
#include <sys/mman.h>
#include <limits.h>
#endif
#if __APPLE__ && __MAC_10_5
#define HAVE_COPYFILE_H 1
#else
#define HAVE_COPYFILE_H 0
#endif
#if HAVE_COPYFILE_H
#include <copyfile.h>
#endif
#if _MSC_VER
#include <process.h>
#endif

#define BS 1024

static int file_stat(const char *file, struct stat* const pStat) {
	r_return_val_if_fail (file && pStat, -1);
#if __WINDOWS__
	wchar_t *wfile = r_utf8_to_utf16 (file);
	if (!wfile) {
		return -1;
	}
	int ret = _wstat (wfile, pStat);
	free (wfile);
	return ret;
#else // __WINDOWS__
	return stat (file, pStat);
#endif // __WINDOWS__
}

// r_file_new("", "bin", NULL) -> /bin
// r_file_new(".", "bin", NULL) -> ./bin
// r_file_new("/", "bin", NULL) -> //bin # shall we be stricts?
R_API char *r_file_new(const char *root, ...) {
	va_list ap;
	va_start (ap, root);
	RStrBuf *sb = r_strbuf_new ("");
	char *home = r_str_home (NULL);
	const char *arg = va_arg (ap, char *);
	r_strbuf_append (sb, arg);
	arg = va_arg (ap, char *);
	while (arg) {
		if (!strcmp (arg, "~")) {
			arg = home;
		}
		r_strbuf_append (sb, R_SYS_DIR);
		r_strbuf_append (sb, arg);
		arg = va_arg (ap, char *);
	}
	va_end (ap);
	free (home);
	char *path = r_strbuf_drain (sb);
	char *abs = r_file_abspath (path);
	free (path);
	return abs;
}

R_API bool r_file_truncate(const char *filename, ut64 newsize) {
	r_return_val_if_fail (filename, false);
	int fd;
	if (r_file_is_directory (filename)) {
		return false;
	}
	if (!r_file_exists (filename) || !r_file_is_regular (filename)) {
		return false;
	}
#if __WINDOWS__
	fd = r_sandbox_open (filename, O_RDWR, 0644);
#else
	fd = r_sandbox_open (filename, O_RDWR | O_SYNC, 0644);
#endif
	if (fd == -1) {
		return false;
	}
#ifdef _MSC_VER
	int r = _chsize (fd, newsize);
#else
	int r = ftruncate (fd, newsize);
#endif
	if (r != 0) {
		eprintf ("Could not resize %s file\n", filename);
		close (fd);
		return false;
	}
	close (fd);
	return true;
}

/*
Example:
	str = r_file_basename ("home/inisider/Downloads/user32.dll");
	// str == user32.dll
*/
R_API const char *r_file_basename(const char *path) {
	r_return_val_if_fail (path, NULL);
	const char *ptr = r_str_rchr (path, NULL, '/');
	if (ptr) {
		path = ptr + 1;
	} else {
		if ((ptr = r_str_rchr (path, NULL, '\\'))) {
			path = ptr + 1;
		}
	}
	return path;
}

/*
Example:
	str = r_file_basename ("home/inisider/Downloads");
	// str == "home/inisider/Downloads"
	free (str);
*/
R_API char *r_file_dirname(const char *path) {
	r_return_val_if_fail (path, NULL);
	char *newpath = strdup (path);
	char *ptr = (char*)r_str_rchr (newpath, NULL, '/');
	if (ptr) {
		*ptr = 0;
	} else {
		ptr = (char*)r_str_rchr (newpath, NULL, '\\');
		if (ptr) {
			*ptr = 0;
		}
	}
	return newpath;
}

R_API bool r_file_is_c(const char *file) {
	r_return_val_if_fail (file, false);
	const char *ext = r_str_lchr (file, '.'); // TODO: add api in r_file_extension or r_str_ext for this
	if (ext) {
		ext++;
		if (!strcmp (ext, "cparse")
		||  !strcmp (ext, "c")
		||  !strcmp (ext, "h")) {
			return true;
		}
	}
	return false;
}

R_API bool r_file_is_regular(const char *str) {
	struct stat buf = {0};
	if (!str || !*str || file_stat (str, &buf) == -1) {
		return false;
	}
	return ((S_IFREG & buf.st_mode) == S_IFREG);
}

R_API bool r_file_is_directory(const char *str) {
	struct stat buf = {0};
	r_return_val_if_fail (!R_STR_ISEMPTY (str), false);
	if (file_stat (str, &buf) == -1) {
		return false;
	}
#ifdef S_IFBLK
	if ((S_IFBLK & buf.st_mode) == S_IFBLK) {
		return false;
	}
#endif
	return S_IFDIR == (S_IFDIR & buf.st_mode);
}

R_API bool r_file_fexists(const char *fmt, ...) {
	int ret;
	char string[BS];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = r_file_exists (string);
	va_end (ap);
	return ret;
}

R_API bool r_file_exists(const char *str) {
	char *absfile = r_file_abspath (str);
	struct stat buf = {0};
	r_return_val_if_fail (!R_STR_ISEMPTY (str), false);
	if (file_stat (absfile, &buf) == -1) {
		free (absfile);
		return false;
	}
	free (absfile);
	return S_IFREG == (S_IFREG & buf.st_mode);
}

R_API ut64 r_file_size(const char *str) {
	r_return_val_if_fail (!R_STR_ISEMPTY (str), 0);
	struct stat buf = {0};
	if (file_stat (str, &buf) == -1) {
		return 0;
	}
	return (ut64)buf.st_size;
}

R_API bool r_file_is_abspath(const char *file) {
	r_return_val_if_fail (!R_STR_ISEMPTY (file), 0);
	return ((*file && file[1]==':') || *file == '/');
}

R_API char *r_file_abspath_rel(const char *cwd, const char *file) {
	char *ret = NULL;
	if (!file || !strcmp (file, ".") || !strcmp (file, "./")) {
		return r_sys_getdir ();
	}
	if (strstr (file, "://")) {
		return strdup (file);
	}
	if (!strncmp (file, "~/", 2) || !strncmp (file, "~\\", 2)) {
		ret = r_str_home (file + 2);
	} else {
#if __UNIX__
		if (cwd && *file != '/') {
			ret = r_str_newf ("%s" R_SYS_DIR "%s", cwd, file);
		}
#elif __WINDOWS__
		// Network path
		if (!strncmp (file, "\\\\", 2)) {
			return strdup (file);
		}
		if (!strchr (file, ':')) {
			PTCHAR abspath = malloc (MAX_PATH * sizeof (TCHAR));
			if (abspath) {
				PTCHAR f = r_sys_conv_utf8_to_win (file);
				int s = GetFullPathName (f, MAX_PATH, abspath, NULL);
				if (s > MAX_PATH) {
					R_LOG_ERROR ("r_file_abspath/GetFullPathName: Path to file too long.\n");
				} else if (!s) {
					r_sys_perror ("r_file_abspath/GetFullPathName");
				} else {
					ret = r_sys_conv_win_to_utf8 (abspath);
				}
				free (abspath);
				free (f);
			}
		}
#endif
	}
	if (!ret) {
		ret = strdup (file);
	}
#if __UNIX__
	char *abspath = realpath (ret, NULL);
	if (abspath) {
		free (ret);
		ret = abspath;
	}
#endif
	return ret;
}

R_API char *r_file_abspath(const char *file) {
	r_return_val_if_fail (file, NULL);
	char *cwd = r_sys_getdir ();
	if (cwd) {
		char *ret = r_file_abspath_rel (cwd, file);
		free (cwd);
		return ret;
	}
	return NULL;
}

R_API char *r_file_binsh(void) {
	char *bin_sh = r_sys_getenv ("SHELL");
	if (R_STR_ISEMPTY (bin_sh)) {
		free (bin_sh);
		bin_sh = r_file_path("sh");
		if (R_STR_ISEMPTY (bin_sh)) {
			free (bin_sh);
			bin_sh = strdup ("/bin/sh");
		}
	}
	return bin_sh;
}

R_API char *r_file_path(const char *bin) {
	r_return_val_if_fail (bin, NULL);
	char *file = NULL;
	char *path = NULL;
	char *str, *ptr;
	const char *extension = "";
	if (!strncmp (bin, "./", 2)) {
		return r_file_exists (bin)
			? r_file_abspath (bin): NULL;
	}
	char *path_env = (char *)r_sys_getenv ("PATH");
#if __WINDOWS__
	if (!r_str_endswith (bin, ".exe")) {
		extension = ".exe";
	}
#endif
	if (path_env) {
		str = path = strdup (path_env);
		do {
			ptr = strchr (str, R_SYS_ENVSEP[0]);
			if (ptr) {
				*ptr = '\0';
				file = r_str_newf (R_JOIN_2_PATHS ("%s", "%s%s"), str, bin, extension);
				if (r_file_exists (file)) {
					free (path);
					free (path_env);
					return file;
				}
				str = ptr + 1;
				free (file);
			}
		} while (ptr);
	}
	free (path_env);
	free (path);
	return strdup (bin);
}

R_API char *r_stdin_slurp (int *sz) {
#if __UNIX__ || __WINDOWS__
	int i, ret, newfd;
	if ((newfd = dup (0)) < 0) {
		return NULL;
	}
	char *buf = malloc (BS);
	if (!buf) {
		close (newfd);
		return NULL;
	}
	for (i = ret = 0; i >= 0; i += ret) {
		char *new = realloc (buf, i + BS);
		if (!new) {
			eprintf ("Cannot realloc to %d\n", i+BS);
			free (buf);
			return NULL;
		}
		buf = new;
		ret = read (0, buf + i, BS);
		if (ret < 1) {
			break;
		}
	}
	if (i < 1) {
		i = 0;
		R_FREE (buf);
	} else {
		buf[i] = 0;
		dup2 (newfd, 0);
		close (newfd);
	}
	if (sz) {
		*sz = i;
	}
	if (!i) {
		R_FREE (buf);
	}
	return buf;
#else
#warning TODO r_stdin_slurp
	return NULL;
#endif
}

R_API char *r_file_slurp(const char *str, R_NULLABLE size_t *usz) {
	r_return_val_if_fail (str, NULL);
	if (usz) {
		*usz = 0;
	}
	if (!r_file_exists (str)) {
		return NULL;
	}
	FILE *fd = r_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
	if (fseek (fd, 0, SEEK_END) == -1) {
		// cannot determine the size of the file
	}
	long sz = ftell (fd);
	if (sz < 0) {
		fclose (fd);
		return NULL;
	}
	if (!sz) {
		if (r_file_is_regular (str)) {
			char *buf = NULL;
			long size = 0;
			(void)fseek (fd, 0, SEEK_SET);
			do {
				char *nbuf = realloc (buf, size + BS);
				if (!nbuf) {
					break;
				}
				buf = nbuf;
				size_t r = fread (buf + size, 1, BS, fd);
				if (ferror (fd)) {
					R_FREE (buf);
					goto regular_err;
				}
				size += r;
			} while (!feof (fd));
			char *nbuf = realloc (buf, size + 1);
			if (!nbuf) {
				free (buf);
				return NULL;
			}
			buf = nbuf;
			buf[size] = '\0';
			if (usz) {
				*usz = size;
			}
		regular_err:
			fclose (fd);
			return buf;
		}
		// try to read 64K
		sz = UT16_MAX;
	}
	rewind (fd);
	char *ret = (char *)malloc (sz + 1);
	if (!ret) {
		fclose (fd);
		return NULL;
	}
	size_t rsz = fread (ret, 1, sz, fd);
	if (rsz != sz) {
		eprintf ("Warning: r_file_slurp: fread: truncated read\n");
		sz = rsz;
	}
	fclose (fd);
	ret[sz] = '\0';
	if (usz) {
		*usz = sz;
	}
	return ret;
}

R_API ut8 *r_file_gzslurp(const char *str, int *outlen, int origonfail) {
	r_return_val_if_fail (str, NULL);
	if (outlen) {
		*outlen = 0;
	}
	size_t sz;
	ut8 *in = (ut8*)r_file_slurp (str, &sz);
	if (!in) {
		return NULL;
	}
	ut8 *out = r_inflate (in, (int)sz, NULL, outlen);
	if (!out && origonfail) {
		// if uncompression fails, return orig buffer ?
		if (outlen) {
			*outlen = (int)sz;
		}
		in[sz] = 0;
		return in;
	}
	free (in);
	return out;
}

R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz) {
	r_return_val_if_fail (str, NULL);
	if (usz) {
		*usz = 0;
	}
	ut8 *ret;
	long sz;
	int c, bytes = 0;
	FILE *fd = r_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
	(void) fseek (fd, 0, SEEK_END);
	sz = ftell (fd);
	(void) fseek (fd, 0, SEEK_SET);
	ret = (ut8*)malloc ((sz>>1)+1);
	if (!ret) {
		fclose (fd);
		return NULL;
	}
	for (;;) {
		if (fscanf (fd, " #%*[^\n]") == 1)  {
			continue;
		}
		if (fscanf (fd, "%02x", &c) == 1) {
			ret[bytes++] = c;
			continue;
		}
		if (feof (fd)) {
			break;
		}
		free (ret);
		fclose (fd);
		return NULL;
	}
	ret[bytes] = '\0';
	fclose (fd);
	if (usz) {
		*usz = bytes;
	}
	return ret;
}

R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz) {
	char *ret;
	size_t read_items;
	FILE *fd = r_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
	// XXX handle out of bound reads (eof)
	if (fseek (fd, off, SEEK_SET) < 0) {
		fclose (fd);
		return NULL;
	}
	ret = (char *) malloc (sz + 1);
	if (ret) {
		if (osz) {
			*osz = (int)(size_t) fread (ret, 1, sz, fd);
		} else {
			read_items = fread (ret, 1, sz, fd);
			if (!read_items) {
				fclose (fd);
				return ret;
			}
		}
		ret[sz] = '\0';
	}
	fclose (fd);
	return ret;
}

R_API char *r_file_slurp_random_line(const char *file) {
	r_return_val_if_fail (file, NULL);
	int i = 0;
	return r_file_slurp_random_line_count (file, &i);
}

R_API char *r_file_slurp_random_line_count(const char *file, int *line) {
	r_return_val_if_fail (file && line, NULL);
	/* Reservoir Sampling */
	char *ptr = NULL, *str;
	size_t i, lines, selection = -1;
	int start = *line;
	if ((str = r_file_slurp (file, NULL))) {
		r_num_irand ();
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				//here rand doesn't have any security implication
				// https://www.securecoding.cert.org/confluence/display/c/MSC30-C.+Do+not+use+the+rand()+function+for+generating+pseudorandom+numbers
				if (!(r_num_rand ((++(*line))))) {
					selection = (*line - 1);  /* The line we want. */
				}
			}
		}
		if ((selection < start) || (selection == -1)) {
			free (str);
			return NULL;
		} else {
			lines = selection - start;
		}
		if (lines > 0) {
			for (i = 0; str[i] && lines; i++) {
				if (str[i] == '\n') {
					lines--;
				}
			}
			ptr = str + i;
			for (i = 0; ptr[i]; i++) {
				if (ptr[i] == '\n') {
					ptr[i] = '\0';
					break;
				}
			}
			ptr = strdup (ptr);
		}
		free (str);
	}
	return ptr;
}

R_API char *r_file_slurp_line(const char *file, int line, int context) {
	r_return_val_if_fail (file, NULL);
	int i, lines = 0;
	size_t sz;
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			free (str);
			return NULL;
		}
		lines = line - 1;
		for (i = 0; str[i]&&lines; i++) {
			if (str[i] == '\n') {
				lines--;
			}
		}
		ptr = str+i;
		for (i = 0; ptr[i]; i++) {
			if (ptr[i] == '\n') {
				ptr[i] = '\0';
				break;
			}
		}
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

R_API char *r_file_slurp_lines_from_bottom(const char *file, int line) {
	r_return_val_if_fail (file, NULL);
	int i, lines = 0;
	size_t sz;
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			return strdup (str);	// number of lines requested in more than present, return all
		}
		i--;
		for (; str[i] && line; i--) {
			if (str[i] == '\n') {
				line--;
			}
		}
		ptr = str+i;
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

R_API char *r_file_slurp_lines(const char *file, int line, int count) {
	r_return_val_if_fail (file, NULL);
	int i, lines = 0;
	size_t sz;
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			free (str);
			return NULL;
		}
		lines = line - 1;
		for (i = 0; str[i]&&lines; i++) {
			if (str[i] == '\n') {
				lines--;
			}
		}
		ptr = str+i;
		for (i = 0; ptr[i]; i++) {
			if (ptr[i] == '\n') {
				if (count) {
					count--;
				} else {
					ptr[i] = '\0';
					break;
				}
			}
		}
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

R_API char *r_file_root(const char *root, const char *path) {
	r_return_val_if_fail (root && path, NULL);
	char *ret, *s = r_str_replace (strdup (path), "..", "", 1);
	// XXX ugly hack
	while (strstr (s, "..")) {
		s = r_str_replace (s, "..", "", 1);
	}
	while (strstr (s, "./")) {
		s = r_str_replace (s, "./", "", 1);
	}
	while (strstr (s, "//")) {
		s = r_str_replace (s, "//", "", 1);
	}
	ret = r_str_append (strdup (root), R_SYS_DIR);
	ret = r_str_append (ret, s);
	free (s);
	return ret;
}

R_API bool r_file_hexdump(const char *file, const ut8 *buf, int len, int append) {
	FILE *fd;
	int i,j;
	if (!file || !*file || !buf || len < 0) {
		eprintf ("r_file_hexdump file: %s buf: %p\n", file, buf);
		return false;
	}
	if (append) {
		fd = r_sandbox_fopen (file, "ab");
	} else {
		r_sys_truncate (file, 0);
		fd = r_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return false;
	}
	for (i = 0; i < len; i += 16) {
		int l = R_MIN (16, len - i);
		fprintf (fd, "0x%08"PFMT64x"  ", (ut64)i);
		for (j = 0; j + 2 <= l; j += 2) {
			fprintf (fd, "%02x%02x ", buf[i +j], buf[i+j+1]);
		}
		if (j < l) {
			fprintf (fd, "%02x   ", buf[i + j]);
			j += 2;
		}
		if (j < 16) {
			fprintf (fd, "%*s ", (16 - j) / 2 * 5, "");
		}
		for (j = 0; j < 16; j++) {
			fprintf (fd, "%c", j < l && IS_PRINTABLE (buf[i + j])? buf[i+j]: '.');
		}
		fprintf (fd, "\n");
	}
	fclose (fd);
	return true;
}

R_API bool r_file_touch(const char *file) {
	r_return_val_if_fail (file, false);
	return r_file_dump (file, NULL, 0, true);
}

R_API bool r_file_dump(const char *file, const ut8 *buf, int len, bool append) {
	r_return_val_if_fail (!R_STR_ISEMPTY (file), false);
	FILE *fd;
	if (append) {
		fd = r_sandbox_fopen (file, "ab");
	} else {
		r_sys_truncate (file, 0);
		fd = r_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return false;
	}
	if (buf) {
		if (len < 0) {
			len = strlen ((const char *)buf);
		}
		if (len > 0 && fwrite (buf, len, 1, fd) != 1) {
			r_sys_perror ("r_file_dump: fwrite: error\n");
			fclose (fd);
			return false;
		}
	}
	fclose (fd);
	return true;
}

R_API bool r_file_move(const char *src, const char *dst) {
	r_return_val_if_fail (!R_STR_ISEMPTY (src) && !R_STR_ISEMPTY (dst), false);
	if (r_sandbox_enable (0)) {
		return false;
	}
	// rename fails when files are in different mountpoints
	// in this situation it needs to be copied and removed
	if (rename (src, dst) != 0) {
		char *a = r_str_escape (src);
		char *b = r_str_escape (dst);
		char *input = r_str_newf ("\"%s\" \"%s\"", a, b);
#if __WINDOWS__
		int rc = r_sys_cmdf ("move %s", input);
#else
		int rc = r_sys_cmdf ("mv %s", input);
#endif
		free (a);
		free (b);
		return rc == 0;
	}
	return true;
}

R_API bool r_file_rm(const char *file) {
	r_return_val_if_fail (!R_STR_ISEMPTY (file), false);
	if (r_sandbox_enable (0)) {
		return false;
	}
	if (r_file_is_directory (file)) {
#if __WINDOWS__
		LPTSTR file_ = r_sys_conv_utf8_to_win (file);
		bool ret = RemoveDirectory (file_);

		free (file_);
		return !ret;
#else
		return !rmdir (file);
#endif
	} else {
#if __WINDOWS__
		LPTSTR file_ = r_sys_conv_utf8_to_win (file);
		bool ret = DeleteFile (file_);

		free (file_);
		return !ret;
#else
		return !unlink (file);
#endif
	}
}

R_API char *r_file_readlink(const char *path) {
	r_return_val_if_fail (!R_STR_ISEMPTY (path), false);
	if (!r_sandbox_enable (0)) {
#if __UNIX__
		int ret;
		char pathbuf[4096] = {0};
		strncpy (pathbuf, path, sizeof (pathbuf) - 1);
		repeat:
		ret = readlink (path, pathbuf, sizeof (pathbuf)-1);
		if (ret != -1) {
			pathbuf[ret] = 0;
			path = pathbuf;
			goto repeat;
		}
		return strdup (pathbuf);
#endif
	}
	return NULL;
}

R_API int r_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len) {
#if __WINDOWS__
	HANDLE fh = INVALID_HANDLE_VALUE;
	DWORD written = 0;
	LPTSTR file_ = NULL;
	int ret = -1;

	if (r_sandbox_enable (0)) {
		return -1;
	}
	file_ = r_sys_conv_utf8_to_win (file);
	fh = CreateFile (file_, GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (fh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("r_file_mmap_write/CreateFile");
		goto err_r_file_mmap_write;
	}
	SetFilePointer (fh, addr, NULL, FILE_BEGIN);
	if (!WriteFile (fh, buf, (DWORD)len,  &written, NULL)) {
		r_sys_perror ("r_file_mmap_write/WriteFile");
		goto err_r_file_mmap_write;
	}
	ret = len;
err_r_file_mmap_write:
	free (file_);
	if (fh != INVALID_HANDLE_VALUE) {
		CloseHandle (fh);
	}
	return ret;
#elif __UNIX__
	int fd = r_sandbox_open (file, O_RDWR|O_SYNC, 0644);
	const int pagesize = getpagesize ();
	int mmlen = len + pagesize;
	int rest = addr % pagesize;
        ut8 *mmap_buf;
	if (fd == -1) {
		return -1;
	}
	if ((st64)addr < 0) {
		return -1;
	}
	mmap_buf = mmap (NULL, mmlen*2, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)addr - rest);
	if (((int)(size_t)mmap_buf) == -1) {
		return -1;
	}
	memcpy (mmap_buf+rest, buf, len);
	msync (mmap_buf+rest, len, MS_INVALIDATE);
	munmap (mmap_buf, mmlen*2);
	close (fd);
	return len;
#else
	return -1;
#endif
}

R_API int r_file_mmap_read (const char *file, ut64 addr, ut8 *buf, int len) {
#if __WINDOWS__
	HANDLE fm = NULL, fh = INVALID_HANDLE_VALUE;
	LPTSTR file_ = NULL;
	int ret = -1;
	if (r_sandbox_enable (0)) {
		return -1;
	}
	file_ = r_sys_conv_utf8_to_win (file);
	fh = CreateFile (file_, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (fh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("r_file_mmap_read/CreateFile");
		goto err_r_file_mmap_read;
	}
	fm = CreateFileMapping (fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!fm) {
		r_sys_perror ("CreateFileMapping");
		goto err_r_file_mmap_read;
	}
	ut8 *obuf = MapViewOfFile (fm, FILE_MAP_READ, 0, 0, len);
	if (!obuf) {
		goto err_r_file_mmap_read;
	}
	memcpy (obuf, buf, len);
	UnmapViewOfFile (obuf);
	ret = len;
err_r_file_mmap_read:
	if (fh != INVALID_HANDLE_VALUE) {
		CloseHandle (fh);
	}
	if (fm) {
		CloseHandle (fm);
	}
	free (file_);
	return ret;
#elif __UNIX__
	int fd = r_sandbox_open (file, O_RDONLY, 0644);
	const int pagesize = 4096;
	int mmlen = len+pagesize;
	int rest = addr%pagesize;
	ut8 *mmap_buf;
	if (fd == -1) {
		return -1;
	}
	mmap_buf = mmap (NULL, mmlen*2, PROT_READ, MAP_SHARED, fd, (off_t)addr-rest);
	if (((int)(size_t)mmap_buf) == -1) {
		return -1;
	}
	memcpy (buf, mmap_buf+rest, len);
	munmap (mmap_buf, mmlen*2);
	close (fd);
	return len;
#endif
	return 0;
}

#if __UNIX__
static RMmap *r_file_mmap_unix (RMmap *m, int fd) {
	ut8 empty = m->len == 0;
	m->buf = mmap (NULL, (empty?BS:m->len) ,
		m->rw?PROT_READ|PROT_WRITE:PROT_READ,
		MAP_SHARED, fd, (off_t)m->base);
	if (m->buf == MAP_FAILED) {
		m->buf = NULL;
	}
	return m;
}
#elif __WINDOWS__
static RMmap *r_file_mmap_windows(RMmap *m, const char *file) {
	LPTSTR file_ = r_sys_conv_utf8_to_win (file);
	bool success = false;

	m->fh = CreateFile (file_, GENERIC_READ | (m->rw ? GENERIC_WRITE : 0),
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (m->fh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("CreateFile");
		goto err_r_file_mmap_windows;
	}
	m->fm = CreateFileMapping (m->fh, NULL, PAGE_READONLY, 0, 0, NULL);
		//m->rw?PAGE_READWRITE:PAGE_READONLY, 0, 0, NULL);
	if (!m->fm) {
		r_sys_perror ("CreateFileMapping");
		goto err_r_file_mmap_windows;

	}
	m->buf = MapViewOfFile (m->fm,
		// m->rw?(FILE_MAP_READ|FILE_MAP_WRITE):FILE_MAP_READ,
		FILE_MAP_COPY,
		UT32_HI (m->base), UT32_LO (m->base), 0);
	success = true;
err_r_file_mmap_windows:
	if (!success) {
		if (m->fh != INVALID_HANDLE_VALUE) {
			CloseHandle (m->fh);
		}
		R_FREE (m);
	}
	free (file_);
	return m;
}
#else
static RMmap *file_mmap_other (RMmap *m) {
	ut8 empty = m->len == 0;
	m->buf = malloc ((empty? BS: m->len));
	if (!empty && m->buf) {
		lseek (m->fd, (off_t)0, SEEK_SET);
		read (m->fd, m->buf, m->len);
	} else {
		R_FREE (m);
	}
	return m;
}
#endif

R_API RMmap *r_file_mmap_arch(RMmap *mmap, const char *filename, int fd) {
#if __WINDOWS__
	(void)fd;
	return r_file_mmap_windows (mmap, filename);
#elif __UNIX__
	(void)filename;
	return r_file_mmap_unix (mmap, fd);
#else
	(void)filename;
	(void)fd;
	return file_mmap_other (mmap);
#endif
}

// TODO: add rwx support?
R_API RMmap *r_file_mmap(const char *file, bool rw, ut64 base) {
	RMmap *m = NULL;
	int fd = -1;
	if (!rw && !r_file_exists (file)) {
		return m;
	}
	fd = r_sandbox_open (file, rw? O_RDWR: O_RDONLY, 0644);
	if (fd == -1 && !rw) {
		eprintf ("r_file_mmap: file does not exis.\n");
		//m->buf = malloc (m->len);
		return m;
	}
	m = R_NEW (RMmap);
	if (!m) {
		if (fd != -1) {
			close (fd);
		}
		return NULL;
	}
	m->base = base;
	m->rw = rw;
	m->fd = fd;
	m->len = fd != -1? lseek (fd, (off_t)0, SEEK_END) : 0;
	m->filename = strdup (file);

	if (m->fd == -1) {
		return m;
	}

	if (m->len == (off_t)-1) {
		close (fd);
		R_FREE (m);
		return NULL;
	}
#if __UNIX__
	return r_file_mmap_unix (m, fd);
#elif __WINDOWS__
	close (fd);
	m->fd = -1;
	return r_file_mmap_windows (m, file);
#else
	return file_mmap_other (m);
#endif
}

R_API void r_file_mmap_free(RMmap *m) {
	if (!m) {
		return;
	}
#if __WINDOWS__
	if (m->fm != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fm);
	}
	if (m->fh != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fh);
	}
	if (m->buf) {
		UnmapViewOfFile (m->buf);
	}
#endif
	if (m->fd == -1) {
		free (m);
		return;
	}
	free (m->filename);
#if __UNIX__
	munmap (m->buf, m->len);
#endif
	close (m->fd);
	free (m);
}

R_API char *r_file_temp(const char *prefix) {
	if (!prefix) {
		prefix = "";
	}
	char *path = r_file_tmpdir ();
	char *res = r_str_newf ("%s/%s.%"PFMT64x, path, prefix, r_time_now ());
	free (path);
	return res;
}

R_API int r_file_mkstemp(R_NULLABLE const char *prefix, char **oname) {
	int h = -1;
	char *path = r_file_tmpdir ();
	if (!prefix) {
		prefix = "r2";
	}
#if __WINDOWS__
	LPTSTR name = NULL;
	LPTSTR path_ = r_sys_conv_utf8_to_win (path);
	LPTSTR prefix_ = r_sys_conv_utf8_to_win (prefix);

	name = (LPTSTR)malloc (sizeof (TCHAR) * (MAX_PATH + 1));
	if (!name) {
		goto err_r_file_mkstemp;
	}
	if (GetTempFileName (path_, prefix_, 0, name)) {
		char *name_ = r_sys_conv_win_to_utf8 (name);
		h = r_sandbox_open (name_, O_RDWR|O_EXCL|O_BINARY, 0644);
		if (oname) {
			if (h != -1) {
				*oname = name_;
			} else {
				*oname = NULL;
				free (name_);
			}
		} else {
			free (name_);
		}
	}
err_r_file_mkstemp:
	free (name);
	free (path_);
	free (prefix_);
#else
	char pfxx[1024];
	const char *suffix = strchr (prefix, '*');

	if (suffix) {
		suffix++;
		r_str_ncpy (pfxx, prefix, (size_t)(suffix - prefix));
		prefix = pfxx;
	} else {
		suffix = "";
	}

	char *name = r_str_newf ("%s/r2.%s.XXXXXX%s", path, prefix, suffix);
	mode_t mask = umask (S_IWGRP | S_IWOTH);
	if (suffix && *suffix) {
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && 2 <= __GLIBC__ && 19 <= __GLIBC__MINOR__
		h = mkstemps (name, strlen (suffix));
#else
		char *const xpos = strrchr (name, 'X');
		const char c = (char)(NULL != xpos ? *(xpos + 1) : 0);
		if (0 != c) {
			xpos[1] = 0;
			h = mkstemp (name);
			xpos[1] = c;
		} else {
			h = -1;
		}
#endif
	} else {
		h = mkstemp (name);
	}
	umask (mask);
	if (oname) {
		*oname = (h!=-1)? strdup (name): NULL;
	}
	free (name);
#endif
	free (path);
	return h;
}

R_API char *r_file_tmpdir(void) {
#if __WINDOWS__
	LPTSTR tmpdir;
	char *path = NULL;
	DWORD len = 0;

	tmpdir = (LPTSTR)calloc (1, sizeof (TCHAR) * (MAX_PATH + 1));
	if (!tmpdir) {
		return NULL;
	}
	if ((len = GetTempPath (MAX_PATH + 1, tmpdir)) == 0) {
		path = r_sys_getenv ("TEMP");
		if (!path) {
			path = strdup ("C:\\WINDOWS\\Temp\\");
		}
	} else {
		tmpdir[len] = 0;
		DWORD (WINAPI *glpn)(LPCTSTR, LPCTSTR, DWORD) = r_lib_dl_sym (GetModuleHandle (TEXT ("kernel32.dll")), W32_TCALL("GetLongPathName"));
		if (glpn) {
			// Windows XP sometimes returns short path name
			glpn (tmpdir, tmpdir, MAX_PATH + 1);
		}
		path = r_sys_conv_win_to_utf8 (tmpdir);
	}
	free (tmpdir);
	// Windows 7, stat() function fail if tmpdir ends with '\\'
	if (path) {
		size_t path_len = strlen (path);
		if (path_len > 0 && path[path_len - 1] == '\\') {
			path[path_len - 1] = '\0';
		}
	}
#else
	char *path = r_sys_getenv ("TMPDIR");
	if (path && !*path) {
		R_FREE (path);
	}
	if (!path) {
#if __ANDROID__
		path = strdup ("/data/data/org.radare.radare2installer/radare2/tmp");
#else
		path = strdup ("/tmp");
#endif
	}
#endif
	if (!r_file_is_directory (path)) {
		eprintf ("Cannot find temporary directory '%s'\n", path);
	}
	return path;
}

R_API bool r_file_copy(const char *src, const char *dst) {
	/* TODO: implement in C */
	/* TODO: Use NO_CACHE for iOS dyldcache copying */
#if HAVE_COPYFILE_H
	return copyfile (src, dst, 0, COPYFILE_DATA | COPYFILE_XATTR) != -1;
#elif __WINDOWS__
	PTCHAR s = r_sys_conv_utf8_to_win (src);
	PTCHAR d = r_sys_conv_utf8_to_win (dst);
	if (!s || !d) {
		R_LOG_ERROR ("r_file_copy: Failed to allocate memory\n");
		free (s);
		free (d);
		return false;
	}
	bool ret = CopyFile (s, d, 0);
	if (!ret) {
		r_sys_perror ("r_file_copy");
	}
	free (s);
	free (d);
	return ret;
#else
	char *src2 = r_str_replace (strdup (src), "'", "\\'", 1);
	char *dst2 = r_str_replace (strdup (dst), "'", "\\'", 1);
	int rc = r_sys_cmdf ("cp -f '%s' '%s'", src2, dst2);
	free (src2);
	free (dst2);
	return rc == 0;
#endif
}

R_API bool r_file_dir_recursive(RList *dst, const char *dir) {
	bool ret = false;
	char *cwd = r_sys_getdir ();
	if (!cwd) {
		return false;
	}
	if (r_sys_chdir (dir) == false) {
		free (cwd);
		return ret;
	}
	RList *files = r_sys_dir (".");
	RListIter *iter;
	char *name;
	r_return_val_if_fail (files, false);
	r_list_foreach (files, iter, name) {
		if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0) {
			continue;
		}
		r_list_append (dst, r_file_abspath (name));
		if (r_file_is_directory (name)) {
			ret = r_file_dir_recursive (dst, name);
		}
	}
	r_sys_chdir (cwd);
	return ret;
}

static void recursive_search_glob(const char *path, const char *glob, RList* list, int depth) {
	if (depth < 1) {
		return;
	}
	char* file;
	RListIter *iter;
	RList *dir = r_sys_dir (path);
	r_list_foreach (dir, iter, file) {
		if (!strcmp (file, ".") || !strcmp (file, "..")) {
			continue;
		}
		char *filename = malloc (strlen (path) + strlen (file) + 2);
		strcpy (filename, path);
		strcat (filename, file);
		if (r_file_is_directory (filename)) {
			strcat (filename, R_SYS_DIR);
			recursive_search_glob (filename, glob, list, depth - 1);
			free (filename);
		} else if (r_str_glob (file, glob)) {
			r_list_append (list, filename);
		} else {
			free (filename);
		}
	}
	r_list_free (dir);
}

R_API RList* r_file_globsearch(const char *_globbed_path, int maxdepth) {
	char *globbed_path = strdup (_globbed_path);
	RList *files = r_list_newf (free);
	char *glob = strchr (globbed_path, '*');
	if (!glob) {
		r_list_append (files, strdup (globbed_path));
	} else {
		*glob = '\0';
		char *last_slash = (char *)r_str_last (globbed_path, R_SYS_DIR);
		*glob = '*';
		char *path, *glob_ptr;
		if (last_slash) {
			glob_ptr = last_slash + 1;
			if (globbed_path[0] == '~') {
				char *rpath = r_str_newlen (globbed_path + 2, last_slash - globbed_path - 1);
				path = r_str_home (r_str_get (rpath));
				free (rpath);
			} else {
				path = r_str_newlen (globbed_path, last_slash - globbed_path + 1);
			}
		} else {
			glob_ptr = globbed_path;
			path = r_str_newf (".%s", R_SYS_DIR);
		}

		if (!path) {
			r_list_free (files);
			free (globbed_path);
			return NULL;
		}

		if (*(glob + 1) == '*') {  // "**"
			recursive_search_glob (path, glob_ptr, files, maxdepth);
		} else {                   // "*"
			recursive_search_glob (path, glob_ptr, files, 1);
		}
		free (path);
	}
	free (globbed_path);
	return files;
}
