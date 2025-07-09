/* radare - LGPL - Copyright 2007-2025 - pancake */

#define R_LOG_ORIGIN "util.file"

#include <r_util.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <r_lib.h>
#if R2__UNIX__
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

#if R2__UNIX__ && !defined(__serenity__)
#define RDWR_FLAGS O_RDWR | O_SYNC
#else
#define RDWR_FLAGS O_RDWR
#endif

#define BS 1024

static int file_stat(const char *file, struct stat* const pStat) {
	R_RETURN_VAL_IF_FAIL (file && pStat, -1);
#if R2__WINDOWS__
	wchar_t *wfile = r_utf8_to_utf16 (file);
	if (!wfile) {
		return -1;
	}
	int ret = _wstat (wfile, (struct _stat64i32 *)pStat);
	free (wfile);
	return ret;
#else
	return stat (file, pStat);
#endif
}

// r_file_new("", "bin", NULL) -> /bin
// r_file_new(".", "bin", NULL) -> ./bin
// r_file_new("/", "bin", NULL) -> //bin # shall we be stricts?
R_API char *r_file_new(const char *root, ...) {
	va_list ap;
	va_start (ap, root);
	RStrBuf *sb = r_strbuf_new ("");
	if (!strcmp (root, "~")) {
		char *h = r_file_home (NULL);
		if (!h) {
			va_end (ap);
			r_strbuf_free (sb);
			return NULL;
		}
		r_strbuf_append (sb, h);
		free (h);
	} else {
		r_strbuf_append (sb, root);
	}
	const char *arg = va_arg (ap, char *);
	if (arg) {
		if (!r_str_endswith (r_strbuf_get (sb), R_SYS_DIR)) {
			r_strbuf_append (sb, R_SYS_DIR);
		}
	}
	while (arg) {
		if (!r_str_endswith (r_strbuf_get (sb), R_SYS_DIR)) {
			r_strbuf_append (sb, R_SYS_DIR);
		}
		r_strbuf_append (sb, arg);
		arg = va_arg (ap, char *);
	}
	va_end (ap);
	char *path = r_strbuf_drain (sb);
	char *abs = r_file_abspath (path);
	free (path);
	return abs;
}

R_API bool r_file_truncate(const char *filename, ut64 newsize) {
	R_RETURN_VAL_IF_FAIL (filename, false);
	if (r_file_is_directory (filename)) {
		return false;
	}
	if (!r_file_exists (filename) || !r_file_is_regular (filename)) {
		return false;
	}
	int fd = r_sandbox_open (filename, RDWR_FLAGS, 0644);
	if (fd == -1) {
		return false;
	}
#if defined(_MSC_VER) || R2__WINDOWS__
	int r = _chsize (fd, newsize);
#else
	int r = ftruncate (fd, newsize);
#endif
	if (r != 0) {
		R_LOG_ERROR ("Could not resize %s file", filename);
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
	R_RETURN_VAL_IF_FAIL (path, NULL);
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
	R_RETURN_VAL_IF_FAIL (path, NULL);
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
	R_RETURN_VAL_IF_FAIL (file, false);
	const char *ext = r_str_lchr (file, '.'); // TODO: add api in r_file_extension or r_str_ext for this
	if (ext) {
		ext++;
		if (!strcmp (ext, "cparse") || !strcmp (ext, "c") || !strcmp (ext, "h")) {
			return true;
		}
	}
	return false;
}

R_API bool r_file_is_regular(const char *str) {
	struct stat buf = {0};
	if (R_STR_ISEMPTY (str) || file_stat (str, &buf) == -1) {
		return false;
	}
	return ((S_IFREG & buf.st_mode) == S_IFREG);
}

R_API bool r_file_is_directory(const char *str) {
	struct stat buf = {0};
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (str), false);
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

// TODO: rename to existf .. or maybe not
R_API bool r_file_fexists(const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (fmt, false);
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
	R_RETURN_VAL_IF_FAIL (str, false);
	return r_file_is_regular (str);
}

R_API ut64 r_file_size(const char *str) {
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (str), 0);
	struct stat buf = {0};
	if (file_stat (str, &buf) != 0) {
		return 0;
	}
	return (ut64)buf.st_size;
}

R_API bool r_file_is_abspath(const char *file) {
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (file), 0);
	return ((*file && file[1] == ':') || *file == '/');
}

R_API char *r_file_abspath_rel(const char *cwd, const char *file) {
	char *ret = NULL;
	if (R_STR_ISEMPTY (file) || !strcmp (file, ".") || !strcmp (file, "./")) {
		return r_sys_getdir ();
	}
	if (strstr (file, "://")) {
		return strdup (file);
	}
	if (r_str_startswith (file, "~/") || r_str_startswith (file, "~\\")) {
		ret = r_file_home (file + 2);
	} else {
#if R2__UNIX__
		if (cwd && *file != '/') {
			ret = r_str_newf ("%s" R_SYS_DIR "%s", cwd, file);
		}
#elif R2__WINDOWS__
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
					R_LOG_ERROR ("r_file_abspath/GetFullPathName: Path to file too long");
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
#if R2__UNIX__ && !__wasi__
	char *abspath = realpath (ret, NULL);
	if (abspath) {
		free (ret);
		ret = abspath;
	}
#endif
	return ret;
}

R_API char *r_file_abspath(const char *file) {
	R_RETURN_VAL_IF_FAIL (file, NULL);
	char *cwd = r_sys_getdir ();
	if (cwd) {
		char *ret = r_file_abspath_rel (cwd, file);
		free (cwd);
		return ret;
	}
	// v-- if getcwd returns null we fallback like this
	return strdup (file);
}

R_API char *r_file_binsh(void) {
	char *bin_sh = r_sys_getenv ("SHELL");
	if (R_STR_ISEMPTY (bin_sh)) {
		free (bin_sh);
		bin_sh = r_file_path ("sh");
		if (!bin_sh) {
			bin_sh = strdup (SHELL_PATH);
		}
	}
	return bin_sh;
}

// Returns bin location in PATH, NULL if not found
R_API char *r_file_path(const char *bin) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	char *file = NULL;
	char *path = NULL;
	char *str, *ptr;
	const char *extension = "";
	if (r_str_startswith (bin, "./")) {
		return r_file_exists (bin)
			? r_file_abspath (bin)
			: NULL;
	}
	char *path_env = r_sys_getenv ("PATH");
#if R2__WINDOWS__
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
			}
			file = r_str_newf (R_JOIN_2_PATHS ("%s", "%s%s"), str, bin, extension);
			if (r_file_exists (file)) {
				free (path);
				free (path_env);
				return file;
			}
			if (ptr) {
				str = ptr + 1;
			}
			free (file);
		} while (ptr);
	}
	free (path_env);
	free (path);
	return NULL;
}

R_API char *r_stdin_readline(int *sz) {
	int l = 0;
	RStrBuf *sb = r_strbuf_new ("");
	*sz = 0;
	if (!sb) {
		return NULL;
	}
	char buf[4096];
	for (;;) {
		int n = read (0, buf, sizeof (buf));
		if (n < 1) {
			r_strbuf_free (sb);
			return NULL;
		}
		r_strbuf_append_n (sb, buf, n);
		l += n;
		if (0 && buf[n - 1] == '\n') {
			l--;
			buf[n - 1] = 0;
			break;
		}
		if (n < sizeof (buf)) {
			break;
		}
	}
	*sz = l;
	// NOTE that r_strbuf_drain uses r_str_ndup which chops strings with null bytes
	char *res = r_mem_dup (r_strbuf_getbin (sb, NULL), l + 1);
	r_strbuf_free (sb);
	return res;
}

R_API char *r_stdin_slurp(int *sz) {
#if (R2__UNIX__ || R2__WINDOWS__) && !__wasi__
	int i, ret;
	char *buf = NULL;
#if R2__WINDOWS__
	int stdinfd = _fileno (stdin);
	int omode = _setmode (stdinfd, _O_BINARY);
#else
	int stdinfd = fileno (stdin);
#endif
	int newfd = dup (stdinfd);
	if (newfd < 0) {
		goto beach;
	}
	buf = malloc (BS);
	if (!buf) {
		close (newfd);
		goto beach;
	}
	for (i = ret = 0; i >= 0; i += ret) {
		char *nbuf = realloc (buf, i + BS);
		if (!nbuf) {
			R_LOG_WARN ("Realloc fail %d", i + BS);
			R_FREE (buf);
			goto beach;
		}
		buf = nbuf;
		ret = read (stdinfd, buf + i, BS);
		if (ret < 1) {
			break;
		}
	}
	if (i < 1) {
		i = 0;
		R_FREE (buf);
	} else {
		buf[i] = 0;
		dup2 (newfd, stdinfd);
		close (newfd);
	}
	if (sz) {
		*sz = i;
	}
	if (!i) {
		R_FREE (buf);
	}
beach:
#if R2__WINDOWS__
	_setmode (_fileno (stdin), omode);
#endif
	return buf;
#else
#warning TODO r_stdin_slurp
	return NULL;
#endif
}

// returns null terminated buffer with contents of the file
R_API char *r_file_slurp(const char *str, size_t * R_NULLABLE usz) {
	R_RETURN_VAL_IF_FAIL (str, NULL);
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
#if __wasi__
	fclose (fd);
	fd = r_sandbox_fopen (str, "rb");
	if (!fd) {
		return NULL;
	}
#endif
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
				fclose (fd);
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
		R_LOG_WARN ("r_file_slurp: fread: truncated read (%d / %d)", (int)rsz, (int)sz);
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
	R_RETURN_VAL_IF_FAIL (str, NULL);
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
	R_RETURN_VAL_IF_FAIL (str, NULL);
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

R_API char *r_file_slurp_range(const char *file, ut64 off, int sz, int *osz) {
	if (sz < 1) {
		return NULL;
	}
	size_t read_items;
	FILE *fd = r_sandbox_fopen (file, "rb");
	if (!fd) {
		return NULL;
	}
	// XXX handle out of bound reads (eof)
	if (fseek (fd, off, SEEK_SET) < 0) {
		fclose (fd);
		return NULL;
	}
	char *ret = (char *) malloc (sz + 1);
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
	R_RETURN_VAL_IF_FAIL (file, NULL);
	int i = 0;
	return r_file_slurp_random_line_count (file, &i);
}

R_API char *r_file_slurp_random_line_count(const char *file, int *line) {
	R_RETURN_VAL_IF_FAIL (file && line, NULL);
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

R_API bool r_file_dump_line(const char *file, int line, const char *msg, bool replace) {
	R_RETURN_VAL_IF_FAIL (file, false);
	if (!msg || !*msg) {
		return false;
	}
	RStrBuf *sb = r_strbuf_new ("");
	int i, lines = 0;
	size_t sz;
	if (line > 0) {
		line--;
	}
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
#if 0
		if (line > lines) {
			free (str);
			eprintf ("lieav lines\n");
			return NULL;
		}
#endif
		lines = line - 1;
		for (i = 0; str[i] && lines > 0; i++) {
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
		r_strbuf_append_n (sb, ptr, i);
		r_strbuf_append (sb, "\n");
		r_strbuf_append (sb, msg);
		r_strbuf_append (sb, "\n");
		if (!replace) {
			r_strbuf_append (sb, ptr);
		}
		r_strbuf_append (sb, ptr + i + 1);
		free (str);
	}
	int sblen = r_strbuf_length (sb);
	char *res = r_strbuf_drain (sb);
	eprintf ("%s\n", res);
	bool rc = r_file_dump (file, (const ut8*)res, sblen, false);
	free (res);
	return rc;
}

R_API char *r_file_slurp_line(const char *file, int line, int context) {
	R_RETURN_VAL_IF_FAIL (file, NULL);
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
	R_RETURN_VAL_IF_FAIL (file, NULL);
	int i, lines = 0;
	size_t sz;
	if (line < 1) {
		return strdup ("");
	}
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		r_str_trim (str);
		for (i = 0; str[i]; i++) {
			if (str[i] == '\n') {
				lines++;
			}
		}
		if (line > lines) {
			return str;	// number of lines requested in more than present, return all
		}
		i--;
		line++;
		for (; str[i] && line; i--) {
			if (str[i] == '\n') {
				line--;
			}
		}
		ptr = str + i;
		ptr = strdup (ptr + 2);
		free (str);
	}
	return ptr;
}

R_API char *r_file_slurp_lines(const char *file, int line, int count) {
	R_RETURN_VAL_IF_FAIL (file, NULL);
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
		for (i = 0; str[i] && lines; i++) {
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
	R_RETURN_VAL_IF_FAIL (root && path, NULL);
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
		R_LOG_ERROR ("r_file_hexdump file: %s buf: %p", file, buf);
		return false;
	}
	if (append) {
		fd = r_sandbox_fopen (file, "ab");
	} else {
		r_sys_truncate (file, 0);
		fd = r_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		R_LOG_ERROR ("Cannot open '%s' for writing", file);
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
	R_RETURN_VAL_IF_FAIL (file, false);
	return r_file_dump (file, NULL, 0, true);
}

R_API bool r_file_dump(const char *file, const ut8 *buf, int len, bool append) {
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (file), false);
	FILE *fd;
	if (append) {
		fd = r_sandbox_fopen (file, "ab");
	} else {
		r_sys_truncate (file, 0);
		fd = r_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		R_LOG_ERROR ("Cannot open '%s' for writing", file);
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
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (src) && !R_STR_ISEMPTY (dst), false);
	if (r_sandbox_enable (0)) {
		return false;
	}
	// rename fails when files are in different mountpoints
	// in this situation it needs to be copied and removed
	if (rename (src, dst) != 0) {
		char *a = r_str_escape (src);
		char *b = r_str_escape (dst);
		char *input = r_str_newf ("\"%s\" \"%s\"", a, b);
#if R2__WINDOWS__
		int rc = r_sys_cmdf ("move %s", input);
#else
		int rc = r_sys_cmdf ("mv %s", input);
#endif
		free (a);
		free (b);
		free (input);
		return rc == 0;
	}
	return true;
}

R_API bool r_file_rm(const char *file) {
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (file), false);
	if (r_sandbox_enable (0)) {
		return false;
	}
	if (r_file_is_directory (file)) {
#if R2__WINDOWS__
		LPTSTR file_ = r_sys_conv_utf8_to_win (file);
		bool ret = RemoveDirectory (file_);

		free (file_);
		return !ret;
#else
		return !rmdir (file);
#endif
	} else {
#if R2__WINDOWS__
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
	R_RETURN_VAL_IF_FAIL (!R_STR_ISEMPTY (path), false);
	if (!r_sandbox_enable (0)) {
#if R2__UNIX__
		int ret;
		char pathbuf[4096] = {0};
		r_str_ncpy (pathbuf, path, sizeof (pathbuf));
		for (;;) {
			ret = readlink (path, pathbuf, sizeof (pathbuf)-1);
			if (ret == -1) {
				break;
			}
			pathbuf[ret] = 0;
			path = pathbuf;
		}
		return strdup (pathbuf);
#endif
	}
	return NULL;
}

// TODO: rename to r_file_mmap_resize
R_API bool r_file_mmap_resize(RMmap *m, ut64 newsize) {
#if R2__WINDOWS__
	if (m->fm != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fm);
		m->fm = INVALID_HANDLE_VALUE;
	}
	if (m->fh != INVALID_HANDLE_VALUE) {
		CloseHandle (m->fh);
		m->fh = INVALID_HANDLE_VALUE;
	}
	if (m->buf) {
		UnmapViewOfFile (m->buf);
		m->buf = NULL; // Mark as unmapped
	}
	if (!r_sys_truncate (m->filename, newsize)) {
		return false;
	}
	m->len = newsize;
	return r_file_mmap_fd (m, m->filename, m->fd);
#elif R2__UNIX__ && !__wasi__
	size_t oldlen = m->len;
	void *oldbuf = m->buf;
	
	// First unmap the current mapping
	if (oldbuf && oldlen > 0) {
		if (munmap (oldbuf, oldlen) != 0) {
			return false;
		}
		m->buf = NULL; // Mark as unmapped
	}
	
	// Then truncate the file
	if (!r_sys_truncate (m->filename, newsize)) {
		return false;
	}
	
	// Update length and remap
	m->len = newsize;
	return r_file_mmap_fd (m, m->filename, m->fd);
#else
	if (!r_sys_truncate (m->filename, newsize)) {
		return false;
	}
	m->len = newsize;
	return r_file_mmap_fd (m, m->filename, m->fd);
#endif
}

R_API int r_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len) {
#if R2__WINDOWS__
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
#elif __wasi__ || EMSCRIPTEN
	return -1;
#elif R2__UNIX__
	int fd = r_sandbox_open (file, RDWR_FLAGS, 0644);
	const int pagesize = getpagesize ();
	int mmlen = len + pagesize;
	int rest = addr % pagesize;
	if (fd == -1) {
		return -1;
	}
	if ((st64)addr < 0) {
		return -1;
	}
	ut8 *mmap_buf = mmap (NULL, mmlen * 2, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)addr - rest);
	if (((int)(size_t)mmap_buf) == -1) {
		return -1;
	}
	memcpy (mmap_buf + rest, buf, len);
#if !defined(__serenity__)
	msync (mmap_buf + rest, len, MS_INVALIDATE);
#endif
	munmap (mmap_buf, mmlen * 2);
	close (fd);
	return len;
#else
	return -1;
#endif
}

// R2_600 - TODO implement this for rbufmmap
R_API int r_file_mmap_read(RMmap *m, ut64 addr, ut8 *buf, int len) {
	R_LOG_TODO ("Implement RFile.mmapRead");
#if R2__WINDOWS__
	// TODO
#elif __wasi__ || EMSCRIPTEN
	return 0;
#elif R2__UNIX__
	// dandandan
	// flock+fstat+memcpy+funlock
	return 0;
#else
	return 0;
#endif
}

R_API int r_file_slurp_mmap(const char *file, ut64 addr, ut8 *buf, int len) {
#if R2__WINDOWS__
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
#elif __wasi__ || EMSCRIPTEN
	return 0;
#elif R2__UNIX__
	int fd = r_sandbox_open (file, O_RDONLY, 0644);
	const int pagesize = 4096;
	int mmlen = len + pagesize;
	int rest = addr % pagesize;
	if (fd == -1) {
		return -1;
	}
	ut8 *mmap_buf = mmap (NULL, mmlen * 2, PROT_READ, MAP_SHARED, fd, (off_t)addr - rest);
	if (((int)(size_t)mmap_buf) == -1) {
		return -1;
	}
	memcpy (buf, mmap_buf + rest, len);
	munmap (mmap_buf, mmlen * 2);
	close (fd);
	return len;
#else
	return 0;
#endif
}

#if __wasi__ || EMSCRIPTEN
static bool r_file_mmap_unix(RMmap *m, int fd) {
	return false;
}
#elif R2__UNIX__
static bool r_file_mmap_unix(RMmap *m, int fd) {
	const bool empty = m->len == 0;
	const int perm = m->rw? PROT_READ | PROT_WRITE: PROT_READ;
	void *map = mmap (NULL, (empty? BS: m->len), perm,
		MAP_SHARED, fd, (off_t)m->base);
	if (map == MAP_FAILED) {
		m->buf = NULL;
		m->len = 0;
		return false;
	}
	m->buf = map;
	return true;
}
#elif R2__WINDOWS__
static bool r_file_mmap_windows(RMmap *m, const char *file) {
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
	return success;
}
#else
static bool file_mmap_other(RMmap *m) {
	ut8 empty = m->len == 0;
	m->buf = malloc ((empty? BS: m->len));
	if (!empty && m->buf) {
		lseek (m->fd, (off_t)0, SEEK_SET);
		read (m->fd, m->buf, m->len);
		return true;
	}
	R_FREE (m);
	return false;
}
#endif

// XXX _arch is a very badname
R_API bool r_file_mmap_fd(RMmap *mmap, const char *filename, int fd) {
#if R2__WINDOWS__
	(void)fd;
	return r_file_mmap_windows (mmap, filename);
#elif R2__UNIX__
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
	if (!rw && !r_file_exists (file)) {
		return NULL;
	}
	int fd = r_sandbox_open (file, rw? RDWR_FLAGS: O_RDONLY, 0644);
	if (fd == -1 && !rw) {
		R_LOG_ERROR ("r_file_mmap: file (%s) does not exist", file);
		//m->buf = malloc (m->len);
		return NULL;
	}
	RMmap *m = R_NEW (RMmap);
	m->base = base;
	m->rw = rw;
	m->fd = fd;
	m->len = fd != -1? lseek (fd, (off_t)0, SEEK_END) : 0;
	m->filename = strdup (file);
	lseek (fd, 0, SEEK_SET);

	if (m->fd == -1) {
		return m;
	}

	if (m->len == (off_t)-1) {
		close (fd);
		R_FREE (m);
		return NULL;
	}
	bool res = false;
#if R2__UNIX__
	res = r_file_mmap_unix (m, fd);
#elif R2__WINDOWS__
	close (fd);
	m->fd = -1;
	res = r_file_mmap_windows (m, file);
#else
	res = file_mmap_other (m);
#endif
	if (!res) {
		free (m);
		m = NULL;
	}
	return m;
}

R_API ut64 r_file_mmap_size(RMmap *m) {
#if R2__UNIX__
	struct stat st;
	if (fstat (m->fd, &st) == 0) {
		m->len = st.st_size;
		return m->len;
	}
	// XXX maybe unsafe
	return m->len;
#else
	return m->len;
#endif
}

R_API void r_file_mmap_free(RMmap *m) {
	if (!m) {
		return;
	}
#if R2__WINDOWS__
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
#if R2__UNIX__ && !__wasi__
	munmap (m->buf, m->len);
#endif
	close (m->fd);
	free (m);
}

R_API char *r_file_temp(const char * R_NULLABLE prefix) {
	if (!prefix) {
		prefix = "";
	}
	char *path = r_file_tmpdir ();
	char *res = r_str_newf ("%s/%s.%"PFMT64x, path, prefix, r_time_now ());
	free (path);
	return res;
}

R_API char *r_file_temp_ex(const char * R_NULLABLE prefix, const char * R_NULLABLE ex) {
	prefix = R_STR_ISEMPTY (prefix)? "r2": prefix;
	ex = R_STR_ISEMPTY (ex)? "": ex;
	char *path = r_file_tmpdir ();
	char *res = NULL;
	if (path) {
		ut64 t = r_time_now ();
		res = r_str_newf ("%s/%s.%" PFMT64x "%s", path, prefix, t, ex);
		free (path);
	}
	return res;
}

static inline char *file_fmt_split(const char *fmt) {
	if (R_STR_ISEMPTY (fmt)) {
		return r_file_temp_ex (NULL, NULL);
	}
	char *name = NULL;
	char *dup = strdup (fmt);
	if (dup) {
		RList *splt = r_str_split_list (dup, "*", 2);
		if (splt && r_list_length (splt)) {
			char *pref = r_list_pop_head (splt);
			char *ex = r_list_pop_head (splt);
			name = r_file_temp_ex (pref, ex);
		}
		r_list_free (splt);
		free (dup);
	}
	return name;
}

R_API int r_file_mkstemp(const char * R_NULLABLE prefix, char **oname) {
	int h = -1;
	if (!prefix) {
		prefix = "r2";
	}
#if R2__WINDOWS__
	LPTSTR name = NULL;
	char *path = r_file_tmpdir ();
	if (!path) {
		return -1;
	}
	LPTSTR path_ = r_sys_conv_utf8_to_win (path);
	free (path);
	LPTSTR prefix_ = r_sys_conv_utf8_to_win (prefix);

	name = (LPTSTR)malloc (sizeof (TCHAR) * (MAX_PATH + 1));
	if (!name) {
		goto err_r_file_mkstemp;
	}
	if (GetTempFileName (path_, prefix_, 0, name)) {
		char *name_ = r_sys_conv_win_to_utf8 (name);
		h = r_sandbox_open (name_, RDWR_FLAGS | O_EXCL | O_BINARY, 0644);
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
#elif __wasi__
	// nothing to do for wasm, drops to return -1
#else
	char *name = file_fmt_split (prefix);
	if (name) {
		int perm = RDWR_FLAGS | O_CREAT | O_EXCL | O_BINARY;
		h = r_sandbox_open (name, perm, 0644);
		if (h != -1) {
			*oname = name;
		} else {
			free (name);
		}
	}
#endif
	return h;
}

R_API char *r_file_tmpdir(void) {
#if R2__WINDOWS__
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
	char *path = r_sys_getenv ("XDG_RUNTIME_DIR");
	if (R_STR_ISEMPTY (path)) {
		free (path);
		path = r_sys_getenv ("TMPDIR");
		if (path && !*path) {
			R_FREE (path);
		}
	}
	if (!path) {
#if __ANDROID__
		if (r_file_is_directory (TERMUX_PREFIX "/tmp")) {
			path = strdup (TERMUX_PREFIX "/tmp");
		} else {
			path = strdup ("/data/local/tmp");
		}
#else
		path = strdup ("/tmp");
#endif
	}
#endif
	if (!r_file_is_directory (path)) {
		free (path);
		return NULL;
		//R_LOG_ERROR ("Cannot find dir.tmp '%s'", path);
	}
	return path;
}

R_API bool r_file_copy(const char *src, const char *dst) {
	R_RETURN_VAL_IF_FAIL (R_STR_ISNOTEMPTY (src) && R_STR_ISNOTEMPTY (dst), false);
	if (!strcmp (src, dst)) {
		R_LOG_ERROR ("Cannot copy file '%s' to itself", src);
		return false;
	}
	/* TODO: implement in C */
	/* TODO: Use NO_CACHE for iOS dyldcache copying */
#if HAVE_COPYFILE_H
	return copyfile (src, dst, 0, COPYFILE_DATA | COPYFILE_XATTR) != -1;
#elif R2__WINDOWS__
	PTCHAR s = r_sys_conv_utf8_to_win (src);
	PTCHAR d = r_sys_conv_utf8_to_win (dst);
	if (!s || !d) {
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

static bool dir_recursive(RList *dst, const char *dir) {
	char *name, *path = NULL;
	RListIter *iter;
	bool ret = true;
	RList *files = r_sys_dir (dir);
	if (!files) {
		return false;
	}
	r_list_foreach (files, iter, name) {
		if (!strcmp (name, "..") || !strcmp (name, ".")) {
			continue;
		}
		path = r_str_newf ("%s" R_SYS_DIR "%s", dir, name);
		if (!path) {
			ret = false;
			break;
		}
		if (!r_list_append (dst, strdup (path))) {
			ret = false;
			break;
		}
		if (r_file_is_directory (path)) {
			if (!dir_recursive (dst, path)) {
				ret = false;
				break;
			}
		}
		R_FREE (path);
	}
	free (path);
	r_list_free (files);
	return ret;
}

R_API RList *r_file_lsrf(const char *dir) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	if (!dir_recursive (ret, dir)) {
		r_list_free (ret);
		return NULL;
	}
	return ret;
}

R_API bool r_file_rm_rf(const char *dir) {
	if (r_file_exists (dir)) {
		return r_file_rm (dir);
	}
	RList *files = r_file_lsrf (dir);
	if (!files) {
		return false;
	}
	r_list_sort (files, (RListComparator) strcmp);
	RListIter *iter;
	char *f;
	r_list_foreach_prev (files, iter, f)  {
		r_file_rm (f);
	}
	r_list_free (files);
	return r_file_rm (dir);
}

static void recursive_glob(const char *path, const char *glob, RList* list, int depth) {
	if (depth < 1) {
		return;
	}
	char* file;
	RListIter *iter;
	RList *files = r_sys_dir (path);
	r_list_foreach (files, iter, file) {
		if (!strcmp (file, ".") || !strcmp (file, "..")) {
			continue;
		}
		char *filename = r_file_new (path, file, NULL);
		if (r_file_is_directory (filename)) {
			recursive_glob (filename, glob, list, depth - 1);
			free (filename);
		} else if (r_str_glob (file, glob)) {
			r_list_append (list, filename);
		} else {
			free (filename);
		}
	}
	r_list_free (files);
}

R_API RList* r_file_glob(const char *_globbed_path, int maxdepth) {
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
				char *rpath = R_STR_NDUP (globbed_path + 2, last_slash - globbed_path - 1);
				path = r_file_home (r_str_get (rpath));
				free (rpath);
			} else {
				path = R_STR_NDUP (globbed_path, last_slash - globbed_path + 1);
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
			recursive_glob (path, glob_ptr, files, maxdepth);
		} else {            // "*"
			recursive_glob (path, glob_ptr, files, 1);
		}
		free (path);
	}
	free (globbed_path);
	return files;
}

#if R2__UNIX__
static bool is_executable_header(const char *file) {
	bool ret = false;
	int osz = 0;
	char *data = r_file_slurp_range (file, 0, 1024, &osz);
	if (data && osz > 4) {
		// 0xfeedface 0xcefaedfe) // 32bit
		// 0xfeedfacf 0xcffaedfe) // 64bit
		if (!memcmp (data, "\xca\xfe\xba\xbe", 4)) {
			ret = true;
		} else if (!memcmp (data, "#!/", 3)) {
			ret = true;
		} else if (!memcmp (data, "\x7f" "ELF", 4)) {
			ret = true;
		}
	}
	free (data);
	return ret;
}
#endif
R_API bool r_file_is_executable(const char *file) {
	bool ret = false;
#if R2__UNIX__
	struct stat buf = {0};
	if (stat (file, &buf) != 0) {
		return false;
	}
	if (buf.st_mode & 0111) {
		return is_executable_header (file);
	}
#elif R2__WINDOWS__
	const char *ext = r_file_extension (file);
	if (ext) {
		return !strcmp (ext, "exe") || !strcmp (ext, "com") || !strcmp (ext, "bat");
	}
#endif
	return ret;
}

R_API const char *r_file_extension(const char *str) {
	const char *dot = r_str_lchr (str, '.');
	if (dot) {
		return dot + 1;
	}
	return NULL;
}

// returns true if both files exist and f2 is modified after f1 (aka f2 > newer-than > f1)
R_API bool r_file_is_newer(const char *f1, const char *f2) {
	struct stat a1, a2;
	if (stat (f1, &a1) == -1) {
		return false;
	}
	if (stat (f2, &a2) == -1) {
		return true;
	}
	long a = a1.st_mtime;
	long b = a2.st_mtime;
	return a > b;
}
