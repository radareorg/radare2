/* radare - LGPL - Copyright 2007-2025 - pancake */

#define R_LOG_ORIGIN "util.file"

#include <r_util.h>
#include <r_util/r_file.h>
#if R2__UNIX__
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/file.h>  /* for flock */
#include <sys/stat.h>  /* for struct stat */
#include <limits.h>
#endif

#define BS 1024

#if R2__UNIX__ && !defined(__serenity__)
#define RDWR_FLAGS O_RDWR | O_SYNC
#else
#define RDWR_FLAGS O_RDWR
#endif

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
	DWORD written = 0;
	int ret = -1;

	if (r_sandbox_enable (0)) {
		return -1;
	}
	LPTSTR file_ = r_sys_conv_utf8_to_win (file);
	HANDLE fh = CreateFile (file_, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (fh != INVALID_HANDLE_VALUE) {
		SetFilePointer (fh, addr, NULL, FILE_BEGIN);
		if (WriteFile (fh, buf, (DWORD)len, &written, NULL)) {
			ret = len;
		}
	}
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
	ut8 *mmap_buf = mmap (NULL, mmlen * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)addr - rest);
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

R_API int r_file_mmap_read(RMmap *m, ut64 addr, ut8 *buf, int len) {
#if R2__WINDOWS__
	if (!m || !buf || len < 0) {
		return -1;
	}
	/* Compute offset within mapping */
	ut64 base = m->base;
	if (addr < base) {
		return -1;
	}
	DWORD offLow = (DWORD)(addr - base);
	DWORD offHigh = (DWORD)((addr - base) >> 32);
	DWORD lenLow = (DWORD)len;
	DWORD lenHigh = 0;
	OVERLAPPED ov = {0};
	ov.Offset = offLow;
	ov.OffsetHigh = offHigh;
	/* Acquire shared lock on file region */
	if (!LockFileEx (m->fh, 0, 0, lenLow, lenHigh, &ov)) {
		return -1;
	}
	/* Get file size */
	LARGE_INTEGER filesize;
	if (!GetFileSizeEx (m->fh, &filesize)) {
		UnlockFileEx (m->fh, 0, lenLow, lenHigh, &ov);
		return -1;
	}
	ut64 limit = (ut64)filesize.QuadPart;
	if (limit > m->len) {
		limit = m->len;
	}
	{
		ut64 offset64 = (ut64)(addr - base);
		ut64 readlen = len;
		if (offset64 >= limit) {
			UnlockFileEx (m->fh, 0, lenLow, lenHigh, &ov);
			return 0;
		}
		if (offset64 + readlen > limit) {
			readlen = limit - offset64;
		}
		memcpy (buf, (const ut8*)m->buf + offset64, (size_t)readlen);
		UnlockFileEx (m->fh, 0, lenLow, lenHigh, &ov);
		return (int)readlen;
	}
#elif __wasi__ || EMSCRIPTEN
	if (!m || !buf || len < 0) {
		return -1;
	}
	/* Compute offset within mapping */
	ut64 base = m->base;
	if (addr < base) {
		return -1;
	}
	off_t off = (off_t)(addr - base);
	/* Check bounds via fstat */
	struct stat st;
	if (fstat(m->fd, &st) != 0) {
		return -1;
	}
	ut64 limit2 = (ut64)st.st_size;
	{
		ut64 off64 = (ut64)off;
		ut64 readlen = len;
		if (off64 >= limit2) {
			return 0;
		}
		if (off64 + readlen > limit2) {
			readlen = limit2 - off64;
		}
		/* Seek and read from file descriptor */
		if (lseek (m->fd, off, SEEK_SET) == (off_t)-1) {
			return -1;
		}
		ssize_t rd = read (m->fd, buf, (size_t)readlen);
		if (rd < 0) {
			return -1;
		}
		return (int)rd;
	}
#elif R2__UNIX__
	if (!m || !buf || len < 0) {
		return -1;
	}
	/* Compute offset within mapping */
	ut64 base = m->base;
	if (addr < base) {
		return -1;
	}
	off_t offset = (off_t)(addr - base);
	/* Acquire shared lock for atomic fstat+memcpy */
	if (flock (m->fd, LOCK_SH) != 0) {
		return -1;
	}
	struct stat st;
	if (fstat (m->fd, &st) != 0) {
		flock (m->fd, LOCK_UN);
		return -1;
	}
	/* Bound check: do not read past file or mapping length */
	ut64 limit = (ut64)st.st_size;
	if (limit > m->len) {
		limit = m->len;
	}
	{
		ut64 offset64 = (ut64)offset;
		ut64 readlen = len;
		if (offset64 >= limit) {
			flock (m->fd, LOCK_UN);
			return 0;
		}
		if (offset64 + readlen > limit) {
			readlen = limit - offset64;
		}
		memcpy (buf, (const ut8 *)m->buf + offset64, (size_t)readlen);
		flock (m->fd, LOCK_UN);
		return (int)readlen;
	}
#else
	return -1;
#endif
}

R_API int r_file_slurp_mmap(const char *file, ut64 addr, ut8 *buf, int len) {
#if R2__WINDOWS__
	HANDLE fm = NULL;
	int ret = -1;
	if (r_sandbox_enable (0)) {
		return -1;
	}
	LPTSTR file_ = r_sys_conv_utf8_to_win (file);
	HANDLE fh = CreateFile (file_, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
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
	if (!m->fm) {
		r_sys_perror ("CreateFileMapping");
		goto err_r_file_mmap_windows;

	}
	m->buf = MapViewOfFile (m->fm, FILE_MAP_COPY, UT32_HI (m->base), UT32_LO (m->base), 0);
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
	m->filename = strdup (file);
	if (fd == -1) {
		m->len = 0;
		return m;
	}
	off_t ores = lseek (fd, (off_t)0, SEEK_END);
	if (ores == (off_t)-1) {
		close (fd);
		R_FREE (m);
		return NULL;
	}
	m->len = ores;
	if (lseek (fd, 0, SEEK_SET) == (off_t)-1) {
		R_LOG_ERROR ("Failed to seek to beginning of file");
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
	}
#endif
	return m->len;
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
