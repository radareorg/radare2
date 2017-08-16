/* radare - LGPLv3 - Copyright 2017 - xarkes */
#include <stdio.h>
#include <r_util.h>
#include "ar.h"

const char *AR_MAGIC_HEADER = "!<arch>\n";
const char *AR_FILE_HEADER_END = "`\n";

R_API RBuffer *ar_open_file(const char *arname, const char *filename) {
	int r;
	ut64 filesize = 0;
	char *curfile = NULL;
	char *tmp = NULL;
	RBuffer *b = r_buf_new_file (arname, 0);
	if (!b) {
		r_sys_perror (__FUNCTION__);
		return NULL;
	}

	/* Read magic header */
	char *buffer = calloc (1, 1024);
	// r = r_buf_read (b, buffer, 8);
	r = ar_read (b, buffer, 8);
	if (!r) {
		goto end;
	}
	if (strncmp (buffer, AR_MAGIC_HEADER, 8)) {
		eprintf ("Wrong file type.\n");
		goto end;
	}

	/* Read lookup table */
	while (true) {
		r = ar_read (b, buffer, 2);
		if (!r) {
			break;
		}
		/* "//" denotes the start of a filename table */
		// if (*buffer == '/' && *(buffer + 1) != '/') {
		/* File identifier */
		r = ar_read (b, buffer + 2, 14);
		free (curfile);
		curfile = strdup (buffer);
		if (!curfile) {
			goto end;
		}
		tmp = strchr (curfile, '/');
		if (!tmp) {
			goto end;
		}
		*tmp = '\0';
		if (r != 14) {
			goto end;
		}
		/* File timestamp */
		r = ar_read (b, buffer, 12);
		if (r != 12) {
			goto end;
		}
		/* Owner id */
		r = ar_read (b, buffer, 6);
		if (r != 6) {
			goto end;
		}
		/* Group id */
		r = ar_read (b, buffer, 6);
		if (r != 6) {
			goto end;
		}
		/* File mode */
		r = ar_read (b, buffer, 8);
		if (r != 8) {
			goto end;
		}
		/* File size */
		r = ar_read (b, buffer, 10);
		filesize = strtoull (buffer, &tmp, 10);
		if (r != 10) {
			goto end;
		}
		/* Header end */
		r = ar_read (b, buffer, 2);
		if (strncmp (buffer, AR_FILE_HEADER_END, 2)) {
			goto end;
		}
		/* File content */
		if (!strcmp (curfile, filename)) {
			break;
		}
		b->cur += filesize;
		// if (fseek (f, filesize, SEEK_CUR)) goto end;
		// }
	}
	free (buffer);
	b->length = filesize;
	b->base = b->cur;
	return b;
end:
	free (buffer);
	ar_close (b);
	return NULL;
}

R_API int ar_close(RBuffer *b) {
	r_buf_free (b);
	return 0;
}

R_API int ar_read_at(RBuffer *b, ut64 off, void *buf, int count) {
	return r_buf_read_at (b, off + b->base, buf, count);
}

R_API int ar_write_at(RBuffer *b, ut64 off, void *buf, int count) {
	return r_buf_write_at (b, off + b->base, buf, count);
}

int ar_read(RBuffer *b, void *dest, int len) {
	int r = r_buf_read_at (b, R_BUF_CUR, dest, len);
	if (!r) {
		return 0;
	}
	b->cur += r;
	return r;
}
