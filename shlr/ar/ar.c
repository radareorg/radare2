/* radare - LGPLv3 - Copyright 2017 - xarkes */
#include <stdio.h>
#include <r_util.h>
#include "ar.h"

#define BUF_SIZE 512

const char *AR_MAGIC_HEADER = "!<arch>\n";
const char *AR_FILE_HEADER_END = "`\n";

/* Used to lookup filename table */
static int index_filename = -2;

/**
 * Open an ar/lib file. If filename is NULL, list archive files
 */
R_API RBuffer *ar_open_file(const char *arname, const char *filename) {
	int r;
	RBuffer *b = r_buf_new_file (arname, 0);
	if (!b) {
		r_sys_perror (__FUNCTION__);
		return NULL;
	}

	/* Read magic header */
	char *buffer = calloc (1, BUF_SIZE);
	if (!buffer) {
		return NULL;
	}
	r = ar_read_header (b, buffer);
	if (!r) {
		goto fail;
	}

	/* Parse archive */
	RList *files = r_list_new ();
	ar_read_file (b, buffer, true, NULL, NULL);
	ar_read_filename_table (b, buffer, files, filename);

	/* If b->base is set, then we found the file root in the archive */
	while (r && !b->base) {
		ar_read (b, buffer, 2);
		/* Fix padding */
		if (*buffer == '\n') {
			buffer[0] = buffer[1];
			b->cur -= 1;
			ar_read (b, buffer, 2);
		}
		r = ar_read_file (b, buffer, false, files, filename);
	}

	if (!filename) {
		RListIter *iter;
		char *name;
		puts ("Available files:\n");
		r_list_foreach (files, iter, name) {
			printf ("%s\n", name);
		}
		goto fail;
	}

	if (!r) {
		goto fail;
	}

	free (buffer);
	r_list_free (files);
	return b;
fail:
	r_list_free (files);
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

int ar_read_until_slash(RBuffer *b, char *buffer, int limit) {
	ut32 i = 0;
	ut32 lim = (limit && limit < BUF_SIZE)? limit: BUF_SIZE;
	while (i < lim) {
		ar_read (b, buffer + i, 1);
		if (buffer[i] == '/') {
			break;
		}
		i++;
	}
	buffer[i] = '\0';
	return i;
}

int ar_read_header(RBuffer *b, char *buffer) {
	int r = ar_read (b, buffer, 8);
	if (!r) {
		return 0;
	}
	if (strncmp (buffer, AR_MAGIC_HEADER, 8)) {
		eprintf ("Wrong file type.\n");
		return 0;
	}
	return r;
}

int ar_read_file(RBuffer *b, char *buffer, bool lookup, RList *files, const char *filename) {
	ut64 filesize = 0;
	char *tmp = NULL;
	char *curfile = NULL;
	ut32 index = -1;
	int r;

	/* File identifier */
	if (lookup) {
		r = ar_read (b, buffer, 16);
	} else {
		r = ar_read (b, buffer + 2, 14);
	}
	/* Fix some padding issues */
	if (buffer[15] != '/' && buffer[15] != ' ') {
		tmp = strrchr (buffer, ' ');
		int dif = (int) (tmp - buffer);
		dif = 31 - dif;
		b->cur -= dif;
		r = ar_read (b, buffer, 16);
	}
	free (curfile);
	curfile = strdup (buffer);
	if (!curfile) {
		return 0;
	}
	/* If /XX then refer to filename table later */
	if (curfile[0] == '/' && curfile[1] >= '0' && curfile[1] <= '9') {
		index = strtoul (buffer + 1, NULL, 10);
	} else if (curfile[0] != '/') {
		/* Read filename */
		tmp = strchr (curfile, '/');
		if (!tmp) {
			return 0;
		}
		*tmp = '\0';
		if (files) {
			r_list_append (files, strdup (curfile));
		}
	}
	/* File timestamp */
	r = ar_read (b, buffer, 12);
	if (r != 12) {
		return 0;
	}
	/* Owner id */
	r = ar_read (b, buffer, 6);
	if (r != 6) {
		return 0;
	}
	/* Group id */
	r = ar_read (b, buffer, 6);
	if (r != 6) {
		return 0;
	}
	/* File mode */
	r = ar_read (b, buffer, 8);
	if (r != 8) {
		return 0;
	}
	/* File size */
	r = ar_read (b, buffer, 10);
	filesize = strtoull (buffer, &tmp, 10);
	if (r != 10) {
		return 0;
	}
	/* Header end */
	r = ar_read (b, buffer, 2);
	if (strncmp (buffer, AR_FILE_HEADER_END, 2)) {
		return 0;
	}

	/* File content */
	if (!lookup && filename) {
		/* Check filename */
		if (index == index_filename || !strcmp (curfile, filename)) {
			b->length = filesize;
			b->base = b->cur;
			return b->length;
		}
	}
	r = ar_read (b, buffer, 1);

	b->cur += filesize - 1;
	return filesize;
}

int ar_read_filename_table(RBuffer *b, char *buffer, RList *files, const char *filename) {
	int r = ar_read (b, buffer, 16);
	if (r != 16) {
		return 0;
	}
	if (strncmp (buffer, "//", 2)) {
		b->cur -= 16;
		return 0;
	}

	/* Read table size */
	b->cur += 32;
	r = ar_read (b, buffer, 10);
	ut64 tablesize = strtoull (buffer, NULL, 10);

	/* Header end */
	r = ar_read (b, buffer, 2);
	if (strncmp (buffer, AR_FILE_HEADER_END, 2)) {
		return 0;
	}

	/* Read table */
	ut64 len = 0;
	ut32 index = 0;
	while (r && len < tablesize) {
		r = ar_read_until_slash (b, buffer, tablesize - len);
		if (filename && !strcmp (filename, (char *) buffer)) {
			index_filename = index;
		}
		if (*(char *) buffer == '\n') {
			break;
		}
		r_list_append (files, strdup ((char *) buffer));
		/* End slash plus separation character ("/\n") */
		len += r + 2;
		/* Separation character (not always '\n') */
		b->cur += 1;
		index++;
	}
	return len;
}
