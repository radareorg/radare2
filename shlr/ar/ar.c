/* radare - LGPLv3 - Copyright 2017 - xarkes */
#include <stdio.h>
#include <r_util.h>
#include "ar.h"

#define BUF_SIZE 512

const char *AR_MAGIC_HEADER = "!<arch>\n";
const char *AR_FILE_HEADER_END = "`\n";
const int AR_FILENAME_LEN = 16;

/* Used to lookup filename table */
static int index_filename = -2;

/**
 * Open an ar/lib file. If filename is NULL, list archive files
 */
R_API RBuffer *ar_open_file(const char *arname, const char *filename) {
	int r;
	RList *files = NULL;
	RBuffer *b = r_buf_new_file (arname, 0);
	if (!b) {
		r_sys_perror (__FUNCTION__);
		return NULL;
	}

	/* Read magic header */
	char *buffer = calloc (1, BUF_SIZE + 1);
	if (!buffer) {
		return NULL;
	}
	r = ar_read_header (b, buffer);
	if (!r) {
		goto fail;
	}
	files = r_list_new ();
	/* Parse archive */
	ar_read_file (b, buffer, true, NULL, NULL);
	ar_read_filename_table (b, buffer, files, filename);

	/* If b->base is set, then we found the file root in the archive */
	while (r && !b->base) {
		r = ar_read_file (b, buffer, false, files, filename);
	}

	if (!filename) {
		RListIter *iter;
		char *name;
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
		ar_read (b, buffer, AR_FILENAME_LEN);
	} else {
		ar_read (b, buffer, 2);
		/* Fix padding issues */
		if (*buffer == '\n') {
			buffer[0] = buffer[1];
			b->cur--;
			ar_read (b, buffer, 2);
		}
		ar_read (b, buffer + 2, AR_FILENAME_LEN - 2);
	}
	buffer[AR_FILENAME_LEN] = '\0';
	/* Fix some padding issues */
	if (buffer[AR_FILENAME_LEN - 1] != '/' && buffer[AR_FILENAME_LEN - 1] != ' ') {
		// Find padding offset
		tmp = (char *)r_str_lchr (buffer, ' ');
		if (!tmp) {
			goto fail;
		}
		int dif = (int) (tmp - buffer);
		dif = 31 - dif;
		// Re-read the whole filename
		b->cur -= dif;
		r = ar_read (b, buffer, AR_FILENAME_LEN);
	}
	free (curfile);
	curfile = strdup (buffer);
	if (!curfile) {
		goto fail;
	}
	/* If /XX then refer to filename table later */
	if (curfile[0] == '/' && curfile[1] >= '0' && curfile[1] <= '9') {
		index = strtoul (buffer + 1, NULL, 10);
	} else if (curfile[0] != '/') {
		/* Read filename */
		tmp = strchr (curfile, '/');
		if (!tmp) {
			goto fail;
		}
		*tmp = '\0';
		if (files) {
			r_list_append (files, strdup (curfile));
		}
	}
	/* Timestamp 12
	 * Owner ID   6
	 * Group ID   6
	 * File Mode  8
	 * File Size 10
	 * Header end 2 */
	r = ar_read (b, buffer, 44);
	if (r != 44) {
		goto fail;
	}

	filesize = strtoull (buffer + 32, &tmp, 10);

	/* Header end */
	if (strncmp (buffer + 42, AR_FILE_HEADER_END, 2)) {
		goto fail;
	}

	/* File content */
	if (!lookup && filename) {
		/* Check filename */
		if (index == index_filename || !strcmp (curfile, filename)) {
			b->length = filesize;
			b->base = b->cur;
			free (curfile);
			return b->length;
		}
	}
	r = ar_read (b, buffer, 1);

	b->cur += filesize - 1;
	free (curfile);
	return filesize;
fail:
	free (curfile);
	return 0;
}

int ar_read_filename_table(RBuffer *b, char *buffer, RList *files, const char *filename) {
	int r = ar_read (b, buffer, AR_FILENAME_LEN);
	if (r != AR_FILENAME_LEN) {
		return 0;
	}
	if (strncmp (buffer, "//", 2)) {
		// What we read was not a filename table, just go back
		b->cur -= AR_FILENAME_LEN;
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
