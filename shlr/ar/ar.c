/* radare - LGPLv3 - Copyright 2017 - xarkes */
#include <stdio.h>
#include <r_util.h>
#include "ar.h"

#define AR_MAGIC_HEADER "!<arch>\n"
#define AR_FILE_HEADER_END "`\n"

typedef struct Filetable {
	char *data;
	ut64 size;
	ut64 offset;
} filetable;

static RArFp *arfp_new(RBuffer *b, ut32 *refcount) {
	r_return_val_if_fail (b, NULL);
	RArFp *f = R_NEW (RArFp);
	if (f) {
		if (refcount) {
			(*refcount)++;
		}
		f->name = NULL;
		f->refcount = refcount;
		f->buf = b;
		f->start = 0;
		f->end = 0;
	}
	return f;
}

bool ar_check_magic(RBuffer *b) {
	char buf[sizeof (AR_MAGIC_HEADER) - 1];
	if (r_buf_read (b, (ut8 *)buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	if (strncmp (buf, AR_MAGIC_HEADER, 8)) {
		eprintf ("Wrong file type.\n");
		return false;
	}
	return true;
}

static inline void arf_clean_name(RArFp *arf) {
	free (arf->name);
	arf->name = NULL;
}

static char *name_from_table(ut64 off, filetable *tbl) {
	if (off > tbl->size) {
		eprintf ("Malformed ar: name lookup out of bounds for header at offset 0x%" PFMT64x "\n", off);
		return NULL;
	}
	// files are suppose to be line feed seperated but we also stop on invalid
	// chars, such as '/' or '\0'

	char *buf = tbl->data;
	ut64 i;
	for (i = off; i < tbl->size; i++) {
		char c = buf[i];
		if (c == '\n' || c == '\0') {
			break;
		}
	}
	if (i == off) {
		return NULL;
	}
	return r_str_newlen (buf + off, i - off - 1);
}

#define VERIFY_AR_NUM_FIELD(x, s)                                                                \
	x[sizeof (x) - 1] = '\0';                                                                \
	r_str_trim_tail (x);                                                                     \
	if (x[0] != '\0' && (x[0] == '-' || !r_str_isnumber (x))) {                              \
		eprintf ("Malformed AR: bad %s in header at offset 0x%" PFMT64x "\n", s, h_off); \
		return -1;                                                                       \
	}

/* -1 error, 0 end, 1 contnue */
static int ar_parse_header(RArFp *arf, filetable *tbl, ut64 arsize) {
	r_return_val_if_fail (arf && arf->buf && tbl, -1);
	RBuffer *b = arf->buf;

	ut64 h_off = r_buf_tell (b);
	if (h_off % 2 == 1) {
		// headers start at even offset
		ut8 tmp[1];
		if (r_buf_read (b, tmp, 1) != 1 || tmp[0] != '\n') {
			return -1;
		}
		h_off++;
	}

	struct header {
		char name[16];
		char timestamp[12];
		char oid[6];
		char gid[6];
		char mode[8];
		char size[10];
		char end[2];
	} h;

	int r = r_buf_read (b, (ut8 *)&h, sizeof (h));
	if (r != sizeof (h)) {
		if (r == 0) {
			return 0; // no more file
		}
		if (r < 0) {
			eprintf ("io_ar: io error\n");
		} else {
			eprintf ("io_ar: Invalid file length\n");
		}
		return -1;
	}

	if (strncmp (h.end, AR_FILE_HEADER_END, sizeof (h.end))) {
		eprintf ("Invalid header at offset 0x%" PFMT64x ": bad end field\n", h_off);
		return -1;
	}

	// remove trailing spaces from fields and verify they are valid
	VERIFY_AR_NUM_FIELD (h.timestamp, "timestamp")
	VERIFY_AR_NUM_FIELD (h.oid, "oid")
	VERIFY_AR_NUM_FIELD (h.gid, "gid")
	VERIFY_AR_NUM_FIELD (h.mode, "mode")
	VERIFY_AR_NUM_FIELD (h.size, "size")

	if (h.size[0] == '\0') {
		eprintf ("Malformed AR: bad size in header at offset 0x%" PFMT64x "\n", h_off);
		return -1;
	}
	ut64 size = atol (h.size);

	h.timestamp[0] = '\0'; // null terminate h.name
	r_str_trim_tail (h.name);

	/*
	 * handle fake files
	*/
	if (!strcmp (h.name, "/")) {
		// skip over symbol table
		if (r_buf_seek (b, size, R_BUF_CUR) <= 0 || r_buf_tell (b) > arsize) {
			eprintf ("Malformed ar: too short\n");
			return -1;
		}
		// return next entry
		return ar_parse_header (arf, tbl, arsize);
	} else if (!strcmp (h.name, "//")) {
		// table of file names
		if (tbl->data || tbl->size != 0) {
			eprintf ("invalid ar file: two filename lookup tables (at 0x%" PFMT64x ", and 0x%" PFMT64x ")\n", tbl->offset, h_off);
			return -1;
		}
		tbl->data = (char *)malloc (size + 1);
		if (!tbl->data || r_buf_read (b, (ut8 *)tbl->data, size) != size) {
			return -1;
		}
		tbl->data[size] = '\0';
		tbl->size = size;
		tbl->offset = h_off;

		// return next entry
		return ar_parse_header (arf, tbl, arsize);
	}

	/*
	 * handle real files
	*/
	RList *list = r_str_split_duplist (h.name, "/", false); // don't strip spaces
	if (r_list_length (list) != 2) {
		r_list_free (list);
		eprintf ("invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", h_off);
		return -1;
	}

	char *tmp = r_list_pop_head (list);
	if (tmp[0] == '\0') {
		free (tmp);
		tmp = r_list_pop (list);
		if (r_str_isnumber (tmp)) {
			arf->name = name_from_table (atol (tmp), tbl);
		} else {
			eprintf ("invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", h_off);
		}
		free (tmp);
	} else {
		arf->name = tmp;
		tmp = r_list_pop (list);
		if (tmp[0]) {
			arf_clean_name (arf);
			eprintf ("invalid ar file: invalid file name in header at: 0x%" PFMT64x "\n", h_off);
		}
		free (tmp);
	}
	r_list_free (list);

	if (!arf->name) {
		return -1;
	}
	arf->start = r_buf_tell (b);
	arf->end = arf->start + size;

	// skip over file content and make sure it is all there
	if (r_buf_seek (b, size, R_BUF_CUR) <= 0 || r_buf_tell (b) > arsize) {
		eprintf ("Malformed ar: missing the end of %s (header offset: 0x%" PFMT64x ")\n", arf->name, h_off);
		arf_clean_name (arf);
		return -1;
	}

	return 1;
}
#undef VERIFY_AR_NUM_FIELD

/**
 * \brief Open specific file withen a ar/lib file.
 * \param arname the name of the .a file
 * \param filename the name of file in the .a file that you wish to open
 * \return a handle of the internal filename or NULL
 *
 * Open an ar/lib file by name. If filename is NULL, then archive files will be
 * listed.
 */
R_API RArFp *ar_open_file(const char *arname, const char *filename) {
	RBuffer *b = r_buf_new_file (arname, O_RDWR, 0);
	if (!b) {
		r_sys_perror (__FUNCTION__);
		return NULL;
	}

	r_buf_seek (b, 0, R_BUF_END);
	ut64 arsize = r_buf_tell (b);
	r_buf_seek (b, 0, R_BUF_SET);

	if (!ar_check_magic (b)) {
		r_buf_free (b);
		return NULL;
	}

	RArFp *arf = arfp_new (b, NULL);
	if (!arf) {
		r_buf_free (b);
		return NULL;
	}

	filetable tbl = {NULL, 0, 0};
	int r;
	while ((r = ar_parse_header (arf, &tbl, arsize)) > 0) {
		if (filename) {
			if (!strcmp (filename, arf->name)) {
				// found the right file
				break;
			}
		} else {
			printf ("%s\n", arf->name);
		}

		// clean RArFp for next loop
		arf_clean_name (arf);
	}

	free (tbl.data);

	if (r <= 0) {
		if (r == 0 && filename) {
			eprintf ("Cound not find file '%s' in archive '%s'\n", filename, arname);
		}
		ar_close (arf); // results in buf being free'd
		return NULL;
	}

	return arf;
}

R_API int ar_close(RArFp *f) {
	if (f) {
		free (f->name);
		if (f->refcount) {
			(*f->refcount)--;
		}

		// no more files open, clean underlying buffer
		if (!f->refcount || f->refcount == 0) {
			free (f->refcount);
			r_buf_free (f->buf);
		}
		free (f);
	}
	return 0;
}

R_API int ar_read_at(RArFp *f, ut64 off, void *buf, int count) {
	off += f->start;
	if (off > f->end) {
		return -1;
	}
	if (count + off > f->end) {
		count = f->end - off;
	}
	return r_buf_read_at (f->buf, off, buf, count);
}

R_API int ar_write_at(RArFp *f, ut64 off, void *buf, int count) {
	off += f->start;
	if (off > f->end) {
		return -1;
	}
	if (count + off > f->end) {
		count = f->end - off;
	}
	return r_buf_write_at (f->buf, off + f->start, buf, count);
}
