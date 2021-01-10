/* radare - LGPLv3- Copyright 2017 - xarkes */
#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_cons.h>
#include "ar.h"


static const char *r_io_get_individual_schema(const char *file) {
	if (r_str_startswith (file, "arall://")) {
		return "ar://";
	}
	if (r_str_startswith (file, "liball://")) {
		return "lib://";
	}
	return NULL;
}

static bool r_io_ar_plugin_open(RIO *io, const char *file, bool many) {
	r_return_val_if_fail (io && file, NULL);
	if (many) {
		return (r_io_get_individual_schema (file) != NULL);
	}
	return !strncmp ("ar://", file, 5) || !strncmp ("lib://", file, 6);
}

static int r_io_ar_close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	return ar_close ((RArFp *)fd->data);
}

static RIODesc *r_io_ar_open(RIO *io, const char *file, int rw, int mode) {
	r_return_val_if_fail (r_io_ar_plugin_open (io, file, false), NULL);
	const char *arname = strstr (file, "://") + 3;
	char *filename = strstr (arname, "//");
	if (filename) {
		*filename = 0;
		filename += 2;
	}

	RArFp *arf = ar_open_file (arname, filename);
	RIODesc *res = NULL;
	if (arf) {
		res = r_io_desc_new (io, &r_io_plugin_ar, file, rw, mode, arf);
		if (res) {
			res->name = strdup (filename);
		}
	}
	return res;
}

typedef struct ar_many_data {
	const char *schema;
	const char *arname;
	RIO *io;
	bool rw;
	int mode;
	RList *list;
} ar_many_data;

static int __io_ar_list(RArFp *arf, void *user) {
	ar_many_data *data = (ar_many_data *)user;
	char *uri = r_str_newf ("%s%s//%s", data->schema, data->arname, arf->name);
	RIODesc *des = r_io_desc_new (data->io, &r_io_plugin_ar, uri, data->rw, data->mode, arf);
	free (uri);

	if (!des) {
		ar_close (arf);
		return -1; // stop error
	}

	des->name = strdup (arf->name);
	if (!r_list_append (data->list, des)) {
		r_io_ar_close (des);
		return -1; // stop error
	}
	return 0; // continue
}

static RList *r_io_ar_open_many(RIO *io, const char *file, int rw, int mode) {
	r_return_val_if_fail (io && file, NULL);
	ar_many_data data;
	if ((data.schema = r_io_get_individual_schema (file)) == NULL) {
		r_warn_if_reached ();
		return NULL;
	}
	data.io = io;
	data.rw = rw;
	data.mode = mode;
	data.arname = strstr (file, "://") + 3;
	data.list = r_list_newf ((RListFree)r_io_ar_close);
	if (data.list && ar_open_all_cb (data.arname, (RArOpenManyCB)__io_ar_list, (void *)&data) < 0) {
		r_list_free (data.list);
		return NULL;
	}
	return data.list;
}

static ut64 r_io_ar_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	r_return_val_if_fail (io && fd && fd->data, -1);

	RArFp *arf = (RArFp *) fd->data;
	ut64 size = arf->end - arf->start;
	switch (whence) {
	case SEEK_SET:
		io->off = R_MIN (size, offset);
		break;
	case SEEK_CUR:
		io->off = R_MIN (size, io->off + offset);
		break;
	case SEEK_END:
		io->off = size;
		break;
	default:
		return -1;
	}

	return io->off;
}

static int r_io_ar_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	return ar_read_at ((RArFp *) fd->data, io->off, buf, count);
}

static int r_io_ar_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	return ar_write_at ((RArFp *) fd->data, io->off, (void *) buf, count);
}

RIOPlugin r_io_plugin_ar = {
	.name = "ar",
	.desc = "Open ar/lib files",
	.license = "LGPL3",
	.uris = "ar://,lib://,arall://,liball://",
	.open = r_io_ar_open,
	.open_many = r_io_ar_open_many,
	.write = r_io_ar_write,
	.read = r_io_ar_read,
	.close = r_io_ar_close,
	.lseek = r_io_ar_lseek,
	.check = r_io_ar_plugin_open
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ar,
	.version = R2_VERSION
};
#endif
