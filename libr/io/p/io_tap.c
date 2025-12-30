/* radare - LGPL - Copyright 2025 - pancake */

#include <r_io.h>

#define URI_PREFIX "tap://"
#define TAP_HEADER_SIZE 4
#define TAP_MAGIC_EOM 0xFFFFFFFFU
#define TAP_MAGIC_MARK 0x00000000U
#define TAP_MAGIC_GAP 0xFFFFFFFEU
#define TAP_CLASS_GOOD 0x00

typedef struct tap_object_t {
	ut64 phys_off;
	ut32 type; // 0: good data, 1: bad data, 2: mark, 3: gap, 4: eom
	ut64 size;
	ut64 virt_off;
} TapObject;

#define TYPE_DATA_GOOD 0
#define TYPE_DATA_BAD 1
#define TYPE_MARK 2
#define TYPE_GAP 3
#define TYPE_EOM 4

typedef struct rio_tap_t {
	char *filename;
	ut8 *data;
	ut64 data_size;
	int mode; // 0: raw, 1: flat
	RList *objects; // RList<TapObject *>
	ut64 flat_size;
	ut64 phys_size;
} RIOTap;

static RList *parse_tap(RIOTap *ri) {
	RList *list = r_list_newf (free);
	ut64 pos = 0;
	ut64 fsize = ri->data_size;
	ri->phys_size = ri->data_size;
	ut64 virt = 0;
	while (pos + TAP_HEADER_SIZE <= fsize) {
		ut32 val = r_read_le32 (ri->data + pos);
		pos += TAP_HEADER_SIZE;
		TapObject *obj = R_NEW0 (TapObject);
		obj->phys_off = pos - TAP_HEADER_SIZE;
		obj->virt_off = virt;
		if (val == TAP_MAGIC_EOM) {
			obj->type = TYPE_EOM;
		} else if (val == TAP_MAGIC_MARK) {
			obj->type = TYPE_MARK;
		} else if (val == TAP_MAGIC_GAP) {
			obj->type = TYPE_GAP;
		} else {
			ut8 cls = (val >> 24) & 0xFF;
			ut32 n = val & 0x00FFFFFF;
			obj->type = (cls == TAP_CLASS_GOOD) ? TYPE_DATA_GOOD : TYPE_DATA_BAD;
			obj->size = n;
			ut64 pad = (n & 1) ? 1 : 0;
			ut64 next_pos = pos + n + pad + TAP_HEADER_SIZE;
			if (next_pos > fsize) {
				free (obj);
				break;
			}
			if (r_read_le32 (ri->data + pos + n + pad) != val) {
				free (obj);
				pos = next_pos;
				continue;
			}
			pos = next_pos;
			virt += n;
		}
		r_list_append (list, obj);
	}
	ri->flat_size = virt;
	return list;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, URI_PREFIX);
}

static RIODesc *__open(RIO *io, const char *pathname, int perm, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}
	if (mode & R_PERM_W) {
		R_LOG_WARN ("tap is for now just readonly");
	}
	const char *file = pathname + strlen (URI_PREFIX);
	size_t data_size = 0;
	ut8 *data = (ut8 *)r_file_slurp (file, &data_size);
	if (!data) {
		return NULL;
	}
	RIOTap *ri = R_NEW0 (RIOTap);
	ri->filename = strdup (file);
	ri->data = data;
	ri->data_size = data_size;
	ri->mode = 0; // raw by default
	ri->objects = parse_tap (ri);
	return r_io_desc_new (io, &r_io_plugin_tap, pathname, R_PERM_R, 0, ri);
}

static bool __close(RIODesc *fd) {
	if (fd && fd->data) {
		RIOTap *ri = fd->data;
		free (ri->data);
		free (ri->filename);
		r_list_free (ri->objects);
		free (ri);
		return true;
	}
	return false;
}

static ut64 __seek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data) {
		return UT64_MAX;
	}
	RIOTap *ri = fd->data;
	ut64 max = (ri->mode == 0) ? ri->phys_size : ri->flat_size;
	ut64 ret = 0;
	switch (whence) {
	case SEEK_SET: ret = offset; break;
	case SEEK_CUR: ret = io->off + offset; break;
	case SEEK_END: ret = max + offset; break;
	default: return UT64_MAX;
	}
	if (ret > max) {
		ret = max;
	}
	io->off = ret;
	return ret;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || count <= 0) {
		return -1;
	}
	RIOTap *ri = fd->data;
	if (io->off == UT64_MAX) {
		return -1;
	}
	if (ri->mode == 0) { // raw
		if (io->off >= ri->phys_size) {
			return 0;
		}
		ut64 to_read = R_MIN ((ut64)count, ri->phys_size - io->off);
		memcpy (buf, ri->data + io->off, to_read);
		return (int)to_read;
	}
	// flat
	int total_read = 0;
	ut64 voff = io->off;
	RListIter *iter;
	TapObject *obj;
	r_list_foreach (ri->objects, iter, obj) {
		if (obj->type != TYPE_DATA_GOOD && obj->type != TYPE_DATA_BAD) {
			continue;
		}
		if (voff >= obj->virt_off + obj->size) {
			continue;
		}
		ut64 rel = voff - obj->virt_off;
		ut64 to_read = R_MIN ((ut64)count - total_read, obj->size - rel);
		ut64 data_phys = obj->phys_off + TAP_HEADER_SIZE + rel; // skip leading length
		if (data_phys >= ri->phys_size) {
			break;
		}
		ut64 avail = ri->phys_size - data_phys;
		ut64 chunk = R_MIN (to_read, avail);
		memcpy (buf + total_read, ri->data + data_phys, chunk);
		total_read += chunk;
		voff += chunk;
		if (total_read >= count || chunk < to_read) {
			break;
		}
	}
	return total_read;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return -1; // Read-only for now
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
	if (!fd || !fd->data) {
		return NULL;
	}
	RIOTap *ri = fd->data;
	if (!strcmp (command, "?")) {
		return strdup (
			"?             Show this help\n"
			"mode          Show current stream mode\n"
			"mode raw      Show raw stream\n"
			"mode flat     Show concatenated data blocks\n"
			"marks         Create flags for marks and records\n");
	} else if (r_str_startswith (command, "mode ")) {
		const char *m = command + 5;
		if (!strcmp (m, "raw")) {
			ri->mode = 0;
			return NULL;
		} else if (!strcmp (m, "flat")) {
			ri->mode = 1;
			return NULL;
		}
		return strdup ("Usage: mode [raw|flat]");
	}
	if (!strcmp (command, "mode ")) {
		return strdup (ri->mode? "flat": "raw");
	}
	if (!strcmp (command, "marks")) {
		RStrBuf *sb = r_strbuf_new ("");
		int mark_idx = 0;
		int rec_idx = 0;
		RListIter *iter;
		TapObject *obj;
		r_list_foreach (ri->objects, iter, obj) {
			ut64 addr = (ri->mode == 0) ? obj->phys_off : obj->virt_off;
			if (obj->type == TYPE_MARK) {
				r_strbuf_appendf (sb, "f tape_mark_%d @ 0x%"PFMT64x"\n", mark_idx++, addr);
			} else if (obj->type == TYPE_DATA_GOOD || obj->type == TYPE_DATA_BAD) {
				r_strbuf_appendf (sb, "f record_%d %"PFMT64d" @ 0x%"PFMT64x"\n", rec_idx++, (ut64)obj->size, addr);
			}
			// Skip gaps and eom for flags
		}
		return r_strbuf_drain (sb);
	}
	return NULL;
}

RIOPlugin r_io_plugin_tap = {
	.meta = {
		.name = "tap",
		.desc = "SIMH .tap file IO plugin",
		.author = "pancake",
		.license = "LGPL3",
	},
	.uris = "tap://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __seek,
	.write = __write,
	.system = __system,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_tap,
	.version = R2_VERSION
};
#endif
