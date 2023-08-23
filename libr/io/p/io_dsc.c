/* radare - LGPL - Copyright 2008-2023 - mrmacete, pancake */

#include <r_io.h>
#include <r_lib.h>
#include "../../bin/format/mach0/dsc.c"

typedef struct {
	int fd;
	ut64 start;
	ut64 end;
} RIODscSlice;

static void r_io_dsc_slice_free(RIODscSlice * slice);

R_VEC_TYPE_WITH_FINI (RIODscSlices, RIODscSlice, r_io_dsc_slice_free);

typedef struct {
	char *filename;
	int mode;
	int perm;
	bool nocache;
	RIO *io_backref;
	RIODscSlices slices;
	ut64 total_size;
} RIODscObject;

typedef enum {
	SUBCACHE_FORMAT_UNDEFINED,
	SUBCACHE_FORMAT_V1,
	SUBCACHE_FORMAT_V2
} RDscSubcacheFormat;

typedef struct {
	ut8 uuid[16];
	ut64 cacheVMOffset;
} RDscSubcacheEntryV1;

typedef struct {
	ut8 uuid[16];
	ut64 cacheVMOffset;
	char suffix[32];
} RDscSubcacheEntryV2;

#define URL_SCHEME "dsc://"

static RIODscObject *r_io_dsc_object_new(RIO  *io, const char *filename, int perm, int mode);
static void r_io_dsc_object_free(RIODscObject *dsc);
static RDSCHeader * r_io_dsc_read_header(int fd, ut64 offset);

static int r_io_internal_read(RIODscObject * dsc, ut64 off,  ut8 *buf, int count);

static int r_io_posix_open(const char *file, int perm, int mode, bool nocache);
static int r_io_dsc_object_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static ut64 r_io_dsc_object_seek(RIO *io, RIODscObject *dsc, ut64 offset, int whence);

static bool r_io_dsc_object_dig_slices(RIODscObject * dsc);
static bool r_io_dsc_detect_subcache_format(int fd, ut32 sc_offset, ut32 sc_count, ut64 size, ut64 * out_entry_size, RDscSubcacheFormat * out_format);
static bool r_io_dsc_dig_subcache(RIODscObject * dsc, const char * filename, ut64 start, ut8 * check_uuid, ut64 * out_size);
static bool r_io_dsc_object_dig_one_slice(RIODscObject * dsc, int fd, ut64 start, ut64 end, ut8 * check_uuid, RDSCHeader * header, bool walk_monocache);
static RIODscSlice * r_io_dsc_object_get_slice(RIODscObject * dsc, ut64 off_global);

static bool is_valid_magic(ut8 magic[16]);
static bool is_null_uuid(ut8 uuid[16]);

static bool __check(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, URL_SCHEME);
}

static RIODesc *__open(RIO *io, const char *file, int perm, int mode) {
	if (*file && __check (io, file, false)) {
		RIODscObject *dsc = r_io_dsc_object_new (io, file, perm, mode);
		if (!dsc) {
			return NULL;
		}

		RIODesc *d = r_io_desc_new (io, &r_io_plugin_dsc, dsc->filename, perm, mode, dsc);
		if (!d->name) {
			d->name = strdup (dsc->filename);
		}

		return d;
	}
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	return r_io_dsc_object_read (io, fd, buf, len);
}

static bool __close(RIODesc *fd) {
	r_return_val_if_fail (fd, false);
	if (fd->data) {
		r_io_dsc_object_free ((RIODscObject *) fd->data);
		fd->data = NULL;
	}
	return true;
}

static ut64 __lseek_dsc(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	r_return_val_if_fail (fd && fd->data, UT64_MAX);
	return r_io_dsc_object_seek (io, (RIODscObject *)fd->data, offset, whence);
}

static RIODscObject *r_io_dsc_object_new(RIO  *io, const char *filename, int perm, int mode) {
	r_return_val_if_fail (io && filename, NULL);

	RIODscObject *dsc = R_NEW0 (RIODscObject);
	if (!dsc) {
		return NULL;
	}

	if (r_str_startswith (filename, URL_SCHEME)) {
		filename += strlen (URL_SCHEME);
	}

	dsc->filename = strdup (filename);
	dsc->perm = perm;
	dsc->mode = mode;
	dsc->nocache = false;
	dsc->io_backref = io;

	if (!r_io_dsc_object_dig_slices (dsc)) {
		r_io_dsc_object_free (dsc);
		return NULL;
	}

	return dsc;
}

static void r_io_dsc_object_free(RIODscObject *dsc) {
	if (dsc) {
		free (dsc->filename);
		RIODscSlices_fini (&dsc->slices);
		free (dsc);
	}
}

static bool r_io_dsc_object_dig_slices(RIODscObject * dsc) {
	int fd = r_io_posix_open (dsc->filename, O_RDONLY, dsc->mode, dsc->nocache);
	if (fd == -1) {
		return false;
	}

	RDSCHeader * header = r_io_dsc_read_header (fd, 0);
	if (!header) {
		R_LOG_ERROR ("Could not parse header");
		goto error;
	}

	ut32 subCacheArrayOffset;
	ut32 subCacheArrayCount;

	ut64 codeSignatureOffset, codeSignatureSize;
	dsc_header_get_u64 (header, "codeSignatureOffset", &codeSignatureOffset);
	dsc_header_get_u64 (header, "codeSignatureSize", &codeSignatureSize);
	ut64 next_or_end = codeSignatureOffset + codeSignatureSize;

	if (!dsc_header_get_u32 (header, "subCacheArrayOffset", &subCacheArrayOffset)) {
		// not a multi-file cache
		dsc->total_size = next_or_end;
		return r_io_dsc_object_dig_one_slice (dsc, fd, 0, next_or_end, NULL, header, false);
	} else {
		if (!dsc_header_get_u32 (header, "subCacheArrayCount", &subCacheArrayCount)) {
			R_LOG_ERROR ("Malformed multi file cache");
			goto error;
		}
		if (subCacheArrayCount == 0) {
			R_LOG_ERROR ("Please open the first file of the cache");
			goto error;
		}

		if (lseek (fd, next_or_end, SEEK_SET) >= 0) {
			ut8 tmp[16];
			if (read (fd, tmp, 16) == 16) {
				if (is_valid_magic (tmp)) {
					// cache files are cat together ("monocache")
					dsc->total_size = next_or_end;
					return r_io_dsc_object_dig_one_slice (dsc, fd, 0, next_or_end, NULL, header, true);
				}
			}
		}

		ut64 sc_entry_size;
		RDscSubcacheFormat sc_format = SUBCACHE_FORMAT_UNDEFINED;

		if (!r_io_dsc_detect_subcache_format(fd, subCacheArrayOffset, subCacheArrayCount, next_or_end, &sc_entry_size, &sc_format)) {
			R_LOG_ERROR ("Could not detect subcache entry format");
			goto error;
		}
		if (sc_format == SUBCACHE_FORMAT_UNDEFINED) {
			R_LOG_ERROR ("Ambiguous or unsupported subcache entry format");
			goto error;
		}

		ut64 cursor = 0;
		int i;

		r_io_dsc_object_dig_one_slice (dsc, fd, 0, next_or_end, NULL, header, false);
		cursor = next_or_end;

		ut64 sc_entry_cursor = subCacheArrayOffset;

		for (i = 0; i != subCacheArrayCount; i++) {
			char * suffix;
			ut8 check_uuid[16];

			if (lseek (fd, sc_entry_cursor, SEEK_SET) < 0) {
				goto error;
			}

			switch (sc_format) {
				case SUBCACHE_FORMAT_V1:
				{
					RDscSubcacheEntryV1 entry;

					if (read (fd, &entry, sc_entry_size) != sc_entry_size) {
						goto error;
					}

					suffix = r_str_newf (".%d", i + 1);
					memcpy (check_uuid, entry.uuid, 16);
					break;
				}
				case SUBCACHE_FORMAT_V2:
				{
					RDscSubcacheEntryV2 entry;

					if (read (fd, &entry, sc_entry_size) != sc_entry_size) {
						return false;
					}

					suffix = malloc (33);
					if (!suffix) {
						goto error;
					}
					memcpy (suffix, entry.suffix, 32);
					suffix[32] = 0;

					memcpy (check_uuid, entry.uuid, 16);
					break;
				}
				case SUBCACHE_FORMAT_UNDEFINED:
					suffix = NULL;
					break;
			}

			char * subcache_filename = r_str_newf ("%s%s", dsc->filename, suffix);
			free (suffix);
			if (!subcache_filename) {
				goto error;
			}
			ut64 size;
			bool success = r_io_dsc_dig_subcache (dsc, subcache_filename, cursor, check_uuid, &size);
			free (subcache_filename);
			if (!success) {
				goto error;
			}
			cursor += size;
			sc_entry_cursor += sc_entry_size;
		}

		ut8 sym_uuid[16];
		if (dsc_header_get_field (header, "symbolFileUUID", sym_uuid, 16) && !is_null_uuid (sym_uuid)) {
			ut64 size;
			char * subcache_filename = r_str_newf ("%s.symbols", dsc->filename);
			if (!subcache_filename) {
				goto error;
			}
			bool success = r_io_dsc_dig_subcache (dsc, subcache_filename, cursor, sym_uuid, &size);
			free (subcache_filename);
			if (!success) {
				goto error;
			}
			cursor += size;
		}

		dsc->total_size = cursor;
	}

	dsc_header_free (header);
	return true;

error:
	dsc_header_free (header);
	close (fd);
	return false;
}

static bool r_io_dsc_detect_subcache_format(int fd, ut32 sc_offset, ut32 sc_count, ut64 size, ut64 * out_entry_size, RDscSubcacheFormat * out_format) {
	RDscSubcacheFormat sc_format = SUBCACHE_FORMAT_UNDEFINED;
	ut64 sc_entry_size = 0;
	if (sc_count != 0) {
		ut64 array_size_v1 = sizeof (RDscSubcacheEntryV1) * sc_count;
		ut64 array_size_v2 = sizeof (RDscSubcacheEntryV2) * sc_count;
		char test_v1, test_v2;

		if (array_size_v1 + 1 >= size || array_size_v2 + 1 >= size) {
			R_LOG_ERROR ("Malformed subcache entries");
			return false;
		}
		if (lseek (fd, sc_offset + array_size_v1, SEEK_SET) < 0) {
			return false;
		}
		if (read (fd, &test_v1, 1) != 1) {
			return false;
		}
		if (lseek (fd, sc_offset + array_size_v2, SEEK_SET) < 0) {
			return false;
		}
		if (read (fd, &test_v2, 1) != 1) {
			return false;
		}

		if (test_v1 == '/' && test_v2 != '/') {
			sc_format = SUBCACHE_FORMAT_V1;
			sc_entry_size = sizeof (RDscSubcacheEntryV1);
		} else if (test_v1 != '/' && test_v2 == '/') {
			sc_format = SUBCACHE_FORMAT_V2;
			sc_entry_size = sizeof (RDscSubcacheEntryV2);
		}
	}

	*out_entry_size = sc_entry_size;
	*out_format = sc_format;

	return true;
}

static bool r_io_dsc_dig_subcache(RIODscObject * dsc, const char * filename, ut64 start, ut8 * check_uuid, ut64 * out_size) {
	int sc_fd = r_io_posix_open (filename, O_RDONLY, dsc->mode, dsc->nocache);
	if (sc_fd == -1) {
		R_LOG_ERROR ("Could not open subcache %s", filename);
		return false;
	}

	RDSCHeader * sc_header = r_io_dsc_read_header (sc_fd, 0);
	if (!sc_header) {
		close (sc_fd);
		R_LOG_ERROR ("Could not parse header");
		return false;
	}

	ut64 codeSignatureOffset, codeSignatureSize;
	dsc_header_get_u64 (sc_header, "codeSignatureOffset", &codeSignatureOffset);
	dsc_header_get_u64 (sc_header, "codeSignatureSize", &codeSignatureSize);
	ut64 size = codeSignatureOffset + codeSignatureSize;

	*out_size = size;

	if (!r_io_dsc_object_dig_one_slice (dsc, sc_fd, start, start + size, check_uuid, sc_header, false)) {
		close (sc_fd);
		dsc_header_free (sc_header);
		return false;
	}

	dsc_header_free (sc_header);
	return true;
}

static bool r_io_dsc_object_dig_one_slice(RIODscObject * dsc, int fd, ut64 start, ut64 end, ut8 * check_uuid, RDSCHeader * header, bool walk_monocache) {
	if (check_uuid) {
		ut8 uuid[16];

		if (!dsc_header_get_field (header, "uuid", uuid, 16)) {
			R_LOG_ERROR ("Malformed subcache");
			return false;
		}
		if (memcmp (uuid, check_uuid, 16) != 0) {
			R_LOG_ERROR ("Mismatched uuid for subcache");
			return false;
		}
	}

	RIODscSlice * slice = RIODscSlices_emplace_back (&dsc->slices);
	if (!slice) {
		return false;
	}

	slice->fd = fd;
	slice->start = start;

	if (walk_monocache) {
		ut64 cursor = end;

		while (true) {
			RDSCHeader * sc_header = r_io_dsc_read_header (fd, cursor);
			if (!sc_header) {
				break;
			}

			// TODO: parse rebase info

			ut64 codeSignatureOffset, codeSignatureSize;
			dsc_header_get_u64 (sc_header, "codeSignatureOffset", &codeSignatureOffset);
			dsc_header_get_u64 (sc_header, "codeSignatureSize", &codeSignatureSize);
			ut64 size = codeSignatureOffset + codeSignatureSize;

			dsc_header_free (sc_header);

			cursor += size;
		}

		slice->end = cursor;
		dsc->total_size = cursor;
	} else {
		slice->end = end;
	}

	return true;
}

static void r_io_dsc_slice_free(RIODscSlice * slice) {
	if (!slice) {
		return;
	}
	close (slice->fd);
}

static int r_io_posix_open(const char *file, int perm, int mode, bool nocache) {
	int fd;

#if R2__WINDOWS__
	fd = r_sandbox_open (file, O_RDONLY | O_BINARY, 0);
#else
	fd = r_sandbox_open (file, O_RDONLY, mode);
#endif

#ifdef F_NOCACHE
	if (nocache) {
		fcntl (fd, F_NOCACHE, 1);
	}
#endif

	return fd;
}

static int r_io_dsc_object_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	r_return_val_if_fail (fd && fd->data && buf, -1);
	if (io->off == UT64_MAX) {
		memset (buf, 0xff, count);
		return count;
	}
	RIODscObject *dsc = fd->data;
	if (!dsc) {
		return -1;
	}
	int r = r_io_internal_read (dsc, io->off, buf, count);
	if (r > 0) {
		io->off += r;
	}
	return r;
}

static int r_io_internal_read(RIODscObject * dsc, ut64 off_global, ut8 *buf, int count) {
	RIODscSlice * slice = r_io_dsc_object_get_slice(dsc, off_global);
	if (!slice) {
		return -1;
	}

	ut64 off_local = off_global - slice->start;

	if (lseek (slice->fd, off_local, SEEK_SET) < 0) {
		return -1;
	}
	return read (slice->fd, buf, count);
}

static ut64 r_io_dsc_object_seek(RIO *io, RIODscObject *dsc, ut64 offset, int whence) {
	if (!dsc || offset == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 off_global;

	switch (whence) {
		case SEEK_SET:
			off_global = offset;
			break;
		case SEEK_CUR:
			off_global = io->off + offset;
			break;
		case SEEK_END:
			off_global = dsc->total_size + offset;
			break;
	}

	RIODscSlice * slice = r_io_dsc_object_get_slice(dsc, off_global);
	if (!slice) {
		if (whence == SEEK_END && off_global >= dsc->total_size) {
			io->off = dsc->total_size;
			return io->off;
		}
		return UT64_MAX;
	}

	ut64 off_local = off_global - slice->start;
	off_local = lseek (slice->fd, off_local, SEEK_SET);
	if (off_local == UT64_MAX) {
		return UT64_MAX;
	}

	io->off = off_local + slice->start;

	return io->off;
}

static RIODscSlice * r_io_dsc_object_get_slice(RIODscObject * dsc, ut64 off_global) {
	RIODscSlice * slice;

	R_VEC_FOREACH (&dsc->slices, slice) {
		if (slice->start <= off_global && slice->end > off_global) {
			return slice;
		}
	}

	return NULL;
}

#if R2__UNIX__
static bool __is_blockdevice(RIODesc *desc) {
	return false;
}
#endif

static RDSCHeader * r_io_dsc_read_header(int fd, ut64 offset) {
	ut8 tmp[16];

	if (lseek (fd, offset, SEEK_SET) < 0) {
		return NULL;
	}
	if (read (fd, tmp, 16) != 16) {
		return NULL;
	}
	if (!is_valid_magic (tmp)) {
		return NULL;
	}
	if (read (fd, tmp, 4) != 4) {
		return NULL;
	}
	if (lseek (fd, offset, SEEK_SET) < 0) {
		return NULL;
	}

	ut32 header_size = r_read_le32 (tmp);
	if (header_size > 4096 || header_size == 0) {
		return NULL;
	}

	ut8 * header_data = malloc (header_size);

	if (read (fd, header_data, header_size) != header_size) {
		free (header_data);
		return NULL;
	}

	return dsc_header_new (header_data, header_size, dsc_header_fields);
}

static bool is_valid_magic(ut8 magic[16]) {
	return !strcmp ((char *) magic, "dyld_v1   arm64")
		|| !strcmp ((char *) magic, "dyld_v1  arm64e")
		|| !strcmp ((char *) magic, "dyld_v1  x86_64")
		|| !strcmp ((char *) magic, "dyld_v1 x86_64h");
}

static bool is_null_uuid(ut8 uuid[16]) {
	int i;
	ut64 sum = 0;
	for (i = 0; i != 16; i+= 8) {
		sum |= *(ut64*)&uuid[i];
	}
	return sum == 0;
}

RIOPlugin r_io_plugin_dsc = {
	.meta = {
		.name = "dsc",
		.desc = "Open dyld shared library caches",
		.license = "LGPL3",
	},
	.uris = URL_SCHEME,
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek_dsc,
#if R2__UNIX__
	.is_blockdevice = __is_blockdevice,
#endif
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_dsc,
	.version = R2_VERSION
};
#endif

