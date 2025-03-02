/* radare - LGPL - Copyright 2008-2025 - mrmacete, pancake */

#include <r_io.h>
#include <r_lib.h>
#include "../../bin/format/mach0/mach0_specs.h"
#include "../../bin/format/mach0/dsc.c"

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
} RDyldRebaseInfo;

typedef struct {
	ut64 start;
	ut64 end;
	RDyldRebaseInfo *info;
} RDyldRebaseInfosEntry;

typedef struct {
	RDyldRebaseInfosEntry *entries;
	size_t length;
} RDyldRebaseInfos;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut64 delta_mask;
	ut32 delta_shift;
	ut32 high8_shift;
	ut64 value_add;
} RDyldRebaseInfo5;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut64 delta_mask;
	ut32 delta_shift;
	ut64 auth_value_add;
} RDyldRebaseInfo3;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut16 *page_extras;
	ut32 page_extras_count;
	ut64 delta_mask;
	ut64 value_mask;
	ut32 delta_shift;
	ut64 value_add;
} RDyldRebaseInfo2;

typedef struct {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *toc;
	ut32 toc_count;
	ut8 *entries;
	ut32 entries_size;
} RDyldRebaseInfo1;

static void dsc_rebase_infos_free(RDyldRebaseInfosEntry * entry);

R_VEC_TYPE_WITH_FINI (RIODscRebaseInfos, RDyldRebaseInfosEntry, dsc_rebase_infos_free);

typedef struct {
	int fd;
	char * file_name;
	ut64 start;
	ut64 end;
	RIODscRebaseInfos rebase_infos;
} RIODscSlice;

typedef struct {
	RIODscSlice * slice;
	ut64 seek;
	ut64 count;
	ut64 buf_off;
} RIODscTrimmedSlice;

typedef struct {
	RDyldRebaseInfosEntry * info;
	ut64 off_local;
	ut64 count;
	ut64 buf_off;
} RIODscTrimmedRebaseInfo;

static void dsc_slice_free(RIODscSlice * slice);

R_VEC_TYPE_WITH_FINI (RIODscSlices, RIODscSlice, dsc_slice_free);

typedef struct {
	char *filename;
	int mode;
	int perm;
	bool nocache;
	RIO *io_backref;
	RIODscSlices slices;
	ut64 total_size;
	ut64 last_seek;
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

#define R_IS_PTR_AUTHENTICATED(x) B_IS_SET(x, 63)
#define URL_SCHEME "dsc://"

#define RIO_FREAD_AT(fd, offset, store, fmt, check) {\
	ut8 tmp[sizeof (store)]; \
	if (lseek (fd, offset, SEEK_SET) < 0) { \
		check = false; \
	} else { \
		if (read (fd, tmp, sizeof (store)) != sizeof (store)) { \
			check = false; \
		} else { \
			RBuffer * buf = r_buf_new_with_bytes (tmp, sizeof (store)); \
			if (!buf) { \
				check = false; \
			} else { \
				check = r_buf_fread_at (buf, 0, (ut8*)&store, fmt, 1) == sizeof (store); \
				r_buf_free (buf); \
			} \
		} \
	} \
}

#define RIO_FREAD_AT_INTO(fd, offset, store, fmt, size, n, check) {\
	if (lseek (fd, offset, SEEK_SET) < 0) { \
		check = false; \
	} else { \
		if (read (fd, store, size) != size) { \
			check = false; \
		} else { \
			RBuffer * buf = r_buf_new_with_bytes (store, size); \
			if (!buf) { \
				check = false; \
			} else { \
				check = r_buf_fread_at (buf, 0, (ut8*)store, fmt, n) == size; \
				r_buf_free (buf); \
			} \
		} \
	} \
}

#define RIO_FREAD_AT_INTO_DIRECT(fd, offset, store, size, check) {\
	if (lseek (fd, offset, SEEK_SET) < 0) { \
		check = false; \
	} else { \
		check = read (fd, store, size) == size; \
	} \
}

static RIODscObject *dsc_object_new(RIO  *io, const char *filename, int perm, int mode);
static void dsc_object_free(RIODscObject *dsc);
static RDSCHeader * dsc_read_header(int fd, ut64 offset);

static int r_io_internal_read(RIODscObject * dsc, ut64 off,  ut8 *buf, int count);
static int dsc_slice_read(RIODscSlice * slice, ut64 off_local, ut8 * buf, int size);
static void dsc_slice_rebase_bytes(RIODscSlice * slice, ut64 off_local, ut8 * buf, int size);
static RList * dsc_slice_get_rebase_infos_by_range(RIODscSlice * slice, ut64 off_local, int size);
static void rebase_bytes_v1(RIODscSlice * slice, RDyldRebaseInfo1 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off);
static void rebase_bytes_v2(RIODscSlice * slice, RDyldRebaseInfo2 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off);
static void rebase_bytes_v3(RIODscSlice * slice, RDyldRebaseInfo3 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off);
static void rebase_bytes_v5(RIODscSlice * slice, RDyldRebaseInfo5 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off);

static int r_io_posix_open(const char *file, int perm, int mode, bool nocache);
static int dsc_object_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static ut64 dsc_object_seek(RIO *io, RIODscObject *dsc, ut64 offset, int whence);

static bool dsc_dig_slices(RIODscObject * dsc);
static bool dsc_detect_subcache_format(int fd, ut32 sc_offset, ut32 sc_count, ut32 array_end, ut64 size, ut64 * out_entry_size, RDscSubcacheFormat * out_format);
static bool dsc_dig_subcache(RIODscObject * dsc, const char * filename, ut64 start, ut8 * check_uuid, ut64 * out_size);
static bool dsc_dig_one_slice(RIODscObject * dsc, int fd, const char * file_name, ut64 start, ut64 end, ut8 * check_uuid, RDSCHeader * header, bool walk_monocache);
static RIODscSlice * dsc_get_slice(RIODscObject * dsc, ut64 off_global);
static RList * dsc_get_slices_by_range(RIODscObject * dsc, ut64 off_global, int size);

static bool is_valid_magic(ut8 magic[16]);
static bool is_null_uuid(ut8 uuid[16]);

static bool get_rebase_infos(RIODscSlice * slice, int fd, ut64 start, RDSCHeader * header, bool monocache);
static RDyldRebaseInfo *get_rebase_info(int fd, ut64 slideInfoOffset, ut64 slideInfoSize, ut64 start_of_data, ut64 slide);
static void rebase_info_free(RDyldRebaseInfo *rebase_info);
static ut32 dumb_ctzll(ut64 x);

static bool __check(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, URL_SCHEME);
}

static RIODesc *__open(RIO *io, const char *file, int perm, int mode) {
	if (*file && __check (io, file, false)) {
		RIODscObject *dsc = dsc_object_new (io, file, perm, mode);
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
	return dsc_object_read (io, fd, buf, len);
}

static bool __close(RIODesc *fd) {
	R_RETURN_VAL_IF_FAIL (fd, false);
	if (fd->data) {
		dsc_object_free ((RIODscObject *) fd->data);
		fd->data = NULL;
	}
	return true;
}

static ut64 __lseek_dsc(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	R_RETURN_VAL_IF_FAIL (fd && fd->data, UT64_MAX);
	return dsc_object_seek (io, (RIODscObject *)fd->data, offset, whence);
}

static char *__infoPointer(RIODscObject * dsc, ut64 size, int mode) {
	PJ *pj = NULL;
	RStrBuf *sb = NULL;
	if (mode == R_MODE_JSON) {
		pj = pj_new ();
		if (!pj) {
			return NULL;
		}
	} else if (mode == R_MODE_PRINT) {
		sb = r_strbuf_new ("");
	} else {
		return NULL;
	}

	ut64 paddr = dsc->last_seek;

	RList *slices = dsc_get_slices_by_range (dsc, paddr, size);
	if (!slices) {
		pj_free (pj);
		r_strbuf_free (sb);
		return NULL;
	}

	RListIter * iter;
	RIODscTrimmedSlice * trimmed;

	if (pj) {
		pj_a (pj);
	}

	r_list_foreach (slices, iter, trimmed) {
		RList * infos = dsc_slice_get_rebase_infos_by_range (trimmed->slice, trimmed->seek, trimmed->count);
		if (!infos) {
			pj_free (pj);
			r_list_free (slices);
			r_strbuf_free (sb);
			return NULL;
		}

		RListIter * iter;
		RIODscTrimmedRebaseInfo * trimmed_info;

		r_list_foreach (infos, iter, trimmed_info) {
			ut64 remaining_size = trimmed_info->count;
			ut64 cursor = 0;
			while (remaining_size > 0) {
				ut8 raw_value_buf[8];
				bool got_raw_value;
				ut64 off_local = trimmed_info->off_local + cursor;
				RIO_FREAD_AT_INTO_DIRECT (trimmed->slice->fd, off_local, &raw_value_buf, 8, got_raw_value);
				remaining_size -= 8;
				cursor += 8;
				if (!got_raw_value) {
					R_LOG_ERROR ("reading raw pointer");
					break;
				}

				ut64 raw_value = r_read_le64 (raw_value_buf);

				if (pj) {
					pj_o (pj);
				}

				char * tmp = r_str_newf ("0x%"PFMT64x, trimmed->slice->start + off_local);
				if (pj) {
					pj_ks (pj, "paddr", tmp);
				} else if (sb) {
					r_strbuf_appendf (sb, "paddr: %s\n", tmp);
				}
				free (tmp);

				tmp = r_str_newf ("0x%"PFMT64x, raw_value);
				if (pj) {
					pj_ks (pj, "raw", tmp);
				} else if (sb) {
					r_strbuf_appendf (sb, "raw: %s\n", tmp);
				}
				free (tmp);

				tmp = r_str_newf ("v%d", trimmed_info->info->info->version);
				if (pj) {
					pj_ks (pj, "format", tmp);
				} else if (sb) {
					r_strbuf_appendf (sb, "format: %s\n", tmp);
				}
				free (tmp);

				switch (trimmed_info->info->info->version) {
				case 1:
				case 2:
				case 4:
					break;
				case 3:
					if (R_IS_PTR_AUTHENTICATED (raw_value)) {
						bool has_diversity = (raw_value & (1ULL << 48)) != 0;
						if (pj) {
							pj_kb (pj, "has_diversity", has_diversity);
						}
						if (has_diversity) {
							ut64 diversity = (raw_value >> 32) & 0xFFFF;
							if (pj) {
								pj_kn (pj, "diversity", diversity);
							} else if (sb) {
								r_strbuf_appendf (sb, "diversity: 0x%"PFMT64x"\n", diversity);
							}
						}
						ut64 key = (raw_value >> 49) & 3;
						const char * names[4] = { "ia", "ib", "da", "db" };
						if (pj) {
							pj_ks (pj, "key", names[key]);
						} else if (sb) {
							r_strbuf_appendf (sb, "key: %s\n", names[key]);
						}
					}
					break;
				case 5:
					if (R_IS_PTR_AUTHENTICATED (raw_value)) {
						bool has_diversity = (raw_value & (1ULL << 50)) != 0;
						if (pj) {
							pj_kb (pj, "has_diversity", has_diversity);
						}
						if (has_diversity) {
							ut64 diversity = (raw_value >> 34) & 0xFFFF;
							if (pj) {
								pj_kn (pj, "diversity", diversity);
							} else if (sb) {
								r_strbuf_appendf (sb, "diversity: 0x%"PFMT64x"\n", diversity);
							}
						}
						ut64 key = (raw_value >> 51) & 1;
						const char * names[2] = { "ia", "da" };
						if (pj) {
							pj_ks (pj, "key", names[key]);
						} else if (sb) {
							r_strbuf_appendf (sb, "key: %s\n", names[key]);
						}
					}
					break;
				default:
					R_LOG_ERROR ("Unsupported rebase info version %d", trimmed_info->info->info->version);
				}
				if (pj) {
					pj_end (pj);
				} else if (sb) {
					r_strbuf_append (sb, "\n");
				}
			}
		}
		r_list_free (infos);
	}

	r_list_free (slices);

	if (pj) {
		pj_end (pj);
		return pj_drain (pj);
	}
	if (sb) {
		return r_strbuf_drain (sb);
	}
	return NULL;
}

static char *__infoSubCache(RIODscObject * dsc, ut64 size, int mode) {
	PJ *pj = NULL;
	RStrBuf *sb = NULL;
	if (mode == R_MODE_JSON) {
		pj = pj_new ();
		if (!pj) {
			return NULL;
		}
	} else if (mode == R_MODE_PRINT) {
		sb = r_strbuf_new ("");
	} else {
		return NULL;
	}

	ut64 paddr = dsc->last_seek;

	RList * slices = dsc_get_slices_by_range (dsc, paddr, size);
	if (!slices) {
		r_strbuf_free (sb);
		pj_free (pj);
		return NULL;
	}

	RListIter * iter;
	RIODscTrimmedSlice * trimmed;

	if (pj) {
		pj_a (pj);
	}

	r_list_foreach (slices, iter, trimmed) {
		if (pj) {
			pj_o (pj);
		}

		if (pj) {
			pj_ks (pj, "file", trimmed->slice->file_name);
		} else {
		    r_strbuf_appendf (sb, "file: %s\n", trimmed->slice->file_name);
		}

		char * tmp = r_str_newf ("0x%"PFMT64x, trimmed->slice->start);
		if (pj) {
			pj_ks (pj, "start", tmp);
		} else if (sb) {
			r_strbuf_appendf (sb, "start: %s\n", tmp);
		}
		free (tmp);

		tmp = r_str_newf ("0x%"PFMT64x, trimmed->slice->end);
		if (pj) {
			pj_ks (pj, "end", tmp);
		} else if (sb) {
			r_strbuf_appendf (sb, "end: %s\n", tmp);
		}
		free (tmp);

		if (pj) {
			pj_end (pj);
		} else if (sb) {
			r_strbuf_append (sb, "\n");
		}
	}

	r_list_free (slices);

	if (pj) {
		pj_end (pj);
	}

	if (pj) {
		return pj_drain (pj);
	}
	if (sb) {
		return r_strbuf_drain (sb);
	}
	return NULL;
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
	R_RETURN_VAL_IF_FAIL (io && fd && fd->data && command, NULL);
	RIODscObject *dsc = (RIODscObject*) fd->data;

	if (r_str_startswith (command, "iP")) {
		ut64 size = 8;
		switch (command[2]) {
		case '?':
			io->cb_printf ("Usage: :iP[j?] [size]\n");
			io->cb_printf (" :iP?   get this help message\n");
			io->cb_printf (" :iP    show pointer metadata\n");
			io->cb_printf (" :iPj   show pointer metadata in json\n\n");
			return NULL;
		case 'j':
			if (command[3] == ' ') {
				size = r_num_math (NULL, command + 4);
			}
			return __infoPointer (dsc, size, R_MODE_JSON);
		case ' ':
			size = r_num_math (NULL, command + 3);
		case '\0':
			return __infoPointer (dsc, size, R_MODE_PRINT);
		}
	} else if (r_str_startswith (command, "iF")) {
		ut64 size = 8;
		switch (command[2]) {
		case '?':
			io->cb_printf ("Usage: :iF[j?] [size]\n");
			io->cb_printf (" :iF?   get this help message\n");
			io->cb_printf (" :iF    show info about (sub)cache file\n");
			io->cb_printf (" :iF    show info about (sub)cache file in JSON\n\n");
			return NULL;
		case 'j':
			if (command[3] == ' ') {
				size = r_num_math (NULL, command + 4);
			}
			return __infoSubCache (dsc, size, R_MODE_JSON);
		case ' ':
			size = r_num_math (NULL, command + 3);
		case '\0':
			return __infoSubCache (dsc, size, R_MODE_PRINT);
		}
	} else if (command && command[0] == '?') {
		io->cb_printf ("DSC commands are prefixed with `:` (alias for `=!`).\n");
		io->cb_printf (":iP[j?] [size]        show pointer metadata at current seek\n");
		io->cb_printf (":iF[j?] [size]        show info about (sub)cache file at current seek\n\n");
	}

	return NULL;
}

static RIODscObject *dsc_object_new(RIO  *io, const char *filename, int perm, int mode) {
	R_RETURN_VAL_IF_FAIL (io && filename, NULL);

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

	if (!dsc_dig_slices (dsc)) {
		dsc_object_free (dsc);
		return NULL;
	}

	return dsc;
}

static void dsc_object_free(RIODscObject *dsc) {
	if (dsc) {
		free (dsc->filename);
		RIODscSlices_fini (&dsc->slices);
		free (dsc);
	}
}

static bool dsc_dig_slices(RIODscObject * dsc) {
	int fd = r_io_posix_open (dsc->filename, O_RDONLY, dsc->mode, dsc->nocache);
	if (fd == -1) {
		return false;
	}

	RDSCHeader * header = dsc_read_header (fd, 0);
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
		return dsc_dig_one_slice (dsc, fd, dsc->filename, 0, next_or_end, NULL, header, false);
	} else {
		if (!dsc_header_get_u32 (header, "subCacheArrayCount", &subCacheArrayCount)) {
			R_LOG_ERROR ("Malformed multi file cache");
			goto error;
		}
		ut8 sym_uuid[16];
		bool has_symbols_file = dsc_header_get_field (header, "symbolFileUUID", sym_uuid, 16) && !is_null_uuid (sym_uuid);
		if (subCacheArrayCount == 0 && !has_symbols_file) {
			const char * slash = strrchr (dsc->filename, '/');
			const char * dot = strrchr (dsc->filename, '.');
			if (dot && slash && dot > slash) {
				R_LOG_WARN ("Please open the first file of the cache");
				goto error;
			}
		}

		if (lseek (fd, next_or_end, SEEK_SET) >= 0) {
			ut8 tmp[16];
			if (read (fd, tmp, 16) == 16) {
				if (is_valid_magic (tmp)) {
					// cache files are cat together ("monocache")
					dsc->total_size = next_or_end;
					return dsc_dig_one_slice (dsc, fd, dsc->filename, 0, next_or_end, NULL, header, true);
				}
			}
		}

		ut64 sc_entry_size;
		RDscSubcacheFormat sc_format = SUBCACHE_FORMAT_UNDEFINED;

		if (subCacheArrayCount) {
			ut32 array_end = 0;

			dsc_header_get_u32 (header, "maybePointsToLinkeditMapAtTheEndOfSubCachesArray", &array_end);

			if (!dsc_detect_subcache_format(fd, subCacheArrayOffset, subCacheArrayCount, array_end, next_or_end, &sc_entry_size, &sc_format)) {
				R_LOG_ERROR ("Could not detect subcache entry format");
				goto error;
			}
			if (sc_format == SUBCACHE_FORMAT_UNDEFINED) {
				R_LOG_ERROR ("Ambiguous or unsupported subcache entry format");
				goto error;
			}
		} else {
			sc_entry_size = 0;
		}

		ut64 cursor = 0;
		int i;

		dsc_dig_one_slice (dsc, fd, dsc->filename, 0, next_or_end, NULL, header, false);
		cursor = next_or_end;

		ut64 sc_entry_cursor = subCacheArrayOffset;

		for (i = 0; i != subCacheArrayCount; i++) {
			char * suffix = NULL;
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
				suffix = r_str_ndup (entry.suffix, 32);
				memcpy (check_uuid, entry.uuid, 16);
				break;
			}
#if 1
			// its unreachable by coverity but reachable by gcc, so it cant be commented :D
			case SUBCACHE_FORMAT_UNDEFINED:
				suffix = NULL;
				break;
#endif
			}

			char * subcache_filename = r_str_newf ("%s%s", dsc->filename, suffix);
			free (suffix);
			if (!subcache_filename) {
				goto error;
			}
			ut64 size;
			bool success = dsc_dig_subcache (dsc, subcache_filename, cursor, check_uuid, &size);
			free (subcache_filename);
			if (!success) {
				goto error;
			}
			cursor += size;
			sc_entry_cursor += sc_entry_size;
		}

		if (has_symbols_file) {
			ut64 size;
			char * subcache_filename = r_str_newf ("%s.symbols", dsc->filename);
			if (!subcache_filename) {
				goto error;
			}
			bool success = dsc_dig_subcache (dsc, subcache_filename, cursor, sym_uuid, &size);
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

static bool dsc_detect_subcache_format(int fd, ut32 sc_offset, ut32 sc_count, ut32 array_end, ut64 size, ut64 * out_entry_size, RDscSubcacheFormat * out_format) {
	RDscSubcacheFormat sc_format = SUBCACHE_FORMAT_UNDEFINED;
	ut64 sc_entry_size = 0;
	ut64 array_size_v2 = sizeof (RDscSubcacheEntryV2) * sc_count;

	if (array_end) {
		if (array_end == sc_offset + array_size_v2) {
			sc_format = SUBCACHE_FORMAT_V2;
			sc_entry_size = sizeof (RDscSubcacheEntryV2);
			goto beach;
		}
	}

	if (sc_count != 0) {
		ut64 array_size_v1 = sizeof (RDscSubcacheEntryV1) * sc_count;
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
beach:
	*out_entry_size = sc_entry_size;
	*out_format = sc_format;

	return true;
}

static bool dsc_dig_subcache(RIODscObject * dsc, const char * filename, ut64 start, ut8 * check_uuid, ut64 * out_size) {
	int sc_fd = r_io_posix_open (filename, O_RDONLY, dsc->mode, dsc->nocache);
	if (sc_fd == -1) {
		R_LOG_ERROR ("Could not open subcache %s", filename);
		return false;
	}

	RDSCHeader * sc_header = dsc_read_header (sc_fd, 0);
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

	if (!dsc_dig_one_slice (dsc, sc_fd, filename, start, start + size, check_uuid, sc_header, false)) {
		close (sc_fd);
		dsc_header_free (sc_header);
		return false;
	}

	dsc_header_free (sc_header);
	return true;
}

static bool dsc_dig_one_slice(RIODscObject * dsc, int fd, const char * file_name, ut64 start, ut64 end, ut8 * check_uuid, RDSCHeader * header, bool walk_monocache) {
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
	memset (slice, 0, sizeof (RIODscSlice));

	slice->fd = fd;
	slice->start = start;
	if (file_name) {
		slice->file_name = strdup (file_name);
	}

	if (walk_monocache) {
		ut64 cursor = start;

		while (true) {
			RDSCHeader * sc_header = dsc_read_header (fd, cursor);
			if (!sc_header) {
				break;
			}

			get_rebase_infos (slice, fd, cursor, sc_header, walk_monocache);

			ut64 codeSignatureOffset, codeSignatureSize;
			dsc_header_get_u64 (sc_header, "codeSignatureOffset", &codeSignatureOffset);
			dsc_header_get_u64 (sc_header, "codeSignatureSize", &codeSignatureSize);
			ut64 size = codeSignatureOffset + codeSignatureSize;

			dsc_header_free (sc_header);

			if ((st64)size <= 0) {
				R_LOG_ERROR ("Failed to walk sub-caches, file is corrupted");
				break;
			}

			cursor += size;
		}

		slice->end = cursor;
		dsc->total_size = cursor;
	} else {
		slice->end = end;
		get_rebase_infos (slice, fd, slice->start, header, walk_monocache);
	}

	return true;
}

static void dsc_slice_free(RIODscSlice * slice) {
	if (!slice) {
		return;
	}
	R_FREE (slice->file_name);
	close (slice->fd);
	RIODscRebaseInfos_fini (&slice->rebase_infos);
}

static void dsc_rebase_infos_free(RDyldRebaseInfosEntry * entry) {
	if (!entry) {
		return;
	}
	rebase_info_free (entry->info);
	entry->info = NULL;
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

static int dsc_object_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	R_RETURN_VAL_IF_FAIL (fd && fd->data && buf, -1);
	if (io->off == UT64_MAX) {
		memset (buf, io->Oxff, count);
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
	RList * slices = dsc_get_slices_by_range (dsc, off_global, count);
	if (!slices) {
		return -1;
	}

	RListIter * iter;
	RIODscTrimmedSlice * trimmed;
	int total = 0;
	int failures = 0;
	int index = 0;
	int n_slices = r_list_length (slices);

	r_list_foreach (slices, iter, trimmed) {
		int one_result = dsc_slice_read (trimmed->slice, trimmed->seek, buf + trimmed->buf_off, trimmed->count);
		if (one_result == -1) {
			failures++;
			if (index < n_slices - 1) {
				total += trimmed->count;
			}
		} else {
			total += one_result;
		}
		index++;
	}

	r_list_free (slices);

	if (failures == n_slices) {
		return -1;
	}

	return total;
}

static ut64 dsc_object_seek(RIO *io, RIODscObject *dsc, ut64 offset, int whence) {
	if (!dsc || offset == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 off_global;
	switch (whence) {
	case R_IO_SEEK_SET:
		off_global = offset; // XXX
		break;
	case R_IO_SEEK_CUR:
		off_global = io->off + offset; // XXX
		break;
	case R_IO_SEEK_END:
		off_global = dsc->total_size + offset; // XXX
		break;
	default:
		return UT64_MAX;
	}

	RIODscSlice * slice = dsc_get_slice (dsc, off_global);
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

	dsc->last_seek = io->off;

	return io->off;
}

static RIODscSlice *dsc_get_slice(RIODscObject * dsc, ut64 off_global) {
	RIODscSlice * slice;

	R_VEC_FOREACH (&dsc->slices, slice) {
		if (slice->start <= off_global && slice->end > off_global) {
			return slice;
		}
	}

	return NULL;
}

static RList *dsc_get_slices_by_range(RIODscObject * dsc, ut64 off_global, int size) {
	if (off_global == UT64_MAX || size == UT64_MAX || size == 0) {
		return NULL;
	}

	RList * result = r_list_new ();
	if (!result) {
		return NULL;
	}

	ut64 ffo = off_global + size;

	RIODscSlice * slice;
	R_VEC_FOREACH (&dsc->slices, slice) {
		ut64 start = slice->start;
		ut64 end = slice->end;

		if (end > off_global && start < ffo) {
			RIODscTrimmedSlice * trimmed_slice = R_NEW0 (RIODscTrimmedSlice);
			if (!trimmed_slice) {
				break;
			}

			trimmed_slice->slice = slice;

			ut64 trimmed_end = (ffo >= end) ? slice->end : ffo;
			ut64 trimmed_start = (off_global <= start) ? slice->start : off_global;

			trimmed_slice->seek = trimmed_start - slice->start;
			trimmed_slice->count = trimmed_end - trimmed_start;
			trimmed_slice->buf_off = trimmed_start - off_global;

			r_list_append (result, trimmed_slice);
		}
	}

	return result;
}

static int dsc_slice_read(RIODscSlice * slice, ut64 off_local, ut8 * buf, int size) {
	if (lseek (slice->fd, off_local, SEEK_SET) < 0) {
		return -1;
	}
	int count = read (slice->fd, buf, size);
	dsc_slice_rebase_bytes (slice, off_local, buf, count);
	return count;
}

static void dsc_slice_rebase_bytes(RIODscSlice * slice, ut64 off_local, ut8 * buf, int size) {
	RList * infos = dsc_slice_get_rebase_infos_by_range (slice, off_local, size);
	if (!infos) {
		return;
	}

	RListIter * iter;
	RIODscTrimmedRebaseInfo * trimmed;

	r_list_foreach (infos, iter, trimmed) {
		switch (trimmed->info->info->version) {
			case 1:
				rebase_bytes_v1 (slice, (RDyldRebaseInfo1 *) trimmed->info->info,
						buf, trimmed->off_local, trimmed->count, trimmed->buf_off);
				break;
			case 2:
			case 4:
				rebase_bytes_v2 (slice, (RDyldRebaseInfo2 *) trimmed->info->info,
						buf, trimmed->off_local, trimmed->count, trimmed->buf_off);
				break;
			case 3:
				rebase_bytes_v3 (slice, (RDyldRebaseInfo3 *) trimmed->info->info,
						buf, trimmed->off_local, trimmed->count, trimmed->buf_off);
				break;
			case 5:
				rebase_bytes_v5 (slice, (RDyldRebaseInfo5 *) trimmed->info->info,
						buf, trimmed->off_local, trimmed->count, trimmed->buf_off);
				break;
			default:
				R_LOG_ERROR ("Unsupported rebase info version %d", trimmed->info->info->version);
		}
	}

	r_list_free (infos);
}

static RList * dsc_slice_get_rebase_infos_by_range(RIODscSlice * slice, ut64 off_local, int size) {
	ut64 slice_size = slice->end - slice->start;
	if (off_local + size > slice_size  || size == 0) {
		return NULL;
	}

	RList * result = r_list_new ();
	if (!result) {
		return NULL;
	}

	ut64 ffo = off_local + size;

	RDyldRebaseInfosEntry * info;
	R_VEC_FOREACH (&slice->rebase_infos, info) {
		if (!info->info) {
			continue;
		}
		ut64 start = info->start;
		ut64 end = info->end;

		if (end > off_local && start < ffo) {
			RIODscTrimmedRebaseInfo * trimmed_info = R_NEW0 (RIODscTrimmedRebaseInfo);
			if (!trimmed_info) {
				break;
			}

			trimmed_info->info = info;

			ut64 trimmed_end = (ffo >= end) ? slice->end : ffo;
			ut64 trimmed_start = (off_local < start) ? slice->start : off_local;

			trimmed_info->off_local = trimmed_start;
			trimmed_info->count = trimmed_end - trimmed_start;
			trimmed_info->buf_off = trimmed_start - off_local;

			r_list_append (result, trimmed_info);
		}
	}

	return result;
}

static void rebase_bytes_v1(RIODscSlice * slice, RDyldRebaseInfo1 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off) {
	int in_buf = buf_off;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;
		ut64 entry_index = page_offset / 32;
		ut64 offset_in_entry = (page_offset % 32) / 4;

		if (entry_index >= rebase_info->entries_size) {
			in_buf += to_next_page;
			offset += to_next_page;
			continue;
		}

		if (page_index >= rebase_info->toc_count) {
			break;
		}

		ut8 *entry = &rebase_info->entries[rebase_info->toc[page_index] * rebase_info->entries_size];
		ut8 b = entry[entry_index];

		if (b & (1 << offset_in_entry)) {
			ut64 value = r_read_le64 (buf + in_buf);
			value += rebase_info->slide;
			r_write_le64 (buf + in_buf, value);
			in_buf += 8;
			offset += 8;
		} else {
			in_buf += 4;
			offset += 4;
		}
	}
}

static void rebase_bytes_v2(RIODscSlice * slice, RDyldRebaseInfo2 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off) {
	int in_buf = buf_off;
	while (in_buf < count + buf_off) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut16 page_flag = rebase_info->page_starts[page_index];

		if (page_flag == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		if (!(page_flag & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)) {
			ut64 first_rebase_off = rebase_info->page_starts[page_index] * 4;
			if (first_rebase_off < page_offset + count) {
				ut32 delta = 1;
				if (first_rebase_off < page_offset) {
					ut64 back_size = page_offset - first_rebase_off;
					ut8 * back_bytes = malloc (back_size);
					if (!back_bytes) {
						return;
					}
					bool got_back_bytes = false;
					RIO_FREAD_AT_INTO_DIRECT (slice->fd, offset - back_size, back_bytes, back_size, got_back_bytes);
					if (!got_back_bytes) {
						free (back_bytes);
						return;
					}

					int cursor = 0;
					while (delta && cursor <= back_size - 8) {
						ut64 raw_value = r_read_le64 (back_bytes + cursor);
						delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift);
						cursor += delta;
					}

					first_rebase_off += cursor;

					free (back_bytes);
				}
				while (delta) {
					ut64 position = in_buf + first_rebase_off - page_offset;
					if (position + 8 > count) {
						break;
					}
					ut64 raw_value = r_read_le64 (buf + position);
					delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift);
					if (position >= buf_off) {
						ut64 new_value = raw_value & rebase_info->value_mask;
						if (new_value != 0) {
							new_value += rebase_info->value_add;
							new_value += rebase_info->slide;
						}
						r_write_le64 (buf + position, new_value);
					}
					first_rebase_off += delta;
				}
			}
		} else {
			R_LOG_ERROR ("DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA not handled, please file a bug");
		}
next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static void rebase_bytes_v5(RIODscSlice * slice, RDyldRebaseInfo5 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off) {
	int in_buf = buf_off;
	while (in_buf < count + buf_off) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut64 delta = rebase_info->page_starts[page_index];

		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		ut64 first_rebase_off = delta;
		if (first_rebase_off < page_offset + count) {
			if (first_rebase_off < page_offset) {
				ut64 back_size = page_offset - first_rebase_off;
				ut8 * back_bytes = malloc (back_size);
				if (!back_bytes) {
					return;
				}
				bool got_back_bytes = false;
				RIO_FREAD_AT_INTO_DIRECT (slice->fd, offset - back_size, back_bytes, back_size, got_back_bytes);
				if (!got_back_bytes) {
					free (back_bytes);
					return;
				}

				int cursor = 0;
				while (cursor <= back_size - 8) {
					ut64 raw_value = r_read_le64 (back_bytes + cursor);
					delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
					cursor += delta;
					if (!delta) {
						break;
					}
				}

				first_rebase_off += cursor;

				free (back_bytes);

				if (!delta) {
					goto next_page;
				}
			}
			do {
				ut64 position = in_buf + first_rebase_off - page_offset;
				if (position + 8 > count) {
					break;
				}
				ut64 raw_value = r_read_le64 (buf + position);
				delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
				if (position >= buf_off) {
					ut64 new_value = (raw_value & 0x3ffffffff) + rebase_info->value_add + rebase_info->slide;
					if (!R_IS_PTR_AUTHENTICATED (raw_value)) {
						new_value = ((raw_value << rebase_info->high8_shift) & 0xFF00000000000000ULL) | new_value;
					}
					r_write_le64 (buf + position, new_value);
				}
				first_rebase_off += delta;
			} while (delta);
		}
next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static void rebase_bytes_v3(RIODscSlice * slice, RDyldRebaseInfo3 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 buf_off) {
	int in_buf = buf_off;
	while (in_buf < count + buf_off) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut64 delta = rebase_info->page_starts[page_index];

		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		ut64 first_rebase_off = delta;
		if (first_rebase_off < page_offset + count) {
			if (first_rebase_off < page_offset) {
				ut64 back_size = page_offset - first_rebase_off;
				ut8 * back_bytes = malloc (back_size);
				if (!back_bytes) {
					return;
				}
				bool got_back_bytes = false;
				RIO_FREAD_AT_INTO_DIRECT (slice->fd, offset - back_size, back_bytes, back_size, got_back_bytes);
				if (!got_back_bytes) {
					free (back_bytes);
					return;
				}

				int cursor = 0;
				while (cursor <= back_size - 8) {
					ut64 raw_value = r_read_le64 (back_bytes + cursor);
					delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
					cursor += delta;
					if (!delta) {
						break;
					}
				}

				first_rebase_off += cursor;

				free (back_bytes);

				if (!delta) {
					goto next_page;
				}
			}
			do {
				ut64 position = in_buf + first_rebase_off - page_offset;
				if (position + 8 > count) {
					break;
				}
				ut64 raw_value = r_read_le64 (buf + position);
				delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
				if (position >= buf_off) {
					ut64 new_value = 0;
					if (R_IS_PTR_AUTHENTICATED (raw_value)) {
						new_value = (raw_value & 0xFFFFFFFFULL) + rebase_info->auth_value_add;
						// TODO: don't throw auth info away
					} else {
						new_value = ((raw_value << 13) & 0xFF00000000000000ULL) | (raw_value & 0x7ffffffffffULL);
						new_value &= 0x00FFFFFFFFFFFFFFULL;
					}
					if (new_value != 0) {
						new_value += rebase_info->slide;
					}
					r_write_le64 (buf + position, new_value);
				}
				first_rebase_off += delta;
			} while (delta);
		}
next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

#if R2__UNIX__
static bool __is_blockdevice(RIODesc *desc) {
	return false;
}
#endif

static RDSCHeader * dsc_read_header(int fd, ut64 offset) {
	ut8 tmp[16];

	if (lseek (fd, offset, SEEK_SET) < 0) {
		R_LOG_ERROR ("Cannot seek at header offset 0x%llx", offset);
		return NULL;
	}
	if (read (fd, tmp, 16) != 16) {
		return NULL;
	}
	if (!is_valid_magic (tmp)) {
		return NULL;
	}
	if (read (fd, tmp, 4) != 4) {
		R_LOG_ERROR ("Cannot read header size at offset 0x%llx", offset + 4);
		return NULL;
	}
	if (lseek (fd, offset, SEEK_SET) < 0) {
		R_LOG_ERROR ("Cannot seek at header offset 0x%llx", offset);
		return NULL;
	}

	ut32 header_size = r_read_le32 (tmp);
	if (header_size > 4096 || header_size == 0) {
		R_LOG_ERROR ("Invalid header size at offset 0x%llx", offset + 4);
		return NULL;
	}

	ut8 * header_data = malloc (header_size);

	if (read (fd, header_data, header_size) != header_size) {
		R_LOG_ERROR ("Cannot read header data at offset 0x%llx", offset);
		free (header_data);
		return NULL;
	}

	return dsc_header_new (header_data, header_size, dsc_header_fields);
}

static bool is_valid_magic(ut8 magic[16]) {
	const char * ma = (const char *)magic;
	if (r_str_startswith (ma, "dyld_v1 ")) {
		const size_t off = strlen ("dyld_v1 ");
		const size_t left = 16 - off;
		return 0 \
			|| !strncmp (ma + off, "  arm64", left)
			|| !strncmp (ma + off, " arm64e", left)
			|| !strncmp (ma + off, " x86_64", left)
			|| !strncmp (ma + off, "x86_64h", left);
	}
	return false;
}

static bool is_null_uuid(ut8 uuid[16]) {
	int i;
	ut64 sum = 0;
	for (i = 0; i != 16; i+= 8) {
		sum |= *(ut64*)&uuid[i];
	}
	return sum == 0;
}

static bool get_rebase_infos(RIODscSlice * slice, int fd, ut64 start, RDSCHeader * header, bool monocache) {
	ut64 slideInfoOffset, slideInfoSize;
	dsc_header_get_u64 (header, "slideInfoOffsetUnused", &slideInfoOffset);
	dsc_header_get_u64 (header, "slideInfoSizeUnused", &slideInfoSize);

	if (slideInfoOffset == 0 && slideInfoSize == 0) {
		ut32 mappingWithSlideOffset, mappingWithSlideCount;
		dsc_header_get_u32 (header, "mappingWithSlideCount", &mappingWithSlideCount);
		if (mappingWithSlideCount == 0) {
			R_LOG_ERROR ("Missing slide count");
			return false;
		}
		dsc_header_get_u32 (header, "mappingWithSlideOffset", &mappingWithSlideOffset);
		if (mappingWithSlideOffset == 0) {
			R_LOG_ERROR ("Missing slide offset");
			return false;
		}
		if (monocache) {
			mappingWithSlideOffset += start;
		}

		ut32 j;
		for (j = 0; j < mappingWithSlideCount; j++) {
			ut64 offset = mappingWithSlideOffset + j * sizeof (cache_mapping_slide);
			cache_mapping_slide entry;
			bool got_entry = false;
			RIO_FREAD_AT (fd, offset, entry, "6lii", got_entry);
			if (!got_entry) {
				break;
			}

			if (entry.slideInfoOffset && entry.slideInfoSize) {
				RDyldRebaseInfosEntry * info = RIODscRebaseInfos_emplace_back (&slice->rebase_infos);
				if (!info) {
					break;
				}
				memset (info, 0, sizeof (RDyldRebaseInfosEntry));
				info->start = entry.fileOffset;
				info->end = info->start + entry.size;
				slideInfoOffset = entry.slideInfoOffset;
				if (monocache) {
					slideInfoOffset += start;
					info->start += start;
					info->end += start;
				}
				slideInfoSize = entry.slideInfoSize;
				info->info = get_rebase_info (fd, slideInfoOffset, slideInfoSize, info->start, 0);
				if (!info->info) {
					R_LOG_ERROR ("Failed to get rebase info");
					return false;
				}
			}
		}
	} else {
		ut32 mappingCount;
		dsc_header_get_u32 (header, "mappingCount", &mappingCount);
		if (mappingCount > 1) {
			ut32 mappingOffset;
			dsc_header_get_u32 (header, "mappingOffset", &mappingOffset);
			cache_map_t w_map;
			bool got_map = false;
			mappingOffset += sizeof (w_map);
			RIO_FREAD_AT (fd, mappingOffset, w_map, "3l2i", got_map);
			if (!got_map) {
				return false;
			}

			RDyldRebaseInfosEntry * info = RIODscRebaseInfos_emplace_back (&slice->rebase_infos);
			if (!info) {
				return false;
			}
			memset (info, 0, sizeof (RDyldRebaseInfosEntry));

			info->start = w_map.fileOffset;
			info->end = info->start + w_map.size;
			info->info = get_rebase_info (fd, slideInfoOffset, slideInfoSize, info->start, 0);
			if (!info->info) {
				R_LOG_ERROR ("Failed to get rebase info");
				return false;
			}
		}
	}

	return true;
}

static RDyldRebaseInfo *get_rebase_info(int fd, ut64 slideInfoOffset, ut64 slideInfoSize, ut64 start_of_data, ut64 slide) {
	ut8 *tmp_buf_1 = NULL;
	ut8 *tmp_buf_2 = NULL;
	ut8 *one_page_buf = NULL;

	ut64 offset = slideInfoOffset;
	ut32 slide_info_version = 0;
	bool got_version = false;

	RIO_FREAD_AT (fd, offset, slide_info_version, "i", got_version);
	if (!got_version) {
		R_LOG_ERROR("Could not get slide info version");
		return NULL;
	}

	if (slide_info_version == 5) {
		ut64 size = sizeof (cache_slide3_t);
		cache_slide5_t slide_info;
		bool got_info = false;
		RIO_FREAD_AT (fd, offset, slide_info, "4i1l", got_info);
		if (!got_info) {
			R_LOG_ERROR ("Could not read slide info v5");
			return NULL;
		}

		ut64 page_starts_offset = offset + size;
		ut64 page_starts_size = slide_info.page_starts_count * 2;

		if (page_starts_size + size > slideInfoSize) {
			R_LOG_ERROR ("Size mismatch in slide info v5");
			return NULL;
		}

		if (page_starts_size > 0) {
			tmp_buf_1 = malloc (page_starts_size);
			if (!tmp_buf_1) {
				goto beach;
			}
			bool got_starts = false;
			RIO_FREAD_AT_INTO (fd, page_starts_offset, tmp_buf_1, "s", page_starts_size, slide_info.page_starts_count, got_starts);
			if (!got_starts) {
				R_LOG_ERROR ("Could not read slide info v3 page starts");
				goto beach;
			}
		}

		RDyldRebaseInfo5 *rebase_info = R_NEW0 (RDyldRebaseInfo5);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 5;
		rebase_info->delta_mask = 0x7ff0000000000000ULL;
		rebase_info->delta_shift = 52; // right
		rebase_info->high8_shift = 22; // left
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16*) tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->value_add = slide_info.value_add;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->slide = slide;

		return (RDyldRebaseInfo*) rebase_info;
	} else if (slide_info_version == 3) {
		ut64 size = sizeof (cache_slide3_t);
		cache_slide3_t slide_info;
		bool got_info = false;
		RIO_FREAD_AT (fd, offset, slide_info, "4i1l", got_info);
		if (!got_info) {
			R_LOG_ERROR ("Could not read slide info v3");
			return NULL;
		}

		ut64 page_starts_offset = offset + size;
		ut64 page_starts_size = slide_info.page_starts_count * 2;

		if (page_starts_size + size > slideInfoSize) {
			R_LOG_ERROR ("Size mismatch in slide info v3");
			return NULL;
		}

		if (page_starts_size > 0) {
			tmp_buf_1 = malloc (page_starts_size);
			if (!tmp_buf_1) {
				goto beach;
			}
			bool got_starts = false;
			RIO_FREAD_AT_INTO (fd, page_starts_offset, tmp_buf_1, "s", page_starts_size, slide_info.page_starts_count, got_starts);
			if (!got_starts) {
				R_LOG_ERROR ("Could not read slide info v3 page starts");
				goto beach;
			}
		}

		RDyldRebaseInfo3 *rebase_info = R_NEW0 (RDyldRebaseInfo3);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 3;
		rebase_info->delta_mask = 0x3ff8000000000000ULL;
		rebase_info->delta_shift = 51;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16*) tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->auth_value_add = slide_info.auth_value_add;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->slide = slide;

		return (RDyldRebaseInfo*) rebase_info;
	} else if (slide_info_version == 2 || slide_info_version == 4) {
		cache_slide2_t slide_info;
		bool got_info = false;
		RIO_FREAD_AT (fd, offset, slide_info, "6i2l", got_info);
		if (!got_info) {
			R_LOG_ERROR ("Could not read slide info v%d", slide_info_version);
			return NULL;
		}

		if (slide_info.page_starts_offset == 0 ||
				slide_info.page_starts_offset > slideInfoSize ||
				slide_info.page_starts_offset + slide_info.page_starts_count * 2 > slideInfoSize) {
			R_LOG_ERROR ("Size mismatch in slide info v%d page starts", slide_info_version);
			return NULL;
		}

		if (slide_info.page_extras_offset > slideInfoSize ||
				slide_info.page_extras_offset + slide_info.page_extras_count * 2 > slideInfoSize) {
			R_LOG_ERROR ("Size mismatch in slide info v%d page extras", slide_info_version);
			return NULL;
		}

		if (slide_info.page_starts_count > 0) {
			ut64 size = slide_info.page_starts_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_starts_offset;
			tmp_buf_1 = malloc (size);
			if (!tmp_buf_1) {
				goto beach;
			}
			bool got_starts = false;
			RIO_FREAD_AT_INTO (fd, at, tmp_buf_1, "s", size, slide_info.page_starts_count, got_starts);
			if (!got_starts) {
				R_LOG_ERROR ("Could not read slide info v%d page starts", slide_info_version);
				goto beach;
			}
		}

		if (slide_info.page_extras_count > 0) {
			ut64 size = slide_info.page_extras_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_extras_offset;
			tmp_buf_2 = malloc (size);
			if (!tmp_buf_2) {
				goto beach;
			}
			bool got_extras = false;
			RIO_FREAD_AT_INTO (fd, at, tmp_buf_2, "s", size, slide_info.page_extras_count, got_extras);
			if (!got_extras) {
				R_LOG_ERROR ("Could not read slide info v%d page extras", slide_info_version);
				goto beach;
			}
		}

		RDyldRebaseInfo2 *rebase_info = R_NEW0 (RDyldRebaseInfo2);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = slide_info_version;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16*) tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->page_extras = (ut16*) tmp_buf_2;
		rebase_info->page_extras_count = slide_info.page_extras_count;
		rebase_info->value_add = slide_info.value_add;
		rebase_info->delta_mask = slide_info.delta_mask;
		rebase_info->value_mask = ~rebase_info->delta_mask;
		rebase_info->delta_shift = dumb_ctzll (rebase_info->delta_mask) - 2;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->slide = slide;

		return (RDyldRebaseInfo*) rebase_info;
	} else if (slide_info_version == 1) {
		cache_slide1_t slide_info;
		bool got_info = false;
		RIO_FREAD_AT (fd, offset, slide_info, "6i", got_info);
		if (!got_info) {
			R_LOG_ERROR ("Could not read slide info v1");
			return NULL;
		}

		if (slide_info.toc_offset == 0 ||
			slide_info.toc_offset > slideInfoSize ||
			slide_info.toc_offset + slide_info.toc_count * 2 > slideInfoSize) {
			R_LOG_ERROR ("Size mismatch in slide info v1 toc offset");
			return NULL;
		}

		if (slide_info.entries_offset == 0 ||
			slide_info.entries_offset > slideInfoSize ||
			slide_info.entries_offset + slide_info.entries_count * slide_info.entries_size > slideInfoSize) {
			R_LOG_ERROR ("Size mismatch in slide info v1 entries offset");
			return NULL;
		}

		if (slide_info.toc_count > 0) {
			ut64 size = slide_info.toc_count * 2;
			ut64 at = slideInfoOffset + slide_info.toc_offset;
			tmp_buf_1 = malloc (size);
			if (!tmp_buf_1) {
				goto beach;
			}
			bool got_toc = false;
			RIO_FREAD_AT_INTO (fd, at, tmp_buf_1, "s", size, slide_info.toc_count, got_toc);
			if (!got_toc) {
				R_LOG_ERROR ("Could not read slide info v1 toc");
				goto beach;
			}
		}

		if (slide_info.entries_count > 0) {
			ut64 size = (ut64) slide_info.entries_count * (ut64) slide_info.entries_size;
			ut64 at = slideInfoOffset + slide_info.entries_offset;
			tmp_buf_2 = malloc (size);
			if (!tmp_buf_2) {
				goto beach;
			}
			bool got_entries = false;
			RIO_FREAD_AT_INTO_DIRECT (fd, at, tmp_buf_2, size, got_entries);
			if (!got_entries) {
				R_LOG_ERROR ("Could not read slide info v1 entries");
				goto beach;
			}
		}

		RDyldRebaseInfo1 *rebase_info = R_NEW0 (RDyldRebaseInfo1);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 1;
		rebase_info->start_of_data = start_of_data;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->page_size = 4096;
		rebase_info->toc = (ut16*) tmp_buf_1;
		rebase_info->toc_count = slide_info.toc_count;
		rebase_info->entries = tmp_buf_2;
		rebase_info->entries_size = slide_info.entries_size;
		rebase_info->slide = slide;

		return (RDyldRebaseInfo*) rebase_info;
	} else {
		R_LOG_ERROR ("Unsupported slide info version %d", slide_info_version);
		return NULL;
	}

beach:
	R_FREE (tmp_buf_1);
	R_FREE (tmp_buf_2);
	R_FREE (one_page_buf);
	return NULL;
}

static void rebase_info5_free(RDyldRebaseInfo5 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->page_starts);
		R_FREE (rebase_info);
	}
}

static void rebase_info3_free(RDyldRebaseInfo3 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->page_starts);
		R_FREE (rebase_info);
	}
}

static void rebase_info2_free(RDyldRebaseInfo2 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->page_starts);
		R_FREE (rebase_info->page_extras);
		R_FREE (rebase_info);
	}
}

static void rebase_info1_free(RDyldRebaseInfo1 *rebase_info) {
	if (rebase_info) {
		R_FREE (rebase_info->toc);
		R_FREE (rebase_info->entries);
		R_FREE (rebase_info);
	}
}

static void rebase_info_free(RDyldRebaseInfo *rebase_info) {
	if (!rebase_info) {
		return;
	}
	R_FREE (rebase_info->one_page_buf);
	ut8 version = rebase_info->version;
	if (version == 1) {
		rebase_info1_free ((RDyldRebaseInfo1*) rebase_info);
	} else if (version == 2 || version == 4) {
		rebase_info2_free ((RDyldRebaseInfo2*) rebase_info);
	} else if (version == 3) {
		rebase_info3_free ((RDyldRebaseInfo3*) rebase_info);
	} else if (version == 5) {
		rebase_info5_free ((RDyldRebaseInfo5*) rebase_info);
	} else {
		R_FREE (rebase_info);
	}
}

static ut32 dumb_ctzll(ut64 x) {
	ut64 result = 0;
	int i, j;
	for (i = 0; i < 64; i += 8) {
		ut8 byte = (x >> i) & 0xff;
		if (!byte) {
			result += 8;
		} else {
			for (j = 0; j < 8; j++) {
				if (!((byte >> j) & 1)) {
					result++;
				} else {
					break;
				}
			}
			break;
		}
	}
	return result;
}

RIOPlugin r_io_plugin_dsc = {
	.meta = {
		.name = "dsc",
		.desc = "Open dyld shared library caches",
		.author = "mrmacete",
		.license = "LGPL-3.0-only",
	},
	.uris = URL_SCHEME,
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek_dsc,
	.system = __system,
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

