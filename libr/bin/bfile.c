/* radare2 - LGPL - Copyright 2009-2019 - pancake, nibble, dso */

#include <r_bin.h>
#include <r_hash.h>
#include "i/private.h"

// maybe too big sometimes? 2KB of stack eaten here..
#define R_STRING_SCAN_BUFFER_SIZE 2048
#define R_STRING_MAX_UNI_BLOCKS 4

static RBinString *find_string_at(RBinFile *bf, RList *ret, ut64 addr) {
	if (addr != 0 && addr != UT64_MAX) {
		RBinString *res = ht_up_find (bf->o->strings_db, addr, NULL);
		return res;
	}
	return NULL;
}

static void print_string(RBinFile *bf, RBinString *string, int raw) {
	r_return_if_fail (bf && string);

	int mode = bf->strmode;
	ut64 addr, vaddr;
	RBin *bin = bf->rbin;
	const char *section_name, *type_string;
	RIO *io = bin->iob.io;
	if (!io) {
		return;
	}
	RBinSection *s = r_bin_get_section_at (bf->o, string->paddr, false);
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	section_name = s ? s->name : "";
	type_string = r_bin_string_type (string->type);
	vaddr = addr = r_bin_get_vaddr (bin, string->paddr, string->vaddr);

	// If raw string dump mode, use printf to dump directly to stdout.
	//  PrintfCallback temp = io->cb_printf;
	switch (mode) {
	case R_MODE_SIMPLEST: 
		io->cb_printf ("%s\n", string->string);
		break;
	case R_MODE_SIMPLE: 
		if (raw == 2) {
			io->cb_printf ("0x%08"PFMT64x" %s\n", addr, string->string);
		} else {
			io->cb_printf ("%s\n", string->string);
		}
		break;
	case R_MODE_RADARE: {
		char *f_name, *nstr;
		f_name = strdup (string->string);
		r_name_filter (f_name, 512);
		if (bin->prefix) {
			nstr = r_str_newf ("%s.str.%s", bin->prefix, f_name);
			io->cb_printf ("f %s.str.%s %u @ 0x%08"PFMT64x"\n"
					"Cs %u @ 0x%08"PFMT64x"\n",
					bin->prefix, f_name, string->size, addr,
					string->size, addr);
		} else {
			nstr = r_str_newf ("str.%s", f_name);
			io->cb_printf ("f str.%s %u @ 0x%08"PFMT64x"\n"
					"Cs %u @ 0x%08"PFMT64x"\n",
					f_name, string->size, addr,
					string->size, addr);
		}
		free (nstr);
		free (f_name);
		break;
		}
	case R_MODE_PRINT: 
		io->cb_printf ("%03u 0x%08" PFMT64x " 0x%08" PFMT64x " %3u %3u "
			       "(%s) %5s %s\n",
			string->ordinal, string->paddr, vaddr,
			string->length, string->size,
			section_name, type_string, string->string);
		break;
	}
}

static int string_scan_range(RList *list, RBinFile *bf, int min,
			      const ut64 from, const ut64 to, int type, int raw, RBinSection *section) {
	ut8 tmp[R_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = R_STRING_TYPE_DETECT;

	// if list is null it means its gonna dump
	r_return_val_if_fail (bf, -1);

	if (type == -1) {
		type = R_STRING_TYPE_DETECT;
	}
	if (from >= to) {
		eprintf ("Invalid range to find strings 0x%"PFMT64x" .. 0x%"PFMT64x"\n", from, to);
		return -1;
	}
	int len = to - from;
	ut8 *buf = calloc (len, 1);
	if (!buf || !min) {
		free (buf);
		return -1;
	}
	st64 vdelta = 0, pdelta = 0;
	RBinSection *s = NULL;
	r_buf_read_at (bf->buf, from, buf, len);
	// may oobread
	while (needle < to) {
		rc = r_utf8_decode (buf + needle - from, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (type == R_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc - from;
			if ((to - needle) > 5 + rc) {
				bool is_wide32 = (needle + rc + 2 < to) && (!w[0] && !w[1] && !w[2] && w[3] && !w[4]);
				if (is_wide32) {
					str_type = R_STRING_TYPE_WIDE32;
				} else {
					bool is_wide = needle + rc + 2 < to && !w[0] && w[1] && !w[2];
					str_type = is_wide? R_STRING_TYPE_WIDE: R_STRING_TYPE_ASCII;
				}
			} else {
				str_type = R_STRING_TYPE_ASCII;
			}
		} else {
			str_type = type;
		}
		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (i = 0; i < sizeof (tmp) - 3 && needle < to; i += rc) {
			RRune r = {0};

			if (str_type == R_STRING_TYPE_WIDE32) {
				rc = r_utf32le_decode (buf + needle - from, to - needle, &r);
				if (rc) {
					rc = 4;
				}
			} else if (str_type == R_STRING_TYPE_WIDE) {
				rc = r_utf16le_decode (buf + needle - from, to - needle, &r);
				if (rc == 1) {
					rc = 2;
				}
			} else {
				rc = r_utf8_decode (buf + needle - from, to - needle, &r);
				if (rc > 1) {
					str_type = R_STRING_TYPE_UTF8;
				}
			}

			/* Invalid sequence detected */
			if (!rc) {
				needle++;
				break;
			}

			needle += rc;

			if (r_isprint (r) && r != '\\') {
				if (str_type == R_STRING_TYPE_WIDE32) {
					if (r == 0xff) {
						r = 0;
					}
				}
				rc = r_utf8_encode (&tmp[i], r);
				runes++;
				/* Print the escape code */
			} else if (r && r < 0x100 && strchr ("\b\v\f\n\r\t\a\033\\", (char)r)) {
				if ((i + 32) < sizeof (tmp) && r < 93) {
					tmp[i + 0] = '\\';
					tmp[i + 1] = "       abtnvfr             e  "
					             "                              "
					             "                              "
					             "  \\"[r];
				} else {
					// string too long
					break;
				}
				rc = 2;
				runes++;
			} else {
				/* \0 marks the end of C-strings */
				break;
			}
		}

		tmp[i++] = '\0';

		if (runes >= min) {
			// reduce false positives
			int j, num_blocks, *block_list;
			if (str_type == R_STRING_TYPE_ASCII) {
				for (j = 0; j < i; j++) {
					char ch = tmp[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE (tmp[j])) {
							continue;
						}
					}
				}
			}
			switch (str_type) {
			case R_STRING_TYPE_UTF8:
			case R_STRING_TYPE_WIDE:
			case R_STRING_TYPE_WIDE32:
				num_blocks = 0;
				block_list = r_utf_block_list ((const ut8*)tmp, i - 1);
				if (block_list) {
					for (j = 0; block_list[j] != -1; j++) {
						num_blocks++;
					}
				}
				free (block_list);
				if (num_blocks > R_STRING_MAX_UNI_BLOCKS) {
					continue;
				}
			}
			RBinString *bs = R_NEW0 (RBinString);
			if (!bs) {
				break;
			}
			bs->type = str_type;
			bs->length = runes;
			bs->size = needle - str_start;
			bs->ordinal = count++;
			// TODO: move into adjust_offset
			switch (str_type) {
			case R_STRING_TYPE_WIDE:
				if (str_start - from > 1) {
					const ut8 *p = buf + str_start - 2 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 2; // \xff\xfe
					}
				}
				break;
			case R_STRING_TYPE_WIDE32:
				if (str_start - from > 3) {
					const ut8 *p = buf + str_start - 4 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 4; // \xff\xfe\x00\x00
					}
				}
				break;
			}
			if (!s) {
				if (section) {
					s = section;
				} else if (bf->o) {
					s = r_bin_get_section_at (bf->o, str_start, false);
				}
				if (s) {
					vdelta = s->vaddr;
					pdelta = s->paddr;
				}
			}
			bs->paddr = str_start;
			bs->vaddr = str_start - pdelta + vdelta;
			bs->string = r_str_ndup ((const char *)tmp, i);
			if (list) {
				r_list_append (list, bs);
				if (bf->o) {
					ht_up_insert (bf->o->strings_db, bs->vaddr, bs);
				}
			} else {
				print_string (bf, bs, raw);
				r_bin_string_free (bs);
			}
			if (from == 0 && to == bf->size) {
				/* force lookup section at the next one */
				s = NULL;
			}
		}
	}
	free (buf);
	return count;
}

static int is_data_section(RBinFile *a, RBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	}
 	// Rust
	return strstr (s->name, "_const") != NULL;
}

static void get_strings_range(RBinFile *bf, RList *list, int min, int raw, ut64 from, ut64 to, RBinSection * section) {
	r_return_if_fail (bf && bf->buf);

	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);

	if (!raw && (!plugin || !plugin->info)) {
		return;
	}
	if (!min) {
		min = plugin? plugin->minstrlen: 4;
	}
	/* Some plugins return zero, fix it up */
	if (!min) {
		min = 4;
	}
	if (min < 0) {
		return;
	}
	if (!to || to > r_buf_size (bf->buf)) {
		to = r_buf_size (bf->buf);
	}
	if (!to) {
		return;
	}
	if (raw != 2) {
		ut64 size = to - from;
		// in case of dump ignore here
		if (bf->rbin->maxstrbuf && size && size > bf->rbin->maxstrbuf) {
			if (bf->rbin->verbose) {
				eprintf ("WARNING: bin_strings buffer is too big (0x%08" PFMT64x "). Use -zzz or set bin.maxstrbuf (RABIN2_MAXSTRBUF) in r2 (rabin2)\n",
					size);
			}
			return;
		}
	}
	string_scan_range (list, bf, min, from, to, -1, raw, section);
}

R_IPI RBinFile *r_bin_file_new(RBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr) {
	ut32 bf_id;
	if (!r_id_pool_grab_id (bin->ids->pool, &bf_id)) {
		return NULL;
	}
	RBinFile *bf = R_NEW0 (RBinFile);
	if (!bf) {
		return NULL;
	}
	bf->id = bf_id;
	bf->rbin = bin;
	bf->file = file ? strdup (file) : NULL;
	bf->rawstr = rawstr;
	bf->fd = fd;
	bf->curxtr = xtrname ? r_bin_get_xtrplugin_by_name (bin, xtrname) : NULL;
	bf->sdb = sdb;
	bf->size = file_sz;
	bf->xtr_data = r_list_newf ((RListFree)r_bin_xtrdata_free);
	bf->xtr_obj = NULL;
	bf->sdb = sdb_new0 ();
	bf->sdb_addrinfo = sdb_new0 (); //ns (bf->sdb, "addrinfo", 1);
	// bf->sdb_addrinfo->refs++;
	return bf;
}

static RBinPlugin *get_plugin_from_buffer(RBin *bin, const char *pluginname, RBuffer *buf) {
	RBinPlugin *plugin = bin->force? r_bin_get_binplugin_by_name (bin, bin->force): NULL;
	if (plugin) {
		return plugin;
	}
	plugin = pluginname? r_bin_get_binplugin_by_name (bin, pluginname): NULL;
	if (plugin) {
		return plugin;
	}
	plugin = r_bin_get_binplugin_by_buffer (bin, buf);
	if (plugin) {
		return plugin;
	}
	return r_bin_get_binplugin_any (bin);
}

R_API bool r_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data) {
	r_return_val_if_fail (bin && bf && data, false);

	ut64 offset = data->offset;
	ut64 sz = data->size;

	RBinPlugin *plugin = get_plugin_from_buffer (bin, NULL, data->buf);
	bf->buf = r_buf_ref (data->buf);

	RBinObject *o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, offset, sz);
	if (!o) {
		return false;
	}
	// size is set here because the reported size of the object depends on
	// if loaded from xtr plugin or partially read
	if (!o->size) {
		o->size = sz;
	}
	bf->narch = data->file_count;
	if (!o->info) {
		o->info = R_NEW0 (RBinInfo);
	}
	free (o->info->file);
	free (o->info->arch);
	free (o->info->machine);
	free (o->info->type);
	o->info->file = strdup (bf->file);
	o->info->arch = strdup (data->metadata->arch);
	o->info->machine = strdup (data->metadata->machine);
	o->info->type = strdup (data->metadata->type);
	o->info->bits = data->metadata->bits;
	o->info->has_crypto = bf->o->info->has_crypto;
	data->loaded = true;
	return true;
}

static bool xtr_metadata_match(RBinXtrData *xtr_data, const char *arch, int bits) {
	if (!xtr_data->metadata || !xtr_data->metadata->arch) {
		return false;
	}
	const char *iter_arch = xtr_data->metadata->arch;
	int iter_bits = xtr_data->metadata->bits;
	return bits == iter_bits && !strcmp (iter_arch, arch) && !xtr_data->loaded;
}

R_IPI RBinFile *r_bin_file_new_from_buffer(RBin *bin, const char *file, RBuffer *buf, ut64 file_sz, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname, ut64 offset) {
	r_return_val_if_fail (file_sz != UT64_MAX, NULL);

	RBinFile *bf = r_bin_file_new (bin, file, file_sz, rawstr, fd, pluginname, NULL, false);
	if (bf) {
		bf->buf = r_buf_ref (buf);
		RBinPlugin *plugin = get_plugin_from_buffer (bin, pluginname, bf->buf);
		RBinObject *o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, 0, r_buf_size (bf->buf));
		if (!o) {
			r_bin_file_free (bf);
			return NULL;
		}
		// size is set here because the reported size of the object depends on
		// if loaded from xtr plugin or partially read
		if (!o->size) {
			o->size = file_sz;
		}
		r_list_append (bin->binfiles, bf);
	}
	return bf;
}

R_API RBinFile *r_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits) {
	RListIter *iter;
	RBinFile *binfile = NULL;
	RBinXtrData *xtr_data;

	r_return_val_if_fail (bin && arch, NULL);

	r_list_foreach (bin->binfiles, iter, binfile) {
		RListIter *iter_xtr;
		if (!binfile->xtr_data) {
			continue;
		}
		// look for sub-bins in Xtr Data and Load if we need to
		r_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (xtr_metadata_match (xtr_data, arch, bits)) {
				if (!r_bin_file_object_new_from_xtr_data (bin, binfile, xtr_data->baddr,
					    xtr_data->laddr, xtr_data)) {
					return NULL;
				}
				return binfile;
			}
		}
	}
	return binfile;
}

R_IPI RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 binfile_id) {
	RBinFile *binfile = NULL;
	RListIter *iter = NULL;
	r_list_foreach (bin->binfiles, iter, binfile) {
		if (binfile->id == binfile_id) {
			break;
		}
		binfile = NULL;
	}
	return binfile;
}

R_API int r_bin_file_delete_all(RBin *bin) {
	int counter = 0;
	if (bin) {
		counter = r_list_length (bin->binfiles);
		r_list_purge (bin->binfiles);
		bin->cur = NULL;
	}
	return counter;
}

R_API int r_bin_file_delete(RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf;
	RBinFile *cur = r_bin_cur (bin);
	if (bin && cur) {
		r_list_foreach (bin->binfiles, iter, bf) {
			if (bf && bf->fd == bin_fd) {
				if (cur->fd == bin_fd) {
					//avoiding UaF due to dead reference
					bin->cur = NULL;
				}
				r_list_delete (bin->binfiles, iter);
				return 1;
			}
		}
	}
	return 0;
}

R_API RBinFile *r_bin_file_find_by_fd(RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf;

	r_return_val_if_fail (bin, NULL);

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf->fd == bin_fd) {
			return bf;
		}
	}
	return NULL;
}

R_API RBinFile *r_bin_file_find_by_name(RBin *bin, const char *name) {
	RListIter *iter;
	RBinFile *bf;

	r_return_val_if_fail (bin && name, NULL);

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf->file && !strcmp (bf->file, name)) {
			return bf;
		}
	}
	return NULL;
}

R_IPI RBinFile *r_bin_file_find_by_name_n(RBin *bin, const char *name, int idx) {
	RListIter *iter;
	RBinFile *bf = NULL;
	int i = 0;
	if (!bin) {
		return bf;
	}

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->file && !strcmp (bf->file, name)) {
			if (i == idx) {
				break;
			}
			i++;
		}
		bf = NULL;
	}
	return bf;
}

R_API bool r_bin_file_set_cur_by_id(RBin *bin, ut32 bin_id) {
	RBinFile *bf = r_bin_file_find_by_id (bin, bin_id);
	return bf? r_bin_file_set_cur_binfile (bin, bf): false;
}

R_API bool r_bin_file_set_cur_by_fd(RBin *bin, ut32 bin_fd) {
	RBinFile *bf = r_bin_file_find_by_fd (bin, bin_fd);
	return bf? r_bin_file_set_cur_binfile (bin, bf): false;
}

R_IPI bool r_bin_file_set_cur_binfile_obj(RBin *bin, RBinFile *bf, RBinObject *obj) {
	r_return_val_if_fail (bin && bf, false);
	if (!obj) {
		return false;
	}
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	if (obj) {
		bf->o = obj;
	}
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (bin->minstrlen < 1) {
		bin->minstrlen = plugin? plugin->minstrlen: bin->minstrlen;
	}
	return true;
}

R_API bool r_bin_file_set_cur_binfile(RBin *bin, RBinFile *bf) {
	r_return_val_if_fail (bin && bf, false);
	return r_bin_file_set_cur_binfile_obj (bin, bf, bf->o);
}

R_API bool r_bin_file_set_cur_by_name(RBin *bin, const char *name) {
	r_return_val_if_fail (bin && name, false);
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API bool r_bin_file_deref(RBin *bin, RBinFile *a) {
	r_return_val_if_fail (bin && a, false);

	RBinObject *o = r_bin_cur_object (bin);
	int res = false;
	if (!o) {
		return false;
	}

	bin->cur = NULL;
	return res;
}

R_API void r_bin_file_free(void /*RBinFile*/ *_bf) {
	if (!_bf) {
		return;
	}
	RBinFile *bf = _bf;
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	// Binary format objects are connected to the
	// RBinObject, so the plugin must destroy the
	// format data first
	if (plugin && plugin->destroy) {
		plugin->destroy (bf);
	}
	r_buf_free (bf->buf);
	if (bf->curxtr && bf->curxtr->destroy && bf->xtr_obj) {
		bf->curxtr->free_xtr ((void *)(bf->xtr_obj));
	}
	// TODO: unset related sdb namespaces
	if (bf->sdb_addrinfo) {
		sdb_free (bf->sdb_addrinfo);
		bf->sdb_addrinfo = NULL;
	}
	free (bf->file);
	bf->o = NULL;
	r_list_free (bf->xtr_data);
	if (bf->id != -1) {
		// TODO: use r_storage api
		r_id_pool_kick_id (bf->rbin->ids->pool, bf->id);
	}
	free (bf);
}

R_IPI RBinFile *r_bin_file_xtr_load_buffer(RBin *bin, RBinXtrPlugin *xtr, const char *filename, RBuffer *buf, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
	r_return_val_if_fail (bin && xtr && buf, NULL);

	RBinFile *bf = r_bin_file_find_by_name (bin, filename);
	if (!bf) {
		bf = r_bin_file_new (bin, filename, file_sz, rawstr, fd, xtr->name, bin->sdb, false);
		if (!bf) {
			return NULL;
		}
		r_list_append (bin->binfiles, bf);
		if (!bin->cur) {
			bin->cur = bf;
		}
	}
	r_list_free (bf->xtr_data);
	bf->xtr_data = NULL;
	if (xtr->extractall_from_buffer) {
		bf->xtr_data = xtr->extractall_from_buffer (bin, buf);
	} else if (xtr->extractall_from_bytes) {
		ut64 sz = 0;
		const ut8 *bytes = r_buf_data (buf, &sz);
		eprintf ("TODO: Implement extractall_from_buffer in '%s' xtr.bin plugin\n", xtr->name);
		bf->xtr_data = xtr->extractall_from_bytes (bin, bytes, sz);
	}
	if (bf->xtr_data) {
		RListIter *iter;
		RBinXtrData *x;
		//populate xtr_data with baddr and laddr that will be used later on
		//r_bin_file_object_new_from_xtr_data
		r_list_foreach (bf->xtr_data, iter, x) {
			x->baddr = baseaddr? baseaddr : UT64_MAX;
			x->laddr = loadaddr? loadaddr : UT64_MAX;
		}
	}
	bf->loadaddr = loadaddr;
	return bf;
}

// XXX deprecate this function imho.. wee can just access bf->buf directly
R_IPI bool r_bin_file_set_bytes(RBinFile *bf, const ut8 *bytes, ut64 sz, bool steal_ptr) {
	r_return_val_if_fail (bf && bytes, false);
	r_buf_free (bf->buf);
	if (steal_ptr) {
		bf->buf = r_buf_new_with_pointers (bytes, sz, true);
	} else {
		bf->buf = r_buf_new_with_bytes (bytes, sz);
	}
	return bf->buf != NULL;
}

R_API RBinPlugin *r_bin_file_cur_plugin(RBinFile *bf) {
	return (bf && bf->o)? bf->o->plugin: NULL;
}

R_IPI RList *r_bin_file_get_strings(RBinFile *a, int min, int dump, int raw) {
	r_return_val_if_fail (a, NULL);
	RListIter *iter;
	RBinSection *section;
	RList *ret = dump? NULL: r_list_newf (r_bin_string_free);

	if (!raw && a->o && a->o && a->o->sections && !r_list_empty (a->o->sections)) {
		RBinObject *o = a->o;
		r_list_foreach (o->sections, iter, section) {
			if (is_data_section (a, section)) {
				get_strings_range (a, ret, min, raw, section->paddr,
						section->paddr + section->size, section);
			}
		}
		r_list_foreach (o->sections, iter, section) {
			/* load objc/swift strings */
			const int bits = (a->o && a->o->info) ? a->o->info->bits : 32;
			const int cfstr_size = (bits == 64) ? 32 : 16;
			const int cfstr_offs = (bits == 64) ? 16 :  8;
			if (strstr (section->name, "__cfstring")) {
				int i;
				// XXX do not walk if bin.strings == 0
				ut8 *p;
				if (section->size > a->size) {
					continue;
				}
				ut8 *sbuf = malloc (section->size);
				if (!sbuf) {
					continue;
				}
				r_buf_read_at (a->buf, section->paddr + cfstr_offs, sbuf, section->size);
				for (i = 0; i < section->size; i += cfstr_size) {
					ut8 *buf = sbuf;
					p = buf + i;
					if ((i + ((bits==64)? 8:4)) >= section->size) {
						break;
					}
					ut64 cfstr_vaddr = section->vaddr + i;
					ut64 cstr_vaddr = (bits == 64) ? r_read_le64 (p) : r_read_le32 (p);
					RBinString *s = find_string_at (a, ret, cstr_vaddr);
					if (s) {
						RBinString *bs = R_NEW0 (RBinString);
						if (bs) {
							bs->type = s->type;
							bs->length = s->length;
							bs->size = s->size;
							bs->ordinal = s->ordinal;
							bs->vaddr = cfstr_vaddr;
							bs->paddr = cfstr_vaddr; // XXX should be paddr instead
							bs->string = r_str_newf ("cstr.%s", s->string);
							r_list_append (ret, bs);
							ht_up_insert (o->strings_db, bs->vaddr, bs);
						}
					}
				}
				free (sbuf);
			}
		}
	} else {
		get_strings_range (a, ret, min, raw, 0, a->size, NULL);
	}
	return ret;
}

R_API ut64 r_bin_file_get_baddr(RBinFile *binfile) {
	return binfile? r_bin_object_get_baddr (binfile->o): UT64_MAX;
}

R_API bool r_bin_file_close(RBin *bin, int bd) {
	r_return_val_if_fail (bin, false);
	RBinFile *bf = r_id_storage_take (bin->ids, bd);
	if (bf) {
		// file_free removes the fd already.. maybe its unnecessary
		r_id_storage_delete (bin->ids, bd);
		r_bin_file_free (bf);
		return true;
	}
	return false;
}

R_API bool r_bin_file_hash(RBin *bin, ut64 limit, const char *file, RList/*<RBinFileHash>*/ **old_file_hashes) {
	r_return_val_if_fail (bin, false);

	char hash[128];
	RHash *ctx;
	ut64 buf_len = 0, r = 0;
	RBinFile *bf = bin->cur;
	if (!bf) {
		return false;
	}
	RBinObject *o = bf->o;
	if (!o || !o->info) {
		return false;
	}
	RIODesc *iod = r_io_desc_get (bin->iob.io, bf->fd);
	if (!iod) {
		return false;
	}
	if (!file && iod) {
		file = iod->name;
	}
	buf_len = r_io_desc_size (iod);
	// By SLURP_LIMIT normally cannot compute ...
	if (buf_len > limit) {
	//	if (bin->verbose) {
			eprintf ("Warning: r_bin_file_hash: file exceeds bin.hashlimit\n");
	//	}
		return false;
	}
	const size_t blocksize = 64000;
	ut8 *buf = malloc (blocksize);
	if (!buf) {
		eprintf ("Cannot allocate computation buffer\n");
		return false;
	}
	if (old_file_hashes) {
		*old_file_hashes = NULL;
	}
	if (!r_list_empty (o->info->file_hashes)) {
		if (old_file_hashes && o->info->file_hashes) {
			*old_file_hashes = o->info->file_hashes;
		} else {
			r_list_free (o->info->file_hashes);
		}
		o->info->file_hashes = NULL;
	}
	ctx = r_hash_new (false, R_HASH_MD5 | R_HASH_SHA1);
	while (r + blocksize < buf_len) {
		r_io_desc_seek (iod, r, R_IO_SEEK_SET);
		int b = r_io_desc_read (iod, buf, blocksize);
		(void)r_hash_do_md5 (ctx, buf, blocksize);
		(void)r_hash_do_sha1 (ctx, buf, blocksize);
		r += b;
	}
	if (r < buf_len) {
		r_io_desc_seek (iod, r, R_IO_SEEK_SET);
		const size_t rem_len = buf_len-r;
		int b = r_io_desc_read (iod, buf, rem_len);
		if (b < 1) {
			eprintf ("r_io_desc_read: error\n");
		} else {
			(void)r_hash_do_md5 (ctx, buf, b);
			(void)r_hash_do_sha1 (ctx, buf, b);
		}
	}
	r_hash_do_end (ctx, R_HASH_MD5);
	r_hex_bin2str (ctx->digest, R_HASH_SIZE_MD5, hash);

	o->info->file_hashes = r_list_newf ((RListFree) r_bin_file_hash_free);
	RBinFileHash *md5h = R_NEW0 (RBinFileHash);
	if (md5h) {
		md5h->type = strdup ("md5");
		md5h->hex = strdup (hash);
		r_list_push (o->info->file_hashes, md5h);
	}
	r_hash_do_end (ctx, R_HASH_SHA1);
	r_hex_bin2str (ctx->digest, R_HASH_SIZE_SHA1, hash);

	RBinFileHash *sha1h = R_NEW0 (RBinFileHash);
	if (sha1h) {
		sha1h->type = strdup ("sha1");
		sha1h->hex = strdup (hash);
		r_list_push (o->info->file_hashes, sha1h);
	}
	// TODO: add here more rows

	free (buf);
	r_hash_free (ctx);
	return true;
}
