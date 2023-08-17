/* radare2 - LGPL - Copyright 2009-2023 - pancake, nibble, dso */

#include <r_bin.h>
#include <r_hash.h>
#include "i/private.h"

// maybe too big sometimes? 2KB of stack eaten here..
#define R_STRING_SCAN_BUFFER_SIZE 2048
#define R_STRING_MAX_UNI_BLOCKS 4

static RBinClass *__getClass(RBinFile *bf, const char *name) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->classes_ht && name, NULL);
	return ht_pp_find (bf->bo->classes_ht, name, NULL);
}

static RBinSymbol *__getMethod(RBinFile *bf, const char *klass, const char *method) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->methods_ht && klass && method, NULL);
	r_strf_var (name, 128, "%s::%s", klass, method);
	return ht_pp_find (bf->bo->methods_ht, name, NULL);
}

static RBinString *__stringAt(RBinFile *bf, RList *ret, ut64 addr) {
	if (R_LIKELY (addr != 0 && addr != UT64_MAX)) {
		return ht_up_find (bf->bo->strings_db, addr, NULL);
	}
	return NULL;
}

static void print_string(RBinFile *bf, RBinString *string, int raw, PJ *pj) {
	r_return_if_fail (bf && string);

	int mode = bf->strmode;
	RBin *bin = bf->rbin;
	if (!bin) {
		return;
	}
	RIO *io = bin->iob.io;
	if (!io) {
		return;
	}
	RBinSection *s = r_bin_get_section_at (bf->bo, string->paddr, false);
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	const char *section_name = s ? s->name : "";
	const char *type_string = r_bin_string_type (string->type);
	ut64 vaddr = r_bin_get_vaddr (bin, string->paddr, string->vaddr);
	ut64 addr = vaddr;

	// If raw string dump mode, use printf to dump directly to stdout.
	//  PrintfCallback temp = io->cb_printf;
	switch (mode) {
	case R_MODE_JSON:
		{
			if (pj) {
				pj_o (pj);
				pj_kn (pj, "vaddr", vaddr);
				pj_kn (pj, "paddr", string->paddr);
				pj_kn (pj, "ordinal", string->ordinal);
				pj_kn (pj, "size", string->size);
				pj_kn (pj, "length", string->length);
				pj_ks (pj, "section", section_name);
				pj_ks (pj, "type", type_string);
				pj_ks (pj, "string", string->string);
				pj_end (pj);
			}
		}
		break;
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
		char *f_name = strdup (string->string);
		r_name_filter (f_name, -1);
		if (bin->prefix) {
			io->cb_printf ("f %s.str.%s %u @ 0x%08"PFMT64x"\n"
					"Cs %u @ 0x%08"PFMT64x"\n",
					bin->prefix, f_name, string->size, addr,
					string->size, addr);
		} else {
			io->cb_printf ("f str.%s %u @ 0x%08"PFMT64x"\n"
					"Cs %u @ 0x%08"PFMT64x"\n",
					f_name, string->size, addr,
					string->size, addr);
		}
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

// TODO: this code must be implemented in RSearch as options for the strings mode
static int string_scan_range(RList *list, RBinFile *bf, int min, const ut64 from, const ut64 to, int type, int raw, RBinSection *section) {
	RBin *bin = bf->rbin;
	const bool strings_nofp = bin->strings_nofp;
	ut8 tmp[R_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = R_STRING_TYPE_DETECT;
	const int limit = bf->rbin->limit;

	// if list is null it means its gonna dump
	r_return_val_if_fail (bf, -1);

	if (type == -1) {
		type = R_STRING_TYPE_DETECT;
	}
	if (from == UT64_MAX || from == to) {
		return 0;
	}
	if (from > to) {
		R_LOG_ERROR ("Invalid range to find strings 0x%"PFMT64x" .. 0x%"PFMT64x, from, to);
		return -1;
	}
	st64 len = (st64)(to - from);
	if (len < 1 || len > ST32_MAX) {
		R_LOG_ERROR ("String scan range is invalid (%"PFMT64d" bytes)", len);
		return -1;
	}
	ut8 *buf = calloc (len, 1);
	if (!buf || !min) {
		free (buf);
		return -1;
	}
	st64 vdelta = 0, pdelta = 0;
	RBinSection *s = NULL;
	bool ascii_only = false;
	PJ *pj = NULL;
	if (bf->strmode == R_MODE_JSON && !list) {
		pj = pj_new ();
		if (pj) {
			pj_a (pj);
		}
	}
	r_buf_read_at (bf->buf, from, buf, len);
	char *charset = r_sys_getenv ("RABIN2_CHARSET");
	if (!R_STR_ISEMPTY (charset)) {
		RCharset *ch = r_charset_new ();
		if (r_charset_use (ch, charset)) {
			int outlen = len * 4;
			ut8 *out = calloc (len, 4);
			if (out) {
				int res = r_charset_encode_str (ch, out, outlen, buf, len);
				int i;
				// TODO unknown chars should be translated to null bytes
				for (i = 0; i < res; i++) {
					if (out[i] == '?') {
						out[i] = 0;
					}
				}
				free (buf);
				buf = out;
			}
		} else {
			R_LOG_ERROR ("Invalid value for RABIN2_CHARSET");
		}
		r_charset_free (ch);
	}
	free (charset);
	RConsIsBreaked is_breaked = (bin && bin->consb.is_breaked)? bin->consb.is_breaked: NULL;
	// may oobread
	while (needle < to && needle < UT64_MAX - 4) {
		if (is_breaked && is_breaked ()) {
			break;
		}
		// smol optimization
		if (to > 4 && needle < to - 4) {
			ut32 n1 = r_read_le32 (buf + (needle - from));
			if (!n1) {
				needle += 4;
				continue;
			}
		}
		rc = r_utf8_decode (buf + (needle - from), to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		bool addr_aligned = !(needle % 4);

		if (type == R_STRING_TYPE_DETECT) {
			char *w = (char *)buf + (needle + rc - from);
			if (((to - needle) > 8 + rc)) {
				// TODO: support le and be
				bool is_wide32le = (needle + rc + 2 < to) && (!w[0] && !w[1] && !w[2] && w[3] && !w[4]);
				// reduce false positives
				if (is_wide32le) {
					if (!w[5] && !w[6] && w[7] && w[8]) {
						is_wide32le = false;
					}
				}
				if (!addr_aligned) {
					is_wide32le = false;
				}
				///is_wide32be &= (n1 < 0xff && n11 < 0xff); // false; // n11 < 0xff;
				if (is_wide32le  && addr_aligned) {
					str_type = R_STRING_TYPE_WIDE32; // asume big endian,is there little endian w32?
				} else {
					// bool is_wide = (n1 && n2 && n1 < 0xff && (!n2 || n2 < 0xff));
					bool is_wide = needle + rc + 4 < to && !w[0] && w[1] && !w[2] && w[3] && !w[4];
					str_type = is_wide? R_STRING_TYPE_WIDE: R_STRING_TYPE_ASCII;
				}
			} else {
				if (rc > 1) {
					str_type = R_STRING_TYPE_UTF8; // could be charset if set :?
				} else {
					str_type = R_STRING_TYPE_ASCII;
				}
			}
		} else if (type == R_STRING_TYPE_UTF8) {
			str_type = R_STRING_TYPE_ASCII; // initial assumption
		} else {
			str_type = type;
		}
		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (i = 0; i < sizeof (tmp) - 4 && needle < to; i += rc) {
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
				rc = r_utf8_decode (buf + (needle - from), to - needle, &r);
				if (rc > 1) {
					str_type = R_STRING_TYPE_UTF8;
				}
			}

			/* Invalid sequence detected */
			if (!rc || (ascii_only && r > 0x7f)) {
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
				rc = r_utf8_encode (tmp + i, r);
				runes++;
			} else if (r && r < 0x100 && strchr ("\b\v\f\n\r\t\a\033\\", (char)r)) {
				/* Print the escape code */
				if (strings_nofp) {
					rc = 2;
					if (r && r < 0x100 && strchr ("\n\r\t\033\\", (char)r)) {
						// eprintf ("is special\n");
						runes++;
						// accept it as it is
						rc = 1;
					} else {
						rc = 1;
						r = 0;
						break;
					}
				} else {
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
				}
			} else {
				/* \0 marks the end of C-strings */
				break;
			}
		}

		tmp[i++] = '\0';

		if (runes < min && runes >= 2 && str_type == R_STRING_TYPE_ASCII && needle < to) {
			// back up past the \0 to the last char just in case it starts a wide string
			needle -= 2;
		}
		if (runes >= min) {
			// reduce false positives
			int j, num_blocks, *block_list;
			int *freq_list = NULL, expected_ascii, actual_ascii, num_chars;
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
				block_list = r_utf_block_list ((const ut8*)tmp, i - 1,
						str_type == R_STRING_TYPE_WIDE? &freq_list: NULL);
				if (block_list) {
					for (j = 0; block_list[j] != -1; j++) {
						num_blocks++;
					}
				}
				if (freq_list) {
					num_chars = 0;
					actual_ascii = 0;
					for (j = 0; freq_list[j] != -1; j++) {
						num_chars += freq_list[j];
						if (!block_list[j]) { // ASCII
							actual_ascii = freq_list[j];
						}
					}
					free (freq_list);
					expected_ascii = num_blocks ? num_chars / num_blocks : 0;
					if (actual_ascii > expected_ascii) {
						ascii_only = true;
						needle = str_start;
						free (block_list);
						continue;
					}
				}
				free (block_list);
				if (num_blocks > R_STRING_MAX_UNI_BLOCKS) {
					needle++;
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
			if (limit > 0 && count > limit) {
				R_LOG_WARN ("el.limit for strings");
				break;
			}
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
				} else if (bf->bo) {
					s = r_bin_get_section_at (bf->bo, str_start, false);
				}
				if (s) {
					vdelta = s->vaddr;
					pdelta = s->paddr;
				}
			}
			ut64 baddr = bf->loadaddr && bf->bo? bf->bo->baddr: bf->loadaddr;
			bs->paddr = str_start + baddr;
			bs->vaddr = str_start - pdelta + vdelta + baddr;
			bs->string = r_str_ndup ((const char *)tmp, i); // Use stringviews to save memory
			if (strings_nofp) {
				r_str_trim (bs->string); // trim spaces to ease readability
			}
			if (list) {
				r_list_append (list, bs);
				if (bf->bo) {
					ht_up_insert (bf->bo->strings_db, bs->vaddr, bs);
				}
			} else {
				print_string (bf, bs, raw, pj);
				r_bin_string_free (bs);
			}
			if (from == 0 && to == bf->size) {
				/* force lookup section at the next one */
				s = NULL;
			}
		}
		ascii_only = false;
	}
	free (buf);
	if (pj) {
		pj_end (pj);
		if (bin) {
			RIO *io = bin->iob.io;
			if (io) {
				io->cb_printf ("%s", pj_string (pj));
			}
		}
		pj_free (pj);
	}
	return count;
}

static bool __isDataSection(RBinFile *a, RBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	}
 	// Rust
	return strstr (s->name, "_const");
}

static void get_strings_range(RBinFile *bf, RList *list, int min, int raw, bool nofp, ut64 from, ut64 to, RBinSection *section) {
	r_return_if_fail (bf && bf->buf);

	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);

	if (!raw && (!plugin || !plugin->info)) {
		return;
	}
	if (!min) {
		min = plugin? plugin->minstrlen: 4;
	}
	/* Some plugins return zero, fix it up */
	if (min < 0) {
		return;
	}
	if (!min) {
		min = 4;
	}
	{
		RIO *io = bf->rbin->iob.io;
		RCoreBind *cb = &io->coreb;
		if (cb && cb->cfgGet) {
			const bool cfg_debug = cb->cfgGet (cb->core, "cfg.debug");
			if (!cfg_debug) {
				if (!to || to > r_buf_size (bf->buf)) {
					to = r_buf_size (bf->buf);
				}
				if (!to) {
					return;
				}
			}
		}
	}
	if (raw != 2) {
		ut64 size = to - from;
		// in case of dump ignore here
		if (bf->rbin->maxstrbuf && size && size > bf->rbin->maxstrbuf) {
			if (bf->rbin->verbose) {
				R_LOG_WARN ("bin_strings buffer is too big (0x%08" PFMT64x "). Use -zzz or set bin.str.maxbuf (RABIN2_MAXSTRBUF) in r2 (rabin2)", size);
			}
			return;
		}
	}
	int type;
	const char *enc = bf->rbin->strenc;
	if (!enc) {
		type = R_STRING_TYPE_DETECT;
	} else if (!strcmp (enc, "latin1")) {
		type = R_STRING_TYPE_ASCII;
	} else if (!strcmp (enc, "utf8")) {
		type = R_STRING_TYPE_UTF8;
	} else if (!strcmp (enc, "utf16le")) {
		type = R_STRING_TYPE_WIDE;
	} else if (!strcmp (enc, "utf32le")) {
		type = R_STRING_TYPE_WIDE32;
	} else { // TODO utf16be, utf32be
		R_LOG_ERROR ("encoding %s not supported", enc);
		return;
	}
	string_scan_range (list, bf, min, from, to, type, raw, section);
}

R_IPI RBinFile *r_bin_file_new(RBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr) {
	ut32 bf_id;
	if (!r_id_pool_grab_id (bin->ids->pool, &bf_id)) {
		return NULL;
	}
	RBinFile *bf = R_NEW0 (RBinFile);
	if (bf) {
		bf->id = bf_id;
		bf->rbin = bin;
		bf->file = file ? strdup (file) : NULL;
		bf->rawstr = rawstr;
		bf->fd = fd;
		bf->curxtr = xtrname ? r_bin_get_xtrplugin_by_name (bin, xtrname) : NULL;
		bf->sdb = sdb;
		if ((st64)file_sz < 0) {
			file_sz = 1024 * 64;
		}
		bf->size = file_sz;
		bf->xtr_data = r_list_newf ((RListFree)r_bin_xtrdata_free);
		bf->xtr_obj = NULL;
		bf->sdb = sdb_new0 ();
		bf->sdb_addrinfo = sdb_new0 (); // ns (bf->sdb, "addrinfo", 1);
		// bf->sdb_addrinfo->refs++;
	}
	return bf;
}

static RBinPlugin *get_plugin_from_buffer(RBin *bin, RBinFile *bf, const char *pluginname, RBuffer *buf) {
	RBinPlugin *plugin = bin->force? r_bin_get_binplugin_by_name (bin, bin->force): NULL;
	if (plugin) {
		return plugin;
	}
	plugin = pluginname? r_bin_get_binplugin_by_name (bin, pluginname): NULL;
	if (plugin) {
		return plugin;
	}
	plugin = r_bin_get_binplugin_by_buffer (bin, bf, buf);
	if (plugin) {
		return plugin;
	}
	return r_bin_get_binplugin_by_name (bin, "any");
}

R_API bool r_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data) {
	r_return_val_if_fail (bin && bf && data, false);

	ut64 offset = data->offset;
	ut64 sz = data->size;

	RBinPlugin *plugin = get_plugin_from_buffer (bin, bf, NULL, data->buf);
	bf->buf = r_buf_ref (data->buf);
	bf->user_baddr = baseaddr;

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
	R_FREE (o->info->file);
	R_FREE (o->info->arch);
	R_FREE (o->info->machine);
	R_FREE (o->info->type);
	o->info->file = strdup (bf->file);
	if (data->metadata) {
		if (data->metadata->arch) {
			o->info->arch = strdup (data->metadata->arch);
		}
		if (data->metadata->machine) {
			o->info->machine = strdup (data->metadata->machine);
		}
		if (data->metadata->type) {
			o->info->type = strdup (data->metadata->type);
		}
		o->info->bits = data->metadata->bits;
	}
	o->info->has_crypto = bf->bo->info->has_crypto;
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

R_IPI RBinFile *r_bin_file_new_from_buffer(RBin *bin, const char *file, RBuffer *buf, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname) {
	r_return_val_if_fail (bin && file && buf, NULL);

	RBinFile *bf = r_bin_file_new (bin, file, r_buf_size (buf), rawstr, fd, pluginname, NULL, false);
	if (bf) {
		RListIter *item = r_list_append (bin->binfiles, bf);
		bf->buf = r_buf_ref (buf);
		bf->user_baddr = baseaddr;
		RBinPlugin *plugin = get_plugin_from_buffer (bin, bf, pluginname, bf->buf);
		RBinObject *o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, 0, r_buf_size (bf->buf));
		if (!o) {
			r_list_delete (bin->binfiles, item);
			return NULL;
		}
		// size is set here because the reported size of the object depends on
		// if loaded from xtr plugin or partially read
		if (!o->size) {
			o->size = r_buf_size (buf);
		}
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

R_IPI RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 bf_id) {
	RBinFile *bf;
	RListIter *iter;
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf->id == bf_id) {
			return bf;
		}
	}
	return NULL;
}

R_API ut64 r_bin_file_delete_all(RBin *bin) {
	if (bin) {
		ut64 counter = r_list_length (bin->binfiles);
		r_list_purge (bin->binfiles);
		bin->cur = NULL;
		return counter;
	}
	return 0;
}

R_API bool r_bin_file_delete(RBin *bin, ut32 bin_id) {
	r_return_val_if_fail (bin, false);

	RListIter *iter;
	RBinFile *bf, *cur = r_bin_cur (bin);

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->id == bin_id) {
			if (cur && cur->id == bin_id) {
				// avoiding UaF due to dead reference
				bin->cur = NULL;
			}
			r_list_delete (bin->binfiles, iter);
			return true;
		}
	}
	return false;
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

R_API bool r_bin_file_set_cur_by_id(RBin *bin, ut32 bin_id) {
	RBinFile *bf = r_bin_file_find_by_id (bin, bin_id);
	return bf? r_bin_file_set_cur_binfile (bin, bf): false;
}

R_API bool r_bin_file_set_cur_by_fd(RBin *bin, ut32 bin_fd) {
	RBinFile *bf = r_bin_file_find_by_fd (bin, bin_fd);
	return bf? r_bin_file_set_cur_binfile (bin, bf): false;
}

R_IPI bool r_bin_file_set_obj(RBin *bin, RBinFile *bf, RBinObject *obj) {
	r_return_val_if_fail (bin && bf, false);
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	if (obj) {
		bf->bo = obj;
	} else {
		obj = bf->bo;
	}
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (bin->minstrlen < 1) {
		bin->minstrlen = plugin? plugin->minstrlen: bin->minstrlen;
	}
	if (obj) {
		if (!obj->info) {
			R_LOG_DEBUG ("bin object have no information");
			return false;
		}
		if (!obj->info->lang) {
			obj->info->lang = r_bin_lang_tostring (obj->lang);
		}
	}
	return true;
}

R_API bool r_bin_file_set_cur_binfile(RBin *bin, RBinFile *bf) {
	r_return_val_if_fail (bin && bf, false);
	return r_bin_file_set_obj (bin, bf, bf->bo);
}

R_API bool r_bin_file_set_cur_by_name(RBin *bin, const char *name) {
	r_return_val_if_fail (bin && name, false);
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API bool r_bin_file_deref(RBin *bin, RBinFile *a) {
	r_return_val_if_fail (bin && a, false);
	if (!r_bin_cur_object (bin)) {
		return false;
	}
	bin->cur = NULL;
	return true;
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
	r_bin_object_free (bf->bo);
	r_list_free (bf->xtr_data);
	if (bf->id != -1) {
		// TODO: use r_storage api
		r_id_pool_kick_id (bf->rbin->ids->pool, bf->id);
	}
	(void) r_bin_object_delete (bf->rbin, bf->id);
	free (bf);
}

R_IPI RBinFile *r_bin_file_xtr_load(RBin *bin, RBinXtrPlugin *xtr, const char *filename, RBuffer *buf, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
	r_return_val_if_fail (bin && xtr && buf, NULL);

	RBinFile *bf = r_bin_file_find_by_name (bin, filename);
	if (!bf) {
		bf = r_bin_file_new (bin, filename, r_buf_size (buf), rawstr, fd, xtr->meta.name, bin->sdb, false);
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
		R_LOG_WARN ("TODO: Implement extractall_from_buffer in '%s' xtr.bin plugin", xtr->meta.name);
		bf->xtr_data = xtr->extractall_from_bytes (bin, bytes, sz);
	}
	if (bf->xtr_data) {
		RListIter *iter;
		RBinXtrData *x;
		//populate xtr_data with baddr and laddr that will be used later on
		//r_bin_file_object_new_from_xtr_data
		r_list_foreach (bf->xtr_data, iter, x) {
			if (x == NULL) {
				R_LOG_WARN ("Null entry found in xtrdata list");
			} else {
				x->baddr = baseaddr? baseaddr : UT64_MAX;
				x->laddr = loadaddr? loadaddr : UT64_MAX;
			}
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
	return bf->buf;
}

R_API RBinPlugin *r_bin_file_cur_plugin(RBinFile *bf) {
	return (bf && bf->bo)? bf->bo->plugin: NULL;
}

// TODO: searchStrings() instead
R_IPI RList *r_bin_file_get_strings(RBinFile *bf, int min, int dump, int raw) {
	const bool nofp = bf->rbin->strings_nofp;
	r_return_val_if_fail (bf, NULL);
	RListIter *iter;
	RBinSection *section;
	RList *ret = dump? NULL: r_list_newf (r_bin_string_free);

	if (!raw && bf && bf->bo && bf->bo->sections && !r_list_empty (bf->bo->sections)) {
		RBinObject *o = bf->bo;
		r_list_foreach (o->sections, iter, section) {
			if (__isDataSection (bf, section)) {
				get_strings_range (bf, ret, min, raw, nofp, section->paddr,
						section->paddr + section->size, section);
			}
		}
		r_list_foreach (o->sections, iter, section) {
			/* load objc/swift strings */
			const int bits = (bf->bo && bf->bo->info) ? bf->bo->info->bits : 32;
			const int cfstr_size = (bits == 64) ? 32 : 16;
			const int cfstr_offs = (bits == 64) ? 16 :  8;
			if (strstr (section->name, "__cfstring")) {
				int i;
				// XXX do not walk if bin.strings == 0
				ut8 *p;
				if (section->size > bf->size) {
					continue;
				}
				if (section->size < 1) {
					continue;
				}
				ut8 *sbuf = malloc (section->size);
				if (!sbuf) {
					continue;
				}
				r_buf_read_at (bf->buf, section->paddr + cfstr_offs, sbuf, section->size);
				for (i = 0; i < section->size; i += cfstr_size) {
					ut8 *buf = sbuf;
					p = buf + i;
					if ((i + ((bits == 64)? 8: 4)) >= section->size) {
						break;
					}
					ut64 cfstr_vaddr = section->vaddr + i;
					ut64 cstr_vaddr = (bits == 64) ? r_read_le64 (p) : r_read_le32 (p);
					RBinString *s = __stringAt (bf, ret, cstr_vaddr);
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
		get_strings_range (bf, ret, min, raw, nofp, 0, bf->size, NULL);
	}
	return ret;
}

R_API ut64 r_bin_file_get_baddr(RBinFile *bf) {
	if (bf && bf->bo) {
		return bf->bo->baddr;
	}
	return UT64_MAX;
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

// TODO: do not compute md5 or sha1, those are weak and vulnerable hashes
R_API RList *r_bin_file_compute_hashes(RBin *bin, ut64 limit) {
	r_return_val_if_fail (bin && bin->cur && bin->cur->bo, NULL);
	ut64 buf_len = 0, r = 0;
	RBinFile *bf = bin->cur;
	RBinObject *o = bf->bo;

	RIODesc *iod = r_io_desc_get (bin->iob.io, bf->fd);
	if (!iod) {
		return NULL;
	}

	buf_len = r_io_desc_size (iod);
	// By SLURP_LIMIT normally cannot compute ...
	if (buf_len > limit) {
		if (bin->verbose) {
			R_LOG_WARN ("file size exceeds bin.hashlimit");
		}
		return NULL;
	}
	const size_t blocksize = 64000;
	ut8 *buf = malloc (blocksize);
	if (!buf) {
		return NULL;
	}

	char hash[128];
	RHash *ctx = r_hash_new (false, R_HASH_MD5 | R_HASH_SHA1 | R_HASH_SHA256);
	while (r + blocksize < buf_len) {
		r_io_desc_seek (iod, r, R_IO_SEEK_SET);
		int b = r_io_desc_read (iod, buf, blocksize);
		(void)r_hash_do_md5 (ctx, buf, blocksize);
		(void)r_hash_do_sha1 (ctx, buf, blocksize);
		(void)r_hash_do_sha256 (ctx, buf, blocksize);
		r += b;
	}
	if (r < buf_len) {
		r_io_desc_seek (iod, r, R_IO_SEEK_SET);
		const size_t rem_len = buf_len-r;
		int b = r_io_desc_read (iod, buf, rem_len);
		if (b < 1) {
			R_LOG_ERROR ("cannot read from descriptor");
		} else {
			(void)r_hash_do_md5 (ctx, buf, b);
			(void)r_hash_do_sha1 (ctx, buf, b);
			(void)r_hash_do_sha256 (ctx, buf, b);
		}
	}
	r_hash_do_end (ctx, R_HASH_MD5);
	r_hex_bin2str (ctx->digest, R_HASH_SIZE_MD5, hash);

	RList *file_hashes = r_list_newf ((RListFree) r_bin_file_hash_free);
	RBinFileHash *md5h = R_NEW0 (RBinFileHash);
	if (md5h) {
		md5h->type = strdup ("md5");
		md5h->hex = strdup (hash);
		r_list_push (file_hashes, md5h);
	}
	r_hash_do_end (ctx, R_HASH_SHA1);
	r_hex_bin2str (ctx->digest, R_HASH_SIZE_SHA1, hash);

	RBinFileHash *sha1h = R_NEW0 (RBinFileHash);
	if (sha1h) {
		sha1h->type = strdup ("sha1");
		sha1h->hex = strdup (hash);
		r_list_push (file_hashes, sha1h);
	}
	r_hash_do_end (ctx, R_HASH_SHA256);
	r_hex_bin2str (ctx->digest, R_HASH_SIZE_SHA256, hash);

	RBinFileHash *sha256h = R_NEW0 (RBinFileHash);
	if (sha256h) {
		sha256h->type = strdup ("sha256");
		sha256h->hex = strdup (hash);
		r_list_push (file_hashes, sha256h);
	}

	if (o->plugin && o->plugin->hashes) {
		RList *plugin_hashes = o->plugin->hashes (bf);
		r_list_join (file_hashes, plugin_hashes);
		free (plugin_hashes);
	}
	// TODO: add here more rows

	free (buf);
	r_hash_free (ctx);
	return file_hashes;
}

// Set new hashes to current RBinInfo, caller should free the returned RList
R_API RList *r_bin_file_set_hashes(RBin *bin, RList/*<RBinFileHash*/ *new_hashes) {
	r_return_val_if_fail (bin && bin->cur && bin->cur->bo && bin->cur->bo->info, NULL);
	RBinFile *bf = bin->cur;
	RBinInfo *info = bf->bo->info;

	RList *prev_hashes = info->file_hashes;
	info->file_hashes = new_hashes;

	return prev_hashes;
}

R_API RBinClass *r_bin_class_new(const char *name, const char *super, int view) {
	r_return_val_if_fail (name, NULL);
	RBinClass *c = R_NEW0 (RBinClass);
	if (c) {
		c->name = strdup (name);
		if (super) {
			c->super = r_list_newf (free);
			r_list_append (c->super, strdup (super));
		}
		c->methods = r_list_newf (r_bin_symbol_free);
		c->fields = r_list_newf (r_bin_field_free);
		c->visibility = view;
	}
	return c;
}

R_API void r_bin_class_free(RBinClass *k) {
	if (k) {
		free (k->name);
		r_list_free (k->super);
		free (k->visibility_str);
		r_list_free (k->methods);
		r_list_free (k->fields);
		free (k);
	}
}

R_API RBinClass *r_bin_file_add_class(RBinFile *bf, const char *name, const char *super, int view) {
	r_return_val_if_fail (name && bf && bf->bo, NULL);
	RBinClass *c = __getClass (bf, name);
	if (c) {
		if (super) {
			r_list_free (c->super);
			c->super = r_list_newf (free);
			r_list_append (c->super, strdup (super));
		}
		return c;
	}
	c = r_bin_class_new (name, super, view);
	if (c) {
		// XXX. no need for a list, the ht is iterable too
		c->index = r_list_length (bf->bo->classes);
		r_list_append (bf->bo->classes, c);
		ht_pp_insert (bf->bo->classes_ht, name, c);
	}
	return c;
}

R_API RBinSymbol *r_bin_file_add_method(RBinFile *bf, const char *klass, const char *method, int nargs) {
	r_return_val_if_fail (bf, NULL);

	RBinClass *c = r_bin_file_add_class (bf, klass, NULL, 0);
	if (!c) {
		R_LOG_ERROR ("Cannot allocate class %s", klass);
		return NULL;
	}
	int lang = (strstr (method, "JNI") || strstr (klass, "JNI"))? R_BIN_LANG_JNI: R_BIN_LANG_CXX;
	c->lang = lang;
	RBinSymbol *sym = __getMethod (bf, klass, method);
	if (!sym) {
		sym = R_NEW0 (RBinSymbol);
		if (sym) {
			sym->name = strdup (method);
			sym->lang = lang;
			char *name = r_str_newf ("%s::%s", klass, method);
			ht_pp_insert (bf->bo->methods_ht, name, sym);
			// RBinSymbol *dsym = r_bin_symbol_clone (sym);
			r_list_append (c->methods, sym);
			free (name);
		}
	}
	return sym;
}

R_API RBinField *r_bin_file_add_field(RBinFile *binfile, const char *classname, const char *name) {
	R_LOG_TODO ("RBinFile.addField() is not implemented");
	return NULL;
}

// XXX this api name makes no sense
/* returns vaddr, rebased with the baseaddr of binfile, if va is enabled for
 * bin, paddr otherwise */
R_API ut64 r_bin_file_get_vaddr(RBinFile *bf, ut64 paddr, ut64 vaddr) {
	r_return_val_if_fail (bf && bf->bo, paddr);
	if (bf->bo->info && bf->bo->info->has_va) {
		return bf->bo->baddr_shift + vaddr;
	}
	return paddr;
}

R_API RList *r_bin_file_get_trycatch(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->plugin, NULL);
	if (bf->bo->plugin->trycatch) {
		return bf->bo->plugin->trycatch (bf);
	}
	return NULL;
}

// TODO: Deprecate, we dont want to clone the vec into a list
R_API RList *r_bin_file_get_symbols(RBinFile *bf) {
	r_return_val_if_fail (bf, NULL);
	RBinObject *bo = bf->bo;
	if (!bo->symbols) {
		if (!RVecRBinSymbol_empty (&bo->symbols_vec)) {
			R_LOG_DEBUG ("cloning symbols vector into a list"); // R2_600
			RList *list = r_list_newf (NULL);
			RBinSymbol *s;
			R_VEC_FOREACH (&bo->symbols_vec, s) {
				r_list_append (list, s);
			}
			bo->symbols = list;
		}
	}
	return bo? bo->symbols: NULL;
}

R_API RVecRBinSymbol *r_bin_file_get_symbols_vec(RBinFile *bf) {
	r_return_val_if_fail (bf, NULL);
	RBinObject *bo = bf->bo;
	if (bo) {
		if (bo->symbols && RVecRBinSymbol_empty (&bo->symbols_vec)) {
			R_LOG_DEBUG ("SLOW: cloning symbols list into a vec"); // R2_600
			RBinSymbol *symbol;
			// Create a vector for those plugins not loading the rvec
			RList *list = bo->symbols;
			RListIter *iter;
			r_list_foreach (list, iter, symbol) {
				RVecRBinSymbol_push_back (&bo->symbols_vec, symbol);
			}
		}
		return &bo->symbols_vec;
	}
	return NULL;
}

R_API RBinFile *r_bin_file_open(RBin *bin, const char *file, RBinFileOptions *opt) {
	if (r_bin_open (bin, file, opt)) {
		return r_bin_cur (bin);
	}
	return NULL;
}

// TODO Improve this API
R_API void r_bin_file_merge(RBinFile *dst, RBinFile *src) {
	// merge imports
	// merge dbginfo
	sdb_merge (dst->bo->kv, src->bo->kv);
	sdb_merge (dst->sdb_addrinfo, src->sdb_addrinfo);
	sdb_merge (dst->sdb_info, src->sdb_info);
}
