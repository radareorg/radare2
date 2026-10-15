/* radare2 - LGPL - Copyright 2009-2026 - pancake, nibble, dso */

#include <r_bin.h>
#include <r_muta.h>
#include "i/private.h"
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

// maybe too big sometimes? 2KB of stack eaten here..
#define R_STRING_SCAN_BUFFER_SIZE 4096
#define R_STRING_MAX_UNI_BLOCKS 4

typedef struct {
	RBinFile *bf;
	RVecRBinString *strings;
	HtUP *strings_index;
	RStrBuf *output;
	int min, raw;
} RBinStringScanOptions;

static RBinClass *__getClass(RBinFile *bf, const char *name) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->classes_ht && name, NULL);
	return ht_pp_find (bf->bo->classes_ht, name, NULL);
}

static RBinSymbol *__getMethod(RBinClass *c, const char *method) {
	R_RETURN_VAL_IF_FAIL (c && method, NULL);
	RBinSymbol *sym;
	R_VEC_FOREACH (&c->methods, sym) {
		const char *n = r_bin_name_tostring (sym->name);
		if (n && !strcmp (n, method)) {
			return sym;
		}
	}
	return NULL;
}

static void print_string(const RBinStringScanOptions *options, RBinString *string, PJ *pj) {
	RBinFile *bf = options->bf;
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
	ut64 vaddr = io->va ? r_bin_get_vaddr (bin, string->paddr, string->vaddr) : string->paddr;

	switch (bf->strmode) {
	case R_MODE_JSON:
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
		break;
	case R_MODE_SIMPLEST:
		r_strbuf_appendf (options->output, "%s\n", string->string);
		break;
	case R_MODE_SIMPLE:
		if (options->raw == 2) {
			r_strbuf_appendf (options->output, "0x%08"PFMT64x" %s\n", vaddr, string->string);
		} else {
			r_strbuf_appendf (options->output, "%s\n", string->string);
		}
		break;
	case R_MODE_RADARE: {
		char *f_name = strdup (string->string);
		r_name_filter (f_name, -1);
		if (bin->prefix) {
			r_strbuf_appendf (options->output, "'0x%08"PFMT64x"'f %s.str.%s %u\n"
					"'0x%08"PFMT64x"'Cs %u\n",
					vaddr, bin->prefix, f_name, string->size,
					vaddr, string->size);
		} else {
			r_strbuf_appendf (options->output, "'0x%08"PFMT64x"'f str.%s %u\n"
					"'0x%08"PFMT64x"'Cs %u\n",
					vaddr, f_name, string->size,
					vaddr, string->size);
		}
		free (f_name);
		break;
		}
	case R_MODE_PRINT:
		r_strbuf_appendf (options->output, "%03u 0x%08" PFMT64x " 0x%08" PFMT64x " %3u %3u "
			       "(%s) %5s %s\n",
			string->ordinal, string->paddr, vaddr,
			string->length, string->size,
			section_name, type_string, string->string);
		break;
	}
}

static void string_set_addrs(RBinString *bs, ut64 str_start, ut64 pdelta, ut64 vdelta, ut64 baddr, ut64 maddr) {
	ut64 addr = 0;
	bs->paddr = r_add_overflow (str_start, baddr, &addr) ? str_start : addr;
	if (r_sub_overflow (str_start, pdelta, &addr) ||
			r_add_overflow (addr, vdelta, &addr) ||
			r_add_overflow (addr, baddr, &addr) ||
			r_add_overflow (addr, maddr, &addr)) {
		addr = str_start;
	}
	bs->vaddr = addr;
}

// TODO: this code must be implemented in RSearch as options for the strings mode
static void string_scan_range(const RBinStringScanOptions *options, const ut64 from, const ut64 to, int type, RBinSection *section) {
	RBinFile *bf = options->bf;
	RBin *bin = bf->rbin;
	const int min = options->min;
	const bool strings_nofp = bin->strings_nofp;
	ut8 tmp[64]; // temporal buffer to encode characters in utf8 form
	ut64 str_start, needle = from;
	int i, rc, runes;
	int str_type = R_STRING_TYPE_DETECT;
	const int limit = bf->rbin->options.limit;
	int maxstr = bin->options.maxstrlen;
	if (maxstr < 1) {
		maxstr = R_STRING_SCAN_BUFFER_SIZE;
	}

	if (from == UT64_MAX || from == to) {
		return;
	}
	if (from > to) {
		R_LOG_ERROR ("Invalid range to find strings 0x%"PFMT64x" .. 0x%"PFMT64x, from, to);
		return;
	}
	st64 len = (st64)(to - from);
	if (len < 1 || len > ST32_MAX) {
		R_LOG_ERROR ("String scan range is invalid (%"PFMT64d" bytes)", len);
		return;
	}
	ut8 *buf = calloc (len, 1);
	if (!buf) {
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		free (buf);
		return;
	}
	st64 vdelta = 0, pdelta = 0;
	RBinSection *s = NULL;
	bool ascii_only = false;
	PJ *pj = NULL;
	if (bf->strmode == R_MODE_JSON && options->output) {
		pj = pj_new ();
		if (pj) {
			pj_a (pj);
		}
	}
	r_buf_read_at (bf->buf, from, buf, len);
	const char *charset = getenv ("RABIN2_CHARSET");
	if (R_STR_ISNOTEMPTY (charset) && bin->mb.muta) {
		// Decode the buffer using the specified charset
		RMutaSession *ms = bin->mb.muta_use (bin->mb.muta, charset);
		if (ms) {
			ms->dir = R_MUTA_OP_DECRYPT;
			r_muta_session_update (ms, buf, len);
			int outlen = 0;
			ut8 *obuf = bin->mb.muta_session_get_output (ms, &outlen);
			if (outlen > 0 && obuf) {
				ut8 *out = calloc (len, 1);
				if (out) {
					int i;
					int cpy = R_MIN ((int)len, outlen);
					memcpy (out, obuf, cpy);
					// TODO unknown chars should be translated to null bytes
					for (i = 0; i < cpy; i++) {
						if (out[i] == '?') {
							out[i] = 0;
						}
					}
					free (buf);
					buf = out;
				}
			}
			free (obuf);
			bin->mb.muta_session_free (ms);
		} else {
			R_LOG_ERROR ("Invalid value for RABIN2_CHARSET");
		}
	}
	RCons *cons = bin->consb.cons;
	RConsIsBreaked is_breaked = (bin && bin->consb.is_breaked)? bin->consb.is_breaked: NULL;
	// may oobread
	while (needle < to && needle < UT64_MAX - 4) {
		if (is_breaked && is_breaked (cons)) {
			break;
		}
		// smol optimization
		if (to > 4 && needle < to - 4) {
			ut32 n1 = r_read_le32 (buf + needle - from);
			if (!n1) {
				needle += 4;
				continue;
			}
		}
		rc = r_utf8_decode (buf + needle - from, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		const bool addr_aligned = !(needle % 4);

		if (type == R_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc - from;
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
				if (is_wide32le && addr_aligned) {
					str_type = R_STRING_TYPE_WIDE32; // asume big endian,is there little endian w32?
				} else {
					// bool is_wide = (n1 && n2 && n1 < 0xff && (!n2 || n2 < 0xff));
					bool is_wide = needle + rc + 4 < to && !w[0] && w[1] && !w[2] && w[3] && !w[4];
					str_type = is_wide? R_STRING_TYPE_WIDE: R_STRING_TYPE_ASCII;
				}
			} else {
				str_type = (rc > 1)
					? R_STRING_TYPE_UTF8
					: R_STRING_TYPE_ASCII;
			}
		} else if (type == R_STRING_TYPE_UTF8) {
			str_type = R_STRING_TYPE_ASCII; // initial assumption
		} else {
			str_type = type;
		}
		runes = 0;
		str_start = needle;

		r_strbuf_set (sb, "");
		/* Eat a whole C string */
		for (i = 0; i < maxstr && needle < to; i += rc) {
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
				rc = r_utf8_encode (tmp, r);
				tmp[rc] = 0;
				r_strbuf_append (sb, (const char *)tmp);
				runes++;
			} else if (r && r < 0x100 && strchr ("\b\v\f\n\r\t\a\033\\", (char)r)) {
				/* Print the escape code */
				if (strings_nofp) {
					rc = 2;
					if (r && r < 0x100 && strchr ("\n\r\t\033\\", (char)r)) {
						runes++; // accept it as it is
						rc = 1;
					} else {
						rc = 1;
						r = 0;
						break;
					}
				} else {
					if (r < 93) {
						tmp[0] = '\\';
						tmp[1] = "       abtnvfr             e  "
							"                              "
							"                              "
							"  \\"[r];
					} else {
						// string too long
						break;
					}
					rc = 2;
					tmp[rc] = 0;
					r_strbuf_append (sb, (const char *)tmp);
					runes++;
				}
			} else {
				/* \0 marks the end of C-strings */
				break;
			}
		}

		i++;

		if (runes < min && runes >= 2 && str_type == R_STRING_TYPE_ASCII && needle < to) {
			// back up past the \0 to the last char just in case it starts a wide string
			needle -= 2;
		}
		if (runes >= min) {
			// discard unaligned strings
			const int str_align = bin->options.str_align;
			if (str_align > 0 && (str_start % str_align)) {
				continue;
			}
			const char *tmpstr = r_strbuf_get (sb);
			size_t tmplen = r_strbuf_length (sb);
			// reduce false positives
			int j, num_blocks;
			int *freq_list = NULL, expected_ascii, actual_ascii, num_chars;
			if (str_type == R_STRING_TYPE_ASCII) {
				for (j = 0; j < tmplen; j++) {
					char ch = tmpstr[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE (ch)) {
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
				int *block_list = r_utf_block_list ((const ut8*)tmpstr, tmplen,
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
						if (block_list && !block_list[j]) { // ASCII
							actual_ascii = freq_list[j];
						}
					}
					free (freq_list);
					expected_ascii = num_blocks ? num_chars / num_blocks : 0;
					if (actual_ascii > expected_ascii) {
						ascii_only = true;
						needle = str_start;
						R_FREE (block_list);
						continue;
					}
				}
				R_FREE (block_list);
				if (num_blocks > R_STRING_MAX_UNI_BLOCKS) {
					needle++;
					continue;
				}
			}
			RBinString bs = { 0 };
			bs.type = str_type;
			bs.size = needle - str_start;
			bs.ordinal = bf->string_count++;
			if (limit > 0 && bf->string_count > limit) {
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
					s = r_bin_get_section_at (bf->bo, str_start + bf->bo->boffset + bf->bo->loadaddr, false);
				}
				if (s) {
					vdelta = s->vaddr;
					pdelta = r_bin_file_get_buffer_offset (bf, s->paddr);
				}
			}
			ut64 baddr = bf->loadaddr && bf->bo? bf->bo->baddr: bf->loadaddr;
			if (!s && bf->bo && RVecRBinSection_empty (&bf->bo->sections_vec) && !bf->loadaddr && bf->bo->baddr != UT64_MAX) {
				baddr = bf->bo->baddr;
			}
			ut64 maddr = bf->bo? 0: bf->loadaddr;
			string_set_addrs (&bs, str_start, pdelta, vdelta, baddr, maddr);
			if (bf->bo) {
				bs.paddr += bf->bo->boffset;
			}
			char *str = r_strbuf_drain (sb);
			sb = r_strbuf_new ("");
			size_t before = strlen (str);
			if (strings_nofp) {
				r_str_trim (str); // trim spaces to ease readability
			} else {
				r_str_trim_tail (str);
			}
			bs.string = str;
			bs.length = runes - (before - strlen (str));
			if (options->strings) {
				size_t string_index = RVecRBinString_length (options->strings);
				RBinString *dst = RVecRBinString_emplace_back (options->strings);
				if (dst) {
					*dst = bs;
					r_bin_strings_index_insert (options->strings_index, dst->vaddr, string_index);
				} else {
					r_bin_string_fini (&bs);
					break;
				}
			} else {
				print_string (options, &bs, pj);
				r_bin_string_fini (&bs);
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
		r_strbuf_append (options->output, pj_string (pj));
		pj_free (pj);
	}
	r_strbuf_free (sb);
}

static bool is_data_section(RBinFile *a, RBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	}
 	// Rust
	return s->name && strstr (s->name, "_const");
}

static void get_strings_range(RBinStringScanOptions *options, ut64 from, ut64 to, RBinSection *section) {
	RBinFile *bf = options->bf;
	RBin *bin = bf->rbin;
	if (!bf->buf) {
		return;
	}
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (!options->raw && (!plugin || !plugin->info)) {
		return;
	}
	if (!options->min) {
		options->min = plugin && plugin->minstrlen? plugin->minstrlen: 4;
	}
	if (options->min < 0) {
		return;
	}
	RCoreBind *cb = &bin->iob.io->coreb;
	if (cb->cfgGet && cb->cfgGetI) {
		if (!cb->cfgGet (cb->core, "cfg.debug")) {
			if (!to || to > r_buf_size (bf->buf)) {
				to = r_buf_size (bf->buf);
			}
			if (!to) {
				return;
			}
		}
		if (!bf->bo) {
			bf->loadaddr = cb->cfgGetI (cb->core, "bin.laddr");
		}
	}
	if (options->raw != 2) {
		ut64 size = to - from;
		ut64 maxstrbuf = bin->options.maxstrbuf;
		if (maxstrbuf && size > maxstrbuf) {
			if (bin->options.verbose) {
				R_LOG_WARN ("bin_strings buffer is too big (0x%08" PFMT64x "). Use -zzz or set bin.str.maxbuf (RABIN2_MAXSTRBUF) in r2 (rabin2)", size);
			}
			return;
		}
	}
	int type;
	const char *enc = bin->strenc;
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
	} else {
		R_LOG_ERROR ("encoding %s not supported", enc);
		return;
	}
	string_scan_range (options, from, to, type, section);
}

/////////////////////////////
/// ^move into addrline.c ///
/////////////////////////////

static void addrline_item_fini(RBinAddrline *item) {
	// RBinAddrline fields are indexes into strpool, no need to free
}

R_VEC_TYPE_WITH_FINI (RVecAddrLine, RBinAddrline, addrline_item_fini);

typedef struct {
	RVecAddrLine vec;
	RStrpool *pool;
	HtUP *ht;  // maps addr -> index+1 in vec (0 means not found)
} AddrLineStore;

static bool al_add(RBinAddrLineStore *als, ut64 addr, const char *file, const char *path, ut32 line, ut32 column) {
	AddrLineStore *store = als->storage;
	als->used = true;
	bool found = false;
	ut64 existing_idx = (ut64)(size_t)ht_up_find (store->ht, addr, &found);
	if (found && existing_idx > 0) {
		RBinAddrline *hitem = RVecAddrLine_at (&store->vec, existing_idx - 1);
		if (hitem && hitem->line == line) {
			return false;
		}
		// Different line at same address - add to vec but keep first hash entry
		RBinAddrline *di = RVecAddrLine_emplace_back (&store->vec);
		di->addr = addr;
		di->line = line;
		di->column = column;
		di->file = file ? r_strpool_add (store->pool, file) : UT32_MAX;
		di->path = path ? r_strpool_add (store->pool, path) : UT32_MAX;
		return true;
	}
	size_t new_idx = RVecAddrLine_length (&store->vec);
	RBinAddrline *di = RVecAddrLine_emplace_back (&store->vec);
	di->addr = addr;
	di->line = line;
	di->column = column;
	di->file = file ? r_strpool_add (store->pool, file) : UT32_MAX;
	di->path = path ? r_strpool_add (store->pool, path) : UT32_MAX;
	ht_up_insert (store->ht, addr, (void*)(size_t)(new_idx + 1));
	return true;
}

static bool al_add_cu(RBinAddrLineStore *als, ut64 addr, const char *file, const char *path, ut32 line, ut32 column) {
	AddrLineStore *store = als->storage;
	if (file) {
		als->used = true;
		r_strpool_add (store->pool, file);
	}
	return true;
}

static void al_reset(RBinAddrLineStore *als) {
	AddrLineStore *store = als->storage;
	RVecAddrLine_fini (&store->vec);
	RVecAddrLine_init (&store->vec);
	r_strpool_free (store->pool);
	store->pool = r_strpool_new ();
	ht_up_free (store->ht);
	store->ht = ht_up_new0 ();
}

static RList *al_files(RBinAddrLineStore *als) {
	AddrLineStore *store = als->storage;
	RList *files = r_list_newf (free);
	int i;
	for (i = 0; true; i++) {
		char *n = r_strpool_get_nth (store->pool, i);
		if (!n) {
			break;
		}
		r_list_append (files, strdup (n));
	}
	return files;
}

static void al_foreach(RBinAddrLineStore *als, RBinDbgInfoCallback cb, void *user) {
	AddrLineStore *store = als->storage;
	RBinAddrline *item;
	R_VEC_FOREACH (&store->vec, item) {
		if (!cb (user, item)) {
			break;
		}
	}
}

static void al_del(RBinAddrLineStore *als, ut64 addr) {
	AddrLineStore *store = als->storage;
	ht_up_delete (store->ht, addr);
	// Note: not removing from vec as it would be O(n) and shift pointers
}

static const RBinAddrline *al_get(RBinAddrLineStore *als, ut64 addr) {
	AddrLineStore *store = als->storage;
	bool found = false;
	ut64 idx = (ut64)(size_t)ht_up_find (store->ht, addr, &found);
	if (found && idx > 0) {
		return RVecAddrLine_at (&store->vec, idx - 1);
	}
	return NULL;
}

static bool addrline_file_match_str(const char *path, const char *file) {
	if (R_STR_ISEMPTY (path) || R_STR_ISEMPTY (file)) {
		return false;
	}
	if (!strcmp (path, file)) {
		return true;
	}
	const char *pbase = r_file_basename (path);
	const char *fbase = r_file_basename (file);
	return (pbase && fbase && !strcmp (pbase, fbase));
}

static ut64 al_find(RBinAddrLineStore *als, const char *file, ut32 line) {
	AddrLineStore *store = als->storage;
	RBinAddrline *item;
	R_VEC_FOREACH (&store->vec, item) {
		if (item->line != line) {
			continue;
		}
		const char *path = r_strpool_get_nth (store->pool, item->path);
		const char *fname = r_strpool_get_nth (store->pool, item->file);
		if (addrline_file_match_str (path, file) || addrline_file_match_str (fname, file)) {
			return item->addr;
		}
	}
	return UT64_MAX;
}

static const char *al_str(RBinAddrLineStore *als, ut32 idx) {
	if (idx == UT32_MAX) {
		return NULL;
	}
	AddrLineStore *store = als->storage;
	return r_strpool_get_nth (store->pool, idx);
}

static void addrline_store_init(RBinAddrLineStore *b) {
	AddrLineStore *als = R_NEW0 (AddrLineStore);
	als->ht = ht_up_new0 ();
	RVecAddrLine_init (&als->vec);
	als->pool = r_strpool_new ();
	b->storage = (void*)als;
	b->al_add = al_add;
	b->al_add_cu = al_add_cu;
	b->al_get = al_get;
	b->al_find = al_find;
	b->al_del = al_del;
	b->al_reset = al_reset;
	b->al_foreach = al_foreach;
	b->al_files = al_files;
	b->al_str = al_str;
}

static void addrline_store_fini(RBinAddrLineStore *als) {
	AddrLineStore *store = als->storage;
	if (store) {
		ht_up_free (store->ht);
		RVecAddrLine_fini (&store->vec);
		r_strpool_free (store->pool);
	}
	free (als->storage);
}
//////////////////////////////////

R_IPI RBinFile *r_bin_file_new(RBin *bin, const char *file, ut64 file_sz, RBinFileOptions *opt, Sdb *sdb, bool steal_ptr) {
	ut32 bf_id;
	if (!r_id_pool_grab_id (bin->ids->pool, &bf_id)) {
		return NULL;
	}
	// Create arena first for efficient memory management
	RArena *arena = r_arena_new ();
	if (!arena) {
		r_id_pool_kick_id (bin->ids->pool, bf_id);
		return NULL;
	}
	RBinFile *bf = r_arena_calloc (arena, sizeof (RBinFile));
	if (!bf) {
		r_arena_free (arena);
		r_id_pool_kick_id (bin->ids->pool, bf_id);
		return NULL;
	}
	bf->arena = arena;
	addrline_store_init (&bf->addrline);
	bf->id = bf_id;
	bf->rbin = bin;
	bf->file = file ? r_arena_push_str (arena, file) : NULL;
	bf->rawstr = opt->rawstr;
	bf->inmem = opt->inmem;
	bf->fd = opt->fd;
	bf->curxtr = opt->pluginname? r_libstore_find_name_in (bin->libstore, bin->libstore->xtrs, opt->pluginname) : NULL;
	if ((st64)file_sz < 0) {
		file_sz = 1024 * 64;
	}
	bf->size = file_sz;
	bf->xtr_data = r_list_newf ((RListFree)r_bin_xtrdata_free);
	bf->xtr_obj = NULL;
	bf->sdb = sdb_new0 ();
	bf->dwarf_metadata.comp_dir = NULL;
	bf->dwarf_metadata.comp_dirs = NULL;
	return bf;
}

static RBinPlugin *get_plugin_from_buffer(RBin *bin, RBinFile *bf, const char *pluginname, RBuffer *buf) {
	RBinPlugin *plugin = bin->force? r_libstore_find_name (bin->libstore, bin->force): NULL;
	if (!plugin) {
		plugin = pluginname? r_libstore_find_name (bin->libstore, pluginname): NULL;
		if (!plugin) {
			plugin = r_bin_get_binplugin_by_buffer (bin, bf, buf);
			if (!plugin) {
				return r_libstore_find_name (bin->libstore, "null");
			}
		}
	}
	return plugin;
}

R_API bool r_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data) {
	R_RETURN_VAL_IF_FAIL (bin && bf && data, false);

	ut64 offset = data->offset;
	ut64 sz = data->size;

	RBinPlugin *plugin = get_plugin_from_buffer (bin, bf, NULL, data->buf);
	bf->buf = r_ref (data->buf);
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
	o->info->file = strdup (bf->file);
	if (data->metadata) {
		if (data->metadata->arch) {
			R_FREE (o->info->arch);
			o->info->arch = strdup (data->metadata->arch);
		}
		if (data->metadata->machine) {
			R_FREE (o->info->machine);
			o->info->machine = strdup (data->metadata->machine);
		}
		if (data->metadata->type) {
			R_FREE (o->info->type);
			o->info->type = strdup (data->metadata->type);
		}
		if (data->metadata->bits > 0) {
			o->info->bits = data->metadata->bits;
		}
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
	return bits == iter_bits && !strcmp (iter_arch, arch);
}

static int native_arm64_subtype(void) {
#if defined(__APPLE__)
	int cpu_type = 0;
	int subtype = 0;
	size_t size = sizeof (cpu_type);
	if (!sysctlbyname ("hw.cputype", &cpu_type, &size, NULL, 0) && cpu_type == 0x0100000c) {
		size = sizeof (subtype);
		if (!sysctlbyname ("hw.cpusubtype", &subtype, &size, NULL, 0)) {
			return subtype & 0x00ffffff;
		}
	}
#endif
	return 0;
}

static int xtr_arm64_priority(const char *machine, int native_subtype) {
	if (!strcmp (r_str_get (machine), "arm64e.x1")) {
		return native_subtype == 12? 5: 0;
	}
	if (!strcmp (r_str_get (machine), "arm64.x1")) {
		return native_subtype == 3 || native_subtype == 12? 4: 0;
	}
	if (!strcmp (r_str_get (machine), "arm64e")) {
		return native_subtype == 2 || native_subtype == 12? 3: 1;
	}
	return 2;
}

static RBinFile *find_arch_in_file(RBin *bin, RBinFile *bf, const char *arch, int bits) {
	if (!bf) {
		return NULL;
	}
	RBinInfo *info = bf->bo? bf->bo->info: NULL;
	const bool current_matches = info && info->arch && info->bits == bits && !strcmp (info->arch, arch);
	if (r_list_empty (bf->xtr_data)) {
		return current_matches? bf: NULL;
	}
	const bool arm64 = bits == 64 && !strcmp (arch, "arm");
	const int native_subtype = arm64? native_arm64_subtype (): 0;
	RBinXtrData *selected = NULL;
	RBinXtrData *candidate;
	RListIter *iter;
	int priority = -1;
	r_list_foreach (bf->xtr_data, iter, candidate) {
		if (!xtr_metadata_match (candidate, arch, bits)) {
			continue;
		}
		if (candidate->loaded && current_matches && bf->bo->boffset == candidate->offset) {
			return bf;
		}
		int candidate_priority = arm64? xtr_arm64_priority (candidate->metadata->machine, native_subtype): 0;
		if (candidate_priority > priority) {
			selected = candidate;
			priority = candidate_priority;
		}
	}
	if (selected && r_bin_file_object_new_from_xtr_data (bin, bf, selected->baddr, selected->laddr, selected)) {
		return bf;
	}
	return NULL;
}

R_IPI RBinFile *r_bin_file_new_from_buffer(RBin *bin, const char *file, RBuffer *buf, RBinFileOptions *opt) {
	// int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname) {
	R_RETURN_VAL_IF_FAIL (bin && file && buf, NULL);

	RBinFile *bf = r_bin_file_new (bin, file, r_buf_size (buf), opt, NULL, false);
	if (bf) {
		RListIter *item = r_list_append (bin->binfiles, bf);
		bf->buf = r_ref (buf);
		bf->user_baddr = opt->baseaddr;
		RBinPlugin *plugin = get_plugin_from_buffer (bin, bf, opt->pluginname, bf->buf);
		RBinObject *o = r_bin_object_new (bf, plugin, opt->baseaddr, opt->loadaddr, 0, r_buf_size (bf->buf));
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

	R_RETURN_VAL_IF_FAIL (bin && arch, NULL);
	RBinFile *current = find_arch_in_file (bin, bin->cur, arch, bits);
	if (current) {
		return current;
	}

	r_list_foreach (bin->binfiles, iter, binfile) {
		if (binfile == bin->cur) {
			continue;
		}
		if (find_arch_in_file (bin, binfile, arch, bits)) {
			return binfile;
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
	R_RETURN_VAL_IF_FAIL (bin, false);

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
	R_RETURN_VAL_IF_FAIL (bin, NULL);

	RListIter *iter;
	RBinFile *bf;

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf->fd == bin_fd) {
			return bf;
		}
	}
	return NULL;
}

R_API RBinFile *r_bin_file_find_by_name(RBin *bin, const char *name) {
	R_RETURN_VAL_IF_FAIL (bin && name, NULL);

	RListIter *iter;
	RBinFile *bf;
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf->file && !strcmp (bf->file, name)) {
			return bf;
		}
	}
	return NULL;
}

R_API bool r_bin_file_set_cur_by_id(RBin *bin, ut32 bin_id) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *bf = r_bin_file_find_by_id (bin, bin_id);
	return bf? r_bin_file_set_cur_binfile (bin, bf): false;
}

R_API bool r_bin_file_set_cur_by_fd(RBin *bin, ut32 bin_fd) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *bf = r_bin_file_find_by_fd (bin, bin_fd);
	return bf? r_bin_file_set_cur_binfile (bin, bf): false;
}

R_IPI bool r_bin_file_set_obj(RBin *bin, RBinFile *bf, RBinObject * R_NULLABLE obj) {
	R_RETURN_VAL_IF_FAIL (bin && bf, false);
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	if (obj) {
		bf->bo = obj;
	} else {
		obj = bf->bo;
	}
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (bin->options.minstrlen < 1) {
		bin->options.minstrlen = plugin? plugin->minstrlen: bin->options.minstrlen;
	}
	if (obj) {
		if (!obj->info) {
			R_LOG_DEBUG ("bin object have no information");
			return false;
		}
		if (!obj->info->lang) {
			obj->info->lang = r_bin_lang_tostring (R_VPACK_FIRST (obj->langs));
		}
	}
	return true;
}

R_API bool r_bin_file_set_cur_binfile(RBin *bin, RBinFile * R_NULLABLE bf) {
	// R2_600 - deprecate - because this is unsafe. always use id
	R_RETURN_VAL_IF_FAIL (bin, false);
	if (bf == NULL) {
		bin->cur = NULL;
		return true;
	}
	return r_bin_file_set_obj (bin, bf, bf->bo);
}

R_API bool r_bin_file_set_cur_by_name(RBin *bin, const char *name) {
	R_RETURN_VAL_IF_FAIL (bin && name, false);
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API bool r_bin_file_deref(RBin *bin, RBinFile *a) {
	R_RETURN_VAL_IF_FAIL (bin && a, false);
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
	RBinPlugin *plugin = R_UNWRAP3 (bf, bo, plugin);
	// Binary format objects are connected to the
	// RBinObject, so the plugin must destroy the
	// format data first
	if (plugin && plugin->destroy) {
		plugin->destroy (bf);
	}
	addrline_store_fini (&bf->addrline);
	r_unref (bf->buf);
	if (bf->curxtr && bf->curxtr->destroy && bf->xtr_obj) {
		bf->curxtr->free_xtr ((void *)(bf->xtr_obj));
	}
	// Avoid double-free: r_bin_object_new aliases bo->kv to bf->sdb
	if (bf->bo && bf->bo->kv == bf->sdb) {
		bf->bo->kv = NULL;
	}
	sdb_free (bf->sdb);
	// Cleanup DWARF metadata
	R_FREE (bf->dwarf_metadata.comp_dir);
	ht_up_free (bf->dwarf_metadata.comp_dirs);
	r_bin_object_free (bf->bo);
	r_list_free (bf->xtr_data);
	if (bf->id != -1) {
		// TODO: use r_storage api
		r_id_pool_kick_id (bf->rbin->ids->pool, bf->id);
	}
	(void) r_bin_object_delete (bf->rbin, bf->id);
	// Arena owns all arena-allocated memory including bf->file and bf itself
	r_arena_free (bf->arena);
}

R_IPI RBinFile *r_bin_file_xtr_load(RBin *bin, RBinXtrPlugin *xtr, const char *filename, RBuffer *buf, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
	R_RETURN_VAL_IF_FAIL (bin && xtr && buf, NULL);

	RBinFile *bf = r_bin_file_find_by_name (bin, filename);
	if (!bf) {
		RBinFileOptions opt = {
			.rawstr = rawstr,
			.fd = fd,
			.pluginname = xtr->meta.name,
		};
		bf = r_bin_file_new (bin, filename, r_buf_size (buf), &opt, bin->sdb, false);
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
	R_RETURN_VAL_IF_FAIL (bf && bytes, false);
	r_unref (bf->buf);
	if (steal_ptr) {
		bf->buf = r_buf_new_with_pointers (bytes, sz, true);
	} else {
		bf->buf = r_buf_new_with_bytes (bytes, sz);
	}
	return bf->buf;
}

R_API RBinPlugin *r_bin_file_cur_plugin(RBinFile *bf) {
	return R_UNWRAP3 (bf, bo, plugin);
}

// TODO: searchStrings() instead
R_IPI RVecRBinString *r_bin_file_get_strings(RBinFile *bf, int min, int raw, RStrBuf *output) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	RBinObject *bo = bf->bo;
	RBinSection *section;
	RVecRBinString *ret = output? NULL: RVecRBinString_new ();
	const bool has_sections = !raw && bo && !RVecRBinSection_empty (&bo->sections_vec);
	HtUP *strings_index = ret && has_sections? ht_up_new0 (): NULL;
	RBinStringScanOptions options = {
		.bf = bf,
		.strings = ret,
		.strings_index = strings_index,
		.output = output,
		.min = min,
		.raw = raw,
	};
	const int limit = bf->rbin->options.limit;
	if (ret && limit > 0) {
		RVecRBinString_reserve (ret, (size_t)limit);
	}

	bf->string_count = 0;
	if (has_sections) {
		R_VEC_FOREACH (&bo->sections_vec, section) {
			if (is_data_section (bf, section)) {
				ut64 offset = r_bin_file_get_buffer_offset (bf, section->paddr);
				ut64 buffer_size = r_buf_size (bf->buf);
				if (offset <= buffer_size && section->size <= buffer_size - offset) {
					get_strings_range (&options, offset, offset + section->size, section);
				}
			}
		}
	} else {
		get_strings_range (&options, 0, bf->size, NULL);
		ht_up_free (strings_index);
		return ret;
	}
	R_VEC_FOREACH (&bo->sections_vec, section) {
		if (!section->name) {
			continue;
		}
		/* load objc/swift strings */
		const int bits = (bo->info) ? bo->info->bits : 32;
		const int cfstr_size = (bits == 64) ? 32 : 16;
		const int cfstr_offs = (bits == 64) ? 16 :  8;
		if (strstr (section->name, "__cfstring")) {
			int i;
			// XXX do not walk if bin.strings == 0
			ut8 *p;
			ut64 offset = r_bin_file_get_buffer_offset (bf, section->paddr);
			ut64 buffer_size = r_buf_size (bf->buf);
			if (offset > buffer_size || section->size > buffer_size - offset) {
				continue;
			}
			if (section->size < 1) {
				continue;
			}
			if (ret) {
				ut64 cfstr_bound64 = (section->size / cfstr_size) + 1;
				if (cfstr_bound64 <= SZT_MAX) {
					size_t need;
					size_t cfstr_bound = (size_t)cfstr_bound64;
					if (!r_add_overflow (RVecRBinString_length (ret), cfstr_bound, &need)) {
						RVecRBinString_reserve (ret, need);
					}
				}
			}
			ut8 *sbuf = malloc (section->size);
			if (!sbuf) {
				continue;
			}
			r_buf_read_at (bf->buf, offset + cfstr_offs, sbuf, section->size);
			for (i = 0; i < section->size; i += cfstr_size) {
				ut8 *buf = sbuf;
				p = buf + i;
				if ((i + ((bits == 64)? 8: 4)) >= section->size) {
					break;
				}
				ut64 cfstr_vaddr = section->vaddr + i;
				ut64 cstr_vaddr = (bits == 64) ? r_read_le64 (p) : r_read_le32 (p);
				RBinString *s = r_bin_strings_index_get (ret, strings_index, cstr_vaddr);
				if (s) {
					RBinString src = *s;
					RBinString *bs = RVecRBinString_emplace_back (ret);
					if (!bs) {
						break;
					}
					bs->type = src.type;
					bs->length = src.length;
					bs->size = src.size;
					bs->ordinal = src.ordinal;
					bs->vaddr = cfstr_vaddr;
					bs->paddr = cfstr_vaddr; // XXX should be paddr instead
					bs->string = r_str_newf ("cstr.%s", src.string);
					r_bin_strings_index_insert (strings_index, bs->vaddr, RVecRBinString_length (ret) - 1);
				}
			}
			free (sbuf);
		}
	}
	ht_up_free (strings_index);
	return ret;
}

R_API ut64 r_bin_file_get_baddr(RBinFile *bf) {
	if (bf && bf->bo) {
		return bf->bo->baddr;
	}
	return UT64_MAX;
}

R_API bool r_bin_file_close(RBin *bin, int bd) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *bf = r_id_storage_take (bin->ids, bd);
	if (bf) {
		// file_free removes the fd already.. maybe its unnecessary
		r_id_storage_delete (bin->ids, bd);
		r_bin_file_free (bf);
		return true;
	}
	return false;
}

static RBinFileHash *compute_hash(RMutaBind *mb, const char *algo, const ut8 *buf, int len) {
	if (!mb || !mb->hash) {
		return NULL;
	}
	int outlen = 0;
	ut8 *digest = mb->hash (mb, algo, buf, len, &outlen);
	if (!digest || outlen < 1) {
		free (digest);
		return NULL;
	}
	char *hex = malloc ((outlen * 2) + 1);
	if (!hex) {
		free (digest);
		return NULL;
	}
	r_hex_bin2str (digest, outlen, hex);
	free (digest);
	RBinFileHash *fh = R_NEW0 (RBinFileHash);
	fh->type = strdup (algo);
	fh->hex = hex;
	return fh;
}

// TODO: do not compute md5 or sha1, those are weak and vulnerable hashes
R_API RList *r_bin_file_compute_hashes(RBin *bin, ut64 limit) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && bin->cur->bo, NULL);
	RBinFile *bf = bin->cur;
	RBinObject *o = bf->bo;

	RIODesc *iod = r_io_desc_get (bin->iob.io, bf->fd);
	if (!iod) {
		return NULL;
	}

	ut64 buf_len = r_io_desc_size (iod);
	if (buf_len > limit) {
		if (bin->options.verbose) {
			R_LOG_WARN ("file size exceeds bin.hashlimit");
		}
		return NULL;
	}
	ut8 *buf = malloc (buf_len);
	if (!buf) {
		return NULL;
	}
	r_io_desc_seek (iod, 0, R_IO_SEEK_SET);
	int bytes_read = r_io_desc_read (iod, buf, buf_len);
	if (bytes_read < 1) {
		R_LOG_ERROR ("cannot read from descriptor");
		free (buf);
		return NULL;
	}

	RList *file_hashes = r_list_newf ((RListFree) r_bin_file_hash_free);
	RBinFileHash *h;
	if ((h = compute_hash (&bin->mb, "md5", buf, bytes_read))) {
		r_list_push (file_hashes, h);
	}
	if ((h = compute_hash (&bin->mb, "sha1", buf, bytes_read))) {
		r_list_push (file_hashes, h);
	}
	if ((h = compute_hash (&bin->mb, "sha256", buf, bytes_read))) {
		r_list_push (file_hashes, h);
	}

	if (o->plugin && o->plugin->hashes) {
		RList *plugin_hashes = o->plugin->hashes (bf);
		r_list_join (file_hashes, plugin_hashes);
		free (plugin_hashes);
	}

	free (buf);
	return file_hashes;
}

// Set new hashes to current RBinInfo, caller should free the returned RList
R_API RList *r_bin_file_set_hashes(RBin *bin, RList/*<RBinFileHash*/ *new_hashes) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && bin->cur->bo && bin->cur->bo->info, NULL);
	RBinFile *bf = bin->cur;
	RBinInfo *info = bf->bo->info;

	RList *prev_hashes = info->file_hashes;
	info->file_hashes = new_hashes;

	return prev_hashes;
}

R_API RBinClass *r_bin_class_new(const char *name, const char *super, ut64 attr) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	RBinClass *c = R_NEW0 (RBinClass);
	if (c) {
		c->name = r_bin_name_new (name);
		if (R_STR_ISNOTEMPTY (super)) {
			c->super = r_list_newf (free);
			r_list_append (c->super, r_bin_name_new (super));
		}
		RVecRBinSymbol_init (&c->methods);
		RVecRBinField_init (&c->fields);
		c->attr.flags = attr;
		c->origin = R_BIN_CLASS_ORIGIN_BIN;
	}
	return c;
}

R_API const char *r_bin_class_origin_tostring(RBinClassOrigin origin) {
	static const char *originstr[] = {
		"bin",    // R_BIN_CLASS_ORIGIN_BIN
		"app",    // R_BIN_CLASS_ORIGIN_APP
		"rtti",   // R_BIN_CLASS_ORIGIN_RTTI
		"anal",   // R_BIN_CLASS_ORIGIN_ANAL
		"name",   // R_BIN_CLASS_ORIGIN_NAME
		"user",   // R_BIN_CLASS_ORIGIN_USER
		"script", // R_BIN_CLASS_ORIGIN_SCRIPT
		"other",  // R_BIN_CLASS_ORIGIN_OTHER
	};
	if (origin >= 0 && origin < R_BIN_CLASS_ORIGIN_LAST) {
		return originstr[origin];
	}
	return "other";
}

R_API void r_bin_class_fini(RBinClass *k) {
	if (k) {
		r_bin_name_free (k->name);
		r_list_free (k->super);
		free (k->visibility_str);
		free (k->attr.ns);
		RVecRBinSymbol_fini (&k->methods);
		RVecRBinField_fini (&k->fields);
	}
}

R_API void r_bin_class_free(RBinClass *k) {
	if (k) {
		r_bin_class_fini (k);
		free (k);
	}
}

R_API RBinClass *r_bin_file_add_class(RBinFile *bf, const char *name, const char *super, ut64 attr) {
	R_RETURN_VAL_IF_FAIL (name && bf && bf->bo, NULL);
	if (bf->rbin && !bf->rbin->options.load_unnamed && r_bin_name_is_unnamed (name)) {
		return NULL;
	}
	RBinClass *c = __getClass (bf, name);
	if (c) {
		if (R_STR_ISNOTEMPTY (super)) {
			r_list_free (c->super);
			c->super = r_list_newf (free);
			r_list_append (c->super, strdup (super));
		}
		return c;
	}
	c = r_bin_class_new (name, super, attr);
	if (c) {
		// XXX. no need for a list, the ht is iterable too
		c->index = r_list_length (bf->bo->classes);
		r_list_append (bf->bo->classes, c);
		ht_pp_insert (bf->bo->classes_ht, name, c);
	}
	return c;
}

R_IPI RBinSymbol *r_bin_class_add_method(RBinFile *bf, const char *classname, const char *name, int nargs) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && classname && name, NULL);
	if (bf->rbin && !bf->rbin->options.load_unnamed
			&& (r_bin_name_is_unnamed (classname) || r_bin_name_is_unnamed (name))) {
		return NULL;
	}
	RBinClass *c = r_bin_file_add_class (bf, classname, NULL, 0);
	if (!c) {
		return NULL;
	}
	if (bf->rbin && bf->rbin->options.classes_names_only) {
		return NULL;
	}
	RBinSymbol *sym = RVecRBinSymbol_emplace_back (&c->methods);
	sym->name = r_bin_name_new (name);
	sym->classname = strdup (classname);
	return sym;
}

R_API RBinSymbol *r_bin_file_add_method(RBinFile *bf, const char *rawname, const char *klass, const char *method, int nargs) {
	R_RETURN_VAL_IF_FAIL (bf && klass && method, NULL);
	RBinClass *c = r_bin_file_add_class (bf, klass, NULL, 0);
	if (!c) {
		R_LOG_ERROR ("Cannot allocate class %s", klass);
		return NULL;
	}
	RBinLanguage lang = R_BIN_LANG_CXX;
	if (strstr (method, "JNI") || strstr (klass, "JNI")) {
		lang = R_BIN_LANG_JNI;
	} else if (rawname && (rawname[0] == '-' || rawname[0] == '+') && rawname[1] == '[') {
		lang = R_BIN_LANG_OBJC;
	}
	c->attr.lang = lang;
	r_bin_file_add_language (bf, lang);
	RBinSymbol *sym = __getMethod (c, method);
	if (!sym) {
		sym = r_bin_class_add_method (bf, klass, method, nargs);
		if (!sym) {
			return NULL;
		}
		sym->name->name = strdup (method);
		sym->attr.lang = lang;
	}
	if (sym->name) {
		free (sym->name->oname);
		sym->name->oname = rawname? strdup (rawname): NULL;
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
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, paddr);
	RBinObject *bo = bf->bo;
	if (bo->info && bo->info->has_va) {
		const ut64 file_baddr = bo->baddr - (ut64)bo->baddr_shift;
		if (bo->baddr_shift && vaddr < file_baddr) {
			return paddr;
		}
		if (bo->baddr_shift) {
			ut64 addr = 0;
			return r_add_overflow (bo->baddr, vaddr - file_baddr, &addr) ? paddr : addr;
		}
		return vaddr;
	}
	return paddr;
}

R_API RVecRBinSymbol *r_bin_file_get_symbols_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	return bf->bo? &bf->bo->symbols_vec: NULL;
}

R_API RVecRBinImport *r_bin_file_get_imports_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	return bf->bo? &bf->bo->imports_vec: NULL;
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
	sdb_merge (dst->sdb_info, src->sdb_info);
	dst->addrline = src->addrline;
	memset (&src->addrline, 0, sizeof (src->addrline));
}
