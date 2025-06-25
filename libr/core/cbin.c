/* radare - LGPL - Copyright 2011-2025 - pancake */

#include "r_io.h"
#include "r_types.h"
#undef R_LOG_ORIGIN
#define R_LOG_ORIGIN "core.bin"
#include <r_core.h>

#define is_in_range(at, from, sz) ((at) >= (from) && (at) < ((from) + (sz)))

#define VA_FALSE 0
#define VA_TRUE 1
#define VA_NOREBASE 2

#define LOAD_BSS_MALLOC 0

#define IS_MODE_SET(mode) ((mode) & R_MODE_SET)
#define IS_MODE_SIMPLE(mode) ((mode) & R_MODE_SIMPLE)
#define IS_MODE_SIMPLEST(mode) ((mode) & R_MODE_SIMPLEST)
#define IS_MODE_JSON(mode) ((mode) & R_MODE_JSON)
#define IS_MODE_RAD(mode) ((mode) & R_MODE_RADARE)
#define IS_MODE_EQUAL(mode) ((mode) & R_MODE_EQUAL)
#define IS_MODE_NORMAL(mode) (!(mode))
#define IS_MODE_CLASSDUMP(mode) ((mode) & R_MODE_CLASSDUMP)

static R_TH_LOCAL int old_bits = -1;
static R_TH_LOCAL char *old_arch = NULL;

static void pair(RCore *core, const char *key, const char *val) {
	if (R_STR_ISNOTEMPTY (val)) {
		r_kons_printf (core->cons, "%-9s%s\n", key, val);
	}
}

static void pair_bool(RCore *core, PJ *pj, const char *key, bool val) {
	if (pj) {
		pj_kb (pj, key, val);
	} else {
		pair (core, key, r_str_bool (val));
	}
}

static char *csv_supers(RList *supers) {
	RBinName *bn;
	RListIter *iter;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (supers, iter, bn) {
		if (!r_strbuf_is_empty (sb)) {
			r_strbuf_append (sb, ", ");
		}
		r_strbuf_append (sb, r_bin_name_tostring (bn));
	}
	return r_strbuf_drain (sb);
}

static void pair_int(RCore *core, PJ *pj, const char *key, int val) {
	if (pj) {
		pj_ki (pj, key, val);
	} else {
		char decnum[64];
		snprintf (decnum, sizeof (decnum), "%d", val);
		pair (core, key, decnum);
	}
}

static void pair_ut64(RCore *core, PJ *pj, const char *key, ut64 val) {
	if (pj) {
		pj_kn (pj, key, val);
	} else {
		char decnum[64];
		snprintf (decnum, sizeof (decnum), "%"PFMT64d, val);
		pair (core, key, decnum);
	}
}

static void pair_ut64x(RCore *core, PJ *pj, const char *key, ut64 val) {
	if (pj) {
		pair_ut64 (core, pj, key, val);
	} else {
		r_strf_var (sval, 32, "0x%"PFMT64x, val);
		pair (core, key, sval);
	}
}

static void pair_str(RCore *core, PJ *pj, const char *key, const char *val) {
	if (pj) {
		pj_ks (pj, key, val? val: "");
	} else {
		pair (core, key, val);
	}
}

static ut64 rva(RBin *bin, ut64 paddr, ut64 vaddr, int va) {
	if (va == VA_TRUE) {
		if (paddr != UT64_MAX) {
			return r_bin_get_vaddr (bin, paddr, vaddr);
		}
	}
	if (va == VA_NOREBASE) {
		return vaddr;
	}
	return paddr;
}

R_API bool r_core_bin_set_by_fd(RCore *core, ut64 bin_fd) {
	if (r_bin_file_set_cur_by_fd (core->bin, bin_fd)) {
		r_core_bin_set_cur (core, r_bin_cur (core->bin));
		return true;
	}
	return false;
}

R_API void r_core_bin_export_info(RCore *core, int mode) {
	char *flagname = NULL, *offset = NULL;
	SdbList *ls = NULL;
	RBinFile *bf = r_bin_cur (core->bin);
	if (!bf) {
		return;
	}
	Sdb *db = sdb_ns (bf->sdb, "info", 0);
	if (!db) {
		return;
	}
	SdbListIter *iter;
	SdbKv *kv;
	if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "fs format\n");
	} else if (IS_MODE_SET (mode)) {
		r_flag_space_push (core->flags, "format");
	}
	if (!r_config_get_b (core->config, "bin.types")) {
		goto leave;
	}

	// iterate over all keys
	ls = sdb_foreach_list (db, false);
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key (kv);
		char *v = sdbkv_value (kv);
		char *dup = strdup (k);
		//printf ("?e (%s) (%s)\n", k, v);
		if ((flagname = strstr (dup, ".offset"))) {
			*flagname = 0;
			flagname = dup;
			if (IS_MODE_RAD (mode)) {
				r_kons_printf (core->cons, "f %s @ %s\n", flagname, v);
			} else if (IS_MODE_SET (mode)) {
				ut64 nv = r_num_math (core->num, v);
				r_flag_set (core->flags, flagname, nv, 0);
			}
			free (offset);
			offset = strdup (v);
		}
		if (strstr (dup, ".cparse")) {
			if (IS_MODE_RAD (mode)) {
				r_kons_printf (core->cons, "'td %s\n", v);
			} else if (IS_MODE_SET (mode)) {
				char *code = r_str_newf ("%s;", v);
				char *errmsg = NULL;
				char *out = r_anal_cparse (core->anal, code, &errmsg);
				free (code);
				if (errmsg) {
					R_LOG_ERROR ("%s", errmsg);
					free (errmsg);
				}
				if (out) {
					r_anal_save_parsed_type (core->anal, out);
					free (out);
				}
			}
		}
		free (dup);
	}
	R_FREE (offset);
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key (kv);
		char *v = sdbkv_value (kv);
		char *dup = strdup (k);
		if ((flagname = strstr (dup, ".format"))) {
			*flagname = 0;
			if (!offset) {
				offset = strdup ("0");
			}
			flagname = dup;
			if (IS_MODE_RAD (mode)) {
				r_kons_printf (core->cons, "pf.%s %s\n", flagname, v);
			} else if (IS_MODE_SET (mode)) {
				sdb_set (core->print->formats, flagname, v, 0);
			}
		}
		free (dup);
	}
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key (kv);
		char *v = sdbkv_value (kv);
		char *dup = strdup (k);
		if ((flagname = strstr (dup, ".format"))) {
			*flagname = 0;
			if (!offset) {
				offset = strdup ("0");
			}
			flagname = dup;
			int fmtsize = r_print_format_struct_size (core->print, v, 0, 0);
			char *offset_key = r_str_newf ("%s.offset", flagname);
			const char *off = sdb_const_get (db, offset_key, 0);
			if (fmtsize < 1) {
				continue;
			}
			fmtsize += 4; // increase buffer to fix a bug in compuatation for pf.elf_header size doesnt harms other cases but should be fixed
			free (offset_key);
			if (off) {
				if (IS_MODE_RAD (mode)) {
					r_kons_printf (core->cons, "Cf %d %s @ %s\n", fmtsize, v, off);
				} else if (IS_MODE_SET (mode)) {
					ut64 addr = r_num_get (NULL, off);
					ut8 *buf = malloc (fmtsize);
					if (buf) {
						r_io_read_at (core->io, addr, buf, fmtsize);
						int res = r_print_format (core->print, addr, buf,
								fmtsize, v, 0, NULL, NULL);
						free (buf);
						if (res < 0) {
							R_LOG_WARN ("Cannot register invalid format (%s)", v);
						}
					}
				}
			}
		}
		if ((flagname = strstr (dup, ".size"))) {
			*flagname = 0;
			flagname = dup;
			if (IS_MODE_RAD (mode)) {
				r_kons_printf (core->cons, "fl %s %s\n", flagname, v);
			} else if (IS_MODE_SET (mode)) {
				RFlagItem *fi = r_flag_get (core->flags, flagname);
				if (fi) {
					fi->size = r_num_math (core->num, v);
				} else {
					R_LOG_ERROR ("Cannot find flag named '%s'", flagname);
				}
			}
		}
		free (dup);
	}
leave:
	free (offset);
	ls_free (ls);
	if (IS_MODE_SET (mode)) {
		r_flag_space_pop (core->flags);
	}
}

R_API bool r_core_bin_load_structs(RCore *core, const char *file) {
	R_RETURN_VAL_IF_FAIL (core && core->io, false);
	if (!file) {
		int fd = r_io_fd_get_current (core->io);
		RIODesc *desc = r_io_desc_get (core->io, fd);
		if (desc) {
			file = desc->name;
		}
		if (!file) {
			return false;
		}
	}
	if (strchr (file, '\'') || strchr (file, '\"')) { // TODO: escape "?
		R_LOG_ERROR ("Invalid char found in filename");
		return false;
	}
	RBinFileOptions opt = {0};
	r_bin_open (core->bin, file, &opt);
	RBinFile *bf = r_bin_cur (core->bin);
	if (bf) {
		r_core_bin_export_info (core, R_MODE_SET);
		r_bin_file_delete (core->bin, bf->id);
		return true;
	}
	R_LOG_ERROR ("Cannot open bin '%s'", file);
	return false;
}

R_API bool r_core_bin_set_by_name(RCore *core, const char *name) {
	if (r_bin_file_set_cur_by_name (core->bin, name)) {
		r_core_bin_set_cur (core, r_bin_cur (core->bin));
		return true;
	}
	return false;
}

R_API bool r_core_bin_set_env(RCore *core, RBinFile *binfile) {
	R_RETURN_VAL_IF_FAIL (core, false);

	RBinObject *binobj = binfile? binfile->bo: NULL;
	RBinInfo *info = binobj? binobj->info: NULL;
	if (info) {
		int va = info->has_va;
		const char *arch = info->arch;
		ut16 bits = info->bits;
		ut64 baseaddr = r_bin_get_baddr (core->bin);
		if (baseaddr == UT64_MAX) {
			baseaddr = 0;
		}
		RConfig *config = core->config;
		r_config_set_i (core->config, "bin.baddr", baseaddr);
		sdb_num_add (core->sdb, "orig_baddr", baseaddr, 0);
		core->dbg->bp->baddr = baseaddr;
		r_config_set_i (core->config, "asm.bits", bits);
		if (arch) {
			r_config_set (config, "asm.arch", arch);
			if (!strcmp (arch, "arm")) {
				r_config_set_b (config, "anal.nopskip", false);
			}
			r_config_set (config, "anal.arch", arch);
			const char *cpu = R_STR_ISNOTEMPTY (info->cpu)? info->cpu: arch;
			r_config_set (config, "asm.cpu", cpu);
			r_asm_use (core->rasm, arch);
		}
		r_core_bin_info (core, R_CORE_BIN_ACC_ALL, NULL, R_MODE_SET, va, NULL, NULL);
		r_core_bin_set_cur (core, binfile);
		return true;
	}
	return false;
}

R_API bool r_core_bin_set_cur(RCore *core, RBinFile *binfile) {
	R_RETURN_VAL_IF_FAIL (core && binfile, false);
	ut32 fd = UT32_MAX;
	if (!core->bin) {
		return false;
	}
	if (!binfile) {
		if (core && core->io->desc) {
			fd = core->io->desc->fd;
		}
	}
	// Find first available binfile
	if (fd == UT32_MAX) {
		return false;
	}
	binfile = r_bin_file_find_by_fd (core->bin, fd);
	if (!binfile) {
		return false;
	}
	r_bin_file_set_cur_binfile (core->bin, binfile);
	return true;
}

static void _print_strings(RCore *core, RList *list, PJ *pj, int mode, int va) {
	RTable *table = r_core_table_new (core, "strings");
	if (!table) {
		return;
	}
	R_CRITICAL_ENTER (core);
	bool b64str = r_config_get_i (core->config, "bin.str.debase64");
	int minstr = r_config_get_i (core->config, "bin.str.min");
	int maxstr = r_config_get_i (core->config, "bin.str.max");
	RBin *bin = core->bin;
	RBinObject *obj = r_bin_cur_object (bin);
	RListIter *iter;
	RBinString *string;
	RBinSection *section;

	bin->options.minstrlen = minstr;
	bin->options.maxstrlen = maxstr;
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "fs strings");
	} else if (IS_MODE_SET (mode) && r_config_get_i (core->config, "bin.strings")) {
		r_flag_space_set (core->flags, R_FLAGS_FS_STRINGS);
		r_cons_break_push (core->cons, NULL, NULL);
	} else if (IS_MODE_NORMAL (mode)) {
		r_table_set_columnsf (table, "nXXnnsss", "nth", "paddr", "vaddr", "len", "size", "section", "type", "string");
	}
	RBinString b64 = {0};
	r_list_foreach (list, iter, string) {
		const char *section_name, *type_string;
		ut64 paddr = string->paddr;
		ut64 vaddr = rva (core->bin, paddr, string->vaddr, va);
		if (!r_bin_string_filter (bin, string->string, vaddr)) {
			continue;
		}
		if (string->length < minstr) {
			continue;
		}
		if (maxstr && string->length > maxstr) {
			continue;
		}
#if FALSE_POSITIVES
		{
			int *block_list = r_utf_block_list ((const ut8*)string->string, -1, NULL);
			if (block_list) {
				if (block_list[0] == 0 && block_list[1] == -1) {
					/* Don't show block list if
					   just Basic Latin (0x00 - 0x7F) */
					// nothing
				} else {
					continue;
				}
			}
		}
#endif
		section = obj? r_bin_get_section_at (obj, paddr, 0): NULL;
		section_name = section ? section->name : "";
		type_string = r_bin_string_type (string->type);
		if (b64str) {
			ut8 *s = r_base64_decode_dyn (string->string, -1, NULL);
			if (R_STR_ISNOTEMPTY (s) && IS_PRINTABLE (*s)) {
				// TODO: add more checks
				free (b64.string);
				memcpy (&b64, string, sizeof (b64));
				b64.string = (char *)s;
				b64.size = strlen (b64.string);
				string = &b64;
			}
		}
		if (IS_MODE_SET (mode)) {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			r_meta_set (core->anal, R_META_TYPE_STRING, vaddr, string->size, string->string);
			char *str = (core->bin->prefix)
				? r_str_newf ("%s.str.%s", core->bin->prefix, string->string)
				: r_str_newf ("str.%s", string->string);
			r_name_filter (str, -1);
			RFlagItem *fi = r_flag_set (core->flags, str, vaddr, string->size);
			const bool realstr = r_config_get_i (core->config, "bin.str.real");
			if (fi && realstr) {
				char *es = r_str_escape (string->string);
				char *s = r_str_newf ("\"%s\"", es);
				r_flag_item_set_realname (core->flags, fi, s);
				free (s);
				free (es);
			}
			free (str);
		} else if (IS_MODE_SIMPLE (mode)) {
			r_kons_printf (core->cons, "0x%"PFMT64x" %d %d %s\n", vaddr,
				string->size, string->length, string->string);
		} else if (IS_MODE_SIMPLEST (mode)) {
			r_cons_println (core->cons, string->string);
		} else if (IS_MODE_JSON (mode)) {
			int *block_list;
			pj_o (pj);
			pj_kn (pj, "vaddr", vaddr);
			pj_kn (pj, "paddr", paddr);
			pj_kn (pj, "ordinal", string->ordinal);
			pj_kn (pj, "size", string->size);
			pj_kn (pj, "length", string->length);
			pj_ks (pj, "section", section_name);
			pj_ks (pj, "type", type_string);
			// data itself may be encoded so use pj_ks
			pj_ks (pj, "string", string->string);

			switch (string->type) {
			case R_STRING_TYPE_UTF8:
			case R_STRING_TYPE_WIDE:
			case R_STRING_TYPE_WIDE32:
				block_list = r_utf_block_list ((const ut8*)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't include block list if
						   just Basic Latin (0x00 - 0x7F) */
					} else {
						int *block_ptr = block_list;
						pj_k (pj, "blocks");
						pj_a (pj);
						for (; *block_ptr != -1; block_ptr++) {
							const char *utfName = r_utf_block_name (*block_ptr);
							pj_s (pj, r_str_get (utfName));
						}
						pj_end (pj);
					}
					R_FREE (block_list);
				}
				break;
			}
			pj_end (pj);
		} else if (IS_MODE_RAD (mode)) {
			char *str = (core->bin->prefix)
				? r_str_newf ("%s.str.%s", core->bin->prefix, string->string)
				: r_str_newf ("str.%s", string->string);
			r_name_filter (str, R_FLAG_NAME_SIZE);
			r_kons_printf (core->cons, "f %s %u 0x%08"PFMT64x"\n"
				"Cs %u @ 0x%08"PFMT64x"\n",
				str, string->size, vaddr,
				string->size, vaddr);
			free (str);
		} else {
			int *block_list;
			char *str = string->string;
			char *no_dbl_bslash_str = NULL;
			if (!core->print->esc_bslash) {
				char *ptr;
				for (ptr = str; *ptr; ptr++) {
					if (*ptr != '\\') {
						continue;
					}
					if (*(ptr + 1) == '\\') {
						if (!no_dbl_bslash_str) {
							no_dbl_bslash_str = strdup (str);
							if (!no_dbl_bslash_str) {
								break;
							}
							ptr = no_dbl_bslash_str + (ptr - str);
						}
						memmove (ptr + 1, ptr + 2, strlen (ptr + 2) + 1);
					}
				}
				if (no_dbl_bslash_str) {
					str = no_dbl_bslash_str;
				}
			}

			char *blocks = NULL;
			RStrBuf *buf = r_strbuf_new (str);
			switch (string->type) {
			case R_STRING_TYPE_UTF8:
			case R_STRING_TYPE_WIDE:
			case R_STRING_TYPE_WIDE32:
				block_list = r_utf_block_list ((const ut8*)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't show block list if
						   just Basic Latin (0x00 - 0x7F) */
						break;
					}
					int *block_ptr = block_list;
					RStrBuf *sb = r_strbuf_new ("");
					// a bit noisy and useless for listing here imho
					for (; *block_ptr != -1; block_ptr++) {
						if (block_ptr != block_list) {
							r_strbuf_append (sb, ",");
						}
						const char *name = r_utf_block_name (*block_ptr);
						if (name) {
							r_strbuf_append (sb, name);
						}
					}
					free (block_list);
					blocks = r_strbuf_drain (sb);
				}
				break;
			}
			char *bufstr = r_strbuf_drain (buf);
			r_table_add_rowf (table, "nXXddsss", (ut64)string->ordinal, paddr, vaddr,
				(int)string->length, (int)string->size, section_name,
				type_string, bufstr);
			free (blocks);
			free (bufstr);
			free (no_dbl_bslash_str);
		}
	}
	R_FREE (b64.string);
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	} else if (IS_MODE_SET (mode)) {
		r_cons_break_pop (core->cons);
	} else if (IS_MODE_NORMAL (mode)) {
		bool show_table = true;
		if (core->table_query) {
			show_table = r_table_query (table, core->table_query);
		}
		if (show_table) {
			char *s = r_table_tostring (table);
			if (s) {
				r_kons_print (core->cons, s);
				free (s);
			}
		}
	}
	r_table_free (table);
	R_CRITICAL_LEAVE (core);
}

static bool bin_raw_strings(RCore *core, PJ *pj, int mode, int va) {
	RBinFile *bf = r_bin_cur (core->bin);
	bool new_bf = false;
	if (bf && strstr (bf->file, "malloc://")) {
		//sync bf->buf to search string on it
		ut8 *tmp = R_NEWS (ut8, bf->size);
		if (!tmp) {
			return false;
		}
		r_io_read_at (core->io, 0, tmp, bf->size);
		r_buf_write_at (bf->buf, 0, tmp, bf->size);
	}
	if (!core->io->desc) {
		R_LOG_ERROR ("Core doesnt have any file");
		if (IS_MODE_JSON (mode)) {
			pj_a (pj);
			pj_end (pj);
			return true;
		}
		return false;
	}
	if (!bf) {
		bf = R_NEW0 (RBinFile);
		RIODesc *desc = core->io->desc;
		if (!desc) {
			free (bf);
			return false;
		}
		bf->file = strdup (desc->name);
		bf->size = r_io_desc_size (desc);
		if (bf->size == UT64_MAX) {
			free (bf);
			return false;
		}
		bf->buf = r_buf_new_with_io (&core->bin->iob, core->io->desc->fd);
		bf->bo = NULL;
		bf->rbin = core->bin;
		new_bf = true;
		va = false;
	}
	RList *l = r_bin_raw_strings (bf, 0);
	_print_strings (core, l, pj, mode, va);
	r_list_free (l);
	if (new_bf) {
		r_buf_free (bf->buf);
		bf->buf = NULL;
		bf->id = -1;
		r_bin_file_free (bf);
	}
	return true;
}

static bool bin_strings(RCore *core, PJ *pj, int mode, int va) {
	RBinFile *binfile = r_bin_cur (core->bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	int rawstr = r_config_get_i (core->config, "bin.str.raw");
	if (!binfile || !plugin) {
		return false;
	}
	if (!r_config_get_i (core->config, "bin.strings")) {
		return false;
	}
	if (plugin->info && plugin->meta.name) {
		if (!strcmp (plugin->meta.name, "any") && !rawstr) {
			if (IS_MODE_JSON (mode)) {
				pj_a (pj);
				pj_end (pj);
				return true;
			}
			return false;
		}
	}
	RList *list = r_bin_get_strings (core->bin);
	if (list) {
		_print_strings (core, list, pj, mode, va);
		return true;
	}
	return false;
}

static const char* get_compile_time(Sdb *binFileSdb) {
	Sdb *info_ns = sdb_ns (binFileSdb, "info", false);
	const char *timeDateStamp_string = sdb_const_get (info_ns,
		"image_file_header.TimeDateStamp_string", 0);
	return timeDateStamp_string;
}

static bool is_executable(RBinObject *bo) {
	RListIter *it;
	RBinSection* sec;
	R_RETURN_VAL_IF_FAIL (bo, false);
	if (bo->info && bo->info->arch) {
		return true;
	}
	r_list_foreach (bo->sections, it, sec) {
		if (sec->perm & R_PERM_X) {
			return true;
		}
	}
	return false;
}

static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new (0, path, 0);
	sdb_merge (s, db);
	sdb_close (db);
	sdb_free (db);
}

static void load_types_from(RCore *core, const char *fmt, ...) {
	const char *dir_prefix = r_config_get (core->config, "dir.prefix");
	va_list ap;
	va_start (ap, fmt);
	char *s = r_str_newvf (fmt, ap);
	SdbGperf *gp = r_anal_get_gperf_types (s);
	if (gp) {
#if HAVE_GPERF
		Sdb *gd = sdb_new0 ();
		sdb_open_gperf (gd, gp);
		sdb_reset (core->anal->sdb_types);
		sdb_merge (core->anal->sdb_types, gd);
		sdb_close (gd);
		sdb_free (gd);
#endif
	} else {
		char *dbpath = r_str_newf ("%s/%s/%s.sdb", dir_prefix, R2_SDB_FCNSIGN, s);
		if (r_file_exists (dbpath)) {
			sdb_concat_by_path (core->anal->sdb_types, dbpath);
		}
		free (dbpath);
	}
	free (s);
	va_end (ap);
}

R_API void r_core_anal_type_init(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal);
	int bits = core->rasm->config->bits;
	Sdb *types = core->anal->sdb_types;
	// make sure they are empty this is initializing
	sdb_reset (types);
	const char *anal_arch = r_config_get (core->config, "anal.arch");
	const char *os = r_config_get (core->config, "asm.os");

	load_types_from (core, "types");
	load_types_from (core, "types-%s", anal_arch);
	load_types_from (core, "types-%s", os);
	if (!strcmp (os, "ios") || !strcmp (os, "macos")) {
		load_types_from (core, "types-darwin");
	}
	load_types_from (core, "types-%d", bits);
	load_types_from (core, "types-%s-%d", os, bits);
	load_types_from (core, "types-%s-%d", anal_arch, bits);
	load_types_from (core, "types-%s-%s", anal_arch, os);
	load_types_from (core, "types-%s-%s-%d", anal_arch, os, bits);
}

R_API void r_core_anal_cc_init(RCore *core) {
	R_RETURN_IF_FAIL (core);
	char *anal_arch = strdup (r_config_get (core->config, "anal.arch"));
	if (anal_arch && !strcmp (anal_arch, "r2ghidra")) {
		free (anal_arch);
		anal_arch = strdup (r_config_get (core->config, "asm.cpu"));
	}
	if (!anal_arch) {
		return;
	}
	const int bits = core->anal->config->bits;
	r_str_after (anal_arch, '.');
	if (old_bits != -1) {
		if (old_bits == bits) {
			if (!strcmp (old_arch, anal_arch)) {
				free (anal_arch);
				return;
			}
		}
	}
	old_bits = bits;
	free (old_arch);
	old_arch = strdup (anal_arch);
#if HAVE_GPERF
	char *k = r_str_newf ("cc_%s_%d", anal_arch, bits);
	SdbGperf *gp = r_anal_get_gperf_cc (k);
	free (k);
	r_anal_cc_reset (core->anal);
	if (gp) {
		Sdb *gd = sdb_new0 ();
		sdb_open_gperf (gd, gp);
		sdb_merge (core->anal->sdb_cc, gd);
		sdb_close (gd);
		sdb_free (gd);
	}
	{
		// same as "tcc `arcc`"
		char *s = r_reg_profile_to_cc (core->anal->reg);
		if (s) {
			if (!r_anal_cc_set (core->anal, s)) {
				R_LOG_WARN ("Invalid CC from reg profile");
			}
			free (s);
		} else {
			R_LOG_WARN ("Cannot derive CC from reg profile");
		}
	}
#else
	const char *dir_prefix = r_config_get (core->config, "dir.prefix");
	char *dbpath = r_str_newf (R_JOIN_3_PATHS ("%s", R2_SDB_FCNSIGN, "cc-%s-%d.sdb"),
		dir_prefix, anal_arch, bits);
	char *fcnsigndir = r_xdg_datadir ("fcnsign");
	char *dbhomepath = r_str_newf ("%s/cc-%s-%d.sdb", fcnsigndir, anal_arch, bits);
	free (fcnsigndir);
	Sdb *cc = core->anal->sdb_cc;
	// Avoid sdb reloading
	if (cc->path && (!strcmp (cc->path, dbpath) || !strcmp (cc->path, dbhomepath))) {
		free (anal_arch);
		free (dbpath);
		free (dbhomepath);
		return;
	}
	sdb_reset (cc);
	{
		// same as "tcc `arcc`"
		char *s = r_reg_profile_to_cc (core->anal->reg);
		if (s) {
			if (!r_anal_cc_set (core->anal, s)) {
				R_LOG_WARN ("Invalid CC from reg profile");
			}
			free (s);
		} else {
			R_LOG_WARN ("Cannot derive CC from reg profile");
		}
	}
	R_FREE (cc->path);
	if (r_file_exists (dbhomepath)) {
		sdb_concat_by_path (cc, dbhomepath);
		cc->path = strdup (dbhomepath);
	}
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (cc, dbpath);
		cc->path = strdup (dbpath);
	}
	if (anal_arch && sdb_isempty (core->anal->sdb_cc)) {
		R_LOG_WARN ("Missing calling conventions for '%s' %d. Deriving it from the regprofile", anal_arch, bits);
	}
	free (dbpath);
	free (dbhomepath);
#endif
	free (anal_arch);
}

static bool bin_info(RCore *core, PJ *pj, int mode, ut64 laddr) {
	int i, j, v;
	char str[R_FLAG_NAME_SIZE];
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinFile *bf = r_bin_cur (core->bin);
	if (!bf) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}
	RBinObject *obj = bf->bo;

	if (!info || !obj) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
			return true;
		}
		return false;
	}
	bool havecode = is_executable (obj) | (!!obj->entries);
	const char *compiled = get_compile_time (bf->sdb);

	if (IS_MODE_SET (mode)) {
		r_config_set (core->config, "file.type", info->rclass);
		r_config_set (core->config, "cfg.bigendian",
			      info->big_endian ? "true" : "false");
		if (!info->rclass || strcmp (info->rclass, "fs")) {
			if (info->lang && info->lang[0] != '?') {
				r_config_set (core->config, "bin.lang", info->lang);
			}
			r_config_set (core->config, "asm.os", info->os);
			if (info->rclass && !strcmp (info->rclass, "pe")) {
				r_config_set (core->config, "anal.cxxabi", "msvc");
			} else {
				r_config_set (core->config, "anal.cxxabi", "itanium");
			}
			if (R_STR_ISNOTEMPTY (info->abi)) {
				r_config_set (core->config, "asm.abi", info->abi);
			}
			// we can take the eabi from bin.features from arm (f.ex eabi4 eabi5)
			if (info->arch) {
				r_config_set (core->config, "asm.arch", info->arch);
				r_config_set (core->config, "anal.arch", info->arch);
				snprintf (str, R_FLAG_NAME_SIZE, "%i", info->bits);
				r_config_set (core->config, "asm.bits", str);
			}
			// r_config_set (core->config, "arch.decoder", info->arch);
			if (R_STR_ISNOTEMPTY (info->charset)) {
				r_config_set (core->config, "cfg.charset", info->charset);
			}
			r_config_set (core->config, "asm.dwarf",
				(R_BIN_DBG_STRIPPED & info->dbg_info) ? "false" : "true");
			if (R_STR_ISNOTEMPTY (info->cpu)) {
				r_config_set (core->config, "asm.cpu", info->cpu);
			}
		}
		r_core_anal_type_init (core);
		r_core_anal_cc_init (core);
		if (info->default_cc && r_anal_cc_exist (core->anal, info->default_cc)) {
			r_core_cmdf (core, "e anal.cc=%s", info->default_cc);
		}
	} else if (IS_MODE_SIMPLE (mode)) {
		r_kons_printf (core->cons, "arch %s\n", info->arch);
		if (R_STR_ISNOTEMPTY (info->cpu)) {
			r_kons_printf (core->cons, "cpu %s\n", info->cpu);
		}
		if (R_STR_ISNOTEMPTY (info->charset)) {
			r_kons_printf (core->cons, "charset %s\n", info->charset);
		}
		r_kons_printf (core->cons, "bits %d\n", info->bits);
		r_kons_printf (core->cons, "os %s\n", info->os);
		r_kons_printf (core->cons, "endian %s\n", info->big_endian? "big": "little");
	} else if (IS_MODE_RAD (mode)) {
		if (info->type && !strcmp (info->type, "fs")) {
			r_kons_printf (core->cons, "e file.type=fs\n");
			r_kons_printf (core->cons, "m /root %s 0\n", info->arch);
		} else {
			r_kons_printf (core->cons, "e cfg.bigendian=%s\n"
				"e asm.bits=%i\n"
				"e asm.dwarf=%s\n",
				r_str_bool (info->big_endian),
				info->bits,
				r_str_bool (R_BIN_DBG_STRIPPED &info->dbg_info));
			int v = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
			r_kons_printf (core->cons, "e asm.codealign=%d\n", (v > 0)? v: 0);
			if (R_STR_ISNOTEMPTY (info->lang) && info->lang[0] != '?') {
				r_kons_printf (core->cons, "e bin.lang=%s\n", info->lang);
			}
			if (R_STR_ISNOTEMPTY (info->charset)) {
				r_kons_printf (core->cons, "e cfg.charset=%s\n", info->charset);
			}
			if (R_STR_ISNOTEMPTY (info->rclass)) {
				r_kons_printf (core->cons, "e file.type=%s\n", info->rclass);
			}
			if (info->os) {
				r_kons_printf (core->cons, "e asm.os=%s\n", info->os);
			}
			if (info->arch) {
				r_kons_printf (core->cons, "e asm.arch=%s\n", info->arch);
			}
			if (R_STR_ISNOTEMPTY (info->cpu)) {
				r_kons_printf (core->cons, "e asm.cpu=%s\n", info->cpu);
			}
			if (R_STR_ISNOTEMPTY (info->abi)) {
				r_kons_printf (core->cons, "e asm.abi=%s\n", info->abi);
			}
			if (R_STR_ISNOTEMPTY (info->default_cc)) {
				r_kons_printf (core->cons, "e anal.cc=%s", info->default_cc);
			}
		}
	} else {
		// XXX: if type is 'fs' show something different?
		char *tmp_buf;
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
		}
		pair_str (core, pj, "arch", info->arch);
		if (R_STR_ISNOTEMPTY (info->cpu)) {
			pair_str (core, pj, "cpu", info->cpu);
		}
		ut64 baddr = r_bin_get_baddr (core->bin);
		if (baddr != UT64_MAX) {
			pair_ut64x (core, pj, "baddr", baddr);
		}
		pair_ut64 (core, pj, "binsz", r_bin_get_size (core->bin));
		pair_str (core, pj, "bintype", info->rclass);
		if (R_STR_ISNOTEMPTY (info->charset)) {
			pair_str (core, pj, "charset", info->charset);
		}
		pair_int (core, pj, "bits", info->bits);
		pair_bool (core, pj, "canary", info->has_canary);
		if (info->has_nobtcfi) {
			pair_bool (core, pj, "nobtcfi", info->has_nobtcfi);
		}
		if (info->dbglink) {
			pair_str (core, pj, "dbglink", info->dbglink);
		}
		pair_bool (core, pj, "injprot", info->has_libinjprot);
		if (info->has_retguard != -1) {
			pair_bool (core, pj, "retguard", info->has_retguard);
		}
		pair_str (core, pj, "class", info->bclass);
		if (info->actual_checksum) {
			/* computed checksum */
			pair_str (core, pj, "cmp.csum", info->actual_checksum);
		}
		pair_str (core, pj, "compiled", compiled);
		pair_str (core, pj, "compiler", info->compiler);
		if (R_STR_ISNOTEMPTY (info->flags)) {
			pair_str (core, pj, "flags", info->flags);
		}
		if (R_STR_ISNOTEMPTY (info->abi)) {
			pair_str (core, pj, "abi", info->abi);
		}
		pair_bool (core, pj, "crypto", info->has_crypto);
		pair_str (core, pj, "dbg_file", info->debug_file_name);
		pair_str (core, pj, "endian", info->big_endian ? "big" : "little");
		if (info->rclass && !strcmp (info->rclass, "mdmp")) {
			tmp_buf = sdb_get (bf->sdb, "mdmp.flags", 0);
			if (tmp_buf) {
				pair_str (core, pj, "flags", tmp_buf);
				free (tmp_buf);
			}
		}
		pair_bool (core, pj, "havecode", havecode);
		if (havecode) {
			if (info->claimed_checksum) {
				/* checksum specified in header */
				pair_str (core, pj, "hdr.csum", info->claimed_checksum);
			}
			pair_str (core, pj, "guid", info->guid);
			pair_str (core, pj, "intrp", info->intrp);
			pair_ut64x (core, pj, "laddr", laddr);
			if (info->lang && *info->lang != '?') {
				pair_str (core, pj, "lang", info->lang);
			}
			pair_bool (core, pj, "linenum", R_BIN_DBG_LINENUMS & info->dbg_info);
			pair_bool (core, pj, "lsyms", R_BIN_DBG_SYMS & info->dbg_info);
			pair_str (core, pj, "machine", info->machine);
			pair_bool (core, pj, "nx", info->has_nx);
			pair_str (core, pj, "os", info->os);
			if (info->rclass && !strcmp (info->rclass, "pe")) {
				pair_bool (core, pj, "overlay", info->pe_overlay);
			}
			pair_str (core, pj, "cc", info->default_cc);
			pair_bool (core, pj, "pic", info->has_pi);
			pair_bool (core, pj, "relocs", R_BIN_DBG_RELOCS & info->dbg_info);
			Sdb *sdb_info = sdb_ns (obj->kv, "info", false);
			if (sdb_info) {
				tmp_buf = sdb_get (sdb_info, "elf.relro", 0);
				if (R_STR_ISNOTEMPTY (tmp_buf)) {
					pair_str (core, pj, "relro", tmp_buf);
				}
				free (tmp_buf);
			}
			pair_str (core, pj, "rpath", info->rpath);
			if (info->rclass && !strcmp (info->rclass, "pe")) {
				//this should be moved if added to mach0 (or others)
				pair_bool (core, pj, "signed", info->signature);
			}
			pair_bool (core, pj, "sanitize", info->has_sanitizers);
			pair_bool (core, pj, "static", r_bin_is_static (core->bin));
			if (info->rclass && !strcmp (info->rclass, "mdmp")) {
				v = sdb_num_get (bf->sdb, "mdmp.streams", 0);
				if (v != -1) {
					pair_int (core, pj, "streams", v);
				}
			}
			pair_bool (core, pj, "stripped", R_BIN_DBG_STRIPPED & info->dbg_info);
			pair_str (core, pj, "subsys", info->subsystem);
			pair_bool (core, pj, "va", info->has_va);
		}
		if (IS_MODE_JSON (mode)) {
			pj_ko (pj, "checksums");
		}
		for (i = 0; info->sum[i].type; i++) {
			RBinHash *h = &info->sum[i];
			ut64 hash = r_hash_name_to_bits (h->type);
			RHash *rh = r_hash_new (true, hash);
			ut8 *tmp = R_NEWS (ut8, h->to);
			if (!tmp) {
				return false;
			}
			r_buf_read_at (bf->buf, h->from, tmp, h->to);
			int len = r_hash_calculate (rh, hash, tmp, h->to);
			free (tmp);
			if (len < 1) {
				R_LOG_ERROR ("Invalid checksum length");
			}
			r_hash_free (rh);
			if (IS_MODE_JSON (mode)) {
				pj_ko (pj, h->type);
				char *buf = malloc (2 * h->len + 1);
				if (!buf) {
					return false;
				}
				for (j = 0; j < h->len; j++) {
					snprintf (buf + 2 * j, 3, "%02x", h->buf[j]);
				}
				pj_ks (pj, "hex", buf);
				free (buf);
				pj_end (pj);
			} else {
				r_kons_printf (core->cons, "%s  %" PFMT64u "-%" PFMT64u "c  ", h->type, h->from, h->to+h->from);
				for (j = 0; j < h->len; j++) {
					r_kons_printf (core->cons, "%02x", h->buf[j]);
				}
				r_cons_newline (core->cons);
			}
		}
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
			pj_end (pj);
		}
	}
	const char *dir_prefix = r_config_get (core->config, "dir.prefix");
	char *spath = r_str_newf ("%s/"R2_SDB_FCNSIGN"/spec.sdb", dir_prefix);
	if (r_file_exists (spath)) {
		sdb_concat_by_path (core->anal->sdb_fmts, spath);
	}
	free (spath);
	return true;
}

typedef struct {
	size_t *line_starts;
	char *content;
	size_t line_count;
} FileLines;

static void file_lines_free(FileLines *file) {
	if (!file) {
		return;
	}
	free (file->line_starts);
	free (file->content);
	free (file);
}

FileLines *read_file_lines(const char *path) {
	FileLines *result = R_NEW0 (FileLines);
	result->content = r_file_slurp (path, NULL);
	if (result->content) {
		result->line_starts = r_str_split_lines (result->content, &result->line_count);
	}
	if (!result->content || !result->line_starts) {
		R_FREE (result);
	}
	return result;
}

static void file_lines_free_kv(HtPPKv *kv) {
	free (kv->key);
	file_lines_free (kv->value);
}

static bool bin_addrline(RCore *core, PJ *pj, int mode) {
	RBinAddrline *row;
	RListIter *iter;
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	}
	if (!r_config_get_b (core->config, "bin.dbginfo")) {
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
		}
		return false;
	}
	RBinFile *binfile = r_bin_cur (core->bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (!binfile) {
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
		}
		return false;
	}
	RList *list = NULL;
	RList *ownlist = NULL;
	if (plugin && plugin->lines) {
		// list is not cloned to improve speed. avoid use after free
		list = plugin->lines (binfile);
	} else if (core->bin) {
		// TODO: complete and speed-up support for dwarf
		RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (core->bin, mode);
		if (!da) {
			if (IS_MODE_JSON (mode)) {
				pj_end (pj);
			}
			return false;
		}
		RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (core->bin, da, mode);
		HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (core->bin, core->anal->config->bits / 8);
		// I suppose there is no reason the parse it for a printing purposes
		if (info && mode != R_MODE_PRINT) {
			/* Should we do this by default? */
			RAnalDwarfContext ctx = {
				.info = info,
				.loc = loc_table
			};
			r_anal_dwarf_process_info (core->anal, &ctx);
		}
		if (loc_table) {
			if (mode == R_MODE_PRINT) {
				r_bin_dwarf_print_loc (loc_table, core->anal->config->bits / 8, r_cons_printf);
			}
			r_bin_dwarf_free_loc (loc_table);
		}
		r_bin_dwarf_free_debug_info (info);
		r_bin_dwarf_parse_aranges (core->bin, mode);
		list = ownlist = r_bin_dwarf_parse_line (core->bin, mode);
		r_bin_dwarf_free_debug_abbrev (da);
	}
	if (!list) {
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
		}
		return false;
	}

	r_cons_break_push (core->cons, NULL, NULL);
	/* cache file:line contents */
	HtPP* file_lines = ht_pp_new (NULL, file_lines_free_kv, NULL);

	SetP *set = set_p_new ();
	// XXX this leaks like there's no stopper
	r_list_foreach (list, iter, row) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (mode) {
			// TODO: use 'Cl' instead of CC
			const char *path = row->file;
			FileLines *current_lines = ht_pp_find (file_lines, path, NULL);
			if (!current_lines) {
				if (!set_p_contains (set, (void*)path)) {
					set_p_add (set, (void*)path);
					current_lines = read_file_lines (path);
					if (!ht_pp_insert (file_lines, path, current_lines)) {
						file_lines_free (current_lines);
						current_lines = NULL;
					}
				}
			}
			char *line = NULL;

			if (current_lines) {
				int nl = row->line - 1;
				if (nl >= 0 && nl < current_lines->line_count) {
					line = strdup (current_lines->content + current_lines->line_starts[nl]);
				}
			}
			if (line) {
				r_str_filter (line, strlen (line));
				line = r_str_replace (line, "\"", "\\\"", 1);
				line = r_str_replace (line, "\\\\", "\\", 1);
			}
			bool chopPath = !r_config_get_i (core->config, "dir.dwarf.abspath");
			char *file = strdup (row->file);
			if (chopPath) {
				const char *slash = r_str_lchr (file, '/');
				if (slash) {
					memmove (file, slash + 1, strlen (slash));
				}
			}
			// TODO: implement internal : if ((mode & R_MODE_SET))
			if ((mode & R_MODE_SIMPLE)) {
				r_kons_printf (core->cons, "0x%08"PFMT64x" %s:%d\n",
					row->addr, file, (int)row->line);
			} else if ((mode & R_MODE_SET)) {
				// TODO: use CL here.. but its not necessary.. so better not do anything imho
				// r_core_cmdf (core, "CL %s:%d 0x%08"PFMT64x, file, (int)row->line, row->address);
#if 0
				char *cmt = r_str_newf ("%s:%d %s", file, (int)row->line, r_str_get (line));
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, row->address, cmt);
				free (cmt);
#endif
			} else if (IS_MODE_JSON (mode)) {
				pj_a (pj);

				pj_o (pj);
				pj_ks (pj, "name", "CC");
				pj_ks (pj, "file", file);
				pj_ki (pj, "line_num", (int) row->line);
				pj_kn (pj, "addr", row->addr);
				pj_end (pj);

				pj_o (pj);
				pj_ks (pj, "name", "CL");
				pj_ks (pj, "file", file);
				pj_ki (pj, "line_num", (int) row->line);
				pj_ks (pj, "line", r_str_get (line));
				pj_kn (pj, "addr", row->addr);
				pj_end (pj);

				pj_end (pj);
			} else {
				r_kons_printf (core->cons, "'@0x%08"PFMT64x"'CL %s:%d\n",
					row->addr, file, (int)row->line);
				r_kons_printf (core->cons, "'@0x%08"PFMT64x"'CC %s:%d %s\n",
					row->addr, file, row->line, r_str_get (line));
			}
			free (file);
			free (line);
		} else {
			r_kons_printf (core->cons, "0x%08" PFMT64x "\t%s\t%d\n",
				       row->addr, row->file, row->line);
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
	set_p_free (set);
	r_cons_break_pop (core->cons);
	ht_pp_free (file_lines);
	r_list_free (ownlist);
	return true;
}

R_API bool r_core_pdb_info(RCore *core, const char *file, PJ *pj, int mode) {
	R_RETURN_VAL_IF_FAIL (core && file, false);

	ut64 baddr = r_config_get_i (core->config, "bin.baddr");
	if (!baddr && core->bin->cur && core->bin->cur->bo && core->bin->cur->bo->baddr) {
		baddr = core->bin->cur->bo->baddr;
	}
	if (baddr == UT64_MAX) {
		R_LOG_WARN ("Cannot find base address, flags will probably be misplaced");
		baddr = 0;
	}
	RPdb pdb = {0};

	pdb.cb_printf = r_cons_printf;
	if (!init_pdb_parser (&pdb, file)) {
		if (pj || mode == 'j') {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}
	if (!pdb.pdb_parse (&pdb)) {
		R_LOG_ERROR ("pdb was not parsed");
		pdb.finish_pdb_parse (&pdb);
		if (pj || mode == 'j') {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}

	switch (mode) {
	case R_MODE_SET:
		mode = 's';
		r_core_cmd0 (core, ".iP*");
		if (pj) {
			pj_end (pj);
		}
		return true;
	case R_MODE_JSON:
		mode = 'j';
		break;
	case '*':
	case 1:
		mode = 'r';
		break;
	default:
		mode = 'd'; // default
		break;
	}

	if (mode == 'j') {
		pj_o (pj);
	}
	pdb.print_types (&pdb, pj, mode);
	pdb.print_gvars (&pdb, baddr, pj, mode);
	// Save compound types into SDB
	r_parse_pdb_types (core->anal, &pdb);
	pdb.finish_pdb_parse (&pdb);
	if (mode == 'j') {
		pj_end (pj);
	}

	return true;
}

#if 0
static ut64 srclineVal(const void *a) {
	return r_str_hash64 (a);
}
#endif

static bool bin_source(RCore *core, PJ *pj, int mode) {
	RList *final_list = r_list_new ();
	RBinFile * binfile = core->bin->cur;

	if (!binfile) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
		}
		r_list_free (final_list);
		return false;
	}
#if 1
	// TODO: future optimization: dump the stringpool containing filenames
	RList *files = r_bin_addrline_files (core->bin);
	if (files) {
		char *s = r_str_list_join (files, "\n");
		r_cons_println (core->cons, s);
		free (s);
	}
#else
	SdbListIter *iter;
	RListIter *iter2;
	char* srcline;
	SdbKv *kv;
	SdbList *ls = sdb_foreach_list (binfile->sdb_addrinfo, false);
	ls_foreach (ls, iter, kv) {
		char *v = sdbkv_value (kv);
		RList *list = r_str_split_list (v, "|", 0);
		srcline = r_list_first (list);
		if (srcline) {
			if (!strstr (srcline, "0x")) {
				r_list_append (final_list, srcline);
			}
		}
		r_list_free (list);
	}
	r_list_uniq_inplace (final_list, srclineVal);
	r_list_foreach (final_list, iter2, srcline) {
		r_kons_printf (core->cons, "%s\n", srcline);
	}
	r_list_free (final_list);
#endif
	return true;
}

static ut64 a2b(RBin *bin, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (bin, UT64_MAX);
	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		return o->baddr_shift + addr;
	}
	return addr;
}

static bool bin_main(RCore *core, PJ *pj, int mode, int va) {
	RBinAddr *binmain = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN);
	if (!binmain) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}
	ut64 addr = va ? a2b (core->bin, binmain->vaddr) : binmain->paddr;
	bool isthumb = (binmain->bits == 16);
	if (IS_MODE_SET (mode)) {
		r_flag_space_set (core->flags, R_FLAGS_FS_SYMBOLS);
		r_flag_set (core->flags, "main", addr, core->blocksize);
		if (isthumb) {
			r_core_cmd_call_at (core, addr, "ahb 16");
		}
	} else if (IS_MODE_SIMPLE (mode)) {
		r_kons_printf (core->cons, "%"PFMT64d, addr);
	} else if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "'fs symbols\n");
		r_kons_printf (core->cons, "'@0x%08"PFMT64x"'f main\n", addr);
		if (isthumb) {
			r_kons_printf (core->cons, "'@0x%08"PFMT64x"'ahb 16\n", addr);
		}
	} else if (IS_MODE_JSON (mode)) {
		pj_o (pj);
		pj_kn (pj, "vaddr", addr);
		pj_kn (pj, "paddr", binmain->paddr);
		pj_end (pj);
	} else {
		r_kons_printf (core->cons,
			"vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x"\n",
			addr, binmain->paddr);
	}
	return true;
}

static inline bool is_initfini(RBinAddr *entry) {
	switch (entry->type) {
	case R_BIN_ENTRY_TYPE_INIT:
	case R_BIN_ENTRY_TYPE_FINI:
	case R_BIN_ENTRY_TYPE_PREINIT:
		return true;
	default:
		return false;
	}
}

static bool bin_entry(RCore *core, PJ *pj, int mode, ut64 laddr, int va, bool inifin) {
	char str[R_FLAG_NAME_SIZE];
	const RList *entries = r_bin_get_entries (core->bin);
	RListIter *iter;
	RBinAddr *entry = NULL;
	int i = 0, init_i = 0, fini_i = 0, preinit_i = 0;
	ut64 baddr = r_bin_get_baddr (core->bin);

	if (IS_MODE_RAD (mode)) {
		if (r_list_empty (entries)) {
			return true;
		}
		r_cons_println (core->cons, "'fs+symbols");
	} else if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	}
	RTable *table = NULL;

	r_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 hpaddr = UT64_MAX;
		ut64 hvaddr = UT64_MAX;
		if (mode != R_MODE_SET) {
			if (inifin) {
				if (entry->type == R_BIN_ENTRY_TYPE_PROGRAM) {
					continue;
				}
			} else {
				if (entry->type != R_BIN_ENTRY_TYPE_PROGRAM) {
					continue;
				}
			}
		}
		if (entry->hpaddr) {
			hpaddr = entry->hpaddr;
			if (entry->hvaddr) {
				hvaddr = rva (core->bin, hpaddr, entry->hvaddr, va);
			}
		}
		ut64 at = rva (core->bin, paddr, entry->vaddr, va);
		const char *type = r_bin_entry_type_string (entry->type);
		if (!type) {
			type = "unknown";
		}
		const char *hpaddr_key = (entry->type == R_BIN_ENTRY_TYPE_PROGRAM)
			? "haddr": "hpaddr";
		if (IS_MODE_SET (mode)) {
			r_flag_space_set (core->flags, R_FLAGS_FS_SYMBOLS);
			if (entry->type == R_BIN_ENTRY_TYPE_INIT) {
				snprintf (str, R_FLAG_NAME_SIZE, "entry.init%i", init_i);
			} else if (entry->type == R_BIN_ENTRY_TYPE_FINI) {
				snprintf (str, R_FLAG_NAME_SIZE, "entry.fini%i", fini_i);
			} else if (entry->type == R_BIN_ENTRY_TYPE_PREINIT) {
				snprintf (str, R_FLAG_NAME_SIZE, "entry.preinit%i", preinit_i);
			} else {
				snprintf (str, R_FLAG_NAME_SIZE, "entry%i", i);
			}
			r_flag_set (core->flags, str, at, 1);
			if (is_initfini (entry) && hvaddr != UT64_MAX) {
				r_meta_set (core->anal, R_META_TYPE_DATA, hvaddr, entry->bits / 8, NULL);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			r_kons_printf (core->cons, "0x%08"PFMT64x"\n", at);
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_kn (pj, "paddr", paddr);
			pj_kn (pj, "vaddr", at);
			pj_kn (pj, "baddr", baddr);
			pj_kn (pj, "laddr", laddr);
			if (hvaddr != UT64_MAX) {
				pj_kn (pj, "hvaddr", hvaddr);
			}
			pj_kn (pj, hpaddr_key, hpaddr);
			if (R_STR_ISNOTEMPTY (type)) {
				pj_ks (pj, "type", type);
			}
			pj_end (pj);
		} else if (IS_MODE_RAD (mode)) {
			char *name = NULL;
			if (entry->type == R_BIN_ENTRY_TYPE_INIT) {
				name = r_str_newf ("entry.init%i", init_i);
			} else if (entry->type == R_BIN_ENTRY_TYPE_FINI) {
				name = r_str_newf ("entry.fini%i", fini_i);
			} else if (entry->type == R_BIN_ENTRY_TYPE_PREINIT) {
				name = r_str_newf ("entry.preinit%i", preinit_i);
			} else {
				name = r_str_newf ("entry%i", i);
			}
			char *n = r_name_filter_quoted_shell (name);
			r_kons_printf (core->cons, "'f %s 1 0x%08"PFMT64x"\n", n, at);
			r_kons_printf (core->cons, "'f %s_%s 1 0x%08"PFMT64x"\n", n, hpaddr_key, hpaddr);
			r_kons_printf (core->cons, "'s %s\n", n);
			free (n);
			free (name);
		} else if (IS_MODE_EQUAL (mode)) {
			r_kons_printf (core->cons, "paddr=0x%08"PFMT64x" vaddr=0x%08"PFMT64x, paddr, at);
			r_kons_printf (core->cons, " %s=", hpaddr_key);
			if (hpaddr == UT64_MAX) {
				r_kons_printf (core->cons, "%"PFMT64d, hpaddr);
			} else {
				r_kons_printf (core->cons, "0x%08"PFMT64x, hpaddr);
			}
			if (is_initfini (entry) && hvaddr != UT64_MAX) {
				r_kons_printf (core->cons, " vhaddr=0x%08"PFMT64x, hvaddr);
			} else if (entry->type == R_BIN_ENTRY_TYPE_PROGRAM && hvaddr != UT64_MAX) {
				r_kons_printf (core->cons, " vhaddr=0x%08"PFMT64x, hvaddr);
			}
			r_kons_printf (core->cons, " type=%s\n", type);
		} else {
			if (!table) {
				table = r_core_table_new (core, "entrypoints");
				r_table_set_columnsf (table, "XXXXs", "paddr", "vaddr", "phaddr", "vhaddr", "type");
			}
			ut64 vaddr = at;
			r_table_add_rowf (table, "XXXXs", paddr, vaddr, hpaddr, hvaddr, type);
		}
		if (entry->type == R_BIN_ENTRY_TYPE_INIT) {
			init_i++;
		} else if (entry->type == R_BIN_ENTRY_TYPE_FINI) {
			fini_i++;
		} else if (entry->type == R_BIN_ENTRY_TYPE_PREINIT) {
			preinit_i++;
		} else {
			i++;
		}
	}
	if (table) {
		if (core->table_query) {
			r_table_query (table, core->table_query);
		}
		char *s = r_table_tostring (table);
		r_kons_print (core->cons, s);
		free (s);
		r_table_free (table);
	} else if (IS_MODE_SET (mode)) {
		if (entry) {
			ut64 at = rva (core->bin, entry->paddr, entry->vaddr, va);
			r_core_seek (core, at, false);
		}
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "'fs-");
	} else if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
	return true;
}

static const char *bin_reloc_type_name(RBinReloc *reloc) {
#define CASE(T) case R_BIN_RELOC_ ## T: return reloc->additive ? "ADD_" #T : "SET_" #T
	switch (reloc->type) {
	CASE(1);
	CASE(2);
	CASE(4);
	CASE(8);
	CASE(16);
	CASE(24);
	CASE(32);
	CASE(48);
	CASE(64);
	}
	return "UNKNOWN";
#undef CASE
}

static ut8 bin_reloc_size(RBinReloc *reloc) {
#define CASE(T) case R_BIN_RELOC_ ## T: return (T) / 8
	switch (reloc->type) {
	CASE(1);
	CASE(2);
	CASE(4);
	CASE(8);
	CASE(16);
	CASE(24);
	CASE(32);
	CASE(48);
	CASE(64);
	}
	return 0;
#undef CASE
}

static char *resolveModuleOrdinal(Sdb *sdb, const char *module, int ordinal) {
	r_strf_buffer(64);
	Sdb *db = sdb;
	char *foo = sdb_get (db, r_strf ("%d", ordinal), 0);
	if (foo) {
		if (!*foo) {
			R_FREE (foo);
		}
	}
	return foo;
}

// name can be optionally used to explicitly set the used base name (for example for demangling), otherwise the import name will be used.
static char *construct_reloc_name(RBinReloc * R_NONNULL reloc, const char * R_NULLABLE name) {
	RStrBuf *buf = r_strbuf_new ("");

	// (optional) libname_
	if (reloc->import && reloc->import->libname) {
		r_strbuf_appendf (buf, "%s_", reloc->import->libname);
	} else if (reloc->symbol && reloc->symbol->libname) {
		r_strbuf_appendf (buf, "%s_", reloc->symbol->libname);
	}

	// actual name
	if (name) {
		r_strbuf_append (buf, name);
	} else if (reloc->import) {
		r_strbuf_append (buf, r_bin_name_tostring (reloc->import->name));
	} else if (reloc->symbol) {
		r_strbuf_append (buf, r_bin_name_tostring (reloc->symbol->name));
	} else if (reloc->is_ifunc) {
		// addend is the function pointer for the resolving ifunc
		r_strbuf_appendf (buf, "ifunc_%"PFMT64x, reloc->addend);
	} else {
		// TODO implement constant relocs.
		r_strbuf_set (buf, "");
	}
	return r_strbuf_drain (buf);
}

typedef struct {
	RCore *core;
	bool bin_demangle;
	bool keep_lib;
	const char *lang;
	bool is_sandbox;
	bool is_pe;
	bool is32;
} RelocInfo;

static void ri_init(RCore *core, RelocInfo *ri) {
	ri->core = core;
	ri->bin_demangle = r_config_get_b (core->config, "bin.demangle");
	ri->keep_lib = r_config_get_b (core->config, "bin.demangle.pfxlib");
	ri->lang = r_config_get (core->config, "bin.lang");
	const RBinInfo *info = r_bin_get_info (core->bin);
	const char *rclass = info->rclass;
	ri->is32 = r_config_get_i (core->config, "asm.bits") <= 32;
	ri->is_pe = rclass && r_str_startswith (rclass, "pe");
}

static void set_bin_relocs(RelocInfo *ri, RBinReloc *reloc, ut64 addr, Sdb **db, char **sdb_module) {
	RCore *core = ri->core;
	r_strf_buffer (64);

	const char *name = reloc->import? r_bin_name_tostring (reloc->import->name): NULL;
	if (ri->is_pe && name && reloc->import->libname && r_str_startswith (name, "Ordinal_")) {
		char *module = strdup (reloc->import->libname);
		r_str_case (module, false);

		// strip trailing ".dll"
		size_t module_len = strlen (module);
		if (module_len > 4 && !strcmp (module + module_len - 4, ".dll")) {
			module[module_len - 4] = '\0';
		}

		const char *import = name + strlen ("Ordinal_");
		if (import) {
			char *filename = NULL;
			int ordinal = atoi (import);
			if (!*sdb_module || strcmp (module, *sdb_module)) {
				sdb_free (*db);
				*db = NULL;
				free (*sdb_module);
				*sdb_module = strdup (module);
				/* always lowercase */
				filename = r_strf ("%s.sdb", module);
				r_str_case (filename, false);
				if (r_file_exists (filename)) {
					*db = sdb_new (NULL, filename, 0);
				} else {
					const char *dirPrefix = r_sys_prefix (NULL);
					filename = r_strf (R_JOIN_4_PATHS ("%s", R2_SDB_FORMAT, "dll", "%s.sdb"), dirPrefix, module);
					if (r_file_exists (filename)) {
						*db = sdb_new (NULL, filename, 0);
					}
				}
			}
			if (*db) {
				// ordinal-1 because we enumerate starting at 0
				char *symname = resolveModuleOrdinal (*db, module, ordinal - 1);  // uses sdb_get
				if (symname) {
					char *s = symname;
					if (core->bin->prefix) {
						s = r_str_newf ("%s.%s", core->bin->prefix, symname);
						R_FREE (symname);
					}
					r_bin_name_demangled (reloc->import->name, s);
					free (s);
				}
			}
		}
		r_anal_hint_set_size (core->anal, reloc->vaddr, 4);
		r_meta_set (core->anal, R_META_TYPE_DATA, reloc->vaddr, 4, NULL);
		free (module);
	}

	char flagname[R_FLAG_NAME_SIZE];
	char *reloc_name = construct_reloc_name (reloc, NULL);
	if (R_STR_ISEMPTY (reloc_name)) {
		char name[32] = {0};
		r_io_read_at (core->io, reloc->addend, (ut8*)name, sizeof (name));
		name[sizeof (name) - 1] = 0;
		if (name[0] && name[1] && isalpha (name[0]) && isalpha (name[1])) {
			r_name_filter (name, -1);
			R_LOG_DEBUG ("Naming fixup reloc with string %s", name);
			reloc_name = r_str_newf ("fixup.%s", name);
			// add xref from fixup to string
			r_anal_xrefs_set (core->anal, reloc->vaddr, reloc->addend, R_ANAL_REF_TYPE_DATA);
		} else {
			free (reloc_name);
			return;
		}
	}
	if (core->bin->prefix) {
		snprintf (flagname, R_FLAG_NAME_SIZE, "%s.reloc.%s", core->bin->prefix, reloc_name);
	} else {
		snprintf (flagname, R_FLAG_NAME_SIZE, "reloc.%s", reloc_name);
	}
	if (reloc->laddr) {
		char *internal_reloc = r_str_newf ("rsym.%s", reloc_name);
		(void)r_flag_set (core->flags, internal_reloc, reloc->laddr, bin_reloc_size (reloc));
		free (internal_reloc);
	}
	free (reloc_name);
	char *demname = NULL;
	if (ri->bin_demangle) {
		demname = r_bin_demangle (core->bin->cur, ri->lang, flagname, addr, ri->keep_lib);
		if (demname) {
			snprintf (flagname, R_FLAG_NAME_SIZE, "reloc.%s", demname);
		}
	}
	r_name_filter (flagname, 0);
	if (addr == UT64_MAX) {
		R_LOG_DEBUG ("Cannot resolve reloc %s", demname);
	} else {
		RFlagItem *fi = r_flag_set (core->flags, flagname, addr, bin_reloc_size (reloc));
		if (fi && demname) {
			char *realname = (core->bin->prefix)
				? r_str_newf ("%s.reloc.%s", core->bin->prefix, demname)
				: r_str_newf ("%s", demname);
			r_flag_item_set_realname (core->flags, fi, realname);
			free (realname);
		}
	}

	free (demname);
}

/* Define new data at relocation address if it's not in an executable section */
static void add_metadata(RCore *core, RBinReloc *reloc, ut64 addr, int mode) {
	RBinFile * binfile = core->bin->cur;
	RBinObject *binobj = binfile ? binfile->bo: NULL;
	RBinInfo *info = binobj ? binobj->info: NULL;

	int cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;
	if (cdsz == 0) {
		return;
	}
	RIOMap *map = r_io_map_get_at (core->io, addr);
	if (!map || map ->perm & R_PERM_X) {
		return;
	}
	if (IS_MODE_SET (mode)) {
		r_meta_set (core->anal, R_META_TYPE_DATA, reloc->vaddr, cdsz, NULL);
	} else if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "Cd %d @ 0x%08" PFMT64x "\n", cdsz, addr);
	}
}

static inline bool is_section_symbol(RBinSymbol *s) {
	/* workaround for some bin plugs (e.g. ELF) */
	return (s && s->type && !strcmp (s->type, R_BIN_TYPE_SECTION_STR));
}

static inline bool is_special_symbol(RBinSymbol *s) {
	return s && s->type && !strcmp (s->type, R_BIN_TYPE_SPECIAL_SYM_STR);
}

static inline bool is_section_reloc(RBinReloc *core) {
	return is_section_symbol (core->symbol);
}

static inline bool is_file_symbol(RBinSymbol *s) {
	/* workaround for some bin plugs (e.g. ELF) */
	return (s && s->type && !strcmp (s->type, R_BIN_TYPE_FILE_STR));
}

static inline bool is_file_reloc(RBinReloc *core) {
	return is_file_symbol (core->symbol);
}

static bool warn_if_dbg(RCore *core) {
	RIODesc *desc = NULL;
	RIOMap *map = r_io_map_get_at (core->io, 0); // core->addr);
	if (map) {
		desc = r_io_desc_get (core->io, map->fd);
	} else {
		RBinFile *bf = core->bin->cur;
		int fd;
		if (bf) {
			fd = bf->fd;
		} else {
			fd = r_io_fd_get_current (core->io);
		}
		if (fd != -1) {
			desc = r_io_desc_get (core->io, fd);
		}
	}
	if (desc) {
		const char *uri = desc->uri;
		R_LOG_DEBUG ("Using uri %s", uri);
		if (r_io_desc_is_dbg (desc)) {
			R_LOG_ERROR ("bin.relocs and io.cache should not be used with the current io plugin");
			return false;
		}
	}
	return true;
}

static bool bin_relocs(RCore *core, PJ *pj, int mode, int va) {
	bool bin_demangle = r_config_get_b (core->config, "bin.demangle");
	bool keep_lib = r_config_get_i (core->config, "bin.demangle.pfxlib");
	const char *lang = r_config_get (core->config, "bin.lang");
	RTable *table = r_core_table_new (core, "relocs");
	R_RETURN_VAL_IF_FAIL (table, false);
	Sdb *db = NULL;
	char *sdb_module = NULL;

	R_TIME_PROFILE_BEGIN;
	{
		int fd = r_io_fd_get_current (core->io);
		if (fd != -1) {
			RIODesc *desc = r_io_desc_get (core->io, fd);
			if (desc && r_io_desc_is_dbg (desc)) {
				R_LOG_DEBUG ("Ignoring reloc patching in debugger mode");
				return false;
			}

		}
	}

	va = VA_TRUE; // XXX relocs always vaddr?
	//this has been created for reloc object files
	RRBTree *relocs = r_bin_get_relocs (core->bin);
	const bool apply_relocs = r_config_get_b (core->config, "bin.relocs.apply");
	const bool bc = r_config_get_b (core->config, "bin.cache");
	if (apply_relocs) {
		if (!warn_if_dbg (core)) {
			return false;
		}
		// TODO: remove the bin.cache crap
		if (bc) {
			if (!(core->io->cachemode & R_PERM_W)) {
				r_config_set_b (core->config, "io.cache", true);
			}
			core->bin->iob.overlay_write_at = r_io_cache_write_at;
		}
		relocs = r_bin_patch_relocs (core->bin->cur); // XXX other way to get RBinFile?
		if (bc) {
			core->bin->iob.overlay_write_at = r_io_vwrite_to_overlay_at;
		} else {
			r_io_drain_overlay (core->io);
		}
	} else {
		if (bc) {
			if (!warn_if_dbg (core)) {
				return false;
			}
			if (!(core->io->cachemode & R_PERM_W)) {
				r_config_set_b (core->config, "io.cache", true);
			}
			core->bin->iob.overlay_write_at = r_io_write_at;
			relocs = r_bin_patch_relocs (core->bin->cur); // XXX other way to get RBinFile?
		} else if (relocs) {
			R_LOG_WARN ("Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time");
		}
	}
	if (!relocs) {
		if (pj) {
			pj_a (pj);
			pj_end (pj);
		}
		r_table_free (table);
		return false;
	}

	if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "fs relocs");
	} else if (IS_MODE_NORMAL (mode)) {
		r_table_set_columnsf (table, "XXsds", "vaddr", "paddr", "type", "ntype", "name");
	} else if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	} else if (IS_MODE_SET (mode)) {
		r_flag_space_set (core->flags, R_FLAGS_FS_RELOCS);
	}

	RRBNode *node;
	RBinReloc *reloc;
	RelocInfo ri = {0};
	ri_init (core, &ri);
	r_crbtree_foreach (relocs, node, RBinReloc, reloc) {
		ut64 addr = rva (core->bin, reloc->paddr, reloc->vaddr, va);
		if (IS_MODE_SET (mode) && (is_section_reloc (reloc) || is_file_reloc (reloc))) {
			/*
			 * Skip section reloc because they will have their own flag.
			 * Skip also file reloc because not useful for now.
			 */
		} else if (IS_MODE_SET (mode)) {
			set_bin_relocs (&ri, reloc, addr, &db, &sdb_module);
			add_metadata (core, reloc, addr, mode);
		} else if (IS_MODE_SIMPLEST (mode)) {
			if (reloc->import) {
				r_kons_printf (core->cons, "0x%08"PFMT64x"\n", addr);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			if (reloc->import) {
				const char *name = r_bin_name_tostring (reloc->import->name);
				r_kons_printf (core->cons, "0x%08"PFMT64x"  %s\n", addr, name);
			}
		} else if (IS_MODE_RAD (mode)) {
			char *name = reloc->import
				? strdup (r_bin_name_tostring (reloc->import->name))
				: (reloc->symbol ? strdup (r_bin_name_tostring (reloc->symbol->name)) : NULL);
			if (name) {
				if (bin_demangle) {
					char *mn = r_bin_demangle (core->bin->cur, NULL, name, addr, keep_lib);
					if (mn) {
						free (name);
						name = mn;
					}
				}
				int reloc_size = 4;
				// char *n = r_name_filter_quoted_shell (name);
				char *n = strdup (name);
				r_name_filter (n, -1);
				r_kons_printf (core->cons, "'f %s%s%s %d 0x%08"PFMT64x"\n",
					r_str_get_fail (core->bin->prefix, "reloc."),
					core->bin->prefix ? "." : "", n, reloc_size, addr);
				add_metadata (core, reloc, addr, mode);
				free (n);
				free (name);
#if 0
				if (reloc->symbol && reloc->symbol->vaddr != addr) {
					// ut64 saddr = reloc->symbol->vaddr;
					ut64 saddr = rva (core->bin, reloc->symbol->paddr, reloc->symbol->vaddr, va);
					r_kons_printf (core->cons, "'f %s%s%s %d 0x%08"PFMT64x"\n",
						r_str_get_fail (core->bin->prefix, "rsym."),
						core->bin->prefix ? "." : "", n, reloc_size, saddr);
				}
#endif
			} else {
				ut64 v = reloc->symbol? reloc->symbol->vaddr: reloc->addend;
				ut64 a = addr;
				r_kons_printf (core->cons, "wv8 0x%"PFMT64x" @ 0x%"PFMT64x"\n", v, a);
			}
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			char *mn = NULL;
			char *relname = NULL;

			if (reloc->import) {
				const char *iname = r_bin_name_tostring (reloc->import->name);
				mn = r_bin_demangle (core->bin->cur, lang, iname, addr, keep_lib);
				relname = strdup (iname);
			} else if (reloc->symbol) {
				const char *sname = r_bin_name_tostring (reloc->symbol->name);
				mn = r_bin_demangle (core->bin->cur, lang, sname, addr, keep_lib);
				relname = strdup (sname);
			}

			// check if name is available
			if (relname && *relname) {
				pj_ks (pj, "name", relname);
			}
			if (R_STR_ISNOTEMPTY (mn)) {
				pj_ks (pj, "demname", mn);
			}
			pj_ks (pj, "type", bin_reloc_type_name (reloc));
			pj_kn (pj, "ntype", reloc->ntype);
			pj_kn (pj, "vaddr", reloc->vaddr);
			pj_kn (pj, "paddr", reloc->paddr);
			if (reloc->symbol) {
				pj_kn (pj, "sym_va", reloc->symbol->vaddr);
			}
			pj_kb (pj, "is_ifunc", reloc->is_ifunc);
			// end reloc item
			pj_end (pj);

			free (mn);
			if (relname) {
				free (relname);
			}
		} else if (IS_MODE_NORMAL (mode)) {
			if (addr == UT64_MAX) {
				R_LOG_DEBUG ("Cannot resolve address for %s", bin_reloc_type_name (reloc));
				continue;
			}

			char *name = reloc->import
				? strdup (r_bin_name_tostring (reloc->import->name))
					: reloc->symbol
					? strdup (r_bin_name_tostring (reloc->symbol->name))
				: NULL;
			if (bin_demangle) {
				char *mn = r_bin_demangle (core->bin->cur, NULL, name, addr, keep_lib);
				if (R_STR_ISNOTEMPTY (mn)) {
					free (name);
					name = mn;
				}
			}
			char *reloc_name = construct_reloc_name (reloc, name);
			RStrBuf *buf = r_strbuf_new (reloc_name);
			free (reloc_name);
			R_FREE (name);
			if (reloc->addend) {
				if ((reloc->import || reloc->symbol) && !r_strbuf_is_empty (buf) && reloc->addend > 0) {
					r_strbuf_append (buf," +");
				}
				if (reloc->addend < 0) {
					r_strbuf_appendf (buf," - 0x%08"PFMT64x, -reloc->addend);
				} else {
					r_strbuf_appendf (buf," 0x%08"PFMT64x, reloc->addend);
				}
			}
			if (reloc->is_ifunc) {
				r_strbuf_append (buf, " (ifunc)");
			}

			char *res = r_strbuf_drain (buf);
			r_table_add_rowf (table, "XXsds", addr, reloc->paddr,
				bin_reloc_type_name (reloc), reloc->ntype, res);
			free (res);
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
	if (IS_MODE_NORMAL (mode)) {
		bool show_table = true;
		if (core->table_query) {
			show_table = r_table_query (table, core->table_query);
		}
		if (show_table) {
			char *s = r_table_tostring (table);
			if (s) {
				r_kons_print (core->cons, s);
				free (s);
			}
		}
	}

	r_table_free (table);
	R_FREE (sdb_module);
	sdb_free (db);
	db = NULL;

	R_TIME_PROFILE_END;
	return true;
}

/* R2_600 - avoid using globals to resolve symbols and imports without making it expensive */
R_DEPRECATE static R_TH_LOCAL Sdb *mydb = NULL;
R_DEPRECATE static R_TH_LOCAL RVecRBinSymbol *osymbols = NULL;

R_DEPRECATE static RBinSymbol *get_import(RBin *bin, RVecRBinSymbol *symbols, const char *name, ut64 addr) {
	r_strf_buffer(64);
	RBinSymbol *symbol, *res = NULL;
	if (mydb && symbols && symbols != osymbols) {
		sdb_free (mydb);
		mydb = NULL;
		osymbols = symbols;
	}
	if (mydb) {
		if (name) {
			res = (RBinSymbol*)(void*)(size_t)
				sdb_num_get (mydb, r_strf ("%x", sdb_hash (name)), NULL);
		} else {
			res = (RBinSymbol*)(void*)(size_t)
				sdb_num_get (mydb, r_strf ("0x%08"PFMT64x, addr), NULL);
		}
	} else {
		mydb = sdb_new0 ();
		R_VEC_FOREACH (symbols, symbol) {
			if (!symbol->name || !symbol->is_imported) {
				continue;
			}
			/* ${name}=${ptrToSymbol} */
			if (!sdb_num_add (mydb, r_strf ("%x", sdb_hash (r_bin_name_tostring (symbol->name))), (ut64)(size_t)symbol, 0)) {
			//	eprintf ("DUP (%s)\n", symbol->name);
			}
			/* 0x${vaddr}=${ptrToSymbol} */
			if (!sdb_num_add (mydb, r_strf ("0x%08"PFMT64x, symbol->vaddr), (ut64)(size_t)symbol, 0)) {
			//	eprintf ("DUP (%s)\n", symbol->name);
			}
			if (name) {
				if (!res && !strcmp (r_bin_name_tostring (symbol->name), name)) {
					res = symbol;
				}
			} else {
				if (symbol->vaddr == addr) {
					res = symbol;
				}
			}
		}
		osymbols = symbols;
	}
	return res;
}

/* XXX: This is a hack to get PLT references in rabin2 -i */
R_API ut64 r_core_bin_impaddr(RBin *bin, int va, const char *name) {
	R_RETURN_VAL_IF_FAIL (bin, UT64_MAX);
	ut64 addr = UT64_MAX;
	if (!name || !*name) {
		return addr;
	}
	RVecRBinSymbol *symbols = r_bin_get_symbols_vec (bin);
	if (!symbols) {
		return addr;
	}
	RBinSymbol *s = get_import (bin, symbols, name, 0LL);
	// maybe ut64_MAX to indicate import not found?
	if (s) {
		if (va) {
			if (s->paddr == UT64_MAX) {
				addr = s->vaddr;
			} else {
				addr = r_bin_get_vaddr (bin, s->paddr, s->vaddr);
			}
		} else {
			addr = s->paddr;
		}
	}
	return addr;
}

static bool bin_imports(RCore *core, PJ *pj, int mode, int va, const char *name) {
	RBinInfo *info = r_bin_get_info (core->bin);
	bool bin_demangle = r_config_get_b (core->config, "bin.demangle");
	bool keep_lib = r_config_get_b (core->config, "bin.demangle.pfxlib");
	RTable *table = r_core_table_new (core, "imports");
	R_RETURN_VAL_IF_FAIL (table, false);
	RBinImport *import;
	RListIter *iter;
	r_strf_buffer (64);
	bool lit = info ? info->has_lit: false;

	if (!info) {
		if (IS_MODE_JSON (mode)) {
			pj_a (pj);
			pj_end (pj);
		}
		r_table_free (table);
		return false;
	}

	const RList *imports = r_bin_get_imports (core->bin);
	int cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "fs imports");
	} else if (IS_MODE_NORMAL (mode)) {
		r_table_set_columnsf (table, "nXssss", "nth", "vaddr", "bind", "type", "lib", "name");
	}
	r_list_foreach (imports, iter, import) {
		const char *iname = r_bin_name_tostring (import->name);
		if (name && strcmp (iname, name)) {
			continue;
		}
		char *symname = strdup (iname);
		char *libname = import->libname ? strdup (import->libname) : NULL;
		ut64 addr = lit ? r_core_bin_impaddr (core->bin, va, symname): 0;
		if (bin_demangle) {
			char *dname = r_bin_demangle (core->bin->cur, NULL, symname, addr, keep_lib);
			if (dname) {
				free (symname);
				symname = r_str_newf ("sym.imp.%s", dname);
				free (dname);
			}
		}
		if (core->bin->prefix) {
			char *prname = r_str_newf ("%s.%s", core->bin->prefix, symname);
			free (symname);
			symname = prname;
		}
		if (IS_MODE_SET (mode)) {
			// TODO(eddyb) symbols that are imports.
			// Add a dword/qword for PE imports
			if (libname && strstr (libname, ".dll") && cdsz) {
				r_meta_set (core->anal, R_META_TYPE_DATA, addr, cdsz, NULL);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			r_kons_printf (core->cons, "%s%s%s\n", r_str_get (libname), libname ? " " : "", symname);
		} else if (IS_MODE_SIMPLEST (mode)) {
			r_cons_println (core->cons, symname);
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ki (pj, "ordinal", import->ordinal);
			if (import->bind) {
				pj_ks (pj, "bind", import->bind);
			}
			if (import->type) {
				pj_ks (pj, "type", import->type);
			}
			if (import->classname && import->classname[0]) {
				pj_ks (pj, "classname", import->classname);
				pj_ks (pj, "descriptor", import->descriptor);
			}
			pj_ks (pj, "name", symname);
			if (libname) {
				pj_ks (pj, "libname", libname);
			}
			if (addr && addr != UT64_MAX) {
				pj_kn (pj, "plt", addr);
			}
			pj_end (pj);
		} else if (IS_MODE_RAD (mode)) {
			// TODO(eddyb) symbols that are imports.
		} else {
			const char *bind = r_str_get_fail (import->bind, "NONE");
			const char *type = r_str_get_fail (import->type, "NONE");
			if (import->classname && import->classname[0]) {
				r_table_add_rowf (table, "nXssss", (ut64)import->ordinal, addr, bind, type, r_str_get (libname),
					r_strf ("%s.%s", import->classname, symname));
			} else {
				r_table_add_rowf (table, "nXssss", (ut64)import->ordinal, addr, bind, type, r_str_get (libname),
					symname);
			}

			if (import->descriptor && import->descriptor[0]) {
				// Uh?
				r_kons_printf (core->cons, " descriptor=%s", import->descriptor);
			}
			if (!IS_MODE_NORMAL (mode)) {
				r_cons_newline (core->cons);
			}
		}
		R_FREE (symname);
		R_FREE (libname);
	}

	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	} else if (IS_MODE_NORMAL (mode)) {
		bool show_table = true;
		if (core->table_query) {
			show_table = r_table_query (table, core->table_query);
		}
		if (show_table) {
			char *s = r_table_tostring (table);
			r_kons_print (core->cons, s);
			free (s);
		}
	}

	r_table_free (table);
	// NOTE: if we comment out this, it will leak.. but it will be faster
	// because it will keep the cache across multiple RBin calls
	osymbols = NULL;
	sdb_free (mydb);
	mydb = NULL;
	return true;
}

static const char *symbol_flag_prefix(RBinSymbol *sym) {
	if (sym) {
		// workaround for ELF
		if (sym->type) {
			if (!strcmp (sym->type, R_BIN_TYPE_NOTYPE_STR)) {
				return sym->is_imported ? "loc.imp" : "loc";
			}
			if (!strcmp (sym->type, R_BIN_TYPE_OBJECT_STR)) {
				return sym->is_imported ? "obj.imp" : "obj";
			}
		}
		return sym->is_imported ? "sym.imp" : "sym";
	}
	return "sym";
}

#define MAXFLAG_LEN_DEFAULT 128

static char *construct_symbol_flagname(const char *pfx, const char *libname, const char *symname, int len) {
	char *s = r_str_newf ("%s.%s%s%s", pfx, r_str_get (libname), libname ? "_" : "", symname);
	if (s) {
		r_name_filter (s, len); // maybe unnecessary..
		char *R = r_name_filter_quoted_shell (s);
		free (s);
		return R;
	}
	return NULL;
}

typedef struct {
	const char *pfx; // prefix for flags
	char *name;      // raw symbol name
	char *libname;   // name of the lib this symbol is specific to, if any
	char *nameflag;  // flag name for symbol
	char *demname;   // demangled raw symbol name
	char *demflag;   // flag name for demangled symbol
	char *classname; // classname
	char *classflag; // flag for classname
	char *methname;  // methods [class]::[method]
	char *methflag;  // methods flag sym.[class].[method]
} SymName;

static void snInit(RCore *core, SymName *sn, RBinSymbol *sym, const char *lang, bool bin_demangle, bool keep_lib) {
	bin_demangle &= !!lang;
	if (!core || !sym || !sym->name) {
		return;
	}
	sym->name->name = NULL;
	const char *sym_name = r_bin_name_tostring (sym->name);

	sn->name = r_str_newf ("%s%s", sym->is_imported ? "imp." : "", sym_name);
	sn->libname = sym->libname ? strdup (sym->libname) : NULL;
	const char *pfx = symbol_flag_prefix (sym);
	const char *symname = sym_name;
	char *resymname = NULL;
	if (sym->dup_count > 0) {
		resymname = r_str_newf ("%s_%d", sym_name, sym->dup_count);
		symname = resymname;
	}
	sn->nameflag = construct_symbol_flagname (pfx, sym->libname, symname, MAXFLAG_LEN_DEFAULT);
	free (resymname);
	if (R_STR_ISNOTEMPTY (sym->classname)) {
		sn->classname = strdup (sym->classname);
		sn->classflag = r_str_newf ("sym.%s.%s", sn->classname, sn->name);
		r_name_filter (sn->classflag, MAXFLAG_LEN_DEFAULT);
		sn->methname = r_str_newf ("%s::%s", sn->classname, sym_name);
		sn->methflag = r_str_newf ("sym.%s.%s", sn->classname, sym_name);
		r_name_filter (sn->methflag, strlen (sn->methflag));
	} else {
		sn->classname = NULL;
		sn->classflag = NULL;
		sn->methname = NULL;
		sn->methflag = NULL;
	}
	sn->demname = NULL;
	sn->demflag = NULL;
	if (bin_demangle && sym->paddr) {
		sn->demname = r_bin_demangle (core->bin->cur, lang, sn->name, sym->vaddr, keep_lib);
		if (sn->demname) {
			// XXX LEAK
			sn->demflag = construct_symbol_flagname (pfx, sym->libname, sn->demname, -1);
		}
	}
}

static void snFini(SymName *sn) {
	R_FREE (sn->name);
	R_FREE (sn->libname);
	R_FREE (sn->nameflag);
	R_FREE (sn->demname);
	R_FREE (sn->demflag);
	R_FREE (sn->classname);
	R_FREE (sn->classflag);
	R_FREE (sn->methname);
	R_FREE (sn->methflag);
}

static bool its_an_export(RBinSymbol *s) {
	/* workaround for some bin plugs */
	if (s->is_imported) {
		return false;
	}
	return (s->bind && !strcmp (s->bind, R_BIN_BIND_GLOBAL_STR));
}

static ut64 compute_addr(RBin *bin, ut64 paddr, ut64 vaddr, int va) {
	return paddr == UT64_MAX? vaddr: rva (bin, paddr, vaddr, va);
}

static void handle_arm_special_symbol(RCore *core, RBinSymbol *symbol, int va) {
	ut64 addr = compute_addr (core->bin, symbol->paddr, symbol->vaddr, va);
	const char *oname = r_bin_name_tostring2 (symbol->name, 'o');
	if (!strcmp (oname, "$a")) {
		r_anal_hint_set_bits (core->anal, addr, 32);
	} else if (!strcmp (oname, "$x")) {
		r_anal_hint_set_bits (core->anal, addr, 64);
	} else if (!strcmp (oname, "$t")) {
		r_anal_hint_set_bits (core->anal, addr, 16);
	} else if (!strcmp (oname, "$d")) {
		// TODO: we could add data meta type at addr, but sometimes $d
		// is in the middle of the code and it would make the code less
		// readable.
	} else {
		if (core->bin->options.verbose) {
			R_LOG_WARN ("Special symbol %s not handled", oname);
		}
	}
}

static void handle_arm_hint(RCore *core, RBinInfo *info, ut64 paddr, ut64 vaddr, int bits, int va) {
	if (info->bits > 32) { // we look at 16 or 32 bit only
		return;
	}

	int force_bits = 0;
	ut64 addr = compute_addr (core->bin, paddr, vaddr, va);
	if (paddr & 1 || bits == 16) {
		force_bits = 16;
	} else if (info->bits == 16 && bits == 32) {
		force_bits = 32;
	} else if (!(paddr & 1) && bits == 32) {
		force_bits = 32;
	}
	if (force_bits) {
		r_anal_hint_set_bits (core->anal, addr, force_bits);
	}
}

static void handle_arm_symbol(RCore *core, RBinSymbol *symbol, RBinInfo *info, int va) {
	handle_arm_hint (core, info, symbol->paddr, symbol->vaddr, symbol->bits, va);
}

static void handle_arm_entry(RCore *core, RBinAddr *entry, RBinInfo *info, int va) {
	handle_arm_hint (core, info, entry->paddr, entry->vaddr, entry->bits, va);
}

static void select_flag_space(RCore *core, RBinSymbol *symbol) {
	if (symbol->is_imported) {
		r_flag_space_push (core->flags, R_FLAGS_FS_IMPORTS);
	} else if (symbol->type && !strcmp (symbol->type, R_BIN_TYPE_SECTION_STR)) {
		// TODO get rid of this R2_590
		r_flag_space_push (core->flags, R_FLAGS_FS_SYMBOLS_SECTIONS);
	} else {
		r_flag_space_push (core->flags, R_FLAGS_FS_SYMBOLS);
	}
}

static bool bin_symbols(RCore *core, PJ *pj, int mode, ut64 laddr, int va, ut64 at, const char *name, bool exponly, const char *args) {
	RBinInfo *info = r_bin_get_info (core->bin);
	const RList *entries = r_bin_get_entries (core->bin);
	RBinAddr *entry;
	RListIter *iter;
	bool firstexp = true;
	bool printHere = (args && *args == '.');
	bool none = true;

	int lastfs = 's';
	RTable *table = r_core_table_new (core, "symbols");
	bool bin_demangle = r_config_get_b (core->config, "bin.demangle");
	const bool keep_lib = r_config_get_b (core->config, "bin.demangle.pfxlib");
	if (IS_MODE_JSON (mode)) {
		if (!printHere) {
			pj_a (pj);
		}
	}
	if (!info) {
		if (IS_MODE_JSON (mode)) {
			if (printHere) {
				pj_o (pj);
			}
			pj_end (pj);
		}
		r_table_free (table);
		return false;
	}

	bool is_arm = info && info->arch && r_str_startswith (info->arch, "arm");
	const char *lang = bin_demangle ? r_config_get (core->config, "bin.lang") : NULL;

	RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
	r_spaces_push (&core->anal->meta_spaces, "bin");

	if (IS_MODE_SET (mode)) {
		r_flag_space_set (core->flags, R_FLAGS_FS_SYMBOLS);
	} else if (at == UT64_MAX && exponly) {
		if (IS_MODE_RAD (mode)) {
			r_kons_printf (core->cons, "fs exports\n");
		}
	} else if (at == UT64_MAX && !exponly) {
		if (IS_MODE_RAD (mode)) {
			r_kons_printf (core->cons, "fs symbols\n");
		}
	}
	if (IS_MODE_NORMAL (mode)) {
		r_table_set_columnsf (table, "dXXssdsss", "nth", "paddr","vaddr","bind", "type", "size", "lib", "name", "demangled");
	}

	RBinSymbol *symbol;
	r_cons_break_push (core->cons, NULL, NULL);
	R_VEC_FOREACH (symbols, symbol) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		const char *rawname = r_bin_name_tostring2 (symbol->name, 'o');
		const char *name = r_bin_name_tostring (symbol->name);
		if (!name) {
			continue;
		}
		if (rawname == name) {
			rawname = NULL;
		}
		if (exponly && !its_an_export (symbol)) {
			continue;
		}
		if (name && strcmp (name, name)) {
			continue;
		}
		ut64 addr = compute_addr (core->bin, symbol->paddr, symbol->vaddr, va);
		ut32 len = symbol->size ? symbol->size : 1;
		if (at != UT64_MAX && (!symbol->size || !is_in_range (at, addr, symbol->size))) {
			continue;
		}
		if (printHere) {
			// const ut64 addr = va? symbol->vaddr: symbol->paddr;
			if (!is_in_range (core->addr, addr, len)) {
				continue;
			}
		}
		SymName sn = {0};
		snInit (core, &sn, symbol, lang, bin_demangle, keep_lib);
		char *r_symbol_name = r_str_escape_utf8 (sn.name, false, true);

		if (IS_MODE_SET (mode) && (is_section_symbol (symbol) || is_file_symbol (symbol))) {
			/*
			 * Skip section symbols because they will have their own flag.
			 * Skip also file symbols because not useful for now.
			 */
		} else if (IS_MODE_SET (mode) && is_special_symbol (symbol)) {
			if (is_arm) {
				handle_arm_special_symbol (core, symbol, va);
			}
		} else if (IS_MODE_SET (mode)) {
			// TODO: provide separate API in RBinPlugin to let plugins handle anal hints/metadata
			if (is_arm) {
				handle_arm_symbol (core, symbol, info, va);
			}
			select_flag_space (core, symbol);
			/* If that's a Classed symbol (method or so) */
			if (sn.classname) {
				RFlagItem *fi = r_flag_get (core->flags, sn.methflag);
				if (core->bin->prefix) {
					char *prname = r_str_newf ("%s.%s", core->bin->prefix, sn.methflag);
					free (sn.methflag);
					sn.methflag = prname;
					r_name_filter (sn.methflag, -1);
				}
				if (fi) {
					r_flag_item_set_realname (core->flags, fi, sn.methname);
					if ((fi->addr - core->flags->base) == addr) {
						r_flag_unset (core->flags, fi);
					}
				} else {
					fi = r_flag_set (core->flags, sn.methflag, addr, symbol->size);
#if 0
					char *comment = (fi && fi->comment) ? strdup (fi->comment) : NULL;
					if (comment) {
						r_flag_item_set_comment (fi, comment);
						free (comment);
					}
#endif
				}
			} else {
				const char *n = sn.demname ? sn.demname : name;
				const char *fn = sn.demflag ? sn.demflag : sn.nameflag;
				char *fnp = (core->bin->prefix) ?
					r_str_newf ("%s.%s", core->bin->prefix, fn):
					strdup (r_str_get (fn));
				if (addr == UT64_MAX) {
					R_LOG_DEBUG ("Cannot resolve symbol address %s", n);
				} else {
					RFlagItem *fi = r_flag_set (core->flags, fnp, addr, symbol->size);
					if (fi) {
						r_flag_item_set_realname (core->flags, fi, n);
						const bool is_demangled = (bool)(size_t)sn.demname;
						if (is_demangled) {
#if 0 && METAFLAG
							RFlagItemMeta *fim = r_flag_get_meta2 (core->flags, fi);
							fim->demangled = true;
#else
							fi->demangled = true;
#endif
						}
					} else {
						if (fn) {
							R_LOG_WARN ("Can't find flag (%s)", fn);
						}
					}
				}
				free (fnp);
			}
			if (sn.demname) {
				ut64 size = symbol->size > 0? symbol->size: 1;
				r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, size, sn.demname);
			}
			r_flag_space_pop (core->flags);
		} else if (IS_MODE_JSON (mode)) {
			none = false;
			pj_o (pj);
			pj_ks (pj, "name", r_symbol_name);
			if (sn.demname) {
				pj_ks (pj, "demname", sn.demname);
			}
			pj_ks (pj, "flagname", (bin_demangle && sn.demflag) ? sn.demflag : sn.nameflag);
			pj_ks (pj, "realname", r_symbol_name); // (bin_demangle && sn.demname) ? sn.demname : r_symbol_name);
			if (rawname) {
				pj_ks (pj, "rawname", rawname);
			}
			if (symbol->classname) {
				pj_ks (pj, "classname", symbol->classname);
			}
			pj_ki (pj, "ordinal", symbol->ordinal);
			pj_ks (pj, "bind", symbol->bind);
			pj_kn (pj, "size", (ut64)symbol->size);
			const char *safetyName = r_bin_import_tags (core->bin, name);
			if (safetyName) {
				pj_ks (pj, "unsafe", safetyName);
			}
			pj_ks (pj, "type", symbol->type);
			pj_kn (pj, "vaddr", addr);
			pj_kn (pj, "paddr", symbol->paddr);
			pj_kb (pj, "is_imported", symbol->is_imported);
			pj_end (pj);
		} else if (IS_MODE_SIMPLE (mode)) {
			const char *n = sn.demname? sn.demname: r_symbol_name;
			r_kons_printf (core->cons, "0x%08"PFMT64x" %d %s%s%s\n", addr, (int)symbol->size,
				r_str_get (sn.libname), sn.libname ? " " : "", n);
		} else if (IS_MODE_SIMPLEST (mode)) {
			const char *n = sn.demname? sn.demname: r_symbol_name;
			r_kons_printf (core->cons, "%s\n", n);
		} else if (IS_MODE_RAD (mode)) {
			/* Skip special symbols because we do not flag them and
			 * they shouldn't be printed in the rad format either */
			if (is_special_symbol (symbol)) {
				goto next;
			}
			RBinFile *binfile;
			RBinPlugin *plugin;
			const char *n = sn.demname? sn.demname: r_symbol_name;
			if (!n) {
				goto next;
			}
			if (symbol->is_imported) {
				if (lastfs != 'i') {
					r_kons_printf (core->cons, "fs imports\n");
				}
				lastfs = 'i';
			} else {
				if (lastfs != 's') {
					const char *fs = exponly? "exports": "symbols";
					r_kons_printf (core->cons, "fs %s\n", fs);
				}
				lastfs = 's';
			}
			if (core->bin->prefix || *n) { // we don't want unnamed symbol flags
				char *flagname = construct_symbol_flagname ("sym", sn.libname, n, MAXFLAG_LEN_DEFAULT);
				if (!flagname) {
					goto next;
				}
				r_kons_printf (core->cons, "'f %s%s%s %u 0x%08" PFMT64x "\n",
					r_str_get (core->bin->prefix), core->bin->prefix ? "." : "",
					flagname, symbol->size, addr);
				free (flagname);
			}
			binfile = r_bin_cur (core->bin);
			plugin = r_bin_file_cur_plugin (binfile);
			if (plugin && plugin->meta.name) {
				if (r_str_startswith (plugin->meta.name, "pe")) {
					char *module = strdup (r_symbol_name);
					char *p = strstr (module, ".dll_");
					if (p && symbol->is_imported) {
						char *symname = r_name_filter_shell (p + 5);
						char *m = r_name_filter_shell (module);
						*p = 0;
						if (core->bin->prefix) {
							r_kons_printf (core->cons, "'k bin/pe/%s/%d=%s.%s\n",
								module, symbol->ordinal, core->bin->prefix, symname);
						} else {
							r_kons_printf (core->cons, "'k bin/pe/%s/%d=%s\n",
								module, symbol->ordinal, symname);
						}
						free (symname);
						free (m);
					}
					free (module);
				}
			}
		} else {
			const char *bind = r_str_get_fail (symbol->bind, "NONE");
			const char *type = r_str_get_fail (symbol->type, "NONE");
			const char *n = r_str_getf (sn.demname? sn.demname: sn.name);
			// const char *fwd = r_str_getf (symbol->forwarder);
			r_table_add_rowf (table, "dXXssdsss",
					symbol->ordinal,
					symbol->paddr,
					addr,
					bind,
					type,
					symbol->size,
					r_str_get (symbol->libname),
					sn.name,
					strcmp (n, sn.name)? n: "");
		}
next:
		snFini (&sn);
		free (r_symbol_name);
		if (exponly && firstexp) {
			firstexp = false;
		}
		if (printHere) {
			break;
		}
	}
	r_cons_break_pop (core->cons);
	if (IS_MODE_NORMAL (mode)) {
		if (core->table_query) {
			if (!r_table_query (table, core->table_query)) {
				r_table_free (table);
				return false;
			}
		}
		char *s = r_table_tostring (table);
		r_kons_print (core->cons, s);
		free (s);
	}

	// handle thumb and arm for entry point since they are not present in symbols
	if (is_arm) {
		r_list_foreach (entries, iter, entry) {
			if (IS_MODE_SET (mode)) {
				handle_arm_entry (core, entry, info, va);
			}
		}
	}
	if (IS_MODE_JSON (mode)) {
		if (!printHere) {
			pj_end (pj);
		} else if (none) {
			pj_o (pj);
			pj_end (pj);
		}
	}

	r_spaces_pop (&core->anal->meta_spaces);
	r_table_free (table);
	return true;
}

static char *build_hash_string(PJ *pj, int mode, const char *chksum, ut8 *data, ut32 datalen) {
	char *chkstr = NULL, *aux = NULL, *ret = NULL;
	RList *hashlist = r_str_split_duplist (chksum, ",", true);
	RListIter *iter;
	const char *hashname;
	r_list_foreach (hashlist, iter, hashname) {
		chkstr = r_hash_tostring (NULL, hashname, data, datalen);
		if (!chkstr) {
			continue;
		}
		if (IS_MODE_SIMPLE (mode) || IS_MODE_NORMAL (mode)) {
			aux = r_str_newf (iter->n? "%s " : "%s", chkstr);
		} else if (IS_MODE_JSON (mode)) {
			pj_ks (pj, hashname, chkstr);
		} else {
			aux = r_str_newf ("%s=%s ", hashname, chkstr);
		}
		ret = r_str_append (ret, aux);
		free (chkstr);
		free (aux);
	}
	r_list_free (hashlist);
	return ret;
}

static char *filter_hash_string(const char *chksum) {
	if (!chksum) {
		return NULL;
	}
	char *ret = NULL;
	bool isFirst = true;
	RList *hashlist = r_str_split_duplist (chksum, ",", true);
	RListIter *iter;
	char *hashname;
	r_list_foreach (hashlist, iter, hashname) {
		if (r_hash_name_to_bits (hashname)) {
			char *aux = r_str_newf (isFirst? "%s" : ", %s", hashname);
			ret = r_str_append (ret, aux);
			free (aux);
			if (isFirst) {
				isFirst = false;
			}
		}
	}
	r_list_free (hashlist);
	return ret;
}

typedef struct {
	const char *uri;
	int perm;
	RIODesc *desc;
} FindFile;

static bool findFile(void *user, void *data, ut32 id) {
	FindFile *res = (FindFile*)user;
	RIODesc *desc = (RIODesc*)data;
	if (desc->perm && res->perm && !strcmp (desc->uri, res->uri)) {
		res->desc = desc;
		return false;
	}
	return true;
}

static RIODesc *findReusableFile(RIO *io, const char *uri, int perm) {
	FindFile arg = {
		.uri = uri,
		.perm = perm,
		.desc = NULL,
	};
	r_id_storage_foreach (&io->files, findFile, &arg);
	return arg.desc;
}

static bool io_create_mem_map(RIO *io, RBinSection *sec, ut64 at, ut64 gap) {
	R_RETURN_VAL_IF_FAIL (io && sec, false);

	bool reused = false;
	char *uri = r_str_newf ("null://%"PFMT64u, gap);
	RIODesc *desc = findReusableFile (io, uri, sec->perm);
	if (desc) {
		RIOMap *map = r_io_map_get_at (io, at);
		if (!map) {
			r_io_map_add (io, desc->fd, desc->perm, 0LL, at, gap);
		}
		reused = true;
	}
	if (!desc) {
		desc = r_io_open_at (io, uri, sec->perm, 0664, at);
	}
	free (uri);
	if (!desc) {
		return false;
	}
	// this works, because new maps are always born on the top
	RIOMap *map = r_io_map_get_at (io, at);
	// check if the mapping failed
	if (!map) {
		if (!reused) {
			r_io_desc_close (desc);
		}
		return false;
	}
	// let the section refere to the map as a memory-map
	free (map->name);
	map->name = r_str_newf ("mmap.%s", sec->name);
	return true;
}

static void add_section(RCore *core, RBinSection *sec, ut64 addr, int fd) {
	if (sec->backing_fd > 0) {
		RIOMap *map = r_io_map_add (core->io, sec->backing_fd, R_PERM_RWX, 0LL, addr, sec->vsize);
		if (map) {
			free (map->name);
			map->name = r_str_newf ("unpack.%s", sec->name);
		} else {
			R_LOG_ERROR ("map failed!");
		}
		return;
	}

	if (!r_io_desc_get (core->io, fd) || UT64_ADD_OVFCHK (sec->size, sec->paddr) ||
			UT64_ADD_OVFCHK (sec->size, addr) || !sec->vsize) {
		return;
	}

	ut64 size = sec->vsize;
	const ut64 fdsize = r_io_fd_size (core->io, fd);
	const ut64 psize = (sec->paddr < fdsize)? R_MIN (sec->size, fdsize - sec->paddr): 0LL;
	// if there is some part of the section that needs to be zeroed by the loader
	// we add a null map that takes care of it
	if (sec->vsize > psize) {
		int oldfd = r_io_fd_get_current (core->io);
		size = psize;
		if (!io_create_mem_map (core->io, sec, addr + psize, sec->vsize - psize) || !size) {
			return;
		}
		if (oldfd != r_io_fd_get_current (core->io)) {
			r_io_use_fd (core->io, oldfd);
		}
	}
	// then we map the part of the section that comes from the physical file
	char *map_name = r_str_newf ("fmap.%s", sec->name);
	if (!map_name) {
		return;
	}
	r_name_filter (map_name, R_FLAG_NAME_SIZE);
	int perm = sec->perm;
	// workaround to force exec bit in text section
	if (sec->name &&  strstr (sec->name, "text")) {
		perm |= R_PERM_X;
	}
	RIOMap *map = r_io_map_add (core->io, fd, perm, sec->paddr, addr, size);
	if (map) {
		free (map->name);
		map->name = map_name;
	} else {
		free (map_name);
	}
}

struct io_bin_section_info_t {
	RBinSection *sec;
	ut64 addr;
	int fd;
};

/* Map Sections to Segments https://github.com/radareorg/radare2/issues/14647 */
static bool bin_map_sections_to_segments(RCore *core, PJ *pj, int mode) {
	RBin*bin = core->bin;
	RListIter *iter, *iter2;
	RBinSection *section = NULL, *segment = NULL;
	RList *sections = r_list_new ();
	RList *segments = r_list_new ();
	RList *tmp = r_bin_get_sections (bin);
	RTable *table = r_core_table_new (core, "segments");
	RTableColumnType *typeString = r_table_type ("string");

	r_table_add_column (table, typeString, "Segment", 0);
	r_table_add_column (table, typeString, "Section", 0);

	r_list_foreach (tmp, iter, section) {
		RList *list = section->is_segment? segments: sections;
		r_list_append (list, section);
	}

	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
		pj_o (pj);
	}

	r_list_foreach (segments, iter, segment) {
		RInterval segment_itv = (RInterval){segment->vaddr, segment->size};
		char *tmp2 = strdup ("");
		r_list_foreach (sections, iter2, section) {
			RInterval section_itv = (RInterval){section->vaddr, section->size};
			if (r_itv_begin (section_itv) >= r_itv_begin (segment_itv) && r_itv_end (section_itv) <= r_itv_end (segment_itv) && section->name[0]) {
				tmp2 = r_str_appendf (tmp2, "%s ", section->name);
			}
		}
		r_table_add_row (table, segment->name, tmp2, 0);
		if (IS_MODE_JSON (mode)) {
			pj_ks (pj, segment->name, tmp2);
		}
		free (tmp2);
	}

	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		pj_end (pj);
	}

	if (IS_MODE_NORMAL (mode)) {
		r_kons_printf (core->cons, "Section to Segment mapping:\n");
		char *s = r_table_tostring (table);
		r_kons_print (core->cons, s);
		free (s);
	}
	r_list_free (segments);
	r_list_free (sections);
	r_table_free (table);
	return true;
}

static bool bin_sections(RCore *core, PJ *pj, int mode, ut64 laddr, int va, ut64 at, const char *name, const char *chksum, bool print_segments) {
	char *str = NULL;
	RBinSection *section;
	RBinInfo *info = NULL;
	RListIter *iter;
	RTable *table = r_core_table_new (core, "sections");
	int i = 0;
	int fd = -1;
	bool printHere = false;
	RList *sections = r_bin_get_sections (core->bin);
#if LOAD_BSS_MALLOC
	const bool inDebugger = r_config_get_b (core->config, "cfg.debug");
#endif
	HtPP *dup_chk_ht = ht_pp_new0 ();
	bool ret = false;
	const char *type = print_segments? "segment": "section";
	bool segments_only = true;
	RList *io_section_info = NULL;
	ut64 bin_hashlimit = r_config_get_i (core->config, "bin.hashlimit");
	if (core->bin->cur == NULL) {
		if (pj) {
			pj_a (pj);
			pj_end (pj);
		}
		return false;
	}
	r_io_use_fd (core->io, core->bin->cur->fd);
	ut64 filesize = (core->io->desc) ? r_io_fd_size (core->io, core->io->desc->fd): 0;

	if (!dup_chk_ht) {
		r_table_free (table);
		return false;
	}

	if (chksum && *chksum == '.') {
		if (at == UT64_MAX) {
			at = core->addr;
		}
		printHere = true;
		chksum++;
	}
	char *hashtypes = filter_hash_string (chksum);
	if (IS_MODE_EQUAL (mode)) {
		int cols = r_cons_get_size (core->cons, NULL);
		RList *list = r_list_newf ((RListFree) r_listinfo_free);
		if (!list) {
			free (hashtypes);
			ht_pp_free (dup_chk_ht);
			r_table_free (table);
			return false;
		}
		RBinSection *s;
		r_list_foreach (sections, iter, s) {
			char humansz[8];
			if (print_segments != s->is_segment) {
				continue;
			}
			RInterval pitv = (RInterval){s->paddr, s->size};
			RInterval vitv = (RInterval){s->vaddr, s->vsize};
			r_num_units (humansz, sizeof (humansz), s->size);
			RListInfo *info = r_listinfo_new (s->name, pitv, vitv, s->perm, humansz);
			r_list_append (list, info);
		}
		RTable *table = r_core_table_new (core, "sections");
		r_table_visual_list (table, list, core->addr, -1, cols, core->io->va);
		bool show_table = true;
		if (core->table_query) {
			show_table = r_table_query (table, core->table_query);
		}
		if (show_table) {
			char *s = r_table_tostring (table);
			r_kons_print (core->cons, s);
			free (s);
		}
		r_table_free (table);
		r_list_free (list);
		goto out;
	}
	if (IS_MODE_JSON (mode)) {
		if (!printHere) {
			pj_a (pj);
		}
	} else if (IS_MODE_RAD (mode) && at == UT64_MAX) {
		r_kons_printf (core->cons, "fs %ss\n", type);
	} else if (IS_MODE_NORMAL (mode) && printHere) {
		r_kons_printf (core->cons, "Current section\n");
	} else if (IS_MODE_SET (mode)) {
		if (core && core->io->desc) {
			fd = core->io->desc->fd;
		}
		r_flag_space_set (core->flags, print_segments? R_FLAGS_FS_SEGMENTS: R_FLAGS_FS_SECTIONS);
	}
	if (IS_MODE_NORMAL (mode)) {
		if (hashtypes) {
			r_table_set_columnsf (table, "dXxXxsxsss",
				"nth", "paddr", "size", "vaddr", "vsize", "perm", "flags", hashtypes, "type", "name");
		} else {
			r_table_set_columnsf (table, "dXxXxsxss",
				"nth", "paddr", "size", "vaddr", "vsize", "perm", "flags", "type", "name");
		}
		// r_table_align (table, 0, R_TABLE_ALIGN_CENTER);
		r_table_align (table, 2, R_TABLE_ALIGN_RIGHT);
		r_table_align (table, 4, R_TABLE_ALIGN_RIGHT);
	}
	if (IS_MODE_SET (mode)) {
		r_list_foreach (sections, iter, section) {
			if (!section->is_segment) {
				segments_only = false;
				break;
			}
		}
		io_section_info = r_list_newf ((RListFree)free);
	}
	int plimit = filesize? R_MIN (filesize, bin_hashlimit): bin_hashlimit;
	r_list_foreach (sections, iter, section) {
		char perms[] = "----";
		int va_sect = va;

		if (va && !(section->perm & R_PERM_R)) {
			va_sect = VA_NOREBASE;
		}
		ut64 addr = rva (core->bin, section->paddr, section->vaddr, va_sect);
		ut64 size = va ? section->vsize : section->size;
		if (name && strcmp (section->name, name)) {
			continue;
		}
#if 0
		if (printHere && !(addr <= r->offset && r->offset < (addr + size))) {
			continue;
		}
#endif
		if (at != UT64_MAX && (!size || !is_in_range (at, addr, size))) {
			continue;
		}

		if (section->is_segment != print_segments) {
			continue;
		}
		// XXX use r_str_perm instead of doing it here imho
		if (section->perm & R_PERM_SHAR) {
			perms[0] = 's';
		}
		if (section->perm & R_PERM_R) {
			perms[1] = 'r';
		}
		if (section->perm & R_PERM_W) {
			perms[2] = 'w';
		}
		if (section->perm & R_PERM_X) {
			perms[3] = 'x';
		}
		const char *arch = NULL;
		int bits = 0;
		if (section->arch || section->bits) {
			arch = section->arch;
			bits = section->bits;
		}
		if (info) {
			if (!arch) {
				arch = info->arch;
			}
			if (!bits) {
				bits = info->bits;
			}
		}
		if (!arch) {
			arch = r_config_get (core->config, "asm.arch");
		}
		if (!bits) {
			bits = R_SYS_BITS;
		}
		if (IS_MODE_RAD (mode)) {
			char *fname = r_str_newf ("%s.%s", type, section->name);
			r_name_filter (fname, -1);
			r_kons_printf (core->cons, "'f %s 1 0x%08"PFMT64x"\n", fname, section->vaddr);
			free (fname);
		} else if (IS_MODE_SET (mode)) {
#if LOAD_BSS_MALLOC
			if (!strcmp (section->name, ".bss")) {
				// check if there's already a file opened there
				int loaded = 0;
				RListIter *iter;
				RIOMap *m;
				r_list_foreach (core->io->maps, iter, m) {
					if (m->from == addr) {
						loaded = 1;
					}
				}
				if (!loaded && !inDebugger) {
					r_core_cmdf (core, "on malloc://%d 0x%"PFMT64x, section->vsize, addr);
				}
			}
#endif
			if (core->bin->prefix) {
				str = r_str_newf ("%s.%s.%s", core->bin->prefix, type, name);
			} else {
				str = r_str_newf ("%s.%s", type, section->name);
			}
			r_name_filter (str, R_FLAG_NAME_SIZE);

			r_flag_set (core->flags, str, addr, size);
			R_FREE (str);

			if (!section->is_segment || segments_only) {
				char *pfx = core->bin->prefix;
				str = r_str_newf ("[%02d] %s %s size %" PFMT64d " named %s%s%s",
						i, perms, type, size,
						r_str_get (pfx), pfx? ".": "", section->name);
				r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, str);
				R_FREE (str);
			}
			if (section->add) {
				bool found;
				str = r_str_newf ("%" PFMT64x ".%" PFMT64x ".%" PFMT64x ".%" PFMT64x
							".%" PFMT32u ".%s.%" PFMT32u ".%d",
						section->paddr, addr, section->size,
						section->vsize, section->perm, section->name,
						core->bin->cur->id, fd);
				ht_pp_find (dup_chk_ht, str, &found);
				if (!found) {
					// can't directly add maps because they
					// need to be reversed, otherwise for
					// the way IO works maps would be shown
					// in reverse order
					struct io_bin_section_info_t *ibs = R_NEW (struct io_bin_section_info_t);
					if (!ibs) {
						R_LOG_ERROR ("Could not allocate memory");
						goto out;
					}
					ibs->sec = section;
					ibs->addr = addr;
					ibs->fd = fd;
					r_list_append (io_section_info, ibs);
					ht_pp_insert (dup_chk_ht, str, NULL);
				}
				R_FREE (str);
			}
		} else if (IS_MODE_SIMPLEST (mode)) {
			r_kons_printf (core->cons, "%s\n", section->name);
		} else if (IS_MODE_SIMPLE (mode)) {
			char *hashstr = NULL;
			if (hashtypes) {
				int datalen = section->size;
				if (datalen > 0 && datalen < plimit) {
					ut8 *data = malloc (datalen);
					if (!data) {
						goto out;
					}
					int dl = r_io_pread_at (core->io, section->paddr, data, datalen);
					if (dl == datalen) {
						hashstr = build_hash_string (pj, mode, hashtypes, data, datalen);
					} else if (core->bin->options.verbose) {
						R_LOG_ERROR ("Cannot read section at 0x%08"PFMT64x, section->paddr);
					}
					free (data);
				} else if (core->bin->options.verbose) {
					R_LOG_ERROR ("Section at 0x%08"PFMT64x" larger than bin.hashlimit", section->paddr);
				}
			}
			r_kons_printf (core->cons, "0x%08"PFMT64x" 0x%08"PFMT64x" %s %s%s%s\n",
				addr, addr + section->size,
				perms,
				r_str_get (hashstr), hashstr ? " " : "",
				section->name
			);
			free (hashstr);
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "name", section->name);
			pj_kN (pj, "size", section->size);
			pj_kN (pj, "vsize", section->vsize);
			if (R_STR_ISNOTEMPTY (section->type)) {
				pj_ks (pj, "type", section->type);
			}
			pj_ks (pj, "perm", perms);
			pj_kN (pj, "flags", section->flags);
			if (hashtypes && (int)section->size > 0) {
				int datalen = section->size;
				if (datalen > 0 && datalen < plimit) {
					ut8 *data = malloc (datalen);
					if (!data) {
						goto out;
					}
					int dl = r_io_pread_at (core->io, section->paddr, data, datalen);
					if (dl == datalen) {
						free (build_hash_string (pj, mode, hashtypes, data, datalen));
					} else if (core->bin->options.verbose) {
						R_LOG_ERROR ("Cannot read section at 0x%08"PFMT64x, section->paddr);
					}
					free (data);
				} else {
					R_LOG_WARN ("Section at 0x%08"PFMT64x" larger than bin.hashlimit", section->paddr);
				}
			}
			pj_kn (pj, "paddr", section->paddr);
			pj_kn (pj, "vaddr", addr);
			pj_end (pj);
		} else {
			char *hashstr = NULL, str[128];
			if (hashtypes && section->size > 0) {
				int datalen = section->size;
				if (datalen > 0 && datalen < plimit) {
					ut8 *data = calloc (datalen, 1);
					if (!data) {
						goto out;
					}
					int dl = r_io_pread_at (core->io, section->paddr, data, datalen);
					if (dl == datalen) {
						hashstr = build_hash_string (pj, mode, hashtypes, data, datalen);
					} else if (core->bin->options.verbose) {
						hashstr = strdup ("*error*");
						R_LOG_WARN ("Cannot read section at 0x%08"PFMT64x, section->paddr);
					}
					free (data);
				} else {
					R_LOG_WARN ("Section at 0x%08"PFMT64x" larger than bin.hashlimit", section->paddr);
				}
			}
			if (section->arch || section->bits) {
				snprintf (str, sizeof (str), "arch=%s bits=%d ",
					r_str_get (arch), bits);
			} else {
				str[0] = 0;
			}
			r_strf_buffer (128);
			const char *section_name = (core->bin->prefix)
				? r_strf ("%s.%s", core->bin->prefix, section->name)
				: section->name;
			// seems like asm.bits is a bitmask that seems to be always 32,64
			// const char *asmbits = r_str_sysbits (bits);
			const char *stype = (section->type)? section->type: "";
			if (R_STR_ISEMPTY (stype)) {
				stype = print_segments? "MAP": "----";
			}
			if (hashtypes) {
				r_table_add_rowf (table, "dXxXxsxsss", i,
					(ut64)section->paddr, (ut64)section->size,
					(ut64)addr, (ut64)section->vsize,
					perms, section->flags, r_str_get (hashstr), stype, section_name);
			} else {
				r_table_add_rowf (table, "dXxXxsxss", i,
					(ut64)section->paddr, (ut64)section->size,
					(ut64)addr, (ut64)section->vsize,
					perms, section->flags, stype, section_name);
			}
			free (hashstr);
		}
		i++;
		if (printHere) {
			break;
		}
	}
	if (IS_MODE_SET (mode) && !r_io_desc_is_dbg (core->io->desc)) {
		RListIter *it;
		struct io_bin_section_info_t *ibs;
		r_list_foreach_prev (io_section_info, it, ibs) {
			add_section (core, ibs->sec, ibs->addr, ibs->fd);
		}
	}
	r_list_free (io_section_info);
	io_section_info = NULL;
	if (IS_MODE_JSON (mode) && !printHere) {
		pj_end (pj);
	}
	// run the formats now
	r_list_foreach (sections, iter, section) {
		if (R_STR_ISNOTEMPTY (section->format)) {
			// This is damn slow if section vsize is HUGE
			if (section->vsize < 1024 * 1024 * 2) {
				R_LOG_DEBUG ("(section %s) %s @ 0x%" PFMT64x, section->name, section->format, section->vaddr);
				r_core_cmd_call_at (core, section->vaddr, section->format);
			}
		}
	}

	ret = true;
out:
	if (IS_MODE_NORMAL (mode)) {
		bool show_table = true;
		if (core->table_query) {
			show_table = r_table_query (table, core->table_query);
		}
		if (show_table) {
			char *s = r_table_tostring (table);
			r_kons_print (core->cons, s);
			free (s);
		}
	}
	free (hashtypes);
	r_table_free (table);
	ht_pp_free (dup_chk_ht);
	r_list_free (io_section_info);
	return ret;
}

static bool bin_fields(RCore *core, PJ *pj, int mode, int va) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	RListIter *iter;
	RBinField *field;
	RBin *bin = core->bin;
	RBinObject *o = r_bin_cur_object (bin);
	if (!o) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}
	RList *fields = o->fields;
	if (!fields) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		// load header types
		r_core_bin_export_info (core, R_MODE_SET);
		pj_a (pj);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "'fs+header");
	}
	r_list_foreach (fields, iter, field) {
		const bool haveComment = R_STR_ISNOTEMPTY (field->comment);
		ut64 v = field->value;
		if (v == UT64_MAX) {
			v = 0;
		}
		ut64 addr = rva (bin, field->paddr, field->vaddr, va);

		const char *cmt = field->comment;
		if (IS_MODE_RAD (mode)) {
			const char *fname = r_bin_name_tostring2 (field->name, 'f');
			r_kons_printf (core->cons, "'f header.%s 1 0x%08"PFMT64x"\n", fname, addr);
			if (field->value != 0 && field->value != UT64_MAX) {
				r_kons_printf (core->cons, "'f header.%s.value 1 0x%08"PFMT64x"\n", fname, field->value);
			}
			if (R_STR_ISNOTEMPTY (cmt)) {
				char *e = sdb_encode ((const ut8*)cmt, -1);
				r_kons_printf (core->cons, "CCu base64:%s @ 0x%"PFMT64x"\n", e, addr);
				free (e);
				char *f = r_name_filter_shell (field->format);
				r_kons_printf (core->cons, "Cf %d %s @ 0x%"PFMT64x"\n", field->size, f, addr);
				free (f);
			}
			if (field->size > 0) {
				if (field->size == 8) {
					r_kons_printf (core->cons, "Cd8 @ 0x%"PFMT64x"\n", addr);
				} else if (field->size == 4) {
					r_kons_printf (core->cons, "Cd4 @ 0x%"PFMT64x"\n", addr);
				}
			}
			if (!field->format_named && R_STR_ISNOTEMPTY (field->format)) {
				r_kons_printf (core->cons, "pf.%s %s\n", fname, field->format);
			}
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "name", r_bin_name_tostring2 (field->name, pref));
			pj_kN (pj, "vaddr", field->vaddr);
			pj_kN (pj, "paddr", field->paddr);
			if (field->size > 0) {
				pj_kN (pj, "size", field->size);
			}
			if (v) {
				pj_kN (pj, "value", v);
			}
			if (R_STR_ISNOTEMPTY (cmt)) {
				// TODO: filter comment before json
				pj_ks (pj, "comment", cmt);
			}
			if (R_STR_ISNOTEMPTY (field->format)) {
				// TODO: filter comment before json
				pj_ks (pj, "format", field->format);
			}
			char *o = r_core_cmd_strf (core, "pfj%c%s@0x%"PFMT64x,
				field->format_named ? '.' :  ' ', field->format, field->vaddr);
			if (R_STR_ISNOTEMPTY (o)) {
				r_str_trim_tail (o);
				pj_k (pj, "pf");
				pj_j (pj, o); // XXX  if json is invalid this may fuck the things
			}
			free (o);
			pj_end (pj);
		} else if (IS_MODE_NORMAL (mode)) {
			r_kons_printf (core->cons, "0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s%s%s",
				field->vaddr, field->paddr, v, r_bin_name_tostring2 (field->name, pref),
				haveComment? "; ": "",
				haveComment? cmt: "");
			r_cons_newline (core->cons);
		} else if (IS_MODE_SET (mode)) {
			// nothing
		} else {
			// quiet
			r_kons_printf (core->cons, "0x%08"PFMT64x" 0x%08"PFMT64x" %s\n",
				field->vaddr, v, r_bin_name_tostring2 (field->name, pref));
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "'fs-");
	}

	return true;
}

static char *get_rp(const char *rtype) {
	char *rp = NULL;
	switch (rtype[0]) {
	case 'v':
		rp = strdup ("void");
		break;
	case 'c':
		rp = strdup ("char");
		break;
	case 'i':
		rp = strdup ("int");
		break;
	case 's':
		rp = strdup ("short");
		break;
	case 'l':
		rp = strdup ("long");
		break;
	case 'q':
		rp = strdup ("long long");
		break;
	case 'C':
		rp = strdup ("unsigned char");
		break;
	case 'I':
		rp = strdup ("unsigned int");
		break;
	case 'S':
		rp = strdup ("unsigned short");
		break;
	case 'L':
		rp = strdup ("unsigned long");
		break;
	case 'Q':
		rp = strdup ("unsigned long long");
		break;
	case 'f':
		rp = strdup ("float");
		break;
	case 'd':
		rp = strdup ("double");
		break;
	case 'D':
		rp = strdup ("long double");
		break;
	case 'B':
		rp = strdup ("bool");
		break;
	case '#':
		rp = strdup ("CLASS");
		break;
	default:
		rp = strdup ("unknown");
		break;
	}
	return rp;
}

static bool bin_trycatch(RCore *core, PJ *pj, int mode) {
	RBinFile *bf = r_bin_cur (core->bin);
	RListIter *iter;
	RBinTrycatch *tc;
	RList *trycatch = r_bin_file_get_trycatch (bf);
	int idx = 0;
	// fixme: json mode
	r_list_foreach (trycatch, iter, tc) {
		r_kons_printf (core->cons, "f try.%d.%"PFMT64x".from=0x%08"PFMT64x"\n", idx, tc->source, tc->from);
		r_kons_printf (core->cons, "f try.%d.%"PFMT64x".to=0x%08"PFMT64x"\n", idx, tc->source, tc->to);
		r_kons_printf (core->cons, "f try.%d.%"PFMT64x".catch=0x%08"PFMT64x"\n", idx, tc->source, tc->handler);
		idx++;
	}
	return true;
}

// TODO: move this into r.bin.demangle
// https://nshipster.com/type-encodings/
static char *objc_type_toc(const char *objc_type) {
	if (!objc_type) {
		return strdup ("void*");
	}
	if (*objc_type == '^' && objc_type[1] == '{') {
		char *a = strdup (objc_type + 2);
		char *b = strchr (a, '>');
		if (b) {
			*b = 0;
		}
		a[strlen (a) - 1] = 0;
		return a;
	}
	if (*objc_type == '<') {
		char *a = strdup (objc_type + 1);
		char *b = strchr (a, '>');
		if (b) {
			*b = 0;
		}
		return a;
	}
	if (!strcmp (objc_type, "f")) { return strdup ("float"); }
	if (!strcmp (objc_type, "d")) { return strdup ("double"); }
	if (!strcmp (objc_type, "i")) { return strdup ("int"); }
	if (!strcmp (objc_type, "s")) { return strdup ("short"); }
	if (!strcmp (objc_type, "l")) { return strdup ("long"); }
	if (!strcmp (objc_type, "L")) { return strdup ("unsigned long"); }
	if (!strcmp (objc_type, "*")) { return strdup ("char*"); }
	if (!strcmp (objc_type, "c")) { return strdup ("bool"); }
	if (!strcmp (objc_type, "v")) { return strdup ("void"); }
	if (!strcmp (objc_type, "#")) { return strdup ("class"); }
	if (!strcmp (objc_type, "B")) { return strdup ("cxxbool"); }
	if (!strcmp (objc_type, "Q")) { return strdup ("uint64_t"); }
	if (!strcmp (objc_type, "q")) { return strdup ("long long"); }
	if (!strcmp (objc_type, "C")) { return strdup ("uint8_t"); }
	if (strlen (objc_type) == 1) {
		R_LOG_WARN ("Unknown objc type '%s'", objc_type);
	}
	if (r_str_startswith (objc_type, "@\"")) {
		char *s = r_str_newf ("struct %s", objc_type + 2);
		s[strlen (s) - 1] = '*';
		return s;
	}
	return strdup (objc_type);
}

static char *objc_name_toc(const char *objc_name) {
	const char *n = r_str_lchr (objc_name, ')');
	char *s = strdup (n? n + 1: objc_name);
	char *p = strchr (s, '(');
	if (p) {
		*p = 0;
	}
	return s;
}

static void classdump_c(RCore *core, RBinClass *c) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	r_kons_printf (core->cons, "typedef struct {\n");
	RListIter *iter2;
	RBinField *f;
	bool is_objc = false;
	r_list_foreach (c->fields, iter2, f) {
		if (f->name) {
			const char *fn = r_bin_name_tostring2 (f->name, pref);
			const char *ft = f->type? r_bin_name_tostring2 (f->type, pref): NULL;
			char *n = objc_name_toc (fn);
			char *t = ft? objc_type_toc (ft): NULL;
			if (f->offset < 32 && !t) {
				free (n);
				continue;
			}
			if (R_STR_ISEMPTY (t)) {
				free (t);
				t = strdup ("void*");
			}
			if (!is_objc && !strcmp (n, "isa")) {
				is_objc = true;
			}
			r_str_replace_char (n, ':', '_');
			r_str_replace_char (n, '.', '_');
			r_kons_printf (core->cons, "    %s %s; // 0x%x\n", t, n, f->offset);
			free (t);
			free (n);
		}
	}
	const char *klass_name = r_bin_name_tostring2 (c->name, pref);
	if (is_objc) {
		r_kons_printf (core->cons, "} objc_class_%s;\n", klass_name);
	} else {
		r_kons_printf (core->cons, "} class_%s;\n", klass_name);
	}
}

static void classdump_cxx(RCore *core, RBinClass *c) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	const char *klass_name = r_bin_name_tostring2 (c->name, pref);
	r_kons_printf (core->cons, "class %s {\n", klass_name);
	RListIter *iter2;
	RBinField *f;
	bool is_objc = false;
	r_list_foreach (c->fields, iter2, f) {
		if (f->name) {
			const char *fn = r_bin_name_tostring2 (f->name, pref);
			const char *ft = r_bin_name_tostring2 (f->type, pref);
			char *n = objc_name_toc (fn);
			char *t = ft? objc_type_toc (ft): NULL;
			if (f->offset < 32 && !t) {
				free (n);
				continue;
			}
			if (R_STR_ISEMPTY (t)) {
				free (t);
				t = strdup ("void*");
			}
			if (!is_objc && !strcmp (n, "isa")) {
				is_objc = true;
			}
			r_str_replace_char (n, ':', '_');
			r_str_replace_char (n, '.', '_');
			r_kons_printf (core->cons, "    %s %s; // 0x%x\n", t, n, f->offset);
			free (t);
			free (n);
		}
	}
	r_cons_println (core->cons, "};\n");
}

static void classdump_objc(RCore *core, RBinClass *c) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	const char *cname = r_bin_name_tostring2 (c->name, pref);
	if (c->super) {
		int n = 0;
		r_kons_printf (core->cons, "@interface %s :", cname);
		RBinName *bn;
		RListIter *iter;
		r_list_foreach (c->super, iter, bn) {
			const char *sk = r_bin_name_tostring2 (bn, pref);
			switch (n) {
			case 0: r_kons_printf (core->cons, " %s", sk); break;
			case 1: r_kons_printf (core->cons, "< %s", sk); break;
			default: r_kons_printf (core->cons, ", %s", sk); break;
			}
		}
		if (r_list_length (c->super) > 1) {
			r_kons_printf (core->cons, " >\n{\n");
		} else {
			r_kons_printf (core->cons, "\n{\n");
		}
	} else {
		r_kons_printf (core->cons, "@interface %s\n{\n", cname);
	}
	RListIter *iter2, *iter3;
	RBinField *f;
	RBinSymbol *sym;
	r_list_foreach (c->fields, iter2, f) {
		if (f->name) { //  && r_regex_match ("ivar","e", f->name)) {
			const char *ks = r_bin_field_kindstr (f);
			const char *fn = r_bin_name_tostring2 (f->name, pref);
			if (f->type) {
				const char *ft = r_bin_name_tostring2 (f->type, pref);
				r_kons_printf (core->cons, "  %s %s::(%s)%s\n", ft, cname, ks, fn);
			} else {
				r_kons_printf (core->cons, "  isa %s::(%s)%s\n", cname, ks, fn);
			}
		}
	}
	r_cons_println (core->cons, "}");
	r_list_foreach (c->methods, iter3, sym) {
		const char *sname = r_bin_name_tostring2 (sym->name, pref);
		char *rp = NULL;
		if (sym->rtype && sym->rtype[0] != '@') {
			rp = get_rp (sym->rtype);
		} else if (sym->type) {
			rp = strdup ("id");
		}
		if (rp) {
			const char *sign = r_str_startswith (sym->type, R_BIN_TYPE_METH_STR)? "+": "-";
			r_kons_printf (core->cons, "%s (%s) %s\n", sign, rp, sname);
			free (rp);
		}
	}
	r_kons_printf (core->cons, "@end\n");
}

static void classdump_swift(RCore *core, RBinClass *c) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	RBinField *f;
	RListIter *iter;
	RBinSymbol *sym;
	const char *cname = r_bin_name_tostring2 (c->name, pref);
	char *pn = strdup (cname);
	char *cn = (char *)r_str_rchr (pn, NULL, '/');
	if (cn) {
		*cn++ = 0;
		r_str_replace_char (pn, '/', '.');
	}
	char *klassname = cn? cn: pn;
	if (cn) {
		r_kons_printf (core->cons, "// namespace %s\n\n", pn);
	}
	if (c->lang == R_BIN_LANG_OBJC) {
		r_kons_printf (core->cons, "@objc\n");
	}
	r_kons_printf (core->cons, "class %s ", klassname);
	if (!r_list_empty (c->super)) {
		RBinName *bn;
		r_list_foreach (c->super, iter, bn) {
			r_kons_printf (core->cons, ": %s", r_bin_name_tostring2 (bn, 'd')); // TODO pref));
		}
		r_kons_printf (core->cons, " ");
	}
	r_kons_printf (core->cons, "{\n");
	free (pn);
	r_list_foreach (c->fields, iter, f) {
		if (!f->name) {
			continue;
		}
		const char *var = r_bin_field_kindstr (f);
		const char *fname = r_bin_name_tostring2 (f->name, pref);
		const char *ftype = r_bin_name_tostring2 (f->type, pref);
		if (R_STR_ISNOTEMPTY (ftype)) {
			r_kons_printf (core->cons, "  %s %s : %s;\n", var, fname, ftype);
		} else {
			r_kons_printf (core->cons, "  %s %s;\n", var, fname);
		}
	}
	r_list_foreach (c->methods, iter, sym) {
		const char *mn = r_bin_name_tostring2 (sym->name, pref);
		const char *ms = strstr (mn, "method.");
		if (ms) {
			mn = ms + strlen ("method.");
		}
		r_kons_printf (core->cons, "  func %s", mn? mn: ms? ms: "method");
		if (!strchr (mn, '(')) {
			r_kons_printf (core->cons, "()");
		}
		r_kons_printf (core->cons, " {}  // 0x%08"PFMT64x"\n", sym->vaddr);
	}
	r_kons_printf (core->cons, "}\n");
}

static void classdump_java(RCore *core, RBinClass *c) {
	RBinField *f;
	RListIter *iter;
	RBinSymbol *sym;
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	const char *cname = r_bin_name_tostring2 (c->name, pref);
	char *pn = strdup (cname);
	char *cn = (char *)r_str_rchr (pn, NULL, '/');
	if (cn) {
		*cn = 0;
		cn++;
		r_str_replace_char (pn, '/', '.');
	} else {
		char *dot = (char *)r_str_rchr (pn, NULL, '.');
		cn = dot? dot + 1: pn;
	}
	r_kons_printf (core->cons, "package %s;\n\n", pn);
	r_kons_printf (core->cons, "public class %s {\n", cn);
	free (pn);
	r_list_foreach (c->fields, iter, f) {
		if (f->name && f->kind == R_BIN_FIELD_KIND_VARIABLE) {
			const char *fname = r_bin_name_tostring2 (f->name, pref);
			const char *tp = r_bin_name_tostring2 (f->type, pref);
			r_kons_printf (core->cons, "  public %s %s\n", R_STR_ISNOTEMPTY (tp)? tp: "Object", fname);
		}
	}
	r_list_foreach (c->methods, iter, sym) {
		const char *mn = r_bin_name_tostring2 (sym->name, pref);
		const char *ms = strstr (mn, "method.");
		if (ms) {
			mn = ms + strlen ("method.");
		}
		r_kons_printf (core->cons, "  public %s ();\n", mn);
	}
	r_kons_printf (core->cons, "}\n\n");
}

static bool is_swift(RBinFile *bf) {
	return (bf->bo->lang == R_BIN_LANG_SWIFT);
}

static bool is_javaish(RBinFile *bf) {
	if (bf->bo->lang == R_BIN_LANG_JAVA) {
		return true;
	}
	if (bf->bo->info && bf->bo->info->lang && strstr (bf->bo->info->lang, "dalvik")) {
		return true;
	}
	return false;
}

static bool bin_classes(RCore *core, PJ *pj, int mode) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	RListIter *iter, *iter2, *iter3;
	RBinSymbol *sym;
	RBinClass *c;
	RBinField *f;
	RList *cs = r_bin_get_classes (core->bin);
	if (!cs) {
		if (IS_MODE_JSON (mode)) {
			pj_a (pj);
			pj_end (pj);
			return true;
		}
		return false;
	}
	// XXX: support for classes is broken and needs more love
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	} else if (IS_MODE_SET (mode)) {
		r_flag_space_set (core->flags, R_FLAGS_FS_CLASSES);
	} else if (IS_MODE_RAD (mode) && !IS_MODE_CLASSDUMP (mode)) {
		r_cons_println (core->cons, "fs classes");
	}
	const bool bin_filter = r_config_get_b (core->config, "bin.filter");
	r_list_foreach (cs, iter, c) {
		const char *cname = r_bin_name_tostring2 (c->name, pref);
		const char *rname = r_bin_name_tostring2 (c->name, 'o');
		if (!c || R_STR_ISEMPTY (cname)) {
			continue;
		}
		char *name = strdup (cname);
		r_name_filter (name, -1);
		ut64 at_min = UT64_MAX;
		ut64 at_max = 0LL;

		r_list_foreach (c->methods, iter2, sym) {
			if (sym->vaddr) {
				if (sym->vaddr < at_min) {
					at_min = sym->vaddr;
				}
				if (sym->vaddr + sym->size > at_max) {
					at_max = sym->vaddr + sym->size;
				}
			}
		}
		if (at_min == UT64_MAX) {
			at_min = c->addr;
			at_max = c->addr; // XXX + size?
		}

		if (IS_MODE_SET (mode)) {
			r_strf_var (classname, 256, "class.%s", name);
			r_flag_set (core->flags, classname, c->addr, 1);
			r_list_foreach (c->methods, iter2, sym) {
				const char *sym_name = r_bin_name_tostring (sym->name);
				// char *mflags = r_core_bin_attr_tostring (core, sym->attr, mode);
				char *mflags = r_bin_attr_tostring (sym->attr, false);
				r_str_replace_char (mflags, ' ', '.');
				// XXX probably access flags should not be part of the flag name
				r_strf_var (method, 256, "method%s%s.%s.%s", R_STR_ISEMPTY (mflags)? "":".", mflags, cname, sym_name);
				R_FREE (mflags);
				r_name_filter (method, -1);
				r_flag_set (core->flags, method, sym->vaddr, 1);
			}
			r_list_foreach (c->fields, iter2, f) {
				const char *fname = r_bin_name_tostring2 (f->name, pref);
				const char *kind = r_bin_field_kindstr (f);
				// XXX remove 'field' and just use kind?
				char *fn = r_str_newf ("field.%s.%s.%s", classname, kind, fname);
				ut64 at = f->vaddr;
				r_flag_set (core->flags, fn, at, 1);
				free (fn);
			}
		} else if (IS_MODE_SIMPLEST (mode)) {
			r_kons_printf (core->cons, "%s\n", cname);
		} else if (IS_MODE_SIMPLE (mode)) {
			char *supers = csv_supers (c->super);
			r_kons_printf (core->cons, "0x%08"PFMT64x" [0x%08"PFMT64x" - 0x%08"PFMT64x"] %s %s%s%s\n",
				c->addr, at_min, at_max, r_bin_lang_tostring (c->lang), cname, *supers ? " " : "", supers);
			free (supers);
		} else if (IS_MODE_CLASSDUMP (mode)) {
			if (c) {
				const char *vlang = r_config_get (core->config, "bin.lang");
				r_str_var (lang, 16, vlang);
				if (*lang) {
					if (!strcmp (lang, "java") || !strcmp (lang, "kotlin")) {
						classdump_java (core, c);
					} else if (!strcmp (lang, "swift")) {
						classdump_swift (core, c);
					} else if (!strcmp (lang, "cxx") || !strcmp (lang, "c++")) {
						classdump_cxx (core, c);
					} else if (!strcmp (lang, "c")) {
						classdump_c (core, c);
					} else if (r_str_startswith (lang, "objc")) {
						classdump_objc (core, c);
					} else {
						classdump_c (core, c);
					}
				} else {
					RBinFile *bf = r_bin_cur (core->bin);
					if (bf && bf->bo) {
						if (IS_MODE_RAD (mode)) {
							classdump_c (core, c);
						} else if (mode == 'O') {
							classdump_objc (core, c);
						} else if (is_javaish (bf) || mode == 'J') {
							classdump_java (core, c);
						} else if (is_swift (bf) || mode == 'S') {
							classdump_swift (core, c);
						} else {
							classdump_objc (core, c);
						}
					} else {
						classdump_c (core, c);
					}
				}
			}
		} else if (IS_MODE_RAD (mode)) {
			char *n = r_name_filter_shell (name);
			r_kons_printf (core->cons, "'f class.%s = 0x%"PFMT64x"\n", n, at_min);
			if (c->super) {
				const char *cn = cname;
				RListIter *iter;
				RBinName *bn;
				r_list_foreach (c->super, iter, bn) {
					char *fsk = strdup (r_bin_name_tostring2 (bn, pref));
					r_name_filter (fsk, -1);
					r_kons_printf (core->cons, "'f super.%s.%s = %d\n", cn, fsk, c->index);
					free (fsk);
				}
			}
			r_list_foreach (c->methods, iter2, sym) {
				char *mflags = r_bin_attr_tostring (sym->attr, false);
				r_str_replace_char (mflags, ' ', '.');
				const char *n = cname; //  r_name_filter_shell (cname);
				char *sn = r_bin_name_tostring (sym->name); //r_name_filter_shell (sym->name); // symbol contains classname
				const char *predot = R_STR_ISNOTEMPTY (mflags)? ".": "";
				char *cmd = r_str_newf ("'f method.%s%s%s.%s = 0x%"PFMT64x"\n", n, predot, mflags, sn, sym->vaddr);
				// free (n);
				// free (sn);
				if (cmd) {
					// use namefilter thing to create the right flag
					r_str_replace_char (cmd, ' ', '_');
					if (strlen (cmd) > 2) {
						cmd[2] = ' ';
					}
					char *eq = (char *)r_str_rchr (cmd, NULL, '=');
					if (eq && eq != cmd) {
						eq[-1] = eq[1] = ' ';
					}
					r_str_replace_char (cmd, '\n', 0);
					r_kons_printf (core->cons, "%s\n", cmd);
					free (cmd);
				}
				R_FREE (mflags);
			}
			r_list_foreach (c->fields, iter2, f) {
				const char *kind = r_bin_field_kindstr (f);
				const char *fname = r_bin_name_tostring2 (f->name, pref);
				char *fn = r_str_newf ("field.%s.%s.%s", cname, kind, fname);
				r_name_filter (fn, -1);
				ut64 at = f->vaddr; //  sym->vaddr + (f->vaddr &  0xffff);
				r_kons_printf (core->cons, "'f %s = 0x%08"PFMT64x"\n", fn, at);
				free (fn);
			}

			// C struct
			r_kons_printf (core->cons, "'td struct %s {", cname);
			if (r_list_empty (c->fields)) {
				// XXX workaround because we cant register empty structs yet
				// XXX https://github.com/radareorg/radare2/issues/16342
				r_kons_printf (core->cons, " char empty[0];");
			} else {
				r_list_foreach (c->fields, iter2, f) {
					const char *fn = r_bin_name_tostring (f->name);
					const char *tn = f->type? r_bin_name_tostring (f->type): NULL;
					char *n = objc_name_toc (fn);
					char *t = objc_type_toc (tn);
					if (R_STR_ISEMPTY (t)) {
						free (t);
						t = strdup ("void* ");
					}
					r_kons_printf (core->cons, " %s %s;", t, n);
					free (t);
					free (n);
				}
			}
			r_kons_printf (core->cons, "};\n");
			free (n);
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "classname", cname);
			if (rname && rname != cname && strcmp (cname, rname)) {
				pj_ks (pj, "rawclassname", rname);
			}
			pj_kN (pj, "addr", c->addr);
			const char *lang = r_bin_lang_tostring (c->lang);
			if (lang && *lang != '?') {
				pj_ks (pj, "lang", lang);
			}
			pj_ki (pj, "index", c->index);
			if (c->super) {
				if (c->visibility_str) {
					pj_ks (pj, "visibility", c->visibility_str);
				}
				RListIter *iter;
				pj_ka (pj, "super");
				RBinName *bn;
				r_list_foreach (c->super, iter, bn) {
#if 0
					pj_o (pj);
					if (bn->name) {
						pj_ks (pj, "name", bn->name);
					}
					if (bn->oname) {
						pj_ks (pj, "rawname", bn->oname);
					}
					pj_end (pj);
#else
					pj_s (pj, r_bin_name_tostring (bn));
#endif
				}
				pj_end (pj);

				pj_ka (pj, "rawsuper");
				r_list_foreach (c->super, iter, bn) {
					pj_s (pj, bn->oname);
				}
				pj_end (pj);
			}
			if (!r_list_empty (c->methods)) {
				pj_ka (pj, "methods");
				r_list_foreach (c->methods, iter2, sym) {
					pj_o (pj);
					const char *rname = r_bin_name_tostring2 (sym->name, 'o');
					const char *sname = r_bin_name_tostring2 (sym->name, 'd');
					if (sname == rname || !strcmp (sname, rname)) {
						rname = NULL;
					}
					pj_ks (pj, "name", sname);
					RFlagItem *fi = r_flag_get_at (core->flags, sym->vaddr, false);
					if (fi) {
						pj_ks (pj, "flag", fi->realname? fi->realname: fi->name);
					}
					if (bin_filter) {
						#if 0
							// XXX SUPER SLOW and probably unnecessary
							char *s = r_core_cmd_strf (core, "isqq.@0x%08"PFMT64x"@e:bin.demangle=%d", sym->vaddr, r_config_get_b (core->config, "bin.demangle"));
							r_str_trim (s);
							if (R_STR_ISNOTEMPTY (s)) {
								pj_ks (pj, "realname", s);
							}
							free (s);
						#endif
					}
					if (sym->attr) {
						char *mflags = r_core_bin_attr_tostring (core, sym->attr, mode);
						pj_k (pj, "flags");
						pj_j (pj, mflags);
						free (mflags);
					}
					if (rname) {
						pj_ks (pj, "rawname", rname);
					}
					const char *lang = r_bin_lang_tostring (sym->lang);
					if (lang && *lang != '?') {
						pj_ks (pj, "lang", lang);
					}
					pj_kN (pj, "addr", sym->vaddr);
					pj_end (pj);
				}
				pj_end (pj);
			}
			if (!r_list_empty (c->fields)) {
				pj_ka (pj, "fields");
				r_list_foreach (c->fields, iter3, f) {
					pj_o (pj);
					pj_ks (pj, "name", r_bin_name_tostring2 (f->name, pref));
					pj_ks (pj, "kind", r_bin_field_kindstr (f));
					const char *type = f->type? r_bin_name_tostring2 (f->type, pref): NULL;
					if (R_STR_ISNOTEMPTY (type)) {
						pj_ks (pj, "type", type);
					}
					if (f->attr) {
						char *mflags = r_core_bin_attr_tostring (core, f->attr, mode);
						pj_k (pj, "attr");
						pj_j (pj, mflags);
						free (mflags);
					}
					pj_kN (pj, "addr", f->vaddr);
					pj_end (pj);
				}
				pj_end (pj);
			}
			pj_end (pj);
		} else {
			int m = 0;
			const char *cl = r_bin_lang_tostring (c->lang);
			r_kons_printf (core->cons, "0x%08"PFMT64x" [0x%08"PFMT64x" - 0x%08"PFMT64x"] %6"PFMT64d" %s class %d %s",
				c->addr, at_min, at_max, (at_max - at_min), cl, c->index, cname);
			if (r_list_empty (c->super)) {
				r_cons_newline (core->cons);
			} else {
				char *csv = csv_supers (c->super);
				if (r_str_startswith (csv, "_T")) {
					R_LOG_WARN ("undemangled symbol, maybe good to fix in rbin instead of core");
					char *dsuper = r_bin_demangle (core->bin->cur, csv, csv, 0, false);
					r_kons_printf (core->cons, " :: %s\n", dsuper);
					free (dsuper);
				} else {
					r_kons_printf (core->cons, " :: %s\n", csv);
				}
				free (csv);
			}
			r_list_foreach (c->methods, iter2, sym) {
				char *mflags = r_core_bin_attr_tostring (core, sym->attr, mode);
				const char *ls = r_bin_lang_tostring (sym->lang);
				const char *sname = r_bin_name_tostring2 (sym->name, pref);
				r_kons_printf (core->cons, "0x%08"PFMT64x" %s %8s %3d %s %s\n",
					sym->vaddr, ls? ls: "?", "method", m, mflags, sname);
				R_FREE (mflags);
				m++;
			}
			m = 0;
			const char *ls = r_bin_lang_tostring (c->lang);
			r_list_foreach (c->fields, iter3, f) {
				char *mflags = r_core_bin_attr_tostring (core, f->attr, mode);
				const char *ks = r_bin_field_kindstr (f);
				r_kons_printf (core->cons, "0x%08"PFMT64x" %s %8s %3d %s %s\n",
					f->vaddr, ls, ks, m, mflags, r_bin_name_tostring2 (f->name, pref));
				m++;
				free (mflags);
			}
		}
		free (name);
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}

	return true;
}

static bool bin_size(RCore *core, PJ *pj, int mode) {
	ut64 size = r_bin_get_size (core->bin);
	if (IS_MODE_SIMPLE (mode)) {
		r_kons_printf (core->cons, "%"PFMT64u"\n", size);
	} else if (IS_MODE_JSON (mode)) {
		pj_n (pj, size);
	} else if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "f bin_size @ %"PFMT64u"\n", size);
	} else if (IS_MODE_SET (mode)) {
		r_core_cmdf (core, "f bin_size @ %"PFMT64u, size);
	} else {
		r_kons_printf (core->cons, "%"PFMT64u"\n", size);
	}
	return true;
}

static bool bin_libs(RCore *core, PJ *pj, int mode) {
	RListIter *iter;
	char* lib;

	RList *libs = r_bin_get_libs (core->bin);
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	} else {
		if (!libs) {
			return false;
		}
	}
	r_list_foreach (libs, iter, lib) {
		if (IS_MODE_SET (mode)) {
			// Nothing to set.
			// TODO: load libraries with iomaps?
		} else if (IS_MODE_RAD (mode)) {
			r_kons_printf (core->cons, "'CCa entry0 %s\n", lib);
		} else if (IS_MODE_JSON (mode)) {
			pj_s (pj, lib);
		} else {
			// simple and normal print mode
			r_cons_println (core->cons, lib);
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
	return true;
}

static void bin_mem_print(RCore *core, PJ *pj, RList *mems, int perms, int depth, int mode) {
	RBinMem *mem;
	RListIter *iter;
	if (!mems) {
		return;
	}
	if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "f oldfd=`oqq`\n");
	}
	r_list_foreach (mems, iter, mem) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "name", mem->name);
			pj_ki (pj, "size", mem->size);
			pj_kn (pj, "address", mem->addr);
			pj_ks (pj, "flags", r_str_rwx_i (mem->perms & perms));
			pj_end (pj);
		} else if (IS_MODE_SIMPLE (mode)) {
			// r_kons_printf (core->cons, "%s\n", mem->name);
			r_kons_printf (core->cons, "0x%08"PFMT64x"\n", mem->addr);
		} else if (IS_MODE_RAD (mode)) {
			r_kons_printf (core->cons, "of malloc://%d\n", mem->size);
			r_kons_printf (core->cons, "om . 0x%08"PFMT64x" 0x%04x 0 %s %s\n",
					mem->addr, mem->size, r_str_rwx_i (mem->perms & perms),
					mem->name);
		} else if (IS_MODE_SET (mode)) {
			bin_mem_print (core, pj, mem->mirrors, mem->perms & perms, depth + 1, mode);
		} else {
			r_kons_printf (core->cons, "0x%08"PFMT64x" +0x%04x %s %s\n",
					mem->addr, mem->size, r_str_rwx_i (mem->perms & perms),
					mem->name);
		}
		if (mem->mirrors) {
			bin_mem_print (core, pj, mem->mirrors, mem->perms & perms, depth + 1, mode);
		}
	}
	if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "o=oldfd;f-oldfd\n");
	}
}

static bool bin_mem(RCore *core, PJ *pj, int mode) {
	RList *mem = r_bin_get_mem (core->bin);
	if (!mem) {
		if (IS_MODE_JSON (mode)) {
			pj_a (pj);
			pj_end (pj);
			return true;
		}
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
		bin_mem_print (core, pj, mem, 7, 0, R_MODE_JSON);
		pj_end (pj);
	} else if (IS_MODE_SIMPLE (mode)) {
		bin_mem_print (core, pj, mem, 7, 0, R_MODE_SIMPLE);
	} else if (IS_MODE_RAD (mode)) {
		bin_mem_print (core, pj, mem, 7, 0, R_MODE_RADARE);
	} else if (IS_MODE_SET (mode)) {
		bin_mem_print (core, NULL, mem, 7, 0, mode);
	} else {
		bin_mem_print (core, pj, mem, 7, 0, 0);
	}
	return true;
}

static void bin_pe_versioninfo(RCore *core, PJ *pj, int mode) {
	Sdb *sdb = NULL;
	int num_version = 0;
	int num_stringtable = 0;
	int num_string = 0;
	const char *format_version = "bin/cur/info/vs_version_info/VS_VERSIONINFO%d";
	const char *format_stringtable = "%s/string_file_info/stringtable%d";
	const char *format_string = "%s/string%d";
	if (!IS_MODE_JSON (mode)) {
		r_kons_printf (core->cons, "=== VS_VERSIONINFO ===\n\n");
	} else {
		pj_o (pj);
	}
	do {
		char *path_version = r_str_newf (format_version, num_version);
		sdb = sdb_ns_path (core->sdb, path_version, 0);
		if (!sdb) {
			free (path_version);
			break;
		}
		if (IS_MODE_JSON (mode)) {
			pj_ko (pj, "VS_FIXEDFILEINFO");
		} else {
			r_kons_printf (core->cons, "# VS_FIXEDFILEINFO\n\n");
		}
		char *path_fixedfileinfo = r_str_newf ("%s/fixed_file_info", path_version);
		sdb = sdb_ns_path (core->sdb, path_fixedfileinfo, 0);
		free (path_fixedfileinfo);
		if (!sdb) {
			if (IS_MODE_JSON (mode)) {
				pj_end (pj);
			}
			free (path_version);
			break;
		}
		ut32 file_version_ms = sdb_num_get (sdb, "FileVersionMS", 0);
		ut32 file_version_ls = sdb_num_get (sdb, "FileVersionLS", 0);
		char *file_version = r_str_newf ("%u.%u.%u.%u", file_version_ms >> 16, file_version_ms & 0xFFFF,
				file_version_ls >> 16, file_version_ls & 0xFFFF);
		ut32 product_version_ms = sdb_num_get (sdb, "ProductVersionMS", 0);
		ut32 product_version_ls = sdb_num_get (sdb, "ProductVersionLS", 0);
		char *product_version = r_str_newf ("%u.%u.%u.%u", product_version_ms >> 16, product_version_ms & 0xFFFF,
				product_version_ls >> 16, product_version_ls & 0xFFFF);
		if (IS_MODE_JSON (mode)) {
			pj_kn (pj, "Signature", sdb_num_get (sdb, "Signature", 0));
			pj_kn (pj, "StrucVersion", sdb_num_get (sdb, "StrucVersion", 0));
			pj_ks (pj, "FileVersion", file_version);
			pj_ks (pj, "ProductVersion", product_version);
			pj_kn (pj, "FileFlagsMask", sdb_num_get (sdb, "FileFlagsMask", 0));
			pj_kn (pj, "FileFlags", sdb_num_get (sdb, "FileFlags", 0));
			pj_kn (pj, "FileOS", sdb_num_get (sdb, "FileOS", 0));
			pj_kn (pj, "FileType", sdb_num_get (sdb, "FileType", 0));
			pj_kn (pj, "FileSubType", sdb_num_get (sdb, "FileSubType", 0));
			pj_end (pj);
		} else {
			r_kons_printf (core->cons, "  Signature: 0x%"PFMT64x"\n", sdb_num_get (sdb, "Signature", 0));
			r_kons_printf (core->cons, "  StrucVersion: 0x%"PFMT64x"\n", sdb_num_get (sdb, "StrucVersion", 0));
			r_kons_printf (core->cons, "  FileVersion: %s\n", file_version);
			r_kons_printf (core->cons, "  ProductVersion: %s\n", product_version);
			r_kons_printf (core->cons, "  FileFlagsMask: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileFlagsMask", 0));
			r_kons_printf (core->cons, "  FileFlags: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileFlags", 0));
			r_kons_printf (core->cons, "  FileOS: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileOS", 0));
			r_kons_printf (core->cons, "  FileType: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileType", 0));
			r_kons_printf (core->cons, "  FileSubType: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileSubType", 0));
			r_cons_newline (core->cons);
		}
		free (file_version);
		free (product_version);
#if 0
		r_kons_printf (core->cons, "  FileDate: %d.%d.%d.%d\n",
			sdb_num_get (sdb, "FileDateMS", 0) >> 16,
			sdb_num_get (sdb, "FileDateMS", 0) & 0xFFFF,
			sdb_num_get (sdb, "FileDateLS", 0) >> 16,
			sdb_num_get (sdb, "FileDateLS", 0) & 0xFFFF);
#endif
		if (IS_MODE_JSON (mode)) {
			pj_ko (pj, "StringTable");
		} else {
			r_kons_printf (core->cons, "# StringTable\n\n");
		}
		for (num_stringtable = 0; sdb; num_stringtable++) {
			char *path_stringtable = r_str_newf (format_stringtable, path_version, num_stringtable);
			sdb = sdb_ns_path (core->sdb, path_stringtable, 0);
			for (num_string = 0; sdb; num_string++) {
				char *path_string = r_str_newf (format_string, path_stringtable, num_string);
				sdb = sdb_ns_path (core->sdb, path_string, 0);
				if (sdb) {
					int lenkey = 0;
					int lenval = 0;
					ut8 *key_utf16 = sdb_decode (sdb_const_get (sdb, "key", 0), &lenkey);
					ut8 *val_utf16 = sdb_decode (sdb_const_get (sdb, "value", 0), &lenval);
					ut8 *key_utf8 = calloc (lenkey * 2, 1);
					ut8 *val_utf8 = calloc (lenval * 2, 1);
					if (r_str_utf16_to_utf8 (key_utf8, lenkey * 2, key_utf16, lenkey, true) < 0
						|| r_str_utf16_to_utf8 (val_utf8, lenval * 2, val_utf16, lenval, true) < 0) {
						R_LOG_WARN ("Cannot decode utf16 to utf8");
					} else if (IS_MODE_JSON (mode)) {
						pj_ks (pj, (char*)key_utf8, (char*)val_utf8);
					} else {
						r_kons_printf (core->cons, "  %s: %s\n", (char*)key_utf8, (char*)val_utf8);
					}
					free (key_utf8);
					free (val_utf8);
					free (key_utf16);
					free (val_utf16);
				}
				free (path_string);
			}
			free (path_stringtable);
		}
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
		}
		num_version++;
		free (path_version);
	} while (sdb);
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
}

static void bin_elf_versioninfo(RCore *core, PJ *pj, int mode) {
	const char *format = "bin/cur/info/versioninfo/%s%d";
	int num_versym;
	int num_verneed = 0;
	int num_version = 0;
	Sdb *sdb = NULL;
	const char *oValue = NULL;
	if (IS_MODE_JSON (mode)) {
		pj_o (pj);
		pj_ka (pj, "versym");
	}
	for (num_versym = 0;; num_versym++) {
		r_strf_var (versym_path, 128, format, "versym", num_versym);
		if (!(sdb = sdb_ns_path (core->sdb, versym_path, 0))) {
			break;
		}
		const ut64 addr = sdb_num_get (sdb, "addr", 0);
		const ut64 offset = sdb_num_get (sdb, "offset", 0);
		const ut64 link = sdb_num_get (sdb, "link", 0);
		const ut64 num_entries = sdb_num_get (sdb, "num_entries", 0);
		const char *const section_name = sdb_const_get (sdb, "section_name", 0);
		const char *const link_section_name = sdb_const_get (sdb, "link_section_name", 0);

		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "section_name", section_name);
			pj_kn (pj, "address", addr);
			pj_kn (pj, "offset", offset);
			pj_kn (pj, "link", link);
			pj_ks (pj, "link_section_name", link_section_name);
			pj_ka (pj, "entries");
		} else {
			r_kons_printf (core->cons, "Version symbols section '%s' contains %"PFMT64u" entries:\n", section_name, num_entries);
			r_kons_printf (core->cons, " Addr: 0x%08"PFMT64x"  Offset: 0x%08"PFMT64x"  Link: %x (%s)\n",
				(ut64)addr, (ut64)offset, (ut32)link, link_section_name);
		}
		int i;
		for (i = 0; i < num_entries; i++) {
			r_strf_var (key, 32, "entry%d", i);
			const char *const value = sdb_const_get (sdb, key, 0);
			if (value) {
				if (oValue && !strcmp (value, oValue)) {
					continue;
				}
				if (IS_MODE_JSON (mode)) {
					pj_o (pj);
					pj_kn (pj, "idx", (ut64)i);
					pj_ks (pj, "value", value);
					pj_end (pj);
				} else {
					r_kons_printf (core->cons, "  0x%08"PFMT64x": ", (ut64) i);
					r_kons_printf (core->cons, "%s\n", value);
				}
				oValue = value;
			}
		}
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
			pj_end (pj);
		} else {
			r_kons_printf (core->cons, "\n\n");
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		pj_ka (pj, "verneed");
	}

	do {
		char *verneed_path = r_str_newf (format, "verneed", num_verneed++);
		if (!(sdb = sdb_ns_path (core->sdb, verneed_path, 0))) {
			break;
		}
		const char *const section_name = sdb_const_get (sdb, "section_name", 0);
		const ut64 address = sdb_num_get (sdb, "addr", 0);
		const ut64 offset = sdb_num_get (sdb, "offset", 0);
		const ut64 link = sdb_num_get (sdb, "link", 0);
		const char *const link_section_name = sdb_const_get (sdb, "link_section_name", 0);
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "section_name", section_name);
			pj_kn (pj, "address", address);
			pj_kn (pj, "offset", offset);
			pj_kn (pj, "link", link);
			pj_ks (pj, "link_section_name", link_section_name);
			pj_ka (pj, "entries");
		} else {
			r_kons_printf (core->cons, "Version need section '%s' contains %d entries:\n",
				section_name, (int)sdb_num_get (sdb, "num_entries", 0));
			r_kons_printf (core->cons, " Addr: 0x%08"PFMT64x, address);
			r_kons_printf (core->cons, "  Offset: 0x%08"PFMT64x"  Link to section: %"PFMT64d" (%s)\n",
				offset, link, link_section_name);
		}
		for (num_version = 0;; num_version++) {
			const char *filename = NULL;
			int num_vernaux = 0;

			r_strf_var (path_version, 64, "%s/version%d", verneed_path, num_version);
			if (!(sdb = sdb_ns_path (core->sdb, path_version, 0))) {
				break;
			}
			if (IS_MODE_JSON (mode)) {
				pj_o (pj);
				pj_kn (pj, "idx", sdb_num_get (sdb, "idx", 0));
				pj_ki (pj, "vn_version", (int)sdb_num_get (sdb, "vn_version", 0));
			} else {
				r_kons_printf (core->cons, "  0x%08"PFMT64x": Version: %d",
					sdb_num_get (sdb, "idx", 0), (int)sdb_num_get (sdb, "vn_version", 0));
			}

			if ((filename = sdb_const_get (sdb, "file_name", 0))) {
				if (IS_MODE_JSON (mode)) {
					pj_ks (pj, "file_name", filename);
				} else {
					r_kons_printf (core->cons, "  File: %s", filename);
				}
			}
			const int cnt = (int)sdb_num_get (sdb, "cnt", 0);
			if (IS_MODE_JSON (mode)) {
				pj_ki (pj, "cnt", cnt);
			} else {
				r_kons_printf (core->cons, "  Cnt: %d\n", cnt);
			}
			if (IS_MODE_JSON (mode)) {
				pj_ka (pj, "vernaux");
			}
			do {
				char *path_vernaux = r_str_newf ("%s/vernaux%d", path_version, num_vernaux++);
				sdb = sdb_ns_path (core->sdb, path_vernaux, 0);
				free (path_vernaux);
				if (!sdb) {
					break;
				}
				const ut64 idx = sdb_num_get (sdb, "idx", 0);
				const char *const name = sdb_const_get (sdb, "name", 0);
				const char *const flags = sdb_const_get (sdb, "flags", 0);
				const int version = (int)sdb_num_get (sdb, "version", 0);
				if (IS_MODE_JSON (mode)) {
					pj_o (pj);
					pj_kn (pj, "idx", idx);
					pj_ks (pj, "name", name);
					pj_ks (pj, "flags", flags);
					pj_ki (pj, "version", version);
					pj_end (pj);
				} else {
					r_kons_printf (core->cons, "  0x%08"PFMT64x":   Name: %s", idx, name);
					r_kons_printf (core->cons, "  Flags: %s Version: %d\n", flags, version);
				}
			} while (sdb);
			if (IS_MODE_JSON (mode)) {
				pj_end (pj);
				pj_end (pj);
			}
		}
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
			pj_end (pj);
		}
		free (verneed_path);
	} while (sdb);
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
		pj_end (pj);
	}
}

static void bin_mach0_versioninfo(RCore *core) {
	/* TODO */
}

static void bin_pe_resources(RCore *core, PJ *pj, int mode) {
	Sdb *sdb = NULL;
	int index = 0;
	const char *pe_path = "bin/cur/info/pe_resource";
	if (!(sdb = sdb_ns_path (core->sdb, pe_path, 0))) {
		return;
	}
	if (IS_MODE_SET (mode)) {
		r_flag_space_set (core->flags, R_FLAGS_FS_RESOURCES);
	} else if (IS_MODE_RAD (mode)) {
		r_kons_printf (core->cons, "fs resources\n");
	} else if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	}
	while (true) {
		r_strf_var (timestrKey, 32, "resource.%d.timestr", index);
		r_strf_var (vaddrKey, 32, "resource.%d.vaddr", index);
		r_strf_var (sizeKey, 32, "resource.%d.size", index);
		r_strf_var (typeKey, 32, "resource.%d.type", index);
		r_strf_var (languageKey, 32, "resource.%d.language", index);
		r_strf_var (nameKey, 32, "resource.%d.name", index);
		char *timestr = sdb_get (sdb, timestrKey, 0);
		if (!timestr) {
			break;
		}
		ut64 vaddr = sdb_num_get (sdb, vaddrKey, 0);
		int size = (int)sdb_num_get (sdb, sizeKey, 0);
		char *name = sdb_get (sdb, nameKey, 0);
		char *type = sdb_get (sdb, typeKey, 0);
		char *lang = sdb_get (sdb, languageKey, 0);

		if (IS_MODE_SET (mode)) {
			r_strf_var (name, 32, "resource.%d", index);
			r_flag_set (core->flags, name, vaddr, size);
		} else if (IS_MODE_RAD (mode)) {
			r_kons_printf (core->cons, "f resource.%d %d 0x%08"PFMT64x"\n", index, size, vaddr);
		} else if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_ks (pj, "name", name);
			pj_ki (pj, "index", index);
			if (R_STR_ISNOTEMPTY (type)) {
				pj_ks (pj, "type", type);
			}
			pj_kn (pj, "vaddr", vaddr);
			pj_ki (pj, "size", size);
			if (lang && *lang != '?') {
				pj_ks (pj, "lang", lang);
			}
			pj_ks (pj, "timestamp", timestr);
			pj_end (pj);
		} else {
			char humansz[8];
			r_num_units (humansz, sizeof (humansz), size);
			r_kons_printf (core->cons, "Resource %d\n", index);
			r_kons_printf (core->cons, "  name: %s\n", name);
			r_kons_printf (core->cons, "  timestamp: %s\n", timestr);
			r_kons_printf (core->cons, "  vaddr: 0x%08"PFMT64x"\n", vaddr);
			r_kons_printf (core->cons, "  size: %s\n", humansz);
			r_kons_printf (core->cons, "  type: %s\n", type);
			r_kons_printf (core->cons, "  language: %s\n", lang);
		}

		R_FREE (timestr);
		R_FREE (name);
		R_FREE (type);
		R_FREE (lang)

		index++;
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println (core->cons, "fs *");
	}
}

static void bin_no_resources(RCore *core, PJ *pj, int mode) {
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
		pj_end (pj);
	}
}

static bool bin_resources(RCore *core, PJ *pj, int mode) {
	const RBinInfo *info = r_bin_get_info (core->bin);
	if (!info || !info->rclass) {
		if (IS_MODE_JSON (mode)) {
			pj_o (pj);
			pj_end (pj);
		}
		return false;
	}
	if (!strncmp ("pe", info->rclass, 2)) {
		bin_pe_resources (core, pj, mode);
	} else {
		bin_no_resources (core, pj, mode);
	}
	return true;
}

static bool bin_versioninfo(RCore *core, PJ *pj, int mode) {
	if (IS_MODE_JSON (mode)) {
		pj_a (pj);
	}
	const RBinInfo *info = r_bin_get_info (core->bin);
	if (!info || !info->rclass) {
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
		}
		return false;
	}
	const char *rclass = info->rclass;
	if (r_str_startswith (rclass, "pe")) {
		bin_pe_versioninfo (core, pj, mode);
	} else if (r_str_startswith (rclass, "elf")) {
		bin_elf_versioninfo (core, pj, mode);
	} else if (r_str_startswith (rclass, "mach0")) {
		bin_mach0_versioninfo (core); // TODO
	} else {
		if (IS_MODE_JSON (mode)) {
			pj_end (pj);
		}
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
	return true;
}

static bool bin_signature(RCore *core, PJ *pj, int mode) {
	bool have_signature = false;
	RBinFile *cur = r_bin_cur (core->bin);
	RBinPlugin *plg = r_bin_file_cur_plugin (cur);
	if (IS_MODE_JSON (mode)) {
		pj_o (pj);
	}
	if (plg && plg->signature) {
		char *signature = plg->signature (cur, IS_MODE_JSON (mode));
		if (signature) {
			have_signature = true;
			if (IS_MODE_JSON (mode)) {
				pj_k (pj, "signature");
				pj_j (pj, signature);
			} else {
				r_cons_println (core->cons, signature);
			}
			free (signature);
		}
	}
	if (IS_MODE_JSON (mode)) {
		pj_end (pj);
	}
	return have_signature;
}

R_API bool r_core_bin_info(RCore *core, int action, PJ *pj, int mode, int va, RCoreBinFilter *filter, const char *chksum) {
	R_RETURN_VAL_IF_FAIL (core, false);
	const char *name = (filter && filter->name)? filter->name : NULL;
	bool ret = true;
	ut64 at = UT64_MAX, loadaddr = r_bin_get_laddr (core->bin);
	if (filter && filter->addr) {
		at = filter->addr;
	}
	// use our internal values for va
	va = va ? VA_TRUE : VA_FALSE;
	if ((action & R_CORE_BIN_ACC_RAW_STRINGS)) {
		ret &= bin_raw_strings (core, pj, mode, va);
	} else if ((action & R_CORE_BIN_ACC_STRINGS)) {
		ret &= bin_strings (core, pj, mode, va);
	}
	if ((action & R_CORE_BIN_ACC_INFO)) {
		ret &= bin_info (core, pj, mode, loadaddr);
	}
	if ((action & R_CORE_BIN_ACC_MAIN)) {
		ret &= bin_main (core, pj, mode, va);
	}
	if ((action & R_CORE_BIN_ACC_ADDRLINE)) {
		ret &= bin_addrline (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_PDB)) {
		ret &= r_core_pdb_info (core, core->bin->file, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_SOURCE)) {
		ret &= bin_source (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_ENTRIES)) {
		ret &= bin_entry (core, pj, mode, loadaddr, va, false);
	}
	if ((action & R_CORE_BIN_ACC_INITFINI)) {
		ret &= bin_entry (core, pj, mode, loadaddr, va, true);
	}
	if ((action & R_CORE_BIN_ACC_SECTIONS)) {
		ret &= bin_sections (core, pj, mode, loadaddr, va, at, name, chksum, false);
	}
	if ((action & R_CORE_BIN_ACC_SEGMENTS)) {
		ret &= bin_sections (core, pj, mode, loadaddr, va, at, name, chksum, true);
	}
	if ((action & R_CORE_BIN_ACC_SECTIONS_MAPPING)) {
		ret &= bin_map_sections_to_segments (core, pj, mode);
	}
	if (r_config_get_b (core->config, "bin.relocs")) {
		if ((action & R_CORE_BIN_ACC_RELOCS)) {
			ret &= bin_relocs (core, pj, mode, va);
		}
	}
	if ((action & R_CORE_BIN_ACC_LIBS)) {
		ret &= bin_libs (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_IMPORTS)) { // 5s
		ret &= bin_imports (core, pj, mode, va, name);
	}
	if ((action & R_CORE_BIN_ACC_EXPORTS)) {
		ret &= bin_symbols (core, pj, mode, loadaddr, va, at, name, true, chksum);
	}
	if ((action & R_CORE_BIN_ACC_SYMBOLS)) { // 6s
		ret &= bin_symbols (core, pj, mode, loadaddr, va, at, name, false, chksum);
	}
	if ((action & R_CORE_BIN_ACC_CLASSES)) { // 6s
		ret &= bin_classes (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_TRYCATCH)) {
		ret &= bin_trycatch (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_SIZE)) {
		ret &= bin_size (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_MEM)) {
		ret &= bin_mem (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_VERSIONINFO)) {
		ret &= bin_versioninfo (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_RESOURCES)) {
		ret &= bin_resources (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_SIGNATURE)) {
		ret &= bin_signature (core, pj, mode);
	}
	if ((action & R_CORE_BIN_ACC_FIELDS)) {
		if (IS_MODE_SIMPLE (mode)) {
			// ret &= bin_fields (core, NULL, mode, va);
			ret &= bin_fields (core, NULL, mode, va);
			// ret &= bin_header (core, mode);
		} else if (IS_MODE_NORMAL (mode)) {
			// ret &= bin_header (core, mode);
			ret &= bin_fields (core, NULL, mode, va);
		} else {
			if ((action & R_CORE_BIN_ACC_HEADER) || action & R_CORE_BIN_ACC_FIELDS) {
				ret &= bin_fields (core, pj, mode, va);
			}
		}
	}
	return ret;
}

R_API bool r_core_bin_set_arch_bits(RCore *core, const char *name, const char *_arch, RSysBits bits) {
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	if (!name) {
		if (!desc || !desc->name) {
			return false;
		}
		name = desc->name;
	}
	char *arch = _arch? strdup (_arch): NULL;
	if (arch) {
		char *dot = strchr (arch, '.');
		if (dot) {
			*dot = 0;
		}
	}
	/* Check if the arch name is a valid name */
	if (!(arch && r_arch_find (core->anal->arch, arch))) {
		free (arch);
		return false;
	}
	if (!strcmp (arch, "null")) {
		free (arch);
		arch = strdup (R_SYS_ARCH);
	}
	/* Find a file with the requested name/arch/bits */
	RBinFile *binfile = r_bin_file_find_by_arch_bits (core->bin, arch, bits);
	if (!binfile) {
		free (arch);
		return false;
	}
	if (!r_bin_use_arch (core->bin, arch, bits, name)) {
		free (arch);
		return false;
	}
	R_FREE (arch);
	// how bin.xtr plugins can inform
	// if the binbuffer is bigger than the io allocated space, that means that rbin have
	// an uncompressed buffer for us. that's hacky and need a proper way to report that
	// io subsystem manipulation from the rbin side
	RBinFile *curfile = r_bin_cur (core->bin);
	if (curfile && curfile->buf && r_buf_size (curfile->buf) > r_io_size (core->io)) {
		if (binfile && binfile->curxtr && binfile->curxtr->loadbuf) {
			RIODesc *d = r_io_open_buffer (core->io, curfile->buf, R_PERM_RWX, 0);
			if (d) {
				r_io_desc_close (desc);
				curfile = r_bin_cur (core->bin);
			}
		}
	}
	// set env if the binfile changed or we are dealing with xtr
	if (curfile != binfile || binfile->curxtr) {
		r_core_bin_set_cur (core, binfile);
		return r_core_bin_set_env (core, binfile);
	}
	return true;
}

R_API bool r_core_bin_update_arch_bits(RCore *core) {
	int bits = 0;
	if (!core) {
		return 0;
	}
	const char *arch = NULL;
	if (core->anal->arch && core->anal->arch->session) {
		RArchConfig *cfg = core->anal->arch->session->config;
		if (cfg) {
			bits = cfg->bits;
			arch = cfg->arch;
		}
	}
	RBinFile *binfile = r_bin_cur (core->bin);
	const char *name = binfile ? binfile->file : NULL;
	if (core->anal && binfile && binfile->curxtr) {
		r_anal_hint_clear (core->anal);
	}
	return r_core_bin_set_arch_bits (core, name, arch, bits);
}

R_API bool r_core_bin_raise(RCore *core, ut32 bfid) {
	if (!r_bin_select_bfid (core->bin, bfid)) {
		return false;
	}
	RBinFile *bf = r_bin_cur (core->bin);
	if (bf) {
		r_io_use_fd (core->io, bf->fd);
	}
	// it should be 0 to use r_io_use_fd in r_core_block_read
	core->switch_file_view = 0;
	return bf && r_core_bin_set_env (core, bf) && r_core_block_read (core);
}

R_API bool r_core_bin_delete(RCore *core, ut32 bf_id) {
	if (bf_id == UT32_MAX) {
		return false;
	}
	r_bin_file_delete (core->bin, bf_id);
	RBinFile *bf = r_bin_file_at (core->bin, core->addr);
	if (bf) {
		r_io_use_fd (core->io, bf->fd);
	}
	core->switch_file_view = 0;
	return bf && r_core_bin_set_env (core, bf) && r_core_block_read (core);
}

static bool r_core_bin_file_print(RCore *core, RBinFile *bf, PJ *pj, int mode) {
	R_RETURN_VAL_IF_FAIL (core && bf, false);
	if (!bf->bo) {
		return false;
	}
	const char *name = bf ? bf->file : NULL;
	(void)r_bin_get_info (core->bin); // XXX is this necssary for proper iniitialization
	ut32 bin_sz = bf ? bf->size : 0;
	// TODO: handle mode to print in json and r2 commands

	switch (mode) {
	case '*': {
		char *n = r_name_filter_shell (name);
		r_kons_printf (core->cons, "oba 0x%08"PFMT64x" %s # %d\n", bf->bo->boffset, n, bf->id);
		free (n);
		break;
	}
	case 'q':
		r_kons_printf (core->cons, "%d\n", bf->id);
		break;
	case 'j': {
		pj_o (pj);
		pj_ks (pj, "name", r_str_get (name));
		pj_ki (pj, "iofd", bf->fd);
		pj_ki (pj, "bfid", bf->id);
		pj_ki (pj, "size", bin_sz);
		pj_kN (pj, "addr", bf->bo->baddr);
		pj_ko (pj, "obj");
		RBinObject *obj = bf->bo;
		RBinInfo *info = obj->info;
		ut8 bits = info ? info->bits : 0;
		const char *asmarch = r_config_get (core->config, "asm.arch");
		const char *arch = info
			? info->arch
				? info->arch
				: asmarch
			: "unknown";
		pj_ks (pj, "arch", arch);
		pj_ki (pj, "bits", bits);
		pj_kN (pj, "binoffset", obj->boffset);
		pj_kN (pj, "objsize", obj->obj_size);
		pj_end (pj);
		pj_end (pj);
		break;
	}
	default:
		{
			RBinInfo *info = bf->bo->info;
			ut8 bits = info ? info->bits : 0;
			const char *asmarch = r_config_get (core->config, "asm.arch");
			const char *arch = info ? info->arch ? info->arch: asmarch: "unknown";
			const char *curstr = (core->allbins || bf == r_bin_cur (core->bin)) ? "*": "-";
			r_kons_printf (core->cons, "%s %d %d %s-%d ba:0x%08"PFMT64x" sz:%"PFMT64d"%s%s\n",
				curstr, bf->id, bf->fd, arch, bits, bf->bo->baddr, bf->bo->size,
				R_STR_ISNOTEMPTY (name)? " ": "", R_STR_ISNOTEMPTY (name)? name: "");
		}
		break;
	}
	return true;
}

R_API bool r_core_bin_list(RCore *core, int mode) {
	R_RETURN_VAL_IF_FAIL (core && core->bin, false);
	// list all binfiles and there objects and there archs
	RListIter *iter;
	RBinFile *binfile = NULL;
	RBin *bin = core->bin;
	const RList *binfiles = bin->binfiles;
	if (!binfiles) {
		return false;
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return 0;
		}
		pj_a (pj);
	}
	r_list_foreach (binfiles, iter, binfile) {
		r_core_bin_file_print (core, binfile, pj, mode);
	}
	if (mode == 'j') {
		pj_end (pj);
		r_kons_print (core->cons, pj_string (pj));
		pj_free (pj);
	}
	return true;
}

R_API char *r_core_bin_attr_tostring(RCore *core, ut64 flags, int mode) {
	RStrBuf *buf = r_strbuf_new (""); // rename to 'sb'
	if (IS_MODE_SET (mode) || IS_MODE_RAD (mode)) {
		if (flags) {
			char *flag_string = r_bin_attr_tostring (flags, true);
			if (flag_string) {
				r_strbuf_append (buf, flag_string);
			}
			free (flag_string);
		}
	} else if (IS_MODE_JSON (mode)) {
		if (flags) {
			PJ *pj = r_core_pj_new (core);
			pj_a (pj);
			char *flag_string = r_bin_attr_tostring (flags, false);
			if (flag_string) {
				pj_s (pj, flag_string);
			} else {
				// r_strf_var (numstr, 32, "0x%08"PFMT64x, flag);
				pj_n (pj, flags);
			}
			pj_end (pj);
			r_strbuf_append (buf, pj_string (pj));
			pj_free (pj);
			free (flag_string);
		} else {
			r_strbuf_append (buf, "[]");
		}
	} else {
		int len = 4;
		if (flags) {
			// const char *flag_string = r_bin_get_meth_flag_string (flag, true);
			char *flag_string = r_bin_attr_tostring (flags, true);
			if (flag_string) {
				r_strbuf_append (buf, flag_string);
			}
			len -= strlen (flag_string);
			if (len < 1) {
				len = 1;
			}
			free (flag_string);
		}
		for ( ; len > 0; len--) {
			r_strbuf_append (buf, " ");
		}
	}
	return r_strbuf_drain (buf);
}

R_API bool r_core_bin_rebase(RCore *core, ut64 baddr) {
	R_RETURN_VAL_IF_FAIL (core && core->bin, false);
	if (core->bin->cur && baddr != UT64_MAX) {
		RBinFile *bf = core->bin->cur;
		bf->bo->baddr = baddr;
		bf->bo->loadaddr = baddr;
		r_bin_object_set_items (bf, bf->bo);
		return true;
	}
	return false;
}
