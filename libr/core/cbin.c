/* radare - LGPL - Copyright 2011-2018 - earada, pancake */

#include <r_core.h>
#include "r_util.h"

#define DBSPATH "/share/radare2/" R2_VERSION "/fcnsign"
#define is_in_range(at, from, sz) ((at) >= (from) && (at) < ((from) + (sz)))

#define VA_FALSE    0
#define VA_TRUE     1
#define VA_NOREBASE 2

#define IS_MODE_SET(mode) (mode & R_CORE_BIN_SET)
#define IS_MODE_SIMPLE(mode) (mode & R_CORE_BIN_SIMPLE)
#define IS_MODE_SIMPLEST(mode) (mode & R_CORE_BIN_SIMPLEST)
#define IS_MODE_JSON(mode) (mode & R_CORE_BIN_JSON)
#define IS_MODE_RAD(mode) (mode & R_CORE_BIN_RADARE)
#define IS_MODE_NORMAL(mode) (!mode)
#define IS_MODE_CLASSDUMP(mode) (mode & R_CORE_BIN_CLASSDUMP)

// dup from cmd_info
#define PAIR_WIDTH 9

static void pair(const char *a, const char *b, int mode, bool last) {
	if (!b || !*b) {
		return;
	}
	if (IS_MODE_JSON (mode)) {
		const char *lst = last ? "" : ",";
		r_cons_printf ("\"%s\":%s%s", a, b, lst);
	} else {
		char ws[16];
		int al = strlen (a);
		if (al > PAIR_WIDTH) {
			al = 0;
		} else {
			al = PAIR_WIDTH - al;
		}
		memset (ws, ' ', al);
		ws[al] = 0;
		r_cons_printf ("%s%s%s\n", a, ws, b);
	}
}

static void pair_bool(const char *a, bool t, int mode, bool last) {
	pair (a, r_str_bool (t), mode, last);
}

static void pair_int(const char *a, int n, int mode, bool last) {
	pair (a, sdb_fmt (0, "%d", n), mode, last);
}

static void pair_str(const char *a, const char *b, int mode, int last) {
	if (IS_MODE_JSON (mode)) {
		if (!b) {
			b = "";
		}
		char *eb = r_str_utf16_encode (b, -1);
		if (eb) {
			char *qs = r_str_newf ("\"%s\"", eb);
			pair (a, qs, mode, last);
			free (eb);
			free (qs);
		}
	} else {
		pair (a, b, mode, last);
	}
}

#define STR(x) (x)?(x):""
R_API int r_core_bin_set_cur (RCore *core, RBinFile *binfile);

static ut64 rva(RBin *bin, ut64 paddr, ut64 vaddr, int va) {
	if (va == VA_TRUE) {
		return r_bin_get_vaddr (bin, paddr, vaddr);
	}
	if (va == VA_NOREBASE) {
		return vaddr;
	}
	return paddr;
}

R_API int r_core_bin_set_by_fd(RCore *core, ut64 bin_fd) {
	if (r_bin_file_set_cur_by_fd (core->bin, bin_fd)) {
		r_core_bin_set_cur (core, r_core_bin_cur (core));
		return true;
	}
	return false;
}

R_API int r_core_bin_set_by_name(RCore *core, const char * name) {
	if (r_bin_file_set_cur_by_name (core->bin, name)) {
		r_core_bin_set_cur (core, r_core_bin_cur (core));
		return true;
	}
	return false;
}

R_API int r_core_bin_set_env(RCore *r, RBinFile *binfile) {
	RBinObject *binobj = binfile ? binfile->o: NULL;
	RBinInfo *info = binobj ? binobj->info: NULL;
	if (info) {
		int va = info->has_va;
		const char * arch = info->arch;
		ut16 bits = info->bits;
		ut64 baseaddr = r_bin_get_baddr (r->bin);
		r_config_set_i (r->config, "bin.baddr", baseaddr);
		r_config_set (r->config, "asm.arch", arch);
		r_config_set_i (r->config, "asm.bits", bits);
		r_config_set (r->config, "anal.arch", arch);
		if (info->cpu && *info->cpu) {
			r_config_set (r->config, "anal.cpu", info->cpu);
		} else {
			r_config_set (r->config, "anal.cpu", arch);
		}
		r_asm_use (r->assembler, arch);
		r_core_bin_info (r, R_CORE_BIN_ACC_ALL, R_CORE_BIN_SET, va, NULL, NULL);
		r_core_bin_set_cur (r, binfile);
		return true;
	}
	return false;
}

R_API int r_core_bin_set_cur(RCore *core, RBinFile *binfile) {
	if (!core->bin) {
		return false;
	}
	if (!binfile) {
		// Find first available binfile
		ut32 fd = r_core_file_cur_fd (core);
		binfile = fd != (ut32)-1
				  ? r_bin_file_find_by_fd (core->bin, fd)
				  : NULL;
		if (!binfile) {
			return false;
		}
	}
	r_bin_file_set_cur_binfile (core->bin, binfile);
	return true;
}

R_API int r_core_bin_refresh_strings(RCore *r) {
	return r_bin_reset_strings (r->bin) ? true: false;
}

R_API RBinFile * r_core_bin_cur(RCore *core) {
	RBinFile *binfile = r_bin_cur (core->bin);
	return binfile;
}

static void _print_strings(RCore *r, RList *list, int mode, int va) {
	bool b64str = r_config_get_i (r->config, "bin.b64str");
	int minstr = r_config_get_i (r->config, "bin.minstr");
	int maxstr = r_config_get_i (r->config, "bin.maxstr");
	RBin *bin = r->bin;
	RBinObject *obj = r_bin_cur_object (bin);
	RListIter *iter;
	RBinString *string;
	RBinSection *section;
	char *q;

	bin->minstrlen = minstr;
	bin->maxstrlen = maxstr;
	if (IS_MODE_JSON (mode)) {
		r_cons_printf ("[");
	}
	if (IS_MODE_RAD (mode)) {
		r_cons_printf ("fs strings");
	}
	if (IS_MODE_SET (mode) && r_config_get_i (r->config, "bin.strings")) {
		r_flag_space_set (r->flags, "strings");
		r_cons_break_push (NULL, NULL);
	}
	RBinString b64 = {0};
	r_list_foreach (list, iter, string) {
		const char *section_name, *type_string;
		ut64 paddr, vaddr, addr;
		paddr = string->paddr;
		vaddr = r_bin_get_vaddr (bin, paddr, string->vaddr);
		addr = va ? vaddr : paddr;
		if (!r_bin_string_filter (bin, string->string, addr)) {
			continue;
		}
		if (string->length < minstr) {
			continue;
		}
		if (maxstr && string->length > maxstr) {
			continue;
		}

		section = r_bin_get_section_at (obj, paddr, 0);
		section_name = section ? section->name : "";
		type_string = r_bin_string_type (string->type);
		if (b64str) {
			ut8 *s = r_base64_decode_dyn (string->string, -1);
			if (s && *s && IS_PRINTABLE (*s)) {
				// TODO: add more checks
				free (b64.string);
				memcpy (&b64, string, sizeof (b64));
				b64.string = (char *)s;
				b64.size = strlen (b64.string);
				string = &b64;
			}
		}
		if (IS_MODE_SET (mode)) {
			char *f_name, *str;
			if (r_cons_is_breaked ()) {
				break;
			}
			r_meta_add (r->anal, R_META_TYPE_STRING, addr, addr + string->size, string->string);
			f_name = strdup (string->string);
			r_name_filter (f_name, -1);
			if (r->bin->prefix) {
				str = r_str_newf ("%s.str.%s", r->bin->prefix, f_name);
			} else {
				str = r_str_newf ("str.%s", f_name);
			}
			r_flag_set (r->flags, str, addr, string->size);
			free (str);
			free (f_name);
		} else if (IS_MODE_SIMPLE (mode)) {
			r_cons_printf ("0x%"PFMT64x" %d %d %s\n", addr,
				string->size, string->length, string->string);
		} else if (IS_MODE_SIMPLEST (mode)) {
			r_cons_println (string->string);
		} else if (IS_MODE_JSON (mode)) {
			int *block_list;
			q = r_base64_encode_dyn (string->string, -1);
			r_cons_printf ("%s{\"vaddr\":%"PFMT64d
				",\"paddr\":%"PFMT64d",\"ordinal\":%d"
				",\"size\":%d,\"length\":%d,\"section\":\"%s\","
				"\"type\":\"%s\",\"string\":\"%s\"",
				iter->p ? ",": "",
				vaddr, paddr, string->ordinal, string->size,
				string->length, section_name, type_string, q);
			switch (string->type) {
			case R_STRING_TYPE_UTF8:
			case R_STRING_TYPE_WIDE:
			case R_STRING_TYPE_WIDE32:
				block_list = r_utf_block_list ((const ut8*)string->string);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't include block list if
						   just Basic Latin (0x00 - 0x7F) */
						break;
					}
					int *block_ptr = block_list;
					r_cons_printf (",\"blocks\":[");
					for (; *block_ptr != -1; block_ptr++) {
						if (block_ptr != block_list) {
							r_cons_printf (",");
						}
						const char *utfName = r_utf_block_name (*block_ptr);
						r_cons_printf ("\"%s\"", utfName? utfName: "");
					}
					r_cons_printf ("]");
					R_FREE (block_list);
				}
			}
			r_cons_printf ("}");
			free (q);
		} else if (IS_MODE_RAD (mode)) {
			char *f_name, *str;
			f_name = strdup (string->string);
			r_name_filter (f_name, R_FLAG_NAME_SIZE);
			if (r->bin->prefix) {
				str = r_str_newf ("%s.str.%s", r->bin->prefix, f_name);
				r_cons_printf ("f %s.str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
					"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
					r->bin->prefix, f_name, string->size, addr,
					string->size, addr);
			} else {
				str = r_str_newf ("str.%s", f_name);
				r_cons_printf ("f str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
					"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
					f_name, string->size, addr,
					string->size, addr);
			}
			free (str);
			free (f_name);
		} else {
			int *block_list;
			char *str = string->string;
			char *no_dbl_bslash_str = NULL;
			if (!r->print->esc_bslash) {
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
#if 0
			r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"
				PFMT64x" ordinal=%03u sz=%u len=%u "
				"section=%s type=%s string=%s",
				vaddr, paddr, string->ordinal, string->size,
				string->length, section_name, type_string, str);
#else
			r_cons_printf ("%03u 0x%08"PFMT64x" 0x%08"
				PFMT64x" %3u %3u "
				"(%s) %5s %s",
				string->ordinal, paddr, vaddr, 
				string->length, string->size,
				section_name, type_string, str);
#endif
			if (str == no_dbl_bslash_str) {
				R_FREE (str);
			}
			switch (string->type) {
			case R_STRING_TYPE_UTF8:
			case R_STRING_TYPE_WIDE:
			case R_STRING_TYPE_WIDE32:
				block_list = r_utf_block_list ((const ut8*)string->string);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't show block list if
						   just Basic Latin (0x00 - 0x7F) */
						break;
					}
					int *block_ptr = block_list;
					r_cons_printf (" blocks=");
					for (; *block_ptr != -1; block_ptr++) {
						if (block_ptr != block_list) {
							r_cons_printf (",");
						}
						const char *name = r_utf_block_name (*block_ptr);
						r_cons_printf ("%s", name? name: "");
					}
					free (block_list);
				}
				break;
			}
			r_cons_printf ("\n");
		}
	}
	R_FREE (b64.string);
	if (IS_MODE_JSON (mode)) {
		r_cons_printf ("]");
	}
	if (IS_MODE_SET (mode)) {
		r_cons_break_pop ();
	}
}

static bool bin_raw_strings(RCore *r, int mode, int va) {
	RBinFile *bf = r_bin_cur (r->bin);
	if (!bf && r->io && r->io->desc && r->io->desc->uri) {
		// -n scenario is handled already
		// eprintf ("Likely you used -nn \n");
		// eprintf ("try: .!rabin2 -B <baddr> -zzr filename\n");
		return false;
	}
	if (bf && strstr (bf->file, "malloc://")) {
		//sync bf->buf to search string on it
		r_io_read_at (r->io, 0, bf->buf->buf, bf->size);
	}
	if (!r->file) {
		eprintf ("Core file not open\n");
		return false;
	}
	RList *l = r_bin_raw_strings (bf, 0);
	_print_strings (r, l, mode, va);
	return true;
}

static bool bin_strings(RCore *r, int mode, int va) {
	RList *list;
	RBinFile *binfile = r_core_bin_cur (r);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	int rawstr = r_config_get_i (r->config, "bin.rawstr");
	if (!binfile) {
		return false;
	}
	if (!r_config_get_i (r->config, "bin.strings")) {
		return false;
	}
	if (!plugin) {
		return false;
	}
	if (plugin->info && plugin->name) {
		if (strcmp (plugin->name, "any") == 0 && !rawstr) {
			if (IS_MODE_JSON (mode)) {
				r_cons_print("[]");
			}
			return false;
		}
	}

	if (!(list = r_bin_get_strings (r->bin))) {
		return false;
	}
	_print_strings (r, list, mode, va);
	return true;
}

static const char* get_compile_time(Sdb *binFileSdb) {
	Sdb *info_ns = sdb_ns (binFileSdb, "info", false);
	const char *timeDateStamp_string = sdb_const_get (info_ns,
		"image_file_header.TimeDateStamp_string", 0);
	return timeDateStamp_string;
}

static int is_executable(RBinObject *obj) {
	RListIter *it;
	RBinSection* sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		r_list_foreach (obj->sections, it, sec) {
			if (R_BIN_SCN_EXECUTABLE & sec->srwx) {
				return true;
			}
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

R_API void r_core_anal_type_init(RCore *core) {
	Sdb *types = NULL;
	const char *anal_arch = NULL, *os = NULL;
	char *dbpath;
	if (!core || !core->anal) {
		return;
	}
	const char *dir_prefix = r_config_get (core->config, "dir.prefix");
	int bits = core->assembler->bits;
	types = core->anal->sdb_types;
 	// make sure they are empty this is initializing
	sdb_reset (types);
	anal_arch = r_config_get (core->config, "anal.arch");
	os = r_config_get (core->config, "asm.os");
	// spaguetti ahead
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types.sdb", dir_prefix);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%s.sdb", dir_prefix, anal_arch);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%s.sdb", dir_prefix, os);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%d.sdb", dir_prefix, bits);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%s-%d.sdb", dir_prefix, os, bits);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%s-%d.sdb", dir_prefix, anal_arch, bits);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%s-%s.sdb", dir_prefix, anal_arch, os);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	dbpath = sdb_fmt (-1, "%s/"DBSPATH"/types-%s-%s-%d.sdb", dir_prefix, anal_arch, os, bits);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
}

static int save_ptr(void *p, const char *k, const char *v) {
	Sdb *sdbs[2];
	sdbs[0] = ((Sdb**) p)[0];
	sdbs[1] = ((Sdb**) p)[1];
	if (!strncmp (v, "cc", strlen ("cc") + 1)) {
		const char *x = sdb_const_get (sdbs[1], sdb_fmt (-1, "cc.%s.name", k), 0);
		char *tmp = sdb_fmt (-1, "%p", x);
		sdb_set (sdbs[0], tmp, x, 0);
	}
	return 1;
}

R_API void r_core_anal_cc_init(RCore *core) {
	Sdb *sdbs[2] = {
		sdb_new0 (),
		core->anal->sdb_cc
	};
	const char *dir_prefix = r_config_get (core->config, "dir.prefix");
	//save pointers and values stored inside them
	//to recover from freeing heeps
	const char *defaultcc = sdb_const_get (sdbs[1], "default.cc", 0);
	sdb_set (sdbs[0], sdb_fmt (-1, "0x%08"PFMT64x, r_num_get (NULL, defaultcc)), defaultcc, 0);
	sdb_foreach (core->anal->sdb_cc, save_ptr, sdbs);
	sdb_reset ( core->anal->sdb_cc);
	const char *anal_arch = r_config_get (core->config, "anal.arch");

	int bits = core->anal->bits;
	if (bits == 16 && !strcmp (anal_arch, "arm")) {
		bits = 32;
	}

	char *dbpath = sdb_fmt (-1, "%s/"DBSPATH"/cc-%s-%d.sdb", dir_prefix, anal_arch, bits);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (core->anal->sdb_cc, dbpath);
	}
	//restore all freed CC or replace with new default cc
	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, it, fcn) {
		char *ptr = sdb_fmt (-1, "%p", fcn->cc);
		const char *cc = sdb_const_get (sdbs[0], ptr, 0);
		if (cc) {
			fcn->cc = r_anal_cc_to_constant (core->anal, (char *)cc);
		}
		if (!fcn->cc) {
			fcn->cc = r_anal_cc_default (core->anal);
		}
		fcn->cc = r_str_const (fcn->cc);
	}
	sdb_close (sdbs[0]);
	sdb_free (sdbs[0]);
}
#undef DBSPATH

static int bin_info(RCore *r, int mode) {
	int i, j, v;
	char str[R_FLAG_NAME_SIZE];
	RBinInfo *info = r_bin_get_info (r->bin);
	RBinFile *binfile = r_core_bin_cur (r);
	RBinObject *obj = r_bin_cur_object (r->bin);
	const char *compiled = NULL;
	bool havecode;

	if (!binfile || !info || !obj) {
		if (mode & R_CORE_BIN_JSON) {
			r_cons_printf ("{}");
		}
		return false;
	}
	havecode = is_executable (obj) | (obj->entries != NULL);
	compiled = get_compile_time (binfile->sdb);

	if (IS_MODE_SET (mode)) {
		r_config_set (r->config, "file.type", info->rclass);
		r_config_set (r->config, "cfg.bigendian",
			      info->big_endian ? "true" : "false");
		if (info->rclass && !strcmp (info->rclass, "fs")) {
			// r_config_set (r->config, "asm.arch", info->arch);
			// r_core_seek (r, 0, 1);
			// eprintf ("m /root %s 0", info->arch);
	//		r_core_cmdf (r, "m /root hfs @ 0", info->arch);
		} else {
			if (info->lang) {
				r_config_set (r->config, "bin.lang", info->lang);
			}
			r_config_set (r->config, "asm.os", info->os);
			r_config_set (r->config, "asm.arch", info->arch);
			if (info->cpu && *info->cpu) {
				r_config_set (r->config, "asm.cpu", info->cpu);
			}
			r_config_set (r->config, "anal.arch", info->arch);
			snprintf (str, R_FLAG_NAME_SIZE, "%i", info->bits);
			r_config_set (r->config, "asm.bits", str);
			r_config_set (r->config, "asm.dwarf",
				(R_BIN_DBG_STRIPPED & info->dbg_info) ? "false" : "true");
			v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_ALIGN);
			if (v != -1) r_config_set_i (r->config, "asm.pcalign", v);
		}
	} else if (IS_MODE_SIMPLE (mode)) {
		r_cons_printf ("arch %s\n", info->arch);
		if (info->cpu && *info->cpu) {
			r_cons_printf ("cpu %s\n", info->cpu);
		}
		r_cons_printf ("bits %d\n", info->bits);
		r_cons_printf ("os %s\n", info->os);
		r_cons_printf ("endian %s\n", info->big_endian? "big": "little");
		v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			r_cons_printf ("minopsz %d\n", v);
		}
		v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
		if (v != -1) {
			r_cons_printf ("maxopsz %d\n", v);
		}
		v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_ALIGN);
		if (v != -1) {
			r_cons_printf ("pcalign %d\n", v);
		}
	} else if (IS_MODE_RAD (mode)) {
		if (info->type && !strcmp (info->type, "fs")) {
			r_cons_printf ("e file.type=fs\n");
			r_cons_printf ("m /root %s 0\n", info->arch);
		} else {
			r_cons_printf ("e cfg.bigendian=%s\n"
				"e asm.bits=%i\n"
				"e asm.dwarf=%s\n",
				r_str_bool (info->big_endian),
				info->bits,
				r_str_bool (R_BIN_DBG_STRIPPED &info->dbg_info));
			if (info->lang && *info->lang) {
				r_cons_printf ("e bin.lang=%s\n", info->lang);
			}
			if (info->rclass && *info->rclass) {
				r_cons_printf ("e file.type=%s\n",
					info->rclass);
			}
			if (info->os) {
				r_cons_printf ("e asm.os=%s\n", info->os);
			}
			if (info->arch) {
				r_cons_printf ("e asm.arch=%s\n", info->arch);
			}
			if (info->cpu && *info->cpu) {
				r_cons_printf ("e asm.cpu=%s\n", info->cpu);
			}
			v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_ALIGN);
			if (v != -1) r_cons_printf ("e asm.pcalign=%d\n", v);
		}
	} else {
		// XXX: if type is 'fs' show something different?
		char *tmp_buf;
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("{");
		}
		pair_str ("arch", info->arch, mode, false);
		if (info->cpu && *info->cpu) {
			pair_str ("cpu", info->cpu, mode, false);
		}
		pair_int ("binsz", r_bin_get_size (r->bin), mode, false);
		pair_str ("bintype", info->rclass, mode, false);
		pair_int ("bits", info->bits, mode, false);
		pair_bool ("canary", info->has_canary, mode, false);
		pair_str ("class", info->bclass, mode, false);
		if (info->actual_checksum) {
			/* computed checksum */
			pair_str ("cmp.csum", info->actual_checksum, mode, false);
		}
		pair_str ("compiled", compiled, mode, false);
		pair_bool ("crypto", info->has_crypto, mode, false);
		pair_str ("dbg_file", info->debug_file_name, mode, false);
		pair_str ("endian", info->big_endian ? "big" : "little", mode, false);
		if (info->rclass && !strcmp (info->rclass, "mdmp")) {
			tmp_buf = sdb_get (binfile->sdb, "mdmp.flags", 0);
			if (tmp_buf) {
				pair_str ("flags", tmp_buf, mode, false);
				free (tmp_buf);
			}
		}
		pair_bool ("havecode", havecode, mode, false);
		if (info->claimed_checksum) {
			/* checksum specified in header */
			pair_str ("hdr.csum", info->claimed_checksum, mode, false);
		}
		pair_str ("guid", info->guid, mode, false);
		pair_str ("intrp", info->intrp, mode, false);
		pair_str ("lang", info->lang, mode, false);
		pair_bool ("linenum", R_BIN_DBG_LINENUMS & info->dbg_info, mode, false);
		pair_bool ("lsyms", R_BIN_DBG_SYMS & info->dbg_info, mode, false);
		pair_str ("machine", info->machine, mode, false);
		v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
		if (v != -1) {
			pair_int ("maxopsz", v, mode, false);
		}
		v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			pair_int ("minopsz", v, mode, false);
		}
		pair_bool ("nx", info->has_nx, mode, false);
		pair_str ("os", info->os, mode, false);
		if (info->rclass && !strcmp (info->rclass, "pe")) {
			pair_bool ("overlay", info->pe_overlay, mode, false);
		}
		v = r_anal_archinfo (r->anal, R_ANAL_ARCHINFO_ALIGN);
		if (v != -1) {
			pair_int ("pcalign", v, mode, false);
		}
		pair_bool ("pic", info->has_pi, mode, false);
		pair_bool ("relocs", R_BIN_DBG_RELOCS & info->dbg_info, mode, false);
		tmp_buf = sdb_get (obj->kv, "elf.relro", 0);
		if (tmp_buf) {
			pair_str ("relro", tmp_buf, mode, false);
			free (tmp_buf);
		}
		pair_str ("rpath", info->rpath, mode, false);
		if (info->rclass && !strcmp (info->rclass, "pe")) {
			//this should be moved if added to mach0 (or others)
			pair_bool ("signed", info->signature, mode, false);
		}
		pair_bool ("static", r_bin_is_static (r->bin), mode, false);
		if (info->rclass && !strcmp (info->rclass, "mdmp")) {
			v = sdb_num_get (binfile->sdb, "mdmp.streams", 0);
			if (v != -1) {
				pair_int ("streams", v, mode, false);
			}
		}
		pair_bool ("stripped", R_BIN_DBG_STRIPPED & info->dbg_info, mode, false);
		pair_str ("subsys", info->subsystem, mode, false);
		pair_bool ("va", info->has_va, mode, true);
		if (IS_MODE_JSON (mode)) {
			r_cons_printf (",\"checksums\":{");
			for (i = 0; info->sum[i].type; i++) {
				RBinHash *h = &info->sum[i];
				ut64 hash = r_hash_name_to_bits (h->type);
				RHash *rh = r_hash_new (true, hash);
				int len = r_hash_calculate (rh, hash, (const ut8*)
						binfile->buf->buf+h->from, h->to);
				if (len < 1) {
					eprintf ("Invaild checksum length\n");
				}
				r_hash_free (rh);
				r_cons_printf ("%s\"%s\":{\"hex\":\"", i?",": "", h->type);
				// r_cons_printf ("%s\t%d-%dc\t", h->type, h->from, h->to+h->from);
				for (j = 0; j < h->len; j++) {
					r_cons_printf ("%02x", h->buf[j]);
				}
				r_cons_printf ("\"}");
			}
			r_cons_printf ("}");
		} else {
			for (i = 0; info->sum[i].type; i++) {
				RBinHash *h = &info->sum[i];
				ut64 hash = r_hash_name_to_bits (h->type);
				RHash *rh = r_hash_new (true, hash);
				int len = r_hash_calculate (rh, hash, (const ut8*)
						binfile->buf->buf+h->from, h->to);
				if (len < 1) {
					eprintf ("Invaild wtf\n");
				}
				r_hash_free (rh);
				r_cons_printf ("%s  %d-%dc  ", h->type, h->from, h->to+h->from);
				for (j = 0; j < h->len; j++) {
					r_cons_printf ("%02x", h->buf[j]);
				}
				r_cons_newline ();
			}
		}
		if (IS_MODE_JSON (mode)) r_cons_printf ("}");
	}
	r_core_anal_type_init (r);
	r_core_anal_cc_init (r);
	return true;
}

static int bin_dwarf(RCore *core, int mode) {
	RBinDwarfRow *row;
	RListIter *iter;
	RList *list = NULL;
	if (!r_config_get_i (core->config, "bin.dbginfo")) {
		return false;
	}
	RBinFile *binfile = r_core_bin_cur (core);
	RBinPlugin * plugin = r_bin_file_cur_plugin (binfile);
	if (!binfile) {
		return false;
	}
	if (plugin && plugin->lines) {
		list = plugin->lines (binfile);
	} else if (core->bin) {
		// TODO: complete and speed-up support for dwarf
		RBinDwarfDebugAbbrev *da = NULL;
		da = r_bin_dwarf_parse_abbrev (core->bin, mode);
		r_bin_dwarf_parse_info (da, core->bin, mode);
		r_bin_dwarf_parse_aranges (core->bin, mode);
		list = r_bin_dwarf_parse_line (core->bin, mode);
		r_bin_dwarf_free_debug_abbrev (da);
		free (da);
	}
	if (!list) {
		return false;
	}

	r_cons_break_push (NULL, NULL);
	/* cache file:line contents */
	const char *lastFile = NULL;
	int *lastFileLines = NULL;
	char *lastFileContents = NULL;
	int lastFileLinesCount = 0;

	/* ugly dupe for speedup */
	const char *lastFile2 = NULL;
	int *lastFileLines2 = NULL;
	char *lastFileContents2 = NULL;
	int lastFileLinesCount2 = 0;

	const char *lf = NULL;
	int *lfl = NULL;
	char *lfc = NULL;
	int lflc = 0;

	//TODO we should need to store all this in sdb, or do a filecontentscache in libr/util
	//XXX this whole thing has leaks
	r_list_foreach (list, iter, row) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (mode) {
			// TODO: use 'Cl' instead of CC
			const char *path = row->file;
			if (!lastFile || strcmp (path, lastFile)) {
				if (lastFile && lastFile2 && !strcmp (path, lastFile2)) {
					lf = lastFile;
					lfl = lastFileLines;
					lfc = lastFileContents;
					lflc = lastFileLinesCount;
					lastFile = lastFile2;
					lastFileLines = lastFileLines2;
					lastFileContents = lastFileContents2;
					lastFileLinesCount = lastFileLinesCount2;
					lastFile2 = lf;
					lastFileLines2 = lfl;
					lastFileContents2 = lfc;
					lastFileLinesCount2 = lflc;
				} else {
					lastFile2 = lastFile;
					lastFileLines2 = lastFileLines;
					lastFileContents2 = lastFileContents;
					lastFileLinesCount2 = lastFileLinesCount;
					lastFile = path;
					lastFileContents = r_file_slurp (path, NULL);
					if (lastFileContents) {
						lastFileLines = r_str_split_lines (lastFileContents, &lastFileLinesCount);
					}
				}
			}
			char *line = NULL;
			//r_file_slurp_line (path, row->line - 1, 0);
			if (lastFileLines && lastFileContents) {
				int nl = row->line - 1;
				if (nl >= 0 && nl < lastFileLinesCount) {
					line = strdup (lastFileContents + lastFileLines[nl]);
				}
			} else {
				line = NULL;
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
			// TODO: implement internal : if ((mode & R_CORE_BIN_SET))
			if ((mode & R_CORE_BIN_SET)) {
				// TODO: use CL here.. but its not necessary.. so better not do anything imho
				// r_core_cmdf (core, "CL %s:%d 0x%08"PFMT64x, file, (int)row->line, row->address);
#if 0
				char *cmt = r_str_newf ("%s:%d %s", file, (int)row->line, line? line: "");
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, row->address, cmt);
				free (cmt);
#endif
			} else {
				r_cons_printf ("CL %s:%d 0x%08" PFMT64x "\n",
					       file, (int)row->line,
					       row->address);
				r_cons_printf ("\"CC %s:%d %s\"@0x%" PFMT64x
					       "\n",
					       file, row->line,
					       line ? line : "", row->address);
			}
			free (file);
			free (line);
		} else {
			r_cons_printf ("0x%08" PFMT64x "\t%s\t%d\n",
				       row->address, row->file, row->line);
		}
	}
	r_cons_break_pop ();
	R_FREE (lastFileContents);
	R_FREE (lastFileContents2);
	// this list is owned by rbin, not us, we shouldnt free it
	// r_list_free (list);
	free (lastFileLines);
	return true;
}

static int bin_pdb(RCore *core, int mode) {
	R_PDB pdb = R_EMPTY;
	ut64 baddr = r_bin_get_baddr (core->bin);

	pdb.cb_printf = r_cons_printf;
	if (!init_pdb_parser (&pdb, core->bin->file)) {
		return false;
	}
	if (!pdb.pdb_parse (&pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb.finish_pdb_parse (&pdb);
		return false;
	}
	if (mode == R_CORE_BIN_JSON) {
		r_cons_printf("[");
	}

	switch (mode) {
	case R_CORE_BIN_SET:
		mode = 's';
		r_core_cmd0 (core, ".iP*");
		return true;
	case R_CORE_BIN_JSON:
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

	pdb.print_types (&pdb, mode);
	if (mode == 'j') {
		r_cons_printf (",");
	}
	pdb.print_gvars (&pdb, baddr, mode);
	if (mode == 'j') {
		r_cons_printf ("]");
	}
	pdb.finish_pdb_parse (&pdb);

	return true;
}

static int bin_main(RCore *r, int mode, int va) {
	RBinAddr *binmain = r_bin_get_sym (r->bin, R_BIN_SYM_MAIN);
	ut64 addr;
	if (!binmain) {
		return false;
	}
	addr = va ? r_bin_a2b (r->bin, binmain->vaddr) : binmain->paddr;

	if (IS_MODE_SET (mode)) {
		r_flag_space_set (r->flags, "symbols");
		r_flag_set (r->flags, "main", addr, r->blocksize);
	} else if (IS_MODE_SIMPLE (mode)) {
		r_cons_printf ("%"PFMT64d, addr);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_printf ("fs symbols\n");
		r_cons_printf ("f main @ 0x%08"PFMT64x"\n", addr);
	} else if (IS_MODE_JSON (mode)) {
		r_cons_printf ("{\"vaddr\":%" PFMT64d
			",\"paddr\":%" PFMT64d "}", addr, binmain->paddr);
	} else {
		r_cons_printf ("[Main]\n");
		r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x"\n",
			addr, binmain->paddr);
	}
	return true;
}

static int bin_entry(RCore *r, int mode, ut64 laddr, int va, bool inifin) {
	char str[R_FLAG_NAME_SIZE];
	RList *entries = r_bin_get_entries (r->bin);
	RListIter *iter;
	RBinAddr *entry = NULL;
	int i = 0;
	ut64 baddr = r_bin_get_baddr (r->bin);

	if (IS_MODE_RAD (mode)) {
		r_cons_printf ("fs symbols\n");
	} else if (IS_MODE_JSON (mode)) {
		r_cons_printf ("[");
	} else if (IS_MODE_NORMAL (mode)) {
		if (inifin) {
			r_cons_printf ("[Constructors]\n");
		} else {
			r_cons_printf ("[Entrypoints]\n");
		}
	}

	r_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 haddr = UT64_MAX;
		if (mode != R_CORE_BIN_SET) {
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
		if (entry->haddr) {
			haddr = entry->haddr;
		}
		ut64 at = rva (r->bin, paddr, entry->vaddr, va);
		const char *type = r_bin_entry_type_string (entry->type);
		if (!type) {
			type = "unknown";
		}
		if (IS_MODE_SET (mode)) {
			r_flag_space_set (r->flags, "symbols");
			if (entry->type == R_BIN_ENTRY_TYPE_INIT) {
				snprintf (str, R_FLAG_NAME_SIZE, "entry%i.init", i);
			} else if (entry->type == R_BIN_ENTRY_TYPE_FINI) {
				snprintf (str, R_FLAG_NAME_SIZE, "entry%i.fini", i);
			} else {
				snprintf (str, R_FLAG_NAME_SIZE, "entry%i", i);
			}
			r_flag_set (r->flags, str, at, 1);
		} else if (IS_MODE_SIMPLE (mode)) {
			r_cons_printf ("0x%08"PFMT64x"\n", at);
		} else if (IS_MODE_JSON (mode)) {
			r_cons_printf ("%s{\"vaddr\":%" PFMT64d ","
				"\"paddr\":%" PFMT64d ","
				"\"baddr\":%" PFMT64d ","
				"\"laddr\":%" PFMT64d ","
				"\"haddr\":%" PFMT64d ","
				"\"type\":\"%s\"}",
				iter->p ? "," : "", at, paddr, baddr, laddr, haddr, type);
		} else if (IS_MODE_RAD (mode)) {
			char *name = NULL;
			if (entry->type == R_BIN_ENTRY_TYPE_INIT) {
				name = r_str_newf ("entry%i.init", i);
			} else if (entry->type == R_BIN_ENTRY_TYPE_FINI) {
				name = r_str_newf ("entry%i.fini", i);
			} else {
				name = r_str_newf ("entry%i", i);
			}
			r_cons_printf ("f %s 1 @ 0x%08"PFMT64x"\n", name, at);
			r_cons_printf ("f %s_haddr 1 @ 0x%08"PFMT64x"\n", name, haddr);
			r_cons_printf ("s %s\n", name);
			free (name);
		} else {
			r_cons_printf (
				 "vaddr=0x%08"PFMT64x
				" paddr=0x%08"PFMT64x
				" baddr=0x%08"PFMT64x
				" laddr=0x%08"PFMT64x,
				at, paddr, baddr, laddr);
			if (haddr == UT64_MAX) {
				r_cons_printf (
					" haddr=%"PFMT64d
					" type=%s\n",
					haddr, type);
			} else {
				r_cons_printf (
					" haddr=0x%08"PFMT64x
					" type=%s\n",
					haddr, type);
			}
		}
		i++;
	}
	if (IS_MODE_SET (mode)) {
		if (entry) {
			ut64 at = rva (r->bin, entry->paddr, entry->vaddr, va);
			r_core_seek (r, at, 0);
		}
	} else if (IS_MODE_JSON (mode)) {
		r_cons_printf ("]");
		r_cons_newline ();
	} else if (IS_MODE_NORMAL (mode)) {
		r_cons_printf ("\n%i entrypoints\n", i);
	}
	return true;
}

static const char *bin_reloc_type_name(RBinReloc *reloc) {
#define CASE(T) case R_BIN_RELOC_ ## T: return reloc->additive ? "ADD_" #T : "SET_" #T
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	}
	return "UNKNOWN";
#undef CASE
}

static ut8 bin_reloc_size(RBinReloc *reloc) {
#define CASE(T) case R_BIN_RELOC_ ## T: return T / 8
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	}
	return 0;
#undef CASE
}

static char *resolveModuleOrdinal(Sdb *sdb, const char *module, int ordinal) {
	Sdb *db = sdb;
	char *foo = sdb_get (db, sdb_fmt (0, "%d", ordinal), 0);
	return (foo && *foo) ? foo : NULL;
}

static char *get_reloc_name(RBinReloc *reloc, ut64 addr) {
	char *reloc_name = NULL;
	if (reloc->import && reloc->import->name) {
		reloc_name = sdb_fmt (-1, "reloc.%s_%d", reloc->import->name,
				      (int)(addr & 0xff));
		if (!reloc_name) {
			return NULL;
		}
		r_str_replace_char (reloc_name, '$', '_');
	} else if (reloc->symbol && reloc->symbol->name) {
		reloc_name = sdb_fmt (-1, "reloc.%s_%d", reloc->symbol->name, (int)(addr & 0xff));
		if (!reloc_name) {
			return NULL;
		}
		r_str_replace_char (reloc_name, '$', '_');
	} else if (reloc->is_ifunc) {
		// addend is the function pointer for the resolving ifunc
		reloc_name = sdb_fmt (-1, "reloc.ifunc_%"PFMT64x, reloc->addend);
	} else {
		// TODO(eddyb) implement constant relocs.
	}
	return reloc_name;
}

static void set_bin_relocs(RCore *r, RBinReloc *reloc, ut64 addr, Sdb **db, char **sdb_module) {
	int bin_demangle = r_config_get_i (r->config, "bin.demangle");
	const char *lang = r_config_get (r->config, "bin.lang");
	char *reloc_name, *demname = NULL;
	bool is_pe = true;
	int is_sandbox = r_sandbox_enable (0);

	if (reloc->import && reloc->import->name[0]) {
		char str[R_FLAG_NAME_SIZE];
		RFlagItem *fi;

		if (is_pe && !is_sandbox && strstr (reloc->import->name, "Ordinal")) {
			const char *TOKEN = ".dll_Ordinal_";
			char *module = strdup (reloc->import->name);
			char *import = strstr (module, TOKEN);

			r_str_case (module, false);
			if (import) {
				char *filename = NULL;
				int ordinal;
				*import = 0;
				import += strlen (TOKEN);
				ordinal = atoi (import);
				if (!*sdb_module || strcmp (module, *sdb_module)) {
					sdb_free (*db);
					*db = NULL;
					free (*sdb_module);
					*sdb_module = strdup (module);
					/* always lowercase */
					filename = sdb_fmt (1, "%s.sdb", module);
					r_str_case (filename, false);
					if (r_file_exists (filename)) {
						*db = sdb_new (NULL, filename, 0);
					} else {
					// XXX. we have dir.prefix, windows shouldnt work different
						filename = sdb_fmt (1, "%s/share/radare2/" R2_VERSION"/format/dll/%s.sdb", r_config_get (r->config, "dir.prefix"), module);
						if (r_file_exists (filename)) {
							*db = sdb_new (NULL, filename, 0);
#if __WINDOWS__
						} else {
							char invoke_dir[MAX_PATH];
							if (r_sys_get_src_dir_w32 (invoke_dir)) {
								filename = sdb_fmt (1, "%s/share/radare2/"R2_VERSION "/format/dll/%s.sdb", invoke_dir, module);
							} else {
								filename = sdb_fmt (1, "share/radare2/"R2_VERSION"/format/dll/%s.sdb", module);
							}
#else
							filename = sdb_fmt (1, "%s/share/radare2/" R2_VERSION"/format/dll/%s.sdb", r_config_get (r->config, "dir.prefix"), module);
							if (r_file_exists (filename)) {
								*db = sdb_new (NULL, filename, 0);
							}
#endif
						}
					}
				}
				if (*db) {
					// ordinal-1 because we enumerate starting at 0
					char *symname = resolveModuleOrdinal (*db, module, ordinal - 1);  // uses sdb_get
					if (symname) {
						if (r->bin->prefix) {
							reloc->import->name = r_str_newf
								("%s.%s.%s", r->bin->prefix, module, symname);
						} else {
							reloc->import->name = r_str_newf
								("%s.%s", module, symname);
						}
						R_FREE (symname);
					}
				}
			}
			free (module);
			r_anal_hint_set_size (r->anal, reloc->vaddr, 4);
			r_meta_add (r->anal, R_META_TYPE_DATA, reloc->vaddr, reloc->vaddr+4, NULL);
		}
		reloc_name = reloc->import->name;
		if (r->bin->prefix) {
			snprintf (str, R_FLAG_NAME_SIZE, "%s.reloc.%s_%d", r->bin->prefix, reloc_name, (int)(addr&0xff));
		} else {
			snprintf (str, R_FLAG_NAME_SIZE, "reloc.%s_%d", reloc_name, (int)(addr&0xff));
		}
		if (bin_demangle) {
			demname = r_bin_demangle (r->bin->cur, lang, str, addr);
		}
		r_name_filter (str, 0);
		fi = r_flag_set (r->flags, str, addr, bin_reloc_size (reloc));
		if (demname) {
			char *realname;
			if (r->bin->prefix) {
				realname = sdb_fmt (0, "%s.reloc.%s", r->bin->prefix, demname);
			} else {
				realname = sdb_fmt (0, "reloc.%s", demname);
			}
			r_flag_item_set_realname (fi, realname);
		}
	} else {
		char *reloc_name = get_reloc_name (reloc, addr);
		r_flag_set (r->flags, reloc_name, addr, bin_reloc_size (reloc));
	}
}

static int bin_relocs(RCore *r, int mode, int va) {
	bool bin_demangle = r_config_get_i (r->config, "bin.demangle");
	RList *relocs;
	RListIter *iter;
	RBinReloc *reloc = NULL;
	Sdb *db = NULL;
	char *sdb_module = NULL;
	int i = 0;

	va = VA_TRUE; // XXX relocs always vaddr?
	//this has been created for reloc object files
	relocs = r_bin_patch_relocs (r->bin);
	if (!relocs) {
		relocs = r_bin_get_relocs (r->bin);
	}

	if (IS_MODE_RAD (mode)) {
		r_cons_println ("fs relocs");
	} else if (IS_MODE_NORMAL (mode)) {
		r_cons_println ("[Relocations]");
	} else if (IS_MODE_JSON (mode)) {
		r_cons_print ("[");
	} else if (IS_MODE_SET (mode)) {
		r_flag_space_set (r->flags, "relocs");
	}
	RBinFile * binfile = r->bin->cur;
	RBinObject *binobj = binfile ? binfile->o: NULL;
	RBinInfo *info = binobj ? binobj->info: NULL;
	int cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;
	r_list_foreach (relocs, iter, reloc) {
		ut64 addr = rva (r->bin, reloc->paddr, reloc->vaddr, va);
		if (IS_MODE_SET (mode)) {
			set_bin_relocs (r, reloc, addr, &db, &sdb_module);
			if (cdsz) {
				r_meta_add (r->anal, R_META_TYPE_DATA, reloc->vaddr, reloc->vaddr + cdsz, NULL);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			r_cons_printf ("0x%08"PFMT64x"  %s\n", addr, reloc->import ? reloc->import->name : "");
		} else if (IS_MODE_RAD (mode)) {
			char *name = reloc->import
				? strdup (reloc->import->name)
				: (reloc->symbol ? strdup (reloc->symbol->name) : NULL);
			if (name && bin_demangle) {
				char *mn = r_bin_demangle (r->bin->cur, NULL, name, addr);
				if (mn) {
					free (name);
					name = mn;
				}
			}
			if (name) {
				r_cons_printf ("f %s%s%s @ 0x%08"PFMT64x"\n",
					r->bin->prefix ? r->bin->prefix : "reloc.",
					r->bin->prefix ? "." : "", name, addr);
				if (cdsz) {
					r_cons_printf ("f Cd %d @ 0x%08"PFMT64x"\n", cdsz, addr);
				}
				free (name);
			}
		} else if (IS_MODE_JSON (mode)) {
			if (iter->p) {
				r_cons_printf (",{\"name\":");
			} else {
				r_cons_printf ("{\"name\":");
			}
			// take care with very long symbol names! do not use sdb_fmt or similar
			if (reloc->import) {
				r_cons_printf ("\"%s\"", reloc->import->name);
			} else if (reloc->symbol) {
				r_cons_printf ("\"%s\"", reloc->symbol->name);
			} else {
				r_cons_printf ("null");
			}

			r_cons_printf (","
				"\"type\":\"%s\","
				"\"vaddr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d","
				"\"is_ifunc\":%s}",
				bin_reloc_type_name (reloc),
				reloc->vaddr, reloc->paddr,
				r_str_bool (reloc->is_ifunc));
		} else if (IS_MODE_NORMAL (mode)) {
			char *name = reloc->import
				? strdup (reloc->import->name)
				: reloc->symbol
				? strdup (reloc->symbol->name)
				: strdup ("null");
			if (bin_demangle) {
				char *mn = r_bin_demangle (r->bin->cur, NULL, name, addr);
				if (mn && *mn) {
					free (name);
					name = mn;
				}
			}
			r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" type=%s",
				addr, reloc->paddr, bin_reloc_type_name (reloc));
			if (reloc->import && reloc->import->name[0]) {
				r_cons_printf (" %s", name);
			} else if (reloc->symbol && name && name[0]) {
				r_cons_printf (" %s", name);
			}
			free (name);
			if (reloc->addend) {
				if (reloc->import && reloc->addend > 0) {
					r_cons_printf (" +");
				}
				if (reloc->addend < 0) {
					r_cons_printf (" - 0x%08"PFMT64x, -reloc->addend);
				} else {
					r_cons_printf (" 0x%08"PFMT64x, reloc->addend);
				}
			}
			if (reloc->is_ifunc) {
				r_cons_print (" (ifunc)");
			}
			r_cons_newline ();
		}
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("]");
	}
	if (IS_MODE_NORMAL (mode)) {
		r_cons_printf ("\n%i relocations\n", i);
	}

	R_FREE (sdb_module);
	sdb_free (db);
	db = NULL;

	return relocs != NULL;
}

#define MYDB 1
/* this is a hacky workaround that needs proper refactoring in Rbin to use Sdb */
#if MYDB
static Sdb *mydb = NULL;
static RList *osymbols = NULL;

static RBinSymbol *get_symbol(RBin *bin, RList *symbols, const char *name, ut64 addr) {
	RBinSymbol *symbol, *res = NULL;
	RListIter *iter;
	if (mydb && symbols && symbols != osymbols) {
		sdb_free (mydb);
		mydb = NULL;
		osymbols = symbols;
	}
	if (mydb) {
		if (name) {
			res = (RBinSymbol*)(void*)(size_t)
				sdb_num_get (mydb, sdb_fmt (0, "%x", sdb_hash (name)), NULL);
		} else {
			res = (RBinSymbol*)(void*)(size_t)
				sdb_num_get (mydb, sdb_fmt (0, "0x"PFMT64x, addr), NULL);
		}
	} else {
		mydb = sdb_new0 ();
		r_list_foreach (symbols, iter, symbol) {
			/* ${name}=${ptrToSymbol} */
			if (!sdb_num_add (mydb, sdb_fmt (0, "%x", sdb_hash (symbol->name)), (ut64)(size_t)symbol, 0)) {
			//	eprintf ("DUP (%s)\n", symbol->name);
			}
			/* 0x${vaddr}=${ptrToSymbol} */
			if (!sdb_num_add (mydb, sdb_fmt (0, "0x"PFMT64x, symbol->vaddr), (ut64)(size_t)symbol, 0)) {
			//	eprintf ("DUP (%s)\n", symbol->name);
			}
			if (name) {
				if (!res && !strcmp (symbol->name, name)) {
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
#else
static RList *osymbols = NULL;
static RBinSymbol *get_symbol(RBin *bin, RList *symbols, const char *name, ut64 addr) {
	RBinSymbol *symbol;
	RListIter *iter;
	r_list_foreach (symbols, iter, symbol) {
		if (name) {
			if (!strcmp (symbol->name, name))
				return symbol;
		} else {
			if (symbol->vaddr == addr) {
				return symbol;
			}
		}
	}
	return NULL;
}
#endif

/* XXX: This is a hack to get PLT references in rabin2 -i */
/* imp. is a prefix that can be rewritten by the symbol table */
static ut64 impaddr(RBin *bin, int va, const char *name) {
	RList *symbols;

	if (!name || !*name) {
		return false;
	}
	if (!(symbols = r_bin_get_symbols (bin))) {
		return false;
	}
	char *impname = sdb_fmt (2, "imp.%s", name);
	RBinSymbol *s = get_symbol (bin, symbols, impname, 0LL);
	if (s) {
		if (va) {
			return r_bin_get_vaddr (bin, s->paddr, s->vaddr);
		}
		return s->paddr;
	}
	return 0LL;
}

static int bin_imports(RCore *r, int mode, int va, const char *name) {
	RBinInfo *info = r_bin_get_info (r->bin);
	int bin_demangle = r_config_get_i (r->config, "bin.demangle");
	RBinImport *import;
	RListIter *iter;
	bool lit = info ? info->has_lit: false;
	char *str;
	int i = 0;

	RList *imports = r_bin_get_imports (r->bin);
	int cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("[");
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println ("fs imports");
	} else if (IS_MODE_NORMAL (mode)) {
		r_cons_println ("[Imports]");
	}
	r_list_foreach (imports, iter, import) {
		if (name && strcmp (import->name, name)) {
			continue;
		}
		char *symname = strdup (import->name);
		ut64 addr = lit ? impaddr (r->bin, va, symname): 0;
		if (bin_demangle) {
			char *dname = r_bin_demangle (r->bin->cur, NULL, symname, addr);
			if (dname) {
				free (symname);
				symname = r_str_newf ("sym.imp.%s", dname);
				free (dname);
			}
		}
		if (r->bin->prefix) {
			char *prname = r_str_newf ("%s.%s", r->bin->prefix, symname);
			free (symname);
			symname = prname;
		}
		if (IS_MODE_SET (mode)) {
			// TODO(eddyb) symbols that are imports.
			// Add a dword/qword for PE imports
			if (strstr (symname, ".dll_") && cdsz) {
				r_meta_add (r->anal, R_META_TYPE_DATA, addr, addr + cdsz, NULL);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			r_cons_println (symname);
		} else if (IS_MODE_JSON (mode)) {
			str = r_str_utf16_encode (symname, -1);
			str = r_str_replace (str, "\"", "\\\"", 1);
			r_cons_printf ("%s{\"ordinal\":%d,"
				"\"bind\":\"%s\","
				"\"type\":\"%s\",",
				iter->p ? "," : "",
				import->ordinal,
				import->bind,
				import->type);
			if (import->classname && import->classname[0]) {
				r_cons_printf ("\"classname\":\"%s\","
					"\"descriptor\":\"%s\",",
					import->classname,
					import->descriptor);
			}
			r_cons_printf ("\"name\":\"%s\",\"plt\":%"PFMT64d"}",
				str, addr);
			free (str);
		} else if (IS_MODE_RAD (mode)) {
			// TODO(eddyb) symbols that are imports.
		} else {
			const char *bind = r_str_get (import->bind);
			const char *type = r_str_get (import->type);
#if 0
			r_cons_printf ("ordinal=%03d plt=0x%08"PFMT64x" bind=%s type=%s",
				import->ordinal, addr, bind, type);
			if (import->classname && import->classname[0]) {
				r_cons_printf (" classname=%s", import->classname);
			}
			r_cons_printf (" name=%s", symname);
			if (import->descriptor && import->descriptor[0]) {
				r_cons_printf (" descriptor=%s", import->descriptor);
			}
			r_cons_newline ();
#else
			r_cons_printf ("%4d 0x%08"PFMT64x" %7s %7s ",
				import->ordinal, addr, bind, type);
			if (import->classname && import->classname[0]) {
				r_cons_printf ("%s.", import->classname);
			}
			r_cons_printf ("%s", symname);
			if (import->descriptor && import->descriptor[0]) {
				// Uh?
				r_cons_printf (" descriptor=%s", import->descriptor);
			}
			r_cons_newline ();
#endif
		}
		R_FREE (symname);
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("]");
	} else if (IS_MODE_NORMAL (mode)) {
		// r_cons_printf ("# %i imports\n", i);
	}
#if MYDB
	// NOTE: if we comment out this, it will leak.. but it will be faster
	// because it will keep the cache across multiple RBin calls
	osymbols = NULL;
	sdb_free (mydb);
	mydb = NULL;
#endif
	return true;
}

static const char *getPrefixFor(const char *s) {
	if (s) {
		if (!strcmp (s, "NOTYPE")) {
			return "loc";
		}
		if (!strcmp (s, "OBJECT")) {
			return "obj";
		}
	}
	return "sym";
}

typedef struct {
	const char *pfx; // prefix for flags
	char *name;      // raw symbol name
	char *nameflag;  // flag name for symbol
	char *demname;   // demangled raw symbol name
	char *demflag;   // flag name for demangled symbol
	char *classname; // classname
	char *classflag; // flag for classname
	char *methname;  // methods [class]::[method]
	char *methflag;  // methods flag sym.[class].[method]
} SymName;

static void snInit(RCore *r, SymName *sn, RBinSymbol *sym, const char *lang) {
#define MAXFLAG_LEN 128
	int bin_demangle = lang != NULL;
	const char *pfx;
	if (!r || !sym || !sym->name) return;
	pfx = getPrefixFor (sym->type);
	sn->name = strdup (sym->name);
	if (sym->dup_count) {
		sn->nameflag = r_str_newf ("%s.%s_%d", pfx, sym->name, sym->dup_count);
	} else {
		sn->nameflag = r_str_newf ("%s.%s", pfx, sym->name);
	}
	r_name_filter (sn->nameflag, MAXFLAG_LEN);
	if (sym->classname && sym->classname[0]) {
		sn->classname = strdup (sym->classname);
		sn->classflag = r_str_newf ("sym.%s.%s", sn->classname, sn->name);
		r_name_filter (sn->classflag, MAXFLAG_LEN);
		const char *name = sym->dname? sym->dname: sym->name;
		sn->methname = r_str_newf ("%s::%s", sn->classname, name);
		sn->methflag = r_str_newf ("sym.%s.%s", sn->classname, name);
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
		sn->demname = r_bin_demangle (r->bin->cur, lang, sn->name, sym->vaddr);
		if (sn->demname) {
			sn->demflag = r_str_newf ("%s.%s", pfx, sn->demname);
			r_name_filter (sn->demflag, -1);
		}
	}
}

static void snFini(SymName *sn) {
	R_FREE (sn->name);
	R_FREE (sn->nameflag);
	R_FREE (sn->demname);
	R_FREE (sn->demflag);
	R_FREE (sn->classname);
	R_FREE (sn->classflag);
	R_FREE (sn->methname);
	R_FREE (sn->methflag);
}


static bool isAnExport(RBinSymbol *s) {
	/* workaround for some bin plugs */
	if (!strncmp (s->name, "imp.", 4)) {
		return false;
	}
	return (s->bind && !strcmp (s->bind, "GLOBAL"));
}

static int bin_symbols_internal(RCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, bool exponly, const char *args) {
	RBinInfo *info = r_bin_get_info (r->bin);
	RList *entries = r_bin_get_entries (r->bin);
	RBinSymbol *symbol;
	RBinAddr *entry;
	RListIter *iter;
	RList *symbols;
	const char *lang;
	bool firstexp = true;
	bool printHere = false;
	int i = 0, is_arm, lastfs = 's';
	bool bin_demangle = r_config_get_i (r->config, "bin.demangle");
	if (!info) {
		return 0;
	}

	if (args && *args == '.') {
		printHere = true;
	}

	is_arm = info && info->arch && !strncmp (info->arch, "arm", 3);
	lang = bin_demangle ? r_config_get (r->config, "bin.lang") : NULL;

	symbols = r_bin_get_symbols (r->bin);
	r_space_set (&r->anal->meta_spaces, "bin");

	if (IS_MODE_JSON (mode) && !printHere) {
		r_cons_printf ("[");
	} else if (IS_MODE_SET (mode)) {
		r_flag_space_set (r->flags, "symbols");
	} else if (!at && exponly) {
		if (IS_MODE_RAD (mode)) {
			r_cons_printf ("fs exports\n");
		} else if (IS_MODE_NORMAL (mode)) {
			r_cons_printf (printHere ? "" : "[Exports]\n");
		}
	} else if (!at && !exponly) {
		if (IS_MODE_RAD (mode)) {
			r_cons_printf ("fs symbols\n");
		} else if (IS_MODE_NORMAL (mode)) {
			r_cons_printf (printHere ? "" : "[Symbols]\n");
		}
	}

	r_list_foreach (symbols, iter, symbol) {
		ut64 addr = rva (r->bin, symbol->paddr, symbol->vaddr, va);
		int len = symbol->size ? symbol->size : 32;
		SymName sn;

		if (exponly && !isAnExport (symbol)) {
			continue;
		}
		if (name && strcmp (symbol->name, name)) {
			continue;
		}
		if (at && (!symbol->size || !is_in_range (at, addr, symbol->size))) {
			continue;
		}
		if ((printHere && !is_in_range (r->offset, symbol->paddr, len))
				&& (printHere && !is_in_range (r->offset, addr, len))) {
			continue;
		}
		snInit (r, &sn, symbol, lang);

		if (IS_MODE_SET (mode)) {
			if (is_arm && info->bits < 33) { // 16 or 32
				int force_bits = 0;
				if (symbol->paddr & 1 || symbol->bits == 16) {
					force_bits = 16;
				} else if (info->bits == 16 && symbol->bits == 32) {
					force_bits = 32;
				} else if (!(symbol->paddr & 1) && symbol->bits == 32) {
					force_bits = 32;
				}
				if (force_bits) {
					r_anal_hint_set_bits (r->anal, addr, force_bits);
				}
			}
			if (!strncmp (symbol->name, "imp.", 4)) {
				if (lastfs != 'i') {
					r_flag_space_set (r->flags, "imports");
				}
				lastfs = 'i';
			} else {
				if (lastfs != 's') {
					r_flag_space_set (r->flags, "symbols");
				}
				lastfs = 's';
			}
			/* If that's a Classed symbol (method or so) */
			if (sn.classname) {
				RFlagItem *fi = NULL;
				char *comment = NULL;
				fi = r_flag_get (r->flags, sn.methflag);
				if (r->bin->prefix) {
					char *prname;
					prname = r_str_newf ("%s.%s", r->bin->prefix, sn.methflag);
					r_name_filter (sn.methflag, -1);
					free (sn.methflag);
					sn.methflag = prname;
				}
				if (fi) {
					r_flag_item_set_realname (fi, sn.methname);
					if ((fi->offset - r->flags->base) == addr) {
						comment = fi->comment ? strdup (fi->comment) : NULL;
						r_flag_unset (r->flags, fi);
					}
				} else {
					fi = r_flag_set (r->flags, sn.methflag, addr, symbol->size);
					comment = fi->comment ? strdup (fi->comment) : NULL;
					if (comment) {
						r_flag_item_set_comment (fi, comment);
						R_FREE (comment);
					}
				}
			} else {
				const char *fn, *n;
				RFlagItem *fi;
				n = sn.demname ? sn.demname : sn.name;
				fn = sn.demflag ? sn.demflag : sn.nameflag;
				char *fnp = (r->bin->prefix) ?
					r_str_newf ("%s.%s", r->bin->prefix, fn):
					strdup (fn);
				fi = r_flag_set (r->flags, fnp, addr, symbol->size);
				if (fi) {
					r_flag_item_set_realname (fi, n);
				} else {
					if (fn) {
						eprintf ("[Warning] Can't find flag (%s)\n", fn);
					}
				}
				free (fnp);
			}
			if (sn.demname) {
				r_meta_add (r->anal, R_META_TYPE_COMMENT,
					addr, symbol->size, sn.demname);
			}
		} else if (IS_MODE_JSON (mode)) {
			char *str = r_str_utf16_encode (symbol->name, -1);
			// str = r_str_replace (str, "\"", "\\\"", 1);
			r_cons_printf ("%s{\"name\":\"%s\","
				"\"demname\":\"%s\","
				"\"flagname\":\"%s\","
				"\"ordinal\":%d,"
				"\"bind\":\"%s\","
				"\"size\":%d,"
				"\"type\":\"%s\","
				"\"vaddr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d"}",
				((exponly && firstexp) || printHere) ? "" : (iter->p ? "," : ""),
				str,
				sn.demname? sn.demname: "",
				sn.nameflag,
				symbol->ordinal,
				symbol->bind,
				(int)symbol->size,
				symbol->type,
				(ut64)addr, (ut64)symbol->paddr);
			free (str);
		} else if (IS_MODE_SIMPLE (mode)) {
			const char *name = sn.demname? sn.demname: symbol->name;
			r_cons_printf ("0x%08"PFMT64x" %d %s\n",
				addr, (int)symbol->size, name);
		} else if (IS_MODE_SIMPLEST (mode)) {
			const char *name = sn.demname? sn.demname: symbol->name;
			r_cons_printf ("%s\n", name);
		} else if (IS_MODE_RAD (mode)) {
			RBinFile *binfile;
			RBinPlugin *plugin;
			char *name = strdup (sn.demname? sn.demname: symbol->name);
			r_name_filter (name, -1);
			if (!strncmp (name, "imp.", 4)) {
				if (lastfs != 'i')
					r_cons_printf ("fs imports\n");
				lastfs = 'i';
			} else {
				if (lastfs != 's') {
					r_cons_printf ("fs %s\n",
						exponly? "exports": "symbols");
				}
				lastfs = 's';
			}
			if (r->bin->prefix) {
				if (symbol->dup_count) {
					r_cons_printf ("f %s.sym.%s_%d %u 0x%08"PFMT64x"\n",
						r->bin->prefix, name, symbol->dup_count, symbol->size, addr);
				} else {
					r_cons_printf ("f %s.sym.%s %u 0x%08"PFMT64x"\n",
						r->bin->prefix, name, symbol->size, addr);
				}
			} else {
				if (symbol->dup_count) {
					r_cons_printf ("f sym.%s_%d %u 0x%08"PFMT64x"\n",
						name, symbol->dup_count, symbol->size, addr);
				} else {
					r_cons_printf ("f sym.%s %u 0x%08"PFMT64x"\n",
						name, symbol->size, addr);
				}
			}
			binfile = r_core_bin_cur (r);
			plugin = r_bin_file_cur_plugin (binfile);
			if (plugin && plugin->name) {
				if (!strncmp (plugin->name, "pe", 2)) {
					char *p, *module = strdup (symbol->name);
					p = strstr (module, ".dll_");
					if (p) {
						const char *symname = p + 5;
						*p = 0;
						if (r->bin->prefix) {
							r_cons_printf ("k bin/pe/%s/%d=%s.%s\n",
								module, symbol->ordinal, r->bin->prefix, symname);
						} else {
							r_cons_printf ("k bin/pe/%s/%d=%s\n",
								module, symbol->ordinal, symname);
						}
					}
					free (module);
				}
			}
		} else {
			const char *bind = r_str_get (symbol->bind);
			const char *type = r_str_get (symbol->type);
			const char *name = r_str_get (sn.demname? sn.demname: symbol->name);
			// const char *fwd = r_str_get (symbol->forwarder);
			r_cons_printf ("%03u 0x%08"PFMT64x" 0x%08"PFMT64x" "
				"%6s %6s %4d %s\n",
				symbol->ordinal,
				symbol->paddr, addr, bind, type,
				symbol->size, name);
			// r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" ord=%03u "
			//	"fwd=%s sz=%u bind=%s type=%s name=%s\n",
			//	addr, symbol->paddr, symbol->ordinal, fwd,
			//	symbol->size, bind, type, name);
		}
		snFini (&sn);
		i++;
		if (exponly && firstexp) {
			firstexp = false;
		}
		if (printHere) {
			break;
		}
	}

	//handle thumb and arm for entry point since they are not present in symbols
	if (is_arm) {
		r_list_foreach (entries, iter, entry) {
			if (IS_MODE_SET (mode)) {
				if (info->bits < 33) { // 16 or 32
					int force_bits = 0;
					ut64 addr = rva (r->bin, entry->paddr, entry->vaddr, va);
					if (entry->paddr & 1 || entry->bits == 16) {
						force_bits = 16;
					} else if (info->bits == 16 && entry->bits == 32) {
						force_bits = 32;
					} else if (!(entry->paddr & 1)) {
						force_bits = 32;
					}
					if (force_bits) {
						r_anal_hint_set_bits (r->anal, addr, force_bits);
					}
				}
			}
		}
	}
	if (IS_MODE_JSON (mode) && !printHere) r_cons_printf ("]");
#if 0
	if (IS_MODE_NORMAL (mode) && !at) {
		r_cons_printf ("\n%i %s\n", i, exponly ? "exports" : "symbols");
	}
#endif

	r_space_set (&r->anal->meta_spaces, NULL);
	return true;
}

static int bin_exports(RCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, const char *args) {
	return bin_symbols_internal (r, mode, laddr, va, at, name, true, args);
}

static int bin_symbols(RCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, const char *args) {
	return bin_symbols_internal (r, mode, laddr, va, at, name, false, args);
}

static char *build_hash_string(int mode, const char *chksum, ut8 *data, ut32 datalen) {
	char *chkstr = NULL, *aux, *ret = NULL;
	const char *ptr = chksum;
	char tmp[128];
	int i;
	do {
		for (i = 0; *ptr && *ptr != ',' && i < sizeof (tmp) -1; i++) {
			tmp[i] = *ptr++;
		}
		tmp[i] = '\0';
		r_str_trim_head_tail (tmp);
		chkstr = r_hash_to_string (NULL, tmp, data, datalen);
		if (!chkstr) {
			if (*ptr && *ptr == ',') {
				ptr++;
			}
			continue;
		}
		if (IS_MODE_SIMPLE (mode)) {
			aux = r_str_newf ("%s ", chkstr);
		} else if (IS_MODE_JSON (mode)) {
			aux = r_str_newf ("\"%s\":\"%s\",", tmp, chkstr);
		} else {
			aux = r_str_newf ("%s=%s ", tmp, chkstr);
		}
		ret = r_str_append (ret, aux);
		free (chkstr);
		free (aux);
		if (*ptr && *ptr == ',') ptr++;
	} while (*ptr);

	return ret;
}

static int bin_sections(RCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, const char *chksum) {
	char *str = NULL;
	RBinSection *section;
	RBinInfo *info = NULL;
	RList *sections;
	RListIter *iter;
	int i = 0;
	int fd = -1;
	bool printHere = false;
	sections = r_bin_get_sections (r->bin);
	bool inDebugger = r_config_get_i (r->config, "cfg.debug");
	SdbHash *dup_chk_ht = ht_new (NULL, NULL, NULL);
	bool ret = false;

	if (!dup_chk_ht) {
		return false;
	}
	
	if (chksum && *chksum == '.') {
		printHere = true;
	}
	if (IS_MODE_JSON (mode) && !printHere) r_cons_printf ("[");
	else if (IS_MODE_RAD (mode) && !at) r_cons_printf ("fs sections\n");
	else if (IS_MODE_NORMAL (mode) && !at && !printHere) r_cons_printf ("[Sections]\n");
	else if (IS_MODE_NORMAL (mode) && printHere) r_cons_printf("Current section\n");
	else if (IS_MODE_SET (mode)) {
		fd = r_core_file_cur_fd (r);
		r_flag_space_set (r->flags, "sections");
	}
	r_list_foreach (sections, iter, section) {
		char perms[] = "-----";
		int va_sect = va;
		ut64 addr;

		if (va && !(section->srwx & R_BIN_SCN_READABLE)) {
			va_sect = VA_NOREBASE;
		}
		addr = rva (r->bin, section->paddr, section->vaddr, va_sect);

		if (name && strcmp (section->name, name)) {
			continue;
		}

		if ((printHere && !(section->paddr <= r->offset && r->offset < (section->paddr + section->size)))
				&& (printHere && !(addr <= r->offset && r->offset < (addr + section->size)))) {
			continue;
		}

		r_name_filter (section->name, sizeof (section->name));
		if (at && (!section->size || !is_in_range (at, addr, section->size))) {
			continue;
		}

		if (section->srwx & R_BIN_SCN_MAP) perms[0] = 'm';
		if (section->srwx & R_BIN_SCN_SHAREABLE) perms[1] = 's';
		if (section->srwx & R_BIN_SCN_READABLE) perms[2] = 'r';
		if (section->srwx & R_BIN_SCN_WRITABLE) perms[3] = 'w';
		if (section->srwx & R_BIN_SCN_EXECUTABLE) perms[4] = 'x';

		if (IS_MODE_SET (mode)) {
#if LOAD_BSS_MALLOC
			if (!strcmp (section->name, ".bss")) {
				// check if there's already a file opened there
				int loaded = 0;
				RListIter *iter;
				RIOMap *m;
				r_list_foreach (r->io->maps, iter, m) {
					if (m->from == addr) {
						loaded = 1;
					}
				}
				if (!loaded && !inDebugger) {
					r_core_cmdf (r, "on malloc://%d 0x%"PFMT64x" # bss\n",
						section->vsize, addr);
				}
			}
#endif
			r_name_filter (section->name, 128);
			if (section->format) {
				// This is damn slow if section vsize is HUGE
				if (section->vsize < 1024 * 1024 * 2) {
					r_core_cmdf (r, "%s @ 0x%"PFMT64x, section->format, section->vaddr);
				}
			}
			if (r->bin->prefix) {
				str = r_str_newf ("%s.section.%s", r->bin->prefix, section->name);
			} else {
				str = r_str_newf ("section.%s", section->name);

			}
			r_flag_set (r->flags, str, addr, section->size);
			R_FREE (str);

			if (r->bin->prefix) {
				str = r_str_newf ("%s.section_end.%s", r->bin->prefix, section->name);
			} else {
				str = r_str_newf ("section_end.%s", section->name);
			}
			r_flag_set (r->flags, str, addr + section->vsize, 0);
			R_FREE (str);

			if (section->arch || section->bits) {
				const char *arch = section->arch;
				int bits = section->bits;
				if (info) {
					if (!arch) {
						arch = info->arch;
					}
					if (!bits) {
						bits = info->bits;
					}
				}
				//r_io_section_set_archbits (r->io, addr, arch, bits);
			}
			char *pfx = r->bin->prefix;
			str = r_str_newf ("[%02d] %s section size %" PFMT64d" named %s%s%s",
				i, perms, section->size,
				pfx? pfx: "", pfx? ".": "", section->name);
			r_meta_add (r->anal, R_META_TYPE_COMMENT, addr, addr, str);
			R_FREE (str);
			if (section->add) {
				str = r_str_newf ("%"PFMT64x".%"PFMT64x".%"PFMT64x".%"PFMT64x".%"PFMT32u".%s.%"PFMT32u".%d",
					section->paddr, addr, section->size, section->vsize, section->srwx, section->name, r->bin->cur->id, fd);
				if (!ht_find (dup_chk_ht, str, NULL) && r_io_section_add (r->io, section->paddr, addr,
						section->size, section->vsize,
						section->srwx, section->name,
						r->bin->cur->id, fd)) {
					ht_insert (dup_chk_ht, str, NULL);
				}
				R_FREE (str);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			char *hashstr = NULL;
			if (chksum) {
				ut8 *data = malloc (section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				r_io_pread_at (r->io, section->paddr, data, datalen);
				hashstr = build_hash_string (mode, chksum,
							data, datalen);
				free (data);
			}
			r_cons_printf ("0x%"PFMT64x" 0x%"PFMT64x" %s %s%s%s\n",
				addr, addr + section->size,
				perms,
				hashstr ? hashstr : "", hashstr ? " " : "",
				section->name
			);
			free (hashstr);
		} else if (IS_MODE_JSON (mode)) {
			char *hashstr = NULL;
			if (chksum) {
				ut8 *data = malloc (section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				r_io_pread_at (r->io, section->paddr, data, datalen);
				hashstr = build_hash_string (mode, chksum,
							data, datalen);
				free (data);

			}
			r_cons_printf ("%s{\"name\":\"%s\","
				"\"size\":%"PFMT64d","
				"\"vsize\":%"PFMT64d","
				"\"flags\":\"%s\","
				"%s"
				"\"paddr\":%"PFMT64d","
				"\"vaddr\":%"PFMT64d"}",
				(iter->p && !printHere)?",":"",
				section->name,
				section->size,
				section->vsize,
				perms,
				hashstr ? hashstr : "",
				section->paddr,
				addr);
			free (hashstr);
		} else if (IS_MODE_RAD (mode)) {
			if (!strcmp (section->name, ".bss") && !inDebugger) {
#if LOAD_BSS_MALLOC
				r_cons_printf ("on malloc://%d 0x%"PFMT64x" # bss\n",
						section->vsize, addr);
#endif
			}
			if (r->bin->prefix) {
				r_cons_printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s.%s %d\n",
					section->paddr, addr, section->size, section->vsize,
					r->bin->prefix, section->name, (int)section->srwx);
			} else {
				r_cons_printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d\n",
					section->paddr, addr, section->size, section->vsize,
					section->name, (int)section->srwx);

			}
			if (section->arch || section->bits) {
				const char *arch = section->arch;
				int bits = section->bits;
				if (info) {
					if (!arch) arch = info->arch;
					if (!bits) bits = info->bits;
				}
				if (!arch) {
					arch = r_config_get (r->config, "asm.arch");
				}
				r_cons_printf ("Sa %s %d @ 0x%08"
					PFMT64x"\n", arch, bits, addr);
			}
			if (r->bin->prefix) {
				r_cons_printf ("f %s.section.%s %"PFMT64d" 0x%08"PFMT64x"\n",
						r->bin->prefix, section->name, section->size, addr);
				r_cons_printf ("f %s.section_end.%s 1 0x%08"PFMT64x"\n",
						r->bin->prefix, section->name, addr + section->vsize);
				r_cons_printf ("CC section %i va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
						"rwx=%s %s.%s @ 0x%08"PFMT64x"\n",
						i, addr, section->paddr, section->size, section->vsize,
						perms, r->bin->prefix, section->name, addr);

			} else {
				r_cons_printf ("f section.%s %"PFMT64d" 0x%08"PFMT64x"\n",
						section->name, section->size, addr);
				r_cons_printf ("f section_end.%s 1 0x%08"PFMT64x"\n",
						section->name, addr + section->vsize);
				r_cons_printf ("CC section %i va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
						"rwx=%s %s @ 0x%08"PFMT64x"\n",
						i, addr, section->paddr, section->size, section->vsize,
						perms, section->name, addr);
			}
		} else {
			char *hashstr = NULL, str[128];
			if (chksum) {
				ut8 *data = malloc (section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				// VA READ IS BROKEN?
				r_io_pread_at (r->io, section->paddr, data, datalen);
				hashstr = build_hash_string (mode, chksum,
							data, datalen);
				free (data);
			}
			if (section->arch || section->bits) {
				const char *arch = section->arch;
				int bits = section->bits;
				if (!arch && info) {
					arch = info->arch;
					if (!arch) {
						arch = r_config_get (r->config, "asm.arch");
					}
				}
				if (!bits) {
					bits = info? info->bits: R_SYS_BITS;
				}
				snprintf (str, sizeof (str), "arch=%s bits=%d ",
					r_str_get2 (arch), bits);
			} else {
				str[0] = 0;
			}
			if (r->bin->prefix) {
#if 0
				r_cons_printf ("idx=%02i vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
					"perm=%s %s%sname=%s.%s\n",
					i, addr, section->paddr, section->size, section->vsize,
					perms, str, hashstr ?hashstr : "", r->bin->prefix, section->name);
#endif
				r_cons_printf ("%02i 0x%08"PFMT64x" %5"PFMT64d" 0x%08"PFMT64x" %5"PFMT64d" "
					"%s %s% %s.%s\n",
					i, section->paddr, section->size, addr, section->vsize,
					perms, str, hashstr ?hashstr : "", r->bin->prefix, section->name);
			} else {
#if 0
				r_cons_printf ("idx=%02i vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
					"perm=%s %s%sname=%s\n",
					i, addr, section->paddr, section->size, section->vsize,
					perms, str, hashstr ?hashstr : "", section->name);
#endif
				r_cons_printf ("%02i 0x%08"PFMT64x" %5"PFMT64d" 0x%08"PFMT64x" %5"PFMT64d" "
					"%s %s%s%s\n",
					i, section->paddr, (ut64)section->size, addr, (ut64)section->vsize,
					perms, str, hashstr ?hashstr : "", section->name);
			}
			free (hashstr);
		}
		i++;
		if (printHere) {
			break;
		}
	}
	if (r->bin && r->bin->cur && r->io && !r_io_desc_is_dbg (r->io->desc)) {
		r_io_section_apply_bin (r->io, r->bin->cur->id, R_IO_SECTION_APPLY_FOR_ANALYSIS);
	}
	if (IS_MODE_JSON (mode) && !printHere) {
		r_cons_println ("]");
	} else if (IS_MODE_NORMAL (mode) && !at && !printHere) {
		// r_cons_printf ("\n%i sections\n", i);
	}

	ret = true;
out:
	ht_free (dup_chk_ht);
	return ret;
}

static int bin_fields(RCore *r, int mode, int va) {
	RList *fields;
	RListIter *iter;
	RBinField *field;
	int i = 0;
	RBin *bin = r->bin;
	RBinFile *binfile = r_core_bin_cur (r);
	ut64 size = binfile ? binfile->size : UT64_MAX;
	ut64 baddr = r_bin_get_baddr (r->bin);

	if (!(fields = r_bin_get_fields (bin))) {
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("[");
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println ("fs header");
	} else if (IS_MODE_NORMAL (mode)) {
		r_cons_println ("[Header fields]");
	}
//why this? there is an overlap in bin_sections with ehdr
//because there can't be two sections with the same name
#if 0
	else if (IS_MODE_SET (mode)) {
		// XXX: Need more flags??
		// this will be set even if the binary does not have an ehdr
		int fd = r_core_file_cur_fd(r);
		r_io_section_add (r->io, 0, baddr, size, size, 7, "ehdr", 0, fd);
	}
#endif
	r_list_foreach (fields, iter, field) {
		ut64 addr = rva (bin, field->paddr, field->vaddr, va);

		if (IS_MODE_RAD (mode)) {
			r_name_filter (field->name, -1);
			r_cons_printf ("f header.%s @ 0x%08"PFMT64x"\n", field->name, addr);
			if (field->comment && *field->comment) {
				r_cons_printf ("CC %s @ 0x%"PFMT64x"\n", field->comment, addr);
			}
			if (field->format && *field->format) {
				r_cons_printf ("pf.%s %s\n", field->name, field->format);
			}
		} else if (IS_MODE_JSON (mode)) {
			r_cons_printf ("%s{\"name\":\"%s\","
				"\"vaddr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d,
				iter->p? ",": "",
				field->name,
				field->vaddr,
				field->paddr
				);
			if (field->comment && *field->comment) {
				// TODO: filter comment before json
				r_cons_printf (",\"comment\":\"%s\"", field->comment);
			}
			if (field->format && *field->format) {
				// TODO: filter comment before json
				r_cons_printf (",\"format\":\"%s\"", field->format);
			}
			r_cons_printf ("}");
		} else if (IS_MODE_NORMAL (mode)) {
			const bool haveComment = (field->comment && *field->comment);
			r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %s%s%s\n",
				field->vaddr, field->paddr, field->name,
				haveComment? "; ": "",
				haveComment? field->comment: "");
		}
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_printf ("]");
	} else if (IS_MODE_RAD (mode)) {
		/* add program header section */
		r_cons_printf ("S 0 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x" ehdr rwx\n",
			baddr, size, size);
	} else if (IS_MODE_NORMAL (mode)) {
		r_cons_printf ("\n%i fields\n", i);
	}

	return true;
}

static char* get_rp (const char* rtype) {
	char *rp = NULL;
	switch(rtype[0]) {
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

static int bin_classes(RCore *r, int mode) {
	RListIter *iter, *iter2, *iter3;
	RBinSymbol *sym;
	RBinClass *c;
	RBinField *f;
	char *name;
	RList *cs = r_bin_get_classes (r->bin);
	if (!cs) {
		if (IS_MODE_JSON (mode)) {
			r_cons_print("[]");
		}
		return false;
	}
	// XXX: support for classes is broken and needs more love
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("[");
	} else if (IS_MODE_SET (mode)) {
		if (!r_config_get_i (r->config, "bin.classes")) {
			return false;
		}
		r_flag_space_set (r->flags, "classes");
	} else if (IS_MODE_RAD (mode)) {
		r_cons_println ("fs classes");
	}

	r_list_foreach (cs, iter, c) {
		if (!c || !c->name || !c->name[0]) {
			continue;
		}
		name = strdup (c->name);
		r_name_filter (name, 0);
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
			const char *classname = sdb_fmt (0, "class.%s", name);
			r_flag_set (r->flags, classname, c->addr, 1);
			r_list_foreach (c->methods, iter2, sym) {
				char *mflags = r_core_bin_method_flags_str (sym->method_flags, mode);
				char *method = sdb_fmt (1, "method%s.%s.%s",
					mflags, c->name, sym->name);
				R_FREE (mflags);
				r_name_filter (method, -1);
				r_flag_set (r->flags, method, sym->vaddr, 1);
			}
		} else if (IS_MODE_SIMPLE (mode)) {
			r_cons_printf ("0x%08"PFMT64x" [0x%08"PFMT64x" - 0x%08"PFMT64x"] %s%s%s\n",
				c->addr, at_min, at_max, c->name, c->super ? " " : "",
				c->super ? c->super : "");
		} else if (IS_MODE_RAD (mode)) {
			r_cons_printf ("\"f class.%s = 0x%"PFMT64x"\"\n",
				name, at_min);
			if (c->super) {
				r_cons_printf ("\"f super.%s.%s = %d\"\n",
					c->name, c->super, c->index);
			}
			r_list_foreach (c->methods, iter2, sym) {
				char *mflags = r_core_bin_method_flags_str (sym->method_flags, mode);
				char *cmd = r_str_newf ("\"f method%s.%s.%s = 0x%"PFMT64x"\"\n", mflags, c->name, sym->name, sym->vaddr);
				r_str_replace_char (cmd, '\n', 0);
				r_cons_printf ("%s\n", cmd);
				R_FREE (mflags);
				free (cmd);
			}
		} else if (IS_MODE_JSON (mode)) {
			if (c->super) {
				r_cons_printf ("%s{\"classname\":\"%s\",\"addr\":%"PFMT64d",\"index\":%d,\"super\":\"%s\",\"methods\":[",
					iter->p ? "," : "", c->name, c->addr,
					c->index, c->super);
			} else {
				r_cons_printf ("%s{\"classname\":\"%s\",\"addr\":%"PFMT64d",\"index\":%d,\"methods\":[",
					iter->p ? "," : "", c->name, c->addr,
					c->index);
			}
			r_list_foreach (c->methods, iter2, sym) {
				if (sym->method_flags) {
					char *mflags = r_core_bin_method_flags_str (sym->method_flags, mode);
					r_cons_printf ("%s{\"name\":\"%s\",\"flags\":%s,\"addr\":%"PFMT64d"}",
						iter2->p? ",": "", sym->name, mflags, sym->vaddr);
					R_FREE (mflags);
				} else {
					r_cons_printf ("%s{\"name\":\"%s\",\"addr\":%"PFMT64d"}",
						iter2->p? ",": "", sym->name, sym->vaddr);
				}
			}
			r_cons_printf ("], \"fields\":[");
			r_list_foreach (c->fields, iter3, f) {
				if (f->flags) {
					char *mflags = r_core_bin_method_flags_str (f->flags, mode);
					r_cons_printf ("%s{\"name\":\"%s\",\"flags\":%s,\"addr\":%"PFMT64d"}",
						iter3->p? ",": "", f->name, mflags, f->vaddr);
					R_FREE (mflags);
				} else {
					r_cons_printf ("%s{\"name\":\"%s\",\"addr\":%"PFMT64d"}",
						iter3->p? ",": "", f->name, f->vaddr);
				}
			}
			r_cons_printf ("]}");
		} else if (IS_MODE_CLASSDUMP (mode)) {
			char *rp = NULL;
			if (c) {
				//TODO -> Print Superclass
				r_cons_printf ("@interface %s :  \n{\n", c->name);
				r_list_foreach (c->fields, iter2, f) {
					if (f->name && r_regex_match ("ivar","e", f->name)) {
						r_cons_printf ("  %s %s\n", f->type, f->name);
					}
				}
				r_cons_printf ("}\n");
				r_list_foreach (c->methods, iter3, sym) {
					if (sym->rtype && sym->rtype[0] != '@') {
						rp = get_rp (sym->rtype);
						r_cons_printf ("%s (%s) %s\n", strncmp (sym->type,"METH",4) ? "+": "-", rp, sym->dname? sym->dname: sym->name);
					}
				}
				r_cons_printf ("@end\n");
			}
		} else {
			int m = 0;
			r_cons_printf ("0x%08"PFMT64x" [0x%08"PFMT64x" - 0x%08"PFMT64x"] (sz %"PFMT64d") class %d %s",
				c->addr, at_min, at_max, (at_max - at_min), c->index, c->name);
			if (c->super) {
				r_cons_printf (" super: %s\n", c->super);
			} else {
				r_cons_newline ();
			}
			r_list_foreach (c->methods, iter2, sym) {
				char *mflags = r_core_bin_method_flags_str (sym->method_flags, mode);
				r_cons_printf ("0x%08"PFMT64x" method %d %s %s\n",
					sym->vaddr, m, mflags, sym->dname? sym->dname: sym->name);
				R_FREE (mflags);
				m++;
			}
		}
		free (name);
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("]");
	}

	return true;
}

static int bin_size(RCore *r, int mode) {
	ut64 size = r_bin_get_size (r->bin);
	if (IS_MODE_SIMPLE (mode) || IS_MODE_JSON (mode)) {
		r_cons_printf ("%"PFMT64u"\n", size);
	} else if (IS_MODE_RAD (mode)) {
		r_cons_printf ("f bin_size @ %"PFMT64u"\n", size);
	} else if (IS_MODE_SET (mode)) {
		r_core_cmdf (r, "f bin_size @ %"PFMT64u"\n", size);
	} else {
		r_cons_printf ("%"PFMT64u"\n", size);
	}
	return true;
}

static int bin_libs(RCore *r, int mode) {
	RList *libs;
	RListIter *iter;
	char* lib;
	int i = 0;

	if (!(libs = r_bin_get_libs (r->bin))) {
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("[");
	} else if (IS_MODE_NORMAL (mode)) {
		r_cons_println ("[Linked libraries]");
	}
	r_list_foreach (libs, iter, lib) {
		if (IS_MODE_SET (mode)) {
			// Nothing to set.
			// TODO: load libraries with iomaps?
		} else if (IS_MODE_RAD (mode)) {
			r_cons_printf ("CCa entry0 %s\n", lib);
		} else if (IS_MODE_JSON (mode)) {
			r_cons_printf ("%s\"%s\"", iter->p ? "," : "", lib);
		} else {
			// simple and normal print mode
			r_cons_println (lib);
		}
		i++;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("]");
	} else if (IS_MODE_NORMAL (mode)) {
		if (i == 1) {
			r_cons_printf ("\n%i library\n", i);
		} else {
			r_cons_printf ("\n%i libraries\n", i);
		}
	}
	return true;
}

static void bin_mem_print(RList *mems, int perms, int depth, int mode) {
	RBinMem *mem;
	RListIter *iter;
	if (!mems) {
		return;
	}
	r_list_foreach (mems, iter, mem) {
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("{\"name\":\"%s\",\"size\":%d,\"address\":%d,"
					"\"flags\":\"%s\"}", mem->name, mem->size,
					mem->addr, r_str_rwx_i (mem->perms & perms));
		} else if (IS_MODE_SIMPLE (mode)) {
			r_cons_printf ("0x%08"PFMT64x"\n", mem->addr);
		} else {
			r_cons_printf ("0x%08"PFMT64x" +0x%04x %s %*s%-*s\n",
					mem->addr, mem->size, r_str_rwx_i (mem->perms & perms),
					depth, "", 20-depth, mem->name);
		}
		if (mem->mirrors) {
			if (IS_MODE_JSON (mode)) {
				r_cons_printf (",");
			}
			bin_mem_print (mem->mirrors, mem->perms & perms, depth + 1, mode);
		}
		if (IS_MODE_JSON(mode)) {
			if (iter->n) {
				r_cons_printf (",");
			}
		}
	}
}

static int bin_mem(RCore *r, int mode) {
	RList *mem = NULL;
	if (!r)	return false;
	if (!IS_MODE_JSON(mode)) {
		if (!(IS_MODE_RAD (mode) || IS_MODE_SET (mode))) {
			r_cons_println ("[Memory]\n");
		}
	}
	if (!(mem = r_bin_get_mem (r->bin))) {
		if (IS_MODE_JSON (mode)) {
			r_cons_print("[]");
		}
		return false;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_print ("[");
		bin_mem_print (mem, 7, 0, R_CORE_BIN_JSON);
		r_cons_println ("]");
		return true;
	} else if (!(IS_MODE_RAD (mode) || IS_MODE_SET (mode))) {
		bin_mem_print (mem, 7, 0, mode);
	}
	return true;
}

static void bin_pe_versioninfo(RCore *r, int mode) {
	Sdb *sdb = NULL;
	int num_version = 0;
	int num_stringtable = 0;
	int num_string = 0;
	const char *format_version = "bin/cur/info/vs_version_info/VS_VERSIONINFO%d";
	const char *format_stringtable = "%s/string_file_info/stringtable%d";
	const char *format_string = "%s/string%d";
	if (!IS_MODE_JSON (mode)) {
		r_cons_printf ("=== VS_VERSIONINFO ===\n\n");
	}
	bool firstit_dowhile = true;
	do {
		char path_version[256] = R_EMPTY;
		snprintf (path_version, sizeof (path_version), format_version, num_version);
		if (!(sdb = sdb_ns_path (r->sdb, path_version, 0))) {
			break;
		}
		if (!firstit_dowhile && IS_MODE_JSON (mode)) { r_cons_printf (","); }
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("{\"VS_FIXEDFILEINFO\":{");
		} else {
			r_cons_printf ("# VS_FIXEDFILEINFO\n\n");
		}
		char path_fixedfileinfo[256] = R_EMPTY;
		snprintf (path_fixedfileinfo, sizeof (path_fixedfileinfo), "%s/fixed_file_info", path_version);
		if (!(sdb = sdb_ns_path (r->sdb, path_fixedfileinfo, 0))) {
			r_cons_printf ("}");
			break;
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"Signature\":%"PFMT64u",", sdb_num_get (sdb, "Signature", 0));
		} else {
			r_cons_printf ("  Signature: 0x%"PFMT64x"\n", sdb_num_get (sdb, "Signature", 0));
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"StrucVersion\":%"PFMT64u",", sdb_num_get (sdb, "StrucVersion", 0));
		} else {
			r_cons_printf ("  StrucVersion: 0x%"PFMT64x"\n", sdb_num_get (sdb, "StrucVersion", 0));
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"FileVersion\":\"%"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\",",
				sdb_num_get (sdb, "FileVersionMS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "FileVersionLS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionLS", 0) & 0xFFFF);
		} else {
			r_cons_printf ("  FileVersion: %"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\n",
				sdb_num_get (sdb, "FileVersionMS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "FileVersionLS", 0) >> 16,
				sdb_num_get (sdb, "FileVersionLS", 0) & 0xFFFF);
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"ProductVersion\":\"%"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\",",
				sdb_num_get (sdb, "ProductVersionMS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "ProductVersionLS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionLS", 0) & 0xFFFF);
		} else {
			r_cons_printf ("  ProductVersion: %"PFMT64d".%"PFMT64d".%"PFMT64d".%"PFMT64d"\n",
				sdb_num_get (sdb, "ProductVersionMS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionMS", 0) & 0xFFFF,
				sdb_num_get (sdb, "ProductVersionLS", 0) >> 16,
				sdb_num_get (sdb, "ProductVersionLS", 0) & 0xFFFF);
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"FileFlagsMask\":%"PFMT64u",", sdb_num_get (sdb, "FileFlagsMask", 0));
		} else {
			r_cons_printf ("  FileFlagsMask: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileFlagsMask", 0));
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"FileFlags\":%"PFMT64u",", sdb_num_get (sdb, "FileFlags", 0));
		} else {
			r_cons_printf ("  FileFlags: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileFlags", 0));
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"FileOS\":%"PFMT64u",", sdb_num_get (sdb, "FileOS", 0));
		} else {
			r_cons_printf ("  FileOS: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileOS", 0));
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"FileType\":%"PFMT64u",", sdb_num_get (sdb, "FileType", 0));
		} else {
			r_cons_printf ("  FileType: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileType", 0));
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"FileSubType\":%"PFMT64u, sdb_num_get (sdb, "FileSubType", 0));
		} else {
			r_cons_printf ("  FileSubType: 0x%"PFMT64x"\n", sdb_num_get (sdb, "FileSubType", 0));
		}
#if 0
		r_cons_printf ("  FileDate: %d.%d.%d.%d\n",
			sdb_num_get (sdb, "FileDateMS", 0) >> 16,
			sdb_num_get (sdb, "FileDateMS", 0) & 0xFFFF,
			sdb_num_get (sdb, "FileDateLS", 0) >> 16,
			sdb_num_get (sdb, "FileDateLS", 0) & 0xFFFF);
#endif
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("},");
		} else {
			r_cons_newline ();
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("\"StringTable\":{");
		} else {
			r_cons_printf ("# StringTable\n\n");
		}
		for (num_stringtable = 0; sdb; num_stringtable++) {
			char path_stringtable[256] = R_EMPTY;
			snprintf (path_stringtable, sizeof (path_stringtable), format_stringtable, path_version, num_stringtable);
			sdb = sdb_ns_path (r->sdb, path_stringtable, 0);
			bool firstit_for = true;
			for (num_string = 0; sdb; num_string++) {
				char path_string[256] = R_EMPTY;
				snprintf (path_string, sizeof (path_string), format_string, path_stringtable, num_string);
				sdb = sdb_ns_path (r->sdb, path_string, 0);
				if (sdb) {
					if (!firstit_for && IS_MODE_JSON (mode)) { r_cons_printf (","); }
					int lenkey = 0;
					int lenval = 0;
					ut8 *key_utf16 = sdb_decode (sdb_const_get (sdb, "key", 0), &lenkey);
					ut8 *val_utf16 = sdb_decode (sdb_const_get (sdb, "value", 0), &lenval);
					ut8 *key_utf8 = calloc (lenkey * 2, 1);
					ut8 *val_utf8 = calloc (lenval * 2, 1);

					if (r_str_utf16_to_utf8 (key_utf8, lenkey * 2, key_utf16, lenkey, true) < 0
						|| r_str_utf16_to_utf8 (val_utf8, lenval * 2, val_utf16, lenval, true) < 0) {
						eprintf ("Warning: Cannot decode utf16 to utf8\n");
					} else if (IS_MODE_JSON (mode)) {
						char *escaped_key_utf8 = r_str_escape ((char*)key_utf8);
						char *escaped_val_utf8 = r_str_escape ((char*)val_utf8);
						r_cons_printf ("\"%s\":\"%s\"", escaped_key_utf8, escaped_val_utf8);
						free (escaped_key_utf8);
						free (escaped_val_utf8);
					} else {
						r_cons_printf ("  %s: %s\n", (char*)key_utf8, (char*)val_utf8);
					}

					free (key_utf8);
					free (val_utf8);
					free (key_utf16);
					free (val_utf16);
				}
				firstit_for = false;
			}
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("}}");
		}
		num_version++;
		firstit_dowhile = false;
	} while (sdb);
}

static void bin_elf_versioninfo(RCore *r, int mode) {
	const char *format = "bin/cur/info/versioninfo/%s%d";
	char path[256] = {0};
	int num_versym = 0;
	int num_verneed = 0;
	int num_version = 0;
	Sdb *sdb = NULL;
	const char *oValue = NULL;
	bool firstit_for_versym = true;
	if (IS_MODE_JSON (mode)) { r_cons_printf ("{\"versym\":["); }
	for (;; num_versym++) {
		snprintf (path, sizeof (path), format, "versym", num_versym);
		if (!(sdb = sdb_ns_path (r->sdb, path, 0))) {
			break;
		}
		ut64 addr = sdb_num_get (sdb, "addr", 0);
		ut64 offset = sdb_num_get (sdb, "offset", 0);
		ut64 link = sdb_num_get (sdb, "link", 0);
		ut64 num_entries = sdb_num_get (sdb, "num_entries", 0);
		const char *section_name = sdb_const_get (sdb, "section_name", 0);
		const char *link_section_name = sdb_const_get (sdb, "link_section_name", 0);

		if (IS_MODE_JSON (mode)) {
			if (!firstit_for_versym) { r_cons_printf (","); }
			r_cons_printf ("{\"section_name\":\"%s\",\"address\":%"PFMT64u",\"offset\":%"PFMT64u",",
					section_name, (ut64)addr, (ut64)offset);
			r_cons_printf ("\"link\":%"PFMT64u",\"link_section_name\":\"%s\",\"entries\":[",
					(ut32)link, link_section_name);
		} else {
			r_cons_printf ("Version symbols section '%s' contains %"PFMT64u" entries:\n", section_name, num_entries);
			r_cons_printf (" Addr: 0x%08"PFMT64x"  Offset: 0x%08"PFMT64x"  Link: %x (%s)\n",
				(ut64)addr, (ut64)offset, (ut32)link, link_section_name);
		}
		int i;
		for (i = 0; i < num_entries; i++) {
			char key[32] = R_EMPTY;
			snprintf (key, sizeof (key), "entry%d", i);
			const char *value = sdb_const_get (sdb, key, 0);
			if (value) {
				if (oValue && !strcmp (value, oValue)) {
					continue;
				}
				if (IS_MODE_JSON (mode)) {
					if (i > 0) { r_cons_printf (","); }
					char *escaped_value = r_str_escape (value);
					r_cons_printf ("{\"idx\":%"PFMT64u",\"value\":\"%s\"}",
							(ut64) i, escaped_value);
					free (escaped_value);
				} else {
					r_cons_printf ("  0x%08"PFMT64x": ", (ut64) i);
					r_cons_printf ("%s\n", value);
				}
				oValue = value;
			}
		}
		if (IS_MODE_JSON (mode)) {
			r_cons_printf ("]}");
		} else {
			r_cons_printf ("\n\n");
		}
		firstit_for_versym = false;
	}
	if (IS_MODE_JSON (mode)) { r_cons_printf ("],\"verneed\":["); }

	bool firstit_dowhile_verneed = true;
	do {
		char path_version[256] = R_EMPTY;
		snprintf (path, sizeof (path), format, "verneed", num_verneed++);
		if (!(sdb = sdb_ns_path (r->sdb, path, 0))) {
			break;
		}

		if (IS_MODE_JSON (mode)) {
			if (!firstit_dowhile_verneed) { r_cons_printf (","); }
			r_cons_printf ("{\"section_name\":\"%s\",\"address\":%"PFMT64u",\"offset\":%"PFMT64u",",
				sdb_const_get (sdb, "section_name", 0), sdb_num_get (sdb, "addr", 0), sdb_num_get (sdb, "offset", 0));
			r_cons_printf ("\"link\":%"PFMT64u",\"link_section_name\":\"%s\",\"entries\":[",
				sdb_num_get (sdb, "link", 0), sdb_const_get (sdb, "link_section_name", 0));
		} else {
			r_cons_printf ("Version need section '%s' contains %d entries:\n",
				sdb_const_get (sdb, "section_name", 0), (int)sdb_num_get (sdb, "num_entries", 0));

			r_cons_printf (" Addr: 0x%08"PFMT64x, sdb_num_get (sdb, "addr", 0));

			r_cons_printf ("  Offset: 0x%08"PFMT64x"  Link to section: %"PFMT64d" (%s)\n",
				sdb_num_get (sdb, "offset", 0), sdb_num_get (sdb, "link", 0),
				sdb_const_get (sdb, "link_section_name", 0));
		}
		bool firstit_for_verneed = true;
		for (num_version = 0;; num_version++) {
			snprintf (path_version, sizeof (path_version), "%s/version%d", path, num_version);
			const char *filename = NULL;
			char path_vernaux[256] = R_EMPTY;
			int num_vernaux = 0;
			if (!(sdb = sdb_ns_path (r->sdb, path_version, 0))) {
				break;
			}
			if (IS_MODE_JSON (mode)) {
				if (!firstit_for_verneed) { r_cons_printf (","); }
				r_cons_printf ("{\"idx\":%"PFMT64u",\"vn_version\":%d,",
					sdb_num_get (sdb, "idx", 0), (int)sdb_num_get (sdb, "vn_version", 0));
			} else {
				r_cons_printf ("  0x%08"PFMT64x": Version: %d",
					sdb_num_get (sdb, "idx", 0), (int)sdb_num_get (sdb, "vn_version", 0));
			}

			if ((filename = sdb_const_get (sdb, "file_name", 0))) {
				if (IS_MODE_JSON (mode)) {
					char *escaped_filename = r_str_escape (filename);
					r_cons_printf ("\"file_name\":\"%s\",", escaped_filename);
					free (escaped_filename);
				} else {
					r_cons_printf ("  File: %s", filename);
				}
			}
			if (IS_MODE_JSON (mode)) {
				r_cons_printf ("\"cnt\":%d,", (int)sdb_num_get (sdb, "cnt", 0));
			} else {
				r_cons_printf ("  Cnt: %d\n", (int)sdb_num_get (sdb, "cnt", 0));
			}
			if (IS_MODE_JSON (mode)) {
				r_cons_printf ("\"vernaux\":[");
			}
			bool firstit_dowhile_vernaux = true;
			do {
				snprintf (path_vernaux, sizeof (path_vernaux), "%s/vernaux%d",
					path_version, num_vernaux++);
				if (!(sdb = sdb_ns_path (r->sdb, path_vernaux, 0))) {
					break;
				}
				if (IS_MODE_JSON (mode)) {
					if (!firstit_dowhile_vernaux) { r_cons_printf (","); }
					r_cons_printf ("{\"idx\":%"PFMT64x",\"name\":\"%s\",",
						sdb_num_get (sdb, "idx", 0), sdb_const_get (sdb, "name", 0));
					r_cons_printf ("\"flags\":\"%s\",\"version\":%d}",
						sdb_const_get (sdb, "flags", 0), (int)sdb_num_get (sdb, "version", 0));
				} else {
					r_cons_printf ("  0x%08"PFMT64x":   Name: %s",
						sdb_num_get (sdb, "idx", 0), sdb_const_get (sdb, "name", 0));
					r_cons_printf ("  Flags: %s Version: %d\n",
						sdb_const_get (sdb, "flags", 0), (int)sdb_num_get (sdb, "version", 0));
				}
				firstit_dowhile_vernaux = false;
			} while (sdb);
			if (IS_MODE_JSON (mode)) { r_cons_printf ("]}"); };
			firstit_for_verneed = false;
		}
		if (IS_MODE_JSON (mode)) { r_cons_printf ("]}"); };
		firstit_dowhile_verneed = false;
	} while (sdb);
	if (IS_MODE_JSON (mode)) { r_cons_printf ("]}"); }
}

static void bin_mach0_versioninfo(RCore *r) {
	/* TODO */
}

static void bin_pe_resources(RCore *r, int mode) {
	Sdb *sdb = NULL;
	int index = 0;
	const char *pe_path = "bin/cur/info/pe_resource";
	if (!(sdb = sdb_ns_path (r->sdb, pe_path, 0))) {
		return;
	}
	if (IS_MODE_SET (mode)) {
		r_flag_space_set (r->flags, "resources");
	} else if (IS_MODE_RAD (mode)) {
		r_cons_printf ("fs resources\n");
	} else if (IS_MODE_JSON (mode)) {
		r_cons_printf ("[");
	}
	while (true) {
		const char *timestrKey = sdb_fmt (0, "resource.%d.timestr", index);
		const char *vaddrKey = sdb_fmt (1, "resource.%d.vaddr", index);
		const char *sizeKey  = sdb_fmt (2, "resource.%d.size", index);
		const char *typeKey  = sdb_fmt (3, "resource.%d.type", index);
		const char *languageKey = sdb_fmt (4, "resource.%d.language", index);
		const char *nameKey = sdb_fmt (5, "resource.%d.name", index);
		char *timestr = sdb_get (sdb, timestrKey, 0);
		if (!timestr) {
			break;
		}
		ut64 vaddr = sdb_num_get (sdb, vaddrKey, 0);
		int size = (int)sdb_num_get (sdb, sizeKey, 0);
		int name = (int)sdb_num_get (sdb, nameKey, 0);
		char *type = sdb_get (sdb, typeKey, 0);
		char *lang = sdb_get (sdb, languageKey, 0);

		if (IS_MODE_SET (mode)) {
			const char *name = sdb_fmt (4, "resource.%d", index);
			r_flag_set (r->flags, name, vaddr, size);
		} else if (IS_MODE_RAD (mode)) {
			r_cons_printf ("f resource.%d %d 0x%08"PFMT32x"\n", index, size, vaddr);
		} else if (IS_MODE_JSON (mode)) {
			r_cons_printf("%s{\"name\":%d,\"index\":%d, \"type\":\"%s\","
					"\"vaddr\":%"PFMT64d", \"size\":%d, \"lang\":\"%s\"}",
					index? ",": "", name, index, type, vaddr, size, lang);
		} else {
			char *humanSize = r_num_units (NULL, size);
			r_cons_printf ("Resource %d\n", index);
			r_cons_printf ("\tname: %d\n", name);
			r_cons_printf ("\ttimestamp: %s\n", timestr);
			r_cons_printf ("\tvaddr: 0x%08"PFMT64x"\n", vaddr);
			r_cons_printf ("\tsize: %s\n", humanSize);
			r_cons_printf ("\ttype: %s\n", type);
			r_cons_printf ("\tlanguage: %s\n", lang);
			free (humanSize);
		}

		R_FREE (timestr);
		R_FREE (type);
		R_FREE (lang)

		index++;
	}
	if (IS_MODE_JSON (mode)) {
		r_cons_printf ("]");
	} else if (IS_MODE_RAD (mode)) {
		r_cons_printf ("fs *");
	}
}

static void bin_no_resources(RCore *r, int mode) {
	if (IS_MODE_JSON (mode)) {
		r_cons_printf ("[]");
	}
}


static int bin_resources(RCore *r, int mode) {
	const RBinInfo *info = r_bin_get_info (r->bin);
	if (!info || !info->rclass) {
		return false;
	}
	if (!strncmp ("pe", info->rclass, 2)) {
		bin_pe_resources (r, mode);
	} else {
		bin_no_resources (r, mode);
	}
	return true;
}

static int bin_versioninfo(RCore *r, int mode) {
	const RBinInfo *info = r_bin_get_info (r->bin);
	if (!info || !info->rclass) {
		return false;
	}
	if (!strncmp ("pe", info->rclass, 2)) {
		bin_pe_versioninfo (r, mode);
	} else if (!strncmp ("elf", info->rclass, 3)) {
		bin_elf_versioninfo (r, mode);
	} else if (!strncmp ("mach0", info->rclass, 5)) {
		bin_mach0_versioninfo (r);
	} else {
		r_cons_println ("Unknown format");
		return false;
	}
	return true;
}

static int bin_signature(RCore *r, int mode) {
	RBinFile *cur = r_bin_cur (r->bin);
	RBinPlugin *plg = r_bin_file_cur_plugin (cur);
	if (plg && plg->signature) {
		const char *signature = plg->signature (cur, IS_MODE_JSON (mode));
		r_cons_println (signature);
		free ((char*) signature);
		return true;
	}
	return false;
}


R_API void r_core_bin_export_info_rad(RCore *core) {
	Sdb *db = NULL;
	char *flagname = NULL, *offset = NULL;
	RBinFile *bf = r_core_bin_cur (core);
	if (!bf) {
		return;
	}
	db = sdb_ns (bf->sdb, "info", 0);;
	if (!db) {
		return;
	}
	if (db) {
		SdbListIter *iter;
		SdbKv *kv;
		r_cons_printf ("fs format\n");
		// iterate over all keys
		SdbList *ls = sdb_foreach_list (db, false);
		ls_foreach (ls, iter, kv) {
			char *k = kv->key;
			char *v = kv->value;
			char *dup = strdup (k);
			//printf ("?e (%s) (%s)\n", k, v);
			if ((flagname = strstr (dup, ".offset"))) {
				*flagname = 0;
				flagname = dup;
				r_cons_printf ("f %s @ %s\n", flagname, v);
				free (offset);
				offset = strdup (v);
			}
			if ((flagname = strstr (dup, ".cparse"))) {
				r_cons_printf ("\"td %s\"\n", v);
			}
			free (dup);
		}
		R_FREE (offset);
		ls_foreach (ls, iter, kv) {
			char *k = kv->key;
			char *v = kv->value;
			char *dup = strdup (k);
			if ((flagname = strstr (dup, ".format"))) {
				*flagname = 0;
				if (!offset) {
					offset = strdup ("0");
				}
				flagname = dup;
				r_cons_printf ("pf.%s %s\n", flagname, v);
			}
			free (dup);
		}
		ls_foreach (ls, iter, kv) {
			char *k = kv->key;
			char *v = kv->value;
			char *dup = strdup (k);
			if ((flagname = strstr (dup, ".format"))) {
				*flagname = 0;
				if (!offset) {
					offset = strdup ("0");
				}
				flagname = dup;
				int fmtsize = r_print_format_struct_size (v, core->print, 0, 0);
				char *offset_key = r_str_newf ("%s.offset", flagname);
				const char *off = sdb_const_get (db, offset_key, 0);
				free (offset_key);
				if (off) {
					r_cons_printf ("Cf %d %s @ %s\n", fmtsize, v, off);
				}
			}
			if ((flagname = strstr (dup, ".size"))) {
				*flagname = 0;
				flagname = dup;
				r_cons_printf ("fl %s %s\n", flagname, v);
			}
		}
		free (offset);
	}
}

static int bin_header(RCore *r, int mode) {
	RBinFile *cur = r_bin_cur (r->bin);
	RBinPlugin *plg = r_bin_file_cur_plugin (cur);
	if (plg && plg->header) {
		plg->header (cur);
		return true;
	}
	return false;
}

R_API int r_core_bin_info(RCore *core, int action, int mode, int va, RCoreBinFilter *filter, const char *chksum) {
	int ret = true;
	const char *name = NULL;
	ut64 at = 0, loadaddr = r_bin_get_laddr (core->bin);
	if (filter && filter->offset) {
		at = filter->offset;
	}
	if (filter && filter->name) {
		name = filter->name;
	}
	
	// use our internal values for va
	va = va ? VA_TRUE : VA_FALSE;
#if 0
	if (r_config_get_i (core->config, "anal.strings")) {
		r_core_cmd0 (core, "aar");
	}
#endif
	if ((action & R_CORE_BIN_ACC_STRINGS)) ret &= bin_strings (core, mode, va);
	if ((action & R_CORE_BIN_ACC_RAW_STRINGS)) ret &= bin_raw_strings (core, mode, va);
	if ((action & R_CORE_BIN_ACC_INFO)) ret &= bin_info (core, mode);
	if ((action & R_CORE_BIN_ACC_MAIN)) ret &= bin_main (core, mode, va);
	if ((action & R_CORE_BIN_ACC_DWARF)) ret &= bin_dwarf (core, mode);
	if ((action & R_CORE_BIN_ACC_PDB)) ret &= bin_pdb (core, mode);
	if ((action & R_CORE_BIN_ACC_ENTRIES)) ret &= bin_entry (core, mode, loadaddr, va, false);
	if ((action & R_CORE_BIN_ACC_INITFINI)) ret &= bin_entry (core, mode, loadaddr, va, true);
	if ((action & R_CORE_BIN_ACC_SECTIONS)) ret &= bin_sections (core, mode, loadaddr, va, at, name, chksum);
	if (r_config_get_i (core->config, "bin.relocs")) {
		if ((action & R_CORE_BIN_ACC_RELOCS)) ret &= bin_relocs (core, mode, va);
	}
 	if ((action & R_CORE_BIN_ACC_IMPORTS)) ret &= bin_imports (core, mode, va, name); // 6s
	if ((action & R_CORE_BIN_ACC_EXPORTS)) ret &= bin_exports (core, mode, loadaddr, va, at, name, chksum);
	if ((action & R_CORE_BIN_ACC_SYMBOLS)) ret &= bin_symbols (core, mode, loadaddr, va, at, name, chksum); // 6s
	if ((action & R_CORE_BIN_ACC_LIBS)) ret &= bin_libs (core, mode);
	if ((action & R_CORE_BIN_ACC_CLASSES)) ret &= bin_classes (core, mode); // 3s
	if ((action & R_CORE_BIN_ACC_SIZE)) ret &= bin_size (core, mode);
	if ((action & R_CORE_BIN_ACC_MEM)) ret &= bin_mem (core, mode);
	if ((action & R_CORE_BIN_ACC_VERSIONINFO)) ret &= bin_versioninfo (core, mode);
	if ((action & R_CORE_BIN_ACC_RESOURCES)) ret &= bin_resources (core, mode);
	if ((action & R_CORE_BIN_ACC_SIGNATURE)) ret &= bin_signature (core, mode);
	if ((action & R_CORE_BIN_ACC_FIELDS)) {
		if (IS_MODE_SIMPLE (mode)) {
			if ((action & R_CORE_BIN_ACC_HEADER) || action & R_CORE_BIN_ACC_FIELDS) {
				/* ignore mode, just for quiet/simple here */
				ret &= bin_fields (core, 0, va);
			}
		} else {
			if (IS_MODE_NORMAL(mode)) {
				ret &= bin_header (core, mode);
			} else {
				if ((action & R_CORE_BIN_ACC_HEADER) || action & R_CORE_BIN_ACC_FIELDS) {
					ret &= bin_fields (core, mode, va);
				}
			}
		}
	}
	return ret;
}

R_API int r_core_bin_set_arch_bits(RCore *r, const char *name, const char * arch, ut16 bits) {
	int fd = r_io_fd_get_current (r->io);
	RIODesc *desc = r_io_desc_get (r->io, fd);
	RBinFile *curfile, *binfile = NULL;
	if (!name) {
		name = (desc) ? desc->name : NULL;
	}
	if (!name) {
		return false;
	}
	/* Check if the arch name is a valid name */
	if (!r_asm_is_valid (r->assembler, arch)) {
		return false;
	}
	/* Find a file with the requested name/arch/bits */
	binfile = r_bin_file_find_by_arch_bits (r->bin, arch, bits, name);
	if (!binfile) {
		return false;
	}
	if (!r_bin_use_arch (r->bin, arch, bits, name)) {
		return false;
	}
	curfile = r_bin_cur (r->bin);
	//set env if the binfile changed or we are dealing with xtr
	if (curfile != binfile || binfile->curxtr) {
		r_core_bin_set_cur (r, binfile);
		return r_core_bin_set_env (r, binfile);
	}
	return true;
}

R_API int r_core_bin_update_arch_bits(RCore *r) {
	RBinFile *binfile = NULL;
	const char *name = NULL, *arch = NULL;
	ut16 bits = 0;
	if (!r) {
		return 0;
	}
	if (r->assembler) {
		bits = r->assembler->bits;
	   	if (r->assembler->cur) {
			arch = r->assembler->cur->arch;
		}
	}
	binfile = r_core_bin_cur (r);
	name = binfile ? binfile->file : NULL;
	if (binfile && binfile->curxtr) {
		r_anal_hint_clear (r->anal);
	}
	return r_core_bin_set_arch_bits (r, name, arch, bits);
}

R_API int r_core_bin_raise(RCore *core, ut32 binfile_idx, ut32 binobj_idx) {
	RBin *bin = core->bin;
	RBinFile *binfile = NULL;

	if (binfile_idx == UT32_MAX && binobj_idx == UT32_MAX) {
		return false;
	}
	if (!r_bin_select_by_ids (bin, binfile_idx, binobj_idx)) {
		return false;
	}
	binfile = r_core_bin_cur (core);
	if (binfile) {
		r_io_use_fd (core->io, binfile->fd);
	}
	// it should be 0 to use r_io_use_fd in r_core_block_read
	core->switch_file_view = 0;
	return binfile && r_core_bin_set_env (core, binfile) && r_core_block_read (core);
}

R_API bool r_core_bin_delete(RCore *core, ut32 binfile_idx, ut32 binobj_idx) {
	if (binfile_idx == UT32_MAX && binobj_idx == UT32_MAX) {
		return false;
	}
	if (!r_bin_object_delete (core->bin, binfile_idx, binobj_idx)) {
		return false;
	}
	RBinFile *binfile = r_core_bin_cur (core);
	if (binfile) {
		r_io_use_fd (core->io, binfile->fd);
	}
	core->switch_file_view = 0;
	return binfile && r_core_bin_set_env (core, binfile) && r_core_block_read (core);
}

static int r_core_bin_file_print(RCore *core, RBinFile *binfile, int mode) {
	RListIter *iter;
	RBinObject *obj;
	const char *name = binfile ? binfile->file : NULL;
	(void)r_bin_get_info (core->bin); // XXX is this necssary for proper iniitialization
	ut32 id = binfile ? binfile->id : 0;
	ut32 fd = binfile ? binfile->fd : 0;
	ut32 bin_sz = binfile ? binfile->size : 0;
	// TODO: handle mode to print in json and r2 commands

	if (!binfile) {
		return false;
	}
	switch (mode) {
	case '*':
		r_list_foreach (binfile->objs, iter, obj) {
			r_cons_printf ("oba 0x%08"PFMT64x" %s # %d\n", obj->boffset, name, obj->id);
		}
		break;
	case 'q':
		r_list_foreach (binfile->objs, iter, obj) {
			r_cons_printf ("%d\n", obj->id);
		}
		break;
	case 'j':
		r_cons_printf ("{\"name\":\"%s\",\"fd\":%d,\"id\":%d,\"size\":%d,\"objs\":[",
			name, fd, id, bin_sz);
		r_list_foreach (binfile->objs, iter, obj) {
			RBinInfo *info = obj->info;
			ut8 bits = info ? info->bits : 0;
			const char *arch = info ? info->arch : "unknown";
			r_cons_printf ("{\"objid\":%d,\"arch\":\"%s\",\"bits\":%d,\"binoffset\":%"
					PFMT64d",\"objsize\":%"PFMT64d"}",
					obj->id, arch, bits, obj->boffset, obj->obj_size);
			if (iter->n) {
				r_cons_print (",");
			}
		}
		r_cons_print ("]}");
		break;
	default:
		r_list_foreach (binfile->objs, iter, obj) {
			RBinInfo *info = obj->info;
			ut8 bits = info ? info->bits : 0;
			const char *arch = info ? info->arch : "unknown";
			if (!arch) {
				arch = r_config_get (core->config, "asm.arch");
			}
			r_cons_printf ("%4d  %s-%d at:0x%08"PFMT64x" sz:%"PFMT64d" ",
					obj->id, arch, bits, obj->boffset, obj->obj_size );
			r_cons_printf ("fd:%d %s\n", fd, name);
		}
		break;
	}
	return true;
}

R_API int r_core_bin_list(RCore *core, int mode) {
	// list all binfiles and there objects and there archs
	int count = 0;
	RListIter *iter;
	RBinFile *binfile = NULL; //, *cur_bf = r_core_bin_cur (core) ;
	RBin *bin = core->bin;
	const RList *binfiles = bin ? bin->binfiles: NULL;
	if (!binfiles) {
		return false;
	}
	if (mode == 'j') {
		r_cons_print ("[");
	}
	r_list_foreach (binfiles, iter, binfile) {
		r_core_bin_file_print (core, binfile, mode);
		if (iter->n && mode == 'j') {
			r_cons_print (",");
		}
	}
	if (mode == 'j') {
		r_cons_println ("]");
	}
	//r_core_file_set_by_file (core, cur_cf);
	//r_core_bin_bind (core, cur_bf);
	return count;
}

R_API char *r_core_bin_method_flags_str(ut64 flags, int mode) {
	char *str;
	RStrBuf *buf;
	int i, len = 0;

	buf = r_strbuf_new ("");
	if (IS_MODE_SET (mode) || IS_MODE_RAD (mode)) {
		if (!flags) {
			goto out;
		}

		for (i = 0; i != 64; i++) {
			ut64 flag = flags & (1UL << i);
			if (flag) {
				const char *flag_string = r_bin_get_meth_flag_string (flag, false);
				if (flag_string) {
					r_strbuf_appendf (buf, ".%s", flag_string);
				}
			}
		}
	} else if (IS_MODE_JSON (mode)) {
		if (!flags) {
			r_strbuf_append (buf, "[]");
			goto out;
		}

		r_strbuf_append (buf, "[");

		for (i = 0; i != 64; i++) {
			ut64 flag = flags & (1LL << i);
			if (flag) {
				const char *flag_string = r_bin_get_meth_flag_string (flag, false);
				if (len != 0) {
					r_strbuf_append (buf, ",");
				}
				if (flag_string) {
					r_strbuf_appendf (buf, "\"%s\"", flag_string);
				} else {
					r_strbuf_appendf (buf, "\"0x%08"PFMT64x"\"", flag);
				}
				len++;
			}
		}

		r_strbuf_append (buf, "]");
	} else {
		int pad_len = 4; //TODO: move to a config variable

		if (!flags) {
			goto padding;
		}
		for (i = 0; i != 64; i++) {
			ut64 flag = flags & (1L << i);
			if (flag) {
				const char *flag_string = r_bin_get_meth_flag_string (flag, true);

				if (flag_string) {
					r_strbuf_append (buf, flag_string);
				} else {
					r_strbuf_append (buf, "?");
				}

				len++;
			}
		}
padding:
		for ( ; len < pad_len; len++) {
			r_strbuf_append (buf, " ");
		}
	}

out:
	str = strdup (r_strbuf_get (buf));
	r_strbuf_free (buf);

	return str;
}
