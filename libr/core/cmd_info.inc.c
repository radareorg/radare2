/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

// R2R db/formats/dwarf
// R2R db/cmd/cmd_i

#include "../bin/format/pdb/pdb_downloader.h"

static RCoreHelpMessage help_msg_ih = {
	"Usage: ih", "[*jq]", "Display header information",
	"ih", "", "normal output to display binary headers",
	"ih*", "", "same as above, but in r2 commands",
	"ihj", "", "in json format",
	NULL
};

static RCoreHelpMessage help_msg_iH = {
	"Usage: iH", "[*jq]", "Display header fields information",
	"iH", "", "normal output to display binary headers",
	"iH*", "", "same as above, but in r2 commands",
	"iHj", "", "in json format",
	NULL
};

static RCoreHelpMessage help_msg_is = {
	"Usage: is", "[*hjq]", "List symbols from current selected binary",
	"is,", "[table-query]", "list symbols in table using given expression",
	"is.", "", "current symbol",
	"is*", "", "same as above, but in r2 commands",
	"isj", "", "in json format",
	"ise", "", "entrypoints symbols (see 'ies')",
	NULL
};

static RCoreHelpMessage help_msg_ic = {
	"Usage: ic", "[.-+clgjsq][jq]", "Display class information",
	"ic", "", "List classes, methods and fields (icj for json)",
	"ic.", "", "show class and method name in current seek",
	"ic,", "[table-query]", "query comma separated values",
	"ic-", "[klass.method]", "delete given klass or klass.name",
	"ic+", "[klass.method]", "add new symbol in current seek for a given klass and method name",
	"icc", " [lang]", "List classes, methods and fields in Header Format (see bin.lang=swift,java,objc,cxx)",
	"icg", " [str]", "List classes hirearchy graph with agn/age (match str if provided)",
	"icq", "", "List classes, in quiet mode (just the classname)",
	"icqq", "", "List classes, in quieter mode (only show non-system classnames)",
	"icl", "[c]", "Show addresses of class and it methods, without names (iclc = class count)",
	"ics", "", "Show class symbols in an easy to parse format",
	NULL
};

static RCoreHelpMessage help_msg_iz = {
	"Usage: iz", "[][jq*]", "List strings",
	"iz", "", "strings in data sections (in JSON/Base64)",
	"iz,", "[:help]", "perform a table query on strings listing",
	"iz-", " [addr]", "purge string via bin.str.purge",
	"iz*", "", "print flags and comments r2 commands for all the strings",
	"izz", "", "search for Strings in the whole binary",
	"izz*", "", "same as iz* but exposing the strings of the whole binary",
	"izzz", "", "dump Strings from whole binary to r2 shell (for huge files)",
	NULL
};

static RCoreHelpMessage help_msg_iE = { // rename to ise? maybe
	"Usage: iE", "[][jq*]", "List exported symbols",
	"iE", "", "exports (global symbols)",
	"iE,", "[table-query]", "exported symbols using the table query",
	"iE.", "", "show export in current address",
	NULL
};

static RCoreHelpMessage help_msg_iS = {
	"Usage: iS", "[][jq*]", "List sections and segments",
	"iS ", "[sha1,crc32(,..)]", "sections (see Lh to list the hash algorithms supported)",
	"iS.", "", "current section",
	"iS,", "[table-query]", "list sections in table using given expression",
	"iS=", "", "show ascii-art color bars with the section ranges",
	"iSS", "[,tablequery]", "list memory segments (maps with om)",
	"iSm", "[cj]", "list sections with the symbols contained (iSmc for count only, iSmj for json)",
	NULL
};

static RCoreHelpMessage help_msg_iic = {
	"Usage: iic", "[jkq*]", "info import classes",
	"iic", " [symname]", "show all imports matching a class",
	"iic", "", "list imports grouped by class",
	"iic.", "", "show classes associated with the import in the current address",
	"iicc", " [type]", "show kind of given symbol name",
	"iiccx", " [type]", "show functions calling the imports of this class",
	"iicj", "", "list grouped imports in json",
	"iick", "", "group imports by class, listed in key/value format",
	NULL
};

static RCoreHelpMessage help_msg_ie = {
	"Usage: ie", "[qj=]", "Show entrypoints and constructors",
	"ie", "[j]", "show entrypointsie=entrypoint",
	"iee", "[j]", "list constructors and destructors",
	"ies", "[j]", "list entrypoint symbols (see 'ise')",
	NULL
};

static RCoreHelpMessage help_msg_i = {
	"Usage: i", "", "Get info from opened file (see rabin2's manpage)",
	"i", "[*jq]", "show info of current file (in JSON)",
	"i:", "[?]", "run rbinplugin specific commands",
	"ia", "", "list archs found in current binary (same as rabin2 -A)",
	"ib", "", "reload the current buffer for setting of the bin (use once only)",
	"ic", "[?]", "List classes, methods and fields (icj for json)",
	"iC", "[j]", "show signature info (entitlements, ...)",
	"id", "[?]", "show DWARF source lines information",
	"iD", " lang sym", "demangle symbolname for given language",
	"ie", "[?][es]", "ie=entrypoint, iee=constructors+destructors, ies=epsymbols",
	"iE", "[?]", "exports (global symbols)",
	"ig", "[?][h]", "guess size of binary program (h for human friendly unit)",
	"ih", "[?]", "show binary headers (see iH)",
	"iH", "[?]", "show binary headers fields",
	"ii", "[?][cj*,]", "list the symbols imported from other libraries",
	"iic", "[?][jqk*] ([type])", "classify imports",
	"iI", "", "binary info", // deprecate imho, may confuse with il and its already in `i`
	"ik", " [query]", "key-value database from RBinObject",
	"il", "", "libraries",
	"iL", " [plugin]", "list all RBin plugins loaded or plugin details",
	"im", "", "show info about predefined memory allocation",
	"iM", "", "show main address",
	"io", " [file]", "load info from file (or last opened) use bin.baddr",
	"iO", "[?]", "perform binary operation (dump, resize, change sections, ...)",
	"ir", "", "list the relocations",
	"iR", "", "list the resources",
	"is", "[?]", "list the symbols",
	"iS", "[?]", "list sections, segments and compute their hash",
	"it", "", "file hashes", // hashes in it? wtf, thats a pretty bad subcommand
	"iT", "", "file signature", // iT for signatures omg thats worst
	"iV", "", "display file version info", // wtf why not iv
	"iw", "", "show try/catch blocks", // bad naming..
	"iz", "[?]", "strings in data sections (in JSON/Base64)",
	NULL
};

static RCoreHelpMessage help_msg_idl = {
	"Usage: idl", "", "Debug information",
	"idl", "", "show debuglink file",
	"idl*", "", "show command to load the debuglink file",
	"idld", "", "download associated debuglink file",
	"idld*", "", "show url to pull the debuglink file",
	NULL
};

static RCoreHelpMessage help_msg_id = {
	"Usage: id", "", "Debug information",
	"id", "", "show DWARF source lines information",
	"idj", "", "show addrline information in json format",
	"idl", "[?]", "show debug link file name",
	"idp", " [file.pdb]", "load pdb file information",
	"idpd", "", "download pdb file on remote server",
	"idpi", " [file.pdb]", "show pdb file information",
	"idpi*", "", "show symbols from pdb as flags (prefix with dot to import)",
	"idx", "", "display source files used via dwarf (previously known as iX)",
	NULL
};

#define PAIR_WIDTH 9
// TODO: reuse implementation in core/bin.c
static void pair(RCore *core, const char *a, const char *b) {
	if (!b) {
		return;
	}
	char ws[16];
	size_t al = strlen (a);
	memset (ws, ' ', sizeof (ws));
	al = PAIR_WIDTH - al;
	if (al < 0) {
		al = 0;
	}
	ws[al] = 0;
	r_cons_printf (core->cons, "%s%s%s\n", a, ws, b);
}

static void classdump_keys(RCore *core, RBinObject *bo) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	const bool iova = r_config_get_b (core->config, "io.va");
	RBinClass *k;
	RBinField *f;
	RBinSymbol *m;
	RListIter *iter, *iter2;
	r_list_foreach (bo->classes, iter, k) {
		const char *kname = r_bin_name_tostring2 (k->name, pref);
		r_list_foreach (k->fields, iter2, f) {
			const char *kind = r_bin_field_kindstr (f);
			r_cons_printf (core->cons, "klass.%s.field.%s.%s=0x%"PFMT64x"\n",
					kname, kind, r_bin_name_tostring2 (f->name, 'f'),
					iova? f->vaddr: f->paddr);
		}
		r_list_foreach (k->methods, iter2, m) {
			char *attr = r_bin_attr_tostring (m->attr, true);
			const char *mname = r_bin_name_tostring2 (m->name, 'f');
			r_cons_printf (core->cons, "klass.%s.method.%s.%s=0x%"PFMT64x"\n",
					kname, r_str_get (attr), mname,
					iova? m->vaddr: m->paddr);
			free (attr);
		}
	}
}

static char *demangle_internal(RCore *core, int type, const char *s) {
	char *res = NULL;
	switch (type) {
	case R_BIN_LANG_CXX: res = r_bin_demangle_cxx (core->bin->cur, s, 0); break;
	case R_BIN_LANG_JAVA: res = r_bin_demangle_java (s); break;
	case R_BIN_LANG_OBJC: res = r_bin_demangle_objc (NULL, s); break;
	case R_BIN_LANG_SWIFT: res = r_bin_demangle_swift (s, core->bin->options.demangle_usecmd, core->bin->options.demangle_trylib); break;
	case R_BIN_LANG_DLANG: res = r_bin_demangle_plugin (core->bin, "dlang", s); break;
	case R_BIN_LANG_MSVC: res = r_bin_demangle_msvc (s); break;
	case R_BIN_LANG_RUST: res = r_bin_demangle_rust (core->bin->cur, s, 0); break;
	case R_BIN_LANG_PASCAL: res = r_bin_demangle_freepascal (s); break;
	default:
		r_core_return_value (core, 1);
	}
	return res;
}

static void cmd_info_demangle(RCore *core, const char *input, PJ *pj, int mode) {
	if (input[1] == 'j' && input[2] == ' ') {
		mode = R_MODE_JSON;
		input += 3;
	} else if (input[1] == ' ') {
		input += 2;
	} else {
		// iD receives no arguments
		if (!pj) {
			r_core_cmd_help_match (core, help_msg_i, "iD");
		} else {
			r_cons_print (core->cons, "{}");
		}
		return;
	}
	char *args = r_str_trim_dup (input);
	const char *lang = args;
	char *text = strchr (args, ' ');
	const char *err = "Cannot demangle string";
	if (text) {
		*text ++ = 0;
	} else {
		// iD receives 1 argument we will assume language is the one defined in bin.lang config var
		lang = r_config_get (core->config, "bin.lang");
		if (R_STR_ISEMPTY (lang)) {
			err = "Set the language in `e bin.lang` or pass a second argument";
		}
		text = args;
	}
	int lang_type = r_bin_demangle_type (lang);
	if (lang_type == R_BIN_LANG_NONE) {
		if (!pj) {
			r_bin_demangle_list (core->bin);
		}
		r_core_return_value (core, 1);
	}
	char *res = demangle_internal (core, lang_type, text);
	if (mode == R_MODE_JSON) {
		pj_o (pj);
		pj_ks (pj, "lang", lang);
		pj_ks (pj, "mangled", text);
		if (res) {
			pj_ks (pj, "demangled", res);
		} else {
			pj_ks (pj, "error", err);
		}
		pj_end (pj);
	} else {
		if (res) {
			r_cons_println (core->cons, res);
		} else {
			R_LOG_ERROR (err);
		}
	}
	free (args);
	return;
}

// XXX i.j ij. is inconsistent maybe move to 'ai'?
static void cmd_info_here(RCore *core, PJ *pj, int mode) {
	RCoreItem *item = r_core_item_at (core, core->addr);
	// fixme: other modes
	if (!item) {
		return;
	}
	if (mode == R_MODE_JSON) {
		pj_o (pj);
		pj_ks (pj, "type", item->type);
		pj_ks (pj, "perm", r_str_rwx_i (item->perm));
		pj_kn (pj, "size", item->size);
		pj_kn (pj, "addr", item->addr);
		pj_kn (pj, "next", item->next);
		pj_kn (pj, "prev", item->prev);
		if (item->fcnname) {
			pj_ks (pj, "fcnname", item->fcnname);
		}
		if (item->sectname) {
			pj_ks (pj, "sectname", item->sectname);
		}
		if (item->comment) {
			pj_ks (pj, "comment", item->comment);
		}
		if (item->data) {
			pj_ks (pj, "data", item->data);
		}
		{
			RVecAnalRef *refs = r_anal_refs_get (core->anal, core->addr);
			if (refs && !RVecAnalRef_empty (refs)) {
				pj_k (pj, "refs");
				pj_a (pj);
				RAnalRef *ref;
				R_VEC_FOREACH (refs, ref) {
					pj_o (pj);
					pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
					pj_kn (pj, "addr", ref->addr);
					pj_end (pj);
				}
				pj_end (pj);
			}
			RVecAnalRef_free (refs);
		}
		{
			RVecAnalRef *refs = r_anal_xrefs_get (core->anal, core->addr);
			if (refs && !RVecAnalRef_empty (refs)) {
				pj_k (pj, "xrefs");
				pj_a (pj);
				RAnalRef *ref;
				R_VEC_FOREACH (refs, ref) {
					pj_o (pj);
					pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
					pj_kn (pj, "addr", ref->addr);
					pj_end (pj);
				}
				pj_end (pj);
			}
			RVecAnalRef_free (refs);
		}
		pj_end (pj);
		r_core_item_free (item);
	} else {
		// TODO show more info
		// type cant be code if perms are ---
		r_cons_printf (core->cons, "type = %s\n", item->type);
		r_cons_printf (core->cons, "perm = %s\n", r_str_rwx_i (item->perm));
		r_cons_printf (core->cons, "size = %d\n", item->size);
		r_cons_printf (core->cons, "addr = 0x%"PFMT64x"\n", item->addr);
		// pj_kn (pj, "next", item->next);
		// pj_kn (pj, "prev", item->prev);
	}
}

static RFlagItem *get_flag_for_import(RCore* core, const char *value) {
	char *fname = r_str_newf ("sym.imp.%s", value);
	RFlagItem *item = r_flag_get (core->flags, fname);
	if (!item) {
		free (fname);
		fname = r_str_newf ("reloc.%s", value);
		item = r_flag_get (core->flags, fname);
	}
	free (fname);
	return item;
}

static ut64 valstr(const void *_a) {
	const char *a = _a;
	return r_str_hash64 (a);
}
static int cmpstr(const void *_a, const void *_b) {
	const char *a = _a, *b = _b;
	return (int)strcmp (a, b);
}
static RList *uniqrefs_for(RCore *core, ut64 addr) {
	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
	if (xrefs) {
		RList *res = r_list_newf (free);
		RAnalRef *xref;
		R_VEC_FOREACH (xrefs, xref) {
			RList *funcs = r_anal_get_functions_in (core->anal, xref->addr);
			RAnalFunction *f = r_list_pop (funcs);
			if (f) {
				r_list_append (res, strdup (f->name));
			} else {
				r_list_append (res, r_str_newf ("0x%08"PFMT64x, xref->addr));
			}
			r_list_free (funcs);
		}
		RVecAnalRef_free (xrefs);
		r_list_sort (res, cmpstr);
		RList *nres = r_list_uniq (res, valstr);
		res->free = NULL;
		r_list_free (res);
		return nres;
	}
	return NULL;
}

static void cmd_iic2(RCore *core, int mode, const char *symname) {
	if (symname && !mode) {
		const char *un = r_bin_import_tags (core->bin, symname);
		if (R_STR_ISNOTEMPTY (un)) {
			r_cons_println (core->cons, un);
		}
		return;
	}
	const RList *imports = r_bin_get_imports (core->bin);
	RListIter *iter, *iter2;
	RBinSymbol *imp;
	Sdb *db = sdb_new0 ();
	r_list_foreach (imports, iter, imp) {
		const char *name = r_bin_name_tostring2 (imp->name, 'o');
		const char *un = r_bin_import_tags (core->bin, name);
		if (!un) {
			R_LOG_DEBUG ("Symbol not classified %s", name);
			continue;
		}
		char *a = strdup (un);
		const char *key;
		RList *keys = r_str_split_list (a, ",", 0);
		r_list_foreach (keys, iter2, key) {
			ut32 cas;
			if (!sdb_array_contains (db, key, name, &cas)) {
				sdb_array_append (db, key, name, cas);
			}
		}
		free (a);
		r_list_free (keys);
	}
	if (mode == 'c') {
		char *s = sdb_querys (db, NULL, 0, symname);
		if (s) {
			r_str_replace_ch (s, ',', '\n', -1);
			r_cons_print (core->cons, s);
			free (s);
		}
	} else if (mode == 'x') {
		char *s = sdb_querys (db, NULL, 0, symname);
		if (s) {
			RListIter *iter2;
			const char *value;
			RList *values = r_str_split_list (s, ",", 0);
			RList *rrrr = NULL;
			r_list_foreach (values, iter2, value) {
				RFlagItem *fi = get_flag_for_import (core, value);
				if (fi) {
					RList *refs = uniqrefs_for (core, fi->addr);
					if (refs && rrrr) {
						r_list_join (rrrr, refs);
					} else if (refs && !rrrr) {
						rrrr = refs;
					} else if (!rrrr) {
						rrrr = r_list_newf (free);
					}
				} else {
					R_LOG_WARN ("Cannot resolve %s", value);
				}
			}
			r_list_sort (rrrr, cmpstr);
			RList *nres = r_list_uniq (rrrr, valstr);
			char *ref;
			r_list_foreach (nres, iter, ref) {
				r_cons_println (core->cons, ref);
			}
			free (s);
			r_list_free (rrrr);
		}
	} else if (mode == '*') {
		SdbKv *kv;
		SdbListIter *it;
		SdbList *keys = sdb_foreach_list (db, true);
		ls_foreach (keys, it, kv) {
			const char *k = sdbkv_key (kv);
			char *v = strdup (sdbkv_value (kv));
			const char *value;
			RList *values = r_str_split_list (v, ",", 0);
			r_list_foreach (values, iter2, value) {
				RFlagItem *fi = get_flag_for_import (core, value);
				if (fi) {
					const ut64 at = fi->addr;
					r_cons_printf (core->cons, "'@0x%08"PFMT64x"'CC kind(%s)\n", at, k);
				}
			}
			free (v);
			r_list_free (values);
		}
	} else if (mode == 'k') {
		char *s = sdb_querys (db, NULL, 0, "*");
		if (s) {
			r_cons_print (core->cons, s);
			free (s);
		}
	} else if (mode == 'j') {
		PJ *pj = r_core_pj_new (core);
		pj_o (pj);
		SdbKv *kv;
		SdbListIter *it;
		SdbList *keys = sdb_foreach_list (db, true);
		ls_foreach (keys, it, kv) {
			const char *k = sdbkv_key (kv);
			char *v = strdup (sdbkv_value (kv));
			pj_ko (pj, k);
			const char *value;
			RList *values = r_str_split_list (v, ",", 0);
			r_list_foreach (values, iter2, value) {
				pj_ka (pj, value);
				RFlagItem *fi = get_flag_for_import (core, value);
				if (fi) {
					RList *refs = uniqrefs_for (core, fi->addr);
					RListIter *iter;
					char *ref;
					r_list_foreach (refs, iter, ref) {
						pj_s (pj, ref);
					}
					r_list_free (refs);
				} else {
					R_LOG_WARN ("Cannot resolve %s", value);
				}
				pj_end (pj);
			}
			pj_end (pj);
			free (v);
			r_list_free (values);
		}
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_print (core->cons, s);
		free (s);
	} else {
		SdbKv *kv;
		SdbListIter *it;
		SdbList *keys = sdb_foreach_list (db, true);
		ls_foreach (keys, it, kv) {
			const char *k = sdbkv_key (kv);
			char *v = strdup (sdbkv_value (kv));
			r_cons_printf (core->cons, "|- %s:\n", k);
			const char *value;
			RList *values = r_str_split_list (v, ",", 0);
			r_list_foreach (values, iter2, value) {
				r_cons_printf (core->cons, "|  |- %s\n", value);
				RFlagItem *fi = get_flag_for_import (core, value);
				if (fi) {
					RList *refs = uniqrefs_for (core, fi->addr);
					RListIter *iter;
					char *ref;
					r_list_foreach (refs, iter, ref) {
						r_cons_printf (core->cons, "|  |  |- %s\n", ref);
					}
					r_list_free (refs);
				} else {
					R_LOG_WARN ("Cannot resolve %s", value);
				}
			}
			free (v);
			r_list_free (values);
		}
	}
	sdb_free (db);
}

static int cmd_iic(RCore *core, const char *input) {
	switch (input[2]) {
	case 'j': // "iicj"
	case 'q': // "iicq"
	case 'k': // "iick"
	case '*': // "iic*"
	case 0: // "iic"
		cmd_iic2 (core, input[2], NULL);
		break;
	case '.':
		{
			char *here = r_core_cmd_str (core, "fd.");
			r_str_trim (here);
			here = r_str_replace (here, "sym.imp.", "", 0);
			here = r_str_replace (here, "reloc.", "", 0);
			cmd_iic2 (core, 0, here);
			free (here);
		}
		break;
	case ' ': // "iic "
		cmd_iic2 (core, 0, r_str_trim_head_ro (input + 3));
		break;
	case 'c': // "iicc"
		if (input[3] == 'x') { // "iiccx"
			cmd_iic2 (core, 'x', r_str_trim_head_ro (input + 4));
		} else if (input[3] == ' ') { // "iicc"
			cmd_iic2 (core, 'c', r_str_trim_head_ro (input + 3));
		} else if (input[3] == '?') { // "iicc?"
			r_core_cmd_help_contains (core, help_msg_iic, "iicc");
		} else {
			r_core_return_invalid_command (core, "iicc", input[3]);
		}
		break;
	case '?': // "iic?"
		r_core_cmd_help (core, help_msg_iic);
		break;
	default:
		r_core_return_invalid_command (core, "iic", input[2]);
		break;
	}
	return 0;
}

static void r_core_file_info(RCore *core, PJ *pj, int mode) {
	const char *fn = NULL;
	bool io_cache = r_config_get_i (core->config, "io.cache");
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinFile *binfile = r_bin_cur (core->bin);
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (mode == R_MODE_JSON) {
		pj_o (pj);
	}
	if (mode == R_MODE_RADARE) {
		return;
	}
	if (mode == R_MODE_SIMPLE) {
		return;
	}
	if (info) {
		fn = info->file;
		if (mode == R_MODE_JSON) {
			pj_ks (pj, "type", r_str_get (info->type));
		}
	} else {
		fn = desc ? desc->name: NULL;
	}
	if (mode == R_MODE_JSON) {
		const char *uri = fn;
		if (!uri) {
			if (desc && desc->uri && *desc->uri) {
				uri = desc->uri;
			} else {
				uri = "";
			}
		}
		pj_ks (pj, "file", uri);
		if (desc) {
			ut64 fsz = r_io_desc_size (desc);
			pj_ki (pj, "fd", desc->fd);
			if (fsz != UT64_MAX) {
				char humansz[8];
				pj_kN (pj, "size", fsz);
				r_num_units (humansz, sizeof (humansz), fsz);
				pj_ks (pj, "humansz", humansz);
			}
			pj_kb (pj, "iorw", io_cache || desc->perm & R_PERM_W);
			pj_ks (pj, "mode", r_str_rwx_i (desc->perm & R_PERM_RWX));
			if (desc->referer && *desc->referer) {
				pj_ks (pj, "referer", desc->referer);
			}
		}
		pj_ki (pj, "block", core->blocksize);
		if (binfile) {
			if (binfile->curxtr) {
				pj_ks (pj, "packet", binfile->curxtr->meta.name);
			}
			if (plugin) {
				pj_ks (pj, "format", plugin->meta.name);
			}
		}
		pj_end (pj);
	} else if (desc && mode != R_MODE_SIMPLE) {
		r_strf_buffer (32);
		if (desc) {
			pair (core, "fd", r_strf ("%d", desc->fd));
		}
		if (fn || (desc && desc->uri)) {
			char *escaped = r_str_escape_utf8_keep_printable (fn? fn: desc->uri, false, false);
			if (escaped) {
				pair (core, "file", escaped);
				free (escaped);
			}
		}
		if (desc) {
			ut64 fsz = r_io_desc_size (desc);
			if (fsz != UT64_MAX) {
				char humansz[8];
				pair (core, "size", r_strf ("0x%"PFMT64x, fsz));
				r_num_units (humansz, sizeof (humansz), fsz);
				pair (core, "humansz", humansz);
			}
		}
		if (desc) {
			pair (core, "mode", r_str_rwx_i (desc->perm & R_PERM_RWX));
		}
		if (plugin) {
			pair (core, "format", plugin->meta.name);
		}
		if (desc) {
			pair (core, "iorw", r_str_bool (io_cache || desc->perm & R_PERM_W));
		}
		pair (core, "block", r_strf ("0x%x", core->blocksize));

		if (binfile && binfile->curxtr) {
			pair (core, "packet", binfile->curxtr->meta.name);
		}
		if (desc && desc->referer && *desc->referer) {
			pair (core, "referer", desc->referer);
		}
		if (info) {
			pair (core, "type", info->type);
		}
	}
}

static int bin_is_executable(RBinObject *obj) {
	RListIter *it;
	RBinSection *sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		r_list_foreach (obj->sections, it, sec) {
			if (sec->perm & R_PERM_X) {
				return true;
			}
		}
		if (obj->info && obj->info->bclass) {
			return true;
		}
	}
	return false;
}

static void cmd_info_bin(RCore *core, int va, PJ *pj, int mode) {
	RBinObject *obj = r_bin_cur_object (core->bin);
	int array = 0;
	if (core->io->desc || obj) {
		if (mode & R_MODE_JSON) {
			if (!(mode & R_MODE_ARRAY)) {
				pj_o (pj);
			} else {
				array = 1;
			}
			mode = R_MODE_JSON;
			pj_k (pj, "core");
		}
		r_core_file_info (core, pj, mode);
		if (bin_is_executable (obj)) {
			if ((mode & R_MODE_JSON)) {
				pj_k (pj, "bin");
			}
			r_core_bin_info (core, R_CORE_BIN_ACC_INFO, pj, mode, va, NULL, NULL);
		}
		if ((mode & R_MODE_JSON) && array == 0) {
			pj_end (pj);
		}
	} else {
		if (mode & R_MODE_JSON) {
			r_cons_print (core->cons, "{}");
		}
		R_LOG_ERROR ("No file selected");
	}
}

static void tts_say(RCore *core, const char *n, int len) {
	if (r_config_get_b (core->config, "scr.tts")) {
		char *s = (*n && len > 0)
			? r_str_newf ("%d %s", len, n)
			: r_str_newf ("there are no %s", n);
		if (s) {
			r_sys_tts (s, true);
			free (s);
		}
	}
}

static bool is_equal_file_hashes(RList *lfile_hashes, RList *rfile_hashes, bool *equal) {
	R_RETURN_VAL_IF_FAIL (lfile_hashes, false);
	R_RETURN_VAL_IF_FAIL (rfile_hashes, false);
	R_RETURN_VAL_IF_FAIL (equal, false);

	*equal = true;
	RBinFileHash *fh_l, *fh_r;
	RListIter *hiter_l, *hiter_r;
	r_list_foreach (lfile_hashes, hiter_l, fh_l) {
		r_list_foreach (rfile_hashes, hiter_r, fh_r) {
			if (strcmp (fh_l->type, fh_r->type)) {
				continue;
			}
			if (!!strcmp (fh_l->hex, fh_r->hex)) {
				*equal = false;
				return true;
			}
		}
	}
	return true;
}

static RList *r_core_bin_files(RCore *core) {
	RList *list = r_list_newf (NULL);
	if (core->allbins) {
		RBinFile *bf;
		RListIter *iter;
		r_list_foreach (core->bin->binfiles, iter, bf) {
			r_list_append (list, bf);
		}
	} else {
		RBinFile *bf = r_bin_cur (core->bin);
		if (bf && bf->bo) {
			r_list_append (list, bf);
		}
	}
	return list;
}

static bool isKnownAndroidPackage(const char *cn) {
	if (*cn == 'L') {
		if (r_str_startswith (cn, "Lkotlin")) {
			return true;
		}
		if (r_str_startswith (cn, "Lcom/google")) {
			return true;
		}
		if (r_str_startswith (cn, "Lcom/facebook")) {
			return true;
		}
		if (r_str_startswith (cn, "Lokhttp")) {
			return true;
		}
		if (r_str_startswith (cn, "Landroid")) {
			return true;
		}
		if (r_str_startswith (cn, "Ljava")) {
			return true;
		}
		if (r_str_startswith (cn, "Lokio")) {
			return true;
		}
	}
	return false;
}

static void cmd_ic_comma(RCore *core, const char *input) {
	R_RETURN_IF_FAIL (core && input[0] == ',');
	const char *q = input + 1;
	RList *bfiles = r_core_bin_files (core);
	RListIter *objs_iter;
	RBinFile *bf;
	RBinFile *cur = core->bin->cur;
	RTable *t = r_core_table_new (core, "flags");
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	r_table_add_column (t, typeNumber, "addr", 0);
	r_table_add_column (t, typeString, "type", 0);
	r_table_add_column (t, typeString, "klass", 0);
	r_table_add_column (t, typeString, "name", 0);
	const bool iova = r_config_get_b (core->config, "io.va");
	r_list_foreach (bfiles, objs_iter, bf) {
		RBinObject *obj = bf->bo;
		RBinClass *klass;
		RListIter *iter, *iter2;
		core->bin->cur = bf;
		r_list_foreach (obj->classes, iter, klass) {
			const char *kname = r_bin_name_tostring (klass->name);
			RBinSymbol *method;
			r_list_foreach (klass->methods, iter2, method) {
				char *addr = r_str_newf ("0x%08"PFMT64x, iova? method->vaddr: method->paddr);
				r_table_add_row (t, addr, "method", kname, method->name, NULL);
				free (addr);
			}
			RBinField *field;
			r_list_foreach (klass->fields, iter2, field) {
				char *addr = r_str_newf ("0x%08"PFMT64x, iova? field->vaddr: field->paddr);
				r_table_add_row (t, addr, "field", kname, field->name, NULL);
				free (addr);
			}
		}
	}
	core->bin->cur = cur;
	r_list_free (bfiles);
	if (r_table_query (t, q)) {
		char *s = r_table_tostring (t);
		r_cons_printf (core->cons, "%s\n", s);
		free (s);
	}
	r_table_free (t);
}

static void cmd_ic_sub(RCore *core, const char *input) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 0: 'o';
	RListIter *iter;
	RBinClass *k;
	RBinSymbol *m;

	const char ch0 = *input;
	if (ch0 == '*') {
		R_LOG_TODO ("Cannot reset binclass info");
		// reset!
		return;
	}
	if (ch0 == 0 || ch0 == '?') {
		// delete klass or method
		R_LOG_INFO ("Usage: ic-[klassname][.methodname]");
		return;
	}
	char *klass_name = strdup (input);
	char *method_name = r_str_after (klass_name, '.');
	RBinClass *klass = NULL;
	RList *klasses = r_bin_get_classes (core->bin);
	r_list_foreach (klasses, iter, k) {
		const char *kname = r_bin_name_tostring2 (k->name, pref);
		if (!strcmp (kname, klass_name)) {
			if (method_name) {
				klass = k;
			} else {
				// delete class!
				r_list_delete (klasses, iter);
				return;
			}
			break;
		}
	}
	if (klass && method_name) {
		r_list_foreach (klass->methods, iter, m) {
			const char *mname = r_bin_name_tostring2 (m->name, 'o');
			if (!strcmp (method_name, mname)) {
				r_list_delete (klass->methods, iter);
				return;
			}
		}
	}
	R_LOG_ERROR ("Cannot find given klass or method");
}

void cmd_ic_add(RCore *core, const char *input) {
	const char ch0 = *input;
	if (ch0 == 0 || ch0 == '?') {
		R_LOG_INFO ("Usage: ic+[klassname][.methodname]");
		return;
	}
	RList *klasses = r_bin_get_classes (core->bin);
	RListIter *iter;
	RBinClass *k;
	char *klass_name = strdup (input);
	char *method_name = r_str_after (klass_name, '.');
	RBinClass *klass = NULL;
	r_list_foreach (klasses, iter, k) {
		const char *kname = r_bin_name_tostring (k->name);
		if (!strcmp (kname, klass_name)) {
			klass = k;
			break;
		}
	}
	if (!klass) {
		klass = R_NEW0 (RBinClass);
		klass->name = r_bin_name_new (klass_name);
		r_list_append (klasses, klass);
	}
	if (method_name == NULL) {
		klass->addr = core->addr;
	} else {
		ut64 pa = core->addr; // XXX
		ut64 va = core->addr;
		RBinSymbol *m;
		bool found = false;
		r_list_foreach (klass->methods, iter, m) {
			const char *mname = r_bin_name_tostring2 (m->name, 'o');
			if (!strcmp (mname, method_name)) {
				found = true;
				break;
			}
		}
		if (!found) {
			RBinSymbol *sym = r_bin_symbol_new (method_name, pa, va);
			if (!klass->methods) {
				klass->methods = r_list_new ();
			}
			r_list_append (klass->methods, sym);
		}
	}
}

static void cmd_icg(RCore *core, RBinObject *obj, const char *arg) { // "icg"
	const int pref = r_config_get_b (core->config, "asm.demangle")? 0: 'o';
	RBinClass *cls;
	RListIter *iter, *iter2;
	if (!obj) {
		return;
	}
	bool fullGraph = true;
	const char *match = r_str_trim_head_ro (arg);
	if (R_STR_ISNOTEMPTY (match)) {
		r_list_foreach (obj->classes, iter, cls) {
			const char *kname = r_bin_name_tostring2 (cls->name, pref);
			if (!match || !strstr (kname, match)) {
				continue;
			}
			r_cons_printf (core->cons, "'agn %s\n", kname);
			if (cls->super) {
				RBinName *bn;
				r_list_foreach (cls->super, iter2, bn) {
					const char *sk = r_bin_name_tostring2 (bn, pref);
					if (match && strstr (sk, match)) {
						r_cons_printf (core->cons, "'agn %s\n", sk);
						r_cons_printf (core->cons, "'age %s %s\n", sk, kname);
					}
				}
			}
		}
	} else if (fullGraph) {
		r_list_foreach (obj->classes, iter, cls) {
			const char *kname = r_bin_name_tostring2 (cls->name, pref);
			RBinName *bn;
			r_cons_printf (core->cons, "'agn %s\n", kname);
			r_list_foreach (cls->super, iter2, bn) {
				const char *sk = r_bin_name_tostring2 (bn, pref);
				r_cons_printf (core->cons, "'agn %s\n", sk);
				r_cons_printf (core->cons, "'age %s %s\n", sk, kname);
			}
		}
	} else {
		r_list_foreach (obj->classes, iter, cls) {
			const char *kname = r_bin_name_tostring2 (cls->name, pref);
			char *sk;
			RListIter *iter;
			r_list_foreach (cls->super, iter, sk) {
				if (strstr (sk, "NSObject")) {
					continue;
				}
				r_cons_printf (core->cons, "'agn %s\n", sk);
				r_cons_printf (core->cons, "'agn %s\n", kname);
				r_cons_printf (core->cons, "'age %s %s\n", sk, kname);
			}
		}
	}
}

static bool isjvm(RCore *core) {
	RArchConfig *cfg = R_UNWRAP3 (core, rasm, config);
	if (cfg) {
		const char *arch = cfg->arch;
		if (!strcmp (arch, "dalvik")) {
			return true;
		}
		if (!strcmp (arch, "java")) {
			return true;
		}
	}
	return false;
}

#define RBININFO(n,x,y,z)\
	if (z) { tts_say (core, n, z); }\
	r_core_bin_info (core, x, pj, mode, va, NULL, y);

static void cmd_ic0(RCore *core, RBinObject *obj, int mode, PJ *pj, bool is_array, bool va, int idx, const char *cls_name, int *count, bool is_doublerad) {
	const bool iova = va; // r_config_get_b (core->config, "io.va");
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	RListIter *iter, *iter2;
	RBinSymbol *sym;
	RBinClass *cls;
	if (mode == 'c') {
		r_cons_printf (core->cons, "%d\n", r_list_length (obj->classes));
		return;
	}
	r_list_foreach (obj->classes, iter, cls) {
		const char *kname = r_bin_name_tostring2 (cls->name, pref);
		if ((idx >= 0 && idx != (*count)++) || (R_STR_ISNOTEMPTY (cls_name) && strcmp (cls_name, kname))) {
			continue;
		}
		if (is_doublerad) {
			r_cons_printf (core->cons, "'ac %s\n", kname);
			r_list_foreach (cls->methods, iter2, sym) {
				const char *name = r_bin_name_tostring2 (sym->name, pref);
				r_cons_printf (core->cons, "'ac %s %s 0x%08"PFMT64x"\n", kname,
						name, iova? sym->vaddr: sym->paddr);
			}
			continue;
		}
		bool listed_classes = false;

		switch (mode) {
		case '*':
			{
				listed_classes = true;
				int mode = R_MODE_RADARE;
				RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (obj->classes));
			}
#if 0
			r_list_foreach (cls->methods, iter2, sym) {
				r_cons_printf (core->cons, "f sym.%s @ 0x%"PFMT64x "\n",
						sym->name, iova? sym->vaddr: sym->paddr);
			}
#endif
			break;
		case 'l': // "icl"
			r_list_foreach (cls->methods, iter2, sym) {
				const char *comma = iter2->p? " ": "";
				r_cons_printf (core->cons, "%s0x%"PFMT64x, comma, iova? sym->vaddr: sym->paddr);
			}
			r_cons_newline (core->cons);
			break;
		case 'j':
			{
				int mode = R_MODE_JSON; // (oldmode == 'q')? R_MODE_SIMPLE: 0;
				int len = r_list_length (obj->classes);
				listed_classes = true;
				RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, len);
			}
			break;
		case 0:
			if (idx == -1 && R_STR_ISEMPTY (cls_name)) {
				size_t len = r_list_length (obj->classes);
				int mode = 0;
				RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, len);
				listed_classes = true;
			} else {
				r_cons_printf (core->cons, "class %s\n", kname);
				r_list_foreach (cls->methods, iter2, sym) {
					char *flags = r_core_bin_attr_tostring (core, sym->attr, true);
					const char *name = r_bin_name_tostring (sym->name);
					r_cons_printf (core->cons, "0x%08"PFMT64x " method %s %-4s %s\n",
							iova? sym->vaddr: sym->paddr,
							kname, flags, name);
					free (flags);
				}
			}
			break;
		case 'q':
			{
				size_t len = r_list_length (obj->classes);
				int mode = R_MODE_SIMPLE;
				RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, len);
				listed_classes = true;
			}
			break;
		default:
			r_cons_printf (core->cons, "class %s\n", kname);
			r_list_foreach (cls->methods, iter2, sym) {
				char *flags = r_core_bin_attr_tostring (core, sym->attr, true);
				const char *name = r_bin_name_tostring (sym->name);
				r_cons_printf (core->cons, "0x%08"PFMT64x " method %s %-4s %s\n",
						iova? sym->vaddr: sym->paddr,
						kname, flags, name);
				free (flags);
			}
			break;
		}
		if (listed_classes) {
			break;
		}
	}
}

static void cmd_ic(RCore *core, const char *input, PJ *pj, bool is_array, bool va) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	int cmd = input[0];
	int mode = 0;
	const char *arg = input + 2;
	const char *lastchar = strchr (input, ' ');
	if (lastchar) {
		arg = r_str_trim_head_ro (lastchar + 1);
		lastchar = lastchar - 1;
	} else {
		arg = "";
		lastchar = input + strlen (input) - 1;
	}
	bool show_help = false;
	if (*lastchar == '?') {
		show_help = true;
		lastchar--;
	}
	switch (*lastchar) {
	case 'j':
	case 'k':
	case '*':
	case 'q': // quiet
	case 'Q': // quieter
	case ',':
		mode = *lastchar;
		if (lastchar > input && cmd == *lastchar) {
			cmd = 'Q';
		}
		break;
	default:
		mode = 0;
		break;
	}
	const bool is_superquiet = strstr (input, "qq");
	const bool is_doublerad = strstr (input, "**");
	switch (cmd) {
	// help message
	case '?': // "ic?"
		r_core_cmd_help (core, help_msg_ic);
		break;
	case '-': // "ic-"
		cmd_ic_sub (core, input);
		break;
	case '+': // "ic+"
		cmd_ic_add (core, r_str_trim_head_ro (input + 1));
		break;
	case ',':
		mode = ',';
	// commands that iterate
	case ' ': // "ic "
	case 'k': // "ick"
	case 'q': // "icq"
	case 'Q': // "icQ" // "icqq"
	case '.': // "ic."
	case 's': // "ics"
	case 'g': // "icg"
	case 'j': // "icj"
	case 'l': // "icl"
	case 'c': // "icc"
	case '*': // "ic*"
	case 0: // "ic" "icq"
		if (mode == ',') {
			cmd_ic_comma (core, input);
		} else {
			if (show_help) {
				r_core_cmd_help_contains (core, help_msg_i, "ic");
				break;
			}
			bool is_jvm = isjvm (core);
			const bool iova = r_config_get_b (core->config, "io.va");
			RListIter *objs_iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			RList *objs = r_core_bin_files (core);
			int count = 0;
			int idx = -1;
			const char *cls_name = NULL;
			if (r_num_is_valid_input (core->num, arg)) {
				idx = r_num_math (core->num, arg);
			} else {
				const char *first_char = arg;
				int not_space = strspn (first_char, " ");
				if (first_char[not_space]) {
					cls_name = first_char + not_space;
				}
			}
			bool first = true;
			if (r_list_empty (objs) && mode == 'j') {
				r_cons_print (core->cons, "[]");
				return;
			}
			r_list_foreach (objs, objs_iter, bf) {
				RBinObject *bo = bf->bo;
				if (!bo || !bo->classes || r_list_empty (bo->classes)) {
					if (r_str_startswith (input, "lc")) { // "iclc"
						r_cons_printf (core->cons, "0\n");
					}
					if (mode == 'j') {
						r_cons_printf (core->cons, "%s[]", first? "": ",");
					}
					first = false;
					continue;
				}
				first = false;
				RBinClass *cls;
				RBinSymbol *sym;
				RListIter *iter, *iter2;
				core->bin->cur = bf;

				if (is_superquiet && is_jvm) {
					r_list_foreach (bo->classes, iter, cls) {
						const char *kname = r_bin_name_tostring (cls->name);
						if (!isKnownAndroidPackage (kname)) {
							r_cons_printf (core->cons, "%s\n", kname);
						}
					}
					break;
				}
				tts_say (core, "classes", r_list_length (bo->classes));
				switch (cmd) {
				case 'g': // "icg"
					cmd_icg (core, bo, arg);
					break;
				case 's': // "ics"
					r_list_foreach (bo->classes, iter, cls) {
						const char *kname = r_bin_name_tostring (cls->name);
						r_list_foreach (cls->methods, iter2, sym) {
							ut64 addr = iova? sym->vaddr: sym->paddr;
							if (addr == 0 || addr == UT64_MAX) {
								continue;
							}
							const char *sname = r_bin_name_tostring2 (sym->name, pref);
							r_cons_printf (core->cons, "0x%"PFMT64x" [%s] %s\n", addr, kname, sname);
						}
					}
					break;
				case 'k': // "ick"
					classdump_keys (core, bo);
					break;
				case 'l': // "icl"
					if (r_str_startswith (input, "lc")) {
						cmd_ic0 (core, bo, 'c', pj, is_array, va, idx, cls_name, &count, is_doublerad);
					} else {
						r_list_foreach (bo->classes, iter, cls) {
							r_list_foreach (cls->methods, iter2, sym) {
								const char *comma = iter2->p? " ": "";
								r_cons_printf (core->cons, "%s0x%"PFMT64x, comma,
										iova? sym->vaddr: sym->paddr);
							}
							if (!r_list_empty (cls->methods)) {
								r_cons_newline (core->cons);
							}
						}
					}
					break;
				case '.': // "ic."
					{
					ut64 addr = core->addr;
					ut64 min = UT64_MAX;
					const char *method = NULL;
					ut64 max = 0LL;
					r_list_foreach (bo->classes, iter, cls) {
						method = NULL;
						r_list_foreach (cls->methods, iter2, sym) {
							ut64 at = iova? sym->vaddr: sym->paddr;
							if (at < min) {
								min = at;
							}
							if (at + sym->size > max) {
								max = at + sym->size;
							}
							if (addr >= at && addr <= at + sym->size) {
								method = r_bin_name_tostring (sym->name);
							}
						}
						if (addr >= min && addr < max) {
							const char *kname = r_bin_name_tostring (cls->name);
							if (method) {
								r_cons_printf (core->cons, "%s::%s\n", kname, method);
							} else {
								r_cons_printf (core->cons, "%s\n", kname);
							}
						}
						min = UT64_MAX;
						max = 0LL;
					}
					}
					break;
				case 'c': // "icc"
					mode = R_MODE_CLASSDUMP;
					if (mode == '*') {
						mode |= R_MODE_RADARE;
					} else if (mode == 'k') { // "icck"
						classdump_keys (core, bo);
						return;
					}
					const char *lang = strchr (input, ' ');
					char *olang = NULL;
					if (lang) {
						olang = strdup (r_config_get (core->config, "bin.lang"));
						r_config_set (core->config, "bin.lang", lang + 1);
					}
					RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (bo->classes));
					if (olang) {
						r_config_set (core->config, "bin.lang", olang);
						free (olang);
					}
					// input = " ";
					break;
				case 'j':
					mode = R_MODE_JSON;
					RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (bo->classes));
					break;
				case '*':
					mode = R_MODE_RADARE;
					RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (bo->classes));
					break;
				case 'Q':
				case 'q':
					mode = (cmd == 'Q')? R_MODE_SIMPLEST: R_MODE_SIMPLE;
					// TODO add the ability to filter by name
					RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (bo->classes));
					break;
				case ' ': // "ic"
				case 0: // "ic"
					cmd_ic0 (core, bo, mode, pj, is_array, va, idx, cls_name, &count, is_doublerad);
					break;
				default:
					r_core_return_invalid_command (core, "ic", mode);
					break;
				}
				core->bin->cur = cur;
			}
		}
		break;
	default:
		r_core_return_invalid_command (core, "ic", cmd);
		break;
	}
}

static void cmd_iz(RCore *core, PJ *pj, int mode, int is_array, bool va, const char *input) {
	bool rdump = false;
	if (input[1] == '-') { // "iz-"
		char *strpurge = core->bin->strpurge;
		ut64 addr = core->addr;
		bool old_tmpseek = core->tmpseek;
		input++;
		if (input[1] == ' ') {
			const char *argstr = r_str_trim_head_ro (input + 2);
			ut64 arg = r_num_get (NULL, argstr);
			input++;
			if (arg != 0 || *argstr == '0') {
				addr = arg;
			}
		}
		core->tmpseek = false;
		r_core_cmdf (core, "e bin.str.purge=%s%s0x%" PFMT64x,
				r_str_get (strpurge),
				(strpurge && *strpurge)? ",": "",
				addr);
		core->tmpseek = old_tmpseek;
	} else if (input[1] == 'z') { // "izz"
		switch (input[2]) {
		case 'z':// "izzz"
			rdump = true;
			break;
		case '*': // "izz*"
			mode = R_MODE_RADARE;
			break;
		case 'j': // "izzj"
			mode = R_MODE_JSON;
			break;
		case 'q': // "izzq"
			if (input[3] == 'q') { // "izzqq"
				mode = R_MODE_SIMPLEST;
				input++;
			} else {
				mode = R_MODE_SIMPLE;
			}
			break;
		default:
			mode = R_MODE_PRINT;
			break;
		}
		input++;
		if (rdump) {
			RBinFile *bf = r_bin_cur (core->bin);
			int min = r_config_get_i (core->config, "bin.str.min");
			if (bf) {
				bf->strmode = mode;
				RList *res = r_bin_dump_strings (bf, min, 2);
				r_list_free (res);
			}
		} else {
			RBININFO ("strings", R_CORE_BIN_ACC_RAW_STRINGS, NULL, 0);
		}
	} else {
		// "iz"
		bool validcmd = true;
		switch (input[1]) {
		case ',': // "iz,"
			R_FREE (core->table_query);
			core->table_query = strdup (input + 2);
			break;
		case 'J': // "izJ"
			validcmd = false;
			break;
		case '*': // "iz*"
		case 'j': // "izj"
		case 0: // "iz"
			validcmd = true;
			break;
		case 'q':
			// "izq"
			mode = (input[2] == 'q')
				? R_MODE_SIMPLEST
				: R_MODE_SIMPLE;
			input++;
			break;
		default:
			// invalid subcommand handler?
			break;
		}
		if (validcmd) {
			RList *bfiles = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			r_list_foreach (bfiles, iter, bf) {
				core->bin->cur = bf;
				RBinObject *bo = r_bin_cur_object (core->bin);
				RBININFO ("strings", R_CORE_BIN_ACC_STRINGS, NULL,
						(bo && bo->strings)? r_list_length (bo->strings): 0);
			}
			core->bin->cur = cur;
			r_list_free (bfiles);
		} else {
			//
		}
	}
}

static bool inrange(RBinSection *sec, RBinSymbol *sym) {
	if (sym->vaddr >= sec->vaddr) {
		if (sym->vaddr < sec->vaddr + sec->vsize) {
			return true;
		}
	}
	return false;
}

static void cmd_iSm(RCore *core, const char *input, PJ **_pj, int mode, const bool va, const bool is_array) {
	// TODO: Add iSm= to show with progressbars
	RListIter *iter, *iter2;
	RBinSection *sec;
	RBinSymbol *sym;
	bool countmode = (input[2] == 'c');

	RBinFile *bf = core->bin->cur;
	if (!bf) {
		return;
	}
	RBinObject *bo = bf->bo;
	if (!bo) {
		return;
	}

	PJ *pj = *_pj;
	RList *symbols = r_bin_file_get_symbols (bf);
	r_list_foreach (bo->sections, iter, sec) {
		int vsize = sec->vsize;
		if (vsize < 1) {
			continue;
		}
		if (pj) {
			pj_o (pj);
			pj_ks (pj, "section", sec->name);
			pj_ka (pj, "symbols");
			r_list_foreach (symbols, iter2, sym) {
				if (inrange (sec, sym)) {
					pj_o (pj);
					pj_ks (pj, "name", r_bin_name_tostring (sym->name));
					if (sym->size > 0) {
						pj_ki (pj, "size", sym->size);
						pj_kd (pj, "percent", (sym->size * 100 ) / vsize);
					}
					pj_end (pj);
				}
			}
			pj_end (*_pj);
			pj_end (*_pj);
		} else {
			char *hsz = r_num_units (NULL, 0, sec->vsize);
			r_cons_printf (core->cons, "0x%08"PFMT64x"-0x%08"PFMT64x" %8s %s",
					sec->vaddr, sec->vaddr + sec->vsize, hsz, sec->name);
			free (hsz);
			if (countmode) {
				int count = 0;
				r_list_foreach (symbols, iter2, sym) {
					if (inrange (sec, sym)) {
						count++;
					}
				}
				r_cons_printf (core->cons, " = %d symbols\n", count);
			} else {
				r_cons_newline (core->cons);
				r_list_foreach (symbols, iter2, sym) {
					if (inrange (sec, sym)) {
						r_cons_printf (core->cons, "    - %8d %s\n",
								sym->size, r_bin_name_tostring (sym->name));
					}
				}
			}
		}
	}
}

static void cmd_iS(RCore *core, const char *input, PJ **_pj, int mode, const bool va, const bool is_array) {
	PJ *pj = *_pj;
	RBinInfo *info = r_bin_get_info (core->bin);
	if (!info && pj) {
		r_cons_print (core->cons, "[]");
		r_core_return_value (core, 1);
		return;
	}
	if (!input[1]) {
		RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, NULL, 0);
	} else if (input[1] == 'm') {
		cmd_iSm (core, input, &pj, mode, va, is_array);
	} else if (input[1] == 'S' && !input[2]) { // "iSS"
		RBININFO ("segments", R_CORE_BIN_ACC_SEGMENTS, NULL, 0);
	} else { // iS/iSS entropy,sha1
		const char *name = "sections";
		int action = R_CORE_BIN_ACC_SECTIONS;
		int param_shift = 0;
		if (input[1] == 'S') {
			name = "segments";
			input++;
			action = R_CORE_BIN_ACC_SEGMENTS;
		}
		char input0 = input[1];
		if (*input == ' ') {
			input ++;
		}
		const char *comma = strchr (input, ',');
		if (comma) {
			R_FREE (core->table_query);
			core->table_query = strdup (comma + 1);
		}
		switch (input0) {
		case '=': // "iS="
			mode = R_MODE_EQUAL;
			break;
		case '*':
			mode = R_MODE_RADARE;
			break;
		case 'q':
			mode = (input[2] == 'q')? R_MODE_SIMPLEST: R_MODE_SIMPLE;
			break;
		case 'j':
			if (input[2] == '.') {
				mode = R_MODE_JSON;
				if (!pj) {
					*_pj = r_core_pj_new (core);
					pj = *_pj;
					// pj_o (pj);
				}
			}
		}
		if (mode == R_MODE_RADARE || mode == R_MODE_JSON || mode == R_MODE_SIMPLE) {
			if (input[param_shift + 1]) {
				param_shift ++;
			}
		}
		{
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			r_list_foreach (objs, iter, bf) {
				RBinObject *obj = bf->bo;
				core->bin->cur = bf;
				int count = (obj && obj->sections)? r_list_length (obj->sections): 0;
				RBININFO (name, action, input + 1 + param_shift, count);
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
	}
}

static bool bin_header(RCore *r, int mode) {
	R_RETURN_VAL_IF_FAIL (r, false);
	RBinFile *cur = r_bin_cur (r->bin);
	if (cur) {
		RBinPlugin *plg = r_bin_file_cur_plugin (cur);
		if (plg && plg->header) {
			plg->header (cur);
			return true;
		}
	}
	return false;
}

static void cmd_it(RCore *core, PJ *pj) {
	bool is_json = pj != NULL;
	ut64 limit = r_config_get_i (core->config, "bin.hashlimit");
	RBinInfo *info = r_bin_get_info (core->bin);
	if (!info) {
		if (is_json) {
			r_cons_print (core->cons, "{}");
		} else {
			R_LOG_ERROR ("Cannot get bin info");
		}
		r_core_return_value (core, 1);
		return;
	}

	RList *new_hashes = r_bin_file_compute_hashes (core->bin, limit);
	RList *old_hashes = r_bin_file_set_hashes (core->bin, new_hashes);
	bool equal = true;
	if (!r_list_empty (new_hashes) && !r_list_empty (old_hashes)) {
		if (!is_equal_file_hashes (new_hashes, old_hashes, &equal)) {
			R_LOG_ERROR ("is_equal_file_hashes: Cannot compare file hashes");
			r_list_free (old_hashes);
			r_core_return_value (core, 1);
			return;
		}
	}
	RBinFileHash *fh_old, *fh_new;
	RListIter *hiter_old, *hiter_new;
	if (is_json) { // "itj"
		pj_o (pj);
		r_list_foreach (new_hashes, hiter_new, fh_new) {
			pj_ks (pj, fh_new->type, fh_new->hex);
		}
		if (!equal) {
			// print old hashes prefixed with `o` character like `omd5` and `isha1`
			r_list_foreach (old_hashes, hiter_old, fh_old) {
				char *key = r_str_newf ("o%s", fh_old->type);
				pj_ks (pj, key, fh_old->hex);
				free (key);
			}
		}
		pj_end (pj);
	} else { // "it"
		if (!equal) {
			R_LOG_INFO ("File has been modified");
			hiter_new = r_list_iterator (new_hashes);
			hiter_old = r_list_iterator (old_hashes);
			while (r_list_iter_next (hiter_new) && r_list_iter_next (hiter_old)) {
				fh_new = (RBinFileHash *)r_list_iter_get (hiter_new);
				fh_old = (RBinFileHash *)r_list_iter_get (hiter_old);
				if (strcmp (fh_new->type, fh_old->type)) {
					R_LOG_WARN ("Wrong file hashes structure");
				}
				if (!strcmp (fh_new->hex, fh_old->hex)) {
					r_cons_printf (core->cons, "= %s %s\n", fh_new->type, fh_new->hex); // output one line because hash remains same `= hashtype hashval`
				} else {
					// output diff-like two lines, one with old hash val `- hashtype hashval` and one with new `+ hashtype hashval`
					r_cons_printf (core->cons, "- %s %s\n+ %s %s\n",
							fh_old->type, fh_old->hex,
							fh_new->type, fh_new->hex);
				}
			}
		} else { // hashes are equal
			r_list_foreach (new_hashes, hiter_new, fh_new) {
				r_cons_printf (core->cons, "%s %s\n", fh_new->type, fh_new->hex);
			}
		}
	}
	r_list_free (old_hashes);
}

static void cmd_idp(RCore *core, PJ *pj, const char *input, bool is_array, int mode) {
	SPDBOptions pdbopts;
	RBinInfo *info;
	bool file_found;
	char *filename;

	switch (input[2]) {
	case ' ': // "idp file.pdb"
		r_core_cmdf (core, ".idpi* %s", input + 3);
		break;
	case '\0': // "idp"
		r_core_cmd0 (core, ".idpi*");
		break;
	case 'd': // "idpd"
		if (input[3] == '?') {
			r_core_cmd_help_contains (core, help_msg_id, "idpd");
			break;
		}
		pdbopts.user_agent = (char*) r_config_get (core->config, "pdb.useragent");
		pdbopts.extract = r_config_get_i (core->config, "pdb.extract");
		pdbopts.symbol_store_path = (char*) r_config_get (core->config, "pdb.symstore");
		char *str = strdup (r_config_get (core->config, "pdb.server"));
		RList *server_l = r_str_split_list (str, " ", 0);
		RListIter *it;
		char *server;
		int r = 1;
		r_list_foreach (server_l, it, server) {
			pdbopts.symbol_server = server;
			r = r_bin_pdb_download (core, pj, &pdbopts);
			if (!r) {
				break;
			}
		}
		if (r > 0) {
			R_LOG_ERROR ("Cannot download the pdb file");
		}
		free (str);
		r_list_free (server_l);
		input++;
		break;
	case 'i': // "idpi"
		if (input[3] == '?') {
			r_core_cmd_help_contains (core, help_msg_id, "idpi");
			break;
		}
		info = r_bin_get_info (core->bin);
		filename = strchr (input, ' ');
		while (input[2]) {
			input++;
		}
		if (filename) {
			*filename++ = '\0';
			filename = strdup (filename);
			file_found = r_file_exists (filename);
		} else {
			/* Autodetect local file */
			if (!info || !info->debug_file_name) {
				R_LOG_ERROR ("Cannot get file's debug information");
				break;
			}
			// Check raw path for debug filename
			const char *dfn = r_file_basename (info->debug_file_name);
			file_found = r_file_exists (dfn);
			if (file_found) {
				filename = strdup (dfn);
			} else {
				// Check debug filename basename in current directory
				char* basename = (char*) r_file_basename (dfn);
				file_found = r_file_exists (basename);
				if (!file_found) {
					// Check if debug file is in file directory
					char *dir = r_file_dirname (core->bin->cur->file);
					filename = r_str_newf ("%s/%s", dir, basename);
					file_found = r_file_exists (filename);
					free (dir);
				} else {
					filename = strdup (basename);
				}
			}

			// Last chance: Check if file is in downstream symbol store
			if (!file_found) {
				const char* symstore_path = r_config_get (core->config, "pdb.symstore");
				const char *base_file = r_file_basename (info->debug_file_name);
				char* pdb_path = r_str_newf ("%s" R_SYS_DIR "%s" R_SYS_DIR "%s" R_SYS_DIR "%s",
						symstore_path, base_file, info->guid, base_file);
				file_found = r_file_exists (pdb_path);
				if (file_found) {
					free (filename);
					filename = pdb_path;
				} else {
					free (pdb_path);
				}
			}
		}
		if (!file_found) {
			if (info->debug_file_name) {
				const char *fn = r_file_basename (info->debug_file_name);
				R_LOG_ERROR ("File '%s' not found in file directory or symbol store", fn);
			} else {
				R_LOG_ERROR ("Cannot open file");
			}
			r_core_return_value (core, 1);
			free (filename);
			break;
		}
		r_core_pdb_info (core, filename, pj, mode);
		free (filename);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_id);
		break;
	default:
		r_core_return_invalid_command (core, "id", input[1]);
		break;
	}
}

static void cmd_id(RCore *core, PJ *pj, const char *input, bool is_array, int mode) {
	const bool va = r_config_get_b (core->config, "io.va");
	switch (input[1]) {
	case 'l': // "idl"
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_idl);
		} else {
			char *linkname = NULL;
			RBinInfo *info = r_bin_get_info (core->bin);
			if (info && info->dbglink) {
				linkname = strdup (info->dbglink);
				char *dot = (char *)r_str_lchr (linkname, '.');
				if (dot) {
					*dot = 0;
				}
			}
			switch (input[2]) {
			case 'd':
				if (linkname) {
					char *url = r_str_newf ("%s/%s/debuginfo", r_config_get (core->config, "dbg.linkurl"), linkname);
					if (input[3] == '*') {
						r_cons_printf (core->cons, "%s\n", url);
					} else {
						char *dir_debuglink = strdup (r_config_get (core->config, "dir.debuglink"));
						char *colon = strchr (dir_debuglink, ':');
						if (colon) {
							*colon = 0;
						}
						// TODO: check if file exists before downloading
						// TODO: use seprate path instead of the first one from the list?
						R_LOG_WARN ("This curl oneliner is subject to command injection. Use it at your own risk");
						r_sys_cmdf ("curl -o \"%s/%s\" \"%s\"", dir_debuglink, info->dbglink, url);
						free (dir_debuglink);
					}
					free (url);
				} else {
					R_LOG_ERROR ("No debuglink file to download");
				}
				break;
			case '*':
				if (linkname) {
					char *dirlink = strdup (r_config_get (core->config, "dir.debuglink"));
					RList *paths = r_str_split_list (dirlink, ":", 0);
					RListIter *iter;
					bool found = false;
					char *path;
					r_list_foreach (paths, iter, path) {
						char *f = r_str_newf ("%s/%s", path, info->dbglink);
						if (r_file_exists (f)) {
							found = true;
							r_cons_printf (core->cons, "'obf %s\n", f);
							free (f);
							break;
						}
						free (f);
					}
					r_list_free (paths);
					free (dirlink);
					if (!found) {
						R_LOG_ERROR ("Cannot find %s in dir.debuglink. Use idld instead", info->dbglink);
						r_cons_printf (core->cons, "'obf %s\n", info->dbglink);
					}
				}
				break;
			case 0:
				if (linkname) {
					r_cons_println (core->cons, info->dbglink);
				}
				break;
			default:
				r_core_return_invalid_command (core, "idl", input[2]);
				break;
			}
			free (linkname);
		}
		break;
	case 'x': // "idx"
		RBININFO ("source", R_CORE_BIN_ACC_SOURCE, NULL, 0);
		break;
	case 'p': // "idp"
		cmd_idp (core, pj, input, is_array, mode);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_id);
		break;
	case 0:
	case '*':
	case 'j':
	case 'q':
		RBININFO ("dwarf", R_CORE_BIN_ACC_ADDRLINE, NULL, -1);
		break;
	default:
		r_core_return_invalid_command (core, "id", input[1]);
		break;
	}
}

static void cmd_is(RCore *core, const char *input, PJ *pj, bool is_array, int mode, bool va) {
	RList *objs = r_core_bin_files (core);
	RListIter *iter;
	RBinFile *bf;
	if (r_list_empty (objs)) {
		if (pj) {
			pj_a (pj);
			pj_end (pj);
		}
		r_list_free (objs);
		return;
	}
	r_list_foreach (objs, iter, bf) {
		RBinObject *obj = bf->bo;
		if (!obj) {
			continue;
		}
		core->bin->cur = bf;
		// Case for isj.
#if R2_590
		// TODO: use obj->symbols_vec if obj->symbols is null
#else
		size_t symcount = (obj && obj->symbols)? r_list_length (obj->symbols): 0;
		if (input[1] == 'j' && input[2] == '.') {
			RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, symcount);
		} else if (input[1] == ',') {
			R_FREE (core->table_query);
			core->table_query = strdup (input + 2);
			RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, symcount);
		} else if (input[1] == 'q' && input[2] == 'q') {
			mode = R_MODE_SIMPLEST;
			RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 3, symcount);
		} else if (input[1] == 'q' && input[2] == '.') {
			mode = R_MODE_SIMPLE;
			RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, 0);
		} else {
			RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, symcount);
		}
#endif
	}
	input += strlen (input) - 1;
	r_list_free (objs);
}

static void cmd_ik(RCore *core, const char *input) {
	RBinObject *o = r_bin_cur_object (core->bin);
	Sdb *db = o? o->kv: NULL;
	switch (input[1]) {
	case 'v':
		if (db) {
			char *o = sdb_querys (db, NULL, 0, input + 3);
			if (R_STR_ISNOTEMPTY (o)) {
				r_cons_print (core->cons, o);
			}
			free (o);
		}
		break;
	case '*':
		r_core_bin_export_info (core, R_MODE_RADARE);
		break;
	case '.':
	case ' ':
		if (db) {
			char *o = sdb_querys (db, NULL, 0, input + 2);
			if (R_STR_ISNOTEMPTY (o)) {
				r_cons_print (core->cons, o);
			}
			free (o);
		}
		break;
	case '\0':
		if (db) {
			char *o = sdb_querys (db, NULL, 0, "*");
			if (R_STR_ISNOTEMPTY (o)) {
				r_cons_print (core->cons, o);
			}
			free (o);
		}
		break;
	case '?':
	default:
		r_core_cmd_help_contains (core, help_msg_i, "ik");
		break;
	}
}

struct fdof_t {
	RCore *core;
	const char *fn;
	int fd;
};

static bool fdof_cb(void *user, void *data, ut32 id) {
	struct fdof_t *fof = (struct fdof_t *)user;
	RIODesc *desc = (RIODesc *)data;
	if (fof && desc) {
		if (!strcmp (desc->uri, fof->fn)) {
			fof->fd = desc->fd;
			return false;
		}
	}
	return true;
}

static bool is_entrypoint_symbol(const char *name) {
#if 0
	On Swift any method can be an entrypoint if @main is used as attribute
#endif
	const char *words[] = {
		"main", "_start", "_main", "Main",
		"WinMain", "wmain", "DllMain", "wWinMain",
		"UIApplicationMain",
		"applicationDidFinishLaunching",
		"application:didFinishLaunchingWithOptions",
		"applicationWillResignActive",
		"applicationDidEnterBackground",
		"applicationWillEnterForeground",
		"applicationDidBecomeActive",
		"applicationWillTerminate",
		"application:configurationForConnectingSceneSession:options",
		"application:didDiscardSceneSessions",
		"application:openURL:options",
		"application:performFetchWithCompletionHandler",
		"application:didReceiveRemoteNotification:fetchCompletionHandler",
		"application:handleEventsForBackgroundURLSession:completionHandler",
		"application:shouldSaveSecureApplicationState",
		"application:shouldRestoreSecureApplicationState",
		"application:didRegisterForRemoteNotificationsWithDeviceToken",
		"application:didFailToRegisterForRemoteNotificationsWithError",
		"application:didReceiveRemoteNotification",
		"application:handleOpenURL",
		"application:continueUserActivity:restorationHandler",
		"application:didUpdateUserActivity",
		"scene:willConnectToSession:options",
		"sceneDidDisconnect",
		"sceneDidBecomeActive",
		"sceneWillResignActive",
		"sceneWillEnterForeground",
		"sceneDidEnterBackground",
		"application:handleWatchKitExtensionRequest:reply",
		"main",
		"loadView",
		"viewDidLoad"
	};
	size_t i, size = sizeof (words) / sizeof (words[0]);

	for (i = 0; i < size; i++) {
		if (!strcmp (name, words[i])) {
			return true;
		}
	}
	return false;
}

static void cmd_ies(RCore *core, const char *input, PJ *pj, int mode, int va) {
	// iterate over symbols and class methods that match
	RBinSymbol *sym;
	RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
	if (symbols) {
		R_VEC_FOREACH (symbols, sym) {
			const char *name = r_bin_name_tostring2 (sym->name, 'o');
			if (is_entrypoint_symbol (name)) {
				if (pj) {
					pj_o (pj);
					pj_kn (pj, "addr", sym->vaddr);
					pj_ks (pj, "name", name);
					pj_end (pj);
				} else {
					r_cons_printf (core->cons, "0x%08"PFMT64x"  %s\n", sym->vaddr, name);
				}
			}
		}
	}
	RList *bfiles = r_core_bin_files (core);
	if (!bfiles) {
		return;
	}
	RBinFile *bf;
	RListIter *objs_iter;
	r_list_foreach (bfiles, objs_iter, bf) {
		RBinObject *obj = bf->bo;
		RBinClass *klass;
		RListIter *iter, *iter2;
		core->bin->cur = bf;
		RBinSymbol *method;
		r_list_foreach (obj->classes, iter, klass) {
			r_list_foreach (klass->methods, iter2, method) {
				const char *name = r_bin_name_tostring2 (method->name, 'o');
				if (is_entrypoint_symbol (name)) {
					const char *kname = r_bin_name_tostring2 (klass->name, 'o');
					if (pj) {
						pj_o (pj);
						pj_kn (pj, "addr", method->vaddr);
						char *fname = r_str_newf ("%s.%s", kname, name);
						pj_ks (pj, "name", fname);
						free (fname);
						pj_end (pj);
					} else {
						r_cons_printf (core->cons, "0x%08"PFMT64x"  %s.%s\n",
								method->vaddr, kname, name);
					}
				}
			}
		}
	}
	RFlagItem *fi = r_flag_get (core->flags, "main");
	if (fi) {
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "addr", fi->addr);
			pj_ks (pj, "name", "main");
			pj_end (pj);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x"  main\n", fi->addr);
		}
	}
	fi = r_flag_get (core->flags, "entry0");
	if (fi) {
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "addr", fi->addr);
			pj_ks (pj, "name", "entry0");
			pj_end (pj);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x"  entry0\n", fi->addr);
		}
	}
}

static void cmd_ie(RCore *core, const char *input, PJ *pj, int mode, bool is_array, int va) {
	char i1 = input[1];
	char i2 = input[1]? input[2]: 0;
	if (i1 == ',') {
		i1 = 0;
		R_FREE (core->table_query);
		core->table_query = strdup (input + 2);
	}
	if (i1 == '?') {
		r_core_cmd_help (core, help_msg_ie);
	} else if (i1 == 's') {
		if (i2 == '?') {
			r_core_cmd_help_contains (core, help_msg_ie, "ies");
		} else {
			cmd_ies (core, input, pj, mode, va);
		}
	} else if (i1 == ' ' || i1 == '*' || i1 == 'e' || i1 == 'j' || i1 == '=' || i1 == 'q' || !i1) {
		if (i1 && i2 == '?') {
			r_core_cmd_help (core, help_msg_ie);
			return;
		}
		RList *objs = r_core_bin_files (core);
		RListIter *iter;
		RBinFile *bf;
		RBinFile *cur = core->bin->cur;
		size_t objs_count = r_list_length (objs);
		bool show_constructors = r_str_startswith (input, "ee"); // "iee"
		if (objs_count == 1) {
			if (show_constructors) {
				RBININFO ("initfini", R_CORE_BIN_ACC_INITFINI, NULL, 0);
			} else {
				RBININFO ("entries", R_CORE_BIN_ACC_ENTRIES, NULL, 0);
			}
		} else {
			if (mode & R_MODE_JSON) {
				pj_a (pj);
			}
			r_list_foreach (objs, iter, bf) {
				if (mode & R_MODE_JSON) {
					pj_o (pj);
					pj_kn (pj, "id", bf->id);
					pj_ks (pj, "filename", bf->file);
					pj_k (pj, "data");
				}
				core->bin->cur = bf;
				if (show_constructors) {
					RBININFO ("initfini", R_CORE_BIN_ACC_INITFINI, NULL, 0);
				} else {
					RBININFO ("entries", R_CORE_BIN_ACC_ENTRIES, NULL, 0);
				}
				if (mode & R_MODE_JSON) {
					pj_end (pj);
				}
			}
			if (mode & R_MODE_JSON) {
				pj_end (pj);
			}
		}
		core->bin->cur = cur;
		r_list_free (objs);
	} else {
		r_core_return_invalid_command (core, "ie", input[1]);
	}
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *) data;
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	int i;
	const bool va = core->io->va || r_config_get_b (core->config, "cfg.debug");
	bool is_array = false;
	PJ *pj = NULL;

	if (r_str_startswith (input, "ddqd")) {
		r_cons_printf (core->cons, "GOD MODE ON\n");
		return 0;
	}
	int mode = 0;
#if 1
	// advance input until theres a space.. maybe not needed
	for (i = 0; input[i] && input[i] != ' '; i++)
		;
	if (i > 0) {
		switch (input[i - 1]) {
		case '*': mode = R_MODE_RADARE; break;
		case 'j': mode = R_MODE_JSON; break;
		case '=': mode = R_MODE_EQUAL; break;
		case 'k': mode = R_MODE_KV; break;
		case 'q':
			if (i > 1 && input[i - 2] == 'q') {
				mode = R_MODE_SIMPLEST;
			} else {
				mode = R_MODE_SIMPLE;
			}
			break;
		}
	}
#endif
	#define INIT_PJ()\
		if (!pj) {\
			pj = r_core_pj_new (core);\
			if (!pj) {\
				return 1;\
			}\
		}
	if (mode == R_MODE_JSON) {
		INIT_PJ ();
	}
	r_core_return_value (core, 0);
	if (!*input) {
		cmd_info_bin (core, va, pj, mode);
	}
	/* i* is an alias for iI* */
	if (!strcmp (input, "*")) {
		input = "I*";
	}
	char *question = strchr (input, '?');
	const char *space = strchr (input, ' ');
	if (!space && question) {
		space = question + 1;
	}
	if (input[0] && input[1] == '?') {
		char cmd[3] = "ii";
		cmd[1] = input[0];
		switch (input[0]) {
		case 'h': // "ih?"
			r_core_cmd_help (core, help_msg_ih);
			break;
		case 'E': // "iE?"
			r_core_cmd_help (core, help_msg_iE);
			break;
		case 's': // "is?"
			r_core_cmd_help (core, help_msg_is);
			break;
		case 'S': // "iS?"
			r_core_cmd_help (core, help_msg_iS);
			break;
		case 'z': // "iz?"
			r_core_cmd_help (core, help_msg_iz);
			break;
		case 'c': // "ic?"
			r_core_cmd_help (core, help_msg_ic);
			break;
		case 'd': // "id?"
			r_core_cmd_help (core, help_msg_id);
			break;
		case 'e': // "ie?"
			r_core_cmd_help (core, help_msg_ie);
			break;
		default:
			r_core_cmd_help_contains (core, help_msg_i, cmd);
			break;
		}
		return 0;
	}
	switch (input[0]) {
	case 'O': // "iO"
		{
			char *res = NULL;
			switch (input[1]) {
			case ' ':
				res = r_sys_cmd_strf ("rabin2 -O \"%s\" \"%s\"",
					r_str_trim_head_ro (input + 1), desc->name);
				break;
			default:
				res = r_sys_cmd_strf ("rabin2 -O help");
				break;
			}
			if (res) {
				r_cons_print (core->cons, res);
				free (res);
			}
		}
		break;
	case 'i': // "ii"
		if (input[1] == 'c') { // "iic"
			return cmd_iic (core, input);
		} else {
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (input[1] == ',') {
				R_FREE (core->table_query);
				core->table_query = strdup (input + 2);
			}
			if (!r_list_empty (objs)) {
				r_list_foreach (objs, iter, bf) {
					RBinObject *obj = bf->bo;
					core->bin->cur = bf;
					int amount = (obj && obj->imports)? r_list_length (obj->imports): 0;
					RBININFO ("imports", R_CORE_BIN_ACC_IMPORTS, NULL, amount);
				}
			} else if (mode & R_MODE_JSON) {
				r_cons_print (core->cons, "[]");
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
		break;
	case 'I': // "iI" -- dupe of "i"
		{
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (!cur && pj) {
				r_cons_print (core->cons, "{}");
			}
			r_list_foreach (objs, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("info", R_CORE_BIN_ACC_INFO, NULL, 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
		break;
	case 'M': // "iM"
		{
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (!cur && pj) {
				r_cons_print (core->cons, "{}");
			}
			r_list_foreach (objs, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("main", R_CORE_BIN_ACC_MAIN, NULL, 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
		break;
	case 'm': // "im"
		{
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (!cur && pj) {
				r_cons_print (core->cons, "[]");
			}
			r_list_foreach (objs, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("memory", R_CORE_BIN_ACC_MEM, input + 1, 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
		break;
	case 'w': // "iw"
		{
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			r_list_foreach (objs, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("trycatch", R_CORE_BIN_ACC_TRYCATCH, NULL, 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
		break;
	case 'v': // "iv" // should replace iV imho.. but 'V' is there because of rabin2 -v is for version
	case 'V': // "iV"
		{
			RList *bfiles = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (!cur && pj) {
				r_cons_print (core->cons, "[]");
			}
			r_list_foreach (bfiles, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("versioninfo", R_CORE_BIN_ACC_VERSIONINFO, NULL, 0);
			}
			core->bin->cur = cur;
			r_list_free (bfiles);
		}
		break;
	case 'q': // "iq"
		mode = R_MODE_SIMPLE;
		cmd_info_bin (core, va, pj, mode);
		break;
	case 'j': // "ij"
		mode = R_MODE_JSON;
		if (is_array) {
			mode |= R_MODE_ARRAY;
		}
		INIT_PJ ();
		cmd_info_bin (core, va, pj, mode);
		break;
	case 'E':
		if (input[1] == 'j' && input[2] == '.') {
			mode = R_MODE_JSON;
			INIT_PJ ();
			RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, input + 2, 0);
		} else if (input[1] == ',') {
			R_FREE (core->table_query);
			core->table_query = strdup (input + 2);
			RBinObject *obj = r_bin_cur_object (core->bin);
			RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS,
				input + 1, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
			// table query here
		} else {
			RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, input + 1, 0);
		}
		input = input + strlen (input) - 1;
		break;
	case 'a': // "ia"
		if (r_str_startswith (input, "iaito")) {
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2iaito");
		} else if (input[1] == 'j') {
			RTable *t = r_core_table_new (core, "archs");
			pj_o (pj); // weird
			r_bin_list_archs (core->bin, pj, t, 'j');
			pj_end (pj);
		} else {
			RTable *t = r_core_table_new (core, "archs");
			r_bin_list_archs (core->bin, NULL, t, 1);
		}
		break;
	case 'e': // "ie"
		cmd_ie (core, input, pj, mode, is_array, va);
		break;
	case 'k': // "ik"
		cmd_ik (core, input);
		break;
	case 'o': // "io"
		if (desc) {
			int oldfd = -1;
			const char *fn = (input[1] == ' ')
				? r_str_trim_head_ro (input + 2): desc->name;
			struct fdof_t fof = { core, fn, -1 };
			r_id_storage_foreach (&core->io->files, fdof_cb, &fof);
			if (fof.fd != -1) {
				oldfd = fof.fd;
			}
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			fof.fd = -1;
			r_core_bin_load (core, fn, baddr);
			r_id_storage_foreach (&core->io->files, fdof_cb, &fof);
			if (fof.fd != oldfd) {
				r_core_cmdf (core, "o-%d", fof.fd);
			}
		} else {
			R_LOG_ERROR ("Core file not open");
			return 0;
		}
		break;
	case 'h': // "ih"
		if (question) {
			r_core_cmd_help (core, help_msg_ih);
		} else {
			RBININFO ("fields", R_CORE_BIN_ACC_FIELDS, NULL, 0);
		}
		break;
	case 'H': // "iH"
		if (question) {
			r_core_cmd_help (core, help_msg_iH);
		} else if (!bin_header (core, mode)) {
			/// XXX header vs fields wtf
			if (!r_core_bin_info (core, R_CORE_BIN_ACC_HEADER, pj, mode, va, NULL, NULL)) {
				if (!pj) {
					R_LOG_ERROR ("No header fields found");
				}
				r_core_return_value (core, 1);
			}
		}
		break;
	case 'L': // "iL"
		{
			char *ptr = strchr (input, ' ');
			int json = input[1] == 'j'? 'j': 0;

			if (ptr && ptr[0] && ptr[1]) {
				const char *plugin_name = ptr + 1;
				if (is_array) {
					pj_k (pj, "plugin");
				}
				r_bin_list_plugin (core->bin, plugin_name, pj, json);
			} else {
				r_bin_list (core->bin, pj, json);
			}
			break;
		}
	case 't': // "it"
		cmd_it (core, pj);
		break;
	case 'Z': // "iZ"
		RBININFO ("size", R_CORE_BIN_ACC_SIZE, NULL, 0);
		break;
	case 'R': // "iR"
		RBININFO ("resources", R_CORE_BIN_ACC_RESOURCES, NULL, 0);
		break;
	case 'g': // "ig"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_i, "ig");
		} else if (input[1] == 'h') {
			char ss[64];
			ut64 bs = r_bin_get_size (core->bin);
			if (r_num_units (ss, sizeof (ss), bs)) {
				r_cons_printf (core->cons, "%s\n", ss);
			}
		} else {
			ut64 bs = r_bin_get_size (core->bin);
			r_cons_printf (core->cons, "0x%08"PFMT64x"\n", bs);
		}
		break;
	case 'c': // "ic"
		cmd_ic (core, input + 1, pj, is_array, va);
		break;
	case 'D': // "iD"
		cmd_info_demangle (core, input, pj, mode);
		break;
	case ':': // "i:"
		if (!r_bin_command (core->bin, input)) {
			R_LOG_ERROR ("Unhandled RBinPlugin.cmd");
		}
		break;
	case 's': // "is"
		switch (input[1]) {
		case 'e': // "ise"
			r_core_cmdf (core, "ies%s", input + 1);
			return 0;
		case '*':
			mode = R_MODE_RADARE;
			break;
		case 'j':
			mode = R_MODE_JSON;
			INIT_PJ ();
			break;
		case 'q':
			if (input[2] == 'q') {
				mode = R_MODE_SIMPLEST;
			}
		case 0:
		case ' ':
		case '.':
		case ',':
			break;
		default:
			r_core_return_invalid_command (core, "is", input[1]);
			break;
		}
		cmd_is (core, input, pj, is_array, mode, va);
		break;
	case 'T': // "iT"
	case 'C': // "iC" // rabin2 -C create // should be deprecated and just use iT (or find a better name)
		{
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (!cur && pj) {
				r_cons_print (core->cons, "{}");
				break;
			}
			RList *bfiles = r_core_bin_files (core);
			r_list_foreach (bfiles, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("signature", R_CORE_BIN_ACC_SIGNATURE, NULL, 0);
			}
			r_list_free (bfiles);
			core->bin->cur = cur;
		}
		break;
	case 'd':
		cmd_id (core, pj, input, is_array, mode);
		break;
	case 'l': { // "il"
		RList *objs = r_core_bin_files (core);
		RListIter *iter;
		RBinFile *cur = core->bin->cur;
		RBinFile *bf;
		switch (r_list_length (objs)) {
		case 0:
			if (!cur && pj) {
				r_cons_print (core->cons, "[]");
			}
			break;
		case 1:
			if (core->bin->cur) {
				RBinFile *bf = core->bin->cur;
				RBinObject *obj = bf->bo;
				int nlibs = (obj && obj->libs)? r_list_length (obj->libs): 0;
				RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, nlibs);
			}
			break;
		default:;
			if (pj) {
				pj_a (pj);
			}
			r_list_foreach (objs, iter, bf) {
				if (pj) {
					pj_o (pj);
					pj_kn (pj, "id", bf->id);
					pj_ks (pj, "filename", bf->file);
					pj_k (pj, "data");
				}
				RBinObject *obj = bf->bo;
				core->bin->cur = bf;
				int nlibs = (obj && obj->libs)? r_list_length (obj->libs): 0;
				RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, nlibs);
				if (mode & R_MODE_JSON) {
					pj_end (pj);
				}
			}
			core->bin->cur = cur;
			if (mode & R_MODE_JSON) {
				pj_end (pj);
			}
			break;
		}
		r_list_free (objs);
	}
		break;
	case 'r': // "ir"
		{
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			if (!cur && pj) {
				r_cons_print (core->cons, "[]");
			}
			r_list_foreach (objs, iter, bf) {
				core->bin->cur = bf;
				RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS, NULL, 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
		}
		break;
	case 'S': // "iS"
		cmd_iS (core, input, &pj, mode, va, is_array);
		break;
	case '.': // "i."
		cmd_info_here (core, pj, mode); // input[1]);
		break;
	case 'z': // "iz"
		cmd_iz (core, pj, mode, is_array, va, input);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_i);
		break;
	case 0:
		// do nothing
		break;
	default:
		r_core_return_invalid_command (core, "i", *input);
		break;
	}
	R_FREE (core->table_query);
	if (pj || mode & R_MODE_JSON) {
#if 0
		if (is_array && !is_izzzj && !is_idpij) {
			pj_end (pj);
		}
#endif
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
	return 0;
}

#endif
