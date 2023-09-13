/* radare - LGPL - Copyright 2009-2023 - pancake */

#if R_INCLUDE_BEGIN

#include "../bin/format/pdb/pdb_downloader.h"

static RCoreHelpMessage help_msg_i = {
	"Usage: i", "", "Get info from opened file (see rabin2's manpage)",
	"Output mode:", "", "",
	"'*'", "", "output in radare commands",
	"'j'", "", "output in json",
	"'q'", "", "simple quiet output",
	"Actions:", "", "",
	"i|ij", "", "show info of current file (in JSON)",
	"iA", "", "list archs",
	"ia", "", "show all info (imports, exports, sections..)",
	"ib", "", "reload the current buffer for setting of the bin (use once only)",
	"ic", "", "List classes, methods and fields (icj for json)",
	"ic.", "", "show class and method name in current seek",
	"ic-", "[klass.method]", "delete given klass or klass.name",
	"ic+", "[klass.method]", "add new symbol in current seek for a given klass and method name",
	"icc", "", "List classes, methods and fields in Header Format",
	"icg", " [str]", "List classes as agn/age commands to create class hierarchy graphs (matches str if provided)",
	"icq", "", "List classes, in quiet mode (just the classname)",
	"icqq", "", "List classes, in quieter mode (only show non-system classnames)",
	"icl", "", "Show addresses of class and it methods, without names",
	"ics", "", "Show class symbols in an easy to parse format",
	"iC", "[j]", "show signature info (entitlements, ...)",
	"id", "[?]", "show DWARF source lines information",
	"iD", " lang sym", "demangle symbolname for given language",
	"ie", "", "entrypoint",
	"iee", "", "show Entry and Exit (preinit, init and fini)",
	"iE", "", "exports (global symbols)",
	"iE.", "", "current export",
	"ih", "", "headers (alias for iH)",
	"iHH", "", "verbose Headers in raw text",
	"ii", "", "imports",
	"iI", "", "binary info",
	"ik", " [query]", "key-value database from RBinObject",
	"il", "", "libraries",
	"iL ", "[plugin]", "list all RBin plugins loaded or plugin details",
	"im", "", "show info about predefined memory allocation",
	"iM", "", "show main address",
	"io", " [file]", "load info from file (or last opened) use bin.baddr",
	"iO", "[?]", "perform binary operation (dump, resize, change sections, ...)",
	"ir", "", "list the Relocations",
	"iR", "", "list the Resources",
	"is", "", "list the Symbols",
	"is,", "[table-query]", "list symbols in table using given expression",
	"is.", "", "current symbol",
	"iS ", "[entropy,sha1]", "sections (choose which hash algorithm to use)",
	"iS.", "", "current section",
	"iS,", "[table-query]", "list sections in table using given expression",
	"iS=", "", "show ascii-art color bars with the section ranges",
	"iSS", "", "list memory segments (maps with om)",
	"it", "", "file hashes",
	"iT", "", "file signature",
	"iV", "", "display file version info",
	"iw", "", "show try/catch blocks",
	"iX", "", "display source files used (via dwarf)",
	"iz", "[?][j]", "strings in data sections (in JSON/Base64)",
	"iz*", "", "print flags and comments r2 commands for all the strings",
	"izz", "", "search for Strings in the whole binary",
	"izz*", "", "same as iz* but exposing the strings of the whole binary",
	"izzz", "", "dump Strings from whole binary to r2 shell (for huge files)",
	"iz-", " [addr]", "purge string via bin.str.purge",
	"iZ", "", "guess size of binary program",
	NULL
};

// TODO: this command needs a refactoring
static RCoreHelpMessage help_msg_id = {
	"Usage: idp", "", "Debug information",
	"id", "", "show DWARF source lines information",
	"idp", " [file.pdb]", "load pdb file information",
	"idpi", " [file.pdb]", "show pdb file information",
	"idpi*", "", "show symbols from pdb as flags (prefix with dot to import)",
	"idpd", "", "download pdb file on remote server",
	NULL
};

#define PAIR_WIDTH 9
// TODO: reuse implementation in core/bin.c
static void pair(const char *a, const char *b) {
	char ws[16];
	int al = strlen (a);
	if (!b) {
		return;
	}
	memset (ws, ' ', sizeof (ws));
	al = PAIR_WIDTH - al;
	if (al < 0) {
		al = 0;
	}
	ws[al] = 0;
	r_cons_printf ("%s%s%s\n", a, ws, b);
}

static bool demangle_internal(RCore *core, const char *lang, const char *s) {
	char *res = NULL;
	int type = r_bin_demangle_type (lang);
	switch (type) {
	case R_BIN_LANG_CXX: res = r_bin_demangle_cxx (core->bin->cur, s, 0); break;
	case R_BIN_LANG_JAVA: res = r_bin_demangle_java (s); break;
	case R_BIN_LANG_OBJC: res = r_bin_demangle_objc (NULL, s); break;
	case R_BIN_LANG_SWIFT: res = r_bin_demangle_swift (s, core->bin->demangle_usecmd, core->bin->demangle_trylib); break;
	case R_BIN_LANG_DLANG: res = r_bin_demangle_plugin (core->bin, "dlang", s); break;
	case R_BIN_LANG_MSVC: res = r_bin_demangle_msvc (s); break;
	case R_BIN_LANG_RUST: res = r_bin_demangle_rust (core->bin->cur, s, 0); break;
	case R_BIN_LANG_PASCAL: res = r_bin_demangle_freepascal (s); break;
	default:
		r_bin_demangle_list (core->bin);
		return true;
	}
	if (res) {
		if (*res) {
			r_cons_printf ("%s\n", res);
		}
		free (res);
		return false;
	}
	return true;
}

static bool demangle(RCore *core, const char *s) {
	r_return_val_if_fail (core && s, false);
	const char *ss = strchr (s, ' ');
	if (!*s) {
		return false;
	}
	if (!ss) {
		const char *lang = r_config_get (core->config, "bin.lang");
		demangle_internal (core, lang, s);
		return true;
	}
	char *p = strdup (s);
	char *q = p + (ss - s);
	*q = 0;
	demangle_internal (core, p, q + 1);
	free (p);
	return true;
}

static void cmd_info_here(RCore *core, PJ *pj, int mode) {
	RCoreItem *item = r_core_item_at (core, core->offset);
	// fixme: other modes
	if (item && mode == R_MODE_JSON) {
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
			RVecAnalRef *refs = r_anal_refs_get (core->anal, core->offset);
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
			RVecAnalRef *refs = r_anal_xrefs_get (core->anal, core->offset);
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
	}
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
			pair ("fd", r_strf ("%d", desc->fd));
		}
		if (fn || (desc && desc->uri)) {
			char *escaped = r_str_escape_utf8_keep_printable (fn? fn: desc->uri, false, false);
			if (escaped) {
				pair ("file", escaped);
				free (escaped);
			}
		}
		if (desc) {
			ut64 fsz = r_io_desc_size (desc);
			if (fsz != UT64_MAX) {
				char humansz[8];
				pair ("size", r_strf ("0x%"PFMT64x, fsz));
				r_num_units (humansz, sizeof (humansz), fsz);
				pair ("humansz", humansz);
			}
		}
		if (desc) {
			pair ("mode", r_str_rwx_i (desc->perm & R_PERM_RWX));
		}
		if (plugin) {
			pair ("format", plugin->meta.name);
		}
		if (desc) {
			pair ("iorw", r_str_bool (io_cache || desc->perm & R_PERM_W));
		}
		pair ("block", r_strf ("0x%x", core->blocksize));

		if (binfile && binfile->curxtr) {
			pair ("packet", binfile->curxtr->meta.name);
		}
		if (desc && desc->referer && *desc->referer) {
			pair ("referer", desc->referer);
		}
		if (info) {
			pair ("type", info->type);
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
		R_LOG_ERROR ("No file selected");
	}
}

static void playMsg(RCore *core, const char *n, int len) {
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
	r_return_val_if_fail (lfile_hashes, false);
	r_return_val_if_fail (rfile_hashes, false);
	r_return_val_if_fail (equal, false);

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

static int __r_core_bin_reload(RCore *r, const char *file, ut64 baseaddr) {
	int result = 0;
	RIODesc *cd = r->io->desc;
	if (baseaddr == UT64_MAX) {
		baseaddr = 0;
	}
	if (cd) {
		RBinFile *bf = r_bin_file_find_by_fd (r->bin, cd->fd);
		if (bf) {
			result = r_bin_reload (r->bin, bf->id, baseaddr);
		}
	}
	r_core_bin_set_env (r, r_bin_cur (r->bin));
	return result;
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

static bool isKnownPackage(const char *cn) {
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
		if (r_str_startswith (cn, "Lokio")) {
			return true;
		}
	}
	return false;
}

static void cmd_ic_comma(RCore *core, const char *input) {
	r_return_if_fail (core && input[0] == 'c' && input[1] == ',');
	const char *q = input + 2;
	RList *objs = r_core_bin_files (core);
	RListIter *objs_iter;
	RBinFile *bf;
	RBinFile *cur = core->bin->cur;
	RTable *t = r_core_table (core, "flags");
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	r_table_add_column (t, typeNumber, "addr", 0);
	r_table_add_column (t, typeString, "type", 0);
	r_table_add_column (t, typeString, "klass", 0);
	r_table_add_column (t, typeString, "name", 0);
	const bool iova = r_config_get_b (core->config, "io.va");
	r_list_foreach (objs, objs_iter, bf) {
		RBinObject *obj = bf->bo;
		RBinClass *klass;
		RListIter *iter, *iter2;
		core->bin->cur = bf;
		r_list_foreach (obj->classes, iter, klass) {
			if (!klass->name) {
				continue;
			}
			RBinSymbol *method;
			r_list_foreach (klass->methods, iter2, method) {
				char *addr = r_str_newf ("0x%08"PFMT64x, iova? method->vaddr: method->paddr);
				r_table_add_row (t, addr, "method", klass->name, method->name, NULL);
				free (addr);
			}
			RBinField *field;
			r_list_foreach (klass->fields, iter2, field) {
				char *addr = r_str_newf ("0x%08"PFMT64x, iova? field->vaddr: field->paddr);
				r_table_add_row (t, addr, "field", klass->name, field->name, NULL);
				free (addr);
			}
		}
	}
	core->bin->cur = cur;
	r_list_free (objs);
	if (r_table_query (t, q)) {
		char *s = r_table_tostring (t);
		r_cons_printf ("%s\n", s);
		free (s);
	}
	r_table_free (t);
}

void cmd_ic_sub(RCore *core, const char *input) {
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
		eprintf ("Usage: ic-[klassname][.methodname]\n");
		return;
	}
	char *klass_name = strdup (input);
	char *method_name = r_str_after (klass_name, '.');
	RBinClass *klass = NULL;
	RList *klasses = r_bin_get_classes (core->bin);
	r_list_foreach (klasses, iter, k) {
		if (!strcmp (k->name, klass_name)) {
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
			if (!strcmp (method_name, m->name)) {
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
		eprintf ("Usage: ic+[klassname][.methodname]\n");
		return;
	}
	RList *klasses = r_bin_get_classes (core->bin);
	RListIter *iter;
	RBinClass *k;
	char *klass_name = strdup (input);
	char *method_name = r_str_after (klass_name, '.');
	RBinClass *klass = NULL;
	r_list_foreach (klasses, iter, k) {
		if (!strcmp (k->name, klass_name)) {
			klass = k;
			break;
		}
	}
	if (!klass) {
		klass = R_NEW0 (RBinClass);
		klass->name = strdup (klass_name);
		r_list_append (klasses, klass);
	}
	if (method_name == NULL) {
		klass->addr = core->offset;
	} else {
		ut64 pa = core->offset; // XXX
		ut64 va = core->offset;
		RBinSymbol *m;
		bool found = false;
		r_list_foreach (klass->methods, iter, m) {
			if (!strcmp (m->name, method_name)) {
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

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *) data;
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	int i;
	const bool va = core->io->va || r_config_get_b (core->config, "cfg.debug");
	int mode = 0;
	bool rdump = false;
	int is_array = 0;
	bool is_izzzj = false;
	bool is_idpij = false;
	Sdb *db;
	PJ *pj = NULL;

	if (r_str_startswith (input, "ddqd")) {
		r_cons_printf ("GOD MODE ON\n");
		return 0;
	}
	for (i = 0; input[i] && input[i] != ' '; i++)
		;
	if (i > 0) {
		switch (input[i - 1]) {
		case '*': mode = R_MODE_RADARE; break;
		case 'j': mode = R_MODE_JSON; break;
		case 'q': mode = R_MODE_SIMPLE; break;
		}
	}
	#define INIT_PJ()\
		if (!pj) {\
			pj = r_core_pj_new (core);\
			if (!pj) {\
				return 1;\
			}\
		}
	if (mode == R_MODE_JSON) {
		INIT_PJ ();
		int suffix_shift = 0;
		if (r_str_startswith (input, "SS") || r_str_startswith (input, "ee") || r_str_startswith (input, "zz")) {
			suffix_shift = 1;
		}
		if (strlen (input + 1 + suffix_shift) > 1) {
			is_array = 1;
		}
		if (r_str_startswith (input, "zzz")) {
			is_izzzj = true;
		}
		if (r_str_startswith (input, "dpi")) {
			is_idpij = true;
		}
	}
	if (is_array && !is_izzzj && !is_idpij) {
		pj_o (pj);
	}
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
	if (question < space && question > input) {
		question--;
		char *prefix = strdup (input);
		char *tmp = strchr (prefix, '?');
		if (tmp) {
			*tmp = 0;
		}
		if (*prefix == 'd') {
			r_core_cmd_help (core, help_msg_id);
		} else {
			r_core_cmdf (core, "i?~& i%s", prefix);
		}
		free (prefix);
		goto done;
	}
	R_FREE (core->table_query);
	if (space && (*space == ' ' || *space == ',')) {
		core->table_query = r_str_trim_dup (space + 1);
	}
	while (*input) {
		const char ch = *input;
		if (ch == ' ') {
			break;
		}
		switch (*input) {
		case 'b': // "ib"
		{
			ut64 baddr = (input[1] == ' ')? r_num_math (core->num, input + 1) : r_config_get_i (core->config, "bin.baddr");
			// XXX: this will reload the bin using the buffer.
			// An assumption is made that assumes there is an underlying
			// plugin that will be used to load the bin (e.g. malloc://)
			// TODO: Might be nice to reload a bin at a specified offset?
			__r_core_bin_reload (core, NULL, baddr);
			r_core_block_read (core);
		}
		break;
		case 'k': // "ik"
		{
			RBinObject *o = r_bin_cur_object (core->bin);
			db = o? o->kv: NULL;
			switch (input[1]) {
			case 'v':
				if (db) {
					char *o = sdb_querys (db, NULL, 0, input + 3);
					if (o && *o) {
						r_cons_print (o);
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
					if (o && *o) {
						r_cons_print (o);
					}
					free (o);
				}
				break;
			case '\0':
				if (db) {
					char *o = sdb_querys (db, NULL, 0, "*");
					if (o && *o) {
						r_cons_print (o);
					}
					free (o);
				}
				break;
			case '?':
			default:
				r_core_cmd_help_match (core, help_msg_i, "ik", false);
			}
			goto done;
		}
		break;
		case 'o': // "io"
		{
			if (!desc) {
				R_LOG_ERROR ("Core file not open");
				return 0;
			}
			const char *fn = input[1] == ' '? input + 2: desc->name;
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			r_core_bin_load (core, fn, baddr);
		}
		break;
#define RBININFO(n,x,y,z)\
	if (is_array) {\
		pj_k (pj, n);\
	}\
	if (z) { playMsg (core, n, z);}\
	r_core_bin_info (core, x, pj, mode, va, NULL, y);
		case 'A': // "iA"
			if (input[1] == 'j') {
				pj_o (pj);
				r_bin_list_archs (core->bin, pj, 'j');
				pj_end (pj);
			} else {
				r_bin_list_archs (core->bin, NULL, 1);
			}
			break;
		case 'E': // "iE"
		{
			if (input[1] == 'j' && input[2] == '.') {
				mode = R_MODE_JSON;
				INIT_PJ ();
				RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, input + 2, 0);
			} else {
				RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, input + 1, 0);
			}
			input = input + strlen (input) - 1;
			break;
		}
		case 't': // "it"
			{
				ut64 limit = r_config_get_i (core->config, "bin.hashlimit");
				RBinInfo *info = r_bin_get_info (core->bin);
				if (!info) {
					R_LOG_ERROR ("Cannot get bin info");
					return 0;
				}

				RList *new_hashes = r_bin_file_compute_hashes (core->bin, limit);
				RList *old_hashes = r_bin_file_set_hashes (core->bin, new_hashes);
				bool equal = true;
				if (!r_list_empty (new_hashes) && !r_list_empty (old_hashes)) {
					if (!is_equal_file_hashes (new_hashes, old_hashes, &equal)) {
						R_LOG_ERROR ("is_equal_file_hashes: Cannot compare file hashes");
						r_list_free (old_hashes);
						return 0;
					}
				}
				RBinFileHash *fh_old, *fh_new;
				RListIter *hiter_old, *hiter_new;
				const bool is_json = input[1] == 'j'; // "itj"
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
								r_cons_printf ("= %s %s\n", fh_new->type, fh_new->hex); // output one line because hash remains same `= hashtype hashval`
							} else {
								// output diff-like two lines, one with old hash val `- hashtype hashval` and one with new `+ hashtype hashval`
								r_cons_printf ("- %s %s\n+ %s %s\n",
									fh_old->type, fh_old->hex,
									fh_new->type, fh_new->hex);
							}
						}
					} else { // hashes are equal
						r_list_foreach (new_hashes, hiter_new, fh_new) {
							r_cons_printf ("%s %s\n", fh_new->type, fh_new->hex);
						}
					}
				}
				r_list_free (old_hashes);
			}
			break;
		case 'Z': // "iZ"
			RBININFO ("size", R_CORE_BIN_ACC_SIZE, NULL, 0);
			break;
		case 'O': // "iO"
			switch (input[1]) {
			case ' ':
				r_sys_cmdf ("rabin2 -O \"%s\" \"%s\"", r_str_trim_head_ro (input + 1), desc->name);
				break;
			default:
				r_sys_cmdf ("rabin2 -O help");
				break;
			}
			return 0;
		case 'S': // "iS"
			//we comes from ia or iS
			if ((input[1] == 'm' && input[2] == 'z') || !input[1]) {
				RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, NULL, 0);
			} else if (input[1] == ',') {
				R_FREE (core->table_query);
				core->table_query = strdup (input + 2);
				RBinObject *obj = r_bin_cur_object (core->bin);
				RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, input + 1, (obj && obj->sections)? r_list_length (obj->sections): 0);
			} else if (input[1] == 'S' && !input[2]) {  // "iSS"
				RBININFO ("segments", R_CORE_BIN_ACC_SEGMENTS, NULL, 0);
			} else {  //iS/iSS entropy,sha1
				const char *name = "sections";
				int action = R_CORE_BIN_ACC_SECTIONS;
				int param_shift = 0;
				if (input[1] == 'S') {
					name = "segments";
					input++;
					action = R_CORE_BIN_ACC_SEGMENTS;
				}
				// case for iS=
				if (input[1] == '=') {
					mode = R_MODE_EQUAL;
				} else if (input[1] == '*') {
					mode = R_MODE_RADARE;
				} else if (input[1] == 'q' && input[2] == '.') {
					mode = R_MODE_SIMPLE;
				} else if (input[1] == 'j' && input[2] == '.') {
					mode = R_MODE_JSON;
					INIT_PJ ();
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
						RBININFO (name, action, input + 1 + param_shift,
								(obj && obj->sections)? r_list_length (obj->sections): 0);
					}
					core->bin->cur = cur;
					r_list_free (objs);
				}


			}
			input = input + strlen (input) - 1;
			break;
		case 'H': // "iH"
			if (input[1] == 'H') { // "iHH"
				playMsg (core, "header", -1);
				if (!r_core_bin_info (core, R_CORE_BIN_ACC_HEADER, pj, mode, va, NULL, NULL)) {
					R_LOG_ERROR ("No header fields found");
				}
				break;
			} else {
				playMsg (core, "fields", -1);
				if (!r_core_bin_info (core, R_CORE_BIN_ACC_FIELDS, pj, mode, va, NULL, NULL)) {
					R_LOG_ERROR ("No header fields found");
				}
			}
			break;
		case 'h': // "ih"
			RBININFO ("fields", R_CORE_BIN_ACC_FIELDS, NULL, 0);
			break;
		case 'l': { // "il"
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			r_list_foreach (objs, iter, bf) {
				RBinObject *obj = bf->bo;
				core->bin->cur = bf;
				RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, (obj && obj->libs)? r_list_length (obj->libs): 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
			break;
		}
		case 'L': { // "iL"
			char *ptr = strchr (input, ' ');
			int json = input[1] == 'j'? 'j': 0;

			if (ptr && ptr[1]) {
				const char *plugin_name = ptr + 1;
				if (is_array) {
					pj_k (pj, "plugin");
				}
				r_bin_list_plugin (core->bin, plugin_name, pj, json);
			} else {
				r_bin_list (core->bin, pj, json);
			}
			goto done;
		}
		case 's': { // "is"
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			if (input[1] == 'j' && input[2] == '.') {
				mode = R_MODE_JSON;
				INIT_PJ ();
			} else if (input[1] == 'q' && input[2] == 'q') {
				mode = R_MODE_SIMPLEST;
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
				if (input[1] == 'j' && input[2] == '.') {
					RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
				} else if (input[1] == ',') {
					R_FREE (core->table_query);
					core->table_query = strdup (input + 2);
					RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
				} else if (input[1] == 'q' && input[2] == 'q') {
					mode = R_MODE_SIMPLEST;
					RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 3, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
				} else if (input[1] == 'q' && input[2] == '.') {
					mode = R_MODE_SIMPLE;
					RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, 0);
				} else {
					RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
				}
#endif
			}
			input = input + strlen (input) - 1;
			r_list_free (objs);
			break;
		}
		case 'R': // "iR"
			RBININFO ("resources", R_CORE_BIN_ACC_RESOURCES, NULL, 0);
			break;
		case 'r': // "ir"
			{
				RList *objs = r_core_bin_files (core);
				RListIter *iter;
				RBinFile *bf;
				RBinFile *cur = core->bin->cur;
				r_list_foreach (objs, iter, bf) {
					core->bin->cur = bf;
					RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS, NULL, 0);
				}
				core->bin->cur = cur;
				r_list_free (objs);
			}
			break;
		case 'X': // "iX"
			RBININFO ("source", R_CORE_BIN_ACC_SOURCE, NULL, 0);
			break;
		case 'd': // "id"
			if (input[1] == 'p') { // "idp"
				SPDBOptions pdbopts;
				RBinInfo *info;
				bool file_found;
				char *filename;

				switch (input[2]) {
				case ' ': // "idp file.pdb"
					r_core_cmdf (core, ".idpi* %s", input + 3);
					while (input[2]) {
						input++;
					}
					break;
				case '\0': // "idp"
					r_core_cmd0 (core, ".idpi*");
					break;
				case 'd': // "idpd"
					pdbopts.user_agent = (char*) r_config_get (core->config, "pdb.useragent");
					pdbopts.extract = r_config_get_i (core->config, "pdb.extract");
					pdbopts.symbol_store_path = (char*) r_config_get (core->config, "pdb.symstore");
					char *str = strdup (r_config_get (core->config, "pdb.server"));
					RList *server_l = r_str_split_list (str, ";", 0);
					RListIter *it;
					char *server;
					int r = 1;
					r_list_foreach (server_l, it, server) {
						pdbopts.symbol_server = server;
						r = r_bin_pdb_download (core, pj, input[3] == 'j', &pdbopts);
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
					info = r_bin_get_info (core->bin);
					filename = strchr (input, ' ');
					while (input[2]) input++;
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
						file_found = r_file_exists (r_file_basename (info->debug_file_name));
						if (file_found) {
							filename = strdup (r_file_basename (info->debug_file_name));
						} else {
							// Check debug filename basename in current directory
							char* basename = (char*) r_file_basename (info->debug_file_name);
							file_found = r_file_exists (basename);
							if (!file_found) {
								// Check if debug file is in file directory
								char* dir = r_file_dirname (core->bin->cur->file);
								filename = r_str_newf ("%s/%s", dir, basename);
								file_found = r_file_exists (filename);
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
								filename = pdb_path;
							} else {
								R_FREE (pdb_path);
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
						free (filename);
						break;
					}
					r_core_pdb_info (core, filename, pj, mode);
					free (filename);
					break;
				case '?':
				default:
					r_core_cmd_help (core, help_msg_id);
					input++;
					break;
				}
				input++;
			} else if (input[1] == '?') { // "id?"
				r_core_cmd_help (core, help_msg_id);
				input++;
			} else { // "id"
				RBININFO ("dwarf", R_CORE_BIN_ACC_DWARF, NULL, -1);
			}
			break;
		case 'i': { // "ii"
			RList *objs = r_core_bin_files (core);
			RListIter *iter;
			RBinFile *bf;
			RBinFile *cur = core->bin->cur;
			r_list_foreach (objs, iter, bf) {
				RBinObject *obj = bf->bo;
				core->bin->cur = bf;
				RBININFO ("imports", R_CORE_BIN_ACC_IMPORTS, NULL,
					(obj && obj->imports)? r_list_length (obj->imports): 0);
			}
			core->bin->cur = cur;
			r_list_free (objs);
			break;
		}
		case 'I': // "iI"
			  {
				  RList *objs = r_core_bin_files (core);
				  RListIter *iter;
				  RBinFile *bf;
				  RBinFile *cur = core->bin->cur;
				  r_list_foreach (objs, iter, bf) {
					  core->bin->cur = bf;
					  RBININFO ("info", R_CORE_BIN_ACC_INFO, NULL, 0);
				  }
				  core->bin->cur = cur;
				  r_list_free (objs);
			  }
			break;
		case 'e': // "ie"
			{
				  RList *objs = r_core_bin_files (core);
				  RListIter *iter;
				  RBinFile *bf;
				  RBinFile *cur = core->bin->cur;
				  r_list_foreach (objs, iter, bf) {
					  core->bin->cur = bf;
					  if (input[1] == 'e') {
						  RBININFO ("initfini", R_CORE_BIN_ACC_INITFINI, NULL, 0);
						  input++;
					  } else {
						  RBININFO ("entries", R_CORE_BIN_ACC_ENTRIES, NULL, 0);
					  }
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
		case 'V': // "iV"
			  {
				  RList *objs = r_core_bin_files (core);
				  RListIter *iter;
				  RBinFile *bf;
				  RBinFile *cur = core->bin->cur;
				  r_list_foreach (objs, iter, bf) {
					  core->bin->cur = bf;
					  RBININFO ("versioninfo", R_CORE_BIN_ACC_VERSIONINFO, NULL, 0);
				  }
				  core->bin->cur = cur;
				  r_list_free (objs);
			  }
			break;
		case 'T': // "iT"
		case 'C': // "iC" // rabin2 -C create // should be deprecated and just use iT (or find a better name)
			  {
				  RList *objs = r_core_bin_files (core);
				  RListIter *iter;
				  RBinFile *bf;
				  RBinFile *cur = core->bin->cur;
				  r_list_foreach (objs, iter, bf) {
					  core->bin->cur = bf;
					  RBININFO ("signature", R_CORE_BIN_ACC_SIGNATURE, NULL, 0);
				  }
				  core->bin->cur = cur;
				  r_list_free (objs);
			  }
			break;
		case 'z': // "iz"
			if (input[1] == '-') { // "iz-"
				char *strpurge = core->bin->strpurge;
				ut64 addr = core->offset;
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
					INIT_PJ ();
					break;
				case 'q': // "izzq"
					if (input[3] == 'q') { //izzqq
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
					goto done;
				}
				RBININFO ("strings", R_CORE_BIN_ACC_RAW_STRINGS, NULL, 0);
			} else {
				// "iz"
				bool validcmd = true;
				switch (input[1]) {
				case 'J':
					validcmd = false;
					break;
				case '*':
				case 'j':
				case 0:
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
					RList *objs = r_core_bin_files (core);
					RListIter *iter;
					RBinFile *bf;
					RBinFile *cur = core->bin->cur;
					r_list_foreach (objs, iter, bf) {
						core->bin->cur = bf;
						RBinObject *obj = r_bin_cur_object (core->bin);
						RBININFO ("strings", R_CORE_BIN_ACC_STRINGS, NULL,
								(obj && obj->strings)? r_list_length (obj->strings): 0);
					}
					core->bin->cur = cur;
					r_list_free (objs);
				} else {
					//
				}
			}
			break;
		case 'c': // "ic"
			// XXX this is dupe of cbin.c:bin_classes()
			if (input[1] == '?') {
				r_core_cmd_help_match (core, help_msg_i, "ic", false);
			} else if (input[1] == ',') { // "ic,"
				cmd_ic_comma (core, input);
			} else if (input[1] == '-') { // "ic-"
				cmd_ic_sub (core, input + 2);
			} else if (input[1] == '+') { // "ic+"
				cmd_ic_add (core, input + 2);
			} else if (input[1] == 'g') { // "icg"
				RBinClass *cls;
				RListIter *iter, *iter2;
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (!obj) {
					break;
				}
				bool fullGraph = true;
				const char *match = r_str_trim_head_ro (input + 2);
				if (R_STR_ISNOTEMPTY (match)) {
					r_list_foreach (obj->classes, iter, cls) {
						char *sk;
						if (!match || !strstr (cls->name, match)) {
							continue;
						}
						r_cons_printf ("agn %s\n", cls->name);
						if (cls->super) {
							r_list_foreach (cls->super, iter2, sk) {
								if (match && strstr (sk, match)) {
									r_cons_printf ("agn %s\n", sk);
									r_cons_printf ("age %s %s\n", sk, cls->name);
								}
							}
						}
					}
				} else if (fullGraph) {
					r_list_foreach (obj->classes, iter, cls) {
						const char *sk;
						r_cons_printf ("agn %s\n", cls->name);
						r_list_foreach (cls->super, iter2, sk) {
							r_cons_printf ("agn %s\n", sk);
							r_cons_printf ("age %s %s\n", sk, cls->name);
						}
					}
				} else {
					r_list_foreach (obj->classes, iter, cls) {
						char *sk;
						RListIter *iter;
						r_list_foreach (cls->super, iter, sk) {
							if (strstr (sk, "NSObject")) {
								continue;
							}
							r_cons_printf ("agn %s\n", sk);
							r_cons_printf ("agn %s\n", cls->name);
							r_cons_printf ("age %s %s\n", sk, cls->name);
						}
					}
				}
				goto done;
			} else if (input[1] == ' ' || input[1] == '.' || input[1] == 's' || input[1] == 'q' || input[1] == 'j' || input[1] == 'l' || input[1] == 'c' || input[1] == '*') {
				const bool iova = r_config_get_b (core->config, "io.va");
				RList *objs = r_core_bin_files (core);
				RListIter *objs_iter;
				RBinFile *bf;
				RBinFile *cur = core->bin->cur;
				r_list_foreach (objs, objs_iter, bf) {
					RBinObject *obj = bf->bo;
					RBinClass *cls;
					RBinSymbol *sym;
					RListIter *iter, *iter2;
					core->bin->cur = bf;
					//RBinObject *obj = r_bin_cur_object (core->bin);
					if (!obj) {
						break;
					}
					if (input[2] && input[2] != '*' && input[2] != 'j' && !strstr (input, "qq")) {
						bool radare2 = strstr (input, "**");
						int idx = -1;
						const char * cls_name = NULL;
						if (radare2) {
							input ++;
						}
						if (r_num_is_valid_input (core->num, input + 2)) {
							idx = r_num_math (core->num, input + 2);
						} else {
							const char * first_char = input + ((input[1] == ' ') ? 1 : 2);
							int not_space = strspn (first_char, " ");
							if (first_char[not_space]) {
								cls_name = first_char + not_space;
							}
						}
						if (radare2) {
							input++;
						}
						int count = 0;
						int mode = input[1];
						r_list_foreach (obj->classes, iter, cls) {
							if (radare2) {
								r_cons_printf ("ac %s\n", cls->name);
								r_list_foreach (cls->methods, iter2, sym) {
									r_cons_printf ("ac %s %s 0x%08"PFMT64x"\n", cls->name,
											sym->name, iova? sym->vaddr: sym->paddr);
								}
								continue;
							}
							if ((idx >= 0 && idx != count++) || (R_STR_ISNOTEMPTY (cls_name) && strcmp (cls_name, cls->name))) {
								continue;
							}
							switch (mode) {
							case '*':
								r_list_foreach (cls->methods, iter2, sym) {
									r_cons_printf ("f sym.%s @ 0x%"PFMT64x "\n",
										sym->name, iova? sym->vaddr: sym->paddr);
								}
								input++;
								break;
							case 'l':
								r_list_foreach (cls->methods, iter2, sym) {
									const char *comma = iter2->p? " ": "";
									r_cons_printf ("%s0x%"PFMT64d, comma,
										iova? sym->vaddr: sym->paddr);
								}
								r_cons_newline ();
								input++;
								break;
							case 'j':
								input++;
								pj_ks (pj, "class", cls->name);
								pj_ka (pj, "methods");
								r_list_foreach (cls->methods, iter2, sym) {
									pj_o (pj);
									pj_ks (pj, "name", sym->name);
									if (sym->method_flags) {
										char *flags = r_core_bin_method_flags_str (sym->method_flags, R_MODE_JSON);
										pj_k (pj, "flags");
										pj_j (pj, flags);
										free (flags);
									}
									pj_kN (pj, "vaddr", sym->vaddr);
									pj_kN (pj, "paddr", sym->paddr);
									pj_end (pj);
								}
								pj_end (pj);
								break;
							default:
								r_cons_printf ("class %s\n", cls->name);
								r_list_foreach (cls->methods, iter2, sym) {
									char *flags = r_core_bin_method_flags_str (sym->method_flags, 0);
									r_cons_printf ("0x%08"PFMT64x " method %s %s %s\n",
											iova? sym->vaddr: sym->paddr,
											cls->name, flags, sym->name);
									R_FREE (flags);
								}
								break;
							}
							goto done;
						}
						goto done;
					} else if (obj->classes) {
						const bool iova = r_config_get_b (core->config, "io.va");
						playMsg (core, "classes", r_list_length (obj->classes));
						if (strstr (input, "qq")) { // "icqq"
							r_list_foreach (obj->classes, iter, cls) {
								if (!isKnownPackage (cls->name)) {
									r_cons_printf ("%s\n", cls->name);
								}
							}
						} else if (input[1] == 's') { // "ics"
							r_list_foreach (obj->classes, iter, cls) {
								r_list_foreach (cls->methods, iter2, sym) {
									ut64 addr = iova? sym->vaddr: sym->paddr;
									if (addr == 0 || addr == UT64_MAX) {
										continue;
									}
									r_cons_printf ("0x%"PFMT64d" [%s] %s\n",
										addr, cls->name, sym->name);
								}
							}
						} else if (input[1] == 'l') { // "icl"
							r_list_foreach (obj->classes, iter, cls) {
								r_list_foreach (cls->methods, iter2, sym) {
									const char *comma = iter2->p? " ": "";
									r_cons_printf ("%s0x%"PFMT64d, comma,
										iova? sym->vaddr: sym->paddr);
								}
								if (!r_list_empty (cls->methods)) {
									r_cons_newline ();
								}
							}
						} else if (input[1] == '.') { // "ic."
							ut64 addr = core->offset;
							ut64 min = UT64_MAX;
							const char *method = NULL;
							ut64 max = 0LL;
							r_list_foreach (obj->classes, iter, cls) {
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
										method = sym->name;
									}
								}
								if (addr >= min && addr < max) {
									if (method) {
										r_cons_printf ("%s::%s\n", cls->name, method);
									} else {
										r_cons_printf ("%s\n", cls->name);
									}
								}
								min = UT64_MAX;
								max = 0LL;
							}
						} else if (input[1] == 'c') { // "icc"
							mode = R_MODE_CLASSDUMP;
							if (input[2] == '*') {
								mode |= R_MODE_RADARE;
							}
							RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (obj->classes));
							input = " ";
						} else { // "icq"
							if (input[2] == 'j') {
								mode |= R_MODE_JSON; // default mode is R_MODE_SIMPLE
							}
							RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (obj->classes));
						}
						goto done;
					}
				}
				core->bin->cur = cur;
				r_list_free (objs);
			} else { // "ic"
				// R2_600 - all commands have RCore.binFiles() loop . this is racy and dupe, maybe good to separate this logic into a function that takes another function as argument to generalize and simplify code
				RList *objs = r_core_bin_files (core);
				RListIter *iter;
				RBinFile *bf;
				RBinFile *cur = core->bin->cur;
				r_list_foreach (objs, iter, bf) {
					core->bin->cur = bf;
					RBinObject *obj = bf->bo;
					if (obj && obj->classes) {
						int len = r_list_length (obj->classes);
						RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, len);
					}
				}
				core->bin->cur = cur;
				r_list_free (objs);
			}
			break;
		case 'D': // "iD"
			if (input[1] != ' ' || !demangle (core, input + 2)) {
				r_core_cmd_help_match (core, help_msg_i, "iD", true);
			}
			return 0;
		case 'a': // "ia"
			switch (mode) {
			case R_MODE_RADARE: cmd_info (core, "IieEcsSmz*"); break;
			case R_MODE_JSON: cmd_info (core, "IieEcsSmzj"); break;
			case R_MODE_SIMPLE: cmd_info (core, "IieEcsSmzq"); break;
			default: cmd_info (core, "IiEecsSmz"); break;
			}
			break;
		case '?': // "i?"
			if (input[1] == 'j') {
				r_cons_cmd_help_json (help_msg_i);
			} else {
				r_core_cmd_help (core, help_msg_i);
			}
			goto redone;
		case '*': // "i*"
			mode = R_MODE_RADARE;
			goto done;
		case 'q': // "iq"
			mode = R_MODE_SIMPLE;
			cmd_info_bin (core, va, pj, mode);
			goto done;
		case 'j': // "ij"
			mode = R_MODE_JSON;
			if (is_array > 1) {
				mode |= R_MODE_ARRAY;
			}
			cmd_info_bin (core, va, pj, mode);
			goto done;
		case '.': // "i."
			cmd_info_here (core, pj, input[1]);
			goto done;
		case '-':
		case '+':
		case ',':
			// ignore comma
			goto done;
		default:
	//		cmd_info_bin (core, va, pj, mode);
			R_LOG_WARN ("Invalid `i` subcommand '%c'", *input);
			goto done;
		}
		// input can be overwritten like the 'input = " ";' a few lines above
		if (*input != ' ') {
			input++;
			if ((*input == 'j' || *input == 'q') && (input[0] && !input[1])) {
				break;
			}
		} else {
			break;
		}
	}
done:
	if (mode & R_MODE_JSON) {
		if (is_array && !is_izzzj && !is_idpij) {
			pj_end (pj);
		}
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
redone:
	return 0;
}

#endif
