/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <string.h>
#include "r_bin.h"
#include "r_config.h"
#include "r_cons.h"
#include "r_core.h"

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
	case R_BIN_NM_CXX: res = r_bin_demangle_cxx (core->bin->cur, s, 0); break;
	case R_BIN_NM_JAVA: res = r_bin_demangle_java (s); break;
	case R_BIN_NM_OBJC: res = r_bin_demangle_objc (NULL, s); break;
	case R_BIN_NM_SWIFT: res = r_bin_demangle_swift (s, core->bin->demanglercmd); break;
	case R_BIN_NM_DLANG: res = r_bin_demangle_plugin (core->bin, "dlang", s); break;
	default:
		r_bin_demangle_list (core->bin);
		return true;
	}
	if (res) {
		if (*res) printf ("%s\n", res);
		free (res);
		return false;
	}
	return true;
}

static int demangle(RCore *core, const char *s) {
	char *p, *q;
	const char *ss = strchr (s, ' ');
	if (!*s) return 0;
	if (!ss) {
		const char *lang = r_config_get (core->config, "bin.lang");
		demangle_internal (core, lang, s);
		return 1;
	}
	p = strdup (s);
	q = p + (ss - s);
	*q = 0;
	demangle_internal (core, p, q + 1);
	free (p);
	return 1;
}

#define STR(x) (x)?(x):""
static void r_core_file_info (RCore *core, int mode) {
	const char *fn = NULL;
	int dbg = r_config_get_i (core->config, "cfg.debug");
	bool io_cache = r_config_get_i (core->config, "io.cache");
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinFile *binfile = r_core_bin_cur (core);
	RCoreFile *cf = core->file;
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (mode == R_CORE_BIN_JSON)
		r_cons_printf ("{");
	if (mode == R_CORE_BIN_RADARE)
		return;
	if (mode == R_CORE_BIN_SIMPLE)
		return;
	if (info) {
		fn = info->file;
		switch (mode) {
		case R_CORE_BIN_JSON:
			r_cons_printf ("\"type\":\"%s\"", STR(info->type));
			break;
		default:
			pair ("type", info->type);
			break;
		}
	} else {
		fn = (cf && cf->desc) ? cf->desc->name : NULL;
	}
	if (cf && mode == R_CORE_BIN_JSON) {
		const char *uri = fn;
		if (!uri) {
			if (cf->desc && cf->desc->uri && *cf->desc->uri) {
				uri = cf->desc->uri;
			} else {
				uri = "";
			}
		}
		r_cons_printf (",\"file\":\"%s\"", uri);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		if (cf->desc) {
			ut64 fsz = r_io_desc_size (cf->desc);
			r_cons_printf (",\"fd\":%d", cf->desc->fd);
			if (fsz != UT64_MAX) {
				r_cons_printf (",\"size\":%"PFMT64d, fsz);
			}
			r_cons_printf (",\"iorw\":%s", r_str_bool ( io_cache || \
				cf->desc->flags & R_IO_WRITE ));
			r_cons_printf (",\"mode\":\"%s\"", r_str_rwx_i (
				cf->desc->flags & 7 ));
			r_cons_printf (",\"obsz\":%"PFMT64d, (ut64)core->io->desc->obsz);
			if (cf->desc->referer && *cf->desc->referer)
				r_cons_printf (",\"referer\":\"%s\"", cf->desc->referer);
		}
		r_cons_printf (",\"block\":%d", core->blocksize);
		if (binfile) {
			if (binfile->curxtr)
				r_cons_printf (",\"packet\":\"%s\"",
					binfile->curxtr->name);
			if (plugin)
				r_cons_printf (",\"format\":\"%s\"",
					plugin->name);
		}
		r_cons_printf ("}");
	} else if (cf && mode != R_CORE_BIN_SIMPLE) {
		//r_cons_printf ("# Core file info\n");
		pair ("file", fn ? fn : cf->desc->uri);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		if (cf->desc) {
			ut64 fsz = r_io_desc_size (cf->desc);
			if (cf->desc->referer && *cf->desc->referer)
				pair ("referer", cf->desc->referer);
			pair ("fd", sdb_fmt (0, "%d", cf->desc->fd));
			if (fsz != UT64_MAX) {
				pair ("size", sdb_fmt (0,"0x%"PFMT64x, fsz));
			}
			pair ("iorw", r_str_bool ( io_cache || \
				cf->desc->flags & R_IO_WRITE ));
			pair ("blksz", sdb_fmt (0, "0x%"PFMT64x,
				(ut64)core->io->desc->obsz));
			pair ("mode", r_str_rwx_i (cf->desc->flags & 7));
		}
		pair ("block", sdb_fmt (0, "0x%x", core->blocksize));
		if (binfile && binfile->curxtr)
			pair ("packet", binfile->curxtr->name);
		if (plugin)
			pair ("format", plugin->name);
	}
}

static int bin_is_executable (RBinObject *obj){
	RListIter *it;
	RBinSection* sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		r_list_foreach (obj->sections, it, sec){
			if (R_BIN_SCN_EXECUTABLE & sec->srwx)
				return true;
		}
	}
	return false;
}

static void cmd_info_bin(RCore *core, int va, int mode) {
	RBinObject *obj = r_bin_cur_object (core->bin);
	int array = 0;
	if (core->file) {
		if ((mode & R_CORE_BIN_JSON) && !(mode & R_CORE_BIN_ARRAY)) {
			mode = R_CORE_BIN_JSON;
			r_cons_printf ("{\"core\":");
		}
		if ((mode & R_CORE_BIN_JSON) && (mode & R_CORE_BIN_ARRAY)) {
			mode = R_CORE_BIN_JSON;
			array = 1;
			r_cons_printf (",\"core\":");
		}
		r_core_file_info (core, mode);
		if (obj && bin_is_executable (obj)) {
			if ((mode & R_CORE_BIN_JSON)) {
				r_cons_printf (",\"bin\":");
			}
			r_core_bin_info (core, R_CORE_BIN_ACC_INFO,
				mode, va, NULL, NULL);
		}
		if (mode == R_CORE_BIN_JSON && array == 0) {
			r_cons_printf ("}\n");
		}
	} else {
		eprintf ("No file selected\n");
	}
}

static void playMsg(RCore *core, const char *n, int len) {
	if (r_config_get_i (core->config, "scr.tts")) {
		if (len > 0) {
			char *s = r_str_newf ("%d %s", len, n);
			r_sys_tts (s, true);
			free (s);
		} else if (len == 0) {
			char *s = r_str_newf ("there are no %s", n);
			r_sys_tts (s, true);
			free (s);
		}
	}
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	bool newline = r_config_get_i (core->config, "scr.interactive");
	RBinObject *o = r_bin_cur_object (core->bin);
	RCoreFile *cf = core->file;
	int i, va = core->io->va || core->io->debug;
	int mode = 0; //R_CORE_BIN_SIMPLE;
	int is_array = 0;
	Sdb *db;

	for (i = 0; input[i] && i<2; i++) {
		switch (input[i]) {
		case '*': mode = R_CORE_BIN_RADARE; break;
		case 'j': mode = R_CORE_BIN_JSON; break;
		case 'q': mode = R_CORE_BIN_SIMPLE; break;
		}
	}

	if (mode == R_CORE_BIN_JSON) {
		if (strlen (input+1)>1)
			is_array = 1;
	}
	if (is_array) {
		r_cons_printf ("{");
	}
	if (!*input) {
		cmd_info_bin (core, va, mode);
	}
	/* i* is an alias for iI* */
	if (!strcmp (input, "*")) {
		input = "I*";
	}
	RBinObject *obj = r_bin_cur_object (core->bin);
	while (*input) {
		switch (*input) {
		case 'b': // "ib"
			{
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			if (input[1] == ' ') {
				baddr = r_num_math (core->num, input+1);
			}
			// XXX: this will reload the bin using the buffer.
			// An assumption is made that assumes there is an underlying
			// plugin that will be used to load the bin (e.g. malloc://)
			// TODO: Might be nice to reload a bin at a specified offset?
			r_core_bin_reload (core, NULL, baddr);
			r_core_block_read (core);
			newline = false;
			}
			break;
		case 'k':
			db = o ? o->kv : NULL;
			//:eprintf ("db = %p\n", db);
			switch (input[1]) {
			case 'v':
				if (db) {
					char *o = sdb_querys (db, NULL, 0, input+3);
					if (o && *o) r_cons_print (o);
					free (o);
				}
				break;
			case '*':
				r_core_bin_export_info_rad (core);
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
					if (o && *o) r_cons_print (o);
					free (o);
				}
				break;
			case '?':
			default:
				eprintf ("Usage: ik [sdb-query]\n");
				eprintf ("Usage: ik*    # load all header information\n");
			}
			goto done;
			break;
		case 'o':
			{
				if (!cf) {
					eprintf ("Core file not open\n");
					return 0;
				}
				const char *fn = input[1]==' '? input+2: cf->desc->name;
				ut64 baddr = r_config_get_i (core->config, "bin.baddr");
				r_core_bin_load (core, fn, baddr);
			}
			break;
	#define RBININFO(n,x,y,z) \
	if (is_array) { \
		if (is_array == 1) is_array++; else r_cons_printf (","); \
		r_cons_printf ("\"%s\":",n); \
	}\
	if (z) playMsg(core, n, z);\
	r_core_bin_info (core, x, mode, va, NULL, y);
		case 'A':
			newline = false;
			if (input[1]=='j') {
				r_cons_printf ("{");
				r_bin_list_archs (core->bin, 'j');
				r_cons_printf ("}\n");
			} else {
				r_bin_list_archs (core->bin, 1);
			}
			break;
		case 'E': RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, NULL, 0); break;
		case 'Z': RBININFO ("size", R_CORE_BIN_ACC_SIZE, NULL, 0); break;
		case 'S':
			//we comes from ia or iS
			if ((input[1] == 'm' && input[2] == 'z') || !input[1]) {
				RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, NULL, 0);
			} else  { //iS entropy,sha1
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (mode == R_CORE_BIN_RADARE || mode == R_CORE_BIN_JSON || mode == R_CORE_BIN_SIMPLE) {
					RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, input + 2, 
					  	obj ? r_list_length (obj->sections) : 0);
				} else {
					RBININFO ("sections", R_CORE_BIN_ACC_SECTIONS, input + 1, 
					  	obj ? r_list_length (obj->sections) : 0);
				}
				//we move input until get '\0'
				while (*(++input));
				//input-- because we are inside a while that does input++
				// oob read if not input--
				input--;
			}
			break;
		case 'H':
			if (input[1] == 'H') { //iHH
				RBININFO ("header", R_CORE_BIN_ACC_HEADER, NULL, -1);
				break;
			}
		case 'h': RBININFO ("fields", R_CORE_BIN_ACC_FIELDS, NULL, 0); break;
		case 'l': RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, obj? r_list_length (obj->libs):0); break;
		case 'L':
			r_bin_list (core->bin, input[1] == 'j');
			break;
		case 's':
			if (input[1] == '.') {
				ut64 addr = core->offset + (core->print->cur_enabled? core->print->cur: 0);
				RFlagItem *f = r_flag_get_at (core->flags, addr, false);
				if (f) {
					if (f->offset == addr || !f->offset) {
						r_cons_printf ("%s", f->name);
					} else {
						r_cons_printf ("%s+%d", f->name, (int)(addr-f->offset));
					}
				}
				input++;
				break;
			} else {
				RBinObject *obj = r_bin_cur_object (core->bin);
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, NULL, obj? r_list_length (obj->symbols): 0);
				break;
			}
		case 'R':
		case 'r': RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS, NULL, 0); break;
		case 'd': RBININFO ("dwarf", R_CORE_BIN_ACC_DWARF, NULL, -1); break;
		case 'i': RBININFO ("imports",R_CORE_BIN_ACC_IMPORTS, NULL, obj? r_list_length (obj->imports): 0); break;
		case 'I': RBININFO ("info", R_CORE_BIN_ACC_INFO, NULL, 0); break;
		case 'e': RBININFO ("entries", R_CORE_BIN_ACC_ENTRIES, NULL, 0); break;
		case 'M': RBININFO ("main", R_CORE_BIN_ACC_MAIN, NULL, 0); break;
		case 'm': RBININFO ("memory", R_CORE_BIN_ACC_MEM, NULL, 0); break;
		case 'V': RBININFO ("versioninfo", R_CORE_BIN_ACC_VERSIONINFO, NULL, 0); break;
		case 'C': RBININFO ("signature", R_CORE_BIN_ACC_SIGNATURE, NULL, 0); break;
		case 'z':
			if (input[1] == 'z') { //izz
				switch (input[2]) {
				case '*':
					mode = R_CORE_BIN_RADARE;
					break;
				case 'j':
					mode = R_CORE_BIN_JSON;
					break;
				case 'q': //izzq
					if (input[3] == 'q') { //izzqq
						mode = R_CORE_BIN_SIMPLEST;
						input++;
					} else {
						mode = R_CORE_BIN_SIMPLE;
					}
					break;
				default: 
					mode = R_CORE_BIN_PRINT;
					break;
				}
				input++;
				RBININFO ("strings", R_CORE_BIN_ACC_RAW_STRINGS, NULL, 0);
			} else {
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (input[1] == 'q') {
					mode = (input[2] == 'q')
					? R_CORE_BIN_SIMPLEST
					: R_CORE_BIN_SIMPLE;
					input++;
				}
				if (obj) {
					RBININFO ("strings", R_CORE_BIN_ACC_STRINGS, NULL, 
						obj? r_list_length (obj->strings): 0);
				}
			}
			break;
		case 'c': // for r2 `ic`
			if (input[1]== '?') {
				eprintf ("Usage: ic[ljq*] [class-index]\n");
			} else if (input[1]== ' ' || input[1] == 'q' || input[1] == 'j' || input[1] == 'l') {
				RBinClass *cls;
				RBinSymbol *sym;
				RListIter *iter, *iter2;
				RBinObject *obj = r_bin_cur_object (core->bin);
				int idx = r_num_math (core->num, input +2);
				int count = 0;
				if (obj) {
					if (input[2]) {
						r_list_foreach (obj->classes, iter, cls) {
							if (idx != count++) {
								continue;
							}
							switch (input[1]) {
							case '*':
								r_list_foreach (cls->methods, iter2, sym) {
									r_cons_printf ("f sym.%s @ 0x%"PFMT64x"\n",
											sym->name, sym->vaddr);
								}
								input++;
								break;
							case 'l':
								r_list_foreach (cls->methods, iter2, sym) {
									const char *comma = iter2->p? " ": "";
									r_cons_printf ("%s0x%"PFMT64d, comma, sym->vaddr);
								}
								r_cons_newline ();
								input++;
								break;
							case 'j':
								input++;
								r_cons_printf ("\"class\":\"%s\"", cls->name);
								r_cons_printf (",\"methods\":[");
								r_list_foreach (cls->methods, iter2, sym) {
									const char *comma = iter2->p? ",": "";
									r_cons_printf ("%s{\"name\":\"%s\",\"vaddr\":%"PFMT64d"}",
											comma, sym->name, sym->vaddr);
								}
								r_cons_printf ("]");
								break;
							default:
								r_cons_printf ("class %s\n", cls->name);
								r_list_foreach (cls->methods, iter2, sym) {
									r_cons_printf ("0x%08"PFMT64x" method %s %s\n",
											sym->vaddr, cls->name, sym->name);
								}
								break;
							}
							goto done;
						}
					} else {
						playMsg (core, "classes", r_list_length (obj->classes));
						if (input[1] == 'l' && obj) { // "icl"
							r_list_foreach (obj->classes, iter, cls) {
								r_list_foreach (cls->methods, iter2, sym) {
									const char *comma = iter2->p? " ": "";
									r_cons_printf ("%s0x%"PFMT64d, comma, sym->vaddr);
								}
								if (!r_list_empty (cls->methods)) {
									r_cons_newline ();
								}
							}
						} else {
							RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (obj->classes));
						}
					}
				}
			} else {
				RBinObject *obj = r_bin_cur_object (core->bin);
				int len = obj? r_list_length (obj->classes): 0;
				RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, len);
			}
			break;
		case 'D':
			if (input[1]!=' ' || !demangle (core, input + 2)) {
				eprintf ("|Usage: iD lang symbolname\n");
			}
			return 0;
		case 'a':
			switch (mode) {
			case R_CORE_BIN_RADARE: cmd_info (core, "i*IiecsSmz"); break;
			case R_CORE_BIN_JSON: cmd_info (core, "ijIiecsSmz"); break;
			case R_CORE_BIN_SIMPLE: cmd_info (core, "iqIiecsSmz"); break;
			default: cmd_info (core, "IiEecsSmz"); break;
			}
			break;
		case '?': {
			const char * help_message[] = {
				"Usage: i", "", "Get info from opened file (see rabin2's manpage)",
				"Output mode:", "", "",
				"'*'", "", "Output in radare commands",
				"'j'", "", "Output in json",
				"'q'", "", "Simple quiet output",
				"Actions:", "", "",
				"i|ij", "", "Show info of current file (in JSON)",
				"iA", "", "List archs",
				"ia", "", "Show all info (imports, exports, sections..)",
				"ib", "", "Reload the current buffer for setting of the bin (use once only)",
				"ic", "", "List classes, methods and fields",
				"iC", "", "Show signature info (entitlements, ...)",
				"id", "", "Debug information (source lines)",
				"iD", " lang sym", "demangle symbolname for given language",
				"ie", "", "Entrypoint",
				"iE", "", "Exports (global symbols)",
				"ih", "", "Headers (alias for iH)",
				"iHH", "", "Verbose Headers in raw text",
				"ii", "", "Imports",
				"iI", "", "Binary info",
				"ik", " [query]", "Key-value database from RBinObject",
				"il", "", "Libraries",
				"iL", "", "List all RBin plugins loaded",
				"im", "", "Show info about predefined memory allocation",
				"iM", "", "Show main address",
				"io", " [file]", "Load info from file (or last opened) use bin.baddr",
				"ir|iR", "", "Relocs",
				"is", "", "Symbols",
				"iS ", "[entropy,sha1]", "Sections (choose which hash algorithm to use)",
				"iV", "", "Display file version info",
				"iz", "", "Strings in data sections",
				"izz", "", "Search for Strings in the whole binary",
				"iZ", "", "Guess size of binary program",
				NULL
				};
				r_core_cmd_help (core, help_message);
			}
			goto done;
		case '*':
			mode = R_CORE_BIN_RADARE;
			goto done;
		case 'q':
			mode = R_CORE_BIN_SIMPLE;
			cmd_info_bin (core, va, mode);
			goto done;
		case 'j':
			mode = R_CORE_BIN_JSON;
			if (is_array > 1) {
				mode |= R_CORE_BIN_ARRAY;
			}
			cmd_info_bin (core, va, mode);
			goto done;
		default:
			cmd_info_bin (core, va, mode);
			break;
		}
		input++;
		if ((*input == 'j' || *input == 'q') && !input[1]) {
			break;
		}
	}
done:
	if (is_array)
		r_cons_printf ("}\n");
	if (newline) r_cons_newline();
	return 0;
}
