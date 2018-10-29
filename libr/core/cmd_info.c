/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <string.h>
#include "r_bin.h"
#include "r_config.h"
#include "r_cons.h"
#include "r_core.h"
#include "../bin/pdb/pdb_downloader.h"

static const char *help_msg_i[] = {
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
	"icc", "", "List classes, methods and fields in Header Format",
	"iC", "", "Show signature info (entitlements, ...)",
	"id", "[?]", "Debug information (source lines)",
	"idp", "", "Load pdb file information",
	"iD", " lang sym", "demangle symbolname for given language",
	"ie", "", "Entrypoint",
	"iee", "", "Show Entry and Exit (preinit, init and fini)",
	"iE", "", "Exports (global symbols)",
	"iE.", "", "Current export",
	"ih", "", "Headers (alias for iH)",
	"iHH", "", "Verbose Headers in raw text",
	"ii", "", "Imports",
	"iI", "", "Binary info",
	"ik", " [query]", "Key-value database from RBinObject",
	"il", "", "Libraries",
	"iL ", "[plugin]", "List all RBin plugins loaded or plugin details",
	"im", "", "Show info about predefined memory allocation",
	"iM", "", "Show main address",
	"io", " [file]", "Load info from file (or last opened) use bin.baddr",
	"iO", "[?]", "Perform binary operation (dump, resize, change sections, ...)",
	"ir", "", "Relocs",
	"iR", "", "Resources",
	"is", "", "Symbols",
	"is.", "", "Current symbol",
	"iS ", "[entropy,sha1]", "Sections (choose which hash algorithm to use)",
	"iS.", "", "Current section",
	"iSS", " [entropy,sha1]", "Segments",
	"iV", "", "Display file version info",
	"iX", "", "Display source files used (via dwarf)",
	"iz|izj", "", "Strings in data sections (in JSON/Base64)",
	"izz", "", "Search for Strings in the whole binary",
	"izzz", "", "Dump Strings from whole binary to r2 shell (for huge files)",
	"iz-", " [addr]", "Purge string via bin.strpurge",
	"iZ", "", "Guess size of binary program",
	NULL
};

// TODO: this command needs a refactoring
static const char *help_msg_id[] = {
	"Usage: idp", "", "Debug information",
	"id", "", "Show DWARF source lines information",
	"idp", " [file.pdb]", "Load pdb file information",
	"idpi", " [file.pdb]", "Show pdb file information",
	"idpi*", "", "Show symbols from pdb as flags (prefix with dot to import)",
	"idpd", "", "Download pdb file on remote server",
	NULL
};

static void cmd_info_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, i);
	DEFINE_CMD_DESCRIPTOR (core, id);
}

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
	case R_BIN_NM_MSVC: res = r_bin_demangle_msvc (s); break;
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

static int demangle(RCore *core, const char *s) {
	char *p, *q;
	const char *ss = strchr (s, ' ');
	if (!*s) {
		return 0;
	}
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

#define STR(x) (x)? (x): ""
static void r_core_file_info(RCore *core, int mode) {
	const char *fn = NULL;
	int dbg = r_config_get_i (core->config, "cfg.debug");
	bool io_cache = r_config_get_i (core->config, "io.cache");
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinFile *binfile = r_core_bin_cur (core);
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (mode == R_MODE_JSON) {
		r_cons_printf ("{");
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
			r_cons_printf ("\"type\":\"%s\",", STR (info->type));
		}
	} else {
		fn = desc ? desc->name: NULL;
	}
	if (desc && mode == R_MODE_JSON) {
		const char *uri = fn;
		if (!uri) {
			if (desc && desc->uri && *desc->uri) {
				uri = desc->uri;
			} else {
				uri = "";
			}
		}
		{
			char *escapedFile = r_str_utf16_encode (uri, -1);
			r_cons_printf ("\"file\":\"%s\"", escapedFile);
			free (escapedFile);
		}
		if (dbg) {
			dbg = R_PERM_WX;
		}
		if (desc) {
			ut64 fsz = r_io_desc_size (desc);
			r_cons_printf (",\"fd\":%d", desc->fd);
			if (fsz != UT64_MAX) {
				r_cons_printf (",\"size\":%"PFMT64d, fsz);
				char *humansz = r_num_units (NULL, fsz);
				if (humansz) {
					r_cons_printf (",\"humansz\":\"%s\"", humansz);
					free (humansz);
				}
			}
			r_cons_printf (",\"iorw\":%s", r_str_bool ( io_cache || desc->perm & R_PERM_W));
			r_cons_printf (",\"mode\":\"%s\"", r_str_rwx_i (desc->perm & R_PERM_RWX));
			r_cons_printf (",\"obsz\":%"PFMT64d, (ut64) core->io->desc->obsz);
			if (desc->referer && *desc->referer) {
				r_cons_printf (",\"referer\":\"%s\"", desc->referer);
			}
		}
		r_cons_printf (",\"block\":%d", core->blocksize);
		if (binfile) {
			if (binfile->curxtr) {
				r_cons_printf (",\"packet\":\"%s\"",
					binfile->curxtr->name);
			}
			if (plugin) {
				r_cons_printf (",\"format\":\"%s\"",
					plugin->name);
			}
		}
		r_cons_printf ("}");
	} else if (desc && mode != R_MODE_SIMPLE) {
		//r_cons_printf ("# Core file info\n");
		if (dbg) {
			dbg = R_PERM_WX;
		}
		if (desc) {
			pair ("blksz", sdb_fmt ("0x%"PFMT64x, (ut64) core->io->desc->obsz));
		}
		pair ("block", sdb_fmt ("0x%x", core->blocksize));
		if (desc) {
			pair ("fd", sdb_fmt ("%d", desc->fd));
		}
		if (fn || (desc && desc->uri)) {
			pair ("file", fn? fn: desc->uri);
		}
		if (plugin) {
			pair ("format", plugin->name);
		}
		if (desc) {
			pair ("iorw", r_str_bool (io_cache || desc->perm & R_PERM_W));
			pair ("mode", r_str_rwx_i (desc->perm & R_PERM_RWX));
		}
		if (binfile && binfile->curxtr) {
			pair ("packet", binfile->curxtr->name);
		}
		if (desc && desc->referer && *desc->referer) {
			pair ("referer", desc->referer);
		}
		if (desc) {
			ut64 fsz = r_io_desc_size (desc);
			if (fsz != UT64_MAX) {
				pair ("size", sdb_itoca (fsz));
				char *humansz = r_num_units (NULL, fsz);
				if (humansz) {
					pair ("humansz", humansz);
					free (humansz);
				}
			}
		}
		if (info) {
			pair ("type", info->type);
		}
	}
}

static int bin_is_executable(RBinObject *obj){
	RListIter *it;
	RBinSection *sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		r_list_foreach (obj->sections, it, sec){
			if (sec->perm & R_PERM_X) {
				return true;
			}
		}
	}
	return false;
}

static void cmd_info_bin(RCore *core, int va, int mode) {
	RBinObject *obj = r_bin_cur_object (core->bin);
	int array = 0;
	if (core->file) {
		if ((mode & R_MODE_JSON) && !(mode & R_MODE_ARRAY)) {
			mode = R_MODE_JSON;
			r_cons_strcat ("{\"core\":");
		}
		if ((mode & R_MODE_JSON) && (mode & R_MODE_ARRAY)) {
			mode = R_MODE_JSON;
			array = 1;
			r_cons_strcat (",\"core\":");
		}
		r_core_file_info (core, mode);
		if (bin_is_executable (obj)) {
			if ((mode & R_MODE_JSON)) {
				r_cons_strcat (",\"bin\":");
			}
			r_core_bin_info (core, R_CORE_BIN_ACC_INFO, mode, va, NULL, NULL);
		}
		if (mode == R_MODE_JSON && array == 0) {
			r_cons_strcat ("}\n");
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
	RCore *core = (RCore *) data;
	bool newline = r_config_get_i (core->config, "scr.interactive");
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	int i, va = core->io->va || core->io->debug;
	int mode = 0; //R_MODE_SIMPLE;
	bool rdump = false;
	int is_array = 0;
	Sdb *db;

	for (i = 0; input[i] && input[i] != ' '; i++)
		;
	if (i > 0) {
		switch (input[i - 1]) {
		case '*': mode = R_MODE_RADARE; break;
		case 'j': mode = R_MODE_JSON; break;
		case 'q': mode = R_MODE_SIMPLE; break;
		}
	}
	if (mode == R_MODE_JSON) {
		int suffix_shift = 0;
		if (!strncmp (input, "SS", 2) || !strncmp (input, "ee", 2)
			|| !strncmp (input, "zz", 2)) {
			suffix_shift = 1;
		}
		if (strlen (input + 1 + suffix_shift) > 1) {
			is_array = 1;
		}
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
	while (*input) {
		switch (*input) {
		case 'b': // "ib"
		{
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			if (input[1] == ' ') {
				baddr = r_num_math (core->num, input + 1);
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
		case 'k': // "ik"
		{
			RBinObject *o = r_bin_cur_object (core->bin);
			db = o? o->kv: NULL;
			//:eprintf ("db = %p\n", db);
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
					if (o && *o) {
						r_cons_print (o);
					}
					free (o);
				}
				break;
			case '?':
			default:
				eprintf ("Usage: ik [sdb-query]\n");
				eprintf ("Usage: ik*    # load all header information\n");
			}
			goto done;
		}
		break;
		case 'o': // "io"
		{
			if (!desc) {
				eprintf ("Core file not open\n");
				return 0;
			}
			const char *fn = input[1] == ' '? input + 2: desc->name;
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			r_core_bin_load (core, fn, baddr);
		}
		break;
			#define RBININFO(n,x,y,z)\
				if (is_array) {\
					if (is_array == 1) { is_array++;\
					} else { r_cons_printf (",");}\
					r_cons_printf ("\"%s\":",n);\
				}\
				if (z) { playMsg (core, n, z);}\
				r_core_bin_info (core, x, mode, va, NULL, y);
		case 'A': // "iA"
			newline = false;
			if (input[1] == 'j') {
				r_cons_printf ("{");
				r_bin_list_archs (core->bin, 'j');
				r_cons_printf ("}\n");
			} else {
				r_bin_list_archs (core->bin, 1);
			}
			break;
		case 'E': // "iE"
		{
			if (input[1] == 'j' && input[2] == '.') {
				mode = R_MODE_JSON;
				RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, input + 2, 0);
			} else {
				RBININFO ("exports", R_CORE_BIN_ACC_EXPORTS, input + 1, 0);
			}
			while (*(++input)) ;
			input--;
			break;
		}
		case 'Z': // "iZ"
			RBININFO ("size", R_CORE_BIN_ACC_SIZE, NULL, 0);
			break;
		case 'O': // "iO"
			switch (input[1]) {
			case ' ':
			        r_sys_cmdf ("rabin2 -O \"%s\" \"%s\"", r_str_trim_ro (input + 1), desc->name);
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
			} else if (input[1] == 'S' && !input[2]) {  // "iSS"
				RBININFO ("segments", R_CORE_BIN_ACC_SEGMENTS, NULL, 0);
			} else {  //iS/iSS entropy,sha1
				const char *name = "sections";
				int action = R_CORE_BIN_ACC_SECTIONS;
				int param_shift = 0;
				if (input[1] == 'S') {
					name = "segments";
					action = R_CORE_BIN_ACC_SEGMENTS;
					param_shift = 1;
				}
				// case for iS=
				if (input[1] == '=') {
					mode = R_MODE_EQUAL;
				} else if (input[1] == 'q' && input[2] == '.') {
					mode = R_MODE_SIMPLE;
				} else if (input[1] == 'j' && input[2] == '.') {
					mode = R_MODE_JSON;
				}
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (mode == R_MODE_RADARE || mode == R_MODE_JSON || mode == R_MODE_SIMPLE) {
					RBININFO (name, action, input + 2 + param_shift,
						(obj && obj->sections)? r_list_length (obj->sections): 0);
				} else {
					RBININFO (name, action, input + 1 + param_shift,
						(obj && obj->sections)? r_list_length (obj->sections): 0);
				}
			}
			//we move input until get '\0'
			while (*(++input)) ;
			//input-- because we are inside a while that does input++
			// oob read if not input--
			input--;
			break;
		case 'H': // "iH"
			if (input[1] == 'H') { // "iHH"
				RBININFO ("header", R_CORE_BIN_ACC_HEADER, NULL, -1);
				break;
			}
		case 'h': // "ih"
			RBININFO ("fields", R_CORE_BIN_ACC_FIELDS, NULL, 0);
			break;
		case 'l': { // "il"
			RBinObject *obj = r_bin_cur_object (core->bin);
			RBININFO ("libs", R_CORE_BIN_ACC_LIBS, NULL, (obj && obj->libs)? r_list_length (obj->libs): 0);
			break;
		}
		case 'L': { // "iL"
			char *ptr = strchr (input, ' ');
			int json = input[1] == 'j'? 'j': 0;

			if (ptr && ptr[1]) {
				const char *plugin_name = ptr + 1;
				if (is_array) {
					r_cons_printf ("\"plugin\": ");
				}
				r_bin_list_plugin (core->bin, plugin_name, json);
			} else {
				r_bin_list (core->bin, json);
			}
			newline = false;
			goto done;
		}
		case 's': { // "is"
			RBinObject *obj = r_bin_cur_object (core->bin);
			// Case for isj.
			if (input[1] == 'j' && input[2] == '.') {
				mode = R_MODE_JSON;
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
			} else {
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
			}
			while (*(++input)) ;
			input--;
			break;
		}
		case 'R': // "iR"
			if  (input[1] == '*') {
				mode = R_MODE_RADARE;
			} else if (input[1] == 'j') {
				mode = R_MODE_JSON;
			}
			RBININFO ("resources", R_CORE_BIN_ACC_RESOURCES, NULL, 0);
			break;
		case 'r': // "ir"
			RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS, NULL, 0);
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
				case ' ':
					r_core_cmdf (core, ".idpi* %s", input + 3);
					while (input[2]) input++;
					break;
				case '\0':
					r_core_cmd0 (core, ".idpi*");
					break;
				case 'd':
					pdbopts.user_agent = (char*) r_config_get (core->config, "pdb.useragent");
					pdbopts.symbol_server = (char*) r_config_get (core->config, "pdb.server");
					pdbopts.extract = r_config_get_i (core->config, "pdb.extract");
					pdbopts.symbol_store_path = (char*) r_config_get (core->config, "pdb.symstore");
					int r = r_bin_pdb_download (core, 0, NULL, &pdbopts);
					if (r > 0) {
						eprintf ("Error while downloading pdb file");
					}
					input++;
					break;
				case 'i':
					info = r_bin_get_info (core->bin);
					file_found = false;
					filename = strchr (input, ' ');
					while (input[2]) input++;
					if (filename) {
						*filename++ = '\0';
						filename = strdup (filename);
						file_found = r_file_exists (filename);
					} else {
						/* Autodetect local file */
						if (!info || !info->debug_file_name) {
							eprintf ("Cannot get file's debug information");
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
							char* pdb_path = r_str_newf ("%s" R_SYS_DIR "%s" R_SYS_DIR "%s" R_SYS_DIR "%s",
										     symstore_path, r_file_basename (info->debug_file_name),
										     info->guid, r_file_basename (info->debug_file_name));
							file_found = r_file_exists (pdb_path);
							if (file_found) {
								filename = pdb_path;
							} else {
								R_FREE(pdb_path);
							}
						}
					}

					if (!file_found) {
						eprintf ("File '%s' not found in file directory or symbol store", r_file_basename (info->debug_file_name));
						free (filename);
						break;
					}
					ut64 baddr = 0;
					if (core->bin->cur && core->bin->cur->o) {
						baddr = core->bin->cur->o->baddr;
					} else {
						eprintf ("Warning: Cannot find base address, flags will probably be misplaced\n");
					}
					r_core_pdb_info (core, filename, baddr, mode);
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
			RBinObject *obj = r_bin_cur_object (core->bin);
			RBININFO ("imports", R_CORE_BIN_ACC_IMPORTS, NULL,
				(obj && obj->imports)? r_list_length (obj->imports): 0);
			break;
		}
		case 'I': // "iI"
			RBININFO ("info", R_CORE_BIN_ACC_INFO, NULL, 0);
			break;
		case 'e': // "ie"
			if (input[1] == 'e') {
				RBININFO ("initfini", R_CORE_BIN_ACC_INITFINI, NULL, 0);
				input++;
			} else {
				RBININFO ("entries", R_CORE_BIN_ACC_ENTRIES, NULL, 0);
			}
			break;
		case 'M': // "iM"
			RBININFO ("main", R_CORE_BIN_ACC_MAIN, NULL, 0);
			break;
		case 'm': // "im"
			RBININFO ("memory", R_CORE_BIN_ACC_MEM, NULL, 0);
			break;
		case 'V': // "iV"
			RBININFO ("versioninfo", R_CORE_BIN_ACC_VERSIONINFO, NULL, 0);
			break;
		case 'C': // "iC"
			RBININFO ("signature", R_CORE_BIN_ACC_SIGNATURE, NULL, 0);
			break;
		case 'z': // "iz"
			if (input[1] == '-') { //iz-
				char *strpurge = core->bin->strpurge;
				ut64 addr = core->offset;
				bool old_tmpseek = core->tmpseek;
				input++;
				if (input[1] == ' ') {
					const char *argstr = r_str_trim_ro (input + 2);
					ut64 arg = r_num_get (NULL, argstr);
					input++;
					if (arg != 0 || *argstr == '0') {
						addr = arg;
					}
				}
				core->tmpseek = false;
				r_core_cmdf (core, "e bin.strpurge=%s%s0x%" PFMT64x,
				             strpurge ? strpurge : "",
				             strpurge && *strpurge ? "," : "",
				             addr);
				core->tmpseek = old_tmpseek;
				newline = false;
			} else if (input[1] == 'z') { //izz
				switch (input[2]) {
				case 'z'://izzz
					rdump = true;
					break;
				case '*':
					mode = R_MODE_RADARE;
					break;
				case 'j':
					mode = R_MODE_JSON;
					break;
				case 'q': //izzq
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
					RBinFile *bf = r_core_bin_cur (core);
					int min = r_config_get_i (core->config, "bin.minstr");
					if (bf) {
						bf->strmode = mode;
						r_bin_dump_strings (bf, min, 2);
					}
					goto done;
				}
				RBININFO ("strings", R_CORE_BIN_ACC_RAW_STRINGS, NULL, 0);
			} else {
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (input[1] == 'q') {
					mode = (input[2] == 'q')
					? R_MODE_SIMPLEST
					: R_MODE_SIMPLE;
					input++;
				}
				if (obj) {
					RBININFO ("strings", R_CORE_BIN_ACC_STRINGS, NULL,
						(obj && obj->strings)? r_list_length (obj->strings): 0);
				}
			}
			break;
		case 'c': // "ic"
			if (input[1] == '?') {
				eprintf ("Usage: ic[ljqc*] [class-index or name]\n");
			} else if (input[1] == ' ' || input[1] == 'q' || input[1] == 'j' || input[1] == 'l' || input[1] == 'c') {
				RBinClass *cls;
				RBinSymbol *sym;
				RListIter *iter, *iter2;
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (obj) {
					if (input[2]) {
						int idx = -1;
						const char * cls_name = NULL;
						if (r_num_is_valid_input (core->num, input + 2)) {
							idx = r_num_math (core->num, input + 2);
						} else {
							const char * first_char = input + ((input[1] == ' ') ? 1 : 2);
							int not_space = strspn (first_char, " ");
							if (first_char[not_space]) {
								cls_name = first_char + not_space;
							}
						}
						int count = 0;
						r_list_foreach (obj->classes, iter, cls) {
							if ((idx >= 0 && idx != count++) ||
							   (cls_name && strcmp (cls_name, cls->name) != 0)){
								continue;
							}
							switch (input[1]) {
							case '*':
								r_list_foreach (cls->methods, iter2, sym) {
									r_cons_printf ("f sym.%s @ 0x%"PFMT64x "\n",
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

									if (sym->method_flags) {
										char *flags = r_core_bin_method_flags_str (sym->method_flags, R_MODE_JSON);
										r_cons_printf ("%s{\"name\":\"%s\",\"flags\":%s,\"vaddr\":%"PFMT64d "}",
											comma, sym->name, flags, sym->vaddr);
										R_FREE (flags);
									} else {
										r_cons_printf ("%s{\"name\":\"%s\",\"vaddr\":%"PFMT64d "}",
											comma, sym->name, sym->vaddr);
									}
								}
								r_cons_printf ("]");
								break;
							default:
								r_cons_printf ("class %s\n", cls->name);
								r_list_foreach (cls->methods, iter2, sym) {
									char *flags = r_core_bin_method_flags_str (sym->method_flags, 0);
									r_cons_printf ("0x%08"PFMT64x " method %s %s %s\n",
										sym->vaddr, cls->name, flags, sym->name);
									R_FREE (flags);
								}
								break;
							}
							goto done;
						}
						goto done;
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
						} else if (input[1] == 'c' && obj) { // "icc"
                					mode = R_MODE_CLASSDUMP;
							RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (obj->classes));
							input = " ";
						} else {
							RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, r_list_length (obj->classes));
						}
					}
        			}
			} else {
				RBinObject *obj = r_bin_cur_object (core->bin);
				if (obj && obj->classes) {
					int len = r_list_length (obj->classes);
					RBININFO ("classes", R_CORE_BIN_ACC_CLASSES, NULL, len);
				}
			}
			break;
		case 'D': // "iD"
			if (input[1] != ' ' || !demangle (core, input + 2)) {
				eprintf ("|Usage: iD lang symbolname\n");
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
			r_core_cmd_help (core, help_msg_i);
			goto redone;
		case '*': // "i*"
			mode = R_MODE_RADARE;
			goto done;
		case 'q': // "iq"
			mode = R_MODE_SIMPLE;
			cmd_info_bin (core, va, mode);
			goto done;
		case 'j': // "ij"
			mode = R_MODE_JSON;
			if (is_array > 1) {
				mode |= R_MODE_ARRAY;
			}
			cmd_info_bin (core, va, mode);
			goto done;
		default:
			cmd_info_bin (core, va, mode);
			break;
		}
		// input can be overwritten like the 'input = " ";' a few lines above
		if (input[0] != ' ') {
			input++;
			if ((*input == 'j' || *input == 'q') && (input[0] && !input[1])) {
				break;
			}
		} else {
			break;
		}
	}
done:
	if (is_array) {
		r_cons_printf ("}\n");
	}
	if (newline) {
		r_cons_newline ();
	}
redone:
	return 0;
}
