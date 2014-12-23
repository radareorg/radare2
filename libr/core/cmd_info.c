/* radare - LGPL - Copyright 2009-2014 - pancake */

#define PAIR_WIDTH 9
static void pair(const char *a, const char *b) {
	char ws[16];
	int al = strlen (a);
	if (!b) b = "";
	memset (ws, ' ', sizeof (ws));
	al = PAIR_WIDTH-al;
	if (al<0) al = 0;
	ws[al] = 0;
	r_cons_printf ("%s%s%s\n", a, ws, b);
}

#define STR(x) (x)?(x):""
static void r_core_file_info (RCore *core, int mode) {
	const char *fn = NULL;
	int dbg = r_config_get_i (core->config, "cfg.debug");
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
			r_cons_printf ("\"type\":\"%s\","
			"\"os\":\"%s\","
			"\"arch\":\"%s\","
			"\"bits\":%d,"
			"\"endian\":\"%s\","
			, STR(info->type)
			, STR(info->os)
			, STR(info->machine)
			, info->bits
			, info->big_endian? "big": "little");
			break;
		default:
			pair ("type", info->type);
			pair ("os", info->os);
			pair ("arch", info->machine);
			pair ("bits", sdb_fmt (0, "%d", info->bits));
			pair ("endian", info->big_endian? "big": "little");
			break;
		}
	} else fn = (cf && cf->desc) ? cf->desc->name : NULL;
	if (cf && mode == R_CORE_BIN_JSON) {
		r_cons_printf ("\"file\":\"%s\"", fn);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		if (cf->desc) {
			r_cons_printf (",\"uri\":\"%s\"", cf->desc->uri);
			r_cons_printf (",\"fd\":%d", cf->desc->fd);
			r_cons_printf (",\"size\":%"PFMT64d, r_io_desc_size (core->io, cf->desc));
			r_cons_printf (",\"mode\":\"%s\"", r_str_rwx_i (
				cf->desc->flags & 7 ));
			if (cf->desc->referer && *cf->desc->referer)
				r_cons_printf ("\"referer\":\"%s\"", cf->desc->referer);
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
		pair ("file", fn);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		if (cf->desc) {
			if (cf->desc->referer && *cf->desc->referer)
				pair ("referer", cf->desc->referer);
			pair ("fd", sdb_fmt (0, "%d", cf->desc->fd));
			pair ("size", sdb_fmt (0,"0x%"PFMT64x, r_io_desc_size (core->io, cf->desc)));
			pair ("mode", r_str_rwx_i (cf->desc->flags & 7));
			pair ("uri", cf->desc->uri);
		}
		pair ("block", sdb_fmt (0, "0x%x", core->blocksize));
		if (binfile && binfile->curxtr)
			pair ("packet", binfile->curxtr->name);
		if (plugin)
			pair ("format", plugin->name);
	}
}

static void cmd_info_bin(RCore *core, ut64 offset, int va, int mode) {
	if (core->file) {
		if (mode == R_CORE_BIN_JSON)
			r_cons_printf ("{\"bin\":");
		r_core_bin_info (core, R_CORE_BIN_ACC_INFO,
			mode, va, NULL, offset, NULL);
		if (mode == R_CORE_BIN_JSON)
			r_cons_printf (",\"core\":");
		r_core_file_info (core, mode);
		if (mode == R_CORE_BIN_JSON)
			r_cons_printf ("}\n");
	} else eprintf ("No selected file\n");
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int newline = r_config_get_i (core->config, "scr.interactive");
	ut64 offset = r_bin_get_offset (core->bin);
	RBinObject *o = r_bin_cur_object (core->bin);
	RCoreFile *cf = core->file;

	int va = core->io->va || core->io->debug;
	int mode = 0; //R_CORE_BIN_SIMPLE;
	int is_array = 0;
	Sdb *db;

	if (strchr (input, '*'))
		mode = R_CORE_BIN_RADARE;
	if (strchr (input, 'j'))
		mode = R_CORE_BIN_JSON;
	if (strchr (input, 'q'))
		mode = R_CORE_BIN_SIMPLE;

	if (mode == R_CORE_BIN_JSON) {
		if (strlen (input+1)>1)
			is_array = 1;
	}
	if (is_array)
		r_cons_printf ("{");
	if (!*input)
		cmd_info_bin (core, offset, va, mode);
	while (*input) {
		switch (*input) {
		case 'b':
			{
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			if (input[1]==' ')
				baddr = r_num_math (core->num, input+1);
			// XXX: this will reload the bin using the buffer.
			// An assumption is made that assumes there is an underlying
			// plugin that will be used to load the bin (e.g. malloc://)
			// TODO: Might be nice to reload a bin at a specified offset?
			r_core_bin_reload (core, NULL, baddr);
			r_core_block_read (core, 0);
			}
			break;
		case 'k':
			db = o ? o->kv : NULL;
			//:eprintf ("db = %p\n", db);
			switch (input[1]) {
			case 'v':
				if (db) {
					char *o = sdb_querys (db, NULL, 0, input+3);
					if (o && *o) r_cons_printf ("%s", o);
					free (o);
				}
				break;
			case '.':
			case ' ':
				if (db) {
					char *o = sdb_querys (db, NULL, 0, input+2);
					if (o && *o) r_cons_printf ("%s", o);
					free (o);
				}
				break;
			case '\0':
				if (db) {
					char *o = sdb_querys (db, NULL, 0, "*");
					if (o && *o) r_cons_printf ("%s", o);
					free (o);
				}
				break;
			case '?':
			default:
				eprintf ("Usage: ik [sdb-query]\n");
			}
			break;
		case 'o':
			 {
				if (!cf) {
					eprintf ("Core file not open\n");
					return 0;
				}
				const char *fn = input[1]==' '? input+2: cf->desc->name;
				ut64 laddr = UT64_MAX;
				laddr = r_config_get_i (core->config, "bin.baddr");
				r_core_bin_load (core, fn, laddr);
			 }
			break;
	#define RBININFO(n,x) \
	if (is_array) { \
		if (is_array==1) is_array++; else r_cons_printf (","); \
		r_cons_printf ("\"%s\":",n); \
	}\
	r_core_bin_info (core,x,mode,va,NULL,offset,NULL);
		case 'A': newline=0; r_bin_list_archs (core->bin, 1); break;
		case 'Z': RBININFO ("size",R_CORE_BIN_ACC_SIZE); break;
		case 'S': RBININFO ("sections",R_CORE_BIN_ACC_SECTIONS); break;
		case 'h': RBININFO ("fields", R_CORE_BIN_ACC_FIELDS); break;
		case 'l': RBININFO ("libs", R_CORE_BIN_ACC_LIBS); break;
		case 's': RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS); break;
		case 'R':
		case 'r': RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS); break;
		case 'd': RBININFO ("dwarf", R_CORE_BIN_ACC_DWARF); break;
		case 'i': RBININFO ("imports",R_CORE_BIN_ACC_IMPORTS); break;
		case 'I': RBININFO ("info", R_CORE_BIN_ACC_INFO); break;
		case 'e': RBININFO ("entries",R_CORE_BIN_ACC_ENTRIES); break;
		case 'z':
			if (input[1] == 'z') {
				/* TODO: reimplement in C to avoid forks */
				if (!core->file) {
					eprintf ("Core file not open\n");
					return 0;
				}
				char *ret;
				switch (input[2]) {
				case '*':
					ret = r_sys_cmd_strf ("rabin2 -rzz '%s'", core->file->desc->name);
					break;
				case 'q':
					ret = r_sys_cmd_strf ("rabin2 -qzz '%s'", core->file->desc->name);
					break;
				case 'j':
					ret = r_sys_cmd_strf ("rabin2 -jzz '%s'", core->file->desc->name);
					break;
				default:
					ret = r_sys_cmd_strf ("rabin2 -zz '%s'", core->file->desc->name);
					break;
				}
				if (ret && *ret) {
					r_cons_strcat (ret);
				}
				free (ret);
				input++;
			} else {
				RBININFO ("strings", R_CORE_BIN_ACC_STRINGS);
			}
			break;
		case 'c':
		case 'C': RBININFO ("classes", R_CORE_BIN_ACC_CLASSES); break;
		case 'a':
			{
				switch (mode) {
				case R_CORE_BIN_RADARE: cmd_info (core, "i*IiesSz"); break;
				case R_CORE_BIN_JSON: cmd_info (core, "iIiesSzj"); break;
				default:
				case R_CORE_BIN_SIMPLE: cmd_info (core, "iIiesSz"); break;
				}
			}
			break;
		case '?': {
				const char * help_message[] = {
				"Usage: i", "", "Get info from opened file",
				"Output mode:", "", "",
				"'*'", "", "Output in radare commands",
				"'j'", "", "Output in json",
				"'q'", "", "Simple quiet output",
				"Actions:", "", "",
				"i|ij", "", "Show info of current file (in JSON)",
				"iA", "", "List archs",
				"ia", "", "Show all info (imports, exports, sections..)",
				"ib", "", "Reload the current buffer for setting of the bin (use once only)",
				"ic", "", "List classes",
				"id", "", "Debug information (source lines)",
				"ie", "", "Entrypoint",
				"ih", "", "Headers",
				"ii", "", "Imports",
				"iI", "", "Binary info",
				"ik", " [query]", "Key-value database from RBinObject",
				"il", "", "Libraries",
				"io", " [file]", "Load info from file (or last opened) use bin.baddr",
				"ir|iR", "", "Relocs",
				"is", "", "Symbols",
				"iS", "", "Sections",
				"iz", "", "Strings in data sections",
				"izz", "", "Search for Strings in the whole binary",
				NULL
				};
				r_core_cmd_help(core, help_message);

				}
			goto done;
		case '*':
			mode = R_CORE_BIN_RADARE;
			goto done;
		case 'q':
			mode = R_CORE_BIN_SIMPLE;
			cmd_info_bin (core, offset, va, mode);
			goto done;
		case 'j':
			mode = R_CORE_BIN_JSON;
			cmd_info_bin (core, offset, va, mode);
			goto done;
		default:
			cmd_info_bin (core, offset, va, mode);
			break;
		}
		input++;
		if (!strcmp (input, "j"))
			break;
		if (!strcmp (input, "q"))
			break;
	}
done:
	if (is_array)
		r_cons_printf ("}\n");
	if (newline) r_cons_newline();
	return 0;
}
