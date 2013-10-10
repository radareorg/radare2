/* radare - LGPL - Copyright 2009-2013 - pancake */

static void r_core_file_info (RCore *core, int mode) {
	const char *fn = NULL;
	int dbg = r_config_get_i (core->config, "cfg.debug");
	RBinInfo *info = r_bin_get_info (core->bin);
	if (mode == R_CORE_BIN_JSON)
		r_cons_printf ("{");
	if (mode == R_CORE_BIN_RADARE)
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
			, info->type
			, info->os
			, info->machine
			, info->bits
			, info->big_endian? "big": "little");
			break;
		default:
		r_cons_printf ("type\t%s\n"
			"os\t%s\n"
			"arch\t%s\n"
			"bits\t%d\n"
			"endian\t%s\n"
			, info->type
			, info->os
			, info->machine
			, info->bits
			, info->big_endian? "big": "little");
			break;
		}
	} else fn = core->file->filename;
	if (mode == R_CORE_BIN_JSON) {
		r_cons_printf ("\"file\":\"%s\"", fn);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		r_cons_printf (",\"fd\":%d", core->file->fd->fd);
		r_cons_printf (",\"size\":%d", core->file->size);
		r_cons_printf (",\"mode\":\"%s\"", r_str_rwx_i (
			core->file->rwx | dbg));
		r_cons_printf (",\"block\":%d", core->blocksize);
		r_cons_printf (",\"uri\":\"%s\"", core->file->uri);
		if (core->bin->curxtr)
			r_cons_printf (",\"packet\":\"%s\"",
				core->bin->curxtr->name);
		if (core->bin->curxtr)
			r_cons_printf (",\"format\":\"%s\"",
				core->bin->cur.curplugin->name);
		r_cons_printf ("}");
	} else {
		//r_cons_printf ("# Core file info\n");
		r_cons_printf ("file\t%s\n", fn);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		r_cons_printf ("fd\t%d\n", core->file->fd->fd);
		r_cons_printf ("size\t0x%x\n", core->file->size);
		r_cons_printf ("mode\t%s\n", r_str_rwx_i (core->file->rwx | dbg));
		r_cons_printf ("block\t0x%x\n", core->blocksize);
		r_cons_printf ("uri\t%s\n", core->file->uri);
		if (core->bin->curxtr)
			r_cons_printf ("packet\t%s\n",
				core->bin->curxtr->name);
		if (core->bin->curxtr)
			r_cons_printf ("format\t%s\n",
				core->bin->cur.curplugin->name);
	}
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 offset = r_bin_get_offset (core->bin);
	int va = core->io->va || core->io->debug;
	int mode = 0;
	if (input[0]) {
		switch (input[1]) {
		case '*': mode = R_CORE_BIN_RADARE; break;
		case 'j': mode = R_CORE_BIN_JSON; break;
		case 'q': mode = R_CORE_BIN_SIMPLE; break;
		}
	}

	switch (*input) {
	case 'o': r_core_bin_load (core, input[1]==' '?
			input+1: core->file->filename); break;
#define RBININFO(x) r_core_bin_info(core,x,mode,va,NULL,offset)
	case 'S': RBININFO (R_CORE_BIN_ACC_SECTIONS); break;
	case 'h': RBININFO (R_CORE_BIN_ACC_FIELDS); break;
	case 'l': RBININFO (R_CORE_BIN_ACC_LIBS); break;
	case 's': RBININFO (R_CORE_BIN_ACC_SYMBOLS); break;
	case 'R':
	case 'r': RBININFO (R_CORE_BIN_ACC_RELOCS); break;
	case 'd': RBININFO (R_CORE_BIN_ACC_DWARF); break;
	case 'i': RBININFO (R_CORE_BIN_ACC_IMPORTS); break;
	case 'I': RBININFO (R_CORE_BIN_ACC_INFO); break;
	case 'e': RBININFO (R_CORE_BIN_ACC_ENTRIES); break;
	case 'z': RBININFO (R_CORE_BIN_ACC_STRINGS); break;
	case 'c':
	case 'C': RBININFO (R_CORE_BIN_ACC_CLASSES); break;
	case 'a':
		if (input[1]=='*') {
			cmd_info (core, "I*");
			cmd_info (core, "e*");
			cmd_info (core, "i*");
			cmd_info (core, "s*");
			cmd_info (core, "S*");
			cmd_info (core, "z*");
		} else {
			cmd_info (core, "I");
			cmd_info (core, "e");
			cmd_info (core, "i");
			cmd_info (core, "s");
			cmd_info (core, "S");
			cmd_info (core, "z");
		}
		break;
	case '?':
		r_cons_printf (
		"Usage: i[aeciIsosSz][jq*]      ; get info from opened file\n"
		"Output mode:\n"
		" '*'   output in radare commands\n"
		" 'j'   output in json\n"
		" 'q'   simple quiet output\n"
		"Actions:\n"
		" io [file] ; load info from given file (or last opened)\n"
		" ia        ; show all info (imports, exports, sections..)\n"
		" ic        ; list classes\n"
		" id        ; debug information (source lines)\n"
		" ie        ; entrypoint\n"
		" ih        ; headers\n"
		" ii        ; imports\n"
		" iI        ; binary info\n"
		" il        ; libraries\n"
		" is        ; symbols\n"
		" iS        ; sections\n"
		" ir/iR     ; relocs\n"
		" iz        ; strings\n");
		break;
	case '*': mode = R_CORE_BIN_RADARE;
	case 'j': if (*input=='j') mode = R_CORE_BIN_JSON;
	default:
		if (core->file) {
			if (mode == R_CORE_BIN_JSON)
				r_cons_printf ("{\"bin\":");
			r_core_bin_info (core, R_CORE_BIN_ACC_INFO,
				mode, va, NULL, offset);
			if (mode == R_CORE_BIN_JSON)
				r_cons_printf (",\"core\":");
			r_core_file_info (core, mode);
			if (mode == R_CORE_BIN_JSON)
				r_cons_printf ("}\n");
		} else eprintf ("No selected file\n");
	}
	return 0;
}
