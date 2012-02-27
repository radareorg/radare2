
/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 offset = r_bin_get_offset (core->bin);
	int va = core->io->va || core->io->debug;
	int mode = (input[1]=='*')?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT;
	switch (*input) {
	case 'S':
		r_core_bin_info (core, R_CORE_BIN_ACC_SECTIONS|R_CORE_BIN_ACC_FIELDS, mode, va, NULL, offset);
		break;
	case 's':
		r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, mode, va, NULL, offset);
		break;
	case 'i':
		r_core_bin_info (core, R_CORE_BIN_ACC_IMPORTS, mode, va, NULL, offset);
		break;
	case 'I':
		r_core_bin_info (core, R_CORE_BIN_ACC_INFO, mode, va, NULL, offset);
		break;
	case 'e':
		r_core_bin_info (core, R_CORE_BIN_ACC_ENTRIES, mode, va, NULL, offset);
		break;
	case 'z':
		r_core_bin_info (core, R_CORE_BIN_ACC_STRINGS, mode, va, NULL, offset);
		break;
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
		"Usage: i[aeiIsSz]*      ; get info from opened file\n"
		"NOTE: Append a '*' to get the output in radare commands\n"
		" ia    ; show all info (imports, exports, sections..)\n"
		" ii    ; imports\n"
		" iI    ; binary info\n"
		" ie    ; entrypoint\n"
		" is    ; symbols\n"
		" iS    ; sections\n"
		" iz    ; strings\n");
		break;
	case '*':
		break;
	default:
		if (core->file) {
			const char *fn = NULL;
			int dbg = r_config_get_i (core->config, "cfg.debug");
			RBinInfo *info = r_bin_get_info (core->bin);
			if (info) {
				fn = info->file;
				r_cons_printf ("type\t%s\n", info->type);
				r_cons_printf ("os\t%s\n", info->os);
				r_cons_printf ("arch\t%s\n", info->machine);
				r_cons_printf ("bits\t%d\n", info->bits);
				r_cons_printf ("endian\t%s\n", info->big_endian? "big": "little");
			} else {
				fn = core->file->filename;
			}
			r_cons_printf ("file\t%s\n", fn);
			if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
			r_cons_printf ("fd\t%d\n", core->file->fd->fd);
			r_cons_printf ("size\t0x%x\n", core->file->size);
			r_cons_printf ("mode\t%s\n", r_str_rwx_i (core->file->rwx | dbg));
			r_cons_printf ("block\t0x%x\n", core->blocksize);
			r_cons_printf ("uri\t%s\n", core->file->uri);
			if (core->bin->curxtr)
				r_cons_printf ("packet\t%s\n", core->bin->curxtr->name);
			if (core->bin->curxtr)
				r_cons_printf ("format\t%s\n", core->bin->curarch.curplugin->name);
		} else eprintf ("No selected file\n");
	}
	return 0;
}
