/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_core.h>

R_API ut64 r_core_file_resize(struct r_core_t *core, ut64 newsize) {
	if (newsize==0 && core->file)
		return core->file->size;
	return 0LL;
}

R_API void r_core_sysenv_update(RCore *core) {
	char buf[64];
#if DISCUSS
 EDITOR      cfg.editor (vim or so)
 CURSOR      cursor position (offset from curseek)
 COLOR       scr.color?1:0
 VERBOSE     cfg.verbose
// only if cmd matches BYTES or BLOCK ?
 BYTES       hexpairs of current block
 BLOCK       temporally file with contents of current block
#endif
	if (!core->file)
		return;
	if (core->file->filename)
		r_sys_setenv ("FILE", core->file->filename);
	snprintf (buf, sizeof (buf), "%"PFMT64d, core->offset);
	r_sys_setenv ("OFFSET", buf);
	snprintf (buf, sizeof (buf), "0x%08"PFMT64x, core->offset);
	r_sys_setenv ("XOFFSET", buf);
	snprintf (buf, sizeof (buf), "%"PFMT64d, core->file->size);
	r_sys_setenv ("SIZE", buf);
	r_sys_setenv ("ENDIAN", core->assembler->big_endian?"big":"little");
	snprintf (buf, sizeof (buf), "%d", core->blocksize);
	r_sys_setenv ("BSIZE", buf);
	r_sys_setenv ("ARCH", r_config_get (core->config, "asm.arch"));
	r_sys_setenv ("DEBUG", r_config_get_i (core->config, "cfg.debug")?"1":"0");
	r_sys_setenv ("IOVA", r_config_get_i (core->config, "io.va")?"1":"0");
}

R_API int r_core_bin_load(RCore *r, const char *file) {
	RBinObj *obj;
	RList *list;
	RListIter *iter;
	ut64 baddr;
	int va = r->io->va || r->io->debug;
	int i = 0;
	char str[R_FLAG_NAME_SIZE];

	if (!r_bin_load (r->bin, file, 0))
		return R_FALSE;
	r->file->obj = obj = r_bin_get_object (r->bin, 0);
	baddr = r_bin_get_baddr (r->bin);

	// I -> Binary info
	RBinInfo *info;

	if ((info = r_bin_get_info (r->bin)) != NULL) {
		r_config_set (r->config, "file.type", info->rclass);
		r_config_set (r->config, "cfg.bigendian", info->big_endian?"true":"false");
		r_config_set (r->config, "asm.os", info->os);
		r_config_set (r->config, "asm.arch", info->arch);
		r_config_set (r->config, "anal.plugin", info->arch);
		snprintf (str, R_FLAG_NAME_SIZE, "%i", info->bits);
		r_config_set (r->config, "asm.bits", str);
		r_config_set (r->config, "asm.dwarf", R_BIN_DBG_STRIPPED (info->dbg_info)?"false":"true");
	}

	// M -> Main
	RBinAddr *binmain;

	r_flag_space_set (r->flags, "symbols");
	if ((binmain = r_bin_get_sym (r->bin, R_BIN_SYM_MAIN)) != NULL)
		r_flag_set (r->flags, "main", va?baddr+binmain->rva:binmain->offset,
				r->blocksize, 0);

	// e -> Entrypoints
	RBinAddr *entry;
	i = 0;

	if ((list = r_bin_get_entries (r->bin)) != NULL) {
		r_list_foreach (list, iter, entry) {
			snprintf (str, R_FLAG_NAME_SIZE, "entry%i", i++);
			r_flag_set (r->flags, str, va?baddr+entry->rva:entry->offset,
					r->blocksize, 0);
		}
		/* Seek to the last entry point */
		r_core_seek (r, va?baddr+entry->rva:entry->offset, 0);
	}

	// s -> Symbols
	RBinSymbol *symbol;

	if ((list = r_bin_get_symbols (r->bin)) != NULL) {
		r_list_foreach (list, iter, symbol) {
			r_flag_name_filter (symbol->name);
			snprintf (str, R_FLAG_NAME_SIZE, "fcn.sym.%s", symbol->name);
			if (!strncmp (symbol->type,"FUNC", 4)) {
				r_flag_space_set (r->flags, "functions");
				r_flag_set (r->flags, str, va?baddr+symbol->rva:symbol->offset,
						symbol->size, 0);
				r_flag_space_set (r->flags, "symbols");
			} else if (!strncmp (symbol->type,"OBJECT", 6))
				r_meta_add (r->meta, R_META_DATA, va?baddr+symbol->rva:symbol->offset,
				(va?baddr+symbol->rva:symbol->offset)+symbol->size, symbol->name);
			r_flag_set (r->flags, str+4, va?baddr+symbol->rva:symbol->offset,
						symbol->size, 0);
		}
	}

	// R -> Relocations
	RBinReloc *reloc;

	r_flag_space_set (r->flags, "relocs");
	if ((list = r_bin_get_relocs (r->bin)) != NULL) {
		r_list_foreach (list, iter, reloc) {
			snprintf (str, R_FLAG_NAME_SIZE, "reloc.%s", reloc->name);
			r_flag_set (r->flags, str, va?baddr+reloc->rva:reloc->offset,
					r->blocksize, 0);
		}
	}

	// z -> Strings
	RBinString *string;

	r_flag_space_set (r->flags, "strings");
	if ((list = r_bin_get_strings (r->bin)) != NULL) {
		r_list_foreach (list, iter, string) {
			/* Jump the withespaces before the string */
			for (i=0;*(string->string+i)==' ';i++);
			r_meta_add (r->meta, R_META_STRING, va?baddr+string->rva:string->offset,
				(va?baddr+string->rva:string->offset)+string->size, string->string+i);
			r_flag_name_filter (string->string);
			snprintf (str, R_FLAG_NAME_SIZE, "str.%s", string->string);
			r_flag_set (r->flags, str, va?baddr+string->rva:string->offset,
					string->size, 0);
		}
	}

	// i -> Imports
	RBinImport *import;

	if ((list = r_bin_get_imports (r->bin)) != NULL) {
		r_list_foreach (list, iter, import) {
			r_flag_name_filter (import->name);
			if (import->size)
				if (!r_anal_fcn_add (r->anal, va?baddr+import->rva:import->offset,
							import->size, import->name, R_ANAL_DIFF_NULL))
					eprintf ("Cannot add function: %s (duplicated)\n", import->name);
			snprintf (str, R_FLAG_NAME_SIZE, "fcn.imp.%s", import->name);
			r_flag_space_set (r->flags, "functions");
			r_flag_set (r->flags, str, va?baddr+import->rva:import->offset,
					import->size, 0);
			r_flag_space_set (r->flags, "imports");
			r_flag_set (r->flags, str+4, va?baddr+import->rva:import->offset,
					import->size, 0);
		}
	}

	// S -> Sections
	RBinSection *section;
	i = 0;

	if ((list = r_bin_get_sections (r->bin)) != NULL) {
		r_flag_space_set (r->flags, "sections");
		r_list_foreach (list, iter, section) {
			r_flag_name_filter (section->name);
			snprintf (str, R_FLAG_NAME_SIZE, "section.%s", section->name);
			r_flag_set (r->flags, str, va?baddr+section->rva:section->offset,
					section->size, 0);
			r_io_section_add (r->io, section->offset, baddr+section->rva,
					section->size, section->vsize, section->srwx, section->name);
			snprintf (str, R_FLAG_NAME_SIZE, "va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"
					PFMT64d" vsz=%"PFMT64d" rwx=%c%c%c%c %s",
					baddr+section->rva, section->offset, section->size, section->vsize,
					R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
					R_BIN_SCN_READABLE (section->srwx)?'r':'-',
					R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
					R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
					section->name);
			r_meta_add (r->meta, R_META_COMMENT, va?baddr+section->rva:section->offset,
					va?baddr+section->rva:section->offset, str);
		}
	}

	return R_TRUE;
}

R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int mode) {
	RCoreFile *fh;
	const char *cp;
	char *p;
	int fd = r_io_open (r->io, file, mode, 0644);
	if (fd == -1)
		return NULL;

	fh = R_NEW (RCoreFile);
	fh->fd = fd;
	fh->uri = strdup (file);
	fh->filename = fh->uri;
	p = strstr (fh->filename, "://");
	if (p != NULL)
		fh->filename = p+3;
	fh->rwx = mode;
	r->file = fh;
	fh->size = r_io_size (r->io, fd);
	list_add (&(fh->list), &r->files);

	r_core_bin_load (r, fh->filename);
	r_core_block_read (r, 0);

	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp)
		r_core_cmd (r, cp, 0);
	r_config_set (r->config, "file.path", file);
	return fh;
}

R_API int r_core_file_close(struct r_core_t *r, struct r_core_file_t *fh) {
	int ret = r_io_close (r->io, fh->fd);
	// TODO: free fh->obj
	list_del (&(fh->list));
	// TODO: set previous opened file as current one
	return ret;
}

R_API struct r_core_file_t *r_core_file_get_fd(struct r_core_t *core, int fd) {
	struct list_head *pos;
	list_for_each_prev (pos, &core->files) {
		RCoreFile *file = list_entry (pos, RCoreFile, list);
		if (file->fd == fd)
			return file;
	}
	return NULL;
}

R_API int r_core_file_list(struct r_core_t *core) {
	int count = 0;
	struct list_head *pos;
	list_for_each_prev (pos, &core->files) {
		RCoreFile *f = list_entry (pos, RCoreFile, list);
		eprintf ("%d %s\n", f->fd, f->uri);
		count++;
	}
	return count;
}

R_API int r_core_file_close_fd(struct r_core_t *core, int fd) {
	int ret = r_io_close (core->io, fd);
	struct r_core_file_t *fh = r_core_file_get_fd (core, fd);
	if (fh != NULL)
		list_del (&(fh->list));
	return ret;
}
