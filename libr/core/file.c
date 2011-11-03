/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_core.h>

R_API ut64 r_core_file_resize(struct r_core_t *core, ut64 newsize) {
	if (newsize==0 && core->file)
		return core->file->size;
	return 0LL;
}

// NOTE: probably not all environment vars takes sesnse
// because they can be replaced by commands in the given
// command.. we should only expose the most essential and
// unidirectional ones.
R_API void r_core_sysenv_help() {
	r_cons_printf (
	"Usage: !<cmd>\n"
	"  !ls                   ; execute 'ls' in shell\n"
	"  .!rabin2 -ri ${FILE}  ; run each output line as a r2 cmd\n"
	"  !echo $SIZE           ; display file size\n"
	"Environment:\n"
	"  FILE       file name\n"
	"  SIZE       file size\n"
	"  OFFSET     10base offset 64bit value\n"
	"  XOFFSET    same as above, but in 16 base\n"
	"  BSIZE      block size\n"
	"  ENDIAN     'big' or 'little'\n"
	"  ARCH       value of asm.arch\n"
	"  DEBUG      debug mode enabled? (1,0)\n"
	"  IOVA       is io.va true? virtual addressing (1,0)\n"
	"  BLOCK      TODO: dump current block to tmp file\n"
	"  BYTES      TODO: variable with bytes in curblock\n"
	);
}

R_API void r_core_sysenv_end(RCore *core, const char *cmd) {
	// TODO: remove tmpfilez
	if (strstr (cmd, "BLOCK")) {
		// remove temporary BLOCK file
	}
}

R_API char *r_core_sysenv_begin(RCore *core, const char *cmd) {
	char buf[64], *ret;
#if DISCUSS
	// EDITOR      cfg.editor (vim or so)
	CURSOR      cursor position (offset from curseek)
	COLOR       scr.color?1:0
	VERBOSE     cfg.verbose
	// only if cmd matches BYTES or BLOCK ?
	BYTES       hexpairs of current block
	BLOCK       temporally file with contents of current block
#endif
	if (!core->file)
		return NULL;
	ret = strdup (cmd);
	if (strstr (cmd, "BLOCK")) {
		// replace BLOCK in RET string
	}
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
	return ret;
}

R_API int r_core_bin_load(RCore *r, const char *file) {
	int va = r->io->va || r->io->debug;
	char str[R_FLAG_NAME_SIZE];
	RBinSection *section;
	RBinSymbol *symbol;
	RBinString *string;
	RBinImport *import;
	RBinAddr *binmain;
	RBinReloc *reloc;
	RListIter *iter;
	RBinAddr *entry;
	RBinInfo *info;
	RBinObj *obj;
	RList *list;
	ut64 baddr;
	int i = 0;
	ut64 size;

	if (file == NULL)
		file = r->file->filename;
	if (!r_bin_load (r->bin, file, 0))
		return R_FALSE;
	r->file->obj = obj = r_bin_get_object (r->bin, 0);
	baddr = r_bin_get_baddr (r->bin);
	size = r->bin->curarch.size;

	// I -> Binary info
	if ((info = r_bin_get_info (r->bin)) != NULL) {
		r_config_set (r->config, "file.type", info->rclass);
		r_config_set (r->config, "cfg.bigendian", info->big_endian?"true":"false");
		if (!strcmp (info->rclass, "fs")) {
			r_config_set (r->config, "asm.arch", info->arch);
			r_core_cmdf (r, "m %s /root 0", info->arch);
		} else {
			r_config_set (r->config, "asm.os", info->os);
			r_config_set (r->config, "asm.arch", info->arch);
			r_config_set (r->config, "anal.plugin", info->arch);
			snprintf (str, R_FLAG_NAME_SIZE, "%i", info->bits);
			r_config_set (r->config, "asm.bits", str);
			r_config_set (r->config, "asm.dwarf", R_BIN_DBG_STRIPPED (info->dbg_info)?"false":"true");
		}
	}

	// M -> Main
	r_flag_space_set (r->flags, "symbols");
	if ((binmain = r_bin_get_sym (r->bin, R_BIN_SYM_MAIN)) != NULL)
		r_flag_set (r->flags, "main", va? baddr+binmain->rva: binmain->offset,
				r->blocksize, 0);

	// e -> Entrypoints
	i = 0;
	if ((list = r_bin_get_entries (r->bin)) != NULL) {
		r_list_foreach (list, iter, entry) {
			snprintf (str, R_FLAG_NAME_SIZE, "entry%i", i++);
			r_flag_set (r->flags, str, va? baddr+entry->rva: entry->offset,
					r->blocksize, 0);
		}
		/* Seek to the last entry point */
		if (entry)
			r_core_seek (r, va? baddr+entry->rva: entry->offset, 0);
	}

	// s -> Symbols
	if ((list = r_bin_get_symbols (r->bin)) != NULL) {
		char *name, *dname;
		r_flag_space_set (r->flags, "symbols");
		r_list_foreach (list, iter, symbol) {
			name = strdup (symbol->name);
			r_name_filter (name, 80);
			snprintf (str, R_FLAG_NAME_SIZE, "sym.%s", name);
			if (!strncmp (symbol->type,"OBJECT", 6))
				r_meta_add (r->anal->meta, R_META_TYPE_DATA,
					va? baddr+symbol->rva: symbol->offset,
					(va? baddr+symbol->rva: symbol->offset)+symbol->size, name);
			r_flag_set (r->flags, str, va? baddr+symbol->rva: symbol->offset,
						symbol->size, 0);
			dname = r_bin_demangle (r->bin, symbol->name);
			if (dname) {
				r_meta_add (r->anal->meta, R_META_TYPE_COMMENT,
					va? baddr+symbol->rva: symbol->offset,
					symbol->size, dname);
				free (dname);
			}
			free (name);
		}
	}

	// R -> Relocations
	if ((list = r_bin_get_relocs (r->bin)) != NULL) {
		r_flag_space_set (r->flags, "relocs");
		r_list_foreach (list, iter, reloc) {
			snprintf (str, R_FLAG_NAME_SIZE, "reloc.%s", reloc->name);
			r_flag_set (r->flags, str, va?baddr+reloc->rva:reloc->offset,
					r->blocksize, 0);
		}
	}

	// z -> Strings
	if (r_config_get_i (r->config, "bin.strings"))
	if ((list = r_bin_get_strings (r->bin)) != NULL) {
/*
// load all strings ALWAYS!! rhashtable is fast
		if (r_list_length (list) > 102400) {
			eprintf ("rabin2: too many strings. not importing string info\n");
		} else {
*/
			r_flag_space_set (r->flags, "strings");
			r_list_foreach (list, iter, string) {
				/* Jump the withespaces before the string */
				for (i=0;*(string->string+i)==' ';i++);
				r_meta_add (r->anal->meta, R_META_TYPE_STRING, va?baddr+string->rva:string->offset,
					(va?baddr+string->rva:string->offset)+string->size, string->string+i);
				r_name_filter (string->string, 128);
				snprintf (str, R_FLAG_NAME_SIZE, "str.%s", string->string);
				r_flag_set (r->flags, str, va?baddr+string->rva:string->offset,
						string->size, 0);
			}
		//}
	}

	// i -> Imports
	if ((list = r_bin_get_imports (r->bin)) != NULL) {
		r_flag_space_set (r->flags, "imports");
		r_list_foreach (list, iter, import) {
			r_name_filter (import->name, 128);
			snprintf (str, R_FLAG_NAME_SIZE, "imp.%s", import->name);
			if (import->size)
				if (!r_anal_fcn_add (r->anal, va?baddr+import->rva:import->offset,
						import->size, str, R_ANAL_FCN_TYPE_IMP, NULL))
					eprintf ("Cannot add function: %s (duplicated)\n", import->name);
			r_flag_set (r->flags, str, va?baddr+import->rva:import->offset,
					import->size, 0);
		}
	}

	// S -> Sections
	i = 0;
	if ((list = r_bin_get_sections (r->bin)) != NULL) {
		r_flag_space_set (r->flags, "sections");
		r_list_foreach (list, iter, section) {
			r_name_filter (section->name, 128);
			snprintf (str, R_FLAG_NAME_SIZE, "section.%s", section->name);
			r_flag_set (r->flags, str, va?baddr+section->rva:section->offset,
					section->size, 0);
			r_io_section_add (r->io, section->offset, baddr+section->rva,
					section->size, section->vsize, section->srwx, section->name);
			snprintf (str, R_FLAG_NAME_SIZE, "[%i] va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"
					PFMT64d" vsz=%"PFMT64d" rwx=%c%c%c%c %s",
					i++, baddr+section->rva, section->offset, section->size, section->vsize,
					R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
					R_BIN_SCN_READABLE (section->srwx)?'r':'-',
					R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
					R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
					section->name);
			r_meta_add (r->anal->meta, R_META_TYPE_COMMENT, va?baddr+section->rva:section->offset,
					va?baddr+section->rva:section->offset, str);
		}
	}
	// H -> Header fields
	r_io_section_add (r->io, 0, baddr, size, size, 7, "ehdr");

	return R_TRUE;
}

R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int mode, ut64 loadaddr) {
	RCoreFile *fh;
	const char *cp;
	char *p;
	RIODesc *fd = r_io_open (r->io, file, mode, 0644);
	if (fd == NULL)
		return NULL;
	if (r_io_is_listener (r->io)) {
		r_core_serve (r, fd);
		return NULL;
	}

	fh = R_NEW (RCoreFile);
	fh->fd = fd;
	fh->map = NULL;
	fh->uri = strdup (file);
	fh->filename = strdup (fh->uri);
	p = strstr (fh->filename, "://");
	if (p != NULL)
		fh->filename = p+3;
	fh->rwx = mode;
	r->file = fh;
	r->io->plugin = fd->plugin;
	fh->size = r_io_size (r->io);
	r_list_append (r->files, fh);

//	r_core_bin_load (r, fh->filename);
	r_core_block_read (r, 0);
	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp)
		r_core_cmd (r, cp, 0);
	r_config_set (r->config, "file.path", file);
	r_config_set_i (r->config, "zoom.to", loadaddr+fh->size);
	fh->map = r_io_map_add (r->io, fh->fd->fd, mode, 0, loadaddr, fh->size);
	return fh;
}

R_API void r_core_file_free(RCoreFile *cf) {
	free (cf->uri);
	cf->uri = NULL;
	free (cf->filename);
	cf->filename = NULL;
	cf->fd = NULL;
}

R_API int r_core_file_close(struct r_core_t *r, struct r_core_file_t *fh) {
	int ret = r_io_close (r->io, fh->fd);
	// TODO: free fh->obj
	//r_list_delete (fh);
	//list_del (&(fh->list));
	// TODO: set previous opened file as current one
	return ret;
}

R_API RCoreFile *r_core_file_get_fd(RCore *core, int fd) {
	RCoreFile *file;
	RListIter *iter;
	r_list_foreach (core->files, iter, file) {
		if (file->fd->fd == fd)
			return file;
	}
	return NULL;
}

R_API int r_core_file_list(RCore *core) {
	int count = 0;
	RCoreFile *f;
	RListIter *iter;
	r_list_foreach (core->files, iter, f) {
		if (f->map)
			eprintf ("%c %d %s 0x%"PFMT64x"\n",
				core->io->raised == f->fd->fd?'*':' ',
				f->fd->fd, f->uri, f->map->from);
		else eprintf ("  %d %s\n", f->fd->fd, f->uri);
		count++;
	}
	return count;
}

R_API int r_core_file_close_fd(RCore *core, int fd) {
	RCoreFile *file;
	RListIter *iter;
	r_list_foreach (core->files, iter, file) {
		if (file->fd->fd == fd) {
			r_io_close (core->io, file->fd);
			r_list_delete (core->files, iter);
			if (r_list_empty (core->files))
				core->file = NULL;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_core_hash_load(RCore *r, const char *file) {
	const ut8 *buf = NULL;
	int i, buf_len = 0;
	const ut8 *md5, *sha1;
	char hash[128], *p;
	RHash *ctx;
	ut64 limit;

	limit = r_config_get_i (r->config, "cfg.hashlimit");
	if (r->file->size > limit)
		return R_FALSE;
	buf = (const ut8*)r_file_slurp (file, &buf_len);
	if (buf==NULL)
		return R_FALSE;
	ctx = r_hash_new (R_TRUE, R_HASH_MD5);
	md5 = r_hash_do_md5 (ctx, buf, buf_len);
	p = hash;
	for (i=0; i<R_HASH_SIZE_MD5; i++) {
		sprintf (p, "%02x", md5[i]);
		p+=2;
	}
	*p=0;
	r_config_set (r->config, "file.md5", hash);
	r_hash_free (ctx);
	ctx = r_hash_new (R_TRUE, R_HASH_SHA1);
	sha1 = r_hash_do_sha1 (ctx, buf, buf_len);
	p = hash;
	for (i=0; i<R_HASH_SIZE_SHA1;i++) {
		sprintf (p, "%02x", sha1[i]);
		p+=2;
	}
	*p=0;
	r_config_set (r->config, "file.sha1", hash);
	r_hash_free (ctx);
	return R_TRUE;
}
