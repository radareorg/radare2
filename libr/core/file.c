/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_core.h>
#include <stdlib.h>

R_API ut64 r_core_file_resize(struct r_core_t *core, ut64 newsize) {
	if (newsize==0 && core->file)
		return core->file->size;
	return 0LL;
}

// TODO: add support for args
R_API int r_core_file_reopen(RCore *core, const char *args, int perm) {
	char *path;
	ut64 ofrom, addr = 0; // XXX ? check file->map ?
	RCoreFile *file, *ofile = core->file;
	int newpid, ret = R_FALSE;
	if (r_sandbox_enable (0)) {
		eprintf ("Cannot reopen in sandbox\n");
		return R_FALSE;
	}
	if (!core->file) {
		eprintf ("No file opened to reopen\n");
		return R_FALSE;
	}
	newpid = core->file->fd->fd;
	if (!perm) perm = core->file->rwx;
	path = strdup (core->file->uri);
	if (r_config_get_i (core->config, "cfg.debug"))
		r_debug_kill (core->dbg, 0, R_FALSE, 9); // KILL

	// HACK: move last mapped address to higher place
	ofrom = ofile->map->from;
	ofile->map->from = UT64_MAX;

	// r_core_file_close (core, ofile);
	file = r_core_file_open (core, path, perm, addr);
	if (file) {
		eprintf ("File %s reopened in %s mode\n", path,
			perm&R_IO_WRITE?"read-write": "read-only");
		ret = R_TRUE;
		// close old file
		r_core_file_close (core, ofile);
		r_io_set_fdn (core->io, file->fd->fd);
		core->file = file;
	} else {
		// lower it down back
		ofile->map->from = ofrom;
		eprintf ("r_core_file_reopen: Cannot reopen file.\n");
		core->file = ofile; // XXX: not necessary?
	}
	// TODO: in debugger must select new PID
	if (r_config_get_i (core->config, "cfg.debug")) {
		if (core->file && core->file->fd)
			newpid = core->file->fd->fd;
		r_debug_select (core->dbg, newpid, newpid);
	}
	r_core_block_read (core, 1);
	free (path);
	return ret;
}

// NOTE: probably not all environment vars takes sesnse
// because they can be replaced by commands in the given
// command.. we should only expose the most essential and
// unidirectional ones.
R_API void r_core_sysenv_help() {
	r_cons_printf (
	"Usage: !<cmd>\n"
	"  !                       list all historic commands\n"
	"  !ls                     execute 'ls' in shell\n"
	"  !!                      save command history to hist file\n"
	"  !!ls~txt                print output of 'ls' and grep for 'txt'\n"
	"  .!rabin2 -rvi ${FILE}   run each output line as a r2 cmd\n"
	"  !echo $SIZE             display file size\n"
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
		char *f = r_sys_getenv ("BLOCK");
		if (f) {
			r_file_rm (f);
			r_sys_setenv ("BLOCK", NULL);
		}
	}
	r_sys_setenv ("BYTES", NULL);
	r_sys_setenv ("OFFSET", NULL);
}

R_API char *r_core_sysenv_begin(RCore *core, const char *cmd) {
	char buf[64], *ret, *f;
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
		if ((f = r_file_temp ("r2block"))) {
			if (r_file_dump (f, core->block, core->blocksize))
				r_sys_setenv ("BLOCK", f);
			free (f);
		}
	}
	if (strstr (cmd, "BYTES")) {
		char *s = r_hex_bin2strdup (core->block, core->blocksize);
		r_sys_setenv ("BYTES", s);
		free (s);
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

static ut64 get_base_from_maps(RCore *core, const char *file) {
	RDebugMap *map;
	RListIter *iter;
	ut64 b = 0LL;

	r_debug_map_sync (core->dbg); // update process memory maps
	r_list_foreach (core->dbg->maps, iter, map) {
		if ((map->perm & 5)==5) {
			// TODO: make this more flexible
			// XXX - why "copy/" here?
			if (map->name && strstr (map->name, "copy/")) return map->addr;
			if (map->file && !strcmp (map->file, file)) return map->addr;
			if (map->name && !strcmp (map->name, file)) return map->addr;
			// XXX - Commented out, as this could unexpected results
			//b = map->addr;
		}
	}
	return b;
}

R_API int r_core_bin_reload(RCore *r, const char *file, ut64 baseaddr) {
	int result = 0;
	result = r_core_bin_load (r, file, baseaddr);
	return result;
}

R_API int r_core_bin_load(RCore *r, const char *file, ut64 baddr) {
	int i, va = r->io->va || r->io->debug;
	ut64 loadaddr = 0;
	RListIter *iter;
	ut64 offset = 0;
	RIOMap *im;
	int is_io_load = r && r->file && r->file->fd && r->file->fd->plugin;

	if ( (file == NULL || !*file) && r->file)
		file = r->file->filename;

	if (!file) {
		eprintf ("r_core_bin_load: no file specified\n");
		return R_FALSE;
	}

	if (r->file && r->file->map) {
		loadaddr = r->file->map->from;
	}
	/* TODO: fat bins are loaded multiple times, this is a problem that must be fixed . see '-->' marks. */
	/* r_bin_select, r_bin_select_idx and r_bin_load end up loading the bin */

	//if (!r->bin->cur) r->bin->cur = R_NEW0 (RBinFile);
	//r->bin->cur->rawstr = r_config_get_i (r->config, "bin.rawstr");

	r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
	if (is_io_load) {
		// DEBUGGER
		// Fix to select pid before trying to load the binary
		if (r_config_get_i (r->config, "cfg.debug")) {
			if (r->file && r->file->fd) {
				int newpid = r->file->fd->fd;
				r_debug_select (r->dbg, newpid, newpid);
			}
			baddr = get_base_from_maps (r, file);
			r_config_set_i (r->config, "bin.baddr", baddr);
			if (baddr > 0 && r_bin_get_baddr(r->bin) == 0) r_bin_set_baddr (r->bin, baddr);
			r_core_bin_info (r, R_CORE_BIN_ACC_ALL, R_CORE_BIN_SET,
				va, NULL, baddr);
			r_bin_load (r->bin, file, baddr, loadaddr, R_FALSE);
			r_config_set_i (r->config, "io.va",
				(r->bin->cur->o->info)? r->bin->cur->o->info->has_va: 0);
			offset = r_bin_get_offset (r->bin);
		} else {
			// XXX - May need to handle additional extraction here as well
			RBinObject *_obj = NULL;
			r_io_set_fd (r->io, r->file->fd);
			r_bin_io_load (r->bin, r->io, r->file->fd, baddr, loadaddr, R_FALSE);
			if ( r->bin->cur->curplugin &&
					strncmp (r->bin->cur->curplugin->name, "any", 5)==0 ) {
				// set use of raw strings
				r_config_set (r->config, "bin.rawstr", "true");
				// get bin.minstr
				r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
			} else {
				r_bin_select (r->bin, r->assembler->cur->arch, r->assembler->bits, NULL);
			}
			// Making sure the RBinObject gets set
			_obj = r->bin->cur->o;//r_bin_get_object (r->bin);

			if (_obj && _obj->info && _obj->info->bits) {
				r_config_set_i (r->config, "asm.bits", _obj->info->bits);
				//r->file->binfile = r->bin->cur;
			}
			if (_obj) _obj->baddr = baddr;

			if (r->bin->cur && r->bin->cur->curplugin &&
				r_asm_is_valid (r->assembler, r->bin->cur->curplugin->name) ) {

				r_asm_use (r->assembler, r->bin->cur->curplugin->name);
				r_bin_select (r->bin, r->assembler->cur->arch, r->assembler->bits, NULL);
			}
		}
	} else if (r_bin_load (r->bin, file, baddr, loadaddr, R_FALSE)) { // --->
		// HEXEDITOR
		if (r->bin->narch>1 && r_config_get_i (r->config, "scr.prompt")) {
			RBinObject *o = NULL;
			eprintf ("NOTE: Fat binary found. Selected sub-bin is: -a %s -b %d\n",
				r->assembler->cur->arch, r->assembler->bits);
			eprintf ("NOTE: Use -a and -b to select sub binary in fat binary\n");
			for (i=0; i<r->bin->narch; i++) {
				r_bin_select_idx (r->bin, i); // -->
				o = r->bin->cur->o;
				if (o->info) {
					eprintf ("  $ r2 -a %s -b %d %s  # 0x%08"PFMT64x"\n",
							o->info->arch,
							o->info->bits,
							r->bin->file,
							r->bin->cur->offset);
				} else eprintf ("No extract info found.\n");
			}
			r_bin_select (r->bin, r->assembler->cur->arch,
				r->assembler->bits, NULL); // -->
		}
		/* Fix for fat bins */
		r_list_foreach (r->io->maps, iter, im) {
			if (r->bin->cur->size > 0) {
				im->delta = r->bin->cur->offset;
				im->to = im->from + r->bin->cur->size;
			}
		}
	} else if (!r_bin_load (r->bin, file, baddr, loadaddr, R_TRUE)) {
		return R_FALSE;
	}
	if (!r->file) {
		RBinObject *obj = r_bin_get_object (r->bin);
		if (obj && obj->info && obj->info->bits) {
			r_config_set_i (r->config, "asm.bits", obj->info->bits);
		}
		return R_TRUE;
	}
	//r->file->binfile = r->bin->cur;//r_bin_get_object (r->bin);
	if (baddr) r_bin_set_baddr(r->bin, baddr);
	if (r->file && r->bin && r->bin->cur) r->bin->cur->fd = r->file->fd->fd;
	if (r->bin) r_core_bin_bind (r);

	if (r->bin && r->bin->cur && r->bin->cur->o) {
		r_config_set_i (r->config, "io.va",
			(r->bin->cur->o->info)? r->bin->cur->o->info->has_va: 0);
	}
	offset = r_bin_get_offset (r->bin);
	// XXX - should this be offset, base address, or base address + offset. (referring to the last argument) 
	r_core_bin_info (r, R_CORE_BIN_ACC_ALL, R_CORE_BIN_SET, va, NULL, r_bin_get_baddr(r->bin));

	if (r->bin->cur->curplugin && !strcmp (r->bin->cur->curplugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `#sha1 $s-32 @32` @12 ; wx `#adler32 $s-12 @12` @8)\"\n");
	}

	if (r_config_get_i (r->config, "file.analyze"))
		r_core_cmd0 (r, "aa");
	return R_TRUE;
}

R_API RIOMap *r_core_file_get_next_map (RCore *core, RCoreFile * fh, int mode, ut64 loadaddr) {
	const char *loadmethod = r_config_get (core->config, "file.loadmethod");
	const char *suppress_warning = r_config_get (core->config, "file.nowarn");
	ut64 load_align = r_config_get_i (core->config, "file.loadalign");
	RIOMap *map = NULL;
	if (!strcmp (loadmethod, "overwrite"))
		map = r_io_map_new (core->io, fh->fd->fd, mode, 0, loadaddr, fh->size);
	if (!strcmp (loadmethod, "fail"))
		map = r_io_map_add (core->io, fh->fd->fd, mode, 0, loadaddr, fh->size);
	if (!strcmp (loadmethod, "append"))
		map = r_io_map_add_next_available (core->io, fh->fd->fd, mode, 0, loadaddr, fh->size, load_align);
	if (!strcmp (suppress_warning, "false")) {
		if (!map)
			eprintf ("r_core_file_get_next_map: Unable to load specified file to 0x%08"PFMT64x"\n", loadaddr);
		else {
			if (map->from != loadaddr)
				eprintf ("r_core_file_get_next_map: Unable to load specified file to 0x%08"PFMT64x",\n"
					 "but loaded to 0x%08"PFMT64x"\n", loadaddr, map->from);
		}
	}
	r_io_sort_maps (core->io);				//necessary ???
	return map;
}


R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int mode, ut64 loadaddr) {
	RList *list_fds = NULL;
	list_fds = r_io_open_many (r->io, file, mode, 0644);
	RCoreFile *fh, *top_file = NULL;
	RIODesc *fd;
	RListIter *fd_iter;
	ut64 current_loadaddr = loadaddr;
	const char *suppress_warning = r_config_get (r->config, "file.nowarn");

	const char *cp = NULL;
	char *loadmethod = NULL;

	if (!list_fds || r_list_length (list_fds) == 0 ) {
		r_list_free (list_fds);
		return NULL;
	}

	cp = r_config_get (r->config, "file.loadmethod");
	if (cp) loadmethod = strdup (cp);
	r_config_set (r->config, "file.loadmethod", "append");

	r_list_foreach (list_fds, fd_iter, fd) {
		fh = R_NEW0 (RCoreFile);

		if (!fh) {
			eprintf ("file.c:r_core_many failed to allocate new RCoreFile.\n");
			break;
		}
		fh->uri = strdup (file);
		fh->fd = fd;
		fh->size = r_io_desc_size (r->io, fd);
		fh->filename = strdup (fd->name);
		fh->rwx = mode;
		r->file = fh;
		r->io->plugin = fd->plugin;
		fh->size = r_io_size (r->io);
		// XXX - load addr should be at a set offset
		fh->map = r_core_file_get_next_map (r, fh, mode, current_loadaddr);

		if (!fh->map) {
			r_core_file_free(fh);
			if (!strcmp (suppress_warning, "false"))
				eprintf("Unable to load file due to failed mapping.\n");
			continue;
		}

		current_loadaddr = fh->map->to;
		if (!top_file) {
			top_file = fh;
			// check load addr to make sure its still valid
			loadaddr =  top_file->map->from;
		}
		r_list_append (r->files, fh);
		r_core_bin_load (r, fh->filename, fh->map->from);
	}
	if (!top_file) {
		free (loadmethod);
		return top_file;
	}
	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp) r_core_cmd (r, cp, 0);

	r_config_set (r->config, "file.path", top_file->filename);
	r_config_set_i (r->config, "zoom.to", top_file->map->from+top_file->size);
	if (loadmethod) r_config_set (r->config, "file.loadmethod", loadmethod);
	free (loadmethod);

	return top_file;
}

R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int mode, ut64 loadaddr) {
	const char *cp;
	RCoreFile *fh;
	RIODesc *fd;
	const char *suppress_warning = r_config_get (r->config, "file.nowarn");

	if (!strcmp (file, "-")) {
		file = "malloc://512";
		mode = 4|2;
	}
	r->io->bits = r->assembler->bits; // TODO: we need an api for this
	fd = r_io_open (r->io, file, mode, 0644);
	if (fd == NULL) {
		// XXX - make this an actual option somewhere?
		fh = r_core_file_open_many (r, file, mode, loadaddr);
		if (fh) return fh;
	}
	if (fd == NULL) {
		if (mode & 2) {
			if (!r_io_create (r->io, file, 0644, 0))
				return NULL;
			if (!(fd = r_io_open (r->io, file, mode, 0644)))
				return NULL;
		} else return NULL;
	}
	if (r_io_is_listener (r->io)) {
		r_core_serve (r, fd);
		return NULL;
	}

	fh = R_NEW0 (RCoreFile);
	if (!fh) {
		eprintf ("file.c:r_core_open failed to allocate RCoreFile.\n");
		//r_io_close (r->io, fd);
		return NULL;
	}
	fh->uri = strdup (file);
	fh->fd = fd;
	fh->size = r_io_desc_size (r->io, fd);
	fh->filename = strdup (fd->name);
	fh->rwx = mode;
	fh->size = r_io_size (r->io);

	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp)
		r_core_cmd (r, cp, 0);
	r_config_set (r->config, "file.path", file);
	fh->map = r_core_file_get_next_map (r, fh, mode, loadaddr);
	if (!fh->map) {
		r_core_file_free (fh);
		fh = NULL;
		if (!strcmp (suppress_warning, "false"))
			eprintf("Unable to load file due to failed mapping.\n");
		return NULL;
	}
	// check load addr to make sure its still valid
	r_list_append (r->files, fh);
	r->file = fh;
	r->io->plugin = fd->plugin;

	r_config_set_i (r->config, "zoom.to", fh->map->from+fh->size);
	return fh;
}

R_API RCoreFile * r_core_file_find_by_fd(RCore* core, int fd){
	RCoreFile *result = NULL, *cf = NULL;
	RListIter *iter;

	if (!core || !core->files)
		return result;

	r_list_foreach (core->files, iter, cf) {
		if (cf && cf->fd->fd == fd) {
			result = cf;
			break;
		}
	}
	return cf;
}

R_API void r_core_file_free(RCoreFile *cf) {
	if (cf) {
		// double free libr/io/io.c:70 performs free
		//if (cf->map) free(cf->map);
		free (cf->filename);
		free (cf->uri);
// XXX: already done by someone else :)
		r_io_desc_free (cf->fd);
		cf->fd = NULL;
		cf->map = NULL;
		cf->filename = NULL;
		cf->uri = NULL;
// XXX avoid segfault
		free (cf);
	}
	cf = NULL;
}

R_API int r_core_file_close(RCore *r, RCoreFile *fh) {
	int ret = (fh&&r)? r_io_close (r->io, fh->fd): 0;
	// TODO: free fh->obj
	if (fh) r_list_delete_data (r->files, fh);
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
			r_cons_printf ("%c %d %s @ 0x%"PFMT64x" ; %s\n",
				core->io->raised == f->fd->fd?'*':'-',
				f->fd->fd, f->uri, f->map->from,
				f->fd->flags & R_IO_WRITE? "rw": "r");
		else r_cons_printf ("- %d %s\n", f->fd->fd, f->uri);
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
			//r_io_raise (core->io, fd);
#if 0
			if (r_list_empty (core->files))
				core->file = NULL;
#endif
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_core_hash_load(RCore *r, const char *file) {
	const ut8 *md5, *sha1;
	char hash[128], *p;
	int i, buf_len = 0;
	ut8 *buf = NULL;
	RHash *ctx;
	ut64 limit;

	limit = r_config_get_i (r->config, "cfg.hashlimit");
	if (r->file->size > limit)
		return R_FALSE;
	buf = (ut8*)r_file_slurp (file, &buf_len);
	if (buf==NULL)
		return R_FALSE;
	ctx = r_hash_new (R_TRUE, R_HASH_MD5);
	md5 = r_hash_do_md5 (ctx, buf, buf_len);
	p = hash;
	for (i=0; i<R_HASH_SIZE_MD5; i++) {
		sprintf (p, "%02x", md5[i]);
		p += 2;
	}
	*p = 0;
	r_config_set (r->config, "file.md5", hash);
	r_hash_free (ctx);
	ctx = r_hash_new (R_TRUE, R_HASH_SHA1);
	sha1 = r_hash_do_sha1 (ctx, buf, buf_len);
	p = hash;
	for (i=0; i<R_HASH_SIZE_SHA1; i++) {
		sprintf (p, "%02x", sha1[i]);
		p += 2;
	}
	*p = 0;
	r_config_set (r->config, "file.sha1", hash);
	r_hash_free (ctx);
	free (buf);
	return R_TRUE;
}
