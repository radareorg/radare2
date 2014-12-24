/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_core.h>
#include <stdlib.h>


static int r_core_file_do_load_for_debug (RCore *r, ut64 loadaddr, const char *filenameuri);
static int r_core_file_do_load_for_io_plugin (RCore *r, ut64 baseaddr, ut64 loadaddr);
// After June 2014, if no problems delete r_core_file_do_load_for_hex
//static int r_core_file_do_load_for_hex (RCore *r, ut64 baddr, ut64 loadaddr, const char *filenameuri);


// TODO: add support for args
R_API int r_core_file_reopen(RCore *core, const char *args, int perm, int loadbin) {
	int isdebug = r_config_get_i (core->config, "cfg.debug");
	char *path;
	ut64 ofrom = 0, baddr = 0; // XXX ? check file->map ?
	RCoreFile *file = NULL;
	RCoreFile *ofile = core->file;
	RBinFile *bf = (ofile && ofile->desc) ?
		r_bin_file_find_by_fd (core->bin, ofile->desc->fd) : NULL;
	RIODesc *odesc = ofile ? ofile->desc : NULL;
	char *ofilepath = NULL, *obinfilepath = bf ? strdup (bf->file) : NULL;
	int newpid, ret = R_FALSE;
	ut64 origoff = core->offset;
	if (odesc) {
		if (odesc->referer) {
			ofilepath = odesc->referer;
		} else if (odesc->uri) {
			ofilepath = odesc->uri;
		}
	}

	if (r_sandbox_enable (0)) {
		eprintf ("Cannot reopen in sandbox\n");
		return R_FALSE;
	}
#if 0
	if (isdebug) {
		// if its in debugger mode we have to respawn a new process
		// instead of reattaching
		free (ofilepath);
		ofilepath = r_str_newf ("dbg://%s", odesc->name);
	}
#endif
	if (!core->file) {
		eprintf ("No file opened to reopen\n");
		free (ofilepath);
		free (obinfilepath);
		return R_FALSE;
	}
	newpid = odesc ? odesc->fd : -1;

	if (isdebug) {
		r_debug_kill (core->dbg, core->dbg->pid,
			core->dbg->tid, 9); // KILL
		perm = 7;
	} else {
		if (!perm) {
			perm = 4; //R_IO_READ;
		}
	}
	if (!ofilepath) {
		eprintf ("Unknown file path");
		return R_FALSE;
	}

	// HACK: move last mapped address to higher place
	// XXX - why does this hack work?
	if (ofile->map) {
		ofrom = ofile->map->from;
		ofile->map->from = UT32_MAX;
	}
	// closing the file to make sure there are no collisions
	// when the new memory maps are created.
	path = strdup (ofilepath);
	obinfilepath = strdup(ofilepath);

	file = r_core_file_open (core, path, perm, baddr);
	if (file) {
		int had_rbin_info = 0;
		ofile->map->from = ofrom;
		if (r_bin_file_delete (core->bin, ofile->desc->fd)) {
			had_rbin_info = 1;
		}
		r_core_file_close (core, ofile);
		r_core_file_set_by_file (core, file);
		r_core_file_set_by_fd (core, file->desc->fd);
		ofile = NULL;
		odesc = NULL;
	//	core->file = file;
		eprintf ("File %s reopened in %s mode\n", path,
			(perm&R_IO_WRITE)? "read-write": "read-only");

		if (loadbin && (loadbin==2 || had_rbin_info)) {
			ret = r_core_bin_load (core, obinfilepath, baddr);
			if (!ret) {
				eprintf ("Error: Failed to reload rbin for: %s", path);
			}
		}

		/*
		if (core->bin->cur && file->desc) {
			core->bin->cur->fd = file->desc->fd;
			ret = R_TRUE;
		}*/
		// close old file
	} else if (ofile) {
		eprintf ("r_core_file_reopen: Cannot reopen file: %s with perms 0x%04x,"
			     " attempting to open read-only.\n", path, perm);
		// lower it down back
		//ofile = r_core_file_open (core, path, R_IO_READ, addr);
		r_core_file_set_by_file (core, ofile);
		ofile->map->from = ofrom;
	} else {
		eprintf ("Cannot reopen\n");
	}
	if (isdebug) {
		// XXX - select the right backend
		if (core->file && core->file->desc)
			newpid = core->file->desc->fd;
		r_core_setup_debugger (core, "native");
		r_debug_select (core->dbg, newpid, newpid);
	}

	if (core->file) {
		RCoreFile * cf = core->file;
		RIODesc *desc = cf ? cf->desc : NULL;
		if (desc) {
#if 0
			r_io_raise (core->io, desc->fd);
			core->switch_file_view = 1;
#endif
			r_core_block_read (core, 0);
		} else {
			const char *name = (cf && cf->desc) ? cf->desc->name : "ERROR";
			eprintf ("Error: Unable to switch the view to file: %s\n", name);
		}
	}
	r_core_seek (core, origoff, 1);
	if (isdebug) {
		r_core_cmd0 (core, ".dr*");
		r_core_cmd0 (core, "sr pc");
	}
	// This is done to ensure that the file is correctly
	// loaded into the view
	free (obinfilepath);
	//free (ofilepath);
	free (path);
	return ret;
}

// NOTE: probably not all environment vars takes sesnse
// because they can be replaced by commands in the given
// command.. we should only expose the most essential and
// unidirectional ones.
R_API void r_core_sysenv_help(const RCore* core) {
	const char* help_msg[] = {
	"Usage:", "!<cmd>", "Run given command as in system(3)",
	"!", "", "list all historic commands",
	"!", "ls", "execute 'ls' in shell",
	"!!", "", "save command history to hist file",
	"!!", "ls~txt", "print output of 'ls' and grep for 'txt'",
	".!", "rabin2 -rpsei ${FILE}", "run each output line as a r2 cmd",
	"!", "echo $SIZE", "display file size",
	"\nEnvironment:", "", "",
	"FILE", "", "file name",
	"SIZE", "","file size",
	"OFFSET", "", "10base offset 64bit value",
	"XOFFSET", "", "same as above, but in 16 base",
	"BSIZE", "", "block size",
	"ENDIAN", "", "'big' or 'little'",
	"ARCH", "", "value of asm.arch",
	"DEBUG", "", "debug mode enabled? (1,0)",
	"IOVA", "", "is io.va true? virtual addressing (1,0)",
	"BLOCK", "", "TODO: dump current block to tmp file", 
	"BYTES", "", "TODO: variable with bytes in curblock",
	"PDB_SERVER", "", "e pdb.server",
	NULL
	};
	r_core_cmd_help (core, help_msg);
}

R_API void r_core_sysenv_end(RCore *core, const char *cmd) {
	// TODO: remove tmpfilez
	if (strstr (cmd, "BLOCK")) {
		// remove temporary BLOCK file
		char *f = r_sys_getenv ("BLOCK");
		if (f) {
			r_file_rm (f);
			r_sys_setenv ("BLOCK", NULL);
			free (f);
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
	ret = strdup (cmd);
	if (strstr (cmd, "BYTES")) {
		char *s = r_hex_bin2strdup (core->block, core->blocksize);
		r_sys_setenv ("BYTES", s);
		free (s);
	}
	r_sys_setenv ("PDB_SERVER", r_config_get (core->config, "pdb.server"));
	if (core->file && core->file->desc && core->file->desc->name) {
		r_sys_setenv ("FILE", core->file->desc->name);
		snprintf (buf, sizeof (buf), "%"PFMT64d, r_io_desc_size (core->io, core->file->desc));
		r_sys_setenv ("SIZE", buf);
		if (strstr (cmd, "BLOCK")) {
			// replace BLOCK in RET string
			if ((f = r_file_temp ("r2block"))) {
				if (r_file_dump (f, core->block, core->blocksize))
					r_sys_setenv ("BLOCK", f);
				free (f);
			}
		}
	}
	snprintf (buf, sizeof (buf), "%"PFMT64d, core->offset);
	r_sys_setenv ("OFFSET", buf);
	snprintf (buf, sizeof (buf), "0x%08"PFMT64x, core->offset);
	r_sys_setenv ("XOFFSET", buf);
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
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? cf->desc : NULL;
	RBinFile *bf = NULL;

	if (desc) result = r_bin_reload (r->bin, desc, baseaddr);
	bf = r_bin_cur (r->bin);
	r_core_bin_set_env (r, bf);
	return result;
}

// XXX - need to handle index selection during debugging
static int r_core_file_do_load_for_debug (RCore *r, ut64 loadaddr, const char *filenameuri) {
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? cf->desc : NULL;
	RBinFile *binfile = NULL;
	RBinPlugin *plugin;
	ut64 baseaddr = 0;
	//int va = r->io->va || r->io->debug;
	int xtr_idx = 0; // if 0, load all if xtr is used
	int treat_as_rawstr = R_FALSE;

	if (!desc) return R_FALSE;
	if (cf && desc) {
		int newpid = desc->fd;
		r_debug_select (r->dbg, newpid, newpid);
	}
	baseaddr = get_base_from_maps (r, filenameuri);
	if (baseaddr != UT64_MAX) {
		// eprintf ("LOADING AT 0x%08llx\n", baseaddr);
		r_config_set_i (r->config, "bin.laddr", baseaddr);
	}

	if (!r_bin_load (r->bin, filenameuri, baseaddr, loadaddr, xtr_idx, desc->fd, treat_as_rawstr)) {
		if (r_config_get_i (r->config, "bin.rawstr")) {
			treat_as_rawstr = R_TRUE;
			if (!r_bin_load (r->bin, filenameuri, baseaddr, loadaddr, xtr_idx, desc->fd, treat_as_rawstr)) {
				return R_FALSE;
			}
		}
	}

	binfile = r_bin_cur (r->bin);
	r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if ( plugin && strncmp (plugin->name, "any", 5)==0 ) {
		// set use of raw strings
		r_config_set_i (r->config, "io.va", 0);
		//\\ r_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
	} else if (binfile) {
		RBinObject *obj = r_bin_get_object (r->bin);
		RBinInfo * info = obj ? obj->info : NULL;
		if (plugin && strcmp (plugin->name, "any") && info) {
			r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
		}
	}

	if (plugin && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `#sha1 $s-32 @32` @12 ; wx `#adler32 $s-12 @12` @8)\"\n");
	}

	if (r_config_get_i (r->config, "file.analyze")) r_core_cmd0 (r, "aa");
	return R_TRUE;
}

static int r_core_file_do_load_for_io_plugin (RCore *r, ut64 baseaddr, ut64 loadaddr) {
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? cf->desc : NULL;
	RBinFile *binfile = NULL;
	int xtr_idx = 0; // if 0, load all if xtr is used
	RBinPlugin * plugin;

	if (!desc) return R_FALSE;
	r_io_use_desc (r->io, desc);
	if ( !r_bin_load_io (r->bin, desc, baseaddr, loadaddr, xtr_idx)) {
		//eprintf ("Failed to load the bin with an IO Plugin.\n");
		return R_FALSE;
	}
	binfile = r_bin_cur (r->bin);
	r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if ( plugin && strncmp (plugin->name, "any", 5)==0 ) {
		// set use of raw strings
		r_config_set_i (r->config, "io.va", 0);
		// r_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
	} else if (binfile) {
		RBinObject *obj = r_bin_get_object (r->bin);
		RBinInfo * info = obj ? obj->info : NULL;
		if (plugin && strcmp (plugin->name, "any") && info) {
			r_core_bin_set_arch_bits (r, binfile->file,
				info->arch, info->bits);
		} else {
			r_config_set_i (r->config, "io.va", 0);
		}
	}

	if (plugin && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `#sha1 $s-32 @32` @12 ; wx `#adler32 $s-12 @12` @8)\"\n");
	}

	if (r_config_get_i (r->config, "file.analyze"))
		r_core_cmd0 (r, "aa");
	return R_TRUE;
}

#if 0
// XXX - remove this code after June 2014, because current code setup is sufficient
static int r_core_file_do_load_for_hex (RCore *r, ut64 baddr, ut64 loadaddr, const char *filenameuri) {
	// HEXEDITOR
	RBinFile * binfile = NULL;
	ut64 fd = r_core_file_cur_fd (r);
	int i = 0;
	int xtr_idx = 0; // if 0, load all if xtr is used
	int treat_as_rawstr = R_FALSE;

	if (!r_bin_load (r->bin, filenameuri, baddr, loadaddr, xtr_idx, fd, treat_as_rawstr)) {
		treat_as_rawstr = R_TRUE;
		if (!r_bin_load (r->bin, filenameuri, baddr, loadaddr, xtr_idx, fd, treat_as_rawstr))
			return R_FALSE;
	}

	binfile = r_core_bin_cur (r);
	if (binfile) {
		r_core_bin_bind (r, binfile);
	}

	// binary files should be treated as views into a file
	// not the actual file
	/*
	{
		RListIter *iter;
		RIOMap *im;

		r_list_foreach (r->io->maps, iter, im) {
			if (binfile->size > 0) {
				im->delta = binfile->offset;
				im->to = im->from + binfile->size;
			}
		}
	}*/

	if (binfile->narch>1 && r_config_get_i (r->config, "scr.prompt")) {
		int narch = binfile->narch;
		eprintf ("NOTE: Fat binary found. Selected sub-bin is: -a %s -b %d\n",
					r->assembler->cur->arch, r->assembler->bits);
		eprintf ("NOTE: Use -a and -b to select sub binary in fat binary\n");

		for (i=0; i<narch; i++) {
			RBinFile *lbinfile = r_bin_file_find_by_name_n (r->bin, binfile->file, i);
			RBinObject *lbinobj = lbinfile ? lbinfile->o : NULL;
			if (lbinobj && lbinobj->info) {
				eprintf ("  $ r2 -a %s -b %d %s  # 0x%08"PFMT64x"\n",
						lbinobj->info->arch,
						lbinobj->info->bits,
						binfile->file,
						lbinobj->boffset);
			} else eprintf ("No extract info found.\n");
		}
	}

	return R_TRUE;
}
#endif

R_API int r_core_bin_load(RCore *r, const char *filenameuri, ut64 baddr) {
	const char *suppress_warning = r_config_get (r->config, "file.nowarn");
	ut64 loadaddr = 0;
	RCoreFile *cf = r_core_file_cur (r);
	RBinFile *binfile = NULL;
	RIODesc *desc = cf ? cf->desc : NULL;
	RBinPlugin *plugin = NULL;

	int is_io_load = desc && desc->plugin;

	if (cf) {
		if ((filenameuri == NULL || !*filenameuri))
			filenameuri = cf->desc->name;
		else if (cf->desc->name && strcmp (filenameuri, cf->desc->name) ) {
			// XXX - this needs to be handled appropriately
			// if the cf does not match the filenameuri then
			// either that RCoreFIle * needs to be loaded or a
			// new RCoreFile * should be opened.
			if (!strcmp (suppress_warning, "false"))
				eprintf ("Error: The filenameuri %s is not the same as the current RCoreFile: %s\n",
				    filenameuri, cf->desc->name);
		}
		if (cf->map)	//XXX: a file can have more then 1 map
			loadaddr = cf->map->from;
	}

	if (!filenameuri) {
		eprintf ("r_core_bin_load: no file specified\n");
		return R_FALSE;
	}

	r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
	if (is_io_load) {
		// TODO? necessary to restore the desc back?
		// RIODesc *oldesc = desc;
		// Fix to select pid before trying to load the binary
		if ( (desc->plugin && desc->plugin->isdbg) \
				|| r_config_get_i (r->config, "cfg.debug")) {
			r_core_file_do_load_for_debug (r, loadaddr, filenameuri);
		} else {
			r_core_file_do_load_for_io_plugin (r, baddr, loadaddr);
		}
		// Restore original desc
		r_io_use_desc (r->io, desc);
	}

	if (cf && binfile && desc)
		binfile->fd = desc->fd;
	binfile = r_bin_cur (r->bin);
	r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->name && !strncmp (plugin->name, "any", 3)) {
		// set use of raw strings
		//r_config_set (r->config, "bin.rawstr", "true");
		r_config_set_i (r->config, "io.va", 0);
		// get bin.minstr
		r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
	} else if (binfile) {
		RBinObject *obj = r_bin_get_object (r->bin);
		RBinInfo * info = obj ? obj->info : NULL;
		if (plugin && plugin->name)
			if (strcmp (plugin->name, "any") && info)
				r_core_bin_set_arch_bits (r, binfile->file,
					info->arch, info->bits);
	}

	if (plugin && plugin->name && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `#sha1 $s-32 @32` @12 ;"
			" wx `#adler32 $s-12 @12` @8)\"\n");
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
		map = r_io_map_new (core->io, fh->desc->fd, mode, 0, loadaddr, r_io_desc_size (core->io, fh->desc));
	if (!strcmp (loadmethod, "fail"))
		map = r_io_map_add (core->io, fh->desc->fd, mode, 0, loadaddr, r_io_desc_size (core->io, fh->desc));
	if (!strcmp (loadmethod, "append") && load_align) {
		map = r_io_map_add_next_available (core->io, fh->desc->fd, mode, 0, loadaddr, r_io_desc_size (core->io, fh->desc), load_align);
	}
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


R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int flags, ut64 loadaddr) {
	RIODesc *fd;
	RList *list_fds = NULL;
	const char *cp = NULL;
	char *loadmethod = NULL;
	RListIter *fd_iter, *iter2;
	RCoreFile *fh, *top_file = NULL;
	ut64 current_loadaddr = loadaddr;
	const char *suppress_warning = r_config_get (r->config, "file.nowarn");
	int openmany = r_config_get_i (r->config, "file.openmany"), opened_count = 0;


	list_fds = r_io_open_many (r->io, file, flags, 0644);

	if (!list_fds || r_list_length (list_fds) == 0 ) {
		r_list_free (list_fds);
		return NULL;
	}

	cp = r_config_get (r->config, "file.loadmethod");
	if (cp) loadmethod = strdup (cp);
	r_config_set (r->config, "file.loadmethod", "append");

	r_list_foreach_safe (list_fds, fd_iter, iter2, fd) {
		opened_count++;
		if (opened_count > openmany) {
			// XXX - Open Many should limit the number of files
			// loaded in io plugin area this needs to be more premptive
			// like down in the io plugin layer.
			// start closing down descriptors
			r_list_delete (list_fds, fd_iter);
			continue;
		}
		fh = R_NEW0 (RCoreFile);
		if (!fh) {
			eprintf ("file.c:r_core_many failed to allocate new RCoreFile.\n");
			break;
		}
		fh->alive = 1;
		fh->core = r;
		fh->desc = fd;
		r->file = fh;
		r->io->plugin = fd->plugin;
		// XXX - load addr should be at a set offset
		fh->map = r_core_file_get_next_map (r, fh, flags, current_loadaddr);

		if (!fh->map) {
			r_core_file_free (fh);
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
		r_bin_bind (r->bin, &(fh->binb));
		r_list_append (r->files, fh);
		r_core_bin_load (r, fh->desc->name, fh->map->from);
	}
	if (!top_file) {
		free (loadmethod);
		return top_file;
	}
	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp) r_core_cmd (r, cp, 0);

	r_config_set (r->config, "file.path", top_file->desc->name);
	r_config_set_i (r->config, "zoom.to", top_file->map->from + r_io_desc_size (r->io, top_file->desc));
	if (loadmethod) r_config_set (r->config, "file.loadmethod", loadmethod);
	free (loadmethod);

	return top_file;
}

R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int flags, ut64 loadaddr) {
	const char *suppress_warning = r_config_get (r->config, "file.nowarn");
	const int openmany = r_config_get_i (r->config, "file.openmany");
	const char *cp;
	RCoreFile *fh;
	RIODesc *fd;

	if (!file)
		return NULL;
	if (!strcmp (file, "-")) {
		file = "malloc://512";
		flags = 4|2;
	}
	r->io->bits = r->assembler->bits; // TODO: we need an api for this
	fd = r_io_open_nomap (r->io, file, flags, 0644);
	if (fd == NULL && openmany > 2) {
		// XXX - make this an actual option somewhere?
		fh = r_core_file_open_many (r, file, flags, loadaddr);
		if (fh) return fh;
	}
	if (fd == NULL) {
		if (flags & 2) {
			if (!r_io_create (r->io, file, 0644, 0))
				return NULL;
			if (!(fd = r_io_open_nomap (r->io, file, flags, 0644)))
				return NULL;
		} else return NULL;
	}
	if (r_io_is_listener (r->io)) {
		r_core_serve (r, fd);
		return NULL;
	}

	fh = R_NEW0 (RCoreFile);
	if (!fh) {
		eprintf ("core/file.c: r_core_open failed to allocate RCoreFile.\n");
		//r_io_close (r->io, fd);
		return NULL;
	}
	fh->alive = 1;
	fh->core = r;
	fh->desc = fd;

	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp)
		r_core_cmd (r, cp, 0);
	r_config_set (r->config, "file.path", file);
	fh->map = r_core_file_get_next_map (r, fh, flags, loadaddr);
	if (!fh->map) {
		r_core_file_free (fh);
		fh = NULL;
		if (!strcmp (suppress_warning, "false"))
			eprintf("Unable to load file due to failed mapping.\n");
		return NULL;
	}
	// check load addr to make sure its still valid
	r_bin_bind (r->bin, &(fh->binb));
	r_list_append (r->files, fh);
	r_core_file_set_by_file (r, fh);
	r_config_set_i (r->config, "zoom.to", fh->map->from + r_io_desc_size (r->io, fh->desc));
	return fh;
}

R_API int r_core_files_free (const RCore *core, RCoreFile *cf) {
	if (!core || !core->files || !cf) return R_FALSE;
	return r_list_delete_data (core->files, cf);
}

R_API void r_core_file_free(RCoreFile *cf) {
	int res = 1;
	if (!cf || !cf->core)
		return;
	if (cf) {
		res = r_core_files_free (cf->core, cf);
	}
	//if (!res && cf && cf->alive) {
	if (res && cf && cf->alive) {
		// double free libr/io/io.c:70 performs free
		RIO *io = NULL;
		if (cf) {
			io = (RIO*)(cf->desc ? cf->desc->io : NULL);
			if (cf->map) {
				r_io_map_del_all (io, cf->map->fd);
				cf->map = NULL;
			}
			r_bin_file_deref_by_bind (&cf->binb);
			r_io_close ((RIO *) io, cf->desc);
			free (cf);
		}
	}
	cf = NULL;
}

R_API int r_core_file_close(RCore *r, RCoreFile *fh) {
	int ret;
	RIODesc *desc = fh && fh->desc? fh->desc : NULL;
	RCoreFile *prev_cf = r && r->file != fh ? r->file : NULL;

	// TODO: This is not correclty done. because map and iodesc are 
	// still referenced // we need to fully clear all R_IO structs
	// related to a file as well as the ones needed for RBin.
	//
	// XXX -these checks are intended to *try* and catch
	// stale objects.  Unfortunately, if the file handle
	// (fh) is stale and freed, and there is more than 1
	// fh in the r->files list, we are hosed. (design flaw)
	// TODO maybe using sdb to keep track of the allocated and
	// deallocated files might be a good solutions
	if (!r || !desc || r_list_empty (r->files))
		return R_FALSE;

	if (fh == r->file) r->file = NULL;

	r_core_file_set_by_fd (r, fh->desc->fd);
	r_core_bin_set_by_fd (r, fh->desc->fd);

	/* delete filedescriptor from io descs here */
	r_io_desc_del (r->io, fh->desc->fd);

	// AVOID DOUBLE FREE HERE
	r->files->free = NULL;

	ret = r_list_delete_data (r->files, fh);
	if (ret) {
		if (!prev_cf && r_list_length (r->files) > 0)
			prev_cf = (RCoreFile *) r_list_get_n (r->files, 0);

		if (prev_cf) {
			RIODesc *desc = prev_cf->desc;
			if (!desc)
				eprintf ("Error: RCoreFile's found with out a supporting RIODesc.\n");
			ret = r_core_file_set_by_file (r, prev_cf);
		}
	}
#if 0
	{
		RListIter *iter;
		RIODesc *iod;
		RCoreFile *mcf;
		r_list_foreach (r->files, iter, mcf) {
			r_cons_printf ("[cf]--> %p %p %d\n", mcf, mcf->desc, mcf->desc->fd);
		}
		r_list_foreach (r->io->files, iter, iod) {
			r_cons_printf ("[io]--> %p %d\n", iod, iod->fd);
		}
	}
#endif
	return ret;
}

R_API RCoreFile *r_core_file_get_by_fd(RCore *core, int fd) {
	RCoreFile *file;
	RListIter *iter;
	r_list_foreach (core->files, iter, file) {
		if (file->desc->fd == fd)
			return file;
	}
	return NULL;
}

R_API int r_core_file_list(RCore *core, int mode) {
	int overlapped, count = 0;
	RCoreFile *f;
	ut64 from;
	RListIter *iter;
	if (mode=='j')
		r_cons_printf ("[");
	r_list_foreach (core->files, iter, f) {
		if (f->map) {
			from = f->map->from;
			overlapped = r_io_map_overlaps (core->io, f->desc, f->map);
		} else {
			from = 0LL;
			overlapped = R_FALSE;
		}
		switch (mode) {
		case 'j':
			r_cons_printf ("{\"raised\":%s,\"fd\":%d,\"uri\":\"%s\",\"from\":%"
				PFMT64d",\"writable\":%s,\"size\":%d,\"overlaps\":%s}%s",
				core->io->raised == f->desc->fd?"true":"false",
				f->desc->fd, f->desc->uri, from,
				f->desc->flags & R_IO_WRITE? "true": "false",
				r_io_desc_size (core->io, f->desc),
				overlapped?"true":"false",
				iter->n? ",":"");
			break;
		case '*':
		case 'r':
			r_cons_printf ("o %s 0x%llx\n", f->desc->uri, from);
			break;
		default:
			r_cons_printf ("%c %d %s @ 0x%"PFMT64x" ; %s size=%d %s\n",
					core->io->raised == f->desc->fd?'*':'-',
					f->desc->fd, f->desc->uri, from,
					f->desc->flags & R_IO_WRITE? "rw": "r",
					r_io_desc_size (core->io, f->desc),
					overlapped?"overlaps":"");
			break;
		}
		count++;
	}
	if (mode=='j')
		r_cons_printf ("]\n");
	return count;
}

// XXX - needs to account for binfile index and bin object index
R_API int r_core_file_bin_raise (RCore *core, ut32 binfile_idx) {
	RBin *bin = core->bin;
	int v = binfile_idx > 1 ? binfile_idx : 1;
	RBinFile *bf = r_list_get_n (bin->binfiles, v);
	int res = R_FALSE;
	if (bf) {
		res = r_bin_file_set_cur_binfile (bin, bf);
		if (res) r_io_raise (core->io, bf->fd);
		res = res ? r_core_file_set_by_fd (core, bf->fd) : res;
		if (res) core->switch_file_view = 1;
	}
	return res;
}

R_API int r_core_file_binlist(RCore *core) {
	int count = 0;
	RListIter *iter;
	RCoreFile *cur_cf = core->file, *cf = NULL;
	RBinFile *binfile = NULL;
	RBin *bin = core->bin;
	const RList *binfiles = bin ? bin->binfiles: NULL;

	if (!binfiles) return R_FALSE;

	r_list_foreach (binfiles, iter, binfile) {
		int fd = binfile->fd;
		cf = r_core_file_get_by_fd (core, fd);
		if (cf && cf->map) {
			r_cons_printf ("%c %d %s @ 0x%"PFMT64x" ; %s\n",
				core->io->raised == cf->desc->fd?'*':'-',
				fd, cf->desc->uri, cf->map->from,
				cf->desc->flags & R_IO_WRITE? "rw": "r");
		}
	}
	r_core_file_set_by_file (core, cur_cf);
	//r_core_bin_bind (core, cur_bf);
	return count;
}

R_API int r_core_file_close_fd(RCore *core, int fd) {
	RCoreFile *file;
	RListIter *iter;
	r_list_foreach (core->files, iter, file) {
		if (file->desc->fd == fd) {
			r_core_file_close (core, file);
			if (file == core->file) {
				core->file = NULL; // deref
			}
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
	int i;
	int buf_len = 0;
	ut8 *buf = NULL;
	RHash *ctx;
	ut64 limit;
	RCoreFile *cf = r_core_file_cur (r);

	limit = r_config_get_i (r->config, "cfg.hashlimit");
	if (r_io_desc_size (r->io, cf->desc) > limit)
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

R_API RCoreFile * r_core_file_find_by_fd (RCore *core, ut64 fd) {
	RListIter *iter;
	RCoreFile *cf = NULL;

	r_list_foreach (core->files, iter, cf) {
		if (cf && cf->desc && cf->desc->fd == fd) break;
		cf = NULL;
	}
	return cf;
}

R_API RCoreFile * r_core_file_find_by_name (RCore * core, const char * name) {
	RListIter *iter;
	RCoreFile *cf = NULL;

	r_list_foreach (core->files, iter, cf) {
		if (cf && cf->desc && !strcmp (cf->desc->name, name)) break;
		cf = NULL;
	}
	return cf;
}

R_API int r_core_file_set_by_fd (RCore * core, ut64 fd) {
	RCoreFile *cf = r_core_file_find_by_fd (core, fd);
	return r_core_file_set_by_file (core, cf);
}

R_API int r_core_file_set_by_name (RCore * core, const char * name) {
	RCoreFile *cf = r_core_file_find_by_name (core, name);
	return r_core_file_set_by_file (core, cf);
}

R_API int r_core_file_set_by_file (RCore * core, RCoreFile *cf) {
	if (cf) {
		RIODesc *desc = cf->desc;
		core->offset = cf && cf->map ? cf->map->from : 0LL;
		core->file = cf;
		if (desc) {
			r_io_use_desc (core->io, desc);
			r_core_bin_set_by_fd (core, desc->fd);
		}
		return R_TRUE;
	}
	return R_FALSE;
}

R_API ut32 r_core_file_cur_fd (RCore *core) {
	RIODesc *desc = core->file ? core->file->desc : NULL;
	if (desc) {
		return desc->fd;
	}
	return (ut32)-1;		//WTF
}

R_API RCoreFile * r_core_file_cur (RCore *r) {
	// Add any locks here
	return r->file;
}
