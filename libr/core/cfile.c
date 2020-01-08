/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_core.h>
#include <stdlib.h>
#include <string.h>

#define UPDATE_TIME(a) (r->times->file_open_time = r_sys_now () - (a))

static int r_core_file_do_load_for_debug(RCore *r, ut64 loadaddr, const char *filenameuri);
static int r_core_file_do_load_for_io_plugin(RCore *r, ut64 baseaddr, ut64 loadaddr);

static bool __isMips (RAsm *a) {
	return a && a->cur && a->cur->arch && strstr (a->cur->arch, "mips");
}

static void loadGP(RCore *core) {
	if (__isMips (core->assembler)) {
		ut64 gp = r_num_math (core->num, "loc._gp");
		if (!gp || gp == UT64_MAX) {
			r_config_set (core->config, "anal.roregs", "zero");
			r_core_cmd0 (core, "10aes@entry0");
			r_config_set (core->config, "anal.roregs", "zero,gp");
			gp = r_reg_getv (core->anal->reg, "gp");
		}
		// eprintf ("[mips] gp: 0x%08"PFMT64x"\n", gp);
		r_config_set_i (core->config, "anal.gp", gp);
	}
}


R_API int r_core_file_reopen(RCore *core, const char *args, int perm, int loadbin) {
	int isdebug = r_config_get_i (core->config, "cfg.debug");
	char *path;
	ut64 laddr = r_config_get_i (core->config, "bin.laddr");
	RCoreFile *file = NULL;
	RCoreFile *ofile = core->file;
	RBinFile *bf = ofile ? r_bin_file_find_by_fd (core->bin, ofile->fd)
		: NULL;
	RIODesc *odesc = (core->io && ofile) ? r_io_desc_get (core->io, ofile->fd) : NULL;
	char *ofilepath = NULL, *obinfilepath = (bf && bf->file)? strdup (bf->file): NULL;
	int ret = false;
	ut64 origoff = core->offset;
	if (odesc) {
		if (odesc->referer) {
			ofilepath = odesc->referer;
		} else if (odesc->uri) {
			ofilepath = odesc->uri;
		}
	}

	ut64 new_baddr = UT64_MAX;
	if (args) {
		new_baddr = r_num_math (core->num, args);
		if (new_baddr && new_baddr != UT64_MAX) {
			r_config_set_i (core->config, "bin.baddr", new_baddr);
		} else {
			new_baddr = UT64_MAX;
		}
	}
	if (new_baddr == UT64_MAX) {
		new_baddr = r_config_get_i (core->config, "bin.baddr");
	}

	if (r_sandbox_enable (0)) {
		eprintf ("Cannot reopen in sandbox\n");
		free (obinfilepath);
		return false;
	}
	if (!core->file) {
		eprintf ("No file opened to reopen\n");
		free (ofilepath);
		free (obinfilepath);
		return false;
	}
	int newpid = odesc? odesc->fd: -1;

	if (isdebug) {
		r_debug_kill (core->dbg, core->dbg->pid, core->dbg->tid, 9); // KILL
		perm = 7;
	} else {
		if (!perm) {
			perm = 4; //R_PERM_R;
		}
	}
	if (!ofilepath) {
		eprintf ("Unknown file path");
		free (obinfilepath);
		return false;
	}

	// HACK: move last mapped address to higher place
	// XXX - why does this hack work?
	// when the new memory maps are created.
	path = strdup (ofilepath);
	free (obinfilepath);
	obinfilepath = strdup (ofilepath);

	// r_str_trim (path);
	file = r_core_file_open (core, path, perm, laddr);

	if (isdebug) {
		int newtid = newpid;
		// XXX - select the right backend
		if (core->file) {
			newpid = r_io_fd_get_pid (core->io, core->file->fd);
			newtid = r_io_fd_get_tid (core->io, core->file->fd);
#if __linux__
			core->dbg->main_pid = newpid;
			newtid = newpid;
#endif
		}
		// Reset previous pid and tid
		core->dbg->pid = -1;
		core->dbg->tid = -1;
		// Reopen and attach
		r_core_setup_debugger (core, "native", true);
		r_debug_select (core->dbg, newpid, newtid);
	}

	if (file) {
		bool had_rbin_info = false;

		if (ofile && bf) {
			if (r_bin_file_delete (core->bin, bf->id)) {
				had_rbin_info = true;
			}
		}
		r_core_file_close (core, ofile);
		r_core_file_set_by_file (core, file);
		ofile = NULL;
		odesc = NULL;
		//	core->file = file;
		eprintf ("File %s reopened in %s mode\n", path,
			(perm & R_PERM_W)? "read-write": "read-only");

		if (loadbin && (loadbin == 2 || had_rbin_info)) {
			ut64 baddr;
			if (isdebug) {
				baddr = r_debug_get_baddr (core->dbg, path);
			} else if (new_baddr != UT64_MAX) {
				baddr = new_baddr;
			} else {
				baddr = r_config_get_i (core->config, "bin.baddr");
			}
			ret = r_core_bin_load (core, obinfilepath, baddr);
			r_core_bin_update_arch_bits (core);
			if (!ret) {
				eprintf ("Error: Failed to reload rbin for: %s", path);
			}
			origoff = r_num_math (core->num, "entry0");
		}

		if (core->bin->cur && core->io && r_io_desc_get (core->io, file->fd) && !loadbin) {
			//force here NULL because is causing uaf look this better in future XXX @alvarofe
			core->bin->cur = NULL;
		}
		// close old file
	} else if (ofile) {
		eprintf ("r_core_file_reopen: Cannot reopen file: %s with perms 0x%x,"
			" attempting to open read-only.\n", path, perm);
		// lower it down back
		//ofile = r_core_file_open (core, path, R_PERM_R, addr);
		r_core_file_set_by_file (core, ofile);
	} else {
		eprintf ("Cannot reopen\n");
	}
	if (core->file) {
		r_io_use_fd (core->io, core->file->fd);
		core->switch_file_view = 1;
		r_core_block_read (core);
#if 0
		else {
			const char *name = (cf && cf->desc)? cf->desc->name: "ERROR";
			eprintf ("Error: Unable to switch the view to file: %s\n", name);
		}
#endif
	}
	r_core_seek (core, origoff, 1);
	if (isdebug) {
		r_core_cmd0 (core, ".dm*");
		r_core_cmd0 (core, ".dr*");
		r_core_cmd0 (core, "sr PC");
	} else {
		loadGP (core);
	}
	// update anal io bind
	r_io_bind (core->io, &(core->anal->iob));
	if (core->file && core->file->fd >= 0) {
		r_core_cmd0 (core, "o-!");
	}
	r_core_file_close_all_but (core);
	// This is done to ensure that the file is correctly
	// loaded into the view
	free (obinfilepath);
	//free (ofilepath);
	free (path);
	return ret;
}

R_API void r_core_sysenv_end(RCore *core, const char *cmd) {
	// TODO: remove tmpfilez
	if (strstr (cmd, "R2_BLOCK")) {
		// remove temporary BLOCK file
		char *f = r_sys_getenv ("R2_BLOCK");
		if (f) {
			r_file_rm (f);
			r_sys_setenv ("R2_BLOCK", NULL);
			free (f);
		}
	}
	r_sys_setenv ("R2_FILE", NULL);
	r_sys_setenv ("R2_BYTES", NULL);
	r_sys_setenv ("R2_OFFSET", NULL);

	// remove temporary R2_CONFIG file
	char *r2_config = r_sys_getenv ("R2_CONFIG");
	if (r2_config) {
		r_file_rm (r2_config);
		r_sys_setenv ("R2_CONFIG", NULL);
		free (r2_config);
	}
}

#if DISCUSS
EDITOR r_sys_setenv ("EDITOR", r_config_get (core->config, "cfg.editor"));
CURSOR cursor position (offset from curseek)
VERBOSE cfg.verbose
#endif

R_API char *r_core_sysenv_begin(RCore * core, const char *cmd) {
	char *f, *ret = cmd? strdup (cmd): NULL;
	RIODesc *desc = core->file ? r_io_desc_get (core->io, core->file->fd) : NULL;
	if (cmd && strstr (cmd, "R2_BYTES")) {
		char *s = r_hex_bin2strdup (core->block, core->blocksize);
		r_sys_setenv ("R2_BYTES", s);
		free (s);
	}
	r_sys_setenv ("RABIN2_PDBSERVER", r_config_get (core->config, "pdb.server"));
	if (desc && desc->name) {
		r_sys_setenv ("R2_FILE", desc->name);
		r_sys_setenv ("R2_SIZE", sdb_fmt ("%"PFMT64d, r_io_desc_size (desc)));
		if (cmd && strstr (cmd, "R2_BLOCK")) {
			// replace BLOCK in RET string
			if ((f = r_file_temp ("r2block"))) {
				if (r_file_dump (f, core->block, core->blocksize, 0)) {
					r_sys_setenv ("R2_BLOCK", f);
				}
				free (f);
			}
		}
	}
	r_sys_setenv ("R2_OFFSET", sdb_fmt ("%"PFMT64d, core->offset));
	r_sys_setenv ("R2_XOFFSET", sdb_fmt ("0x%08"PFMT64x, core->offset));
	r_sys_setenv ("R2_ENDIAN", core->assembler->big_endian? "big": "little");
	r_sys_setenv ("R2_BSIZE", sdb_fmt ("%d", core->blocksize));

	// dump current config file so other r2 tools can use the same options
	char *config_sdb_path = NULL;
	int config_sdb_fd = r_file_mkstemp (NULL, &config_sdb_path);
	if (config_sdb_fd >= 0) {
		close (config_sdb_fd);
	}

	Sdb *config_sdb = sdb_new (NULL, config_sdb_path, 0);
	r_config_serialize (core->config, config_sdb);
	sdb_sync (config_sdb);
	sdb_free (config_sdb);
	r_sys_setenv ("R2_CONFIG", config_sdb_path);

	r_sys_setenv ("RABIN2_LANG", r_config_get (core->config, "bin.lang"));
	r_sys_setenv ("RABIN2_DEMANGLE", r_config_get (core->config, "bin.demangle"));
	r_sys_setenv ("R2_ARCH", r_config_get (core->config, "asm.arch"));
	r_sys_setenv ("R2_BITS", sdb_fmt ("%d", r_config_get_i (core->config, "asm.bits")));
	r_sys_setenv ("R2_COLOR", r_config_get_i (core->config, "scr.color")? "1": "0");
	r_sys_setenv ("R2_DEBUG", r_config_get_i (core->config, "cfg.debug")? "1": "0");
	r_sys_setenv ("R2_IOVA", r_config_get_i (core->config, "io.va")? "1": "0");
	free (config_sdb_path);
	return ret;
}

#if !__linux__ && !__WINDOWS__
static ut64 get_base_from_maps(RCore *core, const char *file) {
	RDebugMap *map;
	RListIter *iter;
	ut64 b = 0LL;

	r_debug_map_sync (core->dbg); // update process memory maps
	r_list_foreach (core->dbg->maps, iter, map) {
		if ((map->perm & 5) == 5) {
			// TODO: make this more flexible
			// XXX - why "copy/" here?
			if (map->name && strstr (map->name, "copy/")) {
				return map->addr;
			}
			if (map->file && !strcmp (map->file, file)) {
				return map->addr;
			}
			if (map->name && !strcmp (map->name, file)) {
				return map->addr;
			}
			// XXX - Commented out, as this could unexpected results
			//b = map->addr;
		}
	}
	// fallback resolution copied from cmd_debug.c:r_debug_get_baddr
	r_list_foreach (core->dbg->maps, iter, map) {
		if (map->perm == 5) { // r-x
			return map->addr;
		}
	}

	return b;
}
#endif

#if __linux__ || __APPLE__
static bool setbpint(RCore *r, const char *mode, const char *sym) {
	RBreakpointItem *bp;
	RFlagItem *fi = r_flag_get (r->flags, sym);
	if (!fi) {
		return false;
	}
	bp = r_bp_add_sw (r->dbg->bp, fi->offset, 1, R_BP_PROT_EXEC);
	if (bp) {
		bp->internal = true;
#if __linux__
		bp->data = r_str_newf ("?e %s: %s", mode, sym);
#else
		bp->data = r_str_newf ("?e %s: %s;ps@rdi", mode, sym);
#endif
		return true;
	}
	eprintf ("Cannot set breakpoint at %s\n", sym);
	return false;
}
#endif

// XXX - need to handle index selection during debugging
static int r_core_file_do_load_for_debug(RCore *r, ut64 baseaddr, const char *filenameuri) {
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? r_io_desc_get (r->io, cf->fd) : NULL;
	RBinFile *binfile = NULL;
	RBinPlugin *plugin;
	int xtr_idx = 0; // if 0, load all if xtr is used

	// TODO : Honor file.path eval var too?
	if (!strncmp ("dbg://", filenameuri, 6)) {
		filenameuri += 6;
	}
	if (!desc) {
		return false;
	}
	if (cf) {
		r_debug_select (r->dbg, r_io_fd_get_pid (r->io, cf->fd),
				r_io_fd_get_tid (r->io, cf->fd));
	}
#if !__linux__
#if !__WINDOWS__
	baseaddr = get_base_from_maps (r, filenameuri);
#endif
	if (baseaddr != UT64_MAX) {
		r_config_set_i (r->config, "bin.baddr", baseaddr);
	}
#endif
	int fd = cf? cf->fd: -1;
	RBinOptions opt;
	r_bin_options_init (&opt, fd, baseaddr, UT64_MAX, false);
	opt.xtr_idx = xtr_idx;
	if (!r_bin_open (r->bin, filenameuri, &opt)) {
		eprintf ("RBinLoad: Cannot open %s\n", filenameuri);
		if (r_config_get_i (r->config, "bin.rawstr")) {
			r_bin_options_init (&opt, fd, baseaddr, UT64_MAX, true);
			opt.xtr_idx = xtr_idx;
			if (!r_bin_open (r->bin, filenameuri, &opt)) {
				return false;
			}
		}
	}

	if (*r_config_get (r->config, "dbg.libs")) {
		r_core_cmd0 (r, ".dmm*");
#if __linux__
		setbpint (r, "dbg.libs", "sym.imp.dlopen");
		setbpint (r, "dbg.libs", "sym.imp.dlmopen");
		setbpint (r, "dbg.unlibs", "sym.imp.dlclose");
#elif __APPLE__
		setbpint (r, "dbg.libs", "sym._dlopen");
		setbpint (r, "dbg.libs", "sym._dlclose");
#endif
	}
	binfile = r_bin_cur (r->bin);
	r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && !strncmp (plugin->name, "any", 5)) {
		// set use of raw strings
		// r_config_set_i (r->config, "io.va", false);
		//\\ r_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
		r->bin->maxstrbuf = r_config_get_i (r->config, "bin.maxstrbuf");
	} else if (binfile) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (plugin && strcmp (plugin->name, "any") && info) {
			r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
		}
	}

	if (plugin && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)\"\n");
	}

	return true;
}

static int r_core_file_do_load_for_io_plugin(RCore *r, ut64 baseaddr, ut64 loadaddr) {
	RCoreFile *cf = r_core_file_cur (r);
	int fd = cf ? cf->fd : -1;
	RBinFile *binfile = NULL;
	int xtr_idx = 0; // if 0, load all if xtr is used
	RBinPlugin *plugin;

	if (fd < 0) {
		return false;
	}
	r_io_use_fd (r->io, fd);
	RBinOptions opt;
	r_bin_options_init (&opt, fd, baseaddr, loadaddr, r->bin->rawstr);
	opt.xtr_idx = xtr_idx;
	if (!r_bin_open_io (r->bin, &opt)) {
		//eprintf ("Failed to load the bin with an IO Plugin.\n");
		return false;
	}
	binfile = r_bin_cur (r->bin);
	r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && !strcmp (plugin->name, "any")) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (!info) {
			return false;
		}
		// set use of raw strings
		r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
		// r_config_set_i (r->config, "io.va", false);
		// r_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
		r->bin->maxstrbuf = r_config_get_i (r->config, "bin.maxstrbuf");
	} else if (binfile) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (!info) {
			return false;
		}
		if (plugin && strcmp (plugin->name, "any") && info) {
			r_core_bin_set_arch_bits (r, binfile->file,
				info->arch, info->bits);
		}
	}

	if (plugin && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)\"\n");
	}
	return true;
}

static bool try_loadlib(RCore *core, const char *lib, ut64 addr) {
	if (r_core_file_open (core, lib, 0, addr) != NULL) {
		r_core_bin_load (core, lib, addr);
		return true;
	}
	return false;
}

R_API bool r_core_file_loadlib(RCore *core, const char *lib, ut64 libaddr) {
	const char *dirlibs = r_config_get (core->config, "dir.libs");
	bool free_libdir = true;
#ifdef __WINDOWS__
	char *libdir = r_str_r2_prefix (R2_LIBDIR);
#else
	char *libdir = strdup (R2_LIBDIR);
#endif
	if (!libdir) {
		libdir = R2_LIBDIR;
		free_libdir = false;
	}
	if (!dirlibs || !*dirlibs) {
		dirlibs = "." R_SYS_DIR;
	}
	const char *ldlibrarypath[] = {
		dirlibs,
		libdir,
#ifndef __WINDOWS__
		"/usr/local/lib",
		"/usr/lib",
		"/lib",
#endif
		"." R_SYS_DIR,
		NULL
	};
	const char * *libpath = (const char * *) &ldlibrarypath;

	bool ret = false;
#ifdef __WINDOWS__
	if (strlen (lib) >= 3 && lib[1] == ':' && lib[2] == '\\') {
#else
	if (*lib == '/') {
#endif
		if (try_loadlib (core, lib, libaddr)) {
			ret = true;
		}
	} else {
		while (*libpath) {
			char *s = r_str_newf ("%s" R_SYS_DIR "%s", *libpath, lib);
			if (try_loadlib (core, s, libaddr)) {
				ret = true;
			}
			free (s);
			if (ret) {
				break;
			}
			libpath++;
		}
	}
	if (free_libdir) {
		free (libdir);
	}
	return ret;
}

R_API int r_core_bin_rebase(RCore *core, ut64 baddr) {
	if (!core || !core->bin || !core->bin->cur) {
		return 0;
	}
	if (baddr == UT64_MAX) {
		return 0;
	}
	RBinFile *bf = core->bin->cur;
	bf->o->baddr = baddr;
	bf->o->loadaddr = baddr;
	r_bin_object_set_items (bf, bf->o);
	return 1;
}

static void load_scripts_for(RCore *core, const char *name) {
	// TODO:
	char *file;
	RListIter *iter;
	char *hdir = r_str_newf (R_JOIN_2_PATHS (R2_HOME_BINRC, "bin-%s"), name);
	char *path = r_str_home (hdir);
	RList *files = r_sys_dir (path);
	if (!r_list_empty (files)) {
		eprintf ("[binrc] path: %s\n", path);
	}
	r_list_foreach (files, iter, file) {
		if (*file && *file != '.') {
			eprintf ("[binrc] loading %s\n", file);
			r_core_cmdf (core, ". %s/%s", path, file);
		}
	}
	r_list_free (files);
	free (path);
	free (hdir);
}

typedef struct {
	const char *name;
	bool found;
} RCoreFileData;

static bool filecb(void *user, void *data, ut32 id) {
	RCoreFileData *fd = user;
	RIODesc *desc = (RIODesc *)data;
	if (!strcmp (desc->name, fd->name)) {
		fd->found = true;
	}
	return true;
}

typedef struct {
	const char *name;
	ut64 addr;
	RBin *bin;
} RCoreLinkData;

static bool linkcb(void *user, void *data, ut32 id) {
	RCoreLinkData *ld = user;
	RIODesc *desc = (RIODesc *)data;

	RBinFile *bf = r_bin_file_find_by_fd (ld->bin, desc->fd);
	if (bf) {
		RListIter *iter;
		RBinSymbol *sym;
		RList *symbols = r_bin_file_get_symbols (bf);
		r_list_foreach (symbols, iter, sym) {
			if (!strcmp (sym->name, ld->name)) {
				ld->addr = sym->vaddr;
				return false;
			}
		}
	}
	return true;
}


R_API bool r_core_bin_load(RCore *r, const char *filenameuri, ut64 baddr) {
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? r_io_desc_get (r->io, cf->fd) : NULL;
	ut64 laddr = r_config_get_i (r->config, "bin.laddr");
	RBinFile *binfile = NULL;
	RBinPlugin *plugin = NULL;
	bool is_io_load;
	const char *cmd_load;
	if (!cf) {
		return false;
	}
	// NULL deref guard
	if (desc) {
		is_io_load = desc && desc->plugin;
		if (!filenameuri || !*filenameuri) {
			filenameuri = desc->name;
		}
	} else {
		is_io_load = false;
	}

	if (!filenameuri) {
		eprintf ("r_core_bin_load: no file specified\n");
		return false;
	}

	r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
	r->bin->maxstrbuf = r_config_get_i (r->config, "bin.maxstrbuf");
	if (is_io_load) {
		// TODO? necessary to restore the desc back?
		// Fix to select pid before trying to load the binary
		if ((desc->plugin && desc->plugin->isdbg) || r_config_get_i (r->config, "cfg.debug")) {
			r_core_file_do_load_for_debug (r, baddr, filenameuri);
		} else {
			r_core_file_do_load_for_io_plugin (r, baddr, 0LL);
		}
		r_io_use_fd (r->io, desc->fd);
		// Restore original desc
	}
	if (cf && binfile && desc) {
		binfile->fd = desc->fd;
	}
	binfile = r_bin_cur (r->bin);
	if (r->bin->cur && r->bin->cur->o && r->bin->cur->o->plugin && r->bin->cur->o->plugin->strfilter) {
		char msg[2];
		msg[0] = r->bin->cur->o->plugin->strfilter;
		msg[1] = 0;
		r_config_set (r->config, "bin.str.filter", msg);
	}
	//r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->name) {
		load_scripts_for (r, plugin->name);
	}
	cmd_load = r_config_get (r->config, "cmd.load");
	if (cmd_load && *cmd_load) {
		r_core_cmd (r, cmd_load, 0);
	}

	if (plugin && plugin->name) {
		if (!strcmp (plugin->name, "any")) {
			if (r_str_startswith (desc->name, "rap") && strstr (desc->name, "://")) {
				r_io_map_new (r->io, desc->fd, desc->perm, 0, laddr, UT64_MAX);
			} else {
				r_io_map_new (r->io, desc->fd, desc->perm, 0, laddr, r_io_desc_size (desc));
			}
			// set use of raw strings
			//r_config_set (r->config, "bin.rawstr", "true");
			// r_config_set_i (r->config, "io.va", false);
			// get bin.minstr
			r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
			r->bin->maxstrbuf = r_config_get_i (r->config, "bin.maxstrbuf");
		} else if (binfile) {
			RBinObject *obj = r_bin_cur_object (r->bin);
			if (obj) {
				bool va = obj->info ? obj->info->has_va : 0;
				if (!va) {
					r_config_set_i (r->config, "io.va", 0);
				}
				//workaround to map correctly malloc:// and raw binaries
				if (r_io_desc_is_dbg (desc) || (!obj->sections || !va)) {
					r_io_map_new (r->io, desc->fd, desc->perm, 0, laddr, r_io_desc_size (desc));
				}
				RBinInfo *info = obj->info;
				if (info) {
					r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
				} else {
					r_core_bin_set_arch_bits (r, binfile->file,
						r_config_get (r->config, "asm.arch"),
						r_config_get_i (r->config, "asm.bits"));
				}
			}
		}
	} else {
		if (desc) {
			r_io_map_new (r->io, desc->fd, desc->perm, 0, laddr, r_io_desc_size (desc));
		}
		if (binfile) {
			r_core_bin_set_arch_bits (r, binfile->file,
					r_config_get (r->config, "asm.arch"),
					r_config_get_i (r->config, "asm.bits"));
		}
	}
	if (desc && r_config_get_i (r->config, "io.exec")) {
		desc->perm |= R_PERM_X;
	}
	if (plugin && plugin->name && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ;"
			" wx `ph adler32 $s-12 @12` @8)\"\n");
	}
	if (!r_config_get_i (r->config, "cfg.debug")) {
		loadGP (r);
	}
	if (r_config_get_i (r->config, "bin.libs")) {
		const char *lib;
		RListIter *iter;
		RList *libs = r_bin_get_libs (r->bin);
		r_list_foreach (libs, iter, lib) {
			eprintf ("[bin.libs] Opening %s\n", lib);
			RCoreFileData filedata = {lib, false};
			r_id_storage_foreach (r->io->files, filecb, &filedata);
			if (filedata.found) {
				eprintf ("Already opened\n");
				continue;
			}
			ut64 baddr = r_io_map_location (r->io, 0x200000);
			if (baddr != UT64_MAX) {
				r_core_file_loadlib (r, lib, baddr);
			}
		}
		r_core_cmd0 (r, "obb 0;s entry0");
		r_config_set_i (r->config, "bin.at", true);
		eprintf ("[bin.libs] Linking imports...\n");
		RBinImport *imp;
		RList *imports = r_bin_get_imports (r->bin);
		r_list_foreach (imports, iter, imp) {
			// PLT finding
			RFlagItem *impsym = r_flag_get (r->flags, sdb_fmt ("sym.imp.%s", imp->name));
			if (!impsym) {
				//eprintf ("Cannot find '%s' import in the PLT\n", imp->name);
				continue;
			}
			ut64 imp_addr = impsym->offset;
			eprintf ("Resolving %s... ", imp->name);
			RCoreLinkData linkdata = {imp->name, UT64_MAX, r->bin};
			r_id_storage_foreach (r->io->files, linkcb, &linkdata);
			if (linkdata.addr != UT64_MAX) {
				eprintf ("0x%08"PFMT64x"\n", linkdata.addr);
				ut64 a = linkdata.addr;
				ut64 b = imp_addr;
				r_core_cmdf (r, "ax 0x%08"PFMT64x" 0x%08"PFMT64x, a, b);
			} else {
				eprintf ("NO\n");
			}
		}
	}

	//If type == R_BIN_TYPE_CORE, we need to create all the maps
	if (plugin && binfile && plugin->file_type
		 && plugin->file_type (binfile) == R_BIN_TYPE_CORE) {
		ut64 sp_addr = (ut64)-1;
		RIOMap *stack_map = NULL;

		// Setting the right arch and bits, so regstate will be shown correctly
		if (plugin->info) {
			RBinInfo *inf = plugin->info (binfile);
			eprintf ("Setting up coredump arch-bits to: %s-%d\n", inf->arch, inf->bits);
			r_config_set (r->config, "asm.arch", inf->arch);
			r_config_set_i (r->config, "asm.bits", inf->bits);
			r_bin_info_free (inf);
		}
		if (binfile->o->regstate) {
			if (r_reg_arena_set_bytes (r->anal->reg, binfile->o->regstate)) {
				eprintf ("Setting up coredump: Problem while setting the registers\n");
			} else {
				eprintf ("Setting up coredump: Registers have been set\n");
				const char *regname = r_reg_get_name (r->anal->reg, R_REG_NAME_SP);
				if (regname) {
					RRegItem *reg = r_reg_get (r->anal->reg, regname, -1);
					if (reg) {
						sp_addr = r_reg_get_value (r->anal->reg, reg);
						stack_map = r_io_map_get (r->io, sp_addr);
					}
				}
				regname = r_reg_get_name (r->anal->reg, R_REG_NAME_PC);
				if (regname) {
					RRegItem *reg = r_reg_get (r->anal->reg, regname, -1);
					if (reg) {
						ut64 seek = r_reg_get_value (r->anal->reg, reg);
						r_core_seek (r, seek, 1);
					}
				}
			}
		}

		RBinObject *o = binfile->o;
		int map = 0;
		if (o && o->maps) {
			RList *maps = o->maps;
			RListIter *iter;
			RBinMap *mapcore;

			r_list_foreach (maps, iter, mapcore) {
				RIOMap *iomap = r_io_map_get (r->io, mapcore->addr);
				if (iomap && (mapcore->file || stack_map == iomap)) {
					r_io_map_set_name (iomap, mapcore->file ? mapcore->file : "[stack]");
				}
				map++;
			}
			r_list_free (maps);
			o->maps = NULL;
		}
		eprintf ("Setting up coredump: %d maps have been found and created\n", map);
		goto beach;
	}
beach:
	return true;
}

R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int perm, ut64 loadaddr) {
	const bool openmany = r_config_get_i (r->config, "file.openmany");
	int opened_count = 0;
	RListIter *fd_iter, *iter2;
	RIODesc *fd;

	RList *list_fds = r_io_open_many (r->io, file, perm, 0644);

	if (!list_fds || r_list_length (list_fds) == 0) {
		r_list_free (list_fds);
		return NULL;
	}

	r_list_foreach_safe (list_fds, fd_iter, iter2, fd) {
		opened_count++;
		if (openmany && opened_count > 1) {
			// XXX - Open Many should limit the number of files
			// loaded in io plugin area this needs to be more premptive
			// like down in the io plugin layer.
			// start closing down descriptors
			r_list_delete (list_fds, fd_iter);
			continue;
		}
		RCoreFile *fh = R_NEW0 (RCoreFile);
		if (fh) {
			fh->alive = 1;
			fh->core = r;
			fh->fd = fd->fd;
			r->file = fh;
			r_bin_bind (r->bin, &(fh->binb));
			r_list_append (r->files, fh);
			r_core_bin_load (r, fd->name, loadaddr);
		}
	}
	return NULL;
}

/* loadaddr is r2 -m (mapaddr) */
R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int flags, ut64 loadaddr) {
	r_return_val_if_fail (r && file, NULL);
	ut64 prev = r_sys_now ();
	const bool openmany = r_config_get_i (r->config, "file.openmany");
	RCoreFile *fh = NULL;

	if (!strcmp (file, "-")) {
		file = "malloc://512";
	}
	//if not flags was passed open it with -r--
	if (!flags) {
		flags = R_PERM_R;
	}
	r->io->bits = r->assembler->bits; // TODO: we need an api for this
	RIODesc *fd = r_io_open_nomap (r->io, file, flags, 0644);
	if (r_cons_is_breaked()) {
		goto beach;
	}
	if (!fd && openmany) {
		// XXX - make this an actual option somewhere?
		fh = r_core_file_open_many (r, file, flags, loadaddr);
		if (fh) {
			goto beach;
		}
	}
	if (!fd) {
		if (flags & R_PERM_W) {
		//	flags |= R_IO_CREAT;
			if (!(fd = r_io_open_nomap (r->io, file, flags, 0644))) {
				goto beach;
			}
		} else {
			goto beach;
		}
	}
	if (r_io_is_listener (r->io)) {
		r_core_serve (r, fd);
		r_io_desc_free (fd);
		goto beach;
	}

	fh = R_NEW0 (RCoreFile);
	if (!fh) {
		eprintf ("core/file.c: r_core_open failed to allocate RCoreFile.\n");
		goto beach;
	}
	fh->alive = 1;
	fh->core = r;
	fh->fd = fd->fd;
	{
		const char *cp = r_config_get (r->config, "cmd.open");
		if (cp && *cp) {
			r_core_cmd (r, cp, 0);
		}
		char *absfile = r_file_abspath (file);
		r_config_set (r->config, "file.path", absfile);
		free (absfile);
	}
	// check load addr to make sure its still valid
	r_bin_bind (r->bin, &(fh->binb));

	if (!r->files) {
		r->files = r_list_newf ((RListFree)r_core_file_free);
	}

	r->file = fh;
	r_io_use_fd (r->io, fd->fd);

	r_list_append (r->files, fh);
	if (r_config_get_i (r->config, "cfg.debug")) {
		bool swstep = true;
		if (r->dbg->h && r->dbg->h->canstep) {
			swstep = false;
		}
		r_config_set_i (r->config, "dbg.swstep", swstep);
		// Set the correct debug handle
		if (fd->plugin && fd->plugin->isdbg) {
			char *dh = r_str_ndup (file, (strstr (file, "://") - file));
			if (dh) {
				r_debug_use (r->dbg, dh);
				free (dh);
			}
		}
	}
	//used by r_core_bin_load otherwise won't load correctly
	//this should be argument of r_core_bin_load <shrug>
	if (loadaddr != UT64_MAX) {
		r_config_set_i (r->config, "bin.laddr", loadaddr);
	}
	r_core_cmd0 (r, "=!");
beach:
	r->times->file_open_time = r_sys_now () - prev;
	return fh;
}

R_API void r_core_file_free(RCoreFile *cf) {
	int res = 1;

	r_return_if_fail (cf);

	if (!cf->core) {
		free (cf);
		return;
	}
	res = r_list_delete_data (cf->core->files, cf);
	if (res && cf->alive) {
		// double free libr/io/io.c:70 performs free
		RIO *io = cf->core->io;
		if (io) {
			RBin *bin = cf->binb.bin;
			RBinFile *bf = r_bin_cur (bin);
			if (bf) {
				r_bin_file_deref (bin, bf);
			}
			r_io_fd_close (io, cf->fd);
			free (cf);
		}
	}
}

R_API int r_core_file_close(RCore *r, RCoreFile *fh) {
	int ret;
	RIODesc *desc = fh && r ? r_io_desc_get (r->io, fh->fd) : NULL;
	RCoreFile *prev_cf = r && r->file != fh? r->file: NULL;

	// TODO: This is not correctly done. because map and iodesc are
	// still referenced // we need to fully clear all R_IO structs
	// related to a file as well as the ones needed for RBin.
	//
	// XXX -these checks are intended to *try* and catch
	// stale objects.  Unfortunately, if the file handle
	// (fh) is stale and freed, and there is more than 1
	// fh in the r->files list, we are hosed. (design flaw)
	// TODO maybe using sdb to keep track of the allocated and
	// deallocated files might be a good solutions
	if (!r || !desc || r_list_empty (r->files)) {
		return false;
	}

	if (fh == r->file) {
		r->file = NULL;
	}

	r_core_file_set_by_fd (r, fh->fd);
	r_core_bin_set_by_fd (r, fh->fd);

	/* delete filedescriptor from io descs here */
	// r_io_desc_del (r->io, fh->fd);

	// AVOID DOUBLE FREE HERE
	r->files->free = NULL;

	ret = r_list_delete_data (r->files, fh);
	if (ret) {
		if (!prev_cf && r_list_length (r->files) > 0) {
			prev_cf = (RCoreFile *) r_list_get_n (r->files, 0);
		}

		if (prev_cf) {
			RIODesc *desc = prev_cf && r ? r_io_desc_get (r->io, prev_cf->fd) : NULL;
			if (!desc) {
				eprintf ("Error: RCoreFile's found with out a supporting RIODesc.\n");
			}
			ret = r_core_file_set_by_file (r, prev_cf);
		}
	}
	r_io_desc_close (desc);
	r_core_file_free (fh);
	return ret;
}

R_API RCoreFile *r_core_file_get_by_fd(RCore *core, int fd) {
	RCoreFile *file;
	RListIter *iter;
	r_list_foreach (core->files, iter, file) {
		if (file->fd == fd) {
			return file;
		}
	}
	return NULL;
}

R_API int r_core_file_list(RCore *core, int mode) {
	int count = 0;
	RCoreFile *f;
	RIODesc *desc;
	ut64 from;
	RListIter *it;
	RBinFile *bf;
	RListIter *iter;
	if (mode == 'j') {
		r_cons_printf ("[");
	}
	r_list_foreach (core->files, iter, f) {
		desc = r_io_desc_get (core->io, f->fd);
		if (!desc) {
			// cannot find desc for this fd, RCoreFile inconsistency!!!1
			continue;
		}
		from = 0LL;
		switch (mode) {
		case 'j':
			r_cons_printf ("{\"raised\":%s,\"fd\":%d,\"uri\":\"%s\",\"from\":%"
				PFMT64d ",\"writable\":%s,\"size\":%d}%s",
				r_str_bool (core->io->desc->fd == f->fd),
				(int) f->fd, desc->uri, (ut64) from,
				r_str_bool (desc->perm & R_PERM_W),
				(int) r_io_desc_size (desc),
				iter->n? ",": "");
			break;
		case '*':
		case 'r':
			// TODO: use a getter
			{
				bool fileHaveBin = false;
				char *absfile = r_file_abspath (desc->uri);
				r_list_foreach (core->bin->binfiles, it, bf) {
					if (bf->fd == f->fd) {
						r_cons_printf ("o %s 0x%"PFMT64x "\n", absfile, (ut64) from);
						fileHaveBin = true;
					}
				}
				if (!fileHaveBin && !strstr (absfile, "://")) {
					r_cons_printf ("o %s 0x%"PFMT64x "\n", absfile, (ut64) from);
				}
				free (absfile);
			}
			break;
		case 'n':
			{
				bool header_loaded = false;
				r_list_foreach (core->bin->binfiles, it, bf) {
					if (bf->fd == f->fd) {
						header_loaded = true;
						break;
					}
				}
				if (!header_loaded) {
					RList* maps = r_io_map_get_for_fd (core->io, f->fd);
					RListIter *iter;
					RIOMap* current_map;
					char *absfile = r_file_abspath (desc->uri);
					r_list_foreach (maps, iter, current_map) {
						if (current_map) {
							r_cons_printf ("on %s 0x%"PFMT64x "\n", absfile, current_map->itv.addr);
						}
					}
					r_list_free (maps);
					free(absfile);

				}
			}
			break;
		default:
		{
			ut64 sz = r_io_desc_size (desc);
			const char *fmt;
			if (sz == UT64_MAX) {
				fmt = "%c %d %d %s @ 0x%"PFMT64x " ; %s size=%"PFMT64d "\n";
			} else {
				fmt = "%c %d %d %s @ 0x%"PFMT64x " ; %s size=%"PFMT64u "\n";
			}
			r_cons_printf (fmt,
				core->io->desc->fd == f->fd ? '*': '-',
				count,
				(int) f->fd, desc->uri, (ut64) from,
				desc->perm & R_PERM_W? "rw": "r",
				r_io_desc_size (desc));
		}
		break;
		}
		count++;
	}
	if (mode == 'j') {
		r_cons_printf ("]\n");
	}
	return count;
}

// XXX - needs to account for binfile index and bin object index
R_API bool r_core_file_bin_raise(RCore *core, ut32 bfid) {
	RBin *bin = core->bin;
	RBinFile *bf = r_list_get_n (bin->binfiles, bfid);
	bool res = false;
	if (bf) {
		res = r_bin_file_set_cur_binfile (bin, bf);
		if (res) {
			r_io_use_fd (core->io, bf->fd);
		}
		res = res? r_core_file_set_by_fd (core, bf->fd): res;
		if (res) {
			core->switch_file_view = 1;
		}
	}
	return res;
}

R_API int r_core_file_binlist(RCore *core) {
	int count = 0;
	RListIter *iter;
	RCoreFile *cur_cf = core->file, *cf = NULL;
	RBinFile *binfile = NULL;
	RIODesc *desc;
	RBin *bin = core->bin;
	const RList *binfiles = bin? bin->binfiles: NULL;

	if (!binfiles) {
		return false;
	}
	r_list_foreach (binfiles, iter, binfile) {
		int fd = binfile->fd;
		cf = r_core_file_get_by_fd (core, fd);
		desc = r_io_desc_get (core->io, fd);
		if (cf) {
			r_cons_printf ("%c %d %s ; %s\n",
				core->io->desc == desc ? '*': '-',
				fd, desc->uri, desc->perm & R_PERM_W? "rw": "r");
		}
	}
	r_core_file_set_by_file (core, cur_cf);
	//r_core_bin_bind (core, cur_bf);
	return count;
}

static bool close_but_cb(void *user, void *data, ut32 id) {
	RCore *core = (RCore *)user;
	RIODesc *desc = (RIODesc *)data;
	if (core && desc && core->file) {
		if (desc->fd != core->file->fd) {
			// TODO: use the API
			r_core_cmdf (core, "o-%d", desc->fd);
		}
	}
	return true;
}

R_API bool r_core_file_close_all_but(RCore *core) {
	r_id_storage_foreach (core->io->files, close_but_cb, core);
	return true;
}

R_API bool r_core_file_close_fd(RCore *core, int fd) {
	RCoreFile *file;
	RListIter *iter;
	if (fd == -1) {
		// FIXME: Only closes files known to the core!
		r_list_free (core->files);
		core->files = NULL;
		core->file = NULL;
		return true;
	}
	r_list_foreach (core->files, iter, file) {
		if (file->fd == fd) {
			r_core_file_close (core, file);
			if (file == core->file) {
				core->file = NULL; // deref
			}
			return true;
		}
	}
	return r_io_fd_close (core->io, fd);
}

R_API RCoreFile *r_core_file_find_by_fd(RCore *core, ut64 fd) {
	RListIter *iter;
	RCoreFile *cf = NULL;
	r_list_foreach (core->files, iter, cf) {
		if (cf && cf->fd == fd) {
			break;
		}
		cf = NULL;
	}
	return cf;
}

R_API RCoreFile *r_core_file_find_by_name(RCore *core, const char *name) {
	RListIter *iter;
	RCoreFile *cf = NULL;
	RIODesc *desc;

	if (!core) {
		return NULL;
	}

	r_list_foreach (core->files, iter, cf) {
		desc = r_io_desc_get (core->io, cf->fd);
		if (desc && !strcmp (desc->name, name)) {
			break;
		}
		cf = NULL;
	}
	return cf;
}

R_API int r_core_file_set_by_fd(RCore *core, ut64 fd) {
	if (core) {
		r_io_use_fd (core->io, fd);
		r_core_bin_set_by_fd (core, fd);
		return true;
	}
	return false;
}

R_API int r_core_file_set_by_name(RCore *core, const char *name) {
	RCoreFile *cf = r_core_file_find_by_name (core, name);
	return r_core_file_set_by_file (core, cf);
}

R_API int r_core_file_set_by_file(RCore *core, RCoreFile *cf) {
	if (core && cf) {
		if (!r_core_file_set_by_fd (core, cf->fd)) {
			return false;
		}
		core->file = cf;
		return true;
	}
	return false;
}

R_API ut32 r_core_file_cur_fd(RCore *core) {
	if (core && core->file) {
		return core->file->fd;
	}
	return UT32_MAX;
}

R_API RCoreFile *r_core_file_cur(RCore *r) {
	// Add any locks here
	return r->file;
}
