/* radare - LGPL - Copyright 2009-2021 - pancake */

#include <r_core.h>
#include <stdlib.h>
#include <string.h>

#define UPDATE_TIME(a) (r->times->file_open_time = r_time_now_mono () - (a))

static int r_core_file_do_load_for_debug(RCore *r, ut64 loadaddr, const char *filenameuri);
static int r_core_file_do_load_for_io_plugin(RCore *r, ut64 baseaddr, ut64 loadaddr);

static bool close_but_cb(void *user, void *data, ut32 id) {
       RCore *core = (RCore *)user;
       RIODesc *desc = (RIODesc *)data;
       if (core && desc && core->io->desc) {
               if (desc->fd != core->io->desc->fd) {
                       // TODO: use the API
                       r_core_cmdf (core, "o-%d", desc->fd);
               }
       }
       return true;
}

// TODO: move to IO as a helper?
R_API bool r_core_file_close_all_but(RCore *core) {
       r_id_storage_foreach (core->io->files, close_but_cb, core);
       return true;
}

static bool __isMips (RAsm *a) {
	return a && a->cur && a->cur->arch && strstr (a->cur->arch, "mips");
}

static void loadGP(RCore *core) {
	if (__isMips (core->rasm)) {
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

R_API bool r_core_file_reopen(RCore *core, const char *args, int perm, int loadbin) {
	const bool isdebug = r_config_get_b (core->config, "cfg.debug");
	char *path;
	ut64 laddr = r_config_get_i (core->config, "bin.laddr");
	RIODesc *file = NULL;
	RIODesc *odesc = core->io ? core->io->desc : NULL;
	RBinFile *bf = odesc ? r_bin_file_find_by_fd (core->bin, odesc->fd) : NULL;
	char *ofilepath = NULL, *obinfilepath = (bf && bf->file)? strdup (bf->file): NULL;
	bool ret = false;
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
	if (!odesc) {
		eprintf ("No file opened to reopen\n");
		free (ofilepath);
		free (obinfilepath);
		return false;
	}
	int newpid = odesc->fd;

	if (isdebug) {
		r_debug_kill (core->dbg, core->dbg->pid, core->dbg->tid, 9); // SIGKILL
		do {
			r_debug_continue (core->dbg);
		} while (!r_debug_is_dead (core->dbg));
		r_debug_detach (core->dbg, core->dbg->pid);
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
		if (core->io->desc) {
			newpid = r_io_fd_get_pid (core->io, core->io->desc->fd);
#if __linux__
			core->dbg->main_pid = newpid;
			newtid = newpid;
#else
			newtid = r_io_fd_get_tid (core->io, core->io->desc->fd);
#endif
		}
		// Reset previous pid and tid
		core->dbg->pid = -1;
		core->dbg->tid = -1;
		core->dbg->recoil_mode = R_DBG_RECOIL_NONE;
		memset (&core->dbg->reason, 0, sizeof (core->dbg->reason));
		// Reopen and attach
		r_core_setup_debugger (core, "native", true);
		r_debug_select (core->dbg, newpid, newtid);
	}

	if (file) {
		bool had_rbin_info = false;

		if (odesc && bf) {
			if (r_bin_file_delete (core->bin, bf->id)) {
				had_rbin_info = true;
			}
		}
		r_io_fd_close (core->io, odesc->fd);
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
	} else if (odesc) {
		eprintf ("r_core_file_reopen: Cannot reopen file: %s with perms 0x%x,"
			" attempting to open read-only.\n", path, perm);
		// lower it down back
		//ofile = r_core_file_open (core, path, R_PERM_R, addr);
	} else {
		eprintf ("Cannot reopen\n");
	}
	if (core->io->desc) {
		core->switch_file_view = 1;
		r_core_block_read (core);
	}
	r_core_seek (core, origoff, true);
	if (isdebug) {
		r_core_cmd0 (core, ".dm*");
		r_core_cmd0 (core, ".dr*");
		r_core_cmd0 (core, "sr PC");
	} else {
		loadGP (core);
	}
	// update anal io bind
	r_io_bind (core->io, &(core->anal->iob));
	if (core->io->desc && core->io->desc->fd >= 0) {
		r_core_cmd0 (core, "o-!");
	}
	r_core_file_close_all_but (core);
	// This is done to ensure that the file is correctly
	// loaded into the view
	free (obinfilepath);
	//free (ofilepath);
	// causes double free . dont free file here // R_FREE (file);
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

R_API char *r_core_sysenv_begin(RCore * core, const char *cmd) {
	char *f, *ret = cmd? strdup (cmd): NULL;
	RIODesc *desc = core->io->desc;
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
	r_sys_setenv ("R2_ENDIAN", core->rasm->big_endian? "big": "little");
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
	r_sys_setenv ("R2_BITS", sdb_fmt ("%"PFMT64u, r_config_get_i (core->config, "asm.bits")));
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
	RIODesc *desc = r->io->desc;
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
	int fd = desc->fd;
	r_debug_select (r->dbg, r_io_fd_get_pid (r->io, fd),
			r_io_fd_get_tid (r->io, fd));
#if !__linux__
#if !__WINDOWS__
	baseaddr = get_base_from_maps (r, filenameuri);
#endif
	if (baseaddr != UT64_MAX) {
		r_config_set_i (r->config, "bin.baddr", baseaddr);
	}
#endif
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
	if (plugin && !strcmp (plugin->name, "any")) {
		// set use of raw strings
		// r_config_set_i (r->config, "io.va", false);
		//\\ r_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
		r->bin->maxstrbuf = r_config_get_i (r->config, "bin.maxstrbuf");
	} else if (binfile) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (plugin && info) {
			r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
		}
	}

	if (plugin && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)\"\n");
	}

	return true;
}

static int r_core_file_do_load_for_io_plugin(RCore *r, ut64 baseaddr, ut64 loadaddr) {
	RIODesc *cd = r->io->desc;
	int fd = cd ? cd->fd : -1;
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
	if (r_core_bin_set_env (r, binfile)) {
		if (!r->anal->sdb_cc->path) {
			R_LOG_WARN ("No calling convention defined for this file, analysis may be inaccurate.\n");
		}
	}
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && !strcmp (plugin->name, "any")) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (!info) {
			return false;
		}
		info->bits = r->rasm->bits;
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
		if (plugin) {
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
	void *p = r_core_file_open (core, lib, 0, addr);
	if (p) {
		r_core_bin_load (core, lib, addr);
		R_FREE (p);
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
} MyFileData;

static bool filecb(void *user, void *data, ut32 id) {
	MyFileData *filedata = user;
	RIODesc *desc = (RIODesc *)data;
	if (!strcmp (desc->name, filedata->name)) {
		filedata->found = true;
	}
	return true;
}

static bool file_is_loaded(RCore *core, const char *lib) {
	MyFileData filedata = {lib, false};
	r_id_storage_foreach (core->io->files, filecb, &filedata);
	return filedata.found;
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
	RIODesc *desc = r->io->desc;
	ut64 laddr = r_config_get_i (r->config, "bin.laddr");
	RBinFile *binfile = NULL;
	RBinPlugin *plugin = NULL;
	bool is_io_load;
	const char *cmd_load;
	if (!desc) {
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
		if ((desc->plugin && desc->plugin->isdbg) || r_config_get_b (r->config, "cfg.debug")) {
			r_core_file_do_load_for_debug (r, baddr, filenameuri);
		} else {
			r_core_file_do_load_for_io_plugin (r, baddr, 0LL);
		}
		r_io_use_fd (r->io, desc->fd);
		// Restore original desc
	}
	if (binfile && desc) {
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
	if (!r_config_get_b (r->config, "cfg.debug")) {
		loadGP (r);
	}
	if (r_config_get_i (r->config, "bin.libs")) {
		const char *lib;
		RListIter *iter;
		RList *libs = r_bin_get_libs (r->bin);
		r_list_foreach (libs, iter, lib) {
			if (file_is_loaded (r, lib)) {
				continue;
			}
			eprintf ("[bin.libs] Opening %s\n", lib);
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
						stack_map = r_io_map_get_at (r->io, sp_addr);
					}
				}
				regname = r_reg_get_name (r->anal->reg, R_REG_NAME_PC);
				if (regname) {
					RRegItem *reg = r_reg_get (r->anal->reg, regname, -1);
					if (reg) {
						ut64 seek = r_reg_get_value (r->anal->reg, reg);
						r_core_seek (r, seek, true);
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
				RIOMap *iomap = r_io_map_get_at (r->io, mapcore->addr);
				if (iomap && (mapcore->file || stack_map == iomap)) {
					r_io_map_set_name (iomap, r_str_get_fail (mapcore->file, "[stack]"));
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

R_API RIODesc *r_core_file_open_many(RCore *r, const char *file, int perm, ut64 loadaddr) {
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
		r_core_bin_load (r, fd->name, loadaddr);
	}
	return NULL;
}

/* loadaddr is r2 -m (mapaddr) */
R_API RIODesc *r_core_file_open(RCore *r, const char *file, int flags, ut64 loadaddr) {
	r_return_val_if_fail (r && file, NULL);
	ut64 prev = r_time_now_mono ();
	const bool openmany = r_config_get_i (r->config, "file.openmany");

	if (!strcmp (file, "-")) {
		file = "malloc://512";
	}
	//if not flags was passed open it with -r--
	if (!flags) {
		flags = R_PERM_R;
	}
	r->io->bits = r->rasm->bits; // TODO: we need an api for this
	RIODesc *fd = r_io_open_nomap (r->io, file, flags, 0644);
	if (r_cons_is_breaked()) {
		goto beach;
	}
	if (!fd && openmany) {
		// XXX - make this an actual option somewhere?
		fd = r_core_file_open_many (r, file, flags, loadaddr);
		if (fd) {
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
		fd = NULL;
		goto beach;
	}

	{
		const char *cp = r_config_get (r->config, "cmd.open");
		if (cp && *cp) {
			r_core_cmd (r, cp, 0);
		}
	}

	r_io_use_fd (r->io, fd->fd);

	if (r_config_get_b (r->config, "cfg.debug")) {
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
	r->times->file_open_time = r_time_now_mono () - prev;
	return fd;
}
