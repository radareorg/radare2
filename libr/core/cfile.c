/* radare - LGPL - Copyright 2009-2023 - pancake */

#define R_LOG_ORIGIN "cfile"
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

static bool its_a_mips(RCore *core) {
	RArchConfig *cfg = core->rasm->config;
	return cfg && cfg->arch && !strcmp (cfg->arch, "mips");
}

static void loadGP(RCore *core) {
	// R2R db/cmd/cmd_eval
	if (its_a_mips (core)) {
		ut64 e0 = r_num_math (core->num, "entry0");
		ut64 gp = r_num_math (core->num, "loc._gp");
		if ((!gp || gp == UT64_MAX) && (e0 && e0 != UT64_MAX)) {
			r_core_cmd0 (core, "aeim; s entry0;dr PC=entry0");
			r_config_set (core->config, "anal.roregs", "zero"); // gp is writable here
			r_core_cmd0 (core, "10aes");
			gp = r_reg_getv (core->anal->reg, "gp");
			r_core_cmd0 (core, "dr0;aeim");
			r_reg_setv (core->anal->reg, "gp", gp);
			r_config_set (core->config, "anal.roregs", "zero,gp");
		}
		R_LOG_DEBUG ("[mips] gp: 0x%08"PFMT64x, gp);
		r_config_set_i (core->config, "anal.gp", gp);
	}
}

R_API bool r_core_file_reopen(RCore *core, const char *args, int perm, int loadbin) {
	const bool isdebug = r_config_get_b (core->config, "cfg.debug");
	char *path;
	ut64 laddr = r_config_get_i (core->config, "bin.laddr");
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
		R_LOG_ERROR ("Cannot reopen in sandbox");
		free (obinfilepath);
		return false;
	}
	if (!odesc) {
		R_LOG_ERROR ("No file opened to reopen");
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
		R_LOG_ERROR ("Unknown file path");
		free (obinfilepath);
		return false;
	}

	// HACK: move last mapped address to higher place
	// XXX - why does this hack work?
	// when the new memory maps are created.
	path = r_str_trim_dup (ofilepath);
	free (obinfilepath);
	obinfilepath = r_str_trim_dup (ofilepath);

	RIODesc *file = r_core_file_open (core, path, perm, laddr);
	if (isdebug) {
		int newtid = newpid;
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
		R_LOG_INFO ("File %s reopened in %s mode", path, (perm & R_PERM_W)? "read-write": "read-only");
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
				R_LOG_ERROR ("Failed to reload rbin for: %s", path);
			}
			origoff = r_num_math (core->num, "entry0");
		}

		if (core->bin->cur && core->io && r_io_desc_get (core->io, file->fd) && !loadbin) {
			//force here NULL because is causing uaf look this better in future XXX @alvarofe
			core->bin->cur = NULL;
		}
		// close old file
	} else if (odesc) {
		R_LOG_ERROR ("Cannot reopen file: %s with perms 0x%x, attempting to open read-only", path, perm);
		// lower it down back
		//ofile = r_core_file_open (core, path, R_PERM_R, addr);
	} else {
		R_LOG_ERROR ("Cannot reopen");
	}
	if (core->io->desc) {
		core->switch_file_view = 1;
		r_core_block_read (core);
	}
	r_core_seek (core, origoff, true);
	if (isdebug) {
		r_core_cmd0 (core, ".dm*");
		r_core_cmd0 (core, ".dr*");
		r_core_cmd_call (core, "sr PC");
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
	r_sys_setenv ("R2_UTF8", NULL);

	// remove temporary R2_CONFIG file
	char *r2_config = r_sys_getenv ("R2_CONFIG");
	if (r2_config) {
		r_file_rm (r2_config);
		r_sys_setenv ("R2_CONFIG", NULL);
		free (r2_config);
	}
}

R_API char *r_core_sysenv_begin(RCore *core, const char *cmd) {
	char *f, *ret = cmd? strdup (cmd): NULL;
	RIODesc *desc = core->io->desc;
	if (cmd && strstr (cmd, "R2_BYTES")) {
		char *s = r_hex_bin2strdup (core->block, core->blocksize);
		r_sys_setenv ("R2_BYTES", s);
		free (s);
	}
	r_strf_buffer (64);
	r_sys_setenv ("RABIN2_PDBSERVER", r_config_get (core->config, "pdb.server"));
	if (desc && desc->name) {
		r_sys_setenv ("R2_FILE", desc->name);
		r_sys_setenv ("R2_SIZE", r_strf ("%"PFMT64d, r_io_desc_size (desc)));
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
	r_sys_setenv ("R2PM_LEGACY", "0");
	r_sys_setenv ("R2_OFFSET", r_strf ("%"PFMT64d, core->offset));
	r_sys_setenv ("R2_XOFFSET", r_strf ("0x%08"PFMT64x, core->offset));
	r_sys_setenv ("R2_ENDIAN", R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config)? "big": "little");	//XXX
	r_sys_setenv ("R2_BSIZE", r_strf ("%d", core->blocksize));
#if 0
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
#endif
	r_sys_setenv ("RABIN2_LANG", r_config_get (core->config, "bin.lang"));
	r_sys_setenv ("RABIN2_DEMANGLE", r_config_get (core->config, "bin.demangle"));
	r_sys_setenv ("R2_ARCH", r_config_get (core->config, "asm.arch"));
	r_sys_setenv ("R2_BITS", r_strf ("%"PFMT64u, r_config_get_i (core->config, "asm.bits")));
	char *s = sdb_itoas (r_config_get_i (core->config, "scr.color"), 10);
	r_sys_setenv ("R2_COLOR", s);
	free (s);
	r_sys_setenv ("R2_UTF8", r_config_get_b (core->config, "scr.utf8")? "1": "0");
	r_sys_setenv ("R2_DEBUG", r_config_get_b (core->config, "cfg.debug")? "1": "0");
	r_sys_setenv ("R2_IOVA", r_config_get_b (core->config, "io.va")? "1": "0");
#if 0
	free (config_sdb_path);
#endif
	return ret;
}

#if !__linux__ && !R2__WINDOWS__
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
			if (file) {
				if (map->file && !strcmp (map->file, file)) {
					return map->addr;
				}
				if (map->name && !strcmp (map->name, file)) {
					return map->addr;
				}
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
	R_LOG_ERROR ("Cannot set breakpoint at %s", sym);
	return false;
}
#endif

// XXX - need to handle index selection during debugging
static int r_core_file_do_load_for_debug(RCore *r, ut64 baseaddr, R_NULLABLE const char *filenameuri) {
	RIODesc *desc = r->io->desc;
	RBinFile *binfile = NULL;
	RBinPlugin *plugin;
	int xtr_idx = 0; // if 0, load all if xtr is used

	// TODO : Honor file.path eval var too?
	if (filenameuri && r_str_startswith (filenameuri, "dbg://")) {
		filenameuri += 6;
	}
	if (!desc) {
		return false;
	}
	int fd = desc->fd;
	r_debug_select (r->dbg, r_io_fd_get_pid (r->io, fd),
			r_io_fd_get_tid (r->io, fd));
#if !__linux__
#if !R2__WINDOWS__
	baseaddr = get_base_from_maps (r, filenameuri);
#endif
	if (baseaddr != UT64_MAX) {
		r_config_set_i (r->config, "bin.baddr", baseaddr);
	}
#endif
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, fd, baseaddr, UT64_MAX, false);
	opt.xtr_idx = xtr_idx;
	if (!r_bin_open (r->bin, filenameuri, &opt)) {
		R_LOG_ERROR ("bin.open failed %s", filenameuri);
		if (r_config_get_b (r->config, "bin.str.raw")) {
			r_bin_file_options_init (&opt, fd, baseaddr, UT64_MAX, true);
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
	const char *plugin_name = plugin? plugin->meta.name: "";
	if (!strcmp (plugin_name, "any")) {
		// set use of raw strings
		// r_config_set_i (r->config, "io.va", false);
		// r_config_set_b (r->config, "bin.str.raw", true);
		// get bin.str.min
		r->bin->minstrlen = r_config_get_i (r->config, "bin.str.min");
		r->bin->maxstrbuf = r_config_get_i (r->config, "bin.str.maxbuf");
	} else if (binfile) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (plugin && info) {
			r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
		}
	}
	if (!strcmp (plugin_name, "dex")) {
		r_core_cmd0 (r, "'(fix-dex;wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)");
	}

	return true;
}

static int r_core_file_do_load_for_io_plugin(RCore *r, ut64 baseaddr, ut64 loadaddr) {
	RIODesc *cd = r->io->desc;
	int fd = cd ? cd->fd : -1;
	int xtr_idx = 0; // if 0, load all if xtr is used
	RBinPlugin *plugin;

	if (fd < 0) {
		return false;
	}
	R_CRITICAL_ENTER (r);
	r_io_use_fd (r->io, fd);
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, fd, baseaddr, loadaddr, r->bin->rawstr);
	// opt.fd = fd;
	opt.xtr_idx = xtr_idx;
	if (!r_bin_open_io (r->bin, &opt)) {
		R_CRITICAL_LEAVE (r);
		return false;
	}
	RBinFile *binfile = r_bin_cur (r->bin);
	if (r_core_bin_set_env (r, binfile)) {
		if (r->anal->verbose && !sdb_const_get (r->anal->sdb_cc, "default.cc", 0)) {
			R_LOG_WARN ("No calling convention defined for this file, analysis may be inaccurate");
		}
	}
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && !strcmp (plugin->meta.name, "any")) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (!info) {
			R_CRITICAL_LEAVE (r);
			return false;
		}
		info->bits = r->rasm->config->bits;
		// set use of raw strings
		r_core_bin_set_arch_bits (r, binfile->file, info->arch, info->bits);
		// r_config_set_i (r->config, "io.va", false);
		// r_config_set_b (r->config, "bin.str.raw", true);
		// get bin.str.min
		r->bin->minstrlen = r_config_get_i (r->config, "bin.str.min");
		r->bin->maxstrbuf = r_config_get_i (r->config, "bin.str.maxbuf");
	} else if (binfile) {
		RBinObject *obj = r_bin_cur_object (r->bin);
		RBinInfo *info = obj? obj->info: NULL;
		if (!info) {
			R_CRITICAL_LEAVE (r);
			return false;
		}
		if (plugin) {
			r_core_bin_set_arch_bits (r, binfile->file,
				info->arch, info->bits);
		}
	}

	if (plugin && !strcmp (plugin->meta.name, "dex")) {
		r_core_cmd0 (r, "'(fix-dex;wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)");
	}
	R_CRITICAL_LEAVE (r);
	return true;
}

static bool try_loadlib(RCore *core, const char *lib, ut64 addr) {
	void *p = r_core_file_open (core, lib, 0, addr);
	if (p) {
		r_core_bin_load (core, lib, addr);
		return true;
	}
	return false;
}

R_API bool r_core_file_loadlib(RCore *core, const char *lib, ut64 libaddr) {
	const char *dirlibs = r_config_get (core->config, "dir.libs");
#ifdef R2__WINDOWS__
	char *libdir = r_str_r2_prefix (R2_LIBDIR);
	if (!libdir) {
		libdir = strdup (R2_LIBDIR);
	}
#else
	char *libdir = strdup (R2_LIBDIR);
#endif
	if (!dirlibs || !*dirlibs) {
		dirlibs = "." R_SYS_DIR;
	}
	const char *ldlibrarypath[] = {
		dirlibs,
		libdir,
#ifndef R2__WINDOWS__
		"/usr/local/lib",
		"/usr/lib",
		"/lib",
#endif
		"." R_SYS_DIR,
		NULL
	};
	const char * *libpath = (const char * *) &ldlibrarypath;

	bool ret = false;
#ifdef R2__WINDOWS__
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
	free (libdir);
	return ret;
}

#if 0
static void load_scripts_for(RCore *core, const char *name) {
	// imho nobody uses this: run scripts depending on a specific filetype
	char *file;
	RListIter *iter;
	char *hdir = r_str_newf (R_JOIN_2_PATHS (R2_HOME_BINRC, "bin-%s"), name);
	char *path = r_file_home (hdir);
	RList *files = r_sys_dir (path);
	if (!r_list_empty (files)) {
		R_LOG_INFO ("[binrc] path: %s", path);
	}
	r_list_foreach (files, iter, file) {
		if (*file && *file != '.') {
			R_LOG_INFO ("[binrc] loading %s", file);
			r_core_cmdf (core, ". %s/%s", path, file);
		}
	}
	r_list_free (files);
	free (path);
	free (hdir);
}
#endif

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
		RBinSymbol *sym;
		RVecRBinSymbol *symbols = r_bin_file_get_symbols_vec (bf);
		R_VEC_FOREACH (symbols, sym) {
			if (!strcmp (sym->name, ld->name)) {
				ld->addr = sym->vaddr;
				return false;
			}
		}
	}
	return true;
}

R_API bool r_core_bin_load(RCore *r, const char *filenameuri, ut64 baddr) {
	r_return_val_if_fail (r && r->io, false);
	R_CRITICAL_ENTER (r);
	ut64 laddr = r_config_get_i (r->config, "bin.laddr");
	RBinFile *binfile = NULL;
	RBinPlugin *plugin = NULL;
	RIODesc *desc = r->io->desc;
	if (!desc && filenameuri) {
		desc = r_io_desc_get_byuri (r->io, filenameuri);
	}
	if (!desc) {
		// hack for openmany handlers
		if (!filenameuri || *filenameuri == '-') {
			// filenameuri = "malloc://512";
			R_CRITICAL_LEAVE (r);
			return false;
		}
		r_core_file_open (r, filenameuri, 0, baddr);
		desc = r->io->desc;
	}
	bool is_io_load = false;
	if (desc && desc->plugin) {
		is_io_load = true;
	//	r_io_use_fd (r->io, desc->fd);
	}
	r->bin->minstrlen = r_config_get_i (r->config, "bin.str.min");
	r->bin->maxstrbuf = r_config_get_i (r->config, "bin.str.maxbuf");
	R_CRITICAL_LEAVE (r);
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
	if (r->bin->cur && r->bin->cur->bo && r->bin->cur->bo->plugin && r->bin->cur->bo->plugin->strfilter) {
		char msg[2];
		msg[0] = r->bin->cur->bo->plugin->strfilter;
		msg[1] = 0;
		r_config_set (r->config, "bin.str.filter", msg);
	}
	plugin = r_bin_file_cur_plugin (binfile);
#if 0
	//r_core_bin_set_env (r, binfile);
	if (plugin && plugin->name) {
		load_scripts_for (r, plugin->name);
	}
#endif
	r_core_bin_export_info (r, R_MODE_SET);
	const char *cmd_load = r_config_get (r->config, "cmd.load");
	if (R_STR_ISNOTEMPTY (cmd_load)) {
		r_core_cmd (r, cmd_load, 0);
	}

	if (plugin && plugin->meta.name) {
		if (!strcmp (plugin->meta.name, "any")) {
			ut64 size = (desc->name && (r_str_startswith (desc->name, "rap") && strstr (desc->name, "://")))
				? UT64_MAX : r_io_desc_size (desc);
			r_io_map_add (r->io, desc->fd, desc->perm, 0, laddr, size);
			// set use of raw strings
			// r_config_set_b (r->config, "bin.str.raw", true);
			// r_config_set_b (r->config, "io.va", false);
			// get bin.str.min
			r->bin->minstrlen = r_config_get_i (r->config, "bin.str.min");
			r->bin->maxstrbuf = r_config_get_i (r->config, "bin.str.maxbuf");
		} else if (binfile) {
			RBinObject *obj = r_bin_cur_object (r->bin);
			if (obj) {
				bool va = obj->info ? obj->info->has_va : 0;
				if (!va) {
					r_config_set_i (r->config, "io.va", 0);
				}
				//workaround to map correctly malloc:// and raw binaries
				if (r_io_desc_is_dbg (desc) || (!obj->sections || !va)) {
					r_io_map_add (r->io, desc->fd, desc->perm, 0, laddr, r_io_desc_size (desc));
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
		bool basemap = r_config_get_b (r->config, "io.basemap");
		if (desc && basemap) {
			r_io_map_add (r->io, desc->fd, desc->perm, 0, laddr, r_io_desc_size (desc));
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
	if (plugin && plugin->meta.name && !strcmp (plugin->meta.name, "dex")) {
		r_core_cmd0 (r, "'(fix-dex;wx `ph sha1 $s-32 @32` @12;wx `ph adler32 $s-12 @12` @8)");
	}
	if (!r_config_get_b (r->config, "cfg.debug")) {
		loadGP (r);
	}
	if (r_config_get_b (r->config, "bin.libs")) {
		const char *lib;
		RListIter *iter;
		RList *libs = r_bin_get_libs (r->bin);
		r_list_foreach (libs, iter, lib) {
			if (file_is_loaded (r, lib)) {
				continue;
			}
			R_LOG_INFO ("[bin.libs] Opening %s", lib);
			ut64 baddr = (r->io->bits == 64)? 0x60000000000LL: 0x60000000;	// do we really need io->bits?
			if (r_io_map_locate (r->io, &baddr, 0x200000, 1)) {
				r_core_file_loadlib (r, lib, baddr);
			}
		}
		r_core_cmd0 (r, "obb 0;s entry0");
		r_config_set_i (r->config, "bin.at", true);
		R_LOG_INFO ("[bin.libs] Linking imports");
		RBinImport *imp;
		const RList *imports = r_bin_get_imports (r->bin);
		r_list_foreach (imports, iter, imp) {
			// PLT finding
			char *flagname = r_str_newf ("sym.imp.%s", imp->name);
			RFlagItem *impsym = r_flag_get (r->flags, flagname);
			free (flagname);
			if (!impsym) {
				//R_LOG_ERROR ("Cannot find '%s' import in the PLT", imp->name);
				continue;
			}
			ut64 imp_addr = impsym->offset;
			eprintf ("Resolving %s... ", imp->name);
			RCoreLinkData linkdata = {imp->name, UT64_MAX, r->bin};
			r_id_storage_foreach (r->io->files, linkcb, &linkdata);
			if (linkdata.addr != UT64_MAX) {
				eprintf ("0x%08"PFMT64x, linkdata.addr);
				ut64 a = linkdata.addr;
				ut64 b = imp_addr;
				r_core_cmdf (r, "ax 0x%08"PFMT64x" 0x%08"PFMT64x, a, b);
			}
		}
	}

	//If type == R_BIN_TYPE_CORE, we need to create all the maps
	if (plugin && binfile && plugin->file_type && plugin->file_type (binfile) == R_BIN_TYPE_CORE) {
		ut64 sp_addr = (ut64)-1;
		RIOMap *stack_map = NULL;
		// Setting the right arch and bits, so regstate will be shown correctly
		if (plugin->info) {
			RBinInfo *inf = plugin->info (binfile);
			R_LOG_INFO ("Setting up coredump arch-bits to: %s-%d", inf->arch, inf->bits);
			r_config_set (r->config, "asm.arch", inf->arch);
			r_config_set_i (r->config, "asm.bits", inf->bits);
			r_bin_info_free (inf);
		}
		if (binfile->bo->regstate) {
			if (r_reg_arena_set_bytes (r->anal->reg, binfile->bo->regstate)) {
				R_LOG_INFO ("Setting up coredump: Problem while setting the registers");
			} else {
				R_LOG_INFO ("Setting up coredump: Registers have been set");
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

		RBinObject *o = binfile->bo;
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
		R_LOG_INFO ("Setting up coredump: %d maps have been found and created", map);
		goto beach;
	}
beach:
	if (r_config_get_b (r->config, "bin.dbginfo") && R_STR_ISNOTEMPTY (filenameuri)) {
		// load companion dwarf files
		const char *basename = r_file_basename (filenameuri);
		char *macdwarf = r_str_newf ("%s.dSYM/Contents/Resources/DWARF/%s", filenameuri, basename);
		if (r_file_exists (macdwarf)) {
			// RBinObject *obj = r_bin_cur_object (r->bin);
			// ut64 nbaddr = obj? obj->baddr: baddr;
			r_core_cmd_callf (r, "o %s", macdwarf);
			r_core_cmd_call (r, "obm-");
			// r_core_cmd_callf (r, "o-."); // causes uaf
		}
		free (macdwarf);
	}

	r_flag_space_set (r->flags, "*");
	return true;
}

R_API RIODesc *r_core_file_open_many(RCore *r, const char *file, int perm, ut64 loadaddr) {
	RIODesc *fd;

	RList *list_fds = r_io_open_many (r->io, file, perm, 0644);

	if (!list_fds || r_list_length (list_fds) == 0) {
		r_list_free (list_fds);
		return NULL;
	}
	RListIter *iter;
	RIODesc *first = NULL;
	bool incloadaddr = loadaddr == 0;
	// r_config_set_b (r->config, "io.va", false);
	r_list_foreach (list_fds, iter, fd) {
		if (fd->uri) {
			if (!first) {
				first = fd;
			}
			r_io_use_fd (r->io, fd->fd);
			// r_core_file_open (r, fd->uri, perm, loadaddr);
			ut64 sz = r_io_fd_size (r->io, fd->fd);
			r_core_bin_load (r, fd->uri, loadaddr);
			if (incloadaddr && sz != UT64_MAX) {
				const int rest = (sz % 4096);
				const int pillow = 0x4000;
				loadaddr += sz + rest + pillow;
			}
			r_esil_setup (r->anal->esil, r->anal, 0, 0, false);
		}
	}
	return first;
}

/* loadaddr is r2 -m (mapaddr) */
R_API RIODesc *r_core_file_open(RCore *r, const char *file, int flags, ut64 loadaddr) {
	r_return_val_if_fail (r && file, NULL);
	ut64 prev = r_time_now_mono ();

	if (!strcmp (file, "-")) {
		file = "malloc://512";
	}
	//if not flags was passed open it with -r--
	if (!flags) {
		flags = R_PERM_R;
	}
	r->io->bits = r->rasm->config->bits; // TODO: we need an api for this
	RIODesc *fd = r_io_open_nomap (r->io, file, flags, 0644);
	if (r_cons_is_breaked()) {
		goto beach;
	}
	if (!fd) {
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

	r_esil_setup (r->anal->esil, r->anal, 0, 0, false);
	if (r_config_get_b (r->config, "cfg.debug")) {
		bool swstep = true;
		if (r->dbg->current && r->dbg->current->plugin.canstep) {
			swstep = false;
		}
		r_config_set_b (r->config, "dbg.swstep", swstep);
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
