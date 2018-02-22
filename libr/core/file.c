/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_core.h>
#include <stdlib.h>
#include <string.h>

#define UPDATE_TIME(a) r->times->file_open_time = r_sys_now () - a

static int r_core_file_do_load_for_debug(RCore *r, ut64 loadaddr, const char *filenameuri);
static int r_core_file_do_load_for_io_plugin(RCore *r, ut64 baseaddr, ut64 loadaddr);

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
			perm = 4; //R_IO_READ;
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
	if (file) {
		bool had_rbin_info = false;

		if (ofile) {
			if (r_bin_file_delete (core->bin, ofile->fd)) {
				had_rbin_info = true;
			}
		}
		r_core_file_close (core, ofile);
		r_core_file_set_by_file (core, file);
		ofile = NULL;
		odesc = NULL;
		//	core->file = file;
		eprintf ("File %s reopened in %s mode\n", path,
			(perm & R_IO_WRITE)? "read-write": "read-only");

		if (loadbin && (loadbin == 2 || had_rbin_info)) {
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			ret = r_core_bin_load (core, obinfilepath, baddr);
			r_core_bin_update_arch_bits (core);
			if (!ret) {
				eprintf ("Error: Failed to reload rbin for: %s", path);
			}
		}

		if (core->bin->cur && core->io && r_io_desc_get (core->io, file->fd) && !loadbin) {
			//force here NULL because is causing uaf look this better in future XXX @alvarofe
			core->bin->cur = NULL;
		}
		// close old file
	} else if (ofile) {
		eprintf ("r_core_file_reopen: Cannot reopen file: %s with perms 0x%04x,"
			" attempting to open read-only.\n", path, perm);
		// lower it down back
		//ofile = r_core_file_open (core, path, R_IO_READ, addr);
		r_core_file_set_by_file (core, ofile);
	} else {
		eprintf ("Cannot reopen\n");
	}
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
#pragma message ("fix debugger-concept in core")
#if __WINDOWS__
			r_debug_select (core->dbg, newpid, newtid);
			core->dbg->reason.type = R_DEBUG_REASON_NONE;
#endif
		}
		//reopen and attach
		r_core_setup_debugger (core, "native", true);
		r_debug_select (core->dbg, newpid, newtid);
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
		ut64 gp = r_num_math (core->num, "loc._gp");
		if (gp && gp != UT64_MAX) {
			r_config_set_i (core->config, "anal.gp", gp);
		}
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

// NOTE: probably not all environment vars takes sesnse
// because they can be replaced by commands in the given
// command.. we should only expose the most essential and
// unidirectional ones.
R_API void r_core_sysenv_help(const RCore *core) {
	const char *help_msg[] = {
		"Usage:", "!<cmd>", "  Run given command as in system(3)",
		"!", "", "list all historic commands",
		"!", "ls", "execute 'ls' in shell",
		"!!", "", "save command history to hist file",
		"!!", "ls~txt", "print output of 'ls' and grep for 'txt'",
		".!", "rabin2 -rpsei ${FILE}", "run each output line as a r2 cmd",
		"!", "echo $SIZE", "display file size",
		"!-", "", "clear history in current session",
		"!-*", "", "clear and save empty history log",
		"!=!", "", "enable remotecmd mode",
		"=!=", "", "disable remotecmd mode",
		"\nEnvironment:", "", "",
		"R2_FILE", "", "file name",
		"R2_OFFSET", "", "10base offset 64bit value",
		"R2_BYTES", "", "TODO: variable with bytes in curblock",
		"R2_XOFFSET", "", "same as above, but in 16 base",
		"R2_BSIZE", "", "block size",
		"R2_ENDIAN", "", "'big' or 'little'",
		"R2_IOVA", "", "is io.va true? virtual addressing (1,0)",
		"R2_DEBUG", "", "debug mode enabled? (1,0)",
		"R2_BLOCK", "", "TODO: dump current block to tmp file",
		"R2_SIZE", "","file size",
		"R2_ARCH", "", "value of asm.arch",
		"R2_BITS", "", "arch reg size (8, 16, 32, 64)",
		"RABIN2_LANG", "", "assume this lang to demangle",
		"RABIN2_DEMANGLE", "", "demangle or not",
		"RABIN2_PDBSERVER", "", "e pdb.server",
		NULL
	};
	r_core_cmd_help (core, help_msg);
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
		r_sys_setenv ("R2_SIZE", sdb_fmt (0, "%"PFMT64d, r_io_desc_size (desc)));
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
	r_sys_setenv ("RABIN2_LANG", r_config_get (core->config, "bin.lang"));
	r_sys_setenv ("RABIN2_DEMANGLE", r_config_get (core->config, "bin.demangle"));
	r_sys_setenv ("R2_OFFSET", sdb_fmt (0, "%"PFMT64d, core->offset));
	r_sys_setenv ("R2_XOFFSET", sdb_fmt (0, "0x%08"PFMT64x, core->offset));
	r_sys_setenv ("R2_ENDIAN", core->assembler->big_endian? "big": "little");
	r_sys_setenv ("R2_BSIZE", sdb_fmt (0, "%d", core->blocksize));
	r_sys_setenv ("R2_ARCH", r_config_get (core->config, "asm.arch"));
	r_sys_setenv ("R2_BITS", sdb_fmt (0, "%d", r_config_get_i (core->config, "asm.bits")));
	r_sys_setenv ("R2_COLOR", r_config_get_i (core->config, "scr.color")? "1": "0");
	r_sys_setenv ("R2_DEBUG", r_config_get_i (core->config, "cfg.debug")? "1": "0");
	r_sys_setenv ("R2_IOVA", r_config_get_i (core->config, "io.va")? "1": "0");
	return ret;
}

#if !__linux__
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

R_API int r_core_bin_reload(RCore *r, const char *file, ut64 baseaddr) {
	int result = 0;
	RCoreFile *cf = r_core_file_cur (r);
	RBinFile *bf = NULL;
	if (cf) {
		result = r_bin_reload (r->bin, cf->fd, baseaddr);
	}
	bf = r_bin_cur (r->bin);
	r_core_bin_set_env (r, bf);
	return result;
}

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

// XXX - need to handle index selection during debugging
static int r_core_file_do_load_for_debug(RCore *r, ut64 baseaddr, const char *filenameuri) {
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? r_io_desc_get (r->io, cf->fd) : NULL;
	RBinFile *binfile = NULL;
	RBinPlugin *plugin;
	int xtr_idx = 0; // if 0, load all if xtr is used
	int treat_as_rawstr = false;

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
	int fd = cf ? cf->fd : -1;
	if (!r_bin_load (r->bin, filenameuri, baseaddr, UT64_MAX, xtr_idx, fd, treat_as_rawstr)) {
		eprintf ("RBinLoad: Cannot open %s\n", filenameuri);
		if (r_config_get_i (r->config, "bin.rawstr")) {
			treat_as_rawstr = true;
			if (!r_bin_load (r->bin, filenameuri, baseaddr, UT64_MAX, xtr_idx, fd, treat_as_rawstr)) {
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
		RBinObject *obj = r_bin_get_object (r->bin);
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
	if (!r_bin_load_io (r->bin, fd, baseaddr, loadaddr, xtr_idx)) {
		//eprintf ("Failed to load the bin with an IO Plugin.\n");
		return false;
	}
	binfile = r_bin_cur (r->bin);
	r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && !strcmp (plugin->name, "any")) {
		RBinObject *obj = r_bin_get_object (r->bin);
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
		RBinObject *obj = r_bin_get_object (r->bin);
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

static int try_loadlib(RCore *core, const char *lib, ut64 addr) {
	RCoreFile *cf = r_core_file_open (core, lib, 0, addr);
	if (!cf) {
		return false;
	}
	return true;
}

R_API bool r_core_file_loadlib(RCore *core, const char *lib, ut64 libaddr) {
	const char *ldlibrarypath[] = {
		"/usr/local/lib",
		"/usr/lib",
		"/lib",
		"./",
		NULL
	};
	const char * *libpath = (const char * *) &ldlibrarypath;

	if (*lib == '/') {
		if (try_loadlib (core, lib, libaddr)) {
			return true;
		}
	} else {
		while (*libpath) {
			bool ret = false;
			char *s = r_str_newf ("%s/%s", *libpath, lib);
			if (try_loadlib (core, s, libaddr)) {
				ret = true;
			}
			free (s);
			if (ret) {
				return true;
			}
			libpath++;
		}
	}
	return false;
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
	char *hdir = r_str_newf (R2_HOMEDIR "/rc.d/bin-%s", name);
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

R_API bool r_core_bin_load(RCore *r, const char *filenameuri, ut64 baddr) {
	bool suppress_warning = r_config_get_i (r->config, "file.nowarn");
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? r_io_desc_get (r->io, cf->fd) : NULL;
	int va = 1;
	ut64 laddr = r_config_get_i (r->config, "bin.laddr");
	RBinFile *binfile = NULL;
	RBinPlugin *plugin = NULL;
	RBinObject *obj = NULL;
	int is_io_load;
	if (!cf) {
		return false;
	}
	// NULL deref guard
	if (desc) {
		is_io_load = desc && desc->plugin;
		if (!filenameuri || !*filenameuri) {
			filenameuri = desc->name;
		} else if (desc->name && strcmp (filenameuri, desc->name)) {
			// XXX - this needs to be handled appropriately
			// if the cf does not match the filenameuri then
			// either that RCoreFIle * needs to be loaded or a
			// new RCoreFile * should be opened.
			if (!suppress_warning) {
				eprintf ("Error: The filenameuri '%s' is not the same as in RCoreFile: %s\n",
					filenameuri, desc->name);
			}
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
			r_core_file_do_load_for_io_plugin (r, baddr, laddr);
		}
		// Restore original desc
		r_io_use_fd (r->io, desc->fd);
	}
	if (cf && binfile && desc) {
		binfile->fd = desc->fd;
	}
	binfile = r_bin_cur (r->bin);
	if (r->bin->cur && r->bin->cur->curplugin && r->bin->cur->curplugin->strfilter) {
		char msg[2];
		msg[0] = r->bin->cur->curplugin->strfilter;
		msg[1] = 0;
		r_config_set (r->config, "bin.strfilter", msg);
	}
	//r_core_bin_set_env (r, binfile);
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->name) {
		load_scripts_for (r, plugin->name);
	}

	if (plugin && plugin->name) {
		if (!strncmp (plugin->name, "any", 3)) {
			// set use of raw strings
			//r_config_set (r->config, "bin.rawstr", "true");
			// r_config_set_i (r->config, "io.va", false);
			// get bin.minstr
			r->bin->minstrlen = r_config_get_i (r->config, "bin.minstr");
			r->bin->maxstrbuf = r_config_get_i (r->config, "bin.maxstrbuf");
		} else if (binfile) {
			obj = r_bin_get_object (r->bin);
			RBinInfo *info = obj? obj->info: NULL;
			if (info) {
				r_core_bin_set_arch_bits (r, binfile->file,
						info->arch, info->bits);
			} else {
				r_core_bin_set_arch_bits (r, binfile->file,
						r_config_get (r->config, "asm.arch"),
						r_config_get_i (r->config, "asm.bits"));
			}
		}
	} else {
		if (binfile) {
			r_core_bin_set_arch_bits (r, binfile->file,
					r_config_get (r->config, "asm.arch"),
					r_config_get_i (r->config, "asm.bits"));
		}
	}
	if (desc && r_config_get_i (r->config, "io.exec")) {
		desc->flags |= R_IO_EXEC;
	}
	if (plugin && plugin->name && !strcmp (plugin->name, "dex")) {
		r_core_cmd0 (r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ;"
			" wx `ph adler32 $s-12 @12` @8)\"\n");
	}
	if (!r_config_get_i (r->config, "cfg.debug")) {
		/* load GP for mips */
		ut64 gp = r_num_math (r->num, "loc._gp");
		if (gp && gp != UT64_MAX) {
			r_config_set_i (r->config, "anal.gp", gp);
		}
	}
	if (r_config_get_i (r->config, "bin.libs")) {
		ut64 libaddr = (r->assembler->bits == 64)? 0x00007fff00000000LL: 0x7f000000;
		const char *lib;
		RListIter *iter;
		RList *libs = r_bin_get_libs (r->bin);
		r_list_foreach (libs, iter, lib) {
			eprintf ("Opening %s\n", lib);
			r_core_file_loadlib (r, lib, libaddr);
			libaddr += 0x2000000;
		}
	}
	obj = r_bin_cur_object (r->bin);
	if (obj && plugin && strcmp (plugin->name, "any")) {
		va = obj->info ? obj->info->has_va : va;
	}
	if (!va) {
		r_config_set_i (r->config, "io.va", 0);
	}
	//workaround to map correctly malloc:// and raw binaries
	if (!plugin || !strcmp (plugin->name, "any") || r_io_desc_is_dbg (desc) || (obj && (!obj->sections || !va))) {
		r_io_map_new (r->io, desc->fd, desc->flags, 0LL, laddr, r_io_desc_size (desc), true);
	}
	return true;
}

R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int flags, ut64 loadaddr) {
	bool openmany = r_config_get_i (r->config, "file.openmany");
	int opened_count = 0;
	// ut64 current_loadaddr = loadaddr;
	RCoreFile *fh; //, *top_file = NULL;
	RListIter *fd_iter, *iter2;
	RList *list_fds = NULL;
	RIODesc *fd;

	list_fds = r_io_open_many (r->io, file, flags, 0644);

	if (!list_fds || r_list_length (list_fds) == 0) {
		r_list_free (list_fds);
		return NULL;
	}

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
		fh->fd = fd->fd;
		r->file = fh;
		// XXX - load addr should be at a set offset
		//r_core_file_get_next_map (r, fh, flags, current_loadaddr);
		r_bin_bind (r->bin, &(fh->binb));
		r_list_append (r->files, fh);
		r_core_bin_load (r, fd->name, 0LL);
	}
	return NULL;
}

/* loadaddr is r2 -m (mapaddr) */
R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int flags, ut64 loadaddr) {
	ut64 prev = r_sys_now ();
	// bool suppress_warning = r_config_get_i (r->config, "file.nowarn");
	const int openmany = r_config_get_i (r->config, "file.openmany");
	const char *cp;
	RCoreFile *fh = NULL;
	RIODesc *fd;

	if (!file || !*file) {
		goto beach;
	}
	if (!strcmp (file, "-")) {
		file = "malloc://512";
	}
	//if not flags was passed open it with -r--
	if (!flags) {
		flags = R_IO_READ;
	}
	r->io->bits = r->assembler->bits; // TODO: we need an api for this
	fd = r_io_open_nomap (r->io, file, flags, 0644);
	if (!fd && openmany > 2) {
		// XXX - make this an actual option somewhere?
		fh = r_core_file_open_many (r, file, flags, loadaddr);
		if (fh) {
			goto beach;
		}
	}
	if (!fd) {
		if (flags & 2) {
			if (!r_io_create (r->io, file, 0644, 0)) {
				goto beach;
			}
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

	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp) {
		r_core_cmd (r, cp, 0);
	}
	{
		char *absfile = r_file_abspath (file);
		r_config_set (r->config, "file.path", absfile);
		free (absfile);
	}
	// check load addr to make sure its still valid
	r_bin_bind (r->bin, &(fh->binb));

	if (!r->files) {
		r->files = r_list_newf ((RListFree)r_core_file_free);
	}

	r_core_file_set_by_file (r, fh);
	r_list_append (r->files, fh);
	if (r_config_get_i (r->config, "cfg.debug")) {
		bool swstep = true;
		if (r->dbg->h && r->dbg->h->canstep) {
			swstep = false;
		}
		r_config_set_i (r->config, "dbg.swstep", swstep);
	}
	//used by r_core_bin_load otherwise won't load correctly
	//this should be argument of r_core_bin_load <shrug>
	r_config_set_i (r->config, "bin.laddr", loadaddr);
beach:
	r->times->file_open_time = r_sys_now () - prev;
	return fh;
}

R_API int r_core_files_free(const RCore *core, RCoreFile *cf) {
	if (!core || !core->files || !cf) {
		return false;
	}
	return r_list_delete_data (core->files, cf);
}

R_API void r_core_file_free(RCoreFile *cf) {
	int res = 1;
	if (!cf || !cf->core) {
		return;
	}
	res = r_core_files_free (cf->core, cf);
	//if (!res && cf && cf->alive) {
	if (res && cf->alive) {
		// double free libr/io/io.c:70 performs free
		RIO *io = cf->core->io;
		if (io) {
			r_bin_file_deref_by_bind (&cf->binb);
			r_io_fd_close (io, cf->fd);
			free (cf);
		}
	}
	cf = NULL;
}

R_API int r_core_file_close(RCore *r, RCoreFile *fh) {
	int ret;
	RIODesc *desc = fh && r ? r_io_desc_get (r->io, fh->fd) : NULL;
	RCoreFile *prev_cf = r && r->file != fh? r->file: NULL;

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
				core->io->desc->fd == f->fd ? "true": "false",
				(int) f->fd, desc->uri, (ut64) from,
				desc->flags & R_IO_WRITE? "true": "false",
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
				desc->flags & R_IO_WRITE? "rw": "r",
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
R_API int r_core_file_bin_raise(RCore *core, ut32 binfile_idx) {
	RBin *bin = core->bin;
	int v = binfile_idx > 1? binfile_idx: 1;
	RBinFile *bf = r_list_get_n (bin->binfiles, v);
	int res = false;
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
				fd, desc->uri, desc->flags & R_IO_WRITE? "rw": "r");
		}
	}
	r_core_file_set_by_file (core, cur_cf);
	//r_core_bin_bind (core, cur_bf);
	return count;
}

static bool close_but_cb (void *user, void *data, ut32 id) {
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

R_API int r_core_hash_load(RCore *r, const char *file) {
	const ut8 *md5, *sha1;
	char hash[128], *p;
	int i;
	int buf_len = 0;
	ut8 *buf = NULL;
	RHash *ctx;
	ut64 limit;
	RCoreFile *cf = r_core_file_cur (r);
	RIODesc *desc = cf ? r_io_desc_get (r->io, cf->fd) : NULL;
	if (!file && desc) {
		file = desc->name;
	}
	if (!file) {
		return false;
	}

	limit = r_config_get_i (r->config, "cfg.hashlimit");
	if (desc && r_io_desc_size (desc) > limit) {
		return false;
	}
	buf = (ut8 *) r_file_slurp (file, &buf_len);
	if (!buf) {
		return false;
	}
	ctx = r_hash_new (true, R_HASH_MD5);
	md5 = r_hash_do_md5 (ctx, buf, buf_len);
	p = hash;
	for (i = 0; i < R_HASH_SIZE_MD5; i++) {
		sprintf (p, "%02x", md5[i]);
		p += 2;
	}
	*p = 0;
	r_config_set (r->config, "file.md5", hash);
	r_hash_free (ctx);
	ctx = r_hash_new (true, R_HASH_SHA1);
	sha1 = r_hash_do_sha1 (ctx, buf, buf_len);
	p = hash;
	for (i = 0; i < R_HASH_SIZE_SHA1; i++) {
		sprintf (p, "%02x", sha1[i]);
		p += 2;
	}
	*p = 0;
	r_config_set (r->config, "file.sha1", hash);
	r_hash_free (ctx);
	free (buf);
	return true;
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

	if (!core)
		return NULL;

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
