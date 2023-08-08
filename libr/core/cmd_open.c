/* radare - LGPL - Copyright 2009-2023 - pancake */

static R_TH_LOCAL int fdsz = 0;

static RCoreHelpMessage help_msg_o = {
	"Usage: o","[file] ([offset])","Open and close files, maps, and banks",
	"o","","list opened files",
	"o"," [file] 0x4000 rwx", "map file at 0x4000",
	"o"," [file]","open [file] file in read-only",
	"o","-1","close file descriptor 1",
	"o*","","list opened files in r2 commands",
	"o+"," [file]", "open a file in read-write mode",
	"o++"," [file]", "create and open file in read-write mode (see ot and omr)",
	"o-","[?][#!*$.]","close opened files",
	"o.","","show current filename (or o.q/oq to get the fd)",
	"o:"," [len]","open a malloc://[len] copying the bytes from current offset", // XXX R2_590 - should be an alias for ':' no need for a malloc:// wrapper imho
	"o=","","list opened files (ascii-art bars)",
	"oL","","list all IO plugins registered",
	"oa","[-] [A] [B] [filename]","specify arch and bits for given file",
	"ob","[?] [lbdos] [...]","list opened binary files backed by fd",
	"oc"," [file]","open core file, like relaunching r2",
	"of","[?] [file]","open file without creating any map",
	"oe"," [filename]","open cfg.editor with given file",
	"oj","","list opened files in JSON format",
	"om","[?]","create, list, remove IO maps",
	"on","[?][n] [file] 0x4000","map raw file at 0x4000 (no r_bin involved)",
	"oo","[?][+bcdnm]","reopen current file (see oo?) (reload in rw or debugger)",
	"op","[npr] [fd]", "select priorized file by fd (see ob), opn/opp/opr = next/previous/rotate",
	"ot"," [file]", "same as `touch [file]`",
	"oq","","list all open files",
	"ox", " fd fdx", "exchange the descs of fd and fdx and keep the mapping",
	"open", " [file]", "use system xdg-open/open on a file",
	NULL
};

static RCoreHelpMessage help_msg_on = {
	"Usage: on[n+*]", "[file] ([addr] [rwx])","Open file without parsing headers",
	"on"," /bin/ls 0x4000","map raw file at 0x4000 (no r_bin involved)",
	"onn"," [file] ([rwx])","open file without creating any map or parsing headers with rbin)",
	"onnu"," [file] ([rwx])","same as onn, but unique, will return previos fd if already opened",
	"on+"," [file] ([rwx])","open file in rw mode without parsing headers",
	"on*", "", "list open files as r2 commands",
	NULL
};

static RCoreHelpMessage help_msg_o_dash = {
	"Usage: o-[#!*$.-]", "", "close opened files",
	"o-*","","close all opened files",
	"o-!","","close all files except the current one",
	"o-3","","close fd=3",
	"o-$","","close last fd",
	"o-.","","close current fd",
	"o--","","close all files, analysis, binfiles, flags, same as !r2 --",
	NULL
};

static RCoreHelpMessage help_msg_op = {
	"Usage: op[rnp]", "[fd]", "",
	"opr", "", "open next file rotating",
	"opn", "", "open next file",
	"opp", "", "open previous file",
	"op", " [fd]", "open priorizing fd",
	NULL
};

static RCoreHelpMessage help_msg_omn = {
	"Usage: omn[.i]", "([fd]) [name]", "Define a name for the given map",
	"omn", " mapaddr [name]", "set/delete name for map which spans mapaddr",
	"omn.", "([-|name])", "show/set/delete name for current map",
	"omni", " mapid [name]", "set/delete name for map with mapid",
	NULL
};

static RCoreHelpMessage help_msg_omb = {
	"Usage: omb[+-adgq]", "[fd]", "Operate on memory banks",
	"omb", "", "list all memory banks",
	"omb", " [id]", "switch to use a different bank",
	"omb+", " [name]", "create a new bank with given name",
	"omba", " [id]", "adds a map to the bank",
	"ombd", " [id]", "delete a map from the bank",
	"omb-", "*", "delete all banks",
	"omb-", " [mapid]", "delete the bank with given id",
	"ombg", "", "associate all maps to the current bank",
	"ombq", "", "show current bankid",
	NULL
};

static RCoreHelpMessage help_msg_oba = {
	"Usage: oba", "[addr] ([filename])", "Load bininfo and update flags",
	"oba", " [addr]", "open bin info from the given address",
	"oba", " [addr] [baddr]", "open file and load bin info at given address",
	"oba", " [addr] [/abs/filename]", "open file and load bin info at given address",
	NULL
};

static RCoreHelpMessage help_msg_ob = {
	"Usage: ob", "", "List open binary files backed by fd",
	"ob", " [name|bfid]", "switch to open given objid (or name)",
	"ob", "", "list opened binary files and objid",
	"ob*", "", "list opened binary files and objid (r2 commands)",
	"ob", " *", "select all bins (use 'ob bfid' to pick one)",
	"obm", "([id])", "merge current selected binfile into previous binfile (id-1)",
	"obm-", "([id])", "same as obm, but deletes the current binfile",
	"ob-", "*", "delete all binfiles",
	"ob-", "[objid]", "delete binfile by binobjid",
	"ob--", "", "delete the last binfile",
	"ob.", " ([addr])", "show bfid at current address",
	"ob=", "", "show ascii art table having the list of open files",
	"obL", "", "same as iL or Li",
	"oba", " [addr] [baddr]", "open file and load bin info at given address",
	"oba", " [addr] [filename]", "open file and load bin info at given address",
	"oba", " [addr]", "open bin info from the given address",
	"obf", " ([file])", "load bininfo for current file (useful for r2 -n)",
	"obj", "", "list opened binary files and objid (JSON format)",
	"obo", " [fd]", "switch to open binfile by fd number",
	"obr", " [baddr]", "rebase current bin object",
	NULL
};

static RCoreHelpMessage help_msg_om = {
	"Usage: om", "[arg]", "Map opened files",
	"om", " [fd]", "list all defined IO maps for a specific fd",
	"om", " fd vaddr [size] [paddr] [rwx] [name]", "create new io map",
	"om", "", "list all defined IO maps",
	"om*", "", "list all maps in r2 commands format",
	"om-", "mapid", "remove the map with corresponding id",
	"om-*", "", "remove all maps",
	"om-..", "", "hud view of all the maps to select the one to remove",
	"om.", "", "show map, that is mapped to current offset",
	"om,", " [query]", "list maps using table api",
	"om=", "", "list all maps in ascii art",
	"oma"," [fd]", "create a map covering all VA for given fd",
	"omb", " ", "list/select memory map banks",
	"omB", " mapid addr", "relocate map with corresponding id",
	"omB.", " addr", "relocate current map",
	"omd", " from to @ paddr", "simplified om; takes current seek, fd and perms",
	"omf", " [mapid] rwx", "change flags/perms for current/given map",
	"omfg", "[+-]rwx", "change flags/perms for all maps (global)",
	"omj", "", "list all maps in json format",
	"omm"," [fd]", "create default map for given fd (omm `oq`)",
	"omn", "[?] ([fd]) [name]", "manage map names",
	"omo", " fd", "map the given fd with lowest priority",
	"omp", " mapid", "prioritize map with corresponding id",
	"ompb", " [fd]", "prioritize maps of the bin associated with the binid",
	"ompd", " mapid", "deprioritize map with corresponding id",
	"ompf", " [fd]", "prioritize map by fd",
	"omq", "", "list all maps and their fds",
	"omqq", "", "list all maps addresses (See $MM to get the size)",
	"omr", " [mapid newsize]", "resize map with corresponding id",
	NULL
};

static RCoreHelpMessage help_msg_oo = {
	"Usage: oo", "[arg]", "Map opened files",
	"oo", "", "reopen current file",
	"oo+", "", "reopen in read-write",
	"oob", " [baddr]", "reopen loading rbin info (change base address?)",
	"ooc", "", "reopen core with current file",
	"ood", "[?]", "reopen in debug mode",
	"oom", "[?]", "reopen in malloc://",
	"oon", "", "reopen without loading rbin info",
	"oon+", "", "reopen in read-write mode without loading rbin info",
	"oonn", "", "reopen without loading rbin info, but with header flags",
	"oonn+", "", "reopen in read-write mode without loading rbin info, but with",
	NULL
};

static RCoreHelpMessage help_msg_ood = {
	"Usage: ood", "", "Debug (re)open commands",
	"ood", " [args]", "reopen in debug mode (with args)",
	"oodf", " [file]", "reopen in debug mode using the given file",
	"oodr", " [rarun2]", "same as dor ..;ood",
	NULL
};

static bool isfile(const char *filename) {
	return R_STR_ISNOTEMPTY (filename)
		&& (
			   r_file_exists (filename)
			|| r_str_startswith (filename, "./")
			|| r_str_startswith (filename, "/")
		);
}

// HONOR bin.at
static void cmd_open_bin(RCore *core, const char *input) {
	const char *value = NULL;
	ut32 binfile_num = -1;

	switch (input[1]) {
	case 'L': // "obL"
		r_core_cmd0 (core, "iL");
		break;
	case '\0': // "ob"
	case 'q': // "obj"
	case 'j': // "obj"
	case '*': // "ob*"
		r_core_bin_list (core, input[1]);
		if (input[1] == 'j') {
			r_cons_newline ();
		}
		break;
	case '.': // "ob."
		{
			const char *arg = r_str_trim_head_ro (input + 2);
			ut64 at = core->offset;
			if (*arg) {
				at = r_num_math (core->num, arg);
				if (at == 0 && *arg != '0') {
					at = core->offset;
				}
			}
			RBinFile *bf = r_bin_file_at (core->bin, at);
			if (bf) {
				r_cons_printf ("%d\n", bf->id);
			}
		}
		break;
	case 'a': // "oba"
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_oba);
			break;
		}
		if (input[2] && input[3]) {
			char *arg = strdup (input + 3);
			char *filename = strchr (arg, ' ');
			if (filename && isfile (filename + 1)) {
				int saved_fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_open (core->io, filename + 1, R_PERM_RX, 0);
				if (desc) {
					*filename = 0;
					ut64 addr = r_num_math (core->num, arg);
					RBinFileOptions opt;
					r_bin_file_options_init (&opt, desc->fd, addr, 0, core->bin->rawstr);
					r_bin_open_io (core->bin, &opt);
					r_core_bin_load (core, NULL, UT64_MAX);
					r_core_cmd0 (core, ".is*");
					r_io_desc_close (desc);
					r_io_use_fd (core->io, saved_fd);
				} else {
					R_LOG_ERROR ("Cannot open '%s'", r_str_trim_head_ro (filename + 1));
				}
			} else if (R_STR_ISNOTEMPTY (filename)) {
				ut64 baddr = r_num_math (core->num, filename);
				ut64 addr = r_num_math (core->num, input + 2); // mapaddr
				int fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					RBinFileOptions opt;
					opt.baseaddr = baddr;
					opt.loadaddr = addr;
					opt.sz = 1024 * 1024 * 1;
					r_bin_file_options_init (&opt, desc->fd, baddr, addr, core->bin->rawstr);
					r_bin_open_io (core->bin, &opt);
					r_core_cmd0 (core, ".is*");
				} else {
					R_LOG_ERROR ("No file to load bin from?");
				}
			} else {
				ut64 addr = r_num_math (core->num, input + 2);
				int fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					RBinFileOptions opt;
					opt.baseaddr = addr;
					opt.loadaddr = addr;
					opt.sz = 1024 * 1024 * 1;
					r_bin_file_options_init (&opt, desc->fd, addr, addr, core->bin->rawstr);
					r_bin_open_io (core->bin, &opt);
					r_core_cmd0 (core, ".is*");
				} else {
					R_LOG_ERROR ("No file to load bin from?");
				}
			}
			free (arg);
		} else {
			RList *ofiles = r_id_storage_list (core->io->files);
			RIODesc *desc;
			RListIter *iter;
			RList *files = r_list_newf (NULL);
			r_list_foreach (ofiles, iter, desc) {
				r_list_append (files, (void*)(size_t)desc->fd);
			}

			void *_fd;
			r_list_foreach (files, iter, _fd) {
				int fd = (size_t)_fd;
				RBinFileOptions opt;
				r_bin_file_options_init (&opt, fd, core->offset, 0, core->bin->rawstr);
				r_bin_open_io (core->bin, &opt);
				r_core_cmd0 (core, ".ies*");
				break;
			}
			r_list_free (files);
		}
		break;
	case ' ': // "ob " // select bf by id or name
	{
		ut32 id;
		const char *tmp;
		if (input[2] == '-' || input[2] == '*') {
			core->allbins = true;
			break;
		}
		core->allbins = false;

		char *v = input[2] ? strdup (input + 2) : NULL;
		if (!v) {
			R_LOG_ERROR ("Invalid arguments");
			break;
		}
		int n = r_str_word_set0 (v);
		if (n < 1 || n > 2) {
			r_core_cmd_help_match (core, help_msg_o, "ob", true);
			free (v);
			break;
		}
		tmp = r_str_word_get0 (v, 0);
		id = *v && r_is_valid_input_num_value (core->num, tmp)
			? r_get_input_num_value (core->num, tmp): UT32_MAX;
		if (n == 2) {
			tmp = r_str_word_get0 (v, 1);
		} else {
			binfile_num = id;
		}
		r_core_bin_raise (core, binfile_num);
		free (v);
		break;
	}
	case 'r': // "obr"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_ob, "obr", true);
		} else {
			r_core_bin_rebase (core, r_num_math (core->num, input + 3));
			r_core_cmd0 (core, ".is*");
		}
		break;
	case 'f': // "obf"
		if (input[2] == ' ') {
			r_core_cmdf (core, "oba 0 %s", input + 3);
		} else {
			r_core_bin_load (core, NULL, UT64_MAX);
			value = input[2] ? input + 2 : NULL;
		}
		break;
	case 'm': // "obm"
		{
			int dstid = atoi (input + 2);
			// TODO take argument with given id to merge to
			RBinFile *src = r_bin_cur (core->bin);
			int current = src? src->id: -1;
			if (current > 0) {
				if (dstid < 1) {
					dstid = current - 1;
				}
				RBinFile *dst = r_bin_file_find_by_id (core->bin, dstid);
				if (dst) {
					r_bin_file_merge (dst, src);
					R_LOG_DEBUG ("merge %d into %d", current, dstid);
					if (strchr (input + 2, '-')) { // "obm-"
						int curfd = -1;
						if (core->io->desc) {
							curfd = core->io->desc->fd;
						}
						r_core_cmd_callf (core, "op %d", dst->fd);
						r_bin_file_set_cur_binfile (core->bin, dst);
						r_bin_file_delete (core->bin, current);
						if (curfd >= 0) {
							r_io_fd_close (core->io, curfd);
							// r_core_cmd_callf (core, "o-%d", curfd);
						}
					}
					break;
				} else {
					R_LOG_ERROR ("Cannot find binfile with id=%d", dstid);
				}
			}
			R_LOG_INFO ("Nothing to merge");
		}
		break;
	case 'o': // "obo"
		if (input[2] == ' ') {
			ut32 fd = r_num_math (core->num, input + 3);
			RBinFile *bf = r_bin_file_find_by_fd (core->bin, fd);
			if (!bf || !r_core_bin_raise (core, bf->id)) {
				R_LOG_ERROR ("Invalid RBinFile.id number");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_ob, "obo", true);
		}
		break;
	case '-': // "ob-"
		if (input[2] == '*') {
			r_bin_file_delete_all (core->bin);
		} else if (input[2] == '-') {
			RBinFile *bf = r_bin_cur (core->bin);
			int current = bf? bf->id: 0;
			if (current >= 0) {
				r_core_cmd_callf (core, "ob-%d", current);
				r_core_cmd_callf (core, "ob %d", current -1);
			}
		} else {
			ut32 id;
			value = r_str_trim_head_ro (input + 2);
			if (!value) {
				R_LOG_ERROR ("Invalid argument");
				break;
			}
			id = (*value && r_is_valid_input_num_value (core->num, value)) ?
					r_get_input_num_value (core->num, value) : UT32_MAX;
			RBinFile *bf = r_bin_file_find_by_id (core->bin, id);
			if (bf) {
				int bfid = bf->id;
				if (!r_core_bin_delete (core, bfid)) {
					R_LOG_ERROR ("Cannot find an RBinFile associated with id %d", bfid);
				}
			} else {
				R_LOG_ERROR ("Invalid binid");
			}
		}
		break;
	case '=': // "ob="
		{
			char temp[SDB_NUM_BUFSZ];
			RListIter *iter;
			RList *list = r_list_newf ((RListFree) r_listinfo_free);
			RBinFile *bf = NULL;
			RBin *bin = core->bin;
			if (!bin) {
				return;
			}
			r_list_foreach (bin->binfiles, iter, bf) {
				RInterval inter = (RInterval) {bf->bo->baddr, bf->bo->size};
				RListInfo *info = r_listinfo_new (bf->file, inter, inter, -1, sdb_itoa (bf->fd, 10, temp, sizeof (temp)));
				if (!info) {
					break;
				}
				r_list_append (list, info);
			}
			RTable *table = r_core_table (core, "bins");
			r_table_visual_list (table, list, core->offset, core->blocksize,
				r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
			char *table_text = r_table_tostring (table);
			if (table_text) {
				r_cons_printf ("\n%s\n", table_text);
				r_free (table_text);
			}
			r_table_free (table);
			r_list_free (list);
		} break;
	case '?': // "ob?"
		r_core_cmd_help (core, help_msg_ob);
		break;
	}
}

// TODO: discuss the output format
static void map_list(RCore *core, int mode, RPrint *print, int fd) {
	RIO *io = core->io;
	ut64 off = core->offset;
	r_return_if_fail (io && print && print->cb_printf);
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	char *om_cmds = NULL;

	bool check_for_current_map = true;
	RIOBank *bank = r_io_bank_get (io, io->bank);
	if (!bank) {
		pj_free (pj);
		return;
	}
	RIOMapRef *mapref;
	RListIter *iter;
	r_list_foreach_prev (bank->maprefs, iter, mapref) {
		RIOMap *map = r_io_map_get (io, mapref->id);
		if (fd >= 0 && map->fd != fd) {
			continue;
		}
		switch (mode) {
		case 'q':
			if (fd == -2) {
				print->cb_printf ("0x%08"PFMT64x"\n", r_io_map_begin (map));
			} else {
				print->cb_printf ("%d %d\n", map->fd, map->id);
			}
			break;
		case 'j':
			pj_o (pj);
			pj_ki (pj, "map", map->id);
			pj_ki (pj, "fd", map->fd);
			pj_kn (pj, "delta", map->delta);
			pj_kn (pj, "from", r_io_map_begin (map));
			pj_kn (pj, "to", r_io_map_to (map));
			pj_ks (pj, "perm", r_str_rwx_i (map->perm));
			pj_ks (pj, "name", r_str_get (map->name));
			pj_end (pj);
			break;
		case 1:
		case '*':
		case 'r': {
			// Need FIFO order here
			char *om_cmd = r_str_newf ("omu %d 0x%08"PFMT64x" 0x%08"PFMT64x
					" 0x%08"PFMT64x" %s%s%s\n", map->fd, r_io_map_begin (map),
					r_io_map_size (map), map->delta, r_str_rwx_i (map->perm),
					R_STR_ISEMPTY (map->name)? "": " ", r_str_get (map->name));
			if (om_cmd) {
				om_cmds = r_str_prepend (om_cmds, om_cmd);
				free (om_cmd);
			}
			break;
		}
		default:
			print->cb_printf ("%c%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s%s%s\n",
					(check_for_current_map && r_io_map_contain (map, off)) ?
					'*' : '-', map->id, map->fd, map->delta, r_io_map_begin (map),
					r_io_map_to (map), r_str_rwx_i (map->perm),
					R_STR_ISEMPTY (map->name)? "": " ",r_str_get (map->name));
			check_for_current_map &= !r_io_map_contain (map, off);
			break;
		}
	}
	if (om_cmds) {
		print->cb_printf ("%s", om_cmds);
		free (om_cmds);
	}
	if (mode == 'j') {
		pj_end (pj);
		print->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

// TODO: move into r_io_remap()
static void cmd_omfg(RCore *core, const char *input) {
	input = r_str_trim_head_ro (input);
	int perm = *input ? (*input == '+' || *input == '-')
		? r_str_rwx (input + 1)
		: r_str_rwx (input) : 7;
	ut32 mapid;
	if (!r_id_storage_get_lowest (core->io->maps, &mapid)) {
		ut32 fd = r_io_fd_get_current (core->io);
		RIODesc *desc = r_io_desc_get (core->io, fd);
		if (desc) {
			r_core_cmd0 (core, "omm");
		}
		return;
	}
	switch (*input) {
	case '+':
		do {
			RIOMap *map = r_io_map_get (core->io, mapid);
			map->perm |= perm;
		} while (r_id_storage_get_next (core->io->maps, &mapid));
		break;
	case '-':
		do {
			RIOMap *map = r_io_map_get (core->io, mapid);
			map->perm &= ~perm;
		} while (r_id_storage_get_next (core->io->maps, &mapid));
		break;
	default:
		do {
			RIOMap *map = r_io_map_get (core->io, mapid);
			map->perm = perm;
		} while (r_id_storage_get_next (core->io->maps, &mapid));
		break;
	}
}

static void cmd_omf(RCore *core, int argc, char *argv[]) {
	switch (argc) {
	case 0:
		break;
	case 1:
		{
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				map->perm = r_str_rwx (argv[0]);
			}
		}
		break;
	case 2:
	default:
		{
			const int id = r_num_math (core->num, argv[0]);
			RIOMap *map = r_io_map_get (core->io, id);
			if (map) {
				map->perm = r_str_rwx (argv[1]);
			}
		}
	}
}

static void r_core_cmd_omt(RCore *core, const char *arg) {
	RTable *t = r_table_new ("iomaps");
	if (!t) {
		return;
	}
	r_table_set_columnsf (t, "nnnnnnnss", "id", "fd", "pa", "pa_end", "size", "va", "va_end", "perm", "name", NULL);
	ut32 mapid = 0;
	r_id_storage_get_lowest (core->io->maps, &mapid);
	do {
		RIOMap *m = r_id_storage_get (core->io->maps, mapid);
		if (!m) {
			R_LOG_WARN ("Cannot find mapid %d", mapid);
			break;
		}
		ut64 va = r_itv_begin (m->itv);
		ut64 va_end = r_itv_end (m->itv);
		ut64 pa = m->delta;
		ut64 pa_size = r_itv_size (m->itv);
		ut64 pa_end = pa + pa_size;
		const char *name = r_str_get (m->name);
		r_table_add_rowf (t, "ddxxxxxss",
			m->id, m->fd, pa, pa_end, pa_size,
			va, va_end, r_str_rwx_i (m->perm), name);
	} while (r_id_storage_get_next (core->io->maps, &mapid));
	if (r_table_query (t, arg)) {
		char *ts = strchr (arg, ':')? r_table_tostring (t) : r_table_tofancystring (t);
		r_cons_printf ("%s", ts);
		free (ts);
	}
	r_table_free (t);
}

static bool cmd_om(RCore *core, const char *input, int arg) {
	char *s = r_str_trim_dup (input + 1);
	if (!s) {
		return false;
	}
	if (strchr (s, ' ')) {
		int fd = 0, rwx = 0;
		ut64 size = 0, vaddr = 0, paddr = 0;
		const char *name = NULL;
		bool rwx_arg = false;
		RIODesc *desc = NULL;
		int words = r_str_word_set0 (s);
		switch (words) {
		case 6:
			name = r_str_word_get0 (s, 5);
			// fallthrough
		case 5:
			rwx = r_str_rwx (r_str_word_get0 (s, 4));
			rwx_arg = true;
			// fallthrough
		case 4:
			paddr = r_num_math (core->num, r_str_word_get0 (s, 3));
			// fallthrough
		case 3:
			size = r_num_math (core->num, r_str_word_get0 (s, 2));
			// fallthrough
		case 2:
			vaddr = r_num_math (core->num, r_str_word_get0 (s, 1));
			// fallthrough
		case 1:
			fd = r_num_math (core->num, r_str_word_get0 (s, 0));
			break;
		}
		if (fd < 3) {
			R_LOG_ERROR ("Wrong fd, it must be greater than 3");
			return false;
		}
		desc = r_io_desc_get (core->io, fd);
		if (desc) {
			if (!size) {
				size = r_io_fd_size (core->io, fd);
			}
			bool addmap = true;
			if (arg == 'u') {
				// check if map exists before adding it
				RIOMap *map = r_io_map_get_at (core->io, vaddr);
				if (map) {
					ut64 ms = r_itv_size (map->itv);
					ut64 mp = map->delta;
					if (mp == paddr && ms == size) {
						addmap = false;
					}
				}
			}
			if (addmap) {
				RIOMap *map = r_io_map_add (core->io, fd, rwx_arg ? rwx : desc->perm, paddr, vaddr, size);
				if (map) {
					if (name) {
						r_io_map_set_name (map, name);
					}
				} else {
					R_LOG_ERROR ("Cannot add map");
				}
			}
		}
	} else {
		int fd = r_io_fd_get_current (core->io);
		if (r_io_desc_get (core->io, fd)) {
			map_list (core, 0, core->print, fd);
		} else {
			R_LOG_ERROR ("Invalid fd %d", (int)fd);
		}
	}
	free (s);
	return true;
}

static void cmd_omd(RCore *core, const char* input) {
	if (*input == '?') {
		r_core_cmd_help_match (core, help_msg_om, "omd", true);
		return;
	}
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	if (desc) {
		char *inp = r_str_trim_dup (input);
		RList *args = r_str_split_list (inp, " ", 0);
		if (args && r_list_length (args) == 2) {
			ut64 pa = core->offset;
			ut64 va = r_num_math (core->num, r_list_get_n (args, 0));
			ut64 vb = r_num_math (core->num, r_list_get_n (args, 1));
			ut64 sz = vb - va;
			RIOMap *map = NULL;
			if (va < vb) {
				map = r_io_map_add (core->io, fd, desc->perm, pa, va, sz);
			}
			if (!map) {
				R_LOG_ERROR ("Invalid map range");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_om, "omd", true);
		}
		r_list_free (args);
		r_free (inp);
	} else {
		R_LOG_ERROR ("Cannot get any fd");
	}
}

static void cmd_open_banks(RCore *core, int argc, char *argv[]) {
	if (argc == 1) {
		switch (argv[0][1]) {
		case 'g': // "ombg"
			{
				ut32 mapid;
				r_id_storage_get_lowest (core->io->maps, &mapid);
				do {
					RIOMap *map = r_id_storage_get (core->io->maps, mapid);
					r_io_bank_map_add_top (core->io, core->io->bank, map->id);
				} while (r_id_storage_get_next (core->io->maps, &mapid));
			}
			break;
		case 'q': // "ombq"
			r_cons_printf ("%d\n", core->io->bank);
			break;
		case 0: // "omb"
			{
				ut32 bank_id = 0;
				if (!r_id_storage_get_lowest (core->io->banks, &bank_id)) {
					break;
				}
				do {
					RIOBank *bank = r_id_storage_get (core->io->banks, bank_id);
					const char ch = core->io->bank == bank_id? '*': '-';
					r_cons_printf ("%c %d %s [", ch, bank->id, bank->name);
					RIOMapRef *mapref;
					RListIter *iter;
					r_list_foreach (bank->maprefs, iter, mapref) {
						r_cons_printf (" %d", mapref->id);
					}
					r_cons_printf (" ]\n");
					// list all the associated maps
				} while (r_id_storage_get_next (core->io->banks, &bank_id));
			}
			break;
		case '+': // "omb+ [name]"
			{
				const char *name = argv[0] + 2;
				if (IS_DIGIT (*name)) {
					// add a map to the current bank
					// we cant name a bank with a number :?
					r_io_bank_map_add_top (core->io, core->io->bank, atoi (name));
				} else {
					// add a new bank
					RIOBank *bank = r_io_bank_new (name);
					if (bank) {
						r_io_bank_add (core->io, bank);
					}
				}
			}
			break;
		case '?': // "omb?"
		default:
			r_core_cmd_help (core, help_msg_omb);
			break;
		}
		return;
	}
	switch (argv[0][1]) {
	case 'a': // "omba"
		if (IS_DIGIT (argv[1][0])) {
			int mapid = atoi (argv[1]);
			if (r_io_map_get (core->io, mapid)) {
				r_io_bank_map_add_top (core->io, core->io->bank, mapid);
			} else {
				R_LOG_ERROR ("Invalid map id");
			}
		} else {
			R_LOG_ERROR ("Expect a mapid number");
		}
		break;
	case 'd': // "ombd"
		{
			int mapid = atoi (argv[1]);
			RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
			if (bank) {
				r_io_bank_del_map (core->io, core->io->bank, mapid);
			} else {
				R_LOG_ERROR ("Unknown bank id");
			}
		}
		break;
	case '-': // "omb-"
		if (!strcmp ("*", argv[1])) {
			r_io_bank_drain (core->io, core->io->bank);
			core->io->bank = r_io_bank_first (core->io);
		} else {
			int bank_id = atoi (argv[1]);
			r_io_bank_del (core->io, bank_id);
		}
		break;
	case '+': // "omb+ [name]"
		{
			RIOBank *bank = r_io_bank_new (argv[1]);
			r_io_bank_add (core->io, bank);
		}
		break;
	case 0: // "omb [id]"
		{
			if (!r_io_bank_use (core->io, r_num_get (NULL, argv[1]))) {
				R_LOG_ERROR ("Cannot find bank by id %s", argv[1]);
			}
		}
		break;
	case '?': // "omb?"
	default:
		r_core_cmd_help (core, help_msg_omb);
		break;
	}
}

static void cmd_open_map(RCore *core, const char *input) {
	ut64 fd = 0LL;
	ut32 id = 0;
	ut64 addr = 0;
	char *s = NULL, *p = NULL, *q = NULL;
	ut64 newaddr;
	RIOMap *map = NULL;
	const char *P;
	PJ *pj;

	switch (input[1]) {
	case '.': // "om."
		map = r_io_map_get_at (core->io, core->offset);
		if (map) {
			if (input[2] == 'j') { // "om.j"
				pj = pj_new ();
				if (!pj) {
					return;
				}
				pj_o (pj);
				pj_ki (pj, "map", map->id);
				pj_ki (pj, "fd", map->fd);
				pj_kn (pj, "delta", map->delta);
				pj_kn (pj, "from", r_io_map_begin (map));
				pj_kn (pj, "to", r_io_map_to (map));
				pj_ks (pj, "perm", r_str_rwx_i (map->perm));
				pj_ks (pj, "name", r_str_get (map->name));
				pj_end (pj);

				core->print->cb_printf ("%s\n", pj_string (pj));

				pj_free (pj);
			} else {
				core->print->cb_printf ("%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s %s\n", map->id, map->fd,
					map->delta, r_io_map_begin (map), r_io_map_to (map),
					r_str_rwx_i (map->perm), r_str_get (map->name));
			}
		}
		break;
	case 'r': // "omr"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_om, "omr", true);
			break;
		}
		if (input[2] != ' ') {
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				r_cons_printf ("%"PFMT64d"\n", r_itv_size (map->itv));
			}
			break;
		}
		P = strchr (input + 3, ' ');
		if (P) {
			id = (ut32)r_num_math (core->num, input + 3);
			newaddr = r_num_math (core->num, P + 1);
			r_io_map_resize (core->io, id, newaddr);
		}
		break;
	case 'b': // "omb" -- manage memory banks
		{
			int argc;
			char **argv = r_str_argv (&input[1], &argc);
			cmd_open_banks (core, argc, argv);
			r_str_argv_free (argv);
		}
		break;
	case 'B': // "omB"
		if (input[2] == '.') {
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				ut64 dst = r_num_math (core->num, input + 3);
				r_io_map_remap (core->io, map->id, dst);
			}
		} else {
			if (input[2] != ' ') {
				break;
			}
			P = strchr (input + 3, ' ');
			if (P) {
				id = (ut32)r_num_math (core->num, input + 3);
				newaddr = r_num_math (core->num, P + 1);
				r_io_map_remap (core->io, id, newaddr);
			}
		}
		break;
	case 'o': // "omo"
		if (input[2] == ' ') {
			r_core_cmdf (core, "om %s 0x%08" PFMT64x " $s r omo", input + 2, core->offset);
		} else {
			r_core_cmd0 (core, "om `oq.` $B $s r");
		}
		r_core_cmd0 (core, "ompd `omq.`");
		break;
	case 'p':
		switch (input[2]) {
		case 'd': // "ompf"
			id = r_num_math (core->num, input + 3);		//mapid
			if (r_io_map_exists_for_id (core->io, id)) {
				r_io_map_depriorize (core->io, id);
			} else {
				R_LOG_ERROR ("Cannot find any map with mapid %d", id);
			}
			break;
		case 'f': // "ompf"
			fd = r_num_math (core->num, input + 3);
			if (!r_io_map_priorize_for_fd (core->io, (int)fd)) {
				R_LOG_ERROR ("Cannot prioritize any map for fd %d", (int)fd);
			}
			break;
		case 'b': // "ompb"
			id = (ut32)r_num_math (core->num, input + 4);
			if (!r_bin_file_set_cur_by_id (core->bin, id)) {
				R_LOG_ERROR ("Cannot prioritize bin with fd %d", id);
			}
			break;
		case ' ': // "omp"
			id = r_num_math (core->num, input + 3);		//mapid
			if (r_io_map_exists_for_id (core->io, id)) {
				r_io_map_priorize (core->io, id);
				r_core_block_read (core);
			} else {
				R_LOG_ERROR ("Cannot find any map with mapid %d", id);
			}
			break;
		}
		break;
	case 't': // "omt"
		R_LOG_WARN ("Deprecated. use 'om,' instead of 'omt'")
		r_core_cmd_omt (core, input + 2);
		break;
	case ',': // "om,"
		r_core_cmd_omt (core, input + 2);
		break;
	case ' ': // "om"
		cmd_om (core, input, 0);
		break;
	case 'n': // "omn"
		if (input[2] == '?') { // "omn?"
			r_core_cmd_help (core, help_msg_omn);
		} else if (input[2] == '.') { // "omn."
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				switch (input[3]) {
				case '-':
					r_io_map_del_name (map);
					break;
				case 0:
					r_cons_printf ("%s\n", map->name);
					break;
				default:
					r_io_map_set_name (map, r_str_trim_head_ro (input + 3));
					break;
				}
			}
		} else {
			bool use_id = (input[2] == 'i') ? true : false;
			s = strdup (use_id ? input + 3 : input + 2);
			if (!s) {
				break;
			}
			p = s;

			while (*s == ' ') {
				s++;
			}
			if (*s == '\0') {
				s = p;
				break;
			}
			if (!(q = strchr (s, ' '))) {
				if (use_id) {
					id = (ut32)r_num_math (core->num, s);
					map = r_io_map_get (core->io, id);
				} else {
					addr = r_num_math (core->num, s);
					map = r_io_map_get_at (core->io, addr);
				}
				r_io_map_del_name (map);
				s = p;
				break;
			}
			*q = '\0';
			q++;
			if (use_id) {
				id = (ut32)r_num_math (core->num, s);
				map = r_io_map_get (core->io, id);
			} else {
				addr = r_num_math (core->num, s);
				map = r_io_map_get_at (core->io, addr);
			}
			if (map) {
				if (*q) {
					r_io_map_set_name (map, q);
				} else {
					r_io_map_del_name (map);
				}
			}
			s = p;
		}
		break;
	case 'a': // "oma"
		{
			ut32 fd = input[2]? r_num_math (core->num, input + 2): r_io_fd_get_current (core->io);
			RIODesc *desc = r_io_desc_get (core->io, fd);
			if (desc) {
				map = r_io_map_add (core->io, fd, desc->perm, 0, 0, UT64_MAX);
				if (map) {
					r_io_map_set_name (map, desc->name);
				}
			} else {
				r_core_cmd_help_match (core, help_msg_om, "oma", false);
			}
		}
		break;
	case 'm': // "omm"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_om, "omm", false);
		} else {
			ut32 fd = input[2]? r_num_math (core->num, input + 2): r_io_fd_get_current (core->io);
			RIODesc *desc = r_io_desc_get (core->io, fd);
			if (desc) {
				ut64 size = r_io_desc_size (desc);
				map = r_io_map_add (core->io, fd, desc->perm, 0, 0, size);
				if (map && desc->name) {
					r_io_map_set_name (map, desc->name);
				}
			} else {
				R_LOG_DEBUG ("Cannot find any fd to map");
			}
		}
		break;
	case '-': // "om-"
		if (!strcmp (input + 2, "..")) {
			r_core_cmd0 (core, "om-`om~...`~[0]");
		} else if (input[2] == '*') {
			r_io_map_reset (core->io);
		} else {
			r_io_map_del (core->io, r_num_math (core->num, input + 2));
		}
		break;
	case 'u': // "omu"
		// same as "om", but checks if already exists
		cmd_om (core, input + 1, 'u');
		break;
	case 'd': // "omd"
		cmd_omd (core, input + 2);
		break;
	case 'f': // "omf"
		switch (input[2]) {
		case 'g': // "omfg"
			cmd_omfg (core, input + 3);
			break;
		case ' ': // "omf"
			{
				int argc;
				char **argv = r_str_argv (&input[3], &argc);
				cmd_omf (core, argc, argv);
				r_str_argv_free (argv);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_om);
			break;
		}
		break;
	case '\0': // "om"
	case 'j': // "omj"
	case '*': // "om*"
	case 'q': // "omq"
		if (input[1] && input[2] == '.') {
			map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				core->print->cb_printf ("%i\n", map->id);
			}
		} else {
			if (input[1] && input[2] == 'q') { // "omqq"
				map_list (core, input[1], core->print, -2);
			} else {
				map_list (core, input[1], core->print, -1);
			}
		}
		break;
	case '=': // "om="
		{
		RList *list = r_list_newf ((RListFree) r_listinfo_free);
		if (!list) {
			return;
		}
		RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
			if (!bank) {
			r_list_free (list);
			return;
		}
		RListIter *iter;
		RIOMapRef *mapref;
		r_list_foreach_prev (bank->maprefs, iter, mapref) {
			RIOMap *map = r_io_map_get (core->io, mapref->id);
			char temp[32];
			snprintf (temp, sizeof (temp), "%d", map->fd);
			RListInfo *info = r_listinfo_new (map->name, map->itv, map->itv, map->perm, temp);
			if (!info) {
				break;
			}
			r_list_append (list, info);
		}
		RTable *table = r_core_table (core, "maps");
		r_table_visual_list (table, list, core->offset, core->blocksize,
			r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
		char *tablestr = r_table_tostring (table);
		r_cons_printf ("\n%s\n", tablestr);
		r_table_free (table);
		r_list_free (list);
		free (tablestr);
		} break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg_om);
		break;
	}
	R_FREE (s);
	r_core_block_read (core);
}

static bool reopen_in_malloc_cb(void *user, void *data, ut32 id) {
	RIO *io = (RIO *)user;
	RIODesc *desc = (RIODesc *)data;

	if (r_io_desc_is_blockdevice (desc) || r_io_desc_is_dbg (desc)) {
		return true;
	}

	if (strstr (desc->uri, "://")) {
		return true;
	}

	ut64 size = r_io_desc_size (desc);

	char *uri = r_str_newf ("malloc://%"PFMT64u, size);
	if (!uri) {
		return false;
	}

	ut8 *buf = malloc (size);
// if malloc fails, we can just abort the loop by returning false
	if (!buf) {
		free (uri);
		return false;
	}

	RIODesc *ndesc = r_io_open_nomap (io, uri, R_PERM_RW, 0);
	free (uri);
	if (!ndesc) {
		free (buf);
		return false;
	}

	r_io_desc_read_at (desc, 0LL, buf, (int)size);	//that cast o_O
	r_io_desc_write_at (ndesc, 0LL, buf, (int)size);
	free (buf);
	r_io_desc_exchange (io, desc->fd, ndesc->fd);

	r_io_desc_close (desc);
	return true;
}

R_API void r_core_file_reopen_in_malloc(RCore *core) {
	if (core && core->io && core->io->files) {
		r_id_storage_foreach (core->io->files, reopen_in_malloc_cb, core->io);
	}
}

static RList *__save_old_sections(RCore *core) {
	RList *sections = r_bin_get_sections (core->bin);
	RListIter *it;
	RBinSection *sec;
	RList *old_sections = r_list_new ();

	// Return an empty list
	if (!sections) {
		R_LOG_WARN ("No sections found, functions and flags won't be rebased");
		return old_sections;
	}

	old_sections->free = sections->free;
	r_list_foreach (sections, it, sec) {
		RBinSection *old_sec = R_NEW0 (RBinSection);
		if (!old_sec) {
			break;
		}
		*old_sec = *sec;
		old_sec->name = strdup (sec->name);
		old_sec->format = NULL;
		r_list_append (old_sections, old_sec);
	}
	return old_sections;
}

struct __rebase_struct {
	RCore *core;
	RList *old_sections;
	ut64 old_base;
	ut64 diff;
	int type;
};

#define __is_inside_section(item_addr, section)\
	(item_addr >= old_base + section->vaddr && item_addr <= old_base + section->vaddr + section->vsize)

static bool __rebase_flags(RFlagItem *flag, void *user) {
	struct __rebase_struct *reb = user;
	ut64 old_base = reb->old_base;
	RListIter *it;
	RBinSection *sec;
	// Only rebase flags that were in the rebased sections, otherwise it will take too long
	r_list_foreach (reb->old_sections, it, sec) {
		if (__is_inside_section (flag->offset, sec)) {
			r_flag_set (reb->core->flags, flag->name, flag->offset + reb->diff, flag->size);
			break;
		}
	}
	return true;
}

static void __rebase_everything(RCore *core, RList *old_sections, ut64 old_base) {
	RListIter *it, *itit, *ititit;
	RAnalFunction *fcn;
	ut64 new_base = (core->bin->cur && core->bin->cur->bo)? core->bin->cur->bo->baddr_shift: 0;
	RBinSection *old_section;
	ut64 diff = new_base - old_base;
	if (!diff) {
		return;
	}
	// FUNCTIONS
	r_list_foreach (core->anal->fcns, it, fcn) {
		r_list_foreach (old_sections, itit, old_section) {
			if (!__is_inside_section (fcn->addr, old_section)) {
				continue;
			}
				r_anal_function_rebase_vars (core->anal, fcn);
			r_anal_function_relocate (fcn, fcn->addr + diff);
			RAnalBlock *bb;
			ut64 new_sec_addr = new_base + old_section->vaddr;
			r_list_foreach (fcn->bbs, ititit, bb) {
				if (bb->addr >= new_sec_addr && bb->addr <= new_sec_addr + old_section->vsize) {
					// Todo: Find better way to check if bb was already rebased
					continue;
				}
				r_anal_block_relocate (bb, bb->addr + diff, bb->size);
				if (bb->jump != UT64_MAX) {
					bb->jump += diff;
				}
				if (bb->fail != UT64_MAX) {
					bb->fail += diff;
				}
			}
			break;
		}
	}

	// FLAGS
	struct __rebase_struct reb = {
		core,
		old_sections,
		old_base,
		diff
	};
	r_flag_foreach (core->flags, __rebase_flags, &reb);

	// META
	r_meta_rebase (core->anal, diff);

	// REFS
	RVecAnalRef *old_refs = r_anal_refs_get (core->anal, UT64_MAX);
	// r_anal_xrefs_free (core->anal);
	r_anal_xrefs_init (core->anal); // init already calls free

	if (old_refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (old_refs, ref) {
			ref->addr += diff;
			ref->at += diff;
			r_anal_xrefs_set (core->anal, ref->at, ref->addr, ref->type);
		}
	}

	RVecAnalRef_free (old_refs);

	// BREAKPOINTS
	r_debug_bp_rebase (core->dbg, old_base, new_base);
}

R_API void r_core_file_reopen_remote_debug(RCore *core, char *uri, ut64 addr) {
	RIODesc *desc = core->io->desc;
	RIODesc *file;
	int fd;

	if (!desc || !desc->uri) {
		R_LOG_ERROR ("No file open?");
		return;
	}

	RList *old_sections = __save_old_sections (core);
	ut64 old_base = core->bin->cur->bo->baddr_shift;
	int bits = core->rasm->config->bits;
	r_config_set_i (core->config, "asm.bits", bits);
	r_config_set_b (core->config, "cfg.debug", true);
	// Set referer as the original uri so we could return to it with `oo`
	desc->referer = desc->uri;
	desc->uri = strdup (uri);

	if ((file = r_core_file_open (core, uri, R_PERM_RW, addr))) {
		fd = file->fd;
		r_core_return_value (core, fd);
		// if no baddr is defined, use the one provided by the file
		if (addr == 0) {
			desc = r_io_desc_get (core->io, file->fd);
			if (desc->plugin->isdbg) {
				addr = r_debug_get_baddr (core->dbg, desc->name);
			} else {
				addr = r_bin_get_baddr (core->bin);
			}
		}
		r_core_bin_load (core, uri, addr);
	} else {
		R_LOG_ERROR ("cannot open file %s", uri);
		r_list_free (old_sections);
		return;
	}
	r_core_block_read (core);
	if (r_config_get_i (core->config, "dbg.rebase")) {
		__rebase_everything (core, old_sections, old_base);
	}
	r_list_free (old_sections);
	r_core_cmd0 (core, "sr PC");
}

R_API void r_core_file_reopen_debug(RCore *core, const char *args) {
	RIODesc *desc = core->io->desc;

	if (!desc || !desc->uri) {
		R_LOG_ERROR ("No file open?");
		return;
	}

	// Reopen the original file as read only since we can't open native debug while the
	// file is open with write permissions
	if (!(desc->plugin && desc->plugin->isdbg) && (desc->perm & R_PERM_W)) {
		R_LOG_ERROR ("Cannot debug file (%s) with permissions set to 0x%x"
			"Reopening the original file in read-only mode.\n", desc->name, desc->perm);
		int fd = desc->fd;
		if (r_io_reopen (core->io, fd, R_PERM_RX, 755)) {
			desc = r_io_desc_get (core->io, fd);
		} else {
			R_LOG_ERROR ("Cannot reopen");
			return;
		}
	}

	RBinFile *bf = r_bin_file_find_by_fd (core->bin, desc->fd);
	char *binpath = (bf && bf->file) ? strdup (bf->file) : NULL;
	if (!binpath) {
		if (r_file_exists (desc->name)) {
			binpath = strdup (desc->name);
		}
	}
	if (!binpath) {
		/* fallback to oo */
		(void)r_core_cmd0 (core, "oo");
		return;
	}

	RList *old_sections = __save_old_sections (core);
	ut64 old_base = (core->bin->cur && core->bin->cur->bo)? core->bin->cur->bo->baddr_shift: 0;
	int bits = core->rasm->config->bits;
	char *bin_abspath = r_file_abspath (binpath);
	if (strstr (bin_abspath, "://")) {
		free (bin_abspath);
		free (binpath);
		r_list_free (old_sections);
		return;
	}
	char *escaped_path = r_str_arg_escape (bin_abspath);
	char *newfile = r_str_newf ("dbg://%s%c%s", escaped_path, *args?' ':0, args);
	desc->uri = newfile;
	desc->referer = NULL;
	r_config_set_i (core->config, "asm.bits", bits);
	r_config_set_b (core->config, "cfg.debug", true);
	r_core_file_reopen (core, newfile, 0, 2);
	if (r_config_get_i (core->config, "dbg.rebase")) {
		__rebase_everything (core, old_sections, old_base);
	}
	r_list_free (old_sections);
	r_core_cmd0 (core, "sr PC");
	free (bin_abspath);
	free (escaped_path);
	free (binpath);
}

static bool init_desc_list_visual_cb(void *user, void *data, ut32 id) {
	RIODesc *desc = (RIODesc *)data;
	ut64 sz = r_io_desc_size (desc);
	if (sz > fdsz) {
		fdsz = sz;
	}
	return true;
}

static bool desc_list_visual_cb(void *user, void *data, ut32 id) {
	RPrint *p = (RPrint *)user;
	RIODesc *desc = (RIODesc *)data;
	ut64 sz = r_io_desc_size (desc);
	r_cons_printf ("%2d %c %s 0x%08"PFMT64x" ", desc->fd,
			(desc->io && (desc->io->desc == desc)) ? '*' : '-', r_str_rwx_i (desc->perm), sz);
	int flags = p->flags;
	p->flags &= ~R_PRINT_FLAGS_HEADER;
	r_print_progressbar (p, sz * 100 / fdsz, r_cons_get_size (NULL) - 40);
	p->flags = flags;
	r_cons_printf (" %s\n", desc->uri);
#if 0
	RIOMap *map;
	SdbListIter *iter;
	if (desc->io && desc->io->va && desc->io->maps) {
		ls_foreach_prev (desc->io->maps, iter, map) {
			if (map->fd == desc->fd) {
				p->cb_printf ("  +0x%"PFMT64x" 0x%"PFMT64x
					" - 0x%"PFMT64x" : %s : %s : %s\n", map->delta,
					map->from, map->to, r_str_rwx_i (map->flags), "",
					r_str_get (map));
			}
		}
	}
#endif
	return true;
}

static bool desc_list_quiet2_cb(void *user, void *data, ut32 id) {
	RPrint *p = (RPrint *)user;
	RIODesc *desc = (RIODesc *)data;
	p->cb_printf ("%d\n", desc->fd);
	return false;
}

static bool desc_list_quiet_cb(void *user, void *data, ut32 id) {
	RPrint *p = (RPrint *)user;
	RIODesc *desc = (RIODesc *)data;
	p->cb_printf ("%d\n", desc->fd);
	return true;
}

static bool desc_list_cmds_cb(void *user, void *data, ut32 id) {
	RCore *core = (RCore *)user;
	RPrint *p = core->print;
	RIODesc *desc = (RIODesc *)data;
	RBinFile *bf = r_bin_file_find_by_fd (core->bin, desc->fd);
	if (bf) {
		p->cb_printf ("o \"%s\" 0x%08"PFMT64x" %s\n", desc->uri, bf->bo->baddr, r_str_rwx_i (desc->perm));
	} else {
		p->cb_printf ("onnu %s %s\n", desc->uri, r_str_rwx_i (desc->perm));
	}
	if (strstr (desc->uri, "null://")) {
		// null descs dont want to be mapped
		return true;
	}

	RList *list = r_bin_get_sections (core->bin);
	RList *maps = r_io_map_get_by_fd (core->io, desc->fd);
	RListIter *iter, *iter2;
	RBinSection *sec;
	RIOMap *map;
	r_list_foreach_prev (maps, iter, map) {
		bool map_from_bin = false;
		bool have_segments = false;
		r_list_foreach (list, iter2, sec) {
			if (sec->is_segment) {
				have_segments = true;
				if (sec->vaddr == map->itv.addr && sec->vsize == map->itv.size) {
					map_from_bin = true;
					break;
				}
			}
		}
		if (!have_segments) {
			map_from_bin = true;
		}
		if (!map_from_bin) {
			// ut64 paddr = 0; // map->itv.addr;
			ut64 paddr = map->itv.addr;
			if (paddr == map->itv.addr) {
				paddr = 0;
			}
			ut64 vaddr = map->itv.addr + map->delta;
			ut64 vsize = map->itv.size;
			if (vsize > 0) {
				p->cb_printf ("om $d 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %s\n",
						vaddr, vsize, paddr, r_str_rwx_i (map->perm), r_str_get (map->name));
			}
		}
	}
	return true;
}
static bool desc_list_cb(void *user, void *data, ut32 id) {
	RPrint *p = (RPrint *)user;
	RIODesc *desc = (RIODesc *)data;
	p->cb_printf ("%2d %c %s 0x%08"PFMT64x" %s\n", desc->fd,
			(desc->io && (desc->io->desc == desc)) ? '*' : '-',
			r_str_rwx_i (desc->perm), r_io_desc_size (desc), desc->uri);
	return true;
}

static bool desc_list_json_cb(void *user, void *data, ut32 id) {
	PJ *pj = (PJ *)user;
	RIODesc *desc = (RIODesc *)data;
	// TODO: from is always 0? See libr/core/file.c:945
	ut64 from = 0LL;
	pj_o (pj);
	pj_kb (pj, "raised", desc->io && (desc->io->desc == desc));
	pj_kN (pj, "fd", desc->fd);
	pj_ks (pj, "uri", desc->uri);
	pj_kn (pj, "from", from);
	pj_kb (pj, "writable", desc->perm & R_PERM_W);
	pj_kN (pj, "size", r_io_desc_size (desc));
	pj_end (pj);
	return true;
}

static bool cmd_op(RCore *core, char mode, int fd) {
	int cur_fd = r_io_fd_get_current (core->io);
	int next_fd = cur_fd;
	switch (mode) {
	case 0:
		next_fd = fd;
		break;
	case 'n':
		next_fd = r_io_fd_get_next (core->io, cur_fd);
		break;
	case 'p':
		next_fd = r_io_fd_get_prev (core->io, cur_fd);
		break;
	case 'r':
		next_fd = r_io_fd_get_next (core->io, cur_fd);
		if (next_fd == -1) {
			next_fd = r_io_fd_get_lowest (core->io);
		}
		break;
	}
	if (next_fd >= 0 && next_fd != cur_fd && r_io_use_fd (core->io, next_fd)) {
		RBinFile *bf = r_bin_file_find_by_fd (core->bin, next_fd);
		if (bf && r_core_bin_raise (core, bf->id)) {
			r_core_block_read (core);
			return true;
		}
	}
	return next_fd != -1;
}


typedef struct {
	const char *name;
	RIODesc *desc;
	RCore *core;
} Onn;

static bool find_desc_by_name(void *user, void *data, ut32 id) {
	Onn *on = (Onn *)user;
	RIODesc *desc = (RIODesc *)data;
	if (!strcmp (desc->name, on->name)) {
		on->desc = desc;
		return false;
	}
	// eprintf ("%s %c", desc->name, 10);
	return true;
}

static bool cmd_onn(RCore *core, const char* input) {
	const char *arg0 = input;
	while (*arg0 && *arg0 != ' ') {
		arg0++;
	}
	arg0 = r_str_trim_head_ro (arg0);
	if (!*arg0) {
		r_core_cmd_help_match (core, help_msg_on, "onn", false);
		return false;
	}
	char *ptr = r_str_trim_dup (arg0);
	int perms = R_PERM_R;
	char *arg_perm = strchr (ptr, ' ');
	if (arg_perm) {
		*arg_perm++ = 0;
		arg0 = ptr;
		perms = r_str_rwx (arg_perm);
	}
	Onn on = {arg0, NULL, core};
	ut64 addr = 0LL;
	// check if file is opened already
	if (r_str_startswith (input, "nnu")) {
		r_id_storage_foreach (core->io->files, find_desc_by_name, &on);
		if (on.desc) {
			core->io->desc = on.desc;
			return true;
		}
	}

	RIODesc *desc = r_io_open_at (core->io, ptr, perms, 0644, addr);
	if (!desc || desc->fd == -1) {
		R_LOG_ERROR ("Cannot open file '%s'", ptr);
		free (ptr);
		return false;
	}
	RList *maps = r_io_map_get_by_fd (core->io, desc->fd);
	if (maps) {
		RIOMap *map;
		RListIter *iter;
		r_list_foreach (maps, iter, map) {
			r_io_map_del (core->io, map->id);
		}
		r_list_free (maps);
	}
	free (ptr);
	return true;
}

static int cmd_open(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int perms = R_PERM_R;
	ut64 baddr = r_config_get_i (core->config, "bin.baddr");
	ut64 addr = 0LL;
	int argc, fd = -1;
	RIODesc *file;
	RIODesc *desc;
	const char *ptr = NULL;
	char **argv = NULL;

	switch (*input) {
	case 'a': // "oa"
		switch (input[1]) {
		case '*': // "oa*"
			{
				RListIter *iter;
				RBinFile *bf = NULL;
				r_list_foreach (core->bin->binfiles, iter, bf) {
					if (bf && bf->bo && bf->bo->info) {
						r_cons_printf ("oa %s %d %s\n", bf->bo->info->arch, bf->bo->info->bits, bf->file);
					}
				}
				return 1;
			}
			break;
		case '?': // "oa?"
			r_core_cmd_help_match (core, help_msg_o, "oa", true);
			return 1;
		case ' ': { // "oa "
			int i;
			char *ptr = strdup (input+2);
			const char *arch = NULL;
			ut16 bits = 0;
			const char *filename = NULL;
			i = r_str_word_set0 (ptr);
			if (i < 2) {
				R_LOG_ERROR ("Missing argument");
				free (ptr);
				return 0;
			}
			if (i == 3) {
				filename = r_str_word_get0 (ptr, 2);
			}
			bits = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			arch = r_str_word_get0 (ptr, 0);
			r_core_bin_set_arch_bits (core, filename, arch, bits);
			RBinFile *file = NULL;
			if (filename) {
				file = r_bin_file_find_by_name (core->bin, filename);
				if (!file) {
					R_LOG_ERROR ("Cannot find file %s", filename);
				}
			} else if (r_list_length (core->bin->binfiles) == 1) {
				file = (RBinFile *)r_list_first (core->bin->binfiles);
			} else {
				R_LOG_INFO ("More than one file is opened, you must specify the filename");
			}
			if (!file) {
				free (ptr);
				return 0;
			}
			if (file->bo && file->bo->info) {
				free (file->bo->info->arch);
				file->bo->info->arch = strdup (arch);
				file->bo->info->bits = bits;
				r_core_bin_set_env (core, file);
			}
			free (ptr);
			return 1;
			}
			break;
		default:
			r_core_cmd_help_match (core, help_msg_o, "oa", true);
			return 0;
		}
		break;
	case 'n': // "on"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_on);
			return 0;
		}
		if (input[1] == 'n') { // "onn"
			cmd_onn (core, input);
			return 0;
		}
		if (input[1] == '*') { // "on*"
			R_LOG_TODO ("on* is not yet implemented");
			return 0;
		}
		if (input[1] == '+') { // "on+"
			perms |= R_PERM_W;
			if (input[2] != ' ') {
				r_core_cmd_help_match (core, help_msg_on, "on+", true);
				return 0;
			}
			ptr = r_str_trim_head_ro (input + 3);
		} else if (input[1] == ' ') {
			ptr = input + 2;
		} else {
			r_core_cmd_help (core, help_msg_on);
			return 0;
		}
		argv = r_str_argv (ptr, &argc);
		if (!argc) {
			r_core_cmd_help (core, help_msg_on);
			r_str_argv_free (argv);
			return 0;
		}
		ptr = argv[0];
		if (argc == 2) {
			if (r_num_is_valid_input (core->num, argv[1])) {
				addr = r_num_math (core->num, argv[1]);
			} else {
				perms = r_str_rwx (argv[1]);
			}
		}
		if (argc == 3) {
			addr = r_num_math (core->num, argv[1]);
			perms = r_str_rwx (argv[2]);
		}
		if (!strcmp (ptr, "-")) {
			ptr = "malloc://512";
		}
		if ((desc = r_io_open_at (core->io, ptr, perms, 0644, addr))) {
			fd = desc->fd;
		}
		if (fd == -1) {
			R_LOG_ERROR ("Cannot open file '%s'", ptr);
		}
		r_str_argv_free (argv);
		r_core_return_value (core, fd);
		r_core_block_read (core);
		return 0;
	case 'e': // "oe"
		if (input[1] == ' ') {
			const char *arg = r_str_trim_head_ro (input + 1);
			free (r_core_editor (core, arg, NULL));
		} else {
			r_core_cmd_help_match (core, help_msg_o, "oe", false);
		}
		return 0;
	// XXX projects use the of command, but i think we should deprecate it... keeping it for now
	case 'f': // "of"
		if (input[1]) {
			ptr = r_str_trim_head_ro (input + 2);
			argv = r_str_argv (ptr, &argc);
			if (argc == 0 || input[1] == '?') {
				r_core_cmd_help_match (core, help_msg_o, "of", true);
				r_str_argv_free (argv);
				return 0;
			}
			if (argc == 2) {
				perms = r_str_rwx (argv[1]);
			}
			fd = r_io_fd_open (core->io, argv[0], perms, 0);
			r_core_return_value (core, fd);
			r_str_argv_free (argv);
		} else {
			r_core_cmd_help_match (core, help_msg_o, "of", true);
		}
		return 0;
	case 't': // "ot"
		r_core_cmdf (core, "touch%s", input + 1);
		return 0;
	case 'p': // "op"
		/* handle prioritize */
		if (input[1]) {
			switch (input[1]) {
			case 'e': // "ope" - 'open'
				{
					const char *sp = strchr (input, ' ');
					if (sp) {
#if R2__WINDOWS__
						r_sys_cmdf ("start %s", sp + 1);
#else
						if (r_file_exists ("/usr/bin/xdg-open")) {
							r_sys_cmdf ("xdg-open %s", sp + 1);
						} else if (r_file_exists ("/usr/local/bin/xdg-open")) {
							r_sys_cmdf ("xdg-open %s", sp + 1);
						} else if (r_file_exists ("/usr/bin/open")) {
							r_sys_cmdf ("open %s", sp + 1);
						} else {
							eprintf ("Unknown open tool. Cannot find xdg-open\n");
						}
#endif
					} else {
						r_core_cmd_help_match (core, help_msg_o, "open", true);
					}
				}
				break;
			case 'r': // "opr" - open next file + rotate if not found
			case 'n': // "opn" - open next file
			case 'p': // "opp" - open previous file
				if (!cmd_op (core, input[1], -1)) {
					R_LOG_ERROR ("Cannot find file");
				}
				break;
			case ' ': {
				int fd = r_num_math (core->num, input + 1);
				if (fd >= 0 || input[1] == '0') {
					cmd_op (core, 0, fd);
				} else {
					R_LOG_ERROR ("Invalid fd number");
				}
				}
				break;
			default:
				r_core_cmd_help (core, help_msg_op);
				break;
			}
		} else {
			if (core->io && core->io->desc) {
				r_cons_printf ("%d\n", core->io->desc->fd);
			}
		}
		return 0;
		break;
	case '+': // "o+"
		if (input[1] == '?' || (input[1] && input[2] == '?')) {
			r_core_cmd_help_match (core, help_msg_o, "o+", false);
			return 0;
		}
		perms |= R_PERM_W;
		if (input[1] == '+') { // "o++"
			perms |= R_PERM_CREAT;
			input++;
		}
		/* fallthrough */
	case ' ': // "o" "o "
		ptr = input + 1;
		argv = r_str_argv (ptr, &argc);
		if (argc == 0) {
			if (perms & R_PERM_W) {
				r_core_cmd_help_match (core, help_msg_o, "o+", false);
			} else {
				r_core_cmd_help_match (core, help_msg_o, "o", true);
			}
			r_str_argv_free (argv);
			return 0;
		}
		if (argv) {
			if (r_str_startswith (argv[0], "base64:")) {
				char *decoded = (char *)sdb_decode (argv[0] + 7, NULL);
				if (decoded) {
					free (argv[0]);
					argv[0] = decoded;
				}
			} else {
				// Unescape spaces from the path
				r_str_path_unescape (argv[0]);
			}
			if (argc == 2) {
				if (r_num_is_valid_input (core->num, argv[1])) {
					addr = r_num_math (core->num, argv[1]);
				} else {
					perms = r_str_rwx (argv[1]);
				}
			}
			if (argc == 3) {
				addr = r_num_math (core->num, argv[1]);
				perms = r_str_rwx (argv[2]);
			}
		}
		{
			const char *argv0 = argv ? argv[0] : ptr;
			if ((file = r_core_file_open (core, argv0, perms, addr))) {
				fd = file->fd;
				r_core_return_value (core, fd);
				if (addr == 0) { // if no baddr defined, use the one provided by the file
					addr = UT64_MAX;
				}
				r_core_bin_load (core, argv0, addr);
				if (*input == '+') { // "o+"
					RIODesc *desc = r_io_desc_get (core->io, fd);
					if (desc && (desc->perm & R_PERM_W)) {
						RListIter *iter;
						RList *maplist = r_io_map_get_by_fd (core->io, desc->fd);
						if (!maplist) {
							break;
						}
						RIOMap *map;
						r_list_foreach (maplist, iter, map) {
							map->perm |= R_PERM_WX;
						}
						r_list_free (maplist);
					} else {
						R_LOG_ERROR ("%s is not writable", argv0);
					}
				}
			} else {
				if (perms & R_PERM_W) {
					// create file!
				}
				R_LOG_ERROR ("cannot open file %s", argv0);
			}
		}
		r_core_block_read (core);
		r_str_argv_free (argv);
		return 0;
	}

	switch (*input) {
	case '=': // "o="
		fdsz = 0;
		r_id_storage_foreach (core->io->files, init_desc_list_visual_cb, core->print);
		r_id_storage_foreach (core->io->files, desc_list_visual_cb, core->print);
		break;
	case 'q': // "oq"
		if (input[1] == '.') {
			r_id_storage_foreach (core->io->files, desc_list_quiet2_cb, core->print);
		} else {
			r_id_storage_foreach (core->io->files, desc_list_quiet_cb, core->print);
		}
		break;
	case '\0': // "o"
		r_id_storage_foreach (core->io->files, desc_list_cb, core->print);
		break;
	case '*': // "o*"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_o, "o*", true);
			break;
		}
		r_id_storage_foreach (core->io->files, desc_list_cmds_cb, core);
		break;
	case 'j': // "oj"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_o, "oj", true);
			break;
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		r_id_storage_foreach (core->io->files, desc_list_json_cb, pj);
		pj_end (pj);
		core->print->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		break;
	case 'L': // "oL"
		if (r_sandbox_enable (0)) {
			R_LOG_ERROR ("This command is disabled in sandbox mode");
			return 0;
		}
		if (input[1] == ' ') {
			if (r_lib_open (core->lib, input + 2) == -1) {
				R_LOG_ERROR ("Oops. Cannot open library");
			}
		} else {
			if ('j' == input[1]) {
				r_io_plugin_list_json (core->io);
			} else {
				r_io_plugin_list (core->io);
			}
		}
		break;
	case 'u': { // "ou"
		core->switch_file_view = 0;
		int num = atoi (input + 2);

		r_io_use_fd (core->io, num);
		RBinFile *bf = r_bin_file_find_by_fd (core->bin, num);
		if (bf) {
			r_core_bin_raise (core, bf->id);
			r_core_block_read (core);
		}
		break;
	}
	case 'b': // "ob"
		cmd_open_bin (core, input);
		break;
	case '-': // "o-"
		switch (input[1]) {
		case '!': // "o-!"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_o_dash, "o-!", true);
			} else {
				r_core_file_close_all_but (core);
			}
			break;
		case '$': // "o-$"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_o_dash, "o-$", true);
			} else {
				R_LOG_TODO ("o-$: close last fd is not implemented");
			}
			break;
		case '.': // "o-."
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_o_dash, "o-*", true);
			} else {
				RBinFile *bf = r_bin_cur (core->bin);
				if (bf && bf->fd >= 0) {
					core->bin->cur = NULL;
					int fd = bf->fd;
					if (!r_io_fd_close (core->io, fd)) {
						R_LOG_ERROR ("Unable to find file descriptor %d", fd);
					}
				}
			}
			break;
		case '*': // "o-*"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_o_dash, "o-*", true);
			} else {
				r_io_close_all (core->io);
				r_bin_file_delete_all (core->bin);
			}
			break;
		case '-': // "o--"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_o_dash, "o--", true);
			} else {
				r_io_close_all (core->io);
				r_bin_file_delete_all (core->bin);
				r_core_cmd0 (core, "o-*;om-*");
				r_anal_purge (core->anal);
				r_flag_unset_all (core->flags);
			}
			break;
		case '\0':
		case '?':
			r_core_cmd_help (core, help_msg_o_dash);
			break;
		default: {
			int fd = (int)r_num_math (core->num, input + 1);
			if (!r_io_fd_close (core->io, fd)) {
				R_LOG_ERROR ("Unable to find file descriptor %d", fd);
			}
			}
			break;
		}
		break;
	case '.': // "o."
		if (input[1] == 'q') { // "o.q" // same as oq
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				r_cons_printf ("%d\n", map->fd);
			}
		} else {
			RIOMap *map = r_io_map_get_at (core->io, core->offset);
			if (map) {
				RIODesc *desc = r_io_desc_get (core->io, map->fd);
				if (desc) {
					r_cons_printf ("%s\n", desc->uri);
				}
			}
		}
		break;
	case ':': // "o:"
		{
			int len = r_num_math (core->num, input + 1);
			if (len < 1) {
				len = core->blocksize;
			}
			char *uri = r_str_newf ("malloc://%d", len);
			ut8 *data = calloc (len, 1);
			r_io_read_at (core->io, core->offset, data, len);
			if ((file = r_core_file_open (core, uri, R_PERM_RWX, 0))) {
				fd = file->fd;
				r_core_return_value (core, fd);
				r_core_bin_load (core, uri, 0);
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					// TODO: why r_io_desc_write() fails?
					r_io_desc_write_at (desc, 0, data, len);
				}
			} else {
				R_LOG_ERROR ("Cannot %s", uri);
			}
			free (uri);
			free (data);
		}
		break;
	case 'm': // "om"
		cmd_open_map (core, input);
		break;
	case 'o': // "oo"
		switch (input[1]) {
		case 'm': // "oom"
			r_core_file_reopen_in_malloc (core);
			break;
		case 'd': // "ood" : reopen in debugger
			switch (input[2]) {
			case 'r': // "oodr"
				r_core_cmdf (core, "dor %s", input + 3);
				r_core_file_reopen_debug (core, "");
				break;
			case 'f': // "oodf"
				argv = r_str_argv (input + 3, &argc);
				if (argc < 1 || argc > 2) {
					r_core_cmd_help_match (core, help_msg_ood, "oodf", true);
					r_str_argv_free (argv);
					return 0;
				}
				if (argc == 2 && r_num_is_valid_input (core->num, argv[1])) {
					addr = r_num_math (core->num, argv[1]);
				}
				r_core_file_reopen_remote_debug (core, argv[0], addr);
				r_str_argv_free (argv);
				break;
			case '\0': // "ood"
			case ' ': // "ood "
				r_core_file_reopen_debug (core, r_str_trim_head_ro (input + 2));
				break;
			case '?': // "ood?"
			default:
				r_core_cmd_help (core, help_msg_ood);
				break;
			}
			break;
		case 'c': // "ooc"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_oo, "ooc", true);
			} else {
				r_core_cmd0 (core, "oc `o.`");
			}
			break;
		case 'b': // "oob" : reopen with bin info
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_oo, "oob", true);
			} else {
				r_core_file_reopen (core, input + 2, 0, 2);
			}
			break;
		case 'n': // "oon"
			switch (input[2]) {
			case 0: // "oon"
				r_core_file_reopen (core, NULL, 0, 0);
				break;
			case '+': // "oon+"
				r_core_file_reopen (core, NULL, R_PERM_RW, 0);
				break;
			case 'n': // "oonn"
				if (input[3] == '?' || !core->io->desc) {
					r_core_cmd_help_match (core, help_msg_oo, "oonn", false);
					break;
				}
				RIODesc *desc = r_io_desc_get (core->io, core->io->desc->fd);
				if (desc) {
					perms = core->io->desc->perm;
					if (input[3] == '+') {
						perms |= R_PERM_RW;
					}
					char *fname = strdup (desc->name);
					if (fname) {
						r_core_bin_load_structs (core, fname);
						r_core_file_reopen (core, fname, perms, 0);
						free (fname);
					}
					break;
				}
				break;
			case '?':
			default:
				r_core_cmd_help_match (core, help_msg_oo, "oon", false);
				break;
			}
			break;
		case '+': // "oo+"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_oo, "oo+", true);
			} else if (core && core->io && core->io->desc) {
				int fd;
				int perms = R_PERM_RW;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)r_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
					perms |= core->io->desc->perm;
				}
				if (r_io_reopen (core->io, fd, perms, 644)) {
					RListIter *iter;
					RList *maplist = r_io_map_get_by_fd (core->io, fd);
					if (!maplist) {
						break;
					}
					RIOMap *map;
					r_list_foreach (maplist, iter, map) {
						map->perm |= R_PERM_WX;
					}
					r_list_free (maplist);
				}
			}
			break;
		case '\0': // "oo"
			if (core && core->io && core->io->desc) {
				int fd;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)r_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
				}
				if (r_config_get_b (core->config, "cfg.debug")) {
					RBinFile *bf = r_bin_cur (core->bin);
					if (bf && r_file_exists (bf->file)) {
						// Escape spaces so that o's argv parse will detect the path properly
						char *file = r_str_path_escape (bf->file);
						// Backup the baddr and sections that were already rebased to
						// revert the rebase after the debug session is closed
						ut64 orig_baddr = core->bin->cur->bo->baddr_shift;
						RList *orig_sections = __save_old_sections (core);

						r_core_cmd0 (core, "ob-*");
						r_io_close_all (core->io);
						r_config_set_b (core->config, "cfg.debug", false);
						r_core_cmdf (core, "o %s", file);

						r_core_block_read (core);
						__rebase_everything (core, orig_sections, orig_baddr);
						r_list_free (orig_sections);
						free (file);
					} else {
						R_LOG_WARN ("Nothing to do");
					}
				} else {
					// r_io_reopen (core->io, fd, R_PERM_R, 644);
					if (!r_io_reopen (core->io, fd, R_PERM_RX, 755)) {
						R_LOG_ERROR ("Cannot reopen");
					}
				}
			}
			break;
		case '?': // "oo?"
		default:
			 r_core_cmd_help (core, help_msg_oo);
			 break;
		}
		break;
	case 'c': // "oc"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_o, "oc", true);
		} else if (input[1] && input[2]) {
			if (r_sandbox_enable (0)) {
				R_LOG_ERROR ("This command is disabled in sandbox mode");
				return 0;
			}
			if (core->tasks.current_task != core->tasks.main_task) {
				R_LOG_ERROR ("This command can only be executed on the main task!");
				return 0;
			}
			// memleak? lose all settings wtf
			// if load fails does not fallbacks to previous file
			r_core_task_sync_end (&core->tasks);
			r_core_fini (core);
			r_core_init (core);
			r_core_task_sync_begin (&core->tasks);
			if (r_core_file_open (core, input + 2, R_PERM_RX, 0)) {
				(void)r_core_bin_load (core, NULL, baddr);
			} else {
				R_LOG_ERROR ("Cannot open file");
			}
		} else {
			R_LOG_ERROR ("Missing argument");
		}
		break;
	case 'x': // "ox"
		if (input[1] && input[1] != '?') {
			int fd, fdx;
			fd = fdx = -1;
			char *ptr, *inp = strdup (input);
			if ((ptr = strrchr (inp, ' '))) {
				fdx = (int)r_num_math (core->num, ptr + 1);
				*ptr = '\0';
				if ((ptr = strchr (inp, ' '))) {
					fd = r_num_math (core->num, ptr + 1);
				}
			}
			if ((fdx == -1) || (fd == -1) || (fdx == fd)) {
				free (inp);
				break;
			}
			r_io_desc_exchange (core->io, fd, fdx);
			free (inp);
			r_core_block_read (core);
		} else {
			r_core_cmd_help_match (core, help_msg_o, "oxr", true);
		}
		break;
	case '?': // "o?"
	default:
		r_core_cmd_help (core, help_msg_o);
		break;
	}
	return 0;
}
