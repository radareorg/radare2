/* radare - LGPL - Copyright 2009-2020 - pancake */

#include "r_list.h"
#include "r_config.h"
#include "r_core.h"
#include "r_util.h"
#include "r_bin.h"
#include "r_debug.h"

static const char *help_msg_o[] = {
	"Usage: o","[com- ] [file] ([offset])","",
	"o"," [file] 0x4000 rwx", "map file at 0x4000",
	"o"," [file]","open [file] file in read-only",
	"o","","list opened files",
	"o","-1","close file descriptor 1",
	"o*","","list opened files in r2 commands",
	"o+"," [file]","open file in read-write mode",
	"o-","!*","close all opened files",
	"o--","","close all files, analysis, binfiles, flags, same as !r2 --",
	"o.","","show current filename (or o.q/oq to get the fd)",
	"o:"," [len]","open a malloc://[len] copying the bytes from current offset",
	"o=","","list opened files (ascii-art bars)",
	"oL","","list all IO plugins registered",
	"oa","[-] [A] [B] [filename]","Specify arch and bits for given file",
	"ob","[?] [lbdos] [...]","list opened binary files backed by fd",
	"oc"," [file]","open core file, like relaunching r2",
	"of"," [file]","open file and map it at addr 0 as read-only",
	"oi","[-|idx]","alias for o, but using index instead of fd",
	"oj","[?]	","list opened files in JSON format",
	"om","[?]","create, list, remove IO maps",
	"on"," [file] 0x4000","map raw file at 0x4000 (no r_bin involved)",
	"oo","[?+bcdnm]","reopen current file (see oo?) (reload in rw or debugger)",
	"op"," [fd]", "select the given fd as current file (see also ob)",
	"oq","","list all open files",
	"ox", " fd fdx", "exchange the descs of fd and fdx and keep the mapping",
	NULL
};

static const char *help_msg_o_[] = {
	"Usage: o-","[#!*]", "",
	"o-*","","close all opened files",
	"o-!","","close all files except the current one",
	"o-3","","close fd=3",
	NULL
};

static const char *help_msg_o_star[] = {
	"Usage:", "o* [> files.r2]", "",
	"o*", "", "list opened files in r2 commands", NULL
};

static const char *help_msg_oa[] = {
	"Usage:", "oba [addr] ([filename])", " # load bininfo and update flags",
	"oba", " [addr]", "Open bin info from the given address",
	"oba", " [addr] [baddr]", "Open file and load bin info at given address",
	"oba", " [addr] [/abs/filename]", "Open file and load bin info at given address",
	NULL
};

static const char *help_msg_ob[] = {
	"Usage:", "ob", " # List open binary files backed by fd",
	"ob", " [bfid]", "Switch to open given objid",
	"ob", "", "List opened binary files and objid",
	"ob*", "", "List opened binary files and objid (r2 commands)",
	"ob-", "*", "Delete all binfiles",
	"ob-", "[objid]", "Delete binfile by binobjid",
	"ob.", " ([addr])", "Show bfid at current address",
	"ob=", "", "Show ascii art table having the list of open files",
	"obL", "", "Same as iL or Li",
	"oba", " [addr] [baddr]", "Open file and load bin info at given address",
	"oba", " [addr] [filename]", "Open file and load bin info at given address",
	"oba", " [addr]", "Open bin info from the given address",
	"obb", " [bfid]", "Switch to open binfile by fd number (Same as op)",
	"obf", " ([file])", "Load bininfo for current file (useful for r2 -n)",
	"obj", "", "List opened binary files and objid (JSON format)",
	"obn", " [name]", "Select binfile by name",
	"obo", " [iofd]", "Switch to open binary file by objid (DEPRECATED)",
	"obr", " [baddr]", "Rebase current bin object",
	NULL
};

static const char *help_msg_oj[] = {
	"Usage:", "oj [~{}]", " # Use ~{} to indent the JSON",
	"oj", "", "list opened files in JSON format", NULL
};

static const char *help_msg_om[] = {
	"Usage:", "om[-] [arg]", " # map opened files",
	"om", " [fd]", "list all defined IO maps for a specific fd",
	"om", " fd vaddr [size] [paddr] [rwx] [name]", "create new io map",
	"om", "", "list all defined IO maps",
	"om*", "", "list all maps in r2 commands format",
	"om-", "mapid", "remove the map with corresponding id",
	"om-*", "", "remove all maps",
	"om-..", "", "hud view of all the maps to select the one to remove",
	"om.", "", "show map, that is mapped to current offset",
	"om=", "", "list all maps in ascii art",
	"oma"," [fd]", "create a map covering all VA for given fd",
	"omb", " mapid addr", "relocate map with corresponding id",
	"omb.", " addr", "relocate current map",
	"omf", " [mapid] rwx", "change flags/perms for current/given map",
	"omfg", "[+-]rwx", "change flags/perms for all maps (global)",
	"omj", "", "list all maps in json format",
	"omm"," [fd]", "create default map for given fd. (omm `oq`)",
	"omn", " mapaddr [name]", "set/delete name for map which spans mapaddr",
	"omn.", "([-|name])", "show/set/delete name for current map",
	"omni", " mapid [name]", "set/delete name for map with mapid",
	"omo", " fd", "map the given fd with lowest priority",
	"omp", " mapid", "prioritize map with corresponding id",
	"ompb", " [fd]", "prioritize maps of the bin associated with the binid",
	"ompd", " mapid", "deprioritize map with corresponding id",
	"ompf", " [fd]", "prioritize map by fd",
	"omq", "", "list all maps and their fds",
	"omqq", "", "list all maps addresses (See $MM to get the size)",
	"omr", " mapid newsize", "resize map with corresponding id",
	"omt", " [query]", "list maps using table api",
	NULL
};

static const char *help_msg_oo[] = {
	"Usage:", "oo[-] [arg]", " # map opened files",
	"oo", "", "reopen current file",
	"oo+", "", "reopen in read-write",
	"oob", " [baddr]", "reopen loading rbin info (change base address?)",
	"ooc", "", "reopen core with current file",
	"ood", "", "reopen in debug mode",
	"oom", "", "reopen in malloc://",
	"oon", "", "reopen without loading rbin info",
	"oon+", "", "reopen in read-write mode without loading rbin info",
	"oonn", "", "reopen without loading rbin info, but with header flags",
	"oonn+", "", "reopen in read-write mode without loading rbin info, but with",
	NULL
};

static const char *help_msg_oo_plus[] = {
	"Usage:", "oo+", " # reopen in read-write",
	NULL
};

static const char *help_msg_oob[] = {
	"Usage:", "oob", " # reopen loading rbin info",
	NULL
};

static const char *help_msg_ood[] = {
	"Usage:", "ood", " # Debug (re)open commands",
	"ood", " [args]", " # reopen in debug mode (with args)",
	"oodf", " [file]", " # reopen in debug mode using the given file",
	"oodr", " [rarun2]", " # same as dor ..;ood",
	NULL
};

static const char *help_msg_oon[] = {
	"Usage:", "oon", " # reopen without loading rbin info",
	NULL
};

static const char *help_msg_oonn[] = {
	"Usage:", "oonn", " # reopen without loading rbin info, but with header flags",
	NULL
};

static void cmd_open_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, o);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, o*, o_star);
	DEFINE_CMD_DESCRIPTOR (core, oa);
	DEFINE_CMD_DESCRIPTOR (core, ob);
	DEFINE_CMD_DESCRIPTOR (core, oj);
	DEFINE_CMD_DESCRIPTOR (core, om);
	DEFINE_CMD_DESCRIPTOR (core, oo);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, oo+, oo_plus);
	DEFINE_CMD_DESCRIPTOR (core, oob);
	DEFINE_CMD_DESCRIPTOR (core, ood);
	DEFINE_CMD_DESCRIPTOR (core, oon);
	DEFINE_CMD_DESCRIPTOR (core, oonn);
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
		if ('?' == input[2]) {
			r_core_cmd_help (core, help_msg_oa);
			break;
		}
		if (input[2] && input[3]) {
			char *arg = strdup (input + 3);
			char *filename = strchr (arg, ' ');
			if (filename && *filename && (filename[1] == '/' || filename[1] == '.')) {
				int saved_fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_open (core->io, filename + 1, R_PERM_R, 0);
				if (desc) {
					*filename = 0;
					ut64 addr = r_num_math (core->num, arg);
					RBinOptions opt;
					r_bin_options_init (&opt, desc->fd, addr, 0, core->bin->rawstr);
					r_bin_open_io (core->bin, &opt);
					r_io_desc_close (desc);
					r_core_cmd0 (core, ".is*");
					r_io_use_fd (core->io, saved_fd);
				} else {
					eprintf ("Cannot open %s\n", filename + 1);
				}
			} else if (filename && *filename) {
				ut64 baddr = r_num_math (core->num, filename);
				ut64 addr = r_num_math (core->num, input + 2); // mapaddr
				int fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					RBinOptions opt;
					opt.baseaddr = baddr;
					opt.loadaddr = addr;
					opt.sz = 1024*1024*1;
					r_bin_options_init (&opt, desc->fd, baddr, addr, core->bin->rawstr);
					r_bin_open_io (core->bin, &opt);
					r_core_cmd0 (core, ".is*");
				} else {
					eprintf ("No file to load bin from?\n");
				}
			} else {
				ut64 addr = r_num_math (core->num, input + 2);
				int fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					RBinOptions opt;
					opt.baseaddr = addr;
					opt.loadaddr = addr;
					opt.sz = 1024 * 1024 * 1;
					r_bin_options_init (&opt, desc->fd, addr, addr, core->bin->rawstr);
					r_bin_open_io (core->bin, &opt);
					r_core_cmd0 (core, ".is*");
				} else {
					eprintf ("No file to load bin from?\n");
				}
			}
			free (arg);
		} else {
			RList *files = r_id_storage_list (core->io->files);
			RIODesc *desc;
			RListIter *iter;
			r_list_foreach (files, iter, desc) {
				RBinOptions opt;
				r_bin_options_init (&opt, desc->fd, core->offset, 0, core->bin->rawstr);
				r_bin_open_io (core->bin, &opt);
				r_core_cmd0 (core, ".ies*");
				break;
			}
			r_list_free (files);
		}
		break;
	case 'b': // "obb"
		if (input[2] == ' ') {
			ut32 id = r_num_math (core->num, input + 3);
			if (!r_core_bin_raise (core, id)) {
				eprintf ("Invalid RBinFile.id number.\n");
			}
		} else {
			eprintf ("Usage: obb [bfid]\n");
		}
		break;
	case ' ': // "ob "
	{
		ut32 id;
		int n;
		const char *tmp;
		char *v;
		v = input[2] ? strdup (input + 2) : NULL;
		if (!v) {
			eprintf ("Invalid arguments");
			break;
		}
		n = r_str_word_set0 (v);
		if (n < 1 || n > 2) {
			eprintf ("Usage: ob [file|objid]\n");
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
		r_core_bin_rebase (core, r_num_math (core->num, input + 3));
		r_core_cmd0 (core, ".is*");
		break;
	case 'f':
		if (input[2] == ' ') {
			r_core_cmdf (core, "oba 0 %s", input + 3);
		} else {
			r_core_bin_load (core, NULL, UT64_MAX);
			value = input[2] ? input + 2 : NULL;
		}
		break;
	case 'o': // "obo"
		if (input[2] == ' ') {
			ut32 fd = r_num_math (core->num, input + 3);
			RBinFile *bf = r_bin_file_find_by_fd (core->bin, fd);
			if (!bf || !r_core_bin_raise (core, bf->id)) {
				eprintf ("Invalid RBinFile.id number.\n");
			}
		} else {
			eprintf ("Usage: obb [bfid]\n");
		}
		break;
	case '-': // "ob-"
		if (input[2] == '*') {
			r_bin_file_delete_all (core->bin);
		} else {
			ut32 id;
			value = r_str_trim_head_ro (input + 2);
			if (!value) {
				eprintf ("Invalid argument\n");
				break;
			}
			id = (*value && r_is_valid_input_num_value (core->num, value)) ?
					r_get_input_num_value (core->num, value) : UT32_MAX;
			RBinFile *bf = r_bin_file_find_by_id (core->bin, id);
			if (!bf) {
				eprintf ("Invalid binid\n");
				break;
			}
			if (!r_core_bin_delete (core, bf->id)) {
				eprintf ("Cannot find an RBinFile associated with that id.\n");
			}
		}
		break;
	case '=': // "ob="
		{
			RListIter *iter;
			RList *list = r_list_newf ((RListFree) r_listinfo_free);
			RBinFile *bf = NULL;
			RBin *bin = core->bin;
			if (!bin) {
				return;
			}
			r_list_foreach (bin->binfiles, iter, bf) {
				char temp[4];
				RInterval inter = (RInterval) {bf->o->baddr, bf->o->size};
				RListInfo *info = r_listinfo_new (bf->file, inter, inter, -1,  sdb_itoa (bf->fd, temp, 10));
				if (!info) {
					break;
				}
				r_list_append (list, info);
			}
			RTable *table = r_core_table (core);
			r_table_visual_list (table, list, core->offset, core->blocksize,
				r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
			r_cons_printf ("\n%s\n", r_table_tostring (table));
			r_table_free (table);
			r_list_free (list);
		} break;
	case '?': // "ob?"
		r_core_cmd_help (core, help_msg_ob);
		break;
	}
}

// TODO: discuss the output format
static void map_list(RIO *io, int mode, RPrint *print, int fd) {
	SdbListIter *iter;
	RIOMap *map;
	if (!io || !io->maps || !print || !print->cb_printf) {
		return;
	}
	if (mode == 'j') {
		print->cb_printf ("[");
	}
	bool first = true;
	char *om_cmds = NULL;
	ls_foreach_prev (io->maps, iter, map) {			//this must be prev (LIFO)
		if (fd >= 0 && map->fd != fd) {
			continue;
		}
		switch (mode) {
		case 'q':
			if (fd == -2) {
				print->cb_printf ("0x%08"PFMT64x"\n", map->itv.addr);
			} else {
				print->cb_printf ("%d %d\n", map->fd, map->id);
			}
			break;
		case 'j':
			if (!first) {
				print->cb_printf (",");
			}
			first = false;
			print->cb_printf ("{\"map\":%i,\"fd\":%d,\"delta\":%"PFMT64u",\"from\":%"PFMT64u
					",\"to\":%"PFMT64u",\"perm\":\"%s\",\"name\":\"%s\"}", map->id, map->fd,
					map->delta, map->itv.addr, r_itv_end (map->itv),
					r_str_rwx_i (map->perm), (map->name ? map->name : ""));
			break;
		case 1:
		case '*':
		case 'r': {
			// Need FIFO order here
			char *om_cmd = r_str_newf ("om %d 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s%s%s\n",
					map->fd, map->itv.addr, map->itv.size, map->delta, r_str_rwx_i(map->perm),
					map->name ? " " : "", map->name ? map->name : "");
			if (om_cmd) {
				om_cmds = r_str_prepend (om_cmds, om_cmd);
				free (om_cmd);
			}
			break;
		}
		default:
			print->cb_printf ("%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s %s\n", map->id, map->fd,
					map->delta, map->itv.addr, r_itv_end (map->itv) - 1,
					r_str_rwx_i (map->perm), (map->name ? map->name : ""));
			break;
		}
	}
	if (om_cmds) {
		print->cb_printf ("%s", om_cmds);
		free (om_cmds);
	}
	if (mode == 'j') {
		print->cb_printf ("]\n");
	}
}

static void cmd_omfg(RCore *core, const char *input) {
	SdbListIter *iter;
	RIOMap *map;
	input = r_str_trim_head_ro (input);
	if (input) {
		int perm = *input
		? (*input == '+' || *input == '-')
			? r_str_rwx (input + 1)
			: r_str_rwx (input)
		: 7;
		switch (*input) {
		case '+':
			ls_foreach (core->io->maps, iter, map) {
				map->perm |= perm;
			}
			break;
		case '-':
			ls_foreach (core->io->maps, iter, map) {
				map->perm &= ~perm;
			}
			break;
		default:
			ls_foreach (core->io->maps, iter, map) {
				map->perm = perm;
			}
			break;
		}
	}
}

static void cmd_omf(RCore *core, const char *input) {
	SdbListIter *iter;
	RIOMap *map;
	char *arg = strdup (r_str_trim_head_ro (input));
	if (!arg) {
		return;
	}
	char *sp = strchr (arg, ' ');
	if (sp) {
		// change perms of Nth map
		*sp++ = 0;
		int id = r_num_math (core->num, arg);
		int perm = (*sp)? r_str_rwx (sp): R_PERM_RWX;
		ls_foreach (core->io->maps, iter, map) {
			if (map->id == id) {
				map->perm = perm;
				break;
			}
		}
	} else {
		// change perms of current map
		int perm = (arg && *arg)? r_str_rwx (arg): R_PERM_RWX;
		ls_foreach (core->io->maps, iter, map) {
			if (r_itv_contain (map->itv, core->offset)) {
				map->perm = perm;
			}
		}
	}
	free (arg);
}

static void r_core_cmd_omt(RCore *core, const char *arg) {
	RTable *t = r_table_new ();

	r_table_set_columnsf (t, "nnnnnnnss", "id", "fd", "pa", "pa_end", "size", "va", "va_end", "perm", "name", NULL);

	SdbListIter *iter;
	RIOMap *m;
	ls_foreach_prev (core->io->maps, iter, m) {
		ut64 va = r_itv_begin (m->itv);
		ut64 va_end = r_itv_end (m->itv);
		ut64 pa = m->delta;
		ut64 pa_size = r_itv_size (m->itv);
		ut64 pa_end = pa + pa_size;
		const char *name = m->name? m->name: "";
		r_table_add_rowf (t, "ddxxxxxss", m->id, m->fd, pa, pa_end, pa_size, va, va_end, r_str_rwx_i (m->perm), name);
	}

	if (r_table_query (t, arg)) {
		char *ts = r_table_tofancystring (t);
		r_cons_printf ("%s", ts);
		free (ts);
	}
	r_table_free (t);
}

static void cmd_open_map(RCore *core, const char *input) {
	ut64 fd = 0LL;
	ut32 id = 0;
	ut64 addr = 0;
	char *s = NULL, *p = NULL, *q = NULL;
	ut64 new;
	RIOMap *map = NULL;
	const char *P;

	switch (input[1]) {
	case '.': // "om."
		map = r_io_map_get (core->io, core->offset);
		if (map) {
			core->print->cb_printf ("map: %i fd: %i +0x%"PFMT64x" 0x%"PFMT64x
				" - 0x%"PFMT64x" ; %s : %s\n", map->id, map->fd,
				map->delta, map->itv.addr, r_itv_end (map->itv),
			r_str_rwx_i (map->perm), map->name ? map->name : "");
		}
		break;
	case 'r': // "omr"
		if (input[2] != ' ') {
			break;
		}
		P = strchr (input+3, ' ');
		if (P) {
			id = (ut32)r_num_math (core->num, input+3);	//mapid
			new = r_num_math (core->num, P+1);
			r_io_map_resize (core->io, id, new);
		}
		break;
	case 'b': // "omb"
		if (input[2] == '.') {
			RIOMap *map = r_io_map_get (core->io, core->offset);
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
				id = (ut32)r_num_math (core->num, input+3);	//mapid
				new = r_num_math (core->num, P + 1);
				r_io_map_remap (core->io, id, new);
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
				eprintf ("Cannot find any map with mapid %d\n", id);
			}
			break;
		case 'f': // "ompf"
			fd = r_num_math (core->num, input + 3);
			if (!r_io_map_priorize_for_fd (core->io, (int)fd)) {
				eprintf ("Cannot prioritize any map for fd %d\n", (int)fd);
			}
			break;
		case 'b': // "ompb"
			id = (ut32)r_num_math (core->num, input + 4);
			if (!r_bin_file_set_cur_by_id (core->bin, id)) {
				eprintf ("Cannot prioritize bin with fd %d\n", id);
			}
			break;
		case ' ': // "omp"
			id = r_num_math (core->num, input + 3);		//mapid
			if (r_io_map_exists_for_id (core->io, id)) {
				r_io_map_priorize (core->io, id);
				r_core_block_read (core);
			} else {
				eprintf ("Cannot find any map with mapid %d\n", id);
			}
			break;
		}
		break;
	case 't': // "omt"
		r_core_cmd_omt (core, input + 2);
		break;
	case ' ': // "om"
		s = strdup (input + 2);
		if (!s) {
			break;
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
			case 5:			//this sucks
				rwx = r_str_rwx (r_str_word_get0 (s, 4));
				rwx_arg = true;
			case 4:
				paddr = r_num_math (core->num, r_str_word_get0 (s, 3));
			case 3:
				size = r_num_math (core->num, r_str_word_get0 (s, 2));
			case 2:
				vaddr = r_num_math (core->num, r_str_word_get0 (s, 1));
			case 1:
				fd = r_num_math (core->num, r_str_word_get0 (s, 0));
			}
			if (fd < 3) {
				eprintf ("wrong fd, it must be greater than 3\n");
				break;
			}
			desc = r_io_desc_get (core->io, fd);
			if (desc) {
				if (!size) {
					size = r_io_fd_size (core->io, fd);
				}
				map = r_io_map_add (core->io, fd, rwx_arg ? rwx : desc->perm, paddr, vaddr, size);
				r_io_map_set_name (map, name);
			}
		} else {
			int fd = r_io_fd_get_current (core->io);
			if (r_io_desc_get (core->io, fd)) {
				map_list (core->io, 0, core->print, fd);
			} else {
				eprintf ("Invalid fd %d\n", (int)fd);
			}
		}
		R_FREE (s);
		break;
	case 'n': // "omn"
		if (input[2] == '.') { // "omn."
			RIOMap *map = r_io_map_get (core->io, core->offset);
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
			s = strdup ( use_id ? &input[3] : &input[2]);
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
					map = r_io_map_resolve (core->io, id);
				} else {
					addr = r_num_math (core->num, s);
					map = r_io_map_get (core->io, addr);
				}
				r_io_map_del_name (map);
				s = p;
				break;
			}
			*q = '\0';
			q++;
			if (use_id) {
				id = (ut32)r_num_math (core->num, s);
				map = r_io_map_resolve (core->io, id);
			} else {
				addr = r_num_math (core->num, s);
				map = r_io_map_get (core->io, addr);
			}
			if (*q) {
				r_io_map_set_name (map, q);
			} else {
				r_io_map_del_name (map);
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
				r_io_map_set_name (map, desc->name);
			} else {
				eprintf ("Usage: omm [fd]\n");
			}
		}
		break;
	case 'm': // "omm"
		{
			ut32 fd = input[2]? r_num_math (core->num, input + 2): r_io_fd_get_current (core->io);
			RIODesc *desc = r_io_desc_get (core->io, fd);
			if (desc) {
				ut64 size = r_io_desc_size (desc);
				map = r_io_map_add (core->io, fd, desc->perm, 0, 0, size);
				r_io_map_set_name (map, desc->name);
			} else {
				eprintf ("Usage: omm [fd]\n");
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
	case 'f': // "omf"
		switch (input[2]) {
		case 'g': // "omfg"
			cmd_omfg (core, input + 3);
			break;
		case ' ': // "omf"
			cmd_omf (core, input + 3);
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
			map = r_io_map_get (core->io, core->offset);
			if (map) {
				core->print->cb_printf ("%i\n", map->id);
			}
		} else {
			if (input[1] && input[2] == 'q') { // "omqq"
				map_list (core->io, input[1], core->print, -2);
			} else {
				map_list (core->io, input[1], core->print, -1);
			}
		}
		break;
	case '=': // "om="
		{
		RList *list = r_list_newf ((RListFree) r_listinfo_free);
		if (!list) {
			return;
		}
		SdbListIter *iter;
		RIOMap *map;
		ls_foreach_prev (core->io->maps, iter, map) {
			char temp[4];
			RListInfo *info = r_listinfo_new (map->name, map->itv, map->itv, map->perm, sdb_itoa (map->fd, temp, 10));
			if (!info) {
				break;
			}
			r_list_append (list, info);
		}
		RTable *table = r_core_table (core);
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
		eprintf ("WARNING: No sections found, functions and flags won't be rebased");
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

static bool __rebase_refs_i(void *user, const ut64 k, const void *v) {
	struct __rebase_struct *reb = (void *)user;
	RAnalRef *ref = (RAnalRef *)v;
	ref->addr += reb->diff;
	ref->at += reb->diff;
	if (reb->type) {
		r_anal_xrefs_set (reb->core->anal, ref->addr, ref->at, ref->type);
	} else {
		r_anal_xrefs_set (reb->core->anal, ref->at, ref->addr, ref->type);
	}
	return true;
}

static bool __rebase_refs(void *user, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach (ht, __rebase_refs_i, user);
	return true;
}

static void __rebase_everything(RCore *core, RList *old_sections, ut64 old_base) {
	RListIter *it, *itit, *ititit;
	RAnalFunction *fcn;
	ut64 new_base = core->bin->cur->o->baddr_shift;
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
			r_anal_var_rebase (core->anal, fcn, diff);
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
	RList *meta_list = r_meta_enumerate (core->anal, R_META_TYPE_ANY);
	RAnalMetaItem *item;
	r_list_foreach (meta_list, it, item) {
		r_meta_del (core->anal, item->type, item->from, item->size);
		item->from += diff;
		r_meta_add_with_subtype (core->anal, item->type, item->subtype, item->from, item->from + item->size, item->str);
	}
	r_list_free (meta_list);

	// REFS
	HtUP *old_refs = core->anal->dict_refs;
	HtUP *old_xrefs = core->anal->dict_xrefs;
	core->anal->dict_refs = NULL;
	core->anal->dict_xrefs = NULL;
	r_anal_xrefs_init (core->anal);
	reb.type = 0;
	ht_up_foreach (old_refs, __rebase_refs, &reb);
	reb.type = 1;
	ht_up_foreach (old_xrefs, __rebase_refs, &reb);
	ht_up_free (old_refs);
	ht_up_free (old_xrefs);

	// BREAKPOINTS
	r_debug_bp_rebase (core->dbg, old_base, new_base);
}

R_API void r_core_file_reopen_remote_debug(RCore *core, char *uri, ut64 addr) {
	RCoreFile *ofile = core->file;
	RIODesc *desc;
	RCoreFile *file;
	int fd;

	if (!ofile || !(desc = r_io_desc_get (core->io, ofile->fd)) || !desc->uri) {
		eprintf ("No file open?\n");
		return;
	}

	RList *old_sections = __save_old_sections (core);
	ut64 old_base = core->bin->cur->o->baddr_shift;
	int bits = core->assembler->bits;
	r_config_set_i (core->config, "asm.bits", bits);
	r_config_set_i (core->config, "cfg.debug", true);
	// Set referer as the original uri so we could return to it with `oo`
	desc->referer = desc->uri;
	desc->uri = strdup (uri);

	if ((file = r_core_file_open (core, uri, R_PERM_R | R_PERM_W, addr))) {
		fd = file->fd;
		core->num->value = fd;
		// if no baddr is defined, use the one provided by the file
		if (addr == 0) {
			desc = r_io_desc_get (core->io, file->fd);
			if (desc->plugin->isdbg) {
				addr = r_debug_get_baddr(core->dbg, desc->name);
			} else {
				addr = r_bin_get_baddr (file->binb.bin);
			}
		}
		r_core_bin_load (core, uri, addr);
	} else {
		eprintf ("cannot open file %s\n", uri);
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
	RCoreFile *ofile = core->file;
	RIODesc *desc;

	if (!ofile || !(desc = r_io_desc_get (core->io, ofile->fd)) || !desc->uri) {
		eprintf ("No file open?\n");
		return;
	}

	// Reopen the original file as read only since we can't open native debug while the
	// file is open with write permissions
	if (!(desc->plugin && desc->plugin->isdbg) && (desc->perm & R_PERM_W)) {
		eprintf ("Cannot debug file (%s) with permissions set to 0x%x.\n"
			"Reopening the original file in read-only mode.\n", desc->name, desc->perm);
		r_io_reopen (core->io, ofile->fd, R_PERM_R, 644);
		desc = r_io_desc_get (core->io, ofile->fd);
	}

	RBinFile *bf = r_bin_file_find_by_fd (core->bin, ofile->fd);
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
	ut64 old_base = core->bin->cur->o->baddr_shift;
	int bits = core->assembler->bits;
	char *bin_abspath = r_file_abspath (binpath);
	char *escaped_path = r_str_arg_escape (bin_abspath);
	char *newfile = r_str_newf ("dbg://%s %s", escaped_path, args);
	desc->uri = newfile;
	desc->referer = NULL;
	r_config_set_i (core->config, "asm.bits", bits);
	r_config_set_i (core->config, "cfg.debug", true);
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

static int fdsz = 0;

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
					map->name ? map->name : "");
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

static int cmd_open(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int perms = R_PERM_R;
	ut64 baddr = r_config_get_i (core->config, "bin.baddr");
	ut64 addr = 0LL;
	int argc, fd = -1;
	RCoreFile *file;
	RIODesc *desc;
	bool write = false;
	const char *ptr = NULL;
	char **argv = NULL;

	switch (*input) {
	case 'a':
		switch (input[1]) {
		case '*': // "oa*"
			{
				RListIter *iter;
				RBinFile *bf = NULL;
				r_list_foreach (core->bin->binfiles, iter, bf) {
					if (bf && bf->o && bf->o->info) {
						eprintf ("oa %s %d %s\n", bf->o->info->arch, bf->o->info->bits, bf->file);
					}
				}
				return 1;
			}
		case '?': // "oa?"
		case ' ': // "oa "
			{
				int i;
				char *ptr = strdup (input+2);
				const char *arch = NULL;
				ut16 bits = 0;
				const char *filename = NULL;
				i = r_str_word_set0 (ptr);
				if (i < 2) {
					eprintf ("Missing argument\n");
					free (ptr);
					return 0;
				}
				if (i == 3) {
					filename = r_str_word_get0 (ptr, 2);
				}
				bits = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				arch = r_str_word_get0 (ptr, 0);
				r_core_bin_set_arch_bits (core, filename, arch, bits);
				RBinFile *file = r_bin_file_find_by_name (core->bin, filename);
				if (!file) {
					eprintf ("Cannot find file %s\n", filename);
					free (ptr);
					return 0;
				}
				if (file->o && file->o->info) {
					file->o->info->arch = strdup(arch);
					file->o->info->bits = bits;
					r_core_bin_set_env (core, file);
				}
				free (ptr);
				return 1;
			}
		break;
		default:
			eprintf ("Usage: oa[-][arch] [bits] [filename]\n");
			return 0;
	}
	case 'n': // "on"
		if (input[1] == '*') {
			r_core_file_list (core, 'n');
			return 0;
		}
		if (input[1] == '+') { // "on+"
			write = true;
			perms |= R_PERM_W;
			if (input[2] != ' ') {
				eprintf ("Usage: on+ file [addr] [rwx]\n");
				return 0;
			}
			ptr = input + 3;
		} else if (input[1] == ' ') {
			ptr = input + 2;
		} else {
			eprintf ("Usage: on file [addr] [rwx]\n");
			return 0;
		}
		argv = r_str_argv (ptr, &argc);
		if (!argc) {
			eprintf ("Usage: on%s file [addr] [rwx]\n", write?"+":"");
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
			eprintf ("Cannot open file '%s'\n", ptr);
		}
		r_str_argv_free (argv);
		core->num->value = fd;
		r_core_block_read (core);
		return 0;
#if 1
	// XXX projects use the of command, but i think we should deprecate it... keeping it for now
	case 'f': // "of"
		ptr = r_str_trim_head_ro (input + 2);
		argv = r_str_argv (ptr, &argc);
		if (argc == 0) {
			eprintf ("Usage: of [filename] (rwx)\n");
			r_str_argv_free (argv);
			return 0;
		} else if (argc == 2) {
			perms = r_str_rwx (argv[1]);
		}
		fd = r_io_fd_open (core->io, argv[0], perms, 0);
		core->num->value = fd;
		r_str_argv_free (argv);
		return 0;
#else
		{
			if ((input[1] == 's') && (input[2] == ' ')) {
				silence = true;
				input++;
			}
			addr = 0; // honor bin.baddr ?
			const char *argv0 = r_str_trim_head_ro (input + 2);
			if ((file = r_core_file_open (core, argv0, perms, addr))) {
				fd = file->fd;
				if (!silence) {
					eprintf ("%d\n", fd);
				}
				r_core_bin_load (core, argv0, baddr);
			} else {
				eprintf ("cannot open file %s\n", argv0);
			}
			r_str_argv_free (argv);
		}
		r_core_block_read (core);
		return 0;
		break;
#endif
	case 'p': // "op"
		/* handle prioritize */
		if (input[1]) {
			int fd = r_num_math (core->num, input + 1);
			if (fd >= 0 || input[1] == '0') {
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					// only useful for io.va=0
					// load bininfo for given fd
					r_core_cmdf (core, "obo %d", fd);
					core->io->desc = desc; // XXX we should use fd here, not *pointer
					r_core_block_read (core);
				} else {
					eprintf ("Cannot find RBinFile associated with fd %d\n", fd);
				}
			} else {
				eprintf ("Invalid fd number\n");
			}
		} else {
			if (core->io && core->io->desc) {
				r_cons_printf ("%d\n", core->io->desc->fd);
			}
		}
		return 0;
		break;
	case '+': // "o+"
		perms |= R_PERM_W;
	case ' ': // "o" "o "
		ptr = input + 1;
		argv = r_str_argv (ptr, &argc);
		if (argc == 0) {
			eprintf ("Usage: o (uri://)[/path/to/file] (addr)\n");
			r_str_argv_free (argv);
			return 0;
		}
		if (argv) {
			// Unescape spaces from the path
			r_str_path_unescape (argv[0]);
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
				core->num->value = fd;
				if (addr == 0) { // if no baddr defined, use the one provided by the file
					addr = UT64_MAX;
				}
				r_core_bin_load (core, argv0, addr);
			} else {
				eprintf ("cannot open file %s\n", argv0);
			}
			r_str_argv_free (argv);
		}
		r_core_block_read (core);
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
		if ('?' == input[1]) {
			r_core_cmd_help (core, help_msg_o_star);
			break;
		}
		r_core_file_list (core, (int)(*input));
		break;
	case 'j': // "oj"
		if ('?' == input[1]) {
			r_core_cmd_help (core, help_msg_oj);
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
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1] == ' ') {
			if (r_lib_open (core->lib, input + 2) == -1) {
				eprintf ("Oops\n");
			}
		} else {
			if ('j' == input[1]) {
				r_io_plugin_list_json (core->io);
			} else {
				r_io_plugin_list (core->io);
			}
		}
		break;
	case 'i': // "oi"
		switch (input[1]) {
		case ' ': // "oi "
			{
				RListIter *iter = NULL;
				RCoreFile *f;
				int nth = r_num_math (core->num, input + 2);
				int count = 0;
				r_list_foreach (core->files, iter, f) {
					if (count == nth) {
						r_io_use_fd (core->io, f->fd);
						break;
					}
					count++;
				}
			}
			break;
		case '-': // "oi-"
			{
				RListIter *iter = NULL;
				RCoreFile *f;
				int nth = r_num_math (core->num, input + 2);
				int count = 0;
				r_list_foreach (core->files, iter, f) {
					if (count == nth) {
						r_core_file_close_fd (core, f->fd);
						break;
					}
					count++;
				}
			}
			break;
		case 'j': // "oij"
		case '*': // "oi*"
		case 0: // "oi"
			r_core_file_list (core, input[1]);
			break;
		}
		break;
	case 'u': { // "ou"
		RListIter *iter = NULL;
		RCoreFile *f;
		core->switch_file_view = 0;
		int num = atoi (input + 2);

		r_list_foreach (core->files, iter, f) {
			if (f->fd == num) {
				core->file = f;
			}
		}
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
			r_core_file_close_all_but (core);
			break;
		case '*': // "o-*"
			r_core_file_close_fd (core, -1);
			r_io_close_all (core->io);
			r_bin_file_delete_all (core->bin);
			if (core->files) {
				r_list_purge (core->files);
			}
			break;
		case '-': // "o--"
			eprintf ("All core files, io, anal and flags info purged.\n");
			r_core_file_close_fd (core, -1);
			r_io_close_all (core->io);
			r_bin_file_delete_all (core->bin);

			// TODO: Move to a-- ?
			r_anal_purge (core->anal);
			// TODO: Move to f-- ?
			r_flag_unset_all (core->flags);
			// TODO: rbin?
			break;
		default:
			{
				int fd = (int)r_num_math (core->num, input + 1);
				if (!r_core_file_close_fd (core, fd)) {
					eprintf ("Unable to find filedescriptor %d\n", fd);
				}
			}
			break;
		case 0:
		case '?':
			r_core_cmd_help (core, help_msg_o_);
		}
		break;
	case '.': // "o."
		if (input[1] == 'q') { // "o.q" // same as oq
			RIOMap *map = r_io_map_get (core->io, core->offset);
			if (map) {
				r_cons_printf ("%d\n", map->fd);
			}
		} else {
			RIOMap *map = r_io_map_get (core->io, core->offset);
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
                        RIODesc *fd = r_io_open (core->io, uri, R_PERM_R | R_PERM_W, 0);
                        if (fd) {
                                r_io_desc_write (fd, data, len);
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
			if (input[2] == 'r') { // "oodr"
				r_core_cmdf (core, "dor %s", input + 3);
				r_core_file_reopen_debug (core, "");
			} else if (input[2] == 'f') { // "oodf"
				char **argv = NULL;
				int addr = 0;
				argv = r_str_argv (input + 3, &argc);
				if (argc == 0) {
					eprintf ("Usage: oodf (uri://)[/path/to/file] (addr)\n");
					r_str_argv_free (argv);
					return 0;
				}
				if (argc == 2) {
					if (r_num_is_valid_input (core->num, argv[1])) {
						addr = r_num_math (core->num, argv[1]);
					}
				}
				r_core_file_reopen_remote_debug (core, argv[0], addr);
				r_str_argv_free (argv);
			} else if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_ood);
			} else {
				r_core_file_reopen_debug (core, input + 2);
			}
			break;
		case 'c': // "oob" : reopen with bin info
			r_core_cmd0 (core, "oc `o.`");
			break;
		case 'b': // "oob" : reopen with bin info
			if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_oob);
			} else {
				r_core_file_reopen (core, input + 2, 0, 2);
			}
			break;
		case 'n': // "oon"
			if ('n' == input[2]) {
				RIODesc *desc = r_io_desc_get (core->io, core->file->fd);
				if ('?' == input[3]) {
					r_core_cmd_help (core, help_msg_oonn);
					break;
				}
				perms = (input[3] == '+')? R_PERM_R|R_PERM_W: 0;
				r_core_file_reopen (core, input + 4, perms, 0);
				if (desc) {
					r_core_bin_load_structs (core, desc->name);
				}
			} else if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_oon);
				break;
			}

			perms = ('+' == input[2])? R_PERM_R | R_PERM_W: 0;
			r_core_file_reopen (core, input + 3, perms, 0);
			break;
		case '+': // "oo+"
			if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_oo_plus);
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
					SdbListIter *iter;
					RIOMap *map;
					ls_foreach_prev (core->io->maps, iter, map) {
						if (map->fd == fd) {
							map->perm |= R_PERM_WX;
						}
					}
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
				if (r_config_get_i (core->config, "cfg.debug")) {
					RBinFile *bf = r_bin_cur (core->bin);
					if (bf && r_file_exists (bf->file)) {
						// Escape spaces so that o's argv parse will detect the path properly
						char *file = r_str_path_escape (bf->file);
						// Backup the baddr and sections that were already rebased to
						// revert the rebase after the debug session is closed
						ut64 orig_baddr = core->bin->cur->o->baddr_shift;
						RList *orig_sections = __save_old_sections (core);

						r_core_cmd0 (core, "ob-*");
						r_io_close_all (core->io);
						r_config_set (core->config, "cfg.debug", "false");
						r_core_cmdf (core, "o %s", file);

						r_core_block_read (core);
						__rebase_everything (core, orig_sections, orig_baddr);
						r_list_free (orig_sections);
						free (file);
					} else {
						eprintf ("Nothing to do.\n");
					}
				} else {
					r_io_reopen (core->io, fd, R_PERM_R, 644);
				}
			}
			break;
		case '?':
		default:
			 r_core_cmd_help (core, help_msg_oo);
			 break;
		}
		break;
	case 'c': // "oc"
		if (input[1] && input[2]) {
			if (r_sandbox_enable (0)) {
				eprintf ("This command is disabled in sandbox mode\n");
				return 0;
			}
			if (core->tasks.current_task != core->tasks.main_task) {
				eprintf ("This command can only be executed on the main task!\n");
				return 0;
			}
			// memleak? lose all settings wtf
			// if load fails does not fallbacks to previous file
			r_core_task_sync_end (&core->tasks);
			r_core_fini (core);
			r_core_init (core);
			r_core_task_sync_begin (&core->tasks);
			if (!r_core_file_open (core, input + 2, R_PERM_R, 0)) {
				eprintf ("Cannot open file\n");
			}
			(void)r_core_bin_load (core, NULL, baddr);
		} else {
			eprintf ("Missing argument\n");
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
			r_core_block_read (core);
		} else {
			eprintf ("Usage: ox [fd] [fdx] - exchange two file descriptors\n");
		}
		break;
	case '?': // "o?"
	default:
		r_core_cmd_help (core, help_msg_o);
		break;
	}
	return 0;
}
