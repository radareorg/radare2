/* radare - LGPL - Copyright 2009-2018 - pancake */

#include "r_list.h"
#include "r_config.h"
#include "r_core.h"
#include "r_print.h"
#include "r_bin.h"
#include "r_debug.h"

static const char *help_msg_o[] = {
	"Usage: o","[com- ] [file] ([offset])","",
	"o","","list opened files",
	"o"," 4","Switch to open file on fd 4",
	"o","-1","close file descriptor 1",
	"o-","!*","close all opened files",
	"o--","","close all files, analysis, binfiles, flags, same as !r2 --",
	"o"," [file]","open [file] file in read-only",
	"o+"," [file]","open file in read-write mode",
	"o"," [file] 0x4000 rwx", "map file at 0x4000",
	"oa","[-] [A] [B] [filename]","Specify arch and bits for given file",
	"oq","","list all open files",
	"o*","","list opened files in r2 commands",
	"o."," [len]","open a malloc://[len] copying the bytes from current offset",
	"o=","","list opened files (ascii-art bars)",
	"ob","[?] [lbdos] [...]","list opened binary files backed by fd",
	"oc"," [file]","open core file, like relaunching r2",
	"of"," [file]","open file and map it at addr 0 as read-only",
	"oi","[-|idx]","alias for o, but using index instead of fd",
	"oj","[?]	","list opened files in JSON format",
	"oL","","list all IO plugins registered",
	"om","[?]","create, list, remove IO maps",
	"on"," [file] 0x4000","map raw file at 0x4000 (no r_bin involved)",
	"oo","[?]","reopen current file (kill+fork in debugger)",
	"oo","+","reopen current file in read-write",
	"ood","[r] [args]","reopen in debugger mode (with args)",
	"oo[bnm]"," [...]","see oo? for help",
	"op"," [fd]", "prioritize given fd (see also ob)",
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
	"Usage:", "oa [addr] ([filename])", " # load bininfo and update flags",
	"oba", " [addr]", "Open bin info from the given address",
	"oba", " [addr] [filename]", "Open file and load bin info at given address",
	NULL
};

static const char *help_msg_ob[] = {
	"Usage:", "ob", " # List open binary files backed by fd",
	"ob", "", "List opened binary files and objid",
	"ob*", "", "List opened binary files and objid (r2 commands)",
	"ob", " [fd objid]", "Switch to open binary file by fd number and objid",
	"oba", " [addr]", "Open bin info from the given address",
	"oba", " [addr] [filename]", "Open file and load bin info at given address",
	"obb", " [fd]", "Switch to open binfile by fd number",
	"obf", " ([file])", "Load bininfo for current file (useful for r2 -n)",
	"obj", "", "List opened binary files and objid (JSON format)",
	"obr", " [baddr]", "Rebase current bin object",
	"ob-", "[objid]", "Delete binfile by binobjid",
	"ob-", "*", "Delete all binfiles",
	"obo", " [objid]", "Switch to open binary file by objid",
	NULL
};

static const char *help_msg_oj[] = {
	"Usage:", "oj [~{}]", " # Use ~{} to indent the JSON",
	"oj", "", "list opened files in JSON format", NULL
};

static const char *help_msg_om[] = {
	"Usage:", "om[-] [arg]", " # map opened files",
	"om", "", "list all defined IO maps",
	"omq", "", "list all maps and their fds",
	"om*", "", "list all maps in r2 commands format",
	"om=", "", "list all maps in ascii art",
	"omj", "", "list all maps in json format",
	"om", " [fd]", "list all defined IO maps for a specific fd",
	"om", "-mapid", "remove the map with corresponding id",
	"om", " fd vaddr [size] [paddr] [rwx] [name]", "create new io map",
	"omm"," [fd]", "create default map for given fd. (omm `oq`)",
	"om.", "", "show map, that is mapped to current offset",
	"omn", " mapid [name]", "set/delete name for map with mapid",
	"omn.", "([-|name])", "show/set/delete name for current map",
	"omf", " [mapid] rwx", "change flags/perms for current/given map",
	"omfg", "[+-]rwx", "change flags/perms for all maps (global)",
	"omb", " mapid addr", "relocate map with corresponding id",
	"omb.", " addr", "relocate current map",
	"omr", " mapid newsize", "resize map with corresponding id",
	"omp", " mapid", "prioritize map with corresponding id",
	"ompf", "[fd]", "prioritize map by fd",
	"ompb", " binid", "prioritize maps of mapped bin with binid",
	"omps", " sectionid", "prioritize maps of mapped section with sectionid",
	NULL
};

static const char *help_msg_oo[] = {
	"Usage:", "oo[-] [arg]", " # map opened files",
	"oo", "", "reopen current file",
	"oo+", "", "reopen in read-write",
	"oob", "", "reopen loading rbin info",
	"ood", "", "reopen in debug mode",
	"oom", "", "reopen in malloc://",
	"oon", "", "reopen without loading rbin info",
	"oon+", "", "reopen in read-write mode without loading rbin info",
	"oonn", "", "reopen without loading rbin info, but with header flags",
	"oonn+", "", "reopen in read-write mode without loading rbin info, but with",
	NULL
};

static const char *help_msg_oo_plus[] = {
	"oo+", "", "reopen in read-write",
	NULL
};

static const char *help_msg_oob[] = {
	"oob", "", "reopen loading rbin info",
	NULL
};

static const char *help_msg_ood[] = {
	"ood"," [args]","reopen in debugger mode (with args)",
	"oodr"," [rarun2]","same as dor ..;ood",
	NULL
};

static const char *help_msg_oon[] = {
	"oon", "", "reopen without loading rbin info",
	NULL
};

static const char *help_msg_oonn[] = {
	"oonn", "", "reopen without loading rbin info, but with header flags",
	NULL
};

static inline ut32 find_binfile_id_by_fd (RBin *bin, ut32 fd) {
	RListIter *it;
	RBinFile *bf;
	r_list_foreach (bin->binfiles, it, bf) {
		if (bf->fd == fd) {
			return bf->id;
		}
	}
	return UT32_MAX;
}

static RBinObject *find_binfile_by_id (RBin *bin, ut32 id) {
	RListIter *it, *it2;
	RBinFile *bf;
	RBinObject *obj;
	r_list_foreach (bin->binfiles, it, bf) {
		r_list_foreach (bf->objs, it2, obj) {
			if (obj->id == id) {
				return obj;
			}
		}
	}
	return NULL;
}

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

// very similiar to section list, must reuse more code
static void list_maps_visual(RIO *io, ut64 seek, ut64 len, int width, int use_color) {
	ut64 mul, min = -1, max = 0;
	SdbListIter *iter;
	RIOMap *s;
	int j, i;

	width -= 80;
	if (width < 1) {
		width = 30;
	}

	// seek = (io->va || io->debug) ? r_io_section_vaddr_to_maddr_try (io, seek) : seek;

	ls_foreach_prev (io->maps, iter, s) {			//this must be prev, maps the previous map allways has lower priority
		min = R_MIN (min, s->itv.addr);
		max = R_MAX (max, r_itv_end (s->itv) - 1);
	}
	mul = (max - min) / width;
	if (min != -1 && mul != 0) {
		const char * color = "", *color_end = "";
		i = 0;
		ls_foreach_prev (io->maps, iter, s) {
			if (use_color) {
				color_end = Color_RESET;
				if (s->flags & 1) { // exec bit
					color = Color_GREEN;
				} else if (s->flags & 2) { // write bit
					color = Color_RED;
				} else {
					color = "";
					color_end = "";
				}
			} else {
				color = "";
				color_end = "";
			}
			if (io->va) {
				io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", i,
						r_itv_contain (s->itv, seek) ? '*' : ' ',
						color, s->itv.addr, color_end);
			} else {
				io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", i,
						r_itv_contain (s->itv, seek) ? '*' : ' ',
						color, s->itv.addr, color_end);
			}
			for (j = 0; j < width; j++) {
				ut64 pos = min + j * mul;
				ut64 npos = min + (j + 1) * mul;
				// TODO trailing bytes
				io->cb_printf (r_itv_overlap2 (s->itv, pos, npos - pos) ? "#" : "-");
			}
			io->cb_printf ("| %s0x%08"PFMT64x"%s %s %d %s\n",
					color, r_itv_end (s->itv), color_end,
					r_str_rwx_i (s->flags), s->fd, s->name);
			i++;
		}
		/* current seek */
		if (i > 0 && len != 0) {
			if (seek == UT64_MAX) {
				seek = 0;
			}
			//len = 8096;//r_io_size (io);
			io->cb_printf ("=>  0x%08"PFMT64x" |", seek);
			for (j=0;j<width;j++) {
				io->cb_printf (
					((j*mul)+min >= seek &&
					 (j*mul)+min <= seek+len)
					?"^":"-");
			}
			io->cb_printf ("| 0x%08"PFMT64x"\n", seek+len);
		}
	}
}

static void cmd_open_bin(RCore *core, const char *input) {
	const char *value = NULL;
	ut32 binfile_num = -1, binobj_num = -1;

	switch (input[1]) {
	case '\0': // "ob"
	case 'q': // "obj"
	case 'j': // "obj"
	case '*': // "ob*"
		r_core_bin_list (core, input[1]);
		break;
	case 'a': // "oba"
		if ('?' == input[2]) {
			r_core_cmd_help (core, help_msg_oa);
			break;
		}
		if (input[2] && input[3]) {
			char *arg = strdup (input + 3);
			char *filename = strchr (arg, ' ');
			if (filename) {
				RIODesc *desc = r_io_open (core->io, filename + 1, R_IO_READ, 0);
				if (desc) {
					*filename = 0;
					ut64 addr = r_num_math (core->num, arg);
					r_bin_load_io (core->bin, desc->fd, addr, 0, 0);
					r_io_desc_close (desc);
					r_core_cmd0 (core, ".is*");
				} else {
					eprintf ("Cannot open %s\n", filename + 1);
				}
			} else {
				ut64 addr = r_num_math (core->num, input + 2);
				int fd = r_io_fd_get_current (core->io);
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					r_bin_load_io (core->bin, desc->fd, addr, 0, 0);
					r_core_cmd0 (core, ".is*");
				} else {
					eprintf ("No file to load bin from?\n");
				}
			}
			free (arg);
		} else {
			eprintf ("RCoreFile has been killed here, this needs to be redone properly from non-uri iofiles\n");
			RList *files = r_id_storage_list (core->io->files);
			RIODesc *desc;
			RListIter *iter;
			r_list_foreach (files, iter, desc) {
				r_bin_load_io (core->bin, desc->fd, core->offset, 0, 0);
				r_core_cmd0 (core, ".is*");
				break;
			}
			r_list_free (files);
		}
		//r_bin_load_io_at_offset_as (core->bin, core->file->desc,
		break;
	case 'b': // "obb"
		{
			ut32 fd;
			value = *(input + 3) ? input + 3 : NULL;
			if (!value) {
				eprintf ("Invalid fd number.");
				break;
			}
			binfile_num = UT32_MAX;
			fd = *value && r_is_valid_input_num_value (core->num, value) ?
				r_get_input_num_value (core->num, value) : UT32_MAX;
			binfile_num = find_binfile_id_by_fd (core->bin, fd);
			if (binfile_num == UT32_MAX) {
				eprintf ("Invalid fd number.");
				break;
			}
			r_core_bin_raise (core, binfile_num, -1);
		}
		break;
	case ' ': // "ob "
	{
		ut32 fd;
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
			eprintf ("Invalid arguments\n");
			eprintf ("usage: ob fd obj\n");
			free (v);
			break;
		}
		tmp = r_str_word_get0 (v, 0);
		fd  = *v && r_is_valid_input_num_value (core->num, tmp) ?
			r_get_input_num_value (core->num, tmp) : UT32_MAX;
		if (n == 2) {
			tmp = r_str_word_get0 (v, 1);
			binobj_num  = *v && r_is_valid_input_num_value (core->num, tmp) ?
				r_get_input_num_value (core->num, tmp) : UT32_MAX;
		} else {
			binfile_num = find_binfile_id_by_fd (core->bin, fd);
		}
		r_core_bin_raise (core, binfile_num, binobj_num);
		free (v);
		break;
	}
	case 'r': // "obr"
		r_core_bin_rebase (core, r_num_math (core->num, input + 3));
		r_core_cmd0 (core, ".is*");
		break;
	case 'f':
		// TODO: specify path to file?
		r_core_bin_load (core, NULL, UT64_MAX);
		value = input[2] ? input + 2 : NULL;
		// r2_obf (core, value);
		break;
	case 'o': // "obo"
		value = input[2] ? input + 2 : NULL;
		if (!value) {
			eprintf ("Invalid argument");
			break;
		}
		if (*value == ' ') value ++;
		binobj_num  = *value && r_is_valid_input_num_value (core->num, value) ?
				r_get_input_num_value (core->num, value) : UT32_MAX;
		if (binobj_num == UT32_MAX) {
			eprintf ("Invalid binobj_num");
			break;
		}
		r_core_bin_raise (core, -1, binobj_num);
		break;
	case '-': // "ob-"
		if (input[2] == '*') {
			r_bin_file_delete_all (core->bin);
		} else {
			ut32 fd;
			value = r_str_trim_ro (input + 2);
			if (!value) {
				eprintf ("Invalid argument\n");
				break;
			}
			fd  = *value && r_is_valid_input_num_value (core->num, value) ?
					r_get_input_num_value (core->num, value) : UT32_MAX;
			RBinObject *bo = find_binfile_by_id (core->bin, fd);
			if (!bo) {
				eprintf ("Invalid binid\n");
				break;
			}
			if (r_core_bin_delete (core, binfile_num, bo->id)) {
				if (!r_bin_file_delete (core->bin, fd)) {
					eprintf ("Cannot find an RBinFile associated with that fd.\n");
				}
			}
		}
		break;
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
	ls_foreach_prev (io->maps, iter, map) {			//this must be prev
		if (fd != -1 && map->fd != fd) {
			continue;
		}
		switch (mode) {
		case 'q':
			print->cb_printf ("%d %d\n", map->fd, map->id);
			break;
		case 'j':
			if (!first) {
				print->cb_printf (",");
			}
			first = false;
			print->cb_printf ("{\"map\":%i,\"fd\":%d,\"delta\":%"PFMT64u",\"from\":%"PFMT64u
					",\"to\":%"PFMT64u",\"flags\":\"%s\",\"name\":\"%s\"}", map->id, map->fd,
					map->delta, map->itv.addr, r_itv_end (map->itv),
					r_str_rwx_i (map->flags), (map->name ? map->name : ""));
			break;
		case 1:
		case '*':
		case 'r':
			print->cb_printf ("om %d 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x" %s%s%s\n", map->fd,
					map->itv.addr, map->itv.size, map->delta, r_str_rwx_i(map->flags),
					map->name ? " " : "", map->name ? map->name : "");
			break;
		default:
			print->cb_printf ("%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s %s\n", map->id, map->fd,
					map->delta, map->itv.addr, r_itv_end (map->itv) - 1,
					r_str_rwx_i (map->flags), (map->name ? map->name : ""));
			break;
		}
	}
	if (mode == 'j') {
		print->cb_printf ("]\n");
	}
}

static void cmd_omfg (RCore *core, const char *input) {
	SdbListIter *iter;
	RIOMap *map;
	input = r_str_trim_ro (input);
	if (input) {
		int flags = *input
		? (*input == '+' || *input == '-')
			? r_str_rwx (input + 1)
			: r_str_rwx (input)
		: 7;
		switch (*input) {
		case '+':
			ls_foreach (core->io->maps, iter, map) {
				map->flags |= flags;
			}
			break;
		case '-':
			ls_foreach (core->io->maps, iter, map) {
				map->flags &= ~flags;
			}
			break;
		default:
			ls_foreach (core->io->maps, iter, map) {
				map->flags = flags;
			}
			break;
		}
	}
}

static void cmd_omf (RCore *core, const char *input) {
	SdbListIter *iter;
	RIOMap *map;
	char *arg = strdup (r_str_trim_ro (input));
	if (!arg) {
		return;
	}
	char *sp = strchr (arg, ' ');
	if (sp) {
		// change perms of Nth map
		*sp++ = 0;
		int id = r_num_math (core->num, arg);
		int flags = (*sp)? r_str_rwx (sp): 7;
		ls_foreach (core->io->maps, iter, map) {
			if (map->id == id) {
				map->flags = flags;
				break;
			}
		}
	} else {
		// change perms of current map
		int flags = (arg && *arg)? r_str_rwx (arg): 7;
		ls_foreach (core->io->maps, iter, map) {
			if (r_itv_contain (map->itv, core->offset)) {
				map->flags = flags;
			}
		}
	}
	free (arg);
}

static void cmd_open_map(RCore *core, const char *input) {
	ut64 fd = 0LL;
	ut32 id = 0;
	char *s = NULL, *p = NULL, *q = NULL;
	ut64 new;
	RIOMap *map = NULL;
	const char *P;

	switch (input[1]) {
	case '.':
		map = r_io_map_get (core->io, core->offset);
		if (map) {
			core->print->cb_printf ("map: %i fd: %i +0x%"PFMT64x" 0x%"PFMT64x
				" - 0x%"PFMT64x" ; %s : %s\n", map->id, map->fd,
				map->delta, map->itv.addr, r_itv_end (map->itv),
			r_str_rwx_i (map->flags), map->name ? map->name : "");
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
	case 'p':
		switch (input[2]) {
		case 'f': // "ompf"
			fd = r_num_math (core->num, input + 3);
			if (!r_io_map_priorize_for_fd (core->io, (int)fd)) {
				eprintf ("Cannot prioritize any map for fd %d\n", (int)fd);
			}
			break;
		case 'b': // "ompb"
			id = (ut32)r_num_math (core->num, input + 4);
			if (!r_io_section_priorize_bin (core->io, id)) {
				eprintf ("Cannot prioritize bin with binid %d\n", id);
			}
			break;
		case 's': // "omps"
			id = (ut32)r_num_math (core->num, input + 4);
			if (!r_io_section_priorize (core->io, id)) {
				eprintf ("Cannot prioritize section with sectionid %d\n", id);
			}
			break;
		case ' ': // "omp"
			id = r_num_math (core->num, input + 3);		//mapid
			if (r_io_map_exists_for_id (core->io, id)) {
				r_io_map_priorize (core->io, id);
			} else {
				eprintf ("Cannot find any map with mapid %d\n", id);
			}
			break;
		}
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
				map = r_io_map_add (core->io, fd, rwx_arg ? rwx : desc->flags, paddr, vaddr, size, true);
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
					r_io_map_set_name (map, input + 3);
					break;
				}
			}
		} else {
			if (!(s = strdup (&input[2]))) {
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
				id = (ut32)r_num_math (core->num, s);
				map = r_io_map_get (core->io, id);
				r_io_map_del_name (map);
				s = p;
				break;
			}
			*q = '\0';
			q++;
			id = (ut32)r_num_math (core->num, s);
			map = r_io_map_get (core->io, id);
			if (*q) {
				r_io_map_set_name (map, q);
			} else {
				r_io_map_del_name (map);
			}
			s = p;
		}
		break;
	case 'm': // "omm"
		{
			ut64 fd = input[3]? r_num_math (core->num, input + 3): UT64_MAX;
			RIODesc *desc = r_io_desc_get (core->io, fd);
			if (!desc) {
				fd = r_io_fd_get_current (core->io);
				desc = r_io_desc_get (core->io, fd);
			}
			if (desc) {
				ut64 size = r_io_desc_size (desc);
				map = r_io_map_add (core->io, fd, desc->flags, 0, 0, size, true);
				r_io_map_set_name (map, desc->name);
			} else {
				eprintf ("Usage: omm [fd]\n");
			}
		}
		break;
	case '-': // "om-"
		if (input[2] == '*') {
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
		map_list (core->io, input[1], core->print, -1);
		break;
	case '=': // "om="
		list_maps_visual (core->io, core->offset, core->blocksize,
			r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg_om);
		break;
	}
	R_FREE (s);
	r_core_block_read (core);
}

R_API void r_core_file_reopen_in_malloc (RCore *core) {
	RListIter *iter;
	RList *files = r_id_storage_list (core->io->files);
	RIODesc *desc;
	r_list_foreach (files, iter, desc) {
		if (strstr (desc->name, "://")) {
			continue;
		}
		ut64 sz = r_io_desc_size (desc);
		ut8 *buf = calloc (sz, 1);
		if (!buf) {
			eprintf ("Cannot allocate %d\n", (int)sz);
			continue;
		}
		(void)r_io_pread_at (core->io, 0, buf, sz);
		char *url = r_str_newf ("malloc://%d", (int)sz);
		// use r_io_desc_exchange pls
		RIODesc *newDesc = r_io_open (core->io, url, R_IO_READ | R_IO_WRITE, 0);
		if (newDesc) {
			r_io_desc_close (desc);
			(void)r_io_write_at (core->io, 0, buf, sz);
		} else {
			eprintf ("Cannot open %s\n", url);
		}
		free (buf);
		free (url);
		break;
	}
	r_core_block_read (core);
}

R_API void r_core_file_reopen_debug (RCore *core, const char *args) {
	RCoreFile *ofile = core->file;
	RBinFile *bf = NULL;
	RIODesc *desc;
	char *binpath = NULL;
	if (!ofile || !(desc = r_io_desc_get (core->io, ofile->fd)) || !desc->uri) {
		eprintf ("No file open?\n");
		return;
	}
	bf = r_bin_file_find_by_fd (core->bin, ofile->fd);
	binpath = (bf && bf->file) ? strdup (bf->file) : NULL;
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
	int bits = core->assembler->bits;
	char *oldname = r_file_abspath (binpath);
	char *newfile = r_str_newf ("dbg://%s %s", oldname, args);
	char *newfile2 = strdup (newfile);
	desc->uri = newfile;
	desc->referer = NULL;
	r_config_set_i (core->config, "asm.bits", bits);
	r_config_set_i (core->config, "cfg.debug", true);
	r_core_file_reopen (core, newfile, 0, 2);
	newfile = newfile2;
#if !__WINDOWS__
	ut64 new_baddr = r_debug_get_baddr (core->dbg, newfile);
	ut64 old_baddr = r_config_get_i (core->config, "bin.baddr");
	if (old_baddr != new_baddr) {
		r_bin_set_baddr (core->bin, new_baddr);
		r_config_set_i (core->config, "bin.baddr", new_baddr);
		r_core_bin_rebase (core, new_baddr);
		// r_core_bin_load (core, newfile, new_baddr);
		// reload symbols with new baddr
		r_core_cmd0 (core, ".is*");
		r_core_cmd0 (core, ".ir*");
		r_core_cmd0 (core, ".iz*");
		r_core_cmd0 (core, ".iM*");
	}
#endif
	r_core_cmd0 (core, "sr PC");
	free (oldname);
	free (binpath);
	free (newfile);
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
			(desc->io && (desc->io->desc == desc)) ? '*' : '-', r_str_rwx_i (desc->flags), sz);
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
			r_str_rwx_i (desc->flags), r_io_desc_size (desc), desc->uri);
	return true;
}

static int cmd_open(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int perms = R_IO_READ;
	ut64 baddr = r_config_get_i (core->config, "bin.baddr"),
	     addr = 0LL;
	int nowarn = r_config_get_i (core->config, "file.nowarn"),
	    argc, fd;
	RCoreFile *file;
	bool silence = false;
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
		} else if (input[1] == '+') { // "on+"
			write = true;
			perms |= R_IO_WRITE;
			if (input[2] != ' ') {
				eprintf ("Usage: on+ file [addr] [rwx]\n");
				return 0;
			}
			ptr = input + 3;
		} else if (input[1] == 's') { // "ons"
			silence = true;
			if (input[2] == '+') { // "ons+"
				write = true;
				perms |= R_IO_WRITE;
				if (input[3] != ' ') {
					eprintf ("Usage: ons+ file [addr] [rwx]\n");
					return 0;
				}
				ptr = input + 4;
			} else if (input[2] == ' ') {
				ptr = input + 3;
			} else {
				eprintf ("Usage: ons file [addr] [rwx]\n");
				return 0;
			}
		} else if (input[1] == ' ') {
			ptr = input + 2;
		} else {
			eprintf ("Usage: on file [addr] [rwx]\n");
			return 0;
		}
		argv = r_str_argv (ptr, &argc);
		if (!argc) {
			if (write) {
				if (silence) eprintf ("Usage: ons+ file [addr] [rwx]\n");
				else eprintf ("Usage: on+ file [addr] [rwx]\n");
			} else {
				if (silence) eprintf ("Usage: ons file [addr] [rwx]\n");
				else eprintf ("Usage: on file [addr] [rwx]\n");
			}
			r_str_argv_free (argv);
			return 0;
		} else {
			ptr = argv[0];
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
		if ((file = r_core_file_open (core, ptr, perms, addr))) {
			fd = file->fd;
			r_io_map_add (core->io, fd, perms, 0LL, addr,
					r_io_fd_size (core->io, fd), true);
		}
		r_str_argv_free (argv);
		if (!silence) {
			eprintf ("%d\n", fd);
		}
		r_core_block_read (core);
		return 0;
#if 1
	// XXX projects use the of command, but i think we should deprecate it... keeping it for now
	case 'f': // "of"
		if ((input[1] == 's') && (input[2] == ' ')) {
			silence = true;
			ptr = input + 3;
		} else if (input[1] == ' ') {
			ptr = input + 2;
		} else {
			eprintf ("wrong\n");
			return 0;
		}
		argv = r_str_argv (ptr, &argc);
		if (argc == 0) {
			eprintf ("wrong\n");
			r_str_argv_free (argv);
			return 0;
		} else if (argc == 2) {
			perms = r_str_rwx (argv[1]);
		}
		fd = r_io_fd_open (core->io, argv[0], perms, 0);
		if (!silence) {
			eprintf ("%d\n", fd);
		}
		r_str_argv_free (argv);
		return 0;
#else
		{
			if ((input[1] == 's') && (input[2] == ' ')) {
				silence = true;
				input++;
			}
			addr = 0; // honor bin.baddr ?
			const char *argv0 = r_str_trim_ro (input + 2);
			if ((file = r_core_file_open (core, argv0, perms, addr))) {
				fd = file->fd;
				if (!silence) {
					eprintf ("%d\n", fd);
				}
				r_core_bin_load (core, argv0, baddr);
			} else if (!nowarn) {
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
		{
			int fd = r_num_math (core->num, input + 1);
			if (fd) {
				RIODesc *desc = r_io_desc_get (core->io, fd);
				if (desc) {
					// only useful for io.va=0
					core->io->desc = desc;
					// load bininfo for given fd
					r_core_cmdf (core, "ob %d", fd);
				}
			}
			r_core_block_read (core);
		}
		return 0;
		break;
	case '+': // "o+"
		perms |= R_IO_WRITE;
	case 's': // "os"
		silence = true;
	case ' ': // "o" "o "
		if (silence) {
			ptr = input + 2;
		} else {
			ptr = input + 1;
		}
		if (ptr[-1] != ' ') {
			eprintf ("wrong\n");
			return 0;
		}
		argv = r_str_argv (ptr, &argc);
		if (argc == 0) {
			eprintf ("wrong\n");
			r_str_argv_free (argv);
			return 0;
		}
		if (argv) {
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
				if (!silence) {
					eprintf ("%d\n", fd);
				}
				r_core_bin_load (core, argv0, baddr);
			} else if (!nowarn) {
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
		r_id_storage_foreach (core->io->files, desc_list_quiet_cb, core->print);
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
		r_core_file_list (core, (int)(*input));
		break;
	case 'L': // "oL"
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1] == ' ') {
			if (r_lib_open (core->lib, input+2) == R_FAIL) {
				eprintf ("Oops\n");
			}
		} else {
			if ('j' == input[1]) {
				r_io_plugin_list_json (core->io);
			} else {
				r_io_plugin_list (core->io);
			}
			eprintf ("Usage: op [r2plugin."R_LIB_EXT"]\n");
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
	case 'u':
		{
			RListIter *iter = NULL;
			RCoreFile *f;
			int binfile_num;
			core->switch_file_view = 0;
			int num = atoi (input + 2);

			r_list_foreach (core->files, iter, f) {
				if (f->fd == num) {
					core->file = f;
				}
			}
			r_io_use_fd (core->io, num);
			binfile_num = find_binfile_id_by_fd (core->bin, num);
			r_core_bin_raise (core, binfile_num, -1);
		}
		r_core_block_read (core);
		break;
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
			r_list_purge (core->files);
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
			eprintf ("Usage: o-#, o-! or o-*, where # is the filedescriptor number\n");
		}
		break;
	case '.': // "o."
		{
			int len = r_num_math (core->num, input + 1);
			if (len < 1) {
				len = core->blocksize;
			}
                        char *uri = r_str_newf ("malloc://%d", len);
			ut8 *data = calloc (len, 1);
			r_core_read_at (core, core->offset, data, len);
                        RIODesc *fd = r_io_open (core->io, uri, R_IO_READ | R_IO_WRITE, 0);
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
			} else if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_ood);
			} else {
				r_core_file_reopen_debug (core, input + 2);
			}
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
				perms = (input[3] == '+')? R_IO_READ|R_IO_WRITE: 0;
				r_core_file_reopen (core, input + 4, perms, 0);
				// TODO: Use API instead of !rabin2 -rk
				if (desc) {
					r_core_cmdf (core, ".!rabin2 -rk '' '%s'", desc->name);
				}
			} else if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_oon);
				break;
			}

			perms = ('+' == input[2])? R_IO_READ | R_IO_WRITE: 0;
			r_core_file_reopen (core, input + 3, perms, 0);
			break;
		case '+': // "oo+"
			if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_oo_plus);
			} else if (core && core->io && core->io->desc) {
				int fd;
				int perms = R_IO_READ | R_IO_WRITE;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)r_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
					perms |= core->io->desc->flags;
				}
				if (r_io_reopen (core->io, fd, perms, 644)) {
					SdbListIter *iter;
					RIOMap *map;
					ls_foreach_prev (core->io->maps, iter, map) {
						if (map->fd == fd) {
							map->flags |= R_IO_WRITE;
							map->flags |= R_IO_EXEC;
						}
					}
				}
			}
			break;
		case '\0': // "oo"
			if (core && core->io && core->io->desc) {
				//does not work for debugging
				int fd;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)r_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
				}
				r_io_reopen (core->io, fd, R_IO_READ, 644);
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
			// memleak? lose all settings wtf
			// if load fails does not fallbacks to previous file
			r_core_fini (core);
			r_core_init (core);
			if (!r_core_file_open (core, input + 2, R_IO_READ, 0)) {
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
