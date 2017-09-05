/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "r_list.h"
#include "r_config.h"
#include "r_core.h"
#include "r_print.h"
#include "r_bin.h"
#include "r_debug.h"

static const char *help_msg_o[] = {
	"Usage: o","[com- ] [file] ([offset])","",
	"o","","list opened files",
	"oq","","list all open files",
	"o*","","list opened files in r2 commands",
	"o=","","list opened files (ascii-art bars)",
	"ob","[?] [lbdos] [...]","list opened binary files backed by fd",
	"oc"," [file]","open core file, like relaunching r2",
	"oi","[-|idx]","alias for o, but using index instead of fd",
	"oj","[?]	","list opened files in JSON format",
	"oL","","list all IO plugins registered",
	"om","[?]","create, list, remove IO maps",
	"on"," [file] 0x4000","map raw file at 0x4000 (no r_bin involved)",
	"oo","[?]","reopen current file (kill+fork in debugger)",
	"oo","+","reopen current file in read-write",
	"ood"," [args]","reopen in debugger mode (with args)",
	"oo[bnm]"," [...]","see oo? for help",
	"op"," ["R_LIB_EXT"]","open r2 native plugin (asm, bin, core, ..)",
	"o"," 4","Switch to open file on fd 4",
	"o","-1","close file descriptor 1",
	"o-","*","close all opened files",
	"o--","","close all files, analysis, binfiles, flags, same as !r2 --",
	"o"," [file]","open [file] file in read-only",
	"o","+ [file]","open file in read-write mode",
	"o"," [file] 0x4000","map file at 0x4000",
	"ox", " fd fdx", "exchange the descs of fd and fdx and keep the mapping",
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
	"obj", "", "List opened binary files and objid (JSON format)",
	"obr", " [baddr]", "Rebase current bin object",
	"ob-", " [fd]", "Delete binfile by fd",
	"obd", " [objid]", "Delete binary file by objid. Do nothing if only one loaded.",
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
	"om", " fd vaddr [size] [paddr] [name]", "create new io map",
	"om.", "", "show map, that is mapped to current offset",
	"omn", " mapid [name]", "set/delete name for map with mapid",
	"omf", " [mapid] rwx", "change flags/perms for current/given map",
	"omfg", "[+-]rwx", "change flags/perms for all maps (global)",
	"omr", " mapid addr", "relocate map with corresponding id",
	"omp", " mapid", "priorize map with corresponding id",
	"ompf", "[fd]", "priorize map by fd",
	"ompb", " binid", "priorize maps of mapped bin with binid",
	"omps", " sectionid", "priorize maps of mapped section with sectionid",
	"om*", "", "show r2 commands to restore mapaddr",
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
	ut64 mul, min = -1, max = -1;
	SdbListIter *iter;
	RIOMap *s;
	int j, i;

	width -= 80;
	if (width < 1) {
		width = 30;
	}

	// seek = (io->va || io->debug) ? r_io_section_vaddr_to_maddr_try (io, seek) : seek;

	ls_foreach_prev (io->maps, iter, s) {			//this must be prev, maps the previous map allways has lower priority
		if (min == -1 || s->from < min) {
			min = s->from;
		}
		if (max == -1 || s->to > max) {
			max = s->to;
		}
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
						(seek>=s->from&& seek<s->to)?'*':' ',
						//(seek>=s->vaddr && seek<s->vaddr+s->size)?'*':' ',
						color, s->from, color_end);
			} else {
				io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", i,
						(seek >= s->from && seek < s->to) ? '*':' ',
						color, s->from, color_end);
			}
			for (j=0; j<width; j++) {
				ut64 pos = min + (j*mul);
				ut64 npos = min + ((j+1)*mul);
				if (s->from<npos && (s->to)>pos)
					io->cb_printf ("#");
				else io->cb_printf ("-");
			}
			io->cb_printf ("| %s0x%08"PFMT64x"%s %s %d %s\n",
				color, s->to, color_end,
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
	case 'j': // "obj"
	case '*': // "ob*"
		r_core_bin_list (core, input[1]);
		break;
	case 'a': // "oba"
		if ('?' == input[2]) {
			r_core_cmd_help (core, help_msg_oa);
			break;
		}
		if (input[3]) {
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
				RCoreFile *cf = r_core_file_cur (core);
				if (cf) {
					RIODesc *desc = r_io_desc_get (core->io, cf->fd);
					if (desc) {
						r_bin_load_io (core->bin, desc->fd, addr, 0, 0);
						r_core_cmd0 (core, ".is*");
					} else {
						eprintf ("No file to load bin from?\n");
					}
				}
			}
			free (arg);
		} else {
			/* reload all bininfo */
			RIODesc *desc;
			RListIter *iter;
			RCoreFile *file;
			r_list_foreach (core->files, iter, file) {
				desc = r_io_desc_get (core->io, file->fd);
				r_bin_load_io (core->bin, desc->fd, core->offset, 0, 0);
				r_core_cmd0 (core, ".is*");
				break;
			}
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
		if (n < 2 || n > 2) {
			eprintf ("Invalid arguments\n");
			eprintf ("usage: ob fd obj\n");
			free (v);
			break;
		}
		tmp = r_str_word_get0 (v, 0);
		fd  = *v && r_is_valid_input_num_value (core->num, tmp) ?
			r_get_input_num_value (core->num, tmp) : UT32_MAX;
		tmp = r_str_word_get0 (v, 1);
		binobj_num  = *v && r_is_valid_input_num_value (core->num, tmp) ?
			r_get_input_num_value (core->num, tmp) : UT32_MAX;
		binfile_num = find_binfile_id_by_fd (core->bin, fd);
		r_core_bin_raise (core, binfile_num, binobj_num);
		free (v);
		break;
	}
	case 'r': // "obr"
		r_core_bin_rebase (core, r_num_math (core->num, input + 3));
		r_core_cmd0 (core, ".is*");
		break;
	case 'o': // "obo"
		value = input[3] ? input + 3 : NULL;
		if (!value) {
			eprintf ("Invalid argument");
			break;
		}
		binobj_num  = *value && r_is_valid_input_num_value (core->num, value) ?
				r_get_input_num_value (core->num, value) : UT32_MAX;
		if (binobj_num == UT32_MAX) {
			eprintf ("Invalid binobj_num");
			break;
		}
		r_core_bin_raise (core, -1, binobj_num);
		break;
	case '-': // "ob-"
		//FIXME this command doesn't remove nothing
		if (input[2] == '*') {
			//FIXME this only delete from a list but it doesn't free any space
			r_cons_printf ("[i] Deleted %d binfiles\n",
					r_bin_file_delete_all (core->bin));
		} else {
			ut32 fd;
			value = input[3] ? input + 3 : NULL;
			if (!value) {
				eprintf ("Invalid argument\n");
				break;
			}
			fd  = *value && r_is_valid_input_num_value (core->num, value) ?
					r_get_input_num_value (core->num, value) : UT32_MAX;

			binfile_num = find_binfile_id_by_fd (core->bin, fd);
			if (binfile_num == UT32_MAX) {
				eprintf ("Invalid fd\n");
				break;
			}
			if (r_core_bin_delete (core, binfile_num, -1)){
				if (!r_bin_file_delete (core->bin, fd))
					eprintf ("Cannot find an RBinFile associated with that fd.\n");
			} else {
				eprintf ("Couldn't erase because there must be 1 bin object loaded\n");
			}
		}
		break;
	case 'd': // "obd" backward compat, must be deleted
		value = input[2] ? input + 2 : NULL;
		if (!value) {
			eprintf ("Invalid bin object number.");
			break;
		}
		binobj_num = *value && r_is_valid_input_num_value (core->num, value) ?
			r_get_input_num_value (core->num, value) : UT32_MAX;
		if (binobj_num == UT32_MAX) {
			eprintf ("Invalid bin object number.");
			break;
		}
		r_core_bin_delete (core, -1, binobj_num);
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
			print->cb_printf ("{\"map\":%i,\"fd\":%d,\"delta\":%"PFMT64d",\"from\":%"PFMT64d
					",\"to\":%"PFMT64d",\"flags\":\"%s\",\"name\":\"%s\"}", map->id, map->fd,
					map->delta, map->from, map->to,
					r_str_rwx_i (map->flags), (map->name ? map->name : ""));
			break;
		case 1:
		case '*':
		case 'r':
			print->cb_printf ("om %d 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x"\n", map->fd,
					map->from, map->to - map->from + 1, map->delta);
			break;
		default:
			print->cb_printf ("%2d fd: %i +0x%08"PFMT64x" 0x%08"PFMT64x
					" - 0x%08"PFMT64x" %s %s\n", map->id, map->fd,
					map->delta, map->from, map->to,
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
	input = r_str_chop_ro (input);
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
	char *arg = strdup (r_str_chop_ro (input));
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
			if (R_BETWEEN (map->from, core->offset, map->to)) {
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
			map->delta, map->from, map->to,
			r_str_rwx_i (map->flags), map->name ? map->name : "");
		}

		break;
	case 'r':
		if (input[2] != ' ') {
			break;
		}
		P = strchr (input+3, ' ');
		if (P) {
			id = (ut32)r_num_math (core->num, input+3);	//mapid
			new = r_num_math (core->num, P+1);
			r_io_map_remap (core->io, id, new);
		}
		break;
	case 'p':
		switch (input[2]) {
		case 'f': // "ompf"
			fd = r_num_math (core->num, input + 3);
			if (!r_io_map_priorize_for_fd (core->io, (int)fd)) {
				eprintf ("Cannot priorize any map for fd %d\n", (int)fd);
			}
			break;
		case 'b': // "ompb"
			id = (ut32)r_num_math (core->num, input + 4);
			if (!r_io_section_priorize_bin (core->io, id)) {
				eprintf ("Cannot priorize bin with binid %d\n", id);
			}
			break;
		case 's': // "omps"
			id = (ut32)r_num_math (core->num, input + 4);
			if (!r_io_section_priorize (core->io, id)) {
				eprintf ("Cannot priorize section with sectionid %d\n", id);
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
			int fd = 0, words = 0;
			ut64 size = 0, vaddr = 0, paddr = 0;
			const char *name = NULL;
			RIODesc *desc = NULL;
			words = r_str_word_set0 (s);
			switch (words) {
			case 5:
				name = r_str_word_get0 (s, 4);
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
				map = r_io_map_add (core->io, fd, desc->flags, paddr, vaddr, size, true);
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
	case 'n': //omn
		if (!(s = strdup (&input[2]))) {
			break;
		}
		p = s;
		while (*s == ' ') {
			s++;
		}
		if (*s == '\0') {
			R_FREE (p);
			break;
		}
		if (!(q = strchr (s, ' '))) {
			id = (ut32)r_num_math (core->num, s);
			map = r_io_map_get (core->io, id);
			r_io_map_del_name (map);
			R_FREE (p);
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
		R_FREE (p);
		break;
	case '-':
		r_io_map_del (core->io, r_num_math (core->num, input+2));
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
	RCoreFile *f;
	RListIter *iter;
	r_list_foreach (core->files, iter, f) {
		ut64 sz = r_io_fd_size (core->io, f->fd);
		ut8 *buf = calloc (sz, 1);
		if (!buf) {
			eprintf ("Cannot allocate %d\n", (int)sz);
			continue;
		}
		(void)r_io_pread_at (core->io, 0, buf, sz);
		char *url = r_str_newf ("malloc://%d", (int)sz);
		RIODesc *desc = r_io_open (core->io, url, R_IO_READ | R_IO_WRITE, 0);		//use r_io_desc_exchange pls
		if (desc) {
			r_io_fd_close (core->io, f->fd);
			f->fd = desc->fd;
			(void)r_io_write_at (core->io, 0, buf, sz);
		} else {
			eprintf ("Cannot open %s\n", url);
		}
		free (buf);
		free (url);
		break;
	}
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
	binpath = bf ? strdup (bf->file) : NULL;
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
	//r_core_file_reopen (core, newfile, 0, 2);
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
	ut64 baddr = r_config_get_i (core->config, "bin.baddr");
	int nowarn = r_config_get_i (core->config, "file.nowarn");
	RCoreFile *file;
	int isn = 0;
	char *ptr;

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
		r_io_plugin_list (core->io);
		break;
	case 'p': // "op"
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1]==' ') {
			if (r_lib_open (core->lib, input+2) == R_FAIL) {
				eprintf ("Oops\n");
			}
		} else {
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
	case '+': // "o+"
		perms = R_IO_READ | R_IO_WRITE;
		/* fall through */
	case 'f': // "of"
		/* open file with spaces or special chars */
		if (input[1] == ' ') {
			const char *fn = input + 2;
			file = r_core_file_open (core, fn, perms, 0);
			if (file) {
				r_core_bin_load (core, fn, UT64_MAX);
			} else {
				eprintf ("Cannot open (%s)\n", fn);
			}
		} else {
			eprintf ("Usage: of [path-to-file]\n");
		}
		break;
	case 'n': // "on"
		// like in r2 -n
		isn = 1;
		if (input[1] == '*') {
			r_core_file_list (core, 'n');
			break;
		}
		if (input[1] != ' ') {
			break;
		}
		/* fall through */
	case ' ': // "o "
		{
			ut64 ba = baddr;
			ut64 ma = 0L;
			char *fn = strdup (input + (isn? 2:1));
			if (!fn || !*fn) {
				if (isn) {
					eprintf ("Usage: on [file]\n");
				} else {
					eprintf ("Usage: o [file] addr\n");
				}
				free (fn);
				break;
			}
			ptr = strchr (fn, ' ');
			if (ptr) {
				*ptr++ = '\0';
				ma = r_num_math (core->num, ptr);
			}
			int num = atoi (input + 1);
			if (num <= 0) {
				if (fn && *fn) {
					file = r_core_file_open (core, fn, perms, ma);
					if (file) {
						r_cons_printf ("%d\n", (ut32)file->fd);
						// MUST CLEAN BEFORE LOADING
						if (isn) {
							RIODesc *d = r_io_desc_get (core->io, file->fd);
							if (d) {
								r_io_map_new (core->io, d->fd, d->flags, 0LL, ma, r_io_desc_size (d), true);
							}
						} else {
							r_core_bin_load (core, fn, ba);
						}
					} else if (!nowarn) {
						eprintf ("Cannot open file '%s'\n", fn);
					}
				} else {
					eprintf ("Usage: on [file] ([maddr]) ([baddr])\n");
				}
			} else {
				RListIter *iter = NULL;
				RCoreFile *f;
				core->switch_file_view = 0;
				r_list_foreach (core->files, iter, f) {
					if (f->fd == num) {
						r_io_use_fd (core->io, num);
						//core->switch_file_view = 1;
						// raise rbinobj too
						int binfile_num = find_binfile_id_by_fd (core->bin, num);
						r_core_bin_raise (core, binfile_num, -1);
						break;
					}
				}
			}
			r_core_block_read (core);
			free (fn);
		}
		break;
	case 'b': // "ob"
		cmd_open_bin (core, input);
		break;
	case '-': // "o-"
		switch (input[1]) {
		case '*': // "o-*"
			r_core_file_close_fd (core, -1);
			r_io_close_all (core->io);
			r_bin_file_delete_all (core->bin);
			r_list_purge(core->files);
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
			eprintf ("Usage: o-# or o-*, where # is the filedescriptor number\n");
		}
		// hackaround to fix invalid read
		//r_core_cmd0 (core, "oo");
		// uninit deref
		//r_core_block_read (core);
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
			if ('?' == input[2]) {
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

			perms = ('+' == input[2])? R_IO_READ|R_IO_WRITE: 0;
			r_core_file_reopen (core, input + 3, perms, 0);
			break;
		case '+': // "oo+"
			if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_oo_plus);
			} else if (core && core->io && core->io->desc) {
				int fd;
				if ((ptr = strrchr (input, ' ')) && ptr[1]) {
					fd = (int)r_num_math (core->num, ptr + 1);
				} else {
					fd = core->io->desc->fd;
				}
				if (r_io_reopen (core->io, fd, R_IO_READ | R_IO_WRITE, 644)) {
					SdbListIter *iter;
					RIOMap *map;
					ls_foreach_prev (core->io->maps, iter, map) {
						if (map->fd == fd) {
							map->flags |= R_IO_WRITE;
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
		{
			int fd, fdx;
			fd = fdx = -1;
			if ((ptr = strrchr (input, ' '))) {
				fdx = (int)r_num_math (core->num, ptr + 1);
				*ptr = '\0';
				if ((ptr = strchr (input, ' '))) {
					fd = r_num_math (core->num, ptr + 1);
				}
			}
			if ((fdx == -1) || (fd == -1) || (fdx == fd)) {
				break;
			}
			r_io_desc_exchange (core->io, fd, fdx);
			r_core_block_read (core);
		}
		break;
	case '?': // "o?"
	default:
		r_core_cmd_help (core, help_msg_o);
		break;
	}
	return 0;
}
