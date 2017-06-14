/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_list.h"
#include "r_config.h"
#include "r_core.h"
#include "r_print.h"
#include "r_bin.h"
#include "r_debug.h"


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

static void cmd_open_bin(RCore *core, const char *input) {
	const char* help_msg[] = {
		"Usage:", "ob", " # List open binary files backed by fd",
		"ob", "", "List opened binary files and objid",
		"ob", " [fd objid]", "Switch to open binary file by fd number and objid",
		"obb", " [fd]", "Switch to open binfile by fd number",
		"obr", " [baddr]", "Rebase current bin object",
		"ob-", " [fd]", "Delete binfile by fd",
		"obd", " [objid]", "Delete binary file by objid. Do nothing if only one loaded.",
		"obo", " [objid]", "Switch to open binary file by objid",
		NULL};
	const char *value = NULL;
	ut32 binfile_num = -1, binobj_num = -1;

	switch (input[1]) {
	case 0:
	case 'l':
	case 'j':
	case '*':
		r_core_bin_list (core, input[1]);
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
		break;
	}
	case ' ':
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
	case 'r':
		r_core_bin_rebase (core, r_num_math (core->num, input + 3));
		r_core_cmd0 (core, ".is*");
		break;
	case 'o':
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
	case 'd': // backward compat, must be deleted
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
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}
}

static void cmd_open_map (RCore *core, const char *input) {
	const char* help_msg[] = {
		"Usage:", "om[-] [arg]", " # map opened files",
		"om", "", "list all defined IO maps",
		"om", "-0x10000", "remove the map at given address",
		"om", " fd addr [size]", "create new io map",
		"omr", " fd|0xADDR ADDR", "relocate current map",
		"om*", "", "show r2 commands to restore mapaddr",
		NULL };
	ut64 fd = 0LL;
	ut64 addr = 0LL;
	ut64 size = 0LL;
	ut64 delta = 0LL;
	char *s, *p, *q;
	ut64 cur, new;
	RIOMap *map = NULL;
	const char *P;

	switch (input[1]) {
	case 'r':
		if (input[2] != ' ')
			break;
		P = strchr (input+3, ' ');
		if (P) {
			cur = r_num_math (core->num, input+3);
			new = r_num_math (core->num, P+1);
			map = atoi (input+3)>0?
				r_io_map_resolve (core->io, cur):
				r_io_map_get (core->io, cur);
			if (map) {
				ut64 diff = map->to - map->from;
				map->from = new;
				map->to = new+diff;
			} else eprintf ("Cannot find any map here\n");
		} else {
			cur = core->offset;
			new = r_num_math (core->num, input+3);
			map = r_io_map_resolve (core->io, core->file->desc->fd);
			if (map) {
				ut64 diff = map->to - map->from;
				map->from = new;
				map->to = new+diff;
			} else eprintf ("Cannot find any map here\n");
		}
		break;
	case ' ':
		// i need to parse delta, offset, size
		s = strdup (input+2);
		p = strchr (s, ' ');
		if (p) {
			q = strchr (p+1, ' ');
			*p = 0;
			fd = r_num_math (core->num, s);
			addr = r_num_math (core->num, p+1);
			if (q) {
				char *r = strchr (q+1, ' ');
				*q = 0;
				if (r) {
					*r = 0;
					size = r_num_math (core->num, q+1);
					delta = r_num_math (core->num, r+1);
				} else size = r_num_math (core->num, q+1);
			} else size = r_io_size (core->io);
			r_io_map_add (core->io, fd, 0, delta, addr, size);
		} else eprintf ("Invalid use of om . See om? for help.");
		free (s);
		break;
	case '-':
		if (atoi (input + 3)>0) {
			r_io_map_del (core->io,
					r_num_math (core->num, input+2));
		} else {
			r_io_map_del_at (core->io,
					r_num_math (core->num, input+2));
		}
		break;
	case '\0':
		r_io_map_list (core->io, 0);
		break;
	case '*':
		r_io_map_list (core->io, 'r');
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}
	r_core_block_read (core);
}

R_API void r_core_file_reopen_in_malloc (RCore *core) {
	RCoreFile *f;
	RListIter *iter;
	r_list_foreach (core->files, iter, f) {
		ut64 sz = r_io_desc_size (core->io, f->desc);
		ut8 *buf = calloc (sz, 1);
		if (!buf) {
			eprintf ("Cannot allocate %d\n", (int)sz);
			continue;
		}
		(void)r_io_pread (core->io, 0, buf, sz);
		char *url = r_str_newf ("malloc://%d", (int)sz);
		RIODesc *desc = r_io_open (core->io, url, R_IO_READ | R_IO_WRITE, 0);
		if (desc) {
			r_io_close (core->io, f->desc);
			f->desc = desc;
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
	char *binpath = NULL;
	if (!ofile || !ofile->desc || !ofile->desc->uri || !ofile->desc->fd) {
		eprintf ("No file open?\n");
		return;
	}
	bf = r_bin_file_find_by_fd (core->bin, ofile->desc->fd);
	binpath = bf ? strdup (bf->file) : NULL;
	if (!binpath) {
		if (r_file_exists (ofile->desc->name)) {
			binpath = strdup (ofile->desc->name);
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
	core->file->desc->uri = newfile;
	core->file->desc->referer = NULL;
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


static int cmd_open(void *data, const char *input) {
	const char *help_msg[] = {
		"Usage: o","[com- ] [file] ([offset])","",
		"o","","list opened files",
		"o=","","list opened files (ascii-art bars)",
		"o*","","list opened files in r2 commands",
		"oa","[?] [addr]","Open bin info from the given address",
		"ob","[?] [lbdos] [...]","list open binary files backed by fd",
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
		NULL
	};
	const char* help_msg_oo[] = {
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
		NULL};
	RCore *core = (RCore*)data;
	int perms = R_IO_READ;
	ut64 addr, baddr = r_config_get_i (core->config, "bin.baddr");
	int nowarn = r_config_get_i (core->config, "file.nowarn");
	RCoreFile *file;
	int num = -1;
	int isn = 0;
	char *ptr;
	RListIter *iter;

	switch (*input) {
	case '=':
		r_io_desc_list_visual (core->io, core->offset, core->blocksize,
			r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
		break;
	case '\0':
		r_core_file_list (core, (int)(*input));
		break;
	case '*':
		if ('?' == input[1]) {
			const char *help_msg[] = {
				"Usage:", "o* [> files.r2]", "",
				"o*", "", "list opened files in r2 commands", NULL
			};
			r_core_cmd_help (core, help_msg);
			break;
		}
	case 'j':
		if ('?' == input[1]) {
			const char *help_msg[] = {
				"Usage:", "oj [~{}]", " # Use ~{} to indent the JSON",
				"oj", "", "list opened files in JSON format", NULL
			};
			r_core_cmd_help (core, help_msg);
			break;
		}
		r_core_file_list (core, (int)(*input));
		break;
	case 'L':
		r_io_plugin_list (core->io);
		break;
	case 'a': // "oa"
		if ('?' == input[1]) {
			const char *help_msg[] = {
				"Usage:", "oa [addr] ([filename])", " # load bininfo and update flags",
				"oa", " [addr]", "Open bin info from the given address",
				"oa", " [addr] [filename]", "Open file and load bin info at given address",NULL
			};
			r_core_cmd_help (core, help_msg);
			break;
		}
		addr = core->offset;
		if (input[1]) {
			char *arg = strdup (input + 2);
			char *filename = strchr (arg, ' ');
			if (filename) {
				RIODesc *desc = r_io_open (core->io, filename + 1, R_IO_READ, 0);
				if (desc) {
					*filename = 0;
					addr = r_num_math (core->num, arg);
					r_bin_load_io (core->bin, desc, addr, 0, 0);
					r_io_close (core->io, desc);
					r_core_cmd0 (core, ".is*");
				} else {
					eprintf ("Cannot open %s\n", filename + 1);
				}
			} else {
				addr = r_num_math (core->num, input + 1);
				RCoreFile *cf = r_core_file_cur (core);
				if (cf && cf->desc) {
					r_bin_load_io (core->bin, cf->desc, addr, 0, 0);
					r_core_cmd0 (core, ".is*");
				} else {
					eprintf ("No file to load bin from?\n");
				}
			}
			free (arg);
		} else {
			/* reload all bininfo */
			r_list_foreach (core->files, iter, file) {
				r_bin_load_io (core->bin, file->desc, addr, 0, 0);
				r_core_cmd0 (core, ".is*");
				break;
			}
		}
		//r_bin_load_io_at_offset_as (core->bin, core->file->desc,
		break;
	case 'p':
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
						r_io_raise (core->io, num);
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
						r_core_file_close_fd (core, f->desc->fd);
						break;
					}
					count++;
				}
			}
			break;
		case 'j':
		case '*':
		case 0:
			r_core_file_list (core, input[1]);
			break;
		}
		break;
	case '+':
		perms = R_IO_READ|R_IO_WRITE;
		/* fall through */
	case 'f':
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

		/* fall through */
	case ' ':
		{
			ut64 ba = 0L;
			ut64 ma = 0L;
			char *fn = strdup (input + (isn? 2:1));
			if (!fn || !*fn) {
				eprintf ("Usage: on [file]\n");
				free (fn);
				break;
			}
			ptr = strchr (fn, ' ');
			if (ptr) {
				*ptr++ = '\0';
				char *ptr2 = strchr (ptr, ' ');
				if (ptr2) {
					*ptr2++ = 0;
					ba = r_num_math (core->num, ptr2);
				}
				ma = r_num_math (core->num, ptr);
			}
			int num = atoi (input + 1);
			if (num <= 0) {
				if (fn && *fn) {
					file = r_core_file_open (core, fn, perms, ma);
					if (file) {
						r_cons_printf ("%d\n", file->desc->fd);
						// MUST CLEAN BEFORE LOADING
						if (!isn) {
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
					if (f->desc->fd == num) {
						r_io_raise (core->io, num);
						core->switch_file_view = 1;
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
	case 'b':
		cmd_open_bin (core, input);
		break;
	case '-': // o-
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
			if (!r_core_file_close_fd (core, atoi (input + 1))) {
				eprintf ("Unable to find filedescriptor %d\n",
						atoi (input + 1));
			}
			break;
		case '?':
			eprintf ("Usage: o-# or o-*, where # is the filedescriptor number\n");
		}
		// hackaround to fix invalid read
		//r_core_cmd0 (core, "oo");
		// uninit deref
		//r_core_block_read (core);
		break;
	case 'm':
		cmd_open_map (core, input);
		break;
	case 'o':
		switch (input[1]) {
		case 'm': // "oom"
			r_core_file_reopen_in_malloc (core);
			break;
		case 'd': // "ood" : reopen in debugger
			if ('?' == input[2]) {
				const char *help_msg[] = {
					"ood"," [args]","reopen in debugger mode (with args)",NULL
				};
				r_core_cmd_help (core, help_msg);
			} else {
				r_core_file_reopen_debug (core, input + 2);
			}
			break;
		case 'b': // "oob" : reopen with bin info
			if ('?' == input[2]) {
				const char *help_msg[] = {
					"oob", "", "reopen loading rbin info",NULL
				};
				r_core_cmd_help (core, help_msg);
			} else {
				r_core_file_reopen (core, input + 2, 0, 2);
			}
			break;
		case 'n':
			if ('n' == input[2]) {
				if ('?' == input[3]) {
					const char *help_msg[] = {
						"oonn", "", "reopen without loading rbin info, but with header flags",NULL
					};
					r_core_cmd_help (core, help_msg);
					break;
				}
				perms = (input[3] == '+')? R_IO_READ|R_IO_WRITE: 0;
				r_core_file_reopen (core, input + 4, perms, 0);
				// TODO: Use API instead of !rabin2 -rk
				r_core_cmdf (core, ".!rabin2 -rk '' '%s'", core->file->desc->name);
			} else if ('?' == input[2]) {
				const char *help_msg[] = {
					"oon", "", "reopen without loading rbin info",NULL
				};
				r_core_cmd_help (core, help_msg);
				break;
			}

			perms = ('+' == input[2])? R_IO_READ|R_IO_WRITE: 0;
			r_core_file_reopen (core, input + 3, perms, 0);
			break;
		case '+':
			if ('?' == input[2]) {
				const char *help_msg[] = {
					"oo+", "", "reopen in read-write",NULL
				};
				r_core_cmd_help (core, help_msg);
			} else {
				r_core_file_reopen (core, input + 2, R_IO_READ | R_IO_WRITE, 1);
			}
			break;
		case 0: // "oo"
			r_core_file_reopen (core, input + 2, 0, 1);
			break;
		case '?':
		default:
			 r_core_cmd_help (core, help_msg_oo);
			 break;
		}
		break;
	case 'c':
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
			if (!r_core_bin_load (core, NULL, baddr)) {
				r_config_set_i (core->config, "io.va", false);
			}
		} else {
			eprintf ("Missing argument\n");
		}
		break;
	case '?':
	default:
		r_core_cmd_help (core, help_msg);
		break;
	}
	return 0;
}
