/* radare - LGPL - Copyright 2009-2014 - pancake */

static int cmd_open(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int perms = R_IO_READ;
	ut64 addr, baddr = r_config_get_i (core->config, "bin.baddr");
	int nowarn = r_config_get_i (core->config, "file.nowarn");
	RIOMap *map = NULL;
	RCoreFile *file;
	int num = -1;
	int isn = 0;
	char *ptr;

	switch (*input) {
	case '\0':
	case '*':
	case 'j':
		r_core_file_list (core, *input);
		break;
	case 'p':
		if (r_sandbox_enable (0)) {
			eprintf ("This command is disabled in sandbox mode\n");
			return 0;
		}
		if (input[1]==' ') {
			if (r_lib_open (core->lib, input+2) == R_FAIL)
				eprintf ("Oops\n");
		} else {
			eprintf ("Usage: op [r2plugin."R_LIB_EXT"]\n");
		}
		break;
	case '+':
		perms = R_IO_READ|R_IO_WRITE;
	case 'n':
		// like in r2 -n
		isn = 1;
	case ' ':
		ptr = strchr (input+(isn?2:1), ' ');
		if (ptr && ptr[1]=='0' && ptr[2]=='x') { // hack to fix opening files with space in path
			*ptr = '\0';
			addr = r_num_math (core->num, ptr+1);
		} else {
			num = atoi (ptr? ptr: input+1);
			addr = 0LL;
		}
		if (num<=0) {
			const char *fn = input+1; //(isn?2:1);
			if (fn && *fn) {
				if (isn) fn++;
				file = r_core_file_open (core, fn, perms, addr);
				if (file) {
					r_cons_printf ("%d\n", file->desc->fd);
					// MUST CLEAN BEFORE LOADING
					if (!isn)
						r_core_bin_load (core, fn, baddr);
				} else if (!nowarn) {
					eprintf ("Cannot open file '%s'\n", fn);
				}
			} else {
				eprintf ("Usage: on [file]\n");
			}
		} else {
			RListIter *iter = NULL;
			RCoreFile *f;
			core->switch_file_view = 0;
			r_list_foreach (core->files, iter, f) {
				if (f->desc->fd == num) {
					r_io_raise (core->io, num);
					core->switch_file_view = 1;
					break;
				}
			}
		}
		r_core_block_read (core, 0);
		break;
	case 'b':
		{
			const char *value = NULL;
			ut32 binfile_num = -1, binobj_num = -1;

			switch (input[1]) {
				case 0:
				case 'l':
				case 'j':
				case '*':
					r_core_bin_list (core, input[1]);
					break;
				case 's':
					value = *(input+2) ? input+3 : NULL;
					if (!value) {
						eprintf ("Invalid binfile number.");
						break;
					}
					binfile_num = *value && r_is_valid_input_num_value (core->num, value) ?
							r_get_input_num_value (core->num, value) : UT32_MAX;

					if (binfile_num == UT32_MAX) {
						eprintf ("Invalid binfile number.");
						break;
					}

					value = *(value+1) ? r_str_tok (value+1, ' ', -1) : NULL;
					value = value && *(value+1) ? value+1 : NULL;

					binobj_num = value && binfile_num != -1 && r_is_valid_input_num_value (core->num, value) ?
							r_get_input_num_value (core->num, value) : UT32_MAX;

					if (binobj_num == UT32_MAX) {
						eprintf ("Invalid bin object number.");
						break;
					}
					r_core_bin_raise (core, binfile_num, binobj_num);
					break;
				case 'b':
					value = *(input+2) ? input+3 : NULL;
					if (!value) {
						eprintf ("Invalid binfile number.");
						break;
					}
					binfile_num = *value && r_is_valid_input_num_value (core->num, value) ?
							r_get_input_num_value (core->num, value) : UT32_MAX;

					if (binfile_num == UT32_MAX) {
						eprintf ("Invalid binfile number.");
						break;
					}
					value = *(value+1) ? r_str_tok (value+1, ' ', -1) : NULL;
					value = value && *(value+1) ? value+1 : NULL;

					r_core_bin_raise (core, binfile_num, -1);
					break;
				case 'o':
					value = *(input+2) ? input+3 : NULL;
					if (!value) {
						eprintf ("Invalid binfile number.");
						break;
					}
					binobj_num = *value && r_is_valid_input_num_value (core->num, value) ?
							r_get_input_num_value (core->num, value) : UT32_MAX;

					if (binobj_num == UT32_MAX) {
						eprintf ("Invalid bin object number.");
						break;
					}
					r_core_bin_raise (core, -1, binobj_num);
					break;
				case '-':
					if (!r_bin_file_delete (core->bin, r_num_math (core->num, input+2))) {
						eprintf ("Cant find an RBinFile associated with that fd.\n");
					}
					break;
				case 'd': // backward compat, must be deleted
					value = *(input+2) ? input+2 : NULL;
					if (!value) {
						eprintf ("Invalid binfile number.");
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
				case '?':{
					const char* help_msg[] = {
						"Usage:", "ob", " # List open binary files backed by fd",
						"ob", "", "List opened binfiles and bin objects",
						"obb", " [binfile #]", "Prioritize by binfile number with current selected object",
						"ob-", " [binfile #]", "Delete binfile",
						"obd", " [binobject #]", "Delete binfile object numbers, if more than 1 object is loaded",
						"obo", " [binobject #]", "Prioritize by bin object number",
						"obs", " [bf #] [bobj #]", "Prioritize by binfile and object numbers",
						NULL};
						r_core_cmd_help (core, help_msg);
					}
			}
		}
		break;
	case '-':
		if (!r_core_file_close_fd (core, atoi (input+1)))
			eprintf ("Unable to find filedescriptor %d\n",
				atoi (input+1));
		// hackaround to fix invalid read
		//r_core_cmd0 (core, "oo");
		// uninit deref
		//r_core_block_read (core, 0);
		break;
	case 'm':
		switch (input[1]) {
		case 'r':
			{
			ut64 cur, new;
			const char *p;
			if (input[2] != ' ')
				break;
			p = strchr (input+3, ' ');
			if (p) {
				cur = r_num_math (core->num, input+3);
				new = r_num_math (core->num, p+1);
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
			}
			break;
		case ' ':
			// i need to parse delta, offset, size
			{
			ut64 fd = 0LL;
			ut64 addr = 0LL;
			ut64 size = 0LL;
			ut64 delta = 0LL;
			char *s = strdup (input+2);
			char *p = strchr (s, ' ');
			if (p) {
				char *q = strchr (p+1, ' ');
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
			}
			break;
		case '-':
			if (atoi (input+3)>0) {
				r_io_map_del(core->io,
					r_num_math (core->num, input+2));
			} else {
				r_io_map_del_at (core->io,
					r_num_math (core->num, input+2));
			}
			break;
		case '\0':
			r_io_map_list (core->io);
			break;
		default:
		case '?':{
			const char* help_msg[] = {
				"Usage:", "om[-] [arg]", " # map opened files",
				"om", "", "list all defined IO maps",
				"om", "-0x10000", "remove the map at given address",
				"om", " fd addr [size]", "create new io map",
				"omr", " fd|0xADDR ADDR", "relocate current map",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		}
		r_core_block_read (core, 0);
		break;
	case 'o':
		switch (input[1]) {
		case 'b': // "oob" : reopen with bin info
			r_core_file_reopen (core, input+2, 0, 2);
			break;
		case 'n':
			r_core_file_reopen (core, input+2, 0, 0);
			break;
		case '+':
			r_core_file_reopen (core, input+2, R_IO_READ | R_IO_WRITE, 1);
			break;
		case 0: // "oo"
			r_core_file_reopen (core, input+2, 0, 1);
			break;
		case '?':
		default:
			{
				 const char* help_msg[] = {
					 "Usage:", "oo[-] [arg]", " # map opened files",
					 "oo", "", "reopen current file",
					 "oob", "", "reopen loading rbin info",
					 "oon", "", "reopen without loading rbin info",
					 "oo+", "", "reopen in read-write",
					 NULL};
				 r_core_cmd_help (core, help_msg);
			 }
			 break;
		}
		break;
	case 'c':
		// memleak? lose all settings wtf
		// if load fails does not fallbacks to previous file
		r_core_fini (core);
		r_core_init (core);
		if (!r_core_file_open (core, input+2, R_IO_READ, 0))
			eprintf ("Cannot open file\n");
		if (!r_core_bin_load (core, NULL, baddr))
			r_config_set (core->config, "io.va", "false");
		break;
	case '?':
	default:
		{
		const char *help_msg[] = {
		"Usage: o","[com- ] [file] ([offset])","",
		"o","","list opened files",
		"o*","","list opened files in r2 commands",
		"oj","","list opened files in JSON format",
		"oc"," [file]","open core file, like relaunching r2",
		"op"," ["R_LIB_EXT"]","open r2 native plugin (asm, bin, core, ..)",
		"oo","","reopen current file (kill+fork in debugger)",
		"oo","+","reopen current file in read-write",
		"o"," 4","priorize io on fd 4 (bring to front)",
		"o","-1","close file descriptor 1",
		"o"," /bin/ls","open /bin/ls file in read-only",
		"o","+/bin/ls","open /bin/ls file in read-write mode",
		"o"," /bin/ls 0x4000","map file at 0x4000",
		"on"," /bin/ls 0x4000","map raw file at 0x4000 (no r_bin involved)",
		"ob","[lbdos] [...]","list open binary files backed by fd",
		"ob"," 4","priorize io and fd on 4 (bring to binfile to front)",
		"om","[?]","create, list, remove IO maps",
		NULL
		};
		r_core_cmd_help (core, help_msg);
		}
		break;
	}
	return 0;
}
