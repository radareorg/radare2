/* radare - LGPL - Copyright 2009-2014 - pancake */

static int cmd_open(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int perms = R_IO_READ;
	ut64 addr, baddr = r_config_get_i (core->config, "bin.baddr");
	int nowarn = r_config_get_i (core->config, "file.nowarn");
	RIOMap *map = NULL;
	RCoreFile *file;
	RListIter *iter;
	int num = -1;
	int isn = 0;
	char *ptr;

	switch (*input) {
	case '\0':
		r_core_file_list (core);
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
			const char *fn = input+(isn?2:1);
			file = r_core_file_open (core, fn, perms, addr);
			if (file) {
				// MUST CLEAN BEFORE LOADING
				if (!isn)
					r_core_bin_load (core, fn, baddr);
			} else if (!nowarn) {
				eprintf ("Cannot open file '%s'\n", fn);
			}
		} else {
			RListIter *iter = NULL;
			RCoreFile *f;
			core->switch_file_view = 0;
			r_list_foreach (core->files, iter, f) {
				if (f->fd->fd == num) {
					r_io_raise (core->io, num);
					core->switch_file_view = 1;
					break;
				}
			}
		}
		r_core_block_read (core, 0);
		break;
	case '-':
		if (!r_core_file_close_fd (core, atoi (input+1)))
			eprintf ("Unable to find filedescriptor %d\n", atoi (input+1));
		r_core_block_read (core, 0);
		break;
	case 'm':
		switch (input[1]) {
		case 'r':
			{
			ut64 cur, new;
			const char *p = strchr (input+3, ' ');
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
				map = r_io_map_resolve (core->io, core->file->fd->fd);
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
			} else eprintf ("Usage: om fd addr [size] [delta]\n");
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
			r_list_foreach (core->io->maps, iter, map) { // _prev?
				r_cons_printf (
					"%d +0x%"PFMT64x" 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", 
					(int)map->fd, (ut64)map->delta, (ut64)map->from, (ut64)map->to);
			}
			break;
		default:
		case '?':
			r_cons_printf ("|Usage: om[-] [arg]  # map opened files\n"
				"| om                  list all defined IO maps\n"
				"| om-0x10000          remove the map at given address\n"
				"| om fd addr [size]   create new io map\n"
				"| omr fd|0xADDR ADDR  relocate current map\n");
			break;
		}
		r_core_block_read (core, 0);
		break;
	case 'o':
		r_core_file_reopen (core, input+2, (input[1]=='+')?R_IO_READ|R_IO_WRITE:0);
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
		r_cons_printf ("|Usage: o[com- ] [file] ([offset])\n"
		"| o                  list opened files\n"
		"| oc [file]          open core file, like relaunching r2\n"
		"| oo                 reopen current file (kill+fork in debugger)\n"
		"| oo+                reopen current file in read-write\n"
		"| o 4                priorize io on fd 4 (bring to front)\n"
		"| o-1                close file index 1\n"
		"| o /bin/ls          open /bin/ls file in read-only\n"
		"| o+/bin/ls          open /bin/ls file in read-write mode\n"
		"| o /bin/ls 0x4000   map file at 0x4000\n"
		"| on /bin/ls 0x4000  map raw file at 0x4000 (no r_bin involved)\n"
		"| om[?]              create, list, remove IO maps\n");
		break;
	}
	return 0;
}
