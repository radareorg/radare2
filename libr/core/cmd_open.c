/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */

static int cmd_open(void *data, const char *input) {
	ut64 addr;
	int num = -1;
	RCore *core = (RCore*)data;
	RCoreFile *file;
	char *ptr;

	switch (*input) {
	case '\0':
		r_core_file_list (core);
		break;
	case ' ':
		ptr = strchr (input+1, ' ');
		if (ptr && ptr[1]=='0' && ptr[2]=='x') { // hack to fix opening files with space in path
			*ptr = '\0';
			addr = r_num_math (core->num, ptr+1);
		} else {
			num = atoi (input+1);
			addr = 0LL;
		}
		if (num<=0) {
			file = r_core_file_open (core, input+1, R_IO_READ, addr);
			if (file) {
				//eprintf ("Map '%s' in 0x%08"PFMT64x" with size 0x%"PFMT64x"\n",
				//	input+1, addr, file->size);
			} else eprintf ("Cannot open file '%s'\n", input+1);
		} else r_io_raise (core->io, num);
		r_core_block_read (core, 0);
		break;
	case '-':
		if (!r_core_file_close_fd (core, atoi (input+1)))
			eprintf ("Unable to find filedescriptor %d\n", atoi (input+1));
		r_core_block_read (core, 0);
		break;
	case 'm':
		switch (input[1]) {
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
			r_io_map_del_at (core->io, r_num_math (core->num, input+2));
			break;
		case '\0':
			{
			RIOMap *im = NULL;
			RListIter *iter;
			r_list_foreach (core->io->maps, iter, im) { // _prev?
				r_cons_printf (
					"%d 0x%08"PFMT64x" 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", 
					im->fd, im->delta, im->from, im->to);
			}
			}
			break;
		default:
		case '?':
			r_cons_printf ("Usage: om[-] [arg]       file maps\n");
			r_cons_printf ("om                  list all defined IO maps\n");
			r_cons_printf ("om-0x10000          remove the map at given address\n");
			r_cons_printf ("om fd addr [size]   create new io map\n");
			break;
		}
		break;
	case 'o':
		r_core_file_reopen (core, input+2);
		break;
	case '?':
	default:
		eprintf ("Usage: o[o-] [file] ([offset])\n"
		" o                  list opened files\n"
		" oo                 reopen current file (kill+fork in debugger)\n"
		" o 4                priorize io on fd 4 (bring to front)\n"
		" o-1                close file index 1\n"
		" o /bin/ls          open /bin/ls file\n"
		" o /bin/ls 0x4000   map file at 0x4000\n"
		" om[?]              create, list, remove IO maps\n");
		break;
	}
	return 0;
}


