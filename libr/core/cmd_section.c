/* radare - LGPL - Copyright 2009-2012 - pancake<nopcode.org> */

static int cmd_section(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '?':
		r_cons_printf (
		" S                ; list sections\n"
		" S.               ; show current section name\n"
		" S?               ; show this help message\n"
		" S*               ; list sections (in radare commands)\n"
		" S=               ; list sections (in nice ascii-art bars)\n"
		" Sd [file]        ; dump current section to a file (see dmd)\n"
		" Sl [file]        ; load contents of file into current section (see dml)\n"
		" Sr [name]        ; rename section on current seek\n"
		" S [off] [vaddr] [sz] [vsz] [name] [rwx] ; add new section\n"
		" S-[id|0xoff|*]   ; remove this section definition\n");
		break;
	case 'r':
		if (input[1]==' ') {
			RIOSection *s;
			int len = 0;
			ut64 addr;
			char *p;

			p = strchr (input+2, ' ');
			if (p) {
				addr = r_num_math (core->num, p+1);
				len = (int)(size_t)(p-input+2);
			} else addr = core->offset;
			s = r_io_section_get (core->io, addr);
			if (s) {
				if (!len) len = sizeof (s->name);
				r_str_ncpy (s->name, input+2, len);
			} else eprintf ("No section found in 0x%08"PFMT64x"\n", core->offset);
		} else eprintf ("Usage: Sr [name] ([offset])\n");
		break;
	case 'd':
		{
		char file[128];
		ut64 o = core->offset;
		RListIter *iter;
		RIOSection *s;
		if (core->io->va || core->io->debug)
			o = r_io_section_vaddr_to_offset (core->io, o);
		r_list_foreach (core->io->sections, iter, s) {
			if (o>=s->offset && o<s->offset+s->size) {
				ut8 *buf = malloc (s->size);
				r_io_read_at (core->io, s->offset, buf, s->size);
				if (input[1]==' ' && input[2]) {
					strncpy (file, input+2, sizeof (file));
				} else snprintf (file, sizeof (file), "0x%08"PFMT64x"-0x%08"PFMT64x"-%s.dmp",
					s->vaddr, s->vaddr+s->size, r_str_rwx_i (s->rwx));
				if (!r_file_dump (file, buf, s->size)) {
					eprintf ("Cannot write '%s'\n", file);
					free (buf);
					return R_FALSE;
				}
				eprintf ("Dumped %d bytes into %s\n", (int)s->size, file);
				free (buf);
				return R_TRUE;
			}
		}
		}
		break;
	case 'l':
		{
		ut64 o = core->offset;
		RListIter *iter;
		RIOSection *s;
		if (input[1] != ' ') {
			eprintf ("Usage: Sl [file]\n");
			return R_FALSE;
		}
		if (core->io->va || core->io->debug)
			o = r_io_section_vaddr_to_offset (core->io, o);
		r_list_foreach (core->io->sections, iter, s) {
			if (o>=s->offset && o<s->offset+s->size) {
				int sz;
				char *buf = r_file_slurp (input+2, &sz);
#warning TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf ("Cannot allocate 0x%08"PFMT64x" bytes\n", s->size);
					return R_FALSE;
				}
				r_io_write_at (core->io, s->vaddr, (const ut8*)buf, sz);
				eprintf ("Loaded %d bytes into the map region at 0x%08"PFMT64x"\n", sz, s->vaddr);
				free (buf);
				return R_TRUE;
			}
		}
		eprintf ("No debug region found here\n");
		return R_FALSE;
		}
		break;
	case '-':
		if (input[1] == '*') {
			// remove all sections
			r_io_section_init (core->io);
		} else
		if (input[1] == '0' && input[2]=='x') {
			RIOSection *s = r_io_section_get (core->io, r_num_get (NULL, input+1));
			// use offset
			r_io_section_rm (core->io, s->id);
		} else {
			r_io_section_rm (core->io, atoi (input+1));
		}
		break;
	case ' ':
		switch (input[1]) {
		case '-': // remove
			if (input[2]=='?' || input[2]=='\0')
				eprintf ("Usage: S -N   # where N is the section index\n");
			else r_io_section_rm (core->io, atoi (input+1));
			break;
		default:
			{
			int i, rwx = 7;
			char *ptr = strdup(input+1);
			const char *name = NULL;
			ut64 vaddr = 0LL;
			ut64 offset = 0LL;
			ut64 size = 0LL;
			ut64 vsize = 0LL;

			i = r_str_word_set0 (ptr);
			switch (i) {
			case 6: // get rwx
				rwx = r_str_rwx (r_str_word_get0 (ptr, 5));
			case 5: // get name
				name = r_str_word_get0 (ptr, 4);
			case 4: // get vsize
				vsize = r_num_math (core->num, r_str_word_get0 (ptr, 3));
			case 3: // get size
				size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
			case 2: // get vaddr
				vaddr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get offset
				offset = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			r_io_section_add (core->io, offset, vaddr, size, vsize, rwx, name);
			free (ptr);
			}
			break;
		}
		break;
	case '=':
		r_io_section_list_visual (core->io, core->offset, core->blocksize);
		break;
	case '.':
		{
		ut64 o = core->offset;
		RListIter *iter;
		RIOSection *s;
		if (core->io->va || core->io->debug)
			o = r_io_section_vaddr_to_offset (core->io, o);
		r_list_foreach (core->io->sections, iter, s) {
			if (o>=s->offset && o<s->offset+s->size) {
				r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %s\n",
					s->offset + s->vaddr,
					s->offset + s->vaddr + s->size,
					s->name);
				break;
			}
		}
		}
		break;
	case '\0':
		r_io_section_list (core->io, core->offset, 0);
		break;
	case '*':
		r_io_section_list (core->io, core->offset, 1);
		break;
	}
	return 0;
}

