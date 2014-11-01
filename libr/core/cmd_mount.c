/* radare - LGPL - Copyright 2009-2014 // pancake */

static int cmd_mount(void *data, const char *_input) {
	ut64 off = 0;
	char *input, *oinput, *ptr, *ptr2;
	RList *list;
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	RFSPlugin *plug;
	RFSPartition *part;
	RCore *core = (RCore *)data;
	input = oinput = strdup (_input);

	switch (*input) {
	case ' ':
		input++;
		if (input[0]==' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			ptr++;
			ptr2 = strchr (ptr, ' ');
			if (ptr2) {
				*ptr2 = 0;
				off = r_num_math (core->num, ptr2+1);
			}
			if (!r_fs_mount (core->fs, ptr, input, off))
				eprintf ("Cannot mount %s\n", input);
		} else {
			if (!(ptr = r_fs_name (core->fs, core->offset)))
				eprintf ("Unknown filesystem type\n");
			else if (!r_fs_mount (core->fs, ptr, input, core->offset))
				eprintf ("Cannot mount %s\n", input);
			free (ptr);
		}
		break;
	case '-':
		r_fs_umount (core->fs, input+1);
		break;
	case '*':
		eprintf ("List commands in radare format\n");
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("m %s %s 0x%"PFMT64x"\n",
				root-> path, root->p->name, root->delta);
		}
		break;
	case '\0':
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("%s\t0x%"PFMT64x"\t%s\n",
				root->p->name, root->delta, root->path);
		}
		break;
	case 'l': // list of plugins
		r_list_foreach (core->fs->plugins, iter, plug) {
			r_cons_printf ("%10s  %s\n", plug->name, plug->desc);
		}
		break;
	case 'd':
		input++;
		if (input[0]==' ')
			input++;
		list = r_fs_dir (core->fs, input);
		if (list) {
			r_list_foreach (list, iter, file) {
				r_cons_printf ("%c %s\n", file->type, file->name);
			}
			r_list_free (list);
		} else eprintf ("Cannot open '%s' directory\n", input);
		break;
	case 'p':
		input++;
		if (*input == ' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			off = r_num_math (core->num, ptr+1);
		}
		list = r_fs_partitions (core->fs, input, off);
		if (list) {
			r_list_foreach (list, iter, part) {
				r_cons_printf ("%d %02x 0x%010"PFMT64x" 0x%010"PFMT64x"\n",
					part->number, part->type,
					part->start, part->start+part->length);
			}
			r_list_free (list);
		} else eprintf ("Cannot read partition\n");
		break;
	case 'o':
		input++;
		if (input[0]==' ')
			input++;
		file = r_fs_open (core->fs, input);
		if (file) {
			// XXX: dump to file or just pipe?
			r_fs_read (core->fs, file, 0, file->size);
			r_cons_printf ("f file %d 0x%08"PFMT64x"\n", file->size, file->off);
			r_fs_close (core->fs, file);
		} else eprintf ("Cannot open file\n");
		break;
	case 'g':
		input++;
		if (*input == ' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr)
			*ptr++ = 0;
		else
			ptr = "./";
		file = r_fs_open (core->fs, input);
		if (file) {
			r_fs_read (core->fs, file, 0, file->size);
			write (1, file->data, file->size);
			r_fs_close (core->fs, file);
			write (1, "\n", 1);
		} else if (!r_fs_dir_dump (core->fs, input, ptr))
			eprintf ("Cannot open file\n");
		break;
	case 'f':
		input++;
		switch (*input) {
		case '?':
			r_cons_printf (
			"Usage: mf[no] [...]\n"
			" mfn /foo *.c       ; search files by name in /foo path\n"
			" mfo /foo 0x5e91    ; search files by offset in /foo path\n"
			);
			break;
		case 'n':
			input++;
			if (*input == ' ')
				input++;
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				list = r_fs_find_name (core->fs, input, ptr);
				r_list_foreach (list, iter, ptr) {
					r_str_chop_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: r_list_purge (list);
			} else eprintf ("Unknown store path\n");
			break;
		case 'o':
			input++;
			if (*input == ' ')
				input++;
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				ut64 off = r_num_math (core->num, ptr);
				list = r_fs_find_off (core->fs, input, off);
				r_list_foreach (list, iter, ptr) {
					r_str_chop_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: r_list_purge (list);
			} else eprintf ("Unknown store path\n");
			break;
		}
		break;
	case 's':
		if (core->http_up) {
			free (oinput);
			return R_FALSE;
		}
		input++;
		if (input[0]==' ')
			input++;
		r_fs_prompt (core->fs, input);
		break;
	case 'y':
		eprintf ("TODO\n");
		break;
	case '?': {
		const char* help_msg[] = {
			"Usage:", "m[-?*dgy] [...] ", "Mountpoints management",
			"m", "", "List all mountpoints in human readable format",
			"m*", "", "Same as above, but in r2 commands",
			"ml", "", "List filesystem plugins",
			"m", " /mnt", "Mount fs at /mnt with autodetect fs and current offset",
			"m", " /mnt ext2 0", "Mount ext2 fs at /mnt with delta 0 on IO",
			"m-/", "", "Umount given path (/)",
			"my", "", "Yank contents of file into clipboard",
			"mo", " /foo", "Get offset and size of given file",
			"mg", " /foo", "Get contents of file/dir dumped to disk (XXX?)",
			"mf", "[o|n]", "Search files for given filename or for offset",
			"md", " /", "List directory contents for path",
			"mp", "", "List all supported partition types",
			"mp", " msdos 0", "Show partitions in msdos format at offset 0",
			"ms", " /mnt", "Open filesystem prompt at /mnt",
			//"TODO: support multiple mountpoints and RFile IO's (need io+core refactorn",
			NULL};
		r_core_cmd_help (core, help_msg);
		}
		break;
	}
	free (oinput);
	return 0;
}


