/* radare - LGPL - Copyright 2009-2023 // pancake */

static RCoreHelpMessage help_msg_m = {
	"Usage:", "m[-?*dgy] [...] ", "Mountpoints management",
	"m", " /mnt ext2 0", "mount ext2 fs at /mnt with delta 0 on IO",
	"m", " /mnt", "mount fs at /mnt with autodetect fs and current offset",
	"m", "", "list all mountpoints in human readable format",
	"m*", "", "same as above, but in r2 commands",
	"m-/", "", "umount given path (/)",
	"mL", "[Lj]", "list filesystem plugins (Same as Lm), mLL shows only fs plugin names",
	"mc", " [file]", "cat: Show the contents of the given file",
	"md", " /", "list files and directory on the virtual r2's fs",
	"mdd", " /", "show file size like `ls -l` in ms",
	"mdq", " /", "show just the file name (quiet)",
	"mf", "[?] [o|n]", "search files for given filename or for offset",
	"mg", " /foo [offset size]", "get fs file/dir and dump to disk (support base64:)",
	"mi", " /foo/bar", "get offset and size of given file",
	"mj", "", "list mounted filesystems in JSON",
	"mo", " /foo/bar", "open given file into a malloc://",
	"mp", " msdos 0", "show partitions in msdos format at offset 0",
	"mp", "", "list all supported partition types",
	"ms", " /mnt", "open filesystem shell at /mnt (or fs.cwd if not defined)",
	"mw", " [file] [data]", "write data into file",
	"mwf", " [diskfile] [r2filepath]", "write contents of local diskfile into r2fs mounted path",
	"my", "", "yank contents of file into clipboard",
	"ma", "[n] [page]", "manpage reading",
	//"TODO: support multiple mountpoints and RFile IO's (need io+core refactorn",
	NULL
};

static RCoreHelpMessage help_msg_mf = {
	"Usage:", "mf[no] [...]", "search files matching name or offset",
	"mfn", " /foo *.c","search files by name in /foo path",
	"mfo", " /foo 0x5e91","search files by offset in /foo path",
	NULL
};

static char *readman(const char *page) {
	int cat = 1;
	char *p = r_str_newf ("%s/man/man%d/%s.%d",R2_DATDIR, cat, page, cat);
	char *res = r_file_slurp (p, NULL);
	if (!res) {
		free (p);
		p = r_str_newf ("%s/man/man%d/%s.%d", "/usr/share", cat, page, cat);
		res = r_file_slurp (p, NULL);
	}
	if (res) {
		char *p = strstr (res, "\n.");
		while (p) {
			if (p[1] == '\\' || p != res) {
				p++;
			}
			switch (p[1]) {
			case '\\': // ".\""
				p--; *p = ' ';
				while (*p && *p != '\n') {
					*p = ' ';
					p++;
				}
				break;
			case 'F': // ".Fl"
			case 'T': // ".Tn"
			case 'B': // ".Bl"
				while (*p && *p != '\n') {
					*p = ' ';
					p++;
				}
				break;
			case 'E': // ".El"
			case 'N': // ".Nm"
			case 'X': // ".Xr"
			case 'D': // ".Dt"
			case 'P': // ".Dt"
			case 'A': // ".Ar"
				memset (p, ' ', 3);
				break;
			case 'O': // ".Op Fl"
				memset (p, ' ', 6);
				p[6] = '-';
				break;
			case 'S': //  .Sh section header
				memcpy (p, "\n##", 3);
				break;
			case 'I': // ".It"
				memcpy (p, "\n   * ", 6);
				break;
			}
			p = strstr (p, "\n.");
		}
		// replace \n.XX with stuff
		res = r_str_replace_all (res, " Ar ", " ");
	}
	free (p);
	return res;
}

static int cmd_man(RCore *core, const char *input) {
	const char *arg = strchr (input, ' ');
	// TODO: implement our own man page reader for non-unix platforms
	if (R_STR_ISNOTEMPTY (arg)) {
		// use our internal reader (
#if 0 && R2__UNIX__
		r_sys_cmdf ("man %s", page);
#else
		char *text = readman (r_str_trim_head_ro (arg));
		if (text) {
			r_cons_less_str (text, NULL);
			free (text);
		} else {
			R_LOG_ERROR ("Cannot find manpage");
		}
#endif
	} else {
		R_LOG_ERROR ("Usage: man [page]");
	}
	return 0;
}

static int cmd_mktemp(RCore *core, const char *input) {
	char *res = r_syscmd_mktemp (input);
	if (res) {
		r_core_return_value (core, 1);
		r_cons_printf ("%s", res);
		free (res);
	} else {
		r_core_return_value (core, 0);
	}
	return 0;
}

static int cmd_mkdir(RCore *core, const char *input) {
	int rc = r_syscmd_mkdir (input)? 0: 1;
	r_core_return_value (core, rc);
	return 0;
}

static int cmd_mv(void *data, const char *input) {
	return r_syscmd_mv (input)? 1: 0;
}

#define av_max 1024

static const char *t2s(const char ch) {
	switch (ch) {
	case 'f': return "file";
	case 'd': return "directory";
	case 'm': return "mountpoint";
	}
	return "unknown";
}

static void cmd_mount_ls(RCore *core, const char *input) {
	bool isJSON = *input == 'j';
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	bool minus_ele = *input == 'd'; // "mdd"
	if (minus_ele) {
		input++;
	}
	bool minus_quiet = *input == 'q'; // "mdq"
	if (minus_quiet) {
		input++;
	}
	input = r_str_trim_head_ro (input + isJSON);
	if (r_str_startswith (input, "base64:")) {
		const char *encoded = input + 7;
		char *decoded = (char *)sdb_decode (encoded, NULL);
		if (decoded) {
			input = decoded;
		}
	}
	RList *list = r_fs_dir (core->fs, input);
	PJ *pj = NULL;
	if (isJSON) {
		pj = pj_new ();
		pj_a (pj);
	}
	if (list) {
		r_list_foreach (list, iter, file) {
			if (isJSON) {
				pj_o (pj);
				pj_ks (pj, "type", t2s (file->type));
				pj_kn (pj, "size", file->size);
				pj_ks (pj, "name", file->name);
				pj_end (pj);
			} else {
				if (minus_quiet) {
					if (file->type == 'd') {
						r_cons_printf ("%s/\n", file->name);
					} else {
						r_cons_printf ("%s\n", file->name);
					}
				} else if (minus_ele) {
					r_cons_printf ("%c %10d %s\n", file->type, file->size, file->name);
				} else {
					r_cons_printf ("%c %s\n", file->type, file->name);
				}
			}
		}
		r_list_free (list);
	} else {
		if (strlen (input) > 1) {
			R_LOG_ERROR ("Invalid path");
		}
	}
	const char *path = *input ? input : "/";
	r_list_foreach (core->fs->roots, iter, root) {
		// TODO: adjust contents between //
		if (!strncmp (path, root->path, strlen (path))) {
			char *base = strdup (root->path);
			char *ls = (char *)r_str_lchr (base, '/');
			if (ls) {
				ls++;
				*ls = 0;
			}
			// TODO: adjust contents between //
			if (!strcmp (path, base)) {
				if (isJSON) {
					pj_o (pj);
					pj_ks (pj, "path", root->path);
					pj_kn (pj, "delta", root->delta);
					pj_ks (pj, "type", root->p->name);
					pj_end (pj);
				} else {
					r_cons_printf ("m %s\n", root->path); //  (root->path && root->path[0]) ? root->path + 1: "");
				}
			}
			free (base);
		}
	}
	if (isJSON) {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

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

	if (r_str_startswith (_input, "an")) {
		return cmd_man (data, _input);
	}
	if (r_str_startswith (_input, "ktemp")) {
		return cmd_mktemp (data, _input);
	}
	if (r_str_startswith (_input, "kdir")) {
		return cmd_mkdir (data, _input);
	}
	if (r_str_startswith (_input, "v")) {
		return cmd_mv (data, _input);
	}
	input = oinput = strdup (_input);

	switch (*input) {
	case ' ': // "m "
		input = (char *)r_str_trim_head_ro (input + 1);
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			ptr = (char *)r_str_trim_head_ro (ptr + 1);
			ptr2 = strchr (ptr, ' ');
			if (ptr2) {
				*ptr2 = 0;
				off = r_num_math (core->num, ptr2+1);
			}
			input = (char *)r_str_trim_head_ro (input);
			ptr = (char*)r_str_trim_head_ro (ptr);

			const char *mountp = input;
			const char *fstype = ptr;
			if (*mountp != '/') {
				if (*fstype != '/') {
					R_LOG_ERROR ("Invalid mountpoint");
					return 0;
				}
				mountp = ptr;
				fstype = input;
			}
			if (fstype && !r_fs_mount (core->fs, fstype, mountp, off)) {
				R_LOG_ERROR ("Cannot mount %s", input);
			}
		} else {
			if (!(ptr = r_fs_name (core->fs, core->offset))) {
				R_LOG_ERROR ("Unknown filesystem type");
			}
			if (ptr && !r_fs_mount (core->fs, ptr, input, core->offset)) {
				R_LOG_ERROR ("Cannot mount %s", input);
			}
			free (ptr);
		}
		break;
	case '-':
		if (input[1] == '?') { // "m-?"
			r_core_cmd_help_match (core, help_msg_m, "m-", true);
		} else {
			r_fs_umount (core->fs, input + 1);
		}
		break;
	case 'j':
		if (input[1] == '?') { // "mj?"
			r_core_cmd_help_match (core, help_msg_m, "mj", true);
		} else {
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			pj_k (pj, "mountpoints");
			pj_a (pj);
			r_list_foreach (core->fs->roots, iter, root) {
				pj_o (pj);
				pj_ks (pj, "path", root->path);
				pj_ks (pj, "plugin", root->p->name);
				pj_kn (pj, "offset", root->delta);
				pj_end (pj);
			}
			pj_end (pj);
			pj_k (pj, "plugins");
			pj_a (pj);
			r_list_foreach (core->fs->plugins, iter, plug) {
				pj_o (pj);
				pj_ks (pj, "name", plug->name);
				pj_ks (pj, "description", plug->desc);
				pj_end (pj);
			}

			pj_end (pj);
			pj_end (pj);
			r_cons_printf ("%s\n", pj_string (pj));
			pj_free (pj);
		}
		break;
	case '*': // "m*"
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("m %s %s 0x%"PFMT64x"\n",
				root->path, root->p->name, root->delta);
		}
		break;
	case '\0': // "m"
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("%s\t0x%"PFMT64x"\t%s\n",
				root->p->name, root->delta, root->path);
		}
		break;
	case 'L': // "mL" list of plugins
		if (input[1] == '?') { // "mL?"
			r_core_cmd_help_match (core, help_msg_m, "mL", true);
		} else if (input[1] == 'L') {
			r_list_foreach (core->fs->plugins, iter, plug) {
				r_cons_printf ("%s\n", plug->name);
			}
		} else if (input[1] == 'j') {
			PJ *pj = r_core_pj_new (core);
			pj_a (pj);
			r_list_foreach (core->fs->plugins, iter, plug) {
				pj_o (pj);
				pj_ks (pj, "name", plug->name);
				pj_ks (pj, "description", plug->desc);
				pj_end (pj);
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_printf ("%s\n", s);
			free (s);
		} else {
			r_list_foreach (core->fs->plugins, iter, plug) {
				r_cons_printf ("%10s  %s\n", plug->name, plug->desc);
			}
		}
		break;
	case 'd': // "md"
		if (input[1] == '?') { // "md?"
			r_core_cmd_help_match (core, help_msg_m, "md", true);
		} else {
			cmd_mount_ls (core, input + 1);
		}
		break;
	case 'p': // "mp"
		input = (char *)r_str_trim_head_ro (input + 1);
		if (input[0] == '?') { // "mp?"
			r_core_cmd_help_match (core, help_msg_m, "mp", true);
			break;
		}
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
		} else {
			R_LOG_ERROR ("Cannot read partition");
		}
		break;
	case 'o': // "mo"
		input = (char *)r_str_trim_head_ro (input + 1);
		if (*input == '?') { // "mo?"
			r_core_cmd_help_match (core, help_msg_m, "mo", true);
		} else {
			file = r_fs_open (core->fs, input, false);
			if (file) {
				r_fs_read (core->fs, file, 0, file->size);
				char *uri = r_str_newf ("malloc://%d", file->size);
				RIODesc *fd = r_io_open (core->io, uri, R_PERM_RW, 0);
				if (fd) {
					r_io_desc_write (fd, file->data, file->size);
				}
			} else {
				R_LOG_ERROR ("Cannot open file");
			}
		}
		break;
	case 'i':
		if (input[1] == '?') { // "mi?"
			r_core_cmd_help_match (core, help_msg_m, "mi", true);
		} else {
			input = (char *)r_str_trim_head_ro (input + 1);
			file = r_fs_open (core->fs, input, false);
			if (file) {
				// XXX: dump to file or just pipe?
				r_fs_read (core->fs, file, 0, file->size);
				r_cons_printf ("f file %d 0x%08"PFMT64x"\n", file->size, file->off);
				r_fs_close (core->fs, file);
			} else {
				R_LOG_ERROR ("Cannot open file");
			}
		}
		break;
	case 'c': // "mc"
		if (input[1] == '?') { // "mc?"
			r_core_cmd_help_match (core, help_msg_m, "mc", true);
		} else {
			input = (char *)r_str_trim_head_ro (input + 1);
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
			} else {
				ptr = "./";
			}
			file = r_fs_open (core->fs, input, false);
			if (file) {
				r_fs_read (core->fs, file, 0, file->size);
				r_cons_write ((const char *)file->data, file->size);
				r_fs_close (core->fs, file);
				r_cons_write ("\n", 1);
			} else if (!r_fs_dir_dump (core->fs, input, ptr)) {
				eprintf ("Cannot open file\n");
			}
		}
		break;
	case 'g': // "mg"
		if (input[1] == '?') { // "mg?"
			r_core_cmd_help_match (core, help_msg_m, "mg", true);
			break;
		}
		input = (char *)r_str_trim_head_ro (input + 1);
		int offset = 0;
		int size = 0;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr++ = 0;
			char *input2 = strdup (ptr++);
			const char *args = r_str_trim_head_ro (input2);
			if (args) {
				ptr = strchr (args, ' ');
				if (ptr) {
					*ptr++ = 0;
					size = r_num_math (core->num, ptr);
				}
				offset = r_num_math (core->num, args);
			}
		} else {
			ptr = "./";
		}
		char *hfilename = NULL;
		const char *filename = r_str_trim_head_ro (input);
		if (R_STR_ISEMPTY (filename)) {
			R_LOG_WARN ("No filename given");
			break;
		}
		if (r_str_startswith (filename, "base64:")) {
			const char *encoded = filename + 7;
			char *decoded = (char *)sdb_decode (encoded, NULL);
			if (decoded) {
				filename = decoded;
				hfilename = decoded;
			}
		}
		file = r_fs_open (core->fs, filename, false);
		if (file) {
			char *localFile = strdup (filename);
			char *slash = (char *)r_str_rchr (localFile, NULL, '/');
			if (slash) {
				memmove (localFile, slash + 1, strlen (slash));
			}
			size_t ptr = offset;
			int total_bytes_read = 0;
			int blocksize = file->size < core->blocksize ? file->size : core->blocksize;
			size = size > 0 ? size : file->size;
			if (r_file_exists (localFile) && !r_sys_truncate (localFile, 0)) {
				R_LOG_ERROR ("Cannot create file %s", localFile);
				break;
			}
			while (total_bytes_read < size && ptr < file->size) {
				int left = (size - total_bytes_read < blocksize)? size - total_bytes_read: blocksize;
				int bytes_read = r_fs_read (core->fs, file, ptr, left);
				if (bytes_read > 0) {
					r_file_dump (localFile, file->data, bytes_read, true);
				}
				ptr += bytes_read;
				total_bytes_read += bytes_read;
			}
			r_fs_close (core->fs, file);
			eprintf ("File '%s' created. ", localFile);
			if (offset) {
				eprintf ("(offset: 0x%"PFMT64x" size: %d bytes)\n", (ut64) offset, size);
			} else {
				eprintf ("(size: %d bytes)\n", size);
			}
			free (localFile);
		} else if (!r_fs_dir_dump (core->fs, filename, ptr)) {
			R_LOG_ERROR ("Cannot open file (%s) (%s)", filename, ptr);
		}
		free (hfilename);
		break;
	case 'f':
		input++;
		switch (*input) {
		case '?': // "mf?"
			r_core_cmd_help (core, help_msg_mf);
			break;
		case 'n':
			input = (char *)r_str_trim_head_ro (input + 1);
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				list = r_fs_find_name (core->fs, input, ptr);
				r_list_foreach (list, iter, ptr) {
					r_str_trim_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: r_list_purge (list);
			} else {
				R_LOG_ERROR ("Unknown store path");
			}
			break;
		case 'o':
			input = (char *)r_str_trim_head_ro (input + 1);
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				ut64 off = r_num_math (core->num, ptr);
				list = r_fs_find_off (core->fs, input, off);
				r_list_foreach (list, iter, ptr) {
					r_str_trim_path (ptr);
					r_cons_println (ptr);
				}
				//XXX: r_list_purge (list);
			} else {
				R_LOG_ERROR ("Unknown store path");
			}
			break;
		}
		break;
	case 's': // "ms"
		if (input[1] == '?') { // "ms?"
			r_core_cmd_help_match (core, help_msg_m, "ms", true);
			break;
		};
		if (!r_config_get_b (core->config, "scr.interactive")) {
			R_LOG_ERROR ("mount shell requires scr.interactive");
			break;
		}
		if (core->http_up) {
			free (oinput);
			return false;
		}
		input = (char *)r_str_trim_head_ro (input + 1);
		r_cons_set_raw (false);
		{
			free (core->rfs->cwd);
			core->rfs->cwd = strdup (r_config_get (core->config, "fs.cwd"));
			core->rfs->set_prompt = r_line_set_prompt;
			core->rfs->readline = r_line_readline;
			core->rfs->hist_add = r_line_hist_add;
			core->autocomplete_type = AUTOCOMPLETE_MS;
			r_core_autocomplete_reload (core);
			r_fs_shell (core->rfs, core->fs, input);
			core->autocomplete_type = AUTOCOMPLETE_DEFAULT;
			r_core_autocomplete_reload (core);
			r_config_set (core->config, "fs.cwd", (const char *)core->rfs->cwd);
		}
		break;
	case 'w': // "mw"
		if (input[1] == 'f') { // "mwf"
			char *arg0 = r_str_trim_dup (input + 1);
			char *arg1 = strchr (arg0, ' ');
			if (arg1) {
				*arg1++ = 0;
			} else {
				r_core_cmd_help_match (core, help_msg_m, "mwf", true);
				free (arg0);
				break;
			}
			size_t size = 0;
			char *buf = r_file_slurp (arg0, &size);
			RFSFile *f = r_fs_open (core->fs, arg1, true);
			if (f) {
				r_fs_write (core->fs, f, 0, (const ut8 *)buf, size);
				r_fs_close (core->fs, f);
				r_fs_file_free (f);
			} else {
				eprintf ("Cannot write\n");
			}
			free (arg0);
			free (buf);
		} else if (input[1] == ' ') {
			char *args = r_str_trim_dup (input + 1);
			char *arg = strchr (args, ' ');
			if (arg) {
				*arg++ = 0;
			} else {
				arg = "";
			}
			RFSFile *f = r_fs_open (core->fs, args, true);
			if (f) {
				r_fs_write (core->fs, f, 0, (const void *)arg, strlen (arg));
				r_fs_close (core->fs, f);
				r_fs_file_free (f);
			}
			free (args);
		} else {
			r_core_cmd_help_match (core, help_msg_m, "mw", false);
		}
		break;
	case 'y':
		if (input[1] == '?') { // "my?"
			r_core_cmd_help_match (core, help_msg_m, "my", true);
			break;
		}
		input = (char *)r_str_trim_head_ro (input + 1);
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr++ = 0;
		} else {
			ptr = "./";
		}
		file = r_fs_open (core->fs, input, false);
		if (file) {
			r_fs_read (core->fs, file, 0, file->size);
			r_core_yank_set (core, 0, file->data, file->size);
			r_fs_close (core->fs, file);
		} else {
			eprintf ("Cannot open file\n");
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_m);
		break;
	}
	free (oinput);
	return 0;
}
