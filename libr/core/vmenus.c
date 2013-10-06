/* radare - LGPL - Copyright 2009-2013 - pancake */

#include "r_core.h"

#define MAX_FORMAT 3

R_API int r_core_visual_trackflags(RCore *core) {
	const char *fs = NULL, *fs2 = NULL;
	int hit, i, j, ch;
	RListIter *iter;
	RFlagItem *flag;
	int _option = 0;
	int option = 0;
	char cmd[1024];
	int format = 0;
	int delta = 7;
	int menu = 0;

	for (j=i=0; i<R_FLAG_SPACES_MAX; i++)
		if (core->flags->spaces[i])
			j = 1;
	if (j==0) menu = 1;
	for (;;) {
		r_cons_gotoxy (0, 0);
		r_cons_clear ();

		if (menu) {
			r_cons_printf ("Flags in flagspace '%s'. Press '?' for help.\n\n",
			(core->flags->space_idx==-1)?"*":core->flags->spaces[core->flags->space_idx]);
			hit = 0;
			i = j = 0;
			r_list_foreach (core->flags->flags, iter, flag) {
				/* filter per flag spaces */
				if ((core->flags->space_idx != -1) &&
					(flag->space != core->flags->space_idx))
					continue;
				if (option==i) {
					fs2 = flag->name;
					hit = 1;
				}
				if ((i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
					r_cons_printf (" %c  %03d 0x%08"PFMT64x" %4"PFMT64d" %s\n",
						(option==i)?'>':' ',
						i, flag->offset, flag->size, flag->name);
					j++;
				}
				i++;
			}
			if (!hit && i>0) {
				option = i-1;
				continue;
			}
			if (fs2) {
				r_cons_printf ("\n Selected: %s\n\n", fs2);

				// Honor MAX_FORMATS here
				switch (format) {
				case 0: snprintf (cmd, sizeof (cmd), "px @ %s!64", fs2); core->printidx = 0; break;
				case 1: snprintf (cmd, sizeof (cmd), "pd 12 @ %s!64", fs2); core->printidx = 1; break;
				case 2: snprintf (cmd, sizeof (cmd), "ps @ %s!64", fs2); core->printidx = 5; break;
				case 3: strcpy (cmd, "f="); break;
				default: format = 0; continue;
				}
				if (*cmd) r_core_cmd (core, cmd, 0);
			} else r_cons_printf ("(no flags)\n");
		} else {
			r_cons_printf ("Flag spaces:\n\n");
			hit = 0;
			for (j=i=0;i<R_FLAG_SPACES_MAX;i++) {
				if (core->flags->spaces[i]) {
					if (option==i) {
						fs = core->flags->spaces[i];
						hit = 1;
					}
					if ((i >=option-delta) && ((i<option+delta)|| \
							((option<delta)&&(i<(delta<<1))))) {
						r_cons_printf(" %c %02d %c %s\n",
							(option==i)?'>':' ', j,
							(i==core->flags->space_idx)?'*':' ',
							core->flags->spaces[i]);
						j++;
					}
				}
			}
			if (core->flags->spaces[9]) {
				if (option == j) {
					fs = "*";
					hit = 1;
				}
				r_cons_printf (" %c %02d %c %s\n",
					(option==j)?'>':' ', j,
					(i==core->flags->space_idx)?'*':' ',
					"*");
			}
			if (!hit && j>0) {
				option = j-1;
				continue;
			}
		}
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'J': option += 10; break;
		case 'o': r_flag_sort (core->flags, 0); break;
		case 'n': r_flag_sort (core->flags, 1); break;
		case 'j': option++; break;
		case 'k': if (--option<0) option = 0; break;
		case 'K': option-=10; if (option<0) option = 0; break;
		case 'h':
		case 'b': // back
		case 'q':
			if (menu<=0) return R_TRUE; menu--;
			option = _option;
			if (menu==0) {
				// if no flagspaces, just quit
				for (j=i=0;i<R_FLAG_SPACES_MAX;i++)
					if (core->flags->spaces[i])
						j = 1;
				if (!j) return R_TRUE;
			}
			break;
		case 'a':
			switch (menu) {
			case 0: // new flag space
				r_cons_show_cursor (R_TRUE);
				r_line_set_prompt ("add flagspace: ");
				strcpy (cmd, "fs ");
				if (r_cons_fgets (cmd+3, sizeof (cmd)-4, 0, NULL) > 0) {
					r_core_cmd (core, cmd, 0);
					r_cons_set_raw (1);
					r_cons_show_cursor (R_FALSE);
				}
				break;
			case 1: // new flag
				r_cons_show_cursor (R_TRUE);
				r_line_set_prompt ("add flag: ");
				strcpy (cmd, "f ");
				if (r_cons_fgets (cmd+2, sizeof (cmd)-3, 0, NULL) > 0) {
					r_core_cmd (core, cmd, 0);
					r_cons_set_raw (1);
					r_cons_show_cursor (R_FALSE);
				}
				break;
			}
			break;
		case 'd':
			r_flag_unset (core->flags, fs2, NULL);
			break;
		case 'e':
			/* TODO: prompt for addr, size, name */
			eprintf ("TODO\n");
			r_sys_sleep (1);
			break;
		case '*':
			r_core_block_size (core, core->blocksize+16);
			break;
		case '/':
			r_core_block_size (core, core->blocksize-16);
			break;
		case '+':
			if (menu==1)
				r_core_cmdf (core, "f %s=%s+1", fs2, fs2);
			else r_core_block_size (core, core->blocksize+1);
			break;
		case '-':
			if (menu==1)
				r_core_cmdf (core, "f %s=%s-1", fs2, fs2);
			else r_core_block_size (core, core->blocksize-1);
			break;
		case 'r':
			if (menu == 1) {
				int len;
				r_cons_show_cursor (R_TRUE);
				r_cons_set_raw (0);
				// TODO: use r_flag_rename or wtf?..fr doesnt uses this..
				snprintf (cmd, sizeof (cmd), "fr %s ", fs2);
				len = strlen (cmd);
				eprintf ("Rename flag '%s' as:\n", fs2);
				r_line_set_prompt (":> ");
				if (r_cons_fgets (cmd+len, sizeof (cmd)-len-1, 0, NULL) <0)
					cmd[0]='\0';
				r_core_cmd (core, cmd, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (R_FALSE);
			}
			break;
		case 'R':
			if (menu == 1) {
				char line[1024];
				r_cons_show_cursor (R_TRUE);
				r_cons_set_raw (0);
				eprintf ("Rename function '%s' as:\n", fs2);
				r_line_set_prompt (":> ");
				if (r_cons_fgets (line, sizeof (line), 0, NULL) <0)
					cmd[0]='\0';
				snprintf (cmd, sizeof (cmd), "afr %s %s", line, fs2);
				r_core_cmd (core, cmd, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (R_FALSE);
			}
			break;
		case 'P': if (--format<0) format = MAX_FORMAT; break;
// = (format<=0)? MAX_FORMAT: format-1; break;
		case 'p': format++; break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			if (menu == 1) {
				sprintf (cmd, "s %s", fs2);
				r_core_cmd (core, cmd, 0);
				return R_TRUE;
			}
			r_flag_space_set (core->flags, fs);
			menu = 1;
			_option = option;
			option = 0;
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf (
			"\nVt: Visual Track help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" l/' ' - accept current selection\n"
			" a/d/e - add/delete/edit flag\n"
			" +/-   - increase/decrease block size\n"
			" o     - sort flags by offset\n"
			" r/R   - rename flag / Rename function\n"
			" n     - sort flags by name\n"
			" p/P   - rotate print format\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key ();
			break;
		case ':':
			r_cons_show_cursor (R_TRUE);
			r_cons_set_raw (0);
			cmd[0]='\0';
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) <0)
				cmd[0]='\0';
			//line[strlen(line)-1]='\0';
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (R_FALSE);
			if (cmd[0])
				r_cons_any_key ();
			//cons_gotoxy(0,0);
			r_cons_clear ();
			continue;
		}
	}
	return R_TRUE;
}

R_API int r_core_visual_comments (RCore *core) {
	char *str, cmd[512], *p = NULL;
	int mode = 0;
	int delta = 7;
	int i, ch, option = 0;
	int format = 0;
	int found = 0;
	ut64 from = 0, size = 0;
	RListIter *iter;
	RMetaItem *d;

// XXX: mode is always 0, remove useless code
	for (;;) {
		r_cons_gotoxy (0, 0);
		r_cons_clear ();
		r_cons_strcat ("Comments:\n");

		i = 0;
		found = 0;
		mode = 0;
		r_list_foreach (core->anal->meta->data, iter, d) {
			str = r_str_unscape (d->str);
			if (str) {
				if (d->type=='s') /* Ignore strings, there are in trackflags */
					continue;
				if ((i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
					r_str_sanitize (str);
					if (option==i) {
						mode = 0;
						found = 1;
						from = d->from;
						size = d->size;
						p = str;
						r_cons_printf ("  >  %s\n", str);
					} else {
						r_cons_printf ("     %s\n", str);
						free (str);
					}
				}
				i++;
			}
		}
		if (!found) {
			option--;
			if (option<0) break;
			continue;
		}
		r_cons_newline ();
#if 0
		r_list_foreach (core->anal->fcns, iter, fcn) {
			if ((i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
				if (option==i) {
					mode = 1;
					from = fcn->addr;
					size = fcn->size;
				}
				r_cons_printf("  %c .. %s\n", (option==i)?'>':' ', fcn->name);
			}
			i++;
		}
#endif

		switch (format) {
		case 0: sprintf (cmd, "px @ 0x%"PFMT64x":64", from); core->printidx = 0; break;
		case 1: sprintf (cmd, "pd 12 @ 0x%"PFMT64x":64", from); core->printidx = 1; break;
		case 2: sprintf (cmd, "ps @ 0x%"PFMT64x":64", from); core->printidx = 5; break;
		default: format = 0; continue;
		}
		if (*cmd) r_core_cmd (core, cmd, 0);

		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'a':
			//TODO
			break;
		case 'e':
			//TODO
			break;
		case 'd':
			if (mode == 0) {
				if (p) r_meta_del (core->anal->meta, R_META_TYPE_ANY, from, size, p);
			} else {
				r_anal_fcn_del_locs (core->anal, from);
				r_anal_fcn_del (core->anal, from);
			}
			break;
		case 'P':
			if (--format<0)
				format = MAX_FORMAT;
			break;
		case 'p':
			format++;
			break;
		case 'J':
			option += 10;
			break;
		case 'j':
			option++;
			break;
		case 'k':
			if (--option<0)
				option = 0;
			break;
		case 'K':
			option-=10;
			if (option<0)
				option = 0;
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			sprintf (cmd, "s 0x%"PFMT64x, from);
			r_core_cmd (core, cmd, 0);
			if (p)
				free (p);
			return R_TRUE;
		case 'q':
			if (p)
				free (p);
			return R_TRUE;
		case '?':
		case 'h':
			r_cons_clear00 ();
			r_cons_printf (
			"\nVT: Visual Comments/Anal help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" l/' ' - accept current selection\n"
			" a/d/e - add/delete/edit comment/anal symbol\n"
			" p/P   - rotate print format\n");
			r_cons_flush ();
			r_cons_any_key ();
			break;
		}
		if (p) {
			free (p);
			p = NULL;
		}
	}
	return R_TRUE;
}

static void config_visual_hit_i(RCore *core, const char *name, int delta) {
	struct r_config_node_t *node;
	node = r_config_node_get (core->config, name);
	if (node && ((node->flags & CN_INT) || (node->flags & CN_OFFT)))
		r_config_set_i(core->config, name, r_config_get_i(core->config, name)+delta);
}

/* Visually activate the config variable */
static void config_visual_hit(RCore *core, const char *name, int editor) {
	char buf[1024];
	RConfigNode *node;

	if (!(node = r_config_node_get (core->config, name)))
		return;
	if (node->flags & CN_BOOL) {
		r_config_set_i (core->config, name, node->i_value? 0:1);
	} else {
// XXX: must use config_set () to run callbacks!
		if (editor) {
			char * buf = r_core_editor (core, node->value);
			node->value = r_str_dup (node->value, buf);
			free (buf);
		} else {
			// FGETS AND SO
			r_cons_printf ("New value (old=%s): \n", node->value);
			r_cons_show_cursor (R_TRUE);
			r_cons_flush ();
			r_cons_set_raw (0);
			r_line_set_prompt (":> ");
			r_cons_fgets (buf, sizeof (buf)-1, 0, 0);
			r_cons_set_raw (1);
			r_cons_show_cursor (R_FALSE);
			r_config_set (core->config, name, buf);
			//node->value = r_str_dup (node->value, buf);
		}
	}
}

R_API void r_core_visual_config(RCore *core) {
	char cmd[1024], *fs = NULL, *fs2 = NULL;
	int i, j, ch, hit, show;
	int option, _option = 0;
	RListIter *iter;
	RConfigNode *bt;
	char old[1024];
	int delta = 9;
	int menu = 0;
	old[0]='\0';

	option = 0;
	for (;;) {
		r_cons_gotoxy (0,0);
		r_cons_clear ();

		switch (menu) {
		case 0: // flag space
			r_cons_printf ("\n Eval spaces:\n\n");
			hit = j = i = 0;
			r_list_foreach (core->config->nodes, iter, bt) {
				if (option==i) {
					fs = bt->name;
				}
				if (old[0]=='\0') {
					r_str_ccpy (old, bt->name, '.');
					show = 1;
				} else if (r_str_ccmp (old, bt->name, '.')) {
					r_str_ccpy (old, bt->name, '.');
					show = 1;
				} else show = 0;

				if (show) {
					if (option == i) hit = 1;
					if ( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						r_cons_printf(" %c  %s\n", (option==i)?'>':' ', old);
						j++;
					}
					i++;
				}
			}
			if (!hit && j>0) {
				option--;
				continue;
			}
			r_cons_printf ("\n Sel:%s \n\n", fs);
			break;
		case 1: // flag selection
			r_cons_printf ("\n Eval variables: (%s)\n\n", fs);
			hit = 0;
			j = i = 0;
			// TODO: cut -d '.' -f 1 | sort | uniq !!!
			r_list_foreach (core->config->nodes, iter, bt) {
				if (option==i) {
					fs2 = bt->name;
					hit = 1;
				}
				if (!r_str_ccmp (bt->name, fs, '.')) {
					if ( (i>=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						// TODO: Better align
						r_cons_printf (" %c  %s = %s\n", (option==i)?'>':' ', bt->name, bt->value);
						j++;
					}
					i++;
				}
			}
			if (!hit && j>0) {
				option = i-1;
				continue;
			}
			if (fs2 != NULL)
				r_cons_printf ("\n Selected: %s\n\n", fs2);
		}

		if (fs && !memcmp (fs, "asm.", 4))
			r_core_cmd (core, "pd 5", 0);
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char

		switch (ch) {
		case 'j': option++; break;
		case 'k': option = (option<=0)? 0: option-1; break;
		case 'h':
		case 'b': // back
			menu = 0;
			option = _option;
			break;
		case 'q':
			if (menu<=0) return; menu--;
			break;
		case '*':
		case '+':
			if (fs2 != NULL)
				config_visual_hit_i (core, fs2, +1);
			continue;
		case '/':
		case '-':
			if (fs2 != NULL)
				config_visual_hit_i (core, fs2, -1);
			continue;
		case 'l':
		case 'E': // edit value
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (menu == 1) {
				if (fs2 != NULL)
					config_visual_hit (core, fs2, (ch=='E'));
			} else {
				menu = 1;
				_option = option;
				option = 0;
			}
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf ("\nVe: Visual Eval help:\n\n"
			" q     - quit menu\n"
			" j/k   - down/up keys\n"
			" h/b   - go back\n"
			" e/' ' - edit/toggle current variable\n"
			" E     - edit variable with 'cfg.editor' (vi?)\n"
			" +/-   - increase/decrease numeric value\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key ();
			break;
		case ':':
			r_cons_show_cursor (R_TRUE);
			r_cons_set_raw(0);
/* WTF READLINE?? WE DONT USE THAT!! */
#if HAVE_LIB_READLINE
			{
			char *ptr = readline(VISUAL_PROMPT);
			if (ptr) {
				strncpy(cmd, ptr, sizeof (cmd)-1);
				r_core_cmd(core, cmd, 1);
				free(ptr);
			}
			}
#else
			*cmd = '\0';
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) <0)
				cmd[0]='\0';
			//line[strlen(line)-1]='\0';
			r_core_cmd (core, cmd, 1);
#endif
			r_cons_set_raw (1);
			r_cons_show_cursor (R_FALSE);
			if (cmd[0])
				r_cons_any_key ();
			//r_cons_gotoxy(0,0);
			r_cons_clear00 ();
			continue;
		}
	}
}

R_API void r_core_visual_mounts (RCore *core) {
	RList *list;
	RFSRoot *fsroot;
	RListIter *iter;
	RFSFile *file;
	RFSPartition *part;
	int i, ch, option, mode, partition, dir, delta = 7;
	char *str, path[4096], buf[1024], *root = NULL;
	const char *n, *p;

	dir = partition = option = mode = 0;
	for (;;) {
		/* Clear */
		r_cons_gotoxy (0,0);
		r_cons_clear ();

		/* Show */
		if (mode == 0) {
			r_cons_printf ("Partitions:\n\n");
			n = r_fs_partition_type_get (partition);
			list = r_fs_partitions (core->fs, n, 0);
			i = 0;
			if (list) {
				r_list_foreach (list, iter, part) {
					if ((option-delta <= i) && (i <= option+delta)) {
						if (option == i)
							r_cons_printf (" > ");
						else r_cons_printf ("   ");
						r_cons_printf ("%d %02x 0x%010"PFMT64x" 0x%010"PFMT64x"\n",
								part->number, part->type,
								part->start, part->start+part->length);
					}
					i++;
				}
				r_list_free (list);
			} else r_cons_printf ("Cannot read partition\n");
		} else if (mode == 1) {
			r_cons_printf ("Types:\n\n");
			for(i=0;;i++) {
				n = r_fs_partition_type_get (i);
				if (!n) break;
				r_cons_printf ("%s%s\n", (i==partition)?" > ":"   ", n);
			}
		} else if (mode == 3) {
			i = 0;
			r_cons_printf ("Mountpoints:\n\n");
			r_list_foreach (core->fs->roots, iter, fsroot) {
				if ((option-delta <= i) && (i <= option+delta)) {
					r_cons_printf ("%s %s\n", (option == i)?" > ":"   ",
							fsroot->path);
				}
				i++;
			}
		} else {
			if (root) {
				list = r_fs_dir (core->fs, path);
				if (list) {
					r_cons_printf ("%s:\n\n", path);
					i = 0;
					r_list_foreach (list, iter, file) {
						if ((dir-delta <= i) && (i <= dir+delta)) {
							r_cons_printf ("%s%c %s\n", (dir == i)?" > ":"   ",
									file->type, file->name);
						}
						i++;
					}
					r_cons_printf ("\n");
					r_list_free (list);
				} else r_cons_printf ("Cannot open '%s' directory\n", root);
			} else r_cons_printf ("Root undefined\n");
		}
		if (mode==2) {
			r_str_chop_path (path);
			str = path + strlen (path);
			strncat (path, "/", sizeof (path)-strlen (path)-1);
			list = r_fs_dir (core->fs, path);
			file = r_list_get_n (list, dir);
			if (file && file->type != 'd')
				r_core_cmdf (core, "px @ 0x%"PFMT64x"!64", file->off);
			*str='\0';
		}
		r_cons_flush ();

		/* Ask for option */
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
			case 'l':
			case '\r':
			case '\n':
				if (mode == 0) {
					n = r_fs_partition_type_get (partition);
					list = r_fs_partitions (core->fs, n, 0);
					if (!list) {
						r_cons_printf ("Unknown partition\n");
						r_cons_any_key ();
						r_cons_flush ();
						break;
					}
					part = r_list_get_n (list, option);
					if (!part) {
						r_cons_printf ("Unknown partition\n");
						r_cons_any_key ();
						r_cons_flush ();
						break;
					}
					p = r_fs_partition_type (n, part->type);
					if (p) {
						if (r_fs_mount (core->fs, p, "/root", part->start)) {
							if (root)
								free (root);
							root = strdup ("/root");
							strncpy (path, root, sizeof (path)-1);
							mode = 2;
						} else {
							r_cons_printf ("Cannot mount partition\n");
							r_cons_flush ();
							r_cons_any_key ();
						}
					} else {
						r_cons_printf ("Unknown partition type\n");
						r_cons_flush ();
						r_cons_any_key ();
					}
				} else if (mode == 2){
					r_str_chop_path (path);
					strncat (path, "/", sizeof (path)-strlen (path)-1);
					list = r_fs_dir (core->fs, path);
					file = r_list_get_n (list, dir);
					if (file) {
						if (file->type == 'd') {
							strncat (path, file->name, sizeof (path)-strlen (path)-1);
							r_str_chop_path (path);
							if (memcmp (root, path, strlen (root)-1))
								strncpy (path, root, sizeof (path)-1);
						} else {
							r_core_cmdf (core, "s 0x%"PFMT64x, file->off);
							r_fs_umount (core->fs, root);
							return;
						}
					} else {
						r_cons_printf ("Unknown file\n");
						r_cons_flush ();
						r_cons_any_key ();
					}

				} else if (mode == 3) {
					fsroot = r_list_get_n (core->fs->roots, option);
					root = strdup (fsroot->path);
					strncpy (path, root, sizeof (path)-1);
					mode = 2;
				}
				dir = partition = option = 0;
				break;
			case 'k':
				if (mode == 0 || mode == 3) {
					if (option > 0)
						option--;
				} else if (mode == 1) {
					if (partition > 0)
						partition--;
				} else {
					if (dir>0)
						dir--;
				}
				break;
			case 'j':
				if (mode == 0) {
					n = r_fs_partition_type_get (partition);
					list = r_fs_partitions (core->fs, n, 0);
					if (option < r_list_length (list)-1)
						option++;
				} else if (mode == 1) {
					if (partition < r_fs_partition_get_size ()-1)
						partition++;
				} else if (mode == 3) {
					if (option < r_list_length (core->fs->roots)-1)
						option++;
				} else {
					list = r_fs_dir (core->fs, path);
					if (dir < r_list_length (list)-1)
						dir++;
				}
				break;
			case 't':
				mode = 1;
				break;
			case 'h':
				if (mode == 2) {
					if (strcmp (path, root)) {
						strcat (path, "/..");
						r_str_chop_path (path);
					} else {
						r_fs_umount (core->fs, root);
						mode = 0;
					}
				} else if (mode == 1) {
					mode = 0;
				} else return;
				break;
			case 'q':
				if (mode == 2 && root) {
					r_fs_umount (core->fs, root);
					mode = 0;
				} else
					return;
				break;
			case 'g':
				if (mode == 2){
					r_str_chop_path (path);
					str = path + strlen (path);
					strncat (path, "/", sizeof (path)-strlen (path)-1);
					list = r_fs_dir (core->fs, path);
					file = r_list_get_n (list, dir);
					if (file) {
						strncat (path, file->name, sizeof (path)-strlen (path)-1);
						r_str_chop_path (path);
						if (memcmp (root, path, strlen (root)-1))
							strncpy (path, root, sizeof (path)-1);
						file = r_fs_open (core->fs, path);
						if (file) {
							r_fs_read (core->fs, file, 0, file->size);
							r_cons_show_cursor (R_TRUE);
							r_cons_set_raw (0);
							r_line_set_prompt ("Dump path (ej: /tmp/file): ");
							r_cons_fgets (buf, sizeof (buf)-1, 0, 0);
							r_cons_set_raw (1);
							r_cons_show_cursor (R_FALSE);
							r_file_dump (buf, file->data, file->size);
							r_fs_close (core->fs, file);
							r_cons_printf ("Done\n");
						} else r_cons_printf ("Cannot dump file\n");
					} else r_cons_printf ("Cannot dump file\n");
					r_cons_flush ();
					r_cons_any_key ();
					*str='\0';
				}
				break;
			case 'm':
				mode = 3;
				option = 0;
				break;
			case '?':
				r_cons_clear00 ();
				r_cons_printf ("\nVM: Visual Mount points help:\n\n");
				r_cons_printf (" q     - go back or quit menu\n");
				r_cons_printf (" j/k   - down/up keys\n");
				r_cons_printf (" h/l   - forward/go keys\n");
				r_cons_printf (" t     - choose partition type\n");
				r_cons_printf (" g     - dump file\n");
				r_cons_printf (" m     - show mountpoints\n");
				r_cons_printf (" :     - enter command\n");
				r_cons_printf (" ?     - show this help\n");
				r_cons_flush ();
				r_cons_any_key ();
				break;
			case ':':
				r_cons_show_cursor (R_TRUE);
				r_cons_set_raw (0);
				r_line_set_prompt (":> ");
				r_cons_fgets (buf, sizeof (buf)-1, 0, 0);
				r_cons_set_raw (1);
				r_cons_show_cursor (R_FALSE);
				r_core_cmd (core, buf, 1);
				r_cons_any_key ();
				break;
		}
	}
}

static void var_index_show(RAnal *anal, RAnalFunction *fcn, ut64 addr, int idx) {
	int i = 0;
	RAnalVar *v;
	RAnalVarAccess *x;
	RListIter *iter, *iter2;
	int window = 15;
	int wdelta = (idx>5)?idx-5:0;
	if (!fcn) return;
	r_list_foreach(fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			if (i>=wdelta) {
				if (i>window+wdelta) {
					r_cons_printf("...\n");
					break;
				}
				if (idx == i) r_cons_printf (" * ");
				else r_cons_printf ("   ");
#if 0
				if (v->type->type == R_ANAL_TYPE_ARRAY) {
eprintf ("TODO: support for arrays\n");
					r_cons_printf ("0x%08llx - 0x%08llx scope=%s type=%s name=%s delta=%d array=%d\n",
						v->addr, v->eaddr, r_anal_var_scope_to_str (anal, v->scope),
						r_anal_type_to_str (anal, v->type, ""),
						v->name, v->delta, v->type->custom.a->count);
				} else 
#endif
				{
					char *s = r_anal_type_to_str (anal, v->type);
					if (!s) s = strdup ("<unk>");
					r_cons_printf ("0x%08llx - 0x%08llx scope=%s type=%s name=%s delta=%d\n",
						v->addr, v->eaddr, r_anal_var_scope_to_str (anal, v->scope),
						s, v->name, v->delta);
					free (s);
				}
				r_list_foreach (v->accesses, iter2, x) {
					r_cons_printf ("  0x%08llx %s\n", x->addr, x->set?"set":"get");
				}
			}
			i++;
		}
	}
}

// helper
static void function_rename(RCore *core, ut64 addr, const char *name) {
	RListIter *iter;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (fcn->addr == addr) {
			r_flag_unset (core->flags, fcn->name, NULL);
			free (fcn->name);
			fcn->name = strdup (name);
			r_flag_set (core->flags, name, addr, fcn->size, 0);
			break;
		}
	}
}

static ut64 var_functions_show(RCore *core, int idx, int show) {
	int i = 0;
	ut64 seek = core->offset;
	ut64 addr = core->offset;
	int window = 15;
	int wdelta = (idx>5)?idx-5:0;
	RListIter *iter;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (i>=wdelta) {
			if (i> window+wdelta) {
				r_cons_printf("...\n");
				break;
			}
			//if (seek >= fcn->addr && seek <= fcn->addr+fcn->size)
			if (idx == i)
				addr = fcn->addr;
			if (show)
				r_cons_printf ("%c%c 0x%08llx (%s)\n",
					(seek == fcn->addr)?'>':' ',
					(idx==i)?'*':' ',
					fcn->addr, fcn->name);
		}
		i++;
	}
	return addr;
}

static int level = 0;
static ut64 addr = 0;
static int option = 0;

static void r_core_visual_anal_refresh_column (RCore *core) {
	char *oprofile = strdup (r_config_get (core->config, "asm.profile"));
	ut64 addr = level?  core->offset: var_functions_show (core, option, 0);
	r_cons_printf ("Visual code analysis manipulation\n");
	r_config_set (core->config, "asm.profile", "simple");
	r_core_cmdf (core, "pd @ 0x%"PFMT64x"!16", addr);
	r_config_set (core->config, "asm.profile", oprofile);
	free (oprofile);
}

static void r_core_visual_anal_refresh (RCore *core) {
	RAnalFunction *fcn;
	ut64 addr;
	char old[1024];
	int cols = r_cons_get_size (NULL);

	if (!core) return;
	old[0]='\0';
	addr = core->offset;
	fcn = r_anal_fcn_find (core->anal, addr, R_ANAL_FCN_TYPE_NULL);

	cols -= 50;
	if (cols > 60) cols = 60;
	r_cons_clear ();
	if (cols>20) {
		r_core_visual_anal_refresh_column (core);
		r_cons_column (cols);
	}
	switch (level) {
	case 0:
		r_cons_printf ("-[ functions ]---------------- \n"
			"(a) add     (x)xrefs     (q)quit \n"
			"(m) modify  (c)calls     (g)go   \n"
			"(d) delete  (v)variables (?)help \n");
		addr = var_functions_show (core, option, 1);
		break;
	case 1:
		r_cons_printf (
			"-[ variables ]----- 0x%08"PFMT64x"\n"
			"(a) add     (x)xrefs  \n"
			"(m) modify  (g)go     \n"
			"(d) delete  (q)quit   \n", addr);
		var_index_show (core->anal, fcn, addr, option);
		break;
	case 2:
		r_cons_printf ("-[ calls ]----------------------- 0x%08"PFMT64x" (TODO)\n", addr);
#if 0
		sprintf(old, "aCf@0x%08llx", addr);
		cons_flush();
		radare_cmd(old, 0);
#endif
		break;
	case 3:
		r_cons_printf ("-[ xrefs ]----------------------- 0x%08"PFMT64x"\n", addr);
		sprintf (old, "arl~0x%08"PFMT64x, addr);
		r_core_cmd0 (core, old);
		break;
	}
	if (cols<=20)
		r_core_visual_anal_refresh_column (core);
	r_cons_flush ();
}

/* Like emenu but for real */
R_API void r_core_visual_anal(RCore *core) {
	char old[218];
	int ch, _option = 0;
	RConsEvent olde = core->cons->event_resize;
	core->cons->event_resize = (RConsEvent) r_core_visual_anal_refresh;
	level = 0;
	addr = core->offset;

	for (;;) {
		r_core_visual_anal_refresh (core);
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case '?':
			r_cons_clear ();
			r_cons_printf (
				"Usage: Vv [\n"
				"Actions supported:\n"
				" functions: Add, Modify, Delete, Xrefs Calls Vars\n"
				" variables: Add, Modify, Delete\n"
				"Moving:\n"
				" j,k     select next/prev item\n"
				" h,q     go back, quit\n"
				" l,ret   enter, function\n"
			);
			r_cons_flush ();
			r_cons_any_key ();
			break;
		case ':':
			r_core_visual_prompt (core);
			continue;
		case 'a':
			switch (level) {
			case 0:
eprintf ("TODO: Add new function manually\n");
/*
				r_cons_show_cursor (R_TRUE);
				r_cons_set_raw (R_FALSE);
				r_line_set_prompt ("Address: ");
				if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
				old[strlen (old)-1] = 0;
				if (!*old) break;
				addr = r_num_math (core->num, old);
				r_line_set_prompt ("Size: ");
				if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
				old[strlen (old)-1] = 0;
				if (!*old) break;
				size = r_num_math (core->num, old);
				r_line_set_prompt ("Name: ");
				if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
				old[strlen (old)-1] = 0;
				r_flag_set (core->flags, old, addr, 0, 0);
				//XXX sprintf(cmd, "CF %lld @ 0x%08llx", size, addr);
				// XXX r_core_cmd0(core, cmd);
				r_cons_set_raw (R_TRUE);
				r_cons_show_cursor (R_FALSE);
*/
				break;
			case 1:
				break;
			}
			break;
		case 'm':
			r_cons_show_cursor (R_TRUE);
			r_cons_set_raw (R_FALSE);
			r_line_set_prompt ("New name: ");
			if (!r_cons_fgets (old, sizeof (old), 0, NULL)) break;
			//old[strlen (old)-1] = 0;
			function_rename (core, addr, old);
			r_cons_set_raw (R_TRUE);
			r_cons_show_cursor (R_FALSE);
			break;
		case 'd':
			switch (level) {
			case 0:
				eprintf ("TODO\n");
				//data_del(addr, DATA_FUN, 0);
				// XXX correcly remove all the data contained inside the size of the function
				//flag_remove_at(addr);
				break;
			}
			break;
		case 'x': level = 3; break;
		case 'c': level = 2; break;
		case 'v': level = 1; break;
		case 'j': option++; break;
		case 'k': option = (option<=0)? 0: option-1; break;
		case 'g': 
			r_core_seek (core, addr, SEEK_SET);
			goto beach;
		case ' ':
		case 'l':
			level = 1;
			_option = option;
			break;
		case 'h':
		case 'b': // back
			level = 0;
			option = _option;
			break;
		case 'q':
			if (level==0)
				goto beach;
			level--;
			break;
		}
	}
beach:
	core->cons->event_resize = olde;
	level = 0;
}

R_API void r_core_seek_next(RCore *core, const char *type) {
	RListIter *iter;
	ut64 next = UT64_MAX;
	if (strstr (type, "opc")) {
		RAnalOp aop;
		if (r_anal_op (core->anal, &aop, core->offset, core->block, core->blocksize))
			next = core->offset + aop.length;
		else eprintf ("Invalid opcode\n");
	} else
	if (strstr (type, "fun")) {
		RAnalFunction *fcni;
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (fcni->addr < next && fcni->addr > core->offset)
				next = fcni->addr;
		}
	} else
	if (strstr (type, "hit")) {
		const char *pfx = r_config_get (core->config, "search.prefix");
		RFlagItem *flag;
		r_list_foreach (core->flags->flags, iter, flag) {
			if (!memcmp (flag->name, pfx, strlen (pfx)))
				if (flag->offset < next && flag->offset > core->offset)
					next = flag->offset;
		}
	} else { // flags
		RFlagItem *flag;
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->offset < next && flag->offset > core->offset)
				next = flag->offset;
		}
	}
	if (next!=UT64_MAX)
		r_core_seek (core, next, 1);
}

R_API void r_core_seek_previous (RCore *core, const char *type) {
	RListIter *iter;
	ut64 next = 0;
	if (strstr (type, "opc")) {
		eprintf ("TODO: r_core_seek_previous (opc)\n");
	} else
	if (strstr (type, "fun")) {
		RAnalFunction *fcni;
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (fcni->addr > next && fcni->addr < core->offset)
				next = fcni->addr;
		}
	} else
	if (strstr (type, "hit")) {
		RFlagItem *flag;
		const char *pfx = r_config_get (core->config, "search.prefix");
		r_list_foreach (core->flags->flags, iter, flag) {
			if (!memcmp (flag->name, pfx, strlen (pfx)))
				if (flag->offset > next && flag->offset< core->offset)
					next = flag->offset;
		}
	} else { // flags
		RFlagItem *flag;
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->offset > next && flag->offset < core->offset)
				next = flag->offset;
		}
	}
	if (next!=0)
		r_core_seek (core, next, 1);
}

R_API void r_core_visual_define (RCore *core) {
	int cur = R_MIN (core->print->cur, core->print->ocur);
	int plen = core->blocksize;
	ut64 off = core->offset;
	int n, ch, ntotal = 0;
	ut8 *p = core->block;
	RAnalFunction *f;
	char *name;

	if (core->print->cur_enabled) {
		off += cur;
		p += cur;
		plen = R_ABS (core->print->cur- core->print->ocur)+1;
	}
	r_cons_printf ("Define current block as:\n"
		" r  - rename function\n"
		" d  - set as data\n"
		" c  - set as code\n"
		" s  - set string\n"
		" S  - set strings in current block\n"
		" f  - analyze function\n"
		" u  - undefine metadata here\n"
		" q  - quit/cancel operation\n");
	r_cons_flush ();

	// get ESC+char, return 'hjkl' char
	ch = r_cons_arrow_to_hjkl (r_cons_readchar ());

	switch (ch) {
	case 'r':
		r_core_cmd0 (core, "?i new function name;afr `?y`");
		break;
	case 'S':
		do {
			n = r_str_nlen ((const char*)p+ntotal, plen-ntotal)+1;
			name = malloc (n+10);
			strcpy (name, "str.");
			strncpy (name+4, (const char *)p+ntotal, n);
			r_flag_set (core->flags, name, off, n, 0);
			r_meta_add (core->anal->meta, R_META_TYPE_STRING,
				off+ntotal, off+n+ntotal, (const char *)p+ntotal);
			free (name);
			if (n<2) break;
			ntotal+= n;
		} while (ntotal<core->blocksize);
		break;
	case 's':
		// TODO: r_core_cmd0 (core, "Cz");
		n = r_str_nlen ((const char*)p, plen)+1;
		name = malloc (n+10);
		strcpy (name, "str.");
		strncpy (name+4, (const char *)p, n);
		r_flag_set (core->flags, name, off, n, 0);
		r_meta_add (core->anal->meta, R_META_TYPE_STRING, off, off+n, (const char *)p);
		free (name);
		break;
	case 'd': // TODO: check
		r_meta_cleanup (core->anal->meta, off, off+plen);
		r_meta_add (core->anal->meta, R_META_TYPE_DATA, off, off+plen, "");
		break;
	case 'c': // TODO: check
		r_meta_cleanup (core->anal->meta, off, off+plen);
		r_meta_add (core->anal->meta, R_META_TYPE_CODE, off, off+plen, "");
		break;
	case 'u':
		r_flag_unset_i (core->flags, off, NULL);
		f = r_anal_fcn_find (core->anal, off, 0);
		r_anal_fcn_del_locs (core->anal, off);
		if (f) r_meta_del (core->anal->meta, R_META_TYPE_ANY, off, f->size, "");
		r_anal_fcn_del (core->anal, off);
		break;
	case 'f':
		{
			int funsize = 0;
			int depth = r_config_get_i (core->config, "anal.depth");
			if (core->print->cur_enabled) {
				funsize = 1+ R_ABS (core->print->cur - core->print->ocur);
				depth = 0;
			}
			r_cons_break (NULL,NULL);
			r_core_anal_fcn (core, off, UT64_MAX,
				R_ANAL_REF_TYPE_NULL, depth);
			r_cons_break_end ();
			if (funsize) {
				RAnalFunction *f = r_anal_fcn_find (core->anal, off, -1);
				if (f) f->size = funsize;
			}
		}
		break;
	case 'q':
	default:
		break;
	}
}

R_API void r_core_visual_colors(RCore *core) {
	char color[32], cstr[32];
	const char *k, *kol;
	int ch, opt = 0, oopt = -1;
	ut8 r, g, b;

	r = g = b = 0;
	kol = r_cons_pal_get_color (opt);
	r_cons_rgb_parse (kol, &r, &g, &b, NULL);
	for (;;) {
		r_cons_clear ();
		k = r_cons_pal_get_i (opt);
		if (!k) {
			opt = 0;
			k = r_cons_pal_get_i (opt);
		}
		r_cons_gotoxy (0, 0);
		r_cons_rgb_str (cstr, r, g, b, 0);
		r&=0xf;
		g&=0xf;
		b&=0xf;
		sprintf (color, "rgb:%x%x%x", r, g, b);
//r_cons_printf ("COLOR%s(%sXXX)"Color_RESET"\n", kol, kol?kol+1:"");
		r_cons_printf ("# Colorscheme %d - Use '.' and ':' to randomize palette\n"
			"# Press 'rRgGbB', 'jk' or 'q'\nec %s %s   # %d (%s)\n",
			opt, k, color, atoi (cstr+7), cstr+1);
		r_core_cmdf (core, "ec %s %s", k, color);
		r_core_cmd0 (core, "pd 25");
		r_cons_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch);
		switch (ch) {
#define CASE_RGB(x,X,y) \
	case x:y--;if(y>0x7f)y=0;break;\
	case X:y++;if(y>15)y=15;break;
		CASE_RGB ('R','r',r);
		CASE_RGB ('G','g',g);
		CASE_RGB ('B','b',b);
		case 'q': return;
		case 'k': opt--; break;
		case 'j': opt++; break;
		case 'K': opt=0; break;
		case 'J': opt=0; break; // XXX must go to end
		case ':': r_cons_pal_random (); break;
		case '.':
			r = r_num_rand (0xf);
			g = r_num_rand (0xf);
			b = r_num_rand (0xf);
			break;
		}
		if (opt != oopt) {
			kol = r_cons_pal_get_color (opt);
			r_cons_rgb_parse (kol, &r, &g, &b, NULL);
			oopt = opt;
		}
	}
}
