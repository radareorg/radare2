/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include "r_core.h"

#define NPF 6
static int printidx = 0;
const char *printfmt[] = { "x", "pd", "f tmp&&sr sp&&x 64&&dr=&&s-&&s tmp&&f-tmp&&pd", "p8", "pc", "ps" };

static int curset = 0, cursor = 0, ocursor=-1;
static int color = 1;
static int debug = 1;
static int flags = R_PRINT_FLAGS_ADDRMOD;

static int marks_init = 0;
static ut64 marks[UT8_MAX+1];

static void r_core_visual_mark(RCore *core, ut8 ch) {
	if (!marks_init) {
		int i;
		for (i=0;i<UT8_MAX;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	marks[ch] = core->offset;
}

static void r_core_visual_mark_seek(RCore *core, ut8 ch) {
	if (!marks_init) {
		int i;
		for (i=0;i<UT8_MAX;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	if (marks[ch])
		r_core_seek (core, marks[ch], 1);
}

R_API int r_core_visual_trackflags(RCore *core) {
	char cmd[1024];
	struct list_head *pos;
#define MAX_FORMAT 2
	int format = 0;
	const char *ptr;
	const char *fs = NULL;
	char *fs2 = NULL;
	int option = 0;
	int _option = 0;
	int delta = 7;
	int menu = 0;
	int i,j, ch;
	int hit;

	for (;;) {
		r_cons_gotoxy (0,0);
		r_cons_clear ();
		/* Execute visual prompt */
		ptr = r_config_get (core->config, "cmd.vprompt");
		if (ptr&&ptr[0])
			r_core_cmd (core, ptr, 0);

		if (menu) {
			r_cons_printf ("\n Flags in flagspace '%s'. Press '?' for help.\n\n",
			(core->flags->space_idx==-1)?"*":core->flags->space[core->flags->space_idx]);
			hit = 0;
			i = j = 0;
			list_for_each_prev (pos, &core->flags->flags) {
				RFlagItem *flag = (RFlagItem*) list_entry(pos, RFlagItem, list);
				/* filter per flag spaces */
				if ((core->flags->space_idx != -1) && 
					(flag->space != core->flags->space_idx))
					continue;
				if (option==i) {
					fs2 = flag->name;
					hit = 1;
				}
				if ((i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
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
			r_cons_printf ("\n Selected: %s\n\n", fs2);

			switch (format) {
			case 0: sprintf (cmd, "px @ %s", fs2); printidx = 0; break;
			case 1: sprintf (cmd, "pd 12 @ %s", fs2); printidx = 1; break;
			case 2: sprintf (cmd, "ps @ %s", fs2); printidx = 5; break;
			default: format = 0; continue;
			}
			if (*cmd) r_core_cmd (core, cmd, 0);
		} else {
			r_cons_printf ("\n Flag spaces:\n\n");
			hit = 0;
			for (j=i=0;i<R_FLAG_SPACES_MAX;i++) {
				if (core->flags->space[i]) {
					if (option==i) {
						fs = core->flags->space[i];
						hit = 1;
					}
					if ((i >=option-delta) && ((i<option+delta)|| \
							((option<delta)&&(i<(delta<<1))))) {
						r_cons_printf(" %c %02d %c %s\n",
							(option==i)?'>':' ', j, 
							(i==core->flags->space_idx)?'*':' ',
							core->flags->space[i]);
						j++;
					}
				}
			}
			{
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
		r_cons_flush ();
		ch = r_cons_readchar ();
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'J':
			option+=10;
			break;
		case 'o':
			r_flag_sort (core->flags, 0);
			break;
		case 'n':
			r_flag_sort (core->flags, 1);
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
		case 'h':
		case 'b': // back
			menu = 0;
			option = _option;
			break;
		case 'a':
			switch (menu) {
			case 0: // new flag space
				break;
			case 1: // new flag
				break;
			}
			break;
		case 'd':
			r_flag_unset (core->flags, fs2);
			break;
		case 'e':
			/* TODO: prompt for addr, size, name */
			eprintf ("TODO\n");
			r_sys_sleep (1);
			break;
		case 'q':
			if (menu<=0) return R_TRUE; menu--;
			break;
		case '*':
			r_core_block_size (core, core->blocksize+16);
			break;
		case '+':
			r_core_block_size (core, core->blocksize+1);
			break;
		case '/':
			r_core_block_size (core, core->blocksize-16);
			break;
		case '-':
			r_core_block_size (core, core->blocksize-1);
			break;
		case 'r':
			if (menu == 1) {
				int len;
				r_cons_set_raw (0);
				// TODO: use r_flag_rename or wtf?..fr doesnt uses this..
				snprintf (cmd, sizeof (cmd), "fr %s ", fs2);
				len = strlen (cmd);
				eprintf ("Rename flag '%s' as:\n", fs2);
				if (r_cons_fgets (cmd+len, sizeof (cmd)-len-1, 0, NULL) <0)
					cmd[0]='\0';
				r_core_cmd (core, cmd, 0);
				r_cons_set_raw (1);
			}
			break;
		case 'P':
			if (--format<0)
				format = MAX_FORMAT;
			break;
		case 'p':
			format++;
			break;
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
			" r     - rename flag\n"
			" n     - sort flags by name\n"
			" p/P   - rotate print format\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key ();
			break;
		case ':':
			r_cons_set_raw (0);
			cmd[0]='\0';
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) <0)
				cmd[0]='\0';
			//line[strlen(line)-1]='\0';
			r_core_cmd (core, cmd, 1);
			r_cons_set_raw (1);
			if (cmd[0])
				r_cons_any_key ();
			//cons_gotoxy(0,0);
			r_cons_clear ();
			continue;
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
static void config_visual_hit(RCore *core, const char *name) {
	char buf[1024];
	RConfigNode *node;

	if (!(node = r_config_node_get(core->config, name)))
		return;
	if (node->flags & CN_BOOL) {
		/* TOGGLE */
		node->i_value = !node->i_value;
		node->value = r_str_dup(node->value, node->i_value?"true":"false");
	} else {
		// FGETS AND SO
		r_cons_printf("New value (old=%s): ", node->value);
		r_cons_flush();
		r_cons_set_raw(0);
		r_cons_fgets(buf, 1023, 0, 0);
		r_cons_set_raw(1);
		node->value = r_str_dup(node->value, buf);
	}
}

R_API void r_core_visual_config(RCore *core) {
	char cmd[1024];
	struct list_head *pos;
#define MAX_FORMAT 2
	const char *ptr;
	char *fs = NULL;
	char *fs2 = NULL;
	int option = 0;
	int _option = 0;
	int delta = 9;
	int menu = 0;
	int i,j, ch;
	int hit;
	int show;
	char old[1024];
	old[0]='\0';

	for (;;) {
		r_cons_gotoxy (0,0);
		r_cons_clear ();

		/* Execute visual prompt */
		ptr = r_config_get (core->config, "cmd.vprompt");
		if (ptr&&ptr[0]) {
//			int tmp = last_print_format;
			r_core_cmd (core, ptr, 0);
//			last_print_format = tmp;
		}

		if (fs&&!memcmp (fs, "asm.", 4))
			r_core_cmd (core, "pd 5", 0);

		switch (menu) {
		case 0: // flag space
			r_cons_printf ("\n Eval spaces:\n\n");
			hit = 0;
			j = i = 0;
			list_for_each(pos, &(core->config->nodes)) {
				struct r_config_node_t *bt = list_entry(pos, struct r_config_node_t, list);
				if (option==i) {
					fs = bt->name;
					hit = 1;
				}
				if (old[0]=='\0') {
					r_str_ccpy (old, bt->name, '.');
					show = 1;
				} else if (r_str_ccmp(old, bt->name, '.')) {
					r_str_ccpy (old, bt->name, '.');
					show = 1;
				} else show = 0;

				if (show) {
					if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						r_cons_printf(" %c  %s\n", (option==i)?'>':' ', old);
						j++;
					}
					i++;
				}
			}
			if (!hit && j>0) {
				option = j-1;
				continue;
			}
			r_cons_printf("\n Sel:%s \n\n", fs);
			break;
		case 1: // flag selection
			r_cons_printf("\n Eval variables: (%s)\n\n", fs);
			hit = 0;
			j = i = 0;
			// TODO: cut -d '.' -f 1 | sort | uniq !!!
			list_for_each (pos, &(core->config->nodes)) {
				RConfigNode *bt = list_entry(pos, RConfigNode, list);
				if (option==i) {
					fs2 = bt->name;
					hit = 1;
				}
				if (!r_str_ccmp(bt->name, fs, '.')) {
					if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
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
				r_cons_printf("\n Selected: %s\n\n", fs2);
		}
		r_cons_flush();
		ch = r_cons_readchar();
		ch = r_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char

		switch(ch) {
		case 'j':
			option++;
			break;
		case 'k':
			if (--option<0)
				option = 0;
			break;
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
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (menu == 1) {
				if (fs2 != NULL)
					config_visual_hit (core, fs2);
			} else {
				r_flag_space_set (core->flags, fs);
				menu = 1;
				_option = option;
				option = 0;
			}
			break;
		case '?':
			r_cons_clear00();
			r_cons_printf("\nVe: Visual Eval help:\n\n");
			r_cons_printf(" q     - quit menu\n");
			r_cons_printf(" j/k   - down/up keys\n");
			r_cons_printf(" h/b   - go back\n");
			r_cons_printf(" e/' ' - edit/toggle current variable\n");
			r_cons_printf(" +/-   - increase/decrease numeric value\n");
			r_cons_printf(" :     - enter command\n");
			r_cons_flush();
			r_cons_any_key();
			break;
		case ':':
			r_cons_set_raw(0);
/* WTF READLINE?? WE DONT USE THAT!! */
#if HAVE_LIB_READLINE
			{
			char *ptr = readline(VISUAL_PROMPT);
			if (ptr) {
				strncpy(cmd, ptr, sizeof (cmd));
				r_core_cmd(core, cmd, 1);
				free(ptr);
			}
			}
#else
			cmd[0]='\0';
			//dl_prompt = ":> ";
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) <0)
				cmd[0]='\0';
			//line[strlen(line)-1]='\0';
			r_core_cmd (core, cmd, 1);
#endif
			r_cons_set_raw (1);
			if (cmd[0])
				r_cons_any_key ();
			//r_cons_gotoxy(0,0);
			r_cons_clear00 ();
			continue;
		}
	}
}

#if 1
static void var_index_show(RAnal *anal, RAnalFcn *fcn, ut64 addr, int idx) {
	int i = 0;
	RAnalVar *v;
	RAnalVarAccess *x;
	RListIter *iter, *iter2;
	int window = 15;
	int wdelta = (idx>5)?idx-5:0;
	if (!fcn)
		return;
	r_list_foreach(fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			if (i>=wdelta) {
				if (i> window+wdelta) {
					r_cons_printf("...\n");
					break;
				}
				if (idx == i) r_cons_printf(" * ");
				else r_cons_printf("   ");
				r_cons_printf("0x%08llx - 0x%08llx type=%s type=%s name=%s delta=%d array=%d\n",
					v->addr, v->eaddr, r_anal_var_type_to_str (anal, v->type),
					v->vartype, v->name, v->delta, v->array);
				r_list_foreach(v->accesses, iter2, x) {
					r_cons_printf("  0x%08llx %s\n", x->addr, x->set?"set":"get");
				}
			}
			i++;
		}
	}
}

// helper
static ut64 var_functions_show(RCore *core, int idx) {
	const char *mark = "";//nullstr;
	int i = 0;
	ut64 seek = core->offset;
	ut64 addr = core->offset;
	int window = 15;
	int wdelta = (idx>5)?idx-5:0;
	RListIter *iter;
	RAnalFcn *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (i>=wdelta) {
			if (i> window+wdelta) {
				r_cons_printf("...\n");
				break;
			}
			if (seek > fcn->addr && seek < fcn->addr+fcn->size)
				mark = "<SEEK IS HERE>";
			else mark = "";
			if (idx == i)
				addr = fcn->addr;
			r_cons_printf (" %c 0x%08llx (%s) %s\n", (idx==i)?'*':' ',
				fcn->addr, fcn->name, mark);
		}
		i++;
	}
	return addr;
}
/* Like emenu but for real */
R_API void r_core_visual_anal(RCore *core) {
	int option = 0;
	int _option = 0;
	int ch, level = 0;
	char old[1024];
	ut64 size, addr = core->offset;
	old[0]='\0';
	RAnalFcn *fcn = r_anal_fcn_find (core->anal, core->offset);

	for(;;) {
		r_cons_gotoxy(0,0);
		r_cons_clear();
		r_cons_printf("Visual code analysis manipulation\n");
		switch(level) {
		case 0:
			r_cons_printf("-[ functions ]------------------- \n"
				"(a) add       (x)xrefs       (q)quit\n"
				"(m) modify    (c)calls       (g)go\n"
				"(d) delete    (v)variables\n");
			addr = var_functions_show(core, option);
			break;
		case 1:
			r_cons_printf("-[ variables ]------------------- 0x%08llx\n"
				"(a) add       (x)xrefs       (q)quit\n"
				"(m) modify    (c)calls       (g)go\n"
				"(d) delete    (v)variables\n", addr);
			var_index_show(core->anal, fcn, addr, option);
			break;
		case 2:
			r_cons_printf("-[ calls ]----------------------- 0x%08llx (TODO)\n", addr);
#if 0
			sprintf(old, "aCf@0x%08llx", addr);
			cons_flush();
			radare_cmd(old, 0);
#endif
			break;
		case 3:
			r_cons_printf("-[ xrefs ]----------------------- 0x%08llx\n", addr);
			sprintf(old, "arl~0x%08llx", addr);
			r_core_cmd0 (core, old);
			//cons_printf("\n");
			break;
		}
		r_cons_flush();
// show indexable vars
		ch = r_cons_readchar();
		ch = r_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch(ch) {
		case 'a':
			switch(level) {
			case 0:
				r_cons_set_raw(0);
				printf("Address: ");
				fflush(stdout);
				if (!fgets(old, sizeof(old), stdin)) break;
				old[strlen(old)-1] = 0;
				if (!old[0]) break;
				addr = r_num_math(core->num, old);
				printf("Size: ");
				fflush(stdout);
				if (!fgets(old, sizeof(old), stdin)) break;
				old[strlen(old)-1] = 0;
				if (!old[0]) break;
				size = r_num_math(core->num, old);
				printf("Name: ");
				fflush(stdout);
				if (!fgets(old, sizeof(old), stdin)) break;
				old[strlen(old)-1] = 0;
				r_flag_set(core->flags, old, addr, 0, 0);
				//XXX sprintf(cmd, "CF %lld @ 0x%08llx", size, addr);
				// XXX r_core_cmd0(core, cmd);
				r_cons_set_raw(1);
				break;
			case 1:
				break;
			}
			break;
		case 'd':
			switch(level) {
			case 0:
				eprintf ("TODO\n");
				//data_del(addr, DATA_FUN, 0);
				// XXX correcly remove all the data contained inside the size of the function
				//flag_remove_at(addr);
				break;
			}
			break;
		case 'x':
			level = 3;
			break;
		case 'c':
			level = 2;
			break;
		case 'v':
			level = 1;
			break;
		case 'j':
			option++;
			break;
		case 'k':
			if (--option<0)
				option = 0;
			break;
		case 'g': // go!
			r_core_seek (core, addr, SEEK_SET);
			return;
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
				return;
			level = 0;
			break;
		}
	}
}
#endif


R_API void r_core_visual_define (RCore *core) {
	int ch;
	ut64 off = core->offset;
	if (core->print->cur_enabled)
		off += core->print->cur;
	r_cons_printf ("Define current block as:\n"
		" d  - set as data\n"
		" c  - set as code\n"
		" s  - set string\n"
		" f  - analyze function\n"
		" u  - undefine metadata here\n"
		" q  - quit/cancel operation\n"
		"TODO: add support for data, string, code ..\n");
	r_cons_flush ();

	// get ESC+char, return 'hjkl' char
	ch = r_cons_arrow_to_hjkl (r_cons_readchar ());

	switch (ch) {
	case 's':
		// detect type of string
		// find EOS
		// capture string value
		r_meta_add (core->meta, R_META_STRING, off, off+core->blocksize, "");
		break;
	case 'd': // TODO: check
		r_meta_add (core->meta, R_META_DATA, off, off+core->blocksize, "");
		break;
	case 'c': // TODO: check 
		r_meta_add (core->meta, R_META_CODE, off, off+core->blocksize, "");
		break;
	case 'u':
		r_meta_del (core->meta, R_META_ANY, off, 1, "");
		r_flag_unset_i (core->flags, off);
		break;
	case 'f':
		r_core_cmd (core, "af", 0);
		r_core_cmd (core, "ab", 0);
		break;
	case 'q':
	default:
		break;
	}
}

/* TODO: use r_cmd here in core->vcmd..optimize over 255 table */ 
R_API int r_core_visual_cmd(RCore *core, int ch) {
	char buf[1024];
	ch = r_cons_arrow_to_hjkl (ch);

	// do we need hotkeys for data references? not only calls?
	if (ch>='0'&&ch<='9') {
		if (core->reflines2) {
			struct list_head *pos;
			int n = ch-'0';
			list_for_each (pos, &core->reflines2->list) {
				RAnalRefline *r = list_entry (pos, RAnalRefline, list);
				if (!--n) {
					r_core_seek (core, r->to, 1);
					r_io_sundo_push (core->io);
					break;
				}
			}
		}
	} else
	switch (ch) {
	case 'c':
		// XXX dupped flag imho
		curset ^= 1;
		if (curset) flags|=R_PRINT_FLAGS_CURSOR; 
		else flags &= ~(flags&R_PRINT_FLAGS_CURSOR);
		r_print_set_flags (core->print, flags);
		break;
	case 'd':
		r_core_visual_define (core);
		break;
	case 'C':
		color ^= 1;
		if (color) flags |= R_PRINT_FLAGS_COLOR;
		else flags &= ~(flags&R_PRINT_FLAGS_COLOR);
		r_config_set_i (core->config, "scr.color", color);
		r_print_set_flags (core->print, flags);
		break;
	case 'a':
		r_cons_printf ("Enter assembler opcodes separated with ';':\n");
		r_cons_flush ();
		r_cons_set_raw (R_FALSE);
		strcpy (buf, "wa ");
		if (r_cons_fgets (buf+3, 1000, 0, NULL) <0) buf[0]='\0';
		if (buf[0]) {
			if (curset) r_core_seek (core, core->offset + cursor, 0);
			r_core_cmd (core, buf, R_TRUE);
			if (curset) r_core_seek (core, core->offset - cursor, 1);
		}
		r_cons_set_raw (R_TRUE);
		break;
	case 'w':
		r_cons_printf ("Enter hexpair string to write:\n");
		r_cons_flush ();
		r_cons_set_raw (0);
		strcpy (buf, "wx ");
		if (r_cons_fgets (buf+3, 1000, 0, NULL) <0) buf[0]='\0';
		if (buf[0]) {
			if (curset) r_core_seek(core, core->offset + cursor, 0);
			r_core_cmd(core, buf, 1);
			if (curset) r_core_seek(core, core->offset - cursor, 1);
		}
		r_cons_set_raw(1);
		break;
	/* select */
	case 'H':
		if (curset) {
			if (ocursor==-1) ocursor=cursor;
			cursor--;
		} else r_core_cmd (core, "s-2", 0);
		break;
	case 'e':
		r_core_visual_config (core);
		break;
	case 't':
		r_core_visual_trackflags (core);
		break;
	case 'v':
		r_core_visual_anal (core);
		break;
	case 'J':
		if (curset) {
			if (ocursor==-1) ocursor = cursor;
			cursor += 16;
		} else r_core_cmd (core, "s++", 0);
		break;
	case 'g':
		r_core_cmd (core, "s 0", 0);
		break;
	case 'G':
		r_core_seek (core, core->file->size-core->blocksize, 1);
		r_io_sundo_push (core->io);
		//r_core_cmd(core, "s 0", 0);
		break;
	case 'K':
		if (curset) {
			if (ocursor==-1) ocursor=cursor;
			cursor -= 16;
		} else r_core_cmd (core, "s--", 0);
		break;
	case 'L':
		if (curset) {
			if (ocursor==-1) ocursor=cursor;
			cursor++;
		} else r_core_cmd (core, "s+2", 0);
		break;
	/* move */
	case 'h':
		if (curset) {
			cursor--;
			ocursor=-1;
		} else r_core_cmd (core, "s-1", 0);
		break;
	case 'l':
		if (curset) {
			cursor++;
			ocursor=-1;
		} else r_core_cmd (core, "s+1", 0);
		break;
	case 'u':
		if (r_io_sundo (core->io))
			r_core_seek (core, core->io->off, 1);
		break;
	case 'U':
		if (r_io_sundo_redo (core->io))
			r_core_seek (core, core->io->off, 1);
		break;
	case 'j':
		if (curset) {
			cursor+=16;
			ocursor=-1;
		} else {
			if (printidx==1)
				r_core_cmd (core, "s+ 8", 0);
			else r_core_cmd (core, "s+ 16", 0);
		}
		break;
	case 'k':
		if (curset) {
			cursor-=16;
			ocursor=-1;
		} else r_core_cmd (core, (printidx==1)?"s- 8":"s- 16", 0);
		break;
	case 's':
		r_core_cmd (core, "ds", 0);
		r_core_cmd (core, ".dr*", 0);
		//r_core_cmd(core, "s eip", 0);
		break;
	case 'S':
		r_core_cmd (core, "dso", 0);
		r_core_cmd (core, ".dr*", 0);
		//r_core_cmd(core, "s eip", 0);
		break;
	case 'p':
		printidx++;
		break;
	case 'P':
		printidx--;
		break;
	case 'm':
		r_core_visual_mark (core, r_cons_readchar());
		break;
	case '\'':
		r_core_visual_mark_seek (core, r_cons_readchar());
		break;
	case 'y':
		if (ocursor==-1) r_core_yank (core, core->offset+cursor, 1);
		else r_core_yank (core, core->offset+((ocursor<cursor)?ocursor:cursor), R_ABS (cursor-ocursor)+1);
		break;
	case 'Y':
		if (core->yank) r_core_yank_paste (core, core->offset+cursor, 0);
		else {
			r_cons_printf ("Can't paste, clipboard is empty.\n");
			r_cons_flush ();
			r_cons_any_key ();
		}
		break;
	case '-':
		if (core->print->cur_enabled) {
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			if (ocursor==-1) sprintf (buf, "wos 01 @ $$+%i:1",cursor);
			else sprintf (buf, "wos 01 @ $$+%i:%i", cursor<ocursor?cursor:ocursor, R_ABS (ocursor-cursor)+1);
			r_core_cmd (core, buf, 0);
		} else r_core_block_size (core, core->blocksize-1);
		break;
	case '+':
		if (core->print->cur_enabled) {
			int cur = core->print->cur;
			if (cur>=core->blocksize)
				cur = core->print->cur-1;
			if (ocursor==-1) sprintf (buf, "woa 01 @ $$+%i:1",cursor);
			else sprintf (buf, "woa 01 @ $$+%i:%i", cursor<ocursor?cursor:ocursor, R_ABS (ocursor-cursor)+1);
			r_core_cmd (core, buf, 0);
		} else r_core_block_size (core, core->blocksize+1);
		break;
	case '/':
		r_core_block_size (core, core->blocksize-16);
		break;
	case '*':
		r_core_block_size (core, core->blocksize+16);
		break;
	case '>':
		r_core_seek_align (core, core->blocksize, 1);
		r_io_sundo_push (core->io);
		break;
	case '<':
		r_core_seek_align (core, core->blocksize, -1);
		r_io_sundo_push (core->io);
		break;
	case '.':
		r_core_cmd (core, "sr pc", 0); // XXX
		break;
	case ':': {
		ut64 oseek = core->offset;
		if (curset) r_core_seek (core, core->offset+cursor, 1);
		r_cons_fgets (buf, 1023, 0, NULL);
		r_core_cmd (core, buf, 0);
		r_cons_any_key ();
		if (curset) r_core_seek (core, oseek, 1);
		}
		break;
	case ';':
		r_cons_printf ("Enter a comment: (prefix it with '-' to remove)\n");
		r_cons_flush ();
		r_cons_set_raw (0);
		strcpy (buf, "CC 0 ");
		if (r_cons_fgets (buf+5, 1000, 0, NULL) <0)
			buf[0]='\0';
		if (buf[0]) {
			if (curset) r_core_seek (core, core->offset + cursor, 0);
			r_core_cmd (core, buf, 1);
			if (curset) r_core_seek (core, core->offset - cursor, 1);
		}
		r_cons_set_raw (1);
		break;
	case 'x':
		r_core_cmdf (core, "./a 0x%08llx @ entry0", core->offset);
		break;
	case '?':
		r_cons_clear00 ();
		r_cons_printf (
		"\nVisual mode help:\n\n"
		" >||<    -  seek aligned to block size\n"
		" hjkl    -  move around\n"
		" HJKL    -  move around faster\n"
		" pP      -  rotate print modes\n"
		" /*+-    -  change block size\n"
		" cC      -  toggle cursor and colors\n"
		" d[f?]   -  define function, data, code, ..\n"
		" x       -  find xrefs for current offset\n"
		" sS      -  step / step over\n"
		" uU      -  undo/redo seek\n"
		" yY      -  copy and paste selection\n"
		" mK/'K   -  mark/go to Key (any key)\n"
		" :cmd    -  run radare command\n"
		" ;[-]cmt -  add/remove comment\n"
		" .       -  seek to program counter\n"
		" q       -  back to radare shell\n");
		r_cons_flush ();
		r_cons_any_key ();
		break;
	case 'q':
	case 'Q':
		return R_FALSE;
	}
	return R_TRUE;
}

// TODO: simplify R_ABS(printidx%NPF) into a macro, or just control negative values..
R_API void r_core_visual_prompt(RCore *core, int color) {
	if (cursor<0) cursor = 0;
	if (color) r_cons_strcat (Color_YELLOW);
	if (curset) r_cons_printf ("[0x%08"PFMT64x" %s(%d:%d=%d)]> %s\n", core->offset, core->file->filename,
		cursor, ocursor, ocursor==-1?1:R_ABS (cursor-ocursor)+1, printfmt[R_ABS (printidx%NPF)]);
	else r_cons_printf ("[0x%08"PFMT64x" %s]> %s\n", core->offset, core->file->filename, printfmt[R_ABS (printidx%NPF)]);
	if (color) r_cons_strcat (Color_RESET);
}

R_API int r_core_visual(RCore *core, const char *input) {
	const char *cmdprompt;
	const char *vi;
	ut64 scrseek;
	int ch;

	core->print->cur_enabled = R_FALSE;
	vi = r_config_get (core->config, "cmd.vprompt");
	if (vi) r_core_cmd (core, vi, 0);

	while (input[0]) {
		if (!r_core_visual_cmd (core, input[0])) {
			r_cons_clear00 ();
			r_core_cmd (core, printfmt[R_ABS (printidx%NPF)], 0);
			r_cons_visual_flush ();
			r_cons_any_key ();
			return 0;
		}
		input = input + 1;
	}

	color = r_config_get_i (core->config, "scr.color");
	debug = r_config_get_i (core->config, "cfg.debug");
	flags = R_PRINT_FLAGS_ADDRMOD | R_PRINT_FLAGS_HEADER;
	if (color) flags |= R_PRINT_FLAGS_COLOR;
	do {
		scrseek = r_num_math (core->num, 
			r_config_get (core->config, "scr.seek"));
		if (scrseek != 0LL) {
			r_core_seek (core, scrseek, 1);
			// TODO: read?
		}
		if (debug)
			r_core_cmd (core, ".dr*", 0);
		cmdprompt = r_config_get (core->config, "cmd.vprompt");
		if (cmdprompt && *cmdprompt)
			r_core_cmd (core, cmdprompt, 0);
		r_cons_clear00 ();
		r_print_set_cursor (core->print, curset, ocursor, cursor);
		r_core_visual_prompt (core, color);
		r_core_cmd (core, printfmt[R_ABS (printidx%NPF)], 0);
		r_cons_visual_flush ();
		ch = r_cons_readchar ();
	} while (r_core_visual_cmd (core, ch));

	if (color)
		r_cons_printf (Color_RESET);
	core->print->cur_enabled = R_FALSE;

	return 0;
}
