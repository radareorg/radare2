/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"

#define NPF 6
static int printidx = 0;
const char *printfmt[] = { "x", "pd", "p8", "pc", "ps", "s esp&&x 64&&dr&&s eip&&pd" };

static int curset = 0, cursor = -1, ocursor=-1;
static int color = 1;
static int flags = R_PRINT_FLAGS_ADDRMOD;

static int marks_init = 0;
static u64 marks[256];

static void r_core_visual_mark(struct r_core_t *core, u8 ch)
{
	if (marks_init==0) {
		int i;
		for(i=0;i<255;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	marks[ch] = core->seek;
}

static void r_core_visual_mark_seek(struct r_core_t *core, u8 ch)
{
	if (marks_init==0) {
		int i;
		for(i=0;i<255;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	if (marks[ch])
		r_core_seek(core, marks[ch]);
}

R_API int r_core_visual_trackflags(struct r_core_t *core)
{
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

	while(1) {
		r_cons_gotoxy(0,0);
		r_cons_clear();
		/* Execute visual prompt */
		ptr = r_config_get(&core->config, "cmd.vprompt");
		if (ptr&&ptr[0]) {
			//int tmp = 0; //last_print_format;
			r_core_cmd(core, ptr, 0);
			//last_print_format = tmp;
		}

		switch(menu) {
		case 0: // flag space
			r_cons_printf("\n Flag spaces:\n\n");
			hit = 0;
			for(j=i=0;i<R_FLAG_SPACES_MAX;i++) {
				if (core->flags.space[i]) {
					if (option==i) {
						fs = core->flags.space[i];
						hit = 1;
					}
					if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
						r_cons_printf(" %c %02d %c %s\n",
						(option==i)?'>':' ', j, 
						(i==core->flags.space_idx)?'*':' ',
						core->flags.space[i]);
						j++;
					}
				}
			}
			if (!hit && j>0) {
				option = j-1;
				continue;
			}
			break;
		case 1: // flag selection
			r_cons_printf("\n Flags in flagspace '%s'. Press '?' for help.\n\n",
				core->flags.space[core->flags.space_idx]);
			hit = 0;
			i = j = 0;
			list_for_each(pos, &core->flags.flags) {
				struct r_flag_item_t *flag = (struct r_flag_item_t *)
					list_entry(pos, struct r_flag_item_t, list);
				/* filter per flag spaces */
				if ((core->flags.space_idx != -1) && 
					(flag->space != core->flags.space_idx))
					continue;
				if (option==i) {
					fs2 = flag->name;
					hit = 1;
				}
				if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
					r_cons_printf(" %c  %03d 0x%08llx %4lld %s\n",
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
			r_cons_printf("\n Selected: %s\n\n", fs2);

			switch(format) {
			case 0: sprintf(cmd, "px @ %s", fs2); break;
			case 1: sprintf(cmd, "pd @ %s", fs2); break;
			case 2: sprintf(cmd, "ps @ %s", fs2); break;
			default: format = 0; continue;
			}
#if 0
			/* TODO: auto seek + print + disasm + string ...analyze stuff and proper print */
			cmd[0]='\0';
			if (strstr(fs2, "str_")) {
				sprintf(cmd, "pz @ %s", fs2);
			} else
			if (strstr(fs2, "sym_")) {
				sprintf(cmd, "pd @ %s", fs2);
			} else
				sprintf(cmd, "px @ %s", fs2);
#endif
			if (cmd[0])
				r_core_cmd(core, cmd, 0);
		}
		r_cons_flush();
		ch = r_cons_readchar();
		ch = r_cons_get_arrow(ch); // get ESC+char, return 'hjkl' char
		switch(ch) {
		case 'J':
			option+=10;
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
			switch(menu) {
			case 0: // new flag space
				break;
			case 1: // new flag
				break;
			}
			break;
		case 'd':
			r_flag_unset(&core->flags, fs2);
			break;
		case 'e':
			/* TODO: prompt for addr, size, name */
			break;
		case 'q':
			if (menu<=0) return R_TRUE; menu--;
			break;
		case '*':
		case '+':
			r_core_block_size(core, core->blocksize+1);
			break;
		case '/':
		case '-':
			r_core_block_size(core, core->blocksize-1);
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
				sprintf(cmd, "s %s", fs2);
				r_core_cmd(core, cmd, 0);
				return R_TRUE;
			}
			r_flag_space_set(&core->flags, fs);
			menu = 1;
			_option = option;
			option = 0;
			break;
		case '?':
			r_cons_clear00();
			r_cons_printf("\nVt: Visual Track help:\n\n");
			r_cons_printf(" q     - quit menu\n");
			r_cons_printf(" j/k   - down/up keys\n");
			r_cons_printf(" h/b   - go back\n");
			r_cons_printf(" l/' ' - accept current selection\n");
			r_cons_printf(" a/d/e - add/delete/edit flag\n");
			r_cons_printf(" +/-   - increase/decrease block size\n");
			r_cons_printf(" p/P   - rotate print format\n");
			r_cons_printf(" :     - enter command\n");
			r_cons_flush();
			r_cons_any_key();
			break;
		case ':':
			r_cons_set_raw(0);
#if HAVE_LIB_READLINE
			char *ptr = (char *)readline(VISUAL_PROMPT);
			if (ptr) {
				strncpy(cmd, ptr, sizeof(cmd));
				r_core_cmd(core, cmd, 1);
				//commands_parse(line);
				free(ptr);
			}
#else
			cmd[0]='\0';
			//dl_prompt = ":> ";
			if (r_cons_fgets(cmd, 1000, 0, NULL) <0)
				cmd[0]='\0';
			//line[strlen(line)-1]='\0';
			r_core_cmd(core, cmd, 1);
#endif
			r_cons_set_raw(1);
			if (cmd[0])
				r_cons_any_key();
			//cons_gotoxy(0,0);
			r_cons_clear();
			continue;
		}
	}
	return R_TRUE;
}

static void config_visual_hit_i(struct r_core_t *core, const char *name, int delta)
{
	struct r_config_node_t *node;
	node = r_config_node_get(&core->config, name);
	if (node && ((node->flags & CN_INT) || (node->flags & CN_OFFT)))
		r_config_set_i(&core->config, name, r_config_get_i(&core->config, name)+delta);
}

/* Visually activate the config variable */
static void config_visual_hit(struct r_core_t *core, const char *name)
{
	char buf[1024];
	struct r_config_node_t *node;

	node = r_config_node_get(&core->config, name);
	if (node) {
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
}

R_API void r_core_visual_config(struct r_core_t *core)
{
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

	while(1) {
		r_cons_gotoxy(0,0);
		r_cons_clear();

		/* Execute visual prompt */
		ptr = r_config_get(&core->config, "cmd.vprompt");
		if (ptr&&ptr[0]) {
//			int tmp = last_print_format;
			r_core_cmd(core, ptr, 0);
//			last_print_format = tmp;
		}

		if (fs&&!memcmp(fs, "asm.", 4))
			r_core_cmd(core, "pd 5", 0);

		switch(menu) {
			case 0: // flag space
				r_cons_printf("\n Eval spaces:\n\n");
				hit = 0;
				j = i = 0;
				list_for_each(pos, &(core->config.nodes)) {
					struct r_config_node_t *bt = list_entry(pos, struct r_config_node_t, list);
					if (option==i) {
						fs = bt->name;
						hit = 1;
					}
					show = 0;
					if (old[0]=='\0') {
						r_str_ccpy(old, bt->name, '.');
						show = 1;
					} else if (r_str_ccmp(old, bt->name, '.')) {
						r_str_ccpy(old, bt->name, '.');
						show = 1;
					}

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
				list_for_each(pos, &(core->config.nodes)) {
					struct r_config_node_t *bt = list_entry(pos, struct r_config_node_t, list);
					if (option==i) {
						fs2 = bt->name;
						hit = 1;
					}
					if (!r_str_ccmp(bt->name, fs, '.')) {
						if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
							// TODO: Better align
							r_cons_printf(" %c  %s = %s\n", (option==i)?'>':' ', bt->name, bt->value);
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
		ch = r_cons_get_arrow(ch); // get ESC+char, return 'hjkl' char

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
				config_visual_hit_i(core, fs2, +1);
			continue;
		case '/':
		case '-':
			if (fs2 != NULL)
				config_visual_hit_i(core, fs2, -1);
			continue;
		case 'l':
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (menu == 1) {
				if (fs2 != NULL)
					config_visual_hit(core, fs2);
			} else {
				r_flag_space_set(&core->flags, fs);
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
#if HAVE_LIB_READLINE
			char *ptr = readline(VISUAL_PROMPT);
			if (ptr) {
				strncpy(cmd, ptr, sizeof(cmd));
				r_core_cmd(core, cmd, 1);
				free(ptr);
			}
#else
			cmd[0]='\0';
			//dl_prompt = ":> ";
			if (r_cons_fgets(cmd, 1000, 0, NULL) <0)
				cmd[0]='\0';
			//line[strlen(line)-1]='\0';
			r_core_cmd(core, cmd, 1);
#endif
			r_cons_set_raw(1);
			if (cmd[0])
				r_cons_any_key();
			//r_cons_gotoxy(0,0);
			r_cons_clear00();
			continue;
		}
	}
}

/* TODO: use r_cmd here in core->vcmd..optimize over 255 table */ 
R_API int r_core_visual_cmd(struct r_core_t *core, int ch)
{
	char buf[1024];

	switch(ch) {
	case 'c':
		curset ^= 1;
		if (curset) flags|=R_PRINT_FLAGS_CURSOR; // XXX dupped flag imho
		else flags &= !(flags&R_PRINT_FLAGS_CURSOR);
		r_print_set_flags(&core->print, flags);
		break;
	case 'C':
		color ^= 1;
		if (color) flags|=R_PRINT_FLAGS_COLOR;
		else flags &= !(flags&R_PRINT_FLAGS_COLOR);
		r_print_set_flags(&core->print, flags);
		break;
	/* select */
	case 'H':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor--;
		} else
		r_core_cmd(core, "s-2", 0);
		break;
	case 'e':
		r_core_visual_config(core);
		break;
	case 't':
		r_core_visual_trackflags(core);
		break;
	case 'J':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor+=16;
		} else
		r_core_cmd(core, "s++", 0);
		break;
	case 'g':
		r_core_cmd(core, "s 0", 0);
		break;
	case 'G':
		// TODO: seek to file size
		//r_core_cmd(core, "s 0", 0);
		break;
	case 'K':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor-=16;
		} else
		r_core_cmd(core, "s--", 0);
		break;
	case 'L':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor++;
		} else
		r_core_cmd(core, "s+2", 0);
		break;
	/* move */
	case 'h':
		if (curset) {
			cursor--;
			ocursor=-1;
		} else r_core_cmd(core, "s-1", 0);
		break;
	case 'l':
		if (curset) {
			cursor++;
			ocursor=-1;
		} else r_core_cmd(core, "s+1", 0);
		break;
	case 'j':
		if (curset) {
			cursor+=16;
			ocursor=-1;
		} else r_core_cmd(core, "s+16", 0);
		break;
	case 'k':
		if (curset) {
			cursor-=16;
			ocursor=-1;
		} else r_core_cmd(core, "s- 16", 0);
		break;
	case 's':
		r_core_cmd(core, "ds", 0);
		r_core_cmd(core, ".dr", 0);
		//r_core_cmd(core, "s eip", 0);
		break;
	case 'p':
		printidx++;
		break;
	case 'P':
		printidx--;
		break;
	case '-':
		r_core_block_size( core, core->blocksize-1);
		break;
	case 'm':
		r_core_visual_mark(core, r_cons_readchar());
		break;
	case '\'':
		r_core_visual_mark_seek(core, r_cons_readchar());
		break;
	case '+':
		r_core_block_size(core, core->blocksize+1);
		break;
	case '/':
		r_core_block_size(core, core->blocksize-=16);
		break;
	case '*':
		r_core_block_size(core, core->blocksize+=16);
		break;
	case '>':
		r_core_seek_align(core, core->blocksize, 1);
		break;
	case '<':
		r_core_seek_align(core, core->blocksize, -1);
		break;
	case ':':
		r_cons_fgets(buf, 1023, 0, NULL);
		r_core_cmd(core, buf, 0);
		break;
	case ';':
		r_cons_printf("Enter a comment: (prefix it with '-' to remove)\n");
		r_cons_flush();
		r_cons_set_raw(0);
		strcpy(buf, "CC ");
		if (r_cons_fgets(buf+3, 1000, 0, NULL) <0)
			buf[0]='\0';
		if (buf[0])
			r_core_cmd(core, buf, 1);
		r_cons_set_raw(1);
		break;
	case '?':
		r_cons_clear00();
		r_cons_printf(
		"\nVisual mode help:\n\n"
		" >||<    -  seek aligned to block size\n"
		" hjkl    -  move around\n"
		" HJKL    -  move around faster\n"
		" P||p    -  rotate print modes\n"
		" /*+-    -  change block size\n"
		" :cmd    -  run radare command\n"
		" ;[-]cmt -  add/remove comment\n"
		" q       -  back to radare shell\n");
		r_cons_flush();
		r_cons_any_key();
		break;
	case 'q':
	case 'Q':
		return 0;
	}
	return 1;
}

R_API void r_core_visual_prompt(struct r_core_t *core)
{
	r_cons_printf("[0x%08llx] %s\n", core->seek, printfmt[printidx%NPF]);
}

R_API int r_core_visual(struct r_core_t *core, const char *input)
{
	const char *cmdprompt;
	const char *vi;
	u64 scrseek;
	int ch;

	vi = r_config_get(&core->config, "cmd.visual");
	if (vi) r_core_cmd(core, vi, 0);

	while(input[0]) {
		if (!r_core_visual_cmd(core, input[0])) {
			r_cons_clear00();
			r_core_cmd(core, printfmt[printidx%NPF], 0);
			r_cons_flush();
			r_cons_any_key();
			return 0;
		}
		input = input + 1;
	}

	color = r_config_get_i(&core->config, "scr.color");
	do {
		scrseek = r_num_math(&core->num, 
			r_config_get(&core->config, "scr.seek"));
		if (scrseek != 0LL) {
			r_core_seek (core, scrseek);
			// TODO: read?
		}
		cmdprompt = r_config_get (&core->config, "cmd.vprompt");
		if (cmdprompt && cmdprompt[0])
			r_core_cmd(core, cmdprompt, 0);
		r_cons_clear00();
		r_print_set_cursor(&core->print, curset, ocursor, cursor);
		r_core_visual_prompt(core);
		r_core_cmd(core, printfmt[printidx%NPF], 0);
		r_cons_flush();
		ch = r_cons_readchar();
	} while (r_core_visual_cmd(core, ch));

	return 0;
}
