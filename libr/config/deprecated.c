
/* Like emenu but for real */
void config_visual_menu()
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
		cons_gotoxy(0,0);
		cons_clear();

		/* Execute visual prompt */
		ptr = config_get("cmd.vprompt");
		if (ptr&&ptr[0]) {
			int tmp = last_print_format;
			radare_cmd_raw(ptr, 0);
			last_print_format = tmp;
		}

		if (fs&&!memcmp(fs, "asm.", 4))
			radare_cmd_raw("pd 5", 0);

		switch(menu) {
			case 0: // flag space
				cons_printf("\n Eval spaces:\n\n");
				hit = 0;
				j = i = 0;
				list_for_each(pos, &(config_new.nodes)) {
					struct config_node_t *bt = list_entry(pos, struct config_node_t, list);
					if (option==i) {
						fs = bt->name;
						hit = 1;
					}
					show = 0;
					if (old[0]=='\0') {
						strccpy(old, bt->name, '.');
						show = 1;
					} else if (strccmp(old, bt->name, '.')) {
						strccpy(old, bt->name, '.');
						show = 1;
					}

					if (show) {
						if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
							cons_printf(" %c  %s\n", (option==i)?'>':' ', old);
							j++;
						}
						i++;
					}
				}
				if (!hit && j>0) {
					option = j-1;
					continue;
				}
				cons_printf("\n Sel:%s \n\n", fs);
				break;
			case 1: // flag selection
				cons_printf("\n Eval variables: (%s)\n\n", fs);
				hit = 0;
				j = i = 0;
				// TODO: cut -d '.' -f 1 | sort | uniq !!!
				list_for_each(pos, &(config_new.nodes)) {
					struct config_node_t *bt = list_entry(pos, struct config_node_t, list);
					if (option==i) {
						fs2 = bt->name;
						hit = 1;
					}
					if (!strccmp(bt->name, fs, '.')) {
						if( (i >=option-delta) && ((i<option+delta)||((option<delta)&&(i<(delta<<1))))) {
							// TODO: Better align
							cons_printf(" %c  %s = %s\n", (option==i)?'>':' ', bt->name, bt->value);
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
					cons_printf("\n Selected: %s\n\n", fs2);
		}
		cons_flush();
		ch = cons_readchar();
		ch = cons_get_arrow(ch); // get ESC+char, return 'hjkl' char
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
					config_visual_hit_i(fs2, +1);
				continue;
			case '/':
			case '-':
				if (fs2 != NULL)
					config_visual_hit_i(fs2, -1);
				continue;
			case 'l':
			case 'e': // edit value
			case ' ':
			case '\r':
			case '\n': // never happens
				if (menu == 1) {
					if (fs2 != NULL)
						config_visual_hit(fs2);
				} else {
					flag_space_set(fs);
					menu = 1;
					_option = option;
					option = 0;
				}
				break;
			case '?':
				cons_clear00();
				cons_printf("\nVe: Visual Eval help:\n\n");
				cons_printf(" q     - quit menu\n");
				cons_printf(" j/k   - down/up keys\n");
				cons_printf(" h/b   - go back\n");
				cons_printf(" e/' ' - edit/toggle current variable\n");
				cons_printf(" +/-   - increase/decrease numeric value\n");
				cons_printf(" :     - enter command\n");
				cons_flush();
				cons_any_key();
				break;
			case ':':
				cons_set_raw (0);
#if HAVE_LIB_READLINE
				char *ptr = readline (VISUAL_PROMPT);
				if (ptr) {
					strncpy (cmd, ptr, sizeof (cmd)-1);
					radare_cmd (cmd, 1);
					free (ptr);
				}
#else
				cmd[0]='\0';
				dl_prompt = ":> ";
				if (cons_fgets(cmd, 1000, 0, NULL) <0)
					cmd[0]='\0';
				//line[strlen(line)-1]='\0';
				radare_cmd(cmd, 1);
#endif
				cons_set_raw(1);
				if (cmd[0])
					cons_any_key();
				cons_gotoxy(0,0);
				cons_clear();
				continue;
		}
	}
}


/* Visually activate the config variable */
void config_visual_hit(const char *name)
{
	char buf[1024];
	struct config_node_t *node;
	node = config_node_get(name);
	if (node) {
		if (node->flags & CN_BOOL) {
			/* TOGGLE */
			node->i_value = !node->i_value;
			node->value = estrdup(node->value, node->i_value?"true":"false");
		} else {
			// FGETS AND SO
			cons_printf("New value (old=%s): ", node->value);
			cons_flush();
			cons_set_raw(0);
			cons_fgets(buf, 1023, 0, 0);
			cons_set_raw(1);
			node->value = estrdup(node->value, buf);
		}
	}
}
