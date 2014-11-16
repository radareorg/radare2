/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_cmd.h>
#include <r_util.h>
#include <stdio.h>
#include <r_cons.h>
#include <r_cmd.h>
#include <r_util.h>

static int value = 0;

#define NCMDS (sizeof (cmd->cmds)/sizeof(*cmd->cmds))
R_LIB_VERSION (r_cmd);

R_API void r_cmd_alias_init(RCmd *cmd) {
	cmd->aliases.count = 0;
	cmd->aliases.keys = NULL;
	cmd->aliases.values = NULL;
}

R_API RCmd *r_cmd_new () {
	int i;
	RCmd *cmd = R_NEW (RCmd);
	if (!cmd) return cmd;

	cmd->lcmds = r_list_new ();
	for (i=0;i<NCMDS;i++)
		cmd->cmds[i] = NULL;
	cmd->nullcallback = cmd->data = NULL;
	r_core_plugin_init (cmd);
	r_cmd_macro_init (&cmd->macro);
	r_cmd_alias_init (cmd);
	return cmd;
}

R_API RCmd *r_cmd_free(RCmd *cmd) {
	int i;
	if (!cmd) return NULL;
	r_cmd_alias_free (cmd);
	// dinitialize plugin commands
	r_core_plugin_deinit(cmd);
	r_list_free (cmd->plist);
	r_list_free (cmd->lcmds);
	for (i=0;i<NCMDS;i++)
		if (cmd->cmds[i])
			R_FREE (cmd->cmds[i]);
	free (cmd);
	return NULL;
}

R_API char **r_cmd_alias_keys(RCmd *cmd, int *sz) {
	if (sz) *sz = cmd->aliases.count;
	return cmd->aliases.keys;
}

R_API void r_cmd_alias_free (RCmd *cmd) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		free (cmd->aliases.keys[i]);
		free (cmd->aliases.values[i]);
	}
	cmd->aliases.count = 0;
	free (cmd->aliases.keys);
	free (cmd->aliases.values);
	cmd->aliases.keys = NULL;
	cmd->aliases.values = NULL;
}

R_API int r_cmd_alias_del (RCmd *cmd, const char *k) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		if (!strcmp (k, cmd->aliases.keys[i])) {
			free (cmd->aliases.values[i]);
			cmd->aliases.values[i] = NULL;
			cmd->aliases.count--;
			if (cmd->aliases.count>0) {
				if (i>0) {
					free (cmd->aliases.keys[i]);
					cmd->aliases.keys[i] = cmd->aliases.keys[0];
					free (cmd->aliases.values[i]);
					cmd->aliases.values[i] = cmd->aliases.values[0];
				}
				memmove (cmd->aliases.values,
					cmd->aliases.values+1,
					cmd->aliases.count*sizeof (void*));
				memmove (cmd->aliases.keys,
					cmd->aliases.keys+1,
					cmd->aliases.count*sizeof (void*));
			}
			return 1;
		}
	}
	return 0;
}

R_API int r_cmd_alias_set (RCmd *cmd, const char *k, const char *v) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		if (!strcmp (k, cmd->aliases.keys[i])) {
			free (cmd->aliases.values[i]);
			cmd->aliases.values[i] = strdup (v);
			return 1;
		}
	}
	// new
	i = cmd->aliases.count++;
	cmd->aliases.keys = (char **)realloc (cmd->aliases.keys,
		sizeof (char**)*cmd->aliases.count);
	cmd->aliases.values = (char **)realloc (cmd->aliases.values,
		sizeof (char**)*cmd->aliases.count);
	cmd->aliases.keys[i] = strdup (k);
	cmd->aliases.values[i] = strdup (v);
	return 0;
}

R_API char *r_cmd_alias_get (RCmd *cmd, const char *k) {
	int i; // find
	for (i=0; i<cmd->aliases.count; i++) {
		if (!strcmp (k, cmd->aliases.keys[i]))
			return cmd->aliases.values[i];
	}
	return NULL;
}

R_API int r_cmd_set_data(RCmd *cmd, void *data) {
	cmd->data = data;
	return 1;
}

R_API int r_cmd_add_long(RCmd *cmd, const char *lcmd, const char *scmd, const char *desc) {
	RCmdLongItem *item = R_NEW (RCmdLongItem);
	if (item == NULL)
		return R_FALSE;
	strncpy (item->cmd, lcmd, sizeof (item->cmd)-1);
	strncpy (item->cmd_short, scmd, sizeof (item->cmd_short)-1);
	item->cmd_len = strlen (lcmd);
	strncpy (item->desc, desc, sizeof (item->desc)-1);
	r_list_append (cmd->lcmds, item);
	return R_TRUE;
}

R_API int r_cmd_add(RCmd *c, const char *cmd, const char *desc, r_cmd_callback(cb)) {
	struct r_cmd_item_t *item;
	int idx = (ut8)cmd[0];

	item = c->cmds[idx];
	if (item == NULL) {
		item = R_NEW (RCmdItem);
		c->cmds[idx] = item;
	}
	strncpy (item->cmd, cmd, sizeof (item->cmd)-1);
	strncpy (item->desc, desc, sizeof (item->desc)-1);
	item->callback = cb;
	return R_TRUE;
}

R_API int r_cmd_del(RCmd *cmd, const char *command) {
	int idx = (ut8)command[0];
	free(cmd->cmds[idx]);
	cmd->cmds[idx] = NULL;
	return 0;
}

R_API int r_cmd_call(RCmd *cmd, const char *input) {
	struct r_cmd_item_t *c;
	int ret = -1;
	RListIter *iter;
	RCorePlugin *cp;
	if (!input || !*input) {
		if (cmd->nullcallback != NULL)
			ret = cmd->nullcallback (cmd->data);
	} else {
		r_list_foreach (cmd->plist, iter, cp) {
			if (cp->call (cmd->data, input))
				return R_TRUE;
		}
		c = cmd->cmds[(ut8)input[0]];
		if (c && c->callback)
			ret = c->callback (cmd->data, input+1);
		else ret = -1;
	}
	return ret;
}

R_API int r_cmd_call_long(RCmd *cmd, const char *input) {
	char *inp;
	RListIter *iter;
	RCmdLongItem *c;
	int ret, inplen = strlen (input)+1;

	r_list_foreach (cmd->lcmds, iter, c) {
		if (inplen>=c->cmd_len && !r_str_cmp (input, c->cmd, c->cmd_len)) {
			int lcmd = strlen (c->cmd_short);
			int linp = strlen (input+c->cmd_len);
			/// SLOW malloc on most situations. use stack
			inp = malloc (lcmd+linp+2); // TODO: use static buffer with R_CMD_MAXLEN
			if (inp == NULL)
				return -1;
			memcpy (inp, c->cmd_short, lcmd);
			memcpy (inp+lcmd, input+c->cmd_len, linp+1);
			ret = r_cmd_call (cmd, inp);
			free (inp);
			return ret;
		}
	}
	return -1;
}

/** macro.c **/

R_API void r_cmd_macro_init(RCmdMacro *mac) {
	mac->counter = 0;
	mac->_brk_value = 0;
	mac->brk_value = &mac->_brk_value;
	mac->printf = (void*)printf;
	mac->num = NULL;
	mac->user = NULL;
	mac->cmd = NULL;
	mac->macros = r_list_new ();
}

// XXX add support single line function definitions
// XXX add support for single name multiple nargs macros
R_API int r_cmd_macro_add(RCmdMacro *mac, const char *oname) {
	struct r_cmd_macro_item_t *macro;
	char *name, *args = NULL;
	//char buf[R_CMD_MAXLEN];
	RCmdMacroItem *m;
	int macro_update;
	RListIter *iter;
	char *pbody;
	// char *bufp;
	char *ptr;
	int lidx;

	if (!*oname) {
		r_cmd_macro_list (mac);
		return 0;
	}

	name = strdup (oname);
	if (name == NULL) {
		perror ("strdup");
		return 0;
	}

	pbody = strchr (name, ',');
	if (pbody) {
		*pbody = '\0';
		pbody++;
	} else {
		eprintf ("Invalid macro body\n");
		free (name);
		return R_FALSE;
	}

	if (name[strlen (name)-1]==')') {
		eprintf ("r_cmd_macro_add: missing macro body?\n");
		free (name);
		return -1;
	}

	macro = NULL;
	ptr = strchr (name, ' ');
	if (ptr) {
		*ptr='\0';
		args = ptr +1;
	}
	macro_update = 0;
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (name, m->name)) {
			macro = m;
	//		free (macro->name);
			free (macro->code);
			free (macro->args);
			macro_update = 1;
			break;
		}
	}
	if (ptr)
		*ptr = ' ';
	if (macro == NULL) {
		macro = (struct r_cmd_macro_item_t *)malloc (
			sizeof (struct r_cmd_macro_item_t));
		macro->name = strdup (name);
	}

	macro->codelen = (pbody[0])? strlen (pbody)+2 : 4096;
	macro->code = (char *)malloc (macro->codelen);
	*macro->code = '\0';
	macro->nargs = 0;
	if (args == NULL)
		args = "";
	macro->args = strdup (args);
	ptr = strchr (macro->name, ' ');
	if (ptr != NULL) {
		*ptr = '\0';
		macro->nargs = r_str_word_set0 (ptr+1);
	}

	if (pbody) {
		for (lidx=0; pbody[lidx]; lidx++) {
			if (pbody[lidx]==',')
				pbody[lidx]='\n';
			else
			if (pbody[lidx]==')' && pbody[lidx-1]=='\n')
				pbody[lidx]='\0';
		}
		strncpy (macro->code, pbody, macro->codelen);
		macro->code[macro->codelen-1] = 0;
		//strcat (macro->code, ",");
#if 0
	} else {
		int lbufp, codelen = 0, nl = 0;
		eprintf ("Reading macro from stdin:\n");
		for (;codelen<R_CMD_MAXLEN;) { // XXX input from mac->fd
#if 0
			if (stdin == r_cons_stdin_fd) {
				mac->printf(".. ");
				fflush(stdout);
			}
			fgets(buf, 1023, r_cons_stdin_fd);
#endif
			fgets (buf, sizeof (buf)-1, stdin);
			if (*buf=='\n' && nl)
				break;
			nl = (*buf == '\n')?1:0;
			if (*buf==')')
				break;
			for (bufp=buf;*bufp==' '||*bufp=='\t';bufp++);
			lidx = strlen (buf)-2;
			lbufp = strlen (bufp);
			if (buf[lidx]==')' && buf[lidx-1]!='(') {
				buf[lidx]='\0';
				memcpy (macro->code+codelen, bufp, lbufp+1);
				break;
			}
			if (*buf != '\n') {
				memcpy (macro->code+codelen, bufp, lbufp+1);
				codelen += lbufp;
			}
		}
#endif
	}
	if (macro_update == 0)
		r_list_append (mac->macros, macro);
	free (name);
	return 0;
}

R_API int r_cmd_macro_rm(RCmdMacro *mac, const char *_name) {
	RListIter *iter;
	RCmdMacroItem *m;
	char *name = strdup (_name);
	char *ptr = strchr (name, ')');
	if (ptr) *ptr = '\0';
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (m->name, name)) {
			r_list_delete (mac->macros, iter);
			eprintf ("Macro '%s' removed.\n", name);
			free (m->name);
			free (m->code);
			free (m);
			free (name);
			return R_TRUE;
		}
	}
	free (name);
	return R_FALSE;
}

// TODO: use mac->printf which is r_cons_printf at the end
R_API void r_cmd_macro_list(RCmdMacro *mac) {
	RCmdMacroItem *m;
	int j, idx = 0;
	RListIter *iter;
	r_list_foreach (mac->macros, iter, m) {
		mac->printf ("%d (%s %s, ", idx, m->name, m->args);
		for (j=0; m->code[j]; j++) {
			if (m->code[j]=='\n')
				mac->printf (", ");
			else mac->printf ("%c", m->code[j]);
		}
		mac->printf (")\n");
		idx++;
	}
}
#if 0
(define name value
  f $0 @ $1)

(define loop cmd
  loop:
  ? $0 == 0
  ?? .loop:
  )

.(define patata 3)
#endif

R_API int r_cmd_macro_cmd_args(RCmdMacro *mac, const char *ptr, const char *args, int nargs) {
	int i, j;
	char *pcmd, cmd[R_CMD_MAXLEN];
	const char *arg = args;

	for (*cmd=i=j=0; j<R_CMD_MAXLEN && ptr[j]; i++,j++) {
		if (ptr[j]=='$') {
			if (ptr[j+1]>='0' && ptr[j+1]<='9') {
				int wordlen;
				int w = ptr[j+1]-'0';
				const char *word = r_str_word_get0 (arg, w);
				if (word && *word) {
					wordlen = strlen (word);
					if ((i+wordlen+1) >= sizeof (cmd))
						return -1;
					memcpy (cmd+i, word, wordlen+1);
					i += wordlen-1;
					j++;
				} else eprintf ("Undefined argument %d\n", w);
			} else
			if (ptr[j+1]=='@') {
				char off[32];
				int offlen;
				offlen = snprintf (off, sizeof (off), "%d",
					mac->counter);
				if ((i+offlen+1) >= sizeof (cmd))
					return -1;
				memcpy (cmd+i, off, offlen+1);
				i += offlen-1;
				j++;
			} else {
				cmd[i] = ptr[j];
				cmd[i+1] = '\0';
			}
		} else {
			cmd[i] = ptr[j];
			cmd[i+1] = '\0';
		}
	}
	for (pcmd = cmd; *pcmd && (*pcmd==' ' || *pcmd == '\t'); pcmd++);
	//eprintf ("-pre %d\n", (int)mac->num->value);
	int xx = (*pcmd==')')? 0: mac->cmd (mac->user, pcmd);
	//eprintf ("-pos %p %d\n", mac->num, (int)mac->num->value);
	return xx;
}

R_API char *r_cmd_macro_label_process(RCmdMacro *mac, RCmdMacroLabel *labels, int *labels_n, char *ptr) {
	int i;
	for (; *ptr==' '; ptr++);
	if (ptr[strlen (ptr)-1]==':' && !strchr (ptr, ' ')) {
		/* label detected */
		if (ptr[0]=='.') {
		//	eprintf("---> GOTO '%s'\n", ptr+1);
			/* goto */
			for (i=0;i<*labels_n;i++) {
		//	eprintf("---| chk '%s'\n", labels[i].name);
				if (!strcmp (ptr+1, labels[i].name)) {
					return labels[i].ptr;
			}
			}
			return NULL;
		} else
		/* conditional goto */
		if (ptr[0]=='?' && ptr[1]=='!' && ptr[2] != '?') {
			if (mac->num && mac->num->value != 0) {
				char *label = ptr + 3;
				for (; *label==' '||*label=='.'; label++);
		//		eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for (i=0;i<*labels_n;i++) {
					if (!strcmp (label, labels[i].name))
						return labels[i].ptr;
				}
				return NULL;
			}
		} else
		/* conditional goto */
		if (ptr[0]=='?' && ptr[1]=='?' && ptr[2] != '?') {
			if (mac->num->value == 0) {
				char *label = ptr + 3;
				for (;label[0]==' '||label[0]=='.'; label++);
		//		eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for (i=0; i<*labels_n; i++) {
					if (!strcmp (label, labels[i].name))
						return labels[i].ptr;
				}
				return NULL;
			}
		} else {
			for (i=0; i<*labels_n; i++) {
		//	eprintf("---| chk '%s'\n", labels[i].name);
				if (!strcmp (ptr+1, labels[i].name)) {
					i = 0;
					break;
				}
			}
			/* Add label */
		//	eprintf("===> ADD LABEL(%s)\n", ptr);
			if (i == 0) {
				strncpy (labels[*labels_n].name, ptr, 64);
				labels[*labels_n].ptr = ptr+strlen (ptr)+1;
				*labels_n = *labels_n + 1;
			}
		}
		return ptr + strlen (ptr)+1;
	}
	return ptr;
}

/* TODO: add support for spaced arguments */
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name) {
	RCons *cons;
	char *args;
	int nargs = 0;
	char *str, *ptr, *ptr2;
	RListIter *iter;
	static int macro_level = 0;
	RCmdMacroItem *m;
	/* labels */
	int labels_n = 0;
	struct r_cmd_macro_label_t labels[MACRO_LABELS];

	str = strdup (name);
	if (str == NULL) {
		perror ("strdup");
		return R_FALSE;
	}
	ptr = strchr (str, ')');
	if (ptr == NULL) {
		eprintf ("Missing end ')' parenthesis.\n");
		free (str);
		return R_FALSE;
	} else *ptr='\0';

	args = strchr (str, ' ');
	if (args) {
		*args = '\0';
		args++;
		nargs = r_str_word_set0 (args);
	}

	macro_level++;
	if (macro_level > MACRO_LIMIT) {
		eprintf ("Maximum macro recursivity reached.\n");
		macro_level--;
		free (str);
		return 0;
	}
	ptr = strchr (str, ',');
	if (ptr) *ptr =0;

	cons = r_cons_singleton ();
	r_cons_break (NULL, NULL);
	r_list_foreach (mac->macros, iter, m) {
		if (!strcmp (str, m->name)) {
			char *ptr = m->code;
			char *end = strchr (ptr, '\n');

			if (m->nargs != 0 && nargs != m->nargs) {
				eprintf ("Macro '%s' expects %d args, not %d\n",
					m->name, m->nargs, nargs);
				macro_level --;
				free (str);
				return R_FALSE;
			}

			mac->brk = 0;
			do {
				if (end) *end = '\0';
				if (cons->breaked) {
					eprintf ("Interrupted at (%s)\n", ptr);
					if (end) *end = '\n';
					free (str);
					return R_FALSE;
				}
				r_cons_flush ();

				/* Label handling */
				ptr2 = r_cmd_macro_label_process (mac, &(labels[0]), &labels_n, ptr);
				if (ptr2 == NULL) {
					eprintf ("Oops. invalid label name\n");
					break;
				} else
				if (ptr != ptr2) { // && end) {
					ptr = ptr2;
					if (end) *end ='\n';
					end = strchr (ptr, '\n');
					continue;
				}
				/* Command execution */
				if (*ptr) {
					mac->num->value = value;
					int r = r_cmd_macro_cmd_args (mac, ptr, args, nargs);
					// TODO: handle quit? r == 0??
					// quit, exits the macro. like a break
					value = mac->num->value;
					if (r <0) {
						free (str);
						return r;
					}
				}
				if (end) {
					*end = '\n';
					ptr = end + 1;
				} else {
					macro_level --;
					free (str);
					return R_TRUE;
				}

				/* Fetch next command */
				end = strchr (ptr, '\n');
			} while (!mac->brk);

			if (mac->brk) {
				macro_level--;
				free (str);
				return R_TRUE;
			}
		}
	}
	eprintf ("No macro named '%s'\n", str);
	macro_level--;
	free (str);
	return R_TRUE;
}

R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value) {
	mac->brk = 1;
	mac->brk_value = NULL;
	mac->_brk_value = (ut64)r_num_math (mac->num, value);
	if (value && *value)
		mac->brk_value = &mac->_brk_value;
	return 0;
}

#if 0
int cmd_quit(void *data, const char *input) {
	printf("quit\n");
//	exit(1);
	return 0;
}

int cmd_echo(void *data, const char *input) {
	const char *arg = strchr(input, ' ');
	if (arg == NULL)
		arg = input;
	printf("%s\n", arg+1);
	return 0;
}

int main()
{
	struct r_cmd_t *cmd;

	cmd = r_cmd_new();

	r_cmd_add(cmd, "e", "echo message", &cmd_echo);
	r_cmd_add(cmd, "q", "quit program", &cmd_quit);

	r_cmd_add_long(cmd, "echo", "e", "echo message");
	r_cmd_add_long(cmd, "exit", "q", "quit program");

	r_cmd_call(cmd, "e hello world short");
	r_cmd_call_long(cmd, "echo hello world long");
	r_cmd_call_long(cmd, "exit");
	if (!r_cmd_call(cmd, "**dummy**"))
		eprintf ("==> Cannot call **dummy**\n");
	else eprintf ("==> **dummy** called\n");
	r_cmd_call(cmd, "quit");

	return 0;
}
#endif
