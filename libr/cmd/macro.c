/* radare - LGPL - Copyright 2008-2012 - pancake */

#include <stdio.h>
#include <r_cons.h>
#include <r_cmd.h>
#include <r_util.h>

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
	RListIter *iter;
	RCmdMacroItem *m;
	struct r_cmd_macro_item_t *macro;
	char buf[R_CMD_MAXLEN];
	char *bufp;
	char *pbody;
	char *ptr;
	int lidx;
	int macro_update;
	char *name, *args = NULL;

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
	}

	if (name[strlen (name)-1]==')') {
		eprintf ("r_cmd_macro_add: missing macro body?\n");
		free (name);
		return -1;
	}

	macro = NULL;
	macro_update = 0;
	ptr = strchr (name, ' ');
	if (ptr) {
		*ptr='\0';
		args = ptr +1;
	}
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
		macro = (struct r_cmd_macro_item_t *)malloc (sizeof (struct r_cmd_macro_item_t));
		macro->name = strdup (name);
	}

	macro->codelen = (pbody)? strlen (pbody)+2 : 4096;
	macro->code = (char *)malloc (macro->codelen);
	*macro->code = '\0';
	macro->nargs = 0;
	if (args == NULL)
		args = "";
	macro->args = strdup (args);
	ptr = strchr (macro->name, ' ');
	if (ptr != NULL) {
		*ptr='\0';
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
		//strcat (macro->code, ",");
	} else {
		int lbufp, codelen = 0;
		for (;codelen<R_CMD_MAXLEN;) { // XXX input from mac->fd
#if 0
			if (stdin == r_cons_stdin_fd) {
				mac->printf(".. ");
				fflush(stdout);
			}
			fgets(buf, 1023, r_cons_stdin_fd);
#endif
			fgets (buf, sizeof (buf)-1, stdin);
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
	if (ptr) *ptr='\0';
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

	for (*cmd=i=j=0; ptr[j] && j<R_CMD_MAXLEN; i++,j++) {
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
				cmd[i]=ptr[j];
				cmd[i+1]='\0';
			}
		} else {
			cmd[i] = ptr[j];
			cmd[i+1] = '\0';
		}
	}
	for (pcmd = cmd; *pcmd && (*pcmd==' ' || *pcmd == '\t'); pcmd++);
	return (*pcmd==')')? 0: mac->cmd (mac->user, pcmd);
}

R_API char *r_cmd_macro_label_process(RCmdMacro *mac, RCmdMacroLabel *labels, int *labels_n, char *ptr) {
	int i;
	for (; *ptr==' '; ptr++);
	if (ptr[strlen (ptr)-1]==':') {
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

					r_cmd_macro_cmd_args (mac, ptr, args, nargs);
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
