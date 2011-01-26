/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

#include <stdio.h>
#include "r_cmd.h"
#include "r_util.h"

#if 0
static ut64 _macro_break_value = 0;
ut64 *macro_break_value = NULL;
static int macro_break;
int macro_counter = 0;
static struct list_head macros;
#endif

R_API void r_cmd_macro_init(RCmdMacro *mac) {
	mac->counter = 0;
	mac->_brk_value = 0;
	mac->brk_value = &mac->_brk_value;
	mac->printf = (void*)printf;
	mac->num = NULL;
	mac->user = NULL;
	mac->cmd = NULL;
	INIT_LIST_HEAD (&mac->macros);
}

// XXX add support single line function definitions
// XXX add support for single name multiple nargs macros
R_API int r_cmd_macro_add(RCmdMacro *mac, const char *oname) {
	struct list_head *pos;
	struct r_cmd_macro_item_t *macro;
	char buf[1024];
	char *bufp;
	char *pbody;
	char *ptr;
	int lidx;
	int macro_update;
	char *name, *args = NULL;

	if (oname[0]=='\0') {
		r_cmd_macro_list(mac);
		return 0;
	}

	name = alloca (strlen(oname)+1);
	strcpy (name, oname);

	pbody = strchr (name, ',');
	if (pbody) {
		pbody[0]='\0';
		pbody = pbody + 1;
	}

	if (name[strlen(name)-1]==')') {
		eprintf("No body?\n");
		return -1;
	}

	macro = NULL;
	macro_update = 0;
	ptr = strchr (name, ' ');
	if (ptr) {
		*ptr='\0';
		args = ptr +1;
	}
	list_for_each_prev (pos, &mac->macros) {
		RCmdMacroItem *m = list_entry(pos, struct r_cmd_macro_item_t, list);
		if (!strcmp(name, m->name)) {
			macro = m;
	//		free(macro->name);
			free(macro->code);
			free(macro->args);
			macro_update = 1;
			break;
		}
	}
	if (macro == NULL) {
		macro = (struct r_cmd_macro_item_t *)malloc(sizeof(struct r_cmd_macro_item_t));
		macro->name = strdup(name);
	}
	if (pbody) macro->code = (char *)malloc(strlen(pbody)+2);
	else macro->code = (char *)malloc(4096);
	macro->code[0]='\0';
	macro->nargs = 0;
	if (args == NULL)
		args = "";
	macro->args = strdup(args);
	ptr = strchr(macro->name, ' ');
	if (ptr != NULL) {
		*ptr='\0';
		macro->nargs = r_str_word_set0(ptr+1);
	}

	if (pbody) {
		for(lidx=0;pbody[lidx];lidx++) {
			if (pbody[lidx]==',')
				pbody[lidx]='\n';
			else
			if (pbody[lidx]==')') // && pbody[lidx-1]=='\n')
				pbody[lidx]='\0';
		}
		strcpy(macro->code, pbody);
		strcat(macro->code, ",");
	} else {
		while(1) { // XXX input from mac->fd
#if 0
			if (stdin == r_cons_stdin_fd) {
				mac->printf(".. ");
				fflush(stdout);
			}
			fgets(buf, 1023, r_cons_stdin_fd);
#endif
			fgets(buf, 1023, stdin);
			if (buf[0]==')')
				break;
			for(bufp=buf;*bufp==' '||*bufp=='\t';bufp=bufp+1);
			lidx = strlen(buf)-2;
			if (buf[lidx]==')' && buf[lidx-1]!='(') {
				buf[lidx]='\0';
				strcat (macro->code, bufp);
				break;
			}
			if (buf[0] != '\n')
				strcat (macro->code, bufp);
		}
	}
	if (macro_update == 0)
		list_add_tail (&(macro->list), &(mac->macros));
	return 0;
}

R_API int r_cmd_macro_rm(struct r_cmd_macro_t *mac, const char *_name) {
	char *name = alloca (strlen(_name));
	struct list_head *pos;
	char *ptr = strchr (name, ')');
	if (ptr) *ptr='\0';
	list_for_each_prev(pos, &mac->macros) {
		RCmdMacroItem *mac = list_entry(pos, RCmdMacroItem, list);
		if (!strcmp (mac->name, name)) {
			free (mac->name);
			free (mac->code);
			list_del (&(mac->list));
			free (mac);
			eprintf ("Macro '%s' removed.\n", name);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// TODO: use mac->printf which is r_cons_printf at the end
R_API void r_cmd_macro_list(RCmdMacro *mac) {
	int j, idx = 0;
	struct list_head *pos;
	list_for_each_prev (pos, &mac->macros) {
		RCmdMacroItem *m = list_entry (pos, RCmdMacroItem, list);
		/* mac-> */ printf ("%d (%s %s, ", idx, m->name, m->args);
		for (j=0; m->code[j]; j++) {
			if (m->code[j]=='\n')
				/* mac-> */ printf (", ");
			else /* mac->*/ printf ("%c", m->code[j]);
		}
		/* mac->*/ printf (")\n");
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
	int i,j;
	char *cmd = alloca(strlen(ptr)+1024);
	char *arg = args?strdup(args):strdup("");
	cmd[0]='\0';

//	eprintf("call(%s)\n", ptr);
	for(i=j=0;ptr[j];i++,j++) {
		if (ptr[j]=='$') {
			if (ptr[j+1]>='0' && ptr[j+1]<='9') {
				char *word = r_str_word_get0(arg, ptr[j+1]-'0');
// TODO: use r_str_concat ??
				strcat(cmd, word);
				j++;
				i = strlen(cmd)-1;
			} else
			if (ptr[j+1]=='@') {
				char off[32];
				sprintf(off, "%d", mac->counter);
				strcat(cmd, off);
				j++;
				i = strlen(cmd)-1;
			} else {
				cmd[i]=ptr[j];
				cmd[i+1]='\0';
			}
		} else {
			cmd[i]=ptr[j];
			cmd[i+1]='\0';
		}
	}
	while(*cmd==' '||*cmd=='\t')
		cmd = cmd + 1;
	free(arg);
	return (*cmd==')')?0:mac->cmd(mac->user, cmd);
}

R_API char *r_cmd_macro_label_process(RCmdMacro *mac, RCmdMacroLabel *labels, int *labels_n, char *ptr) {
	int i;
	for (;ptr[0]==' ';ptr=ptr+1);
	if (ptr[strlen(ptr)-1]==':') {
		/* label detected */
		if (ptr[0]=='.') {
		//	eprintf("---> GOTO '%s'\n", ptr+1);
			/* goto */
			for(i=0;i<*labels_n;i++) {
		//	eprintf("---| chk '%s'\n", labels[i].name);
				if (!strcmp(ptr+1, labels[i].name))
					return labels[i].ptr;
			}
			return NULL;
		} else
		/* conditional goto */
		if (ptr[0]=='?' && ptr[1]=='!' && ptr[2] != '?') {
			if (mac->num && mac->num->value != 0) {
				char *label = ptr + 3;
				for(;label[0]==' '||label[0]=='.';label=label+1);
		//		eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for(i=0;i<*labels_n;i++) {
					if (!strcmp(label, labels[i].name))
						return labels[i].ptr;
				}
				return NULL;
			}
		} else
		/* conditional goto */
		if (ptr[0]=='?' && ptr[1]=='?' && ptr[2] != '?') {
			if (mac->num->value == 0) {
				char *label = ptr + 3;
				for(;label[0]==' '||label[0]=='.';label=label+1);
		//		eprintf("===> GOTO %s\n", label);
				/* goto label ptr+3 */
				for(i=0;i<*labels_n;i++) {
					if (!strcmp(label, labels[i].name))
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
				labels[*labels_n].ptr = ptr+strlen(ptr)+1;
				*labels_n = *labels_n + 1;
			}
		}
		return ptr + strlen (ptr)+1;
	}

	return ptr;
}

/* TODO: add support for spaced arguments */
R_API int r_cmd_macro_call(RCmdMacro *mac, const char *name) {
	char *args;
	int nargs = 0;
	char *str, *ptr, *ptr2;
	struct list_head *pos;
	static int macro_level = 0;
	/* labels */
	int labels_n = 0;
	struct r_cmd_macro_label_t labels[MACRO_LABELS];

	str = alloca (strlen (name)+1);
	strcpy (str, name);
	ptr = strchr (str, ')');
	if (ptr == NULL) {
		eprintf ("Missing end ')' parenthesis.\n");
		return R_FALSE;
	} else *ptr='\0';

	args = strchr (str, ' ');
	if (args) {
		*args='\0';
		args = args+1;
		nargs = r_str_word_set0 (args);
	}

	macro_level ++;
	if (macro_level > MACRO_LIMIT) {
		eprintf ("Maximum macro recursivity reached.\n");
		macro_level --;
		return 0;
	}

	list_for_each_prev (pos, &mac->macros) {
		RCmdMacroItem *m = list_entry (pos, RCmdMacroItem, list);

		if (!strcmp (str, m->name)) {
			char *ptr = m->code;
			char *end = strchr (ptr, '\n');

			if (m->nargs != 0 && nargs != m->nargs) {
				eprintf ("Macro '%s' expects %d args\n", m->name, m->nargs);
				macro_level --;
				return R_FALSE;
			}

			mac->brk = 0;
			do {
				if (end) *end='\0';

				/* Label handling */
				ptr2 = r_cmd_macro_label_process (mac, &(labels[0]), &labels_n, ptr);
				if (ptr2 == NULL) {
					eprintf ("Oops. invalid label name\n");
					break;
				} else
				if (ptr != ptr2 && end) {
					*end='\n';
					ptr = ptr2;
					end = strchr(ptr, '\n');
					continue;
				}

				/* Command execution */
				if (*ptr)
					r_cmd_macro_cmd_args (mac, ptr, args, nargs);
				if (end) {
					*end='\n';
					ptr = end + 1;
				} else {
					macro_level --;
					return R_TRUE;
				}

				/* Fetch next command */
				end = strchr (ptr, '\n');
			} while (!mac->brk);

			if (mac->brk) {
				macro_level--;
				return R_TRUE;
			}
		}
	}
	eprintf ("No macro named '%s'\n", str);
	macro_level--;
	return R_TRUE;
}

R_API int r_cmd_macro_break(RCmdMacro *mac, const char *value) {
	mac->brk = 1;
	mac->brk_value= NULL;
	mac->_brk_value = (ut64)r_num_math (mac->num, value);
	if (value && *value)
		mac->brk_value = &mac->_brk_value;
	return 0;
}
