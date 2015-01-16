/* radare - LGPL - Copyright 2015 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flags.h>
#include <r_anal.h>
#include <r_parse.h>

static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		char *op;
		char *str;
	} ops[] = {
		{ "abs",  "1 = abs(1)"},
		{ "adc",  "1 = 2 + 3"},
		{ "add",  "1 = 2 + 3"},
		{ "adf",  "1 = 2 + 3"},
		{ "adrp",  "1 = 2"},
		{ "and",  "1 = 2 & 3"},
		{ "asl",  "1 = 2 << 3"},
		{ "asr",  "1 = 2 >> 3"},
		{ "b",  "jmp 1"},
		{ "b.gt",  "jmp ifgt 1"},
		{ "b.le",  "jmp ifle 1"},
		{ "beq lr",  "ifeq ret"},
		{ "beq",  "je 1"},
		{ "bl",  "call 1"},
		{ "blx",  "call 1"},
		{ "bx lr",  "ret"},
		{ "bxeq",  "je 1"},
		{ "cmf",  "cmp 1 2"},
		{ "cmp",  "cmp 1 2"},
		{ "dvf",  "1 = 2 / 3"},
		{ "eor",  "1 = 2 ^ 3"},
		{ "fdv",  "1 = 2 / 3"},
		{ "fml",  "1 = 2 * 3"},
		{ "ldr",  "1 = 2 + 3"},
		{ "ldrb",  "1 = 2"},
		{ "ldrsw",  "1 = 2 + 3"},
		{ "lsl",  "1 = 2 << 3"},
		{ "lsr",  "1 = 2 >> 3"},
		{ "mov",  "1 = 2"},
		{ "movz",  "1 = 2"},
		{ "muf",  "1 = 2 * 3"},
		{ "mul",  "1 = 2 * 3"},
		{ "orr",  "1 = 2 | 3"},
		{ "rmf",  "1 = 2 % 3"},
		{ "sbc",  "1 = 2 - 3"},
		{ "sqt",  "1 = sqrt(2)"},
		{ "str",  "2 + 3 = 1"},
		{ "sub",  "1 = 2 - 3"},
		{ "swp",  "swap(1, 2)"},
		{ NULL }
	};

	for (i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0; ops[i].str[j]!='\0'; j++, k++) {
					if (ops[i].str[j]>='0' && ops[i].str[j]<='9') {
						const char *w = argv[ ops[i].str[j]-'0' ];
						if (w != NULL) {
							strcpy(newstr+k, w);
							k += strlen(w)-1;
						}
					} else newstr[k] = ops[i].str[j];
				}
				newstr[k]='\0';
			}
			return R_TRUE;
		}
	}

	/* TODO: this is slow */
	if (newstr != NULL) {
		newstr[0] = '\0';
		for (i=0; i<argc; i++) {
			strcat (newstr, argv[i]);
			strcat (newstr, (i == 0 || i== argc - 1)?" ":",");
		}
	}
	return R_FALSE;
}

static int parse(RParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256];
	int i, len = strlen (data);
	char *buf, *ptr, *optr;

	if (len>=sizeof (w0))
		return R_FALSE;
	// malloc can be slow here :?
	if ((buf = malloc (len+1)) == NULL)
		return R_FALSE;
	memcpy (buf, data, len+1);

	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = '\0';
		ptr = strchr (buf, ' ');
		if (ptr == NULL)
			ptr = strchr (buf, '\t');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr==' '; ptr++);
			strncpy (w0, buf, sizeof (w0) - 1);
			strncpy (w1, ptr, sizeof (w1) - 1);

			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr==' '; ptr++);
				strncpy (w1, optr, sizeof (w1) - 1);
				strncpy (w2, ptr, sizeof (w2) - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr==' '; ptr++);
					strncpy (w2, optr, sizeof (w2) - 1);
					strncpy (w3, ptr, sizeof (w3) - 1);
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3 };
			int nw = 0;
			for (i=0; i<4; i++) {
				if (wa[i][0] != '\0')
				nw++;
			}
			replace (nw, wa, str);
		}
	}
	free (buf);
	return R_TRUE;
}

static int varsub(RParse *p, RAnalFunction *f, char *data, char *str, int len) {
	RAnalVar *var;
	RListIter *iter;
	char oldstr[64], newstr[64];
	char *tstr = strdup (data);
	RList *vars, *args;

	if (!p->varlist) {
                free(tstr);
		return R_FALSE;
        }

	vars = p->varlist (p->anal, f, 'v');
	args = p->varlist (p->anal, f, 'a');
	r_list_join (vars, args);
	switch (p->anal->bits) {
	case 64:
		r_list_foreach (vars, iter, var) {
			if (var->delta < 10) snprintf (oldstr, sizeof (oldstr)-1,
					"[%s, %d]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->delta);
			else snprintf (oldstr, sizeof (oldstr)-1,
					"[%s, 0x%x]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->delta);
			snprintf (newstr, sizeof (newstr)-1, "[%s+%s]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->name);
			if (strstr (tstr, oldstr) != NULL) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
			// Try with no spaces
			snprintf (oldstr, sizeof (oldstr)-1, "[%s+0x%x]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->delta);
			if (strstr (tstr, oldstr) != NULL) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
		break;
	case 32:
		r_list_foreach (vars, iter, var) {
			if (var->delta < 10) snprintf (oldstr, sizeof (oldstr)-1,
					"[%s, -%d]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->delta);
			else snprintf (oldstr, sizeof (oldstr)-1,
					"[%s, -0x%x]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->delta);
			snprintf (newstr, sizeof (newstr)-1, "[%s-%s]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->name);
			if (strstr (tstr, oldstr) != NULL) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
			// Try with no spaces
			snprintf (oldstr, sizeof (oldstr)-1, "[%s-0x%x]",
					p->anal->reg->name[R_REG_NAME_BP],
					var->delta);
			if (strstr (tstr, oldstr) != NULL) {
				tstr = r_str_replace (tstr, oldstr, newstr, 1);
				break;
			}
		}
		break;
	case 16:
		//
		break;
	}
	if (len > strlen (tstr)) {
		strncpy (str, tstr, strlen (tstr));
		str[strlen (tstr)] = 0;
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		free (tstr);
		return R_FALSE;
	}
	free (tstr);
	return R_TRUE;
}

struct r_parse_plugin_t r_parse_plugin_arm_pseudo = {
	.name = "arm.pseudo",
	.desc = "ARM/ARM64 pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.assemble = NULL,
	.filter = NULL,
	.varsub = &varsub,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_arm_pseudo
};
#endif
