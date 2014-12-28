/* radare - LGPL - Copyright 2009-2012 - nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flags.h>
#include <r_anal.h>
#include <r_parse.h>
// 16 bit examples
//    0x0001f3a4      9a67620eca       call word 0xca0e:0x6267
//    0x0001f41c      eabe76de12       jmp word 0x12de:0x76be [2]
//    0x0001f56a      ea7ed73cd3       jmp word 0xd33c:0xd77e [6]
static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		char *op;
		char *str;
	} ops[] = {
		{ "in",   "1 = io[2]"},
		{ "out",  "io[1] = 2"},
		{ "cmp",  "cmp 1, 2"},
		{ "test", "cmp 1, 2"},
		{ "lea",  "1 = 2"},
		{ "mov",  "1 = 2"},
		{ "cmovl","ifnot zf,1 = 2"},
		{ "xor",  "1 ^= 2"},
		{ "and",  "1 &= 2"},
		{ "or",   "1 |= 2"},
		{ "add",  "1 += 2"},
		{ "sub",  "1 -= 2"},
		{ "mul",  "1 *= 2"},
		{ "div",  "1 /= 2"},
		{ "call", "call 1"},
		{ "jmp",  "goto 1"},
		{ "je",   "je 1"},
		{ "push", "push 1"},
		{ "pop",  "pop 1"},
		{ NULL }
	};

	if (argc>2 && !strcmp (argv[0], "xor")) {
		if (!strcmp (argv[1], argv[2])) {
			argv[0] = "mov";
			argv[2] = "0";
		}
	}
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

static int assemble(RParse *p, char *data, char *str) {
	char *ptr;
	printf ("assembling '%s' to generate real asm code\n", str);
	ptr = strchr (str, '=');
	if (ptr) {
		*ptr = '\0';
		sprintf (data, "mov %s, %s", str, ptr+1);
	} else strcpy (data, str);
	return R_TRUE;
}

#if 0
static inline int ishexch (char c) {
	if (c>=0 && c<=9) return 1;
	if (c>='a' && c<='f') return 1;
	if (c>='A' && c<='F') return 1;
	return 0;
}

static inline int issegoff (const char *w) {
	if (!ishexch (w[0])) return 0;
	if (!ishexch (w[1])) return 0;
	if (!ishexch (w[2])) return 0;
	if (!ishexch (w[3])) return 0;
	// :
	if (!ishexch (w[5])) return 0;
	if (!ishexch (w[6])) return 0;
	if (!ishexch (w[7])) return 0;
	if (!ishexch (w[8])) return 0;
	return 1;
}
#endif

static int varsub(RParse *p, RAnalFunction *f, char *data, char *str, int len) {
#if USE_VARSUBS
	int i;
	char *ptr, *ptr2;
	for (i = 0; i < R_ANAL_VARSUBS; i++)
		if (f->varsubs[i].pat[0] != '\0' && \
			f->varsubs[i].sub[0] != '\0' && \
			(ptr = strstr (data, f->varsubs[i].pat))) {
				*ptr = '\0';
				ptr2 = ptr + strlen (f->varsubs[i].pat);
				snprintf (str, len, "%s%s%s", data,
					f->varsubs[i].sub, ptr2);
		}
	return R_TRUE;
#else
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
	r_list_foreach (vars, iter, var) {
		if (var->delta < 10) snprintf (oldstr, sizeof (oldstr)-1,
			"[%s - %d]",
			p->anal->reg->name[R_REG_NAME_BP],
			var->delta);
		else snprintf (oldstr, sizeof (oldstr)-1,
			"[%s - 0x%x]",
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
	if (len > strlen (tstr)) {
		strncpy (str, tstr, strlen(tstr));
		str[strlen (tstr)] = 0;
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		return R_FALSE;
	}
	free (tstr);
	return R_TRUE;
#endif
}

struct r_parse_plugin_t r_parse_plugin_x86_pseudo = {
	.name = "x86.pseudo",
	.desc = "X86 pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.assemble = &assemble,
	.filter = NULL,
	.varsub = &varsub,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_x86_pseudo
};
#endif
