/* radare - LGPL - Copyright 2009-2012 - nibble, pancake */

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
		{ "ret",  "ret"},
		{ NULL }
	};

	for(i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0;ops[i].str[j]!='\0';j++,k++) {
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
	char w0[64], w1[64], w2[64], w3[64];
	int i, len = strlen (data);
	char *buf, *ptr, *optr;

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
			strcpy (w0, buf);
			strcpy (w1, ptr);

			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr==' '; ptr++);
				strcpy (w1, optr);
				strcpy (w2, ptr);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr==' '; ptr++);
					strcpy (w2, optr);
					strcpy (w3, ptr);
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

static int filter(RParse *p, RFlag *f, char *data, char *str, int len) {
	char *ptr = data, *ptr2;
	RListIter *iter;
	RFlagItem *flag;
	ut64 off;

	while ((ptr = strstr (ptr, "0x"))) {
		for (ptr2 = ptr; *ptr2 && !isseparator (*ptr2); ptr2++);
		off = r_num_math (NULL, ptr);
		if (!off) {
			ptr = ptr2;
			continue;
		}
		// XXX. tooslow
		r_list_foreach (f->flags, iter, flag) {
			if (flag->offset == off && strchr (flag->name, '.')) {
				if (p->notin_flagspace != -1) {
					if (p->flagspace == flag->space)
						continue;
				} else
				if (p->flagspace != -1 && \
					(p->flagspace != flag->space)) {
					continue;
				}
				*ptr = 0;
				snprintf (str, len, "%s%s%s", data, flag->name,
					ptr2!=ptr? ptr2: "");
				return R_TRUE;
			}
		}
		ptr = ptr2;
	}
	strncpy (str, data, len);
	return R_FALSE;
}

static int varsub(RParse *p, RAnalFunction *f, char *data, char *str, int len) {
	int i;
	char *ptr, *ptr2;
	strncpy (str, data, len);
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
}

struct r_parse_plugin_t r_parse_plugin_x86_pseudo = {
	.name = "x86.pseudo",
	.desc = "X86 pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.assemble = &assemble,
	.filter = &filter,
	.varsub = &varsub,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_x86_pseudo
};
#endif
