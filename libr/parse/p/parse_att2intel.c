/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */

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
		{ "cmpl",  "cmp 2, 1"},
		{ "testl", "test 2, 1"},
		{ "leal",  "lea 2, 1"},
		{ "movl",  "mov 2, 1"},
		{ "xorl",  "xor 2, 1"},
		{ "andl",  "and 2, 1"},
		{ "orl",   "or 2, 1"},
		{ "addl",  "add 2, 1"},
		{ "incl",  "inc 1"},
		{ "decl",  "dec 1"},
		{ "subl",  "sub 2, 1"},
		{ "mull",  "mul 2, 1"},
		{ "divl",  "div 2, 1"},
		{ "pushl", "push 1"},
		{ "popl",  "pop 1"},
		{ "ret",  "ret"},
		{ NULL }
	};

	for (i=0; ops[i].op != NULL; i++) {
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
	int i, n;
	char w0[32];
	char w1[32];
	char w2[32];
	char w3[32];
	char *buf, *ptr, *optr, *num;

	// malloc can be slow here :?
	buf = strdup (data);
	r_str_trim_head (buf);

	ptr = strchr (buf, '#');
	if (ptr) {
		*ptr = 0;
		r_str_chop (buf);
	}
	if (*buf == '.' || buf[strlen(buf)-1] == ':') {
		free (buf);
		strcpy (str, data);
		return R_TRUE;
	}
	r_str_replace_char (buf, '$', 0);
	r_str_replace_char (buf, '%', 0);
	r_str_replace_char (buf, '\t', ' ');
	r_str_replace_char (buf, '(', '[');
	r_str_replace_char (buf, ')', ']');
	ptr = strchr (buf, '[');
	if (ptr) {
		*ptr = 0;
		num = (char*)r_str_lchr (buf, ' ');
		if (!num)
			num = (char*)r_str_lchr (buf, ',');
		if (num) {
			n = atoi (num+1);
			*ptr = '[';
			memmove (num+1, ptr, strlen (ptr)+1);
			ptr = (char*)r_str_lchr (buf, ']');
			if (n && ptr) {
				char *rest = strdup (ptr+1);
				if(n>0) sprintf (ptr, "+%d]%s", n, rest);
				else sprintf (ptr, "%d]%s", n, rest);
				free (rest);
			}
		} else *ptr = '[';
	}

	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = 0;
		ptr = strchr (buf, ' ');
		if (ptr == NULL)
			ptr = strchr (buf, '\t');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr==' '; ptr++);
			strncpy (w0, buf, sizeof(w0) - 1);
			strncpy (w1, ptr, sizeof(w1) - 1);

			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr==' '; ptr++);
				strncpy (w1, optr, sizeof(w1)-1);
				strncpy (w2, ptr, sizeof(w2)-1);
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr==' '; ptr++);
					strncpy (w2, optr, sizeof(w2)-1);
					strncpy (w3, ptr, sizeof(w3)-1);
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
	printf ("---> assembling '%s' to generate real asm code\n", str);
	ptr = strchr (str, '=');
	if (ptr) {
		*ptr = '\0';
		sprintf (data, "mov %s, %s", str, ptr+1);
	} else strcpy (data, str);
	return R_TRUE;
}

static int varsub(RParse *p, RAnalFunction *f, char *data, char *str, int len) {
#if USE_VARSUBS
	char *ptr, *ptr2;
	int i;
	strncpy (str, data, len);
	for (i = 0; i < R_ANAL_VARSUBS; i++)
		if (f->varsubs[i].pat[0] != '\0' && f->varsubs[i].sub[0] != '\0' &&
			(ptr = strstr (data, f->varsubs[i].pat))) {
				*ptr = '\0';
				ptr2 = ptr + strlen (f->varsubs[i].pat);
				snprintf (str, len, "%s%s%s", data, f->varsubs[i].sub, ptr2);
		}
	return R_TRUE;
#else
	strncpy (str, data, len);
	return R_FALSE;
#endif
}

struct r_parse_plugin_t r_parse_plugin_att2intel = {
	.name = "att2intel",
	.desc = "X86 att 2 intel plugin",
	.init = NULL,
	.fini = NULL,
	.parse = &parse,
	.assemble = &assemble,
	.varsub = &varsub,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_att2intel
};
#endif
