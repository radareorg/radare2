/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_parse.h>

static int replace(int argc, const char *argv[], char *newstr)
{
	int i,j,k;
	struct {
		char *op;
		char *str;
	} ops[] = {
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

	for(i=0;ops[i].op != NULL;i++) {
		if (!strcmp(ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for(j=k=0;ops[i].str[j]!='\0';j++,k++) {
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

	if (newstr != NULL) {
		newstr[0] = '\0';
		for (i=0; i<argc; i++) {
			strcat(newstr, argv[i]);
			strcat(newstr, (i == 0 || i== argc - 1)?" ":",");
		}
	}

	return R_FALSE;
}

static int parse(struct r_parse_t *p, void *data, char *str)
{
	int i, len = strlen((char*)data);
	char w0[32];
	char w1[32];
	char w2[32];
	char w3[32];
	char *buf, *ptr, *optr;

	if ((buf = alloca(len+1)) == NULL)
		return R_FALSE;
	memcpy(buf, (char*)data, len+1);

	if (buf[0]!='\0') {
		w0[0]='\0';
		w1[0]='\0';
		w2[0]='\0';
		w3[0]='\0';
		ptr = strchr(buf, ' ');
		if (ptr == NULL)
			ptr = strchr(buf, '\t');
		if (ptr) {
			ptr[0]='\0';
			for(ptr=ptr+1;ptr[0]==' ';ptr=ptr+1);
			strcpy(w0, buf);
			strcpy(w1, ptr);

			optr=ptr;
			ptr = strchr(ptr, ',');
			if (ptr) {
				ptr[0]='\0';
				for(ptr=ptr+1;ptr[0]==' ';ptr=ptr+1);
				strcpy(w1, optr);
				strcpy(w2, ptr);
				ptr = strchr(ptr, ',');
				if (ptr) {
					ptr[0]='\0';
					for(ptr=ptr+1;ptr[0]==' ';ptr=ptr+1);
					strcpy(w2, optr);
					strcpy(w3, ptr);
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3 };
			int nw=0;

			for(i=0;i<4;i++) {
				if (wa[i][0] != '\0')
				nw++;
			}

			replace(nw, wa, str);
		}
	}

	return R_TRUE;
}

static int assemble(struct r_parse_t *p, void *data, char *str)
{
	printf("assembling '%s' to generate real asm code\n", str);
	return R_TRUE;
}

struct r_parse_handle_t r_parse_plugin_x86_pseudo = {
	.name = "parse_x86_pseudo",
	.desc = "X86 pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = &parse,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_x86_pseudo
};
#endif
