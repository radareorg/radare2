/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

static int r_asm_x86_aop(int argc, const char *argv[], char *newstr)
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

int r_asm_x86_pseudo(struct r_asm_t *a)
{
	int i, len = strlen(a->buf_asm);
	char w0[32];
	char w1[32];
	char w2[32];
	char w3[32];
	char *str, *ptr, *optr;

	if ((str = alloca(len+1)) == NULL)
		return R_FALSE;
	memcpy(str, a->buf_asm, len+1);

	if (str[0]!='\0') {
		w0[0]='\0';
		w1[0]='\0';
		w2[0]='\0';
		w3[0]='\0';
		ptr = strchr(str, ' ');
		if (ptr == NULL)
			ptr = strchr(str, '\t');
		if (ptr) {
			ptr[0]='\0';
			for(ptr=ptr+1;ptr[0]==' ';ptr=ptr+1);
			strcpy(w0, str);
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

			r_asm_x86_aop(nw, wa, (char*)a->aux);
		}
	}

	return R_TRUE;
}
