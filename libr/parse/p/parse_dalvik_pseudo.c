/* radare - LGPL - Copyright 2012-2013 - pancake */

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
		{ "rsub-int",   "1 = 2 - 3"},
		{ "float-to-double", "1 = (double) 2"},
		{ "float-to-long", "1 = (long) 2"},
		{ "long-to-float", "1 = (float) 2"},
		{ "long-to-double", "1 = (double) 2"},
		{ "double-to-long", "1 = (long) 2"},
		{ "int-to-double", "1 = (double) 2"},
		{ "int-to-long", "1 = (long) 2"},
		{ "int-to-byte", "1 = (byte) 2"},
		{ "aget-byte", "1 = 2[3]"},
		{ "sput-wide", "1 = 2"},
		{ "add-long", "1 = 2 + 3"},
		{ "add-double", "1 = 2 + 3"},
		{ "mul-long", "1 = 2 * 3"},
		{ "const-string/jumbo", "1 = (jumbo-string) 2"},
		{ "const-string", "1 = (string) 2"},
		{ "const-wide", "1 = (wide) 2"},
		{ "const/4", "1 = (wide) 2"},
		{ "cmp-int", "1 = (2 == 3)"},
		{ "cmp-long", "1 = (2 == 3)"},
		{ "cmpl-double", "1 = (2 == 3)"},
		{ "cmpg-double", "1 = (2 == 3)"},
		{ "or-int/2addr", "1 |= 2"},
		{ "or-long", "1 |= 2"},
		{ "and-long/2addr", "1 &= 2"},
		{ "sub-float/2addr", "1 -= 2"},
		{ "sub-float", "1 = 2 - 3"},
		{ "sub-int", "1 = 2 - 3"},
		{ "sub-int/2addr", "1 -= 2"},
		{ "move", "1 = 2"},
		{ "move/16", "1 = 2"},
		{ "move-object", "1 = (object) 2"},
		{ "move-object/from16", "1 = (object) 2"},
		{ "move-wide/from16", "1 = (wide) 2"},
		{ "array-length", "1 = array_length (2)"},
		{ "new-array", "1 = new array (2, 3)"},
		{ "new-instance", "1 = new 2"},
		{ "shr-long/2addr", "1 >>= 2"},
		{ "shr-long", "1 = 2 >> 3"},
		{ "ushr-int", "1 >>>= 2"},
		{ "ushr-int/2addr", "1 >>>= 2"},
		{ "ushl-int/2addr", "1 <<<= 2"},
		{ "shl-int/2addr", "1 <<<= 2"},
		{ "shl-int", "1 = 2 << 3"},
		{ "move/from16", "1 = 2"},
		{ "move-exception", "1 = exception"},
		{ "move-result", "1 = result"},
		{ "move-result-wide", "1 = (wide) result"},
		{ "move-result-object", "1 = (object) result"},
		{ "const-wide/high16", "1 = 2"},
		{ "const/16", "1 = 2"},
		{ "const-wide/16", "1 = 2"},
		{ "const-wide/32", "1 = 2"},
		{ "const-class", "1 = (class) 2"},
		{ "const/high16", "1 = 2"},
		{ "rem-long", "1 = 2 % 3"},
		{ "rem-long/2addr", "1 %= 2"},
		{ "rem-float/2addr", "1 %= 2"},
		{ "instance-of", "1 = insteanceof (2) == 3"},
		{ "aput-object", "2[3] = (object) 1"},
		{ "aput-wide", "2[3] = (wide) 1"},
		{ "aput-char", "2[3] = (char) 1"},
		{ "aget", "1 = 2[3]"},
		{ "aget-wide", "1 = (wide) 2[3]"},
		{ "aget-boolean", "1 = (boolean) 2[3]"},
		{ "sget", "1 = 2"},
		{ "sget-char", "1 = (char) 2"},
		{ "sget-boolean", "1 = (bool) 2"},
		{ "iput", "2[3] = 1"},
		{ "iget", "1 = 2[3]"},
		{ "iget-byte", "1 = (byte) 2[3]"},
		{ "iget-char", "1 = (char) 2[3]"},
		{ "iget-short", "1 = (short) 2[3]"},
		{ "iget-wide", "1 = (wide) 2[3]"},
		{ "iget-object", "1 = (object) 2[3]"},
		{ "iget-boolean", "1 = (bool) 2[3]"},
		{ "if-eq", "if (1 == 2) goto 3"},
		{ "if-eqz", "if (!1) goto 2"},
		{ "if-ge", "if (1 > zero) goto 2"},
		{ "if-le", "if (1 > 2) goto 3"},
		{ "neg-long", "1 = -2"},
		{ "neg-float", "1 = -2"},
		{ "not-int", "1 = !2"},
		{ "invoke-direct", "call 2 1"},
		{ "invoke-super/range", "call super 2 1"},
		{ "invoke-virtual/range", "call 2 1"},
		{ "invoke-virtual", "call 2 1"},
		{ "+invoke-virtual-quick", "call 2 1"},
		{ "+invoke-interface/range", "call 2 1"},
		{ "invoke-interface/range", "call 2 1"},
		{ "div-float/2addr", "1 /= 2"},
		{ "div-float", "1 = 2 / 3"},
		{ "div-int/lit8", "1 = 2 / 3"},
		{ "div-int/lit16", "1 = 2 / 3"},
		{ "goto/16", "goto 1"},
		{ "goto/32", "goto 1"},
		{ "add-int/lit8", "1 = 2 + 3"},
		{ "add-int/lit16", "1 = 2 + 3"},
		{ "add-int/2addr", "1 += 2"},
		{ "mul-float/2addr", "1 *= 2"},
		{ "mul-float", "1 = 2 * 3"},
		{ "mul-double", "1 = 2 * 3"},
		{ "move-wide", "1 = 2"},
		{ "move-wide/16", "1 = 2"},
		{ "return-wide", "ret (wide) 1"},
		{ "return-object", "ret (object) 1"},
		// { "sget", "1 = 2[3]"},
		{ NULL }
	};

	for (i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0;ops[i].str[j]!='\0';j++,k++) {
					if (ops[i].str[j]>='1' && ops[i].str[j]<='9') {
						const char *w = argv[ ops[i].str[j]-'0' ];
						if (w != NULL) {
							strcpy (newstr+k, w);
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
			strcat (newstr, (i == 0 || i== argc - 1)?" ":", ");
		}
	}

	return R_FALSE;
}

static int parse(RParse *p, const char *data, char *str) {
	int i, len = strlen (data);
	char *buf, *ptr, *optr, *ptr2;
	char w0[64];
	char w1[64];
	char w2[64];
	char w3[64];
	char w4[64];

	if (!strcmp (data, "invalid")
	||  !strcmp (data, "nop")
	||  !strcmp (data, "DEPRECATED")) {
		str[0] = 0;
		return R_TRUE;
	}
	
	// malloc can be slow here :?
	if ((buf = malloc (len+1)) == NULL)
		return R_FALSE;
	memcpy (buf, data, len+1);

	r_str_chop (buf);

	if (*buf) {
		w0[0]='\0';
		w1[0]='\0';
		w2[0]='\0';
		w3[0]='\0';
		w4[0]='\0';
		ptr = strchr (buf, ' ');
		if (ptr == NULL)
			ptr = strchr (buf, '\t');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr==' '; ptr++);
			strncpy (w0, buf, sizeof (w0) - 1);
			w0[sizeof(w0)-1] = '\0';
			strncpy (w1, ptr, sizeof (w1) - 1);
			w1[sizeof(w1)-1] = '\0';

			optr=ptr;
			ptr2 = strchr (ptr, '}');
			if (ptr2) ptr = ptr2+1;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr==' '; ptr++);
				strncpy (w1, optr, sizeof (w1) - 1);
				w1[sizeof(w1)-1] = '\0';
				strncpy (w2, ptr, sizeof (w2) - 1);
				w2[sizeof(w2)-1] = '\0';
				optr=ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr==' '; ptr++);
					strncpy (w2, optr, sizeof (w2) - 1);
					w2[sizeof(w2)-1] = '\0';
					strncpy (w3, ptr, sizeof (w3) - 1);
					w3[sizeof(w3)-1] = '\0';
					optr=ptr;
// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (++ptr; *ptr==' '; ptr++);
						strncpy (w3, optr, sizeof (w3) - 1);
						w3[sizeof(w3)-1] = '\0';
						strncpy (w4, ptr, sizeof (w4) - 1);
						w4[sizeof(w4)-1] = '\0';
					}
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i=0; i<4; i++) {
				if (wa[i][0] != '\0')
				nw++;
			}
			replace (nw, wa, str);
{
	char *p = strdup (str);
	p = r_str_replace (p, "+ -", "- ", 0);
#if EXPERIMENTAL_ZERO
	p = r_str_replace (p, "zero", "0", 0);
	if (!memcmp (p, "0 = ", 4)) *p = 0; // nop
#endif
	if (!strcmp (w1, w2)) {
		char a[32], b[32];
#define REPLACE(x,y) \
		sprintf (a, x, w1, w1); \
		sprintf (b, y, w1); \
		p = r_str_replace (p, a, b, 0);

// TODO: optimize
		REPLACE ("%s = %s +", "%s +=");
		REPLACE ("%s = %s -", "%s -=");
		REPLACE ("%s = %s &", "%s &=");
		REPLACE ("%s = %s |", "%s |=");
		REPLACE ("%s = %s ^", "%s ^=");
		REPLACE ("%s = %s >>", "%s >>=");
		REPLACE ("%s = %s <<", "%s <<=");
	}
	strcpy (str, p);
	free (p);
}
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
		// TODO not yet implemented
		sprintf (data, "move %s, %s", str, ptr+1);
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

struct r_parse_plugin_t r_parse_plugin_dalvik_pseudo = {
	.name = "dalvik.pseudo",
	.desc = "DALVIK pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.assemble = &assemble,
	.varsub = &varsub,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_dalvik_pseudo
};
#endif
