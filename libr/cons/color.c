/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

// XXX: deprecate this stuff

#include <r_cons.h>
#include <string.h>

static const char *nullstr="";
//static const char *r_cons_palette_default = "7624 6646 2378 6824 3623";

// XXX -- deprecate -- do not use global/extern stuff
static char r_cons_palette[CONS_PALETTE_SIZE][8] = {
	/* PROMPT */
	/* ADDRESS */
	/* DEFAULT */
	/* CHANGED */

	/* JUMPS */
	/* CALLS */
	/* PUSH */
	/* TRAP */

	/* CMP */
	/* RET */
	/* NOP */
	/* METADATA */

	/* HEADER */
	/* PRINTABLE */
	/* LINES0 */
	/* LINES1 */

	/* LINES2 */
	/* 00 */
	/* 7F */
	/* FF */
};

static const char *r_cons_color_names[CONS_COLORS_SIZE+1] = {
	"black", "gray", "white", "red", "magenta", "blue", "green", "yellow",
	"cyan", "bblack", "bgray", "bwhite", "bred", "bmagenta", "bblue",
	"bgreen", "byellow", "bcyan", "reset", "bgblack", "bgred", NULL
};

static const char *r_cons_colors[CONS_COLORS_SIZE+1] = {
	Color_BLACK,      // 0
	Color_GRAY,       // 1
	Color_WHITE,      // 2
	Color_RED,        // 3
	Color_MAGENTA,    // 4
	Color_BLUE,       // 5
	Color_GREEN,      // 6
	Color_YELLOW,     // 7
	Color_CYAN,   // 8
	/* BOLD */
	Color_BBLACK,     // a
	Color_BGRAY,      // b
	Color_BWHITE,     // c
	Color_BRED,       // d
	Color_BMAGENTA,   // e
	Color_BBLUE,      // f
	Color_BGREEN,     // g
	Color_BYELLOW,    // h
	Color_BCYAN,  // i
	/* SPECIAL */
	Color_RESET,      // r
	Color_BGBLACK,    //
	Color_BGRED,
	NULL
};

const char *pal_names[CONS_PALETTE_SIZE]={
	"prompt", "address", "default", "changed", "jumps", "calls",
	"push", "trap", "cmp", "ret", "nop", "metadata", "header",
	"printable", "lines0", "lines1", "lines2", "00", "7f", "ff",
	NULL
};

static const char *r_cons_get_color(int ch) {
	if (ch>='0' && ch<='8')
		return r_cons_colors[ch-'0'];
	if (ch>='a' && ch<='i')
		return r_cons_colors['8'-'0'+ch-'a'];
	return NULL;
}

static const char *r_cons_get_color_by_name(const char *str) {
	int i;
	for (i=0;r_cons_color_names[i];i++) {
		if (!strcmp(str, r_cons_color_names[i]))
			return r_cons_colors[i];
	}
	return nullstr;
}

R_API int r_cons_palette_init(const unsigned char *pal) {
	int palstrlen;
	int i,j=1,k;

	if (pal==NULL || pal[0]=='\0') {
		r_cons_printf ("\n=>( Targets ):");
		for (j=0;pal_names[j]&&*pal_names[j];j++)
			r_cons_printf("%s .%s\x1b[0m ", r_cons_palette[j], pal_names[j]);
		r_cons_printf ("\n\n=>( Colors ): "
		"/*normal*/, " "black, = 0, " "gray, = 1, " "white, = 2, " "red, = 3, " "magenta, = 4, "
		"blue, = 5, " "green, = 6, " "yellow, = 7, " "cyan, = 8, " "/*bold*/, " "bblack, = a, "
		"bgray, = b, " "bwhite, = c, " "bred, = d, " "bmagenta, = e, " "bblue, = f, " "bgreen, = g, "
		"byellow, = h, " "bcyan, = i, " "/*special*/, " "reset, = r\n");
		r_cons_printf("\nExample: eval scr.palette = .prompt=3.address=4\n\n");
		return 0;
	}

	palstrlen = strlen((const char *)pal);
	for (i=k=0;i<CONS_PALETTE_SIZE;i++,k++)
		if (j && pal[i]) {
			if (pal[i] == '.') { // che! action!!
				for (j=0;pal_names[j]&&*pal_names[j];j++) {
					int memcmp_len = palstrlen-i-1;
					if (!pal_names[j]) break;
					if (strlen(pal_names[j])<memcmp_len)
						memcmp_len = strlen(pal_names[j]);
					else continue;
				//	printf("CHK %s,%s,%d\n", pal_names[j], pal+i, memcmp_len);
					if (!memcmp(pal_names[j], pal+i+1, memcmp_len -1)) {
						i+=memcmp_len+1;
						if (pal[i] != '=') {
							eprintf ("oops (%c) invalid format string (%s)\n", pal[i], pal+i);
							continue;
						}
				//		printf("KEYWORD FOUND = %s (value = %c)\n", pal_names[j], pal[i+1]);
						strcpy (r_cons_palette[j], r_cons_get_color(pal[i+1]));
					}
				}
			} else {
				const char *ptr = r_cons_get_color(pal[i]);
				if (ptr) strcpy(r_cons_palette[k], ptr);
				else k--;
			}
		} else {
			strcpy (r_cons_palette[i], Color_RESET);
			j = 0;
		}
	return 1;
}

R_API int r_cons_palette_set(const char *key, const char *value) {
	const char *str;
	int i;

	for (i=0;pal_names[i];i++) {
		if (!strcmp (key, pal_names[i])) {
			str = r_cons_get_color_by_name (value);
			if (str != NULL) {
				strcpy (r_cons_palette[i], str);
				return 0;
			}
		}
	}
	return 1;
}
