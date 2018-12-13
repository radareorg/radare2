/* radare - LGPL - Copyright 2006-2018 pancake */

#include "r_search.h"

// TODO: this file needs some love
enum {
	ENCODING_ASCII = 0,
	ENCODING_CP850 = 1
};

static char *encodings[3] = { "ascii", "cp850", NULL };
//static int encoding = ENCODING_ASCII; // default
	//encoding = resolve_encoding(config_get("cfg.encoding"));

R_API int r_search_get_encoding(const char *name) {
	int i;
	if (!name || !*name) {
		return ENCODING_ASCII;
	}
	ut32 lename = strlen (name);
	for (i = 0; encodings[i]; i++) {
		ut32 sz = R_MIN (strlen (encodings[i]), lename);
		if (!r_str_ncasecmp (name, encodings[i], sz)) {
			return i; 
		}
	}
	return ENCODING_ASCII;
}

static bool is_encoded(int encoding, unsigned char c) {
	switch (encoding) {
	case ENCODING_ASCII:
		break;
	case ENCODING_CP850:
		switch (c) {
		// CP850
		case 128: // cedilla
		case 133: // a grave
		case 135: // minicedilla
		case 160: // a acute
		case 161: // i acute
		case 129: // u dieresi
		case 130: // e acute
		case 139: // i dieresi
		case 162: // o acute
		case 163: // u acute
		case 164: // enye
		case 165: // enyemay
		case 181: // A acute
		case 144: // E acute
		case 214: // I acute
		case 224: // O acute
		case 233: // U acute
			return true;
		}
		break;
	}
	return false;
}

R_API int r_search_strings_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	int i = 0;
	int widechar = 0;
	int matches = 0;
	char str[4096];
	RListIter *iter;
	RSearchKeyword *kw;

	r_list_foreach (s->kws, iter, kw) {
		for (i = 0; i < len; i++) {
			char ch = buf[i];
			// non-cp850 encoded
			if (IS_PRINTABLE(ch) || IS_WHITESPACE(ch) || is_encoded (0, ch)) {
				str[matches] = ch;
				if (matches < sizeof (str)) {
					matches++;
				}
			} else {
				/* wide char check \x??\x00\x??\x00 */
				if (matches && i + 2 < len && buf[i+2]=='\0' && buf[i]=='\0' && buf[i+1]!='\0') {
					// widechar = 1;
					return 1; // widechar
				}
				/* check if the length fits on our request */
				if (matches >= s->string_min && (s->string_max == 0 || matches <= s->string_max)) {
					str[matches] = '\0';
					int len = strlen(str);
					if (len>2) {
						if (widechar) {
							ut64 off = (ut64)from+i-(len*2)+1;
							r_search_hit_new (s, kw, off);
						} else {
							ut64 off = (ut64)from+i-matches;
							r_search_hit_new (s, kw, off);
						}
					}
					fflush (stdout);
				}
				matches = 0;
				widechar = 0;
			}
		}
	}
	return 0;
}
