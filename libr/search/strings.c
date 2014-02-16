/* radare - LGPL - Copyright 2006-2009 pancake<nopcode.org> */

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
	if (name != NULL)
		for (i=0;encodings[i];i++)
			if (!strcasecmp (name, encodings[i]))
				return i;
	return ENCODING_ASCII;
}

static int is_encoded(int encoding, unsigned char c) {
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
			return 1;
		}
		break;
	}
	return 0;
}

R_API int r_search_strings_update(void *_s, ut64 from, const ut8 *buf, size_t len) {
	RSearch *s = (RSearch *)_s;
	const int enc = 0; // hardcoded
	int i = 0;
	int widechar = 0;
	int matches = 0;
	char str[4096];
	RListIter *iter;
	RSearchKeyword *kw;

	r_list_foreach (s->kws, iter, kw) {
	for (i=0; i<len; i++) {
		char ch = buf[i];
		if (IS_PRINTABLE(ch) || IS_WHITESPACE(ch) || is_encoded (enc, ch)) {
			str[matches] = ch;
			if (matches < sizeof(str))
				matches++;
		} else {
			/* wide char check \x??\x00\x??\x00 */
			if (matches && (i+2 < len) && buf[i+2]=='\0' && buf[i]=='\0' && buf[i+1]!='\0') {
				widechar = 1;
				return 1; // widechar
			}
			/* check if the length fits on our request */
			if (matches >= s->string_min && (s->string_max == 0 || matches <= s->string_max)) {
				str[matches] = '\0';
				size_t len = strlen(str);
				if (len>2) {
					kw->count++;
					if (widechar) {
						ut64 off = (ut64)from+i-(len*2)+1;
						r_search_hit_new (s, kw, off);
					} else {
						ut64 off = (ut64)from+i-matches;
						r_search_hit_new (s, kw, off);
					}
				}
				fflush(stdout);
			}
			matches = 0;
			widechar = 0;
		}
	}
	}
	return 0;
}
#if 0
R_API int r_search_strings_update_char(const ut8 *buf, int min, int max, int enc, ut64 offset, const char *match)
{
	static int widechar = 0;
	static int matches = 0;
	static char str[4096];

	if (IS_PRINTABLE(buf[0]) || is_encoded(enc, buf[0])) {
		str[matches] = buf[0];
		if (matches < sizeof(str))
			matches++;
	} else {
		/* wide char check \x??\x00\x??\x00 */
		if (matches && buf[2]=='\0' && buf[0]=='\0' && buf[1]!='\0') {
			widechar = 1;
			return 1; // widechar
		}
		/* check if the length fits on our request */
		if (matches >= min && (max == 0 || matches <= max)) {
			str[matches] = '\0';
			// XXX Support for 32 and 64 bits here
			if (match && match[0]=='*' && match[1]=='\0') {
				int i,len = strlen(str);
				char msg[32];
				if (len>20) len = 20;
				strcpy(msg, "str_");
				memcpy(msg+4, str, len);
				str[4+len]='\0';
				for(i=4;i<len+4;i++) {
					switch(msg[i]) {
					case ' ':
					case '@':
					case '%':
					case '#':
					case '!':
					case ':':
					case '"':
					case '&':
					case '>':
					case '<':
					case ';':
					case '`':
					case '\'':
						msg[i]='_';
					}
				}

				printf("f %s @ 0x%08x\n", msg, (unsigned int)offset-matches);
			} else {
				if ((!match) || (match && strstr(str, match)) ){
					size_t len = strlen(str);
					if (len>2) {
						if (widechar) {
							ut64 off = offset-(len*2)+1;
							printf("0x%08"PFMT64x" %3d W %s\n", off, len, str);
						} else {
							printf("0x%08"PFMT64x" %3d A %s\n",
								(ut64)offset-matches, len, str);
						}
					}
					fflush(stdout);
				}
			}
		}
		matches = 0;
		widechar = 0;
	}
	return 0;
}
#endif
#if 0

int stripstr_from_file(const char *filename, int min, int max, int encoding, ut64 seek, ut64 limit)
{
	int fd = open(filename, O_RDONLY);
	unsigned char *buf;
	ut64 i = seek;
	ut64 len;

	if (fd == -1) {
		eprintf("Cannot open target file.\n");
		return 1;
	}

	len = lseek(fd, (off_t)0, SEEK_END);

	/* TODO: do not use mmap */
#if __UNIX__
	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, (off_t)0);
	if (((int)buf) == -1 ) {
		perror("mmap");
		return 1;
	}
	if (min <1)
		min = 5;
	max = 0;

	if (limit && limit < len)
		len = limit;

	radare_controlc();
	for(i = (size_t)seek; !config.interrupted && i < len; i++)
		stripstr_iterate(buf+i, i, min, max, encoding, i, "");
	radare_controlc_end();
	
	munmap(buf, len); 
#endif
#if __WINDOWS__
	eprintf("Not yet implemented\n");
#endif
	close(fd);

	return 0;
}
#endif
