/* radare - LGPL - Copyright 2006-2009 pancake<nopcode.org> */

#include "r_search.h"

enum {
	ENCODING_ASCII = 0,
	ENCODING_CP850 = 1
};

static char *encodings[3] = { "ascii", "cp850", NULL };
//static int encoding = ENCODING_ASCII; // default
	//encoding = resolve_encoding(config_get("cfg.encoding"));

int r_search_get_encoding(const char *name)
{
	int i;

	if (name != NULL)
		for(i=0;encodings[i];i++)
			if (!strcasecmp(name, encodings[i]))
				return i;

	return ENCODING_ASCII;
}

static int is_encoded(int encoding, unsigned char c)
{
	switch(encoding) {
	case ENCODING_ASCII:
		break;
	case ENCODING_CP850:
		switch(c) {
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

// XXX last char is lost :(
int r_search_strings_update_char(const u8 *buf, int min, int max, int enc, u64 offset, const char *match)
{
	int i = 0;
	static int widechar = 0;
	static int matches = 0;
	char str[4096];

#define IS_PRINTABLE(x) (x>=' '&&x<='~')

	if (IS_PRINTABLE(buf[i]) || (is_encoded(enc, buf[i]))) {
#if 0
		if (matches == 0)
			offset += i;
#endif
		str[matches] = buf[i];
		if (matches < sizeof(str))
			matches++;
	} else {
		/* wide char check \x??\x00\x??\x00 */
		if (matches && buf[i+2]=='\0' && buf[i]=='\0' && buf[i+1]!='\0') {
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

#if 0
				// XXX THIS IS UGLY AS SHIT
				do {
					flag = flag_get(msg);
					if (flag && flag->offset != (offset-matches))
						strcat(msg, "0");
					else break;
				} while(1);
#endif

				printf("f %s @ 0x%08x\n", msg, (unsigned int)offset-matches);
			} else
			if ((!match) || (match && strstr(str, match)) ){
				int len = strlen(str);
				if (len>2) {
					if (widechar) {
						u64 off = offset-(len*2)+1;
						printf("0x%08llx %3d W %s\n", off, len, str);
					} else {
						printf("0x%08llx %3d A %s\n",
							(u64)offset-matches, len, str); //-matches, len, str);
					}
				}
				fflush(stdout);
			}
		}
		matches = 0;
		widechar = 0;
	}
	return 0;
}
#if 0

int stripstr_from_file(const char *filename, int min, int max, int encoding, u64 seek, u64 limit)
{
	int fd = open(filename, O_RDONLY);
	unsigned char *buf;
	u64 i = seek;
	u64 len;

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
