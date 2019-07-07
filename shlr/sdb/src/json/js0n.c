// by jeremie miller - 2010-2018
// public domain, contributions/improvements welcome via github

// opportunity to further optimize would be having different jump tables for higher depths

#include "rangstr.h"

#define PUSH(i) if(depth == 1) prev = *out++ = ((cur+i) - js)
#define CAP(i) if(depth == 1) prev = *out++ = ((cur+i) - (js + prev) + 1)

#ifdef _MSC_VER
#define HAVE_COMPUTED_GOTOS 0
#elif __EMSCRIPTEN__
#define HAVE_COMPUTED_GOTOS 0
#else
#define HAVE_COMPUTED_GOTOS 1
#endif

#if HAVE_COMPUTED_GOTOS

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"

#define HAVE_RAWSTR 0

int sdb_js0n(const ut8 *js, RangstrType len, RangstrType *out) {
	ut32 prev = 0;
	const ut8 *cur, *end;
	int depth = 0, utf8_remain = 0;
	static void *gostruct[] = {
		[0 ... 255] = &&l_bad,
		['\t'] = &&l_loop, [' '] = &&l_loop, ['\r'] = &&l_loop, ['\n'] = &&l_loop,
		['"'] = &&l_qup,
		[':'] = &&l_loop, [','] = &&l_loop,
		['['] = &&l_up, [']'] = &&l_down, // tracking [] and {} individually would allow fuller validation but is really messy
		['{'] = &&l_up, ['}'] = &&l_down,
//TODO: add support for rawstrings 
#if HAVE_RAWSTR
		['a'...'z'] = &&l_rawstr,
#else
		['-'] = &&l_bare, [48 ... 57] = &&l_bare, // 0-9
		['t'] = &&l_bare, ['f'] = &&l_bare, ['n'] = &&l_bare // true, false, null
#endif
	};
	static void *gobare[] = {
		[0 ... 31] = &&l_bad,
		[32 ... 126] = &&l_loop, // could be more pedantic/validation-checking
		['\t'] = &&l_unbare, [' '] = &&l_unbare, ['\r'] = &&l_unbare, ['\n'] = &&l_unbare,
		[','] = &&l_unbare, [']'] = &&l_unbare, ['}'] = &&l_unbare,
		[127 ... 255] = &&l_bad
	};
#if HAVE_RAWSTR
	static void *gorawstr[] = {
		[0 ... 31] = &&l_bad, [127] = &&l_bad,
		[32 ... 126] = &&l_loop,
		['\\'] = &&l_esc, [':'] = &&l_qdown,
		[128 ... 191] = &&l_bad,
		[192 ... 223] = &&l_utf8_2,
		[224 ... 239] = &&l_utf8_3,
		[240 ... 247] = &&l_utf8_4,
		[248 ... 255] = &&l_bad
	};
#endif
	static void *gostring[] = {
		[0 ... 31] = &&l_bad, [127] = &&l_bad,
		[32 ... 126] = &&l_loop,
		['\\'] = &&l_esc, ['"'] = &&l_qdown,
		[128 ... 191] = &&l_bad,
		[192 ... 223] = &&l_utf8_2,
		[224 ... 239] = &&l_utf8_3,
		[240 ... 247] = &&l_utf8_4,
		[248 ... 255] = &&l_bad
	};
	static void *goutf8_continue[] = {
		[0 ... 127] = &&l_bad,
		[128 ... 191] = &&l_utf_continue,
		[192 ... 255] = &&l_bad
	};
	static void *goesc[] = {
		[0 ... 255] = &&l_bad,
		['"'] = &&l_unesc, ['\\'] = &&l_unesc, ['/'] = &&l_unesc, ['b'] = &&l_unesc,
		['f'] = &&l_unesc, ['n'] = &&l_unesc, ['r'] = &&l_unesc, ['t'] = &&l_unesc, ['u'] = &&l_unesc
	};
	static void **go = gostruct;
	
#if 0 
printf ("                 gostrct= %p\n", gostruct);
printf ("                 gobare = %p\n", gobare);
printf ("                 gostr = %p\n", gostring);
printf ("                 goesc = %p\n", goesc);
printf ("                 goutf8= %p\n", goutf8_continue);
#endif
	for (cur=js, end = js+len; cur<end; cur++) {
//printf (" --> %s %p\n", cur, go[*cur]);
		goto *go[*cur];
l_loop:;
	}
	return depth; // 0 if successful full parse, >0 for incomplete data
l_bad:
	return 1;
l_up:
	PUSH(0);
	++depth;
	goto l_loop;
l_down:
	--depth;
	CAP (0);
	goto l_loop;
l_qup:
	PUSH (1);
	go = gostring;
	goto l_loop;
l_qdown:
	CAP (-1);
	go = gostruct;
	goto l_loop;
l_esc:
	go = goesc;
	goto l_loop;
l_unesc:
	go = gostring;
	goto l_loop;
#if HAVE_RAWSTR
l_rawstr:
	PUSH (0);
	go = gorawstr;
	goto l_loop;
#endif
l_bare:
	PUSH (0);
	go = gobare;
	goto l_loop;
l_unbare:
	CAP (-1);
	go = gostruct;
	goto *go[*cur];
l_utf8_2:
	go = goutf8_continue;
	utf8_remain = 1;
	goto l_loop;
l_utf8_3:
	go = goutf8_continue;
	utf8_remain = 2;
	goto l_loop;
l_utf8_4:
	go = goutf8_continue;
	utf8_remain = 3;
	goto l_loop;
l_utf_continue:
	if (!--utf8_remain)
		go = gostring;
	goto l_loop;
}

#else // HAVE_COMPUTED_GOTOS

#define GO_DOWN (1)
#define GO_UP (1 << 1)
#define GO_Q_DOWN (1 << 2)
#define GO_Q_UP (1 << 3)
#define GO_BARE (1 << 4)
#define GO_UNBARE (1 << 5)
#define GO_ESCAPE (1 << 6)
#define GO_UNESCAPE (1 << 7)
#define GO_UTF8 (1 << 8)
#define GO_UTF8_CONTINUE (1 << 9)
int sdb_js0n(const ut8 *js, RangstrType len, RangstrType *out) {
	ut32 prev = 0;
	const ut8 *cur, *end;
	int depth = 0, utf8_remain = 0, what_did = 1;
	for (cur = js, end = js + len; cur < end; cur++) {
		if (what_did & GO_BARE) {
			switch (*cur) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
			case ',':
			case ']':
			case '}':
				what_did = GO_UNBARE;
				CAP (-1);
				break;
			default:
				if (*cur >= 32 && *cur <= 126) {
					continue;
				}
				return 1;
			}
			// Same *cur
		}
		if (what_did & GO_UTF8) {
			if (*cur < 128 || (*cur >=192 && *cur <= 255)) {
				return 1;
			}
			if (!--utf8_remain) {
				what_did = GO_UTF8_CONTINUE;
			}
			continue;
		}
		if (what_did & GO_ESCAPE) {
			switch (*cur) {
			case '"':
			case '\\':
			case '/':
			case 'b':
			case 'f':
			case 'n':
			case 'r':
			case 't':
			case 'u':
				what_did = GO_UNESCAPE;
				break;
			default:
				return 1;
			}
			continue;
		}
		if (what_did & GO_Q_UP || what_did & GO_UTF8_CONTINUE || what_did & GO_UNESCAPE) {
			switch (*cur) {
			case '\\':
				what_did = GO_ESCAPE;
				break;
			case '"':
				what_did = GO_Q_DOWN;
				CAP (-1);
				break;
			default:
				if (*cur <= 31 || (*cur >= 127 && *cur <= 191) || (*cur >= 248 && *cur <= 255)) {
					return 1;
				}
				if (*cur < 127) {
					continue;
				}
				what_did = GO_UTF8;
				if (*cur < 224) {
					utf8_remain = 1;
					continue;
				}
				if (*cur < 239) {
					utf8_remain = 2;
					continue;
				}
				utf8_remain = 3;
				break;
			}
			continue;
		}
		switch (*cur) {
			case '\t':
			case ' ':
			case '\r':
			case '\n':
			case ',':
			case ':':
				break;
			case '"':
				PUSH (1);
				what_did = GO_Q_UP;
				break;
			case '[':
			case '{':
				PUSH (0);
				++depth;
				what_did = GO_UP;
				break;
			case ']':
			case '}':
				--depth;
				CAP (0);
				what_did = GO_DOWN;
				break;
			case '-':
			case 't':
			case 'f':
			case 'n':
				what_did = GO_BARE;
				PUSH (0);
				break;
			default:
				if (*cur >= 48 && *cur  <= 57) { // 0-9
					what_did = GO_BARE;
					PUSH (0);
					break;
				}
				return 1;
		}
	}
	return depth;
}
#endif // HAVE_COMPUTED_GOTOS
