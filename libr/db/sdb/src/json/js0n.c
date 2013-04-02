// by jeremie miller - 2010
// public domain, contributions/improvements welcome via github

// opportunity to further optimize would be having different jump tables for higher depths

#define HAVE_RAWSTR 0
#define PUSH(i) if(depth == 1) prev = *out++ = ((cur+i) - js)
#define CAP(i) if(depth == 1) prev = *out++ = ((cur+i) - (js + prev) + 1)

int js0n(const unsigned char *js, unsigned int len, unsigned short *out) {
	unsigned short prev = 0;
	const unsigned char *cur, *end;
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
