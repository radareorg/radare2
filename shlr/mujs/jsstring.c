#include "jsi.h"
#include "jsvalue.h"
#include "jsbuiltin.h"
#include "utf.h"
#include "regexp.h"

static int js_doregexec(js_State *J, Reprog *prog, const char *string, Resub *sub, int eflags)
{
	int result = js_regexec(prog, string, sub, eflags);
	if (result < 0)
		js_error(J, "regexec failed");
	return result;
}

static const char *checkstring(js_State *J, int idx)
{
	if (!js_iscoercible(J, idx))
		js_typeerror(J, "string function called on null or undefined");
	return js_tostring(J, idx);
}

int js_runeat(js_State *J, const char *s, int i)
{
	Rune rune = EOF;
	while (i-- >= 0) {
		rune = *(unsigned char*)s;
		if (rune < Runeself) {
			if (rune == 0)
				return EOF;
			++s;
		} else
			s += chartorune(&rune, s);
	}
	return rune;
}

const char *js_utfidxtoptr(const char *s, int i)
{
	Rune rune;
	while (i-- > 0) {
		rune = *(unsigned char*)s;
		if (rune < Runeself) {
			if (rune == 0)
				return NULL;
			++s;
		} else
			s += chartorune(&rune, s);
	}
	return s;
}

int js_utfptrtoidx(const char *s, const char *p)
{
	Rune rune;
	int i = 0;
	while (s < p) {
		if (*(unsigned char *)s < Runeself)
			++s;
		else
			s += chartorune(&rune, s);
		++i;
	}
	return i;
}

static void jsB_new_String(js_State *J)
{
	js_newstring(J, js_gettop(J) > 1 ? js_tostring(J, 1) : "");
}

static void jsB_String(js_State *J)
{
	js_pushstring(J, js_gettop(J) > 1 ? js_tostring(J, 1) : "");
}

static void Sp_toString(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CSTRING) js_typeerror(J, "not a string");
	js_pushstring(J, self->u.s.string);
}

static void Sp_valueOf(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CSTRING) js_typeerror(J, "not a string");
	js_pushstring(J, self->u.s.string);
}

static void Sp_charAt(js_State *J)
{
	char buf[UTFmax + 1];
	const char *s = checkstring(J, 0);
	int pos = js_tointeger(J, 1);
	Rune rune = js_runeat(J, s, pos);
	if (rune >= 0) {
		buf[runetochar(buf, &rune)] = 0;
		js_pushstring(J, buf);
	} else {
		js_pushliteral(J, "");
	}
}

static void Sp_charCodeAt(js_State *J)
{
	const char *s = checkstring(J, 0);
	int pos = js_tointeger(J, 1);
	Rune rune = js_runeat(J, s, pos);
	if (rune >= 0)
		js_pushnumber(J, rune);
	else
		js_pushnumber(J, NAN);
}

static void Sp_concat(js_State *J)
{
	int i, top = js_gettop(J);
	int n;
	char * volatile out = NULL;
	const char *s;

	if (top == 1)
		return;

	s = checkstring(J, 0);
	n = 1 + strlen(s);

	if (js_try(J)) {
		js_free(J, out);
		js_throw(J);
	}

	if (n > JS_STRLIMIT)
		js_rangeerror(J, "invalid string length");
	out = js_malloc(J, n);
	strcpy(out, s);

	for (i = 1; i < top; ++i) {
		s = js_tostring(J, i);
		n += strlen(s);
		if (n > JS_STRLIMIT)
			js_rangeerror(J, "invalid string length");
		out = js_realloc(J, out, n);
		strcat(out, s);
	}

	js_pushstring(J, out);
	js_endtry(J);
	js_free(J, out);
}

static void Sp_indexOf(js_State *J)
{
	const char *haystack = checkstring(J, 0);
	const char *needle = js_tostring(J, 1);
	int pos = js_tointeger(J, 2);
	int len = strlen(needle);
	int k = 0;
	Rune rune;
	while (*haystack) {
		if (k >= pos && !strncmp(haystack, needle, len)) {
			js_pushnumber(J, k);
			return;
		}
		haystack += chartorune(&rune, haystack);
		++k;
	}
	js_pushnumber(J, -1);
}

static void Sp_lastIndexOf(js_State *J)
{
	const char *haystack = checkstring(J, 0);
	const char *needle = js_tostring(J, 1);
	int pos = js_isdefined(J, 2) ? js_tointeger(J, 2) : (int)strlen(haystack);
	int len = strlen(needle);
	int k = 0, last = -1;
	Rune rune;
	while (*haystack && k <= pos) {
		if (!strncmp(haystack, needle, len))
			last = k;
		haystack += chartorune(&rune, haystack);
		++k;
	}
	js_pushnumber(J, last);
}

static void Sp_localeCompare(js_State *J)
{
	const char *a = checkstring(J, 0);
	const char *b = js_tostring(J, 1);
	js_pushnumber(J, strcmp(a, b));
}

static void Sp_slice(js_State *J)
{
	const char *str = checkstring(J, 0);
	const char *ss, *ee;
	int len = utflen(str);
	int s = js_tointeger(J, 1);
	int e = js_isdefined(J, 2) ? js_tointeger(J, 2) : len;

	s = s < 0 ? s + len : s;
	e = e < 0 ? e + len : e;

	s = s < 0 ? 0 : s > len ? len : s;
	e = e < 0 ? 0 : e > len ? len : e;

	if (s < e) {
		ss = js_utfidxtoptr(str, s);
		ee = js_utfidxtoptr(ss, e - s);
	} else {
		ss = js_utfidxtoptr(str, e);
		ee = js_utfidxtoptr(ss, s - e);
	}

	js_pushlstring(J, ss, ee - ss);
}

static void Sp_substring(js_State *J)
{
	const char *str = checkstring(J, 0);
	const char *ss, *ee;
	int len = utflen(str);
	int s = js_tointeger(J, 1);
	int e = js_isdefined(J, 2) ? js_tointeger(J, 2) : len;

	s = s < 0 ? 0 : s > len ? len : s;
	e = e < 0 ? 0 : e > len ? len : e;

	if (s < e) {
		ss = js_utfidxtoptr(str, s);
		ee = js_utfidxtoptr(ss, e - s);
	} else {
		ss = js_utfidxtoptr(str, e);
		ee = js_utfidxtoptr(ss, s - e);
	}

	js_pushlstring(J, ss, ee - ss);
}

static void Sp_toLowerCase(js_State *J)
{
	const char *s = checkstring(J, 0);
	char * volatile dst = NULL;
	char *d;
	Rune rune;

	if (js_try(J)) {
		js_free(J, dst);
		js_throw(J);
	}

	d = dst = js_malloc(J, UTFmax * strlen(s) + 1);
	while (*s) {
		s += chartorune(&rune, s);
		rune = tolowerrune(rune);
		d += runetochar(d, &rune);
	}
	*d = 0;

	js_pushstring(J, dst);
	js_endtry(J);
	js_free(J, dst);
}

static void Sp_toUpperCase(js_State *J)
{
	const char *s = checkstring(J, 0);
	char * volatile dst = NULL;
	char *d;
	Rune rune;

	if (js_try(J)) {
		js_free(J, dst);
		js_throw(J);
	}

	d = dst = js_malloc(J, UTFmax * strlen(s) + 1);
	while (*s) {
		s += chartorune(&rune, s);
		rune = toupperrune(rune);
		d += runetochar(d, &rune);
	}
	*d = 0;

	js_pushstring(J, dst);
	js_endtry(J);
	js_free(J, dst);
}

static int istrim(int c)
{
	return c == 0x9 || c == 0xB || c == 0xC || c == 0x20 || c == 0xA0 || c == 0xFEFF ||
		c == 0xA || c == 0xD || c == 0x2028 || c == 0x2029;
}

static void Sp_trim(js_State *J)
{
	const char *s, *e;
	s = checkstring(J, 0);
	while (istrim(*s))
		++s;
	e = s + strlen(s);
	while (e > s && istrim(e[-1]))
		--e;
	js_pushlstring(J, s, e - s);
}

static void S_fromCharCode(js_State *J)
{
	int i, top = js_gettop(J);
	char * volatile s = NULL;
	char *p;
	Rune c;

	if (js_try(J)) {
		js_free(J, s);
		js_throw(J);
	}

	s = p = js_malloc(J, (top-1) * UTFmax + 1);

	for (i = 1; i < top; ++i) {
		c = js_touint32(J, i);
		p += runetochar(p, &c);
	}
	*p = 0;

	js_pushstring(J, s);
	js_endtry(J);
	js_free(J, s);
}

static void Sp_match(js_State *J)
{
	js_Regexp *re;
	const char *text;
	int len;
	const char *a, *b, *c, *e;
	Resub m;

	text = checkstring(J, 0);

	if (js_isregexp(J, 1))
		js_copy(J, 1);
	else if (js_isundefined(J, 1))
		js_newregexp(J, "", 0);
	else
		js_newregexp(J, js_tostring(J, 1), 0);

	re = js_toregexp(J, -1);
	if (!(re->flags & JS_REGEXP_G)) {
		js_RegExp_prototype_exec(J, re, text);
		return;
	}

	re->last = 0;

	js_newarray(J);

	len = 0;
	a = text;
	e = text + strlen(text);
	while (a <= e) {
		if (js_doregexec(J, re->prog, a, &m, a > text ? REG_NOTBOL : 0))
			break;

		b = m.sub[0].sp;
		c = m.sub[0].ep;

		js_pushlstring(J, b, c - b);
		js_setindex(J, -2, len++);

		a = c;
		if (c - b == 0)
			++a;
	}

	if (len == 0) {
		js_pop(J, 1);
		js_pushnull(J);
	}
}

static void Sp_search(js_State *J)
{
	js_Regexp *re;
	const char *text;
	Resub m;

	text = checkstring(J, 0);

	if (js_isregexp(J, 1))
		js_copy(J, 1);
	else if (js_isundefined(J, 1))
		js_newregexp(J, "", 0);
	else
		js_newregexp(J, js_tostring(J, 1), 0);

	re = js_toregexp(J, -1);

	if (!js_doregexec(J, re->prog, text, &m, 0))
		js_pushnumber(J, js_utfptrtoidx(text, m.sub[0].sp));
	else
		js_pushnumber(J, -1);
}

static void Sp_replace_regexp(js_State *J)
{
	js_Regexp *re;
	const char *source, *s, *r;
	js_Buffer *sb = NULL;
	int n, x;
	Resub m;

	source = checkstring(J, 0);
	re = js_toregexp(J, 1);

	if (js_doregexec(J, re->prog, source, &m, 0)) {
		js_copy(J, 0);
		return;
	}

	re->last = 0;

loop:
	s = m.sub[0].sp;
	n = m.sub[0].ep - m.sub[0].sp;

	if (js_iscallable(J, 2)) {
		js_copy(J, 2);
		js_pushundefined(J);
		for (x = 0; m.sub[x].sp; ++x) /* arg 0..x: substring and subexps that matched */
			js_pushlstring(J, m.sub[x].sp, m.sub[x].ep - m.sub[x].sp);
		js_pushnumber(J, s - source); /* arg x+2: offset within search string */
		js_copy(J, 0); /* arg x+3: search string */
		js_call(J, 2 + x);
		r = js_tostring(J, -1);
		js_putm(J, &sb, source, s);
		js_puts(J, &sb, r);
		js_pop(J, 1);
	} else {
		r = js_tostring(J, 2);
		js_putm(J, &sb, source, s);
		while (*r) {
			if (*r == '$') {
				switch (*(++r)) {
				case 0: --r; /* end of string; back up */
				/* fallthrough */
				case '$': js_putc(J, &sb, '$'); break;
				case '`': js_putm(J, &sb, source, s); break;
				case '\'': js_puts(J, &sb, s + n); break;
				case '&':
					js_putm(J, &sb, s, s + n);
					break;
				case '0': case '1': case '2': case '3': case '4':
				case '5': case '6': case '7': case '8': case '9':
					x = *r - '0';
					if (r[1] >= '0' && r[1] <= '9')
						x = x * 10 + *(++r) - '0';
					if (x > 0 && x < m.nsub) {
						js_putm(J, &sb, m.sub[x].sp, m.sub[x].ep);
					} else {
						js_putc(J, &sb, '$');
						if (x > 10) {
							js_putc(J, &sb, '0' + x / 10);
							js_putc(J, &sb, '0' + x % 10);
						} else {
							js_putc(J, &sb, '0' + x);
						}
					}
					break;
				default:
					js_putc(J, &sb, '$');
					js_putc(J, &sb, *r);
					break;
				}
				++r;
			} else {
				js_putc(J, &sb, *r++);
			}
		}
	}

	if (re->flags & JS_REGEXP_G) {
		source = m.sub[0].ep;
		if (n == 0) {
			if (*source)
				js_putc(J, &sb, *source++);
			else
				goto end;
		}
		if (!js_doregexec(J, re->prog, source, &m, REG_NOTBOL))
			goto loop;
	}

end:
	js_puts(J, &sb, s + n);
	js_putc(J, &sb, 0);

	if (js_try(J)) {
		js_free(J, sb);
		js_throw(J);
	}
	js_pushstring(J, sb ? sb->s : "");
	js_endtry(J);
	js_free(J, sb);
}

static void Sp_replace_string(js_State *J)
{
	const char *source, *needle, *s, *r;
	js_Buffer *sb = NULL;
	int n;

	source = checkstring(J, 0);
	needle = js_tostring(J, 1);

	s = strstr(source, needle);
	if (!s) {
		js_copy(J, 0);
		return;
	}
	n = strlen(needle);

	if (js_iscallable(J, 2)) {
		js_copy(J, 2);
		js_pushundefined(J);
		js_pushlstring(J, s, n); /* arg 1: substring that matched */
		js_pushnumber(J, s - source); /* arg 2: offset within search string */
		js_copy(J, 0); /* arg 3: search string */
		js_call(J, 3);
		r = js_tostring(J, -1);
		js_putm(J, &sb, source, s);
		js_puts(J, &sb, r);
		js_puts(J, &sb, s + n);
		js_putc(J, &sb, 0);
		js_pop(J, 1);
	} else {
		r = js_tostring(J, 2);
		js_putm(J, &sb, source, s);
		while (*r) {
			if (*r == '$') {
				switch (*(++r)) {
				case 0: --r; /* end of string; back up */
				/* fallthrough */
				case '$': js_putc(J, &sb, '$'); break;
				case '&': js_putm(J, &sb, s, s + n); break;
				case '`': js_putm(J, &sb, source, s); break;
				case '\'': js_puts(J, &sb, s + n); break;
				default: js_putc(J, &sb, '$'); js_putc(J, &sb, *r); break;
				}
				++r;
			} else {
				js_putc(J, &sb, *r++);
			}
		}
		js_puts(J, &sb, s + n);
		js_putc(J, &sb, 0);
	}

	if (js_try(J)) {
		js_free(J, sb);
		js_throw(J);
	}
	js_pushstring(J, sb ? sb->s : "");
	js_endtry(J);
	js_free(J, sb);
}

static void Sp_replace(js_State *J)
{
	if (js_isregexp(J, 1))
		Sp_replace_regexp(J);
	else
		Sp_replace_string(J);
}

static void Sp_split_regexp(js_State *J)
{
	js_Regexp *re;
	const char *text;
	int limit, len, k;
	const char *p, *a, *b, *c, *e;
	Resub m;

	text = checkstring(J, 0);
	re = js_toregexp(J, 1);
	limit = js_isdefined(J, 2) ? js_tointeger(J, 2) : 1 << 30;

	js_newarray(J);
	len = 0;

	e = text + strlen(text);

	/* splitting the empty string */
	if (e == text) {
		if (js_doregexec(J, re->prog, text, &m, 0)) {
			if (len == limit) return;
			js_pushliteral(J, "");
			js_setindex(J, -2, 0);
		}
		return;
	}

	p = a = text;
	while (a < e) {
		if (js_doregexec(J, re->prog, a, &m, a > text ? REG_NOTBOL : 0))
			break; /* no match */

		b = m.sub[0].sp;
		c = m.sub[0].ep;

		/* empty string at end of last match */
		if (b == p) {
			++a;
			continue;
		}

		if (len == limit) return;
		js_pushlstring(J, p, b - p);
		js_setindex(J, -2, len++);

		for (k = 1; k < m.nsub; ++k) {
			if (len == limit) return;
			js_pushlstring(J, m.sub[k].sp, m.sub[k].ep - m.sub[k].sp);
			js_setindex(J, -2, len++);
		}

		a = p = c;
	}

	if (len == limit) return;
	js_pushstring(J, p);
	js_setindex(J, -2, len);
}

static void Sp_split_string(js_State *J)
{
	const char *str = checkstring(J, 0);
	const char *sep = js_tostring(J, 1);
	int limit = js_isdefined(J, 2) ? js_tointeger(J, 2) : 1 << 30;
	int i, n;

	js_newarray(J);

	n = strlen(sep);

	/* empty string */
	if (n == 0) {
		Rune rune;
		for (i = 0; *str && i < limit; ++i) {
			n = chartorune(&rune, str);
			js_pushlstring(J, str, n);
			js_setindex(J, -2, i);
			str += n;
		}
		return;
	}

	for (i = 0; str && i < limit; ++i) {
		const char *s = strstr(str, sep);
		if (s) {
			js_pushlstring(J, str, s-str);
			js_setindex(J, -2, i);
			str = s + n;
		} else {
			js_pushstring(J, str);
			js_setindex(J, -2, i);
			str = NULL;
		}
	}
}

static void Sp_split(js_State *J)
{
	if (js_isundefined(J, 1)) {
		js_newarray(J);
		js_pushstring(J, js_tostring(J, 0));
		js_setindex(J, -2, 0);
	} else if (js_isregexp(J, 1)) {
		Sp_split_regexp(J);
	} else {
		Sp_split_string(J);
	}
}

void jsB_initstring(js_State *J)
{
	J->String_prototype->u.s.shrstr[0] = 0;
	J->String_prototype->u.s.string = J->String_prototype->u.s.shrstr;
	J->String_prototype->u.s.length = 0;

	js_pushobject(J, J->String_prototype);
	{
		jsB_propf(J, "String.prototype.toString", Sp_toString, 0);
		jsB_propf(J, "String.prototype.valueOf", Sp_valueOf, 0);
		jsB_propf(J, "String.prototype.charAt", Sp_charAt, 1);
		jsB_propf(J, "String.prototype.charCodeAt", Sp_charCodeAt, 1);
		jsB_propf(J, "String.prototype.concat", Sp_concat, 0); /* 1 */
		jsB_propf(J, "String.prototype.indexOf", Sp_indexOf, 1);
		jsB_propf(J, "String.prototype.lastIndexOf", Sp_lastIndexOf, 1);
		jsB_propf(J, "String.prototype.localeCompare", Sp_localeCompare, 1);
		jsB_propf(J, "String.prototype.match", Sp_match, 1);
		jsB_propf(J, "String.prototype.replace", Sp_replace, 2);
		jsB_propf(J, "String.prototype.search", Sp_search, 1);
		jsB_propf(J, "String.prototype.slice", Sp_slice, 2);
		jsB_propf(J, "String.prototype.split", Sp_split, 2);
		jsB_propf(J, "String.prototype.substring", Sp_substring, 2);
		jsB_propf(J, "String.prototype.toLowerCase", Sp_toLowerCase, 0);
		jsB_propf(J, "String.prototype.toLocaleLowerCase", Sp_toLowerCase, 0);
		jsB_propf(J, "String.prototype.toUpperCase", Sp_toUpperCase, 0);
		jsB_propf(J, "String.prototype.toLocaleUpperCase", Sp_toUpperCase, 0);

		/* ES5 */
		jsB_propf(J, "String.prototype.trim", Sp_trim, 0);
	}
	js_newcconstructor(J, jsB_String, jsB_new_String, "String", 0); /* 1 */
	{
		jsB_propf(J, "String.fromCharCode", S_fromCharCode, 0); /* 1 */
	}
	js_defglobal(J, "String", JS_DONTENUM);
}
