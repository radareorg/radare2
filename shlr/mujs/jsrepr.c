#include "jsi.h"
#include "jslex.h"
#include "jsvalue.h"
#include "jsbuiltin.h"
#include "jscompile.h"
#include "utf.h"

static void reprvalue(js_State *J, js_Buffer **sb);

static void reprnum(js_State *J, js_Buffer **sb, double n)
{
	char buf[40];
	if (n == 0 && signbit(n))
		js_puts(J, sb, "-0");
	else
		js_puts(J, sb, jsV_numbertostring(J, buf, n));
}

static void reprstr(js_State *J, js_Buffer **sb, const char *s)
{
	static const char *HEX = "0123456789ABCDEF";
	int i, n;
	Rune c;
	js_putc(J, sb, '"');
	while (*s) {
		n = chartorune(&c, s);
		switch (c) {
		case '"': js_puts(J, sb, "\\\""); break;
		case '\\': js_puts(J, sb, "\\\\"); break;
		case '\b': js_puts(J, sb, "\\b"); break;
		case '\f': js_puts(J, sb, "\\f"); break;
		case '\n': js_puts(J, sb, "\\n"); break;
		case '\r': js_puts(J, sb, "\\r"); break;
		case '\t': js_puts(J, sb, "\\t"); break;
		default:
			if (c < ' ') {
				js_putc(J, sb, '\\');
				js_putc(J, sb, 'x');
				js_putc(J, sb, HEX[(c>>4)&15]);
				js_putc(J, sb, HEX[c&15]);
			} else if (c < 128) {
				js_putc(J, sb, c);
			} else if (c < 0x10000) {
				js_putc(J, sb, '\\');
				js_putc(J, sb, 'u');
				js_putc(J, sb, HEX[(c>>12)&15]);
				js_putc(J, sb, HEX[(c>>8)&15]);
				js_putc(J, sb, HEX[(c>>4)&15]);
				js_putc(J, sb, HEX[c&15]);
			} else {
				for (i = 0; i < n; ++i)
					js_putc(J, sb, s[i]);
			}
			break;
		}
		s += n;
	}
	js_putc(J, sb, '"');
}

#ifndef isalpha
#define isalpha(c) ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
#endif
#ifndef isdigit
#define isdigit(c) (c >= '0' && c <= '9')
#endif

static void reprident(js_State *J, js_Buffer **sb, const char *name)
{
	const char *p = name;
	if (isdigit(*p))
		while (isdigit(*p))
			++p;
	else if (isalpha(*p) || *p == '_')
		while (isdigit(*p) || isalpha(*p) || *p == '_')
			++p;
	if (p > name && *p == 0)
		js_puts(J, sb, name);
	else
		reprstr(J, sb, name);
}

static void reprobject(js_State *J, js_Buffer **sb)
{
	const char *key;
	int i, n;

	n = js_gettop(J) - 1;
	for (i = 0; i < n; ++i) {
		if (js_isobject(J, i)) {
			if (js_toobject(J, i) == js_toobject(J, -1)) {
				js_puts(J, sb, "{}");
				return;
			}
		}
	}

	n = 0;
	js_putc(J, sb, '{');
	js_pushiterator(J, -1, 1);
	while ((key = js_nextiterator(J, -1))) {
		if (n++ > 0)
			js_puts(J, sb, ", ");
		reprident(J, sb, key);
		js_puts(J, sb, ": ");
		js_getproperty(J, -2, key);
		reprvalue(J, sb);
		js_pop(J, 1);
	}
	js_pop(J, 1);
	js_putc(J, sb, '}');
}

static void reprarray(js_State *J, js_Buffer **sb)
{
	int n, i;

	n = js_gettop(J) - 1;
	for (i = 0; i < n; ++i) {
		if (js_isobject(J, i)) {
			if (js_toobject(J, i) == js_toobject(J, -1)) {
				js_puts(J, sb, "[]");
				return;
			}
		}
	}

	js_putc(J, sb, '[');
	n = js_getlength(J, -1);
	for (i = 0; i < n; ++i) {
		if (i > 0)
			js_puts(J, sb, ", ");
		if (js_hasindex(J, -1, i)) {
			reprvalue(J, sb);
			js_pop(J, 1);
		}
	}
	js_putc(J, sb, ']');
}

static void reprfun(js_State *J, js_Buffer **sb, js_Function *fun)
{
	int i;
	js_puts(J, sb, "function ");
	js_puts(J, sb, fun->name);
	js_putc(J, sb, '(');
	for (i = 0; i < fun->numparams; ++i) {
		if (i > 0)
			js_puts(J, sb, ", ");
		js_puts(J, sb, fun->vartab[i]);
	}
	js_puts(J, sb, ") { [byte code] }");
}

static void reprvalue(js_State *J, js_Buffer **sb)
{
	if (js_isundefined(J, -1))
		js_puts(J, sb, "undefined");
	else if (js_isnull(J, -1))
		js_puts(J, sb, "null");
	else if (js_isboolean(J, -1))
		js_puts(J, sb, js_toboolean(J, -1) ? "true" : "false");
	else if (js_isnumber(J, -1))
		reprnum(J, sb, js_tonumber(J, -1));
	else if (js_isstring(J, -1))
		reprstr(J, sb, js_tostring(J, -1));
	else if (js_isobject(J, -1)) {
		js_Object *obj = js_toobject(J, -1);
		switch (obj->type) {
		default:
			reprobject(J, sb);
			break;
		case JS_CARRAY:
			reprarray(J, sb);
			break;
		case JS_CFUNCTION:
		case JS_CSCRIPT:
			reprfun(J, sb, obj->u.f.function);
			break;
		case JS_CCFUNCTION:
			js_puts(J, sb, "function ");
			js_puts(J, sb, obj->u.c.name);
			js_puts(J, sb, "() { [native code] }");
			break;
		case JS_CBOOLEAN:
			js_puts(J, sb, "(new Boolean(");
			js_puts(J, sb, obj->u.boolean ? "true" : "false");
			js_puts(J, sb, "))");
			break;
		case JS_CNUMBER:
			js_puts(J, sb, "(new Number(");
			reprnum(J, sb, obj->u.number);
			js_puts(J, sb, "))");
			break;
		case JS_CSTRING:
			js_puts(J, sb, "(new String(");
			reprstr(J, sb, obj->u.s.string);
			js_puts(J, sb, "))");
			break;
		case JS_CREGEXP:
			js_putc(J, sb, '/');
			js_puts(J, sb, obj->u.r.source);
			js_putc(J, sb, '/');
			if (obj->u.r.flags & JS_REGEXP_G) js_putc(J, sb, 'g');
			if (obj->u.r.flags & JS_REGEXP_I) js_putc(J, sb, 'i');
			if (obj->u.r.flags & JS_REGEXP_M) js_putc(J, sb, 'm');
			break;
		case JS_CDATE:
			{
				char buf[40];
				js_puts(J, sb, "(new Date(");
				js_puts(J, sb, jsV_numbertostring(J, buf, obj->u.number));
				js_puts(J, sb, "))");
			}
			break;
		case JS_CERROR:
			js_puts(J, sb, "(new ");
			js_getproperty(J, -1, "name");
			js_puts(J, sb, js_tostring(J, -1));
			js_pop(J, 1);
			js_putc(J, sb, '(');
			if (js_hasproperty(J, -1, "message")) {
				reprvalue(J, sb);
				js_pop(J, 1);
			}
			js_puts(J, sb, "))");
			break;
		case JS_CMATH:
			js_puts(J, sb, "Math");
			break;
		case JS_CJSON:
			js_puts(J, sb, "JSON");
			break;
		case JS_CITERATOR:
			js_puts(J, sb, "[iterator ");
			break;
		case JS_CUSERDATA:
			js_puts(J, sb, "[userdata ");
			js_puts(J, sb, obj->u.user.tag);
			js_putc(J, sb, ']');
			break;
		}
	}
}

void js_repr(js_State *J, int idx)
{
	js_Buffer *sb = NULL;
	int savebot;

	if (js_try(J)) {
		js_free(J, sb);
		js_throw(J);
	}

	js_copy(J, idx);

	savebot = J->bot;
	J->bot = J->top - 1;
	reprvalue(J, &sb);
	J->bot = savebot;

	js_pop(J, 1);

	js_putc(J, &sb, 0);
	js_pushstring(J, sb ? sb->s : "undefined");

	js_endtry(J);
	js_free(J, sb);
}

const char *js_torepr(js_State *J, int idx)
{
	js_repr(J, idx);
	js_replace(J, idx < 0 ? idx-1 : idx);
	return js_tostring(J, idx);
}

const char *js_tryrepr(js_State *J, int idx, const char *error)
{
	const char *s;
	if (js_try(J)) {
		js_pop(J, 1);
		return error;
	}
	s = js_torepr(J, idx);
	js_endtry(J);
	return s;
}
