#include "jsi.h"
#include "jslex.h"
#include "jscompile.h"
#include "jsvalue.h"
#include "jsbuiltin.h"
#include "regexp.h"

static void jsB_globalf(js_State *J, const char *name, js_CFunction cfun, int n)
{
	js_newcfunction(J, cfun, name, n);
	js_defglobal(J, name, JS_DONTENUM);
}

void jsB_propf(js_State *J, const char *name, js_CFunction cfun, int n)
{
	const char *pname = strrchr(name, '.');
	pname = pname ? pname + 1 : name;
	js_newcfunction(J, cfun, name, n);
	js_defproperty(J, -2, pname, JS_DONTENUM);
}

void jsB_propn(js_State *J, const char *name, double number)
{
	js_pushnumber(J, number);
	js_defproperty(J, -2, name, JS_READONLY | JS_DONTENUM | JS_DONTCONF);
}

void jsB_props(js_State *J, const char *name, const char *string)
{
	js_pushliteral(J, string);
	js_defproperty(J, -2, name, JS_DONTENUM);
}

static void jsB_parseInt(js_State *J)
{
	const char *s = js_tostring(J, 1);
	int radix = js_isdefined(J, 2) ? js_tointeger(J, 2) : 0;
	double sign = 1;
	double n;
	char *e;

	while (jsY_iswhite(*s) || jsY_isnewline(*s))
		++s;
	if (*s == '-') {
		++s;
		sign = -1;
	} else if (*s == '+') {
		++s;
	}
	if (radix == 0) {
		radix = 10;
		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
			s += 2;
			radix = 16;
		}
	} else if (radix < 2 || radix > 36) {
		js_pushnumber(J, NAN);
		return;
	}
	n = js_strtol(s, &e, radix);
	if (s == e)
		js_pushnumber(J, NAN);
	else
		js_pushnumber(J, n * sign);
}

static void jsB_parseFloat(js_State *J)
{
	const char *s = js_tostring(J, 1);
	char *e;
	double n;

	while (jsY_iswhite(*s) || jsY_isnewline(*s)) ++s;
	if (!strncmp(s, "Infinity", 8))
		js_pushnumber(J, INFINITY);
	else if (!strncmp(s, "+Infinity", 9))
		js_pushnumber(J, INFINITY);
	else if (!strncmp(s, "-Infinity", 9))
		js_pushnumber(J, -INFINITY);
	else {
		n = js_stringtofloat(s, &e);
		if (e == s)
			js_pushnumber(J, NAN);
		else
			js_pushnumber(J, n);
	}
}

static void jsB_isNaN(js_State *J)
{
	double n = js_tonumber(J, 1);
	js_pushboolean(J, isnan(n));
}

static void jsB_isFinite(js_State *J)
{
	double n = js_tonumber(J, 1);
	js_pushboolean(J, isfinite(n));
}

static void Encode(js_State *J, const char *str_, const char *unescaped)
{
	/* NOTE: volatile to silence GCC warning about longjmp clobbering a variable */
	const char * volatile str = str_;
	js_Buffer *sb = NULL;

	static const char *HEX = "0123456789ABCDEF";

	if (js_try(J)) {
		js_free(J, sb);
		js_throw(J);
	}

	while (*str) {
		int c = (unsigned char) *str++;
		if (strchr(unescaped, c))
			js_putc(J, &sb, c);
		else {
			js_putc(J, &sb, '%');
			js_putc(J, &sb, HEX[(c >> 4) & 0xf]);
			js_putc(J, &sb, HEX[c & 0xf]);
		}
	}
	js_putc(J, &sb, 0);

	js_pushstring(J, sb ? sb->s : "");
	js_endtry(J);
	js_free(J, sb);
}

static void Decode(js_State *J, const char *str_, const char *reserved)
{
	/* NOTE: volatile to silence GCC warning about longjmp clobbering a variable */
	const char * volatile str = str_;
	js_Buffer *sb = NULL;
	int a, b;

	if (js_try(J)) {
		js_free(J, sb);
		js_throw(J);
	}

	while (*str) {
		int c = (unsigned char) *str++;
		if (c != '%')
			js_putc(J, &sb, c);
		else {
			if (!str[0] || !str[1])
				js_urierror(J, "truncated escape sequence");
			a = *str++;
			b = *str++;
			if (!jsY_ishex(a) || !jsY_ishex(b))
				js_urierror(J, "invalid escape sequence");
			c = jsY_tohex(a) << 4 | jsY_tohex(b);
			if (!strchr(reserved, c))
				js_putc(J, &sb, c);
			else {
				js_putc(J, &sb, '%');
				js_putc(J, &sb, a);
				js_putc(J, &sb, b);
			}
		}
	}
	js_putc(J, &sb, 0);

	js_pushstring(J, sb ? sb->s : "");
	js_endtry(J);
	js_free(J, sb);
}

#define URIRESERVED ";/?:@&=+$,"
#define URIALPHA "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define URIDIGIT "0123456789"
#define URIMARK "-_.!~*'()"
#define URIUNESCAPED URIALPHA URIDIGIT URIMARK

static void jsB_decodeURI(js_State *J)
{
	Decode(J, js_tostring(J, 1), URIRESERVED "#");
}

static void jsB_decodeURIComponent(js_State *J)
{
	Decode(J, js_tostring(J, 1), "");
}

static void jsB_encodeURI(js_State *J)
{
	Encode(J, js_tostring(J, 1), URIUNESCAPED URIRESERVED "#");
}

static void jsB_encodeURIComponent(js_State *J)
{
	Encode(J, js_tostring(J, 1), URIUNESCAPED);
}

void jsB_init(js_State *J)
{
	/* Create the prototype objects here, before the constructors */
	J->Object_prototype = jsV_newobject(J, JS_COBJECT, NULL);
	J->Array_prototype = jsV_newobject(J, JS_CARRAY, J->Object_prototype);
	J->Function_prototype = jsV_newobject(J, JS_CCFUNCTION, J->Object_prototype);
	J->Boolean_prototype = jsV_newobject(J, JS_CBOOLEAN, J->Object_prototype);
	J->Number_prototype = jsV_newobject(J, JS_CNUMBER, J->Object_prototype);
	J->String_prototype = jsV_newobject(J, JS_CSTRING, J->Object_prototype);
	J->Date_prototype = jsV_newobject(J, JS_CDATE, J->Object_prototype);

	J->RegExp_prototype = jsV_newobject(J, JS_CREGEXP, J->Object_prototype);
	J->RegExp_prototype->u.r.prog = js_regcompx(J->alloc, J->actx, "(?:)", 0, NULL);
	J->RegExp_prototype->u.r.source = js_strdup(J, "(?:)");

	/* All the native error types */
	J->Error_prototype = jsV_newobject(J, JS_CERROR, J->Object_prototype);
	J->EvalError_prototype = jsV_newobject(J, JS_CERROR, J->Error_prototype);
	J->RangeError_prototype = jsV_newobject(J, JS_CERROR, J->Error_prototype);
	J->ReferenceError_prototype = jsV_newobject(J, JS_CERROR, J->Error_prototype);
	J->SyntaxError_prototype = jsV_newobject(J, JS_CERROR, J->Error_prototype);
	J->TypeError_prototype = jsV_newobject(J, JS_CERROR, J->Error_prototype);
	J->URIError_prototype = jsV_newobject(J, JS_CERROR, J->Error_prototype);

	/* Create the constructors and fill out the prototype objects */
	jsB_initobject(J);
	jsB_initarray(J);
	jsB_initfunction(J);
	jsB_initboolean(J);
	jsB_initnumber(J);
	jsB_initstring(J);
	jsB_initregexp(J);
	jsB_initdate(J);
	jsB_initerror(J);
	jsB_initmath(J);
	jsB_initjson(J);

	/* Initialize the global object */
	js_pushnumber(J, NAN);
	js_defglobal(J, "NaN", JS_READONLY | JS_DONTENUM | JS_DONTCONF);

	js_pushnumber(J, INFINITY);
	js_defglobal(J, "Infinity", JS_READONLY | JS_DONTENUM | JS_DONTCONF);

	js_pushundefined(J);
	js_defglobal(J, "undefined", JS_READONLY | JS_DONTENUM | JS_DONTCONF);

	jsB_globalf(J, "parseInt", jsB_parseInt, 1);
	jsB_globalf(J, "parseFloat", jsB_parseFloat, 1);
	jsB_globalf(J, "isNaN", jsB_isNaN, 1);
	jsB_globalf(J, "isFinite", jsB_isFinite, 1);

	jsB_globalf(J, "decodeURI", jsB_decodeURI, 1);
	jsB_globalf(J, "decodeURIComponent", jsB_decodeURIComponent, 1);
	jsB_globalf(J, "encodeURI", jsB_encodeURI, 1);
	jsB_globalf(J, "encodeURIComponent", jsB_encodeURIComponent, 1);
}
