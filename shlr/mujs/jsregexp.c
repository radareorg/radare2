#include "jsi.h"
#include "jsvalue.h"
#include "jsbuiltin.h"
#include "regexp.h"

static char *escaperegexp(js_State *J, const char *pattern) {
	char *copy, *p;
	const char *s;
	int n = 0;
	for (s = pattern; *s; ++s) {
		if (*s == '/')
			++n;
		++n;
	}
	copy = p = js_malloc(J, n+1);
	for (s = pattern; *s; ++s) {
		if (*s == '/')
			*p++ = '\\';
		*p++ = *s;
	}
	*p = 0;
	return copy;
}

static void js_newregexpx(js_State *J, const char *pattern, int flags, int is_clone)
{
	const char *error;
	js_Object *obj;
	Reprog *prog;
	int opts;

	obj = jsV_newobject(J, JS_CREGEXP, J->RegExp_prototype);

	opts = 0;
	if (flags & JS_REGEXP_I) opts |= REG_ICASE;
	if (flags & JS_REGEXP_M) opts |= REG_NEWLINE;

	prog = js_regcompx(J->alloc, J->actx, pattern, opts, &error);
	if (!prog)
		js_syntaxerror(J, "regular expression: %s", error);

	obj->u.r.prog = prog;
	obj->u.r.source = is_clone ? js_strdup(J, pattern) : escaperegexp(J, pattern);
	obj->u.r.flags = flags;
	obj->u.r.last = 0;
	js_pushobject(J, obj);
}

void js_newregexp(js_State *J, const char *pattern, int flags)
{
	js_newregexpx(J, pattern, flags, 0);
}

void js_RegExp_prototype_exec(js_State *J, js_Regexp *re, const char *text)
{
	const char *haystack;
	int result;
	int i;
	int opts;
	Resub m;

	haystack = text;
	opts = 0;
	if (re->flags & JS_REGEXP_G) {
		if (re->last > strlen(haystack)) {
			re->last = 0;
			js_pushnull(J);
			return;
		}
		if (re->last > 0) {
			haystack = text + re->last;
			opts |= REG_NOTBOL;
		}
	}

	result = js_regexec(re->prog, haystack, &m, opts);
	if (result < 0)
		js_error(J, "regexec failed");
	if (result == 0) {
		js_newarray(J);
		js_pushstring(J, text);
		js_setproperty(J, -2, "input");
		js_pushnumber(J, js_utfptrtoidx(text, m.sub[0].sp));
		js_setproperty(J, -2, "index");
		for (i = 0; i < m.nsub; ++i) {
			js_pushlstring(J, m.sub[i].sp, m.sub[i].ep - m.sub[i].sp);
			js_setindex(J, -2, i);
		}
		if (re->flags & JS_REGEXP_G)
			re->last = m.sub[0].ep - text;
		return;
	}

	if (re->flags & JS_REGEXP_G)
		re->last = 0;

	js_pushnull(J);
}

static void Rp_test(js_State *J)
{
	js_Regexp *re;
	const char *text;
	int result;
	int opts;
	Resub m;

	re = js_toregexp(J, 0);
	text = js_tostring(J, 1);

	opts = 0;
	if (re->flags & JS_REGEXP_G) {
		if (re->last > strlen(text)) {
			re->last = 0;
			js_pushboolean(J, 0);
			return;
		}
		if (re->last > 0) {
			text += re->last;
			opts |= REG_NOTBOL;
		}
	}

	result = js_regexec(re->prog, text, &m, opts);
	if (result < 0)
		js_error(J, "regexec failed");
	if (result == 0) {
		if (re->flags & JS_REGEXP_G)
			re->last = re->last + (m.sub[0].ep - text);
		js_pushboolean(J, 1);
		return;
	}

	if (re->flags & JS_REGEXP_G)
		re->last = 0;

	js_pushboolean(J, 0);
}

static void jsB_new_RegExp(js_State *J)
{
	js_Regexp *old;
	const char *pattern;
	int flags;
	int is_clone = 0;

	if (js_isregexp(J, 1)) {
		if (js_isdefined(J, 2))
			js_typeerror(J, "cannot supply flags when creating one RegExp from another");
		old = js_toregexp(J, 1);
		pattern = old->source;
		flags = old->flags;
		is_clone = 1;
	} else if (js_isundefined(J, 1)) {
		pattern = "(?:)";
		flags = 0;
	} else {
		pattern = js_tostring(J, 1);
		flags = 0;
	}

	if (strlen(pattern) == 0)
		pattern = "(?:)";

	if (js_isdefined(J, 2)) {
		const char *s = js_tostring(J, 2);
		int g = 0, i = 0, m = 0;
		while (*s) {
			if (*s == 'g') ++g;
			else if (*s == 'i') ++i;
			else if (*s == 'm') ++m;
			else js_syntaxerror(J, "invalid regular expression flag: '%c'", *s);
			++s;
		}
		if (g > 1) js_syntaxerror(J, "invalid regular expression flag: 'g'");
		if (i > 1) js_syntaxerror(J, "invalid regular expression flag: 'i'");
		if (m > 1) js_syntaxerror(J, "invalid regular expression flag: 'm'");
		if (g) flags |= JS_REGEXP_G;
		if (i) flags |= JS_REGEXP_I;
		if (m) flags |= JS_REGEXP_M;
	}

	js_newregexpx(J, pattern, flags, is_clone);
}

static void jsB_RegExp(js_State *J)
{
	if (js_isregexp(J, 1))
		return;
	jsB_new_RegExp(J);
}

static void Rp_toString(js_State *J)
{
	js_Regexp *re;
	char * volatile out = NULL;

	re = js_toregexp(J, 0);

	if (js_try(J)) {
		js_free(J, out);
		js_throw(J);
	}

	out = js_malloc(J, strlen(re->source) + 6); /* extra space for //gim */
	strcpy(out, "/");
	strcat(out, re->source);
	strcat(out, "/");
	if (re->flags & JS_REGEXP_G) strcat(out, "g");
	if (re->flags & JS_REGEXP_I) strcat(out, "i");
	if (re->flags & JS_REGEXP_M) strcat(out, "m");

	js_pop(J, 0);
	js_pushstring(J, out);
	js_endtry(J);
	js_free(J, out);
}

static void Rp_exec(js_State *J)
{
	js_RegExp_prototype_exec(J, js_toregexp(J, 0), js_tostring(J, 1));
}

void jsB_initregexp(js_State *J)
{
	js_pushobject(J, J->RegExp_prototype);
	{
		jsB_propf(J, "RegExp.prototype.toString", Rp_toString, 0);
		jsB_propf(J, "RegExp.prototype.test", Rp_test, 0);
		jsB_propf(J, "RegExp.prototype.exec", Rp_exec, 0);
	}
	js_newcconstructor(J, jsB_RegExp, jsB_new_RegExp, "RegExp", 1);
	js_defglobal(J, "RegExp", JS_DONTENUM);
}
