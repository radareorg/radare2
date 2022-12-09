#include "jsi.h"
#include "jslex.h"
#include "jscompile.h"
#include "jsvalue.h"
#include "utf.h"

#define JSV_ISSTRING(v) (v->type==JS_TSHRSTR || v->type==JS_TMEMSTR || v->type==JS_TLITSTR)
#define JSV_TOSTRING(v) (v->type==JS_TSHRSTR ? v->u.shrstr : v->type==JS_TLITSTR ? v->u.litstr : v->type==JS_TMEMSTR ? v->u.memstr->p : "")

double js_strtol(const char *s, char **p, int base)
{
	/* ascii -> digit value. max base is 36. */
	static const unsigned char table[256] = {
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 80, 80, 80, 80, 80, 80,
		80, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 80, 80, 80, 80, 80,
		80, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
		80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80
	};
	double x;
	unsigned char c;
	if (base == 10)
		for (x = 0, c = *s++; (0 <= c - '0') && (c - '0' < 10); c = *s++)
			x = x * 10 + (c - '0');
	else
		for (x = 0, c = *s++; table[c] < base; c = *s++)
			x = x * base + table[c];
	if (p)
		*p = (char*)s-1;
	return x;
}

int jsV_numbertointeger(double n)
{
	if (n == 0) return 0;
	if (isnan(n)) return 0;
	n = (n < 0) ? -floor(-n) : floor(n);
	if (n < INT_MIN) return INT_MIN;
	if (n > INT_MAX) return INT_MAX;
	return (int)n;
}

int jsV_numbertoint32(double n)
{
	double two32 = 4294967296.0;
	double two31 = 2147483648.0;

	if (!isfinite(n) || n == 0)
		return 0;

	n = fmod(n, two32);
	n = n >= 0 ? floor(n) : ceil(n) + two32;
	if (n >= two31)
		return n - two32;
	else
		return n;
}

unsigned int jsV_numbertouint32(double n)
{
	return (unsigned int)jsV_numbertoint32(n);
}

short jsV_numbertoint16(double n)
{
	return jsV_numbertoint32(n);
}

unsigned short jsV_numbertouint16(double n)
{
	return jsV_numbertoint32(n);
}

/* obj.toString() */
static int jsV_toString(js_State *J, js_Object *obj)
{
	js_pushobject(J, obj);
	js_getproperty(J, -1, "toString");
	if (js_iscallable(J, -1)) {
		js_rot2(J);
		js_call(J, 0);
		if (js_isprimitive(J, -1))
			return 1;
		js_pop(J, 1);
		return 0;
	}
	js_pop(J, 2);
	return 0;
}

/* obj.valueOf() */
static int jsV_valueOf(js_State *J, js_Object *obj)
{
	js_pushobject(J, obj);
	js_getproperty(J, -1, "valueOf");
	if (js_iscallable(J, -1)) {
		js_rot2(J);
		js_call(J, 0);
		if (js_isprimitive(J, -1))
			return 1;
		js_pop(J, 1);
		return 0;
	}
	js_pop(J, 2);
	return 0;
}

/* ToPrimitive() on a value */
void jsV_toprimitive(js_State *J, js_Value *v, int preferred)
{
	js_Object *obj;

	if (v->type != JS_TOBJECT)
		return;

	obj = v->u.object;

	if (preferred == JS_HNONE)
		preferred = obj->type == JS_CDATE ? JS_HSTRING : JS_HNUMBER;

	if (preferred == JS_HSTRING) {
		if (jsV_toString(J, obj) || jsV_valueOf(J, obj)) {
			*v = *js_tovalue(J, -1);
			js_pop(J, 1);
			return;
		}
	} else {
		if (jsV_valueOf(J, obj) || jsV_toString(J, obj)) {
			*v = *js_tovalue(J, -1);
			js_pop(J, 1);
			return;
		}
	}

	if (J->strict)
		js_typeerror(J, "cannot convert object to primitive");

	v->type = JS_TLITSTR;
	v->u.litstr = "[object]";
	return;
}

/* ToBoolean() on a value */
int jsV_toboolean(js_State *J, js_Value *v)
{
	switch (v->type) {
	default:
	case JS_TSHRSTR: return v->u.shrstr[0] != 0;
	case JS_TUNDEFINED: return 0;
	case JS_TNULL: return 0;
	case JS_TBOOLEAN: return v->u.boolean;
	case JS_TNUMBER: return v->u.number != 0 && !isnan(v->u.number);
	case JS_TLITSTR: return v->u.litstr[0] != 0;
	case JS_TMEMSTR: return v->u.memstr->p[0] != 0;
	case JS_TOBJECT: return 1;
	}
}

const char *js_itoa(char *out, int v)
{
	char buf[32], *s = out;
	unsigned int a;
	int i = 0;
	if (v < 0) {
		a = -v;
		*s++ = '-';
	} else {
		a = v;
	}
	while (a) {
		buf[i++] = (a % 10) + '0';
		a /= 10;
	}
	if (i == 0)
		buf[i++] = '0';
	while (i > 0)
		*s++ = buf[--i];
	*s = 0;
	return out;
}

double js_stringtofloat(const char *s, char **ep)
{
	char *end;
	double n;
	const char *e = s;
	int isflt = 0;
	if (*e == '+' || *e == '-') ++e;
	while (*e >= '0' && *e <= '9') ++e;
	if (*e == '.') { ++e; isflt = 1; }
	while (*e >= '0' && *e <= '9') ++e;
	if (*e == 'e' || *e == 'E') {
		++e;
		if (*e == '+' || *e == '-') ++e;
		while (*e >= '0' && *e <= '9') ++e;
		isflt = 1;
	}
	if (isflt)
		n = js_strtod(s, &end);
	else
		n = js_strtol(s, &end, 10);
	if (end == e) {
		*ep = (char*)e;
		return n;
	}
	*ep = (char*)s;
	return 0;
}

/* ToNumber() on a string */
double jsV_stringtonumber(js_State *J, const char *s)
{
	char *e;
	double n;
	while (jsY_iswhite(*s) || jsY_isnewline(*s)) ++s;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && s[2] != 0)
		n = js_strtol(s + 2, &e, 16);
	else if (!strncmp(s, "Infinity", 8))
		n = INFINITY, e = (char*)s + 8;
	else if (!strncmp(s, "+Infinity", 9))
		n = INFINITY, e = (char*)s + 9;
	else if (!strncmp(s, "-Infinity", 9))
		n = -INFINITY, e = (char*)s + 9;
	else
		n = js_stringtofloat(s, &e);
	while (jsY_iswhite(*e) || jsY_isnewline(*e)) ++e;
	if (*e) return NAN;
	return n;
}

/* ToNumber() on a value */
double jsV_tonumber(js_State *J, js_Value *v)
{
	switch (v->type) {
	default:
	case JS_TSHRSTR: return jsV_stringtonumber(J, v->u.shrstr);
	case JS_TUNDEFINED: return NAN;
	case JS_TNULL: return 0;
	case JS_TBOOLEAN: return v->u.boolean;
	case JS_TNUMBER: return v->u.number;
	case JS_TLITSTR: return jsV_stringtonumber(J, v->u.litstr);
	case JS_TMEMSTR: return jsV_stringtonumber(J, v->u.memstr->p);
	case JS_TOBJECT:
		jsV_toprimitive(J, v, JS_HNUMBER);
		return jsV_tonumber(J, v);
	}
}

double jsV_tointeger(js_State *J, js_Value *v)
{
	return jsV_numbertointeger(jsV_tonumber(J, v));
}

/* ToString() on a number */
const char *jsV_numbertostring(js_State *J, char buf[32], double f)
{
	char digits[32], *p = buf, *s = digits;
	int exp, ndigits, point;

	if (f == 0) return "0";
	if (isnan(f)) return "NaN";
	if (isinf(f)) return f < 0 ? "-Infinity" : "Infinity";

	/* Fast case for integers. This only works assuming all integers can be
	 * exactly represented by a float. This is true for 32-bit integers and
	 * 64-bit floats. */
	if (f >= INT_MIN && f <= INT_MAX) {
		int i = (int)f;
		if ((double)i == f)
			return js_itoa(buf, i);
	}

	ndigits = js_grisu2(f, digits, &exp);
	point = ndigits + exp;

	if (signbit(f))
		*p++ = '-';

	if (point < -5 || point > 21) {
		*p++ = *s++;
		if (ndigits > 1) {
			int n = ndigits - 1;
			*p++ = '.';
			while (n--)
				*p++ = *s++;
		}
		js_fmtexp(p, point - 1);
	}

	else if (point <= 0) {
		*p++ = '0';
		*p++ = '.';
		while (point++ < 0)
			*p++ = '0';
		while (ndigits-- > 0)
			*p++ = *s++;
		*p = 0;
	}

	else {
		while (ndigits-- > 0) {
			*p++ = *s++;
			if (--point == 0 && ndigits > 0)
				*p++ = '.';
		}
		while (point-- > 0)
			*p++ = '0';
		*p = 0;
	}

	return buf;
}

/* ToString() on a value */
const char *jsV_tostring(js_State *J, js_Value *v)
{
	char buf[32];
	const char *p;
	switch (v->type) {
	default:
	case JS_TSHRSTR: return v->u.shrstr;
	case JS_TUNDEFINED: return "undefined";
	case JS_TNULL: return "null";
	case JS_TBOOLEAN: return v->u.boolean ? "true" : "false";
	case JS_TLITSTR: return v->u.litstr;
	case JS_TMEMSTR: return v->u.memstr->p;
	case JS_TNUMBER:
		p = jsV_numbertostring(J, buf, v->u.number);
		if (p == buf) {
			int n = strlen(p);
			if (n <= soffsetof(js_Value, type)) {
				char *s = v->u.shrstr;
				while (n--) *s++ = *p++;
				*s = 0;
				v->type = JS_TSHRSTR;
				return v->u.shrstr;
			} else {
				v->u.memstr = jsV_newmemstring(J, p, n);
				v->type = JS_TMEMSTR;
				return v->u.memstr->p;
			}
		}
		return p;
	case JS_TOBJECT:
		jsV_toprimitive(J, v, JS_HSTRING);
		return jsV_tostring(J, v);
	}
}

/* Objects */

static js_Object *jsV_newboolean(js_State *J, int v)
{
	js_Object *obj = jsV_newobject(J, JS_CBOOLEAN, J->Boolean_prototype);
	obj->u.boolean = v;
	return obj;
}

static js_Object *jsV_newnumber(js_State *J, double v)
{
	js_Object *obj = jsV_newobject(J, JS_CNUMBER, J->Number_prototype);
	obj->u.number = v;
	return obj;
}

static js_Object *jsV_newstring(js_State *J, const char *v)
{
	js_Object *obj = jsV_newobject(J, JS_CSTRING, J->String_prototype);
	size_t n = strlen(v);
	if (n < sizeof(obj->u.s.shrstr)) {
		obj->u.s.string = obj->u.s.shrstr;
		memcpy(obj->u.s.shrstr, v, n + 1);
	} else {
		obj->u.s.string = js_strdup(J, v);
	}
	obj->u.s.length = utflen(v);
	return obj;
}

/* ToObject() on a value */
js_Object *jsV_toobject(js_State *J, js_Value *v)
{
	js_Object *o;
	switch (v->type) {
	default:
	case JS_TUNDEFINED: js_typeerror(J, "cannot convert undefined to object");
	case JS_TNULL: js_typeerror(J, "cannot convert null to object");
	case JS_TOBJECT: return v->u.object;
	case JS_TSHRSTR: o = jsV_newstring(J, v->u.shrstr); break;
	case JS_TLITSTR: o = jsV_newstring(J, v->u.litstr); break;
	case JS_TMEMSTR: o = jsV_newstring(J, v->u.memstr->p); break;
	case JS_TBOOLEAN: o = jsV_newboolean(J, v->u.boolean); break;
	case JS_TNUMBER: o = jsV_newnumber(J, v->u.number); break;
	}
	v->type = JS_TOBJECT;
	v->u.object = o;
	return o;
}

void js_newobjectx(js_State *J)
{
	js_Object *prototype = NULL;
	if (js_isobject(J, -1))
		prototype = js_toobject(J, -1);
	js_pop(J, 1);
	js_pushobject(J, jsV_newobject(J, JS_COBJECT, prototype));
}

void js_newobject(js_State *J)
{
	js_pushobject(J, jsV_newobject(J, JS_COBJECT, J->Object_prototype));
}

void js_newarguments(js_State *J)
{
	js_pushobject(J, jsV_newobject(J, JS_CARGUMENTS, J->Object_prototype));
}

void js_newarray(js_State *J)
{
	js_Object *obj = jsV_newobject(J, JS_CARRAY, J->Array_prototype);
	obj->u.a.simple = 1;
	js_pushobject(J, obj);
}

void js_newboolean(js_State *J, int v)
{
	js_pushobject(J, jsV_newboolean(J, v));
}

void js_newnumber(js_State *J, double v)
{
	js_pushobject(J, jsV_newnumber(J, v));
}

void js_newstring(js_State *J, const char *v)
{
	js_pushobject(J, jsV_newstring(J, v));
}

void js_newfunction(js_State *J, js_Function *fun, js_Environment *scope)
{
	js_Object *obj = jsV_newobject(J, JS_CFUNCTION, J->Function_prototype);
	obj->u.f.function = fun;
	obj->u.f.scope = scope;
	js_pushobject(J, obj);
	{
		js_pushnumber(J, fun->numparams);
		js_defproperty(J, -2, "length", JS_READONLY | JS_DONTENUM | JS_DONTCONF);
		js_newobject(J);
		{
			js_copy(J, -2);
			js_defproperty(J, -2, "constructor", JS_DONTENUM);
		}
		js_defproperty(J, -2, "prototype", JS_DONTENUM | JS_DONTCONF);
	}
}

void js_newscript(js_State *J, js_Function *fun, js_Environment *scope)
{
	js_Object *obj = jsV_newobject(J, JS_CSCRIPT, NULL);
	obj->u.f.function = fun;
	obj->u.f.scope = scope;
	js_pushobject(J, obj);
}

void js_newcfunctionx(js_State *J, js_CFunction cfun, const char *name, int length, void *data, js_Finalize finalize)
{
	js_Object *obj = jsV_newobject(J, JS_CCFUNCTION, J->Function_prototype);
	obj->u.c.name = name;
	obj->u.c.function = cfun;
	obj->u.c.constructor = NULL;
	obj->u.c.length = length;
	obj->u.c.data = data;
	obj->u.c.finalize = finalize;
	js_pushobject(J, obj);
	{
		js_pushnumber(J, length);
		js_defproperty(J, -2, "length", JS_READONLY | JS_DONTENUM | JS_DONTCONF);
		js_newobject(J);
		{
			js_copy(J, -2);
			js_defproperty(J, -2, "constructor", JS_DONTENUM);
		}
		js_defproperty(J, -2, "prototype", JS_DONTENUM | JS_DONTCONF);
	}
}

void js_newcfunction(js_State *J, js_CFunction cfun, const char *name, int length)
{
	js_newcfunctionx(J, cfun, name, length, NULL, NULL);
}

/* prototype -- constructor */
void js_newcconstructor(js_State *J, js_CFunction cfun, js_CFunction ccon, const char *name, int length)
{
	js_Object *obj = jsV_newobject(J, JS_CCFUNCTION, J->Function_prototype);
	obj->u.c.name = name;
	obj->u.c.function = cfun;
	obj->u.c.constructor = ccon;
	obj->u.c.length = length;
	js_pushobject(J, obj); /* proto obj */
	{
		js_pushnumber(J, length);
		js_defproperty(J, -2, "length", JS_READONLY | JS_DONTENUM | JS_DONTCONF);
		js_rot2(J); /* obj proto */
		js_copy(J, -2); /* obj proto obj */
		js_defproperty(J, -2, "constructor", JS_DONTENUM);
		js_defproperty(J, -2, "prototype", JS_DONTENUM | JS_DONTCONF);
	}
}

void js_newuserdatax(js_State *J, const char *tag, void *data, js_HasProperty has, js_Put put, js_Delete delete, js_Finalize finalize)
{
	js_Object *prototype = NULL;
	js_Object *obj;

	if (js_isobject(J, -1))
		prototype = js_toobject(J, -1);
	js_pop(J, 1);

	obj = jsV_newobject(J, JS_CUSERDATA, prototype);
	obj->u.user.tag = tag;
	obj->u.user.data = data;
	obj->u.user.has = has;
	obj->u.user.put = put;
	obj->u.user.delete = delete;
	obj->u.user.finalize = finalize;
	js_pushobject(J, obj);
}

void js_newuserdata(js_State *J, const char *tag, void *data, js_Finalize finalize)
{
	js_newuserdatax(J, tag, data, NULL, NULL, NULL, finalize);
}

/* Non-trivial operations on values. These are implemented using the stack. */

int js_instanceof(js_State *J)
{
	js_Object *O, *V;

	if (!js_iscallable(J, -1))
		js_typeerror(J, "instanceof: invalid operand");

	if (!js_isobject(J, -2))
		return 0;

	js_getproperty(J, -1, "prototype");
	if (!js_isobject(J, -1))
		js_typeerror(J, "instanceof: 'prototype' property is not an object");
	O = js_toobject(J, -1);
	js_pop(J, 1);

	V = js_toobject(J, -2);
	while (V) {
		V = V->prototype;
		if (O == V)
			return 1;
	}

	return 0;
}

void js_concat(js_State *J)
{
	js_toprimitive(J, -2, JS_HNONE);
	js_toprimitive(J, -1, JS_HNONE);

	if (js_isstring(J, -2) || js_isstring(J, -1)) {
		const char *sa = js_tostring(J, -2);
		const char *sb = js_tostring(J, -1);
		char * volatile sab = NULL;
		/* TODO: create js_String directly */
		if (js_try(J)) {
			js_free(J, sab);
			js_throw(J);
		}
		sab = js_malloc(J, strlen(sa) + strlen(sb) + 1);
		strcpy(sab, sa);
		strcat(sab, sb);
		js_pop(J, 2);
		js_pushstring(J, sab);
		js_endtry(J);
		js_free(J, sab);
	} else {
		double x = js_tonumber(J, -2);
		double y = js_tonumber(J, -1);
		js_pop(J, 2);
		js_pushnumber(J, x + y);
	}
}

int js_compare(js_State *J, int *okay)
{
	js_toprimitive(J, -2, JS_HNUMBER);
	js_toprimitive(J, -1, JS_HNUMBER);

	*okay = 1;
	if (js_isstring(J, -2) && js_isstring(J, -1)) {
		return strcmp(js_tostring(J, -2), js_tostring(J, -1));
	} else {
		double x = js_tonumber(J, -2);
		double y = js_tonumber(J, -1);
		if (isnan(x) || isnan(y))
			*okay = 0;
		return x < y ? -1 : x > y ? 1 : 0;
	}
}

int js_equal(js_State *J)
{
	js_Value *x = js_tovalue(J, -2);
	js_Value *y = js_tovalue(J, -1);

retry:
	if (JSV_ISSTRING(x) && JSV_ISSTRING(y))
		return !strcmp(JSV_TOSTRING(x), JSV_TOSTRING(y));
	if (x->type == y->type) {
		if (x->type == JS_TUNDEFINED) return 1;
		if (x->type == JS_TNULL) return 1;
		if (x->type == JS_TNUMBER) return x->u.number == y->u.number;
		if (x->type == JS_TBOOLEAN) return x->u.boolean == y->u.boolean;
		if (x->type == JS_TOBJECT) return x->u.object == y->u.object;
		return 0;
	}

	if (x->type == JS_TNULL && y->type == JS_TUNDEFINED) return 1;
	if (x->type == JS_TUNDEFINED && y->type == JS_TNULL) return 1;

	if (x->type == JS_TNUMBER && JSV_ISSTRING(y))
		return x->u.number == jsV_tonumber(J, y);
	if (JSV_ISSTRING(x) && y->type == JS_TNUMBER)
		return jsV_tonumber(J, x) == y->u.number;

	if (x->type == JS_TBOOLEAN) {
		x->type = JS_TNUMBER;
		x->u.number = x->u.boolean ? 1 : 0;
		goto retry;
	}
	if (y->type == JS_TBOOLEAN) {
		y->type = JS_TNUMBER;
		y->u.number = y->u.boolean ? 1 : 0;
		goto retry;
	}
	if ((JSV_ISSTRING(x) || x->type == JS_TNUMBER) && y->type == JS_TOBJECT) {
		jsV_toprimitive(J, y, JS_HNONE);
		goto retry;
	}
	if (x->type == JS_TOBJECT && (JSV_ISSTRING(y) || y->type == JS_TNUMBER)) {
		jsV_toprimitive(J, x, JS_HNONE);
		goto retry;
	}

	return 0;
}

int js_strictequal(js_State *J)
{
	js_Value *x = js_tovalue(J, -2);
	js_Value *y = js_tovalue(J, -1);

	if (JSV_ISSTRING(x) && JSV_ISSTRING(y))
		return !strcmp(JSV_TOSTRING(x), JSV_TOSTRING(y));

	if (x->type != y->type) return 0;
	if (x->type == JS_TUNDEFINED) return 1;
	if (x->type == JS_TNULL) return 1;
	if (x->type == JS_TNUMBER) return x->u.number == y->u.number;
	if (x->type == JS_TBOOLEAN) return x->u.boolean == y->u.boolean;
	if (x->type == JS_TOBJECT) return x->u.object == y->u.object;
	return 0;
}
