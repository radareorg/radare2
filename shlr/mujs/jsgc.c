#include "jsi.h"
#include "jscompile.h"
#include "jsvalue.h"
#include "jsrun.h"

#include "regexp.h"

static void jsG_freeenvironment(js_State *J, js_Environment *env)
{
	js_free(J, env);
}

static void jsG_freefunction(js_State *J, js_Function *fun)
{
	js_free(J, fun->funtab);
	js_free(J, fun->vartab);
	js_free(J, fun->code);
	js_free(J, fun);
}

static void jsG_freeproperty(js_State *J, js_Property *node)
{
	if (node->left->level) jsG_freeproperty(J, node->left);
	if (node->right->level) jsG_freeproperty(J, node->right);
	js_free(J, node);
}

static void jsG_freeiterator(js_State *J, js_Iterator *node)
{
	while (node) {
		js_Iterator *next = node->next;
		js_free(J, node);
		node = next;
	}
}

static void jsG_freeobject(js_State *J, js_Object *obj)
{
	if (obj->properties->level)
		jsG_freeproperty(J, obj->properties);
	if (obj->type == JS_CREGEXP) {
		js_free(J, obj->u.r.source);
		js_regfreex(J->alloc, J->actx, obj->u.r.prog);
	}
	if (obj->type == JS_CSTRING) {
		if (obj->u.s.string != obj->u.s.shrstr)
			js_free(J, obj->u.s.string);
	}
	if (obj->type == JS_CARRAY && obj->u.a.simple)
		js_free(J, obj->u.a.array);
	if (obj->type == JS_CITERATOR)
		jsG_freeiterator(J, obj->u.iter.head);
	if (obj->type == JS_CUSERDATA && obj->u.user.finalize)
		obj->u.user.finalize(J, obj->u.user.data);
	if (obj->type == JS_CCFUNCTION && obj->u.c.finalize)
		obj->u.c.finalize(J, obj->u.c.data);
	js_free(J, obj);
}

/* Mark and add object to scan queue */
static void jsG_markobject(js_State *J, int mark, js_Object *obj)
{
	obj->gcmark = mark;
	obj->gcroot = J->gcroot;
	J->gcroot = obj;
}

static void jsG_markfunction(js_State *J, int mark, js_Function *fun)
{
	int i;
	fun->gcmark = mark;
	for (i = 0; i < fun->funlen; ++i)
		if (fun->funtab[i]->gcmark != mark)
			jsG_markfunction(J, mark, fun->funtab[i]);
}

static void jsG_markenvironment(js_State *J, int mark, js_Environment *env)
{
	do {
		env->gcmark = mark;
		if (env->variables->gcmark != mark)
			jsG_markobject(J, mark, env->variables);
		env = env->outer;
	} while (env && env->gcmark != mark);
}

static void jsG_markproperty(js_State *J, int mark, js_Property *node)
{
	if (node->left->level) jsG_markproperty(J, mark, node->left);
	if (node->right->level) jsG_markproperty(J, mark, node->right);

	if (node->value.type == JS_TMEMSTR && node->value.u.memstr->gcmark != mark)
		node->value.u.memstr->gcmark = mark;
	if (node->value.type == JS_TOBJECT && node->value.u.object->gcmark != mark)
		jsG_markobject(J, mark, node->value.u.object);
	if (node->getter && node->getter->gcmark != mark)
		jsG_markobject(J, mark, node->getter);
	if (node->setter && node->setter->gcmark != mark)
		jsG_markobject(J, mark, node->setter);
}

/* Mark everything the object can reach. */
static void jsG_scanobject(js_State *J, int mark, js_Object *obj)
{
	if (obj->properties->level)
		jsG_markproperty(J, mark, obj->properties);
	if (obj->prototype && obj->prototype->gcmark != mark)
		jsG_markobject(J, mark, obj->prototype);
	if (obj->type == JS_CARRAY && obj->u.a.simple) {
		int i;
		for (i = 0; i < obj->u.a.length; ++i) {
			js_Value *v = &obj->u.a.array[i];
			if (v->type == JS_TMEMSTR && v->u.memstr->gcmark != mark)
				v->u.memstr->gcmark = mark;
			if (v->type == JS_TOBJECT && v->u.object->gcmark != mark)
				jsG_markobject(J, mark, v->u.object);
		}
	}
	if (obj->type == JS_CITERATOR && obj->u.iter.target->gcmark != mark) {
		jsG_markobject(J, mark, obj->u.iter.target);
	}
	if (obj->type == JS_CFUNCTION || obj->type == JS_CSCRIPT) {
		if (obj->u.f.scope && obj->u.f.scope->gcmark != mark)
			jsG_markenvironment(J, mark, obj->u.f.scope);
		if (obj->u.f.function && obj->u.f.function->gcmark != mark)
			jsG_markfunction(J, mark, obj->u.f.function);
	}
}

static void jsG_markstack(js_State *J, int mark)
{
	js_Value *v = J->stack;
	int n = J->top;
	while (n--) {
		if (v->type == JS_TMEMSTR && v->u.memstr->gcmark != mark)
			v->u.memstr->gcmark = mark;
		if (v->type == JS_TOBJECT && v->u.object->gcmark != mark)
			jsG_markobject(J, mark, v->u.object);
		++v;
	}
}

void js_gc(js_State *J, int report)
{
	js_Function *fun, *nextfun, **prevnextfun;
	js_Object *obj, *nextobj, **prevnextobj;
	js_String *str, *nextstr, **prevnextstr;
	js_Environment *env, *nextenv, **prevnextenv;
	unsigned int nenv = 0, nfun = 0, nobj = 0, nstr = 0, nprop = 0;
	unsigned int genv = 0, gfun = 0, gobj = 0, gstr = 0, gprop = 0;
	int mark;
	int i;

	if (J->gcpause) {
		if (report)
			js_report(J, "garbage collector is paused");
		return;
	}

	mark = J->gcmark = J->gcmark == 1 ? 2 : 1;

	/* Add initial roots. */

	jsG_markobject(J, mark, J->Object_prototype);
	jsG_markobject(J, mark, J->Array_prototype);
	jsG_markobject(J, mark, J->Function_prototype);
	jsG_markobject(J, mark, J->Boolean_prototype);
	jsG_markobject(J, mark, J->Number_prototype);
	jsG_markobject(J, mark, J->String_prototype);
	jsG_markobject(J, mark, J->RegExp_prototype);
	jsG_markobject(J, mark, J->Date_prototype);

	jsG_markobject(J, mark, J->Error_prototype);
	jsG_markobject(J, mark, J->EvalError_prototype);
	jsG_markobject(J, mark, J->RangeError_prototype);
	jsG_markobject(J, mark, J->ReferenceError_prototype);
	jsG_markobject(J, mark, J->SyntaxError_prototype);
	jsG_markobject(J, mark, J->TypeError_prototype);
	jsG_markobject(J, mark, J->URIError_prototype);

	jsG_markobject(J, mark, J->R);
	jsG_markobject(J, mark, J->G);

	jsG_markstack(J, mark);

	jsG_markenvironment(J, mark, J->E);
	jsG_markenvironment(J, mark, J->GE);
	for (i = 0; i < J->envtop; ++i)
		jsG_markenvironment(J, mark, J->envstack[i]);

	/* Scan objects until none remain. */

	while ((obj = J->gcroot) != NULL) {
		J->gcroot = obj->gcroot;
		obj->gcroot = NULL;
		jsG_scanobject(J, mark, obj);
	}

	/* Free everything not marked. */

	prevnextenv = &J->gcenv;
	for (env = J->gcenv; env; env = nextenv) {
		nextenv = env->gcnext;
		if (env->gcmark != mark) {
			*prevnextenv = nextenv;
			jsG_freeenvironment(J, env);
			++genv;
		} else {
			prevnextenv = &env->gcnext;
		}
		++nenv;
	}

	prevnextfun = &J->gcfun;
	for (fun = J->gcfun; fun; fun = nextfun) {
		nextfun = fun->gcnext;
		if (fun->gcmark != mark) {
			*prevnextfun = nextfun;
			jsG_freefunction(J, fun);
			++gfun;
		} else {
			prevnextfun = &fun->gcnext;
		}
		++nfun;
	}

	prevnextobj = &J->gcobj;
	for (obj = J->gcobj; obj; obj = nextobj) {
		nprop += obj->count;
		nextobj = obj->gcnext;
		if (obj->gcmark != mark) {
			gprop += obj->count;
			*prevnextobj = nextobj;
			jsG_freeobject(J, obj);
			++gobj;
		} else {
			prevnextobj = &obj->gcnext;
		}
		++nobj;
	}

	prevnextstr = &J->gcstr;
	for (str = J->gcstr; str; str = nextstr) {
		nextstr = str->gcnext;
		if (str->gcmark != mark) {
			*prevnextstr = nextstr;
			js_free(J, str);
			++gstr;
		} else {
			prevnextstr = &str->gcnext;
		}
		++nstr;
	}

	unsigned int ntot = nenv + nfun + nobj + nstr + nprop;
	unsigned int gtot = genv + gfun + gobj + gstr + gprop;
	unsigned int remaining = ntot - gtot;

	J->gccounter = remaining;
	J->gcthresh = remaining * JS_GCFACTOR;

	if (report) {
		char buf[256];
		snprintf(buf, sizeof buf, "garbage collected (%d%%): %d/%d envs, %d/%d funs, %d/%d objs, %d/%d props, %d/%d strs",
			100*gtot/ntot, genv, nenv, gfun, nfun, gobj, nobj, gprop, nprop, gstr, nstr);
		js_report(J, buf);
	}
}

void js_freestate(js_State *J)
{
	js_Function *fun, *nextfun;
	js_Object *obj, *nextobj;
	js_Environment *env, *nextenv;
	js_String *str, *nextstr;

	if (!J)
		return;

	for (env = J->gcenv; env; env = nextenv)
		nextenv = env->gcnext, jsG_freeenvironment(J, env);
	for (fun = J->gcfun; fun; fun = nextfun)
		nextfun = fun->gcnext, jsG_freefunction(J, fun);
	for (obj = J->gcobj; obj; obj = nextobj)
		nextobj = obj->gcnext, jsG_freeobject(J, obj);
	for (str = J->gcstr; str; str = nextstr)
		nextstr = str->gcnext, js_free(J, str);

	jsS_freestrings(J);

	js_free(J, J->lexbuf.text);
	J->alloc(J->actx, J->stack, 0);
	J->alloc(J->actx, J, 0);
}
