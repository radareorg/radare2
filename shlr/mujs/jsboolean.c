#include "jsi.h"
#include "jsvalue.h"
#include "jsbuiltin.h"

static void jsB_new_Boolean(js_State *J)
{
	js_newboolean(J, js_toboolean(J, 1));
}

static void jsB_Boolean(js_State *J)
{
	js_pushboolean(J, js_toboolean(J, 1));
}

static void Bp_toString(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CBOOLEAN) js_typeerror(J, "not a boolean");
	js_pushliteral(J, self->u.boolean ? "true" : "false");
}

static void Bp_valueOf(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CBOOLEAN) js_typeerror(J, "not a boolean");
	js_pushboolean(J, self->u.boolean);
}

void jsB_initboolean(js_State *J)
{
	J->Boolean_prototype->u.boolean = 0;

	js_pushobject(J, J->Boolean_prototype);
	{
		jsB_propf(J, "Boolean.prototype.toString", Bp_toString, 0);
		jsB_propf(J, "Boolean.prototype.valueOf", Bp_valueOf, 0);
	}
	js_newcconstructor(J, jsB_Boolean, jsB_new_Boolean, "Boolean", 1);
	js_defglobal(J, "Boolean", JS_DONTENUM);
}
