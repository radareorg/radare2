/* radare2 - LGPL - Copyright 2017-2018 - wargio */

#include <r_types.h>
#include <r_util.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum {
	R_JS_NULL = 0,
	R_JS_NUMBERS,
	R_JS_BOOLEAN,
	R_JS_STRING,
	R_JS_ARRAY,
	R_JS_OBJECT,
} RJSType;

R_API void r_json_var_free (RJSVar* var) {
	ut32 i;
	if (!var) {
		return;
	}
	var->ref--;
	if (var->ref > 0) {
		return;
	}
	switch (var->type) {
	case R_JS_STRING:
		free ((char*) var->string.s);
		break;
	case R_JS_ARRAY:
		for (i = 0; i < var->array.l; i++) {
			r_json_var_free (var->array.a[i]);
		}
		free (var->array.a);
		break;
	case R_JS_OBJECT:
		for (i = 0; i < var->object.l; i++) {
			r_json_var_free (var->object.a[i]);
			free ((char*) var->object.n[i]);
		}
		free ((char**) var->object.n);
		free (var->object.a);
		break;
	default:
		break;
	}
	free (var);
}

R_API RJSVar* r_json_object_new () {
	RJSVar* var = R_NEW0 (RJSVar);
	if (var) {
		var->type = R_JS_OBJECT;
	}
	return var;
}

R_API RJSVar* r_json_array_new (int len) {
	if (len < 0) {
		return NULL;
	}
	RJSVar* var = R_NEW0 (RJSVar);
	if (!var) {
		return NULL;
	}
	if (len) {
		var->array.a = R_NEWS0 (RJSVar*, len);
		var->array.l = var->array.a ? len : 0;
	} else {
		var->array.a = NULL;
		var->array.l = 0;
	}
	var->type = R_JS_ARRAY;
	return var;
}

R_API RJSVar* r_json_string_new (const char* name) {
	if (!name) {
		return NULL;
	}
	RJSVar* var = R_NEW0 (RJSVar);
	if (!var) {
		return NULL;
	}
	var->type = R_JS_STRING;
	var->string.s = strdup (name);
	var->string.l = strlen (name) + 1;
	return var;
}

R_API RJSVar* r_json_number_new (int value) {
	RJSVar* var = R_NEW0 (RJSVar);
	if (!var) {
		return NULL;
	}
	var->type = R_JS_NUMBERS;
	var->number = value;
	return var;
}

R_API RJSVar* r_json_boolean_new (bool value) {
	RJSVar* var = R_NEW0 (RJSVar);
	if (!var) {
		return NULL;
	}
	var->type = R_JS_BOOLEAN;
	var->boolean = value;
	return var;
}

R_API RJSVar* r_json_null_new () {
	RJSVar* var = R_NEW0 (RJSVar);
	if (!var) {
		return NULL;
	}
	var->type = R_JS_NULL;
	return var;
}

R_API bool r_json_object_add (RJSVar* object, const char* name, RJSVar* value) {
	ut32 len;
	RJSVar** v;
	char** c;
	if (!object || !name || !value) {
		return false;
	}
	len = object->object.l + 1;
	if (len <= 0) {
		value->ref--;;
		return false;
	}
	v = (RJSVar**) malloc (len * sizeof (RJSVar*));
	if (!v) {
		return false;
	}
	c = (char**) malloc (len * sizeof (char*));
	if (!c) {
		free (v);
		return false;
	}
	value->ref++;
	memcpy (v, object->object.a, (object->object.l * sizeof (RJSVar*)));
	memcpy (c, object->object.n, (object->object.l * sizeof (char*)));
	v[len - 1] = value;
	c[len - 1] = strdup (name);
	object->object.l = len;
	free (object->object.a);
	object->object.a = v;
	free ((void *)object->object.n);
	object->object.n = (const char**) c;
	return true;
}

R_API bool r_json_array_add (RJSVar* array, RJSVar* value) {
	ut32 len;
	RJSVar** v;
	if (!array || !value) {
		return false;
	}
	len = array->array.l + 1;
	if (len <= 0) {
		return false;
	}
	v = (RJSVar**) realloc (array->array.a, len * sizeof (RJSVar*));
	if (!v) {
		return false;
	}
	value->ref++;
	v[len - 1] = value;
	array->array.l = len;
	array->array.a = v;
	return true;
}

R_API RJSVar* r_json_object_get (RJSVar* object, const char* name) {
	if (!object || !name) {
		return NULL;
	}
	ut32 i;
	for (i = 0; i < object->object.l; i++) {
		if (!strcmp (name, object->object.n[i])) {
			return object->object.a[i];
		}
	}
	return NULL;
}

R_API RJSVar* r_json_array_get (RJSVar* array, int index) {
	if (!array || index <= 0 || index >= array->array.l) {
		return NULL;
	}
	return array->array.a[index];
}

static char* _r_json_null_str (bool expanded) {
	if (!expanded) {
		return NULL;
	}
	const int len = sizeof (R_JSON_NULL);
	char *c = (char*) malloc (len);
	if (c) {
		memcpy (c, R_JSON_NULL, len);
	}
	return c;
}

R_API char* r_json_var_string (RJSVar* var, bool expanded) {
	char *c = NULL;
	ut32 i, len = 0;
	if (!var) {
		return _r_json_null_str (expanded);
	}
	switch (var->type) {
	case R_JS_NULL:
		c = _r_json_null_str (expanded);
		break;
	case R_JS_NUMBERS:
		len = snprintf (NULL, 0, "%d", var->number) + 1;
		c = (char*) malloc (len);
		if (!c) {
			break;
		}
		snprintf (c, len, "%d", var->number);
		break;
	case R_JS_BOOLEAN:
		len = var->boolean ? sizeof (R_JSON_TRUE) : sizeof (R_JSON_FALSE);
		c = (char*) malloc (len);
		if (!c) {
			break;
		}
		snprintf (c, len, "%s", var->boolean ? R_JSON_TRUE : R_JSON_FALSE);
		break;
	case R_JS_STRING:
		len = var->string.l + 2;
		c = (char*) malloc (len);
		if (!c) {
			break;
		}
		memcpy (c + 1, var->string.s, var->string.l);
		c[0] = '"';
		c[len - 2] = '"';
		c[len - 1] = 0;
		break;
	case R_JS_ARRAY:
		if (var->array.l) {
			len = 3;
			char* p, *e;
			char** t = R_NEWS0 (char*, var->array.l);
			if (!t) {
				c = (char*) malloc (sizeof (R_JSON_EMPTY_ARR));
				memcpy (c, R_JSON_EMPTY_ARR, sizeof (R_JSON_EMPTY_ARR));
				break;
			}
			for (i = 0; i < var->array.l; i++) {
				t[i] = r_json_var_string (var->array.a[i], expanded);
				if (!t[i]) {
					continue;
				}
				len += strlen (t[i]) + 1;
			}
			c = (char*) calloc (len, 1);
			p = c + 1;
			e = p + len;
			for (i = 0; i < var->array.l; i++) {
				if (!t[i]) {
					continue;
				}
				if (c) {
					p += snprintf (p, e - p, "%s,", t[i]);
				}
				free (t[i]);
			}
			if (c) {
				c[0] = '[';
				if (p == c + 1) {
					p++;
				}
				c[len - (e - p)] = ']';
				c[len - 1] = 0;
			}
			free (t);
		} else {
			c = (char*) malloc (sizeof (R_JSON_EMPTY_ARR));
			memcpy (c, R_JSON_EMPTY_ARR, sizeof (R_JSON_EMPTY_ARR));
		}
		break;
	case R_JS_OBJECT:
		if (var->object.l) {
			char* p, *e;
			char** t = R_NEWS0 (char*, var->object.l);
			if (!t) {
				c = (char*) malloc (sizeof (R_JSON_EMPTY_OBJ));
				memcpy (c, R_JSON_EMPTY_OBJ, sizeof (R_JSON_EMPTY_OBJ));
				break;
			}
			len = 3;
			for (i = 0; i < var->object.l; i++) {
				t[i] = r_json_var_string (var->object.a[i], expanded);
				if (!t[i]) {
					continue;
				}
				fflush (stdout);
				len += strlen (t[i]) + strlen (var->object.n[i]) + 4;
			}
			c = (char*) malloc (len);
			p = c + 1;
			e = p + len;
			for (i = 0; i < var->object.l; i++) {
				if (!t[i]) {
					continue;
				}
				if (c) {
					p += snprintf (p, e - p, "\"%s\":%s,", var->object.n[i], t[i]);
				}
				free (t[i]);
			}
			if (c) {
				c[0] = '{';
				if (p == c + 1) {
					p++;
				}
				c[len - (e - p)] = '}';
				c[len - 1] = 0;
			}
			free (t);
		} else {
			c = (char*) malloc (sizeof (R_JSON_EMPTY_OBJ));
			memcpy (c, R_JSON_EMPTY_OBJ, sizeof (R_JSON_EMPTY_OBJ));
		}
		break;
	}
	if (!c) {
		c = _r_json_null_str (expanded);
	}
	return c;
}

R_API char* r_json_stringify (RJSVar* var, bool expanded) {
	if (!var || (var->type != R_JS_OBJECT && var->type != R_JS_ARRAY)) {
		return NULL;
	}
	return r_json_var_string (var, expanded);
}
