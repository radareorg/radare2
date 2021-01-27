/* radare - LGPL3 - Copyright 2016-2020 - Matthieu (c0riolis) Tardy - l0stb1t*/

#include <r_io.h>
#include <r_bin.h>
#include "marshal.h"
#include "pyc_magic.h"

// avoiding using r2 internals asserts
#define if_true_return(cond,ret) if(cond){return(ret);}

static ut32 magic_int;
static ut32 symbols_ordinal = 0;

static RList *refs = NULL; // If you don't have a good reason, do not change this. And also checkout !refs in get_code_object()

/* interned_table is used to handle TYPE_INTERNED object */
extern RList *interned_table;

static pyc_object *get_object(RBuffer *buffer);
static pyc_object *copy_object(pyc_object *object);
static void free_object(pyc_object *object);

static ut8 get_ut8(RBuffer *buffer, bool *error) {
	ut8 ret = 0;
	int size = r_buf_read (buffer, &ret, sizeof (ret));
	if (size < sizeof (ret)) {
		*error = true;
	}
	return ret;
}

static ut16 get_ut16(RBuffer *buffer, bool *error) {
	ut16 ret = 0;

	int size = r_buf_read (buffer, (ut8 *)&ret, sizeof (ret));
	if (size != sizeof (ret)) {
		*error = true;
	}
	return ret;
}

static ut32 get_ut32(RBuffer *buffer, bool *error) {
	ut32 ret = 0;
	int size = r_buf_read (buffer, (ut8 *)&ret, sizeof (ret));
	if (size != sizeof (ret)) {
		*error = true;
	}
	return ret;
}

static st32 get_st32(RBuffer *buffer, bool *error) {
	st32 ret = 0;
	int size = r_buf_read (buffer, (ut8 *)&ret, sizeof (ret));
	if (size < sizeof (ret)) {
		*error = true;
	}
	return ret;
}

static st64 get_st64(RBuffer *buffer, bool *error) {
	st64 ret = 0;
	int size = r_buf_read (buffer, (ut8 *)&ret, sizeof (ret));
	if (size < sizeof (ret)) {
		*error = true;
	}
	return ret;
}

static double get_float64(RBuffer *buffer, bool *error) {
	double ret = 0;
	int size = r_buf_read (buffer, (ut8 *)&ret, sizeof (ret));
	if (size < sizeof (ret)) {
		*error = true;
	}
	return ret;
}

static ut8 *get_bytes(RBuffer *buffer, ut32 size) {
	ut8 *ret = R_NEWS0 (ut8, size + 1);
	if (!ret) {
		return NULL;
	}
	if (r_buf_read (buffer, ret, size) < size) {
		free (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_none_object(void) {
	pyc_object *ret;

	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_NONE;
	ret->data = strdup ("None");
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_false_object(void) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_FALSE;
	ret->data = strdup ("False");
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_true_object(void) {
	pyc_object *ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_TRUE;
	ret->data = strdup ("True");
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_int_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;

	st32 i = get_st32 (buffer, &error);
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_INT;
	ret->data = r_str_newf ("%d", i);
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_int64_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	st64 i;

	i = get_st64 (buffer, &error);

	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_INT64;
	ret->data = r_str_newf ("%lld", i);
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

/* long is used when the number is > MAX_INT64 */
static pyc_object *get_long_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	bool neg = false;
	ut32 tmp = 0;
	size_t size;
	size_t i, j = 0, left = 0;
	ut16 n;
	char *hexstr;
	char digist2hex[] = "0123456789abcdef";

	st32 ndigits = get_st32 (buffer, &error);
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_LONG;
	if (ndigits < 0) {
		ndigits = -ndigits;
		neg = true;
	}
	if (ndigits == 0) {
		ret->data = strdup ("0x0");
	} else {
		size = ndigits * 15;
		size = (size - 1) / 4 + 1;
		size += 3 + (neg? 1: 0);
		hexstr = calloc (size, sizeof (char));
		if (!hexstr) {
			free (ret);
			return NULL;
		}
		j = size - 1;

		for (i = 0; i < ndigits; i++) {
			n = get_ut16 (buffer, &error);
			tmp |= n << left;
			left += 15;

			while (left >= 4) {
				hexstr[--j] = digist2hex[tmp & 0xf];
				tmp >>= 4;
				left -= 4;
			}
		}

		if (tmp) {
			hexstr[--j] = digist2hex[tmp & 0xf];
		}

		hexstr[--j] = 'x';
		hexstr[--j] = '0';
		if (neg) {
			hexstr[--j] = '-';
		}

		ret->data = &hexstr[j];
	}
	return ret;
}

static pyc_object *get_stringref_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_st32 (buffer, &error);
	if (n >= r_list_length (interned_table)) {
		eprintf ("bad marshal data (string ref out of range)");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_STRINGREF;
	ret->data = r_list_get_n (interned_table, n);
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_float_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 size = 0;
	ut8 n = 0;

	n = get_ut8 (buffer, &error);
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ut8 *s = malloc (n + 1);
	if (!s) {
		free (ret);
		return NULL;
	}
	/* object contain string representation of the number */
	size = r_buf_read (buffer, s, n);
	if (size != n) {
		R_FREE (s);
		R_FREE (ret);
		return NULL;
	}
	s[n] = '\0';
	ret->type = TYPE_FLOAT;
	ret->data = s;
	return ret;
}

static pyc_object *get_binary_float_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	double f;

	f = get_float64 (buffer, &error);
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_FLOAT;
	ret->data = r_str_newf ("%.15g", f);
	if (!ret->data) {
		R_FREE (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_complex_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 size = 0;
	ut32 n1 = 0;
	ut32 n2 = 0;

	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}

	if ((magic_int & 0xffff) <= 62061) {
		n1 = get_ut8 (buffer, &error);
	} else {
		n1 = get_st32 (buffer, &error);
	}
	if (error) {
		free (ret);
		return NULL;
	}
	ut8 *s1 = malloc (n1 + 1);
	if (!s1) {
		free (ret);
		return NULL;
	}
	/* object contain string representation of the number */
	size = r_buf_read (buffer, s1, n1);
	if (size != n1) {
		R_FREE (s1);
		R_FREE (ret);
		return NULL;
	}
	s1[n1] = '\0';

	if ((magic_int & 0xffff) <= 62061) {
		n2 = get_ut8 (buffer, &error);
	} else
		n2 = get_st32 (buffer, &error);
	if (error) {
		return NULL;
	}
	ut8 *s2 = malloc (n2 + 1);
	if (!s2) {
		return NULL;
	}
	/* object contain string representation of the number */
	size = r_buf_read (buffer, s2, n2);
	if (size != n2) {
		R_FREE (s1);
		R_FREE (s2);
		R_FREE (ret);
		return NULL;
	}
	s2[n2] = '\0';

	ret->type = TYPE_COMPLEX;
	ret->data = r_str_newf ("%s+%sj", s1, s2);
	R_FREE (s1);
	R_FREE (s2);
	if (!ret->data) {
		R_FREE (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_binary_complex_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	double a, b;

	//a + bj
	a = get_float64 (buffer, &error);
	b = get_float64 (buffer, &error);
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_BINARY_COMPLEX;
	ret->data = r_str_newf ("%.15g+%.15gj", a, b);
	if (!ret->data) {
		R_FREE (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_string_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (n > ST32_MAX) {
		eprintf ("bad marshal data (string size out of range)");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_STRING;
	ret->data = get_bytes (buffer, n);
	if (!ret->data) {
		R_FREE (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_unicode_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (n > ST32_MAX) {
		eprintf ("bad marshal data (unicode size out of range)");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	ret->type = TYPE_UNICODE;
	ret->data = get_bytes (buffer, n);
	if (!ret->data) {
		R_FREE (ret);
		return NULL;
	}
	return ret;
}

static pyc_object *get_interned_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (n > ST32_MAX) {
		eprintf ("bad marshal data (string size out of range)");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_INTERNED;
	ret->data = get_bytes (buffer, n);
	/* add data pointer to interned table */
	r_list_append (interned_table, ret->data);
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_array_object_generic(RBuffer *buffer, ut32 size) {
	pyc_object *tmp = NULL;
	pyc_object *ret = NULL;
	ut32 i = 0;

	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->data = r_list_newf ((RListFree)free_object);
	if (!ret->data) {
		free (ret);
		return NULL;
	}
	for (i = 0; i < size; i++) {
		tmp = get_object (buffer);
		if (!tmp) {
			r_list_free (ret->data);
			R_FREE (ret);
			return NULL;
		}
		if (!r_list_append (ret->data, tmp)) {
			free_object (tmp);
			r_list_free (ret->data);
			free (ret);
			return NULL;
		}
	}
	return ret;
}

/* small TYPE_SMALL_TUPLE doesn't exist in python2 */
/* */
static pyc_object *get_small_tuple_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut8 n = 0;

	n = get_ut8 (buffer, &error);
	if (error) {
		return NULL;
	}
	ret = get_array_object_generic (buffer, n);
	if (ret) {
		ret->type = TYPE_SMALL_TUPLE;
		return ret;
	}
	return NULL;
}

static pyc_object *get_tuple_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (n > ST32_MAX) {
		eprintf ("bad marshal data (tuple size out of range)\n");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = get_array_object_generic (buffer, n);
	if (ret) {
		ret->type = TYPE_TUPLE;
		return ret;
	}
	return NULL;
}

static pyc_object *get_list_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (n > ST32_MAX) {
		eprintf ("bad marshal data (list size out of range)\n");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = get_array_object_generic (buffer, n);
	if (ret) {
		ret->type = TYPE_LIST;
		return ret;
	}
	return NULL;
}

static pyc_object *get_dict_object(RBuffer *buffer) {
	pyc_object *ret = NULL,
		   *key = NULL,
		   *val = NULL;

	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->data = r_list_newf ((RListFree)free_object);
	if (!ret->data) {
		R_FREE (ret);
		return NULL;
	}
	for (;;) {
		key = get_object (buffer);
		if (!key) {
			break;
		}
		if (!r_list_append (ret->data, key)) {
			r_list_free (ret->data);
			R_FREE (ret);
			free_object (key);
			return NULL;
		}
		val = get_object (buffer);
		if (!val) {
			break;
		}
		if (!r_list_append (ret->data, val)) {
			r_list_free (ret->data);
			R_FREE (ret);
			free_object (val);
			return NULL;
		}
	}
	ret->type = TYPE_DICT;
	return ret;
}

static pyc_object *get_set_object(RBuffer *buffer) {
	pyc_object *ret = NULL;
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (n > ST32_MAX) {
		eprintf ("bad marshal data (set size out of range)\n");
		return NULL;
	}
	if (error) {
		return NULL;
	}
	ret = get_array_object_generic (buffer, n);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_SET;
	return ret;
}

static pyc_object *get_ascii_object_generic(RBuffer *buffer, ut32 size, bool interned) {
	pyc_object *ret = NULL;

	ret = R_NEW0 (pyc_object);
	if (!ret) {
		return NULL;
	}
	ret->type = TYPE_ASCII;
	ret->data = get_bytes (buffer, size);
	if (!ret->data) {
		R_FREE (ret);
	}
	return ret;
}

static pyc_object *get_ascii_object(RBuffer *buffer) {
	bool error = false;
	ut32 n = 0;

	n = get_ut32 (buffer, &error);
	if (error) {
		return NULL;
	}
	return get_ascii_object_generic (buffer, n, true);
}

static pyc_object *get_ascii_interned_object(RBuffer *buffer) {
	bool error = false;
	ut32 n;

	n = get_ut32 (buffer, &error);
	if (error) {
		return NULL;
	}
	return get_ascii_object_generic (buffer, n, true);
}

static pyc_object *get_short_ascii_object(RBuffer *buffer) {
	bool error = false;
	ut8 n;

	n = get_ut8 (buffer, &error);
	if (error) {
		return NULL;
	}
	return get_ascii_object_generic (buffer, n, false);
}

static pyc_object *get_short_ascii_interned_object(RBuffer *buffer) {
	bool error = false;
	ut8 n;

	n = get_ut8 (buffer, &error);
	if (error) {
		return NULL;
	}
	return get_ascii_object_generic (buffer, n, true);
}

static pyc_object *get_ref_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret;
	pyc_object *obj;
	ut32 index;

	index = get_ut32 (buffer, &error);
	if (error) {
		return NULL;
	}
	if (index >= r_list_length (refs)) {
		return NULL;
	}
	obj = r_list_get_n (refs, index);
	if (!obj) {
		return NULL;
	}
	ret = copy_object (obj);
	return ret;
}

static void free_object(pyc_object *object) {
	if (!object) {
		return;
	}
	switch (object->type) {
	case TYPE_SMALL_TUPLE:
	case TYPE_TUPLE:
		r_list_free (object->data);
		break;
	case TYPE_STRING:
	case TYPE_TRUE:
	case TYPE_FALSE:
	case TYPE_INT:
	case TYPE_NONE:
	case TYPE_NULL:
	case TYPE_ASCII_INTERNED:
	case TYPE_SHORT_ASCII:
	case TYPE_ASCII:
	case TYPE_SHORT_ASCII_INTERNED:
		free (object->data);
		break;
	case TYPE_CODE_v0:
	case TYPE_CODE_v1: {
		pyc_code_object *cobj = object->data;
		free_object (cobj->code);
		free_object (cobj->consts);
		free_object (cobj->names);
		free_object (cobj->varnames);
		free_object (cobj->freevars);
		free_object (cobj->cellvars);
		free_object (cobj->filename);
		free_object (cobj->name);
		free_object (cobj->lnotab);
		free (object->data);
		break;
	}
	case TYPE_REF:
		free_object (object->data);
		break;
	case TYPE_SET:
	case TYPE_FROZENSET:
	case TYPE_ELLIPSIS:
	case TYPE_STOPITER:
	case TYPE_BINARY_COMPLEX:
	case TYPE_BINARY_FLOAT:
	case TYPE_COMPLEX:
	case TYPE_STRINGREF:
	case TYPE_DICT:
	case TYPE_FLOAT:
	case TYPE_INT64:
	case TYPE_INTERNED:
	case TYPE_LIST:
	case TYPE_LONG:
	case TYPE_UNICODE:
	case TYPE_UNKNOWN:
		eprintf ("Free not implemented for type %x\n", object->type);
		break;
	default:
		eprintf ("Undefined type in free_object (%x)\n", object->type);
		break;
	}
	free (object);
}

static pyc_object *copy_object(pyc_object *object) {
	pyc_object *copy = R_NEW0 (pyc_object);
	if (!copy || !object) {
		free (copy);
		return NULL;
	}
	copy->type = object->type;
	switch (object->type) {
	case TYPE_NULL:
		break;
	case TYPE_TUPLE:
	case TYPE_SMALL_TUPLE:
		copy->data = r_list_clone (object->data);
		break;
	case TYPE_INT:
	case TYPE_INT64:
	case TYPE_NONE:
	case TYPE_TRUE:
	case TYPE_FALSE:
	case TYPE_STRING:
	case TYPE_ASCII:
	case TYPE_SHORT_ASCII:
	case TYPE_ASCII_INTERNED:
	case TYPE_SHORT_ASCII_INTERNED:
		copy->data = strdup (object->data);
		break;
	case TYPE_CODE_v0:
	case TYPE_CODE_v1: {
		pyc_code_object *src = object->data;
		pyc_code_object *dst = R_NEW0 (pyc_code_object);
		if (!dst) {
			break;
		}
		memcpy (dst, src, sizeof (*dst));
		dst->code = copy_object (src->code);
		dst->consts = copy_object (src->consts);
		dst->names = copy_object (src->names);
		dst->varnames = copy_object (src->varnames);
		dst->freevars = copy_object (src->freevars);
		dst->cellvars = copy_object (src->cellvars);
		dst->filename = copy_object (src->filename);
		dst->name = copy_object (src->name);
		dst->lnotab = copy_object (src->lnotab);
		copy->data = dst;
		break;
	}
	case TYPE_REF:
		copy->data = copy_object (object->data);
		break;
	case TYPE_ELLIPSIS:
	case TYPE_STOPITER:
	case TYPE_BINARY_COMPLEX:
	case TYPE_BINARY_FLOAT:
	case TYPE_COMPLEX:
	case TYPE_STRINGREF:
	case TYPE_DICT:
	case TYPE_FLOAT:
	case TYPE_FROZENSET:
	case TYPE_INTERNED:
	case TYPE_LIST:
	case TYPE_LONG:
	case TYPE_SET:
	case TYPE_UNICODE:
	case TYPE_UNKNOWN:
		eprintf ("Copy not implemented for type %x\n", object->type);
		break;
	default:
		eprintf ("Undefined type in copy_object (%x)\n", object->type);
		break;
	}
	if (!copy->data) {
		R_FREE (copy);
	}
	return copy;
}

static pyc_object *get_code_object(RBuffer *buffer) {
	bool error = false;

	pyc_object *ret = R_NEW0 (pyc_object);
	pyc_code_object *cobj = R_NEW0 (pyc_code_object);
	if (!ret || !cobj) {
		free (ret);
		free (cobj);
		return NULL;
	}

	//ret->type = TYPE_CODE_v1;
	// support start from v1.0
	ret->data = cobj;

	bool v10_to_12 = magic_int_within (magic_int, 39170, 16679, &error); // 1.0.1 - 1.2
	bool v13_to_22 = magic_int_within (magic_int, 11913, 60718, &error); // 1.3b1 - 2.2a1
	bool v11_to_14 = magic_int_within (magic_int, 39170, 20117, &error); // 1.0.1 - 1.4
	bool v15_to_22 = magic_int_within (magic_int, 20121, 60718, &error); // 1.5a1 - 2.2a1
	bool v13_to_20 = magic_int_within (magic_int, 11913, 50824, &error); // 1.3b1 - 2.0b1
	//bool v21_to_27 = (!v13_to_20) && magic_int_within (magic_int, 60124, 62212, &error);
	bool has_posonlyargcount = magic_int_within (magic_int, 3410, 3424, &error); // v3.8.0a4 - latest
	if (error) {
		free (ret);
		free (cobj);
		return NULL;
	}

	if (v13_to_22) {
		cobj->argcount = get_ut16 (buffer, &error);
	} else if (v10_to_12) {
		cobj->argcount = 0;
	} else {
		cobj->argcount = get_ut32 (buffer, &error);
	}

	if (has_posonlyargcount) {
		cobj->posonlyargcount = get_ut32 (buffer, &error); // Included in argcount
	} else {
		cobj->posonlyargcount = 0; // None
	}

	if (((3020 < (magic_int & 0xffff)) && ((magic_int & 0xffff) < 20121)) && (!v11_to_14)) {
		cobj->kwonlyargcount = get_ut32 (buffer, &error); // Not included in argcount
	} else {
		cobj->kwonlyargcount = 0;
	}

	if (v13_to_22) {
		cobj->nlocals = get_ut16 (buffer, &error);
	} else if (v10_to_12) {
		cobj->nlocals = 0;
	} else {
		cobj->nlocals = get_ut32 (buffer, &error);
	}

	if (v15_to_22) {
		cobj->stacksize = get_ut16 (buffer, &error);
	} else if (v11_to_14 || v10_to_12) {
		cobj->stacksize = 0;
	} else {
		cobj->stacksize = get_ut32 (buffer, &error);
	}

	if (v13_to_22) {
		cobj->flags = get_ut16 (buffer, &error);
	} else if (v10_to_12) {
		cobj->flags = 0;
	} else {
		cobj->flags = get_ut32 (buffer, &error);
	}

	//to help disassemble the code
	cobj->start_offset = r_buf_tell (buffer) + 5; // 1 from get_object() and 4 from get_string_object()
	if (!refs) {
		return ret; //return for entried part to get the root object of this file
	}
	cobj->code = get_object (buffer);
	cobj->end_offset = r_buf_tell (buffer);

	cobj->consts = get_object (buffer);
	cobj->names = get_object (buffer);

	if (v10_to_12) {
		cobj->varnames = NULL;
	} else {
		cobj->varnames = get_object (buffer);
	}

	if (!(v10_to_12 || v13_to_20)) {
		cobj->freevars = get_object (buffer);
		cobj->cellvars = get_object (buffer);
	} else {
		cobj->freevars = NULL;
		cobj->cellvars = NULL;
	}

	cobj->filename = get_object (buffer);
	cobj->name = get_object (buffer);

	if (v15_to_22) {
		cobj->firstlineno = get_ut16 (buffer, &error);
	} else if (v11_to_14) {
		cobj->firstlineno = 0;
	} else {
		cobj->firstlineno = get_ut32 (buffer, &error);
	}

	if (v11_to_14) {
		cobj->lnotab = NULL;
	} else {
		cobj->lnotab = get_object (buffer);
	}

	if (error) {
		free_object (cobj->code);
		free_object (cobj->consts);
		free_object (cobj->names);
		free_object (cobj->varnames);
		free_object (cobj->freevars);
		free_object (cobj->cellvars);
		free_object (cobj->filename);
		free_object (cobj->name);
		free_object (cobj->lnotab);
		free (cobj);
		R_FREE (ret);
		return NULL;
	}
	return ret;
}

ut64 get_code_object_addr(RBuffer *buffer, ut32 magic) {
	magic_int = magic;
	pyc_object *co = get_code_object (buffer);
	ut64 result = 0;
	if (!co) {
		return 0;
	}

	pyc_code_object *cobj = co->data;
	result = cobj->start_offset;
	free_object (co);

	return result;
}

static pyc_object *get_object(RBuffer *buffer) {
	bool error = false;
	pyc_object *ret = NULL;
	ut8 code = get_ut8 (buffer, &error);
	ut8 flag = code & FLAG_REF;
	RListIter *ref_idx = NULL;
	ut8 type = code & ~FLAG_REF;

	if (error) {
		return NULL;
	}

	if (flag) {
		ret = get_none_object ();
		if (!ret) {
			return NULL;
		}
		ref_idx = r_list_append (refs, ret);
		if (!ref_idx) {
			free_object (ret);
			return NULL;
		}
	}

	switch (type) {
	case TYPE_NULL:
		free_object (ret);
		return NULL;
	case TYPE_TRUE:
		free_object (ret);
		return get_true_object ();
	case TYPE_FALSE:
		free_object (ret);
		return get_false_object ();
	case TYPE_NONE:
		free_object (ret);
		return get_none_object ();
	case TYPE_REF:
		free_object (ret);
		return get_ref_object (buffer);
	case TYPE_SMALL_TUPLE:
		ret = get_small_tuple_object (buffer);
		break;
	case TYPE_TUPLE:
		ret = get_tuple_object (buffer);
		break;
	case TYPE_STRING:
		ret = get_string_object (buffer);
		break;
	case TYPE_CODE_v0:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v0;
		}
		break;
	case TYPE_CODE_v1:
		ret = get_code_object (buffer);
		if (ret) {
			ret->type = TYPE_CODE_v1;
		}
		break;
	case TYPE_INT:
		ret = get_int_object (buffer);
		break;
	case TYPE_ASCII_INTERNED:
		ret = get_ascii_interned_object (buffer);
		break;
	case TYPE_SHORT_ASCII:
		ret = get_short_ascii_object (buffer);
		break;
	case TYPE_ASCII:
		ret = get_ascii_object (buffer);
		break;
	case TYPE_SHORT_ASCII_INTERNED:
		ret = get_short_ascii_interned_object (buffer);
		break;
	case TYPE_INT64:
		ret = get_int64_object (buffer);
		break;
	case TYPE_INTERNED:
		ret = get_interned_object (buffer);
		break;
	case TYPE_STRINGREF:
		ret = get_stringref_object (buffer);
		break;
	case TYPE_FLOAT:
		ret = get_float_object (buffer);
		break;
	case TYPE_BINARY_FLOAT:
		ret = get_binary_float_object (buffer);
		break;
	case TYPE_COMPLEX:
		ret = get_complex_object (buffer); // behaviour depends on Python version
		break;
	case TYPE_BINARY_COMPLEX:
		ret = get_binary_complex_object (buffer);
		break;
	case TYPE_LIST:
		ret = get_list_object (buffer);
		break;
	case TYPE_LONG:
		ret = get_long_object (buffer);
		break;
	case TYPE_UNICODE:
		ret = get_unicode_object (buffer);
		break;
	case TYPE_DICT:
		ret = get_dict_object (buffer);
		break;
	case TYPE_FROZENSET:
	case TYPE_SET:
		ret = get_set_object (buffer);
		break;
	case TYPE_STOPITER:
	case TYPE_ELLIPSIS:
		ret = R_NEW0 (pyc_object);
		break;
	case TYPE_UNKNOWN:
		eprintf ("Get not implemented for type 0x%x\n", type);
		free_object (ret);
		return NULL;
	default:
		eprintf ("Undefined type in get_object (0x%x)\n", type);
		free_object (ret);
		return NULL;
	}

	if (flag && ref_idx) {
		free_object (ref_idx->data);
		ref_idx->data = copy_object (ret);
	}
	return ret;
}

static bool extract_sections_symbols(pyc_object *obj, RList *sections, RList *symbols, RList *cobjs, char *prefix) {
	pyc_code_object *cobj = NULL;
	RBinSection *section = NULL;
	RBinSymbol *symbol = NULL;
	RListIter *i = NULL;

	//each code object is a section
	if_true_return (!obj || (obj->type != TYPE_CODE_v1 && obj->type != TYPE_CODE_v0), false);

	cobj = obj->data;

	if_true_return (!cobj || !cobj->name, false);
	if_true_return (cobj->name->type != TYPE_ASCII && cobj->name->type != TYPE_STRING && cobj->name->type != TYPE_INTERNED, false);
	if_true_return (!cobj->name->data, false);
	if_true_return (!cobj->consts, false);

	//add the cobj to objs list
	if (!r_list_append (cobjs, cobj)) {
		goto fail;
	}
	section = R_NEW0 (RBinSection);
	symbol = R_NEW0 (RBinSymbol);
	prefix = r_str_newf ("%s%s%s", r_str_get (prefix),
		prefix? ".": "", (const char *)cobj->name->data);
	if (!prefix || !section || !symbol) {
		goto fail;
	}
	section->name = strdup (prefix);
	if (!section->name) {
		goto fail;
	}
	section->paddr = cobj->start_offset;
	section->vaddr = cobj->start_offset;
	section->size = cobj->end_offset - cobj->start_offset;
	section->vsize = cobj->end_offset - cobj->start_offset;
	if (!r_list_append (sections, section)) {
		goto fail;
	}
	// start building symbol
	symbol->name = strdup (prefix);
	//symbol->bind;
	symbol->type = R_BIN_TYPE_FUNC_STR;
	symbol->size = cobj->end_offset - cobj->start_offset;
	symbol->vaddr = cobj->start_offset;
	symbol->paddr = cobj->start_offset;
	symbol->ordinal = symbols_ordinal++;
	if (cobj->consts->type != TYPE_TUPLE && cobj->consts->type != TYPE_SMALL_TUPLE) {
		goto fail;
	}
	if (!r_list_append (symbols, symbol)) {
		goto fail;
	}
	r_list_foreach (((RList *)(cobj->consts->data)), i, obj)
		extract_sections_symbols (obj, sections, symbols, cobjs, prefix);
	free (prefix);
	return true;
fail:

	free (section);
	free (prefix);
	free (symbol);
	return false;
}

bool get_sections_symbols_from_code_objects(RBuffer *buffer, RList *sections, RList *symbols, RList *cobjs, ut32 magic) {
	bool ret;
	magic_int = magic;
	refs = r_list_newf ((RListFree)free_object);
	if (!refs) {
		return false;
	}
	ret = extract_sections_symbols (get_object (buffer), sections, symbols, cobjs, NULL);
	r_list_free (refs);
	return ret;
}
