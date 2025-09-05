/* radare - LGPL - Copyright 2019-2023 - mrmacete, pancake, Siguza */

#include <r_util.h>
#include <r_util/r_xml.h>
#include <r_list.h>
#include "r_cf_dict.h"

typedef enum {
	R_CF_STATE_ROOT,
	R_CF_STATE_IN_DICT,
	R_CF_STATE_IN_ARRAY,
	R_CF_STATE_IN_KEY,
	R_CF_STATE_IN_SCALAR,
	R_CF_STATE_IN_IGNORE,
	R_CF_STATE_IN_ATTR_ID,
	R_CF_STATE_IN_ATTR_IDREF,
} RCFParsePhase;

typedef enum {
	R_CF_ID_STATE_NONE,
	R_CF_ID_STATE_SET,
	R_CF_ID_STATE_REF,
} RCFIDState;

typedef struct _RCFParseState {
	RCFParsePhase phase;
	RCFIDState idstate;
	ut32 id;
	char *key;
	RCFValueType value_type;
	RCFValueDict *dict;
	RCFValueArray *array;
} RCFParseState;

static RCFParseState *r_cf_parse_state_new(RCFParsePhase phase);
static void r_cf_parse_state_free(RCFParseState *state);

static RCFKeyValue *r_cf_key_value_new(char *key, RCFValue *value);
static void r_cf_key_value_free(RCFKeyValue *key_value);

static RCFValueDict *r_cf_value_dict_new(void);
static void r_cf_value_dict_add(RCFValueDict *dict, RCFKeyValue *key_value);
static void r_cf_value_dict_print(RCFValueDict *dict);

static RCFValueArray *r_cf_value_array_new(void);
static void r_cf_value_array_free(RCFValueArray *array);
static void r_cf_value_array_add(RCFValueArray *array, RCFValue *value);
static void r_cf_value_array_print(RCFValueArray *dict);

static RCFValueString *r_cf_value_string_new(char *string);
static void r_cf_value_string_free(RCFValueString *string);
static void r_cf_value_string_print(RCFValueString *string);

static RCFValueInteger *r_cf_value_integer_new(char *string);
static void r_cf_value_integer_free(RCFValueInteger *integer);
static void r_cf_value_integer_print(RCFValueInteger *integer);

static RCFValueData *r_cf_value_data_new(char *string);
static void r_cf_value_data_free(RCFValueData *data);
static void r_cf_value_data_print(RCFValueData *data);

static RCFValueNULL *r_cf_value_null_new(void);
static void r_cf_value_null_free(RCFValueNULL *null);
static void r_cf_value_null_print(RCFValueNULL *null);

static RCFValueBool *r_cf_value_bool_new(bool value);
static void r_cf_value_bool_free(RCFValueBool *bool_value);
static void r_cf_value_bool_print(RCFValueBool *bool_value);

static RCFValue *r_cf_value_clone(RCFValue *value);
static void r_cf_value_free(RCFValue *value);

RCFValueDict *r_cf_value_dict_parse (RBuffer *file_buf, ut64 offset, ut64 size, int options) {
	RList *idlist = NULL;
	RCFValueDict *result = NULL;
	int i;
	char *content = NULL;

	RXml *x = r_xml_new (4096);

	RList *stack = r_list_newf ((RListFree)&r_cf_parse_state_free);
	if (!stack) {
		goto beach;
	}

	if (options & R_CF_OPTION_SUPPORT_IDREF) {
		idlist = r_list_new ();
		if (!idlist) {
			goto beach;
		}
	}

	r_list_push (stack, r_cf_parse_state_new (R_CF_STATE_ROOT));

	for (i = 0; i < size; i++) {
		ut8 doc = 0;
		r_buf_read_at (file_buf, offset + i, &doc, 1);
		if (!doc) {
			break;
		}

		RXmlRet r = r_xml_parse (x, doc);
		if (r < 0) {
			R_LOG_ERROR ("Parse at :%08" PFMT64d ":%" PFMT64d " byte offset %" PFMT64d, x->line, x->byte, x->total);
			goto beach;
		}

		switch (r) {
		case R_XML_ELEMSTART: {
			RCFParseState *state = (RCFParseState *)r_list_last (stack);
			RCFParseState *next_state = NULL;

			if (!strcmp (x->elem, "dict")) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_DICT);
				if (!next_state) {
					goto beach;
				}
				next_state->dict = r_cf_value_dict_new ();
			} else if (!strcmp (x->elem, "array")) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_ARRAY);
				if (!next_state) {
					goto beach;
				}
				next_state->array = r_cf_value_array_new ();
			} else if (!strcmp (x->elem, "key") && state->phase == R_CF_STATE_IN_DICT) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_KEY);
				if (!next_state) {
					goto beach;
				}
				next_state->dict = state->dict;
			} else if (!strcmp (x->elem, "string")) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = R_CF_STRING;
			} else if (!strcmp (x->elem, "integer")) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = R_CF_INTEGER;
			} else if (!strcmp (x->elem, "data")) {
				if (options & R_CF_OPTION_SKIP_NSDATA) {
					next_state = r_cf_parse_state_new (R_CF_STATE_IN_IGNORE);
				} else {
					next_state = r_cf_parse_state_new (R_CF_STATE_IN_SCALAR);
					if (!next_state) {
						goto beach;
					}
					next_state->value_type = R_CF_DATA;
				}
			} else if (!strcmp (x->elem, "true")) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = R_CF_TRUE;
			} else if (!strcmp (x->elem, "false")) {
				next_state = r_cf_parse_state_new (R_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = R_CF_FALSE;
			}

			if (next_state) {
				r_list_push (stack, next_state);
			} else {
				R_LOG_ERROR ("Missing next state for elem: %s phase: %d", x->elem, state->phase);
				break;
			}

			break;
		}
		case R_XML_ELEMEND: {
			RCFParseState *state = (RCFParseState *)r_list_pop (stack);
			RCFParseState *next_state = (RCFParseState *)r_list_last (stack);
			if (!state || !next_state) {
				goto beach;
			}

			if (next_state->phase == R_CF_STATE_ROOT) {
				if (state->phase == R_CF_STATE_IN_DICT) {
					result = state->dict;
					r_cf_parse_state_free (state);
					break;
				} else {
					R_LOG_ERROR ("Root element is not a dict");
					goto beach;
				}
			}

			if (next_state->phase == R_CF_STATE_IN_DICT && state->phase == R_CF_STATE_IN_KEY) {
				if (!content) {
					R_LOG_ERROR ("NULL key not supported");
					goto beach;
				}
				next_state->key = content;
			}

			if (state->phase != R_CF_STATE_IN_KEY) {
				RCFValue *value = NULL;

				if (idlist && state->idstate == R_CF_ID_STATE_REF) {
					value = r_list_get_n (idlist, (int)state->id);
					if (!value) {
						R_LOG_ERROR ("Missing value for IDREF %"PFMT64d, state->id);
						goto beach;
					}
					if (state->phase == R_CF_STATE_IN_DICT) {
						if (r_list_length (state->dict->pairs) != 0) {
							R_LOG_ERROR ("Dict with IDREF already has elements");
							goto beach;
						}
						r_cf_value_dict_free (state->dict);
						state->dict = NULL;
					} else if (state->phase == R_CF_STATE_IN_ARRAY) {
						if (r_list_length (state->dict->pairs) != 0) {
							R_LOG_ERROR ("Array with IDREF already has elements");
							goto beach;
						}
						r_cf_value_array_free (state->array);
						state->array = NULL;
					} else if (state->phase == R_CF_STATE_IN_SCALAR && content) {
						R_LOG_ERROR ("Element with IDREF already has content");
						goto beach;
					}
					value = r_cf_value_clone (value);
					if (!value) {
						goto beach;
					}
				} else {
					switch (state->phase) {
					case R_CF_STATE_IN_DICT:
						value = (RCFValue *)state->dict;
						break;
					case R_CF_STATE_IN_ARRAY:
						value = (RCFValue *)state->array;
						break;
					case R_CF_STATE_IN_SCALAR:
						if (!content && state->value_type != R_CF_FALSE && state->value_type != R_CF_TRUE) {
							value = (RCFValue *)r_cf_value_null_new ();
						} else {
							switch (state->value_type) {
							case R_CF_STRING:
								value = (RCFValue *)r_cf_value_string_new (content);
								break;
							case R_CF_INTEGER:
								value = (RCFValue *)r_cf_value_integer_new (content);
								R_FREE (content);
								break;
							case R_CF_DATA:
								value = (RCFValue *)r_cf_value_data_new (content);
								R_FREE (content);
								break;
							case R_CF_TRUE:
								value = (RCFValue *)r_cf_value_bool_new (true);
								break;
							case R_CF_FALSE:
								value = (RCFValue *)r_cf_value_bool_new (false);
								break;
							default:
								break;
							}
						}
						break;
					default:
						break;
					}

					if (idlist && state->idstate == R_CF_ID_STATE_SET) {
						if (value) {
							r_list_insert (idlist, state->id, value);
						} else {
							R_LOG_WARN ("Missing value for ID %"PFMT64d, state->id);
						}
					}
				}

				if (next_state->phase == R_CF_STATE_IN_DICT) {
					if (value) {
						RCFKeyValue *key_value = r_cf_key_value_new (next_state->key, value);
						r_cf_value_dict_add (next_state->dict, key_value);
					} else if (state->phase != R_CF_STATE_IN_IGNORE) {
						R_LOG_ERROR ("Missing value for key %s", next_state->key);
						r_cf_value_free ((RCFValue *)value);
						goto beach;
					}
				} else if (next_state->phase == R_CF_STATE_IN_ARRAY) {
					if (value) {
						r_cf_value_array_add (next_state->array, value);
					} else if (state->phase != R_CF_STATE_IN_IGNORE) {
						R_LOG_ERROR ("Missing value for array");
						r_cf_value_free ((RCFValue *)value);
						goto beach;
					}
				}
			}
			content = NULL;
			r_cf_parse_state_free (state);
			break;
		}
		case R_XML_CONTENT: {
			RCFParseState *state = (RCFParseState *)r_list_last (stack);
			if (state->phase == R_CF_STATE_IN_IGNORE) {
				break;
			}
			content = r_str_append (content, x->data);
			break;
		}
		case R_XML_ATTRSTART: {
			if (idlist) {
				RCFParseState *state = (RCFParseState *)r_list_last (stack);
				if (state->phase != R_CF_STATE_IN_DICT && state->phase != R_CF_STATE_IN_ARRAY && state->phase != R_CF_STATE_IN_SCALAR) {
					break;
				}
				RCFParsePhase next_phase;
				if (!strcmp (x->attr, "ID")) {
					next_phase = R_CF_STATE_IN_ATTR_ID;
				} else if (!strcmp (x->attr, "IDREF")) {
					next_phase = R_CF_STATE_IN_ATTR_IDREF;
				} else {
					break;
				}
				if (state->idstate != R_CF_ID_STATE_NONE) {
					R_LOG_ERROR ("Cannot have ID and IDREF on the same element");
					goto beach;
				}
				RCFParseState *next_state = r_cf_parse_state_new (next_phase);
				if (!next_state) {
					goto beach;
				}
				r_list_push (stack, next_state);
			}
			break;
		}
		case R_XML_ATTRVAL: {
			if (idlist) {
				RCFParseState *state = (RCFParseState *)r_list_last (stack);
				if (state->phase != R_CF_STATE_IN_ATTR_ID && state->phase != R_CF_STATE_IN_ATTR_IDREF) {
					break;
				}
				content = r_str_append (content, x->data);
			}
			break;
		}
		case R_XML_ATTREND: {
			if (idlist) {
				RCFParseState *state = (RCFParseState *)r_list_last (stack);
				if (state->phase != R_CF_STATE_IN_ATTR_ID && state->phase != R_CF_STATE_IN_ATTR_IDREF) {
					break;
				}
				r_list_pop (stack);
				RCFParseState *next_state = (RCFParseState *)r_list_last (stack);
				next_state->id = (ut32)r_num_get (NULL, content);
				next_state->idstate = state->phase == R_CF_STATE_IN_ATTR_ID ? R_CF_ID_STATE_SET : R_CF_ID_STATE_REF;
				R_FREE (content);
				content = NULL;
				r_cf_parse_state_free (state);
			}
			break;
		}
		default:
			break;
		}

		if (result) {
			break;
		}
	}

	RXmlRet r = r_xml_eof (x);
	if (r < 0) {
		R_LOG_ERROR ("Invalid xml");
	}
beach:
	r_xml_free (x);
	r_list_free (stack);
	r_list_free (idlist);
	free (content);

	return result;
}

static RCFParseState *r_cf_parse_state_new(RCFParsePhase phase) {
	RCFParseState *state = R_NEW0 (RCFParseState);
	if (state) {
		state->phase = phase;
	}
	return state;
}

static void r_cf_parse_state_free(RCFParseState *state) {
	if (state) {
		R_FREE (state);
	}
}

static RCFKeyValue *r_cf_key_value_new(char *key, RCFValue *value) {
	RCFKeyValue *key_value = R_NEW0 (RCFKeyValue);
	if (!key_value) {
		return NULL;
	}

	key_value->key = key;
	key_value->value = value;

	return key_value;
}

static void r_cf_key_value_free(RCFKeyValue *key_value) {
	if (!key_value) {
		return;
	}

	if (key_value->key) {
		R_FREE (key_value->key);
	}
	if (key_value->value) {
		r_cf_value_free (key_value->value);
		key_value->value = NULL;
	}

	R_FREE (key_value);
}

static RCFValueDict *r_cf_value_dict_new(void) {
	RCFValueDict *dict = R_NEW0 (RCFValueDict);
	if (!dict) {
		return NULL;
	}

	dict->type = R_CF_DICT;
	dict->pairs = r_list_newf ((RListFree)&r_cf_key_value_free);

	return dict;
}

void r_cf_value_dict_free (RCFValueDict *dict) {
	R_RETURN_IF_FAIL (dict);

	if (dict->pairs) {
		r_list_free (dict->pairs);
		dict->pairs = NULL;
	}
	dict->type = R_CF_INVALID;
	R_FREE (dict);
}

static void r_cf_value_dict_add(RCFValueDict *dict, RCFKeyValue *key_value) {
	if (!dict || !dict->pairs) {
		return;
	}
	r_list_push (dict->pairs, key_value);
}

static void r_cf_value_dict_print(RCFValueDict *dict) {
	RListIter *iter;
	RCFKeyValue *key_value;
	int length = r_list_length (dict->pairs);
	int i = 0;
	printf ("{");
	r_list_foreach (dict->pairs, iter, key_value) {
		printf ("\"%s\":", key_value->key);
		r_cf_value_print (key_value->value);
		if (i++ < length - 1) {
			printf (",");
		}
	}
	printf ("}");
}

static RCFValueArray *r_cf_value_array_new(void) {
	RCFValueArray *array = R_NEW0 (RCFValueArray);
	if (array) {
		array->type = R_CF_ARRAY;
		array->values = r_list_newf ((RListFree)&r_cf_value_free);
	}
	return array;
}

static void r_cf_value_array_free(RCFValueArray *array) {
	if (array) {
		if (array->values) {
			r_list_free (array->values);
			array->values = NULL;
		}
		free (array);
	}
}

static void r_cf_value_array_add(RCFValueArray *array, RCFValue *value) {
	if (!array || !array->values) {
		return;
	}

	r_list_push (array->values, value);
}

static void r_cf_value_array_print(RCFValueArray *array) {
	RListIter *iter;
	RCFValue *value;
	int length = r_list_length (array->values);
	int i = 0;
	printf ("[");
	r_list_foreach (array->values, iter, value) {
		r_cf_value_print (value);
		if (i++ < length - 1) {
			printf (",");
		}
	}
	printf ("]");
}

static RCFValueString *r_cf_value_string_new(char *string) {
	RCFValueString *value_string = R_NEW0 (RCFValueString);
	if (!value_string) {
		return NULL;
	}

	value_string->type = R_CF_STRING;
	value_string->value = string;

	return value_string;
}

static void r_cf_value_string_free(RCFValueString *string) {
	if (!string) {
		return;
	}

	if (string->value) {
		R_FREE (string->value);
	}

	string->type = R_CF_INVALID;
	R_FREE (string);
}

static void r_cf_value_string_print(RCFValueString *string) {
	char *escaped = strdup (string->value);
	escaped = r_str_replace (escaped, "\"", "\\\"", 1);
	printf ("\"%s\"", escaped);
	R_FREE (escaped);
}

static RCFValueInteger *r_cf_value_integer_new(char *string) {
	RCFValueInteger *integer = R_NEW0 (RCFValueInteger);
	if (!integer) {
		return NULL;
	}

	integer->type = R_CF_INTEGER;
	integer->value = r_num_get (NULL, string);

	return integer;
}

static void r_cf_value_integer_free(RCFValueInteger *integer) {
	if (!integer) {
		return;
	}

	integer->type = R_CF_INVALID;
	R_FREE (integer);
}

static void r_cf_value_integer_print(RCFValueInteger *integer) {
	printf ("%"PFMT64u, integer->value);
}

static RCFValueData *r_cf_value_data_new(char *string) {
	RCFValueData *data = R_NEW0 (RCFValueData);
	if (!data) {
		return NULL;
	}

	const int len = strlen (string);
	const int out_len = len / 4 * 3 + 1;
	ut8 *out = calloc (sizeof (ut8), out_len);
	if (!out) {
		R_FREE (data);
		return NULL;
	}
	r_base64_decode (out, string, len);

	data->type = R_CF_DATA;
	data->value = r_buf_new_with_pointers (out, out_len, true);

	return data;
}

static void r_cf_value_data_free(RCFValueData *data) {
	if (!data) {
		return;
	}

	data->type = R_CF_INVALID;
	if (data->value) {
		r_buf_free (data->value);
		data->value = NULL;
	}

	R_FREE (data);
}

static void r_cf_value_data_print(RCFValueData *data) {
	printf ("\"...\"");
}

static RCFValueNULL *r_cf_value_null_new(void) {
	RCFValueNULL *null = R_NEW0 (RCFValueNULL);
	if (!null) {
		return NULL;
	}

	null->type = R_CF_NULL;

	return null;
}

static void r_cf_value_null_free(RCFValueNULL *null) {
	if (!null) {
		return;
	}

	null->type = R_CF_INVALID;
	R_FREE (null);
}

static void r_cf_value_null_print(RCFValueNULL *null) {
	printf ("null");
}

static RCFValueBool *r_cf_value_bool_new(bool value) {
	RCFValueBool *bool_value = R_NEW0 (RCFValueBool);
	if (!bool_value) {
		return NULL;
	}

	bool_value->type = value ? R_CF_TRUE : R_CF_FALSE;
	return bool_value;
}

static void r_cf_value_bool_free(RCFValueBool *bool_value) {
	if (bool_value) {
		bool_value->type = R_CF_INVALID;
		R_FREE (bool_value);
	}
}

static void r_cf_value_bool_print(RCFValueBool *bool_value) {
	if (bool_value->type == R_CF_TRUE) {
		printf ("true");
	} else {
		printf ("false");
	}
}

static RCFValue *r_cf_value_clone(RCFValue *value) {
	if (!value) {
		return NULL;
	}

	RCFValue *copy = NULL;

	switch (value->type) {
	case R_CF_DICT: {
		RCFValueDict *dict = r_cf_value_dict_new ();
		if (dict) {
			copy = (RCFValue *)dict;
			RListIter *iter;
			RCFKeyValue *item;
			r_list_foreach (((RCFValueDict *)value)->pairs, iter, item) {
				char *key = strdup (item->key);
				if (key) {
					RCFValue *clone = r_cf_value_clone (item->value);
					if (clone) {
						RCFKeyValue *pair = r_cf_key_value_new (key, clone);
						if (pair) {
							r_cf_value_dict_add (dict, pair);
						}
						r_cf_value_free (clone);
					}
					R_FREE (key);
				}
				r_cf_value_dict_free (dict);
				copy = NULL;
				break;
			}
		}
		break;
	}
	case R_CF_ARRAY: {
		RCFValueArray *array = r_cf_value_array_new ();
		if (array) {
			copy = (RCFValue *)array;
			RListIter *iter;
			RCFValue *item;
			r_list_foreach (((RCFValueArray *)value)->values, iter, item) {
				RCFValue *clone = r_cf_value_clone (item);
				if (clone) {
					r_cf_value_array_add (array, clone);
					continue;
				}
				r_cf_value_array_free (array);
				copy = NULL;
				break;
			}
		}
		break;
	}
	case R_CF_STRING: {
		RCFValueString *string = R_NEW0 (RCFValueString);
		if (string) {
			string->value = strdup (((RCFValueString *)value)->value);
			if (string->value) {
				copy = (RCFValue *)string;
			} else {
				R_FREE (string);
			}
		}
		break;
	}
	case R_CF_INTEGER: {
		RCFValueInteger *integer = R_NEW0 (RCFValueInteger);
		if (integer) {
			integer->value = ((RCFValueInteger *)value)->value;
			copy = (RCFValue *)integer;
		}
		break;
	}
	case R_CF_DATA: {
		RCFValueData *data = R_NEW0 (RCFValueData);
		if (data) {
			data->value = r_buf_new_with_buf(((RCFValueData *)value)->value);
			if (data->value) {
				copy = (RCFValue *)data;
			} else {
				R_FREE (data);
			}
		}
		break;
	}
	case R_CF_NULL:
		copy = (RCFValue *)(R_NEW0 (RCFValueNULL));
		break;
	case R_CF_TRUE:
	case R_CF_FALSE:
		copy = (RCFValue *)(R_NEW0 (RCFValueBool));
		break;
	default:
		break;
	}

	if (copy) {
		copy->type = value->type;
	}

	return copy;
}

static void r_cf_value_free(RCFValue *value) {
	if (!value) {
		return;
	}

	switch (value->type) {
	case R_CF_DICT:
		r_cf_value_dict_free ((RCFValueDict *)value);
		break;
	case R_CF_ARRAY:
		r_cf_value_array_free ((RCFValueArray *)value);
		break;
	case R_CF_STRING:
		r_cf_value_string_free ((RCFValueString *)value);
		break;
	case R_CF_INTEGER:
		r_cf_value_integer_free ((RCFValueInteger *)value);
		break;
	case R_CF_DATA:
		r_cf_value_data_free ((RCFValueData *)value);
		break;
	case R_CF_NULL:
		r_cf_value_null_free ((RCFValueNULL *)value);
		break;
	case R_CF_TRUE:
	case R_CF_FALSE:
		r_cf_value_bool_free ((RCFValueBool *)value);
		break;
	default:
		break;
	}
}

void r_cf_value_print (RCFValue *value) {
	if (!value) {
		return;
	}

	switch (value->type) {
	case R_CF_DICT:
		r_cf_value_dict_print ((RCFValueDict *)value);
		break;
	case R_CF_ARRAY:
		r_cf_value_array_print ((RCFValueArray *)value);
		break;
	case R_CF_STRING:
		r_cf_value_string_print ((RCFValueString *)value);
		break;
	case R_CF_INTEGER:
		r_cf_value_integer_print ((RCFValueInteger *)value);
		break;
	case R_CF_DATA:
		r_cf_value_data_print ((RCFValueData *)value);
		break;
	case R_CF_NULL:
		r_cf_value_null_print ((RCFValueNULL *)value);
		break;
	case R_CF_TRUE:
	case R_CF_FALSE:
		r_cf_value_bool_print ((RCFValueBool *)value);
		break;
	default:
		break;
	}
}
