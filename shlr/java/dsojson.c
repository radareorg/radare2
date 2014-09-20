/* radare - Apache - Copyright 2014 dso <adam.pridgen@thecoverofnight.com | dso@rice.edu> */

#include "dsojson.h"
#include "class.h"
#include <r_types.h>
#include <r_util.h>
#include <stdint.h>

R_API char * dso_json_dict_entry_to_str (DsoJsonDictEntry * entry);
R_API char * dso_json_list_to_str (DsoJsonList *list);
R_API char * dso_json_dict_to_str (DsoJsonDict *list);
R_API char * dso_json_num_to_str (DsoJsonNum * num);
R_API char * dso_json_str_to_str (DsoJsonStr *str);

static int cmpDsoStr (DsoJsonStr *dsoStr1, DsoJsonStr *dsoStr2);
static int cmpDsoStr_to_str (DsoJsonStr *dsoStr1, char *dsoStr2);
static const DsoJsonInfo* get_type_info (unsigned int type);
static char * dso_json_get_str_data (DsoJsonObj *dso_obj);
static DsoJsonStr * dso_json_get_str (DsoJsonObj *dso_obj);

static DsoJsonInfo DSO_JSON_INFOS []= {
	{DSO_JSON_NULL},
	{DSO_JSON_NUM},//, dso_json_num_new, dso_json_free_num, dso_json_insert, dso_json_append, NULL, NULL, NULL, NULL},
	{DSO_JSON_STR},//, dso_json_str_new, dso_json_str_new, dso_json_insert, dso_json_append, NULL, NULL, NULL, NULL},
	{DSO_JSON_LIST},//, dso_json_list_new, dso_json_list_free, dso_json_insert, dso_json_list_append, NULL, NULL, NULL, NULL},
	{DSO_JSON_DICT},//, dso_json_dict_new, dso_json_free_dict, dso_json_insert_dict, dso_json_append, NULL, NULL, NULL, NULL},
	{DSO_JSON_DICT_ENTRY},//, dso_json_dict_entry_new, dso_json_dict_entry_free, dso_json_insert, dso_json_append, NULL, NULL, NULL, NULL},
	{DSO_JSON_END},//, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
};



static void * json_new0 (unsigned int sz) {
	char *alloc = malloc (sz);
	if (alloc) memset (alloc, 0, sz);
	return alloc;
}

static RList * build_str_list_from_iterable (RList *the_list) {
	RList * res = r_list_newf (free);
	DsoJsonObj *json_obj;
	RListIter *iter;
	r_list_foreach (the_list, iter, json_obj) {
		char *str = dso_json_obj_to_str (json_obj);
		r_list_append (res, str);
	}
	return res;
}

static char * build_str_from_str_list_for_iterable (RList *the_list) {
	char *res = NULL, *str;
	int len = 3, pos = 1;
	RListIter *iter = NULL;
	RList *str_list = build_str_list_from_iterable (the_list);
	int commas = r_list_length (str_list)-1;

	if (commas > -1) {
		r_list_foreach (str_list, iter, str) {
			len += strlen (str) + 1;
		}
	}

	res = json_new0 (len);

	if (res) {
		// build string
		int bytes = 0;
		char *str;
		r_list_foreach (str_list, iter, str) {
			if (commas > 0)
				bytes = snprintf (res+pos, len - pos, "%s,", str);
			else
				bytes = snprintf (res+pos, len - pos, "%s", str);
			pos += bytes;
			commas--;
		}
	}
	return res;
}
static int get_type (DsoJsonObj *y) {
	if (y) return y->info->type;
	return -1;
}

static int dso_json_is_null (DsoJsonObj *y) {
	return get_type (y) == DSO_JSON_NULL;
}

static int dso_json_is_str (DsoJsonObj *y) {
	return get_type (y) == DSO_JSON_STR;
}

static int dso_json_is_num (DsoJsonObj *y) {
	return get_type (y) == DSO_JSON_NUM;
}

static int dso_json_is_list (DsoJsonObj *y) {
	return get_type (y) == DSO_JSON_LIST;
}

static int dso_json_is_dict (DsoJsonObj *y) {
	return get_type (y) == DSO_JSON_DICT;
}

static int dso_json_is_dict_entry (DsoJsonObj *y) {
	return get_type (y) == DSO_JSON_DICT_ENTRY;
}

R_API ut8  dso_json_char_needs_hexing ( ut8 b) {
	if (b < 0x20) return 1;
	switch (b) {
		case 0x7f:
		case 0x81:
		case 0x8F:
		case 0x90:
		case 0x9D:
		case 0xA0:
		case 0xAD:
			return 1;
	}
	return 0;
}

R_API char * dso_json_obj_to_str (DsoJsonObj * dso_obj) {
	char *res = NULL;
	if (dso_obj) {
		switch (dso_obj->info->type) {
		case DSO_JSON_NULL: res = malloc (5); strcpy (res, "null"); break;
		case DSO_JSON_NUM: res = dso_json_num_to_str (dso_obj->val._num); break;
		case DSO_JSON_STR: res = dso_json_str_to_str (dso_obj->val._str); break;
		case DSO_JSON_LIST: res = dso_json_list_to_str (dso_obj->val._list); break;
		case DSO_JSON_DICT: res = dso_json_dict_to_str (dso_obj->val._dict); break;
		case DSO_JSON_DICT_ENTRY: res = dso_json_dict_entry_to_str (dso_obj->val._dict_entry); break;
		default: break;
		}
	}
	return res;
}

R_API void dso_json_obj_del (void *dso_objv) {
	DsoJsonObj *dso_obj = NULL;
	if (dso_objv) {
 		dso_obj = ((DsoJsonObj *) dso_objv);
		switch (dso_obj->info->type) {
		case DSO_JSON_NULL: /*do nothing */ break;
		case DSO_JSON_NUM: dso_json_num_free (dso_obj->val._num); break;
		case DSO_JSON_STR: dso_json_str_free (dso_obj->val._str); break;
		case DSO_JSON_LIST: dso_json_list_free (dso_obj->val._list); break;
		case DSO_JSON_DICT: dso_json_dict_free (dso_obj->val._dict); break;
		case DSO_JSON_DICT_ENTRY: dso_json_dict_entry_free (dso_obj->val._dict_entry); break;
		default: break;
		}
		dso_obj->val._num = NULL;
		dso_obj->info = NULL;
		free (dso_obj);
	}
}

static const DsoJsonInfo* get_type_info (unsigned int type) {
	unsigned int i = 0;
	for (; DSO_JSON_INFOS[i].type != DSO_JSON_END; i++) {
		if (DSO_JSON_INFOS[i].type == type) return &DSO_JSON_INFOS[i];
	}
	return NULL;
}

static int cmpDsoStr (DsoJsonStr *dsoStr1, DsoJsonStr *dsoStr2) {
	if (dsoStr1 && dsoStr2) return cmpDsoStr_to_str (dsoStr1, dsoStr2->data);
	return -1;
}

static int cmpDsoStr_to_str (DsoJsonStr *dsoStr1, char *dsoStr2) {
	if (dsoStr1 && dsoStr1->data && dsoStr2)
		return strcmp (dsoStr1->data, dsoStr2);
	return -1;
}

static void allocDsoStr (DsoJsonStr *dsoStr, unsigned int sz) {
	if (dsoStr->data) free (dsoStr->data);
	if (sz > 0) dsoStr->data = json_new0 (sz);
	else dsoStr->data = json_new0 (10);
	dsoStr->len = sz;
}

static RList * dso_json_get_list (DsoJsonObj *dso_obj) {
	RList *the_list = NULL;
	if (dso_obj) {
		switch (dso_obj->info->type) {
		case DSO_JSON_LIST: the_list = dso_obj->val._list->json_list; break;
		case DSO_JSON_DICT: the_list = dso_obj->val._dict->json_dict; break;
		default: break;
		}
	}
	return the_list;
}

static char * dso_json_get_str_data (DsoJsonObj *dso_obj) {
	DsoJsonStr * str = dso_json_get_str (dso_obj);
	if (str) return str->data;
	return NULL;
}

static DsoJsonStr * dso_json_get_str (DsoJsonObj *dso_obj) {
	DsoJsonStr * str = NULL;
	if (dso_obj) {
		switch (dso_obj->info->type) {
		case DSO_JSON_STR: str = dso_obj->val._str; break;
		case DSO_JSON_DICT_ENTRY: str = dso_json_get_str (dso_obj->val._dict_entry->key); break;
		default: break;
		}
	}
	return str;
}

R_API DsoJsonObj * dso_json_null_new () {
	DsoJsonObj *x = json_new0 (sizeof (DsoJsonObj));
	x->info = get_type_info (DSO_JSON_NULL);
	return x;
}

R_API void dso_json_null_free (void *x) {
	free (x);
}

R_API DsoJsonObj * dso_json_str_new () {
	DsoJsonObj *x = dso_json_null_new ();
	x->info = get_type_info (DSO_JSON_STR);
	x->val._str = json_new0  (sizeof (DsoJsonStr));
	return x;
}

R_API void dso_json_str_free (void *y) {
	DsoJsonStr *x = (DsoJsonStr *)y;
	if (x) {
		free (x->data);
		x->data = NULL;
	}
	free (x);
}

R_API DsoJsonObj * dso_json_dict_entry_new () {
	DsoJsonObj *x = dso_json_null_new ();
	x->info = get_type_info (DSO_JSON_DICT_ENTRY);
	x->val._dict_entry = json_new0  (sizeof (DsoJsonDictEntry));
	x->val._dict_entry->key = dso_json_str_new ();
	x->val._dict_entry->value = dso_json_null_new ();
	return x;
}

R_API DsoJsonObj * dso_json_dict_entry_new_from_key_obj_val_obj (DsoJsonObj *key, DsoJsonObj *value) {
	DsoJsonObj *x = dso_json_dict_entry_new ();
	dso_json_obj_del (x->val._dict_entry->key);
	dso_json_obj_del (x->val._dict_entry->value);
	x->val._dict_entry->key = key;
	x->val._dict_entry->value = value;
	return x;

}
R_API void dso_json_dict_entry_free (void *y) {
	DsoJsonDictEntry *entry = (DsoJsonDictEntry *)y;
	if (entry) {
		dso_json_obj_del (entry->key);
		dso_json_obj_del (entry->value);
		entry->key = NULL;
		entry->value = NULL;
	}
	free (entry);
}

R_API char * dso_json_dict_entry_to_str (DsoJsonDictEntry * entry) {
	char *res = NULL;
	if (entry) {
		char *key = dso_json_obj_to_str (entry->key),
		     *value = dso_json_obj_to_str (entry->value);

		if (key) {
			int len = 2 + 3 + strlen (key);
			if (value) len += strlen(value);
			res = json_new0 (len);
			if (res && value) {
				snprintf (res, len, "%s:%s", key, value);
			} else if (res) {
				snprintf (res, len, "%s:\"\"", key);
			}
		}
		free (key);
		free (value);

	}
	return res;
}

R_API int dso_json_dict_entry_set_key_str (DsoJsonObj * entry_obj, char *key) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonDictEntry *entry = (DsoJsonDictEntry *)entry_obj;
		DsoJsonObj *o_key = dso_json_str_new_from_str (key);
		if (entry->key) {
			dso_json_obj_del (entry->key);
		}
		entry->key = o_key;
		res = R_TRUE;
	}
	return res;
}

R_API int dso_json_dict_entry_set_key_str_len (DsoJsonObj * entry_obj, char *key, unsigned int len) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonDictEntry *entry = (DsoJsonDictEntry *)entry_obj;
		DsoJsonObj *o_key = dso_json_str_new_from_str_len (key, len);
		if (entry->key) {
			dso_json_obj_del (entry->key);
		}
		entry->key = o_key;
		res = R_TRUE;
	}
	return res;
}

R_API int dso_json_dict_entry_set_key_num (DsoJsonObj * entry_obj, st64 num) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonDictEntry *entry = (DsoJsonDictEntry *)entry_obj;
		DsoJsonObj *o_key = dso_json_num_new_from_num (num);
		if (entry->key) {
			dso_json_obj_del (entry->key);
		}
		entry->key = o_key;
		res = R_TRUE;
	}
	return res;
}

R_API int dso_json_dict_entry_value_append_str (DsoJsonObj *entry_obj, char *str) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_str = dso_json_str_new_from_str (str);
		res = dso_json_dict_entry_value_append_obj (entry_obj, o_str);
		if (!res) dso_json_obj_del (o_str);
	}
	return res;
}

R_API int dso_json_dict_entry_value_append_str_len (DsoJsonObj *entry_obj, char *str, unsigned int len) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_str = dso_json_str_new_from_str_len (str, len);
		res = dso_json_dict_entry_value_append_obj (entry_obj, o_str);
		if (!res) dso_json_obj_del (o_str);
	}
	return res;
}

R_API int dso_json_dict_entry_value_append_num (DsoJsonObj *entry_obj, st64 num) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_num = dso_json_num_new_from_num (num);
		res = dso_json_dict_entry_value_append_obj (entry_obj, o_num);
		if (!res) dso_json_obj_del (o_num);
	}
	return res;
}

R_API int dso_json_dict_entry_value_append_obj (DsoJsonObj *entry_obj, DsoJsonObj *obj) {
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonDictEntry *x = entry_obj->val._dict_entry;

		// check to see if the object can be converted to a list
		if (dso_json_is_null (x->value)) {
			DsoJsonObj *new_list = dso_json_list_new ();
			dso_json_obj_del (x->value);
			x->value = new_list;
		} else if (!dso_json_is_list (x->value)) {
			DsoJsonObj *tmp = x->value;
			x->value = dso_json_list_new ();
			dso_json_list_append (x->value, tmp);
		}

		if (dso_json_is_list (x->value)) {
			dso_json_list_append (x->value, obj);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int dso_json_dict_entry_value_set_str (DsoJsonObj *entry_obj, char *str) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_val = dso_json_str_new_from_str (str);
		res = dso_json_dict_entry_value_set_obj (entry_obj, o_val);
	}
	return res;
}

R_API int dso_json_dict_entry_value_set_str_len (DsoJsonObj *entry_obj, char *str, unsigned int len) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_val = dso_json_str_new_from_str_len (str, len);
		res = dso_json_dict_entry_value_set_obj (entry_obj, o_val);
	}
	return res;
}

R_API int dso_json_dict_entry_value_set_num (DsoJsonObj *entry_obj, st64 num) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_val = dso_json_num_new_from_num (num);
		res = dso_json_dict_entry_value_set_obj (entry_obj, o_val);
	}
	return res;
}

R_API int dso_json_dict_entry_value_set_empty_dict (DsoJsonObj *entry_obj) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_val = dso_json_dict_new ();
		res = dso_json_dict_entry_value_set_obj (entry_obj, o_val);
	}
	return res;
}

R_API int dso_json_dict_entry_value_set_empty_list (DsoJsonObj *entry_obj) {
	int res = R_FALSE;
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonObj *o_val = dso_json_list_new ();
		res = dso_json_dict_entry_value_set_obj (entry_obj, o_val);
	}
	return res;
}

R_API int dso_json_dict_entry_value_set_obj (DsoJsonObj *entry_obj, DsoJsonObj *obj) {
	if (dso_json_is_dict_entry (entry_obj)) {
		DsoJsonDictEntry *entry = entry_obj->val._dict_entry;
		if (entry->value) dso_json_obj_del (entry->value);
		entry->value = obj;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API DsoJsonObj * dso_json_list_new () {
	DsoJsonObj *x = dso_json_null_new ();
	x->info = get_type_info (DSO_JSON_LIST);
	x->val._list = json_new0  (sizeof (DsoJsonList));
	x->val._list->json_list = r_list_newf(dso_json_obj_del);
	return x;
}

R_API void dso_json_list_free (void *y) {
	DsoJsonList *x = (DsoJsonList *)y;
	if (x && x->json_list) {
		r_list_free (x->json_list);
		x->json_list = NULL;
	}
	free (x);
}

R_API char * dso_json_list_to_str (DsoJsonList *list) {
	char *res = NULL;
	if (list && list->json_list) {
		// TODO create a new list of strings from the list
		// of json objs
		res = build_str_from_str_list_for_iterable (list->json_list);
	}
	// adding [ and ] to the list ends
	if (!res) {
		res = json_new0 (3);
		strncpy (res, "[]", 3);
	} else {
		int end = 0;
		// need to put the prefix type or strlen returns 0;
		res[0] = '[';
		end = strlen (res);
		res[end] = ']';
	}
	return res;
}


R_API int dso_json_list_append (DsoJsonObj *list_obj, DsoJsonObj *y) {
	if (get_type (list_obj) == DSO_JSON_LIST) {
		DsoJsonList * list = list_obj->val._list;
		r_list_append (list->json_list, y);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int dso_json_list_append_str (DsoJsonObj *list_obj, char *y) {
	if (get_type (list_obj) == DSO_JSON_LIST) {
		DsoJsonObj *val = dso_json_str_new_from_str (y);
		int res = dso_json_list_append (list_obj, val);
		if (!res) dso_json_obj_del (val);
		return res;
	}
	return R_FALSE;
}

R_API int dso_json_list_append_num (DsoJsonObj *list_obj, ut64 y) {
	if (get_type (list_obj) == DSO_JSON_LIST) {
		DsoJsonObj *val = dso_json_num_new_from_num (y);
		int res = dso_json_list_append (list_obj, val);
		if (!res) dso_json_obj_del (val);
		return res;
	}
	return R_FALSE;
}

R_API DsoJsonObj * dso_json_dict_new () {
	DsoJsonObj *x = dso_json_null_new ();
	x->info = get_type_info (DSO_JSON_DICT);
	x->val._dict = json_new0 (sizeof (DsoJsonObj));
	x->val._dict->json_dict = r_list_newf (dso_json_obj_del);
	return x;
}

R_API void dso_json_dict_free (void *y) {
	DsoJsonDict *x = (DsoJsonDict *)y;
	if (x && x->json_dict) {
		r_list_free (x->json_dict);
		x->json_dict = NULL;
	}
	free (x);
}

R_API char * dso_json_dict_to_str (DsoJsonDict *dict) {
	char *res = NULL;
	if (dict && dict->json_dict) {
		res = build_str_from_str_list_for_iterable (dict->json_dict);
	}
	// adding { and } to the list ends
	if (!res) {
		res = json_new0 (3);
		strncpy (res, "{}", 3);
	} else {
		int end = 0;
		// need to put the prefix type or strlen returns 0;
		res[0] = '{';
		end = strlen (res);
		res[end] = '}';
	}
	return res;
}

R_API int dso_json_dict_insert_str_key_obj (DsoJsonObj *dict, char *key, DsoJsonObj *val_obj) {
	DsoJsonObj *key_obj = dso_json_str_new_from_str (key);
	int res = dso_json_dict_insert_key_obj (dict, key_obj, val_obj);
	if (!res) {
		dso_json_obj_del (key_obj);
	}
	return res;
}


R_API int dso_json_dict_insert_str_key_num (DsoJsonObj *dict, char *key, int val) {
	DsoJsonObj *key_obj = dso_json_str_new_from_str (key),
			*val_obj = dso_json_num_new_from_num (val);
	int res = dso_json_dict_insert_key_obj (dict, key_obj, val_obj);
	if (!res) {
		dso_json_obj_del (key_obj);
		dso_json_obj_del (val_obj);
	}
	return res;
}

R_API int dso_json_dict_insert_str_key_str (DsoJsonObj *dict, char *key, char *val) {
	DsoJsonObj *key_obj = dso_json_str_new_from_str (key),
			*val_obj = dso_json_str_new_from_str (val);
	int res = dso_json_dict_insert_key_obj (dict, key_obj, val_obj);
	if (!res) {
		dso_json_obj_del (key_obj);
		dso_json_obj_del (val_obj);
	}
	return res;
}

// create keys from num value
R_API int dso_json_dict_insert_num_key_obj (DsoJsonObj *dict, int key, DsoJsonObj *val_obj) {
	DsoJsonObj *key_obj = dso_json_str_new_from_num (key);
	int res = dso_json_dict_insert_key_obj (dict, key_obj, val_obj);
	if (!res) {
		dso_json_obj_del (key_obj);
	}
	return res;
}


R_API int dso_json_dict_insert_num_key_num (DsoJsonObj *dict, int key, int val) {
	DsoJsonObj *key_obj = dso_json_str_new_from_num (key),
			*val_obj = dso_json_num_new_from_num (val);
	int res = dso_json_dict_insert_key_obj (dict, key_obj, val_obj);
	if (!res) {
		dso_json_obj_del (key_obj);
		dso_json_obj_del (val_obj);
	}
	return res;
}

R_API int dso_json_dict_insert_num_key_str (DsoJsonObj *dict, int key, char *val) {
	DsoJsonObj *key_obj = dso_json_str_new_from_num (key),
			*val_obj = dso_json_str_new_from_str (val);
	int res = dso_json_dict_insert_key_obj (dict, key_obj, val_obj);
	if (!res) {
		dso_json_obj_del (key_obj);
		dso_json_obj_del (val_obj);
	}
	return res;
}

// TODO inserting the dicts.
R_API int dso_json_dict_insert_key_obj (DsoJsonObj *dict, DsoJsonObj *key, DsoJsonObj *value) {
	int res = R_FALSE;
	RList* the_list = dso_json_get_list (dict);
	if (!the_list) return R_FALSE;
	if (get_type (key) != DSO_JSON_STR) return R_FALSE;
	if (!value) value = dso_json_null_new ();
	if (value && key && !dso_json_dict_contains_key_obj (dict, key)) {
		DsoJsonObj *entry = dso_json_dict_entry_new_from_key_obj_val_obj (key, value);
		r_list_append (the_list, entry);
		res = R_TRUE;
	//TODO implement the remove key
	}else if (value && key && !dso_json_dict_remove_key_obj (dict, key)) {
		DsoJsonObj *entry = dso_json_dict_entry_new_from_key_obj_val_obj (key, value);
		r_list_append (the_list, entry);
		res = R_TRUE;
	}
	return res;
}

R_API int dso_json_dict_remove_key_obj (DsoJsonObj *dict, DsoJsonObj *key) {
	return dso_json_dict_remove_key_str (dict, dso_json_get_str_data (key));
}

R_API int dso_json_dict_remove_key_str (DsoJsonObj *dict, char *key) {
	RListIter *iter;
	DsoJsonObj *dso_obj;
	int res = R_FALSE;
	RList* the_list = dso_json_get_list (dict);
	if (the_list) {
		r_list_foreach (the_list, iter, dso_obj) {
			if (get_type (dso_obj) == DSO_JSON_DICT_ENTRY &&
				get_type (dso_obj->val._dict_entry->key) == DSO_JSON_STR) {
				if (!cmpDsoStr_to_str (dso_json_get_str (dso_obj), key)) {
					res = R_TRUE;
					r_list_delete (the_list, iter);
					break;
				}
			}
		}
	}
	return res;
}

R_API int dso_json_dict_contains_key_obj (DsoJsonObj *dict, DsoJsonObj *key) {
	return dso_json_dict_contains_key_str (dict, dso_json_get_str_data (key));
}

R_API int dso_json_dict_contains_key_str (DsoJsonObj *dict, char *key) {
	RListIter *iter;
	DsoJsonObj *dso_obj;
	int res = R_FALSE;
	RList* the_list = dso_json_get_list (dict);
	if (the_list) {
		r_list_foreach (the_list, iter, dso_obj) {
			if (get_type (dso_obj) == DSO_JSON_DICT_ENTRY &&
				get_type (dso_obj->val._dict_entry->key) == DSO_JSON_STR) {
				if (!cmpDsoStr_to_str (dso_json_get_str (dso_obj),  key)) {
					res = R_TRUE;
					break;
				}
			}
		}
	}
	return res;
}


// TODO append value to key 1) check that key is valid, 2) if not create new entry and append it

R_API DsoJsonObj * dso_json_num_new () {
	DsoJsonObj *x = dso_json_null_new ();
	x->info = get_type_info (DSO_JSON_NUM);
	x->val._num = json_new0 (sizeof (DsoJsonNum));
	return x;
}

R_API void dso_json_num_free (void *y) {
	DsoJsonNum *x = (DsoJsonNum *)y;
	free (x);
}

R_API char * dso_json_num_to_str (DsoJsonNum * num) {
	char *res = NULL;
	if (num) {
		int len = 50+3;
		res = json_new0 (len);
		if (res) snprintf (res, len, "%"PFMT64d, num->value);
	}
	return res;
}

R_API DsoJsonObj * dso_json_num_new_from_num (ut64 num) {
	DsoJsonObj *x = dso_json_num_new ();
	x->val._num->value = num;
	return x;
}

R_API char * dso_json_convert_string (const char * bytes, ut32 len ) {
	ut32 idx = 0, pos = 1;
	ut32 str_sz = 4*len+1+2;
	int end = 0;
	char *cpy_buffer = len > 0 ? malloc (str_sz): NULL;
	if (!cpy_buffer) return cpy_buffer;
	// 4x is the increase from byte to \xHH where HH represents hexed byte
	memset (cpy_buffer, 0, str_sz);
	cpy_buffer[0] = '"';
	while (idx < len) {
		if (bytes[idx] == '"') {
			sprintf (cpy_buffer+pos, "\\%c", bytes[idx]);
			pos += 2;
		} else if (dso_json_char_needs_hexing (bytes[idx])) {
			sprintf (cpy_buffer+pos, "\\x%02x", bytes[idx]);
			pos += 4;
		} else {
			cpy_buffer[pos] = bytes[idx];
			pos++;
		}
		idx ++;
	}
	end = strlen (cpy_buffer);
	cpy_buffer[end] = '"';
	return cpy_buffer;
}

R_API char * dso_json_str_to_str (DsoJsonStr *str) {
	char *res = NULL;
	if (str) {
		res = dso_json_convert_string (str->data, str->len);
	}
	return res;
}

R_API DsoJsonObj * dso_json_str_new_from_str (const char *str) {
	DsoJsonObj *x = dso_json_str_new ();
	DsoJsonStr * dsoStr = x->val._str;
	allocDsoStr (dsoStr, strlen (str));
	if (dsoStr->data) memcpy (dsoStr->data, str, dsoStr->len);
	return x;
}

R_API DsoJsonObj * dso_json_str_new_from_str_len (const char *str, unsigned int len) {
	DsoJsonObj *x = dso_json_str_new ();
	DsoJsonStr * dsoStr = x->val._str;
	allocDsoStr (dsoStr, len);
	if (dsoStr) memcpy (dsoStr->data, str, dsoStr->len);
	return x;
}

R_API DsoJsonObj * dso_json_str_new_from_num (long num) {
	DsoJsonObj *x = dso_json_str_new ();
	DsoJsonStr * dsoStr = x->val._str;
	int len = snprintf (NULL, 0, "%lu", num);
	allocDsoStr (dsoStr, len-1);
	snprintf (dsoStr->data, dsoStr->len, "%lu", num);
	return x;
}
