/* radare - Apache - Copyright 2014 dso <adam.pridgen@thecoverofnight.com | dso@rice.edu> */

#ifndef _INCLUDE_DOSJSON_H_
#define _INCLUDE_DOSJSON_H_

#include <r_types.h>
#include <r_util.h>

struct  basic_json_t;
typedef struct dso_json_info_t {
	unsigned char type;
} DsoJsonInfo;

typedef enum {
	DSO_JSON_NULL = 0x00,
	DSO_JSON_NUM = 0x01,
	DSO_JSON_STR = 0x02,
	DSO_JSON_LIST = 0x03,
	DSO_JSON_DICT = 0x04,
	DSO_JSON_DICT_ENTRY = 0x05,
	DSO_JSON_END = 0xFF,
} DSO_JSON_TYPES;

typedef struct  basic_json_num_t {
	ut64 value;
} DsoJsonNum;

typedef struct  basic_json_str_t {
	ut64 len;
	char * data;
} DsoJsonStr;

typedef struct  basic_json_dict_entry_t {
	struct  basic_json_t *key;
	struct  basic_json_t *value;
} DsoJsonDictEntry;

typedef struct  basic_json_dict_t {
	// TODO finish this
	RList /*DsoJsonDictEntry*/ *json_dict;
} DsoJsonDict;

typedef struct  basic_json_list_t {
	// TODO finish this
	RList *json_list;
} DsoJsonList;


typedef struct  basic_json_t {
	const DsoJsonInfo *info;
	union {
		DsoJsonNum*  _num;
		DsoJsonStr* _str;
		DsoJsonList *_list;
		DsoJsonDict *_dict;
		DsoJsonDictEntry *_dict_entry;
	} val;
} DsoJsonObj;

R_API ut8  dso_json_char_needs_hexing ( ut8 b);

R_API void dso_json_obj_del (void *dso_objv);

R_API char * dso_json_obj_to_str (DsoJsonObj * dso_obj);
R_API DsoJsonObj * dso_json_null_new ();
R_API void dso_json_null_free (void *x);
R_API DsoJsonObj * dso_json_str_new ();
R_API void dso_json_str_free (void *y);
R_API DsoJsonObj * dso_json_str_new_from_str (const char *str);
R_API DsoJsonObj * dso_json_str_new_from_str_len (const char *str, unsigned int len);
R_API DsoJsonObj * dso_json_str_new_from_num (long num);

R_API DsoJsonObj * dso_json_dict_entry_new ();
R_API void dso_json_dict_entry_free (void *y);
R_API int dso_json_dict_entry_set_key_str (DsoJsonObj * entry_obj, char *key);
R_API int dso_json_dict_entry_set_key_str_len (DsoJsonObj * entry_obj, char *key, unsigned int len);
R_API int dso_json_dict_entry_set_key_num (DsoJsonObj * entry_obj, st64 num);
R_API int dso_json_dict_entry_value_append_str (DsoJsonObj *entry_obj, char *str);
R_API int dso_json_dict_entry_value_append_str_len (DsoJsonObj *entry_obj, char *str, unsigned int len);
R_API int dso_json_dict_entry_value_append_num (DsoJsonObj *entry_obj, st64 num);
R_API int dso_json_dict_entry_value_append_obj (DsoJsonObj *entry_obj, DsoJsonObj *obj);
R_API int dso_json_dict_entry_value_set_str (DsoJsonObj *entry_obj, char *str);
R_API int dso_json_dict_entry_value_set_str_len (DsoJsonObj *entry_obj, char *str, unsigned int len);
R_API int dso_json_dict_entry_value_set_num (DsoJsonObj *entry_obj, st64 num);
R_API int dso_json_dict_entry_value_set_empty_dict (DsoJsonObj *entry_obj);
R_API int dso_json_dict_entry_value_set_empty_list (DsoJsonObj *entry_obj);
R_API int dso_json_dict_entry_value_set_obj (DsoJsonObj *entry_obj, DsoJsonObj *obj);

R_API DsoJsonObj * dso_json_list_new ();
R_API void dso_json_list_free (void *y);
R_API int dso_json_list_append (DsoJsonObj *list_obj, DsoJsonObj *y);
R_API int dso_json_list_append_str (DsoJsonObj *list_obj, char *y);
R_API int dso_json_list_append_num (DsoJsonObj *list_obj, ut64 y);

R_API DsoJsonObj * dso_json_dict_new ();
R_API int dso_json_dict_insert_str_key_obj (DsoJsonObj *dict, char *key, DsoJsonObj *val_obj);
R_API int dso_json_dict_insert_str_key_num (DsoJsonObj *dict, char *key, int val);
R_API int dso_json_dict_insert_str_key_str (DsoJsonObj *dict, char *key, char *val);
R_API int dso_json_dict_insert_num_key_obj (DsoJsonObj *dict, int key, DsoJsonObj *val_obj);
R_API int dso_json_dict_insert_num_key_num (DsoJsonObj *dict, int key, int val);
R_API int dso_json_dict_insert_num_key_str (DsoJsonObj *dict, int key, char *val);
R_API int dso_json_dict_insert_key_obj (DsoJsonObj *dict, DsoJsonObj *key, DsoJsonObj *value);
R_API int dso_json_dict_remove_key_obj (DsoJsonObj *dict, DsoJsonObj *key);
R_API int dso_json_dict_remove_key_str (DsoJsonObj *dict, char *key);
R_API int dso_json_dict_contains_key_str (DsoJsonObj *dict, char *key);
R_API int dso_json_dict_contains_key_obj (DsoJsonObj *dict, DsoJsonObj *key);
R_API void dso_json_dict_free (void * y);

R_API DsoJsonObj * dso_json_num_new ();
R_API void dso_json_num_free (void *y);
R_API DsoJsonObj * dso_json_num_new_from_num (ut64 num);

R_API char * dso_json_convert_string (const char * bytes, ut32 len );


#endif
