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
	DSO_JSON_NULL = 1,
	DSO_JSON_NUM,
	DSO_JSON_STR,
	DSO_JSON_LIST,
	DSO_JSON_DICT,
	DSO_JSON_DICT_ENTRY,
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

ut8  dso_json_char_needs_hexing ( ut8 b);

void dso_json_obj_del (DsoJsonObj *dso_obj);
char * dso_json_obj_to_str (DsoJsonObj * dso_obj);
DsoJsonObj * dso_json_null_new (void);
void dso_json_null_free (void *x);
DsoJsonObj * dso_json_str_new (void);
void dso_json_str_free (void *y);
DsoJsonObj * dso_json_str_new_from_str (const char *str);
DsoJsonObj * dso_json_str_new_from_str_len (const char *str, unsigned int len);
DsoJsonObj * dso_json_str_new_from_num (long num);

DsoJsonObj * dso_json_dict_entry_new (void);
void dso_json_dict_entry_free (void *y);
int dso_json_dict_entry_set_key_str (DsoJsonObj * entry_obj, char *key);
int dso_json_dict_entry_set_key_str_len (DsoJsonObj * entry_obj, char *key, unsigned int len);
int dso_json_dict_entry_set_key_num (DsoJsonObj * entry_obj, st64 num);
int dso_json_dict_entry_value_append_str (DsoJsonObj *entry_obj, char *str);
int dso_json_dict_entry_value_append_str_len (DsoJsonObj *entry_obj, char *str, unsigned int len);
int dso_json_dict_entry_value_append_num (DsoJsonObj *entry_obj, st64 num);
int dso_json_dict_entry_value_append_obj (DsoJsonObj *entry_obj, DsoJsonObj *obj);
int dso_json_dict_entry_value_set_str (DsoJsonObj *entry_obj, char *str);
int dso_json_dict_entry_value_set_str_len (DsoJsonObj *entry_obj, char *str, unsigned int len);
int dso_json_dict_entry_value_set_num (DsoJsonObj *entry_obj, st64 num);
int dso_json_dict_entry_value_set_empty_dict (DsoJsonObj *entry_obj);
int dso_json_dict_entry_value_set_empty_list (DsoJsonObj *entry_obj);
int dso_json_dict_entry_value_set_obj (DsoJsonObj *entry_obj, DsoJsonObj *obj);

DsoJsonObj * dso_json_list_new (void);
void dso_json_list_free (DsoJsonObj *x);
int dso_json_list_append (DsoJsonObj *list_obj, DsoJsonObj *y);
int dso_json_list_append_str (DsoJsonObj *list_obj, char *y);
int dso_json_list_append_num (DsoJsonObj *list_obj, ut64 y);

DsoJsonObj * dso_json_dict_new (void);
int dso_json_dict_insert_str_key_obj (DsoJsonObj *dict, char *key, DsoJsonObj *val_obj);
int dso_json_dict_insert_str_key_num (DsoJsonObj *dict, char *key, int val);
int dso_json_dict_insert_str_key_str (DsoJsonObj *dict, char *key, char *val);
int dso_json_dict_insert_num_key_obj (DsoJsonObj *dict, int key, DsoJsonObj *val_obj);
int dso_json_dict_insert_num_key_num (DsoJsonObj *dict, int key, int val);
int dso_json_dict_insert_num_key_str (DsoJsonObj *dict, int key, char *val);
int dso_json_dict_insert_key_obj (DsoJsonObj *dict, DsoJsonObj *key, DsoJsonObj *value);
int dso_json_dict_remove_key_obj (DsoJsonObj *dict, DsoJsonObj *key);
int dso_json_dict_remove_key_str (DsoJsonObj *dict, char *key);
int dso_json_dict_contains_key_str (DsoJsonObj *dict, char *key);
int dso_json_dict_contains_key_obj (DsoJsonObj *dict, DsoJsonObj *key);
void dso_json_dict_free (void * y);

DsoJsonObj * dso_json_num_new (void);
void dso_json_num_free (void *y);
DsoJsonObj * dso_json_num_new_from_num (ut64 num);

char * dso_json_convert_string (const char * bytes, ut32 len );


#endif
