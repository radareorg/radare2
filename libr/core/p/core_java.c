/* radare - Apache - Copyright 2014-2016 - dso, pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>
#include <r_anal.h>
#include <r_anal_ex.h>

#if 0
#include "../../../shlr/java/ops.c"
#include "../../../shlr/java/code.c"
#include "../../../shlr/java/class.c"
#endif
#include "../../../shlr/java/class.h"
#include "../../../shlr/java/code.h"
#include "../../../shlr/java/dsojson.h"

#define DO_THE_DBG 0
#undef IFDBG
#define IFDBG if (DO_THE_DBG)


typedef struct found_idx_t {
	ut16 idx;
	ut64 addr;
	const RBinJavaCPTypeObj *obj;
} RCmdJavaCPResult;

typedef int (*RCMDJavaCmdHandler) (RCore *core, const char *cmd);

static const char * r_cmd_java_strtok (const char *str1, const char b, size_t len);
static const char * r_cmd_java_consumetok (const char *str1, const char b, size_t len);
static int r_cmd_java_reload_bin_from_buf (RCore *core, RBinJavaObj *obj, ut8* buffer, ut64 len);

static int r_cmd_java_print_json_definitions( RBinJavaObj *obj  );
static int r_cmd_java_print_all_definitions( RAnal *anal );
static int r_cmd_java_print_class_definitions( RBinJavaObj *obj );
static int r_cmd_java_print_field_definitions( RBinJavaObj *obj );
static int r_cmd_java_print_method_definitions( RBinJavaObj *obj );
static int r_cmd_java_print_import_definitions( RBinJavaObj *obj );

static int r_cmd_java_resolve_cp_idx (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_resolve_cp_type (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_resolve_cp_idx_b64 (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_resolve_cp_address (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_resolve_cp_to_key (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_resolve_cp_summary (RBinJavaObj *obj, ut16 idx);

static int r_cmd_java_print_class_access_flags_value( const char * flags );
static int r_cmd_java_print_field_access_flags_value( const char * flags );
static int r_cmd_java_print_method_access_flags_value( const char * flags );
static int r_cmd_java_get_all_access_flags_value (const char *cmd);

static int r_cmd_java_set_acc_flags (RCore *core, ut64 addr, ut16 num_acc_flag);

#define _(x) UNUSED_FUNCTION(x)
static int r_cmd_java_print_field_summary (RBinJavaObj *obj, ut16 idx);
static int _(r_cmd_java_print_field_count) (RBinJavaObj *obj);
static int r_cmd_java_print_field_name (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_print_field_num_name (RBinJavaObj *obj);
static int r_cmd_java_print_method_summary (RBinJavaObj *obj, ut16 idx);
static int _(r_cmd_java_print_method_count) (RBinJavaObj *obj);
static int r_cmd_java_print_method_name (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_print_method_num_name (RBinJavaObj *obj);

static RBinJavaObj * r_cmd_java_get_bin_obj(RAnal *anal);
static RList * r_cmd_java_get_bin_obj_list(RAnal *anal);
static ut64 r_cmd_java_get_input_num_value(RCore *core, const char *input_value);
static int r_cmd_java_is_valid_input_num_value(RCore *core, const char *input_value);


static int r_cmd_java_call(void *user, const char *input);
static int r_cmd_java_handle_help (RCore * core, const char * input);
static int r_cmd_java_handle_set_flags (RCore * core, const char * cmd);
static int r_cmd_java_handle_prototypes (RCore * core, const char * cmd);
static int r_cmd_java_handle_resolve_cp (RCore * core, const char * cmd);
static int r_cmd_java_handle_calc_flags (RCore * core, const char * cmd);
static int r_cmd_java_handle_flags_str (RCore *core, const char *cmd);
static int r_cmd_java_handle_flags_str_at (RCore *core, const char *cmd);
static int r_cmd_java_handle_field_info (RCore *core, const char *cmd);
static int r_cmd_java_handle_method_info (RCore *core, const char *cmd);

static int r_cmd_java_handle_find_cp_const (RCore *core, const char *cmd);

static RList * cpfind_float (RCore *core, RBinJavaObj *obj, const char *cmd);
static RList * cpfind_double (RCore *core, RBinJavaObj *obj, const char *cmd);
static RList * cpfind_long (RCore *core, RBinJavaObj *obj, const char *cmd);
static RList * cpfind_int (RCore *core, RBinJavaObj *obj, const char *cmd);
static RList * cpfind_str (RCore *core, RBinJavaObj *obj, const char *cmd);

static int cpfind (RCore *core, const char *cmd);

static int r_cmd_java_get_cp_bytes_and_write (RCore *core, RBinJavaObj *obj, ut16 idx, ut64 addr, const ut8* buf, const ut64 len);
static int r_cmd_java_handle_replace_cp_value_float (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int r_cmd_java_handle_replace_cp_value_double (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int r_cmd_java_handle_replace_cp_value_long (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int r_cmd_java_handle_replace_cp_value_int (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int r_cmd_java_handle_replace_cp_value_str (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int r_cmd_java_handle_replace_cp_value (RCore *core, const char *cmd);

static int r_cmd_java_handle_replace_classname_value (RCore *core, const char *cmd);
static char * r_cmd_replace_name_def (const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len);
static char * r_cmd_replace_name (const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len);
static int r_cmd_is_object_descriptor (const char *name, ut32 name_len);
static ut32 r_cmd_get_num_classname_str_occ (const char * str, const char *match_me);
static const char * r_cmd_get_next_classname_str (const char * str, const char *match_me);

static int r_cmd_java_handle_summary_info (RCore *core, const char *cmd);
static int r_cmd_java_handle_reload_bin (RCore *core, const char *cmd);
static int r_cmd_java_handle_list_code_references (RCore *core, const char *cmd);
static char * r_cmd_java_get_descriptor (RCore *core, RBinJavaObj *bin, ut16 idx);

static int r_cmd_java_handle_print_exceptions (RCore *core, const char *input);
static int r_cmd_java_handle_insert_method_ref (RCore *core, const char *input);
static int r_cmd_java_handle_yara_code_extraction_refs (RCore *core, const char *input);

static int r_cmd_java_handle_isvalid (RCore *core, const char *cmd);
static int r_cmd_java_handle_calc_class_sz (RCore *core, const char *cmd);

typedef struct r_cmd_java_cms_t {
	const char *name;
	const char *args;
	const char *desc;
	const ut32 name_len;
	RCMDJavaCmdHandler handler;
} RCmdJavaCmd;

/* XXX : Most of those command arguments are absurd, must be reviewed + changed */

#define CALC_SZ "calc_sz"
#define CALC_SZ_ARGS " <addr>"
#define CALC_SZ_DESC "calculate class file size at location"
#define CALC_SZ_LEN 7

#define ISVALID "is_valid"
#define ISVALID_ARGS " <addr> <sz>"
#define ISVALID_DESC "check buffer to see if it is a valid class file"
#define ISVALID_LEN 8

#define SET_ACC_FLAGS "set_flags"
#define SET_ACC_FLAGS_ARGS " [addr cmf <value>]" //[<addr> <c | m | f> <num_flag_val>] | [<addr> < c | m | f> <flag value separated by space> ]"
#define SET_ACC_FLAGS_DESC "set the access flags attributes for a field or method"
#define SET_ACC_FLAGS_LEN 9

#define PROTOTYPES "prototypes"
#define PROTOTYPES_ARGS " <jaicmf>" // < j | a | i | c | m | f>
#define PROTOTYPES_DESC "show in JSON, or All,Imports,Class,Methods,Fields"
#define PROTOTYPES_LEN 10

#define RESOLVE_CP "resolve_cp"
#define RESOLVE_CP_ARGS " [<stecadg> idx]"
#define RESOLVE_CP_DESC "cp type or value @ idx. Summary,Type,b64Encode,Const,Addr,Dump,Gsumarize"
//d = dump all,  g = summarize all, s = summary, a = address, t = type, c = get value, e = base64 enode the result"
#define RESOLVE_CP_LEN 10

#define CALC_FLAGS "calc_flags"
#define CALC_FLAGS_ARGS " <lcfm> [visib.]"
//[ <l <[c|f|m]>> | <c [public,private,static...]>  | <f [public,private,static...]> | <m c [public,private,static...]>]"
#define CALC_FLAGS_DESC "value from access flags: ListAll, flags, Class, Field, Method"
#define CALC_FLAGS_LEN 10

#define FLAGS_STR_AT "flags_str_at"
#define FLAGS_STR_AT_ARGS " <cfm> [addr]"
#define FLAGS_STR_AT_DESC "string value from access flags @ addr: Class, Field, Method"
#define FLAGS_STR_AT_LEN 12

#define FLAGS_STR "flags_str"
#define FLAGS_STR_ARGS " [<cfm> <access>]" //acc_flags_value>]"
#define FLAGS_STR_DESC "string value for the flags number: Class, Field, Method"
#define FLAGS_STR_LEN 9

#define METHOD_INFO "m_info"
#define METHOD_INFO_ARGS " [<p,c,s idx> | <n idx>]"
//#define METHOD_INFO_DESC "method index info: c = dump methods and ord , s = dump of all meta-data, n = method"
#define METHOD_INFO_DESC "method information at index (c:method+ord, s:metadata)"
#define METHOD_INFO_LEN 6

#define FIELD_INFO "f_info"
#define FIELD_INFO_ARGS " [<p,c,s idx> | #idx]"
#define FIELD_INFO_DESC "field information at index (c:field+ord, s:metadata)"
// : c = dump field and ord , s = dump of all meta-data, n = method"
#define FIELD_INFO_LEN 6

#define HELP "help"
#define HELP_DESC "displays this message"
#define HELP_ARGS ""
#define HELP_LEN 4

#define FIND_CP_CONST "find_cp_const"
#define FIND_CP_CONST_ARGS " [a|#idx]"
#define FIND_CP_CONST_DESC "find references to constant CP Object in code: AllReferences"
#define FIND_CP_CONST_LEN 13

#define FIND_CP_VALUE "find_cp_value"
#define FIND_CP_VALUE_ARGS " [<silfd> V]"
#define FIND_CP_VALUE_DESC "find references to CP constants by value"
#define FIND_CP_VALUE_LEN 13

#define REPLACE_CP_VALUE "replace_cp_value"
#define REPLACE_CP_VALUE_ARGS " [<idx> V]"
#define REPLACE_CP_VALUE_DESC "replace CP constants with value if the no resizing is required"
#define REPLACE_CP_VALUE_LEN 16

#define REPLACE_CLASS_NAME "replace_classname_value"
#define REPLACE_CLASS_NAME_ARGS " <c> <nc>"
#define REPLACE_CLASS_NAME_DESC "rename class name" //"replace CP constants with value if no resize needed"
#define REPLACE_CLASS_NAME_LEN 23

#define RELOAD_BIN "reload_bin"
#define RELOAD_BIN_ARGS " addr [size]"
#define RELOAD_BIN_DESC "reload and reanalyze the Java class file starting at address"
#define RELOAD_BIN_LEN 10

#define SUMMARY_INFO "summary"
#define SUMMARY_INFO_ARGS ""
#define SUMMARY_INFO_DESC "print summary information for the current java class file"
#define SUMMARY_INFO_LEN 7

#define LIST_CODE_REFS "lcr"
#define LIST_CODE_REFS_ARGS " [addr]"
#define LIST_CODE_REFS_DESC "list all references to fields and methods in code sections"
#define LIST_CODE_REFS_LEN 3

#define PRINT_EXC "exc"
#define PRINT_EXC_ARGS " [<addr>]"
#define PRINT_EXC_DESC "list all exceptions to fields and methods in code sections"
#define PRINT_EXC_LEN 3

#define YARA_CODE_REFS "yc_w_refs"
#define YARA_CODE_REFS_ARGS " [name] [start] [count]"
#define YARA_CODE_REFS_DESC "yara code bytes extraction with a name starting at <start> to <count>"
#define YARA_CODE_REFS_LEN 9

#define INSERT_MREF "i_mref"
#define INSERT_MREF_ARGS " C M S" //<meth> <desc>" //descriptor in form of (Lpref;)Lref;"
#define INSERT_MREF_DESC "add Method to Class with given method signature" //append a method reference CP object to the end of the CP object array (creates all requisite objects)"
#define INSERT_MREF_LEN 6


static RCmdJavaCmd JAVA_CMDS[] = {
	{HELP, HELP_ARGS, HELP_DESC, HELP_LEN, r_cmd_java_handle_help},
	{SET_ACC_FLAGS, SET_ACC_FLAGS_ARGS, SET_ACC_FLAGS_DESC, SET_ACC_FLAGS_LEN, r_cmd_java_handle_set_flags},
	{PROTOTYPES, PROTOTYPES_ARGS, PROTOTYPES_DESC, PROTOTYPES_LEN, r_cmd_java_handle_prototypes},
	{RESOLVE_CP, RESOLVE_CP_ARGS, RESOLVE_CP_DESC, RESOLVE_CP_LEN, r_cmd_java_handle_resolve_cp},
	{CALC_FLAGS, CALC_FLAGS_ARGS, CALC_FLAGS_DESC, CALC_FLAGS_LEN, r_cmd_java_handle_calc_flags},
	{FLAGS_STR_AT, FLAGS_STR_AT_ARGS, FLAGS_STR_AT_DESC, FLAGS_STR_AT_LEN, r_cmd_java_handle_flags_str_at},
	{FLAGS_STR, FLAGS_STR_ARGS, FLAGS_STR_DESC, FLAGS_STR_LEN, r_cmd_java_handle_flags_str},
	{METHOD_INFO, METHOD_INFO_ARGS, METHOD_INFO_DESC, METHOD_INFO_LEN, r_cmd_java_handle_method_info},
	{FIELD_INFO, FIELD_INFO_ARGS, FIELD_INFO_DESC, FIELD_INFO_LEN, r_cmd_java_handle_field_info},
	{FIND_CP_CONST, FIND_CP_CONST_ARGS, FIND_CP_CONST_DESC, FIND_CP_CONST_LEN, r_cmd_java_handle_find_cp_const},
	{FIND_CP_VALUE, FIND_CP_VALUE_ARGS, FIND_CP_VALUE_DESC, FIND_CP_VALUE_LEN, cpfind},
	{REPLACE_CP_VALUE, REPLACE_CP_VALUE_ARGS, REPLACE_CP_VALUE_DESC, REPLACE_CP_VALUE_LEN, r_cmd_java_handle_replace_cp_value},
	{REPLACE_CLASS_NAME, REPLACE_CLASS_NAME_ARGS, REPLACE_CLASS_NAME_DESC, REPLACE_CLASS_NAME_LEN, r_cmd_java_handle_replace_classname_value},
	{RELOAD_BIN, RELOAD_BIN_ARGS, RELOAD_BIN_DESC, RELOAD_BIN_LEN, r_cmd_java_handle_reload_bin},
	{SUMMARY_INFO, SUMMARY_INFO_ARGS, SUMMARY_INFO_DESC, SUMMARY_INFO_LEN, r_cmd_java_handle_summary_info},
	{LIST_CODE_REFS, LIST_CODE_REFS_ARGS, LIST_CODE_REFS_DESC, LIST_CODE_REFS_LEN, r_cmd_java_handle_list_code_references},
	{PRINT_EXC, PRINT_EXC_ARGS, PRINT_EXC_DESC, PRINT_EXC_LEN, r_cmd_java_handle_print_exceptions},
	{YARA_CODE_REFS, YARA_CODE_REFS_ARGS, YARA_CODE_REFS_DESC, YARA_CODE_REFS_LEN, r_cmd_java_handle_yara_code_extraction_refs},
	{INSERT_MREF, INSERT_MREF_ARGS, INSERT_MREF_DESC, INSERT_MREF_LEN, r_cmd_java_handle_insert_method_ref},
	{CALC_SZ, CALC_SZ_ARGS, CALC_SZ_DESC, CALC_SZ_LEN, r_cmd_java_handle_calc_class_sz},
	{ISVALID, ISVALID_ARGS, ISVALID_DESC, ISVALID_LEN, r_cmd_java_handle_isvalid},
};

enum {
	HELP_IDX = 0,
	SET_ACC_FLAGS_IDX = 1,
	PROTOTYPES_IDX = 2,
	RESOLVE_CP_IDX = 3,
	CALC_FLAGS_IDX = 4,
	FLAGS_STR_AT_IDX = 5,
	FLAGS_STR_IDX = 6,
	METHOD_INFO_IDX = 7,
	FIELD_INFO_IDX = 8,
	FIND_CP_CONST_IDX = 9,
	FIND_CP_VALUE_IDX = 10,
	REPLACE_CP_VALUE_IDX = 11,
	REPLACE_CLASS_NAME_IDX = 12,
	RELOAD_BIN_IDX = 13,
	SUMMARY_INFO_IDX = 14,
	LIST_CODE_REFS_IDX = 15,
	PRINT_EXC_IDX = 16,
	YARA_CODE_REFS_IDX = 17,
	INSERT_MREF_IDX = 18,
	CALC_SZ_IDX = 19,
	ISVALID_IDX = 20,
	END_CMDS = 21,
};

static ut8 _(r_cmd_java_obj_ref)(const char *name, const char *class_name, ut32 len) {
	if (!name || !class_name) return false;
	if (strncmp (class_name, name, len)) return false;
	if (*(name-1) == 'L' && *(name+len) == ';') return true;
	if (!strncmp (class_name, name, len) && !*(name+len)) return true;
	return false;
}

static const char * r_cmd_get_next_classname_str (const char * str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me ? strlen (match_me) : 0;
	if (len && str && *str) {
		result = str;
		while (result && *result && (result - str < len)) {
			result = strstr (result, match_me);
			if (result ) break;
		}
	}
	return result;
}

static ut32 r_cmd_get_num_classname_str_occ (const char * str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me ? strlen (match_me) : 0;
	ut32 occ = 0;

	if (len == 0 || !str || !*str ) return 0;
	result = str;
	while (result && *result && (result - str < len)) {
		result = strstr (result, match_me);
		if (result) {
			IFDBG eprintf ("result: %s\n", result);
			result+=len;
			occ++;
		}
	}
	return occ;
}

static const char * r_cmd_java_consumetok (const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p) return p;
	if (len == -1) len = strlen (str1);
	for ( ; i < len; i++,p++) {
		if (*p != b) {
			break;
		}
	}
	return p;
}

static const char * r_cmd_java_strtok (const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p || !*p) return p;
	if (len == -1) len = strlen (str1);
	IFDBG r_cons_printf ("Looking for char (%c) in (%s) up to %d\n", b, p, len);
	for ( ; i < len; i++,p++) {
		if (*p == b) {
			IFDBG r_cons_printf ("Found? for char (%c) @ %d: (%s)\n", b, i, p);
			break;
		}
	}
	if (i == len) p = NULL;
	IFDBG r_cons_printf ("Found? for char (%c) @ %d: (%s)\n", b, len, p);
	return p;
}

static RAnal * get_anal (RCore *core) {
	return core? core->anal: NULL;
}

static void r_cmd_java_print_cmd_help (RCmdJavaCmd *cmd) {
	eprintf ("[*] %s %s\n[+] %s\n\n", cmd->name, cmd->args, cmd->desc);
}

static int r_cmd_java_handle_help (RCore * core, const char * input) {
	ut32 i = 0;
	const char **help_msg = (const char**)malloc (sizeof(char *) * END_CMDS*4);
	help_msg[0] = "Usage:";
	help_msg[1] = "java [cmd] [arg..] ";
	help_msg[2] = r_core_plugin_java.desc;
	for (i = 0; i <END_CMDS; i++) {
		RCmdJavaCmd *cmd = &JAVA_CMDS[i];
		help_msg[3+(i*3)+0] = cmd->name;
		help_msg[3+(i*3)+1] = cmd->args;
		help_msg[3+(i*3)+2] = cmd->desc;
	}
	help_msg[3+(i*3)] = NULL;
	r_core_cmd_help (core, help_msg);
	free (help_msg);
	return true;
}

static int r_cmd_java_handle_prototypes (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}

	switch (*(cmd)) {
	case 'm': return r_cmd_java_print_method_definitions (obj);
	case 'f': return r_cmd_java_print_field_definitions (obj);
	case 'i': return r_cmd_java_print_import_definitions (obj);
	case 'c': return r_cmd_java_print_class_definitions (obj);
	case 'a': return r_cmd_java_print_all_definitions (anal);
	case 'j': return r_cmd_java_print_json_definitions (obj);
	}
	return false;
}

static int r_cmd_java_handle_summary_info (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}

	r_cons_printf ("Summary for %s:\n", obj->file);
	r_cons_printf ("  Size 0x%"PFMT64x":\n", obj->size);
	r_cons_printf ("  Constants  size: 0x%"PFMT64x" count: %d:\n", obj->cp_size, obj->cp_count);
	r_cons_printf ("  Methods    size: 0x%"PFMT64x" count: %d:\n", obj->methods_size, obj->methods_count);
	r_cons_printf ("  Fields     size: 0x%"PFMT64x" count: %d:\n", obj->fields_size, obj->fields_count);
	r_cons_printf ("  Attributes size: 0x%"PFMT64x" count: %d:\n", obj->attrs_size, obj->attrs_count);
	r_cons_printf ("  Interfaces size: 0x%"PFMT64x" count: %d:\n", obj->interfaces_size, obj->interfaces_count);

	return true;
}

static int _(r_cmd_java_check_op_idx) (const ut8 *op_bytes, ut16 idx) {
	return R_BIN_JAVA_USHORT (op_bytes, 0) == idx;
}

/* Find stuff in the constant pool */
static RList * cpfind_double (RCore *core, RBinJavaObj *obj, const char *cmd) {
	double value = cmd && *cmd ? strtod (cmd, NULL) : 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0') ) return r_list_new();
	return r_bin_java_find_cp_const_by_val ( obj, (const ut8 *) &value, 8, R_BIN_JAVA_CP_DOUBLE);
}

static RList * cpfind_float (RCore *core, RBinJavaObj *obj, const char *cmd) {
	float value = cmd && *cmd ? atof (cmd) : 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0') ) return r_list_new();
	return r_bin_java_find_cp_const_by_val ( obj, (const ut8 *) &value, 4, R_BIN_JAVA_CP_FLOAT);
}

static RList * cpfind_long (RCore *core, RBinJavaObj *obj, const char *cmd) {
	ut64 value = r_cmd_java_get_input_num_value (core, cmd);
	if ( !r_cmd_java_is_valid_input_num_value (core, cmd) ) return r_list_new ();
	return r_bin_java_find_cp_const_by_val ( obj, (const ut8 *) &value, 8, R_BIN_JAVA_CP_LONG);
}

static RList * cpfind_int (RCore *core, RBinJavaObj *obj, const char *cmd) {
	ut32 value = (ut32) r_cmd_java_get_input_num_value (core, cmd);
	if ( !r_cmd_java_is_valid_input_num_value (core, cmd) ) return r_list_new ();
	return r_bin_java_find_cp_const_by_val ( obj, (const ut8 *) &value, 4, R_BIN_JAVA_CP_INTEGER);
}

static RList * cpfind_str (RCore *core, RBinJavaObj *obj, const char *cmd) {
	if (!cmd) return r_list_new();
	IFDBG r_cons_printf ("Looking for str: %s (%d)\n", cmd, strlen (cmd));
	return r_bin_java_find_cp_const_by_val ( obj, (const ut8 *) cmd, strlen (cmd), R_BIN_JAVA_CP_UTF8);
}

static int cpfind (RCore *core, const char *cmd) {
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (get_anal (core));
	const char *p = cmd;
	char f_type = 0;
	RList *find_list = NULL;
	RListIter *iter;
	ut32 *idx;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}
	IFDBG r_cons_printf ("Function call made: %s\n", p);
	if (p && *p) {
		p = r_cmd_java_consumetok (cmd, ' ', -1);
		f_type = *p;
		p+=2;
	}
	IFDBG r_cons_printf ("Function call made: %s\n", p);
	switch (f_type) {
	case 's': find_list = cpfind_str (core, obj, p); break;
	case 'i': find_list = cpfind_int (core, obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	case 'l': find_list = cpfind_long (core, obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	case 'f': find_list = cpfind_float (core, obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	case 'd': find_list = cpfind_double (core, obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	default:
		eprintf ("[-] r_cmd_java: invalid java type to search for.\n");
		return true;
	}

	r_list_foreach (find_list, iter, idx) {
		ut64 addr = r_bin_java_resolve_cp_idx_address (obj, (ut16) *idx);
		r_cons_printf ("Offset: 0x%"PFMT64x" idx: %d\n", addr, *idx);
	}
	r_list_free (find_list);
	return true;
}

static int r_cmd_java_reload_bin_from_buf (RCore *core, RBinJavaObj *obj, ut8* buffer, ut64 len) {
	if (!buffer || len < 10) return false;
	int res = r_bin_java_load_bin (obj, buffer, len);

	if (res == true) {
		//RBinPlugin *cp = NULL;
		RBinPlugin *tmp;
		RListIter *iter;
		r_list_foreach (core->bin->plugins, iter, tmp) {
			if (!strncmp ("java", tmp->name, 4)) {
				//cp = tmp;
				break;
			}
		}
		// XXX - this API is no longer valid.
		// need a function that will re-read bin bytes
		// and parse the file
		//if (cp) r_bin_update_items (core->bin, cp);
	}
	return res;
}

static int r_cmd_java_get_cp_bytes_and_write (RCore *core, RBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 * buf, const ut64 len) {
	int res = false;
	RBinJavaCPTypeObj *cp_obj = r_bin_java_get_item_from_bin_cp_list (obj, idx);
	ut64 c_file_sz = r_io_size (core->io);
	ut32 n_sz = 0, c_sz = obj ? r_bin_java_cp_get_size (obj, idx): -1;
	ut8 * bytes = NULL;

	if (c_sz == -1) return res;

	bytes = r_bin_java_cp_get_bytes (cp_obj->tag, &n_sz, buf, len);

	if (n_sz < c_sz) {
		res = r_core_shift_block (core, addr+c_sz, 0, (int)n_sz - (int)c_sz) &&
		r_io_resize(core->io, c_file_sz + (int) n_sz - (int) c_sz);
	} else if (n_sz > c_sz) {
		res = r_core_extend_at(core, addr,  (int)n_sz - (int)c_sz);
	} else {
		eprintf ("[X] r_cmd_java_get_cp_bytes_and_write: Failed to resize the file correctly aborting.\n");
		return res;
	}

	if (n_sz > 0 && bytes) {
		res = r_core_write_at(core, addr, (const ut8 *)bytes, n_sz) && r_core_seek (core, addr, 1);
	}

	if (res == false) {
		eprintf ("[X] r_cmd_java_get_cp_bytes_and_write: Failed to write the bytes to the file correctly aborting.\n");
		return res;
	}

	free (bytes);
	bytes = NULL;

	if (res == true) {
		ut64 n_file_sz = 0;
		ut8 * bin_buffer = NULL;
		res = r_io_desc_use (core->io, core->file->desc->fd);
		n_file_sz = r_io_size (core->io);
		bin_buffer = n_file_sz > 0 ? malloc (n_file_sz) : NULL;
		if (bin_buffer) {
			memset (bin_buffer, 0, n_file_sz);
			res = n_file_sz == r_io_read_at (core->io, obj->loadaddr,
				bin_buffer, n_file_sz) ? true : false;
			if (res == true) {
				res = r_cmd_java_reload_bin_from_buf (
					core, obj, bin_buffer, n_file_sz);
			} else eprintf ("[X] r_cmd_java_get_cp_bytes_and_write: Failed to read the file in aborted, bin reload.\n");
			free (bin_buffer);
		}
	}
	return res;
}

static int r_cmd_java_handle_replace_cp_value_float (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	float value = cmd && *cmd ? atof (cmd) : 0.0;
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *) &value, 4);
	return res;
}

static int r_cmd_java_handle_replace_cp_value_double (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	double value = cmd && *cmd ? strtod (cmd, NULL) : 0.0;
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *) &value, 8);
	return res;
}

static int r_cmd_java_handle_replace_cp_value_long (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut64 value = r_cmd_java_get_input_num_value (core, cmd);
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *) &value, 8);
	return res;
}

static int r_cmd_java_handle_replace_cp_value_int (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut32 value = (ut32) r_cmd_java_get_input_num_value (core, cmd);
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *) &value, 4);
	return res;
}

static int r_cmd_java_handle_replace_cp_value_str (RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	int res = false;
	ut32 len = cmd && *cmd ? strlen (cmd) : 0;
	if (len > 0 && cmd && *cmd == '"') {
		cmd++;
		len = cmd && *cmd ? strlen (cmd) : 0;
	}
	if (cmd && len > 0) {
		res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *) cmd, len);
	}
	return res;
}

static int r_cmd_java_handle_replace_cp_value (RCore *core, const char *cmd) {
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (get_anal (core));
	ut16 idx = -1;
	ut64 addr = 0;
	const char *p = cmd;
	char cp_type = 0;
	IFDBG r_cons_printf ("Function call made: %s\n", p);
	if (p && *p) {
		p = r_cmd_java_consumetok (cmd, ' ', -1);
		if (r_cmd_java_is_valid_input_num_value (core, p)) {
			idx = r_cmd_java_get_input_num_value (core, p);
			p = r_cmd_java_strtok (p, ' ', strlen(p));
		}
	}
	if (idx == (ut16) -1 ) {
		eprintf ("[-] r_cmd_java: Invalid index value.\n");
	} else if (!obj) {
		eprintf ("[-] r_cmd_java: The current binary is not a Java Bin Object.\n");
	} else if (!p || (p && !*p)) {
		r_cmd_java_print_cmd_help (JAVA_CMDS+REPLACE_CP_VALUE_IDX);
		return true;
	} else {
		cp_type = r_bin_java_resolve_cp_idx_tag(obj, idx);
		addr = r_bin_java_resolve_cp_idx_address (obj, idx);
		IFDBG r_cons_printf ("Function call made: %s\n", p);
		switch (cp_type) {
		case R_BIN_JAVA_CP_UTF8: return r_cmd_java_handle_replace_cp_value_str (
			core, obj, r_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case R_BIN_JAVA_CP_INTEGER: return r_cmd_java_handle_replace_cp_value_int (
			core, obj, r_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case R_BIN_JAVA_CP_LONG: return r_cmd_java_handle_replace_cp_value_long (
			core, obj, r_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case R_BIN_JAVA_CP_FLOAT: return r_cmd_java_handle_replace_cp_value_float (
			core, obj, r_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case R_BIN_JAVA_CP_DOUBLE: return r_cmd_java_handle_replace_cp_value_double (
			core, obj, r_cmd_java_consumetok (p, ' ', -1), idx, addr);
		default:
			eprintf ("[-] r_cmd_java: invalid java type to search for.\n");
			return false;
		}
		return true;
	}
	return false;
}

static char * r_cmd_replace_name_def (const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	const char * fmt = "L%s;";
	char *s_new_ref = s_new && replace_len > 0 ? malloc (3 + replace_len) : NULL;
	char *s_old_ref = s_old && match_len > 0 ? malloc (3 + match_len) : NULL;
	char *result = NULL;
	*res_len = 0;
	if (s_new_ref && s_old_ref) {
		snprintf (s_new_ref, replace_len+3, fmt, s_new);
		snprintf (s_old_ref, match_len+3, fmt, s_old);
		result = r_cmd_replace_name (s_new_ref, replace_len+2, s_old_ref, match_len+2, buffer, buf_len, res_len);
	}
	free (s_new_ref);
	free (s_old_ref);
	return result;
}

static int r_cmd_is_object_descriptor (const char *name, ut32 name_len) {
	int found_L = false, found_Semi = false;
	ut32 idx = 0, L_pos = 0, Semi_pos = 0;
	const char *p_name = name;

	for (idx = 0, L_pos = 0; idx < name_len; idx++,p_name++) {
		if (*p_name == 'L') {
			found_L = true;
			L_pos = idx;
			break;
		}
	}

	for (idx = 0, L_pos = 0; idx < name_len; idx++,p_name++) {
		if (*p_name == ';') {
			found_Semi = true;
			Semi_pos = idx;
			break;
		}
	}

	return true ? found_L == found_Semi && found_L == true && L_pos < Semi_pos : false;
}

static char * r_cmd_replace_name (const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	ut32 num_occurrences = 0, i = 0;
	char * result = NULL, *p_result = NULL;

	num_occurrences = r_cmd_get_num_classname_str_occ (buffer, s_old);
	*res_len = 0;
	if (num_occurrences > 0 && replace_len > 0 && s_old) {
		ut32 consumed = 0;
		const char * next = r_cmd_get_next_classname_str (buffer+consumed, s_old);
		IFDBG r_cons_printf ("Replacing \"%s\" with \"%s\" in: %s\n", s_old, s_new, buffer);
		result = malloc (num_occurrences*replace_len + buf_len);
		memset (result, 0, num_occurrences*replace_len + buf_len);
		p_result = result;
		while (next && consumed < buf_len) {
			// replace up to next
			IFDBG r_cons_printf ("next: \"%s\", len to: %d\n", next, next-buffer );
			for (; buffer + consumed < next  && consumed < buf_len; consumed++, p_result++) {
				*p_result = *(buffer + consumed);
				(*res_len)++;
			}

			for (i=0; i < replace_len; i++,  p_result++){
				*p_result = *(s_new + i);
				(*res_len)++;
			}
			consumed += match_len;
			next = r_cmd_get_next_classname_str (buffer+consumed, s_old);
		}
		IFDBG r_cons_printf ("Found last occurrence of: \"%s\", remaining: %s\n", s_old, buffer+consumed);
		IFDBG r_cons_printf ("result is: \"%s\"\n", result);
		for (; consumed < buf_len; consumed++, p_result++, (*res_len)++)
			*p_result = *(buffer+consumed);
		IFDBG r_cons_printf ("Old: %s\nNew: %s\n", buffer, result);
	}
	return result;
}


static int r_cmd_java_get_class_names_from_input (const char *input, char **class_name, ut32 *class_name_len, char **new_class_name, ut32 *new_class_name_len) {
	const char *p = input;

	ut32 cmd_sz = input && *input ? strlen (input) : 0;
	int res = false;

	if (!class_name || *class_name) return res;
	else if (!new_class_name || *new_class_name) return res;
	else if (!new_class_name_len || !class_name_len) return res;

	*new_class_name = NULL;
	*class_name_len = 0;

	if (p && *p && cmd_sz > 1) {
		const char *end;
		p = r_cmd_java_consumetok (p, ' ', cmd_sz);
		end = p && *p ? r_cmd_java_strtok (p, ' ', -1) : NULL;

		if (p && end && p != end) {
			*class_name_len = end - p + 1;
			*class_name = malloc (*class_name_len);
			snprintf (*class_name, *class_name_len, "%s", p );
			cmd_sz = *class_name_len - 1 < cmd_sz ? cmd_sz - *class_name_len : 0;
		}

		if (*class_name && cmd_sz > 0) {
			p = r_cmd_java_consumetok (end+1, ' ', cmd_sz);
			end = p && *p ? r_cmd_java_strtok (p, ' ', -1) : NULL;

			if (!end && p && *p) end = p + cmd_sz;

			if (p && end && p != end) {
				*new_class_name_len = end - p + 1;
				*new_class_name = malloc (*new_class_name_len);
				snprintf (*new_class_name, *new_class_name_len, "%s", p );
				res = true;
			}
		}
	}
	return res;
}

static int r_cmd_java_handle_replace_classname_value (RCore *core, const char *cmd) {
	RBinJavaObj *obj;
	char *class_name = NULL, *new_class_name = NULL;
	ut32 class_name_len = 0, new_class_name_len = 0;
	RAnal *anal = get_anal (core);
	const char *p = cmd;
	int res = false;
	ut16 idx = -1;

	if (!core || !anal || !cmd) {
		return false;
	}
	IFDBG r_cons_printf ("Function call made: %s\n", p);
	obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	if (!obj) {
		eprintf ("The current binary is not a Java Bin Object.\n");
		return true;
	}
	res = r_cmd_java_get_class_names_from_input (cmd, &class_name,
		&class_name_len, &new_class_name, &new_class_name_len);

	if (!class_name || !new_class_name) {
		r_cmd_java_print_cmd_help (JAVA_CMDS+REPLACE_CLASS_NAME_IDX);
		free (class_name);
		free (new_class_name);
		return true;
	}
	for (idx = 1; idx <=obj->cp_count; idx++) {
		RBinJavaCPTypeObj* cp_obj = r_bin_java_get_item_from_bin_cp_list (obj, idx);
		char *name = NULL;
		ut8 * buffer = NULL;
		ut32 buffer_sz = 0;
		ut16 len = 0;
		if (cp_obj && cp_obj->tag == R_BIN_JAVA_CP_UTF8 &&
			cp_obj->info.cp_utf8.length && cp_obj->info.cp_utf8.length >= class_name_len-1) {
			ut32 num_occurrences = 0;
			ut64 addr = cp_obj->file_offset + cp_obj->loadaddr;
			buffer = r_bin_java_cp_get_idx_bytes (obj, idx, &buffer_sz);

			if (!buffer) continue;
			len = R_BIN_JAVA_USHORT ( buffer, 1);
			name = malloc (len+3);
			memcpy (name, buffer+3, len);
			name[len] = 0;

			num_occurrences = r_cmd_get_num_classname_str_occ (name, class_name);

			if (num_occurrences > 0) {
				// perform inplace replacement
				ut32 res_len = 0;
				char * result = NULL;

				if (r_cmd_is_object_descriptor (name, len) == true) {
					result = r_cmd_replace_name_def (new_class_name,
						new_class_name_len-1, class_name,
						class_name_len-1, name, len, &res_len);
				} else {
					result = r_cmd_replace_name (new_class_name,
						new_class_name_len-1, class_name,
						class_name_len-1, name, len, &res_len);
				}
				if (result) {
					res = r_cmd_java_get_cp_bytes_and_write (
						core, obj, idx, addr,
						(const ut8*)result, res_len);
					if  (res == false) {
						eprintf ("ERROR: r_cmd_java: Failed to write bytes or reload the binary.\n");
					}
				}
				free (result);
			}
			free (buffer);
			free (name);
		}

	}
	free (class_name);
	free (new_class_name);
	return true;
}

static int r_cmd_java_handle_reload_bin (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	const char *p = cmd;
	ut64 addr = 0LL; //cur_offset = core->offset, addr = 0;
	ut64 buf_size = 0;
	ut8 * buf = NULL;
	int res = false;

	if (*cmd == ' ') {
		p = r_cmd_java_consumetok (p, ' ', -1);
	}
	if (!*cmd) {
		r_cmd_java_print_cmd_help (JAVA_CMDS+RELOAD_BIN_IDX);
		return true;
	}

	addr = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;
	if (*cmd == ' ') p = r_cmd_java_consumetok (p, ' ', -1);
	buf_size = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	// XXX this may cause problems cause the file we are looking at may not be the bin we want.
	// lets pretend it is for now
	if (buf_size == 0) {
		res = r_io_desc_use (core->io, core->file->desc->fd);
		buf_size = r_io_size (core->io);
		buf = malloc (buf_size);
		memset (buf, 0, buf_size);
		r_io_read_at (core->io, addr, buf, buf_size);
	}
	if (buf && obj) {
		res = r_cmd_java_reload_bin_from_buf (core, obj, buf, buf_size);
	}
	free (buf);
	return res;
}

static int r_cmd_java_handle_find_cp_const (RCore *core, const char *cmd) {
	const char *p = (cmd && *cmd == ' ')?  r_cmd_java_consumetok (cmd, ' ', -1): NULL;
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (get_anal (core));
	RAnalFunction *fcn = NULL;
	RAnalBlock *bb = NULL;
	RListIter *bb_iter, *fn_iter, *iter;
	RCmdJavaCPResult *cp_res = NULL;
	ut16 idx = -1;
	RList *find_list;

	if (p && *p == 'a') idx = -1;
	else idx = r_cmd_java_get_input_num_value (core, p);

	IFDBG r_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}
	if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FIND_CP_CONST_IDX);
		return true;
	}
	if (idx == 0) {
		eprintf ("[-] r_cmd_java: invalid CP Obj Index Supplied.\n");
		return true;
	}
	find_list = r_list_new ();
	find_list->free = free;
	// XXX - this will break once RAnal moves to sdb
	r_list_foreach (core->anal->fcns, fn_iter, fcn) {
		r_list_foreach (fcn->bbs, bb_iter, bb) {
			char op = bb->op_bytes[0];
			cp_res = NULL;
			switch (op) {
				case 0x12:
					cp_res = (idx == (ut16) -1) || (bb->op_bytes[1] == idx) ?
								R_NEW0(RCmdJavaCPResult) : NULL;
					if (cp_res) cp_res->idx = bb->op_bytes[1];
					break;
				case 0x13:
				case 0x14:
					cp_res = (idx == (ut16) -1) || (R_BIN_JAVA_USHORT (bb->op_bytes, 1) == idx) ?
								R_NEW0(RCmdJavaCPResult) : NULL;
					if (cp_res) cp_res->idx = R_BIN_JAVA_USHORT (bb->op_bytes, 1);
					break;
			}

			if (cp_res) {
				cp_res->addr = bb->addr;
				cp_res->obj = r_bin_java_get_item_from_cp (obj, cp_res->idx);
				r_list_append (find_list, cp_res);
			}
		}
	}
	if (idx == (ut16) -1) {
		r_list_foreach (find_list, iter, cp_res) {
			const char *t = ((RBinJavaCPTypeMetas *) cp_res->obj->metas->type_info)->name;
			r_cons_printf ("@0x%"PFMT64x" idx = %d Type = %s\n", cp_res->addr, cp_res->idx, t);
		}

	} else {
		r_list_foreach (find_list, iter, cp_res) {
			r_cons_printf ("@0x%"PFMT64x"\n", cp_res->addr);
		}
	}
	r_list_free (find_list);
	return true;
}

static int r_cmd_java_handle_field_info (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FIELD_INFO_IDX);
		return true;
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = r_cmd_java_get_input_num_value (core, cmd+1);
	}

	switch (*(cmd)) {
		case 'c': return r_cmd_java_print_field_num_name (obj);
		case 's': return r_cmd_java_print_field_summary (obj, idx);
		case 'n': return r_cmd_java_print_field_name (obj, idx);
	}
	IFDBG r_cons_printf ("Command is (%s)\n", cmd);
	eprintf ("[-] r_cmd_java: invalid command syntax.\n");
	r_cmd_java_print_cmd_help (JAVA_CMDS+FIELD_INFO_IDX);
	return false;
}

static int r_cmd_java_handle_method_info (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Command is (%s)\n", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+METHOD_INFO_IDX);
		return false;
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = r_cmd_java_get_input_num_value (core, cmd+1);
	}

	switch (*(cmd)) {
		case 'c': return r_cmd_java_print_method_num_name (obj);
		case 's': return r_cmd_java_print_method_summary (obj, idx);
		case 'n': return r_cmd_java_print_method_name (obj, idx);
	}

	IFDBG r_cons_printf ("Command is (%s)\n", cmd);
	eprintf ("[-] r_cmd_java: invalid command syntax.\n");
	r_cmd_java_print_cmd_help (JAVA_CMDS+METHOD_INFO_IDX);
	return false;
}

static int r_cmd_java_handle_calc_class_sz (RCore *core, const char *cmd) {
	int res = false;
	ut64 sz = UT64_MAX;
	ut64 addr = UT64_MAX;
	ut64 res_size = UT64_MAX,
		 cur_fsz = r_io_desc_size (r_core_file_cur (core)->desc);
	ut8 *buf = NULL;
	ut32 init_size = (1 << 16);
	const char *p = cmd ? r_cmd_java_consumetok (cmd, ' ', -1): NULL;
	addr = p && *p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : UT64_MAX;

	// TODO add a size parameter to the command to skip the guessing part.

	if (addr != UT64_MAX && sz == UT64_MAX) {
		IFDBG r_cons_printf ("Function call made: %s\n", cmd);
		IFDBG r_cons_printf ("Attempting to calculate class file size @ : 0x%"PFMT64x".\n", addr);
		sz = cur_fsz < init_size ? cur_fsz : init_size;
		while (sz <= cur_fsz) {
			buf = realloc (buf, sz);
			ut64 r_sz = r_core_read_at (core, addr, buf, sz);
			// check the return read on the read
			if (r_sz == UT64_MAX || r_sz == 0) break;
			res_size = r_bin_java_calc_class_size (buf, sz);
			// if the data buffer contains a class starting
			// at address, then the res_size will be the size
			// if the r_sz is less than the sz, then we are near
			// the end of the core buffer, and there is no need
			// to continue trying to find the class size.
			if (res_size != UT64_MAX ||
				r_sz < sz) {
				res = r_sz < sz ? false : true;
				free (buf);
				break;
			}else {
				sz += (1 << 16);
			}
		}
		if (res) r_cons_printf ("%"PFMT64d, res_size);
		else r_cons_printf ("-1\n");

		//snprintf (cmd_buf, 50, fmt, num_acc_flag, addr);
		//res = r_core_cmd0(core, y);
	} else {
		r_cmd_java_print_cmd_help (JAVA_CMDS+CALC_SZ_IDX);
	}
	return true;
}

static int r_cmd_java_handle_isvalid (RCore *core, const char *cmd) {
	int res = false;
	ut64 res_size = UT64_MAX;
	ut8 *buf = NULL;
	ut32 cur_fsz =  r_io_desc_size (r_core_file_cur (core)->desc);
	ut64 sz = UT64_MAX;
	const char *p = cmd ? r_cmd_java_consumetok (cmd, ' ', -1): NULL;
	ut64 addr = UT64_MAX;
	addr = p && *p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : UT64_MAX;

	// TODO add a size parameter to the command to skip the guessing part.

	if (addr != UT64_MAX && sz == UT64_MAX) {
		IFDBG r_cons_printf ("Function call made: %s\n", cmd);
		IFDBG r_cons_printf ("Attempting to calculate class file size @ : 0x%"PFMT64x".\n", addr);

		while (sz <= cur_fsz) {
			buf = realloc (buf, sz);
			ut64 r_sz = r_core_read_at (core, addr, buf, sz);
			// check the return read on the read
			if (r_sz == UT64_MAX || r_sz == 0) break;
			res_size = r_bin_java_calc_class_size (buf, sz);
			// if the data buffer contains a class starting
			// at address, then the res_size will be the size
			// if the r_sz is less than the sz, then we are near
			// the end of the core buffer, and there is no need
			// to continue trying to find the class size.
			if (res_size != UT64_MAX ||
				r_sz < sz) {
				res = r_sz < sz ? false : true;
				free (buf);
				break;
			}else {
				sz <<= 1;
			}
		}
		if (res) r_cons_printf ("True\n");
		else r_cons_printf ("False\n");
	} else
		r_cmd_java_print_cmd_help (JAVA_CMDS+ISVALID_IDX);
	return true;
}

static int r_cmd_java_handle_resolve_cp (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	char c_type = cmd && *cmd ? *cmd : 0;
	RBinJavaObj *obj = r_cmd_java_get_bin_obj (anal);
	ut16 idx = r_cmd_java_get_input_num_value (core, cmd+2);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);
	IFDBG r_cons_printf ("Ctype: %d (%c) RBinJavaObj points to: %p and the idx is (%s): %d\n", c_type, c_type, obj, cmd+2, idx);
	int res = false;
	if (idx > 0 && obj) {
		switch (c_type) {
			case 't': return r_cmd_java_resolve_cp_type (obj, idx);
			case 'c': return r_cmd_java_resolve_cp_idx (obj, idx);
			case 'e': return r_cmd_java_resolve_cp_idx_b64 (obj, idx);
			case 'a': return r_cmd_java_resolve_cp_address (obj, idx);
			case 's': return r_cmd_java_resolve_cp_summary (obj, idx);
			case 'k': return r_cmd_java_resolve_cp_to_key (obj, idx);
		}
	} else if (obj && c_type == 'g') {
		for (idx = 1; idx <=obj->cp_count; idx++) {
			ut64 addr = r_bin_java_resolve_cp_idx_address (obj, idx) ;
			char * str = r_bin_java_resolve_cp_idx_type (obj, idx);
			r_cons_printf ("CP_OBJ Type %d =  %s @ 0x%"PFMT64x"\n", idx, str, addr);
			free (str);
		}
		res = true;
	} else if (obj && c_type == 'd') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			r_cmd_java_resolve_cp_summary (obj, idx);
		}
		res = true;
	} else {
		if (!obj) {
			eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		} else {
			eprintf ("[-] r_cmd_java: invalid cp index given, must idx > 1.\n");
			r_cmd_java_print_cmd_help (JAVA_CMDS+RESOLVE_CP_IDX);
		}
		res = true;
	}
	return res;
}

static int r_cmd_java_get_all_access_flags_value (const char *cmd) {
	RList *the_list = NULL;
	RListIter *iter = NULL;
	char *str = NULL;

	switch (*(cmd)) {
		case 'f': the_list = retrieve_all_field_access_string_and_value (); break;
		case 'm': the_list = retrieve_all_method_access_string_and_value (); break;
		case 'c': the_list = retrieve_all_class_access_string_and_value (); break;
	}
	if (!the_list) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+CALC_FLAGS_IDX);
		return false;
	}
	switch (*(cmd)) {
		case 'f': r_cons_printf ("[=] Fields Access Flags List\n"); break;
		case 'm': r_cons_printf ("[=] Methods Access Flags List\n"); break;
		case 'c': r_cons_printf ("[=] Class Access Flags List\n");; break;
	}

	r_list_foreach (the_list, iter, str) {
		r_cons_println (str);
	}
	r_list_free (the_list);
	return true;
}

static int r_cmd_java_handle_calc_flags (RCore *core, const char *cmd) {
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);
	int res = false;

	switch (*(cmd)) {
		case 'f': return r_cmd_java_print_field_access_flags_value (cmd+2);
		case 'm': return r_cmd_java_print_method_access_flags_value (cmd+2);
		case 'c': return r_cmd_java_print_class_access_flags_value (cmd+2);
	}

	if ( *(cmd) == 'l') {
		const char *lcmd = *cmd+1 == ' '? cmd+2 : cmd+1;
		IFDBG eprintf ("Seeing %s and accepting %s\n", cmd, lcmd);
		switch (*(lcmd)) {
			case 'f':
			case 'm':
			case 'c': res = r_cmd_java_get_all_access_flags_value (lcmd); break;
		}
		// Just print them all out
		if (res == false) {
			r_cmd_java_get_all_access_flags_value ("c");
			r_cmd_java_get_all_access_flags_value ("m");
			res = r_cmd_java_get_all_access_flags_value ("f");
		}
	}
	if (res == false) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+CALC_FLAGS_IDX);
		res = true;
	}
	return res;
}

static int r_cmd_java_handle_flags_str (RCore *core, const char *cmd) {

	int res = false;
	ut32 flag_value = -1;
	const char f_type = cmd ? *cmd : 0;
	const char *p = cmd ? cmd + 2: NULL;
	char * flags_str = NULL;

	IFDBG r_cons_printf ("r_cmd_java_handle_flags_str: ftype = %c, idx = %s\n", f_type, p);
	if (p)
		flag_value = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	if (p && f_type) {
		switch (f_type) {
			case 'm': flags_str = retrieve_method_access_string((ut16) flag_value); break;
			case 'f': flags_str = retrieve_field_access_string((ut16) flag_value); break;
			case 'c': flags_str = retrieve_class_method_access_string((ut16) flag_value); break;
			default: flags_str = NULL;
		}
	}

	if (flags_str) {
		switch (f_type) {
			case 'm': r_cons_printf ("Method Access Flags String: "); break;
			case 'f': r_cons_printf ("Field Access Flags String: "); break;
			case 'c': r_cons_printf ("Class Access Flags String: "); break;
		}
		r_cons_println (flags_str);
		free (flags_str);
		res = true;
	}
	if (res == false) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FLAGS_STR_IDX);
		res = true;
	}
	return res;
}

static int r_cmd_java_handle_flags_str_at (RCore *core, const char *cmd) {

	int res = false;
	ut64 flag_value_addr = -1;
	ut32 flag_value = -1;
	const char f_type = cmd ? *r_cmd_java_consumetok (cmd, ' ', -1) : 0;
	const char *p = cmd ? cmd + 2: NULL;
	char * flags_str = NULL;

	IFDBG r_cons_printf ("r_cmd_java_handle_flags_str_at: ftype = 0x%02x, idx = %s\n", f_type, p);
	if (p) {
		flag_value = 0;
		ut64 cur_offset = core->offset;
		flag_value_addr = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;
		r_core_read_at (core, flag_value_addr, (ut8 *) &flag_value, 2);
		IFDBG r_cons_printf ("r_cmd_java_handle_flags_str_at: read = 0x%04x\n", flag_value);
		if (cur_offset != core->offset) r_core_seek (core, cur_offset-2, 1);
		flag_value = R_BIN_JAVA_USHORT (((ut8 *) &flag_value), 0);
	}

	if (p && f_type) {
		switch (f_type) {
			case 'm': flags_str = retrieve_method_access_string((ut16) flag_value); break;
			case 'f': flags_str = retrieve_field_access_string((ut16) flag_value); break;
			case 'c': flags_str = retrieve_class_method_access_string((ut16) flag_value); break;
			default: flags_str = NULL;
		}
	}

	if (flags_str) {
		switch (f_type) {
			case 'm': r_cons_printf ("Method Access Flags String: "); break;
			case 'f': r_cons_printf ("Field Access Flags String: "); break;
			case 'c': r_cons_printf ("Class Access Flags String: "); break;
		}
		r_cons_println (flags_str);
		free (flags_str);
		res = true;
	}
	if (res == false) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FLAGS_STR_IDX);
		res = true;
	}
	return res;
}


static char r_cmd_java_is_valid_java_mcf (char b) {
	char c = 0;
	switch (b) {
		case 'c':
		case 'f':
		case 'm': c = b;
	}
	return c;
}

static int r_cmd_java_handle_set_flags (RCore * core, const char * input) {
	//#define SET_ACC_FLAGS_ARGS "< c | m | f> <addr> <d | <s <flag value separated by space> >"
	const char *p = r_cmd_java_consumetok (input, ' ', -1);

	ut64 addr = p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;
	ut32 flag_value = -1;
	char f_type = '?';
	int res = false;

	p = r_cmd_java_strtok (p+1, ' ', -1);
	if (!p || !*p) {
		r_cmd_java_print_cmd_help (JAVA_CMDS+SET_ACC_FLAGS_IDX);
		return true;
	}
	f_type = p && *p ? r_cmd_java_is_valid_java_mcf (*(++p)) : 0;

	flag_value = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	if (flag_value == 16 && f_type == 'f') {
		flag_value = -1;
	}
	IFDBG r_cons_printf ("Converting %s to flags\n",p);

	if (p) p+=2;
	if (flag_value == -1)
		flag_value = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	if (!input) {
		eprintf ("[-] r_cmd_java: no address provided .\n");
		res = true;
	} else if (addr == -1) {
		eprintf ("[-] r_cmd_java: no address provided .\n");
		res = true;
	} else if (!f_type && flag_value == -1) {
		eprintf ("[-] r_cmd_java: no flag type provided .\n");
		res = true;
	}

	if (res) {
		r_cmd_java_print_cmd_help (JAVA_CMDS+SET_ACC_FLAGS_IDX);
		return res;
	}

	IFDBG r_cons_printf ("Writing to %c to 0x%"PFMT64x", %s.\n", f_type, addr, p);

	//  handling string based access flags (otherwise skip ahead)
	IFDBG r_cons_printf ("Converting %s to flags\n",p);
	if (f_type && flag_value != -1) {
		switch (f_type) {
			case 'f': flag_value = r_bin_java_calculate_field_access_value (p); break;
			case 'm': flag_value = r_bin_java_calculate_method_access_value (p); break;
			case 'c': flag_value = r_bin_java_calculate_class_access_value (p); break;
			default: flag_value = -1;
		}
		if (flag_value == -1) {
			eprintf ("[-] r_cmd_java: in valid flag type provided .\n");
			res = true;
		}
	}
	IFDBG r_cons_printf ("Current args: (flag_value: 0x%04x addr: 0x%"PFMT64x")\n.", flag_value, addr, res);
	if (flag_value != -1) {
		res = r_cmd_java_set_acc_flags (core, addr, ((ut16) flag_value) & 0xffff);
		IFDBG r_cons_printf ("Writing 0x%04x to 0x%"PFMT64x": %d.", flag_value, addr, res);
	} else {
		eprintf ("[-] r_cmd_java: invalid flag value or type provided .\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+SET_ACC_FLAGS_IDX);
		res = true;
	}
	return res;
}

static int r_cmd_java_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	int res = false;
	ut32 i = 0;
	if (strncmp (input, "java", 4)) {
		return false;
	}
	if (input[4] != ' ') {
		return r_cmd_java_handle_help (core, input);
	}
	for (; i < END_CMDS; i++) {
		//IFDBG r_cons_printf ("Checking cmd: %s %d %s\n", JAVA_CMDS[i].name, JAVA_CMDS[i].name_len, p);
		IFDBG r_cons_printf ("Checking cmd: %s %d\n", JAVA_CMDS[i].name, strncmp (input+5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len));
		if (!strncmp (input + 5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len)) {
			const char *cmd = input + 5 + JAVA_CMDS[i].name_len;
			if (*cmd && *cmd == ' ') cmd++;
			//IFDBG r_cons_printf ("Executing cmd: %s (%s)\n", JAVA_CMDS[i].name, cmd+5+JAVA_CMDS[i].name_len );
			res =  JAVA_CMDS[i].handler (core, cmd);
			break;
		}
	}
	if (!res) {
		res = r_cmd_java_handle_help (core, input);
	}
	return true;
}


static int r_cmd_java_print_method_definitions ( RBinJavaObj *obj ) {
	RList * the_list = r_bin_java_get_method_definitions (obj),
			* off_list = r_bin_java_get_method_offsets (obj);
	char * str = NULL;
	ut32 idx = 0, end = r_list_length (the_list);

	while (idx < end) {
		ut64 *addr = r_list_get_n (off_list, idx);
		str = r_list_get_n (the_list, idx);
		r_cons_printf("%s; // @0x%04"PFMT64x"\n", str, *addr);
		idx++;
	}

	r_list_free(the_list);
	r_list_free(off_list);
	return true;
}

static int r_cmd_java_print_field_definitions ( RBinJavaObj *obj ) {
	RList * the_list = r_bin_java_get_field_definitions (obj),
			* off_list = r_bin_java_get_field_offsets (obj);
	char * str = NULL;
	ut32 idx = 0, end = r_list_length (the_list);

	while (idx < end) {
		ut64 *addr = r_list_get_n (off_list, idx);
		str = r_list_get_n (the_list, idx);
		r_cons_printf("%s; // @0x%04"PFMT64x"\n", str, *addr);
		idx++;
	}

	r_list_free(the_list);
	r_list_free(off_list);
	return true;
}

static int r_cmd_java_print_import_definitions ( RBinJavaObj *obj ) {
	RList * the_list = r_bin_java_get_import_definitions (obj);
	char * str = NULL;
	RListIter *iter;
	r_list_foreach (the_list, iter, str) {
		r_cons_printf("import %s;\n", str);
	}
	r_list_free(the_list);
	return true;
}

static int r_cmd_java_print_all_definitions( RAnal *anal ) {
	RList * obj_list  = r_cmd_java_get_bin_obj_list (anal);
	RListIter *iter;
	RBinJavaObj *obj;

	if (!obj_list) return 1;
	r_list_foreach (obj_list, iter, obj) {
		r_cmd_java_print_class_definitions (obj);
	}
	return true;
}

static int r_cmd_java_print_json_definitions( RBinJavaObj *obj ) {
	DsoJsonObj *json_obj = r_bin_java_get_bin_obj_json (obj);
	char *str = dso_json_obj_to_str (json_obj);
	dso_json_obj_del (json_obj); // XXX memleak
	r_cons_println (str);
	return true;
}

static int r_cmd_java_print_class_definitions( RBinJavaObj *obj ) {
	RList * the_fields = r_bin_java_get_field_definitions (obj),
			* the_methods = r_bin_java_get_method_definitions (obj),
			* the_imports = r_bin_java_get_import_definitions (obj),
			* the_moffsets = r_bin_java_get_method_offsets (obj),
			* the_foffsets = r_bin_java_get_field_offsets (obj);

	char * class_name = r_bin_java_get_this_class_name(obj);
	char * str = NULL;

	r_cmd_java_print_import_definitions (obj);
	r_cons_printf ("\nclass %s { // @0x%04"PFMT64x"\n", class_name, obj->loadaddr);

	if (the_fields && the_foffsets && r_list_length (the_fields) > 0) {
		r_cons_printf ("\n  // Fields defined in the class\n");
		ut32 idx = 0, end = r_list_length (the_fields);

		while (idx < end) {
			ut64 *addr = r_list_get_n (the_foffsets, idx);
			str = r_list_get_n (the_fields, idx);
			r_cons_printf("  %s; // @0x%04"PFMT64x"\n", str, *addr);
			idx++;
		}
	}

	if (the_methods && the_moffsets && r_list_length (the_methods) > 0) {
		r_cons_printf ("\n  // Methods defined in the class\n");
		ut32 idx = 0, end = r_list_length (the_methods);

		while (idx < end) {
			ut64 *addr = r_list_get_n (the_moffsets, idx);
			str = r_list_get_n (the_methods, idx);
			r_cons_printf ("  %s; // @0x%04"PFMT64x"\n", str, *addr);
			idx++;
		}
	}
	r_cons_printf ("}\n");

	r_list_free (the_imports);
	r_list_free (the_fields);
	r_list_free (the_methods);
	r_list_free (the_foffsets);
	r_list_free (the_moffsets);

	free(class_name);
	return true;
}

static RList * r_cmd_java_get_bin_obj_list(RAnal *anal) {
	RBinJavaObj *bin_obj = (RBinJavaObj * ) r_cmd_java_get_bin_obj(anal);
	// See libr/bin/p/bin_java.c to see what is happening here.  The original intention
	// was to use a shared global db variable from shlr/java/class.c, but the
	// BIN_OBJS_ADDRS variable kept getting corrupted on Mac, so I (deeso) switched the
	// way the access to the db was taking place by using the bin_obj as a proxy back
	// to the BIN_OBJS_ADDRS which is instantiated in libr/bin/p/bin_java.c
	// not the easiest way to make sausage, but its getting made.
	return  r_bin_java_get_bin_obj_list_thru_obj (bin_obj);
}

static RBinJavaObj * r_cmd_java_get_bin_obj(RAnal *anal) {
	RBin *b;
	int is_java;
	RBinPlugin *plugin;
	if (!anal || !anal->binb.bin)
		return NULL;
	b = anal->binb.bin;
	if (!b->cur || !b->cur->o)
		return NULL;
	plugin = b->cur->o->plugin;
	is_java = (plugin  && strcmp (plugin->name, "java") == 0) ? 1 : 0;
	return is_java ? b->cur->o->bin_obj : NULL;
}

static int r_cmd_java_resolve_cp_idx (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_without_space (obj, idx);
		r_cons_println (str);
		free (str);
	}
	return true;
}

static int r_cmd_java_resolve_cp_type (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_cp_idx_type (obj, idx);
		r_cons_println (str);
		free (str);
	}
	return true;
}

static int r_cmd_java_resolve_cp_idx_b64 (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_b64_encode (obj, idx) ;
		r_cons_println (str);
		free (str);
	}
	return true;
}

static int r_cmd_java_resolve_cp_address (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		ut64 addr = r_bin_java_resolve_cp_idx_address (obj, idx) ;
		if (addr == -1)
			r_cons_printf ("Unable to resolve CP Object @ index: 0x%04x\n", idx);
		else
			r_cons_printf ("0x%"PFMT64x"\n", addr);
	}
	return true;
}

static int r_cmd_java_resolve_cp_to_key (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_cp_idx_to_string (obj, idx) ;
		r_cons_println (str);
		free (str);
	}
	return true;
}
static int r_cmd_java_resolve_cp_summary (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		r_bin_java_resolve_cp_idx_print_summary (obj, idx) ;
	}
	return true;
}

static int r_cmd_java_is_valid_input_num_value(RCore *core, const char *input_value){
	ut64 value = input_value ? r_num_math (core->num, input_value) : 0;
	return !(value == 0 && input_value && *input_value == '0');
}

static ut64 r_cmd_java_get_input_num_value(RCore *core, const char *input_value){
	ut64 value = input_value ? r_num_math (core->num, input_value) : 0;
	return value;
}

static int r_cmd_java_print_class_access_flags_value( const char * flags ){
	ut16 result = r_bin_java_calculate_class_access_value (flags);
	r_cons_printf ("Access Value for %s = 0x%04x\n", flags, result);
	return true;
}
static int r_cmd_java_print_field_access_flags_value( const char * flags ){
	ut16 result = r_bin_java_calculate_field_access_value (flags);
	r_cons_printf ("Access Value for %s = 0x%04x\n", flags,  result);
	return true;
}
static int r_cmd_java_print_method_access_flags_value( const char * flags ){
	ut16 result = r_bin_java_calculate_method_access_value (flags);
	r_cons_printf ("Access Value for %s = 0x%04x\n", flags,  result);
	return true;
}

static int r_cmd_java_set_acc_flags (RCore *core, ut64 addr, ut16 num_acc_flag) {
	char cmd_buf [50];
	//const char * fmt = "wx %04x @ 0x%"PFMT64x;

	int res = false;
	//ut64 cur_offset = core->offset;
	num_acc_flag = R_BIN_JAVA_USHORT (((ut8*) &num_acc_flag), 0);
	res = r_core_write_at(core, addr, (const ut8 *)&num_acc_flag, 2);
	//snprintf (cmd_buf, 50, fmt, num_acc_flag, addr);
	//res = r_core_cmd0(core, cmd_buf);
	res = true;
	IFDBG r_cons_printf ("Executed cmd: %s == %d\n", cmd_buf, res);
	/*if (cur_offset != core->offset) {
		IFDBG eprintf ("Ooops, write advanced the cursor, moving it back.");
		r_core_seek (core, cur_offset-2, 1);
	}*/
	return res;
}
static int r_cmd_java_print_field_num_name (RBinJavaObj *obj) {
	RList * the_list = r_bin_java_get_field_num_name (obj);
	char * str;
	RListIter *iter = NULL;
	r_list_foreach (the_list, iter, str) {
		r_cons_println (str);
	}
	r_list_free (the_list);
	return true;
}

static int r_cmd_java_print_method_num_name (RBinJavaObj *obj) {
	RList * the_list = r_bin_java_get_method_num_name (obj);
	char * str;
	RListIter *iter = NULL;
	r_list_foreach (the_list, iter, str) {
		r_cons_println (str);
	}
	r_list_free (the_list);
	return true;
}

static int r_cmd_java_print_field_summary (RBinJavaObj *obj, ut16 idx) {
	int res = r_bin_java_print_field_idx_summary (obj, idx);
	if (res == false) {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
		res = true;
	}
	return res;
}

static int UNUSED_FUNCTION(r_cmd_java_print_field_count) (RBinJavaObj *obj) {
	ut32 res = r_bin_java_get_field_count (obj);
	r_cons_printf ("%d\n", res);
	r_cons_flush();
	return true;
}

static int r_cmd_java_print_field_name (RBinJavaObj *obj, ut16 idx) {
	char * res = r_bin_java_get_field_name (obj, idx);
	if (res) {
		r_cons_println (res);
	} else {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
	}
	free (res);
	return true;
}

static int r_cmd_java_print_method_summary (RBinJavaObj *obj, ut16 idx) {
	int res = r_bin_java_print_method_idx_summary (obj, idx);
	if (res == false) {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
		res = true;
	}
	return res;
}

static int _(r_cmd_java_print_method_count)(RBinJavaObj *obj) {
	ut32 res = r_bin_java_get_method_count (obj);
	r_cons_printf ("%d\n", res);
	r_cons_flush();
	return true;
}

static int r_cmd_java_print_method_name (RBinJavaObj *obj, ut16 idx) {
	char * res = r_bin_java_get_method_name (obj, idx);
	if (res) {
		r_cons_println (res);
	} else {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
	}
	free (res);
	return true;
}
static char * r_cmd_java_get_descriptor (RCore *core, RBinJavaObj *bin, ut16 idx) {
	char *class_name = NULL, *fullname = NULL, *name = NULL, *descriptor = NULL;
	RBinJavaCPTypeObj * obj = r_bin_java_get_item_from_bin_cp_list (bin, idx);
	char * prototype = NULL;

	if (idx == 0) {
		prototype = strdup ("NULL");
		return prototype;
	}

	if (obj->tag == R_BIN_JAVA_CP_INTERFACEMETHOD_REF ||
		obj->tag == R_BIN_JAVA_CP_METHODREF ||
		obj->tag == R_BIN_JAVA_CP_FIELDREF) {
		class_name = r_bin_java_get_name_from_bin_cp_list (bin, obj->info.cp_method.class_idx);
		name = r_bin_java_get_item_name_from_bin_cp_list (bin, obj);
		descriptor = r_bin_java_get_item_desc_from_bin_cp_list (bin, obj);
	}

	if (class_name && name) {
		ut32 fn_len = 0;
		fn_len += strlen (class_name);
		fn_len += strlen (name);
		fn_len += 2; // dot + null
		fullname = malloc (fn_len);
		snprintf (fullname, fn_len, "%s.%s", class_name, name);
	}
	if (fullname) prototype = r_bin_java_unmangle_without_flags (fullname, descriptor);
	free (class_name);
	free (name);
	free (descriptor);
	free (fullname);
	return prototype;
}

static int r_cmd_java_handle_list_code_references (RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = anal ? (RBinJavaObj *) r_cmd_java_get_bin_obj (anal) : NULL;
	RAnalBlock *bb = NULL;
	RAnalFunction *fcn = NULL;
	RListIter *bb_iter = NULL, *fcn_iter = NULL;
	ut64 func_addr = -1;
	const char *fmt, *p = r_cmd_java_consumetok (input, ' ', -1);
	func_addr = p && *p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;


	if (!core || !anal || !bin) {
		eprintf ("Unable to access the current bin.\n");
		return false;
	}
	if (r_list_length (anal->fcns) == 0) {
		eprintf ("Unable to access the current analysis, perform 'af' for function analysis.\n");
		return true;
	}

	fmt = "addr:0x%"PFMT64x" method_name:\"%s\", op:\"%s\" type:\"%s\" info:\"%s\"\n";

	r_list_foreach (anal->fcns, fcn_iter, fcn) {
		ut8 do_this_one = func_addr == -1 || r_anal_fcn_is_in_offset (fcn, func_addr);
		if (!do_this_one) continue;
		r_list_foreach (fcn->bbs, bb_iter, bb) {
			char *operation = NULL, *type = NULL;
			ut64 addr = -1;
			ut16 cp_ref_idx = -1;
			char *full_bird = NULL;
			// if bb_type is a call
			if (bb->op_bytes[0] == 0x01) continue;
			if (bb->op_bytes[0] == 0x12) {
				// loading a constant
				addr = bb->addr;
				full_bird = r_bin_java_resolve_without_space(bin, bb->op_bytes[1]);
				operation = strdup ("read constant");
				type = r_bin_java_resolve_cp_idx_type (bin, bb->op_bytes[1]);
				r_cons_printf (fmt, addr, fcn->name, operation, type, full_bird);
				free (full_bird);
				free (type);
				free (operation);
				full_bird = type = operation = NULL;
			} else if ( (bb->type2 &  R_ANAL_EX_CODEOP_CALL) == R_ANAL_EX_CODEOP_CALL) {
				ut8 op_byte = bb->op_bytes[0];
				// look at the bytes determine if it belongs to this class
				switch (op_byte) {
				case 0xb6: // invokevirtual
					operation = strdup ("call virtual");
					type = strdup ("FUNCTION");
					addr = bb->addr;
					break;
				case 0xb7: // invokespecial
					operation = strdup ("call special");
					type = strdup ("FUNCTION");
					addr = bb->addr;
					break;
				case 0xb8: // invokestatic
					operation = strdup ("call static");
					type = strdup ("FUNCTION");
					addr = bb->addr;
					break;
				case 0xb9: // invokeinterface
					operation = strdup ("call interface");
					type = strdup ("FUNCTION");
					addr = bb->addr;
					break;
				case 0xba: // invokedynamic
					operation = strdup ("call dynamic");
					type = strdup ("FUNCTION");
					addr = bb->addr;
					break;
				default:
					operation = NULL;
					addr = -1;
					break;
				}
			} else if ( (bb->type2 & R_ANAL_EX_LDST_LOAD_GET_STATIC) == R_ANAL_EX_LDST_LOAD_GET_STATIC) {
				operation = strdup ("read static");
				type = strdup ("FIELD");
				addr = bb->addr;
			} else if ( (bb->type2 & R_ANAL_EX_LDST_LOAD_GET_FIELD)  == R_ANAL_EX_LDST_LOAD_GET_FIELD) {
				operation = strdup ("read dynamic");
				type = strdup ("FIELD");
				addr = bb->addr;
			} else if ( (bb->type2 & R_ANAL_EX_LDST_STORE_PUT_STATIC) == R_ANAL_EX_LDST_STORE_PUT_STATIC) {
				operation = strdup ("write static");
				type = strdup ("FIELD");
				addr = bb->addr;
			} else if ( (bb->type2 & R_ANAL_EX_LDST_STORE_PUT_FIELD)  == R_ANAL_EX_LDST_STORE_PUT_FIELD) {
				operation = strdup ("write dynamic");
				type = strdup ("FIELD");
				addr = bb->addr;
			}

			if (operation) {
				cp_ref_idx = R_BIN_JAVA_USHORT (bb->op_bytes, 1);
				full_bird = r_cmd_java_get_descriptor (core, bin, cp_ref_idx);
				if (!full_bird) {
					eprintf ("Error identifying reference @ 0x%"PFMT64x"\n", bb->addr);
					full_bird = strdup ("ANALYSIS_ERROR");
				}
				r_cons_printf (fmt, addr, fcn->name, operation, type, full_bird);
			}
			free (full_bird);
			free (type);
			free (operation);
		}
	}
	return true;
}

static int r_cmd_java_handle_yara_code_extraction_refs (RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = anal ? (RBinJavaObj *) r_cmd_java_get_bin_obj (anal) : NULL;
	const char *p = input? r_cmd_java_consumetok (input, ' ', -1): NULL, *n = NULL;
	char *name = NULL;
	ut64 addr = -1, count = -1;
	int res = false;

	if (!bin) return res;
	else if (!anal || !anal->fcns || r_list_length (anal->fcns) == 0) {
		eprintf ("Unable to access the current analysis, perform 'af' for function analysis.\n");
		return true;
	}

	if (!p) return res;

	n = *p ? r_cmd_java_strtok (p, ' ', -1) : NULL;
	name = n && p && p != n ? malloc (n - p + 2) : NULL;

	if (!name) return res;

	memset (name, 0, n-p);
	memcpy (name, p, n-p);

	p = r_cmd_java_strtok (p, ' ', -1);
	addr = p && *p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	p = r_cmd_java_strtok (p, ' ', -1);
	count = p && *p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	if (name && count != (ut64) -1 && addr != (ut64) -1) {
		// find function at addr

		// find the start basic block

		// read the bytes

		// hexlify the bytes

		// set the name = bytes

		// print t
	}
	free (name);
	return res;
}

static int r_cmd_java_handle_insert_method_ref (RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = anal ? (RBinJavaObj *) r_cmd_java_get_bin_obj (anal) : NULL;
	const char *p = input? r_cmd_java_consumetok (input, ' ', -1): NULL, *n = NULL;
	char  *classname=NULL, *name = NULL, *descriptor = NULL;
	ut32 cn_sz = 0, n_sz = 0, d_sz = 0;
	int res = false;

	if (!bin) {
		return res;
	}
	if (!anal || !anal->fcns || r_list_length (anal->fcns) == 0) {
		eprintf ("Unable to access the current analysis, perform 'af' for function analysis.\n");
		return true;
	}
	if (!p) return res;

	n = p && *p ? r_cmd_java_strtok (p, ' ', -1) : NULL;
	classname = n && p && p != n ? malloc (n-p+1) : NULL;
	cn_sz = n && p ? n-p +1 : 0;
	if (!classname) return res;

	snprintf (classname, cn_sz, "%s", p);
	//memset (classname, 0, cn_sz);
	//memcpy (classname, p, n-p);
	p = n+1;
	n = p && *p ? r_cmd_java_strtok (p, ' ', -1) : NULL;
	name = n && p && p != n ? malloc (n-p+1) : NULL;
	n_sz = n && p ? n-p +1 : 0;
	if (!name) {
		free (classname);
		return res;
	}
	snprintf (name, n_sz, "%s", p);
	//memset (name, 0, n_sz);
	//memcpy (name, p, n-p);

	p = n + 1;
	n =  p && *p ? r_cmd_java_strtok (p, ' ', -1) : NULL;
	if (n) {
		descriptor = n && p && p != n ? malloc (n-p+1) : NULL;
		d_sz = n-p +1;
	} else if (p && *p) {
		d_sz = strlen (p) + 1;
		descriptor = d_sz > 1 ? malloc (d_sz) : NULL;
	}

	if (!descriptor) {
		free (classname);
		free (name);
		return res;
	}
	snprintf (descriptor, d_sz, "%s", p);
	//memset (descriptor, 0, d_sz);
	//memcpy (descriptor, p, n-p);

	r_cons_printf ("Would be adding class name:%s, name: %s, descriptor: %s\n", classname, name, descriptor);
	free (classname);
	free (name);
	free (descriptor);
	res = true;
	return res;
}

static int r_cmd_java_handle_print_exceptions (RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	RListIter *exc_iter = NULL, *methods_iter=NULL;
	RBinJavaField *method;
	ut64 func_addr = -1;
	RBinJavaExceptionEntry *exc_entry;

	const char *p = input? r_cmd_java_consumetok (input, ' ', -1): NULL;
	func_addr = p && *p && r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	if (!bin) return false;

	r_list_foreach (bin->methods_list, methods_iter, method) {
		ut64 start = r_bin_java_get_method_start(bin, method),
			end = r_bin_java_get_method_end(bin, method);
		ut8 do_this_one = start <= func_addr && func_addr <= end;	RList * exc_table = NULL;
		do_this_one = func_addr == -1 ? 1 : do_this_one;
		if (!do_this_one) continue;
		exc_table = r_bin_java_get_method_exception_table_with_addr (bin, start);

		if (r_list_length (exc_table) == 0){
			r_cons_printf (" Exception table for %s @ 0x%"PFMT64x":\n", method->name, start);
			r_cons_printf (" [ NONE ]\n");
		} else {
			r_cons_printf (" Exception table for %s (%d entries) @ 0x%"PFMT64x":\n", method->name,
				r_list_length (exc_table) , start);
		}
		r_list_foreach (exc_table, exc_iter, exc_entry) {
			char *class_info = r_bin_java_resolve_without_space (bin, exc_entry->catch_type);
			r_cons_printf ("  Catch Type: %d, %s @ 0x%"PFMT64x"\n", exc_entry->catch_type,
				class_info, exc_entry->file_offset+6);
			r_cons_printf ("  Start PC: (0x%"PFMT64x") 0x%"PFMT64x" @ 0x%"PFMT64x"\n",
				exc_entry->start_pc, exc_entry->start_pc+start, exc_entry->file_offset);
			r_cons_printf ("  End PC: (0x%"PFMT64x") 0x%"PFMT64x" 0x%"PFMT64x"\n",
				exc_entry->end_pc, exc_entry->end_pc+start, exc_entry->file_offset + 2);
			r_cons_printf ("  Handler PC: (0x%"PFMT64x") 0x%"PFMT64x" 0x%"PFMT64x"\n",
				exc_entry->handler_pc, exc_entry->handler_pc+start, exc_entry->file_offset+4);
			free (class_info);
		}
	}
	return true;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_java = {
	.name = "java",
	.desc = "Suite of java commands, java help for more info",
	.license = "Apache",
	.call = r_cmd_java_call,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_java,
	.version = R2_VERSION
};
#endif
