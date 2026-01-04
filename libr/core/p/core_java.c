/* radare2 - Apache - Copyright 2014-2025 - dso, pancake */

#include <r_core.h>

#include "../../../shlr/java/ops.h"
#include "../../../shlr/java/class.h"
#include "../../../shlr/java/code.h"

typedef struct found_idx_t {
	ut16 idx;
	ut64 addr;
	const RBinJavaCPTypeObj *obj;
} RCmdJavaCPResult;

typedef bool (*RCMDJavaCmdHandler) (RCore *core, const char *cmd);

static const char *r_cmd_java_strtok(RCore *core, const char *str1, const char b, size_t len);
static const char *r_cmd_java_consumetok(const char *str1, const char b, size_t len);
static bool r_cmd_java_reload_bin_from_buf(RCore *core, RBinJavaObj *obj, ut8* buffer, ut64 len);

static bool r_cmd_java_print_json_definitions(RCore *core, RBinJavaObj *obj);
static bool r_cmd_java_print_all_definitions(RCore *core);
static bool r_cmd_java_print_class_definitions(RCore *core, RBinJavaObj *obj);
static bool r_cmd_java_print_field_definitions(RCore *core, RBinJavaObj *obj);
static bool r_cmd_java_print_method_definitions(RCore *core, RBinJavaObj *obj);
static bool r_cmd_java_print_import_definitions(RCore *core, RBinJavaObj *obj);

static bool r_cmd_java_print_class_access_flags_value(RCore *core, const char *flags );
static bool r_cmd_java_print_field_access_flags_value(RCore *core, const char *flags );
static bool r_cmd_java_print_method_access_flags_value(RCore *core, const char *flags );
static bool r_cmd_java_get_all_access_flags_value(RCore *core, const char *cmd);

static bool r_cmd_java_set_acc_flags(RCore *core, ut64 addr, ut16 num_acc_flag);

#define _(x) UNUSED_FUNCTION(x)
static bool r_cmd_java_print_field_summary(RBinJavaObj *obj, ut16 idx);
// static bool _(r_cmd_java_print_field_count)(RBinJavaObj *obj);
static bool r_cmd_java_print_field_name(RCore *core, RBinJavaObj *obj, ut16 idx);
static bool r_cmd_java_print_field_num_name(RCore *core, RBinJavaObj *obj);
static bool r_cmd_java_print_method_summary(RBinJavaObj *obj, ut16 idx);
static bool r_cmd_java_print_method_name(RCore *core, RBinJavaObj *obj, ut16 idx);
static bool r_cmd_java_print_method_num_name(RCore *core, RBinJavaObj *obj);

static RBinJavaObj *r_cmd_java_get_bin_obj(RAnal *anal);
static RList *r_cmd_java_get_bin_obj_list(RAnal *anal);
static ut64 r_cmd_java_get_input_num_value(RCore *core, const char *input_value);
static bool r_cmd_java_is_valid_input_num_value(RCore *core, const char *input_value);

static bool r_cmd_java_handle_help(RCore * core, const char *input);
static bool r_cmd_java_handle_set_flags(RCore *core, const char *cmd);
static bool r_cmd_java_handle_prototypes(RCore *core, const char *cmd);
static bool r_cmd_java_handle_resolve_cp(RCore *core, const char *cmd);
static bool r_cmd_java_handle_calc_flags(RCore *core, const char *cmd);
static bool r_cmd_java_handle_flags_str(RCore *core, const char *cmd);
static bool r_cmd_java_handle_flags_str_at(RCore *core, const char *cmd);
static bool r_cmd_java_handle_field_info(RCore *core, const char *cmd);
static bool r_cmd_java_handle_method_info(RCore *core, const char *cmd);

static bool r_cmd_java_handle_find_cp_const(RCore *core, const char *cmd);

static RList *cpfind_float(RBinJavaObj *obj, const char *cmd);
static RList *cpfind_double(RBinJavaObj *obj, const char *cmd);
static RList *cpfind_long(RCore *core, RBinJavaObj *obj, const char *cmd);
static RList *cpfind_int(RCore *core, RBinJavaObj *obj, const char *cmd);
static RList *cpfind_str(RBinJavaObj *obj, const char *cmd);

static bool cpfind(RCore *core, const char *cmd);

static bool r_cmd_java_get_cp_bytes_and_write(RCore *core, RBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 *buf, const ut64 len);
static bool r_cmd_java_handle_replace_cp_value_float(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static bool r_cmd_java_handle_replace_cp_value_double(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static bool r_cmd_java_handle_replace_cp_value_long(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static bool r_cmd_java_handle_replace_cp_value_int(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static bool r_cmd_java_handle_replace_cp_value_str(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static bool r_cmd_java_handle_replace_cp_value(RCore *core, const char *cmd);

static bool r_cmd_java_handle_replace_classname_value(RCore *core, const char *cmd);
static bool r_cmd_is_object_descriptor(const char *name, ut32 name_len);
static ut32 r_cmd_get_num_classname_str_occ(const char *str, const char *match_me);
static const char *r_cmd_get_next_classname_str(const char *str, const char *match_me);

static bool r_cmd_java_handle_summary_info(RCore *core, const char *cmd);
static bool r_cmd_java_handle_reload_bin(RCore *core, const char *cmd);

static bool r_cmd_java_handle_print_exceptions(RCore *core, const char *input);
static bool r_cmd_java_handle_insert_method_ref(RCore *core, const char *input);
static bool r_cmd_java_handle_yara_code_extraction_refs(RCore *core, const char *input);

static bool r_cmd_java_handle_isvalid(RCore *core, const char *cmd);
static bool r_cmd_java_handle_calc_class_sz(RCore *core, const char *cmd);

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
	{ HELP, HELP_ARGS, HELP_DESC, HELP_LEN, r_cmd_java_handle_help },
	{ SET_ACC_FLAGS, SET_ACC_FLAGS_ARGS, SET_ACC_FLAGS_DESC, SET_ACC_FLAGS_LEN, r_cmd_java_handle_set_flags },
	{ PROTOTYPES, PROTOTYPES_ARGS, PROTOTYPES_DESC, PROTOTYPES_LEN, r_cmd_java_handle_prototypes },
	{ RESOLVE_CP, RESOLVE_CP_ARGS, RESOLVE_CP_DESC, RESOLVE_CP_LEN, r_cmd_java_handle_resolve_cp },
	{ CALC_FLAGS, CALC_FLAGS_ARGS, CALC_FLAGS_DESC, CALC_FLAGS_LEN, r_cmd_java_handle_calc_flags },
	{ FLAGS_STR_AT, FLAGS_STR_AT_ARGS, FLAGS_STR_AT_DESC, FLAGS_STR_AT_LEN, r_cmd_java_handle_flags_str_at },
	{ FLAGS_STR, FLAGS_STR_ARGS, FLAGS_STR_DESC, FLAGS_STR_LEN, r_cmd_java_handle_flags_str },
	{ METHOD_INFO, METHOD_INFO_ARGS, METHOD_INFO_DESC, METHOD_INFO_LEN, r_cmd_java_handle_method_info },
	{ FIELD_INFO, FIELD_INFO_ARGS, FIELD_INFO_DESC, FIELD_INFO_LEN, r_cmd_java_handle_field_info },
	{ FIND_CP_CONST, FIND_CP_CONST_ARGS, FIND_CP_CONST_DESC, FIND_CP_CONST_LEN, r_cmd_java_handle_find_cp_const },
	{ FIND_CP_VALUE, FIND_CP_VALUE_ARGS, FIND_CP_VALUE_DESC, FIND_CP_VALUE_LEN, cpfind },
	{ REPLACE_CP_VALUE, REPLACE_CP_VALUE_ARGS, REPLACE_CP_VALUE_DESC, REPLACE_CP_VALUE_LEN, r_cmd_java_handle_replace_cp_value },
	{ REPLACE_CLASS_NAME, REPLACE_CLASS_NAME_ARGS, REPLACE_CLASS_NAME_DESC, REPLACE_CLASS_NAME_LEN, r_cmd_java_handle_replace_classname_value },
	{ RELOAD_BIN, RELOAD_BIN_ARGS, RELOAD_BIN_DESC, RELOAD_BIN_LEN, r_cmd_java_handle_reload_bin },
	{ SUMMARY_INFO, SUMMARY_INFO_ARGS, SUMMARY_INFO_DESC, SUMMARY_INFO_LEN, r_cmd_java_handle_summary_info },
	{ PRINT_EXC, PRINT_EXC_ARGS, PRINT_EXC_DESC, PRINT_EXC_LEN, r_cmd_java_handle_print_exceptions },
	{ YARA_CODE_REFS, YARA_CODE_REFS_ARGS, YARA_CODE_REFS_DESC, YARA_CODE_REFS_LEN, r_cmd_java_handle_yara_code_extraction_refs },
	{ INSERT_MREF, INSERT_MREF_ARGS, INSERT_MREF_DESC, INSERT_MREF_LEN, r_cmd_java_handle_insert_method_ref },
	{ CALC_SZ, CALC_SZ_ARGS, CALC_SZ_DESC, CALC_SZ_LEN, r_cmd_java_handle_calc_class_sz },
	{ ISVALID, ISVALID_ARGS, ISVALID_DESC, ISVALID_LEN, r_cmd_java_handle_isvalid },
	{ NULL, NULL, NULL, 0, NULL }
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
	PRINT_EXC_IDX = 15,
	YARA_CODE_REFS_IDX = 16,
	INSERT_MREF_IDX = 17,
	CALC_SZ_IDX = 18,
	ISVALID_IDX = 19,
	END_CMDS = 20,
};

static ut8 _(r_cmd_java_obj_ref)(const char *name, const char *class_name, ut32 len) {
	if (!name || !class_name) {
		return false;
	}
	if (strncmp (class_name, name, len)) {
		return false;
	}
	if (*(name - 1) == 'L' && *(name + len) == ';') {
		return true;
	}
	if (!strncmp (class_name, name, len) && !*(name + len)) {
		return true;
	}
	return false;
}

static const char *r_cmd_get_next_classname_str(const char *str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me? strlen (match_me): 0;
	if (len && str && *str) {
		result = str;
		while (result && *result && (result - str < len)) {
			result = strstr (result, match_me);
			if (result) {
				break;
			}
		}
	}
	return result;
}

static ut32 r_cmd_get_num_classname_str_occ(const char *str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me? strlen (match_me): 0;
	ut32 occ = 0;

	if (len == 0 || !str || !*str) {
		return 0;
	}
	result = str;
	while (result && *result && (result - str < len)) {
		result = strstr (result, match_me);
		if (result) {
			R_LOG_DEBUG ("result: %s", result);
			result += len;
			occ++;
		}
	}
	return occ;
}

static const char *r_cmd_java_consumetok(const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p) {
		return p;
	}
	if (len == (size_t)-1) {
		len = strlen (str1);
	}
	for (; i < len; i++, p++) {
		if (*p != b) {
			break;
		}
	}
	return p;
}

static const char *r_cmd_java_strtok(RCore *core, const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (R_STR_ISEMPTY (p)) {
		return p;
	}
	if (len == (size_t)-1) {
		len = strlen (str1);
	}
	R_LOG_DEBUG ("Looking for char (%c) in (%s) up to %u", b, p, (unsigned int)len);
	for (; i < len; i++, p++) {
		if (*p == b) {
			R_LOG_DEBUG ("Found? for char (%c) @ %u: (%s)", b, (unsigned int)i, p);
			break;
		}
	}
	if (i == len) {
		p = NULL;
	}
	R_LOG_DEBUG ("Found? for char (%c) @ %u: (%s)", b, (unsigned int)len, p);
	return p;
}

static RAnal *get_anal(RCore *core) {
	return core? core->anal: NULL;
}

static void r_cmd_java_print_cmd_help(RCmdJavaCmd *cmd) {
	eprintf ("[*] %s %s\n[+] %s\n\n", cmd->name, cmd->args, cmd->desc);
}

static bool r_cmd_java_handle_help(RCore *core, const char *input) {
	ut32 i = 0;
	const char **help_msg = (const char **)malloc (sizeof (char *) * END_CMDS * 4);
	help_msg[0] = "Usage:";
	help_msg[1] = "java [cmd] [arg..] ";
	help_msg[2] = r_core_plugin_java.meta.desc;
	for (i = 0; JAVA_CMDS[i].name; i++) {
		RCmdJavaCmd *cmd = &JAVA_CMDS[i];
		help_msg[3 + (i * 3) + 0] = cmd->name;
		help_msg[3 + (i * 3) + 1] = cmd->args;
		help_msg[3 + (i * 3) + 2] = cmd->desc;
	}
	help_msg[3 + (i * 3)] = NULL;
	r_core_cmd_help (core, help_msg);
	free ((void *)help_msg);
	return true;
}

static bool r_cmd_java_handle_prototypes(RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	R_LOG_DEBUG ("Function call made: %s", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}

	switch (*(cmd)) {
	case 'm': return r_cmd_java_print_method_definitions (core, obj);
	case 'f': return r_cmd_java_print_field_definitions (core, obj);
	case 'i': return r_cmd_java_print_import_definitions (core, obj);
	case 'c': return r_cmd_java_print_class_definitions (core, obj);
	case 'a': return r_cmd_java_print_all_definitions (core);
	case 'j': return r_cmd_java_print_json_definitions (core, obj);
	}
	return false;
}

static bool r_cmd_java_handle_summary_info(RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	R_LOG_DEBUG ("Function call made: %s", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}

	r_cons_printf (core->cons, "Summary for %s:\n", obj->file);
	r_cons_printf (core->cons, "  Size 0x%x:\n", obj->size);
	r_cons_printf (core->cons, "  Constants  size: 0x%x count: %d:\n", obj->cp_size, obj->cp_count);
	r_cons_printf (core->cons, "  Methods    size: 0x%x count: %d:\n", obj->methods_size, obj->methods_count);
	r_cons_printf (core->cons, "  Fields     size: 0x%x count: %d:\n", obj->fields_size, obj->fields_count);
	r_cons_printf (core->cons, "  Attributes size: 0x%x count: %d:\n", obj->attrs_size, obj->attrs_count);
	r_cons_printf (core->cons, "  Interfaces size: 0x%x count: %d:\n", obj->interfaces_size, obj->interfaces_count);

	return true;
}

static bool _(r_cmd_java_check_op_idx)(const ut8 *op_bytes, ut16 idx) {
	return R_BIN_JAVA_USHORT (op_bytes, 0) == idx;
}

/* Find stuff in the constant pool */
static RList *cpfind_double(RBinJavaObj *obj, const char *cmd) {
	double value = cmd && *cmd? strtod (cmd, NULL): 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0')) {
		return r_list_new ();
	}
	return r_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 8, R_BIN_JAVA_CP_DOUBLE);
}

static RList *cpfind_float(RBinJavaObj *obj, const char *cmd) {
	float value = cmd && *cmd? atof (cmd): 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0')) {
		return r_list_new ();
	}
	return r_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 4, R_BIN_JAVA_CP_FLOAT);
}

static RList *cpfind_long(RCore *core, RBinJavaObj *obj, const char *cmd) {
	ut64 value = r_cmd_java_get_input_num_value (core, cmd);
	if (!r_cmd_java_is_valid_input_num_value (core, cmd)) {
		return r_list_new ();
	}
	return r_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 8, R_BIN_JAVA_CP_LONG);
}

static RList *cpfind_int(RCore *core, RBinJavaObj *obj, const char *cmd) {
	ut32 value = (ut32)r_cmd_java_get_input_num_value (core, cmd);
	if (!r_cmd_java_is_valid_input_num_value (core, cmd)) {
		return r_list_new ();
	}
	return r_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 4, R_BIN_JAVA_CP_INTEGER);
}

static RList *cpfind_str(RBinJavaObj *obj, const char *cmd) {
	if (!cmd) {
		return r_list_new ();
	}
	R_LOG_DEBUG ("Looking for str: %s (%u)", cmd, (unsigned int)strlen (cmd));
	return r_bin_java_find_cp_const_by_val (obj, (const ut8 *)cmd, strlen (cmd), R_BIN_JAVA_CP_UTF8);
}

static bool cpfind(RCore *core, const char *cmd) {
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (get_anal (core));
	const char *p = cmd;
	char f_type = 0;
	RList *find_list = NULL;
	RListIter *iter;
	ut32 *idx;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}
	R_LOG_DEBUG ("Function call made: %s", p);
	if (p && *p) {
		p = r_cmd_java_consumetok (cmd, ' ', -1);
		f_type = *p;
		p += 2;
	}
	R_LOG_DEBUG ("Function call made: %s", p);
	switch (f_type) {
	case 's': find_list = cpfind_str (obj, p); break;
	case 'i': find_list = cpfind_int (core, obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	case 'l': find_list = cpfind_long (core, obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	case 'f': find_list = cpfind_float (obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	case 'd': find_list = cpfind_double (obj, r_cmd_java_consumetok (p, ' ', -1)); break;
	default:
		eprintf ("[-] r_cmd_java: invalid java type to search for.\n");
		return true;
	}

	r_list_foreach (find_list, iter, idx) {
		ut64 addr = r_bin_java_resolve_cp_idx_address (obj, (ut16)*idx);
		r_cons_printf (core->cons, "Offset: 0x%" PFMT64x " idx: %d\n", addr, *idx);
	}
	r_list_free (find_list);
	return true;
}

static bool r_cmd_java_reload_bin_from_buf(RCore *core, RBinJavaObj *obj, ut8 *buffer, ut64 len) {
	if (!buffer || len < 10) {
		return false;
	}
	int res = r_bin_java_load_bin (obj, buffer, len);

	if (res == true) {
		//RBinPlugin *cp = NULL;
		RBinPlugin *tmp;
		RListIter *iter;
		r_list_foreach (core->bin->plugins, iter, tmp) {
			if (!strncmp ("java", tmp->meta.name, 4)) {
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

static bool r_cmd_java_get_cp_bytes_and_write(RCore *core, RBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 *buf, const ut64 len) {
	int res = false;
	RBinJavaCPTypeObj *cp_obj = r_bin_java_get_item_from_bin_cp_list (obj, idx);
	ut64 c_file_sz = r_io_size (core->io);
	ut32 n_sz = 0, c_sz = obj? r_bin_java_cp_get_size (obj, idx): (ut32)-1;
	ut8 *bytes = NULL;

	if (c_sz == (ut32)-1) {
		return res;
	}

	bytes = r_bin_java_cp_get_bytes (cp_obj->tag, &n_sz, buf, len);

	if (n_sz < c_sz) {
		res = r_core_shift_block (core, addr + c_sz, 0, (int)n_sz - (int)c_sz) &&
			r_io_resize (core->io, c_file_sz + (int)n_sz - (int)c_sz);
	} else if (n_sz > c_sz) {
		res = r_core_extend_at (core, addr, (int)n_sz - (int)c_sz);
	} else {
		eprintf ("[X] r_cmd_java_get_cp_bytes_and_write: Failed to resize the file correctly aborting.\n");
		return res;
	}

	if (n_sz > 0 && bytes) {
		res = r_core_write_at (core, addr, (const ut8 *)bytes, n_sz) && r_core_seek (core, addr, true);
	}

	if (res == false) {
		eprintf ("[X] r_cmd_java_get_cp_bytes_and_write: Failed to write the bytes to the file correctly aborting.\n");
		return res;
	}

	R_FREE (bytes);

	if (res == true) {
		ut64 n_file_sz = 0;
		ut8 *bin_buffer = NULL;
		n_file_sz = r_io_size (core->io);
		bin_buffer = n_file_sz > 0? malloc (n_file_sz): NULL;
		if (bin_buffer) {
			memset (bin_buffer, 0, n_file_sz);
			res = (n_file_sz == r_io_read_at (core->io, obj->loadaddr, bin_buffer, n_file_sz))? true: false;
			if (res == true) {
				res = r_cmd_java_reload_bin_from_buf (
					core, obj, bin_buffer, n_file_sz);
			} else {
				eprintf ("[X] r_cmd_java_get_cp_bytes_and_write: Failed to read the file in aborted, bin reload.\n");
			}
			free (bin_buffer);
		}
	}
	return res;
}

static bool r_cmd_java_handle_replace_cp_value_float(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	float value = cmd && *cmd? atof (cmd): 0.0;
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 4);
	return res;
}

static bool r_cmd_java_handle_replace_cp_value_double(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	double value = cmd && *cmd? strtod (cmd, NULL): 0.0;
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 8);
	return res;
}

static bool r_cmd_java_handle_replace_cp_value_long(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut64 value = r_cmd_java_get_input_num_value (core, cmd);
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 8);
	return res;
}

static bool r_cmd_java_handle_replace_cp_value_int(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut32 value = (ut32)r_cmd_java_get_input_num_value (core, cmd);
	int res = false;
	res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 4);
	return res;
}

static bool r_cmd_java_handle_replace_cp_value_str(RCore *core, RBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	int res = false;
	ut32 len = cmd && *cmd? strlen (cmd): 0;
	if (len > 0 && cmd && *cmd == '"') {
		cmd++;
		len = cmd && *cmd? strlen (cmd): 0;
	}
	if (cmd && len > 0) {
		res = r_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)cmd, len);
	}
	return res;
}

static bool r_cmd_java_handle_replace_cp_value(RCore *core, const char *cmd) {
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (get_anal (core));
	ut16 idx = -1;
	ut64 addr = 0;
	const char *p = cmd;
	char cp_type = 0;
	R_LOG_DEBUG ("Function call made: %s", p);
	if (p && *p) {
		p = r_cmd_java_consumetok (cmd, ' ', -1);
		if (r_cmd_java_is_valid_input_num_value (core, p)) {
			idx = r_cmd_java_get_input_num_value (core, p);
			p = r_cmd_java_strtok (core, p, ' ', strlen (p));
		}
	}
	if (idx == (ut16)-1) {
		eprintf ("[-] r_cmd_java: Invalid index value.\n");
	} else if (!obj) {
		eprintf ("[-] r_cmd_java: The current binary is not a Java Bin Object.\n");
	} else if (!p || (p && !*p)) {
		r_cmd_java_print_cmd_help (JAVA_CMDS + REPLACE_CP_VALUE_IDX);
		return true;
	} else {
		cp_type = r_bin_java_resolve_cp_idx_tag (obj, idx);
		addr = r_bin_java_resolve_cp_idx_address (obj, idx);
		R_LOG_DEBUG ("Function call made: %s", p);
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

static char *r_cmd_replace_name(RCore *core, const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	ut32 num_occurrences = 0, i = 0;
	char *result = NULL, *p_result = NULL;

	num_occurrences = r_cmd_get_num_classname_str_occ (buffer, s_old);
	*res_len = 0;
	if (num_occurrences > 0 && replace_len > 0 && s_old) {
		ut32 consumed = 0;
		const char *next = r_cmd_get_next_classname_str (buffer + consumed, s_old);
		R_LOG_DEBUG ("Replacing \"%s\" with \"%s\" in: %s", s_old, s_new, buffer);
		result = malloc (num_occurrences * replace_len + buf_len);
		memset (result, 0, num_occurrences * replace_len + buf_len);
		p_result = result;
		while (next && consumed < buf_len) {
			// replace up to next
			R_LOG_DEBUG ("next: \"%s\", len to: %" PFMTDPTR, next, (ptrdiff_t)(next - buffer));
			for (; buffer + consumed < next && consumed < buf_len; consumed++, p_result++) {
				*p_result = *(buffer + consumed);
				(*res_len)++;
			}

			for (i = 0; i < replace_len; i++, p_result++) {
				*p_result = *(s_new + i);
				(*res_len)++;
			}
			consumed += match_len;
			next = r_cmd_get_next_classname_str (buffer + consumed, s_old);
		}
		R_LOG_DEBUG ("Found last occurrence of: \"%s\", remaining: %s", s_old, buffer + consumed);
		R_LOG_DEBUG ("result is: \"%s\"", result);
		for (; consumed < buf_len; consumed++, p_result++, (*res_len)++) {
			*p_result = *(buffer + consumed);
		}
		R_LOG_DEBUG ("Old: %s vs New: %s", buffer, result);
	}
	return result;
}

static char *r_cmd_replace_name_def(RCore *core, const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	const char *fmt = "L%s;";
	char *s_new_ref = s_new && replace_len > 0? malloc (3 + replace_len): NULL;
	char *s_old_ref = s_old && match_len > 0? malloc (3 + match_len): NULL;
	char *result = NULL;
	*res_len = 0;
	if (s_new_ref && s_old_ref) {
		snprintf (s_new_ref, replace_len + 3, fmt, s_new);
		snprintf (s_old_ref, match_len + 3, fmt, s_old);
		result = r_cmd_replace_name (core, s_new_ref, replace_len + 2, s_old_ref, match_len + 2, buffer, buf_len, res_len);
	}
	free (s_new_ref);
	free (s_old_ref);
	return result;
}

static bool r_cmd_is_object_descriptor(const char *name, ut32 name_len) {
	int found_L = false, found_Semi = false;
	ut32 idx = 0, L_pos = 0, Semi_pos = 0;
	const char *p_name = name;

	for (idx = 0, L_pos = 0; idx < name_len; idx++, p_name++) {
		if (*p_name == 'L') {
			found_L = true;
			L_pos = idx;
			break;
		}
	}

	for (idx = 0, Semi_pos = 0; idx < name_len; idx++, p_name++) {
		if (*p_name == ';') {
			found_Semi = true;
			Semi_pos = idx;
			break;
		}
	}

	return true? found_L == found_Semi && found_L == true && L_pos < Semi_pos: false;
}

static bool r_cmd_java_get_class_names_from_input(RCore *core, const char *input, char **class_name, ut32 *class_name_len, char **new_class_name, ut32 *new_class_name_len) {
	const char *p = input;

	ut32 cmd_sz = input && *input? strlen (input): 0;
	int res = false;

	if (!class_name || *class_name) {
		return res;
	} else if (!new_class_name || *new_class_name) {
		return res;
	} else if (!new_class_name_len || !class_name_len) {
		return res;
	}

	*new_class_name = NULL;
	*class_name_len = 0;

	if (p && *p && cmd_sz > 1) {
		const char *end;
		p = r_cmd_java_consumetok (p, ' ', cmd_sz);
		end = p && *p? r_cmd_java_strtok (core, p, ' ', -1): NULL;

		if (p && end && p != end) {
			*class_name_len = end - p + 1;
			*class_name = malloc (*class_name_len);
			snprintf (*class_name, *class_name_len, "%s", p);
			cmd_sz = *class_name_len - 1 < cmd_sz? cmd_sz - *class_name_len: 0;
		}

		if (*class_name && cmd_sz > 0) {
			p = r_cmd_java_consumetok (end + 1, ' ', cmd_sz);
			end = p && *p? r_cmd_java_strtok (core, p, ' ', -1): NULL;

			if (!end && p && *p) {
				end = p + cmd_sz;
			}

			if (p && end && p != end) {
				*new_class_name_len = end - p + 1;
				*new_class_name = malloc (*new_class_name_len);
				snprintf (*new_class_name, *new_class_name_len, "%s", p);
				res = true;
			}
		}
	}
	return res;
}

static bool r_cmd_java_handle_replace_classname_value(RCore *core, const char *cmd) {
	RBinJavaObj *obj;
	char *class_name = NULL, *new_class_name = NULL;
	ut32 class_name_len = 0, new_class_name_len = 0;
	RAnal *anal = get_anal (core);
	int res = false;
	ut32 idx = -1;

	if (!core || !anal || !cmd) {
		return false;
	}
	R_LOG_DEBUG ("Function call made: %s", cmd);
	obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	if (!obj) {
		eprintf ("The current binary is not a Java Bin Object.\n");
		return true;
	}
	res = r_cmd_java_get_class_names_from_input (core, cmd, &class_name,
		&class_name_len, &new_class_name, &new_class_name_len);

	if (!res || !class_name || !new_class_name) {
		r_cmd_java_print_cmd_help (JAVA_CMDS + REPLACE_CLASS_NAME_IDX);
		free (class_name);
		free (new_class_name);
		return true;
	}
	for (idx = 1; idx <= obj->cp_count; idx++) {
		RBinJavaCPTypeObj *cp_obj = r_bin_java_get_item_from_bin_cp_list (obj, idx);
		char *name = NULL;
		ut8 *buffer = NULL;
		ut32 buffer_sz = 0;
		ut16 len = 0;
		if (cp_obj && cp_obj->tag == R_BIN_JAVA_CP_UTF8 &&
			cp_obj->info.cp_utf8.length && cp_obj->info.cp_utf8.length >= class_name_len - 1) {
			ut32 num_occurrences = 0;
			ut64 addr = cp_obj->file_offset + cp_obj->loadaddr;
			buffer = r_bin_java_cp_get_idx_bytes (obj, idx, &buffer_sz);

			if (!buffer) {
				continue;
			}
			len = R_BIN_JAVA_USHORT (buffer, 1);
			name = malloc (len + 3);
			memcpy (name, buffer + 3, len);
			name[len] = 0;

			num_occurrences = r_cmd_get_num_classname_str_occ (name, class_name);

			if (num_occurrences > 0) {
				// perform inplace replacement
				ut32 res_len = 0;
				char *result = NULL;

				if (r_cmd_is_object_descriptor (name, len) == true) {
					result = r_cmd_replace_name_def (core, new_class_name,
						new_class_name_len - 1, class_name,
						class_name_len - 1, name, len, &res_len);
				} else {
					result = r_cmd_replace_name (core, new_class_name,
						new_class_name_len - 1, class_name,
						class_name_len - 1, name, len, &res_len);
				}
				if (result) {
					res = r_cmd_java_get_cp_bytes_and_write (
						core, obj, idx, addr,
						(const ut8 *)result, res_len);
					if (res == false) {
						R_LOG_ERROR ("r_cmd_java: Failed to write bytes or reload the binary");
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

static bool r_cmd_java_handle_reload_bin(RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	const char *p = cmd;
	ut64 addr = 0LL;
	ut64 buf_size = 0;
	ut8 *buf = NULL;
	int res = false;

	if (*cmd == ' ') {
		p = r_cmd_java_consumetok (p, ' ', -1);
	}
	if (!*cmd) {
		r_cmd_java_print_cmd_help (JAVA_CMDS + RELOAD_BIN_IDX);
		return true;
	}

	addr = r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): (ut32)-1;
	if (*cmd == ' ') {
		p = r_cmd_java_consumetok (p, ' ', -1);
	}
	buf_size = r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): (ut32)-1;

	// XXX this may cause problems cause the file we are looking at may not be the bin we want.
	// lets pretend it is for now
	if (buf_size == 0) {
		res = true;
		buf_size = r_io_size (core->io);
		buf = calloc (1, buf_size);
		if (!buf) {
			R_LOG_ERROR ("Cannot allocate %d", buf_size);
			return false;
		}
		r_io_read_at (core->io, addr, buf, buf_size);
	}
	if (buf && obj) {
		res = r_cmd_java_reload_bin_from_buf (core, obj, buf, buf_size);
	}
	free (buf);
	return res;
}

static bool r_cmd_java_handle_find_cp_const(RCore *core, const char *cmd) {
	const char *p = (cmd && *cmd == ' ')? r_cmd_java_consumetok (cmd, ' ', -1): NULL;
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (get_anal (core));
	RAnalFunction *fcn = NULL;
	RAnalBlock *bb = NULL;
	RListIter *bb_iter, *fn_iter, *iter;
	RCmdJavaCPResult *cp_res = NULL;
	ut16 idx = -1;
	RList *find_list;

	if (p && *p == 'a') {
		idx = -1;
	} else {
		idx = r_cmd_java_get_input_num_value (core, p);
	}

	R_LOG_DEBUG ("Function call made: %s", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	}
	if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + FIND_CP_CONST_IDX);
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
				cp_res = (idx == (ut16)-1) || (bb->op_bytes[1] == idx)? R_NEW0 (RCmdJavaCPResult): NULL;
				if (cp_res) {
					cp_res->idx = bb->op_bytes[1];
				}
				break;
			case 0x13:
			case 0x14:
				cp_res = (idx == (ut16)-1) || (R_BIN_JAVA_USHORT (bb->op_bytes, 1) == idx)? R_NEW0 (RCmdJavaCPResult): NULL;
				if (cp_res) {
					cp_res->idx = R_BIN_JAVA_USHORT (bb->op_bytes, 1);
				}
				break;
			}
			if (cp_res) {
				cp_res->addr = bb->addr;
				cp_res->obj = r_bin_java_get_item_from_cp (obj, cp_res->idx);
				r_list_append (find_list, cp_res);
			}
		}
	}
	if (idx == (ut16)-1) {
		r_list_foreach (find_list, iter, cp_res) {
			const char *t = ((RBinJavaCPTypeMetas *)cp_res->obj->metas->type_info)->name;
			r_cons_printf (core->cons, "@0x%" PFMT64x " idx = %d Type = %s\n", cp_res->addr, cp_res->idx, t);
		}

	} else {
		r_list_foreach (find_list, iter, cp_res) {
			r_cons_printf (core->cons, "@0x%" PFMT64x "\n", cp_res->addr);
		}
	}
	r_list_free (find_list);
	return true;
}

static bool r_cmd_java_handle_field_info(RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	R_LOG_DEBUG ("Function call made: %s", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + FIELD_INFO_IDX);
		return true;
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = r_cmd_java_get_input_num_value (core, cmd + 1);
	}

	switch (*(cmd)) {
	case 'c': return r_cmd_java_print_field_num_name (core, obj);
	case 's': return r_cmd_java_print_field_summary (obj, idx);
	case 'n': return r_cmd_java_print_field_name (core, obj, idx);
	}
	R_LOG_DEBUG ("Command is (%s)", cmd);
	eprintf ("[-] r_cmd_java: invalid command syntax.\n");
	r_cmd_java_print_cmd_help (JAVA_CMDS + FIELD_INFO_IDX);
	return false;
}

static bool r_cmd_java_handle_method_info(RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	R_LOG_DEBUG ("Command is (%s)", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return true;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + METHOD_INFO_IDX);
		return false;
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = r_cmd_java_get_input_num_value (core, cmd + 1);
	}

	switch (*(cmd)) {
	case 'c': return r_cmd_java_print_method_num_name (core, obj);
	case 's': return r_cmd_java_print_method_summary (obj, idx);
	case 'n': return r_cmd_java_print_method_name (core, obj, idx);
	}

	R_LOG_DEBUG ("Command is (%s)", cmd);
	eprintf ("[-] r_cmd_java: invalid command syntax.\n");
	r_cmd_java_print_cmd_help (JAVA_CMDS + METHOD_INFO_IDX);
	return false;
}

static bool r_cmd_java_handle_calc_class_sz(RCore *core, const char *cmd) {
	int res = false;
	ut64 sz = UT64_MAX;
	ut64 addr = UT64_MAX;
	ut64 res_size = UT64_MAX,
	     cur_fsz = r_io_fd_size (core->io, core->io->desc->fd);
	ut8 *tbuf, *buf = NULL;
	ut32 init_size = (1 << 16);
	const char *p = cmd? r_cmd_java_consumetok (cmd, ' ', -1): NULL;
	addr = p && *p && r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): UT64_MAX;

	// TODO add a size parameter to the command to skip the guessing part.

	if (addr != UT64_MAX && sz == UT64_MAX) {
		R_LOG_DEBUG ("Function call made: %s", cmd);
		R_LOG_DEBUG ("Attempting to calculate class file size @ : 0x%" PFMT64x, addr);
		sz = cur_fsz < init_size? cur_fsz: init_size;
		while (sz <= cur_fsz) {
			tbuf = realloc (buf, sz);
			if (!tbuf) {
				eprintf ("Memory allocation failed.\n");
				free (buf);
				break;
			}
			buf = tbuf;
			ut64 r_sz = r_io_read_at (core->io, addr, buf, sz)? sz: 0LL;
			// check the return read on the read
			if (r_sz == 0) {
				break;
			}
			res_size = r_bin_java_calc_class_size (buf, sz);
			// if the data buffer contains a class starting
			// at address, then the res_size will be the size
			// if the r_sz is less than the sz, then we are near
			// the end of the core buffer, and there is no need
			// to continue trying to find the class size.
			if (res_size != UT64_MAX ||
				r_sz < sz) {
				res = r_sz < sz? false: true;
				free (buf);
				break;
			} else {
				sz += (1 << 16);
			}
		}
		if (res) {
			r_cons_printf (core->cons, "%" PFMT64d, res_size);
		} else {
			r_cons_printf (core->cons, "-1\n");
		}

		//snprintf (cmd_buf, 50, fmt, num_acc_flag, addr);
		//res = r_core_cmd0(core, y);
	} else {
		r_cmd_java_print_cmd_help (JAVA_CMDS + CALC_SZ_IDX);
	}
	return true;
}

static bool r_cmd_java_handle_isvalid(RCore *core, const char *cmd) {
	int res = false;
	ut64 res_size = UT64_MAX;
	ut8 *tbuf, *buf = NULL;
	ut32 cur_fsz = r_io_fd_size (core->io, core->io->desc->fd);
	ut64 sz = UT64_MAX;
	const char *p = cmd? r_cmd_java_consumetok (cmd, ' ', -1): NULL;
	ut64 addr = UT64_MAX;
	addr = p && *p && r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): UT64_MAX;

	// TODO add a size parameter to the command to skip the guessing part.

	if (addr != UT64_MAX && sz == UT64_MAX) {
		R_LOG_DEBUG ("Function call made: %s", cmd);
		R_LOG_DEBUG ("Attempting to calculate class file size @ : 0x%" PFMT64x, addr);

		while (sz <= cur_fsz) {
			tbuf = realloc (buf, sz);
			if (!tbuf) {
				eprintf ("Memory allocation failed.\n");
				free (buf);
				break;
			}
			buf = tbuf;
			ut64 r_sz = r_io_read_at (core->io, addr, buf, sz)? sz: 0LL;
			// check the return read on the read
			if (r_sz == 0) {
				break;
			}
			res_size = r_bin_java_calc_class_size (buf, sz);
			// if the data buffer contains a class starting
			// at address, then the res_size will be the size
			// if the r_sz is less than the sz, then we are near
			// the end of the core buffer, and there is no need
			// to continue trying to find the class size.
			if (res_size != UT64_MAX ||
				r_sz < sz) {
				res = r_sz < sz? false: true;
				free (buf);
				break;
			} else {
				sz <<= 1;
			}
		}
		r_cons_printf (core->cons, "%s\n", r_str_bool (res));
	} else {
		r_cmd_java_print_cmd_help (JAVA_CMDS + ISVALID_IDX);
	}
	return true;
}

static bool r_cmd_java_resolve_cp_idx(RCore *core, RBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		char *str = r_bin_java_resolve_without_space (obj, idx);
		r_cons_println (core->cons, str);
		free (str);
	}
	return true;
}

static bool r_cmd_java_handle_resolve_cp(RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	char c_type = cmd && *cmd? *cmd: 0;
	RBinJavaObj *obj = r_cmd_java_get_bin_obj (anal);
	ut32 idx = r_cmd_java_get_input_num_value (core, cmd + 2);
	R_LOG_DEBUG ("Function call made: %s", cmd);
	R_LOG_DEBUG ("Ctype: %d (%c) RBinJavaObj points to: %p and the idx is (%s): %d", c_type, c_type, obj, cmd + 2, idx);
	int res = false;
	if (idx > 0 && obj) {
		switch (c_type) {
		case 't': // r_cmd_java_resolve_cp_type (obj, idx);
			{
				char *str = r_bin_java_resolve_cp_idx_type (obj, idx);
				r_cons_println (core->cons, str);
				free (str);
			}
			return true;
		case 'c': return r_cmd_java_resolve_cp_idx (core, obj, idx);
		case 'e': // r_cmd_java_resolve_cp_idx_b64 (obj, idx);
			{
				char *str = r_bin_java_resolve_b64_encode (obj, idx);
				r_cons_println (core->cons, str);
				free (str);
			}
			return true;
		case 'a': // r_cmd_java_resolve_cp_address (core, obj, idx);
			{
				ut64 addr = r_bin_java_resolve_cp_idx_address (obj, idx);
				if (addr == UT64_MAX) {
					R_LOG_ERROR ("Unable to resolve CP Object @ index: 0x%04x", idx);
				} else {
					r_cons_printf (core->cons, "0x%" PFMT64x "\n", addr);
				}
			}
			return true;
		case 's': // r_cmd_java_resolve_cp_summary (obj, idx);
			{
				r_bin_java_resolve_cp_idx_print_summary (obj, idx);
			}
			return true;
		case 'k': // return r_cmd_java_resolve_cp_to_key (obj, idx);
			{
				char *str = r_bin_java_resolve_cp_idx_tostring (obj, idx);
				r_cons_println (core->cons, str);
				free (str);
			}
			return true;

		}
	} else if (obj && c_type == 'g') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			ut64 addr = r_bin_java_resolve_cp_idx_address (obj, idx);
			char *str = r_bin_java_resolve_cp_idx_type (obj, idx);
			r_cons_printf (core->cons, "CP_OBJ Type %d =  %s @ 0x%" PFMT64x "\n", idx, str, addr);
			free (str);
		}
		res = true;
	} else if (obj && c_type == 'd') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			r_bin_java_resolve_cp_idx_print_summary (obj, idx);
		}
		res = true;
	} else {
		if (!obj) {
			eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		} else {
			eprintf ("[-] r_cmd_java: invalid cp index given, must idx > 1.\n");
			r_cmd_java_print_cmd_help (JAVA_CMDS + RESOLVE_CP_IDX);
		}
		res = true;
	}
	return res;
}

static bool r_cmd_java_get_all_access_flags_value(RCore *core, const char *cmd) {
	RList *the_list = NULL;
	RListIter *iter = NULL;
	char *str = NULL;

	switch (*cmd) {
	case 'f': the_list = retrieve_all_field_access_string_and_value (); break;
	case 'm': the_list = retrieve_all_method_access_string_and_value (); break;
	case 'c': the_list = retrieve_all_class_access_string_and_value (); break;
	}
	if (!the_list) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + CALC_FLAGS_IDX);
		return false;
	}
	switch (*(cmd)) {
	case 'f': r_cons_printf (core->cons, "[=] Fields Access Flags List\n"); break;
	case 'm': r_cons_printf (core->cons, "[=] Methods Access Flags List\n"); break;
	case 'c':
		r_cons_printf (core->cons, "[=] Class Access Flags List\n");
		break;
	}

	r_list_foreach (the_list, iter, str) {
		r_cons_println (core->cons, str);
	}
	r_list_free (the_list);
	return true;
}

static bool r_cmd_java_handle_calc_flags(RCore *core, const char *cmd) {
	R_LOG_DEBUG ("Function call made: %s", cmd);
	int res = false;

	switch (*(cmd)) {
	case 'f': return r_cmd_java_print_field_access_flags_value (core, cmd + 2);
	case 'm': return r_cmd_java_print_method_access_flags_value (core, cmd + 2);
	case 'c': return r_cmd_java_print_class_access_flags_value (core, cmd + 2);
	}

	if (*(cmd) == 'l') {
		const char *lcmd = cmd[1] == ' '? cmd + 2: cmd + 1;
		R_LOG_DEBUG ("Seeing %s and accepting %s", cmd, lcmd);
		switch (*(lcmd)) {
		case 'f':
		case 'm':
		case 'c': res = r_cmd_java_get_all_access_flags_value (core, lcmd); break;
		}
		// Just print them all out
		if (res == false) {
			r_cmd_java_get_all_access_flags_value (core, "c");
			r_cmd_java_get_all_access_flags_value (core, "m");
			res = r_cmd_java_get_all_access_flags_value (core, "f");
		}
	}
	if (res == false) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + CALC_FLAGS_IDX);
		res = true;
	}
	return res;
}

static bool r_cmd_java_handle_flags_str(RCore *core, const char *cmd) {

	int res = false;
	ut32 flag_value = -1;
	const char f_type = cmd? *cmd: 0;
	const char *p = cmd? cmd + 2: NULL;
	char *flags_str = NULL;

	R_LOG_DEBUG ("r_cmd_java_handle_flags_str: ftype = %c, idx = %s", f_type, p);
	if (p) {
		flag_value = r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): (ut32)-1;
	}

	if (p && f_type) {
		switch (f_type) {
		case 'm': flags_str = r_bin_java_accessflags_tostring ((ut32)flag_value, JAVA_FLAG_TYPE_METHOD); break;
		case 'f': flags_str = r_bin_java_accessflags_tostring ((ut32)flag_value, JAVA_FLAG_TYPE_FIELD); break;
		case 'c': flags_str = r_bin_java_accessflags_tostring ((ut32)flag_value, JAVA_FLAG_TYPE_CLASS); break;
		default: flags_str = NULL;
		}
	}

	if (flags_str) {
		switch (f_type) {
		case 'm': r_cons_printf (core->cons, "Method Access Flags String: "); break;
		case 'f': r_cons_printf (core->cons, "Field Access Flags String: "); break;
		case 'c': r_cons_printf (core->cons, "Class Access Flags String: "); break;
		}
		r_cons_println (core->cons, flags_str);
		free (flags_str);
		res = true;
	}
	if (res == false) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + FLAGS_STR_IDX);
		res = true;
	}
	return res;
}

static bool r_cmd_java_handle_flags_str_at(RCore *core, const char *cmd) {
	int res = false;
	ut32 flag_value = -1;
	const char f_type = cmd? *r_cmd_java_consumetok (cmd, ' ', -1): 0;
	const char *p = cmd? cmd + 2: NULL;
	char *flags_str = NULL;

	R_LOG_DEBUG ("r_cmd_java_handle_flags_str_at: ftype = 0x%02x, idx = %s", f_type, p);
	if (p) {
		flag_value = 0;
		ut64 cur_offset = core->addr;
		ut64 flag_value_addr = r_cmd_java_is_valid_input_num_value (core, p)
			? r_cmd_java_get_input_num_value (core, p): UT64_MAX;
		r_io_read_at (core->io, flag_value_addr, (ut8 *)&flag_value, 2);
		R_LOG_DEBUG ("r_cmd_java_handle_flags_str_at: read = 0x%04x", flag_value);
		if (cur_offset != core->addr) {
			r_core_seek (core, cur_offset - 2, true);
		}
		flag_value = R_BIN_JAVA_USHORT (((ut8 *)&flag_value), 0);
	}

	if (p && f_type) {
		switch (f_type) {
		case 'm': flags_str = r_bin_java_accessflags_tostring ((ut32)flag_value, JAVA_FLAG_TYPE_METHOD); break;
		case 'f': flags_str = r_bin_java_accessflags_tostring ((ut32)flag_value, JAVA_FLAG_TYPE_FIELD); break;
		case 'c': flags_str = r_bin_java_accessflags_tostring ((ut32)flag_value, JAVA_FLAG_TYPE_CLASS); break;
		default: flags_str = NULL;
		}
	}

	if (flags_str) {
		switch (f_type) {
		case 'm': r_cons_printf (core->cons, "Method Access Flags String: "); break;
		case 'f': r_cons_printf (core->cons, "Field Access Flags String: "); break;
		case 'c': r_cons_printf (core->cons, "Class Access Flags String: "); break;
		}
		r_cons_println (core->cons, flags_str);
		free (flags_str);
		res = true;
	}
	if (res == false) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + FLAGS_STR_IDX);
		res = true;
	}
	return res;
}

static char r_cmd_java_is_valid_java_mcf(char b) {
	char c = 0;
	switch (b) {
	case 'c':
	case 'f':
	case 'm': c = b;
	}
	return c;
}

static bool r_cmd_java_handle_set_flags(RCore *core, const char *input) {
	//#define SET_ACC_FLAGS_ARGS "< c | m | f> <addr> <d | <s <flag value separated by space> >"
	const char *p = r_cmd_java_consumetok (input, ' ', -1);
	ut64 addr = p && r_cmd_java_is_valid_input_num_value (core, p)
		? r_cmd_java_get_input_num_value (core, p)
		: UT64_MAX;
	p = r_cmd_java_strtok (core, p + 1, ' ', -1);
	if (R_STR_ISEMPTY (p)) {
		r_cmd_java_print_cmd_help (JAVA_CMDS + SET_ACC_FLAGS_IDX);
		return true;
	}
	p++;
	const char f_type = r_cmd_java_is_valid_java_mcf (*p);

	int flag_value = r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): -1;

	if (flag_value == 16 && f_type == 'f') {
		flag_value = -1;
	}
	R_LOG_DEBUG ("Converting %s to flags", p);
	if (p) {
		p += 2;
	}
	if (flag_value == -1) {
		flag_value = r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): -1;
	}
	bool res = false;
	if (!input) {
		eprintf ("[-] r_cmd_java: no address provided .\n");
		res = true;
	} else if (addr == UT64_MAX) {
		eprintf ("[-] r_cmd_java: no address provided .\n");
		res = true;
	} else if (f_type == '?' && flag_value == -1) {
		eprintf ("[-] r_cmd_java: no flag type provided .\n");
		res = true;
	}

	if (res) {
		r_cmd_java_print_cmd_help (JAVA_CMDS + SET_ACC_FLAGS_IDX);
		return res;
	}

	R_LOG_DEBUG ("Writing ftype '%c' to 0x%" PFMT64x ", %s", f_type, addr, p);

	// handling string based access flags (otherwise skip ahead)
	R_LOG_DEBUG ("Converting %s to flags", p);
	if (f_type && flag_value != -1) {
		switch (f_type) {
		case 'f': flag_value = r_bin_java_calculate_field_access_value (p); break;
		case 'm': flag_value = r_bin_java_calculate_method_access_value (p); break;
		case 'c': flag_value = r_bin_java_calculate_class_access_value (p); break;
		default: flag_value = -1;
		}
	}
	R_LOG_DEBUG ("Current args: (flag_value: 0x%04x addr: 0x%" PFMT64x ")", flag_value, addr);
	if (flag_value != -1) {
		res = r_cmd_java_set_acc_flags (core, addr, ((ut16)flag_value) & 0xffff);
		R_LOG_DEBUG ("Writing 0x%04x to 0x%" PFMT64x ": %d", flag_value, addr, res);
	} else {
		eprintf ("[-] r_cmd_java: invalid flag value or type provided .\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS + SET_ACC_FLAGS_IDX);
		res = true;
	}
	return res;
}

static bool r_cmd_java_call(RCorePluginSession *cps, const char *input) {
	int res = false;
	ut32 i = 0;
	if (!r_str_startswith (input, "java")) {
		return false;
	}
	RCore *core = cps->core;
	if (input[4] != ' ') {
		return r_cmd_java_handle_help (core, input);
	}
	for (; JAVA_CMDS[i].name; i++) {
		//IFDBG r_cons_printf (core->cons, "Checking cmd: %s %d %s\n", JAVA_CMDS[i].name, JAVA_CMDS[i].name_len, p);
		R_LOG_DEBUG ("Checking cmd: %s %d", JAVA_CMDS[i].name,
			strncmp (input + 5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len));
		if (!strncmp (input + 5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len)) {
			const char *cmd = input + 5 + JAVA_CMDS[i].name_len;
			if (*cmd && *cmd == ' ') {
				cmd++;
			}
			//IFDBG r_cons_printf (core->cons, "Executing cmd: %s (%s)\n", JAVA_CMDS[i].name, cmd+5+JAVA_CMDS[i].name_len );
			res = JAVA_CMDS[i].handler (core, cmd);
			break;
		}
	}
	if (!res) {
		return r_cmd_java_handle_help (core, input);
	}
	return true;
}

static bool r_cmd_java_print_method_definitions(RCore *core, RBinJavaObj *obj) {
	RList *the_list = r_bin_java_get_method_definitions (obj);
	RList *off_list = r_bin_java_get_method_offsets (obj);
	char *str = NULL;
	ut32 idx = 0, end = r_list_length (the_list);

	while (idx < end) {
		ut64 *addr = r_list_get_n (off_list, idx);
		str = r_list_get_n (the_list, idx);
		r_cons_printf (core->cons, "%s; // @0x%04" PFMT64x "\n", str, *addr);
		idx++;
	}

	r_list_free (the_list);
	r_list_free (off_list);
	return true;
}

static bool r_cmd_java_print_field_definitions(RCore *core, RBinJavaObj *obj) {
	RList *the_list = r_bin_java_get_field_definitions (obj),
	      *off_list = r_bin_java_get_field_offsets (obj);
	char *str = NULL;
	ut32 idx = 0, end = r_list_length (the_list);

	while (idx < end) {
		ut64 *addr = r_list_get_n (off_list, idx);
		str = r_list_get_n (the_list, idx);
		r_cons_printf (core->cons, "%s; // @0x%04" PFMT64x "\n", str, *addr);
		idx++;
	}

	r_list_free (the_list);
	r_list_free (off_list);
	return true;
}

static bool r_cmd_java_print_import_definitions(RCore *core, RBinJavaObj *obj) {
	RList *the_list = r_bin_java_get_import_definitions (obj);
	char *str = NULL;
	RListIter *iter;
	r_list_foreach (the_list, iter, str) {
		r_cons_printf (core->cons, "import %s;\n", str);
	}
	r_list_free (the_list);
	return true;
}

static bool r_cmd_java_print_all_definitions(RCore *core) {
	RList *obj_list = r_cmd_java_get_bin_obj_list (core->anal);
	RListIter *iter;
	RBinJavaObj *obj;

	if (!obj_list) {
		return 1;
	}
	r_list_foreach (obj_list, iter, obj) {
		r_cmd_java_print_class_definitions (core, obj);
	}
	r_list_free (obj_list);
	return true;
}

static bool r_cmd_java_print_json_definitions(RCore *core, RBinJavaObj *obj) {
	char *s = r_bin_java_get_bin_obj_json (obj);
	r_cons_println (core->cons, s);
	free (s);
	return true;
}

static bool r_cmd_java_print_class_definitions(RCore *core, RBinJavaObj *obj) {
	RList *the_fields = r_bin_java_get_field_definitions (obj),
	      *the_methods = r_bin_java_get_method_definitions (obj),
	      *the_imports = r_bin_java_get_import_definitions (obj),
	      *the_moffsets = r_bin_java_get_method_offsets (obj),
	      *the_foffsets = r_bin_java_get_field_offsets (obj);

	char *class_name = r_bin_java_get_this_class_name (obj);
	char *str = NULL;

	r_cmd_java_print_import_definitions (core, obj);
	r_cons_printf (core->cons, "\nclass %s { // @0x%04" PFMT64x "\n", class_name, obj->loadaddr);

	if (the_fields && the_foffsets && r_list_length (the_fields) > 0) {
		r_cons_printf (core->cons, "\n  // Fields defined in the class\n");
		ut32 idx = 0, end = r_list_length (the_fields);

		while (idx < end) {
			ut64 *addr = r_list_get_n (the_foffsets, idx);
			str = r_list_get_n (the_fields, idx);
			r_cons_printf (core->cons, "  %s; // @0x%04" PFMT64x "\n", str, *addr);
			idx++;
		}
	}

	if (the_methods && the_moffsets && r_list_length (the_methods) > 0) {
		r_cons_printf (core->cons, "\n  // Methods defined in the class\n");
		ut32 idx = 0, end = r_list_length (the_methods);

		while (idx < end) {
			ut64 *addr = r_list_get_n (the_moffsets, idx);
			str = r_list_get_n (the_methods, idx);
			r_cons_printf (core->cons, "  %s; // @0x%04" PFMT64x "\n", str, *addr);
			free (str);
			idx++;
		}
	}
	r_cons_printf (core->cons, "}\n");

	r_list_free (the_imports);
	r_list_free (the_fields);
	r_list_free (the_methods);
	r_list_free (the_foffsets);
	r_list_free (the_moffsets);

	free (class_name);
	return true;
}

static RList *r_cmd_java_get_bin_obj_list(RAnal *anal) {
	RBinJavaObj *bin_obj = (RBinJavaObj *)r_cmd_java_get_bin_obj (anal);
	// See libr/bin/p/bin_java.c to see what is happening here.  The original intention
	// was to use a shared global db variable from shlr/java/class.c, but the
	// BIN_OBJS_ADDRS variable kept getting corrupted on Mac, so I (deeso) switched the
	// way the access to the db was taking place by using the bin_obj as a proxy back
	// to the BIN_OBJS_ADDRS which is instantiated in libr/bin/p/bin_java.c
	// not the easiest way to make sausage, but its getting made.
	return r_bin_java_get_bin_obj_list_thru_obj (bin_obj);
}

static RBinJavaObj *r_cmd_java_get_bin_obj(RAnal *anal) {
	RBin *b;
	int is_java;
	RBinPlugin *plugin;
	if (!anal || !anal->binb.bin) {
		return NULL;
	}
	b = anal->binb.bin;
	if (!b->cur || !b->cur->bo) {
		return NULL;
	}
	plugin = b->cur->bo->plugin;
	is_java = (plugin && strcmp (plugin->meta.name, "java") == 0)? 1: 0;
	return is_java? b->cur->bo->bin_obj: NULL;
}

static bool r_cmd_java_is_valid_input_num_value(RCore *core, const char *input_value) {
	ut64 value = input_value? r_num_math (core->num, input_value): 0;
	return !(value == 0 && input_value && *input_value == '0');
}

static ut64 r_cmd_java_get_input_num_value(RCore *core, const char *input_value) {
	ut64 value = input_value? r_num_math (core->num, input_value): 0;
	return value;
}

static bool r_cmd_java_print_class_access_flags_value(RCore *core, const char *flags) {
	ut16 result = r_bin_java_calculate_class_access_value (flags);
	r_cons_printf (core->cons, "Access Value for %s = 0x%04x\n", flags, result);
	return true;
}
static bool r_cmd_java_print_field_access_flags_value(RCore *core, const char *flags) {
	ut16 result = r_bin_java_calculate_field_access_value (flags);
	r_cons_printf (core->cons, "Access Value for %s = 0x%04x\n", flags, result);
	return true;
}
static bool r_cmd_java_print_method_access_flags_value(RCore *core, const char *flags) {
	ut16 result = r_bin_java_calculate_method_access_value (flags);
	r_cons_printf (core->cons, "Access Value for %s = 0x%04x\n", flags, result);
	return true;
}

static bool r_cmd_java_set_acc_flags(RCore *core, ut64 addr, ut16 num_acc_flag) {
	num_acc_flag = R_BIN_JAVA_USHORT (((ut8 *)&num_acc_flag), 0);
	int res = r_core_write_at (core, addr, (const ut8 *)&num_acc_flag, 2);
	if (!res) {
		eprintf ("[X] r_cmd_java_set_acc_flags: Failed to write.\n");
		return res;
	}
	res = true;
	// R_LOG_DEBUG ("Executed cmd: %s == %d", cmd_buf, res);
	return res;
}
static bool r_cmd_java_print_field_num_name(RCore *core, RBinJavaObj *obj) {
	RList *the_list = r_bin_java_get_num_names (obj, false);
	char *str;
	RListIter *iter = NULL;
	r_list_foreach (the_list, iter, str) {
		r_cons_println (core->cons, str);
	}
	r_list_free (the_list);
	return true;
}

static bool r_cmd_java_print_method_num_name(RCore *core, RBinJavaObj *obj) {
	RList *the_list = r_bin_java_get_num_names (obj, true);
	char *str;
	RListIter *iter = NULL;
	r_list_foreach (the_list, iter, str) {
		r_cons_println (core->cons, str);
	}
	r_list_free (the_list);
	return true;
}

static bool r_cmd_java_print_field_summary(RBinJavaObj *obj, ut16 idx) {
	int res = r_bin_java_print_idx_summary (obj, idx, false);
	if (res == false) {
		R_LOG_ERROR ("Field or Method @ index (%d) not found in the RBinJavaObj", idx);
		res = true;
	}
	return res;
}

#if 0
static bool UNUSED_FUNCTION(r_cmd_java_print_field_count)(RBinJavaObj *obj) {
	ut32 res = r_bin_java_get_count (obj, false);
	r_cons_printf ("%d\n", res);
	r_cons_flush ();
	return true;
}

static bool _(r_cmd_java_print_method_count)(RBinJavaObj *obj) {
	ut32 res = r_bin_java_get_count (obj, true);
	r_cons_printf ("%d\n", res);
	r_cons_flush ();
	return true;
}
#endif

static bool r_cmd_java_print_field_name(RCore *core, RBinJavaObj *obj, ut16 idx) {
	char *res = r_bin_java_get_name (obj, idx, false);
	if (res) {
		r_cons_println (core->cons, res);
	} else {
		R_LOG_ERROR ("Field or Method @ index (%d) not found in the RBinJavaObj", idx);
	}
	free (res);
	return true;
}

static bool r_cmd_java_print_method_summary(RBinJavaObj *obj, ut16 idx) {
	int res = r_bin_java_print_idx_summary (obj, idx, true);
	if (res == false) {
		R_LOG_ERROR ("Field or Method @ index (%d) not found in the RBinJavaObj", idx);
		res = true;
	}
	return res;
}

static bool r_cmd_java_print_method_name(RCore *core, RBinJavaObj *obj, ut16 idx) {
	char *res = r_bin_java_get_name (obj, idx, true);
	if (res) {
		r_cons_println (core->cons, res);
	} else {
		R_LOG_ERROR ("Field or Method @ index (%d) not found in the RBinJavaObj", idx);
	}
	free (res);
	return true;
}

static bool r_cmd_java_handle_yara_code_extraction_refs(RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = anal? (RBinJavaObj *)r_cmd_java_get_bin_obj (anal): NULL;
	const char *p = input? r_cmd_java_consumetok (input, ' ', -1): NULL, *n = NULL;
	ut64 addr = -1, count = -1;
	int res = false;
	char *name = NULL;

	if (!bin) {
		return res;
	}
	if (!anal || !anal->fcns || r_list_length (anal->fcns) == 0) {
		R_LOG_ERROR ("Unable to access the current analysis, perform 'af' for function analysis");
		return true;
	}
	if (!p) {
		return res;
	}

	n = *p? r_cmd_java_strtok (core, p, ' ', -1): NULL;
	name = n && p && p != n? malloc (n - p + 2): NULL;

	if (!name) {
		return res;
	}

	memset (name, 0, n - p);
	memcpy (name, p, n - p);

	p = r_cmd_java_strtok (core, p, ' ', -1);
	addr = p && *p && r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): UT64_MAX;

	p = r_cmd_java_strtok (core, p, ' ', -1);
	count = p && *p && r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): UT64_MAX;

	if (name && count != UT64_MAX && addr != UT64_MAX) {
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

static bool r_cmd_java_handle_insert_method_ref(RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = anal? (RBinJavaObj *)r_cmd_java_get_bin_obj (anal): NULL;
	const char *p = input? r_cmd_java_consumetok (input, ' ', -1): NULL, *n = NULL;
	char *classname = NULL, *name = NULL, *descriptor = NULL;
	ut32 cn_sz = 0, n_sz = 0, d_sz = 0;

	if (!bin) {
		return false;
	}
	if (!anal || !anal->fcns || r_list_length (anal->fcns) == 0) {
		eprintf ("Unable to access the current analysis, perform 'af' for function analysis.\n");
		return true;
	}
	if (!p) {
		return false;
	}

	n = p && *p? r_cmd_java_strtok (core, p, ' ', -1): NULL;
	classname = n && p && p != n? malloc (n - p + 1): NULL;
	cn_sz = n && p? n - p + 1: 0;
	if (!classname) {
		return false;
	}

	snprintf (classname, cn_sz, "%s", p);
	p = n + 1;
	n = p && *p? r_cmd_java_strtok (core, p, ' ', -1): NULL;
	name = n && p && p != n? malloc (n - p + 1): NULL;
	n_sz = n && p? n - p + 1: 0;
	if (!name) {
		free (classname);
		return false;
	}
	snprintf (name, n_sz, "%s", p);

	p = n + 1;
	n = p && *p? r_cmd_java_strtok (core, p, ' ', -1): NULL;
	if (n) {
		descriptor = n && p && p != n? malloc (n - p + 1): NULL;
		d_sz = n - p + 1;
	} else if (p && *p) {
		d_sz = strlen (p) + 1;
		descriptor = d_sz > 1? malloc (d_sz): NULL;
	}

	if (!descriptor) {
		free (classname);
		free (name);
		return false;
	}
	snprintf (descriptor, d_sz, "%s", p);

	r_cons_printf (core->cons, "Would be adding class name:%s, name: %s, descriptor: %s\n", classname, name, descriptor);
	free (classname);
	free (name);
	free (descriptor);
	return true;
}

static bool r_cmd_java_handle_print_exceptions(RCore *core, const char *input) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *bin = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	RListIter *exc_iter = NULL, *methods_iter = NULL;
	RBinJavaField *method;
	RBinJavaExceptionEntry *exc_entry;

	const char *p = input? r_cmd_java_consumetok (input, ' ', -1): NULL;
	ut64 func_addr = p && *p && r_cmd_java_is_valid_input_num_value (core, p)? r_cmd_java_get_input_num_value (core, p): -1;

	if (!bin) {
		return false;
	}

	r_list_foreach (bin->methods_list, methods_iter, method) {
		ut64 start = r_bin_java_get_method_start (bin, method);
		ut64 end = r_bin_java_get_method_end (bin, method);
		ut8 do_this_one = start <= func_addr && func_addr <= end;
		RList *exc_table = NULL;
		if (func_addr == UT64_MAX) do_this_one = 1;
		if (!do_this_one) {
			continue;
		}
		exc_table = r_bin_java_get_method_exception_table_with_addr (bin, start);

		if (r_list_length (exc_table) == 0) {
			r_cons_printf (core->cons, " Exception table for %s @ 0x%"PFMT64x":\n", method->name, start);
			r_cons_printf (core->cons, " [ NONE ]\n");
		} else {
			r_cons_printf (core->cons, " Exception table for %s (%d entries) @ 0x%"PFMT64x":\n", method->name,
				r_list_length (exc_table) , start);
		}
		r_list_foreach (exc_table, exc_iter, exc_entry) {
			char *class_info = r_bin_java_resolve_without_space (bin, exc_entry->catch_type);
			r_cons_printf (core->cons, "  Catch Type: %d, %s @ 0x%"PFMT64x"\n", exc_entry->catch_type,
				class_info, exc_entry->file_offset+6);
			r_cons_printf (core->cons, "  Start PC: (0x%x) 0x%"PFMT64x" @ 0x%"PFMT64x"\n",
				exc_entry->start_pc, exc_entry->start_pc+start, exc_entry->file_offset);
			r_cons_printf (core->cons, "  End PC: (0x%x) 0x%"PFMT64x" 0x%"PFMT64x"\n",
				exc_entry->end_pc, exc_entry->end_pc+start, exc_entry->file_offset + 2);
			r_cons_printf (core->cons, "  Handler PC: (0x%x) 0x%"PFMT64x" 0x%"PFMT64x"\n",
				exc_entry->handler_pc, exc_entry->handler_pc+start, exc_entry->file_offset+4);
			free (class_info);
		}
	}
	return true;
}

RCorePlugin r_core_plugin_java = {
	.meta = {
		.name = "java",
		.author = "dso",
		.desc = "Suite of java commands, java help for more info",
		.license = "Apache-2.0",
	},
	.call = r_cmd_java_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_java,
	.version = R2_VERSION
};
#endif
