/* radare - Apache - Copyright 2014 dso <adam.pridgen@thecoverofnight.com | dso@rice.edu> */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>

#undef R_API
#define R_API static
#include "../../../shlr/java/ops.c"
#include "../../../shlr/java/code.c"
#include "../../../shlr/java/class.c"
//#include "../../../shlr/java/class.h"
#undef R_API
#define R_API

#define DO_THE_DBG 0
#define IFDBG if (DO_THE_DBG)

typedef int (*RCMDJavaCmdHandler) (RCore *core, const char *cmd);

static const char * r_cmd_java_strtok (const char *str1, const char b, size_t len);
static const char * r_cmd_java_consumetok (const char *str1, const char b, size_t len);

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


static int r_cmd_java_print_field_summary (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_print_field_count (RBinJavaObj *obj);
static int r_cmd_java_print_field_name (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_print_method_summary (RBinJavaObj *obj, ut16 idx);
static int r_cmd_java_print_method_count (RBinJavaObj *obj);
static int r_cmd_java_print_method_name (RBinJavaObj *obj, ut16 idx);


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


#define SET_ACC_FLAGS "set_flags"
#define SET_ACC_FLAGS_ARGS "[<addr> <c | m | f> <num_flag_val>] | [<addr> < c | m | f> <flag value separated by space> ]"
#define SET_ACC_FLAGS_DESC "set the access flags attributes for a field or method"
#define SET_ACC_FLAGS_LEN 9
#define SET_ACC_FLAGS_ARG_CNT 2

#define PROTOTYPES "prototypes"
#define PROTOTYPES_ARGS "< a | i | c | m | f>"
#define PROTOTYPES_DESC "print prototypes for all bins, imports only, class, methods, and fields, methods only, or fields only"
#define PROTOTYPES_LEN 10
#define PROTOTYPES_ARG_CNT 1

#define RESOLVE_CP "resolve_cp"
#define RESOLVE_CP_ARGS "< <t | e | c | a> idx>"
#define RESOLVE_CP_DESC "resolve and print cp type or value @ idx. a = address, t = type, c = get value, e = base64 enode the result"
#define RESOLVE_CP_LEN 10
#define RESOLVE_CP_ARG_CNT 2

#define CALC_FLAGS "calc_flags"
#define CALC_FLAGS_ARGS "[ <l <[c|f|m]>> | <c [public,private,static...]>  | <f [public,private,static...]> | <m c [public,private,static...]>]"
#define CALC_FLAGS_DESC "output a value for the given access flags: l = list all flags, c = class, f = field, m = method"
#define CALC_FLAGS_LEN 10
#define CALC_FLAGS_ARG_CNT 2

#define FLAGS_STR_AT "flags_str_at"
#define FLAGS_STR_AT_ARGS "[<c | f | m> <addr>]"
#define FLAGS_STR_AT_DESC "output a string value for the given access flags @ addr: c = class, f = field, m = method"
#define FLAGS_STR_AT_LEN 11
#define FLAGS_STR_AT_ARG_CNT 2

#define FLAGS_STR "flags_str"
#define FLAGS_STR_ARGS "[<c | f | m> <acc_flags_value>]"
#define FLAGS_STR_DESC "output a string value for the given access flags number: c = class, f = field, m = method"
#define FLAGS_STR_LEN 9
#define FLAGS_STR_ARG_CNT 2

#define METHOD_INFO "m_info"
#define METHOD_INFO_ARGS "[<[c | <s idx> | <n idx>>]"
#define METHOD_INFO_DESC "output method information at index : c = count, s = dump of all meta-data, n = method"
#define METHOD_INFO_LEN 6
#define METHOD_INFO_ARG_CNT 2


#define FIELD_INFO "f_info"
#define FIELD_INFO_ARGS "[<[c | <s idx> | <n idx>>]"
#define FIELD_INFO_DESC "output method information at index : c = count, s = dump of all meta-data, n = method"
#define FIELD_INFO_LEN 6
#define FIELD_INFO_ARG_CNT 2

#define HELP "help"
#define HELP_DESC "displays this message"
#define HELP_ARGS "NONE"
#define HELP_LEN 4
#define HELP_ARG_CNT 0


typedef struct r_cmd_java_cms_t {
	const char *name;
	const char *args;
	const char *desc;
	const ut32 arg_cnt;
	const ut32 name_len;
	RCMDJavaCmdHandler handler;
} RCmdJavaCmd;


static RCmdJavaCmd JAVA_CMDS[] = {
	{HELP, HELP_ARGS, HELP_DESC, HELP_ARG_CNT, HELP_LEN, r_cmd_java_handle_help},
	{SET_ACC_FLAGS, SET_ACC_FLAGS_ARGS, SET_ACC_FLAGS_DESC, SET_ACC_FLAGS_ARG_CNT, SET_ACC_FLAGS_LEN, r_cmd_java_handle_set_flags},
	{PROTOTYPES, PROTOTYPES_ARGS, PROTOTYPES_DESC, PROTOTYPES_ARG_CNT, PROTOTYPES_LEN, r_cmd_java_handle_prototypes},
	{RESOLVE_CP, RESOLVE_CP_ARGS, RESOLVE_CP_DESC, RESOLVE_CP_ARG_CNT, RESOLVE_CP_LEN, r_cmd_java_handle_resolve_cp},
	{CALC_FLAGS, CALC_FLAGS_ARGS, CALC_FLAGS_DESC, CALC_FLAGS_ARG_CNT, CALC_FLAGS_LEN, r_cmd_java_handle_calc_flags},
	{FLAGS_STR_AT, FLAGS_STR_AT_ARGS, FLAGS_STR_AT_DESC, FLAGS_STR_AT_ARG_CNT, FLAGS_STR_AT_LEN, r_cmd_java_handle_flags_str_at},
	{FLAGS_STR, FLAGS_STR_ARGS, FLAGS_STR_DESC, FLAGS_STR_ARG_CNT, FLAGS_STR_LEN, r_cmd_java_handle_flags_str},
	{METHOD_INFO, METHOD_INFO_ARGS, METHOD_INFO_DESC, METHOD_INFO_ARG_CNT, METHOD_INFO_LEN, r_cmd_java_handle_method_info},
	{FIELD_INFO, FIELD_INFO_ARGS, FIELD_INFO_DESC, FIELD_INFO_ARG_CNT, FIELD_INFO_LEN, r_cmd_java_handle_field_info},
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
	END_CMDS = 9,
};

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
	return core->anal;
}

static void r_cmd_java_print_cmd_help (RCmdJavaCmd *cmd) {
	eprintf ("[*] %s %s\n[+]\t %s\n\n", cmd->name, cmd->args, cmd->desc);
}

static int r_cmd_java_handle_help (RCore * core, const char * input) {
	ut32 i = 0;
	eprintf ("\n%s %s\n", r_core_plugin_java.name, r_core_plugin_java.desc);
	eprintf ("[*] Help Format: Command Arguments\n[+]\t Description\n\n");
	for (i = 0; i <END_CMDS; i++)
		r_cmd_java_print_cmd_help (JAVA_CMDS+i);
	return R_TRUE;
}


static int r_cmd_java_handle_prototypes (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return R_TRUE;
	}

	switch (*(cmd)) {
		case 'm': return r_cmd_java_print_method_definitions (obj);
		case 'f': return r_cmd_java_print_field_definitions (obj);
		case 'i': return r_cmd_java_print_import_definitions (obj);
		case 'c': return r_cmd_java_print_class_definitions (obj);
		case 'a': return r_cmd_java_print_all_definitions (anal);
	}
	return R_FALSE;
}


static int r_cmd_java_handle_field_info (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return R_TRUE;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FIELD_INFO_IDX);
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = r_cmd_java_get_input_num_value (core, cmd+2);
	}

	switch (*(cmd)) {
		case 'c': return r_cmd_java_print_field_count (obj);
		case 's': return r_cmd_java_print_field_summary (obj, idx);
		case 'n': return r_cmd_java_print_field_name (obj, idx);
	}
	IFDBG r_cons_printf ("Command is (%s)\n", cmd);
	eprintf ("[-] r_cmd_java: invalid command syntax.\n");
	r_cmd_java_print_cmd_help (JAVA_CMDS+FIELD_INFO_IDX);
	return R_FALSE;
}


static int r_cmd_java_handle_method_info (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	RBinJavaObj *obj = (RBinJavaObj *) r_cmd_java_get_bin_obj (anal);
	IFDBG r_cons_printf ("Command is (%s)\n", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		return R_TRUE;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] r_cmd_java: invalid command syntax.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+METHOD_INFO_IDX);
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = r_cmd_java_get_input_num_value (core, cmd+2);
	}

	switch (*(cmd)) {
		case 'c': return r_cmd_java_print_method_count (obj);
		case 's': return r_cmd_java_print_method_summary (obj, idx);
		case 'n': return r_cmd_java_print_method_name (obj, idx);
	}

	IFDBG r_cons_printf ("Command is (%s)\n", cmd);
	eprintf ("[-] r_cmd_java: invalid command syntax.\n");
	r_cmd_java_print_cmd_help (JAVA_CMDS+METHOD_INFO_IDX);
	return R_FALSE;
}


static int r_cmd_java_handle_resolve_cp (RCore *core, const char *cmd) {
	RAnal *anal = get_anal (core);
	char c_type = cmd && *cmd ? *cmd : 0;
	RBinJavaObj *obj = r_cmd_java_get_bin_obj (anal);
	ut16 idx = r_cmd_java_get_input_num_value (core, cmd+2);
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);
	IFDBG r_cons_printf ("Ctype: %d (%c) RBinJavaObj points to: %p and the idx is (%s): %d\n", c_type, c_type, obj, cmd+2, idx);
	int res = R_FALSE;
	if (idx && obj) {
		switch (c_type) {
			case 't': return r_cmd_java_resolve_cp_type (obj, idx);
			case 'c': return r_cmd_java_resolve_cp_idx (obj, idx);
			case 'e': return r_cmd_java_resolve_cp_idx_b64 (obj, idx);
			case 'a': return r_cmd_java_resolve_cp_address (obj, idx);
			case 's': return r_cmd_java_resolve_cp_summary (obj, idx);
			case 'k': return r_cmd_java_resolve_cp_to_key (obj, idx);
		}
	} else {
		if (!obj) {
			eprintf ("[-] r_cmd_java: no valid java bins found.\n");
		} else {
			eprintf ("[-] r_cmd_java: invalid cp index given, must idx > 1.\n");
			r_cmd_java_print_cmd_help (JAVA_CMDS+RESOLVE_CP_IDX);
		}
		res = R_TRUE;
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
		return R_FALSE;
	}
	switch (*(cmd)) {
		case 'f': r_cons_printf ("[=] Fields Access Flags List\n"); break;
		case 'm': r_cons_printf ("[=] Methods Access Flags List\n"); break;
		case 'c': r_cons_printf ("[=] Class Access Flags List\n");; break;
	}

	r_list_foreach (the_list, iter, str) {
		r_cons_printf ("%s\n", str);
	}
	r_list_free (the_list);
	return R_TRUE;
}

static int r_cmd_java_handle_calc_flags (RCore *core, const char *cmd) {
	IFDBG r_cons_printf ("Function call made: %s\n", cmd);
	int res = R_FALSE;

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
		if (res == R_FALSE) {
			r_cmd_java_get_all_access_flags_value ("c");
			r_cmd_java_get_all_access_flags_value ("m");
			res = r_cmd_java_get_all_access_flags_value ("f");
		}
	}
	if (res == R_FALSE) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+CALC_FLAGS_IDX);
		res = R_TRUE;
	}
	return res;
}

static int r_cmd_java_handle_flags_str (RCore *core, const char *cmd) {

	int res = R_FALSE;
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
		r_cons_printf ("%s\n", flags_str);
		free (flags_str);
		res = R_TRUE;
	}
	if (res == R_FALSE) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FLAGS_STR_IDX);
		res = R_TRUE;
	}
	return res;
}

static int r_cmd_java_handle_flags_str_at (RCore *core, const char *cmd) {

	int res = R_FALSE;
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
		r_cons_printf ("%s\n", flags_str);
		free (flags_str);
		res = R_TRUE;
	}
	if (res == R_FALSE) {
		eprintf ("[-] r_cmd_java: incorrect syntax for the flags calculation.\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+FLAGS_STR_IDX);
		res = R_TRUE;
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

	p = r_cmd_java_strtok (p+1, ' ', -1);
	f_type = r_cmd_java_is_valid_java_mcf (*(++p));

	flag_value = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;

	if (flag_value == 16 && f_type == 'f') {
		flag_value = -1;
	}
	IFDBG r_cons_printf ("Converting %s to flags\n",p);

	if (p) p+=2;
	if (flag_value == -1)
		flag_value = r_cmd_java_is_valid_input_num_value(core, p) ? r_cmd_java_get_input_num_value (core, p) : -1;
	int res = R_FALSE;
	if (!input) {
		eprintf ("[-] r_cmd_java: no address provided .\n");
		res = R_TRUE;
	} else if (addr == -1) {
		eprintf ("[-] r_cmd_java: no address provided .\n");
		res = R_TRUE;
	} else if (!f_type && flag_value == -1) {
		eprintf ("[-] r_cmd_java: no flag type provided .\n");
		res = R_TRUE;
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
			res = R_TRUE;
		}
	}
	IFDBG r_cons_printf ("Current args: (flag_value: 0x%04x addr: 0x%"PFMT64x")\n.", flag_value, addr, res);
	if (flag_value != -1) {
		res = r_cmd_java_set_acc_flags (core, addr, ((ut16) flag_value) & 0xffff);
		IFDBG r_cons_printf ("Writing 0x%04x to 0x%"PFMT64x": %d.", flag_value, addr, res);
	} else {
		eprintf ("[-] r_cmd_java: invalid flag value or type provided .\n");
		r_cmd_java_print_cmd_help (JAVA_CMDS+SET_ACC_FLAGS_IDX);
		res = R_TRUE;
	}
	return res;
}

static int r_cmd_java_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	int res = R_FALSE;
	ut32 i = 0;
	IFDBG r_cons_printf ("Function call made: %s\n", input);
	if (strncmp (input, "java",4)) return R_FALSE;
	else if (strncmp (input, "java ",5)) {
		return r_cmd_java_handle_help (core, input);
	}

	for (; i <END_CMDS; i++) {
		//IFDBG r_cons_printf ("Checking cmd: %s %d %s\n", JAVA_CMDS[i].name, JAVA_CMDS[i].name_len, p);
		IFDBG r_cons_printf ("Checking cmd: %s %d\n", JAVA_CMDS[i].name, strncmp (input+5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len));
		if (!strncmp (input+5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len)) {
			//IFDBG r_cons_printf ("Executing cmd: %s (%s)\n", JAVA_CMDS[i].name, cmd+5+JAVA_CMDS[i].name_len );
			res =  JAVA_CMDS[i].handler (core, input+5+JAVA_CMDS[i].name_len+1);
			break;
		}
	}

	if (res == R_FALSE) res = r_cmd_java_handle_help (core, input);
	return R_TRUE;
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
	return R_TRUE;
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
	return R_TRUE;
}

static int r_cmd_java_print_import_definitions ( RBinJavaObj *obj ) {
	RList * the_list = r_bin_java_get_import_definitions (obj);
	char * str = NULL;
	RListIter *iter;
	r_list_foreach (the_list, iter, str) {
		r_cons_printf("import %s;\n", str);
	}
	r_list_free(the_list);
	return R_TRUE;
}

static int r_cmd_java_print_all_definitions( RAnal *anal ) {
	RList * obj_list  = r_cmd_java_get_bin_obj_list (anal);
	RListIter *iter;
	RBinJavaObj *obj;

	if (!obj_list) return 1;
	r_list_foreach (obj_list, iter, obj) {
		r_cmd_java_print_class_definitions (obj);
	}
	return R_TRUE;
}
static int r_cmd_java_print_class_definitions( RBinJavaObj *obj ) {
	RList * the_fields = r_bin_java_get_field_definitions (obj),
			* the_methods = r_bin_java_get_method_definitions (obj),
			* the_imports = r_bin_java_get_import_definitions (obj),
			* the_moffsets = r_bin_java_get_method_offsets (obj),
			* the_foffsets = r_bin_java_get_field_offsets (obj);

	char * class_name = r_bin_java_get_this_class_name(obj),
		 * str = NULL;

	r_cmd_java_print_import_definitions (obj);
	r_cons_printf ("\nclass %s { // @0x%04"PFMT64x"\n", class_name, obj->loadaddr);

	if (the_fields && the_foffsets && r_list_length (the_fields) > 0) {
		r_cons_printf ("\n\t// Fields defined in the class\n");
		ut32 idx = 0, end = r_list_length (the_fields);

		while (idx < end) {
			ut64 *addr = r_list_get_n (the_foffsets, idx);
			str = r_list_get_n (the_fields, idx);
			r_cons_printf("\t%s; // @0x%04"PFMT64x"\n", str, *addr);
			idx++;
		}
	}

	if (the_methods && the_moffsets && r_list_length (the_methods) > 0) {
		r_cons_printf ("\n\t// Methods defined in the class\n");
		ut32 idx = 0, end = r_list_length (the_methods);

		while (idx < end) {
			ut64 *addr = r_list_get_n (the_moffsets, idx);
			str = r_list_get_n (the_methods, idx);
			r_cons_printf("\t%s; // @0x%04"PFMT64x"\n", str, *addr);
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
	return R_TRUE;
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
	RBin *b = anal->binb.bin;
	ut8 is_java = (b && b->cur->curplugin && strcmp (b->cur->curplugin->name, "java") == 0) ? 1 : 0;
	return is_java ? b->cur->o->bin_obj : NULL;
}

static int r_cmd_java_resolve_cp_idx (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_without_space (obj, idx);
		r_cons_printf ("%s\n", str);
		free (str);
	}
	return R_TRUE;
}

static int r_cmd_java_resolve_cp_type (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_cp_idx_type (obj, idx);
		r_cons_printf ("%s\n", str);
		free (str);
	}
	return R_TRUE;
}

static int r_cmd_java_resolve_cp_idx_b64 (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_b64_encode (obj, idx) ;
		r_cons_printf ("%s\n", str);
		free (str);
	}
	return R_TRUE;
}

static int r_cmd_java_resolve_cp_address (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		ut64 addr = r_bin_java_resolve_cp_idx_address (obj, idx) ;
		if (addr == -1)
			r_cons_printf ("Unable to resolve CP Object @ index: 0x%04x\n", idx);
		else
			r_cons_printf ("0x%"PFMT64x"\n", addr);
	}
	return R_TRUE;
}

static int r_cmd_java_resolve_cp_to_key (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		char * str = r_bin_java_resolve_cp_idx_to_string (obj, idx) ;
		r_cons_printf ("%s\n", str);
		free (str);
	}
	return R_TRUE;
}
static int r_cmd_java_resolve_cp_summary (RBinJavaObj *obj, ut16 idx) {
	if (obj && idx){
		r_bin_java_resolve_cp_idx_print_summary (obj, idx) ;
	}
	return R_TRUE;
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
	return R_TRUE;
}
static int r_cmd_java_print_field_access_flags_value( const char * flags ){
	ut16 result = r_bin_java_calculate_field_access_value (flags);
	r_cons_printf ("Access Value for %s = 0x%04x\n", flags,  result);
	return R_TRUE;
}
static int r_cmd_java_print_method_access_flags_value( const char * flags ){
	ut16 result = r_bin_java_calculate_method_access_value (flags);
	r_cons_printf ("Access Value for %s = 0x%04x\n", flags,  result);
	return R_TRUE;
}

static int r_cmd_java_set_acc_flags (RCore *core, ut64 addr, ut16 num_acc_flag) {
	char cmd_buf [50];
	//const char * fmt = "wx %04x @ 0x%"PFMT64x;

	int res = R_FALSE;
	//ut64 cur_offset = core->offset;
	num_acc_flag = R_BIN_JAVA_USHORT (((ut8*) &num_acc_flag), 0);
	res = r_core_write_at(core, addr, (const ut8 *)&num_acc_flag, 2);
	//snprintf (cmd_buf, 50, fmt, num_acc_flag, addr);
	//res = r_core_cmd0(core, cmd_buf);
	res = R_TRUE;
	IFDBG r_cons_printf ("Executed cmd: %s == %d\n", cmd_buf, res);
	/*if (cur_offset != core->offset) {
		IFDBG eprintf ("Ooops, write advanced the cursor, moving it back.");
		r_core_seek (core, cur_offset-2, 1);
	}*/
	return res;
}


static int r_cmd_java_print_field_summary (RBinJavaObj *obj, ut16 idx) {
	int res = r_bin_java_print_field_idx_summary (obj, idx);
	if (res == R_FALSE) {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
		res = R_TRUE;
	}
	return res;
}
static int r_cmd_java_print_field_count (RBinJavaObj *obj) {
	ut32 res = r_bin_java_get_field_count (obj);
	r_cons_printf ("%d\n", res);
	r_cons_flush();
	return R_TRUE;
}

static int r_cmd_java_print_field_name (RBinJavaObj *obj, ut16 idx) {
	char * res = r_bin_java_get_field_name (obj, idx);
	if (res) {
		r_cons_printf ("%s\n", res);
	} else {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
	}
	free (res);
	return R_TRUE;
}

static int r_cmd_java_print_method_summary (RBinJavaObj *obj, ut16 idx) {
	int res = r_bin_java_print_method_idx_summary (obj, idx);
	if (res == R_FALSE) {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
		res = R_TRUE;
	}
	return res;
}

static int r_cmd_java_print_method_count (RBinJavaObj *obj) {
	ut32 res = r_bin_java_get_method_count (obj);
	r_cons_printf ("%d\n", res);
	r_cons_flush();
	return R_TRUE;
}

static int r_cmd_java_print_method_name (RBinJavaObj *obj, ut16 idx) {
	char * res = r_bin_java_get_method_name (obj, idx);
	if (res) {
		r_cons_printf ("%s\n", res);
	} else {
		eprintf ("Error: Field or Method @ index (%d) not found in the RBinJavaObj.\n", idx);
	}
	free (res);
	return R_TRUE;
}


// PLUGIN Definition Info
struct r_cmd_plugin_t r_core_plugin_java = {
	.name = "java",
	.desc = "Suite of java commands, java help for more info",
	.call = r_cmd_java_call,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CMD,
	.data = &r_core_plugin_java
};
#endif
