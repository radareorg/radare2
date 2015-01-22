#include "microsoft_demangle.h"
#include <r_cons.h>

#define _R_LIST_C
#include <r_list.h>

#define MICROSOFT_NAME_LEN (256)
#define MICROSOFR_CLASS_NAMESPACE_LEN (256)
#define IMPOSSIBLE_LEN (MICROSOFT_NAME_LEN + MICROSOFR_CLASS_NAMESPACE_LEN)

typedef enum EObjectType {
	eObjectTypeStaticClassMember = 2,
	eObjectTypeGlobal = 3,
	eObjectTypeMax = 99
} EObjectType;

///////////////////////////////////////////////////////////////////////////////
// State machine for parsing type codes data types
///////////////////////////////////////////////////////////////////////////////
typedef enum ETCStateMachineErr {
	ETCStateMachineErrOK,
	ETCStateMachineErrUncorrectTypeCode,
	ETCStateMachineErrUnsupportedTypeCode,
	ETCStateMachineErrMax
} ETCStateMachineErr;

typedef enum ETCState { // TC - type code
	eTCStateStart = 0,
	eTCStateEnd,
	eTCStateMax
} ETCState;

typedef struct STypeCodeStr {
	char *type_str;
	int type_str_len;
	int curr_pos;
} STypeCodeStr;

struct SStateInfo;
typedef void (*state_func)(struct SStateInfo *, STypeCodeStr *type_code_str);

typedef struct SStateInfo {
	ETCState state;
	char *buff_for_parsing;
	int amount_of_read_chars;
	ETCStateMachineErr err;
} SStateInfo;

static void tc_state_start(SStateInfo *state, STypeCodeStr *type_code_str);

static state_func const state_table[eTCStateMax] = {
	tc_state_start, NULL
};
///////////////////////////////////////////////////////////////////////////////
// End of data types for state machine which parse type codes
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// State machine for parsing type codes functions
///////////////////////////////////////////////////////////////////////////////
static void run_state(	SStateInfo *state_info,
						STypeCodeStr *type_code_str)
{
	state_table[state_info->state](state_info, type_code_str);
}

///////////////////////////////////////////////////////////////////////////////
static void tc_state_start(SStateInfo *state, STypeCodeStr *type_code_str)
{
	state->amount_of_read_chars++;

	switch (*(state->buff_for_parsing)) {
	case 'X': case 'N': case 'D': case 'C': case 'E': case 'F': case 'G':
	case 'H': case 'I': case 'J': case 'K': case '_': case 'M': case 'R':
	case 'O': case 'T': case 'U': case 'Z': case 'P': case 'Q': case 'W':
	case 'S': case 'A': case 'V':
		state->state = eTCStateEnd;
		state->err =ETCStateMachineErrUnsupportedTypeCode;
		break;
	default:
		eprintf("[uncorrect type] error while parsing type\n");

		state->state = eTCStateEnd;
		state->err = ETCStateMachineErrUncorrectTypeCode;
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void init_state_struct(SStateInfo *state, char *buff_for_parsing)
{
	state->state = eTCStateStart;
	state->buff_for_parsing = buff_for_parsing;
	state->amount_of_read_chars = 0;
	state->err = ETCStateMachineErrOK;
}

///////////////////////////////////////////////////////////////////////////////
static int init_type_code_str_struct(STypeCodeStr *type_coder_str)
{
#define TYPE_STR_LEN 1024
	int res = 1; // 1 - initialization finish with success, else - 0

	type_coder_str->type_str_len = TYPE_STR_LEN;

	type_coder_str->type_str = (char *) malloc(TYPE_STR_LEN * sizeof(char));
	if (type_coder_str->type_str == NULL) {
		res = 0;
	}

	type_coder_str->curr_pos = strlen("unknown_type");
	strncpy(type_coder_str->type_str, "unknown_type", type_coder_str->curr_pos);

	return res;
#undef TYPE_STR_LEN
}

///////////////////////////////////////////////////////////////////////////////
static void free_type_code_str_struct(STypeCodeStr *type_code_str)
{
	R_FREE(type_code_str->type_str);
	type_code_str->type_str_len = 0;
}
///////////////////////////////////////////////////////////////////////////////
// End of machine functions for parsting type codes
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
static EDemanglerErr get_type_code_string(	char *sym,
											unsigned int *amount_of_read_chars,
											char **str_type_code)
{
	EDemanglerErr err = eDemanglerErrOK;
	char *tmp_sym = sym;
	STypeCodeStr type_code_str;
	SStateInfo state;

	if (!init_type_code_str_struct(&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto get_type_code_string_err;
	}

	init_state_struct(&state, tmp_sym);

	while (state.state != eTCStateEnd) {
		run_state(&state, &type_code_str);

		if (state.err != ETCStateMachineErrOK) {
			*str_type_code = 0;
			*amount_of_read_chars = 0;
			switch (state.err) {
			case ETCStateMachineErrUncorrectTypeCode:
				err = eDemanglerErrUncorrectMangledSymbol;
				break;
			case ETCStateMachineErrUnsupportedTypeCode:
				err = eDemanglerErrUnsupportedMangling;
			default:
				break;
			}

			goto get_type_code_string_err;
		}
	}

	*str_type_code = strdup(type_code_str.type_str);
	*amount_of_read_chars = state.amount_of_read_chars;

get_type_code_string_err:
	free_type_code_str_struct(&type_code_str);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
/// public mangled name of global object:
/// <public name> ::= ?<name>@[<namespace>@](0->inf)@3<type><storage class>
/// mangled name of a static class member object:
/// <public name> ::= ?<name>@[<classname>@](1->inf)@2<type><storage class>
///////////////////////////////////////////////////////////////////////////////
static EDemanglerErr parse_microsoft_mangled_name(	char *sym,
													char **demangled_name)
{
	EDemanglerErr err = eDemanglerErrOK;
	unsigned int limit_len_arr[] = { MICROSOFT_NAME_LEN,
									 MICROSOFR_CLASS_NAMESPACE_LEN };
	unsigned int amount_of_elements = sizeof(limit_len_arr) / sizeof(unsigned int);
	unsigned int limit_len = 0;
	unsigned int i = 1;

	unsigned int len = 0;
	int tmp_len = 0;

	EObjectType object_type = eObjectTypeMax;
	char *tmp = 0;
	char var_name[MICROSOFT_NAME_LEN];
	RList/*<char*>*/ *names_l = r_list_new();
	RListIter *it;

	char *rest_of_sym = 0;
	char *curr_pos = 0;
	char *prev_pos = 0;

	memset(var_name, 0, MICROSOFT_NAME_LEN);

	rest_of_sym = strstr(sym, "@@");
	tmp_len = rest_of_sym - sym + 1;	// +1 - need to account for the
										// trailing '@'
										// each (class)(namespace)name
										// end with '@'

	if (!rest_of_sym) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	prev_pos = sym;
	curr_pos = strchr(sym, '@');
	while (tmp_len != 0) {
		len = curr_pos - prev_pos;

		// TODO:maybe add check of name correctness? like name can not start
		//		with number
		if ((len <= 0) || (len >= MICROSOFT_NAME_LEN)) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_microsoft_mangled_name_err;
		}

		tmp = (char *) malloc(len + 1);
		tmp[len] = '\0';
		memcpy(tmp, prev_pos, len);

		r_list_append(names_l, tmp);

		tmp_len -= (len + 1);
		prev_pos = curr_pos + 1;
		curr_pos = strchr(curr_pos + 1, '@');
	}

	curr_pos++;
	object_type = *curr_pos - '0';
	switch (object_type) {
	case eObjectTypeStaticClassMember:
		// at least need to be 2 items
		// first variable name, second - class name
		if (r_list_length(names_l) < 1) {
			err = eDemanglerErrUncorrectMangledSymbol;
		}
		break;
	case eObjectTypeGlobal:
		break;
	default:
		err = eDemanglerErrUncorrectMangledSymbol;
		break;
	}

	if (err != eDemanglerErrOK) {
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos++;
	i = 0;
	err = get_type_code_string(curr_pos, &i, &tmp);
	if (err != eDemanglerErrOK) {
		R_FREE(tmp);
		goto parse_microsoft_mangled_name_err;
	}
	// do something with tmp
	printf("%s\n", tmp);
	R_FREE(tmp);

	err = eDemanglerErrUnsupportedMangling;

parse_microsoft_mangled_name_err:
	it = r_list_iterator (names_l);
	r_list_foreach (names_l, it, tmp) {
		printf("%s\n", tmp);
		free(tmp);
	}

	r_list_free(names_l);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
EDemanglerErr microsoft_demangle(SDemangler *demangler, char **demangled_name)
{
	EDemanglerErr err = eDemanglerErrOK;
	char *sym = demangler->symbol;

	// TODO: maybe get by default some sym_len and check it?
	unsigned int sym_len = strlen(sym);

	if (demangler == 0) {
		err = eDemanglerErrMemoryAllocation;
		goto microsoft_demangle_err;
	}

	if (sym[sym_len - 1] == 'Z') {
		err = eDemanglerErrUnsupportedMangling;
	} else {
		err = parse_microsoft_mangled_name(demangler->symbol + 1, demangled_name);
	}

microsoft_demangle_err:
	return err;
}
