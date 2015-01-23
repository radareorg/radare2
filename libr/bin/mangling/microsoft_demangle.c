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
	eTCStateMachineErrOK,
	eTCStateMachineErrUncorrectTypeCode,
	eTCStateMachineErrUnsupportedTypeCode,
	eTCStateMachineErrAlloc,
	eTCStateMachineErrMax
} ETCStateMachineErr;

typedef enum ETCState { // TC - type code
	eTCStateStart = 0, eTCStateEnd, eTCStateH, eTCStateX, eTCStateN, eTCStateD, eTCStateC,
	eTCStateE, eTCStateF, eTCStateG, eTCStateI, eTCStateJ, eTCStateK,
	eTCStateM, eTCStateZ, eTCState_, eTCStateMax
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

#define DECL_STATE_ACTION(action) static void tc_state_##action(SStateInfo *state, STypeCodeStr *type_code_str);
DECL_STATE_ACTION(start)
DECL_STATE_ACTION(X)
DECL_STATE_ACTION(N)
DECL_STATE_ACTION(D)
DECL_STATE_ACTION(C)
DECL_STATE_ACTION(E)
DECL_STATE_ACTION(F)
DECL_STATE_ACTION(G)
DECL_STATE_ACTION(H)
DECL_STATE_ACTION(I)
DECL_STATE_ACTION(J)
DECL_STATE_ACTION(K)
DECL_STATE_ACTION(M)
DECL_STATE_ACTION(Z)
DECL_STATE_ACTION(_)
#undef DECL_STATE_ACTION

#define NAME(action) tc_state_##action
static state_func const state_table[eTCStateMax] = {
	NAME(start), NULL, NAME(H), NAME(X), NAME(N), NAME(D), NAME(C), NAME(E),
	NAME(F), NAME(G), NAME(I), NAME(J), NAME(K), NAME(M), NAME(Z), NAME(_)
};
#undef NAME
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
int copy_string(STypeCodeStr *type_code_str, char *str_for_copy)
{
	int res = 1; // all is OK
	int str_for_copy_len = strlen(str_for_copy);
	int free_space = type_code_str->type_str_len - type_code_str->curr_pos - 1;
	char *dst = 0;

	if (free_space > str_for_copy_len) {
		type_code_str->type_str_len =
				(type_code_str->type_str_len +  str_for_copy_len) >> 1;
		type_code_str->type_str = (char *) realloc(	type_code_str->type_str,
													type_code_str->type_str_len);
		if (type_code_str->type_str == NULL) {
			res = 0;
			goto copy_string_err;
		}
	}

	dst = type_code_str->type_str + type_code_str->curr_pos;
	strncpy(dst, str_for_copy, str_for_copy_len);
	type_code_str->curr_pos += str_for_copy_len;
	type_code_str->type_str[type_code_str->curr_pos] = '\0';

copy_string_err:
	return res;
}

#define SINGLEQUOTED_X 'X'
#define SINGLEQUOTED_D 'D'
#define SINGLEQUOTED_C 'C'
#define SINGLEQUOTED_E 'E'
#define SINGLEQUOTED_F 'F'
#define SINGLEQUOTED_G 'G'
#define SINGLEQUOTED_H 'H'
#define SINGLEQUOTED_I 'I'
#define SINGLEQUOTED_J 'J'
#define SINGLEQUOTED_K 'K'
#define SINGLEQUOTED_M 'M'
#define SINGLEQUOTED_N 'N'
#define SINGLEQUOTED_T 'T'
#define SINGLEQUOTED_Z 'Z'
#define SINGLEQUOTED_W 'W'
#define SINGLEQUOTED__ '_'
#define CHAR_WITH_QUOTES(letter) (SINGLEQUOTED_##letter)

#define DEF_STATE_ACTION(action) static void tc_state_##action(SStateInfo *state, STypeCodeStr *type_code_str)
#define GO_TO_NEXT_STATE(state, new_state) { \
	state->amount_of_read_chars++; \
	state->state = eTCStateEnd; \
}
#define ONE_LETTER_ACTIION(action, type) \
	static void tc_state_##action(SStateInfo *state, STypeCodeStr *type_code_str) \
	{ \
		if (copy_string(type_code_str, type) == 0) { \
			state->err = eTCStateMachineErrAlloc; \
		} \
		GO_TO_NEXT_STATE(state, eTCStateEnd) \
	} \

ONE_LETTER_ACTIION(X, "void")
ONE_LETTER_ACTIION(D, "char")
ONE_LETTER_ACTIION(C, "signed char")
ONE_LETTER_ACTIION(E, "unsigned char")
ONE_LETTER_ACTIION(F, "short int")
ONE_LETTER_ACTIION(G, "unsigned short int")
ONE_LETTER_ACTIION(H, "int")
ONE_LETTER_ACTIION(I, "unsinged int")
ONE_LETTER_ACTIION(J, "long int")
ONE_LETTER_ACTIION(K, "unsigned long int")
ONE_LETTER_ACTIION(M, "float")
ONE_LETTER_ACTIION(N, "double")
ONE_LETTER_ACTIION(Z, "varargs ...")

DEF_STATE_ACTION(_)
{
#define PROCESS_CASE(letter, type_str) \
	case CHAR_WITH_QUOTES(letter): \
		copy_string(type_code_str, type_str); \
		break;

	switch(*(state->buff_for_parsing)) {
		PROCESS_CASE(J, "long long(__int64)")
		PROCESS_CASE(K, "unsigned long long(unsigned __int64)")
		PROCESS_CASE(T, "long double(80 bit precision)")
		PROCESS_CASE(Z, "unsigned long long(unsigned __int64)")
		PROCESS_CASE(W, "wchar_t")
		default:
			state->err = eTCStateMachineErrUncorrectTypeCode;
			break;
	}

	state->state = eTCStateEnd;
#undef PROCESS_CASE
}

#undef ONE_LETTER_ACTION
#undef GO_TO_NEXT_STATE
#undef DEF_STATE_ACTION

///////////////////////////////////////////////////////////////////////////////
static void tc_state_start(SStateInfo *state, STypeCodeStr *type_code_str)
{
#define ONE_LETTER_STATE(letter) \
	case CHAR_WITH_QUOTES(letter): \
		state->state = eTCState##letter; \
		break; \

	switch (*(state->buff_for_parsing)) {
	ONE_LETTER_STATE(X)
	ONE_LETTER_STATE(D)
	ONE_LETTER_STATE(C)
	ONE_LETTER_STATE(E)
	ONE_LETTER_STATE(F)
	ONE_LETTER_STATE(G)
	ONE_LETTER_STATE(H)
	ONE_LETTER_STATE(I)
	ONE_LETTER_STATE(J)
	ONE_LETTER_STATE(K)
	ONE_LETTER_STATE(M)
	ONE_LETTER_STATE(N)
	ONE_LETTER_STATE(Z)
	ONE_LETTER_STATE(_)
	case 'R': case ' ':
	case 'O': case 'T': case 'U': case 'P': case 'Q': case 'W':
	case 'S': case 'A': case 'V':
		state->state = eTCStateEnd;
		state->err = eTCStateMachineErrUnsupportedTypeCode;
		break;
	default:
		eprintf("[uncorrect type] error while parsing type\n");

		state->state = eTCStateEnd;
		state->err = eTCStateMachineErrUncorrectTypeCode;
		break;
	}

	state->amount_of_read_chars++;
	state->buff_for_parsing++;
#undef ONE_LETTER_STATE
}

///////////////////////////////////////////////////////////////////////////////
static void init_state_struct(SStateInfo *state, char *buff_for_parsing)
{
	state->state = eTCStateStart;
	state->buff_for_parsing = buff_for_parsing;
	state->amount_of_read_chars = 0;
	state->err = eTCStateMachineErrOK;
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

	type_coder_str->curr_pos = 0; // strlen("unknown type");
//	strncpy(type_coder_str->type_str, "unknown_type", type_coder_str->curr_pos);

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

		if (state.err != eTCStateMachineErrOK) {
			*str_type_code = 0;
			*amount_of_read_chars = 0;
			switch (state.err) {
			case eTCStateMachineErrUncorrectTypeCode:
				err = eDemanglerErrUncorrectMangledSymbol;
				break;
			case eTCStateMachineErrUnsupportedTypeCode:
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
