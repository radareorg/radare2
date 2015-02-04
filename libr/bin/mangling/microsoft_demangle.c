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
	eTCStateStart = 0, eTCStateEnd, eTCStateH, eTCStateX, eTCStateN, eTCStateD,
	eTCStateC, eTCStateE, eTCStateF, eTCStateG, eTCStateI, eTCStateJ, eTCStateK,
	eTCStateM, eTCStateZ, eTCState_, eTCStateT, eTCStateU, eTCStateW, eTCStateV,
	eTCStateO, eTCStateS, eTCStateP, eTCStateR, eTCStateQ, eTCStateA, eTCStateMax
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

typedef struct SStrInfo {
	char *str_ptr;
	int len;
} SStrInfo;

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
DECL_STATE_ACTION(T)
DECL_STATE_ACTION(U)
DECL_STATE_ACTION(W)
DECL_STATE_ACTION(V)
DECL_STATE_ACTION(O)
DECL_STATE_ACTION(S)
DECL_STATE_ACTION(P)
DECL_STATE_ACTION(R)
DECL_STATE_ACTION(Q)
DECL_STATE_ACTION(A)
#undef DECL_STATE_ACTION

#define NAME(action) tc_state_##action
static state_func const state_table[eTCStateMax] = {
	NAME(start), NULL, NAME(H), NAME(X), NAME(N), NAME(D), NAME(C), NAME(E),
	NAME(F), NAME(G), NAME(I), NAME(J), NAME(K), NAME(M), NAME(Z), NAME(_),
	NAME(T), NAME(U), NAME(W), NAME(V), NAME(O), NAME(S), NAME(P), NAME(R),
	NAME(Q), NAME(A)
};
#undef NAME
///////////////////////////////////////////////////////////////////////////////
// End of data types for state machine which parse type codes
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// State machine for parsing type codes functions
///////////////////////////////////////////////////////////////////////////////

static EDemanglerErr get_type_code_string(	char *sym,
											unsigned int *amount_of_read_chars,
											char **str_type_code);
static int init_type_code_str_struct(STypeCodeStr *type_coder_str);
static void free_type_code_str_struct(STypeCodeStr *type_code_str);

static void run_state(	SStateInfo *state_info,
						STypeCodeStr *type_code_str)
{
	state_table[state_info->state](state_info, type_code_str);
}

///////////////////////////////////////////////////////////////////////////////
int copy_string(STypeCodeStr *type_code_str, char *str_for_copy, unsigned int copy_len)
{
	int res = 1; // all is OK
	int str_for_copy_len = (copy_len == 0) ? strlen(str_for_copy) : copy_len;
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

///////////////////////////////////////////////////////////////////////////////
/// \brief get_namespace_and_name
/// \param buf Current buffer position with mangled name
/// \param type_code_str String with got name and namespaces
/// \param amount_of_names Amount of names that was in list
/// \return Return amount of processed chars
///
int get_namespace_and_name(	char *buf, STypeCodeStr *type_code_str,
							int *amount_of_names)
{
	char *curr_pos = 0, *prev_pos = 0;

	RList /* <SStrInfo *> */ *names_l = 0;
	RListIter *it = 0;
	SStrInfo *str_info = 0;

	int len = 0, read_len = 0, tmp_len = 0;

	curr_pos = strstr(buf, "@@");
	if (!curr_pos) {
		goto get_namespace_and_name_err;
	}

	names_l = r_list_new();

	read_len = tmp_len = curr_pos - buf;

	prev_pos = buf;
	curr_pos = strchr(buf, '@');
	while (tmp_len != -1) {
		len = curr_pos - prev_pos;

		// TODO:maybe add check of name correctness? like name can not start
		//		with number
		if ((len <= 0) || (len >= MICROSOFT_NAME_LEN)) {
			goto get_namespace_and_name_err;
		}

		str_info = (SStrInfo *) malloc(sizeof(SStrInfo));
		str_info->str_ptr = prev_pos;
		str_info->len = len;

		r_list_append(names_l, str_info);

		tmp_len -= (len + 1);
		prev_pos = curr_pos + 1;
		curr_pos = strchr(curr_pos + 1, '@');
	}

get_namespace_and_name_err:
	tmp_len = r_list_length(names_l);
	if (amount_of_names)
		*amount_of_names = tmp_len;
	it = r_list_iterator (names_l);
	r_list_foreach_prev (names_l, it, str_info) {
		copy_string(type_code_str, str_info->str_ptr, str_info->len);

		if (--tmp_len)
			copy_string(type_code_str, "::", 0);
		free(str_info);
	}
	r_list_free(names_l);

	return read_len;
}

#define SINGLEQUOTED_U 'U'
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
#define SINGLEQUOTED_V 'V'
#define SINGLEQUOTED_O 'O'
#define SINGLEQUOTED_S 'S'
#define SINGLEQUOTED_P 'P'
#define SINGLEQUOTED_R 'R'
#define SINGLEQUOTED_Q 'Q'
#define SINGLEQUOTED_A 'A'
#define SINGLEQUOTED__ '_'
#define CHAR_WITH_QUOTES(letter) (SINGLEQUOTED_##letter)

#define DEF_STATE_ACTION(action) static void tc_state_##action(SStateInfo *state, STypeCodeStr *type_code_str)
#define GO_TO_NEXT_STATE(state, new_state) { \
	state->amount_of_read_chars++; \
	state->buff_for_parsing++; \
	state->state = eTCStateEnd; \
}
#define ONE_LETTER_ACTIION(action, type) \
	static void tc_state_##action(SStateInfo *state, STypeCodeStr *type_code_str) \
	{ \
		if (copy_string(type_code_str, type, 0) == 0) { \
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
ONE_LETTER_ACTIION(O, "long double")

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(_)
{
#define PROCESS_CASE(letter, type_str) \
	case CHAR_WITH_QUOTES(letter): \
		copy_string(type_code_str, type_str, 0); \
		break;

	switch(*(state->buff_for_parsing)) {
		PROCESS_CASE(J, "long long(__int64)")
		PROCESS_CASE(K, "unsigned long long(unsigned __int64)")
		PROCESS_CASE(T, "long double(80 bit precision)")
		PROCESS_CASE(Z, "long double(64 bit precision)")
		PROCESS_CASE(W, "wchar_t")
		PROCESS_CASE(N, "bool")
		default:
			state->err = eTCStateMachineErrUncorrectTypeCode;
			break;
	}

	state->amount_of_read_chars++;
	state->buff_for_parsing++;
	state->state = eTCStateEnd;
#undef PROCESS_CASE
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(T)
{
#define PROCESS_CASE(case_string, type_str) { \
	check_len = strlen(case_string); \
	if ((check_len < buff_len) && \
		(strncmp(state->buff_for_parsing, case_string, check_len) == 0)) { \
		copy_string(type_code_str, type_str, 0); \
		state->amount_of_read_chars += check_len + 2; \
		return; \
	} \
}

	int buff_len = strlen(state->buff_for_parsing);
	int check_len = 0;
	char *tmp = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE("__m64@@", "__m64");
	PROCESS_CASE("__m128@@", "__m128");
	PROCESS_CASE("__m128i@@", "__m128i");
	PROCESS_CASE("__m256@@", "__m256");
	PROCESS_CASE("__m256i@@", "__m256i");
	PROCESS_CASE("__m512@@", "__m512");
	PROCESS_CASE("__m512i@@", "__m512i");

	check_len = strstr(state->buff_for_parsing, "@@") - state->buff_for_parsing;
	if ((check_len > 0) && (check_len < buff_len)) {
		memcpy(tmp, state->buff_for_parsing, check_len);
		copy_string(type_code_str, "union ", 0);
		copy_string(type_code_str, state->buff_for_parsing, check_len);
		state->amount_of_read_chars += check_len + 2;
		state->buff_for_parsing += check_len + 2;
		return;
	}

	state->err = eTCStateMachineErrUncorrectTypeCode;
#undef PROCESS_CASE
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(U)
{
#define PROCESS_CASE(case_string, type_str) { \
	check_len = strlen(case_string); \
	if ((check_len < buff_len) && \
		(strncmp(state->buff_for_parsing, case_string, check_len) == 0)) { \
		copy_string(type_code_str, type_str, 0); \
		state->amount_of_read_chars += check_len + 2; \
		state->buff_for_parsing += check_len + 2; \
		return; \
	} \
}

	int buff_len = strlen(state->buff_for_parsing);
	int check_len = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE("__m128d@@", "__m128d");
	PROCESS_CASE("__m256d@@", "__m256d");
	PROCESS_CASE("__m512d@@", "__m512d");

	check_len = strstr(state->buff_for_parsing, "@@") - state->buff_for_parsing;
	if ((check_len > 0) && (check_len < buff_len)) {
		copy_string(type_code_str, "struct ", 0);
		copy_string(type_code_str, state->buff_for_parsing, check_len);
		state->amount_of_read_chars += check_len + 2;
		state->buff_for_parsing += check_len + 2;
		return;
	}

	state->err = eTCStateMachineErrUncorrectTypeCode;
#undef PROCESS_CASE
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(W)
{
	//W4X@@ -> enum X, W4X@Y@@ -> enum Y::X
	int len = 0;
	state->state = eTCStateEnd;

	if (*state->buff_for_parsing != '4') {
		state->err = eTCStateMachineErrUncorrectTypeCode;
	}

	state->buff_for_parsing++;
	state->amount_of_read_chars++;

	copy_string(type_code_str, "enum ", 0);
	len = get_namespace_and_name(state->buff_for_parsing, type_code_str, 0);

	if (len) {
		state->amount_of_read_chars += len + 2; // cause and with @@ and they
												// need to be skipped
		state->buff_for_parsing += len + 2;
	} else {
		state->err = eTCStateMachineErrUncorrectTypeCode;
	}
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(V)
{
	// VX@@ -> class X
	int len = 0;
	state->state = eTCStateEnd;

	copy_string(type_code_str, "class ", 0);
	len = get_namespace_and_name(state->buff_for_parsing, type_code_str, 0);
	if (len) {
		state->amount_of_read_chars += len + 2; // cause and with @@ and they
												// need to be skipped
		state->buff_for_parsing += len + 2;
	} else {
		state->err = eTCStateMachineErrUncorrectTypeCode;
	}
}

#define MODIFIER(modifier_str) { \
	unsigned int i = 0; \
	EDemanglerErr err = eDemanglerErrOK; \
	char *tmp = 0; \
	STypeCodeStr tmp_str; \
	int flag__ptr64 = 0; \
\
	state->state = eTCStateEnd; \
\
	if (!init_type_code_str_struct(&tmp_str)) { \
		state->err = eTCStateMachineErrAlloc; \
		return; \
	} \
\
	if (*state->buff_for_parsing == 'E') { \
		flag__ptr64 = 1; \
		state->amount_of_read_chars++; \
		state->buff_for_parsing++; \
	} \
\
	switch (*state->buff_for_parsing++) { \
	case 'A': \
		break; \
	case 'B': \
		copy_string(&tmp_str, " const", 0); \
		break; \
	case 'C': \
		copy_string(&tmp_str, " volatile", 0); \
		break; \
	case 'D': \
		copy_string(&tmp_str, " const volatile", 0); \
		break; \
	default: \
		state->err = eTCStateMachineErrUnsupportedTypeCode; \
		break; \
	} \
\
	copy_string(&tmp_str, modifier_str, 0); \
	if (flag__ptr64) { \
		copy_string(&tmp_str, " __ptr64 ", 0); \
	} \
\
	err = get_type_code_string(state->buff_for_parsing, &i, &tmp); \
	if (err != eDemanglerErrOK) { \
		state->err = eTCStateMachineErrUnsupportedTypeCode; \
		R_FREE(tmp); \
	} \
\
	copy_string(type_code_str, tmp, 0); \
	copy_string(type_code_str, tmp_str.type_str, tmp_str.curr_pos); \
\
	R_FREE(tmp); \
	free_type_code_str_struct(&tmp_str); \
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(S)
{
	MODIFIER(" * const volatile");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(P)
{
	MODIFIER(" *");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(R)
{
	MODIFIER(" * volatile");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(Q)
{
	MODIFIER(" * const");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(A)
{
	MODIFIER(" &");
}

#undef MODIFIER
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
	ONE_LETTER_STATE(T)
	ONE_LETTER_STATE(U)
	ONE_LETTER_STATE(W)
	ONE_LETTER_STATE(V)
	ONE_LETTER_STATE(O)
	ONE_LETTER_STATE(S)
	ONE_LETTER_STATE(P)
	ONE_LETTER_STATE(R)
	ONE_LETTER_STATE(Q)
	ONE_LETTER_STATE(A)
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

	memset(type_coder_str->type_str, 0, TYPE_STR_LEN * sizeof(char));

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
	STypeCodeStr type_code_str;
	EDemanglerErr err = eDemanglerErrOK;
	EObjectType object_type = eObjectTypeMax;

	unsigned int i = 0;
	unsigned int len = 0;

	char *curr_pos = sym;
	char *tmp = 0;

	if (!init_type_code_str_struct(&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_microsoft_mangled_name_err;
	}

	len = get_namespace_and_name(curr_pos, &type_code_str, (int*)&i);
	if (!len) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos += len + 2;

	object_type = *curr_pos - '0';
	switch (object_type) {
	case eObjectTypeStaticClassMember:
		// at least need to be 2 items
		// first variable name, second - class name
		if (i < 2) {
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

	printf("%s\n", type_code_str.type_str);
	err = eDemanglerErrUnsupportedMangling;

parse_microsoft_mangled_name_err:
	free_type_code_str_struct(&type_code_str);
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
