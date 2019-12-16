/* radare - LGPL - Copyright 2015-2016 - inisider */

#include "microsoft_demangle.h"
#include <ctype.h>
#include <r_cons.h>

#define _R_LIST_C
#include <r_list.h>

#define MICROSOFT_NAME_LEN (256)
#define MICROSOFR_CLASS_NAMESPACE_LEN (256)
#define IMPOSSIBLE_LEN (MICROSOFT_NAME_LEN + MICROSOFR_CLASS_NAMESPACE_LEN)

// TODO: it will be good to change this to some kind of map data structure
static RList *abbr_types = NULL;
static RList *abbr_names = NULL;

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
DECL_STATE_ACTION(end)
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
	NAME(start), NAME(end) , NAME(H), NAME(X), NAME(N), NAME(D), NAME(C), NAME(E),
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

static void init_state_struct(SStateInfo *state, char *buff_for_parsing);
static EDemanglerErr get_type_code_string(char *sym, unsigned int *amount_of_read_chars, char **str_type_code);
static int init_type_code_str_struct(STypeCodeStr *type_coder_str);
static void free_type_code_str_struct(STypeCodeStr *type_code_str);
static int get_template(char *buf, SStrInfo *str_info);
static char *get_num(SStateInfo *state);

static void run_state(SStateInfo *state_info, STypeCodeStr *type_code_str) {
	state_table[state_info->state](state_info, type_code_str);
}

int copy_string(STypeCodeStr *type_code_str, char *str_for_copy, unsigned int copy_len) {
	int res = 1; // all is OK
	int str_for_copy_len = (copy_len == 0 && str_for_copy) ? strlen (str_for_copy) : copy_len;
	int free_space = type_code_str->type_str_len - type_code_str->curr_pos - 1;

	if (str_for_copy_len > free_space) {
		return 0;
	}
	if (free_space > str_for_copy_len) {
		int newlen = type_code_str->type_str_len + (str_for_copy_len << 1) + 1;
		if (newlen < 1) {
			R_FREE (type_code_str->type_str);
			goto copy_string_err;
		}
		type_code_str->type_str_len = newlen;
		char *type_str = (char *) realloc (type_code_str->type_str, newlen);
		if (!type_str) {
			R_FREE (type_code_str->type_str);
			goto copy_string_err;
		}
		type_code_str->type_str = type_str;
		if (!type_code_str->type_str) {
			res = 0;
			goto copy_string_err;
		}
	}

	char *dst = type_code_str->type_str + type_code_str->curr_pos;
	if (!dst) {
		return 0;
	}

	if (str_for_copy) {
		r_str_ncpy  (dst, str_for_copy, str_for_copy_len + 1);
	} else {
		memset (dst, 0, str_for_copy_len);
	}
	type_code_str->curr_pos += str_for_copy_len;
	if (type_code_str->type_str) {
		type_code_str->type_str[type_code_str->curr_pos] = '\0';
	}

copy_string_err:
	return res;
}

int get_template_params(char *sym, unsigned int *amount_of_read_chars, char **str_type_code) {
	EDemanglerErr err = eDemanglerErrOK;
	SStateInfo state;
	init_state_struct (&state, sym);
	const char template_param[] = "template-parameter-";
	char *tmp, *res = NULL;
	if (!strncmp (sym, "?", 1)) {
		// anonymous template param
		state.amount_of_read_chars += 1;
		state.buff_for_parsing += 1;
		res = get_num (&state);
		if (res) {
			tmp = r_str_newf("%s%s", template_param, res);
			free (res);
			res = tmp;
		}
	} else {
		if (strncmp (sym, "$", 1)) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto get_template_params_err;
		}
		sym++;
		state.amount_of_read_chars += 2;
		state.buff_for_parsing += 2;
		if (!strncmp (sym, "0", 1)) {
			// Signed integer
			tmp = get_num (&state);
			if (tmp) {
				int signed_a = atoi (tmp);
				res = r_str_newf ("%d", signed_a);
				free (tmp);
			}
		} else if (!strncmp (sym, "2", 1)) {
			// real value a ^ b
			char *a = get_num (&state);
			char *b = get_num (&state);
			if (a && b) {
				int signed_b = atoi (b);
				res = r_str_newf ("%sE%d", a, signed_b);
			}
			free (a);
			free (b);
		} else if (!strncmp (sym, "D", 1)) {
			// anonymous template param
			res = get_num (&state);
			if (res) {
				tmp = r_str_newf("%s%s", template_param, res);
				free (res);
				res = tmp;
			}
		} else if (!strncmp (sym, "F", 1)) {
			// Signed {a, b}
			char *a = get_num (&state);
			char *b = get_num (&state);
			if (a && b) {
				int signed_a = atoi (a);
				int signed_b = atoi (b);
				res = r_str_newf ("{%d, %d}", signed_a, signed_b);
			}
			free (a);
			free (b);
		} else if (!strncmp (sym, "G", 1)) {
			// Signed {a, b, c}
			char *a = get_num (&state);
			char *b = get_num (&state);
			char *c = get_num (&state);
			if (a && b && c) {
				int signed_a = atoi (a);
				int signed_b = atoi (b);
				int signed_c = atoi (c);
				res = r_str_newf ("{%d, %d, %d}", signed_a, signed_b, signed_c);
			}
			free (a);
			free (b);
			free (c);
		} else if (!strncmp (sym, "H", 1)) {
			// Unsigned integer
			res = get_num (&state);
		} else if (!strncmp (sym, "I", 1)) {
			// Unsigned {x, y}
			char *a = get_num (&state);
			char *b = get_num (&state);
			if (a && b) {
				res = r_str_newf ("{%s, %s}", a, b);
			}
			free (a);
			free (b);
		} else if (!strncmp (sym, "J", 1)) {
			// Unsigned {x, y, z}
			char *a = get_num (&state);
			char *b = get_num (&state);
			char *c = get_num (&state);
			if (a && b && c) {
				res = r_str_newf ("{%s, %s, %s}", a, b, c);
			}
			free (a);
			free (b);
			free (c);
		} else if (!strncmp (sym, "Q", 1)) {
			// anonymous non-type template parameter
			res = get_num (&state);
			if (res) {
				tmp = r_str_newf("non-type-%s%s", template_param, res);
				free (res);
				res = tmp;
			}
		}
	}

	if (!res) {
		err = eDemanglerErrUnsupportedMangling;
		goto get_template_params_err;
	}

	*str_type_code = res;
	*amount_of_read_chars = state.amount_of_read_chars;

get_template_params_err:
	return err;
}

static int get_operator_code(char *buf, RList *names_l) {
	// C++ operator code (one character, or two if the first is '_')
#define SET_OPERATOR_CODE(str) { \
	str_info = (SStrInfo *) malloc (sizeof(SStrInfo)); \
	if (!str_info) break; \
	str_info->len = strlen (str); \
	str_info->str_ptr = str; \
	r_list_append (names_l, str_info); \
}	
	SStrInfo *str_info;
	int read_len = 1;
	switch (*++buf) {
	case '0': SET_OPERATOR_CODE("constructor"); break;
	case '1': SET_OPERATOR_CODE("~destructor"); break;
	case '2': SET_OPERATOR_CODE("operator new"); break;
	case '3': SET_OPERATOR_CODE("operator delete"); break;
	case '4': SET_OPERATOR_CODE("operator="); break;
	case '5': SET_OPERATOR_CODE("operator>>"); break;
	case '6': SET_OPERATOR_CODE("operator<<"); break;
	case '7': SET_OPERATOR_CODE("operator!"); break;
	case '8': SET_OPERATOR_CODE("operator=="); break;
	case '9': SET_OPERATOR_CODE("operator!="); break;
	case 'A': SET_OPERATOR_CODE("operator[]"); break;
	case 'B': SET_OPERATOR_CODE("operator #{return_type}"); break;
	case 'C': SET_OPERATOR_CODE("operator->"); break;
	case 'D': SET_OPERATOR_CODE("operator*"); break;
	case 'E': SET_OPERATOR_CODE("operator++"); break;
	case 'F': SET_OPERATOR_CODE("operator--"); break;
	case 'G': SET_OPERATOR_CODE("operator-"); break;
	case 'H': SET_OPERATOR_CODE("operator+"); break;
	case 'I': SET_OPERATOR_CODE("operator&"); break;
	case 'J': SET_OPERATOR_CODE("operator->*"); break;
	case 'K': SET_OPERATOR_CODE("operator/"); break;
	case 'L': SET_OPERATOR_CODE("operator%"); break;
	case 'M': SET_OPERATOR_CODE("operator<"); break;
	case 'N': SET_OPERATOR_CODE("operator<="); break;
	case 'O': SET_OPERATOR_CODE("operator>"); break;
	case 'P': SET_OPERATOR_CODE("operator>="); break;
	case 'Q': SET_OPERATOR_CODE("operator,"); break;
	case 'R': SET_OPERATOR_CODE("operator()"); break;
	case 'S': SET_OPERATOR_CODE("operator~"); break;
	case 'T': SET_OPERATOR_CODE("operator^"); break;
	case 'U': SET_OPERATOR_CODE("operator|"); break;
	case 'V': SET_OPERATOR_CODE("operator&"); break;
	case 'W': SET_OPERATOR_CODE("operator||"); break;
	case 'X': SET_OPERATOR_CODE("operator*="); break;
	case 'Y': SET_OPERATOR_CODE("operator+="); break;
	case 'Z': SET_OPERATOR_CODE("operator-="); break;
	case '$':
	{
		int i = 0;
		str_info = (SStrInfo *)malloc (sizeof(SStrInfo));
		if (!str_info) {
			break;
		}
		i = get_template (buf + 1, str_info);
		if (!i) {
			R_FREE (str_info);
			return 0;
		}
		r_list_append (names_l, str_info);
		buf += i;
		read_len += i;
		break;
	}
	case '_':
		switch (*++buf) {
		case '0': SET_OPERATOR_CODE ("operator/="); break;
		case '1': SET_OPERATOR_CODE ("operator%="); break;
		case '2': SET_OPERATOR_CODE ("operator>>="); break;
		case '3': SET_OPERATOR_CODE ("operator<<="); break;
		case '4': SET_OPERATOR_CODE ("operator&="); break;
		case '5': SET_OPERATOR_CODE ("operator|="); break;
		case '6': SET_OPERATOR_CODE ("operator^="); break;
		case '7': SET_OPERATOR_CODE ("vftable"); break;
		case '8': SET_OPERATOR_CODE ("vbtable"); break;
		case '9': SET_OPERATOR_CODE ("vcall"); break;
		case 'A': SET_OPERATOR_CODE ("typeof"); break;
		case 'B': SET_OPERATOR_CODE ("local_static_guard"); break;
		case 'C': SET_OPERATOR_CODE ("string"); break;
		case 'D': SET_OPERATOR_CODE ("vbase_dtor"); break;
		case 'E': SET_OPERATOR_CODE ("vector_dtor"); break;
		case 'G': SET_OPERATOR_CODE ("scalar_dtor"); break;
		case 'H': SET_OPERATOR_CODE ("vector_ctor_iter"); break;
		case 'I': SET_OPERATOR_CODE ("vector_dtor_iter"); break;
		case 'J': SET_OPERATOR_CODE ("vector_vbase_ctor_iter"); break;
		case 'L': SET_OPERATOR_CODE ("eh_vector_ctor_iter"); break;
		case 'M': SET_OPERATOR_CODE ("eh_vector_dtor_iter"); break;
		case 'N': SET_OPERATOR_CODE ("eh_vector_vbase_ctor_iter"); break;
		case 'O': SET_OPERATOR_CODE ("copy_ctor_closure"); break;
		case 'S': SET_OPERATOR_CODE ("local_vftable"); break;
		case 'T': SET_OPERATOR_CODE ("local_vftable_ctor_closure"); break;
		case 'U': SET_OPERATOR_CODE ("operator new[]"); break;
		case 'V': SET_OPERATOR_CODE ("operator delete[]"); break;
		case 'X': SET_OPERATOR_CODE ("placement_new_closure"); break;
		case 'Y': SET_OPERATOR_CODE ("placement_delete_closure"); break;
		default:
			r_list_free (names_l);
			return 0;
		}
		read_len++;
		break;
	default:
		r_list_free (names_l);
		return 0;
	}
	read_len++;
	return read_len;
#undef SET_OPERATOR_CODE
}

///////////////////////////////////////////////////////////////////////////////
static int get_template(char *buf, SStrInfo *str_info) {
	int len = 0;
	unsigned int i = 0;
	char *str_type_code = NULL;
	STypeCodeStr type_code_str;
	// RListIter *it = NULL;
	// RList *saved_abbr_names = abbr_names;	// save current abbr names, this

	if (!init_type_code_str_struct(&type_code_str)) {
		goto get_template_err;
	}

	if (*buf == '?') {
		RList *names_l = r_list_new ();
		if (!names_l) {
			return 0;
		}
		int i = get_operator_code (buf, names_l);
		if (!i) {
			return 0;
		}
		len += i;
		buf += i;
		SStrInfo *name = r_list_head (names_l)->data;
		copy_string(&type_code_str, name->str_ptr, name->len);
		r_list_free (names_l);
	} else {
		char *tmp = strchr(buf, '@');
		if (!tmp) {
			goto get_template_err;
		}

		// get/copy template len/name
		len += (tmp - buf + 1);
		copy_string(&type_code_str, buf, len - 1);
		buf += len;
	}

	if (*buf != '@') {
		copy_string(&type_code_str, "<", 0);
	}

	// get identifier
	while (*buf != '@') {
		if (i) {
			copy_string (&type_code_str, ", ", 0);
		}
		if (get_type_code_string (buf, &i, &str_type_code) != eDemanglerErrOK) {
			if (get_template_params (buf, &i, &str_type_code) != eDemanglerErrOK) {
				len = 0;
				goto get_template_err;
			}
		}
		copy_string (&type_code_str, str_type_code, 0);
		buf += i;
		len += i;
		R_FREE (str_type_code);
	}
	if (*buf != '@') {
		len = 0;
		goto get_template_err;
	}
	if (i) {
		copy_string (&type_code_str, ">", 0);
	}
	buf++;
	len++;

	str_info->str_ptr = type_code_str.type_str;
	str_info->len = type_code_str.curr_pos;

get_template_err:
#if 0
	it = r_list_iterator (abbr_names);
	r_list_foreach (abbr_names, it, tmp) {
		R_FREE (tmp);
	}
	r_list_free (abbr_names);
	abbr_names = saved_abbr_names; // restore global list with name abbr.
#endif

	//    will be free at a caller function
	//    free_type_code_str_struct(&type_code_str);
	return len;
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
	char *curr_pos = NULL, *prev_pos = NULL;
	char *tmp = NULL;
	RList /* <SStrInfo *> */ *names_l = NULL;
	RListIter *it = NULL;
	SStrInfo *str_info = NULL;

	int len = 0, read_len = 0, tmp_len = 0;

	names_l = r_list_new ();

	if (*buf == '?') {
		int res = get_operator_code (buf, names_l);
		if (!res) {
			return 0;
		}
		buf += res;
		read_len += res;
	}

	prev_pos = buf;
	curr_pos = strchr (buf, '@');

	// hack for nested templates
	// think about how better to fix this...
	len = curr_pos - prev_pos;
	if (len == 0) {
		goto get_namespace_and_name_err;
	}

	while (curr_pos != NULL) {
		len = curr_pos - prev_pos;
		tmp = prev_pos;

		if ((len == 0) && (*(curr_pos) == '@')) {
			break;
		}

		// TODO:maybe add check of name correctness? like name can not start
		//		with number
		if ((len <= 0) || (len >= MICROSOFT_NAME_LEN)) {
			goto get_namespace_and_name_err;
		}

		// check is it teamplate???
		if ((*tmp == '?') && (*(tmp + 1) == '$')) {
			int i = 0;
			str_info = (SStrInfo *) malloc (sizeof(SStrInfo));
			i = get_template (tmp + 2, str_info);
			if (!i) {
				R_FREE (str_info);
				goto get_namespace_and_name_err;
			}
			r_list_append (names_l, str_info);

			prev_pos = tmp + i + 2;
			curr_pos = strchr(prev_pos, '@');
			read_len += (i + 2);
//			if (curr_pos)
//				read_len++;
			continue;
		}

		if (isdigit ((ut8)*tmp)) {
			tmp = r_list_get_n (abbr_names, *tmp - '0');
			if (!tmp) {
				goto get_namespace_and_name_err;
			}
			len = 1;
		} else {
			tmp = (char *) malloc (len + 1);
			memset (tmp, 0, len + 1);
			memcpy (tmp, prev_pos, len);
			r_list_append (abbr_names, tmp);
		}

		str_info = (SStrInfo *) malloc (sizeof (SStrInfo));
		str_info->str_ptr = tmp;
		str_info->len = strlen (tmp);

		r_list_append (names_l, str_info);

		read_len += len;
		if (len == 1) {
			if (*(prev_pos + 1) == '@') {
				prev_pos = curr_pos;
			} else {
				prev_pos++;
			}
		} else {
			prev_pos = curr_pos + 1;
			curr_pos = strchr(curr_pos + 1, '@');
			if (curr_pos) {
				read_len++;
			}
		}
	}

get_namespace_and_name_err:
	tmp_len = r_list_length(names_l);
	if (amount_of_names) {
		*amount_of_names = tmp_len;
	}
	it = r_list_iterator (names_l);
	r_list_foreach_prev (names_l, it, str_info) {
		copy_string(type_code_str, str_info->str_ptr, str_info->len);

		if (--tmp_len) {
			copy_string(type_code_str, "::", 0);
		}
		free(str_info);
	}
	r_list_free (names_l);

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
	(state)->amount_of_read_chars++; \
	(state)->buff_for_parsing++; \
	(state)->state = eTCStateEnd; \
}
#define ONE_LETTER_ACTIION(action, type) \
	static void tc_state_##action(SStateInfo *state, STypeCodeStr *type_code_str) \
	{ \
		if (copy_string(type_code_str, type, 0) == 0) { \
			state->err = eTCStateMachineErrAlloc; \
		} \
		state->state = eTCStateEnd; \
	} \

ONE_LETTER_ACTIION(X, "void")
ONE_LETTER_ACTIION(D, "char")
ONE_LETTER_ACTIION(C, "signed char")
ONE_LETTER_ACTIION(E, "unsigned char")
ONE_LETTER_ACTIION(F, "short int")
ONE_LETTER_ACTIION(G, "unsigned short int")
ONE_LETTER_ACTIION(H, "int")
ONE_LETTER_ACTIION(I, "unsigned int")
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
		PROCESS_CASE (J, "long long(__int64)")
		PROCESS_CASE (K, "unsigned long long(unsigned __int64)")
		PROCESS_CASE (T, "long double(80 bit precision)")
		PROCESS_CASE (Z, "long double(64 bit precision)")
		PROCESS_CASE (W, "wchar_t")
		PROCESS_CASE (N, "bool")
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
// isdigit need to check is it need to do deabbreviation of names
// +2 -> skipp @@  ( the end of class, union,...
// or +2 -> skip abbreviated_num + '@'
#define GET_USER_DEF_TYPE_NAME(data_struct_str) { \
	copy_string (type_code_str, data_struct_str, 0); \
\
	check_len = get_namespace_and_name (state->buff_for_parsing, type_code_str, 0); \
	if (check_len) { \
		state->amount_of_read_chars += check_len + 1; \
		state->buff_for_parsing += check_len + 1; \
	} else { \
		state->err = eTCStateMachineErrUncorrectTypeCode; \
	} \
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(T)
{
#define PROCESS_CASE(case_string, type_str) { \
	check_len = strlen (case_string); \
	if ((check_len < buff_len) && \
		(strncmp (state->buff_for_parsing, case_string, check_len) == 0)) { \
		copy_string (type_code_str, type_str, 0); \
		state->buff_for_parsing += check_len; \
		state->amount_of_read_chars += check_len; \
		return; \
	} \
}

	int buff_len = strlen (state->buff_for_parsing);
	int check_len = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE ("__m64@@", "__m64");
	PROCESS_CASE ("__m128@@", "__m128");
	PROCESS_CASE ("__m128i@@", "__m128i");
	PROCESS_CASE ("__m256@@", "__m256");
	PROCESS_CASE ("__m256i@@", "__m256i");
	PROCESS_CASE ("__m512@@", "__m512");
	PROCESS_CASE ("__m512i@@", "__m512i");

	GET_USER_DEF_TYPE_NAME ("union ");
#undef PROCESS_CASE
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(U)
{
#define PROCESS_CASE(case_string, type_str) { \
	check_len = strlen (case_string); \
	if ((check_len < buff_len) && \
		(strncmp (state->buff_for_parsing, case_string, check_len) == 0)) { \
		copy_string (type_code_str, type_str, 0); \
		state->amount_of_read_chars += check_len; \
		state->buff_for_parsing += check_len; \
		return; \
	} \
}

	int buff_len = strlen (state->buff_for_parsing);
	int check_len = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE ("__m128d@@", "__m128d");
	PROCESS_CASE ("__m256d@@", "__m256d");
	PROCESS_CASE ("__m512d@@", "__m512d");

	GET_USER_DEF_TYPE_NAME ("struct ");
#undef PROCESS_CASE
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(W)
{
	//W4X@@ -> enum X, W4X@Y@@ -> enum Y::X
	int check_len = 0;
	state->state = eTCStateEnd;

	if (*state->buff_for_parsing != '4') {
		state->err = eTCStateMachineErrUncorrectTypeCode;
	}

	state->buff_for_parsing++;
	state->amount_of_read_chars++;

	GET_USER_DEF_TYPE_NAME("enum ");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(V)
{
	// VX@@ -> class X
	int check_len = 0;
	state->state = eTCStateEnd;

	GET_USER_DEF_TYPE_NAME("class ");
}

///////////////////////////////////////////////////////////////////////////////
static char *get_num(SStateInfo *state)
{
	char *ptr = NULL;
	if (*state->buff_for_parsing >= '0' && *state->buff_for_parsing <= '8') {
		ptr = (char *) malloc (2);
		ptr[0] = *state->buff_for_parsing + 1;
		ptr[1] = '\0';
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	} else if (*state->buff_for_parsing == '9') {
		ptr = (char *) malloc (3);
		ptr[0] = '1';
		ptr[1] = '0';
		ptr[2] = '\0';
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	} else if (*state->buff_for_parsing >= 'A' && *state->buff_for_parsing <= 'P') {
		int ret = 0;

		while (*state->buff_for_parsing >= 'A' && *state->buff_for_parsing <= 'P') {
			ret *= 16;
			ret += *state->buff_for_parsing - 'A';
			state->buff_for_parsing++;
			state->amount_of_read_chars++;
		}

		if (*state->buff_for_parsing != '@') {
			return ptr;
		}

		ptr = (char *)malloc (16);
		sprintf (ptr, "%u", ret);
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	}

	return ptr;
}

#define MODIFIER(modifier_str) { \
	unsigned int i = 0; \
	EDemanglerErr err = eDemanglerErrOK; \
	char *tmp = NULL; \
	STypeCodeStr tmp_str; \
	STypeCodeStr modifier; \
	int flag__64ptr = 0; \
\
	state->state = eTCStateEnd; \
\
	if (!init_type_code_str_struct (&tmp_str)) { \
		state->err = eTCStateMachineErrAlloc; \
		return; \
	} \
	if (!init_type_code_str_struct (&modifier)) { \
		free_type_code_str_struct (&tmp_str); \
		state->err = eTCStateMachineErrAlloc; \
		return; \
	} \
\
	if (*state->buff_for_parsing == 'E') { \
		flag__64ptr = 1; \
		state->amount_of_read_chars++; \
		state->buff_for_parsing++; \
	} \
\
	switch (*state->buff_for_parsing++) { \
	case 'A': \
		break; \
	case 'B': \
		copy_string (&modifier, "const ", 0); \
		break; \
	case 'C': \
		copy_string (&modifier, "volatile ", 0); \
		break; \
	case 'D': \
		copy_string (&modifier, "const volatile ", 0); \
		break; \
	default: \
		state->err = eTCStateMachineErrUnsupportedTypeCode; \
		break; \
	} \
\
	state->amount_of_read_chars++;\
\
	if (*state->buff_for_parsing == 'Y') { \
		char *n1; \
		int num; \
\
		state->buff_for_parsing++; \
		state->amount_of_read_chars++; \
		if (!(n1 = get_num (state))) { \
			goto MODIFIER_err; \
		} \
		num = atoi (n1); \
		R_FREE (n1); \
\
		copy_string (&tmp_str, " ", 0); \
		copy_string (&tmp_str, "(", 0); \
		copy_string (&tmp_str, modifier.type_str, modifier.curr_pos); \
		copy_string (&tmp_str, modifier_str, 0); \
		copy_string (&tmp_str, ")", 0); \
\
		while (num--) { \
			n1 = get_num (state); \
			copy_string (&tmp_str, "[", 0); \
			copy_string (&tmp_str, n1, 0); \
			copy_string (&tmp_str, "]", 0); \
			R_FREE (n1); \
		} \
	} \
\
	if (tmp_str.curr_pos == 0) { \
		copy_string (&tmp_str, " ", 0); \
		copy_string (&tmp_str, modifier.type_str, modifier.curr_pos); \
		copy_string (&tmp_str, modifier_str, 0); \
		if (flag__64ptr) { \
			copy_string (&tmp_str, " __ptr64", 0); \
		} \
	} \
\
	err = get_type_code_string (state->buff_for_parsing, &i, &tmp); \
	if (err != eDemanglerErrOK) { \
		state->err = eTCStateMachineErrUnsupportedTypeCode; \
		goto MODIFIER_err; \
	} \
\
	state->amount_of_read_chars += i; \
	state->buff_for_parsing += i; \
	copy_string (type_code_str, tmp, 0); \
	copy_string (type_code_str, tmp_str.type_str, tmp_str.curr_pos); \
\
MODIFIER_err: \
	R_FREE (tmp); \
	free_type_code_str_struct (&tmp_str); \
	free_type_code_str_struct (&modifier); \
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(S)
{
	MODIFIER ("* const volatile");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(P)
{
	// function pointer
	if (isdigit ((ut8)*state->buff_for_parsing)) {
		if (*state->buff_for_parsing++ == '6') {
			char *call_conv = NULL;
			char *ret_type = NULL;
			char *arg = NULL;
			unsigned int i = 0;
			unsigned int is_abbr_type = 0;
			EDemanglerErr err;

			state->state = eTCStateEnd;

			// Calling convention
			switch (*state->buff_for_parsing++) {
			case 'A': call_conv = "__cdecl"; break;
			case 'B': call_conv = "__cdecl __declspec(dllexport)"; break;
			case 'C': call_conv = "__pascal"; break;
			case 'D': call_conv = "__pascal __declspec(dllexport)"; break;
			case 'E': call_conv = "__thiscall"; break;
			case 'F': call_conv = "__thiscall __declspec(dllexport)"; break;
			case 'G': call_conv = "__stdcall"; break;
			case 'H': call_conv = "__stdcall __declspec(dllexport)"; break;
			case 'I': call_conv = "__fastcall"; break;
			case 'J': call_conv = "__fastcall __declspec(dllexport)"; break;
			case 'K': call_conv = "default (none given)"; break;
			default:
				// XXX unify error messages into a single enum
				state->err = (ETCStateMachineErr)eDemanglerErrUncorrectMangledSymbol;
				break;
			}

			state->amount_of_read_chars += 2; // '6' + call_conv

			// return type
			err = get_type_code_string (state->buff_for_parsing, &i, &ret_type);
			if (err != eDemanglerErrOK) {
				state->err = eTCStateMachineErrUnsupportedTypeCode;
				goto FUNCTION_POINTER_err;
			}

			copy_string (type_code_str, ret_type, 0);
			copy_string (type_code_str, " (", 0);
			R_FREE (ret_type);

			if (call_conv) {
				copy_string (type_code_str, call_conv, 0);
			}

			copy_string (type_code_str, "*)(", 0);

			state->amount_of_read_chars += i;
			state->buff_for_parsing += i;

			//get args
			i = 0;
			while (*state->buff_for_parsing && *state->buff_for_parsing != 'Z') {
				if (*state->buff_for_parsing != '@') {
					if (i) {
						copy_string (type_code_str, ", ", 0);
					}

					err = get_type_code_string (state->buff_for_parsing, &i, &arg);
					if (err != eDemanglerErrOK) {
						// abbreviation of type processing
						if ((*state->buff_for_parsing >= '0') && (*state->buff_for_parsing <= '9')) {
							ut32 id = (ut32)(*state->buff_for_parsing - '0');
							arg = r_list_get_n (abbr_types, id);
							if (!arg) {
								state->err = eTCStateMachineErrUncorrectTypeCode;
								goto FUNCTION_POINTER_err;
							}
							i = 1;
							is_abbr_type = 1;
						} else {
							state->err = eTCStateMachineErrUncorrectTypeCode;
							goto FUNCTION_POINTER_err;
						}
					}

					if (i > 1) {
						r_list_append (abbr_types, strdup (arg));
					}

					copy_string (type_code_str, arg, 0);

					if (!is_abbr_type) {
						R_FREE (arg);
					}

					state->amount_of_read_chars += i;
					state->buff_for_parsing += i;
				} else {
					state->buff_for_parsing++;
					state->amount_of_read_chars++;
				}
			}
			copy_string (type_code_str, ")", 0);

			while (*state->buff_for_parsing == '@') {
				state->buff_for_parsing++;
				state->amount_of_read_chars++;
			}

			if (*(state->buff_for_parsing) != 'Z') {
				// XXX: invalid enum cast conversion
				state->state = (ETCState) eTCStateMachineErrUnsupportedTypeCode;
				goto FUNCTION_POINTER_err;
			}

			state->buff_for_parsing++;
			state->amount_of_read_chars++;

			FUNCTION_POINTER_err:
				return;
		}
	}

	MODIFIER ("*");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(R) {
	MODIFIER ("* volatile");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(Q) {
	MODIFIER ("* const");
}

///////////////////////////////////////////////////////////////////////////////
DEF_STATE_ACTION(A) {
	MODIFIER ("&");
}

#undef MODIFIER
#undef ONE_LETTER_ACTION
#undef GO_TO_NEXT_STATE
#undef DEF_STATE_ACTION

///////////////////////////////////////////////////////////////////////////////
static void tc_state_start(SStateInfo *state, STypeCodeStr *type_code_str) {
#define ONE_LETTER_STATE(letter) \
	case CHAR_WITH_QUOTES(letter): \
		state->state = eTCState##letter; \
		break; \

	switch (*(state->buff_for_parsing)) {
	ONE_LETTER_STATE (X)
	ONE_LETTER_STATE (D)
	ONE_LETTER_STATE (C)
	ONE_LETTER_STATE (E)
	ONE_LETTER_STATE (F)
	ONE_LETTER_STATE (G)
	ONE_LETTER_STATE (H)
	ONE_LETTER_STATE (I)
	ONE_LETTER_STATE (J)
	ONE_LETTER_STATE (K)
	ONE_LETTER_STATE (M)
	ONE_LETTER_STATE (N)
	ONE_LETTER_STATE (Z)
	ONE_LETTER_STATE (_)
	ONE_LETTER_STATE (T)
	ONE_LETTER_STATE (U)
	ONE_LETTER_STATE (W)
	ONE_LETTER_STATE (V)
	ONE_LETTER_STATE (O)
	ONE_LETTER_STATE (S)
	ONE_LETTER_STATE (P)
	ONE_LETTER_STATE (R)
	ONE_LETTER_STATE (Q)
	ONE_LETTER_STATE (A)
	default:
		//eprintf("[uncorrect type] error while parsing type\n");

		state->state = eTCStateEnd;
		state->err = eTCStateMachineErrUncorrectTypeCode;
		break;
	}

	state->amount_of_read_chars++;
	state->buff_for_parsing++;
#undef ONE_LETTER_STATE
}

///////////////////////////////////////////////////////////////////////////////
static void tc_state_end(SStateInfo *state, STypeCodeStr *type_code_str) {
	return;
}

///////////////////////////////////////////////////////////////////////////////
static void init_state_struct(SStateInfo *state, char *buff_for_parsing) {
	state->state = eTCStateStart;
	state->buff_for_parsing = buff_for_parsing;
	state->amount_of_read_chars = 0;
	state->err = eTCStateMachineErrOK;
}

///////////////////////////////////////////////////////////////////////////////
static int init_type_code_str_struct(STypeCodeStr *type_coder_str) {
#define TYPE_STR_LEN 1024
	// 1 - initialization finish with success, else - 0

	type_coder_str->type_str_len = TYPE_STR_LEN;

	type_coder_str->type_str = (char *) calloc (TYPE_STR_LEN, sizeof (char));
	if (!type_coder_str->type_str) {
		return 0;
	}
	memset (type_coder_str->type_str, 0, TYPE_STR_LEN * sizeof(char));

	type_coder_str->curr_pos = 0; // strlen ("unknown type");
//	strncpy(type_coder_str->type_str, "unknown_type", type_coder_str->curr_pos);

	return 1;
#undef TYPE_STR_LEN
}

///////////////////////////////////////////////////////////////////////////////
static void free_type_code_str_struct(STypeCodeStr *type_code_str) {
	if (type_code_str->type_str) {
		R_FREE (type_code_str->type_str);
	}
	type_code_str->type_str_len = 0;
}
///////////////////////////////////////////////////////////////////////////////
// End of machine functions for parsting type codes
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
static EDemanglerErr get_type_code_string(char *sym, unsigned int *amount_of_read_chars, char **str_type_code) {
	EDemanglerErr err = eDemanglerErrOK;
	char *tmp_sym = strdup(sym);
	STypeCodeStr type_code_str;
	SStateInfo state;

	if (!init_type_code_str_struct(&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto get_type_code_string_err;
	}

	init_state_struct (&state, tmp_sym);

	while (state.state != eTCStateEnd) {
		run_state (&state, &type_code_str);
		if (state.err != eTCStateMachineErrOK) {
			*str_type_code = NULL;
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

	*str_type_code = strdup (type_code_str.type_str);
	*amount_of_read_chars = state.amount_of_read_chars;

get_type_code_string_err:
	R_FREE (tmp_sym);
	free_type_code_str_struct (&type_code_str);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
/// public mangled name of global object:
/// <public name> ::= ?<name>@[<namespace>@](0->inf)@3<type><storage class>
/// mangled name of a static class member object:
/// <public name> ::= ?<name>@[<classname>@](1->inf)@2<type><storage class>
///////////////////////////////////////////////////////////////////////////////
static EDemanglerErr parse_microsoft_mangled_name(char *sym, char **demangled_name) {
	STypeCodeStr type_code_str;
	STypeCodeStr func_str;
	EDemanglerErr err = eDemanglerErrOK;

	int is_implicit_this_pointer = 0;
	int is_static = 0;
	unsigned int is_abbr_type = 0;

	char *access_modifier = NULL;
	char *memb_func_access_code = NULL;
	char *call_conv = NULL;
	char *storage_class_code_for_ret = NULL;
	char *ret_type = NULL;
	char *__64ptr = NULL;
	RList /* <char *> */ *func_args = NULL;
	RListIter *it = NULL;
	SStrInfo *str_arg = NULL;

	unsigned int i = 0;
	unsigned int len = 0;

	char *curr_pos = sym;
	char *tmp = NULL;
	char *ptr64 = NULL;
	char *storage_class = NULL;

	memset(&type_code_str, 0, sizeof(type_code_str));

	if (!init_type_code_str_struct (&func_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_microsoft_mangled_name_err;
	}

	if (!init_type_code_str_struct (&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_microsoft_mangled_name_err;
	}

	len = get_namespace_and_name (curr_pos, &type_code_str, (int*)&i);
	if (!len) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos += len + 1;

	// Function/Data type and access level
	switch (*curr_pos++) {
	// Data
	case '0' : // Private static member
	case '1' : // Protected static member
	case '2' : // Public static member
	case '3' : // Normal variable
	case '4' : // Normal variable
		i = 0;
		err = get_type_code_string (curr_pos, &i, &tmp);
		if (err != eDemanglerErrOK) {
			goto parse_microsoft_mangled_name_err;
		}

		curr_pos += i;

		i = strlen (curr_pos);
		if (!i || i > 2) {
			err = eDemanglerErrUncorrectMangledSymbol;
			R_FREE (tmp);
			goto parse_microsoft_mangled_name_err;
		}

		if (i == 2) {
			if (*curr_pos != 'E') {
				err = eDemanglerErrUncorrectMangledSymbol;
				R_FREE (tmp);
				goto parse_microsoft_mangled_name_err;
			}
			ptr64 = "__ptr64";
			curr_pos++;
		}

	#define SET_STORAGE_CLASS(letter, storage_class_str) { \
		case letter: \
			storage_class = storage_class_str; \
			break; \
	}

		switch (*curr_pos) {
		SET_STORAGE_CLASS ('A', 0);
		SET_STORAGE_CLASS ('B', "const");
		SET_STORAGE_CLASS ('C', "volatile");
		SET_STORAGE_CLASS ('D', "const volatile");
		default:
			err = eDemanglerErrUncorrectMangledSymbol;
			R_FREE (tmp);
			goto parse_microsoft_mangled_name_err;
		}
	#undef SET_STORAGE_CLASS

		if (err == eDemanglerErrOK) {
			if (!ptr64) {
				if (!storage_class) {
					*demangled_name = r_str_newf ("%s %s", tmp, type_code_str.type_str);
				} else {
					*demangled_name = r_str_newf ("%s %s %s", tmp, storage_class,type_code_str.type_str);
				}
			} else {
				if (!storage_class) {
					*demangled_name = r_str_newf ("%s %s %s", tmp, ptr64, type_code_str.type_str);
				} else {
					*demangled_name = r_str_newf ("%s %s %s %s", tmp, storage_class, ptr64, type_code_str.type_str);
				}
			}
		}
		goto parse_microsoft_mangled_name_err;

	case '6' : // compiler generated static
	case '7' : // compiler generated static
		err = eDemanglerErrUnsupportedMangling;
		break;

#define SET_ACCESS_MODIFIER(letter, flag_set, modifier_str) { \
	case letter: \
		access_modifier = modifier_str; \
		(flag_set) = 1; \
		break; \
}
	/* Functions */
	SET_ACCESS_MODIFIER ('E', is_implicit_this_pointer, "private virtual");
	SET_ACCESS_MODIFIER ('F', is_implicit_this_pointer, "private virtual");
	SET_ACCESS_MODIFIER ('M', is_implicit_this_pointer, "protected virtual");
	SET_ACCESS_MODIFIER ('N', is_implicit_this_pointer, "protected virtual");
	SET_ACCESS_MODIFIER ('U', is_implicit_this_pointer, "public virtual");
	SET_ACCESS_MODIFIER ('V', is_implicit_this_pointer, "public virtual");
	SET_ACCESS_MODIFIER ('A', is_implicit_this_pointer, "private");
	SET_ACCESS_MODIFIER ('B', is_implicit_this_pointer, "private");
	SET_ACCESS_MODIFIER ('I', is_implicit_this_pointer, "protected");
	SET_ACCESS_MODIFIER ('J', is_implicit_this_pointer, "protected");
	SET_ACCESS_MODIFIER ('Q', is_implicit_this_pointer, "public");
	SET_ACCESS_MODIFIER ('R', is_implicit_this_pointer, "public");
	SET_ACCESS_MODIFIER ('C', is_static, "private: static");
	SET_ACCESS_MODIFIER ('D', is_static, "private: static");
	SET_ACCESS_MODIFIER ('K', is_static, "protected: static");
	SET_ACCESS_MODIFIER ('L', is_static, "protected: static");
	SET_ACCESS_MODIFIER ('S', is_static, "public: static");
	SET_ACCESS_MODIFIER ('T', is_static, "public: static");
	case 'Y' : // near
	case 'Z' : // far
		break;
	default:
		err = eDemanglerErrUncorrectMangledSymbol;
	}
#undef SET_ACCESS_MODIFIER

	if (err != eDemanglerErrOK) {
		goto parse_microsoft_mangled_name_err;
	}

	// TODO: what?????
	if (*curr_pos == 'E') {
		__64ptr = "__ptr64";
		curr_pos++;
	}

	// member function access code
	if (is_implicit_this_pointer) {
		switch (*curr_pos++)
		{
		case 'A': break; // non-const
		case 'B': memb_func_access_code = "const"; break;
		case 'C': memb_func_access_code = "volatile"; break;
		case 'D': memb_func_access_code = "const volatile"; break;
		default:
			err = eDemanglerErrUncorrectMangledSymbol;
			break;
		}
	}

	// currently does not use because I can not find real example of
	// where to use this
	// just read in http://www.agner.org/optimize/calling_conventions.pdf
	// that this is possible
	// when some find the case where it is used please remove this (void)*
	// lines
	(void)is_static;

	if (err != eDemanglerErrOK) {
		goto parse_microsoft_mangled_name_err;
	}

	// Calling convention
	switch (*curr_pos++) {
		case 'A': call_conv = "__cdecl"; break;
		case 'B': call_conv = "__cdecl __declspec(dllexport)"; break;
		case 'C': call_conv = "__pascal"; break;
		case 'D': call_conv = "__pascal __declspec(dllexport)"; break;
		case 'E': call_conv = "__thiscall"; break;
		case 'F': call_conv = "__thiscall __declspec(dllexport)"; break;
		case 'G': call_conv = "__stdcall"; break;
		case 'H': call_conv = "__stdcall __declspec(dllexport)"; break;
		case 'I': call_conv = "__fastcall"; break;
		case 'J': call_conv = "__fastcall __declspec(dllexport)"; break;
		case 'K': call_conv = "default (none given)"; break;
		default:
			err = eDemanglerErrUncorrectMangledSymbol;
			break;
	}

	if (err != eDemanglerErrOK) {
		goto parse_microsoft_mangled_name_err;
	}

	// get storage class code for return
	if (*curr_pos == '?') {
		switch (*++curr_pos) {
		case 'A': break; // default
		case 'B': storage_class_code_for_ret = "const"; break;
		case 'C': storage_class_code_for_ret = "volatile"; break;
		case 'D': storage_class_code_for_ret = "const volatile"; break;
		default:
			err = eDemanglerErrUnsupportedMangling;
			goto parse_microsoft_mangled_name_err;
		}
		curr_pos++;
	}

	// Return type, or @ if 'void'
	if (*curr_pos == '@') {
		ret_type = strdup ("void");
		curr_pos++;
	}
	else {
		i = 0;
		err = get_type_code_string (curr_pos, &i, &ret_type);
		if (err != eDemanglerErrOK) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_microsoft_mangled_name_err;
		}

		curr_pos += i;
	}

	func_args = r_list_new ();

	// Function arguments
	while (*curr_pos && *curr_pos != 'Z')
	{
		if (*curr_pos != '@') {
			err = get_type_code_string (curr_pos, &i, &tmp);
			if (err != eDemanglerErrOK) {
				// abbreviation of type processing
				if ((*curr_pos >= '0') && (*curr_pos <= '9')) {
					tmp = r_list_get_n (abbr_types, (ut32)(*curr_pos - '0'));
					if (!tmp) {
						err = eDemanglerErrUncorrectMangledSymbol;
						goto parse_microsoft_mangled_name_err;
					}
					i = 1;
					is_abbr_type = 1;
				} else {
					err = eDemanglerErrUncorrectMangledSymbol;
					goto parse_microsoft_mangled_name_err;
				}
			}
			curr_pos += i;

			if (i > 1) {
				r_list_append (abbr_types, strdup (tmp));
			}

			str_arg = (SStrInfo *) malloc (sizeof(SStrInfo));
			str_arg->str_ptr = strdup (tmp);
			str_arg->len = strlen (tmp);

			r_list_append (func_args, str_arg);

			if (strncmp (tmp, "void", 4) == 0 && strlen (tmp) == 4) {
				// arguments list is void
				if (!is_abbr_type) {
					R_FREE (tmp);
				}
				break;
			}
			if (!is_abbr_type) {
				R_FREE (tmp);
			}
		} else {
			curr_pos++;
		}
	}

	while (*curr_pos == '@') {
		curr_pos++;
	}

	if (*curr_pos != 'Z') {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	if (access_modifier) {
		copy_string (&func_str, access_modifier, 0);
		if (!strstr (access_modifier, "static")) {
			copy_string (&func_str, ": ", 0);
		} else {
			copy_string (&func_str, " ", 0);
		}
	}

	if (storage_class_code_for_ret) {
		copy_string (&func_str, storage_class_code_for_ret, 0);
		copy_string (&func_str, " ", 0);
	}

	if (ret_type) {
		copy_string (&func_str, ret_type, 0);
		copy_string (&func_str, " ", 0);
	}

	if (call_conv) {
		copy_string (&func_str, call_conv, 0);
		copy_string (&func_str, " ", 0);
	}

	if (type_code_str.type_str) {
		copy_string (&func_str, type_code_str.type_str, type_code_str.curr_pos);
	}

	if (r_list_length (func_args)) {
		copy_string (&func_str, "(", 0);
		i = r_list_length (func_args);
		r_list_foreach (func_args, it, str_arg) {
			copy_string (&func_str, str_arg->str_ptr, 0);
			if (--i) {
				copy_string (&func_str, ", ", 0);
			}
			R_FREE (str_arg->str_ptr);
			R_FREE (str_arg);
		}
		copy_string (&func_str, ")", 0);
	}

	if (memb_func_access_code) {
			copy_string (&func_str, memb_func_access_code, 0);
	}

	if (__64ptr) {
		copy_string (&func_str, " ", 0);
		copy_string (&func_str, __64ptr, 0);
	}

	if (ret_type) {
		if (strstr (func_str.type_str, "#{return_type}")) {
			func_str.type_str = r_str_replace (func_str.type_str, "#{return_type}", ret_type, 0);
			func_str.curr_pos -= strlen ("#{return_type}") - strlen (ret_type);
		}
	}

	// need to be free by user
	if (func_str.type_str) {
		*demangled_name = strdup (func_str.type_str);
	}

parse_microsoft_mangled_name_err:
	R_FREE (ret_type);
//	R_FREE (tmp);
	free_type_code_str_struct (&type_code_str);
	free_type_code_str_struct (&func_str);
	r_list_free (func_args);
	return err;
}

static EDemanglerErr parse_microsoft_rtti_mangled_name(char *sym, char **demangled_name) {
	EDemanglerErr err = eDemanglerErrOK;
	char *type = NULL;
	if (!strncmp (sym, "AT", 2)) {
		type = "union";
	} else if (!strncmp (sym, "AU", 2)) {
		type = "struct";
	} else if (!strncmp (sym, "AV", 2)) {
		type = "class";
	} else if (!strncmp (sym, "AW", 2)) {
		type = "enum";
	} else {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_rtti_mangled_name_err;
	}
	STypeCodeStr type_code_str;
	if (!init_type_code_str_struct(&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_microsoft_rtti_mangled_name_err;
	}
	int len = get_namespace_and_name (sym + 2, &type_code_str, NULL);
	if (!len) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_rtti_mangled_name_err;
	}

	*demangled_name = r_str_newf ("%s %s", type, type_code_str.type_str);
	free (type_code_str.type_str);

parse_microsoft_rtti_mangled_name_err:
	return err;
}

///////////////////////////////////////////////////////////////////////////////
EDemanglerErr microsoft_demangle(SDemangler *demangler, char **demangled_name) {
	EDemanglerErr err = eDemanglerErrOK;
//	RListIter *it = NULL;
//	char *tmp = NULL;

	// TODO: need refactor... maybe remove the static variable somewhere?
	abbr_types = r_list_newf (free);
	abbr_names = r_list_newf (free);

	if (!demangler || !demangled_name) {
		err = eDemanglerErrMemoryAllocation;
		goto microsoft_demangle_err;
	}
	
	if (!strncmp (demangler->symbol, ".?", 2)) {
		err = parse_microsoft_rtti_mangled_name (demangler->symbol + 2, demangled_name);
	} else {
		err = parse_microsoft_mangled_name (demangler->symbol + 1, demangled_name);
	}

microsoft_demangle_err:
	r_list_free (abbr_names);
	r_list_free (abbr_types);
	return err;
}

#undef GET_USER_DEF_TYPE_NAME
