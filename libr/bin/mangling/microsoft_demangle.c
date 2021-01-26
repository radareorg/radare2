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
	eTCStateO, eTCStateS, eTCStateP, eTCStateR, eTCStateQ, eTCStateA, eTCState$,
	eTCStateMax
} ETCState;

typedef struct STypeCodeStr {
	char *type_str;
	size_t type_str_len;
	size_t curr_pos;
} STypeCodeStr;

struct SStateInfo;
typedef void (*state_func)(struct SStateInfo *, STypeCodeStr *type_code_str);

typedef struct SStateInfo {
	ETCState state;
	const char *buff_for_parsing;
	size_t amount_of_read_chars;
	ETCStateMachineErr err;
} SStateInfo;

typedef struct SStrInfo {
	char *str_ptr;
	size_t len;
} SStrInfo;

typedef struct SDataType {
	char *left;
	char *right;
} SDataType;

static void sstrinfo_free(SStrInfo *sstrinfo) {
	free (sstrinfo->str_ptr);
	free (sstrinfo);
}

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
DECL_STATE_ACTION($)
#undef DECL_STATE_ACTION

#define NAME(action) tc_state_##action
static state_func const state_table[eTCStateMax] = {
	NAME(start), NAME(end) , NAME(H), NAME(X), NAME(N), NAME(D), NAME(C), NAME(E),
	NAME(F), NAME(G), NAME(I), NAME(J), NAME(K), NAME(M), NAME(Z), NAME(_),
	NAME(T), NAME(U), NAME(W), NAME(V), NAME(O), NAME(S), NAME(P), NAME(R),
	NAME(Q), NAME(A), NAME($)
};
#undef NAME
///////////////////////////////////////////////////////////////////////////////
// End of data types for state machine which parse type codes
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// State machine for parsing type codes functions
///////////////////////////////////////////////////////////////////////////////

static void init_state_struct(SStateInfo *state, const char *buff_for_parsing);
static EDemanglerErr get_type_code_string(const char *sym, size_t *amount_of_read_chars, char **str_type_code);
static bool init_type_code_str_struct(STypeCodeStr *type_coder_str);
static void free_type_code_str_struct(STypeCodeStr *type_code_str);
static size_t get_template(const char *buf, SStrInfo *str_info, bool memorize);
static char *get_num(SStateInfo *state);
static EDemanglerErr parse_data_type(const char *sym, SDataType *demangled_type, size_t *len);
static size_t get_namespace_and_name(const char *buf, STypeCodeStr *type_code_str, size_t *amount_of_names, bool memorize);
static inline EDemanglerErr get_storage_class(const char encoded, const char **storage_class);
static inline size_t get_ptr_modifier(const char encoded, SDataType *ptr_modifier);
static EDemanglerErr parse_function(const char *sym, STypeCodeStr *type_code_str, char **demangled_function, size_t *chars_read);
static EDemanglerErr parse_microsoft_mangled_name(const char *sym, char **demangled_name, size_t *chars_read);
static EDemanglerErr parse_microsoft_rtti_mangled_name(const char *sym, char **demangled_name, size_t *chars_read);

static void run_state(SStateInfo *state_info, STypeCodeStr *type_code_str) {
	state_table[state_info->state](state_info, type_code_str);
}

static int copy_string(STypeCodeStr *type_code_str, const char *str_for_copy, size_t copy_len) {
	int res = 1; // all is OK
	size_t str_for_copy_len = (copy_len == 0 && str_for_copy) ? strlen (str_for_copy) : copy_len;
	size_t free_space = type_code_str->type_str_len - type_code_str->curr_pos - 1;

	if (free_space < str_for_copy_len) {
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

static int get_template_params(const char *sym, size_t *amount_of_read_chars, char **str_type_code) {
	SStateInfo state;
	init_state_struct (&state, sym);
	const char template_param[] = "template-parameter-";
	char *tmp, *res = NULL;
	const char *const start_sym = sym;
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
			return eDemanglerErrUncorrectMangledSymbol;
		}
		sym++;
		state.amount_of_read_chars += 2;
		state.buff_for_parsing += 2;
		char *a, *b, *c;
		switch (*sym) {
		case '0':
			// Signed integer
			a = get_num (&state);
			if (a) {
				int signed_a = atoi (a);
				res = r_str_newf ("%d", signed_a);
				free (a);
			}
			break;
		case '1': {
			STypeCodeStr str;
			EDemanglerErr err;
			if (!init_type_code_str_struct (&str)) {
				return eDemanglerErrMemoryAllocation;
			}
			sym += 2;
			size_t ret = get_namespace_and_name (sym, &str, NULL, true);
			if (!ret) {
				free_type_code_str_struct (&str);
				return eDemanglerErrUncorrectMangledSymbol;
			}
			sym += ret + 1;
			SDataType data_type;
			if (isdigit ((unsigned char)*sym)) {
				err = parse_data_type (sym, &data_type, &ret);
				*str_type_code = r_str_newf ("&%s %s%s", data_type.left, str.type_str, data_type.right);
				free (data_type.left);
				free (data_type.right);
			} else {
				char *tmp = NULL;
				err = parse_function (sym, &str, &tmp, &ret);
				*str_type_code = r_str_newf ("&%s", tmp);
				free (tmp);
			}
			sym += ret;
			*amount_of_read_chars = sym - start_sym;
			free_type_code_str_struct (&str);
			return err;
		}
		case '2':
			// real value a ^ b
			a = get_num (&state);
			b = get_num (&state);
			if (a && b) {
				int signed_b = atoi (b);
				res = r_str_newf ("%sE%d", a, signed_b);
			}
			free (a);
			free (b);
			break;
		case 'D':
			// anonymous template param
			res = get_num (&state);
			if (res) {
				tmp = r_str_newf ("%s%s", template_param, res);
				free (res);
				res = tmp;
			}
			break;
		case 'F':
			// Signed {a, b}
			a = get_num (&state);
			b = get_num (&state);
			if (a && b) {
				int signed_a = atoi (a);
				int signed_b = atoi (b);
				res = r_str_newf ("{%d, %d}", signed_a, signed_b);
			}
			free (a);
			free (b);
			break;
		case 'G':
			// Signed {a, b, c}
			a = get_num (&state);
			b = get_num (&state);
			c = get_num (&state);
			if (a && b && c) {
				int signed_a = atoi (a);
				int signed_b = atoi (b);
				int signed_c = atoi (c);
				res = r_str_newf ("{%d, %d, %d}", signed_a, signed_b, signed_c);
			}
			free (a);
			free (b);
			free (c);
			break;
		case 'H':
			// Unsigned integer
			res = get_num (&state);
			break;
		case 'I':
			// Unsigned {x, y}
			a = get_num (&state);
			b = get_num (&state);
			if (a && b) {
				res = r_str_newf ("{%s, %s}", a, b);
			}
			free (a);
			free (b);
			break;
		case 'J':
			// Unsigned {x, y, z}
			a = get_num (&state);
			b = get_num (&state);
			c = get_num (&state);
			if (a && b && c) {
				res = r_str_newf ("{%s, %s, %s}", a, b, c);
			}
			free (a);
			free (b);
			free (c);
			break;
		case 'Q':
			// anonymous non-type template parameter
			res = get_num (&state);
			if (res) {
				tmp = r_str_newf("non-type-%s%s", template_param, res);
				free (res);
				res = tmp;
			}
			break;
		default:
			break;
		}
	}

	if (!res) {
		return eDemanglerErrUnsupportedMangling;
	}

	*str_type_code = res;
	*amount_of_read_chars = state.amount_of_read_chars;

	return eDemanglerErrOK;
}

static size_t get_operator_code(const char *buf, RList *names_l, bool memorize) {
	// C++ operator code (one character, or two if the first is '_')
#define SET_OPERATOR_CODE(str) { \
	str_info = malloc (sizeof (SStrInfo)); \
	if (!str_info) break; \
	str_info->len = strlen (str); \
	str_info->str_ptr = strdup (str); \
	r_list_append (names_l, str_info); \
}	
	SStrInfo *str_info;
	size_t read_len = 1;
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
		str_info = malloc (sizeof (SStrInfo));
		if (!str_info) {
			break;
		}
		size_t i = get_template (buf + 1, str_info, memorize);
		if (!i) {
			R_FREE (str_info);
			return 0;
		}
		r_list_append (names_l, str_info);
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
		case 'R':
			switch (*++buf) {
			case '0': {
				size_t len;
				char *str = NULL;
				if (parse_microsoft_rtti_mangled_name (buf + 2, &str, &len) != eDemanglerErrOK) {
					r_list_free (names_l);
					return 0;
				}
				read_len += len + 2;
				str = r_str_append (str, " `RTTI Type Descriptor'");
				SET_OPERATOR_CODE (str);
				free (str);
				break;
			}
			case '1': {
				SStateInfo state;
				init_state_struct (&state, buf + 1);
				char *a = get_num (&state);
				char *b = get_num (&state);
				char *c = get_num (&state);
				char *d = get_num (&state);
				if (!a || !b || !c || !d) {
					r_list_free (names_l);
					return 0;
				}
				read_len += state.amount_of_read_chars + 1;
				r_str_newf ("`RTTI Base Class Descriptor at (%s,%s,%s,%s)'", a, b, c, d);
				break;
			}
			case '2': SET_OPERATOR_CODE ("`RTTI Base Class Array'"); break;
			case '3': SET_OPERATOR_CODE ("`RTTI Class Hierarchy Descriptor'"); break;
			case '4': SET_OPERATOR_CODE ("`RTTI Complete Object Locator'"); break;
			default: return 0;
			}
			break;
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
static size_t get_template(const char *buf, SStrInfo *str_info, bool memorize) {
	size_t len = 0;
	char *str_type_code = NULL;
	STypeCodeStr type_code_str;
	// RListIter *it = NULL;
	RList *saved_abbr_names = abbr_names;	// save current abbr names, this
	RList *new_abbr_names = r_list_newf (free);

	if (!init_type_code_str_struct(&type_code_str)) {
		goto get_template_err;
	}

	if (*buf == '?') {
		RList *names_l = r_list_newf ((RListFree)sstrinfo_free);
		if (!names_l) {
			return 0;
		}
		size_t i = get_operator_code (buf, names_l, memorize);
		if (!i) {
			return 0;
		}
		len += i;
		buf += i;
		SStrInfo *name = r_list_head (names_l)->data;
		copy_string (&type_code_str, name->str_ptr, name->len);
		r_list_free (names_l);
	} else {
		char *tmp = strchr(buf, '@');
		if (!tmp) {
			goto get_template_err;
		}

		// get/copy template len/name
		len += (tmp - buf + 1);
		copy_string (&type_code_str, buf, len - 1);
		r_list_append (new_abbr_names, r_str_ndup (buf, len - 1));
		buf += len;
	}

	if (*buf != '@') {
		copy_string (&type_code_str, "<", 0);
	}

	abbr_names = new_abbr_names;

	// get identifier
	size_t i = 0;
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
	r_list_free (new_abbr_names);
	abbr_names = saved_abbr_names; // restore global list with name abbr.

	if (memorize) {
		r_list_append (abbr_names, strdup (type_code_str.type_str));
	}

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
static size_t get_namespace_and_name(const char *buf, STypeCodeStr *type_code_str, size_t *amount_of_names, bool memorize) {
	const char *curr_pos = NULL, *prev_pos = NULL, *tmp = NULL;
	RList /* <SStrInfo *> */ *names_l = NULL;
	RListIter *it = NULL;
	SStrInfo *str_info = NULL;

	size_t len = 0, read_len = 0, tmp_len = 0;

	names_l = r_list_newf ((RListFree)sstrinfo_free);

	if (*buf == '?') {
		size_t res = get_operator_code (buf, names_l, memorize);
		if (!res) {
			return 0;
		}
		memorize = true;
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

		str_info = malloc (sizeof (SStrInfo));
		if (!str_info) {
			break;
		}

		// check is it teamplate???
		if ((*tmp == '?') && (*(tmp + 1) == '$')) {
			size_t i = 0;
			i = get_template (tmp + 2, str_info, memorize);
			if (!i) {
				R_FREE (str_info);
				goto get_namespace_and_name_err;
			}
			r_list_append (names_l, str_info);

			prev_pos = tmp + i + 2;
			curr_pos = strchr (prev_pos, '@');
			read_len += i + 2;
//			if (curr_pos)
//				read_len++;
			continue;
		}

		if ((*tmp == '?') && (*(tmp + 1) == 'Q')) {
			STypeCodeStr str;
			if (!init_type_code_str_struct (&str)) {
				break;
			}
			size_t i = get_namespace_and_name (tmp + 2, &str, NULL, true);
			if (!i) {
				break;
			}
			prev_pos = tmp + i + 3;
			curr_pos = strchr (prev_pos, '@');
			read_len += i + 3;
			str_info->str_ptr = r_str_newf ("[%s]", str.type_str);
			str_info->len = strlen (str_info->str_ptr);
			r_list_append (names_l, str_info);
			free (str.type_str);
			continue;
		}
		
		// Nested name
		if (*tmp == '?') {
			read_len++;
			// Optional sequence number
			char *num = NULL;
			if (*(tmp + 1) != '?') {
				SStateInfo state;
				init_state_struct (&state, tmp + 1);
				num = get_num (&state);
				tmp += state.amount_of_read_chars + 1;
				read_len += state.amount_of_read_chars + 1;
			}
			char *demangled;
			if (parse_microsoft_mangled_name (tmp + 2, &demangled, &len) != eDemanglerErrOK) {
				break;
			}
			read_len += len + 1;
			if (num) {
				str_info->str_ptr = r_str_newf ("`%s'::`%s'", demangled, num);
				free (num);
			} else {
				str_info->str_ptr = r_str_newf ("`%s'", demangled);
			}

			str_info->len = strlen (str_info->str_ptr);
			r_list_append (names_l, str_info);
			r_list_append (abbr_names, strdup (str_info->str_ptr));
			free (demangled);
			break;
		}

		if (isdigit ((ut8)*tmp)) {
			tmp = r_list_get_n (abbr_names, *tmp - '0');
			if (!tmp) {
				break;
			}
			len = 1;
		} else {
			char *tmpname = malloc (len + 1);
			memset (tmpname, 0, len + 1);
			memcpy (tmpname, prev_pos, len);
			r_list_append (abbr_names, tmpname);
			tmp = tmpname;
		}

		str_info->str_ptr = strdup (tmp);
		str_info->len = strlen (tmp);

		r_list_append (names_l, str_info);

		memorize = true;

		read_len += len;
		if (len == 1) {
			if (*(prev_pos + 1) == '@') {
				prev_pos = curr_pos;
			} else {
				prev_pos++;
			}
		} else {
			prev_pos = curr_pos + 1;
			curr_pos = strchr (curr_pos + 1, '@');
			if (curr_pos) {
				read_len++;
			}
		}
	}

get_namespace_and_name_err:
	tmp_len = r_list_length (names_l);
	if (amount_of_names) {
		*amount_of_names = tmp_len;
	}
	it = r_list_iterator (names_l);
	r_list_foreach_prev (names_l, it, str_info) {
		copy_string (type_code_str, str_info->str_ptr, str_info->len);

		if (--tmp_len) {
			copy_string (type_code_str, "::", 0);
		}
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
#define SINGLEQUOTED_$ '$'
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
	check_len = get_namespace_and_name (state->buff_for_parsing, type_code_str, NULL, true); \
	if (check_len) { \
		state->amount_of_read_chars += check_len; \
		state->buff_for_parsing += check_len; \
		if (*state->buff_for_parsing) { \
			state->buff_for_parsing++; \
			state->amount_of_read_chars++; \
		} \
	} else { \
		state->err = eTCStateMachineErrUncorrectTypeCode; \
	} \
}

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

	size_t buff_len = strlen (state->buff_for_parsing);
	size_t check_len = 0;

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

	size_t buff_len = strlen (state->buff_for_parsing);
	size_t check_len = 0;

	state->state = eTCStateEnd;

	PROCESS_CASE ("__m128d@@", "__m128d");
	PROCESS_CASE ("__m256d@@", "__m256d");
	PROCESS_CASE ("__m512d@@", "__m512d");

	GET_USER_DEF_TYPE_NAME ("struct ");
#undef PROCESS_CASE
}

DEF_STATE_ACTION(W)
{
	//W4X@@ -> enum X, W4X@Y@@ -> enum Y::X
	size_t check_len = 0;
	state->state = eTCStateEnd;

	if (*state->buff_for_parsing != '4') {
		state->err = eTCStateMachineErrUncorrectTypeCode;
	}

	state->buff_for_parsing++;
	state->amount_of_read_chars++;

	GET_USER_DEF_TYPE_NAME("enum ");
}

DEF_STATE_ACTION(V)
{
	// VX@@ -> class X
	size_t check_len = 0;
	state->state = eTCStateEnd;

	GET_USER_DEF_TYPE_NAME("class ");
}

#undef GET_USER_DEF_TYPE_NAME

static char *get_num(SStateInfo *state) {
	char *ptr = NULL;
	if (*state->buff_for_parsing >= '0' && *state->buff_for_parsing <= '8') {
		ptr = malloc (2);
		if (!ptr) {
			return NULL;
		}
		ptr[0] = *state->buff_for_parsing + 1;
		ptr[1] = '\0';
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	} else if (*state->buff_for_parsing == '9') {
		ptr = strdup ("10");
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	} else if (*state->buff_for_parsing >= 'A' && *state->buff_for_parsing <= 'P') {
		ut32 ret = 0;

		while (*state->buff_for_parsing >= 'A' && *state->buff_for_parsing <= 'P') {
			ret *= 16;
			ret += *state->buff_for_parsing - 'A';
			state->buff_for_parsing++;
			state->amount_of_read_chars++;
		}

		if (*state->buff_for_parsing != '@') {
			return NULL;
		}

		ptr = r_str_newf ("%u", ret);
		state->buff_for_parsing++;
		state->amount_of_read_chars++;
	}

	return ptr;
}

static inline void parse_type_modifier(SStateInfo *state, STypeCodeStr *type_code_str, const char *modifier_str) {
	size_t i = 0;
	EDemanglerErr err = eDemanglerErrOK;
	char *tmp = NULL;
	STypeCodeStr tmp_str;
	STypeCodeStr modifier;
	bool is_pin_ptr = false;
	char clr_type = '\0';

	state->state = eTCStateEnd;

	if (!init_type_code_str_struct (&tmp_str)) {
		state->err = eTCStateMachineErrAlloc;
		return;
	}
	if (!init_type_code_str_struct (&modifier)) {
		free_type_code_str_struct (&tmp_str);
		state->err = eTCStateMachineErrAlloc;
		return;
	}

	if (*state->buff_for_parsing == '$') {
		if (state->buff_for_parsing[1] == '0') {
			// TODO: no idea what this means
			state->buff_for_parsing += 3;
			state->amount_of_read_chars += 3;
		}
	}

	SDataType mod;
	i = get_ptr_modifier (*state->buff_for_parsing, &mod);
	state->buff_for_parsing += i;
	state->amount_of_read_chars += i;

	if (*state->buff_for_parsing == '$') {
		state->buff_for_parsing++;
		switch (*state->buff_for_parsing++) {
		case 'A':
			clr_type = '^';
			break;
		case 'B': // cli::pin_ptr<T>
			is_pin_ptr = true;
			break;
		case 'C':
			clr_type = '%';
			break;
		default:
			state->err = eTCStateMachineErrUnsupportedTypeCode;
			break;
		}
		state->amount_of_read_chars += 2;
	}
	
	SDataType mod2;
	i = get_ptr_modifier (*state->buff_for_parsing, &mod2);
	state->buff_for_parsing += i;
	state->amount_of_read_chars += i;

	const char *storage_class;
	if (get_storage_class (*state->buff_for_parsing, &storage_class) != eDemanglerErrOK) {
		state->err = eTCStateMachineErrUnsupportedTypeCode;
		goto MODIFIER_err;
	}
	if (storage_class) {
		copy_string (&modifier, storage_class, 0);
		copy_string (&modifier, " ", 1);
	}
	copy_string (&modifier, mod2.left, 0);

	state->buff_for_parsing++;
	state->amount_of_read_chars++;

	if (*state->buff_for_parsing == 'Y') {
		char *n1;
		int num;

		state->buff_for_parsing++;
		state->amount_of_read_chars++;
		if (!(n1 = get_num (state))) {
			goto MODIFIER_err;
		}
		num = atoi (n1);
		R_FREE (n1);

		copy_string (&tmp_str, " ", 0);
		copy_string (&tmp_str, "(", 0);
		copy_string (&tmp_str, modifier.type_str, modifier.curr_pos);
		copy_string (&tmp_str, modifier_str, 0);
		copy_string (&tmp_str, ")", 0);

		while (num--) {
			n1 = get_num (state);
			copy_string (&tmp_str, "[", 0);
			copy_string (&tmp_str, n1, 0);
			copy_string (&tmp_str, "]", 0);
			R_FREE (n1);
		}
	}

	if (tmp_str.curr_pos == 0) {
		copy_string (&tmp_str, " ", 0);
		copy_string (&tmp_str, modifier.type_str, modifier.curr_pos);
		copy_string (&tmp_str, mod.left, 0);
		if (clr_type) {
			char *str = strdup (modifier_str);
			if (!str) {
				state->err = eTCStateMachineErrAlloc;
				goto MODIFIER_err;
			}
			*str = clr_type;
			copy_string (&tmp_str, str, 0);
			free (str);
		} else {
			if (is_pin_ptr) {
				while (*++modifier_str == ' ') {};
			}
			copy_string (&tmp_str, modifier_str, 0);
		}
		copy_string (&tmp_str, mod2.right, 0);
	}

	if (!strncmp (state->buff_for_parsing, "__Z", 3)) {
		// TODO: no idea what this means
		state->buff_for_parsing += 3;
		state->amount_of_read_chars += 3;
	}

	err = get_type_code_string (state->buff_for_parsing, &i, &tmp);
	if (err != eDemanglerErrOK) {
		state->err = eTCStateMachineErrUnsupportedTypeCode;
		goto MODIFIER_err;
	}

	state->amount_of_read_chars += i;
	state->buff_for_parsing += i;
	if (is_pin_ptr) {
		copy_string (type_code_str, "cli::pin_ptr<", 0);
	}
	copy_string (type_code_str, tmp, 0);
	copy_string (type_code_str, tmp_str.type_str, tmp_str.curr_pos);
	if (is_pin_ptr) {
		copy_string (type_code_str, ">", 0);
	}
	copy_string (type_code_str, mod.right, 0);

MODIFIER_err:
	R_FREE (tmp);
	free_type_code_str_struct (&tmp_str);
	free_type_code_str_struct (&modifier);
}

DEF_STATE_ACTION(S)
{
	parse_type_modifier (state, type_code_str, "* const volatile");
}

static inline const char *get_calling_convention(char calling_convention) {
	switch (calling_convention) {
		case 'A': return "__cdecl";
		case 'B': return "__cdecl __declspec(dllexport)";
		case 'C': return "__pascal";
		case 'D': return "__pascal __declspec(dllexport)";
		case 'E': return "__thiscall";
		case 'F': return "__thiscall __declspec(dllexport)";
		case 'G': return "__stdcall";
		case 'H': return "__stdcall __declspec(dllexport)";
		case 'I': return "__fastcall";
		case 'J': return "__fastcall __declspec(dllexport)";
		case 'K': return "default (none given)";
		case 'L': return "default (none given) __declspec(dllexport)";
		case 'M': return "__clrcall";
		default: return NULL;
	}
}

static EDemanglerErr parse_function_args(const char *sym, char **demangled_args, size_t *read_chars) {
	EDemanglerErr err = eDemanglerErrOK;
	const char *curr_pos = sym;
	size_t len = 0;

	STypeCodeStr func_str;
	if (!init_type_code_str_struct (&func_str)) {
		return eDemanglerErrMemoryAllocation;
	}

	copy_string (&func_str, "(", 0);

	// Function arguments
	while (*curr_pos && *curr_pos != 'Z') {
		if (*curr_pos != '@') {
			char *tmp;
			bool is_abbr_type = false;
			if (len) {
				copy_string (&func_str, ", ", 0);
			}
			err = get_type_code_string (curr_pos, &len, &tmp);
			if (err != eDemanglerErrOK) {
				// abbreviation of type processing
				if ((*curr_pos >= '0') && (*curr_pos <= '9')) {
					free (tmp);
					tmp = r_list_get_n (abbr_types, (ut32)(*curr_pos - '0'));
					if (!tmp) {
						err = eDemanglerErrUncorrectMangledSymbol;
						break;
					}
					err = eDemanglerErrOK;
					len = 1;
					is_abbr_type = true;
				} else {
					err = eDemanglerErrUncorrectMangledSymbol;
					free (tmp);
					break;
				}
			}
			curr_pos += len;

			if (len > 1) {
				r_list_append (abbr_types, strdup (tmp));
			}

			copy_string (&func_str, tmp, 0);

			if (!strcmp (tmp, "void")) {
				// arguments list is void
				if (!is_abbr_type) {
					free (tmp);
				}
				break;
			}
			if (!is_abbr_type) {
				free (tmp);
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
	}
	
	copy_string (&func_str, ")", 0);

	if (demangled_args) {
		*demangled_args = strdup (func_str.type_str);
	}

	free_type_code_str_struct (&func_str);

	if (read_chars) {
		*read_chars = curr_pos - sym + 1;
	}

	return err;
}

// TODO: use parse_function() instead
static void pf(SStateInfo *state, STypeCodeStr *type_code_str, const char *pointer_str) {
	const char *call_conv = NULL;
	const char *storage = NULL;
	char *ret_type = NULL;
	size_t i = 0;
	EDemanglerErr err;

	state->state = eTCStateEnd;

	// Calling convention
	call_conv = get_calling_convention (*state->buff_for_parsing++);
	if (!call_conv) {
		// XXX unify error messages into a single enum
		state->err = (ETCStateMachineErr)eDemanglerErrUncorrectMangledSymbol;
	}

	state->amount_of_read_chars += 2; // '6' + call_conv

	// return type
	if (*state->buff_for_parsing == '?') {
		err = get_storage_class (*++state->buff_for_parsing, &storage);
		if (err != eDemanglerErrOK) {
			state->err = eTCStateMachineErrUncorrectTypeCode;
			return;
		}
		state->buff_for_parsing++;
		state->amount_of_read_chars += 2;
	}
	err = get_type_code_string (state->buff_for_parsing, &i, &ret_type);
	if (err != eDemanglerErrOK) {
		state->err = eTCStateMachineErrUnsupportedTypeCode;
		return;
	}

	copy_string (type_code_str, ret_type, 0);
	if (storage) {
		copy_string (type_code_str, " ", 1);
		copy_string (type_code_str, storage, 0);
	}
	copy_string (type_code_str, " (", 0);
	R_FREE (ret_type);

	copy_string (type_code_str, call_conv, 0);
	copy_string (type_code_str, " ", 1);
	copy_string (type_code_str, pointer_str, 0);
	copy_string (type_code_str, ")", 1);

	state->amount_of_read_chars += i;
	state->buff_for_parsing += i;

	char *demangled_args;
	if (parse_function_args (state->buff_for_parsing, &demangled_args, &i) != eDemanglerErrOK) {
		state->err = eTCStateMachineErrUncorrectTypeCode;
		return;
	}
	state->amount_of_read_chars += i;
	state->buff_for_parsing += i;
	copy_string (type_code_str, demangled_args, 0);
	free (demangled_args);
	return;
}

static void parse_pointer(SStateInfo *state, STypeCodeStr *type_code_str, const char *pointer_str) {
	if (isdigit ((ut8)*state->buff_for_parsing)) {
		ut8 digit = *state->buff_for_parsing++;
		if (digit == '6' || digit == '7') {
			pf (state, type_code_str, pointer_str);
			return;
		} else if (digit == '8' || digit == '9') {
			STypeCodeStr func_str;
			if (!init_type_code_str_struct (&func_str)) {
				state->err = eTCStateMachineErrAlloc;
				return;
			};
			size_t read = get_namespace_and_name (state->buff_for_parsing, &func_str, NULL, true) + 1;
			state->amount_of_read_chars += read;
			state->buff_for_parsing += read;
			copy_string (&func_str, "::", 2);
			copy_string (&func_str, pointer_str, 0);
			pf (state, type_code_str, func_str.type_str);
			free_type_code_str_struct (&func_str);
			state->state = eTCStateEnd;
			return;
		}
	}
	parse_type_modifier (state, type_code_str, pointer_str);
}

#define PARSE_POINTER(pointer_str) parse_pointer (state, type_code_str, pointer_str)


DEF_STATE_ACTION(P) {
	PARSE_POINTER ("*");
}

DEF_STATE_ACTION(R) {
	PARSE_POINTER ("* volatile");
}

DEF_STATE_ACTION(Q) {
	PARSE_POINTER ("* const");
}

DEF_STATE_ACTION(A) {
	PARSE_POINTER ("&");
}

DEF_STATE_ACTION($) {
	if (*(state->buff_for_parsing++) != '$') {
		state->err = eTCStateMachineErrUncorrectTypeCode;
		return;
	}
	state->amount_of_read_chars += 2;
	switch (*state->buff_for_parsing++) {
	case 'A':
		state->state = eTCStateP;
		break;
	case 'B':
		parse_type_modifier (state, type_code_str, "");
		break;
	case 'C':
		parse_type_modifier (state, type_code_str, "");
		break;
	case 'F':
		state->state = eTCStateP;
		break;
	case 'Q':
		parse_type_modifier (state, type_code_str, "&&");
		state->state = eTCStateEnd;
		break;
	case 'R':
		parse_type_modifier (state, type_code_str, "&& volatile");
		state->state = eTCStateEnd;
		break;
	case 'T':
		copy_string (type_code_str, "std::nullptr_t", 15);
		state->state = eTCStateEnd;
		break;
	case 'V':
		state->state = eTCStateEnd;
		break;
	case 'Z':
		state->state = eTCStateEnd;
		break;
	default:
		state->err = eTCStateMachineErrUncorrectTypeCode;
		break;
	}
}

#undef ONE_LETTER_ACTION
#undef GO_TO_NEXT_STATE
#undef DEF_STATE_ACTION

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
	ONE_LETTER_STATE ($)
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

static void tc_state_end(SStateInfo *state, STypeCodeStr *type_code_str) {
	return;
}

static void init_state_struct(SStateInfo *state, const char *buff_for_parsing) {
	state->state = eTCStateStart;
	state->buff_for_parsing = buff_for_parsing;
	state->amount_of_read_chars = 0;
	state->err = eTCStateMachineErrOK;
}

static bool init_type_code_str_struct(STypeCodeStr *type_coder_str) {
#define TYPE_STR_LEN 1024
	// 1 - initialization finish with success, else - 0

	type_coder_str->type_str_len = TYPE_STR_LEN;

	type_coder_str->type_str = (char *) calloc (TYPE_STR_LEN, sizeof (char));
	if (!type_coder_str->type_str) {
		return false;
	}
	memset (type_coder_str->type_str, 0, TYPE_STR_LEN * sizeof(char));

	type_coder_str->curr_pos = 0; // strlen ("unknown type");
//	strncpy(type_coder_str->type_str, "unknown_type", type_coder_str->curr_pos);

	return true;
#undef TYPE_STR_LEN
}

static void free_type_code_str_struct(STypeCodeStr *type_code_str) {
	if (type_code_str->type_str) {
		R_FREE (type_code_str->type_str);
	}
	type_code_str->type_str_len = 0;
}

///////////////////////////////////////////////////////////////////////////////
// End of machine functions for parsing type codes
///////////////////////////////////////////////////////////////////////////////

static EDemanglerErr get_type_code_string(const char *sym, size_t *amount_of_read_chars, char **str_type_code) {
	EDemanglerErr err = eDemanglerErrOK;
	char *tmp_sym = strdup (sym);
	STypeCodeStr type_code_str;
	SStateInfo state;

	if (!init_type_code_str_struct (&type_code_str)) {
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

static inline size_t get_ptr_modifier(const char encoded, SDataType *ptr_modifier) {
	size_t read = 0;
#define SET_PTR_MODIFIER(letter, modifier_left, modifier_right) \
	case letter: \
		ptr_modifier->left = modifier_left; \
		ptr_modifier->right = modifier_right; \
		read++; \
		break;

	switch (encoded) {
	SET_PTR_MODIFIER ('E', "", " __ptr64")
	SET_PTR_MODIFIER ('F', "__unaligned ", "")
	SET_PTR_MODIFIER ('G', "", " &")
	SET_PTR_MODIFIER ('H', "", " &&")
	SET_PTR_MODIFIER ('I', "", " __restrict")
	default:
		ptr_modifier->left = ptr_modifier->right = "";
	}
#undef SET_PTR_MODIFIER
	return read;
}

static inline EDemanglerErr get_storage_class(const char encoded, const char **storage_class) {
	switch (encoded) {
	case 'A':
		*storage_class = NULL;
		break; // non-const
	case 'B':
	case 'J':
		*storage_class = "const";
		break;
	case 'C':
	case 'G':
	case 'K':
		*storage_class = "volatile";
		break;
	case 'D':
	case 'H':
	case 'L':
		*storage_class = "const volatile";
		break;
	default:
		return eDemanglerErrUncorrectMangledSymbol;
	}
	return eDemanglerErrOK;
}

static EDemanglerErr parse_data_type(const char *sym, SDataType *data_type, size_t *len) {
	EDemanglerErr err = eDemanglerErrOK;
	size_t i;
	const char *curr_pos = sym;
	SDataType modifier;
	const char *storage_class = NULL;
	char *tmp;
	if (len) {
		*len = 0;
	}
	data_type->left = data_type->right = NULL;
	// Data type and access level
	switch (*curr_pos++) {
	// Data
	case '0': // Private static member
	case '1': // Protected static member
	case '2': // Public static member
	case '3': // Normal variable
	case '4': // Normal variable
	case '5': // Normal variable
		i = 0;
		err = get_type_code_string (curr_pos, &i, &tmp);
		if (err != eDemanglerErrOK) {
			return err;
		}

		curr_pos += i;
		curr_pos += get_ptr_modifier (*curr_pos, &modifier);
		if (get_storage_class (*curr_pos, &storage_class) != eDemanglerErrOK) {
			free (tmp);
			return eDemanglerErrUncorrectMangledSymbol;
		}
		curr_pos++;

		if (data_type) {
			data_type->right = strdup ("");
			if (!storage_class) {
				data_type->left = r_str_newf ("%s%s%s", modifier.left, tmp, modifier.right);
			} else {
				data_type->left = r_str_newf ("%s%s %s%s", modifier.left, tmp, storage_class, modifier.right);
			}
			free (tmp);
		}
		break;
	case '6': // compiler generated static
	case '7': // compiler generated static
		if (data_type) {
			curr_pos += get_ptr_modifier (*curr_pos, &modifier);
			if (get_storage_class (*curr_pos, &storage_class) != eDemanglerErrOK) {
				return eDemanglerErrUncorrectMangledSymbol;
			}
			curr_pos++;

			data_type->left = r_str_newf ("%s%s%s", storage_class, modifier.left , modifier.right);
			if (*curr_pos != '@') {
				STypeCodeStr str;
				if (!init_type_code_str_struct (&str)) {
					return eDemanglerErrMemoryAllocation;
				}
				size_t i = get_namespace_and_name (curr_pos, &str, NULL, true);
				if (!i) {
					free_type_code_str_struct (&str);
					return eDemanglerErrUncorrectMangledSymbol;
				}
				curr_pos += i;
				if (*(curr_pos + 1) != '@') {
					STypeCodeStr str2;
					if (!init_type_code_str_struct (&str2)) {
						free_type_code_str_struct (&str);
						return eDemanglerErrMemoryAllocation;
					}
					i = get_namespace_and_name (curr_pos + 1, &str2, NULL, true);
					if (!i) {
						free_type_code_str_struct (&str);
						free_type_code_str_struct (&str2);
						return eDemanglerErrUncorrectMangledSymbol;
					}
					curr_pos += i + 1;
					data_type->right = r_str_newf ("{for `%s's `%s'}", str.type_str, str2.type_str);
					free_type_code_str_struct (&str2);
				} else {
					data_type->right = r_str_newf ("{for `%s'}", str.type_str);
				}
				free_type_code_str_struct (&str);
			} else {
				data_type->right = strdup ("");
			}
		}
		break;
	}
	if (len) {
		*len = curr_pos - sym;
	}
	return eDemanglerErrOK;
}

static EDemanglerErr parse_function_type(const char *sym, SDataType *data_type,
	size_t *len, bool *is_static, bool *is_implicit_this_pointer) {
	const char *curr_pos = sym;
	data_type->left = data_type->right = "";
	*is_static = *is_implicit_this_pointer = false;
	#define SET_THUNK_MODIFIER(letter, modifier_str) \
	case letter: { \
		SStateInfo state; \
		init_state_struct (&state, curr_pos); \
		char *num = get_num (&state); \
		if (!num) {\
			return eDemanglerErrUncorrectMangledSymbol; \
		} \
		data_type->left = modifier_str; \
		data_type->right = r_str_newf ("`adjustor{%s}'", num); \
		free (num);\
		*is_implicit_this_pointer = true; \
		curr_pos += state.amount_of_read_chars; \
		break; \
	}

	#define SET_ACCESS_MODIFIER(letter, flag_set, modifier_str) \
	case letter: \
		data_type->left = modifier_str; \
		*flag_set = true; \
		break; \

	/* Functions */
	switch (*curr_pos++) {
	SET_ACCESS_MODIFIER ('A', is_implicit_this_pointer, "private");
	SET_ACCESS_MODIFIER ('B', is_implicit_this_pointer, "private");
	SET_ACCESS_MODIFIER ('C', is_static, "private: static");
	SET_ACCESS_MODIFIER ('D', is_static, "private: static");
	SET_ACCESS_MODIFIER ('E', is_implicit_this_pointer, "private virtual");
	SET_ACCESS_MODIFIER ('F', is_implicit_this_pointer, "private virtual");
	SET_THUNK_MODIFIER ('G', "[thunk]:private virtual");
	SET_THUNK_MODIFIER ('H', "[thunk]:private virtual");
	SET_ACCESS_MODIFIER ('I', is_implicit_this_pointer, "protected");
	SET_ACCESS_MODIFIER ('J', is_implicit_this_pointer, "protected");
	SET_ACCESS_MODIFIER ('K', is_static, "protected: static");
	SET_ACCESS_MODIFIER ('L', is_static, "protected: static");
	SET_ACCESS_MODIFIER ('M', is_implicit_this_pointer, "protected virtual");
	SET_ACCESS_MODIFIER ('N', is_implicit_this_pointer, "protected virtual");
	SET_THUNK_MODIFIER ('O', "[thunk]:protected virtual");
	SET_THUNK_MODIFIER ('P', "[thunk]:protected virtual");
	SET_ACCESS_MODIFIER ('Q', is_implicit_this_pointer, "public");
	SET_ACCESS_MODIFIER ('R', is_implicit_this_pointer, "public");
	SET_ACCESS_MODIFIER ('S', is_static, "public: static");
	SET_ACCESS_MODIFIER ('T', is_static, "public: static");
	SET_ACCESS_MODIFIER ('U', is_implicit_this_pointer, "public virtual");
	SET_ACCESS_MODIFIER ('V', is_implicit_this_pointer, "public virtual");
	SET_THUNK_MODIFIER ('W', "[thunk]:public virtual");
	SET_THUNK_MODIFIER ('X', "[thunk]:public virtual");
	case 'Y': // near
	case 'Z': // far
		break;
	default:
		return eDemanglerErrUncorrectMangledSymbol;
	}
#undef SET_ACCESS_MODIFIER
	if (len) {
		*len = curr_pos - sym;
	}
	return eDemanglerErrOK;
}

static EDemanglerErr parse_function(const char *sym, STypeCodeStr *type_code_str, char **demangled_function, size_t *chars_read) {
	EDemanglerErr err = eDemanglerErrOK;
	bool is_implicit_this_pointer;
	bool is_static;
	const char *memb_func_access_code = NULL;
	const char *call_conv = NULL;
	const char *storage_class_code_for_ret = NULL;
	char *demangled_args;
	char *ret_type = NULL;
	const char *curr_pos = sym;
	SDataType data_type;
	const char *__64ptr = NULL;
	size_t len;

	STypeCodeStr func_str;
	if (!init_type_code_str_struct (&func_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_function_err;
	}

	if (!strncmp (curr_pos, "$$F", 3)) {
		// Managed function (Managed C++ or C++/CLI)
		curr_pos += 3;
	}

	err = parse_function_type (curr_pos, &data_type, &len, &is_static, &is_implicit_this_pointer);
	if (err != eDemanglerErrOK) {
		goto parse_function_err;
	}

	curr_pos += len;

	if (*curr_pos == 'E') {
		__64ptr = "__ptr64";
		curr_pos++;
	}

	if (*curr_pos == '$') {
		curr_pos += 2;
	}

	// member function access code
	if (is_implicit_this_pointer) {
		err = get_storage_class (*curr_pos++, &memb_func_access_code);
		if (err != eDemanglerErrOK) {
			goto parse_function_err;
		}
	}

	// currently does not use because I can not find real example of
	// where to use this
	// just read in http://www.agner.org/optimize/calling_conventions.pdf
	// that this is possible
	// when some find the case where it is used please remove this (void)*
	// lines
	(void)is_static;

	// Calling convention
	call_conv = get_calling_convention (*curr_pos++);
	if (!call_conv) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_function_err;
	}

	// get storage class code for return
	if (*curr_pos == '?') {
		err = get_storage_class (*++curr_pos, &memb_func_access_code);
		if (err != eDemanglerErrOK) {
			goto parse_function_err;
		}
		curr_pos++;
	}

	// Return type, or @ if 'void'
	if (*curr_pos == '@') {
		ret_type = strdup ("void");
		curr_pos++;
	} else {
		err = get_type_code_string (curr_pos, &len, &ret_type);
		if (err != eDemanglerErrOK) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_function_err;
		}

		curr_pos += len;
	}

	err = parse_function_args (curr_pos, &demangled_args, &len);
	if (err != eDemanglerErrOK) {
		goto parse_function_err;
	}

	curr_pos += len;

	if (*data_type.left) {
		copy_string (&func_str, data_type.left, 0);
		if (!strstr (data_type.left, "static")) {
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

	if (type_code_str->type_str) {
		copy_string (&func_str, type_code_str->type_str, type_code_str->curr_pos);
	}

	if (*data_type.right) {
		copy_string (&func_str, data_type.right, 0);
		free (data_type.right);
	}

	copy_string (&func_str, demangled_args, 0);
	free (demangled_args);

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
		*demangled_function = strdup (func_str.type_str);
	}

parse_function_err:
	if (chars_read) {
		*chars_read = curr_pos - sym;
	}
	free_type_code_str_struct (&func_str);
	free (ret_type);
	return err;
}

///////////////////////////////////////////////////////////////////////////////
/// public mangled name of global object:
/// <public name> ::= ?<name>@[<namespace>@](0->inf)@3<type><storage class>
/// mangled name of a static class member object:
/// <public name> ::= ?<name>@[<classname>@](1->inf)@2<type><storage class>
///////////////////////////////////////////////////////////////////////////////
static EDemanglerErr parse_microsoft_mangled_name(const char *sym, char **demangled_name, size_t *chars_read) {
	STypeCodeStr type_code_str;
	EDemanglerErr err = eDemanglerErrOK;

	SDataType data_type;

	const char *curr_pos = sym;

	if (!init_type_code_str_struct (&type_code_str)) {
		err = eDemanglerErrMemoryAllocation;
		goto parse_microsoft_mangled_name_err;
	}
	size_t i;
	size_t len = get_namespace_and_name (curr_pos, &type_code_str, &i, false);
	if (!len) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos += len + 1;

	if (!strncmp (curr_pos, "$$F", 3)) {
		// Managed function (Managed C++ or C++/CLI)
		curr_pos += 3;
	}
	
	if (curr_pos[0] == '_') {
		// TODO: __based()
		curr_pos++;
	}

	if (isdigit ((unsigned char)*curr_pos)) {
		err = parse_data_type (curr_pos, &data_type, &len);
		if (err != eDemanglerErrOK) {
			goto parse_microsoft_mangled_name_err;
		}
		curr_pos += len;
		*demangled_name = NULL;
		if (data_type.left) {
			*demangled_name = r_str_newf ("%s ", data_type.left);
		}
		*demangled_name = r_str_append (*demangled_name, type_code_str.type_str);
		*demangled_name = r_str_append (*demangled_name, data_type.right);
		free (data_type.left);
		free (data_type.right);
	} else if (isalpha ((unsigned char)*curr_pos)) {
		err = parse_function (curr_pos, &type_code_str, demangled_name, &len);
		curr_pos += len;
	} else {
		err = eDemanglerErrUncorrectMangledSymbol;
	}

parse_microsoft_mangled_name_err:
	free_type_code_str_struct (&type_code_str);
	if (chars_read) {
		*chars_read = curr_pos - sym;
	}
	return err;
}

static EDemanglerErr parse_microsoft_rtti_mangled_name(const char *sym, char **demangled_name, size_t *chars_read) {
	EDemanglerErr err = eDemanglerErrOK;
	char *type = NULL;
	const char *storage = NULL;
	if (chars_read) {
		*chars_read = 0;
	}
	err = get_storage_class (*sym++, &storage);
	if (err != eDemanglerErrOK) {
		return err;
	}
	size_t len;
	err = get_type_code_string (sym, &len, &type);
	if (err != eDemanglerErrOK) {
		return err;
	}
	if (storage) {
		*demangled_name = r_str_newf ("%s %s", type, storage);
	} else {
		*demangled_name = r_str_newf ("%s", type);
	}
	if (chars_read) {
		*chars_read = len + 1;
	}
	free (type);
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
		err = parse_microsoft_rtti_mangled_name (demangler->symbol + 2, demangled_name, NULL);
	} else {
		err = parse_microsoft_mangled_name (demangler->symbol + 1, demangled_name, NULL);
	}

microsoft_demangle_err:
	r_list_free (abbr_names);
	r_list_free (abbr_types);
	return err;
}
