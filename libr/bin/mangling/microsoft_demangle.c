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
/// public mangled name of global object:
/// <public name> ::= ?<name>@[<namespace>@](0->inf)@3<type><storage class>
/// mangled name of a static class member object:
/// <public name> ::= ?<name>@[<classname>@](1->inf)@2<type><storage class>
///////////////////////////////////////////////////////////////////////////////
EDemanglerErr parse_microsoft_mangled_name(	char *sym,
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
