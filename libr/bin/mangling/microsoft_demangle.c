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

	unsigned int len = IMPOSSIBLE_LEN;

	EObjectType object_type = eObjectTypeMax;
	char *tmp = 0;
	char var_name[MICROSOFT_NAME_LEN];
	RList/*<char*>*/ *names_l = r_list_new();
	RListIter *it;

	char *curr_pos = 0;
	char *prev_pos = 0;

	memset(var_name, 0, MICROSOFT_NAME_LEN);

	prev_pos = sym;
	curr_pos = strchr(sym, '@');

	if (curr_pos) {
		// get variable name length
		len = curr_pos - prev_pos;
	}

	while (curr_pos != NULL) {
		// firstly it is going variable name, so need to get max length of
		// variable name; further it is going just class name or namespace, so
		// need to check the max length of class_namespace.
		if (i <= amount_of_elements) {
			limit_len = limit_len_arr[i - 1];
		}

		// if len is zero in first step of cycle it means that variable name
		// has zero length, that is impossible.
		// len MUST be equal to zero JUST in case when there is end of list
		// with class name or namespace, OR in case when there is no class name
		// or namespace for this variable
		// so if we are here and len is 0, it is mean that that it was
		// situation like: ?name@@classname|namepace@@ that is not impossible
		if (len == 0) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_microsoft_mangled_name_err;
		}

		len = curr_pos - prev_pos;

		if ((len >= limit_len)) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_microsoft_mangled_name_err;
		}

		switch (i) {
		case 1: // variable name
			memcpy(var_name, prev_pos, len);
			break;
		default:
			// names of class names | namespaces | etc
			tmp = (char *) malloc(len + 1);
			memset(tmp, '\0', len + 1);
			memcpy(tmp, prev_pos, len);
			r_list_append(names_l, tmp);
			break;
		}

		i++;
		prev_pos = curr_pos + 1;
		curr_pos = strchr(curr_pos + 1, '@');
	}

	// if len is equal to IMPOSSIBLE_LEN, than it means that there is no '@' in
	// mangled symbol, that is impossible situation, so go away
	// if len is not 0, than it mean that name of variable length name is 0,
	// and this is not possible situation
	// len = 0 is correct cause at after the last name or class name or
	// namespace name, or there is not class name or namespace name,
	// it is going @@
	if ((len != 0) || (len == IMPOSSIBLE_LEN)) {
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos = prev_pos;

	switch (*curr_pos - '0') {
	case eObjectTypeStaticClassMember:
		object_type = eObjectTypeStaticClassMember;

		// length < 1 can be just in situation like:
		// ?name@@...
		// this situation is impossible because class member need to have
		// class name
		if (r_list_length(names_l) < 1) {
			err = eDemanglerErrUncorrectMangledSymbol;
			goto parse_microsoft_mangled_name_err;
		}
		break;
	case eObjectTypeGlobal:
		object_type = eObjectTypeGlobal;
		break;

	default:
		err = eDemanglerErrUncorrectMangledSymbol;
		goto parse_microsoft_mangled_name_err;
	}

	curr_pos++;

	// TODO: add parsing of <type> and <storage class>

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
