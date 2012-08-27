#include <stdio.h>
#include <stdlib.h>
#include <r_anal.h>
#include "cdata.h"

// FIXME: Temporary hack to use global variable
// Need to remove that in next release
RAnalType *tmp_tree = NULL;

static int new_tree() {
	return 0;
}

RAnalType* new_variable_node(char* name, short type, short sign, short modifier) {
	RAnalTypeVar *ivar = R_NEW (RAnalTypeVar);
	RAnalType *tmp;
	ivar->name = name;
	ivar->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER_MASK);
	tmp = R_NEW (RAnalType);
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_VARIABLE;
	tmp->custom.v = ivar;
	// FIXME: Temporary hack to use global variable
	// Neet to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file
	return tmp;
}

RAnalType* new_pointer_node(char* name, short type, short sign, short modifier) {
	RAnalTypePtr *iptr = R_NEW (RAnalTypePtr);
	RAnalType *tmp;
	iptr->name = name;
	iptr->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER_MASK);
	tmp = (RAnalType *)malloc(sizeof(RAnalType));
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_POINTER;
	tmp->custom.p = iptr;
	// FIXME: Temporary hack to use global variable
	// Neet to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file

	return tmp;
}

RAnalType* new_array_node(char* name, short type, short sign, short modifier, long size) {
	RAnalTypeArray *iarr = (RAnalTypeArray *)malloc(sizeof(RAnalTypeArray));
	RAnalType *tmp;
	iarr->name = name;
	iarr->count = size;
	iarr->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER_MASK);
	tmp = (RAnalType *)malloc(sizeof(RAnalType));
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_ARRAY;
	tmp->custom.a = iarr;
	// FIXME: Temporary hack to use global variable
	// Neet to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file

	return tmp;
}

RAnalType* new_struct_node(char* name, RAnalType *defs) {
	RAnalTypeStruct *istr = R_NEW (RAnalTypeStruct);
	RAnalType *tmp = R_NEW (RAnalType);
	istr->name = name;
	istr->items = defs;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_STRUCT;
	tmp->custom.s = istr;
	// FIXME: Temporary hack to use global variable
	// Neet to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file

	return tmp;
}

RAnalType* new_union_node(char* name, RAnalType *defs) {
	RAnalTypeUnion *iun = R_NEW (RAnalTypeUnion);
	RAnalType *tmp = R_NEW (RAnalType);
	iun->name = name;
	iun->items = defs;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_UNION;
	tmp->custom.u = iun;
	// FIXME: Temporary hack to use global variable
	// Neet to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file

	return tmp;
}

/* Function can return another function or have multiple returns */
//item_list* new_function_node(char* name, item_list *rets, item_list *args)
RAnalType* new_function_node(char* name, short ret_type, RAnalType *args, short fmodifier, short callconvention, char* attributes) {
	RAnalFunction *ifnc = R_NEW (RAnalFunction);
	RAnalType *tmp = R_NEW (RAnalType);
	ifnc->name = name;
	ifnc->rets = ret_type;
	ifnc->fmod = fmodifier;
	ifnc->call = callconvention;
	ifnc->attr = attributes;
	ifnc->args = args;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_FUNCTION;
	tmp->custom.f = ifnc;
	// FIXME: Temporary hack to use global variable
	// Neet to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file

	return tmp;
}
