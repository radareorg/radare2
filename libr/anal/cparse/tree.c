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
	// Need to remove that in next release
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
	tmp = R_NEW (RAnalType);
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_POINTER;
	tmp->custom.p = iptr;
	// FIXME: Temporary hack to use global variable
	// Need to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file
	return tmp;
}

RAnalType* new_array_node(char* name, short type, short sign, short modifier, long size) {
	RAnalTypeArray *iarr = R_NEW (RAnalTypeArray);
	RAnalType *tmp;
	iarr->name = name;
	iarr->count = size;
	iarr->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER_MASK);
	tmp = R_NEW0 (RAnalType);
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_ARRAY;
	tmp->custom.a = iarr;
	// FIXME: Temporary hack to use global variable
	// Need to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file

	return tmp;
}

RAnalType* new_struct_node(char* name, RAnalType *defs) {
	RAnalTypeStruct *istr = R_NEW (RAnalTypeStruct);
	RAnalType *tmp = R_NEW (RAnalType);
	istr->name = name;
	istr->items = defs;
	tmp->name = istr->name;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_STRUCT;
	tmp->custom.s = istr;
	// FIXME: Temporary hack to use global variable
	// Need to remove that in next release
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
	// Need to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file
	return tmp;
}

RAnalType* new_alloca_node(long address, long size, RAnalType *defs) {
	RAnalTypeAlloca *ia = R_NEW(RAnalTypeAlloca);
	RAnalType *tmp = R_NEW (RAnalType);
	ia->address = address;
	ia->size = size;
	ia->items = defs;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_ALLOCA;
	tmp->custom.al = ia;
	return tmp;
}

RAnalLocals* new_locals_node(RAnalType *defs) {
	RAnalLocals *il = R_NEW (RAnalLocals);
	il->items = defs;
	return il;
}

/* Function can return another function or have multiple returns */
//item_list* new_function_node(char* name, item_list *rets, item_list *args)
RAnalType* new_function_node(char* name, short ret_type, RAnalType *args,
		short fmodifier, short callconvention, char* attributes,
		RAnalLocals *locals, RAnalType* valaattr) {
	RAnalFunction *ifnc = R_NEW (RAnalFunction);
	RAnalType *tmp = R_NEW (RAnalType);
	ifnc->name = name;
	ifnc->rets = ret_type;
	ifnc->fmod = fmodifier;
	ifnc->call = callconvention;
	ifnc->attr = attributes;
	ifnc->args = args;
	ifnc->locs = locals;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_FUNCTION;
	tmp->custom.f = ifnc;
	// FIXME: Temporary hack to use global variable
	// Need to remove that in next release
	// and provide proper way to handle global tree
	// outside from this file
	return tmp;
}
