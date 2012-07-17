#include <stdio.h>
#include <stdlib.h>
#include <r_anal.h>
#include "cdata.h"

int new_tree() {
	return 0;
}

int print_tree(RAnalType *t) {
	RAnalType *p;
	p = t;
	if (p != NULL) {
		while (p != NULL) {
			switch (p->type) {
				case R_ANAL_TYPE_VARIABLE:
					printf("var %s\n", p->custom.v->name);
					break;
				case R_ANAL_TYPE_POINTER:
					printf("ptr %s\n", p->custom.p->name);
					break;
				case R_ANAL_TYPE_ARRAY:
					printf("arr %s[%ld]\n", p->custom.a->name, p->custom.a->count);
					break;
				case R_ANAL_TYPE_STRUCT:
					printf("Entering struct %s...\n", p->custom.s->name);
					print_tree(p->custom.s->items);
					break;
				case R_ANAL_TYPE_UNION:
					printf("Entering union %s...\n", p->custom.u->name);
					print_tree(p->custom.u->items);
					break;
				case R_ANAL_TYPE_FUNCTION:
					printf("Entering function %s...\n", p->custom.f->name);
					print_tree(p->custom.f->args);
					break;
				default:
					printf("invalid item!\n");
					break;
			}
			p = p->next;
		}
	} else {
		printf("Empty tree!\n");
	}
	return 0;
}

RAnalType* new_variable_node(char* name, short type, short sign, short modifier)
{
	RAnalTypeVar *ivar = (RAnalTypeVar *)malloc(sizeof(RAnalTypeVar));
	RAnalType *tmp;
	ivar->name = name;
	ivar->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER);
	tmp = (RAnalType *)malloc(sizeof(RAnalType));
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_VARIABLE;
	tmp->custom.v = ivar;
	return tmp;
}

RAnalType* new_pointer_node(char* name, short type, short sign, short modifier)
{
	RAnalTypePtr *iptr = (RAnalTypePtr *)malloc(sizeof(RAnalTypePtr));
	RAnalType *tmp;
	iptr->name = name;
	iptr->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER);
	tmp = (RAnalType *)malloc(sizeof(RAnalType));
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_POINTER;
	tmp->custom.p = iptr;
	return tmp;
}

RAnalType* new_array_node(char* name, short type, short sign, short modifier, long size)
{
	RAnalTypeArray *iarr = (RAnalTypeArray *)malloc(sizeof(RAnalTypeArray));
	RAnalType *tmp;
	iarr->name = name;
	iarr->count = size;
	iarr->type = (type & R_ANAL_VAR_TYPE_SIZE_MASK) |
		((sign << R_ANAL_VAR_TYPE_SIGN_SHIFT) & R_ANAL_VAR_TYPE_SIGN_MASK) |
		((modifier << R_ANAL_VAR_TYPE_MODIFIER_SHIFT) & R_ANAL_VAR_TYPE_MODIFIER);
	tmp = (RAnalType *)malloc(sizeof(RAnalType));
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_ARRAY;
	tmp->custom.a = iarr;
	return tmp;
}

RAnalType* new_struct_node(char* name, RAnalType *defs)
{
	RAnalTypeStruct *istr = (RAnalTypeStruct *)malloc(sizeof(RAnalTypeStruct));
	RAnalType *tmp = (RAnalType *)malloc(sizeof(RAnalType));
	istr->name = name;
	istr->items = defs;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_STRUCT;
	tmp->custom.s = istr;
	return tmp;
}

RAnalType* new_union_node(char* name, RAnalType *defs)
{
	RAnalTypeUnion *iun = (RAnalTypeUnion *)malloc(sizeof(RAnalTypeUnion));
	RAnalType *tmp = (RAnalType *)malloc(sizeof(RAnalType));
	iun->name = name;
	iun->items = defs;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_UNION;
	tmp->custom.u = iun;
	return tmp;
}

/* Function can return another function or have multiple returns */
//item_list* new_function_node(char* name, item_list *rets, item_list *args)
RAnalType* new_function_node(char* name, short ret_type, RAnalType *args, short fmodifier, short callconvention, char* attributes)
{
	RAnalTypeFunction *ifnc = (RAnalTypeFunction *)malloc(sizeof(RAnalTypeFunction));
	RAnalType *tmp = (RAnalType *)malloc(sizeof(RAnalType));
	ifnc->name = name;
	ifnc->rets = ret_type;
	ifnc->fmod = fmodifier;
	ifnc->call = callconvention;
	ifnc->attr = attributes;
	ifnc->args = args;
	tmp->next = NULL;
	tmp->type = R_ANAL_TYPE_FUNCTION;
	tmp->custom.f = ifnc;
	return tmp;
}


