
#include "tpi.h"

#include "stream_file.h"

static unsigned int base_idx = 0;
static RList *p_types_list;

///////////////////////////////////////////////////////////////////////////////
static void print_base_type(EBASE_TYPES base_type, char **name)
{
	switch (base_type) {
	case eT_32PINT4:
		*name = "pointer to long";
		break;
	case eT_32PRCHAR:
		*name = "pointer to unsigned char";
		break;
	case eT_32PUCHAR:
		*name = "pointer to unsigned char";
		break;
	case eT_32PULONG:
		*name = "pointer to unsigned long";
		break;
	case eT_32PLONG:
		*name = "pointer to long";
		break;
	case eT_32PUQUAD:
		*name = "pointer to unsigned long long";
		break;
	case eT_32PUSHORT:
		*name = "pointer to unsigned short";
		break;
	case eT_32PVOID:
		*name = "pointer to void";
		break;
	case eT_64PVOID:
		*name = "pointer64 to void";
		break;
	case eT_INT4:
		*name = "long";
		break;
	case eT_INT8:
		*name = "long long";
		break;
	case eT_LONG:
		*name = "long";
		break;
	case eT_QUAD:
		*name = "long long";
		break;
	case eT_RCHAR:
		*name = "unsigned char";
		break;
	case eT_REAL32:
		*name = "float";
		break;
	case eT_REAL64:
		*name = "double";
		break;
	case eT_REAL80:
		*name = "long double";
		break;
	case eT_SHORT:
		*name = "short";
		break;
	case eT_UCHAR:
		*name = "unsigned char";
		break;
	case eT_UINT4:
		*name = "unsigned long";
		break;
	case eT_ULONG:
		*name = "unsigned long";
		break;
	case eT_UQUAD:
		*name = "unsigned long long";
		break;
	case eT_USHORT:
		*name = "unsigned short";
		break;
	case eT_WCHAR:
		*name = "wchar";
		break;
	case eT_VOID:
		*name = "void";
		break;
	case eT_32PWCHAR:
		*name = "pointer to wchar";
		break;
	default:
		*name = "unsupported base type";
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_name_len(SVal *val, int *res_len)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		*res_len = scstr->size;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			*res_len = lf_ulong->name.size;
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			*res_len = lf_ushort->name.size;
			break;
		}
		default:
			*res_len = 0;
			printf("get_sval_name::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_name(SVal *val, char **name)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		*name = scstr->name;
//		strcpy(name, scstr->name);
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			*name = lf_ulong->name.name;
//			strcpy(name, lf_ulong->name.name);
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			*name =lf_ushort->name.name;
//			strcpy(name, lf_ushort->name.name);
			break;
		}
		default:
			*name = 0;
			printf("get_sval_name::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
//static void get_arglist_type(void *type, void **arglist_type)
//{
//	STypeInfo *t = (STypeInfo *) type;
//	SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *) t->type_info;
//	RList *l = (RList *) *arglist_type;
//	int i = 0;
//	int tmp = 0;

//	for (i = 0; i < lf_arglist->count; i++) {
//		tmp = lf_arglist->arg_type[i];
//		if (tmp < base_idx) {
//			// 0 - means NO_TYPE
//			r_list_append(l, 0);
//		} else {
//			r_list_append(l, r_list_get_n(p_types_list, (tmp - base_idx)));
//		}
//	}
//}

///////////////////////////////////////////////////////////////////////////////
static void is_union_fwdref(void *type, int *is_fwdref)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf = (SLF_UNION *) t->type_info;

	*is_fwdref = lf->prop.bits.fwdref;
}

///////////////////////////////////////////////////////////////////////////////
static void is_struct_class_fwdref(void *type, int *is_fwdref)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;

	*is_fwdref = lf->prop.bits.fwdref;
}

///////////////////////////////////////////////////////////////////////////////
static int get_array_element_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;
	int curr_idx = lf_array->element_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_array_index_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;
	int curr_idx = lf_array->index_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_bitfield_base_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_BITFIELD *lf = (SLF_BITFIELD *) t->type_info;
	int curr_idx = lf->base_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_class_struct_derived(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;
	int curr_idx = lf->derived;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_class_struct_vshape(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;
	int curr_idx = lf->vshape;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_return_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->return_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_class_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->class_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_this_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->this_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_arglist(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->arglist;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_modifier_modified_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MODIFIER *lf = (SLF_MODIFIER *) t->type_info;
	int curr_idx = lf->modified_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_pointer_utype(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_POINTER *lf = (SLF_POINTER *) t->type_info;
	int curr_idx = lf->utype;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_procedure_return_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_PROCEDURE *lf = (SLF_PROCEDURE *) t->type_info;
	int curr_idx = lf->return_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_procedure_arglist(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_PROCEDURE *lf = (SLF_PROCEDURE *) t->type_info;
	int curr_idx = lf->arg_list;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_member_index(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *) t->type_info;
	int curr_idx = lf->inedex;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_nesttype_index(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *) t->type_info;
	int curr_idx = lf->index;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_onemethod_index(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *) t->type_info;
	int curr_idx = lf->index;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_method_mlist(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_METHOD *lf = (SLF_METHOD *) t->type_info;
	int curr_idx = lf->mlist;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_enum_utype(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf = (SLF_ENUM *) t->type_info;
	int curr_idx = lf->utype;

	if (curr_idx < base_idx) {
		*ret_type = 0;
	} else {
		curr_idx -= base_idx;
		*ret_type = r_list_get_n(p_types_list, curr_idx);
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static void get_fieldlist_members(void *type, RList **l)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *) t->type_info;

	*l = lf_fieldlist->substructs;
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_members(void *type, RList **l)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;
	unsigned int indx = 0;

	if (lf_union->field_list == 0) {
		*l = 0;
	} else {
		SType *tmp = 0;
		indx = lf_union->field_list - base_idx;
		tmp = (SType *)r_list_get_n(p_types_list, indx);
		*l = ((SLF_FIELDLIST *) tmp->type_data.type_info)->substructs;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_struct_class_members(void *type, RList **l)
{
	SLF_FIELDLIST *lf_fieldlist = 0;
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;
	unsigned int indx = 0;

	if (lf->field_list == 0) {
		*l = 0;
	} else {
		SType *tmp = 0;
		indx = lf->field_list - base_idx;
		tmp = (SType *)r_list_get_n(p_types_list, indx);
		lf_fieldlist = (SLF_FIELDLIST *) tmp->type_data.type_info;
		*l = lf_fieldlist->substructs;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_members(void *type, RList **l)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf = (SLF_ENUM *) t->type_info;
	unsigned int indx = 0;

	if (lf->field_list == 0) {
		*l = 0;
	} else {
		SType *tmp = 0;
		indx = lf->field_list - base_idx;
		tmp = (SType *)r_list_get_n(p_types_list, indx);
		*l = ((SLF_FIELDLIST *) tmp->type_data.type_info)->substructs;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_val(SVal *val, int *res)
{
	if (val->value_or_type < eLF_CHAR) {
		*res = val->value_or_type;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			*res = lf_ulong->value;
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			*res = lf_ushort->value;
			break;
		}
		default:
			*res = 0;
			printf("get_sval_val::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
//static void get_member_indx_val(void *type, int *indx_val)
//{
//	STypeInfo *t = (STypeInfo *) type;
//	SLF_MEMBER *lf_member = (SLF_MEMBER *)t->type_info;

//	*indx_val = lf_member->inedex;
//}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *)t->type_info;

	*res_len = lf_onemethod->val.str_data.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;

	*res_len = lf_enum->name.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;

	get_sval_name_len(&lf->size, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	get_sval_name_len(&lf_array->size, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	get_sval_name_len(&lf_union->size, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_name_len(&lf->enum_value, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_nesttype_name_len(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;

	*res = lf->name.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_name_len(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;

	*res = lf->name.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_name_len(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_name_len(&lf->offset, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_name(&lf->offset, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *)t->type_info;

	*name = lf->val.str_data.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;

	*name = lf->name.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_nesttype_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;

	*name = lf->name.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_name(&lf->enum_value, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;

	*name = lf_enum->name.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;

	get_sval_name(&lf->size, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	get_sval_name(&lf_array->size, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	get_sval_name(&lf_union->size, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *) t->type_info;

	*res = lf->val.val;
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_val(&lf->offset, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_val(&lf->enum_value, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;

	get_sval_val(&lf->size, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	get_sval_val(&lf_array->size, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	get_sval_val(&lf_union->size, res);
}

///////////////////////////////////////////////////////////////////////////////
//static void printf_sval_name(SVal *val)
//{
//	int len = 0;
//	char *name = 0;

//	get_sval_name_len(val, &len);
//	name = (char *) malloc(len);
//	get_sval_name(val, &name);
//	printf("%s", name);

//	free(name);
//}

//typedef struct {
//	SParsedPDBStream *parsed_pdb_stream;
//	SPDBInfoStreamD data;
//} SPDBInfoStream;

///////////////////////////////////////////////////////////////////////////////
static void free_sval(SVal *val)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		R_FREE(scstr->name);
		R_FREE(val->name_or_val);
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			R_FREE(lf_ulong->name.name);
			R_FREE(val->name_or_val);
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			R_FREE(lf_ushort->name.name);
			R_FREE(val->name_or_val);
			break;
		}
		default:
			printf("free_sval()::not supproted type\n");
			break;
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////
static void free_lf_enumerate(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_ENUMERATE *lf_en = (SLF_ENUMERATE *) typeInfo->type_info;

	free_sval(&(lf_en->enum_value));
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_nesttype(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_NESTTYPE *lf_nest = (SLF_NESTTYPE *) typeInfo->type_info;

	free(lf_nest->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_method(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_METHOD *lf_meth = (SLF_METHOD *) typeInfo->type_info;

	free(lf_meth->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_member(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_MEMBER *lf_mem = (SLF_MEMBER *) typeInfo->type_info;

	free_sval(&lf_mem->offset);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_fieldlist(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *) t->type_info;
	RListIter *it;
	STypeInfo *type_info = 0;

	it = r_list_iterator(lf_fieldlist->substructs);
	while (r_list_iter_next(it)) {
		type_info = (STypeInfo *) r_list_iter_get(it);
		if (type_info->free_)
			type_info->free_(type_info);
		if (type_info->type_info) {
			free(type_info->type_info);
		}
		if (type_info)
			free(type_info);
	}
	r_list_free(lf_fieldlist->substructs);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_class(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_CLASS *lf_class = (SLF_CLASS *) t->type_info;

	free_sval(&lf_class->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_union(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	free_sval(&lf_union->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_onemethod(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *) t->type_info;

	free(lf_onemethod->val.str_data.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_enum(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *) t->type_info;

	free(lf_enum->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_array(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	free_sval(&lf_array->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_arglist(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *) t->type_info;

	free(lf_arglist->arg_type);
	lf_arglist->arg_type = 0;
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_vtshape(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_VTSHAPE *lf_vtshape = (SLF_VTSHAPE *) t->type_info;

	free(lf_vtshape->vt_descriptors);
	lf_vtshape->vt_descriptors = 0;
}

///////////////////////////////////////////////////////////////////////////////
static void free_tpi_stream(void *stream)
{
	STpiStream *tpi_stream = (STpiStream *)stream;
	RListIter *it;
	SType *type = 0;

	it = r_list_iterator(tpi_stream->types);
	while (r_list_iter_next(it)) {
		type = (SType *) r_list_iter_get(it);
		if (type) {
			if (type->type_data.free_) {
				type->type_data.free_(&type->type_data);
				type->type_data.free_ = 0;
			}
		}
		if (type->type_data.type_info) {
			free(type->type_data.type_info);
			type->type_data.free_ = 0;
			type->type_data.type_info = 0;
		}
		free(type);
		type = 0;
	}
	r_list_free(tpi_stream->types);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_element_type(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("array: ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "array: ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_pointer_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_utype(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("pointer to ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "pointer to ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_modifier_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_modified_type(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("modifier ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "modifier ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_procedure_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("proc ");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "proc ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_bitfield_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;
	SLF_BITFIELD *bitfeild_info = (SLF_BITFIELD *)ti->type_info;

	base_type = ti->get_base_type(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("bitfield ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	name_len += 4;
	*name = (char *) malloc(name_len + 1 + 1);
	// name[name_len] = '\0';
	if (tmp_name) {
		sprintf(*name, "%s %s : %d", "bitfield", tmp_name, (int)bitfeild_info->length);
	} else {
		sprintf(*name, "%s : %d", "bitfield", (int)bitfeild_info->length);
	}

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_fieldlist_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("fieldlist ");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "fieldlist ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_utype(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("enum ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "enum ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	lt = ti->leaf_type;
	ti->get_name(ti, &tmp_name);

	if (lt == eLF_CLASS) {
		tmp1 = "class ";
	} else {
		tmp1 = "struct ";
	}
	name_len = strlen(tmp1);
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name)
		strcat(*name, tmp_name);

//	if (need_to_free) {
//		free(tmp_name);
//		tmp_name = 0;
//	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_arglist_print_type(void *type, char **name)
{
	(void) type;
	int name_len = 0;

	name_len = strlen("arg_list");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "arg_list");
//	STypeInfo *ti = (STypeInfo *) type;
//	SType *t = 0;
//	char *tmp_name = 0;
//	int name_len = 0;
//	int need_to_free = 1;
//	int base_type = 0;

//	base_type = ti->get_arg_type(ti, (void **)&t);
//	if (!t) {
//		need_to_free = 0;
//		print_base_type(base_type, &tmp_name);
//	} else {
//		ti = &t->type_data;
//		ti->get_print_type(ti, &tmp_name);
//	}

//	name_len = strlen("arglist ");
//	name_len += strlen(tmp_name);
//	*name = (char *) malloc(name_len + 1);
//	// name[name_len] = '\0';
//	strcpy(*name, "arglist ");
//	strcat(*name, tmp_name);

//	if (need_to_free)
//		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_mfunction_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("mfunction ");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "mfunction ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
//	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

//	lt = ti->leaf_type;
	ti->get_name(ti, &tmp_name);

	tmp1 = "union ";
	name_len = strlen(tmp1);
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name)
		strcat(*name, tmp_name);

//	if (need_to_free) {
//		free(tmp_name);
//		tmp_name = 0;
//	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_vtshape_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("vtshape");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "vthape");
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	ti->get_name(ti, &tmp_name);

	tmp1 = "enumerate ";
	name_len = strlen(tmp1);
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name)
	strcat(*name, tmp_name);

//	if (need_to_free)
//		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_nesttype_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_index(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("nesttype ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "nesttype ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	ti->get_name(ti, &tmp_name);

	tmp1 = "method ";
	name_len = strlen(tmp1);
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name)
		strcat(*name, tmp_name);

//	if (need_to_free)
//		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_index(ti, (void **) &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("(member) ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "(member) ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free) {
		R_FREE(tmp_name);
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_index(ti, (void **)&t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("onemethod ");
	if (tmp_name)
		name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "onemethod ");
	if (tmp_name)
		strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
void init_scstring(SCString *cstr, unsigned int size, char *name)
{
	cstr->size = size;
	cstr->name = (char *) malloc(size);
	strcpy(cstr->name, name);
}

///////////////////////////////////////////////////////////////////////////////
void deinit_scstring(SCString *cstr)
{
	free(cstr->name);
}

///////////////////////////////////////////////////////////////////////////////
int parse_sctring(SCString *sctr, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int c = 0;

	sctr->name = 0;

	while (*leaf_data != 0) {
		CAN_READ((*read_bytes + c), 1, len);
		c++;
		leaf_data++;
	}
	CAN_READ(*read_bytes, 1, len);
	leaf_data += 1;
	(*read_bytes) += (c + 1);

	init_scstring(sctr, c + 1, (char *)leaf_data - (c + 1));
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_sval(SVal *val, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	val->name_or_val = 0;

	READ(*read_bytes, 2, len, val->value_or_type, leaf_data, unsigned short);

	if (val->value_or_type < eLF_CHAR) {
		SCString *sctr = (SCString *) malloc(sizeof(SCString));
		parse_sctring(sctr, leaf_data, read_bytes, len);
		val->name_or_val = sctr;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG lf_ulong;
			lf_ulong.value = 0;
			// unsinged long = 4 bytes for Windows, but not in Linux x64,
			// so here is using unsinged int instead of unsigned long when
			// reading ulong value
			READ(*read_bytes, 4, len, lf_ulong.value, leaf_data, unsigned int);
			parse_sctring(&lf_ulong.name, leaf_data, read_bytes, len);
			val->name_or_val = malloc(sizeof(SVal_LF_ULONG));
			memcpy(val->name_or_val, &lf_ulong, sizeof(SVal_LF_ULONG));
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT lf_ushort;
			READ(*read_bytes, 2, len, lf_ushort.value, leaf_data, unsigned short);
			parse_sctring(&lf_ushort.name, leaf_data, read_bytes, len);
			val->name_or_val = malloc(sizeof(SVal_LF_USHORT));
			memcpy(val->name_or_val, &lf_ushort, sizeof(SVal_LF_USHORT));
			break;
		}
		default:
			printf("parse_sval()::oops\n");
			return 0;
		}
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_enumerate(SLF_ENUMERATE *lf_enumerate, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = 0, tmp_read_bytes_before = 0;

	lf_enumerate->enum_value.name_or_val = 0;

	read_bytes_before = *read_bytes;
	READ(*read_bytes, 2, len, lf_enumerate->fldattr.fldattr, leaf_data, unsigned short);

	tmp_read_bytes_before = *read_bytes;
	parse_sval(&lf_enumerate->enum_value, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_enumerate->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_enumerate->pad, *read_bytes, leaf_data, len);

//	printf("%s:", "parse_lf_enumerate()");
//	printf_sval_name(&lf_enumerate->enum_value);
//	printf("\n");

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_nesttype(SLF_NESTTYPE *lf_nesttype, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = *read_bytes;

	lf_nesttype->name.name = 0;

	READ(*read_bytes, 2, len, lf_nesttype->pad, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_nesttype->index, leaf_data, unsigned short);

	parse_sctring(&lf_nesttype->name, leaf_data, read_bytes, len);
//	printf("parse_lf_nesttype(): name = %s\n", lf_nesttype->name.name);

	return *read_bytes - read_bytes_before;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_method(SLF_METHOD *lf_method, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;

	lf_method->name.name = 0;

	READ(*read_bytes, 2, len, lf_method->count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_method->mlist, leaf_data, unsigned int);

	tmp_read_bytes_before = *read_bytes;
	parse_sctring(&lf_method->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_method->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_method->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_method(): name = %s\n", lf_method->name.name);

	return *read_bytes - read_bytes_before;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_member(SLF_MEMBER *lf_member, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;

	lf_member->offset.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_member->fldattr.fldattr, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_member->inedex, leaf_data, unsigned int);

	tmp_read_bytes_before = *read_bytes;
	parse_sval(&lf_member->offset, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_member->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_member->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_member(): name = ");
//	printf_sval_name(&lf_member->offset);
//	printf("\n");

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_onemethod(SLF_ONEMETHOD *lf_onemethod, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	int read_bytes_before = *read_bytes, tmp_before_read_bytes = 0;

	lf_onemethod->val.str_data.name = 0;
	lf_onemethod->val.val = 0;

	READ(*read_bytes, 2, len, lf_onemethod->fldattr.fldattr, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_onemethod->index, leaf_data, unsigned int);

	lf_onemethod->fldattr.fldattr = SWAP_UINT16(lf_onemethod->fldattr.fldattr);

	if((lf_onemethod->fldattr.bits.mprop == eMTintro) ||
		(lf_onemethod->fldattr.bits.mprop == eMTpureintro)) {
		READ(*read_bytes, 4, len, lf_onemethod->val.val, leaf_data, unsigned int);
	}

	tmp_before_read_bytes = *read_bytes;
	parse_sctring(&(lf_onemethod->val.str_data), leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_onemethod->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_onemethod->pad, *read_bytes, leaf_data, len);

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static void init_stype_info(STypeInfo *type_info)
{
	type_info->free_ = 0;
	type_info->get_members = 0;
	type_info->get_name = 0;
	type_info->get_val = 0;
	type_info->get_name_len = 0;
	type_info->get_arg_type = 0;
	type_info->get_element_type = 0;
	type_info->get_index_type = 0;
	type_info->get_base_type = 0;
	type_info->get_derived = 0;
	type_info->get_vshape = 0;
	type_info->get_utype = 0;
	type_info->get_return_type = 0;
	type_info->get_class_type = 0;
	type_info->get_this_type = 0;
	type_info->get_arglist = 0;
	type_info->get_index = 0;
	type_info->get_mlist = 0;
	type_info->get_modified_type = 0;
	type_info->is_fwdref = 0;
	type_info->get_print_type = 0;

	switch (type_info->leaf_type) {
	case eLF_FIELDLIST:
		type_info->get_members = get_fieldlist_members;
		type_info->free_ = free_lf_fieldlist;
		type_info->get_print_type = get_fieldlist_print_type;
		break;
	case eLF_ENUM:
		type_info->get_name = get_enum_name;
		type_info->get_name_len = get_enum_name_len;
		type_info->get_members = get_enum_members;
		type_info->get_utype = get_enum_utype;
		type_info->free_ = free_lf_enum;
		type_info->get_print_type = get_enum_print_type;
		break;
	case eLF_CLASS:
	case eLF_STRUCTURE:
		type_info->get_name = get_class_struct_name;
		type_info->get_val = get_class_struct_val; // for structure this is size
		type_info->get_name_len = get_class_struct_name_len;
		type_info->get_members = get_struct_class_members;
		type_info->get_derived = get_class_struct_derived;
		type_info->get_vshape = get_class_struct_vshape;
		type_info->is_fwdref = is_struct_class_fwdref;
		type_info->free_ = free_lf_class;
		type_info->get_print_type = get_class_struct_print_type;
		break;
	case eLF_POINTER:
		type_info->get_utype = get_pointer_utype;
		type_info->get_print_type = get_pointer_print_type;
		break;
	case eLF_ARRAY:
		type_info->get_name = get_array_name;
		type_info->get_val = get_array_val;
		type_info->get_name_len = get_array_name_len;
		type_info->get_element_type = get_array_element_type;
		type_info->get_index_type = get_array_index_type;
		type_info->free_ = free_lf_array;
		type_info->get_print_type = get_array_print_type;
		break;
	case eLF_MODIFIER:
		type_info->get_modified_type = get_modifier_modified_type;
		type_info->get_print_type = get_modifier_print_type;
		break;
	case eLF_ARGLIST:
		type_info->free_ = free_lf_arglist;
		type_info->get_print_type = get_arglist_print_type;
		break;
	case eLF_MFUNCTION:
		type_info->get_return_type = get_mfunction_return_type;
		type_info->get_class_type = get_mfunction_class_type;
		type_info->get_this_type = get_mfunction_this_type;
		type_info->get_arglist = get_mfunction_arglist;
		type_info->get_print_type = get_mfunction_print_type;
		break;
	case eLF_METHODLIST:
		break;
	case eLF_PROCEDURE:
		type_info->get_return_type = get_procedure_return_type;
		type_info->get_arglist = get_procedure_arglist;
		type_info->get_print_type = get_procedure_print_type;
		break;
	case eLF_UNION:
		type_info->get_name = get_union_name;
		type_info->get_val = get_union_val;
		type_info->get_name_len = get_union_name_len;
		type_info->get_members = get_union_members;
		type_info->is_fwdref = is_union_fwdref;
		type_info->free_ = free_lf_union;
		type_info->get_print_type = get_union_print_type;
		break;
	case eLF_BITFIELD:
		type_info->get_base_type = get_bitfield_base_type;
		type_info->get_print_type = get_bitfield_print_type;
		break;
	case eLF_VTSHAPE:
		type_info->free_ = free_lf_vtshape;
		type_info->get_print_type = get_vtshape_print_type;
		break;
	case eLF_ENUMERATE:
		type_info->get_name = get_enumerate_name;
		type_info->get_val = get_enumerate_val;
		type_info->get_name_len = get_enumerate_name_len;
		type_info->free_ = free_lf_enumerate;
		type_info->get_print_type = get_enumerate_print_type;
		break;
	case eLF_NESTTYPE:
		type_info->get_name = get_nesttype_name;
		type_info->get_name_len = get_nesttype_name_len;
		type_info->get_index = get_nesttype_index;
		type_info->free_ = free_lf_nesttype;
		type_info->get_print_type = get_nesttype_print_type;
		break;
	case eLF_METHOD:
		type_info->get_name = get_method_name;
		type_info->get_name_len = get_method_name_len;
		type_info->get_mlist = get_method_mlist;
		type_info->free_ = free_lf_method;
		type_info->get_print_type = get_method_print_type;
		break;
	case eLF_MEMBER:
		type_info->get_name = get_member_name;
		type_info->get_val = get_member_val;
		type_info->get_name_len = get_member_name_len;
		type_info->get_index = get_member_index;
		type_info->free_ = free_lf_member;
		type_info->get_print_type = get_member_print_type;
		break;
	case eLF_ONEMETHOD:
		type_info->get_name = get_onemethod_name;
		type_info->get_name_len = get_onemethod_name_len;
		type_info->get_val = get_onemethod_val;
		type_info->get_index = get_onemethod_index;
		type_info->free_ = free_lf_onemethod;
		type_info->get_print_type = get_onemethod_print_type;
		break;
	default:
//		printf("init_stype_info(): unknown type for init\n");
		type_info->get_name = 0;
		type_info->get_val = 0;
		type_info->get_name_len = 0;
		type_info->get_members = 0;
		type_info->get_arg_type = 0;
		type_info->get_element_type = 0;
		type_info->get_index_type = 0;
		type_info->get_base_type = 0;
		type_info->get_derived = 0;
		type_info->get_vshape = 0;
		type_info->get_utype = 0;
		type_info->get_return_type = 0;
		type_info->get_class_type = 0;
		type_info->get_this_type = 0;
		type_info->get_arglist = 0;
		type_info->get_index = 0;
		type_info->get_mlist = 0;
		type_info->get_print_type = 0;
		break;
	}
}

#define PARSE_LF2(lf_type, lf_func_name, type) { \
	STypeInfo *type_info = (STypeInfo *) malloc(sizeof(STypeInfo)); \
	lf_type *lf = (lf_type *) malloc(sizeof(lf_type)); \
	curr_read_bytes = parse_##lf_func_name(lf, p, read_bytes, len); \
	type_info->type_info = (void *) lf; \
	type_info->leaf_type = type; \
	init_stype_info(type_info); \
	r_list_append(lf_fieldlist->substructs, type_info); \
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_fieldlist(SLF_FIELDLIST *lf_fieldlist,  unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	ELeafType leaf_type;
	int curr_read_bytes = 0;
	unsigned char *p = leaf_data;

	lf_fieldlist->substructs = r_list_new();

	while (*read_bytes <= len) {
		READ(*read_bytes, 2, len, leaf_type, p, unsigned short);
		switch (leaf_type) {
		case eLF_ENUMERATE:
			PARSE_LF2(SLF_ENUMERATE, lf_enumerate, eLF_ENUMERATE);
			break;
		case eLF_NESTTYPE:
			PARSE_LF2(SLF_NESTTYPE, lf_nesttype, eLF_NESTTYPE);
			break;
		case eLF_METHOD:
			PARSE_LF2(SLF_METHOD, lf_method, eLF_METHOD);
			break;
		case eLF_MEMBER:
			PARSE_LF2(SLF_MEMBER, lf_member, eLF_MEMBER);
			break;
		case eLF_ONEMETHOD:
			PARSE_LF2(SLF_ONEMETHOD, lf_onemethod, eLF_ONEMETHOD);
			break;
		default:
//			printf("unsupported leaf type in parse_lf_fieldlist()\n");
			return 0;
		}

		if (curr_read_bytes != 0) {
			p += curr_read_bytes;
		} else return 0;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_enum(SLF_ENUM *lf_enum, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	lf_enum->name.name = 0;

	READ(*read_bytes, 2, len, lf_enum->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_enum->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_enum->utype, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_enum->field_list, leaf_data, unsigned int);

	lf_enum->prop.cv_property = SWAP_UINT16(lf_enum->prop.cv_property);
	before_read_bytes = *read_bytes;
	parse_sctring(&lf_enum->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_enum->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_enum->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_enum(): name = %s\n", lf_enum->name.name);
	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_class(SLF_CLASS *lf_class, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_CLASS lf_class;
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	lf_class->size.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_class->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_class->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_class->field_list, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_class->derived, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_class->vshape, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_class->size, leaf_data, read_bytes, len);
	before_read_bytes = *read_bytes - before_read_bytes;
	leaf_data = (unsigned char *)leaf_data + before_read_bytes;

	PEEK_READ(*read_bytes, 1, len, lf_class->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_class->pad, *read_bytes, leaf_data, len);

//	printf("%s:", "parse_lf_class()");
//	printf_sval_name(&lf_class->size);
//	printf("\n");
	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_structure(SLF_STRUCTURE *lf_structure, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_STRUCTURE lf_structure;
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	lf_structure->size.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_structure->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_structure->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_structure->field_list, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_structure->derived, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_structure->vshape, leaf_data, unsigned int);

	lf_structure->prop.cv_property = SWAP_UINT16(lf_structure->prop.cv_property);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_structure->size, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_structure->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_structure->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_structure(): name = ");
//	printf_sval_name(&lf_structure->size);
//	printf("\n");
	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_pointer(SLF_POINTER *lf_pointer, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ(*read_bytes, 4, len, lf_pointer->utype, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_pointer->ptr_attr.ptr_attr, leaf_data, unsigned int);

	lf_pointer->ptr_attr.ptr_attr = SWAP_UINT32(lf_pointer->ptr_attr.ptr_attr);

	PEEK_READ(*read_bytes, 1, len, lf_pointer->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_pointer->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_array(SLF_ARRAY *lf_array, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	lf_array->size.name_or_val = 0;

	READ(*read_bytes, 4, len, lf_array->element_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_array->index_type, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_array->size, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_array->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_array->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_array(): name = ");
//	printf_sval_name(&lf_array->size);
//	printf("\n");
	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_modifier(SLF_MODIFIER *lf_modifier, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ(*read_bytes, 4, len, lf_modifier->modified_type, leaf_data, unsigned int);
	READ(*read_bytes, 2, len, lf_modifier->umodifier.modifier, leaf_data, unsigned short);
	lf_modifier->umodifier.modifier = SWAP_UINT16(lf_modifier->umodifier.modifier);

	PEEK_READ(*read_bytes, 1, len, lf_modifier->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_modifier->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_arglist(SLF_ARGLIST *lf_arglist, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;

	lf_arglist->arg_type = 0;

	READ(*read_bytes, 4, len, lf_arglist->count, leaf_data, unsigned int);

	lf_arglist->arg_type = (unsigned int *) malloc(lf_arglist->count * 4);
	memcpy(lf_arglist->arg_type, leaf_data, lf_arglist->count * 4);
	leaf_data += (lf_arglist->count * 4);
	*read_bytes += (lf_arglist->count * 4);

	PEEK_READ(*read_bytes, 1, len, lf_arglist->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_arglist->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_mfunction(SLF_MFUNCTION *lf_mfunction, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ(*read_bytes, 4, len, lf_mfunction->return_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_mfunction->class_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_mfunction->this_type, leaf_data, unsigned int);
	READ(*read_bytes, 1, len, lf_mfunction->call_conv, leaf_data, unsigned char);
	READ(*read_bytes, 1, len, lf_mfunction->reserved, leaf_data, unsigned char);
	READ(*read_bytes, 2, len, lf_mfunction->parm_count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_mfunction->arglist, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_mfunction->this_adjust, leaf_data, int);

	PEEK_READ(*read_bytes, 1, len, lf_mfunction->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_mfunction->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

/////////////////////////////////////////////////////////////////////////////////
static int parse_lf_procedure(SLF_PROCEDURE *lf_procedure, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ(*read_bytes, 4, len, lf_procedure->return_type, leaf_data, unsigned int);
	READ(*read_bytes, 1, len, lf_procedure->call_conv, leaf_data, unsigned char);
	READ(*read_bytes, 1, len, lf_procedure->reserved, leaf_data, unsigned char);
	READ(*read_bytes, 2, len, lf_procedure->parm_count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_procedure->arg_list, leaf_data, unsigned int);

	PEEK_READ(*read_bytes, 1, len, lf_procedure->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_procedure->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_union(SLF_UNION *lf_union, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	lf_union->size.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_union->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_union->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_union->field_list, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_union->size, leaf_data, read_bytes, len);
	before_read_bytes = *read_bytes - before_read_bytes;
	leaf_data = (unsigned char *)leaf_data + before_read_bytes;

	PEEK_READ(*read_bytes, 1, len, lf_union->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_union->pad, *read_bytes, leaf_data, len);

//	printf("%s:", "parse_lf_union()");
//	printf_sval_name(&lf_union->size);
//	printf("\n");
	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_bitfield(SLF_BITFIELD *lf_bitfield, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ(*read_bytes, 4, len, lf_bitfield->base_type, leaf_data, unsigned int);
	READ(*read_bytes, 1, len, lf_bitfield->length, leaf_data, unsigned char);
	READ(*read_bytes, 1, len, lf_bitfield->position, leaf_data, unsigned char);

	PEEK_READ(*read_bytes, 1, len, lf_bitfield->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_bitfield->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_vtshape(SLF_VTSHAPE *lf_vtshape, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int size; // in bytes;

	lf_vtshape->vt_descriptors = 0;

	READ(*read_bytes, 2, len, lf_vtshape->count, leaf_data, unsigned short);

	size = (4 * lf_vtshape->count + (lf_vtshape->count % 2) * 4) / 8;
	lf_vtshape->vt_descriptors = (char *) malloc(size);
	memcpy(lf_vtshape->vt_descriptors, leaf_data, size);
	leaf_data += size;
	*read_bytes += size;

	PEEK_READ(*read_bytes, 1, len, lf_vtshape->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_vtshape->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

#define PARSE_LF(lf_type, lf_func) { \
	lf_type *lf = (lf_type *) malloc(sizeof(lf_type)); \
	parse_##lf_func(lf, leaf_data + 2, &read_bytes, type->length); \
	type->type_data.type_info = (void *) lf; \
	init_stype_info(&type->type_data); \
}

///////////////////////////////////////////////////////////////////////////////
static int parse_tpi_stypes(R_STREAM_FILE *stream, SType *type) {
	unsigned char *leaf_data;
	unsigned int read_bytes = 0;

	stream_file_read(stream, 2, (char *)&type->length);
	if (type->length<1)
		return 0;
	leaf_data = (unsigned char *) malloc(type->length);
	stream_file_read (stream, type->length, (char *)leaf_data);
	type->type_data.leaf_type = *(unsigned short *)leaf_data;
	read_bytes += 2;
	switch (type->type_data.leaf_type) {
	case eLF_FIELDLIST:
//		printf("eLF_FIELDLIST\n");
		PARSE_LF(SLF_FIELDLIST, lf_fieldlist);
		break;
	case eLF_ENUM:
//		printf("eLF_ENUM\n");
		PARSE_LF(SLF_ENUM, lf_enum);
		break;
	// TODO: combine with eLF_STRUCTURE
	case eLF_CLASS:
//		printf("eLF_CLASS\n");
		PARSE_LF(SLF_CLASS, lf_class);
		break;
	case eLF_STRUCTURE:
//		printf("eLF_STRUCTURE\n");
		PARSE_LF(SLF_STRUCTURE, lf_structure);
		break;
	case eLF_POINTER:
//		printf("eLF_POINTER\n");
	{
		SLF_POINTER *lf = (SLF_POINTER *) malloc(sizeof(SLF_POINTER)); \
		parse_lf_pointer(lf, leaf_data + 2, &read_bytes, type->length); \
		type->type_data.type_info = (void *) lf; \
		init_stype_info(&type->type_data); \
	}
//		PARSE_LF(SLF_POINTER, lf_pointer);
		break;
	case eLF_ARRAY:
//		printf("eLF_ARRAY\n");
		PARSE_LF(SLF_ARRAY, lf_array);
		break;
	case eLF_MODIFIER:
//		printf("eLF_MODIFIER\n");
		PARSE_LF(SLF_MODIFIER, lf_modifier);
		break;
	case eLF_ARGLIST:
//		printf("eLF_ARGLIST\n");
		PARSE_LF(SLF_ARGLIST, lf_arglist);
		break;
	case eLF_MFUNCTION:
//		printf("eLF_MFUNCTION\n");
		PARSE_LF(SLF_MFUNCTION, lf_mfunction);
		break;
	case eLF_METHODLIST:
//		printf("eLF_METHOD_LIST\n");
		break;
	case eLF_PROCEDURE:
//		printf("eLF_PROCEDURE\n");
		PARSE_LF(SLF_PROCEDURE, lf_procedure);
		break;
	case eLF_UNION:
//		printf("eLF_UNION\n");
		PARSE_LF(SLF_UNION, lf_union);
		break;
	case eLF_BITFIELD:
//		printf("eLF_BITFIELD\n");
		PARSE_LF(SLF_BITFIELD, lf_bitfield);
		break;
	case eLF_VTSHAPE:
//		printf("eLF_VTSHAPE\n");
		PARSE_LF(SLF_VTSHAPE, lf_vtshape);
		break;
	default:
		printf("parse_tpi_streams(): unsupported leaf type\n");
		break;
	}

	free (leaf_data);
	return read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
int parse_tpi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream) {
	int i;
	SType *type = 0;
	STpiStream *tpi_stream = (STpiStream *) parsed_pdb_stream;
	tpi_stream->types = r_list_new();
	p_types_list = tpi_stream->types;

	stream_file_read(stream, sizeof(STPIHeader), (char *)&tpi_stream->header);

	base_idx = tpi_stream->header.ti_min;

	for (i = tpi_stream->header.ti_min; i < tpi_stream->header.ti_max; i++) {
		type = (SType *) malloc(sizeof(SType));
		type->tpi_idx = i;
		type->type_data.type_info = 0;
		type->type_data.leaf_type = eLF_MAX;
		init_stype_info(&type->type_data);
		if (!parse_tpi_stypes(stream, type))
			return 0;
		r_list_append(tpi_stream->types, type);
	}
	return 1;
	// Postprocessing...
}

///////////////////////////////////////////////////////////////////////////////
void init_tpi_stream(STpiStream *tpi_stream)
{
	tpi_stream->free_ = free_tpi_stream;
}
