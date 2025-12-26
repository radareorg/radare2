/* radare - LGPL - Copyright 2014-2025 - inisider, pancake */

#include "types.h"
#include "tpi.h"
#include "stream_file.h"

static bool is_simple_type(int idx) {
	/* https://llvm.org/docs/PDB/TpiStream.html#type-indices */
	return ((ut32)idx) < 0x1000;
}

// Free a simple type that was dynamically allocated (tpi_idx == 0)
static void free_simple_type(SType *t) {
	if (t && t->tpi_idx == 0 && t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *st = (SLF_SIMPLE_TYPE *)t->type_data.type_info;
		free (st->type);
		free (st);
		free (t);
	}
}

/**
 * @brief Parses simple type if the idx represents one
 *
 * @param idx
 * @return STypeInfo, leaf_type = 0 -> error
 *  This can be made smarter by using the masks
 *  and splitting it on 2 parts, 1 mode, 1 type
 */
static STypeInfo parse_simple_type(ut32 idx) {
	STypeInfo type = { 0 };
	SLF_SIMPLE_TYPE *simple_type = R_NEW0 (SLF_SIMPLE_TYPE);
	switch (idx) {
	case eT_NOTYPE: // uncharacterized type (no type)
		simple_type->size = 0;
		simple_type->type = strdup ("notype_t");
		break;
	case eT_VOID: // void
		simple_type->size = 0;
		simple_type->type = strdup ("void");
		break;
	case eT_PVOID: // near ptr to void (2 bytes?)
		simple_type->size = 2;
		simple_type->type = strdup ("void *");
		break;
	case eT_PFVOID: // far ptr to void (4 bytes)
	case eT_PHVOID: // huge ptr to void (4 bytes)
	case eT_32PVOID:
	case eT_32PFVOID:
		simple_type->size = 4;
		simple_type->type = strdup ("void *");
		break;
	case eT_64PVOID:
		simple_type->size = 8;
		simple_type->type = strdup ("void *");
		break;

	case eT_CHAR:
		simple_type->size = 1;
		simple_type->type = strdup ("char");
		break;
	case eT_PCHAR: // near
		simple_type->size = 2;
		simple_type->type = strdup ("char *");
		break;
	case eT_PFCHAR:
	case eT_PHCHAR:
	case eT_32PCHAR:
	case eT_32PFCHAR:
		simple_type->size = 4;
		simple_type->type = strdup ("uint8_t *");
		break;
	case eT_64PCHAR:
		simple_type->size = 8;
		simple_type->type = strdup ("uint8_t *");
		break;

	case eT_UCHAR:
		simple_type->size = 1;
		simple_type->type = strdup ("uint8_t");
		break;
	case eT_PUCHAR:
		simple_type->size = 2;
		simple_type->type = strdup ("uint8_t *");
		break;
	case eT_PFUCHAR:
	case eT_PHUCHAR:
	case eT_32PUCHAR:
	case eT_32PFUCHAR:
		simple_type->size = 4;
		simple_type->type = strdup ("uint8_t *");
		break;
	case eT_64PUCHAR:
		simple_type->size = 8;
		simple_type->type = strdup ("uint8_t *");
		break;

	case eT_RCHAR:
		simple_type->size = 1;
		simple_type->type = strdup ("char");
		break;
	case eT_PRCHAR:
		simple_type->size = 2;
		simple_type->type = strdup ("char *");
		break;
	case eT_PFRCHAR:
	case eT_PHRCHAR:
	case eT_32PRCHAR:
	case eT_32PFRCHAR:
		simple_type->size = 4;
		simple_type->type = strdup ("char *");
		break;
	case eT_64PRCHAR:
		simple_type->size = 8;
		simple_type->type = strdup ("char *");
		break;

	case eT_WCHAR:
		simple_type->size = 4;
		simple_type->type = strdup ("wchar_t");
		break;
	case eT_PWCHAR:
		simple_type->size = 2;
		simple_type->type = strdup ("wchar_t *");
		break;
	case eT_PFWCHAR:
	case eT_PHWCHAR:
	case eT_32PWCHAR:
	case eT_32PFWCHAR:
		simple_type->size = 4;
		simple_type->type = strdup ("wchar_t *");
		break;
	case eT_64PWCHAR:
		simple_type->size = 8;
		simple_type->type = strdup ("wchar_t *");
		break;

	case eT_BYTE:
		simple_type->size = 1;
		simple_type->type = strdup ("char");
		break;
	case eT_PBYTE:
		simple_type->size = 2;
		simple_type->type = strdup ("char *");
		break;
	case eT_PFBYTE:
	case eT_PHBYTE:
	case eT_32PBYTE:
	case eT_32PFBYTE:
		simple_type->size = 4;
		simple_type->type = strdup ("char *");
		break;
	case eT_64PBYTE:
		simple_type->size = 8;
		simple_type->type = strdup ("char *");
		break;

	case eT_UBYTE:
		simple_type->size = 1;
		simple_type->type = strdup ("uint8_t");
		break;
	case eT_PUBYTE:
		simple_type->size = 2;
		simple_type->type = strdup ("uint8_t *");
		break;
	case eT_PFUBYTE:
	case eT_PHUBYTE:
	case eT_32PUBYTE:
	case eT_32PFUBYTE:
		simple_type->size = 4;
		simple_type->type = strdup ("uint8_t *");
		break;
	case eT_64PUBYTE:
		simple_type->size = 8;
		simple_type->type = strdup ("uint8_t*");
		break;

	case eT_INT16: // 16 bit
	case eT_SHORT: // 16 bit short
		simple_type->size = 2;
		simple_type->type = strdup ("uint16_t");
		break;
	case eT_PINT16:
	case eT_PSHORT:
		simple_type->size = 2;
		simple_type->type = strdup ("uint16_t *");
		break;
	case eT_PFSHORT:
	case eT_PHSHORT:
	case eT_32PSHORT:
	case eT_32PFSHORT:
	case eT_PFINT16:
	case eT_PHINT16:
	case eT_32PINT16:
	case eT_32PFINT16:
		simple_type->size = 4;
		simple_type->type = strdup ("uint16_t *");
		break;
	case eT_64PINT16:
	case eT_64PSHORT:
		simple_type->size = 8;
		simple_type->type = strdup ("uint16_t *");
		break;

	case eT_UINT16: // 16 bit
	case eT_USHORT: // 16 bit short
		simple_type->size = 2;
		simple_type->type = strdup ("uint16_t");
		break;
	case eT_PUINT16:
	case eT_PUSHORT:
		simple_type->size = 2;
		simple_type->type = strdup ("uint16_t *");
		break;
	case eT_PFUSHORT:
	case eT_PHUSHORT:
	case eT_32PUSHORT:
	case eT_PFUINT16:
	case eT_PHUINT16:
	case eT_32PUINT16:
	case eT_32PFUINT16:
	case eT_32PFUSHORT:
		simple_type->size = 4;
		simple_type->type = strdup ("uint16_t *");
		break;
	case eT_64PUINT16:
	case eT_64PUSHORT:
		simple_type->size = 8;
		simple_type->type = strdup ("uint16_t *");
		break;

	case eT_LONG:
	case eT_INT4:
		simple_type->size = 4;
		simple_type->type = strdup ("int32_t");
		break;
	case eT_PLONG:
	case eT_PINT4:
		simple_type->size = 2;
		simple_type->type = strdup ("int32_t *");
		break;
	case eT_PFLONG:
	case eT_PHLONG:
	case eT_32PLONG:
	case eT_32PFLONG:
	case eT_PFINT4:
	case eT_PHINT4:
	case eT_32PINT4:
	case eT_32PFINT4:
		simple_type->size = 4;
		simple_type->type = strdup ("int32_t *");
		break;
	case eT_64PLONG:
	case eT_64PINT4:
		simple_type->size = 8;
		simple_type->type = strdup ("int32_t *");
		break;

	case eT_ULONG:
	case eT_UINT4:
		simple_type->size = 4;
		simple_type->type = strdup ("uint32_t");
		break;
	case eT_PULONG:
	case eT_PUINT4:
		simple_type->size = 2;
		simple_type->type = strdup ("uint32_t *");
		break;
	case eT_PFULONG:
	case eT_PHULONG:
	case eT_32PULONG:
	case eT_32PFULONG:
	case eT_PFUINT4:
	case eT_PHUINT4:
	case eT_32PUINT4:
	case eT_32PFUINT4:
		simple_type->size = 4;
		simple_type->type = strdup ("uint32_t *");
		break;
	case eT_64PULONG:
	case eT_64PUINT4:
		simple_type->size = 8;
		simple_type->type = strdup ("uint32_t *");
		break;

	case eT_INT8:
	case eT_QUAD:
		simple_type->size = 8;
		simple_type->type = strdup ("int64_t");
		break;
	case eT_PQUAD:
	case eT_PINT8:
		simple_type->size = 2;
		simple_type->type = strdup ("int64_t *");
		break;
	case eT_PFQUAD:
	case eT_PHQUAD:
	case eT_32PQUAD:
	case eT_32PFQUAD:
	case eT_PFINT8:
	case eT_PHINT8:
	case eT_32PINT8:
	case eT_32PFINT8:
		simple_type->size = 4;
		simple_type->type = strdup ("int64_t *");
		break;
	case eT_64PQUAD:
	case eT_64PINT8:
		simple_type->size = 8;
		simple_type->type = strdup ("int64_t *");
		break;

	case eT_UQUAD:
	case eT_UINT8:
		simple_type->size = 8;
		simple_type->type = strdup ("uint64_t");
		break;

	case eT_PUQUAD:
	case eT_PUINT8:
		simple_type->size = 2;
		simple_type->type = strdup ("uint64_t *");
		break;
	case eT_PFUQUAD:
	case eT_PHUQUAD:
	case eT_32PUQUAD:
	case eT_32PFUQUAD:
	case eT_PFUINT8:
	case eT_PHUINT8:
	case eT_32PUINT8:
	case eT_32PFUINT8:
		simple_type->size = 4;
		simple_type->type = strdup ("uint64_t *");
		break;
	case eT_64PUQUAD:
	case eT_64PUINT8:
		simple_type->size = 8;
		simple_type->type = strdup ("uint64_t *");
		break;
	case eT_INT128:
	case eT_OCT:
		simple_type->size = 16;
		simple_type->type = strdup ("int128_t");
		break;
	case eT_PINT128:
	case eT_POCT:
		simple_type->size = 2;
		simple_type->type = strdup ("int128_t *");
		break;
	case eT_PFINT128:
	case eT_PHINT128:
	case eT_32PINT128:
	case eT_32PFINT128:
	case eT_PFOCT:
	case eT_PHOCT:
	case eT_32POCT:
	case eT_32PFOCT:
		simple_type->size = 4;
		simple_type->type = strdup ("int128_t *");
		break;
	case eT_64PINT128:
	case eT_64POCT:
		simple_type->size = 8;
		simple_type->type = strdup ("int128_t *");
		break;

	case eT_UINT128:
	case eT_UOCT:
		simple_type->size = 16;
		simple_type->type = strdup ("uint128_t");
		break;
	case eT_PUINT128:
	case eT_PUOCT:
		simple_type->size = 2;
		simple_type->type = strdup ("uint128_t *");
		break;
	case eT_PFUINT128:
	case eT_PHUINT128:
	case eT_32PUINT128:
	case eT_32PFUINT128:
	case eT_PFUOCT:
	case eT_PHUOCT:
	case eT_32PUOCT:
	case eT_32PFUOCT:
		simple_type->size = 4;
		simple_type->type = strdup ("uint128_t *");
		break;
	case eT_64PUINT128:
	case eT_64PUOCT:
		simple_type->size = 8;
		simple_type->type = strdup ("uint128_t *");
		break;
	case eT_REAL32:
		simple_type->size = 4;
		simple_type->type = strdup ("float");
		break;
	case eT_PREAL32:
		simple_type->size = 2;
		simple_type->type = strdup ("float *");
		break;
	case eT_PFREAL32:
	case eT_PHREAL32:
	case eT_32PREAL32:
	case eT_32PFREAL32:
		simple_type->size = 4;
		simple_type->type = strdup ("float *");
		break;
	case eT_64PREAL32:
		simple_type->size = 8;
		simple_type->type = strdup ("float *");
		break;
	case eT_REAL48:
		simple_type->size = 6;
		simple_type->type = strdup ("float");
		break;
	case eT_PREAL48:
		simple_type->size = 2;
		simple_type->type = strdup ("float *");
		break;
	case eT_PFREAL48:
	case eT_PHREAL48:
	case eT_32PREAL48:
	case eT_32PFREAL48:
		simple_type->size = 4;
		simple_type->type = strdup ("float *");
		break;
	case eT_64PREAL48:
		simple_type->size = 8;
		simple_type->type = strdup ("float *");
		break;
	case eT_REAL64:
		simple_type->size = 8;
		simple_type->type = strdup ("double");
		break;
	case eT_PREAL64:
		simple_type->size = 2;
		simple_type->type = strdup ("double *");
		break;
	case eT_PFREAL64:
	case eT_PHREAL64:
	case eT_32PREAL64:
	case eT_32PFREAL64:
		simple_type->size = 4;
		simple_type->type = strdup ("long double *");
		break;
	case eT_64PREAL64:
		simple_type->size = 8;
		simple_type->type = strdup ("long double *");
		break;

	case eT_REAL80:
		simple_type->size = 10;
		simple_type->type = strdup ("long double");
		break;
	case eT_PREAL80:
		simple_type->size = 2;
		simple_type->type = strdup ("long double *");
		break;
	case eT_PFREAL80:
	case eT_PHREAL80:
	case eT_32PREAL80:
	case eT_32PFREAL80:
		simple_type->size = 4;
		simple_type->type = strdup ("long double *");
		break;
	case eT_64PREAL80:
		simple_type->size = 8;
		simple_type->type = strdup ("long double *");
		break;

	case eT_REAL128:
		simple_type->size = 16;
		simple_type->type = strdup ("long double");
		break;
	case eT_PREAL128:
		simple_type->size = 2;
		simple_type->type = strdup ("long double *");
		break;
	case eT_PFREAL128:
	case eT_PHREAL128:
	case eT_32PREAL128:
	case eT_32PFREAL128:
		simple_type->size = 4;
		simple_type->type = strdup ("long double *");
		break;
	case eT_64PREAL128:
		simple_type->size = 8;
		simple_type->type = strdup ("long double *");
		break;

	case eT_CPLX32:
		simple_type->size = 4;
		simple_type->type = strdup ("float _Complex");
		break;
	case eT_PCPLX32:
		simple_type->size = 2;
		simple_type->type = strdup ("float _Complex *");
		break;
	case eT_PFCPLX32:
	case eT_PHCPLX32:
	case eT_32PCPLX32:
	case eT_32PFCPLX32:
		simple_type->size = 4;
		simple_type->type = strdup ("float _Complex *");
		break;
	case eT_64PCPLX32:
		simple_type->size = 8;
		simple_type->type = strdup ("float _Complex *");
		break;

	case eT_CPLX64:
		simple_type->size = 8;
		simple_type->type = strdup ("double _Complex");
		break;
	case eT_PCPLX64:
		simple_type->size = 2;
		simple_type->type = strdup ("double _Complex *");
		break;
	case eT_PFCPLX64:
	case eT_PHCPLX64:
	case eT_32PCPLX64:
	case eT_32PFCPLX64:
		simple_type->size = 4;
		simple_type->type = strdup ("double _Complex *");
		break;
	case eT_64PCPLX64:
		simple_type->size = 8;
		simple_type->type = strdup ("double _Complex *");
		break;

	case eT_CPLX80:
		simple_type->size = 10;
		simple_type->type = strdup ("long double _Complex");
		break;
	case eT_PCPLX80:
		simple_type->size = 2;
		simple_type->type = strdup ("long double _Complex *");
		break;
	case eT_PFCPLX80:
	case eT_PHCPLX80:
	case eT_32PCPLX80:
	case eT_32PFCPLX80:
		simple_type->size = 4;
		simple_type->type = strdup ("long double _Complex *");
		break;
	case eT_64PCPLX80:
		simple_type->size = 8;
		simple_type->type = strdup ("long double _Complex *");
		break;

	case eT_CPLX128:
		simple_type->size = 16;
		simple_type->type = strdup ("long double _Complex");
		break;
	case eT_PCPLX128:
		simple_type->size = 2;
		simple_type->type = strdup ("long double _Complex *");
		break;
	case eT_PFCPLX128:
	case eT_PHCPLX128:
	case eT_32PCPLX128:
	case eT_32PFCPLX128:
		simple_type->size = 4;
		simple_type->type = strdup ("long double _Complex *");
		break;
	case eT_64PCPLX128:
		simple_type->size = 8;
		simple_type->type = strdup ("long double _Complex *");
		break;

	case eT_BOOL08: // _Bool probably isn't ideal for bool > 08
		simple_type->size = 1;
		simple_type->type = strdup ("_Bool");
		break;
	case eT_PBOOL08:
		simple_type->size = 2;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_PFBOOL08:
	case eT_PHBOOL08:
	case eT_32PBOOL08:
	case eT_32PFBOOL08:
		simple_type->size = 4;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_64PBOOL08:
		simple_type->size = 8;
		simple_type->type = strdup ("_Bool *");
		break;

	case eT_BOOL16:
		simple_type->size = 2;
		simple_type->type = strdup ("_Bool");
		break;
	case eT_PBOOL16:
		simple_type->size = 2;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_PFBOOL16:
	case eT_PHBOOL16:
	case eT_32PBOOL16:
	case eT_32PFBOOL16:
		simple_type->size = 4;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_64PBOOL16:
		simple_type->size = 8;
		simple_type->type = strdup ("_Bool *");
		break;

	case eT_BOOL32:
		simple_type->size = 4;
		simple_type->type = strdup ("_Bool");
		break;
	case eT_PBOOL32:
		simple_type->size = 2;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_PFBOOL32:
	case eT_PHBOOL32:
	case eT_32PBOOL32:
	case eT_32PFBOOL32:
		simple_type->size = 4;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_64PBOOL32:
		simple_type->size = 8;
		simple_type->type = strdup ("_Bool *");
		break;

	case eT_BOOL64:
		simple_type->size = 8;
		simple_type->type = strdup ("_Bool");
		break;
	case eT_PBOOL64:
		simple_type->size = 2;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_PFBOOL64:
	case eT_PHBOOL64:
	case eT_32PBOOL64:
	case eT_32PFBOOL64:
		simple_type->size = 4;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_64PBOOL64:
		simple_type->size = 8;
		simple_type->type = strdup ("_Bool *");
		break;

	case eT_BOOL128:
		simple_type->size = 16;
		simple_type->type = strdup ("_Bool");
		break;
	case eT_PBOOL128:
		simple_type->size = 2;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_PFBOOL128:
	case eT_PHBOOL128:
	case eT_32PBOOL128:
	case eT_32PFBOOL128:
		simple_type->size = 4;
		simple_type->type = strdup ("_Bool *");
		break;
	case eT_64PBOOL128:
		simple_type->size = 8;
		simple_type->type = strdup ("_Bool *");
		break;
	default:
		simple_type->size = 0;
		simple_type->type = strdup ("unknown_t");
		break;
	}
	simple_type->simple_type = idx;
	type.type_info = simple_type;
	type.leaf_type = eLF_SIMPLE_TYPE;
	return type;
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_name_len(SVal *val, int *res_len) {
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr = (SCString *)val->name_or_val;
		*res_len = scstr->size;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
			{
				SVal_LF_ULONG *lf_ulong;
				lf_ulong = (SVal_LF_ULONG *)val->name_or_val;
				*res_len = lf_ulong->name.size;
				break;
			}
		case eLF_USHORT:
			{
				SVal_LF_USHORT *lf_ushort;
				lf_ushort = (SVal_LF_USHORT *)val->name_or_val;
				*res_len = lf_ushort->name.size;
				break;
			}
		default:
			*res_len = 0;
			printf ("get_sval_name_len: Skipping unsupported type (%d)\n", val->value_or_type);
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_name(STpiStream *ss, SVal *val, char **name) {
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *)val->name_or_val;
		if (scstr) {
			*name = scstr->name;
		} else {
			*name = NULL;
		}
	} else {
		switch (val->value_or_type) {
		case eLF_UQUADWORD:
			{
				SVal_LF_UQUADWORD *lf_uquadword;
				lf_uquadword = (SVal_LF_UQUADWORD *)val->name_or_val;
				*name = lf_uquadword->name.name;
				break;
			}
		case eLF_QUADWORD:
			{
				SVal_LF_QUADWORD *lf_quadword;
				lf_quadword = (SVal_LF_QUADWORD *)val->name_or_val;
				*name = lf_quadword->name.name;
				break;
			}
		case eLF_CHAR:
			{
				SVal_LF_CHAR *lf_char;
				lf_char = (SVal_LF_CHAR *)val->name_or_val;
				*name = lf_char->name.name;
				//			strcpy (name, lf_uchar->name.name);
				break;
			}
		case eLF_ULONG:
			{
				SVal_LF_ULONG *lf_ulong;
				lf_ulong = (SVal_LF_ULONG *)val->name_or_val;
				*name = lf_ulong->name.name;
				//			strcpy (name, lf_ulong->name.name);
				break;
			}
		case eLF_LONG:
			{
				SVal_LF_LONG *lf_long;
				lf_long = (SVal_LF_LONG *)val->name_or_val;
				*name = lf_long->name.name;
				//			strcpy (name, lf_long->name.name);
				break;
			}
		case eLF_USHORT:
			{
				SVal_LF_USHORT *lf_ushort;
				lf_ushort = (SVal_LF_USHORT *)val->name_or_val;
				*name = lf_ushort->name.name;
				//			strcpy (name, lf_ushort->name.name);
				break;
			}
		case eLF_SHORT:
			{
				SVal_LF_SHORT *lf_short;
				lf_short = (SVal_LF_SHORT *)val->name_or_val;
				*name = lf_short->name.name;
				break;
			}
		default:
			*name = NULL;
			R_LOG_ERROR ("Skipping unsupported type (%d)", val->value_or_type);
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void is_union_fwdref(STpiStream *ss, void *type, int *is_fwdref) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_UNION *lf = (SLF_UNION *)t->type_info;

	*is_fwdref = lf->prop.bits.fwdref;
}

///////////////////////////////////////////////////////////////////////////////
//
static void is_struct_class_fwdref(STpiStream *ss, void *type, int *is_fwdref) {
	STypeInfo *t = (STypeInfo *)type;
	// SLF_STRUCTURE and SLF_CLASS refer to the same struct so this is fine
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;
	*is_fwdref = lf->prop.bits.fwdref;
}

///////////////////////////////////////////////////////////////////////////////
static int get_array_element_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *)t->type_info;
	int curr_idx = lf_array->element_type;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	return curr_idx;
}

static int get_array_index_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *)t->type_info;
	int curr_idx = lf_array->index_type;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	return curr_idx;
}

static int get_bitfield_base_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_BITFIELD *lf = (SLF_BITFIELD *)t->type_info;
	int curr_idx = lf->base_type;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	return curr_idx;
}

static int get_class_struct_derived(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;
	int curr_idx = lf->derived;
	if (curr_idx) {
		curr_idx -= ss->ctx.base_idx;
		*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	} else {
		*ret_type = NULL;
	}

	return curr_idx;
}

static int get_class_struct_vshape(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;
	int curr_idx = lf->vshape;
	if (curr_idx) {
		curr_idx -= ss->ctx.base_idx;
		*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	} else {
		*ret_type = NULL;
	}
	return curr_idx;
}

static int get_mfunction_return_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *)t->type_info;
	int curr_idx = lf->return_type;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	return curr_idx;
}

static int get_mfunction_class_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *)t->type_info;
	int curr_idx = lf->class_type;

	if (curr_idx) {
		curr_idx -= ss->ctx.base_idx;
		*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	} else {
		*ret_type = NULL;
	}

	return curr_idx;
}

static int get_mfunction_this_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *)t->type_info;
	int curr_idx = lf->this_type;

	if (curr_idx) {
		curr_idx -= ss->ctx.base_idx;
		*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	} else {
		*ret_type = NULL;
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_arglist(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *)t->type_info;
	int curr_idx = lf->arglist;

	if (curr_idx) {
		curr_idx -= ss->ctx.base_idx;
		*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	} else {
		*ret_type = NULL;
	}

	return curr_idx;
}

///////////////////////////////////////////////////////////////////////////////
static int get_modifier_modified_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MODIFIER *lf = (SLF_MODIFIER *)t->type_info;
	int curr_idx = lf->modified_type;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	return curr_idx;
}

static int get_pointer_utype(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_POINTER *lf = (SLF_POINTER *)t->type_info;
	int curr_idx = lf->utype;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);
	return curr_idx;
}

static int get_procedure_return_type(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_PROCEDURE *lf = (SLF_PROCEDURE *)t->type_info;
	int curr_idx = lf->return_type;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static int get_procedure_arglist(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_PROCEDURE *lf = (SLF_PROCEDURE *)t->type_info;
	int curr_idx = lf->arg_list;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static int get_member_index(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;
	int curr_idx = lf->index;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static int get_nesttype_index(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;
	int curr_idx = lf->index;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static int get_onemethod_index(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *)t->type_info;
	int curr_idx = lf->index;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static int get_method_mlist(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;
	int curr_idx = lf->mlist;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static int get_enum_utype(STpiStream *ss, void *type, void **ret_type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUM *lf = (SLF_ENUM *)t->type_info;
	int curr_idx = lf->utype;

	if (is_simple_type (curr_idx)) {
		STypeInfo base_type = parse_simple_type (curr_idx);
		SType *base_ret_type = R_NEW0 (SType);
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		*ret_type = base_ret_type;
		return 0;
	}
	curr_idx -= ss->ctx.base_idx;
	*ret_type = r_list_get_n (ss->ctx.types_list, curr_idx);

	return curr_idx;
}

static void get_fieldlist_members(STpiStream *ss, void *type, RList **l) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *)t->type_info;

	*l = lf_fieldlist->substructs;
}

static void get_union_members(STpiStream *ss, void *type, RList **l) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_UNION *lf_union = (SLF_UNION *)t->type_info;
	unsigned int indx = 0;

	if (!lf_union || lf_union->field_list == 0) {
		*l = 0;
	} else {
		SType *tmp = 0;
		indx = lf_union->field_list - ss->ctx.base_idx;
		tmp = (SType *)r_list_get_n (ss->ctx.types_list, indx);
		*l = tmp? ((SLF_FIELDLIST *)tmp->type_data.type_info)->substructs: NULL;
	}
}

static void get_struct_class_members(STpiStream *ss, void *type, RList **l) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;
	unsigned int indx = 0;

	if (!lf || lf->field_list == 0) {
		*l = 0;
	} else {
		SType *tmp = 0;
		indx = lf->field_list - ss->ctx.base_idx;
		tmp = (SType *)r_list_get_n (ss->ctx.types_list, indx);
		*l = tmp? ((SLF_FIELDLIST *)tmp->type_data.type_info)->substructs: NULL;
	}
}

static void get_enum_members(STpiStream *ss, void *type, RList **l) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUM *lf = (SLF_ENUM *)t->type_info;

	if (!lf || lf->field_list == 0) {
		*l = 0;
	} else {
		unsigned int indx = lf->field_list - ss->ctx.base_idx;
		SType *tmp = (SType *)r_list_get_n (ss->ctx.types_list, indx);
		*l = tmp? ((SLF_FIELDLIST *)tmp->type_data.type_info)->substructs: NULL;
	}
}

static void get_sval_val(SVal *val, int *res) {
	if (val->value_or_type < eLF_CHAR) {
		*res = val->value_or_type;
		return;
	}
	switch (val->value_or_type) {
	case eLF_UQUADWORD:
		{
			SVal_LF_UQUADWORD *lf_uqword;
			lf_uqword = (SVal_LF_UQUADWORD *)val->name_or_val;
			*res = lf_uqword->value;
			break;
		}
	case eLF_QUADWORD:
		{
			SVal_LF_QUADWORD *lf_qword;
			lf_qword = (SVal_LF_QUADWORD *)val->name_or_val;
			*res = lf_qword->value;
			break;
		}
	case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *)val->name_or_val;
			*res = lf_ulong->value;
			break;
		}
	case eLF_LONG:
		{
			SVal_LF_LONG *lf_long;
			lf_long = (SVal_LF_LONG *)val->name_or_val;
			*res = lf_long->value;
			break;
		}
	case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *)val->name_or_val;
			*res = lf_ushort->value;
			break;
		}
	case eLF_SHORT:
		{
			SVal_LF_SHORT *lf_short;
			lf_short = (SVal_LF_SHORT *)val->name_or_val;
			*res = lf_short->value;
			break;
		}
	case eLF_CHAR:
		{
			SVal_LF_CHAR *lf_char;
			lf_char = (SVal_LF_CHAR *)val->name_or_val;
			*res = lf_char->value;
			break;
		}

	default:
		*res = 0;
		R_LOG_ERROR ("Skipping unsupported type (%d)", val->value_or_type);
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
// static void get_member_indx_val (void *type, int *indx_val)
//{
//	STypeInfo *t = (STypeInfo *) type;
//	SLF_MEMBER *lf_member = (SLF_MEMBER *)t->type_info;

//	*indx_val = lf_member->index;
//}

static void get_onemethod_name_len(STpiStream *ss, void *type, int *res_len) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *)t->type_info;

	*res_len = lf_onemethod->val.str_data.size;
}

static void get_enum_name_len(STpiStream *ss, void *type, int *res_len) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;

	*res_len = lf_enum->name.size;
}

static void get_class_struct_name_len(STpiStream *ss, void *type, int *res_len) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;

	get_sval_name_len (&lf->size, res_len);
}

static void get_array_name_len(STpiStream *ss, void *type, int *res_len) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *)t->type_info;

	get_sval_name_len (&lf_array->size, res_len);
}

static void get_union_name_len(STpiStream *ss, void *type, int *res_len) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_UNION *lf_union = (SLF_UNION *)t->type_info;

	get_sval_name_len (&lf_union->size, res_len);
}

static void get_enumerate_name_len(STpiStream *ss, void *type, int *res_len) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_name_len (&lf->enum_value, res_len);
}

static void get_nesttype_name_len(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;

	*res = lf->name.size;
}

static void get_method_name_len(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;

	*res = lf->name.size;
}

static void get_member_name_len(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_name_len (&lf->offset, res);
}

static void get_member_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_name (ss, &lf->offset, name);
}

static void get_onemethod_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *)t->type_info;

	*name = lf->val.str_data.name;
}

static void get_method_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;

	*name = lf->name.name;
}

static void get_nesttype_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;

	*name = lf->name.name;
}

static void get_enumerate_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;
	get_sval_name (ss, &lf->enum_value, name);
}

static void get_enum_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;
	*name = lf_enum->name.name;
}

static void get_class_struct_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;

	get_sval_name (ss, &lf->size, name);
}

static void get_array_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *)t->type_info;

	get_sval_name (ss, &lf_array->size, name);
}

static void get_union_name(STpiStream *ss, void *type, char **name) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_UNION *lf_union = (SLF_UNION *)t->type_info;
	get_sval_name (ss, &lf_union->size, name);
}

static void get_onemethod_val(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *)t->type_info;

	*res = lf->val.val;
}

static void get_member_val(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;
	get_sval_val (&lf->offset, res);
}

static void get_enumerate_val(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;
	get_sval_val (&lf->enum_value, res);
}

static void get_class_struct_val(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;
	get_sval_val (&lf->size, res);
}

static void get_array_val(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *)t->type_info;
	get_sval_val (&lf_array->size, res);
}

static void get_union_val(STpiStream *ss, void *type, int *res) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_UNION *lf_union = (SLF_UNION *)t->type_info;

	get_sval_val (&lf_union->size, res);
}

static void free_sval(SVal *val) {
	if (!val) {
		return;
	}
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *)val->name_or_val;
		R_FREE (scstr->name);
		R_FREE (val->name_or_val);
		return;
	}
	switch (val->value_or_type) {
	case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *)val->name_or_val;
			R_FREE (lf_ulong->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	case eLF_LONG:
		{
			SVal_LF_LONG *lf_long;
			lf_long = (SVal_LF_LONG *)val->name_or_val;
			R_FREE (lf_long->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	case eLF_SHORT:
		{
			SVal_LF_SHORT *lf_short;
			lf_short = (SVal_LF_SHORT *)val->name_or_val;
			R_FREE (lf_short->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *)val->name_or_val;
			R_FREE (lf_ushort->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	case eLF_CHAR:
		{
			SVal_LF_CHAR *lf_char;
			lf_char = (SVal_LF_CHAR *)val->name_or_val;
			R_FREE (lf_char->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	case eLF_UQUADWORD:
		{
			SVal_LF_UQUADWORD *lf_uqword;
			lf_uqword = (SVal_LF_UQUADWORD *)val->name_or_val;
			R_FREE (lf_uqword->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	case eLF_QUADWORD:
		{
			SVal_LF_QUADWORD *lf_qword;
			lf_qword = (SVal_LF_QUADWORD *)val->name_or_val;
			R_FREE (lf_qword->name.name);
			R_FREE (val->name_or_val);
			break;
		}
	default:
		printf ("free_sval()::not supproted type\n");
		break;
	}
}

static void free_lf_enumerate(STpiStream *ss, void *type_info) {
	STypeInfo *typeInfo = (STypeInfo *)type_info;
	SLF_ENUMERATE *lf_en = (SLF_ENUMERATE *)typeInfo->type_info;
	free_sval (&(lf_en->enum_value));
}

static void free_lf_nesttype(STpiStream *ss, void *type_info) {
	STypeInfo *typeInfo = (STypeInfo *)type_info;
	SLF_NESTTYPE *lf_nest = (SLF_NESTTYPE *)typeInfo->type_info;
	free (lf_nest->name.name);
}

static void free_lf_method(STpiStream *ss, void *type_info) {
	STypeInfo *typeInfo = (STypeInfo *)type_info;
	SLF_METHOD *lf_meth = (SLF_METHOD *)typeInfo->type_info;
	free (lf_meth->name.name);
}

static void free_lf_member(STpiStream *ss, void *type_info) {
	STypeInfo *typeInfo = (STypeInfo *)type_info;
	SLF_MEMBER *lf_mem = (SLF_MEMBER *)typeInfo->type_info;
	free_sval (&lf_mem->offset);
}

static void free_lf_fieldlist(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *)t->type_info;
	STypeInfo *type_info = 0;
	RListIter *it = r_list_iterator (lf_fieldlist->substructs);
	while (r_list_iter_next (it)) {
		type_info = (STypeInfo *)r_list_iter_get (it);
		if (type_info->free_) {
			type_info->free_(ss, type_info);
		}
		if (type_info->type_info) {
			free (type_info->type_info);
		}
		free (type_info);
	}
	r_list_free (lf_fieldlist->substructs);
}

static void free_lf_class(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_CLASS *lf_class = (SLF_CLASS *)t->type_info;

	free_sval (&lf_class->size);
}

static void free_lf_union(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_UNION *lf_union = (SLF_UNION *)t->type_info;
	free_sval (&lf_union->size);
}

static void free_lf_onemethod(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *)t->type_info;
	free (lf_onemethod->val.str_data.name);
}

static void free_lf_enum(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;
	free (lf_enum->name.name);
}

static void free_lf_array(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *)t->type_info;
	free_sval (&lf_array->size);
}

static void free_lf_arglist(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *)t->type_info;
	free (lf_arglist->arg_type);
	lf_arglist->arg_type = 0;
}

static void free_lf_vtshape(STpiStream *ss, void *type) {
	STypeInfo *t = (STypeInfo *)type;
	SLF_VTSHAPE *lf_vtshape = (SLF_VTSHAPE *)t->type_info;
	free (lf_vtshape->vt_descriptors);
	lf_vtshape->vt_descriptors = 0;
}

static void free_tpi_stream(STpiStream *ss, void *stream) {
	SType *type = NULL;
	RListIter *it = r_list_iterator (ss->types);
	while (r_list_iter_next (it)) {
		type = (SType *)r_list_iter_get (it);
		if (!type) {
			continue;
		}
		if (type->type_data.free_) {
			type->type_data.free_(ss, &type->type_data);
			type->type_data.free_ = 0;
		}
		if (type->type_data.type_info) {
			free (type->type_data.type_info);
			type->type_data.free_ = 0;
			type->type_data.type_info = 0;
		}
		R_FREE (type);
	}
	r_list_free (ss->types);
}

static void get_array_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = NULL;

	SType *t = NULL;
	ti->get_element_type (ss, ti, (void **)&t);

	// XXX asserts are bad
	R_RETURN_IF_FAIL (t); // t == NULL indicates malformed PDB?
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		ti->get_print_type (ss, ti, &tmp_name);
	}
	int size = 0;
	if (ti->get_val) {
		ti->get_val (ss, ti, &size);
	}
	*name = r_str_newf ("%s[%d]", tmp_name? tmp_name: "", size);
	free (tmp_name);
}

static void get_pointer_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = NULL;
	char *tmp_name = NULL;

	ti->get_utype (ss, ti, (void **)&t);
	R_RETURN_IF_FAIL (t); // t == NULL indicates malformed PDB?
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		ti->get_print_type (ss, ti, &tmp_name);
	}

	*name = r_str_newf ("%s*", tmp_name? tmp_name: "");
	free (tmp_name);
}

static void get_modifier_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *stype_info = type;
	SType *stype = NULL;
	char *tmp_name = NULL;

	stype_info->get_modified_type (ss, stype_info, (void **)&stype);
	if (stype && stype->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = stype->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (stype);
	} else {
		STypeInfo *refered_type_info = NULL;
		refered_type_info = &stype->type_data;
		refered_type_info->get_print_type (ss, refered_type_info, &tmp_name);
	}
	SLF_MODIFIER *modifier = stype_info->type_info;
	*name = r_str_newf ("%s%s%s%s",
		modifier->umodifier.bits.const_? "const ": "",
		modifier->umodifier.bits.volatile_? "volatile ": "",
		modifier->umodifier.bits.unaligned? "unaligned ": "",
		tmp_name? tmp_name: "");
	free (tmp_name);
}

static void get_procedure_print_type(STpiStream *ss, void *type, char **name) {
	*name = strdup ("proc ");
}

static void get_bitfield_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;
	SLF_BITFIELD *bitfeild_info = (SLF_BITFIELD *)ti->type_info;

	ti->get_base_type (ss, ti, (void **)&t);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		ti->get_print_type (ss, ti, &tmp_name);
	}

	*name = r_str_newf ("bitfield%s%s : %d",
		tmp_name? " ": "",
		tmp_name? tmp_name: "",
		(int)bitfeild_info->length);
	free (tmp_name);
}

static void get_fieldlist_print_type(STpiStream *ss, void *type, char **name) {
	*name = strdup ("fieldlist ");
}

static void get_enum_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = NULL;
	char *tmp_name = NULL;

	ti->get_utype (ss, ti, (void **)&t);
	R_RETURN_IF_FAIL (t); // This shouldn't happen?, TODO explore this situation
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) { // BaseType
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		ti->get_print_type (ss, ti, &tmp_name);
	}

	*name = r_str_newf ("enum %s", tmp_name? tmp_name: "");
	free (tmp_name);
}

static void get_class_struct_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = NULL;
	const char *tmp1 = NULL;

	ELeafType lt = ti->leaf_type;
	ti->get_name (ss, ti, &tmp_name);

	if (lt == eLF_CLASS) {
		tmp1 = "class ";
	} else {
		tmp1 = "struct ";
	}

	*name = r_str_newf ("%s%s", tmp1, tmp_name? tmp_name: "");
}

static void get_arglist_print_type(STpiStream *ss, void *type, char **name) {
	(void)type;
	*name = strdup ("arg_list");
	//	STypeInfo *ti = (STypeInfo *) type;
	//	SType *t = 0;
	//	char *tmp_name = 0;
	//	int name_len = 0;
	//	int need_to_free = 1;
	//	int base_type = 0;

	//	base_type = ti->get_arg_type (ti, (void **)&t);
	//	if (!t) {
	//		need_to_free = 0;
	//		print_base_type (base_type, &tmp_name);
	//	} else {
	//		ti = &t->type_data;
	//		ti->get_print_type (ti, &tmp_name);
	//	}

	//	name_len = strlen ("arglist ");
	//	name_len += strlen (tmp_name);
	//	*name = (char *) malloc (name_len + 1);
	//	// name[name_len] = '\0';
	//	strcpy (*name, "arglist ");
	//	strcat (*name, tmp_name);

	//	if (need_to_free)
	//		free (tmp_name);
}

// TODO, nothing is really being parsed here
static void get_mfunction_print_type(STpiStream *ss, void *type, char **name) {
	*name = strdup ("mfunction ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = NULL;
	ti->get_name (ss, ti, &tmp_name);
	*name = r_str_newf ("union %s", tmp_name? tmp_name: "");
}

static void get_vtshape_print_type(STpiStream *ss, void *type, char **name) {
	*name = strdup ("vtshape");
}

static void get_enumerate_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = NULL;
	ti->get_name (ss, ti, &tmp_name);
	*name = r_str_newf ("enumerate %s", tmp_name? tmp_name: "");
}

static void get_nesttype_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;

	ti->get_index (ss, ti, (void **)&t);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		if (ti->get_print_type) {
			ti->get_print_type (ss, ti, &tmp_name);
		} else {
			// TODO: this shouldnt happen because it means corrupted or invalid type
			// R_LOG_WARN ("strange for nesttype");
		}
	}

	*name = r_str_newf ("nesttype %s", tmp_name? tmp_name: "");
	free (tmp_name);
}

static void get_method_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = 0;
	ti->get_name (ss, ti, &tmp_name);
	*name = r_str_newf ("method %s", tmp_name? tmp_name: "");
}

static void get_member_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = NULL;
	char *tmp_name = NULL;

	ti->get_index (ss, ti, (void **)&t);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		ti->get_print_type (ss, ti, &tmp_name);
	}
	if (tmp_name) {
		*name = tmp_name;
	}
}

static void get_onemethod_print_type(STpiStream *ss, void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;

	ti->get_index (ss, ti, (void **)&t);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = strdup (base_type->type);
		free_simple_type (t);
	} else {
		ti = &t->type_data;
		ti->get_print_type (ss, ti, &tmp_name);
	}

	*name = r_str_newf ("onemethod %s", tmp_name? tmp_name: "");
	free (tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
void init_scstring(SCString *cstr, unsigned int size, char *name) {
	cstr->size = size;
	cstr->name = strdup (name);
}

///////////////////////////////////////////////////////////////////////////////
void deinit_scstring(SCString *cstr) {
	free (cstr->name);
}

int parse_sctring(SCString *sctr, ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	ut32 c = 0;
	sctr->name = NULL;
	sctr->size = 0;
	while (*leaf_data) {
		if (!can_read (*read_bytes + c, 1, len)) {
			return 0;
		}
		c++;
		leaf_data++;
	}
	if (!can_read (*read_bytes, 1, len)) {
		return 0;
	}
	leaf_data += 1;
	*read_bytes += (c + 1);
	init_scstring (sctr, c + 1, (char *)leaf_data - (c + 1));
	return 1;
}

static int parse_sval(SVal *val, ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	val->name_or_val = 0;
	if (!can_read (*read_bytes, 2, len)) {
		return 0;
	}
	val->value_or_type = r_read_le16 (leaf_data);
	leaf_data += 2;
	*read_bytes += 2;
	if (val->value_or_type < eLF_CHAR) {
		SCString *sctr = R_NEW0 (SCString);
		parse_sctring (sctr, leaf_data, read_bytes, len);
		val->name_or_val = sctr;
	} else {
		switch (val->value_or_type) {
		case eLF_UQUADWORD:
			{
				if (!can_read (*read_bytes, 8, len)) {
					return 0;
				}
				SVal_LF_UQUADWORD lf_uqword;
				lf_uqword.value = r_read_le64 (leaf_data);
				leaf_data += 8;
				*read_bytes += 8;
				parse_sctring (&lf_uqword.name, leaf_data, read_bytes, len);
				val->name_or_val = R_NEW0 (SVal_LF_UQUADWORD);
				memcpy (val->name_or_val, &lf_uqword, sizeof (SVal_LF_UQUADWORD));
				break;
			}
		case eLF_QUADWORD:
			{
				if (!can_read (*read_bytes, 8, len)) {
					return 0;
				}
				SVal_LF_QUADWORD lf_qword;
				lf_qword.value = (st64)r_read_le64 (leaf_data);
				leaf_data += 8;
				*read_bytes += 8;
				parse_sctring (&lf_qword.name, leaf_data, read_bytes, len);
				val->name_or_val = malloc (sizeof (SVal_LF_QUADWORD));
				if (!val->name_or_val) {
					break;
				}
				memcpy (val->name_or_val, &lf_qword, sizeof (SVal_LF_QUADWORD));
				break;
			}
		case eLF_CHAR:
			{
				if (!can_read (*read_bytes, 1, len)) {
					return 0;
				}
				SVal_LF_CHAR lf_char;
				lf_char.value = (st8)leaf_data[0];
				leaf_data += 1;
				*read_bytes += 1;
				parse_sctring (&lf_char.name, leaf_data, read_bytes, len);
				val->name_or_val = malloc (sizeof (SVal_LF_CHAR));
				if (!val->name_or_val) {
					break;
				}
				memcpy (val->name_or_val, &lf_char, sizeof (SVal_LF_CHAR));
				break;
			}
		case eLF_LONG:
			{
				if (!can_read (*read_bytes, 4, len)) {
					return 0;
				}
				SVal_LF_LONG lf_long;
				lf_long.value = (st32)r_read_le32 (leaf_data);
				leaf_data += 4;
				*read_bytes += 4;
				parse_sctring (&lf_long.name, leaf_data, read_bytes, len);
				val->name_or_val = malloc (sizeof (SVal_LF_LONG));
				if (!val->name_or_val) {
					break;
				}
				memcpy (val->name_or_val, &lf_long, sizeof (SVal_LF_LONG));
				break;
			}
		case eLF_ULONG:
			{
				if (!can_read (*read_bytes, 4, len)) {
					return 0;
				}
				SVal_LF_ULONG lf_ulong;
				lf_ulong.value = r_read_le32 (leaf_data);
				leaf_data += 4;
				*read_bytes += 4;
				parse_sctring (&lf_ulong.name, leaf_data, read_bytes, len);
				val->name_or_val = malloc (sizeof (SVal_LF_ULONG));
				if (!val->name_or_val) {
					break;
				}
				memcpy (val->name_or_val, &lf_ulong, sizeof (SVal_LF_ULONG));
				break;
			}
		case eLF_SHORT:
			{
				if (!can_read (*read_bytes, 2, len)) {
					return 0;
				}
				SVal_LF_SHORT lf_short;
				lf_short.value = (st16)r_read_le16 (leaf_data);
				leaf_data += 2;
				*read_bytes += 2;
				parse_sctring (&lf_short.name, leaf_data, read_bytes, len);
				val->name_or_val = malloc (sizeof (SVal_LF_SHORT));
				if (!val->name_or_val) {
					break;
				}
				memcpy (val->name_or_val, &lf_short, sizeof (SVal_LF_SHORT));
				break;
			}
		case eLF_USHORT:
			{
				if (!can_read (*read_bytes, 2, len)) {
					return 0;
				}
				SVal_LF_USHORT lf_ushort;
				lf_ushort.value = r_read_le16 (leaf_data);
				leaf_data += 2;
				*read_bytes += 2;
				parse_sctring (&lf_ushort.name, leaf_data, read_bytes, len);
				val->name_or_val = malloc (sizeof (SVal_LF_USHORT));
				if (!val->name_or_val) {
					break;
				}
				memcpy (val->name_or_val, &lf_ushort, sizeof (SVal_LF_USHORT));
				break;
			}
		default:
			R_LOG_WARN ("parse_sval: Skipping unsupported type (%d)", val->value_or_type);
			return 0;
		}
	}
	return 1;
}

static int parse_lf_enumerate(SLF_ENUMERATE *lf_enumerate, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	if (!can_read (*read_bytes, 2, len)) {
		return 0;
	}
	lf_enumerate->enum_value.name_or_val = 0;
	lf_enumerate->fldattr.fldattr = r_read_le16 (leaf_data);
	leaf_data += 2;
	*read_bytes += 2;
	ut32 before = *read_bytes;
	parse_sval (&lf_enumerate->enum_value, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_enumerate->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_enumerate->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_nesttype(SLF_NESTTYPE *lf_nesttype, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 6;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_nesttype->name.name = 0;
	lf_nesttype->pad = r_read_le16 (leaf_data);
	lf_nesttype->index = r_read_le32 (leaf_data + 2);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	parse_sctring (&lf_nesttype->name, (ut8 *)leaf_data, read_bytes, len);
	return *read_bytes - start;
}

static int parse_lf_method(SLF_METHOD *lf_method, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 6;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_method->name.name = 0;
	lf_method->count = r_read_le16 (leaf_data);
	lf_method->mlist = r_read_le32 (leaf_data + 2);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sctring (&lf_method->name, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_method->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_method->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_member(SLF_MEMBER *lf_member, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 6;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_member->offset.name_or_val = 0;
	lf_member->fldattr.fldattr = r_read_le16 (leaf_data);
	lf_member->index = r_read_le32 (leaf_data + 2);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sval (&lf_member->offset, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_member->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_member->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_onemethod(SLF_ONEMETHOD *lf_onemethod, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 6;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_onemethod->val.str_data.name = 0;
	lf_onemethod->val.val = 0;
	lf_onemethod->fldattr.fldattr = r_read_le16 (leaf_data);
	lf_onemethod->index = r_read_le32 (leaf_data + 2);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	if ((lf_onemethod->fldattr.bits.mprop == eMTintro) ||
		(lf_onemethod->fldattr.bits.mprop == eMTpureintro)) {
		if (!can_read (*read_bytes, 4, len)) {
			return 0;
		}
		lf_onemethod->val.val = r_read_le32 (leaf_data);
		leaf_data += 4;
		*read_bytes += 4;
	}
	ut32 before = *read_bytes;
	parse_sctring (&(lf_onemethod->val.str_data), (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_onemethod->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_onemethod->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

///////////////////////////////////////////////////////////////////////////////
static void init_stype_info(STypeInfo *type_info) {
	// XXX cant we just memset the type?
	type_info->free_ = NULL;
	type_info->get_members = NULL;
	type_info->get_name = NULL;
	type_info->get_val = NULL;
	type_info->get_name_len = NULL;
	type_info->get_arg_type = NULL;
	type_info->get_element_type = NULL;
	type_info->get_index_type = NULL;
	type_info->get_base_type = NULL;
	type_info->get_derived = NULL;
	type_info->get_vshape = NULL;
	type_info->get_utype = NULL;
	type_info->get_return_type = NULL;
	type_info->get_class_type = NULL;
	type_info->get_this_type = NULL;
	type_info->get_arglist = NULL;
	type_info->get_index = NULL;
	type_info->get_mlist = NULL;
	type_info->get_modified_type = NULL;
	type_info->is_fwdref = NULL;
	type_info->get_print_type = NULL;

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
	case eLF_METHODLIST: // TODO missing stuff
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
		// XXX cant we just memset the type?
		type_info->get_name = NULL;
		type_info->get_val = NULL;
		type_info->get_name_len = NULL;
		type_info->get_members = NULL;
		type_info->get_arg_type = NULL;
		type_info->get_element_type = NULL;
		type_info->get_index_type = NULL;
		type_info->get_base_type = NULL;
		type_info->get_derived = NULL;
		type_info->get_vshape = NULL;
		type_info->get_utype = NULL;
		type_info->get_return_type = NULL;
		type_info->get_class_type = NULL;
		type_info->get_this_type = NULL;
		type_info->get_arglist = NULL;
		type_info->get_index = NULL;
		type_info->get_mlist = NULL;
		type_info->get_print_type = NULL;
		break;
	}
}

#define PARSE_LF2(lf_type, lf_func_name, type) \
	{ \
		STypeInfo *type_info = R_NEW0 (STypeInfo); \
		lf_type *lf = R_NEW0 (lf_type); \
		curr_read_bytes = parse_ ## lf_func_name (lf, p, read_bytes, len); \
		type_info->type_info = (void *)lf; \
		type_info->leaf_type = type; \
		init_stype_info (type_info); \
		r_list_append (lf_fieldlist->substructs, type_info); \
	}

static int parse_lf_fieldlist(SLF_FIELDLIST *lf_fieldlist, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	int curr_read_bytes = 0;
	const ut8 *p = leaf_data;
	lf_fieldlist->substructs = r_list_new ();
	while (*read_bytes <= len) {
		if (!can_read (*read_bytes, 2, len)) {
			return 0;
		}
		ut16 leaf_type = r_read_le16 (p);
		p += 2;
		*read_bytes += 2;
		switch (leaf_type) {
		case eLF_ENUMERATE:
			PARSE_LF2 (SLF_ENUMERATE, lf_enumerate, eLF_ENUMERATE);
			break;
		case eLF_NESTTYPE:
			PARSE_LF2 (SLF_NESTTYPE, lf_nesttype, eLF_NESTTYPE);
			break;
		case eLF_METHOD:
			PARSE_LF2 (SLF_METHOD, lf_method, eLF_METHOD);
			break;
		case eLF_MEMBER:
			PARSE_LF2 (SLF_MEMBER, lf_member, eLF_MEMBER);
			break;
		case eLF_ONEMETHOD:
			PARSE_LF2 (SLF_ONEMETHOD, lf_onemethod, eLF_ONEMETHOD);
			break;
		default:
			return 0;
		}
		if (curr_read_bytes == 0) {
			break;
		}
		p += curr_read_bytes;
	}
	return 0;
}

static int parse_lf_enum(SLF_ENUM *lf_enum, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 12;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_enum->name.name = 0;
	lf_enum->count = r_read_le16 (leaf_data);
	lf_enum->prop.cv_property = r_read_le16 (leaf_data + 2);
	lf_enum->utype = r_read_le32 (leaf_data + 4);
	lf_enum->field_list = r_read_le32 (leaf_data + 8);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sctring (&lf_enum->name, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_enum->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_enum->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_class(SLF_CLASS *lf_class, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 16;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_class->size.name_or_val = 0;
	lf_class->count = r_read_le16 (leaf_data);
	lf_class->prop.cv_property = r_read_le16 (leaf_data + 2);
	lf_class->field_list = r_read_le32 (leaf_data + 4);
	lf_class->derived = r_read_le32 (leaf_data + 8);
	lf_class->vshape = r_read_le32 (leaf_data + 12);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sval (&lf_class->size, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += *read_bytes - before;
	lf_class->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_class->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_structure(SLF_STRUCTURE *lf_structure, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 16;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_structure->size.name_or_val = 0;
	lf_structure->count = r_read_le16 (leaf_data);
	lf_structure->prop.cv_property = r_read_le16 (leaf_data + 2);
	lf_structure->field_list = r_read_le32 (leaf_data + 4);
	lf_structure->derived = r_read_le32 (leaf_data + 8);
	lf_structure->vshape = r_read_le32 (leaf_data + 12);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sval (&lf_structure->size, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_structure->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_structure->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_pointer(SLF_POINTER *lf_pointer, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 8;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_pointer->utype = r_read_le32 (leaf_data);
	lf_pointer->ptr_attr.ptr_attr = r_read_le32 (leaf_data + 4);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	lf_pointer->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_pointer->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_array(SLF_ARRAY *lf_array, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 8;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_array->size.name_or_val = 0;
	lf_array->element_type = r_read_le32 (leaf_data);
	lf_array->index_type = r_read_le32 (leaf_data + 4);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sval (&lf_array->size, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before);
	lf_array->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_array->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_modifier(SLF_MODIFIER *lf_modifier, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 6;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_modifier->modified_type = r_read_le32 (leaf_data);
	lf_modifier->umodifier.modifier = r_read_le16 (leaf_data + 4);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	lf_modifier->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_modifier->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_arglist(SLF_ARGLIST *lf_arglist, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	if (!can_read (*read_bytes, 4, len)) {
		return 0;
	}
	lf_arglist->arg_type = 0;
	lf_arglist->count = r_read_le32 (leaf_data);
	leaf_data += 4;
	*read_bytes += 4;
	if (!can_read_array (*read_bytes, lf_arglist->count, 4, len)) {
		return 0;
	}
	const ut32 byte_size = lf_arglist->count * 4;
	lf_arglist->arg_type = (unsigned int *)malloc (byte_size);
	if (!lf_arglist->arg_type) {
		return 0;
	}
	memcpy (lf_arglist->arg_type, leaf_data, byte_size);
	leaf_data += byte_size;
	*read_bytes += byte_size;
	lf_arglist->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_arglist->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_mfunction(SLF_MFUNCTION *lf_mfunction, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 24;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_mfunction->return_type = r_read_le32 (leaf_data);
	lf_mfunction->class_type = r_read_le32 (leaf_data + 4);
	lf_mfunction->this_type = r_read_le32 (leaf_data + 8);
	lf_mfunction->call_conv = leaf_data[12];
	lf_mfunction->reserved = leaf_data[13];
	lf_mfunction->parm_count = r_read_le16 (leaf_data + 14);
	lf_mfunction->arglist = r_read_le32 (leaf_data + 16);
	lf_mfunction->this_adjust = (st32)r_read_le32 (leaf_data + 20);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	lf_mfunction->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_mfunction->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_procedure(SLF_PROCEDURE *lf_procedure, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 12;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_procedure->return_type = (ut16)r_read_le32 (leaf_data);
	lf_procedure->call_conv = leaf_data[4];
	lf_procedure->reserved = leaf_data[5];
	lf_procedure->parm_count = r_read_le16 (leaf_data + 6);
	lf_procedure->arg_list = r_read_le32 (leaf_data + 8);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	lf_procedure->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_procedure->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_union(SLF_UNION *lf_union, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 8;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_union->size.name_or_val = 0;
	lf_union->count = r_read_le16 (leaf_data);
	lf_union->prop.cv_property = r_read_le16 (leaf_data + 2);
	lf_union->field_list = r_read_le32 (leaf_data + 4);
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	ut32 before = *read_bytes;
	parse_sval (&lf_union->size, (ut8 *)leaf_data, read_bytes, len);
	leaf_data += *read_bytes - before;
	lf_union->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_union->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_bitfield(SLF_BITFIELD *lf_bitfield, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	const ut32 fixed_size = 6;
	if (!can_read (*read_bytes, fixed_size, len)) {
		return 0;
	}
	lf_bitfield->base_type = r_read_le32 (leaf_data);
	lf_bitfield->length = leaf_data[4];
	lf_bitfield->position = leaf_data[5];
	leaf_data += fixed_size;
	*read_bytes += fixed_size;
	lf_bitfield->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_bitfield->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

static int parse_lf_vtshape(SLF_VTSHAPE *lf_vtshape, const ut8 *leaf_data, ut32 *read_bytes, ut32 len) {
	const ut32 start = *read_bytes;
	if (!can_read (*read_bytes, 2, len)) {
		return 0;
	}
	lf_vtshape->vt_descriptors = 0;
	lf_vtshape->count = r_read_le16 (leaf_data);
	leaf_data += 2;
	*read_bytes += 2;
	const ut32 size = (4 * lf_vtshape->count + (lf_vtshape->count % 2) * 4) / 8;
	if (!can_read (*read_bytes, size, len)) {
		return 0;
	}
	lf_vtshape->vt_descriptors = (char *)malloc (size);
	if (!lf_vtshape->vt_descriptors) {
		return 0;
	}
	memcpy (lf_vtshape->vt_descriptors, leaf_data, size);
	leaf_data += size;
	*read_bytes += size;
	lf_vtshape->pad = (len > *read_bytes)? leaf_data[0]: 0;
	if (!pad_align (lf_vtshape->pad, (ut8 **)&leaf_data, read_bytes, len)) {
		return 0;
	}
	return *read_bytes - start;
}

#define PARSE_LF(lf_type, lf_func) \
	{ \
		lf_type *lf = (lf_type *)malloc (sizeof (lf_type)); \
		if (!lf) { \
			free (leaf_data); \
			return 0; \
		} \
		parse_ ## lf_func (lf, leaf_data + 2, &read_bytes, type->length); \
		type->type_data.type_info = (void *)lf; \
		init_stype_info (&type->type_data); \
	}

///////////////////////////////////////////////////////////////////////////////
static int parse_tpi_stypes(R_STREAM_FILE *stream, SType *type) {
	uint8_t *leaf_data;
	unsigned int read_bytes = 0;

	stream_file_read (stream, 2, (char *)&type->length);
	if (type->length < 1) {
		return 0;
	}
	leaf_data = (uint8_t *)malloc (type->length);
	if (!leaf_data) {
		return 0;
	}
	stream_file_read (stream, type->length, (char *)leaf_data);
	type->type_data.leaf_type = *(uint16_t *)leaf_data;
	read_bytes += 2;
	switch (type->type_data.leaf_type) {
	case eLF_FIELDLIST:
		PARSE_LF (SLF_FIELDLIST, lf_fieldlist);
		break;
	case eLF_ENUM:
		PARSE_LF (SLF_ENUM, lf_enum);
		break;
	// TODO: combine with eLF_STRUCTURE
	case eLF_CLASS:
		PARSE_LF (SLF_CLASS, lf_class);
		break;
	case eLF_STRUCTURE:
		PARSE_LF (SLF_STRUCTURE, lf_structure);
		break;
	case eLF_POINTER:
		{
			// PARSE_LF (SLF_POINTER, lf_pointer);
			SLF_POINTER *lf = (SLF_POINTER *)malloc (sizeof (SLF_POINTER));
			if (!lf) {
				free (leaf_data);
				return 0;
			}
			parse_lf_pointer (lf, leaf_data + 2, &read_bytes, type->length);
			type->type_data.type_info = (void *)lf;
			init_stype_info (&type->type_data);
		}
		break;
	case eLF_ARRAY:
		PARSE_LF (SLF_ARRAY, lf_array);
		break;
	case eLF_MODIFIER:
		PARSE_LF (SLF_MODIFIER, lf_modifier);
		break;
	case eLF_ARGLIST:
		PARSE_LF (SLF_ARGLIST, lf_arglist);
		break;
	case eLF_MFUNCTION:
		PARSE_LF (SLF_MFUNCTION, lf_mfunction);
		break;
	case eLF_METHODLIST:
		break;
	case eLF_PROCEDURE:
		PARSE_LF (SLF_PROCEDURE, lf_procedure);
		break;
	case eLF_UNION:
		PARSE_LF (SLF_UNION, lf_union);
		break;
	case eLF_BITFIELD:
		PARSE_LF (SLF_BITFIELD, lf_bitfield);
		break;
	case eLF_VTSHAPE:
		PARSE_LF (SLF_VTSHAPE, lf_vtshape);
		break;
	default:
		R_LOG_DEBUG ("parse_tpi_streams(): skipping unsupported leaf type 0x%" PFMT32x,
			type->type_data.leaf_type);
		read_bytes = type->length;
		type->type_data.type_info = NULL;
		break;
	}

	free (leaf_data);
	return read_bytes;
}

int parse_tpi_stream(STpiStream *ss, R_STREAM_FILE *stream) {
	ss->types = r_list_new ();
	// Initialize context for parsing session
	stream_file_read (stream, sizeof (STPIHeader), (char *)&ss->header);

	ss->ctx.base_idx = ss->header.idx_begin;
	ss->ctx.types_list = ss->types;

	int i;
	for (i = ss->header.idx_begin; i < ss->header.idx_end; i++) {
		SType *type = R_NEW0 (SType);
		type->tpi_idx = i;
		type->type_data.type_info = 0;
		type->type_data.leaf_type = eLF_MAX;
		init_stype_info (&type->type_data);
		if (parse_tpi_stypes (stream, type)) {
			r_list_append (ss->types, type);
		} else {
			free (type);
		}
	}

	return 1;
}

void init_tpi_stream(STpiStream *ss) {
	ss->free_ = free_tpi_stream;
}
