/* radare - LGPL - Copyright 2007-2013 - pancake 
   class.c rewrite: Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com>
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "class.h"
#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>
#include <math.h>

#ifdef IFDBG
#undef IFDBG
#endif

#define IFDBG  if(0)

// taken from LLVM Code Byte Swap
inline ut32 r_bin_java_swap_uint(ut32 x){
	ut32 Byte0 = x & 0x000000FF;
	ut32 Byte1 = x & 0x0000FF00;
	ut32 Byte2 = x & 0x00FF0000;
	ut32 Byte3 = x & 0xFF000000;
	return (Byte0 << 24) | (Byte1 << 8) | (Byte2 >> 8) | (Byte3 >> 24); 
}

inline ut16 r_bin_java_swap_ushort(ut16 x){
	ut32 Byte0 = x & 0x00FF;
	ut32 Byte1 = x & 0xFF00;
	return (Byte0 << 8) | (Byte1 >> 8); 
}
inline ut32 r_bin_java_read_int(RBinJavaObj *bin, ut64 offset){
	ut32 sh = 0;
	r_buf_read_at (bin->b, offset, (ut8*)&sh, 4);
	return r_bin_java_swap_uint(sh);
}
inline ut16 r_bin_java_read_short(RBinJavaObj *bin, ut64 offset){
	ut16 sh = 0;
	r_buf_read_at (bin->b, offset, (ut8*)&sh, 2);
	return r_bin_java_swap_ushort (sh);
}

inline ut32 r_bin_java_read_int_from_buffer(ut8 *buffer, ut64 offset){
	ut32 sh = 0;
	memcpy((ut8 *)&sh, buffer, 4);
	return r_bin_java_swap_uint(sh);
}
inline ut16 r_bin_java_read_short_from_buffer(ut8 *buffer, ut64 offset){
	ut16 sh = 0;
	memcpy((ut8 *)&sh, buffer, 2);
	return r_bin_java_swap_ushort (sh);
}


volatile ut8 R_BIN_JAVA_NULL_TYPE_INITTED = 0;
RBinJavaObj* R_BIN_JAVA_GLOBAL_BIN = NULL;
// NOTE: must be initialized for safe use
//static struct r_bin_java_cp_item_t cp_null_item = {0};


static RBinJavaAccessFlags METHOD_ACCESS_FLAGS[] = {
	{"Public", R_BIN_JAVA_METHOD_ACC_PUBLIC},
	{"Private", R_BIN_JAVA_METHOD_ACC_PRIVATE},
	{"Protected", R_BIN_JAVA_METHOD_ACC_PROTECTED},
	{"Static", R_BIN_JAVA_METHOD_ACC_STATIC},

	{"Final", R_BIN_JAVA_METHOD_ACC_FINAL},
	{"Synchronized", R_BIN_JAVA_METHOD_ACC_SYNCHRONIZED},
	{"Bridge", R_BIN_JAVA_METHOD_ACC_BRIDGE},
	{"Var Args", R_BIN_JAVA_METHOD_ACC_VARARGS},
	
	{"Native", R_BIN_JAVA_METHOD_ACC_NATIVE},
	{"Interface", R_BIN_JAVA_METHOD_ACC_INTERFACE},
	{"Abstract", R_BIN_JAVA_METHOD_ACC_ABSTRACT},
	{"Strict", R_BIN_JAVA_METHOD_ACC_STRICT},
	
	{"Synthetic", R_BIN_JAVA_METHOD_ACC_SYNTHETIC},
	{"Annotation", R_BIN_JAVA_METHOD_ACC_ANNOTATION},
	{"Enum", R_BIN_JAVA_METHOD_ACC_ENUM}
};

static RBinJavaAccessFlags CLASS_ACCESS_FLAGS[] = {
	{"Public", R_BIN_JAVA_CLASS_ACC_PUBLIC},
	{"Private", R_BIN_JAVA_CLASS_ACC_PRIVATE},
	{"Protected", R_BIN_JAVA_CLASS_ACC_PROTECTED},
	{"Static", R_BIN_JAVA_CLASS_ACC_STATIC},

	{"Final", R_BIN_JAVA_CLASS_ACC_FINAL},
	{"Synchronized", R_BIN_JAVA_CLASS_ACC_SUPER},
	{"Bridge", R_BIN_JAVA_CLASS_ACC_BRIDGE},
	{"Var Args", R_BIN_JAVA_CLASS_ACC_VARARGS},
	
	{"Native", R_BIN_JAVA_CLASS_ACC_NATIVE},
	{"Interface", R_BIN_JAVA_CLASS_ACC_INTERFACE},
	{"Abstract", R_BIN_JAVA_CLASS_ACC_ABSTRACT},
	{"Strict", R_BIN_JAVA_CLASS_ACC_STRICT},
	
	{"Synthetic", R_BIN_JAVA_CLASS_ACC_SYNTHETIC},
	{"Annotation", R_BIN_JAVA_CLASS_ACC_ANNOTATION},
	{"Enum", R_BIN_JAVA_CLASS_ACC_ENUM}
};


static RBinJavaRefMetas R_BIN_JAVA_REF_METAS[] = {
	{"Unknown", R_BIN_JAVA_REF_UNKNOWN}, 
	{"GetField", R_BIN_JAVA_REF_GETFIELD}, 
	{"GetStatic", R_BIN_JAVA_REF_GETSTATIC},
	{"PutField", R_BIN_JAVA_REF_PUTFIELD},
	{"PutStatic", R_BIN_JAVA_REF_PUTSTATIC},
	{"InvokeVirtual", R_BIN_JAVA_REF_INVOKEVIRTUAL},
	{"InvokeStatic", R_BIN_JAVA_REF_INVOKESTATIC},
	{"InvokeSpecial", R_BIN_JAVA_REF_INVOKESPECIAL},
	{"NewInvokeSpecial", R_BIN_JAVA_REF_NEWINVOKESPECIAL},
	{"InvokeInterface", R_BIN_JAVA_REF_INVOKEINTERFACE}
};

static ut16 R_BIN_JAVA_ELEMENT_VALUE_METAS_SZ = 14;
static RBinJavaElementValueMetas R_BIN_JAVA_ELEMENT_VALUE_METAS[] = {
	{"Byte", R_BIN_JAVA_EV_TAG_BYTE, NULL},
	{"Char", R_BIN_JAVA_EV_TAG_CHAR, NULL},
	{"Double", R_BIN_JAVA_EV_TAG_DOUBLE, NULL},
	{"Float", R_BIN_JAVA_EV_TAG_FLOAT, NULL},
	{"Integer", R_BIN_JAVA_EV_TAG_INT, NULL},
	{"Long", R_BIN_JAVA_EV_TAG_LONG, NULL},
	{"Short", R_BIN_JAVA_EV_TAG_SHORT, NULL},
	{"Boolean", R_BIN_JAVA_EV_TAG_BOOLEAN, NULL},
	{"Array of ", R_BIN_JAVA_EV_TAG_ARRAY, NULL},
	{"String", R_BIN_JAVA_EV_TAG_STRING, NULL},
	{"Enum", R_BIN_JAVA_EV_TAG_ENUM, NULL},
	{"Class", R_BIN_JAVA_EV_TAG_CLASS, NULL},
	{"Annotation", R_BIN_JAVA_EV_TAG_ANNOTATION, NULL},
	{"Unknown", R_BIN_JAVA_EV_TAG_UNKNOWN, NULL},
};

static RBinJavaVerificationMetas R_BIN_JAVA_VERIFICATION_METAS[] = {
	{"Top", R_BIN_JAVA_STACKMAP_TOP},
	{"Integer", R_BIN_JAVA_STACKMAP_INTEGER},
	{"Float", R_BIN_JAVA_STACKMAP_FLOAT},
	{"Double", R_BIN_JAVA_STACKMAP_DOUBLE},
	{"Long", R_BIN_JAVA_STACKMAP_LONG},
	{"NULL", R_BIN_JAVA_STACKMAP_NULL},
	{"This", R_BIN_JAVA_STACKMAP_THIS},
	{"Object", R_BIN_JAVA_STACKMAP_OBJECT},
	{"Uninitialized", R_BIN_JAVA_STACKMAP_UNINIT},
	{"Unknown", R_BIN_JAVA_STACKMAP_UNKNOWN}
}; 

static RBinJavaStackMapFrameMetas R_BIN_JAVA_STACK_MAP_FRAME_METAS[] = {
	{"ImplicitStackFrame", R_BIN_JAVA_STACK_FRAME_IMPLICIT, NULL},
	{"Same", R_BIN_JAVA_STACK_FRAME_SAME, NULL},
	{"SameLocals1StackItem", R_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1, NULL},
	{"Chop", R_BIN_JAVA_STACK_FRAME_CHOP, NULL},
	{"SameFrameExtended", R_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED, NULL},
	{"Append", R_BIN_JAVA_STACK_FRAME_APPEND, NULL},
	{"FullFrame", R_BIN_JAVA_STACK_FRAME_FULL_FRAME, NULL},
	{"Reserved", R_BIN_JAVA_STACK_FRAME_RESERVED, NULL}
}; 


static RBinJavaCPTypeObjectAllocs R_BIN_ALLOCS_CONSTANTS[]= {
	{r_bin_java_do_nothing_new, r_bin_java_do_nothing_free, r_bin_java_print_null_cp_summary, r_bin_java_do_nothing_calc_size},
	{r_bin_java_utf8_cp_new, r_bin_java_utf8_info_free, r_bin_java_print_utf8_cp_summary, r_bin_java_utf8_cp_calc_size},
	{r_bin_java_unknown_cp_new, r_bin_java_default_free, r_bin_java_print_unknown_cp_summary, r_bin_java_unknown_cp_calc_size},
	{r_bin_java_integer_cp_new, r_bin_java_default_free, r_bin_java_print_integer_cp_summary, r_bin_java_integer_cp_calc_size},
	{r_bin_java_float_cp_new, r_bin_java_default_free, r_bin_java_print_float_cp_summary, r_bin_java_float_cp_calc_size},
	{r_bin_java_long_cp_new, r_bin_java_default_free, r_bin_java_print_long_cp_summary, r_bin_java_long_cp_calc_size},
	{r_bin_java_double_cp_new, r_bin_java_default_free, r_bin_java_print_double_cp_summary, r_bin_java_double_cp_calc_size},
	{r_bin_java_class_cp_new, r_bin_java_default_free, r_bin_java_print_classref_cp_summary, r_bin_java_class_cp_calc_size},
	{r_bin_java_string_cp_new, r_bin_java_default_free, r_bin_java_print_string_cp_summary, r_bin_java_string_cp_calc_size},
	{r_bin_java_fieldref_cp_new, r_bin_java_default_free, r_bin_java_print_fieldref_cp_summary, r_bin_java_fieldref_cp_calc_size},
	{r_bin_java_methodref_cp_new, r_bin_java_default_free, r_bin_java_print_methodref_cp_summary, r_bin_java_methodref_cp_calc_size},
	{r_bin_java_interfacemethodref_cp_new, r_bin_java_default_free, r_bin_java_print_interfacemethodref_cp_summary, r_bin_java_interfacemethodref_cp_calc_size},
	{r_bin_java_name_and_type_cp_new, r_bin_java_default_free, r_bin_java_print_name_and_type_cp_summary, r_bin_java_name_and_type_cp_calc_size},
	{NULL, NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL},
	{r_bin_java_methodhandle_cp_new, r_bin_java_default_free, r_bin_java_print_methodhandle_cp_summary, r_bin_java_methodhandle_cp_calc_size},
	{r_bin_java_methodtype_cp_new, r_bin_java_default_free, r_bin_java_print_methodtype_cp_summary, r_bin_java_methodtype_cp_calc_size},
	{NULL, NULL, NULL, NULL},
	{r_bin_java_invokedynamic_cp_new, r_bin_java_default_free, r_bin_java_print_invokedynamic_cp_summary, r_bin_java_invokedynamic_cp_calc_size},
};
	
	
static RBinJavaCPTypeObj R_BIN_JAVA_NULL_TYPE;

static ut8 R_BIN_JAVA_CP_METAS_SZ = 12;
static RBinJavaCPTypeMetas R_BIN_JAVA_CP_METAS[] = {
	// Each field has a name pointer and a tag field
	{ "(null)", R_BIN_JAVA_CP_NULL, 0,  &R_BIN_ALLOCS_CONSTANTS[0] },
	{ "Utf8", R_BIN_JAVA_CP_UTF8, 3,  &R_BIN_ALLOCS_CONSTANTS[1] }, // 2 bytes = length, N bytes string (containts a pointer in the field)
	{ "Unknown", R_BIN_JAVA_CP_UNKNOWN, 0,  &R_BIN_ALLOCS_CONSTANTS[2] },
	{ "Integer", R_BIN_JAVA_CP_INTEGER, 5,  &R_BIN_ALLOCS_CONSTANTS[3] }, // 4 bytes
	{ "Float", R_BIN_JAVA_CP_FLOAT, 5,  &R_BIN_ALLOCS_CONSTANTS[4] }, // 4 bytes
	{ "Long", R_BIN_JAVA_CP_LONG, 9, &R_BIN_ALLOCS_CONSTANTS[5] }, // 4 high 4 low
	{ "Double", R_BIN_JAVA_CP_DOUBLE, 9, &R_BIN_ALLOCS_CONSTANTS[6] }, // 4 high 4 low
	{ "Class", R_BIN_JAVA_CP_CLASS, 3, &R_BIN_ALLOCS_CONSTANTS[7] }, // 2 name_idx
	{ "String", R_BIN_JAVA_CP_STRING, 3, &R_BIN_ALLOCS_CONSTANTS[8] }, // 2 string_idx
	{ "FieldRef", R_BIN_JAVA_CP_FIELDREF, 5, &R_BIN_ALLOCS_CONSTANTS[9] }, // 2 class idx, 2 name/type_idx
	{ "MethodRef", R_BIN_JAVA_CP_METHODREF, 5, &R_BIN_ALLOCS_CONSTANTS[10] }, // 2 class idx, 2 name/type_idx
	{ "InterfaceMethodRef", R_BIN_JAVA_CP_INTERFACEMETHOD_REF, 5 , &R_BIN_ALLOCS_CONSTANTS[11] }, // 2 class idx, 2 name/type_idx
	{ "NameAndType", R_BIN_JAVA_CP_NAMEANDTYPE, 5, &R_BIN_ALLOCS_CONSTANTS[12] }, // 4 high 4 low
	{ "Unknown", R_BIN_JAVA_CP_UNKNOWN, 0, &R_BIN_ALLOCS_CONSTANTS[2] },
	{ "Unknown", R_BIN_JAVA_CP_UNKNOWN, 0, &R_BIN_ALLOCS_CONSTANTS[2] },
	{ "MethodHandle", R_BIN_JAVA_CP_METHODHANDLE, 4, &R_BIN_ALLOCS_CONSTANTS[15] }, // 4 high 4 low
	{ "MethodType", R_BIN_JAVA_CP_METHODTYPE, 3, &R_BIN_ALLOCS_CONSTANTS[16] }, // 4 high 4 low
	{ "Unknown", R_BIN_JAVA_CP_UNKNOWN, 0, &R_BIN_ALLOCS_CONSTANTS[2] },
	{ "InvokeDynamic", R_BIN_JAVA_CP_INVOKEDYNAMIC, 5, &R_BIN_ALLOCS_CONSTANTS[18] }, // 4 high 4 low

};


static RBinJavaAttrInfoObjectAllocs RBIN_JAVA_ATTRS_ALLOCS[] = {
	{ r_bin_java_annotation_default_attr_new, r_bin_java_annotation_default_attr_free, r_bin_java_print_annotation_default_attr_summary, r_bin_java_annotation_default_attr_calc_size   },
	{ r_bin_java_bootstrap_methods_attr_new, r_bin_java_bootstrap_methods_attr_free, r_bin_java_print_bootstrap_methods_attr_summary, r_bin_java_bootstrap_methods_attr_calc_size   },
	{ r_bin_java_code_attr_new, r_bin_java_code_attr_free, r_bin_java_print_code_attr_summary, r_bin_java_code_attr_calc_size },
	{ r_bin_java_constant_value_attr_new, r_bin_java_constant_value_attr_free,  r_bin_java_print_constant_value_attr_summary, r_bin_java_constant_value_attr_calc_size}, 
	{ r_bin_java_deprecated_attr_new, r_bin_java_deprecated_attr_free, r_bin_java_print_deprecated_attr_summary, r_bin_java_deprecated_attr_calc_size },
	{ r_bin_java_enclosing_methods_attr_new, r_bin_java_enclosing_methods_attr_free, r_bin_java_print_enclosing_methods_attr_summary, r_bin_java_enclosing_methods_attr_calc_size },
	{ r_bin_java_exceptions_attr_new, r_bin_java_exceptions_attr_free, r_bin_java_print_exceptions_attr_summary, r_bin_java_exceptions_attr_calc_size },
	{ r_bin_java_inner_classes_attr_new, r_bin_java_inner_classes_attr_free, r_bin_java_print_inner_classes_attr_summary, r_bin_java_inner_classes_attr_calc_size },
	{ r_bin_java_line_number_table_attr_new, r_bin_java_line_number_table_attr_free, r_bin_java_print_line_number_table_attr_summary, r_bin_java_line_number_table_attr_calc_size }, 
	{ r_bin_java_local_variable_table_attr_new, r_bin_java_local_variable_table_attr_free, r_bin_java_print_local_variable_table_attr_summary, r_bin_java_local_variable_table_attr_calc_size }, 
	{ r_bin_java_local_variable_type_table_attr_new, r_bin_java_local_variable_type_table_attr_free, r_bin_java_print_local_variable_type_table_attr_summary, r_bin_java_local_variable_type_table_attr_calc_size }, 
	{ r_bin_java_rti_annotations_attr_new, r_bin_java_rti_annotations_attr_free, r_bin_java_print_rti_annotations_attr_summary, r_bin_java_rti_annotations_attr_calc_size  }, 
	{ r_bin_java_rtip_annotations_attr_new, r_bin_java_rtip_annotations_attr_free, r_bin_java_print_rtip_annotations_attr_summary, r_bin_java_rtip_annotations_attr_calc_size },
	{ r_bin_java_rtv_annotations_attr_new, r_bin_java_rtv_annotations_attr_free, r_bin_java_print_rtv_annotations_attr_summary,r_bin_java_rtv_annotations_attr_calc_size }, 
	{ r_bin_java_rtvp_annotations_attr_new, r_bin_java_rtvp_annotations_attr_free, r_bin_java_print_rtvp_annotations_attr_summary, r_bin_java_rtvp_annotations_attr_calc_size },
	{ r_bin_java_signature_attr_new, r_bin_java_signature_attr_free, r_bin_java_print_signature_attr_summary, r_bin_java_signature_attr_calc_size }, 
	{ r_bin_java_source_debug_attr_new, r_bin_java_source_debug_attr_free, r_bin_java_print_source_debug_attr_summary, r_bin_java_source_debug_attr_calc_size }, 
	{ r_bin_java_source_code_file_attr_new, r_bin_java_source_code_file_attr_free, r_bin_java_print_source_code_file_attr_summary, r_bin_java_source_code_file_attr_calc_size }, 
	{ r_bin_java_stack_map_table_attr_new, r_bin_java_stack_map_table_attr_free, r_bin_java_print_stack_map_table_attr_summary, r_bin_java_stack_map_table_attr_calc_size }, 
	{ r_bin_java_synthetic_attr_new, r_bin_java_synthetic_attr_free, r_bin_java_print_synthetic_attr_summary, r_bin_java_synthetic_attr_calc_size },
	{ r_bin_java_unknown_attr_new, r_bin_java_unknown_attr_free, r_bin_java_print_unknown_attr_summary, r_bin_java_unknown_attr_calc_size} 
};

static ut32 RBIN_JAVA_ATTRS_METAS_SZ = 20;
static RBinJavaAttrMetas RBIN_JAVA_ATTRS_METAS[] = {
	{ "AnnotationDefault", R_BIN_JAVA_ATTR_TYPE_ANNOTATION_DEFAULT_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[0]},
	{ "BootstrapMethods", R_BIN_JAVA_ATTR_TYPE_BOOTSTRAP_METHODS_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[1]},
	{ "Code", R_BIN_JAVA_ATTR_TYPE_CODE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[2]},
	{ "ConstantValue", R_BIN_JAVA_ATTR_TYPE_CONST_VALUE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[3]},
	{ "Deperecated", R_BIN_JAVA_ATTR_TYPE_DEPRECATED_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[4]}, 
	{ "EnclosingMethod", R_BIN_JAVA_ATTR_TYPE_ENCLOSING_METHOD_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[5]},
	{ "Exceptions", R_BIN_JAVA_ATTR_TYPE_EXCEPTIONS_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[6]},
	{ "InnerClasses", R_BIN_JAVA_ATTR_TYPE_INNER_CLASSES_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[7]},
	{ "LineNumberTable", R_BIN_JAVA_ATTR_TYPE_LINE_NUMBER_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[8]}, 
	{ "LocalVariableTable", R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[9]}, 
	{ "LocalVariableTypeTable", R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TYPE_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[10]}, 
	{ "RuntimeInvisibleAnnotations", R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[11]},
	{ "RuntimeInvisibleParameterAnnotations", R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[12]},
	{ "RuntimeVisibleAnnotations", R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[13]},
	{ "RuntimeVisibleParameterAnnotations", R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[14]},
	{ "Signature", R_BIN_JAVA_ATTR_TYPE_SIGNATURE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[15]}, 
	{ "SourceDebugExtension", R_BIN_JAVA_ATTR_TYPE_SOURCE_DEBUG_EXTENTSION_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[16]},
	{ "SourceFile", R_BIN_JAVA_ATTR_TYPE_SOURCE_FILE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[17]}, 
	{ "StackMapTable", R_BIN_JAVA_ATTR_TYPE_STACK_MAP_TABLE_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[18]}, 
	{ "Synthetic", R_BIN_JAVA_ATTR_TYPE_SYNTHETIC_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[19]}, 
	{ "Unknown", R_BIN_JAVA_ATTR_TYPE_UNKNOWN_ATTR, &RBIN_JAVA_ATTRS_ALLOCS[20]} 
};

R_API RBinJavaCPTypeObj* r_bin_java_get_java_null_cp(){
	if(R_BIN_JAVA_NULL_TYPE_INITTED)
		return &R_BIN_JAVA_NULL_TYPE;

	R_BIN_JAVA_NULL_TYPE_INITTED = 1;
	memset(&R_BIN_JAVA_NULL_TYPE, 0, sizeof(R_BIN_JAVA_NULL_TYPE));
	R_BIN_JAVA_NULL_TYPE.metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
	if (R_BIN_JAVA_NULL_TYPE.metas == NULL)
		return NULL;

	memset( R_BIN_JAVA_NULL_TYPE.metas, 0, sizeof(RBinJavaMetaInfo));
	R_BIN_JAVA_NULL_TYPE.metas->type_info = &R_BIN_JAVA_CP_METAS[0];
	R_BIN_JAVA_NULL_TYPE.metas->ord = -1;
	R_BIN_JAVA_NULL_TYPE.file_offset = -1;
	return &R_BIN_JAVA_NULL_TYPE;
}

R_API RBinJavaElementValueMetas* r_bin_java_get_ev_meta_from_tag(ut8 tag){
	ut16 i = 0;
	RBinJavaElementValueMetas *result = &R_BIN_JAVA_ELEMENT_VALUE_METAS[13];
	for (i = 0; i < R_BIN_JAVA_ELEMENT_VALUE_METAS_SZ; i++ ){
		if (tag == R_BIN_JAVA_ELEMENT_VALUE_METAS[i].tag){
			result = &R_BIN_JAVA_ELEMENT_VALUE_METAS[i];
			break;
		}
	}
	return result;
}

R_API RBinJavaCPTypeMetas* r_bin_java_get_cp_meta_from_tag(ut8 tag){
	ut16 i = 0;
	// set default to unknown.
	RBinJavaCPTypeMetas *result = &R_BIN_JAVA_CP_METAS[2];
	for (i = 0; i < R_BIN_JAVA_CP_METAS_SZ; i++ ){
		if (tag == R_BIN_JAVA_CP_METAS[i].tag){
			result = &R_BIN_JAVA_CP_METAS[i];
			break;
		}
	}
	return result;
}
void deinit_java_type_null(){
	if (R_BIN_JAVA_NULL_TYPE.metas)
		free(R_BIN_JAVA_NULL_TYPE.metas);
}

R_API ut8 r_bin_java_quick_check(ut8 expected_tag, ut8 actual_tag, ut32 actual_len, const char* name){

	ut8 result = 0;
	if (expected_tag > R_BIN_JAVA_CP_METAS_SZ){
		eprintf ("Invalid tag '%d' expected 0x%02x for %s.\n",actual_tag, expected_tag, name);
		result = 1; 
	}else if (expected_tag != actual_tag){
		eprintf ("Invalid tag '%d' expected 0x%02x for %s.\n",actual_tag, expected_tag, name);
		result = 1;
	}else if (actual_len < R_BIN_JAVA_CP_METAS[expected_tag].len){
		eprintf ("Unable to parse '%d' expected sz=0x%02x got 0x%02x for %s.\n",
				actual_tag, R_BIN_JAVA_CP_METAS[expected_tag].len, actual_len, name);
		result = 2;
	}
	return result;
} 

R_API ut64 rbin_java_raw_to_long(ut8* raw, ut64 offset){
	return RBIN_JAVA_LONG(raw, offset);
} 

// yanked from careercup, because i am lazy:
// 1) dont want to figure out how make radare use math library
// 2) dont feel like figuring it out when google does it in O(1).
R_API double my_pow(double a,int b)
{
   if(b==0) return 1;
   if(b==1) return a;
   double temp=my_pow(a,b/2);
   temp=temp*temp;
   return ((b%2==0)? temp : temp*a);
}

double rbin_java_raw_to_double(ut8* raw, ut64 offset){
	ut64 bits = RBIN_JAVA_LONG(raw, offset);
	int s = ((bits >> 63) == 0) ? 1 : -1;
    int e = (int)((bits >> 52) & 0x7ffL);
    long m = (e == 0) ?
    		(bits & 0xfffffffffffffL) << 1 :
    		(bits & 0xfffffffffffffL) | 0x10000000000000L;
    double result = 0.0;
    IFDBG printf("Convert Long to Double: %llx\n", bits);
    if (0x7ff0000000000000 == bits){
    	result = INFINITY;
    }else if (0xfff0000000000000 == bits){
    	result = -INFINITY;
    }else if (0x7ff0000000000001 <= bits && bits <= 0x7fffffffffffffffL  ){
    	result = NAN;
    }else if (0xfff0000000000001 <= bits && bits <= 0xffffffffffffffffL  ){
    	result = NAN;
    }else{
    	result = s* m* my_pow(2, e-1075);//XXXX TODO Get double to work correctly here
    	IFDBG printf("Convert Long to Double s: %d, m: 0x%08lx, e: 0x%08x, result: %f\n", s, m, e, result);
    }
    return result;
}



R_API RBinJavaField* r_bin_java_read_next_method(RBinJavaObj *bin, ut64 offset){
	RBinJavaField *method;
	RBinJavaAttrInfo* attr;
	ut32 i;
	ut8 buf[8];

	if (offset == R_BUF_CUR )
		offset = bin->b->cur;

	method = (RBinJavaField *) malloc(sizeof(RBinJavaField));
	method->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
	if(method->metas)
		memset(method->metas, 0, sizeof(RBinJavaMetaInfo));

	r_buf_read_at (bin->b, offset, (ut8*)buf, 8);
	method->file_offset = offset;
	method->flags = R_BIN_JAVA_USHORT (buf, 0);
	method->name_idx = R_BIN_JAVA_USHORT(buf, 2);
	method->descriptor_idx = R_BIN_JAVA_USHORT(buf, 4);
	method->attr_count = R_BIN_JAVA_USHORT(buf, 6);
	method->attributes = r_list_new();
	method->type = R_BIN_JAVA_FIELD_TYPE_METHOD;
	
	method->metas->ord = bin->method_idx;

	method->name = r_bin_java_get_utf8_from_bin_cp_list(bin, (ut32) (method->name_idx));
	if(method->name == NULL){
		method->name = (char *)malloc(21);
		snprintf((char *) method->name, 20, "sym.method_%08x", method->metas->ord);
		eprintf("r_bin_java_read_next_method: Unable to find the name for 0x%02x index.\n", method->name_idx);
	}

	method->descriptor = r_bin_java_get_utf8_from_bin_cp_list(bin, (ut32) method->descriptor_idx);
	if(method->descriptor == NULL){
		method->descriptor = r_str_dup (NULL, "NULL");
		eprintf("r_bin_java_read_next_method: Unable to find the descriptor for 0x%02x index.\n", method->descriptor_idx);
	}
	
	method->field_ref_cp_obj = r_bin_java_find_cp_ref_info_from_name_and_type(method->name_idx, method->descriptor_idx);
	if (method->field_ref_cp_obj){
		method->class_name = r_bin_java_get_item_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, method->field_ref_cp_obj);
		if (method->class_name == NULL)
			method->class_name = r_str_dup(NULL, "NULL");

	}

	IFDBG printf("Parsing %s(%s)", method->name, method->descriptor);


	if (method->attr_count > 0) {
		for (i=0; i< method->attr_count ; i++){
			attr = r_bin_java_read_next_attr(bin, bin->b->cur);
			if ((r_bin_java_get_attr_type_by_name(attr->name))->type == R_BIN_JAVA_ATTR_TYPE_CODE_ATTR){
				// This is necessary for determing the appropriate number of bytes when readin
				// uoffset, ustack, ulocalvar values
				bin->cur_method_code_length = attr->info.code_attr.code_length;
				bin->offset_sz = 2;//(attr->info.code_attr.code_length > 65535) ? 4 : 2;
				bin->ustack_sz = 2;// (attr->info.code_attr.max_stack > 65535) ? 4 : 2;
				bin->ulocalvar_sz = 2;//(attr->info.code_attr.max_locals > 65535) ? 4 : 2;
			}
			r_list_append(method->attributes, attr);
		}
	}

	// reset after parsing the method attributes
	return method;

}



R_API RBinJavaField* r_bin_java_read_next_field(RBinJavaObj *bin, ut64 offset){
	RBinJavaField *field;
	RBinJavaAttrInfo* attr;
	ut32 i;
	ut8 buf[8];

	if (offset == R_BUF_CUR )
		offset = bin->b->cur;
	
	field = (RBinJavaField *) malloc(sizeof(RBinJavaField));
	field->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
	if(field->metas)
		memset(field->metas, 0, sizeof(RBinJavaMetaInfo));

	r_buf_read_at (bin->b, offset, (ut8*)buf, 8);
	field->file_offset = offset;
	field->flags = R_BIN_JAVA_USHORT (buf, 0);
	field->name_idx = R_BIN_JAVA_USHORT(buf, 2);
	field->descriptor_idx = R_BIN_JAVA_USHORT(buf, 4);
	field->attr_count = R_BIN_JAVA_USHORT(buf, 6);
	field->attributes = r_list_new();
	field->type = R_BIN_JAVA_FIELD_TYPE_FIELD;

	field->metas->ord = bin->field_idx;

	field->name = r_bin_java_get_utf8_from_bin_cp_list(bin, field->name_idx);
	if(field->name == NULL){
		field->name = r_str_dup (NULL, "NULL");
		eprintf("r_bin_java_read_next_field: Unable to find the name for %d index.\n", field->name_idx);
	}

	field->descriptor = r_bin_java_get_utf8_from_bin_cp_list(bin, field->descriptor_idx);
	if(field->descriptor == NULL){
		field->descriptor = r_str_dup (NULL, "NULL");
		eprintf("r_bin_java_read_next_field: Unable to find the descriptor for %d index.\n", field->descriptor_idx);
	}
	
	field->field_ref_cp_obj = r_bin_java_find_cp_ref_info_from_name_and_type(field->name_idx, field->descriptor_idx);
	if (field->field_ref_cp_obj){
		field->class_name = r_bin_java_get_item_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, field->field_ref_cp_obj);
		if (field->class_name == NULL)
			field->class_name = r_str_dup(NULL, "NULL");

	}

	if (field->attr_count > 0) {


		for (i=0; i< field->attr_count ; i++){
			attr = r_bin_java_read_next_attr(bin, bin->b->cur);
			r_list_append(field->attributes, attr);
		}
	}

	return field;

}

R_API RBinJavaCPTypeObj* r_bin_java_clone_cp_idx(RBinJavaObj *bin, ut32 idx){
	
	RBinJavaCPTypeObj* obj = NULL;
	if (bin)
		obj = r_bin_java_get_item_from_bin_cp_list(bin, idx);
	return r_bin_java_clone_cp_item(obj);	
}

R_API RBinJavaCPTypeObj* r_bin_java_clone_cp_item(RBinJavaCPTypeObj *obj){
	RBinJavaCPTypeObj *clone_obj = NULL;
		                        
	if (obj == NULL)
		return clone_obj;

	clone_obj = (RBinJavaCPTypeObj*) malloc(sizeof(RBinJavaCPTypeObj));
	if(clone_obj){
		memcpy(clone_obj, obj, sizeof(RBinJavaCPTypeObj));
		if(obj->tag == R_BIN_JAVA_CP_UTF8){
			clone_obj->info.cp_utf8.bytes = (ut8 *) malloc(obj->info.cp_utf8.length+1);
			if (clone_obj->info.cp_utf8.bytes){
				memcpy(clone_obj->info.cp_utf8.bytes, obj->info.cp_utf8.bytes, clone_obj->info.cp_utf8.length+1); 
			}else{
				// TODO: eprintf allocation error
			}
		}
	}
	return clone_obj;

}

R_API RBinJavaCPTypeObj* r_bin_java_read_next_constant_pool_item(RBinJavaObj *bin, ut64 offset){
	RBinJavaCPTypeMetas *java_constant_info = NULL;
	ut8 tag = 0;
	ut64 buf_sz = 0;
	ut8 *buf = NULL;
	ut32 str_len = 0;
	RBinJavaCPTypeObj *java_obj = NULL;

	if (offset == R_BUF_CUR )
		offset = bin->b->cur;

	r_buf_read_at (bin->b, offset, &tag, 1);
	if ( tag > R_BIN_JAVA_CP_METAS_SZ){
		eprintf ("Invalid tag '%d' at offset 0x%08llx\n", tag, (ut64)offset);
		java_obj = r_bin_java_unknown_cp_new(bin, &tag, 1);
		
		if (java_obj != NULL && java_obj->metas != NULL){
			java_obj->file_offset = offset;
		}
		return java_obj;
	}

	java_constant_info = &R_BIN_JAVA_CP_METAS[tag];
	if (java_constant_info->tag == 0 || java_constant_info->tag == 2 ) {
		java_obj->file_offset = offset;
		return java_obj;
	}
	
	buf_sz += java_constant_info->len;
	if (java_constant_info->tag == 1){
		r_buf_read_at(bin->b, offset+1, (ut8 *) &str_len, sizeof(ut16));
		buf_sz += r_bin_java_swap_ushort (str_len);	
	}
	buf = malloc(buf_sz);
	
	if (!buf)
		return java_obj;

	memset(buf, 0, buf_sz);
	r_buf_read_at(bin->b, offset, (ut8*) buf, buf_sz);
	IFDBG printf ("Parsed the tag '%d':%s and create object from offset 0x%08llx.\n",tag, R_BIN_JAVA_CP_METAS[tag].name, offset);
	java_obj = (*java_constant_info->allocs->new_obj)(bin, buf, buf_sz);
	
	if (java_obj != NULL && java_obj->metas != NULL){
		java_obj->file_offset = offset;
		//IFDBG printf ("java_obj->file_offset = 0x%08llx.\n",java_obj->file_offset);
	
	}else if(java_obj == NULL){
		eprintf ("Unable to parse the tag '%d' and create valid object.\n",tag);
	}else if(java_obj->metas == NULL){
		eprintf ("Unable to parse the tag '%d' and create valid object.\n",tag);		
	}else{
		eprintf ("Failed to set the java_obj->metas-file_offset for '%d' offset is(0x%08llx).\n",tag, offset);
	}

	free(buf);
	return java_obj;
}



R_API RBinJavaInterfaceInfo* r_bin_java_read_next_interface_item(RBinJavaObj *bin, ut64 offset){
	ut8 buf[2] = {0};
	RBinJavaInterfaceInfo *interface_obj;
	
	if (offset == R_BUF_CUR )
		offset = bin->b->cur;

	r_buf_read_at (bin->b, offset, buf, 2);
	interface_obj = r_bin_java_interface_new(bin, buf, 2);
	if (interface_obj)
		interface_obj->file_offset = offset;
	return interface_obj;
}


/*
ut16 r_bin_java_read_short(RBinJavaObj *bin, ut64 offset) {
	ut16 sh = 0;
	r_buf_read_at (bin->b, offset, (ut8*)&sh, 2);
	return r_bin_java_swap_ushort (sh);
}

ut32 r_bin_java_read_int(RBinJavaObj *bin, ut64 offset) {
	ut32 sh = 0;
	r_buf_read_at (bin->b, offset, (ut8*)&sh, 4);
	return R_BIN_JAVA_SWAPUINT (sh);
}
*/

static void addrow (RBinJavaObj *bin, int addr, int line) {
	int n = bin->lines.count++;
	// XXX. possible memleak
	bin->lines.addr = realloc (bin->lines.addr, sizeof(int)*n+1);
	bin->lines.addr[n] = addr;
	bin->lines.line = realloc (bin->lines.line, sizeof(int)*n+1);
	bin->lines.line[n] = line;
}

//static struct r_bin_java_cp_item_t* r_bin_java_get_item_from_cp_CP(RBinJavaObj *bin, int i) {
//	return (i<0||i>bin->cf.cp_count)? &cp_null_item: &bin->cp_items[i];
//}

R_API RBinJavaCPTypeObj* r_bin_java_get_item_from_cp(RBinJavaObj *bin, int i) {
	if (i < 0 || i > bin->cf.cp_count )
		return  &R_BIN_JAVA_NULL_TYPE;

	RBinJavaCPTypeObj* obj = (RBinJavaCPTypeObj*)r_list_get_n(bin->cp_list, i);
	if (obj == NULL)
		return  &R_BIN_JAVA_NULL_TYPE;

	return obj;
}

R_API char* r_bin_java_get_utf8_from_bin_cp_list(RBinJavaObj *bin, ut64 idx){
	/*
		Search through the Constant Pool list for the given CP Index.
		If the idx not found by directly going to the list index,
		the list will be walked and then the IDX will be checked.

		rvalue: new char* for caller to free.
	
	*/
	if (bin == NULL)
		return NULL;

	return r_bin_java_get_utf8_from_cp_item_list(bin->cp_list, idx);
}

R_API char* r_bin_java_get_name_from_bin_cp_list(RBinJavaObj *bin, ut64 idx){
	/*
		Search through the Constant Pool list for the given CP Index.
		If the idx not found by directly going to the list index,
		the list will be walked and then the IDX will be checked.

		rvalue: new char* for caller to free.
	
	*/
	if (bin == NULL)
		return NULL;

	return r_bin_java_get_name_from_cp_item_list(bin->cp_list, idx);
}

R_API char* r_bin_java_get_desc_from_bin_cp_list(RBinJavaObj *bin, ut64 idx){
	/*
		Search through the Constant Pool list for the given CP Index.
		If the idx not found by directly going to the list index,
		the list will be walked and then the IDX will be checked.

		rvalue: new char* for caller to free.
	
	*/
	if (bin == NULL)
		return NULL;

	return r_bin_java_get_desc_from_cp_item_list(bin->cp_list, idx);
}

R_API RBinJavaCPTypeObj* r_bin_java_get_item_from_bin_cp_list(RBinJavaObj *bin, ut64 idx){
	/*
		Search through the Constant Pool list for the given CP Index.
		If the idx not found by directly going to the list index,
		the list will be walked and then the IDX will be checked.

		rvalue: RBinJavaObj* (user does NOT free).
	
	*/
	if (bin == NULL)
		return NULL;

	return r_bin_java_get_item_from_cp_item_list(bin->cp_list, idx);
}

R_API char* r_bin_java_get_item_name_from_bin_cp_list(RBinJavaObj *bin, RBinJavaCPTypeObj *obj){
	/*
		Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
		return the actual descriptor string.  
		@param cp_list: RList of RBinJavaCPTypeObj *
		@param obj object to look up the name for 
		@rvalue char* (user frees) or NULL
	*/
	if (bin == NULL)
		return NULL;

	return r_bin_java_get_item_name_from_cp_item_list(bin->cp_list, obj);
}

R_API char* r_bin_java_get_item_desc_from_bin_cp_list(RBinJavaObj *bin, RBinJavaCPTypeObj *obj){
	/*
		Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
		return the actual descriptor string.  
		@param cp_list: RList of RBinJavaCPTypeObj *
		@param obj object to look up the name for 
		@rvalue char* (user frees) or NULL
	*/
	if (bin == NULL)
		return NULL;

	return r_bin_java_get_item_desc_from_cp_item_list(bin->cp_list, obj);
}


R_API char* r_bin_java_get_utf8_from_cp_item_list(RList *cp_list, ut64 idx){
	/*
		Search through the Constant Pool list for the given CP Index.
		If the idx not found by directly going to the list index,
		the list will be walked and then the IDX will be checked.

		rvalue: new char* for caller to free.
	
	*/

	char *value = NULL;
	RListIter *iter; 
	RBinJavaCPTypeObj *item = NULL;
	
	if (cp_list == NULL)
		return NULL;

	item = (RBinJavaCPTypeObj *) r_list_get_n(cp_list, idx);
	if (item && (item->tag == R_BIN_JAVA_CP_UTF8) && item->metas->ord == idx){
		value = r_str_dup (NULL, (const char *) item->info.cp_utf8.bytes);
	}

	if (value == NULL){
        r_list_foreach (cp_list, iter, item ) {
            if (item && (item->tag == R_BIN_JAVA_CP_UTF8) && item->metas->ord == idx){
				value = r_str_dup (NULL, (const char *) item->info.cp_utf8.bytes);
				break;
	        }
        }
	}

	return value;
}

R_API RBinJavaCPTypeObj* r_bin_java_get_item_from_cp_item_list(RList *cp_list, ut64 idx){
	/*
		Search through the Constant Pool list for the given CP Index.

		rvalue: RBinJavaObj *
	
	*/
	RBinJavaCPTypeObj *item = NULL;
	if (cp_list == NULL)
		return NULL;

	item = (RBinJavaCPTypeObj *) r_list_get_n(cp_list, idx);
	return item;
}




R_API char* r_bin_java_get_item_name_from_cp_item_list(RList *cp_list, RBinJavaCPTypeObj *obj){
	/*
		Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
		return the actual descriptor string.  
		@param cp_list: RList of RBinJavaCPTypeObj *
		@param obj object to look up the name for 
		@rvalue ut8* (user frees) or NULL
	*/

	char *value = NULL;
	ut32 idx = 0;

	if(obj == NULL || cp_list == NULL)
		return NULL;

	else if( obj->tag != R_BIN_JAVA_CP_METHODREF &&
		obj->tag != R_BIN_JAVA_CP_INTERFACEMETHOD_REF &&
		obj->tag != R_BIN_JAVA_CP_FIELDREF && 
		obj->tag != R_BIN_JAVA_CP_CLASS)
		return NULL;

	if (obj->tag == R_BIN_JAVA_CP_CLASS){
		idx = obj->info.cp_class.name_idx;
		value = r_bin_java_get_utf8_from_cp_item_list(cp_list, idx);
	}else{
		switch(obj->tag){
			case R_BIN_JAVA_CP_METHODREF:
				idx = obj->info.cp_method.name_and_type_idx;
				break;
			case R_BIN_JAVA_CP_FIELDREF:
				idx = obj->info.cp_field.name_and_type_idx;
				break;
			case R_BIN_JAVA_CP_INTERFACEMETHOD_REF:
				idx = obj->info.cp_interface.name_and_type_idx;
				break;			
		}

		RBinJavaCPTypeObj *item = r_bin_java_get_item_from_cp_item_list(cp_list, idx);

		if(item){
			idx = obj->info.cp_name_and_type.name_idx;	
			value = r_bin_java_get_utf8_from_cp_item_list(cp_list, idx);	
		}
	}


	return value; 

}

R_API char* r_bin_java_get_name_from_cp_item_list(RList *cp_list, ut64 idx){
	/*
		Given a constant poool object Class, FieldRef, MethodRef, or InterfaceMethodRef
		return the actual descriptor string.  
		@param cp_list: RList of RBinJavaCPTypeObj *
		@param obj object to look up the name for 
		@rvalue ut8* (user frees) or NULL
	*/

	RBinJavaCPTypeObj *obj = r_bin_java_get_item_from_cp_item_list(cp_list, idx);
	if (cp_list == NULL)
		return NULL;

	return r_bin_java_get_item_name_from_cp_item_list(cp_list, obj);

}

R_API char* r_bin_java_get_item_desc_from_cp_item_list(RList *cp_list, RBinJavaCPTypeObj *obj){
	/*
		Given a constant poool object FieldRef, MethodRef, or InterfaceMethodRef
		return the actual descriptor string.  

		@rvalue ut8* (user frees) or NULL
	*/

	RBinJavaCPTypeObj *item = NULL;
	ut32 idx = 0;

	if(obj == NULL || cp_list == NULL)
		return NULL;
	else if( obj->tag != R_BIN_JAVA_CP_METHODREF &&
		obj->tag != R_BIN_JAVA_CP_INTERFACEMETHOD_REF &&
		obj->tag != R_BIN_JAVA_CP_FIELDREF)
		return NULL;

	switch(obj->tag){
		case R_BIN_JAVA_CP_METHODREF:
			idx = obj->info.cp_method.name_and_type_idx;
			break;
		case R_BIN_JAVA_CP_FIELDREF:
			idx = obj->info.cp_field.name_and_type_idx;
			break;
		case R_BIN_JAVA_CP_INTERFACEMETHOD_REF:
			idx = obj->info.cp_interface.name_and_type_idx;
			break;			
	}

	item = r_bin_java_get_item_from_cp_item_list(cp_list, idx);

	if(item == NULL)
		return NULL;
	
	idx = obj->info.cp_name_and_type.descriptor_idx;
	return r_bin_java_get_name_from_cp_item_list(cp_list, idx); 
}

R_API char* r_bin_java_get_desc_from_cp_item_list(RList *cp_list, ut64 idx){
	/*
		Given a constant poool object FieldRef, MethodRef, or InterfaceMethodRef
		return the actual descriptor string.  

		@rvalue ut8* (user frees) or NULL
	*/

	char *value = NULL;

	RBinJavaCPTypeObj *obj = NULL;

	if (cp_list == NULL)
		return NULL;

	obj = r_bin_java_get_item_from_cp_item_list(cp_list, idx);

	if(obj == NULL)
		return value;
	else if( obj->tag != R_BIN_JAVA_CP_METHODREF &&
		obj->tag != R_BIN_JAVA_CP_INTERFACEMETHOD_REF &&
		obj->tag != R_BIN_JAVA_CP_FIELDREF)
		return value;

	switch(obj->tag){
		case R_BIN_JAVA_CP_METHODREF:
			idx = obj->info.cp_method.name_and_type_idx;
			break;
		case R_BIN_JAVA_CP_FIELDREF:
			idx = obj->info.cp_field.name_and_type_idx;
			break;
		case R_BIN_JAVA_CP_INTERFACEMETHOD_REF:
			idx = obj->info.cp_interface.name_and_type_idx;
			break;			
	}

	return r_bin_java_get_utf8_from_cp_item_list(cp_list, idx); 
}

R_API RBinJavaAttrInfo* r_bin_java_get_method_code_attribute(RBinJavaField *method){
	/*
		Search through a methods attributes and return the code attr.
		
		rvalue: RBinJavaAttrInfo* if found otherwise NULL.
	
	*/
	RBinJavaAttrInfo *result = NULL, *attr = NULL;
	RListIter *iter; 
	
	if (method){
        r_list_foreach (method->attributes, iter, attr ) {
            if (attr && (attr->type == R_BIN_JAVA_ATTR_TYPE_CODE_ATTR) ){
				result = attr;
				break;
	        }
        }
	}

	return result;
}

R_API RBinJavaAttrInfo* r_bin_java_get_attr_from_field(RBinJavaField *field, R_BIN_JAVA_ATTR_TYPE attr_type, ut32 pos ){
	/*
		Search through the Attribute list for the given type starting at position pos.
		rvalue: NULL or the first occurrence of attr_type after pos
	
	*/
	RBinJavaAttrInfo *attr, *item;
	RListIter *iter; 
	ut32 i;

	if (field){
        r_list_foreach (field->attributes, iter, item) {
        	// Note the increment happens after the comparison
        	if ( (i++) >= pos){
	            if (item && (item->type == attr_type)){
					attr = item;
					break;
		        }        		
        	}
        }
	}
	return attr;
}
R_API ut8* r_bin_java_get_attr_buf(RBinJavaObj *bin, ut64 offset, ut64 sz){
	ut8 buf[10];
	ut8 *attr_buf = NULL;
	if (offset == R_BUF_CUR)
		offset = bin->b->cur;

	attr_buf = (ut8 *) malloc(sz);
	memset(attr_buf, 0, sz);
	
	r_buf_read_at (bin->b, offset, (ut8*)attr_buf, sz);
	
	if (attr_buf == NULL){
		eprintf("Unable to allocate enough bytes (0x%04llx) to read in the attribute.\n", sz);
		return attr_buf;
	}
	return attr_buf;
}

R_API RBinJavaAttrInfo* r_bin_java_default_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	
	RBinJavaAttrInfo *attr = (RBinJavaAttrInfo *) malloc(sizeof(RBinJavaAttrInfo));
	RBinJavaAttrMetas *type_info = NULL;
	ut64 offset = 0;
	// read the offset now, before we make modifications or read from the buffer

	memset(attr, 0, sizeof(RBinJavaAttrInfo));
	attr->metas = (RBinJavaMetaInfo *)malloc(sizeof(RBinJavaMetaInfo));
	if (attr->metas == NULL){
		free(attr);
		return NULL;
	}
	
	memset(attr->metas, 0, sizeof(RBinJavaMetaInfo));
	
	attr->file_offset = buf_offset;
	
	attr->name_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	attr->size += 2;

	attr->length = R_BIN_JAVA_UINT(buffer, offset);
	offset += 4;
	attr->size += 4;

	attr->name = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, attr->name_idx);
	if(attr->name == NULL){
		// Something bad has happened
		attr->name = r_str_dup (NULL, "NULL");
		eprintf("r_bin_java_default_attr_new: Unable to find the name for %d index.\n", attr->name_idx);
	}


	type_info = r_bin_java_get_attr_type_by_name(attr->name);

	attr->metas->ord = (R_BIN_JAVA_GLOBAL_BIN->attr_idx++);
	attr->metas->type_info = (void *) type_info;
	//IFDBG printf("      Addrs for type_info [tag=%d]: 0x%08"PFMT64x"\n", type_val, &attr->metas->type_info);

	return attr;
}

RBinJavaAttrMetas* r_bin_java_get_attr_type_by_name(ut8 *name){
	RBinJavaAttrMetas* result = &RBIN_JAVA_ATTRS_METAS[R_BIN_JAVA_ATTR_TYPE_UNKNOWN_ATTR];
	
	ut32 i = 0;
	for (i = 0; i < RBIN_JAVA_ATTRS_METAS_SZ; i++){
		if (strcmp ( (const char *) name, RBIN_JAVA_ATTRS_METAS[i].name) == 0){
			result = &RBIN_JAVA_ATTRS_METAS[i];
			break;
		}
	}
	return result;
}


R_API RBinJavaAttrInfo* r_bin_java_read_next_attr(RBinJavaObj *bin, ut64 buf_offset){
	RBinJavaAttrInfo* attr = NULL;
	ut64 sz = 0;
	ut8* buffer = NULL;
	ut8 attr_idx_len = 6;
	if (buf_offset == R_BUF_CUR)
		buf_offset = bin->b->cur;
	
	// ut16 attr_idx, ut32 length of attr.
	sz = r_bin_java_read_int(bin, buf_offset+2) + attr_idx_len;
	// when reading the attr bytes, need to also 
	// include the initial 6 bytes, which
	// are not included in the attribute length
	IFDBG eprintf("Reading %"PFMT64d" bytes from 0x%"PFMT64x" to 0x%"PFMT64x"\n",
		sz, buf_offset, buf_offset+sz);
	buffer = r_bin_java_get_attr_buf(bin, buf_offset, sz);
	attr = r_bin_java_read_next_attr_from_buffer(buffer, sz, buf_offset);
	if (attr) // advance the cursor to the correct place
		bin->b->cur = (buf_offset + sz);
	return attr;

}

R_API RBinJavaAttrInfo* r_bin_java_read_next_attr_from_buffer(ut8 *buffer, ut64 sz, ut64 buf_offset){
	
	RBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	RBinJavaAttrMetas* type_info = NULL;

	if (buffer){
		ut8* name = NULL;
		ut16 name_idx = R_BIN_JAVA_USHORT(buffer, offset);
		
		offset += 2;

		sz = R_BIN_JAVA_UINT(buffer, offset);
		offset += 4;
		
		name = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, name_idx);
		// figure the appropriate Attributes Meta,
		// get the meta
		// call its from buffer 
		type_info = r_bin_java_get_attr_type_by_name(name);
		free(name);
		
		attr =  type_info->allocs->new_obj(buffer, sz, buf_offset);
		
		if (attr){
			attr->metas->ord = (R_BIN_JAVA_GLOBAL_BIN->attr_idx++); 
		}		
	}

	return attr;
}

RBinJavaClass2* r_bin_java_read_class_file2(RBinJavaObj *bin, ut64 offset){
	RBinJavaClass2 *cf2 = (RBinJavaClass2 *) malloc(sizeof(RBinJavaClass2));

	if (cf2){
		memset(cf2, 0, sizeof(RBinJavaClass2));
		IFDBG printf ("\n0x%x Offset before reading the cf2 structure\n", bin->b->cur);
		r_buf_read_at (bin->b, bin->b->cur, (ut8*)cf2, 3*sizeof(ut16));
		/*
		Reading the following fields:
			ut16 access_flags;
			ut16 this_class;
			ut16 super_class;
		*/
		cf2->this_class = r_bin_java_swap_ushort (cf2->this_class);
	}else{
		eprintf ("r_bin_java_read_class_file2: Unable to allocate bytes for RBinJavaClass2");
	}
	return cf2;
}


static int javasm_init(RBinJavaObj *bin) {
	RBinJavaField *method, *field;
	RBinJavaInterfaceInfo *interfaces_obj;
	RBinJavaCPTypeObj *obj;
	int i;
	/* Initialize structs */
	R_BIN_JAVA_GLOBAL_BIN = bin;
	bin->lines.count = 0;
	bin->cp_list = r_list_new ();
	r_bin_java_get_java_null_cp ();

	/* Initialize cp_null_item */
	//cp_null_item.tag = -1;
	//strncpy (cp_null_item.name, "(null)", sizeof (cp_null_item.name)-1);
	//cp_null_item.value = strdup ("(null)"); // strdup memleak wtf

	/* start parsing */
	r_buf_read_at (bin->b, bin->b->cur, (ut8*)&bin->cf, 10);
	if (memcmp (bin->cf.cafebabe, "\xCA\xFE\xBA\xBE", 4)) {
		eprintf ("javasm_init: Invalid header (%02x %02x %02x %02x)\n",
				bin->cf.cafebabe[0], bin->cf.cafebabe[1],
				bin->cf.cafebabe[2], bin->cf.cafebabe[3]);
		return R_FALSE;
	}

	if (bin->cf.major[0]==bin->cf.major[1] && bin->cf.major[0]==0) {
		eprintf ("Java CLASS with MACH0 header?\n");
		return R_FALSE;
	}
	
	bin->cp_count = r_bin_java_swap_ushort (bin->cf.cp_count)-1;
	IFDBG printf ("ConstantPoolCount %d\n", bin->cp_count);
	bin->cp_offset = bin->b->cur;
	for (i=0; i < bin->cp_count; i++, bin->cp_idx++) {        
		obj = r_bin_java_read_next_constant_pool_item (bin, bin->b->cur);		
		if (obj) {
			//IFDBG printf ("SUCCESS Read ConstantPoolItem %d\n", i);
			obj->metas->ord = i+1;
			r_list_append (bin->cp_list, obj);
			if (obj->tag == R_BIN_JAVA_CP_LONG || obj->tag == R_BIN_JAVA_CP_DOUBLE){
				i++;
				bin->cp_idx++;
				r_list_append (bin->cp_list, &R_BIN_JAVA_NULL_TYPE);
			}
			IFDBG ((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->print_summary(obj);	
		} else {
			IFDBG printf ("Failed to read ConstantPoolItem %d\n", i);	
		}
		
	}
	bin->cp_size = bin->b->cur - bin->cp_offset;
	
	
	bin->cf2 = r_bin_java_read_class_file2(bin, bin->b->cur);
	if (bin->cf2 == NULL){
		eprintf ("Unable to read the class file info: bin->cf2 is NULL Failing?\n");
		return R_FALSE;	
	}

	IFDBG printf ("0x%x Access flags: 0x%04x\n", bin->b->cur, bin->cf2->access_flags);
	IFDBG printf ("This class: %d\n", bin->cf2->this_class);
	
	bin->interfaces_count = r_bin_java_read_short (bin, bin->b->cur);
	bin->interfaces_list = r_list_new();


	IFDBG printf("Interfaces count: %d\n", bin->interfaces_count);
	bin->interfaces_offset = bin->b->cur;
	if (bin->interfaces_count > 0) {
		for (i = 0; i < bin->fields_count; i++, bin->field_idx++){
			interfaces_obj = r_bin_java_read_next_interface_item(bin, bin->b->cur);
			r_list_append(bin->interfaces_list, interfaces_obj);			
		}		
	} 
	bin->interfaces_size = bin->b->cur - bin->interfaces_offset;

	bin->fields_count = r_bin_java_read_short (bin, bin->b->cur);
	bin->fields_list = r_list_new();

	bin->fields_offset = bin->b->cur;
	IFDBG printf ("Fields count: %d\n", bin->fields_count);
	if (bin->fields_count > 0) {
		for (i = 0; i < bin->fields_count; i++, bin->field_idx++){

			field = r_bin_java_read_next_field(bin, bin->b->cur);		
			if (obj){
				r_list_append(bin->fields_list, field);
				
				IFDBG r_bin_java_print_field_summary(field);	
			}else{
				IFDBG printf ("Failed to read Field %d\n", i);	
			}
		}
	}
	bin->fields_size = bin->b->cur - bin->fields_offset;
	
	bin->methods_offset = bin->b->cur;
	bin->methods_count = r_bin_java_read_short (bin,bin->b->cur);
	bin->methods_list = r_list_new ();

	IFDBG printf ("Methods count: %d\n", bin->methods_count);
	bin->main = NULL;
	bin->entrypoint = NULL;
	bin->main_code_attr = NULL;
	bin->entrypoint_code_attr = NULL;
	if (bin->methods_count > 0) {
		for ( i=0; i<bin->methods_count; i++,bin->method_idx++) {
			method = r_bin_java_read_next_method(bin, bin->b->cur);
			if (method){
				r_list_append (bin->methods_list, method);
			}
			// Update Main, Init, or Class Init
			if (method && !strcmp ( (const char *) method->name, "main")){
				bin->main = method;
				// get main code attr 
				bin->main_code_attr = r_bin_java_get_attr_from_field(method, R_BIN_JAVA_ATTR_TYPE_CODE_ATTR, 0);
			}
			else if (method && !strcmp ( (const char *) method->name, "<init>")){
				bin->entrypoint = method;
				bin->entrypoint_code_attr = r_bin_java_get_attr_from_field(method, R_BIN_JAVA_ATTR_TYPE_CODE_ATTR, 0);
			}
			else if (method && !strcmp ( (const char *) method->name, "<cinit>")) {
				bin->cf2->this_class_entrypoint = method;
				bin->cf2->this_class_entrypoint_code_attr = r_bin_java_get_attr_from_field(method, R_BIN_JAVA_ATTR_TYPE_CODE_ATTR, 0);

			}
			IFDBG r_bin_java_print_field_summary(method);

		}
	}
	bin->methods_size = bin->b->cur - bin->methods_offset;
	
	bin->attributes_offset = bin->b->cur;
	bin->attributes_count = r_bin_java_read_short (bin,bin->b->cur);

	if (bin->attributes_count > 0) {
		for ( i=0; i<bin->attributes_count; i++,bin->attributes_idx++) {
			RBinJavaAttrInfo* attr = r_bin_java_read_next_attr(bin, bin->b->cur);
			if (attr)
				r_list_append(bin->attributes, attr);
		}
	}
	bin->methods_size = bin->b->cur - bin->methods_offset;	
	return R_TRUE;
}

R_API char* r_bin_java_get_version(RBinJavaObj* bin) {
	return r_str_dup_printf ("0x%02x%02x 0x%02x%02x",
			bin->cf.major[1],bin->cf.major[0],
			bin->cf.minor[1],bin->cf.minor[0]);
}

R_API ut64 r_bin_java_get_main(RBinJavaObj* bin) {
	if (bin->main_code_attr){
		return bin->main_code_attr->info.code_attr.code_offset;
	}
	return 0;
}

R_API ut64 r_bin_java_get_entrypoint(RBinJavaObj* bin) {
	if (bin->entrypoint_code_attr){
		return bin->entrypoint_code_attr->info.code_attr.code_offset;
	}
	return 0;
}

R_API ut64 r_bin_java_get_class_entrypoint(RBinJavaObj* bin) {
	if (bin->cf2->this_class_entrypoint_code_attr){
		return bin->cf2->this_class_entrypoint_code_attr->info.code_attr.code_offset;
	}
	return 0;
}
/*
typedef struct r_bin_symbol_t {
	char name[R_BIN_SIZEOF_STRINGS];
	char forwarder[R_BIN_SIZEOF_STRINGS];
	char bind[R_BIN_SIZEOF_STRINGS];
	char type[R_BIN_SIZEOF_STRINGS];
	const char *classname;
	ut64 rva;
	ut64 offset;
	ut64 size;
	ut64 ordinal;
} RBinSymbol;
*/

RBinSymbol* r_bin_java_allocate_symbol(){
	RBinSymbol* t = (RBinSymbol *) malloc(sizeof(RBinSymbol));
	
	if (t)
		memset(t, 0, sizeof(RBinSymbol));
	
	return t;
}


R_API ut64 r_bin_java_get_method_code_size(RBinJavaField *fm_type){
	RListIter *attr_iter=NULL, *attr_iter_tmp=NULL;
	RBinJavaAttrInfo *attr = NULL, *code_attr = NULL;
	
	ut64 sz = 0;
	r_list_foreach_safe(fm_type->attributes, attr_iter, attr_iter_tmp, attr){
		if (attr->type == R_BIN_JAVA_ATTR_TYPE_CODE_ATTR) {
			sz = attr->info.code_attr.code_length;
			break;
		}
	}
	return sz;

}

R_API ut64 r_bin_java_get_method_code_offset(RBinJavaField *fm_type){
	RListIter *attr_iter=NULL, *attr_iter_tmp=NULL;
	RBinJavaAttrInfo *attr = NULL, *code_attr = NULL;
	
	ut64 offset = 0;
	r_list_foreach_safe(fm_type->attributes, attr_iter, attr_iter_tmp, attr){
		if (attr->type == R_BIN_JAVA_ATTR_TYPE_CODE_ATTR) {
			offset = attr->info.code_attr.code_offset;
			break;
		}
	}
	return offset;
}
/*
typedef struct r_bin_field_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
} RBinField;
*/
RBinField* r_bin_java_allocate_rbinfield(){
	RBinField* t = (RBinField *) malloc(sizeof(RBinField));
	
	if (t)
		memset(t, 0, sizeof(RBinField));
	
	return t;
}

R_API RBinField* r_bin_java_create_new_rbinfield_from_field(RBinJavaField *fm_type){

	RBinField *field = r_bin_java_allocate_rbinfield();

	if (field){
		strncpy(field->name, fm_type->name, R_BIN_SIZEOF_STRINGS);
		field->offset = fm_type->file_offset;
		field->visibility = fm_type->flags;
	}
	return field;
}

R_API RBinSymbol* r_bin_java_create_new_symbol_from_field(RBinJavaField *fm_type){

	RBinSymbol *sym = r_bin_java_allocate_symbol();

	if (sym){
		strncpy(sym->name, fm_type->name, R_BIN_SIZEOF_STRINGS);
		strncpy(sym->type, fm_type->descriptor, R_BIN_SIZEOF_STRINGS);
		sym->classname = r_str_dup(NULL, fm_type->class_name);
		sym->offset = fm_type->file_offset;
		sym->rva = r_bin_java_get_method_code_offset(fm_type);
		sym->ordinal = fm_type->metas->ord;
		sym->size = r_bin_java_get_method_code_size(fm_type);
		sym->visibility = fm_type->flags;
	}
	return sym;
}

R_API RBinSymbol* r_bin_java_create_new_symbol_from_ref(RBinJavaCPTypeObj *obj){
	RBinSymbol *sym = r_bin_java_allocate_symbol();
	ut8 *class_name, *name, *type_name; 

	if (obj == NULL || (obj->tag != R_BIN_JAVA_CP_METHODREF && 
		               obj->tag != R_BIN_JAVA_CP_INTERFACEMETHOD_REF &&  
		               obj->tag != R_BIN_JAVA_CP_FIELDREF) ){
		if (sym)
			free(sym);
		sym = NULL;
		return sym;
	}


	if (sym){
		class_name = r_bin_java_get_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, obj->info.cp_method.class_idx);
		name = r_bin_java_get_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, obj->info.cp_method.name_and_type_idx);
		type_name = r_bin_java_get_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, obj->info.cp_method.name_and_type_idx);
		
		if (name){
			strncpy(sym->name, name, R_BIN_SIZEOF_STRINGS);
			free(name);
			name = NULL;
		}
		if (type_name){
			strncpy(sym->type, type_name, R_BIN_SIZEOF_STRINGS);
			free(type_name);
			type_name = NULL;
		}
		if (class_name)
			sym->classname = class_name;

		sym->offset = obj->file_offset;
		sym->rva = obj->file_offset;
		sym->ordinal = obj->metas->ord;
		sym->size = 0;
	}
	return sym;
}
/*
typedef struct r_bin_section_t {
	char name[R_BIN_SIZEOF_STRINGS];
	ut64 size;
	ut64 vsize;
	ut64 rva;
	ut64 offset;
	ut64 srwx;
	// per section platform info
	const char *arch;
	int bits;
} RBinSection;
*/

R_API RBinSection* r_bin_java_allocate_section(){
	RBinSection* section = (RBinSection *) malloc(sizeof(RBinSection));
	if(section)
		memset(section, 0, sizeof(RBinSection));
	return section;
}

R_API RList* r_bin_java_get_sections(RBinJavaObj *bin){
	RBinSection* section = NULL;
	RList *sections = r_list_new();


	if (bin->cp_count > 0){
		section = r_bin_java_allocate_section();
		if(section){
			strcpy (section->name, "constant_pool");
			section->size = bin->cp_size;
			section->offset = bin->cp_offset;
			section->srwx = 0;
			r_list_append (sections, section);
		}
		section = NULL;
	}
	if (bin->fields_count > 0){
		section = r_bin_java_allocate_section();
		if(section){
			strcpy (section->name, "fields");
			section->size = bin->fields_size;
			section->offset = bin->fields_offset;
			section->srwx = 0;
			r_list_append (sections, section);
		}
		section = NULL;			
	}
	if (bin->methods_count > 0){
		section = r_bin_java_allocate_section();
		if(section){
			strcpy (section->name, "methods");
			section->size = bin->methods_size;
			section->offset = bin->methods_offset;
			section->srwx = 0;
			r_list_append (sections, section);
		}
		section = NULL;			
	}
	if (bin->interfaces_count > 0){
		section = r_bin_java_allocate_section();
		if(section){
			strcpy (section->name, "interfaces");
			section->size = bin->interfaces_size;
			section->offset = bin->interfaces_offset;
			section->srwx = 0;
			r_list_append (sections, section);
		}
		section = NULL;			
		
	}
	if (bin->attributes_count > 0){
		section = r_bin_java_allocate_section();
		if(section){
			strcpy (section->name, "attributes");
			section->size = bin->attributes_size;
			section->offset = bin->attributes_offset;
			r_list_append (sections, section);
		}
		section = NULL;			
	}
	return sections;
}

R_API RList* r_bin_java_enum_class_methods(RBinJavaObj *bin, ut16 class_idx){
	RList* methods = r_list_new ();
	RListIter *iter;
	RBinJavaField *fm_type;
	RBinSymbol *sym = NULL;
	r_list_foreach (bin->methods_list, iter, fm_type) {
		if (fm_type && fm_type->field_ref_cp_obj && \
		fm_type->field_ref_cp_obj->metas->ord == class_idx) {
			sym = r_bin_java_create_new_symbol_from_ref (
				fm_type->field_ref_cp_obj);
			if (sym) r_list_append (methods, sym);
		}
	}
	return methods; 
}

R_API RList* r_bin_java_enum_class_fields(RBinJavaObj *bin, ut16 class_idx){
	RList* fields = r_list_new();
	RListIter *iter, *iter_tmp;
	RBinJavaField *fm_type;
	RBinField *field = NULL;
	r_list_foreach_safe(bin->fields_list, iter, iter_tmp, fm_type){
		if (fm_type) {
			if (fm_type && fm_type->field_ref_cp_obj 
				&& fm_type->field_ref_cp_obj->metas->ord == class_idx){
				
				field = r_bin_java_create_new_rbinfield_from_field(fm_type);
				if (field) r_list_append(fields, field);

			}
		}

	}
	return fields; 
}

R_API RBinClass* r_bin_java_allocate_r_bin_class(){
	RBinClass* class_ = R_NEW0 (RBinClass);
	if (class_) {
		//class_->methods = r_list_new();
		//class_->fields = r_list_new();
	}
	return class_;
}

R_API RList* r_bin_java_get_classes(RBinJavaObj *bin){
	RBinSection* rclass = NULL;
	RList *classes = r_list_new ();
	RListIter *iter, *iter_tmp;
	RBinJavaCPTypeObj *cp_obj = NULL;
	ut32 idx = 0;
	RBinClass *class_;
	
	class_ = r_bin_java_allocate_r_bin_class ();
	class_->visibility = bin->cf2->access_flags;
	class_->methods = r_bin_java_enum_class_methods(bin, bin->cf2->this_class);
	class_->fields = r_bin_java_enum_class_fields(bin, bin->cf2->this_class);
	class_->name = r_bin_java_get_item_name_from_bin_cp_list(bin, cp_obj);
	class_->super = r_bin_java_get_name_from_bin_cp_list(bin, bin->cf2->super_class);	
	class_->index = (idx++);
	r_list_append (classes, class_);

	r_list_foreach_safe (bin->cp_list, iter, iter_tmp, cp_obj){
		if (cp_obj && 
			cp_obj->tag == R_BIN_JAVA_CP_CLASS &&
			bin->cf2->this_class != cp_obj->info.cp_class.name_idx){
			
			class_ = r_bin_java_allocate_r_bin_class();
			class_->methods = r_bin_java_enum_class_methods(bin, cp_obj->info.cp_class.name_idx);
			class_->fields = r_bin_java_enum_class_fields(bin, cp_obj->info.cp_class.name_idx);
			class_->index = idx;
			class_->name = r_bin_java_get_item_name_from_bin_cp_list(bin, cp_obj);
			r_list_append(classes, class_);
			idx++;
		}
	}
	return classes;
}

R_API RBinSymbol* r_bin_java_create_new_symbol_from_invoke_dynamic(RBinJavaCPTypeObj *obj){

	RBinSymbol *sym = NULL;	
	if (obj == NULL || (obj->tag != R_BIN_JAVA_CP_INVOKEDYNAMIC))
		return sym;
	return r_bin_java_create_new_symbol_from_cp_idx(obj->info.cp_invoke_dynamic.name_and_type_index);
}

R_API RBinSymbol* r_bin_java_create_new_symbol_from_cp_idx(ut32 cp_idx) {
	RBinSymbol *sym = NULL;
	RBinJavaCPTypeObj *obj = r_bin_java_get_item_from_bin_cp_list (
		R_BIN_JAVA_GLOBAL_BIN, cp_idx);

	if (obj) switch (obj->tag) {
	case R_BIN_JAVA_CP_METHODREF:
	case R_BIN_JAVA_CP_FIELDREF:
	case R_BIN_JAVA_CP_INTERFACEMETHOD_REF:
		sym = r_bin_java_create_new_symbol_from_ref (obj);
		break;
	case R_BIN_JAVA_CP_INVOKEDYNAMIC:
		sym = r_bin_java_create_new_symbol_from_invoke_dynamic (obj);
		break;
	default:
		break;
	}
	return sym;
}

RList* r_bin_java_get_fields(RBinJavaObj* bin) {
	RListIter *iter = NULL, *iter_tmp=NULL;
	RList *fields = r_list_new();
	RBinField *field;
	RBinJavaField *fm_type;

	r_list_foreach_safe(bin->fields_list, iter, iter_tmp, fm_type){	
		field = r_bin_java_create_new_rbinfield_from_field(fm_type);
		if(field){
			r_list_append(fields, field);
		}
	}
	return fields;
}


RList* r_bin_java_get_symbols(RBinJavaObj* bin) {
	RListIter *iter = NULL, *iter_tmp=NULL;
	RList *symbols = r_list_new();
	RBinSymbol *sym;
	RBinJavaField *fm_type;

	sym = NULL;
	r_list_foreach_safe(bin->methods_list, iter, iter_tmp, fm_type){	
		sym = r_bin_java_create_new_symbol_from_field(fm_type);
		if(sym){
			r_list_append(symbols, (void *) sym);
		}

	}
	return symbols;
}
/*
typedef struct r_bin_string_t {
	// TODO: rename string->name (avoid colisions)
	char string[R_BIN_SIZEOF_STRINGS];
	ut64 rva;
	ut64 offset;
	ut64 ordinal;
	ut64 size;
} RBinString;
*/

R_API RList* r_bin_java_get_strings(RBinJavaObj* bin) {
	RList *strings = r_list_new();
	RBinString *str = NULL;
		
	RListIter *iter = NULL, *iter_tmp=NULL;
	RBinJavaCPTypeObj *cp_obj = NULL;
	r_list_foreach_safe(bin->cp_list, iter, iter_tmp, cp_obj){

		if (cp_obj && cp_obj->tag == R_BIN_JAVA_CP_UTF8) {
			str = (RBinString *) malloc(sizeof(RBinString));
			if(str){
				str->offset = cp_obj->file_offset;
				str->ordinal = cp_obj->metas->ord;
				str->size = cp_obj->info.cp_utf8.length;
				strncpy ((char *) str->string, (const char *) cp_obj->info.cp_utf8.bytes, R_BIN_JAVA_MAXSTR);
				r_list_append(strings, (void *) str);
			}
		}
	}
	return strings;
}

R_API void* r_bin_java_free(RBinJavaObj* bin) {
	if (!bin) return NULL;
	// free up the constant pool list
	r_bin_java_constant_pool_list_free(bin);
	// free up the fields list
	r_bin_java_fields_list_free(bin);
	// free up methods list 
	r_bin_java_methods_list_free(bin);
	// free up interfaces list 
	r_bin_java_interfaces_list_free(bin);
	// TODO: XXX if a class list of all inner classes
	// are formed then this will need to be updated

	if (bin->b) r_buf_free (bin->b);
	if (bin->cf2) free(bin->cf2);	
	bin->b = NULL;
	R_BIN_JAVA_GLOBAL_BIN = NULL;
	free (bin);
	return NULL;
}

R_API RBinJavaObj* r_bin_java_new(const char* file) {
	ut8 *buf;
	RBinJavaObj *bin = R_NEW0 (RBinJavaObj);
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) 
		return r_bin_java_free (bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size))
		return r_bin_java_free (bin);
	free (buf);
	if (!javasm_init (bin))
		return r_bin_java_free (bin);
	return bin;
}

R_API RBinJavaObj* r_bin_java_new_buf(RBuffer *buf) {
	RBinJavaObj *bin = R_NEW0 (RBinJavaObj);
	if (!bin) return NULL;
	bin->b = buf;
	bin->size = buf->length;
	buf->cur = 0; // rewind
	if (!javasm_init (bin))
		return r_bin_java_free (bin);
	return bin;
}



R_API void r_bin_java_free_attribute_list(RList *attributes){
	RBinJavaAttrInfo* attr = NULL;
	RListIter *attr_iter, *attr_iter_tmp  = NULL;
	if(attributes){
		r_list_foreach_safe(attributes, attr_iter, attr_iter_tmp, attr){
			// Note the attr->type_info->delete_obj will free the attribute object
			((RBinJavaAttrMetas *) attr->metas->type_info)->allocs->delete_obj(attr);
			r_list_delete(attributes, attr_iter);
		}
		r_list_free(attributes);		
	}
	attributes = NULL;
}


R_API void r_bin_java_constant_pool_list_free(RBinJavaObj* bin){
	RListIter *iter, *iter_tmp;
	RBinJavaCPTypeObj *obj = NULL;
	
	if (bin->cp_list){
		r_list_foreach_safe(bin->cp_list, iter, iter_tmp, obj){
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
			r_list_delete(bin->cp_list, iter);
		}
		r_list_free(bin->cp_list);
		bin->cp_list = NULL;
	}
}



R_API void r_bin_java_methods_list_free(RBinJavaObj* bin){
	RBinJavaField* method = NULL;
	RListIter *iter=NULL, *iter_tmp = NULL;
	
	if(bin->methods_list){
		// Delete the attr entries
		r_list_foreach_safe(bin->methods_list, iter, iter_tmp, method){
			
			if (method->descriptor)
				free(method->descriptor);
			if (method->name)
				free (method->name);

			if (method->attributes){
				r_bin_java_free_attribute_list(method->attributes);
			}
			method->attributes = NULL;
			free(method);
			r_list_delete(bin->methods_list, iter);
		}
		r_list_free(bin->methods_list);
	} 
	bin->methods_list = NULL;
}

R_API void r_bin_java_interfaces_list_free(RBinJavaObj* bin){
	RBinJavaInterfaceInfo* obj = NULL;
	RListIter *iter=NULL, *iter_tmp = NULL;
	
	if(bin->interfaces_list){
		// Delete the attr entries
		r_list_foreach_safe(bin->interfaces_list, iter, iter_tmp, obj){
			r_bin_java_interface_free(obj);
			r_list_delete(bin->interfaces_list, iter);
		}
		r_list_free(bin->interfaces_list);
	}
	bin->interfaces_list = NULL;
}


R_API void r_bin_java_fields_list_free(RBinJavaObj* bin){
	RBinJavaField* field = NULL;
	RListIter *iter=NULL, *iter_tmp = NULL;
	
	if(bin->fields_list){
		// Delete the attr entries
		r_list_foreach_safe(bin->fields_list, iter, iter_tmp, field){
			
			if (field->descriptor)
				free(field->descriptor);
			if (field->name)
				free (field->name);

			if (field->attributes){
				r_bin_java_free_attribute_list(field->attributes);	
			}
			field->attributes = NULL;
			free(field);
			r_list_delete(bin->fields_list, iter);
		}
		r_list_free(bin->fields_list);
	}
	bin->fields_list = NULL;
}


// Start Free the various attribute types

R_API void r_bin_java_unknown_attr_free(RBinJavaAttrInfo *attr){

	if(attr){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		free(attr);
	}
}


R_API void r_bin_java_local_variable_table_attr_free(RBinJavaAttrInfo *attr){

	RBinJavaLocalVariableAttribute* lvattr = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TABLE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);

		if (attr->info.local_variable_table_attr.local_variable_table){
			// Delete the attr entries
			r_list_foreach_safe(attr->info.local_variable_table_attr.local_variable_table, iter, iter_tmp, lvattr){
				
				if (lvattr->descriptor)
					free(lvattr->descriptor);
				if (lvattr->name)
					free (lvattr->name);

				free(lvattr);
				r_list_delete(attr->info.local_variable_table_attr.local_variable_table, iter);
			}
			r_list_free(attr->info.local_variable_table_attr.local_variable_table);
		}
		attr->info.local_variable_table_attr.local_variable_table = NULL;
		free(attr);
	}

}

R_API void r_bin_java_local_variable_type_table_attr_free(RBinJavaAttrInfo *attr){

	RBinJavaLocalVariableTypeAttribute* lvtattr = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TYPE_TABLE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);

		if (attr->info.local_variable_type_table_attr.local_variable_table){
			// Delete the attr entries
			r_list_foreach_safe(attr->info.local_variable_type_table_attr.local_variable_table, iter, iter_tmp, lvtattr){
				
				if (lvtattr->name)
					free (lvtattr->name);
				if (lvtattr->signature)
					free (lvtattr->signature);

				free(lvtattr);
				r_list_delete(attr->info.local_variable_type_table_attr.local_variable_table, iter);
			}
			r_list_free(attr->info.local_variable_type_table_attr.local_variable_table);
		}
		attr->info.local_variable_type_table_attr.local_variable_table = NULL;
		free(attr);
	}

}

R_API void r_bin_java_deprecated_attr_free(RBinJavaAttrInfo *attr){

	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_DEPRECATED_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		free(attr);
	}
}

R_API void r_bin_java_enclosing_methods_attr_free(RBinJavaAttrInfo *attr){

	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_ENCLOSING_METHOD_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);

		if (attr->info.enclosing_method_attr.class_name){
			free(attr->info.enclosing_method_attr.class_name);
		}
		if (attr->info.enclosing_method_attr.method_name){
			free(attr->info.enclosing_method_attr.method_name);
		}
		if (attr->info.enclosing_method_attr.method_descriptor){
			free(attr->info.enclosing_method_attr.method_descriptor);
		}

		free(attr);
	}
}

R_API void r_bin_java_synthetic_attr_free(RBinJavaAttrInfo *attr){
	
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_SYNTHETIC_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		free(attr);
	}
}

R_API void r_bin_java_constant_value_attr_free(RBinJavaAttrInfo *attr){
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_CONST_VALUE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		free(attr);
	}
}


R_API void r_bin_java_line_number_table_attr_free(RBinJavaAttrInfo *attr){
	RBinJavaLineNumberAttribute *lnattr;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_LINE_NUMBER_TABLE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);

		if (attr->info.line_number_table_attr.line_number_table){
			// Delete the attr entries
			r_list_foreach_safe(attr->info.line_number_table_attr.line_number_table, iter, iter_tmp, lnattr){
				free(lnattr);
				r_list_delete(attr->info.line_number_table_attr.line_number_table, iter);
			}
			r_list_free(attr->info.line_number_table_attr.line_number_table);
		}
		attr->info.line_number_table_attr.line_number_table = NULL;
		free(attr);	
	}
}

R_API void r_bin_java_code_attr_free(RBinJavaAttrInfo *attr){
	RBinJavaExceptionEntry *exc_entry = NULL;
	RBinJavaAttrInfo *_attr;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_CODE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		if (attr->info.code_attr.implicit_frame)
			r_bin_java_stack_frame_free(attr->info.code_attr.implicit_frame);

		if(attr->info.code_attr.exception_table){
			// Delete the attr entries
			r_list_foreach_safe(attr->info.code_attr.exception_table, iter, iter_tmp, exc_entry){
				free(exc_entry);
				r_list_delete(attr->info.code_attr.exception_table, iter);
			}
			r_list_free(attr->info.code_attr.exception_table);
		}
		attr->info.code_attr.exception_table = NULL;
		// Delete the exception_table entries
		if(attr->info.code_attr.attributes){
			r_list_foreach_safe(attr->info.code_attr.attributes, iter, iter_tmp, _attr){
				if(_attr->metas->type_info)
					((RBinJavaAttrMetas *) _attr->metas->type_info)->allocs->delete_obj(_attr);
				r_list_delete(attr->info.code_attr.attributes, iter);
			}
			r_list_free(attr->info.code_attr.attributes);
		}
		attr->info.code_attr.attributes = NULL;
		free(attr);
	}
}

R_API void r_bin_java_exceptions_attr_free(RBinJavaAttrInfo *attr){
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_EXCEPTIONS_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		if (attr->info.exceptions_attr.exception_idx_table)
			free (attr->info.exceptions_attr.exception_idx_table);

		free(attr);
	}
}

R_API void r_bin_java_inner_classes_attr_free(RBinJavaAttrInfo *attr){

	RBinJavaClassesAttribute *icattr;
	RListIter *iter, *iter_tmp=NULL;

	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_INNER_CLASSES_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		
		if(attr->info.inner_classes_attr.classes){
			// Delete the classes entries
			r_list_foreach_safe(attr->info.inner_classes_attr.classes, iter, iter_tmp, icattr){
				if(icattr){
					if(icattr->name) free(icattr->name);
					free(icattr);
				}
				r_list_delete(attr->info.inner_classes_attr.classes, iter);
			}
			r_list_free(attr->info.inner_classes_attr.classes);
		}
		attr->info.inner_classes_attr.classes = NULL;
		free(attr);
	}	
}

R_API void r_bin_java_signature_attr_free(RBinJavaAttrInfo *attr){

	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_SIGNATURE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		if (attr->info.signature_attr.signature)
			free(attr->info.signature_attr.signature);
		free(attr);
	}
}
R_API void r_bin_java_source_debug_attr_free(RBinJavaAttrInfo *attr){
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_SOURCE_DEBUG_EXTENTSION_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		if (attr->info.debug_extensions.debug_extension)
			free(attr->info.debug_extensions.debug_extension);
		attr->info.debug_extensions.debug_extension = NULL;
		free(attr);
	}
}

R_API void r_bin_java_source_code_file_attr_free(RBinJavaAttrInfo *attr){

	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_SOURCE_FILE_ATTR){
		if(attr->name)
			free(attr->name);
		if (attr->metas)
			free(attr->metas);
		free(attr);
	}

}

R_API void r_bin_java_stack_map_table_attr_free(RBinJavaAttrInfo* attr){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RList* ptrList = NULL;
	RBinJavaStackMapFrame *frame = NULL;
	
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_STACK_MAP_TABLE_ATTR){	
		if(attr->name)
			free(attr->name);

		if (attr->metas)
			free(attr->metas);
		
		ptrList = attr->info.stack_map_table_attr.stack_map_frame_entries; 
		if(ptrList){
			r_list_foreach_safe(ptrList, iter, iter_tmp, frame){
				if (frame)
					r_bin_java_stack_frame_free(frame);
				r_list_delete(ptrList, iter);
			}
			r_list_free(ptrList);
		}
		
		ptrList = NULL;
		attr->info.stack_map_table_attr.stack_map_frame_entries = NULL;
		free(attr);
	}
}


R_API void r_bin_java_stack_frame_free(RBinJavaStackMapFrame* obj){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RList* ptrList = NULL;
	RBinJavaVerificationObj *ver_obj = NULL;

	if (obj){
		ptrList = obj->local_items;
		if (obj->metas){
			free(obj->metas);
			obj->metas = NULL;
		} 
		if(ptrList){
			r_list_foreach_safe(ptrList, iter, iter_tmp, ver_obj){
				if (ver_obj)
					r_bin_java_verification_info_free(ver_obj);
				r_list_delete(ptrList, iter);
			}
			r_list_free(ptrList);
		}
		obj->local_items = NULL;

		ptrList = obj->stack_items; 
		if(ptrList){
			r_list_foreach_safe(ptrList, iter, iter_tmp, ver_obj){
				if (ver_obj)
					r_bin_java_verification_info_free(ver_obj);
				r_list_delete(ptrList, iter);
			}
			r_list_free(ptrList);
		}
		obj->stack_items = NULL;
		ptrList = NULL;
		free(obj);
	}
}

R_API void r_bin_java_verification_info_free(RBinJavaVerificationObj* obj){
	if(obj){
		if (obj->name)
			free(obj->name);
		free(obj);
	}
}


R_API void r_bin_java_interface_free(RBinJavaInterfaceInfo *obj){
	if (obj) {
		if (obj->name)
			free(obj->name);
		free(obj);
	}
}


// End Free the various attribute types

// Start the various attibute types new

R_API ut64 r_bin_java_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	if (attr)
		size =  ((RBinJavaAttrMetas *) attr->metas->type_info)->allocs->calc_size(attr);
	return size;
}


R_API ut64 r_bin_java_unknown_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	if (attr){
		size += 6;
	}
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_unknown_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	return r_bin_java_default_attr_new(buffer, sz, buf_offset);
}

R_API ut64 r_bin_java_code_attr_calc_size(RBinJavaAttrInfo *attr){

	RBinJavaExceptionEntry *exc_entry = NULL;
	RBinJavaAttrInfo *_attr = NULL;
	RListIter *iter, *iter_tmp;
	ut64 size = 0;

	if (attr){
		//attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
		size += 6;
		
		//attr->info.code_attr.max_stack = R_BIN_JAVA_USHORT(buffer, 0);
		size += 2;
		
		//attr->info.code_attr.max_locals = R_BIN_JAVA_USHORT(buffer, 2);
		size += 2;
		
		//attr->info.code_attr.code_length = R_BIN_JAVA_UINT(buffer, 4);
		size += 2;

		if (attr->info.code_attr.code){
			size += attr->info.code_attr.code_length;			
		}

		//attr->info.code_attr.exception_table_length =  R_BIN_JAVA_USHORT (buffer, offset);
		size += 2;

		r_list_foreach_safe(attr->info.code_attr.exception_table, iter, iter_tmp, exc_entry){
			//exc_entry->start_pc = R_BIN_JAVA_USHORT(buffer,offset);
			size += 2;

			//exc_entry->end_pc = R_BIN_JAVA_USHORT(buffer,offset);
			size += 2;

			//exc_entry->handler_pc = R_BIN_JAVA_USHORT(buffer,offset);
			size += 2;

			//exc_entry->catch_type = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;
		}
		//attr->info.code_attr.attributes_count = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		if (attr->info.code_attr.attributes_count > 0) {
			r_list_foreach_safe(attr->info.code_attr.attributes, iter, iter_tmp, _attr){
				size += r_bin_java_attr_calc_size(attr);
			}
		}
	}
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_code_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){

	RBinJavaExceptionEntry *exc_entry = NULL;
	RBinJavaAttrInfo *attr = NULL, *_attr = NULL;
	ut32 k = 0, cur_location;
	ut64 offset = 0;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if(attr == NULL)
		return attr;


	attr->type = R_BIN_JAVA_ATTR_TYPE_CODE_ATTR;
	
	//r_buf_read_at (bin->b, offset, (ut8*)buf, 8);

	
	attr->info.code_attr.max_stack = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	
	attr->info.code_attr.max_locals = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	
	attr->info.code_attr.code_length = R_BIN_JAVA_UINT(buffer, offset);
	offset += 4;
	
	attr->info.code_attr.code_offset = buf_offset+offset;

	attr->info.code_attr.code = (ut8* ) malloc(attr->info.code_attr.code_length);

	if (attr->info.code_attr.code == NULL){
		eprintf("Handling Code Attributes: Unable to allocate memory (%u bytes )for a code.\n", attr->info.code_attr.code_length);
		return attr;
	}

	R_BIN_JAVA_GLOBAL_BIN->current_code_attr = attr;

	memset(attr->info.code_attr.code, 0, attr->info.code_attr.code_length);
	//r_buf_read_at (bin->b, bin->b->cur, attr->info.code_attr.code, attr->info.code_attr.code_length); // READ CODE
	
	memcpy(attr->info.code_attr.code, buffer+offset, attr->info.code_attr.code_length);
	offset += attr->info.code_attr.code_length; 

	attr->info.code_attr.exception_table_length =  R_BIN_JAVA_USHORT (buffer, offset);
	offset += 2;

	attr->info.code_attr.exception_table = r_list_new();

	for (k = 0; k < attr->info.code_attr.exception_table_length; k++) {
		cur_location = buf_offset+offset;
		//r_buf_read_at(bin->b, bin->b->cur, (ut8*)buf, 8);
		

		exc_entry = (RBinJavaExceptionEntry *) malloc(sizeof(RBinJavaExceptionEntry));
		if (exc_entry == NULL){
			eprintf("Handling Code Attributes :Unable to allocate memory (%u bytes )for a new exception handler structure.\n", 8);
			break;
		}
		exc_entry->file_offset = cur_location;
		
		exc_entry->start_pc = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;

		exc_entry->end_pc = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;

		exc_entry->handler_pc = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;

		exc_entry->catch_type = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		r_list_append(attr->info.code_attr.exception_table, exc_entry);
		exc_entry->size = 8;
	}
	
	//attr->info.code_attr.attributes_count = (unsigned int)r_bin_java_read_short(bin, bin->b->cur);
	attr->info.code_attr.attributes_count = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	//IFDBG printf("      code Attributes_count: %d\n", attr->info.code_attr.attributes_count);


	attr->info.code_attr.attributes = r_list_new();
	if (attr->info.code_attr.attributes_count > 0) {
		for (k = 0; k < attr->info.code_attr.attributes_count; k++){
			_attr = r_bin_java_read_next_attr_from_buffer(buffer+offset, sz-offset, buf_offset+offset);
			if (_attr){
				offset += _attr->size;
				r_list_append(attr->info.code_attr.attributes, _attr);
			}
			
			if (_attr && _attr->type == R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TABLE_ATTR){
				IFDBG printf("Parsed the LocalVariableTable, preparing the implicit mthod frame.\n");
				IFDBG r_bin_java_print_attr_summary(_attr);
				
				attr->info.code_attr.implicit_frame = r_bin_java_build_stack_frame_from_local_variable_table(R_BIN_JAVA_GLOBAL_BIN, _attr);
				IFDBG r_bin_java_print_stack_map_frame_summary(attr->info.code_attr.implicit_frame);
			}

		}
	}
	if (attr->info.code_attr.implicit_frame == NULL){
		// build a default implicit_frame
		attr->info.code_attr.implicit_frame = r_bin_java_default_stack_frame();
	}

	attr->size = offset;
	return attr;
}



R_API RBinJavaAttrInfo* r_bin_java_constant_value_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo* attr = NULL;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr){	
		attr->type = R_BIN_JAVA_ATTR_TYPE_CONST_VALUE_ATTR;
		attr->info.constant_value_attr.constantvalue_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		attr->size = offset;
	}	
	//IFDBG r_bin_java_print_constant_value_attr_summary(attr);
	return attr;	
}

R_API ut64 r_bin_java_constant_value_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	
	if (attr){
		size = 6;
		size += 2; 
	}
	return size;
}



R_API RBinJavaAttrInfo* r_bin_java_deprecated_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	RBinJavaAttrInfo* attr = NULL;
	ut64 offset = 0;
	
	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_DEPRECATED_ATTR;
		attr->size = offset;	
	}

	//IFDBG r_bin_java_print_deprecated_attr_summary(attr);
	return attr;
}

R_API ut64 r_bin_java_deprecated_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	
	if (attr){
		size = 6;	
	}
	//IFDBG r_bin_java_print_deprecated_attr_summary(attr);
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_signature_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo* attr = NULL;
	
	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf allocation fail
		return attr;
	}
	
	attr->type = R_BIN_JAVA_ATTR_TYPE_SOURCE_FILE_ATTR;
	attr->info.source_file_attr.sourcefile_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	attr->info.signature_attr.signature_idx = R_BIN_JAVA_USHORT(buffer, offset);		
	offset += 2;

	attr->info.signature_attr.signature = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, attr->info.signature_attr.signature_idx);
	
	if (attr->info.signature_attr.signature == NULL)
		eprintf("r_bin_java_signature_attr_new: Unable to resolve the Signature UTF8 String Index: 0x%02x\n", attr->info.signature_attr.signature_idx);


	attr->size = offset;
	//IFDBG r_bin_java_print_source_code_file_attr_summary(attr);
	return attr;
}

R_API ut64 r_bin_java_signature_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	if (attr == NULL){
		// TODO eprintf allocation fail
		return size;
	}
	size += 6;
	//attr->info.source_file_attr.sourcefile_idx = R_BIN_JAVA_USHORT(buffer, offset);
	size += 2;

	//attr->info.signature_attr.signature_idx = R_BIN_JAVA_USHORT(buffer, offset);		
	size += 2;

	return size;
}

R_API RBinJavaAttrInfo* r_bin_java_enclosing_methods_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo* attr = NULL;


	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf
		return attr;
	}

	attr->type = R_BIN_JAVA_ATTR_TYPE_ENCLOSING_METHOD_ATTR;
	
	attr->info.enclosing_method_attr.class_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	attr->info.enclosing_method_attr.method_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	
	attr->info.enclosing_method_attr.class_name = r_bin_java_get_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, attr->info.enclosing_method_attr.class_idx);
	if (attr->info.enclosing_method_attr.class_name == NULL)
		eprintf("Could not resolve enclosing class name for the enclosed method.\n");
	
	attr->info.enclosing_method_attr.method_name = r_bin_java_get_name_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, attr->info.enclosing_method_attr.method_idx);
	if (attr->info.enclosing_method_attr.class_name == NULL)
		eprintf("Could not resolve method descriptor for the enclosed method.\n");

	attr->info.enclosing_method_attr.method_descriptor = r_bin_java_get_desc_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, attr->info.enclosing_method_attr.method_idx); 
	if (attr->info.enclosing_method_attr.method_name == NULL)
		eprintf("Could not resolve method name for the enclosed method.\n");

	attr->size = offset;
	return attr;
}

R_API ut64 r_bin_java_enclosing_methods_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	if (attr){
		size += 6;

		//attr->info.enclosing_method_attr.class_idx = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;

		//attr->info.enclosing_method_attr.method_idx = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
	}
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_exceptions_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0, offset = 0;
	RBinJavaAttrInfo* attr = NULL;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf 
		return attr;
	}

	attr->type = R_BIN_JAVA_ATTR_TYPE_LINE_NUMBER_TABLE_ATTR;

	attr->info.exceptions_attr.number_of_exceptions = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	attr->info.exceptions_attr.exception_idx_table = (ut16 *) malloc( sizeof(ut16)* attr->info.exceptions_attr.number_of_exceptions);

	for (i = 0; i < attr->info.exceptions_attr.number_of_exceptions; i++){
		attr->info.exceptions_attr.exception_idx_table[i] = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
	}
	attr->size = offset;
	//IFDBG r_bin_java_print_exceptions_attr_summary(attr);
	return attr;
}

R_API ut64 r_bin_java_exceptions_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0, i = 0;
	if (attr){
		size += 6;
		for (i = 0; i < attr->info.exceptions_attr.number_of_exceptions; i++){
			//attr->info.exceptions_attr.exception_idx_table[i] = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;
		}

	}
	return size;
}



R_API RBinJavaAttrInfo* r_bin_java_inner_classes_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){

	RBinJavaClassesAttribute *icattr;
	RBinJavaAttrInfo *attr = NULL;

	ut32 i = 0;
	ut64 offset = 0, cur_location;
	
	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf
		return attr;
	}

	attr->type = R_BIN_JAVA_ATTR_TYPE_INNER_CLASSES_ATTR;
	
	attr->info.inner_classes_attr.number_of_classes = R_BIN_JAVA_USHORT(buffer, offset);
	attr->info.inner_classes_attr.classes = r_list_new();
	
	for(i = 0; i < attr->info.inner_classes_attr.number_of_classes; i++){
		cur_location = buf_offset + offset;
		icattr = (RBinJavaClassesAttribute*) malloc(sizeof(RBinJavaClassesAttribute));
		if (icattr){
			memset(icattr, 0, sizeof(RBinJavaClassesAttribute));
		}else{
			eprintf("Handling Inner Classes Attributes :Unable to allocate memory (%lu bytes )for a new exception handler structure.\n", sizeof(RBinJavaLocalVariableAttribute));
			break;
		}

		icattr->inner_class_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		icattr->outer_class_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		icattr->inner_name_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		icattr->inner_class_access_flags = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2; 

		icattr->file_offset = cur_location;
		icattr->size = 8;

		icattr->name = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, icattr->inner_name_idx);
		if(icattr->name == NULL){
			icattr->name = r_str_dup (NULL, "NULL");
			eprintf("r_bin_java_inner_classes_attr: Unable to find the name for %d index.\n", icattr->inner_name_idx);
		}
		
		r_list_append(attr->info.inner_classes_attr.classes, (void *) icattr);

	}
	attr->size = offset;
	//IFDBG r_bin_java_print_inner_classes_attr_summary(attr);
	return attr;
}

R_API ut64 r_bin_java_inner_class_attr_calc_size(RBinJavaClassesAttribute *icattr){
	ut64 size = 0;

	if (icattr){
			
		//icattr->inner_class_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;

		//icattr->outer_class_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		
		//icattr->inner_name_idx = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;

		//icattr->inner_class_access_flags = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2; 
	
	}
	return size;
}

R_API ut64 r_bin_java_inner_classes_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	RListIter *iter, *iter_tmp;
	RBinJavaClassesAttribute *icattr = NULL;

	if (attr == NULL)
		return size;

	size += 6;
	r_list_foreach_safe(attr->info.inner_classes_attr.classes, iter, iter_tmp, icattr){
		size += r_bin_java_inner_class_attr_calc_size(icattr);
	}
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_line_number_table_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	RBinJavaLineNumberAttribute *lnattr;
	RBinJavaAttrInfo *attr = NULL;
	ut32 i = 0;
	ut64 cur_location, offset = 0;
	
	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO printf
		return attr;
	}
	
	attr->type = R_BIN_JAVA_ATTR_TYPE_LINE_NUMBER_TABLE_ATTR;
	attr->info.line_number_table_attr.line_number_table_length = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	attr->info.line_number_table_attr.line_number_table = r_list_new();

	for(i = 0; i < attr->info.line_number_table_attr.line_number_table_length; i++){
		cur_location = buf_offset+offset;
		lnattr = (RBinJavaLineNumberAttribute*) malloc(sizeof(RBinJavaLineNumberAttribute));
		if (lnattr){
			memset(lnattr, 0, sizeof(RBinJavaLineNumberAttribute));
		}else{
			eprintf("Handling Local Variable Table Attributes :Unable to allocate memory (%lu bytes) for a new exception handler structure.\n", sizeof(RBinJavaLocalVariableAttribute));
			break;
		}

		lnattr->start_pc = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		lnattr->line_number = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		lnattr->file_offset = cur_location;
		lnattr->size = 4;

		r_list_append(attr->info.line_number_table_attr.line_number_table, lnattr);

	}
	attr->size = offset;
	//IFDBG r_bin_java_print_line_number_table_attr_summary(attr);
	return attr;
}

R_API ut64 r_bin_java_line_number_table_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	RBinJavaLineNumberAttribute *lnattr;
	RListIter *iter, *iter_tmp;

	if (attr == NULL)
		return size;

	size += 6;
	r_list_foreach_safe(attr->info.line_number_table_attr.line_number_table, iter, iter_tmp, lnattr){
		//lnattr->start_pc = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		
		//lnattr->line_number = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
	}
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_source_debug_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo *attr = NULL;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf bad allocation
		return attr;
	}

	attr->type = R_BIN_JAVA_ATTR_TYPE_SOURCE_DEBUG_EXTENTSION_ATTR;
	if (attr->length == 0){
		eprintf("r_bin_java_source_debug_attr_new: Attempting to allocate 0 bytes for debug_extension.\n");
		attr->info.debug_extensions.debug_extension = NULL;
		return attr;	
	}else if ((attr->length+offset) > sz){
		eprintf("r_bin_java_source_debug_attr_new: Expected %d bytes got %lld bytes for debug_extension.\n", attr->length, (offset + sz));
	}
	
	attr->info.debug_extensions.debug_extension = (ut8 *) malloc(attr->length);
	if (attr->info.debug_extensions.debug_extension && (attr->length > (sz-offset)) ) {
		memcpy(attr->info.debug_extensions.debug_extension, buffer+offset, sz-offset);
	}else if (attr->info.debug_extensions.debug_extension) {
		memcpy(attr->info.debug_extensions.debug_extension, buffer+offset, attr->length);
	}else{
		eprintf("r_bin_java_source_debug_attr_new: Unable to allocated the data for the debug_extension.\n");
	}
	
	offset += attr->length;
	attr->size = offset;
	return attr;

}

R_API ut64 r_bin_java_source_debug_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	if (attr == NULL){
		return size;
	}
	size += 6;
	if (attr->info.debug_extensions.debug_extension){
		size += attr->length;
	}
	return size;
}


R_API ut64 r_bin_java_local_variable_table_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	RListIter *iter, *iter_tmp;
	RBinJavaLocalVariableAttribute* lvattr = NULL;

	if (attr == NULL){
		// TODO eprintf
		return size;
	}

	size += 6;

	//attr->info.local_variable_table_attr.table_length = R_BIN_JAVA_USHORT(buffer, offset);
	size += 2;

	r_list_foreach_safe(attr->info.local_variable_table_attr.local_variable_table, iter, iter_tmp, lvattr){
		//lvattr->start_pc = R_BIN_JAVA_USHORT(buffer,offset);
		size += 2;

		//lvattr->length = R_BIN_JAVA_USHORT(buffer,offset);
		size += 2;
		
		//lvattr->name_idx = R_BIN_JAVA_USHORT(buffer,offset);
		size += 2;
		
		//lvattr->descriptor_idx = R_BIN_JAVA_USHORT(buffer,offset);
		size += 2;
		
		//lvattr->index = R_BIN_JAVA_USHORT(buffer,offset);
		size += 2;
	}
	return size;

}


R_API RBinJavaAttrInfo* r_bin_java_local_variable_table_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	RBinJavaAttrInfo *attr = NULL;
	RBinJavaLocalVariableAttribute* lvattr;
	ut64 cur_location = 0, offset = 0;
	

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;
	if (attr == NULL){
		// TODO eprintf
		return attr;
	}

	ut32 i = 0;
	attr->type = R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TABLE_ATTR;

	attr->info.local_variable_table_attr.table_length = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	attr->info.local_variable_table_attr.local_variable_table = r_list_new();
	
	for(i = 0; i < attr->info.local_variable_table_attr.table_length; i++){
		cur_location = buf_offset + offset;

		lvattr = (RBinJavaLocalVariableAttribute*) malloc(sizeof(RBinJavaLocalVariableAttribute));
		if (lvattr){
			memset(lvattr, 0, sizeof(RBinJavaLocalVariableAttribute));
		}else{
			eprintf("Handling Local Variable Table Attributes :Unable to allocate memory (%lu bytes )for a new exception handler structure.\n", sizeof(RBinJavaLocalVariableAttribute));
			break;
		}

		
		lvattr->start_pc = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;

		lvattr->length = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;
		
		lvattr->name_idx = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;
		
		lvattr->descriptor_idx = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;
		
		lvattr->index = R_BIN_JAVA_USHORT(buffer,offset);
		offset += 2;
		
		lvattr->file_offset = cur_location;
		lvattr->name = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, lvattr->name_idx);
		lvattr->size = 10;

		if(lvattr->name == NULL){
			lvattr->name = r_str_dup (NULL, "NULL");
			eprintf("r_bin_java_local_variable_table_attr_new: Unable to find the name for %d index.\n", lvattr->name_idx);
		}

		lvattr->descriptor = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, lvattr->descriptor_idx);
		if(lvattr->descriptor == NULL){
			lvattr->descriptor = r_str_dup (NULL, "NULL");
			eprintf("r_bin_java_local_variable_table_attr_new: Unable to find the descriptor for %d index.\n", lvattr->descriptor_idx);
		}
		

		r_list_append(attr->info.local_variable_table_attr.local_variable_table, lvattr);

	}
	attr->size = offset; 
	//IFDBG r_bin_java_print_local_variable_table_attr_summary(attr);
	return attr;
}

R_API ut64 r_bin_java_local_variable_type_table_attr_calc_size(RBinJavaAttrInfo *attr){
	RBinJavaLocalVariableTypeAttribute* lvattr;
	RListIter *iter, *iter_tmp;
	ut64 size = 0;
		
	if (attr){
		size += 6;

		// attr->info.local_variable_type_table_attr.table_length = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		r_list_foreach_safe(attr->info.local_variable_type_table_attr.local_variable_table, iter, iter_tmp, lvattr){
			//lvattr->start_pc = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;

			//lvattr->length = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;
			
			//lvattr->name_idx = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;
			
			//lvattr->signature_idx = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;
			
			//lvattr->index = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;		
		}

	}
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_local_variable_type_table_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	RBinJavaLocalVariableTypeAttribute* lvattr;
	RBinJavaAttrInfo* attr = NULL;
	ut64 offset = 0;
	ut32 i = 0;
	
	attr = r_bin_java_default_attr_new(buffer, sz, offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf
		return attr;
	}

	attr->type = R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TYPE_TABLE_ATTR;
	

	attr->info.local_variable_type_table_attr.table_length = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	attr->info.local_variable_type_table_attr.local_variable_table = r_list_new();

	
	for(i = 0; i < attr->info.local_variable_type_table_attr.table_length; i++){
		ut64 cur_location = buf_offset + offset;
		lvattr = (RBinJavaLocalVariableTypeAttribute*) malloc(sizeof(RBinJavaLocalVariableTypeAttribute));
		if (lvattr){
			memset(lvattr, 0, sizeof(RBinJavaLocalVariableTypeAttribute));
		}else{
			eprintf("Handling Local Variable Table Attributes :Unable to allocate memory (%lu bytes )for a new exception handler structure.\n", sizeof(RBinJavaLocalVariableAttribute));
			break;
		}

		
		lvattr->start_pc = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		lvattr->length = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		lvattr->name_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		lvattr->signature_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		lvattr->index = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		lvattr->file_offset = cur_location;
		lvattr->name = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, lvattr->name_idx);
		lvattr->size = 10;

		if(lvattr->name == NULL){
			lvattr->name = r_str_dup (NULL, "NULL");
			eprintf("r_bin_java_local_variable_type_table_attr_new: Unable to find the name for %d index.\n", lvattr->name_idx);
		}

		lvattr->signature = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, lvattr->signature_idx);
		if(lvattr->signature == NULL){
			lvattr->signature = r_str_dup (NULL, "NULL");
			eprintf("r_bin_java_local_variable_type_table_attr_new: Unable to find the descriptor for %d index.\n", lvattr->signature_idx);
		}
		

		r_list_append(attr->info.local_variable_type_table_attr.local_variable_table, lvattr);

	}
	//IFDBG r_bin_java_print_local_variable_type_table_attr_summary(attr);
	attr->size = offset;
	return attr;
}

R_API RBinJavaAttrInfo* r_bin_java_source_code_file_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo* attr = NULL;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if (attr == NULL){
		// TODO eprintf allocation fail
		return attr;
	}
	attr->type = R_BIN_JAVA_ATTR_TYPE_SOURCE_FILE_ATTR;
	attr->info.source_file_attr.sourcefile_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	attr->size = offset;
	//IFDBG r_bin_java_print_source_code_file_attr_summary(attr);
	return attr;

}

R_API ut64 r_bin_java_source_code_file_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	if (attr == NULL){
		// TODO eprintf allocation fail
		return size;
	}
	size += (6 + 2);
	return size;
}


R_API RBinJavaAttrInfo* r_bin_java_synthetic_attr_new(ut8 *buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo* attr = NULL;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	attr->type = R_BIN_JAVA_ATTR_TYPE_SYNTHETIC_ATTR;
	attr->size = offset;
	return attr;
}

R_API ut64 r_bin_java_synthetic_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 6;
	if (attr == NULL){
		// TODO eprintf allocation fail
		return size;
	}
	size += 6;
	return size;
}


R_API RBinJavaInterfaceInfo* r_bin_java_interface_new(RBinJavaObj *bin, ut8 *buffer, ut64 sz){
	RBinJavaInterfaceInfo *interface_obj = NULL;

	interface_obj = (RBinJavaInterfaceInfo *) malloc(sizeof(RBinJavaInterfaceInfo));
	

	if(interface_obj == NULL){
		eprintf ("Unable to allocate memory for RBinJavaInterfaceInfo.\n");
		return interface_obj;
	}


	memset(interface_obj, 0, sizeof(RBinJavaInterfaceInfo));

	if (buffer){
		interface_obj->class_info_idx = R_BIN_JAVA_USHORT(buffer, 0);
	
		interface_obj->cp_class = r_bin_java_get_item_from_bin_cp_list(bin, interface_obj->class_info_idx);
		if (interface_obj->cp_class){
			interface_obj->name = r_bin_java_get_item_name_from_bin_cp_list(bin, interface_obj->cp_class);
		}else{
			interface_obj->name = r_str_dup(NULL, "NULL");
		}
	}else{
		interface_obj->class_info_idx = 0xffff;
		interface_obj->name = r_str_dup(NULL, "NULL");
	}
	return interface_obj;

}


R_API RBinJavaVerificationObj* r_bin_java_verification_info_from_type(RBinJavaObj *bin, R_BIN_JAVA_STACKMAP_TYPE type, ut32 value){
	RBinJavaVerificationObj *stack_element = (RBinJavaVerificationObj *) malloc(sizeof(RBinJavaVerificationObj));
	if (stack_element == NULL)
		return NULL;
	
	memset(stack_element, 0, sizeof(RBinJavaVerificationObj));

	stack_element->tag = type;
	if (stack_element->tag == R_BIN_JAVA_STACKMAP_OBJECT){
		stack_element->info.obj_val_cp_idx = (ut16) value; 		
	}
	else if (stack_element->tag == R_BIN_JAVA_STACKMAP_UNINIT){
		/*if (bin->offset_sz == 4){
			stack_element->info.uninit_offset = value;
		}else{
			stack_element->info.uninit_offset = (ut16) value;
		}*/	
		stack_element->info.uninit_offset = (ut16) value;
	}
	return stack_element;

}

R_API RBinJavaVerificationObj* r_bin_java_read_from_buffer_verification_info_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	
	ut64 offset = 0;
	RBinJavaVerificationObj *stack_element = (RBinJavaVerificationObj *) malloc(sizeof(RBinJavaVerificationObj));


	if (stack_element == NULL){
		// eprintf error here
		return stack_element;
	}

	
	memset(stack_element, 0, sizeof(RBinJavaVerificationObj));
	stack_element->file_offset = buf_offset;

	/*if (sz == 0){
		eprintf("rbin_java_read_next_verification_info: Failed to read bytes for tag.\n");
		//r_bin_java_verification_info_free(stack_element);
		//return NULL;
	}*/

	stack_element->tag = buffer[offset];
	offset += 1;

	if (stack_element->tag == R_BIN_JAVA_STACKMAP_OBJECT){
		
		/*if( (offset + 2) <= sz){		
			stack_element->info.obj_val_cp_idx = R_BIN_JAVA_USHORT(buffer, offset);
			offset += 2;
		}else{
			eprintf("rbin_java_read_next_verification_info: Failed to read bytes for StackMapTable R_BIN_JAVA_STACKMAP_OBJECT Object.\n");
			//r_bin_java_verification_info_free(stack_element);
			//return stack_element;			
		}*/
		stack_element->info.obj_val_cp_idx = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

	}
	else if (stack_element->tag == R_BIN_JAVA_STACKMAP_UNINIT){
		/*if( (offset + 2) <= sz){		
			stack_element->info.uninit_offset = R_BIN_JAVA_USHORT(buffer, offset);
			offset += 2;
		}else{
			eprintf("rbin_java_read_next_verification_info: Failed to read bytes for StackMapTable R_BIN_JAVA_STACKMAP_UNINIT Object.\n");
			//r_bin_java_verification_info_free(stack_element);
			//return stack_element;			
		}*/
		stack_element->info.uninit_offset = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

	}

	if (R_BIN_JAVA_STACKMAP_UNINIT < stack_element->tag){
		eprintf("rbin_java_read_next_verification_info: Unknown Tag: 0x%02x\n", stack_element->tag);
	}
	
	stack_element->size = offset;

	return stack_element;
}

R_API ut64 rbin_java_verification_info_calc_size(RBinJavaVerificationObj* stack_element){
	ut64 sz = 0;
	if (stack_element == NULL){
		// eprintf error here
		return sz;
	}

	// r_buf_read_at (bin->b, offset, (ut8*)(&stack_element->tag), 1)
	sz += 1;
	if (stack_element->tag == R_BIN_JAVA_STACKMAP_OBJECT){
		//r_buf_read_at (bin->b, offset+1, (ut8*)buf, 2)
		sz += 2;
	}
	else if (stack_element->tag == R_BIN_JAVA_STACKMAP_UNINIT){
		//r_buf_read_at (bin->b, offset+1, (ut8*)buf, 2)
		sz += 2;
	}

	return sz;
}





R_API RBinJavaStackMapFrameMetas* r_bin_java_determine_stack_frame_type(ut8 tag){
	ut8 type_value = 0;
	
	if (tag < 64)
		type_value = R_BIN_JAVA_STACK_FRAME_SAME;
	else if (63 < tag && tag < 128)
		type_value = R_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1;
	else if (247 < tag && tag < 251)
		type_value = R_BIN_JAVA_STACK_FRAME_CHOP;
	else if (tag == 251)
		type_value = R_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED;
	else if (251 < tag && tag < 255)
		type_value = R_BIN_JAVA_STACK_FRAME_APPEND;	
	else if (tag == 255)
		type_value = R_BIN_JAVA_STACK_FRAME_FULL_FRAME;
	else
		type_value = R_BIN_JAVA_STACK_FRAME_RESERVED;
	
	return &R_BIN_JAVA_STACK_MAP_FRAME_METAS[type_value];
	
}


void copy_type_info_to_stack_frame_list(RList *type_list, RList *sf_list){
	RListIter *iter, *iter_tmp;
	RBinJavaVerificationObj *ver_obj, *new_ver_obj;
	if (type_list == NULL)
		return;
	if (sf_list == NULL)
		return;

	r_list_foreach_safe(type_list, iter, iter_tmp, ver_obj){
		new_ver_obj = (RBinJavaVerificationObj *) malloc(sizeof(RBinJavaVerificationObj));
		// FIXME: how to handle failed memory allocation?
		if(ver_obj){
			memcpy(new_ver_obj, ver_obj, sizeof(RBinJavaVerificationObj));
			r_list_append(sf_list, (void *) new_ver_obj);
		}
	}

}
void copy_type_info_to_stack_frame_list_up_to_idx(RList *type_list, RList *sf_list, ut64 idx){
	RListIter *iter, *iter_tmp;
	RBinJavaVerificationObj *ver_obj, *new_ver_obj;
	ut32 pos = 0;
	if (type_list == NULL)
		return;
	if (sf_list == NULL)
		return;

	r_list_foreach_safe(type_list, iter, iter_tmp, ver_obj){
		new_ver_obj = (RBinJavaVerificationObj *) malloc(sizeof(RBinJavaVerificationObj));
		// FIXME: how to handle failed memory allocation?
		if(ver_obj){
			memcpy(new_ver_obj, ver_obj, sizeof(RBinJavaVerificationObj));
			r_list_append(sf_list, (void *) new_ver_obj);
		}
		pos++;
		if (pos == idx){
			break;
		}
		

	}	
}

R_API ut64 r_bin_java_stack_map_frame_calc_size(RBinJavaStackMapFrame *stack_frame){
	ut64 size = 0;
	RListIter *iter, *iter_tmp;
	RBinJavaVerificationObj *stack_element;
	if (stack_frame){
		//stack_frame->tag = buffer[offset];
		size += 1;
		if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_SAME){
			// Nothing to read
		}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1){
			
			r_list_foreach_safe(stack_frame->stack_items, iter, iter_tmp, stack_element){
				size += rbin_java_verification_info_calc_size(stack_element);
			}

		}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_CHOP){

			//stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;

		}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED){
			
			//stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;

			r_list_foreach_safe(stack_frame->stack_items, iter, iter_tmp, stack_element){
				size += rbin_java_verification_info_calc_size(stack_element);
			}


		}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_APPEND){
			//stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2 ;
			
			r_list_foreach_safe(stack_frame->stack_items, iter, iter_tmp, stack_element){
				size += rbin_java_verification_info_calc_size(stack_element);
			}

		}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_FULL_FRAME){		

			//stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2; 
			
			//stack_frame->number_of_locals = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2; 

			r_list_foreach_safe(stack_frame->local_items, iter, iter_tmp, stack_element){
				size += rbin_java_verification_info_calc_size(stack_element);
			}

			//stack_frame->number_of_stack_items = R_BIN_JAVA_USHORT(buffer, offset);
			size += 2;
			
			r_list_foreach_safe(stack_frame->stack_items, iter, iter_tmp, stack_element){
				size += rbin_java_verification_info_calc_size(stack_element);
			}
		}
	}
	return size;
} 


R_API RBinJavaStackMapFrame* r_bin_java_stack_map_frame_new (ut8* buffer, ut64 sz, RBinJavaStackMapFrame *p_frame, ut64 buf_offset){
	RBinJavaStackMapFrame *stack_frame = r_bin_java_default_stack_frame();
	RBinJavaVerificationObj *stack_element;
	ut64 offset = 0;
	int i = 0;

	
	if(stack_frame == NULL){
		// TODO eprintf
		return stack_frame;
	}


	stack_frame->tag = buffer[offset];
	offset += 1;

	stack_frame->metas->type_info = (void *)  r_bin_java_determine_stack_frame_type(stack_frame->tag);
	stack_frame->type = ((RBinJavaStackMapFrameMetas *) stack_frame->metas->type_info)->type;

	stack_frame->local_items = r_list_new();
	stack_frame->stack_items = r_list_new();
	stack_frame->file_offset = buf_offset;
	stack_frame->p_stack_frame = p_frame;
	
	if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_SAME){
		// Maybe?  1. Copy the previous frames locals and set the locals count.
		//copy_type_info_to_stack_frame_list_up_to_idx(p_frame->local_items, stack_frame->local_items, idx);
		stack_frame->number_of_locals = p_frame->number_of_locals;
		eprintf("r_bin_java_stack_map_frame_new: TODO Stack Frame Same Locals Condition is untested, so there may be issues.\n");

	}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_SAME_LOCALS_1){
		// 1. Read the stack type
		stack_frame->number_of_stack_items = 1;
		stack_element = r_bin_java_read_from_buffer_verification_info_new(buffer+offset, sz-offset, buf_offset+offset);

		if (stack_element){
			offset += stack_element->size;
		}else{
			eprintf("r_bin_java_stack_map_frame_new: Unable to parse the Stack Items for the stack frame.\n");
			r_bin_java_stack_frame_free(stack_frame);
			return NULL;
		}
		
		r_list_append(stack_frame->stack_items, (void *) stack_element);
		// Maybe?  3. Copy the previous frames locals and set the locals count.
		//copy_type_info_to_stack_frame_list_up_to_idx(p_frame->local_items, stack_frame->local_items, idx);
		stack_frame->number_of_locals = p_frame->number_of_locals;
		eprintf("r_bin_java_stack_map_frame_new: TODO Stack Frame Same Locals 1 Stack Element Condition is untested, so there may be issues.\n");

	}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_CHOP){

		// 1. Calculate the max index we want to copy from the list of the 
		//    previous frames locals 
		ut16 k = 251 - stack_frame->tag;/*,
		     idx = p_frame->number_of_locals - k;
		*/
		// 2.  read the uoffset value
		
		stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		// Maybe? 3. Copy the previous frames locals and set the locals count.
		//copy_type_info_to_stack_frame_list_up_to_idx(p_frame->local_items, stack_frame->local_items, idx);
		stack_frame->number_of_locals = p_frame->number_of_locals;
		eprintf("r_bin_java_stack_map_frame_new: TODO Stack Frame Chop Condition is untested, so there may be issues.\n");

	}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_SAME_FRAME_EXTENDED){
		
		// 1. Read the uoffset		
		stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		// 2. Read the stack element type
		stack_frame->number_of_stack_items = 1;
		stack_element = r_bin_java_read_from_buffer_verification_info_new(buffer+offset, sz-offset, buf_offset+offset);
		
		if(stack_element){
			offset += stack_element->size;
		}else{
			eprintf("r_bin_java_stack_map_frame_new: Unable to parse the Stack Items for the stack frame.\n");
			r_bin_java_stack_frame_free(stack_frame);
			return NULL;
		}
		r_list_append(stack_frame->stack_items, (void *) stack_element);
		
		// Maybe? 3. Copy the previous frames locals to the current locals
		//copy_type_info_to_stack_frame_list_up_to_idx(p_frame->local_items, stack_frame->local_items, idx);
		stack_frame->number_of_locals = p_frame->number_of_locals;
		eprintf("r_bin_java_stack_map_frame_new: TODO Stack Frame Same Locals Frame Stack 1 Extended Condition is untested, so there may be issues.\n");


	}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_APPEND){
		// 1. Calculate the max index we want to copy from the list of the 
		//    previous frames locals 
		ut16 k = stack_frame->tag - 251,
		     i = 0;

		// 2. Read the uoffset		
		stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		
		// Maybe? 3. Copy the previous frames locals to the current locals
		//copy_type_info_to_stack_frame_list_up_to_idx(p_frame->local_items, stack_frame->local_items, idx);
		
		// 4. Read off the rest of the appended locals types
		for (i=0; i < k; i++){
			stack_element = r_bin_java_read_from_buffer_verification_info_new(buffer+offset, sz-offset, buf_offset+offset);

			if (stack_element){
				offset += stack_element->size;
			}else{
				eprintf("r_bin_java_stack_map_frame_new: Unable to parse the locals for the stack frame.\n");
				r_bin_java_stack_frame_free(stack_frame);
				return NULL;
			}
			r_list_append(stack_frame->local_items, (void *) stack_element);
					
		}
		stack_frame->number_of_locals = p_frame->number_of_locals + k;

		
		eprintf("r_bin_java_stack_map_frame_new: TODO Stack Frame Same Locals Frame Stack 1 Extended Condition is untested, so there may be issues.\n");

	}else if(stack_frame->type == R_BIN_JAVA_STACK_FRAME_FULL_FRAME){		

		stack_frame->offset_delta = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		//IFDBG printf("r_bin_java_stack_map_frame_new: Code Size > 65535, read( %d bytes), offset = 0x%08x.\n", var_sz, stack_frame->offset_delta);
		
		// Read the number of variables based on the max # local variable
		stack_frame->number_of_locals = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		//IFDBG printf("r_bin_java_stack_map_frame_new: Max ulocalvar > 65535, read( %d bytes), number_of_locals = 0x%08x.\n", var_sz, stack_frame->number_of_locals);
		
		IFDBG r_bin_java_print_stack_map_frame_summary(stack_frame);
		// read the number of locals off the stack
		for (i = 0; i < stack_frame->number_of_locals; i++){
			stack_element = r_bin_java_read_from_buffer_verification_info_new(buffer+offset, sz-offset, buf_offset+offset);

			if (stack_element){
				offset += stack_element->size;
				//r_list_append(stack_frame->local_items, (void *) stack_element);
			}else{
				eprintf("r_bin_java_stack_map_frame_new: Unable to parse the locals for the stack frame.\n");
				r_bin_java_stack_frame_free(stack_frame);
				return NULL;
			}
			r_list_append(stack_frame->local_items, (void *) stack_element);
		}

		// Read the number of stack items based on the max size of stack
		stack_frame->number_of_stack_items = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		//IFDBG printf("r_bin_java_stack_map_frame_new: Max ustack items > 65535, read( %d bytes), number_of_locals = 0x%08x.\n", var_sz, stack_frame->number_of_stack_items);

		// read the stack items 
		for (i = 0; i < stack_frame->number_of_stack_items; i++){
			stack_element = r_bin_java_read_from_buffer_verification_info_new(buffer+offset, sz-offset, buf_offset+offset);
			if(stack_element){
				offset += stack_element->size;
			//	r_list_append(stack_frame->stack_items, (void *) stack_element);
			}else{
				eprintf("r_bin_java_stack_map_frame_new: Unable to parse the the stack items for the stack frame.\n");
				r_bin_java_stack_frame_free(stack_frame);
				return NULL;
			}
			r_list_append(stack_frame->local_items, (void *) stack_element);

		}
	}
	//IFDBG printf("Created a stack frame at offset(0x%llx) of size: %d\n", buf_offset, stack_frame->size);//r_bin_java_print_stack_map_frame_summary(stack_frame);
	stack_frame->size = offset;
	//IFDBG r_bin_java_print_stack_map_frame_summary(stack_frame);
	return stack_frame;		

}

ut16 r_bin_java_find_cp_class_ref_from_name_idx(RBinJavaObj *bin, ut16 name_idx){
	ut16 pos, len = (ut16) r_list_length(bin->cp_list);
	RBinJavaCPTypeObj *item;
	
	for (pos = 0; pos < len; pos++){
		item = (RBinJavaCPTypeObj *) r_list_get_n(bin->cp_list, pos);
		if (item && item->tag == R_BIN_JAVA_CP_CLASS && item->info.cp_class.name_idx == name_idx)
			break;
	}

	return pos;

}

R_API RBinJavaStackMapFrame* r_bin_java_default_stack_frame(){

	RBinJavaStackMapFrame* stack_frame = (RBinJavaStackMapFrame *) malloc(sizeof(RBinJavaStackMapFrame));
	if(stack_frame == NULL)
		return stack_frame;

	memset(stack_frame, 0, sizeof(RBinJavaStackMapFrame));
	stack_frame->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
	
	if(stack_frame->metas == NULL){
		free(stack_frame);
		return NULL;
	}
	memset(stack_frame->metas, 0, sizeof(RBinJavaMetaInfo));

	stack_frame->metas->type_info = (void *)  &R_BIN_JAVA_STACK_MAP_FRAME_METAS[R_BIN_JAVA_STACK_FRAME_IMPLICIT];
	stack_frame->type = ((RBinJavaStackMapFrameMetas *) stack_frame->metas->type_info)->type;
	
	stack_frame->local_items = r_list_new();
	stack_frame->stack_items = r_list_new();
	
	stack_frame->number_of_stack_items = 0;
	stack_frame->number_of_locals = 0;
	
	return stack_frame;
}

R_API RBinJavaStackMapFrame* r_bin_java_build_stack_frame_from_local_variable_table(RBinJavaObj *bin, RBinJavaAttrInfo *attr){
	RBinJavaStackMapFrame *stack_frame = r_bin_java_default_stack_frame();
	RBinJavaLocalVariableAttribute *lvattr = NULL;
	RBinJavaVerificationObj *type_item;
	RListIter *iter = NULL, *iter_tmp = NULL;
	ut32 value_cnt = 0;

	if (bin == NULL || attr == NULL || attr->type != R_BIN_JAVA_ATTR_TYPE_LOCAL_VARIABLE_TABLE_ATTR){
		eprintf("Attempting to create a stack_map frame from a bad attribute.\n");
		return stack_frame;
	}

	if(stack_frame == NULL)
		return stack_frame;


	stack_frame->number_of_locals = attr->info.local_variable_table_attr.table_length;

	r_list_foreach_safe(attr->info.local_variable_table_attr.local_variable_table, iter, iter_tmp, lvattr){
		ut32 pos = 0;
		ut8 value = 'N';
		if ( lvattr == NULL)
			continue;

		// knock the array Types
		while (lvattr->descriptor[pos] == '['){ 
			pos ++;
		}
		value = lvattr->descriptor[pos];
		//IFDBG printf("Found the following type value: %c at pos %d in %s\n", value, pos, lvattr->descriptor);


		if (value == 'I'){
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_INTEGER, 0);
		}else if (value == 'F'){
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_FLOAT, 0);
		}else if (value == 'D'){
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_DOUBLE, 0);
		}else if (value == 'J'){
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_LONG, 0);
		}else if (value == 'L'){
			// TODO: FIXME write something that will iterate over the CP Pool and find the 
			// CONSTANT_Class_info referencing this
			ut16 idx = r_bin_java_find_cp_class_ref_from_name_idx(bin, lvattr->name_idx);
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_OBJECT, idx);
		}else{
			eprintf("r_bin_java_build_stack_frame_from_local_variable_table: not sure how to handle: name: %s, type: %s\n", lvattr->name, lvattr->descriptor);
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_NULL, 0);
		}
		/*else if (strcmp("", "") == 0){
			type_item = r_bin_java_verification_info_from_type(bin, R_BIN_JAVA_STACKMAP_DOUBLE, 0);
		}*/
		if (type_item)
			r_list_append(stack_frame->local_items, (void *)type_item);
		value_cnt++;
	}
	if (value_cnt != attr->info.local_variable_table_attr.table_length){
		IFDBG eprintf("r_bin_java_build_stack_frame_from_local_variable_table: Number of locals not accurate.  Expected %d but got %d", attr->info.local_variable_table_attr.table_length, value_cnt);
	}
	return stack_frame;

}

R_API ut64 r_bin_java_stack_map_table_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	RListIter *iter, *iter_tmp;
	RBinJavaStackMapFrame *stack_frame = NULL;
	if (attr){
		//attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
		size += 6;
		
		if (attr == NULL){
			// TODO eprintf
			return size;
		}

		//IFDBG r_bin_java_print_source_code_file_attr_summary(attr);
		// Current spec does not call for variable sizes.

		//attr->info.stack_map_table_attr.number_of_entries = R_BIN_JAVA_USHORT(buffer, offset);
		size +=  2;
		r_list_foreach_safe(attr->info.stack_map_table_attr.stack_map_frame_entries, iter, iter_tmp, stack_frame){
			size += r_bin_java_stack_map_frame_calc_size(stack_frame);
		}		

	}
	return size;

} 

R_API RBinJavaAttrInfo* r_bin_java_stack_map_table_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	ut64 offset = 0;
	RBinJavaStackMapFrame *stack_frame = NULL, *new_stack_frame = NULL;
	
	RBinJavaAttrInfo *attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;
	
	if (attr == NULL){
		// TODO eprintf
		return attr;
	}

	attr->info.stack_map_table_attr.stack_map_frame_entries = r_list_new();
	//IFDBG r_bin_java_print_source_code_file_attr_summary(attr);
	// Current spec does not call for variable sizes.

	attr->info.stack_map_table_attr.number_of_entries = R_BIN_JAVA_USHORT(buffer, offset);
	offset +=  2;
	
	//IFDBG r_bin_java_print_stack_map_table_attr_summary(attr);
	
	
	for(i=0; i < attr->info.stack_map_table_attr.number_of_entries; i++){
		// read next stack frame
 		//IFDBG printf("Reading StackMap Entry #%d @ 0x%llx\n", i, buf_offset+offset);
		if (stack_frame == NULL && R_BIN_JAVA_GLOBAL_BIN && R_BIN_JAVA_GLOBAL_BIN->current_code_attr)
			stack_frame = R_BIN_JAVA_GLOBAL_BIN->current_code_attr->info.code_attr.implicit_frame;
		
		new_stack_frame = r_bin_java_stack_map_frame_new(buffer+offset, sz-offset, stack_frame, buf_offset+offset);
		
		if (new_stack_frame){
			offset += new_stack_frame->size;
			// append stack frame to the list
			r_list_append(attr->info.stack_map_table_attr.stack_map_frame_entries, (void *) new_stack_frame);
			stack_frame = new_stack_frame;

		}else{
			eprintf("r_bin_java_stack_map_table_attr_new: Unable to parse the the stack the stack frame for the stack map table.\n");
			r_bin_java_stack_map_table_attr_free(attr);
			attr = NULL;
			break;
		}

	}

	if (attr)
		attr->size = offset;
	
	return attr;
}


// End attribute types new


// Start new Constant Pool Types

R_API RBinJavaCPTypeObj* r_bin_java_do_nothing_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	return (RBinJavaCPTypeObj *)NULL;
}

R_API ut64 r_bin_java_do_nothing_calc_size(RBinJavaCPTypeObj *obj){
	return 0;
}


R_API void r_bin_java_do_nothing_free(RBinJavaCPTypeObj *obj){
	return ;
}

R_API RBinJavaCPTypeObj* r_bin_java_unknown_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){

	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	
	obj = (RBinJavaCPTypeObj*) malloc(sizeof(RBinJavaCPTypeObj));	                        
	
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[R_BIN_JAVA_CP_UNKNOWN];
		
	}

	return obj;
}
R_API ut64 r_bin_java_unknown_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	size += 1; 
	return size;
} 

R_API RBinJavaCPTypeObj* r_bin_java_class_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;

	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_CLASS, tag, sz, "Class" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj*) malloc(sizeof(RBinJavaCPTypeObj));	                        
	
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];

		obj->info.cp_class.name_idx = R_BIN_JAVA_USHORT (buffer, 1);
		
	}
	

	return obj;
}
R_API ut64 r_bin_java_class_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	//ut8 tag = buffer[0];
	size += 1;
	//obj->info.cp_class.name_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 2;
	return size;
}




R_API RBinJavaCPTypeObj* r_bin_java_fieldref_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;

	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_FIELDREF, tag, sz, "FieldRef" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj*) malloc(sizeof(RBinJavaCPTypeObj));	                        
	
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
			
		obj->info.cp_field.class_idx = R_BIN_JAVA_USHORT (buffer, 1);
		obj->info.cp_field.name_and_type_idx = R_BIN_JAVA_USHORT (buffer, 3);
		
		
	}
	return (RBinJavaCPTypeObj*) obj;
}

R_API ut64 r_bin_java_fieldref_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_field.class_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 2;
	//obj->info.cp_field.name_and_type_idx = R_BIN_JAVA_USHORT (buffer, 3);
	size += 2;
	return size;
}


R_API RBinJavaCPTypeObj* r_bin_java_methodref_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_METHODREF, tag, sz, "MethodRef" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];

		obj->info.cp_method.class_idx = R_BIN_JAVA_USHORT (buffer, 1);
		obj->info.cp_method.name_and_type_idx = R_BIN_JAVA_USHORT (buffer, 3);
		
	}

	return obj;
}

R_API ut64 r_bin_java_methodref_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_method.class_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 2;
	//obj->info.cp_method.name_and_type_idx = R_BIN_JAVA_USHORT (buffer, 3);
	size += 2;
	return size;
}


R_API RBinJavaCPTypeObj* r_bin_java_interfacemethodref_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_INTERFACEMETHOD_REF, tag, sz, "InterfaceMethodRef" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);


		obj->info.cp_interface.class_idx = R_BIN_JAVA_USHORT (buffer, 1);
		obj->info.cp_interface.name_and_type_idx = R_BIN_JAVA_USHORT (buffer, 3);

		
	}
	return (RBinJavaCPTypeObj*) obj;
}

R_API ut64 r_bin_java_interfacemethodref_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_interface.class_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 2;
	//obj->info.cp_interface.name_and_type_idx = R_BIN_JAVA_USHORT (buffer, 3);
	size += 2;
	return size;
}



R_API RBinJavaCPTypeObj* r_bin_java_string_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;

	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_STRING, tag, sz, "String" );
	if (quick_check > 0){
		return (RBinJavaCPTypeObj*) obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);

		obj->info.cp_string.string_idx = R_BIN_JAVA_USHORT (buffer, 1);
		
	}
	return  obj;
}

R_API ut64 r_bin_java_string_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_string.string_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 2;
	return size;
}

R_API RBinJavaCPTypeObj* r_bin_java_integer_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_INTEGER, tag, sz, "Integer" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);
		
		memset(&obj->info.cp_integer.bytes, 0, sizeof(obj->info.cp_integer.bytes));
		memcpy(&obj->info.cp_integer.bytes.raw, buffer+1, 4);
		
		
	}
	return obj;
}
R_API ut64 r_bin_java_integer_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_string.string_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 4;
	return size;	
}

R_API RBinJavaCPTypeObj* r_bin_java_float_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_FLOAT, tag, sz, "Float" );
	if (quick_check > 0){
		return  obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);

		memset(&obj->info.cp_float.bytes, 0, sizeof(obj->info.cp_float.bytes));
		memcpy(&obj->info.cp_float.bytes.raw, buffer, 4);
		
		
	}
	return (RBinJavaCPTypeObj*) obj;
}

R_API ut64 r_bin_java_float_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_string.string_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 4;
	return size;
}

R_API RBinJavaCPTypeObj* r_bin_java_long_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_LONG, tag, sz, "Long" );
	if (quick_check > 0){
		return  obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);

		memset(&obj->info.cp_long.bytes, 0, sizeof(obj->info.cp_long.bytes));
		memcpy(&(obj->info.cp_long.bytes), buffer+1, 8);
		
		
	}
	return obj;
}

R_API ut64 r_bin_java_long_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_string.string_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 8;
	return size;
}

R_API RBinJavaCPTypeObj* r_bin_java_double_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_DOUBLE, tag, sz, "Double" );
	if (quick_check > 0){
		return (RBinJavaCPTypeObj*) obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);

		memset(&obj->info.cp_double.bytes, 0, sizeof(obj->info.cp_double.bytes));
		memcpy(&obj->info.cp_double.bytes, buffer+1, 8);
		
		

	}

	return obj;
}

R_API ut64 r_bin_java_double_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	// tag
	size += 1;
	//obj->info.cp_string.string_idx = R_BIN_JAVA_USHORT (buffer, 1);
	size += 8;
	return size;
}


R_API RBinJavaCPTypeObj* r_bin_java_utf8_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_UTF8, tag, sz, "Utf8" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){

		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		obj->tag = tag;
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);

		obj->info.cp_utf8.length = R_BIN_JAVA_USHORT (buffer, 1);
		obj->info.cp_utf8.bytes = (ut8 *) malloc(obj->info.cp_utf8.length+1);
		if (obj->info.cp_utf8.bytes){
			memset(obj->info.cp_utf8.bytes, 0, obj->info.cp_utf8.length+1);
			if (obj->info.cp_utf8.length < (sz - 3)){
				memcpy(obj->info.cp_utf8.bytes, buffer+3,  (sz - 3));
				obj->info.cp_utf8.length = sz - 3;
			}else{
				memcpy(obj->info.cp_utf8.bytes, buffer+3, obj->info.cp_utf8.length);	
			}
			obj->value = obj->info.cp_utf8.bytes; 
			
		}
		else{
			r_bin_java_obj_free(obj);
			obj = NULL;
		}

	}
	return obj;

}

R_API ut64 r_bin_java_utf8_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	size += 1;
	if (obj && R_BIN_JAVA_CP_UTF8 == obj->tag){
		// memcpy(obj->info.cp_utf8.bytes, buffer+3, obj->info.cp_utf8.length);
		size += obj->info.cp_utf8.length;
	}
	return size;
}

R_API RBinJavaCPTypeObj* r_bin_java_name_and_type_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_NAMEANDTYPE, tag, sz, "RBinJavaCPTypeNameAndType" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);;

		obj->tag = tag;
		obj->info.cp_name_and_type.name_idx = R_BIN_JAVA_USHORT (buffer, 1);
		obj->info.cp_name_and_type.descriptor_idx = R_BIN_JAVA_USHORT (buffer, 3);
		
	}
	return obj;

}

R_API ut64 r_bin_java_name_and_type_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	
	if (obj){
		size += 1;
		//obj->info.cp_name_and_type.name_idx = R_BIN_JAVA_USHORT (buffer, 1);
		size += 2;
		//obj->info.cp_name_and_type.descriptor_idx = R_BIN_JAVA_USHORT (buffer, 3);
		size += 2;
	}
	return size;
}

R_API RBinJavaCPTypeObj* r_bin_java_methodtype_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_METHODTYPE, tag, sz, "RBinJavaCPTypeMethodType" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);;

		obj->tag = tag;
		obj->info.cp_method_type.descriptor_index = R_BIN_JAVA_USHORT (buffer, 1);
		
	}
	return obj;

}

R_API ut64 r_bin_java_methodtype_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	size += 1;
	// obj->info.cp_method_type.descriptor_index = R_BIN_JAVA_USHORT (buffer, 1);
	size += 2;
	return size;
}


R_API RBinJavaCPTypeObj* r_bin_java_methodhandle_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_METHODHANDLE, tag, sz, "RBinJavaCPTypeMethodHandle" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);;

		obj->tag = tag;
		obj->info.cp_method_handle.reference_kind = buffer[1];
		obj->info.cp_method_handle.reference_index =  R_BIN_JAVA_USHORT(buffer, 2);
	}
	return obj;
}

R_API ut64 r_bin_java_methodhandle_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	size += 1;
	//obj->info.cp_method_handle.reference_index =  R_BIN_JAVA_USHORT(buffer, 2);
	size += 2;
	return size;
}

R_API RBinJavaCPTypeObj* r_bin_java_invokedynamic_cp_new(RBinJavaObj *bin, ut8* buffer, ut64 sz){
	ut8 tag = buffer[0];
	RBinJavaCPTypeObj *obj =  NULL;
	int quick_check = 0;
	quick_check = r_bin_java_quick_check(R_BIN_JAVA_CP_INVOKEDYNAMIC, tag, sz, "RBinJavaCPTypeMethodHandle" );
	if (quick_check > 0){
		return obj;	
	}
	
	obj = (RBinJavaCPTypeObj *) malloc(sizeof(RBinJavaCPTypeObj));	                        
	if (obj){
		memset(obj, 0, sizeof(RBinJavaCPTypeObj));
		
		obj->metas = (RBinJavaMetaInfo *) malloc(sizeof(RBinJavaMetaInfo));
		obj->metas->type_info = (void *)&R_BIN_JAVA_CP_METAS[tag];
		obj->name = r_str_dup(NULL, (const char *) R_BIN_JAVA_CP_METAS[tag].name);;

		obj->tag = tag;
		obj->info.cp_invoke_dynamic.bootstrap_method_attr_index = R_BIN_JAVA_USHORT(buffer, 1);
		obj->info.cp_invoke_dynamic.name_and_type_index = R_BIN_JAVA_USHORT(buffer, 3);
	}
	return obj;
}

R_API ut64 r_bin_java_invokedynamic_cp_calc_size(RBinJavaCPTypeObj* obj){
	ut64 size = 0;
	size += 1; 
	//obj->info.cp_invoke_dynamic.bootstrap_method_attr_index = R_BIN_JAVA_USHORT(buffer, 1);
	size += 2;
	//obj->info.cp_invoke_dynamic.name_and_type_index = R_BIN_JAVA_USHORT(buffer, 3);
	size += 2;
	return size;
}


// End new Constant Pool types

// Start free Constant Pool types
R_API void r_bin_java_default_free(RBinJavaCPTypeObj *obj){
	if(obj){
		if(obj->metas) free(obj->metas);
		if(obj->name) free(obj->name);
		if(obj->value) free(obj->value);
		free(obj);
	}
}




R_API void r_bin_java_utf8_info_free(RBinJavaCPTypeObj *obj){
	if(obj){
		if(obj->metas)
			free(obj->metas);
		if (obj->info.cp_utf8.bytes)
			free(obj->info.cp_utf8.bytes);
		free(obj);
	}
}

// Deallocs for type objects
R_API void r_bin_java_obj_free(RBinJavaCPTypeObj *obj){
	( (RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
}


R_API void r_bin_java_print_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *.\n");
		return;
	}
	((RBinJavaAttrMetas *) attr->metas->type_info)->allocs->print_summary(attr);
}

R_API void r_bin_java_print_source_debug_attr_summary(RBinJavaAttrInfo *attr){
	ut32 i = 0;
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaSourceDebugExtensionAttr *.\n");
		return;
	}
	printf("Source Debug Extension Attribute information:\n");
	printf("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("   Extension length: %d\n", attr->length);
	printf("   Source Debug Extension value: \n");

	for (i = 0; i < attr->length; i++){
		printf("%c", attr->info.debug_extensions.debug_extension[i]);	
	}
	printf("\n   Source Debug Extension End\n");
}


R_API void r_bin_java_print_unknown_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *Unknown.\n");
		return;
	}
	printf("Unknown Attribute information:\n");
	printf("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("   Attribute length: %d\n", attr->length);

}
R_API void r_bin_java_print_code_exceptions_attr_summary(RBinJavaExceptionEntry *exc_entry){
	if (exc_entry == NULL){
		eprintf ("Attempting to print an invalid RBinJavaExceptionEntry *.\n");
		return;
	}
	printf("   Exception Table Entry Information\n");
	printf ("      offset:     0x%08llx\n", exc_entry->file_offset);
	printf("       catch_type: %d\n", exc_entry->catch_type);
	printf("       start_pc:   0x%04x\n", exc_entry->start_pc);
	printf("       end_pc:     0x%04x\n", exc_entry->end_pc);
	printf("       handler_pc: 0x%04x\n", exc_entry->handler_pc);

}

// End free Constant Pool types
R_API void r_bin_java_print_code_attr_summary(RBinJavaAttrInfo *attr){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaExceptionEntry* exc_entry = NULL;
	RBinJavaAttrInfo *_attr = NULL;
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *Code.\n");
		return;
	}
	printf("Code Attribute information:\n");
	printf("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf("   Attribute length: %d, Attribute Count: %d\n", attr->length, attr->info.code_attr.attributes_count);
	printf("      Max Stack: %d\n", attr->info.code_attr.max_stack);
	printf("      Max Locals: %d\n", attr->info.code_attr.max_locals);
	printf("      Code Length: %d\n", attr->info.code_attr.code_length);
	printf("      Code At Offset: 0x%08"PFMT64x"\n", (ut64)attr->info.code_attr.code_offset);
	printf ("Code Attribute Exception table information:\n");
	printf("      Exception table length: %d\n",attr->info.code_attr.exception_table_length);
	if(attr->info.code_attr.exception_table){
		// Delete the attr entries
		r_list_foreach_safe(attr->info.code_attr.exception_table, iter, iter_tmp, exc_entry){
			r_bin_java_print_code_exceptions_attr_summary(exc_entry);
		}
	}
	
	printf("      Implicit Method Stack Frame: \n");
	r_bin_java_print_stack_map_frame_summary(attr->info.code_attr.implicit_frame);


	printf ("Code Attribute Attributes information:\n");

	if(attr->info.code_attr.attributes  && attr->info.code_attr.attributes_count > 0){
		printf("      Code Attribute Attributes count: %d\n",attr->info.code_attr.attributes_count);
	
		r_list_foreach_safe(attr->info.code_attr.attributes, iter, iter_tmp, _attr){
			r_bin_java_print_attr_summary(_attr);
		}
	}

}

R_API void r_bin_java_print_constant_value_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *ConstantValue.\n");
		return;
	}
	printf ("Constant Value Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	printf ("   ConstantValue Index: %d\n", attr->info.constant_value_attr.constantvalue_idx);
}


R_API void r_bin_java_print_deprecated_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *Deperecated.\n");
		return;
	}
	printf ("Deperecated Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
}

R_API void r_bin_java_print_enclosing_methods_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *Deperecated.\n");
		return;
	}
	printf ("Enclosing Method Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	printf ("   Class Info Index : 0x%02x\n", attr->info.enclosing_method_attr.class_idx);
	printf ("   Method Name and Type Index : 0x%02x\n", attr->info.enclosing_method_attr.method_idx);

	printf ("   Class Name : %s\n", attr->info.enclosing_method_attr.class_name);
	printf ("   Method Name and Desc : %s %s\n", attr->info.enclosing_method_attr.method_name, attr->info.enclosing_method_attr.method_descriptor);

}
R_API void r_bin_java_print_exceptions_attr_summary(RBinJavaAttrInfo *attr){
	ut32 i = 0;
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *Exceptions.\n");
		return;
	}
	printf ("Exceptions Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	for (i = 0; i < attr->length; i++){
		printf ("   Exceptions Attribute Index[%d]: %d\n", i, attr->info.exceptions_attr.exception_idx_table[i]);
	}


}

R_API void r_bin_java_print_classes_attr_summary(RBinJavaClassesAttribute *icattr){
	if (icattr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaClassesAttribute* (InnerClasses element).\n");
		return;
	}

	printf ("   Inner Classes Class Attribute Offset: 0x%08llx\n", icattr->file_offset);
	printf ("   Inner Classes Class Attribute Class Name (%d): %s\n", icattr->inner_name_idx, icattr->name);
	printf ("   Inner Classes Class Attribute Class inner_class_info_idx: %d\n", icattr->inner_class_info_idx);
	printf ("   Inner Classes Class Attribute Class inner_class_access_flags: %d\n", icattr->inner_class_access_flags);
	printf ("   Inner Classes Class Attribute Class outer_class_info_idx: %d\n", icattr->outer_class_info_idx);
	printf ("   Inner Classes Class Field Information:\n");
	r_bin_java_print_field_summary(icattr->clint_field);
	printf ("   Inner Classes Class Field Information:\n");
	r_bin_java_print_field_summary(icattr->clint_field);
	printf ("   Inner Classes Class Attr Info Information:\n");
	r_bin_java_print_attr_summary(icattr->clint_attr);

}

R_API void r_bin_java_print_inner_classes_attr_summary(RBinJavaAttrInfo *attr){
	RBinJavaClassesAttribute *icattr;
	RListIter *iter, *iter_tmp;

	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *InnerClasses.\n");
		return;
	}

	printf ("Inner Classes Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);

	r_list_foreach_safe(attr->info.inner_classes_attr.classes, iter, iter_tmp, icattr){
		r_bin_java_print_classes_attr_summary(icattr);
	}

}

R_API void r_bin_java_print_line_number_attr_summary(RBinJavaLineNumberAttribute *lnattr){
	if (lnattr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaLineNumberAttribute *.\n");
		return;
	}
	printf ("   Line Number Attribute offset: 0x%08llx\n", lnattr->file_offset);
	printf ("   Line Number Attribute start_pc: %d\n", lnattr->start_pc);
	printf ("   Line Number Attribute line_number: %d\n", lnattr->line_number);

}

R_API void r_bin_java_print_line_number_table_attr_summary(RBinJavaAttrInfo *attr){
	RBinJavaLineNumberAttribute *lnattr;
	RListIter *iter, *iter_tmp;
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *LineNumberTable.\n");
		return;
	}
	printf ("Line Number Table Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	r_list_foreach_safe(attr->info.line_number_table_attr.line_number_table, iter, iter_tmp, lnattr){
		r_bin_java_print_line_number_attr_summary(lnattr);
	}

}

R_API void r_bin_java_print_local_variable_attr_summary(RBinJavaLocalVariableAttribute *lvattr){
	if (lvattr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaLocalVariableAttribute *.\n");
		return;
	}
	printf ("   Local Variable Attribute offset: 0x%08llx\n", lvattr->file_offset);
	printf ("   Local Variable Attribute start_pc: %d\n", lvattr->start_pc);
	printf ("   Local Variable Attribute length: %d\n", lvattr->length);
	printf ("   Local Variable Attribute name_idx: %d\n", lvattr->name_idx);
	printf ("   Local Variable Attribute name: %s\n", lvattr->name);
	printf ("   Local Variable Attribute descriptor_idx: %d\n", lvattr->descriptor_idx);
	printf ("   Local Variable Attribute descriptor: %s\n", lvattr->descriptor);
	printf ("   Local Variable Attribute index: %d\n", lvattr->index);
}

R_API void r_bin_java_print_local_variable_table_attr_summary(RBinJavaAttrInfo *attr){
	RBinJavaLocalVariableAttribute *lvattr;
	RListIter *iter, *iter_tmp;
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *LocalVariableTable.\n");
		return;
	}
	printf ("Local Variable Table Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	r_list_foreach_safe(attr->info.local_variable_table_attr.local_variable_table, iter, iter_tmp, lvattr){
		r_bin_java_print_local_variable_attr_summary(lvattr);
	}
}

R_API void r_bin_java_print_local_variable_type_attr_summary(RBinJavaLocalVariableTypeAttribute *lvattr){
	if (lvattr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaLocalVariableTypeAttribute *.\n");
		return;
	}
	printf ("   Local Variable Type Attribute offset: 0x%08llx\n", lvattr->file_offset);
	printf ("   Local Variable Type Attribute start_pc: %d\n", lvattr->start_pc);
	printf ("   Local Variable Type Attribute length: %d\n", lvattr->length);
	printf ("   Local Variable Type Attribute name_idx: %d\n", lvattr->name_idx);
	printf ("   Local Variable Type Attribute name: %s\n", lvattr->name);
	printf ("   Local Variable Type Attribute signature_idx: %d\n", lvattr->signature_idx);
	printf ("   Local Variable Type Attribute signature: %s\n", lvattr->signature);
	printf ("   Local Variable Type Attribute index: %d\n", lvattr->index);
}
R_API void r_bin_java_print_local_variable_type_table_attr_summary(RBinJavaAttrInfo *attr){
	RBinJavaLocalVariableTypeAttribute *lvtattr;
	RListIter *iter, *iter_tmp;
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *LocalVariableTable.\n");
		return;
	}
	printf ("Local Variable Type Table Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	r_list_foreach_safe(attr->info.local_variable_type_table_attr.local_variable_table, iter, iter_tmp, lvtattr){
		r_bin_java_print_local_variable_type_attr_summary(lvtattr);
	}
}

R_API void r_bin_java_print_signature_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *SignatureAttr.\n");
		return;
	}
	printf ("Signature Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	printf ("   Signature UTF8 Index: %d\n", attr->info.signature_attr.signature_idx);	
	printf ("   Signature string: %s\n", attr->info.signature_attr.signature);
}


R_API void r_bin_java_print_source_code_file_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *SourceFile.\n");
		return;
	}
	printf ("Source File Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	printf ("   Source File Index: %d\n", attr->info.source_file_attr.sourcefile_idx);	
}

R_API void r_bin_java_print_synthetic_attr_summary(RBinJavaAttrInfo *attr){
	if (attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaAttrInfo *Synthetic.\n");
		return;
	}
	printf ("Synthetic Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	printf ("   Attribute Index: %d\n", attr->info.source_file_attr.sourcefile_idx);	
}

R_API void r_bin_java_print_stack_map_table_attr_summary(RBinJavaAttrInfo *attr){
	RListIter *iter, *iter_tmp;
	RList *ptrList;
	RBinJavaStackMapFrame *frame;

	if(attr == NULL){
		eprintf ("Attempting to print an invalid RBinJavaStackMapTableAttr*  .\n");
		return;
	}

	printf ("StackMapTable Attribute information:\n");
	printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
	printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
	printf ("   Attribute length: %d\n", attr->length);
	printf ("   StackMapTable Method Code Size: 0x%08x\n", attr->info.stack_map_table_attr.code_size);
	printf ("   StackMapTable Frame Entries: 0x%08x\n", attr->info.stack_map_table_attr.number_of_entries);
	printf ("   StackMapTable Frames:\n");
	

	ptrList = attr->info.stack_map_table_attr.stack_map_frame_entries;
	if (ptrList){
		r_list_foreach_safe(ptrList, iter, iter_tmp, frame){
			r_bin_java_print_stack_map_frame_summary(frame);
		}		
	}


}

R_API void r_bin_java_print_stack_map_append_frame_summary(RBinJavaStackMapFrame *obj){
	RListIter *iter, *iter_tmp;
	RList *ptrList;
	RBinJavaVerificationObj *ver_obj;
	
	printf("Stack Map Frame Information\n");
	printf("    Tag Value = 0x%02x Name: %s\n", obj->tag, ((RBinJavaStackMapFrameMetas *) obj->metas->type_info)->name);
	printf("    Offset: 0x%08llx\n", obj->file_offset);
	printf("    Local Variable Count = 0x%04x\n", obj->number_of_locals);	
	printf("    Local Variables:\n");	
	ptrList = obj->local_items;
	r_list_foreach_safe(ptrList, iter, iter_tmp, ver_obj){
		r_bin_java_print_verification_info_summary(ver_obj);
	}

	printf("    Stack Items Count = 0x%04x\n", obj->number_of_stack_items);	
	printf("    Stack Items:\n");	
	
	ptrList = obj->stack_items;
	r_list_foreach_safe(ptrList, iter, iter_tmp, ver_obj){
		r_bin_java_print_verification_info_summary(ver_obj);
	}
}
R_API void r_bin_java_print_stack_map_frame_summary(RBinJavaStackMapFrame *obj){
	RListIter *iter, *iter_tmp;
	RList *ptrList;
	RBinJavaVerificationObj *ver_obj;
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaStackMapFrame*  .\n");
		return;
	}


	printf("Stack Map Frame Information\n");
	printf("    Tag Value = 0x%02x Name: %s\n", obj->tag, ((RBinJavaStackMapFrameMetas *) obj->metas->type_info)->name);
	printf("    Offset: 0x%08llx\n", obj->file_offset);
	printf("    Local Variable Count = 0x%04x\n", obj->number_of_locals);	
	printf("    Stack Items Count = 0x%04x\n", obj->number_of_stack_items);	

	printf("    Local Variables:\n");	
	ptrList = obj->local_items;
	r_list_foreach_safe(ptrList, iter, iter_tmp, ver_obj){
		r_bin_java_print_verification_info_summary(ver_obj);
	}

	printf("    Stack Items:\n");	
	
	ptrList = obj->stack_items;
	r_list_foreach_safe(ptrList, iter, iter_tmp, ver_obj){
		r_bin_java_print_verification_info_summary(ver_obj);
	}
}


R_API void r_bin_java_print_verification_info_summary(RBinJavaVerificationObj *obj){
	ut8 tag_value = R_BIN_JAVA_STACKMAP_UNKNOWN; 
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaVerificationObj*  .\n");
		return;
	}

	if (obj->tag < R_BIN_JAVA_STACKMAP_UNKNOWN)
		tag_value = obj->tag;

	printf("Verification Information\n");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Tag Value = 0x%02x\n", obj->tag);
	printf("    Name = %s\n", R_BIN_JAVA_VERIFICATION_METAS[tag_value].name);	
	
	if (obj->tag == R_BIN_JAVA_STACKMAP_OBJECT){
		printf("    Object Constant Pool Index = 0x%x\n", obj->info.obj_val_cp_idx);	
	}else if(obj->tag == R_BIN_JAVA_STACKMAP_UNINIT){
		printf("    Uninitialized Object offset in code = 0x%x\n", obj->info.uninit_offset);			
	}
	
}




R_API void r_bin_java_print_field_summary(RBinJavaField *field){
	RBinJavaAttrInfo *attr;
	RListIter *iter, *iter_tmp;

	if (field == NULL){
		eprintf ("Attempting to print an invalid RBinJavaField* Field.\n");
		return;
	}
	if(field && field->type == R_BIN_JAVA_FIELD_TYPE_METHOD){
		r_bin_java_print_method_summary(field);
		return;
	}/*else if(field && field->type == R_BIN_JAVA_FIELD_TYPE_INTERFACE){
		r_bin_java_print_interface_summary(field);
		return;
	}*/

	printf("Field Summary Information:\n");
	printf("    File offset: 0x%08llx", field->file_offset);
	printf("    Access Flags: %d\n", field->flags);
	printf("    Name Index: %d (%s)\n", field->name_idx, field->name);
	printf("    Descriptor Index: %d (%s)\n", field->descriptor_idx, field->descriptor); 
	printf("    Field Attributes Count: %d\n", field->attr_count);
	printf("    Field Attributes:\n");
	r_list_foreach_safe(field->attributes, iter, iter_tmp, attr){
		r_bin_java_print_attr_summary(attr);
	}
}

R_API void r_bin_java_print_method_summary(RBinJavaField *field){
	RBinJavaAttrInfo *attr;
	RListIter *iter, *iter_tmp;
	if (field == NULL){
		eprintf ("Attempting to print an invalid RBinJavaField* Method.\n");
		return;
	}

	printf("Method Summary Information:\n");
	printf("    File offset: 0x%08llx", field->file_offset);
	printf("    Access Flags: %d\n", field->flags);
	printf("    Name Index: %d (%s)\n", field->name_idx, field->name);
	printf("    Descriptor Index: %d (%s)\n", field->descriptor_idx, field->descriptor); 
	printf("    Method Attributes Count: %d\n", field->attr_count);
	printf("    Method Attributes:\n");

	r_list_foreach_safe(field->attributes, iter, iter_tmp, attr){
		r_bin_java_print_attr_summary(attr);
	}
}

/*
R_API void r_bin_java_print_interface_summary(ut16 idx){//RBinJavaField *field){
	RBinJavaAttrInfo *attr;
	RBinJavaCPTypeObj *class_info;
	RListIter *iter, *iter_tmp;


	if (field == NULL){
		eprintf ("Attempting to print an invalid RBinJavaField* Interface.\n");
		return;
	}
	printf("Interface Summary Information:\n");
	printf("    File offset: 0x%08llx", field->file_offset);
	printf("    Access Flags: %d\n", field->flags);
	printf("    Name Index: %d (%s)\n", field->name_idx, field->name);
	printf("    Descriptor Index: %d (%s)\n", field->descriptor_idx, field->descriptor); 
	printf("    Interface Attributes Count: %d\n", field->attr_count);
	printf("    Interface Attributes:\n");
	r_list_foreach_safe(field->attributes, iter, iter_tmp, attr){
		r_bin_java_print_attr_summary(attr);
	}
}
*/

R_API void r_bin_java_print_interfacemethodref_cp_summary(RBinJavaCPTypeObj* obj){
	
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  InterfaceMethodRef.\n");
		return;
	}


	printf("InterfaceMethodRef ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Class Index = %d\n", obj->info.cp_interface.class_idx);
	printf("    Name and type Index = %d\n", obj->info.cp_interface.name_and_type_idx);
}

R_API void r_bin_java_print_methodhandle_cp_summary(RBinJavaCPTypeObj* obj){
	ut8 ref_kind;
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  RBinJavaCPTypeMethodHandle.\n");
		return;
	}
	ref_kind = obj->info.cp_method_handle.reference_kind;

	printf("MethodHandle ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Reference Kind = (0x%02x) %s\n", ref_kind, R_BIN_JAVA_REF_METAS[ref_kind].name);
	printf("    Reference Index = %d\n", obj->info.cp_method_handle.reference_index);

}

R_API void r_bin_java_print_methodtype_cp_summary(RBinJavaCPTypeObj* obj){
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  RBinJavaCPTypeMethodType.\n");
		return;
	}
	
	printf("MethodType ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	
	printf("    Descriptor Index = 0x%02x\n", obj->info.cp_method_type.descriptor_index);

}
R_API void r_bin_java_print_invokedynamic_cp_summary(RBinJavaCPTypeObj* obj){
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  RBinJavaCPTypeInvokeDynamic.\n");
		return;
	}
	
	printf("InvokeDynamic ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Bootstrap Method Attr Index = (0x%02x)\n", obj->info.cp_invoke_dynamic.bootstrap_method_attr_index);
	printf("    Bootstrap Name and Type Index = (0x%02x)\n", obj->info.cp_invoke_dynamic.name_and_type_index);

}


R_API void r_bin_java_print_methodref_cp_summary(RBinJavaCPTypeObj* obj){
	
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  MethodRef.\n");
		return;
	}

	printf("MethodRef ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Class Index = %d\n", obj->info.cp_method.class_idx);
	printf("    Name and type Index = %d\n", obj->info.cp_method.name_and_type_idx);
}

R_API void r_bin_java_print_fieldref_cp_summary(RBinJavaCPTypeObj* obj){
	
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  FieldRef.\n");
		return;
	}

	printf("FieldRef ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Class Index = %d\n", obj->info.cp_field.class_idx);
	printf("    Name and type Index = %d\n", obj->info.cp_field.name_and_type_idx);
}


R_API void r_bin_java_print_classref_cp_summary(RBinJavaCPTypeObj* obj){
	
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  ClassRef.\n");
		return;
	}

	printf("ClassRef ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    Name Index = %d\n", obj->info.cp_class.name_idx);

}


R_API void r_bin_java_print_string_cp_summary(RBinJavaCPTypeObj* obj){
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  String.\n");
		return;
	}

	printf("String ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    String Index = %d\n", obj->info.cp_string.string_idx);

}

R_API void r_bin_java_print_integer_cp_summary(RBinJavaCPTypeObj* obj){
	
	ut8 *b = NULL;
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  Integer.\n");
		return;
	}

	b = obj->info.cp_integer.bytes.raw;

	printf("Integer ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("    integer = %d\n", R_BIN_JAVA_UINT(obj->info.cp_integer.bytes.raw, 0));

}

R_API void r_bin_java_print_float_cp_summary(RBinJavaCPTypeObj* obj){
	
	ut8 *b = NULL;
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  Double.\n");
		return;
	}

	b = obj->info.cp_float.bytes.raw;

	printf("Float ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("    float = %f\n", R_BIN_JAVA_FLOAT(obj->info.cp_float.bytes.raw, 0));
}

R_API void r_bin_java_print_long_cp_summary(RBinJavaCPTypeObj* obj){
	
	ut8 *b = NULL;
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  Long.\n");
		return;
	}


	b = obj->info.cp_long.bytes.raw;

	printf("Long ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    High-bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("    Low-bytes = %02x %02x %02x %02x\n", b[4], b[5], b[6], b[7]);
	printf("    long = %llx\n", rbin_java_raw_to_long(obj->info.cp_long.bytes.raw, 0));
}

R_API void r_bin_java_print_double_cp_summary(RBinJavaCPTypeObj* obj){
	
	ut8 *b = NULL;
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  Double.\n");
		return;
	}


	b = obj->info.cp_double.bytes.raw;

	printf("Double ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    High-bytes = %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
	printf("    Low-bytes = %02x %02x %02x %02x\n", b[4], b[5], b[6], b[7]);
	printf("    double = %f\n", rbin_java_raw_to_double(obj->info.cp_double.bytes.raw, 0));
}

R_API void r_bin_java_print_name_and_type_cp_summary(RBinJavaCPTypeObj* obj){
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  Name_And_Type.\n");
		return;
	}


	printf("Name_And_Type ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    name_idx = (%d)\n", obj->info.cp_name_and_type.name_idx);
	printf("    descriptor_idx = (%d)\n", obj->info.cp_name_and_type.name_idx);
	
}

R_API void r_bin_java_print_utf8_cp_summary(RBinJavaCPTypeObj* obj){
	if(obj == NULL){
		eprintf ("Attempting to print an invalid RBinJavaCPTypeObj*  Utf8.\n");
		return;
	}

	printf("UTF8 ConstantPool Type ");
	printf("    Offset: 0x%08llx", obj->file_offset);
	printf("    length = %d\n", obj->info.cp_utf8.length);
	// XXX - TODO UTF8 Interpretation
	printf("    strlen(%lu) utf8 = %s\n", strlen( (const char *) obj->info.cp_utf8.bytes) ,(char *) obj->info.cp_utf8.bytes);

}


R_API void r_bin_java_print_null_cp_summary(RBinJavaCPTypeObj* obj){
	printf ("Unknown ConstantPool Type Tag: 0x%04x .\n", obj->tag);
	
}

R_API void r_bin_java_print_unknown_cp_summary(RBinJavaCPTypeObj* obj){
	printf ("NULL ConstantPool Type.\n");
	
}


R_API void r_bin_java_stack_frame_default_free(RBinJavaStackMapFrame *stack_frame){
	if(stack_frame){
		if (stack_frame->metas){
			//((RBinJavaStackMapFrameMetas *) attr->metas->type_info)->allocs->delete_obj(stack_frame);
			free(stack_frame->metas);
			stack_frame->metas = NULL;
		}
		free(stack_frame);
		stack_frame = NULL;
	}
}
R_API void r_bin_java_stack_frame_do_nothing_free(RBinJavaStackMapFrame *stack_frame){}

R_API void r_bin_java_stack_frame_do_nothing_new(RBinJavaObj *bin, RBinJavaStackMapFrame *stack_frame, ut64 offset){}




R_API RBinJavaElementValuePair* r_bin_java_element_pair_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	RBinJavaElementValuePair *ev_pair = NULL;
	ut64 offset = 0;
	ev_pair = (RBinJavaElementValuePair *) malloc(sizeof(RBinJavaElementValuePair));

	if (ev_pair == NULL){
		// TODO eprintf ev_pair failed to allocate
		return ev_pair;
	}
	// TODO: What is the signifigance of ev_pair element
	ev_pair->element_name_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	ev_pair->file_offset = buf_offset;
	ev_pair->name = r_bin_java_get_utf8_from_bin_cp_list(R_BIN_JAVA_GLOBAL_BIN, ev_pair->element_name_idx);
	if (ev_pair->name == NULL){
		// TODO: eprintf unable to find the name for the given index
	}
	ev_pair->value = r_bin_java_element_value_new(buffer+offset, sz-offset, buf_offset+offset);
	offset += ev_pair->value->size;
	ev_pair->size = offset;
	return ev_pair;
}


R_API void r_bin_java_print_element_pair_summary(RBinJavaElementValuePair *ev_pair){
	if(ev_pair == NULL){
		eprintf ("Attempting to print an invalid RBinJavaElementValuePair *pair.\n");
		return;
	}
	printf("Element Value Pair information:\n");
	printf("   EV Pair File Offset: 0x%08llx\n", ev_pair->file_offset);	
	printf("   EV Pair Element Name index: 0x%02x\n", ev_pair->element_name_idx);	
	printf("   EV Pair Element Name: %s\n", ev_pair->name);	
	printf("   EV Pair Element Value:\n");
	r_bin_java_print_element_value_summary(ev_pair->value);

}



R_API void r_bin_java_print_element_value_summary(RBinJavaElementValue *element_value){
	RBinJavaCPTypeObj *obj;
	RBinJavaElementValue *ev_element=NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	char* name;
	if(ev_element == NULL){
		eprintf ("Attempting to print an invalid RBinJavaElementValuePair *pair.\n");
		return;
	}
	name = ((RBinJavaElementValueMetas *)element_value->metas->type_info)->name;
	printf("Element Value information:\n");
	printf("   EV Pair File Offset: 0x%08llx\n", element_value->file_offset);
	printf("   EV Value Type (%d): %s\n", element_value->tag, name );
	switch(element_value->tag){
		case R_BIN_JAVA_EV_TAG_BYTE:
		case R_BIN_JAVA_EV_TAG_CHAR:
		case R_BIN_JAVA_EV_TAG_DOUBLE:
		case R_BIN_JAVA_EV_TAG_FLOAT:
		case R_BIN_JAVA_EV_TAG_INT:
		case R_BIN_JAVA_EV_TAG_LONG:
		case R_BIN_JAVA_EV_TAG_SHORT:
		case R_BIN_JAVA_EV_TAG_BOOLEAN:
				
			printf("   EV Value Constant Value index: 0x%02x\n", element_value->value.const_value.const_value_idx);
			printf("   EV Value Constant Value Information:\n");
			obj = element_value->value.const_value.const_value_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->print_summary(obj);	
			break;
		case R_BIN_JAVA_EV_TAG_ENUM:
			printf("   EV Value Enum Constant Value Const Name Index: 0x%02x\n", element_value->value.enum_const_value.const_name_idx);
			printf("   EV Value Enum Constant Value Type Name Index: 0x%02x\n", element_value->value.enum_const_value.type_name_idx);
			printf("   EV Value Enum Constant Value Const CP Information:\n");
			obj = element_value->value.enum_const_value.const_name_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->print_summary(obj);	
			printf("   EV Value Enum Constant Value Type CP Information:\n");
			obj = element_value->value.enum_const_value.type_name_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->print_summary(obj);	
			break;
		case R_BIN_JAVA_EV_TAG_CLASS:
			printf("   EV Value Class Info Index: 0x%02x\n", element_value->value.class_value.class_info_idx);
			printf("   EV Value Class Info CP Information:\n");
			obj = element_value->value.class_value.class_info_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->print_summary(obj);	
			break;
		case R_BIN_JAVA_EV_TAG_ARRAY:
			printf("   EV Value Array Value Number of Values: 0x%04x\n", element_value->value.array_value.num_values);
			printf("   EV Value Array Values\n");
			r_list_foreach_safe(element_value->value.array_value.values, iter, iter_tmp, ev_element){
				r_bin_java_print_element_value_summary(ev_element);
			}
			break;
		case R_BIN_JAVA_EV_TAG_ANNOTATION:
			printf("   EV Annotation Information:\n");
			r_bin_java_print_annotation_summary(&element_value->value.annotation_value);
			break;
		default: 
			// eprintf unable to handle tag
			break;
		}
}



R_API void r_bin_java_element_pair_free(RBinJavaElementValuePair *ev_pair){
	
	if(ev_pair){
		if (ev_pair->name){
			free(ev_pair->name);
			ev_pair->name = NULL;
		}
		if(ev_pair->value){
			r_bin_java_element_value_free(ev_pair->value);
			ev_pair->value = NULL;			
		}
		free(ev_pair);
	}
	ev_pair = NULL;
}
R_API void r_bin_java_element_value_free(RBinJavaElementValue* element_value){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaCPTypeObj *obj = NULL;
	RBinJavaElementValuePair *ev_pairs = NULL;
	RBinJavaElementValue *ev_element = NULL;

	if(element_value){
		switch(element_value->tag){
			case R_BIN_JAVA_EV_TAG_BYTE:
			case R_BIN_JAVA_EV_TAG_CHAR:
			case R_BIN_JAVA_EV_TAG_DOUBLE:
			case R_BIN_JAVA_EV_TAG_FLOAT:
			case R_BIN_JAVA_EV_TAG_INT:
			case R_BIN_JAVA_EV_TAG_LONG:
			case R_BIN_JAVA_EV_TAG_SHORT:
			case R_BIN_JAVA_EV_TAG_BOOLEAN:
				//Delete the CP Type Object
				obj = element_value->value.const_value.const_value_cp_obj;
				((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
				break;
			case R_BIN_JAVA_EV_TAG_ENUM:
				//Delete the CP Type Objects
				obj = element_value->value.enum_const_value.const_name_cp_obj;
				((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
				obj = element_value->value.enum_const_value.type_name_cp_obj;
				((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
				break;
			case R_BIN_JAVA_EV_TAG_CLASS:
				//Delete the CP Type Object
				obj = element_value->value.class_value.class_info_cp_obj;
				((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
				break;
			case R_BIN_JAVA_EV_TAG_ARRAY:
				//Delete the Element Value array List
				r_list_foreach_safe(element_value->value.array_value.values, iter, iter_tmp, ev_element){
					if (ev_element){
						r_bin_java_element_value_free(ev_element);
					}else{
						// TODO eprintf ev_pairs value was NULL
					}
					r_list_delete(element_value->value.array_value.values, iter);
					ev_element = NULL;
				}
				r_list_free(element_value->value.array_value.values);
				break;
			case R_BIN_JAVA_EV_TAG_ANNOTATION:
				//Delete the Annotations List
				r_list_foreach_safe(element_value->value.annotation_value.element_value_pairs, iter, iter_tmp, ev_pairs){
					if (ev_pairs){
						r_bin_java_element_pair_free(ev_pairs);
					}
					else{
						// TODO eprintf ev_pairs value was NULL
					}
					r_list_delete(element_value->value.annotation_value.element_value_pairs, iter);
					ev_pairs = NULL;
				}
				r_list_free(element_value->value.annotation_value.element_value_pairs);
				break;
			default: 
				// eprintf unable to free the tag
				break;

		}
		free(element_value);
	}
}

R_API ut64 r_bin_java_annotation_default_attr_calc_size(RBinJavaAttrInfo *attr){
	ut64 size = 0;
	
	if (attr){
		//attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
		size += 6;
		//attr->info.annotation_default_attr.default_value = r_bin_java_element_value_new(buffer+offset, sz-offset, buf_offset+offset); 
		size += r_bin_java_element_value_calc_size(attr->info.annotation_default_attr.default_value);
	}
	return size;
} 

R_API RBinJavaAttrInfo* r_bin_java_annotation_default_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut64 offset = 0;
	RBinJavaAttrInfo* attr = NULL;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if(attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_ANNOTATION_DEFAULT_ATTR; 
		attr->info.annotation_default_attr.default_value = r_bin_java_element_value_new(buffer+offset, sz-offset, buf_offset+offset);
		
		if (attr->info.annotation_default_attr.default_value){
			offset += attr->info.annotation_default_attr.default_value->size;
		}
	}
	return attr;
}

R_API void r_bin_java_annotation_default_attr_free(RBinJavaAttrInfo *attr){
	RBinJavaElementValuePair *ev_pairs = NULL;
	RBinJavaElementValue* element_value = NULL, *ev_element = NULL;

	RBinJavaCPTypeObj *obj = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if (attr == NULL || attr->type != R_BIN_JAVA_ATTR_TYPE_ANNOTATION_DEFAULT_ATTR){
		return;
	}
	element_value = (attr->info.annotation_default_attr.default_value);
	switch(element_value->tag){
		case R_BIN_JAVA_EV_TAG_BYTE:
		case R_BIN_JAVA_EV_TAG_CHAR:
		case R_BIN_JAVA_EV_TAG_DOUBLE:
		case R_BIN_JAVA_EV_TAG_FLOAT:
		case R_BIN_JAVA_EV_TAG_INT:
		case R_BIN_JAVA_EV_TAG_LONG:
		case R_BIN_JAVA_EV_TAG_SHORT:
		case R_BIN_JAVA_EV_TAG_BOOLEAN:
			//Delete the CP Type Object
			obj = element_value->value.const_value.const_value_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
			break;
		case R_BIN_JAVA_EV_TAG_ENUM:
			//Delete the CP Type Objects
			obj = element_value->value.enum_const_value.const_name_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
			obj = element_value->value.enum_const_value.type_name_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
			break;
		case R_BIN_JAVA_EV_TAG_CLASS:
			//Delete the CP Type Object
			obj = element_value->value.class_value.class_info_cp_obj;
			((RBinJavaCPTypeMetas *) obj->metas->type_info)->allocs->delete_obj(obj);
			break;
		case R_BIN_JAVA_EV_TAG_ARRAY:
			//Delete the Element Value array List
			r_list_foreach_safe(element_value->value.array_value.values, iter, iter_tmp, ev_element){
				if (ev_element){
					r_bin_java_element_value_free(ev_element);
				}else{
					// TODO eprintf ev_pairs value was NULL
				}
				r_list_delete(element_value->value.array_value.values, iter);
				ev_element = NULL;
			}
			r_list_free(element_value->value.array_value.values);
			break;
		case R_BIN_JAVA_EV_TAG_ANNOTATION:
			//Delete the Annotations List
			r_list_foreach_safe(element_value->value.annotation_value.element_value_pairs, iter, iter_tmp, ev_pairs){
				if (ev_pairs){
					r_bin_java_element_pair_free(ev_pairs);
				}
				else{
					// TODO eprintf ev_pairs value was NULL
				}
				r_list_delete(element_value->value.annotation_value.element_value_pairs, iter);
				ev_pairs = NULL;
			}
			r_list_free(element_value->value.annotation_value.element_value_pairs);
			break;
		default: 
			// eprintf unable to free the tag
			break;

	}	
}


R_API RBinJavaAnnotation* r_bin_java_annotation_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	RBinJavaAnnotation *annotation = NULL;
	RBinJavaElementValuePair *ev_pairs = NULL;
	ut64 offset = 0;
	annotation = (RBinJavaAnnotation *)malloc(sizeof(RBinJavaAnnotation));
	if (annotation == NULL){
		// TODO eprintf annotation allocation failed
		return NULL;
	}
	
	memset(annotation, 0, sizeof(RBinJavaAnnotation));

	// (ut16) read and set annotation_value.type_idx;
	annotation->type_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	// (ut16) read and set annotation_value.num_element_value_pairs;
	annotation->num_element_value_pairs = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	

	annotation->element_value_pairs = r_list_new();
	// read annotation_value.num_element_value_pairs, and append to annotation_value.element_value_pairs
	for (i = 0; i < annotation->num_element_value_pairs; i++){
		ev_pairs = r_bin_java_element_pair_new(buffer+offset, sz-offset, buf_offset+offset);
		if(ev_pairs == NULL){
			// TODO: eprintf error when reading element pair
		}
		if (ev_pairs){
			offset += ev_pairs->size;
		}
		r_list_append(annotation->element_value_pairs, (void *) ev_pairs);
	}
	annotation->size = offset;
	return annotation;
}

R_API ut64 r_bin_java_annotation_calc_size(RBinJavaAnnotation* annotation){
	ut64  sz = 0;
	RListIter *iter, *iter_tmp;
	RBinJavaElementValuePair *ev_pairs = NULL;
	if (annotation == NULL){
		// TODO eprintf allocation fail
		return sz;
	}
	//annotation->type_idx = R_BIN_JAVA_USHORT(buffer, offset);
	sz += 2;

	//annotation->num_element_value_pairs = R_BIN_JAVA_USHORT(buffer, offset);
	sz += 2;
	
	r_list_foreach_safe(annotation->element_value_pairs, iter, iter_tmp, ev_pairs){
		if (ev_pairs)
			sz += r_bin_java_element_pair_calc_size(ev_pairs);
	}
	return sz;
}


R_API void r_bin_java_annotation_free(RBinJavaAnnotation *annotation){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaElementValuePair *ev_pairs = NULL;
	
	if (annotation){
		if(annotation->element_value_pairs){
			r_list_foreach_safe(annotation->element_value_pairs, iter, iter_tmp, ev_pairs){
				if (ev_pairs){
					r_bin_java_element_pair_free(ev_pairs);
				}
				else{
					// TODO eprintf ev_pairs value was NULL
				}
				r_list_delete(annotation->element_value_pairs, iter);
				ev_pairs = NULL;
			}
			r_list_free(annotation->element_value_pairs);
		}
		free(annotation);
	}
}

R_API void r_bin_java_print_annotation_summary(RBinJavaAnnotation *annotation){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaElementValuePair *ev_pair = NULL;
	if (annotation == NULL){
		// TODO eprintf invalid annotation
		return;
	}
	printf("   Annotation Type Index: 0x%02x\n", annotation->type_idx);	
	printf("   Annotation Number of EV Pairs: 0x%04x\n", annotation->num_element_value_pairs);	
	printf("   Annotation EV Pair Values:\n");
	if(annotation->element_value_pairs){
		r_list_foreach_safe(annotation->element_value_pairs, iter, iter_tmp, ev_pair){
			r_bin_java_print_element_pair_summary(ev_pair);
		}
	}
}

R_API ut64 r_bin_java_element_pair_calc_size(RBinJavaElementValuePair *ev_pair){
    ut64 sz = 0;
    if (ev_pair == NULL)
        return sz;
    
    //ev_pair->element_name_idx = r_bin_java_read_short(bin, bin->b->cur);
    sz += 2;
    //ev_pair->value = r_bin_java_element_value_new(bin, offset+2);
    if (ev_pair->value)
        sz += r_bin_java_element_value_calc_size(ev_pair->value);    
    
    return sz;
}


R_API ut64 r_bin_java_element_value_calc_size(RBinJavaElementValue *element_value){
    RListIter *iter, *iter_tmp;
    RBinJavaElementValue* ev_element;
    RBinJavaElementValuePair *ev_pairs;
	ut64 sz = 0;
	if (element_value == NULL)
		return sz;
	// tag
	sz += 1;
	switch(element_value->tag){
		case R_BIN_JAVA_EV_TAG_BYTE:
		case R_BIN_JAVA_EV_TAG_CHAR:
		case R_BIN_JAVA_EV_TAG_DOUBLE:
		case R_BIN_JAVA_EV_TAG_FLOAT:
		case R_BIN_JAVA_EV_TAG_INT:
		case R_BIN_JAVA_EV_TAG_LONG:
		case R_BIN_JAVA_EV_TAG_SHORT:
		case R_BIN_JAVA_EV_TAG_BOOLEAN:
			// look up value in bin->cp_list
			// (ut16) read and set const_value.const_value_idx
			//element_value->value.const_value.const_value_idx = r_bin_java_read_short(bin, bin->b->cur);
			sz += 2;			
			break;
		case R_BIN_JAVA_EV_TAG_ENUM:
			// (ut16) read and set enum_const_value.type_name_idx
			//element_value->value.enum_const_value.type_name_idx = r_bin_java_read_short(bin, bin->b->cur);			
			sz += 2;
			// (ut16) read and set enum_const_value.const_name_idx
			//element_value->value.enum_const_value.const_name_idx = r_bin_java_read_short(bin, bin->b->cur);
			sz += 2;
			break;
		case R_BIN_JAVA_EV_TAG_CLASS:
			// (ut16) read and set class_value.class_info_idx
			//element_value->value.class_value.class_info_idx = r_bin_java_read_short(bin, bin->b->cur);
			sz += 2;
			break;
		case R_BIN_JAVA_EV_TAG_ARRAY:
			// (ut16) read and set array_value.num_values
			//element_value->value.array_value.num_values = r_bin_java_read_short(bin, bin->b->cur);
			sz += 2;
            r_list_foreach_safe(element_value->value.array_value.values, iter, iter_tmp, ev_element){
                if (ev_element){
                    sz += r_bin_java_element_value_calc_size(ev_element);
                }
            }

			break;
		case R_BIN_JAVA_EV_TAG_ANNOTATION:
			// annotation new is not used here.
			// (ut16) read and set annotation_value.type_idx;
			//element_value->value.annotation_value.type_idx = r_bin_java_read_short(bin, bin->b->cur);
	    	sz += 2;
	    	// (ut16) read and set annotation_value.num_element_value_pairs;
	    	//element_value->value.annotation_value.num_element_value_pairs = r_bin_java_read_short(bin, bin->b->cur);
			sz += 2;
			element_value->value.annotation_value.element_value_pairs = r_list_new();
            r_list_foreach_safe(element_value->value.annotation_value.element_value_pairs, iter, iter_tmp, ev_pairs ){
                if (ev_pairs){
                    sz += r_bin_java_element_pair_calc_size(ev_pairs);
                }
            }
			break;
		default: 
			// eprintf unable to handle tag
			break;
	}
	return sz;
} 


R_API RBinJavaElementValue* r_bin_java_element_value_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	ut64 offset = 0;
	RBinJavaElementValue* element_value = (RBinJavaElementValue *) malloc(sizeof(RBinJavaElementValue));
	RBinJavaElementValuePair* ev_pairs = NULL;

	// read element_value->tag
	if(element_value == NULL){
		// eprintf bad allocation
		return element_value;
	}

	memset(element_value, 0, sizeof(RBinJavaElementValue));
	element_value->file_offset = buf_offset;
	element_value->tag = buffer[offset];
	element_value->size += 1;
	offset += 1;

	element_value->metas->type_info = (void *) r_bin_java_get_ev_meta_from_tag( element_value->tag);
	switch(element_value->tag){
		case R_BIN_JAVA_EV_TAG_BYTE:
		case R_BIN_JAVA_EV_TAG_CHAR:
		case R_BIN_JAVA_EV_TAG_DOUBLE:
		case R_BIN_JAVA_EV_TAG_FLOAT:
		case R_BIN_JAVA_EV_TAG_INT:
		case R_BIN_JAVA_EV_TAG_LONG:
		case R_BIN_JAVA_EV_TAG_SHORT:
		case R_BIN_JAVA_EV_TAG_BOOLEAN:
			// look up value in bin->cp_list
			// (ut16) read and set const_value.const_value_idx
			element_value->value.const_value.const_value_idx = R_BIN_JAVA_USHORT(buffer, offset);
			element_value->size += 2;			
			offset += 2;
			// look-up, deep copy, and set const_value.const_value_cp_obj
			element_value->value.const_value.const_value_cp_obj = r_bin_java_clone_cp_idx(R_BIN_JAVA_GLOBAL_BIN, element_value->value.const_value.const_value_idx);
			break;
		case R_BIN_JAVA_EV_TAG_ENUM:
			// (ut16) read and set enum_const_value.type_name_idx
			element_value->value.enum_const_value.type_name_idx = R_BIN_JAVA_USHORT(buffer, offset);			
			element_value->size += 2;
			offset += 2;
			// (ut16) read and set enum_const_value.const_name_idx
			element_value->value.enum_const_value.const_name_idx = R_BIN_JAVA_USHORT(buffer, offset);
			element_value->size += 2;
			offset += 2;
			// look up type_name_index in bin->cp_list    
			// look-up, deep copy, and set enum_const_value.const_name_cp_obj
			element_value->value.enum_const_value.const_name_cp_obj = r_bin_java_clone_cp_idx(R_BIN_JAVA_GLOBAL_BIN, element_value->value.enum_const_value.const_name_idx);
			// look-up, deep copy, and set enum_const_value.type_name_cp_obj
			element_value->value.enum_const_value.type_name_cp_obj = r_bin_java_clone_cp_idx(R_BIN_JAVA_GLOBAL_BIN, element_value->value.enum_const_value.type_name_idx);
			break;
		case R_BIN_JAVA_EV_TAG_CLASS:
			// (ut16) read and set class_value.class_info_idx
			element_value->value.class_value.class_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
			element_value->size += 2;
			offset += 2;
			// look up type_name_index in bin->cp_list    
			// look-up, deep copy, and set class_value.class_info_cp_obj
			element_value->value.class_value.class_info_cp_obj = r_bin_java_clone_cp_idx(R_BIN_JAVA_GLOBAL_BIN, element_value->value.class_value.class_info_idx);
			break;
		case R_BIN_JAVA_EV_TAG_ARRAY:
			// (ut16) read and set array_value.num_values
			element_value->value.array_value.num_values = R_BIN_JAVA_USHORT(buffer, offset);
			element_value->size += 2;
			offset += 2;
			element_value->value.array_value.values = r_list_new();
			for (i = 0; i < element_value->value.array_value.num_values; i++){
				RBinJavaElementValue* ev_element = r_bin_java_element_value_new(buffer+offset, sz-offset, buf_offset+offset);
				
				if (ev_element){
					element_value->size += ev_element->size;
					offset += ev_element->size;
				}
				// read array_value.num_values, and append to array_value.values
				r_list_append(element_value->value.array_value.values, (void *) ev_element);
				if (ev_element == NULL){
					// TODO: eprintf error when reading element value
				}
			}
			break;
		case R_BIN_JAVA_EV_TAG_ANNOTATION:
			// annotation new is not used here.
			// (ut16) read and set annotation_value.type_idx;
			element_value->value.annotation_value.type_idx = R_BIN_JAVA_USHORT(buffer, offset);
			element_value->size += 2;
			offset += 2;
	    	// (ut16) read and set annotation_value.num_element_value_pairs;
	    	element_value->value.annotation_value.num_element_value_pairs = R_BIN_JAVA_USHORT(buffer, offset);
			element_value->size += 2;
			offset += 2;
			element_value->value.annotation_value.element_value_pairs = r_list_new();
			// read annotation_value.num_element_value_pairs, and append to annotation_value.element_value_pairs
	    	for (i = 0; i < element_value->value.annotation_value.num_element_value_pairs; i++){
	    		ev_pairs = r_bin_java_element_pair_new(buffer+offset, sz-offset, buf_offset+offset);
	    		if (ev_pairs){
					element_value->size += ev_pairs->size;
					offset += ev_pairs->size;
	    		}
	    		if(ev_pairs == NULL){
	    			// TODO: eprintf error when reading element pair
	    		}
	    		r_list_append(element_value->value.annotation_value.element_value_pairs, (void *) ev_pairs);
	    	}
			break;
		default: 
			// eprintf unable to handle tag
			break;

	}
	return element_value;
}
R_API void r_bin_java_bootstrap_method_argument_free(RBinJavaBootStrapArgument *bsm_arg){
	if (bsm_arg){
		if (bsm_arg->argument_info_cp_obj){
			((RBinJavaCPTypeMetas *) bsm_arg->argument_info_cp_obj)->allocs->delete_obj(bsm_arg->argument_info_cp_obj);
			bsm_arg->argument_info_cp_obj = NULL;
		}
		free(bsm_arg);
	}
}

R_API void r_bin_java_print_bootstrap_method_argument_summary(RBinJavaBootStrapArgument* bsm_arg){

	if(bsm_arg == NULL){
		eprintf ("Attempting to print an invalid RBinJavaBootStrapArgument *.\n");
		return;
	}

	printf("Bootstrap Method Argument Information:\n");
	printf("    Offset: 0x%08llx", bsm_arg->file_offset);
	printf("    Name_And_Type Index = (0x%02x)\n", bsm_arg->argument_info_idx);
	if (bsm_arg->argument_info_cp_obj){
		printf("    Bootstrap Method Argument Type and Name Info:\n");
		((RBinJavaCPTypeMetas *) bsm_arg->argument_info_cp_obj)->allocs->print_summary(bsm_arg->argument_info_cp_obj);
	}
	else
		printf("    Bootstrap Method Argument Type and Name Info: INVALID\n");
}


R_API void r_bin_java_print_bootstrap_method_summary(RBinJavaBootStrapMethod* bsm){
	RBinJavaBootStrapArgument* bsm_arg = NULL;
	RListIter *iter = NULL, *iter_tmp=NULL;
	if(bsm == NULL){
		eprintf ("Attempting to print an invalid RBinJavaBootStrapArgument *.\n");
		return;
	}

	printf("Bootstrap Method Information:\n");
	printf("    Offset: 0x%08llx", bsm->file_offset);
	printf("    Method Reference Index = (0x%02x)\n", bsm->bootstrap_method_ref);
	printf("    Number of Method Arguments = (0x%02x)\n", bsm->num_bootstrap_arguments);
	if (bsm->bootstrap_arguments){
		r_list_foreach_safe(bsm->bootstrap_arguments, iter, iter_tmp, bsm_arg){
			if(bsm_arg)
				r_bin_java_print_bootstrap_method_argument_summary(bsm_arg);
		}
	}
	else
		printf("    Bootstrap Method Argument: NONE \n");
}




R_API RBinJavaBootStrapArgument* r_bin_java_bootstrap_method_argument_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	RBinJavaBootStrapArgument *bsm_arg = NULL;
	ut64 offset = 0;

	bsm_arg = (RBinJavaBootStrapArgument *) malloc(sizeof(RBinJavaBootStrapArgument));
	if (bsm_arg == NULL){
		// TODO eprintf failed to allocate bytes for bootstrap_method.
		return bsm_arg;
	}
	memset(bsm_arg, 0, sizeof(RBinJavaBootStrapArgument));
	bsm_arg->file_offset = buf_offset;
	bsm_arg->argument_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	bsm_arg->argument_info_cp_obj = r_bin_java_clone_cp_idx(R_BIN_JAVA_GLOBAL_BIN, bsm_arg->argument_info_idx);
	bsm_arg->size = offset;
	return bsm_arg;

}
R_API void r_bin_java_bootstrap_method_free(RBinJavaBootStrapMethod *bsm){
	RListIter *iter, *iter_tmp;
	RBinJavaBootStrapArgument *obj = NULL;

	if (bsm){
		if (bsm->bootstrap_arguments){
			r_list_foreach_safe(bsm->bootstrap_arguments, iter, iter_tmp, obj){
				if(obj)
					r_bin_java_bootstrap_method_argument_free(obj);
				
				r_list_delete(bsm->bootstrap_arguments, iter);
			}
			r_list_free(bsm->bootstrap_arguments);
			bsm->bootstrap_arguments = NULL;
		}	
		free(bsm);
	}
}


R_API RBinJavaBootStrapMethod* r_bin_java_bootstrap_method_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	RBinJavaBootStrapMethod *bsm = NULL;
	RBinJavaBootStrapArgument *bsm_arg = NULL;
	ut32 i = 0;
	ut64 offset = 0;		


	bsm = (RBinJavaBootStrapMethod *) malloc(sizeof(RBinJavaBootStrapMethod));
	if (bsm == NULL){
		// TODO eprintf failed to allocate bytes for bootstrap_method.
		return bsm;
	}
	memset(bsm, 0, sizeof(RBinJavaBootStrapMethod));
	bsm->file_offset = buf_offset;
	
	bsm->bootstrap_method_ref = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	bsm->num_bootstrap_arguments = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;

	bsm->bootstrap_arguments = r_list_new();
	for (i = 0; i < bsm->num_bootstrap_arguments; i++){
		//bsm_arg = r_bin_java_bootstrap_method_argument_new(bin, bin->b->cur);
		bsm_arg = r_bin_java_bootstrap_method_argument_new(buffer+offset, sz-offset, buf_offset+offset);
		if(bsm_arg){
			offset += bsm_arg->size;
			r_list_append(bsm->bootstrap_arguments, (void *) bsm_arg);
		}else{
			// TODO eprintf Failed to read the %d boot strap method.
		}
	}
	bsm->size = offset;
	return bsm;

}

R_API void r_bin_java_print_bootstrap_methods_attr_summary(RBinJavaAttrInfo *attr){
	RListIter *iter, *iter_tmp;
	RBinJavaBootStrapMethod *obj = NULL;
	if (attr == NULL || attr->type == R_BIN_JAVA_ATTR_TYPE_BOOTSTRAP_METHODS_ATTR){
		eprintf("Unable to print attribue summary for RBinJavaAttrInfo *RBinJavaBootstrapMethodsAttr");
		return;
	}

	printf("Bootstrap Methods Attribute Information Information:\n");
	printf("    Attribute Offset: 0x%08llx", attr->file_offset);
	printf("    Length: 0x%08x", attr->length);
	printf("    Number of Method Arguments = (0x%02x)\n", attr->info.bootstrap_methods_attr.num_bootstrap_methods);

	if (attr->info.bootstrap_methods_attr.bootstrap_methods){
		r_list_foreach_safe(attr->info.bootstrap_methods_attr.bootstrap_methods, iter, iter_tmp, obj){
			if(obj)
				r_bin_java_print_bootstrap_method_summary(obj);
		}
	}else{
		printf("    Bootstrap Methods: NONE \n");
	}	
}

R_API void r_bin_java_bootstrap_methods_attr_free(RBinJavaAttrInfo *attr){
	RListIter *iter, *iter_tmp;
	RBinJavaBootStrapMethod *obj = NULL;
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_BOOTSTRAP_METHODS_ATTR){
		if (attr->info.bootstrap_methods_attr.bootstrap_methods){

			r_list_foreach_safe(attr->info.bootstrap_methods_attr.bootstrap_methods, iter, iter_tmp, obj){
				if(obj)
					r_bin_java_bootstrap_method_free(obj);
				
				r_list_delete(attr->info.bootstrap_methods_attr.bootstrap_methods, iter);
			}
			r_list_free(attr->info.bootstrap_methods_attr.bootstrap_methods);
			attr->info.bootstrap_methods_attr.bootstrap_methods = NULL;
		}	
		free(attr);
	}
}


R_API ut64 r_bin_java_bootstrap_methods_attr_calc_size(RBinJavaAttrInfo* attr){
	RListIter *iter, *iter_tmp;
	RBinJavaBootStrapMethod *bsm = NULL;
	ut64 size = 0;
	if (attr){
		size += 6;
		
		//attr->info.bootstrap_methods_attr.num_bootstrap_methods = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		
		r_list_foreach_safe(attr->info.bootstrap_methods_attr.bootstrap_methods, iter, iter_tmp, bsm){
			if(bsm){
				size += r_bin_java_bootstrap_method_calc_size(bsm);
			}else{
				// TODO eprintf Failed to read the %d boot strap method.
			}

		}
	}
	return size;
}

R_API ut64 r_bin_java_bootstrap_arg_calc_size(RBinJavaBootStrapArgument *bsm_arg){
	ut64 size = 0;
	if (bsm_arg){
		//bsm_arg->argument_info_idx = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
	}
	return size;
}

R_API ut64 r_bin_java_bootstrap_method_calc_size(RBinJavaBootStrapMethod *bsm){
	RListIter *iter, *iter_tmp;
	RBinJavaBootStrapArgument *bsm_arg = NULL;
	ut64 size = 0;
	if (bsm){
		size += 6;
		
		//bsm->bootstrap_method_ref = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		//bsm->num_bootstrap_arguments = R_BIN_JAVA_USHORT(buffer, offset);
		size += 2;
		
		r_list_foreach_safe(bsm->bootstrap_arguments, iter, iter_tmp, bsm_arg){
			if(bsm_arg){
				size += r_bin_java_bootstrap_arg_calc_size(bsm_arg);
			}else{
				// TODO eprintf Failed to read the %d boot strap method.
			}

		}
	}
	return size;
}

R_API RBinJavaAttrInfo* r_bin_java_bootstrap_methods_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	RBinJavaBootStrapMethod *bsm = NULL;
	ut64 offset = 0;
	
	RBinJavaAttrInfo *attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if(attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_BOOTSTRAP_METHODS_ATTR;
		attr->info.bootstrap_methods_attr.num_bootstrap_methods = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		attr->info.bootstrap_methods_attr.bootstrap_methods = r_list_new();
		for (i = 0; i < attr->info.bootstrap_methods_attr.num_bootstrap_methods; i++){
			//bsm = r_bin_java_bootstrap_method_new(bin, bin->b->cur);
			bsm = r_bin_java_bootstrap_method_new(buffer+offset, sz-offset, buf_offset+offset);
			if(bsm){
				offset += bsm->size;
				r_list_append(attr->info.bootstrap_methods_attr.bootstrap_methods, (void *) bsm);
			}else{
				// TODO eprintf Failed to read the %d boot strap method.
			}
		}
		attr->size = offset;
	}
	return attr;
}


R_API void r_bin_java_print_annotation_default_attr_summary(RBinJavaAttrInfo *attr){
	
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_ANNOTATION_DEFAULT_ATTR){
		printf("Annotation Default Attribute Information:\n");
		printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
		printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf ("   Attribute length: %d\n", attr->length);
		r_bin_java_print_element_value_summary((attr->info.annotation_default_attr.default_value));
	}else{
		// TODO: eprintf attr is invalid
	}
}

R_API void r_bin_java_annotation_array_free(RBinJavaAnnotationsArray *annotation_array){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaAnnotation *annotation;
	
	if (annotation_array->annotations == NULL){
		// TODO eprintf
		return;
	}
	r_list_foreach_safe(annotation_array->annotations, iter, iter_tmp, annotation){
		if (annotation)
			r_bin_java_annotation_free(annotation);
		r_list_delete(annotation_array->annotations, iter);
	}
	r_list_free(annotation_array->annotations);
	free(annotation_array);
}

R_API void r_bin_java_print_annotation_array_summary(RBinJavaAnnotationsArray *annotation_array){
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaAnnotation *annotation;
	
	if (annotation_array->annotations == NULL){
		// TODO eprintf
		return;
	}
	printf ("   Annotation Array Information:\n");
	printf ("   Number of Annotation Array Elements: %d\n", annotation_array->num_annotations);
	r_list_foreach_safe(annotation_array->annotations, iter, iter_tmp, annotation){
		r_bin_java_print_annotation_summary(annotation);
	}

}

R_API RBinJavaAnnotationsArray* r_bin_java_annotation_array_new(ut8* buffer, ut64 sz, ut64 buf_offset){

	RBinJavaAnnotation *annotation;
	RBinJavaAnnotationsArray *annotation_array;
	ut32 i;
	ut64 offset = 0;

	annotation_array = (RBinJavaAnnotationsArray *) malloc(sizeof(RBinJavaAnnotationsArray));
	if (annotation_array == NULL){
		// TODO eprintf
		return NULL;
	}

	annotation_array->num_annotations = R_BIN_JAVA_USHORT(buffer, offset);
	offset += 2;
	
	annotation_array->annotations = r_list_new();
	for (i=0; i < annotation_array->num_annotations; i++){
		annotation = r_bin_java_annotation_new(buffer+offset, sz-offset, buf_offset+offset);
		if (annotation){
			offset += annotation->size;
		}
		if (annotation == NULL){
			// TODO eprintf
		}
		r_list_append(annotation_array->annotations, (void *) annotation);
	}
	annotation_array->size = offset;	
	return annotation_array;
}

R_API RBinJavaAttrInfo* r_bin_java_rtv_annotations_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	RBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if(attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_ANNOTATION_ATTR; 
		
		attr->info.annotation_array.num_annotations = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;

		attr->info.annotation_array.annotations = r_list_new();
		for (i=0; i < attr->info.annotation_array.num_annotations; i++){
			RBinJavaAnnotation* annotation = r_bin_java_annotation_new(buffer+offset, sz-offset, buf_offset+offset);
			if (annotation == NULL){

			}
			if (annotation){
				offset += annotation->size;
			}
			r_list_append(attr->info.annotation_array.annotations, (void *) annotation);
		}
		attr->size = offset;
	}
	return attr;
}

R_API ut64 r_bin_java_annotation_array_calc_size(RBinJavaAnnotationsArray* annotation_array){
	ut64 size = 0;
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaAnnotation *annotation;
	
	if (annotation_array->annotations == NULL){
		// TODO eprintf
		return size;
	}
	//annotation_array->num_annotations = R_BIN_JAVA_USHORT(buffer, offset);
	size += 2;
	
	r_list_foreach_safe(annotation_array->annotations, iter, iter_tmp, annotation){
		size += r_bin_java_annotation_calc_size(annotation);
	}
	
	return size;
}

R_API ut64 r_bin_java_rtv_annotations_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	if (attr == NULL){
		// TODO eprintf allocation fail
		return size;
	}
	size += (6 + r_bin_java_annotation_array_calc_size(&(attr->info.annotation_array)));
	return size;
}


R_API RBinJavaAttrInfo*  r_bin_java_rti_annotations_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	RBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;

	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	if(attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_ANNOTATION_ATTR; 

		attr->info.annotation_array.num_annotations = R_BIN_JAVA_USHORT(buffer, offset);
		offset += 2;
		attr->info.annotation_array.annotations = r_list_new();
		for (i=0; i < attr->info.rtv_annotations_attr.num_annotations; i++){
			RBinJavaAnnotation* annotation = r_bin_java_annotation_new(buffer+offset, sz-offset, buf_offset+offset);
			if (annotation == NULL){

			}
			if (annotation)
				offset += annotation->size;
			r_list_append(attr->info.annotation_array.annotations, (void *) annotation);
		}
		attr->size = offset;
	}
	return attr;
}

R_API ut64 r_bin_java_rti_annotations_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	if (attr == NULL){
		// TODO eprintf allocation fail
		return size;
	}
	size += (6 + r_bin_java_annotation_array_calc_size(&(attr->info.annotation_array)));
	return size;
}


R_API void r_bin_java_rtv_annotations_attr_free(RBinJavaAttrInfo *attr){
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_ANNOTATION_ATTR){
		RListIter *iter = NULL, *iter_tmp = NULL;
		RBinJavaAnnotation *annotation;
	
		if (attr->info.annotation_array.annotations){

			r_list_foreach_safe(attr->info.annotation_array.annotations, iter, iter_tmp, annotation){
				if (annotation)
					r_bin_java_annotation_free(annotation);
				r_list_delete(attr->info.annotation_array.annotations, iter);
			}
			r_list_free(attr->info.annotation_array.annotations);
		}
		free(attr);
	}
}
R_API void r_bin_java_rti_annotations_attr_free(RBinJavaAttrInfo *attr){
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_ANNOTATION_ATTR){ 
		RListIter *iter = NULL, *iter_tmp = NULL;
		RBinJavaAnnotation *annotation;
	
		if (attr->info.annotation_array.annotations){

			r_list_foreach_safe(attr->info.annotation_array.annotations, iter, iter_tmp, annotation){
				if (annotation)
					r_bin_java_annotation_free(annotation);
				r_list_delete(attr->info.annotation_array.annotations, iter);
			}
			r_list_free(attr->info.annotation_array.annotations);
		}
		free(attr);
	}
}

R_API void r_bin_java_print_rtv_annotations_attr_summary(RBinJavaAttrInfo *attr){
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_ANNOTATION_ATTR){
		printf("Runtime Visible Annotations Attribute Information:\n");
		printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
		printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf ("   Attribute length: %d\n", attr->length);
		r_bin_java_print_annotation_array_summary(&attr->info.annotation_array);
	}
}
R_API void r_bin_java_print_rti_annotations_attr_summary(RBinJavaAttrInfo *attr){
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_ANNOTATION_ATTR){ 
		printf("Runtime Invisible Annotations Attribute Information:\n");
		printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
		printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf ("   Attribute length: %d\n", attr->length);
		r_bin_java_print_annotation_array_summary(&attr->info.annotation_array);
	}
}

R_API ut64 r_bin_java_rtip_annotations_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaAnnotationsArray *annotation_array;
	if (attr == NULL){
		// TODO eprintf allocation fail
		return size;
	}
	//attr->info.rtip_annotations_attr.num_parameters = buffer[offset];
	size += (6 + 1);
	r_list_foreach_safe(attr->info.rtip_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array){
		if(annotation_array)
			size += r_bin_java_annotation_array_calc_size(annotation_array);
	}
	return size;
}

R_API RBinJavaAttrInfo* r_bin_java_rtip_annotations_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	RBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	
	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	RBinJavaAnnotationsArray *annotation_array;

	if(attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR; 
		attr->info.rtip_annotations_attr.num_parameters = buffer[offset];
		offset += 1;
		
		attr->info.rtip_annotations_attr.parameter_annotations = r_list_new();
		for (i=0; i < attr->info.rtip_annotations_attr.num_parameters; i++){
			annotation_array = r_bin_java_annotation_array_new(buffer+offset, sz-offset, buf_offset+offset);
			if (annotation_array == NULL){

			}
			if (annotation_array)
				offset += annotation_array->size;

			r_list_append(attr->info.rtip_annotations_attr.parameter_annotations, (void *) annotation_array);
		}
		attr->size = offset;
	}
	return attr;
}



R_API RBinJavaAttrInfo* r_bin_java_rtvp_annotations_attr_new(ut8* buffer, ut64 sz, ut64 buf_offset){
	ut32 i = 0;
	RBinJavaAttrInfo *attr = NULL;
	ut64 offset = 0;
	
	attr = r_bin_java_default_attr_new(buffer, sz, buf_offset);
	offset += 6;

	RBinJavaAnnotationsArray *annotation_array;
	
	if(attr){
		attr->type = R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR; 
		
		attr->info.rtvp_annotations_attr.num_parameters = buffer[offset];
		offset += 1;
		
		attr->info.rtvp_annotations_attr.parameter_annotations = r_list_new();
		
		for (i=0; i < attr->info.rtvp_annotations_attr.num_parameters; i++){
			annotation_array = r_bin_java_annotation_array_new(buffer+offset, sz-offset, buf_offset+offset);
			if (annotation_array == NULL){

			}
			if (annotation_array)
				offset += annotation_array->size;

			r_list_append(attr->info.rtvp_annotations_attr.parameter_annotations, (void *) annotation_array);
		}
		attr->size = offset;
	}
	return attr;
}

R_API ut64 r_bin_java_rtvp_annotations_attr_calc_size(RBinJavaAttrInfo* attr){
	ut64 size = 0;
	RListIter *iter = NULL, *iter_tmp = NULL;
	RBinJavaAnnotationsArray *annotation_array;
	if (!attr) return size;
	size += (6+ 1);
	r_list_foreach_safe (attr->info.rtvp_annotations_attr.parameter_annotations,
			iter, iter_tmp, annotation_array) {
		if (annotation_array)
			size += r_bin_java_annotation_array_calc_size (
				annotation_array);
	}
	return size;
}


R_API void r_bin_java_rtvp_annotations_attr_free(RBinJavaAttrInfo *attr){
	RBinJavaAnnotationsArray *annotation_array = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if (attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR){
		if (attr->info.rtvp_annotations_attr.parameter_annotations){
			r_list_foreach_safe(attr->info.rtvp_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array){
				if (annotation_array)
					r_bin_java_annotation_array_free(annotation_array);

				r_list_delete(attr->info.rtvp_annotations_attr.parameter_annotations, iter);	
			}
			r_list_free(attr->info.rtvp_annotations_attr.parameter_annotations);				
		}
	}	
}
R_API void r_bin_java_rtip_annotations_attr_free(RBinJavaAttrInfo *attr){
	RBinJavaAnnotationsArray *annotation_array = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR){
		if (attr->info.rtip_annotations_attr.parameter_annotations){
			r_list_foreach_safe(attr->info.rtip_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array){
				if (annotation_array)
					r_bin_java_annotation_array_free(annotation_array);

				r_list_delete(attr->info.rtip_annotations_attr.parameter_annotations, iter);	
			}
			r_list_free(attr->info.rtip_annotations_attr.parameter_annotations);				
		}
	}	
}

R_API void r_bin_java_print_rtvp_annotations_attr_summary(RBinJavaAttrInfo *attr){
	RBinJavaAnnotationsArray *annotation_array = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_VISIBLE_PARAMETER_ANNOTATION_ATTR){
		printf("Runtime Visible Parameter Annotations Attribute Information:\n");
		printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
		printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf ("   Attribute length: %d\n", attr->length);
		printf ("   Number of Runtime Invisible Parameters: %d\n", attr->info.rtvp_annotations_attr.num_parameters);
		r_list_foreach_safe(attr->info.rtvp_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array){
			r_bin_java_print_annotation_array_summary(annotation_array);	
		}		
	}
}
R_API void r_bin_java_print_rtip_annotations_attr_summary(RBinJavaAttrInfo *attr){
	RBinJavaAnnotationsArray *annotation_array = NULL;
	RListIter *iter = NULL, *iter_tmp = NULL;
	if(attr && attr->type == R_BIN_JAVA_ATTR_TYPE_RUNTIME_INVISIBLE_PARAMETER_ANNOTATION_ATTR){
		printf("Runtime Invisible Parameter Annotations Attribute Information:\n");
		printf ("   Attribute Offset: 0x%08llx\n", attr->file_offset);	
		printf ("   Attribute Name Index: %d (%s)\n", attr->name_idx, attr->name);
		printf ("   Attribute length: %d\n", attr->length);
		printf ("   Number of Runtime Invisible Parameters: %d\n", attr->info.rtip_annotations_attr.num_parameters);
		r_list_foreach_safe(attr->info.rtip_annotations_attr.parameter_annotations, iter, iter_tmp, annotation_array){
			r_bin_java_print_annotation_array_summary(annotation_array);	
		}		
	}
}

R_API RBinJavaCPTypeObj *r_bin_java_find_cp_name_and_type_info(ut16 name_idx, ut16 descriptor_idx){
	RListIter *iter, *iter_tmp;
	RBinJavaCPTypeObj *result= NULL, *obj = NULL;

	r_list_foreach_safe(R_BIN_JAVA_GLOBAL_BIN->cp_list, iter, iter_tmp, obj){
		if(obj && obj->tag == R_BIN_JAVA_CP_NAMEANDTYPE){
			if (obj->info.cp_name_and_type.name_idx == name_idx &&
				obj->info.cp_name_and_type.descriptor_idx == descriptor_idx){
				result = obj;
				break;
			}

		}
	}
	return result;
}

R_API RBinJavaCPTypeObj *r_bin_java_find_cp_ref_info_from_name_and_type(ut16 name_idx, ut16 descriptor_idx){
	RBinJavaCPTypeObj *result= NULL, 
	                   *obj = r_bin_java_find_cp_name_and_type_info(name_idx, descriptor_idx);
	if(obj)
		result = r_bin_java_find_cp_ref_info(obj->metas->ord);
	return result;
}


R_API RBinJavaCPTypeObj *r_bin_java_find_cp_ref_info(ut16 name_and_type_idx){
	RListIter *iter, *iter_tmp;
	RBinJavaCPTypeObj *result= NULL, *obj = NULL;

	r_list_foreach_safe(R_BIN_JAVA_GLOBAL_BIN->cp_list, iter, iter_tmp, obj){
		if(obj == NULL){
			continue;
		} else if (obj->tag == R_BIN_JAVA_CP_FIELDREF &&
				obj->info.cp_field.name_and_type_idx == name_and_type_idx){
			result = obj;
			break;

		} else if (obj->tag == R_BIN_JAVA_CP_METHODREF &&
				obj->info.cp_method.name_and_type_idx == name_and_type_idx){
			result = obj;
			break;
		}
	}
	return result;
}
