/* radare - LGPL - Copyright 2011-2026 - pancake */

#ifndef R2_JAVA_DESCRIPTOR_H
#define R2_JAVA_DESCRIPTOR_H

#include <r_bin.h>

typedef enum {
	R_JAVA_TYPE_INVALID,
	R_JAVA_TYPE_VOID,
	R_JAVA_TYPE_BOOLEAN,
	R_JAVA_TYPE_BYTE,
	R_JAVA_TYPE_CHAR,
	R_JAVA_TYPE_SHORT,
	R_JAVA_TYPE_INT,
	R_JAVA_TYPE_LONG,
	R_JAVA_TYPE_FLOAT,
	R_JAVA_TYPE_DOUBLE,
	R_JAVA_TYPE_OBJECT,
} RJavaTypeKind;

typedef enum {
	R_JAVA_MEMBER_CLASS,
	R_JAVA_MEMBER_FIELD,
	R_JAVA_MEMBER_METHOD,
} RJavaMemberKind;

typedef struct r_java_type_t {
	RJavaTypeKind kind;
	char *class_name; // JVM internal name for object types
	char *name; // Java display name
	char *jni_name;
	ut16 slots;
	ut8 array_dimensions;
} RJavaType;

typedef struct r_java_member_t {
	RJavaMemberKind kind;
	char *class_name;
	char *name;
	char *descriptor;
	ut32 access_flags; // raw JVM access_flags
	RBinAttr attr; // access_flags normalized to R_BIN_ATTR_*
	RJavaType *type; // field type or method return type
	RList/*<RJavaType *>*/ *arguments; // method arguments
	char *visibility;
	char *definition;
	char *jni_definition;
	ut16 argument_slots;
	ut16 return_slots;
} RJavaMember;

R_API RJavaMember *r_java_member_parse(const char *class_name, const char *name, const char *descriptor, RJavaMemberKind kind, ut32 access_flags);
R_API void r_java_member_free(RJavaMember *member);

#endif
