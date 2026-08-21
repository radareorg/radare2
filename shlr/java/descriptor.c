/* radare - LGPL - Copyright 2011-2026 - pancake */

#include <r_bin.h>

// JVM access_flags shared by classes, fields and methods.
#define JAVA_ACC_PUBLIC 0x0001
#define JAVA_ACC_PRIVATE 0x0002
#define JAVA_ACC_PROTECTED 0x0004
#define JAVA_ACC_STATIC 0x0008
#define JAVA_ACC_FINAL 0x0010
#define JAVA_ACC_SUPER_SYNCHRONIZED 0x0020
#define JAVA_ACC_VOLATILE_BRIDGE 0x0040
#define JAVA_ACC_TRANSIENT_VARARGS 0x0080
#define JAVA_ACC_NATIVE 0x0100
#define JAVA_ACC_INTERFACE 0x0200
#define JAVA_ACC_ABSTRACT 0x0400
#define JAVA_ACC_STRICT 0x0800
#define JAVA_ACC_SYNTHETIC 0x1000
#define JAVA_ACC_ANNOTATION 0x2000
#define JAVA_ACC_ENUM 0x4000
#define JAVA_ACC_HIDDEN 0x04000000

typedef enum {
	JAVA_STYLE_DISPLAY,
	JAVA_STYLE_JNI,
} JavaTypeStyle;

static const char *java_type_name(RBinJavaTypeKind kind, JavaTypeStyle style) {
	if (style == JAVA_STYLE_JNI) {
		switch (kind) {
		case R_BIN_JAVA_TYPE_VOID: return "void";
		case R_BIN_JAVA_TYPE_BOOLEAN: return "jboolean";
		case R_BIN_JAVA_TYPE_BYTE: return "jbyte";
		case R_BIN_JAVA_TYPE_CHAR: return "jchar";
		case R_BIN_JAVA_TYPE_SHORT: return "jshort";
		case R_BIN_JAVA_TYPE_INT: return "jint";
		case R_BIN_JAVA_TYPE_LONG: return "jlong";
		case R_BIN_JAVA_TYPE_FLOAT: return "jfloat";
		case R_BIN_JAVA_TYPE_DOUBLE: return "jdouble";
		default: return NULL;
		}
	}
	switch (kind) {
	case R_BIN_JAVA_TYPE_VOID: return "void";
	case R_BIN_JAVA_TYPE_BOOLEAN: return "boolean";
	case R_BIN_JAVA_TYPE_BYTE: return "byte";
	case R_BIN_JAVA_TYPE_CHAR: return "char";
	case R_BIN_JAVA_TYPE_SHORT: return "short";
	case R_BIN_JAVA_TYPE_INT: return "int";
	case R_BIN_JAVA_TYPE_LONG: return "long";
	case R_BIN_JAVA_TYPE_FLOAT: return "float";
	case R_BIN_JAVA_TYPE_DOUBLE: return "double";
	default: return NULL;
	}
}

static const char *java_jni_array_name(RBinJavaTypeKind kind) {
	switch (kind) {
	case R_BIN_JAVA_TYPE_BOOLEAN: return "jbooleanArray";
	case R_BIN_JAVA_TYPE_BYTE: return "jbyteArray";
	case R_BIN_JAVA_TYPE_CHAR: return "jcharArray";
	case R_BIN_JAVA_TYPE_SHORT: return "jshortArray";
	case R_BIN_JAVA_TYPE_INT: return "jintArray";
	case R_BIN_JAVA_TYPE_LONG: return "jlongArray";
	case R_BIN_JAVA_TYPE_FLOAT: return "jfloatArray";
	case R_BIN_JAVA_TYPE_DOUBLE: return "jdoubleArray";
	default: return "jobjectArray";
	}
}

static char *java_type_tostring(const RBinJavaType *type, JavaTypeStyle style) {
	if (style == JAVA_STYLE_JNI && type->array_dimensions) {
		return strdup (type->array_dimensions == 1? java_jni_array_name (type->kind): "jobjectArray");
	}
	char *result = NULL;
	if (type->kind == R_BIN_JAVA_TYPE_OBJECT) {
		if (style == JAVA_STYLE_JNI) {
			if (!strcmp (type->class_name, "java/lang/String")) {
				return strdup ("jstring");
			}
			if (!strcmp (type->class_name, "java/lang/Class")) {
				return strdup ("jclass");
			}
			if (!strcmp (type->class_name, "java/lang/Throwable")) {
				return strdup ("jthrowable");
			}
			return strdup ("jobject");
		}
		result = strdup (type->class_name);
		r_str_replace_char (result, '/', '.');
	} else {
		const char *name = java_type_name (type->kind, style);
		if (!name) {
			return NULL;
		}
		result = strdup (name);
	}
	if (style == JAVA_STYLE_DISPLAY && type->array_dimensions) {
		RStrBuf *sb = r_strbuf_new (result);
		ut8 i;
		for (i = 0; i < type->array_dimensions; i++) {
			r_strbuf_append (sb, "[]");
		}
		free (result);
		result = r_strbuf_drain (sb);
	}
	return result;
}

static void java_type_free(void *ptr) {
	RBinJavaType *type = ptr;
	if (type) {
		free (type->class_name);
		free (type->name);
		free (type->jni_name);
		free (type);
	}
}

static bool java_class_name_valid(const char *name, size_t len) {
	if (!len || name[0] == '/' || name[len - 1] == '/') {
		return false;
	}
	size_t i;
	for (i = 0; i < len; i++) {
		const ut8 ch = name[i];
		if (ch <= 0x20 || ch == '.' || ch == '[' || ch == ';' || ch == '(' || ch == ')' || ch == '\\') {
			return false;
		}
		if (ch == '/' && (i + 1 == len || name[i + 1] == '/')) {
			return false;
		}
	}
	return true;
}

static RBinJavaType *java_type_new(RBinJavaTypeKind kind, char *class_name, ut32 dimensions) {
	RBinJavaType *type = R_NEW0 (RBinJavaType);
	type->kind = kind;
	type->class_name = class_name;
	type->array_dimensions = dimensions;
	if (dimensions) {
		type->slots = 1;
	} else if (kind == R_BIN_JAVA_TYPE_VOID) {
		type->slots = 0;
	} else {
		type->slots = kind == R_BIN_JAVA_TYPE_LONG || kind == R_BIN_JAVA_TYPE_DOUBLE? 2: 1;
	}
	type->name = java_type_tostring (type, JAVA_STYLE_DISPLAY);
	type->jni_name = java_type_tostring (type, JAVA_STYLE_JNI);
	return type;
}

static RBinJavaType *java_type_parse(const char **cursor, bool allow_void) {
	const char *p = *cursor;
	ut32 dimensions = 0;
	while (*p == '[') {
		if (++dimensions > 255) {
			return NULL;
		}
		p++;
	}
	RBinJavaTypeKind kind = R_BIN_JAVA_TYPE_INVALID;
	switch (*p) {
	case 'V':
		if (!allow_void || dimensions) {
			return NULL;
		}
		kind = R_BIN_JAVA_TYPE_VOID;
		p++;
		break;
	case 'Z': kind = R_BIN_JAVA_TYPE_BOOLEAN; p++; break;
	case 'B': kind = R_BIN_JAVA_TYPE_BYTE; p++; break;
	case 'C': kind = R_BIN_JAVA_TYPE_CHAR; p++; break;
	case 'S': kind = R_BIN_JAVA_TYPE_SHORT; p++; break;
	case 'I': kind = R_BIN_JAVA_TYPE_INT; p++; break;
	case 'J': kind = R_BIN_JAVA_TYPE_LONG; p++; break;
	case 'F': kind = R_BIN_JAVA_TYPE_FLOAT; p++; break;
	case 'D': kind = R_BIN_JAVA_TYPE_DOUBLE; p++; break;
	case 'L':
		{
			const char *name = ++p;
			const char *end = strchr (name, ';');
			if (!end || !java_class_name_valid (name, end - name)) {
				return NULL;
			}
			*cursor = end + 1;
			return java_type_new (R_BIN_JAVA_TYPE_OBJECT, r_str_ndup (name, end - name), dimensions);
		}
	default:
		return NULL;
	}
	*cursor = p;
	return java_type_new (kind, NULL, dimensions);
}

static RBinAttribute java_access_flags(RBinJavaMemberKind kind, ut32 access_flags) {
	RBinAttribute attr = R_BIN_ATTR_NONE;
	if (access_flags & JAVA_ACC_PUBLIC) {
		attr |= R_BIN_ATTR_PUBLIC;
	} else if (access_flags & JAVA_ACC_PRIVATE) {
		attr |= R_BIN_ATTR_PRIVATE;
	} else if (access_flags & JAVA_ACC_PROTECTED) {
		attr |= R_BIN_ATTR_PROTECTED;
	}
	if (access_flags & JAVA_ACC_STATIC) {
		attr |= R_BIN_ATTR_STATIC;
	}
	if (access_flags & JAVA_ACC_FINAL) {
		attr |= R_BIN_ATTR_FINAL;
	}
	if (access_flags & JAVA_ACC_SYNTHETIC) {
		attr |= R_BIN_ATTR_SYNTHETIC;
	}
	if (kind == R_BIN_JAVA_MEMBER_CLASS) {
		if (access_flags & JAVA_ACC_SUPER_SYNCHRONIZED) {
			attr |= R_BIN_ATTR_SUPER;
		}
		if (access_flags & JAVA_ACC_INTERFACE) {
			attr |= R_BIN_ATTR_INTERFACE;
		}
		if (access_flags & JAVA_ACC_ABSTRACT) {
			attr |= R_BIN_ATTR_ABSTRACT;
		}
		if (access_flags & JAVA_ACC_ANNOTATION) {
			attr |= R_BIN_ATTR_ANNOTATION;
		}
		if (access_flags & JAVA_ACC_ENUM) {
			attr |= R_BIN_ATTR_ENUM;
		}
		if (access_flags & JAVA_ACC_HIDDEN) {
			attr |= R_BIN_ATTR_HIDDEN;
		}
	} else if (kind == R_BIN_JAVA_MEMBER_FIELD) {
		if (access_flags & JAVA_ACC_VOLATILE_BRIDGE) {
			attr |= R_BIN_ATTR_VOLATILE;
		}
		if (access_flags & JAVA_ACC_TRANSIENT_VARARGS) {
			attr |= R_BIN_ATTR_TRANSIENT;
		}
		if (access_flags & JAVA_ACC_ENUM) {
			attr |= R_BIN_ATTR_ENUM;
		}
	} else if (kind == R_BIN_JAVA_MEMBER_METHOD) {
		if (access_flags & JAVA_ACC_SUPER_SYNCHRONIZED) {
			attr |= R_BIN_ATTR_SYNCHRONIZED;
		}
		if (access_flags & JAVA_ACC_VOLATILE_BRIDGE) {
			attr |= R_BIN_ATTR_BRIDGE;
		}
		if (access_flags & JAVA_ACC_TRANSIENT_VARARGS) {
			attr |= R_BIN_ATTR_VARARGS;
		}
		if (access_flags & JAVA_ACC_NATIVE) {
			attr |= R_BIN_ATTR_NATIVE;
		}
		if (access_flags & JAVA_ACC_ABSTRACT) {
			attr |= R_BIN_ATTR_ABSTRACT;
		}
		if (access_flags & JAVA_ACC_STRICT) {
			attr |= R_BIN_ATTR_STRICT;
		}
	}
	return attr;
}

static const char *java_visibility(RBinAttribute attr) {
	if (attr & R_BIN_ATTR_PUBLIC) {
		return "public";
	}
	if (attr & R_BIN_ATTR_PRIVATE) {
		return "private";
	}
	if (attr & R_BIN_ATTR_PROTECTED) {
		return "protected";
	}
	return "package";
}

static void java_member_attributes_tostring(RStrBuf *sb, RBinAttribute attr) {
	if (attr & R_BIN_ATTR_PUBLIC) {
		r_strbuf_append (sb, "public ");
	} else if (attr & R_BIN_ATTR_PRIVATE) {
		r_strbuf_append (sb, "private ");
	} else if (attr & R_BIN_ATTR_PROTECTED) {
		r_strbuf_append (sb, "protected ");
	}
	if (attr & R_BIN_ATTR_STATIC) {
		r_strbuf_append (sb, "static ");
	}
	if (attr & R_BIN_ATTR_FINAL) {
		r_strbuf_append (sb, "final ");
	}
	if (attr & R_BIN_ATTR_SYNCHRONIZED) {
		r_strbuf_append (sb, "synchronized ");
	}
	if (attr & R_BIN_ATTR_VOLATILE) {
		r_strbuf_append (sb, "volatile ");
	}
	if (attr & R_BIN_ATTR_TRANSIENT) {
		r_strbuf_append (sb, "transient ");
	}
	if (attr & R_BIN_ATTR_NATIVE) {
		r_strbuf_append (sb, "native ");
	}
	if (attr & R_BIN_ATTR_ABSTRACT) {
		r_strbuf_append (sb, "abstract ");
	}
	if (attr & R_BIN_ATTR_STRICT) {
		r_strbuf_append (sb, "strictfp ");
	}
}

static char *java_member_name(const RBinJavaMember *member) {
	RStrBuf *sb = r_strbuf_new (NULL);
	if (R_STR_ISNOTEMPTY (member->class_name)) {
		char *class_name = strdup (member->class_name);
		r_str_replace_char (class_name, '/', '.');
		r_strbuf_append (sb, class_name);
		r_strbuf_append (sb, ".");
		free (class_name);
	}
	if (member->kind == R_BIN_JAVA_MEMBER_CLASS) {
		char *name = strdup (r_str_get (member->name));
		r_str_replace_char (name, '/', '.');
		r_strbuf_append (sb, name);
		free (name);
	} else {
		r_strbuf_append (sb, r_str_get (member->name));
	}
	return r_strbuf_drain (sb);
}

static char *java_member_tostring(const RBinJavaMember *member, JavaTypeStyle style) {
	RStrBuf *sb = r_strbuf_new (NULL);
	java_member_attributes_tostring (sb, member->attr.flags);
	char *name = java_member_name (member);
	if (member->kind == R_BIN_JAVA_MEMBER_CLASS) {
		if (member->attr.flags & R_BIN_ATTR_ANNOTATION) {
			r_strbuf_append (sb, "@interface ");
		} else if (member->attr.flags & R_BIN_ATTR_INTERFACE) {
			r_strbuf_append (sb, "interface ");
		} else if (member->attr.flags & R_BIN_ATTR_ENUM) {
			r_strbuf_append (sb, "enum ");
		} else {
			r_strbuf_append (sb, "class ");
		}
		r_strbuf_append (sb, name);
		free (name);
		return r_strbuf_drain (sb);
	}
	const char *type = style == JAVA_STYLE_JNI? member->type->jni_name: member->type->name;
	r_strbuf_append (sb, type);
	if (R_STR_ISNOTEMPTY (name)) {
		r_strbuf_appendf (sb, " %s", name);
	}
	free (name);
	if (member->kind == R_BIN_JAVA_MEMBER_METHOD) {
		r_strbuf_append (sb, " (");
		RListIter *iter;
		RBinJavaType *argument;
		bool first = true;
		r_list_foreach (member->arguments, iter, argument) {
			if (!first) {
				r_strbuf_append (sb, ", ");
			}
			r_strbuf_append (sb, style == JAVA_STYLE_JNI? argument->jni_name: argument->name);
			first = false;
		}
		r_strbuf_append (sb, ")");
	}
	return r_strbuf_drain (sb);
}

R_API void r_bin_java_member_free(RBinJavaMember *member) {
	if (member) {
		free (member->class_name);
		free (member->name);
		free (member->descriptor);
		free (member->attr.ns);
		java_type_free (member->type);
		r_list_free (member->arguments);
		free (member->visibility);
		free (member->definition);
		free (member->jni_definition);
		free (member);
	}
}

R_API RBinJavaMember *r_bin_java_member_parse(const char *class_name, const char *name, const char *descriptor, RBinJavaMemberKind kind, ut32 access_flags) {
	if (kind < R_BIN_JAVA_MEMBER_CLASS || kind > R_BIN_JAVA_MEMBER_METHOD) {
		return NULL;
	}
	RBinJavaMember *member = R_NEW0 (RBinJavaMember);
	member->kind = kind;
	member->class_name = R_STR_ISNOTEMPTY (class_name)? strdup (class_name): NULL;
	member->name = R_STR_ISNOTEMPTY (name)? strdup (name): NULL;
	member->access_flags = access_flags;
	member->attr.flags = java_access_flags (kind, access_flags);
	member->attr.lang = R_BIN_LANG_JAVA;
	member->visibility = strdup (java_visibility (member->attr.flags));
	if (kind == R_BIN_JAVA_MEMBER_CLASS) {
		if (!member->name || R_STR_ISNOTEMPTY (descriptor)) {
			r_bin_java_member_free (member);
			return NULL;
		}
		member->definition = java_member_tostring (member, JAVA_STYLE_DISPLAY);
		member->jni_definition = java_member_tostring (member, JAVA_STYLE_JNI);
		return member;
	}
	if (R_STR_ISEMPTY (descriptor)) {
		r_bin_java_member_free (member);
		return NULL;
	}
	member->descriptor = strdup (descriptor);
	const char *p = descriptor;
	if (kind == R_BIN_JAVA_MEMBER_FIELD) {
		member->type = java_type_parse (&p, false);
		if (!member->type || *p) {
			r_bin_java_member_free (member);
			return NULL;
		}
		member->definition = java_member_tostring (member, JAVA_STYLE_DISPLAY);
		member->jni_definition = java_member_tostring (member, JAVA_STYLE_JNI);
		return member;
	}
	if (*p++ != '(') {
		r_bin_java_member_free (member);
		return NULL;
	}
	member->arguments = r_list_newf (java_type_free);
	while (*p && *p != ')') {
		RBinJavaType *argument = java_type_parse (&p, false);
		if (!argument || member->argument_slots > UT16_MAX - argument->slots) {
			java_type_free (argument);
			r_bin_java_member_free (member);
			return NULL;
		}
		member->argument_slots += argument->slots;
		r_list_append (member->arguments, argument);
	}
	if (*p++ != ')') {
		r_bin_java_member_free (member);
		return NULL;
	}
	member->type = java_type_parse (&p, true);
	if (!member->type || *p) {
		r_bin_java_member_free (member);
		return NULL;
	}
	member->return_slots = member->type->slots;
	if (member->name && !strcmp (member->name, "<init>")) {
		member->attr.flags |= R_BIN_ATTR_CONSTRUCTOR;
	} else if (member->name && !strcmp (member->name, "<clinit>")) {
		member->attr.flags |= R_BIN_ATTR_STATIC;
	}
	member->definition = java_member_tostring (member, JAVA_STYLE_DISPLAY);
	member->jni_definition = java_member_tostring (member, JAVA_STYLE_JNI);
	return member;
}
