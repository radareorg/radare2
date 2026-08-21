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

// indexed by RBinJavaTypeKind - R_BIN_JAVA_TYPE_VOID
static const struct {
	char tag;
	ut8 slots;
	const char *name;
	const char *jni_name;
} java_primitives[] = {
	{ 'V', 0, "void", "void" },
	{ 'Z', 1, "boolean", "jboolean" },
	{ 'B', 1, "byte", "jbyte" },
	{ 'C', 1, "char", "jchar" },
	{ 'S', 1, "short", "jshort" },
	{ 'I', 1, "int", "jint" },
	{ 'J', 2, "long", "jlong" },
	{ 'F', 1, "float", "jfloat" },
	{ 'D', 2, "double", "jdouble" },
};

static const char *java_type_name(RBinJavaTypeKind kind, JavaTypeStyle style) {
	const int idx = (int)kind - R_BIN_JAVA_TYPE_VOID;
	if (idx < 0 || idx >= (int)R_ARRAY_SIZE (java_primitives)) {
		return NULL;
	}
	return style == JAVA_STYLE_JNI? java_primitives[idx].jni_name: java_primitives[idx].name;
}

static char *java_type_tostring(const RBinJavaType *type, JavaTypeStyle style) {
	if (style == JAVA_STYLE_JNI && type->array_dimensions) {
		const char *elem = type->array_dimensions == 1? java_type_name (type->kind, JAVA_STYLE_JNI): NULL;
		return elem? r_str_newf ("%sArray", elem): strdup ("jobjectArray");
	}
	char *result = NULL;
	if (type->kind == R_BIN_JAVA_TYPE_OBJECT) {
		if (style == JAVA_STYLE_JNI) {
			const char *cn = type->class_name;
			return strdup (!strcmp (cn, "java/lang/String")? "jstring"
				: !strcmp (cn, "java/lang/Class")? "jclass"
				: !strcmp (cn, "java/lang/Throwable")? "jthrowable": "jobject");
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
	type->slots = 1;
	if (!dimensions && kind != R_BIN_JAVA_TYPE_OBJECT) {
		type->slots = java_primitives[kind - R_BIN_JAVA_TYPE_VOID].slots;
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
	if (*p == 'L') {
		const char *name = ++p;
		const char *end = strchr (name, ';');
		if (!end || !java_class_name_valid (name, end - name)) {
			return NULL;
		}
		*cursor = end + 1;
		return java_type_new (R_BIN_JAVA_TYPE_OBJECT, r_str_ndup (name, end - name), dimensions);
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (java_primitives); i++) {
		if (*p == java_primitives[i].tag) {
			break;
		}
	}
	const RBinJavaTypeKind kind = R_BIN_JAVA_TYPE_VOID + i;
	if (i == R_ARRAY_SIZE (java_primitives) || (kind == R_BIN_JAVA_TYPE_VOID && (!allow_void || dimensions))) {
		return NULL;
	}
	*cursor = p + 1;
	return java_type_new (kind, NULL, dimensions);
}

#define JK_C (1 << R_BIN_JAVA_MEMBER_CLASS)
#define JK_F (1 << R_BIN_JAVA_MEMBER_FIELD)
#define JK_M (1 << R_BIN_JAVA_MEMBER_METHOD)
#define JK_ANY (JK_C | JK_F | JK_M)

// the same JVM bit maps to different attributes depending on the member kind
static const struct {
	ut32 acc;
	RBinAttribute attr;
	ut8 kinds;
} java_attr_bits[] = {
	{ JAVA_ACC_STATIC, R_BIN_ATTR_STATIC, JK_ANY },
	{ JAVA_ACC_FINAL, R_BIN_ATTR_FINAL, JK_ANY },
	{ JAVA_ACC_SYNTHETIC, R_BIN_ATTR_SYNTHETIC, JK_ANY },
	{ JAVA_ACC_SUPER_SYNCHRONIZED, R_BIN_ATTR_SUPER, JK_C },
	{ JAVA_ACC_SUPER_SYNCHRONIZED, R_BIN_ATTR_SYNCHRONIZED, JK_M },
	{ JAVA_ACC_VOLATILE_BRIDGE, R_BIN_ATTR_VOLATILE, JK_F },
	{ JAVA_ACC_VOLATILE_BRIDGE, R_BIN_ATTR_BRIDGE, JK_M },
	{ JAVA_ACC_TRANSIENT_VARARGS, R_BIN_ATTR_TRANSIENT, JK_F },
	{ JAVA_ACC_TRANSIENT_VARARGS, R_BIN_ATTR_VARARGS, JK_M },
	{ JAVA_ACC_NATIVE, R_BIN_ATTR_NATIVE, JK_M },
	{ JAVA_ACC_INTERFACE, R_BIN_ATTR_INTERFACE, JK_C },
	{ JAVA_ACC_ABSTRACT, R_BIN_ATTR_ABSTRACT, JK_C | JK_M },
	{ JAVA_ACC_STRICT, R_BIN_ATTR_STRICT, JK_M },
	{ JAVA_ACC_ANNOTATION, R_BIN_ATTR_ANNOTATION, JK_C },
	{ JAVA_ACC_ENUM, R_BIN_ATTR_ENUM, JK_C | JK_F },
	{ JAVA_ACC_HIDDEN, R_BIN_ATTR_HIDDEN, JK_C },
};

static RBinAttribute java_access_flags(RBinJavaMemberKind kind, ut32 access_flags) {
	RBinAttribute attr = R_BIN_ATTR_NONE;
	if (access_flags & JAVA_ACC_PUBLIC) {
		attr |= R_BIN_ATTR_PUBLIC;
	} else if (access_flags & JAVA_ACC_PRIVATE) {
		attr |= R_BIN_ATTR_PRIVATE;
	} else if (access_flags & JAVA_ACC_PROTECTED) {
		attr |= R_BIN_ATTR_PROTECTED;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (java_attr_bits); i++) {
		if ((java_attr_bits[i].kinds & (1 << kind)) && (access_flags & java_attr_bits[i].acc)) {
			attr |= java_attr_bits[i].attr;
		}
	}
	return attr;
}

static const char *java_visibility(RBinAttribute attr) {
	return (attr & R_BIN_ATTR_PUBLIC)? "public"
		: (attr & R_BIN_ATTR_PRIVATE)? "private"
		: (attr & R_BIN_ATTR_PROTECTED)? "protected": "package";
}

static const struct {
	RBinAttribute attr;
	const char *keyword;
} java_keywords[] = {
	{ R_BIN_ATTR_STATIC, "static" },
	{ R_BIN_ATTR_FINAL, "final" },
	{ R_BIN_ATTR_SYNCHRONIZED, "synchronized" },
	{ R_BIN_ATTR_VOLATILE, "volatile" },
	{ R_BIN_ATTR_TRANSIENT, "transient" },
	{ R_BIN_ATTR_NATIVE, "native" },
	{ R_BIN_ATTR_ABSTRACT, "abstract" },
	{ R_BIN_ATTR_STRICT, "strictfp" },
};

static void java_member_attributes_tostring(RStrBuf *sb, RBinAttribute attr) {
	if (attr & (R_BIN_ATTR_PUBLIC | R_BIN_ATTR_PRIVATE | R_BIN_ATTR_PROTECTED)) {
		r_strbuf_appendf (sb, "%s ", java_visibility (attr));
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (java_keywords); i++) {
		if (attr & java_keywords[i].attr) {
			r_strbuf_appendf (sb, "%s ", java_keywords[i].keyword);
		}
	}
}

static char *java_member_name(const RBinJavaMember *member) {
	// '/' only occurs in class names; unqualified member names cannot contain it
	const char *dot = R_STR_ISNOTEMPTY (member->class_name)? ".": "";
	char *name = r_str_newf ("%s%s%s", r_str_get (member->class_name), dot, r_str_get (member->name));
	r_str_replace_char (name, '/', '.');
	return name;
}

static char *java_member_tostring(const RBinJavaMember *member, JavaTypeStyle style) {
	RStrBuf *sb = r_strbuf_new (NULL);
	java_member_attributes_tostring (sb, member->attr.flags);
	char *name = java_member_name (member);
	if (member->kind == R_BIN_JAVA_MEMBER_CLASS) {
		const RBinAttribute flags = member->attr.flags;
		const char *keyword = (flags & R_BIN_ATTR_ANNOTATION)? "@interface"
			: (flags & R_BIN_ATTR_INTERFACE)? "interface"
			: (flags & R_BIN_ATTR_ENUM)? "enum": "class";
		r_strbuf_appendf (sb, "%s %s", keyword, name);
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
		r_list_foreach (member->arguments, iter, argument) {
			const char *comma = iter->p? ", ": "";
			r_strbuf_appendf (sb, "%s%s", comma, style == JAVA_STYLE_JNI? argument->jni_name: argument->name);
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

static RBinJavaMember *java_member_finish(RBinJavaMember *member) {
	member->definition = java_member_tostring (member, JAVA_STYLE_DISPLAY);
	member->jni_definition = java_member_tostring (member, JAVA_STYLE_JNI);
	return member;
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
			goto beach;
		}
		return java_member_finish (member);
	}
	if (R_STR_ISEMPTY (descriptor)) {
		goto beach;
	}
	member->descriptor = strdup (descriptor);
	const char *p = descriptor;
	if (kind == R_BIN_JAVA_MEMBER_FIELD) {
		member->type = java_type_parse (&p, false);
		if (!member->type || *p) {
			goto beach;
		}
		return java_member_finish (member);
	}
	if (*p++ != '(') {
		goto beach;
	}
	member->arguments = r_list_newf (java_type_free);
	while (*p && *p != ')') {
		RBinJavaType *argument = java_type_parse (&p, false);
		if (!argument || member->argument_slots > UT16_MAX - argument->slots) {
			java_type_free (argument);
			goto beach;
		}
		member->argument_slots += argument->slots;
		r_list_append (member->arguments, argument);
	}
	if (*p++ != ')') {
		goto beach;
	}
	member->type = java_type_parse (&p, true);
	if (!member->type || *p) {
		goto beach;
	}
	member->return_slots = member->type->slots;
	if (member->name && !strcmp (member->name, "<init>")) {
		member->attr.flags |= R_BIN_ATTR_CONSTRUCTOR;
	} else if (member->name && !strcmp (member->name, "<clinit>")) {
		member->attr.flags |= R_BIN_ATTR_STATIC;
	}
	return java_member_finish (member);
beach:
	r_bin_java_member_free (member);
	return NULL;
}
