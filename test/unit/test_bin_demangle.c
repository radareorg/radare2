#include <r_bin.h>
#include "../../shlr/java/descriptor.h"
#include "minunit.h"

static char *unit_demangle(RBinFile *bf, const char *symbol, ut64 vaddr) {
	(void)bf;
	(void)vaddr;
	return strdup (symbol);
}

static bool test_demangle_registry(void) {
	mu_assert_eq (r_bin_demangle_type ("java"), R_BIN_LANG_JAVA, "Java selects the Java demangler");
	mu_assert_eq (r_bin_demangle_type ("dalvik"), R_BIN_LANG_NONE, "Dalvik is a runtime, not a demangler");
	char *invalid_msvc = r_bin_demangle_msvc ("?metadata");
	mu_assert_null (invalid_msvc, "reject invalid MSVC decoration");

	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "RBin allocation");
	mu_assert_true (r_libstore_load (bin->libstore), "load static RBin plugins");

	RBinDemanglePlugin *cxx = r_bin_demangle_plugin_find (bin, "cxx");
	if (cxx) {
		mu_assert_ptreq (cxx, r_bin_demangle_plugin_find (bin, "c++"), "C++ alias lookup");
		mu_assert_ptreq (cxx, bin->demangle_by_type[R_BIN_LANG_CXX], "C++ direct table lookup");
	}

	RBinDemanglePlugin plugin = {
		.meta = {
			.name = "unit",
			.desc = "unit test demangler",
		},
		.type = R_BIN_LANG_NONE,
		.aliases = "test,testalias",
		.demangle = unit_demangle,
	};
	mu_assert_true (r_bin_demangle_plugin_add (bin, &plugin), "add named demangler");
	mu_assert_ptreq (r_bin_demangle_plugin_find (bin, "unit"), r_bin_demangle_plugin_find (bin, "testalias"), "custom alias lookup");

	RBinFile bf = { 0 };
	RBinObject bo = { 0 };
	bf.rbin = bin;
	bf.bo = &bo;
	char *res = r_bin_demangle (&bf, "test", "symbol", 0, false);
	mu_assert_streq (res, "symbol", "dispatch an explicitly named demangler");
	free (res);
	res = r_bin_demangle (&bf, "__mh_execute_header", "__mh_execute_header", 0, false);
	mu_assert_null (res, "reject a C symbol that only resembles C++ mangling");
	mu_assert_false (R_VPACK_HAS (bo.langs, R_BIN_LANG_CXX), "failed demangling does not register a language");

	RBinDemanglePlugin duplicate_alias = {
		.meta.name = "duplicate",
		.type = R_BIN_LANG_NONE,
		.aliases = "testalias",
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &duplicate_alias), "reject duplicate aliases");

	RBinDemanglePlugin typed = {
		.meta.name = "typed",
		.type = R_BIN_LANG_CIL,
		.demangle = unit_demangle,
	};
	mu_assert_true (r_bin_demangle_plugin_add (bin, &typed), "add typed demangler");
	RBinDemanglePlugin duplicate_type = {
		.meta.name = "duplicate_type",
		.type = R_BIN_LANG_CIL,
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &duplicate_type), "reject duplicate language providers");
	res = r_bin_demangle (&bf, "cil", "typed-symbol", 0, false);
	mu_assert_streq (res, "typed-symbol", "direct language table dispatch");
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_CIL), "demangling registers the binary language");
	free (res);

	RBinDemanglePlugin invalid_type = {
		.meta.name = "invalid_type",
		.type = R_BIN_LANG_LAST,
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &invalid_type), "reject invalid language type");
	mu_assert_true (r_bin_demangle_plugin_remove (bin, &typed), "remove typed demangler");
	mu_assert_true (r_bin_demangle_plugin_remove (bin, &plugin), "remove named demangler");
	mu_assert_null (r_bin_demangle_plugin_find (bin, "testalias"), "remove alias index");
	mu_assert_null (r_bin_demangle_plugin (bin, "missing", "symbol"), "missing demangler");

	r_bin_free (bin);
	mu_end;
}

static bool test_java_descriptor(void) {
	RJavaMember *member = r_java_member_parse (NULL, "nLoadSO",
		"(ZILjava/lang/String;)Z", R_JAVA_MEMBER_METHOD, 0x109);
	mu_assert_notnull (member, "parse JNI method descriptor");
	mu_assert_eq (member->kind, R_JAVA_MEMBER_METHOD, "method kind");
	mu_assert_streq (member->name, "nLoadSO", "method name");
	mu_assert_streq (member->visibility, "public", "method visibility");
	mu_assert_true (member->attr.flags & R_BIN_ATTR_PUBLIC, "public attribute");
	mu_assert_true (member->attr.flags & R_BIN_ATTR_STATIC, "static attribute");
	mu_assert_true (member->attr.flags & R_BIN_ATTR_NATIVE, "native attribute");
	mu_assert_eq (member->argument_slots, 3, "argument slots");
	mu_assert_eq (member->return_slots, 1, "return slots");
	mu_assert_eq (r_list_length (member->arguments), 3, "argument count");
	mu_assert_streq (member->definition,
		"public static native boolean nLoadSO (boolean, int, java.lang.String)",
		"Java definition");
	mu_assert_streq (member->jni_definition,
		"public static native jboolean nLoadSO (jboolean, jint, jstring)",
		"JNI definition");
	RJavaType *argument = r_list_get_n (member->arguments, 2);
	mu_assert_notnull (argument, "object argument");
	mu_assert_eq (argument->kind, R_JAVA_TYPE_OBJECT, "object kind");
	mu_assert_streq (argument->class_name, "java/lang/String", "internal class name");
	mu_assert_streq (argument->name, "java.lang.String", "Java class name");
	mu_assert_streq (argument->jni_name, "jstring", "JNI class name");
	r_java_member_free (member);

	member = r_java_member_parse (NULL, "nativeGreater", "(J[J[JJ)V",
		R_JAVA_MEMBER_METHOD, 0);
	mu_assert_notnull (member, "parse primitive arrays");
	mu_assert_eq (member->argument_slots, 6, "wide primitive argument slots");
	mu_assert_eq (member->return_slots, 0, "void return slots");
	mu_assert_streq (member->definition,
		"void nativeGreater (long, long[], long[], long)", "array definition");
	argument = r_list_get_n (member->arguments, 1);
	mu_assert_eq (argument->kind, R_JAVA_TYPE_LONG, "array element kind");
	mu_assert_eq (argument->array_dimensions, 1, "array dimensions");
	mu_assert_streq (argument->jni_name, "jlongArray", "JNI primitive array");
	r_java_member_free (member);

	member = r_java_member_parse (NULL, "primitives", "(ZBCSIJFD)V",
		R_JAVA_MEMBER_METHOD, 0);
	mu_assert_notnull (member, "parse every primitive type");
	mu_assert_eq (r_list_length (member->arguments), 8, "primitive argument count");
	mu_assert_eq (member->argument_slots, 10, "primitive argument slots");
	mu_assert_streq (member->definition,
		"void primitives (boolean, byte, char, short, int, long, float, double)",
		"primitive definition");
	r_java_member_free (member);

	member = r_java_member_parse ("pkg/C", "values", "[[I",
		R_JAVA_MEMBER_FIELD, 0x59);
	mu_assert_notnull (member, "parse field descriptor");
	mu_assert_streq (member->definition,
		"public static final volatile int[][] pkg.C.values", "field definition");
	mu_assert_streq (member->jni_definition,
		"public static final volatile jobjectArray pkg.C.values", "JNI field definition");
	mu_assert_eq (member->type->array_dimensions, 2, "multidimensional field");
	mu_assert_eq (member->type->slots, 1, "array reference slot");
	r_java_member_free (member);

	member = r_java_member_parse (NULL, "pkg/C", NULL,
		R_JAVA_MEMBER_CLASS, 0x31);
	mu_assert_notnull (member, "parse class metadata");
	mu_assert_streq (member->definition, "public final class pkg.C", "class definition");
	mu_assert_true (member->attr.flags & R_BIN_ATTR_SUPER, "class super attribute");
	r_java_member_free (member);

	char array_descriptor[258];
	memset (array_descriptor, '[', 255);
	array_descriptor[255] = 'I';
	array_descriptor[256] = 0;
	member = r_java_member_parse (NULL, "maximumArray", array_descriptor,
		R_JAVA_MEMBER_FIELD, 0);
	mu_assert_notnull (member, "accept 255 array dimensions");
	mu_assert_eq (member->type->array_dimensions, 255, "maximum array dimensions");
	r_java_member_free (member);
	mu_end;
}

static bool test_java_descriptor_rejects_malformed(void) {
	const char *bad_methods[] = {
		"(I", "I)V", "(V)V", "([V)V", "(L;)V",
		"(Ljava/lang/String)V", "(Ljava.lang.String;)V",
		"(Ljava//lang/String;)V", "(Ljava\\/lang/String;)V",
		"()", "()VV", "()Vx", "()[V"
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bad_methods); i++) {
		RJavaMember *member = r_java_member_parse (NULL, "bad",
			bad_methods[i], R_JAVA_MEMBER_METHOD, 0);
		mu_assert_null (member, bad_methods[i]);
	}
	const char *bad_fields[] = { "V", "Igarbage", "Ljava/lang/String" };
	for (i = 0; i < R_ARRAY_SIZE (bad_fields); i++) {
		RJavaMember *member = r_java_member_parse (NULL, "bad",
			bad_fields[i], R_JAVA_MEMBER_FIELD, 0);
		mu_assert_null (member, bad_fields[i]);
	}
	char too_many_dimensions[259];
	memset (too_many_dimensions, '[', 256);
	too_many_dimensions[256] = 'I';
	too_many_dimensions[257] = 0;
	RJavaMember *member = r_java_member_parse (NULL, "bad",
		too_many_dimensions, R_JAVA_MEMBER_FIELD, 0);
	mu_assert_null (member, "reject more than 255 array dimensions");
	char *demangled = r_bin_demangle_java ("nativeGreater(J[J[JJ)V");
	mu_assert_streq (demangled, "void nativeGreater (long, long[], long[], long)",
		"legacy demangler uses structured parser");
	free (demangled);
	mu_assert_null (r_bin_demangle_java ("broken(V)V"), "legacy demangler rejects void argument");
	mu_assert_null (r_bin_demangle_java ("broken()Vx"), "legacy demangler rejects trailing garbage");
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_demangle_registry);
	mu_run_test (test_java_descriptor);
	mu_run_test (test_java_descriptor_rejects_malformed);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
