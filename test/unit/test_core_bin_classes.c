#include <r_core.h>
#include "minunit.h"

static RCore *class_core_new(void) {
	RCore *core = r_core_new ();
	r_config_set_i (core->config, "scr.color", 0);
	if (!r_core_file_open (core, "malloc://512", R_PERM_RW, 0)
		|| !r_core_bin_load (core, "malloc://512", 0)) {
		r_core_free (core);
		return NULL;
	}
	return core;
}

bool test_class_name_registration(void) {
	RCore *core = class_core_new ();
	mu_assert_notnull (core, "open memory binary");
	const char *invalid_commands[] = {
		"'ic+Bad.", "'ic+.Bad",
		"'ic+Bad\x1bname", "'ic+Bad\xc2\x85", "'ic+Bad\xe2\x80\xa8", "'ic+Bad\xe2\x80\xa9",
		"'ic+Bad\x80", "'ic+Bad\xc0\xaf", "'ic+Bad\xed\xa0\x80", "'ic+Bad\xf4\x90\x80\x80", "'ic+Bad\xf0\x9f"
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (invalid_commands); i++) {
		r_core_cmd0 (core, invalid_commands[i]);
		mu_assert_eq (r_list_length (r_bin_get_classes (core->bin)), 0, "rejection must not create a class");
	}
	mu_assert_false (core->flags->utf8, "ASCII flag representations by default");
	r_core_cmd0 (core, "ic+🦀");
	r_core_cmd0 (core, "ic+🦀..café int");
	r_core_cmd0 (core, "ic+🦀.👩‍💻:");
	r_core_cmd0 (core, "ic+🦀:基础");
	mu_assert_eq (r_list_length (r_bin_get_classes (core->bin)), 1, "one UTF-8 class");
	RBinClass *klass = r_list_first (r_bin_get_classes (core->bin));
	mu_assert_streq (r_bin_name_tostring (klass->name), "🦀", "preserve class spelling");
	mu_assert_eq (RVecRBinSymbol_length (&klass->methods), 1, "selector is a method, not a superclass");
	mu_assert_eq (RVecRBinField_length (&klass->fields), 1, "UTF-8 field");
	mu_assert_streq (r_bin_name_tostring (RVecRBinSymbol_at (&klass->methods, 0)->name), "👩‍💻:", "preserve symbol spelling with ASCII flags");
	char *ascii_script = r_core_cmd_str (core, "ic*");
	mu_assert_notnull (strstr (ascii_script, "'f class._ ="), "filter only the flag representation");
	mu_assert_notnull (strstr (ascii_script, "'td struct 🦀 { int café;};"), "preserve class and field type names");
	free (ascii_script);
	r_config_set_b (core->config, "asm.flags.utf8", true);
	char *script = r_core_cmd_str (core, "ic*");
	mu_assert_notnull (script, "export UTF-8 types");
	char *type_command = strstr (script, "'td struct 🦀 { int café;};");
	mu_assert_notnull (type_command, "preserve UTF-8 type and field names");
	*type_command = 0;
	r_core_cmd_lines (core, script);
	free (script);
	mu_assert_notnull (r_flag_get (core->flags, "class.🦀"), "replay UTF-8 flag");
	r_core_cmd0 (core, ".ic 0 **");
	mu_assert_true (r_anal_class_exists (core->anal, "🦀"), "replay UTF-8 analysis class");
	RAnalMethod method = {0};
	mu_assert_eq (r_anal_class_method_get (core->anal, "🦀", "👩‍💻:", &method), R_ANAL_CLASS_ERR_SUCCESS, "replay UTF-8 selector");
	r_anal_class_method_fini (&method);
	r_core_cmd0 (core, "ic-🦀.👩‍💻:");
	mu_assert_true (RVecRBinSymbol_empty (&klass->methods), "delete UTF-8 selector");
	r_core_cmd0 (core, "ic-🦀..café");
	mu_assert_true (RVecRBinField_empty (&klass->fields), "delete UTF-8 field");
	r_core_free (core);
	mu_end;
}

bool test_class_imported_name_export(void) {
	RCore *core = class_core_new ();
	mu_assert_notnull (core, "open memory binary");
	RBinFile *bf = r_bin_cur (core->bin);
	RBinClass *klass = r_bin_file_add_class (bf, "Evil;}", NULL, 0);
	mu_assert_notnull (klass, "keep original binary class name");
	RBinSymbol *method = r_bin_file_add_method (bf, "bad", "Evil;}", "m;\nf injected=1", 0);
	mu_assert_notnull (method, "keep original binary method name");
	method->vaddr = 0x42;
	method->paddr = 0x42;
	RBinField *field = RVecRBinField_emplace_back (&klass->fields);
	memset (field, 0, sizeof (*field));
	field->name = r_bin_name_new ("value;}");
	field->type = r_bin_name_new ("int;};f injected=1");
	mu_assert_notnull (r_bin_file_add_class (bf, "Bad\nf injected=1\n", "Base\nf injected=1\n", 0), "keep imported class and base newlines");
	char *script = r_core_cmd_str (core, "ic*");
	mu_assert_notnull (script, "export class script");
	mu_assert_null (strstr (script, "Evil;}"), "escape imported class name");
	mu_assert_null (strstr (script, "\nf injected=1"), "escape imported method newline");
	mu_assert_notnull (strstr (script, "'td struct Evil__ { int___f injected=1 value__;};"), "sanitize command syntax without C identifier rules");
	r_core_cmd_lines (core, script);
	free (script);
	mu_assert_null (r_flag_get (core->flags, "injected"), "export cannot inject commands");
	r_core_cmd0 (core, ".ic 0 **");
	RVecAnalMethod *methods = r_anal_class_method_get_all (core->anal, "r2name_4576696c3b7d");
	mu_assert_notnull (methods, "replay imported analysis methods");
	mu_assert_eq (RVecAnalMethod_length (methods), 1, "one imported method");
	mu_assert_eq (RVecAnalMethod_at (methods, 0)->addr, 0x42, "preserve method address");
	RVecAnalMethod_free (methods);
	mu_assert_streq (r_bin_name_tostring (klass->name), "Evil;}", "export does not mutate imported names");
	mu_assert_streq (r_bin_name_tostring (field->name), "value;}", "export does not mutate imported fields");
	r_core_free (core);
	mu_end;
}

bool test_class_export_name_collisions(void) {
	RCore *core = class_core_new ();
	mu_assert_notnull (core, "open memory binary");
	r_core_cmd0 (core, "ic+K.foo.bar");
	r_core_cmd0 (core, "ic+K.foo_bar");
	r_core_cmd0 (core, "ic+K.r2name_666f6f2e626172");
	r_core_cmd0 (core, ".ic 0 **");
	RVecAnalMethod *methods = r_anal_class_method_get_all (core->anal, "K");
	mu_assert_notnull (methods, "exported methods");
	mu_assert_eq (RVecAnalMethod_length (methods), 3, "encoded names must not overwrite each other");
	RVecAnalMethod_free (methods);
	r_core_free (core);
	mu_end;
}

bool test_class_destructor_name(void) {
	RCore *core = class_core_new ();
	mu_assert_notnull (core, "open memory binary");
	r_core_cmd0 (core, "'ic+Foo.~Foo");
	RBinClass *klass = r_list_first (r_bin_get_classes (core->bin));
	mu_assert_notnull (klass, "create binary class");
	mu_assert_eq (RVecRBinSymbol_length (&klass->methods), 1, "create destructor");
	RBinSymbol *method = RVecRBinSymbol_at (&klass->methods, 0);
	mu_assert_streq (r_bin_name_tostring (method->name), "~Foo", "preserve destructor in binary metadata");
	char *json = r_core_cmd_str (core, "icj");
	mu_assert_notnull (strstr (json, "\"name\":\"~Foo\""), "preserve destructor in JSON");
	free (json);
	r_core_cmd0 (core, ".ic*");
	mu_assert_notnull (r_flag_get (core->flags, "method.Foo._Foo"), "filter destructor flag name");
	mu_assert_null (r_flag_get (core->flags, "method.Foo.~Foo"), "tilde is invalid in flags");
	mu_assert_streq (r_bin_name_tostring (method->name), "~Foo", "flag export does not mutate binary metadata");
	r_core_cmd0 (core, "'ic+Foo.operator+");
	mu_assert_eq (RVecRBinSymbol_length (&klass->methods), 2, "create operator method");
	mu_assert_streq (r_bin_name_tostring (RVecRBinSymbol_at (&klass->methods, 1)->name), "operator+", "preserve operator punctuation");
	r_core_cmd0 (core, "'ic-Foo.~Foo");
	mu_assert_eq (RVecRBinSymbol_length (&klass->methods), 1, "delete destructor by original name");
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_class_name_registration);
	mu_run_test (test_class_imported_name_export);
	mu_run_test (test_class_export_name_collisions);
	mu_run_test (test_class_destructor_name);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
