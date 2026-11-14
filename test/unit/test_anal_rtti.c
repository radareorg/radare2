#include <r_core.h>
#include "minunit.h"

static RCore *rtti_test_core_new(bool msvc) {
	RCore *core = r_core_new ();
	if (!r_core_file_open (core, "malloc://4096", R_PERM_RWX, 0)
		|| !r_core_bin_load (core, "malloc://4096", 0)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 32);
	r_config_set_b (core->config, "cfg.bigendian", false);
	r_config_set (core->config, "anal.cxxabi", msvc? "msvc": "itanium");
	RVecRBinSection *sections = r_bin_get_sections_vec (core->bin);
	RVecRBinSection_clear (sections);
	const char *names[] = { ".text", ".rdata", ".data" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		RBinSection *section = RVecRBinSection_emplace_back (sections);
		section->name = strdup (names[i]);
		section->vaddr = section->paddr = 0x100 * (i + 1);
		section->vsize = section->size = 0x100;
		section->perm = i? R_PERM_R: R_PERM_RX;
		section->is_data = i != 0;
	}

	ut8 data[0x400] = {0};
	ut32 invalid_rtti = msvc? UT32_MAX: 0x380;
	for (i = 0; i < 5; i++) {
		ut32 vtable = 0x208 + i * 0x10;
		r_write_le32 (data + vtable - 4, i % 2? 0x300: invalid_rtti);
		r_write_le32 (data + vtable, 0x180);
		data[0x100 + i * 5] = 0xb8;
		r_write_le32 (data + 0x101 + i * 5, vtable);
		r_anal_xrefs_set (core->anal, 0x100 + i * 5, vtable, R_ANAL_REF_TYPE_DATA);
	}
	if (msvc) {
		r_write_le32 (data + 0x30c, 0x340);
		r_write_le32 (data + 0x310, 0x360);
		memcpy (data + 0x348, ".?AVA@@", sizeof (".?AVA@@"));
	} else {
		r_write_le32 (data + 0x304, 0x340);
		memcpy (data + 0x340, "1A", sizeof ("1A"));
	}
	if (!r_io_write_at (core->io, 0, data, sizeof (data))) {
		r_core_free (core);
		return NULL;
	}
	r_cons_reset (core->cons);
	r_cons_print (core->cons, "existing output");
	return core;
}

static bool test_rtti_returns_output(void) {
	int abi;
	for (abi = 0; abi < 2; abi++) {
		RCore *core = rtti_test_core_new (abi != 0);
		mu_assert_notnull (core, "create RTTI memory image");
		RCoreBind core_bind = core->anal->coreb;
		core->anal->coreb = (RCoreBind){0};
		core->anal->print = NULL;
		RVTableContext context;
		r_anal_vtable_begin (core->anal, &context);
		RList *vtables = r_anal_vtable_search (&context);
		mu_assert_eq (r_list_length (vtables), 5, "find valid and invalid RTTI candidates");
		r_list_free (vtables);
		char *text = r_anal_rtti_print_all (core->anal, 0);
		mu_assert_notnull (text, "return text");
		mu_assert_notnull (strstr (text, abi? "name: .?AVA@@": "Type Name: A"), "return valid RTTI text");
		char *single = r_anal_rtti_print_at_vtable (core->anal, 0x218, 0);
		mu_assert_notnull (single, "return single RTTI text without a core binding");
		mu_assert_true (*single && strstr (text, single), "single RTTI matches the full listing");
		free (single);
		mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "existing output", "text leaves console untouched");
		free (text);

		char *json = r_anal_rtti_print_all (core->anal, 'j');
		mu_assert_notnull (json, "return JSON");
		RJson *parsed = r_json_parsedup (json);
		mu_assert_notnull (parsed, "valid JSON with invalid RTTI before, between and after valid entries");
		mu_assert_eq (parsed->type, R_JSON_ARRAY, "JSON array");
		mu_assert_eq (parsed->children.count, 2, "both valid entries retained");
		mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "existing output", "JSON leaves console untouched");
		r_json_free (parsed);
		free (json);
		json = r_anal_rtti_print_at_vtable (core->anal, 0x218, 'j');
		parsed = r_json_parsedup (json);
		mu_assert_notnull (parsed, "return single RTTI JSON without a core binding");
		mu_assert_eq (parsed->children.count, 1, "single RTTI array");
		r_json_free (parsed);
		free (json);
		mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "existing output", "single RTTI leaves console untouched");
		core->anal->coreb = core_bind;
		core->anal->print = core->print;
		r_cons_reset (core->cons);
		r_core_free (core);
	}
	mu_end;
}

static bool test_rtti_empty_output(void) {
	int abi;
	for (abi = 0; abi < 2; abi++) {
		RCore *core = rtti_test_core_new (abi != 0);
		mu_assert_notnull (core, "create RTTI memory image");
		ut8 invalid_rtti[4];
		r_write_le32 (invalid_rtti, abi? UT32_MAX: 0x380);
		r_io_write_at (core->io, 0x214, invalid_rtti, sizeof (invalid_rtti));
		r_io_write_at (core->io, 0x234, invalid_rtti, sizeof (invalid_rtti));
		char *json = r_anal_rtti_print_all (core->anal, 'j');
		mu_assert_streq (json, "[]\n", "empty JSON array when every RTTI is invalid");
		free (json);
		RVecRBinSection_clear (r_bin_get_sections_vec (core->bin));
		char *text = r_anal_rtti_print_all (core->anal, 0);
		mu_assert_streq (text, "", "empty text without vtables");
		free (text);
		json = r_anal_rtti_print_all (core->anal, 'j');
		mu_assert_streq (json, "[]\n", "empty JSON array without vtables");
		free (json);
		mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "existing output", "empty output leaves console untouched");
		r_cons_reset (core->cons);
		r_core_free (core);
	}
	mu_end;
}

static bool test_rtti_interrupted(void) {
	RCore *core = rtti_test_core_new (false);
	mu_assert_notnull (core, "create RTTI memory image");
	r_cons_break (core->cons);
	char *json = r_anal_rtti_print_all (core->anal, 'j');
	mu_assert_streq (json, "[]\n", "interrupted search returns a complete JSON array");
	mu_assert_streq (r_cons_get_buffer (core->cons, NULL), "existing output", "interrupted search leaves console untouched");
	free (json);
	r_cons_break_clear (core->cons);
	r_cons_reset (core->cons);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_rtti_returns_output);
	mu_run_test (test_rtti_empty_output);
	mu_run_test (test_rtti_interrupted);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
