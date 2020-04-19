#include <r_arch.h>
#include "minunit.h"

static bool test_default_setup(RArchSetup *setup) {
	setup->endian = R_ARCH_ENDIAN_LITTLE;
	setup->bits = 8;
	setup->syntax = R_ARCH_SYNTAX_NONE;
	setup->cpu = "test_cpu";
	return true;
}

static bool test_xxcode(RArchSession *as, RArchInstruction *ins, RArchInputOptions inopt, RArchOutputOptions outopt) {
	int data_len;
	if (!(inopt & R_ARCH_INOPT_DATA)) {
		return false;
	}
	ut8 *data = r_strbuf_getbin (&ins->data, &data_len);
	if (data_len != 1 || data[0] != 0x90) {
		return false;
	}
	if (outopt & R_ARCH_OUTOPT_CODE) {
		r_strbuf_set (&ins->code, "nop");
	}
	return true;
}

static RArchPlugin test_plugin = {
	.name = "test_plugin",
	.arch = "test",
	.author = "radare2",
	.desc = "Example RArch plugin",
	.endian = R_ARCH_ENDIAN_LITTLE | R_ARCH_ENDIAN_BIG,
	.bits = 8 | 32,
	.cpus = "test_cpu,radare2_cpu",
	.default_setup = test_default_setup,
	.inopts = R_ARCH_INOPT_DATA,
	.outopts = R_ARCH_OUTOPT_CODE,
	.xxcode = test_xxcode,
};

bool test_register_plugin(void) {
	RArch *a = r_arch_new ();
	bool res = r_arch_add (a, &test_plugin);
	mu_assert ("test_plugin should be registered the first time", res);
	res = r_arch_add (a, &test_plugin);
	mu_assert ("test_plugin was already registered", !res);

	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	mu_assert_notnull (ap, "test_plugin should be found");
	mu_assert_ptreq (ap, &test_plugin, "test_plugin and ap should be the same");

	res = r_arch_del (a, ap);
	mu_assert ("test_plugin should be deleted", res);
	res = r_arch_del (a, ap);
	mu_assert ("test_plugin was already deleted", !res);

	ap = r_arch_get_plugin (a, "test_plugin");
	mu_assert_null (ap, "test_plugin should NOT be found, because deleted");

	r_arch_free (a);
	mu_end;
}

bool test_session(void) {
	RArch *a = r_arch_new ();
	r_arch_add (a, &test_plugin);
	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	RArchSession *as = r_arch_session_new (a, ap, NULL);

	mu_assert_notnull (as, "a new session should be created with default values");
	mu_assert_eq (as->setup.endian, R_ARCH_ENDIAN_LITTLE, "default endian");
	mu_assert_eq (as->setup.bits, 8, "default bits");
	mu_assert_eq (as->setup.syntax, R_ARCH_SYNTAX_NONE, "default syntax");
	mu_assert_streq (as->setup.cpu, "test_cpu", "default cpu");

	r_arch_session_unref (as);

	RArchSetup my_setup = {
		.endian = R_ARCH_ENDIAN_BIG,
		.bits = 32,
		.syntax = R_ARCH_SYNTAX_INTEL,
		.cpu = NULL,
	};
	as = r_arch_session_new (a, ap, &my_setup);

	mu_assert_notnull (as, "a new session should be created with my_setup values");
	mu_assert_eq (as->setup.endian, R_ARCH_ENDIAN_BIG, "my_setup endian");
	mu_assert_eq (as->setup.bits, 32, "my_setup bits");
	mu_assert_eq (as->setup.syntax, R_ARCH_SYNTAX_INTEL, "my_setup syntax");
	mu_assert_null (as->setup.cpu, "my_setup cpu");

	bool can_xxcode = r_arch_session_can_xxcode (as, R_ARCH_INOPT_DATA, R_ARCH_OUTOPT_CODE);
	mu_assert ("data2code is supported", can_xxcode);
	can_xxcode = r_arch_session_can_xxcode (as, R_ARCH_INOPT_DATA, R_ARCH_OUTOPT_ESIL);
	mu_assert ("data2esil is not supported", !can_xxcode);
	can_xxcode = r_arch_session_can_xxcode (as, R_ARCH_INOPT_CODE, R_ARCH_OUTOPT_DATA);
	mu_assert ("code2data is not supported", !can_xxcode);

	r_arch_session_unref (as);

	r_arch_free (a);
	mu_end;
}

bool test_data2code(void) {
	RArch *a = r_arch_new ();
	r_arch_add (a, &test_plugin);
	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	RArchSession *as = r_arch_session_new (a, ap, NULL);

	RArchInstruction ins;
	r_arch_instruction_init_data (&ins, 0xdeadbeef, (const ut8 *)"\x00", 1);
	bool res = r_arch_session_xxcode (as, &ins, R_ARCH_INOPT_DATA, R_ARCH_OUTOPT_CODE);
	mu_assert ("invalid instruction returns false", !res);

	r_arch_instruction_init_data (&ins, 0xdeadbeef, (const ut8 *)"\x00", 1);
	res = r_arch_session_xxcode (as, &ins, R_ARCH_INOPT_DATA, R_ARCH_OUTOPT_ESIL);
	mu_assert ("invalid mode returns false", !res);

	r_arch_instruction_init_data (&ins, 0xdeadbeef, (const ut8 *)"\x90", 1);
	res = r_arch_session_xxcode (as, &ins, R_ARCH_INOPT_DATA, R_ARCH_OUTOPT_CODE);
	mu_assert ("valid instruction returns true", res);

	mu_assert_streq (r_strbuf_get (&ins.code), "nop", "0x90 is nop");
	mu_assert_eq (ins.addr, 0xdeadbeef, "address is right");
	mu_assert_eq (ins.size, 1, "size is 1");

	r_arch_session_unref (as);
	r_arch_free (a);
	mu_end;
}

bool test_code2data(void) {
	RArch *a = r_arch_new ();
	r_arch_add (a, &test_plugin);
	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	RArchSession *as = r_arch_session_new (a, ap, NULL);

	// TODO: implement me

	r_arch_session_unref (as);
	r_arch_free (a);
	mu_end;
}

bool test_data2esil(void) {
	RArch *a = r_arch_new ();
	r_arch_add (a, &test_plugin);
	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	RArchSession *as = r_arch_session_new (a, ap, NULL);

	// TODO: implement me

	r_arch_session_unref (as);
	r_arch_free (a);
	mu_end;
}

bool test_code2esil(void) {
	RArch *a = r_arch_new ();
	r_arch_add (a, &test_plugin);
	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	RArchSession *as = r_arch_session_new (a, ap, NULL);

	// TODO: implement me

	r_arch_session_unref (as);
	r_arch_free (a);
	mu_end;
}

bool test_data2codeesil(void) {
	RArch *a = r_arch_new ();
	r_arch_add (a, &test_plugin);
	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	RArchSession *as = r_arch_session_new (a, ap, NULL);

	// TODO: implement me

	r_arch_session_unref (as);
	r_arch_free (a);
	mu_end;
}

int all_tests() {
	mu_run_test (test_register_plugin);
	mu_run_test (test_session);
	mu_run_test (test_data2code);
	mu_run_test (test_code2data);
	mu_run_test (test_data2esil);
	mu_run_test (test_code2esil);
	mu_run_test (test_data2codeesil);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
