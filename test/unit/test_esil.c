#include <r_anal.h>
#include <string.h>
#include "minunit.h"

static bool test_is_reg(void *reg, const char *name) {
	return reg && name && !strcmp (name, "pc");
}

static bool test_reg_read(void *reg, const char *name, ut64 *val) {
	if (!test_is_reg (reg, name)) {
		return false;
	}
	*val = 0x1234;
	return true;
}

static bool test_reg_write(void *reg, const char *name, ut64 val) {
	return test_is_reg (reg, name) && val == 0x1234;
}

static ut32 test_reg_size(void *reg, const char *name) {
	return test_is_reg (reg, name)? 32: 0;
}

static bool test_reg_alias(void *reg, const char *name, const char *alias) {
	return test_is_reg (reg, name) && alias && !strcmp (alias, "PC");
}

static bool test_mem_read(void *mem, ut64 addr, ut8 *buf, int len) {
	if (!mem || !buf || len < 1 || addr != 0x1234) {
		return false;
	}
	buf[0] = 0xcc;
	return true;
}

static bool test_mem_write(void *mem, ut64 addr, const ut8 *buf, int len) {
	return mem && buf && len == 1 && addr == 0x1234 && buf[0] == 0xcc;
}

bool test_setup_keeps_custom_interfaces(void) {
	int reg_user = 1;
	int mem_user = 2;
	REsilRegInterface reg_if = {
		.user = &reg_user,
		.is_reg = test_is_reg,
		.reg_read = test_reg_read,
		.reg_write = test_reg_write,
		.reg_size = test_reg_size,
		.reg_alias = test_reg_alias,
	};
	REsilMemInterface mem_if = {
		.user = &mem_user,
		.mem_read = test_mem_read,
		.mem_write = test_mem_write,
	};
	REsil *esil = r_esil_new_ex (32, false, 32, &reg_if, &mem_if, NULL);
	mu_assert_notnull (esil, "r_esil_new_ex failed");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new failed");

	bool setup = r_esil_setup (esil, anal, false, false, false);
	mu_assert_true (setup, "r_esil_setup failed");
	mu_assert_ptreq (esil->reg_if.user, &reg_user, "reg user was replaced");
	mu_assert ("is_reg was replaced", esil->reg_if.is_reg == test_is_reg);
	mu_assert ("reg_read was replaced", esil->reg_if.reg_read == test_reg_read);
	mu_assert ("reg_write was replaced", esil->reg_if.reg_write == test_reg_write);
	mu_assert ("reg_size was replaced", esil->reg_if.reg_size == test_reg_size);
	mu_assert ("reg_alias was replaced", esil->reg_if.reg_alias == test_reg_alias);
	mu_assert_ptreq (esil->mem_if.user, &mem_user, "mem user was replaced");
	mu_assert ("mem_read was replaced", esil->mem_if.mem_read == test_mem_read);
	mu_assert ("mem_write was replaced", esil->mem_if.mem_write == test_mem_write);

	r_esil_free (esil);
	r_anal_free (anal);
	mu_end;
}

bool test_setup_installs_default_interfaces(void) {
	REsil *esil = r_esil_new (32, false, 32);
	mu_assert_notnull (esil, "r_esil_new failed");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new failed");

	bool setup = r_esil_setup (esil, anal, false, false, false);
	mu_assert_true (setup, "r_esil_setup failed");
	mu_assert_ptreq (esil->reg_if.user, esil, "default reg user was not installed");
	mu_assert_notnull (esil->reg_if.is_reg, "default is_reg was not installed");
	mu_assert_notnull (esil->reg_if.reg_read, "default reg_read was not installed");
	mu_assert_notnull (esil->reg_if.reg_write, "default reg_write was not installed");
	mu_assert_notnull (esil->reg_if.reg_size, "default reg_size was not installed");
	mu_assert_notnull (esil->reg_if.reg_alias, "default reg_alias was not installed");
	mu_assert_ptreq (esil->mem_if.user, esil, "default mem user was not installed");
	mu_assert_notnull (esil->mem_if.mem_read, "default mem_read was not installed");
	mu_assert_notnull (esil->mem_if.mem_write, "default mem_write was not installed");

	r_esil_free (esil);
	r_anal_free (anal);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_setup_keeps_custom_interfaces);
	mu_run_test (test_setup_installs_default_interfaces);
	return tests_passed != tests_run;
}
