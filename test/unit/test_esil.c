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

static bool test_reg_alias(void *reg, int alias, const char *name) {
	return test_is_reg (reg, name) && alias == R_REG_ALIAS_PC;
}

static ut32 test_reg_size(void *reg, const char *name) {
	return test_is_reg (reg, name)? 32: 0;
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

typedef struct {
	RReg *reg;
	int alias;
	char name[16];
	char old_name[16];
} TestRegAliasVoyeur;

static void test_reg_alias_voyeur(void *user, int alias, const char *name) {
	TestRegAliasVoyeur *test = user;
	const char *old_name = r_reg_alias_getname (test->reg, alias);
	test->alias = alias;
	r_str_ncpy (test->name, name, sizeof (test->name));
	r_str_ncpy (test->old_name, r_str_get (old_name), sizeof (test->old_name));
}

bool test_setup_keeps_custom_interfaces(void) {
	int reg_user = 1;
	int mem_user = 2;
	REsilRegInterface reg_if = {
		.user = &reg_user,
		.is_reg = test_is_reg,
		.reg_read = test_reg_read,
		.reg_write = test_reg_write,
		.reg_alias = test_reg_alias,
		.reg_size = test_reg_size,
	};
	REsilMemInterface mem_if = {
		.user = &mem_user,
		.mem_read = test_mem_read,
		.mem_write = test_mem_write,
	};
	REsilOptions opt = r_esil_options (NULL, NULL);
	opt.stacksize = 32;
	opt.addrsize = 32;
	opt.ifaces.reg = reg_if;
	opt.ifaces.mem = mem_if;
	REsil *esil = r_esil_new (&opt);
	mu_assert_notnull (esil, "r_esil_new failed");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new failed");

	bool setup = r_esil_setup (esil, anal, false, false, false);
	mu_assert_true (setup, "r_esil_setup failed");
	mu_assert_ptreq (esil->reg_if.user, &reg_user, "reg user was replaced");
	mu_assert ("is_reg was replaced", esil->reg_if.is_reg == test_is_reg);
	mu_assert ("reg_read was replaced", esil->reg_if.reg_read == test_reg_read);
	mu_assert ("reg_write was replaced", esil->reg_if.reg_write == test_reg_write);
	mu_assert ("reg_alias was replaced", esil->reg_if.reg_alias == test_reg_alias);
	mu_assert ("reg_size was replaced", esil->reg_if.reg_size == test_reg_size);
	mu_assert_ptreq (esil->mem_if.user, &mem_user, "mem user was replaced");
	mu_assert ("mem_read was replaced", esil->mem_if.mem_read == test_mem_read);
	mu_assert ("mem_write was replaced", esil->mem_if.mem_write == test_mem_write);

	r_esil_free (esil);
	r_anal_free (anal);
	mu_end;
}

bool test_setup_installs_default_interfaces(void) {
	REsilOptions opt = r_esil_options (NULL, NULL);
	opt.stacksize = 32;
	opt.addrsize = 32;
	REsil *esil = r_esil_new (&opt);
	mu_assert_notnull (esil, "r_esil_new failed");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new failed");

	bool setup = r_esil_setup (esil, anal, false, false, false);
	mu_assert_true (setup, "r_esil_setup failed");
	mu_assert_ptreq (esil->reg_if.user, esil, "default reg user was not installed");
	mu_assert_notnull (esil->reg_if.is_reg, "default is_reg was not installed");
	mu_assert_notnull (esil->reg_if.reg_read, "default reg_read was not installed");
	mu_assert_notnull (esil->reg_if.reg_write, "default reg_write was not installed");
	mu_assert_notnull (esil->reg_if.reg_alias, "default reg_alias was not installed");
	mu_assert_notnull (esil->reg_if.reg_size, "default reg_size was not installed");
	mu_assert_ptreq (esil->mem_if.user, esil, "default mem user was not installed");
	mu_assert_notnull (esil->mem_if.mem_read, "default mem_read was not installed");
	mu_assert_notnull (esil->mem_if.mem_write, "default mem_write was not installed");

	r_esil_free (esil);
	r_anal_free (anal);
	mu_end;
}

bool test_reg_alias_op(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "r_anal_new failed");
	bool profile = r_reg_set_profile_string (anal->reg,
		"=PC r0\n"
		"=A0 r0\n"
		"gpr r0 .16 0 0\n"
		"gpr r1 .16 16 0");
	mu_assert_true (profile, "failed to set reg profile");

	TestRegAliasVoyeur voyeur = {
		.reg = anal->reg,
		.alias = -1,
	};
	ut32 vid = r_esil_add_voyeur (anal->esil, &voyeur,
		test_reg_alias_voyeur, R_ESIL_VOYEUR_REG_ALIAS);
	mu_assert_neq (vid, R_ESIL_VOYEUR_ERR, "failed to add reg alias voyeur");

	bool parsed = r_esil_parse (anal->esil, "r1,PC,r=");
	mu_assert_true (parsed, "failed to parse reg alias op");
	mu_assert_streq (r_reg_alias_getname (anal->reg, R_REG_ALIAS_PC), "r1", "PC alias was not updated");
	mu_assert_eq (voyeur.alias, R_REG_ALIAS_PC, "PC alias voyeur was not called");
	mu_assert_streq (voyeur.old_name, "r0", "PC alias voyeur did not see old register");
	mu_assert_streq (voyeur.name, "r1", "PC alias voyeur had wrong register");

	r_anal_free (anal);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_setup_keeps_custom_interfaces);
	mu_run_test (test_setup_installs_default_interfaces);
	mu_run_test (test_reg_alias_op);
	return tests_passed != tests_run;
}
