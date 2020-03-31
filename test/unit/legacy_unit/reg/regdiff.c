#include <r_reg.h>
#include <r_util.h>
#include <r_print.h>

const char *reg_profile = 
	"gpr eax .32 0 0\n"
	"gpr ecx .32 4 0\n"
	"gpr edx .32 8 0\n"
	"gpr ebx .32 12 0\n"
	"gpr esp .32 16 0\n"
	"gpr ebp .32 20 0\n"
	"gpr esi .32 24 0\n"
	"gpr edi .32 28 0\n"
	"gpr eip .32 32 0\n"
	"gpr eflags .32 36 0\n"
#if 1
	"seg cs .32 40 0\n"
	"seg ss .32 44 0\n"
	"seg ds .32 48 0\n"
	"seg es .32 52 0\n"
	"seg fs .32 56 0\n"
	"seg gs .32 60 0\n"
#endif
#if 1
	"gpr st0 .80 64 0\n"
	"gpr st1 .80 74 0\n"
	"gpr st2 .80 84 0\n"
	"gpr st3 .80 94 0\n"
	"gpr st4 .80 104 0\n"
	"gpr st5 .80 114 0\n"
	"gpr st6 .80 124 0\n"
	"gpr st7 .80 134 0\n"
#endif
	"gpr fctrl .32 144 0\n"
	"gpr fstat .32 148 0\n"
	"gpr ftag .32 152 0\n"
	"gpr fiseg .32 156 0\n"
	"gpr fioff .32 160 0\n"
	"gpr foseg .32 164 0\n"
	"gpr fooff .32 168 0\n"
	"gpr fop .32 172 0\n"
#if 1
	"gpr xmm0 .128 176 0\n"
	"gpr xmm1 .128 192 0\n"
	"gpr xmm2 .128 208 0\n"
	"gpr xmm3 .128 224 0\n"
	"gpr xmm4 .128 240 0\n"
	"gpr xmm5 .128 256 0\n"
	"gpr xmm6 .128 272 0\n"
	"gpr xmm7 .128 288 0\n"
#endif
	"gpr mxcsr .32 304 0\n"
;

static void dumpregs(RReg *reg) {
	int sz;
	ut8 *buf = r_reg_get_bytes (reg, 0, &sz);
	r_print_hexdump (NULL, 0, buf, sz, 16, 16);
	free (buf);
}
int main() {
	int sz, type = R_REG_TYPE_GPR;
	RReg *reg = r_reg_new();
	RReg *reg2 = r_reg_new();
	r_reg_set_profile_string (reg, reg_profile);
	r_reg_set_profile_string (reg2, reg_profile);
	r_reg_setv (reg2, "ecx", 0xdeadbeef);
	RRegItem* current = NULL;

	free (r_reg_get_bytes (reg, R_REG_TYPE_GPR, &sz));
	eprintf ("arena: %d\n", sz);
	if (sz != 308) {
		eprintf ("ARENA SIZE IS WRONG\n");
	}
		dumpregs (reg);
		dumpregs (reg2);
	for (;;) {
		current = r_reg_next_diff (reg, type,
			reg2->regset[type].arena->bytes,
			sz, current, 32);
		if (!current) break;
		eprintf("Reg: <%s>\n", current->name);
	}
	return 0;
}
