#include <r_reg.h>
#include <r_debug.h>

static int x86_nregs = 10;
static char *x86_regs[] = {
   "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip", 
   "ax", "bx", "cx", "dx", "si", "di", "sp", "bp", "ip", // 16 tits
   "ah","al", "bh", "bl", "ch","cl", "dh","dl", // 8 tits
   NULL };
#if 0
// XXX
- we need size of register
struct r_reg_item_t {
	char name[16];
	char get[128];
	char set[128];
	int size;
	int delta;
};

struct r_reg_arch_t {
	char *name;
	int nregs;
	struct r_reg_item_t regs[128];
};

/* TODO: autogenerate it from a file in C or perl */
struct r_reg_arch_t x86 {
	.name = "",
	.nregs = 32,
	.regs = { {
		.name = "eax",
		.size = 32,
		.delta = offsetof(r_regs_t, eax)
		},{
		.name = "ebx",
		.size = 32,
		.delta = offsetof(r_regs_t, ebx)
		}
	}
}
#endif

int r_reg_set_arch(struct r_reg_t *reg, int arch, int bits)
{
	int ret = R_TRUE;

	switch(arch) {
	case R_DBG_ARCH_X86:
		switch(bits) {
		case 64:
			reg->nregs = x86_nregs;
			reg->regs  = x86_regs;
			break;
		case 32:
			reg->nregs = x86_nregs;
			reg->regs  = x86_regs;
			break;
		case 16:
			reg->nregs = x86_nregs;
			reg->regs  = x86_regs;
			break;
		}
		break;
	/* TODO: add more architectures */
	case R_DBG_ARCH_ARM:
	case R_DBG_ARCH_MIPS:
	default:
		ret = R_FALSE;
		break;
	}
	return ret;
}
