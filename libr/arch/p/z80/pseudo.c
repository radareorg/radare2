/* radare - LGPL - Copyright 2015-2025 - pancake, jvoisin */

#include <r_lib.h>
#include <r_asm.h>
#include <r_util/r_str.h>

static const char *pseudo_rules[] = {
	/* Arithmetic operations */
	"adc/2/$1 = $1 + $2 + carry",
	"add/2/$1 = $1 + $2",
	"add/3/$1 = $2 + $3",
	"and/1/a &= $1",
	"and/2/$1 &= $2",
	"and/3/$1 = $2 & $3",
	"cp/2/if ($1 == $2)",
	"cp/1/if ($1 == 0)",
	"neg/1/$1 = -$1",
	"sbc/2/$1 = $1 - $2 - carry",
	"sub/2/$1 = $1 - $2",
	"sub/3/$1 = $2 - $3",
	"xor/2/$1 ^= $2",
	"xor/3/$1 = $2 ^ $3",
	"or/2/$1 |= $2",
	"or/3/$1 = $2 | $3",

	/* Bit manipulation */
	"bit/2/if (($2 & (1 << $1)) != 0)",
	"res/2/$2 &= ~(1 << $1)",
	"set/2/$2 |= (1 << $1)",
	"cpl/1/$1 = ~$1",
	"ccf/1/carry = !carry",
	"scf/1/carry = 1",

	/* Shift and rotate operations */
	"rl/1/$1 = rotate_left($1, 1)",
	"rl/2/$1 = rotate_left($1, $2)",
	"rla/0/a = rotate_left(a, 1)",
	"rlc/1/$1 = rotate_left($1, 1) | (carry << 7)",
	"rlc/2/$1 = rotate_left($1, $2) | (carry << 7)",
	"rlca/0/a = rotate_left(a, 1) | (carry << 7)",
	"rr/1/$1 = rotate_right($1, 1)",
	"rr/2/$1 = rotate_right($1, $2)",
	"rra/0/a = rotate_right(a, 1)",
	"rrc/1/$1 = rotate_right($1, 1) | (carry << 7)",
	"rrc/2/$1 = rotate_right($1, $2) | (carry << 7)",
	"rrca/0/a = rotate_right(a, 1) | (carry << 7)",
	"sla/1/$1 <<= 1",
	"sla/2/$1 <<= $2",
	"sra/1/$1 >>= 1",
	"sra/2/$1 >>= $2",
	"srl/1/$1 >>= 1",
	"srl/2/$1 >>= $2",

	/* Load operations */
	"ld/2/$1 = $2",
	"ld/3/$1 = $2[$3]",
	"ldd/2/$1 = $2--",
	"lddr/2/$1 = $2--",
	"ldi/2/$1 = $2++",
	"ldir/2/$1 = $2++",
	"ldh/2/$1 = $2",
	"ldhl/2/$1 = $2",

	/* Store operations */
	"st/2/$2 = $1",
	"std/2/$2 = $1--",
	"stdr/2/$2 = $1--",
	"sti/2/$2 = $1++",
	"stir/2/$2 = $1++",

	/* Stack operations */
	"pop/1/$1 = stack[--sp]",
	"push/1/stack[sp++] = $1",
	"ex/2/swap($1, $2)",
	"exx/0/swap(bc, de), swap(hl, hl')",

	/* Input/Output */
	"in/2/$1 = io[$2]",
	"ini/2/$1 = io[$2++]",
	"inir/2/$1 = io[$2++]",
	"ind/2/$1 = io[$2--]",
	"indr/2/$1 = io[$2--]",
	"out/2/io[$2] = $1",
	"outi/2/io[$2++] = $1",
	"otir/2/io[$2++] = $1",
	"outd/2/io[$2--] = $1",
	"otdr/2/io[$2--] = $1",

	/* Jump operations */
	"jp/1/goto $1",
	"jp/2/if ($1) goto $2",
	"jr/1/goto $1",
	"jr/2/if ($1) goto $2",
	"jr/3/if ($1) goto $2 + $3",
	"djnz/1/b--; if (b != 0) goto $1",
	"call/1/$1()",
	"call/2/if ($1) $2()",
	"ret/0/return",
	"ret/1/if ($1) return",
	"reti/0/return_interrupt",
	"retn/0/return_non_maskable_interrupt",
	"rst/1/interrupt_vector($1)",

	/* Compare and search */
	"cpi/2/if (a == *$2++)",
	"cpir/2/if (a == *$2++)",
	"cpd/2/if (a == *$2--)",
	"cpdr/2/if (a == *$2--)",

	/* Block operations */
	"ldi/2/$1 = *$2++",
	"ldir/2/$1 = *$2++",
	"ldd/2/$1 = *$2--",
	"lddr/2/$1 = *$2--",

	/* Increment/Decrement */
	"inc/1/$1++",
	"dec/1/$1--",

	/* Interrupt control */
	"ei/0/enable_interrupts",
	"di/0/disable_interrupts",
	"im/1/interrupt_mode($1)",
	"halt/0/halt_until_interrupt",

	/* No operation */
	"nop/0/; nop",

	/* GameBoy specific instructions */
	"stop/0/stop_cpu",
	"ldh/2/$1 = $2",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

#if Z80_IS_GB
RAsmPlugin r_asm_plugin_gb = {
	.meta = {
		.name = "gb",
		.desc = "GameBoy pseudo syntax",
	},
	.parse = parse,
};
#else
RAsmPlugin r_asm_plugin_z80 = {
	.meta = {
		.name = "z80",
		.desc = "Z80 pseudo syntax",
	},
	.parse = parse,
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_z80,
	.version = R2_VERSION
};
#endif
