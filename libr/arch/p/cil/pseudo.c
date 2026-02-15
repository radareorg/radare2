/* radare - LGPL - Copyright 2025 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include <r_util/r_str.h>

static const char *pseudo_rules[] = {
	/* Stack operations - load argument */
	"ldarg.0/0/push(arg0)",
	"ldarg.1/0/push(arg1)",
	"ldarg.2/0/push(arg2)",
	"ldarg.3/0/push(arg3)",
	"ldarg.s/1/push(arg[$1])",
	"ldarga.s/1/push(&arg[$1])",
	"ldarg/1/push(arg[$1])",
	"ldarga/1/push(&arg[$1])",

	/* Stack operations - store argument */
	"starg.s/1/arg[$1] = pop()",
	"starg/1/arg[$1] = pop()",

	/* Stack operations - load local */
	"ldloc.0/0/push(loc0)",
	"ldloc.1/0/push(loc1)",
	"ldloc.2/0/push(loc2)",
	"ldloc.3/0/push(loc3)",
	"ldloc.s/1/push(loc[$1])",
	"ldloca.s/1/push(&loc[$1])",
	"ldloc/1/push(loc[$1])",
	"ldloca/1/push(&loc[$1])",

	/* Stack operations - store local */
	"stloc.0/0/loc0 = pop()",
	"stloc.1/0/loc1 = pop()",
	"stloc.2/0/loc2 = pop()",
	"stloc.3/0/loc3 = pop()",
	"stloc.s/1/loc[$1] = pop()",
	"stloc/1/loc[$1] = pop()",

	/* Load constants */
	"ldnull/0/push(null)",
	"ldc.i4.m1/0/push(-1)",
	"ldc.i4.0/0/push(0)",
	"ldc.i4.1/0/push(1)",
	"ldc.i4.2/0/push(2)",
	"ldc.i4.3/0/push(3)",
	"ldc.i4.4/0/push(4)",
	"ldc.i4.5/0/push(5)",
	"ldc.i4.6/0/push(6)",
	"ldc.i4.7/0/push(7)",
	"ldc.i4.8/0/push(8)",
	"ldc.i4.s/1/push($1)",
	"ldc.i4/1/push($1)",
	"ldc.i8/1/push($1)",
	"ldc.r4/1/push($1)",
	"ldc.r8/1/push($1)",

	/* Stack manipulation */
	"dup/0/push(top())",
	"pop/0/pop()",

	/* Arithmetic operations */
	"add/0/push(pop() + pop())",
	"sub/0/push(pop() - pop())",
	"mul/0/push(pop() * pop())",
	"div/0/push(pop() / pop())",
	"div.un/0/push((uint)pop() / (uint)pop())",
	"rem/0/push(pop() % pop())",
	"rem.un/0/push((uint)pop() % (uint)pop())",
	"neg/0/push(-pop())",

	/* Overflow checked arithmetic */
	"add.ovf/0/push(pop() + pop()) // overflow check",
	"add.ovf.un/0/push((uint)pop() + (uint)pop()) // overflow check",
	"sub.ovf/0/push(pop() - pop()) // overflow check",
	"sub.ovf.un/0/push((uint)pop() - (uint)pop()) // overflow check",
	"mul.ovf/0/push(pop() * pop()) // overflow check",
	"mul.ovf.un/0/push((uint)pop() * (uint)pop()) // overflow check",

	/* Bitwise operations */
	"and/0/push(pop() & pop())",
	"or/0/push(pop() | pop())",
	"xor/0/push(pop() ^ pop())",
	"not/0/push(~pop())",
	"shl/0/push(pop() << pop())",
	"shr/0/push(pop() >> pop())",
	"shr.un/0/push((uint)pop() >> pop())",

	/* Conversion operations */
	"conv.i1/0/push((int8)pop())",
	"conv.i2/0/push((int16)pop())",
	"conv.i4/0/push((int32)pop())",
	"conv.i8/0/push((int64)pop())",
	"conv.r4/0/push((float)pop())",
	"conv.r8/0/push((double)pop())",
	"conv.u1/0/push((uint8)pop())",
	"conv.u2/0/push((uint16)pop())",
	"conv.u4/0/push((uint32)pop())",
	"conv.u8/0/push((uint64)pop())",
	"conv.i/0/push((nint)pop())",
	"conv.u/0/push((nuint)pop())",
	"conv.ovf.i/0/push((nint)pop()) // overflow check",
	"conv.ovf.u/0/push((nuint)pop()) // overflow check",

	/* Indirect load */
	"ldind.i1/0/push(*(int8*)pop())",
	"ldind.u1/0/push(*(uint8*)pop())",
	"ldind.i2/0/push(*(int16*)pop())",
	"ldind.u2/0/push(*(uint16*)pop())",
	"ldind.i4/0/push(*(int32*)pop())",
	"ldind.u4/0/push(*(uint32*)pop())",
	"ldind.i8/0/push(*(int64*)pop())",
	"ldind.i/0/push(*(nint*)pop())",
	"ldind.r4/0/push(*(float*)pop())",
	"ldind.r8/0/push(*(double*)pop())",
	"ldind.ref/0/push(*(ref*)pop())",

	/* Indirect store */
	"stind.ref/0/*(ref*)pop() = pop()",
	"stind.i1/0/*(int8*)pop() = pop()",
	"stind.i2/0/*(int16*)pop() = pop()",
	"stind.i4/0/*(int32*)pop() = pop()",
	"stind.i8/0/*(int64*)pop() = pop()",
	"stind.r4/0/*(float*)pop() = pop()",
	"stind.r8/0/*(double*)pop() = pop()",
	"stind.i/0/*(nint*)pop() = pop()",

	/* Compare operations */
	"ceq/0/push(pop() == pop() ? 1 : 0)",
	"cgt/0/push(pop() > pop() ? 1 : 0)",
	"cgt.un/0/push((uint)pop() > (uint)pop() ? 1 : 0)",
	"clt/0/push(pop() < pop() ? 1 : 0)",
	"clt.un/0/push((uint)pop() < (uint)pop() ? 1 : 0)",

	/* Unconditional branch */
	"br/1/goto $1",
	"br.s/1/goto $1",
	"leave/1/goto $1",
	"leave.s/1/goto $1",

	/* Conditional branch */
	"brfalse/1/if (!pop()) goto $1",
	"brfalse.s/1/if (!pop()) goto $1",
	"brtrue/1/if (pop()) goto $1",
	"brtrue.s/1/if (pop()) goto $1",
	"beq/1/if (pop() == pop()) goto $1",
	"beq.s/1/if (pop() == pop()) goto $1",
	"bne.un/1/if (pop() != pop()) goto $1",
	"bne.un.s/1/if (pop() != pop()) goto $1",
	"bge/1/if (pop() >= pop()) goto $1",
	"bge.s/1/if (pop() >= pop()) goto $1",
	"bge.un/1/if ((uint)pop() >= (uint)pop()) goto $1",
	"bge.un.s/1/if ((uint)pop() >= (uint)pop()) goto $1",
	"bgt/1/if (pop() > pop()) goto $1",
	"bgt.s/1/if (pop() > pop()) goto $1",
	"bgt.un/1/if ((uint)pop() > (uint)pop()) goto $1",
	"bgt.un.s/1/if ((uint)pop() > (uint)pop()) goto $1",
	"ble/1/if (pop() <= pop()) goto $1",
	"ble.s/1/if (pop() <= pop()) goto $1",
	"ble.un/1/if ((uint)pop() <= (uint)pop()) goto $1",
	"ble.un.s/1/if ((uint)pop() <= (uint)pop()) goto $1",
	"blt/1/if (pop() < pop()) goto $1",
	"blt.s/1/if (pop() < pop()) goto $1",
	"blt.un/1/if ((uint)pop() < (uint)pop()) goto $1",
	"blt.un.s/1/if ((uint)pop() < (uint)pop()) goto $1",

	/* Method calls */
	"call/1/$1()",
	"callvirt/1/$1()",
	"ret/0/return",

	/* Object operations */
	"newobj/1/push(new $1())",
	"castclass/1/push(($1)pop())",
	"isinst/1/push(pop() is $1)",
	"box/1/push(box($1, pop()))",
	"unbox/1/push(unbox($1, pop()))",
	"unbox.any/1/push(unbox_any($1, pop()))",

	/* Field operations */
	"ldfld/1/push(pop().$1)",
	"ldflda/1/push(&pop().$1)",
	"stfld/1/pop().$1 = pop()",
	"ldsfld/1/push($1)",
	"ldsflda/1/push(&$1)",
	"stsfld/1/$1 = pop()",

	/* Array operations */
	"newarr/1/push(new $1[pop()])",
	"ldlen/0/push(pop().length)",
	"ldelema/1/push(&pop()[pop()])",
	"ldelem/1/push(pop()[pop()])",
	"stelem/1/pop()[pop()] = pop()",
	"ldelem.i1/0/push((int8)pop()[pop()])",
	"ldelem.u1/0/push((uint8)pop()[pop()])",
	"ldelem.i2/0/push((int16)pop()[pop()])",
	"ldelem.u2/0/push((uint16)pop()[pop()])",
	"ldelem.i4/0/push((int32)pop()[pop()])",
	"ldelem.u4/0/push((uint32)pop()[pop()])",
	"ldelem.i8/0/push((int64)pop()[pop()])",
	"ldelem.i/0/push((nint)pop()[pop()])",
	"ldelem.r4/0/push((float)pop()[pop()])",
	"ldelem.r8/0/push((double)pop()[pop()])",
	"ldelem.ref/0/push((ref)pop()[pop()])",
	"stelem.i1/0/pop()[pop()] = (int8)pop()",
	"stelem.i2/0/pop()[pop()] = (int16)pop()",
	"stelem.i4/0/pop()[pop()] = (int32)pop()",
	"stelem.i8/0/pop()[pop()] = (int64)pop()",
	"stelem.i/0/pop()[pop()] = (nint)pop()",
	"stelem.r4/0/pop()[pop()] = (float)pop()",
	"stelem.r8/0/pop()[pop()] = (double)pop()",
	"stelem.ref/0/pop()[pop()] = (ref)pop()",

	/* String operations */
	"ldstr/1/push($1)",
	"ldtoken/1/push(token($1))",

	/* Object operations */
	"ldobj/1/push(*($1*)pop())",
	"stobj/1/*($1*)pop() = pop()",
	"cpobj/1/*($1*)pop() = *($1*)pop()",
	"initobj/1/*($1*)pop() = default($1)",
	"sizeof/1/push(sizeof($1))",

	/* Function pointer operations */
	"ldftn/1/push(&$1)",
	"ldvirtftn/1/push(&pop().$1)",

	/* Memory operations */
	"localloc/0/push(stackalloc(pop()))",
	"cpblk/0/memcpy(pop(), pop(), pop())",
	"initblk/0/memset(pop(), pop(), pop())",

	/* Exception handling */
	"throw/0/throw pop()",
	"rethrow/0/rethrow",
	"endfinally/0/endfinally",
	"endfilter/0/endfilter",

	/* Miscellaneous */
	"nop/0/; nop",
	"break/0/break",
	"switch/1/switch(pop()) $1",
	"arglist/0/push(arglist)",
	"refanyval/1/push(refanyval($1, pop()))",
	"mkrefany/1/push(mkrefany($1, pop()))",
	"refanytype/0/push(refanytype(pop()))",

	/* Prefix instructions */
	"tail./0/; tail call follows",
	"volatile./0/; volatile access follows",
	"unaligned./1/; unaligned($1) access follows",
	"constrained./1/; constrained($1) call follows",

	NULL
};

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_cil = {
	.meta = {
		.name = "cil",
		.desc = "CIL/MSIL pseudo syntax",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_cil,
	.version = R2_VERSION
};
#endif
