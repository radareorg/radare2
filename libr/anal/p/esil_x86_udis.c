/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "udis86/types.h"
#include "udis86/extern.h"
#include "esil.h"


UDIS86_ESIL (nop,   ",");
UDIS86_ESIL (jo,    "?of,%s=%s", info->pc, dst);
UDIS86_ESIL (jno,   "?!of,%s=%s", info->pc, dst);
UDIS86_ESIL (jb,    "?cf,%s=%s", info->pc, dst);
UDIS86_ESIL (jae,   "?cf,%s=%s", info->pc, dst);
UDIS86_ESIL (je,    "?zf,%s=%s", info->pc, dst);
UDIS86_ESIL (jne,   "?!zf,%s=%s", info->pc, dst);
UDIS86_ESIL (ja,    "?!cf&!zf,%s=%s", info->pc, dst);
UDIS86_ESIL (jbe,   "?cf&zf,%s=%s", info->pc, dst);
UDIS86_ESIL (js,    "?sf,%s=%s", info->pc, dst);
UDIS86_ESIL (jns,   "?!sf,%s=%s", info->pc, dst);
UDIS86_ESIL (jp,    "?pf,%s=%s", info->pc, dst);
UDIS86_ESIL (jnp,   "?!pf,%s=%s", info->pc, dst);
UDIS86_ESIL (jl,    "?sf^of,%s=%s", info->pc, dst);
UDIS86_ESIL (jge,   "?sf^!of,%s=%s", info->pc, dst);
UDIS86_ESIL (jle,   "?(sf^of)|zf,%s=%s", info->pc, dst);
UDIS86_ESIL (jg,    "?(sf^!of)&!zf,%s=%s", info->pc, dst);
UDIS86_ESIL (jcxz,  "?cx==0,%s=%s", info->pc, dst);
UDIS86_ESIL (jecxz, "?ecx==0,%s=%s", info->pc, dst);
UDIS86_ESIL (jrcxz, "?rcx==0,%s=%s", info->pc, dst);
UDIS86_ESIL (jmp,   "%s=%s", info->pc, dst);
UDIS86_ESIL (call,  "%s-=%d,%d[%s]=%s,%s=%s", info->sp, info->regsz, info->regsz, info->sp, info->pc, info->pc, dst);
UDIS86_ESIL (shl,   "cf=%s&(1<<%d-%s),%s<<=%s,zf=%s==0", dst, info->regsz * 8, src, dst, src, dst);
UDIS86_ESIL (rol,   "cf=%s&(1<<%s),%s>>=%s,zf=%s==0", dst, src, dst, src, dst);
UDIS86_ESIL (ror,   "cf=%s&(1<<%d-%s),%s<<<=%s,zf=%s==0", dst, info->regsz * 8, src, dst, src, dst);
UDIS86_ESIL (add,   "cf=%s<=-%s&%s!=0,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s+=%s,zf=%s==0,sf=%s>>%d", dst, src, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (inc,   "of=(%s^(%s+1))>>%d,%s++,zf=%s==0,sf=%s>>%d", dst, dst, info->bits - 1, dst, dst, dst, info->bits - 1);
UDIS86_ESIL (sub,   "cf=%s<%s,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s-=%s,zf=%s==0,sf=%s>>%d", dst, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (dec,   "of=(%s^(%s-1))>>%d,%s--,zf=%s==0,sf=%s>>%d", dst, dst, info->bits - 1, dst, dst, dst, info->bits - 1);
UDIS86_ESIL (cmp,   "cf=%s<%s,zf=%s==%s", dst, src, dst, src);
UDIS86_ESIL (xor,   "%s^=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (or,    "%s|=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (and,   "%s&=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (test,  "zf=%s&%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, info->bits - 1);
UDIS86_ESIL (syscall, "$");
UDIS86_ESIL (int,   "$0x%"PFMT64x, info->n);
UDIS86_ESIL (lea,   "%s=%s", dst, src);
UDIS86_ESIL (mov,   "%s=%s", dst, src);
UDIS86_ESIL (push,  "%s-=%d,%d[%s]=%s", info->sp, info->regsz, info->regsz, info->sp, dst);
UDIS86_ESIL (pop,   "%s=%d[%s],%s+=%d", dst, info->regsz, info->sp, info->sp, info->regsz);
UDIS86_ESIL (leave, "%s=%s,%s=%d[%s],%s+=%d", info->sp, info->bp, src, info->regsz, info->sp, info->sp, info->regsz);
UDIS86_ESIL (ret,   "%s=%d[%s],%s+=%d", info->pc, info->regsz, info->sp, info->sp, info->regsz);
UDIS86_ESIL (xchg,  "%s^=%s,%s^=%s,%s^=%s", dst, src, src, dst, dst, src);
UDIS86_ESIL (xadd,  "%s^=%s,%s^=%s,%s^=%s,cf=%s<=-%s&%s!=0,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s+=%s,zf=%s==0,sf=%s>>%d", dst, src, src, dst, dst, src, dst, src, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (bt,    "cf=%s&(1<<%d)!=0", dst, (int) info->n);
UDIS86_ESIL (btc,   "cf=%s&(1<<%d)!=0,%s^=(1<<%d)",  dst, (int) info->n, dst, (int) info->n);
UDIS86_ESIL (bts,   "cf=%s&(1<<%d)!=0,%s|=(1<<%d)",  dst, (int) info->n, dst, (int) info->n);
UDIS86_ESIL (btr,   "cf=%s&(1<<%d)!=0,%s&=!(1<<%d)", dst, (int) info->n, dst, (int) info->n);
UDIS86_ESIL (clc,   "cf=0");
UDIS86_ESIL (cli,   "if=0");
UDIS86_ESIL (cld,   "df=0");
UDIS86_ESIL (cmc,   "cf=!cf");
UDIS86_ESIL (int3,  "$3");
UDIS86_ESIL (into,  "?of,$4");
UDIS86_ESIL (lahf,  "ah=%s", info->bits == 16 ? "flags" : (info->bits == 32 ? "eflags" : "rflags"));
UDIS86_ESIL (loop,  "%s--,?%s==0,%s=%s", info->bits == 16 ? "cx" : (info->bits == 32 ? "ecx" : "rcx"), info->bits == 16 ? "cx" : (info->bits == 32 ? "ecx" : "rcx"), info->pc, dst);
UDIS86_ESIL (loope, "%s--,?%s==0|zf,%s=%s", info->bits == 16 ? "cx" : (info->bits == 32 ? "ecx" : "rcx"), info->bits == 16 ? "cx" : (info->bits == 32 ? "ecx" : "rcx"), info->pc, dst);
UDIS86_ESIL (loopne,"%s--,?%s==0|!zf,%s=%s", info->bits == 16 ? "cx" : (info->bits == 32 ? "ecx" : "rcx"), info->bits == 16 ? "cx" : (info->bits == 32 ? "ecx" : "rcx"), info->pc, dst);

#define OP(args, inst) [JOIN (UD_I, inst)] = {args, UDIS86_ESIL_HANDLER (inst)}

/* This is the fastest way I can think about to implement this list of handlers */
UDis86Esil udis86_esil_callback_table[904] =
{
	OP (0, nop),   OP (1, jo),    OP (1, jno),    OP (1, jb),     OP (1, jae),
	OP (1, je),    OP (1, jne),   OP (1, ja),     OP (1, jbe),    OP (1, js),
	OP (1, jns),   OP (1, jp),    OP (1, jnp),    OP (1, jl),     OP (1, jge),
	OP (1, jle),   OP (1, jg),    OP (1, jcxz),   OP (1, jecxz),  OP (1, jrcxz),
	OP (1, jmp),   OP (1, call),  OP (2, shl),    OP (2, rol),    OP (2, ror),
	OP (2, add),   OP (1, inc),   OP (2, sub),    OP (1, dec),    OP (2, cmp),
	OP (2, xor),   OP (2, or),    OP (2, and),    OP (2, test),   OP (0, syscall),
	OP (1, int),   OP (2, lea),   OP (2, mov),    OP (1, push),   OP (1, pop),
	OP (0, leave), OP (0, ret),   OP (2, xchg),   OP (2, xadd),   OP (2, bt),
	OP (2, btc),   OP (2, bts),   OP (2, btr),    OP (0, clc),    OP (0, cli),
	OP (0, cld),   OP (0, cmc),   OP (0, int3),   OP (0, into),   OP (0, lahf),
	OP (1, loop),  OP (1, loope), OP (1, loopne)
};

UDis86Esil *
udis86_esil_get_handler (enum ud_mnemonic_code code)
{
	if (udis86_esil_callback_table[code].callback == NULL)
		return NULL;

	return udis86_esil_callback_table + code;
}
