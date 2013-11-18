/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "udis86/types.h"
#include "udis86/extern.h"
#include "udis86/esil.h"


UDIS86_ESIL (nop,   ",");
UDIS86_ESIL (jo,    "?of,%s=%s", info->pc, dst);
UDIS86_ESIL (jno,   "?!of,%s=%s", info->pc, dst);
UDIS86_ESIL (jb,    "?cf,%s=%s", info->pc, dst);
UDIS86_ESIL (jae,   "?cf,%s=%s", info->pc, dst);
UDIS86_ESIL (jz,    "?zf,%s=%s", info->pc, dst);
UDIS86_ESIL (jnz,   "?!zf,%s=%s", info->pc, dst);
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
UDIS86_ESIL (add,   "cf=(%s+%s)<%s|(%s+%s)<%s,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s+=%s,zf=%s==0,sf=%s>>%d", dst, src, dst, dst, src, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (inc,   "of=(%s^(%s+1))>>%d,%s++,zf=%s==0,sf=%s>>%d", dst, dst, info->bits - 1, dst, dst, dst, info->bits - 1);
UDIS86_ESIL (sub,   "cf=%s<%s,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s-=%s,zf=%s==0,sf=%s>>%d", dst, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (dec,   "of=(%s^(%s-1))>>%d,%s--,zf=%s==0,sf=%s>>%d", dst, dst, info->bits - 1, dst, dst, dst, info->bits - 1);
UDIS86_ESIL (cmp,   "cf=%s<%s,zf=%s==%s", dst, src, dst, src);
UDIS86_ESIL (xor,   "%s^=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (or,    "%s|=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (and,   "%s&=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
UDIS86_ESIL (test,  "zf=%s&%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, info->bits - 1);
UDIS86_ESIL (syscall, "$");
UDIS86_ESIL (int,   "$0x%"PFMT64x",%s+=%d", info->n, info->pc, info->oplen);
UDIS86_ESIL (lea,   "%s=%s,%s+=%d", dst, src, info->pc, info->oplen);
UDIS86_ESIL (mov,   "%s=%s,%s+=%d", dst, src, info->pc, info->oplen);
UDIS86_ESIL (push,  "%s-=%d,%d[%s]=%s,%s+=%d", info->sp, info->regsz, info->regsz, info->sp, dst, info->pc, info->oplen);
UDIS86_ESIL (pop,   "%s=%d[%s],%s+=%d,%s+=%d", dst, info->regsz, info->sp, info->sp, info->regsz, info->pc, info->oplen);
UDIS86_ESIL (leave, "%s=%s,%s=%d[%s],%s+=%d,%s+=%d", info->sp, info->bp, src, info->regsz, info->sp, info->sp, info->regsz, info->pc, info->oplen);
UDIS86_ESIL (ret,   "%s=%d[%s],%s+=%d", info->pc, info->regsz, info->sp, info->sp, info->regsz);

#define OP(args, inst) [JOIN (UD_I, inst)] = {args, UDIS86_ESIL_HANDLER (inst)}

/* This is the fastest way I can think about to implement this list of handlers */
UDis86Esil udis86_esil_callback_table[904] =
{
	OP (0, nop),   OP (1, jo),   OP (1, jno),  OP (1, jb),     OP (1, jae),
	OP (1, jz),    OP (1, jnz),  OP (1, ja),   OP (1, jbe),    OP (1, js),
	OP (1, jns),   OP (1, jp),   OP (1, jnp),  OP (1, jl),     OP (1, jge),
	OP (1, jle),   OP (1, jg),   OP (1, jcxz), OP (1, jecxz),  OP (1, jrcxz),
	OP (1, jmp),   OP (1, call), OP (2, shl),  OP (2, rol),    OP (2, ror),
	OP (2, add),   OP (1, inc),  OP (2, sub),  OP (1, dec),    OP (2, cmp),
	OP (2, xor),   OP (2, or),   OP (2, and),  OP (2, test),   OP (0, syscall),
	OP (1, int),   OP (2, lea),  OP (2, mov),  OP (1, push),   OP (1, pop),
	OP (0, leave), OP (0, ret)
};

UDis86Esil *
udis86_esil_get_handler (enum ud_mnemonic_code code)
{
	if (udis86_esil_callback_table[code].callback == NULL)
		return NULL;

	return udis86_esil_callback_table + code;
}
