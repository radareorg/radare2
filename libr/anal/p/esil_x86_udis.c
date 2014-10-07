/* radare - LGPL - Copyright 2013-2014 - batchdrake */

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "udis86/types.h"
#include "udis86/extern.h"
#include "esil.h"

#define RPN 

RPN UDIS86_ESIL (nop,   ",");
RPN UDIS86_ESIL (jo,    "of,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jno,   "of,!,?{,%s,%s,}", dst, info->pc);
RPN UDIS86_ESIL (jb,    "cf,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jae,   "cf,?{,%s,%s,=,}", dst, info->pc);

//  UDIS86_ESIL (je,    "?zf,%s=%s", info->pc, dst);
RPN UDIS86_ESIL (je,    "zf,?{,%s,%s,=,}", dst, info->pc);

//  UDIS86_ESIL (jne,   "?!zf,%s=%s", info->pc, dst);
RPN UDIS86_ESIL (jne,   "zf,!,?{,%s,%s,=,}", dst, info->pc);

RPN UDIS86_ESIL (ja,    "cf,!,zf,!,&,?{,%s,%s,}",dst, info->pc);
RPN UDIS86_ESIL (jbe,   "zf,cf,&,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (js,    "sf,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jns,   "sf,!,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jp,    "pf,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jnp,   "pf,!,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jl,    "of,sf,^,?{,%s,%s,}", dst, info->pc);
RPN UDIS86_ESIL (jge,   "of,!,sf,^,?{,%s,%s,}", dst, info->pc);
RPN UDIS86_ESIL (jle,   "of,sf,^,zf,|,%s,%s,=", dst, info->pc);
RPN UDIS86_ESIL (jg,    "sf,of,!,^,zf,!,&,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jcxz,  "cx,!,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jecxz, "ecx,!,?{,%s,%s,=,}", dst, info->pc);
RPN UDIS86_ESIL (jrcxz, "rcx,!,?{,%s,%s,=,}", dst, info->pc);

//  UDIS86_ESIL (jmp,   "%s=%s", info->pc, dst);
RPN UDIS86_ESIL (jmp,   "%s,%s,=", dst, info->pc);

RPN UDIS86_ESIL (call,
	"%d,%s,+,"
	"%d,%s,-=,%s,"
	"=[],"
	"%s,%s,=",
	5, info->pc,
	info->regsz, info->sp, info->sp,
	dst, info->pc);
    
RPN UDIS86_ESIL (hlt, "hlt,TODO");
RPN UDIS86_ESIL (shl, "%s,%s,<<=,cz,%%z,zf,=", src, dst);
RPN UDIS86_ESIL (shr, "%s,%s,>>=,cz,%%z,zf,=", src, dst);
RPN UDIS86_ESIL (salc, "%s,%s,<<=,%%z,zf,=", src, dst);
RPN UDIS86_ESIL (sar, "%s,%s,>>=,%%z,zf,=", src, dst);
RPN UDIS86_ESIL (rol, "%s,%s,<<<=", src, dst);
RPN UDIS86_ESIL (ror, "%s,%s,>>>=", src, dst);
#if 0
RPN UDIS86_ESIL (rol, "%s,1,<<,%s,&,cf,=,%s,%s,>>=,%s,zf,=", src, dst, src, dst, dst)
RPN UDIS86_ESIL (ror, "%s,%d,-,1,<<,%s,&,cf,=,%s,%s,>>=,%s,zf,=", src, info->regsz*8, dst, src, dst, dst)
//  UDIS86_ESIL (rol, "cf=%s&(1<<%s),%s>>=%s,zf=%s==0", dst, src, dst, src, dst);
    UDIS86_ESIL (ror, "cf=%s&(1<<%d-%s),%s<<<=%s,zf=%s==0", dst, info->regsz * 8, src, dst, src, dst);
#endif
//    UDIS86_ESIL (add,   "cf=%s<=-%s&%s!=0,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s+=%s,zf=%s==0,sf=%s>>%d", dst, src, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
// XXX: this is wrong coz add [rax], al -> al,[rax+0],= ;;; this is not valid esil
RPN UDIS86_ESIL (add, "%s,%s,+=", src, dst); //cf=%s<=-%s&%s!=0,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s+=%s,zf=%s==0,sf=%s>>%d", dst, src, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
RPN UDIS86_ESIL (inc, "1,%s,+=,z,%%z,zf,=", dst);
RPN UDIS86_ESIL (dec, "1,%s,-=,%%z,zf,=,%%o,of,=,%%s,sf,=", dst);
//    UDIS86_ESIL (inc,   "of=(%s^(%s+1))>>%d,%s++,zf=%s==0,sf=%s>>%d", dst, dst, info->bits - 1, dst, dst, dst, info->bits - 1);
//  UDIS86_ESIL (sub,   "cf=%s<%s,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s-=%s,zf=%s==0,sf=%s>>%d", dst, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
RPN UDIS86_ESIL (sub,   "%s,%s,-=,%%c,cf,=,%%z,zf,=,%%s,sf,=,%%o,of,=", src, dst); // TODO: update flags
   // UDIS86_ESIL (dec,   "of=(%s^(%s-1))>>%d,%s--,zf=%s==0,sf=%s>>%d", dst, dst, info->bits - 1, dst, dst, dst, info->bits - 1);
//  UDIS86_ESIL (cmp,   "cf=%s<%s,zf=%s==%s", dst, src, dst, src);
RPN UDIS86_ESIL (cmp,  "%s,%s,==,%%z,zf,=", dst, src);
//  UDIS86_ESIL (xor,   "%s^=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
RPN UDIS86_ESIL (xor,   "%s,%s,^=", dst, src);
//  UDIS86_ESIL (or,    "%s|=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
RPN UDIS86_ESIL (or,    "%s,%s,|=", src, dst);
//    UDIS86_ESIL (and,   "%s&=%s,zf=%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, dst, info->bits - 1);
RPN UDIS86_ESIL (and,   "%s,%s,&=", src, dst);
#if 0
RPN UDIS86_ESIL (and,   "%s,%s,&=,%s,!,zf,%s,%d,>>,sf,=,0,cf,=,0,of,=",
			src, dst, dst, dst, info->bits-1);
#endif
    // UDIS86_ESIL (test,  "zf=%s&%s==0,sf=%s>>%d,cf=0,of=0", dst, src, dst, info->bits - 1);
RPN UDIS86_ESIL (test,  "%s,%s,==,%%z,zf,=", dst, src);

//  UDIS86_ESIL (syscall, "$");
RPN UDIS86_ESIL (syscall, "$");
//  UDIS86_ESIL (int3,  "$3");
RPN UDIS86_ESIL (int3,  "3,$");
//  UDIS86_ESIL (int,   "$0x%"PFMT64x, info->n);
RPN UDIS86_ESIL (int,   "0x%"PFMT64x",$", info->n);

RPN UDIS86_ESIL (lea,   "%s,%s,=", src, dst);
RPN UDIS86_ESIL (movzx, "%s,%s,=", src, dst); // not working? try 0fb63d55380000
RPN UDIS86_ESIL (mov,   "%s,%s,=", src, dst);
//  UDIS86_ESIL (push,  "%s-=%d,%d[%s]=%s", info->sp, info->regsz, info->regsz, info->sp, dst);
RPN UDIS86_ESIL (push,  "%d,%s,-=,%s,%s,=[%d]", info->regsz, info->sp, dst, info->sp, info->regsz);

//  UDIS86_ESIL (pop,   "%s=%d[%s],%s+=%d", dst, info->regsz, info->sp, info->sp, info->regsz);
RPN UDIS86_ESIL (pop,   "%s,[%d],%s,=,%d,%s,+=",
	info->sp, info->regsz, dst, info->regsz, info->sp);
RPN UDIS86_ESIL (leave, "%s,%s,=,%s,[%d],%s,%d,%s,-=",
	info->bp, info->sp, info->sp, info->regsz, info->bp, info->regsz, info->sp);

RPN UDIS86_ESIL (ret,   "%s,[%d],%s,=,%d,%s,+=", info->sp, info->regsz, info->pc, info->regsz, info->sp);
RPN UDIS86_ESIL (iretf,   "%s,[%d],%s,=,%d,%s,+=", info->sp, info->regsz, info->pc, info->regsz, info->sp);
RPN UDIS86_ESIL (iretd,   "%s,[%d],%s,=,%d,%s,+=", info->sp, info->regsz, info->pc, info->regsz, info->sp);

//    UDIS86_ESIL (xchg,  "%s^=%s,%s^=%s,%s^=%s", dst, src, src, dst, dst, src);
// TODO: add support for rpnesil tmp regs?

//RPN UDIS86_ESIL (xchg,  "%s,%s,^=,%s,%s,^=,%s,%s,^=", src, dst, src, src, dst, dst);
RPN UDIS86_ESIL (xchg,  "%s,%s,%s,=,%s,=", dst, src, dst, src);
    UDIS86_ESIL (xadd,  "%s^=%s,%s^=%s,%s^=%s,cf=%s<=-%s&%s!=0,of=!((%s^%s)>>%d)&(((%s+%s)^%s)>>%d),%s+=%s,zf=%s==0,sf=%s>>%d", dst, src, src, dst, dst, src, dst, src, src, dst, src, info->bits - 1, dst, src, src, info->bits - 1, dst, src, dst, dst, info->bits - 1);
    UDIS86_ESIL (bt,    "cf=%s&(1<<%d)!=0", dst, (int) info->n);
    UDIS86_ESIL (btc,   "cf=%s&(1<<%d)!=0,%s^=(1<<%d)",  dst, (int) info->n, dst, (int) info->n);
    UDIS86_ESIL (bts,   "cf=%s&(1<<%d)!=0,%s|=(1<<%d)",  dst, (int) info->n, dst, (int) info->n);
    UDIS86_ESIL (btr,   "cf=%s&(1<<%d)!=0,%s&=!(1<<%d)", dst, (int) info->n, dst, (int) info->n);
//  UDIS86_ESIL (clc,   "cf=0");
RPN UDIS86_ESIL (clc,   "0,cf,=");

RPN UDIS86_ESIL (sti,   "1,if,="); // interrupt flag
RPN UDIS86_ESIL (cli,   "0,if,="); // interrupt flag
//  UDIS86_ESIL (cld,   "df=0");
RPN UDIS86_ESIL (std,   "1,df,=");
RPN UDIS86_ESIL (cld,   "0,df,=");

#define IS16 (info->bits==16)
#define IS32 (info->bits==32)
#define IS64 (info->bits==64)

#define RSZ (IS32?4:IS64?8:2)
RPN UDIS86_ESIL (pushad,
	"%s"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]",
	IS64? 
	  "rdi,rsi,rbp,rsp,rbx,rdx,rcx,rax"
	: "edi,esi,ebp,esp,ebx,edx,ecx,eax",
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp
	);
RPN UDIS86_ESIL (pusha,
	"%s"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]"
	",%%r,%s,-=,%s,=[]",
	IS64? 
	  "rdi,rsi,rbp,rsp,rbx,rdx,rcx,rax"
	: "edi,esi,ebp,esp,ebx,edx,ecx,eax",
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp,
	info->sp, info->sp
	);

RPN UDIS86_ESIL (popad,
	"%s", IS64?
	"rsp,[],rdi,="
	",8,rsp,+,[],rsi,="
	",16,rsp,+,[],rbp,="
	",24,rsp,+,[],rsp,="
	",32,rsp,+,[],rbx,="
	",40,rsp,+,[],rdx,="
	",48,rsp,+,[],rcx,="
	",56,rsp,+,[],rax,="
	",64,rsp,+="
	:
	"esp,[],edi,="
	",4,esp,+,[],esi,="
	",8,esp,+,[],ebp,="
	",12,esp,+,[],esp,="
	",16,esp,+,[],ebx,="
	",20,esp,+,[],edx,="
	",24,esp,+,[],ecx,="
	",28,esp,+,[],eax,="
	",32,esp,+="
	);
RPN UDIS86_ESIL (popa,
	"%s", IS64?
	"rsp,[],rdi,="
	",8,rsp,+,[],rsi,="
	",16,rsp,+,[],rbp,="
	",24,rsp,+,[],rsp,="
	",32,rsp,+,[],rbx,="
	",40,rsp,+,[],rdx,="
	",48,rsp,+,[],rcx,="
	",56,rsp,+,[],rax,="
	",64,rsp,+="
	:
	"esp,[],edi,="
	",4,esp,+,[],esi,="
	",8,esp,+,[],ebp,="
	",12,esp,+,[],esp,="
	",16,esp,+,[],ebx,="
	",20,esp,+,[],edx,="
	",24,esp,+,[],ecx,="
	",28,esp,+,[],eax,="
	",32,esp,+="
	);

RPN UDIS86_ESIL (cmc,   "cf,!=");
RPN UDIS86_ESIL (into,  "of,?{,4,$,}");
RPN UDIS86_ESIL (lahf,  "%s,ah,=", info->bits == 16 ? "flags" : (info->bits == 32 ? "eflags" : "rflags"));
RPN UDIS86_ESIL (loop,  "1,%s,-=,!,?{%s,%s,=,}",
		info->bits == 16 ? "cx" : IS32 ? "ecx" : "rcx",
		dst, info->pc);
RPN UDIS86_ESIL (loope, "1,%s,-=,zf,?{,%s,%s,}",
		info->bits == 16 ? "cx" : IS32 ? "ecx" : "rcx",
		dst, info->pc);
RPN UDIS86_ESIL (loopne, "1,%s,-=,zf,!,?{,%s,%s,}",
		info->bits == 16 ? "cx" : IS32 ? "ecx" : "rcx",
		dst, info->pc);

#define OP(args, inst) [JOIN (UD_I, inst)] = {args, UDIS86_ESIL_HANDLER (inst)}

/* This is the fastest way I can think about to implement this list of handlers */
UDis86Esil udis86_esil_callback_table[ UD_MAX_MNEMONIC_CODE ] = {
	OP (0, nop),  OP (1, jo),   OP (1, jno), OP (1, jb),   OP (1, jae),
	OP (1, je),   OP (1, jne),  OP (1, ja),  OP (1, jbe),  OP (1, js),
	OP (1, jns),  OP (1, jp),   OP (1, jnp), OP (1, jl),   OP (1, jge),
	OP (1, jle),  OP (1, jg),   OP (1, jcxz),OP (1, jecxz),OP (1, jrcxz),
	OP (1, jmp),  OP (1, call), OP (2, shl), OP (2, rol),  OP (2, ror),
	OP (2, add),  OP (1, inc),  OP (2, sub), OP (1, dec),  OP (2, cmp),
	OP (2, xor),  OP (2, or),   OP (2, and), OP (2, test), OP (0, syscall),
	OP (1, int),  OP (2, lea),  OP (2, mov), OP (1, push), OP (1, pop),
	OP (0, leave),OP (0, ret),  OP (2, xchg),OP (2, xadd), OP (2, bt),
	OP (2, btc),  OP (2, bts),  OP (2, btr), OP (0, clc),  OP (0, cli),
	OP (0, cld),  OP (0, cmc),  OP (0, int3),OP (0, into), OP (0, lahf),
	OP (1, loop), OP (1, loope),OP (1, loopne), OP(2,sar), OP (2, salc)
};

UDis86Esil * udis86_esil_get_handler (enum ud_mnemonic_code code) {
	if (udis86_esil_callback_table[code].callback == NULL)
		return NULL;
	return udis86_esil_callback_table + code;
}
