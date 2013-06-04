/* ------------------------------------------------------------------ */
/* WARNING: relative order of tokens is important. */

/* register */
 DEF_ASM(al)
 DEF_ASM(cl)
 DEF_ASM(dl)
 DEF_ASM(bl)
 DEF_ASM(ah)
 DEF_ASM(ch)
 DEF_ASM(dh)
 DEF_ASM(bh)
 DEF_ASM(ax)
 DEF_ASM(cx)
 DEF_ASM(dx)
 DEF_ASM(bx)
 DEF_ASM(sp)
 DEF_ASM(bp)
 DEF_ASM(si)
 DEF_ASM(di)
 DEF_ASM(eax)
 DEF_ASM(ecx)
 DEF_ASM(edx)
 DEF_ASM(ebx)
 DEF_ASM(esp)
 DEF_ASM(ebp)
 DEF_ASM(esi)
 DEF_ASM(edi)
#ifdef TCC_TARGET_X86_64
 DEF_ASM(rax)
 DEF_ASM(rcx)
 DEF_ASM(rdx)
 DEF_ASM(rbx)
 DEF_ASM(rsp)
 DEF_ASM(rbp)
 DEF_ASM(rsi)
 DEF_ASM(rdi)
#endif
 DEF_ASM(mm0)
 DEF_ASM(mm1)
 DEF_ASM(mm2)
 DEF_ASM(mm3)
 DEF_ASM(mm4)
 DEF_ASM(mm5)
 DEF_ASM(mm6)
 DEF_ASM(mm7)
 DEF_ASM(xmm0)
 DEF_ASM(xmm1)
 DEF_ASM(xmm2)
 DEF_ASM(xmm3)
 DEF_ASM(xmm4)
 DEF_ASM(xmm5)
 DEF_ASM(xmm6)
 DEF_ASM(xmm7)
 DEF_ASM(cr0)
 DEF_ASM(cr1)
 DEF_ASM(cr2)
 DEF_ASM(cr3)
 DEF_ASM(cr4)
 DEF_ASM(cr5)
 DEF_ASM(cr6)
 DEF_ASM(cr7)
 DEF_ASM(tr0)
 DEF_ASM(tr1)
 DEF_ASM(tr2)
 DEF_ASM(tr3)
 DEF_ASM(tr4)
 DEF_ASM(tr5)
 DEF_ASM(tr6)
 DEF_ASM(tr7)
 DEF_ASM(db0)
 DEF_ASM(db1)
 DEF_ASM(db2)
 DEF_ASM(db3)
 DEF_ASM(db4)
 DEF_ASM(db5)
 DEF_ASM(db6)
 DEF_ASM(db7)
 DEF_ASM(dr0)
 DEF_ASM(dr1)
 DEF_ASM(dr2)
 DEF_ASM(dr3)
 DEF_ASM(dr4)
 DEF_ASM(dr5)
 DEF_ASM(dr6)
 DEF_ASM(dr7)
 DEF_ASM(es)
 DEF_ASM(cs)
 DEF_ASM(ss)
 DEF_ASM(ds)
 DEF_ASM(fs)
 DEF_ASM(gs)
 DEF_ASM(st)

 /* generic two operands */
 DEF_BWLX(mov)

 DEF_BWLX(add)
 DEF_BWLX(or)
 DEF_BWLX(adc)
 DEF_BWLX(sbb)
 DEF_BWLX(and)
 DEF_BWLX(sub)
 DEF_BWLX(xor)
 DEF_BWLX(cmp)

 /* unary ops */
 DEF_BWLX(inc)
 DEF_BWLX(dec)
 DEF_BWLX(not)
 DEF_BWLX(neg)
 DEF_BWLX(mul)
 DEF_BWLX(imul)
 DEF_BWLX(div)
 DEF_BWLX(idiv)

 DEF_BWLX(xchg)
 DEF_BWLX(test)

 /* shifts */
 DEF_BWLX(rol)
 DEF_BWLX(ror)
 DEF_BWLX(rcl)
 DEF_BWLX(rcr)
 DEF_BWLX(shl)
 DEF_BWLX(shr)
 DEF_BWLX(sar)

 DEF_ASM(shldw)
 DEF_ASM(shldl)
 DEF_ASM(shld)
 DEF_ASM(shrdw)
 DEF_ASM(shrdl)
 DEF_ASM(shrd)

 DEF_ASM(pushw)
 DEF_ASM(pushl)
#ifdef TCC_TARGET_X86_64
 DEF_ASM(pushq)
#endif
 DEF_ASM(push)

 DEF_ASM(popw)
 DEF_ASM(popl)
#ifdef TCC_TARGET_X86_64
 DEF_ASM(popq)
#endif
 DEF_ASM(pop)

 DEF_BWL(in)
 DEF_BWL(out)

 DEF_WL(movzb)
 DEF_ASM(movzwl)
 DEF_ASM(movsbw)
 DEF_ASM(movsbl)
 DEF_ASM(movswl)
#ifdef TCC_TARGET_X86_64
 DEF_ASM(movslq)
#endif

 DEF_WLX(lea)

 DEF_ASM(les)
 DEF_ASM(lds)
 DEF_ASM(lss)
 DEF_ASM(lfs)
 DEF_ASM(lgs)

 DEF_ASM(call)
 DEF_ASM(jmp)
 DEF_ASM(lcall)
 DEF_ASM(ljmp)

 DEF_ASMTEST(j)

 DEF_ASMTEST(set)
 DEF_ASMTEST(cmov)

 DEF_WLX(bsf)
 DEF_WLX(bsr)
 DEF_WLX(bt)
 DEF_WLX(bts)
 DEF_WLX(btr)
 DEF_WLX(btc)

 DEF_WLX(lsl)

 /* generic FP ops */
 DEF_FP(add)
 DEF_FP(mul)

 DEF_ASM(fcom)
 DEF_ASM(fcom_1) /* non existant op, just to have a regular table */
 DEF_FP1(com)

 DEF_FP(comp)
 DEF_FP(sub)
 DEF_FP(subr)
 DEF_FP(div)
 DEF_FP(divr)

 DEF_BWLX(xadd)
 DEF_BWLX(cmpxchg)

 /* string ops */
 DEF_BWLX(cmps)
 DEF_BWLX(scmp)
 DEF_BWL(ins)
 DEF_BWL(outs)
 DEF_BWLX(lods)
 DEF_BWLX(slod)
 DEF_BWLX(movs)
 DEF_BWLX(smov)
 DEF_BWLX(scas)
 DEF_BWLX(ssca)
 DEF_BWLX(stos)
 DEF_BWLX(ssto)

 /* generic asm ops */
#define ALT(x)
#define DEF_ASM_OP0(name, opcode) DEF_ASM(name)
#define DEF_ASM_OP0L(name, opcode, group, instr_type)
#define DEF_ASM_OP1(name, opcode, group, instr_type, op0)
#define DEF_ASM_OP2(name, opcode, group, instr_type, op0, op1)
#define DEF_ASM_OP3(name, opcode, group, instr_type, op0, op1, op2)
#ifdef TCC_TARGET_X86_64
# include "x86_64-asm.h"
#else
# include "i386-asm.h"
#endif

#define ALT(x)
#define DEF_ASM_OP0(name, opcode)
#define DEF_ASM_OP0L(name, opcode, group, instr_type) DEF_ASM(name)
#define DEF_ASM_OP1(name, opcode, group, instr_type, op0) DEF_ASM(name)
#define DEF_ASM_OP2(name, opcode, group, instr_type, op0, op1) DEF_ASM(name)
#define DEF_ASM_OP3(name, opcode, group, instr_type, op0, op1, op2) DEF_ASM(name)
#ifdef TCC_TARGET_X86_64
# include "x86_64-asm.h"
#else
# include "i386-asm.h"
#endif
