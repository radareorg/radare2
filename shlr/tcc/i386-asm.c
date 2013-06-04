/*
 *  i386 specific functions for TCC assembler
 *
 *  Copyright (c) 2001, 2002 Fabrice Bellard
 *  Copyright (c) 2009 Frédéric Feret (x86_64 support)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"

/* #define NB_ASM_REGS 8 */
#define MAX_OPERANDS 3
#define NB_SAVED_REGS 3

#define TOK_ASM_first TOK_ASM_clc
#define TOK_ASM_last TOK_ASM_emms

#define OPC_JMP        0x01  /* jmp operand */
#define OPC_B          0x02  /* only used with OPC_WL */
#define OPC_WL         0x04  /* accepts w, l or no suffix */
#define OPC_BWL        (OPC_B | OPC_WL) /* accepts b, w, l or no suffix */
#define OPC_REG        0x08 /* register is added to opcode */
#define OPC_MODRM      0x10 /* modrm encoding */
#define OPC_FWAIT      0x20 /* add fwait opcode */
#define OPC_TEST       0x40 /* test opcodes */
#define OPC_SHIFT      0x80 /* shift opcodes */
#define OPC_D16      0x0100 /* generate data16 prefix */
#define OPC_ARITH    0x0200 /* arithmetic opcodes */
#define OPC_SHORTJMP 0x0400 /* short jmp operand */
#define OPC_FARITH   0x0800 /* FPU arithmetic opcodes */
#ifdef TCC_TARGET_X86_64
# define OPC_WLQ     0x1000  /* accepts w, l, q or no suffix */
# define OPC_BWLQ    (OPC_B | OPC_WLQ) /* accepts b, w, l, q or no suffix */
# define OPC_WLX     OPC_WLQ
#else
# define OPC_WLX     OPC_WL
#endif

#define OPC_GROUP_SHIFT 13

/* in order to compress the operand type, we use specific operands and
   we or only with EA  */
enum {
    OPT_REG8=0, /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_REG16,  /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_REG32,  /* warning: value is hardcoded from TOK_ASM_xxx */
#ifdef TCC_TARGET_X86_64
    OPT_REG64,  /* warning: value is hardcoded from TOK_ASM_xxx */
#endif
    OPT_MMX,    /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_SSE,    /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_CR,     /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_TR,     /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_DB,     /* warning: value is hardcoded from TOK_ASM_xxx */
    OPT_SEG,
    OPT_ST,
    OPT_IM8,
    OPT_IM8S,
    OPT_IM16,
    OPT_IM32,
#ifdef TCC_TARGET_X86_64
    OPT_IM64,
#endif
    OPT_EAX,    /* %al, %ax, %eax or %rax register */
    OPT_ST0,    /* %st(0) register */
    OPT_CL,     /* %cl register */
    OPT_DX,     /* %dx register */
    OPT_ADDR,   /* OP_EA with only offset */
    OPT_INDIR,  /* *(expr) */
    /* composite types */
    OPT_COMPOSITE_FIRST,
    OPT_IM,     /* IM8 | IM16 | IM32 | IM64 */
    OPT_REG,    /* REG8 | REG16 | REG32 | REG64 */
    OPT_REGW,   /* REG16 | REG32 | REG64 */
    OPT_IMW,    /* IM16 | IM32 | IM64 */
#ifdef TCC_TARGET_X86_64
    OPT_IMNO64, /* IM16 | IM32 */
#endif
    /* can be ored with any OPT_xxx */
    OPT_EA = 0x80
};

#define OP_REG8   (1 << OPT_REG8)
#define OP_REG16  (1 << OPT_REG16)
#define OP_REG32  (1 << OPT_REG32)
#define OP_MMX    (1 << OPT_MMX)
#define OP_SSE    (1 << OPT_SSE)
#define OP_CR     (1 << OPT_CR)
#define OP_TR     (1 << OPT_TR)
#define OP_DB     (1 << OPT_DB)
#define OP_SEG    (1 << OPT_SEG)
#define OP_ST     (1 << OPT_ST)
#define OP_IM8    (1 << OPT_IM8)
#define OP_IM8S   (1 << OPT_IM8S)
#define OP_IM16   (1 << OPT_IM16)
#define OP_IM32   (1 << OPT_IM32)
#define OP_EAX    (1 << OPT_EAX)
#define OP_ST0    (1 << OPT_ST0)
#define OP_CL     (1 << OPT_CL)
#define OP_DX     (1 << OPT_DX)
#define OP_ADDR   (1 << OPT_ADDR)
#define OP_INDIR  (1 << OPT_INDIR)
#ifdef TCC_TARGET_X86_64
# define OP_REG64  (1 << OPT_REG64)
# define OP_IM64   (1 << OPT_IM64)
#else
# define OP_REG64 0
# define OP_IM64  0
#endif

#define OP_EA     0x40000000
#define OP_REG    (OP_REG8 | OP_REG16 | OP_REG32 | OP_REG64)

#ifdef TCC_TARGET_X86_64
# define OP_IM      OP_IM64
# define TREG_XAX   TREG_RAX
# define TREG_XCX   TREG_RCX
# define TREG_XDX   TREG_RDX
#else
# define OP_IM      OP_IM32
# define TREG_XAX   TREG_EAX
# define TREG_XCX   TREG_ECX
# define TREG_XDX   TREG_EDX
#endif

typedef struct ASMInstr {
    uint16_t sym;
    uint16_t opcode;
    uint16_t instr_type;
    uint8_t nb_ops;
    uint8_t op_type[MAX_OPERANDS]; /* see OP_xxx */
} ASMInstr;

typedef struct Operand {
    uint32_t type;
    int8_t  reg; /* register, -1 if none */
    int8_t  reg2; /* second register, -1 if none */
    uint8_t shift;
    ExprValue e;
} Operand;

static const uint8_t reg_to_size[9] = {
/*
    [OP_REG8] = 0,
    [OP_REG16] = 1,
    [OP_REG32] = 2,
#ifdef TCC_TARGET_X86_64
    [OP_REG64] = 3,
#endif
*/
    0, 0, 1, 0, 2, 0, 0, 0, 3
};

#define NB_TEST_OPCODES 30

static const uint8_t test_bits[NB_TEST_OPCODES] = {
 0x00, /* o */
 0x01, /* no */
 0x02, /* b */
 0x02, /* c */
 0x02, /* nae */
 0x03, /* nb */
 0x03, /* nc */
 0x03, /* ae */
 0x04, /* e */
 0x04, /* z */
 0x05, /* ne */
 0x05, /* nz */
 0x06, /* be */
 0x06, /* na */
 0x07, /* nbe */
 0x07, /* a */
 0x08, /* s */
 0x09, /* ns */
 0x0a, /* p */
 0x0a, /* pe */
 0x0b, /* np */
 0x0b, /* po */
 0x0c, /* l */
 0x0c, /* nge */
 0x0d, /* nl */
 0x0d, /* ge */
 0x0e, /* le */
 0x0e, /* ng */
 0x0f, /* nle */
 0x0f, /* g */
};

static const uint8_t segment_prefixes[] = {
 0x26, /* es */
 0x2e, /* cs */
 0x36, /* ss */
 0x3e, /* ds */
 0x64, /* fs */
 0x65  /* gs */
};

static const ASMInstr asm_instrs[] = {
#define ALT(x) x
#define DEF_ASM_OP0(name, opcode)
#define DEF_ASM_OP0L(name, opcode, group, instr_type) { TOK_ASM_ ## name, opcode, (instr_type | group << OPC_GROUP_SHIFT), 0 },
#define DEF_ASM_OP1(name, opcode, group, instr_type, op0) { TOK_ASM_ ## name, opcode, (instr_type | group << OPC_GROUP_SHIFT), 1, { op0 }},
#define DEF_ASM_OP2(name, opcode, group, instr_type, op0, op1) { TOK_ASM_ ## name, opcode, (instr_type | group << OPC_GROUP_SHIFT), 2, { op0, op1 }},
#define DEF_ASM_OP3(name, opcode, group, instr_type, op0, op1, op2) { TOK_ASM_ ## name, opcode, (instr_type | group << OPC_GROUP_SHIFT), 3, { op0, op1, op2 }},
#ifdef TCC_TARGET_X86_64
# include "x86_64-asm.h"
#else
# include "i386-asm.h"
#endif
    /* last operation */
    { 0, },
};

static const uint16_t op0_codes[] = {
#define ALT(x)
#define DEF_ASM_OP0(x, opcode) opcode,
#define DEF_ASM_OP0L(name, opcode, group, instr_type)
#define DEF_ASM_OP1(name, opcode, group, instr_type, op0)
#define DEF_ASM_OP2(name, opcode, group, instr_type, op0, op1)
#define DEF_ASM_OP3(name, opcode, group, instr_type, op0, op1, op2)
#ifdef TCC_TARGET_X86_64
# include "x86_64-asm.h"
#else
# include "i386-asm.h"
#endif
};

static inline int get_reg_shift(TCCState *s1)
{
    int shift, v;
#ifdef I386_ASM_16
    if (s1->seg_size == 16)
        tcc_error("invalid effective address");
#endif
    v = asm_int_expr(s1);
    switch(v) {
    case 1:
        shift = 0;
        break;
    case 2:
        shift = 1;
        break;
    case 4:
        shift = 2;
        break;
    case 8:
        shift = 3;
        break;
    default:
        expect("1, 2, 4 or 8 constant");
        shift = 0;
        break;
    }
    return shift;
}

static int asm_parse_reg(void)
{
    int reg = 0;
    if (tok != '%')
        goto error_32;
    next();
    if (tok >= TOK_ASM_eax && tok <= TOK_ASM_edi) {
        reg = tok - TOK_ASM_eax;
#ifdef TCC_TARGET_X86_64
    } else if (tok >= TOK_ASM_rax && tok <= TOK_ASM_rdi) {
        reg = tok - TOK_ASM_rax;
#endif
#ifdef I386_ASM_16
    } else if (tok >= TOK_ASM_ax && tok <= TOK_ASM_di) {
        reg = tok - TOK_ASM_ax;
#endif
    } else {
    error_32:
        expect("register");
    }
    next();
    return reg;
}

static void parse_operand(TCCState *s1, Operand *op)
{
    ExprValue e;
    int reg, indir;
    const char *p;

    indir = 0;
    if (tok == '*') {
        next();
        indir = OP_INDIR;
    }

    if (tok == '%') {
        next();
        if (tok >= TOK_ASM_al && tok <= TOK_ASM_db7) {
            reg = tok - TOK_ASM_al;
            op->type = 1 << (reg >> 3); /* WARNING: do not change constant order */
            op->reg = reg & 7;
            if ((op->type & OP_REG) && op->reg == TREG_XAX)
                op->type |= OP_EAX;
            else if (op->type == OP_REG8 && op->reg == TREG_XCX)
                op->type |= OP_CL;
            else if (op->type == OP_REG16 && op->reg == TREG_XDX)
                op->type |= OP_DX;
        } else if (tok >= TOK_ASM_dr0 && tok <= TOK_ASM_dr7) {
            op->type = OP_DB;
            op->reg = tok - TOK_ASM_dr0;
        } else if (tok >= TOK_ASM_es && tok <= TOK_ASM_gs) {
            op->type = OP_SEG;
            op->reg = tok - TOK_ASM_es;
        } else if (tok == TOK_ASM_st) {
            op->type = OP_ST;
            op->reg = 0;
            next();
            if (tok == '(') {
                next();
                if (tok != TOK_PPNUM)
                    goto reg_error;
                p = tokc.cstr->data;
                reg = p[0] - '0';
                if ((unsigned)reg >= 8 || p[1] != '\0')
                    goto reg_error;
                op->reg = reg;
                next();
                skip(')');
            }
            if (op->reg == 0)
                op->type |= OP_ST0;
            goto no_skip;
        } else {
        reg_error:
            tcc_error("unknown register");
        }
        next();
    no_skip: ;
    } else if (tok == '$') {
        /* constant value */
        next();
        asm_expr(s1, &e);
        op->type = OP_IM;
        op->e.v = e.v;
        op->e.sym = e.sym;
        if (!op->e.sym) {
            if (op->e.v == (uint8_t)op->e.v)
                op->type |= OP_IM8;
            if (op->e.v == (int8_t)op->e.v)
                op->type |= OP_IM8S;
            if (op->e.v == (uint16_t)op->e.v)
                op->type |= OP_IM16;
#ifdef TCC_TARGET_X86_64
            if (op->e.v == (uint32_t)op->e.v)
                op->type |= OP_IM32;
#endif
        }
    } else {
        /* address(reg,reg2,shift) with all variants */
        op->type = OP_EA;
        op->reg = -1;
        op->reg2 = -1;
        op->shift = 0;
        if (tok != '(') {
            asm_expr(s1, &e);
            op->e.v = e.v;
            op->e.sym = e.sym;
        } else {
            next();
            if (tok == '%') {
                unget_tok('(');
                op->e.v = 0;
                op->e.sym = NULL;
            } else {
                /* bracketed offset expression */
                asm_expr(s1, &e);
                if (tok != ')')
                    expect(")");
                next();
                op->e.v = e.v;
                op->e.sym = e.sym;
            }
        }
        if (tok == '(') {
            next();
            if (tok != ',') {
                op->reg = asm_parse_reg();
            }
            if (tok == ',') {
                next();
                if (tok != ',') {
                    op->reg2 = asm_parse_reg();
                }
                if (tok == ',') {
                    next();
                    op->shift = get_reg_shift(s1);
                }
            }
            skip(')');
        }
        if (op->reg == -1 && op->reg2 == -1)
            op->type |= OP_ADDR;
    }
    op->type |= indir;
}

/* XXX: unify with C code output ? */
ST_FUNC void gen_expr32(ExprValue *pe)
{
    gen_addr32(pe->sym ? VT_SYM : 0, pe->sym, pe->v);
}

#ifdef TCC_TARGET_X86_64
static void gen_expr64(ExprValue *pe)
{
    gen_addr64(pe->sym ? VT_SYM : 0, pe->sym, pe->v);
}
#endif

/* XXX: unify with C code output ? */
static void gen_disp32(ExprValue *pe)
{
    Sym *sym = pe->sym;
    if (sym && sym->r == cur_text_section->sh_num) {
        /* same section: we can output an absolute value. Note
           that the TCC compiler behaves differently here because
           it always outputs a relocation to ease (future) code
           elimination in the linker */
        gen_le32(pe->v + sym->jnext - ind - 4);
    } else {
        if (sym && sym->type.t == VT_VOID) {
            sym->type.t = VT_FUNC;
            sym->type.ref = NULL;
        }
        gen_addrpc32(VT_SYM, sym, pe->v);
    }
}

#ifdef I386_ASM_16
static void gen_expr16(ExprValue *pe)
{
    if (pe->sym)
        greloc(cur_text_section, pe->sym, ind, R_386_16);
    gen_le16(pe->v);
}
static void gen_disp16(ExprValue *pe)
{
    Sym *sym;
    sym = pe->sym;
    if (sym) {
        if (sym->r == cur_text_section->sh_num) {
            /* same section: we can output an absolute value. Note
               that the TCC compiler behaves differently here because
               it always outputs a relocation to ease (future) code
               elimination in the linker */
            gen_le16(pe->v + sym->jnext - ind - 2);
        } else {
            greloc(cur_text_section, sym, ind, R_386_PC16);
            gen_le16(pe->v - 2);
        }
    } else {
        /* put an empty PC32 relocation */
        put_elf_reloc(symtab_section, cur_text_section,
                      ind, R_386_PC16, 0);
        gen_le16(pe->v - 2);
    }
}
#endif

/* generate the modrm operand */
static inline void asm_modrm(int reg, Operand *op)
{
    int mod, reg1, reg2, sib_reg1;

    if (op->type & (OP_REG | OP_MMX | OP_SSE)) {
        g(0xc0 + (reg << 3) + op->reg);
    } else if (op->reg == -1 && op->reg2 == -1) {
        /* displacement only */
#ifdef I386_ASM_16
        if (tcc_state->seg_size == 16) {
            g(0x06 + (reg << 3));
            gen_expr16(&op->e);
        } else if (tcc_state->seg_size == 32)
#endif
        {
            g(0x05 + (reg << 3));
            gen_expr32(&op->e);
        }
    } else {
        sib_reg1 = op->reg;
        /* fist compute displacement encoding */
        if (sib_reg1 == -1) {
            sib_reg1 = 5;
            mod = 0x00;
        } else if (op->e.v == 0 && !op->e.sym && op->reg != 5) {
            mod = 0x00;
        } else if (op->e.v == (int8_t)op->e.v && !op->e.sym) {
            mod = 0x40;
        } else {
            mod = 0x80;
        }
        /* compute if sib byte needed */
        reg1 = op->reg;
        if (op->reg2 != -1)
            reg1 = 4;
#ifdef I386_ASM_16
        if (tcc_state->seg_size == 32) {
#endif
        g(mod + (reg << 3) + reg1);
        if (reg1 == 4) {
            /* add sib byte */
            reg2 = op->reg2;
            if (reg2 == -1)
                reg2 = 4; /* indicate no index */
            g((op->shift << 6) + (reg2 << 3) + sib_reg1);
        }
#ifdef I386_ASM_16
        } else if (tcc_state->seg_size == 16) {
            /* edi = 7, esi = 6 --> di = 5, si = 4 */
            if ((reg1 == 6) || (reg1 == 7)) {
                reg1 -= 2;
            /* ebx = 3 --> bx = 7 */
            } else if (reg1 == 3) {
                reg1 = 7;
            /* o32 = 5 --> o16 = 6 */
            } else if (reg1 == 5) {
                reg1 = 6;
            /* sib not valid in 16-bit mode */
            } else if (reg1 == 4) {
                reg2 = op->reg2;
		/* bp + si + offset */
		if ((sib_reg1 == 5) && (reg2 == 6)) {
		    reg1 = 2;
		/* bp + di + offset */
		} else if ((sib_reg1 == 5) && (reg2 == 7)) {
		    reg1 = 3;
		/* bx + si + offset */
		} else if ((sib_reg1 == 3) && (reg2 == 6)) {
		    reg1 = 0;
		/* bx + di + offset */
		} else if ((sib_reg1 == 3) && (reg2 == 7)) {
		    reg1 = 1;
		} else {
		    tcc_error("invalid effective address");
		}
		if (op->e.v == 0)
		    mod = 0;
            } else {
                tcc_error("invalid register");
            }
            g(mod + (reg << 3) + reg1);
        }
#endif
        /* add offset */
        if (mod == 0x40) {
            g(op->e.v);
        } else if (mod == 0x80 || op->reg == -1) {
#ifdef I386_ASM_16
            if (tcc_state->seg_size == 16)
                gen_expr16(&op->e);
            else if (tcc_state->seg_size == 32)
#endif
                gen_expr32(&op->e);
        }
    }
}

ST_FUNC void asm_opcode(TCCState *s1, int opcode)
{
    const ASMInstr *pa;
    int i, modrm_index, reg, v, op1, is_short_jmp, seg_prefix;
    int nb_ops, s;
    Operand ops[MAX_OPERANDS], *pop;
    int op_type[3]; /* decoded op type */
#ifdef I386_ASM_16
    static int a32 = 0, o32 = 0, addr32 = 0, data32 = 0;
#endif

    /* force synthetic ';' after prefix instruction, so we can handle */
    /* one-line things like "rep stosb" instead of only "rep\nstosb" */
    if (opcode >= TOK_ASM_wait && opcode <= TOK_ASM_repnz)
        unget_tok(';');

    /* get operands */
    pop = ops;
    nb_ops = 0;
    seg_prefix = 0;
    for(;;) {
        if (tok == ';' || tok == TOK_LINEFEED)
            break;
        if (nb_ops >= MAX_OPERANDS) {
            tcc_error("incorrect number of operands");
        }
        parse_operand(s1, pop);
        if (tok == ':') {
           if (pop->type != OP_SEG || seg_prefix)
               tcc_error("incorrect prefix");
           seg_prefix = segment_prefixes[pop->reg];
           next();
           parse_operand(s1, pop);
#ifndef I386_ASM_16
           if (!(pop->type & OP_EA)) {
               tcc_error("segment prefix must be followed by memory reference");
           }
#endif
        }
        pop++;
        nb_ops++;
        if (tok != ',')
            break;
        next();
    }

    is_short_jmp = 0;
    s = 0; /* avoid warning */

    /* optimize matching by using a lookup table (no hashing is needed
       !) */
    for(pa = asm_instrs; pa->sym != 0; pa++) {
        s = 0;
        if (pa->instr_type & OPC_FARITH) {
            v = opcode - pa->sym;
            if (!((unsigned)v < 8 * 6 && (v % 6) == 0))
                continue;
        } else if (pa->instr_type & OPC_ARITH) {
            if (!(opcode >= pa->sym && opcode < pa->sym + 8*NBWLX))
                continue;
            s = (opcode - pa->sym) % NBWLX;
        } else if (pa->instr_type & OPC_SHIFT) {
            if (!(opcode >= pa->sym && opcode < pa->sym + 7*NBWLX))
                continue;
            s = (opcode - pa->sym) % NBWLX;
        } else if (pa->instr_type & OPC_TEST) {
            if (!(opcode >= pa->sym && opcode < pa->sym + NB_TEST_OPCODES))
                continue;
        } else if (pa->instr_type & OPC_B) {
            if (!(opcode >= pa->sym && opcode < pa->sym + NBWLX))
                continue;
            s = opcode - pa->sym;
        } else if (pa->instr_type & OPC_WLX) {
            if (!(opcode >= pa->sym && opcode < pa->sym + NBWLX-1))
                continue;
            s = opcode - pa->sym + 1;
        } else {
            if (pa->sym != opcode)
                continue;
        }
        if (pa->nb_ops != nb_ops)
            continue;
        /* now decode and check each operand */
        for(i = 0; i < nb_ops; i++) {
            int op1, op2;
            op1 = pa->op_type[i];
            op2 = op1 & 0x1f;
            switch(op2) {
            case OPT_IM:
                v = OP_IM8 | OP_IM16 | OP_IM32 | OP_IM64;
                break;
            case OPT_REG:
                v = OP_REG8 | OP_REG16 | OP_REG32 | OP_REG64;
                break;
            case OPT_REGW:
                v = OP_REG16 | OP_REG32 | OP_REG64;
                break;
            case OPT_IMW:
                v = OP_IM16 | OP_IM32 | OP_IM64;
                break;
#ifdef TCC_TARGET_X86_64
            case OPT_IMNO64:
                v = OP_IM16 | OP_IM32;
                break;
#endif
            default:
                v = 1 << op2;
                break;
            }
            if (op1 & OPT_EA)
                v |= OP_EA;
            op_type[i] = v;
            if ((ops[i].type & v) == 0)
                goto next;
        }
        /* all is matching ! */
        break;
    next: ;
    }
    if (pa->sym == 0) {
        if (opcode >= TOK_ASM_first && opcode <= TOK_ASM_last) {
            int b;
            b = op0_codes[opcode - TOK_ASM_first];
#ifdef I386_ASM_16
            if (opcode == TOK_ASM_o32) {
                if (s1->seg_size == 32)
                    tcc_error("incorrect prefix");
                else
                    o32 = data32 = 1;
            } else if (opcode == TOK_ASM_a32) {
                if (s1->seg_size == 32)
                    tcc_error("incorrect prefix");
                else
                    a32 = addr32 = 1;
            }
#endif
            if (b & 0xff00) 
                g(b >> 8);
            g(b);
            return;
        } else {
            tcc_error("unknown opcode '%s'",
                  get_tok_str(opcode, NULL));
        }
    }
    /* if the size is unknown, then evaluate it (OPC_B or OPC_WL case) */
    if (s == NBWLX-1) {
        for(i = 0; s == NBWLX-1 && i < nb_ops; i++) {
            if ((ops[i].type & OP_REG) && !(op_type[i] & (OP_CL | OP_DX)))
                s = reg_to_size[ops[i].type & OP_REG];
        }
        if (s == NBWLX-1) {
            if ((opcode == TOK_ASM_push || opcode == TOK_ASM_pop) &&
                (ops[0].type & (OP_SEG | OP_IM8S | OP_IM32 | OP_IM64)))
                s = 2;
            else
                tcc_error("cannot infer opcode suffix");
        }
    }

#ifdef I386_ASM_16
    for(i = 0; i < nb_ops; i++) {
        if (ops[i].type & OP_REG32) {
            if (s1->seg_size == 16)
                o32 = 1;
        } else if (!(ops[i].type & OP_REG32)) {
            if (s1->seg_size == 32)
                o32 = 1;
        }
    }


    if (s == 1 || (pa->instr_type & OPC_D16)) {
        if (s1->seg_size == 32)
            o32 = 1;
    } else if (s == 2) {
        if (s1->seg_size == 16) {
            if (!(pa->instr_type & OPC_D16))
            o32 = 1;
        }
    }

    /* generate a16/a32 prefix if needed */
    if ((a32 == 1) && (addr32 == 0))
        g(0x67);
    /* generate o16/o32 prefix if needed */
    if ((o32 == 1) && (data32 == 0))
        g(0x66);

    addr32 = data32 = 0;
#else
    /* generate data16 prefix if needed */
    if (s == 1 || (pa->instr_type & OPC_D16))
        g(0x66);
#ifdef TCC_TARGET_X86_64
    else if (s == 3) {
        /* generate REX prefix */
        if ((opcode != TOK_ASM_push && opcode != TOK_ASM_pop)
            || !(ops[0].type & OP_REG64))
            g(0x48);
    }
#endif
#endif

    /* now generates the operation */
    if (pa->instr_type & OPC_FWAIT)
        g(0x9b);
    if (seg_prefix)
        g(seg_prefix);

    v = pa->opcode;
    if ((v == 0x69 || v == 0x6b) && nb_ops == 2) {
        /* kludge for imul $im, %reg */
        nb_ops = 3;
        ops[2] = ops[1];
        op_type[2] = op_type[1];
    } else if (v == 0xcd && ops[0].e.v == 3 && !ops[0].e.sym) {
        v--; /* int $3 case */
        nb_ops = 0;
    } else if ((v == 0x06 || v == 0x07)) {
        if (ops[0].reg >= 4) {
            /* push/pop %fs or %gs */
            v = 0x0fa0 + (v - 0x06) + ((ops[0].reg - 4) << 3);
        } else {
            v += ops[0].reg << 3;
        }
        nb_ops = 0;
    } else if (v <= 0x05) {
        /* arith case */
        v += ((opcode - TOK_ASM_addb) / NBWLX) << 3;
    } else if ((pa->instr_type & (OPC_FARITH | OPC_MODRM)) == OPC_FARITH) {
        /* fpu arith case */
        v += ((opcode - pa->sym) / 6) << 3;
    }
    if (pa->instr_type & OPC_REG) {
        for(i = 0; i < nb_ops; i++) {
            if (op_type[i] & (OP_REG | OP_ST)) {
                v += ops[i].reg;
                break;
            }
        }
        /* mov $im, %reg case */
        if (pa->opcode == 0xb0 && s >= 1)
            v += 7;
    }
    if (pa->instr_type & OPC_B)
        v += s >= 1;
    if (pa->instr_type & OPC_TEST)
        v += test_bits[opcode - pa->sym];
    if (pa->instr_type & OPC_SHORTJMP) {
        Sym *sym;
        int jmp_disp;

        /* see if we can really generate the jump with a byte offset */
        sym = ops[0].e.sym;
        if (!sym)
            goto no_short_jump;
        if (sym->r != cur_text_section->sh_num)
            goto no_short_jump;
        jmp_disp = ops[0].e.v + sym->jnext - ind - 2;
        if (jmp_disp == (int8_t)jmp_disp) {
            /* OK to generate jump */
            is_short_jmp = 1;
            ops[0].e.v = jmp_disp;
        } else {
        no_short_jump:
            if (pa->instr_type & OPC_JMP) {
                /* long jump will be allowed. need to modify the
                   opcode slightly */
                if (v == 0xeb)
                    v = 0xe9;
                else
                    v += 0x0f10;
            } else {
                tcc_error("invalid displacement");
            }
        }
    }
    op1 = v >> 8;
    if (op1)
        g(op1);
    g(v);

    /* search which operand will used for modrm */
    modrm_index = 0;
    if (pa->instr_type & OPC_SHIFT) {
        reg = (opcode - pa->sym) / NBWLX;
        if (reg == 6)
            reg = 7;
    } else if (pa->instr_type & OPC_ARITH) {
        reg = (opcode - pa->sym) / NBWLX;
    } else if (pa->instr_type & OPC_FARITH) {
        reg = (opcode - pa->sym) / 6;
    } else {
        reg = (pa->instr_type >> OPC_GROUP_SHIFT) & 7;
    }
    if (pa->instr_type & OPC_MODRM) {
        /* first look for an ea operand */
        for(i = 0;i < nb_ops; i++) {
            if (op_type[i] & OP_EA)
                goto modrm_found;
        }
        /* then if not found, a register or indirection (shift instructions) */
        for(i = 0;i < nb_ops; i++) {
            if (op_type[i] & (OP_REG | OP_MMX | OP_SSE | OP_INDIR))
                goto modrm_found;
        }
#ifdef ASM_DEBUG
        tcc_error("bad op table");
#endif
    modrm_found:
        modrm_index = i;
        /* if a register is used in another operand then it is
           used instead of group */
        for(i = 0;i < nb_ops; i++) {
            v = op_type[i];
            if (i != modrm_index &&
                (v & (OP_REG | OP_MMX | OP_SSE | OP_CR | OP_TR | OP_DB | OP_SEG))) {
                reg = ops[i].reg;
                break;
            }
        }

        asm_modrm(reg, &ops[modrm_index]);
    }

    /* emit constants */
#ifndef TCC_TARGET_X86_64
    if (pa->opcode == 0x9a || pa->opcode == 0xea) {
        /* ljmp or lcall kludge */
#ifdef I386_ASM_16
        if (s1->seg_size == 16 && o32 == 0)
            gen_expr16(&ops[1].e);
        else
#endif
            gen_expr32(&ops[1].e);
        if (ops[0].e.sym)
            tcc_error("cannot relocate");
        gen_le16(ops[0].e.v);
        return;
    }
#endif
    for(i = 0;i < nb_ops; i++) {
        v = op_type[i];
        if (v & (OP_IM8 | OP_IM16 | OP_IM32 | OP_IM64 | OP_IM8S | OP_ADDR)) {
            /* if multiple sizes are given it means we must look
               at the op size */
            if ((v | OP_IM8 | OP_IM64) == (OP_IM8 | OP_IM16 | OP_IM32 | OP_IM64)) {
                if (s == 0)
                    v = OP_IM8;
                else if (s == 1)
                    v = OP_IM16;
                else if (s == 2 || (v & OP_IM64) == 0)
                    v = OP_IM32;
                else
                    v = OP_IM64;
            }
            if (v & (OP_IM8 | OP_IM8S)) {
                if (ops[i].e.sym)
                    goto error_relocate;
                g(ops[i].e.v);
            } else if (v & OP_IM16) {
#ifdef I386_ASM_16
                if (s1->seg_size == 16)
                    gen_expr16(&ops[i].e);
                else
#endif
                if (ops[i].e.sym)
                error_relocate:
                    tcc_error("cannot relocate");
                else
                    gen_le16(ops[i].e.v);
            } else {
                if (pa->instr_type & (OPC_JMP | OPC_SHORTJMP)) {
                    if (is_short_jmp)
                        g(ops[i].e.v);
#ifdef I386_ASM_16
                    else if (s1->seg_size == 16)
                        gen_disp16(&ops[i].e);
#endif
                    else
                        gen_disp32(&ops[i].e);
                } else {
#ifdef I386_ASM_16
                    if (s1->seg_size == 16 && !((o32 == 1) && (v & OP_IM32)))
                        gen_expr16(&ops[i].e);
                    else
#endif
#ifdef TCC_TARGET_X86_64
                    if (v & OP_IM64)
                        gen_expr64(&ops[i].e);
                    else
#endif
                        gen_expr32(&ops[i].e);
                }
            }
#ifdef I386_ASM_16
        } else if (v & (OP_REG16 | OP_REG32)) {
            if (pa->instr_type & (OPC_JMP | OPC_SHORTJMP)) {
                /* jmp $r */
                g(0xE0 + ops[i].reg);
            }
#endif
#ifdef TCC_TARGET_X86_64
        } else if (v & (OP_REG32 | OP_REG64)) {
            if (pa->instr_type & (OPC_JMP | OPC_SHORTJMP)) {
                /* jmp $r */
                g(0xE0 + ops[i].reg);
            }
#endif
        }
    }
#ifdef I386_ASM_16
    a32 = o32 = 0;
#endif
}

/* return the constraint priority (we allocate first the lowest
   numbered constraints) */
static inline int constraint_priority(const char *str)
{
    int priority, c, pr;

    /* we take the lowest priority */
    priority = 0;
    for(;;) {
        c = *str;
        if (c == '\0')
            break;
        str++;
        switch(c) {
        case 'A':
            pr = 0;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'S':
        case 'D':
            pr = 1;
            break;
        case 'q':
            pr = 2;
            break;
        case 'r':
            pr = 3;
            break;
        case 'N':
        case 'M':
        case 'I':
        case 'i':
        case 'm':
        case 'g':
            pr = 4;
            break;
        default:
            tcc_error("unknown constraint '%c'", c);
            pr = 0;
        }
        if (pr > priority)
            priority = pr;
    }
    return priority;
}

static const char *skip_constraint_modifiers(const char *p)
{
    while (*p == '=' || *p == '&' || *p == '+' || *p == '%')
        p++;
    return p;
}

#define REG_OUT_MASK 0x01
#define REG_IN_MASK  0x02

#define is_reg_allocated(reg) (regs_allocated[reg] & reg_mask)

ST_FUNC void asm_compute_constraints(ASMOperand *operands,
                                    int nb_operands, int nb_outputs,
                                    const uint8_t *clobber_regs,
                                    int *pout_reg)
{
    ASMOperand *op;
    int sorted_op[MAX_ASM_OPERANDS];
    int i, j, k, p1, p2, tmp, reg, c, reg_mask;
    const char *str;
    uint8_t regs_allocated[NB_ASM_REGS];

    /* init fields */
    for(i=0;i<nb_operands;i++) {
        op = &operands[i];
        op->input_index = -1;
        op->ref_index = -1;
        op->reg = -1;
        op->is_memory = 0;
        op->is_rw = 0;
    }
    /* compute constraint priority and evaluate references to output
       constraints if input constraints */
    for(i=0;i<nb_operands;i++) {
        op = &operands[i];
        str = op->constraint;
        str = skip_constraint_modifiers(str);
        if (isnum(*str) || *str == '[') {
            /* this is a reference to another constraint */
            k = find_constraint(operands, nb_operands, str, NULL);
            if ((unsigned)k >= i || i < nb_outputs)
                tcc_error("invalid reference in constraint %d ('%s')",
                      i, str);
            op->ref_index = k;
            if (operands[k].input_index >= 0)
                tcc_error("cannot reference twice the same operand");
            operands[k].input_index = i;
            op->priority = 5;
        } else {
            op->priority = constraint_priority(str);
        }
    }

    /* sort operands according to their priority */
    for(i=0;i<nb_operands;i++)
        sorted_op[i] = i;
    for(i=0;i<nb_operands - 1;i++) {
        for(j=i+1;j<nb_operands;j++) {
            p1 = operands[sorted_op[i]].priority;
            p2 = operands[sorted_op[j]].priority;
            if (p2 < p1) {
                tmp = sorted_op[i];
                sorted_op[i] = sorted_op[j];
                sorted_op[j] = tmp;
            }
        }
    }

    for(i = 0;i < NB_ASM_REGS; i++) {
        if (clobber_regs[i])
            regs_allocated[i] = REG_IN_MASK | REG_OUT_MASK;
        else
            regs_allocated[i] = 0;
    }
    /* esp cannot be used */
    regs_allocated[4] = REG_IN_MASK | REG_OUT_MASK;
    /* ebp cannot be used yet */
    regs_allocated[5] = REG_IN_MASK | REG_OUT_MASK;

    /* allocate registers and generate corresponding asm moves */
    for(i=0;i<nb_operands;i++) {
        j = sorted_op[i];
        op = &operands[j];
        str = op->constraint;
        /* no need to allocate references */
        if (op->ref_index >= 0)
            continue;
        /* select if register is used for output, input or both */
        if (op->input_index >= 0) {
            reg_mask = REG_IN_MASK | REG_OUT_MASK;
        } else if (j < nb_outputs) {
            reg_mask = REG_OUT_MASK;
        } else {
            reg_mask = REG_IN_MASK;
        }
    try_next:
        c = *str++;
        switch(c) {
        case '=':
            goto try_next;
        case '+':
            op->is_rw = 1;
            /* FALL THRU */
        case '&':
            if (j >= nb_outputs)
                tcc_error("'%c' modifier can only be applied to outputs", c);
            reg_mask = REG_IN_MASK | REG_OUT_MASK;
            goto try_next;
        case 'A':
            /* allocate both eax and edx */
            if (is_reg_allocated(TREG_XAX) ||
                is_reg_allocated(TREG_XDX))
                goto try_next;
            op->is_llong = 1;
            op->reg = TREG_XAX;
            regs_allocated[TREG_XAX] |= reg_mask;
            regs_allocated[TREG_XDX] |= reg_mask;
            break;
        case 'a':
            reg = TREG_XAX;
            goto alloc_reg;
        case 'b':
            reg = 3;
            goto alloc_reg;
        case 'c':
            reg = TREG_XCX;
            goto alloc_reg;
        case 'd':
            reg = TREG_XDX;
            goto alloc_reg;
        case 'S':
            reg = 6;
            goto alloc_reg;
        case 'D':
            reg = 7;
        alloc_reg:
            if (is_reg_allocated(reg))
                goto try_next;
            goto reg_found;
        case 'q':
            /* eax, ebx, ecx or edx */
            for(reg = 0; reg < 4; reg++) {
                if (!is_reg_allocated(reg))
                    goto reg_found;
            }
            goto try_next;
        case 'r':
            /* any general register */
            for(reg = 0; reg < 8; reg++) {
                if (!is_reg_allocated(reg))
                    goto reg_found;
            }
            goto try_next;
        reg_found:
            /* now we can reload in the register */
            op->is_llong = 0;
            op->reg = reg;
            regs_allocated[reg] |= reg_mask;
            break;
        case 'i':
            if (!((op->vt->r & (VT_VALMASK | VT_LVAL)) == VT_CONST))
                goto try_next;
            break;
        case 'I':
        case 'N':
        case 'M':
            if (!((op->vt->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST))
                goto try_next;
            break;
        case 'm':
        case 'g':
            /* nothing special to do because the operand is already in
               memory, except if the pointer itself is stored in a
               memory variable (VT_LLOCAL case) */
            /* XXX: fix constant case */
            /* if it is a reference to a memory zone, it must lie
               in a register, so we reserve the register in the
               input registers and a load will be generated
               later */
            if (j < nb_outputs || c == 'm') {
                if ((op->vt->r & VT_VALMASK) == VT_LLOCAL) {
                    /* any general register */
                    for(reg = 0; reg < 8; reg++) {
                        if (!(regs_allocated[reg] & REG_IN_MASK))
                            goto reg_found1;
                    }
                    goto try_next;
                reg_found1:
                    /* now we can reload in the register */
                    regs_allocated[reg] |= REG_IN_MASK;
                    op->reg = reg;
                    op->is_memory = 1;
                }
            }
            break;
        default:
            tcc_error("asm constraint %d ('%s') could not be satisfied",
                  j, op->constraint);
            break;
        }
        /* if a reference is present for that operand, we assign it too */
        if (op->input_index >= 0) {
            operands[op->input_index].reg = op->reg;
            operands[op->input_index].is_llong = op->is_llong;
        }
    }

    /* compute out_reg. It is used to store outputs registers to memory
       locations references by pointers (VT_LLOCAL case) */
    *pout_reg = -1;
    for(i=0;i<nb_operands;i++) {
        op = &operands[i];
        if (op->reg >= 0 &&
            (op->vt->r & VT_VALMASK) == VT_LLOCAL  &&
            !op->is_memory) {
            for(reg = 0; reg < 8; reg++) {
                if (!(regs_allocated[reg] & REG_OUT_MASK))
                    goto reg_found2;
            }
            tcc_error("could not find free output register for reloading");
        reg_found2:
            *pout_reg = reg;
            break;
        }
    }

    /* print sorted constraints */
#ifdef ASM_DEBUG
    for(i=0;i<nb_operands;i++) {
        j = sorted_op[i];
        op = &operands[j];
        printf("%%%d [%s]: \"%s\" r=0x%04x reg=%d\n",
               j,
               op->id ? get_tok_str(op->id, NULL) : "",
               op->constraint,
               op->vt->r,
               op->reg);
    }
    if (*pout_reg >= 0)
        printf("out_reg=%d\n", *pout_reg);
#endif
}

ST_FUNC void subst_asm_operand(CString *add_str,
                              SValue *sv, int modifier)
{
    int r, reg, size, val;
    char buf[64];

    r = sv->r;
    if ((r & VT_VALMASK) == VT_CONST) {
        if (!(r & VT_LVAL) && modifier != 'c' && modifier != 'n')
            cstr_ccat(add_str, '$');
        if (r & VT_SYM) {
            cstr_cat(add_str, get_tok_str(sv->sym->v, NULL));
            if (sv->c.i != 0) {
                cstr_ccat(add_str, '+');
            } else {
                return;
            }
        }
        val = sv->c.i;
        if (modifier == 'n')
            val = -val;
        snprintf(buf, sizeof(buf), "%d", sv->c.i);
        cstr_cat(add_str, buf);
    } else if ((r & VT_VALMASK) == VT_LOCAL) {
        snprintf(buf, sizeof(buf), "%d(%%ebp)", sv->c.i);
        cstr_cat(add_str, buf);
    } else if (r & VT_LVAL) {
        reg = r & VT_VALMASK;
        if (reg >= VT_CONST)
            tcc_error("internal compiler error");
        snprintf(buf, sizeof(buf), "(%%%s)",
                 get_tok_str(TOK_ASM_eax + reg, NULL));
        cstr_cat(add_str, buf);
    } else {
        /* register case */
        reg = r & VT_VALMASK;
        if (reg >= VT_CONST)
            tcc_error("internal compiler error");

        /* choose register operand size */
        if ((sv->type.t & VT_BTYPE) == VT_BYTE)
            size = 1;
        else if ((sv->type.t & VT_BTYPE) == VT_SHORT)
            size = 2;
#ifdef TCC_TARGET_X86_64
        else if ((sv->type.t & VT_BTYPE) == VT_LLONG)
            size = 8;
#endif
        else
            size = 4;
        if (size == 1 && reg >= 4)
            size = 4;

        if (modifier == 'b') {
            if (reg >= 4)
                tcc_error("cannot use byte register");
            size = 1;
        } else if (modifier == 'h') {
            if (reg >= 4)
                tcc_error("cannot use byte register");
            size = -1;
        } else if (modifier == 'w') {
            size = 2;
#ifdef TCC_TARGET_X86_64
        } else if (modifier == 'q') {
            size = 8;
#endif
        }

        switch(size) {
        case -1:
            reg = TOK_ASM_ah + reg;
            break;
        case 1:
            reg = TOK_ASM_al + reg;
            break;
        case 2:
            reg = TOK_ASM_ax + reg;
            break;
        default:
            reg = TOK_ASM_eax + reg;
            break;
#ifdef TCC_TARGET_X86_64
        case 8:
            reg = TOK_ASM_rax + reg;
            break;
#endif
        }
        snprintf(buf, sizeof(buf), "%%%s", get_tok_str(reg, NULL));
        cstr_cat(add_str, buf);
    }
}

/* generate prolog and epilog code for asm statment */
ST_FUNC void asm_gen_code(ASMOperand *operands, int nb_operands,
                         int nb_outputs, int is_output,
                         uint8_t *clobber_regs,
                         int out_reg)
{
    uint8_t regs_allocated[NB_ASM_REGS];
    ASMOperand *op;
    int i, reg;
    static uint8_t reg_saved[NB_SAVED_REGS] = { 3, 6, 7 };

    /* mark all used registers */
    memcpy(regs_allocated, clobber_regs, sizeof(regs_allocated));
    for(i = 0; i < nb_operands;i++) {
        op = &operands[i];
        if (op->reg >= 0)
            regs_allocated[op->reg] = 1;
    }
    if (!is_output) {
        /* generate reg save code */
        for(i = 0; i < NB_SAVED_REGS; i++) {
            reg = reg_saved[i];
            if (regs_allocated[reg]) {
#ifdef I386_ASM_16
                if (tcc_state->seg_size == 16)
                    g(0x66);
#endif
                g(0x50 + reg);
            }
        }

        /* generate load code */
        for(i = 0; i < nb_operands; i++) {
            op = &operands[i];
            if (op->reg >= 0) {
                if ((op->vt->r & VT_VALMASK) == VT_LLOCAL &&
                    op->is_memory) {
                    /* memory reference case (for both input and
                       output cases) */
                    SValue sv;
                    sv = *op->vt;
                    sv.r = (sv.r & ~VT_VALMASK) | VT_LOCAL;
                    load(op->reg, &sv);
                } else if (i >= nb_outputs || op->is_rw) {
                    /* load value in register */
                    load(op->reg, op->vt);
                    if (op->is_llong) {
                        SValue sv;
                        sv = *op->vt;
                        sv.c.ul += 4;
                        load(TREG_XDX, &sv);
                    }
                }
            }
        }
    } else {
        /* generate save code */
        for(i = 0 ; i < nb_outputs; i++) {
            op = &operands[i];
            if (op->reg >= 0) {
                if ((op->vt->r & VT_VALMASK) == VT_LLOCAL) {
                    if (!op->is_memory) {
                        SValue sv;
                        sv = *op->vt;
                        sv.r = (sv.r & ~VT_VALMASK) | VT_LOCAL;
                        load(out_reg, &sv);

                        sv.r = (sv.r & ~VT_VALMASK) | out_reg;
                        store(op->reg, &sv);
                    }
                } else {
                    store(op->reg, op->vt);
                    if (op->is_llong) {
                        SValue sv;
                        sv = *op->vt;
                        sv.c.ul += 4;
                        store(TREG_XDX, &sv);
                    }
                }
            }
        }
        /* generate reg restore code */
        for(i = NB_SAVED_REGS - 1; i >= 0; i--) {
            reg = reg_saved[i];
            if (regs_allocated[reg]) {
#ifdef I386_ASM_16
                if (tcc_state->seg_size == 16)
                    g(0x66);
#endif
                g(0x58 + reg);
            }
        }
    }
}

ST_FUNC void asm_clobber(uint8_t *clobber_regs, const char *str)
{
    int reg;
    TokenSym *ts;

    if (!strcmp(str, "memory") ||
        !strcmp(str, "cc"))
        return;
    ts = tok_alloc(str, strlen(str));
    reg = ts->tok;
    if (reg >= TOK_ASM_eax && reg <= TOK_ASM_edi) {
        reg -= TOK_ASM_eax;
    } else if (reg >= TOK_ASM_ax && reg <= TOK_ASM_di) {
        reg -= TOK_ASM_ax;
#ifdef TCC_TARGET_X86_64
    } else if (reg >= TOK_ASM_rax && reg <= TOK_ASM_rdi) {
        reg -= TOK_ASM_rax;
#endif
    } else {
        tcc_error("invalid clobber register '%s'", str);
    }
    clobber_regs[reg] = 1;
}
