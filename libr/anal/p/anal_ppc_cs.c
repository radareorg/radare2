/* radare2 - LGPL - Copyright 2013-2016 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/ppc.h>

struct Getarg {
    csh handle;
    cs_insn *insn;
    int bits;
};

#define esilprintf(op, fmt, arg...) r_strbuf_appendf (&op->esil, fmt, ##arg)
#define INSOPS insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

ut64 mask64(ut64 mb, ut64 me) {
    int i;
    ut64 mask = 0;
    if (mb < 0 || me < 0 || mb > 63 || me > 63) {
        return mask;
    }

    if (mb < (me + 1)) {
        for(i = mb; i <= me ; i++) {
            mask = mask | (ut64)(1LL << (63 - i));
        }
    } else if (mb == (me + 1)) {
        mask = 0xffffffffffffffffull;
    } else if (mb > (me + 1)) {
        ut64 lo = mask64(0, me);
        ut64 hi = mask64(mb, 63);
        mask = lo | hi;
    }
    return mask;
}

const char* cmask64(const char *mb_c, const char *me_c){
    static char cmask[32];
    ut64 mb = 0;
    ut64 me = 0;
    if (mb_c) mb = atol(mb_c);
    if (me_c) me = atol(me_c);
    snprintf(cmask, sizeof(cmask), "0x%"PFMT64x"", mask64(mb, me));
    return cmask;
}

ut32 mask32(ut32 mb, ut32 me) {
    int i;
    ut32 mask = 0;
    if (mb < 0 || me < 0 || mb > 31 || me > 31) {
        return mask;
    }

    if (mb < (me + 1)) {
        for(i = mb; i <= me ; i++) {
            mask = mask | (ut32)(1LL << (31 - i));
        }
    } else if (mb == (me + 1)) {
        mask = 0xffffffffu;
    } else if (mb > (me + 1)) {
        ut32 lo = mask32(0, me);
        ut32 hi = mask32(mb, 31);
        mask = lo | hi;
    }
    return mask;
}

const char* cmask32(const char *mb_c, const char *me_c){
    static char cmask[32];
    ut32 mb = 32;
    ut32 me = 32;
    if (mb_c) mb += atol(mb_c);
    if (me_c) me += atol(me_c);
    snprintf(cmask, sizeof(cmask), "0x%"PFMT32x"", mask32(mb, me));
    return cmask;
}

const char* inv_mask64(const char *mb_c, const char *sh){
    static char cmask[32];
    ut64 mb = 0;
    ut64 me = 0;
    if (mb_c) mb = atol(mb_c);
    if (sh) me = atol(sh);
    snprintf(cmask, sizeof(cmask), "0x%"PFMT64x"", mask64(mb, ~me));
    return cmask;
}

const char* inv_mask32(const char *mb_c, const char *sh){
    static char cmask[32];
    ut32 mb = 0;
    ut32 me = 0;
    if (mb_c) mb = atol(mb_c);
    if (sh) me = atol(sh);
    snprintf(cmask, sizeof(cmask), "0x%"PFMT32x"", mask32(mb, ~me));
    return cmask;
}

static char *getarg2(struct Getarg *gop, int n, const char *setstr) {
    cs_insn *insn = gop->insn;
    csh handle = gop->handle;
    static char words[8][64];
    cs_ppc_op op;

    if (n < 0 || n >= 8) {
        return NULL;
    }
    op = INSOP (n);
    switch (op.type) {
    case PPC_OP_INVALID:
        strcpy (words[n], "invalid");
        break;
    case PPC_OP_REG:
        snprintf (words[n], sizeof (words[n]), 
            "%s%s", cs_reg_name (handle, op.reg), setstr);
        break;
    case PPC_OP_IMM:
        snprintf (words[n], sizeof (words[n]), 
            "0x%"PFMT64x"%s", (ut64)op.imm, setstr);
        break;
    case PPC_OP_MEM:
        snprintf (words[n], sizeof (words[n]), 
            "%"PFMT64d",%s,+,%s",
            (ut64)op.mem.disp,
            cs_reg_name (handle, op.mem.base), setstr);
        break;
    case PPC_OP_CRX: // Condition Register field
        snprintf (words[n], sizeof (words[n]), 
            "%"PFMT64d"%s", (ut64)op.imm, setstr);
        break;
    }
    return words[n];
}

#define ARG(n) getarg2(&gop, n, "")
#define ARG2(n,m) getarg2(&gop, n, m)

static int set_reg_profile(RAnal *anal) {
    const char *p = NULL;
    if(anal->bits == 32){
        p =
        "=PC    pc\n"
        "=SP    r1\n"
        "=SR    srr1\n" // status register ??
        "=A0    r3\n" // also for ret
        "=A1    r4\n"
        "=A2    r5\n"
        "=A3    r6\n"
        "=A4    r7\n"
        "=A5    r8\n"
        "=A6    r6\n"
        "gpr    srr0    .32 0   0\n"
        "gpr    srr1    .32 4   0\n"
        "gpr    r0  .32 8   0\n"
        "gpr    r1  .32 12  0\n"
        "gpr    r2  .32 16  0\n"
        "gpr    r3  .32 20  0\n"
        "gpr    r4  .32 24  0\n"
        "gpr    r5  .32 28  0\n"
        "gpr    r6  .32 32  0\n"
        "gpr    r7  .32 36  0\n"
        "gpr    r8  .32 40  0\n"
        "gpr    r9  .32 44  0\n"
        "gpr    r10 .32 48  0\n"
        "gpr    r11 .32 52  0\n"
        "gpr    r12 .32 56  0\n"
        "gpr    r13 .32 60  0\n"
        "gpr    r14 .32 64  0\n"
        "gpr    r15 .32 68  0\n"
        "gpr    r16 .32 72  0\n"
        "gpr    r17 .32 76  0\n"
        "gpr    r18 .32 80  0\n"
        "gpr    r19 .32 84  0\n"
        "gpr    r20 .32 88  0\n"
        "gpr    r21 .32 92  0\n"
        "gpr    r22 .32 96  0\n"
        "gpr    r23 .32 100 0\n"
        "gpr    r24 .32 104 0\n"
        "gpr    r25 .32 108 0\n"
        "gpr    r26 .32 112 0\n"
        "gpr    r27 .32 116 0\n"
        "gpr    r28 .32 120 0\n"
        "gpr    r29 .32 124 0\n"
        "gpr    r30 .32 128 0\n"
        "gpr    r31 .32 132 0\n"
        "gpr    cr0 .8  136 0\n"
        "gpr    cr1 .8  137 0\n"
        "gpr    cr2 .8  138 0\n"
        "gpr    cr3 .8  139 0\n"
        "gpr    cr4 .8  140 0\n"
        "gpr    cr5 .8  141 0\n"
        "gpr    cr6 .8  142 0\n"
        "gpr    cr7 .8  143 0\n"
        "gpr    xer .32 144 0\n"
        "gpr    lr  .32 148 0\n"
        "gpr    ctr .32 152 0\n"
        "gpr    mq  .32 156 0\n"
        "gpr    vrsave  .32 160 0\n"
        "gpr    pvr .32 164 0\n"
        "gpr    dccr    .32 168 0\n"
        "gpr    iccr    .32 172 0\n"
        "gpr    dear    .32 176 0\n"
        "gpr    msr .32 180 0\n"
        "gpr    pc  .32 184 0\n"
        "gpr    mask    .32 188 0\n";
    } else {
        p =
        "=PC    pc\n"
        "=SP    r1\n"
        "=SR    srr1\n" // status register ??
        "=A0    r3\n" // also for ret
        "=A1    r4\n"
        "=A2    r5\n"
        "=A3    r6\n"
        "=A4    r7\n"
        "=A5    r8\n"
        "=A6    r6\n"
        "gpr    srr0    .64 0   0\n"
        "gpr    srr1    .64 8   0\n"
        "gpr    r0  .64 16  0\n"
        "gpr    r1  .64 24  0\n"
        "gpr    r2  .64 32  0\n"
        "gpr    r3  .64 40  0\n"
        "gpr    r4  .64 48  0\n"
        "gpr    r5  .64 56  0\n"
        "gpr    r6  .64 64  0\n"
        "gpr    r7  .64 72  0\n"
        "gpr    r8  .64 80  0\n"
        "gpr    r9  .64 88  0\n"
        "gpr    r10 .64 96  0\n"
        "gpr    r11 .64 104 0\n"
        "gpr    r12 .64 112 0\n"
        "gpr    r13 .64 120 0\n"
        "gpr    r14 .64 128 0\n"
        "gpr    r15 .64 136 0\n"
        "gpr    r16 .64 144 0\n"
        "gpr    r17 .64 152 0\n"
        "gpr    r18 .64 160 0\n"
        "gpr    r19 .64 168 0\n"
        "gpr    r20 .64 176 0\n"
        "gpr    r21 .64 184 0\n"
        "gpr    r22 .64 192 0\n"
        "gpr    r23 .64 200 0\n"
        "gpr    r24 .64 208 0\n"
        "gpr    r25 .64 216 0\n"
        "gpr    r26 .64 224 0\n"
        "gpr    r27 .64 232 0\n"
        "gpr    r28 .64 240 0\n"
        "gpr    r29 .64 248 0\n"
        "gpr    r30 .64 256 0\n"
        "gpr    r31 .64 264 0\n"
        "gpr    cr0 .8  272 0\n"
        "gpr    cr1 .8  273 0\n"
        "gpr    cr2 .8  274 0\n"
        "gpr    cr3 .8  275 0\n"
        "gpr    cr4 .8  276 0\n"
        "gpr    cr5 .8  277 0\n"
        "gpr    cr6 .8  278 0\n"
        "gpr    cr7 .8  279 0\n"
        "gpr    xer .64 280 0\n"
        "gpr    lr  .64 288 0\n"
        "gpr    ctr .64 296 0\n"
        "gpr    mq  .64 304 0\n"
        "gpr    vrsave  .64 312 0\n"
        "gpr    pvr .64 320 0\n"
        "gpr    dccr    .32 328 0\n"
        "gpr    iccr    .32 336 0\n"
        "gpr    dear    .32 344 0\n"
        "gpr    msr .64 352 0\n"
        "gpr    pc  .64 360 0\n"
        "gpr    mask    .64 368 0\n";
    }
    return r_reg_set_profile_string (anal->reg, p);
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
    static csh handle = 0;
    static int omode = -1;
    int n, ret;
    cs_insn *insn;
    int mode = (a->bits == 64)? CS_MODE_64: (a->bits == 32)? CS_MODE_32: 0;
    mode |= CS_MODE_BIG_ENDIAN;
    if (mode != omode) {
        cs_close (&handle);
        handle = 0;
        omode = mode;
    }
    if (handle == 0) {
        ret = cs_open (CS_ARCH_PPC, mode, &handle);
        if (ret != CS_ERR_OK) {
            return -1;
        }
        cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    op->delay = 0;
    op->type = R_ANAL_OP_TYPE_NULL;
    op->jump = UT64_MAX;
    op->fail = UT64_MAX;
    op->ptr = op->val = UT64_MAX;
    op->size = 4;

    r_strbuf_init (&op->esil);
    r_strbuf_set (&op->esil, "");
    
    // capstone-next
    n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
    if (n < 1) {
        op->type = R_ANAL_OP_TYPE_ILL;
    } else {
        struct Getarg gop = {
            .handle = handle,
            .insn = insn,
            .bits = a->bits
        };
        op->size = insn->size;
        op->id = insn->id;
        switch (insn->id) {
        case PPC_INS_CMPB:
        case PPC_INS_CMPD:
        case PPC_INS_CMPDI:
        case PPC_INS_CMPLD:
        case PPC_INS_CMPLDI:
        case PPC_INS_CMPLW:
        case PPC_INS_CMPLWI:
        case PPC_INS_CMPW:
        case PPC_INS_CMPWI:
            op->type = R_ANAL_OP_TYPE_CMP;
            esilprintf (op, "%s,%s,-,cr,=", ARG(1), ARG(0));
            break;
        case PPC_INS_MFLR:
            op->type = R_ANAL_OP_TYPE_PUSH;
            esilprintf (op, "pc,%s,=", ARG(0));
            break;
        case PPC_INS_MTLR:
            op->type = R_ANAL_OP_TYPE_POP;
            esilprintf (op, "%s,lr,=", ARG(0));
            break;
        case PPC_INS_MR:
        case PPC_INS_LI:
            esilprintf (op, "%s,%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_LIS:
            op->type = R_ANAL_OP_TYPE_MOV;
            esilprintf (op, "%s0000,%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_RLWINM:
            op->type = R_ANAL_OP_TYPE_ROL;
            break;
        case PPC_INS_SC:
            op->type = R_ANAL_OP_TYPE_SWI;
            esilprintf (op, "0,$");
            break;
        case PPC_INS_SYNC:
        case PPC_INS_ISYNC:
        case PPC_INS_LWSYNC:
        case PPC_INS_MSYNC:
        case PPC_INS_PTESYNC:
        case PPC_INS_TLBSYNC:
        case PPC_INS_SLBIA:
        case PPC_INS_SLBIE:
        case PPC_INS_SLBMFEE:
        case PPC_INS_SLBMTE:
        case PPC_INS_NOP:
            op->type = R_ANAL_OP_TYPE_NOP;
            esilprintf (op, ",");
            break;
        case PPC_INS_STW:
        case PPC_INS_STWU:
        case PPC_INS_STWUX:
        case PPC_INS_STWX:
            op->type = R_ANAL_OP_TYPE_STORE;
            esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[4]"));
            break;
        case PPC_INS_STB:
        case PPC_INS_STBU:
            op->type = R_ANAL_OP_TYPE_MOV;
            esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[1]"));
            break;
        case PPC_INS_STH:
        case PPC_INS_STHU:
            op->type = R_ANAL_OP_TYPE_MOV;
            esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[2]"));
            break;
        case PPC_INS_STD:
        case PPC_INS_STDU:
            op->type = R_ANAL_OP_TYPE_MOV;
            esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[8]"));
            break;
        case PPC_INS_STWBRX:
        case PPC_INS_STWCX:
            op->type = R_ANAL_OP_TYPE_STORE;
            break;
        case PPC_INS_LA:
        case PPC_INS_LBZ:
        case PPC_INS_LBZU:
        case PPC_INS_LBZUX:
        case PPC_INS_LBZX:
            op->type = R_ANAL_OP_TYPE_LOAD;
            esilprintf (op, "%s,[1],%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_LD:
        case PPC_INS_LDARX:
        case PPC_INS_LDBRX:
        case PPC_INS_LDU:
        case PPC_INS_LDUX:
        case PPC_INS_LDX:
            op->type = R_ANAL_OP_TYPE_LOAD;
            esilprintf (op, "%s,[8],%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_LFD:
        case PPC_INS_LFDU:
        case PPC_INS_LFDUX:
        case PPC_INS_LFDX:
        case PPC_INS_LFIWAX:
        case PPC_INS_LFIWZX:
        case PPC_INS_LFS:
        case PPC_INS_LFSU:
        case PPC_INS_LFSUX:
        case PPC_INS_LFSX:
            op->type = R_ANAL_OP_TYPE_LOAD;
            esilprintf (op, "%s,[4],%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_LHA:
        case PPC_INS_LHAU:
        case PPC_INS_LHAUX:
        case PPC_INS_LHAX:
        case PPC_INS_LHBRX:
        case PPC_INS_LHZ:
        case PPC_INS_LHZU:
            op->type = R_ANAL_OP_TYPE_LOAD;
            esilprintf (op, "%s,[2],%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_LWA:
        case PPC_INS_LWARX:
        case PPC_INS_LWAUX:
        case PPC_INS_LWAX:
        case PPC_INS_LWBRX:
        case PPC_INS_LWZ:
        case PPC_INS_LWZU:
        case PPC_INS_LWZUX:
        case PPC_INS_LWZX:
            op->type = R_ANAL_OP_TYPE_LOAD;
            esilprintf (op, "%s,[4],%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_SLW:
        case PPC_INS_SLWI:
            op->type = R_ANAL_OP_TYPE_SHL;
            esilprintf (op, "%s,%s,<<,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_SRW:
        case PPC_INS_SRWI:
            op->type = R_ANAL_OP_TYPE_SHR;
            esilprintf (op, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_MULLI:
        case PPC_INS_MULLW:
            op->type = R_ANAL_OP_TYPE_MUL;
            esilprintf (op, "%s,%s,*,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_SUB:
        case PPC_INS_SUBC:
        case PPC_INS_SUBF:
        case PPC_INS_SUBFIC:
        case PPC_INS_SUBFZE:
            op->type = R_ANAL_OP_TYPE_SUB;
            esilprintf (op, "%s,%s,-,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_ADD:
        case PPC_INS_ADDI:
            op->type = R_ANAL_OP_TYPE_ADD;
            esilprintf (op, "%s,%s,+,%s,=,cf", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_ADDC:
        case PPC_INS_ADDIC:
            op->type = R_ANAL_OP_TYPE_ADD;
            esilprintf (op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_ADDE:
        case PPC_INS_ADDIS:
        case PPC_INS_ADDME:
        case PPC_INS_ADDZE:
            op->type = R_ANAL_OP_TYPE_ADD;
            esilprintf (op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_MTSPR:
            op->type = R_ANAL_OP_TYPE_MOV;
            esilprintf (op, "%s,%s,=", ARG(1), ARG(0));
            break;
        case PPC_INS_BCTR: // switch table here
        case PPC_INS_BCTRL: // switch table here
            op->type = R_ANAL_OP_TYPE_UJMP;
            esilprintf (op, "ctr,pc,=");
            break;
        case PPC_INS_BC:
            op->type = R_ANAL_OP_TYPE_UJMP;
            esilprintf (op, "%s,pc,=", ARG(0));
            break;
        case PPC_INS_B:
        case PPC_INS_BA:
            op->type = R_ANAL_OP_TYPE_JMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            switch (insn->detail->ppc.bc) {
            case PPC_BC_INVALID:
                op->type = R_ANAL_OP_TYPE_JMP;
                op->jump = (ut64)insn->detail->ppc.operands[0].imm;
                esilprintf (op, "%s,pc,=", ARG(0));
                break;
            case PPC_BC_LT:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                esilprintf (op, "cr,0,<,1,?{,%s,pc,=,BREAK,},pc,4,+=", ARG(0));
                break;
            case PPC_BC_LE:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                esilprintf (op, "cr,0,<=,1,?{,%s,pc,=,BREAK,},pc,4,+=", ARG(0));
                break;
            case PPC_BC_EQ:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                esilprintf (op, "cr,0,==,1,?{,%s,pc,=,BREAK,},pc,4,+=", ARG(0));
                break;
            case PPC_BC_GE:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                esilprintf (op, "cr,0,>,1,?{,%s,pc,=,BREAK,},pc,4,+=", ARG(0));
                break;
            case PPC_BC_GT:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                esilprintf (op, "cr,0,>=,1,?{,%s,pc,=,BREAK,},pc,4,+=", ARG(0));
                break;
            case PPC_BC_NE:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                esilprintf (op, "cr,0,!=,1,?{,%s,pc,=,BREAK,},pc,4,+=", ARG(0));
                break;
            case PPC_BC_UN:
            case PPC_BC_NU:
            case PPC_BC_SO:
            case PPC_BC_NS:
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->fail = addr + 4;
                break;
            default:
                break;
            }
            switch (insn->detail->ppc.operands[0].type) {
            case PPC_OP_CRX:
                op->type = R_ANAL_OP_TYPE_CJMP;
                break;
            case PPC_OP_REG:
                if (op->type == R_ANAL_OP_TYPE_CJMP) {
                    op->type = R_ANAL_OP_TYPE_UCJMP;
                } else {
                    op->type = R_ANAL_OP_TYPE_CJMP;
                }
                op->jump = (ut64)insn->detail->ppc.operands[1].imm;
                op->fail = addr+4;
                //op->type = R_ANAL_OP_TYPE_UJMP;
            default:
                break;
            }
            break;
        case PPC_INS_BDNZ:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            esilprintf (op, "ctr,0,!=,1,?{,%s,pc,=,BREAK,},4,pc,+=", ARG(0));
            break;
        case PPC_INS_BDNZA:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            break;
        case PPC_INS_BDNZL:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            break;
        case PPC_INS_BDNZLA:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            break;
        case PPC_INS_BDNZLR:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->fail = addr+4;
            esilprintf (op, "ctr,0,!=,1,?{,lr,pc,=,},");
            break;
        case PPC_INS_BDNZLRL:
            op->fail = addr+4;
            op->type = R_ANAL_OP_TYPE_CJMP;
            break;
        case PPC_INS_BDZ:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            esilprintf (op, "ctr,0,==,1,?{,%s,pc,=,}", ARG(0));
            break;
        case PPC_INS_BDZA:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            break;
        case PPC_INS_BDZL:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            break;
        case PPC_INS_BDZLA:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr+4;
            break;
        case PPC_INS_BDZLR:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->fail = addr+4;
            esilprintf (op, "ctr,0,==,1,?{,lr,pc,=,}");
            break;
        case PPC_INS_BDZLRL:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->fail = addr+4;
            break;
        case PPC_INS_NOR:
            op->type = R_ANAL_OP_TYPE_NOR;
            esilprintf (op, "%s,!,%s,|,%s,=", ARG(1), ARG(2), ARG(0));
            break;
        case PPC_INS_XOR:
        case PPC_INS_XORI:
            op->type = R_ANAL_OP_TYPE_XOR;
            esilprintf (op, "%s,%s,^,%s,=", ARG(1), ARG(2), ARG(0));
            break;
        case PPC_INS_XORIS:
            op->type = R_ANAL_OP_TYPE_XOR;
            esilprintf (op, "16,%s,>>,%s,^,%s,=", ARG(1), ARG(2), ARG(0));
            break;
        case PPC_INS_DIVD:
        case PPC_INS_DIVDU:
        case PPC_INS_DIVW:
        case PPC_INS_DIVWU:
            op->type = R_ANAL_OP_TYPE_DIV;
            esilprintf (op, "%s,%s,/,%s,=", ARG(1), ARG(2), ARG(0));
            break;
        case PPC_INS_BL:
        case PPC_INS_BLA:
            op->type = R_ANAL_OP_TYPE_CALL;
            op->jump = (ut64)insn->detail->ppc.operands[0].imm;
            op->fail = addr + 4;
            esilprintf (op, "pc,lr,=,%s,pc,=", ARG(0));
            break;
        case PPC_INS_TRAP:
            op->type = R_ANAL_OP_TYPE_TRAP;
            break;
        case PPC_INS_BLR:
        case PPC_INS_BLRL:
            op->type = R_ANAL_OP_TYPE_RET;
            esilprintf (op, "lr,pc,=");
            break;
        case PPC_INS_AND:
        case PPC_INS_NAND:
        case PPC_INS_ANDI:
        case PPC_INS_ANDIS:
            op->type = R_ANAL_OP_TYPE_AND;
            esilprintf (op, "%s,%s,&,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_OR:
        case PPC_INS_ORC:
        case PPC_INS_ORI:
        case PPC_INS_ORIS:
            op->type = R_ANAL_OP_TYPE_OR;
            esilprintf (op, "%s,%s,|,%s,=", ARG(2), ARG(1), ARG(0));
            break;
        case PPC_INS_MFPVR:
            esilprintf (op, "pvr,%s,=", ARG(0));
            break;
        case PPC_INS_MFCTR:
            esilprintf (op, "ctr,%s,=", ARG(0));
            break;
        case PPC_INS_MFDCCR:
            esilprintf (op, "dccr,%s,=", ARG(0));
            break;
        case PPC_INS_MFICCR:
            esilprintf (op, "iccr,%s,=", ARG(0));
            break;
        case PPC_INS_MFDEAR:
            esilprintf (op, "dear,%s,=", ARG(0));
            break;
        case PPC_INS_MFMSR:
            esilprintf (op, "msr,%s,=", ARG(0));
            break;
        case PPC_INS_MTCTR:
            esilprintf (op, "%s,ctr,=", ARG(0));
            break;
        case PPC_INS_MTDCCR:
            esilprintf (op, "%s,dccr,=", ARG(0));
            break;
        case PPC_INS_MTICCR:
            esilprintf (op, "%s,iccr,=", ARG(0));
            break;
        case PPC_INS_MTDEAR:
            esilprintf (op, "%s,dear,=", ARG(0));
            break;
        case PPC_INS_MTMSR:
        case PPC_INS_MTMSRD:
            esilprintf (op, "%s,msr,=", ARG(0));
            break;
        // Data Cache Block Zero
        case PPC_INS_DCBZ:
            op->type = R_ANAL_OP_TYPE_STORE;
            esilprintf (op, "%s,%s", ARG(0), ARG2(1, "=[128]"));
            break;
        case PPC_INS_RLDCL:
        case PPC_INS_RLDICL:
            op->type = R_ANAL_OP_TYPE_ROL;
            esilprintf (op, "%s,%s,<<<,0x%"PFMT64x",&,%s,=", ARG(2), ARG(1), cmask64(ARG(3), "63"), ARG(0));
            break;
        }
        r_strbuf_fini (&op->esil);
        cs_free (insn, n);
        //cs_close (&handle);
    }
    return op->size;
}

static int archinfo(RAnal *anal, int q) {
    return 4; /* :D */
}

RAnalPlugin r_anal_plugin_ppc_cs = {
    .name = "ppc",
    .desc = "Capstone PowerPC analysis",
    .license = "BSD",
    .esil = true,
    .arch = "ppc",
    .bits = 32|64,
    .archinfo = archinfo,
    .op = &analop,
    .set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_ppc_cs,
    .version = R2_VERSION
};
#endif
