/*
 *  TCC - Tiny C Compiler
 *
 *  Copyright (c) 2001-2004 Fabrice Bellard
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

/* callback pointers */
ST_DATA char **tcc_cb_ptr;
ST_DATA void (*tcc_cb)(const char *, char **);

/********************************************************/
/* global variables */

/* loc : local variable index
   ind : output code index
   rsym: return symbol
   anon_sym: anonymous symbol index
*/
ST_DATA int rsym, anon_sym, ind, loc;
ST_DATA Sym *sym_free_first;
ST_DATA void **sym_pools;
ST_DATA int nb_sym_pools;
static int arraysize = 0;

static const char *global_symname = NULL;
static const char *global_type = NULL;

ST_DATA Sym *global_stack;
ST_DATA Sym *local_stack;
ST_DATA Sym *scope_stack_bottom;
ST_DATA Sym *define_stack;
ST_DATA Sym *global_label_stack;
ST_DATA Sym *local_label_stack;

ST_DATA int vla_sp_loc_tmp; /* vla_sp_loc is set to this when the value won't be needed later */
ST_DATA int vla_sp_root_loc; /* vla_sp_loc for SP before any VLAs were pushed */
ST_DATA int *vla_sp_loc; /* Pointer to variable holding location to store stack pointer on the stack when modifying stack pointer */
ST_DATA int vla_flags; /* VLA_* flags */

ST_DATA SValue __vstack[1+VSTACK_SIZE], *vtop;

ST_DATA int const_wanted; /* true if constant wanted */
ST_DATA int nocode_wanted; /* true if no code generation wanted for an expression */
ST_DATA int global_expr;  /* true if compound literals must be allocated globally (used during initializers parsing */
ST_DATA CType func_vt; /* current function return type (used by return instruction) */
ST_DATA int func_vc;
ST_DATA int last_line_num, last_ind, func_ind; /* debug last line number and pc */
ST_DATA char *funcname;

ST_DATA CType char_pointer_type, func_old_type, int_type, llong_type, size_type;

/* ------------------------------------------------------------------------- */
static inline CType *pointed_type(CType *type);
static int is_compatible_types(CType *type1, CType *type2);
static int parse_btype(CType *type, AttributeDef *ad);
static void type_decl(CType *type, AttributeDef *ad, int *v, int td);
static void parse_expr_type(CType *type);
static void decl_initializer(CType *type, unsigned long c, int first, int size_only);
static void decl_initializer_alloc(CType *type, AttributeDef *ad, int r, int has_init, int v, char *asm_label, int scope);
static int decl0(int l, int is_for_loop_init);
static void expr_eq(void);
static void unary_type(CType *type);
static int is_compatible_parameter_types(CType *type1, CType *type2);
static void expr_type(CType *type);

ST_INLN int is_float(int t)
{
    int bt;
    bt = t & VT_BTYPE;
    return bt == VT_LDOUBLE || bt == VT_DOUBLE || bt == VT_FLOAT || bt == VT_QFLOAT;
}

/* we use our own 'finite' function to avoid potential problems with
   non standard math libs */
/* XXX: endianness dependent */
ST_FUNC int ieee_finite(double d)
{
    int *p = (int *)&d;
    return ((unsigned)((p[1] | 0x800fffff) + 1)) >> 31;
}

ST_FUNC void test_lvalue(void)
{
    if (!(vtop->r & VT_LVAL))
        expect("lvalue");
}

/* ------------------------------------------------------------------------- */
/* symbol allocator */
static Sym *__sym_malloc(void)
{
    Sym *sym_pool, *sym, *last_sym;
    int i;

    sym_pool = malloc(SYM_POOL_NB * sizeof(Sym));
    dynarray_add(&sym_pools, &nb_sym_pools, sym_pool);

    last_sym = sym_free_first;
    sym = sym_pool;
    for(i = 0; i < SYM_POOL_NB; i++) {
        sym->next = last_sym;
        last_sym = sym;
        sym++;
    }
    sym_free_first = last_sym;
    return last_sym;
}

static inline Sym *sym_malloc(void)
{
    Sym *sym;
    sym = sym_free_first;
    if (!sym)
        sym = __sym_malloc();
    sym_free_first = sym->next;
    return sym;
}

ST_INLN void sym_free(Sym *sym)
{
    sym->next = sym_free_first;
    free(sym->asm_label);
    sym_free_first = sym;
}

/* push, without hashing */
ST_FUNC Sym *sym_push2(Sym **ps, int v, int t, long long c)
{
    Sym *s;
    if (ps == &local_stack) {
        for (s = *ps; s && s != scope_stack_bottom; s = s->prev)
            if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM && s->v == v)
                tcc_error("incompatible types for redefinition of '%s'",
                          get_tok_str(v, NULL));
    }
	// printf (" %d %ld set symbol '%s'\n", t, c, get_tok_str(v, NULL));
    s = *ps;
    s = sym_malloc();
    s->asm_label = NULL;
    s->v = v;
    s->type.t = t;
    s->type.ref = NULL;
#ifdef _WIN64
    s->d = NULL;
#endif
    s->c = c;
    s->next = NULL;
    /* add in stack */
    s->prev = *ps;
    *ps = s;
    return s;
}

/* find a symbol and return its associated structure. 's' is the top
   of the symbol stack */
ST_FUNC Sym *sym_find2(Sym *s, int v)
{
    while (s) {
        if (s->v == v)
            return s;
        s = s->prev;
    }
    return NULL;
}

/* structure lookup */
ST_INLN Sym *struct_find(int v)
{
    v -= TOK_IDENT;
    if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT))
        return NULL;
    return table_ident[v]->sym_struct;
}

/* find an identifier */
ST_INLN Sym *sym_find(int v)
{
    v -= TOK_IDENT;
    if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT))
        return NULL;
    return table_ident[v]->sym_identifier;
}

/* push a given symbol on the symbol stack */
ST_FUNC Sym *sym_push(int v, CType *type, int r, long long c)
{
    Sym *s, **ps;
    TokenSym *ts;

    if (local_stack)
        ps = &local_stack;
    else
        ps = &global_stack;
    s = sym_push2(ps, v, type->t, c);
    s->type.ref = type->ref;
    s->r = r;
    /* don't record fields or anonymous symbols */
    /* XXX: simplify */
    if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
        /* record symbol in token array */
        ts = table_ident[(v & ~SYM_STRUCT) - TOK_IDENT];
        if (v & SYM_STRUCT)
            ps = &ts->sym_struct;
        else
            ps = &ts->sym_identifier;
        s->prev_tok = *ps;
        *ps = s;
    }
    return s;
}

/* push a global identifier */
ST_FUNC Sym *global_identifier_push(int v, int t, long long c)
{
    Sym *s, **ps;
    s = sym_push2(&global_stack, v, t, c);
    /* don't record anonymous symbol */
    if (v < SYM_FIRST_ANOM) {
        ps = &table_ident[v - TOK_IDENT]->sym_identifier;
        /* modify the top most local identifier, so that
           sym_identifier will point to 's' when popped */
        while (*ps != NULL)
            ps = &(*ps)->prev_tok;
        s->prev_tok = NULL;
        *ps = s;
    }
    return s;
}

/* pop symbols until top reaches 'b' */
ST_FUNC void sym_pop(Sym **ptop, Sym *b)
{
    Sym *s, *ss, **ps;
    TokenSym *ts;
    int v;

    s = *ptop;
    while(s != b) {
        ss = s->prev;
        v = s->v;
        /* remove symbol in token array */
        /* XXX: simplify */
        if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
            ts = table_ident[(v & ~SYM_STRUCT) - TOK_IDENT];
            if (v & SYM_STRUCT)
                ps = &ts->sym_struct;
            else
                ps = &ts->sym_identifier;
            *ps = s->prev_tok;
        }
        sym_free(s);
        s = ss;
    }
    *ptop = b;
}

static void weaken_symbol(Sym *sym)
{
    sym->type.t |= VT_WEAK;
}

/* ------------------------------------------------------------------------- */

ST_FUNC void swap(int *p, int *q)
{
    int t;
    t = *p;
    *p = *q;
    *q = t;
}

static void vsetc(CType *type, int r, CValue *vc)
{
    if (vtop >= vstack + (VSTACK_SIZE - 1))
        tcc_error("memory full");
    vtop++;
    vtop->type = *type;
    vtop->r = r;
    vtop->r2 = VT_CONST;
    vtop->c = *vc;
}

/* push constant of type "type" with useless value */
void vpush(CType *type)
{
    CValue cval;
    vsetc(type, VT_CONST, &cval);
}

/* push integer constant */
ST_FUNC void vpushi(int v)
{
    CValue cval = {0};
    cval.i = v;
    vsetc(&int_type, VT_CONST, &cval);
}

/* push a pointer sized constant */
static void vpushs(long long v)
{
	CValue cval;
	if (PTR_SIZE == 4)
		cval.i = (int)v;
	else
		cval.ull = v;
	vsetc(&size_type, VT_CONST, &cval);
}

/* push arbitrary 64 bit constant */
void vpush64(int ty, unsigned long long v)
{
	CValue cval;
	CType ctype;
	ctype.t = ty;
	ctype.ref = NULL;
	cval.ull = v;
	vsetc(&ctype, VT_CONST, &cval);
}

/* push long long constant */
ST_FUNC void vpushll(long long v)
{
	CValue cval;
	cval.ll = v;
	vsetc(&llong_type, VT_CONST, &cval);
}

ST_FUNC void vset(CType *type, int r, int v)
{
    CValue cval;

    cval.i = v;
    vsetc(type, r, &cval);
}

static void vseti(int r, int v)
{
    CType type;
    type.t = VT_INT;
    type.ref = 0;
    vset(&type, r, v);
}

ST_FUNC void vswap(void)
{
    SValue tmp;
    /* cannot let cpu flags if other instruction are generated. Also
       avoid leaving VT_JMP anywhere except on the top of the stack
       because it would complicate the code generator. */
    tmp = vtop[0];
    vtop[0] = vtop[-1];
    vtop[-1] = tmp;

/* XXX: +2% overall speed possible with optimized memswap
 *
 *  memswap(&vtop[0], &vtop[1], sizeof *vtop);
 */
}

ST_FUNC void vpushv(SValue *v)
{
    if (vtop >= vstack + (VSTACK_SIZE - 1))
        tcc_error("memory full");
    vtop++;
    *vtop = *v;
}

static void vdup(void)
{
    vpushv(vtop);
}

/* get address of vtop (vtop MUST BE an lvalue) */
static void gaddrof(void)
{
    vtop->r &= ~VT_LVAL;
    /* tricky: if saved lvalue, then we can go back to lvalue */
    if ((vtop->r & VT_VALMASK) == VT_LLOCAL)
        vtop->r = (vtop->r & ~(VT_VALMASK | VT_LVAL_TYPE)) | VT_LOCAL | VT_LVAL;
}

static int pointed_size(CType *type)
{
    int align;
    return type_size(pointed_type(type), &align);
}

#if 0
static inline int is_null_pointer(SValue *p)
{
    if ((p->r & (VT_VALMASK | VT_LVAL | VT_SYM)) != VT_CONST)
        return 0;
    return ((p->type.t & VT_BTYPE) == VT_INT && p->c.i == 0) ||
        ((p->type.t & VT_BTYPE) == VT_LLONG && p->c.ll == 0) ||
	((p->type.t & VT_BTYPE) == VT_PTR && p->c.ptr == 0);
}
#endif

static inline int is_integer_btype(int bt)
{
    return (bt == VT_BYTE || bt == VT_SHORT ||
            bt == VT_INT || bt == VT_LLONG);
}

/* return type size as known at compile time. Put alignment at 'a' */
ST_FUNC int type_size(CType *type, int *a)
{
    Sym *s;
    int bt;

    bt = type->t & VT_BTYPE;
    if (bt == VT_STRUCT) {
        /* struct/union */
        s = type->ref;
        *a = s->r;
        return s->c;
    } else if (bt == VT_PTR) {
        if (type->t & VT_ARRAY) {
            int ts;

            s = type->ref;
            ts = type_size(&s->type, a);

            if (ts < 0 && s->c < 0)
                ts = -ts;

            return ts * s->c;
        } else {
            *a = PTR_SIZE;
            return PTR_SIZE;
        }
    } else if (bt == VT_LDOUBLE) {
        *a = LDOUBLE_ALIGN;
        return LDOUBLE_SIZE;
    } else if (bt == VT_DOUBLE || bt == VT_LLONG) {
#ifdef TCC_TARGET_I386
#ifdef TCC_TARGET_PE
        *a = 8;
#else
        *a = 4;
#endif
#elif defined(TCC_TARGET_ARM)
#ifdef TCC_ARM_EABI
        *a = 8;
#else
        *a = 4;
#endif
#else
        *a = 8;
#endif
        return 8;
	} else if (bt == VT_ENUM) {
		/* Non standard, but still widely used
		 * and implemented in GCC, MSVC */
		*a = 8;
		return 8;
    } else if (bt == VT_INT || bt == VT_FLOAT) {
        *a = 4;
        return 4;
    } else if (bt == VT_SHORT) {
        *a = 2;
        return 2;
    } else if (bt == VT_QLONG || bt == VT_QFLOAT) {
        *a = 8;
        return 16;
    } else {
        /* char, void, function, _Bool */
        *a = 1;
        return 1;
    }
}

/* return the pointed type of t */
static inline CType *pointed_type(CType *type)
{
    return &type->ref->type;
}

/* modify type so that its it is a pointer to type. */
ST_FUNC void mk_pointer(CType *type)
{
    Sym *s;
    s = sym_push(SYM_FIELD, type, 0, -1);
    type->t = VT_PTR | (type->t & ~VT_TYPE);
    type->ref = s;
}

/* compare function types. OLD functions match any new functions */
static int is_compatible_func(CType *type1, CType *type2)
{
    Sym *s1, *s2;

    s1 = type1->ref;
    s2 = type2->ref;
    if (!is_compatible_types(&s1->type, &s2->type))
        return 0;
    /* check func_call */
    if (FUNC_CALL(s1->r) != FUNC_CALL(s2->r))
        return 0;
    /* XXX: not complete */
    if (s1->c == FUNC_OLD || s2->c == FUNC_OLD)
        return 1;
    if (s1->c != s2->c)
        return 0;
    while (s1 != NULL) {
        if (s2 == NULL)
            return 0;
        if (!is_compatible_parameter_types(&s1->type, &s2->type))
            return 0;
        s1 = s1->next;
        s2 = s2->next;
    }
    if (s2)
        return 0;
    return 1;
}

/* return true if type1 and type2 are the same.  If unqualified is
   true, qualifiers on the types are ignored.

   - enums are not checked as gcc __builtin_types_compatible_p ()
 */
static int compare_types(CType *type1, CType *type2, int unqualified)
{
    int bt1, t1, t2;

    t1 = type1->t & VT_TYPE;
    t2 = type2->t & VT_TYPE;
    if (unqualified) {
        /* strip qualifiers before comparing */
        t1 &= ~(VT_CONSTANT | VT_VOLATILE);
        t2 &= ~(VT_CONSTANT | VT_VOLATILE);
    }
    /* XXX: bitfields ? */
    if (t1 != t2)
        return 0;
    /* test more complicated cases */
    bt1 = t1 & VT_BTYPE;
    if (bt1 == VT_PTR) {
        type1 = pointed_type(type1);
        type2 = pointed_type(type2);
        return is_compatible_types(type1, type2);
    } else if (bt1 == VT_STRUCT) {
        return (type1->ref == type2->ref);
    } else if (bt1 == VT_FUNC) {
        return is_compatible_func(type1, type2);
    } else {
        return 1;
    }
}

/* return true if type1 and type2 are exactly the same (including
   qualifiers).
*/
static int is_compatible_types(CType *type1, CType *type2)
{
    return compare_types(type1,type2,0);
}

/* return true if type1 and type2 are the same (ignoring qualifiers).
*/
static int is_compatible_parameter_types(CType *type1, CType *type2)
{
    return compare_types(type1,type2,1);
}

/* print a type. If 'varstr' is not NULL, then the variable is also
   printed in the type */
/* XXX: union */
/* XXX: add array and function pointers */
static void type_to_str(char *buf, int buf_size,
                 CType *type, const char *varstr)
{
    int bt, v, t;
    Sym *s, *sa;
    char buf1[256];
    const char *tstr;
    t = type->t & VT_TYPE;
    bt = t & VT_BTYPE;
    buf[0] = '\0';
    if (t & VT_CONSTANT)
        pstrcat(buf, buf_size, "const ");
    if (t & VT_VOLATILE)
        pstrcat(buf, buf_size, "volatile ");
    if (t & VT_UNSIGNED)
        pstrcat(buf, buf_size, "unsigned ");
    switch(bt) {
    case VT_VOID:
        tstr = "void";
        goto add_tstr;
    case VT_BOOL:
        tstr = "_Bool";
        goto add_tstr;
    case VT_BYTE:
        tstr = "char";
        goto add_tstr;
    case VT_SHORT:
        tstr = "short";
        goto add_tstr;
    case VT_INT:
        tstr = "int";
        goto add_tstr;
    case VT_LONG:
        tstr = "long";
        goto add_tstr;
    case VT_LLONG:
        tstr = "long long";
        goto add_tstr;
    case VT_FLOAT:
        tstr = "float";
        goto add_tstr;
    case VT_DOUBLE:
        tstr = "double";
        goto add_tstr;
    case VT_LDOUBLE:
        tstr = "long double";
    add_tstr:
        pstrcat(buf, buf_size, tstr);
        break;
    case VT_ENUM:
    case VT_STRUCT:
        if (bt == VT_STRUCT)
            tstr = "struct ";
        else
            tstr = "enum ";
        pstrcat(buf, buf_size, tstr);
        v = type->ref->v & ~SYM_STRUCT;
        if (v >= SYM_FIRST_ANOM)
            pstrcat(buf, buf_size, "<anonymous>");
        else
            pstrcat(buf, buf_size, get_tok_str(v, NULL));
        break;
    case VT_FUNC:
        s = type->ref;
        type_to_str(buf, buf_size, &s->type, varstr);
        pstrcat(buf, buf_size, "(");
        sa = s->next;
        while (sa != NULL) {
            type_to_str(buf1, sizeof(buf1), &sa->type, NULL);
            pstrcat(buf, buf_size, buf1);
            sa = sa->next;
            if (sa)
                pstrcat(buf, buf_size, ", ");
        }
        pstrcat(buf, buf_size, ")");
        goto no_var;
    case VT_PTR:
        s = type->ref;
        pstrcpy(buf1, sizeof(buf1), "*");
        if (varstr)
            pstrcat(buf1, sizeof(buf1), varstr);
        type_to_str(buf, buf_size, &s->type, buf1);
        goto no_var;
    }
    if (varstr) {
        pstrcat(buf, buf_size, " ");
        pstrcat(buf, buf_size, varstr);
    }
 no_var: ;
}

/* Parse GNUC __attribute__ extension. Currently, the following
   extensions are recognized:
   - aligned(n) : set data/function alignment.
   - packed : force data alignment to 1
   - unused : currently ignored, but may be used someday.
   - regparm(n) : pass function parameters in registers (i386 only)
 */
static void parse_attribute(AttributeDef *ad)
{
    int t;
	long long n;

    while (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2) {
    next();
    skip('(');
    skip('(');
    while (tok != ')') {
        if (tok < TOK_IDENT)
            expect("attribute name");
        t = tok;
        next();
        switch(t) {
        case TOK_ALIAS1:
        case TOK_ALIAS2:
            skip('(');
            if (tok != TOK_STR)
                expect("alias(\"target\")");
            ad->alias_target = /* save string as token, for later */
              tok_alloc((char*)tokc.cstr->data, tokc.cstr->size-1)->tok;
            next();
            skip(')');
            break;
        case TOK_ALIGNED1:
        case TOK_ALIGNED2:
            if (tok == '(') {
                next();
                n = expr_const();
                if (n <= 0 || (n & (n - 1)) != 0)
                    tcc_error("alignment must be a positive power of two");
                skip(')');
            } else {
                n = MAX_ALIGN;
            }
            ad->aligned = n;
            break;
        case TOK_PACKED1:
        case TOK_PACKED2:
            ad->packed = 1;
            break;
        case TOK_WEAK1:
        case TOK_WEAK2:
            ad->weak = 1;
            break;
        case TOK_UNUSED1:
        case TOK_UNUSED2:
            /* currently, no need to handle it because tcc does not
               track unused objects */
            break;
        case TOK_NORETURN1:
        case TOK_NORETURN2:
            /* currently, no need to handle it because tcc does not
               track unused objects */
            break;
        case TOK_CDECL1:
        case TOK_CDECL2:
        case TOK_CDECL3:
            ad->func_call = FUNC_CDECL;
            break;
        case TOK_STDCALL1:
        case TOK_STDCALL2:
        case TOK_STDCALL3:
            ad->func_call = FUNC_STDCALL;
            break;
#ifdef TCC_TARGET_I386
        case TOK_REGPARM1:
        case TOK_REGPARM2:
            skip('(');
            n = expr_const();
            if (n > 3)
                n = 3;
            else if (n < 0)
                n = 0;
            if (n > 0)
                ad->func_call = FUNC_FASTCALL1 + n - 1;
            skip(')');
            break;
        case TOK_FASTCALL1:
        case TOK_FASTCALL2:
        case TOK_FASTCALL3:
            ad->func_call = FUNC_FASTCALLW;
            break;
#endif
        case TOK_MODE:
            skip('(');
            switch(tok) {
                case TOK_MODE_DI:
                    ad->mode = VT_LLONG + 1;
                    break;
                case TOK_MODE_HI:
                    ad->mode = VT_SHORT + 1;
                    break;
                case TOK_MODE_SI:
                    ad->mode = VT_INT + 1;
                    break;
                default:
                    tcc_warning("__mode__(%s) not supported\n", get_tok_str(tok, NULL));
                    break;
            }
            next();
            skip(')');
            break;
        case TOK_DLLEXPORT:
            ad->func_export = 1;
            break;
        case TOK_DLLIMPORT:
            ad->func_import = 1;
            break;
        default:
            if (tcc_state->warn_unsupported)
                tcc_warning("'%s' attribute ignored", get_tok_str(t, NULL));
            /* skip parameters */
            if (tok == '(') {
                int parenthesis = 0;
                do {
                    if (tok == '(')
                        parenthesis++;
                    else if (tok == ')')
                        parenthesis--;
                    next();
                } while (parenthesis && tok != -1);
            }
            break;
        }
        if (tok != ',')
            break;
        next();
    }
    skip(')');
    skip(')');
    }
}

/* enum/struct/union declaration. u is either VT_ENUM or VT_STRUCT */
static void struct_decl(CType *type, int u)
{
    int a, v, size, align, maxalign, offset;
	long long c = 0;
    int bit_size, bit_pos, bsize, bt, lbit_pos, prevbt;
    Sym *s, *ss, *ass, **ps;
    AttributeDef ad;
    CType type1, btype;
	const char *name = NULL;

	memset (&type1, 0, sizeof (type1));

    a = tok; /* save decl type */
    next();
	name = get_tok_str (tok, NULL);
    if (tok != '{') {
        v = tok;
        next();
        /* struct already defined ? return it */
        if (v < TOK_IDENT)
            expect("struct/union/enum name");
        s = struct_find(v);
        if (s) {
            if (s->type.t != a)
                tcc_error("invalid type");
            goto do_decl;
        }
    } else {
        v = anon_sym++;
    }
    type1.t = a;
    /* we put an undefined size for struct/union */
    s = sym_push(v | SYM_STRUCT, &type1, 0, -1);
    s->r = 0; /* default alignment is zero as gcc */
    /* put struct/union/enum name in type */
 do_decl:
    type->t = u;
    type->ref = s;

    if (tok == '{') {
        next();
        if (s->c != -1)
            tcc_error("struct/union/enum already defined");
        /* cannot be empty */
        c = 0LL;
        /* non empty enums are not allowed */
        if (a == TOK_ENUM) {
		if (!strcmp (name, "{")) {
			// UNNAMED
			fprintf (stderr, "anonymous enums are ignored\n");
		} else {
			tcc_appendf ("%s=enum\n", name);
		}
            for(;;) {
                v = tok;
                if (v < TOK_UIDENT)
                    expect("identifier");
                next();
                if (tok == '=') {
                    next();
                    c = expr_const();
                }
		if (strcmp (name, "{")) {
			char *varstr = get_tok_str (v, NULL);
			tcc_appendf ("%s.%s=0x%"PFMT64x"\n", name, varstr, c);
			tcc_appendf ("%s.0x%"PFMT64x"=%s\n", name, c, varstr);
// TODO: if token already defined throw an error
//  if (varstr isInside (arrayOfvars)) { erprintf ("ERROR: DUP VAR IN ENUM\n"); }
		}
                /* enum symbols have static storage */
                ss = sym_push(v, &llong_type, VT_CONST, c);
                ss->type.t |= VT_STATIC;
                if (tok != ',')
                    break;
                next();
                c++;
                /* NOTE: we accept a trailing comma */
                if (tok == '}')
                    break;
            }
            skip('}');
        } else {
            maxalign = 1;
            ps = &s->next;
            prevbt = VT_INT;
            bit_pos = 0;
            offset = 0;
            while (tok != '}') {
                parse_btype(&btype, &ad);
                while (1) {
                    bit_size = -1;
                    v = 0;
                    type1 = btype;
                    if (tok != ':') {
                        type_decl(&type1, &ad, &v, TYPE_DIRECT | TYPE_ABSTRACT);
                        if (v == 0 && (type1.t & VT_BTYPE) != VT_STRUCT)
                            expect("identifier");
                        if ((type1.t & VT_BTYPE) == VT_FUNC ||
                            (type1.t & (VT_TYPEDEF | VT_STATIC | VT_EXTERN | VT_INLINE)))
                            tcc_error("invalid type for '%s'",
                                  get_tok_str(v, NULL));
                    }
                    if (tok == ':') {
                        next();
                        bit_size = (int)expr_const();
                        /* XXX: handle v = 0 case for messages */
                        if (bit_size < 0)
                            tcc_error("negative width in bit-field '%s'",
                                  get_tok_str(v, NULL));
                        if (v && bit_size == 0)
                            tcc_error("zero width for bit-field '%s'",
                                  get_tok_str(v, NULL));
                    }
                    size = type_size(&type1, &align);
                    if (ad.aligned) {
                        if (align < ad.aligned)
                            align = ad.aligned;
                    } else if (ad.packed) {
                        align = 1;
                    } else if (*tcc_state->pack_stack_ptr) {
                        if (align > *tcc_state->pack_stack_ptr)
                            align = *tcc_state->pack_stack_ptr;
                    }
                    lbit_pos = 0;
                    if (bit_size >= 0) {
                        bt = type1.t & VT_BTYPE;
                        if (bt != VT_INT &&
                            bt != VT_BYTE &&
                            bt != VT_SHORT &&
                            bt != VT_BOOL &&
                            bt != VT_ENUM &&
                            bt != VT_LLONG)
                            tcc_error("bitfields must have scalar type");
                        bsize = size * 8;
                        if (bit_size > bsize) {
                            tcc_error("width of '%s' exceeds its type",
                                  get_tok_str(v, NULL));
                        } else if (bit_size == bsize) {
                            /* no need for bit fields */
                            bit_pos = 0;
                        } else if (bit_size == 0) {
                            /* XXX: what to do if only padding in a
                               structure ? */
                            /* zero size: means to pad */
                            bit_pos = 0;
                        } else {
                            /* we do not have enough room ?
                               did the type change?
                               is it a union? */
                            if ((bit_pos + bit_size) > bsize ||
                                bt != prevbt || a == TOK_UNION)
                                bit_pos = 0;
                            lbit_pos = bit_pos;
                            /* XXX: handle LSB first */
                            type1.t |= VT_BITFIELD |
                                (bit_pos << VT_STRUCT_SHIFT) |
                                (bit_size << (VT_STRUCT_SHIFT + 6));
                            bit_pos += bit_size;
                        }
                        prevbt = bt;
                    } else {
                        bit_pos = 0;
                    }
                    if (v != 0 || (type1.t & VT_BTYPE) == VT_STRUCT) {
                        /* add new memory data only if starting
                           bit field */
                        if (lbit_pos == 0) {
                            if (a == TOK_STRUCT) {
                                c = (c + align - 1) & -align;
                                offset = c;
                                if (size > 0)
                                    c += size;
                            } else {
                                offset = 0;
                                if (size > c)
                                    c = size;
                            }
                            if (align > maxalign)
                                maxalign = align;
			}
#if 1
			char b[1024];
			char *varstr = get_tok_str (v, NULL);
			type_to_str (b, sizeof(b), &type1, NULL);
			tcc_appendf ("%s=struct\n", name);
			tcc_appendf ("[+]struct.%s=%s\n",
				name, varstr);
			/* compact form */
			tcc_appendf ("struct.%s.%s=%s,%d,%d\n",
				name,varstr,b,offset,arraysize);
#if 0
			printf ("struct.%s.%s.type=%s\n", name, varstr, b);
			printf ("struct.%s.%s.offset=%d\n", name, varstr, offset);
			printf ("struct.%s.%s.array=%d\n", name, varstr, arraysize);
#endif
			 //(%s) field (%s) offset=%d array=%d", name, b, get_tok_str(v, NULL), offset, arraysize);
			arraysize = 0;
			if (type1.t & VT_BITFIELD) {
				tcc_appendf (" pos=%d size=%d",
						(type1.t >> VT_STRUCT_SHIFT) & 0x3f,
						(type1.t >> (VT_STRUCT_SHIFT + 6)) & 0x3f);
			}
                        //printf("\n");
#endif
                    }
                    if (v == 0 && (type1.t & VT_BTYPE) == VT_STRUCT) {
                        ass = type1.ref;
                        while ((ass = ass->next) != NULL) {
                           ss = sym_push(ass->v, &ass->type, 0, offset + ass->c);
                           *ps = ss;
                           ps = &ss->next;
                        }
                    } else if (v) {
                        ss = sym_push(v | SYM_FIELD, &type1, 0, offset);
                        *ps = ss;
                        ps = &ss->next;
                    }
                    if (tok == ';' || tok == TOK_EOF)
                        break;
                    skip(',');
                }
                skip(';');
            }
            skip('}');
            /* store size and alignment */
            s->c = (c + maxalign - 1) & -maxalign;
            s->r = maxalign;
        }
    }
}

/* return 0 if no type declaration. otherwise, return the basic type
   and skip it.
 */
static int parse_btype(CType *type, AttributeDef *ad)
{
    int t, u, type_found, typespec_found, typedef_found;
    Sym *s;
    CType type1;

    memset(ad, 0, sizeof(AttributeDef));
    type_found = 0;
    typespec_found = 0;
    typedef_found = 0;
    t = 0;
    while(1) {
        switch(tok) {
        case TOK_EXTENSION:
            /* currently, we really ignore extension */
            next();
            continue;

            /* basic types */
        case TOK_CHAR:
            u = VT_BYTE;
        basic_type:
            next();
        basic_type1:
            if ((t & VT_BTYPE) != 0)
                tcc_error("too many basic types");
            t |= u;
            typespec_found = 1;
            break;
        case TOK_VOID:
            u = VT_VOID;
            goto basic_type;
        case TOK_SHORT:
            u = VT_SHORT;
            goto basic_type;
        case TOK_INT:
            next();
            typespec_found = 1;
            break;
        case TOK_LONG:
            next();
            if ((t & VT_BTYPE) == VT_DOUBLE) {
#ifndef TCC_TARGET_PE
                t = (t & ~VT_BTYPE) | VT_LDOUBLE;
#endif
            } else if ((t & VT_BTYPE) == VT_LONG) {
                t = (t & ~VT_BTYPE) | VT_LLONG;
            } else {
                u = VT_LONG;
                goto basic_type1;
            }
            break;
        case TOK_BOOL:
            u = VT_BOOL;
            goto basic_type;
        case TOK_FLOAT:
            u = VT_FLOAT;
            goto basic_type;
        case TOK_DOUBLE:
            next();
            if ((t & VT_BTYPE) == VT_LONG) {
#ifdef TCC_TARGET_PE
                t = (t & ~VT_BTYPE) | VT_DOUBLE;
#else
                t = (t & ~VT_BTYPE) | VT_LDOUBLE;
#endif
            } else {
                u = VT_DOUBLE;
                goto basic_type1;
            }
            break;
        case TOK_ENUM:
            struct_decl(&type1, VT_ENUM);
        basic_type2:
            u = type1.t;
            type->ref = type1.ref;
            goto basic_type1;
        case TOK_STRUCT:
        case TOK_UNION:
            struct_decl(&type1, VT_STRUCT);
            goto basic_type2;

            /* type modifiers */
        case TOK_CONST1:
        case TOK_CONST2:
        case TOK_CONST3:
            t |= VT_CONSTANT;
            next();
            break;
        case TOK_VOLATILE1:
        case TOK_VOLATILE2:
        case TOK_VOLATILE3:
            t |= VT_VOLATILE;
            next();
            break;
        case TOK_SIGNED1:
        case TOK_SIGNED2:
        case TOK_SIGNED3:
            typespec_found = 1;
            t |= VT_SIGNED;
            next();
            break;
        case TOK_REGISTER:
        case TOK_AUTO:
        case TOK_RESTRICT1:
        case TOK_RESTRICT2:
        case TOK_RESTRICT3:
            next();
            break;
        case TOK_UNSIGNED:
            t |= VT_UNSIGNED;
            next();
            typespec_found = 1;
            break;

            /* storage */
        case TOK_EXTERN:
            t |= VT_EXTERN;
            next();
            break;
        case TOK_STATIC:
            t |= VT_STATIC;
            next();
            break;
        case TOK_TYPEDEF:
            t |= VT_TYPEDEF;
            next();
            break;
        case TOK_INLINE1:
        case TOK_INLINE2:
        case TOK_INLINE3:
            t |= VT_INLINE;
            next();
            break;

            /* GNUC attribute */
        case TOK_ATTRIBUTE1:
        case TOK_ATTRIBUTE2:
            parse_attribute(ad);
            if (ad->mode) {
                u = ad->mode -1;
                t = (t & ~VT_BTYPE) | u;
            }
            break;
            /* GNUC typeof */
        case TOK_TYPEOF1:
        case TOK_TYPEOF2:
        case TOK_TYPEOF3:
            next();
            parse_expr_type(&type1);
            /* remove all storage modifiers except typedef */
            type1.t &= ~(VT_STORAGE&~VT_TYPEDEF);
            goto basic_type2;
        default:
            if (typespec_found || typedef_found)
                goto the_end;
            s = sym_find(tok);
            if (!s || !(s->type.t & VT_TYPEDEF))
                goto the_end;
            typedef_found = 1;
            t |= (s->type.t & ~VT_TYPEDEF);
            type->ref = s->type.ref;
            if (s->r) {
                /* get attributes from typedef */
                if (0 == ad->aligned)
                    ad->aligned = FUNC_ALIGN(s->r);
                if (0 == ad->func_call)
                    ad->func_call = FUNC_CALL(s->r);
                ad->packed |= FUNC_PACKED(s->r);
            }
            next();
            typespec_found = 1;
            break;
        }
        type_found = 1;
    }
the_end:
    if ((t & (VT_SIGNED|VT_UNSIGNED)) == (VT_SIGNED|VT_UNSIGNED))
        tcc_error("signed and unsigned modifier");
    if (tcc_state->char_is_unsigned) {
        if ((t & (VT_SIGNED|VT_UNSIGNED|VT_BTYPE)) == VT_BYTE)
            t |= VT_UNSIGNED;
    }
    t &= ~VT_SIGNED;

    /* long is never used as type */
    if ((t & VT_BTYPE) == VT_LONG)
#if !defined TCC_TARGET_X86_64 || defined TCC_TARGET_PE
        t = (t & ~VT_BTYPE) | VT_INT;
#else
        t = (t & ~VT_BTYPE) | VT_LLONG;
#endif
    type->t = t;
    return type_found;
}

/* convert a function parameter type (array to pointer and function to
   function pointer) */
static inline void convert_parameter_type(CType *pt)
{
    /* remove const and volatile qualifiers (XXX: const could be used
       to indicate a const function parameter */
    pt->t &= ~(VT_CONSTANT | VT_VOLATILE);
    /* array must be transformed to pointer according to ANSI C */
    pt->t &= ~VT_ARRAY;
    if ((pt->t & VT_BTYPE) == VT_FUNC) {
        mk_pointer(pt);
    }
}

static void post_type(CType *type, AttributeDef *ad)
{
    int n, l, t1, arg_size, align;
    Sym **plast, *s, *first;
    AttributeDef ad1;
    CType pt;
char *symname = NULL;
int narg  =0;

    if (tok == '(') {
        /* function declaration */
        next();
        l = 0;
        first = NULL;
        plast = &first;
{
const char *ret_type = global_type;
free (symname);
symname = strdup (global_symname);
tcc_appendf ("func.%s.ret=%s\n", symname, ret_type);
tcc_appendf ("func.%s.cc=%s\n", symname, "cdecl"); // TODO
tcc_appendf ("%s=func\n", symname);
}
        arg_size = 0;
        if (tok != ')') {
            for(;;) {
                /* read param name and compute offset */
                if (l != FUNC_OLD) {
                    if (!parse_btype(&pt, &ad1)) {
                        if (l) {
                            tcc_error("invalid type");
                        } else {
                            l = FUNC_OLD;
                            goto old_proto;
                        }
                    }
                    l = FUNC_NEW;
                    if ((pt.t & VT_BTYPE) == VT_VOID && tok == ')')
                        break;
                    type_decl(&pt, &ad1, &n, TYPE_DIRECT | TYPE_ABSTRACT);
                    if ((pt.t & VT_BTYPE) == VT_VOID)
                        tcc_error("parameter declared as void");
                    arg_size += (type_size(&pt, &align) + PTR_SIZE - 1) / PTR_SIZE;
                } else {
                old_proto:
                    n = tok;
                    if (n < TOK_UIDENT)
                        expect("identifier");
                    pt.t = VT_INT;
                    next();
                }
                convert_parameter_type(&pt);
                s = sym_push(n | SYM_FIELD, &pt, 0, 0);
{
	    char kind[1024];
	    type_to_str (kind, sizeof (kind), &pt, NULL);
	    tcc_appendf ("func.%s.arg.%d=%s,%s\n",
		symname, narg, kind, global_symname);
	    narg++;
}
                *plast = s;
                plast = &s->next;
                if (tok == ')')
                    break;
                skip(',');
                if (l == FUNC_NEW && tok == TOK_DOTS) {
                    l = FUNC_ELLIPSIS;
                    next();
                    break;
                }
            }
        }
	tcc_appendf ("func.%s.args=%d\n", symname, narg);
        /* if no parameters, then old type prototype */
        if (l == 0)
            l = FUNC_OLD;
        skip(')');
        /* NOTE: const is ignored in returned type as it has a special
           meaning in gcc / C++ */
        type->t &= ~VT_CONSTANT;
        /* some ancient pre-K&R C allows a function to return an array
           and the array brackets to be put after the arguments, such
           that "int c()[]" means something like "int[] c()" */
        if (tok == '[') {
            next();
            skip(']'); /* only handle simple "[]" */
            type->t |= VT_PTR;
        }
        /* we push a anonymous symbol which will contain the function prototype */
        ad->func_args = arg_size;
        s = sym_push(SYM_FIELD, type, INT_ATTR(ad), l);
        s->next = first;
        type->t = VT_FUNC;
        type->ref = s;
free(symname);
symname = NULL;
    } else if (tok == '[') {
        /* array definition */
        next();
        if (tok == TOK_RESTRICT1)
            next();
        n = -1;
        t1 = 0;
        if (tok != ']') {
            if (!local_stack || nocode_wanted)
                 vpushll(expr_const());
            else gexpr();
            if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
                n = vtop->c.i;
                if (n < 0)
                    tcc_error("invalid array size");
            } else {
                if (!is_integer_btype(vtop->type.t & VT_BTYPE))
                    tcc_error("size of variable length array should be an integer");
                t1 = VT_VLA;
            }
        }
        skip(']');
        /* parse next post type */
        post_type(type, ad);

        /* we push an anonymous symbol which will contain the array
           element type */
arraysize = n;
#if 0
if (n<0) {
	printf ("array with no size []\n");
} else {
	printf ("PUSH SIZE %d\n", n);
}
#endif
        s = sym_push(SYM_FIELD, type, 0, n);
        type->t = (t1 ? VT_VLA : VT_ARRAY) | VT_PTR;
        type->ref = s;
    }
}

/* Parse a type declaration (except basic type), and return the type
   in 'type'. 'td' is a bitmask indicating which kind of type decl is
   expected. 'type' should contain the basic type. 'ad' is the
   attribute definition of the basic type. It can be modified by
   type_decl().
 */
static void type_decl(CType *type, AttributeDef *ad, int *v, int td)
{
    Sym *s;
    CType type1, *type2;
    int qualifiers, storage;

    while (tok == '*') {
        qualifiers = 0;
    redo:
        next();
        switch(tok) {
        case TOK_CONST1:
        case TOK_CONST2:
        case TOK_CONST3:
            qualifiers |= VT_CONSTANT;
            goto redo;
        case TOK_VOLATILE1:
        case TOK_VOLATILE2:
        case TOK_VOLATILE3:
            qualifiers |= VT_VOLATILE;
            goto redo;
        case TOK_RESTRICT1:
        case TOK_RESTRICT2:
        case TOK_RESTRICT3:
            goto redo;
        }
        mk_pointer(type);
        type->t |= qualifiers;
    }

    /* XXX: clarify attribute handling */
    if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2)
        parse_attribute(ad);

    /* recursive type */
    /* XXX: incorrect if abstract type for functions (e.g. 'int ()') */
    type1.t = 0; /* XXX: same as int */
    if (tok == '(') {
        next();
        /* XXX: this is not correct to modify 'ad' at this point, but
           the syntax is not clear */
        if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2)
            parse_attribute(ad);
        type_decl(&type1, ad, v, td);
        skip(')');
    } else {
        /* type identifier */
        if (tok >= TOK_IDENT && (td & TYPE_DIRECT)) {
            *v = tok;
            next();
        } else {
            if (!(td & TYPE_ABSTRACT))
                expect("identifier");
            *v = 0;
        }
    }
    storage = type->t & VT_STORAGE;
    type->t &= ~VT_STORAGE;
    if (storage & VT_STATIC) {
        int saved_nocode_wanted = nocode_wanted;
        nocode_wanted = 1;
//eprintf ("STATIC %s\n", get_tok_str(*v, NULL));
        post_type(type, ad);
        nocode_wanted = saved_nocode_wanted;
    } else {
{
	    char kind[1024];
	    char *name = get_tok_str (*v, NULL);
	    type_to_str (kind, sizeof(kind), type, NULL);
	    //eprintf ("---%d %s STATIC %s\n", td, kind, name);
	    global_symname = name;
	    global_type = kind;
}
        post_type(type, ad);
}
    type->t |= storage;
    if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2)
        parse_attribute(ad);

    if (!type1.t)
        return;
    /* append type at the end of type1 */
    type2 = &type1;
    for(;;) {
        s = type2->ref;
//eprintf ("ARG:\n");
        type2 = &s->type;
        if (!type2->t) {
            *type2 = *type;
            break;
        }
    }
    *type = type1;
}

/* compute the lvalue VT_LVAL_xxx needed to match type t. */
ST_FUNC int lvalue_type(int t)
{
    int bt, r;
    r = VT_LVAL;
    bt = t & VT_BTYPE;
    if (bt == VT_BYTE || bt == VT_BOOL)
        r |= VT_LVAL_BYTE;
    else if (bt == VT_SHORT)
        r |= VT_LVAL_SHORT;
    else
        return r;
    if (t & VT_UNSIGNED)
        r |= VT_LVAL_UNSIGNED;
    return r;
}

/* indirection with full error checking and bound check */
ST_FUNC void indir(void)
{
    if ((vtop->type.t & VT_BTYPE) != VT_PTR) {
        if ((vtop->type.t & VT_BTYPE) == VT_FUNC)
            return;
        expect("pointer");
    }
    vtop->type = *pointed_type(&vtop->type);
    /* Arrays and functions are never lvalues */
    if (!(vtop->type.t & VT_ARRAY) && !(vtop->type.t & VT_VLA)
        && (vtop->type.t & VT_BTYPE) != VT_FUNC) {
        vtop->r |= lvalue_type(vtop->type.t);
        /* if bound checking, the referenced pointer must be checked */
#ifdef CONFIG_TCC_BCHECK
        if (tcc_state->do_bounds_check)
            vtop->r |= VT_MUSTBOUND;
#endif
    }
}

/* parse an expression of the form '(type)' or '(expr)' and return its
   type */
static void parse_expr_type(CType *type)
{
    int n;
    AttributeDef ad;

    skip('(');
    if (parse_btype(type, &ad)) {
        type_decl(type, &ad, &n, TYPE_ABSTRACT);
    } else {
        expr_type(type);
    }
    skip(')');
}

static void parse_type(CType *type)
{
    AttributeDef ad;
    int n;

    if (!parse_btype(type, &ad)) {
        expect("type");
    }
    type_decl(type, &ad, &n, TYPE_ABSTRACT);
}

static void vpush_tokc(int t)
{
    CType type;
    type.t = t;
    type.ref = 0;
    vsetc(&type, VT_CONST, &tokc);
}

ST_FUNC void unary(void)
{
    int n, t, align, size, r, sizeof_caller;
    CType type;
    Sym *s;
    AttributeDef ad;
    static int in_sizeof = 0;

    sizeof_caller = in_sizeof;
    in_sizeof = 0;
    /* XXX: GCC 2.95.3 does not generate a table although it should be
       better here */
 tok_next:
    switch(tok) {
    case TOK_EXTENSION:
        next();
        goto tok_next;
    case TOK_CINT:
    case TOK_CCHAR:
    case TOK_LCHAR:
        vpushi(tokc.i);
        next();
        break;
    case TOK_CUINT:
        vpush_tokc(VT_INT | VT_UNSIGNED);
        next();
        break;
    case TOK_CLLONG:
        vpush_tokc(VT_LLONG);
        next();
        break;
    case TOK_CULLONG:
        vpush_tokc(VT_LLONG | VT_UNSIGNED);
        next();
        break;
    case TOK_CFLOAT:
        vpush_tokc(VT_FLOAT);
        next();
        break;
    case TOK_CDOUBLE:
        vpush_tokc(VT_DOUBLE);
        next();
        break;
    case TOK_CLDOUBLE:
        vpush_tokc(VT_LDOUBLE);
        next();
        break;
    case TOK___FUNCTION__:
        if (!gnu_ext)
            goto tok_identifier;
        /* fall thru */
    case TOK___FUNC__:
        {
            void *ptr = NULL;
            int len;
            /* special function name identifier */
            len = strlen(funcname) + 1;
            /* generate char[len] type */
            type.t = VT_BYTE;
            mk_pointer(&type);
            type.t |= VT_ARRAY;
            type.ref->c = len;
            memcpy(ptr, funcname, len);
            next();
        }
        break;
    case TOK_LSTR:
#ifdef TCC_TARGET_PE
        t = VT_SHORT | VT_UNSIGNED;
#else
        t = VT_INT;
#endif
        goto str_init;
    case TOK_STR:
        /* string parsing */
        t = VT_BYTE;
    str_init:
        if (tcc_state->warn_write_strings)
            t |= VT_CONSTANT;
        type.t = t;
        mk_pointer(&type);
        type.t |= VT_ARRAY;
        memset(&ad, 0, sizeof(AttributeDef));
        decl_initializer_alloc(&type, &ad, VT_CONST, 2, 0, NULL, 0);
        break;
    case '(':
        next();
        /* cast ? */
        if (parse_btype(&type, &ad)) {
            type_decl(&type, &ad, &n, TYPE_ABSTRACT);
            skip(')');
            /* check ISOC99 compound literal */
            if (tok == '{') {
                    /* data is allocated locally by default */
                if (global_expr)
                    r = VT_CONST;
                else
                    r = VT_LOCAL;
                /* all except arrays are lvalues */
                if (!(type.t & VT_ARRAY))
                    r |= lvalue_type(type.t);
                memset(&ad, 0, sizeof(AttributeDef));
                decl_initializer_alloc(&type, &ad, r, 1, 0, NULL, 0);
            } else {
                if (sizeof_caller) {
                    vpush(&type);
                    return;
                }
                unary();
            }
        } else if (tok == '{') {
            /* statement expression : we do not accept break/continue
               inside as GCC does */
            skip(')');
        } else {
            gexpr();
            skip(')');
        }
        break;
    case '*':
        next();
        unary();
        indir();
        break;
    case '!':
        next();
        unary();
        if ((vtop->r & VT_VALMASK) == VT_CMP)
            vtop->c.i = vtop->c.i ^ 1;
        break;
    case TOK_SIZEOF:
    case TOK_ALIGNOF1:
    case TOK_ALIGNOF2:
        t = tok;
        next();
        in_sizeof++;
        unary_type(&type); // Perform a in_sizeof = 0;
        size = type_size(&type, &align);
        if (t == TOK_SIZEOF) {
            if (!(type.t & VT_VLA)) {
                if (size < 0)
                    tcc_error("sizeof applied to an incomplete type");
                vpushs(size);
			}
        } else {
            vpushs(align);
        }
        vtop->type.t |= VT_UNSIGNED;
        break;

    case TOK_builtin_types_compatible_p:
        {
            CType type1, type2;
            next();
            skip('(');
            parse_type(&type1);
            skip(',');
            parse_type(&type2);
            skip(')');
            type1.t &= ~(VT_CONSTANT | VT_VOLATILE);
            type2.t &= ~(VT_CONSTANT | VT_VOLATILE);
            vpushi(is_compatible_types(&type1, &type2));
        }
        break;
    case TOK_builtin_constant_p:
        {
            int saved_nocode_wanted;
			long long res;
            next();
            skip('(');
            saved_nocode_wanted = nocode_wanted;
            nocode_wanted = 1;
            gexpr();
            res = (vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
            nocode_wanted = saved_nocode_wanted;
            skip(')');
            vpushll(res);
        }
        break;
    case TOK_builtin_frame_address:
        {
            int level;
            CType type;
            next();
            skip('(');
            if (tok != TOK_CINT || tokc.i < 0) {
                tcc_error("__builtin_frame_address only takes positive integers");
            }
            level = tokc.i;
            next();
            skip(')');
            type.t = VT_VOID;
            mk_pointer(&type);
            vset(&type, VT_LOCAL, 0);       /* local frame */
            while (level--) {
                mk_pointer(&vtop->type);
                indir();                    /* -> parent frame */
            }
        }
        break;
#ifdef TCC_TARGET_X86_64
#ifdef TCC_TARGET_PE
    case TOK_builtin_va_start:
        {
            next();
            skip('(');
            expr_eq();
            skip(',');
            expr_eq();
            skip(')');
            if ((vtop->r & VT_VALMASK) != VT_LOCAL)
                tcc_error("__builtin_va_start expects a local variable");
            vtop->r &= ~(VT_LVAL | VT_REF);
            vtop->type = char_pointer_type;
        }
        break;
#else
    case TOK_builtin_va_arg_types:
        {
            CType type;
            int bt;
            next();
            skip('(');
            parse_type(&type);
            skip(')');
            vpushll(classify_x86_64_va_arg(&type));
        }
        break;
#endif
#endif

    // special qnan , snan and infinity values
    case TOK___NAN__:
        vpush64(VT_DOUBLE, 0x7ff8000000000000ULL);
        next();
        break;
    case TOK___SNAN__:
        vpush64(VT_DOUBLE, 0x7ff0000000000001ULL);
        next();
        break;
    case TOK___INF__:
        vpush64(VT_DOUBLE, 0x7ff0000000000000ULL);
        next();
        break;

    default:
    tok_identifier:
        t = tok;
        next();
        if (t < TOK_UIDENT)
            expect("identifier");
        s = sym_find(t);
        if (!s) {
            if (tok != '(')
                tcc_error("'%s' undeclared", get_tok_str(t, NULL));
        }
        if ((s->type.t & (VT_STATIC | VT_INLINE | VT_BTYPE)) ==
            (VT_STATIC | VT_INLINE | VT_FUNC)) {
            /* if referencing an inline function, then we generate a
               symbol to it if not already done. It will have the
               effect to generate code for it at the end of the
               compilation unit. */
            r = VT_SYM | VT_CONST;
        } else {
            r = s->r;
        }
        vset(&s->type, r, s->c);
        /* if forward reference, we must point to s */
        if (vtop->r & VT_SYM) {
            vtop->sym = s;
            vtop->c.ul = 0;
        }
        break;
    }

    /* post operations */
    while (1) {
        if (tok == '.' || tok == TOK_ARROW) {
            int qualifiers;
            /* field */
            if (tok == TOK_ARROW)
                indir();
            qualifiers = vtop->type.t & (VT_CONSTANT | VT_VOLATILE);
            test_lvalue();
            gaddrof();
            next();
            /* expect pointer on structure */
            if ((vtop->type.t & VT_BTYPE) != VT_STRUCT)
                expect("struct or union");
            s = vtop->type.ref;
            /* find field */
            tok |= SYM_FIELD;
            while ((s = s->next) != NULL) {
                if (s->v == tok)
                    break;
            }
            if (!s)
                tcc_error("field not found: %s",  get_tok_str(tok & ~SYM_FIELD, NULL));
            /* add field offset to pointer */
            vtop->type = char_pointer_type; /* change type to 'char *' */
            vpushi(s->c);
            /* change type to field type, and set to lvalue */
            vtop->type = s->type;
            vtop->type.t |= qualifiers;
            /* an array is never an lvalue */
            if (!(vtop->type.t & VT_ARRAY)) {
                vtop->r |= lvalue_type(vtop->type.t);
#ifdef CONFIG_TCC_BCHECK
                /* if bound checking, the referenced pointer must be checked */
                if (tcc_state->do_bounds_check)
                    vtop->r |= VT_MUSTBOUND;
#endif
            }
            next();
        } else if (tok == '[') {
            next();
            gexpr();
            indir();
            skip(']');
		/*
        } else if (tok == '(') {
            SValue ret;
            Sym *sa;
            int nb_args, sret;
		*/
        } else {
            break;
        }
    }
}

ST_FUNC void expr_prod(void)
{
    unary();
    while (tok == '*' || tok == '/' || tok == '%') {
        next();
        unary();
    }
}

ST_FUNC void expr_sum(void)
{
    expr_prod();
    while (tok == '+' || tok == '-') {
        next();
        expr_prod();
    }
}

static void expr_shift(void)
{
    expr_sum();
    while (tok == TOK_SHL || tok == TOK_SAR) {
        next();
        expr_sum();
    }
}

static void expr_cmp(void)
{
    expr_shift();
    while ((tok >= TOK_ULE && tok <= TOK_GT) ||
           tok == TOK_ULT || tok == TOK_UGE) {
        next();
        expr_shift();
    }
}

static void expr_cmpeq(void)
{
    expr_cmp();
    while (tok == TOK_EQ || tok == TOK_NE) {
        next();
        expr_cmp();
    }
}

static void expr_and(void)
{
    expr_cmpeq();
    while (tok == '&') {
        next();
        expr_cmpeq();
    }
}

static void expr_xor(void)
{
    expr_and();
    while (tok == '^') {
        next();
        expr_and();
    }
}

static void expr_or(void)
{
    expr_xor();
    while (tok == '|') {
        next();
        expr_xor();
    }
}

/* XXX: fix this mess */
static void expr_land_const(void)
{
    expr_or();
    while (tok == TOK_LAND) {
        next();
        expr_or();
    }
}

/* XXX: fix this mess */
static void expr_lor_const(void)
{
    expr_land_const();
    while (tok == TOK_LOR) {
        next();
        expr_land_const();
    }
}

/* only used if non constant */
static void expr_land(void)
{
    expr_or();
    if (tok == TOK_LAND) {
        for(;;) {
            if (tok != TOK_LAND) {
                break;
            }
            next();
            expr_or();
        }
    }
}

static void expr_lor(void)
{
    expr_land();
    if (tok == TOK_LOR) {
        for(;;) {
            if (tok != TOK_LOR) {
                break;
            }
            next();
            expr_land();
        }
    }
}

/* XXX: better constant handling */
static void expr_cond(void)
{
    if (const_wanted) {
        expr_lor_const();
        if (tok == '?') {
            vdup();
            next();
            if (tok != ':' || !gnu_ext) {
                gexpr();
            }
            skip(':');
            expr_cond();
        }
    } else {
        expr_lor();
    }
}

static void expr_eq(void)
{
    int t;

    expr_cond();
    if (tok == '=' ||
        (tok >= TOK_A_MOD && tok <= TOK_A_DIV) ||
        tok == TOK_A_XOR || tok == TOK_A_OR ||
        tok == TOK_A_SHL || tok == TOK_A_SAR) {
        test_lvalue();
        t = tok;
        next();
        if (t == '=') {
            expr_eq();
        } else {
            vdup();
            expr_eq();
        }
    }
}

ST_FUNC void gexpr(void)
{
    while (1) {
        expr_eq();
        if (tok != ',')
            break;
        next();
    }
}

/* parse an expression and return its type without any side effect. */
static void expr_type(CType *type)
{
    int saved_nocode_wanted;

    saved_nocode_wanted = nocode_wanted;
    nocode_wanted = 1;
    gexpr();
    *type = vtop->type;
    nocode_wanted = saved_nocode_wanted;
}

/* parse a unary expression and return its type without any side
   effect. */
static void unary_type(CType *type)
{
    int a;

    a = nocode_wanted;
    nocode_wanted = 1;
    unary();
    *type = vtop->type;
    nocode_wanted = a;
}

/* parse a constant expression and return value in vtop.  */
static void expr_const1(void)
{
    int a;
    a = const_wanted;
    const_wanted = 1;
    expr_cond();
    const_wanted = a;
}

/* parse an integer constant and return its value. */
ST_FUNC long long expr_const(void)
{
    long long c = 0LL;
    expr_const1();
    if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) != VT_CONST)
        expect("constant expression");
    c = vtop->c.ll;
    return c;
}

/* return the label token if current token is a label, otherwise
   return zero */
static int is_label(void)
{
    int last_tok;

    /* fast test first */
    if (tok < TOK_UIDENT)
        return 0;
    /* no need to save tokc because tok is an identifier */
    last_tok = tok;
    next();
    if (tok == ':') {
        next();
        return last_tok;
    } else {
        unget_tok(last_tok);
        return 0;
    }
}

/* t is the array or struct type. c is the array or struct
   address. cur_index/cur_field is the pointer to the current
   value. 'size_only' is true if only size info is needed (only used
   in arrays) */
static void decl_designator(CType *type, unsigned long c,
                            long long *cur_index, Sym **cur_field,
                            int size_only)
{
    Sym *s, *f;
	long long index, index_last;
    int notfirst, align, l, nb_elems, elem_size;
    CType type1;

    notfirst = 0;
    elem_size = 0;
    nb_elems = 1;
    if (gnu_ext && (l = is_label()) != 0)
        goto struct_field;
    while (tok == '[' || tok == '.') {
        if (tok == '[') {
            if (!(type->t & VT_ARRAY))
                expect("array type");
            s = type->ref;
            next();
            index = expr_const();
            if (index < 0 || (s->c >= 0 && index >= s->c))
                expect("invalid index");
            if (tok == TOK_DOTS && gnu_ext) {
                next();
                index_last = expr_const();
                if (index_last < 0 ||
                    (s->c >= 0 && index_last >= s->c) ||
                    index_last < index)
                    expect("invalid index");
            } else {
                index_last = index;
            }
            skip(']');
            if (!notfirst)
                *cur_index = index_last;
            type = pointed_type(type);
            elem_size = type_size(type, &align);
            c += index * elem_size;
            /* NOTE: we only support ranges for last designator */
            nb_elems = index_last - index + 1;
            if (nb_elems != 1) {
                notfirst = 1;
                break;
            }
        } else {
            next();
            l = tok;
            next();
        struct_field:
            if ((type->t & VT_BTYPE) != VT_STRUCT)
                expect("struct/union type");
            s = type->ref;
            l |= SYM_FIELD;
            f = s->next;
            while (f) {
                if (f->v == l)
                    break;
                f = f->next;
            }
            if (!f)
                expect("field");
            if (!notfirst)
                *cur_field = f;
            /* XXX: fix this mess by using explicit storage field */
            type1 = f->type;
            type1.t |= (type->t & ~VT_TYPE);
            type = &type1;
            c += f->c;
        }
        notfirst = 1;
    }
    if (notfirst) {
        if (tok == '=') {
            next();
        } else {
            if (!gnu_ext)
                expect("=");
        }
    } else {
        if (type->t & VT_ARRAY) {
            index = *cur_index;
            type = pointed_type(type);
            c += index * type_size(type, &align);
        } else {
            f = *cur_field;
            if (!f)
                tcc_error("too many field init");
            /* XXX: fix this mess by using explicit storage field */
            type1 = f->type;
            type1.t |= (type->t & ~VT_TYPE);
            type = &type1;
            c += f->c;
        }
    }
    decl_initializer(type, c, 0, size_only);
}

#define EXPR_VAL   0
#define EXPR_CONST 1
#define EXPR_ANY   2

/* store a value or an expression directly in global data or in local array */
static void init_putv(CType *type, unsigned long c,
                      long long v, int expr_type)
{
    int saved_global_expr;
    CType dtype;

    switch(expr_type) {
    case EXPR_VAL:
        vpushll(v);
        break;
    case EXPR_CONST:
        /* compound literals must be allocated globally in this case */
        saved_global_expr = global_expr;
        global_expr = 1;
        expr_const1();
        global_expr = saved_global_expr;
        /* NOTE: symbols are accepted */
        if ((vtop->r & (VT_VALMASK | VT_LVAL)) != VT_CONST)
            tcc_error("initializer element is not constant");
        break;
    case EXPR_ANY:
        expr_eq();
        break;
    }

    dtype = *type;
    dtype.t &= ~VT_CONSTANT; /* need to do that to avoid false warning */

    vset(&dtype, VT_LOCAL|VT_LVAL, c);
    vswap();
}

/* put zeros for variable based init */
static void init_putz(CType *t, unsigned long c, int size)
{
	vseti(VT_LOCAL, c);
	vpushi(0);
	vpushs(size);
}

/* 't' contains the type and storage info. 'c' is the offset of the
   object in section 'sec'. If 'sec' is NULL, it means stack based
   allocation. 'first' is true if array '{' must be read (multi
   dimension implicit array init handling). 'size_only' is true if
   size only evaluation is wanted (only for arrays). */
static void decl_initializer(CType *type, unsigned long c,
                             int first, int size_only)
{
    long long index;
    int array_length, n, no_oblock, nb, parlevel, parlevel1, i;
    int size1, align1, expr_type;
    Sym *s, *f;
    CType *t1;

    if (type->t & VT_ARRAY) {
        s = type->ref;
        n = s->c;
        array_length = 0;
        t1 = pointed_type(type);
        size1 = type_size(t1, &align1);

        no_oblock = 1;
        if ((first && tok != TOK_LSTR && tok != TOK_STR) ||
            tok == '{') {
            if (tok != '{')
                tcc_error("character array initializer must be a literal,"
                    " optionally enclosed in braces");
            skip('{');
            no_oblock = 0;
        }

        /* only parse strings here if correct type (otherwise: handle
           them as ((w)char *) expressions */
        if ((tok == TOK_LSTR &&
#ifdef TCC_TARGET_PE
             (t1->t & VT_BTYPE) == VT_SHORT && (t1->t & VT_UNSIGNED)
#else
             (t1->t & VT_BTYPE) == VT_INT
#endif
            ) || (tok == TOK_STR && (t1->t & VT_BTYPE) == VT_BYTE)) {
            while (tok == TOK_STR || tok == TOK_LSTR) {
                int cstr_len, ch;
                CString *cstr;

                cstr = tokc.cstr;
                /* compute maximum number of chars wanted */
                if (tok == TOK_STR)
                    cstr_len = cstr->size;
                else
                    cstr_len = cstr->size / sizeof(nwchar_t);
                cstr_len--;
                nb = cstr_len;
                if (n >= 0 && nb > (n - array_length))
                    nb = n - array_length;
                if (!size_only) {
                    if (cstr_len > nb)
                        tcc_warning("initializer-string for array is too long");
                    /* in order to go faster for common case (char
                       string in global variable, we handle it
                       specifically */
                    for(i=0;i<nb;i++) {
						if (tok == TOK_STR)
							ch = ((unsigned char *)cstr->data)[i];
						else
							ch = ((nwchar_t *)cstr->data)[i];
						init_putv(t1, c + (array_length + i) * size1,
                                      ch, EXPR_VAL);
                    }
                }
                array_length += nb;
                next();
            }
            /* only add trailing zero if enough storage (no
               warning in this case since it is standard) */
            if (n < 0 || array_length < n) {
                if (!size_only) {
                    init_putv(t1, c + (array_length * size1), 0, EXPR_VAL);
                }
                array_length++;
            }
        } else {
            index = 0;
            while (tok != '}') {
                decl_designator(type, c, &index, NULL, size_only);
                if (n >= 0 && index >= n)
                    tcc_error("index too large");
                /* must put zero in holes (note that doing it that way
                   ensures that it even works with designators) */
                if (!size_only && array_length < index) {
                    init_putz(t1, c + array_length * size1,
                              (index - array_length) * size1);
                }
                index++;
                if (index > array_length)
                    array_length = index;
                /* special test for multi dimensional arrays (may not
                   be strictly correct if designators are used at the
                   same time) */
                if (index >= n && no_oblock)
                    break;
                if (tok == '}')
                    break;
                skip(',');
            }
        }
        if (!no_oblock)
            skip('}');
        /* put zeros at the end */
        if (!size_only && n >= 0 && array_length < n) {
            init_putz(t1, c + array_length * size1,
                      (n - array_length) * size1);
        }
        /* patch type size if needed */
        if (n < 0)
            s->c = array_length;
    } else if ((type->t & VT_BTYPE) == VT_STRUCT &&
               (!first || tok == '{')) {
        int par_count;

        /* NOTE: the previous test is a specific case for automatic
           struct/union init */
        /* XXX: union needs only one init */

        /* XXX: this test is incorrect for local initializers
           beginning with ( without {. It would be much more difficult
           to do it correctly (ideally, the expression parser should
           be used in all cases) */
        par_count = 0;
        if (tok == '(') {
            AttributeDef ad1;
            CType type1;
            next();
            while (tok == '(') {
                par_count++;
                next();
            }
            if (!parse_btype(&type1, &ad1))
                expect("cast");
            type_decl(&type1, &ad1, &n, TYPE_ABSTRACT);
#if 0
            if (!is_assignable_types(type, &type1))
                tcc_error("invalid type for cast");
#endif
            skip(')');
        }
        no_oblock = 1;
        if (first || tok == '{') {
            skip('{');
            no_oblock = 0;
        }
        s = type->ref;
        f = s->next;
        array_length = 0;
        index = 0;
        n = s->c;
        while (tok != '}') {
            decl_designator(type, c, NULL, &f, size_only);
            index = f->c;
            if (!size_only && array_length < index) {
                init_putz(type, c + array_length,
                          index - array_length);
            }
            index = index + type_size(&f->type, &align1);
            if (index > array_length)
                array_length = index;

            /* gr: skip fields from same union - ugly. */
            while (f->next) {
                ///printf("index: %2d %08x -- %2d %08x\n", f->c, f->type.t, f->next->c, f->next->type.t);
                /* test for same offset */
                if (f->next->c != f->c)
                    break;
                /* if yes, test for bitfield shift */
                if ((f->type.t & VT_BITFIELD) && (f->next->type.t & VT_BITFIELD)) {
                    int bit_pos_1 = (f->type.t >> VT_STRUCT_SHIFT) & 0x3f;
                    int bit_pos_2 = (f->next->type.t >> VT_STRUCT_SHIFT) & 0x3f;
                    //printf("bitfield %d %d\n", bit_pos_1, bit_pos_2);
                    if (bit_pos_1 != bit_pos_2)
                        break;
                }
                f = f->next;
            }

            f = f->next;
            if (no_oblock && f == NULL)
                break;
            if (tok == '}')
                break;
            skip(',');
        }
        /* put zeros at the end */
        if (!size_only && array_length < n) {
            init_putz(type, c + array_length,
                      n - array_length);
        }
        if (!no_oblock)
            skip('}');
        while (par_count) {
            skip(')');
            par_count--;
        }
    } else if (tok == '{') {
        next();
        decl_initializer(type, c, first, size_only);
        skip('}');
    } else if (size_only) {
        /* just skip expression */
        parlevel = parlevel1 = 0;
        while ((parlevel > 0 || parlevel1 > 0 ||
		(tok != '}' && tok != ',')) &&  tok != -1) {
            if (tok == '(')
                parlevel++;
            else if (tok == ')')
                parlevel--;
	    else if (tok == '{')
		parlevel1++;
	    else if (tok == '}')
		parlevel1--;
            next();
        }
    } else {
        /* currently, we always use constant expression for globals
           (may change for scripting case) */
        expr_type = EXPR_CONST;
        init_putv(type, c, 0, expr_type);
    }
}

/* parse an initializer for type 't' if 'has_init' is non zero, and
   allocate space in local or global data space ('r' is either
   VT_LOCAL or VT_CONST). If 'v' is non zero, then an associated
   variable 'v' with an associated name represented by 'asm_label' of
   scope 'scope' is declared before initializers are parsed. If 'v' is
   zero, then a reference to the new object is put in the value stack.
   If 'has_init' is 2, a special parsing is done to handle string
   constants. */
static void decl_initializer_alloc(CType *type, AttributeDef *ad, int r,
                                   int has_init, int v, char *asm_label,
                                   int scope)
{
    int size, align, addr;
    int level;
    ParseState saved_parse_state = {0};
    TokenString init_str;
    Sym *flexible_array;

    flexible_array = NULL;
    if ((type->t & VT_BTYPE) == VT_STRUCT) {
        Sym *field;
        field = type->ref;
        while (field && field->next)
            field = field->next;
        if (field->type.t & VT_ARRAY && field->type.ref->c < 0)
            flexible_array = field;
    }

    size = type_size(type, &align);
    /* If unknown size, we must evaluate it before
       evaluating initializers because
       initializers can generate global data too
       (e.g. string pointers or ISOC99 compound
       literals). It also simplifies local
       initializers handling */
    tok_str_new(&init_str);
    if (size < 0 || (flexible_array && has_init)) {
        if (!has_init)
            tcc_error("unknown type size");
        /* get all init string */
        if (has_init == 2) {
            /* only get strings */
            while (tok == TOK_STR || tok == TOK_LSTR) {
                tok_str_add_tok(&init_str);
                next();
            }
        } else {
            level = 0;
            while (level > 0 || (tok != ',' && tok != ';')) {
                if (tok < 0)
                    tcc_error("unexpected end of file in initializer");
                tok_str_add_tok(&init_str);
                if (tok == '{')
                    level++;
                else if (tok == '}') {
                    level--;
                    if (level <= 0) {
                        next();
                        break;
                    }
                }
                next();
            }
        }
        tok_str_add(&init_str, -1);
        tok_str_add(&init_str, 0);

        /* compute size */
        save_parse_state(&saved_parse_state);

        macro_ptr = init_str.str;
        next();
        decl_initializer(type, 0, 1, 1);
        /* prepare second initializer parsing */
        macro_ptr = init_str.str;
        next();

        /* if still unknown size, error */
        size = type_size(type, &align);
        if (size < 0)
            tcc_error("unknown type size");
    }
    if (flexible_array)
        size += flexible_array->type.ref->c * pointed_size(&flexible_array->type);
    /* take into account specified alignment if bigger */
    if (ad->aligned) {
        if (ad->aligned > align)
            align = ad->aligned;
    } else if (ad->packed) {
        align = 1;
    }
    if ((r & VT_VALMASK) == VT_LOCAL) {
        loc = (loc - size) & -align;
        addr = loc;
        if (v) {
            /* local variable */
            sym_push(v, type, r, addr);
        } else {
            /* push local reference */
            vset(type, r, addr);
        }
    } else {
        Sym *sym;

        sym = NULL;
        if (v && scope == VT_CONST) {
            /* see if the symbol was already defined */
            sym = sym_find(v);
            if (sym) {
                if (!is_compatible_types(&sym->type, type))
                    tcc_error("incompatible types for redefinition of '%s'",
                          get_tok_str(v, NULL));
                if (sym->type.t & VT_EXTERN) {
                    /* if the variable is extern, it was not allocated */
                    sym->type.t &= ~VT_EXTERN;
                    /* set array size if it was ommited in extern
                       declaration */
                    if ((sym->type.t & VT_ARRAY) &&
                        sym->type.ref->c < 0 &&
                        type->ref->c >= 0)
                        sym->type.ref->c = type->ref->c;
                } else {
                    /* we accept several definitions of the same
                       global variable. this is tricky, because we
                       must play with the SHN_COMMON type of the symbol */
                    /* XXX: should check if the variable was already
                       initialized. It is incorrect to initialized it
                       twice */
                    /* no init data, we won't add more to the symbol */
                    if (!has_init)
                        goto no_alloc;
                }
            }
        }

        if (v) {
            if (scope != VT_CONST || !sym) {
                sym = sym_push(v, type, r | VT_SYM, 0);
                sym->asm_label = asm_label;
            }
        } else {
            CValue cval;

            cval.ul = 0;
            vsetc(type, VT_CONST | VT_SYM, &cval);
            vtop->sym = sym;
        }
        /* patch symbol weakness */
        if ((type->t & VT_WEAK) && sym)
            weaken_symbol(sym);
    }
    no_alloc: ;
}

/* parse an old style function declaration list */
/* XXX: check multiple parameter */
static void func_decl_list(Sym *func_sym)
{
    AttributeDef ad;
    int v;
    Sym *s;
    CType btype, type;

    /* parse each declaration */
    while (tok != '{' && tok != ';' && tok != ',' && tok != TOK_EOF &&
           tok != TOK_ASM1 && tok != TOK_ASM2 && tok != TOK_ASM3) {
        if (!parse_btype(&btype, &ad))
            expect("declaration list");
        if (((btype.t & VT_BTYPE) == VT_ENUM ||
             (btype.t & VT_BTYPE) == VT_STRUCT) &&
            tok == ';') {
            /* we accept no variable after */
        } else {
            for(;;) {
                type = btype;
                type_decl(&type, &ad, &v, TYPE_DIRECT);
                /* find parameter in function parameter list */
                s = func_sym->next;
                while (s != NULL) {
                    if ((s->v & ~SYM_FIELD) == v)
                        goto found;
                    s = s->next;
                }
                tcc_error("declaration for parameter '%s' but no such parameter",
                      get_tok_str(v, NULL));
            found:
                /* check that no storage specifier except 'register' was given */
                if (type.t & VT_STORAGE)
                    tcc_error("storage class specified for '%s'", get_tok_str(v, NULL));
                convert_parameter_type(&type);
                /* we can add the type (NOTE: it could be local to the function) */
                s->type = type;
                /* accept other parameters */
                if (tok == ',')
                    next();
                else
                    break;
            }
        }
        skip(';');
    }
}

/* 'l' is VT_LOCAL or VT_CONST to define default storage type */
static int decl0(int l, int is_for_loop_init)
{
    int v, has_init, r;
    CType type, btype;
    Sym *sym;
    AttributeDef ad;

    for (;;) {
        if (!parse_btype(&btype, &ad)) {
            if (is_for_loop_init)
                return 0;
            /* skip redundant ';' */
            /* XXX: find more elegant solution */
            if (tok == ';') {
                next();
                continue;
            }
            if (l == VT_CONST &&
                (tok == TOK_ASM1 || tok == TOK_ASM2 || tok == TOK_ASM3)) {
                /* global asm block */
#if 1
eprintf ("global asm not supported\n");
return 1;
#endif
                //asm_global_instr();
                continue;
            }
            /* special test for old K&R protos without explicit int
               type. Only accepted when defining global data */
            if (l == VT_LOCAL || tok < TOK_DEFINE)
                break;
            btype.t = VT_INT;
        }
        if (((btype.t & VT_BTYPE) == VT_ENUM ||
             (btype.t & VT_BTYPE) == VT_STRUCT) &&
            tok == ';') {
            /* we accept no variable after */
            next();
            continue;
        }
        while (1) { /* iterate thru each declaration */
            type = btype;
            type_decl(&type, &ad, &v, TYPE_DIRECT);
#if 0
            {
                char buf[500];
                type_to_str(buf, sizeof(buf), t, get_tok_str(v, NULL));
                printf("type = '%s'\n", buf);
            }
#endif
            if ((type.t & VT_BTYPE) == VT_FUNC) {
                if ((type.t & VT_STATIC) && (l == VT_LOCAL)) {
                    tcc_error("function without file scope cannot be static");
                }
                /* if old style function prototype, we accept a
                   declaration list */
                sym = type.ref;
                if (sym->c == FUNC_OLD)
                    func_decl_list(sym);
            }

            if (ad.weak)
                type.t |= VT_WEAK;
#ifdef TCC_TARGET_PE
            if (ad.func_import)
                type.t |= VT_IMPORT;
            if (ad.func_export)
                type.t |= VT_EXPORT;
#endif
            if (tok == '{') {
                if (l == VT_LOCAL)
                    tcc_error("cannot use local functions");
                if ((type.t & VT_BTYPE) != VT_FUNC)
                    expect("function definition");

                /* reject abstract declarators in function definition */
                sym = type.ref;
                while ((sym = sym->next) != NULL)
                    if (!(sym->v & ~SYM_FIELD))
                       expect("identifier");

                /* XXX: cannot do better now: convert extern line to static inline */
                if ((type.t & (VT_EXTERN | VT_INLINE)) == (VT_EXTERN | VT_INLINE))
                    type.t = (type.t & ~VT_EXTERN) | VT_STATIC;

                sym = sym_find(v);
                if (sym) {
                    if ((sym->type.t & VT_BTYPE) != VT_FUNC)
                        goto func_error1;

                    r = sym->type.ref->r;
                    /* use func_call from prototype if not defined */
                    if (FUNC_CALL(r) != FUNC_CDECL
                     && FUNC_CALL(type.ref->r) == FUNC_CDECL)
                        FUNC_CALL(type.ref->r) = FUNC_CALL(r);

                    /* use export from prototype */
                    if (FUNC_EXPORT(r))
                        FUNC_EXPORT(type.ref->r) = 1;

                    /* use static from prototype */
                    if (sym->type.t & VT_STATIC)
                        type.t = (type.t & ~VT_EXTERN) | VT_STATIC;

                    if (!is_compatible_types(&sym->type, &type)) {
                    func_error1:
                        tcc_error("incompatible types for redefinition of '%s'",
                              get_tok_str(v, NULL));
                    }
                    /* if symbol is already defined, then put complete type */
                    sym->type = type;
                } else {
                    /* put function symbol */
                    sym = global_identifier_push(v, type.t, 0);
                    sym->type.ref = type.ref;
                }
				break;
            } else {
                if (btype.t & VT_TYPEDEF) {
                    /* save typedefed type  */
                    /* XXX: test storage specifiers ? */
                    sym = sym_push(v, &type, INT_ATTR(&ad), 0);
                    sym->type.t |= VT_TYPEDEF;
                } else {
                    r = 0;
                    if ((type.t & VT_BTYPE) == VT_FUNC) {
                        /* external function definition */
                        /* specific case for func_call attribute */
                        type.ref->r = INT_ATTR(&ad);
                    } else if (!(type.t & VT_ARRAY)) {
                        /* not lvalue if array */
                        r |= lvalue_type(type.t);
                    }
                    has_init = (tok == '=');
                    if (has_init && (type.t & VT_VLA))
                        tcc_error("Variable length array cannot be initialized");
                                    }
                if (tok != ',') {
                    if (is_for_loop_init)
                        return 1;
                    skip(';');
                    break;
                }
                next();
            }
            ad.aligned = 0;
        }
    }
    return 0;
}

ST_FUNC void decl(int l)
{
    decl0(l, 0);
}
