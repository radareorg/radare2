/* LGPLv2 - Tiny C Compiler - 2001-2004 fbellard, 2009-2024 pancake */

#include "tcc.h"

#define TCC_ERR(...) do { \
	tcc_error (s1, __VA_ARGS__); \
	return; \
} while (0)

/* ------------------------------------------------------------------------- */
static inline CType *pointed_type(CType *type);
static bool is_compatible_types(CType *type1, CType *type2);
static void expr_type(TCCState *s1, CType *type);
static int parse_btype(TCCState *s1, CType *type, AttributeDef *ad);
static void type_decl(TCCState *s1, CType *type, AttributeDef *ad, int *v, int td);
static void decl_initializer(TCCState *s1, CType *type, unsigned long c, int first, int size_only);
static void decl_initializer_alloc(TCCState *s1, CType *type, AttributeDef *ad, int r, int has_init, int v, char *asm_label, int scope);
static void expr_eq(TCCState *s1);
static void unary_type(TCCState *s1, CType *type);
static bool is_compatible_parameter_types(CType *type1, CType *type2);

/* ------------------------------------------------------------------------- */
static inline bool is_structured(CType *t) {
	return (t->t & VT_BTYPE) == VT_STRUCT || (t->t & VT_BTYPE) == VT_UNION;
}

static inline bool is_struct(CType *t) {
	return (t->t & VT_BTYPE) == VT_STRUCT;
}

static inline bool is_union(CType *t) {
	return (t->t & VT_BTYPE) == VT_UNION;
}

static inline bool is_enum(CType *t) {
	return (t->t & VT_BTYPE) == VT_ENUM;
}

static void gexpr(TCCState *s1) {
	while (tcc_nerr (s1) == 0) {
		expr_eq (s1);
		if (s1->tok != ',') {
			break;
		}
		next (s1);
	}
}

static inline bool is_float(int t) {
	int bt = t & VT_BTYPE;
	return bt == VT_LDOUBLE || bt == VT_DOUBLE || bt == VT_FLOAT || bt == VT_QFLOAT;
}

static inline bool not_structured(CType *t) {
	return (t->t & VT_BTYPE) != VT_STRUCT && (t->t & VT_BTYPE) != VT_UNION;
}

ST_FUNC void test_lvalue(TCCState *s1) {
	if (!(s1->vtop->r & VT_LVAL)) {
		expect (s1, "lvalue");
	}
}

/* symbol allocator */
static Sym *__sym_malloc(TCCState *s1) {
	Sym *sym_pool = calloc (SYM_POOL_NB, sizeof (Sym));
	if (!sym_pool) {
		return NULL;
	}
	dynarray_add (&s1->sym_pools, &s1->nb_sym_pools, sym_pool);
	Sym *last_sym = s1->sym_free_first;
	Sym *sym = sym_pool;
	int i;
	for (i = 0; i < SYM_POOL_NB; i++) {
		sym->next = last_sym;
		last_sym = sym;
		sym++;
	}
	s1->sym_free_first = last_sym;
	return last_sym;
}

static inline Sym *sym_malloc(TCCState *s1) {
	Sym *sym = s1->sym_free_first;
	if (!sym) {
		sym = __sym_malloc (s1);
	}
	s1->sym_free_first = sym->next;
	return sym;
}

static inline void sym_free(TCCState *s1, Sym *sym) {
	sym->next = s1->sym_free_first;
	free (sym->asm_label);
	s1->sym_free_first = sym;
}

/* push, without hashing */
ST_FUNC Sym *sym_push2(TCCState *s1, Sym **ps, int v, int t, long long c) {
#if 0
	if (ps == &local_stack) {
		for (s = *ps; s && s != scope_stack_bottom; s = s->prev) {
			if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM && s->v == v) {
				tcc_error (s1, "incompatible types for redefinition of '%s'",
					get_tok_str (s1, v, NULL));
				return NULL;
			}
		}
	}
#endif
	// printf (" %d %ld set symbol '%s'\n", t, c, get_tok_str(v, NULL));
	// s = *ps;
	Sym *s = sym_malloc (s1);
	if (s) {
		s->asm_label = NULL;
		s->v = v;
		s->type.t = t;
		s->type.ref = NULL;
		s->c = c;
		s->next = NULL;
		/* add in stack */
		s->prev = *ps;
		*ps = s;
	}
	return s;
}

/* structure lookup */
static Sym *struct_find(TCCState *s1, int v) {
	v -= TOK_IDENT;
	if ((unsigned) v >= (unsigned) (s1->tok_ident - TOK_IDENT)) {
		return NULL;
	}
	return s1->table_ident[v]->sym_struct;
}

/* find an identifier */
static inline Sym *sym_find(TCCState *s1, int v) {
	v -= TOK_IDENT;
	if ((unsigned) v >= (unsigned) (s1->tok_ident - TOK_IDENT)) {
		return NULL;
	}
	return s1->table_ident[v]->sym_identifier;
}

// TODO: Add better way to store the meta information about the pushed type
int tcc_sym_push(TCCState *s1, char *typename, int typesize, int meta) {
	CType new_type = {
		.ref = sym_malloc (s1),
		.t = meta
	};
	Sym *sym = sym_push (s1, 0, &new_type, 0, 0);
	return sym != NULL;
}

#if 0
static void dump_type(TCCState *s1, CType *type, int depth) {
	if (depth <= 0) {
		return;
	}
	eprintf ("------------------------\n");
	int bt = type->t & VT_BTYPE;
	eprintf ("BTYPE = %d ", bt);
	switch (bt) {
	case VT_UNION: eprintf ("[UNION]\n");
		break;
	case VT_STRUCT: eprintf ("[STRUCT]\n");
		break;
	case VT_PTR: eprintf ("[PTR]\n");
		break;
	case VT_ENUM: eprintf ("[ENUM]\n");
		break;
	case VT_INT64: eprintf ("[INT64_T]\n");
		break;
	case VT_INT32: eprintf ("[INT32_T]\n");
		break;
	case VT_INT16: eprintf ("[INT16_T]\n");
		break;
	case VT_INT8: eprintf ("[INT8_T]\n");
		break;
	default:
		eprintf ("\n");
		break;
	}
	if (type->ref) {
		eprintf ("v = %d\n", type->ref->v);
		char *varstr = NULL;
		varstr = get_tok_str (s1, type->ref->v, NULL);
		if (varstr) {
			eprintf ("var = %s\n", varstr);
		}
		if (type->ref->asm_label) {
			eprintf ("asm_label = %s\n", type->ref->asm_label);
		}
		eprintf ("r = %d\n", type->ref->r);
		eprintf ("associated type:\n");
		// dump_type(&(type->ref->type), --depth);
	}
}
#endif

/* push a given symbol on the symbol stack */
ST_FUNC Sym *sym_push(TCCState *s1, int v, CType *type, int r, long long c) {
	Sym **ps;

	if (s1->local_stack) {
		ps = &s1->local_stack;
	} else {
		ps = &s1->global_stack;
	}
	// dump_type(type, 5);
	Sym *s = sym_push2 (s1, ps, v, type->t, c);
	if (!s) {
		return NULL;
	}
	s->type.ref = type->ref;
	s->r = r;
	/* don't record fields or anonymous symbols */
	if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
		int i = (v & ~SYM_STRUCT);
		if (i < TOK_IDENT) {
			return NULL;
		}
		// ts = table_ident[i - TOK_IDENT];
		/* record symbol in token array */
		TokenSym *ts = s1->table_ident[(v & ~SYM_STRUCT) - TOK_IDENT];
		if (v & SYM_STRUCT) {
			ps = &ts->sym_struct;
		} else {
			ps = &ts->sym_identifier;
		}
		s->prev_tok = *ps;
		*ps = s;
	}
	return s;
}

#if 1
/* push a global identifier */
ST_FUNC Sym *global_identifier_push(TCCState *s1, int v, int t, long long c) {
	Sym *s = sym_push2 (s1, &s1->global_stack, v, t, c);
	/* don't record anonymous symbol */
	if (s && v < SYM_FIRST_ANOM) {
		int i = (v & ~SYM_STRUCT);
		if (i < TOK_IDENT) {
			R_LOG_WARN ("token not found");
			return NULL;
		}
		Sym **ps = &s1->table_ident[i - TOK_IDENT]->sym_identifier;
		/* modify the top most local identifier, to make sym_identifier point to 's' when popped */
		while (*ps) {
			ps = &(*ps)->prev_tok;
		}
		s->prev_tok = NULL;
		*ps = s;
	}
	return s;
}
#endif

/* pop symbols until top reaches 'b' */
ST_FUNC void sym_pop(TCCState *s1, Sym **ptop, Sym *b) {
	Sym *ss, **ps;
	TokenSym *ts;
	int v;
	if (!b) {
		return;
	}

	Sym *s = *ptop;
	while (s != b) {
		ss = s->prev;
		v = s->v;
		/* remove symbol in token array */
		if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
			int i = (v & ~SYM_STRUCT);
			if (i < TOK_IDENT) {
				R_LOG_WARN ("token not found");
				return;
			}
			ts = s1->table_ident[i - TOK_IDENT]; //(v & ~SYM_STRUCT) - TOK_IDENT];
			if (v & SYM_STRUCT) {
				ps = &ts->sym_struct;
			} else {
				ps = &ts->sym_identifier;
			}
			*ps = s->prev_tok;
		}
		sym_free (s1, s);
		s = ss;
	}
	*ptop = b;
}

static void weaken_symbol(Sym *sym) {
	sym->type.t |= VT_WEAK;
}

static void vsetc(TCCState *s1, CType *type, int r, CValue *vc) {
	if (s1->vtop >= s1->vstack + (VSTACK_SIZE - 1)) {
		TCC_ERR ("memory full");
	}
	s1->vtop++;
	s1->vtop->type = *type;
	s1->vtop->r = r;
	s1->vtop->r2 = VT_CONST;
	s1->vtop->c = *vc;
}

/* push constant of type "type" with useless value */
void vpush(TCCState *s1, CType *type) {
	CValue cval = {0};
	vsetc (s1, type, VT_CONST, &cval);
}

/* push integer constant */
ST_FUNC void vpushi(TCCState *s1, int v) {
	CValue cval = {0};
	// cval.i = v;
	cval.ll = v;
	vsetc (s1, &s1->int32_type, VT_CONST, &cval);
}

/* push a pointer sized constant */
static void vpushs(TCCState *s1, long long v) {
	CValue cval;
	if (PTR_SIZE == 4) {
		cval.i = (int) v;
	} else {
		cval.ull = v;
	}
	vsetc (s1, &s1->size_type, VT_CONST, &cval);
}

/* push arbitrary 64 bit constant */
void vpush64(TCCState *s1, int ty, unsigned long long v) {
	CValue cval = {
		.ull = v
	};
	CType ctype = {
		.t = ty,
		.ref = NULL
	};
	vsetc (s1, &ctype, VT_CONST, &cval);
}

/* push long long constant */
static void vpushll(TCCState *s1, long long v) {
	CValue cval = { .ll = v };
	vsetc (s1, &s1->int64_type, VT_CONST, &cval);
}

static void vset(TCCState *s1, CType *type, int r, int v) {
	CValue cval = { .i = v };
	vsetc (s1, type, r, &cval);
}

static inline void vseti(TCCState *s1, int r, int v) {
	CType type = {
		.t = VT_INT32,
		.ref = NULL
	};
	vset (s1, &type, r, v);
}

static inline void vswap(TCCState *s1) {
	/* cannot let cpu flags if other instruction are generated. Also
	** avoid leaving VT_JMP anywhere except on the top of the stack
	** because it would complicate the code generator. */
	SValue tmp = s1->vtop[0];
	s1->vtop[0] = s1->vtop[-1];
	s1->vtop[-1] = tmp;
}

static inline void vpushv(TCCState *s1, SValue *v) {
	if (s1->vtop >= s1->vstack + (VSTACK_SIZE - 1)) {
		TCC_ERR ("memory full");
	}
	s1->vtop++;
	*s1->vtop = *v;
}

static void vdup(TCCState *s1) {
	vpushv (s1, s1->vtop);
}

/* get address of s1->vtop (vtop MUST BE an lvalue) */
static void gaddrof(TCCState *s1) {
	s1->vtop->r &= ~VT_LVAL;
	/* tricky: if saved lvalue, then we can go back to lvalue */
	if ((s1->vtop->r & VT_VALMASK) == VT_LLOCAL) {
		s1->vtop->r = (s1->vtop->r & ~(VT_VALMASK | VT_LVAL_TYPE)) | VT_LOCAL | VT_LVAL;
	}
}

static int pointed_size(TCCState *s1, CType *type) {
	int align;
	return type_size (s1, pointed_type (type), &align);
}

static inline int is_integer_btype(int bt) {
	return bt == VT_INT8 || bt == VT_INT16 || bt == VT_INT32 || bt == VT_INT64;
}

/* return type size as known at compile time. Put alignment at 'a' */
ST_FUNC int type_size(TCCState *s1, CType *type, int *a) {
	Sym *s;
	int bt = type->t & VT_BTYPE;
	if (is_structured (type)) {
		/* struct/union */
		s = type->ref;
		*a = s->r;
		return s->c;
	}
	if (bt == VT_PTR) {
		if (type->t & VT_ARRAY) {
			s = type->ref;
			int ts = type_size (s1, &s->type, a);
			if (ts < 0 && s->c < 0) {
				ts = -ts;
			}
			return ts * s->c;
		}
		*a = PTR_SIZE;
		return PTR_SIZE;
	}
	if (bt == VT_LDOUBLE) {
		*a = LDOUBLE_ALIGN;
		return LDOUBLE_SIZE;
	}
	if (bt == VT_DOUBLE || bt == VT_INT64) {
		if (r_str_startswith (s1->arch, "x86") && s1->bits == 32) {
			if (r_str_startswith (s1->os, "windows")) {
				*a = 8;
			} else {
				*a = 4;
			}
#if 0
		} else if (!strncmp (s1->arch, "arm", 3)) {
			/* It was like originally:
			#ifdef TCC_ARM_EABI
				*a = 8;
			#else
				*a = 4;
			#endif
			FIXME: Determine EABI then too
			*/
			*a = 8;
#endif
		} else {
			*a = 8;
		}
		return 8;
	}
	if (bt == VT_ENUM) {
		/* Non standard, but still widely used and implemented in GCC, MSVC */
		*a = 8;
		return 8;
	}
	if (bt == VT_INT32 || bt == VT_FLOAT) {
		*a = 4;
		return 4;
	}
	if (bt == VT_INT16) {
		*a = 2;
		return 2;
	}
	if (bt == VT_QLONG || bt == VT_QFLOAT) {
		*a = 8;
		return 16;
	}
	/* char, void, function, _Bool */
	*a = 1;
	return 1;
}

/* return the pointed type of t */
static inline CType *pointed_type(CType *type) {
	return &type->ref->type;
}

/* modify type so that its it is a pointer to type. */
ST_FUNC void mk_pointer(TCCState *s1, CType *type) {
	Sym *s = sym_push (s1, SYM_FIELD, type, 0, -1);
	if (s) {
		type->t = VT_PTR | (type->t & ~VT_TYPE);
		type->ref = s;
	}
}

/* compare function types. OLD functions match any new functions */
static bool is_compatible_func(CType *type1, CType *type2) {
	Sym *s1 = type1->ref;
	Sym *s2 = type2->ref;
	if (!is_compatible_types (&s1->type, &s2->type)) {
		return false;
	}
	/* check func_call */
	if (FUNC_CALL (s1->r) != FUNC_CALL (s2->r)) {
		return false;
	}
	/* XXX: not complete */
	if (s1->c == FUNC_OLD || s2->c == FUNC_OLD) {
		return true;
	}
	if (s1->c != s2->c) {
		return false;
	}
	while (s1) {
		if (!s2) {
			return false;
		}
		if (!is_compatible_parameter_types (&s1->type, &s2->type)) {
			return false;
		}
		s1 = s1->next;
		s2 = s2->next;
	}
	return s2? false: true;
}

/* return true if type1 and type2 are the same.
 * If unqualified is true, qualifiers on the types are ignored.
 * enums are not checked as gcc __builtin_types_compatible_p ()
 */
static bool compare_types(CType *type1, CType *type2, int unqualified) {
	int t1 = type1->t & VT_TYPE;
	int t2 = type2->t & VT_TYPE;
	if (unqualified) {
		/* strip qualifiers before comparing */
		t1 &= ~(VT_CONSTANT | VT_VOLATILE);
		t2 &= ~(VT_CONSTANT | VT_VOLATILE);
	}
	/* XXX: bitfields ? */
	if (t1 != t2) {
		return false;
	}
	const int bt1 = t1 & VT_BTYPE;
	if (bt1 == VT_PTR) {
		type1 = pointed_type (type1);
		type2 = pointed_type (type2);
		return is_compatible_types (type1, type2);
	}
	if (bt1 == VT_STRUCT || bt1 == VT_UNION) {
		return type1->ref == type2->ref;
	}
	if (bt1 == VT_FUNC) {
		return is_compatible_func (type1, type2);
	}
	return true;
}

/* return true if type1 and type2 are exactly the same (including qualifiers) */
static bool is_compatible_types(CType *type1, CType *type2) {
	return compare_types (type1, type2, 0);
}

/* return true if type1 and type2 are the same (ignoring qualifiers).
*/
static bool is_compatible_parameter_types(CType *type1, CType *type2) {
	return compare_types (type1, type2, 1);
}

/* print a type. If 'varstr' is not NULL, then the variable is also
 * printed in the type */
/* XXX: union */
/* XXX: add array and function pointers */
static void type_to_str(TCCState *s1, char *buf, int buf_size, CType *type, const char *varstr) {
	int bt, v, t;
	Sym *s, *sa;
	char buf1[256];
	const char *tstr;
	t = type->t & VT_TYPE;
	bt = t & VT_BTYPE;
	buf[0] = '\0';
	if (t & VT_CONSTANT) {
		strcat2 (buf, buf_size, "const ");
	}
	if (t & VT_VOLATILE) {
		strcat2 (buf, buf_size, "volatile ");
	}
	switch (bt) {
	case VT_VOID:
		tstr = "void";
		goto add_tstr;
	case VT_BOOL:
		tstr = "bool";
		goto add_tstr;
	case VT_INT8:
		if (t & VT_UNSIGNED) {
			tstr = "uint8_t";
		} else {
			if (t & VT_CHAR) {
				tstr = "char";
			} else {
				tstr = "int8_t";
			}
		}
		goto add_tstr;
	case VT_INT16:
		if (t & VT_UNSIGNED) {
			tstr = "uint16_t";
		} else {
			tstr = "int16_t";
		}
		goto add_tstr;
	case VT_INT32:
		if (t & VT_UNSIGNED) {
			tstr = "uint32_t";
		} else {
			tstr = "int32_t";
		}
		goto add_tstr;
	case VT_LONG:
		tstr = "long";
		goto add_tstr;
	case VT_INT64:
		if (t & VT_UNSIGNED) {
			tstr = "uint64_t";
		} else {
			tstr = "int64_t";
		}
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
		strcat2 (buf, buf_size, tstr);
		if ((t & VT_UNSIGNED) && (bt != VT_INT8) &&
				(bt != VT_INT16) && (bt != VT_INT32) &&
				(bt != VT_INT64)) {
			strcat2 (buf, buf_size, "unsigned ");
		}
		break;
	case VT_ENUM:
	case VT_STRUCT:
	case VT_UNION:
		if (bt == VT_STRUCT) {
			tstr = "struct";
		} else if (bt == VT_UNION) {
			tstr = "union";
		} else {
			tstr = "enum";
		}
		strcat2 (buf, buf_size, tstr);
		v = type->ref->v & ~SYM_STRUCT;
		if (v < SYM_FIRST_ANOM) {
			strcat2 (buf, buf_size, " ");
			strcat2 (buf, buf_size, get_tok_str (s1, v, NULL));
		}
		break;
	case VT_FUNC:
		s = type->ref;
		type_to_str (s1, buf, buf_size, &s->type, varstr);
		strcat2 (buf, buf_size, "(");
		sa = s->next;
		while (sa) {
			type_to_str (s1, buf1, sizeof (buf1), &sa->type, NULL);
			strcat2 (buf, buf_size, buf1);
			sa = sa->next;
			if (sa) {
				strcat2 (buf, buf_size, ", ");
			}
		}
		strcat2 (buf, buf_size, ")");
		return;
	case VT_PTR:
		s = type->ref;
		if (t & VT_ARRAY) {
			type_to_str (s1, buf, buf_size, &s->type, NULL);
		} else {
			r_str_ncpy (buf1, "*", sizeof (buf1));
			if (varstr) {
				strcat2 (buf1, sizeof (buf1), varstr);
			}
			type_to_str (s1, buf, buf_size, &s->type, buf1);
		}
		return;
	}
	if (varstr) {
		strcat2 (buf, buf_size, " ");
		strcat2 (buf, buf_size, varstr);
	}
}

/* Parse GNUC __attribute__ extension. Currently, the following
 * extensions are recognized:
 * - aligned(n) : set data/function alignment.
 * - packed : force data alignment to 1
 * - unused : currently ignored, but may be used someday.
 * - regparm(n) : pass function parameters in registers (i386 only)
 */
static void parse_attribute(TCCState *s1, AttributeDef *ad) {
	int t;
	long long n;

	while (s1->tok == TOK_ATTRIBUTE1 || s1->tok == TOK_ATTRIBUTE2) {
		next (s1);
		skip (s1, '(');
		skip (s1, '(');
		while (s1->tok != ')') {
			if (s1->tok < TOK_IDENT) {
				expect (s1, "attribute name");
			}
			t = s1->tok;
			next (s1);
			switch (t) {
			case TOK_ALIAS1:
			case TOK_ALIAS2:
				skip (s1, '(');
				if (s1->tok != TOK_STR) {
					expect (s1, "alias(\"target\")");
				}
#if 0
				ad->alias_target =	/* save string as token, for later */
					tok_alloc (s1, (char *) s1->tokc.cstr->data, s1->tokc.cstr->size - 1)->tok;
#endif
				next (s1);
				skip (s1, ')');
				break;
			case TOK_ALIGNED1:
			case TOK_ALIGNED2:
				if (s1->tok == '(') {
					next (s1);
					n = expr_const (s1);
					if (n <= 0 || (n & (n - 1)) != 0) {
						TCC_ERR ("alignment must be a positive power of two");
					}
					skip (s1, ')');
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
				** track unused objects */
				break;
			case TOK_NORETURN1:
			case TOK_NORETURN2:
				/* currently, no need to handle it because tcc does not
				** track unused objects */
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
				skip (s1, '(');
				n = expr_const (s1);
				if (n > 3) {
					n = 3;
				} else if (n < 0) {
					n = 0;
				}
				if (n > 0) {
					ad->func_call = FUNC_FASTCALL1 + n - 1;
				}
				skip (s1, ')');
				break;
			case TOK_FASTCALL1:
			case TOK_FASTCALL2:
			case TOK_FASTCALL3:
				ad->func_call = FUNC_FASTCALLW;
				break;
#endif
			case TOK_MODE:
				skip (s1, '(');
				switch (s1->tok) {
				case TOK_MODE_DI:
					ad->mode = VT_INT64 + 1;
					break;
				case TOK_MODE_HI:
					ad->mode = VT_INT16 + 1;
					break;
				case TOK_MODE_SI:
					ad->mode = VT_INT32 + 1;
					break;
				default:
					tcc_warning (s1, "__mode__(%s) not supported\n", get_tok_str (s1, s1->tok, NULL));
					break;
				}
				next (s1);
				skip (s1, ')');
				break;
			case TOK_DLLEXPORT:
				ad->func_export = 1;
				break;
			case TOK_DLLIMPORT:
				ad->func_import = 1;
				break;
			default:
				if (s1->warn_unsupported) {
					tcc_warning (s1, "'%s' attribute ignored", get_tok_str (s1, t, NULL));
				}
				/* skip parameters */
				if (s1->tok == '(') {
					int parenthesis = 0;
					do {
						if (s1->tok == '(') {
							parenthesis++;
						} else if (s1->tok == ')') {
							parenthesis--;
						}
						next (s1);
					} while (parenthesis && s1->tok != -1);
				}
				break;
			}
			if (s1->tok != ',') {
				break;
			}
			next (s1);
		}
		skip (s1, ')');
		skip (s1, ')');
	}
}

/* enum/struct/union declaration. u is either VT_ENUM, VT_STRUCT or VT_UNION */
static void struct_decl(TCCState *s1, CType *type, int u, bool is_typedef) {
	int v, size, align, maxalign, offset;
	int bit_size, bit_pos, bsize, bt, lbit_pos, prevbt;
	char buf[STRING_MAX_SIZE + 1];
	Sym *s, *ss, *ass, **ps;
	AttributeDef ad;
	const char *name = NULL;
	bool autonamed = false;
	STACK_NEW0 (CType, type1);
	STACK_NEW0 (CType, btype);

	int a = s1->tok; /* save decl type */
	next (s1);
	name = get_tok_str (s1, s1->tok, NULL);
	if (s1->tok != '{') {
		v = s1->tok;
		next (s1);
		/* struct already defined ? return it */
		if (v < TOK_IDENT) {
			expect (s1, "struct/union/enum name");
		}
		s = struct_find (s1, v);
		if (s) {
			if (s->type.t != a) {
				TCC_ERR ("invalid type");
			}
			goto do_decl;
		}
	} else {
		v = s1->anon_sym++;
		snprintf (buf, sizeof (buf), "%u", v - SYM_FIRST_ANOM);
		name = buf;
		autonamed = true;
	}
	type1.t = a;
	/* we put an undefined size for struct/union/enum */
	s = sym_push (s1, v | SYM_STRUCT, &type1, 0, -1);
	if (!s) {
		return;
	}
	s->r = 0; /* default alignment is zero as gcc */
	/* put struct/union/enum name in type */
	/* TODO: Extract this part into the separate functions per type */
do_decl:
	type->t = u;
	type->ref = s;

	if (s1->tok == '{') {
		next (s1);
		if (s->c != -1) {
			TCC_ERR ("struct/union/enum already defined");
		}
		/* cannot be empty */
		ut64 iota = 0LL;
		/* non empty enums are not allowed */
		if (a == TOK_ENUM) {
			if (!strcmp (name, "{")) {
				// UNNAMED
				R_LOG_WARN ("anonymous enums are ignored");
			}
			while (tcc_nerr (s1) == 0) {
				v = s1->tok;
				if (v < TOK_UIDENT) {
					expect (s1, "identifier");
					break;
				}
				next (s1);
				if (s1->tok == '=') {
					// eprintf ("TOK %d %c\n", s1->tok, s1->tok);
					next (s1);
					// eprintf ("TOK %d %c\n", s1->tok, s1->tok);
					iota = expr_const (s1);
					// eprintf ("TOK %d %c\n", s1->tok, s1->tok);
					//const char *valstr = get_tok_str (s1, s1->ch, NULL);
					//eprintf ("TOK %d %s\n", s1->ch, valstr);
				}
				// TODO: use is_typedef here
				if (strcmp (name, "{")) {
					const char *varstr = get_tok_str (s1, v, NULL);
					tcc_appendf (s1, "%s=enum\n", name);
					tcc_appendf (s1, "[+]enum.%s=%s\n", name, varstr);
					tcc_appendf (s1, "enum.%s.%s=0x%"PFMT64x "\n", name, varstr, iota);
					tcc_appendf (s1, "enum.%s.0x%"PFMT64x "=%s\n", name, iota, varstr);
					// TODO: if token already defined throw an error
					// if (varstr isInside (arrayOfvars)) { erprintf ("ERROR: DUP VAR IN ENUM\n"); }
				}
				/* enum symbols have static storage */
				ss = sym_push (s1, v, &s1->int64_type, VT_CONST, iota);
				if (!ss) {
					return;
				}
				ss->type.t |= VT_STATIC;
				if (s1->tok != ',') {
					break;
				}
				next (s1);
				iota++;
				/* NOTE: we accept a trailing comma */
				if (s1->tok == '}') {
					break;
				}
			}
			skip (s1, '}');
		} else {
			maxalign = 1;
			ps = &s->next;
			prevbt = VT_INT32;
			bit_pos = 0;
			offset = 0;

			const char *ctype = (a == TOK_UNION)? "union": "struct";
			if (!is_typedef || !autonamed) {
				tcc_appendf (s1, "%s=%s\n", name, ctype);
			}

			while (s1->tok != '}') {
				if (!parse_btype (s1, &btype, &ad)) {
					expect (s1, "bracket");
					break;
				}
				while (tcc_nerr (s1) == 0) {
					bit_size = -1;
					v = 0;
					memcpy (&type1, &btype, sizeof (type1));
					if (s1->tok != ':') {
						type_decl (s1, &type1, &ad, &v, TYPE_DIRECT | TYPE_ABSTRACT);
						if (v == 0 && not_structured(&type1)) {
							expect (s1, "identifier2");
						}
						if ((type1.t & VT_BTYPE) == VT_FUNC ||
								(type1.t & (VT_TYPEDEF | VT_STATIC | VT_EXTERN | VT_INLINE))) {
							TCC_ERR ("invalid type for '%s'",
								get_tok_str (s1, v, NULL));
						}
					}
					if (s1->tok == ':') {
						next (s1);
						bit_size = (int) expr_const (s1);
						/* XXX: handle v = 0 case for messages */
						if (bit_size < 0) {
							TCC_ERR ("negative width in bit-field '%s'",
								get_tok_str (s1, v, NULL));
						}
						if (v && bit_size == 0) {
							TCC_ERR ("zero width for bit-field '%s'",
								get_tok_str (s1, v, NULL));
						}
					}
					size = type_size (s1, &type1, &align);
					if (ad.aligned) {
						if (align < ad.aligned) {
							align = ad.aligned;
						}
					} else if (ad.packed) {
						align = 1;
					} else if (*s1->pack_stack_ptr) {
						if (align > *s1->pack_stack_ptr) {
							align = *s1->pack_stack_ptr;
						}
					}
					lbit_pos = 0;
					// FIXME: Here it handles bitfields only in a way
					// of the same endianness as the host system (this code was compiled for)
					// It should depend on the endianness of the `asm.arch` instead.
					if (bit_size >= 0) {
						bt = type1.t & VT_BTYPE;
						if (bt != VT_INT8
							&& bt != VT_INT16
							&& bt != VT_INT32
							&& bt != VT_INT64
							&& bt != VT_ENUM
							&& bt != VT_BOOL) {
							TCC_ERR ("bitfields must have scalar type");
						}
						bsize = size * 8;
						if (bit_size > bsize) {
							TCC_ERR ("width of '%s' exceeds its type",
								get_tok_str (s1, v, NULL));
						} else if (bit_size == bsize) {
							/* no need for bit fields */
							bit_pos = 0;
						} else if (bit_size == 0) {
							/* XXX: what to do if only padding in a structure ? */
							/* zero size: means to pad */
							bit_pos = 0;
						} else {
							/* we do not have enough room ?
							* did the type change?
							* is it a union? */
							if ((bit_pos + bit_size) > bsize || bt != prevbt || a == TOK_UNION) {
								bit_pos = 0;
							}
							lbit_pos = bit_pos;
							/* XXX: handle LSB first */
							type1.t |= VT_BITFIELD
								| (bit_pos << VT_STRUCT_SHIFT)
								| (bit_size << (VT_STRUCT_SHIFT + 6));
							bit_pos += bit_size;
						}
						prevbt = bt;
					} else {
						bit_pos = 0;
					}
					if (v != 0 || is_structured (&type1)) {
						/* add new memory data only if starting bit field */
						if (lbit_pos == 0) {
							if (a == TOK_STRUCT) {
								iota = (iota + align - 1) & - align;
								offset = iota;
								if (size > 0) {
									iota += size;
								}
							} else {
								offset = 0;
								if (size > iota) {
									iota = size;
								}
							}
							if (align > maxalign) {
								maxalign = align;
							}
						}
#if 1
						// TODO: Don't use such a small limit?
						char b[1024];
						char *varstr = get_tok_str (s1, v, NULL);
						type_to_str (s1, b, sizeof (b), &type1, NULL);
						{
							int type_bt = type1.t & VT_BTYPE;
							// eprintf("2: %s.%s = %s\n", ctype, name, varstr);
							if (is_typedef && autonamed) {
								tcc_typedef_appendf (s1, "[+]typedef.%%s.fields=%s\n", varstr);
								tcc_typedef_appendf (s1, "typedef.%%s.%s.meta=%d\n", varstr, type_bt);
								tcc_typedef_appendf (s1, "typedef.%%s.%s=%s,%d,%d\n", varstr, b, offset, (int)s1->arraysize);
							} else {
								tcc_appendf (s1, "[+]%s.%s=%s\n",
									ctype, name, varstr);
								tcc_appendf (s1, "%s.%s.%s.meta=%d\n",
									ctype, name, varstr, type_bt);
								/* compact form */
								tcc_appendf (s1, "%s.%s.%s=%s,%d,%d\n",
									ctype, name, varstr, b, offset, (int)s1->arraysize);
							}
#if 0
							eprintf ("%s.%s.%s.type=%s\n", ctype, name, varstr, b);
							eprintf ("%s.%s.%s.offset=%d\n", ctype, name, varstr, offset);
							eprintf ("%s.%s.%s.array=%d\n", ctype, name, varstr, arraysize);
#endif
							// (%s) field (%s) offset=%d array=%d", name, b, get_tok_str(v, NULL), offset, arraysize);
							s1->arraysize = 0;
							if (type1.t & VT_BITFIELD) {
								tcc_appendf (s1, "%s.%s.%s.bitfield.pos=%d\n",
									ctype, name, varstr, (type1.t >> VT_STRUCT_SHIFT) & 0x3f);
								tcc_appendf (s1, "%s.%s.%s.bitfield.size=%d\n",
									ctype, name, varstr, (type1.t >> (VT_STRUCT_SHIFT + 6)) & 0x3f);
							}
							// printf("\n");
						}
#endif
					}
					if (v == 0 && is_structured (&type1)) {
						ass = type1.ref;
						while ((ass = ass->next)) {
							ss = sym_push (s1, ass->v, &ass->type, 0, offset + ass->c);
							if (!ss) {
								return;
							}
							*ps = ss;
							ps = &ss->next;
						}
					} else if (v) {
						ss = sym_push (s1, v | SYM_FIELD, &type1, 0, offset);
						if (!ss) {
							return;
						}
						*ps = ss;
						ps = &ss->next;
					}
					if (s1->tok == ';' || s1->tok == TOK_EOF) {
						break;
					}
					skip (s1, ',');
				}
				skip (s1, ';');
			}
			skip (s1, '}');
			/* store size and alignment */
			s->c = (iota + maxalign - 1) & - maxalign;
			s->r = maxalign;
		}
	}
}

/* parse an expression of the form '(type)' or '(expr)' and return its type */
static void parse_expr_type(TCCState *s1, CType *type) {
	int n;
	AttributeDef ad;

	skip (s1, '(');
	if (parse_btype (s1, type, &ad)) {
		type_decl (s1, type, &ad, &n, TYPE_ABSTRACT);
	} else {
		expr_type (s1, type);
	}
	skip (s1, ')');
}

/* return 0 if no type declaration. otherwise, return the basic type and skip it */
static int parse_btype(TCCState *s1, CType *type, AttributeDef *ad) {
	int t, u, type_found, typespec_found, typedef_found;
	Sym *s;
	STACK_NEW0 (CType, type1);

	memset (ad, 0, sizeof (AttributeDef));
	type_found = 0;
	typespec_found = 0;
	typedef_found = 0;
	/* FIXME: Make this dependent on the target */
	t = 0; /* default for 'int' */
	while (tcc_nerr (s1) == 0) {
		switch (s1->tok) {
		case TOK_EXTENSION:
			/* currently, we really ignore extension */
			next (s1);
			continue;
		/* basic types */
		/* int8_t, uint8_t, char */
		case TOK_UINT8:
			t |= VT_UNSIGNED;
			/* fall through */
		case TOK_INT8:
			u = VT_INT8;
			goto basic_type;
		case TOK_CHAR:
			u = VT_INT8;
			/* Mark as character type, for strings */
			t |= VT_CHAR;
basic_type:
			next (s1);
basic_type1:
			if ((t & VT_BTYPE) != 0) {
				tcc_error (s1, "too many basic types");
				return 0;
			}
			t |= u;
			typespec_found = 1;
			break;

		/* void* */
		case TOK_VOID:
			u = VT_VOID;
			goto basic_type;

		/* int16_t, uint16_t, short */
		case TOK_UINT16:
			t |= VT_UNSIGNED;
			/* fall through */
		case TOK_INT16:
		case TOK_SHORT:
			u = VT_INT16;
			goto basic_type;
		/* int32_t, uint32_t, int */
		case TOK_UINT32:
			t |= VT_UNSIGNED;
			/* fall through */
		case TOK_INT32:
			u = VT_INT32;
			goto basic_type;
		case TOK_INT:
			next (s1);
			typespec_found = 1;
			break;

		/* int64_t, uint64_t, long, long long */
		case TOK_UINT64:
			t |= VT_UNSIGNED;
			/* fall through */
		case TOK_INT64:
			u = VT_INT64;
			goto basic_type;
		case TOK_LONG:
			next (s1);
			// FIXME: Better handling long and long long types
			if ((t & VT_BTYPE) == VT_DOUBLE) {
				if (!r_str_startswith (s1->os, "windows")) {
					t = (t & ~VT_BTYPE) | VT_LDOUBLE;
				}
			} else if ((t & VT_BTYPE) == VT_LONG) {
				t = (t & ~VT_BTYPE) | VT_INT64;
			} else {
				u = VT_LONG;
				goto basic_type1;
			}
			break;
		case TOK_BOOL:
		case TOK_STDBOOL:
			u = VT_BOOL;
			goto basic_type;
		case TOK_FLOAT:
			u = VT_FLOAT;
			goto basic_type;
		case TOK_DOUBLE:
			next (s1);
			if ((t & VT_BTYPE) == VT_LONG) {
				if (r_str_startswith (s1->os, "windows")) {
					t = (t & ~VT_BTYPE) | VT_DOUBLE;
				} else {
					t = (t & ~VT_BTYPE) | VT_LDOUBLE;
				}
			} else {
				u = VT_DOUBLE;
				goto basic_type1;
			}
			break;
		case TOK_ENUM:
			struct_decl (s1, &type1, VT_ENUM, (bool)(t & VT_ENUM));
basic_type2:
			u = type1.t;
			type->ref = type1.ref;
			goto basic_type1;
		case TOK_STRUCT:
			struct_decl (s1, &type1, VT_STRUCT, (bool)(t & VT_TYPEDEF));
			goto basic_type2;
		case TOK_UNION:
			struct_decl (s1, &type1, VT_UNION, (bool)(t & VT_UNION));
			goto basic_type2;

		/* type modifiers */
		case TOK_CONST1:
		case TOK_CONST2:
		case TOK_CONST3:
			t |= VT_CONSTANT;
			next (s1);
			break;
		case TOK_VOLATILE1:
		case TOK_VOLATILE2:
		case TOK_VOLATILE3:
			t |= VT_VOLATILE;
			next (s1);
			break;
		case TOK_SIGNED1:
		case TOK_SIGNED2:
		case TOK_SIGNED3:
			typespec_found = 1;
			t |= VT_SIGNED;
			next (s1);
			break;
		case TOK_REGISTER:
		case TOK_AUTO:
		case TOK_RESTRICT1:
		case TOK_RESTRICT2:
		case TOK_RESTRICT3:
			next (s1);
			break;
		case TOK_UNSIGNED:
			t |= VT_UNSIGNED;
			next (s1);
			typespec_found = 1;
			break;
		/* storage */
		case TOK_EXTERN:
			t |= VT_EXTERN;
			next (s1);
			break;
		case TOK_STATIC:
			t |= VT_STATIC;
			next (s1);
			break;
		case TOK_TYPEDEF:
			t |= VT_TYPEDEF;
			next (s1);
			break;
		case TOK_INLINE1:
		case TOK_INLINE2:
		case TOK_INLINE3:
			t |= VT_INLINE;
			next (s1);
			break;
		/* GNUC attribute */
		case TOK_ATTRIBUTE1:
		case TOK_ATTRIBUTE2:
			parse_attribute (s1, ad);
			if (ad->mode) {
				u = ad->mode - 1;
				t = (t & ~VT_BTYPE) | u;
			}
			break;
		/* GNUC typeof */
		case TOK_TYPEOF1:
		case TOK_TYPEOF2:
		case TOK_TYPEOF3:
			next (s1);
			parse_expr_type (s1, &type1);
			/* remove all storage modifiers except typedef */
			type1.t &= ~(VT_STORAGE & ~VT_TYPEDEF);
			goto basic_type2;
		default:
			if (typespec_found || typedef_found) {
				goto the_end;
			}
			s = sym_find (s1, s1->tok);
			if (!s || !(s->type.t & VT_TYPEDEF)) {
				goto the_end;
			}
			typedef_found = 1;
			t |= (s->type.t & ~VT_TYPEDEF);
			type->ref = s->type.ref;
			if (s->r) {
				/* get attributes from typedef */
				if (0 == ad->aligned) {
					ad->aligned = FUNC_ALIGN (s->r);
				}
				if (0 == ad->func_call) {
					ad->func_call = FUNC_CALL (s->r);
				}
				ad->packed |= FUNC_PACKED (s->r);
			}
			next (s1);
			typespec_found = 1;
			break;
		}
		type_found = 1;
	}
the_end:
	if ((t & (VT_SIGNED | VT_UNSIGNED)) == (VT_SIGNED | VT_UNSIGNED)) {
		tcc_error (s1, "signed and unsigned modifier");
		return 0;
	}
#if 0
	if (s1->char_is_unsigned) {
		if ((t & (VT_SIGNED | VT_UNSIGNED | VT_BTYPE)) == VT_INT8) {
			t |= VT_UNSIGNED;
		}
	}
#endif
	t &= ~VT_SIGNED;
	/* long is never used as type */
	if ((t & VT_BTYPE) == VT_LONG) {
		if (r_str_startswith (s1->os, "windows") || (r_str_startswith (s1->arch, "x86") && s1->bits == 32)) {
			t = (t & ~VT_BTYPE) | VT_INT32;
		} else {
			t = (t & ~VT_BTYPE) | VT_INT64;
		}
	}
	type->t = t;
	return type_found;
}

/* convert parameter type (array to pointer and function to function pointer) */
static inline void convert_parameter_type(TCCState *s1, CType *pt) {
	/* remove const and volatile qualifiers (XXX: const could be used to indicate a const function parameter */
	pt->t &= ~(VT_CONSTANT | VT_VOLATILE);
	/* array must be transformed to pointer according to ANSI C */
	pt->t &= ~VT_ARRAY;
	if ((pt->t & VT_BTYPE) == VT_FUNC) {
		mk_pointer (s1, pt);
	}
}

static void post_type(TCCState *s1, CType *type, AttributeDef *ad) {
	int n, l, arg_size, align;
	Sym **plast, *s, *first;
	AttributeDef ad1;
	CType pt = {0};
	char *symname = NULL;
	int narg = 0;

	if (s1->tok == '(') {
		/* function declaration */
		next (s1);
		l = 0;
		first = NULL;
		plast = &first;
		{
			const char *ret_type = s1->global_type;
			free (symname);
			symname = strdup (s1->global_symname);
			tcc_appendf (s1, "func.%s.ret=%s\n", symname, ret_type);
			tcc_appendf (s1, "func.%s.cc=%s\n", symname, "cdecl"); // TODO
			tcc_appendf (s1, "%s=func\n", symname);
		}
		arg_size = 0;
		if (s1->tok != ')') {
			while (tcc_nerr (s1) == 0) {
				/* read param name and compute offset */
				if (l != FUNC_OLD) {
					if (!parse_btype (s1, &pt, &ad1)) {
						if (l) {
							TCC_ERR ("invalid type");
						} else {
							l = FUNC_OLD;
							goto old_proto;
						}
					}
					l = FUNC_NEW;
					if ((pt.t & VT_BTYPE) == VT_VOID && s1->tok == ')') {
						break;
					}
					type_decl (s1, &pt, &ad1, &n, TYPE_DIRECT | TYPE_ABSTRACT);
					if ((pt.t & VT_BTYPE) == VT_VOID) {
						TCC_ERR ("parameter declared as void");
					}
					arg_size += (type_size (s1, &pt, &align) + PTR_SIZE - 1) / PTR_SIZE;
				} else {
old_proto:
					n = s1->tok;
					if (n < TOK_UIDENT) {
						expect (s1, "identifier3");
					}
					pt.t = VT_INT32;
					next (s1);
				}
				convert_parameter_type (s1, &pt);
				s = sym_push (s1, n | SYM_FIELD, &pt, 0, 0);
				if (!s) {
					return;
				} else {
					char kind[1024];
					type_to_str (s1, kind, sizeof (kind), &pt, NULL);
					tcc_appendf (s1, "func.%s.arg.%d=%s,%s\n",
						symname, narg, kind, s1->global_symname);
					narg++;
				}
				*plast = s;
				plast = &s->next;
				if (s1->tok == ')') {
					break;
				}
				skip (s1, ',');
				if (l == FUNC_NEW && s1->tok == TOK_DOTS) {
					l = FUNC_ELLIPSIS;
					next (s1);
					break;
				}
			}
		}
		tcc_appendf (s1, "func.%s.args=%d\n", symname, narg);
		/* if no parameters, then old type prototype */
		if (l == 0) {
			l = FUNC_OLD;
		}
		skip (s1, ')');
		/* NOTE: const is ignored in returned type as it has a special meaning in gcc / C++ */
		type->t &= ~VT_CONSTANT;
		/* some ancient pre-K&R C allows a function to return an array and the array brackets
		* to be put after the arguments, such that "int c()[]" means something like "int[] c()" */
		if (s1->tok == '[') {
			next (s1);
			skip (s1, ']'); /* only handle simple "[]" */
			type->t |= VT_PTR;
		}
		/* we push a anonymous symbol which will contain the function prototype */
		ad->func_args = arg_size;
		s = sym_push (s1, SYM_FIELD, type, INT_ATTR (ad), l);
		if (!s) {
			return;
		}
		s->next = first;
		type->t = VT_FUNC;
		type->ref = s;
		R_FREE (symname);
	} else if (s1->tok == '[') {
		/* array definition */
		next (s1);
		if (s1->tok == TOK_RESTRICT1) {
			next (s1);
		}
		n = -1;
		int t1 = VT_ARRAY;
		if (s1->tok == ']') {
			n = 0;
		} else {
			if (!s1->local_stack || s1->nocode_wanted) {
				vpushll (s1, expr_const (s1));
			} else {
				gexpr (s1);
			}
			if ((s1->vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
				n = s1->vtop->c.i;
				if (n < 0) {
					TCC_ERR ("invalid array size");
				}
			} else {
				if (!is_integer_btype (s1->vtop->type.t & VT_BTYPE)) {
					TCC_ERR ("size of variable length array should be an integer");
				}
				t1 = VT_VLA;
			}
		}
		skip (s1, ']');
		/* parse next post type */
		post_type (s1, type, ad);

		/* we push an anonymous symbol which will contain the array element type */
		s1->arraysize = n;
		if (n < 0) {
			TCC_ERR ("array with no size []");
		}
		s = sym_push (s1, SYM_FIELD, type, 0, n);
		if (s) {
			type->t = t1 | VT_PTR;
			type->ref = s;
		}
	}
}

/* Parse a type declaration (except basic type), and return the type in 'type'.
 * 'td' is a bitmask indicating which kind of type decl is expected.
 * 'type' should contain the basic type.
 * 'ad' is the attribute definition of the basic type. It can be modified by type_decl().
 */
static void type_decl(TCCState *s1, CType *type, AttributeDef *ad, int *v, int td) {
	Sym *s;
	int qualifiers, storage;
	CType *type1 = R_NEW0 (CType);
	CType *type2 = R_NEW0 (CType);
	if (!type1 || !type2) {
		free (type1);
		free (type2);
		return;
	}

	while (s1->tok == '*') {
		qualifiers = 0;
redo:
		next (s1);
		switch (s1->tok) {
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
		mk_pointer (s1, type);
		type->t |= qualifiers;
	}

	/* XXX: clarify attribute handling */
	if (s1->tok == TOK_ATTRIBUTE1 || s1->tok == TOK_ATTRIBUTE2) {
		parse_attribute (s1, ad);
	}

	/* recursive type */
	/* XXX: incorrect if abstract type for functions (e.g. 'int ()') */
	type1->t = 0; /* XXX: same as int */
	if (s1->tok == '(') {
		next (s1);
		/* XXX: this is not correct to modify 'ad' at this point, but the syntax is not clear */
		if (s1->tok == TOK_ATTRIBUTE1 || s1->tok == TOK_ATTRIBUTE2) {
			parse_attribute (s1, ad);
		}
		type_decl (s1, type1, ad, v, td);
		skip (s1, ')');
	} else {
		/* type identifier */
		if (s1->tok >= TOK_IDENT && (td & TYPE_DIRECT)) {
			*v = s1->tok;
			next (s1);
		} else {
			if (!(td & TYPE_ABSTRACT)) {
				expect (s1, "identifier4");
			}
			*v = 0;
		}
	}
	storage = type->t & VT_STORAGE;
	type->t &= ~VT_STORAGE;
	if (storage & VT_STATIC) {
		int saved_nocode_wanted = s1->nocode_wanted;
		s1->nocode_wanted = 1;
		post_type (s1, type, ad);
		s1->nocode_wanted = saved_nocode_wanted;
	} else {
		char *name = get_tok_str (s1, *v, NULL);
		type_to_str (s1, s1->decl_kind, sizeof (s1->decl_kind), type, NULL);
		// eprintf ("---%d %s STATIC %s\n", td, kind, name);
		s1->global_symname = name;
		s1->global_type = s1->decl_kind;
		post_type (s1, type, ad);
	}
	type->t |= storage;
	if (s1->tok == TOK_ATTRIBUTE1 || s1->tok == TOK_ATTRIBUTE2) {
		parse_attribute (s1, ad);
	}
	if (!type1->t) {
		free (type1);
		free (type2);
		return;
	}
	/* append type at the end of type1 */
	type2 = type1;
	for (;;) {
		s = type2->ref;
		type2 = &s->type;
		if (!type2->t) {
			*type2 = *type;
			break;
		}
	}
	memcpy (type, type1, sizeof (*type));
}

/* compute the lvalue VT_LVAL_xxx needed to match type t. */
static int lvalue_type(int t) {
	int r = VT_LVAL;
	if (t & VT_UNSIGNED) {
		r |= VT_LVAL_UNSIGNED;
	}
	const int bt = t & VT_BTYPE;
	switch (bt) {
	case VT_INT8:
	case VT_BOOL:
		r |= VT_LVAL_BYTE;
		break;
	case VT_INT16:
		r |= VT_LVAL_SHORT;
		break;
	default:
		return r;
	}
	return r;
}

/* indirection with full error checking and bound check */
static void indir(TCCState *s1) {
	if ((s1->vtop->type.t & VT_BTYPE) != VT_PTR) {
		if ((s1->vtop->type.t & VT_BTYPE) == VT_FUNC) {
			return;
		}
		expect (s1, "pointer");
	}
	s1->vtop->type = *pointed_type (&s1->vtop->type);
	/* Arrays and functions are never lvalues */
	if (!(s1->vtop->type.t & VT_ARRAY) && !(s1->vtop->type.t & VT_VLA) && (s1->vtop->type.t & VT_BTYPE) != VT_FUNC) {
		s1->vtop->r |= lvalue_type (s1->vtop->type.t);
	}
}

static void parse_type(TCCState *s1, CType *type) {
	AttributeDef ad;
	int n;

	if (!parse_btype (s1, type, &ad)) {
		expect (s1, "type");
	}
	type_decl (s1, type, &ad, &n, TYPE_ABSTRACT);
}

static void vpush_tokc(TCCState *s1, int t) {
	CType type = {
		.t = t,
		.ref = NULL
	};
	vsetc (s1, &type, VT_CONST, &s1->tokc);
}

static void unary(TCCState *s1) {
	int n, t, align, size, r;
	CType type = {0};
	Sym *s;
	AttributeDef ad;
	static R_TH_LOCAL int in_sizeof = 0;

	int sizeof_caller = in_sizeof;
	in_sizeof = 0;
tok_next:
	switch (s1->tok) {
	case TOK_EXTENSION:
		next (s1);
		goto tok_next;
	case TOK_CINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
		vpushi (s1, s1->tokc.i);
		next (s1);
		break;
	case TOK_CUINT:
		vpush_tokc (s1, VT_INT32 | VT_UNSIGNED);
		next (s1);
		break;
	case TOK_CLLONG:
		vpush_tokc (s1, VT_INT64);
		next (s1);
		break;
	case TOK_CULLONG:
		vpush_tokc (s1, VT_INT64 | VT_UNSIGNED);
		next (s1);
		break;
	case TOK_CFLOAT:
		vpush_tokc (s1, VT_FLOAT);
		next (s1);
		break;
	case TOK_CDOUBLE:
		vpush_tokc (s1, VT_DOUBLE);
		next (s1);
		break;
	case TOK_CLDOUBLE:
		vpush_tokc (s1, VT_LDOUBLE);
		next (s1);
		break;
	case TOK___FUNCTION__:
		if (!gnu_ext) {
			goto tok_identifier;
		}
	/* fall thru */
	case TOK___FUNC__:
	{
		/* special function name identifier */
		int len = strlen (s1->funcname) + 1;
		/* generate char[len] type */
		type.t = VT_INT8;
		mk_pointer (s1, &type);
		type.t |= VT_ARRAY;
		if (type.ref) {
			type.ref->c = len;
		}
		// XXX ptr is NULL HERE WTF
		// memcpy(ptr, funcname, len);
		next (s1);
	}
	break;
	case TOK_LSTR:
		t = r_str_startswith (s1->os, "windows")? VT_INT32: VT_INT16 | VT_UNSIGNED;
		goto str_init;
	case TOK_STR:
		/* string parsing */
		t = VT_INT8;
str_init:
		if (s1->warn_write_strings) {
			t |= VT_CONSTANT;
		}
		type.t = t;
		mk_pointer (s1, &type);
		type.t |= VT_ARRAY;
		memset (&ad, 0, sizeof (AttributeDef));
		decl_initializer_alloc (s1, &type, &ad, VT_CONST, 2, 0, NULL, 0);
		break;
	case '(':
		next (s1);
		/* cast ? */
		if (parse_btype (s1, &type, &ad)) {
			type_decl (s1, &type, &ad, &n, TYPE_ABSTRACT);
			skip (s1, ')');
			/* check ISOC99 compound literal */
			if (s1->tok == '{') {
				/* data is allocated locally by default */
				if (s1->global_expr) {
					r = VT_CONST;
				} else {
					r = VT_LOCAL;
				}
				/* all except arrays are lvalues */
				if (!(type.t & VT_ARRAY)) {
					r |= lvalue_type (type.t);
				}
				memset (&ad, 0, sizeof (AttributeDef));
				decl_initializer_alloc (s1, &type, &ad, r, 1, 0, NULL, 0);
			} else {
				if (sizeof_caller) {
					vpush (s1, &type);
					return;
				}
				unary (s1);
			}
		} else if (s1->tok == '{') {
			/* statement expression : we do not accept break/continue inside as GCC does */
			skip (s1, ')');
		} else {
			gexpr (s1);
			skip (s1, ')');
		}
		break;
	case '*':
		next (s1);
		unary (s1);
		indir (s1);
		break;
	case '!':
		next (s1);
		unary (s1);
		if ((s1->vtop->r & VT_VALMASK) == VT_CMP) {
			s1->vtop->c.i = s1->vtop->c.i ^ 1;
		}
		break;
	case TOK_SIZEOF:
	case TOK_ALIGNOF1:
	case TOK_ALIGNOF2:
		t = s1->tok;
		next (s1);
		in_sizeof++;
		unary_type (s1, &type); // Perform a in_sizeof = 0;
		size = type_size (s1, &type, &align);
		if (t == TOK_SIZEOF) {
			if (!(type.t & VT_VLA)) {
				if (size < 0) {
					TCC_ERR ("sizeof applied to an incomplete type");
				}
				vpushs (s1, size);
			}
		} else {
			vpushs (s1, align);
		}
		s1->vtop->type.t |= VT_UNSIGNED;
		break;

	case TOK_builtin_types_compatible_p:
	{
		STACK_NEW0 (CType, type1);
		STACK_NEW0 (CType, type2);
		next (s1);
		skip (s1, '(');
		parse_type (s1, &type1);
		skip (s1, ',');
		parse_type (s1, &type2);
		skip (s1, ')');
		type1.t &= ~(VT_CONSTANT | VT_VOLATILE);
		type2.t &= ~(VT_CONSTANT | VT_VOLATILE);
		vpushi (s1, is_compatible_types (&type1, &type2));
	}
		break;
	case TOK_builtin_constant_p:
	{
		long long res;
		next (s1);
		skip (s1, '(');
		bool saved_nocode_wanted = s1->nocode_wanted;
		s1->nocode_wanted = true;
		gexpr (s1);
		res = (s1->vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
		s1->nocode_wanted = saved_nocode_wanted;
		skip (s1, ')');
		vpushll (s1, res);
	}
		break;
	case TOK_builtin_frame_address:
	{
		int level;
		next (s1);
		skip (s1, '(');
		if (s1->tok != TOK_CINT || s1->tokc.i < 0) {
			TCC_ERR ("__builtin_frame_address only takes positive integers");
		}
		level = s1->tokc.i;
		next (s1);
		skip (s1, ')');
		type.t = VT_VOID;
		mk_pointer (s1, &type);
		vset (s1, &type, VT_LOCAL, 0); // local frame
		while (level--) {
			mk_pointer (s1, &s1->vtop->type);
			indir (s1); // -> parent frame
		}
	}
	break;
	case TOK_builtin_va_start:
		if (!strncmp (s1->arch, "x86", 3) && s1->bits == 64 && !strncmp (s1->os, "windows", 7)) {
			next (s1);
			skip (s1, '(');
			expr_eq (s1);
			skip (s1, ',');
			expr_eq (s1);
			skip (s1, ')');
			if ((s1->vtop->r & VT_VALMASK) != VT_LOCAL) {
				TCC_ERR ("__builtin_va_start expects a local variable");
			}
			s1->vtop->r &= ~(VT_LVAL | VT_REF);
			s1->vtop->type = s1->char_pointer_type;
		}
		break;
	case TOK_builtin_va_arg_types:
		if (!(!strncmp (s1->arch, "x86", 3) && s1->bits == 64 && !strncmp (s1->os, "windows", 7))) {
			next (s1);
			skip (s1, '(');
			parse_type (s1, &type);
			skip (s1, ')');
			// FIXME: Handle this too
			// vpushll(classify_x86_64_va_arg(&type));
		}
		break;
	// special qnan , snan and infinity values
	case TOK___NAN__:
		vpush64 (s1, VT_DOUBLE, 0x7ff8000000000000ULL);
		next (s1);
		break;
	case TOK___SNAN__:
		vpush64 (s1, VT_DOUBLE, 0x7ff0000000000001ULL);
		next (s1);
		break;
	case TOK___INF__:
		vpush64 (s1, VT_DOUBLE, 0x7ff0000000000000ULL);
		next (s1);
		break;
	default:
tok_identifier:
		t = s1->tok;
		next (s1);
		if (t < TOK_UIDENT) {
			// eprintf ("%d %d\n", t, TOK_UIDENT);
			expect (s1, "identifier5");
			break;
		}
		s = sym_find (s1, t);
		if (!s) {
			if (s1->tok != '(') {
				TCC_ERR ("'%s' undeclared", get_tok_str (s1, t, NULL));
			}
		}
		if (!s) {
			TCC_ERR ("invalid declaration '%s'", get_tok_str (s1, t, NULL));
		} else {
			if ((s->type.t & (VT_STATIC | VT_INLINE | VT_BTYPE)) == (VT_STATIC | VT_INLINE | VT_FUNC)) {
				/* if referencing an inline function, then we generate a symbol to it if not already done.
				 * It will have the effect to generate code for it at the end of the compilation unit */
				r = VT_SYM | VT_CONST;
			} else {
				r = s->r;
			}
			vset (s1, &s->type, r, s->c);
			/* if forward reference, we must point to s */
			if (s1->vtop->r & VT_SYM) {
				s1->vtop->sym = s;
				s1->vtop->c.ul = 0;
			}
		}
		break;
	}

	/* post operations */
	while (1) {
		if (s1->tok == '.' || s1->tok == TOK_ARROW) {
			int qualifiers;
			/* field */
			if (s1->tok == TOK_ARROW) {
				indir (s1);
			}
			qualifiers = s1->vtop->type.t & (VT_CONSTANT | VT_VOLATILE);
			test_lvalue (s1);
			gaddrof (s1);
			next (s1);
			/* expect pointer on structure */
			if (not_structured (&s1->vtop->type)) {
				expect (s1, "struct or union");
			}
			s = s1->vtop->type.ref;
			/* find field */
			s1->tok |= SYM_FIELD;
			while ((s = s->next)) {
				if (s->v == s1->tok) {
					break;
				}
			}
			if (!s) {
				TCC_ERR ("field not found: %s", get_tok_str (s1, s1->tok & ~SYM_FIELD, NULL));
			}
			/* add field offset to pointer */
			s1->vtop->type = s1->char_pointer_type; /* change type to 'char *' */
			vpushi (s1, s->c);
			/* change type to field type, and set to lvalue */
			s1->vtop->type = s->type;
			s1->vtop->type.t |= qualifiers;
			/* an array is never an lvalue */
			if (!(s1->vtop->type.t & VT_ARRAY)) {
				s1->vtop->r |= lvalue_type (s1->vtop->type.t);
			}
			next (s1);
		} else if (s1->tok == '[') {
			next (s1);
			gexpr (s1);
			indir (s1);
			skip (s1, ']');
		} else {
			break;
		}
	}
}

static void expr_prod(TCCState *s1) {
	unary (s1);
	while (s1->tok == '*' || s1->tok == '/' || s1->tok == '%') {
		next (s1);
		unary (s1);
	}
}

static void expr_sum(TCCState *s1) {
	expr_prod (s1);
	while (s1->tok == '+' || s1->tok == '-') {
		next (s1);
		expr_prod (s1);
	}
}

static void expr_shift(TCCState *s1) {
	expr_sum (s1);
	while (s1->tok == TOK_SHL || s1->tok == TOK_SAR) {
		next (s1);
		expr_sum (s1);
	}
}

static void expr_cmp(TCCState *s1) {
	expr_shift (s1);
	while ((s1->tok >= TOK_ULE && s1->tok <= TOK_GT) || s1->tok == TOK_ULT || s1->tok == TOK_UGE) {
		next (s1);
		expr_shift (s1);
	}
}

static void expr_cmpeq(TCCState *s1) {
	expr_cmp (s1);
	while (s1->tok == TOK_EQ || s1->tok == TOK_NE) {
		next (s1);
		expr_cmp (s1);
	}
}

static void expr_and(TCCState *s1) {
	expr_cmpeq (s1);
	while (s1->tok == '&') {
		next (s1);
		expr_cmpeq (s1);
	}
}

static void expr_xor(TCCState *s1) {
	expr_and (s1);
	while (s1->tok == '^') {
		next (s1);
		expr_and (s1);
	}
}

static void expr_or(TCCState *s1) {
	expr_xor (s1);
	while (s1->tok == '|') {
		next (s1);
		expr_xor (s1);
	}
}

/* XXX: fix this mess */
static void expr_land_const(TCCState *s1) {
	expr_or (s1);
	while (s1->tok == TOK_LAND) {
		next (s1);
		expr_or (s1);
	}
}

/* XXX: fix this mess */
static void expr_lor_const(TCCState *s1) {
	expr_land_const (s1);
	while (s1->tok == TOK_LOR) {
		next (s1);
		expr_land_const (s1);
	}
}

/* only used if non constant */
static void expr_land(TCCState *s1) {
	expr_or (s1);
	if (s1->tok == TOK_LAND) {
		while (tcc_nerr (s1) == 0) {
			if (s1->tok != TOK_LAND) {
				break;
			}
			next (s1);
			expr_or (s1);
		}
	}
}

static void expr_lor(TCCState *s1) {
	expr_land (s1);
	if (s1->tok == TOK_LOR) {
		while (tcc_nerr (s1) == 0) {
			if (s1->tok != TOK_LOR) {
				break;
			}
			next (s1);
			expr_land (s1);
		}
	}
}

/* XXX: better constant handling */
static void expr_cond(TCCState *s1) {
	if (s1->const_wanted) {
		expr_lor_const (s1);
		if (s1->tok == '?') {
			vdup (s1);
			next (s1);
			if (s1->tok != ':' || !gnu_ext) {
				gexpr (s1);
			}
			skip (s1, ':');
			expr_cond (s1);
		}
	} else {
		expr_lor (s1);
	}
}

static void expr_eq(TCCState *s1) {
	expr_cond (s1);
	if (s1->tok == '=' ||
			(s1->tok >= TOK_A_MOD && s1->tok <= TOK_A_DIV) ||
			s1->tok == TOK_A_XOR || s1->tok == TOK_A_OR ||
			s1->tok == TOK_A_SHL || s1->tok == TOK_A_SAR) {
		test_lvalue (s1);
		int t = s1->tok;
		next (s1);
		if (t == '=') {
			expr_eq (s1);
		} else {
			vdup (s1);
			expr_eq (s1);
		}
	}
}

/* parse an expression and return its type without any side effect. */
static void expr_type(TCCState *s1, CType *type) {
	bool saved_nocode_wanted = s1->nocode_wanted;
	s1->nocode_wanted = true;
	gexpr (s1);
	*type = s1->vtop->type;
	s1->nocode_wanted = saved_nocode_wanted;
}

/* parse a unary expression and return its type without any side effect. */
static void unary_type(TCCState *s1, CType *type) {
	bool a = s1->nocode_wanted;
	s1->nocode_wanted = true;
	unary (s1);
	*type = s1->vtop->type;
	s1->nocode_wanted = a;
}

/* parse a constant expression and return value in s1->vtop. */
static void expr_const1(TCCState *s1) {
	const bool a = s1->const_wanted;
	s1->const_wanted = true;
	expr_cond (s1);
	s1->const_wanted = a;
}

/* parse an integer constant and return its value. */
ST_FUNC long long expr_const(TCCState *s1) {
	expr_const1 (s1);
	if ((s1->vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) != VT_CONST) {
		expect (s1, "constant expression");
		return 0;
	}
	return s1->vtop->c.ll;
}

/* return the label token if current token is a label, otherwise return zero */
static bool is_label(TCCState *s1) {
	/* fast test first */
	if (s1->tok < TOK_UIDENT) {
		return false;
	}
	/* no need to save tokc because s1->tok is an identifier */
	const int last_tok = s1->tok;
	next (s1);
	if (s1->tok == ':') {
		next (s1);
		return last_tok;
	}
	unget_tok (s1, last_tok);
	return false;
}

/* t is the array or struct type. c is the array or struct address. cur_index/cur_field is the pointer
 * to the current value. 'size_only' is true if only size info is needed (only used in arrays) */
static void decl_designator(TCCState *s1, CType *type, unsigned long c, long long *cur_index, Sym **cur_field, int size_only) {
	Sym *s, *f = NULL;
	long long index, index_last;
	int notfirst, align, l, nb_elems, elem_size;
	STACK_NEW0 (CType, type1);

	notfirst = 0;
	if (gnu_ext && (l = is_label (s1)) != 0) {
		goto struct_field;
	}
	while (s1->tok == '[' || s1->tok == '.') {
		if (s1->tok == '[') {
			if (!(type->t & VT_ARRAY)) {
				expect (s1, "array type");
			}
			s = type->ref;
			next (s1);
			index = expr_const (s1);
			if (index < 0 || (s->c >= 0 && index >= s->c)) {
				expect (s1, "invalid index");
			}
			if (s1->tok == TOK_DOTS && gnu_ext) {
				next (s1);
				index_last = expr_const (s1);
				if (index_last < 0
						|| (s->c >= 0 && index_last >= s->c)
						|| index_last < index) {
					expect (s1, "invalid index");
				}
			} else {
				index_last = index;
			}
			skip (s1, ']');
			if (!notfirst && cur_index) {
				*cur_index = index_last;
			}
			type = pointed_type (type);
			elem_size = type_size (s1, type, &align);
			c += index * elem_size;
			/* NOTE: we only support ranges for last designator */
			nb_elems = index_last - index + 1;
			if (nb_elems != 1) {
				notfirst = 1;
				break;
			}
		} else {
			next (s1);
			l = s1->tok;
			next (s1);
struct_field:
			if (not_structured (type)) {
				expect (s1, "struct/union type");
			}
			s = type->ref;
			l |= SYM_FIELD;
			f = s->next;
			while (f) {
				if (f->v == l) {
					break;
				}
				f = f->next;
			}
			if (!f) {
				expect (s1, "field");
			}
			if (!notfirst && cur_field) {
				*cur_field = f;
			}
			/* XXX: fix this mess by using explicit storage field */
			if (f) {
				type1 = f->type;
				type1.t |= (type->t & ~VT_TYPE);
				type = &type1;
				c += f->c;
			}
		}
		notfirst = 1;
	}
	if (notfirst) {
		if (s1->tok == '=') {
			next (s1);
		} else {
			if (!gnu_ext) {
				expect (s1, "=");
			}
		}
	} else {
		if (type->t & VT_ARRAY) {
			index = cur_index ? *cur_index : 0;
			type = pointed_type (type);
			c += index * type_size (s1, type, &align);
		} else {
			f = cur_field ? *cur_field : NULL;
			if (!f) {
				TCC_ERR ("too many field init");
			}
			/* XXX: fix this mess by using explicit storage field */
			if (f) {
				type1 = f->type;
				type1.t |= (type->t & ~VT_TYPE);
				type = &type1;
				c += f->c;
			}
		}
	}
	decl_initializer (s1, type, c, 0, size_only);
}

#define EXPR_VAL 0
#define EXPR_CONST 1
#define EXPR_ANY 2

/* store a value or an expression directly in global data or in local array */
static void init_putv(TCCState *s1, CType *type, unsigned long c, long long v, int expr_type) {
	int tmp;

	switch (expr_type) {
	case EXPR_VAL:
		vpushll (s1, v);
		break;
	case EXPR_CONST:
		/* compound literals must be allocated globally in this case */
		tmp = s1->global_expr;
		s1->global_expr = 1;
		expr_const1 (s1);
		s1->global_expr = tmp;
		/* NOTE: symbols are accepted */
		if ((s1->vtop->r & (VT_VALMASK | VT_LVAL)) != VT_CONST) {
			TCC_ERR ("initializer element is not constant");
		}
		break;
	case EXPR_ANY:
		expr_eq (s1);
		break;
	}

	CType dtype = *type;
	dtype.t &= ~VT_CONSTANT;/* need to do that to avoid false warning */

	vset (s1, &dtype, VT_LOCAL | VT_LVAL, c);
	vswap (s1);
}

/* put zeros for variable based init */
static void init_putz(TCCState *s1, CType *t, unsigned long c, int size) {
	vseti (s1, VT_LOCAL, c);
	vpushi (s1, 0);
	vpushs (s1, size);
}

/* 't' contains the type and storage info. 'c' is the offset of the
 * object in section 'sec'. If 'sec' is NULL, it means stack based
 * allocation. 'first' is true if array '{' must be read (multi
 * dimension implicit array init handling). 'size_only' is true if
 * size only evaluation is wanted (only for arrays). */
static void decl_initializer(TCCState *s1, CType *type, unsigned long c, int first, int size_only) {
	long long index;
	int n, no_oblock, parlevel, parlevel1;
	size_t array_length, size1, i;
	int align1, expr_type;
	Sym *s, *f;
	CType *t1;

	if (type->t & VT_ARRAY) {
		s = type->ref;
		n = s->c;
		array_length = 0;
		t1 = pointed_type (type);
		size1 = type_size (s1, t1, &align1);

		no_oblock = 1;
		if ((first && s1->tok != TOK_LSTR && s1->tok != TOK_STR) || s1->tok == '{') {
			if (s1->tok != '{') {
				TCC_ERR ("character array initializer must be a literal or enclosed in braces");
			}
			skip (s1, '{');
			no_oblock = 0;
		}

		/* only parse strings here if correct type (otherwise: handle
		* them as ((w)char *) expressions */
		// TARGET_PE ?? (t1->t & VT_BTYPE) == VT_INT16 && (t1->t & VT_UNSIGNED)
		if ((s1->tok == TOK_LSTR && (t1->t & VT_BTYPE) == VT_INT32) || (s1->tok == TOK_STR && (t1->t & VT_BTYPE) == VT_INT8)) {
			while (tcc_nerr (s1) == 0 && (s1->tok == TOK_STR || s1->tok == TOK_LSTR)) {
				CString *cstr = s1->tokc.cstr;
				/* compute maximum number of chars wanted */
				const int cstr_len = ((s1->tok == TOK_STR) ? cstr->size : cstr->size / sizeof (nwchar_t)) - 1;
				int nb = cstr_len;
				if (n >= 0 && nb > (n - array_length)) {
					nb = n - array_length;
				}
				if (!size_only) {
					if (cstr_len > nb) {
						tcc_warning (s1, "initializer-string for array is too long");
					}
					/* in order to go faster for common case (char string in global variable, we handle it specifically */
					for (i = 0; i < nb; i++) {
						const int ch = (s1->tok == TOK_STR)
							? ((unsigned char *) cstr->data)[i]
							: ((nwchar_t *) cstr->data)[i];
						init_putv (s1, t1, c + (array_length + i) * size1, ch, EXPR_VAL);
					}
				}
				array_length += nb;
				next (s1);
			}
			/* only add trailing zero if enough storage (no warning in this case since it is standard) */
			if (n < 0 || array_length < n) {
				if (!size_only) {
					init_putv (s1, t1, c + (array_length * size1), 0, EXPR_VAL);
				}
				array_length++;
			}
		} else {
			index = 0;
			while (s1->tok != '}') {
				decl_designator (s1, type, c, &index, NULL, size_only);
				if (n >= 0 && index >= n) {
					TCC_ERR ("index too large");
				}
				// fill with zeros to ensure designators work as intended
				if (!size_only && array_length < index) {
					init_putz (s1, t1, c + array_length * size1, (index - array_length) * size1);
				}
				index++;
				if (index > array_length) {
					array_length = index;
				}
				/* special case for multi dimensional arrays (may not be strictly correct if designators are used at the same time) */
				if (index >= n && no_oblock) {
					break;
				}
				if (s1->tok == '}') {
					break;
				}
				skip (s1, ',');
			}
		}
		if (!no_oblock) {
			skip (s1, '}');
		}
		/* put zeros at the end */
		if (!size_only && n >= 0 && array_length < n) {
			init_putz (s1, t1, c + array_length * size1,
				(n - array_length) * size1);
		}
		/* patch type size if needed */
		if (n < 0) {
			s->c = array_length;
		}
	} else if (is_structured (type) && (!first || s1->tok == '{')) {
		/* NOTE: the previous test is a specific case for automatic struct/union init */
		/* XXX: union needs only one init */

		/* XXX: this test is incorrect for local initializers
		* beginning with ( without {. It would be much more difficult
		* to do it correctly (ideally, the expression parser should
		* be used in all cases) */
		int par_count = 0;
		if (s1->tok == '(') {
			AttributeDef ad1;
			STACK_NEW0 (CType, type1);
			next (s1);
			while (s1->tok == '(') {
				par_count++;
				next (s1);
			}
			if (!parse_btype (s1, &type1, &ad1)) {
				expect (s1, "cast");
			}
			type_decl (s1, &type1, &ad1, &n, TYPE_ABSTRACT);
#if 0
			if (!is_assignable_types (type, &type1)) {
				tcc_error (s1, "invalid type for cast");
			}
#endif
			skip (s1, ')');
		}
		no_oblock = 1;
		if (first || s1->tok == '{') {
			skip (s1, '{');
			no_oblock = 0;
		}
		s = type->ref;
		f = s->next;
		if (!f) {
			TCC_ERR ("missing next entry");
		}
		array_length = 0;
		index = 0;
		n = s->c;
		while (s1->tok != '}') {
			decl_designator (s1, type, c, NULL, &f, size_only);
			index = f->c;
			if (!size_only && array_length < index) {
				init_putz (s1, type, c + array_length,
					index - array_length);
			}
			index = index + type_size (s1, &f->type, &align1);
			if (index > array_length) {
				array_length = index;
			}

			/* gr: skip fields from same union - ugly. */
			while (f->next) {
				///printf("index: %2d %08x -- %2d %08x\n", f->c, f->type.t, f->next->c, f->next->type.t);
				/* test for same offset */
				if (f->next->c != f->c) {
					break;
				}
				/* if yes, test for bitfield shift */
				if ((f->type.t & VT_BITFIELD) && (f->next->type.t & VT_BITFIELD)) {
					const int bit_pos_1 = (f->type.t >> VT_STRUCT_SHIFT) & 0x3f;
					const int bit_pos_2 = (f->next->type.t >> VT_STRUCT_SHIFT) & 0x3f;
					// printf("bitfield %d %d\n", bit_pos_1, bit_pos_2);
					if (bit_pos_1 != bit_pos_2) {
						break;
					}
				}
				f = f->next;
			}

			f = f->next;
			if (no_oblock && f == NULL) {
				break;
			}
			if (s1->tok == '}') {
				break;
			}
			skip (s1, ',');
		}
		/* put zeros at the end */
		if (!size_only && array_length < n) {
			init_putz (s1, type, c + array_length, n - array_length);
		}
		if (!no_oblock) {
			skip (s1, '}');
		}
		while (par_count) {
			skip (s1, ')');
			par_count--;
		}
	} else if (s1->tok == '{') {
		next (s1);
		decl_initializer (s1, type, c, first, size_only);
		skip (s1, '}');
	} else if (size_only) {
		/* just skip expression */
		parlevel = parlevel1 = 0;
		while ((parlevel > 0 || parlevel1 > 0 ||
			(s1->tok != '}' && s1->tok != ',')) && s1->tok != -1) {
			if (s1->tok == '(') {
				parlevel++;
			} else if (s1->tok == ')') {
				parlevel--;
			} else if (s1->tok == '{') {
				parlevel1++;
			} else if (s1->tok == '}') {
				parlevel1--;
			}
			next (s1);
		}
	} else {
		/* currently, we always use constant expression for globals (may change for scripting case) */
		expr_type = EXPR_CONST;
		init_putv (s1, type, c, 0, expr_type);
	}
}

/* parse an initializer for type 't' if 'has_init' is non zero, and
 * allocate space in local or global data space ('r' is either
 * VT_LOCAL or VT_CONST). If 'v' is non zero, then an associated
 * variable 'v' with an associated name represented by 'asm_label' of
 * scope 'scope' is declared before initializers are parsed. If 'v' is
 * zero, then a reference to the new object is put in the value stack.
 * If 'has_init' is 2, a special parsing is done to handle string
 * constants. */
static void decl_initializer_alloc(TCCState *s1, CType *type, AttributeDef *ad, int r, int has_init, int v, char *asm_label, int scope) {
	int align;
	int level;
	ParseState saved_parse_state = {
		0
	};
	TokenString init_str;
	Sym *flexible_array = NULL;
	if (is_struct (type)) {
		Sym *field;
		field = type->ref;
		while (field && field->next) {
			field = field->next;
		}
		if (field && (field->type.t & VT_ARRAY) && (field->type.ref->c < 0)) {
			flexible_array = field;
		}
	}

	int size = type_size (s1, type, &align);
	/* If unknown size, we must evaluate it before
	* evaluating initializers because
	* initializers can generate global data too
	* (e.g. string pointers or ISOC99 compound
	* literals). It also simplifies local
	* initializers handling */
	tok_str_init (&init_str);
	if (size < 0 || (flexible_array && has_init)) {
		if (!has_init) {
			TCC_ERR ("unknown type size");
		}
		/* get all init string */
		if (has_init == 2) {
			/* only get strings */
			while (s1->tok == TOK_STR || s1->tok == TOK_LSTR) {
				tok_str_add_tok (s1, &init_str);
				next (s1);
			}
		} else {
			level = 0;
			while (tcc_nerr (s1) == 0 && (level > 0 || (s1->tok != ',' && s1->tok != ';'))) {
				if (s1->tok < 0) {
					TCC_ERR ("unexpected end of file in initializer");
				}
				tok_str_add_tok (s1, &init_str);
				if (s1->tok == '{') {
					level++;
				} else if (s1->tok == '}') {
					level--;
					if (level <= 0) {
						next (s1);
						break;
					}
				}
				next (s1);
			}
		}
		tok_str_add (s1, &init_str, -1);
		tok_str_add (s1, &init_str, 0);

		/* compute size */
		save_parse_state (s1, &saved_parse_state);

		s1->macro_ptr = init_str.str;
		next (s1);
		decl_initializer (s1, type, 0, 1, 1);
		/* prepare second initializer parsing */
		s1->macro_ptr = init_str.str;
		next (s1);

		/* if still unknown size, error */
		size = type_size (s1, type, &align);
		if (size < 0) {
			TCC_ERR ("unknown type size");
		}
	}
	if (flexible_array) {
		size += flexible_array->type.ref->c * pointed_size (s1, &flexible_array->type);
	}
	/* take into account specified alignment if bigger */
	if (ad->aligned) {
		if (ad->aligned > align) {
			align = ad->aligned;
		}
	} else if (ad->packed) {
		align = 1;
	}
	if ((r & VT_VALMASK) == VT_LOCAL) {
		s1->loc = (s1->loc - size) & - align;
		const int addr = s1->loc;
		if (v) {
			/* local variable */
			sym_push (s1, v, type, r, addr);
		} else {
			/* push local reference */
			vset (s1, type, r, addr);
		}
	} else {
		Sym *sym = NULL;
		if (v && scope == VT_CONST) {
			/* see if the symbol was already defined */
			sym = sym_find (s1, v);
			if (sym) {
				if (!is_compatible_types (&sym->type, type)) {
					TCC_ERR ("incompatible types for redefinition of '%s'",
						get_tok_str (s1, v, NULL));
				}
				if (sym->type.t & VT_EXTERN) {
					/* if the variable is extern, it was not allocated */
					sym->type.t &= ~VT_EXTERN;
					/* set array size if it was ommited in extern declaration */
					if ((sym->type.t & VT_ARRAY) && sym->type.ref->c < 0 && type->ref->c >= 0) {
						sym->type.ref->c = type->ref->c;
					}
				} else {
					/* we accept several definitions of the same
					** global variable. this is tricky, because we
					** must play with the SHN_COMMON type of the symbol */
					/* XXX: should check if the variable was already
					** initialized. It is incorrect to initialized it
					** twice */
					/* no init data, we won't add more to the symbol */
					if (!has_init) {
						return;
					}
				}
			}
		}

		if (v) {
			if (scope != VT_CONST || !sym) {
				sym = sym_push (s1, v, type, r | VT_SYM, 0);
				sym->asm_label = asm_label;
			}
		} else {
			CValue cval = {0};
			vsetc (s1, type, VT_CONST | VT_SYM, &cval);
			s1->vtop->sym = sym;
		}
		/* patch symbol weakness */
		if ((type->t & VT_WEAK) && sym) {
			weaken_symbol (sym);
		}
	}
}

#if 1
/* parse an old style function declaration list */
/* XXX: check multiple parameter */
static void func_decl_list(TCCState *s1, Sym *func_sym) {
	AttributeDef ad;
	int v;
	Sym *s = NULL;
	CType btype, type;

	/* parse each declaration */
	while (tcc_nerr (s1) == 0 && s1->tok != '{' && s1->tok != ';' && s1->tok != ',' && s1->tok != TOK_EOF &&
			s1->tok != TOK_ASM1 && s1->tok != TOK_ASM2 && s1->tok != TOK_ASM3) {
		if (!parse_btype (s1, &btype, &ad)) {
			expect (s1, "declaration list");
		}
		if ((is_enum (&btype) || is_structured (&btype)) && s1->tok == ';') {
			/* we accept no variable after */
		} else {
			while (tcc_nerr (s1) == 0) {
				int found;
				type = btype;
				type_decl (s1, &type, &ad, &v, TYPE_DIRECT);
				/* find parameter in function parameter list */
				s = func_sym;
				found = 0;
				while ((s = s->next)) {
					if ((s->v & ~SYM_FIELD) == v) {
						found = 1;
						break;
					}
				}
				if (found == 0) {
					TCC_ERR ("declaration for parameter '%s' but no such parameter",
						get_tok_str (s1, v, NULL));
				}
				/* check that no storage specifier except 'register' was given */
				if (type.t & VT_STORAGE) {
					TCC_ERR ("storage class specified for '%s'", get_tok_str (s1, v, NULL));
				}
				convert_parameter_type (s1, &type);
				/* we can add the type (NOTE: it could be local to the function) */
				if (s) {
					s->type = type;
				}
				/* accept other parameters */
				if (s1->tok == ',') {
					next (s1);
				} else {
					break;
				}
			}
		}
		skip (s1, ';');
	}
}
#endif

/* 'l' is VT_LOCAL or VT_CONST to define default storage type */
// TODO: must return bool
R_API int tcc_decl0(TCCState *s1, int l, int is_for_loop_init) {
	int v, has_init, r;
	CType type = {.t = 0, .ref = NULL}, btype = {.t = 0, .ref = NULL};
	Sym *sym = NULL;
	AttributeDef ad;

	while (tcc_nerr (s1) == 0) {
		if (!parse_btype (s1, &btype, &ad)) {
			if (is_for_loop_init) {
				return 0;
			}
			/* skip redundant ';' */
			/* XXX: find more elegant solution */
			if (s1->tok == ';') {
				next (s1);
				continue;
			}
			if (l == VT_CONST && (s1->tok == TOK_ASM1 || s1->tok == TOK_ASM2 || s1->tok == TOK_ASM3)) {
				R_LOG_ERROR ("global asm statements are not supported");
				return 1;
			}
			/* special test for old K&R protos without explicit int
			** type. Only accepted when defining global data */
			if (l == VT_LOCAL || s1->tok < TOK_DEFINE) {
				break;
			}
			btype.t = VT_INT32;
		}
		if ((is_enum (&btype) || is_structured (&btype)) && s1->tok == ';') {
			/* we accept no variable after */
			next (s1);
			continue;
		}
		/* iterate thru each declaration */
		while (tcc_nerr (s1) == 0) {
			type = btype;
			type_decl (s1, &type, &ad, &v, TYPE_DIRECT);
#if 0
			{
				char buf[500];
				type_to_str (buf, sizeof (buf), t, get_tok_str (s1, v, NULL));
				printf ("type = '%s'\n", buf);
			}
#endif
			if ((type.t & VT_BTYPE) == VT_FUNC) {
				if ((type.t & VT_STATIC) && (l == VT_LOCAL)) {
					tcc_error (s1, "function without file scope cannot be static");
					return 1;
				}
				/* if old style function prototype, we accept a declaration list */
				sym = type.ref;
				if (sym->c == FUNC_OLD) {
					func_decl_list (s1, sym);
				}
			}
			if (ad.weak) {
				type.t |= VT_WEAK;
			}
#if 0
			if (ad.func_import) {
				type.t |= VT_IMPORT;
			}
			if (ad.func_export) {
				type.t |= VT_EXPORT;
			}
#endif
			if (s1->tok == '{') {
				if (l == VT_LOCAL) {
					tcc_error (s1, "cannot use local functions");
					return 1;
				}
				if ((type.t & VT_BTYPE) != VT_FUNC) {
					expect (s1, "function definition");
				}

				/* reject abstract declarators in function definition */
				sym = type.ref;
				if (!sym) {
					return 0; // XXX unmatching braces in typedef?
				}
				while ((sym = sym->next)) {
					if (!(sym->v & ~SYM_FIELD)) {
						expect (s1, "identifier6");
					}
				}

				/* XXX: cannot do better now: convert extern line to static inline */
				if ((type.t & (VT_EXTERN | VT_INLINE)) == (VT_EXTERN | VT_INLINE)) {
					type.t = (type.t & ~VT_EXTERN) | VT_STATIC;
				}

				sym = sym_find (s1, v);
				if (sym) {
					if ((sym->type.t & VT_BTYPE) != VT_FUNC) {
						goto func_error1;
					}
					r = sym->type.ref->r;
					/* use func_call from prototype if not defined */
					if (FUNC_CALL (r) != FUNC_CDECL && FUNC_CALL (type.ref->r) == FUNC_CDECL) {
						/// XXX workaround for the buggy tcc type punning crap
						AttributeDef rd = {0};
						memcpy (&rd, &r, sizeof (r));
						FUNC_CALL (type.ref->r) = FUNC_CALL (rd);
					}

					/* use export from prototype */
					if (FUNC_EXPORT (r)) {
						FUNC_EXPORT (type.ref->r) = 1;
					}

					/* use static from prototype */
					if (sym->type.t & VT_STATIC) {
						type.t = (type.t & ~VT_EXTERN) | VT_STATIC;
					}

					if (!is_compatible_types (&sym->type, &type)) {
func_error1:
						tcc_error (s1, "incompatible types for redefinition of '%s'",
							get_tok_str (s1, v, NULL));
						return 1;
					}
					/* if symbol is already defined, then put complete type */
					sym->type = type;
				} else {
					/* put function symbol */
					sym = global_identifier_push (s1, v, type.t, 0);
					if (!sym) {
						return 1;
					}
					sym->type.ref = type.ref;
				}
				break;
			} else {
				if (btype.t & VT_TYPEDEF) {
					/* save typedefed type */
					/* XXX: test storage specifiers ? */
					if (s1->tok != ';') {
						v = s1->tok;
						next (s1);
					}
					sym = sym_push (s1, v, &type, INT_ATTR (&ad), 0);
					if (!sym) {
						return 1;
					}
					sym->type.t |= VT_TYPEDEF;
					/* Provide SDB with typedefs' info */
					const char *alias = NULL;
					char buf[500];
					alias = get_tok_str (s1, v, NULL);
					type_to_str (s1, buf, sizeof (buf), &sym->type, NULL);
					tcc_appendf (s1, "%s=typedef\n", alias);
					tcc_appendf (s1, "typedef.%s=%s\n", alias, buf);
					tcc_typedef_alias_fields (s1, alias);
				} else {
					r = 0;
					if ((type.t & VT_BTYPE) == VT_FUNC) {
						/* external function definition */
						/* specific case for func_call attribute */
						type.ref->r = INT_ATTR (&ad);
					} else if (!(type.t & VT_ARRAY)) {
						/* not lvalue if array */
						r |= lvalue_type (type.t);
					}
					has_init = (s1->tok == '=');
					if (has_init && (type.t & VT_VLA)) {
						tcc_error (s1, "Variable length array cannot be initialized");
						return 1;
					}
				}
				if (s1->tok != ',') {
					if (is_for_loop_init) {
						return 1;
					}
					skip (s1, ';');
					break;
				}
				next (s1);
			}
			ad.aligned = 0;
		}
	}
	return 0;
}
