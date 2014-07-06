#ifndef __TMS320_DASM_H__
#define __TMS320_DASM_H__

#define IDA_COMPATIBLE_MODE	1

/* forward declarations */

struct tms320_instruction;
typedef struct tms320_instruction insn_item_t;

struct tms320_instruction_mask;
typedef struct tms320_instruction_mask insn_mask_t;

struct tms320_instruction_flag;
typedef struct tms320_instruction_flag insn_flag_t;

struct tms320_instruction_head;
typedef struct tms320_instruction_head insn_head_t;

typedef enum {
	TMS320_FLAG_E = 0x10,
	TMS320_FLAG_R,
	TMS320_FLAG_U,
	TMS320_FLAG_u,
	TMS320_FLAG_g,
	TMS320_FLAG_r,
	TMS320_FLAG_t,

	TMS320_FLAG_uu,
	TMS320_FLAG_mm,
	TMS320_FLAG_cc,
	TMS320_FLAG_tt,
	TMS320_FLAG_vv,
	TMS320_FLAG_ss,
	TMS320_FLAG_dd,
	TMS320_FLAG_SS,
	TMS320_FLAG_DD,

	TMS320_FLAG_k3,
	TMS320_FLAG_k4,
	TMS320_FLAG_k5,
	TMS320_FLAG_k6,
	TMS320_FLAG_k8,
	TMS320_FLAG_k12,
	TMS320_FLAG_k16,

	TMS320_FLAG_K8,
	TMS320_FLAG_K16,

	TMS320_FLAG_l1,
	TMS320_FLAG_l3,
	TMS320_FLAG_l7,
	TMS320_FLAG_l16,

	TMS320_FLAG_L7,
	TMS320_FLAG_L8,
	TMS320_FLAG_L16,

	TMS320_FLAG_P8,
	TMS320_FLAG_P24,
	TMS320_FLAG_D16,

	TMS320_FLAG_SHFT,
	TMS320_FLAG_SHIFTW,
	TMS320_FLAG_CCCCCCC,
	TMS320_FLAG_AAAAAAAI,

	TMS320_FLAG_FSSS,
	TMS320_FLAG_FDDD,
	TMS320_FLAG_XSSS,
	TMS320_FLAG_XDDD,
	TMS320_FLAG_XACS,
	TMS320_FLAG_XACD,

	TMS320_FLAG_XXX,
	TMS320_FLAG_MMM,
	TMS320_FLAG_Y,
	TMS320_FLAG_YY,
} insn_flag_e;

struct tms320_instruction {
#define i_list_last(x)			!(((x)->i_list || (x)->m_list || (x)->f_list || (x)->syntax))
	insn_item_t	* i_list;

	insn_mask_t	* m_list;
	insn_flag_t	* f_list;

	char		* syntax;
};

struct tms320_instruction_mask {
#define m_list_last(x)			!(((x)->f || (x)->n || (x)->v))
	ut8		f, n, v;	/* from, number, value */
};

struct tms320_instruction_flag {
#define f_list_last(x)			!(((x)->f || (x)->v))
	ut8		f, v;		/* from, value */
};

struct tms320_instruction_head {
	ut8		byte;
	ut8		size;
	insn_item_t	insn;
};

/*
 * TMS320 dasm instance
 */

typedef struct {
	insn_head_t		* head;
	insn_item_t		* insn;

	union {
		ut8		opcode;
		ut8		stream[8];
		ut64		opcode64;
	};

#define TMS320_S_INVAL		0x01
	ut8			status;
	ut8			length;
	char			syntax[1024];

#define def_field(name, size)			\
	unsigned int bf_##name##_valid:1;	\
	unsigned int bf_##name##_value:size;

	struct {
		def_field	(E, 1);
		def_field	(R, 1);
		def_field	(U, 1);
		def_field	(u, 1);
		def_field	(g, 1);
		def_field	(r, 1);
		def_field	(t, 1);

		def_field	(k3, 3);
		def_field	(k4, 4);
		def_field	(k5, 5);
		def_field	(k6, 6);
		def_field	(k8, 8);
		def_field	(k12, 12);
		def_field	(k16, 16);

		def_field	(l1, 1);
		def_field	(l3, 3);
		def_field	(l7, 7);
		def_field	(l16, 16);

		def_field	(K8, 8);
		def_field	(K16, 16);

		def_field	(L7, 7);
		def_field	(L8, 8);
		def_field	(L16, 16);

		def_field	(P8, 8);
		def_field	(P24, 24);

		def_field	(D16, 16);

		def_field	(SHFT, 4);
		def_field	(SHIFTW, 6);

		def_field	(ss, 2);
		def_field	(dd, 2);

		def_field	(uu, 2);
		def_field	(cc, 2);
		def_field	(mm, 2);
		def_field	(vv, 2);
		def_field	(tt, 2);

		def_field	(FSSS, 4);
		def_field	(FDDD, 4);
		def_field	(XSSS, 4);
		def_field	(XDDD, 4);
		def_field	(XACS, 4);
		def_field	(XACD, 4);

		def_field	(CCCCCCC, 7);
		def_field	(AAAAAAAI, 8);

		def_field	(SS, 2);
		def_field	(SS2, 2);
		def_field	(DD, 2);
		def_field	(DD2, 2);

		// aggregates

		def_field	(Xmem_mmm, 3);
		def_field	(Xmem_reg, 3);

		def_field	(Ymem_mmm, 3);
		def_field	(Ymem_reg, 3);

		// qualifiers

		def_field	(q_lr, 1)
		def_field	(q_cr, 1)
	} f;

	RHashTable		* map;

#define TMS320_F_CPU_C54X	0x0000001
#define TMS320_F_CPU_C55X	0x0000002
#define TMS320_F_CPU_C55X_PLUS	0x0000003
#define TMS320_F_CPU_MASK	0x00000FF
	ut32			features;
#define tms320_f_get_cpu(d)	((d)->features & TMS320_F_CPU_MASK)
#define tms320_f_set_cpu(d, v)	((d)->features = ((d)->features & ~TMS320_F_CPU_MASK) | (v))
} tms320_dasm_t;

#define field_valid(d, name)		\
	(d)->f.bf_##name##_valid
#define field_value(d, name)		\
	(d)->f.bf_##name##_value

#define set_field_value(d, name, value)	\
({					\
	field_valid(d, name) = 1;	\
	field_value(d, name) = value;	\
})

#define LIST_END			{ 0 }

#define INSN_MASK(af, an, av)		{ .f = af, .n = an, .v = av }
#define INSN_FLAG(af, av)		{ .f = af, .v = TMS320_FLAG_##av }
#define INSN_SYNTAX(arg...)		(char *)#arg

extern int tms320_dasm(tms320_dasm_t *, const ut8 *, int);

extern int tms320_dasm_init(tms320_dasm_t *);
extern int tms320_dasm_fini(tms320_dasm_t *);

#endif /* __TMS320_DASM_H__ */
