#ifndef VC4_H__
#define VC4_H__

#include <stdlib.h>
#include <inttypes.h>

extern unsigned int debug_ctrl;

#define DEBUG_CTRL_BASIC    0x00001
#define DEBUG_CTRL_OPS      0x00002
#define DEBUG_CTRL_MATCH    0x00004
#define DEBUG_CTRL_FILL     0x00008
#define DEBUG_CTRL_FRAG     0x00010
#define DEBUG_CTRL_FIX      0x00020
#define DEBUG_CTRL_RELOC    0x00040
#define DEBUG_CTRL_TABLE    0x00080

#define DEBUG(t, f...)  do { if (debug_ctrl & DEBUG_CTRL_ ## t) printf(f); } while (0)
#define DEBUGn(t, f...) do { if (debug_ctrl & DEBUG_CTRL_ ## t) { printf("%s: ", __func__); printf(f); } } while (0)

uint16_t get_le16(const uint8_t *b);

enum vc4_ins_mode
{
	VC4_INS_SCALAR16,
	VC4_INS_SCALAR32_1,
	VC4_INS_SCALAR32_2,
	VC4_INS_SCALAR48,
	VC4_INS_VECTOR48,
	VC4_INS_VECTOR80,
};

struct vc4_insn
{
	uint16_t w0;
	union {
		uint16_t s32;
		uint32_t s48;
		uint16_t v48[2];
		uint16_t v80[4];
	} u;
};

struct vc4_decode_table
{
	struct vc4_decode_table *next;

	char code;
	size_t count;
	char tab[64][16];
};

/* name, has_reg, has_num, pc_rel, divide */
#define VC4_PX_LIST(m) \
	VC4_PX(m, (reg_0_15,       1, 0, 0, 0))	\
	VC4_PX(m, (reg_0_31,       1, 0, 0, 0)) \
	VC4_PX(m, (reg_0_6_16_24,  0, 0, 0, 0)) \
	VC4_PX(m, (reg_r6,         0, 0, 0, 0)) \
	VC4_PX(m, (reg_sp,         0, 0, 0, 0)) /* 25 */ \
	VC4_PX(m, (reg_lr,         0, 0, 0, 0)) /* 26 */ \
	VC4_PX(m, (reg_sr,         0, 0, 0, 0)) /* 30 */ \
	VC4_PX(m, (reg_pc,         0, 0, 0, 0)) /* 31 */ \
	VC4_PX(m, (reg_cpuid,      0, 0, 0, 0)) \
	VC4_PX(m, (reg_range,      0, 0, 0, 0)) \
	VC4_PX(m, (reg_range_r6,   0, 0, 0, 0)) \
	VC4_PX(m, (reg_shl,        1, 0, 0, 0)) \
	VC4_PX(m, (reg_shl_p1,     1, 0, 0, 0)) \
	VC4_PX(m, (reg_lsr,        1, 0, 0, 0)) \
	VC4_PX(m, (reg_lsr_p1,     1, 0, 0, 0)) \
	VC4_PX(m, (reg_shl_8,      1, 0, 0, 0)) \
	VC4_PX(m, (num_u_shl_p1,   0, 0, 0, 0)) \
	VC4_PX(m, (num_s_shl_p1,   0, 0, 0, 0)) \
	VC4_PX(m, (num_u_lsr_p1,   0, 0, 0, 0)) \
	VC4_PX(m, (num_s_lsr_p1,   0, 0, 0, 0)) \
 \
	VC4_PX(m, (num_u,          0,  1, 0, 1))	/* unsigned int             #0x%04x{u} */ \
	VC4_PX(m, (num_s,          0, -1, 0, 1))	/* signed int               #0x%04x{i} */ \
	VC4_PX(m, (num_u4,         0,  1, 0, 4))	/* unsigned int             #0x%04x{u*4} */ \
	VC4_PX(m, (num_s4,         0, -1, 0, 4))	/* signed int               #0x%04x{i*4} */ \
	VC4_PX(m, (addr_reg_0_15,  1,  0, 0, 0))	/* addr of reg              (r%i{s}) */ \
	VC4_PX(m, (addr_reg_0_31,  1,  0, 0, 0))	/* addr of reg              (r%i{s}) */ \
	VC4_PX(m, (addr_2reg_begin_0_31,  1, 0, 0, 0))	/* addr of reg              (r%i{s} */ \
	VC4_PX(m, (addr_2reg_end_0_31,    1, 0, 0, 0))	/* addr of reg              r%i{s}) */ \
	VC4_PX(m, (addr_reg_num_u, 1, 1, 0, 1))	/* addr of reg + unsigned   0x%04x{u}(r%i{s}) */ \
	VC4_PX(m, (addr_reg_num_s, 1, -1, 0, 1))	/* addr of reg + signed     0x%04x{i}(r%i{s}) */ \
	VC4_PX(m, (addr_reg_0_15_num_u4, 1, 1, 0, 4)) /* addr of reg + unsigned   0x%04x{u*4}(r%i{s}) */ \
	VC4_PX(m, (addr_reg_0_15_num_s4, 1, -1, 0, 4)) /* addr of reg + signed     0x%04x{i*4}(r%i{s}) */ \
	VC4_PX(m, (addr_reg_post_inc, 1, 0, 0, 0)) /* addr of reg              (r%i{s})++ */ \
	VC4_PX(m, (addr_reg_pre_dec,  1, 0, 0, 0)) /* addr of reg              --(r%i{s}) */ \
 \
	VC4_PX(m, (r0_rel_s,    0, -1, 0, 1))	/* r0 rel addr + signed    0x%08x{r0+o} */ \
	VC4_PX(m, (r0_rel_s2,   0, -1, 0, 2))	/* r0 rel addr + signed    0x%08x{r0+o*2} */ \
	VC4_PX(m, (r0_rel_s4,   0, -1, 0, 4))	/* r0 rel addr + signed    0x%08x{r0+o*4} */ \
 \
	VC4_PX(m, (r24_rel_s,   0, -1, 0, 1))	/* r24 rel addr + signed    0x%08x{r24+o} */ \
	VC4_PX(m, (r24_rel_s2,  0, -1, 0, 2))	/* r24 rel addr + signed    0x%08x{r24+o*2} */ \
	VC4_PX(m, (r24_rel_s4,  0, -1, 0, 4))	/* r24 rel addr + signed    0x%08x{r24+o*4} */ \
 \
	VC4_PX(m, (sp_rel_s,    0, -1, 0, 1))	/* sp rel addr + signed     0x%08x{sp+o} */ \
	VC4_PX(m, (sp_rel_s2,   0, -1, 0, 2))	/* sp rel addr + signed     0x%08x{sp+o*2} */ \
	VC4_PX(m, (sp_rel_s4,   0, -1, 0, 4))	/* sp rel addr + signed     0x%08x{sp+o*4} */ \
 \
	VC4_PX(m, (pc_rel_s,    0, -1, 1, 1))	/* pc rel addr + signed     0x%08x{$+o} */ \
	VC4_PX(m, (pc_rel_s2,   0, -1, 1, 2))	/* pc rel addr + signed     0x%08x{$+o*2} */ \
	VC4_PX(m, (pc_rel_s4,   0, -1, 1, 4))	/* pc rel addr + signed     0x%08x{$+o*4} */ \


#define VC4_PX(a, b) VC4_PX_ ## a b

#define VC4_PX_ENUM(n, has_reg, has_num, pc_rel, divide) vc4_p_ ## n,
enum vc4_param_type
{
	vc4_p_unknown,

	VC4_PX_LIST(ENUM)

	vc4_p_MAX
};

struct vc4_param
{
	char *txt;
	enum vc4_param_type type;
	size_t reg_width;
	size_t num_width;
	char reg_code;
	char num_code;
};

struct vc4_val
{
	uint32_t value;
	uint32_t length;
};

#define VC4_MAX_PARAMS 15

struct vc4_opcode
{
	struct vc4_opcode *next;

	enum vc4_ins_mode mode;

	char string[81];
	char *format;
	size_t length;

	uint16_t ins[2];
	uint16_t ins_mask[2];

	size_t num_params;
	struct vc4_param params[VC4_MAX_PARAMS];

	struct vc4_val vals_lc[26];
	struct vc4_val vals_uc[26];
};

/* Part of a 'pattern' opcode */
struct vc4_op_pat
{
	size_t count;
	struct {
		char code;
		uint32_t val;
	} pat[3];
};

struct vc4_lookup
{
	const char *str;
	struct vc4_asm *chain;
};

struct vc4_asm
{
	struct vc4_asm *next;
	struct vc4_asm *next_all;

	char str[16];
	struct vc4_op_pat pat;

	struct vc4_opcode *op;

	uint16_t ins[2];
	uint16_t ins_mask[2];
};

struct vc4_opcode_tab
{
	size_t count;
	struct vc4_opcode *tab[1];
};

#define opcode_tab_size(n) offsetof(struct vc4_opcode_tab, tab[n])

struct vc4_info
{
	struct vc4_decode_table *tables;

	char signed_ops[10];

	struct vc4_opcode_tab *opcodes[0x10000];

	struct vc4_opcode *all_opcodes;

	struct vc4_asm *all_asms;
	struct vc4_asm *all_asms_tail;

	struct vc4_lookup *lookup_tab;
	size_t lookup_count;
};

uint16_t vc4_get_le16(const uint8_t *b);

enum vc4_ins_mode vc4_get_instruction_mode(uint16_t b0);
uint16_t vc4_get_instruction_length(uint16_t b0);

struct vc4_info *vc4_read_arch_file(const char *path);

void vc4_free_info(struct vc4_info *info);

char *vc4_display(const struct vc4_info *info, const struct vc4_opcode *op,
		  uint32_t addr, const uint8_t *b, uint32_t len);

const struct vc4_opcode *vc4_get_opcode(const struct vc4_info *info, const uint8_t *b, size_t l);

void vc4_build_values(struct vc4_val *vals, const struct vc4_opcode *op,
		      const uint8_t *b, uint32_t len);

void vc4_add_opcode_tab(struct vc4_opcode_tab **tabp, struct vc4_opcode *op);

void vc4_get_opcodes(struct vc4_info *info);

void vc4_strncat(char **dest, const char *src, int len);
void vc4_strcat(char **dest, const char *src);

void vc4_trim_space(char *p);

void vc4_fill_value(uint16_t *ins, uint16_t *maskp, const struct vc4_opcode *op,
		    char code, uint32_t val);

const char *vc4_param_name(enum vc4_param_type type);
int vc4_param_has_reg(enum vc4_param_type type);
int vc4_param_has_num(enum vc4_param_type type);
int vc4_param_pc_rel(enum vc4_param_type type);
int vc4_param_divide(enum vc4_param_type type);
char *vc4_param_print(const struct vc4_param *par, char *buf);

void vc4_swap_ins(uint16_t *ins, const struct vc4_opcode *op);

struct vc4_lookup *vc4_lookup_find(const struct vc4_info *inf, const char *name);

uint32_t vc4_op_get_val_width(const struct vc4_opcode *op, char code);

#endif
