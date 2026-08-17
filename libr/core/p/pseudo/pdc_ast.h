/* radare - LGPL - Copyright 2026 - pancake, phix33 */

#ifndef R2_PDC_AST_H
#define R2_PDC_AST_H

#include <r_core.h>

typedef enum {
	PDC_R_BB,	// leaf basic block
	PDC_R_SEQ,	// ordered run of sub-regions
	PDC_R_IF,	// single-armed conditional
	PDC_R_IFELSE,	// two-armed conditional (children: then, else)
	PDC_R_WHILE,	// top-test loop
	PDC_R_DOWHILE,	// tail/self test loop
	PDC_R_SWITCH,	// jump table (children: one per unique case target)
	PDC_R_BREAK,	// edge to the innermost loop exit
	PDC_R_CONTINUE,	// edge back to the innermost loop header
	PDC_R_GOTO	// irreducible / already-emitted fallback, never fails
} PdcRegionType;

// which edge of the parent's heading block a child came from
typedef enum {
	PDC_ROLE_SEQ,	// plain element of a run
	PDC_ROLE_JUMP,	// the heading block's taken edge
	PDC_ROLE_FAIL,	// the heading block's fall-through edge
	PDC_ROLE_CASE,	// a switch arm
	PDC_ROLE_HEAD	// heads the parent's own block
} PdcRole;

typedef struct pdc_region_t PdcRegion;
R_VEC_TYPE (RVecPdcRegionPtr, PdcRegion *);

struct pdc_region_t {
	PdcRegionType type;
	PdcRole role;
	ut64 addr;
	ut64 exit;	// where a break leaves this loop or switch (UT64_MAX if none)
	RVecPdcRegionPtr children;
};

// an unset switch default or table addr reads as 0 (jmptbl.c maps the UT64_MAX
// "none" to 0), while other paths do write UT64_MAX: neither is an address
static inline bool valid_addr(ut64 addr) {
	return addr && addr != UT64_MAX;
}

typedef struct {
	PdcRegion *root;
	bool complete;	// false when a two-way block heads no region: must use the linear pass
} PdcPlan;

// build the structuring plan for fcn (caller frees with pdc_plan_free)
PdcPlan *pdc_plan_build(RCore *core, RAnalFunction *fcn);
void pdc_plan_free(PdcPlan *plan);
// build the AST for fcn and return its textual dump (pdct)
char *pdc_ast_dump(RCore *core, RAnalFunction *fcn);

#endif
