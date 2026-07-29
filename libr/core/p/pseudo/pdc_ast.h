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
	PDC_R_GOTO	// irreducible / already-emitted fallback, never fails
} PdcRegionType;

typedef struct pdc_region_t PdcRegion;
R_VEC_TYPE (RVecPdcRegionPtr, PdcRegion *);

struct pdc_region_t {
	PdcRegionType type;
	ut64 addr;
	RVecPdcRegionPtr children;
};

// build the structuring region AST for fcn (caller frees with pdc_ast_free)
PdcRegion *pdc_ast_build(RCore *core, RAnalFunction *fcn);
void pdc_ast_free(PdcRegion *root);
// build the AST for fcn and return its textual dump (pdct)
char *pdc_ast_dump(RCore *core, RAnalFunction *fcn);

#endif
