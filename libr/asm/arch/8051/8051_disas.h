#ifndef R2_8051_DISAS_H
#define R2_8051_DISAS_H

// R_API int r_8051_disas (ut64 pc, RAsmOp *op, const ut8 *buf, ut64 len);
R_API char *r_8051_disas(ut64 pc, const ut8 *buf, int len, int *olen);

#endif
