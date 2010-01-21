// TODO: use r_range here??
#include <r_bp.h>

// TRAPTRACE
R_API int r_bp_add_traptrace(struct r_bp_t *bp, ut64 from, ut64 to)
{
	// read a memory, overwrite it as breakpointing area
	// everytime it is hitted, instruction is restored
	return R_TRUE;
}

R_API int r_bp_del_traptrace(struct r_bp_t *bp, ut64 from, ut64 to)
{
	// read a memory, overwrite it as breakpointing area
	// everytime it is hitted, instruction is restored
	return R_TRUE;
}

R_API int r_bp_restore_traptrace(struct r_bp_t *bp, ut64 from, ut64 to)
{
	// read a memory, overwrite it as breakpointing area
	// everytime it is hitted, instruction is restored
	return R_TRUE;
}

