static inline int hackyArmAnal(RAnal *a, RAnalOp *op, const ut8 *buf, int len) {
	// Hacky support for ARMv8.3
	if (a->bits == 64 && len >= 4) {
		// xpaci // e#43c1da
		if (!memcmp (buf + 1, "\x43\xc1\xda", 3)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			return op->size = 4;
		}
		// retaa
		if (!memcmp (buf, "\xff\x0b\x5f\xd6", 4)) {
			op->type = R_ANAL_OP_TYPE_RET;
			return op->size = 4;
		}
		// retab
		if (!memcmp (buf, "\xff\x0f\x5f\xd6", 4)) {
			op->type = R_ANAL_OP_TYPE_RET;
			return op->size = 4;
		}
	}
	return -1;
}
