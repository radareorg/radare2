/* implementation */

static int iscallret(RDebug *dbg, ut64 addr) {
	ut8 buf[32];
	RAnalOp op = {0};
	int i;
	if (addr == 0LL || addr == UT64_MAX) {
		return 0;
	}
	/* check if region is executable */
	/* check if previous instruction is a call */
	/* try looking back up to 16 bytes to find a call instruction */
	if (dbg->arch && !strcmp (dbg->arch, "x86")) {
		// On x86, try to find CALL instructions of various lengths
		// Check for common patterns
		int maxdist = (dbg->bits == 64) ? 16 : 8;
		if (!dbg->iob.read_at (dbg->iob.io, addr - maxdist, buf, maxdist)) {
			return 0;
		}
		// Look backwards for CALL instructions
		for (i = maxdist - 1; i >= 0; i--) {
			// Direct CALL (e8 xx xx xx xx)
			if (buf[i] == 0xe8 && (i + 5 == maxdist)) {
				return 1;
			}
			// Indirect CALL (ff /2)
			if (buf[i] == 0xff) {
				int modrm = (i + 1 < maxdist) ? buf[i + 1] : 0;
				int reg = (modrm >> 3) & 7;
				if (reg == 2) { // CALL r/m
					// Estimate instruction length based on ModR/M
					int mod = (modrm >> 6) & 3;
					int rm = modrm & 7;
					int len = 2;
					if (mod == 0 && rm == 5) {
						len = 6; // disp32
					} else if (mod == 1) {
						len = 3; // disp8
					} else if (mod == 2) {
						len = 6; // disp32
					}
					if (i + len == maxdist) {
						return 1;
					}
				}
			}
		}
	} else {
		// For non-x86, use anal to check
		int maxdist = 16;
		if (!dbg->iob.read_at (dbg->iob.io, addr - maxdist, buf, maxdist)) {
			return 0;
		}
		// Try different positions
		for (i = maxdist - 1; i >= maxdist - 8 && i >= 0; i--) {
			if (r_anal_op (dbg->anal, &op, addr - (maxdist - i), buf + i, maxdist - i, R_ARCH_OP_MASK_BASIC) > 0) {
				if ((op.type == R_ANAL_OP_TYPE_CALL || op.type == R_ANAL_OP_TYPE_UCALL) &&
				    (addr - (maxdist - i) + op.size == addr)) {
					return 1;
				}
			}
		}
	}
	return 0;
}

static RList *backtrace_fuzzy(RDebug *dbg, ut64 at) {
	ut8 *ptr;
	const int wordsize = dbg->bits / 8;
	ut64 sp;
	RIOBind *bio = &dbg->iob;
	int i;
	ut64 *p64, addr = 0LL;
	ut32 *p32;
	ut16 *p16;
	ut64 cursp, oldsp;
	RList *list;

	const int stacksize = 1024 * 512; // 512KB .. should get the size from the regions if possible
	ut8 *stack = malloc (stacksize);
	if (!stack) {
		return NULL;
	}
	if (at == UT64_MAX) {
		RRegItem *ri;
		RReg *reg = dbg->reg;
		const char *spname = r_reg_alias_getname (reg, R_REG_ALIAS_SP);
		if (!spname) {
			R_LOG_ERROR ("Cannot find stack pointer register");
			free (stack);
			return NULL;
		}
		ri = r_reg_get (reg, spname, R_REG_TYPE_GPR);
		if (!ri) {
			R_LOG_ERROR ("Cannot find stack pointer register");
			free (stack);
			return NULL;
		}
		sp = r_reg_get_value (reg, ri);
	} else {
		sp = at;
	}

	list = r_list_new ();
	list->free = free;
	cursp = oldsp = sp;
	(void)bio->read_at (bio->io, sp, stack, stacksize);
	ptr = stack;
	for (i = 0; i < dbg->btdepth; i++) {
		p64 = (ut64*)ptr;
		p32 = (ut32*)ptr;
		p16 = (ut16*)ptr;
		switch (wordsize) {
		case 8: addr = *p64; break;
		case 4: addr = *p32; break;
		case 2: addr = *p16; break;
		default:
			R_LOG_ERROR ("Invalid word size with asm.bits");
			r_list_free (list);
			free (stack);
			return NULL;
		}
		if (iscallret (dbg, addr)) {
			RDebugFrame *frame = R_NEW0 (RDebugFrame);
			frame->addr = addr;
			frame->size = cursp - oldsp;
			frame->sp = cursp;
			frame->bp = oldsp; //addr + (i * wordsize); // -4 || -8
			// R_LOG_DEBUG ("--------------> 0x%llx (%d)", addr, frame->size);
			r_list_append (list, frame);
			oldsp = cursp;
		}
		ptr += wordsize;
		cursp += wordsize;
	}
	free (stack);
	return list;
}
