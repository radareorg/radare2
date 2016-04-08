#if __i386__ || __x86_64__
static bool xnu_thread_get_gpr(RDebug *dbg, xnu_thread_t *thread);
static xnu_thread_t* get_xnu_thread(RDebug *dbg, int tid);

static bool xnu_x86_hwstep_enable64(RDebug *dbg, bool enable) {
	R_REG_T *state;
	int ret;
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	ret = xnu_thread_get_gpr (dbg, th);
	if (!ret) {
		eprintf ("error to get gpr registers in trace bit intel\n");
		return false;
	}
	state = (R_REG_T *)&th->gpr;
	if (state->tsh.flavor == x86_THREAD_STATE32) {
		state->uts.ts32.__eflags = (state->uts.ts32.__eflags & \
					~0x100UL) | (enable ? 0x100UL : 0);
	} else if (state->tsh.flavor == x86_THREAD_STATE64) {
		state->uts.ts64.__rflags = (state->uts.ts64.__rflags & \
					~0x100UL) | (enable ? 0x100UL : 0);
	} else {
		eprintf ("Invalid bit size\n");
		return false;
	}
	if (!xnu_thread_set_gpr (dbg, th)) {
		eprintf ("error xnu_thread_set_gpr in modify_trace_bit intel\n");
		return false;
	}
	return true;
}

static bool xnu_x86_hwstep_enable32(RDebug *dbg, bool enable) {
	R_REG_T *state;
	xnu_thread_t *th = get_xnu_thread (dbg, dbg->tid);
	int ret = xnu_thread_get_gpr (dbg, th);
	if (!ret) {
		eprintf ("error to get gpr registers in trace bit intel\n");
		return false;
	}
	state = (R_REG_T *)&th->gpr;
	if (state->tsh.flavor == x86_THREAD_STATE32) {
		state->uts.ts32.__eflags = (state->uts.ts32.__eflags & \
					~0x100UL) | (enable ? 0x100UL : 0);
	} else {
		eprintf ("Invalid bit size\n");
		return false;
	}
	if (!xnu_thread_set_gpr (dbg, th)) {
		eprintf ("error xnu_thread_set_gpr in modify_trace_bit intel\n");
		return false;
	}
	return true;
}

bool xnu_native_hwstep_enable(RDebug *dbg, bool enable) {
	if (dbg->bits == R_SYS_BITS_64)
		return xnu_x86_hwstep_enable64 (dbg, enable);
	return xnu_x86_hwstep_enable32 (dbg, enable);
}
#endif
