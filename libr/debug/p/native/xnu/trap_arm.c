#if __arm || __arm64 || __arch64

static int isThumb32(ut16 op) {
	return (((op & 0xE000) == 0xE000) && (op & 0x1800));
}

static bool ios_hwstep_enable64(RDebug *dbg, bool enable) {
	ARMDebugState64 ds;
	thread_t th = getcurthread (dbg, NULL);

	mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
	if (thread_get_state (th, ARM_DEBUG_STATE64, (thread_state_t)&ds, &count)) {
		perror ("thread-get-state");
		return false;
	}
	// The use of __arm64__ here is not ideal.  If debugserver is running on
	// an armv8 device, regardless of whether it was built for arch arm or
	// arch arm64, it needs to use the MDSCR_EL1 SS bit to single
	// instruction step.

	// MDSCR_EL1 single step bit at gpr.pc
	if (enable) {
		ds.mdscr_el1 |= 1LL;
	} else {
		ds.mdscr_el1 &= ~(1ULL);
	}
	if (thread_set_state (th, ARM_DEBUG_STATE64, (thread_state_t)&ds, count)) {
		perror ("thread-set-state");
	}
	return true;
}

static bool ios_hwstep_enable32(RDebug *dbg, bool enable) {
	mach_msg_type_number_t count;
	arm_unified_thread_state_t state = {{0}};
	_STRUCT_ARM_DEBUG_STATE ds;
	task_t task = 0;
	thread_t th = getcurthread (dbg, &task);
	int ret;

	count = ARM_DEBUG_STATE32_COUNT;
	ret = thread_get_state (th, ARM_DEBUG_STATE32, (thread_state_t)&ds, &count);
	if (ret != KERN_SUCCESS) {
		perror ("thread_get_state(debug)");
	}

	count = ARM_UNIFIED_THREAD_STATE_COUNT;
	ret = thread_get_state (th, ARM_UNIFIED_THREAD_STATE, (thread_state_t)&state, &count);
	if (ret != KERN_SUCCESS) {
		perror ("thread_get_state(unified)");
	}
	//eprintf ("PC = 0x%08x\n", state.ts_32.__pc);
	if (enable) {
		int i;
		RIOBind *bio = &dbg->iob;
		ut32 pc = state.ts_32.__pc;
		ut32 cpsr = state.ts_32.__cpsr;
		for (i = 0; i < 16 ; i++) {
			ds.__bcr[i] = ds.__bvr[i] = 0;
		}
		i = 0;
		ds.__bvr[i] = pc & (UT32_MAX >> 2) << 2;
		ds.__bcr[i] = BCR_M_IMVA_MISMATCH | S_USER | BCR_ENABLE;
		if (cpsr & 0x20) {
			ut16 op;
			if (pc & 2) {
				ds.__bcr[i] |= BAS_IMVA_2_3;
			} else {
				ds.__bcr[i] |= BAS_IMVA_0_1;
			}
			/* check for thumb */
			bio->read_at (bio->io, pc, (void *)&op, 2);
			if (isThumb32 (op)) {
				eprintf ("Thumb32 chain stepping not supported yet\n");
			} else {
				ds.__bcr[i] |= BAS_IMVA_ALL;
			}
		} else {
			ds.__bcr[i] |= BAS_IMVA_ALL;
		}
	}
	if (thread_set_state (th, ARM_DEBUG_STATE32, (thread_state_t)&ds, ARM_DEBUG_STATE32_COUNT)) {
		perror ("ios_hwstep_enable32");
		return false;
	}
	return true;
}

bool xnu_native_hwstep_enable(RDebug *dbg, bool enable) {
	if (dbg->bits == R_SYS_BITS_64 || dbg->bits == 64) {
		return ios_hwstep_enable64 (dbg, enable);
	}
	return ios_hwstep_enable32 (dbg, enable);
}
#endif
