//FIXME improve how we set registers
//FIXME refactor the how we process errors

#include "xnu_threads.h"

#define set_trace_bit(dbg, thread) modify_trace_bit (dbg, thread, 1)
#define clear_trace_bit(dbg, thread) modify_trace_bit (dbg, thread, 0)


#if defined __i386__ || __x86_64__ // intel processors

/* Set/clear bit 8 (Trap Flag) of the EFLAGS processor control
   register to enable/disable single-step mode.
   ENABLE is a boolean, indicating whether to set (1) the Trap Flag
   or clear it (0).  */

static bool modify_trace_bit(RDebug *dbg, xnu_thread_t *th, int enable) {
	R_REG_T *state;
	int ret;
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

#elif __POWERPC__ //ppc processor
//XXX poor support at this stage i don't care so much. Once intel and arm done it could be done
//TODO add better support for ppc
static bool modify_trace_bit(RDebug *dbg, xnu_thread *th, int enable) {
	R_REG_T state;
	unsigned int state_count = R_REG_STATE_SZ;
	kern_return_t kr;
	kr = thread_get_state (th->tid, R_REG_STATE_T,
			(thread_state_t)&state, &state_count);
	if (kr != KERN_SUCCESS) {
		eprintf ("error modify_trace_bit\n");
		return false;
	}
	state.srr1 = (state.srr1 & ~0x400UL) | (enable ? 0x400UL : 0);
	kr = thread_set_state (th->tid, R_REG_STATE_T,
			(thread_state_t)&state, state_count);
	if (kr != KERN_SUCCESS) {
		eprintf ("Error to set thread state modificy_trace_bit ppc\n");
		return false;
	}
	return true;
}

#elif __arm || __arm64  || __aarch64//arm processor

// BCR address match type
#define BCR_M_IMVA_MATCH        ((uint32_t)(0u << 21))
#define BCR_M_CONTEXT_ID_MATCH  ((uint32_t)(1u << 21))
#define BCR_M_IMVA_MISMATCH     ((uint32_t)(2u << 21))
#define BCR_M_RESERVED          ((uint32_t)(3u << 21))

// Link a BVR/BCR or WVR/WCR pair to another
#define E_ENABLE_LINKING	((uint32_t)(1u << 20))

// Byte Address Select
#define BAS_IMVA_PLUS_0		((uint32_t)(1u << 5))
#define BAS_IMVA_PLUS_1		((uint32_t)(1u << 6))
#define BAS_IMVA_PLUS_2		((uint32_t)(1u << 7))
#define BAS_IMVA_PLUS_3		((uint32_t)(1u << 8))
#define BAS_IMVA_0_1		((uint32_t)(3u << 5))
#define BAS_IMVA_2_3		((uint32_t)(3u << 7))
#define BAS_IMVA_ALL		((uint32_t)(0xfu << 5))

// Break only in priveleged or user mode
#define S_RSVD			((uint32_t)(0u << 1))
#define S_PRIV			((uint32_t)(1u << 1))
#define S_USER			((uint32_t)(2u << 1))
#define S_PRIV_USER		((S_PRIV) | (S_USER))

#define BCR_ENABLE		((uint32_t)(1u))
#define WCR_ENABLE		((uint32_t)(1u))

// Watchpoint load/store
#define WCR_LOAD		((uint32_t)(1u << 3))
#define WCR_STORE		((uint32_t)(1u << 4))

// Single instruction step
// (SS bit in the MDSCR_EL1 register)
#define SS_ENABLE ((uint32_t)(1u))

static bool is_thumb_32(ut16 op) {
	return (((op & 0xE000) == 0xE000) && (op & 0x1800));
}

static int modify_trace_bit(RDebug *dbg, xnu_thread *th, int enable) {
	R_DEBUG_REG_T *state;
  	kern_return_t kr;
	int ret;
	ret = xnu_thread_get_drx (dbg, th);
	if (ret == R_FALSE) {
		eprintf ("error to get drx registers modificy_trace_bit arm\n");
		return R_FALSE;
	}
	state = (R_DEBUG_REG_T)th->drx;
	if (state->flavor == ARM_DEBUG_STATE64) {
		state->uds.ds64.__mdscr_el1 = (state->uds64.__mdscr_el1 \
					& SS_ENABLE) & (enable ? SS_ENABLE : 0);

	} else if (state->flavor == ARM_DEBUG_STATE32) {
		R_REG_T *regs;
		ret = xnu_thread_get_gpr (dbg, th);
		if (ret == R_FALSE) {
			eprintf ("error to get gpr register modificy_trace_bit arm\n");
			return R_FALSE;
		}
		regs = (R_REG_T)th->gpr;
		if (enable) {
			int r, i = 0;
			RIOBind *bio = &dbg->io;
			(R_DEBUG_REG_T)th->oldstate = state;
			//set a breakpoint that will stop when the PC doesn't
			//match the current one
			//set the current PC as the breakpoint address
			state->uds.ds32.__bvr[i] = regs->ts_32.__pc;
			state->uds.ds32.__bcr[i] = BCR_M_IMVA_MISMATCH | //stop on address mismatch
				S_USER | //stop only in user mode
				BCR_ENABLE; // enable this breakpoint
			if (regs->ts_32.__cpsr & 0x20) {
				ut16 op;
				// Thumb breakpoint
				if (regs->ts_32.__pc & 2) {
					state->uds.ds32.__bcr[i] |= BAS_IMVA_2_3;
				} else {
					state->uds.ds32.__bcr[i] |= BAS_IMVA_0_1;
				}
				if (bio->read_at (bio->io, regs->ts_32.__pc,
						(void *)&op, 2) < 1) {
					eprintf ("Failed to read opcode modify_trace_bit\n");
					return false;
				}
				if (is_thumb_32 (op)) {
					eprintf ("Thumb32 chain stepping not supported yet\n");
					return false;
				} else {
					// Extend the number of bits to ignore for the mismatch
					state->uds.ds32.__bcr[i] |= BAS_IMVA_ALL;
				}
			} else {
				// ARM breakpoint
				state->uds.ds32.__bcr[i] |= BAS_IMVA_ALL; // Stop when any address bits change
			}
			//disable bits
			for (i = i + 1; i < 16; i++) {
				//Disable all others
				state->uds.ds32.__bcr[i] = 0;
				state->uds.ds32.__bvr[i] = 0;
			}
		} else {
			state->uds.ds32 = ((R_DEBUG_REG_T)th->oldstate)->uds.ds32; //we set the old state
		}
	} else {
		eprintf ("Bad flavor modificy_trace_bit arm\n");
		return false;
	}
	//set state
	th->count = state->dsh.count;
	memcpy (th->state, state->uds, th->count);
	if (!xnu_thread_set_drx (dbg, th)) {
		eprintf ("error to set drx modificy_trace_bit arm\n");
		return false;
	}
	return true;
}

#elif __POWERPC__
	// no need to do this here
static int modify_trace_bit(RDebug *dbg, xnu_thread *th, int enable) {
	return true;
}
#else
#error "unknown architecture"
#endif

//TODO implement current thread
//TODO logic to step
static xnu_exception_info ex = { { 0 } };

//FIXME this will not compile
static bool xnu_save_exception_ports (RDebug *dbg) {
	kern_return_t kr;
	task_t task = pid_to_task (dbg->pid);
	ex.count = (sizeof (ex.ports) / sizeof (ex.ports[0]));
		return false;
	kr = task_get_exception_ports (task, EXC_MASK_ALL,
		ex.masks, &ex.count, ex.ports,
		ex.behaviors, ex.flavors);
	return (kr == KERN_SUCCESS);
}

static void *xnu_exception_thread (void *arg) {
	// here comes the important thing
	eprintf ("xnu.exception.thread started\n");
	return NULL;
}

bool xnu_create_exception_thread(RDebug *dbg) {
	kern_return_t kr;
	int ret;
	mach_port_t exception_port = MACH_PORT_NULL;
        // Got the mach port for the current process
	mach_port_t task_self = mach_task_self ();
	task_t task = pid_to_task (dbg->pid);
	if (task == -1) {
		eprintf ("error to get task for the debugging process"
			" xnu_start_exception_thread\n");
		return false;
	}
	if (!MACH_PORT_VALID (task_self)) {
		eprintf ("error to get the task for the current process"
			" xnu_start_exception_thread\n");
		return false;
	}
        // Allocate an exception port that we will use to track our child process
        kr = mach_port_allocate (task_self, MACH_PORT_RIGHT_RECEIVE,
				&exception_port);
	RETURN_ON_MACH_ERROR ("error to allocate mach_port exception\n", R_FALSE);
        // Add the ability to send messages on the new exception port
        kr  = mach_port_insert_right (task_self, exception_port,
				exception_port, MACH_MSG_TYPE_MAKE_SEND);
	RETURN_ON_MACH_ERROR ("error to allocate insert right\n", R_FALSE);
        // Save the original state of the exception ports for our child process
        ret = xnu_save_exception_ports (dbg);
	if (ret == R_FALSE) {
		eprintf ("error to save exception port info\n");
		return false;
	}
        // Set the ability to get all exceptions on this port
	kr = task_set_exception_ports (task, EXC_MASK_ALL, exception_port,
				EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
				THREAD_STATE_NONE);
	RETURN_ON_MACH_ERROR ("error to set port to receive exceptions\n", R_FALSE);
        // Create the exception thread
	//TODO where to save the exception thread
	//TODO see options pthread_create
        ret = pthread_create (&ex.thread, NULL, &xnu_exception_thread, dbg);
	if (ret) {
		perror ("pthread_create");
		return false;
	}
	return true;
}
