//FIXME deallocate all the port when they are not longer needed

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

static xnu_exception_info ex = { { 0 } };

static bool xnu_save_exception_ports (int pid) {
	kern_return_t kr;
	task_t task = pid_to_task (pid);
	ex.count = (sizeof (ex.ports) / sizeof (ex.ports[0]));
	kr = task_get_exception_ports (task, EXC_MASK_ALL,
		ex.masks, &ex.count, ex.ports,
		ex.behaviors, ex.flavors);
	return (kr == KERN_SUCCESS);
}

static bool xnu_restore_exception_ports (int pid) {
	kern_return_t kr;
	int i;
	task_t task = pid_to_task (pid);
	for (i = 0; i < ex.count; i++) {
		kr = task_set_exception_ports (task, ex.masks[i], ex.ports[i],
					       ex.behaviors[i], ex.flavors[i]);
		if (kr != KERN_SUCCESS) {
			eprintf ("fail to restore exception ports\n");
			return false;
		}
	}
	return true;
}

static void encode_reply(mig_reply_error_t *reply, mach_msg_header_t *hdr, int code) {
	mach_msg_header_t *rh = &reply->Head;
	rh->msgh_bits = MACH_MSGH_BITS (MACH_MSGH_BITS_REMOTE (hdr->msgh_bits), 0);
	rh->msgh_remote_port = hdr->msgh_remote_port;
	rh->msgh_size = (mach_msg_size_t) sizeof (mig_reply_error_t);
	rh->msgh_local_port = MACH_PORT_NULL;
	rh->msgh_id = hdr->msgh_id + 100;
	reply->NDR = NDR_record;
	reply->RetCode = code;
}

static void decode_exception_type(int exception) {
	switch (exception) {
	case EXC_BAD_ACCESS:
		eprintf ("EXC_BAD_ACCESS\n");
		break;
	case EXC_BAD_INSTRUCTION:
		eprintf ("EXC_BAD_INSTRUCTION\n");
		break;
	case EXC_ARITHMETIC:
		eprintf ("EXC_ARITHMETIC\n");
		break;
	case EXC_EMULATION:
		eprintf ("EXC_EMULATION\n");
		break;
	case EXC_SOFTWARE:
		eprintf ("EXC_SOFTWARE\n");
		break;
	case EXC_BREAKPOINT:
		eprintf ("EXC_BREAKPOINT\n");
		break;
	default:
		eprintf ("UNKNOWN\n");
		break;
	}

}

static bool decode_exception_message (RDebug *dbg, exc_msg *msg) {
	kern_return_t kret;
	int ret;
	/* check if the message is for us */
	if (msg->hdr.msgh_local_port != ex.exception_port)
		return false;
	//XXX gdb from apple check this dunno why
	/* check message header. */
	if (!(msg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX))
		return false;
	/* check descriptors.  */
	if (msg->hdr.msgh_size <
	    sizeof (mach_msg_header_t) + sizeof (mach_msg_body_t) +
		    2 * sizeof (mach_msg_port_descriptor_t) +
		    sizeof (NDR_record_t) + sizeof (exception_type_t) +
		    sizeof (mach_msg_type_number_t) +
		    sizeof (mach_exception_data_t))
		return false;
	/* check data representation.  */
	if (msg->NDR.mig_vers != NDR_PROTOCOL_2_0 ||
	    msg->NDR.if_vers != NDR_PROTOCOL_2_0 ||
	    msg->NDR.mig_encoding != NDR_record.mig_encoding ||
	    msg->NDR.int_rep != NDR_record.int_rep ||
	    msg->NDR.char_rep != NDR_record.char_rep ||
	    msg->NDR.float_rep != NDR_record.float_rep)
		return -1;
	/* We got new rights to the task, get rid of it.*/
	kret = mach_port_deallocate (mach_task_self (), msg->task.name);
	if (kret != KERN_SUCCESS) {
		eprintf ("faild to deallocate task port "
			"decode_exception_message\n");
	}
	if (pid_to_task (dbg->pid) != msg->task.name) {
		//we receive a exception from an unkown process this could
		//happen if the child fork, as the created process will inherit
		//its exception port
		//XXX should we manage this in somehow?
		mig_reply_error_t reply;
		kret = mach_port_deallocate (mach_task_self (), msg->thread.name);
		if (kret != KERN_SUCCESS) {
			eprintf ("failed to deallocate thread port "
				"decode_exception_message\n");
			return false;
		}
		encode_reply (&reply, &msg->hdr, KERN_SUCCESS);
		kret = mach_msg (&reply.Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
				reply.Head.msgh_size, 0,
				MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
				MACH_PORT_NULL);
		if (kret != KERN_SUCCESS) {
			eprintf ("failed to reply decode_exception_message\n");
			return false;
		}
	}

	kret = mach_port_deallocate (mach_task_self (), msg->thread.name);
	if (kret != KERN_SUCCESS) {
		eprintf ("failed to deallocate thread port "
			"decode_exception_message two\n");
		return false;
	}
	decode_exception_type (msg->exception);
	ret = write (exc_pipe[1], &msg->exception, sizeof(int));
	if (ret == -1)
		eprintf ("failed to write exception into the pipe\n");
	return true;

}

//handle exception as gdb-2381 does and avoid mach_exc_server
//using continue with ptrace we receive the exception so the 
//issue is ours, in the way we are setting the trace bit since 
//for some reason it doesn't work as it should


static void *xnu_exception_thread (void *arg) {
	// here comes the important thing
	RDebug *dbg;
	kern_return_t kret;
	exc_msg msg;
	if (!arg)
		return NULL;
	dbg = (RDebug *)arg;
	for (;;) {
		//wait for a incoming messages
		kret = mach_msg (&msg.hdr, MACH_RCV_MSG | MACH_RCV_INTERRUPT, 0,
				 sizeof (exc_msg), ex.exception_port, 0,
				 MACH_PORT_NULL);
		if (kret != KERN_SUCCESS) {
			eprintf ("fail to retrieve message exception thread\n");
			break;
		}
		if (msg.hdr.msgh_id == 2401)
			eprintf ("exception raise\n");
		else if (msg.hdr.msgh_id == 2405)
			eprintf ("mach exception raise\n");
		else
			eprintf ("unknown msgh_id");
		(void)decode_exception_message (dbg, &msg);
	}
}




bool xnu_create_exception_thread(RDebug *dbg) {
	kern_return_t kr;
	bool ret;
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
	kr = mach_port_insert_right (task_self, exception_port, exception_port,
				     MACH_MSG_TYPE_MAKE_SEND);
	RETURN_ON_MACH_ERROR ("error to allocate insert right\n", R_FALSE);
        // Save the original state of the exception ports for our child process
        ret = xnu_save_exception_ports (dbg->pid);
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
        ret = pthread_create (&ex.thread, NULL, &xnu_exception_thread, dbg);
	if (ret) {
		perror ("pthread_create");
		return false;
	}
	ex.exception_port = exception_port;
	return true;
}
