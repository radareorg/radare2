/* radare - MIT - Copyright 2026 - pancake */

// backend for the <kernel/debugger.h> nub protocol, included from p/debug_native.c; the session is owned by the haiku io plugin

#ifdef __HAIKU__

#define HAIKU_WAIT_TIMEOUT 200000 // 200ms, keeps ^C responsive

static RIOHaikuDbg *haiku_dbg_get(RDebug *dbg) {
	RIODesc *desc = (dbg->iob.io)? dbg->iob.io->desc: NULL;
	// match by name: the plugin symbol itself is not exported by libr_io
	if (desc && desc->data && desc->plugin && desc->plugin->isdbg
			&& !strcmp (desc->plugin->meta.name, "haiku")) {
		return (RIOHaikuDbg *)desc->data;
	}
	return NULL;
}

static thread_id haiku_dbg_tid(RDebug *dbg, RIOHaikuDbg *hdbg) {
	if (hdbg->stopped_thread >= 0) {
		return hdbg->stopped_thread;
	}
	return (dbg->tid > 0)? (thread_id)dbg->tid: hdbg->main_thread;
}

// map a kernel debugger event to a stop reason, NONE for the boring ones
static RDebugReasonType haiku_dbg_reason(RDebug *dbg, debug_debugger_message_data *msg, int32 code) {
	switch (code) {
	case B_DEBUGGER_MESSAGE_THREAD_DEBUGGED:
		return R_DEBUG_REASON_STOPPED;
	case B_DEBUGGER_MESSAGE_DEBUGGER_CALL:
	case B_DEBUGGER_MESSAGE_TEAM_EXEC:
		return R_DEBUG_REASON_TRAP;
	case B_DEBUGGER_MESSAGE_BREAKPOINT_HIT:
	case B_DEBUGGER_MESSAGE_WATCHPOINT_HIT:
		return R_DEBUG_REASON_BREAKPOINT;
	case B_DEBUGGER_MESSAGE_SINGLE_STEP:
		return R_DEBUG_REASON_STEP;
	case B_DEBUGGER_MESSAGE_SIGNAL_RECEIVED:
		dbg->reason.signum = msg->signal_received.signal;
		return R_DEBUG_REASON_SIGNAL;
	case B_DEBUGGER_MESSAGE_EXCEPTION_OCCURRED:
		switch (msg->exception_occurred.exception) {
		case B_SEGMENT_VIOLATION:
			return R_DEBUG_REASON_SEGFAULT;
		case B_DIVIDE_ERROR:
			return R_DEBUG_REASON_DIVBYZERO;
		case B_INVALID_OPCODE_EXCEPTION:
			return R_DEBUG_REASON_ILLEGAL;
		default:
			return R_DEBUG_REASON_TRAP;
		}
	case B_DEBUGGER_MESSAGE_TEAM_DELETED:
		dbg->reason.signum = msg->team_deleted.signal;
		return R_DEBUG_REASON_DEAD;
	case B_DEBUGGER_MESSAGE_THREAD_CREATED:
		return R_DEBUG_REASON_NEW_TID;
	case B_DEBUGGER_MESSAGE_THREAD_DELETED:
		return R_DEBUG_REASON_EXIT_TID;
	case B_DEBUGGER_MESSAGE_IMAGE_CREATED:
		return R_DEBUG_REASON_NEW_LIB;
	case B_DEBUGGER_MESSAGE_IMAGE_DELETED:
		return R_DEBUG_REASON_EXIT_LIB;
	}
	// syscalls, profiler updates, handover: nothing r2 stops for
	return R_DEBUG_REASON_NONE;
}

// pump events, auto-resuming boring and foreign ones; tries bounds the wait (0 means forever) and breakable turns ^C into a stop request
static RDebugReasonType haiku_dbg_wait_event(RDebug *dbg, RIOHaikuDbg *hdbg, int tries, bool breakable) {
	RCore *core = dbg->coreb.core;
	for (;;) {
		int32 code;
		debug_debugger_message_data msg;
		const ssize_t n = read_port_etc (hdbg->debugger_port, &code, &msg,
			sizeof (msg), B_RELATIVE_TIMEOUT, HAIKU_WAIT_TIMEOUT);
		if (n == B_TIMED_OUT || n == B_INTERRUPTED) {
			if (breakable && r_cons_is_breaked (core->cons)) {
				// force a stop; the THREAD_DEBUGGED answer ends the loop
				debug_thread (haiku_dbg_tid (dbg, hdbg));
			} else if (n == B_TIMED_OUT && tries && !--tries) {
				return R_DEBUG_REASON_ERROR;
			}
			continue;
		}
		if (n < 0) {
			return R_DEBUG_REASON_ERROR;
		}
		const bool sync = msg.origin.thread >= 0 && msg.origin.nub_port >= 0;
		const RDebugReasonType reason = (msg.origin.team == hdbg->team)
			? haiku_dbg_reason (dbg, &msg, code): R_DEBUG_REASON_NONE;
		if (reason == R_DEBUG_REASON_NONE) {
			if (sync) {
				r_haiku_continue_thread (msg.origin.nub_port, msg.origin.thread,
					false, B_THREAD_DEBUG_HANDLE_EVENT);
			}
			continue;
		}
		hdbg->event_code = code;
		if (sync) {
			hdbg->stopped_thread = msg.origin.thread;
			dbg->tid = msg.origin.thread;
		}
		if (msg.origin.thread >= 0) {
			dbg->reason.tid = msg.origin.thread;
		}
		dbg->reason.type = reason;
		return reason;
	}
}

static RDebugReasonType haiku_dbg_wait(RDebug *dbg, int pid) {
	RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
	if (!hdbg) {
		return R_DEBUG_REASON_ERROR;
	}
	RDebugReasonType reason = hdbg->pending;
	hdbg->pending = R_DEBUG_REASON_NONE;
	if (reason == R_DEBUG_REASON_NONE) {
		RCore *core = dbg->coreb.core;
		r_cons_break_push (core->cons, NULL, NULL);
		reason = haiku_dbg_wait_event (dbg, hdbg, 0, true);
		r_cons_break_pop (core->cons);
	}
	return reason;
}

static bool haiku_dbg_attach(RDebug *dbg, int pid) {
	RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
	if (!hdbg || hdbg->team != (team_id)pid) {
		R_LOG_ERROR ("haiku: attaching requires an hdbg:// or attach:// io uri");
		return false;
	}
	if (hdbg->stopped_thread < 0) {
		thread_info ti;
		if (hdbg->main_thread < 0 || get_thread_info (hdbg->main_thread, &ti) != B_OK) {
			return false;
		}
		// a team spawned via load_image() sits suspended before its entrypoint and needs a kick to reach the stop
		debug_thread (hdbg->main_thread);
		if (ti.state == B_THREAD_SUSPENDED) {
			resume_thread (hdbg->main_thread);
		}
		// hold the stop reason for the next wait() call
		hdbg->pending = haiku_dbg_wait_event (dbg, hdbg, 5000000 / HAIKU_WAIT_TIMEOUT, false);
		if (hdbg->pending == R_DEBUG_REASON_ERROR) {
			R_LOG_ERROR ("haiku: no stop event after attaching to %d", pid);
			hdbg->pending = R_DEBUG_REASON_NONE;
			return false;
		}
	}
	dbg->pid = pid;
	return true;
}

static bool haiku_dbg_detach(RDebug *dbg, int pid) {
	RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
	if (hdbg && hdbg->stopped_thread >= 0) {
		r_haiku_continue_thread (hdbg->nub_port, hdbg->stopped_thread, false, B_THREAD_DEBUG_HANDLE_EVENT);
		hdbg->stopped_thread = -1;
		hdbg->pending = R_DEBUG_REASON_NONE;
	}
	return remove_team_debugger ((team_id)pid) == B_OK;
}

static bool haiku_dbg_continue(RDebug *dbg, int pid, int tid, int sig, bool single_step) {
	RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
	if (!hdbg) {
		return false;
	}
	const thread_id t = (hdbg->stopped_thread >= 0)? hdbg->stopped_thread: (thread_id)tid;
	const bool sigev = hdbg->event_code == B_DEBUGGER_MESSAGE_SIGNAL_RECEIVED;
	// sig: -1 keeps the received signal, 0 drops it, else replaces it
	uint32 handle = B_THREAD_DEBUG_HANDLE_EVENT;
	if (sigev && sig >= 0 && sig != dbg->reason.signum) {
		handle = B_THREAD_DEBUG_IGNORE_EVENT;
	}
	if (sig > 0 && (!sigev || sig != dbg->reason.signum)) {
		send_signal (t, sig);
	}
	if (!r_haiku_continue_thread (hdbg->nub_port, t, single_step, handle)) {
		return false;
	}
	hdbg->stopped_thread = -1;
	hdbg->pending = R_DEBUG_REASON_NONE;
	return true;
}

static bool haiku_dbg_step(RDebug *dbg) {
	return haiku_dbg_continue (dbg, dbg->pid, dbg->tid, -1, true);
}

#if __x86_64__ || __i386__
// the plain registers start at the gs member, after the leading fpu/sse state
#define HAIKU_GPR_OFF (offsetof (debug_cpu_state, gs))
#define HAIKU_GPR_SIZE (sizeof (debug_cpu_state) - HAIKU_GPR_OFF)

static bool haiku_dbg_get_cpu_state(RDebug *dbg, RIOHaikuDbg *hdbg, debug_nub_get_cpu_state_reply *reply) {
	debug_nub_get_cpu_state msg = {
		.reply_port = hdbg->reply_port,
		.thread = haiku_dbg_tid (dbg, hdbg)
	};
	return r_haiku_send_msg (hdbg, B_DEBUG_MESSAGE_GET_CPU_STATE,
		&msg, sizeof (msg), reply, sizeof (*reply)) == B_OK && reply->error == B_OK;
}
#endif

static bool haiku_dbg_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
#if __x86_64__ || __i386__
	if (type == R_REG_TYPE_GPR || type == R_REG_TYPE_SEG || type == R_REG_TYPE_FLG) {
		RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
		debug_nub_get_cpu_state_reply reply;
		if (hdbg && haiku_dbg_get_cpu_state (dbg, hdbg, &reply)) {
			memcpy (buf, (const ut8 *)&reply.cpu_state + HAIKU_GPR_OFF,
				R_MIN ((size_t)size, HAIKU_GPR_SIZE));
			return true;
		}
	}
#endif
	return false;
}

static bool haiku_dbg_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
#if __x86_64__ || __i386__
	if (type == R_REG_TYPE_GPR) {
		RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
		debug_nub_get_cpu_state_reply reply;
		if (hdbg && haiku_dbg_get_cpu_state (dbg, hdbg, &reply)) {
			debug_nub_set_cpu_state msg = {
				.thread = haiku_dbg_tid (dbg, hdbg),
				.cpu_state = reply.cpu_state
			};
			memcpy ((ut8 *)&msg.cpu_state + HAIKU_GPR_OFF, buf,
				R_MIN ((size_t)size, HAIKU_GPR_SIZE));
			return r_haiku_send_msg (hdbg, B_DEBUG_MESSAGE_SET_CPU_STATE,
				&msg, sizeof (msg), NULL, 0) == B_OK;
		}
	}
#endif
	return false;
}

static void haiku_dbg_map_free(RDebugMap *map) {
	if (map) {
		free (map->name);
		free (map->file);
		free (map);
	}
}

static bool haiku_image_at(team_id team, ut64 addr, image_info *ii) {
	int32 cookie = 0;
	while (get_next_image_info (team, &cookie, ii) == B_OK) {
		const ut64 text = (ut64)(size_t)ii->text;
		const ut64 data = (ut64)(size_t)ii->data;
		if ((addr >= text && addr < text + ii->text_size)
				|| (addr >= data && addr < data + ii->data_size)) {
			return true;
		}
	}
	return false;
}

static RList *haiku_dbg_map_get(RDebug *dbg) {
	if (dbg->pid == -1) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)haiku_dbg_map_free);
	area_info ai;
	ssize_t cookie = 0;
	while (list && get_next_area_info (dbg->pid, &cookie, &ai) == B_OK) {
		const int perm = ((ai.protection & B_READ_AREA)? R_PERM_R: 0)
			| ((ai.protection & B_WRITE_AREA)? R_PERM_W: 0)
#ifdef B_EXECUTE_AREA
			| ((ai.protection & B_EXECUTE_AREA)? R_PERM_X: 0)
#endif
			;
		const ut64 addr = (ut64)(size_t)ai.address;
		RDebugMap *map = r_debug_map_new (ai.name, addr, addr + ai.size, perm, 0);
		if (!map) {
			break;
		}
		// areas owned by a loaded image take its path, so the debuggee base address resolves from the maps
		image_info ii;
		if (haiku_image_at (dbg->pid, addr, &ii)) {
			free (map->name);
			map->name = strdup (ii.name);
			map->file = strdup (ii.name);
		} else {
			map->file = strdup (ai.name);
		}
		r_list_append (list, map);
	}
	return list;
}

static RList *haiku_dbg_modules_get(RDebug *dbg) {
	if (dbg->pid == -1) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)haiku_dbg_map_free);
	image_info ii;
	int32 cookie = 0;
	while (list && get_next_image_info (dbg->pid, &cookie, &ii) == B_OK) {
		const ut64 text = (ut64)(size_t)ii.text;
		RDebugMap *map = r_debug_map_new (ii.name, text, text + ii.text_size, R_PERM_R | R_PERM_X, 0);
		if (!map) {
			break;
		}
		map->file = strdup (ii.name);
		r_list_append (list, map);
	}
	return list;
}

static RList *haiku_dbg_threads(RDebug *dbg, int pid, RList *list) {
	thread_info ti;
	int32 cookie = 0;
	while (get_next_thread_info ((team_id)pid, &cookie, &ti) == B_OK) {
		const char st = (ti.state == B_THREAD_RUNNING || ti.state == B_THREAD_READY)
			? R_DBG_PROC_RUN: (ti.state == B_THREAD_SUSPENDED)
			? R_DBG_PROC_STOP: R_DBG_PROC_SLEEP;
		r_list_append (list, r_debug_pid_new (ti.name, ti.thread, 0, st, 0));
	}
	return list;
}

static RList *haiku_dbg_pids(RDebug *dbg, int pid, RList *list) {
	team_info ti;
	int32 cookie = 0;
	while ((pid? get_team_info ((team_id)pid, &ti)
			: get_next_team_info (&cookie, &ti)) == B_OK) {
		r_list_append (list, r_debug_pid_new (ti.args, ti.team, ti.uid, R_DBG_PROC_RUN, 0));
		if (pid) {
			break;
		}
	}
	return list;
}

static RDebugInfo *haiku_dbg_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	RIOHaikuDbg *hdbg = haiku_dbg_get (dbg);
	rdi->status = (hdbg && hdbg->stopped_thread >= 0)? R_DBG_PROC_STOP: R_DBG_PROC_SLEEP;
	team_info ti;
	if (get_team_info (dbg->pid, &ti) == B_OK) {
		rdi->cmdline = strdup (ti.args);
		rdi->uid = ti.uid;
		rdi->gid = ti.gid;
	}
	image_info ii;
	int32 cookie = 0;
	while (get_next_image_info (dbg->pid, &cookie, &ii) == B_OK) {
		if (ii.type == B_APP_IMAGE) {
			rdi->exe = strdup (ii.name);
			break;
		}
	}
	return rdi;
}

// kernel assisted (hardware) breakpoints through the debug nub
static bool haiku_dbg_bp(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	RDebug *dbg = bp->user;
	RIOHaikuDbg *hdbg = dbg? haiku_dbg_get (dbg): NULL;
	if (!hdbg) {
		return false;
	}
	if (set) {
		debug_nub_set_breakpoint msg = {
			.reply_port = hdbg->reply_port,
			.address = (void *)(size_t)b->addr
		};
		debug_nub_set_breakpoint_reply reply;
		return r_haiku_send_msg (hdbg, B_DEBUG_MESSAGE_SET_BREAKPOINT,
			&msg, sizeof (msg), &reply, sizeof (reply)) == B_OK && reply.error == B_OK;
	}
	debug_nub_clear_breakpoint msg = {
		.address = (void *)(size_t)b->addr
	};
	return write_port (hdbg->nub_port, B_DEBUG_MESSAGE_CLEAR_BREAKPOINT, &msg, sizeof (msg)) == B_OK;
}

#endif // __HAIKU__
