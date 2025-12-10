/* 2017 - montekki - LGPL3 */

#include <r_debug.h>

typedef struct {
	size_t curr_instruction;

	ut64 *breakpoints;
	size_t breakpoints_capacity;
	size_t breakpoints_length;

} RIOEvmState;

typedef struct {
	ut8 depth;
	ut8 error;
	unsigned pc;
	unsigned gas;
	unsigned gas_cost;

	ut8 *memory;
	size_t memlength;

	ut8 *stack;
	size_t stack_length;
	char *op;
} RIOEvmOp;

typedef struct {
	void *curl;
	char *host;
	int port;
	char *tx;
	char *tx_full;
	char *tx_to;
	char *tx_from;
	char *to_code_resp;
	char *to_code;

	ut8 *code;
	size_t code_size;

	// char *response;
	// size_t curr_resp_size;

	RIOEvmOp *ops;
	size_t ops_size;

	size_t curr_op;
} RIOEvm;

// XXX remove those globals
static R_TH_LOCAL RIOEvm *rio = NULL;
static R_TH_LOCAL RIOEvmState *rios = NULL;

static bool r_debug_evm_step(RDebug *dbg) {
	if (!rio->ops_size || rios->curr_instruction >= rio->ops_size) {
		return false;
	}
	rios->curr_instruction++;
	rio->curr_op = rios->curr_instruction;
	return true;
}

static RList* r_debug_evm_threads(RDebug *dbg, int pid) {
	return NULL;
}

static bool r_debug_evm_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	if (!rios || !rio || !rio->ops_size) {
		return false;
	}
	((ut16*)(buf))[0] = (ut16)rio->ops[rios->curr_instruction].pc;
	((ut16*)(buf))[1] = (ut16)0x8fff;
	return true;
}

static RList *r_debug_evm_map_get(RDebug *dbg) {
	if (rio && !rio->ops_size) {
		return NULL;
	}

	RList *list = r_list_new();
	RDebugMap *map;

	map = r_debug_map_new ("code", 0x0000, 0x7FFF, r_str_rwx("rwx"), 0);
	r_list_append (list, map);

	map = r_debug_map_new ("stack", 0x8FFF, 0xFFFF, r_str_rwx("rwx"), 0);
	r_list_append (list, map);

	map = r_debug_map_new ("memory", 0x10000, 0x1FFFF, r_str_rwx("rwx"), 0);
	r_list_append (list, map);

	return list;
}

static bool r_debug_evm_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	return false;
}

static st64 find_breakpoint(ut64 addr, ut64 *addrs, size_t addrs_len);

static bool r_debug_evm_continue(RDebug *dbg, int pid, int tid, int sig) {
	if (!rio->ops_size) {
		return false;
	}

	st64 bpt_addr = find_breakpoint (rio->ops[rios->curr_instruction].pc,
			rios->breakpoints, rios->breakpoints_length);

	if (bpt_addr >= 0 && rio->ops[rios->curr_instruction].pc == rios->breakpoints[bpt_addr]) {
		rios->curr_instruction++;
	}

	size_t i;
	for (i = rios->curr_instruction; i < rio->ops_size; i++) {
		bpt_addr = find_breakpoint (rio->ops[i].pc, rios->breakpoints, rios->breakpoints_length);
		if (bpt_addr >= 0) {
			rios->curr_instruction = i;
			rio->curr_op = rios->curr_instruction;
			return true;
		}
	}

	return true;
}

static RDebugReasonType r_debug_evm_wait(RDebug *dbg, int pid) {
	return R_DEBUG_REASON_UNKNOWN;
}

#define DEFAULT_BPT_AR_CAPACITY		64

static bool r_debug_evm_attach(RDebug *dbg, int pid) {
	RIODesc *d = dbg->iob.io->desc;
	if (!rios) {
		rios = R_NEW0 (RIOEvmState);
		rios->breakpoints = (ut64 *)calloc (sizeof (ut64), DEFAULT_BPT_AR_CAPACITY);
		rios->breakpoints_length = 0;
		rios->breakpoints_capacity = DEFAULT_BPT_AR_CAPACITY;
	}

	if (d && d->plugin && d->plugin->meta.name && d->data) {
		if (!strcmp ("evm", d->plugin->meta.name)) {
			rio = d->data;
		}
	}

	return true;
}

static bool r_debug_evm_detach(RDebug *dbg, int pid) {
	return true;
}

static const char *r_debug_evm_reg_profile(RDebug *dbg, int pid) {
	return strdup (
			"=PC	pc\n"
			"=SP    sp\n"
			"gpr	pc .16 0 0\n"
			"gpr    sp .16 2 0\n"
		      );
}

static st64 find_breakpoint(ut64 addr, ut64 *addrs, size_t addrs_len) {
	if (addrs_len <= 0) {
		return -1;
	}
	st64 middle = addrs_len / 2;

	if (addrs[middle] == addr) {
		return middle;
	}
	if (addrs[middle] < addr) {
		return find_breakpoint (addr, addrs + middle + 1, addrs_len - middle - 1);
	}
	return find_breakpoint (addr, addrs, middle);
}

static int compare_addrs(const void *a1, const void *a2) {
	return *(ut64*)a1 - *(ut64*)a2;
}

static int r_debug_evm_breakpoint (struct r_bp_t *bp, RBreakpointItem *b, bool set) {
	if (!b || !rio->ops_size) {
		return false;
	}

	if (set) {
		st64 idx = find_breakpoint (b->addr, rios->breakpoints, rios->breakpoints_length);
		if (idx >= 0) {
			return true;
		}
		if (rios->breakpoints_length >= rios->breakpoints_capacity) {
			rios->breakpoints = realloc (rios->breakpoints, rios->breakpoints_capacity + 64);
			rios->breakpoints_capacity += 64;
		}
		rios->breakpoints[rios->breakpoints_length] = b->addr;
		rios->breakpoints_length++;
		qsort (rios->breakpoints, rios->breakpoints_length, sizeof (ut64), compare_addrs);
	} else {
		size_t i;
		st64 idx = find_breakpoint (b->addr, rios->breakpoints, rios->breakpoints_length);
		if (idx < 0) {
			return false;
		}
		for (i = idx; i < rios->breakpoints_length - 1; i++) {
			rios->breakpoints[i] = rios->breakpoints[i + 1];
		}
		rios->breakpoints_length -= 1;
	}

	return true;
}

static bool r_debug_evm_kill(RDebug *dbg, int pid, int tid, int sig) {
	return true;
}

static bool r_debug_evm_select(RDebug *dbg, int pid, int tid) {
	return true;
}

static RDebugInfo* r_debug_evm_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	// meh
	return rdi;
}

static RList* r_debug_evm_frames(RDebug *dbg, ut64 at) {
	return NULL;
}

RDebugPlugin r_debug_plugin_evm = {
	.meta = {
		.name = "evm",
		.license = "LGPL-3.0-only",
		.author = "montekki",
		.desc = "evm debugger backend",
	},
	.arch = "evm",
	.bits = R_SYS_BITS_PACK2 (8, 16),
	.step = r_debug_evm_step,
	.cont = r_debug_evm_continue,
	.attach = &r_debug_evm_attach,
	.detach = &r_debug_evm_detach,
	.threads = &r_debug_evm_threads,
	.canstep = 1,
	.wait = &r_debug_evm_wait,
	.map_get = r_debug_evm_map_get,
	.breakpoint = r_debug_evm_breakpoint,
	.reg_read = r_debug_evm_reg_read,
	.reg_write = r_debug_evm_reg_write,
	.reg_profile = (void *)r_debug_evm_reg_profile,
	.kill = &r_debug_evm_kill,
	.info = &r_debug_evm_info,
	.select = &r_debug_evm_select,
	.frames = &r_debug_evm_frames,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_evm,
	.version = R2_VERSION
};
#endif
