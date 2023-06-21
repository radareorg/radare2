/* radare - LGPL - Copyright 2023 - pancake */

typedef struct {
	ut64 addr;
	bool write;
	const char *reg;
	ut64 value;
	int size;
} RTraceAccessRegister;

typedef struct {
	bool write;
	ut64 addr;
	const ut8 *buf;
	size_t buflen;
} RTraceAccessMemory;

typedef struct {
	bool ismem;
	union {
		RDebugTraceAccessMemory mem;
		RDebugTraceAccessRegister reg;
	}
} RTraceAccess;

typedef struct r_trace_t {
	RList *traces; // can be an RVec
	int count;
	int enabled;
	int tag;
	int dup;
	char *addresses;
	HtPP *ht; // use rbtree like the iocache?
} RTrace;


// R2_590 rename to traceitem for consistency?
#define r_debug_tracepoint_free(x) free((x))
typedef struct r_trace_item_t {
	ut64 addr;
	ut64 tags; // XXX
	int tag; // XXX
	int size;
	int count; // rename to index
	int times; // rename to count :jiji:
	ut64 stamp;
	RVecAccess access;
#if 0
	
	ut64 refaddr;
	int direction
#endif
} RTraceItem;

R_GENERATE_VEC_IMPL_FOR(Access, RTraceAccess);

#if 0
RVecTraces v;
RVecTraces_init (&v);
RDebugTraceAccess t = {
	.ismem = true,
	.mem = {
		.write = true,
		.addr = 0x80000,
		.buf = "hell",
		.buflen = 4,
	}
};
RVecTraces_push_back (&v &t);
#endif
