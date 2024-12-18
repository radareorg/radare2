#include <r_arch.h>
#include <r_anal.h>
#include <r_esil.h>
#include <r_reg.h>

static void htup_vector_free(HtUPKv *kv) {
	if (kv) {
		r_vector_free (kv->value);
	}
}

static void trace_db_init(RAnalEsilTraceDB *db) {
	RVecAnalEsilTraceOp_init (&db->ops);
	RVecAnalEsilAccess_init (&db->accesses);
	db->loop_counts = ht_uu_new0 ();
}

R_API bool r_anal_esil_trace_init(RAnalEsilTrace *trace, REsil *esil, RReg *reg,
	ut64 stack_addr, ut64 stack_size) {
	R_RETURN_VAL_IF_FAIL (trace && esil && reg && stack_size, false);
	*trace = (const RAnalEsilTrace){0};
	trace_db_init (&trace->db);
	trace->registers = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->registers) {
		goto fail_registers_ht;
	}
	trace->memory = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->memory) {
		goto fail_memory_ht;
	}
	trace->stack_data = malloc (stack_size);
	if (!trace->stack_data) {
		goto fail_malloc;
	}
	if (!r_esil_mem_read_silent (esil, stack_addr, trace->stack_data, stack_size)) {
		goto fail_read;
	}
	ut32 i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = reg->regset[i].arena;
		RRegArena *b = r_reg_arena_new (a->size);
		if (!b) {
			goto fail_regs_copy;
		}
		if (b->bytes && a->bytes && b->size > 0) {
			memcpy (b->bytes, a->bytes, b->size);
		}
		trace->arena[i] = b;
	}
	trace->stack_addr = stack_addr;
	trace->stack_size = stack_size;
	return true;
fail_regs_copy:
	while (i) {
		i--;
		r_reg_arena_free (trace->arena[i]);
	}
fail_read:
	R_FREE (trace->stack_data);
fail_malloc:
	ht_up_free (trace->memory);
	trace->memory = NULL;
fail_memory_ht:
	ht_up_free (trace->registers);
	trace->registers = NULL;
fail_registers_ht:
	return false;
}
