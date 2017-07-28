/* radare - LGPL - Copyright 2017 - rkx1209 */
#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

R_API void r_anal_esil_session_free(RAnalEsilSession *session) {
	free (session->data);
	free (session);
}

R_API void r_anal_esil_session_list(RAnalEsil *esil) {
	if (!esil || !esil->sessions) {
		return;
	}
	eprintf ("%d\n", r_list_length (esil->sessions));
}

R_API RAnalEsilSession *r_anal_esil_session_add(RAnalEsil *esil) {
	RAnalEsilSession *session;
	ut32 i;
	if (!esil) {
		return NULL;
	}
	session = R_NEW0 (RAnalEsilSession);
	if (!session) {
		return NULL;
	}
	if (!esil->stack_addr) {
		R_FREE (session);
		return NULL;
	}

	session->addr = esil->stack_addr;
	session->size = esil->stack_size;
	session->data = R_NEWS0 (ut8 *, session->size);
	/* Save current register */
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		session->reg[i] = r_list_tail (esil->anal->reg->regset[i].pool);
	}
	r_reg_arena_push (esil->anal->reg);

	/* Save current memory dump */
	esil->anal->iob.read_at (esil->anal->iob.io, session->addr, session->data, session->size);

	r_list_append (esil->sessions, session);
	return session;
}

R_API void r_anal_esil_session_set(RAnalEsil *esil, RAnalEsilSession *session) {
	if (!esil || !session) {
		return;
	}
	ut32 i;
	RListIter *iter;
	RRegArena *arena;
	/* Restore registers */
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		iter = session->reg[i];
		arena = iter->data;
		if (esil->anal->reg->regset[i].arena->bytes) {
			memcpy (esil->anal->reg->regset[i].arena->bytes, arena->bytes, arena->size);
		}
	}

	/* Restore memory dump */
	esil->anal->iob.write_at (esil->anal->iob.io, session->addr, session->data, session->size);
}
