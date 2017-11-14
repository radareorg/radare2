/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

R_API void r_anal_esil_session_free(void *p) {
	RAnalEsilSession *session = (RAnalEsilSession *) p;
	free (session->data);
	free (session);
}

R_API void r_anal_esil_session_list(RAnalEsil *esil) {
	if (!esil || !esil->sessions) {
		return;
	}
	RListIter *iter;
	RAnalEsilSession *session;
	ut64 idx = 0;
	r_list_foreach (esil->sessions, iter, session) {
		esil->anal->cb_printf ("[%d] 0x%08"PFMT64x "\n", idx++, session->key);
	}
}

R_API RAnalEsilSession *r_anal_esil_session_add(RAnalEsil *esil) {
	if (!esil || !esil->stack_addr || !esil->stack_size) {
		eprintf ("r_anal_esil_session_add: Cannot find any stack, use 'aeim' first.\n");
		return NULL;
	}
	const char *name = r_reg_get_name (esil->anal->reg, R_REG_NAME_PC);
	if (!name) {
		eprintf ("Cannot get alias name for the program counter register. Wrong register profile?\n");
		return NULL;
	}
	RAnalEsilSession *session = R_NEW0 (RAnalEsilSession);
	if (!session) {
		return NULL;
	}
	session->key = r_reg_getv (esil->anal->reg, name);
	session->addr = esil->stack_addr;
	session->size = esil->stack_size;
	session->data = (ut8 *) R_NEWS0 (ut8, session->size);
	if (!session->data) {
		eprintf ("Cannot allocate 0x%"PFMT64x" bytes for stack\n", session->size);
		R_FREE (session);
		return NULL;
	}
	/* Save current register */
	ut32 i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		session->reg[i] = r_list_tail (esil->anal->reg->regset[i].pool);
	}
	r_reg_arena_push (esil->anal->reg);

	/* Save current memory dump */
	esil->anal->iob.read_at (esil->anal->iob.io, session->addr,
		session->data, session->size);

	r_list_append (esil->sessions, session);
	return session;
}

R_API void r_anal_esil_session_set(RAnalEsil *esil, RAnalEsilSession *session) {
	if (!esil || !session) {
		return;
	}
	ut32 i;
	/* Restore registers */
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RListIter *iter = session->reg[i];
		RRegArena *arena = iter->data;
		if (esil->anal->reg->regset[i].arena->bytes) {
			if (esil->anal->reg->regset[i].arena->size >= arena->size) {
				memcpy (esil->anal->reg->regset[i].arena->bytes,
					arena->bytes, arena->size);
			}
		}
	}

	/* Restore memory dump */
	esil->anal->iob.write_at (esil->anal->iob.io, session->addr, session->data, session->size);
}
