#include <r_anal.h>
#include <r_util.h>
#include <r_lib.h>
#include <sdb.h>

static void _interrupt_free_cb(void *user) {
	RAnalEsilInterrupt *intr = (RAnalEsilInterrupt *)user;
	if (intr && intr->handler && intr->handler->fini) {
		intr->handler->fini (intr->user);
	}
	free (intr);
}

R_API void r_anal_esil_interrupts_init(RAnalEsil *esil) {
	if (!esil) {
		return;
	}
	esil->interrupts = dict_new (sizeof(ut32), NULL);
}

R_API RAnalEsilInterrupt *r_anal_esil_interrupt_new(RAnalEsil *esil, ut32 src_id,  RAnalEsilInterruptHandler *ih) {
	RAnalEsilInterrupt *intr;

	if (!esil || !ih || !ih->cb) {
		return NULL;
	}

	intr = R_NEW0(RAnalEsilInterrupt);
	if (!intr) {
		return NULL;
	}

	intr->handler = ih;
	if (ih->init && ih->fini) {
		intr->user = ih->init(esil);
	}
	intr->src_id = src_id;
	r_anal_esil_claim_source (esil, src_id);
	return intr;
}

R_API void r_anal_esil_interrupt_free(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	if (intr && esil) {
		dict_del (esil->interrupts, intr->handler->num);
	}
	if (intr) {
		if (intr->user) {
			intr->handler->fini(intr->user);	//fini must exist when user is !NULL
		}
		r_anal_esil_release_source (esil, intr->src_id);
	}
	free(intr);
}

R_API bool r_anal_esil_set_interrupt(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	RAnalEsilInterrupt *o_intr;

	if (!esil || !esil->interrupts || !intr || !intr->handler || !intr->handler->cb) {
		return false;
	}

// check if interrupt is already set
	o_intr = (RAnalEsilInterrupt *)dict_getu(esil->interrupts, intr->handler->num);
	if (o_intr) {
		r_anal_esil_interrupt_free(esil, o_intr);
	}

//set the new interrupt
	return dict_set(esil->interrupts, intr->handler->num, intr->handler->num, intr);
}

R_API int r_anal_esil_fire_interrupt(RAnalEsil *esil, ut32 intr_num) {
	if (!esil) {
		return false;
	}

	if (esil->cmd && esil->cmd (esil, esil->cmd_intr, intr_num, 0)) {	//compatibility
		return true;
	}

	if (!esil->interrupts) {
		eprintf ("no interrupts initialized\n");
		return false;
	}
	RAnalEsilInterrupt *intr = (RAnalEsilInterrupt *)dict_getu(esil->interrupts, intr_num);
	if (!intr) {
		eprintf ("no handler registered for 0x%x\n", intr_num);
	}
	return (intr && intr->handler && intr->handler->cb) ?
			intr->handler->cb (esil, intr_num, intr->user) : false;
}

R_API bool r_anal_esil_load_interrupts (RAnalEsil *esil, RAnalEsilInterruptHandler *handlers[], ut32 src_id) {
	RAnalEsilInterrupt *intr;
	ut32 i = 0;

	if (!esil || !esil->interrupts || !handlers) {
		return false;
	}

	while (handlers[i]) {
		intr = (RAnalEsilInterrupt *)dict_getu(esil->interrupts, handlers[i]->num);
		if (intr) {
			//first free, then load the new handler or stuff might break in the handlers
			r_anal_esil_interrupt_free (esil, intr);
		}
		intr = r_anal_esil_interrupt_new (esil, src_id, handlers[i]);
		if (intr) {
			r_anal_esil_set_interrupt (esil, intr);
		} else {
			return false;
		}
		i++;
	}

	return true;
}

R_API bool r_anal_esil_load_interrupts_from_lib(RAnalEsil *esil, const char *path) {
	RAnalEsilInterruptHandler **handlers;
	ut32 src_id = r_anal_esil_load_source (esil, path);

	if (!src_id) {
		return false;
	}

	handlers = (RAnalEsilInterruptHandler **)r_lib_dl_sym (r_anal_esil_get_source (esil, src_id), "interrupts");
	if (!handlers) {
		r_anal_esil_release_source(esil, src_id);	//unload
		return false;
	}
	return r_anal_esil_load_interrupts (esil, handlers, src_id);
}

R_API void r_anal_esil_interrupts_fini(RAnalEsil *esil) {
	if (esil && esil->interrupts) {
		esil->interrupts->f = _interrupt_free_cb;
		dict_free (esil->interrupts);
		esil->interrupts = NULL;
	}
}
