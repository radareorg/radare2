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

static bool _set_interrupt(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	return intr->handler->num ?
		dict_set (esil->interrupts, intr->handler->num, intr->handler->num, intr) :
		(esil->intr0 = intr, true);
}

static RAnalEsilInterrupt *_get_interrupt(RAnalEsil *esil, ut32 intr_num) {
	return intr_num ?
		(RAnalEsilInterrupt *)dict_getu(esil->interrupts, intr_num) :
		esil->intr0;
}

static void _del_interrupt(RAnalEsil *esil, ut32 intr_num) {
	if (intr_num) {
		dict_del (esil->interrupts, intr_num);
	} else {
		esil->intr0 = NULL;
	}
}

R_API void r_anal_esil_interrupts_init(RAnalEsil *esil) {
	r_return_if_fail (esil);
	esil->interrupts = dict_new (sizeof (ut32), NULL);
	esil->intr0 = NULL; // is this needed?
}

R_API RAnalEsilInterrupt *r_anal_esil_interrupt_new(RAnalEsil *esil, ut32 src_id,  RAnalEsilInterruptHandler *ih) {
	r_return_val_if_fail (esil && ih && ih->cb, NULL);
	RAnalEsilInterrupt *intr = R_NEW0 (RAnalEsilInterrupt);
	if (!intr) {
		return NULL;
	}
	intr->handler = ih;
	if (ih->init && ih->fini) {
		intr->user = ih->init (esil);
	}
	intr->src_id = src_id;
	r_anal_esil_claim_source (esil, src_id);
	return intr;
}

R_API void r_anal_esil_interrupt_free(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	if (intr && esil) {
		_del_interrupt (esil, intr->handler->num);
	}
	if (intr) {
		if (intr->user) {
			intr->handler->fini (intr->user);	//fini must exist when user is !NULL
		}
		r_anal_esil_release_source (esil, intr->src_id);
	}
	free (intr);
}

R_API bool r_anal_esil_set_interrupt(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	r_return_val_if_fail (esil && esil->interrupts && intr && intr->handler && intr->handler->cb, false);
	// check if interrupt is already set
	RAnalEsilInterrupt *o_intr = _get_interrupt(esil, intr->handler->num);
	if (o_intr) {
		r_anal_esil_interrupt_free (esil, o_intr);
	}
	//set the new interrupt
	return _set_interrupt(esil, intr);
}

R_API int r_anal_esil_fire_interrupt(RAnalEsil *esil, ut32 intr_num) {
	r_return_val_if_fail (esil, false);

	if (esil->cmd && esil->cmd (esil, esil->cmd_intr, intr_num, 0)) {	//compatibility
		return true;
	}

	if (!esil->interrupts) {
		eprintf ("no interrupts initialized\n");
		return false;
	}
	RAnalEsilInterrupt *intr = _get_interrupt (esil, intr_num);
#if 0
	// we don't want this warning
	if (!intr) {
		eprintf ("Warning no interrupt handler registered for 0x%x\n", intr_num);
	}
#endif
	return (intr && intr->handler && intr->handler->cb) ?
			intr->handler->cb (esil, intr_num, intr->user) : false;
}

R_API bool r_anal_esil_load_interrupts (RAnalEsil *esil, RAnalEsilInterruptHandler *handlers[], ut32 src_id) {
	RAnalEsilInterrupt *intr;
	ut32 i = 0;

	r_return_val_if_fail (esil && esil->interrupts && handlers, false);

	while (handlers[i]) {
		intr = _get_interrupt (esil, handlers[i]->num);
		if (intr) {
			//first free, then load the new handler or stuff might break in the handlers
			r_anal_esil_interrupt_free (esil, intr);
		}
		intr = r_anal_esil_interrupt_new (esil, src_id, handlers[i]);
		if (!intr) {
			return false;
		}
		r_anal_esil_set_interrupt (esil, intr);
		i++;
	}

	return true;
}

R_API bool r_anal_esil_load_interrupts_from_lib(RAnalEsil *esil, const char *path) {
	r_return_val_if_fail (esil, false);
	ut32 src_id = r_anal_esil_load_source (esil, path);
	if (!src_id) { // why id=0 is invalid?
		return false;
	}
	RAnalEsilInterruptHandler **handlers = (RAnalEsilInterruptHandler **)\
		r_lib_dl_sym (r_anal_esil_get_source (esil, src_id), "interrupts");
	if (!handlers) {
		r_anal_esil_release_source (esil, src_id); //unload
		return false;
	}
	return r_anal_esil_load_interrupts (esil, handlers, src_id);
}

R_API void r_anal_esil_interrupts_fini(RAnalEsil *esil) {
	if (esil && esil->interrupts) {
		_interrupt_free_cb (esil->intr0);
		esil->intr0 = NULL;
		esil->interrupts->f = _interrupt_free_cb;
		dict_free (esil->interrupts);
		esil->interrupts = NULL;
	}
}
