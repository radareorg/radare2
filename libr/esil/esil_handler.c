/* radare - LGPL - Copyright 2014-2023 - pancake, condret */

// TODO: esil_handler.c -> esil_syscall ? set_interrupts ? set_syscalls?
#define R_LOG_ORIGIN "esil.syscall"

#include <r_esil.h>

static bool _set_interrupt(REsil *esil, REsilHandler *intr, ut32 intr_num) {
	return intr_num ? dict_set (esil->interrupts, intr_num, intr_num, intr) : (esil->intr0 = intr, true);
}

static bool _set_syscall(REsil *esil, REsilHandler *sysc, ut32 sysc_num) {
	return sysc_num ? dict_set (esil->syscalls, sysc_num, sysc_num, sysc) : (esil->sysc0 = sysc, true);
}

static REsilHandler *_get_interrupt(REsil *esil, ut32 intr_num) {
	return intr_num ? (REsilHandler *)dict_getu (esil->interrupts, intr_num) : esil->intr0;
}

static REsilHandler *_get_syscall(REsil *esil, ut32 sysc_num) {
	return sysc_num ? (REsilHandler *)dict_getu (esil->syscalls, sysc_num) : esil->sysc0;
}

R_API void r_esil_handlers_init(REsil *esil) {
	R_RETURN_IF_FAIL (esil);
	esil->interrupts = dict_new (sizeof (ut32), free);
	if (!esil->interrupts) {
		return;
	}
	esil->syscalls = dict_new (sizeof (ut32), free);
	if (!esil->syscalls) {
		dict_free (esil->interrupts);
		return;
	}
	esil->intr0 = NULL;
	esil->sysc0 = NULL;
}

// does this need to be an API function?
R_API REsilHandler *r_esil_handler_new(REsilHandlerCB cb, void *user) {
	R_RETURN_VAL_IF_FAIL (cb, NULL);
	REsilHandler *h = R_NEW0 (REsilHandler);
	if (!h) {
		return NULL;
	}
	h->cb = cb;
	h->user = user;
	return h;
}

R_API bool r_esil_set_interrupt(REsil *esil, ut32 intr_num, REsilHandlerCB cb, void *user) {
	R_RETURN_VAL_IF_FAIL (esil && esil->interrupts && cb, false);
	REsilHandler *intr = r_esil_handler_new (cb, user);
	if (!intr) {
		return false;
	}
	// free potentially existing handler
	free (_get_interrupt (esil, intr_num));
	// set the new interrupt
	return _set_interrupt (esil, intr, intr_num);
}

R_API REsilHandlerCB r_esil_get_interrupt(REsil *esil, ut32 intr_num) {
	R_RETURN_VAL_IF_FAIL (esil && esil->interrupts, NULL);
	REsilHandler *handler = _get_interrupt (esil, intr_num);
	return handler ? handler->cb : NULL;
}

R_API void r_esil_del_interrupt(REsil *esil, ut32 intr_num) {
	R_RETURN_IF_FAIL (esil && esil->interrupts);
	if (intr_num == 0) {
		R_FREE (esil->intr0)
	} else {
		dict_del (esil->interrupts, intr_num);
	}
}

R_API bool r_esil_set_syscall(REsil *esil, ut32 sysc_num, REsilHandlerCB cb, void *user) {
	R_RETURN_VAL_IF_FAIL (esil && esil->syscalls && cb, false);
	REsilHandler *sysc = r_esil_handler_new (cb, user);
	if (!sysc) {
		return false;
	}
	// free potentially existing handler
	free (_get_syscall (esil, sysc_num));
	// set the new interrupt
	return _set_syscall (esil, sysc, sysc_num);
}

R_API REsilHandlerCB r_esil_get_syscall(REsil *esil, ut32 sysc_num) {
	R_RETURN_VAL_IF_FAIL (esil && esil->syscalls, NULL);
	REsilHandler *handler = _get_syscall (esil, sysc_num);
	return handler ? handler->cb : NULL;
}

R_API void r_esil_del_syscall(REsil *esil, ut32 sysc_num) {
	R_RETURN_IF_FAIL (esil && esil->syscalls);
	if (sysc_num == 0) {
		R_FREE (esil->sysc0)
	} else {
		dict_del (esil->syscalls, sysc_num);
	}
}

R_API int r_esil_fire_interrupt(REsil *esil, ut32 intr_num) {
	R_RETURN_VAL_IF_FAIL (esil, false);

	if (esil->cmd && esil->cmd (esil, esil->cmd_intr, intr_num, 0)) { //compatibility
		return true;
	}

	if (!esil->interrupts) {
		eprintf ("no interrupts initialized\n");
		return false;
	}
	REsilHandler *intr = _get_interrupt (esil, intr_num);
	return (intr && intr->cb) ? intr->cb (esil, intr_num, intr->user) : false;
}

R_API int r_esil_do_syscall(REsil *esil, ut32 sysc_num) {
	R_RETURN_VAL_IF_FAIL (esil, false);

	if (!esil->syscalls) {
		eprintf ("no syscalls initialized\n");
		return false;
	}
	REsilHandler *sysc = _get_syscall (esil, sysc_num);
	return (sysc && sysc->cb) ? sysc->cb (esil, sysc_num, sysc->user) : false;
}

R_API void r_esil_handlers_fini(REsil *esil) {
	if (esil) {
		if (esil->interrupts) {
			R_FREE (esil->intr0);
			dict_free (esil->interrupts);
			esil->interrupts = NULL;
		}
		if (esil->syscalls) {
			R_FREE (esil->sysc0);
			dict_free (esil->syscalls);
			esil->syscalls = NULL;
		}
	}
}
