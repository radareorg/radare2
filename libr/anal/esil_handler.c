#include <r_anal.h>
#include <r_util.h>
#include <sdb.h>

static bool _set_interrupt(RAnalEsil *esil, RAnalEsilHandler *intr, ut32 intr_num) {
	return intr_num ? dict_set (esil->interrupts, intr_num, intr_num, intr) : (esil->intr0 = intr, true);
}

static bool _set_syscall(RAnalEsil *esil, RAnalEsilHandler *sysc, ut32 sysc_num) {
	return sysc_num ? dict_set (esil->syscalls, sysc_num, sysc_num, sysc) : (esil->sysc0 = sysc, true);
}

static RAnalEsilHandler *_get_interrupt(RAnalEsil *esil, ut32 intr_num) {
	return intr_num ? (RAnalEsilHandler *)dict_getu (esil->interrupts, intr_num) : esil->intr0;
}

static RAnalEsilHandler *_get_syscall(RAnalEsil *esil, ut32 sysc_num) {
	return sysc_num ? (RAnalEsilHandler *)dict_getu (esil->syscalls, sysc_num) : esil->sysc0;
}

R_API void r_anal_esil_handlers_init(RAnalEsil *esil) {
	r_return_if_fail (esil);
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
R_API RAnalEsilHandler *r_anal_esil_handler_new(RAnalEsilHandlerCB cb, void *user) {
	r_return_val_if_fail (cb, NULL);
	RAnalEsilHandler *h = R_NEW0 (RAnalEsilHandler);
	if (!h) {
		return NULL;
	}
	h->cb = cb;
	h->user = user;
	return h;
}

R_API bool r_anal_esil_set_interrupt(RAnalEsil *esil, ut32 intr_num, RAnalEsilHandlerCB cb, void *user) {
	r_return_val_if_fail (esil && esil->interrupts && cb, false);
	RAnalEsilHandler *intr = r_anal_esil_handler_new (cb, user);
	if (!intr) {
		return false;
	}
	// free potentially existing handler
	free (_get_interrupt (esil, intr_num));
	// set the new interrupt
	return _set_interrupt (esil, intr, intr_num);
}

R_API bool r_anal_esil_set_syscall(RAnalEsil *esil, ut32 sysc_num, RAnalEsilHandlerCB cb, void *user) {
	r_return_val_if_fail (esil && esil->syscalls && cb, false);
	RAnalEsilHandler *sysc = r_anal_esil_handler_new (cb, user);
	if (!sysc) {
		return false;
	}
	// free potentially existing handler
	free (_get_syscall (esil, sysc_num));
	// set the new interrupt
	return _set_syscall (esil, sysc, sysc_num);
}

R_API int r_anal_esil_fire_interrupt(RAnalEsil *esil, ut32 intr_num) {
	r_return_val_if_fail (esil, false);

	if (esil->cmd && esil->cmd (esil, esil->cmd_intr, intr_num, 0)) { //compatibility
		return true;
	}

	if (!esil->interrupts) {
		eprintf ("no interrupts initialized\n");
		return false;
	}
	RAnalEsilHandler *intr = _get_interrupt (esil, intr_num);
	return (intr && intr->cb) ? intr->cb (esil, intr_num, intr->user) : false;
}

R_API int r_anal_esil_do_syscall(RAnalEsil *esil, ut32 sysc_num) {
	r_return_val_if_fail (esil, false);

	if (!esil->syscalls) {
		eprintf ("no syscalls initialized\n");
		return false;
	}
	RAnalEsilHandler *sysc = _get_syscall (esil, sysc_num);
	return (sysc && sysc->cb) ? sysc->cb (esil, sysc_num, sysc->user) : false;
}

R_API void r_anal_esil_handlers_fini(RAnalEsil *esil) {
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
