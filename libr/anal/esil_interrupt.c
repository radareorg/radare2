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
	return intr->handler->num ? dict_set (esil->interrupts, intr->handler->num, intr->handler->num, intr) : (esil->intr0 = intr, true);
}

static bool _set_syscall(RAnalEsil *esil, RAnalEsilSyscall *sysc) {
	return sysc->handler->num ? dict_set (esil->syscalls, sysc->handler->num, sysc->handler->num, sysc) : (esil->sysc0 = sysc, true);
}

static RAnalEsilInterrupt *_get_interrupt(RAnalEsil *esil, ut32 intr_num) {
	return intr_num ? (RAnalEsilInterrupt *)dict_getu (esil->interrupts, intr_num) : esil->intr0;
}

static RAnalEsilSyscall *_get_syscall(RAnalEsil *esil, ut32 sysc_num) {
	return sysc_num ? (RAnalEsilSyscall *)dict_getu (esil->syscalls, sysc_num) : esil->sysc0;
}

static void _del_interrupt(RAnalEsil *esil, ut32 intr_num) {
	if (intr_num) {
		dict_del (esil->interrupts, intr_num);
	} else {
		esil->intr0 = NULL;
	}
}

static void _del_syscall(RAnalEsil *esil, ut32 sysc_num) {
	if (sysc_num) {
		dict_del (esil->syscalls, sysc_num);
	} else {
		esil->sysc0 = NULL;
	}
}

R_API void r_anal_esil_handlers_init(RAnalEsil *esil) {
	r_return_if_fail (esil);
	esil->interrupts = dict_new (sizeof (ut32), NULL);
	if (!esil->interrupts) {
		return;
	}
	esil->syscalls = dict_new (sizeof (ut32), NULL);
	if (!esil->syscalls) {
		dict_free (esil->interrupts);
		return;
	}
	esil->intr0 = NULL;
	esil->sysc0 = NULL;
}

R_API RAnalEsilInterrupt *r_anal_esil_interrupt_new(RAnalEsil *esil, ut32 src_id, RAnalEsilHandler *ih) {
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

R_API RAnalEsilSyscall *r_anal_esil_syscall_new(RAnalEsil *esil, ut32 src_id, RAnalEsilHandler *sh) {
	return r_anal_esil_interrupt_new (esil, src_id, sh);
}

R_API void r_anal_esil_interrupt_free(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	if (intr && esil) {
		_del_interrupt (esil, intr->handler->num);
	}
	if (intr) {
		if (intr->user) {
			intr->handler->fini (intr->user); //fini must exist when user is !NULL
		}
		r_anal_esil_release_source (esil, intr->src_id);
	}
	free (intr);
}

R_API void r_anal_esil_syscall_free(RAnalEsil *esil, RAnalEsilSyscall *sysc) {
	if (sysc && esil) {
		_del_syscall (esil, sysc->handler->num);
	}
	if (sysc) {
		if (sysc->user) {
			sysc->handler->fini (sysc->user); //fini must exist when user is !NULL
		}
		r_anal_esil_release_source (esil, sysc->src_id);
	}
	free (sysc);
}

R_API bool r_anal_esil_set_interrupt(RAnalEsil *esil, RAnalEsilInterrupt *intr) {
	r_return_val_if_fail (esil && esil->interrupts && intr && intr->handler && intr->handler->cb, false);
	// check if interrupt is already set
	RAnalEsilInterrupt *o_intr = _get_interrupt (esil, intr->handler->num);
	if (o_intr) {
		r_anal_esil_interrupt_free (esil, o_intr);
	}
	//set the new interrupt
	return _set_interrupt (esil, intr);
}

R_API bool r_anal_esil_set_syscall(RAnalEsil *esil, RAnalEsilSyscall *sysc) {
	r_return_val_if_fail (esil && esil->syscalls && sysc && sysc->handler && sysc->handler->cb, false);
	// check if interrupt is already set
	RAnalEsilSyscall *o_sysc = _get_syscall (esil, sysc->handler->num);
	if (o_sysc) {
		r_anal_esil_syscall_free (esil, o_sysc);
	}
	//set the new interrupt
	return _set_syscall (esil, sysc);
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
	RAnalEsilInterrupt *intr = _get_interrupt (esil, intr_num);
#if 0
	// we don't want this warning
	if (!intr) {
		eprintf ("Warning no interrupt handler registered for 0x%x\n", intr_num);
	}
#endif
	return (intr && intr->handler && intr->handler->cb) ? intr->handler->cb (esil, intr_num, intr->user) : false;
}

R_API int r_anal_esil_do_syscall(RAnalEsil *esil, ut32 sysc_num) {
	r_return_val_if_fail (esil, false);

	if (!esil->syscalls) {
		eprintf ("no syscalls initialized\n");
		return false;
	}
	RAnalEsilSyscall *sysc = _get_syscall (esil, sysc_num);

	return (sysc && sysc->handler && sysc->handler->cb) ? sysc->handler->cb (esil, sysc_num, sysc->user) : false;
}

R_API bool r_anal_esil_load_interrupts(RAnalEsil *esil, RAnalEsilHandler *handlers[], ut32 src_id) {
	r_return_val_if_fail (esil && esil->interrupts && handlers, false);

	ut32 i = 0;
	while (handlers[i]) {
		RAnalEsilInterrupt *intr = _get_interrupt (esil, handlers[i]->num);
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

R_API bool r_anal_esil_load_syscalls(RAnalEsil *esil, RAnalEsilHandler *handlers[], ut32 src_id) {
	r_return_val_if_fail (esil && esil->syscalls && handlers, false);

	ut32 i = 0;
	while (handlers[i]) {
		RAnalEsilSyscall *sysc = _get_syscall (esil, handlers[i]->num);
		if (sysc) {
			r_anal_esil_syscall_free (esil, sysc);
		}
		sysc = r_anal_esil_syscall_new (esil, src_id, handlers[i]);
		if (!sysc) {
			return false;
		}
		r_anal_esil_set_syscall (esil, sysc);
		i++;
	}

	return true;
}

R_API bool r_anal_esil_load_interrupts_from_lib(RAnalEsil *esil, const char *path) {
	r_return_val_if_fail (esil, false);
	const ut32 src_id = r_anal_esil_load_source (esil, path);
	if (!src_id) { // why id=0 is invalid? id=0 is reserved for handlers that are implemented in libr, that was the idea
		return false;
	}
	RAnalEsilHandler **handlers = (RAnalEsilHandler **)
		r_lib_dl_sym (r_anal_esil_get_source (esil, src_id), "interrupts");
	if (!handlers) {
		r_anal_esil_release_source (esil, src_id); //unload
		return false;
	}
	return r_anal_esil_load_interrupts (esil, handlers, src_id);
}

R_API bool r_anal_esil_load_syscalls_from_lib(RAnalEsil *esil, const char *path) {
	r_return_val_if_fail (esil, false);
	const ut32 src_id = r_anal_esil_load_source (esil, path);
	if (!src_id) {
		return false;
	}
	RAnalEsilHandler **handlers = (RAnalEsilHandler **)
		r_lib_dl_sym (r_anal_esil_get_source (esil, src_id), "syscalls");
	if (!handlers) {
		r_anal_esil_release_source (esil, src_id); //unload
		return false;
	}
	return r_anal_esil_load_syscalls (esil, handlers, src_id);
}

R_API bool r_anal_esil_load_handlers_from_lib(RAnalEsil *esil, const char *path) {
	r_return_val_if_fail (esil, false);
	const ut32 src_id = r_anal_esil_load_source (esil, path);
	if (!src_id) {
		return false;
	}
	RAnalEsilHandler **ihandlers = (RAnalEsilHandler **)
		r_lib_dl_sym (r_anal_esil_get_source (esil, src_id), "interrupts");
	RAnalEsilHandler **shandlers = (RAnalEsilHandler **)
		r_lib_dl_sym (r_anal_esil_get_source (esil, src_id), "syscalls");
	if (!ihandlers && !shandlers) {
		r_anal_esil_release_source (esil, src_id); //unload
		return false;
	}
	bool ret = true;
	if (ihandlers) {
		ret &= r_anal_esil_load_interrupts (esil, ihandlers, src_id);
	}
	if (shandlers) {
		ret &= r_anal_esil_load_syscalls (esil, shandlers, src_id);
	}
	return ret;
}

R_API void r_anal_esil_handlers_fini(RAnalEsil *esil) {
	if (esil) {
		if (esil->interrupts) {
			_interrupt_free_cb (esil->intr0);
			esil->intr0 = NULL;
			esil->interrupts->f = _interrupt_free_cb;
			dict_free (esil->interrupts);
			esil->interrupts = NULL;
		}
		if (esil->syscalls) {
			_interrupt_free_cb (esil->sysc0);
			esil->sysc0 = NULL;
			esil->syscalls->f = _interrupt_free_cb;
			dict_free (esil->syscalls);
			esil->syscalls = NULL;
		}
	}
}
