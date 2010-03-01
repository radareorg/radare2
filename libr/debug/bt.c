#include <r_debug.h>

#define MAXBT 128

// TODO: r_reg typedef must be renamed to this shorter version
#define RReg RRegister

/* TODO: Can I use this as in a coroutine? */
static RList *backtrace_i386(RIOBind *bio, RReg *reg) {
	ut32 i, esp, ebp2;
	ut8 buf[4];
	ut32 _esp = r_reg_get_value (reg, r_reg_get (reg, "esp", R_REG_TYPE_GPR));
	RList *list = r_list_new ();
	list->free = free;
	// TODO: implement [stack] map uptrace method too
	esp = _esp;
	for (i=0; i<MAXBT; i++) {
		bio->read_at (bio->io, esp, (void *)&ebp2, 4);
		*buf = '\0';
		bio->read_at (bio->io, (ebp2-5)-(ebp2-5)%4, (void *)&buf, 4);

		// TODO: arch_is_call() here and this fun will be portable
		if (buf[(ebp2-5)%4]==0xe8) {
			RDebugFrame *frame = R_NEW (RDebugFrame);
			frame->addr = ebp2;
			frame->size = esp-_esp;
			r_list_append (list, frame);
			eprintf ("ADDR: 0x%08x, SIZE: 0x%x\n", ebp2, esp-_esp);
		}
		esp += 4;
	}
	return list;
}

// XXX: Do this work correctly?
static RList *backtrace_x86_64(RIOBind *bio, RReg *reg) {
	int i;
	ut8 buf[4];
	ut64 ptr, ebp2;
	ut64 _rip = r_reg_get_value (reg, r_reg_get (reg, "rip", R_REG_TYPE_GPR));
	ut64 _rsp = r_reg_get_value (reg, r_reg_get (reg, "rsp", R_REG_TYPE_GPR));
	ut64 _rbp = r_reg_get_value (reg, r_reg_get (reg, "rbp", R_REG_TYPE_GPR));
	RList *list = r_list_new ();
	list->free = free;

	bio->read_at (bio->io, _rip, &buf, 4);

	/*
	  %ebp points to the old ebp var
	  %ebp+4 points to ret
	*/
	/* Handle before function prelude: push %ebp ; mov %esp, %ebp */
	if (!memcmp (buf, "\x55\x89\xe5", 3) || !memcmp (buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at (bio->io, _rsp, &ptr, 4) != 4) {
			eprintf ("read error at 0x%08llx\n", _rsp);
			return R_FALSE;
		}
		eprintf ("ADDR: 0x%08llx\n", ptr); // TODO: size!
		_rbp = ptr;
	}

	for (i=1; i<MAXBT; i++) {
		// TODO: make those two reads in a shot
		bio->read_at (bio->io, _rbp, &ebp2, 4);
		bio->read_at (bio->io, _rbp+4, &ptr, 4);
		if (ptr == 0x0 || _rbp == 0x0)
			break;
		eprintf ("ADDR: 0x%08llx\n", ptr);
		_rbp = ebp2;
	}
	return list;
}

R_API RList *r_debug_frames (RDebug *dbg) {
	//if (dbg->bits == 64) {
	//	return backtrace_x86_64 (dbg->bio, dbg->reg) {
	//} else {
		return backtrace_i386 (&dbg->iob, dbg->reg);
	//}
}
