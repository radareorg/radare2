/* TODO: not yet integrate */

#define MAXBT 128

/* TODO: Can I use this as in a coroutine? */
static int backtrace_i386(RIOBind *bio, ut32 _esp) {
	ut32 i, esp, ebp2;
	ut8 buf[4];

	// TODO: implement [stack] map uptrace method too
	esp = _esp;
	for (i=0; i<MAXBT; i++) {
		bio->read_at (bio->io, esp, &ebp2, 4);
		*buf = '\0';
		bio->read_at (bio->io, (ebp2-5)-(ebp2-5)%4, &buf, 4);

		// TODO: arch_is_call() here and this fun will be portable
		if (buf[(ebp2-5)%4]==0xe8) {
			eprintf ("ADDR: 0x%08x, SIZE: 0x%x\n", addr, esp-_esp);
		}
		esp += 4;
	}
	return i;
}

// XXX: Do this works correctly?
static int backtrace_x86_64(RIOBind *bio, ut64 _rip, ut64 _rsp, ut64 _rbp) {
	/*
	%ebp points to the old ebp var
	%ebp+4 points to ret
	*/
	int ret, i;
	ut8 buf[4];
	ut64 ptr, ebp2;

	debug_read_at (ps.tid, &buf, 4, _rip);

	/* Handle before function prelude: push %ebp ; mov %esp, %ebp */
	if (!memcmp(buf, "\x55\x89\xe5", 3) || !memcmp(buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at (bio->io, _rsp, &ptr, 4) != 4) {
			eprintf ("read error at 0x%08llx\n", _rsp);
			return R_FALSE;
		}
		eprintf ("ADDR: 0x%08llx\n", ptr); // TODO: size!
		_rbp = ptr;
	}

	for(i=1; i<MAXBT; i++) {
		// TODO: make those two reads in a shot
		bio->read_at (bio->io, _rbp, &ebp2, 4);
		bio->read_at (bio->io, _rbp+4, &ptr, 4);
		if (ptr == 0x0 || _rbp == 0x0)
			break;
		eprintf ("ADDR: 0x%08llx\n", ptr);
		_rbp = ebp2;
	}
	return i;
	return R_TRUE;
}
