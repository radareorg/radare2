
static RList *backtrace_x86_64(RDebug *dbg, ut64 at) {
	int i;
	ut8 buf[8];
	RDebugFrame *frame;
	ut64 ptr, ebp2;
	ut64 _rip, _rsp, _rbp = 0;
	RList *list;
	RReg *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;

	_rip = r_reg_get_value (reg, r_reg_get (reg, "rip", R_REG_TYPE_GPR));
	if (at == UT64_MAX) {
		_rsp = r_reg_get_value (reg, r_reg_get (reg, "rsp", R_REG_TYPE_GPR));
		_rbp = r_reg_get_value (reg, r_reg_get (reg, "rbp", R_REG_TYPE_GPR));
	} else {
		_rsp = _rbp = at;
	}

	list = r_list_new ();
	list->free = free;
	bio->read_at (bio->io, _rip, (ut8*)&buf, 8);
	/* %rbp=old rbp, %rbp+4 points to ret */
	/* Plugin before function prelude: push %rbp ; mov %rsp, %rbp */
	if (!memcmp (buf, "\x55\x89\xe5", 3) || !memcmp (buf, "\x89\xe5\x57", 3)) {
		if (bio->read_at (bio->io, _rsp, (ut8*)&ptr, 8) != 8) {
			eprintf ("read error at 0x%08"PFMT64x"\n", _rsp);
			r_list_purge (list);
			free (list);
			return false;
		}
		frame = R_NEW0 (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);
		_rbp = ptr;
	}

	for (i=1; i<dbg->btdepth; i++) {
		// TODO: make those two reads in a shot
		bio->read_at (bio->io, _rbp, (ut8*)&ebp2, 8);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at (bio->io, _rbp+8, (ut8*)&ptr, 8);
		if (!ptr || !_rbp)
			break;
		frame = R_NEW0 (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0; // TODO ?
		r_list_append (list, frame);
		_rbp = ebp2;
	}
	return list;
}
// XXX: Do this work correctly?
static RList *backtrace_x86_64_anal(RDebug *dbg, ut64 at) {
	int i;
	ut8 buf[8];
	RDebugFrame *frame;
	ut64 ptr, ebp2 = UT64_MAX;
	ut64 _rip, _rbp;
	RList *list;
	RReg *reg = dbg->reg;
	RIOBind *bio = &dbg->iob;
	RAnalFunction *fcn;

	_rip = r_reg_get_value (reg, r_reg_get (reg, "rip", R_REG_TYPE_GPR));
	if (at == UT64_MAX) {
		//_rsp = r_reg_get_value (reg, r_reg_get (reg, "rsp", R_REG_TYPE_GPR));
		_rbp = r_reg_get_value (reg, r_reg_get (reg, "rbp", R_REG_TYPE_GPR));
	} else {
		_rbp = at;
	}

	list = r_list_new ();
	list->free = free;
	bio->read_at (bio->io, _rip, (ut8*)&buf, 8);

	// TODO : frame->size by using esil to emulate first instructions
	fcn = r_anal_get_fcn_in (dbg->anal, _rip, R_ANAL_FCN_TYPE_NULL);
	if (fcn) {
		frame = R_NEW0 (RDebugFrame);
		frame->addr = _rip;
		frame->size = 0;
		frame->sp = _rbp;
		frame->bp = _rbp + 8; // XXX
		r_list_append (list, frame);
	}

	for (i=1; i<dbg->btdepth; i++) {
		// TODO: make those two reads in a shot
		bio->read_at (bio->io, _rbp, (ut8*)&ebp2, 8);
		if (ebp2 == UT64_MAX)
			break;
		bio->read_at (bio->io, _rbp+8, (ut8*)&ptr, 8);
		if (!ptr || !_rbp)
			break;
		//fcn = r_anal_get_fcn_in (dbg->anal, ptr, R_ANAL_FCN_TYPE_NULL);
		frame = R_NEW0 (RDebugFrame);
		frame->addr = ptr;
		frame->size = 0;
		frame->sp = _rbp;
		frame->bp = _rbp + 8;
		//frame->name = (fcn && fcn->name) ? strdup (fcn->name) : NULL;
		r_list_append (list, frame);
		_rbp = ebp2;
	}

	return list;
}

