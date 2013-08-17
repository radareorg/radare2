/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_io.h>

#if 0
* TODO:
* - make path of indirections shortr (io->undo.foo is slow) */
* - Plugin changes in write and seeks
* - Per-fd history log
#endif

R_API int r_io_undo_init(RIO *io) {
	/* seek undo */
	r_io_sundo_reset (io);

	/* write undo */
	io->undo.w_init = 0;
	io->undo.w_enable = 0;
	io->undo.w_enable = 0;
	io->undo.w_list = r_list_new ();

	return R_TRUE;
}

R_API void r_io_undo_enable(RIO *io, int s, int w) {
	io->undo.s_enable = s;
	io->undo.w_enable = w;
}

/* undo seekz */

R_API ut64 r_io_sundo(RIO *io, ut64 offset) {
	ut64 off;

	if (!io->undo.s_enable || !io->undo.undos)
		return UT64_MAX;

	/* No redos yet, store the current seek so we can redo to it. */
	if (!io->undo.redos) {
		io->undo.seek[io->undo.idx] = offset;
	}

	io->undo.idx = (io->undo.idx - 1 + R_IO_UNDOS) % R_IO_UNDOS;
	io->undo.undos--;
	io->undo.redos++;

	off = io->undo.seek[io->undo.idx];
	io->off = r_io_section_vaddr_to_offset (io, off);
	return off;
}

R_API ut64 r_io_sundo_redo(RIO *io) {
	ut64 off;

	if (!io->undo.s_enable || !io->undo.redos)
		return UT64_MAX;

	io->undo.idx = (io->undo.idx + 1) % R_IO_UNDOS;
	io->undo.undos++;
	io->undo.redos--;

	off = io->undo.seek[io->undo.idx];
	io->off = r_io_section_vaddr_to_offset (io, off);
	return off;
}

R_API void r_io_sundo_push(RIO *io, ut64 off) {
	if (!io->undo.s_enable)
		return;

	io->undo.seek[io->undo.idx] = off;
	io->undo.idx = (io->undo.idx + 1) % R_IO_UNDOS;
	/* Only R_IO_UNDOS - 1 undos can be used because r_io_sundo_undo () must
	 * push the current position for redo as well, which takes one entry in
	 * the table. */
	if (io->undo.undos < R_IO_UNDOS - 1)
		io->undo.undos++;
	/* We only have linear undo/redo, no tree. So after this new possible
	 * undo, all redos are lost. */
	io->undo.redos = 0;
}

R_API void r_io_sundo_reset(RIO *io) {
	io->undo.idx = 0;
	io->undo.undos = 0;
	io->undo.redos = 0;
}

R_API void r_io_sundo_list(RIO *io) {
	int idx, undos, redos, i, j, start, end;

	if (!io->undo.s_enable)
		return;
	undos = io->undo.undos;
	redos = io->undo.redos;
	if (!undos && !redos) {
		io->printf ("-no seeks done-\n");
		return;
	}

	idx = io->undo.idx;
	start = (idx - undos + R_IO_UNDOS) % R_IO_UNDOS;
	end   = (idx + redos + 1) % R_IO_UNDOS;

	j = 0;
	for (i = start; i != end || j == 0; i = (i + 1) % R_IO_UNDOS) {
		if (j < undos) {
			io->printf ("f undo_%d @ 0x%"PFMT64x"\n", undos - j - 1, io->undo.seek[i]);
		} else if (j == undos && j != 0 && redos != 0) {
			io->printf ("# Current undo/redo position.\n");
		} else if (j != undos) {
			io->printf ("f redo_%d @ 0x%"PFMT64x"\n", j - undos - 1, io->undo.seek[i]);
		}
		j++;
	}
}

/* undo writez */

R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len) {
	RIOUndoWrite *uw;
	if (!io->undo.w_enable)
		return;
	/* undo write changes */
	uw = R_NEW (RIOUndoWrite);
	if (!uw) return;
	uw->set = R_TRUE;
	uw->off = off;
	uw->len = len;
	uw->n = (ut8*) malloc (len);
	memcpy(uw->n, data, len);
	uw->o = (ut8*) malloc (len);
	r_io_read_at(io, off, uw->o, len);
	r_list_append (io->undo.w_list, uw);
}

R_API void r_io_wundo_clear(RIO *io) {
	// XXX memory leak
	io->undo.w_list = r_list_new ();
}

// rename to r_io_undo_length ?
R_API int r_io_wundo_size(RIO *io) {
	RIOUndoWrite *uw;
	RListIter *iter;
	int i = 0;

	if (io->undo.w_init)
		r_list_foreach (io->undo.w_list, iter, uw)
			i++;
	return i;
}

// TODO: Deprecate or so? iterators must be language-wide, but helpers are useful
R_API void r_io_wundo_list(RIO *io) {
#define BW 8 /* byte wrap */
	RListIter *iter;
	RIOUndoWrite *u;
	int i = 0, j, len;

	if (io->undo.w_init)
	r_list_foreach (io->undo.w_list, iter, u) {
		io->printf ("%02d %c %d %08"PFMT64x": ", i, u->set?'+':'-', u->len, u->off);
		len = (u->len>BW)?BW:u->len;
		for (j=0;j<len;j++) io->printf ("%02x ", u->o[j]);
		if (len == BW) io->printf (".. ");
		io->printf ("=> ");
		for (j=0;j<len;j++) io->printf ("%02x ", u->n[j]);
		if (len == BW) io->printf (".. ");
		io->printf ("\n");
		i++;
	}
}

R_API int r_io_wundo_apply(RIO *io, struct r_io_undo_w_t *u, int set) {
	int orig = io->undo.w_enable;
	io->undo.w_enable = 0;
	if (set) {
		r_io_write_at (io, u->off, u->n, u->len);
		u->set = R_TRUE;
	} else {
		r_io_write_at (io, u->off, u->o, u->len);
		u->set = R_FALSE;
	}
	io->undo.w_enable = orig;
	return 0;
}

R_API void r_io_wundo_apply_all(RIO *io, int set) {
	RListIter *iter;
	RIOUndoWrite *u;

	r_list_foreach_prev (io->undo.w_list, iter, u) {
		r_io_wundo_apply (io, u, set); //UNDO_WRITE_UNSET);
		eprintf ("%s 0x%08"PFMT64x"\n", set?"redo":"undo", u->off);
	}
}

/* sets or unsets the writes done */
/* if ( set == 0 ) unset(n) */
R_API int r_io_wundo_set(RIO *io, int n, int set) {
	RListIter *iter;
	RIOUndoWrite *u = NULL;
	int i = 0;
	if (io->undo.w_init) {
		r_list_foreach_prev (io->undo.w_list, iter, u)
			if (i++ == n)
				break;
		if (u) { // wtf?
			r_io_wundo_apply (io, u, set);
			return R_TRUE;
		}
		eprintf ("invalid undo-write index\n");
	} else eprintf ("no writes done\n");
	return R_FALSE;
}
