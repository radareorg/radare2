/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include <r_io.h>

#if 0
* TODO:
* - make path of indirections shortr (io->undo.foo is slow) */
* - Plugin changes in write and seeks
* - Per-fd history log
#endif

R_API int r_io_undo_init(RIO *io) {
	io->undo.w_init = 0;
	io->undo.w_enable = 0;
	io->undo.idx = 0;
	io->undo.limit = 0;
	io->undo.s_enable = 0;
	io->undo.w_enable = 0;
	io->undo.w_list = r_list_new ();
	return R_TRUE;
}

R_API void r_io_undo_enable(RIO *io, int s, int w) {
	io->undo.s_enable = s;
	io->undo.w_enable = w;
}

R_API ut64 r_io_sundo_last(RIO *io) {
	return (io->undo.idx>0)?
		io->undo.seek[io->undo.idx-1] : io->off;
}

R_API ut64 r_io_sundo(RIO *io, ut64 offset) {
	ut64 off;
	if (io->undo.idx == io->undo.limit) {
		r_io_sundo_push (io, offset);
		io->undo.idx--;
	}
	io->undo.idx--;
	if (io->undo.idx<0) {
		io->undo.idx = 0;
		return UT64_MAX;
	}
	off = io->undo.seek[io->undo.idx];
	io->off = r_io_section_vaddr_to_offset (io, off);
	return off;
}

R_API ut64 r_io_sundo_redo(RIO *io) {
	ut64 off;

	if (io->undo.idx<io->undo.limit) {
		io->undo.idx += 1;
		if (io->undo.idx<R_IO_UNDOS) {
			off = io->off = io->undo.seek[io->undo.idx];
			io->off = r_io_section_vaddr_to_offset (io, off);
			return off;
		}
		io->undo.idx -= 1;
	}
	return UT64_MAX;
}

R_API void r_io_sundo_push(RIO *io, ut64 off) {
	if (!io->undo.s_enable)
		return;
	io->undo.seek[io->undo.idx] = off;
	io->undo.idx++;
	if (io->undo.idx==R_IO_UNDOS-1) {
		io->undo.idx--;
	}
	io->undo.limit = io->undo.idx;
}

R_API void r_io_sundo_reset(RIO *io) {
	io->undo.idx = 0;
}

R_API void r_io_sundo_list(RIO *io) {
	int i;
	if (io->undo.idx>0) {
		io->printf ("f undo_idx @ %d\n", io->undo.idx);
		for (i=io->undo.idx; i!=0; i--)
			io->printf ("f undo_%d @ 0x%"PFMT64x"\n",
				io->undo.idx-i, io->undo.seek[i-1]);
	} else eprintf("-no seeks done-\n");
}

/* undo writez */

R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len) {
	struct r_io_undo_w_t *uw;
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
	RListIter *iter;
	RIOUndoWrite *uw;
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
