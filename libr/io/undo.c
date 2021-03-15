/* radare - LGPL - Copyright 2007-2018 - pancake */

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

	return true;
}

R_API void r_io_undo_enable(RIO *io, int s, int w) {
	io->undo.s_enable = s;
	io->undo.w_enable = w;
}

/* undo seekz */

R_API RIOUndos *r_io_sundo(RIO *io, ut64 offset) {
	if (!io->undo.s_enable || !io->undo.undos) {
		return NULL;
	}

	RIOUndos *undo;
	/* No redos yet, store the current seek so we can redo to it. */
	if (!io->undo.redos) {
		undo = &io->undo.seek[io->undo.idx];
		undo->off = offset;
		undo->cursor = 0;
	}

	io->undo.idx = (io->undo.idx - 1 + R_IO_UNDOS) % R_IO_UNDOS;
	io->undo.undos--;
	io->undo.redos++;

	undo = &io->undo.seek[io->undo.idx];
	RIOMap *map = r_io_map_get_at (io, undo->off);
	if (!map || (map->delta == r_io_map_begin (map))) {
		io->off = undo->off;
	} else {
		io->off = undo->off - (r_io_map_begin (map) + map->delta);
	}
	return undo;
}

R_API RIOUndos *r_io_sundo_redo(RIO *io) {
	RIOUndos *undo;
	RIOMap *map;

	if (!io->undo.s_enable || !io->undo.redos) {
		return NULL;
	}

	io->undo.idx = (io->undo.idx + 1) % R_IO_UNDOS;
	io->undo.undos++;
	io->undo.redos--;

	undo = &io->undo.seek[io->undo.idx];
	map = r_io_map_get_at (io, undo->off);
	if (!map || (map->delta == r_io_map_begin (map))) {
		io->off = undo->off;
	} else {
		io->off = undo->off - r_io_map_begin (map) + map->delta;
	}
	return undo;
}

R_API void r_io_sundo_push(RIO *io, ut64 off, int cursor) {
	RIOUndos *undo;
	if (!io->undo.s_enable) {
		return;
	}
	// don't push duplicate seek
	if (io->undo.undos > 0) {
		undo = &io->undo.seek[(io->undo.idx - 1 + R_IO_UNDOS) % R_IO_UNDOS];
		if (undo->off == off && undo->cursor == cursor) {
			return;
		}
	}

	undo = &io->undo.seek[io->undo.idx];
	undo->off = off;
	undo->cursor = cursor;
	io->undo.idx = (io->undo.idx + 1) % R_IO_UNDOS;
	/* Only R_IO_UNDOS - 1 undos can be used because r_io_sundo_undo () must
	 * push the current position for redo as well, which takes one entry in
	 * the table. */
	if (io->undo.undos < R_IO_UNDOS - 1) {
		io->undo.undos++;
	}
	/* We only have linear undo/redo, no tree. So after this new possible
	 * undo, all redos are lost. */
	io->undo.redos = 0;
}

R_API void r_io_sundo_reset(RIO *io) {
	io->undo.idx = 0;
	io->undo.undos = 0;
	io->undo.redos = 0;
}

R_API RList *r_io_sundo_list(RIO *io, int mode) {
	int idx, undos, redos, i, j, start, end;
	RList* list = NULL;

	if (mode == '!') {
		mode = 0;
	}
	if (!io->undo.s_enable) {
		return NULL;
	}
	undos = io->undo.undos;
	redos = io->undo.redos;

	idx = io->undo.idx;
	start = (idx - undos + R_IO_UNDOS) % R_IO_UNDOS;
	end = (idx + redos + 1 - 1) % R_IO_UNDOS; // +1 slot for current position, -1 due to inclusive end

	j = 0;
	switch (mode) {
	case 'j':
		io->cb_printf ("[");
		break;
	case 0:
		list = r_list_newf (free);
		break;
	}
	for (i = start;/* condition at the end of loop */; i = (i + 1) % R_IO_UNDOS) {
		int idx = (j < undos)? undos - j - 1: j - undos - 1;
		RIOUndos *undo = &io->undo.seek[i];
		ut64 addr = undo->off;
		bool notLast = (j + 1 < undos);
		switch (mode) {
		case '=':
			if (j < undos) {
				io->cb_printf ("0x%"PFMT64x"%s", addr, notLast? " > ": "");
			}
			break;
		case '*':
			if (j < undos) {
				io->cb_printf ("f undo_%d @ 0x%"PFMT64x"\n", idx, addr);
			} else if (j == undos && j != 0 && redos != 0) {
				io->cb_printf ("# Current undo/redo position.\n");
			} else if (j != undos) {
				io->cb_printf ("f redo_%d @ 0x%"PFMT64x"\n", idx, addr);
			}
			break;
		case 0:
			if (list) {
				RIOUndos  *u = R_NEW0 (RIOUndos);
				if (u) {
					if (!(j == undos && redos == 0)) {
						// Current position gets pushed before seek, so there
						// is no valid offset when we are at the end of list.
						memcpy (u, undo, sizeof (RIOUndos));
					} else {
						u->off = io->off;
					}
					r_list_append (list, u);
				}
			}
			break;
		}
		j++;
		if (i == end) {
			break;
		}
	}
	switch (mode) {
	case '=':
		io->cb_printf ("\n");
		break;
	}
	return list;
}

/* undo writez */

R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len) {
	RIOUndoWrite *uw;
	if (!io->undo.w_enable) {
		return;
	}
	/* undo write changes */
	uw = R_NEW0 (RIOUndoWrite);
	if (!uw) {
		return;
	}
	uw->set = true;
	uw->off = off;
	uw->len = len;
	uw->n = (ut8*) malloc (len);
	if (!uw->n) {
		free (uw);
		return;
	}
	memcpy (uw->n, data, len);
	uw->o = (ut8*) malloc (len);
	if (!uw->o) {
		R_FREE (uw);
		return;
	}
	memset (uw->o, 0xff, len);
	r_io_read_at (io, off, uw->o, len);
	r_list_append (io->undo.w_list, uw);
}

R_API void r_io_wundo_clear(RIO *io) {
	// XXX memory leak
	io->undo.w_list = r_list_new ();
}

// rename to r_io_undo_length ?
R_API int r_io_wundo_size(RIO *io) {
	return r_list_length (io->undo.w_list);
}

// TODO: Deprecate or so? iterators must be language-wide, but helpers are useful
R_API void r_io_wundo_list(RIO *io) {
#define BW 8 /* byte wrap */
	RListIter *iter;
	RIOUndoWrite *u;
	int i = 0, j, len;

	if (io->undo.w_init) {
		r_list_foreach (io->undo.w_list, iter, u) {
			io->cb_printf ("%02d %c %zu %08" PFMT64x ": ", i, u->set ? '+' : '-', u->len, u->off);
			len = (u->len > BW) ? BW : u->len;
			for (j = 0; j < len; j++) {
				io->cb_printf ("%02x ", u->o[j]);
			}
			if (len == BW) {
				io->cb_printf (".. ");
			}
			io->cb_printf ("=> ");
			for (j = 0; j < len; j++) {
				io->cb_printf ("%02x ", u->n[j]);
			}
			if (len == BW) {
				io->cb_printf (".. ");
			}
			io->cb_printf ("\n");
			i++;
		}
	}
}

R_API int r_io_wundo_apply(RIO *io, RIOUndoWrite *u, int set) {
	int orig = io->undo.w_enable;
	io->undo.w_enable = 0;
	if (set) {
		r_io_write_at (io, u->off, u->n, u->len);
		u->set = true;
	} else {
		r_io_write_at (io, u->off, u->o, u->len);
		u->set = false;
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
		r_list_foreach_prev (io->undo.w_list, iter, u) {
			if (i++ == n) {
				break;
			}
		}
		if (u) { // wtf?
			r_io_wundo_apply (io, u, set);
			return true;
		}
		eprintf ("invalid undo-write index\n");
	} else {
		eprintf ("no writes done\n");
	}
	return false;
}
