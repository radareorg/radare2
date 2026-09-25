/* radare - LGPL - Copyright 2007-2026 - pancake */

#include <r_io.h>

#if IDEAS_FOR_UNDO
- make path of indirections shortr (io->undo.foo is slow)
- Plugin changes in write and seeks
- Per-fd history log
#endif

R_API int r_io_undo_init(RIO *io) {
	/* seek undo */
	r_io_sundo_reset (io);

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
	if (!io->undo.s_enable || !io->undo.redos) {
		return NULL;
	}

	io->undo.idx = (io->undo.idx + 1) % R_IO_UNDOS;
	io->undo.undos++;
	io->undo.redos--;

	RIOUndos *undo = &io->undo.seek[io->undo.idx];
	RIOMap *map = r_io_map_get_at (io, undo->off);
	if (!map || (map->delta == r_io_map_begin (map))) {
		io->off = undo->off;
	} else {
		io->off = undo->off - r_io_map_begin (map) + map->delta;
	}
	return undo;
}

R_API void r_io_sundo_push(RIO *io, ut64 off, int cursor) {
	R_RETURN_IF_FAIL (io);
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
	R_RETURN_IF_FAIL (io);
	io->undo.idx = 0;
	io->undo.undos = 0;
	io->undo.redos = 0;
}

R_API char *r_io_sundo_list(RIO *io, int mode) {
	R_RETURN_VAL_IF_FAIL (io, NULL);
	if (!io->undo.s_enable) {
		return NULL;
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = io->coreb.pjWithEncoding? io->coreb.pjWithEncoding (io->coreb.core): pj_new ();
	}
	RStrBuf *buf = mode == 'j'? NULL: r_strbuf_new ("");
	if (!pj && !buf) {
		return NULL;
	}
	int undos = io->undo.undos;
	int redos = io->undo.redos;
	int idx = io->undo.idx;
	int start = (idx - undos + R_IO_UNDOS) % R_IO_UNDOS;
	int end = (idx + redos) % R_IO_UNDOS;

	if (pj) {
		pj_a (pj);
	}

	int i, j = 0;
	for (i = start;/* condition at the end of loop */; i = (i + 1) % R_IO_UNDOS) {
		int u_idx = (j < undos)? undos - j - 1: j - undos - 1;
		ut64 addr = (j == undos && !redos)? io->off: io->undo.seek[i].off;
		switch (mode) {
		case 'j':
			{
				char *name = io->coreb.getNameDelta? io->coreb.getNameDelta (io->coreb.core, addr): NULL;
				if (name) {
					name = r_str_replace (name, " + ", "+", 0);
				}
				pj_o (pj);
				pj_kn (pj, "offset", addr);
				if (R_STR_ISNOTEMPTY (name)) {
					pj_ks (pj, "name", name);
				}
				if (j == undos) {
					pj_kb (pj, "current", true);
				}
				pj_end (pj);
				free (name);
			}
			break;
		case '=':
			if (j < undos) {
				r_strbuf_appendf (buf, "0x%"PFMT64x"%s", addr, j + 1 < undos? " > ": "");
			}
			break;
		case 'r':
			{
				char *cmt = io->coreb.cmdStrF? io->coreb.cmdStrF (io->coreb.core, "fd 0x%08"PFMT64x, addr): NULL;
				if (cmt) {
					r_str_trim (cmt);
				}
				if (j < undos) {
					r_strbuf_appendf (buf, "0x%08"PFMT64x" ; %ds- # %s\n", addr, u_idx + 1, r_str_get (cmt));
				} else if (j == undos && j != 0 && redos != 0) {
					r_strbuf_appendf (buf, "0x%08"PFMT64x" ; # CUR %s\n", addr, r_str_get (cmt));
				} else if (j != undos) {
					r_strbuf_appendf (buf, "0x%08"PFMT64x" ; %ds+ # %s\n", addr, u_idx + 1, r_str_get (cmt));
				} else if (addr != 0) {
					r_strbuf_appendf (buf, "0x%08"PFMT64x" ; # CUR %s\n", addr, r_str_get (cmt));
				}
				free (cmt);
			}
			break;
		case '*':
			if (j < undos) {
				r_strbuf_appendf (buf, "f undo_%d = 0x%"PFMT64x"\n", u_idx, addr);
			} else if (j == undos && j != 0 && redos != 0) {
				r_strbuf_append (buf, "# Current undo/redo position.\n");
			} else if (j != undos) {
				r_strbuf_appendf (buf, "f redo_%d = 0x%"PFMT64x"\n", u_idx, addr);
			}
			break;
		case '!':
			{
				char *name = io->coreb.getNameDelta? io->coreb.getNameDelta (io->coreb.core, addr): NULL;
				r_strbuf_appendf (buf, "0x%"PFMT64x" %s\n", addr, r_str_get (name));
				free (name);
			}
			break;
		case 0:
			{
				char *name = io->coreb.getNameDelta? io->coreb.getNameDelta (io->coreb.core, addr): NULL;
				if (R_STR_ISNOTEMPTY (name)) {
					r_strbuf_append (buf, name);
				} else {
					r_strbuf_appendf (buf, "0x%"PFMT64x, addr);
				}
				if (i != end) {
					r_strbuf_append (buf, " > ");
				}
				free (name);
			}
			break;
		}
		j++;
		if (i == end) {
			break;
		}
	}
	if (mode == '=' || mode == 0) {
		r_strbuf_append (buf, "\n");
	}
	if (pj) {
		pj_end (pj);
		return pj_drain (pj);
	}
	return r_strbuf_drain (buf);
}

/* undo writez */

R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len) {
	R_RETURN_IF_FAIL (io);
	if (!io->undo.w_enable) {
		return;
	}
	ut8 *a = (ut8*) malloc (len);
	ut8 *b = (ut8*) malloc (len);
	if (!a || !b) {
		free (a);
		free (b);
		return;
	}
	/* undo write changes */
	RIOUndoWrite *uw = R_NEW0 (RIOUndoWrite);
	uw->set = true;
	uw->off = off;
	uw->len = len;
	uw->n = a;
	memcpy (uw->n, data, len);
	uw->o = b;
	memset (uw->o, io->Oxff, len);
	r_io_read_at (io, off, uw->o, len);
	r_list_append (io->undo.w_list, uw);
}

R_API void r_io_wundo_clear(RIO *io) {
	R_RETURN_IF_FAIL (io);
	// XXX memory leak
	io->undo.w_list = r_list_new ();
}

// rename to r_io_undo_length ?
R_API int r_io_wundo_size(RIO *io) {
	R_RETURN_VAL_IF_FAIL (io, 0);
	return r_list_length (io->undo.w_list);
}

R_API bool r_io_wundo_apply(RIO *io, RIOUndoWrite *u, bool set) {
	bool orig = io->undo.w_enable;
	io->undo.w_enable = false;
	u->set = set;
	const ut8 *src = set? u->n: u->o;
	const bool good = r_io_write_at (io, u->off, src, u->len);
	io->undo.w_enable = orig;
	return good;
}

R_API bool r_io_wundo_apply_all(RIO *io, bool set) {
	RListIter *iter;
	RIOUndoWrite *u;
	bool allfine = true;
	r_list_foreach_prev (io->undo.w_list, iter, u) {
		allfine &= r_io_wundo_apply (io, u, set);
		R_LOG_INFO ("%s 0x%08"PFMT64x, set? "redo": "undo", u->off);
	}
	return allfine;
}

/* sets or unsets the writes done */
/* if (set == 0) unset(n) */
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
		R_LOG_ERROR ("invalid undo-write index");
	} else {
		R_LOG_INFO ("no writes done");
	}
	return false;
}
