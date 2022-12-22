/* radare2 - LGPL - Copyright 2022 - pancake */

// iostream utilities

#include "io_stream.h"

static char *stream_art(RIOStream *s) {
	ut64 saddr = 0;
	ut64 daddr = 0;
	RListIter *iter;
	RIOStreamItem *si;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "             ");
	r_strbuf_append (sb, ".---------[ host ]-----------.      .---------[ dest ]-----------.\n");
	int i, j;
	bool firstline = true;
	r_list_foreach (s->log, iter, si) {
		firstline = true;
		if (si->size < 1) {
			continue;
		}
		r_strbuf_append (sb, "             ");
		r_strbuf_append (sb, "|                            |      |                            |\n");
		for (i = 0; i < si->size;) {
			ut64 at = i + (si->host? saddr: daddr);
			r_strbuf_appendf (sb, "0x%08"PFMT64x" %c ", at, si->host? '>': '<');
			if (si->host) {
				r_strbuf_append (sb, "|");
			} else {
				r_strbuf_append (sb, "|                            |");
				if (firstline) {
					r_strbuf_append (sb, " <--- |");
				} else {
					r_strbuf_append (sb, "      |");
				}
			}
			// hex
			int oi = i;
			for (j = 0; j < 8 && i < si->size; j++, i++) {
				if ((j % 4) == 0) {
					r_strbuf_append (sb, " ");
				}
				r_strbuf_appendf (sb, "%02x", si->data[i]);
			}
			// padding
			for (; j < 8; j++) {
				if ((j % 4) == 0) {
					r_strbuf_append (sb, " ");
				}
				r_strbuf_append (sb, "  ");
			}
			r_strbuf_append (sb, " ");
			// asc
			i = oi;
			for (j = 0; j < 8 && i < si->size; j++, i++) {
				char ch = IS_PRINTABLE (si->data[i])? si->data[i]: '.';
				r_strbuf_appendf (sb, "%c", ch);
			}
			// padding
			for (; j < 8; j++) {
				r_strbuf_append (sb, " ");
			}
			r_strbuf_append (sb, " ");
			if (si->host) {
				if (firstline) {
					if (si->host) {
						r_strbuf_append (sb, "| ---> ");
					} else {
						r_strbuf_append (sb, "|      ");
					}
				} else {
					r_strbuf_append (sb, "|      ");
				}
			}
			if (si->host) {
				r_strbuf_append (sb, "|                            |\n");
			} else {
				r_strbuf_append (sb, "|\n");
			}
			firstline = false;
		}
		// r_strbuf_append (sb, " |\n");
		if (si->host) {
			saddr += si->size;
		} else {
			daddr += si->size;
		}
	}
	r_strbuf_append (sb, "             ");
	r_strbuf_append (sb, "|                            |      |                            |\n");
	r_strbuf_append (sb, "             ");
	r_strbuf_append (sb, "`----------------------------'      '----------------------------'\n");
	r_strbuf_appendf (sb, "Sent %"PFMT64d" bytes. Received %"PFMT64d" bytes.", saddr, daddr);
	return r_strbuf_drain (sb);
}

static void update_buffer(RIOStream *s) {
	r_buf_free (s->buf);
	s->buf = r_buf_new ();
	RIOStreamItem *si;
	RListIter *iter;
	ut64 size = 0;
	// find the size
	r_list_foreach (s->log, iter, si) {
		switch (s->mode) {
		case R_PERM_R:
			if (!si->host) {
				size += si->size;
			}
			break;
		case R_PERM_W:
			if (si->host) {
				size += si->size;
			}
			break;
		case R_PERM_RW:
			size += si->size;
			break;
		}
	}
	if (size > 0) {
		r_buf_resize (s->buf, size);
		ut64 at = 0;
		// fill it with love
		r_list_foreach (s->log, iter, si) {
			switch (s->mode) {
			case R_PERM_R:
				if (!si->host) {
					r_buf_write_at (s->buf, at, si->data, si->size);
					at += si->size;
				}
				break;
			case R_PERM_W:
				if (si->host) {
					r_buf_write_at (s->buf, at, si->data, si->size);
					at += si->size;
				}
				break;
			case R_PERM_RW:
				r_buf_write_at (s->buf, at, si->data, si->size);
				at += si->size;
				break;
			}
		}
	}
}

R_API void r_io_stream_log_free(RIOStreamItem *log) {
	if (log) {
		free (log->data);
		free (log);
	}
}

R_API void r_io_stream_free(RIOStream *s) {
	r_list_free (s->log);
	free (s);
}

R_API RIOStream *r_io_stream_new(void) {
	RIOStream *s = R_NEW0 (RIOStream);
	if (s) {
		s->log = r_list_newf ((RListFree)&r_io_stream_log_free);
		s->mode = R_PERM_RW;
	}
	return s;
}

static bool add_item(RIOStream *s, const ut8 *data, size_t len, bool host) {
	R_LOG_DEBUG ("add stream slice %d", host);
	RIOStreamItem *is = R_NEW0 (RIOStreamItem);
	if (is) {
		is->host = host;
		is->data = r_mem_dup (data, len);
		if (is->data) {
			is->size = len;
			r_list_append (s->log, is);
			return true;
		}
	}
	free (is->data);
	free (is);
	update_buffer (s);
	return false;
}

R_API bool r_io_stream_write(RIOStream *s, const ut8* data, size_t len) {
	return add_item (s, data, len, true);
}

R_API bool r_io_stream_read(RIOStream *s, const ut8* data, size_t len) {
	return add_item (s, data, len, false);
}

R_API char *r_io_stream_system(RIOStream *s, const char *cmd) {
	if (!s || R_STR_ISEMPTY (cmd)) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	RIOStreamItem *si;
	RListIter *iter;
	int i, count = 0;
	ut64 addr = 0;
	switch (*cmd) {
	case '*':
		r_list_foreach (s->log, iter, si) {
			if (s->mode == R_PERM_R && si->host) {
				continue;
			}
			if (s->mode == R_PERM_W && !si->host) {
				continue;
			}
			r_strbuf_append (sb, "wx+");
			for (i = 0; i < si->size; i++) {
				r_strbuf_appendf (sb, "%02x", si->data[i]);
			}
			r_strbuf_append (sb, "\n");
			count++;
		}
		break;
	case 'f':
		r_list_foreach (s->log, iter, si) {
			if (s->mode == R_PERM_R && si->host) {
				continue;
			}
			if (s->mode == R_PERM_W && !si->host) {
				continue;
			}
			r_strbuf_appendf (sb, "f msg.%d.%s %"PFMT64d" %d\n",
				count, si->host? "w": "r", addr, si->size);
			count++;
			addr += si->size;
		}
		break;
	case 'p':
		if (cmd[1] == 'x') {
			r_list_foreach (s->log, iter, si) {
				r_strbuf_appendf (sb, "%s (%.2d)", si->host? "H>": "D<", si->size);
				for (i = 0; i < si->size; i++) {
					r_strbuf_appendf (sb, " %02x", si->data[i]);
				}
				r_strbuf_append (sb, "\n");
			}
		} else {
			char *o = stream_art (s);
			r_strbuf_append (sb, o);
			free (o);
		}
		break;
	case 'r':
		if (cmd[1] == 'w') {
			s->mode = R_PERM_RW;
		} else {
			s->mode = R_PERM_R;
		}
		update_buffer (s);
		break;
	case 'w':
		s->mode = R_PERM_W;
		update_buffer (s);
		break;
	default:
	case '?':
		r_strbuf_append (sb, "Usage: :[cmd ..]\n");
		r_strbuf_append (sb, ":f         # print flags for current mode\n");
		r_strbuf_append (sb, ":*         # show write commands to fill the buffer\n");
		r_strbuf_append (sb, ":r         # only show the read ops\n");
		r_strbuf_append (sb, ":w         # only show the write ops\n");
		r_strbuf_append (sb, ":rw        # show read and write ops\n");
		r_strbuf_append (sb, ":p         # print two column ascii art of the communication\n");
		r_strbuf_append (sb, ":px        # print (H)ost/(D)est communication in hex per line\n");
		break;
	}
	return r_strbuf_drain (sb);
}
