// iostream utilities

#include "io_stream.h"

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
	}
	return s;
}

static bool add_item(RIOStream *s, const ut8 *data, size_t len, bool host) {
	eprintf ("ADD %d\n", host);
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
	return false;
}

R_API bool r_io_stream_write(RIOStream *s, const ut8* data, size_t len) {
	return add_item (s, data, len, true);
}

R_API bool r_io_stream_read(RIOStream *s, const ut8* data, size_t len) {
	return add_item (s, data, len, false);
}

R_API char *r_io_stream_system(RIOStream *s, const char *cmd) {
	RStrBuf *sb = r_strbuf_new ("");
	RIOStreamItem *si;
	RListIter *iter;
	switch (*cmd) {
	case 'f':
		r_list_foreach (s->log, iter, si) {
			r_strbuf_appendf (sb, "%s %d\n", si->host? "W": "R", si->size);
		}
		eprintf ("flags\n");
		break;
	case '?':
		eprintf ("Halp\n");
		break;
	}
	eprintf ("RETURN (%s)\n", r_strbuf_get (sb));
	return r_strbuf_drain (sb);
}
