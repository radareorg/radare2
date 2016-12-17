/*radare - LGPL - Copyright 2016 - oddcoder */
//dual buffer used as fast way to access large text files
#include <r_types.h>
#include <r_util.h>
int r_dualbuf_fill(RDualBuf *b) {
	if (b->mode == RDualBuf_single) {
		if (b->cp == NULL) {
			b->cp = b->buf1;
		}
		return false;
	}
	if (b->cp == b->buf1_end) {
		b->lsize = fread (b->buf2, sizeof (char), BUF_MAX, b->file);
		if (b->lsize != BUF_MAX) {
			b->buf2[b->lsize] = EOF;
		}
		b->cp = b->buf2;
		return true;
	}
	if(b->cp == b->buf2_end || b->cp == NULL) {
		b->lsize = fread (b->buf1, sizeof (char), BUF_MAX, b->file);
		if (b->lsize != BUF_MAX) {
			b->buf1[b->lsize] = EOF;
		}
		b->cp = b->buf1;
		return true;
	}
	return false;
}

R_API int r_dualbuf_single_init(RDualBuf *buf, char *s) {
	buf->mode = RDualBuf_single;
	buf->buf1 = s;
	buf->buf1_end = s + strlen(s);
	buf->buf2 = "";
	buf->buf2_end = buf->buf2;
	buf->file = NULL;
	buf->cp = NULL;
	return true;
}

R_API int r_dualbuf_init(RDualBuf *buf, FILE *f) {
	buf->mode = RDualBuf_dual;
	buf->buf1 = malloc (BUF_MAX);
	if (!buf->buf1) {
		return false;
	}
	buf->buf2 = malloc (BUF_MAX);
	if (!buf->buf2) {
		free (buf->buf1);
		return false;
	}
	buf->file = f;
	buf->buf1_end = buf->buf1 + BUF_MAX - 1;
	buf->buf2_end = buf->buf2 + BUF_MAX - 1;
	buf->cp = NULL;
	return true;
}

R_API void r_dualbuf_destroy(RDualBuf *b) {
	b->file = NULL;
	b->buf1_end = NULL;
	b->buf2_end = NULL;
	b->cp = NULL;
	if (b->mode == RDualBuf_dual) {
		free (b->buf1);
		free (b->buf2);
	}
	b->buf1 = NULL;
	b->buf2 = NULL;
}

R_API char *r_dualbuf_current_charp(RDualBuf *b) {
	return b->cp;
}

R_API char *r_dualbuf_next_charp(RDualBuf *b) {
	if (!r_dualbuf_fill (b)) {
		b->cp++;
	}
	return b->cp;
}
R_API char *r_dualbuf_prev_charp (RDualBuf *b) {
	if (b->cp == NULL) {
		return NULL;
	}
	if (b->cp == b->buf1) {
		if (b->mode == RDualBuf_single || *b->buf2 == 0) {
			rewind (b->file);
			return b->cp = NULL;
		}
		b->cp = b->buf2_end;
		fseek (b->file,-(2 * BUF_MAX + b->lsize) ,SEEK_CUR);
		fread (b->buf1, sizeof (char), BUF_MAX, b->file);
		fseek (b->file, BUF_MAX, SEEK_CUR);
		b->lsize = BUF_MAX;
		return b->cp;
	}
	if (b->cp == b->buf2) {
		b->cp = b->buf1_end;
		long seek = ftell (b->file);
		if (seek < 2 * BUF_MAX + b->lsize) {
			*b->buf2 = 0;
		} else {
			fseek (b->file,-(2 * BUF_MAX + b->lsize) ,SEEK_CUR);
			fread (b->buf2, sizeof (char), BUF_MAX, b->file);
			fseek (b->file, BUF_MAX, SEEK_CUR);
			b->lsize = BUF_MAX;
		}
		return b->cp;
	}
	return --b->cp;
}
R_API char *r_dualbuf_retrieve_tok (RDualBuf *b, char *start, char *end) {
	if (start >= b->buf1 && start <= b->buf1_end) {
		if (end >= b->buf1 && end <= b->buf1_end) {
			int size = end - start + 1;
			char *ret = malloc (size + 1);
			strncpy (ret, start, size);
			ret [size] = '\0';
			return ret;
		}
		if (end >= b->buf2 && end <= b->buf2_end) {
			int size1 = b->buf1_end - start + 1;
			int size2 = end - b->buf2 + 1;
			char *ret = malloc (size1 + size2 +1);
			strncpy (ret, start, size1);
			strncpy (ret + size1, b->buf2, size2);
			ret[size1 + size2] = '\0';
			return ret;
		}
	}
	if (start >= b->buf2 && start <= b->buf2_end) {
		if (end >= b->buf2 && end <= b->buf2_end) {
			int size = end - start + 1;
			char *ret = malloc (size + 1);
			strncpy (ret, start, size);
			ret [size] = '\0';
			return ret;
		}
		if (end >= b->buf1 && end <= b->buf1_end) {
			int size1 = b->buf2_end - start + 1;
			int size2 = end - b->buf1 + 1;
			char *ret = malloc (size1 + size2 +1);
			strncpy (ret, start, size1);
			strncpy (ret + size1, b->buf1, size2);
			ret[size1 + size2] = '\0';
			return ret;
		}
	}

	return NULL;
}
