/* radare - LGPL - Copyright 2012-2020 - pancake */

#include <r_util.h>

R_API RStrpool* r_strpool_new(int sz) {
	RStrpool *p = R_NEW (RStrpool);
	if (!p) {
		eprintf ("Malloc failed!\n");
		return NULL;
	}
	if (sz < 1) {
		sz = 1024;
	}
	p->str = malloc (sz);
	if (!p->str) {
		eprintf ("Malloc failed!\n");
		free (p);
		return NULL;
	}
	p->size = sz;
	p->len = 0;
	p->str[0] = 0;
	return p;
}

R_API char *r_strpool_empty(RStrpool *p) {
	p->len = 0;
	p->str[0] = 0;
	p->str[1] = 0;
	return p->str;
}

R_API char *r_strpool_alloc(RStrpool *p, int l) {
	char *ret = p->str + p->len;
	if ((p->len + l) >= p->size) {
		ut64 osize = p->size;
		if (l >= R_STRPOOL_INC) {
			p->size += l + R_STRPOOL_INC;
		} else {
			p->size += R_STRPOOL_INC;
		}
		if (p->size < osize) {
			eprintf ("Underflow!\n");
			p->size = osize;
			return NULL;
		}
		ret = realloc (p->str, p->size);
		if (!ret) {
			eprintf ("Realloc failed!\n");
			free (p->str);
			p->str = NULL;
			return NULL;
		}
		p->str = ret;
		ret += p->len;
	}
	p->len += l;
	return ret;
}

R_API int r_strpool_memcat(RStrpool *p, const char *s, int len) {
	char *ptr = r_strpool_alloc (p, len);
	if (!ptr) {
		return -1;
	}
	memcpy (ptr, s, len);
	return (size_t)(ptr - p->str);
}

R_API int r_strpool_append(RStrpool *p, const char *s) {
	int l = strlen (s) + 1;
	return r_strpool_memcat (p, s, l);
}

R_API int r_strpool_ansi_chop(RStrpool *p, int n){
	/* p->str need not be a c-string */
	int i = r_str_ansi_trim (p->str, p->len, n);
	p->len = i;
	return i;
}

R_API void r_strpool_free(RStrpool *p) {
	free (p->str);
	free (p);
}

R_API int r_strpool_fit(RStrpool *p) {
	char *s;
	if (p->len == p->size) {
		return false;
	}
	s = realloc (p->str, p->len);
	if (!s)
	{
		eprintf ("Realloc failed!\n");
		free (p->str);
		return false;
	}
	p->str = s;
	p->size = p->len;
	return true;
}

R_API char *r_strpool_get(RStrpool *p, int index) {
	if (!p || !p->str || index < 0 || index >= p->len) {
		return NULL;
	}
	return p->str + index;
}

R_API char *r_strpool_get_i(RStrpool *p, int index) {
	int i, n = 0;
	if (index < 0 || index >= p->len) {
		return NULL;
	}
	for (i = 0; i < index; i++) {
		char *s = r_strpool_next (p, n);
		n = r_strpool_get_index (p, s);
	}
	return p->str + n;
}

R_API int r_strpool_get_index(RStrpool *p, const char *s) {
	int ret = (size_t)(s - p->str);
	return (ret > 0) ? ret : 0;
}

R_API char *r_strpool_next(RStrpool *p, int index) {
	char *ptr = r_strpool_get (p, index);
	if (ptr) {
		char *q = ptr + strlen (ptr) + 1;
		if (q >= (p->str + p->len)) {
			return NULL;
		}
		ptr = q;
		if (!*ptr) {
			ptr = NULL;
		}
	}
	return ptr;
}

R_API char *r_strpool_slice(RStrpool *p, int index) {
	int idx, len;
	char *o, *x = r_strpool_get_i (p, index + 1);
	if (!x || !*x) {
		return NULL;
	}
	idx = (size_t)(x - p->str);
	len = p->len - idx;
	o = malloc (len + 128);
	if (!o) {
		return NULL;
	}
	memcpy (o, x, len);
	free (p->str);
	p->str = o;
	p->size = len + 128;
	p->len = len;
	return o;
}

#if TEST
int main() {
	RStrpool *p = r_strpool_new (1024);
	printf ("%d\n", r_strpool_append (p, "Hello World"));
	printf ("%d\n", r_strpool_append (p, "Patata Barata"));
	printf ("%s\n", r_strpool_get (p, 12));
	r_strpool_fit (p);
	r_strpool_free (p);
	return 0;
}
#endif
