/* radare - LGPL - Copyright 2012 - pancake */

#include <r_util.h>

R_API RStrpool* r_strpool_new (int sz) {
	RStrpool *p = R_NEW (RStrpool);
	if (sz<1) sz = 1024;
	p->size = sz;
	p->len = 0;
	p->str = malloc (sz);
	if (!p->str) {
		free (p);
		return NULL;
	}
	p->str[0] = 0;
	return p;
}

R_API char *r_strpool_empty (RStrpool *p) {
	p->len = 0;
	p->str[0] = 0;
	p->str[1] = 0;
	return p->str;
}

R_API char *r_strpool_alloc (RStrpool *p, int l) {
	char *ret = p->str+p->len;
	if ((p->len+l)>=p->size) {
		p->size += R_STRPOOL_INC;
		ret = realloc (p->str, p->size);
		if (!ret) return NULL;
		p->str = ret;
		ret += p->len;
	}
	p->len += l;
	return ret;
}

R_API int r_strpool_append(RStrpool *p, const char *s) {
	int l = strlen (s)+1;
	char *ptr = r_strpool_alloc (p, l);
	if (!ptr) return -1;
	memcpy (ptr, s, l);
	return (size_t)(ptr-p->str);
}

R_API void r_strpool_free (RStrpool *p) {
	free (p->str);
	free (p);
}

R_API int r_strpool_fit(RStrpool *p) {
	char *s;
	if (p->len == p->size)
		return R_FALSE;
	s = realloc (p->str, p->len);
	if (!s) return R_FALSE;
	p->str = s;
	p->size = p->len;
	return R_TRUE;
}

R_API char *r_strpool_get(RStrpool *p, int index) {
	if (!p || !p->str || index<0 || index>=p->len)
		return NULL;
	return p->str+index;
}

R_API char *r_strpool_get_i(RStrpool *p, int index) {
	int i, n = 0;
	if (index<0 || index>=p->len)
		return NULL;
	for (i=0; i<index; i++) {
		char *s = r_strpool_next (p, n);
		n = r_strpool_get_index (p, s);
	}
	return p->str+n;
}

R_API int r_strpool_get_index(RStrpool *p, const char *s) {
	int ret = (size_t)(s-p->str);
	return ret>0? ret: 0;
}

R_API char *r_strpool_next(RStrpool *p, int index) {
	char *ptr = r_strpool_get (p, index);
	if (ptr) {
		char *q = ptr + strlen (ptr)+1;
		if (q>=(p->str+p->len))
			return NULL;
		ptr = q;
		if (!*ptr) ptr = NULL;
	}
	return ptr;
}

R_API char *r_strpool_slice (RStrpool *p, int index) {
	int idx, len;
	char *o, *x = r_strpool_get_i (p, index+1);
	if (!x) return NULL;
	idx = (size_t)(x-p->str);
	len = p->len - idx;
	o = malloc (len+128);
	if (!o) return NULL;
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
