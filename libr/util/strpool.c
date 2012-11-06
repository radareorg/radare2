/* radare - LGPL - Copyright 2012 - pancake */

#include <r_util.h>

R_API RStrpool* r_strpool_new (int sz) {
	RStrpool *p = R_NEW (RStrpool);
	p->size = sz;
	p->len = 0;
	p->str = malloc (sz);
	if (!p->str) {
		free (p);
		return NULL;
	}
	return p;
}

R_API char *r_strpool_alloc (RStrpool *p, int l) {
	char *ret = p->str+p->len;
	if ((p->len+l)>=p->size) {
		p->size += R_STRPOOL_INC;
		ret = realloc (p->str, p->size);
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
	if (index<0 || index>=p->len)
		return NULL;
	return p->str+index;
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
