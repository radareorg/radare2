#include <r_util.h>

/* constant string storage */

R_API RConstr* r_constr_new (int size) {
	RConstr *c = R_NEW (RConstr);
	c->l = size>0? size: 1024;
	c->b = malloc (c->l);
	c->i = *c->b = 0;
	return c;
}

R_API void r_constr_free (RConstr *c) {
	free (c->b);
	free (c);
}

R_API const char *r_constr_get (RConstr *c, const char *str) {
	char *e = c->b+c->i, *p = c->b;
	for (p = c->b; p<e; p += strlen (p)+1) {
		if (!strcmp (p, str))
			return p;
	}
	return NULL;
}

R_API const char *r_constr_append (RConstr *c, const char *str) {
	int i = c->i, l = strlen (str)+1;
	if ((c->b + i+l) >= (c->b + c->l))
		return NULL;
	memcpy (c->b + i, str, l);
	c->i += l;
	return c->b+i;
}

R_API const char *r_constr_add (RConstr *c, const char *str) {
	char *p = (char *)r_constr_get (c, str);
	return p? p: r_constr_append (c, str);
}

#if MAIN
main() {
	RConstr *cstr = r_constr_new (7);

	printf ("%s\n", r_constr_add (cstr, "Hello"));
	printf ("%s\n", r_constr_add (cstr, "Hello"));
	printf ("%s\n", r_constr_add (cstr, "World"));

	r_constr_free (cstr);
}
#endif
