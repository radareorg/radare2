#ifndef R_CONSTR_H
#define R_CONSTR_H

typedef struct r_constr_t {
	char *b;
	int l;
	int i;
} RConstr;

R_API RConstr* r_constr_new(int size);
R_API void r_constr_free(RConstr *c);
R_API const char *r_constr_get(RConstr *c, const char *str);
R_API const char *r_constr_append(RConstr *c, const char *str);
R_API const char *r_constr_add(RConstr *c, const char *str);
#endif //  R_CONSTR_H
