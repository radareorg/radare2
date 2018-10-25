#ifndef LIB_PPCVLE_INTERNAL
#define LIB_PPCVLE_INTERNAL


typedef struct {
	ut16 mask;
	ut16 shr;
	ut16 shl;
	ut16 add;
	ut8 idx;
	ut8 type;
} field_t;

typedef struct {
	const char* name;
	ut32 op;
	ut32 mask;
	ut16 type;
	ut32 anal_op;
	int cond;
	ut16 types[5];
} e_vle_t;

typedef struct {
	const char* name;
	ut16 op;
	ut16 mask;
	ut16 n;
	ut32 anal_op;
	int cond;
	field_t fields[5];
} se_vle_t;

typedef struct {
	const char* name;
	ut32 op;
	ut32 mask;
	ut16 type;
	ut32 anal_op;
	int cond;
	ut16 types[5];
} ppc_t;

#endif