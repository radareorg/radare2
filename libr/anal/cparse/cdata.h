struct Token {
	int dval;
	char* sval;
};

typedef struct Token Token;

#define R_ANAL_TYPE_CHAR		0
#define R_ANAL_TYPE_SHORT		1
#define R_ANAL_TYPE_INT			2
#define R_ANAL_TYPE_LONG		3
#define R_ANAL_TYPE_LONGLONG	4
#define R_ANAL_TYPE_FLOAT		5
#define R_ANAL_TYPE_DOUBLE		6
#define R_ANAL_TYPE_VOID		7
#define R_ANAL_TYPE_SIGNED		8
#define R_ANAL_TYPE_UNSIGNED	9

#define R_ANAL_UINT8_T			1
#define R_ANAL_UINT16_T			2
#define R_ANAL_UINT32_T			3
#define R_ANAL_UINT64_T			4

#define NONE_SIGN				11
#define NONE_MODIFIER			12

#define R_ANAL_VAR_STATIC		0
#define R_ANAL_VAR_CONST		1
#define R_ANAL_VAR_REGISTER		2
#define R_ANAL_VAR_VOLATILE		3

#define R_ANAL_FMODIFIER_NONE	0
#define R_ANAL_FMODIFIER_STATIC	1
#define R_ANAL_FMODIFIER_VOLATILE 2
#define R_ANAL_FMODIFIER_INLINE 3

#define R_ANAL_CALLCONV_NONE 0
#define R_ANAL_CALLCONV_STDCALL 1
#define R_ANAL_CALLCONV_CCALL 2

RAnalType* new_variable_node(char* name, short type, short sign, short modifier);
RAnalType* new_pointer_node(char* name, short type, short sign, short modifier);
RAnalType* new_array_node(char* name, short type, short sign, short modifier, long size);
RAnalType* new_struct_node(char* name, RAnalType *defs);
RAnalType* new_union_node(char* name, RAnalType *defs);
RAnalType* new_function_node(char* name, short ret_type, RAnalType *args, short fmodifier, short callconvention, char* attributes);

int print_tree(RAnalType *tmp);

