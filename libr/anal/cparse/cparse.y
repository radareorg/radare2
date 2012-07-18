%include {
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <r_anal.h>
#include "cdata.h"
}

%syntax_error {
	printf("Syntax error!\n");
}

%name cdataParse

%token_type {Token}
%default_type {Token}

%type source {RAnalType *}
%type deflist {RAnalType *}
%type def {RAnalType *}
%type function {RAnalType *}
%type arglist {RAnalType *}
%type argdef {RAnalType *}
%type struct {RAnalType *}
%type union {RAnalType *}
%type variable {RAnalType *}
%type pointer {RAnalType *}
%type array {RAnalType *}

source(A) ::= deflist(B). { A = B; }
deflist(A) ::= def(B) SEMICOLON deflist(C). { B->next = C; A = B; }
deflist(A) ::= def(B) SEMICOLON. { A = B; }
def(A) ::= function(B). { A = B; }
def(A) ::= struct(B). { A = B; }
def(A) ::= union(B). { A = B; }
def(A) ::= variable(B). { A = B; }
def(A) ::= pointer(B). { A = B; }
def(A) ::= array(B). { A = B; }

function(A) ::= FUNCTION type(B) name(C) LPARENT arglist(D) RPARENT. {
	A = new_function_node(C.sval, B.dval, D, R_ANAL_FMODIFIER_NONE, R_ANAL_CALLCONV_NONE, NULL);
}
function(A) ::= FUNCTION fmodifier(B) type(C) name(D) LPARENT arglist(E) RPARENT. {
	A = new_function_node(D.sval, C.dval, E, B.dval, R_ANAL_CALLCONV_NONE, NULL);
}
function(A) ::= FUNCTION callconvention(B) type(C) name(D) LPARENT arglist(E) RPARENT. {
	A = new_function_node(D.sval, C.dval, E, R_ANAL_FMODIFIER_NONE, B.dval, NULL);
}
function(A) ::= FUNCTION callconvention(B) fmodifier(C) type(D) name(E) LPARENT arglist(F) RPARENT. {
	A = new_function_node(E.sval, D.dval, F, C.dval, B.dval, NULL);
}
function(A) ::= FUNCTION attribute(B) fmodifier(C) type(D) name(E) LPARENT arglist(F) RPARENT. {
	A = new_function_node(E.sval, D.dval, F, C.dval, R_ANAL_CALLCONV_NONE, B.sval);
}
function(A) ::= FUNCTION attribute(B) callconvention(C) fmodifier(D) type(E) name(F) LPARENT arglist(G) RPARENT. {
	A = new_function_node(F.sval, E.dval, G, D.dval, C.dval, B.sval);
}

fmodifier(A) ::= INLINE. { A.sval = "inline"; A.dval = R_ANAL_FMODIFIER_INLINE; }
fmodifier(A) ::= VOLATILE. { A.sval = "volatile"; A.dval = R_ANAL_FMODIFIER_VOLATILE; }
fmodifier(A) ::= STATIC. { A.sval = "static"; A.dval = R_ANAL_FMODIFIER_STATIC; }

callconvention(A) ::= STDCALL. { A.sval = "__stdcall"; A.dval = R_ANAL_CALLCONV_STDCALL; }
callconvention(A) ::= CCALL. { A.sval = "__ccall"; A.dval = R_ANAL_CALLCONV_CCALL; }

attribute(A) ::= ATTRIBUTE LPARENT LPARENT name(B) RPARENT RPARENT. {
	A.sval = B.sval; A.dval = 0;
}

arglist(A) ::= argdef(B) COMMA arglist(C). { B->next = C; A = B; }
arglist(A) ::= argdef(B). { A = B; }
argdef(A) ::= variable(B). { A = B; }
argdef(A) ::= pointer(B). { A = B; }
argdef(A) ::= array(B). { A = B; }

struct(A) ::= STRUCT name(B) OBRACE deflist(C) EBRACE. {
	A = new_struct_node(B.sval, C);
}
union(A) ::= UNION name(B) OBRACE deflist(C) EBRACE. {
	A = new_union_node(B.sval, C);
}
variable(A) ::= modifier(E) signedness(D) type(C) name(B). {
	A = new_variable_node(B.sval, C.dval, D.dval, E.dval);
}
variable(A) ::= modifier(E) shorttype(C) name(B). {
	switch (C.dval) {
		case R_ANAL_UINT8_T:
			A = new_variable_node(B.sval, R_ANAL_TYPE_SHORT, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		case R_ANAL_UINT16_T:
			A = new_variable_node(B.sval, R_ANAL_TYPE_INT, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		case R_ANAL_UINT32_T:
			A = new_variable_node(B.sval, R_ANAL_TYPE_LONG, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		case R_ANAL_UINT64_T:
			A = new_variable_node(B.sval, R_ANAL_TYPE_LONGLONG, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		default:
			break;
	}
}
pointer(A) ::= modifier(E) signedness(D) type(C) ASTERISK name(B). {
	A = new_pointer_node(B.sval, C.dval, D.dval, E.dval);
}
pointer(A) ::= modifier(E) shorttype(C) ASTERISK name(B). {
	switch (C.dval) {
		case R_ANAL_UINT8_T:
			A = new_pointer_node(B.sval, R_ANAL_TYPE_SHORT, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		case R_ANAL_UINT16_T:
			A = new_pointer_node(B.sval, R_ANAL_TYPE_INT, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		case R_ANAL_UINT32_T:
			A = new_pointer_node(B.sval, R_ANAL_TYPE_LONG, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		case R_ANAL_UINT64_T:
			A = new_pointer_node(B.sval, R_ANAL_TYPE_LONGLONG, R_ANAL_TYPE_UNSIGNED, E.dval);
			break;
		default:
			break;
	}
}
array(A) ::= modifier(F) signedness(E) type(D) name(B) LBRACKET size(C) RBRACKET. {
	A = new_array_node(B.sval, D.dval, E.dval, F.dval, C.dval);
}
array(A) ::= modifier(F) shorttype(D) name(B) LBRACKET size(C) RBRACKET. {
	switch (D.dval) {
		case R_ANAL_UINT8_T:
			A = new_array_node(B.sval, R_ANAL_TYPE_SHORT, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
			break;
		case R_ANAL_UINT16_T:
			A = new_array_node(B.sval, R_ANAL_TYPE_INT, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
			break;
		case R_ANAL_UINT32_T:
			A = new_array_node(B.sval, R_ANAL_TYPE_LONG, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
			break;
		case R_ANAL_UINT64_T:
			A = new_array_node(B.sval, R_ANAL_TYPE_LONGLONG, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
			break;
		default:
			break;
	}
}
size(A) ::= NUMBER(B). { A.dval = B.dval; }
type ::= .
type(A) ::= CHAR. { A.sval = "char"; A.dval = R_ANAL_TYPE_CHAR; }
type(A) ::= SHORT. { A.sval = "short"; A.dval = R_ANAL_TYPE_SHORT; }
type(A) ::= INTEGER. { A.sval = "int"; A.dval = R_ANAL_TYPE_INT; }
type(A) ::= LONG. { A.sval = "long"; A.dval = R_ANAL_TYPE_LONG; }
type(A) ::= LONG LONG. { A.sval = "long long"; A.dval = R_ANAL_TYPE_LONGLONG; }
type(A) ::= FLOAT. { A.sval = "float"; A.dval = R_ANAL_TYPE_FLOAT; }
type(A) ::= DOUBLE. { A.sval = "double"; A.dval = R_ANAL_TYPE_DOUBLE; }
type(A) ::= VOID. { A.sval = "void"; A.dval = R_ANAL_TYPE_VOID; }
shorttype(A) ::= UINT8. { A.dval = R_ANAL_UINT8_T; }
shorttype(A) ::= UINT16. { A.dval = R_ANAL_UINT16_T; }
shorttype(A) ::= UINT32. { A.dval = R_ANAL_UINT32_T; }
shorttype(A) ::= UINT64. { A.dval = R_ANAL_UINT64_T; }
signedness(A) ::= . { A.sval = ""; A.dval = NONE_SIGN; }
signedness(A) ::= SIGNED. { A.sval = "signed"; A.dval = R_ANAL_TYPE_SIGNED; }
signedness(A) ::= UNSIGNED. { A.sval = "unsigned"; A.dval = R_ANAL_TYPE_UNSIGNED; }
modifier(A) ::= . { A.sval = ""; A.dval = NONE_MODIFIER; }
modifier(A) ::= STATIC. { A.sval = "static"; A.dval = R_ANAL_VAR_STATIC; }
modifier(A) ::= CONST. {A.sval = "const"; A.dval = R_ANAL_VAR_CONST; }
modifier(A) ::= REGISTER. { A.sval = "register"; A.dval = R_ANAL_VAR_REGISTER; }
modifier(A) ::= VOLATILE. { A.sval = "volatile"; A.dval = R_ANAL_VAR_VOLATILE; }
name(A) ::= IDENTIFIER(B). { A.sval = B.sval; }

