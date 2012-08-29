%include {
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <r_anal.h>
#include "cdata.h"
}

%syntax_error {
	eprintf ("Syntax error!\n");
}

%name cdataParse

%token_type {Token}
%default_type {Token}

%extra_argument { RAnalType *trees }

%type source {RAnalType *}
%type deflist {RAnalType *}
%type def {RAnalType *}
%type function {RAnalType *}
%type arglist {RAnalType *}
%type argdef {RAnalType *}
%type struct {RAnalType *}
%type union {RAnalType *}
%type alloca {RAnalType *}
%type locals {RAnalLocals *}
%type variable {RAnalType *}
%type pointer {RAnalType *}
%type array {RAnalType *}

source(A) ::= deflist(B). {
	A = B;
	/* Add definitions to the list */
	trees->next = A;
}
deflist(A) ::= def(B) SEMICOLON deflist(C). {
	B->next = C;
	A = B;
	/* Add definitions to the list */
}
deflist(A) ::= def(B) SEMICOLON. {
	A = B;
	/* Add definition to the list */
}
def(A) ::= function(B). { A = B; }
def(A) ::= struct(B). { A = B; }
def(A) ::= union(B). { A = B; }
def(A) ::= alloca(B). { A = B; }
def(A) ::= variable(B). { A = B; }
def(A) ::= pointer(B). { A = B; }
def(A) ::= array(B). { A = B; }

function(A) ::= FUNCTION type(B) name(C) LPARENT arglist(D) RPARENT locals(E). {
	A = new_function_node(C.sval, B.dval, D, R_ANAL_FQUALIFIER_NONE, R_ANAL_CC_TYPE_NONE, NULL, E);
}
function(A) ::= FUNCTION fqualifier(B) type(C) name(D) LPARENT arglist(E) RPARENT locals(F). {
	A = new_function_node(D.sval, C.dval, E, B.dval, R_ANAL_CC_TYPE_NONE, NULL, F);
}
function(A) ::= FUNCTION callconvention(B) type(C) name(D) LPARENT arglist(E) RPARENT locals(F). {
	A = new_function_node(D.sval, C.dval, E, R_ANAL_FQUALIFIER_NONE, B.dval, NULL, F);
}
function(A) ::= FUNCTION callconvention(B) fqualifier(C) type(D) name(E) LPARENT arglist(F) RPARENT locals(G). {
	A = new_function_node(E.sval, D.dval, F, C.dval, B.dval, NULL, G);
}
function(A) ::= FUNCTION attribute(B) fqualifier(C) type(D) name(E) LPARENT arglist(F) RPARENT locals(G). {
	A = new_function_node(E.sval, D.dval, F, C.dval, R_ANAL_CC_TYPE_NONE, B.sval, G);
}
function(A) ::= FUNCTION attribute(B) callconvention(C) fqualifier(D) type(E) name(F) LPARENT arglist(G) RPARENT locals(H). {
	A = new_function_node(F.sval, E.dval, G, D.dval, C.dval, B.sval, H);
}

fqualifier(A) ::= INLINE. { A.sval = "inline"; A.dval = R_ANAL_FQUALIFIER_INLINE; }
fqualifier(A) ::= VOLATILE. { A.sval = "volatile"; A.dval = R_ANAL_FQUALIFIER_VOLATILE; }
fqualifier(A) ::= STATIC. { A.sval = "static"; A.dval = R_ANAL_FQUALIFIER_STATIC; }
fqualifier(A) ::= NAKED. { A.sval = "naked"; A.dval = R_ANAL_FQUALIFIER_NAKED; }
fqualifier(A) ::= VIRTUAL. { A.sval = "virtual"; A.dval = R_ANAL_FQUALIFIER_VIRTUAL; }

callconvention(A) ::= STDCALL. { A.sval = "__stdcall"; A.dval = R_ANAL_CC_TYPE_STDCALL; }
callconvention(A) ::= CDECL. { A.sval = "__cdecl"; A.dval = R_ANAL_CC_TYPE_CDECL; }
callconvention(A) ::= FASTCALL. { A.sval = "__fastcall"; A.dval = R_ANAL_CC_TYPE_FASTCALL; }
callconvention(A) ::= PASCALCALL. { A.sval = "__pascal"; A.dval = R_ANAL_CC_TYPE_PASCAL; }
callconvention(A) ::= WINAPI. { A.sval = "WINAPI"; A.dval = R_ANAL_CC_TYPE_WINAPI; }
callconvention(A) ::= THISCALL. { A.sval = "__thiscall"; A.dval = R_ANAL_CC_TYPE_THISCALL; }

attribute(A) ::= ATTRIBUTE LPARENT LPARENT name(B) RPARENT RPARENT. {
	A.sval = B.sval; A.dval = 0;
}

arglist(A) ::= argdef(B) COMMA arglist(C). { B->next = C; A = B; }
arglist(A) ::= argdef(B). { A = B; }
argdef(A) ::= variable(B). { A = B; }
argdef(A) ::= pointer(B). { A = B; }
argdef(A) ::= array(B). { A = B; }

locals ::= .
locals(A) ::= OBRACE deflist (B) EBRACE. {
	A = new_locals_node(B);
}
struct(A) ::= STRUCT name(B) OBRACE deflist(C) EBRACE. {
	A = new_struct_node(B.sval, C);
}
union(A) ::= UNION name(B) OBRACE deflist(C) EBRACE. {
	A = new_union_node(B.sval, C);
}
alloca(A) ::= ALLOCA AT address(B) LPARENT size(C) RPARENT OBRACE deflist(D) EBRACE. {
	A = new_alloca_node(B.dval, C.dval, D);
}
variable(A) ::= qualifier(E) signedness(D) type(C) name(B). {
	A = new_variable_node(B.sval, C.dval, D.dval, E.dval);
}
variable(A) ::= qualifier(E) shorttype(C) name(B). {
	switch (C.dval) {
	case R_ANAL_UINT8_T:
		A = new_variable_node(B.sval, R_ANAL_VAR_TYPE_BYTE, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	case R_ANAL_UINT16_T:
		A = new_variable_node(B.sval, R_ANAL_VAR_TYPE_WORD, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	case R_ANAL_UINT32_T:
		A = new_variable_node(B.sval, R_ANAL_VAR_TYPE_DWORD, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	case R_ANAL_UINT64_T:
		A = new_variable_node(B.sval, R_ANAL_VAR_TYPE_QWORD, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	default:
		break;
	}
}
pointer(A) ::= qualifier(E) signedness(D) type(C) ASTERISK name(B). {
	A = new_pointer_node(B.sval, C.dval, D.dval, E.dval);
}
pointer(A) ::= qualifier(E) shorttype(C) ASTERISK name(B). {
	switch (C.dval) {
	case R_ANAL_UINT8_T:
		A = new_pointer_node(B.sval, R_ANAL_VAR_TYPE_BYTE, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	case R_ANAL_UINT16_T:
		A = new_pointer_node(B.sval, R_ANAL_VAR_TYPE_WORD, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	case R_ANAL_UINT32_T:
		A = new_pointer_node(B.sval, R_ANAL_VAR_TYPE_DWORD, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	case R_ANAL_UINT64_T:
		A = new_pointer_node(B.sval, R_ANAL_VAR_TYPE_QWORD, R_ANAL_TYPE_UNSIGNED, E.dval);
		break;
	default:
		break;
	}
}
array(A) ::= qualifier(F) signedness(E) type(D) name(B) LBRACKET size(C) RBRACKET. {
	A = new_array_node(B.sval, D.dval, E.dval, F.dval, C.dval);
}
array(A) ::= qualifier(F) shorttype(D) name(B) LBRACKET size(C) RBRACKET. {
	switch (D.dval) {
	case R_ANAL_UINT8_T:
		A = new_array_node(B.sval, R_ANAL_VAR_TYPE_BYTE, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
		break;
	case R_ANAL_UINT16_T:
		A = new_array_node(B.sval, R_ANAL_VAR_TYPE_WORD, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
		break;
	case R_ANAL_UINT32_T:
		A = new_array_node(B.sval, R_ANAL_VAR_TYPE_DWORD, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
		break;
	case R_ANAL_UINT64_T:
		A = new_array_node(B.sval, R_ANAL_VAR_TYPE_QWORD, R_ANAL_TYPE_UNSIGNED, F.dval, C.dval);
		break;
	default:
		break;
	}
}
address(A) ::= NUMBER(B). { A.dval = B.dval; }
size(A) ::= NUMBER(B). { A.dval = B.dval; }
type ::= .
type(A) ::= CHAR. { A.sval = "char"; A.dval = R_ANAL_VAR_TYPE_CHAR; }
type(A) ::= BYTE. { A.sval = "byte"; A.dval = R_ANAL_VAR_TYPE_BYTE; }
type(A) ::= WORD. { A.sval = "word"; A.dval = R_ANAL_VAR_TYPE_WORD; }
type(A) ::= DWORD. { A.sval = "dword"; A.dval = R_ANAL_VAR_TYPE_DWORD; }
type(A) ::= QWORD. { A.sval = "qword"; A.dval = R_ANAL_VAR_TYPE_QWORD; }
type(A) ::= SHORT. { A.sval = "short"; A.dval = R_ANAL_VAR_TYPE_SHORT; }
type(A) ::= INTEGER. { A.sval = "int"; A.dval = R_ANAL_VAR_TYPE_INT; }
type(A) ::= LONG. { A.sval = "long"; A.dval = R_ANAL_VAR_TYPE_LONG; }
type(A) ::= LONG LONG. { A.sval = "long long"; A.dval = R_ANAL_VAR_TYPE_LONGLONG; }
type(A) ::= FLOAT. { A.sval = "float"; A.dval = R_ANAL_VAR_TYPE_FLOAT; }
type(A) ::= DOUBLE. { A.sval = "double"; A.dval = R_ANAL_VAR_TYPE_DOUBLE; }
type(A) ::= VOID. { A.sval = "void"; A.dval = R_ANAL_VAR_TYPE_VOID; }
shorttype(A) ::= UINT8. { A.dval = R_ANAL_UINT8_T; }
shorttype(A) ::= UINT16. { A.dval = R_ANAL_UINT16_T; }
shorttype(A) ::= UINT32. { A.dval = R_ANAL_UINT32_T; }
shorttype(A) ::= UINT64. { A.dval = R_ANAL_UINT64_T; }
signedness(A) ::= . { A.sval = ""; A.dval = NONE_SIGN; }
signedness(A) ::= SIGNED. { A.sval = "signed"; A.dval = R_ANAL_TYPE_SIGNED; }
signedness(A) ::= UNSIGNED. { A.sval = "unsigned"; A.dval = R_ANAL_TYPE_UNSIGNED; }
qualifier(A) ::= . { A.sval = ""; A.dval = NONE_QUALIFIER; }
qualifier(A) ::= STATIC. { A.sval = "static"; A.dval = R_ANAL_VAR_STATIC; }
qualifier(A) ::= CONST. {A.sval = "const"; A.dval = R_ANAL_VAR_CONST; }
qualifier(A) ::= REGISTER. { A.sval = "register"; A.dval = R_ANAL_VAR_REGISTER; }
qualifier(A) ::= VOLATILE. { A.sval = "volatile"; A.dval = R_ANAL_VAR_VOLATILE; }
name(A) ::= IDENTIFIER(B). { A.sval = B.sval; }
