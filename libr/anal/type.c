/* WORK IN PROGRESS */

// cast can be done via string serialization
// int -> char r_meta_type_
// ..to_string (meta, type);
// ..from_string()

Ct char* 4 z
Ct void 0
Ct int 4 d
Ct ut32 4 x
Ct ut64 8 q
CFt printf void=char*,...
CFt puts int=char*
CFt system int=char*
CFt exit void=int
CFv [arraysize] [type] [name]
CFa [arraysize] [type] [name]
CFf 320 @ fun -> framesize for function
CF 20 

// how to define a function pointer?
// how to define a structure or complex types?
// how to define arrays?

#include <r_meta.h>

typedef struct r_meta_function_t {
	int stackframe;
	RMetaType ret;
	RMetaType *arg[16]; // Just references to already registered data types
	// when we remove a type, we must ensure no function meta signature claims for it
} RMetaFunction;

typedef struct r_meta_type_t {
	char name[32];
	int sign; // already define by format?
	int size;
	int array; // real size = size * array
	char format[16]; // print format
} RMetaType;

#if 0
Types must allow casting between them
Types must support struct with inner types on it

[0x08049850]> Cv?
Usage: Cv [name] [size] [pm-format-string]
  Cv int 4 d   ; define 'int' type
  Cv- int      ; remove 'int' var type
  Cv float 4 f
#endif

R_API RMetaType *r_meta_type_new() {
	RMetaType *type = R_NEW (RMetaType);
	//
	return type;
}
