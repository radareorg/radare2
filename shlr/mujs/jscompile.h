#ifndef js_compile_h
#define js_compile_h

enum js_OpCode
{
	OP_POP,		/* A -- */
	OP_DUP,		/* A -- A A */
	OP_DUP2,	/* A B -- A B A B */
	OP_ROT2,	/* A B -- B A */
	OP_ROT3,	/* A B C -- C A B */
	OP_ROT4,	/* A B C D -- D A B C */

	OP_INTEGER,	/* -K- (number-32768) */
	OP_NUMBER,	/* -N- <number> */
	OP_STRING,	/* -S- <string> */
	OP_CLOSURE,	/* -F- <closure> */

	OP_NEWARRAY,
	OP_NEWOBJECT,
	OP_NEWREGEXP,	/* -S,opts- <regexp> */

	OP_UNDEF,
	OP_NULL,
	OP_TRUE,
	OP_FALSE,

	OP_THIS,
	OP_CURRENT,	/* currently executing function object */

	OP_GETLOCAL,	/* -K- <value> */
	OP_SETLOCAL,	/* <value> -K- <value> */
	OP_DELLOCAL,	/* -K- false */

	OP_HASVAR,	/* -S- ( <value> | undefined ) */
	OP_GETVAR,	/* -S- <value> */
	OP_SETVAR,	/* <value> -S- <value> */
	OP_DELVAR,	/* -S- <success> */

	OP_IN,		/* <name> <obj> -- <exists?> */

	OP_INITARRAY,	/* <obj> <val> -- <obj> */
	OP_INITPROP,	/* <obj> <key> <val> -- <obj> */
	OP_INITGETTER,	/* <obj> <key> <closure> -- <obj> */
	OP_INITSETTER,	/* <obj> <key> <closure> -- <obj> */

	OP_GETPROP,	/* <obj> <name> -- <value> */
	OP_GETPROP_S,	/* <obj> -S- <value> */
	OP_SETPROP,	/* <obj> <name> <value> -- <value> */
	OP_SETPROP_S,	/* <obj> <value> -S- <value> */
	OP_DELPROP,	/* <obj> <name> -- <success> */
	OP_DELPROP_S,	/* <obj> -S- <success> */

	OP_ITERATOR,	/* <obj> -- <iobj> */
	OP_NEXTITER,	/* <iobj> -- ( <iobj> <name> true | false ) */

	OP_EVAL,	/* <args...> -(numargs)- <returnvalue> */
	OP_CALL,	/* <closure> <this> <args...> -(numargs)- <returnvalue> */
	OP_NEW,		/* <closure> <args...> -(numargs)- <returnvalue> */

	OP_TYPEOF,
	OP_POS,
	OP_NEG,
	OP_BITNOT,
	OP_LOGNOT,
	OP_INC,		/* <x> -- ToNumber(x)+1 */
	OP_DEC,		/* <x> -- ToNumber(x)-1 */
	OP_POSTINC,	/* <x> -- ToNumber(x)+1 ToNumber(x) */
	OP_POSTDEC,	/* <x> -- ToNumber(x)-1 ToNumber(x) */

	OP_MUL,
	OP_DIV,
	OP_MOD,
	OP_ADD,
	OP_SUB,
	OP_SHL,
	OP_SHR,
	OP_USHR,
	OP_LT,
	OP_GT,
	OP_LE,
	OP_GE,
	OP_EQ,
	OP_NE,
	OP_STRICTEQ,
	OP_STRICTNE,
	OP_JCASE,
	OP_BITAND,
	OP_BITXOR,
	OP_BITOR,

	OP_INSTANCEOF,

	OP_THROW,

	OP_TRY,		/* -ADDR- /jump/ or -ADDR- <exception> */
	OP_ENDTRY,

	OP_CATCH,	/* push scope chain with exception variable */
	OP_ENDCATCH,

	OP_WITH,
	OP_ENDWITH,

	OP_DEBUGGER,
	OP_JUMP,
	OP_JTRUE,
	OP_JFALSE,
	OP_RETURN,
};

struct js_Function
{
	const char *name;
	int script;
	int lightweight;
	int strict;
	int arguments;
	int numparams;

	js_Instruction *code;
	int codecap, codelen;

	js_Function **funtab;
	int funcap, funlen;

	const char **vartab;
	int varcap, varlen;

	const char *filename;
	int line, lastline;

	js_Function *gcnext;
	int gcmark;
};

js_Function *jsC_compilefunction(js_State *J, js_Ast *prog);
js_Function *jsC_compilescript(js_State *J, js_Ast *prog, int default_strict);
const char *jsC_opcodestring(enum js_OpCode opcode);
void jsC_dumpfunction(js_State *J, js_Function *fun);

#endif
