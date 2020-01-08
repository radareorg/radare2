/* radare - LGPL - Copyright 2009-2019 - pancake, maijin */

#include <r_core.h>

static const char *help_msg_a[] = {
	"Usage:", "a", "[abdefFghoprxstc] [...]",
	"a", "", "alias for aai - analysis information",
	"a*", "", "same as afl*;ah*;ax*",
	"aa", "[?]", "analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
	"a8", " [hexpairs]", "analyze bytes",
	"ab", "[b] [addr]", "analyze block at given address",
	"abb", " [len]", "analyze N basic blocks in [len] (section.size by default)",
	"ac", "[?]", "manage classes",
	"aC", "[?]", "analyze function call",
	"aCe", "[?]", "same as aC, but uses esil with abte to emulate the function",
	"ad", "[?]", "analyze data trampoline (wip)",
	"ad", " [from] [to]", "analyze data pointers to (from-to)",
	"ae", "[?] [expr]", "analyze opcode eval expression (see ao)",
	"af", "[?]", "analyze Functions",
	"aF", "", "same as above, but using anal.depth=1",
	"ag", "[?] [options]", "draw graphs in various formats",
	"ah", "[?]", "analysis hints (force opcode size, ...)",
	"ai", " [addr]", "address information (show perms, stack, heap, ...)",
	"aj", "", "same as a* but in json (aflj)",
	"aL", "", "list all asm/anal plugins (e asm.arch=?)",
	"an"," [name] [@addr]","show/rename/create whatever flag/function is used at addr",
	"ao", "[?] [len]", "analyze Opcodes (or emulate it)",
	"aO", "[?] [len]", "Analyze N instructions in M bytes",
	"ap", "", "find prelude for current offset",
	"ar", "[?]", "like 'dr' but for the esil vm. (registers)",
	"as", "[?] [num]", "analyze syscall using dbg.reg",
	"av", "[?] [.]", "show vtables",
	"ax", "[?]", "manage refs/xrefs (see also afx?)",
	NULL
};

static const char *help_msg_aa[] = {
	"Usage:", "aa[0*?]", " # see also 'af' and 'afna'",
	"aa", " ", "alias for 'af@@ sym.*;af@entry0;afva'", //;.afna @@ fcn.*'",
	"aaa", "[?]", "autoname functions after aa (see afna)",
	"aab", "", "abb across bin.sections.rx",
	"aac", " [len]", "analyze function calls (af @@ `pi len~call[1]`)",
	"aac*", " [len]", "flag function calls without performing a complete analysis",
	"aad", " [len]", "analyze data references to code",
	"aae", " [len] ([addr])", "analyze references with ESIL (optionally to address)",
	"aaf", "[e|r|t] ", "analyze all functions (e anal.hasnext=1;afr @@c:isq) (aafe=aef@@f)",
	"aaF", " [sym*]", "set anal.in=block for all the spaces between flags matching glob",
	"aaFa", " [sym*]", "same as aaF but uses af/a2f instead of af+/afb+ (slower but more accurate)",
	"aai", "[j]", "show info of all analysis parameters",
	"aan", "[gr?]", "autoname functions (aang = golang, aanr = noreturn propagation)",
	"aao", "", "analyze all objc references",
	"aap", "", "find and analyze function preludes",
	"aar", "[?] [len]", "analyze len bytes of instructions for references",
	"aas", " [len]", "analyze symbols (af @@= `isq~[0]`)",
	"aaS", "", "analyze all flags starting with sym. (af @@ sym.*)",
	"aat", " [fcn]", "Analyze all/given function to convert immediate to linked structure offsets (see tl?)",
	"aaT", " [len]", "analyze code after trap-sleds",
	"aau", " [len]", "list mem areas (larger than len bytes) not covered by functions",
	"aav", " [sat]", "find values referencing a specific section or map",
	NULL
};

static const char *help_msg_afls[] = {
	"Usage:", "afls", "[afls] # sort function list",
	"afls", "", "same as aflsa",
	"aflsa", "", "sort by address (same as afls)",
	"aflss", "", "sort by size",
	"aflsn", "", "sort by name",
	"aflsb", "", "sort by number of basic blocks",
	NULL
};

static const char *help_msg_ai[] = {
	"Usage:", "ai", "[j*] [sz] # analysis/address information/imports",
	"aii", " [namespace]", "global import (like afii, but global)",
	"aii", "-", "delete all global imports",
	"ai", " @addr", "show address information",
	NULL
};

static const char *help_msg_aar[] = {
	"Usage:", "aar", "[j*] [sz] # search and analyze xrefs",
	"aar", " [sz]", "analyze xrefs in current section or sz bytes of code",
	"aar*", " [sz]", "list found xrefs in radare commands format",
	"aarj", " [sz]", "list found xrefs in JSON format",
	NULL
};

static const char *help_msg_ab[] = {
	"Usage:", "ab", "",
	"ab", " [addr]", "show basic block information at given address",
	"abb", " [length]", "analyze N bytes and extract basic blocks",
	"abj", " [addr]", "display basic block information in JSON (alias to afbj)",
	"abx", " [hexpair-bytes]", "analyze N bytes",
	"abt[?]", " [addr] [num]", "find num paths from current offset to addr",
	NULL
};

static const char *help_msg_abt[] = {
	"Usage:", "abt", "[addr] [num] # find num paths from current offset to addr",
	"abt", " [addr] [num]", "find num paths from current offset to addr",
	"abte", " [addr]", "emulate from begining of function to the given address",
	"abtj", " [addr] [num]", "display paths in JSON",
	NULL
};

static const char *help_msg_ac[] = {
	"Usage:", "ac", "anal classes commands",
	"acl[lj*]", "", "list all classes",
	"ac", " [class name]", "add class",
	"ac-", " [class name]", "delete class",
	"acn", " [class name] [new class name]", "rename class",
	"acv", " [class name] [addr] ([offset])", "add vtable address to class",
	"acv-", " [class name] [vtable id]", "delete vtable by id (from acv [class name])",
	"acb", " [class name]", "list bases of class",
	"acb", " [class name] [base class name] ([offset])", "add base class",
	"acb-", " [class name] [base class id]", "delete base by id (from acb [class name])",
	"acm", " [class name] [method name] [offset] ([vtable offset])", "add/edit method",
	"acm-", " [class name] [method name]", "delete method",
	"acmn", " [class name] [method name] [new name]", "rename method",
	"ac?", "", "show this help",
	NULL
};

static const char *help_msg_ad[] = {
	"Usage:", "ad", "[kt] [...]",
	"ad", " [N] [D]", "analyze N data words at D depth",
	"ad4", " [N] [D]", "analyze N data words at D depth (asm.bits=32)",
	"ad8", " [N] [D]", "analyze N data words at D depth (asm.bits=64)",
	"adf", "", "analyze data in function (use like .adf @@=`afl~[0]`",
	"adfg", "", "analyze data in function gaps",
	"adt", "", "analyze data trampolines (wip)",
	"adk", "", "analyze data kind (code, text, data, invalid, ...)",
	NULL
};

static const char *help_msg_ae[] = {
	"Usage:", "ae[idesr?] [arg]", "ESIL code emulation",
	"ae", " [expr]", "evaluate ESIL expression",
	"ae?", "", "show this help",
	"ae??", "", "show ESIL help",
	"ae[aA]", "[f] [count]", "analyse esil accesses (regs, mem..)",
	"aeC", "[arg0 arg1..] @ addr", "appcall in esil",
	"aec", "[?]", "continue until ^C",
	"aecs", "", "continue until syscall",
	"aecc", "", "continue until call",
	"aecu", " [addr]", "continue until address",
	"aecue", " [esil]", "continue until esil expression match",
	"aef", " [addr]", "emulate function",
	"aefa", " [addr]", "emulate function to find out args in given or current offset",
	"aeg", " [expr]", "esil graph",
	"aei", "", "initialize ESIL VM state (aei- to deinitialize)",
	"aeim", " [addr] [size] [name]", "initialize ESIL VM stack (aeim- remove)",
	"aeip", "", "initialize ESIL program counter to curseek",
	"aek", " [query]", "perform sdb query on ESIL.info",
	"aek-", "", "resets the ESIL.info sdb instance",
	"aeli", "", "list loaded ESIL interrupts",
	"aeli", " [file]", "load ESIL interrupts from shared object",
	"aelir", " [interrupt number]", "remove ESIL interrupt and free it if needed",
	"aep", "[?] [addr]", "manage esil pin hooks",
	"aepc", " [addr]", "change esil PC to this address",
	"aer", " [..]", "handle ESIL registers like 'ar' or 'dr' does",
	"aets", "[?]", "ESIL Trace session",
	"aes", "", "perform emulated debugger step",
	"aesp", " [X] [N]", "evaluate N instr from offset X",
	"aesb", "", "step back",
	"aeso", " ", "step over",
	"aesou", " [addr]", "step over until given address",
	"aess", " ", "step skip (in case of CALL, just skip, instead of step into)",
	"aesu", " [addr]", "step until given address",
	"aesue", " [esil]", "step until esil expression match",
	"aesuo", " [optype]", "step until given opcode type",
	"aetr", "[esil]", "Convert an ESIL Expression to REIL",
	"aex", " [hex]", "evaluate opcode expression",
	NULL
};

static const char *help_detail_ae[] = {
	"Examples:", "ESIL", " examples and documentation",
	"=", "", "assign updating internal flags",
	":=", "", "assign without updating internal flags",
	"+=", "", "A+=B => B,A,+=",
	"+", "", "A=A+B => B,A,+,A,=",
	"++", "", "increment, 2,A,++ == 3 (see rsi,--=[1], ... )",
	"--", "", "decrement, 2,A,-- == 1",
	"*=", "", "A*=B => B,A,*=",
	"/=", "", "A/=B => B,A,/=",
	"%=", "", "A%=B => B,A,%=",
	"&=", "", "and ax, bx => bx,ax,&=",
	"|", "", "or r0, r1, r2 => r2,r1,|,r0,=",
	"!=", "", "negate all bits",
	"^=", "", "xor ax, bx => bx,ax,^=",
	"", "[]", "mov eax,[eax] => eax,[],eax,=",
	"=", "[]", "mov [eax+3], 1 => 1,3,eax,+,=[]",
	"=", "[1]", "mov byte[eax],1 => 1,eax,=[1]",
	"=", "[8]", "mov [rax],1 => 1,rax,=[8]",
	"[]", "", "peek from random position",
	"[N]", "", "peek word of N bytes from popped address",
	"[*]", "", "peek some from random position",
	"=", "[*]", "poke some at random position",
	"$", "", "int 0x80 => 0x80,$",
	"$$", "", "simulate a hardware trap",
	"==", "", "pops twice, compare and update esil flags",
	"<", "", "compare for smaller",
	"<=", "", "compare for smaller or equal",
	">", "", "compare for bigger",
	">=", "", "compare bigger for or equal",
	">>=", "", "shr ax, bx => bx,ax,>>=  # shift right",
	"<<=", "", "shl ax, bx => bx,ax,<<=  # shift left",
	">>>=", "", "ror ax, bx => bx,ax,>>>=  # rotate right",
	"<<<=", "", "rol ax, bx => bx,ax,<<<=  # rotate left",
	"?{", "", "if popped value != 0 run the block until }",
	"POP", "", "drops last element in the esil stack",
	"DUP", "", "duplicate last value in stack",
	"NUM", "", "evaluate last item in stack to number",
	"SWAP", "", "swap last two values in stack",
	"TRAP", "", "stop execution",
	"BITS", "", "16,BITS  # change bits, useful for arm/thumb",
	"TODO", "", "the instruction is not yet esilized",
	"STACK", "", "show contents of stack",
	"CLEAR", "", "clears the esil stack",
	"REPEAT", "", "repeat n times",
	"BREAK", "", "terminates the string parsing",
	"SETJT", "", "set jump target",
	"SETJTS", "", "set jump target set",
	"SETD", "", "set delay slot",
	"GOTO", "", "jump to the Nth word popped from the stack",
	"$", "", "esil interrupt",
	"$z", "", "internal flag: zero",
	"$c", "", "internal flag: carry",
	"$b", "", "internal flag: borrow",
	"$p", "", "internal flag: parity",
	"$s", "", "internal flag: sign",
	"$o", "", "internal flag: overflow",
	"$ds", "", "internal flag: delay-slot",
	"$jt", "", "internal flag: jump-target",
	"$js", "", "internal flag: jump-target-set",
	// DEPRECATED "$r", "", "internal flag: jump-sign",
	"$$", "", "internal flag: pc address",
	NULL
};

static const char *help_msg_aea[] = {
	"Examples:", "aea", " show regs and memory accesses used in a range",
	"aea", "  [ops]", "Show regs/memory accesses used in N instructions ",
	"aea*", " [ops]", "Create mem.* flags for memory accesses",
	"aeaf", "", "Show regs used in current function",
	"aear", " [ops]", "Show regs read in N instructions",
	"aeaw", " [ops]", "Show regs written in N instructions",
	"aean", " [ops]", "Show regs not written in N instructions",
	"aeaj", " [ops]", "Show aea output in JSON format",
	"aeA", "  [len]", "Show regs used in N bytes (subcommands are the same)",
	"Legend:", "", "",
	"I", "", "input registers (read before being set)",
	"A", "", "all regs accessed",
	"R", "", "register values read",
	"W", "", "registers written",
	"N", "", "not written",
	"@R", "", "memreads",
	"@W", "", "memwrites",
	"NOTE:", "", "mem{reads,writes} with PIC only fetch the offset",
	NULL
};

static const char *help_msg_aec[] = {
	"Examples:", "aec", " continue until ^c",
	"aec", "", "Continue until exception",
	"aecs", "", "Continue until syscall",
	"aecc", "", "Continue until call",
	"aecu", "[addr]", "Continue until address",
	"aecue", "[addr]", "Continue until esil expression",
	NULL
};

static const char *help_msg_aeC[] = {
	"Examples:", "aeC", " arg0 arg1 ... @ calladdr",
	"aeC", " 1 2 @ sym._add", "Call sym._add(1,2)",
	NULL
};

static const char *help_msg_aep[] = {
	"Usage:", "aep[-c] ", " [...]",
	"aepc", " [addr]", "change program counter for esil",
	"aep", "-[addr]", "remove pin",
	"aep", " [name] @ [addr]", "set pin",
	"aep", "", "list pins",
	NULL
};

static const char *help_msg_aets[] = {
	"Usage:", "aets ", " [...]",
	"aets", "", "List all ESIL trace sessions",
	"aets+", "", "Add ESIL trace session",
	NULL
};

static const char *help_msg_af[] = {
	"Usage:", "af", "",
	"af", " ([name]) ([addr])", "analyze functions (start at addr or $$)",
	"afr", " ([name]) ([addr])", "analyze functions recursively",
	"af+", " addr name [type] [diff]", "hand craft a function (requires afb+)",
	"af-", " [addr]", "clean all function analysis data (or function at addr)",
	"afa", "", "analyze function arguments in a call (afal honors dbg.funcarg)",
	"afb+", " fcnA bbA sz [j] [f] ([t]( [d]))", "add bb to function @ fcnaddr",
	"afb", "[?] [addr]", "List basic blocks of given function",
	"afbF", "([0|1])", "Toggle the basic-block 'folded' attribute",
	"afB", " 16", "set current function as thumb (change asm.bits)",
	"afC[lc]", " ([addr])@[addr]", "calculate the Cycles (afC) or Cyclomatic Complexity (afCc)",
	"afc", "[?] type @[addr]", "set calling convention for function",
	"afd", "[addr]","show function + delta for given offset",
	"aff", "", "re-adjust function boundaries to fit",
	"afF", "[1|0|]", "fold/unfold/toggle",
	"afi", " [addr|fcn.name]", "show function(s) information (verbose afl)",
	"afj", " [tableaddr] [count]", "analyze function jumptable",
	"afl", "[?] [ls*] [fcn name]", "list functions (addr, size, bbs, name) (see afll)",
	"afm", " name", "merge two functions",
	"afM", " name", "print functions map",
	"afn", "[?] name [addr]", "rename name for function at address (change flag too)",
	"afna", "", "suggest automatic name for current offset",
	"afo", "[?j] [fcn.name]", "show address for the function name or current offset",
	"afs", "[!] ([fcnsign])", "get/set function signature at current address (afs! uses cfg.editor)",
	"afS", "[stack_size]", "set stack frame size for function at current address",
	"afsr", " [function_name] [new_type]", "change type for given function",
	"aft", "[?]", "type matching, type propagation",
	"afu", " addr", "resize and analyze function from current address until addr",
	"afv[bsra]", "?", "manipulate args, registers and variables in function",
	"afx", "", "list function references",
	NULL
};

static const char *help_msg_afb[] = {
	"Usage:", "afb", " List basic blocks of given function",
	".afbr-", "", "Set breakpoint on every return address of the function",
	".afbr-*", "", "Remove breakpoint on every return address of the function",
	"afb", " [addr]", "list basic blocks of function",
	"afb.", " [addr]", "show info of current basic block",
	"afb=", "", "display ascii-art bars for basic block regions",
	"afb+", " fcn_at bbat bbsz [jump] [fail] ([diff])", "add basic block by hand",
	"afbc", " [addr] [color(ut32)]", "set a color for the bb at a given address",
	"afbe", " bbfrom bbto", "add basic-block edge for switch-cases",
	"afbi", "", "print current basic block information",
	"afbj", " [addr]", "show basic blocks information in json",
	"afbr", "", "Show addresses of instructions which leave the function",
	"afbt", "", "Show basic blocks of current function in a table",
	"afB", " [bits]", "define asm.bits for the given function",
	NULL
};

static const char *help_msg_afc[] = {
	"Usage:", "afc[agl?]", "",
	"afc", " convention", "Manually set calling convention for current function",
	"afc", "", "Show Calling convention for the Current function",
	"afc=", "([cctype])", "Select or show default calling convention",
	"afcr", "[j]", "Show register usage for the current function",
	"afca", "", "Analyse function for finding the current calling convention",
	"afcf", "[j] [name]", "Prints return type function(arg1, arg2...), see afij",
	"afck", "", "List SDB details of call loaded calling conventions",
	"afcl", "", "List all available calling conventions",
	"afco", " path", "Open Calling Convention sdb profile from given path",
	"afcR", "", "Register telescoping using the calling conventions order",
	NULL
};

static const char *help_msg_afC[] = {
	"Usage:", "afC", " [addr]",
	"afC", "", "function cycles cost",
	"afCc", "", "cyclomatic complexity",
	"afCl", "", "loop count (backward jumps)",
	NULL
};

static const char *help_msg_afi[] = {
	"Usage:", "afi[jlp*]", " <addr>",
	"afi", "", "show information of the function",
	"afii", "[-][import]", "show/add/delete imports used in function",
	"afi.", "", "show function name in current offset",
	"afi*", "", "function, variables and arguments",
	"afij", "", "function info in json format",
	"afil", "", "verbose function info",
	"afip", "", "show whether the function is pure or not",
	NULL
};

static const char *help_msg_afl[] = {
	"Usage:", "afl", " List all functions",
	"afl", "", "list functions",
	"afl.", "", "display function in current offset (see afi.)",
	"afl+", "", "display sum all function sizes",
	"afl=", "", "display ascii-art bars with function ranges",
	"aflc", "", "count of functions",
	"aflj", "", "list functions in json",
	"aflt", " [query]", "list functions in table format",
	"afll", " [column]", "list functions in verbose mode (sorted by column name)",
	"afllj", "", "list functions in verbose mode (alias to aflj)",
	"aflm", "", "list functions in makefile style (af@@=`aflm~0x`)",
	"aflq", "", "list functions in quiet mode",
	"aflqj", "", "list functions in json quiet mode",
	"afls", "[?asn]", "sort function list by address, size or name",
	NULL
};

static const char *help_msg_afll[] = {
	"Usage:", "", " List functions in verbose mode",
	"", "", "",
	"Table fields:", "", "",
	"", "", "",
	"address", "", "start address",
	"size", "", "function size (realsize)",
	"nbbs", "", "number of basic blocks",
	"edges", "", "number of edges between basic blocks",
	"cc", "", "cyclomatic complexity ( cc = edges - blocks + 2 * exit_blocks)",
	"cost", "", "cyclomatic cost",
	"min bound", "", "minimal address",
	"range", "", "function size",
	"max bound", "", "maximal address",
	"calls", "", "number of caller functions",
	"locals", "", "number of local variables",
	"args", "", "number of function arguments",
	"xref", "", "number of cross references",
	"frame", "", "function stack size",
	"name", "", "function name",
	NULL
};

static const char *help_msg_afn[] = {
	"Usage:", "afn[sa]", " Analyze function names",
	"afn", " [name]", "rename the function",
	"afn", " base64:encodedname", "rename the function",
	"afn.", "", "same as afn without arguments. show the function name in current offset",
	"afna", "", "construct a function name for the current offset",
	"afns", "", "list all strings associated with the current function",
	"afnsj", "", "list all strings associated with the current function in JSON format",
	NULL
};

static const char *help_msg_afs[] = {
	"Usage:", "afs[r]", " Analyze function signatures",
	"afs", "[!] ([fcnsign])", "get/set function signature at current address (afs! uses cfg.editor)",
	"afsr", " [function_name] [new_type]", "change type for given function",
	NULL
};

static const char *help_msg_aft[] = {
	"Usage:", "aft", "",
	"aft", "", "type matching analysis for current function",
	NULL
};

static const char *help_msg_afv[] = {
	"Usage:", "afv","[rbs]",
	"afvr", "[?]", "manipulate register based arguments",
	"afvb", "[?]", "manipulate bp based arguments/locals",
	"afvs", "[?]", "manipulate sp based arguments/locals",
	"afv*", "", "output r2 command to add args/locals to flagspace",
	"afvR", " [varname]", "list addresses where vars are accessed (READ)",
	"afvW", " [varname]", "list addresses where vars are accessed (WRITE)",
	"afva", "", "analyze function arguments/locals",
	"afvd", " name", "output r2 command for displaying the value of args/locals in the debugger",
	"afvn", " [new_name] ([old_name])", "rename argument/local",
	"afvt", " [name] [new_type]", "change type for given argument/local",
	"afvf", "", "show BP relative stackframe variables",
	"afv-", "([name])", "remove all or given var",
	NULL
};

static const char *help_msg_afvb[] = {
	"Usage:", "afvb", " [idx] [name] ([type])",
	"afvb", "", "list base pointer based arguments, locals",
	"afvb*", "", "same as afvb but in r2 commands",
	"afvb", " [idx] [name] ([type])", "define base pointer based arguments, locals",
	"afvbj", "", "return list of base pointer based arguments, locals in JSON format",
	"afvb-", " [name]", "delete argument/locals at the given name",
	"afvbg", " [idx] [addr]", "define var get reference",
	"afvbs", " [idx] [addr]", "define var set reference",
	NULL
};

static const char *help_msg_afvr[] = {
	"Usage:", "afvr", " [reg] [type] [name]",
	"afvr", "", "list register based arguments",
	"afvr*", "", "same as afvr but in r2 commands",
	"afvr", " [reg] [name] ([type])", "define register arguments",
	"afvrj", "", "return list of register arguments in JSON format",
	"afvr-", " [name]", "delete register arguments at the given index",
	"afvrg", " [reg] [addr]", "define argument get reference",
	"afvrs", " [reg] [addr]", "define argument set reference",
	NULL
};

static const char *help_msg_afvs[] = {
	"Usage:", "afvs", " [idx] [type] [name]",
	"afvs", "", "list stack based arguments and locals",
	"afvs*", "", "same as afvs but in r2 commands",
	"afvs", " [idx] [name] [type]", "define stack based arguments,locals",
	"afvsj", "", "return list of stack based arguments and locals in JSON format",
	"afvs-", " [name]", "delete stack based argument or locals with the given name",
	"afvsg", " [idx] [addr]", "define var get reference",
	"afvss", " [idx] [addr]", "define var set reference",
	NULL
};

static const char *help_msg_ag[] = {
	"Usage:", "ag<graphtype><format> [addr]", "",
	"Graph commands:", "", "",
	"aga", "[format]", "Data references graph",
	"agA", "[format]", "Global data references graph",
	"agc", "[format]", "Function callgraph",
	"agC", "[format]", "Global callgraph",
	"agd", "[format] [fcn addr]", "Diff graph",
	"agf", "[format]", "Basic blocks function graph",
	"agi", "[format]", "Imports graph",
	"agr", "[format]", "References graph",
	"agR", "[format]", "Global references graph",
	"agx", "[format]", "Cross references graph",
	"agg", "[format]", "Custom graph",
	"ag-", "", "Clear the custom graph",
	"agn", "[?] title body", "Add a node to the custom graph",
	"age", "[?] title1 title2", "Add an edge to the custom graph",
	"","","",
	"Output formats:", "", "",
	"<blank>", "", "Ascii art",
	"*", "", "r2 commands",
	"d", "", "Graphviz dot",
	"g", "", "Graph Modelling Language (gml)",
	"j", "", "json ('J' for formatted disassembly)",
	"k", "", "SDB key-value",
	"t", "", "Tiny ascii art",
	"v", "", "Interactive ascii art",
	"w", " [path]", "Write to path or display graph image (see graph.gv.format and graph.web)",
	NULL
};

static const char *help_msg_age[] = {
	"Usage:", "age [title1] [title2]", "",
	"Examples:", "", "",
	"age", " title1 title2", "Add an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age", " \"title1 with spaces\" title2", "Add an edge from node \"title1 with spaces\" to node \"title2\"",
	"age-", " title1 title2", "Remove an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age?", "", "Show this help",
	NULL
};

static const char *help_msg_agn[] = {
	"Usage:", "agn [title] [body]", "",
	"Examples:", "", "",
	"agn", " title1 body1", "Add a node with title \"title1\" and body \"body1\"",
	"agn", " \"title with space\" \"body with space\"", "Add a node with spaces in the title and in the body",
	"agn", " title1 base64:Ym9keTE=", "Add a node with the body specified as base64",
	"agn-", " title1", "Remove a node with title \"title1\"",
	"agn?", "", "Show this help",
	NULL
};

static const char *help_msg_ah[] = {
	"Usage:", "ah[lba-]", "Analysis Hints",
	"ah?", "", "show this help",
	"ah?", " offset", "show hint of given offset",
	"ah", "", "list hints in human-readable format",
	"ah.", "", "list hints in human-readable format from current offset",
	"ah-", "", "remove all hints",
	"ah-", " offset [size]", "remove hints at given offset",
	"ah*", " offset", "list hints in radare commands format",
	"aha", " ppc 51", "set arch for a range of N bytes",
	"ahb", " 16 @ $$", "force 16bit for current instruction",
	"ahc", " 0x804804", "override call/jump address",
	"ahd", " foo a0,33", "replace opcode string",
	"ahe", " 3,eax,+=", "set vm analysis string",
	"ahf", " 0x804840", "override fallback address for call",
	"ahF", " 0x10", "set stackframe size at current offset",
	"ahh", " 0x804840", "highlight this address offset in disasm",
	"ahi", "[?] 10", "define numeric base for immediates (1, 8, 10, 16, s)",
	"ahj", "", "list hints in JSON",
	"aho", " call", "change opcode type (see aho?) (deprecated, moved to \"ahd\")",
	"ahp", " addr", "set pointer hint",
	"ahr", " val", "set hint for return value of a function",
	"ahs", " 4", "set opcode size=4",
	"ahS", " jz", "set asm.syntax=jz for this opcode",
	"aht", " [?] <type>", "Mark immediate as a type offset (deprecated, moved to \"aho\")",
	"ahv", " val", "change opcode's val field (useful to set jmptbl sizes in jmp rax)",
	NULL
};

static const char *help_msg_ahi[] = {
	"Usage:", "ahi [sbodh] [@ offset]", " Define numeric base",
	"ahi", " [base]", "set numeric base (1, 2, 8, 10, 16)",
	"ahi", " b", "set base to binary (2)",
	"ahi", " d", "set base to decimal (10)",
	"ahi", " h", "set base to hexadecimal (16)",
	"ahi", " o", "set base to octal (8)",
	"ahi", " p", "set base to htons(port) (3)",
	"ahi", " i", "set base to IP address (32)",
	"ahi", " S", "set base to syscall (80)",
	"ahi", " s", "set base to string (1)",
	NULL
};

static const char *help_msg_aht[] = {
	"Usage: aht[...]", "", "",
	"ahts", " <offset>", "List all matching structure offsets",
	"aht", " <struct.member>", "Change immediate to structure offset",
	"aht?", "", "show this help",
	NULL
};

static const char *help_msg_ao[] = {
	"Usage:", "ao[e?] [len]", "Analyze Opcodes",
	"aoj", " N", "display opcode analysis information in JSON for N opcodes",
	"aoe", " N", "display esil form for N opcodes",
	"aor", " N", "display reil form for N opcodes",
	"aos", " N", "display size of N opcodes",
	"aom", " [id]", "list current or all mnemonics for current arch",
	"aod", " [mnemonic]", "describe opcode for asm.arch",
	"aoda", "", "show all mnemonic descriptions",
	"aoc", " [cycles]", "analyze which op could be executed in [cycles]",
	"ao", " 5", "display opcode analysis of 5 opcodes",
	"ao*", "", "display opcode in r commands",
	NULL
};

static const char *help_msg_ar[] = {
	"Usage: ar", "", "# Analysis Registers",
	"ar", "", "Show 'gpr' registers",
	"ar.", ">$snapshot", "Show r2 commands to set register values to the current state",
	".ar*", "", "Import register values as flags",
	".ar-", "", "Unflag all registers",
	"ar0", "", "Reset register arenas to 0",
	"ara", "[?]", "Manage register arenas",
	"arA", "", "Show values of function argument calls (A0, A1, A2, ..)",
	"ar", " 16", "Show 16 bit registers",
	"ar", " 32", "Show 32 bit registers",
	"ar", " all", "Show all bit registers",
	"ar", " <type>", "Show all registers of given type",
	"arC", "", "Display register profile comments",
	"arr", "", "Show register references (telescoping)",
	"arrj", "", "Show register references (telescoping) in JSON format",
	"ar=", "([size])(:[regs])", "Show register values in columns",
	"ar?", " <reg>", "Show register value",
	"arb", " <type>", "Display hexdump of the given arena",
	"arc", " <name>", "Conditional flag registers",
	"ard", " <name>", "Show only different registers",
	"arn", " <regalias>", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
	"aro", "", "Show old (previous) register values",
	"arp", "[?] <file>", "Load register profile from file",
	"ars", "", "Stack register state",
	"art", "", "List all register types",
	"arw", " <hexnum>", "Set contents of the register arena",
	NULL
};

static const char *help_msg_ara[] = {
	"Usage:", "ara[+-s]", "Register Arena Push/Pop/Swap",
	"ara", "", "show all register arenas allocated",
	"ara", "+", "push a new register arena for each type",
	"ara", "-", "pop last register arena",
	"aras", "", "swap last two register arenas",
	NULL
};

static const char *help_msg_arw[] = {
	"Usage:", "arw ", "# Set contents of the register arena",
	"arw", " <hexnum>", "Set contents of the register arena",
	NULL
};

static const char *help_msg_as[] = {
	"Usage: as[ljk?]", "", "syscall name <-> number utility",
	"as", "", "show current syscall and arguments",
	"as", " 4", "show syscall 4 based on asm.os and current regs/mem",
	"asc[a]", " 4", "dump syscall info in .asm or .h",
	"asf", " [k[=[v]]]", "list/set/unset pf function signatures (see fcnsign)",
	"asj", "", "list of syscalls in JSON",
	"asl", "", "list of syscalls by asm.os and asm.arch",
	"asl", " close", "returns the syscall number for close",
	"asl", " 4", "returns the name of the syscall number 4",
	"ask", " [query]", "perform syscall/ queries",
	NULL
};

static const char *help_msg_av[] = {
	"Usage:", "av[?jr*]", " C++ vtables and RTTI",
	"av", "", "search for vtables in data sections and show results",
	"avj", "", "like av, but as json",
	"av*", "", "like av, but as r2 commands",
	"avr", "[j@addr]", "try to parse RTTI at vtable addr (see anal.cpp.abi)",
	"avra", "[j]", "search for vtables and try to parse RTTI at each of them",
	"avrr", "", "recover class info from all findable RTTI (see ac)",
	"avrD", " [classname]", "demangle a class name from RTTI",
	NULL
};

static const char *help_msg_ax[] = {
	"Usage:", "ax[?d-l*]", " # see also 'afx?'",
	"ax", "", "list refs",
	"ax*", "", "output radare commands",
	"ax", " addr [at]", "add code ref pointing to addr (from curseek)",
	"ax-", " [at]", "clean all refs/refs from addr",
	"ax-*", "", "clean all refs/refs",
	"axc", " addr [at]", "add generic code ref",
	"axC", " addr [at]", "add code call ref",
	"axg", " [addr]", "show xrefs graph to reach current function",
	"axg*", " [addr]", "show xrefs graph to given address, use .axg*;aggv",
	"axgj", " [addr]", "show xrefs graph to reach current function in json format",
	"axd", " addr [at]", "add data ref",
	"axq", "", "list refs in quiet/human-readable format",
	"axj", "", "list refs in json format",
	"axF", " [flg-glob]", "find data/code references of flags",
	"axm", " addr [at]", "copy data/code references pointing to addr to also point to curseek (or at)",
	"axt", " [addr]", "find data/code references to this address",
	"axf", " [addr]", "find data/code references from this address",
	"ax.", " [addr]", "find data/code references from and to this address",
	"axff[j]", " [addr]", "find data/code references from this function",
	"axs", " addr [at]", "add string ref",
	NULL
};

static void cmd_anal_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, a);
	DEFINE_CMD_DESCRIPTOR (core, aa);
	DEFINE_CMD_DESCRIPTOR (core, aar);
	DEFINE_CMD_DESCRIPTOR (core, ab);
	DEFINE_CMD_DESCRIPTOR (core, ac);
	DEFINE_CMD_DESCRIPTOR (core, ad);
	DEFINE_CMD_DESCRIPTOR (core, ae);
	DEFINE_CMD_DESCRIPTOR (core, aea);
	DEFINE_CMD_DESCRIPTOR (core, aec);
	DEFINE_CMD_DESCRIPTOR (core, aep);
	DEFINE_CMD_DESCRIPTOR (core, af);
	DEFINE_CMD_DESCRIPTOR (core, afb);
	DEFINE_CMD_DESCRIPTOR (core, afc);
	DEFINE_CMD_DESCRIPTOR (core, afC);
	DEFINE_CMD_DESCRIPTOR (core, afi);
	DEFINE_CMD_DESCRIPTOR (core, afl);
	DEFINE_CMD_DESCRIPTOR (core, afll);
	DEFINE_CMD_DESCRIPTOR (core, afn);
	DEFINE_CMD_DESCRIPTOR (core, aft);
	DEFINE_CMD_DESCRIPTOR (core, afv);
	DEFINE_CMD_DESCRIPTOR (core, afvb);
	DEFINE_CMD_DESCRIPTOR (core, afvr);
	DEFINE_CMD_DESCRIPTOR (core, afvs);
	DEFINE_CMD_DESCRIPTOR (core, ag);
	DEFINE_CMD_DESCRIPTOR (core, age);
	DEFINE_CMD_DESCRIPTOR (core, agn);
	DEFINE_CMD_DESCRIPTOR (core, ah);
	DEFINE_CMD_DESCRIPTOR (core, ahi);
	DEFINE_CMD_DESCRIPTOR (core, ao);
	DEFINE_CMD_DESCRIPTOR (core, ar);
	DEFINE_CMD_DESCRIPTOR (core, ara);
	DEFINE_CMD_DESCRIPTOR (core, arw);
	DEFINE_CMD_DESCRIPTOR (core, as);
	DEFINE_CMD_DESCRIPTOR (core, ax);
}

static int cmpname (const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	return (int)strcmp (a->name, b->name);
}

static int cmpsize (const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int sa = (int)r_anal_fcn_size (a);
	int sb = (int)r_anal_fcn_size (b);
	return (sa > sb)? -1: (sa < sb)? 1 : 0;
}

static int cmpbbs (const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int la = (int)r_list_length (a->bbs);
	int lb = (int)r_list_length (b->bbs);
	return (la > lb)? -1: (la < lb)? 1 : 0;
}

static int cmpaddr (const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	return (a->addr > b->addr)? 1: (a->addr <b->addr)? -1: 0;
}

static int listOpDescriptions(void *_core, const char *k, const char *v) {
        r_cons_printf ("%s=%s\n", k, v);
        return 1;
}

/* better aac for windows-x86-32 */
#define JAYRO_03 0

#if JAYRO_03

static bool anal_is_bad_call(RCore *core, ut64 from, ut64 to, ut64 addr, ut8 *buf, int bufi) {
	ut64 align = R_ABS (addr % PE_ALIGN);
	ut32 call_bytes;

	// XXX this is x86 specific
	if (align == 0) {
		call_bytes = (ut32)((ut8*)buf)[bufi + 3] << 24;
		call_bytes |= (ut32)((ut8*)buf)[bufi + 2] << 16;
		call_bytes |= (ut32)((ut8*)buf)[bufi + 1] << 8;
		call_bytes |= (ut32)((ut8*)buf)[bufi];
	} else {
		call_bytes = (ut32)((ut8*)buf)[bufi - align + 3] << 24;
		call_bytes |= (ut32)((ut8*)buf)[bufi - align + 2] << 16;
		call_bytes |= (ut32)((ut8*)buf)[bufi - align + 1] << 8;
		call_bytes |= (ut32)((ut8*)buf)[bufi - align];
	}
	if (call_bytes >= from && call_bytes <= to) {
		return true;
	}
	call_bytes = (ut32)((ut8*)buf)[bufi + 4] << 24;
	call_bytes |= (ut32)((ut8*)buf)[bufi + 3] << 16;
	call_bytes |= (ut32)((ut8*)buf)[bufi + 2] << 8;
	call_bytes |= (ut32)((ut8*)buf)[bufi + 1];
	call_bytes += addr + 5;
	if (call_bytes >= from && call_bytes <= to) {
		return false;
	}
	return false;
}
#endif

// function argument types and names into anal/types
static void __add_vars_sdb(RCore *core, RAnalFunction *fcn) {
	RAnalFcnVarsCache cache;
	r_anal_fcn_vars_cache_init (core->anal, &cache, fcn);
	RListIter *iter;
	RAnalVar *var;
	int arg_count = 0;

	RList *all_vars = cache.bvars;
	r_list_join (all_vars, cache.svars);
	r_list_join (all_vars, cache.rvars);

	r_list_foreach (all_vars, iter, var) {
		if (var->isarg) {
			char *query = r_str_newf ("anal/types/func.%s.arg.%d=%s,%s", fcn->name, arg_count, var->type, var->name);
			sdb_querys (core->sdb, NULL, 0, query);
			free (query);
			arg_count++;
		}
	}
}

static bool cmd_anal_aaft(RCore *core) {
	RListIter *it;
	RAnalFunction *fcn;
	ut64 seek;
	const char *io_cache_key = "io.pcache.write";
	bool io_cache = r_config_get_i (core->config, io_cache_key);
	if (r_config_get_i (core->config, "cfg.debug")) {
		eprintf ("TOFIX: aaft can't run in debugger mode.\n");
		return false;
	}
	if (!io_cache) {
		// XXX. we shouldnt need this, but it breaks 'r2 -c aaa -w ls'
		r_config_set_i (core->config, io_cache_key, true);
	}
	seek = core->offset;
	r_reg_arena_push (core->anal->reg);
	// Iterating Reverse so that we get function in top-bottom call order
	r_list_foreach_prev (core->anal->fcns, it, fcn) {
		r_core_cmd0 (core, "aei");
		r_core_cmd0 (core, "aeim");
		int ret = r_core_seek (core, fcn->addr, true);
		if (!ret) {
			continue;
		}
		r_anal_esil_set_pc (core->anal->esil, fcn->addr);
		r_core_anal_type_match (core, fcn);
		r_core_cmd0 (core, "aeim-");
		r_core_cmd0 (core, "aei-");
		if (r_cons_is_breaked ()) {
			break;
		}
		__add_vars_sdb (core, fcn);
	}
	r_core_seek (core, seek, true);
	r_reg_arena_pop (core->anal->reg);
	r_config_set_i (core->config, io_cache_key, io_cache);
	return true;
}

static void type_cmd(RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	if (!fcn && *input != '?') {
		eprintf ("cant find function here\n");
		return;
	}
	ut64 seek;
	r_cons_break_push (NULL, NULL);
	switch (*input) {
	case '\0': // "aft"
		seek = core->offset;
		r_anal_esil_set_pc (core->anal->esil, fcn? fcn->addr: core->offset);
		r_core_anal_type_match (core, fcn);
		r_core_seek (core, seek, true);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_aft);
		break;
	}
	r_cons_break_pop ();
}

static int cc_print(void *p, const char *k, const char *v) {
	if (!strcmp (v, "cc")) {
		r_cons_println (k);
	}
	return 1;
}

static void find_refs(RCore *core, const char *glob) {
	char cmd[128];
	ut64 curseek = core->offset;
	while (*glob == ' ') glob++;
	if (!*glob) {
		glob = "str.";
	}
	if (*glob == '?') {
		eprintf ("Usage: axF [flag-str-filter]\n");
		return;
	}
	eprintf ("Finding references of flags matching '%s'...\n", glob);
	snprintf (cmd, sizeof (cmd) - 1, ".(findstref) @@= `f~%s[0]`", glob);
	r_core_cmd0 (core, "(findstref,f here=$$,s entry0,/r here,f-here)");
	r_core_cmd0 (core, cmd);
	r_core_cmd0 (core, "(-findstref)");
	r_core_seek (core, curseek, 1);
}

/* set flags for every function */
static void flag_every_function(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_flag_space_push (core->flags, R_FLAGS_FS_FUNCTIONS);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		r_flag_set (core->flags, fcn->name,
			fcn->addr, r_anal_fcn_size (fcn));
	}
	r_flag_space_pop (core->flags);
}

static void var_help(RCore *core, char ch) {
	switch (ch) {
	case 'b':
		r_core_cmd_help (core, help_msg_afvb);
		break;
	case 's':
		r_core_cmd_help (core, help_msg_afvs);
		break;
	case 'r':
		r_core_cmd_help (core, help_msg_afvr);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_afv);
		break;
	default:
		eprintf ("See afv?, afvb?, afvr? and afvs?\n");
	}
}

static void var_accesses_list(RAnal *a, RAnalFunction *fcn, int delta, const char *typestr) {
	const char *var_local = sdb_fmt ("var.0x%"PFMT64x".%d.%d.%s",
			fcn->addr, 1, delta, typestr);
	const char *xss = sdb_const_get (a->sdb_fcns, var_local, 0);
	if (xss && *xss) {
		r_cons_printf ("%s\n", xss);
	} else {
		r_cons_newline ();
	}
}

static void list_vars(RCore *core, RAnalFunction *fcn, int type, const char *name) {
	RAnalVar *var;
	RListIter *iter;
	RList *list = r_anal_var_all_list (core->anal, fcn);
	if (type == '*') {
		const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
		r_cons_printf ("f-fcnvar*\n");
		r_list_foreach (list, iter, var) {
			r_cons_printf ("f fcnvar.%s @ %s%s%d\n", var->name, bp,
				var->delta>=0? "+":"", var->delta);
		}
		return;
	}
	if (type != 'W' && type != 'R') {
		return;
	}
	const char *typestr = type == 'R'?"reads":"writes";
	if (name && *name) {
		var = r_anal_var_get_byname (core->anal, fcn->addr, name);
		if (var) {
			r_cons_printf ("%10s  ", var->name);
			var_accesses_list (core->anal, fcn, var->delta, typestr);
		}
	} else {
		r_list_foreach (list, iter, var) {
			r_cons_printf ("%10s  ", var->name);
			var_accesses_list (core->anal, fcn, var->delta, typestr);
		}
	}
}

static int cmd_an(RCore *core, bool use_json, const char *name)
{
	ut64 off = core->offset;
	RAnalOp op;
	char *q = NULL;
	PJ *pj = NULL;
	ut64 tgt_addr = UT64_MAX;

	if (use_json) {
		pj = pj_new ();
		pj_a (pj);
	}

	r_anal_op (core->anal, &op, off,
			core->block + off - core->offset, 32, R_ANAL_OP_MASK_BASIC);

	tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
	if (op.var) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
		if (fcn) {
			RAnalVar *bar = r_anal_var_get_byname (core->anal, fcn->addr, op.var->name);
			if (bar) {
				if (name) {
					r_anal_var_rename (core->anal, fcn->addr, bar->scope,
									bar->kind, bar->name, name, true);
				} else if (!use_json) {
					r_cons_println (bar->name);
				} else {
					pj_o (pj);
					pj_ks (pj, "name", bar->name);
					pj_ks (pj, "type", "var");
					pj_kn (pj, "offset", tgt_addr);
					pj_end (pj);
				}
			} else {
				eprintf ("Cannot find variable\n");
			}
		} else {
			eprintf ("Cannot find function\n");
		}
	} else if (tgt_addr != UT64_MAX) {
		RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, tgt_addr, R_ANAL_FCN_TYPE_NULL);
		RFlagItem *f = r_flag_get_i (core->flags, tgt_addr);
		if (fcn) {
			if (name) {
				q = r_str_newf ("afn %s 0x%"PFMT64x, name, tgt_addr);
			} else if (!use_json) {
				r_cons_println (fcn->name);
			} else {
				pj_o (pj);
				pj_ks (pj, "name", fcn->name);
				pj_ks (pj, "type", "function");
				pj_kn (pj, "offset", tgt_addr);
				pj_end (pj);
			}
		} else if (f) {
			if (name) {
				q = r_str_newf ("fr %s %s", f->name, name);
			} else if (!use_json) {
				r_cons_println (f->name);
			} else {
				pj_o (pj);
				if (name) {
					pj_ks (pj, "old_name", f->name);
					pj_ks (pj, "new_name", name);
				} else {
					pj_ks (pj, "name", f->name);
				}
				pj_ks (pj, "type", "flag");
				pj_kn (pj, "offset", tgt_addr);
				pj_end (pj);
			}
		} else {
			if (name) {
				q = r_str_newf ("f %s @ 0x%"PFMT64x, name, tgt_addr);
			} else if (!use_json) {
				r_cons_printf ("0x%" PFMT64x "\n", tgt_addr);
			} else {
				pj_o (pj);
				pj_ks (pj, "name", name);
				pj_ks (pj, "type", "address");
				pj_kn (pj, "offset", tgt_addr);
				pj_end (pj);
			}
		}
	}

	if (use_json) {
		pj_end (pj);
	}

	if (pj) {
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}

	if (q) {
		r_core_cmd0 (core, q);
		free (q);
	}
	r_anal_op_fini (&op);
	return 0;
}

// EBP BASED
static int delta_cmp(const void *a, const void *b) {
	const RAnalVar *va = a;
	const RAnalVar *vb = b;
	return vb->delta - va->delta;
}

static int delta_cmp2(const void *a, const void *b) {
	const RAnalVar *va = a;
	const RAnalVar *vb = b;
	return va->delta - vb->delta;
}

static void __cmd_afvf(RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	RListIter *iter;
	RAnalVar *p;
	RList *list = r_anal_var_all_list (core->anal, fcn);
	r_list_sort (list, delta_cmp2);
	r_list_foreach (list, iter, p) {
		if (p->isarg || p->delta > 0) {
			continue;
		}
		const char *pad = r_str_pad (' ', 10 - strlen (p->name));
		r_cons_printf ("0x%08"PFMT64x"  %s:%s%s\n", (ut64)-p->delta, p->name, pad, p->type);
	}
	r_list_sort (list, delta_cmp);
	r_list_foreach (list, iter, p) {
		if (!p->isarg && p->delta < 0) {
			continue;
		}
		// TODO: only stack vars if (p->kind == 's') { }
		const char *pad = r_str_pad (' ', 10 - strlen (p->name));
		// XXX this 0x6a is a hack
		r_cons_printf ("0x%08"PFMT64x"  %s:%s%s\n", ((ut64)p->delta) - 0x6a, p->name, pad, p->type);
	}
	r_list_free (list);

}

static int var_cmd(RCore *core, const char *str) {
	int delta, type = *str, res = true;
	RAnalVar *v1;
	if (!str[0]) {
		// "afv"
		r_core_cmd0 (core, "afvs");
		r_core_cmd0 (core, "afvb");
		r_core_cmd0 (core, "afvr");
		return true;
	}
	if (!str[0] || str[1] == '?'|| str[0] == '?') {
		var_help (core, *str);
		return res;
	}
	if (str[0] == 'j') {
		// "afvj"
		r_cons_printf ("{\"sp\":");
		r_core_cmd0 (core, "afvsj");
		r_cons_printf (",\"bp\":");
		r_core_cmd0 (core, "afvbj");
		r_cons_printf (",\"reg\":");
		r_core_cmd0 (core, "afvrj");
		r_cons_printf ("}\n");
		return true;
	}
	char *p = strdup (str);
	char *ostr = p;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	/* Variable access CFvs = set fun var */
	switch (str[0]) {
	case '-':
		// "afv"
		r_core_cmdf (core, "afvs-%s", str + 1);
		r_core_cmdf (core, "afvb-%s", str + 1);
		r_core_cmdf (core, "afvr-%s", str + 1);
		return true;
	case 'R': // "afvR"
	case 'W': // "afvW"
	case '*': // "afv*"
		if (fcn) {
			char *name = r_str_trim_head (strchr (ostr, ' '));
			list_vars (core, fcn, str[0], name);
			return true;
		} else {
			eprintf ("afv: Cannot find function in 0x%08"PFMT64x"\n", core->offset);
			return false;
		}
	case 'a': // "afva"
		if (fcn) {
			r_anal_var_delete_all (core->anal, fcn->addr, R_ANAL_VAR_KIND_REG);
			r_anal_var_delete_all (core->anal, fcn->addr, R_ANAL_VAR_KIND_BPV);
			r_anal_var_delete_all (core->anal, fcn->addr, R_ANAL_VAR_KIND_SPV);
			r_core_recover_vars (core, fcn, false);
			free (p);
			return true;
		} else {
			eprintf ("afv: Cannot find function in 0x%08"PFMT64x"\n", core->offset);
			return false;
		}
	case 'n':
		if (str[1]) { // "afvn"
			RAnalOp *op = r_core_anal_op (core, core->offset, R_ANAL_OP_MASK_BASIC);
			char *new_name = r_str_trim_head (strchr (ostr, ' '));
			if (!new_name) {
				r_anal_op_free (op);
				free (ostr);
				return false;
			}
			char *old_name = strchr (new_name, ' ');
			if (!old_name) {
				if (op && op->var) {
					old_name = op->var->name;
				} else {
					eprintf ("Cannot find var @ 0x%08"PFMT64x"\n", core->offset);
					r_anal_op_free (op);
					free (ostr);
					return false;
				}
			} else {
				*old_name++ = 0;
				r_str_trim (old_name);
			}
			if (fcn) {
				v1 = r_anal_var_get_byname (core->anal, fcn->addr, old_name);
				if (v1) {
					r_anal_var_rename (core->anal, fcn->addr, R_ANAL_VAR_SCOPE_LOCAL,
							v1->kind, old_name, new_name, true);
					r_anal_var_free (v1);
				} else {
					eprintf ("Cant find var by name\n");
				}
			} else {
				eprintf ("afv: Cannot find function in 0x%08"PFMT64x"\n", core->offset);
				r_anal_op_free (op);
				free (ostr);
				return false;
			}
			r_anal_op_free (op);
			free (ostr);
		} else {
			RListIter *iter;
			RAnalVar *v;
			RList *list = r_anal_var_all_list (core->anal, fcn);
			r_list_foreach (list, iter, v) {
				r_cons_printf ("%s\n", v->name);
			}
		}
		return true;
	case 'd': // "afvd"
		if (!fcn) {
			eprintf ("Cannot find function.\n");
		} else if (str[1]) {
			p = strchr (ostr, ' ');
			if (!p) {
				free (ostr);
				return false;
			}
			r_str_trim (p);
			v1 = r_anal_var_get_byname (core->anal, fcn->addr, p);
			if (!v1) {
				free (ostr);
				return false;
			}
			r_anal_var_display (core->anal, v1->delta, v1->kind, v1->type);
			r_anal_var_free (v1);
			free (ostr);
		} else {
			RListIter *iter;
			RAnalVar *p;
			RList *list = r_anal_var_all_list (core->anal, fcn);
			r_list_foreach (list, iter, p) {
				char *a = r_core_cmd_strf (core, ".afvd %s", p->name);
				if ((a && !*a) || !a) {
					free (a);
					a = strdup ("\n");
				}
				r_cons_printf ("%s %s = %s", p->isarg ? "arg": "var", p->name, a);
				free (a);
			}
			r_list_free (list);
		}
		return true;
	case 'f': // "afvf"
		__cmd_afvf (core, ostr);
		break;
	case 't':
		if (fcn) { // "afvt"
			p = strchr (ostr, ' ');
			if (!p++) {
				free (ostr);
				return false;
			}

			char *type = strchr (p, ' ');
			if (!type) {
				free (ostr);
				return false;
			}
			*type++ = 0;
			v1 = r_anal_var_get_byname (core->anal, fcn->addr, p);
			if (!v1) {
				eprintf ("Cant find get by name %s\n", p);
				free (ostr);
				return false;
			}
			r_anal_var_retype (core->anal, fcn->addr,
					R_ANAL_VAR_SCOPE_LOCAL, -1, v1->kind, type, -1, v1->isarg, p);
			r_anal_var_free (v1);
			free (ostr);
			return true;
		} else {
			eprintf ("Cannot find function\n");
			return false;
		}
	}
	switch (str[1]) { // afv[bsr]
	case '\0':
	case '*':
		r_anal_var_list_show (core->anal, fcn, type, str[1], NULL);
		break;
	case 'j': {
		PJ *pj = pj_new ();
		if (!pj) {
			return -1;
		}
		r_anal_var_list_show (core->anal, fcn, type, str[1], pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
		break;
	case '.':
		r_anal_var_list_show (core->anal, fcn, core->offset, 0, NULL);
		break;
	case '-': // "afv[bsr]-"
		if (str[2] == '*') {
			r_anal_var_delete_all (core->anal, fcn->addr, type);
		} else {
			if (IS_DIGIT (str[2])) {
				r_anal_var_delete (core->anal, fcn->addr,
						type, 1, (int)r_num_math (core->num, str + 1));
			} else {
				char *name = r_str_trim_dup (str + 2);
				if (name) {
					r_anal_var_delete_byname (core->anal, fcn, type, name);
					free (name);
				}
			}
		}
		break;
	case 'd':
		eprintf ("This command is deprecated, use afvd instead\n");
		break;
	case 't':
		eprintf ("This command is deprecated use afvt instead\n");
		break;
	case 's':
	case 'g':
		if (str[2] != '\0') {
			int rw = 0; // 0 = read, 1 = write
			int idx = r_num_math (core->num, str + 2);
			char *vaddr;
			char *p = strchr (ostr, ' ');
			if (!p) {
				var_help (core, type);
				break;
			}
			r_str_trim (p);
			ut64 addr = core->offset;
			if ((vaddr = strchr (p , ' '))) {
				addr = r_num_math (core->num, vaddr);
			}
			RAnalVar *var = r_anal_var_get (core->anal, fcn->addr,
							str[0], R_ANAL_VAR_SCOPE_LOCAL, idx);
			if (!var) {
				eprintf ("Cannot find variable with delta %d\n", idx);
				res = false;
				break;
			}
			rw = (str[1] == 'g')? 0: 1;
			int ptr = *var->type == 's' ? idx - fcn->maxstack : idx;
			r_anal_var_access (core->anal, fcn->addr, str[0],
					R_ANAL_VAR_SCOPE_LOCAL, idx, ptr, rw, addr);
			r_anal_var_free (var);
		} else {
			eprintf ("Missing argument\n");
		}
		break;
	case ' ': {
		const char *name;
		char *vartype;
		bool isarg = false;
		int size = 4;
		int scope = 1;
		for (str++; *str == ' ';) str++;
		p = strchr (str, ' ');
		if (!p) {
			var_help (core, type);
			break;
		}
		*p++ = 0;
		if (type == 'r') { //registers
			RRegItem *i = r_reg_get (core->anal->reg, str, -1);
			if (!i) {
				eprintf ("Register not found");
				break;
			}
			delta = i->index;
			isarg = true;
		} else {
			delta = r_num_math (core->num, str);
		}
		name = p;
		if (!name) {
			eprintf ("Missing name\n");
			break;
		}
		vartype = strchr (name, ' ');
		if (!vartype) {
			vartype = "int";
		} else {
			*vartype++ = 0;
		}
		if ((type == 'b') && delta > 0) {
			isarg = true;
		} else if (type == 's' && fcn && delta > fcn->maxstack) {
			isarg = true;
		}
		if (fcn) {
			r_anal_var_add (core->anal, fcn->addr,scope,
					delta, type, vartype,
					size, isarg, name);
		} else {
			eprintf ("Missing function at 0x%08"PFMT64x"\n", core->offset);
		}
 		}
		break;
	}
	free (ostr);
	return res;
}

static void print_trampolines(RCore *core, ut64 a, ut64 b, size_t element_size) {
	int i;
	for (i = 0; i < core->blocksize; i += element_size) {
		ut32 n;
		memcpy (&n, core->block + i, sizeof (ut32));
		if (n >= a && n <= b) {
			if (element_size == 4) {
				r_cons_printf ("f trampoline.%x @ 0x%" PFMT64x "\n", n, core->offset + i);
			} else {
				r_cons_printf ("f trampoline.%" PFMT64x " @ 0x%" PFMT64x "\n", n, core->offset + i);
			}
			r_cons_printf ("Cd %u @ 0x%" PFMT64x ":%u\n", element_size, core->offset + i, element_size);
			// TODO: add data xrefs
		}
	}
}

static void cmd_anal_trampoline(RCore *core, const char *input) {
	int bits = r_config_get_i (core->config, "asm.bits");
	char *p, *inp = strdup (input);
	p = strchr (inp, ' ');
	if (p) {
		*p = 0;
	}
	ut64 a = r_num_math (core->num, inp);
	ut64 b = p? r_num_math (core->num, p + 1): 0;
	free (inp);

	switch (bits) {
	case 32:
		print_trampolines (core, a, b, 4);
		break;
	case 64:
		print_trampolines (core, a, b, 8);
		break;
	}
}

static const char *syscallNumber(int n) {
	return sdb_fmt (n > 1000 ? "0x%x" : "%d", n);
}

R_API char *cmd_syscall_dostr(RCore *core, st64 n, ut64 addr) {
	int i;
	char str[64];
	st64 N = n;
	int defVector = r_syscall_get_swi (core->anal->syscall);
	if (defVector > 0) {
		n = -1;
	}
	if (n == -1 || defVector > 0) {
		n = (int)r_debug_reg_get (core->dbg, "oeax");
		if (!n || n == -1) {
			const char *a0 = r_reg_get_name (core->anal->reg, R_REG_NAME_SN);
			n = (a0 == NULL)? -1: (int)r_debug_reg_get (core->dbg, a0);
		}
	}
	RSyscallItem *item = r_syscall_get (core->anal->syscall, n, defVector);
	if (!item) {
		item =  r_syscall_get (core->anal->syscall, N, -1);
	}
	if (!item) {
		return r_str_newf ("%s = unknown ()", syscallNumber (n));
	}
	char *res = r_str_newf ("%s = %s (", syscallNumber (item->num), item->name);
	// TODO: move this to r_syscall
	//TODO replace the hardcoded CC with the sdb ones
	for (i = 0; i < item->args; i++) {
		// XXX this is a hack to make syscall args work on x86-32 and x86-64
		// we need to shift sn first.. which is bad, but needs to be redesigned
		int regidx = i;
		if (core->assembler->bits == 32) {
			regidx++;
		}
		ut64 arg = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_FASTCALL, regidx);
		//r_cons_printf ("(%d:0x%"PFMT64x")\n", i, arg);
		if (item->sargs) {
			switch (item->sargs[i]) {
			case 'p': // pointer
				res = r_str_appendf (res, "0x%08" PFMT64x "", arg);
				break;
			case 'i':
				res = r_str_appendf (res, "%" PFMT64u "", arg);
				break;
			case 'z':
				memset (str, 0, sizeof (str));
				r_io_read_at (core->io, arg, (ut8 *)str, sizeof (str) - 1);
				r_str_filter (str, strlen (str));
				res = r_str_appendf (res, "\"%s\"", str);
				break;
			case 'Z': {
				//TODO replace the hardcoded CC with the sdb ones
				ut64 len = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_FASTCALL, i + 2);
				len = R_MIN (len + 1, sizeof (str) - 1);
				if (len == 0) {
					len = 16; // override default
				}
				(void)r_io_read_at (core->io, arg, (ut8 *)str, len);
				str[len] = 0;
				r_str_filter (str, -1);
				res = r_str_appendf (res, "\"%s\"", str);
			} break;
			default:
				res = r_str_appendf (res, "0x%08" PFMT64x "", arg);
				break;
			}
		} else {
			res = r_str_appendf (res, "0x%08" PFMT64x "", arg);
		}
		if (i + 1 < item->args) {
			res = r_str_appendf (res, ", ");
		}
	}
	r_syscall_item_free (item);
	return r_str_appendf (res, ")");
}

static void cmd_syscall_do(RCore *core, st64 n, ut64 addr) {
	char *msg = cmd_syscall_dostr (core, n, addr);
	if (msg) {
		r_cons_println (msg);
		free (msg);
	}
}

static void core_anal_bytes(RCore *core, const ut8 *buf, int len, int nops, int fmt) {
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	bool iotrap = r_config_get_i (core->config, "esil.iotrap");
	bool romem = r_config_get_i (core->config, "esil.romem");
	bool stats = r_config_get_i (core->config, "esil.stats");
	bool be = core->print->big_endian;
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	core->parser->relsub = r_config_get_i (core->config, "asm.relsub");
	int ret, i, j, idx, size;
	const char *color = "";
	const char *esilstr;
	const char *opexstr;
	RAnalHint *hint;
	RAnalEsil *esil = NULL;
	RAsmOp asmop;
	RAnalOp op = {0};
	ut64 addr;
	PJ *pj = NULL;
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	int totalsize = 0;

	// Variables required for setting up ESIL to REIL conversion
	if (use_color) {
		color = core->cons->context->pal.label;
	}
	switch (fmt) {
	case 'j': {
		pj = pj_new ();
		if (!pj) {
			break;
		}
		pj_a (pj);
	} break;
	case 'r':
		// Setup for ESIL to REIL conversion
		esil = r_anal_esil_new (stacksize, iotrap, addrsize);
		if (!esil) {
			return;
		}
		r_anal_esil_to_reil_setup (esil, core->anal, romem, stats);
		r_anal_esil_set_pc (esil, core->offset);
		break;
	}
	for (i = idx = ret = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		addr = core->offset + idx;
		// TODO: use more anal hints
		hint = r_anal_hint_get (core->anal, addr);
		r_asm_set_pc (core->assembler, addr);
		ret = r_anal_op (core->anal, &op, addr, buf + idx, len - idx,
			R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_OPEX | R_ANAL_OP_MASK_HINT);
		(void)r_asm_disassemble (core->assembler, &asmop, buf + idx, len - idx);
		esilstr = R_STRBUF_SAFEGET (&op.esil);
		opexstr = R_STRBUF_SAFEGET (&op.opex);
		char *mnem = strdup (r_asm_op_get_asm (&asmop));
		char *sp = strchr (mnem, ' ');
		if (sp) {
			*sp = 0;
			if (op.prefix) {
				char *arg = strdup (sp + 1);
				char *sp = strchr (arg, ' ');
				if (sp) {
					*sp = 0;
				}
				free (mnem);
				mnem = arg;
			}
		}
		if (ret < 1 && fmt != 'd') {
			eprintf ("Oops at 0x%08" PFMT64x " (", core->offset + idx);
			for (i = idx, j = 0; i < core->blocksize && j < 3; ++i, ++j) {
				eprintf ("%02x ", buf[i]);
			}
			eprintf ("...)\n");
			free (mnem);
			break;
		}
		size = (hint && hint->size)? hint->size: op.size;
		if (fmt == 'd') {
			char *opname = strdup (r_asm_op_get_asm (&asmop));
			if (opname) {
				r_str_split (opname, ' ');
				char *d = r_asm_describe (core->assembler, opname);
				if (d && *d) {
					r_cons_printf ("%s: %s\n", opname, d);
					free (d);
				} else {
					eprintf ("Unknown opcode\n");
				}
				free (opname);
			}
		} else if (fmt == 'e') {
			if (*esilstr) {
				if (use_color) {
					r_cons_printf ("%s0x%" PFMT64x Color_RESET " %s\n", color, core->offset + idx, esilstr);
				} else {
					r_cons_printf ("0x%" PFMT64x " %s\n", core->offset + idx, esilstr);
				}
			}
		} else if (fmt == 's') {
			totalsize += op.size;
		} else if (fmt == 'j') {
			char strsub[128] = { 0 };
			// pc+33
			r_parse_varsub (core->parser, NULL,
				core->offset + idx,
				asmop.size, r_asm_op_get_asm (&asmop),
				strsub, sizeof (strsub));
				ut64 killme = UT64_MAX;
				if (r_io_read_i (core->io, op.ptr, &killme, op.refptr, be)) {
					core->parser->relsub_addr = killme;
				}
			// 0x33->sym.xx
			char *p = strdup (strsub);
			if (p) {
				r_parse_filter (core->parser, addr, core->flags, hint, p,
						strsub, sizeof (strsub), be);
				free (p);
			}
			pj_o (pj);
			pj_ks (pj, "opcode", r_asm_op_get_asm (&asmop));
			if (!*strsub) {
				r_str_ncpy (strsub, r_asm_op_get_asm (&asmop), sizeof (strsub) -1 );
			}
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
				if (fcn) {
					r_parse_varsub (core->parser, fcn, addr, asmop.size,
							strsub, strsub, sizeof (strsub));
				}
			}
			pj_ks (pj, "disasm", strsub);
			// apply pseudo if needed
			{
				char *pseudo = calloc (128 + strlen (strsub), 3);
				r_parse_parse (core->parser, strsub, pseudo);
				if (pseudo && *pseudo) {
					pj_ks (pj, "pseudo", pseudo);
				}
				free (pseudo);
			}
			{
				char *opname = strdup (strsub);
				char *sp = strchr (opname, ' ');
				if (sp) {
					*sp = 0;
				}
				char *d = r_asm_describe (core->assembler, opname);
				if (d && *d) {
					pj_ks (pj, "description", d);
				}
				free (d);
				free (opname);
			}
			pj_ks (pj, "mnemonic", mnem);
			{
				ut8 *mask = r_anal_mask (core->anal, len - idx, buf + idx, core->offset + idx);
				char *maskstr = r_hex_bin2strdup (mask, size);
				pj_ks (pj, "mask", maskstr);
				free (mask);
				free (maskstr);
			}
			if (hint && hint->opcode) {
				pj_ks (pj, "ophint", hint->opcode);
			}
			if (hint && hint->jump != UT64_MAX) {
				op.jump = hint->jump;
			}
			if (hint && hint->fail != UT64_MAX) {
				op.fail = hint->fail;
			}
			if (op.jump != UT64_MAX) {
				pj_kn (pj, "jump", op.jump);
			}
			if (op.fail != UT64_MAX) {
				pj_kn (pj, "fail", op.fail);
			}
			const char *jesil = (hint && hint->esil) ? hint->esil: esilstr;
			if (jesil && *jesil) {
				pj_ks (pj, "esil", jesil);
			}
			pj_kb (pj, "sign", op.sign);
			pj_kn (pj, "prefix", op.prefix);
			pj_ki (pj, "id", op.id);
			if (opexstr && *opexstr) {
				pj_k (pj, "opex");
				pj_j (pj, opexstr);
			}
			pj_kn (pj, "addr", core->offset + idx);
			pj_ks (pj, "bytes", r_hex_bin2strdup (buf + idx, ret));
			if (op.val != UT64_MAX) {
				pj_kn (pj, "val", op.val);
			}
			if (op.disp && op.disp != UT64_MAX) {
				pj_kn (pj, "disp", op.disp);
			}
			if (op.ptr != UT64_MAX) {
				pj_kn (pj, "ptr", op.ptr);
			}
			pj_ki (pj, "size", size);
			pj_ks (pj, "type", r_anal_optype_to_string (op.type));
			{
				const char *datatype = r_anal_datatype_to_string (op.datatype);
				if (datatype) {
					pj_ks (pj, "datatype", datatype);
				}

			}
			if (op.reg) {
				pj_ks (pj, "reg", op.reg);
			}
			if (op.ireg) {
				pj_ks (pj, "ireg", op.ireg);
			}
			pj_ki (pj, "scale", op.scale);
			if (op.refptr != -1) {
				pj_ki (pj, "refptr", op.refptr);
			}
			pj_ki (pj, "cycles", op.cycles);
			pj_ki (pj, "failcycles", op.failcycles);
			pj_ki (pj, "delay", op.delay);
			const char *p1 = r_anal_stackop_tostring (op.stackop);
			if (strcmp (p1, "null")) {
				pj_ks (pj, "stack", p1);
			}
			pj_kn (pj, "stackptr", op.stackptr);
			const char *arg = (op.type & R_ANAL_OP_TYPE_COND)
				? r_anal_cond_tostring (op.cond): NULL;
			if (arg) {
				pj_ks (pj, "cond", arg);
			}
			pj_ks (pj, "family", r_anal_op_family_to_string (op.family));
			pj_end (pj);
		} else if (fmt == 'r') {
			if (*esilstr) {
				if (use_color) {
					r_cons_printf ("%s0x%" PFMT64x Color_RESET "\n", color, core->offset + idx);
				} else {
					r_cons_printf ("0x%" PFMT64x "\n", core->offset + idx);
				}
				r_anal_esil_parse (esil, esilstr);
				r_anal_esil_dumpstack (esil);
				r_anal_esil_stack_free (esil);
			}
		} else {
		char disasm[128] = { 0 };
		r_parse_varsub (core->parser, NULL,
			core->offset + idx,
			asmop.size, r_asm_op_get_asm (&asmop),
			disasm, sizeof (disasm));
		ut64 killme = UT64_MAX;
		if (r_io_read_i (core->io, op.ptr, &killme, op.refptr, be)) {
			core->parser->relsub_addr = killme;
		}
		char *p = strdup (disasm);
		if (p) {
			r_parse_filter (core->parser, addr, core->flags, hint, p,
				disasm, sizeof (disasm), be);
			free (p);
		}
#define printline(k, fmt, arg)\
	{ \
		if (use_color)\
			r_cons_printf ("%s%s: " Color_RESET, color, k);\
		else\
			r_cons_printf ("%s: ", k);\
		if (fmt) r_cons_printf (fmt, arg);\
	}
			printline ("address", "0x%" PFMT64x "\n", core->offset + idx);
			printline ("opcode", "%s\n", r_asm_op_get_asm (&asmop));
			if (!*disasm) {
				r_str_ncpy (disasm, r_asm_op_get_asm (&asmop), sizeof (disasm) - 1);
			}
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
				if (fcn) {
					r_parse_varsub (core->parser, fcn, addr, asmop.size,
							disasm, disasm, sizeof (disasm));
				}
			}
			printline ("disasm", "%s\n", disasm);
			{
				char *pseudo = calloc (128 + strlen (disasm), 3);
				r_parse_parse (core->parser, disasm, pseudo);
				if (pseudo && *pseudo) {
					printline ("pseudo", "%s\n", pseudo);
				}
				free (pseudo);
			}
			printline ("mnemonic", "%s\n", mnem);
			{
				char *opname = strdup (disasm);
				char *sp = strchr (opname, ' ');
				if (sp) {
					*sp = 0;
				}
				char *d = r_asm_describe (core->assembler, opname);
				if (d && *d) {
					printline ("description", "%s\n", d);
				}
				free (d);
				free (opname);
			}
			{
				ut8 *mask = r_anal_mask (core->anal, len - idx, buf + idx, core->offset + idx);
				char *maskstr = r_hex_bin2strdup (mask, size);
				printline ("mask", "%s\n", maskstr);
				free (mask);
				free (maskstr);
			}
			if (hint) {
				if (hint->opcode) {
					printline ("ophint", "%s\n", hint->opcode);
				}
			}
			printline ("prefix", "%" PFMT64u "\n", op.prefix);
			printline ("id", "%d\n", op.id);
#if 0
// no opex here to avoid lot of tests broken..and having json in here is not much useful imho
			if (opexstr && *opexstr) {
				printline ("opex", "%s\n", opexstr);
			}
#endif
			printline ("bytes", NULL, 0);
			int minsz = R_MIN (len, size);
			minsz = R_MAX (minsz, 0);
			for (j = 0; j < minsz; j++) {
				ut8 ch = ((j + idx - 1) > minsz)? 0xff: buf[j + idx];
				r_cons_printf ("%02x", ch);
			}
			r_cons_newline ();
			if (op.val != UT64_MAX) {
				printline ("val", "0x%08" PFMT64x "\n", op.val);
			}
			if (op.ptr != UT64_MAX) {
				printline ("ptr", "0x%08" PFMT64x "\n", op.ptr);
			}
			if (op.disp && op.disp != UT64_MAX) {
				printline ("disp", "0x%08" PFMT64x "\n", op.disp);
			}
			if (op.refptr != -1) {
				printline ("refptr", "%d\n", op.refptr);
			}
			printline ("size", "%d\n", size);
			printline ("sign", "%s\n", r_str_bool (op.sign));
			printline ("type", "%s\n", r_anal_optype_to_string (op.type));
			const char *datatype = r_anal_datatype_to_string (op.datatype);
			if (datatype) {
				printline ("datatype", "%s\n", datatype);
			}
			printline ("cycles", "%d\n", op.cycles);
			if (op.failcycles) {
				printline ("failcycles", "%d\n", op.failcycles);
			}
			if (op.type2) {
				printline ("type2", "0x%x\n", op.type2);
			}
			if (op.reg) {
				printline ("reg", "%s\n", op.reg);
			}
			if (op.ireg) {
				printline ("ireg", "%s\n", op.ireg);
			}
			if (op.scale) {
				printline ("scale", "%d\n", op.scale);
			}
			if (hint && hint->esil) {
				printline ("esil", "%s\n", hint->esil);
			} else if (*esilstr) {
				printline ("esil", "%s\n", esilstr);
			}
			if (hint && hint->jump != UT64_MAX) {
				op.jump = hint->jump;
			}
			if (op.jump != UT64_MAX) {
				printline ("jump", "0x%08" PFMT64x "\n", op.jump);
			}
			if (op.direction != 0) {
				const char * dir = op.direction == 1 ? "read"
					: op.direction == 2 ? "write"
					: op.direction == 4 ? "exec"
					: op.direction == 8 ? "ref": "none";
				printline ("direction", "%s\n", dir);
			}
			if (hint && hint->fail != UT64_MAX) {
				op.fail = hint->fail;
			}
			if (op.fail != UT64_MAX) {
				printline ("fail", "0x%08" PFMT64x "\n", op.fail);
			}
			if (op.delay) {
				printline ("delay", "%d\n", op.delay);
			}
			{
				const char *arg = (op.type & R_ANAL_OP_TYPE_COND)?  r_anal_cond_tostring (op.cond): NULL;
				if (arg) {
					printline ("cond", "%s\n", arg);
				}
			}
			printline ("family", "%s\n", r_anal_op_family_to_string (op.family));
			if (op.stackop != R_ANAL_STACK_NULL) {
				printline ("stackop", "%s\n", r_anal_stackop_tostring (op.stackop));
			}
			if (op.stackptr) {
				printline ("stackptr", "%"PFMT64u"\n", op.stackptr);
			}
		}
		//r_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
		//free (hint);
		free (mnem);
		r_anal_hint_free (hint);
		r_anal_op_fini (&op);
	}
	r_anal_op_fini (&op);
	if (fmt == 's') {
		r_cons_printf ("%d\n", totalsize);
	} else if (fmt == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	r_anal_esil_free (esil);
}

static int bb_cmp(const void *a, const void *b) {
	const RAnalBlock *ba = a;
	const RAnalBlock *bb = b;
	return ba->addr - bb->addr;
}

static int casecmp(const void* _a, const void * _b) {
	const RAnalCaseOp* a = _a;
	const RAnalCaseOp* b = _b;
	return a->addr != b->addr;
}

static bool anal_fcn_list_bb(RCore *core, const char *input, bool one) {
	RDebugTracepoint *tp = NULL;
	RListIter *iter;
	RAnalBlock *b;
	int mode = 0;
	ut64 addr, bbaddr = UT64_MAX;
	PJ *pj = NULL;

	if (*input == '.') {
		one = true;
		input++;
	}
	if (*input) {
		mode = *input;
		input++;
	}
	if (*input == '.') {
		one = true;
		input++;
	}
	if (input && *input) {
		addr = bbaddr = r_num_math (core->num, input);
		if (!addr && *input != '0') {
			addr = core->offset;
		}
	} else {
		addr = core->offset;
	}
	input = r_str_trim_ro (input);
	if (one) {
		bbaddr = addr;
	}
	if (mode == 'j') {
		pj = pj_new ();
		if (!pj) {
			return false;
		}
		pj_a (pj);
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		if (mode == 'j') {
			pj_end (pj);
			r_cons_println (pj_string (pj));
			pj_free (pj);
		}
		eprintf ("Cannot find function in 0x%08"PFMT64x"\n", addr);
		return false;
	}
	if (mode == '*') {
		r_cons_printf ("fs blocks\n");
	}
	r_list_sort (fcn->bbs, bb_cmp);
	if (mode == '=') { // afb
		RList *flist = r_list_newf ((RListFree) r_listinfo_free);
		if (!flist) {
			return false;
		}
		ls_foreach (fcn->bbs, iter, b) {
			RInterval inter = (RInterval) {b->addr, b->size};
			RListInfo *info = r_listinfo_new (b->label, inter, inter, -1, NULL);
			if (!info) {
				break;
			}
			r_list_append (flist, info);
		}
		RTable *table = r_core_table (core);
		r_table_visual_list (table, flist, core->offset, core->blocksize,
			r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
		r_cons_printf ("\n%s\n", r_table_tostring (table));
		r_table_free (table);
		r_list_free (flist);
		return true;
	}

	RTable *t = NULL;
	if (mode == 't') {
		t = r_table_new ();
		r_table_set_columnsf (t, "xdxx", "addr", "size", "jump", "fail");
	}
	r_list_foreach (fcn->bbs, iter, b) {
		if (one) {
			if (bbaddr != UT64_MAX && (bbaddr < b->addr || bbaddr >= (b->addr + b->size))) {
				continue;
			}
		}
		switch (mode) {
		case 't':
			r_table_add_rowf (t, "xdxx", b->addr, b->size, b->jump, b->fail);
			break;
		case 'r':
			if (b->jump == UT64_MAX) {
				ut64 retaddr = r_anal_bb_opaddr_i (b, b->ninstr - 1);
				if (retaddr == UT64_MAX) {
					break;
				}

				if (!strcmp (input, "*")) {
					r_cons_printf ("db 0x%08"PFMT64x"\n", retaddr);
				} else if (!strcmp (input, "-*")) {
					r_cons_printf ("db-0x%08"PFMT64x"\n", retaddr);
				} else {
					r_cons_printf ("0x%08"PFMT64x"\n", retaddr);
				}
			}
			break;
		case '*':
			r_cons_printf ("f bb.%05" PFMT64x " = 0x%08" PFMT64x "\n",
				b->addr & 0xFFFFF, b->addr);
			break;
		case 'q':
			r_cons_printf ("0x%08" PFMT64x "\n", b->addr);
			break;
		case 'j':
			//r_cons_printf ("%" PFMT64u "%s", b->addr, iter->n? ",": "");
			{
			RListIter *iter2;
			RAnalBlock *b2;
			int inputs = 0;
			int outputs = 0;
			r_list_foreach (fcn->bbs, iter2, b2) {
				if (b2->jump == b->addr) {
					inputs++;
				}
				if (b2->fail == b->addr) {
					inputs++;
				}
			}
			if (b->jump != UT64_MAX) {
				outputs ++;
			}
			if (b->fail != UT64_MAX) {
				outputs ++;
			}
			pj_o (pj);

			if (b->jump != UT64_MAX) {
				pj_kn (pj, "jump", b->jump);
			}
			if (b->fail != UT64_MAX) {
				pj_kn (pj, "fail", b->fail);
			}
			if (b->switch_op) {
				pj_k (pj, "switch_op");
				pj_o (pj);
				pj_kn (pj, "addr", b->switch_op->addr);
				pj_kn (pj, "min_val", b->switch_op->min_val);
				pj_kn (pj, "def_val", b->switch_op->def_val);
				pj_kn (pj, "max_val", b->switch_op->max_val);
				pj_k (pj, "cases");
				pj_a (pj);
				{
					RListIter *case_op_iter;
					RAnalCaseOp *case_op;
					r_list_foreach (b->switch_op->cases, case_op_iter, case_op) {
						pj_o (pj);
						pj_kn (pj, "addr", case_op->addr);
						pj_kn (pj, "jump", case_op->jump);
						pj_kn (pj, "value", case_op->value);
						pj_kn (pj, "cond", case_op->cond);
						pj_kn (pj, "bb_ref_to", case_op->bb_ref_to);
						pj_kn (pj, "bb_ref_from", case_op->bb_ref_from);
						pj_end (pj);
					}
				}
				pj_end (pj);
				pj_end (pj);
			}
			pj_kn (pj, "addr", b->addr);
			pj_ki (pj, "size", b->size);
			pj_ki (pj, "inputs", inputs);
			pj_ki (pj, "outputs", outputs);
			pj_ki (pj, "ninstr", b->ninstr);
			pj_ks (pj, "traced", r_str_bool (b->traced));
			pj_end (pj);
			}
			break;
		case 'i':
			{
			RListIter *iter2;
			RAnalBlock *b2;
			int inputs = 0;
			int outputs = 0;
			r_list_foreach (fcn->bbs, iter2, b2) {
				if (b2->jump == b->addr) {
					inputs++;
				}
				if (b2->fail == b->addr) {
					inputs++;
				}
			}
			if (b->jump != UT64_MAX) {
				outputs ++;
			}
			if (b->fail != UT64_MAX) {
				outputs ++;
			}
			if (b->switch_op) {
				RList *unique_cases = r_list_uniq (b->switch_op->cases, casecmp);
				outputs += r_list_length (unique_cases);
				r_list_free (unique_cases);
			}
			if (b->jump != UT64_MAX) {
				r_cons_printf ("jump: 0x%08"PFMT64x"\n", b->jump);
			}
			if (b->fail != UT64_MAX) {
				r_cons_printf ("fail: 0x%08"PFMT64x"\n", b->fail);
			}
			r_cons_printf ("addr: 0x%08"PFMT64x"\nsize: %d\ninputs: %d\noutputs: %d\nninstr: %d\ntraced: %s\n",
				b->addr, b->size, inputs, outputs, b->ninstr, r_str_bool (b->traced));
			}
			break;
		default:
			tp = r_debug_trace_get (core->dbg, b->addr);
			r_cons_printf ("0x%08" PFMT64x " 0x%08" PFMT64x " %02X:%04X %d",
				b->addr, b->addr + b->size,
				tp? tp->times: 0, tp? tp->count: 0,
				b->size);
			if (b->jump != UT64_MAX) {
				r_cons_printf (" j 0x%08" PFMT64x, b->jump);
			}
			if (b->fail != UT64_MAX) {
				r_cons_printf (" f 0x%08" PFMT64x, b->fail);
			}
			if (b->switch_op) {
				RAnalCaseOp *cop;
				RListIter *iter;
				RList *unique_cases = r_list_uniq (b->switch_op->cases, casecmp);
				r_list_foreach (unique_cases, iter, cop) {
					r_cons_printf (" s 0x%08" PFMT64x, cop->addr);
				}
				r_list_free (unique_cases);
			}
			r_cons_newline ();
			break;
		}
	}
	if (mode == 't') {
		const char *arg = input;
		if (r_table_query (t, arg)) {
			char *ts = r_table_tofancystring (t);
			r_cons_printf ("%s", ts);
			free (ts);
		}
		r_table_free (t);
	} else if (mode == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	return true;
}

static bool anal_bb_edge (RCore *core, const char *input) {
	// "afbe" switch-bb-addr case-bb-addr
	char *arg = strdup (r_str_trim_ro (input));
	char *sp = strchr (arg, ' ');
	if (sp) {
		*sp++ = 0;
		ut64 sw_at = r_num_math (core->num, arg);
		ut64 cs_at = r_num_math (core->num, sp);
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, sw_at, 0);
		if (fcn) {
			RAnalBlock *bb;
			RListIter *iter;
			r_list_foreach (fcn->bbs, iter, bb) {
				if (sw_at >= bb->addr && sw_at < (bb->addr + bb->size)) {
					if (!bb->switch_op) {
						bb->switch_op = r_anal_switch_op_new (
							sw_at, 0, 0);
					}
					r_anal_switch_op_add_case (bb->switch_op, cs_at, 0, cs_at);
				}
			}
			free (arg);
			return true;
		}
	}
	free (arg);
	return false;
}

static bool anal_fcn_del_bb(RCore *core, const char *input) {
	ut64 addr = r_num_math (core->num, input);
	if (!addr) {
		addr = core->offset;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		if (!strcmp (input, "*")) {
			r_list_free (fcn->bbs);
			fcn->bbs = NULL;
		} else {
			RAnalBlock *b;
			RListIter *iter;
			r_list_foreach (fcn->bbs, iter, b) {
				if (b->addr == addr) {
					r_list_delete (fcn->bbs, iter);
					return true;
				}
			}
			eprintf ("Cannot find basic block\n");
		}
	} else {
		eprintf ("Cannot find function\n");
	}
	return false;
}

static int anal_fcn_add_bb(RCore *core, const char *input) {
	// fcn_addr bb_addr bb_size [jump] [fail]
	char *ptr;
	const char *ptr2 = NULL;
	ut64 fcnaddr = -1LL, addr = -1LL;
	ut64 size = 0LL;
	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	int type = R_ANAL_BB_TYPE_NULL;
	RAnalFunction *fcn = NULL;
	RAnalDiff *diff = NULL;

	while (*input == ' ') input++;
	ptr = strdup (input);

	switch (r_str_word_set0 (ptr)) {
	case 6:
		ptr2 = r_str_word_get0 (ptr, 6);
		if (!(diff = r_anal_diff_new ())) {
			eprintf ("error: Cannot init RAnalDiff\n");
			free (ptr);
			return false;
		}
		if (ptr2[0] == 'm') {
			diff->type = R_ANAL_DIFF_TYPE_MATCH;
		} else if (ptr2[0] == 'u') {
			diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
		}
	case 5: // get fail
		fail = r_num_math (core->num, r_str_word_get0 (ptr, 4));
	case 4: // get jump
		jump = r_num_math (core->num, r_str_word_get0 (ptr, 3));
	case 3: // get size
		size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
	case 2: // get addr
		addr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
	case 1: // get fcnaddr
		fcnaddr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
	}
	fcn = r_anal_get_fcn_in (core->anal, fcnaddr, 0);
	if (fcn) {
		if (!r_anal_fcn_add_bb (core->anal, fcn, addr, size, jump, fail, type, diff))
		//if (!r_anal_fcn_add_bb_raw (core->anal, fcn, addr, size, jump, fail, type, diff))
		{
			eprintf ("afb+: Cannot add basic block at 0x%08"PFMT64x"\n", addr);
eprintf ("# %s\n", input);
		}
	} else {
		eprintf ("afb+ Cannot find function at 0x%" PFMT64x " from 0x%08"PFMT64x" -> 0x%08"PFMT64x"\n",
				fcnaddr, addr, jump);
	}
	r_anal_diff_free (diff);
	free (ptr);
	return true;
}

static void r_core_anal_nofunclist  (RCore *core, const char *input) {
	int minlen = (int)(input[0]==' ') ? r_num_math (core->num, input + 1): 16;
	ut64 code_size = r_num_get (core->num, "$SS");
	ut64 base_addr = r_num_get (core->num, "$S");
	ut64 chunk_size, chunk_offset, i;
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *b;
	char* bitmap;
	int counter;

	if (minlen < 1) {
		minlen = 1;
	}
	if (code_size < 1) {
		return;
	}
	bitmap = calloc (1, code_size+64);
	if (!bitmap) {
		return;
	}

	// for each function
	r_list_foreach (core->anal->fcns, iter, fcn) {
		// for each basic block in the function
		r_list_foreach (fcn->bbs, iter2, b) {
			// if it is not withing range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr+code_size))
				continue;
			// otherwise mark each byte in the BB in the bitmap
			for (counter = 0; counter < b->size; counter++) {
				bitmap[b->addr+counter-base_addr] = '=';
			}
			// finally, add a special marker to show the beginning of a
			// function
			bitmap[fcn->addr-base_addr] = 'F';
		}
	}

	// Now we print the list of memory regions that are not assigned to a function
	chunk_size = 0;
	chunk_offset = 0;
	for (i = 0; i < code_size; i++) {
		if (bitmap[i]){
			// We only print a region is its size is bigger than 15 bytes
			if (chunk_size >= minlen){
				fcn = r_anal_get_fcn_in (core->anal, base_addr+chunk_offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (fcn) {
					r_cons_printf ("0x%08"PFMT64x"  %6d   %s\n", base_addr+chunk_offset, chunk_size, fcn->name);
				} else {
					r_cons_printf ("0x%08"PFMT64x"  %6d\n", base_addr+chunk_offset, chunk_size);
				}
			}
			chunk_size = 0;
			chunk_offset = i+1;
			continue;
		}
		chunk_size+=1;
	}
	if (chunk_size >= 16) {
		fcn = r_anal_get_fcn_in (core->anal, base_addr+chunk_offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			r_cons_printf ("0x%08"PFMT64x"  %6d   %s\n", base_addr+chunk_offset, chunk_size, fcn->name);
		} else {
			r_cons_printf ("0x%08"PFMT64x"  %6d\n", base_addr+chunk_offset, chunk_size);
		}
	}
	free(bitmap);
}

static void r_core_anal_fmap  (RCore *core, const char *input) {
	int show_color = r_config_get_i (core->config, "scr.color");
	int cols = r_config_get_i (core->config, "hex.cols") * 4;
	ut64 code_size = r_num_get (core->num, "$SS");
	ut64 base_addr = r_num_get (core->num, "$S");
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *b;
	char* bitmap;
	int assigned;
	ut64 i;

	if (code_size < 1) {
		return;
	}
	bitmap = calloc (1, code_size+64);
	if (!bitmap) {
		return;
	}

	// for each function
	r_list_foreach (core->anal->fcns, iter, fcn) {
		// for each basic block in the function
		r_list_foreach (fcn->bbs, iter2, b) {
			// if it is not within range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr+code_size))
				continue;
			// otherwise mark each byte in the BB in the bitmap
			int counter = 1;
			for (counter = 0; counter < b->size; counter++) {
				bitmap[b->addr+counter-base_addr] = '=';
			}
			bitmap[fcn->addr-base_addr] = 'F';
		}
	}
	// print the bitmap
	assigned = 0;
	if (cols < 1) {
		cols = 1;
	}
	for (i = 0; i < code_size; i += 1) {
		if (!(i % cols)) {
			r_cons_printf ("\n0x%08"PFMT64x"  ", base_addr+i);
		}
		if (bitmap[i]) {
			assigned++;
		}
		if (show_color) {
			if (bitmap[i]) {
				r_cons_printf ("%s%c\x1b[0m", Color_GREEN, bitmap[i]);
			} else {
				r_cons_printf (".");
			}
		} else {
			r_cons_printf ("%c", bitmap[i] ? bitmap[i] : '.' );
		}
	}
	r_cons_printf ("\n%d / %d (%.2lf%%) bytes assigned to a function\n", assigned, code_size, 100.0*( (float) assigned) / code_size);
	free(bitmap);
}

static bool fcnNeedsPrefix(const char *name) {
	if (!strncmp (name, "entry", 5)) {
		return false;
	}
	if (!strncmp (name, "main", 4)) {
		return false;
	}
	return (!strchr (name, '.'));
}

static char * getFunctionName (RCore *core, ut64 off, const char *name, bool prefix) {
	const char *fcnpfx = "";
	if (prefix) {
		if (fcnNeedsPrefix (name) && (!fcnpfx || !*fcnpfx)) {
			fcnpfx = "fcn";
		} else {
			fcnpfx = r_config_get (core->config, "anal.fcnprefix");
		}
	}
	if (r_reg_get (core->anal->reg, name, -1)) {
		return r_str_newf ("%s.%08"PFMT64x, "fcn", off);
	}
	if (strlen (name) < 4) {
		return r_str_newf ("%s.%s", (*fcnpfx)? fcnpfx: "fcn", name);
	}
	return strdup (name); // r_str_newf ("%s%s%s", fcnpfx, *fcnpfx? ".": "", name);
}

/* TODO: move into r_anal_fcn_rename(); */
static bool __setFunctionName(RCore *core, ut64 addr, const char *_name, bool prefix) {
	r_return_val_if_fail (core && _name, false);
	char *name = getFunctionName (core, addr, _name, prefix);
	// RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_ANY);
	RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, addr, R_ANAL_FCN_TYPE_ANY);
	if (fcn) {
		free (fcn->name);
		fcn->name = name;
		if (core->anal->cb.on_fcn_rename) {
			core->anal->cb.on_fcn_rename (core->anal, core->anal->user, fcn, name);
		}
		return true;
	}
	free (name);
	return false;
}

static void afCc(RCore *core, const char *input) {
	ut64 addr;
	RAnalFunction *fcn;
	if (*input == ' ') {
		addr = r_num_math (core->num, input);
	} else {
		addr = core->offset;
	}
	if (addr == 0LL) {
		fcn = r_anal_fcn_find_name (core->anal, input + 3);
	} else {
		fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	}
	if (fcn) {
		ut32 totalCycles = r_anal_fcn_cost (core->anal, fcn);
		// FIXME: This defeats the purpose of the function, but afC is used in project files.
		// cf. canal.c
		r_cons_printf ("%d\n", totalCycles);
	} else {
		eprintf ("afCc: Cannot find function\n");
	}
}

static void cmd_anal_fcn_sig(RCore *core, const char *input) {
	bool json = (input[0] == 'j');
	char *p = strchr (input, ' ');
	char *fcn_name = p ? r_str_trim_dup (p): NULL;
	RListIter *iter;
	RAnalFuncArg *arg;

	RAnalFunction *fcn;
	if (fcn_name) {
		fcn = r_anal_fcn_find_name (core->anal, fcn_name);
	} else {
		fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (fcn) {
			fcn_name = fcn->name;
		}
	}
	if (!fcn) {
		return;
	}

	if (json) {
		PJ *j = pj_new ();
		if (!j) {
			return;
		}
		pj_a (j);

		char *key = NULL;
		if (fcn_name) {
			key = resolve_fcn_name (core->anal, fcn_name);
		}

		if (key) {
			const char *fcn_type = r_type_func_ret (core->anal->sdb_types, key);
			int nargs = r_type_func_args_count (core->anal->sdb_types, key);
			if (fcn_type) {
				pj_o (j);
				pj_ks (j, "name", r_str_get (key));
				pj_ks (j, "return", r_str_get (fcn_type));
				pj_k (j, "args");
				pj_a (j);
				if (nargs) {
					RList *list = r_core_get_func_args (core, fcn_name);
					r_list_foreach (list, iter, arg) {
						char *type = arg->orig_c_type;
						pj_o (j);
						pj_ks (j, "name", arg->name);
						pj_ks (j, "type", type);
						pj_end (j);
					}
					r_list_free (list);
				}
				pj_end (j);
				pj_ki (j, "count", nargs);
				pj_end (j);
			}
			free (key);
		} else {
			pj_o (j);
			pj_ks (j, "name", r_str_get (fcn_name));
			pj_k (j, "args");
			pj_a (j);

			RAnalFcnVarsCache cache;
			r_anal_fcn_vars_cache_init (core->anal, &cache, fcn);
			int nargs = 0;
			RAnalVar *var;
			r_list_foreach (cache.rvars, iter, var) {
				nargs++;
				pj_o (j);
				pj_ks (j, "name", var->name);
				pj_ks (j, "type", var->type);
				pj_end (j);
			}
			r_list_foreach (cache.bvars, iter, var) {
				if (var->delta <= 0) {
					continue;
				}
				nargs++;
				pj_o (j);
				pj_ks (j, "name", var->name);
				pj_ks (j, "type", var->type);
				pj_end (j);
			}
			r_list_foreach (cache.svars, iter, var) {
				if (!var->isarg) {
					continue;
				}
				nargs++;
				pj_o (j);
				pj_ks (j, "name", var->name);
				pj_ks (j, "type", var->type);
				pj_end (j);
			}
			r_anal_fcn_vars_cache_fini (&cache);

			pj_end (j);
			pj_ki (j, "count", nargs);
			pj_end (j);
		}
		pj_end (j);
		const char *s = pj_string (j);
		if (s) {
			r_cons_printf ("%s\n", s);
		}
		pj_free (j);
	} else {
		char *sig = r_anal_fcn_format_sig (core->anal, fcn, fcn_name, NULL, NULL, NULL);
		if (sig) {
			r_cons_printf ("%s\n", sig);
			free (sig);
		}
	}
}

static void __updateStats(RCore *core, Sdb *db, ut64 addr, int statsMode) {
	RAnalOp *op = r_core_anal_op (core, addr, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT | R_ANAL_OP_MASK_DISASM);
	if (!op) {
		return;
	}
	if (statsMode == 'f') {
		const char *family = r_anal_op_family_to_string (op->family);
		sdb_num_inc (db, family, 1, 0);
	} else if (statsMode == 'o') {
		const char *type = r_anal_optype_to_string (op->type);
		sdb_num_inc (db, type, 1, 0);
	} else {
		char *mnem = strdup (op->mnemonic);
		char *sp = strchr (mnem, ' ');
		if (sp) {
			*sp = 0;
			//memmove (mnem, sp + 1, strlen (sp));
		}
		sdb_num_inc (db, mnem, 1, 0);
	}
	//sdb_set (db, family, "1", 0);
	//r_cons_printf ("0x%08"PFMT64x" %s\n", addr, family);
	r_anal_op_free (op);
	// r_core_cmdf (core, "pd 1 @ 0x%08"PFMT64x"\n", addr);
}


static Sdb *__core_cmd_anal_fcn_stats (RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	if (!fcn) {
		eprintf ("Cannot find any function at 0x%08"PFMT64x"\n", core->offset);
		return NULL;
	}
	bool silentMode = false;
	int statsMode = 0;
	if (*input == '*') {
		silentMode = true;
		input++;
	}
	switch (*input) {
	case '?':
		eprintf ("Usage: afis[ft]\n");
		eprintf (" afis           enumerate unique opcodes in function\n");
		eprintf (" afisa[fo]      enumerate all the meta of all the functions\n");
		eprintf (" afisf          enumerate unique opcode families in function\n");
		eprintf (" afiso          enumerate unique opcode types in function\n");
		eprintf (" afist [query]  list in table format\n");
		return NULL;
	case 'f':
	case 'o':
		statsMode = *input;
		input++;
		break;
	}

	Sdb *db = sdb_new0 ();
	RAnalBlock *bb;
	RListIter *iter;
	r_list_foreach (fcn->bbs, iter, bb) {
		int i;
		__updateStats (core, db, bb->addr, statsMode);
		for (i = 0; i< bb->op_pos_size; i++) {
			ut16 op_pos = bb->op_pos[i];
			__updateStats (core, db, bb->addr + op_pos, statsMode);
		}
	}
	if (silentMode) {
		// nothing
	} else if (*input == 't') {
		SdbList *ls = sdb_foreach_list (db, true);
		SdbListIter *it;
		RTable *t = r_table_new ();
		SdbKv *kv;
		RTableColumnType *typeString = r_table_type ("string");
		RTableColumnType *typeNumber = r_table_type ("number");
		r_table_add_column (t, typeString, "name", 0);
		ls_foreach (ls, it, kv) {
			const char *key = sdbkv_key (kv);
			r_table_add_column (t, typeNumber, key, 0);
		}
		RList *items = r_list_newf (free);
		r_list_append (items, fcn->name);
		ls_foreach (ls, it, kv) {
			const char *value = sdbkv_value (kv);
			int nv = (int)r_num_get (NULL, value);
			r_list_append (items, r_str_newf ("%d", nv));
		}
		r_table_add_row_list (t, items);
		r_table_query (t, input + 1);
		char *ts = r_table_tostring (t);
		r_cons_printf ("%s", ts);
		free (ts);
		r_table_free (t);
	} else {
		SdbList *ls = sdb_foreach_list (db, true);
		SdbListIter *it;
		SdbKv *kv;
		ls_foreach (ls, it, kv) {
			const char *key = sdbkv_key(kv);
			const char *value = sdbkv_value(kv);
			r_cons_printf ("%4d %s\n", (int)r_num_get (NULL, value), key);
		}
	}
	return db;
	//sdb_free (db);
}

static void __core_cmd_anal_fcn_allstats(RCore *core, const char *input) {
	RAnalFunction *fcn;
	SdbKv *kv;
	RListIter *iter;
	SdbListIter *it;
	RList *dbs = r_list_newf ((RListFree)sdb_free);
	Sdb *d = sdb_new0 ();
	ut64 oseek = core->offset;
	bool isJson = strchr (input, 'j') != NULL;
	
	char *inp = r_str_newf ("*%s", input);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		r_core_seek (core, fcn->addr, true);
		Sdb *db = __core_cmd_anal_fcn_stats (core, inp);
                sdb_num_set (db, ".addr", fcn->addr, 0);
		r_list_append (dbs, db);
	}
	free (inp);
	Sdb *db;
	r_list_foreach (dbs, iter, db) {
		SdbList *ls = sdb_foreach_list (db, true);
		ls_foreach (ls, it, kv) {
			const char *name = sdbkv_key(kv);
			sdb_add (d, name, "1", 0);
		}
		ls_free (ls);
	}
	RTable *t = r_table_new ();
	SdbList *ls = sdb_foreach_list (d, true);
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	r_table_add_column (t, typeString, "name", 0);
	r_table_add_column (t, typeNumber, "addr", 0);
	ls_foreach (ls, it, kv) {
		const char *key = sdbkv_key (kv);
		if (*key == '.') continue;
		r_table_add_column (t, typeNumber, key, 0);
	}
	sdb_free (d);

	r_list_foreach (dbs, iter, db) {
		SdbList *ls = sdb_foreach_list (db, false);
		SdbListIter *it;
		SdbKv *kv;
		char *names[100];
		int i;
		for (i = 0;i<100;i++) {
			names[i] = NULL;
		}
		ls_foreach (ls, it, kv) {
			const char *key = sdbkv_key(kv);
			const char *value = sdbkv_value (kv);
			if (*key == '.') {
				continue;
			}
			int idx = r_table_column_nth (t, key);
			if (idx != -1) {
				ut64 nv = r_num_get (NULL, value);
				names[idx] = r_str_newf ("%d", (int)nv);
			} else {
				eprintf ("Invalid column name (%s) %c", key, 10);
			}
		}
		RList *items = r_list_newf (free);
		ut64 fcnAddr = sdb_num_get (db, ".addr", 0);

		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, fcnAddr, 0);
		r_list_append (items, fcn?strdup (fcn->name):strdup (""));
		r_list_append (items, fcn?r_str_newf ("0x%08"PFMT64x, fcnAddr): strdup ("0"));
		int cols = r_list_length (t->cols);
		for (i = 2; i < cols; i++) {
			if (names[i]) {
				if (names[i][0] != '.') {
					r_list_append (items, strdup (names[i]));
				}
				R_FREE (names[i]);
			} else {
				r_list_append (items, strdup ("0"));
			}
		}
		r_table_add_row_list (t, items);
	}
	r_table_query (t, (*input)?input + 1: "");
	char *ts = isJson? r_table_tojson(t): r_table_tostring (t);
	r_cons_printf ("%s", ts);
	free (ts);
	r_table_free (t);
	r_core_seek (core, oseek, true);
	r_list_free (dbs);
}

static int cmd_anal_fcn(RCore *core, const char *input) {
	char i;

	r_cons_break_timeout (r_config_get_i (core->config, "anal.timeout"));
	switch (input[1]) {
	case '-': // "af-"
		if (!input[2]) {
			cmd_anal_fcn (core, "f-$$");
			r_core_anal_undefine (core, core->offset);
		} else if (!strcmp (input + 2, "*")) {
			RAnalFunction *f;
			RListIter *iter;
			r_list_foreach (core->anal->fcns, iter, f) {
				r_anal_del_jmprefs (core->anal, f);
			}
			r_list_purge (core->anal->fcns);
			core->anal->fcn_tree = NULL;
			core->anal->fcn_addr_tree = NULL;
		} else {
			ut64 addr = input[2]
				? r_num_math (core->num, input + 2)
				: core->offset;
			r_core_anal_undefine (core, addr);
			r_anal_fcn_del_locs (core->anal, addr);
			r_anal_fcn_del (core->anal, addr);
		}
		break;
	case 'j': // "afj"
		{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				char *args = strdup (input + 2);
				RList *argv = r_str_split_list (args, " ", 0);
				ut64 table = r_num_math (core->num, r_list_get_n (argv, 0));
				ut64 elements = r_num_math (core->num, r_list_get_n (argv, 1));
				r_anal_jmptbl (core->anal, fcn, core->offset, table, elements, UT64_MAX);
				run_pending_anal (core);
			} else {
				eprintf ("No function defined here\n");
			}
		}
		break;
	case 'a': // "afa"
		if (input[2] == 'l') { // "afal" : list function call arguments
			int show_args = r_config_get_i (core->config, "dbg.funcarg");
			if (show_args) {
				r_core_print_func_args (core);
			}
		} else {
			r_core_print_func_args (core);
		}
		break;
	case 'd': // "afd"
		{
		ut64 addr = 0;
		if (input[2] == '?') {
			eprintf ("afd [offset]\n");
		} else if (input[2] == ' ') {
			addr = r_num_math (core->num, input + 2);
		} else {
			addr = core->offset;
		}
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
		if (input[2] == 'j') { // afdj
			PJ *pj = pj_new ();
			if (!pj) {
				return false;
			}
			pj_o (pj);
			if (fcn) {
				pj_ks (pj, "name", fcn->name);
				pj_ki (pj, "offset", (int)(addr - fcn->addr));
			}
			pj_end (pj);
			r_cons_println (pj_string (pj));
			pj_free (pj);
		} else {
			if (fcn) {
				if (fcn->addr != addr) {
					r_cons_printf ("%s + %d\n", fcn->name,
							(int)(addr - fcn->addr));
				} else {
					r_cons_println (fcn->name);
				}
			} else {
				eprintf ("afd: Cannot find function\n");
			}
		}
		}
		break;
	case 'f': // "aff"
		r_anal_fcn_fit_overlaps (core->anal, NULL);
		break;
	case 'u': // "afu"
		{
		if (input[2] != ' ') {
			eprintf ("Missing argument\n");
			return false;
		}

		ut64 addr = core->offset;
		ut64 addr_end = r_num_math (core->num, input + 2);
		if (addr_end < addr) {
			eprintf ("Invalid address ranges\n");
		} else {
			int depth = 1;
			ut64 a, b;
			const char *c;
			a = r_config_get_i (core->config, "anal.from");
			b = r_config_get_i (core->config, "anal.to");
			c = r_config_get (core->config, "anal.limits");
			r_config_set_i (core->config, "anal.from", addr);
			r_config_set_i (core->config, "anal.to", addr_end);
			r_config_set (core->config, "anal.limits", "true");

			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) {
				r_anal_fcn_resize (core->anal, fcn, addr_end - addr);
			}
			r_core_anal_fcn (core, addr, UT64_MAX,
					R_ANAL_REF_TYPE_NULL, depth);
			fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) {
				r_anal_fcn_resize (core->anal, fcn, addr_end - addr);
			}
			r_config_set_i (core->config, "anal.from", a);
			r_config_set_i (core->config, "anal.to", b);
			r_config_set (core->config, "anal.limits", c? c: "");
		}
		}
		break;
	case '+': { // "af+"
		if (input[2] != ' ') {
			eprintf ("Missing arguments\n");
			return false;
		}
		char *ptr = strdup (input + 3);
		const char *ptr2;
		int n = r_str_word_set0 (ptr);
		const char *name = NULL;
		ut64 addr = UT64_MAX;
		ut64 size = 0LL;
		RAnalDiff *diff = NULL;
		int type = R_ANAL_FCN_TYPE_FCN;
		if (n > 1) {
			switch (n) {
			case 5:
				size = r_num_math (core->num, r_str_word_get0 (ptr, 4));
			case 4:
				ptr2 = r_str_word_get0 (ptr, 3);
				if (!(diff = r_anal_diff_new ())) {
					eprintf ("error: Cannot init RAnalDiff\n");
					free (ptr);
					return false;
				}
				if (ptr2[0] == 'm') {
					diff->type = R_ANAL_DIFF_TYPE_MATCH;
				} else if (ptr2[0] == 'u') {
					diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				}
			case 3:
				ptr2 = r_str_word_get0 (ptr, 2);
				if (strchr (ptr2, 'l')) {
					type = R_ANAL_FCN_TYPE_LOC;
				} else if (strchr (ptr2, 'i')) {
					type = R_ANAL_FCN_TYPE_IMP;
				} else if (strchr (ptr2, 's')) {
					type = R_ANAL_FCN_TYPE_SYM;
				} else {
					type = R_ANAL_FCN_TYPE_FCN;
				}
			case 2:
				name = r_str_word_get0 (ptr, 1);
			case 1:
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			if (!r_anal_fcn_add (core->anal, addr, size, name, type, diff)) {
				eprintf ("Cannot add function (duplicated)\n");
			}
		}
		r_anal_diff_free (diff);
		free (ptr);
		}
		break;
	case 'o': // "afo"
		switch (input[2]) {
		case '?':
			eprintf ("Usage: afo[?sj] ([name|offset])\n");
			break;
		case 'j':
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				PJ *pj = pj_new ();
				if (!pj) {
					return false;
				}
				pj_o (pj);
				if (fcn) {
					pj_ki (pj, "address", fcn->addr);
				}
				pj_end (pj);
				r_cons_println (pj_string (pj));
				pj_free (pj);
			}
			break;
		case '\0':
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					r_cons_printf ("0x%08" PFMT64x "\n", fcn->addr);
				}
			}
			break;
		case 's': // "afos"
			{
				ut64 addr = core->offset;
				RListIter *iter;
				RList *list = r_anal_get_fcn_in_list (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				RAnalFunction *fcn;
				r_list_foreach (list, iter, fcn) {
					r_cons_printf ("= 0x%08" PFMT64x "\n", fcn->addr);
				}
				r_list_free (list);
			}
			break;
		case ' ':
			{
				RAnalFunction *fcn;
				ut64 addr = r_num_math (core->num, input + 3);
				if (addr == 0LL) {
					fcn = r_anal_fcn_find_name (core->anal, input + 3);
				} else {
					fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				}
				if (fcn) {
					r_cons_printf ("0x%08" PFMT64x "\n", fcn->addr);
				}
			}
			break;
		}
		break;
	case 'i': // "afi"
		switch (input[2]) {
		case '?':
			r_core_cmd_help (core, help_msg_afi);
			break;
		case '.': // "afi."
			{
				ut64 addr = core->offset;
				if (input[3] == ' ') {
					addr = r_num_math (core->num, input + 3);
				}
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					r_cons_printf ("%s\n", fcn->name);
				}
			}
			break;
		case 'l': // "afil"
			if (input[3] == '?') {
				// TODO #7967 help refactor
				help_msg_afll[1] = "afil";
				r_core_cmd_help (core, help_msg_afll);
				break;
			}
			/* fallthrough */
		case 'i': // "afii"
			if (input[3] == '-') {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					r_list_free (fcn->imports);
					fcn->imports = NULL;
				}
			} else if (input[3] == ' ') {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					if (!fcn->imports) {
						fcn->imports = r_list_newf ((RListFree)free);
					}
					r_list_append (fcn->imports, r_str_trim_dup (input + 4));
				} else {
					eprintf ("No function found\n");
				}
			} else {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				if (fcn && fcn->imports) {
					char *imp;
					RListIter *iter;
					r_list_foreach (fcn->imports, iter, imp) {
						r_cons_printf ("%s\n", imp);
					}
				}
			}
			break;
		case 's': // "afis"
			if (input[3] == 'a') { // "afisa"
				__core_cmd_anal_fcn_allstats (core, input + 4);
			} else {
				sdb_free (__core_cmd_anal_fcn_stats (core, input + 3));
			}
			break;
		case 'j': // "afij"
		case '*': // "afi*"
			r_core_anal_fcn_list (core, input + 3, input + 2);
			break;
		case 'p': // "afip"
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					r_cons_printf ("is-pure: %s\n", r_anal_fcn_get_purity (core->anal, fcn) ? "true" : "false");
				}
			}
			break;
		default:
			i = 1;
			r_core_anal_fcn_list (core, input + 2, &i);
			break;
		}
		break;
	case 'l': // "afl"
		switch (input[2]) {
		case '?':
			r_core_cmd_help (core, help_msg_afl);
			break;
		case 's': // "afls"
			switch (input[3]) {
			case '?':
				r_core_cmd_help (core, help_msg_afls);
				break;
			case 'a': // "aflsa"
				core->anal->fcns->sorted = false;
				r_list_sort (core->anal->fcns, cmpaddr);
				break;
			case 'b': // "aflsb"
				core->anal->fcns->sorted = false;
				r_list_sort (core->anal->fcns, cmpbbs);
				break;
			case 's': // "aflss"
				core->anal->fcns->sorted = false;
				r_list_sort (core->anal->fcns, cmpsize);
				break;
			case 'n': // "aflsn"
				core->anal->fcns->sorted = false;
				r_list_sort (core->anal->fcns, cmpname);
				break;
			default:
				core->anal->fcns->sorted = false;
				r_list_sort (core->anal->fcns, cmpaddr);
				break;
			}
			break;
		case 'l': // "afll"
			if (input[3] == '?') {
				// TODO #7967 help refactor
				help_msg_afll[1] = "afll";
				r_core_cmd_help (core, help_msg_afll);
				break;
			}
			/* fallthrough */
		case 't': // "aflt"
		case 'j': // "aflj"
		case 'q': // "aflq"
		case 'm': // "aflm"
		case '+': // "afl+"
		case '=': // "afl="
		case '*': // "afl*"
		case '.': // "afl*"
			r_core_anal_fcn_list (core, NULL, input + 2);
			break;
		case 'c': // "aflc"
			r_cons_printf ("%d\n", r_list_length (core->anal->fcns));
			break;
		default: // "afl "
			r_core_anal_fcn_list (core, NULL, "o");
			break;
		}
		break;
	case 's': // "afs"
		switch (input[2]) {
		case '!': { // "afs!"
			char *sig = r_core_cmd_str (core, "afs");
			char *data = r_core_editor (core, NULL, sig);
			if (sig && data) {
				r_core_cmdf (core, "\"afs %s\"", data);
			}
			free (sig);
			free (data);
			break;
		}
		case 'r': { // "afsr"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) {
				char *type = r_str_newf ("type.%s", input + 4);
				if (sdb_exists (core->anal->sdb_types, type)) {
					char *query = r_str_newf ("anal/types/func.%s.ret=%s", fcn->name, input + 4);
					sdb_querys (core->sdb, NULL, 0, query);
					free (query);
				}
				free (type);
			} else {
				eprintf ("There's no function defined in here.\n");
			}
			break;
		}
		case '?': // "afs?"
			r_core_cmd_help (core, help_msg_afs);
			break;
		default: { // "afs"
			ut64 addr = core->offset;
			RAnalFunction *f;
			const char *arg = r_str_trim_ro (input + 2);
			if ((f = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
				if (arg && *arg) {
					// parse function signature here
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
					char *fcnstr = r_str_newf ("%s;", arg), *fcnstr_copy = strdup (fcnstr);
					char *fcnname = strrchr (r_str_trim_tail (strtok (fcnstr_copy, "(")), ' ');
					if (fcnname) {
						fcnname++;
						 if (strcmp (fcn->name, fcnname)) {
							(void)__setFunctionName (core, addr, fcnname, false);
							f = r_anal_get_fcn_in (core->anal, addr, -1);
						 }
						 r_anal_str_to_fcn (core->anal, f, fcnstr);
					}
					free (fcnstr_copy);
					free (fcnstr);
				} else {
					// not working
					char *str = r_anal_fcn_to_string (core->anal, f);
					if (str) {
						r_cons_println (str);
						free (str);
					}
					// working, but wtf
					char *sig = r_anal_fcn_format_sig (core->anal, f, f->name, NULL, NULL, NULL);
					if (sig) {
						r_cons_println (sig);
						free (sig);
					}
				}
			} else {
				eprintf ("No function defined at 0x%08" PFMT64x "\n", addr);
			}
			break;
		}
		}
		break;
	case 'm': // "afm" - merge two functions
		r_core_anal_fcn_merge (core, core->offset, r_num_math (core->num, input + 2));
		break;
	case 'M': // "afM" - print functions map
		r_core_anal_fmap (core, input + 1);
		break;
	case 'v': // "afv"
		var_cmd (core, input + 2);
		break;
	case 't': // "aft"
		type_cmd (core, input + 2);
		break;
	case 'C': // "afC"
		if (input[2] == 'c') {
			RAnalFunction *fcn;
			if ((fcn = r_anal_get_fcn_in (core->anal, core->offset, 0)) != NULL) {
				r_cons_printf ("%i\n", r_anal_fcn_cc (core->anal, fcn));
			} else {
				eprintf ("Error: Cannot find function at 0x08%" PFMT64x "\n", core->offset);
			}
		} else if (input[2] == 'l') {
			RAnalFunction *fcn;
			if ((fcn = r_anal_get_fcn_in (core->anal, core->offset, 0)) != NULL) {
				r_cons_printf ("%d\n", r_anal_fcn_loops (fcn));
			} else {
				eprintf ("Error: Cannot find function at 0x08%" PFMT64x "\n", core->offset);
			}
		} else if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_afC);
		} else {
			afCc (core, r_str_trim_ro (input + 2));
		}
		break;
	case 'c':{ // "afc"
		RAnalFunction *fcn = NULL;
		if (!input[2] || input[2] == ' ' || input[2] == 'r' || input[2] == 'a') {
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (!fcn) {
				eprintf ("afc: Cannot find function here\n");
				break;
			}
		}
		switch (input[2]) {
		case '\0': // "afc"
			r_cons_println (fcn->cc);
			break;
		case ' ': { // "afc "
			char *argument = strdup (input + 3);
			char *cc = argument;
			r_str_trim (cc);
			if (!r_anal_cc_exist (core->anal, cc)) {
				const char *asmOs = r_config_get (core->config, "asm.os");
				eprintf ("afc: Unknown calling convention '%s' for '%s'\n"
						"See afcl for available types\n", cc, asmOs);
			} else {
				fcn->cc = r_str_constpool_get (&core->anal->constpool, cc);
			}
			free (argument);
			break;
		}
		case '=': // "afc="
			if (input[3]) {
				char *argument = strdup (input + 3);
				char *cc = argument;
				r_str_trim (cc);
				r_core_cmdf (core, "k anal/cc/default.cc=%s", cc);
				r_anal_set_reg_profile (core->anal);
				free (argument);
			} else {
				r_core_cmd0 (core, "k anal/cc/default.cc");
			}
			break;
		case 'a': // "afca"
			eprintf ("Todo\n");
			break;
		case 'f': // "afcf" "afcfj"
			cmd_anal_fcn_sig (core, input + 3);
			break;
		case 'k': // "afck"
			r_core_cmd0 (core, "k anal/cc/*");
			break;
		case 'l': // "afcl" list all function Calling conventions.
			sdb_foreach (core->anal->sdb_cc, cc_print, NULL);
			break;
		case 'o': { // "afco"
			char *dbpath = r_str_trim_dup (input + 3);
			if (r_file_exists (dbpath)) {
				Sdb *db = sdb_new (0, dbpath, 0);
				sdb_merge (core->anal->sdb_cc, db);
				sdb_close (db);
				sdb_free (db);
			}
			free (dbpath);
			break;
		}
		case 'r': {	// "afcr"
			int i;
			char *out, *cmd, *regname, *tmp;
			char *subvec_str = r_str_new ("");
			char *json_str = r_str_new ("");
			// if json_str initialize to NULL, it's possible for afcrj to output a (NULL)
			// subvec_str and json_str should be valid until exiting this code block
			bool json = input[3] == 'j'? true: false;
			for (i = -1; i <= 10; i++) {
				if (i == -1) {
					cmd = r_str_newf ("cc.%s.ret", fcn->cc);
				} else {
					cmd = r_str_newf ("cc.%s.arg%d", fcn->cc, i);
				}
				regname = r_str_new (cmd);
				out = sdb_querys (core->anal->sdb_cc, NULL, 0, cmd);
				free (cmd);
				if (out) {
					out[strlen (out) - 1] = 0;
					if (json) {
						tmp = subvec_str;
						subvec_str = r_str_newf ("%s,\"%s\"", subvec_str, out);
						free (tmp);
					} else {
						r_cons_printf ("%s: %s\n", regname, out);
					}
					free (out);
				}
				free (regname);
				if (!subvec_str[0]) {
					continue;
				}
				switch (i) {
				case -1: {
					tmp = json_str;
					json_str = r_str_newf ("%s,\"ret\":%s", json_str, subvec_str + 1);
					free (tmp);
				} break;
				case 10: {
					tmp = json_str;
					json_str = r_str_newf ("%s,\"args\":[%s]", json_str, subvec_str + 1);
					free (tmp);
				} break;
				default:
					continue;
				}
				free (subvec_str);
				subvec_str = r_str_new ("");
			}
			if (json && json_str[0]) {
				r_cons_printf ("{%s}\n", json_str + 1);
			}
			free (subvec_str);
			free (json_str);
		} break;
		case 'R': { // "afcR"
			/* very slow, but im tired of waiting for having this, so this is the quickest implementation */
			int i;
			char *cc = r_core_cmd_str (core, "k anal/cc/default.cc");
			r_str_trim (cc);
			for (i = 0; i < 6; i++) {
				char *res = r_core_cmd_strf (core, "k anal/cc/cc.%s.arg%d", cc, i);
				r_str_trim_nc (res);
				if (*res) {
					char *row = r_core_cmd_strf (core, "drr~%s 0x", res);
					r_str_trim (row);
					r_cons_printf ("arg[%d] %s\n", i, row);
					free (row);
				}
				free (res);
			}
			free (cc);
			}
			break;
		case '?': // "afc?"
		default:
			r_core_cmd_help (core, help_msg_afc);
		}
		}
		break;
	case 'B': // "afB" // set function bits
		if (input[2] == ' ') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				int bits = atoi (input + 3);
				r_anal_hint_set_bits (core->anal, fcn->addr, bits);
				r_anal_hint_set_bits (core->anal,
					fcn->addr + r_anal_fcn_size (fcn),
					core->anal->bits);
				fcn->bits = bits;
			} else {
				eprintf ("afB: Cannot find function to set bits at 0x%08"PFMT64x"\n", core->offset);
			}
		} else {
			eprintf ("Usage: afB [bits]\n");
		}
		break;
	case 'b': // "afb"
		switch (input[2]) {
		case '-': // "afb-"
			anal_fcn_del_bb (core, input + 3);
			break;
		case 'e': // "afbe"
			anal_bb_edge (core, input + 3);
			break;
		case 'F': // "afbF"
			{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
			if (fcn) {
				RAnalBlock *bb = r_anal_fcn_bbget_in (core->anal, fcn, core->offset);
				if (bb) {
					if (input[3]) {
						int n = atoi (input + 3);
						bb->folded = n;
					} else {
						bb->folded = !bb->folded;
					}
				} else {
					r_warn_if_reached ();
				}
			}
			}
			break;
		case 0:
		case ' ': // "afb "
		case 'q': // "afbq"
		case 'r': // "afbr"
		case '=': // "afb="
		case '*': // "afb*"
		case 'j': // "afbj"
		case 't': // "afbt"
			anal_fcn_list_bb (core, input + 2, false);
			break;
		case 'i': // "afbi"
			anal_fcn_list_bb (core, input + 2, true);
			break;
		case '.': // "afb."
			anal_fcn_list_bb (core, input[2]? " $$": input + 2, true);
			break;
		case '+': // "afb+"
			anal_fcn_add_bb (core, input + 3);
			break;
		case 'c': // "afbc"
			{
			const char *ptr = input + 3;
			ut64 addr = r_num_math (core->num, ptr);
			ut32 color;
			ptr = strchr (ptr, ' ');
			if (ptr) {
				ptr = strchr (ptr + 1, ' ');
				if (ptr) {
					color = r_num_math (core->num, ptr + 1);
					RAnalOp *op = r_core_op_anal (core, addr);
					if (op) {
						r_anal_colorize_bb (core->anal, addr, color);
						r_anal_op_free (op);
					} else {
						eprintf ("Cannot analyze opcode at 0x%08" PFMT64x "\n", addr);
					}
				}
			}
			}
			break;
		default:
		case '?':
			r_core_cmd_help (core, help_msg_afb);
			break;
		}
		break;
	case 'n': // "afn"
		switch (input[2]) {
		case 's': // "afns"
			if (input[3] == 'j') { // "afnsj"
				free (r_core_anal_fcn_autoname (core, core->offset, 1, input[3]));
			} else {
				free (r_core_anal_fcn_autoname (core, core->offset, 1, 0));
			}
			break;
		case 'a': // "afna"
			{
			char *name = r_core_anal_fcn_autoname (core, core->offset, 0, 0);
			if (name) {
				r_cons_printf ("afn %s 0x%08" PFMT64x "\n", name, core->offset);
				free (name);
			}
			}
			break;
		case '.': // "afn."
		case 0: // "afn"
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
				if (fcn) {
					r_cons_printf ("%s\n", fcn->name);
				}
			}
			break;
		case ' ': // "afn "
			{
			ut64 off = core->offset;
			char *p, *name = strdup (r_str_trim_ro (input + 3));
			if ((p = strchr (name, ' '))) {
				*p++ = 0;
				off = r_num_math (core->num, p);
			}
			if (*name == '?') {
				eprintf ("Usage: afn newname [off]   # set new name to given function\n");
			} else {
				if (r_str_startswith (name, "base64:")) {
					char *res = (char *)r_base64_decode_dyn (name + 7, -1);
					if (res) {
						free (name);
						name = res;
					}
				}
				if (!*name || !__setFunctionName (core, off, name, false)) {
					eprintf ("Cannot find function at 0x%08" PFMT64x "\n", off);
				}
			}
			free (name);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_afn);
			break;
		}
		break;
	case 'S': // afS"
		{
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
		if (fcn) {
			fcn->maxstack = r_num_math (core->num, input + 3);
			//fcn->stack = fcn->maxstack;
		}
		}
		break;
#if 0
	/* this is undocumented and probably have no uses. plz discuss */
	case 'e': // "afe"
		{
		RAnalFunction *fcn;
		ut64 off = core->offset;
		char *p, *name = strdup ((input[2]&&input[3])? input + 3: "");
		if ((p = strchr (name, ' '))) {
			*p = 0;
			off = r_num_math (core->num, p + 1);
		}
		fcn = r_anal_get_fcn_in (core->anal, off, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			RAnalBlock *b;
			RListIter *iter;
			RAnalRef *r;
			r_list_foreach (fcn->refs, iter, r) {
				r_cons_printf ("0x%08" PFMT64x " -%c 0x%08" PFMT64x "\n", r->at, r->type, r->addr);
			}
			r_list_foreach (fcn->bbs, iter, b) {
				int ok = 0;
				if (b->type == R_ANAL_BB_TYPE_LAST) ok = 1;
				if (b->type == R_ANAL_BB_TYPE_FOOT) ok = 1;
				if (b->jump == UT64_MAX && b->fail == UT64_MAX) ok = 1;
				if (ok) {
					r_cons_printf ("0x%08" PFMT64x " -r\n", b->addr);
					// TODO: check if destination is outside the function boundaries
				}
			}
		} else eprintf ("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		free (name);
		}
		break;
#endif
	case 'x': // "afx"
		switch (input[2]) {
		case '\0': // "afx"
		case 'j': // "afxj"
		case ' ': // "afx "
		{
			PJ *pj = pj_new ();
			if (input[2] == 'j') {
				pj_a (pj);
			}
			if (!pj) {
				return false;
			}
			// list xrefs from current address
			{
				ut64 addr = input[2]==' '? r_num_math (core->num, input + 2): core->offset;
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					RAnalRef *ref;
					RListIter *iter;
					RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
					r_list_foreach (refs, iter, ref) {
						if (input[2] == 'j') {
							pj_o (pj);
							pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
							pj_kn (pj, "from", ref->at);
							pj_kn (pj, "to", ref->addr);
							pj_end (pj);
						} else {
							r_cons_printf ("%c 0x%08" PFMT64x " -> 0x%08" PFMT64x "\n",
									ref->type, ref->at, ref->addr);
						}
					}
					r_list_free (refs);
				} else {
					eprintf ("afx: Cannot find function at 0x%08"PFMT64x"\n", addr);
				}
			}
			if (input[2] == 'j') {
				pj_end (pj);
				r_cons_println (pj_string (pj));
			}
			pj_free (pj);
			break;
		}
		default:
			eprintf ("Wrong command. Look at af?\n");
			break;
		}
		break;
	case 'F': // "afF"
		{
			int val = input[2] && r_num_math (core->num, input + 2);
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
			if (fcn) {
				fcn->folded = input[2]? val: !fcn->folded;
			}
		}
		break;
	case '?': // "af?"
		r_core_cmd_help (core, help_msg_af);
		break;
	case 'r': // "afr" // analyze function recursively
	case ' ': // "af "
	case '\0': // "af"
		{
		char *uaddr = NULL, *name = NULL;
		int depth = r_config_get_i (core->config, "anal.depth");
		bool analyze_recursively = r_config_get_i (core->config, "anal.calls");
		RAnalFunction *fcn = NULL;
		ut64 addr = core->offset;
		if (input[1] == 'r') {
			input++;
			analyze_recursively = true;
		}

		// first undefine
		if (input[0] && input[1] == ' ') {
			name = strdup (r_str_trim_ro (input + 2));
			uaddr = strchr (name, ' ');
			if (uaddr) {
				*uaddr++ = 0;
				addr = r_num_math (core->num, uaddr);
			}
			// depth = 1; // or 1?
			// disable hasnext
		}
		//r_core_anal_undefine (core, core->offset);
		r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
		fcn = r_anal_get_fcn_in (core->anal, addr, 0);
		if (fcn) {
			/* ensure we use a proper name */
			__setFunctionName (core, addr, fcn->name, false);
			if (core->anal->opt.vars) {
				r_core_recover_vars (core, fcn, true);
			}
		} else {
			if (core->anal->verbose) {
				eprintf ("Warning: Unable to analyze function at 0x%08"PFMT64x"\n", addr);
			}
		}
		if (analyze_recursively) {
			fcn = r_anal_get_fcn_in (core->anal, addr, 0); /// XXX wrong in case of nopskip
			if (fcn) {
				RAnalRef *ref;
				RListIter *iter;
				RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
				r_list_foreach (refs, iter, ref) {
					if (ref->addr == UT64_MAX) {
						//eprintf ("Warning: ignore 0x%08"PFMT64x" call 0x%08"PFMT64x"\n", ref->at, ref->addr);
						continue;
					}
					if (ref->type != R_ANAL_REF_TYPE_CODE && ref->type != R_ANAL_REF_TYPE_CALL) {
						/* only follow code/call references */
						continue;
					}
					if (!r_io_is_valid_offset (core->io, ref->addr, !core->anal->opt.noncode)) {
						continue;
					}
					r_core_anal_fcn (core, ref->addr, fcn->addr, R_ANAL_REF_TYPE_CALL, depth);
					/* use recursivity here */
#if 1
					RAnalFunction *f = r_anal_get_fcn_at (core->anal, ref->addr, 0);
					if (f) {
						RListIter *iter;
						RAnalRef *ref;
						RList *refs1 = r_anal_fcn_get_refs (core->anal, f);
						r_list_foreach (refs1, iter, ref) {
							if (!r_io_is_valid_offset (core->io, ref->addr, !core->anal->opt.noncode)) {
								continue;
							}
							if (ref->type != 'c' && ref->type != 'C') {
								continue;
							}
							r_core_anal_fcn (core, ref->addr, f->addr, R_ANAL_REF_TYPE_CALL, depth);
							// recursively follow fcn->refs again and again
						}
						r_list_free (refs1);
					} else {
						f = r_anal_get_fcn_in (core->anal, fcn->addr, 0);
						if (f) {
							/* cut function */
							r_anal_fcn_resize (core->anal, f, addr - fcn->addr);
							r_core_anal_fcn (core, ref->addr, fcn->addr,
									R_ANAL_REF_TYPE_CALL, depth);
							f = r_anal_get_fcn_at (core->anal, fcn->addr, 0);
						}
						if (!f) {
							eprintf ("af: Cannot find function at 0x%08" PFMT64x "\n", fcn->addr);
						}
					}
#endif
				}
				r_list_free (refs);
				if (core->anal->opt.vars) {
					r_core_recover_vars (core, fcn, true);
				}
			}
		}
		if (name) {
			if (*name && !__setFunctionName (core, addr, name, true)) {
				eprintf ("af: Cannot find function at 0x%08" PFMT64x "\n", addr);
			}
			free (name);
		}
		r_core_anal_propagate_noreturn (core);
#if 0
		// XXX THIS IS VERY SLOW
		if (core->anal->opt.vars) {
			RListIter *iter;
			RAnalFunction *fcni = NULL;
			r_list_foreach (core->anal->fcns, iter, fcni) {
				if (r_cons_is_breaked ()) {
					break;
				}
				r_core_recover_vars (core, fcni, true);
			}
		}
#endif
		flag_every_function (core);
	}
		break;
	default:
		return false;
		break;
	}
	return true;
}

// size: 0: bits; -1: any; >0: exact size
static void __anal_reg_list(RCore *core, int type, int bits, char mode) {
	if (mode == 'i') {
		r_core_debug_ri (core, core->anal->reg, 0);
		return;
	}
	RReg *hack = core->dbg->reg;
	const char *use_color;
	int use_colors = r_config_get_i (core->config, "scr.color");
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->context->pal.x)? core->cons->context->pal.x
		use_color = ConsP (creg) : Color_BWHITE;
	} else {
		use_color = NULL;
	}
	if (bits < 0) {
		// TODO Change the `size` argument of r_debug_reg_list to use -1 for any and 0 for anal->bits
		bits = 0;
	} else if (!bits) {
		bits = core->anal->bits;
	}
	int mode2 = mode;
	if (core->anal) {
		core->dbg->reg = core->anal->reg;
		if (core->anal->cur && core->anal->cur->arch) {
			/* workaround for thumb */
			if (!strcmp (core->anal->cur->arch, "arm") && bits == 16) {
				bits = 32;
			}
			/* workaround for 6502 */
			if (!strcmp (core->anal->cur->arch, "6502") && bits == 8) {
				mode2 = mode == 'j' ? 'J' : mode;
				if (mode == 'j') {
					r_cons_printf ("{");
				}
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 16, mode2, use_color); // XXX detect which one is current usage
				if (mode == 'j') {
					r_cons_printf (",");
				}
			}
			if (!strcmp (core->anal->cur->arch, "avr") && bits == 8) {
				mode2 = mode == 'j' ? 'J' : mode;
				if (mode == 'j') {
					r_cons_printf ("{");
				}
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 16, mode2, use_color); // XXX detect which one is current usage
				if (mode == 'j') {
					r_cons_printf (",");
				}
			}
		}
	}

	if (mode == '=') {
		int pcbits = 0;
		const char *pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
		RRegItem *reg = r_reg_get (core->anal->reg, pcname, 0);
		if (bits != reg->size) {
			pcbits = reg->size;
		}
		if (pcbits) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, 2, use_color); // XXX detect which one is current usage
		}
	}
	r_debug_reg_list (core->dbg, type, bits, mode2, use_color);
	if (mode2 == 'J') {
		r_cons_print ("}\n");
	}
	core->dbg->reg = hack;
}

// XXX dup from drp :OOO
void cmd_anal_reg(RCore *core, const char *str) {
	if (0) {
		/* enable this block when dr and ar use the same code but just using
		   core->dbg->reg or core->anal->reg and removing all the debugger
		   dependent code */
		RReg *reg = core->dbg->reg;
		core->dbg->reg = core->anal->reg;
		cmd_debug_reg (core, str);
		core->dbg->reg = reg;
		return;
	}

	int size = 0, i, type = R_REG_TYPE_GPR;
	int bits = (core->anal->bits & R_SYS_BITS_64)? 64: 32;
	int use_colors = r_config_get_i (core->config, "scr.color");
	RRegItem *r;
	const char *use_color;
	const char *name;
	char *arg;

	if (use_colors) {
#define ConsP(x) (core->cons && core->cons->context->pal.x)? core->cons->context->pal.x
		use_color = ConsP (creg)
		: Color_BWHITE;
	} else {
		use_color = NULL;
	}
	switch (str[0]) {
	case 'l': // "arl"
	{
		const bool use_json = str[1] == 'j';
		RRegSet *rs = r_reg_regset_get (core->anal->reg, R_REG_TYPE_GPR);
		if (rs) {
			RRegItem *r;
			RListIter *iter;
			PJ *pj = pj_new ();
			pj_a (pj);
			r_list_foreach (rs->regs, iter, r) {
				if (use_json) {
					pj_s (pj, r->name);
				} else {
					r_cons_println (r->name);
				}
			}
			if (use_json) {
				pj_end (pj);
				const char *s = pj_string (pj);
				r_cons_println (s);
			}
			pj_free (pj);
		}
	} break;
	case '0': // "ar0"
		r_reg_arena_zero (core->anal->reg);
		break;
	case 'A': // "arA"
		{
			int nargs = 4;
			RReg *reg = core->anal->reg;
			for (i = 0; i < nargs; i++) {
				const char *name = r_reg_get_name (reg, r_reg_get_name_idx (sdb_fmt ("A%d", i)));
				ut64 off = r_reg_getv (core->anal->reg, name);
				r_cons_printf ("0x%08"PFMT64x" ", off);
				// XXX very ugly hack
				char *s = r_core_cmd_strf (core, "pxr 32 @ 0x%08"PFMT64x, off);
				if (s) {
					char *nl = strchr (s, '\n');
					if (nl) {
						*nl = 0;
						r_cons_printf ("%s\n", s);
					}
					free (s);
				}
//				r_core_cmd0 (core, "ar A0,A1,A2,A3");
			}
		}
		break;
	case 'C': // "arC"
		if (core->anal->reg->reg_profile_cmt) {
			r_cons_println (core->anal->reg->reg_profile_cmt);
		}
		break;
	case 'w': // "arw"
		switch (str[1]) {
		case '?': {
			r_core_cmd_help (core, help_msg_arw);
			break;
		}
		case ' ':
			r_reg_arena_set_bytes (core->anal->reg, str + 1);
			break;
		default:
			r_core_cmd_help (core, help_msg_arw);
			break;
		}
		break;
	case 'a': // "ara"
		switch (str[1]) {
		case '?': // "ara?"
			r_core_cmd_help (core, help_msg_ara);
			break;
		case 's': // "aras"
			r_reg_arena_swap (core->anal->reg, false);
			break;
		case '+': // "ara+"
			r_reg_arena_push (core->anal->reg);
			break;
		case '-': // "ara-"
			r_reg_arena_pop (core->anal->reg);
			break;
		default: {
			int i, j;
			RRegArena *a;
			RListIter *iter;
			for (i = 0; i < R_REG_TYPE_LAST; i++) {
				RRegSet *rs = &core->anal->reg->regset[i];
				j = 0;
				r_list_foreach (rs->pool, iter, a) {
					r_cons_printf ("%s %p %d %d %s %d\n",
						(a == rs->arena)? "*": ".", a,
						i, j, r_reg_get_type (i), a->size);
					j++;
				}
			}
		} break;
		}
		break;
	case '?': // "ar?"
		if (str[1]) {
			ut64 off = r_reg_getv (core->anal->reg, str + 1);
			r_cons_printf ("0x%08" PFMT64x "\n", off);
		} else {
			r_core_cmd_help (core, help_msg_ar);
		}
		break;
	case 'r': // "arr"
		switch (str[1]) {
		case 'j': // "arrj"
			r_core_debug_rr (core, core->anal->reg, 'j');
			break;
		default:
			r_core_debug_rr (core, core->anal->reg, 0);
			break;
		}
		break;
	case 'S': { // "arS"
		int sz;
		ut8 *buf = r_reg_get_bytes (core->anal->reg, R_REG_TYPE_GPR, &sz);
		r_cons_printf ("%d\n", sz);
		free (buf);
		} break;
	case 'b': { // "arb" WORK IN PROGRESS // DEBUG COMMAND
		int len, type = R_REG_TYPE_GPR;
		arg = strchr (str, ' ');
		if (arg) {
			char *string = r_str_trim_dup (arg + 1);
			if (string) {
				type = r_reg_type_by_name (string);
				if (type == -1 && string[0] != 'a') {
					type = R_REG_TYPE_GPR;
				}
				free (string);
			}
		}
		ut8 *buf = r_reg_get_bytes (core->dbg->reg, type, &len);
		if (buf) {
			r_print_hexdump (core->print, 0LL, buf, len, 32, 4, 1);
			free (buf);
		}
		} break;
	case 'c': // "arc"
		// TODO: set flag values with drc zf=1
		{
			RRegItem *r;
			const char *name = r_str_trim_ro (str + 1);
			if (*name && name[1]) {
				r = r_reg_cond_get (core->dbg->reg, name);
				if (r) {
					r_cons_println (r->name);
				} else {
					int id = r_reg_cond_from_string (name);
					RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						int o = r_reg_cond_bits (core->dbg->reg, id, rf);
						core->num->value = o;
						// ORLY?
						r_cons_printf ("%d\n", o);
						free (rf);
					} else {
						eprintf ("unknown conditional or flag register\n");
					}
				}
			} else {
				RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
				if (rf) {
					r_cons_printf ("| s:%d z:%d c:%d o:%d p:%d\n",
						rf->s, rf->z, rf->c, rf->o, rf->p);
					if (*name == '=') {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf ("%s:%d ",
								r_reg_cond_to_string (i),
								r_reg_cond_bits (core->dbg->reg, i, rf));
						}
						r_cons_newline ();
					} else {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf ("%d %s\n",
								r_reg_cond_bits (core->dbg->reg, i, rf),
								r_reg_cond_to_string (i));
						}
					}
					free (rf);
				}
			}
		}
		break;
	case 's': // "ars"
		switch (str[1]) {
		case '-': // "ars-"
			r_reg_arena_pop (core->dbg->reg);
			// restore debug registers if in debugger mode
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, true);
			break;
		case '+': // "ars+"
			r_reg_arena_push (core->dbg->reg);
			break;
		case '?': { // "ars?"
			// TODO #7967 help refactor: dup from drp
			const char *help_msg[] = {
				"Usage:", "drs", " # Register states commands",
				"drs", "", "List register stack",
				"drs+", "", "Push register state",
				"drs-", "", "Pop register state",
				NULL };
			r_core_cmd_help (core, help_msg);
		} break;
		default:
			r_cons_printf ("%d\n", r_list_length (
						core->dbg->reg->regset[0].pool));
			break;
		}
		break;
	case 'p': // "arp"
		// XXX we have to break out .h for these cmd_xxx files.
		cmd_reg_profile (core, 'a', str);
		break;
	case 't': // "art"
		for (i = 0; (name = r_reg_get_type (i)); i++)
			r_cons_println (name);
		break;
	case 'n': // "arn"
		if (*(str + 1) == '\0') {
			eprintf ("Oops. try arn [PC|SP|BP|A0|A1|A2|A3|A4|R0|R1|ZF|SF|NF|OF]\n");
			break;
		}
		name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (str + 2));
		if (name && *name) {
			r_cons_println (name);
		} else {
			eprintf ("Oops. try arn [PC|SP|BP|A0|A1|A2|A3|A4|R0|R1|ZF|SF|NF|OF]\n");
		}
		break;
	case 'd': // "ard"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 3, use_color); // XXX detect which one is current usage
		break;
	case 'o': // "aro"
		r_reg_arena_swap (core->dbg->reg, false);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 0, use_color); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, false);
		break;
	case '=': // "ar="
		{
			char *p = NULL;
			char *bits = NULL;
			if (str[1]) {
				p = strdup (str + 1);
				if (str[1] != ':') {
					// Bits were specified
					bits = strtok (p, ":");
					if (r_str_isnumber (bits)) {
						st64 sz = r_num_math (core->num, bits);
						if (sz > 0) {
							size = sz;
						}
					} else {
						r_core_cmd_help (core, help_msg_ar);
						break;
					}
				}
				int len = bits ? strlen (bits) : 0;
				if (str[len + 1] == ':') {
					// We have some regs
					char *regs = bits ? strtok (NULL, ":") : strtok ((char *)str + 1, ":");
					char *reg = strtok (regs, " ");
					RList *q_regs = r_list_new ();
					if (q_regs) {
						while (reg) {
							r_list_append (q_regs, reg);
							reg = strtok (NULL, " ");
						}
						core->dbg->q_regs = q_regs;
					}
				}
			}
			__anal_reg_list (core, type, size, 2);
			if (!r_list_empty (core->dbg->q_regs)) {
				r_list_free (core->dbg->q_regs);
			}
			core->dbg->q_regs = NULL;
			free (p);
		}
		break;
	case '.': // "ar."
	case '-': // "ar-"
	case '*': // "ar*"
	case 'R': // "arR"
	case 'j': // "arj"
	case 'i': // "arj"
	case '\0': // "ar"
		__anal_reg_list (core, type, size, str[0]);
		break;
	case ' ': { // "ar "
		arg = strchr (str + 1, '=');
		if (arg) {
			*arg = 0;
			char *ostr = r_str_trim_dup (str + 1);
			char *regname = r_str_trim_nc (ostr);
			r = r_reg_get (core->dbg->reg, regname, -1);
			if (!r) {
				int role = r_reg_get_name_idx (regname);
				if (role != -1) {
					const char *alias = r_reg_get_name (core->dbg->reg, role);
					r = r_reg_get (core->dbg->reg, alias, -1);
				}
			}
			if (r) {
				//eprintf ("%s 0x%08"PFMT64x" -> ", str,
				//	r_reg_get_value (core->dbg->reg, r));
				r_reg_set_value (core->dbg->reg, r,
						r_num_math (core->num, arg + 1));
				r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
				//eprintf ("0x%08"PFMT64x"\n",
				//	r_reg_get_value (core->dbg->reg, r));
				r_core_cmdf (core, ".dr*%d", bits);
			} else {
				eprintf ("ar: Unknown register '%s'\n", regname);
			}
			free (ostr);
			return;
		}
		char name[32];
		int i = 1, j;
		while (str[i]) {
			if (str[i] == ',') {
				i++;
			} else {
				for (j = i; str[++j] && str[j] != ','; );
				if (j - i + 1 <= sizeof name) {
					r_str_ncpy (name, str + i, j - i + 1);
					if (IS_DIGIT (name[0])) { // e.g. ar 32
						__anal_reg_list (core, R_REG_TYPE_GPR, atoi (name), '\0');
					} else if (showreg (core, name) > 0) { // e.g. ar rax
					} else { // e.g. ar gpr ; ar all
						type = r_reg_type_by_name (name);
						// TODO differentiate ALL and illegal register types and print error message for the latter
						__anal_reg_list (core, type, -1, '\0');
					}
				}
				i = j;
			}
		}
	}
	}
}

static ut64 initializeEsil(RCore *core) {
	const char *name = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	int romem = r_config_get_i (core->config, "esil.romem");
	int stats = r_config_get_i (core->config, "esil.stats");
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int exectrap = r_config_get_i (core->config, "esil.exectrap");
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	int noNULL = r_config_get_i (core->config, "esil.noNULL");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	if (!(core->anal->esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
		return UT64_MAX;
	}
	ut64 addr;
	RAnalEsil *esil = core->anal->esil;
	esil->verbose = r_config_get_i (core->config, "esil.verbose");
	esil->cmd = r_core_esil_cmd;
	r_anal_esil_setup (esil, core->anal, romem, stats, noNULL); // setup io
	{
		const char *cmd_esil_step = r_config_get (core->config, "cmd.esil.step");
		if (cmd_esil_step && *cmd_esil_step) {
			esil->cmd_step = strdup (cmd_esil_step);
		}
		const char *cmd_esil_step_out = r_config_get (core->config, "cmd.esil.stepout");
		if (cmd_esil_step_out && *cmd_esil_step_out) {
			esil->cmd_step_out = strdup (cmd_esil_step_out);
		}
		{
			const char *s = r_config_get (core->config, "cmd.esil.intr");
			if (s) {
				char *my = strdup (s);
				if (my) {
					r_config_set (core->config, "cmd.esil.intr", my);
					free (my);
				}
			}
		}
	}
	esil->exectrap = exectrap;
	RList *entries = r_bin_get_entries (core->bin);
	RBinAddr *entry = NULL;
	RBinInfo *info = NULL;
	if (entries && !r_list_empty (entries)) {
		entry = (RBinAddr *)r_list_pop (entries);
		info = r_bin_get_info (core->bin);
		addr = info->has_va? entry->vaddr: entry->paddr;
		r_list_push (entries, entry);
	} else {
		addr = core->offset;
	}
	r_reg_setv (core->anal->reg, name, addr);
	// set memory read only
	return addr;
}

R_API int r_core_esil_step(RCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver) {
#define return_tail(x) { tail_return_value = x; goto tail_return; }
	int tail_return_value = 0;
	int ret;
	ut8 code[32];
	RAnalOp op = {0};
	RAnalEsil *esil = core->anal->esil;
	const char *name = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	bool breakoninvalid = r_config_get_i (core->config, "esil.breakoninvalid");
	int esiltimeout = r_config_get_i (core->config, "esil.timeout");
	ut64 startTime;
	if (!esil) {
		initializeEsil (core);
	}
	if (esiltimeout > 0) {
		startTime = r_sys_now ();
	}
	ut64 addr = r_reg_getv (core->anal->reg, name);
	r_cons_break_push (NULL, NULL);
repeat:
	if (r_cons_is_breaked ()) {
		eprintf ("[+] ESIL emulation interrupted at 0x%08" PFMT64x "\n", addr);
		return_tail (0);
	}
	//Break if we have exceeded esil.timeout
	if (esiltimeout > 0) {
		ut64 elapsedTime = r_sys_now () - startTime;
		elapsedTime >>= 20;
		if (elapsedTime >= esiltimeout) {
			eprintf ("[ESIL] Timeout exceeded.\n");
			return_tail (0);
		}
	}
	if (!esil) {
		addr = initializeEsil (core);
		esil = core->anal->esil;
		if (!esil) {
			return_tail (0);
		}
	} else {
		esil->trap = 0;
		addr = r_reg_getv (core->anal->reg, name);
		//eprintf ("PC=0x%"PFMT64x"\n", (ut64)addr);
	}
	if (prev_addr) {
		*prev_addr = addr;
	}
	if (esil->exectrap) {
		if (!r_io_is_valid_offset (core->io, addr, R_PERM_X)) {
			esil->trap = R_ANAL_TRAP_EXEC_ERR;
			esil->trap_code = addr;
			eprintf ("[ESIL] Trap, trying to execute on non-executable memory\n");
			return_tail (1);
		}
	}
	r_asm_set_pc (core->assembler, addr);
	// run esil pin command here
	const char *pincmd = r_anal_pin_call (core->anal, addr);
	if (pincmd) {
		r_core_cmd0 (core, pincmd);
		ut64 pc = r_debug_reg_get (core->dbg, "PC");
		if (addr != pc) {
			return_tail (1);
		}
	}
	int dataAlign = r_anal_archinfo (esil->anal, R_ANAL_ARCHINFO_DATA_ALIGN);
	if (dataAlign > 1) {
		if (addr % dataAlign) {
			if (esil->cmd && esil->cmd_trap) {
				esil->cmd (esil, esil->cmd_trap, addr, R_ANAL_TRAP_UNALIGNED);
			}
			if (breakoninvalid) {
				r_cons_printf ("[ESIL] Stopped execution in an unaligned instruction (see e??esil.breakoninvalid)\n");
				return_tail (0);
			}
		}
	}
	(void) r_io_read_at_mapped (core->io, addr, code, sizeof (code));
	// TODO: sometimes this is dupe
	ret = r_anal_op (core->anal, &op, addr, code, sizeof (code), R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_HINT);
	// if type is JMP then we execute the next N instructions
	// update the esil pointer because RAnal.op() can change it
	esil = core->anal->esil;
	if (op.size < 1 || ret < 1) {
		if (esil->cmd && esil->cmd_trap) {
			esil->cmd (esil, esil->cmd_trap, addr, R_ANAL_TRAP_INVALID);
		}
		if (breakoninvalid) {
			eprintf ("[ESIL] Stopped execution in an invalid instruction (see e??esil.breakoninvalid)\n");
			return_tail (0);
		}
		op.size = 1; // avoid inverted stepping
	}
	if (stepOver) {
		switch (op.type) {
		case R_ANAL_OP_TYPE_SWI:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_RET:
		case R_ANAL_OP_TYPE_CRET:
		case R_ANAL_OP_TYPE_UJMP:
			if (addr == until_addr) {
				return_tail (0);
			} else {
				r_reg_setv (core->anal->reg, "PC", op.addr + op.size);
				r_reg_setv (core->dbg->reg, "PC", op.addr + op.size);
			}
			return 1;
		}
	}
	if (r_config_get_i (core->config, "cfg.r2wars")) {
		// this is x86 and r2wars specific, shouldnt hurt outside x86
		ut64 vECX = r_reg_getv (core->anal->reg, "ecx");
		if (op.prefix  & R_ANAL_OP_PREFIX_REP && vECX > 1) {
			char *tmp = strstr (op.esil.ptr, ",ecx,?{,5,GOTO,}");
			if (tmp) {
				tmp[0] = 0;
			}
			op.esil.len -= 16;
		} else {
			r_reg_setv (core->anal->reg, name, addr + op.size);
		}
	} else {
		r_reg_setv (core->anal->reg, name, addr + op.size);
	}
	if (ret) {
		r_anal_esil_set_pc (esil, addr);
		if (core->dbg->trace->enabled) {
			RReg *reg = core->dbg->reg;
			core->dbg->reg = core->anal->reg;
			r_debug_trace_pc (core->dbg, addr);
			core->dbg->reg = reg;
		} else if (R_STR_ISNOTEMPTY (R_STRBUF_SAFEGET (&op.esil))) {
			r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op.esil));
			if (core->anal->cur && core->anal->cur->esil_post_loop) {
				core->anal->cur->esil_post_loop (esil, &op);
			}
			r_anal_esil_stack_free (esil);
		}
		bool isNextFall = false;
		if (op.type == R_ANAL_OP_TYPE_CJMP) {
			ut64 pc = r_debug_reg_get (core->dbg, "PC");
			if (pc == addr + op.size) {
				// do not opdelay here
				isNextFall = true;
			}
		}
		// only support 1 slot for now
		if (op.delay && !isNextFall) {
			ut8 code2[32];
			ut64 naddr = addr + op.size;
			RAnalOp op2 = {0};
			// emulate only 1 instruction
			r_anal_esil_set_pc (esil, naddr);
			(void)r_io_read_at (core->io, naddr, code2, sizeof (code2));
			// TODO: sometimes this is dupe
			ret = r_anal_op (core->anal, &op2, naddr, code2, sizeof (code2), R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_HINT);
			if (ret > 0) {
				switch (op2.type) {
				case R_ANAL_OP_TYPE_CJMP:
				case R_ANAL_OP_TYPE_JMP:
				case R_ANAL_OP_TYPE_CRET:
				case R_ANAL_OP_TYPE_RET:
					// branches are illegal in a delay slot
					esil->trap = R_ANAL_TRAP_EXEC_ERR;
					esil->trap_code = addr;
					eprintf ("[ESIL] Trap, trying to execute a branch in a delay slot\n");
					return_tail (1);
					break;
				}
				r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op2.esil));
			} else {
				eprintf ("Invalid instruction at 0x%08"PFMT64x"\n", naddr);
			}
			r_anal_op_fini (&op2);
		}
		tail_return_value = 1;
	}
	// esil->verbose ?
	// eprintf ("REPE 0x%llx %s => 0x%llx\n", addr, R_STRBUF_SAFEGET (&op.esil), r_reg_getv (core->anal->reg, "PC"));

	st64 follow = (st64)r_config_get_i (core->config, "dbg.follow");
	if (follow > 0) {
		ut64 pc = r_debug_reg_get (core->dbg, "PC");
		if ((pc < core->offset) || (pc > (core->offset + follow))) {
			r_core_cmd0 (core, "sr PC");
		}
	}
	// check breakpoints
	ut64 pc = r_reg_getv (core->anal->reg, name);
	if (r_bp_get_at (core->dbg->bp, pc)) {
		r_cons_printf ("[ESIL] hit breakpoint at 0x%"PFMT64x "\n", pc);
		return_tail (0);
	}
	// check addr
	if (until_addr != UT64_MAX) {
		if (pc == until_addr) {
			return_tail (0);
		}
		goto repeat;
	}
	// check esil
	if (esil && esil->trap) {
		if (core->anal->esil->verbose) {
			eprintf ("TRAP\n");
		}
		return_tail (0);
	}
	if (until_expr) {
		if (r_anal_esil_condition (core->anal->esil, until_expr)) {
			if (core->anal->esil->verbose) {
				eprintf ("ESIL BREAK!\n");
			}
			return_tail (0);
		}
		goto repeat;
	}
tail_return:
	r_anal_op_fini (&op);
	r_cons_break_pop ();
	return tail_return_value;
}

R_API int r_core_esil_step_back(RCore *core) {
	RAnalEsil *esil = core->anal->esil;
	RListIter *tail;
	const char *name = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ut64 prev = 0;
	ut64 end = r_reg_getv (core->anal->reg, name);

	if (!esil || !(tail = r_list_tail (esil->sessions))) {
		return 0;
	}
	RAnalEsilSession *before = (RAnalEsilSession *) tail->data;
	if (!before) {
		eprintf ("Cannot find any previous state here\n");
		return 0;
	}
	eprintf ("NOTE: step back in esil is setting an initial state and stepping into pc is the same.\n");
	eprintf ("NOTE: this is extremely wrong and poorly efficient. so don't use this feature unless\n");
	eprintf ("NOTE: you are going to fix it by making it consistent with dts, which is also broken as hell\n");
	eprintf ("Execute until 0x%08"PFMT64x"\n", end);
	r_anal_esil_session_set (esil, before);
	r_core_esil_step (core, end, NULL, &prev, false);
	eprintf ("Before 0x%08"PFMT64x"\n", prev);
	r_anal_esil_session_set (esil, before);
	r_core_esil_step (core, prev, NULL, NULL, false);
	return 1;
}

static void cmd_address_info(RCore *core, const char *addrstr, int fmt) {
	ut64 addr, type;
	if (!addrstr || !*addrstr) {
		addr = core->offset;
	} else {
		addr = r_num_math (core->num, addrstr);
	}
	type = r_core_anal_address (core, addr);
	switch (fmt) {
	case 'j': {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_o (pj);
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			pj_ks (pj, "program", "true");
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			pj_ks (pj, "library", "true");
		if (type & R_ANAL_ADDR_TYPE_EXEC)
			pj_ks (pj, "exec", "true");
		if (type & R_ANAL_ADDR_TYPE_READ)
			pj_ks (pj, "read", "true");
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			pj_ks (pj, "write", "true");
		if (type & R_ANAL_ADDR_TYPE_FLAG)
			pj_ks (pj, "flag", "true");
		if (type & R_ANAL_ADDR_TYPE_FUNC)
			pj_ks (pj, "func", "true");
		if (type & R_ANAL_ADDR_TYPE_STACK)
			pj_ks (pj, "stack", "true");
		if (type & R_ANAL_ADDR_TYPE_HEAP)
			pj_ks (pj, "heap", "true");
		if (type & R_ANAL_ADDR_TYPE_REG)
			pj_ks (pj, "reg", "true");
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			pj_ks (pj, "ascii", "true");
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			pj_ks (pj, "sequence", "true");
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
		}
		break;
	default:
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			r_cons_printf ("program\n");
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			r_cons_printf ("library\n");
		if (type & R_ANAL_ADDR_TYPE_EXEC)
			r_cons_printf ("exec\n");
		if (type & R_ANAL_ADDR_TYPE_READ)
			r_cons_printf ("read\n");
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			r_cons_printf ("write\n");
		if (type & R_ANAL_ADDR_TYPE_FLAG)
			r_cons_printf ("flag\n");
		if (type & R_ANAL_ADDR_TYPE_FUNC)
			r_cons_printf ("func\n");
		if (type & R_ANAL_ADDR_TYPE_STACK)
			r_cons_printf ("stack\n");
		if (type & R_ANAL_ADDR_TYPE_HEAP)
			r_cons_printf ("heap\n");
		if (type & R_ANAL_ADDR_TYPE_REG)
			r_cons_printf ("reg\n");
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			r_cons_printf ("ascii\n");
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			r_cons_printf ("sequence\n");
		break;
	}
}

static void cmd_anal_info(RCore *core, const char *input) {
	switch (input[0]) {
	case '?':
		r_core_cmd_help (core, help_msg_ai);
		break;
	case ' ':
		cmd_address_info (core, input, 0);
		break;
	case 'i': // "aii"
		// global imports
		if (input[1]) {
			if (input[1] == ' ') {
				if (!core->anal->imports) {
					core->anal->imports = r_list_newf ((RListFree)free);
				}
				r_list_append (core->anal->imports, r_str_trim_dup (input + 1));
			} else if (input[1] == '-') {
				r_list_free (core->anal->imports);
				core->anal->imports = NULL;
			} else {
				eprintf ("Usagae: aii [namespace] # see afii - imports\n");
			}
		} else {
			if (core->anal->imports) {
				char *imp;
				RListIter *iter;
				r_list_foreach (core->anal->imports, iter, imp) {
					r_cons_printf ("%s\n", imp);
				}
			}
		}
		break;
	case 'j': // "aij"
		cmd_address_info (core, input + 1, 'j');
		break;
	default:
		cmd_address_info (core, NULL, 0);
		break;
	}
}

static void initialize_stack (RCore *core, ut64 addr, ut64 size) {
	const char *mode = r_config_get (core->config, "esil.fillstack");
	if (mode && *mode && *mode != '0') {
		const ut64 bs = 4096 * 32;
		ut64 i;
		for (i = 0; i < size; i += bs) {
			ut64 left = R_MIN (bs, size - i);
		//	r_core_cmdf (core, "wx 10203040 @ 0x%llx", addr);
			switch (*mode) {
			case 'd': // "debrujn"
				r_core_cmdf (core, "wopD %"PFMT64u" @ 0x%"PFMT64x, left, addr + i);
				break;
			case 's': // "seq"
				r_core_cmdf (core, "woe 1 0xff 1 4 @ 0x%"PFMT64x"!0x%"PFMT64x, addr + i, left);
				break;
			case 'r': // "random"
				r_core_cmdf (core, "woR %"PFMT64u" @ 0x%"PFMT64x"!0x%"PFMT64x, left, addr + i, left);
				break;
			case 'z': // "zero"
			case '0':
				r_core_cmdf (core, "wow 00 @ 0x%"PFMT64x"!0x%"PFMT64x, addr + i, left);
				break;
			}
		}
		// eprintf ("[*] Initializing ESIL stack with pattern\n");
		// r_core_cmdf (core, "woe 0 10 4 @ 0x%"PFMT64x, size, addr);
	}
}

static void cmd_esil_mem(RCore *core, const char *input) {
	RAnalEsil *esil = core->anal->esil;
	RIOMap *stack_map;
	ut64 curoff = core->offset;
	const char *patt = "";
	ut64 addr = 0x100000;
	ut32 size = 0xf0000;
	char name[128];
	RFlagItem *fi;
	const char *sp, *bp, *pc;
	char uri[32];
	char nomalloc[256];
	char *p;
	if (!esil) {
		int stacksize = r_config_get_i (core->config, "esil.stack.depth");
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		int romem = r_config_get_i (core->config, "esil.romem");
		int stats = r_config_get_i (core->config, "esil.stats");
		int noNULL = r_config_get_i (core->config, "esil.noNULL");
		int verbose = r_config_get_i (core->config, "esil.verbose");
		unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
		if (!(esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
			return;
		}
		r_anal_esil_setup (esil, core->anal, romem, stats, noNULL); // setup io
		core->anal->esil = esil;
		esil->verbose = verbose;
		{
			const char *s = r_config_get (core->config, "cmd.esil.intr");
			if (s) {
				char *my = strdup (s);
				if (my) {
					r_config_set (core->config, "cmd.esil.intr", my);
					free (my);
				}
			}
		}
	}
	if (*input == '?') {
		eprintf ("Usage: aeim [addr] [size] [name] - initialize ESIL VM stack\n");
		eprintf ("Default: 0x100000 0xf0000\n");
		eprintf ("See ae? for more help\n");
		return;
	}

	if (input[0] == 'p') {
		fi = r_flag_get (core->flags, "aeim.stack");
		if (fi) {
			addr = fi->offset;
			size = fi->size;
		} else {
			cmd_esil_mem (core, "");
		}
		if (esil) {
			esil->stack_addr = addr;
			esil->stack_size = size;
		}
		initialize_stack (core, addr, size);
		return;
	}

	if (!*input) {
		char *fi = sdb_get(core->sdb, "aeim.fd", 0);
		if (fi) {
			// Close the fd associated with the aeim stack
			ut64 fd = sdb_atoi (fi);
			(void)r_io_fd_close (core->io, fd);
		}
	}
	addr = r_config_get_i (core->config, "esil.stack.addr");
	size = r_config_get_i (core->config, "esil.stack.size");
	patt = r_config_get (core->config, "esil.stack.pattern");

	p = strncpy (nomalloc, input, 255);
	if ((p = strchr (p, ' '))) {
		while (*p == ' ') p++;
		addr = r_num_math (core->num, p);
		if ((p = strchr (p, ' '))) {
			while (*p == ' ') p++;
			size = (ut32)r_num_math (core->num, p);
			if (size < 1) {
				size = 0xf0000;
			}
			if ((p = strchr (p, ' '))) {
				while (*p == ' ') p++;
				snprintf (name, sizeof (name), "mem.%s", p);
			} else {
				snprintf (name, sizeof (name), "mem.0x%" PFMT64x "_0x%x", addr, size);
			}
		} else {
			snprintf (name, sizeof (name), "mem.0x%" PFMT64x "_0x%x", addr, size);
		}
	} else {
		snprintf (name, sizeof (name), "mem.0x%" PFMT64x "_0x%x", addr, size);
	}
	if (*input == '-') {
		if (esil->stack_fd > 2) {	//0, 1, 2 are reserved for stdio/stderr
			r_io_fd_close (core->io, esil->stack_fd);
			// no need to kill the maps, r_io_map_cleanup does that for us in the close
			esil->stack_fd = 0;
		} else {
			eprintf ("Cannot deinitialize %s\n", name);
		}
		r_flag_unset_name (core->flags, name);
		r_flag_unset_name (core->flags, "aeim.stack");
		sdb_unset(core->sdb, "aeim.fd", 0);
		// eprintf ("Deinitialized %s\n", name);
		return;
	}

	snprintf (uri, sizeof (uri), "malloc://%d", (int)size);
	esil->stack_fd = r_io_fd_open (core->io, uri, R_PERM_RW, 0);
	if (!(stack_map = r_io_map_add (core->io, esil->stack_fd, R_PERM_RW, 0LL, addr, size))) {
		r_io_fd_close (core->io, esil->stack_fd);
		eprintf ("Cannot create map for tha stack, fd %d got closed again\n", esil->stack_fd);
		esil->stack_fd = 0;
		return;
	}
	r_io_map_set_name (stack_map, name);
	// r_flag_set (core->flags, name, addr, size);	//why is this here?
	char val[128], *v;
	v = sdb_itoa (esil->stack_fd, val, 10);
	sdb_set(core->sdb, "aeim.fd", v, 0);

	r_config_set_i (core->config, "io.va", true);
	if (patt && *patt) {
		switch (*patt) {
		case '0':
			// do nothing
			break;
		case 'd':
			r_core_cmdf (core, "wopD %d @ 0x%"PFMT64x, size, addr);
			break;
		case 'i':
			r_core_cmdf (core, "woe 0 255 1 @ 0x%"PFMT64x"!%d",addr, size);
			break;
		case 'w':
			r_core_cmdf (core, "woe 0 0xffff 1 4 @ 0x%"PFMT64x"!%d",addr, size);
			break;
		}
	}
	// SP
	sp = r_reg_get_name (core->dbg->reg, R_REG_NAME_SP);
	if (sp) {
		r_debug_reg_set (core->dbg, sp, addr + (size / 2));
	}
	// BP
	bp = r_reg_get_name (core->dbg->reg, R_REG_NAME_BP);
	if (bp) {
		r_debug_reg_set (core->dbg, bp, addr + (size / 2));
	}
	// PC
	pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	if (pc) {
		r_debug_reg_set (core->dbg, pc, curoff);
	}
	r_core_cmd0 (core, ".ar*");
	if (esil) {
		esil->stack_addr = addr;
		esil->stack_size = size;
	}
	initialize_stack (core, addr, size);
	r_core_seek (core, curoff, 0);
}

#if 0
static ut64 opc = UT64_MAX;
static ut8 *regstate = NULL;

static void esil_init (RCore *core) {
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	int noNULL = r_config_get_i (core->config, "esil.noNULL");
	opc = r_reg_getv (core->anal->reg, pc);
	if (!opc || opc==UT64_MAX) {
		opc = core->offset;
	}
	if (!core->anal->esil) {
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		ut64 stackSize = r_config_get_i (core->config, "esil.stack.size");
		unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
		if (!(core->anal->esil = r_anal_esil_new (stackSize, iotrap, addrsize))) {
			R_FREE (regstate);
			return;
		}
		r_anal_esil_setup (core->anal->esil, core->anal, 0, 0, noNULL);
	}
	free (regstate);
	regstate = r_reg_arena_peek (core->anal->reg);
}

static void esil_fini(RCore *core) {
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	r_reg_arena_poke (core->anal->reg, regstate);
	r_reg_setv (core->anal->reg, pc, opc);
	R_FREE (regstate);
}
#endif

typedef struct {
	RList *regs;
	RList *regread;
	RList *regwrite;
	RList *inputregs;
} AeaStats;

static void aea_stats_init (AeaStats *stats) {
	stats->regs = r_list_newf (free);
	stats->regread = r_list_newf (free);
	stats->regwrite = r_list_newf (free);
	stats->inputregs = r_list_newf (free);
}

static void aea_stats_fini (AeaStats *stats) {
	R_FREE (stats->regs);
	R_FREE (stats->regread);
	R_FREE (stats->regwrite);
	R_FREE (stats->inputregs);
}

static bool contains(RList *list, const char *name) {
	RListIter *iter;
	const char *n;
	r_list_foreach (list, iter, n) {
		if (!strcmp (name, n))
			return true;
	}
	return false;
}

static char *oldregread = NULL;
static RList *mymemxsr = NULL;
static RList *mymemxsw = NULL;

#define R_NEW_DUP(x) memcpy((void*)malloc(sizeof(x)), &(x), sizeof(x))
typedef struct {
	ut64 addr;
	int size;
} AeaMemItem;

static int mymemwrite(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	RListIter *iter;
	AeaMemItem *n;
	r_list_foreach (mymemxsw, iter, n) {
		if (addr == n->addr) {
			return len;
		}
	}
	if (!r_io_is_valid_offset (esil->anal->iob.io, addr, 0)) {
		return false;
	}
	n = R_NEW (AeaMemItem);
	if (n) {
		n->addr = addr;
		n->size = len;
		r_list_push (mymemxsw, n);
	}
	return len;
}

static int mymemread(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	RListIter *iter;
	AeaMemItem *n;
	r_list_foreach (mymemxsr, iter, n) {
		if (addr == n->addr) {
			return len;
		}
	}
	if (!r_io_is_valid_offset (esil->anal->iob.io, addr, 0)) {
		return false;
	}
	n = R_NEW (AeaMemItem);
	if (n) {
		n->addr = addr;
		n->size = len;
		r_list_push (mymemxsr, n);
	}
	return len;
}

static int myregwrite(RAnalEsil *esil, const char *name, ut64 *val) {
	AeaStats *stats = esil->user;
	if (oldregread && !strcmp (name, oldregread)) {
		r_list_pop (stats->regread);
		R_FREE (oldregread)
	}
	if (!IS_DIGIT (*name)) {
		if (!contains (stats->regs, name)) {
			r_list_push (stats->regs, strdup (name));
		}
		if (!contains (stats->regwrite, name)) {
			r_list_push (stats->regwrite, strdup (name));
		}
	}
	return 0;
}

static int myregread(RAnalEsil *esil, const char *name, ut64 *val, int *len) {
	AeaStats *stats = esil->user;
	if (!IS_DIGIT (*name)) {
		if (!contains (stats->inputregs, name)) {
			if (!contains (stats->regwrite, name)) {
				r_list_push (stats->inputregs, strdup (name));
			}
		}
		if (!contains (stats->regs, name)) {
			r_list_push (stats->regs, strdup (name));
		}
		if (!contains (stats->regread, name)) {
			r_list_push (stats->regread, strdup (name));
		}
	}
	return 0;
}

static void showregs (RList *list) {
	if (!r_list_empty (list)) {
		char *reg;
		RListIter *iter;
		r_list_foreach (list, iter, reg) {
			r_cons_print (reg);
			if (iter->n) {
				r_cons_printf (" ");
			}
		}
	}
	r_cons_newline();
}

static void showmem (RList *list) {
	if (!r_list_empty (list)) {
		AeaMemItem *item;
		RListIter *iter;
		r_list_foreach (list, iter, item) {
			r_cons_printf (" 0x%08"PFMT64x, item->addr);

		}
	}
	r_cons_newline ();
}

static void showregs_json (RList *list, PJ *pj) {
	pj_a (pj);
	if (!r_list_empty (list)) {
		char *reg;
		RListIter *iter;

		r_list_foreach (list, iter, reg) {
			pj_s (pj, reg);
		}
	}
	pj_end (pj);
}

static void showmem_json (RList *list, PJ *pj) {
	pj_a (pj);
	if (!r_list_empty (list)) {
		RListIter *iter;
		AeaMemItem *item;
		r_list_foreach (list, iter, item) {
			pj_n (pj, item->addr);
		}
	}

	pj_end (pj);
}

static bool cmd_aea(RCore* core, int mode, ut64 addr, int length) {
	RAnalEsil *esil;
	int ptr, ops, ops_end = 0, len, buf_sz, maxopsize;
	ut64 addr_end;
	AeaStats stats;
	const char *esilstr;
	RAnalOp aop = R_EMPTY;
	ut8 *buf;
	RList* regnow;
	PJ *pj = NULL;
	if (!core) {
		return false;
	}
	maxopsize = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
	if (maxopsize < 1) {
		maxopsize = 16;
	}
	if (mode & 1) {
		// number of bytes / length
		buf_sz = length;
	} else {
		// number of instructions / opcodes
		ops_end = length;
		if (ops_end < 1) {
			ops_end = 1;
		}
		buf_sz = ops_end * maxopsize;
	}
	if (buf_sz < 1) {
		buf_sz = maxopsize;
	}
	addr_end = addr + buf_sz;
	buf = malloc (buf_sz);
	if (!buf) {
		return false;
	}
	(void)r_io_read_at (core->io, addr, (ut8 *)buf, buf_sz);
	aea_stats_init (&stats);

	//esil_init (core);
	//esil = core->anal->esil;
	r_reg_arena_push (core->anal->reg);
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	bool iotrap = r_config_get_i (core->config, "esil.iotrap");
	int romem = r_config_get_i (core->config, "esil.romem");
	int stats1 = r_config_get_i (core->config, "esil.stats");
	int noNULL = r_config_get_i (core->config, "esil.noNULL");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	esil = r_anal_esil_new (stacksize, iotrap, addrsize);
	r_anal_esil_setup (esil, core->anal, romem, stats1, noNULL); // setup io
#	define hasNext(x) (x&1) ? (addr<addr_end) : (ops<ops_end)

	mymemxsr = r_list_new ();
	mymemxsw = r_list_new ();
	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->cb.hook_mem_write = mymemwrite;
	esil->cb.hook_mem_read = mymemread;
	esil->nowrite = true;
	for (ops = ptr = 0; ptr < buf_sz && hasNext (mode); ops++, ptr += len) {
		len = r_anal_op (core->anal, &aop, addr + ptr, buf + ptr, buf_sz - ptr, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_HINT);
		esilstr = R_STRBUF_SAFEGET (&aop.esil);
		if (!*esilstr) {
			eprintf ("Empty ESIL at 0x%08"PFMT64x"\n", addr + ptr);
			break;
		}
		if (len < 1) {
			eprintf ("Invalid 0x%08"PFMT64x" instruction %02x %02x\n",
				addr + ptr, buf[ptr], buf[ptr + 1]);
			break;
		}
		if (r_config_get_i (core->config, "cfg.r2wars")) {
			if (aop.prefix  & R_ANAL_OP_PREFIX_REP) {
				char * tmp = strstr (esilstr, ",ecx,?{,5,GOTO,}");
				if (tmp) {
					tmp[0] = 0;
				}
			}
		}
		r_anal_esil_parse (esil, esilstr);
		r_anal_esil_stack_free (esil);
		r_anal_op_fini (&aop);
	}
	esil->nowrite = false;
	esil->cb.hook_reg_write = NULL;
	esil->cb.hook_reg_read = NULL;
	//esil_fini (core);
	r_anal_esil_free (esil);
	r_reg_arena_pop (core->anal->reg);
	regnow = r_list_newf (free);
	{
		RListIter *iter;
		char *reg;
		r_list_foreach (stats.regs, iter, reg) {
			if (!contains (stats.regwrite, reg)) {
				r_list_push (regnow, strdup (reg));
			}
		}
	}
	if ((mode >> 5) & 1) {
		RListIter *iter;
		AeaMemItem *n;
		int c = 0;
		r_cons_printf ("f-mem.*\n");
		r_list_foreach (mymemxsr, iter, n) {
			r_cons_printf ("f mem.read.%d 0x%08x @ 0x%08"PFMT64x"\n", c++, n->size, n->addr);
		}
		c = 0;
		r_list_foreach (mymemxsw, iter, n) {
			r_cons_printf ("f mem.write.%d 0x%08x @ 0x%08"PFMT64x"\n", c++, n->size, n->addr);
		}
	}

	/* show registers used */
	if ((mode >> 1) & 1) {
		showregs (stats.regread);
	} else if ((mode >> 2) & 1) {
		showregs (stats.regwrite);
	} else if ((mode >> 3) & 1) {
		showregs (regnow);
	} else if ((mode >> 4) & 1) {
		pj = pj_new ();
		if (!pj) {
			return false;
		}
		pj_o (pj);
		pj_k (pj, "A");
		showregs_json (stats.regs, pj);
		pj_k (pj, "I");
		showregs_json (stats.inputregs, pj);
		pj_k (pj, "R");
		showregs_json (stats.regread, pj);
		pj_k (pj, "W");
		showregs_json (stats.regwrite, pj);
		if (!r_list_empty (regnow)){
			pj_k (pj, "N");
			showregs_json (regnow, pj);
		}
		if (!r_list_empty (mymemxsr)){
			pj_k (pj, "@R");
			showmem_json (mymemxsr, pj);
		}
		if (!r_list_empty (mymemxsw)){
			pj_k (pj, "@W");
			showmem_json (mymemxsw, pj);
		}

		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	} else if ((mode >> 5) & 1) {
		// nothing
	} else {
		r_cons_printf (" I: ");
		showregs (stats.inputregs);
		r_cons_printf (" A: ");
		showregs (stats.regs);
		r_cons_printf (" R: ");
		showregs (stats.regread);
		r_cons_printf (" W: ");
		showregs (stats.regwrite);
		if (r_list_length (regnow)){
			r_cons_printf (" N: ");
			showregs (regnow);
		}
		if (!r_list_empty (mymemxsr)){
			r_cons_printf ("@R:");
			showmem (mymemxsr);
		}
		if (!r_list_empty (mymemxsw)){
			r_cons_printf ("@W:");
			showmem (mymemxsw);
		}
	}

	r_list_free (mymemxsr);
	r_list_free (mymemxsw);
	mymemxsr = NULL;
	mymemxsw = NULL;
	aea_stats_fini (&stats);
	free (buf);
	R_FREE (regnow);
	return true;
}

static void cmd_aespc(RCore *core, ut64 addr, int off) {
	RAnalEsil *esil = core->anal->esil;
	int i, j = 0;
	int instr_size = 0;
	ut8 *buf;
	RAnalOp aop = {0};
	int ret , bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");

	if (!esil) {
		if (!(esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
			return;
		}
	}
	buf = malloc (bsize);
	if (!buf) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		free (buf);
		return;
	}
	if (addr == -1) {
		addr = r_debug_reg_get (core->dbg, pc);
	}
	ut64 curpc = addr;
	ut64 oldoff = core->offset;
	for (i = 0, j = 0; j < off ; i++, j++) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (!i) {
			r_io_read_at (core->io, addr, buf, bsize);
		}
		ret = r_anal_op (core->anal, &aop, addr, buf + i, bsize - i, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
		instr_size += ret;
		int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
		if (inc < 0) {
			inc = minopcode;
		}
		i += inc;
		addr += inc;
		r_anal_op_fini (&aop);
	}
	r_reg_set_value (core->dbg->reg, r, curpc);
	r_core_esil_step (core, curpc + instr_size, NULL, NULL, false);
	r_core_seek (core, oldoff, 1);
}

static const char _handler_no_name[] = "<no name>";
static int _aeli_iter(dictkv* kv, void* ud) {
	RAnalEsilInterrupt* interrupt = kv->u;
	r_cons_printf ("%3x: %s\n", kv->k, interrupt->handler->name ? interrupt->handler->name : _handler_no_name);
	return 0;
}

static void r_anal_aefa(RCore *core, const char *arg) {
	ut64 to = r_num_math (core->num, arg);
	ut64 at, from = core->offset;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, to, -1);
	if (!from || from == UT64_MAX) {
		if (fcn) {
			from = fcn->addr;
		} else {
			eprintf ("Usage: aefa [from] # if no from address is given, uses fcn.addr\n");
			return;
		}
	}
	eprintf ("Emulate from 0x%08"PFMT64x" to 0x%08"PFMT64x"\n", from, to);
	eprintf ("Resolve call args for 0x%08"PFMT64x"\n", to);

	// emulate
	// XXX do not use commands, here, just use the api
	r_core_cmd0 (core, "aeim"); // XXX
	ut64 off = core->offset;
	for (at = from; at < to ; at++) {
		r_core_cmdf (core, "aepc 0x%08"PFMT64x, at);
		r_core_cmd0 (core, "aeso");
		r_core_seek (core, at, 1);
		int delta = r_num_get (core->num, "$l");
		if (delta < 1) {
			break;
		}
		at += delta - 1;
	}
	r_core_seek (core, off, 1);

	// the logic of identifying args by function types and
	// show json format and arg name goes into arA
	r_core_cmd0 (core, "arA");
#if 0
	// get results
	const char *fcn_type = r_type_func_ret (core->anal->sdb_types, fcn->name);
	const char *key = resolve_fcn_name (core->anal, fcn->name);
	RList *list = r_core_get_func_args (core, key);
	if (!r_list_empty (list)) {
		eprintf ("HAS signature\n");
	}
	int i, nargs = 3; // r_type_func_args_count (core->anal->sdb_types, fcn->name);
	if (nargs > 0) {
		int i;
		eprintf ("NARGS %d (%s)\n", nargs, key);
		for (i = 0; i < nargs; i++) {
			ut64 v = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_STDCALL, i);
			eprintf ("arg: 0x%08"PFMT64x"\n", v);
		}
	}
#endif
}

static void __core_anal_appcall(RCore *core, const char *input) {
//	r_reg_arena_push (core->dbg->reg);
	RListIter *iter;
	char *arg;
	char *inp = strdup (input);
	RList *args = r_str_split_list (inp, " ", 0);
	int i = 0;
	r_list_foreach (args, iter, arg) {
		const char *alias = sdb_fmt ("A%d", i);
		r_reg_setv (core->anal->reg, alias, r_num_math (core->num, arg));
		i++;
	}
	ut64 sp = r_reg_getv (core->anal->reg, "SP");
	r_reg_setv (core->anal->reg, "SP", 0);

	r_reg_setv (core->anal->reg, "PC", core->offset);
	r_core_cmd0 (core, "aesu 0");

	r_reg_setv (core->anal->reg, "SP", sp);
	free (inp);

//	r_reg_arena_pop (core->dbg->reg);
}

static void cmd_anal_esil(RCore *core, const char *input) {
	RAnalEsil *esil = core->anal->esil;
	ut64 addr = core->offset;
	ut64 adr ;
	char *n, *n1;
	int off;
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int romem = r_config_get_i (core->config, "esil.romem");
	int stats = r_config_get_i (core->config, "esil.stats");
	int noNULL = r_config_get_i (core->config, "esil.noNULL");
	ut64 until_addr = UT64_MAX;
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");

	const char *until_expr = NULL;
	RAnalOp *op = NULL;

	switch (input[0]) {
	case 'p': // "aep"
		switch (input[1]) {
		case 'c': // "aepc"
			if (input[2] == ' ' || input[2] == '=') {
				// seek to this address
				r_core_cmdf (core, "ar PC=%s", r_str_trim_ro (input + 3));
				r_core_cmd0 (core, ".ar*");
			} else {
				eprintf ("Missing argument\n");
			}
			break;
		case 0:
			r_anal_pin_list (core->anal);
			break;
		case '-':
			if (input[2]) {
				addr = r_num_math (core->num, input + 2);
			}
			r_anal_pin_unset (core->anal, addr);
			break;
		case ' ':
			r_anal_pin (core->anal, addr, input + 2);
			break;
		default:
			r_core_cmd_help (core, help_msg_aep);
			break;
		}
		break;
	case 'r': // "aer"
		// 'aer' is an alias for 'ar'
		cmd_anal_reg (core, input + 1);
		break;
	case '*':
		// XXX: this is wip, not working atm
		if (core->anal->esil) {
			r_cons_printf ("trap: %d\n", core->anal->esil->trap);
			r_cons_printf ("trap-code: %d\n", core->anal->esil->trap_code);
		} else {
			eprintf ("esil vm not initialized. run `aei`\n");
		}
		break;
	case ' ':
		//r_anal_esil_eval (core->anal, input+1);
		if (!esil && !(core->anal->esil = esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
			return;
		}
		r_anal_esil_setup (esil, core->anal, romem, stats, noNULL); // setup io
		r_anal_esil_set_pc (esil, core->offset);
		r_anal_esil_parse (esil, input + 1);
		r_anal_esil_dumpstack (esil);
		r_anal_esil_stack_free (esil);
		break;
	case 's': // "aes"
		// "aes" "aeso" "aesu" "aesue"
		// aes -> single step
		// aesb -> single step back
		// aeso -> single step over
		// aesu -> until address
		// aesue -> until esil expression
		switch (input[1]) {
		case '?':
			r_core_cmd0 (core, "ae?~aes");
			break;
		case 'l': // "aesl"
		{
			ut64 pc = r_debug_reg_get (core->dbg, "PC");
			RAnalOp *op = r_core_anal_op (core, pc, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
			// TODO: honor hint
			if (!op) {
				break;
			}
			r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
			r_debug_reg_set (core->dbg, "PC", pc + op->size);
			r_anal_esil_set_pc (esil, pc + op->size);
			r_core_cmd0 (core, ".ar*");
			r_anal_op_free (op);
		} break;
		case 'b': // "aesb"
			if (!r_core_esil_step_back (core)) {
				eprintf ("cannnot step back\n");
			}
			r_core_cmd0 (core, ".ar*");
			break;
		case 'u': // "aesu"
			until_expr = NULL;
			until_addr = UT64_MAX;
			if (r_str_endswith (input, "?")) {
				r_core_cmd0 (core, "ae?~aesu");
			} else switch (input[2]) {
			case 'e': // "aesue"
				until_expr = input + 3;
				break;
			case ' ': // "aesu"
				until_addr = r_num_math (core->num, input + 2);
				break;
			case 'o': // "aesuo"
				step_until_optype (core, r_str_trim_ro (input + 3));
				break;
			default:
				r_core_cmd0 (core, "ae?~aesu");
				break;
			}
			if (until_expr || until_addr != UT64_MAX) {
				r_core_esil_step (core, until_addr, until_expr, NULL, false);
			}
			r_core_cmd0 (core, ".ar*");
			break;
		case 's': // "aess"
			if (input[2] == 'u') { // "aessu"
				if (input[2] == 'e') {
					until_expr = input + 3;
				} else {
					until_addr = r_num_math (core->num, input + 2);
				}
				r_core_esil_step (core, until_addr, until_expr, NULL, true);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL, true);
			}
			r_core_cmd0 (core, ".ar*");
			break;
		case 'o': // "aeso"
			if (input[2] == 'u') { // "aesou"
				if (input[2] == 'e') {
					until_expr = input + 3;
				} else {
					until_addr = r_num_math (core->num, input + 2);
				}
				r_core_esil_step (core, until_addr, until_expr, NULL, true);
				r_core_cmd0 (core, ".ar*");
			} else if (!input[2] || input[2] == ' ') { // "aeso [addr]"
				// step over
				op = r_core_anal_op (core, r_reg_getv (core->anal->reg,
					r_reg_get_name (core->anal->reg, R_REG_NAME_PC)), R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
				if (op && op->type == R_ANAL_OP_TYPE_CALL) {
					until_addr = op->addr + op->size;
				}
				r_core_esil_step (core, until_addr, until_expr, NULL, false);
				r_anal_op_free (op);
				r_core_cmd0 (core, ".ar*");
			} else {
				eprintf ("Usage: aesou [addr] # step over until given address\n");
			}
			break;
		case 'p': //"aesp"
			n = strchr (input, ' ');
			n1 = n ? strchr (n + 1, ' ') : NULL;
			if ((!n || !n1) || (!(n + 1) || !(n1 + 1))) {
				eprintf ("aesp [offset] [num]\n");
				break;
			}
			adr = r_num_math (core->num, n + 1);
			off = r_num_math (core->num, n1 + 1);
			cmd_aespc (core, adr, off);
			break;
		case ' ':
			n = strchr (input, ' ');
			if (!(n + 1)) {
				r_core_esil_step (core, until_addr, until_expr, NULL, false);
				break;
			}
			off = r_num_math (core->num, n + 1);
			cmd_aespc (core, -1, off);
			break;
		default:
			r_core_esil_step (core, until_addr, until_expr, NULL, false);
			r_core_cmd0 (core, ".ar*");
			break;
		}
		break;
	case 'C': // "aeC"
		if (input[1] == '?') { // "aec?"
			r_core_cmd_help (core, help_msg_aeC);
		} else {
			__core_anal_appcall (core, r_str_trim_ro (input + 1));
		}
		break;
	case 'c': // "aec"
		if (input[1] == '?') { // "aec?"
			r_core_cmd_help (core, help_msg_aec);
		} else if (input[1] == 's') { // "aecs"
			const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			for (;;) {
				if (!r_core_esil_step (core, UT64_MAX, NULL, NULL, false)) {
					break;
				}
				r_core_cmd0 (core, ".ar*");
				addr = r_num_get (core->num, pc);
				op = r_core_anal_op (core, addr, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
				if (!op) {
					break;
				}
				if (op->type == R_ANAL_OP_TYPE_SWI) {
					eprintf ("syscall at 0x%08" PFMT64x "\n", addr);
					break;
				} else if (op->type == R_ANAL_OP_TYPE_TRAP) {
					eprintf ("trap at 0x%08" PFMT64x "\n", addr);
					break;
				}
				r_anal_op_free (op);
				op = NULL;
				if (core->anal->esil->trap || core->anal->esil->trap_code) {
					break;
				}
			}
			if (op) {
				r_anal_op_free (op);
				op = NULL;
			}
		} else if (input[1] == 'c') { // "aecc"
			const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			for (;;) {
				if (!r_core_esil_step (core, UT64_MAX, NULL, NULL, false)) {
					break;
				}
				r_core_cmd0 (core, ".ar*");
				addr = r_num_get (core->num, pc);
				op = r_core_anal_op (core, addr, R_ANAL_OP_MASK_BASIC);
				if (!op) {
					break;
				}
				if (op->type == R_ANAL_OP_TYPE_CALL || op->type == R_ANAL_OP_TYPE_UCALL) {
					eprintf ("call at 0x%08" PFMT64x "\n", addr);
					break;
				}
				r_anal_op_free (op);
				op = NULL;
				if (core->anal->esil->trap || core->anal->esil->trap_code) {
					break;
				}
			}
			if (op) {
				r_anal_op_free (op);
			}
		} else {
			// "aec"  -> continue until ^C
			// "aecu" -> until address
			// "aecue" -> until esil expression
			if (input[1] == 'u' && input[2] == 'e') {
				until_expr = input + 3;
			} else if (input[1] == 'u') {
				until_addr = r_num_math (core->num, input + 2);
			} else {
				until_expr = "0";
			}
			r_core_esil_step (core, until_addr, until_expr, NULL, false);
			r_core_cmd0 (core, ".ar*");
		}
		break;
	case 'i': // "aei"
		switch (input[1]) {
		case 's': // "aeis"
		case 'm': // "aeim"
			cmd_esil_mem (core, input + 2);
			break;
		case 'p': // "aeip" // initialize pc = $$
			r_core_cmd0 (core, "ar PC=$$");
			break;
		case '?':
			cmd_esil_mem (core, "?");
			break;
		case '-':
			if (esil) {
				sdb_reset (esil->stats);
			}
			r_anal_esil_free (esil);
			core->anal->esil = NULL;
			break;
		case 0:				//lolololol
			r_anal_esil_free (esil);
			// reinitialize
			{
				const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
				if (pc && r_reg_getv (core->anal->reg, pc) == 0LL) {
					r_core_cmd0 (core, "ar PC=$$");
				}
			}
			if (!(esil = core->anal->esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
				return;
			}
			r_anal_esil_setup (esil, core->anal, romem, stats, noNULL); // setup io
			esil->verbose = (int)r_config_get_i (core->config, "esil.verbose");
			/* restore user settings for interrupt handling */
			{
				const char *s = r_config_get (core->config, "cmd.esil.intr");
				if (s) {
					char *my = strdup (s);
					if (my) {
						r_config_set (core->config, "cmd.esil.intr", my);
						free (my);
					}
				}
			}
			break;
		}
		break;
	case 'k': // "aek"
		switch (input[1]) {
		case '\0':
			input = "123*";
			/* fall through */
		case ' ':
			if (esil && esil->stats) {
				char *out = sdb_querys (esil->stats, NULL, 0, input + 2);
				if (out) {
					r_cons_println (out);
					free (out);
				}
			} else {
				eprintf ("esil.stats is empty. Run 'aei'\n");
			}
			break;
		case '-':
			if (esil) {
				sdb_reset (esil->stats);
			}
			break;
		}
		break;
	case 'l': // ael commands
		switch (input[1]) {
		case 'i': // aeli interrupts
			switch (input[2]) {
			case ' ': // "aeli" with arguments
				if (!r_anal_esil_load_interrupts_from_lib (esil, input + 3)) {
					eprintf ("Failed to load interrupts from '%s'.", input + 3);
				}
				break;
			case 0: // "aeli" with no args
				if (esil && esil->interrupts) {
					dict_foreach (esil->interrupts, _aeli_iter, NULL);
				}
				break;
			case 'r': // "aelir"
				if (esil && esil->interrupts) {
					RAnalEsilInterrupt* interrupt = dict_getu (esil->interrupts, r_num_math (core->num, input + 3));
					r_anal_esil_interrupt_free (esil, interrupt);
				}
				break;

				// TODO: display help?
			}
		}
		break;
	case 'g': // "aeg"
		if (input[1] == 'v') {
			r_core_cmd0 (core, ".aeg;agg");
		} else if (input[1] == ' ') {
			r_core_anal_esil_graph (core, input + 2);
		} else { // "*"
			RAnalOp *aop = r_core_anal_op (core, core->offset, R_ANAL_OP_MASK_ESIL);
			if (aop) {
				const char *esilstr = r_strbuf_get (&aop->esil);
				if (esilstr) {
					r_core_anal_esil_graph (core, esilstr);
				}
			}
		}
		break;
	case 'f': // "aef"
		if (input[1] == 'a') { // "aefa"
			r_anal_aefa (core, r_str_trim_ro (input + 2));
		} else { // This should be aefb -> because its emulating all the bbs
		RListIter *iter;
		RAnalBlock *bb;
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal,
							core->offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			// emulate every instruction in the function recursively across all the basic blocks
			r_list_foreach (fcn->bbs, iter, bb) {
				ut64 pc = bb->addr;
				ut64 end = bb->addr + bb->size;
				RAnalOp op;
				int ret, bbs = end - pc;
				if (bbs < 1 || bbs > 0xfffff) {
					eprintf ("Invalid block size\n");
				}
		//		eprintf ("[*] Emulating 0x%08"PFMT64x" basic block 0x%08" PFMT64x " - 0x%08" PFMT64x "\r[", fcn->addr, pc, end);
				ut8 *buf = calloc (1, bbs + 1);
				if (!buf) {
					break;
				}
				r_io_read_at (core->io, pc, buf, bbs);
				int left;
				while (pc < end) {
					left = R_MIN (end - pc, 32);
					r_asm_set_pc (core->assembler, pc);
					ret = r_anal_op (core->anal, &op, pc, buf + pc - bb->addr, left, R_ANAL_OP_MASK_HINT | R_ANAL_OP_MASK_ESIL); // read overflow
					if (op.type == R_ANAL_OP_TYPE_RET) {
						break;
					}
					if (ret) {
						r_reg_set_value_by_role (core->anal->reg, R_REG_NAME_PC, pc);
						r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op.esil));
						r_anal_esil_dumpstack (esil);
						r_anal_esil_stack_free (esil);
						pc += op.size;
					} else {
						pc += 4; // XXX
					}
				}
				free (buf);
			}
		} else {
			eprintf ("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		}
	} break;
	case 't': // "aet"
		switch (input[1]) {
		case 'r': // "aetr"
		{
			// anal ESIL to REIL.
			RAnalEsil *esil = r_anal_esil_new (stacksize, iotrap, addrsize);
			if (!esil) {
				return;
			}
			r_anal_esil_to_reil_setup (esil, core->anal, romem, stats);
			r_anal_esil_set_pc (esil, core->offset);
			r_anal_esil_parse (esil, input + 2);
			r_anal_esil_dumpstack (esil);
			r_anal_esil_free (esil);
			break;
		}
		case 's': // "aets"
			switch (input[2]) {
			case 0:
				r_anal_esil_session_list (esil);
				break;
			case '+':
				r_anal_esil_session_add (esil);
				break;
			default:
				r_core_cmd_help (core, help_msg_aets);
				break;
			}
			break;
		default:
			eprintf ("Unknown command. Use `aetr`.\n");
			break;
		}
		break;
	case 'A': // "aeA"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_aea);
		} else if (input[1] == 'r') {
			cmd_aea (core, 1 + (1<<1), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'w') {
			cmd_aea (core, 1 + (1<<2), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'n') {
			cmd_aea (core, 1 + (1<<3), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'j') {
			cmd_aea (core, 1 + (1<<4), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == '*') {
			cmd_aea (core, 1 + (1<<5), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'f') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) {
				cmd_aea (core, 1, fcn->addr, r_anal_fcn_size (fcn));
			}
		} else {
			cmd_aea (core, 1, core->offset, (int)r_num_math (core->num, input+2));
		}
		break;
	case 'a': // "aea"
		{
		RReg *reg = core->anal->reg;
		ut64 pc = r_reg_getv (reg, "PC");
		RAnalOp *op = r_core_anal_op (core, pc, 0);
		if (!op) {
			break;
		}
		ut64 newPC = core->offset + op->size;
		r_reg_setv (reg, "PC", newPC);
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_aea);
		} else if (input[1] == 'r') {
			cmd_aea (core, 1<<1, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'w') {
			cmd_aea (core, 1<<2, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'n') {
			cmd_aea (core, 1<<3, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'j') {
			cmd_aea (core, 1<<4, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == '*') {
			cmd_aea (core, 1<<5, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'f') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
                        // "aeafj"
			if (fcn) {
				switch (input[2]) {
				case 'j': // "aeafj"
					cmd_aea (core, 1<<4, fcn->addr, r_anal_fcn_size (fcn));
					break;
				default:
					cmd_aea (core, 1, fcn->addr, r_anal_fcn_size (fcn));
					break;
				}
				break;
			}
		} else if (input[1] == 'b') { // "aeab"
			RAnalBlock *bb = r_anal_bb_from_offset (core->anal, core->offset);
			if (bb) {
				switch (input[2]) {
				case 'j': // "aeabj"
					cmd_aea (core, 1<<4, bb->addr, bb->size);
					break;
				default:
					cmd_aea (core, 1, bb->addr, bb->size);
					break;
				}
			}
		} else {
			const char *arg = input[1]? input + 2: "";
			ut64 len = r_num_math (core->num, arg);
			cmd_aea (core, 0, core->offset, len);
		}
		r_reg_setv (reg, "PC", pc);
}
		break;
	case 'x': { // "aex"
		char *hex;
		int ret, bufsz;

		input = r_str_trim_ro (input + 1);
		hex = strdup (input);
		if (!hex) {
			break;
		}

		RAnalOp aop = R_EMPTY;
		bufsz = r_hex_str2bin (hex, (ut8*)hex);
		ret = r_anal_op (core->anal, &aop, core->offset,
			(const ut8*)hex, bufsz, R_ANAL_OP_MASK_ESIL);
		if (ret>0) {
			const char *str = R_STRBUF_SAFEGET (&aop.esil);
			char *str2 = r_str_newf (" %s", str);
			cmd_anal_esil (core, str2);
			free (str2);
		}
		r_anal_op_fini (&aop);
		break;
	}
	case '?': // "ae?"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_detail_ae);
			break;
		}
		/* fallthrough */
	default:
		r_core_cmd_help (core, help_msg_ae);
		break;
	}
}

static void cmd_anal_bytes(RCore *core, const char *input) {
	int len = core->blocksize;
	int tbs = len;
	if (input[0]) {
		len = (int)r_num_get (core->num, input + 1);
		if (len > tbs) {
			r_core_block_size (core, len);
		}
	}
	core_anal_bytes (core, core->block, len, 0, input[0]);
	if (tbs != core->blocksize) {
		r_core_block_size (core, tbs);
	}
}

static void cmd_anal_opcode(RCore *core, const char *input) {
	int l, len = core->blocksize;
	ut32 tbs = core->blocksize;
	r_core_block_read (core);
	switch (input[0]) {
	case 's': // "aos"
	case 'j': // "aoj"
	case 'e': // "aoe"
	case 'r': {
		int count = 1;
		int obs = core->blocksize;
		if (input[1] && input[2]) {
			l = (int)r_num_get (core->num, input + 1);
			if (l > 0) {
				count = l;
			}
			l *= 8;
			if (l > obs) {
				r_core_block_size (core, l);
			}
		} else {
			count = 1;
		}
		core_anal_bytes (core, core->block, core->blocksize, count, input[0]);
		if (obs != core->blocksize) {
			r_core_block_size (core, obs);
		}
		}
		break;
	case 'm': // "aom"
		if (input[1] == '?') {
			r_cons_printf ("Usage: aom[ljd] [arg] .. list mnemonics for asm.arch\n");
			r_cons_printf (". = current, l = list, d = describe, j=json)\n");
		} else if (input[1] == 'd') {
			const int id = (input[2]==' ')
				?(int)r_num_math (core->num, input + 2): -1;
			char *ops = r_asm_mnemonics (core->assembler, id, false);
			if (ops) {
				char *ptr = ops;
				char *nl = strchr (ptr, '\n');
				while (nl) {
					*nl = 0;
					char *desc = r_asm_describe (core->assembler, ptr);
					if (desc) {
						const char *pad = r_str_pad (' ', 16 - strlen (ptr));
						r_cons_printf ("%s%s%s\n", ptr, pad, desc);
						free (desc);
					} else {
						r_cons_printf ("%s\n", ptr);
					}
					ptr = nl + 1;
					nl = strchr (ptr, '\n');
				}
				free (ops);
			}
		} else if (input[1] == 'l' || input[1] == '=' || input[1] == ' ' || input[1] == 'j') {
			if (input[1] == ' ' && !IS_DIGIT (input[2])) {
				r_cons_printf ("%d\n", r_asm_mnemonics_byname (core->assembler, input + 2));
			} else {
				const int id = (input[1] == ' ')
					?(int)r_num_math (core->num, input + 2): -1;
				char *ops = r_asm_mnemonics (core->assembler, id, input[1] == 'j');
				if (ops) {
					r_cons_println (ops);
					free (ops);
				}
			}
		} else {
			r_core_cmd0 (core, "ao~mnemonic[1]");
		}
		break;
	case 'c': // "aoc"
	{
		RList *hooks;
		RListIter *iter;
		RAnalCycleHook *hook;
		char *instr_tmp = NULL;
		int ccl = input[1]? r_num_math (core->num, &input[2]): 0; //get cycles to look for
		int cr = r_config_get_i (core->config, "asm.cmt.right");
		int fun = r_config_get_i (core->config, "asm.functions");
		int li = r_config_get_i (core->config, "asm.lines");
		int xr = r_config_get_i (core->config, "asm.xrefs");

		r_config_set_i (core->config, "asm.cmt.right", true);
		r_config_set_i (core->config, "asm.functions", false);
		r_config_set_i (core->config, "asm.lines", false);
		r_config_set_i (core->config, "asm.xrefs", false);

		hooks = r_core_anal_cycles (core, ccl); //analyse
		r_cons_clear_line (1);
		r_list_foreach (hooks, iter, hook) {
			instr_tmp = r_core_disassemble_instr (core, hook->addr, 1);
			r_cons_printf ("After %4i cycles:\t%s", (ccl - hook->cycles), instr_tmp);
			r_cons_flush ();
			free (instr_tmp);
		}
		r_list_free (hooks);

		r_config_set_i (core->config, "asm.cmt.right", cr); //reset settings
		r_config_set_i (core->config, "asm.functions", fun);
		r_config_set_i (core->config, "asm.lines", li);
		r_config_set_i (core->config, "asm.xrefs", xr);
	}
	break;
	case 'd': // "aod"
		if (input[1] == 'a') { // "aoda"
			// list sdb database
			sdb_foreach (core->assembler->pair, listOpDescriptions, core);
		} else if (input[1] == 0) {
			int cur = R_MAX (core->print->cur, 0);
			// XXX: we need cmd_xxx.h (cmd_anal.h)
			core_anal_bytes (core, core->block + cur, core->blocksize, 1, 'd');
		} else if (input[1] == ' ') {
			char *d = r_asm_describe (core->assembler, input + 2);
			if (d && *d) {
				r_cons_println (d);
				free (d);
			} else {
				eprintf ("Unknown mnemonic\n");
			}
		} else {
			eprintf ("Use: aod[?a] ([opcode])    describe current, [given] or all mnemonics\n");
		}
		break;
	case '*':
		r_core_anal_hint_list (core->anal, input[0]);
		break;
	case 0:
	case ' ': {
			int count = 0;
			if (input[0]) {
				l = (int)r_num_get (core->num, input + 1);
				if (l > 0) {
					count = l;
				}
				if (l > tbs) {
					r_core_block_size (core, l * 4);
					//len = l;
				}
			} else {
				len = l = core->blocksize;
				count = 1;
			}
			core_anal_bytes (core, core->block, len, count, 0);
		}
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg_ao);
		break;
	}
}

static void cmd_anal_jumps(RCore *core, const char *input) {
	r_core_cmdf (core, "af @@= `ax~ref.code.jmp[1]`");
}

// TODO: cleanup to reuse code
static void cmd_anal_aftertraps(RCore *core, const char *input) {
	int bufi, minop = 1; // 4
	ut8 *buf;
	RAnalOp op = {0};
	ut64 addr, addr_end;
	ut64 len = r_num_math (core->num, input);
	if (len > 0xffffff) {
		eprintf ("Too big\n");
		return;
	}
	RBinFile *bf = r_bin_cur (core->bin);
	if (!bf) {
		return;
	}
	addr = core->offset;
	if (!len) {
		// ignore search.in to avoid problems. analysis != search
		RIOMap *map = r_io_map_get (core->io, addr);
		if (map && (map->perm & R_PERM_X)) {
			// search in current section
			if (map->itv.size > bf->size) {
				addr = map->itv.addr;
				if (bf->size > map->delta) {
					len = bf->size - map->delta;
				} else {
					eprintf ("Opps something went wrong aac\n");
					return;
				}
			} else {
				addr = map->itv.addr;
				len = map->itv.size;
			}
		} else {
			if (map && map->itv.addr != map->delta && bf->size > (core->offset - map->itv.addr + map->delta)) {
				len = bf->size - (core->offset - map->itv.addr + map->delta);
			} else {
				if (bf->size > core->offset) {
					len = bf->size - core->offset;
				} else {
					eprintf ("Oops invalid range\n");
					len = 0;
				}
			}
		}
	}
	addr_end = addr + len;
	if (!(buf = malloc (4096))) {
		return;
	}
	bufi = 0;
	int trapcount = 0;
	int nopcount = 0;
	r_cons_break_push (NULL, NULL);
	while (addr < addr_end) {
		if (r_cons_is_breaked ()) {
			break;
		}
		// TODO: too many ioreads here
		if (bufi > 4000) {
			bufi = 0;
		}
		if (!bufi) {
			r_io_read_at (core->io, addr, buf, 4096);
		}
		if (r_anal_op (core->anal, &op, addr, buf + bufi, 4096 - bufi, R_ANAL_OP_MASK_BASIC)) {
			if (op.size < 1) {
				// XXX must be +4 on arm/mips/.. like we do in disasm.c
				op.size = minop;
			}
			if (op.type == R_ANAL_OP_TYPE_TRAP) {
				trapcount ++;
			} else if (op.type == R_ANAL_OP_TYPE_NOP) {
				nopcount ++;
			} else {
				if (nopcount > 1) {
					r_cons_printf ("af @ 0x%08"PFMT64x"\n", addr);
					nopcount = 0;
				}
				if (trapcount > 0) {
					r_cons_printf ("af @ 0x%08"PFMT64x"\n", addr);
					trapcount = 0;
				}
			}
		} else {
			op.size = minop;
		}
		addr += (op.size > 0)? op.size : 1;
		bufi += (op.size > 0)? op.size : 1;
		r_anal_op_fini (&op);
	}
	r_cons_break_pop ();
	free (buf);
}

static void cmd_anal_blocks(RCore *core, const char *input) {
	ut64 from , to;
	char *arg = strchr (input, ' ');
	r_cons_break_push (NULL, NULL);
	if (!arg) {
		RList *list = r_core_get_boundaries_prot (core, R_PERM_X, NULL, "anal");
		RListIter *iter;
		RIOMap* map;
		if (!list) {
			goto ctrl_c;
		}
		r_list_foreach (list, iter, map) {
			from = map->itv.addr;
			to = r_itv_end (map->itv);
			if (r_cons_is_breaked ()) {
				goto ctrl_c;
			}
			if (!from && !to) {
				eprintf ("Cannot determine search boundaries\n");
			} else if (to - from > UT32_MAX) {
				eprintf ("Skipping huge range\n");
			} else {
				r_core_cmdf (core, "abb 0x%08"PFMT64x" @ 0x%08"PFMT64x, (to - from), from);
			}
		}
	} else {
		st64 sz = r_num_math (core->num, arg + 1);
		if (sz < 1) {
			eprintf ("Invalid range\n");
			return;
		}
		r_core_cmdf (core, "abb 0x%08"PFMT64x" @ 0x%08"PFMT64x, sz, core->offset);
	}
ctrl_c:
	r_cons_break_pop ();
}

static void _anal_calls(RCore *core, ut64 addr, ut64 addr_end, bool printCommands, bool importsOnly) {
	RAnalOp op;
	int depth = r_config_get_i (core->config, "anal.depth");
	const int addrbytes = core->io->addrbytes;
	const int bsz = 4096;
	int bufi = 0;
	int bufi_max = bsz - 16;
	if (addr_end - addr > UT32_MAX) {
		return;
	}
	ut8 *buf = malloc (bsz);
	ut8 *block0 = calloc (1, bsz);
	ut8 *block1 = malloc (bsz);
	if (!buf || !block0 || !block1) {
		eprintf ("Error: cannot allocate buf or block\n");
		free (buf);
		free (block0);
		free (block1);
		return;
	}
	memset (block1, -1, bsz);
	int minop = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	if (minop < 1) {
		minop = 1;
	}
	int setBits = r_config_get_i (core->config, "asm.bits");
	r_cons_break_push (NULL, NULL);
	while (addr < addr_end && !r_cons_is_breaked ()) {
		// TODO: too many ioreads here
		if (bufi > bufi_max) {
			bufi = 0;
		}
		if (!bufi) {
			(void)r_io_read_at (core->io, addr, buf, bsz);
		}
		if (!memcmp (buf, block0, bsz) || !memcmp (buf, block1, bsz)) {
			//eprintf ("Error: skipping uninitialized block \n");
			addr += bsz;
			continue;
		}
		RAnalHint *hint = r_anal_hint_get (core->anal, addr);
		if (hint && hint->bits) {
			setBits = hint->bits;
		}
		r_anal_hint_free (hint);
		if (setBits != core->assembler->bits) {
			r_config_set_i (core->config, "asm.bits", setBits);
		}
		if (r_anal_op (core->anal, &op, addr, buf + bufi, bsz - bufi, 0) > 0) {
			if (op.size < 1) {
				op.size = minop;
			}
			if (op.type == R_ANAL_OP_TYPE_CALL) {
				bool isValidCall = true;
				if (importsOnly) {
					RFlagItem *f = r_flag_get_i (core->flags, op.jump);
					if (!f || !strstr (f->name, "imp.")) {
						isValidCall = false;
					}
				}
				RBinReloc *rel = r_core_getreloc (core, addr, op.size);
				if (rel && (rel->import || rel->symbol)) {
					isValidCall = false;
				}
				if (isValidCall) {
					ut8 buf[4];
					r_io_read_at (core->io, op.jump, buf, 4);
					isValidCall = memcmp (buf, "\x00\x00\x00\x00", 4);
				}
				if (isValidCall) {
#if JAYRO_03
					if (!anal_is_bad_call (core, from, to, addr, buf, bufi)) {
						fcn = r_anal_get_fcn_in (core->anal, op.jump, R_ANAL_FCN_TYPE_ROOT);
						if (!fcn) {
							r_core_anal_fcn (core, op.jump, addr, R_ANAL_REF_TYPE_CALL, depth);
						}
					}
#else
					if (printCommands) {
						r_cons_printf ("ax 0x%08" PFMT64x " 0x%08" PFMT64x "\n", op.jump, addr);
						r_cons_printf ("af @ 0x%08" PFMT64x"\n", op.jump);
					} else {
						// add xref here
						r_anal_xrefs_set (core->anal, addr, op.jump, R_ANAL_REF_TYPE_CALL);
						if (r_io_is_valid_offset (core->io, op.jump, 1)) {
							r_core_anal_fcn (core, op.jump, addr, R_ANAL_REF_TYPE_CALL, depth);
						}
					}
#endif
				}
			}
		} else {
			op.size = minop;
		}
		if ((int)op.size < 1) {
			op.size = minop;
		}
		addr += op.size;
		bufi += addrbytes * op.size;
		r_anal_op_fini (&op);
	}
	r_cons_break_pop ();
	free (buf);
	free (block0);
	free (block1);
}

static void cmd_anal_calls(RCore *core, const char *input, bool printCommands, bool importsOnly) {
	RList *ranges = NULL;
	RIOMap *r;
	ut64 addr;
	ut64 len = r_num_math (core->num, input);
	if (len > 0xffffff) {
		eprintf ("Too big\n");
		return;
	}
	RBinFile *binfile = r_bin_cur (core->bin);
	addr = core->offset;
	if (binfile) {
		if (len) {
			RIOMap *m = R_NEW0 (RIOMap);
			m->itv.addr = addr;
			m->itv.size = len;
			ranges = r_list_newf ((RListFree)free);
			r_list_append (ranges, m);
		} else {
			ranges = r_core_get_boundaries_prot (core, R_PERM_X, NULL, "anal");
		}
	}
	r_cons_break_push (NULL, NULL);
	if (!binfile || (ranges && !r_list_length (ranges))) {
		RListIter *iter;
		RIOMap *map;
		r_list_free (ranges);
		ranges = r_core_get_boundaries_prot (core, 0, NULL, "anal");
		if (ranges) {
			r_list_foreach (ranges, iter, map) {
				ut64 addr = map->itv.addr;
				_anal_calls (core, addr, r_itv_end (map->itv), printCommands, importsOnly);
			}
		}
	} else {
		RListIter *iter;
		if (binfile) {
			r_list_foreach (ranges, iter, r) {
				addr = r->itv.addr;
				//this normally will happen on fuzzed binaries, dunno if with huge
				//binaries as well
				if (r_cons_is_breaked ()) {
					break;
				}
				_anal_calls (core, addr, r_itv_end (r->itv), printCommands, importsOnly);
			}
		}
	}
	r_cons_break_pop ();
	r_list_free (ranges);
}

static void cmd_sdbk(Sdb *db, const char *input) {
	char *out = (input[0] == ' ')
		? sdb_querys (db, NULL, 0, input + 1)
		: sdb_querys (db, NULL, 0, "*");
	if (out) {
		r_cons_println (out);
		free (out);
	} else {
		eprintf ("|ERROR| Usage: ask [query]\n");
	}
}

static void cmd_anal_syscall(RCore *core, const char *input) {
	PJ *pj = NULL;
	RSyscallItem *si;
	RListIter *iter;
	RList *list;
	RNum *num = NULL;
	int n;

	switch (input[0]) {
	case 'c': // "asc"
		if (input[1] == 'a') {
			if (input[2] == ' ') {
				if (!isalpha ((ut8)input[3]) && (n = r_num_math (num, input + 3)) >= 0 ) {
					si = r_syscall_get (core->anal->syscall, n, -1);
					if (si) {
						r_cons_printf (".equ SYS_%s %s\n", si->name, syscallNumber (n));
					}
					else eprintf ("Unknown syscall number\n");
				} else {
					n = r_syscall_get_num (core->anal->syscall, input + 3);
					if (n != -1) {
						r_cons_printf (".equ SYS_%s %s\n", input + 3, syscallNumber (n));
					} else {
						eprintf ("Unknown syscall name\n");
					}
				}
			} else {
				list = r_syscall_list (core->anal->syscall);
				r_list_foreach (list, iter, si) {
					r_cons_printf (".equ SYS_%s %s\n",
						si->name, syscallNumber (si->num));
				}
				r_list_free (list);
			}
		} else {
			if (input[1] == ' ') {
				if (!isalpha ((ut8)input[2]) && (n = r_num_math (num, input + 2)) >= 0 ) {
					si = r_syscall_get (core->anal->syscall, n, -1);
					if (si) {
						r_cons_printf ("#define SYS_%s %s\n", si->name, syscallNumber (n));
					}
					else eprintf ("Unknown syscall number\n");
				} else {
					n = r_syscall_get_num (core->anal->syscall, input + 2);
					if (n != -1) {
						r_cons_printf ("#define SYS_%s %s\n", input + 2, syscallNumber (n));
					} else {
						eprintf ("Unknown syscall name\n");
					}
				}
			} else {
				list = r_syscall_list (core->anal->syscall);
				r_list_foreach (list, iter, si) {
					r_cons_printf ("#define SYS_%s %d\n",
						si->name, syscallNumber (si->num));
				}
				r_list_free (list);
			}
		}
		break;
	case 'f': // "asf"
		cmd_sdbk (core->anal->sdb_fcnsign, input + 1);
		break;
	case 'k': // "ask"
		cmd_sdbk (core->anal->syscall->db, input + 1);
		break;
	case 'l': // "asl"
		if (input[1] == ' ') {
			if (!isalpha ((ut8)input[2]) && (n = r_num_math (num, input + 2)) >= 0 ) {
				si = r_syscall_get (core->anal->syscall, n, -1);
				if (si)
					r_cons_println (si->name);
				else eprintf ("Unknown syscall number\n");
			} else {
				n = r_syscall_get_num (core->anal->syscall, input + 2);
				if (n != -1) {
					r_cons_printf ("%s\n", syscallNumber (n));
				} else {
					eprintf ("Unknown syscall name\n");
				}
			}
		} else {
			list = r_syscall_list (core->anal->syscall);
			r_list_foreach (list, iter, si) {
				r_cons_printf ("%s = 0x%02x.%s\n",
					si->name, si->swi, syscallNumber (si->num));
			}
			r_list_free (list);
		}
		break;
	case 'j': // "asj"
		pj = pj_new ();
		pj_a (pj);
		list = r_syscall_list (core->anal->syscall);
		r_list_foreach (list, iter, si) {
			pj_o (pj);
			pj_ks (pj, "name", si->name);
			pj_ki (pj, "swi", si->swi);
			pj_ki (pj, "num", si->num);
			pj_end (pj);
		}
		pj_end (pj);
		if (pj) {
			r_cons_println (pj_string (pj));
			pj_free (pj);
		}
		break;
	case '\0':
		cmd_syscall_do (core, -1, core->offset);
		break;
	case ' ':
		{
		const char *sn = r_str_trim_ro (input + 1);
		st64 num = r_syscall_get_num (core->anal->syscall, sn);
		if (num < 1) {
			num = (int)r_num_get (core->num, sn);
		}
		cmd_syscall_do (core, num, -1);
		}
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg_as);
		break;
	}
}

static void anal_axg (RCore *core, const char *input, int level, Sdb *db, int opts, PJ* pj) {
	char arg[32], pre[128];
	RListIter *iter;
	RAnalRef *ref;
	ut64 addr = core->offset;
	bool is_json = opts & R_CORE_ANAL_JSON;
	bool is_r2 = opts & R_CORE_ANAL_GRAPHBODY;
	if (is_json && !pj) {
		return;
	}
	if (input && *input) {
		addr = r_num_math (core->num, input);
	}
	// eprintf ("Path between 0x%08"PFMT64x" .. 0x%08"PFMT64x"\n", core->offset, addr);
	int spaces = (level + 1) * 2;
	if (spaces > sizeof (pre) - 4) {
		spaces = sizeof (pre) - 4;
	}
	memset (pre, ' ', sizeof (pre));
	strcpy (pre + spaces, "- ");

	RList *xrefs = r_anal_xrefs_get (core->anal, addr);
	bool open_object = false;
	if (!r_list_empty (xrefs)) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
		if (fcn) {
			if (is_r2) {
				r_cons_printf ("agn 0x%08"PFMT64x" %s\n", fcn->addr, fcn->name);
			} else if (is_json) {
				char taddr[64];
				pj_o (pj);
				pj_k (pj, sdb_itoa (addr, taddr, 10));
				pj_o (pj);
				pj_ks (pj, "type", "fcn");
				pj_kn (pj, "fcn_addr", fcn->addr);
				pj_ks (pj, "name", fcn->name);
				pj_k (pj, "refs");
				pj_a (pj);
				open_object = true;
			} else {
				//if (sdb_add (db, fcn->name, "1", 0)) {
				r_cons_printf ("%s0x%08"PFMT64x" fcn 0x%08"PFMT64x" %s\n",
					pre + 2, addr, fcn->addr, fcn->name);
				//}
			}
		} else {
			if (is_r2) {
				r_cons_printf ("age 0x%08"PFMT64x"\n", addr);
			} else if (is_json) {
				char taddr[64];
				pj_o (pj);
				pj_k (pj, sdb_itoa (addr, taddr, 10));
				pj_o (pj);
				pj_k (pj, "refs");
				pj_a (pj);
				open_object = true;
			} else {
			//snprintf (arg, sizeof (arg), "0x%08"PFMT64x, addr);
			//if (sdb_add (db, arg, "1", 0)) {
				r_cons_printf ("%s0x%08"PFMT64x"\n", pre+2, addr);
			//}
			}
		}
	}
	r_list_foreach (xrefs, iter, ref) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, ref->addr, -1);
		if (fcn) {
			if (is_r2) {
				r_cons_printf ("agn 0x%08"PFMT64x" %s\n", fcn->addr, fcn->name);
				r_cons_printf ("age 0x%08"PFMT64x" 0x%08"PFMT64x"\n", fcn->addr, addr);
			} else if (is_json) {
				if (level == 0) {
					char taddr[64];
					pj_o (pj);
					pj_k (pj, sdb_itoa (ref->addr, taddr, 10));
					pj_o (pj);
					pj_ks (pj, "type", "fcn");
					pj_kn (pj, "fcn_addr", fcn->addr);
					pj_ks (pj, "name", fcn->name);
					pj_k (pj, "refs");
					pj_a (pj);
					open_object = true;
				} else {
					char taddr[64];
					pj_end (pj);
					pj_end (pj);
					pj_end (pj);
					pj_o (pj);
					pj_k (pj, sdb_itoa (ref->addr, taddr, 10));
					pj_o (pj);
					pj_ks (pj, "type", "fcn");
					pj_kn (pj, "fcn_addr", fcn->addr);
					pj_ks (pj, "refs", fcn->name);
					pj_k (pj, "refs");
					pj_a (pj);

				}
			} else {
				r_cons_printf ("%s0x%08"PFMT64x" fcn 0x%08"PFMT64x" %s\n", pre, ref->addr, fcn->addr, fcn->name);
			}
			if (sdb_add (db, fcn->name, "1", 0)) {
				snprintf (arg, sizeof (arg), "0x%08"PFMT64x, fcn->addr);
				anal_axg (core, arg, level + 1, db, opts, pj);
			} else {
				if (is_json) {
					pj_end (pj);
					pj_end (pj);
					pj_end (pj);
					open_object = false;
				}
			}
		} else {
			if (is_r2) {
				r_cons_printf ("agn 0x%08"PFMT64x" ???\n", ref->addr);
				r_cons_printf ("age 0x%08"PFMT64x" 0x%08"PFMT64x"\n", ref->addr, addr);
			} else if (is_json) {
				char taddr[64];
				pj_o (pj);
				pj_k (pj, sdb_itoa (ref->addr, taddr, 10));
				pj_o (pj);
				pj_ks (pj, "type", "???");
				pj_k (pj, "refs");
				pj_a (pj);
				open_object = true;
			} else {
				r_cons_printf ("%s0x%08"PFMT64x" ???\n", pre, ref->addr);
			}
			snprintf (arg, sizeof (arg), "0x%08"PFMT64x, ref->addr);
			if (sdb_add (db, arg, "1", 0)) {
				anal_axg (core, arg, level + 1, db, opts, pj);
			} else {
				if (is_json) {
					pj_end (pj);
					pj_end (pj);
					pj_end (pj);
					open_object = false;
				}
			}
		}
	}
	if (is_json) {
		if (open_object) {
			pj_end (pj);
			pj_end (pj);
			pj_end (pj);
		}
		if (level == 0) {
			if (open_object) {
				pj_end (pj);
				pj_end (pj);
				pj_end (pj);
			}
		}
	}
	r_list_free (xrefs);
}

static void cmd_anal_ucall_ref (RCore *core, ut64 addr) {
	RAnalFunction * fcn = r_anal_get_fcn_at (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (fcn) {
		r_cons_printf (" ; %s", fcn->name);
	} else {
		r_cons_printf (" ; 0x%" PFMT64x, addr);
	}
}

static char *get_buf_asm(RCore *core, ut64 from, ut64 addr, RAnalFunction *fcn, bool color) {
	int has_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	char str[512];
	const int size = 12;
	ut8 buf[12];
	RAsmOp asmop = {0};
	char *buf_asm = NULL;
	bool asm_varsub = r_config_get_i (core->config, "asm.var.sub");
	core->parser->pseudo = r_config_get_i (core->config, "asm.pseudo");
	core->parser->relsub = r_config_get_i (core->config, "asm.relsub");
	core->parser->localvar_only = r_config_get_i (core->config, "asm.var.subonly");

	if (core->parser->relsub) {
		core->parser->relsub_addr = from;
	}
	r_io_read_at (core->io, addr, buf, size);
	r_asm_set_pc (core->assembler, addr);
	r_asm_disassemble (core->assembler, &asmop, buf, size);
	int ba_len = r_strbuf_length (&asmop.buf_asm) + 128;
	char *ba = malloc (ba_len);
	strcpy (ba, r_strbuf_get (&asmop.buf_asm));
	if (asm_varsub) {
		r_parse_varsub (core->parser, fcn, addr, asmop.size,
				ba, ba, sizeof (asmop.buf_asm));
	}
	RAnalHint *hint = r_anal_hint_get (core->anal, addr);
	r_parse_filter (core->parser, addr, core->flags, hint,
			ba, str, sizeof (str), core->print->big_endian);
	r_anal_hint_free (hint);
	r_asm_op_set_asm (&asmop, ba);
	free (ba);
	if (color && has_color) {
		buf_asm = r_print_colorize_opcode (core->print, str,
				core->cons->context->pal.reg, core->cons->context->pal.num, false, fcn ? fcn->addr : 0);
	} else {
		buf_asm = r_str_new (str);
	}
	return buf_asm;
}

#define var_ref_list(a,d,t) sdb_fmt ("var.0x%"PFMT64x".%d.%d.%s",\
		a, 1, d, (t == 'R')?"reads":"writes");

static bool cmd_anal_refs(RCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[0]) {
	case '-': { // "ax-"
		RList *list;
		RListIter *iter;
		RAnalRef *ref;
		char *cp_inp = strdup (input + 1);
		char *ptr = r_str_trim_head (cp_inp);
		if (!strcmp (ptr, "*")) { // "ax-*"
			r_anal_xrefs_init (core->anal);
		} else {
			int n = r_str_word_set0 (ptr);
			ut64 from = UT64_MAX, to = UT64_MAX;
			switch (n) {
			case 2:
				from = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				//fall through
			case 1: // get addr
				to = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				break;
			default:
				to = core->offset;
				break;
			}
			list = r_anal_xrefs_get (core->anal, to);
			if (list) {
				r_list_foreach (list, iter, ref) {
					if (from != UT64_MAX && from == ref->addr) {
						r_anal_xref_del (core->anal, ref->addr, ref->at);
					}
					if (from == UT64_MAX) {
						r_anal_xref_del (core->anal, ref->addr, ref->at);
					}
				}
			}
			r_list_free (list);
		}
		free (cp_inp);
	} break;
	case 'g': // "axg"
		{
			Sdb *db = sdb_new0 ();
			if (input[1] == '*') {
				anal_axg (core, input + 2, 0, db, R_CORE_ANAL_GRAPHBODY, NULL); // r2 commands
			} else if (input[1] == 'j') {
				PJ *pj = pj_new ();
				anal_axg (core, input + 2, 0, db, R_CORE_ANAL_JSON, pj);
				r_cons_printf("%s\n", pj_string (pj));
				pj_free (pj);
			} else {
				anal_axg (core, input[1] ? input + 2 : NULL, 0, db, 0, NULL);
			}
			sdb_free (db);
		}
		break;
	case '\0': // "ax"
	case 'j': // "axj"
	case 'q': // "axq"
	case '*': // "ax*"
		r_anal_xrefs_list (core->anal, input[0]);
		break;
	case '.': { // "ax."
		char *tInput = strdup (input);
		if (r_str_replace_ch (tInput, '.', 't', false)) {
			cmd_anal_refs (core, tInput);
		}
		char *fInput = strdup (input);
		if (r_str_replace_ch (fInput, '.', 'f', false)) {
			cmd_anal_refs (core, fInput);
		}
		free (tInput);
		free (fInput);
	} break;
	case 'm': { // "axm"
		RList *list;
		RAnalRef *ref;
		RListIter *iter;
		char *ptr = strdup (r_str_trim_head ((char *)input + 1));
		int n = r_str_word_set0 (ptr);
		ut64 at = core->offset;
		ut64 addr = UT64_MAX;
		switch (n) {
		case 2: // get at
			at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
		/* fall through */
		case 1: // get addr
			addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			break;
		default:
			free (ptr);
			return false;
		}
		//get all xrefs pointing to addr
		list = r_anal_xrefs_get (core->anal, addr);
		r_list_foreach (list, iter, ref) {
			r_cons_printf ("0x%"PFMT64x" %s\n", ref->addr, r_anal_xrefs_type_tostring (ref->type));
			r_anal_xrefs_set (core->anal, ref->addr, at, ref->type);
		}
		r_list_free (list);
		free (ptr);
	} break;
	case 't': { // "axt"
		RList *list = NULL;
		RAnalFunction *fcn;
		RAnalRef *ref;
		RListIter *iter;
		char *space = strchr (input, ' ');
		char *tmp = NULL;
		char *name = space ? strdup (space + 1): NULL;

		if (name && (tmp = strchr (name, ' '))) {
			char *varname = tmp + 1;
			*tmp = '\0';
			RAnalFunction *fcn = r_anal_fcn_find_name (core->anal, name);
			if (fcn) {
				RAnalVar *var = r_anal_var_get_byname (core->anal, fcn->addr, varname);
				if (var) {
					const char *rvar = var_ref_list (fcn->addr, var->delta, 'R');
					const char *wvar = var_ref_list (fcn->addr, var->delta, 'W');
					char *res = sdb_get (core->anal->sdb_fcns, rvar, 0);
					char *res1 = sdb_get (core->anal->sdb_fcns, wvar, 0);
					const char *ref;
					RListIter *iter;
					RList *list = (res && *res)? r_str_split_list (res, ",", 0): NULL;
					RList *list1 = (res1 && *res1)? r_str_split_list (res1, ",", 0): NULL;
					r_list_join (list , list1);
					r_list_foreach (list, iter, ref) {
						ut64 addr = r_num_math (NULL, ref);
						char *op = get_buf_asm (core, core->offset, addr, fcn, true);
						r_cons_printf ("%s 0x%"PFMT64x" [DATA] %s\n", fcn?  fcn->name : "(nofunc)", addr, op);
						free (op);
					}
					free (res);
					free (res1);
					R_FREE (name);
					r_anal_var_free (var);
					r_list_free (list);
					r_list_free (list1);
					break;
				}
			}
		}
		if (space) {
			addr = r_num_math (core->num, space + 1);
		} else {
			addr = core->offset;
		}
		list = r_anal_xrefs_get (core->anal, addr);
		if (list) {
			if (input[1] == 'q') { // "axtq"
				r_list_foreach (list, iter, ref) {
					r_cons_printf ("0x%" PFMT64x "\n", ref->addr);
				}
			} else if (input[1] == 'j') { // "axtj"
				PJ *pj = pj_new ();
				if (!pj) {
					return false;
				}
				pj_a (pj);
				r_list_foreach (list, iter, ref) {
					fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
					char *str = get_buf_asm (core, addr, ref->addr, fcn, false);
					pj_o (pj);
					pj_kn (pj, "from", ref->addr);
					pj_ks (pj, "type", r_anal_xrefs_type_tostring (ref->type));
					pj_ks (pj, "opcode", str);
					if (fcn) {
						pj_kn (pj, "fcn_addr", fcn->addr);
						pj_ks (pj, "fcn_name", fcn->name);
					}
					RFlagItem *fi = r_flag_get_at (core->flags, fcn? fcn->addr: ref->addr, true);
					if (fi) {
						if (fcn) {
							if (strcmp (fcn->name, fi->name)) {
								pj_ks (pj, "flag", fi->name);
							}
						} else {
							pj_k (pj, "name");
							if (fi->offset != ref->addr) {
								int delta = (int)(ref->addr - fi->offset);
								char *name_ref = r_str_newf ("%s+%d", fi->name, delta);
								pj_s (pj, name_ref);
								free (name_ref);
							} else {
								pj_s (pj, fi->name);
							}
						}
						if (fi->realname && strcmp (fi->name, fi->realname)) {
							char *escaped = r_str_escape (fi->realname);
							if (escaped) {
								pj_ks (pj, "realname", escaped);
								free (escaped);
							}
						}
					}
					char *refname = core->anal->coreb.getNameDelta (core, ref->at);
					if (refname) {
						r_str_replace_ch (refname, ' ', 0, true);
						pj_ks (pj, "refname", refname);
						free (refname);
					}
					pj_end (pj);
					free (str);
				}
				pj_end (pj);
				r_cons_printf ("%s", pj_string (pj));
				pj_free (pj);
				r_cons_newline ();
			} else if (input[1] == 'g') { // axtg
				r_list_foreach (list, iter, ref) {
					char *str = r_core_cmd_strf (core, "fd 0x%"PFMT64x, ref->addr);
					if (!str) {
						str = strdup ("?\n");
					}
					r_str_trim_tail (str);
					r_cons_printf ("agn 0x%" PFMT64x " \"%s\"\n", ref->addr, str);
					free (str);
				}
				if (input[2] != '*') {
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
					r_cons_printf ("agn 0x%" PFMT64x " \"%s\"\n", addr, fcn?fcn->name: "$$");
				}
				r_list_foreach (list, iter, ref) {
					r_cons_printf ("age 0x%" PFMT64x " 0x%"PFMT64x"\n", ref->addr, addr);
				}
			} else if (input[1] == '*') { // axt*
				// TODO: implement multi-line comments
				r_list_foreach (list, iter, ref)
					r_cons_printf ("CCa 0x%" PFMT64x " \"XREF type %d at 0x%" PFMT64x"%s\n",
						ref->addr, ref->type, addr, iter->n? ",": "");
			} else { // axt
				RAnalFunction *fcn;
				char *comment;
				r_list_foreach (list, iter, ref) {
					fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
					char *buf_asm = get_buf_asm (core, addr, ref->addr, fcn, true);
					comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ref->addr);
					char *buf_fcn = comment
						? r_str_newf ("%s; %s", fcn ?  fcn->name : "(nofunc)", strtok (comment, "\n"))
						: r_str_newf ("%s", fcn ? fcn->name : "(nofunc)");
					r_cons_printf ("%s 0x%" PFMT64x " [%s] %s\n",
						buf_fcn, ref->addr, r_anal_xrefs_type_tostring (ref->type), buf_asm);
					free (buf_asm);
					free (buf_fcn);
				}
			}
		} else {
			if (input[1] == 'j') { // "axtj"
				PJ *pj = pj_new ();
				if (!pj) {
					return false;
				}
				pj_a (pj);
				pj_end (pj);
				r_cons_println (pj_string (pj));
				pj_free (pj);
			}
		}
		r_list_free (list);
	} break;
	case 'f':
		if (input[1] == 'f') { // "axff"
			RAnalFunction * fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			RListIter *iter;
			PJ *pj = NULL;
			RAnalRef *refi;
			if (input[2] == 'j') { // "axffj"
				// start a new JSON object
				pj = pj_new ();
				pj_a (pj);
			}
			if (fcn) {
				RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
				r_list_foreach (refs, iter, refi) {
					RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
					const char *name = f ? f->name: "";
					if (input[2] == 'j') {
						pj_o (pj);
						pj_ks (pj, "type", r_anal_xrefs_type_tostring(refi->type));
						pj_kn (pj, "at", refi->at);
						pj_kn (pj, "ref", refi->addr);
						pj_ks (pj, "name", name);
						pj_end (pj);
					} else {
						r_cons_printf ("%s 0x%08"PFMT64x" 0x%08"PFMT64x" %s\n",
							r_anal_xrefs_type_tostring(refi->type), refi->at, refi->addr, name);
					}
				}
				if (input[2] ==  'j') {
					pj_end (pj);
				}
				if (pj) {
					r_cons_println (pj_string (pj));
					pj_free (pj);
				}
			} else {
				eprintf ("Cannot find any function\n");
			}
		} else { // "axf"
			RAsmOp asmop;
			RList *list, *list_ = NULL;
			RAnalRef *ref;
			RListIter *iter;
			char *space = strchr (input, ' ');
			if (space) {
				addr = r_num_math (core->num, space + 1);
			} else {
				addr = core->offset;
			}
			RAnalFunction * fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (input[1] == '.') { // "axf."
				list = list_ = r_anal_xrefs_get_from (core->anal, addr);
				if (!list) {
					list = r_anal_fcn_get_refs (core->anal, fcn);
				}
			} else {
				list = r_anal_refs_get (core->anal, addr);
			}

			if (list) {
				if (input[1] == 'q') { // "axfq"
					r_list_foreach (list, iter, ref) {
						r_cons_printf ("0x%" PFMT64x "\n", ref->at);
					}
				} else if (input[1] == 'j') { // "axfj"
					PJ *pj = pj_new ();
					if (!pj) {
						return false;
					}
					pj_a (pj);
					r_list_foreach (list, iter, ref) {
						// TODO: Use r_core_anal_op(DISASM) instead of all those 4 lines
						ut8 buf[16];
						r_io_read_at (core->io, ref->addr, buf, sizeof (buf));
						r_asm_set_pc (core->assembler, ref->addr);
						r_asm_disassemble (core->assembler, &asmop, buf, sizeof (buf));
						pj_o (pj);
						pj_kn (pj, "from", ref->at);
						pj_kn (pj, "to", ref->addr);
						pj_ks (pj, "type", r_anal_xrefs_type_tostring (ref->type));
						pj_ks (pj, "opcode", r_asm_op_get_asm (&asmop));
						pj_end (pj);
					}
					pj_end (pj);
					r_cons_println (pj_string (pj));
					pj_free (pj);
				} else if (input[1] == '*') { // "axf*"
					// TODO: implement multi-line comments
					r_list_foreach (list, iter, ref) {
						r_cons_printf ("CCa 0x%" PFMT64x " \"XREF from 0x%" PFMT64x "\n",
								ref->at, ref->type, r_asm_op_get_asm (&asmop), iter->n? ",": "");
					}
				} else { // "axf"
					char str[512];
					int has_color = core->print->flags & R_PRINT_FLAGS_COLOR;
					r_list_foreach (list, iter, ref) {
						ut8 buf[16];
						char *desc;
						char *desc_to_free = NULL;
						RFlagItem *flag = r_flag_get_at (core->flags, ref->addr, false);
						if (flag) {
							desc = flag->name;
						} else {
							r_io_read_at (core->io, ref->addr, buf, sizeof (buf));
							r_asm_set_pc (core->assembler, ref->addr);
							r_asm_disassemble (core->assembler, &asmop, buf, sizeof(buf));
							RAnalHint *hint = r_anal_hint_get (core->anal, ref->addr);
							r_parse_filter (core->parser, ref->addr, core->flags, hint, r_asm_op_get_asm (&asmop),
									str, sizeof (str), core->print->big_endian);
							r_anal_hint_free (hint);
							if (has_color) {
								desc = desc_to_free = r_print_colorize_opcode (core->print, str,
										core->cons->context->pal.reg, core->cons->context->pal.num, false, fcn ? fcn->addr : 0);
							} else {
								desc = str;
							}
						}
						r_cons_printf ("%c 0x%" PFMT64x " %s",
								ref->type ? ref->type : ' ', ref->addr, desc);

						if (ref->type == R_ANAL_REF_TYPE_CALL) {
							RAnalOp aop;
							r_anal_op (core->anal, &aop, ref->addr, buf, sizeof(buf), R_ANAL_OP_MASK_BASIC);
							if (aop.type == R_ANAL_OP_TYPE_UCALL) {
								cmd_anal_ucall_ref (core, ref->addr);
							}
						}
						r_cons_newline ();
						free (desc_to_free);
					}
				}
			} else {
				if (input[1] == 'j') { // "axfj"
					r_cons_print ("[]\n");
				}
			}
			r_list_free (list);
		}
		break;
	case 'F': // "axF"
		find_refs (core, input + 1);
		break;
	case 'C': // "axC"
	case 'c': // "axc"
	case 'd': // "axd"
	case 's': // "axs"
	case ' ': // "ax "
		{
		char *ptr = strdup (r_str_trim_head ((char *)input + 1));
		int n = r_str_word_set0 (ptr);
		ut64 at = core->offset;
		ut64 addr = UT64_MAX;
		RAnalRefType reftype = r_anal_xrefs_type (input[0]);
		switch (n) {
		case 2: // get at
			at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
		/* fall through */
		case 1: // get addr
			addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			break;
		default:
			free (ptr);
			return false;
		}
		r_anal_xrefs_set (core->anal, at, addr, reftype);
		free (ptr);
		}
	   	break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg_ax);
		break;
	}

	return true;
}
static void cmd_anal_hint(RCore *core, const char *input) {
	switch (input[0]) {
	case '?':
		if (input[1]) {
			ut64 addr = r_num_math (core->num, input + 1);
			r_core_anal_hint_print (core->anal, addr, 0);
		} else {
			r_core_cmd_help (core, help_msg_ah);
		}
		break;
	case '.': // "ah."
		r_core_anal_hint_print (core->anal, core->offset, 0);
		break;
	case 'a': // "aha" set arch
		if (input[1]) {
			int i;
			char *ptr = strdup (input + 2);
			i = r_str_word_set0 (ptr);
			if (i == 2) {
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			}
			r_anal_hint_set_arch (core->anal, core->offset, r_str_word_get0 (ptr, 0));
			free (ptr);
		} else if (input[1] == '-') {
			r_anal_hint_unset_arch (core->anal, core->offset);
		} else {
			eprintf ("Missing argument\n");
		}
		break;
	case 'o': // "aho"
		if (input[1] == ' ') {
			const char *arg = r_str_trim_ro (input + 1);
			int type = r_anal_optype_from_string (arg);
			r_anal_hint_set_type (core->anal, core->offset, type);
		} else {
			eprintf ("Usage: aho [type] # can be mov, jmp, call, ...\n");
		}
		break;
	case 'b': // "ahb" set bits
		if (input[1]) {
			char *ptr = strdup (input + 2);
			int bits;
			int i = r_str_word_set0 (ptr);
			if (i == 2) {
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			}
			bits = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_anal_hint_set_bits (core->anal, core->offset, bits);
			free (ptr);
		}  else if (input[1] == '-') {
			r_anal_hint_unset_bits (core->anal, core->offset);
		} else {
			eprintf ("Missing argument\n");
		}
		break;
	case 'i': // "ahi"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_ahi);
		} else if (isdigit (input[1])) {
			r_anal_hint_set_nword (core->anal, core->offset, input[1] - '0');
			input++;
		} else if (input[1] == '-') { // "ahi-"
			r_anal_hint_set_immbase (core->anal, core->offset, 0);
		}
		if (input[1] == ' ') {
			// You can either specify immbase with letters, or numbers
			const int base =
				(input[2] == 's') ? 1 :
				(input[2] == 'b') ? 2 :
				(input[2] == 'p') ? 3 :
				(input[2] == 'o') ? 8 :
				(input[2] == 'd') ? 10 :
				(input[2] == 'h') ? 16 :
				(input[2] == 'i') ? 32 : // ip address
				(input[2] == 'S') ? 80 : // syscall
				(int) r_num_math (core->num, input + 1);
			r_anal_hint_set_immbase (core->anal, core->offset, base);
		} else if (input[1] != '?' && input[1] != '-') {
			eprintf ("|ERROR| Usage: ahi [base]\n");
		}
		break;
	case 'h': // "ahh"
		if (input[1] == '-') {
			r_anal_hint_unset_high (core->anal, core->offset);
		} else if (input[1] == ' ') {
			r_anal_hint_set_high (core->anal, r_num_math (core->num, input + 1));
		} else {
			r_anal_hint_set_high (core->anal, core->offset);
		}
		break;
	case 'c': // "ahc"
		if (input[1] == ' ') {
			r_anal_hint_set_jump (
				core->anal, core->offset,
				r_num_math (core->num, input + 1));
		} else if (input[1] == '-') {
			r_anal_hint_unset_jump (core->anal, core->offset);
		}
		break;
	case 'f': // "ahf"
		if (input[1] == ' ') {
			r_anal_hint_set_fail (
				core->anal, core->offset,
				r_num_math (core->num, input + 1));
		} else if (input[1] == '-') {
			r_anal_hint_unset_fail (core->anal, core->offset);
		}
		break;
	case 'F': // "ahF" set stackframe size
		if (input[1] == ' ') {
			r_anal_hint_set_stackframe (
				core->anal, core->offset,
				r_num_math (core->num, input + 1));
		} else if (input[1] == '-') {
			r_anal_hint_unset_stackframe (core->anal, core->offset);
		}
		break;
	case 's': // "ahs" set size (opcode length)
		if (input[1] == ' ') {
			r_anal_hint_set_size (core->anal, core->offset, atoi (input + 1));
		} else if (input[1] == '-') {
			r_anal_hint_unset_size (core->anal, core->offset);
		} else {
			eprintf ("Usage: ahs 16\n");
		}
		break;
	case 'S': // "ahS" set asm.syntax
		if (input[1] == ' ') {
			r_anal_hint_set_syntax (core->anal, core->offset, input + 2);
		} else if (input[1] == '-') {
			r_anal_hint_unset_syntax (core->anal, core->offset);
		} else {
			eprintf ("Usage: ahS att\n");
		}
		break;
	case 'd': // "ahd" set opcode string
		if (input[1] == ' ') {
			r_anal_hint_set_opcode (core->anal, core->offset, input + 2);
		} else if (input[1] == '-') {
			r_anal_hint_unset_opcode (core->anal, core->offset);
		} else {
			eprintf ("Usage: ahd popall\n");
		}
		break;
	case 'e': // "ahe" set ESIL string
		if (input[1] == ' ') {
			r_anal_hint_set_esil (core->anal, core->offset, input + 2);
		} else if (input[1] == '-') {
			r_anal_hint_unset_esil (core->anal, core->offset);
		} else {
			eprintf ("Usage: ahe r0,pc,=\n");
		}
		break;
#if 0
	case 'e': // set endian
		if (input[1] == ' ') {
			r_anal_hint_set_opcode (core->anal, core->offset, atoi (input + 1));
		} else if (input[1] == '-') {
			r_anal_hint_unset_opcode (core->anal, core->offset);
		}
		break;
#endif
	case 'p': // "ahp"
		if (input[1] == ' ') {
			r_anal_hint_set_pointer (core->anal, core->offset, r_num_math (core->num, input + 1));
		} else if (input[1] == '-') { // "ahp-"
			r_anal_hint_unset_pointer (core->anal, core->offset);
		}
		break;
	case 'r': // "ahr"
		if (input[1] == ' ') {
			r_anal_hint_set_ret (core->anal, core->offset, r_num_math (core->num, input + 1));
		} else if (input[1] == '-') { // "ahr-"
			r_anal_hint_unset_ret (core->anal, core->offset);
		}
	case '*': // "ah*"
	case 'j': // "ahj"
	case '\0': // "ah"
		if (input[0] && input[1] == ' ') {
			char *ptr = strdup (r_str_trim_ro (input + 2));
			r_str_word_set0 (ptr);
			ut64 addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_core_anal_hint_print (core->anal, addr, input[0]);
		} else {
			r_core_anal_hint_list (core->anal, input[0]);
		}
		break;
	case 'v': // "ahv"
		if (input[1] == ' ') {
			r_anal_hint_set_val (
				core->anal, core->offset,
				r_num_math (core->num, input + 1));
		} else if (input[1] == '-') {
			r_anal_hint_unset_val (core->anal, core->offset);
		}
		break;
	case '-': // "ah-"
		if (input[1]) {
			if (input[1] == '*') {
				r_anal_hint_clear (core->anal);
			} else {
				char *ptr = strdup (r_str_trim_ro (input + 1));
				ut64 addr;
				int size = 1;
				int i = r_str_word_set0 (ptr);
				if (i == 2) {
					size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				}
				const char *a0 = r_str_word_get0 (ptr, 0);
				if (a0 && *a0) {
					addr = r_num_math (core->num, a0);
				} else {
					addr = core->offset;
				}
				r_anal_hint_del (core->anal, addr, size);
				free (ptr);
			}
		} else {
			r_anal_hint_clear (core->anal);
		} break;
	case 't': // "aht"
		switch (input[1]) {
		case 's': { // "ahts"
			char *off = strdup (input + 2);
			r_str_trim (off);
			int toff = r_num_math (NULL, off);
			if (toff) {
				RList *typeoffs = r_type_get_by_offset (core->anal->sdb_types, toff);
				RListIter *iter;
				char *ty;
				r_list_foreach (typeoffs, iter, ty) {
					r_cons_printf ("%s\n", ty);
				}
				r_list_free (typeoffs);
			}
			free (off);
			break;
		}
		case ' ': {
			// r_anal_hint_set_opcode (core->anal, core->offset, input + 2);
			const char *off = NULL;
			char *type = strdup (r_str_trim_ro (input + 2));
			char *idx = strchr (type, ' ');
			if (idx) {
				*idx++ = 0;
				off = idx;
			}
			char *ptr = strchr (type, '=');
			ut64 offimm = 0;
			int i = 0;
			ut64 addr;

			if (ptr) {
				*ptr++ = 0;
				r_str_trim (ptr);
				if (ptr && *ptr) {
					addr = r_num_math (core->num, ptr);
				} else {
					eprintf ("address is unvalid\n");
					free (type);
					break;
				}
			} else {
				addr = core->offset;
			}
			r_str_trim (type);
			RAsmOp asmop;
			RAnalOp op = { 0 };
			ut8 code[128] = { 0 };
			(void)r_io_read_at (core->io, core->offset, code, sizeof (code));
			r_asm_set_pc (core->assembler, addr);
			(void)r_asm_disassemble (core->assembler, &asmop, code, core->blocksize);
			int ret = r_anal_op (core->anal, &op, core->offset, code, core->blocksize, R_ANAL_OP_MASK_VAL);
			if (ret >= 0) {
				// HACK: Just convert only the first imm seen
				for (i = 0; i < 3; i++) {
					if (op.src[i]) {
						if (op.src[i]->imm) {
							offimm = op.src[i]->imm;
						} else if (op.src[i]->delta) {
							offimm = op.src[i]->delta;
						}
					}
				}
				if (!offimm && op.dst) {
					if (op.dst->imm) {
						offimm = op.dst->imm;
					} else if (op.dst->delta) {
						offimm = op.dst->delta;
					}
				}
				if (offimm != 0) {
					if (off) {
						offimm += r_num_math (NULL, off);
					}
					// TODO: Allow to select from multiple choices
					RList *otypes = r_type_get_by_offset (core->anal->sdb_types, offimm);
					RListIter *iter;
					char *otype = NULL;
					r_list_foreach (otypes, iter, otype) {
						// TODO: I don't think we should silently error, it is confusing
						if (!strcmp (type, otype)) {
							//eprintf ("Adding type offset %s\n", type);
							r_type_link_offset (core->anal->sdb_types, type, addr);
							r_anal_hint_set_offset (core->anal, addr, otype);
							break;
						}
					}
					if (!otype) {
						eprintf ("wrong type for opcode offset\n");
					}
					r_list_free (otypes);
				}
			}
			r_anal_op_fini (&op);
			free (type);
		} break;
		case '?':
			r_core_cmd_help (core, help_msg_aht);
			break;
		}
	}
}

static void agraph_print_node_gml(RANode *n, void *user) {
	r_cons_printf ("  node [\n"
		"    id  %d\n"
		"    label  \"%s\"\n"
		"  ]\n", n->gnode->idx, n->title);
}

static void agraph_print_edge_gml(RANode *from, RANode *to, void *user) {
	r_cons_printf ("  edge [\n"
		"    source  %d\n"
		"    target  %d\n"
		"  ]\n", from->gnode->idx, to->gnode->idx
		);
}

static void agraph_print_node_dot(RANode *n, void *user) {
	char *label = strdup (n->body);
	//label = r_str_replace (label, "\n", "\\l", 1);
	if (!label || !*label) {
		r_cons_printf ("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
				n->title, n->title, n->title);
	} else {
		r_cons_printf ("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\\n%s\"]\n",
				n->title, n->title, n->title, label);
	}
	free (label);
}

static void agraph_print_node(RANode *n, void *user) {
	char *encbody, *cmd;
	int len = strlen (n->body);

	if (len > 0 && n->body[len - 1] == '\n') {
		len--;
	}
	encbody = r_base64_encode_dyn (n->body, len);
	cmd = r_str_newf ("agn \"%s\" base64:%s\n", n->title, encbody);
	r_cons_printf (cmd);
	free (cmd);
	free (encbody);
}

static char *getViewerPath() {
	int i;
	const char *viewers[] = {
#if __WINDOWS__
		"explorer",
#else
		"open",
		"geeqie",
		"gqview",
		"eog",
		"xdg-open",
#endif
		NULL
	};
	for (i = 0; viewers[i]; i++) {
		char *viewerPath = r_file_path (viewers[i]);
		if (viewerPath && strcmp (viewerPath, viewers[i])) {
			return viewerPath;
		}
		free (viewerPath);
	}
	return NULL;
}

static char* graph_cmd(RCore *core, char *r2_cmd, const char *save_path) {
	const char *dot = "dot";
	char *cmd = NULL;
	const char *ext = r_config_get (core->config, "graph.gv.format");
	char *dotPath = r_file_path (dot);
	if (!strcmp (dotPath, dot)) {
		free (dotPath);
		dot = "xdot";
		dotPath = r_file_path (dot);
		if (!strcmp (dotPath, dot)) {
			free (dotPath);
			return r_str_new ("agf");
		}
	}
	if (save_path && *save_path) {
		cmd = r_str_newf ("%s > a.dot;!%s -T%s -o%s a.dot;",
			r2_cmd, dot, ext, save_path);
	} else {
		char *viewer = getViewerPath();
		if (viewer) {
			cmd = r_str_newf ("%s > a.dot;!%s -T%s -oa.%s a.dot;!%s a.%s",
				r2_cmd, dot, ext, ext, viewer, ext);
			free (viewer);
		} else {
			eprintf ("Cannot find a valid picture viewer\n");
		}
	}
	free (dotPath);
	return cmd;
}

static void agraph_print_edge_dot(RANode *from, RANode *to, void *user) {
	r_cons_printf ("\"%s\" -> \"%s\"\n", from->title, to->title);
}

static void agraph_print_edge(RANode *from, RANode *to, void *user) {
	r_cons_printf ("age \"%s\" \"%s\"\n", from->title, to->title);
}

static void cmd_agraph_node(RCore *core, const char *input) {
	switch (*input) {
	case ' ': { // "agn"
		char *newbody = NULL;
		char **args, *body;
		int n_args, B_LEN = strlen ("base64:");
		int color = -1;
		input++;
		args = r_str_argv (input, &n_args);
		if (n_args < 1 || n_args > 3) {
			r_cons_printf ("Wrong arguments\n");
			r_str_argv_free (args);
			break;
		}
		// strdup cause there is double free in r_str_argv_free due to a realloc call
		if (n_args > 1) {
			body = strdup (args[1]);
			if (strncmp (body, "base64:", B_LEN) == 0) {
				body = r_str_replace (body, "\\n", "", true);
				newbody = (char *)r_base64_decode_dyn (body + B_LEN, -1);
				free (body);
				if (!newbody) {
					eprintf ("Cannot allocate buffer\n");
					r_str_argv_free (args);
					break;
				}
				body = newbody;
			}
			body = r_str_append (body, "\n");
			if (n_args > 2) {
			        color = atoi(args[2]);
			}
		} else {
			body = strdup ("");
		}
		r_agraph_add_node_with_color (core->graph, args[0], body, color);
		r_str_argv_free (args);
		free (body);
		//free newbody it's not necessary since r_str_append reallocate the space
		break;
	}
	case '-': { // "agn-"
		char **args;
		int n_args;

		input++;
		args = r_str_argv (input, &n_args);
		if (n_args != 1) {
			r_cons_printf ("Wrong arguments\n");
			r_str_argv_free (args);
			break;
		}
		r_agraph_del_node (core->graph, args[0]);
		r_str_argv_free (args);
		break;
	}
	case '?':
	default:
		r_core_cmd_help (core, help_msg_agn);
		break;
	}
}

static void cmd_agraph_edge(RCore *core, const char *input) {
	switch (*input) {
	case ' ': // "age"
	case '-': { // "age-"
		RANode *u, *v;
		char **args;
		int n_args;

		args = r_str_argv (input + 1, &n_args);
		if (n_args != 2) {
			r_cons_printf ("Wrong arguments\n");
			r_str_argv_free (args);
			break;
		}

		u = r_agraph_get_node (core->graph, args[0]);
		v = r_agraph_get_node (core->graph, args[1]);
		if (!u || !v) {
			if (!u) {
				r_cons_printf ("Node %s not found!\n", args[0]);
			} else {
				r_cons_printf ("Node %s not found!\n", args[1]);
			}
			r_str_argv_free (args);
			break;
		}
		if (*input == ' ') {
			r_agraph_add_edge (core->graph, u, v);
		} else {
			r_agraph_del_edge (core->graph, u, v);
		}
		r_str_argv_free (args);
		break;
	}
	case '?':
	default:
		r_core_cmd_help (core, help_msg_age);
		break;
	}
}

R_API void r_core_agraph_print (RCore *core, int use_utf, const char *input) {
	if (use_utf != -1) {
		r_config_set_i (core->config, "scr.utf8", use_utf);
	}
	switch (*input) {
	case 0:
		core->graph->can->linemode = r_config_get_i (core->config, "graph.linemode");
		core->graph->can->color = r_config_get_i (core->config, "scr.color");
		r_agraph_set_title (core->graph,
			r_config_get (core->config, "graph.title"));
		r_agraph_print (core->graph);
		break;
	case 't':{ // "aggt" - tiny graph
		core->graph->is_tiny = true;
		int e = r_config_get_i (core->config, "graph.edges");
		r_config_set_i (core->config, "graph.edges", 0);
		r_core_visual_graph (core, core->graph, NULL, false);
		r_config_set_i (core->config, "graph.edges", e);
		core->graph->is_tiny = false;
		break;
		}
	case 'k': // "aggk"
	{
		Sdb *db = r_agraph_get_sdb (core->graph);
		char *o = sdb_querys (db, "null", 0, "*");
		r_cons_print (o);
		free (o);
		break;
	}
	case 'v': // "aggv"
	case 'i': // "aggi" - open current core->graph in interactive mode
	{
		RANode *ran = r_agraph_get_first_node (core->graph);
		if (ran) {
			ut64 oseek = core->offset;
			r_agraph_set_title (core->graph, r_config_get (core->config, "graph.title"));
			r_agraph_set_curnode (core->graph, ran);
			core->graph->force_update_seek = true;
			core->graph->need_set_layout = true;
			core->graph->layout = r_config_get_i (core->config, "graph.layout");
			int ov = r_cons_is_interactive ();
			core->graph->need_update_dim = true;
			int update_seek = r_core_visual_graph (core, core->graph, NULL, true);
			r_config_set_i (core->config, "scr.interactive", ov);
			r_cons_show_cursor (true);
			r_cons_enable_mouse (false);
			if (update_seek != -1) {
				r_core_seek (core, oseek, 0);
			}
		} else {
			eprintf ("This graph contains no nodes\n");
		}
		break;
	}
	case 'd': { // "aggd" - dot format
		const char *font = r_config_get (core->config, "graph.font");
		r_cons_printf ("digraph code {\nrankdir=LR;\noutputorder=edgesfirst\ngraph [bgcolor=azure];\n"
			"edge [arrowhead=normal, color=\"#3030c0\" style=bold weight=2];\n"
			"node [fillcolor=white, style=filled shape=box "
			"fontname=\"%s\" fontsize=\"8\"];\n", font);
		r_agraph_foreach (core->graph, agraph_print_node_dot, NULL);
		r_agraph_foreach_edge (core->graph, agraph_print_edge_dot, NULL);
		r_cons_printf ("}\n");
		break;
		}
	case '*': // "agg*" -
		r_agraph_foreach (core->graph, agraph_print_node, NULL);
		r_agraph_foreach_edge (core->graph, agraph_print_edge, NULL);
		break;
	case 'J':
	case 'j': {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_k (pj, "nodes");
		pj_a (pj);
		r_agraph_print_json (core->graph, pj);
		pj_end (pj);
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	} break;
	case 'g':
		r_cons_printf ("graph\n[\n" "hierarchic 1\n" "label \"\"\n" "directed 1\n");
		r_agraph_foreach (core->graph, agraph_print_node_gml, NULL);
		r_agraph_foreach_edge (core->graph, agraph_print_edge_gml, NULL);
		r_cons_print ("]\n");
		break;
	case 'w':{ // "aggw"
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "=H /graph/");
		} else {
			const char *filename = r_str_trim_ro (input + 1);
			char *cmd = graph_cmd (core, "aggd", filename);
			if (cmd && *cmd) {
				if (input[1] == ' ') {
					r_cons_printf ("Saving to file '%s'...\n", filename);
					r_cons_flush ();
				}
				r_core_cmd0 (core, cmd);
			}
			free (cmd);
		}
		break;
	}
	default:
		eprintf ("Usage: see ag?\n");
	}
}

static void cmd_anal_graph(RCore *core, const char *input) {
	core->graph->show_node_titles = r_config_get_i (core->config, "graph.ntitles");
	r_cons_enable_highlight (false);
	switch (input[0]) {
	case 'f': // "agf"
		switch (input[1]) {
		case 0: // "agf"
			r_core_visual_graph (core, NULL, NULL, false);
			break;
		case ' ':{ // "agf "
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			r_core_visual_graph (core, NULL, fcn, false);
			break;
			}
		case 'v': // "agfv"
			eprintf ("\rRendering graph...");
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_ROOT);
			if (fcn) {
				r_core_visual_graph (core, NULL, fcn, 1);
			}
			r_cons_enable_mouse (false);
			r_cons_show_cursor (true);
			break;
		case 't': { // "agft" - tiny graph
			int e = r_config_get_i (core->config, "graph.edges");
			r_config_set_i (core->config, "graph.edges", 0);
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			r_core_visual_graph (core, NULL, fcn, 2);
			r_config_set_i (core->config, "graph.edges", e);
			break;
			}
		case 'd': // "agfd"
			if (input[2] == 'm') {
				r_core_anal_graph (core, r_num_math (core->num, input + 3),
					R_CORE_ANAL_GRAPHLINES);
			} else {
				r_core_anal_graph (core, r_num_math (core->num, input + 2),
					R_CORE_ANAL_GRAPHBODY);
			}
			break;
		case 'j': // "agfj"
			r_core_anal_graph (core, r_num_math (core->num, input + 2), R_CORE_ANAL_JSON);
			break;
		case 'J': {// "agfJ"
			// Honor asm.graph=false in json as well
			RConfigHold *hc = r_config_hold_new (core->config);
			r_config_hold_i (hc, "asm.offset", NULL);
			const bool o_graph_offset = r_config_get_i (core->config, "graph.offset");
			r_config_set_i (core->config, "asm.offset", o_graph_offset);
			r_core_anal_graph (core, r_num_math (core->num, input + 2),
				R_CORE_ANAL_JSON | R_CORE_ANAL_JSON_FORMAT_DISASM);
			r_config_hold_restore (hc);
			r_config_hold_free (hc);
			break;
			}
		case 'g':{ // "agfg"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			r_core_print_bb_gml (core, fcn);
			break;
			}
		case 'k':{ // "agfk"
			r_core_cmdf (core, "ag-; .agf* @ %"PFMT64u"; aggk", core->offset);
			break;
			}
		case '*':{// "agf*"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			r_core_print_bb_custom (core, fcn);
			break;
			}
		case 'w': // "agfw"
			if (r_config_get_i (core->config, "graph.web")) {
				r_core_cmd0 (core, "=H /graph/");
			} else {
				char *cmdargs = r_str_newf ("agfd @ 0x%"PFMT64x, core->offset);
				char *cmd = graph_cmd (core, cmdargs, input + 2);
				if (cmd && *cmd) {
					if (*(input + 2)) {
						r_cons_printf ("Saving to file %s ...\n", input + 2);
						r_cons_flush ();
					}
					r_core_cmd0 (core, cmd);
				}
				free (cmd);
				free (cmdargs);
			}
			break;
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case '-': // "ag-"
		r_agraph_reset (core->graph);
		break;
	case 'n': // "agn"
		cmd_agraph_node (core, input + 1);
		break;
	case 'e': // "age"
		cmd_agraph_edge (core, input + 1);
		break;
	case 'g': // "agg"
		r_core_agraph_print (core, -1, input + 1);
		break;
	case 's': // "ags"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), 0);
		break;
	case 'C': // "agC"
		switch (input[1]) {
		case 'v':
		case 't':
		case 'k':
		case 'w':
		case ' ':
		case 0: {
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agC*; agg%s;", input + 1);
			core->graph->is_callgraph = false;
			break;
			}
		case 'J':
		case 'j':
			r_core_anal_callgraph (core, UT64_MAX, R_GRAPH_FORMAT_JSON);
			break;
		case 'g':
			r_core_anal_callgraph (core, UT64_MAX, R_GRAPH_FORMAT_GML);
			break;
		case 'd':
			r_core_anal_callgraph (core, UT64_MAX, R_GRAPH_FORMAT_DOT);
			break;
		case '*':
			r_core_anal_callgraph (core, UT64_MAX, R_GRAPH_FORMAT_CMD);
			break;
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'r': // "agr" references graph
		switch (input[1]) {
		case 'v':
		case 't':
		case 'd':
		case 'J':
		case 'j':
		case 'g':
		case 'k':
		case 'w':
		case ' ': {
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agr* @ %"PFMT64u"; agg%s;", core->offset, input + 1);
			core->graph->is_callgraph = false;
			break;
			}
		case '*': {
			r_core_anal_coderefs (core, core->offset);
			}
			break;
		case 0:
			r_core_cmd0 (core, "ag-; .agr* $$; agg;");
			break;
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'R': // "agR" global refs
		switch (input[1]) {
		case 'v':
		case 't':
		case 'd':
		case 'J':
		case 'j':
		case 'g':
		case 'k':
		case 'w':
		case ' ':
		case 0: {
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agR*; agg%s;", input + 1);
			core->graph->is_callgraph = false;
			break;
			}
		case '*': {
			ut64 from = r_config_get_i (core->config, "graph.from");
			ut64 to = r_config_get_i (core->config, "graph.to");
			RListIter *it;
			RAnalFunction *fcn;
			r_list_foreach (core->anal->fcns, it, fcn) {
				if ((from == UT64_MAX && to == UT64_MAX) || R_BETWEEN (from, fcn->addr, to)) {
					r_core_anal_coderefs (core, fcn->addr);
				}
			}
			break;
			}
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'x': // "agx" cross refs
		switch (input[1]) {
		case 'v':
		case 't':
		case 'd':
		case 'J':
		case 'j':
		case 'g':
		case 'k':
		case 'w':
		case ' ': {
			r_core_cmdf (core, "ag-; .agx* @ %"PFMT64u"; agg%s;", core->offset, input + 1);
			break;
			}
		case '*': {
			r_core_anal_codexrefs (core, core->offset);
			}
			break;
		case 0:
			r_core_cmd0 (core, "ag-; .agx* $$; agg;");
			break;
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'i': // "agi" import graph
		switch (input[1]) {
		case 'v':
		case 't':
		case 'd':
		case 'J':
		case 'j':
		case 'g':
		case 'k':
		case 'w':
		case ' ':
		case 0:
			r_core_cmdf (core, "ag-; .agi*; agg%s;", input + 1);
			break;
		case '*':
			r_core_anal_importxrefs (core);
			break;
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'c': // "agc"
		switch (input[1]) {
		case 'v':
		case 't':
		case 'k':
		case 'w':
		case ' ': {
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agc* @ %"PFMT64u"; agg%s;", core->offset, input + 1);
			core->graph->is_callgraph = false;
			break;
			}
		case 0:
			core->graph->is_callgraph = true;
			r_core_cmd0 (core, "ag-; .agc* $$; agg;");
			core->graph->is_callgraph = false;
			break;
		case 'g': {
			r_core_anal_callgraph (core, core->offset, R_GRAPH_FORMAT_GMLFCN);
			break;
		}
		case 'd': {
			r_core_anal_callgraph (core, core->offset, R_GRAPH_FORMAT_DOT);
			break;
		}
		case 'J':
		case 'j': {
			r_core_anal_callgraph (core, core->offset, R_GRAPH_FORMAT_JSON);
			break;
		}
		case '*': {
			r_core_anal_callgraph (core, core->offset, R_GRAPH_FORMAT_CMD);
			break;
		}
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'j': // "agj" alias for agfj
		r_core_cmdf (core, "agfj%s", input + 1);
		break;
	case 'J': // "agJ" alias for agfJ
		r_core_cmdf (core, "agfJ%s", input + 1);
		break;
	case 'k': // "agk" alias for agfk
		r_core_cmdf (core, "agfk%s", input + 1);
		break;
	case 'l': // "agl"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), R_CORE_ANAL_GRAPHLINES);
		break;
	case 'a': // "aga"
		switch (input[1]) {
		case 'v':
		case 't':
		case 'k':
		case 'w':
		case 'g':
		case 'j':
		case 'J':
		case 'd':
		case ' ': {
			r_core_cmdf (core, "ag-; .aga* @ %"PFMT64u"; agg%s;", core->offset, input + 1);
			break;
			}
		case 0:
			r_core_cmd0 (core, "ag-; .aga* $$; agg;");
			break;
		case '*': {
			r_core_anal_datarefs (core, core->offset);
			break;
			}
		default:
			 eprintf ("Usage: see ag?\n");
			 break;
		}
		break;
	case 'A': // "agA" global data refs
		switch (input[1]) {
		case 'v':
		case 't':
		case 'd':
		case 'J':
		case 'j':
		case 'g':
		case 'k':
		case 'w':
		case ' ':
		case 0: {
			r_core_cmdf (core, "ag-; .agA*; agg%c;", input[1]);
			break;
			}
		case '*': {
			ut64 from = r_config_get_i (core->config, "graph.from");
			ut64 to = r_config_get_i (core->config, "graph.to");
			RListIter *it;
			RAnalFunction *fcn;
			r_list_foreach (core->anal->fcns, it, fcn) {
				if ((from == UT64_MAX && to == UT64_MAX) || R_BETWEEN (from, fcn->addr, to)) {
					r_core_anal_datarefs (core, fcn->addr);
				}
			}
			break;
			}
		default:
			eprintf ("Usage: see ag?\n");
			break;
		}
		break;
	case 'd': {// "agd"
	        int diff_opt = R_CORE_ANAL_GRAPHBODY | R_CORE_ANAL_GRAPHDIFF;
                switch (input[1]) {
                        case 'j': {
                                ut64 addr = input[2] ? r_num_math (core->num, input + 2) : core->offset;
                                r_core_gdiff_fcn (core, addr, core->offset);
                                r_core_anal_graph (core, addr, diff_opt | R_CORE_ANAL_JSON);
                                break;
                        }
                        case 'J': {
                                ut64 addr = input[2] ? r_num_math (core->num, input + 2) : core->offset;
                                r_core_gdiff_fcn (core, addr, core->offset);
                                r_core_anal_graph (core, addr, diff_opt | R_CORE_ANAL_JSON | R_CORE_ANAL_JSON_FORMAT_DISASM);
                                break;
                        }
                        case '*': {
                                ut64 addr = input[2] ? r_num_math (core->num, input + 2) : core->offset;
                                r_core_gdiff_fcn (core, addr, core->offset);
                                r_core_anal_graph (core, addr, diff_opt | R_CORE_ANAL_STAR);
                                break;
                        }
                        case ' ':
                        case 0:
                        case 't':
                        case 'k':
                        case 'v':
                        case 'g': {
                                ut64 addr = input[2] ? r_num_math (core->num, input + 2) : core->offset;
                                r_core_cmdf (core, "ag-; .agd* @ %"PFMT64u"; agg%s;", addr, input + 1);
                                break;
                        }
                        case 'd': {
                                ut64 addr = input[2] ? r_num_math (core->num, input + 2) : core->offset;
                                r_core_gdiff_fcn (core, addr, core->offset);
                                r_core_anal_graph (core, addr, diff_opt);
                                break;
                        }
                        case 'w': {
                                char *cmdargs = r_str_newf ("agdd 0x%"PFMT64x, core->offset);
                                char *cmd = graph_cmd (core, cmdargs, input + 2);
                                if (cmd && *cmd) {
                                        r_core_cmd0(core, cmd);
                                }
                                free(cmd);
                                free(cmdargs);
                                break;
                        }
                }
                break;
        }
	case 'v': // "agv" alias for "agfv"
		r_core_cmdf (core, "agfv%s", input + 1);
		break;
	case 'w':// "agw"
		if (r_config_get_i (core->config, "graph.web")) {
			r_core_cmd0 (core, "=H /graph/");
		} else {
			char *cmdargs = r_str_newf ("agfd @ 0x%"PFMT64x, core->offset);
			char *cmd = graph_cmd (core, cmdargs, input + 1);
			if (cmd && *cmd) {
				if (input[1]) {
					r_cons_printf ("Saving to file %s ...\n", input + 1);
					r_cons_flush ();
				}
				r_core_cmd0 (core, cmd);
			}
			free (cmd);
			free (cmdargs);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_ag);
		break;
	}
}

R_API int r_core_anal_refs(RCore *core, const char *input) {
	int cfg_debug = r_config_get_i (core->config, "cfg.debug");
	ut64 from, to;
	int rad;
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_aar);
		return 0;
	}

	if (*input == 'j' || *input == '*') {
		rad = *input;
		input++;
	} else {
		rad = 0;
	}

	from = to = 0;
	char *ptr = r_str_trim_head (strdup (input));
	int n = r_str_word_set0 (ptr);
	if (!n) {
		// get boundaries of current memory map, section or io map
		if (cfg_debug) {
			RDebugMap *map = r_debug_map_get (core->dbg, core->offset);
			if (map) {
				from = map->addr;
				to = map->addr_end;
			}
		} else {
			RList *list = r_core_get_boundaries_prot (core, R_PERM_X, NULL, "anal");
			RListIter *iter;
			RIOMap* map;
			if (!list) {
				return 0;
			}
			if (rad == 'j') {
				r_cons_printf ("{");
			}
			int nth = 0;
			r_list_foreach (list, iter, map) {
				from = map->itv.addr;
				to = r_itv_end (map->itv);
				if (r_cons_is_breaked ()) {
					break;
				}
				if (!from && !to) {
					eprintf ("Cannot determine xref search boundaries\n");
				} else if (to - from > UT32_MAX) {
					eprintf ("Skipping huge range\n");
				} else {
					if (rad == 'j') {
						r_cons_printf ("%s\"mapid\":\"%d\",\"refs\":{", nth? ",": "", map->id);
					}
					r_core_anal_search_xrefs (core, from, to, rad);
					if (rad == 'j') {
						r_cons_printf ("}");
					}
					nth++;
				}
			}
			if (rad == 'j') {
				r_cons_printf ("}\n");
			}
			free (ptr);
			r_list_free (list);
			return 1;
		}
	} else if (n == 1) {
		from = core->offset;
		to = core->offset + r_num_math (core->num, r_str_word_get0 (ptr, 0));
	} else {
		eprintf ("Invalid number of arguments\n");
	}
	free (ptr);

	if (from == UT64_MAX && to == UT64_MAX) {
		return false;
	}
	if (!from && !to) {
		return false;
	}
	if (to - from > r_io_size (core->io)) {
		return false;
	}
	if (rad == 'j') {
		r_cons_printf ("{");
	}
	bool res = r_core_anal_search_xrefs (core, from, to, rad);
	if (rad == 'j') {
		r_cons_printf ("}\n");
	}
	return res;
}

static const char *oldstr = NULL;

static int compute_coverage(RCore *core) {
	RListIter *iter;
	SdbListIter *iter2;
	RAnalFunction *fcn;
	RIOMap *map;
	int cov = 0;
	cov += r_meta_get_size(core->anal, R_META_TYPE_DATA);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		ls_foreach (core->io->maps, iter2, map) {
			if (map->perm & R_PERM_X) {
				ut64 section_end = map->itv.addr + map->itv.size;
				ut64 s = r_anal_fcn_realsize (fcn);
				if (fcn->addr >= map->itv.addr && (fcn->addr + s) < section_end) {
					cov += s;
				}
			}
		}
	}
	return cov;
}

static int compute_code (RCore* core) {
	int code = 0;
	SdbListIter *iter;
	RIOMap *map;
	ls_foreach (core->io->maps, iter, map) {
		if (map->perm & R_PERM_X) {
			code += map->itv.size;
		}
	}
	return code;
}

static int compute_calls(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	RList *xrefs;
	int cov = 0;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		xrefs = r_anal_fcn_get_xrefs (core->anal, fcn);
		if (xrefs) {
			cov += r_list_length (xrefs);
			r_list_free (xrefs);
			xrefs = NULL;
		}
	}
	return cov;
}

static void r_core_anal_info (RCore *core, const char *input) {
	int fcns = r_list_length (core->anal->fcns);
	int strs = r_flag_count (core->flags, "str.*");
	int syms = r_flag_count (core->flags, "sym.*");
	int imps = r_flag_count (core->flags, "sym.imp.*");
	int code = compute_code (core);
	int covr = compute_coverage (core);
	int call = compute_calls (core);
	int xrfs = r_anal_xrefs_count (core->anal);
	int cvpc = (code > 0)? (covr * 100 / code): 0;
	if (*input == 'j') {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ki (pj, "fcns", fcns);
		pj_ki (pj, "xrefs", xrfs);
		pj_ki (pj, "calls", call);
		pj_ki (pj, "strings", strs);
		pj_ki (pj, "symbols", syms);
		pj_ki (pj, "imports", imps);
		pj_ki (pj, "covrage", covr);
		pj_ki (pj, "codesz", code);
		pj_ki (pj, "percent", cvpc);
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	} else {
		r_cons_printf ("fcns    %d\n", fcns);
		r_cons_printf ("xrefs   %d\n", xrfs);
		r_cons_printf ("calls   %d\n", call);
		r_cons_printf ("strings %d\n", strs);
		r_cons_printf ("symbols %d\n", syms);
		r_cons_printf ("imports %d\n", imps);
		r_cons_printf ("covrage %d\n", covr);
		r_cons_printf ("codesz  %d\n", code);
		r_cons_printf ("percent %d%%\n", cvpc);
	}
}

static void cmd_anal_aad(RCore *core, const char *input) {
	RListIter *iter;
	RAnalRef *ref;
	RList *list = r_list_newf (NULL);
	r_anal_xrefs_from (core->anal, list, "xref", R_ANAL_REF_TYPE_DATA, UT64_MAX);
	r_list_foreach (list, iter, ref) {
		if (r_io_is_valid_offset (core->io, ref->addr, false)) {
			r_core_anal_fcn (core, ref->at, ref->addr, R_ANAL_REF_TYPE_NULL, 1);
		}
	}
	r_list_free (list);
}

static bool archIsThumbable(RCore *core) {
	RAsm *as = core ? core->assembler : NULL;
	if (as && as->cur && as->bits <= 32 && as->cur->name) {
		return strstr (as->cur->name, "arm");
	}
	return false;
}

static void _CbInRangeAav(RCore *core, ut64 from, ut64 to, int vsize, int count, void *user) {
	bool asterisk = user != NULL;
	int arch_align = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
	bool vinfun = r_config_get_i (core->config, "anal.vinfun");
	int searchAlign = r_config_get_i (core->config, "search.align");
	int align = (searchAlign > 0)? searchAlign: arch_align;
	if (align > 1) {
		if ((from % align) || (to % align)) {
			bool itsFine = false;
			if (archIsThumbable (core)) {
				if ((from & 1) || (to & 1)) {
					itsFine = true;
				}
			}
			if (!itsFine) {
				return;
			}
			if (core->anal->verbose) {
				eprintf ("Warning: aav: false positive in 0x%08"PFMT64x"\n", from);
			}
		}
	}
	if (!vinfun) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, from, -1);
		if (fcn) {
			return;
		}
	}
	if (asterisk) {
		r_cons_printf ("ax 0x%"PFMT64x " 0x%"PFMT64x "\n", to, from);
		r_cons_printf ("Cd %d @ 0x%"PFMT64x "\n", vsize, from);
		r_cons_printf ("f+ aav.0x%08"PFMT64x "= 0x%08"PFMT64x, to, to);
	} else {
		r_anal_xrefs_set (core->anal, from, to, R_ANAL_REF_TYPE_NULL);
		// r_meta_add (core->anal, 'd', from, from + vsize, NULL);
		r_core_cmdf (core, "Cd %d @ 0x%"PFMT64x "\n", vsize, from);
		if (!r_flag_get_at (core->flags, to, false)) {
			char *name = r_str_newf ("aav.0x%08"PFMT64x, to);
			r_flag_set (core->flags, name, to, vsize);
			free (name);
		}
	}
}

static void cmd_anal_aav(RCore *core, const char *input) {
#define seti(x,y) r_config_set_i(core->config, x, y);
#define geti(x) r_config_get_i(core->config, x);
	r_return_if_fail (*input == 'v');
	ut64 o_align = geti ("search.align");
	const char *analin =  r_config_get (core->config, "anal.in");
	char *tmp = strdup (analin);
	bool asterisk = strchr (input, '*');
	bool is_debug = r_config_get_i (core->config, "cfg.debug");
	int archAlign = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
	seti ("search.align", archAlign);
	r_config_set (core->config, "anal.in", "io.maps.x");
	oldstr = r_print_rowlog (core->print, "Finding xrefs in noncode section with anal.in=io.maps");
	r_print_rowlog_done (core->print, oldstr);

	int vsize = 4; // 32bit dword
	if (core->assembler->bits == 64) {
		vsize = 8;
	}

	// body
	oldstr = r_print_rowlog (core->print, "Analyze value pointers (aav)");
	r_print_rowlog_done (core->print, oldstr);
	r_cons_break_push (NULL, NULL);
	if (is_debug) {
		RList *list = r_core_get_boundaries_prot (core, 0, "dbg.map", "anal");
		RListIter *iter;
		RIOMap *map;
		if (!list) {
			goto beach;
		}
		r_list_foreach (list, iter, map) {
			if (r_cons_is_breaked ()) {
				break;
			}
			oldstr = r_print_rowlog (core->print, sdb_fmt ("from 0x%"PFMT64x" to 0x%"PFMT64x" (aav)", map->itv.addr, r_itv_end (map->itv)));
			r_print_rowlog_done (core->print, oldstr);
			(void)r_core_search_value_in_range (core, map->itv,
				map->itv.addr, r_itv_end (map->itv), vsize, _CbInRangeAav, (void *)asterisk);
		}
		r_list_free (list);
	} else {
		RList *list = r_core_get_boundaries_prot (core, 0, NULL, "anal");
		if (!list) {
			goto beach;
		}
		RListIter *iter, *iter2;
		RIOMap *map, *map2;
		ut64 from = UT64_MAX;
		ut64 to = UT64_MAX;
		// find values pointing to non-executable regions
		r_list_foreach (list, iter2, map2) {
			if (r_cons_is_breaked ()) {
				break;
			}
			//TODO: Reduce multiple hits for same addr
			from = r_itv_begin (map2->itv);
			to = r_itv_end (map2->itv);
			oldstr = r_print_rowlog (core->print, sdb_fmt ("Value from 0x%08"PFMT64x " to 0x%08" PFMT64x " (aav)", from, to));
			r_print_rowlog_done (core->print, oldstr);
			r_list_foreach (list, iter, map) {
				ut64 begin = map->itv.addr;
				ut64 end = r_itv_end (map->itv);
				if (r_cons_is_breaked ()) {
					break;
				}
				if (end - begin > UT32_MAX) {
					oldstr = r_print_rowlog (core->print, "Skipping huge range");
					r_print_rowlog_done (core->print, oldstr);
					continue;
				}
				oldstr = r_print_rowlog (core->print, sdb_fmt ("0x%08"PFMT64x"-0x%08"PFMT64x" in 0x%"PFMT64x"-0x%"PFMT64x" (aav)", from, to, begin, end));
				r_print_rowlog_done (core->print, oldstr);
				(void)r_core_search_value_in_range (core, map->itv, from, to, vsize, _CbInRangeAav, (void *)asterisk);
				}
		}
		r_list_free (list);
	}
beach:
	r_cons_break_pop ();
	// end
	r_config_set (core->config, "anal.in", tmp);
	free (tmp);
	seti ("search.align", o_align);
}

static void cmd_anal_abt(RCore *core, const char *input) {
	switch (*input) {
	case 'e':
		{
		int n = 1;
		char *p = strchr (input + 1, ' ');
		if (!p) {
			eprintf ("Usage: abte [addr] # emulate from begining of function to the given address.\n");
			return;
		}
		ut64 addr = r_num_math (core->num, p + 1);
		RList *paths = r_core_anal_graph_to (core, addr, n);
		if (paths) {
			RAnalBlock *bb;
			RList *path;
			RListIter *pathi;
			RListIter *bbi;
			r_cons_printf ("f orip=`dr?PC`\n");
			r_list_foreach (paths, pathi, path) {
				r_list_foreach (path, bbi, bb) {
					r_cons_printf ("# 0x%08" PFMT64x "\n", bb->addr);
					if (addr >= bb->addr && addr < bb->addr + bb->size) {
						r_cons_printf ("aepc 0x%08"PFMT64x"\n", bb->addr);
						r_cons_printf ("aesou 0x%08"PFMT64x"\n", addr);
					} else {
						r_cons_printf ("aepc 0x%08"PFMT64x"\n", bb->addr);
						r_cons_printf ("aesou 0x%08"PFMT64x"\n", bb->addr + bb->size);
					}
				}
				r_cons_newline ();
				r_list_purge (path);
				free (path);
			}
			r_list_purge (paths);
			r_cons_printf ("aepc orip\n");
			free (paths);
		}
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_abt);
		break;
	case 'j': {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		ut64 addr = core->offset;
		char *p;
		int n = 1;
		input++;
		if (*input) {
			char *tmp = strdup (input);
			p = strchr (tmp + 1, ' ');
			if (p) {
				*p++ = '\0';
				n = *p? r_num_math (core->num, p): 1;
			}
			addr = r_num_math (core->num, tmp + 1);
			free (tmp);
		}
		RList *paths = r_core_anal_graph_to (core, addr, n);
		if (paths) {
			RAnalBlock *bb;
			RList *path;
			RListIter *pathi;
			RListIter *bbi;
			pj_a (pj);
			r_list_foreach (paths, pathi, path) {
				pj_a (pj);
				r_list_foreach (path, bbi, bb) {
					pj_n (pj, bb->addr);
				}
				pj_end (pj);
				r_list_purge (path);
				free (path);
			}
			pj_end (pj);
			r_cons_println (pj_string (pj));
			r_list_purge (paths);
			free (paths);
		}
		pj_free (pj);
	}
	break;
	case ' ': {
		ut64 addr;
		char *p;
		int n = 1;
		p = strchr (input + 1, ' ');
		if (p) {
			*p = '\0';
			n = *(++p)? r_num_math (core->num, p): 1;
		}
		addr = r_num_math (core->num, input + 1);
		RList *paths = r_core_anal_graph_to (core, addr, n);
		if (paths) {
			RAnalBlock *bb;
			RList *path;
			RListIter *pathi;
			RListIter *bbi;
			r_list_foreach (paths, pathi, path) {
				r_list_foreach (path, bbi, bb) {
					r_cons_printf ("0x%08" PFMT64x "\n", bb->addr);
				}
				r_cons_newline ();
				r_list_purge (path);
				free (path);
			}
			r_list_purge (paths);
			free (paths);
		}
	}
	case '\0':
		break;
	}
}

static bool is_unknown_file(RCore *core) {
	if (core->bin->cur && core->bin->cur->o) {
		return (r_list_empty (core->bin->cur->o->sections));
	}
	return true;
}

static int cmd_anal_all(RCore *core, const char *input) {
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_aa);
		break;
	case 'b': // "aab"
		cmd_anal_blocks (core, input + 1);
		break;
	case 'f':
		if (input[1] == 'e') {  // "aafe"
			r_core_cmd0 (core, "aef@@f");
		} else if (input[1] == 'r') {
			ut64 cur = core->offset;
			bool hasnext = r_config_get_i (core->config, "anal.hasnext");
			RListIter *iter;
			RIOMap *map;
			RList *list = r_core_get_boundaries_prot (core, R_PERM_X, NULL, "anal");
			if (!list) {
				break;
			}
			r_list_foreach (list, iter, map) {
				r_core_seek (core, map->itv.addr, 1);
				r_config_set_i (core->config, "anal.hasnext", 1);
				r_core_cmd0 (core, "afr");
				r_config_set_i (core->config, "anal.hasnext", hasnext);
			}
			r_list_free (list);
			r_core_seek (core, cur, 1);
		} else if (input[1] == 't') { // "aaft"
			cmd_anal_aaft (core);
		} else if (input[1] == 0) { // "aaf"
			const bool analHasnext = r_config_get_i (core->config, "anal.hasnext");
			r_config_set_i (core->config, "anal.hasnext", true);
			r_core_cmd0 (core, "afr@@c:isq");
			r_config_set_i (core->config, "anal.hasnext", analHasnext);
		} else {
			r_cons_printf ("Usage: aaf[e|r|t] - analyze all functions again\n");
			r_cons_printf (" aafe = aef@@f\n");
			r_cons_printf ("aafr [len] = analyze all consecutive functions in section\n");
			r_cons_printf (" aaft = recursive type matching in all functions\n");
			r_cons_printf (" aaf  = afr@@c:isq\n");
		}
		break;
	case 'c': // "aac"
		switch (input[1]) {
		case '*': // "aac*"
			cmd_anal_calls (core, input + 1, true, false);
			break;
		case 'i': // "aaci"
			cmd_anal_calls (core, input + 1, input[2] == '*', true);
			break;
		case '?': // "aac?"
			eprintf ("Usage: aac, aac* or aaci (imports xrefs only)\n");
			break;
		default: // "aac"
			cmd_anal_calls (core, input + 1, false, false);
			break;
		}
	case 'j': // "aaj"
		cmd_anal_jumps (core, input + 1);
		break;
	case 'd': // "aad"
		cmd_anal_aad (core, input);
		break;
	case 'v': // "aav"
		cmd_anal_aav (core, input);
		break;
	case 'u': // "aau" - print areas not covered by functions
		r_core_anal_nofunclist (core, input + 1);
		break;
	case 'i': // "aai"
		r_core_anal_info (core, input + 1);
		break;
	case 's': // "aas"
		r_core_cmd0 (core, "af @@= `isq~[0]`");
		r_core_cmd0 (core, "af @@ entry*");
		break;
	case 'S': // "aaS"
		r_core_cmd0 (core, "af @@ sym.*");
		r_core_cmd0 (core, "af @@ entry*");
		break;
	case 'F': // "aaF" "aaFa"
		if (!input[1] || input[1] == ' ' || input[1] == 'a') {
			r_core_anal_inflags (core, input + 1);
		} else {
			eprintf ("Usage: aaF[a] - analyze functions in flag bounds (aaFa uses af/a2f instead of af+/afb+)\n");
		}
		break;
	case 'n': // "aan"
		switch (input[1]) {
		case 'r': // "aanr" // all noreturn propagation
			r_core_anal_propagate_noreturn (core);
			break;
		case 'g': // "aang"
			r_core_anal_autoname_all_golang_fcns (core);
			break;
		case '?':
			eprintf ("Usage: aan[rg]\n");
			eprintf ("aan  : autoname all functions\n");
			eprintf ("aang : autoname all golang functions\n");
			eprintf ("aanr : auto-noreturn propagation\n");
			break;
		default: // "aan"
			r_core_anal_autoname_all_fcns (core);
		}
		break;
	case 'p': // "aap"
		if (*input == '?') {
			// TODO: accept parameters for ranges
			eprintf ("Usage: /aap   ; find in memory for function preludes");
		} else {
			r_core_search_preludes (core, true);
		}
		break;
	case '\0': // "aa"
	case 'a':
		if (input[0] && (input[1] == '?' || (input[1] && input[2] == '?'))) {
			r_cons_println ("Usage: See aa? for more help");
		} else {
			bool didAap = false;
			char *dh_orig = NULL;
			if (!strncmp (input, "aaaaa", 5)) {
				eprintf ("An r2 developer is coming to your place to manually analyze this program. Please wait for it\n");
				if (r_cons_is_interactive ()) {
					r_cons_any_key (NULL);
				}
				goto jacuzzi;
			}
			ut64 curseek = core->offset;
			oldstr = r_print_rowlog (core->print, "Analyze all flags starting with sym. and entry0 (aa)");
			r_cons_break_push (NULL, NULL);
			r_cons_break_timeout (r_config_get_i (core->config, "anal.timeout"));
			r_core_anal_all (core);
			r_print_rowlog_done (core->print, oldstr);
			r_core_task_yield (&core->tasks);
			// Run pending analysis immediately after analysis
			// Usefull when running commands with ";" or via r2 -c,-i
			run_pending_anal (core);
			dh_orig = core->dbg->h
				? strdup (core->dbg->h->name)
				: strdup ("esil");
			if (core->io && core->io->desc && core->io->desc->plugin && !core->io->desc->plugin->isdbg) {
				//use dh_origin if we are debugging
				R_FREE (dh_orig);
			}
			if (r_cons_is_breaked ()) {
				goto jacuzzi;
			}
			r_cons_clear_line (1);
			bool cfg_debug = r_config_get_i (core->config, "cfg.debug");
			if (*input == 'a') { // "aaa"
				if (r_str_startswith (r_config_get (core->config, "bin.lang"), "go")) {
					oldstr = r_print_rowlog (core->print, "Find function and symbol names from golang binaries (aang)");
					r_print_rowlog_done (core->print, oldstr);
					r_core_anal_autoname_all_golang_fcns (core);
					oldstr = r_print_rowlog (core->print, "Analyze all flags starting with sym.go. (aF @@ sym.go.*)");
					r_core_cmd0 (core, "aF @@ sym.go.*");
					r_print_rowlog_done (core->print, oldstr);
				}
				r_core_task_yield (&core->tasks);
				if (!cfg_debug) {
					if (dh_orig && strcmp (dh_orig, "esil")) {
						r_core_cmd0 (core, "dL esil");
						r_core_task_yield (&core->tasks);
					}
				}
				int c = r_config_get_i (core->config, "anal.calls");
				r_config_set_i (core->config, "anal.calls", 1);
				r_core_cmd0 (core, "s $S");
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}

				oldstr = r_print_rowlog (core->print, "Analyze function calls (aac)");
				(void)cmd_anal_calls (core, "", false, false); // "aac"
				r_core_seek (core, curseek, 1);
				// oldstr = r_print_rowlog (core->print, "Analyze data refs as code (LEA)");
				// (void) cmd_anal_aad (core, NULL); // "aad"
				r_print_rowlog_done (core->print, oldstr);
				r_core_task_yield (&core->tasks);
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}

				if (is_unknown_file (core)) {
					oldstr = r_print_rowlog (core->print, "find and analyze function preludes (aap)");
					(void)r_core_search_preludes (core, false); // "aap"
					didAap = true;
					r_print_rowlog_done (core->print, oldstr);
					r_core_task_yield (&core->tasks);
					if (r_cons_is_breaked ()) {
						goto jacuzzi;
					}
				}

				oldstr = r_print_rowlog (core->print, "Analyze len bytes of instructions for references (aar)");
				(void)r_core_anal_refs (core, ""); // "aar"
				r_print_rowlog_done (core->print, oldstr);
				r_core_task_yield (&core->tasks);
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}
				run_pending_anal (core);
				oldstr = r_print_rowlog (core->print, "Check for objc references");
				r_print_rowlog_done (core->print, oldstr);
				cmd_anal_objc (core, input + 1, true);
				r_core_task_yield (&core->tasks);
				oldstr = r_print_rowlog (core->print, "Check for vtables");
				r_core_cmd0 (core, "avrr");
				r_print_rowlog_done (core->print, oldstr);
				r_core_task_yield (&core->tasks);
				r_config_set_i (core->config, "anal.calls", c);
				r_core_task_yield (&core->tasks);
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}
				if (!r_str_startswith (r_config_get (core->config, "asm.arch"), "x86")) {
					r_core_cmd0 (core, "aav");
					r_core_task_yield (&core->tasks);
					bool ioCache = r_config_get_i (core->config, "io.pcache");
					r_config_set_i (core->config, "io.pcache", 1);
					oldstr = r_print_rowlog (core->print, "Emulate code to find computed references (aae)");
					r_core_cmd0 (core, "aae");
					r_print_rowlog_done (core->print, oldstr);
					r_core_task_yield (&core->tasks);
					if (!ioCache) {
						r_core_cmd0 (core, "wc-*");
						r_core_task_yield (&core->tasks);
					}
					r_config_set_i (core->config, "io.pcache", ioCache);
					if (r_cons_is_breaked ()) {
						goto jacuzzi;
					}
				}
				if (r_config_get_i (core->config, "anal.autoname")) {
					oldstr = r_print_rowlog (core->print, "Speculatively constructing a function name "
					                         "for fcn.* and sym.func.* functions (aan)");
					r_core_anal_autoname_all_fcns (core);
					r_print_rowlog_done (core->print, oldstr);
					r_core_task_yield (&core->tasks);
				}
				if (core->anal->opt.vars) {
					RAnalFunction *fcni;
					RListIter *iter;
					r_list_foreach (core->anal->fcns, iter, fcni) {
						if (r_cons_is_breaked ()) {
							break;
						}
						RList *list = r_anal_var_list (core->anal, fcni, 'r');
						if (!r_list_empty (list)) {
							r_list_free (list);
							continue;
						}
						//extract only reg based var here
						r_core_recover_vars (core, fcni, true);
						r_list_free (list);
					}
					r_core_task_yield (&core->tasks);
				}
				if (!sdb_isempty (core->anal->sdb_zigns)) {
					oldstr = r_print_rowlog (core->print, "Check for zignature from zigns folder (z/)");
					r_core_cmd0 (core, "z/");
					r_print_rowlog_done (core->print, oldstr);
					r_core_task_yield (&core->tasks);
				}

				oldstr = r_print_rowlog (core->print, "Type matching analysis for all functions (aaft)");
				r_core_cmd0 (core, "aaft");
				r_print_rowlog_done (core->print, oldstr);
				r_core_task_yield (&core->tasks);

				oldstr = r_print_rowlog (core->print, "Propagate noreturn information");
				r_core_anal_propagate_noreturn (core);
				r_print_rowlog_done (core->print, oldstr);
				r_core_task_yield (&core->tasks);

				oldstr = r_print_rowlog (core->print, "Use -AA or aaaa to perform additional experimental analysis.");
				r_print_rowlog_done (core->print, oldstr);

				if (input[1] == 'a') { // "aaaa"
					if (!didAap) {
						oldstr = r_print_rowlog (core->print, "Finding function preludes");
						(void)r_core_search_preludes (core, false); // "aap"
						r_print_rowlog_done (core->print, oldstr);
						r_core_task_yield (&core->tasks);
					}

					oldstr = r_print_rowlog (core->print, "Enable constraint types analysis for variables");
					r_config_set (core->config, "anal.types.constraint", "true");
					r_print_rowlog_done (core->print, oldstr);
				}
				r_core_cmd0 (core, "s-");
				if (dh_orig) {
					r_core_cmdf (core, "dL %s", dh_orig);
					r_core_task_yield (&core->tasks);
				}
			}
			r_core_seek (core, curseek, 1);
		jacuzzi:
			// XXX this shouldnt be called. flags muts be created wheen the function is registered
			flag_every_function (core);
			r_cons_break_pop ();
			R_FREE (dh_orig);
		}
		break;
	case 't': { // "aat"
		char *off = input[1]? r_str_trim_dup (input + 2): NULL;
		RAnalFunction *fcn;
		RListIter *it;
		if (off && *off) {
			ut64 addr = r_num_math (NULL, off);
			fcn = r_anal_get_fcn_at (core->anal, core->offset, 0);
			if (fcn) {
				r_core_link_stroff (core, fcn);
			} else {
				eprintf ("Cannot find function at %08" PFMT64x "\n", addr);
			}
		} else {
			if (r_list_empty (core->anal->fcns)) {
				eprintf ("Couldn't find any functions\n");
				break;
			}
			r_list_foreach (core->anal->fcns, it, fcn) {
				if (r_cons_is_breaked ()) {
					break;
				}
				r_core_link_stroff (core, fcn);
			}
		}
		free (off);
		break;
	}
	case 'T': // "aaT"
		cmd_anal_aftertraps (core, input + 1);
		break;
	case 'o': // "aao"
		cmd_anal_objc (core, input + 1, false);
		break;
	case 'e': // "aae"
		if (input[1]) {
			const char *len = (char *)input + 1;
			char *addr = strchr (input + 2, ' ');
			if (addr) {
				*addr++ = 0;
			}
			r_core_anal_esil (core, len, addr);
		} else {
			ut64 at = core->offset;
			RIOMap *map;
			RListIter *iter;
			RList *list = r_core_get_boundaries_prot (core, -1, NULL, "anal");
			if (!list) {
				break;
			}
			r_list_foreach (list, iter, map) {
				r_core_seek (core, map->itv.addr, 1);
				r_core_anal_esil (core, "$SS", NULL);
			}
			r_list_free (list);
			r_core_seek (core, at, 1);
		}
		break;
	case 'r':
		(void)r_core_anal_refs (core, input + 1);
		break;
	default:
		r_core_cmd_help (core, help_msg_aa);
		break;
	}

	return true;
}

static bool anal_fcn_data (RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	ut32 fcn_size = r_anal_fcn_size (fcn);
	if (fcn) {
		int i;
		bool gap = false;
		ut64 gap_addr = UT64_MAX;
		char *bitmap = calloc (1, fcn_size);
		if (bitmap) {
			RAnalBlock *b;
			RListIter *iter;
			r_list_foreach (fcn->bbs, iter, b) {
				int f = b->addr - fcn->addr;
				int t = R_MIN (f + b->size, fcn_size);
				if (f >= 0) {
					while (f < t) {
						bitmap[f++] = 1;
					}
				}
			}
		}
		for (i = 0; i < fcn_size; i++) {
			ut64 here = fcn->addr + i;
			if (bitmap && bitmap[i]) {
				if (gap) {
					r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", here - gap_addr, gap_addr);
					gap = false;
				}
				gap_addr = UT64_MAX;
			} else {
				if (!gap) {
					gap = true;
					gap_addr = here;
				}
			}
		}
		if (gap) {
			r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", fcn->addr + fcn_size - gap_addr, gap_addr);
		}
		free (bitmap);
		return true;
	}
	return false;
}

static bool anal_fcn_data_gaps (RCore *core, const char *input) {
	ut64 end = UT64_MAX;
	RAnalFunction *fcn;
	RListIter *iter;
	int i, wordsize = (core->assembler->bits == 64)? 8: 4;
	r_list_sort (core->anal->fcns, cmpaddr);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (end != UT64_MAX) {
			int range = fcn->addr - end;
			if (range > 0) {
				for (i = 0; i + wordsize < range; i+= wordsize) {
					r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", wordsize, end + i);
				}
				r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", range - i, end + i);
				//r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", range, end);
			}
		}
		end = fcn->addr + r_anal_fcn_size (fcn);
	}
	return true;
}

static void cmd_anal_rtti(RCore *core, const char *input) {
	switch (input[0]) {
	case '\0': // "avr"
	case 'j': // "avrj"
		r_anal_rtti_print_at_vtable (core->anal, core->offset, input[0]);
		break;
	case 'a': // "avra"
		r_anal_rtti_print_all (core->anal, input[1]);
		break;
	case 'r': // "avrr"
		r_anal_rtti_recover_all (core->anal);
		break;
	case 'D': { // "avrD"
		char *name = r_str_trim_dup (input + 1);
		char *demangled = r_anal_rtti_demangle_class_name (core->anal, name);
		free (name);
		if (demangled) {
			r_cons_println (demangled);
			free (demangled);
		}
		break;
	}
	default :
		r_core_cmd_help (core, help_msg_av);
		break;
	}
}

static void cmd_anal_virtual_functions(RCore *core, const char* input) {
	switch (input[0]) {
	case '\0': // "av"
	case '*': // "av*"
	case 'j': // "avj"
		r_anal_list_vtables (core->anal, input[0]);
		break;
	case 'r': // "avr"
		cmd_anal_rtti (core, input + 1);
		break;
	default :
		r_core_cmd_help (core, help_msg_av);
		break;
	}
}



static void cmd_anal_class_method(RCore *core, const char *input) {
	RAnalClassErr err = R_ANAL_CLASS_ERR_SUCCESS;
	char c = input[0];
	switch (c) {
	case ' ': // "acm"
	case '-': // "acm-"
	case 'n': { // "acmn"
		const char *str = r_str_trim_ro (input + 1);
		if (!*str) {
			eprintf ("No class name given.\n");
			break;
		}
		char *cstr = strdup (str);
		if (!cstr) {
			break;
		}
		char *end = strchr (cstr, ' ');
		if (!end) {
			eprintf ("No method name given.\n");
			free (cstr);
			break;
		}
		*end = '\0';
		char *name_str = end + 1;

		if (c == ' ' || c == 'n') {
			end = strchr (name_str, ' ');
			if (!end) {
				if (c == ' ') {
					eprintf ("No offset given.\n");
				} else if (c == 'n') {
					eprintf ("No new method name given.\n");
				}
				free (cstr);
				break;
			}
			*end = '\0';
		}

		if (c == ' ') {
			char *addr_str = end + 1;
			end = strchr (addr_str, ' ');
			if (end) {
				*end = '\0';
			}

			RAnalMethod meth;
			meth.name = name_str;
			meth.addr = r_num_get (core->num, addr_str);
			meth.vtable_offset = -1;
			if (end) {
				meth.vtable_offset = (int)r_num_get (core->num, end + 1);
			}
			err = r_anal_class_method_set (core->anal, cstr, &meth);
		} else if (c == 'n') {
			char *new_name_str = end + 1;
			end = strchr (new_name_str, ' ');
			if (end) {
				*end = '\0';
			}

			err = r_anal_class_method_rename (core->anal, cstr, name_str, new_name_str);
		} else if (c == '-') {
			err = r_anal_class_method_delete (core->anal, cstr, name_str);
		}

		free (cstr);
		break;
	}
	default:
		r_core_cmd_help (core, help_msg_ac);
		break;
	}

	switch (err) {
		case R_ANAL_CLASS_ERR_NONEXISTENT_CLASS:
			eprintf ("Class does not exist.\n");
			break;
		case R_ANAL_CLASS_ERR_NONEXISTENT_ATTR:
			eprintf ("Method does not exist.\n");
			break;
		default:
			break;
	}
}

static void cmd_anal_class_base(RCore *core, const char *input) {
	RAnalClassErr err = R_ANAL_CLASS_ERR_SUCCESS;
	char c = input[0];
	switch (c) {
	case ' ': // "acb"
	case '-': { // "acb-"
		const char *str = r_str_trim_ro (input + 1);
		if (!*str) {
			eprintf ("No class name given.\n");
			return;
		}
		char *cstr = strdup (str);
		if (!cstr) {
			break;
		}
		char *end = strchr (cstr, ' ');
		if (end) {
			*end = '\0';
			end++;
		}

		if (!end || *end == '\0') {
			if (c == ' ') {
				r_anal_class_list_bases (core->anal, cstr);
			} else /*if (c == '-')*/ {
				eprintf ("No base id given.\n");
			}
			free (cstr);
			break;
		}

		char *base_str = end;
		end = strchr (base_str, ' ');
		if (end) {
			*end = '\0';
		}

		if (c == '-') {
			err = r_anal_class_base_delete (core->anal, cstr, base_str);
			free (cstr);
			break;
		}

		RAnalBaseClass base;
		base.id = NULL;
		base.offset = 0;
		base.class_name = base_str;

		if (end) {
			base.offset = r_num_get (core->num, end + 1);
		}

		err = r_anal_class_base_set (core->anal, cstr, &base);
		free (base.id);
		free (cstr);
		break;
	}
	default:
		r_core_cmd_help (core, help_msg_ac);
		break;
	}

	if (err == R_ANAL_CLASS_ERR_NONEXISTENT_CLASS) {
		eprintf ("Class does not exist.\n");
	}
}

static void cmd_anal_class_vtable(RCore *core, const char *input) {
	RAnalClassErr err = R_ANAL_CLASS_ERR_SUCCESS;
	char c = input[0];
	switch (c) {
	case ' ': // "acv"
	case '-': { // "acv-"
		const char *str = r_str_trim_ro (input + 1);
		if (!*str) {
			eprintf ("No class name given.\n");
			return;
		}
		char *cstr = strdup (str);
		if (!cstr) {
			break;
		}
		char *end = strchr (cstr, ' ');
		if (end) {
			*end = '\0';
			end++;
		}

		if (!end || *end == '\0') {
			if (c == ' ') {
				r_anal_class_list_vtables (core->anal, cstr);
			} else /*if (c == '-')*/ {
				eprintf ("No vtable id given. See acv [class name].\n");
			}
			free (cstr);
			break;
		}

		char *arg1_str = end;
		end = strchr (arg1_str, ' ');
		if (end) {
			*end = '\0';
		}

		if (c == '-') {
			err = r_anal_class_vtable_delete (core->anal, cstr, arg1_str);
			free (cstr);
			break;
		}

		RAnalVTable vtable;
		vtable.id = NULL;
		vtable.addr = r_num_get (core->num, arg1_str);
		vtable.offset = 0;

		if (end) {
			vtable.offset = r_num_get (core->num, end + 1);
		}

		err = r_anal_class_vtable_set (core->anal, cstr, &vtable);
		free (vtable.id);
		free (cstr);
		break;
	}
	default:
		r_core_cmd_help (core, help_msg_ac);
		break;
	}

	if (err == R_ANAL_CLASS_ERR_NONEXISTENT_CLASS) {
		eprintf ("Class does not exist.\n");
	}
}

static void cmd_anal_classes(RCore *core, const char *input) {
	switch (input[0]) {
	case 'l': // "acl"
		r_anal_class_list (core->anal, input[1]);
		break;
	case ' ': // "ac"
	case '-': // "ac-"
	case 'n': { // "acn"
		const char *str = r_str_trim_ro (input + 1);
		if (!*str) {
			break;
		}
		char *cstr = strdup (str);
		if (!cstr) {
			break;
		}
		char *end = strchr (cstr, ' ');
		if (end) {
			*end = '\0';
		}
		if (input[0] == '-') {
			r_anal_class_delete (core->anal, cstr);
		} else if(input[0] == 'n') {
			if (!end) {
				eprintf ("No new class name given.\n");
			} else {
				char *new_name = end + 1;
				end = strchr (new_name, ' ');
				if (end) {
					*end = '\0';
				}
				RAnalClassErr err = r_anal_class_rename (core->anal, cstr, new_name);
				if (err == R_ANAL_CLASS_ERR_NONEXISTENT_CLASS) {
					eprintf ("Class does not exist.\n");
				} else if (err == R_ANAL_CLASS_ERR_CLASH) {
					eprintf ("A class with this name already exists.\n");
				}
			}
		} else {
			r_anal_class_create (core->anal, cstr);
		}
		free (cstr);
		break;
	}
	case 'v':
		cmd_anal_class_vtable (core, input + 1);
		break;
	case 'b': // "acb"
		cmd_anal_class_base (core, input + 1);
		break;
	case 'm': // "acm"
		cmd_anal_class_method (core, input + 1);
		break;
	default: // "ac?"
		r_core_cmd_help (core, help_msg_ac);
		break;
	}
}

static void show_reg_args(RCore *core, int nargs, RStrBuf *sb) {
	int i;
	char regname[8];
	if (nargs < 0) {
		nargs = 4; // default args if not defined
	}
	for (i = 0; i < nargs; i++) {
		snprintf (regname, sizeof (regname), "A%d", i);
		ut64 v = r_reg_getv (core->anal->reg, regname);
		if (sb) {
			r_strbuf_appendf (sb, "%s0x%08"PFMT64x, i?", ":"", v);
		} else {
			r_cons_printf ("A%d 0x%08"PFMT64x"\n", i, v);
		}
	}
}

// ripped from disasm.c: dupe code from there
// TODO: Implement aC* and aCj
static void cmd_anal_aC(RCore *core, const char *input) {
	bool is_aCer = false;
	RAnalFuncArg *arg;
	RListIter *iter;
	RListIter *nextele;
	const char *iarg = strchr (input, ' ');
	if (input[0] == 'e' && input[1] == 'f') { // "aCf"
		// hacky :D
		r_core_cmdf (core, ".aCe* $$ @@=`pdr~call`");
		return;
	}
	if (iarg) {
		iarg++;
	}
	if (!iarg) {
		eprintf ("Usage: aC[e] [addr-of-call] # analyze call args (aCe does esil emulation with abte)\n");
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	ut64 pcv = r_num_math (core->num, iarg);
	if (input[0] == 'e') { // "aCe"
		is_aCer = (input[1] == '*');
		r_core_cmdf (core, ".abte 0x%08"PFMT64x, pcv);
	}
	RAnalOp* op = r_core_anal_op (core, pcv, -1);
	if (!op) {
		return;
	}
bool go_on = true;
	if (op->type != R_ANAL_OP_TYPE_CALL) {
		show_reg_args (core, -1, sb);
		go_on = false;
	}
	const char *fcn_name = NULL;
	RAnalFunction *fcn;
	if (go_on) {
		fcn = r_anal_get_fcn_at (core->anal, pcv, 0);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			RFlagItem *item = r_flag_get_i (core->flags, op->jump);
			if (item) {
				fcn_name = item->name;
			}
		}
		char *key = (fcn_name)? resolve_fcn_name (core->anal, fcn_name): NULL;
		if (key) {
			const char *fcn_type = r_type_func_ret (core->anal->sdb_types, key);
			int nargs = r_type_func_args_count (core->anal->sdb_types, key);
			// remove other comments
			if (fcn_type) {
				r_strbuf_appendf (sb, "%s%s%s(", r_str_get (fcn_type),
						(*fcn_type && fcn_type[strlen (fcn_type) - 1] == '*') ? "" : " ",
						r_str_get (key));
				if (!nargs) {
					r_strbuf_appendf (sb, "void)\n");
				}
			} else {
				eprintf ("Cannot find any function type..lets just use some standards?\n");
			}
		} else {
			if (is_aCer) {
				show_reg_args (core, -1, sb);
				go_on = true;
			} else {
				show_reg_args (core, -1, NULL);
				go_on = false;
			}
		}
	}
	if (go_on) {
		ut64 s_width = (core->anal->bits == 64)? 8: 4;
		const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
		ut64 spv = r_reg_getv (core->anal->reg, sp);
		r_reg_setv (core->anal->reg, sp, spv + s_width); // temporarily set stack ptr to sync with carg.c
		RList *list = r_core_get_func_args (core, fcn_name);
		if (!r_list_empty (list)) {
	#if 0
			bool warning = false;
			bool on_stack = false;
			r_list_foreach (list, iter, arg) {
				if (r_str_startswith (arg->cc_source, "stack")) {
					on_stack = true;
				}
				if (!arg->size) {
					r_cons_printf ("%s: unk_size", arg->c_type);
					warning = true;
				}
	#endif
			r_list_foreach (list, iter, arg) {
				nextele = r_list_iter_get_next (iter);
				if (!arg->fmt) {
					r_strbuf_appendf (sb, "?%s", nextele? ", ": "");
				} else {
					// print_fcn_arg (core, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack, 0);
					// const char *fmt = arg->orig_c_type;
					ut64 addr = arg->src;
					char *res = r_core_cmd_strf (core, "pfq %s @ 0x%08" PFMT64x, arg->fmt, addr);
					// r_cons_printf ("pfq *%s @ 0x%08" PFMT64x"\n", arg->fmt, addr);
					r_str_trim (res);
					r_strbuf_appendf (sb, "%s", res);
					free (res);
				}
			}
			r_strbuf_appendf (sb, ")");
		} else {
			// function name not resolved
			int i, nargs = 4; // DEFAULT_NARGS;
			if (fcn) {
				// @TODO: fcn->nargs should be updated somewhere and used here instead
				nargs = r_anal_var_count (core->anal, fcn, 's', 1) +
					r_anal_var_count (core->anal, fcn, 'b', 1) +
					r_anal_var_count (core->anal, fcn, 'r', 1);
			}
			if (nargs > 0) {
				if (fcn_name) {
					r_strbuf_appendf (sb, "; %s(", fcn_name);
				} else {
					r_strbuf_appendf (sb, "; 0x%"PFMT64x"(", pcv);
				}
				for (i = 0; i < nargs; i++) {
					ut64 v = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_FASTCALL, i);
					r_strbuf_appendf (sb, "%s0x%"PFMT64x, i?", ":"", v);
				}
				r_strbuf_appendf (sb, ")");
			}
		}
		r_reg_setv (core->anal->reg, sp, spv); // reset stack ptr
	}
	char *s = r_strbuf_drain (sb);
	if (is_aCer) {
		char *u = r_base64_encode_dyn (s, -1);
		if (u) {
			r_cons_printf ("CCu base64:%s\n", u);
			free (u);
		}
	} else {
		r_cons_printf ("%s\n", s);
	}
	free (s);
}

static int cmd_anal(void *data, const char *input) {
	const char *r;
	RCore *core = (RCore *)data;
	ut32 tbs = core->blocksize;

	switch (input[0]) {
	case 'p': // "ap"
		{
			const ut8 *prelude = (const ut8*)"\xe9\x2d"; //:fffff000";
			const int prelude_sz = 2;
			const int bufsz = 4096;
			ut8 *buf = calloc (1, bufsz);
			ut64 off = core->offset;
			if (input[1] == ' ') {
				off = r_num_math (core->num, input+1);
				r_io_read_at (core->io, off - bufsz + prelude_sz, buf, bufsz);
			} else {
				r_io_read_at (core->io, off - bufsz + prelude_sz, buf, bufsz);
			}
			//const char *prelude = "\x2d\xe9\xf0\x47"; //:fffff000";
			r_mem_reverse (buf, bufsz);
			//r_print_hexdump (NULL, off, buf, bufsz, 16, -16);
			const ut8 *pos = r_mem_mem (buf, bufsz, prelude, prelude_sz);
			if (pos) {
				int delta = (size_t)(pos - buf);
				eprintf ("POS = %d\n", delta);
				eprintf ("HIT = 0x%"PFMT64x"\n", off - delta);
				r_cons_printf ("0x%08"PFMT64x"\n", off - delta);
			} else {
				eprintf ("Cannot find prelude\n");
			}
			free (buf);
		}
		break;
	case '8':
		{
			ut8 *buf = malloc (strlen (input) + 1);
			if (buf) {
				int len = r_hex_str2bin (input + 1, buf);
				if (len > 0) {
					core_anal_bytes (core, buf, len, 0, input[1]);
				}
				free (buf);
			}
		}
		break;
	case 'b': // "ab"
		if (input[1] == 'b') { // "abb"
			core_anal_bbs (core, input + 2);
		} else if (input[1] == 'r') { // "abr"
			core_anal_bbs_range (core, input + 2);
		} else if (input[1] == 't') {
			cmd_anal_abt (core, input+2);
		} else if (input[1] == 'j') { // "abj"
			anal_fcn_list_bb (core, input + 1, false);
		} else if (input[1] == ' ' || !input[1]) {
			// find block
			ut64 addr = core->offset;
			if (input[1]) {
				addr = r_num_math (core->num, input + 1);
			}
			r_core_cmdf (core, "afbi @ 0x%"PFMT64x, addr);
		} else {
			r_core_cmd_help (core, help_msg_ab);
		}
		break;
	case 'c': // "ac"
		cmd_anal_classes (core, input + 1);
		break;
	case 'C': // "aC"
		cmd_anal_aC (core, input + 1);
		break;
	case 'i': cmd_anal_info (core, input + 1); break; // "ai"
	case 'r': cmd_anal_reg (core, input + 1); break;  // "ar"
	case 'e': cmd_anal_esil (core, input + 1); break; // "ae"
	case 'L': return r_core_cmd0 (core, "e asm.arch=??"); break;
	case 'o': cmd_anal_opcode (core, input + 1); break; // "ao"
	case 'O': cmd_anal_bytes (core, input + 1); break; // "aO"
	case 'F': // "aF"
		r_core_anal_fcn (core, core->offset, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
		break;
	case 'f': // "af"
		{
		int res = cmd_anal_fcn (core, input);
		run_pending_anal (core);
		if (!res) {
			return false;
		}
		}
		break;
	case 'n': // 'an'
		{
		const char *name = NULL;
		bool use_json = false;

		if (input[1] == 'j') {
			use_json = true;
			input++;
		}

		if (input[1] == ' ') {
			name = input + 1;
			while (name[0] == ' ') {
				name++;
			}
			char *end = strchr (name, ' ');
			if (end) {
				*end = '\0';
			}
			if (*name == '\0') {
				name = NULL;
			}
		}

		cmd_an (core, use_json, name);
		}
		break;
	case 'g': // "ag"
		cmd_anal_graph (core, input + 1);
		break;
	case 's': // "as"
		cmd_anal_syscall (core, input + 1);
		break;
	case 'v': // "av"
		cmd_anal_virtual_functions (core, input + 1);
		break;
	case 'x': // "ax"
		if (!cmd_anal_refs (core, input + 1)) {
			return false;
		}
		break;
	case '*': // "a*"
		r_core_cmd0 (core, "afl*");
		r_core_cmd0 (core, "ah*");
		r_core_cmd0 (core, "ax*");
		break;
	case 'a': // "aa"
		if (!cmd_anal_all (core, input + 1)) {
			return false;
		}
		break;
	case 'd': // "ad"
		switch (input[1]) {
		case 'f': // "adf"
			if (input[2] == 'g') {
				anal_fcn_data_gaps (core, input + 1);
			} else {
				anal_fcn_data (core, input + 1);
			}
			break;
		case 't': // "adt"
			cmd_anal_trampoline (core, input + 2);
			break;
		case ' ': { // "ad"
			const int default_depth = 1;
			const char *p;
			int a, b;
			a = r_num_math (core->num, input + 2);
			p = strchr (input + 2, ' ');
			b = p? r_num_math (core->num, p + 1): default_depth;
			if (a < 1) {
				a = 1;
			}
			if (b < 1) {
				b = 1;
			}
			r_core_anal_data (core, core->offset, a, b, 0);
		} break;
		case 'k': // "adk"
			r = r_anal_data_kind (core->anal,
					core->offset, core->block, core->blocksize);
			r_cons_println (r);
			break;
		case '\0': // "ad"
			r_core_anal_data (core, core->offset, 2 + (core->blocksize / 4), 1, 0);
			break;
		case '4': // "ad4"
			r_core_anal_data (core, core->offset, 2 + (core->blocksize / 4), 1, 4);
			break;
		case '8': // "ad8"
			r_core_anal_data (core, core->offset, 2 + (core->blocksize / 4), 1, 8);
			break;
		default:
			r_core_cmd_help (core, help_msg_ad);
			break;
		}
		break;
	case 'h': // "ah"
		cmd_anal_hint (core, input + 1);
		break;
	case '!': // "a!"
		if (core->anal && core->anal->cur && core->anal->cur->cmd_ext) {
			return core->anal->cur->cmd_ext (core->anal, input + 1);
		} else {
			r_cons_printf ("No plugins for this analysis plugin\n");
		}
		break;
	case 'j': // "aj"
		r_core_cmd0 (core, "aflj");
		break;
	case 0: // "a"
		r_core_cmd0 (core, "aai");
		break;
	default:
		r_core_cmd_help (core, help_msg_a);
#if 0
		r_cons_printf ("Examples:\n"
			" f ts @ `S*~text:0[3]`; f t @ section..text\n"
			" f ds @ `S*~data:0[3]`; f d @ section..data\n"
			" .ad t t+ts @ d:ds\n",
			NULL);
#endif
		break;
	}
	if (tbs != core->blocksize) {
		r_core_block_size (core, tbs);
	}
	if (r_cons_is_breaked ()) {
		r_cons_clear_line (1);
	}
	return 0;
}
