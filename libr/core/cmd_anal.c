/* radare - LGPL - Copyright 2009-2023 - pancake, maijin */

#include <r_core.h>

#define MAX_SCAN_SIZE 0x7ffffff

R_VEC_TYPE(RVecUT64, ut64);

static RCoreHelpMessage help_msg_af_plus = {
	"Usage:", "af+", " [addr] ([name] ([type] [diff]))",
	"af+", "$$", "add a raw function element. See afb+ to add basic blocks to it",
	"af+", "$$ main", "add new function in current offset with 'main' as name",
	NULL
};

static RCoreHelpMessage help_msg_aex = {
	"Usage:", "aex", "[a] [9090]",
	"aex", " 90", "decode the given hexpairs and execute them",
	"aexa", " mov rax, 33", "assemble instruction and execute it",
	NULL
};

static RCoreHelpMessage help_msg_a = {
	"Usage:", "a", "[abdefFghoprxstc] [...]",
	"a", "", "alias for aai - analysis information",
	"a:", "[cmd]", "run a command implemented by an analysis plugin (like : for io)",
	"a*", "", "same as afl*;ah*;ax*",
	"aa", "[?]", "analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
	"a8", " [hexpairs]", "analyze bytes",
	"ab", "[?]", "analyze basic block",
	"ac", "[?]", "manage classes",
	"aC", "[?]", "analyze function call",
	"ad", "[?]", "analyze data trampoline (wip) (see 'aod' to describe mnemonics)", // XXX rename to at?
	"ad", " [from] [to]", "analyze data pointers to (from-to)",
	"ae", "[?] [expr]", "analyze opcode eval expression (see ao)",
	"af", "[?]", "analyze functions",
	"aF", "", "same as above, but using anal.depth=1",
	"ag", "[?] [options]", "draw graphs in various formats",
	"ah", "[?]", "analysis hints (force opcode size, ...)",
	"ai", " [addr]", "address information (show perms, stack, heap, ...)",
	"aj", "", "same as a* but in json (aflj)",
	"aL", "[jq]", "list all asm/anal plugins (See `e asm.arch=?` and `La[jq]`)",
	"an", "[?] [name]", "show/rename/create whatever var/flag/function used in current instruction",
	"ao", "[?] [len]", "analyze Opcodes (or emulate it)",
	"aO", "[?] [len]", "analyze N instructions in M bytes",
	"ap", "", "find prelude for current offset",
	"ar", "[?]", "like 'dr' but for the esil vm. (registers)",
	"as", "[?] [num]", "analyze syscall using dbg.reg",
	"av", "[?] [.]", "show vtables",
	"avg", "[?] [.]", "manage global variables",
	"ax", "[?]", "manage refs/xrefs (see also afx?)",
	NULL
};

static RCoreHelpMessage help_msg_afna = {
	"Usage:", "afna", " # construct a function name and rename the function for the current offset.",
	"", "", "Based on flags or methods calls found inside that function.",
	NULL
};

static RCoreHelpMessage help_msg_afu = {
	"Usage:", "afu", "[addr]   # resize and analyze function from current address until addr.",
	"afu", " 0x100004093", "resize and analyze function from current address until 0x100004093",
	NULL
};

static RCoreHelpMessage help_msg_aae = {
	"Usage:", "aae", "[pf] ([addr]) # analyze all kind of stuff using esil",
	"aaep", "", "same as aepa@@@i - define anal pins by import flag names",
	"aaep", "a", "run 'aep ret0@@@i' and then 'aaep' - all unknown imports are faked to return 0",
	"aaef", "", "emulate all functions using esil to find out computed references (same as aef@@@F)",
	"aae", " [size] ([addr])", "same as aepa@@@i - define anal pins by import flag names",
	"aae", "", "honor anal.{in,from,to} and emulate all executable regions",
	NULL
};

static RCoreHelpMessage help_msg_aav = {
	"Usage:", "aav", "[sat] # find values referencing a specific section or map",
	"aav", "", "find absolute reference values",
	"aavr", "", "find relative reference values (address + 4 byte signed int)",
	NULL
};

static RCoreHelpMessage help_msg_aan = {
	"Usage:", "aan", "[rg]   # automatically name functions.",
	"aan", "", "autoname all functions",
	"aang", "", "autoname all golang functions",
	"aanr", "", "auto-noreturn propagation",
	NULL
};

static RCoreHelpMessage help_msg_afm = {
	"Usage:", "afm", "[name]   # merge two functions.",
	"afm", " sym.func.100003d74", "merge current function into 0x100003d74",
	NULL
};

static RCoreHelpMessage help_msg_aF = {
	"Usage:", "aF", " # analyze a function, but using anal.depth=1",
	"aF", "", "check af? for more options and information.",
	NULL
};

static RCoreHelpMessage help_msg_an = {
	"Usage:", "an", " # analyze name for the current address",
	"an", "", "show flag/function/symbol name",
	"an*", "", "same as above but in r2 commands",
	"anj", "", "same as above but in json",
	NULL
};

static RCoreHelpMessage help_msg_a8 = {
	"Usage:", "a8", "[hexpairs]   # analyze the byte array given as input",
	"a8 ", "5548", "analyzes 5548 byte array",
	NULL
};

static RCoreHelpMessage help_msg_ap = {
	"Usage:", "ap[?]", " # analyze prelude in current offset",
	"ap", "", "check if current offset contains a function prelude",
	"apl", "", "list available function preludes defined by the arch plugin",
	// "ap+", "bytes:mask:align", "add a new function prelude",
	"apt", "", "analysis process-thread (like dpt for esil), list threads",
	"apt ", "[id]", "select a thread (change register profile and TLS map",
	"apt+", "[map]", "create a thread with given TLS mapid and prints the new thread id",
	"apt-", "[id]", "delete a thread by id",
	NULL
};

static RCoreHelpMessage help_msg_avg = {
	"Usage:", "avg", " # analyze variable global",
	"avg", "", "use ESIL emulation to find out arguments of a call (uses 'abte')",
	"avg", " [type] [name]", "add global",
	"avg-", "", "delete global",
	NULL
};

static RCoreHelpMessage help_msg_aC = {
	"Usage:", "aC[fej] [addr-of-call]", " # analyze call args",
	"aCe", "", "use ESIL emulation to find out arguments of a call (uses 'abte')",
	"aCf", "", "same as .aCe* $$ @@=`pdr~call`",
	NULL
};

static RCoreHelpMessage help_msg_aaf = {
	"Usage:", "aaf[efrt?]", " # analyse all functionsee also 'af' and 'afna'",
	"aaf", "", "same as afr@@c:isq",
	"aafe", " ", "same as aef@@F",
	"aaff", "", "set a flag for every function",
	"aafr", " [len]", "consecutive function analysis (e anal.hasnext=1;afr@@c:isq)",
	"aaft", "", "recursive type matching across all functions",
	"aafs", "", "single basic block function analysis",
	NULL
};

static RCoreHelpMessage help_msg_aaa = {
	"Usage:", "aa[a[a[a]]]", " # automatically analyze the whole program",
	"a", " ", "show code analysis statistics",
	"aa", " ", "alias for 'af@@ sym.*;af@entry0;afva'",
	"aaa", "", "perform deeper analysis, most common use",
	"aaaa", "", "same as aaa but adds a bunch of experimental iterations",
	"aaaaa", "", "refine the analysis to find more functions after aaaa",
	NULL
};

static RCoreHelpMessage help_msg_aa = {
	"Usage:", "aa[0*?]", " # see also 'af' and 'afna'",
	"aa", " ", "alias for 'af@@ sym.*;af@entry0;afva'", //;.afna @@ fcn.*'",
	"aaa", "[?]", "autoname functions after aa (see afna)",
	"aab", "", "abb across bin.sections.rx",
	"aac", " [len]", "analyze function calls (af @@ `pi len~call[1]`)",
	"aac*", " [len]", "flag function calls without performing a complete analysis",
	"aaci", "", "flag import xrefs only",
	"aad", " [len]", "analyze data references to code",
	"aae", "[?] [len] ([addr])", "analyze references with ESIL (optionally to address)",
	"aaef", "", "analyze references with ESIL in all functions",
	"aaf", "[?][efrt] ", "analyze all functions relationships with flags, type matching and consecutive",
	"aaF", " [sym*]", "set anal.in=block for all the spaces between flags matching glob",
	"aaFa", " [sym*]", "same as aaF but uses af/a2f instead of af+/afb+ (slower but more accurate)",
	"aai", "[j]", "show info of all analysis parameters",
	"aaj", " ", "analyze all jumps",
	"aan", "[?][fgr]", "autoname functions (aang = golang, aanr = noreturn propagation, aanf = afna@@F)",
	"aao", "", "analyze all objc references",
	"aap", "", "find and analyze function preludes",
	"aar", "[?] [len]", "analyze len bytes of instructions for references",
	"aas", " [len]", "analyze symbols (af @@= `isq~[0]`)",
	"aaS", "", "analyze all flags starting with sym. (af @@ sym.*)",
	"aat", " [fcn]", "analyze all/given function to convert immediate to linked structure offsets (see tl?)",
	"aaT", " [len]", "analyze code after trap-sleds",
	"aau", " [len]", "list mem areas (larger than len bytes) not covered by functions",
	"aav", "[?] [sat]", "find values referencing a specific section or map",
	"aaw", "", "analyze all meta words (Cd) and add r. named flags for referenced pointers",
	NULL
};

static RCoreHelpMessage help_msg_afls = {
	"Usage:", "afls", "[afls] # sort function list",
	"afls", "", "same as aflsa",
	"aflsa", "", "sort by address (same as afls)",
	"aflss", "", "sort by size",
	"aflsn", "", "sort by name",
	"aflsb", "", "sort by number of basic blocks",
	NULL
};

static RCoreHelpMessage help_msg_aflx = {
	"Usage:", "aflx", "[jv*] # list function xrefs",
	"aflx", "", "list function xrefs (who references or calls the current function)",
	"aflxj", "", "list function xrefs in JSON format",
	"aflxv", "", "list function xrefs with names",
	"aflx*", "", "list function xrefs in radare commands format",
	NULL
};

static RCoreHelpMessage help_msg_ai = {
	"Usage:", "ai", "[j*] [sz] # analysis/address information/imports",
	"ai", " @addr", "show address information",
	"aia", "", "show architecture specific information instruction size and alignment details",
	"aii", " [namespace]", "global import (like afii, but global)",
	"aii", "-", "delete all global imports",
	"aij", " @addr", "show address information in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_aar = {
	"Usage:", "aar", "[j*] [sz] # search and analyze xrefs",
	"aar", "", "analyze xrefs in current section ",
	"aar", " [sz]", "analyze xrefs starting in current offset until sz bytes are consumed",
	"aarr", "", "analyze all function reference graph to find more functions (EXPERIMENTAL)",
	"aar*", " [sz]", "list found xrefs in radare commands format",
	"aarj", " [sz]", "list found xrefs in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_ab = {
	"Usage:", "ab", "# analyze basic block",
	"ab", " [addr]", "show basic block information at given address",
	"ab-", "[addr]", "delete basic block at given address",
	"ab.", "", "same as: ab $$",
	"aba", " [addr]", "analyze esil accesses in basic block (see aea?)",
	"abb", " [length]", "analyze N bytes and extract basic blocks",
	"abc", "[-] [color]", "change color of the current basic block (same as afbc, abc- to unset)",
	"abe", " [esil-expr]", "assign esil expression to basic block (see: aeb, dre, afbd)",
	"abf", " [addr]", "address of incoming (from) basic blocks",
	"abi", "", "same as ab. or ab",
	"abj", " [addr]", "display basic block information in JSON",
	"abl", "[?] [.-cqj]", "list all basic blocks",
	"abo", "", "list opcode offsets of current basic block",
	"abp", "[?] [addr] [num]", "follow basic blocks paths from current offset to addr",
	"abt", "[tag] ([color])", "trace tags are bitfields, 0 means nontraced, withuot arguments show current value",
	"abx", " [hexpair-bytes]", "analyze N bytes",
	NULL
};

static RCoreHelpMessage help_msg_abl = {
	"Usage:", "abl", "analyzed basicblocks listing",
	"abl", "", "list all program-wide basic blocks analyzed",
	"abl,", " [table-query]", "render the list using a table",
	"ablc", "", "count how many basic blocks are registered",
	"ablj", "", "in json format",
	"ablq", "", "in quiet format",
	NULL
};

static RCoreHelpMessage help_msg_abp = {
	"Usage:", "abp", "[addr] [num] # find num paths from current offset to addr",
	"abp", " [addr] [num]", "find num paths from current offset to addr",
	"abpe", " [addr]", "emulate from beginning of function to the given address",
	"abpj", " [addr] [num]", "display paths in JSON",
	NULL
};

static RCoreHelpMessage help_msg_ac = {
	"Usage:", "ac", "anal classes commands",
	"acl", "[j*]", "list all classes",
	"acll", "[j] (class_name)", "list all or single class detailed",
	"ac", " [class name]", "add class",
	"ac-", " [class name]", "delete class",
	"acn", " [class name] [new class name]", "rename class",
	"acv", " [class name] [addr] ([offset]) ([size])", "add vtable address to class",
	"acvf", " [offset] ([class name])", "lookup function address on vtable offset",
	"acv-", " [class name] [vtable id]", "delete vtable by id (from acv [class name])",
	"acb", " [class name]", "list bases of class",
	"acb", " [class name] [base class name] ([offset])", "add base class",
	"acb-", " [class name] [base class id]", "delete base by id (from acb [class name])",
	"acm", " [class name] [method name] [offset] ([vtable offset])", "add/edit method",
	"acm-", " [class name] [method name]", "delete method",
	"acmn", " [class name] [method name] [new name]", "rename method",
	"acg", "", "print inheritance ascii graph",
	"ac?", "", "show this help",
	NULL
};

static RCoreHelpMessage help_msg_acolon = {
	"Usage:", "a:", "[plugin-command]",
	"a:", "", "list the analysis plugins",
	"a:", "a2f", "run the command associated with the 'a2f' analysis plugin",
	NULL
};

static RCoreHelpMessage help_msg_ad = {
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

static RCoreHelpMessage help_msg_aes = {
	"Usage:", "aes[pbosu]", "esil stepping utilities",
	"aesp", " [X] [N]", "evaluate N instr from offset X",
	"aesb", "", "step back",
	"aeso", " ", "step over",
	"aesou", " [addr]", "step over until given address",
	"aess", " ", "step skip (in case of CALL, just skip, instead of step into)",
	"aesu", " [addr]", "step until given address",
	"aesue", " [esil]", "step until esil expression match",
	"aesuo", " [optype]", "step until given opcode type",
	"aesB", " [addr] [N] @ [from-addr]", "step over every N instructions",
	NULL
};

static RCoreHelpMessage help_msg_aei = {
	"Usage:", "aei", "[smp] [...]",
	"aei", "", "initialize ESIL VM state (aei- to deinitialize)",
	"aeis", " argc [argv] [envp]", "initialize entrypoint stack environment",
	"aeim", " [addr] [size] [name]", "initialize ESIL VM stack (aeim- remove)",
	"aeip", "", "initialize ESIL program counter to curseek",
	NULL
};

static RCoreHelpMessage help_msg_ae = {
	"Usage:", "ae[idesr?] [arg]", "ESIL code emulation",
	"ae", " [expr]", "evaluate ESIL expression",
	"ae?", "", "show this help",
	"ae??", "", "show ESIL help",
	"aea", "[f] [count]", "analyse n esil instructions accesses (regs, mem..)",
	"aeA", "[f] [count]", "analyse n bytes for their esil accesses (regs, mem..)",
	"aeb", " ([addr])", "emulate block in current or given address",
	"aeC", "[arg0 arg1..] @ addr", "appcall in esil",
	"aec", "[?]", "continue until ^C",
	"aef", " [addr]", "emulate function",
	"aefa", " [addr]", "emulate function to find out args in given or current offset",
	"aeg", " [expr]", "esil data flow graph",
	"aegf", " [expr] [register]", "esil data flow graph filter",
	"aei", "[?]", "initialize ESIL VM state (aei- to deinitialize)",
	"aek", "[?] [query]", "perform sdb query on ESIL.info",
	"aeL", "[?][-] [name]", "list ESIL plugins",
	"aep", "[?] [addr]", "manage esil pin hooks (see 'e cmd.esil.pin')",
	"aepc", " [addr]", "change esil PC to this address",
	"aer", "[?] [..]", "handle ESIL registers like 'ar' or 'dr' does",
	"aes", "[?]", "perform emulated debugger step",
	"aet", "[?][s]", "esil trace listing and session management (requires aeim)",
	"aev", " [esil]", "visual esil debugger for the given expression or current instruction",
	"aex", " [hex]", "evaluate opcode expression",
	NULL
};

static RCoreHelpMessage help_detail_ae = {
	"Examples:", "ESIL", " examples and documentation",
	"=", "", "assign updating internal flags",
	":=", "", "assign without updating internal flags",
	"+=", "", "a+=b => b,a,+=",
	"/", "", "division",
	"*", "", "multiply",
	"*=", "", "multiply and assign a *= b",
	"L*", "", "long multiply",
	"+", "", "a=a+b => b,a,+,a,=",
	"++", "", "increment, 2,a,++ == 3 (see rsi,--=[1], ... )",
	"--", "", "decrement, 2,a,-- == 1",
	"*=", "", "a*=b => b,a,*=",
	"/=", "", "a/=b => b,a,/=",
	"%", "", "module",
	"%=", "", "a%=b => b,a,%=",
	"&=", "", "and ax, bx => bx,ax,&=",
	"^", "", "xor",
	"&", "", "and",
	"|", "", "or r0, r1, r2 => r2,r1,|,r0,=",
	"!=", "", "negate all bits",
	"^=", "", "xor ax, bx => bx,ax,^=",
	"", "[]", "mov eax,[eax] => eax,[],eax,=",
	"=", "[]", "mov [eax+3], 1 => 1,3,eax,+,=[]",
	"=", "[1]", "mov byte[eax],1 => 1,eax,=[1]",
	"=", "[8]", "mov [rax],1 => 1,rax,=[8]",
	"()", "", "execute an esil syscall",
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
	"}{", "", "else block",
	"}", "", "end of conditional block",
	"NAN", "", "checks if result in stack is not a number",
	"I2D", "", "signed to double",
	// "S2D", "", "signed to double",
	"U2D", "", "unsigned to double",
	"D2I", "", "double to signed",
	"D2U", "", "double to unsigned",
	"F==", "", "float comparison",
	"CEIL", "", "float ceil",
	"FLOOR", "", "float floor",
	"ROUND", "", "float round",
	"SQRT", "", "float square root",
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
	"$$", "", "internal flag: pc address",
	NULL
};

static RCoreHelpMessage help_msg_aea = {
	"Examples:", "aea", " show regs and memory accesses used in a range",
	"aea", "  [ops]", "show regs/memory accesses used in N instructions",
	"aea*", " [ops]", "create mem.* flags for memory accesses",
	"aeab", "", "show regs used in current basic block",
	"aeaf", "", "show regs used in current function",
	"aear", " [ops]", "show regs read in N instructions",
	"aeaw", " [ops]", "show regs written in N instructions",
	"aean", " [ops]", "show regs not written in N instructions",
	"aeaj", " [ops]", "show aea output in JSON format",
	"aeA", "  [len]", "show regs used in N bytes (subcommands are the same)",
	"Legend:", "", "",
	"I", "", "input registers (read before being set)",
	"A", "", "all regs accessed",
	"R", "", "register values read",
	"W", "", "registers written",
	"N", "", "read but never written",
	"V", "", "values",
	"@R", "", "memreads",
	"@W", "", "memwrites",
	"NOTE:", "", "mem{reads,writes} with PIC only fetch the offset",
	NULL
};

static RCoreHelpMessage help_msg_aec = {
	"Examples:", "aec", " continue until ^c",
	"aec", "", "continue until exception",
	"aecs", "", "continue until syscall",
	"aecc", "", "continue until call",
	"aecu", "[addr]", "continue until address",
	"aecue", "[addr]", "continue until esil expression",
	NULL
};

static RCoreHelpMessage help_msg_aeC = {
	"Examples:", "aeC", " arg0 arg1 ... @ calladdr",
	"aeC", " 1 2 @ sym._add", "Call sym._add(1,2)",
	NULL
};

static RCoreHelpMessage help_msg_aeg = {
	"Usage:", "aeg[fniv]", " [...]",
	"aeg", "", "analyze current instruction as an esil graph",
	"aegb", "", "data flow graph for current basic block (aeg `pieq $Fi`)",
	"aegf", "", "analyze given expression and filter for register",
	"aegn", "", "create data flow graph for N instructions",
	"aegv", "", "analyse and launch the visual interactive mode",
	NULL
};

static RCoreHelpMessage help_msg_aep = {
	"Usage:", "aep[-*c] ", " [...] manage esil pins, run r2 commands instead of esil",
	"aepc", " [addr]", "change program counter for esil",
	"aep*", "", "list pins in r2 commands",
	"aep-", "*", "remove all pins",
	"aep-", "[addr]", "remove pin",
	"aep-", "[name]", "remove pin command",
	"aepa", " ([addr])", "auto set pin in current or given address by flag name (see aaep)",
	"aep", " [name] @ [addr]", "set pin",
	"aep ", "memcpy=wf `dr?A1` `dr?A2` @r:A0", "override esil.cmd.pin for this pin name",
	"aep", "", "list pins",
	"aep.", "", "show pin name in current address if any",
	"aepk", " [query]", "kuery the sdb of pins",
	NULL
};

static RCoreHelpMessage help_msg_aek = {
	"Usage:", "aek ", " [...]",
	"aek", "", "dump the esil.stats database contents",
	"aek ", "sdb.query", "evaluate sdb query on esil.stats db",
	"aek-", "", "clear the esil.stats sdb instance",
	NULL
};

static RCoreHelpMessage help_msg_aets = {
	"Usage:", "aets ", " [...]",
	"aets+", "", "start ESIL trace session",
	"aets-", "", "stop ESIL trace session",
	NULL
};

static RCoreHelpMessage help_msg_af = {
	"Usage:", "af", "",
	"af", " ([name]) ([addr])", "analyze functions (start at addr or $$)",
	"af+", " addr name [type] [diff]", "hand craft a function (requires afb+)",
	"af-", " [addr]", "clean all function analysis data (or function at addr)",
	"afa", "", "analyze function arguments in a call (afal honors dbg.funcarg)",
	"afB", " 16", "set current function as thumb (change asm.bits)",
	"afb", "[?] [addr]", "List basic blocks of given function",
	"afb+", " fcnA bbA sz [j] [f] ([t]( [d]))", "add bb to function @ fcnaddr",
	"afbF", "([0|1])", "Toggle the basic-block 'folded' attribute",
	"afc", "[?] type @[addr]", "set calling convention for function",
	"afC[lc]", " ([addr])@[addr]", "calculate the Cycles (afC) or Cyclomatic Complexity (afCc)",
	"afd", "[addr]","show function + delta for given offset",
	"afF", "[1|0|]", "fold/unfold/toggle",
	"afi", " [addr|fcn.name]", "show function(s) information (verbose afl)",
	"afj", " [tableaddr] [elem_sz] [count] [seg]", "analyze function jumptable (adding seg to each elem)",
	"afl", "[?] [ls*] [fcn name]", "list functions (addr, size, bbs, name) (see afll)",
	"afm", " name", "merge two functions",
	"afM", " name", "print functions map",
	"afn", "[?] name [addr]", "rename name for function at address (change flag too)",
	"afna", "", "suggest automatic name for current offset",
	"afo", "[?j] [fcn.name]", "show address for the function name or current offset",
	"afr", " ([name]) ([addr])", "analyze functions recursively",
	"afs", "[!] ([fcnsign])", "get/set function signature at current address (afs! uses cfg.editor)",
	"afS", "[stack_size]", "set stack frame size for function at current address",
	"afsr", " [function_name] [new_type]", "change type for given function",
	"aft", "[?]", "type matching, type propagation",
	"afu", " addr", "resize and analyze function from current address until addr",
	"afv[absrx]", "?", "manipulate args, registers and variables in function",
	"afx", "[m]", "list function references",
	NULL
};

static RCoreHelpMessage help_msg_afb = {
	"Usage:", "afb", " list basic blocks of given function",
	".afbr-", "", "set breakpoint on every return address of the function",
	".afbr-*", "", "remove breakpoint on every return address of the function",
	"afb", " [addr]", "list basic blocks of function",
	"afb.", " [addr]", "show info of current basic block",
	"afb=", "", "display ascii-art bars for basic block regions",
	"afb+", " fcn_at bbat bbsz [jump] [fail] ([diff])", "add basic block by hand",
	"afbc", "[-] [color] ([addr])", "colorize basic block (same as 'abc', afbc- to unset)",
	"afbd", "", "list function basic block dependency list in order and set abe values",
	"afbe", " bbfrom bbto", "add basic-block edge for switch-cases",
	"afbi", "[j]", "print current basic block information",
	"afbj", " [addr]", "show basic blocks information in json",
	"afbr", "", "show addresses of instructions which leave the function",
	"afbt", "", "show basic blocks of current function in a table",
	"afbo", "", "list addresses of each instruction for every basic block in function (see abo)",
	"afB", " [bits]", "define asm.bits for the given function",
	NULL
};

static RCoreHelpMessage help_msg_afc = {
	"Usage:", "afc[agl?]", "# see also tcc command to manage all calling conventions",
	"afc", " ccname", "manually set calling convention for current function",
	"afc", "", "show calling convention for the Current function (same as tcc)",
	"afcr", "[j]", "show register usage for the current function",
	"afcf", "[j] [name]", "prints return type function(arg1, arg2...), see afij",
	"afci", "", "information about the current calling convention",
	"afck", "", "list SDB details of call loaded calling conventions",
	"afcl", "", "list all available calling conventions",
	"afcll", "", "show all call conventions and its definition",
	"afco", " path", "open Calling Convention sdb profile from given path",
	"afcR", "", "register telescoping using the calling conventions order",
	NULL
};

static RCoreHelpMessage help_msg_afC = {
	"Usage:", "afC", " [addr]",
	"afC", "", "function cycles cost",
	"afCc", "", "cyclomatic complexity",
	"afCl", "", "loop count (backward jumps)",
	NULL
};

static RCoreHelpMessage help_msg_afi = {
	"Usage:", "afi[jlp*]", " <addr>",
	"afi", "", "show information of the function",
	"afi", "[.j*]", "function, variables and arguments",
	"afii", "[-][import]", "show/add/delete imports used in function",
	"afil", "", "verbose function info",
	"afip", "", "show whether the function is pure or not",
	"afiq", "", "show quite few info about the function",
	"afis", "", "show function stats (opcode, meta)",
	"afix", "[.j]", "function xrefs information",
	NULL
};

static RCoreHelpMessage help_msg_afis = {
	"Usage:", "afis[ft]", "",
	"afis", "", "enumerate unique opcodes in function",
	"afisa", "[fo]", "enumerate all the meta of all the functions",
	"afisf", "", "enumerate unique opcode families in function",
	"afiso", "", "enumerate unique opcode types in function",
	"afist", " [query]", "list in table format",
	NULL
};

static RCoreHelpMessage help_msg_afl = {
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
	"aflm", "[?]", "list functions in makefile style (af@@=`aflm~0x`)",
	"aflq", "", "list functions in quiet mode",
	"aflqj", "", "list functions in json quiet mode",
	"afls", "[?asn]", "sort function list by address, size or name",
	"aflx", "[?*jv]", "list function xrefs (who references or calls the current function)",
	NULL
};

static RCoreHelpMessage help_msg_afll = {
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

static RCoreHelpMessage help_msg_afn = {
	"Usage:", "afn[sa]", " Analyze function names",
	"afn", " [name]", "rename the function",
	"afn", " base64:encodedname", "rename the function",
	"afn.", "", "same as afn without arguments. show the function name in current offset",
	"afna", "", "construct a function name for the current offset",
	"afns", "", "list all strings associated with the current function",
	"afnsj", "", "list all strings associated with the current function in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_afs = {
	"Usage:", "afs[r]", " Analyze function signatures",
	"afs", "[!] ([fcnsign])", "get/set function signature at current address (afs! uses cfg.editor)",
	"afs*", " ([signame])", "get function signature in flags",
	"afsj", " ([signame])", "get function signature in JSON",
	"afsr", " [function_name] [new_type]", "change type for given function",
	NULL
};

static RCoreHelpMessage help_msg_aft = {
	"Usage:", "aft", "",
	"aft", "", "type matching analysis for current function",
	NULL
};

static RCoreHelpMessage help_msg_afv = {
	"Usage:", "afv[rbs]"," Function variables manipulation",
	"afv*", "", "output r2 command to add args/locals to flagspace",
	"afv-", "([name])", "remove all or given var",
	"afv=", "", "list function variables and arguments with disasm refs",
	"afva", "", "analyze function arguments/locals",
	"afvb", "[?]", "manipulate bp based arguments/locals",
	"afvd", " name", "output r2 command for displaying the value of args/locals in the debugger",
	"afvf", "", "show BP relative stackframe variables",
	"afvn", " [new_name] ([old_name])", "rename argument/local",
	"afvr", "[?]", "manipulate register based arguments",
	"afvR", " [varname]", "list addresses where vars are accessed (READ)",
	"afvs", "[?]", "manipulate sp based arguments/locals",
	"afvt", " [name] [new_type]", "change type for given argument/local",
	"afvW", " [varname]", "list addresses where vars are accessed (WRITE)",
	"afvx", "", "show function variable xrefs (same as afvR+afvW)",
	NULL
};

static RCoreHelpMessage help_msg_aeim = {
	"Usage:", "aeim", " [addr] [size] [name] - initialize the ESIL VM stack",
	"aeim", "", "initialize esil memory with default values from esil.stack.* evals",
	"aeim", " 0x10000", "same as aeim@e:esil.stack.addr=0x10000",
	"aeim", " 0x10000 2M mystack", "give a name to that new 2MB stack",
	NULL
};

static RCoreHelpMessage help_msg_afvb = {
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

static RCoreHelpMessage help_msg_afvr = {
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

static RCoreHelpMessage help_msg_afvs = {
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

static RCoreHelpMessage help_msg_ag = {
	"Usage:", "ag<graphtype><format> [addr]", "",
	"Graph commands:", "", "",
	"aga", "[format]", "data references graph",
	"agA", "[format]", "global data references graph",
	"agc", "[format]", "function callgraph",
	"agC", "[format]", "global callgraph",
	"agd", "[format] [fcn addr]", "diff graph",
	"agf", "[format]", "basic blocks function graph",
	"agi", "[format]", "imports graph",
	"agr", "[format]", "references graph",
	"agR", "[format]", "global references graph",
	"agx", "[format]", "cross references graph",
	"agg", "[format]", "custom graph",
	"agt", "[format]", "tree map graph",
	"ag-", "", "clear the custom graph",
	"agn", "[?] title body", "add a node to the custom graph",
	"age", "[?] title1 title2", "add an edge to the custom graph",
	"","","",
	"Output formats:", "", "",
	"<blank>", "", "ascii art",
	"*", "", "r2 commands",
	"b", "", "braile art rendering (agfb)",
	"d", "", "graphviz dot",
	"g", "", "graph Modelling Language (gml)",
	"j", "", "json ('J' for formatted disassembly)",
	"k", "", "sdb key-value",
	"m", "", "mermaid",
	"t", "", "tiny ascii art",
	"v", "", "interactive ascii art",
	"w", " [path]", "write to path or display graph image (see graph.gv.format)",
	NULL
};

static RCoreHelpMessage help_msg_age = {
	"Usage:", "age [title1] [title2]", "",
	"Examples:", "", "",
	"age", " title1 title2", "add an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age", " \"title1 with spaces\" title2", "add an edge from node \"title1 with spaces\" to node \"title2\"",
	"age-", " title1 title2", "remove an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"ageh", "", "list all the highlighted edges",
	"ageh", " nodeA nodeB", "highlight edge between nodeA and nodeB",
	"ageh-", " nodeA nodeB", "highlight edge between nodeA and nodeB",
	"age?", "", "show this help",
	NULL
};

static RCoreHelpMessage help_msg_agn = {
	"Usage:", "agn [title] [body]", "",
	"Examples:", "", "",
	"agn", " title1 body1", "add a node with title \"title1\" and body \"body1\"",
	"agn", " \"title with space\" \"body with space\"", "add a node with spaces in the title and in the body",
	"agn", " title1 base64:Ym9keTE=", "add a node with the body specified as base64",
	"agn-", " title1", "remove a node with title \"title1\"",
	"agn?", "", "show this help",
	NULL
};

static RCoreHelpMessage help_msg_ah = {
	"Usage:", "ah[lba-]", "analysis Hints",
	"ah?", "", "show this help",
	"ah?", " offset", "show hint of given offset",
	"ah", "", "list hints in human-readable format",
	"ah.", "", "list hints in human-readable format from current offset",
	"ah-", "", "remove all hints",
	"ah-", " offset [size]", "remove hints at given offset",
	"ah*", " offset", "list hints in radare commands format",
	"aha", " ppc @ 0x42", "force arch ppc for all addrs >= 0x42 or until the next hint",
	"aha", " 0 @ 0x84", "disable the effect of arch hints for all addrs >= 0x84 or until the next hint",
	"ahb", "[-*] [8,16,32,64] @ 0x42", "get/set asm.bits for given address and beyond",
	"ahc", " 0x804804", "override call/jump address",
	"ahd", " foo a0,33", "replace opcode string",
	"ahe", " 3,eax,+=", "set vm analysis string",
	"ahf", " 0x804840", "override fallback address for call",
	"ahF", " 0x10", "set stackframe size at current offset",
	"ahh", " 0x804840", "highlight this address offset in disasm",
	"ahi", "[?] 10", "define numeric base for immediates (2, 8, 10, 10u, 16, i, p, S, s)",
	"ahj", "", "list hints in JSON",
	"aho", " call", "change opcode type (see aho?)",
	"ahp", " addr", "set pointer hint",
	"ahr", " val", "set hint for return value of a function",
	"ahs", " 4", "set opcode size=4",
	"ahS", " jz", "set asm.syntax=jz for this opcode",
	"aht", "[s][?] <type>", "mark immediate as a type offset (deprecated, moved to \"aho\")",
	"ahv", " val", "change opcode's val field (useful to set jmptbl sizes in jmp rax)",
	NULL
};

static RCoreHelpMessage help_msg_ahs = {
	"Usage:", "ahs [size] [@ addr]", " Define opcode size hint",
	"ahs", " 16", "Hint the analysis to make the instruction 16 bytes in size",
	"ahs-", "", "Unset the instruction size hint in the current offset",
	"ahs-", "*", "Unset the instruction size hint in the current offset",
	"ahs*", "", "show all the instruction size hints as r2 commands",
	NULL
};

static RCoreHelpMessage help_msg_aho = {
	"Usage:", "aho [optype] [@ addr]", " Define opcode type hint",
	"aho", " nop", "change the opcode type in current address to be considered a NOP",
	"aho", "", "show the current opcode hint if any",
	"aho-", "$$", "delete hints in current offset",
	"aho*", "", "same as above but in r2 commands syntax",
	NULL
};

static RCoreHelpMessage help_msg_ahb = {
	"Usage:", "ahb [8|16|32|64] [@ addr]", " Define asm.bits hint at given address",
	"ahb", " 16", "set asm.bits=16 in the given address",
	"ahb", "", "get asm.bits used in given addr (current seek)",
	"ahb", "-$$", "delete all the hints in the given address",
	"ahb*", "", "show defined bits hints as r2 commands",
	NULL
};

static RCoreHelpMessage help_msg_ahr = {
	"Usage:", "ahr addr", " Set instruction as return type (similar to 'aho ret'?)",
	"ahr", " $$", "current instruction may be considered as the end of a function",
	NULL
};

static RCoreHelpMessage help_msg_ahi = {
	"Usage:", "ahi [2|8|10|10u|16|bodhipSs] [@ offset]", " Define numeric base",
	"ahi", " <base>", "set numeric base (2, 8, 10, 16)",
	"ahi", " 10|d", "set base to signed decimal (10), sign bit should depend on receiver size",
	"ahi", " 10u|du", "set base to unsigned decimal (11)",
	"ahi", " b", "set base to binary (2)",
	"ahi", " o", "set base to octal (8)",
	"ahi", " h", "set base to hexadecimal (16)",
	"ahi", " i", "set base to IP address (32)",
	"ahi", " p", "set base to htons(port) (3)",
	"ahi", " S", "set base to syscall (80)",
	"ahi", " s", "set base to string (1)",
	"ahi1", " 10", "set base of argument 1 to base 10 (same as ahi1 d)",
	NULL
};

static RCoreHelpMessage help_msg_aht = {
	"Usage:", "aht[s] [addr|type]", "mark immediate as type offset (moved to aho)",
	"ahts", " <offset>", "list all matching structure offsets",
	"aht", " <struct.member>", "change immediate to structure offset",
	"aht?", "", "show this help",
	NULL
};

static RCoreHelpMessage help_msg_aot = {
	"Usage:", "aot[l]", "list opcode types",
	"aot", "", "show type of the current instruction",
	"aotl", "", "list all possible opcode types (See /atl)",
	NULL
};

static RCoreHelpMessage help_msg_aom = {
	"Usage:", "aom[ljd] [arg]", "list opcode mnemonics",
	"aom", "", "show instruction mnemonic",
	"aom.", "", "show instruction mnemonic in current address",
	"aoml", "", "list all mnemonics",
	"aomj", "", "list in json format (TODO: add instruction description too?)",
	"aomd", "", "verbose mnemonic listing with instruction description",
	NULL
};

static RCoreHelpMessage help_msg_ao = {
	"Usage:", "ao[e?] [len]", "analyze Opcodes",
	"ao", " 5", "display opcode analysis of 5 opcodes",
	"ao*", "", "display opcode in r commands",
	"aob", " ([hex])", "analyze meaning of every single bit in the current opcode",
	"aoc", " [cycles]", "analyze which op could be executed in [cycles]",
	"aod", " [mnemonic]", "instruction mnemonic description for asm.arch",
	"aoda", "", "show all mnemonic descriptions",
	"aoe", " N", "display esil form for N opcodes",
	"aoem", " N", "display memory references from esil emulation of N opcode",
	"aoef", " expr", "filter esil expression of opcode by given output",
	"aoeq", " N", "display only the esil expression of N opcodes",
	"aoj", " N", "display opcode analysis information in JSON for N opcodes",
	"aom", "[?] [id]", "list current or all mnemonics for current arch",
	"aor", " [N]", "run N esil instructions + esil.dumpstack",
	"aos", " N", "display size of N opcodes",
	"aot", "[?]", "list all opcode types",
	NULL
};

static RCoreHelpMessage help_msg_ar = {
	"Usage: ar", "", "# Analysis Registers",
	"ar", "", "show 'gpr' registers",
	"ar.", ">$snapshot", "show r2 commands to set register values to the current state",
	"ar,", "", "show registers in table format (see dr,)",
	".ar*", "", "import register values as flags",
	".ar-", "", "unflag all registers",
	"ar0", "", "reset register arenas to 0",
	"ara", "[?]", "manage register arenas",
	"arj", "", "show 'gpr' registers in JSON format",
	"arA", "", "show values of function argument calls (A0, A1, A2, ..)",
	"ar", " 16", "show 16 bit registers",
	"ar", " 32", "show 32 bit registers",
	"ar", " all", "show all bit registers",
	"ar", " <type>", "show all registers of given type",
	"arC", "", "display register profile comments",
	"arr", "", "show register references (telescoping)",
	"arrj", "", "show register references (telescoping) in JSON format",
	"ar=", "([size])(:[regs])", "show register values in columns",
	"ar?", " <reg>", "show register value",
	"arb", " <type>", "display hexdump of the given arena",
	"arc", "[cq=] <name>", "conditional flag registers",
	"arcc", "", "derive calling convention from the register profile",
	"ard", " <name>", "show only different registers",
	"arn", " <regalias>", "get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
	"aro", "", "show old (previous) register values",
	"arp", "[?] <file>", "load register profile from file",
	"ars", "", "stack register state",
	"arS", "", "show the size of the register profile",
	"art", "", "list all register types",
	"arw", " <hexnum>", "set contents of the register arena",
	NULL
};

static RCoreHelpMessage help_msg_ara = {
	"Usage:", "ara[+-s]", "register Arena Push/Pop/Swap",
	"ara", "", "show all register arenas allocated",
	"ara", "+", "push a new register arena for each type",
	"ara", "-", "pop last register arena",
	"aras", "", "swap last two register arenas",
	NULL
};

static RCoreHelpMessage help_msg_arw = {
	"Usage:", "arw ", "# Set contents of the register arena",
	"arw", " <hexnum>", "set contents of the register arena",
	NULL
};

static RCoreHelpMessage help_msg_as = {
	"Usage: as[ljk?]", "", "syscall name <-> number utility",
	"as", "", "show current syscall and arguments",
	"as", " 4", "show syscall 4 based on asm.os and current regs/mem",
	"asc[a]", " 4", "dump syscall info in .asm or .h",
	"asj", "", "list of syscalls in JSON",
	"asl", "", "list of syscalls by asm.os and asm.arch",
	"asl", " close", "returns the syscall number for close",
	"asl", " 4", "returns the name of the syscall number 4",
	"ask", " [query]", "perform syscall/ queries",
	NULL
};

static RCoreHelpMessage help_msg_av = {
	"Usage:", "av[?jr*]", " C++ vtables and RTTI",
	"av", "", "search for vtables in data sections and show results",
	"avj", "", "like av, but as json",
	"av*", "", "like av, but as r2 commands",
	"avr", "[j@addr]", "try to parse RTTI at vtable addr (see anal.cxxabi)",
	"avra", "[j]", "search for vtables and try to parse RTTI at each of them",
	"avrr", "", "recover class info from all findable RTTI (see ac)",
	"avrD", " [classname]", "demangle a class name from RTTI",
	NULL
};

static RCoreHelpMessage help_msg_ax = {
	"Usage:", "ax[?d-l*]", " # see also 'afx?'",
	"ax", " addr [at]", "add code ref pointing to addr (from curseek)",
	"ax", "", "list refs",
	"ax*", "", "output radare commands",
	"ax-", " [at]", "clean all refs/refs from addr",
	"ax-*", "", "clean all refs/refs",
	"ax.", " [addr]", "find data/code references from and to this address",
	"axc", " addr [at]", "add generic code ref",
	"axC", " addr [at]", "add code call ref",
	"axd", " addr [at]", "add data ref",
	"axF", " [flg-glob]", "find data/code references of flags",
	"axf", "[?] [addr]", "find data/code references from this address",
	"axff[j]", " [addr]", "find data/code references from this function",
	"axg", " [addr]", "show xrefs graph to reach current function",
	"axg*", " [addr]", "show xrefs graph to given address, use .axg*;aggv",
	"axgj", " [addr]", "show xrefs graph to reach current function in json format",
	"axi", " addr [at]", "add indirect code reference (see ax?)",
	"axj", "", "add jmp reference", // list refs in json format",
	"axl", "[jcq]", "list xrefs (axlc = count, axlq = quiet, axlj = json)",
	"axm", " addr [at]", "copy data/code references pointing to addr to also point to curseek (or at)",
	"axq", "", "list refs in quiet/human-readable format",
	"axr", " addr [at]", "add data-read ref",
	"axs", " addr [at]", "add string ref",
	"axt", "[?] [addr]", "find data/code references to this address",
	"axv", "[?] [addr]", "list local variables read-write-exec references",
	"axw", " addr [at]", "add data-write ref",
	NULL
};

static RCoreHelpMessage help_msg_axl= {
	"Usage:", "axl[jcq]", "show global xrefs",
	"axl", "", "list all xrefs",
	"axlj", "", "list xrefs in json format",
	"axlc", "", "count how many xrefs are registered",
	"axlq", "", "list xrefs in quiet mode (axq)",
	NULL
};

static RCoreHelpMessage help_msg_axv= {
	"Usage:", "axv[?j]", "show xrefs to local variables in current function",
	"axv", " ([addr])", "optionally you can specify address instead of current seek",
	"axvj", " ([addr])", "show in json",
	NULL
};

static RCoreHelpMessage help_msg_axt= {
	"Usage:", "axt[?gq*]", "find data/code references to this address",
	"axtj", " [addr]", "find data/code references to this address and print in json format",
	"axtg", " [addr]", "display commands to generate graphs according to the xrefs",
	"axtq", " [addr]", "find and list the data/code references in quiet mode",
	"axtm", " [addr]", "show xrefs to in 'make' syntax (see aflm and axfm)",
	"axt*", " [addr]", "same as axt, but prints as r2 commands",
	NULL
};

static RCoreHelpMessage help_msg_axf= {
	"Usage:", "axf[?gq*]", "find data/code references from this address",
	"axfj", " [addr]", "find data/code references to this address and print in json format",
	"axfg", " [addr]", "display commands to generate graphs according to the xrefs",
	"axfq", " [addr]", "find and list the data/code references in quiet mode",
	"axfm", " [addr]", "show refs to in 'make' syntax (see aflm and axtm)",
	"axf*", " [addr]", "same as axt, but prints as r2 commands",
	NULL
};

static inline const char *get_arch_name(RCore *core) {
	return r_config_get (core->config, "asm.arch");
}

static int cmpname(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	return (int)strcmp (a->name, b->name);
}

static int cmpsize(const void *a, const void *b) {
	ut64 sa = (int) r_anal_function_linear_size ((RAnalFunction *) a);
	ut64 sb = (int) r_anal_function_linear_size ((RAnalFunction *) b);
	return (sa > sb)? -1: (sa < sb)? 1 : 0;
}

static int cmpbbs(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int la = (int)r_list_length (a->bbs);
	int lb = (int)r_list_length (b->bbs);
	return (la > lb)? -1: (la < lb)? 1 : 0;
}

static int cmpaddr(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	return (a->addr > b->addr)? 1: (a->addr < b->addr)? -1: 0;
}

static bool listOpDescriptions(void *_core, const char *k, const char *v) {
	r_cons_printf ("%s=%s\n", k, v);
	return true;
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

static ut64 faddr(RCore *core, ut64 addr, bool *nr) {
	RList *fcns = r_anal_get_functions_in (core->anal, addr);
	if (fcns && r_list_length (fcns) > 0) {
		RListIter *iter;
		RAnalFunction *fcn;
		r_list_foreach (fcns, iter, fcn) {
			if (nr && fcn->is_noreturn) {
				*nr = true;
			}
			return fcn->addr;
		}
	}
	r_list_free (fcns);
	return addr;
}

// function argument types and names into anal/types
static void __add_vars_sdb(RCore *core, RAnalFunction *fcn) {
	RAnalFcnVarsCache cache;
	r_anal_function_vars_cache_init (core->anal, &cache, fcn);
	RListIter *iter;
	RAnalVar *var;
	size_t arg_count = 0;

	char *args = r_str_newf ("func.%s.args", fcn->name);
	RList *all_vars = cache.rvars;
	r_list_join (all_vars, cache.bvars);
	r_list_join (all_vars, cache.svars);
#if 0
	r_list_foreach (all_vars, iter, var) {
		if (var->isarg) {
			arg_count++;
		}
	}
	int old_arg_count = r_num_get (NULL, args);
	if (old_arg_count >= arg_count) {
		return;
	}
#endif
	r_list_foreach (all_vars, iter, var) {
		if (var->isarg) {
			char *k = r_str_newf ("func.%s.arg.%d", fcn->name, (int)arg_count);
			const char *o = sdb_const_get (core->anal->sdb_types, k, 0);
			char *comma = o? strchr (o, ','): NULL;
			char *db_type = comma? r_str_ndup (o, comma - o): NULL;
			char *db_name = comma? strdup (comma + 1): NULL;
			if (!strstr (var->name, "arg_") || (o && strstr (o, ",arg_"))) {
				// #if 0
				char *ks = r_str_newf ("func.%s.arg.%d", fcn->name, (int)arg_count);
				// eprintf ("VARNAME %s %s %c", var->name, db_name, 10);
				// eprintf ("VARTYPE %s %s %c", var->type,db_type, 10);
				char *type = db_type && strstr (var->type, "arg_")? db_type: var->type;
				char *v = r_str_newf ("%s,%s", type, var->name);
				sdb_set (core->anal->sdb_types, ks, v, 0);
				free (ks);
				free (v);
			} else {
				char *name = db_name? db_name: var->name;
				char *type = strdup (db_type? db_type: var->type);
				// eprintf ("VARTYPE1 %s %s %c", var->type,db_type, 10);
				if (var->name && !strstr (var->name, "arg_")) {
					o = NULL;
				}
#if 0
				if (name != var->name) {
					o = NULL;
				} else {
					type = strdup (var->type);
				}
#endif
				char *v = comma? strdup (o): r_str_newf ("%s,%s", type, name);
				/// eprintf("arg (%s) %s -- %s%c", k, v, var->name, 10);
				char *s = strdup (name);
				if (o) {
					char *v2 = r_str_newf ("%s,%s", var->type, name);
					if (!strstr (var->name, ",arg_")) {
						free (var->name);
						var->name = s;
					} else {
						free (s);
					}
					// sdb_set (core->anal->sdb_types, k, v, 0);
					free (v2);
				} else {
					free (var->name);
					var->name = s;
					sdb_set (core->anal->sdb_types, k, v, 0);
				}
				free (v);
				free (type);
				// #endif
			}
			free (db_name);
			free (db_type);
			free (k);
			arg_count++;
		}
	}
	//	sdb_num_set (core->anal->sdb_types, args, (int)arg_count, 0);
	if (arg_count > 0) {
		char *k = r_str_newf ("func.%s.args", fcn->name);
		char *v = r_str_newf ("%d", (int)arg_count);
		sdb_set (core->anal->sdb_types, k, v, 0);
		// sdb_num_set (core->anal->sdb_types, k, (ut64)arg_count, 0);
		free (k);
		free (v);
 	}
	free (args);
	r_anal_function_vars_cache_fini (&cache);
}

static bool cmd_anal_aaft(RCore *core) {
	RListIter *it;
	RAnalFunction *fcn;
	ut64 seek;
	const char *io_cache_key = "io.pcache.write";
	bool io_cache = r_config_get_b (core->config, io_cache_key);
	if (r_config_get_b (core->config, "cfg.debug")) {
		R_LOG_WARN ("aaft is disabled in debugger mode");
		return false;
	}
	if (!io_cache) {
		// XXX. we shouldnt need this, but it breaks 'r2 -c aaa -w ls'
		r_config_set_i (core->config, io_cache_key, true);
	}
	const bool iova = r_config_get_b (core->config, "io.va");
	seek = core->offset;
	r_reg_arena_push (core->anal->reg);
	r_reg_arena_zero (core->anal->reg);
	r_core_cmd_call (core, "aei");
	r_core_cmd_call (core, "aeim");
	int saved_arena_size = 0;
	ut8 *saved_arena = r_reg_arena_peek (core->anal->reg, &saved_arena_size);
	// Iterating Reverse so that we get function in top-bottom call order
	r_list_foreach_prev (core->anal->fcns, it, fcn) {
		int ret = r_core_seek (core, fcn->addr, true);
		if (!ret) {
			continue;
		}
		r_reg_arena_poke (core->anal->reg, saved_arena, saved_arena_size);
		r_esil_set_pc (core->anal->esil, fcn->addr);
		r_core_anal_type_match (core, fcn);
		if (r_cons_is_breaked ()) {
			break;
		}
		__add_vars_sdb (core, fcn);
	}
	r_config_set_b (core->config, "io.va", iova);
	r_core_seek (core, seek, true);
	r_reg_arena_pop (core->anal->reg);
	r_config_set_i (core->config, io_cache_key, io_cache);
	free (saved_arena);
	return true;
}

static void type_cmd(RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	if (!fcn && *input != '?') {
		R_LOG_WARN ("cant find function here");
		return;
	}
	ut64 seek;
	r_cons_break_push (NULL, NULL);
	switch (*input) {
	case '\0': // "aft"
		seek = core->offset;
		r_esil_set_pc (core->anal->esil, fcn? fcn->addr: core->offset);
		r_core_anal_type_match (core, fcn);
		r_core_seek (core, seek, true);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_aft);
		break;
	}
	r_cons_break_pop ();
}

static void find_refs(RCore *core, const char *glob) {
	ut64 curseek = core->offset;
	glob = r_str_trim_head_ro (glob);
	if (!*glob) {
		glob = "str.";
	}
	if (*glob == '?') {
		r_core_cmd_help_match (core, help_msg_ax, "axF", true);
		return;
	}
	R_LOG_WARN ("Finding references of flags matching '%s'", glob);
	char *cmd = r_str_newf (".(findstref) @@=`f~%s[0]`", glob);
	r_core_cmd0 (core, "(findstref;f here=$$;s entry0;/r here;f-here)");
	r_core_cmd0 (core, cmd);
	r_core_cmd0 (core, "(-findstref)");
	r_core_seek (core, curseek, true);
	free (cmd);
}

static ut64 sort64val(const void *a) {
	ut64 *na = (ut64*)a;
	return *na;
}
static int sort64(const void *a, const void *b) {
	ut64 *na = (ut64*)a;
	ut64 *nb = (ut64*)b;
	return *na - *nb;
}

static RList *collect_addresses(RCore *core) {
#if 0
	WIP: return addresses where functions start from different sources:
	* [x] symbols
	* [ ] exports
	* [ ] prelude search
	* [ ] call ref analysis
	result is then sorted and uniqified
#endif
	RList *list = r_list_newf (free);
	RBinSymbol *sym;
	RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
	R_VEC_FOREACH (symbols, sym) {
		r_list_append (list, ut64_new (sym->vaddr));
	}
	// find all calls and mark the destinations as function entrypoints
	// r_core_search_preludes (core, true); // __prelude_cb_hit uses globals and calls 'af', should be changed to just return a list for later processing
	r_list_sort (list, sort64);
	r_list_uniq_inplace (list, sort64val);
	return list;
}

static void single_block_analysis(RCore *core) {
	const ut64 max_fcn_size = 1024 * 1024;
	RList *list = collect_addresses (core);
	RListIter *iter;
	ut64 *addr;
	r_list_foreach (list, iter, addr) {
		ut64 *next = iter->n? iter->n->data: addr;
		int len = (*next) - *addr;
		if (len > 0 && len < max_fcn_size) {
			ut64 at = *addr;
			if (r_anal_get_function_at (core->anal, at)) {
				continue;
			}
			RFlagItem *fi = r_flag_get_at (core->flags, at, false);
			char *name = (fi) ? strdup (fi->name): r_str_newf ("fcn.%08"PFMT64x, at);
			RAnalFunction *fcn = r_anal_create_function (core->anal, name, at, 0, NULL);
			if (fcn) {
				r_anal_function_add_bb (core->anal, fcn, at, len, UT64_MAX, UT64_MAX, 0);
			}
			free (name);
		}
	}
	r_list_free (list);
}

/* set flags for every function */
static void flag_every_function(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_flag_space_push (core->flags, R_FLAGS_FS_FUNCTIONS);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		r_flag_set (core->flags, fcn->name,
			fcn->addr, r_anal_function_size_from_entry (fcn));
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
	default:
		r_core_cmd_help (core, help_msg_afv);
		break;
	}
}

static void var_accesses_list(RAnalFunction *fcn, RAnalVar *var, PJ *pj, int access_type, const char *name) {
	RAnalVarAccess *acc;
	bool first = true;
	if (r_vector_empty (&var->accesses)) {
		R_LOG_WARN ("Variable '%s' have no references?", name);
	}
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "name", name);
		pj_ka (pj, "addrs");
	} else {
		r_cons_printf ("%10s", name);
	}
	r_vector_foreach (&var->accesses, acc) {
		if (!(acc->type & access_type)) {
			continue;
		}
		ut64 addr = fcn->addr + acc->offset;
		if (pj) {
			pj_n (pj, addr);
		} else {
			r_cons_printf ("%s0x%" PFMT64x, first ? "  " : ",", addr);
		}
		first = false;
	}
	if (pj) {
		pj_end (pj);
		pj_end (pj);
	} else {
		r_cons_newline ();
	}
}

static void list_vars(RCore *core, RAnalFunction *fcn, PJ *pj, int type, const char *name) {
	RAnalVar *var = NULL;
	RListIter *iter;
	RList *list = r_anal_var_all_list (core->anal, fcn);
	if (type == '=') {
		ut64 oaddr = core->offset;
		r_list_foreach (list, iter, var) {
			r_cons_printf ("* %s\n", var->name);
			RAnalVarAccess *acc;
			r_vector_foreach (&var->accesses, acc) {
				if (!(acc->type & R_ANAL_VAR_ACCESS_TYPE_READ)) {
					continue;
				}
				r_cons_printf ("R 0x%"PFMT64x"  ", fcn->addr + acc->offset);
				r_core_seek (core, fcn->addr + acc->offset, 1);
				r_core_print_disasm_instructions (core, 0, 1);
			}
			r_vector_foreach (&var->accesses, acc) {
				if (!(acc->type & R_ANAL_VAR_ACCESS_TYPE_WRITE)) {
					continue;
				}
				r_cons_printf ("W 0x%"PFMT64x"  ", fcn->addr + acc->offset);
				r_core_seek (core, fcn->addr + acc->offset, 1);
				r_core_print_disasm_instructions (core, 0, 1);
			}
		}
		r_core_seek (core, oaddr, 0);
		r_list_free (list);
		return;
	}
	if (type == '*') {
		const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
		r_cons_printf ("f-fcnvar*\n");
		r_list_foreach (list, iter, var) {
			r_cons_printf ("f fcnvar.%s @ %s%s%d\n", var->name, bp,
				var->delta >= 0? "+":"", var->delta);
		}
		r_list_free (list);
		return;
	}
	if (type != 'W' && type != 'R') {
		r_list_free (list);
		return;
	}
	int access_type = type == 'R' ? R_ANAL_VAR_ACCESS_TYPE_READ : R_ANAL_VAR_ACCESS_TYPE_WRITE;
	if (pj) {
		pj_a (pj);
	}
	if (name && *name) {
		var = r_anal_function_get_var_byname (fcn, name);
		if (var) {
			var_accesses_list (fcn, var, pj, access_type, var->name);
		}
	} else {
		r_list_foreach (list, iter, var) {
			var_accesses_list (fcn, var, pj, access_type, var->name);
		}
	}
	if (pj) {
		pj_end (pj);
	}
	r_list_free (list);
}

static void cmd_afvx(RCore *core, RAnalFunction *fcn, bool json) {
	r_return_if_fail (core);
	if (!fcn) {
		fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_ANY);
	}
	if (fcn) {
		PJ *pj = NULL;
		if (json) {
			pj = pj_new ();
			pj_o (pj);
			pj_k (pj, "reads");
		} else {
			r_cons_printf ("afvR\n");
		}
		list_vars (core, fcn, pj, 'R', NULL);
		if (json) {
			pj_k (pj, "writes");
		} else {
			r_cons_printf ("afvW\n");
		}
		list_vars (core, fcn, pj, 'W', NULL);
		if (json) {
			pj_end (pj);
			char *j = pj_drain (pj);
			r_cons_printf ("%s\n", j);
			free (j);
		}
	}
}

static int cmd_an(RCore *core, const char *name, int mode) {
	int ret = 0;
	RAnalOp op = {0};
	PJ *pj = NULL;

	if (mode == 'j') {
		pj = pj_new ();
		pj_a (pj);
	}
	if (r_anal_op (core->anal, &op, core->offset, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC) < 1) {
		goto failure;
	}
	RAnalVar *var = r_anal_get_used_function_var (core->anal, op.addr);

	ut64 tgt_addr = op.jump != UT64_MAX? op.jump: op.ptr;
	if (var) {
		if (name) {
			ret = r_anal_var_rename (var, name, true) ? 0 : -1;
		} else if (mode == '*') {
			r_cons_printf ("f %s=0x%" PFMT64x "\n", var->name, tgt_addr);
		} else if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "name", var->name);
			pj_ks (pj, "type", "var");
			pj_kn (pj, "offset", tgt_addr);
			pj_end (pj);
		} else {
			r_cons_println (var->name);
		}
	} else {
		if (tgt_addr == UT64_MAX) {
			tgt_addr = core->offset;
		}
		RFlagItem *f = r_flag_get_by_spaces (core->flags, tgt_addr, R_FLAGS_FS_SYMBOLS, R_FLAGS_FS_IMPORTS, NULL);
		if (!f) {
			f = r_flag_get_i (core->flags, tgt_addr);
		}
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, tgt_addr);
		if (fcn) {
			if (name) {
				ret = r_anal_function_rename (fcn, name)? 0: -1;
			} else if (mode == '*') {
				r_cons_printf ("f %s=0x%" PFMT64x "\n", fcn->name, core->offset);
			} else if (mode == 'j') {
				pj_o (pj);
				pj_ks (pj, "name", fcn->name);
				pj_ks (pj, "type", "function");
				pj_kn (pj, "offset", tgt_addr);
				pj_end (pj);
			} else {
				r_cons_println (fcn->name);
			}
		} else if (f) {
			if (name) {
				ret = r_flag_rename (core->flags, f, name)? 0: -1;
			} else if (mode == '*') {
				r_cons_printf ("f %s=0x%" PFMT64x "\n", r_str_get (name), core->offset);
			} else if (mode == 'j') {
				pj_o (pj);
				pj_ks (pj, "name", f->name);
				if (f->realname) {
					pj_ks (pj, "realname", f->realname);
				}
				pj_ks (pj, "type", "flag");
				pj_kn (pj, "offset", tgt_addr);
				pj_end (pj);
			} else {
				r_cons_println (f->name);
			}
		} else {
			if (name) {
				ret = r_flag_set (core->flags, name, tgt_addr, 1)? 0: -1;
			} else if (mode == '*') {
				r_cons_printf ("f %s=0x%" PFMT64x "\n", r_str_get (name), core->offset);
			} else if (mode == 'j') {
				pj_o (pj);
				pj_ks (pj, "name", r_str_get (name));
				pj_ks (pj, "type", "address");
				pj_kn (pj, "offset", tgt_addr);
				pj_end (pj);
			} else {
				r_cons_printf ("0x%" PFMT64x "\n", tgt_addr);
			}
		}
	}
failure:
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}

	r_anal_op_fini (&op);
	return ret;
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
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	if (!fcn) {
		switch (str[0]) {
		case '?':
			r_core_cmd_help (core, help_msg_afv);
			break;
		case 'j':
			r_cons_println ("{}");
			break;
		default:
			R_LOG_ERROR ("No function found in current offset");
			break;
		}
		return false;
	}
	if (!str[0]) {
		if (fcn) {
			// "afv"
			r_core_cmd_call (core, "afvr");
			r_core_cmd_call (core, "afvs");
			r_core_cmd_call (core, "afvb");
		} else {
			R_LOG_WARN ("Cannot find function in 0x%08"PFMT64x, core->offset);
		}
		return true;
	}
	if (str[1] == '?'|| str[0] == '?') {
		var_help (core, *str);
		return res;
	}
	PJ *pj = NULL;
	if (str[0] == 'j') { // "afvj"
		pj = r_core_pj_new (core);
		if (!pj) {
			return false;
		}
		pj_o (pj);
		pj_k (pj, "reg");
		r_anal_var_list_show (core->anal, fcn, 'r', 'j', pj);
		pj_k (pj, "sp");
		r_anal_var_list_show (core->anal, fcn, 's', 'j', pj);
		pj_k (pj, "bp");
		r_anal_var_list_show (core->anal, fcn, 'b', 'j', pj);
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
		return true;
	}
	char *p = strdup (str);
	char *ostr = p;
	/* Variable access CFvs = set fun var */
	switch (str[0]) {
	case '-': // "afv-"
		r_core_cmdf (core, "afvr-%s", str + 1);
		r_core_cmdf (core, "afvs-%s", str + 1);
		r_core_cmdf (core, "afvb-%s", str + 1);
		return true;
	case 'x': // "afvx"
		if (fcn) {
			cmd_afvx (core, fcn, str[1] == 'j');
		} else {
			R_LOG_WARN ("Cannot find function in 0x%08"PFMT64x, core->offset);
		}
		free (ostr);
		return true;
	case 'R': // "afvR"
	case 'W': // "afvW"
	case '*': // "afv*"
	case '=': // "afv="
		if (fcn) {
			const char *name = strchr (ostr, ' ');
			if (name) {
				name = r_str_trim_head_ro (name);
			}
			if (str[1] == 'j') {
				pj = r_core_pj_new (core);
				if (!pj) {
					return false;
				}
			}
			list_vars (core, fcn, pj, str[0], name);
			if (str[1] == 'j') {
				pj_end (pj);
				r_cons_println (pj_string (pj));
				pj_free (pj);
			}
			free (ostr);
			return true;
		} else {
			R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, core->offset);
			free (ostr);
			return false;
		}
	case 'a': // "afva"
		if (fcn) {
			char *type = r_str_newf ("func.%s.ret", fcn->name);
			if (type && sdb_exists (core->anal->sdb_types, type)) {
				// if function type exists
				// do not analize vars if function has a signature
			} else {
				r_anal_function_delete_all_vars (fcn);
				r_core_recover_vars (core, fcn, false);
			}
			free (type);
			free (p);
			return true;
		} else {
			R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, core->offset);
			return false;
		}
	case 'n': // "afvn"
		if (str[1]) {
			RAnalOp *op = r_core_anal_op (core, core->offset, R_ARCH_OP_MASK_BASIC);
			const char *new_name = r_str_trim_head_ro (strchr (ostr, ' '));
			if (!new_name) {
				r_anal_op_free (op);
				free (ostr);
				return false;
			}
			char *old_name = strchr (new_name, ' ');
			if (!old_name) {
				RAnalVar *var = op ? r_anal_get_used_function_var (core->anal, op->addr) : NULL;
				if (var) {
					old_name = var->name;
				} else {
					R_LOG_ERROR ("Cannot find var @ 0x%08"PFMT64x, core->offset);
					r_anal_op_free (op);
					free (ostr);
					return false;
				}
			} else {
				*old_name++ = 0;
				r_str_trim (old_name);
			}
			if (fcn) {
				v1 = r_anal_function_get_var_byname (fcn, old_name);
				if (v1) {
					r_anal_var_rename (v1, new_name, true);
				} else {
					R_LOG_ERROR ("Cant find var by name");
				}
			} else {
				R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, core->offset);
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
			r_list_free (list);
		}
		return true;
	case 'd': // "afvd"
		if (!fcn) {
			R_LOG_ERROR ("Cannot find function");
		} else if (str[1]) {
			p = strchr (ostr, ' ');
			if (!p) {
				free (ostr);
				return false;
			}
			r_str_trim (p);
			v1 = r_anal_function_get_var_byname (fcn, p);
			if (!v1) {
				free (ostr);
				return false;
			}
			r_anal_var_display (core->anal, v1);
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
				r_cons_printf ("%s %s = %s", p->isarg? "arg": "var", p->name, a);
				free (a);
			}
			r_list_free (list);
		}
		free (ostr);
		return true;
	case 'f': // "afvf"
		__cmd_afvf (core, ostr);
		break;
	case 't': // "afvt"
		if (fcn) {
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
			v1 = r_anal_function_get_var_byname (fcn, p);
			if (!v1) {
				R_LOG_ERROR ("Cant find get by name %s", p);
				free (ostr);
				return false;
			}
			r_anal_var_set_type (v1, type);
			free (ostr);
			return true;
		} else {
			R_LOG_ERROR ("Cannot find function");
			return false;
		}
	case 'b': // "afvb"
	case 's': // "afbs"
	case 'r': // "afbr"
		break;
	default:
		if (str[0]) {
			r_core_cmd_help (core, help_msg_afv);
			return false;
		}
	}
	switch (str[1]) { // afv[bsr]
	case '\0':
	case '*': // "afv[bsr]*"
		if (fcn) {
			r_anal_var_list_show (core->anal, fcn, type, str[1], NULL);
		} else {
			R_LOG_ERROR ("Cannot find function");
		}
		break;
	case 'j':  // "afv[bsr]j"
		pj = r_core_pj_new (core);
		if (!pj) {
			return false;
		}
		if (fcn) {
			r_anal_var_list_show (core->anal, fcn, type, str[1], pj);
			r_cons_println (pj_string (pj));
		} else {
			R_LOG_ERROR ("No function");
		}
		pj_free (pj);
		break;
	case '.': // "afv[bsr]."
		r_anal_var_list_show (core->anal, fcn, core->offset, 0, NULL);
		break;
	case '-': // "afv[bsr]-"
		if (!fcn) {
			R_LOG_ERROR ("afv: Cannot find function");
			return false;
		}
		if (str[2] == '*') {
			r_anal_function_delete_vars_by_kind (fcn, type);
		} else {
			RAnalVar *var = NULL;
			if (IS_DIGIT (str[2])) {
				var = r_anal_function_get_var (fcn, type, (int)r_num_math (core->num, str + 1));
			} else {
				char *name = r_str_trim_dup (str + 2);
				if (name) {
					var = r_anal_function_get_var_byname (fcn, name);
					r_free (name);
				}
			}
			if (var) {
				r_anal_var_delete (var);
			}
		}
		break;
	case 's': // "afv[bsr]s" // "afvs"
	case 'g': // "afv[bsr]g"
		if (str[2]) {
			int idx = r_num_math (core->num, str + 2);
			char *vaddr;
			p = strchr (ostr, ' ');
			if (!p) {
				var_help (core, type);
				break;
			}
			r_str_trim (p);
			ut64 addr = core->offset;
			if ((vaddr = strchr (p, ' '))) {
				addr = r_num_math (core->num, vaddr);
			}
			RAnalVar *var = r_anal_function_get_var (fcn, str[0], idx);
			if (!var) {
				R_LOG_ERROR ("Cannot find variable with delta %d", idx);
				res = false;
				break;
			}
			int rw = (str[1] == 'g') ? R_ANAL_VAR_ACCESS_TYPE_READ : R_ANAL_VAR_ACCESS_TYPE_WRITE;
			int ptr = *var->type == 's' ? idx - fcn->maxstack : idx;
			RAnalOp *op = r_core_anal_op (core, addr, 0);
			const char *ireg = op ? op->ireg : NULL;
			r_anal_var_set_access (var, ireg, addr, rw, ptr);
			r_anal_op_free (op);
		} else {
			R_LOG_ERROR ("Missing argument");
		}
		break;
	case ' ': { // "afvs" "afvb" "afvr"
		bool isarg = false;
		const int size = 4;
		p = strchr (ostr, ' ');
		if (!p) {
			var_help (core, type);
			break;
		}
		if (!fcn) {
			R_LOG_ERROR ("Missing function at 0x%08" PFMT64x, core->offset);
			break;
		}
		*p++ = 0;
		r_str_trim_head (p);
		char *name = strchr (p, ' ');
		if (!name) {
			R_LOG_ERROR ("Missing name");
			break;
		}
		*name++ = 0;
		r_str_trim_head (name);

		if (type == 'r') { //registers
			RRegItem *ri = r_reg_get (core->anal->reg, p, -1);
			if (!ri) {
				R_LOG_ERROR ("Register not found");
				break;
			}
			delta = ri->index;
			isarg = true;
			r_unref (ri);
		} else {
			delta = r_num_math (core->num, p);
		}

		char *vartype = strchr (name, ' ');
		if (!vartype) {
			vartype = "int";
		} else {
			*vartype++ = 0;
			r_str_trim (vartype);
		}
		if (type == 'b') {
			delta -= fcn->bp_off;
		}
		if ((type == 'b') && delta > 0) {
			isarg = true;
		} else if (type == 's' && delta > fcn->maxstack) {
			isarg = true;
		}
		r_anal_function_set_var (fcn, delta, type, vartype, size, isarg, name);
 		}
		break;
	default:
		r_core_cmd_help (core, help_msg_afv);
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
				r_cons_printf ("f trampoline.%" PFMT32x " @ 0x%" PFMT64x "\n", n, core->offset + i);
			}
			r_cons_printf ("Cd %u @ 0x%" PFMT64x ":%u\n", (unsigned int)element_size, core->offset + i, (unsigned int)element_size);
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

static const char *syscallNumber(char *snstr, int n) {
	snprintf (snstr, 32, (n>1000)?"0x%x": "%d", n);
	return snstr;
}

R_API char *cmd_syscall_dostr(RCore *core, st64 n, ut64 addr) {
	int i;
	char str[64], snstr[32];
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
		return r_str_newf ("%s = unknown ()", syscallNumber (snstr, n));
	}
	char *res = r_str_newf ("%s = %s (", syscallNumber (snstr, item->num), item->name);
	// TODO: move this to r_syscall
	const char *cc = r_anal_syscc_default (core->anal);
	//TODO replace the hardcoded CC with the sdb ones
	for (i = 0; i < item->args; i++) {
		// XXX this is a hack to make syscall args work on x86-32 and x86-64
		// we need to shift sn first.. which is bad, but needs to be redesigned
		int regidx = i;
		if (core->rasm->config->bits == 32 && !strcmp (core->rasm->config->arch, "x86")) {
			regidx++;
		}
		ut64 arg = r_debug_arg_get (core->dbg, cc, regidx);
		//r_cons_printf ("(%d:0x%"PFMT64x")\n", i, arg);
		if (item->sargs) {
			switch (item->sargs[i]) {
			case 'p': // pointer
				res = r_str_appendf (res, "0x%08" PFMT64x, arg);
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
				ut64 len = r_debug_arg_get (core->dbg, cc, i + 2);
				len = R_MIN (len + 1, sizeof (str) - 1);
				if (len == 0) {
					len = 16; // override default
				}
				(void)r_io_read_at (core->io, arg, (ut8 *)str, len);
				str[len] = 0;
				r_str_filter (str, -1);
				res = r_str_appendf (res, "\"%s\"", str);
				break;
			}
			default:
				res = r_str_appendf (res, "0x%08" PFMT64x, arg);
			}
		} else {
			res = r_str_appendf (res, "0x%08" PFMT64x, arg);
		}
		if (i + 1 < item->args) {
			res = r_str_append (res, ", ");
		}
	}
	r_syscall_item_free (item);
	return r_str_append (res, ")");
}

static bool mw(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	int *ec = (int*)esil->user;
	*ec += (len * 2);
	return true;
}

static bool mr(REsil *esil, ut64 addr, ut8 *buf, int len) {
	int *ec = (int*)esil->user;
	*ec += len;
	return true;
}

static int esil_cost(RCore *core, ut64 addr, const char *expr) {
	if (R_STR_ISEMPTY (expr)) {
		return 0;
	}
	int ec = 0;
	REsil *e = r_esil_new (256, 0, 0);
	r_esil_setup (e, core->anal, false, false, false);
	e->user = &ec;
	e->cb.mem_read = mr;
	e->cb.mem_write = mw;
	r_esil_parse (e, expr);
	r_esil_free (e);
	return ec;
}

static void cmd_syscall_do(RCore *core, st64 n, ut64 addr) {
	char *msg = cmd_syscall_dostr (core, n, addr);
	if (msg) {
		r_cons_println (msg);
		free (msg);
	}
}

static inline REsil *esil_new_setup(RCore *core) {
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	bool iotrap = r_config_get_b (core->config, "esil.iotrap");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	REsil *esil = r_esil_new (stacksize, iotrap, addrsize);
	if (esil) {
		esil->anal = core->anal;
		r_io_bind (core->io, &(core->anal->iob));
		bool romem = r_config_get_b (core->config, "esil.romem");
		bool stats = r_config_get_b (core->config, "esil.stats");
		bool nonull = r_config_get_b (core->config, "esil.nonull");
		r_esil_setup (esil, core->anal, romem, stats, nonull);
		esil->verbose = r_config_get_i (core->config, "esil.verbose");
		esil->cmd = r_core_esil_cmd;
		const char *et = r_config_get (core->config, "cmd.esil.trap");
		esil->cmd_trap = R_STR_ISNOTEMPTY (et)? strdup (et): NULL;

	}
	return esil;
}

static void val_tojson(PJ *pj, RAnalValue *val) {
	char *s = r_anal_value_tostring (val);
	pj_o (pj);
	pj_ks (pj, "name", s);
	free (s);
	pj_ks (pj, "type", r_anal_value_type_tostring (val));
	if (val->access) {
		pj_ks (pj, "access", (val->access & R_PERM_W)? "rw": "ro");
	}
	if (val->absolute) {
		pj_kn (pj, "absolute", val->absolute);
	}
	if (val->imm) {
		pj_kn (pj, "imm", val->imm);
	}
	if (val->delta) {
		pj_kn (pj, "delta", val->delta);
	}
	if (val->mul) {
		pj_kn (pj, "mul", val->mul);
	}
	pj_end (pj);
}


static bool mw2(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	r_cons_printf ("WRITE 0x%08"PFMT64x" %d\n", addr, len);
	return true;
}

static bool mr2(REsil *esil, ut64 addr, ut8 *buf, int len) {
	r_cons_printf ("READ 0x%08"PFMT64x" %d\n", addr, len);
	return true;
}

static void esilmemrefs(RCore *core, const char *expr) {
	REsil *e = r_esil_new (256, 0, 0);
	r_esil_setup (e, core->anal, false, false, false);
	e->cb.mem_read = mr2;
	e->cb.mem_write = mw2;
	r_esil_parse (e, expr);
	r_esil_free (e);
}

static void core_anal_bytes(RCore *core, const ut8 *buf, int len, int nops, int fmt) {
	bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	core->parser->subrel = r_config_get_i (core->config, "asm.sub.rel");
	int ret, i, j, idx, size;
	const char *color = "";
	const char *esilstr;
	const char *opexstr;
	RAnalHint *hint;
	RAnalOp op = {0};
	ut64 addr;
	PJ *pj = NULL;
	int totalsize = 0;
#if 1
	REsil *esil = r_esil_new (256, 0, 0);
	r_esil_setup (esil, core->anal, false, false, false);
	esil->user = &core;
	esil->cb.mem_read = mr;
	esil->cb.mem_write = mw;
#else
	REsil *esil = core->anal->esil;
	//esil->user = &ec;
	esil->cb.mem_read = mr;
	esil->cb.mem_write = mw;
#endif

	// Variables required for setting up ESIL to REIL conversion
	if (use_color) {
		color = core->cons->context->pal.label;
	}
	switch (fmt) {
	case 'j': {
		pj = r_core_pj_new (core);
		if (!pj) {
			break;
		}
		pj_a (pj);
		break;
	}
	}
	const bool smart_mask = r_config_get_b (core->config, "anal.mask");
	for (i = idx = ret = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		RAnalOp asmop = {0};
		addr = core->offset + idx;
		r_asm_set_pc (core->rasm, addr);
		hint = r_anal_hint_get (core->anal, addr);
		ret = r_anal_op (core->anal, &op, addr, buf + idx, len - idx,
			R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_OPEX | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_DISASM);
		(void)r_asm_disassemble (core->rasm, &asmop, buf + idx, len - idx);
		esilstr = R_STRBUF_SAFEGET (&op.esil);
		opexstr = R_STRBUF_SAFEGET (&op.opex);
		char *mnem = strdup (r_str_get (r_asm_op_get_asm (&asmop)));
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
			ret = op.size;
#if 0
			RStrBuf *sb = r_strbuf_new ("");
			for (i = idx, j = 0; i < core->blocksize && j < 3; i++, j++) {
				r_strbuf_appendf (sb, "%02x ", buf[i]);
			}
			R_LOG_ERROR ("Oops at 0x%08" PFMT64x " (%s...)", core->offset + idx, r_strbuf_get (sb));
			r_strbuf_free (sb);
			free (mnem);
			break;
#endif
		}
		size = op.size;
		if (fmt == 'd') {
			char *opname = strdup (r_asm_op_get_asm (&asmop));
			if (opname) {
				r_str_split (opname, ' ');
				char *d = r_asm_describe (core->rasm, opname);
				if (R_STR_ISNOTEMPTY (d)) {
					r_cons_printf ("%s: %s\n", opname, d);
					free (d);
				} else {
					R_LOG_ERROR ("Unknown opcode at 0x%08"PFMT64x, addr);
				}
				free (opname);
			}
		} else if (fmt == 'm') {
			esilmemrefs (core, esilstr);
		} else if (fmt == 'E') {
			r_cons_printf ("%s\n", esilstr);
		} else if (fmt == 'e') {
			if (R_STR_ISNOTEMPTY (esilstr)) {
				if (use_color) {
					r_cons_printf ("%s0x%" PFMT64x Color_RESET " %s\n", color, core->offset + idx, esilstr);
				} else {
					r_cons_printf ("0x%" PFMT64x " %s\n", core->offset + idx, esilstr);
				}
			}
		} else if (fmt == 's') {
			totalsize += op.size;
		} else if (fmt == '*') {
			// TODO: ao* useful for wat? wx [bytes] ?
		} else if (fmt == 'j') {
			char strsub[128] = {0};
			// pc+33
			r_parse_subvar (core->parser, NULL,
				core->offset + idx,
				asmop.size, r_asm_op_get_asm (&asmop),
				strsub, sizeof (strsub));
				ut64 killme = UT64_MAX;
				if (r_io_read_i (core->io, op.ptr, &killme, op.refptr, be)) {
					core->parser->subrel_addr = killme;
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
					r_parse_subvar (core->parser, fcn, addr, asmop.size,
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
				char *d = r_asm_describe (core->rasm, opname);
				if (d && *d) {
					pj_ks (pj, "description", d);
				}
				free (d);
				free (opname);
			}

			if (r_vector_length (&op.srcs) > 0) {
				pj_ka (pj, "srcs");
				RAnalValue *val;
				r_vector_foreach (&op.srcs, val) {
					val_tojson (pj, val);
				}
				pj_end (pj);
			}

			if (r_vector_length (&op.dsts) > 0) {
				pj_ka (pj, "dsts");
				RAnalValue *val;
				r_vector_foreach (&op.dsts, val) {
					val_tojson (pj, val);
				}
				pj_end (pj);
			}

			pj_ks (pj, "mnemonic", mnem);
			if (smart_mask) {
				char *maskstr = r_core_cmd_strf (core, "aobm@0x%08"PFMT64x, op.addr);
				pj_ks (pj, "mask", maskstr);
				free (maskstr);
			} else {
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
			if (op.prefix > 0) {
				pj_kn (pj, "prefix", op.prefix);
			}
			pj_ki (pj, "id", op.id);
			if (op.vliw > 0) {
				pj_ki (pj, "id", op.vliw);
			}
			if (opexstr && *opexstr) {
				pj_k (pj, "opex");
				pj_j (pj, opexstr);
			}
			pj_kn (pj, "addr", core->offset + idx);
			{
				char *bytes = r_hex_bin2strdup (buf + idx, size);
				pj_ks (pj, "bytes", bytes);
				free (bytes);
			}
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
			pj_ks (pj, "type", r_anal_optype_tostring (op.type));
			{
				const char *datatype = r_anal_datatype_tostring (op.datatype);
				if (datatype) {
					pj_ks (pj, "datatype", datatype);
				}

			}
			if (esilstr) {
				int ec = esil_cost (core, addr, esilstr);
				pj_ki (pj, "esilcost", ec);
			}
			if (op.reg) {
				pj_ks (pj, "reg", op.reg);
			}
			if (op.ireg) {
				pj_ks (pj, "ireg", op.ireg);
			}
			if (op.scale > 0) {
				pj_ki (pj, "scale", op.scale);
			}
			if (op.refptr != -1 && op.refptr > 0) {
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
			if (op.direction != 0) {
				pj_ks (pj, "direction", r_anal_op_direction_tostring (&op));
			}
			const char *arg = (op.type & R_ANAL_OP_TYPE_COND)
				? r_anal_cond_type_tostring (op.cond): NULL;
			if (arg) {
				pj_ks (pj, "cond", arg);
			}
			pj_ks (pj, "family", r_anal_op_family_tostring (op.family));
			pj_end (pj);
		} else if (fmt == 'r') {
			if (R_STR_ISNOTEMPTY (esilstr)) {
				if (use_color) {
					r_cons_printf ("%s0x%" PFMT64x Color_RESET " %s\n", color, core->offset + idx, esilstr);
				} else {
					r_cons_printf ("0x%" PFMT64x " %s\n", core->offset + idx, esilstr);
				}
				r_esil_parse (core->anal->esil, esilstr);
				r_esil_dumpstack (core->anal->esil);
				r_esil_stack_free (core->anal->esil);
			} else {
				// ignored/skipped eprintf ("No esil for '%s'\n", op.mnemonic);
			}
		} else {
			char disasm[128] = {0};
			char *text = r_asm_op_get_asm (&asmop);
			if (!text) {
				R_LOG_ERROR ("invalid");
				break;
			}
			r_parse_subvar (core->parser, NULL,
				core->offset + idx,
				asmop.size,  text,
				disasm, sizeof (disasm));
			ut64 killme = UT64_MAX;
			if (r_io_read_i (core->io, op.ptr, &killme, op.refptr, be)) {
				core->parser->subrel_addr = killme;
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
					r_parse_subvar (core->parser, fcn, addr, asmop.size,
							disasm, disasm, sizeof (disasm));
				}
			}
			if (esilstr) {
				int ec = esil_cost (core, addr, esilstr);
				printline ("esilcost", "%d\n", ec);
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
				char *d = r_asm_describe (core->rasm, opname);
				if (d && *d) {
					printline ("description", "%s\n", d);
				}
				free (d);
				free (opname);
			}
			{
				ut8 *mask = r_anal_mask (core->anal, len - idx, buf + idx, core->offset + idx);
				if (smart_mask) {
					char *maskstr = r_core_cmd_strf (core, "aobm@0x%08"PFMT64x, op.addr);
					r_str_trim (maskstr);
					printline ("mask", "%s\n", maskstr);
					free (maskstr);
				} else {
					char *maskstr = r_hex_bin2strdup (mask, size);
					printline ("mask", "%s\n", maskstr);
					free (maskstr);
				}
				free (mask);
			}
			if (hint) {
				if (hint->opcode) {
					printline ("ophint", "%s\n", hint->opcode);
				}
			}
			if (op.prefix > 0) {
				printline ("prefix", "%u\n", op.prefix);
			}
			printline ("id", "%d\n", op.id);
			if (op.vliw > 0) {
				printline ("id", "%d\n", op.vliw);
			}
#if 0
// no opex here to avoid lot of tests broken..and having json in here is not much useful imho
			if (R_STR_ISNOTEMPTY (opexstr)) {
				printline ("opex", "%s\n", opexstr);
			}
#endif
			printline ("bytes", "%s", "");
			int minsz = R_MIN (len, size);
			minsz = R_MAX (minsz, 0);
			for (j = 0; j < minsz; j++) {
				r_cons_printf ("%02x", buf[idx + j]);
			}
			r_cons_newline ();
			if (op.val != UT64_MAX) {
				printline ("val", "0x%08" PFMT64x "\n", op.val);
			}
			if (op.ptr != UT64_MAX) {
				printline ("ptr", "0x%08" PFMT64x "\n", op.ptr);
			}
			if (op.disp && op.disp != UT64_MAX) {
				// printline ("disp", "0x%08" PFMT64x "\n", op.disp);
				printline ("disp", "%" PFMT64d "\n", op.disp);
			}
			if (op.refptr != -1 && op.refptr > 0) {
				printline ("refptr", "%d\n", op.refptr);
			}
			printline ("size", "%d\n", size);
			printline ("sign", "%s\n", r_str_bool (op.sign));
			printline ("type", "%s\n", r_anal_optype_tostring (op.type));
			const char *datatype = r_anal_datatype_tostring (op.datatype);
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
			if (op.scale > 0) {
				printline ("scale", "%d\n", op.scale);
			}
			if (hint && hint->esil) {
				printline ("esil", "%s\n", hint->esil);
			} else if (R_STR_ISNOTEMPTY (esilstr)) {
				printline ("esil", "%s\n", esilstr);
			}
			if (hint && hint->jump != UT64_MAX) {
				op.jump = hint->jump;
			}
			if (op.jump != UT64_MAX) {
				printline ("jump", "0x%08" PFMT64x "\n", op.jump);
			}
			if (op.direction != 0) {
				printline ("direction", "%s\n", r_anal_op_direction_tostring (&op));
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
				const char *arg = (op.type & R_ANAL_OP_TYPE_COND)?  r_anal_cond_type_tostring (op.cond): NULL;
				if (arg) {
					printline ("cond", "%s\n", arg);
				}
			}
			printline ("family", "%s\n", r_anal_op_family_tostring (op.family));
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
		r_asm_op_fini (&asmop);
	}
	r_anal_op_fini (&op);
	if (fmt == 's') {
		r_cons_printf ("%d\n", totalsize);
	} else if (fmt == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	r_esil_free (esil);
}

static int bb_cmp(const void *a, const void *b) {
	const RAnalBlock *ba = a;
	const RAnalBlock *bb = b;
	return ba->addr - bb->addr;
}

static ut64 caseval(const void* _a) {
	const RAnalCaseOp* a = _a;
	return a->addr;
}

static ut64 __opaddr(const RAnalBlock *b, ut64 addr) {
	int i;
	if (addr >= b->addr && addr < (b->addr + b->size)) {
		for (i = 0; i < b->ninstr; i++) {
			ut64 aa = b->addr + r_anal_bb_offset_inst (b, i);
			ut64 ab = b->addr + r_anal_bb_offset_inst (b, i + 1);
			if (addr >= aa && addr < ab) {
				return aa;
			}
		}
	}
	return UT64_MAX;
}

static RVecUT64 *get_xrefs(RAnalBlock *block) {
	RVecUT64 *result = RVecUT64_new ();

	size_t i;
	for (i = 0; i < block->ninstr; i++) {
		const ut64 ia = block->addr + block->op_pos[i];
		RVecAnalRef *xrefs = r_anal_xrefs_get (block->anal, ia);
		if (xrefs) {
			RAnalRef *ref;
			R_VEC_FOREACH (xrefs, ref) {
				ut64 *addr = RVecUT64_emplace_back (result);
				if (R_UNLIKELY (!addr)) {
					RVecUT64_free (result);
					return NULL;
				}

				*addr = ref->addr;
			}
		}

		RVecAnalRef_free (xrefs);
	}

	return result;
}

static char *fcnjoin(RList *list) {
	RAnalFunction *n;
	RListIter *iter;
	RStrBuf buf;
	r_strbuf_init (&buf);
	r_list_foreach (list, iter, n) {
		r_strbuf_appendf (&buf, " 0x%08" PFMT64x, n->addr);
	}
	char *s = strdup (r_strbuf_get (&buf));
	r_strbuf_fini (&buf);
	return s;
}

static char *ut64join(RList *list) {
	ut64 *n;
	RListIter *iter;
	RStrBuf buf;
	r_strbuf_init (&buf);
	r_list_foreach (list, iter, n) {
		r_strbuf_appendf (&buf, " 0x%08" PFMT64x, *n);
	}
	char *s = strdup (r_strbuf_get (&buf));
	r_strbuf_fini (&buf);
	return s;
}

static RList *get_calls(RAnalBlock *block) {
	RList *list = NULL;
	RAnalOp op;
	ut8 *data = malloc (block->size);
	if (data) {
		block->anal->iob.read_at (block->anal->iob.io, block->addr, data, block->size);
		size_t i;
		for (i = 0; i < block->size; i++) {
			int ret = r_anal_op (block->anal, &op, block->addr + i, data + i, block->size - i, R_ARCH_OP_MASK_HINT);
			if (ret < 1) {
				r_anal_op_fini (&op);
				continue;
			}
			if (op.type == R_ANAL_OP_TYPE_CALL) {
				if (!list) {
					list = r_list_newf (free);
				}
				r_list_push (list, ut64_new (op.jump));
			}
			r_anal_op_fini (&op);
			if (op.size > 0) {
				i += op.size - 1;
			}
		}
	}

	free (data);
	return list;
}

static void anal_bb_list(RCore *core, const char *input) {
	const int mode = *input;
	PJ *pj = NULL;
	RTable *table = NULL;
	RBIter iter;
	RAnalBlock *block;
	if (mode == 'c') {
		ut64 count = 0;
		r_rbtree_foreach (core->anal->bb_tree, iter, block, RAnalBlock, _rb) {
			count++;
		}
		r_cons_printf ("%"PFMT64d"\n", count);
		return;
	}
	if (mode == 'j') {
		pj = pj_new ();
		pj_o (pj);
		pj_ka (pj, "blocks");
	} else if (mode == ',' || mode == 't') {
		table = r_table_new ("bbs");
		RTableColumnType *s = r_table_type ("string");
		RTableColumnType *n = r_table_type ("number");
		r_table_add_column (table, n, "addr", 0);
		r_table_add_column (table, n, "size", 0);
		r_table_add_column (table, n, "traced", 0);
		r_table_add_column (table, n, "ninstr", 0);
		r_table_add_column (table, s, "jump", 0);
		r_table_add_column (table, s, "fail", 0);
		r_table_add_column (table, s, "fcns", 0);
		r_table_add_column (table, s, "calls", 0);
		r_table_add_column (table, s, "xrefs", 0);
	}

	r_rbtree_foreach (core->anal->bb_tree, iter, block, RAnalBlock, _rb) {
		RVecUT64 *xrefs = get_xrefs (block);
		RList *calls = get_calls (block);
		switch (mode) {
		case 'j':
			pj_o (pj);
			char *addr = r_str_newf ("0x%" PFMT64x, block->addr);
			pj_ks (pj, "addr", addr);
			free (addr);
			pj_kn (pj, "traced", block->traced);
			pj_kn (pj, "ninstr", block->ninstr);
			pj_kn (pj, "size", block->size);
			if (block->jump != UT64_MAX) {
				pj_kn (pj, "jump", block->jump);
			}
			if (block->fail != UT64_MAX) {
				pj_kn (pj, "fail", block->fail);
			}
			if (xrefs) {
				pj_ka (pj, "xrefs");
				ut64 *addr;
				R_VEC_FOREACH (xrefs, addr) {
					pj_n (pj, *addr);
				}
				pj_end (pj);
			}
			if (calls) {
				pj_ka (pj, "calls");
				RListIter *iter2;
				ut64 *addr;
				r_list_foreach (calls, iter2, addr) {
					pj_n (pj, *addr);
				}
				pj_end (pj);
			}
			pj_ka (pj, "fcns");
			RListIter *iter2;
			RAnalFunction *fcn;
			r_list_foreach (block->fcns, iter2, fcn) {
				pj_n (pj, fcn->addr);
			}
			pj_end (pj);
			pj_end (pj);
			break;
		case ',':
		case 't':
			{
				char *jump = block->jump != UT64_MAX? r_str_newf ("0x%08" PFMT64x, block->jump): strdup ("");
				char *fail = block->fail != UT64_MAX? r_str_newf ("0x%08" PFMT64x, block->fail): strdup ("");
				char *call = ut64join (calls);
				char *xref = ut64join (calls);
				char *fcns = fcnjoin (block->fcns);
				r_table_add_rowf (table, "xnddsssss",
					block->addr,
					block->size,
					block->traced,
					block->ninstr,
					jump,
					fail,
					fcns,
					call,
					xref
				);
				free (jump);
				free (fail);
				free (call);
				free (xref);
				free (fcns);
			}
			break;
		case 'q':
			r_cons_printf ("0x%08" PFMT64x"\n", block->addr);
			break;
		default:
			r_cons_printf ("0x%08" PFMT64x , block->addr);
			if (block->jump != UT64_MAX) {
				r_cons_printf (" jump=0x%08" PFMT64x, block->jump);
			}
			if (block->fail != UT64_MAX) {
				r_cons_printf (" fail=0x%08" PFMT64x, block->fail);
			}
			if (block->traced) {
				r_cons_printf (" trace=0x%08" PFMT64x, block->traced);
			}
			if (xrefs) {
				ut64 *addr;
				R_VEC_FOREACH (xrefs, addr) {
					r_cons_printf (" xref=0x%08" PFMT64x, *addr);
				}
			}
			if (calls) {
				RListIter *iter2;
				ut64 *addr;
				r_list_foreach (calls, iter2, addr) {
					r_cons_printf (" call=0x%08" PFMT64x, *addr);
				}
			}
			if (block->fcns) {
				RListIter *iter2;
				RAnalFunction *fcn;
				r_list_foreach (block->fcns, iter2, fcn) {
					r_cons_printf (" func=0x%" PFMT64x, fcn->addr);
				}
			}
			r_cons_printf (" size=%" PFMT64d "\n", block->size);
		}
		r_list_free (calls);
		RVecUT64_free (xrefs);
	}
	if (mode == 'j') {
		pj_end (pj);
		pj_end (pj);
		char *j = pj_drain (pj);
		r_cons_println (j);
		free (j);
	} else if (mode == 't' || mode == ',') {
		char *q = strchr (input, ' ');
		bool show_query = true;
		if (q) {
			show_query = r_table_query (table, q + 1);
		}
		if (show_query) {
			char *s = r_table_tofancystring (table);
			r_cons_println (s);
			free (s);
		}
		r_table_free (table);
	}
}

static void print_bb(PJ *pj, const RAnalBlock *b, const RAnalFunction *fcn, const ut64 addr) {
	RListIter *iter2;
	RAnalBlock *b2;
	int outputs = (b->jump != UT64_MAX) + (b->fail != UT64_MAX);
	int inputs = 0;
	r_list_foreach (fcn->bbs, iter2, b2) {
		inputs += (b2->jump == b->addr) + (b2->fail == b->addr);
	}
	ut64 opaddr = __opaddr (b, addr);
	if (pj) {
		pj_o (pj);
		pj_kn (pj, "addr", b->addr);
		pj_ki (pj, "size", b->size);
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
				pj_end (pj);
			}
			}
			pj_end (pj);
			pj_end (pj);
		}
		pj_kn (pj, "opaddr", opaddr);
		pj_ki (pj, "inputs", inputs);
		pj_ki (pj, "outputs", outputs);
		{
			RColor k = b->color;
			if (k.r || k.g || k.b) {
				char *s = r_str_newf ("rgb:%x%x%x",
						16 * k.r / 255,
						16 * k.g / 255,
						16 * k.b / 255);
				pj_ks (pj, "color", s);
				free (s);
			}
		}
		pj_ki (pj, "ninstr", b->ninstr);
		pj_ka (pj, "instrs");
		{
			int i;
			for (i = 0; i < b->ninstr; i++) {
				int delta = (i > 0)? b->op_pos[i - 1]: 0;
				pj_n (pj, b->addr + delta);
			}
		}
		pj_end (pj);
		pj_kn (pj, "traced", b->traced);
		pj_end (pj);
	} else {
		if (b->switch_op) {
			r_list_uniq_inplace (b->switch_op->cases, caseval);
			outputs += r_list_length (b->switch_op->cases);
		}
		if (b->jump != UT64_MAX) {
			r_cons_printf ("jump: 0x%08"PFMT64x"\n", b->jump);
		}
		if (b->fail != UT64_MAX) {
			r_cons_printf ("fail: 0x%08"PFMT64x"\n", b->fail);
		}
		r_cons_printf ("opaddr: 0x%08"PFMT64x"\n", opaddr);
		r_cons_printf ("addr: 0x%08" PFMT64x "\nsize: %" PFMT64d "\ninputs: %d\noutputs: %d\nninstr: %d\ntraced: 0x%"PFMT64x"\n",
			b->addr, b->size, inputs, outputs, b->ninstr, b->traced);
	}
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
	if (R_STR_ISNOTEMPTY (input)) {
		addr = bbaddr = r_num_math (core->num, input);
		if (!addr && *input != '0') {
			addr = core->offset;
		}
	} else {
		bbaddr = addr = core->offset;
	}
	input = r_str_trim_head_ro (input);
	if (one) {
		bbaddr = addr;
	}
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			r_cons_println ("[]");
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
		if (mode == 'i' && input && *input == 'j') {
			r_cons_println ("{}");
		}
		R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, addr);
		return false;
	}
	if (mode == '*') {
		r_cons_printf ("fs blocks\n");
	}
	if (fcn->bbs) {
		r_list_sort (fcn->bbs, bb_cmp);
	}
	if (mode == '=') { // afb
		RList *flist = r_list_newf ((RListFree) r_listinfo_free);
		if (!flist) {
			return false;
		}
		ls_foreach (fcn->bbs, iter, b) {
			RInterval inter = (RInterval) {b->addr, b->size};
			RListInfo *info = r_listinfo_new (NULL, inter, inter, -1, NULL);
			if (!info) {
				break;
			}
			r_list_append (flist, info);
		}
		RTable *table = r_core_table (core, "fcnbbs");
		if (!table) {
			return false;
		}
		r_table_visual_list (table, flist, core->offset, core->blocksize,
			r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
		char *s = r_table_tostring (table);
		r_cons_printf ("\n%s\n", s);
		free (s);
		r_table_free (table);
		r_list_free (flist);
		return true;
	}

	RTable *t = NULL;
	if (mode == 't') {
		t = r_table_new ("fcnbbs");
		r_table_set_columnsf (t, "xdxx", "addr", "size", "jump", "fail");
	}
	r_list_foreach (fcn->bbs, iter, b) {
		if (one) {
			if (bbaddr != UT64_MAX && (bbaddr < b->addr || bbaddr >= (b->addr + b->size))) {
				continue;
			}
		}
		switch (mode) {
		case 't': // "afbt"
			r_table_add_rowf (t, "xdxx", b->addr, b->size, b->jump, b->fail);
			break;
		case 'r': // "afbr"
			if (b->jump == UT64_MAX || r_anal_noreturn_at_addr (core->anal, b->jump)) {
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
		case 'q': // "afbq"
			r_cons_printf ("0x%08" PFMT64x "\n", b->addr);
			break;
		case 'j': // "afbj"
			print_bb (pj, b, fcn, addr);
			break;
		case 'i': // "afbi"
			if (*input == 'j') { // "afbij"
				pj = r_core_pj_new (core);
				if (!pj) {
					return false;
				}
				print_bb (pj, b, fcn, addr);
				r_cons_println (pj_string (pj));
				pj_free (pj);
			} else {
				print_bb (NULL, b, fcn, addr);
			}
			break;
		default:
			tp = r_debug_trace_get (core->dbg, b->addr);
			r_cons_printf ("0x%08" PFMT64x " 0x%08" PFMT64x " %02X:%04X %" PFMT64d,
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
				r_list_uniq_inplace (b->switch_op->cases, caseval);
				r_list_foreach (b->switch_op->cases, iter, cop) {
					r_cons_printf (" s 0x%08" PFMT64x, cop->addr);
				}
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

static bool anal_bb_edge(RCore *core, const char *input) {
	// "afbe" switch-bb-addr case-bb-addr
	char *arg = strdup (r_str_trim_head_ro (input));
	char *sp = strchr (arg, ' ');
	bool ret = false;
	if (sp) {
		*sp++ = 0;
		ut64 switch_addr = r_num_math (core->num, arg);
		ut64 case_addr = r_num_math (core->num, sp);
		RList *blocks = r_anal_get_blocks_in (core->anal, switch_addr);
		if (blocks && !r_list_empty (blocks)) {
			r_anal_block_add_switch_case (r_list_first (blocks), switch_addr, 0, case_addr);
			ret = true;
		}
		r_list_free (blocks);
	}
	free (arg);
	return ret;
}

static bool anal_fcn_del_bb(RCore *core, const char *input) {
	ut64 addr = r_num_math (core->num, input);
	if (!addr) {
		addr = core->offset;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		if (!strcmp (input, "*")) {
			while (!r_list_empty (fcn->bbs)) {
				r_anal_function_remove_block (fcn, r_list_first (fcn->bbs));
			}
		} else {
			RAnalBlock *b;
			RListIter *iter;
			r_list_foreach (fcn->bbs, iter, b) {
				if (b->addr == addr) {
					r_anal_function_remove_block (fcn, b);
					return true;
				}
			}
			R_LOG_ERROR ("Cannot find basic block");
		}
	}
	return false;
}

static int cmd_afbplus(RCore *core, const char *input) {
	// fcn_addr bb_addr bb_size [jump] [fail]
	const char *ptr2 = NULL;
	ut64 fcnaddr = -1LL, addr = -1LL;
	ut64 size = 0LL;
	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	RAnalFunction *fcn = NULL;
	RAnalDiff *diff = NULL;

	char *ptr = r_str_trim_dup (input);

	switch (r_str_word_set0 (ptr)) {
	case 6:
		ptr2 = r_str_word_get0 (ptr, 6);
		if (!(diff = r_anal_diff_new ())) {
			R_LOG_ERROR ("Cannot init RAnalDiff");
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
	fcn = r_anal_get_function_at (core->anal, fcnaddr);
	if (fcn && size > 0) {
		if (!r_anal_function_add_bb (core->anal, fcn, addr, size, jump, fail, diff)) {
			R_LOG_ERROR ("afb+: Cannot add basic block at 0x%08"PFMT64x" with size %d", addr, (int)size);
		}
	} else {
		R_LOG_ERROR ("afb+ No function at 0x%" PFMT64x " from 0x%08"PFMT64x" -> 0x%08"PFMT64x,
				fcnaddr, addr, jump);
	}
	r_anal_diff_free (diff);
	free (ptr);
	return true;
}

static void r_core_anal_nofunclist(RCore *core, const char *input) {
	int minlen = (int)(input[0] == ' ') ? r_num_math (core->num, input + 1): 16;
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
	bitmap = calloc (1, code_size + 64);
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
		if (bitmap[i]) {
			// We only print a region is its size is bigger than 15 bytes
			if (chunk_size >= minlen) {
				fcn = r_anal_get_fcn_in (core->anal, base_addr+chunk_offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (fcn) {
					r_cons_printf ("0x%08" PFMT64x "  %6" PFMT64u "   %s\n",
							base_addr+chunk_offset, chunk_size, fcn->name);
				} else {
					r_cons_printf ("0x%08" PFMT64x "  %6" PFMT64u "\n",
							base_addr+chunk_offset, chunk_size);
				}
			}
			chunk_size = 0;
			chunk_offset = i + 1;
			continue;
		}
		chunk_size += 1;
	}
	if (chunk_size >= 16) {
		fcn = r_anal_get_fcn_in (core->anal, base_addr+chunk_offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			r_cons_printf ("0x%08"PFMT64x"  %6" PFMT64u "   %s\n", base_addr+chunk_offset, chunk_size, fcn->name);
		} else {
			r_cons_printf ("0x%08"PFMT64x"  %6" PFMT64u "\n", base_addr+chunk_offset, chunk_size);
		}
	}
	free (bitmap);
}

static void r_core_anal_fmap(RCore *core, const char *input) {
	int show_color = r_config_get_i (core->config, "scr.color");
	int cols = r_config_get_i (core->config, "hex.cols") * 4;
	ut64 code_size = r_num_get (core->num, "$SS");
	ut64 base_addr = r_num_get (core->num, "$S");
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *b;
	int assigned;
	ut64 i;

	if (code_size < 1) {
		return;
	}
	char *bitmap = calloc (1, code_size + 64);
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
	r_cons_printf ("\n%d / %" PFMT64u " (%.2lf%%) bytes assigned to a function\n",
		assigned, code_size, 100.0 * ( (float) assigned) / code_size);
	free (bitmap);
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

static char *getFunctionName(RCore *core, ut64 off, const char *name, bool prefix) {
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
	return strdup (name); // r_str_newf ("%s%s%s", fcnpfx, *fcnpfx? ".": "", name);
}

static void rename_fcnsig(RAnal *anal, const char *oname, const char *nname) {
#define DB anal->sdb_types
	// rename type
	const char *type = sdb_const_get (DB, oname, 0);
	if (type && !strcmp (type, "func")) {
		sdb_unset (DB, oname, 0);
		sdb_set (DB, nname, "func", 0);
	}
	// rename args
	char *k = r_str_newf ("func.%s.args", oname);
	const char *argstr = sdb_const_get (DB, k, 0);
	if (R_STR_ISEMPTY (argstr)) {
		free (k);
		return;
	}
	int i, args = r_num_get (NULL, argstr);
	sdb_unset (DB, k, 0);
	free (k);
	k = r_str_newf ("func.%s.args", nname);
	char *v = r_str_newf ("%d", (int)args);
	sdb_set (DB, k, v, 0);
	free (v);
	// rename arg#
	free (k);
	for (i = 0; i < args; i++) {
		k = r_str_newf ("func.%s.arg.%d", oname, i);
		char *v = sdb_get (DB, k, 0);
		if (v) {
			sdb_unset (DB, k, 0);
			free (k);
			k = r_str_newf ("func.%s.arg.%d", nname, i);
			sdb_set (DB, k, v, 0);
			free (v);
		}
		free (k);
	}
	// unset the leftovers
	for (; i < args + 8; i++) {
		k = r_str_newf ("func.%s.arg.%d", oname, i);
		sdb_unset (DB, k, 0);
		free (k);
	}
	// rename ret
	k = r_str_newf ("func.%s.ret", oname);
	v = sdb_get (DB, k, 0);
	sdb_unset (DB, k, 0);
	free (k);
	k = r_str_newf ("func.%s.ret", nname);
	sdb_set (DB, k, v, 0);
	free (k);
	free (v);
#undef DB
}

/* TODO: move into r_anal_function_rename (); */
static bool __setFunctionName(RCore *core, ut64 addr, const char *_name, bool prefix) {
	r_return_val_if_fail (core && _name, false);
	bool ret = false;
	char *name = getFunctionName (core, addr, r_str_trim_head_ro (_name), prefix);
	char *fname = r_name_filter_dup (name);
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	if (fcn) {
		char *oname = strdup (fcn->name);
		RFlagItem *flag = r_flag_get (core->flags, fcn->name);
		if (flag && flag->space && strcmp (flag->space->name, R_FLAGS_FS_FUNCTIONS) == 0) {
			// Only flags in the functions fs should be renamed, e.g. we don't want to rename symbol flags.
			r_flag_rename (core->flags, flag, fname);
		} else {
			// No flag or not specific to the function, create a new one.
			r_flag_space_push (core->flags, R_FLAGS_FS_FUNCTIONS);
			r_flag_set (core->flags, name, fcn->addr, r_anal_function_size_from_entry (fcn));
			r_flag_space_pop (core->flags);
		}
		rename_fcnsig (core->anal, oname, name);
		r_anal_function_rename (fcn, name);
		if (core->anal->cb.on_fcn_rename) {
			core->anal->cb.on_fcn_rename (core->anal, core->anal->user, fcn, name);
		}
		free (oname);
		ret = true;
	}
	free (name);
	free (fname);
	return ret;
}

static void afCc(RCore *core, const char *input) {
	ut64 addr = (*input == ' ')
		? r_num_math (core->num, input)
		: core->offset;
	RAnalFunction *fcn = (addr == 0LL)
		? r_anal_get_function_byname (core->anal, input + 3)
		: r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (fcn) {
		ut32 totalCycles = r_anal_function_cost (fcn);
		// FIXME: This defeats the purpose of the function, but afC is used in project files.
		// cf. canal.c
		r_cons_printf ("%d\n", totalCycles);
	} else {
		R_LOG_ERROR ("afCc: Cannot find function");
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
		fcn = r_anal_get_function_byname (core->anal, fcn_name);
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
		char *key = (fcn_name)? resolve_fcn_name (core->anal, fcn_name): NULL;
		if (key) {
			const char *fcn_type = r_type_func_ret (core->anal->sdb_types, key);
			int nargs = r_type_func_args_count (core->anal->sdb_types, key);
			if (fcn_type) {
				pj_o (j);
				pj_ks (j, "name", r_str_getf (key));
				pj_ks (j, "return", r_str_getf (fcn_type));
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
			pj_ks (j, "name", r_str_getf (fcn_name));
			pj_k (j, "args");
			pj_a (j);

			RAnalFcnVarsCache cache;
			r_anal_function_vars_cache_init (core->anal, &cache, fcn);
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
			r_anal_function_vars_cache_fini (&cache);

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
		char *sig = r_anal_function_format_sig (core->anal, fcn, fcn_name, NULL, NULL, NULL);
		if (sig) {
			r_cons_printf ("%s\n", sig);
			free (sig);
		}
	}
}

static void __updateStats(RCore *core, Sdb *db, ut64 addr, int statsMode) {
	RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_DISASM);
	if (!op) {
		return;
	}
	if (statsMode == 'f') {
		const char *family = r_anal_op_family_tostring (op->family);
		sdb_num_inc (db, family, 1, 0);
	} else if (statsMode == 'o') {
		const char *type = r_anal_optype_tostring (op->type);
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
	// r_core_cmdf (core, "pd 1 @ 0x%08"PFMT64x, addr);
}

static Sdb *__core_cmd_anal_fcn_stats(RCore *core, const char *input) {
	bool silentMode = false;
	int statsMode = 0;
	if (*input == '*') {
		silentMode = true;
		input++;
	}
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_afis);
		return NULL;
	case 'f':
	case 'o':
		statsMode = *input;
		input++;
		break;
	}

	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	if (!fcn) {
		R_LOG_ERROR ("Cannot find any function at 0x%08"PFMT64x, core->offset);
		return NULL;
	}
	Sdb *db = sdb_new0 ();
	RAnalBlock *bb;
	RListIter *iter;
	r_list_foreach (fcn->bbs, iter, bb) {
		int i;
		__updateStats (core, db, bb->addr, statsMode);
		for (i = 0; i < bb->op_pos_size; i++) {
			ut16 op_pos = bb->op_pos[i];
			__updateStats (core, db, bb->addr + op_pos, statsMode);
		}
	}
	if (silentMode) {
		// nothing
	} else if (*input == 't') {
		SdbList *ls = sdb_foreach_list (db, true);
		SdbListIter *it;
		RTable *t = r_table_new ("fcnstats");
		SdbKv *kv;
		RTableColumnType *typeString = r_table_type ("string");
		RTableColumnType *typeNumber = r_table_type ("number");
		r_table_add_column (t, typeString, "name", 0);
		ls_foreach (ls, it, kv) {
			const char *key = sdbkv_key (kv);
			r_table_add_column (t, typeNumber, key, 0);
		}
		RList *items = r_list_newf (free);
		r_list_append (items, strdup (fcn->name));
		ls_foreach (ls, it, kv) {
			const char *value = sdbkv_value (kv);
			int nv = (int)r_num_get (NULL, value);
			r_list_append (items, r_str_newf ("%d", nv));
		}
		r_table_add_row_list (t, items);
		if (r_table_query (t, input + 1)) {
			char *ts = r_table_tostring (t);
			r_cons_printf ("%s", ts);
			free (ts);
		}
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
	bool isJson = strchr (input, 'j');

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
			const char *name = sdbkv_key (kv);
			sdb_add (d, name, "1", 0);
		}
		ls_free (ls);
	}
	RTable *t = r_table_new ("fcnallstats");
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
		for (i = 0; i < 100; i++) {
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
				R_LOG_ERROR ("Invalid column name (%s)", key);
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
	if (r_table_query (t, (*input)?input + 1: "")) {
		char *ts = isJson? r_table_tojson(t): r_table_tostring (t);
		if (ts) {
			r_cons_printf ("%s%s", ts, isJson ? "\n" : "");
			free (ts);
		}
	}
	r_table_free (t);
	r_core_seek (core, oseek, true);
	r_list_free (dbs);
}

static void _abo(RAnalBlock *bb) {
	int i;
	for (i = 0; i < bb->ninstr; i++) {
		ut64 at = r_anal_block_ninstr (bb, i);
		r_cons_printf ("0x%08"PFMT64x"\n", at);
	}
}

static void abo(RCore *core) {
	RAnalBlock *bb = r_anal_get_block_at (core->anal, core->offset);
	if (bb) {
		_abo (bb);
	}
}

static void afbo(RCore *core) {
	RAnalFunction *f = r_anal_get_function_at (core->anal, core->offset);
	if (f) {
		RListIter *iter;
		RAnalBlock *bb;
		r_list_foreach (f->bbs, iter, bb) {
			_abo (bb);
		}
	}
}

R_API char *fcnshowr(RAnalFunction *function) {
	RAnal *a = function->anal;
	//PJ *pj = a->coreb.pjWithEncoding (a->coreb.core);
	const char *realname = NULL, *import_substring = NULL;
	RStrBuf *sb = r_strbuf_new ("");

	RFlagItem *flag = a->flag_get (a->flb.f, function->addr);
	// Can't access R_FLAGS_FS_IMPORTS, since it is defined in r_core.h
	if (flag && flag->space && !strcmp (flag->space->name, "imports")) {
		// Get substring after last dot
		import_substring = r_str_rchr (function->name, NULL, '.');
		if (import_substring) {
			realname = import_substring + 1;
		}
	} else {
		realname = function->name;
	}

	char *args = strdup ("");
	char *sdb_ret = r_str_newf ("func.%s.ret", realname);
	char *sdb_args = r_str_newf ("func.%s.args", realname);
	// RList *args_list = r_list_newf ((RListFree) free);
	// const char *ret_type = sdb_const_get (a->sdb_types, sdb_ret, 0);
	const char *argc_str = sdb_const_get (a->sdb_types, sdb_args, 0);
	const int argc = argc_str? atoi (argc_str): 0;

	const bool no_return = r_anal_noreturn_at_addr (a, function->addr);
	if (no_return) {
		r_strbuf_appendf (sb, "tn %s\n", function->name);
	}
	if (function->cc) {
		r_strbuf_appendf (sb, "afc %s\n", function->cc);
	}
	int i;
	for (i = 0; i < argc; i++) {
		char *sdb_arg_i = r_str_newf ("func.%s.arg.%d", realname, i);
		char *type = sdb_get (a->sdb_types, sdb_arg_i, 0);
		if (!type) {
			continue;
		}
		char *comma = strchr (type, ',');
		if (comma) {
			*comma = 0;
			r_strf_var (regname, 32, "A%d", i);
			const char *cc_arg = r_reg_get_name (a->reg, r_reg_get_name_idx (regname));
			r_strbuf_appendf (sb, "afvr %s %s %s\n", cc_arg, comma + 1, type);
		}
		free (type);
		free (sdb_arg_i);
	}
	free (sdb_args);
	free (sdb_ret);
	free (args);
	return r_strbuf_drain (sb);
}

static void cmd_afsr(RCore *core, const char *input) {
	ut64 addr = core->offset;
	RAnalFunction *f;
	if ((f = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
		char *res = fcnshowr (f);
		if (R_STR_ISNOTEMPTY (res)) {
			r_cons_println (res);
		}
		free (res);
	} else {
		R_LOG_ERROR ("No function defined at 0x%08" PFMT64x, addr);
	}
}

static void cmd_afsj(RCore *core, const char *arg) {
	ut64 a = r_num_math (core->num, arg);
	const ut64 addr = a? a: core->offset;
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, addr, -1);
	if (f) {
		char *s = r_anal_function_get_json (f);
		r_cons_printf ("%s\n", s);
		free (s);
	} else {
		R_LOG_ERROR ("Cannot find function in 0x%08"PFMT64x, addr);
	}
}

typedef struct {
	ut64 from;
	ut64 to;
	char *regstate;
} BlockItem;

R_VEC_TYPE (RVecBlocks, BlockItem);

static BlockItem *find_predecessor(RVecBlocks *blocks, BlockItem *b0) {
	BlockItem *b1;
	R_VEC_FOREACH (blocks, b1) {
		if (b1->to == b0->from) {
			return b1;
		}
	}
	return NULL;
}

static void emulate_block(RCore *core, RVecBlocks *blocks, BlockItem *b0);
static void save_regstate_in_destinations(RCore *core, RVecBlocks *blocks, BlockItem *b0, BlockItem *b1) {
	BlockItem *b2;
	if (b1) {
		r_core_cmd0 (core, b1->regstate);
	}
	R_LOG_DEBUG ("aeb @0x%"PFMT64x, b0->from);
	r_core_cmdf (core, "aeb @0x%"PFMT64x, b0->from);
	char *regstate = r_core_cmd_str (core, "dre");
	r_str_trim (regstate);
	R_LOG_DEBUG ("dre # %s", regstate);
	bool unused = true;
	R_VEC_FOREACH (blocks, b2) {
		if (!b2->regstate && b0->to == b2->from) {
			R_LOG_DEBUG ("abe %s @ 0x%08"PFMT64x, regstate, b2->from);
			r_core_cmdf (core, "abe %s @ 0x%08"PFMT64x, regstate, b2->from);
			// eprintf ("abe %s @ 0x%"PFMT64x"\n", regstate, b2->from);
			b0->regstate = regstate;
			emulate_block (core, blocks, b2);
			unused = false;
			// break;
		}
	}
	if (unused) {
		free (regstate);
	}
}

static void emulate_block(RCore *core, RVecBlocks *blocks, BlockItem *b0) {
	BlockItem *b1 = find_predecessor (blocks, b0);
	if (b1) {
		if (b1->regstate) {
			save_regstate_in_destinations (core, blocks, b0, b1);
		} else {
			// b1->regstate;
	//		emulate_block (core, blocks, b1);
		}
	} else {
		// root node, assume initial regstate
		eprintf ("# root node 0x%"PFMT64x"\n", b0->from);
		char *regstate = r_core_cmd_str (core, "dre");
		r_str_trim (regstate);
		r_core_cmdf (core, "abe %s @0x%"PFMT64x, regstate, b0->from);
		r_core_cmdf (core, "aeb @0x%"PFMT64x, b0->from);
		b0->regstate = strdup ("dr0,#!"); //initial regstate
		save_regstate_in_destinations (core, blocks, b0, NULL);
	}
}

static void cmd_afbd(RCore *core, const char *input) {
	r_return_if_fail (core && input);
	ut64 addr = core->offset;
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, addr, -1);
	if (!f) {
		R_LOG_ERROR ("No function found");
		return;
	}
	ut64 oaddr = core->offset;
	RAnalBlock *bb;
	RVecBlocks blocks;
	RVecBlocks_init (&blocks);
	RListIter *iter;
	r_core_cmd0 (core, "drs+");
	r_list_foreach (f->bbs, iter, bb) {
		BlockItem bi = { 0 };
		bi.from = bb->addr;
		if (bb->jump != UT64_MAX) {
			bi.to = bb->jump;
			RVecBlocks_push_back (&blocks, &bi);
		}
		if (bb->fail != UT64_MAX) {
			bi.to = bb->fail;
			RVecBlocks_push_back (&blocks, &bi);
		}
		if (bb->switch_op) {
			RListIter *iter;
			RAnalCaseOp *scase;
			r_list_foreach (bb->switch_op->cases, iter, scase) {
				bi.to = scase->jump;
				RVecBlocks_push_back (&blocks, &bi);
			}
		}
	}
	BlockItem *b0;
	R_VEC_FOREACH (&blocks, b0) {
		if (b0->regstate) {
			continue;
		}
		emulate_block (core, &blocks, b0);
	}
	r_core_cmd0 (core, "drs-");
	r_core_seek (core, oaddr, true);
}

static void cmd_afbc(RCore *core, const char *input) {
	r_return_if_fail (core && input);
	char *ptr = strdup (input);
	if (!ptr) {
		return;
	}
	if (*ptr == '?') {
		r_core_cmd_help_match (core, help_msg_afb, "afbc", true);
	} else if (!*ptr) {
		RAnalBlock *bb = r_anal_get_block_at (core->anal, core->offset);
		if (bb && (bb->color.r || bb->color.g || bb->color.b)) {
			char *s = r_cons_rgb_str (NULL, -1, &bb->color);
			if (s) {
				char *name = r_cons_rgb_tostring (bb->color.r, bb->color.g, bb->color.b);
				r_cons_printf ("%s%s"Color_RESET"\n", s, name);
				free (name);
				free (s);
			}
		}
	} else {
		ut64 addr = core->offset;
		const bool del = (*ptr == '-');
		if (del) {
			ptr++;
		}

		char *space = strchr (ptr, ' ');
		if (space) {
			*space++ = 0;
			addr = r_num_math (core->num, space);
		}
		RColor color = {0};
		if (del) {
			ptr--;
		} else {
			(void)r_cons_pal_parse (ptr, &color);
		}
		RAnalBlock *bb = r_anal_get_block_at (core->anal, addr);
		if (bb) {
			bb->color = color;
		}
	}
	free (ptr);
}

// Fcn Xrefs Map
static void xrefs_map(RCore *core, const char *input) {
	RListIter *iter, *iter2;
	RAnalFunction *f, *f2;
	int col = 0;
	int count = 0;
	do {
		r_cons_print ("             ");
		count = 0;
		r_list_foreach (core->anal->fcns, iter, f) {
			int nlen = strlen (f->name);
			if (col >= nlen) {
				r_cons_printf ("|");
				continue;
			}
			count++;
			r_cons_printf ("%c", f->name[col]);
		}
		r_cons_newline ();
		col++;
	} while (count);

	int total = 0;
	r_list_foreach (core->anal->fcns, iter, f) {
		RVecAnalRef *refs = r_anal_function_get_refs (f);
		r_cons_printf ("0x%08"PFMT64x"  ", f->addr);
		total = 0;
		r_list_foreach (core->anal->fcns, iter2, f2) {
			int count = 0;
			RAnalRef *r;
			R_VEC_FOREACH (refs, r) {
				if (r->addr == f2->addr) {
					count++;
				}
			}
			if (count > 0) {
				total++;
				if (count < 10) {
					r_cons_printf ("%d", count);
				} else {
					r_cons_printf ("+");
				}
			} else {
				r_cons_printf (".");
			}
		}
		if (total > 0) {
			r_cons_printf ("  %s\n", f->name);
		} else {
			r_cons_printf ("\r");
		}
		RVecAnalRef_free (refs);
	}
}

R_API void r_core_af(RCore *core, ut64 addr, const char *name, bool anal_calls) {
	int depth = r_config_get_i (core->config, "anal.depth");

	//r_core_anal_undefine (core, core->offset);
	r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (fcn) {
		/* ensure we use a proper name */
		__setFunctionName (core, addr, fcn->name, false);
		if (core->anal->opt.vars) {
			r_core_recover_vars (core, fcn, true);
		}
		__add_vars_sdb (core, fcn);
	} else {
		if (core->anal->verbose) {
			R_LOG_WARN ("Unable to analyze function at 0x%08"PFMT64x, addr);
		}
	}
	if (anal_calls) {
		SetU *visited = set_u_new ();
		fcn = r_anal_get_fcn_in (core->anal, addr, 0); /// XXX wrong in case of nopskip
		if (fcn) {
			RVecAnalRef *refs = r_anal_function_get_refs (fcn);
			RAnalRef *ref;
			R_VEC_FOREACH (refs, ref) {
				if (set_u_contains (visited, ref->addr)) {
					continue;
				}
				set_u_add (visited, ref->addr);
				if (ref->addr == UT64_MAX) {
					R_LOG_DEBUG ("ignore 0x%08"PFMT64x" call 0x%08"PFMT64x, ref->at, ref->addr);
					continue;
				}
				int rt = R_ANAL_REF_TYPE_MASK (ref->type);
				if (rt != R_ANAL_REF_TYPE_CODE && rt != R_ANAL_REF_TYPE_CALL) {
					/* only follow code/call references */
					continue;
				}
				if (!r_io_is_valid_offset (core->io, ref->addr, !core->anal->opt.noncode)) {
					continue;
				}
				r_core_anal_fcn (core, ref->addr, fcn->addr, R_ANAL_REF_TYPE_CALL, depth - 1);
				/* use recursivity here */
#if 1
				RAnalFunction *f = r_anal_get_function_at (core->anal, ref->addr);
				if (f) {
					RVecAnalRef *refs1 = r_anal_function_get_refs (f);
					RAnalRef *ref;
					R_VEC_FOREACH (refs1, ref) {
						const ut64 raddr = ref->addr;
						if (set_u_contains (visited, raddr)) {
							continue;
						}
						set_u_add (visited, raddr);
						if (!r_io_is_valid_offset (core->io, raddr, !core->anal->opt.noncode)) {
							continue;
						}
						const int rt = R_ANAL_REF_TYPE_MASK (ref->type);
						if (rt != R_ANAL_REF_TYPE_CALL && rt != R_ANAL_REF_TYPE_CODE) {
							continue;
						}
						// recursively follow fcn->refs again and again
						if (!r_anal_get_function_at (core->anal, raddr)) {
							// do not reanalize if theres a function already there
							r_core_anal_fcn (core, raddr, f->addr, R_ANAL_REF_TYPE_CALL, depth - 1);
						}
					}
					RVecAnalRef_free (refs1);
				} else {
					f = r_anal_get_fcn_in (core->anal, fcn->addr, 0);
					if (f) {
						/* cut function */
						r_anal_function_resize (f, addr - fcn->addr);
						r_core_anal_fcn (core, ref->addr, fcn->addr, R_ANAL_REF_TYPE_CALL, depth - 1);
						f = r_anal_get_function_at (core->anal, fcn->addr);
					}
					if (!f) {
						R_LOG_ERROR ("af: Cannot find function at 0x%08" PFMT64x, fcn->addr);
					}
				}
#endif
			}
			RVecAnalRef_free (refs);
			if (core->anal->opt.vars) {
				r_core_recover_vars (core, fcn, true);
			}
		}
		set_u_free (visited);
	}
	if (name) {
		if (*name && !__setFunctionName (core, addr, name, true)) {
			R_LOG_ERROR ("af: Cannot find function at 0x%08" PFMT64x, addr);
		}
	}
#if 0
	// XXX THIS IS VERY SLOW
	// r_core_anal_propagate_noreturn (core, addr);
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
//	flag_every_function (core);
#endif
}

static void cmd_aflxj(RCore *core) {
	ut64 addr = faddr (core, core->offset, NULL);
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_ANY);
	Sdb *db = sdb_new0 ();
	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
	if (xrefs) {
		RAnalRef *ref;
		R_VEC_FOREACH (xrefs, ref) {
			bool nr = false;
			ut64 fa = faddr (core, ref->addr, &nr);
			char *key = r_str_newf ("0x%08"PFMT64x, fa);
			sdb_array_add_num (db, key, ref->addr, 0);
		}
	}
	SdbList *keys = sdb_foreach_list (db, true);
	SdbListIter *liter;
	SdbKv *kv;
	PJ * pj = r_core_pj_new (core);
	if (pj) {
		pj_o (pj);
	}
	ls_foreach (keys, liter, kv) {
		const char *key = sdbkv_key (kv);
		const char *value = sdbkv_value (kv);
		ut64 fcn_xref_addr = r_num_get (NULL, key);
		ut64 xref_addr = r_num_get (NULL, value);
		RAnalFunction *xref = r_anal_get_fcn_in (core->anal, fcn_xref_addr, R_ANAL_FCN_TYPE_ANY);
		if (fcn && xref) {
			pj_kn (pj, "address", fcn->addr);
			pj_ks (pj, "name", fcn->name);
			pj_ko (pj, "xrefs");
			pj_ka (pj, xref->name);
			pj_n (pj, xref_addr);
			pj_end (pj);
			pj_end (pj);
		} else {
			R_LOG_WARN ("No function defined here");
		}
	}
	pj_end (pj);
	char *s = pj_drain (pj);
	r_cons_printf ("%s\n", s);
	free (s);
	RVecAnalRef_free (xrefs);
	sdb_free (db);
	ls_free (keys);
}

static void cmd_afci(RCore *core, RAnalFunction *fcn) {
	const char *cc = (fcn && fcn->cc)? fcn->cc: "reg";
	r_core_cmdf (core, "afcll~%s (", cc);
}

static void cmd_afix(RCore *core, const char *input) {
	switch (input[3]) {
	case '?': // "afix?"
		r_core_cmd_help_match (core, help_msg_afi, "afix", false);
		break;
	case 'q': // "afixq"
	case 'j': // "afixj"
		r_core_anal_fcn_list (core, input + 4, input + 2);
		break;
	case 0: // "afix"
		r_core_anal_fcn_list (core, "", "x\x01");
		break;
	default:
		R_LOG_ERROR ("Invalid argument");
		break;
	}
}

static int cmd_af(RCore *core, const char *input) {
	r_cons_break_timeout (r_config_get_i (core->config, "anal.timeout"));
	switch (input[1]) {
	case '-': // "af-"
		if (!input[2]) { // "af-"
			cmd_af (core, "f-$$");
			r_core_anal_undefine (core, core->offset);
		} else if (!strcmp (input + 2, "*")) { // "af-*"
			RAnalFunction *f;
			RListIter *iter, *iter2;
			r_list_foreach_safe (core->anal->fcns, iter, iter2, f) {
				ut64 addr = f->addr;
				r_anal_del_jmprefs (core->anal, f);
				// r_anal_function_del_locs (core->anal, f->addr);
			//	r_anal_function_del (core->anal, addr);
				r_core_anal_undefine (core, addr);
			}
		} else {
			ut64 addr = input[2]
				? r_num_math (core->num, input + 2)
				: core->offset;
			// r_anal_function_del_locs (core->anal, addr);
			// r_anal_function_del (core->anal, addr);
			r_core_anal_undefine (core, addr);
		}
		break;
	case 'j': // "afj"
		{
			RList *blocks = r_anal_get_blocks_in (core->anal, core->offset);
			RAnalBlock *block = r_list_first (blocks);
			if (block && !r_list_empty (block->fcns)) {
				char *args = strdup (input + 2);
				RList *argv = r_str_split_list (args, " ", 0);
				ut64 table = r_num_math (core->num, r_list_get_n (argv, 1));
				ut64 sz = r_num_math (core->num, r_list_get_n (argv, 2));
				ut64 elements = r_num_math (core->num, r_list_get_n (argv, 3));
				ut64 seg = r_num_math (core->num, r_list_get_n (argv, 4));
				int depth = 50;
				try_walkthrough_jmptbl (core->anal, r_list_first (block->fcns), block,
					depth, core->offset, 0, table, seg, sz, elements, 0, false);
				free (args);
			} else {
				R_LOG_ERROR ("No function defined here");
			}
			r_list_free (blocks);
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
			r_core_cmd_help_match (core, help_msg_af, "afd", true);
		} else if (input[2] == ' ') {
			addr = r_num_math (core->num, input + 2);
		} else {
			addr = core->offset;
		}
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
		if (input[2] == 'j') { // afdj
			PJ *pj = r_core_pj_new (core);
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
				R_LOG_ERROR ("afd: Cannot find function");
			}
		}
		}
		break;
	case 'u': // "afu"
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_afu);
			break;
		}

		if (input[2] != ' ') {
			R_LOG_ERROR ("Missing argument");
			return false;
		}

		ut64 addr = core->offset;
		ut64 addr_end = r_num_math (core->num, input + 2);
		if (addr_end < addr) {
			R_LOG_ERROR ("Invalid address ranges");
		} else {
			ut64 a, b;
			const char *c;
			a = r_config_get_i (core->config, "anal.from");
			b = r_config_get_i (core->config, "anal.to");
			c = r_config_get (core->config, "anal.limits");
			r_config_set_i (core->config, "anal.from", addr);
			r_config_set_i (core->config, "anal.to", addr_end);
			r_config_set_b (core->config, "anal.limits", true);

			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) {
				r_anal_function_resize (fcn, addr_end - addr);
			}
			r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
			fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) {
				r_anal_function_resize (fcn, addr_end - addr);
			}
			r_config_set_i (core->config, "anal.from", a);
			r_config_set_i (core->config, "anal.to", b);
			r_config_set (core->config, "anal.limits", r_str_get (c));
		}
		break;
	case '+': { // "af+"
		if (input[2] == '?' || !input[2]) {
			r_core_cmd_help (core, help_msg_af_plus);
			break;
		}
		char *ptr = input[2]? r_str_trim_dup (input + 2): r_str_newf ("0x%"PFMT64x, core->offset);
		const char *ptr2;
		int n = r_str_word_set0 (ptr);
		const char *name = NULL;
		char *hname = NULL; // heaped name
		ut64 addr = UT64_MAX;
		RAnalDiff *diff = NULL;
		int type = R_ANAL_FCN_TYPE_FCN;
		if (n > 0) {
			switch (n) {
			case 4:
				ptr2 = r_str_word_get0 (ptr, 3);
				if (!(diff = r_anal_diff_new ())) {
					R_LOG_ERROR ("Cannot initialize RAnalDiff");
					free (ptr);
					return false;
				}
				if (ptr2[0] == 'm') {
					diff->type = R_ANAL_DIFF_TYPE_MATCH;
				} else if (ptr2[0] == 'u') {
					diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				}
				/* fallthrough */
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
				/* fallthrough */
			case 2:
				name = r_str_word_get0 (ptr, 1);
				/* fallthrough */
			case 1:
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				if (!name) {
					RFlagItem *fi = r_flag_get_at (core->flags, addr, false);
					name = hname = (fi)
						? strdup (fi->name)
						: r_str_newf ("fcn.%08"PFMT64x, addr);
				}
				break;
			}
			RAnalFunction *fcn = r_anal_create_function (core->anal, name, addr, type, diff);
			if (!fcn) {
				R_LOG_ERROR ("Cannot add function '%s' (duplicated) at 0x%08"PFMT64x, name, addr);
			}
			free (hname);
		}
		r_anal_diff_free (diff);
		free (ptr);
		}
		break;
	case 'o': // "afo"
		switch (input[2]) {
		case '?':
			r_core_cmd_help_match (core, help_msg_af, "afo", true);
			break;
		case 'j':
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				PJ *pj = r_core_pj_new (core);
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
				RList *list = r_anal_get_functions_in (core->anal, addr);
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
					fcn = r_anal_get_function_byname (core->anal, input + 3);
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
		case 'x': // "afix"
			cmd_afix (core, input);
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
					R_LOG_ERROR ("No function found");
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
					r_cons_printf ("is-pure: %s\n", r_str_bool (r_anal_function_purity (fcn)));
				}
			}
			break;
		case '=':
		case 'q':
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					// TODO: add info about xrefs and call counts
					int nargs = r_type_func_args_count (core->anal->sdb_types, 0);
					int nvars = r_anal_var_count_locals (fcn);
					int nins = r_anal_function_instrcount (fcn);
					int ebbs = 0;
					int edges = r_anal_function_count_edges (fcn, &ebbs);
					r_anal_function_count_edges (fcn, NULL);
					r_cons_printf ("0x%08" PFMT64x " : %s\n", fcn->addr, fcn->name);
					char *sig = r_core_cmd_strf (core, "afcf @ 0x%"PFMT64x, fcn->addr);
					if (sig) {
						r_str_trim (sig);
						r_cons_printf ("  sign:  %s\n", sig);
						free (sig);
					}
					r_cons_printf ("  stack: 0x%08x (vars:%d args:%d)\n",
						fcn->maxstack, nvars , nargs);
					r_cons_printf ("  size:  %d (0x%08" PFMT64x " .. 0x%08" PFMT64x ")\n",
						(int)r_anal_function_realsize (fcn),
						r_anal_function_min_addr (fcn),
						r_anal_function_max_addr (fcn));
					r_cons_printf ("  nbbs:  %d edges:%d ebbs:%d ninstr:%d\n",
						r_list_length (fcn->bbs), edges, ebbs, nins);
					r_cons_printf ("  cost:  %d complexity:%d\n",
						r_anal_function_cost (fcn), r_anal_function_complexity (fcn));
					r_cons_printf ("  attr:  ");
					if (r_anal_function_islineal (fcn)) {
						r_cons_printf ("lineal");
					}
					if (fcn->is_noreturn) {
						r_cons_printf ("noreturn");
					}
					r_cons_newline ();
				}
			}
			break;
		case ' ':
		case 0:
			{
				const char *arg = input[2]? input + 2: "";
				const char *sec = "\x01";
				r_core_anal_fcn_list (core, arg, sec);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_afi);
			break;
		}
		break;
	case 'l': // "afl"
		switch (input[2]) {
		case '?':
			r_core_cmd_help (core, help_msg_afl);
			break;
		case 'x': // "aflx"
			switch (input[3]) {
			default:
			case '?':
				r_core_cmd_help (core, help_msg_aflx);
				return true;
			case 'v': // "aflxv"
			case '*': // "aflx*"
			case 0: // default for "aflx"
			{
				ut64 addr = faddr (core, core->offset, NULL);
				Sdb *db = sdb_new0 ();
				// sort by function and uniq to avoid dupped results
				RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
				if (xrefs) {
					RAnalRef *ref;
					R_VEC_FOREACH (xrefs, ref) {
						bool nr = false;
						ut64 fa = faddr (core, ref->addr, &nr);
						char *key = r_str_newf ("0x%08"PFMT64x, fa);
						sdb_array_add_num (db, key, ref->addr, 0);
					}
				}
				SdbList *keys = sdb_foreach_list (db, true);
				SdbListIter *liter;
				SdbKv *kv;
				bool rad = input[3] == '*';
				bool verbose = input[3] == 'v';
				ls_foreach (keys, liter, kv) {
					const char *key = sdbkv_key (kv);
					const char *value = sdbkv_value (kv);
				    if (verbose) {
						ut64 fcn_xref_addr = r_num_get (NULL, key);
						RAnalFunction *xref = r_anal_get_fcn_in (core->anal, fcn_xref_addr, R_ANAL_FCN_TYPE_ANY);
						if (xref) {
							r_cons_printf ("%s %s\n",  xref->name, value);
							continue;
						}
					} else if (rad) {                                                                                                                                                                                      r_cons_printf ("s %s;af-;af;s-\n", (const char *)kv->base.key);
						r_cons_printf ("s %s;af-;af;s-\n", key);
						continue;
					}
					r_cons_printf ("%s %s\n", key, value);
				}
				sdb_free (db);
				ls_free (keys);
				break;
			}
			case 'j': // "aflxj"
				cmd_aflxj (core);
				break;
			}
			break;
		case 's': // "afls"
			switch (input[3]) {
			default:
			case '?':
				r_core_cmd_help (core, help_msg_afls);
				return true;
			case 0: // default for "afls"
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
			}
			break;
		case 'l': // "afll"
			if (input[3] == '?') {
				r_core_cmd_help (core, help_msg_afll);
				break;
			}
			/* fallthrough */
		case ',': // "afl,"
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
		case ' ': // "afl [addr]" argument ignored
		case 0: // "afl"
			r_core_anal_fcn_list (core, NULL, "o");
			break;
		default: // "afl "
			r_core_cmd_help (core, help_msg_afl);
			break;
		}
		break;
	case 's': // "afs"
		switch (input[2]) {
		case '!': { // "afs!"
			char *sig = r_core_cmd_str (core, "afs");
			char *data = r_core_editor (core, NULL, sig);
			if (sig && data) {
				r_core_cmd_callf (core, "afs %s", data);
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
				R_LOG_ERROR ("There's no function defined here");
			}
			break;
		}
		case '*': // "afs*"
			cmd_afsr (core, input + 2);
			break;
		case 'j': // "afsj"
			cmd_afsj (core, input + 2);
			break;
		case 0:
		case ' ': { // "afs"
			ut64 addr = core->offset;
			RAnalFunction *f;
			const char *arg = r_str_trim_head_ro (input + 2);
			if ((f = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
				if (R_STR_ISNOTEMPTY (arg)) {
					// parse function signature here
					char *fcnstr = r_str_newf ("%s;", arg), *fcnstr_copy = strdup (fcnstr);
					char *save_ptr = NULL;
					char *fcnname_aux = r_str_tok_r (fcnstr_copy, "(", &save_ptr);
					r_str_trim_tail (fcnname_aux);
					const char *ls = r_str_lchr (fcnname_aux, ' ');
					char *fcnname = strdup (ls? ls: fcnname_aux);
					if (fcnname) {
						// TODO: move this into r_anal_str_to_fcn()
						if (strcmp (f->name, fcnname)) {
							(void)__setFunctionName (core, addr, fcnname, false);
							f = r_anal_get_fcn_in (core->anal, addr, -1);
						}
						r_anal_str_to_fcn (core->anal, f, fcnstr);
					}
					free (fcnname);
					free (fcnstr_copy);
					free (fcnstr);
				} else {
					char *str = r_anal_function_get_signature (f);
					if (str) {
						r_cons_println (str);
						free (str);
					}
				}
			} else {
				R_LOG_ERROR ("No function defined at 0x%08" PFMT64x, addr);
			}
			break;
		}
		default:
		// case '?': // "afs?"
			r_core_cmd_help (core, help_msg_afs);
			break;
		}
		break;
	case 'm': // "afm" - merge two functions
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_afm);
			break;
		}
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
			if ((fcn = r_anal_get_fcn_in (core->anal, core->offset, 0))) {
				r_cons_printf ("%i\n", r_anal_function_complexity (fcn));
			} else {
				R_LOG_ERROR ("Cannot find function at 0x08%" PFMT64x, core->offset);
			}
		} else if (input[2] == 'l') {
			RAnalFunction *fcn;
			if ((fcn = r_anal_get_fcn_in (core->anal, core->offset, 0))) {
				r_cons_printf ("%d\n", r_anal_function_loops (fcn));
			} else {
				R_LOG_ERROR ("Cannot find function at 0x08%" PFMT64x, core->offset);
			}
		} else if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_afC);
		} else {
			afCc (core, r_str_trim_head_ro (input + 2));
		}
		break;
	case 'c': { // "afc"
		RAnalFunction *fcn = NULL;
		if (!input[2] || input[2] == ' ' || input[2] == 'i' || input[2] == 'r' || input[2] == 'a') {
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (!fcn) {
				R_LOG_ERROR ("afc: Cannot find function here");
				break;
			}
		}
		switch (input[2]) {
		case '\0': // "afc"
			r_cons_println (fcn->cc);
			break;
		case ' ': { // "afc "
				  char *cc = r_str_trim_dup (input + 3);
				  if (!r_anal_cc_exist (core->anal, cc)) {
					  const char *asmOs = r_config_get (core->config, "asm.os");
					  R_LOG_ERROR ("afc: Unknown calling convention '%s' for '%s'. See afcl for available types", cc, asmOs);
				  } else {
					  fcn->cc = r_str_constpool_get (&core->anal->constpool, cc);
				  }
				  free (cc);
			  }
			break;
		case 'i':
			cmd_afci (core, fcn);
			break;
		case 'f': // "afcf" "afcfj"
			cmd_anal_fcn_sig (core, input + 3);
			break;
		case 'k': // "afck"
			cmd_afck (core, NULL);
			break;
		case 'l': // "afcl" list all function Calling conventions.
			if (input[3] == '?') {
				r_core_cmd_help (core, help_msg_afc);
			} else {
				cmd_tcc (core, input + 3);
			}
			break;
		case 'o': { // "afco"
				  char *dbpath = r_str_trim_dup (input + 3);
				  if (R_STR_ISNOTEMPTY (dbpath) && r_file_exists (dbpath)) {
					  Sdb *db = sdb_new (0, dbpath, 0);
					  if (db) {
						  sdb_merge (core->anal->sdb_cc, db);
						  sdb_close (db);
						  sdb_free (db);
					  }
				  } else {
					  r_core_cmd_help_match (core, help_msg_afc, "afco", true);
				  }
				  free (dbpath);
			  }
			break;
		case 'r': { // "afcr"
			int i;
			PJ *pj = NULL;
			bool json = input[3] == 'j';
			if (json) {
				pj = r_core_pj_new (core);
				if (!pj) {
					return false;
				}
				pj_o (pj);
			}
			char *cmd = r_str_newf ("cc.%s.ret", fcn->cc);
			const char *regname = sdb_const_get (core->anal->sdb_cc, cmd, 0);
			if (regname) {
				if (json) {
					pj_ks (pj, "ret", regname);
				} else {
					r_cons_printf ("%s: %s\n", cmd, regname);
				}
			}
			free (cmd);
			if (json) {
				pj_ka (pj, "args");
			}
			for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
				cmd = r_str_newf ("cc.%s.arg%d", fcn->cc, i);
				regname = sdb_const_get (core->anal->sdb_cc, cmd, 0);
				if (regname) {
					if (json) {
						pj_s (pj, regname);
					} else {
						r_cons_printf ("%s: %s\n", cmd, regname);
					}
				}
				free (cmd);
			}
			if (json) {
				pj_end (pj);
			}
			cmd = r_str_newf ("cc.%s.self", fcn->cc);
			regname = sdb_const_get (core->anal->sdb_cc, cmd, 0);
			if (regname) {
				if (json) {
					pj_ks (pj, "self", regname);
				} else {
					r_cons_printf ("%s: %s\n", cmd, regname);
				}
			}
			free (cmd);
			cmd = r_str_newf ("cc.%s.error", fcn->cc);
			regname = sdb_const_get (core->anal->sdb_cc, cmd, 0);
			if (regname) {
				if (json) {
					pj_ks (pj, "error", regname);
				} else {
					r_cons_printf ("%s: %s\n", cmd, regname);
				}
			}
			free (cmd);
			if (json) {
				pj_end (pj);
				r_cons_println (pj_string (pj));
				pj_free (pj);
			}
			break;
		}
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
			break;
		}
		case '?': // "afc?"
		default:
			r_core_cmd_help (core, help_msg_afc);
		}
		break;
	}
	case 'B': // "afB" // set function bits
		if (input[2] == ' ') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) { // bits = 0 means unset
				int nbits = atoi (input + 3);
				int obits = core->anal->config->bits;
				if (nbits > 0) {
					r_anal_hint_set_bits (core->anal, r_anal_function_min_addr (fcn), nbits);
					r_anal_hint_set_bits (core->anal, r_anal_function_max_addr (fcn), obits);
					fcn->bits = nbits;
				} else {
					r_anal_hint_unset_bits (core->anal, r_anal_function_min_addr (fcn));
					fcn->bits = 0;
				}
			} else {
				R_LOG_ERROR ("afB: Cannot find function to set bits at 0x%08"PFMT64x, core->offset);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_af, "afB", true);
		}
		break;
	case 'b': // "afb"
		switch (input[2]) {
		case '-': // "afb-"
			anal_fcn_del_bb (core, r_str_trim_head_ro (input + 3));
			break;
		case 'o': // "afbo"
			afbo (core);
			break;
		case 'e': // "afbe"
			anal_bb_edge (core, r_str_trim_head_ro (input + 3));
			break;
		case 'F': { // "afbF"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
			if (fcn) {
				RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, core->offset);
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
			cmd_afbplus (core, input + 3);
			break;
		case 'c': // "afbc"
			cmd_afbc (core, r_str_trim_head_ro (input + 3));
			break;
		case 'd': // "afbd"
			cmd_afbd (core, r_str_trim_head_ro (input + 3));
			break;
		default:
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
			if (input[3] == '?') {
				r_core_cmd_help (core, help_msg_afna);
				break;
			}
			char *name = r_core_anal_fcn_autoname (core, core->offset, 0, 0);
			if (name) {
				r_cons_printf ("afn %s 0x%08" PFMT64x "\n", name, core->offset);
				free (name);
			}
			break;
		case '.': // "afn."
		case 0: { // "afn"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) {
				r_cons_printf ("%s\n", fcn->name);
			}
			}
			break;
		case ' ': { // "afn "
			ut64 off = core->offset;
			char *p, *name = strdup (r_str_trim_head_ro (input + 3));
			if ((p = strchr (name, ' '))) {
				*p++ = 0;
				off = r_num_math (core->num, p);
			}
			if (*name == '?') {
				r_core_cmd_help_match (core, help_msg_afn, "afn", true);
			} else {
				if (r_str_startswith (name, "base64:")) {
					char *res = (char *)r_base64_decode_dyn (name + 7, -1);
					if (res) {
						free (name);
						name = res;
					}
				}
				if (!*name || !__setFunctionName (core, off, name, false)) {
					R_LOG_ERROR ("Cannot find function at 0x%08" PFMT64x, off);
				}
			}
			free (name);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_afn);
			break;
		} // end of switch (input[2])
		break;
	case 'S': { // afS"
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
		if (fcn) {
			fcn->maxstack = r_num_math (core->num, input + 3);
			//fcn->stack = fcn->maxstack;
		}
		break;
	}
#if 0
	/* this is undocumented, broken and probably have no uses. plz discuss */
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
		case 'm': // "afxm"
			xrefs_map (core, input + 1);
			break;
		case '\0': // "afx"
		case 'j': // "afxj"
		case ' ': // "afx "
		{
			PJ *pj = r_core_pj_new (core);
			if (input[2] == 'j') {
				pj_a (pj);
			}
			if (!pj) {
				return false;
			}
			// list xrefs from current address
			{
				ut64 addr = (input[2] == ' ')? r_num_math (core->num, input + 2): core->offset;
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					ut64 oaddr = core->offset;
					RVecAnalRef *refs = r_anal_function_get_refs (fcn);
					RAnalRef *ref;
					R_VEC_FOREACH (refs, ref) {
						if (input[2] == 'j') {
							pj_o (pj);
							pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
							pj_kn (pj, "from", ref->at);
							pj_kn (pj, "to", ref->addr);
							pj_end (pj);
						} else {
							r_cons_printf ("%c 0x%08" PFMT64x " -> ", ref->type, ref->at);
							switch (R_ANAL_REF_TYPE_MASK (ref->type)) {
							case R_ANAL_REF_TYPE_NULL:
								r_cons_printf ("0x%08" PFMT64x " ", ref->addr);
								break;
							case R_ANAL_REF_TYPE_CODE:
							case R_ANAL_REF_TYPE_ICOD:
							case R_ANAL_REF_TYPE_JUMP:
							case R_ANAL_REF_TYPE_CALL:
							case R_ANAL_REF_TYPE_DATA:
								r_cons_printf ("0x%08" PFMT64x " ", ref->addr);
								r_core_seek (core, ref->at, 1);
								r_core_print_disasm_instructions (core, 0, 1);
								break;
							case R_ANAL_REF_TYPE_STRN:
								{
									char *s = r_core_cmd_strf (core, "pxr 8 @ 0x%08"PFMT64x, ref->addr);
									char *nl = strchr (s, '\n');
									if (nl) {
										*nl = 0;
									}
									r_cons_printf ("%s\n", s);
									free (s);
								}
								break;
							default:
								// ignore rwx
								break;
							}
						}
					}
					RVecAnalRef_free (refs);
					r_core_seek (core, oaddr, 1);
				} else {
					R_LOG_ERROR ("afx: Cannot find function at 0x%08"PFMT64x, addr);
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
			R_LOG_ERROR ("Invalid command. Look at af?");
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
			bool anal_calls = r_config_get_b (core->config, "anal.calls");
			if (input[0] && input[1] == 'r') {
				input++;
				anal_calls = true;
			}
			ut64 addr = core->offset;
			const char *name = NULL;
			// first undefine
			if (input[0] && input[1] == ' ') {
				name = r_str_trim_head_ro (input + 2);
				char *uaddr = strchr (name, ' ');
				if (uaddr) {
					*uaddr++ = 0;
					addr = r_num_math (core->num, uaddr);
				}
				// depth = 1; // or 1?
				// disable hasnext
			}
			r_core_af (core, addr, name, anal_calls);
		}
		break;
	default:
		return false;
		break;
	}
	return true;
}

R_API void r_core_anal_undefine(RCore *core, ut64 off) {
	// very slow
	// RAnalFunction *f = r_anal_get_fcn_in (core->anal, off, -1);
	RAnalFunction *f = r_anal_get_function_at (core->anal, off);
	if (f) {
		if (!strncmp (f->name, "fcn.", 4)) {
			r_flag_unset_name (core->flags, f->name);
		}
		r_meta_del (core->anal, R_META_TYPE_ANY, r_anal_function_min_addr (f), r_anal_function_linear_size (f));
		r_anal_function_del (core->anal, off);
	}
	//r_anal_function_del_locs (core->anal, off);
	r_anal_delete_block_at (core->anal, off);
	char *abcmd = r_str_newf ("ab-0x%"PFMT64x, off);
	if (abcmd) {
		cmd_af (core, abcmd);
		free (abcmd);
	}
}

// size: 0: bits; -1: any; >0: exact size
static void __anal_reg_list(RCore *core, int type, int bits, char mode) {
	PJ *pj = NULL;
	if (mode == 'i') {
		r_core_debug_ri (core, core->anal->reg, 0);
		return;
	} else if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
	}
	RReg *hack = core->dbg->reg;
	core->dbg->reg = core->anal->reg;
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
		// TODO Change the `size` argument of r_debug_reg_list to use -1 for any and 0 for anal->config->bits
		bits = 0;
	} else if (!bits) {
		bits = core->anal->config->bits;
	}
	int mode2 = mode;
	const char *arch_name = get_arch_name (core);
	core->dbg->reg = core->anal->reg;
	/* workaround for thumb */
	if (r_str_startswith (arch_name, "arm") && bits == 16) {
		bits = 32;
	} else {
		const int defsz = r_reg_default_bits (core->anal->reg);
		if (defsz > 0) {
			bits = defsz;
		}
	}
	/* workaround for 6502 and avr*/
	if ((!strcmp (arch_name, "6502") && bits == 8)
		|| (!strcmp (arch_name, "avr") && bits == 8)) {
		if (mode == 'j') {
			mode2 = 'J';
			pj_o (pj);
		}
		// XXX detect which one is current usage
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 16, pj, mode2, use_color);
	}
#if 0
	if (mode == '=') {
		int pcbits = 0;
		const char *pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
		if (pcname) {
			RRegItem *reg = r_reg_get (core->anal->reg, pcname, 0);
			if (reg && bits != reg->size) {
				pcbits = reg->size;
			}
			if (pcbits) {
				// r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, NULL, mode, use_color); // XXX detect which one is current usage
			}
		}
	}
#endif
	r_debug_reg_list (core->dbg, type, bits, pj, mode2, use_color);
	if (mode == 'j') {
		if (mode2 == 'J') {
			pj_end (pj);
		}
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}

	core->dbg->reg = hack;
}

static RRegItem *reg_by_name_role(RCore *core, const char *n) {
	RRegItem *r = r_reg_get (core->anal->reg, n, -1);
	if (!r) {
		int role = r_reg_get_name_idx (n);
		if (role != -1) {
			const char *alias = r_reg_get_name (core->anal->reg, role);
			if (alias) {
				r = r_reg_get (core->anal->reg, alias, -1);
			}
		}
	}
	return r;
}

static bool reg_name_roll_set(RCore *core, const char *name, ut64 n) {
	RRegItem *r = reg_by_name_role (core, name);
	if (r) {
		r_reg_set_value (core->anal->reg, r, n);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
		r_core_cmdf (core, ".dr*%d", core->anal->config->bits); // XXX: replace in future
		return true;
	}
	return false;
}

// XXX dup from drp :OOO
void cmd_anal_reg(RCore *core, const char *str) {
#if 0
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
#endif
	int size = 0, i, type = R_REG_TYPE_GPR;
	int use_colors = r_config_get_i (core->config, "scr.color");
	const char *use_color = NULL;
	const char *name;
	char *arg;
	char *save_ptr = NULL;

	if (use_colors) {
#define ConsP(x) (core->cons && core->cons->context->pal.x)? core->cons->context->pal.x
		use_color = ConsP (creg) : Color_BWHITE;
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
	case ',': // "ar,"
		__tableRegList (core, core->anal->reg, str + 1);
		break;
	case 'e': // "are"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, NULL, 'e', NULL);
		break;
	case '0': // "ar0"
		r_reg_arena_zero (core->anal->reg);
		break;
	case 'A': // "arA"
		{
			int nargs = 4;
			RReg *reg = core->anal->reg;
			for (i = 0; i < nargs; i++) {
				r_strf_var (regname, 32, "A%d", i);
				const char *name = r_reg_get_name (reg, r_reg_get_name_idx (regname));
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
		case '?':
			r_core_cmd_help_match (core, help_msg_dr, "drr", false);
			break;
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
		if (str[1] == 'q') { // "arcq"
			RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
			if (rf) {
				r_cons_printf ("s:%d z:%d c:%d o:%d p:%d\n",
						rf->s, rf->z, rf->c, rf->o, rf->p);
				free (rf);
			}
			break;
		}
		if (str[1] == 'c') { // "arcc"
			char *s = r_reg_profile_to_cc (core->anal->reg);
			if (s) {
				r_cons_printf ("%s\n", s);
				free (s);
			}
		} else {
			RRegItem *r;
			const char *name = r_str_trim_head_ro (str + 1);
			if (*name && name[1]) {
				r = r_reg_cond_get (core->dbg->reg, name);
				if (r) {
					r_cons_println (r->name);
				} else {
					int id = r_reg_cond_from_string (name);
					RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						int o = r_reg_cond_bits (core->dbg->reg, id, rf);
						r_core_return_value (core, o);
						// ORLY?
						r_cons_printf ("%d\n", o);
						free (rf);
					} else {
						R_LOG_ERROR ("unknown conditional or flag register");
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
								r_reg_cond_tostring (i),
								r_reg_cond_bits (core->dbg->reg, i, rf));
						}
						r_cons_newline ();
					} else {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf ("%d %s\n",
								r_reg_cond_bits (core->dbg->reg, i, rf),
								r_reg_cond_tostring (i));
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
			RCoreHelpMessage help_msg = {
				"Usage:", "drs", " # Register states commands",
				"drs", "", "list register stack",
				"drs+", "", "push register state",
				"drs-", "", "pop register state",
				NULL };
			r_core_cmd_help (core, help_msg);
		} break;
		default:
			{
				void *p = core->dbg->reg->regset[0].pool;
				int len = p? r_list_length (p): 0;
				r_cons_printf ("%d\n", len);
			}
			break;
		}
		break;
	case 'p': // "arp"
		// XXX we have to break out .h for these cmd_xxx files.
		cmd_reg_profile (core, 'a', str);
		break;
	case 't': // "art"
		if (str[1] == '?') {
			r_core_cmd_help_match (core, help_msg_dr, "drt", false);
		} else {
			for (i = 0; (name = r_reg_get_type (i)); i++) {
				r_cons_println (name);
			}
		}
		break;
	case 'n': // "arn"
		if (*(str + 1) == '\0') {
			R_LOG_ERROR ("Oops. try arn [PC|SP|BP|SN|A0|A1|A2|A3|A4|R0|R1|ZF|SF|NF|OF]");
			break;
		}
		name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (str + 2));
		if (name && *name) {
			r_cons_println (name);
		} else {
			R_LOG_ERROR ("Oops. try arn [PC|SP|BP|SN|A0|A1|A2|A3|A4|R0|R1|ZF|SF|NF|OF]");
		}
		break;
	case 'd': // "ard"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, core->anal->config->bits,
			NULL, 3, use_color); // XXX detect which one is current usage
		break;
	case 'o': // "aro"
		r_reg_arena_swap (core->dbg->reg, false);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, core->anal->config->bits,
			NULL, 0, use_color); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, false);
		break;
	case '=': // "ar="
		{
			char *p = NULL;
			char *bitstr = NULL;
			if (str[1]) {
				p = r_str_trim_dup (str + 1);
				if (str[1] != ':') {
					// Bits were specified
					bitstr = r_str_tok_r (p, ":", &save_ptr);
					if (r_str_isnumber (bitstr)) {
						st64 sz = r_num_math (core->num, bitstr);
						if (sz > 0) {
							size = sz;
						}
					} else {
						r_core_cmd_help (core, help_msg_ar);
						break;
					}
				}
				int len = bitstr ? strlen (bitstr) : 0;
				if (str[len + 1] == ':') {
					// We have some regs
					char *regs = bitstr ? r_str_tok_r (NULL, ":", &save_ptr) : r_str_tok_r ((char *)str + 1, ":", &save_ptr);
					char *reg = r_str_tok_r (regs, " ", &save_ptr);
					RList *q_regs = r_list_new ();
					if (q_regs) {
						while (reg) {
							r_list_append (q_regs, reg);
							reg = r_str_tok_r (NULL, " ", &save_ptr);
						}
						core->dbg->q_regs = q_regs;
					}
				}
			}
			if (size < 32 && r_str_startswith (r_config_get (core->config, "asm.arch"), "arm")) {
				size = 32;
			}
			__anal_reg_list (core, type, size, str[0]);
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
	case 'i': // "ari"
	case '\0': // "ar"
		__anal_reg_list (core, type, size, str[0]);
		break;
	case ' ': { // "ar "
		arg = strchr (str + 1, '=');
		if (arg) {
			*arg = 0;
			ut64 n = r_num_math (core->num, arg + 1);
			char *ostr = r_str_trim_dup (str + 1);
			char *regname = r_str_trim_nc (ostr);
			if (!reg_name_roll_set (core, regname, n)) {
				R_LOG_ERROR ("ar: Unknown register '%s'", regname);
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
					} else if (showreg (core, name) > 0) {
						// e.g. ar rax
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
		break;
	}
}

R_API int r_core_esil_step(RCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver) {
#define return_tail(x) { tail_return_value = x; goto tail_return; }
	int tail_return_value = 0;
	int ret;
	ut8 code[32];
	RAnalOp op = {0};
	REsil *esil = core->anal->esil;
	// esil->trap = 0;
	const char *_pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	if (R_STR_ISEMPTY (_pcname)) {
		R_LOG_ERROR ("Cannot find =PC in current reg profile");
		return 0;
	}
	char *pcname = strdup (_pcname);
	const bool r2wars = r_config_get_b (core->config, "cfg.r2wars");
	const bool breakoninvalid = r_config_get_b (core->config, "esil.breakoninvalid");
	const int esiltimeout = r_config_get_i (core->config, "esil.timeout");
	ut64 startTime = 0;

	if (esiltimeout > 0) {
		startTime = r_time_now_mono ();
	}
	r_cons_break_push (NULL, NULL);
	ut64 addr = -1;
	ut64 oaddr = -1;
	int minopsz = r_arch_info (core->anal->arch, R_ARCH_INFO_MIN_OP_SIZE);
	ut64 naddr = addr + minopsz;
	bool notfirst = false;
	for (; true; r_anal_op_fini (&op)) {
		esil->trap = 0;
		oaddr = addr;
		addr = r_reg_getv (core->anal->reg, "PC");
		if (notfirst && addr == oaddr) {
			r_reg_setv (core->anal->reg, "PC", naddr);
			addr = naddr;
		} else {
			notfirst = true;
		}
		R_LOG_DEBUG ("esil step at 0x%08"PFMT64x, addr);
		if (r_cons_is_breaked ()) {
			R_LOG_INFO ("[+] ESIL emulation interrupted at 0x%08" PFMT64x, addr);
			return_tail (0);
		}
		// Break if we have exceeded esil.timeout
		if (esiltimeout > 0) {
			ut64 elapsedTime = r_time_now_mono () - startTime;
			elapsedTime >>= 20;
			if (elapsedTime >= esiltimeout) {
				R_LOG_INFO ("[ESIL] Timeout exceeded");
				return_tail (0);
			}
		}
		if (prev_addr) {
			*prev_addr = addr;
		}
		const int perm = esil->exectrap ? R_PERM_X: 0;
		if (!r_io_is_valid_offset (core->io, addr, perm)) {
			esil->trap = R_ANAL_TRAP_EXEC_ERR;
			esil->trap_code = addr;
			R_LOG_INFO ("[ESIL] Trap, trying to execute on non-executable memory");
			return_tail (1);
		}
		// eprintf ("addr %"PFMT64x"\n", addr);
		r_asm_set_pc (core->rasm, addr);
		// run esil pin command here
		const char *pincmd = r_anal_pin_call (core->anal, addr);
		if (pincmd) {
			r_core_cmd0 (core, pincmd);
			ut64 pc = r_reg_getv (core->anal->reg, pcname);
			if (addr != pc) {
				R_LOG_ERROR ("pincmd fail");
				return_tail (1);
			}
		}
		int dataAlign = r_anal_archinfo (esil->anal, R_ANAL_ARCHINFO_DATA_ALIGN);
		if (dataAlign > 1) {
			if (addr % dataAlign) {
				if (esil->cmd && R_STR_ISNOTEMPTY (esil->cmd_trap)) {
					esil->cmd (esil, esil->cmd_trap, addr, R_ANAL_TRAP_UNALIGNED);
				}
				if (breakoninvalid) {
					R_LOG_INFO ("Execution stopped on unaligned instruction (see e?esil.breakoninvalid)");
					return_tail (0);
				}
			}
		}
		(void) r_io_read_at (core->io, addr, code, sizeof (code));
		// TODO: sometimes this is dupe
		ret = r_anal_op (core->anal, &op, addr, code, sizeof (code), R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT);
		naddr = addr + op.size;
		// if type is JMP then we execute the next N instructions
		// update the esil pointer because RAnal.op() can change it
		esil = core->anal->esil;
		if (op.size < 1 || ret < 1) {
			// eprintf ("esil trap\n");
			if (esil->cmd && R_STR_ISNOTEMPTY (esil->cmd_trap)) {
				esil->cmd (esil, esil->cmd_trap, addr, R_ANAL_TRAP_INVALID);
			}
			if (breakoninvalid) {
				R_LOG_INFO ("Stopped execution in an invalid instruction (see e??esil.breakoninvalid)");
				return_tail (0);
			}
			if (op.size < 1) {
				op.size = 1; // avoid inverted stepping
			}
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
					r_reg_setv (core->anal->reg, pcname, op.addr + op.size);
					r_reg_setv (core->dbg->reg, pcname, op.addr + op.size);
				}
				return_tail (1);
			}
		}
		if (r2wars) {
			// this is x86 and r2wars specific, shouldnt hurt outside x86
			ut64 vECX = r_reg_getv (core->anal->reg, "ecx");
			if (op.prefix  & R_ANAL_OP_PREFIX_REP && vECX > 1) {
				//char *tmp = strstr (op.esil.ptr, ",ecx,?{,5,GOTO,}");
				char *tmp = strstr (op.esil.ptr, ",0,GOTO");
				if (tmp) {
					tmp[0] = 0;
					op.esil.len -= 7; //16;
				} else {
					r_reg_setv (core->anal->reg, pcname, addr + op.size);
				}
			} else {
				r_reg_setv (core->anal->reg, pcname, addr + op.size);
			}
		} else {
			r_reg_setv (core->anal->reg, pcname, addr + op.size);
		}
		if (ret) {
			r_esil_set_pc (esil, addr);
			const char *e = R_STRBUF_SAFEGET (&op.esil);
			if (core->dbg->trace->enabled) {
				RReg *reg = core->dbg->reg;
				core->dbg->reg = core->anal->reg;
				r_debug_trace_op (core->dbg, &op);
				core->dbg->reg = reg;
			} else if (R_STR_ISNOTEMPTY (e)) {
				r_esil_parse (esil, e);
				if (esil->trap) {
					R_LOG_WARN ("ESIL TRAP %d/%d ON %s at 0x%08"PFMT64x,
							esil->trap, esil->trap_code, e, addr);
					if (r_config_get_b (core->config, "esil.exectrap")) {
						R_LOG_INFO ("ESIL TRAP ignored");
						esil->trap = false;
					}
				}
#if 0
				// XXX thats not related to arch plugins, and wonder if its useful at all or we want it as part of the anal or esil plugs
				if (core->anal->cur && core->anal->cur->esil_post_loop) {
					core->anal->cur->esil_post_loop (esil, &op);
				}
#endif
				// warn if esil stack is not empty
				r_esil_stack_free (esil);
			}
			bool isNextFall = false;
			if (op.type == R_ANAL_OP_TYPE_CJMP) {
				int err = 0;
				ut64 pc = r_reg_getv (core->anal->reg, pcname);
				if (err) {
					R_LOG_ERROR ("Missing PC register in the current profile");
					break;
				}
				if (pc == addr + op.size) {
					// do not opdelay here
					isNextFall = true;
				}
			}
			// only support 1 slot for now
			if (op.delay && !isNextFall) {
				ut8 code2[32];
				// ut64 naddr = addr + op.size;
				RAnalOp op2 = {0};
				// emulate only 1 instruction
				r_esil_set_pc (esil, naddr);
				(void)r_io_read_at (core->io, naddr, code2, sizeof (code2));
				// TODO: sometimes this is dupe
				ret = r_anal_op (core->anal, &op2, naddr, code2, sizeof (code2), R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT);
				if (ret > 0) {
					switch (op2.type) {
					case R_ANAL_OP_TYPE_CJMP:
					case R_ANAL_OP_TYPE_JMP:
					case R_ANAL_OP_TYPE_CRET:
					case R_ANAL_OP_TYPE_RET:
						// branches are illegal in a delay slot
						esil->trap = R_ANAL_TRAP_EXEC_ERR;
						esil->trap_code = addr;
						R_LOG_INFO ("[ESIL] Trap, trying to execute a branch in a delay slot");
						return_tail (1);
						break;
					}
					const char *e = R_STRBUF_SAFEGET (&op2.esil);
					if (R_STR_ISNOTEMPTY (e)) {
						r_esil_parse (esil, e);
						esil->trap = false; // ignore traps on delayed instructions for now
					}
				} else {
					R_LOG_ERROR ("Invalid instruction at 0x%08"PFMT64x, naddr);
				}
				r_anal_op_fini (&op2);
			}
			tail_return_value = 1;
		}
		// esil->verbose ?
		// eprintf ("REPE 0x%"PFMT64x" %s => 0x%"PFMT64x"\n", addr, R_STRBUF_SAFEGET (&op.esil), r_reg_getv (core->anal->reg, "PC"));
		ut64 pc = r_reg_getv (core->anal->reg, pcname);
		if (pc == UT64_MAX || pc == UT32_MAX) {
			R_LOG_ERROR ("Invalid program counter PC=-1 coming from 0x%08"PFMT64x, addr);
			break;
		}
		if (core->anal->config->codealign > 0) {
			pc -= (pc % core->anal->config->codealign);
			r_reg_setv (core->anal->reg, pcname, pc);
			r_reg_setv (core->dbg->reg, pcname, pc);
		}
		st64 follow = (st64)r_config_get_i (core->config, "dbg.follow");
		if (follow > 0) {
			if ((pc < core->offset) || (pc > (core->offset + follow))) {
				r_core_seek (core, pc, true);
			}
		}
		// check breakpoints
		if (r_bp_get_at (core->dbg->bp, pc)) {
			R_LOG_INFO ("esil breakpoint hit at 0x%"PFMT64x, pc);
			return_tail (0);
		}
		// check addr
		if (until_addr != UT64_MAX) {
			if (pc == until_addr) {
				return_tail (0);
			}
			continue;
		}
#if 1
		if (esil->trap) {
			R_LOG_DEBUG ("TRAP");
			return_tail (0);
		}
#endif
		if (until_expr) {
			// eprintf ("CHK %s\n", until_expr);
			if (r_esil_condition (esil, until_expr)) {
				R_LOG_INFO ("ESIL BREAK!");
				return_tail (0);
			}
			esil->trap = false;
			continue;
		}
		break;
	}
tail_return:
	r_anal_op_fini (&op);
	r_cons_break_pop ();
	free (pcname);
	return tail_return_value;
}

R_API bool r_core_esil_step_back(RCore *core) {
	r_return_val_if_fail (core && core->anal, false);
#if 0
	if (!core->anal->esil || !core->anal->esil->trace) {
		R_LOG_INFO ("Run `aeim` to initialize the esil VM and enable e dbg.trace=true");
		return false;
	}
#endif
	REsil *esil = core->anal->esil;
	if (esil && esil->trace && esil->trace->idx > 0) {
		r_esil_trace_restore (esil, esil->trace->idx - 1);
		return true;
	}
	return false;
}

static void cmd_address_info(RCore *core, const char *addrstr, int fmt) {
	ut64 addr = R_STR_ISEMPTY (addrstr)? core->offset: r_num_math (core->num, addrstr);
	ut64 type = r_core_anal_address (core, addr);
	switch (fmt) {
	case 'j': {
		PJ *pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_o (pj);
		if (type & R_ANAL_ADDR_TYPE_PROGRAM) {
			pj_ks (pj, "program", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_LIBRARY) {
			pj_ks (pj, "library", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_EXEC) {
			pj_ks (pj, "exec", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_READ) {
			pj_ks (pj, "read", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_WRITE) {
			pj_ks (pj, "write", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_FLAG) {
			pj_ks (pj, "flag", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_FUNC) {
			pj_ks (pj, "func", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_STACK) {
			pj_ks (pj, "stack", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_HEAP) {
			pj_ks (pj, "heap", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_REG) {
			pj_ks (pj, "reg", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_ASCII) {
			pj_ks (pj, "ascii", "true");
		}
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
			pj_ks (pj, "sequence", "true");
		}
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
		}
		break;
	default:
		if (type & R_ANAL_ADDR_TYPE_PROGRAM) {
			r_cons_printf ("program\n");
		}
		if (type & R_ANAL_ADDR_TYPE_LIBRARY) {
			r_cons_printf ("library\n");
		}
		if (type & R_ANAL_ADDR_TYPE_EXEC) {
			r_cons_printf ("exec\n");
		}
		if (type & R_ANAL_ADDR_TYPE_READ) {
			r_cons_printf ("read\n");
		}
		if (type & R_ANAL_ADDR_TYPE_WRITE) {
			r_cons_printf ("write\n");
		}
		if (type & R_ANAL_ADDR_TYPE_FLAG) {
			r_cons_printf ("flag\n");
		}
		if (type & R_ANAL_ADDR_TYPE_FUNC) {
			r_cons_printf ("func\n");
		}
		if (type & R_ANAL_ADDR_TYPE_STACK) {
			r_cons_printf ("stack\n");
		}
		if (type & R_ANAL_ADDR_TYPE_HEAP) {
			r_cons_printf ("heap\n");
		}
		if (type & R_ANAL_ADDR_TYPE_REG) {
			r_cons_printf ("reg\n");
		}
		if (type & R_ANAL_ADDR_TYPE_ASCII) {
			r_cons_printf ("ascii\n");
		}
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
			r_cons_printf ("sequence\n");
		}
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
	case 'a': // "aia"
		if (input[1] == 'j') { // "aiaj"
			PJ *pj = pj_new ();
			pj_o (pj);
			int v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
			pj_ki (pj, "minopsz", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
			pj_ki (pj, "maxopsz", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_INV_OP_SIZE);
			pj_ki (pj, "invopsz", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_DATA_ALIGN);
			pj_ki (pj, "dtalign", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
			pj_ki (pj, "codealign", v);
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_printf ("%s\n", s);
			free (s);
		} else {
			int v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
			r_cons_printf ("minopsz %d\n", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
			r_cons_printf ("maxopsz %d\n", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_INV_OP_SIZE);
			r_cons_printf ("invopsz %d\n", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_DATA_ALIGN);
			r_cons_printf ("dtalign %d\n", v);
			v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
			r_cons_printf ("codealign %d\n", v);
		}
		break;
	case 'i': // "aii"
		// global imports
		if (input[1]) {
			if (input[1] == ' ') {
				char *s = r_str_trim_dup (input + 1);
				if (s) {
					r_anal_add_import (core->anal, s);
					free (s);
				}
			} else if (input[1] == '-') {
				r_anal_purge_imports (core->anal);
			} else {
				r_core_cmd_help_match (core, help_msg_ai, "aii", true);
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

static void initialize_stack(RCore *core, ut64 addr, ut64 size) {
	const char *mode = r_config_get (core->config, "esil.fillstack");
	if (mode && *mode && *mode != '0') {
		const ut64 bs = 4096 * 32;
		ut64 i;
		for (i = 0; i < size; i += bs) {
			ut64 left = R_MIN (bs, size - i);
		//	r_core_cmdf (core, "wx 10203040 @ 0x%"PFMT64x, addr);
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
	REsil *esil = core->anal->esil;
	RIOMap *stack_map;
	ut64 curoff = core->offset;
	const char *patt = "";
	ut64 addr = 0x100000;
	ut32 size = 0xf0000;
	RFlagItem *fi;
	char uri[32];
	char nomalloc[256];
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_aeim);
		return;
	}
	if (r_config_get_b (core->config, "cfg.debug")) {
		R_LOG_WARN ("When cfg.debug is set, I refuse to create a fake stack");
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
		esil->stack_addr = addr;
		esil->stack_size = size;
		initialize_stack (core, addr, size);
		return;
	}

	if (R_STR_ISEMPTY (input)) {
		char *fi = sdb_get (core->sdb, "aeim.fd", 0);
		if (fi) {
			// Close the fd associated with the aeim stack
			ut64 fd = sdb_atoi (fi);
			(void)r_io_fd_close (core->io, fd);
			free (fi);
		}
	}
	size = r_config_get_i (core->config, "esil.stack.size");
	addr = r_config_get_i (core->config, "esil.stack.addr");

	if (r_io_map_is_mapped (core->io, addr)) {
		addr = core->offset;
		r_io_map_locate (core->io, &addr, size, 0x10000000);
	}
	patt = r_config_get (core->config, "esil.stack.pattern");
	r_str_ncpy (nomalloc, input, 255);
	char *p = nomalloc;
	char *name = NULL;
	if ((p = strchr (p, ' '))) {
		p = (char *)r_str_trim_head_ro (p);
		addr = r_num_math (core->num, p);
		if ((p = strchr (p, ' '))) {
			p = (char *)r_str_trim_head_ro (p);
			size = (ut32)r_num_math (core->num, p);
			if (size < 1) {
				size = 0xf0000;
			}
			if ((p = strchr (p, ' '))) {
				p = (char *)r_str_trim_head_ro (p);
				name = r_str_newf ("mem.%s", p);
			} else {
				name = r_str_newf ("mem.0x%" PFMT64x "_0x%x", addr, size);
			}
		} else {
			name = r_str_newf ("mem.0x%" PFMT64x "_0x%x", addr, size);
		}
	} else {
		name = r_str_newf ("mem.0x%" PFMT64x "_0x%x", addr, size);
	}
	if (*input == '-') {
		if (esil->stack_fd > 2) { // 0, 1, 2 are reserved for stdio/stderr
			r_io_fd_close (core->io, esil->stack_fd);
			// no need to kill the maps, r_io_map_cleanup does that for us in the close
			esil->stack_fd = 0;
		} else {
			R_LOG_ERROR ("Cannot deinitialize %s", name);
		}
		r_flag_unset_name (core->flags, name);
		r_flag_unset_name (core->flags, "aeim.stack");
		sdb_unset (core->sdb, "aeim.fd", 0);
		free (name);
		return;
	}

	snprintf (uri, sizeof (uri), "malloc://%d", (int)size);
	esil->stack_fd = r_io_fd_open (core->io, uri, R_PERM_RW, 0);
	if (!(stack_map = r_io_map_add (core->io, esil->stack_fd, R_PERM_RW, 0LL, addr, size))) {
		r_io_fd_close (core->io, esil->stack_fd);
		R_LOG_ERROR ("Cannot create map for tha stack, fd %d got closed again", esil->stack_fd);
		esil->stack_fd = 0;
		return;
	}
	r_io_map_set_name (stack_map, name);
	free (name);
	// r_flag_set (core->flags, name, addr, size);	//why is this here?
	char val[128], *v;
	v = sdb_itoa (esil->stack_fd, 10, val, sizeof (val));
	sdb_set (core->sdb, "aeim.fd", v, 0);

	r_config_set_b (core->config, "io.va", true);
	if (R_STR_ISNOTEMPTY (patt)) {
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
	ut64 sp = addr + (size / 2);
	r_reg_setv (core->anal->reg, "SP", sp);
	r_reg_setv (core->anal->reg, "BP", sp);
	r_reg_setv (core->anal->reg, "PC", curoff);
	r_core_cmd0 (core, ".ar*");
	esil->stack_addr = addr;
	esil->stack_size = size;
	initialize_stack (core, addr, size);
	r_core_seek (core, curoff, false);
}

typedef struct {
	RList *regs;
	RList *regread;
	RList *regwrite;
	RList *regvalues;
	RList *inputregs;
} AeaStats;

static void aea_stats_init(AeaStats *stats) {
	stats->regs = r_list_newf (free);
	stats->regread = r_list_newf (free);
	stats->regwrite = r_list_newf (free);
	stats->regvalues = r_list_newf (free);
	stats->inputregs = r_list_newf (free);
}

static void aea_stats_fini(AeaStats *stats) {
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

static R_TH_LOCAL char *oldregread = NULL;
static R_TH_LOCAL RList *mymemxsr = NULL;
static R_TH_LOCAL RList *mymemxsw = NULL;

#define R_NEW_DUP(x) memcpy((void*)malloc (sizeof (x)), &(x), sizeof (x))
typedef struct {
	ut64 addr;
	int size;
} AeaMemItem;

static bool mymemwrite(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	AeaMemItem *n;
	RListIter *iter;
	r_list_foreach (mymemxsw, iter, n) {
		if (addr == n->addr) {
			return true;
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
	return true;
}

static bool mymemread(REsil *esil, ut64 addr, ut8 *buf, int len) {
	RListIter *iter;
	AeaMemItem *n;
	r_list_foreach (mymemxsr, iter, n) {
		if (addr == n->addr) {
			return true;
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
	return true;
}

static bool myregwrite(REsil *esil, const char *name, ut64 *val) {
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
		char *v = r_str_newf ("%"PFMT64d, *val);
		if (!contains (stats->regvalues, v)) {
			r_list_push (stats->regvalues, strdup (v));
		}
		free (v);
	}
	return false;
}

static bool myregread(REsil *esil, const char *name, ut64 *val, int *len) {
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
	return false;
}

static void showregs(RList *list) {
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
	r_cons_newline ();
}

static void showmem(RList *list) {
	if (!r_list_empty (list)) {
		AeaMemItem *item;
		RListIter *iter;
		r_list_foreach (list, iter, item) {
			r_cons_printf (" 0x%08"PFMT64x, item->addr);

		}
	}
	r_cons_newline ();
}

static void showregs_json(RList *list, PJ *pj) {
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

static void showmem_json(RList *list, PJ *pj) {
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
	int ptr, ops, ops_end = 0, len, buf_sz;
	ut64 addr_end;
	AeaStats stats;
	const char *esilstr;
	RAnalOp aop = {0};
	RList* regnow;
	PJ *pj = NULL;
	if (!core) {
		return false;
	}
	int maxopsize = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
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
	ut8 *buf = malloc (buf_sz);
	if (!buf) {
		return false;
	}
	(void)r_io_read_at (core->io, addr, (ut8 *)buf, buf_sz);
	aea_stats_init (&stats);
	r_reg_arena_push (core->anal->reg);
	const bool cfg_r2wars = r_config_get_b (core->config, "cfg.r2wars");
	REsil *esil = esil_new_setup (core);
	if (!esil) {
		free (buf);
		return false;
	}
#	define hasNext(x) (x&1) ? (addr<addr_end) : (ops<ops_end)

	mymemxsr = r_list_new ();
	mymemxsw = r_list_new ();
	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->cb.hook_mem_write = mymemwrite;
	esil->cb.hook_mem_read = mymemread;
	esil->nowrite = true;
	r_cons_break_push (NULL, NULL);
	for (ops = ptr = 0; ptr < buf_sz && hasNext (mode); ops++, ptr += len) {
		if (r_cons_is_breaked ()) {
			break;
		}
		len = r_anal_op (core->anal, &aop, addr + ptr, buf + ptr, buf_sz - ptr, R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT);
		esilstr = R_STRBUF_SAFEGET (&aop.esil);
		if (R_STR_ISNOTEMPTY (esilstr)) {
			if (len < 1) {
				R_LOG_ERROR ("Invalid 0x%08"PFMT64x" instruction %02x %02x",
					addr + ptr, buf[ptr], buf[ptr + 1]);
				r_anal_op_fini (&aop);
				break;
			}
			if (cfg_r2wars) {
				if (aop.prefix  & R_ANAL_OP_PREFIX_REP) {
					char *tmp = strstr (esilstr, ",0,GOTO");
					if (tmp) {
						tmp[0] = 0;
					}
				}
			}
			r_esil_parse (esil, esilstr);
			r_esil_stack_free (esil);
		}
		r_anal_op_fini (&aop);
		if (len < 1) {
			len = 1;
		}
	}
	r_cons_break_pop ();
	esil->nowrite = false;
	esil->cb.hook_reg_write = NULL;
	esil->cb.hook_reg_read = NULL;
	r_esil_free (esil);
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
		if (!r_list_empty (stats.regvalues)) {
			pj_k (pj, "V");
			showregs_json (stats.regvalues, pj);
		}
		if (!r_list_empty (regnow)) {
			pj_k (pj, "N");
			showregs_json (regnow, pj);
		}
		if (!r_list_empty (mymemxsr)) {
			pj_k (pj, "@R");
			showmem_json (mymemxsr, pj);
		}
		if (!r_list_empty (mymemxsw)) {
			pj_k (pj, "@W");
			showmem_json (mymemxsw, pj);
		}

		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	} else if ((mode >> 5) & 1) {
		// nothing
	} else {
		if (!r_list_empty (stats.inputregs)) {
			r_cons_printf (" I: ");
			showregs (stats.inputregs);
		}
		if (!r_list_empty (stats.regs)) {
			r_cons_printf (" A: ");
			showregs (stats.regs);
		}
		if (!r_list_empty (stats.regread)) {
			r_cons_printf (" R: ");
			showregs (stats.regread);
		}
		if (!r_list_empty (stats.regwrite)) {
			r_cons_printf (" W: ");
			showregs (stats.regwrite);
		}
		if (!r_list_empty (stats.regvalues)) {
			r_cons_printf (" V: ");
			showregs (stats.regvalues);
		}
		if (!r_list_empty (regnow)) {
			r_cons_printf (" N: ");
			showregs (regnow);
		}
		if (!r_list_empty (mymemxsr)) {
			r_cons_printf ("@R:");
			showmem (mymemxsr);
		}
		if (!r_list_empty (mymemxsw)) {
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

static void cmd_aespc(RCore *core, ut64 addr, ut64 until_addr, int ninstr) {
	REsil *esil = core->anal->esil;
	int i, j = 0;
	RAnalOp aop = {0};
	int ret , bsize = R_MAX (4096, core->blocksize);
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);

#if 0
	// eprintf ("   aesB %llx %llx %d\n", addr, until_addr, off); // 0x%08llx %d  %s\n", aop.addr, ret, aop.mnemonic);
	if (!esil) {
		R_LOG_DEBUG ("cmd_espc: creating new esil instance");
		esil = esil_new_setup (core);
		if (!esil) {
			return;
		}
		r_esil_free (core->anal->esil);
		core->anal->esil = esil;
	}
#endif
	ut8 *buf = malloc (bsize);
	if (!buf) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
		return;
	}
	if (addr == UT64_MAX) {
		addr = r_reg_getv (core->dbg->reg, pc);
	}
	ut64 cursp = r_reg_getv (core->dbg->reg, "SP");
	ut64 oldoff = core->offset;
	const ut64 flags = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_DISASM;
	for (i = 0, j = 0; j < ninstr; i++, j++) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
			R_LOG_WARN ("Chomp %d of %d", i, bsize);
		}
		if (!i) {
			r_io_read_at (core->io, addr, buf, bsize);
		}
		if (addr == until_addr) {
			break;
		}
		ret = r_anal_op (core->anal, &aop, addr, buf + i, bsize - i, flags);
		if (ret < 1) {
			R_LOG_ERROR ("Failed analysis at 0x%08"PFMT64x, addr);
			r_anal_op_fini (&aop);
			break;
		}
		// skip calls and such
		switch (aop.type) {
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_IRCALL:
		case R_ANAL_OP_TYPE_CCALL:
		case R_ANAL_OP_TYPE_UCCALL:
			// skip
			break;
		default:
			r_reg_setv (core->anal->reg, "PC", aop.addr + aop.size);
			r_reg_setv (core->dbg->reg, "PC", aop.addr + aop.size);
			const char *e = R_STRBUF_SAFEGET (&aop.esil);
			if (R_STR_ISNOTEMPTY (e)) {
				 // eprintf ("   0x%08llx %d  %s\n", aop.addr, ret, aop.mnemonic);
				(void)r_esil_parse (esil, e);
			}
			break;
		}
		int inc = (core->search->align > 0)? core->search->align - 1: ret - 1;
		if (inc < 0) {
			inc = minopcode;
		}
		i += inc;
		addr += aop.size;
		r_anal_op_fini (&aop);
	}
	free (buf);
	r_core_seek (core, oldoff, true);
	r_reg_setv (core->dbg->reg, "SP", cursp);
}

static void r_anal_aefa(RCore *core, const char *arg) {
	ut64 to = r_num_math (core->num, arg);
	ut64 at, from = core->offset;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, to, -1);
	if (!from || from == UT64_MAX) {
		if (fcn) {
			from = fcn->addr;
		} else {
			R_LOG_INFO ("Usage: aefa [from] # if no from address is given, uses fcn.addr");
			return;
		}
	}
	R_LOG_INFO ("Emulate from 0x%08"PFMT64x" to 0x%08"PFMT64x, from, to);
	R_LOG_INFO ("Resolve call args for 0x%08"PFMT64x, to);

	// emulate
	// XXX do not use commands, here, just use the api
	r_core_cmd_call (core, "aeim"); // XXX
	ut64 off = core->offset;
	for (at = from; at < to ; at++) {
		r_core_cmdf (core, "aepc 0x%08"PFMT64x, at);
		r_core_cmd_call (core, "aeso");
		r_core_seek (core, at, true);
		int delta = r_num_get (core->num, "$l");
		if (delta < 1) {
			break;
		}
		at += delta - 1;
	}
	r_core_seek (core, off, true);

	// the logic of identifying args by function types and
	// show json format and arg name goes into arA
	r_core_cmd_call (core, "arA");
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
			ut64 v = r_debug_arg_get (core->dbg, "reg", i);
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
		r_strf_var (alias, 32, "A%d", i);
		r_reg_setv (core->anal->reg, alias, r_num_math (core->num, arg));
		i++;
	}
	ut64 sp = r_reg_getv (core->anal->reg, "SP");
	r_reg_setv (core->anal->reg, "SP", 0);

	r_reg_setv (core->anal->reg, "PC", core->offset);
	r_core_cmd_call (core, "aesu 0");

	r_reg_setv (core->anal->reg, "SP", sp);
	free (inp);

//	r_reg_arena_pop (core->dbg->reg);
}

static void cmd_debug_stack_init(RCore *core, int argc, char **argv, char **envp) {
	// TODO: add support for 32 bit
	RBuffer *b = r_buf_new ();
	if (!b) {
		return;
	}
	ut64 sp = core->offset;
	int i;
	ut64 dyld_call_from = UT64_MAX;
	r_buf_append_ut64 (b, dyld_call_from);
	r_buf_append_ut64 (b, 0); // rbp
	r_buf_append_ut64 (b, argc); // rbp
	int envp_count = 0;
	for (i = 0; envp[i]; i++) {
		envp_count++;
	}
	ut64 strp = sp + 40 + (argc * 8) + (envp_count * 8);
	// pointer table
	for (i = 0; i < argc && argv[i]; i++) {
		r_buf_append_ut64 (b, strp);
		strp += strlen (argv[i]) + 1;
	}
	r_buf_append_ut64 (b, 0);
	for (i = 0; i < envp_count; i++) {
		r_buf_append_ut64 (b, strp);
		strp += strlen (envp[i]) + 1;
	}
	r_buf_append_ut64 (b, 0);
	// string table
	for (i = 0; i < argc && argv[i]; i++) {
		r_buf_append_string (b, argv[i]);
		r_buf_append_ut8 (b, 0);
	}
	for (i = 0; i < envp_count; i++) {
		r_buf_append_string (b, envp[i]);
		r_buf_append_ut8 (b, 0);
	}
	int slen = 0;
	ut8 *s = r_buf_read_all (b, &slen);
	char *x = r_hex_bin2strdup (s, slen);
	r_cons_printf ("wx %s\n", x);
	free (x);
	free (s);
	r_buf_free (b);
}

R_IPI int core_type_by_addr(RCore *core, ut64 addr) {
	const RList *list = r_flag_get_list (core->flags, addr);
	RListIter *iter;
	RFlagItem *item;
	bool has_flag = false;
	int type = R_ANAL_REF_TYPE_DATA;
	r_list_foreach (list, iter, item) {
		if (strchr (item->name, '.')) {
			has_flag = true;
			if (r_str_startswith (item->name, "str")) {
				type = R_ANAL_REF_TYPE_STRN;
				break;
			}
		}
	}
	if (!has_flag) {
		return -1;
	}
	return type;
}

static bool regwrite_hook(REsil *esil, const char *name, ut64 *val) {
	RCore *core = esil->user;
	int type = core_type_by_addr (core, *val);
	if (type != -1) {
		r_anal_xrefs_set (core->anal, esil->addr, *val, type);
	}
	return false;
}

static void __anal_esil_function(RCore *core, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
#if 0
	if (!core->anal->esil) {
		r_core_cmd_call (core, "aei");
	}
#endif
	if (!sdb_const_get (core->sdb, "aeim.fd", 0)) {
		r_core_cmd_call (core, "aeim"); // should be set by default imho
	}
	void *u = core->anal->esil->user;
	core->anal->esil->user = core;
	void *p = core->anal->esil->cb.hook_reg_write;
	core->anal->esil->cb.hook_reg_write = regwrite_hook;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal,
			addr, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
	const char *pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	const ut64 old_pc = r_reg_getv (core->anal->reg, pcname);
	if (fcn) {
		bool anal_verbose = r_config_get_b (core->config, "anal.verbose");
		// emulate every instruction in the function recursively across all the basic blocks
		r_list_foreach (fcn->bbs, iter, bb) {
			ut64 pc = bb->addr;
			ut64 end = bb->addr + bb->size;
			RAnalOp op;
			int ret, bbs = end - pc;
			if (bbs < 1 || bbs > 0xfffff || pc >= end) {
				R_LOG_ERROR ("Invalid block size");
				continue;
			}
			// eprintf ("[*] Emulating 0x%08"PFMT64x" basic block 0x%08" PFMT64x " - 0x%08" PFMT64x "\r[", fcn->addr, pc, end);
			ut8 *buf = calloc (1, bbs + 1);
			if (!buf) {
				break;
			}
			// const char *pcname = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
			r_io_read_at (core->io, pc, buf, bbs);
			int left;
			while (pc < end) {
				left = R_MIN (end - pc, 32);
				// r_asm_set_pc (core->rasm, pc);
				ret = r_anal_op (core->anal, &op, pc, buf + pc - bb->addr, left, R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_ESIL| R_ARCH_OP_MASK_DISASM); // read overflow
				if (ret) {
					bool opskip = false;
#if 0
					switch (op.type) {
					case R_ANAL_OP_TYPE_JMP:
					case R_ANAL_OP_TYPE_NOP:
					case R_ANAL_OP_TYPE_CJMP:
					case R_ANAL_OP_TYPE_UJMP:
					case R_ANAL_OP_TYPE_CALL:
					case R_ANAL_OP_TYPE_RET:
						opskip = true;
						break;
					}
#endif
					if (!opskip) {
						const char *esilstr = R_STRBUF_SAFEGET (&op.esil);
						// eprintf ("0x%08"PFMT64x"  %s\n", pc, op.mnemonic);
						if (R_STR_ISNOTEMPTY (esilstr)) {
							r_reg_setv (core->anal->reg, pcname, pc + op.size);
							r_esil_set_pc (core->anal->esil, pc);
							r_esil_parse (core->anal->esil, esilstr);
							if (anal_verbose) {
								r_esil_dumpstack (core->anal->esil);
							}
							r_esil_stack_free (core->anal->esil);
						}
					}
					pc += op.size;
				} else {
					pc += 4; // XXX
				}
				r_anal_op_fini (&op);
			}
			free (buf);
		}
	} else {
		R_LOG_ERROR ("Cannot find function at 0x%08" PFMT64x, addr);
	}
	core->anal->esil->cb.hook_reg_write = p;
	core->anal->esil->user = u;
	r_reg_setv (core->anal->reg, pcname, old_pc);
}

static char *_aeg_get_title(void *data) {
	RAnalEsilDFGNode *enode = (RAnalEsilDFGNode *)data;
	return r_str_newf ("%d", enode->idx);
}

static char *_aeg_get_body(void *data) {
	RAnalEsilDFGNode *enode = (RAnalEsilDFGNode *)data;
	return r_str_newf ("%s%s",
		(enode->type & R_ANAL_ESIL_DFG_TAG_GENERATIVE)? "generative:": "",
		r_strbuf_get (enode->content));
}

static void cmd_aeg(RCore *core, int argc, char *argv[]) {
	r_return_if_fail (core && argc >= 0 && argv);
	RAGraphTransitionCBs cbs = {
		.get_title = _aeg_get_title,
		.get_body = _aeg_get_body
	};
	switch (argv[0][1]) {
	case '\x00': // "aeg"
		if (argc == 1) {
			RAnalOp *aop = r_core_anal_op (core, core->offset, R_ARCH_OP_MASK_ESIL);
			if (!aop) {
				return;
			}
			const char *esilstr = r_strbuf_get (&aop->esil);
			if (R_STR_ISNOTEMPTY (esilstr)) {
				RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (core->anal, NULL, esilstr,
					r_config_get_b (core->config, "esil.dfg.mapinfo"),
					r_config_get_b (core->config, "esil.dfg.maps"));
				if (!dfg) {
					r_anal_op_free (aop);
					return;
				}
				RAGraph *agraph = r_agraph_new_from_graph (dfg->flow, &cbs);
				r_anal_esil_dfg_free (dfg);
				agraph->can->linemode = r_config_get_i (core->config, "graph.linemode");
				agraph->layout = r_config_get_i (core->config, "graph.layout");
				r_agraph_print (agraph);
				r_agraph_free (agraph);
			}
			r_anal_op_free (aop);
		} else {
			RStrBuf *sb = r_strbuf_new ("");
			int i;
			for (i = 1; i < argc; i++) {
				if (r_strbuf_length (sb) > 0) {
					r_strbuf_append (sb, ",");
				}
				r_strbuf_append (sb, argv[i]);
			}
			char *esilexpr = r_strbuf_drain (sb);
			RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (core->anal, NULL, esilexpr,
					r_config_get_b (core->config, "esil.dfg.mapinfo"),
					r_config_get_b (core->config, "esil.dfg.maps"));
			if (dfg) {
				RAGraph *agraph = r_agraph_new_from_graph (dfg->flow, &cbs);
				r_anal_esil_dfg_free (dfg);
				agraph->can->linemode = r_config_get_i (core->config, "graph.linemode");
				agraph->layout = r_config_get_i (core->config, "graph.layout");
				r_agraph_print (agraph);
				r_agraph_free (agraph);
			}
			free (esilexpr);
		}
		break;
	case 'b': // "aegb"
		r_core_cmd0 (core, "aeg `pieq $Fi`");
		break;
	case 'n': // "aegn"
		if (argc > 1) {
			int n = r_num_math (core->num, argv[1]);
			r_core_cmdf (core, "aeg `pieq %d`", n);
		} else {
			R_LOG_ERROR ("Usage: aegn [number-of-instructions-to-combine-its-esil-essence]");
		}
		break;
	case 'v': // "aegv" - visual
	{
		RAGraph *agraph = NULL;
		if (argc == 1) {
			RAnalOp *aop = r_core_anal_op (core, core->offset, R_ARCH_OP_MASK_ESIL);
			if (!aop) {
				return;
			}
			const char *esilstr = r_strbuf_get (&aop->esil);
			if (R_STR_ISNOTEMPTY (esilstr)) {
				RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (core->anal, NULL, esilstr,
					r_config_get_b (core->config, "esil.dfg.mapinfo"),
					r_config_get_b (core->config, "esil.dfg.maps"));
				if (!dfg) {
					r_anal_op_free (aop);
					return;
				}
				agraph = r_agraph_new_from_graph (dfg->flow, &cbs);
				r_anal_esil_dfg_free (dfg);
			}
			r_anal_op_free (aop);
		} else {
			RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (core->anal, NULL, argv[1],
				r_config_get_b (core->config, "esil.dfg.mapinfo"),
				r_config_get_b (core->config, "esil.dfg.maps"));
			r_return_if_fail (dfg);
			agraph = r_agraph_new_from_graph (dfg->flow, &cbs);
			r_anal_esil_dfg_free (dfg);
		}
		const ut64 osc = r_config_get_i (core->config, "scr.color");
		r_config_set_i (core->config, "scr.color", 0);
		ut64 oseek = core->offset;
		if (agraph) {
			agraph->need_update_dim = true;
			// layout
			agraph->layout = r_config_get_i (core->config, "graph.layout");
			agraph->need_set_layout = true;
			int update_seek = r_core_visual_graph (core, agraph, NULL, true);
			r_cons_show_cursor (true);
			r_cons_enable_mouse (false);
			if (update_seek != -1) {
				r_core_seek (core, oseek, false);
			}
			r_agraph_free (agraph);
		}
		r_config_set_i (core->config, "scr.color", osc);
	}
		break;
	case 'f':	// "aegf"
	{
		RStrBuf *filtered = r_anal_esil_dfg_filter_expr (core->anal, argv[1], argv[2],
			r_config_get_b (core->config, "esil.dfg.mapinfo"),
			r_config_get_b (core->config, "esil.dfg.maps"));
		if (filtered) {
			r_cons_printf ("%s\n", r_strbuf_get (filtered));
			r_strbuf_free (filtered);
		}
	}
		break;
#if 0
	case 'c':	// "aegc"
	{
		RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (core->anal, NULL, argv[1]);
		if (!dfg) {
			return;
		}
		r_anal_esil_dfg_fold_const (core->anal, dfg);
		if (argv[0][1] == 'f') {	// "aegcf"
			RStrBuf *filtered = r_anal_esil_dfg_filter (dfg, argv[2]);
			if (filtered) {
				r_cons_printf ("%s\n", r_strbuf_get (filtered));
				r_strbuf_free (filtered);
			}
		} else {
			print_esil_dfg_as_commands (core, dfg);
		}
		r_anal_esil_dfg_free (dfg);
	}
		break;
#endif
	case '?': // "aeg?"
	default:
		r_core_cmd_help (core, help_msg_aeg);
		break;
	}
}

static void cmd_anal_esil(RCore *core, const char *input, bool verbose) {
	REsil *esil = core->anal->esil;
	ut64 addr = core->offset;
	ut64 adr ;
	char *n, *n1;
	int off;
	ut64 until_addr = UT64_MAX;

	const char *until_expr = NULL;
	RAnalOp *op = NULL;

	switch (input[0]) {
	case 'v': // "aev"
		r_core_visual_esil (core, r_str_trim_head_ro (input + 1));
		break;
	case 'p': // "aep"
		switch (input[1]) {
		case 'a': // "aepa"
			{
				ut64 at = core->offset;
				if (input[2] == ' ') {
					at = r_num_math (core->num, input + 2);
				}
				// get flag in current offset
				// find a pin named like the flag, skip dots if any
				RFlagItem *f = r_flag_get_by_spaces (core->flags, at, R_FLAGS_FS_SYMBOLS, R_FLAGS_FS_IMPORTS, NULL);
				if (!f) {
					f = r_flag_get_i (core->flags, at);
				}
				if (f) {
					const char *last = r_str_rchr (f->name, NULL, '.');
					const char *pin_name = last? last + 1: f->name;
					const char *havepin = r_anal_pin_get (core->anal, pin_name);
					if (havepin) {
						r_core_cmdf (core, "aep %s @ 0x%08" PFMT64x, pin_name, at);
					}
				}
			}
			break;
		case '.': // "aep."
			{
			const char *n = r_anal_pin_at (core->anal, core->offset);
			if (R_STR_ISNOTEMPTY (n)) {
				r_cons_printf ("%s\n", n);
			}
			}
			break;
		case 'c': // "aepc"
			if (input[2] == ' ' || input[2] == '=') {
				// seek to this address
				reg_name_roll_set (core, "PC", r_num_math (core->num, input + 3));
				r_core_cmd0 (core, ".ar*");
			} else {
				r_core_cmd_help_match (core, help_msg_aep, "aepc", true);
			}
			break;
		case 'k':
			{
				char *out = sdb_querys (core->anal->sdb_pins, NULL, 0, r_str_trim_head_ro (input + 3));
				if (out) {
					r_cons_printf ("%s\n", out);
					free (out);
				}
			}
			break;
		case '*':
		case 0:
			r_anal_pin_list (core->anal);
			break;
		case '-':
			if (input[2] == '*') {
				r_anal_pin_init (core->anal);
			} else {
				if (input[2]) {
					addr = r_num_math (core->num, input + 2);
				}
				r_anal_pin_unset (core->anal, addr);
			}
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
	case '*': // "aeq"
		// XXX: this is wip, not working atm
		r_cons_printf ("trap: %d\n", core->anal->esil->trap);
		r_cons_printf ("trap-code: %d\n", core->anal->esil->trap_code);
		break;
	case ' ':
	case 'q': // "aeq"
		r_esil_set_pc (esil, core->offset);
		r_esil_parse (esil, r_str_trim_head_ro (input + 1));
		if (verbose && *input != 'q') {
			r_esil_dumpstack (esil);
		}
		r_esil_stack_free (esil);
		break;
	case 's': // "aes" "aeso" "aesu" "aesue"
#if 0
		r_core_cmd0 (core, "ae `aoe@r:PC`");
		r_core_cmd0 (core, ".ar*");
		break;
#endif
		// aes -> single step
		// aesb -> single step back
		// aeso -> single step over
		// aesu -> until address
		// aesue -> until esil expression
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_aes);
			break;
		case 'l': // "aesl"
		{
			ut64 pc = r_debug_reg_get (core->dbg, "PC");
			RAnalOp *op = r_core_anal_op (core, pc, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
			if (!op) {
				break;
			}
			r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
			r_debug_reg_set (core->dbg, "PC", pc + op->size);
			r_esil_set_pc (esil, pc + op->size);
			r_core_cmd0 (core, ".ar*");
			r_anal_op_free (op);
		} break;
		case 'b': // "aesb"
			if (!r_core_esil_step_back (core)) {
				R_LOG_ERROR ("Cannot step back");
			}
			r_core_cmd0 (core, ".ar*");
			break;
		case 'B': // "aesB"
			n = strchr (input + 2, ' ');
			if (n) {
				n = (char *)r_str_trim_head_ro (n + 1);
			}
			if (n) {
				char *n2 = strchr (n, ' ');
				if (n2) {
					*n2++ = 0;
				}
				ut64 off = r_num_math (core->num, n);
				ut64 nth = n2? r_num_math (core->num, n2): 1;
				cmd_aespc (core, core->offset, off, (int)nth);
			} else {
				r_core_cmd_help_match (core, help_msg_aes, "aesB", true);
			}
			break;
		case 'u': // "aesu"
			until_expr = NULL;
			until_addr = UT64_MAX;
			if (r_str_endswith (input, "?")) {
				r_core_cmd_help_match (core, help_msg_aes, "aesu", true);
			} else switch (input[2]) {
			case 'e': // "aesue"
				until_expr = r_str_trim_head_ro (input + 3);
				break;
			case ' ': // "aesu"
				until_addr = r_num_math (core->num, input + 2);
				break;
			case 'o': // "aesuo"
				step_until_optype (core, r_str_trim_head_ro (input + 3));
				break;
			default:
				r_core_cmd0 (core, "aes?~aesu");
				break;
			}
			if (until_expr || until_addr != UT64_MAX) {
				r_core_esil_step (core, until_addr, until_expr, NULL, false);
			}
			r_core_cmd0 (core, ".ar*");
			break;
		case 's': // "aess"
			if (input[2] == 'u') { // "aessu"
				if (input[3] == 'e') {
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
				if (input[3] == 'e') {
					until_expr = input + 3;
				} else {
					until_addr = r_num_math (core->num, input + 2);
				}
				r_core_esil_step (core, until_addr, until_expr, NULL, true);
				r_core_cmd0 (core, ".ar*");
			} else if (!input[2] || input[2] == ' ') { // "aeso [addr]"
				// step over
				op = r_core_anal_op (core, r_reg_getv (core->anal->reg,
					r_reg_get_name (core->anal->reg, R_REG_NAME_PC)), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
				if (op && op->type == R_ANAL_OP_TYPE_CALL) {
					until_addr = op->addr + op->size;
				}
				r_core_esil_step (core, until_addr, until_expr, NULL, false);
				r_anal_op_free (op);
				r_core_cmd0 (core, ".ar*");
			} else {
				r_core_cmd_help_match (core, help_msg_aes, "aesou", true);
			}
			break;
		case 'p': //"aesp"
			n = strchr (input, ' ');
			n1 = R_STR_ISNOTEMPTY (n) ? strchr (n + 1, ' ') : NULL;
			if ((!n || !n1) || (!*n || !*n1)) {
				r_core_cmd_help_match (core, help_msg_aes, "aesp", true);
				break;
			}
			adr = R_STR_ISNOTEMPTY (n)? r_num_math (core->num, n + 1): 0;
			off = R_STR_ISNOTEMPTY (n1)? r_num_math (core->num, n1 + 1): 0;
			cmd_aespc (core, adr, -1, off);
			break;
		case ' ':
			n = strchr (input, ' ');
			n1 = n ? n + 1: NULL;
			if (!n1 || !*n1) {
				r_core_esil_step (core, until_addr, until_expr, NULL, false);
				break;
			}
			off = r_num_math (core->num, n1);
			cmd_aespc (core, -1, -1, off);
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
			__core_anal_appcall (core, r_str_trim_head_ro (input + 1));
		}
		break;
	case 'c': // "aec"
		if (input[1] == '?') { // "aec?"
			r_core_cmd_help (core, help_msg_aec);
		} else if (input[1] == 's') { // "aecs"
			st64 maxsteps = r_config_get_i (core->config, "esil.maxsteps");
			ut64 countsteps = 0;
			const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			for (; !maxsteps || countsteps < maxsteps; countsteps++) {
				// ignore return value is not an error, should 0, 1, -1 imho
				(void)r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
				r_core_cmd0 (core, ".ar*");
				addr = r_reg_getv (core->anal->reg, pc);
				op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
				if (!op) {
					R_LOG_ERROR ("invalid instruction at 0x%08" PFMT64x, addr);
					break;
				}
				if (op->type == R_ANAL_OP_TYPE_SWI) {
					R_LOG_INFO ("syscall instruction at 0x%08" PFMT64x, addr);
					break;
				} else if (op->type == R_ANAL_OP_TYPE_TRAP) {
					R_LOG_INFO ("trap instruction at 0x%08" PFMT64x, addr);
					break;
				}
				r_anal_op_free (op);
				op = NULL;
				if (core->anal->esil->trap || core->anal->esil->trap_code) {
					R_LOG_INFO ("esil trap '%s' (%d) at 0x%08" PFMT64x,
							r_esil_trapstr (core->anal->esil->trap),
							core->anal->esil->trap_code, addr);
					break;
				}
			}
			if (op) {
				r_anal_op_free (op);
				op = NULL;
			}
		} else if (input[1] == 'c') { // "aecc"
			const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			st64 maxsteps = r_config_get_i (core->config, "esil.maxsteps");
			ut64 countsteps = 0;
			for (; !maxsteps || countsteps < maxsteps; countsteps++) {
				(void)r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
				r_core_cmd0 (core, ".ar*");
				addr = r_num_get (core->num, pc);
				op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC);
				if (!op) {
					break;
				}
				if (op->type == R_ANAL_OP_TYPE_CALL || op->type == R_ANAL_OP_TYPE_UCALL) {
					R_LOG_INFO ("stop in call instruction at 0x%08" PFMT64x, addr);
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
			{
				char *arg = r_str_trim_dup (input + 2);
				RList *args = r_str_split_list (arg, " ", 0);
				int i, argc = atoi (r_list_pop_head (args));
				if (argc < 1) {
					r_core_cmd_help (core, help_msg_aei);
					break;
				}
				char **argv = calloc (argc + 1, sizeof (void *));
				for (i = 0; i < argc; i++) {
					char *arg = r_list_pop_head (args);
					if (!arg) {
						break;
					}
					argv[i] = arg;
				}
				argv[i] = 0;
				char **envp = calloc (r_list_length (args) + 1, sizeof (void *));
				for (i = 0; ; i++) {
					char *arg = r_list_pop_head (args);
					if (!arg) {
						break;
					}
					envp[i] = arg;
				}
				envp[i] = 0;
#if R2__UNIX__
				if (strstr (input, "$env")) {
					extern char **environ;
					cmd_debug_stack_init (core, argc, argv, environ);
				} else {
					cmd_debug_stack_init (core, argc, argv, envp);
				}
#else
				cmd_debug_stack_init (core, argc, argv, envp);
#endif
				free (arg);
			}
			break;
		case 'm': // "aeim"
			cmd_esil_mem (core, input + 2);
			break;
		case 'p': // "aeip" // initialize pc = $$
			reg_name_roll_set (core, "PC", core->offset);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_aei);
			cmd_esil_mem (core, "?");
			break;
		case '-':
			r_esil_reset (esil);
			break;
		case 0: // "aei"
			esil = esil_new_setup (core);
			if (esil) {
				r_esil_free (core->anal->esil);
				core->anal->esil = esil;
				r_esil_reset (esil);
				const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
				if (pc && r_reg_getv (core->anal->reg, pc) == 0LL) {
					reg_name_roll_set (core, "PC", core->offset);
				}
			}
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
		default:
			cmd_esil_mem (core, "?");
			break;
		}
		break;
	case 'k': // "aek"
		switch (input[1]) {
		case '\0':
			input = "*";
			/* fall through */
		case ' ':
			if (esil && esil->stats) {
				char *out = sdb_querys (esil->stats, NULL, 0, input + 2);
				if (out) {
					r_cons_println (out);
					free (out);
				}
			} else {
				R_LOG_INFO ("esil.stats is empty. Run 'aei'");
			}
			break;
		case '-':
			if (esil) {
				sdb_reset (esil->stats);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_aek);
			break;
		}
		break;
	case 'L': // "aeL" esil plugins
		if (input[1] == ' ') { // "aeL"
			const char *name = r_str_trim_head_ro (input + 2);
			r_esil_plugin_activate (core->anal->esil, name);
		} else if (input[1] == '-') { // "aeL-"
			const char *name = r_str_trim_head_ro (input + 2);
			r_esil_plugin_deactivate (core->anal->esil, name);
		} else {
			REsilPlugin *p;
			RListIter *iter;
			if (core->anal->esil) {
				r_list_foreach (core->anal->esil->plugins, iter, p) {
					r_cons_printf ("%s\n", p->name);
				}
			} else {
				R_LOG_WARN ("Run 'aei'");
			}
		}
		break;
	case 'g': // "aeg"
		{
			int argc;
			char **argv = r_str_argv (input, &argc);
			r_return_if_fail (argv);
			cmd_aeg (core, argc, argv);
			int i;
			for (i = 0; i < argc; i++) {
				free (argv[i]);
			}
			free (argv);
		}
		break;
	case 'b': // "aeb"
		{
			ut64 addr = r_num_math (core->num, input + 1);
			if (!addr || addr == UT64_MAX) {
				addr = core->offset;
			}
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
			if (fcn) {
				RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, addr);
				if (bb) {
					cmd_aespc (core, bb->addr, bb->addr + bb->size, bb->ninstr);
					// r_core_cmdf (core, "aesp `ab~addr[1]` `ab~ninstr[1]`");
				} else {
					R_LOG_ERROR ("No basic block in this address");
				}
			} else {
				R_LOG_ERROR ("No function in this address");
			}
		// ab~ninstr[1]
		}
		break;
	case 'f': // "aef"
		if (input[1] == 'a') { // "aefa"
			r_anal_aefa (core, r_str_trim_head_ro (input + 2));
		} else { // This should be aefb -> because its emulating all the bbs
			// anal ESIL to REIL.
			__anal_esil_function (core, core->offset);
		} break;
	case 't': // "aet"
		switch (input[1]) {
		case 's': // "aets"
			switch (input[2]) {
			case '+': // "aets+"
#if 0
				if (!esil) {
					R_LOG_ERROR ("ESIL is not initialized. Use `aeim` first");
					break;
				}
#endif
				if (esil->trace) {
					R_LOG_INFO ("ESIL trace already started");
					break;
				}
				esil->trace = r_esil_trace_new (esil);
				if (!esil->trace) {
					break;
				}
				r_config_set_b (core->config, "dbg.trace", true);
				break;
			case '-': // "aets-"
				if (!esil) {
					R_LOG_ERROR ("ESIL is not initialized. Use `aeim` first");
					break;
				}
				if (!esil->trace) {
					R_LOG_ERROR ("No ESIL trace started");
					break;
				}
				r_esil_trace_free (esil->trace);
				esil->trace = NULL;
				r_config_set_b (core->config, "dbg.trace", false);
				break;
			default:
				r_core_cmd_help (core, help_msg_aets);
				break;
			}
			break;
		case 0: // "aet"
			r_esil_trace_list (core->anal->esil, 0);
			break;
		default:
			R_LOG_ERROR ("Unknown command");
			break;
		}
		break;
	case 'A': // "aeA"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_aea);
			break;
		case 'r':
			cmd_aea (core, 1 + (1<<1), core->offset, r_num_math (core->num, input+2));
			break;
		case 'w':
			cmd_aea (core, 1 + (1<<2), core->offset, r_num_math (core->num, input+2));
			break;
		case 'n':
			cmd_aea (core, 1 + (1<<3), core->offset, r_num_math (core->num, input+2));
			break;
		case 'j':
			cmd_aea (core, 1 + (1<<4), core->offset, r_num_math (core->num, input+2));
			break;
		case '*':
			cmd_aea (core, 1 + (1<<5), core->offset, r_num_math (core->num, input+2));
			break;
		case 'f': {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) {
				cmd_aea (core, 1, r_anal_function_min_addr (fcn), r_anal_function_linear_size (fcn));
			}
			break;
			}
		default:
			cmd_aea (core, 1, core->offset, (int)r_num_math (core->num, input[1]? input + 2:input + 1));
		}
		break;
	case 'a': { // "aea"
		RReg *reg = core->anal->reg;
		ut64 pc = r_reg_getv (reg, "PC");
		RAnalOp *op = r_core_anal_op (core, pc, 0);
		if (!op) {
			break;
		}
		ut64 newPC = core->offset + op->size;
		r_reg_setv (reg, "PC", newPC);
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_aea);
			break;
		case 'r':
			cmd_aea (core, 1<<1, core->offset, r_num_math (core->num, input+2));
			break;
		case 'w':
			cmd_aea (core, 1<<2, core->offset, r_num_math (core->num, input+2));
			break;
		case 'n':
			cmd_aea (core, 1<<3, core->offset, r_num_math (core->num, input+2));
			break;
		case 'j':
			cmd_aea (core, 1<<4, core->offset, r_num_math (core->num, input+2));
			break;
		case '*':
			cmd_aea (core, 1<<5, core->offset, r_num_math (core->num, input+2));
			break;
		case 'B': { // "aeaB"
			bool json = input[2] == 'j';
			int a = json? 3: 2;
			ut64 addr = (input[a] == ' ')? r_num_math (core->num, input + a): core->offset;
			RList *l = r_anal_get_blocks_in (core->anal, addr);
			RAnalBlock *b;
			RListIter *iter;
			r_list_foreach (l, iter, b) {
				int mode = json? (1<<4): 1;
				cmd_aea (core, mode, b->addr, b->size);
				break;
			}
			break;
		}
		case 'f': { // "aeaf"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) {
				switch (input[2]) {
				case 'j': // "aeafj"
					cmd_aea (core, 1<<4, r_anal_function_min_addr (fcn), r_anal_function_linear_size (fcn));
					break;
				default:
					cmd_aea (core, 1, r_anal_function_min_addr (fcn), r_anal_function_linear_size (fcn));
					break;
				}
				break;
			}
		}
			break;
		case 'b': { // "aeab"
			RAnalBlock *bb = r_anal_bb_from_offset (core->anal, core->offset);
			if (bb) {
				switch (input[2]) {
				case 'j': // "aeabj"
					cmd_aea (core, 1 | (1<<4), bb->addr, bb->size);
					break;
				default:
					cmd_aea (core, 1, bb->addr, bb->size);
					break;
				}
			}
			}
			break;
		default: {
			const char *arg = input[1]? input + 2: "";
			ut64 len = r_num_math (core->num, arg);
			cmd_aea (core, 0, core->offset, len);
			}
			break;
		}
		r_reg_setv (reg, "PC", pc);
		break;
		  }
	case 'x':
		if (input[1] == ' ') { // "aex"
			char *hex;
			int ret, bufsz;

			input = r_str_trim_head_ro (input + 1);
			hex = strdup (input);
			if (!hex) {
				break;
			}

			RAnalOp aop = {0};
			bufsz = r_hex_str2bin (hex, (ut8*)hex);
			ret = r_anal_op (core->anal, &aop, core->offset,
				(const ut8*)hex, bufsz, R_ARCH_OP_MASK_ESIL);
			if (ret > 0) {
				const char *str = R_STRBUF_SAFEGET (&aop.esil);
				char *str2 = r_str_newf (" %s", str);
				cmd_anal_esil (core, str2, false);
				free (str2);
				r_core_return_value (core, 1);
			} else {
				// fail to exevute, update code
				r_core_return_value (core, 0);
			}
			r_anal_op_fini (&aop);
			free (hex);
		} else if (input[1] == 'a') { // "aexa"
			char *bytes = r_core_cmd_strf (core, "\"pa %s\"", r_str_trim_head_ro (input + 2));
			if (R_STR_ISNOTEMPTY (bytes)) {
				r_core_cmdf (core, "aex %s", bytes);
			}
			free (bytes);
		} else { // "aex?"
			r_core_cmd_help (core, help_msg_aex);
		}
		break;
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
	if (input[0]) {
		len = (int)r_num_get (core->num, input + 1);
	}
	if (len < 1) {
		return;
	}
	ut8 *buf = calloc (len, 1);
	if (buf) {
		r_io_read_at (core->io, core->offset, buf, len);
		core_anal_bytes (core, buf, len, 0, input[0]);
		free (buf);
	}
}

static int compare_mnemonics(const char *a , const char *b) {
	if (!a || !b) {
		return 0;
	}
	char *sa = strdup (a);
	char *sb = strdup (b);
	r_str_replace_ch (sa, ' ', ',', 0);
	r_str_replace_ch (sb, ' ', ',', 0);
	RList *la = r_str_split_list (sa, ",", 0);
	RList *lb = r_str_split_list (sb, ",", 0);
	int i = 0;
	for (i = 0; i < 10; i++) {
		char *wa = r_list_get_n (la, i);
		char *wb = r_list_get_n (lb, i);
		if (!wa || !wb) {
			i = 0;
			break;
		}
		if (strcmp (wa, wb)) {
			break;
		}
	}
	r_list_free (la);
	r_list_free (lb);
	free (sa);
	free (sb);
	return i;
}

static int intsort(const void *a, const void *b) {
	if (a > b) {
		return 1;
	}
	if (a == b) {
		return 0;
	}
	return -1;
}

static void cmd_anal_opcode_bits(RCore *core, const char *arg, int mode) {
	ut8 buf[32] = {0};
	if (R_STR_ISNOTEMPTY (arg)) {
		char *choparg = r_str_ndup (arg, 8);
		int res = r_hex_str2bin (choparg, (ut8 *)buf);
		free (choparg);
		if (res < 1) {
			R_LOG_ERROR ("Invalid hex string");
			return;
		}
	} else {
		r_io_read_at (core->io, core->offset, buf, sizeof (buf));
	}
	RList *args[8];
	int i, j;
	RAnalOp analop, op;
	r_anal_op_init (&analop);
	r_anal_op_set_bytes (&analop, core->offset, buf, sizeof (ut64));
	(void)r_anal_op (core->anal, &analop, core->offset, buf, sizeof (buf), R_ARCH_OP_MASK_DISASM);
	int last = R_MIN (8, analop.size);
	PJ *pj = (mode == 'j')? r_core_pj_new (core): NULL;
	if (last < 1) {
		return;
	}
	for (i = 0; i < 8; i++) {
		args[i] = r_list_new ();
	}

	if (pj) {
		pj_o (pj);
		pj_ks (pj, "opstr", analop.mnemonic);
		pj_kn (pj, "size", analop.size);
		pj_ko (pj, "bytes");
	}
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < last; i++) {
		ut8 *byte = buf + i;
		if (pj) {
			pj_a (pj);
		}
		if (i == 4) {
			r_strbuf_append (sb, "| ");
		}
		for (j = 0; j < 8; j++) {
			bool bit = R_BIT_CHK (byte, 7 - j);
			r_anal_op_init (&op);
			ut8 newbuf[sizeof (ut64)] = {0};
			memcpy (&newbuf, &buf, sizeof (ut64));
			ut8 *newbyte = newbuf + i;
			if (bit) {
				newbuf[i] = R_BIT_UNSET (newbyte, 7 - j);
			} else {
				newbuf[i] = R_BIT_SET (newbyte, 7 - j);
			}
			r_anal_op_set_bytes (&op, core->offset, newbuf, sizeof (newbuf));
			(void)r_anal_op (core->anal, &op, core->offset, newbuf, sizeof (ut64), R_ARCH_OP_MASK_DISASM);
			// r_cons_printf ("%d %s\n%d %s\n\n", (i*8) + j, analop.mnemonic, (i*8)+j, op.mnemonic);
			int word_change = compare_mnemonics (analop.mnemonic, op.mnemonic);
			r_anal_op_fini (&op);
			if (pj) {
				pj_n (pj, word_change);
				r_list_append (args[word_change], (void *)(size_t)((i * 8) + 7 - j));
			}
			r_strbuf_appendf (sb, "%d", word_change);
		}
		if (pj) {
			pj_end (pj);
		}
		r_strbuf_append (sb, " ");
	}
	if (pj) {
		void *n;
		RListIter *iter;
		pj_end (pj);
		char *s = r_strbuf_drain (sb);
		pj_ks (pj, "flipstr", s);
		free (s);
		pj_ka (pj, "args");
		for (j = 0; j < 8; j++) {
			if (r_list_empty (args[j])) {
				break;
			}
			pj_a (pj);
			r_list_sort (args[j], intsort);
			r_list_foreach (args[j], iter, n) {
				int nn = (int)((size_t)n & ST32_MAX);
				pj_n (pj, nn);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
		s = pj_drain (pj);
		r_cons_printf ("%s\n", s);
		free (s);
	} else {
		if (mode == 'm') {
			int pi = 0;
			char *s = r_strbuf_drain (sb);
			char *p = s;
			ut8 finalmask[8] = {0};
			for (; *p; p++) {
				int byte_index = (pi / 8);
				int bit_index = (pi % 8);
				ut8 *byte = finalmask + byte_index;
				if (*p == '0') {
					// only pick the bits that modify the 0th word
					R_BIT_SET (byte, bit_index);
					pi++;
				} else if (isalnum (*p)) {
					pi++;
				}
				if (byte_index >= last) {
					break;
				}
			}
			free (s);
			for (i = 0; i < 8 && i < last; i++) {
				r_cons_printf ("%02x", finalmask[i]);
			}
			r_cons_newline ();
		} else {
			r_strbuf_appendf (sb, " : %s", analop.mnemonic);
			char *s = r_strbuf_drain (sb);
			r_cons_printf ("%s\n", s);
			free (s);
		}
	}
	r_anal_op_fini (&analop);
	for (i = 0; i < 8; i++) {
		r_list_free (args[i]);
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
	case 'r': { // "aor"
		int count = 1;
		int obs = core->blocksize;
		int fmt = input[0];
		if (input[0] == 'e') {
			switch (input[1]) {
			case 'q': // "aoeq"
				fmt = 'E'; // quiet esil
				input++;
				break;
			case 'm': // "aoem"
				fmt = 'm'; // memory esil
				input++;
				break;
			case '?': // "aoe?"
				r_core_cmd_help_match (core, help_msg_ao, "aoe", false);
				return;
			}
		}
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
		core_anal_bytes (core, core->block, core->blocksize, count, fmt);
		if (obs != core->blocksize) {
			r_core_block_size (core, obs);
		}
		}
		break;
	case 't': // "aot"
		if (input[1] == 'l') {
			r_core_cmd_call (core, "/atl");
		} else if (input[1] == '\0') {
			r_core_cmd0 (core, "ao~^type[1]");
		} else {
			r_core_cmd_help (core, help_msg_aot);
		}
		break;
	case 'm': // "aom"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_aom);
		} else if (input[1] == 'd') {
			const int id = (input[2] == ' ')
				?(int)r_num_math (core->num, input + 2): -1;
			char *ops = r_asm_mnemonics (core->rasm, id, false);
			if (ops) {
				char *ptr = ops;
				char *nl = strchr (ptr, '\n');
				while (nl) {
					*nl = 0;
					char *desc = r_asm_describe (core->rasm, ptr);
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
				r_cons_printf ("%d\n", r_asm_mnemonics_byname (core->rasm, input + 2));
			} else {
				// "aoml"
				const int id = (input[1] == ' ')
					?(int)r_num_math (core->num, input + 2): -1;
				char *ops = r_asm_mnemonics (core->rasm, id, input[1] == 'j');
				if (ops) {
					r_str_trim (ops);
					r_cons_println (ops);
					free (ops);
				}
			}
		} else {
			r_core_cmd0 (core, "ao~mnemonic[1]");
		}
		break;
	case 'b': // "aob"
		if (input[1] == 'j') {
			cmd_anal_opcode_bits (core, r_str_trim_head_ro (input + 2), 'j');
		} else if (input[1] == 'm') {
			cmd_anal_opcode_bits (core, NULL, 'm');
		} else {
			cmd_anal_opcode_bits (core, r_str_trim_head_ro (input + 1), 0);
		}
		break;
	case 'c': // "aoc"
	{
		RList *hooks;
		RListIter *iter;
		RAnalCycleHook *hook;
		char *instr_tmp = NULL;
		int ccl = input[1]? r_num_math (core->num, &input[2]): 0; //get cycles to look for
		bool cr = r_config_get_b (core->config, "asm.cmt.right");
		bool fu = r_config_get_b (core->config, "asm.functions");
		bool li = r_config_get_b (core->config, "asm.lines");
		bool xr = r_config_get_b (core->config, "asm.xrefs");

		r_config_set_b (core->config, "asm.cmt.right", true);
		r_config_set_b (core->config, "asm.functions", false);
		r_config_set_b (core->config, "asm.lines", false);
		r_config_set_b (core->config, "asm.xrefs", false);

		hooks = r_core_anal_cycles (core, ccl); //analyse
		r_cons_clear_line (1);
		r_list_foreach (hooks, iter, hook) {
			instr_tmp = r_core_disassemble_instr (core, hook->addr, 1);
			r_cons_printf ("After %4i cycles:\t%s", (ccl - hook->cycles), instr_tmp);
			r_cons_flush ();
			free (instr_tmp);
		}
		r_list_free (hooks);

		r_config_set_b (core->config, "asm.cmt.right", cr); //reset settings
		r_config_set_b (core->config, "asm.functions", fu);
		r_config_set_b (core->config, "asm.lines", li);
		r_config_set_b (core->config, "asm.xrefs", xr);
	}
	break;
	case 'd': // "aod"
		if (input[1] == 'a') { // "aoda"
			// list sdb database
			sdb_foreach (core->rasm->pair, listOpDescriptions, core);
		} else if (input[1] == 0) {
			int cur = R_MAX (core->print->cur, 0);
			// XXX: we need cmd_xxx.h (cmd_anal.h)
			core_anal_bytes (core, core->block + cur, core->blocksize, 1, 'd');
		} else if (input[1] == ' ') {
			char *d = r_asm_describe (core->rasm, input + 2);
			if (d && *d) {
				r_cons_println (d);
				free (d);
			} else {
				R_LOG_ERROR ("Unknown mnemonic");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_ao, "aod", false);
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
	case 'f': // "aof"
		if (strlen (input + 1) > 1) {
			RAnalOp aop = {0};
			ut8 data[32];
			r_io_read_at (core->io, core->offset, data, sizeof (data));
			int ret = r_anal_op (core->anal, &aop, core->offset, data, sizeof (data), R_ARCH_OP_MASK_ESIL);
			if (ret > 0) {
				const char *arg = input + 2;
				const char *expr = R_STRBUF_SAFEGET (&aop.esil);
				RStrBuf *b = r_anal_esil_dfg_filter_expr (core->anal, expr, arg,
					r_config_get_b (core->config, "esil.dfg.mapinfo"),
					r_config_get_b (core->config, "esil.dfg.maps"));
				if (b) {
					char *s = r_strbuf_drain (b);
					r_cons_printf ("%s\n", s);
					free (s);
				}
			} else {
				R_LOG_WARN ("Unable to analyze instruction");
			}
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
	if (len > ALLOC_SIZE_LIMIT) {
		R_LOG_ERROR ("Length is too large");
		return;
	}
	RBinFile *bf = r_bin_cur (core->bin);
	if (!bf) {
		return;
	}
	addr = core->offset;
	if (!len) {
		// ignore search.in to avoid problems. analysis != search
		RIOMap *map = r_io_map_get_at (core->io, addr);
		if (map && (map->perm & R_PERM_X)) {
			// search in current section
			if (r_io_map_size (map) > bf->size) {
				addr = r_io_map_begin (map);
				if (bf->size > map->delta) {
					len = bf->size - map->delta;
				} else {
					R_LOG_ERROR ("Oops something went wrong aac");
					return;
				}
			} else {
				addr = r_io_map_begin (map);
				len = r_io_map_size (map);
			}
		} else {
			if (map && r_io_map_begin (map) != map->delta && bf->size > (core->offset - r_io_map_begin (map) + map->delta)) {
				len = bf->size - (core->offset - r_io_map_begin (map) + map->delta);
			} else {
				if (bf->size > core->offset) {
					len = bf->size - core->offset;
				} else {
					R_LOG_ERROR ("Oops invalid range");
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
		if (r_anal_op (core->anal, &op, addr, buf + bufi, 4096 - bufi, R_ARCH_OP_MASK_BASIC)) {
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
		r_core_cmd0 (core, "abb $SS @ $S");
		RList *list = r_core_get_boundaries_prot (core, R_PERM_X, NULL, "anal");
		RListIter *iter;
		RIOMap* map;
		if (!list) {
			goto ctrl_c;
		}
		r_list_foreach (list, iter, map) {
			from = r_io_map_begin (map);
			to = r_io_map_end (map);
			if (r_cons_is_breaked ()) {
				goto ctrl_c;
			}
			if (!from && !to) {
				R_LOG_ERROR ("Cannot determine search boundaries");
			} else if (to - from > UT32_MAX) {
				char *unit = r_num_units (NULL, 0, to - from);
				R_LOG_WARN ("Skipping huge range (%s)", unit);
				free (unit);
			} else {
				R_LOG_DEBUG ("abb 0x%08"PFMT64x" @ 0x%08"PFMT64x, (to - from), from);
				r_core_cmdf (core, "abb 0x%08"PFMT64x" @ 0x%08"PFMT64x, (to - from), from);
			}
		}
	} else {
		st64 sz = r_num_math (core->num, arg + 1);
		if (sz < 1) {
			R_LOG_ERROR ("Invalid range");
			return;
		}
		r_core_cmdf (core, "abb 0x%08"PFMT64x" @ 0x%08"PFMT64x, sz, core->offset);
	}
ctrl_c:
	r_cons_break_pop ();
}

static void _anal_calls(RCore *core, ut64 addr, ut64 addr_end, bool printCommands, bool importsOnly) {
	RAnalOp op = {0};
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
			addr += bsz;
			continue;
		}
		RAnalHint *hint = r_anal_hint_get (core->anal, addr);
		if (hint && hint->bits) {
			setBits = hint->bits;
		}
		r_anal_hint_free (hint);
		if (setBits != core->rasm->config->bits) {
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
					ut8 zbuf[4] = {0};
					r_io_read_at (core->io, op.jump, zbuf, 4);
					isValidCall = memcmp (zbuf, "\x00\x00\x00\x00", 4);
				}
				if (isValidCall) {
#if JAYRO_03
					if (!anal_is_bad_call (core, from, to, addr, buf, bufi)) {
						fcn = r_anal_get_fcn_in (core->anal, op.jump, R_ANAL_FCN_TYPE_ROOT);
						if (!fcn) {
							r_core_anal_fcn (core, op.jump, addr, R_ANAL_REF_TYPE_CALL, depth - 1);
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
							r_core_anal_fcn (core, op.jump, addr, R_ANAL_REF_TYPE_CALL, depth - 1);
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
		R_LOG_ERROR ("Too big");
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
				ut64 addr = r_io_map_begin (map);
				_anal_calls (core, addr, r_io_map_end (map), printCommands, importsOnly);
				if (r_cons_is_breaked ()) {
					break;
				}
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
	const char *arg = (input[0] == ' ')? input + 1: "*";
	char *out = sdb_querys (db, NULL, 0, arg);
	if (out) {
		r_cons_println (out);
		free (out);
	} else {
		R_LOG_ERROR ("Usage: ask [query]");
	}
}

static void cmd_anal_syscall(RCore *core, const char *input) {
	char snstr[32];
	PJ *pj = NULL;
	RSyscallItem *si;
	RListIter *iter;
	RList *list;
	int n;

	switch (input[0]) {
	case 'c': // "asc"
		if (input[1] == 'a') {
			if (input[2] == ' ') {
				if (!isalpha ((ut8)input[3]) && (n = r_num_math (core->num, input + 3)) >= 0 ) {
					si = r_syscall_get (core->anal->syscall, n, -1);
					if (si) {
						r_cons_printf (".equ SYS_%s %s\n", si->name, syscallNumber (snstr, n));
						r_syscall_item_free (si);
					} else {
						R_LOG_ERROR ("Unknown syscall number");
					}
				} else {
					n = r_syscall_get_num (core->anal->syscall, input + 3);
					if (n != -1) {
						r_cons_printf (".equ SYS_%s %s\n", input + 3, syscallNumber (snstr, n));
					} else {
						R_LOG_ERROR ("Unknown syscall name");
					}
				}
			} else {
				list = r_syscall_list (core->anal->syscall);
				r_list_foreach (list, iter, si) {
					r_cons_printf (".equ SYS_%s %s\n", si->name, syscallNumber (snstr, si->num));
				}
				r_list_free (list);
			}
		} else {
			if (input[1] == ' ') {
				if (!isalpha ((ut8)input[2]) && (n = r_num_math (core->num, input + 2)) >= 0) {
					si = r_syscall_get (core->anal->syscall, n, -1);
					if (si) {
						r_cons_printf ("#define SYS_%s %s\n", si->name, syscallNumber (snstr, n));
						r_syscall_item_free (si);
					} else {
						R_LOG_ERROR ("Unknown syscall number");
					}
				} else {
					n = r_syscall_get_num (core->anal->syscall, input + 2);
					if (n != -1) {
						r_cons_printf ("#define SYS_%s %s\n", input + 2, syscallNumber (snstr, n));
					} else {
						R_LOG_ERROR ("Unknown syscall name");
					}
				}
			} else {
				list = r_syscall_list (core->anal->syscall);
				r_list_foreach (list, iter, si) {
					r_cons_printf ("#define SYS_%s %s\n",
						si->name, syscallNumber (snstr, si->num));
				}
				r_list_free (list);
			}
		}
		break;
	case 'k': // "ask"
		cmd_sdbk (core->anal->syscall->db, input + 1);
		break;
	case 'l': // "asl"
		if (input[1] == ' ') {
			const char *sc_name = r_str_trim_head_ro (input + 2);
			int sc_number = r_syscall_get_num (core->anal->syscall, sc_name);
			if (sc_number != 0) {
				r_cons_printf ("%s\n", syscallNumber (snstr, sc_number));
			} else {
				sc_number = r_num_math (core->num, sc_name);
				si = r_syscall_get (core->anal->syscall, sc_number, -1);
				if (!si) {
					si = r_syscall_get (core->anal->syscall, -1, sc_number);
				}
				if (si) {
					r_cons_println (si->name);
					r_syscall_item_free (si);
				} else {
					R_LOG_ERROR ("Unknown syscall number");
				}
			}
		} else {
			list = r_syscall_list (core->anal->syscall);
			r_list_foreach (list, iter, si) {
				r_cons_printf ("%s = 0x%02x.%s\n",
					si->name, si->swi, syscallNumber (snstr, si->num));
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
		r_list_free (list);
		break;
	case '\0':
		cmd_syscall_do (core, -1, core->offset);
		break;
	case ' ':
		{
		const char *sn = r_str_trim_head_ro (input + 1);
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

static void anal_axg(RCore *core, const char *input, int level, Sdb *db, int opts, PJ* pj) {
	char arg[32], pre[128];
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

	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
	bool open_object = false;
	if (xrefs && !RVecAnalRef_empty (xrefs)) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
		if (fcn) {
			if (is_r2) {
				r_cons_printf ("agn 0x%08"PFMT64x" %s\n", fcn->addr, fcn->name);
			} else if (is_json) {
				char taddr[64];
				pj_o (pj);
				pj_k (pj, sdb_itoa (addr, 10, taddr, sizeof (taddr)));
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
				pj_k (pj, sdb_itoa (addr, 10, taddr, sizeof (taddr)));
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
	if (xrefs) {
		R_VEC_FOREACH (xrefs, ref) {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, ref->addr, -1);
			if (fcn) {
				if (is_r2) {
					r_cons_printf ("agn 0x%08"PFMT64x" %s\n", fcn->addr, fcn->name);
					r_cons_printf ("age 0x%08"PFMT64x" 0x%08"PFMT64x"\n", fcn->addr, addr);
				} else if (is_json) {
					if (level == 0) {
						char taddr[64];
						pj_o (pj);
						pj_k (pj, sdb_itoa (ref->addr, 10, taddr, sizeof (taddr)));
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
						pj_k (pj, sdb_itoa (ref->addr, 10, taddr, sizeof (taddr)));
						pj_o (pj);
						pj_ks (pj, "type", "fcn");
						pj_kn (pj, "fcn_addr", fcn->addr);
						pj_ks (pj, "name", fcn->name);
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
					pj_k (pj, sdb_itoa (ref->addr, 10, taddr, sizeof (taddr)));
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
	RVecAnalRef_free (xrefs);
}

static void cmd_anal_ucall_ref(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	if (fcn) {
		r_cons_printf (" ; %s", fcn->name);
	} else {
		r_cons_printf (" ; 0x%" PFMT64x, addr);
	}
}

static char *get_op_ireg(void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	char *res = NULL;
	RAnalOp *op = r_core_anal_op (core, addr, 0);
	if (op && op->ireg) {
		res = strdup (op->ireg);
	}
	r_anal_op_free (op);
	return res;
}

static char *get_buf_asm(RCore *core, ut64 from, ut64 addr, RAnalFunction *fcn, bool color) {
	int has_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	char str[512];
	const int size = 12;
	ut8 buf[12];
	RAnalOp asmop = {0};
	bool asm_subvar = r_config_get_b (core->config, "asm.sub.var");
	bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
	core->parser->pseudo = r_config_get_b (core->config, "asm.pseudo");
	core->parser->subrel = r_config_get_i (core->config, "asm.sub.rel");
	core->parser->localvar_only = r_config_get_b (core->config, "asm.sub.varonly");

	if (core->parser->subrel) {
		core->parser->subrel_addr = from;
	}
	r_io_read_at (core->io, addr, buf, size);
	r_asm_set_pc (core->rasm, addr);
	r_asm_disassemble (core->rasm, &asmop, buf, size);
	int ba_len = strlen (asmop.mnemonic) + 128;
	char *ba = malloc (ba_len);
	strcpy (ba, asmop.mnemonic);
	if (asm_subvar) {
		core->parser->get_ptr_at = r_anal_function_get_var_stackptr_at;
		core->parser->get_reg_at = r_anal_function_get_var_reg_at;
		core->parser->get_op_ireg = get_op_ireg;
		r_parse_subvar (core->parser, fcn, addr, asmop.size, ba, ba, ba_len);
	}
	RAnalHint *hint = r_anal_hint_get (core->anal, addr);
	r_parse_filter (core->parser, addr, core->flags, hint, ba, str, sizeof (str), be);
	r_anal_hint_free (hint);
	r_anal_op_set_mnemonic (&asmop, asmop.addr, ba);
	free (ba);
	char *buf_asm = NULL;
	if (color && has_color) {
		buf_asm = r_print_colorize_opcode (core->print, str,
				core->cons->context->pal.reg, core->cons->context->pal.num, false, fcn ? fcn->addr : 0);
	} else {
		buf_asm = r_str_new (str);
	}
	return buf_asm;
}

static const char *axtm_name(RCore *core, ut64 addr) {
	const char *name = NULL;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		name = fcn->name;
	} else {
		RFlagItem *f = r_flag_get_at (core->flags, addr, false);
		if (f) {
			name = f->name;
		}
	}
	return name;
}

// Alternative sorting, first by "addr"/"from", then by "at"/"to"
static inline int compare_ref(const RAnalRef *a, const RAnalRef *b) {
	if (a->addr < b->addr) {
		return -1;
	}
	if (a->addr > b->addr) {
		return 1;
	}
	if (a->at < b->at) {
		return -1;
	}
	if (a->at > b->at) {
		return 1;
	}

	return 0;
}

static void axtm(RCore *core) {
	RVecAnalRef *refs = r_anal_xrefs_get (core->anal, UT64_MAX);
	if (refs && !RVecAnalRef_empty (refs)) {
		RVecAnalRef_sort (refs, compare_ref);

		ut64 last_addr = UT64_MAX;
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			const bool is_first = ref->addr != last_addr;
			const char *name;
			if (is_first) {
				name = axtm_name (core, ref->addr);
				r_cons_printf ("0x%"PFMT64x": %s\n", ref->addr, name? name: "?");
			}

			name = axtm_name (core, ref->at);
			r_cons_printf ("  0x%"PFMT64x": %s\n", ref->at, name? name: "?");

			last_addr = ref->addr;
		}
	}

	RVecAnalRef_free (refs);
}

static void axfm(RCore *core) {
	RVecAnalRef *refs = r_anal_xrefs_get_from (core->anal, UT64_MAX);
	if (refs && !RVecAnalRef_empty (refs)) {
		RVecAnalRef_sort (refs, compare_ref);

		ut64 last_addr = UT64_MAX;
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			const bool is_first = ref->addr != last_addr;
			const char *name;
			if (is_first) {
				name = axtm_name (core, ref->addr);
				r_cons_printf ("0x%"PFMT64x": %s\n", ref->addr, name? name: "?");
			}

			name = axtm_name (core, ref->at);
			r_cons_printf ("  0x%"PFMT64x": %s\n", ref->at, name? name: "?");

			last_addr = ref->addr;
		}
	}
	RVecAnalRef_free (refs);
}

static bool cmd_anal_refs(RCore *core, const char *input) {
	bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->print->config);
	ut64 addr = core->offset;
	switch (input[0]) {
	case '-': { // "ax-"
		char *cp_inp = strdup (input + 1);
		char *ptr = cp_inp;
		r_str_trim_head (ptr);
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

			// R2_590 slow, we should add a function that deletes several xrefs
			RVecAnalRef *list = r_anal_xrefs_get (core->anal, to);
			RAnalRef *ref;
			R_VEC_FOREACH (list, ref) {
				if (from != UT64_MAX && from == ref->addr) {
					r_anal_xref_del (core->anal, ref->addr, ref->at);
				}
				if (from == UT64_MAX) {
					r_anal_xref_del (core->anal, ref->addr, ref->at);
				}
			}
			RVecAnalRef_free (list);
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
	case 'q': // "axq"
	case '*': // "ax*"
	case ',': // "ax,"
		r_anal_xrefs_list (core->anal, input[0], *input? r_str_trim_head_ro (input + 1): "");
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
		char *ptr = strdup (r_str_trim_head_ro (input + 1));
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
		RVecAnalRef *list = r_anal_xrefs_get (core->anal, addr);
		RAnalRef *ref;
		R_VEC_FOREACH (list, ref) {
			r_cons_printf ("0x%"PFMT64x" %s %s\n", ref->addr,
				r_anal_ref_perm_tostring (ref),
				r_anal_ref_type_tostring (ref->type));
			r_anal_xrefs_set (core->anal, ref->addr, at, ref->type);
		}
		RVecAnalRef_free (list);
		free (ptr);
	} break;
	case 'v': // "axv"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_axv);
		} else {
			cmd_afvx (core, NULL, input[1] == 'j');
		}
		break;
	case 'l': // "axl"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_axl);
			break;
		case 'j': // "axlj"
			r_anal_xrefs_list (core->anal, 'j', "");
			break;
		case 'c': // "axlc"
			{
				ut64 count = r_anal_xrefs_count (core->anal);
				r_cons_printf ("%"PFMT64d"\n", count);
			}
			break;
		case 'q': // "axlq"
			r_core_cmd_call (core, "axq");
			break;
		default:
			r_core_cmd_call (core, "ax");
			break;
		}
		break;
	case 't': { // "axt"
		if (input[1] == '?') { // "axt?"
			r_core_cmd_help (core, help_msg_axt);
			break;
		}
		if (input[1] == 'm') { // "axtm"
			// like aflm but reversed
			axtm (core);
			break;
		}
		RAnalFunction *fcn;
		char *space = strchr (input, ' ');
		if (space) {
			addr = r_num_math (core->num, space + 1);
			if (core->num->nc.errors > 0) {
				R_LOG_ERROR ("Invalid argument");
				break;
			}
		} else {
			addr = core->offset;
		}
		RVecAnalRef *list = r_anal_xrefs_get (core->anal, addr);
		if (list) {
			if (input[1] == 'q') { // "axtq"
				RAnalRef *ref;
				R_VEC_FOREACH (list, ref) {
					r_cons_printf ("0x%" PFMT64x "\n", ref->addr);
				}
			} else if (input[1] == 'j') { // "axtj"
				PJ *pj = pj_new ();
				if (!pj) {
					return false;
				}
				pj_a (pj);
				RAnalRef *ref;
				R_VEC_FOREACH (list, ref) {
					fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
					char *str = get_buf_asm (core, addr, ref->addr, fcn, false);
					pj_o (pj);
					pj_kn (pj, "from", ref->addr);
					if (ref->type) {
						pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
						pj_ks (pj, "perm", r_anal_ref_perm_tostring (ref));
					}
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
					} else {
						RFlagItem *fi = r_flag_get_at (core->flags, fcn? fcn->addr: ref->addr, false);
						if (fi) {
							pj_ks (pj, "near_name", fi->name);
							pj_kn (pj, "near_addr", fi->offset);
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
				RAnalRef *ref;
				R_VEC_FOREACH (list, ref) {
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
				R_VEC_FOREACH (list, ref) {
					r_cons_printf ("age 0x%" PFMT64x " 0x%"PFMT64x"\n", ref->addr, addr);
				}
			} else if (input[1] == '*') { // axt*
				// TODO: implement multi-line comments
				const ut64 length = RVecAnalRef_length (list);
				ut64 i = 0;
				RAnalRef *ref;
				R_VEC_FOREACH (list, ref) {
					const bool is_at_end = i == length;
					r_cons_printf ("CCa 0x%" PFMT64x " \"XREF type %d at 0x%" PFMT64x"%s\n",
						ref->addr, ref->type, addr, is_at_end? "": ",");
					i++;
				}
			} else if (input[1] == ' ' || input[1] == 0) { // "axt"
				RAnalFunction *fcn;
				RAnalRef *ref;
				R_VEC_FOREACH (list, ref) {
					fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
					char *buf_asm = get_buf_asm (core, addr, ref->addr, fcn, true);
					const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ref->addr);
					char *print_comment = NULL;
					const char *nl = comment ? strchr (comment, '\n') : NULL;
					if (nl) { // display only until the first newline
						comment = print_comment = r_str_ndup (comment, nl - comment);
					}
					char *buf_fcn = comment
						? r_str_newf ("%s; %s", fcn ?  fcn->name : "(nofunc)", comment)
						: r_str_newf ("%s", fcn ? fcn->name : "(nofunc)");
					free (print_comment);
					r_cons_printf ("%s 0x%" PFMT64x " [%s:%s] %s\n",
						buf_fcn, ref->addr, r_anal_ref_type_tostring (ref->type),
						r_anal_ref_perm_tostring (ref), buf_asm);
					free (buf_asm);
					free (buf_fcn);
				}
			} else {
				r_core_cmd_help (core, help_msg_axt);
				break;
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
		RVecAnalRef_free (list);
	} break;
	case 'f':
		if (input[1] == 'f') { // "axff"
			RAnalFunction * fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			PJ *pj = NULL;
			if (input[2] == 'j') { // "axffj"
				// start a new JSON object
				pj = pj_new ();
				pj_a (pj);
			}
			if (fcn) {
				RVecAnalRef *refs = r_anal_function_get_refs (fcn);
				RAnalRef *refi;
				R_VEC_FOREACH (refs, refi) {
					RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
					const char *name = f ? f->name: "";
					if (pj) {
						pj_o (pj);
						pj_ks (pj, "type", r_anal_ref_type_tostring(refi->type));
						pj_kn (pj, "at", refi->at);
						pj_kn (pj, "ref", refi->addr);
						pj_ks (pj, "name", name);
						pj_end (pj);
					} else {
						r_cons_printf ("%s 0x%08"PFMT64x" 0x%08"PFMT64x" %s\n",
							r_anal_ref_type_tostring(refi->type), refi->at, refi->addr, name);
					}
				}
				RVecAnalRef_free (refs);
				if (pj) {
					pj_end (pj);
					r_cons_println (pj_string (pj));
				}
			} else {
				R_LOG_ERROR ("Cannot find any function");
			}
			pj_free (pj);
		} else { // "axf"
			if (input[1] == '?') { // "axf?"
				r_core_cmd_help (core, help_msg_axf);
				break;
			}
			if (input[1] == 'm') { // "axfm"
				// like aflm but reversed
				axfm (core);
				break;
			}
			RAnalOp asmop;
			char *space = strchr (input, ' ');
			if (space) {
				addr = r_num_math (core->num, space + 1);
				if (core->num->nc.errors > 0) {
					R_LOG_ERROR ("Invalid argument");
					break;
				}
			} else {
				addr = core->offset;
			}
			RAnalFunction * fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			RVecAnalRef *list;
			if (input[1] == '.') { // "axf."
				list = r_anal_xrefs_get_from (core->anal, addr);
				if (!list) {
					list = r_anal_function_get_refs (fcn);
				}
			} else {
				list = r_anal_refs_get (core->anal, addr);
			}

			if (list) {
				if (input[1] == 'q') { // "axfq"
					RAnalRef *ref;
					R_VEC_FOREACH (list, ref) {
						r_cons_printf ("0x%" PFMT64x "\n", ref->at);
					}
				} else if (input[1] == 'j') { // "axfj"
					PJ *pj = pj_new ();
					if (!pj) {
						return false;
					}
					pj_a (pj);
					RAnalRef *ref;
					R_VEC_FOREACH (list, ref) {
						// TODO: Use r_core_anal_op(DISASM) instead of all those 4 lines
						ut8 buf[16];
						r_io_read_at (core->io, ref->addr, buf, sizeof (buf));
						r_asm_set_pc (core->rasm, ref->addr);
						r_asm_disassemble (core->rasm, &asmop, buf, sizeof (buf));
						pj_o (pj);
						pj_kn (pj, "from", ref->at);
						pj_kn (pj, "to", ref->addr);
						pj_ks (pj, "type", r_anal_ref_type_tostring (ref->type));
						pj_ks (pj, "perm", r_anal_ref_perm_tostring (ref));
						pj_ks (pj, "opcode", r_asm_op_get_asm (&asmop));
						pj_end (pj);
					}
					pj_end (pj);
					r_cons_println (pj_string (pj));
					pj_free (pj);
				} else if (input[1] == '*') { // "axf*"
					// TODO: implement multi-line comments
					RAnalRef *ref;
					R_VEC_FOREACH (list, ref) {
						r_cons_printf ("CCa 0x%" PFMT64x " \"XREF from 0x%u \n",
								ref->at, ref->type);
					}
				} else { // "axf"
					char str[512];
					int has_color = core->print->flags & R_PRINT_FLAGS_COLOR;
					RAnalRef *ref;
					R_VEC_FOREACH (list, ref) {
						ut8 buf[16] = {0};
						char *desc;
						char *desc_to_free = NULL;
						RFlagItem *flag = r_flag_get_at (core->flags, ref->addr, false);
						if (flag) {
							desc = flag->name;
						} else {
							r_io_read_at (core->io, ref->addr, buf, sizeof (buf));
							r_asm_set_pc (core->rasm, ref->addr);
							r_asm_disassemble (core->rasm, &asmop, buf, sizeof (buf));
							RAnalHint *hint = r_anal_hint_get (core->anal, ref->addr);
							r_parse_filter (core->parser, ref->addr, core->flags, hint, r_asm_op_get_asm (&asmop),
									str, sizeof (str), be);
							r_anal_hint_free (hint);
							if (has_color) {
								desc = desc_to_free = r_print_colorize_opcode (core->print, str,
										core->cons->context->pal.reg, core->cons->context->pal.num, false, fcn ? fcn->addr : 0);
							} else {
								desc = str;
							}
						}
						r_cons_printf ("%s 0x%" PFMT64x " %s",
								r_anal_ref_type_tostring (ref->type), ref->addr, desc);

						if (R_ANAL_REF_TYPE_MASK (ref->type) == R_ANAL_REF_TYPE_CALL) {
							RAnalOp aop;
							r_anal_op (core->anal, &aop, ref->addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
							if (aop.type == R_ANAL_OP_TYPE_UCALL) {
								cmd_anal_ucall_ref (core, ref->addr);
							}
							r_anal_op_fini (&aop);
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
			RVecAnalRef_free (list);
		}
		break;
	case 'F': // "axF"
		find_refs (core, input + 1);
		break;
	case 'C': // "axC"
	case 'c': // "axc"
	case 'i': // "axi"
	case 'r': // "axr"
	case 'w': // "axw"
	case 'j': // "axj"
	case 'd': // "axd"
	case 's': // "axs"
	case ' ': // "ax "
		if (input[1] == '?') {
			char *s = r_str_newf ("ax%c", input[0]);
			r_core_cmd_help_match (core, help_msg_ax, s, true);
			free (s);
		} else {
			char *ptr = strdup (r_str_trim_head_ro ((char *)input + 1));
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
		if (input[1] == ' ') {
			char *ptr = strdup (input + 2);
			r_str_word_set0 (ptr);
			const char *arch = r_str_word_get0 (ptr, 0);
			r_anal_hint_set_arch (core->anal, core->offset, !arch || strcmp (arch, "0") == 0 ? NULL : arch);
			free (ptr);
		} else if (input[1] == '-') {
			r_anal_hint_unset_arch (core->anal, core->offset);
		} else {
			R_LOG_ERROR ("Missing argument");
		}
		break;
	case 'o': // "aho"
		if (input[1] == '*') {
			// show in r2
			RAnalHint *hint = r_anal_hint_get (core->anal, core->offset);
			if (hint && hint->opcode) {
				r_cons_printf ("aho %s @ 0x%08"PFMT64x"\n", hint->opcode, hint->addr);
			}
			r_anal_hint_free (hint);
		} else if (input[1] == 0) {
			// show if any
			RAnalHint *hint = r_anal_hint_get (core->anal, core->offset);
			if (hint && hint->type > 0) {
				r_cons_printf ("%s\n", r_anal_optype_tostring (hint->type));
			}
			r_anal_hint_free (hint);
		}  else if (input[1] == '-') {
			ut64 off = input[2]? r_num_math (core->num, input + 2): core->offset;
			r_anal_hint_unset_bits (core->anal, off);
		} else if (input[1] == ' ') {
			const char *arg = r_str_trim_head_ro (input + 1);
			const int type = r_anal_optype_from_string (arg);
			if (type != -1) {
				r_anal_hint_set_type (core->anal, core->offset, type);
			} else {
				R_LOG_ERROR ("Unknown opcode type. Try: io, acmp, add, sync, call, cjmp, cmp, nop,,,");
			}
		} else {
			r_core_cmd_help (core, help_msg_aho);
		}
		break;
	case 'b': // "ahb" set bits
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_ahb);
		} else if (input[1] == ' ') {
			char *ptr = r_str_trim_dup (input + 2);
			int bits;
			int i = r_str_word_set0 (ptr);
			if (i == 2) {
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			}
			bits = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_anal_hint_set_bits (core->anal, core->offset, bits);
			free (ptr);
		}  else if (input[1] == '-') {
			if (!strcmp (input + 2, "*")) {
				r_anal_hint_unset_bits (core->anal, UT64_MAX);
			} else {
				ut64 off = input[2]? r_num_math (core->num, input + 2): core->offset;
				r_anal_hint_unset_bits (core->anal, off);
			}
		} else {
			RAnalHint *hint = r_anal_hint_get (core->anal, core->offset);
			if (hint && hint->bits) {
				r_cons_printf ("%d\n", hint->bits);
			}
			r_anal_hint_free (hint);
		}
		break;
	case 'i': // "ahi"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_ahi);
			break;
		}
		if (input[1] == '-') { // "ahi-"
			ut64 addr = r_num_get (core->num, input + 2);
			// add ahi-*
			r_anal_hint_set_immbase (core->anal, addr? addr: core->offset, 0);
			break;
		}
		if (isdigit ((unsigned char)input[1])) {
			r_anal_hint_set_nword (core->anal, core->offset, input[1] - '0');
			input++;
		}
		if (input[1] == ' ') {
			// You can either specify immbase with letters, or numbers
			int base;
			if (r_str_startswith (input + 2, "10u") || r_str_startswith (input + 2, "du")) {
				base = 11;
			} else {
				base = (input[2] == 's') ? 1 :
				       (input[2] == 'b') ? 2 :
				       (input[2] == 'p') ? 3 :
				       (input[2] == 'o') ? 8 :
				       (input[2] == 'd') ? 10 :
				       (input[2] == 'h') ? 16 :
				       (input[2] == 'i') ? 32 : // ip address
				       (input[2] == '3') ? 36 : // base36
				       (input[2] == 'S') ? 80 : // syscall
				       (int) r_num_math (core->num, input + 1);
			}
			r_anal_hint_set_immbase (core->anal, core->offset, base);
		} else if (!input[1]) {
			RAnalHint *hint = r_anal_hint_get (core->anal, core->offset);
			if (hint && hint->immbase) {
				r_cons_printf ("%d\n", hint->immbase);
			}
			r_anal_hint_free (hint);
		} else {
			r_core_cmd_help (core, help_msg_ahi);
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
			if (input[2] == '*') {
				R_LOG_INFO ("Not implemented");
				// R2_590 - take arg to specify type of hint to remove .. r_anal_hint_clear (core->anal, );
				// r_anal_hint_unset_size (core->anal, UT64_MAX);
				// r_anal_hint_clear (core->anal);
			} else if (input[2]) {
				ut64 at = r_num_math (core->num, input + 2);
				if (at != UT64_MAX) {
					r_anal_hint_unset_size (core->anal, at);
				}
			} else {
				r_anal_hint_unset_size (core->anal, core->offset);
			}
		} else if (input[1] == 0) {
			r_core_cmd0 (core, "ah~size=");
		} else {
			r_core_cmd_help (core, help_msg_ahs);
		}
		break;
	case 'S': // "ahS" set asm.syntax
		if (input[1] == ' ') {
			r_anal_hint_set_syntax (core->anal, core->offset, input + 2);
		} else if (input[1] == '-') {
			r_anal_hint_unset_syntax (core->anal, core->offset);
		} else {
			r_core_cmd_help_match (core, help_msg_ah, "ahS", true);
		}
		break;
	case 'd': // "ahd" set opcode string
		if (input[1] == ' ') {
			r_anal_hint_set_opcode (core->anal, core->offset, input + 2);
		} else if (input[1] == '-') {
			r_anal_hint_unset_opcode (core->anal, core->offset);
		} else {
			r_core_cmd_help_match (core, help_msg_ah, "ahd", true);
		}
		break;
	case 'e': // "ahe" set ESIL string
		if (input[1] == ' ') {
			r_anal_hint_set_esil (core->anal, core->offset, input + 2);
		} else if (input[1] == '-') {
			r_anal_hint_unset_esil (core->anal, core->offset);
		} else {
			r_core_cmd_help_match (core, help_msg_ah, "ahe", true);
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
		// XXX isnt this the same as 'aho ret' ?
		if (input[1] == ' ') {
			r_anal_hint_set_ret (core->anal, core->offset, r_num_math (core->num, input + 1));
		} else if (input[1] == '-') { // "ahr-"
			r_anal_hint_unset_ret (core->anal, core->offset);
		} else {
			r_core_cmd_help (core, help_msg_ahr);
		}
		break;
	case '*': // "ah*"
	case 'j': // "ahj"
	case '\0': // "ah"
		if (input[0] && input[1] == ' ') {
			char *ptr = strdup (r_str_trim_head_ro (input + 2));
			r_str_word_set0 (ptr);
			ut64 addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_core_anal_hint_print (core->anal, addr, input[0]);
			free (ptr);
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
				char *ptr = strdup (r_str_trim_head_ro (input + 1));
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
			char *type = strdup (r_str_trim_head_ro (input + 2));
			char *idx = strchr (type, ' ');
			if (idx) {
				*idx++ = 0;
				off = idx;
			}
			char *ptr = strchr (type, '=');
			ut64 offimm = 0;
			ut64 addr;

			if (ptr) {
				*ptr++ = 0;
				r_str_trim (ptr);
				if (ptr && *ptr) {
					addr = r_num_math (core->num, ptr);
				} else {
					R_LOG_ERROR ("address is not valid");
					free (type);
					break;
				}
			} else {
				addr = core->offset;
			}
			r_str_trim (type);
			RAnalOp asmop;
			RAnalOp op = {0};
			ut8 code[128] = {0};
			(void)r_io_read_at (core->io, core->offset, code, sizeof (code));
			r_asm_set_pc (core->rasm, addr);
			(void)r_asm_disassemble (core->rasm, &asmop, code, sizeof (code));
			int ret = r_anal_op (core->anal, &op, core->offset, code, sizeof (code), R_ARCH_OP_MASK_VAL);
			if (ret >= 0) {
				// HACK: Just convert only the first imm seen
				RAnalValue *src = NULL;
				r_vector_foreach (&op.srcs, src) {
					if (src) {
						if (src->imm) {
							offimm = src->imm;
						} else if (src->delta) {
							offimm = src->delta;
						}
					}
				}
				if (!offimm) {
					RAnalValue *dst = r_vector_at (&op.dsts, 0);
					if (dst) {
						if (dst->imm) {
							offimm = dst->imm;
						} else if (dst->delta) {
							offimm = dst->delta;
						}
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
						R_LOG_ERROR ("wrong type for opcode offset");
					}
					r_list_free (otypes);
				}
			}
			r_anal_op_fini (&op);
			free (type);
		} break;
		default:
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
	if (R_STR_ISEMPTY (n->body)) {
		r_cons_printf ("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
				n->title, n->title, n->title);
	} else {
		char *label = strdup (n->body);
		//label = r_str_replace (label, "\n", "\\l", 1);
		r_cons_printf ("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\\n%s\"]\n",
				n->title, n->title, n->title, label);
		free (label);
	}
}

static void agraph_print_node(RANode *n, void *user) {
	size_t len = strlen (n->body);

	if (len > 0 && n->body[len - 1] == '\n') {
		len--;
	}
	char *encbody = r_base64_encode_dyn (n->body, len);
	char *cmd = r_str_newf ("agn \"%s\" base64:%s\n", n->title, encbody);
	r_cons_print (cmd);
	free (cmd);
	free (encbody);
}

static char *getViewerPath(void) {
	int i;
	const char *viewers[] = {
#if R2__WINDOWS__
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
		if (viewerPath) {
			return viewerPath;
		}
		free (viewerPath);
	}
	return NULL;
}

static char *dot_executable_path(void) {
	char *dotPath = r_file_path ("dot");
	if (!dotPath) {
		dotPath = r_file_path ("xdot");
	}
	return dotPath;
}

static bool convert_dot_to_image(RCore *core, const char *dot_file, const char *save_path) {
	char *dot = dot_executable_path ();
	bool result = false;
	if (!dot) {
		R_LOG_ERROR ("Graphviz not found in PATH");
		return false;
	}
	const char *ext = r_config_get (core->config, "graph.gv.format");

	char *cmd = NULL;
	if (save_path && *save_path) {
		cmd = r_str_newf ("!%s -T%s -o%s a.dot;", dot, ext, save_path);
	} else {
		char *viewer = getViewerPath();
		if (viewer) {
			cmd = r_str_newf ("!%s -T%s -oa.%s a.dot;!%s a.%s",
				dot, ext, ext, viewer, ext);
			free (viewer);
		} else {
			R_LOG_ERROR ("Cannot find a valid picture viewer");
			goto end;
		}
	}
	r_core_cmd0 (core, cmd);
	result = true;
end:
	free (cmd);
	free (dot);
	return result;
}

static bool convert_dotcmd_to_image(RCore *core, char *r2_cmd, const char *save_path) {
	if (save_path && *save_path) {
		r_cons_printf ("Saving to file '%s'...\n", save_path);
		r_cons_flush ();
	}
	r_core_cmdf (core, "%s > a.dot", r2_cmd); // TODO: check error here
	return convert_dot_to_image (core, "a.dot", save_path);
}

static bool convert_dot_str_to_image(RCore *core, char *str, const char *save_path) {
	if (save_path && *save_path) {
		r_cons_printf ("Saving to file '%s'...\n", save_path);
		r_cons_flush ();
	}
	if (!r_file_dump ("a.dot", (const unsigned char *)str, -1, false)) {
		return false;
	}
	return convert_dot_to_image (core, "a.dot", save_path);
}

static void agraph_print_edge_dot(RANode *from, RANode *to, void *user) {
	RCore *core = (RCore *)user;
	ut64 a = r_num_math (NULL, from->title);
	ut64 b = r_num_math (NULL, to->title);
	r_strf_var (k, 64, "agraph.edge.0x%"PFMT64x"_0x%"PFMT64x".highlight", a, b);
	if (sdb_exists (core->sdb, k)) {
		r_cons_printf ("\"%s\" -> \"%s\" [color=cyan]\n", from->title, to->title);
	} else {
		r_cons_printf ("\"%s\" -> \"%s\"\n", from->title, to->title);
	}
}

static void agraph_print_edge(RANode *from, RANode *to, void *user) {
	r_cons_printf ("age \"%s\" \"%s\"\n", from->title, to->title);
}

static void cmd_agraph_node(RCore *core, const char *input) {
	switch (*input) {
	case ' ': { // "agn"
		char *newbody = NULL;
		char *body;
		int n_args, B_LEN = strlen ("base64:");
		char *color = NULL;
		input++;
		char **args = r_str_argv (input, &n_args);
		if (n_args < 1 || n_args > 3) {
			R_LOG_ERROR ("wrong arguments for agn");
			r_str_argv_free (args);
			break;
		}
		// strdup cause there is double free in r_str_argv_free due to a realloc call
		if (n_args > 1) {
			body = strdup (args[1]);
			if (strncmp (body, "base64:", B_LEN) == 0) {
				if (body[B_LEN]) {
					body = r_str_replace (body, "\\n", "", true);
					newbody = (char *)r_base64_decode_dyn (body + B_LEN, -1);
					if (!newbody) {
						R_LOG_ERROR ("Invalid base64 string in agn (%s)", body+B_LEN);
						r_str_argv_free (args);
						break;
					}
					free (body);
					body = newbody;
				} else {
					free (body);
					body = strdup ("");
				}
			}
			body = r_str_append (body, "\n");
			if (n_args > 2) {
				RColor kolor = {0};
				(void)r_cons_pal_parse (args[2], &kolor);
				color = r_cons_rgb_str (NULL, -1, &kolor);
			}
		} else {
			body = strdup ("");
		}
		r_agraph_add_node (core->graph, args[0], body, color);
		r_str_argv_free (args);
		free (body);
		free (color);
		// free newbody it's not necessary since r_str_append reallocate the space
		break;
	}
	case '-': { // "agn-"
		input++;
		int n_args;
		char **args = r_str_argv (input, &n_args);
		if (n_args != 1) {
			R_LOG_ERROR ("Wrong arguments");
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

static bool cmd_ageh(RCore *core, const char *input) {
	if (!*input) {
		r_core_cmd0 (core, "k~agraph.edge");
		return false;
	}
	bool add = true;
	if (*input == '-') {
		add = false;
		input++;
	}
	char *arg = r_str_trim_dup (input + 1);
	char *sp = strchr (arg, ' ');
	if (!sp) {
		free (arg);
		return false;
	}
	*sp++ = 0;
	ut64 a = r_num_math (core->num, arg);
	ut64 b = r_num_math (core->num, sp);

	r_strf_var (k, 64, "agraph.edge.0x%"PFMT64x"_0x%"PFMT64x".highlight", a, b);
	sdb_set (core->sdb, k, add? "true": "", 0);
	free (arg);
	return true;
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
			const char *arg = args[u? 1: 0];
			r_cons_printf ("Node %s not found!\n", arg);
			r_str_argv_free (args);
			break;
		}
		if (*input == ' ') {
			r_agraph_add_edge (core->graph, u, v, false);
		} else {
			r_agraph_del_edge (core->graph, u, v);
		}
		r_str_argv_free (args);
		break;
	}
	case 'h':
		cmd_ageh (core, input + 1);
		break;
	case '?':
	default:
		r_core_cmd_help (core, help_msg_age);
		break;
	}
}

R_API void cmd_agfb(RCore *core) {
	const int c = r_config_get_b (core->config, "scr.color");
	r_config_set_i (core->config, "scr.color", 0);
	r_cons_push ();
	r_core_visual_graph (core, NULL, NULL, false);
	r_config_set_i (core->config, "scr.color", c);
	char *s = strdup (r_cons_singleton()->context->buffer);
	r_cons_pop ();
	cmd_agfb2 (core, s);
	free (s);
}

R_API void cmd_aggb(RCore *core) {
	const int c = r_config_get_b (core->config, "scr.color");
	r_config_set_i (core->config, "scr.color", 0);
	r_cons_push ();
	int ograph_zoom = r_config_get_i (core->config, "graph.zoom");
	r_config_set_i (core->config, "graph.zoom", 1);
	r_core_cmd_call (core, "agg");
	r_config_set_i (core->config, "scr.color", c);
	char *s = strdup (r_cons_singleton()->context->buffer);
	r_cons_pop ();
	cmd_agfb2 (core, s);
	r_config_set_i (core->config, "graph.zoom", ograph_zoom);
	free (s);
}

R_API void cmd_agfb3(RCore *core, const char *s, int x, int y) {
	int h, w = r_str_size (s, &h);
	RConsPixel *p = r_cons_pixel_new (w, h);
	r_cons_pixel_sets (p, 0, 0, s);
	r_cons_pixel_flush (p, x, y);
	R_FREE (p);
}

R_API void cmd_agfb2(RCore *core, const char *s) {
	int h, w = r_str_size (s, &h);
	RConsPixel *p = r_cons_pixel_new (w, h);
	r_cons_pixel_sets (p, 0, 0, s);
	char *pix = r_cons_pixel_drain (p);
	r_cons_printf ("%s\n", pix);
	free (pix);
}


static char *mermaid_sanitize_str(const char *str) {
	if (!str) {
		return NULL;
	}
	size_t len = strlen (str) * 4 + 1; // '\n' -> "\x0a"
	char *buf = malloc (len);
	if (buf) {
		size_t i;
		for (i = 0; i < len - 5 && *str;) {
			char c = *str++;
			if (c < ' ' || c > '~' || c == '\\' || c == '"' || c == '<') {
				snprintf (buf + i, 5, "\\x%02x", c); // 5 b/c null byte
				i += 4;
			} else {
				buf[i++] = c;
			}
		}
		buf[i] = '\0';
	}
	// buffer wont live long enough to merit a realloc
	return buf;
}

static inline char *mermaid_title_body_node_str(const char *title, const char *body) {
	char *t = mermaid_sanitize_str (title);
	char *b = mermaid_sanitize_str (body);
	if (t && b) {
		char *ret = r_str_newf ("[%s]\\n%s", t, b);
		free (t);
		free (b);
		return ret;
	}
	return t? t: b;
}

static char *mermaid_anod_body(RGraphNode *n) {
	RANode *an = (RANode *)n->data;
	return mermaid_title_body_node_str (an->title, an->body);
}

static char *mermaid_nodeinfo_body(RGraphNode *n) {
	RGraphNodeInfo *nfo = (RGraphNodeInfo *)n->data;
	return mermaid_title_body_node_str (nfo->title, nfo->body);
}

typedef char *(*node_content_cb) (RGraphNode *);
static void mermaid_graph(RGraph *graph, node_content_cb get_body) {
	if (!graph) {
		return;
	}
	if (r_list_empty (graph->nodes)) {
		R_LOG_INFO ("The graph is empty");
		return;
	}
	bool printit = true;
	RStrBuf *nodes = r_strbuf_new ("stateDiagram-v2\n");
	RStrBuf *edges = r_strbuf_new ("");
	RGraphNode *n;
	RListIter *it;
	r_list_foreach (graph->nodes, it, n) {
		char *free_body = get_body (n);
		char *body = free_body? free_body: "";
		printit &= r_strbuf_appendf (nodes, "  state \"%s\" as node_%u\n", body, n->idx);
		free (free_body);

		// edgdes
		RGraphNode *nxt;
		RListIter *itt;
		r_list_foreach (n->out_nodes, itt, nxt) {
			printit &= r_strbuf_appendf (edges, "  node_%u --> node_%u\n", n->idx, nxt->idx);
		}
		if (!printit) {
			break;
		}
	}

	if (printit) {
		char *n = r_strbuf_drain_nofree (nodes);
		char *e = r_strbuf_drain_nofree (edges);
		if (n && e) {
			r_cons_print (n);
			r_cons_print (e);
		}
		free (n);
		free (e);
	}
	r_strbuf_free (nodes);
	r_strbuf_free (edges);
}

typedef struct {
	RAnalFunction *fcn;
	char *name;
	ut64 addr;
	int size;
	int x;
	int y;
	int w;
	int h;
} TreeMapItem;

static void *add_item(RAnalFunction *f, const char *name, ut64 addr, ut64 size) {
	TreeMapItem *item = R_NEW0 (TreeMapItem);
	item->fcn = f;
	item->addr = addr;
	item->name = strdup (name);
	item->size = size;
	return item;
}

static void free_item(void *a) {
	TreeMapItem *item = a;
	if (item) {
		free (item->name);
		free (item);
	}
}

static int bysize(const void *_a, const void *_b) {
	const TreeMapItem *a = _a;
	const TreeMapItem *b = _b;
	return b->size - a->size;
}

static void treemap_layout(RConsCanvas *canvas, RList *maps) {
	RListIter *iter;
	TreeMapItem *mi;
	int i = 0;
	int n = r_list_length (maps);
	if (n == 0) {
		return;
	}
	int nx = 0;
	int ny = 0;
	int nw = canvas->w;
	int nh = canvas->h;
	float mfact = 0.33;
	bool s = true; // layout

	r_list_sort (maps, bysize);
	r_list_foreach (maps, iter, mi) {
		if ((i % 2 && nh / 2 > 2 * mi->w) || (!(i % 2) && nw / 2 > 2 * mi->w)) {
			const int imodfour = (i % 4);
			if (i < n - 1) {
				if (i % 2) {
					nh /= 2;
				} else {
					nw /= 2;
				}
				if (!s) {
					if (imodfour == 2) {
						nx += nw;
					} else if (imodfour == 3) {
						ny += nh;
					}
				}
			}
			switch (imodfour) {
			case 0:
				ny += s? nh: -nh;
				break;
			case 1:
				nx += nw;
				break;
			case 2:
				ny += nh;
				break;
			case 3:
				nx += s? nw: -nw;
				break;
			}
			if (i == 0) {
				if (n != 1) {
					nw = (int)(canvas->w * mfact);
				}
				ny = 0;
			} else if (i == 1) {
				nw = canvas->w - nw;
				nx--;
			} else if (i == 2) {
				nh++;
				// ny--;
			}
			if (2== (i%4)) {
				nh++;
				// nw--;
				ny--;
			}
			i++;
		}
		mi->x = nx;
		mi->y = ny;
		mi->w = nw;
		mi->h = nh;
	}
}

R_API void r_core_agraph_treemap(RCore *core, int use_utf, const char *input) {
	int a = r_config_get_i (core->config, "scr.color");
	r_config_set_i (core->config, "scr.color", 0);
	// walk all the functions and create a treemap and render it
	int h, w = r_cons_get_size (&h);
	w--;
	h--;
	RConsCanvas *canvas = r_cons_canvas_new (w, h);
	r_cons_canvas_box (canvas, 1, 1, w - 1, h - 1, "");
	RListIter *iter;
	RAnalFunction *fcn = NULL;
	RList *maps = r_list_newf (free_item);
#if 1
	RList *list = r_anal_get_fcns (core->anal);
	r_list_foreach (list, iter, fcn) {
		ut64 fsz = r_anal_function_realsize (fcn);
		r_list_append (maps, add_item (fcn, fcn->name, fcn->addr, fsz));
	}
#else
	RAnalBlock *bb;
	if (!fcn) {
		fcn = r_anal_get_function_at (core->anal, core->offset);
		r_list_foreach (fcn->bbs, iter, bb) {
			char *name = r_str_newf ("%d", (int)(size_t)(bb->addr - fcn->addr));
			r_list_append (maps, add_item (fcn, name, bb->addr, bb->size));
			free (name);
		}
	}
#endif
	treemap_layout (canvas, maps);
	TreeMapItem *mi;
	r_list_foreach (maps, iter, mi) {
		// char *s = r_core_cmd_strf (core, "pdb@0x%"PFMT64x"@e:asm.byte=0@e:asm.bytes=0", mi->addr);
		char *s = r_core_cmd_strf (core, "pid@0x%"PFMT64x"@e:asm.bytes=0", mi->addr);
		if (mi->w > 4 && mi->h > 3) {
			char *ns = r_str_crop (s, 0, 0, mi->w * 2, mi->h - 2);
			if (r_cons_canvas_gotoxy (canvas, mi->x + 2, mi->y + 2)) {
				r_cons_canvas_write (canvas, ns);
			}
			free (ns);
		}
		free (s);
	}
	r_list_foreach (maps, iter, mi) {
		if (r_cons_canvas_gotoxy (canvas, mi->x + 2, mi->y + 1)) {
			r_cons_canvas_write (canvas, mi->name);
			r_cons_canvas_box (canvas, mi->x, mi->y, mi->w, mi->h, "");
		}
	}
	char *s = r_cons_canvas_tostring (canvas);
	if (s) {
		r_cons_println (s);
		free (s);
	}
	r_list_free (maps);
	r_config_set_i (core->config, "scr.color", a);
	r_cons_canvas_free (canvas);
}

R_API void r_core_agraph_print(RCore *core, int use_utf, const char *input) {
	if (use_utf != -1) {
		r_config_set_i (core->config, "scr.utf8", use_utf);
	}
	switch (*input) {
	case 0:
		core->graph->can->linemode = r_config_get_i (core->config, "graph.linemode");
		core->graph->can->color = r_config_get_i (core->config, "scr.color");
		r_agraph_set_title (core->graph, r_config_get (core->config, "graph.title"));
		r_agraph_print (core->graph);
		break;
	case 't': { // "aggt" - tiny graph
		core->graph->is_tiny = true;
		int e = r_config_get_i (core->config, "graph.edges");
		r_config_set_i (core->config, "graph.edges", 0);
		r_core_visual_graph (core, core->graph, NULL, false);
		r_config_set_i (core->config, "graph.edges", e);
		core->graph->is_tiny = false;
		break;
	}
	case 'b': // "aggb"
		cmd_aggb (core);
		break;
	case 'm': // "aggm"
		if (core->graph) {
			mermaid_graph (core->graph->graph, mermaid_anod_body);
		}
		break;
	case 'k': // "aggk"
	{
		Sdb *db = r_agraph_get_sdb (core->graph);
		if (db) {
			char *o = sdb_querys (db, "null", 0, "*");
			if (o) {
				r_cons_print (o);
				free (o);
			}
		}
		break;
	}
	case 'v': // "aggv" - open current core->graph in interactive visual mode
	{
		RANode *ran = r_agraph_get_first_node (core->graph);
		if (ran) {
			ut64 oseek = core->offset;
			r_agraph_set_title (core->graph, r_config_get (core->config, "graph.title"));
			r_agraph_set_curnode (core->graph, ran);
			core->graph->force_update_seek = true;
			core->graph->need_set_layout = true;
			core->graph->is_handmade = true;
			core->graph->layout = r_config_get_i (core->config, "graph.layout");
			bool ov = r_cons_is_interactive ();
			core->graph->need_update_dim = true;
			int update_seek = r_core_visual_graph (core, core->graph, NULL, true);
			r_config_set_b (core->config, "scr.interactive", ov);
			r_cons_show_cursor (true);
			core->graph->is_handmade = false;
			r_cons_enable_mouse (false);
			if (update_seek != -1) {
				r_core_seek (core, oseek, false);
			}
		} else {
			R_LOG_INFO ("This graph contains no nodes");
		}
		break;
	}
	case 'd': { // "aggd" - dot format
		const char *font = r_config_get (core->config, "graph.font");
		r_cons_printf ("digraph code {\nrankdir=LR;\noutputorder=edgesfirst\ngraph [bgcolor=azure];\n"
			"edge [arrowhead=normal, color=\"#3030c0\" style=bold weight=2];\n"
			"node [fillcolor=white, style=filled shape=box "
			"fontname=\"%s\" fontsize=\"8\"];\n",
			font);
		r_agraph_foreach (core->graph, agraph_print_node_dot, core);
		r_agraph_foreach_edge (core->graph, agraph_print_edge_dot, core);
		r_cons_printf ("}\n");
		break;
	}
	case '*': // "agg*" -
		r_agraph_foreach (core->graph, agraph_print_node, core);
		r_agraph_foreach_edge (core->graph, agraph_print_edge, core);
		break;
	case 'J':
	case 'j': {
		PJ *pj = r_core_pj_new (core);
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
	break;
		}
	case 'g':
		r_cons_printf ("graph\n[\n"
			       "hierarchic 1\n"
			       "label \"\"\n"
			       "directed 1\n");
		r_agraph_foreach (core->graph, agraph_print_node_gml, NULL);
		r_agraph_foreach_edge (core->graph, agraph_print_edge_gml, NULL);
		r_cons_print ("]\n");
		break;
	case 'w': // "aggw"
		{
			const char *filename = r_str_trim_head_ro (input + 1);
			convert_dotcmd_to_image (core, "aggd", filename);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_ag);
		break;
	}
}

static void print_graph_agg(RGraph /*RGraphNodeInfo*/ *graph) {
	RGraphNodeInfo *print_node;
	RGraphNode *node, *target;
	RListIter *it, *edge_it;
	r_list_foreach (graph->nodes, it, node) {
		char *encbody;
		int len;
		print_node = node->data;
		if (R_STR_ISNOTEMPTY (print_node->body)) {
			len = strlen (print_node->body);

			if (len > 0 && print_node->body[len - 1] == '\n') {
				len--;
			}
			encbody = r_base64_encode_dyn (print_node->body, len);
			r_cons_printf ("agn \"%s\" base64:%s\n", print_node->title, encbody);
			free (encbody);
		} else {
			r_cons_printf ("agn \"%s\"\n", print_node->title);
		}
	}
	r_list_foreach (graph->nodes, it, node) {
		print_node = node->data;
		r_list_foreach (node->out_nodes, edge_it, target) {
			RGraphNodeInfo *to = target->data;
			r_cons_printf ("age \"%s\" \"%s\"\n", print_node->title, to->title);
		}
	}
}

static char *print_graph_dot(RCore *core, RGraph /*<RGraphNodeInfo>*/ *graph) {
	const char *font = r_config_get (core->config, "graph.font");
	char *node_properties = r_str_newf ("fontname=\"%s\"", font);
	char *result = r_graph_drawable_to_dot (graph, node_properties, NULL);
	free (node_properties);
	return result;
}

static char *_graph_node_info_get_title(void *data) {
	RGraphNodeInfo *info = (RGraphNodeInfo *)data;
	return (info && info->title)? strdup (info->title): NULL;
}

static char *_graph_node_info_get_body(void *data) {
	RGraphNodeInfo *info = (RGraphNodeInfo *)data;
	return (info && info->body)? strdup (info->body): NULL;
}

static void r_core_graph_print(RCore *core, RGraph /*<RGraphNodeInfo>*/ *graph, int use_utf, bool use_offset, const char *input) {
	RAGraph *agraph = NULL;
	RListIter *it;
	RListIter *edge_it;
	RGraphNode *graphNode, *target;
	RGraphNodeInfo *print_node;
	if (use_utf != -1) {
		r_config_set_b (core->config, "scr.utf8", use_utf);
	}
	switch (*input) {
	case 0:
	case 't':
	case 'k':
	case 'v':
	case 'i': {
		RAGraphTransitionCBs cbs = {
			.get_title = _graph_node_info_get_title,
			.get_body = _graph_node_info_get_body
		};
		agraph = r_agraph_new_from_graph (graph, &cbs);
		switch (*input) {
		case 0:
			agraph->can->linemode = r_config_get_i (core->config, "graph.linemode");
			agraph->can->color = r_config_get_i (core->config, "scr.color");
			r_agraph_set_title (agraph,
				r_config_get (core->config, "graph.title"));
			r_agraph_print (agraph);
			break;
		case 't': { // "ag_t" - tiny graph
			agraph->is_tiny = true;
			int e = r_config_get_i (core->config, "graph.edges");
			r_config_set_i (core->config, "graph.edges", 0);
			r_core_visual_graph (core, agraph, NULL, false);
			r_config_set_i (core->config, "graph.edges", e);
			break;
		}
		case 'k': // "ag_k"
		{
			Sdb *db = r_agraph_get_sdb (agraph);
			char *o = sdb_querys (db, "null", 0, "*");
			r_cons_print (o);
			free (o);
			break;
		}
		case 'v': // "ag_v"
		case 'i': // "ag_i" - open current core->graph in interactive mode
		{
			RANode *ran = r_agraph_get_first_node (agraph);
			if (ran) {
				ut64 oseek = core->offset;
				r_agraph_set_title (agraph, r_config_get (core->config, "graph.title"));
				r_agraph_set_curnode (agraph, ran);
				agraph->force_update_seek = true;
				agraph->need_set_layout = true;
				agraph->layout = r_config_get_i (core->config, "graph.layout");
				bool ov = r_cons_is_interactive ();
				agraph->need_update_dim = true;
				int update_seek = r_core_visual_graph (core, agraph, NULL, true);
				r_config_set_b (core->config, "scr.interactive", ov);
				r_cons_show_cursor (true);
				r_cons_enable_mouse (false);
				if (update_seek != -1) {
					r_core_seek (core, oseek, false);
				}
			} else {
				R_LOG_INFO ("This graph contains no nodes");
			}
			break;
		}
		}
		break;
	}
	case 'd': { // "ag_d" - dot format
		char *dot_text = print_graph_dot (core, graph);
		if (dot_text) {
			r_cons_print (dot_text);
			free (dot_text);
		}
		break;
	}
	case '*': // "ag_*" -
		print_graph_agg (graph);
		break;
	case 'J':
	case 'j': {
		PJ *pj = pj_new ();
		if (pj) {
			r_graph_drawable_to_json (graph, pj, use_offset);
			r_cons_println (pj_string (pj));
			pj_free (pj);
		}
	} break;
	case 'g':
		r_cons_printf ("graph\n[\n"
			       "hierarchic 1\n"
			       "label \"\"\n"
			       "directed 1\n");
		r_list_foreach (graph->nodes, it, graphNode) {
			print_node = graphNode->data;
			r_cons_printf ("  node [\n"
				       "    id  %d\n"
				       "    label  \"%s\"\n"
				       "  ]\n",
				graphNode->idx, print_node->title);
		}
		r_list_foreach (graph->nodes, it, graphNode) {
			print_node = graphNode->data;
			r_list_foreach (graphNode->out_nodes, edge_it, target) {
				r_cons_printf ("  edge [\n"
					       "    source  %d\n"
					       "    target  %d\n"
					       "  ]\n",
					graphNode->idx, target->idx);
			}
		}
		r_cons_print ("]\n");
		break;
	case 'w': { // "ag_w"
		const char *filename = r_str_trim_head_ro (input + 1);
		char *dot_text = print_graph_dot (core, graph);
		if (dot_text) {
			convert_dot_str_to_image (core, dot_text, filename);
			free (dot_text);
		}
		break;
		}
	case 'm':
		mermaid_graph (graph, mermaid_nodeinfo_body);
		break;
	default:
		r_core_cmd_help (core, help_msg_ag);
		break;
	}
}

static inline bool mermaid_add_node_asm(RAnal *a, RAnalBlock *bb, RStrBuf *nodes) {
	ut8 *bb_buf = calloc (1, bb->size);
	if (!bb_buf) {
		return false;
	}
	if (!a->iob.read_at (a->iob.io, bb->addr, (ut8 *)bb_buf, bb->size)) {
		return false;
	}
	RAnalOpMask mask = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM | R_ANAL_OP_HINT_MASK;
	RAnalOp op = {0};

	// escaped newline to get out of title line
	bool ret = r_strbuf_append (nodes, "\\n");
	int i;
	for (i = 0; i < bb->ninstr; i++) {
		const ut64 prev_pos = r_anal_bb_offset_inst (bb, i);
		const ut64 op_addr = r_anal_bb_opaddr_i (bb, i);
		if (prev_pos >= bb->size) {
			continue;
		}
		int buflen = bb->size - prev_pos;
		ut8 *loc = bb_buf + prev_pos;
		if (r_anal_op (a, &op, op_addr, loc, buflen, mask) > 0) {
			ret &= r_strbuf_appendf (nodes, "%s\\n", op.mnemonic);
		} else {
			ret &= r_strbuf_append (nodes, "...\\n");
		}
		if (!ret) {
			break;
		}
		r_anal_op_fini (&op);
	}
	free (bb_buf);
	return ret;
}

static inline bool fcn_siwtch_mermaid(RAnalBlock *b, RStrBuf *buf) {
	if (b->switch_op) {
		r_return_val_if_fail (b->switch_op->cases, false);
		RListIter *itt;
		RAnalCaseOp *c;
		r_list_foreach (b->switch_op->cases, itt, c) {
			if (!r_strbuf_appendf (buf, "  _0x%" PFMT64x " --> _0x%" PFMT64x ": Case %" PFMT64d "\n", b->addr, c->addr, c->value)) {
				return false;
			}
		}
	}
	return true;
}

static bool cmd_graph_mermaid(RCore *core, bool add_asm) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!fcn || !fcn->bbs) {
		return false;
	}

	bool ret = true;

	// for info on mermaid syntax: https://mermaid-js.github.io/mermaid/#/stateDiagram
	RStrBuf *nodes = r_strbuf_new ("stateDiagram-v2\n");
	RStrBuf *edges = r_strbuf_new ("");

	// TODO: add themeing to nodes buff here -> https://mermaid-js.github.io/mermaid/#/theming

	RAnalBlock *b;
	RListIter *iter;

	r_list_sort (fcn->bbs, bb_cmp);
	r_list_foreach (fcn->bbs, iter, b) {
		ret &= r_strbuf_appendf (nodes, "  state \"[0x%" PFMT64x "]", b->addr);
		if (b->addr == fcn->addr) {
			ret &= r_strbuf_appendf (nodes, " %s", fcn->name);
		}
		if (add_asm) {
			ret &= mermaid_add_node_asm (core->anal, b, nodes);
		}
		// ending of nodes string `... " as _0xfffff`
		// node names start with _0x b/c 0x makes mermaids mad somehow
		ret &= r_strbuf_appendf (nodes, "\" as _0x%" PFMT64x "\n", b->addr);

		if (b->jump != UT64_MAX) {
			if (b->fail != UT64_MAX) {
				ret &= r_strbuf_appendf (edges, "  _0x%" PFMT64x " --> _0x%" PFMT64x ": true\n", b->addr, b->jump);
				ret &= r_strbuf_appendf (edges, "  _0x%" PFMT64x " --> _0x%" PFMT64x ": false\n", b->addr, b->fail);
			} else {
				ret &= r_strbuf_appendf (edges, "  _0x%" PFMT64x " --> _0x%" PFMT64x "\n", b->addr, b->jump);
			}
		} else if (b->fail != UT64_MAX) {
			ret &= r_strbuf_appendf (edges, "  _0x%" PFMT64x " --> _0x%" PFMT64x "\n", b->addr, b->fail);
		}
		ret &= fcn_siwtch_mermaid (b, edges);
		if (!ret) {
			break;
		}
	}

	if (ret) {
		char *n = r_strbuf_drain_nofree (nodes);
		char *e = r_strbuf_drain_nofree (edges);
		if (n && e) {
			r_cons_print (n);
			r_cons_print (e);
		}
		free (n);
		free (e);
	}
	r_strbuf_free (nodes);
	r_strbuf_free (edges);
	return ret;
}

static void cmd_anal_graph(RCore *core, const char *input) {
	core->graph->show_node_titles = r_config_get_i (core->config, "graph.ntitles");
	r_cons_enable_highlight (false);
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_ag);
		return;
	}
	switch (input[0]) {
	case 'f': // "agf"
		switch (input[1]) {
		case 0: // "agf"
			r_core_visual_graph (core, NULL, NULL, false);
			break;
		case 'b': // "agfb" // braile
			cmd_agfb (core);
			break;
		case 'm': /// "agfm" // mermaid
			cmd_graph_mermaid (core, input[2] == 'a');
			break;
		case ' ': { // "agf "
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			r_core_visual_graph (core, NULL, fcn, false);
			break;
		}
		case 'v': // "agfv"
		{
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_ROOT);
			if (fcn) {
				r_core_visual_graph (core, NULL, fcn, 1);
			} else {
				R_LOG_ERROR ("No function to graph");
			}
			r_cons_enable_mouse (false);
			r_cons_show_cursor (true);
		}
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
			if (input[2] == 'm') { // "agfdm"
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
		case 'J': { // "agfJ"
			// Honor asm.graph=false in json as well
			RConfigHold *hc = r_config_hold_new (core->config);
			r_config_hold (hc, "asm.offset", NULL);
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
			 {
				char *cmdargs = r_str_newf ("agfd @ 0x%"PFMT64x, core->offset);
				convert_dotcmd_to_image (core, cmdargs, input + 2);
				free (cmdargs);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_ag);
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
	case 't': // "agt"
		r_core_agraph_treemap (core, -1, input + 1);
		break;
	case 'g': // "agg"
		r_core_agraph_print (core, -1, input + 1);
		break;
	case 's': // "ags"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), 0);
		break;
	case 'C': // "agC"
		switch (input[1]) {
		case 'm':
		case 'v':
		case 't':
		case 'k':
		case 'w':
		case ' ':
		case 0:
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agC*;");
			r_core_agraph_print(core, -1, input + 1);
			core->graph->is_callgraph = false;
			break;
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
			r_core_cmd_help (core, help_msg_ag);
			break;
		}
		break;
	case 'r': // "agr" references graph
		switch (input[1]) {
		case '*':
			r_core_anal_coderefs (core, core->offset);
			break;
		default:
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agr* @ %"PFMT64u";", core->offset);
			r_core_agraph_print(core, -1, input + 1);
			core->graph->is_callgraph = false;
			break;
		}
		break;
	case 'R': // "agR" global refs
		switch (input[1]) {
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
		default: {
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agR*;");
			r_core_agraph_print(core, -1, input + 1);
			core->graph->is_callgraph = false;
			break;
			}
		}
		break;
	case 'x': {// "agx" cross refs
		RGraph *graph = r_core_anal_codexrefs (core, core->offset);
		if (!graph) {
			R_LOG_ERROR ("Cannot create graph");
			break;
		}
		r_core_graph_print (core, graph, -1, true, input + 1);
		r_graph_free (graph);
		break;
	}
	case 'i': { // "agi" import graph
		RGraph *graph = r_core_anal_importxrefs (core);
		if (!graph) {
			R_LOG_ERROR ("Cannot create graph");
			break;
		}
		r_core_graph_print (core, graph, -1, true, input + 1);
		r_graph_free (graph);
		break;
	}
	case 'c': // "agc"
		switch (input[1]) {
		case 'v':
		case 't':
		case 'k':
		case 'w':
		case 'm':
		case ' ': {
			core->graph->is_callgraph = true;
			r_core_cmdf (core, "ag-; .agc* @ %" PFMT64u "; agg%s;", core->offset, input + 1);
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
			r_core_cmd_help (core, help_msg_ag);
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
		case '*': {
			r_core_anal_datarefs (core, core->offset);
			break;
			}
		default:
			r_core_cmdf (core, "ag-; .aga* @ %"PFMT64u";", core->offset);
			r_core_agraph_print(core, -1, input + 1);
			break;
		}
		break;
	case 'A': // "agA" global data refs
		switch (input[1]) {
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
			r_core_cmdf (core, "ag-; .agA*;");
			r_core_agraph_print(core, -1, input + 1);
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
		case 'm':
		case 'g': {
				  ut64 addr = input[2]? r_num_math (core->num, input + 2): core->offset;
				  r_core_cmdf (core, "ag-; .agd* @ %"PFMT64u"; agg%s;", addr, input + 1);
				  break;
			  }
		case 'd': {
				  ut64 addr = input[2]? r_num_math (core->num, input + 2): core->offset;
				  r_core_gdiff_fcn (core, addr, core->offset);
				  r_core_anal_graph (core, addr, diff_opt);
				  break;
			  }
		case 'w': {
				  char *cmdargs = r_str_newf ("agdd 0x%"PFMT64x, core->offset);
				  convert_dotcmd_to_image (core, cmdargs, input + 2);
				  free (cmdargs);
				  break;
			  }
		}
		break;
	}
	case 'v': // "agv" alias for "agfv"
		r_core_cmdf (core, "agfv%s", input + 1);
		break;
	case 'w':// "agw"
		{
			char *cmdargs = r_str_newf ("agfd @ 0x%"PFMT64x, core->offset);
			convert_dotcmd_to_image (core, cmdargs, input + 1);
			free (cmdargs);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_ag);
		break;
	}
}

R_API int r_core_anal_refs(RCore *core, const char *input) {
	const bool cfg_debug = r_config_get_b (core->config, "cfg.debug");
	ut64 from, to;
	int rad;
	PJ *pj = NULL;
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_aar);
		return 0;
	}

	if (*input == 'j' || *input == '*') {
		rad = *input;
		input++;
		if (rad == 'j') {
			pj = r_core_pj_new (core);
			if (!pj) {
				return 0;
			}
		}
	} else {
		rad = 0;
	}

	from = to = 0;
	char *ptr = r_str_trim_dup (input);
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
				pj_o (pj);
			}
			r_list_foreach (list, iter, map) {
				from = r_io_map_begin (map);
				to = r_io_map_end (map);
				if (r_cons_is_breaked ()) {
					break;
				}
				if (!from && !to) {
					R_LOG_ERROR ("Cannot determine xref search boundaries");
				} else if (to - from > UT32_MAX) {
					char *unit = r_num_units (NULL, 0, to - from);
					R_LOG_WARN ("Skipping huge range (%s)", unit);
					free (unit);
				} else {
					if (rad == 'j') {
						pj_ki (pj, "mapid", map->id);
						pj_ko (pj, "refs");
					}
					r_core_anal_search_xrefs (core, from, to, pj, rad);
					if (rad == 'j') {
						pj_end (pj);
					}
				}
			}
			if (rad == 'j') {
				pj_end (pj);
				r_cons_println (pj_string (pj));
				pj_free (pj);
			}
			free (ptr);
			r_list_free (list);
			return 1;
		}
	} else if (n == 1) {
		from = core->offset;
		to = core->offset + r_num_math (core->num, r_str_word_get0 (ptr, 0));
	} else {
		R_LOG_ERROR ("Invalid number of arguments");
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
		pj_o (pj);
	}
	bool res = r_core_anal_search_xrefs (core, from, to, pj, rad);
	if (rad == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	return res;
}

static int compute_coverage(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	int cov = 0;
	cov += r_meta_get_size(core->anal, R_META_TYPE_DATA);
	RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
	if (bank) {
		r_list_foreach (core->anal->fcns, iter, fcn) {
			RIOMapRef *mapref;
			RListIter *ator;
			r_list_foreach (bank->maprefs, ator, mapref) {
				RIOMap *map = r_io_map_get (core->io, mapref->id);
				if (map->perm & R_PERM_X) {
					ut64 section_end = r_io_map_end (map);
					ut64 s = r_anal_function_realsize (fcn);
					if (fcn->addr >= r_io_map_from (map) && (fcn->addr + s) < section_end) {
						cov += s;
					}
				}
			}
		}
	}
	return cov;
}

static int compute_code(RCore* core) {
	int code = 0;
	RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
	if (bank) {
		RIOMapRef *mapref;
		RListIter *ator;
		r_list_foreach (bank->maprefs, ator, mapref) {
			RIOMap *map = r_io_map_get (core->io, mapref->id);
			if (map->perm & R_PERM_X) {
				code += r_io_map_size (map);
			}
		}
	}
	return code;
}

static int compute_calls(RCore *core) {
	int cov = 0;
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		RVecAnalRef *xrefs = r_anal_function_get_xrefs (fcn);
		if (xrefs) {
			cov += RVecAnalRef_length (xrefs);
			RVecAnalRef_free (xrefs);
		}
	}
	return cov;
}

static void r_core_anal_info(RCore *core, const char *input) {
	int fcns = r_list_length (core->anal->fcns);
	int strs = r_flag_count (core->flags, "str.*");
	int syms = r_flag_count (core->flags, "sym.*");
	int imps = r_flag_count (core->flags, "sym.imp.*");
	int code = compute_code (core);
	int covr = compute_coverage (core);
	int call = compute_calls (core);
	int xrfs = r_anal_xrefs_count (core->anal);
	int cvpc = (code > 0)? (int)((covr * 100.0) / code): 0;
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
	RVecAnalRef *list = r_anal_refs_get (core->anal, UT64_MAX);
	RAnalRef *ref;
	R_VEC_FOREACH (list, ref) {
		if (r_io_is_valid_offset (core->io, ref->addr, false)) {
			r_core_anal_fcn (core, ref->at, ref->addr, R_ANAL_REF_TYPE_NULL, 1);
		}
	}
	RVecAnalRef_free (list);
}

static bool archIsThumbable(RCore *core) {
	RArchConfig *ac = R_UNWRAP4 (core, anal, arch, cfg);
	if (ac && ac->bits <= 32) {
		// XXX for some reason this is null
		if (!strcmp (ac->arch, "arm")) {
			return true;
		}
	}
	return false;
}

static void _CbInRangeAav(RCore *core, ut64 from, ut64 to, int vsize, void *user) {
	bool asterisk = user;
	int arch_align = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
	bool vinfun = r_config_get_b (core->config, "anal.vinfun");
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
				R_LOG_WARN ("aav: false positive in 0x%08"PFMT64x, from);
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
		// r_meta_set (core->anal, 'd', from, from + vsize, NULL);
		r_core_cmdf (core, "Cd %d @ 0x%"PFMT64x, vsize, from);
		if (!r_flag_get_at (core->flags, to, false)) {
			char *name = r_str_newf ("aav.0x%08"PFMT64x, to);
			r_flag_set (core->flags, name, to, vsize);
			free (name);
		}
	}
}

static void cmd_anal_aaw(RCore *core, const char *input) {
	bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->print->config);
	int bits = core->anal->config->bits;
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&core->anal->meta, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		ut64 size = r_meta_item_size (node->start, node->end);
		if (item->type == R_META_TYPE_DATA && size == core->anal->config->bits / 8) {
			ut8 buf[8] = {0};
			r_io_read_at (core->io, node->start, buf, 8);
			ut64 n = r_read_ble (buf, be, bits);
			RFlagItem *fi = r_flag_get_at (core->flags, n, false);
			if (fi) {
				char *fn = r_str_newf ("r.%s", fi->name);
				r_flag_set (core->flags, fn, node->start, true);
				free (fn);
			} else if (core->anal->verbose) {
				R_LOG_WARN ("Unknown pointer 0x%"PFMT64x" at 0x%"PFMT64x, n, (ut64)node->start);
			}
		}
	}
}

static void cmd_anal_aav(RCore *core, const char *input) {
#define seti(x,y) r_config_set_i(core->config, x, y);
#define geti(x) r_config_get_i(core->config, x);
	r_return_if_fail (*input == 'v');
	bool relative = input[1] == 'r';
	ut64 o_align = geti ("search.align");
	const char *analin = r_config_get (core->config, "anal.in");
	char *tmp = strdup (analin);
	bool asterisk = strchr (input, '*');
	const bool is_debug = r_config_get_b (core->config, "cfg.debug");
	int archAlign = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
	seti ("search.align", archAlign);
	r_config_set (core->config, "anal.in", "io.maps.x");
	R_LOG_INFO ("Finding xrefs in noncode section (e anal.in=io.maps.x)");

	int vsize = 4; // 32bit dword
	if (core->rasm->config->bits == 64) {
		vsize = 8;
	}
	R_LOG_INFO ("Analyze value pointers (aav)");
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
			(void)r_core_search_value_in_range (core, relative, map->itv,
				r_io_map_begin (map), r_io_map_end (map), vsize, _CbInRangeAav, (void *)(size_t)asterisk);
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
			if ((to - from) > MAX_SCAN_SIZE) {
				R_LOG_WARN ("Skipping large region");
				continue;
			}
			r_list_foreach (list, iter, map) {
				ut64 begin = r_io_map_begin (map);
				ut64 end = r_io_map_end (map);
				if (r_cons_is_breaked ()) {
					break;
				}
				if (end - begin > UT32_MAX) {
					char *unit = r_num_units (NULL, 0, end - begin);
					R_LOG_WARN ("Skipping huge range (%s)", unit);
					free (unit);
					continue;
				}
				R_LOG_INFO ("aav: 0x%08"PFMT64x"-0x%08"PFMT64x" in 0x%"PFMT64x"-0x%"PFMT64x, from, to, begin, end);
				(void)r_core_search_value_in_range (core, relative, map->itv, from, to, vsize, _CbInRangeAav, (void *)(size_t)asterisk);
			}
		}
		r_list_free (list);
	}
beach:
	r_cons_break_pop ();
	r_config_set (core->config, "anal.in", tmp);
	free (tmp);
	seti ("search.align", o_align);
}

static void cmd_anal_abt(RCore *core, const char *input) {
	RAnalBlock *bb = r_anal_get_block_at (core->anal, core->offset);
	if (bb) {
		if (R_STR_ISEMPTY (input)) {
			r_cons_printf ("0x%"PFMT64x"\n", bb->traced);
		} else if (*input == ' ') {
			char *first = (char *)r_str_trim_head_ro (input);
			char *arg = strchr (first, ' ');
			int tag = atoi (first);
			if (tag < 0 || tag > 63) {
				R_LOG_ERROR ("Invalid trace tag number");
				return;
			}
			if (arg) {
				RColor k = {0};
				char *s = r_cons_pal_parse (arg + 1, &k);
				if (s)  {
					core->anal->tracetagcolors[tag] = k;
					free (s);
				} else {
					R_LOG_ERROR ("Invalid error");
				}
			} else {
				bb->traced = tag;
			}
		}
	} else {
		R_LOG_ERROR ("Cannot find any basic block here");
	}
}

static void cmd_anal_abp(RCore *core, const char *input) {
	switch (*input) {
	case 'e': // "abpe"
		{
		int n = 1;
		char *p = strchr (input + 1, ' ');
		if (!p) {
			// TODO use r_cons_cmd_help_match () instead
			r_core_cmd_help (core, help_msg_abp);
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
		r_core_cmd_help (core, help_msg_abp);
		break;
	case 'j': { // "abpj"
		ut64 addr = r_num_math (core->num, input + 1);
		RAnalBlock *block = r_anal_get_block_at (core->anal, core->offset);
		if (!block) {
			break;
		}
		RList *path = r_anal_block_shortest_path (block, addr);
		PJ *pj = r_core_pj_new (core);
		if (pj) {
			pj_a (pj);
			if (path) {
				RListIter *it;
				r_list_foreach (path, it, block) {
					pj_n (pj, block->addr);
				}
			}
			pj_end (pj);
			r_cons_println (pj_string (pj));
			pj_free (pj);
		}
		r_list_free (path);
		break;
	}
	case ' ': {
		ut64 addr = r_num_math (core->num, input + 1);
		if (addr == UT64_MAX || addr == 0) {
			R_LOG_ERROR ("Invalid or missing address passed as argument");
		} else {
			RAnalBlock *block = r_anal_get_block_at (core->anal, core->offset);
			if (!block) {
				R_LOG_ERROR ("No basic block at");
				break;
			}
			RList *path = r_anal_block_shortest_path (block, addr);
			if (path) {
				RListIter *it;
				r_list_foreach (path, it, block) {
					r_cons_printf ("0x%08" PFMT64x "\n", block->addr);
				}
				r_list_free (path);
			}
		}
		break;
	}
	case '\0':
		r_core_cmdf (core, "abl, addr/eq/0x%08"PFMT64x, core->offset);
		break;
	}
}

static bool is_unknown_file(RCore *core) {
	if (core->bin->cur && core->bin->cur->bo) {
		return r_list_empty (core->bin->cur->bo->sections);
	}
	return true;
}

static bool is_apple_target(RCore *core) {
	const char *arch = r_config_get (core->config, "asm.arch");
	if (!strstr (arch, "ppc") && !strstr (arch, "arm") && !strstr (arch, "x86")) {
		return false;
	}
	RBinObject *bo = r_bin_cur_object (core->bin);
	r_return_val_if_fail (!bo || (bo->plugin && bo->plugin->meta.name), false);
	return bo? strstr (bo->plugin->meta.name, "mach"): false;
}

static bool is_valid_code(RCore *core, ut64 addr, int n) {
	int i;
	for (i = 0; i < n; i++) {
		RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC);
		if (op) {
			switch (op->type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_NULL:
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_UNK:
				r_anal_op_free (op);
				return false;
			}
			if (op->size < 1) {
				r_anal_op_free (op);
				return false;
			}
			addr += op->size;
			r_anal_op_free (op);
		} else {
			return false;
		}
	}
	return true;
}

static bool is_executable(RCore *core, ut64 addr) {
	RBinObject *obj = r_bin_cur_object (core->bin);
	RListIter *it;
	RBinSection* sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		r_list_foreach (obj->sections, it, sec) {
			ut64 vaddr_end = sec->vaddr + sec->vsize;
			if (addr >= sec->vaddr && addr < vaddr_end) {
				if (sec->perm & R_PERM_X) {
					return true;
				}
			}
		}
	}
	RIOMap *map = r_io_map_get_at (core->io, addr);
	if (map) {
		if (map->perm & R_PERM_X) {
			return true;
		}
	}
	return false;
}

static bool strnullpad_check(const ut8 *buf, int len, int clen, int inc, bool be) {
	int i;
	for (i = 0; i < len; i += inc) {
		if (inc == 2) {
			if (be) {
				if (!buf[i] && !buf[i + 1]) {
					return false;
				}
				if (!IS_PRINTABLE (buf[i]) || buf[i + 1]) {
					return false;
				}
			} else {
				if (!buf[i] && !buf[i + 1]) {
					return false;
				}
				if (buf[i] || !IS_PRINTABLE (buf[i+1])) {
					return false;
				}
			}
		} else {
			R_LOG_ERROR ("Invalid inc");
			return false;
		}
	}
	return true;
}
// XXX from cmd_print.c
static bool check_string_at(RCore *core, ut64 addr, bool and_print_it) {
	if (!r_io_is_valid_offset (core->io, addr, 0)) {
		return false;
	}
	const int len = core->blocksize; // max string length
	int i;
	// bool is_utf32le = false;
	// bool is_utf32be = false;
	bool is_pascal1 = false;
	bool is_pascal2 = false;
	bool is_utf8 = false;
	bool is_ascii = false;
	char *out = NULL; // utf8 string containing the printable result
	ut8 *buf = malloc (len);
	if (buf) {
		if (r_io_read_at (core->io, addr, buf, len) < 1) {
			free (buf);
			return false;
		}
	} else {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", len);
		return false;
	}
	int nullbyte = r_str_nlen ((const char *)buf, len);
	if (nullbyte == len) {
		// full block, not null terminated somehow. lets check how printable it is first..
		buf[len - 1] = 0;
		nullbyte--;
	}
	if (nullbyte < len && nullbyte > 3) {
		is_ascii = true;
		// it's a null terminated string!
		for (i = 0; i < nullbyte; i++) {
			if (!IS_PRINTABLE (buf[i])) {
				is_ascii = false;
			}
		}
		if (!is_ascii) {
			is_utf8 = true;
			if ((buf[0] & 0xf0) == 0xf0 && (buf[1] & 0xf0) == 0xf0) {
				is_utf8 = false;
			}
			for (i = 0; i < nullbyte; i++) {
				int us = r_utf8_size (buf + i);
				if (us < 1) {
					is_utf8 = false;
					break;
				}
				i += us - 1;
			}
		}
	}

	// utf16le check
	if (strnullpad_check (buf, R_MIN (len, 10), 10, 2, false)) {
		out = malloc (len + 1);
		if (r_str_utf16_to_utf8 ((ut8*)out, len, buf, len, true) < 1) {
			R_FREE (out);
		}
	}
	// utf16be check
	if (strnullpad_check (buf, R_MIN (len, 10), 10, 2, true)) {
		out = malloc (len + 1);
		if (r_str_utf16_to_utf8 ((ut8*)out, len, buf, len, false) < 1) {
			R_FREE (out);
		}
	}
	// TODO: add support for utf32 strings and improve util apis
	// check for pascal string
	{
		ut8 plen = buf[0];
		if (plen > 1 && plen < len) {
			is_pascal1 = true;
			int i;
			for (i = 1; i < plen; i++) {
				if (!IS_PRINTABLE (buf[i])) {
					is_pascal1 = false;
					break;
				}
			}
			if (is_pascal1) {
				char *oout = r_str_ndup ((const char *)buf + 1, i);
				free (out);
				out = oout;
			}
		}
	}
	if (!is_pascal1) {
		ut8 plen = r_read_le16 (buf);
		if (plen > 2 && plen < len) {
			is_pascal2 = true;
			for (i = 2; i < plen; i++) {
				if (!IS_PRINTABLE (buf[i])) {
					is_pascal2 = false;
					break;
				}
			}
			if (is_pascal2) {
				char *oout = r_str_ndup ((const char *)buf + 2, i);
				free (out);
				out = oout;
			}
		}
	}
	if (!and_print_it) {
		free (out);
		return (is_ascii || is_utf8);
	}
#if 0
	eprintf ("pascal %d\n", is_pascal1 + is_pascal2);
	eprintf ("utf8 %d\n", is_utf8);
	eprintf ("utf16 %d\n", is_utf16le+ is_utf16be);
	eprintf ("ascii %d\n", is_ascii);
	eprintf ("render\n");
#endif
	// render the stuff
	if (out) {
		r_cons_printf ("%s\n", out);
		free (out);
		free (buf);
		return true;
	}
	if (is_ascii || is_utf8) {
		r_cons_printf ("%s\n", buf);
		free (buf);
		return true;
	}
	free (buf);
	return false;
}

static bool funref(void *_core, ut64 from, ut64 addr) {
	RCore *core = _core;
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	if (!fcn && is_executable (core, addr)) {
		if (check_string_at (core, addr, false)) {
			return false;
		}
		if (!is_valid_code (core, addr, 10)) {
			return false;
		}
		r_core_cmdf (core, "af@0x%08"PFMT64x, addr);
		// r_core_anal_fcn (core, from, addr, 'c', 100);
	}
	return true;
}

static void anal_aarr(RCore *core) {
	SetU *visited = set_u_new ();
	RAnalFunction *fcn;
	RListIter *it;
	r_list_foreach (core->anal->fcns, it, fcn) {
#if 0
		r_anal_analyze_fcn_refs (core, fcn, depth);
		continue;
#endif
		RVecAnalRef *refs = r_anal_function_get_refs (fcn);
		RAnalRef *refi;
		R_VEC_FOREACH (refs, refi) {
			ut64 ra = refi->addr;
			if (set_u_contains (visited, ra)) {
				continue;
			}
			set_u_add (visited, ra);
			funref (core, refi->at, ra);
		}
		RVecAnalRef_free (refs);
	}
	set_u_free (visited);
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
			r_core_cmd0 (core, "aef@@F");
		} else if (input[1] == 'r') {
			ut64 cur = core->offset;
			bool hasnext = r_config_get_b (core->config, "anal.hasnext");
			RListIter *iter;
			RIOMap *map;
			RList *list = r_core_get_boundaries_prot (core, R_PERM_X, NULL, "anal");
			if (!list) {
				break;
			}
			r_list_foreach (list, iter, map) {
				r_core_seek (core, r_io_map_begin (map), true);
				r_config_set_b (core->config, "anal.hasnext", true);
				r_core_cmd_call (core, "afr");
				r_config_set_b (core->config, "anal.hasnext", hasnext);
			}
			r_list_free (list);
			r_core_seek (core, cur, true);
		} else if (input[1] == 't') { // "aaft"
			cmd_anal_aaft (core);
		} else if (input[1] == 'f') { // "aaff"
			flag_every_function (core);
		} else if (input[1] == 's') { // "aafs"
			single_block_analysis (core);
		} else if (input[1] == 0) { // "aaf"
			const bool analHasnext = r_config_get_b (core->config, "anal.hasnext");
			r_config_set_b (core->config, "anal.hasnext", true);
			r_core_cmd0 (core, "afr@@c:isq");
			r_config_set_b (core->config, "anal.hasnext", analHasnext);
		} else {
			r_core_cmd_help (core, help_msg_aaf);
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
			r_core_cmd_help_match (core, help_msg_aa, "aac", false);
			break;
		default: // "aac"
			cmd_anal_calls (core, input + 1, false, false);
			break;
		}
		break;
	case 'j': // "aaj"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aaj", true);
		} else {
			cmd_anal_jumps (core, input + 1);
		}
		break;
	case 'd': // "aad"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aad", true);
		} else {
			cmd_anal_aad (core, input);
		}
		break;
	case 'v': // "aav"
		if (strchr (input + 1, '?')) {
			r_core_cmd_help (core, help_msg_aav);
		} else {
			cmd_anal_aav (core, input);
		}
		break;
	case 'w': // "aaw"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aaw", true);
		} else {
			cmd_anal_aaw (core, input);
		}
		break;
	case 'u': // "aau" - print areas not covered by functions
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aau", true);
		} else {
			r_core_anal_nofunclist (core, input + 1);
		}
		break;
	case 'i': // "aai"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aai", true);
		} else {
			r_core_anal_info (core, input + 1);
		}
		break;
	case 's': // "aas"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aas", true);
		} else {
			r_core_cmd0 (core, "af @@= `isq~[0]`");
			r_core_cmd0 (core, "af @@f:entry*");
		}
		break;
	case 'S': // "aaS"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aaS", true);
		} else {
			r_core_cmd0 (core, "af @@f:sym.*");
			r_core_cmd0 (core, "af @@f:entry*");
		}
		break;
	case 'F': // "aaF" "aaFa"
		if (!input[1] || input[1] == ' ' || input[1] == 'a') {
			r_core_anal_inflags (core, input + 1);
		} else {
			r_core_cmd_help_match (core, help_msg_aa, "aaF", false);
		}
		break;
	case 'n': // "aan"
		switch (input[1]) {
		case 'r': // "aanr" // all noreturn propagation
			r_core_anal_propagate_noreturn (core, UT64_MAX);
			break;
		case 'g': // "aang"
			r_core_anal_autoname_all_golang_fcns (core);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_aan);
			break;
		case 'f': // "aanf" same as "aan" but more friendly
		default: // "aan"
			r_core_anal_autoname_all_fcns (core);
		}
		break;
	case 'p': // "aap"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aap", true);
		} else {
			r_core_search_preludes (core, true);
		}
		break;
	case '\0': // "aa"
	case 'a':
		if (strchr (input, '?')) {
			r_core_cmd_help (core, help_msg_aaa);
		} else {
			bool didAap = false;
			char *dh_orig = NULL;
			if (!strncmp (input, "aaaaa", 5)) {
				R_LOG_INFO ("We fired the r2 developer that was heading to your location to help you analyze this binary");
				R_LOG_INFO ("Contact support for premium service");
				if (r_cons_is_interactive ()) {
					r_cons_any_key (NULL);
				}
				goto jacuzzi;
			}
			ut64 curseek = core->offset;
			R_LOG_INFO ("Analyze all flags starting with sym. and entry0 (aa)");
			r_cons_break_push (NULL, NULL);
			r_cons_break_timeout (r_config_get_i (core->config, "anal.timeout"));
			r_core_anal_all (core);
			r_core_task_yield (&core->tasks);
			if (r_cons_is_breaked ()) {
				goto jacuzzi;
			}

			// Run afvn in all fcns
			if (r_config_get_b (core->config, "anal.vars")) {
				R_LOG_INFO ("Analyze all functions arguments/locals (afva@@@F)");
				// r_core_cmd0 (core, "afva@@f");
				r_core_cmd0 (core, "afva@@@F");
			}

			// Run pending analysis immediately after analysis
			// Usefull when running commands with ";" or via r2 -c,-i
			dh_orig = core->dbg->current
				? strdup (core->dbg->current->plugin.meta.name)
				: strdup ("esil");
			if (core->io->desc && core->io->desc->plugin && !core->io->desc->plugin->isdbg) {
				//use dh_origin if we are debugging
				R_FREE (dh_orig);
			}
			if (r_cons_is_breaked ()) {
				goto jacuzzi;
			}
			r_cons_clear_line (1);
			bool cfg_debug = r_config_get_b (core->config, "cfg.debug");
			if (*input == 'a') { // "aaa" .. which is checked just in the case above
				if (r_str_startswith (r_config_get (core->config, "bin.lang"), "go")) {
					R_LOG_INFO ("Find function and symbol names from golang binaries (aang)");
					r_core_anal_autoname_all_golang_fcns (core);
					R_LOG_INFO ("Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
					r_core_cmd0 (core, "aF @@@F:sym.go.*");
				}
				r_core_task_yield (&core->tasks);
				if (!cfg_debug) {
					if (dh_orig && strcmp (dh_orig, "esil")) {
						r_core_cmd_call (core, "dL esil");
						r_core_task_yield (&core->tasks);
					}
				}
				// XXX do not override user settings!
				// int c = r_config_get_i (core->config, "anal.calls");
				// r_config_set_b (core->config, "anal.calls", true);
				r_core_cmd_call (core, "s $S");
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}

				R_LOG_INFO ("Analyze function calls (aac)");
				(void)cmd_anal_calls (core, "", false, false); // "aac"
				r_core_seek (core, curseek, true);
				// R_LOG_INFO ("Analyze data refs as code (LEA)");
				// (void) cmd_anal_aad (core, NULL); // "aad"
				r_core_task_yield (&core->tasks);
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}

				if (is_unknown_file (core)) {
					R_LOG_INFO ("find and analyze function preludes (aap)");
					(void)r_core_search_preludes (core, false); // "aap"
					didAap = true;
					r_core_task_yield (&core->tasks);
					if (r_cons_is_breaked ()) {
						goto jacuzzi;
					}
				}

				R_LOG_INFO ("Analyze len bytes of instructions for references (aar)");
				(void)r_core_anal_refs (core, ""); // "aar"
				r_core_task_yield (&core->tasks);
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}
				if (is_apple_target (core)) {
					R_LOG_INFO ("Check for objc references (aao)");
					cmd_anal_objc (core, input + 1, true);
				}
				r_core_task_yield (&core->tasks);
				R_LOG_INFO ("Finding and parsing C++ vtables (avrr)");
				r_core_cmd_call (core, "avrr");
				R_LOG_INFO ("Analyzing methods");
				r_core_cmd0 (core, "af @@ method.*");
				r_core_task_yield (&core->tasks);
				// r_config_set_b (core->config, "anal.calls", c);
				r_core_task_yield (&core->tasks);
				if (r_cons_is_breaked ()) {
					goto jacuzzi;
				}
				const bool isPreludableArch = core->rasm->config->bits == 64 && r_str_startswith (r_config_get (core->config, "asm.arch"), "arm");

				if (!didAap && isPreludableArch) {
					didAap = true;
					R_LOG_INFO ("Finding function preludes (aap)");
					(void)r_core_search_preludes (core, false); // "aap"
					r_core_task_yield (&core->tasks);
				}
				if (!r_str_startswith (r_config_get (core->config, "asm.arch"), "x86")) {
					r_core_cmd_call (core, "aav");
					r_core_task_yield (&core->tasks);
					if (cfg_debug) {
						R_LOG_INFO ("Skipping function emulation in debugger mode (aaef)");
						// nothing to do
					} else {
						const bool io_cache = r_config_get_i (core->config, "io.pcache");
						r_config_set_b (core->config, "io.pcache", true);
						R_LOG_INFO ("Emulate functions to find computed references (aaef)");
						r_core_cmd_call (core, "aaef");
						r_core_task_yield (&core->tasks);
						r_config_set_b (core->config, "io.pcache", io_cache);
					}
					if (r_cons_is_breaked ()) {
						goto jacuzzi;
					}
				}
				if (r_config_get_i (core->config, "anal.autoname")) {
					R_LOG_INFO ("Speculatively constructing a function name for fcn.* and sym.func.* functions (aan)");
					r_core_anal_autoname_all_fcns (core);
					r_core_task_yield (&core->tasks);
				}
				if (core->anal->opt.vars) {
					R_LOG_INFO ("Recovering local variables (afva)");
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
						// extract only reg based var here
						r_core_recover_vars (core, fcni, true);
						r_list_free (list);
					}
					r_core_task_yield (&core->tasks);
				}
				if (!sdb_isempty (core->anal->sdb_zigns)) {
					R_LOG_INFO ("Check for zignature from zigns folder (z/)");
					r_core_cmd_call (core, "z/");
					r_core_task_yield (&core->tasks);
				}
				if (cfg_debug) {
					R_LOG_INFO ("Skipping type matching analysis in debugger mode (aaft)");
					// nothing to do
				} else {
					R_LOG_INFO ("Type matching analysis for all functions (aaft)");
					r_core_cmd_call (core, "aaft");
				}
				r_core_task_yield (&core->tasks);

				R_LOG_INFO ("Propagate noreturn information (aanr)");
				r_core_anal_propagate_noreturn (core, UT64_MAX);
				r_core_task_yield (&core->tasks);

				// apply dwarf function information
				Sdb *dwarf_sdb = sdb_ns (core->anal->sdb, "dwarf", 0);
				if (dwarf_sdb) {
					R_LOG_INFO ("Integrate dwarf function information");
					r_anal_dwarf_integrate_functions (core->anal, core->flags, dwarf_sdb);
				}

				if (input[1] == 'a') { // "aaaa"
					R_LOG_INFO ("Scanning for strings constructed in code (/azs)");
					r_core_cmd_call (core, "/azs");
					if (!didAap) {
						didAap = true;
						R_LOG_INFO ("Finding function preludes (aap)");
						(void)r_core_search_preludes (core, false); // "aap"
						r_core_task_yield (&core->tasks);
					}
					R_LOG_INFO ("Enable anal.types.constraint for experimental type propagation");
					r_config_set_b (core->config, "anal.types.constraint", true);
					if (input[2] == 'a') { // "aaaa"
						R_LOG_INFO ("Reanalizing graph references to improve function count (aarr)");
						r_core_cmd_call (core, "aarr");
					}
				} else {
					R_LOG_INFO ("Use -AA or aaaa to perform additional experimental analysis");
				}
				r_core_cmd_call (core, "s-");
				if (dh_orig) {
					r_core_cmdf (core, "dL %s", dh_orig);
					r_core_task_yield (&core->tasks);
				}
			}
			r_core_seek (core, curseek, true);
		jacuzzi:
			// XXX this shouldnt be called. flags muts be created wheen the function is registered
			flag_every_function (core);
			r_core_anal_propagate_noreturn (core, UT64_MAX);
			r_cons_break_pop ();
			R_FREE (dh_orig);
		}
		break;
	case 't': // "aat"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_aa, "aat", true);
		} else {
			char *off = input[1]? r_str_trim_dup (input + 2): NULL;
			RAnalFunction *fcn;
			RListIter *it;
			if (off && *off) {
				ut64 addr = r_num_math (NULL, off);
				fcn = r_anal_get_function_at (core->anal, core->offset);
				if (fcn) {
					r_core_link_stroff (core, fcn);
				} else {
					R_LOG_ERROR ("Cannot find function at %08" PFMT64x, addr);
				}
			} else {
				if (r_list_empty (core->anal->fcns)) {
					R_LOG_ERROR ("Couldn't find any functions");
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
		}
		break;
	case 'T': // "aaT"
		cmd_anal_aftertraps (core, input + 1);
		break;
	case 'o': // "aao"
		if (input[1] == '?') { // "aao?"
			r_core_cmd_help_match (core, help_msg_aa, "aao", true);
		} else {
			cmd_anal_objc (core, input + 1, false);
		}
		break;
	case 'e': // "aae"
		if (input[1] == 'f') { // "aaef"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_aae, "aaef", true);
			} else {
				r_core_cmd0 (core, "aeim");
				RListIter *it;
				RAnalFunction *fcn;
				ut64 cur_seek = core->offset;
				r_list_foreach (core->anal->fcns, it, fcn) {
					r_core_seek (core, fcn->addr, true);
					r_core_anal_esil (core, "f", NULL);
					// __anal_esil_function (core, fcn->addr);
				}
				r_core_seek (core, cur_seek, true);
			}
		} else if (input[1] == '?') { // "aae?"
			r_core_cmd_help (core, help_msg_aae);
		} else if (input[1] == 'p') { // "aaep" // auto define all esil pins
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_aae, "aaef", true);
			} else {
				r_core_cmd0 (core, "aep ret0@@@i");
				r_core_cmd0 (core, "aepa@@@i");
			}
		} else if (input[1] == ' ') { // "aae "
			char *arg = r_str_trim_dup (input + 1);
			const char *len = (char *)arg;
			char *addr = strchr (arg, ' ');
			if (addr) {
				*addr = 0;
				addr = (char *)r_str_trim_head_ro (addr + 1);
			}
			r_core_cmd0 (core, "aeim");
			r_core_anal_esil (core, len, addr);
			free (arg);
		} else {
			ut64 at = core->offset;
			RIOMap *map;
			RListIter *iter;
			RList *list = r_core_get_boundaries_prot (core, -1, NULL, "anal");
			if (!list) {
				break;
			}
			if (!strcmp ("range", r_config_get (core->config, "anal.in"))) {
				ut64 from = r_config_get_i (core->config, "anal.from");
				ut64 to = r_config_get_i (core->config, "anal.to");
				if (to > from) {
					char *len = r_str_newf (" 0x%"PFMT64x, to - from);
					r_core_seek (core, from, true);
					r_core_anal_esil (core, len, NULL);
					free (len);
				} else {
					R_LOG_ERROR ("Assert: anal.from > anal.to");
				}
			} else {
				r_list_foreach (list, iter, map) {
					if (map->perm & R_PERM_X) {
						char *ss = r_str_newf (" 0x%"PFMT64x, r_io_map_size (map));
						r_core_seek (core, r_io_map_begin (map), true);
						r_core_anal_esil (core, ss, NULL);
						free (ss);
					}
				}
				r_list_free (list);
			}
			r_core_seek (core, at, true);
		}
		break;
	case 'r': // "aar"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_aar);
		} else if (input[1] == 'r') { // "aarr"
			anal_aarr (core);
		} else {
			(void)r_core_anal_refs (core, input + 1);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_aa);
		break;
	}

	return true;
}

static bool anal_fcn_data(RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_ANY);
	if (fcn) {
		int i;
		bool gap = false;
		ut64 gap_addr = UT64_MAX;
		ut32 fcn_size = r_anal_function_size_from_entry (fcn);
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
					r_cons_printf ("Cd %" PFMT64u " @ 0x%08"PFMT64x"\n", here - gap_addr, gap_addr);
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
			r_cons_printf ("Cd %" PFMT64u " @ 0x%08" PFMT64x "\n", fcn->addr + fcn_size - gap_addr, gap_addr);
		}
		free (bitmap);
		return true;
	}
	return false;
}

static bool anal_fcn_data_gaps(RCore *core, const char *input) {
	ut64 end = UT64_MAX;
	RAnalFunction *fcn;
	RListIter *iter;
	int i, wordsize = (core->rasm->config->bits == 64)? 8: 4;
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
		end = fcn->addr + r_anal_function_size_from_entry (fcn);
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

static void cmd_avg(RCore *core, const char* input) {
	switch (input[0]) {
	case ' ':
		if (strchr (input + 1, ' ')) {
			char *a = r_str_trim_dup (input + 1);
			char *b = strchr (a, ' ');
			if (b) {
				*b++ = 0;
				r_anal_global_add (core->anal, core->offset, a, b);
			} else {
				RFlagItem *fi = r_anal_global_get (core->anal, core->offset);
				if (fi) {
					R_LOG_INFO ("type %s", fi->type);
				}
			}
			free (a);
		}
		break;
	case '-':
		r_anal_global_del (core->anal, core->offset);
		break;
	case '\0': // "av"
		r_core_cmd0 (core, "fs+globals;f;fs-");
		break;
	default :
		r_core_cmd_help (core, help_msg_avg);
		break;
	}
}
static void cmd_anal_virtual_functions(RCore *core, const char* input) {
	switch (input[0]) {
	case 'g':
		cmd_avg (core, input + 1);
		break;
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
		const char *str = r_str_trim_head_ro (input + 1);
		if (!*str) {
			R_LOG_ERROR ("No class name given");
			break;
		}
		char *cstr = strdup (str);
		if (!cstr) {
			break;
		}
		char *end = strchr (cstr, ' ');
		if (!end) {
			R_LOG_ERROR ("No method name given");
			free (cstr);
			break;
		}
		*end = '\0';
		char *name_str = end + 1;

		if (c == ' ' || c == 'n') {
			end = strchr (name_str, ' ');
			if (!end) {
				if (c == ' ') {
					R_LOG_ERROR ("No offset given");
				} else if (c == 'n') {
					R_LOG_ERROR ("No new method name given");
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
		R_LOG_ERROR ("Class does not exist");
		break;
	case R_ANAL_CLASS_ERR_NONEXISTENT_ATTR:
		R_LOG_ERROR ("Method does not exist");
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
		const char *str = r_str_trim_head_ro (input + 1);
		if (!*str) {
			R_LOG_ERROR ("No class name given");
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
				R_LOG_ERROR ("No base id given");
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
		R_LOG_ERROR ("Class does not exist");
	}
}

static void cmd_anal_class_vtable(RCore *core, const char *input) {
	RAnalClassErr err = R_ANAL_CLASS_ERR_SUCCESS;
	char c = input[0];
	switch (c) {
	case 'f': {// "acvf" [offset] ([class_name])
		const char *str = r_str_trim_head_ro (input + 1);
		if (!*str) {
			R_LOG_ERROR ("No offset given");
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
		ut64 offset_arg = r_num_get (core->num, cstr); // Should I allow negative offset?
		char *class_arg = NULL;
		if (end) {
			class_arg = (char *)r_str_trim_head_ro (end);
		}

		if (class_arg) {
			end = (char *)r_str_trim_head_wp (class_arg); // in case of extra unwanted stuff at the cmd end
			*end = '\0';
		}
		r_anal_class_list_vtable_offset_functions (core->anal, class_arg, offset_arg);

		free (cstr);
		break;
	}
	case ' ': // "acv"
	case '-': { // "acv-"
		const char *str = r_str_trim_head_ro (input + 1);
		if (!*str) {
			R_LOG_ERROR ("No class name given");
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
				R_LOG_ERROR ("No vtable id given. See acv [class name]");
			}
			free (cstr);
			break;
		}

		char *arg1_str = end;

		if (c == '-') {
			err = r_anal_class_vtable_delete (core->anal, cstr, arg1_str);
			free (cstr);
			break;
		}

		end = strchr (arg1_str, ' ');
		if (end) {
			*end = '\0';
		}

		RAnalVTable vtable;
		vtable.id = NULL;
		vtable.addr = r_num_get (core->num, arg1_str);
		vtable.offset = 0;
		vtable.size = 0;

		char *arg3_str = NULL;
		if (end) {
			vtable.offset = r_num_get (core->num, end + 1);
			// end + 1 won't work on extra whitespace between arguments, TODO
			arg3_str = strchr (end + 1, ' ');
		}

		if (arg3_str) {
			vtable.size = r_num_get (core->num, arg3_str + 1);
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
		R_LOG_ERROR ("Class does not exist");
	}
}

static void cmd_anal_classes(RCore *core, const char *input) {
	switch (input[0]) {
	case 'l': // "acl"
		if (input[1] == 'l') { // "acll" (name)
			char mode = 0;
			int arg_offset = 2;
			if (input[2] == 'j') {
				arg_offset++;
				mode = 'j';
			}
			const char *arg = r_str_trim_head_ro (input + arg_offset);
			if (*arg) { // if there is an argument
				char *class_name = strdup (arg);
				if (!class_name) {
					break;
				}
				char *name_end = (char *)r_str_trim_head_wp (class_name);
				*name_end = 0; // trim the whitespace around the name
				if (mode == 'j') {
					PJ *pj = pj_new ();
					r_anal_class_json (core->anal, pj, class_name);
					r_cons_printf ("%s\n", pj_string (pj));
					pj_free (pj);
				} else {
					r_anal_class_print (core->anal, class_name, true);
				}
				free (class_name);
				break;
			}
		}
		r_anal_class_list (core->anal, input[1]);
		break;
	case ' ': // "ac"
	case '-': // "ac-"
	case 'n': { // "acn"
		const char *str = r_str_trim_head_ro (input + 1);
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
		} else if (input[0] == 'n') {
			if (!end) {
				R_LOG_ERROR ("No new class name given");
			} else {
				char *new_name = end + 1;
				end = strchr (new_name, ' ');
				if (end) {
					*end = '\0';
				}
				RAnalClassErr err = r_anal_class_rename (core->anal, cstr, new_name);
				if (err == R_ANAL_CLASS_ERR_NONEXISTENT_CLASS) {
					R_LOG_ERROR ("Class does not exist");
				} else if (err == R_ANAL_CLASS_ERR_CLASH) {
					R_LOG_ERROR ("A class with this name already exists");
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
	case 'g': { // "acg"
		RGraph *graph = r_anal_class_get_inheritance_graph (core->anal);
		if (!graph) {
			R_LOG_ERROR ("Couldn't create graph");
			break;
		}
		r_core_graph_print (core, graph, -1, false, input + 1);
		r_graph_free (graph);
	} break;
	default: // "ac?"
		r_core_cmd_help (core, help_msg_ac);
		break;
	}
}

static void show_reg_args(RCore *core, int nargs, RStrBuf *sb) {
	int i;
	char regname[16];
	if (nargs < 0) {
		nargs = 4; // default args if not defined
	}
	for (i = 0; i < nargs; i++) {
		snprintf (regname, sizeof (regname), "A%d", i);
		ut64 v = r_reg_getv (core->anal->reg, regname);
		if (sb) {
			r_strbuf_appendf (sb, "%s0x%08"PFMT64x, i? ", ": "", v);
		} else {
			r_cons_printf ("A%d 0x%08"PFMT64x"\n", i, v);
		}
	}
}

// ripped from disasm.c: dupe code from there
// TODO: Implement aC* and aCj
static void cmd_anal_aC(RCore *core, const char *input) {
	bool is_aCer = false;
	const char *cc = r_anal_cc_default (core->anal);
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
		r_core_cmd_help (core, help_msg_aC);
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	ut64 pcv = r_num_math (core->num, iarg);
	if (input[0] == 'e') { // "aCe"
		is_aCer = (input[1] == '*');
		r_core_cmdf (core, ".abpe 0x%08"PFMT64x, pcv);
	}
	RAnalOp* op = r_core_anal_op (core, pcv, -1);
	if (!op) {
		r_strbuf_free (sb);
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
		fcn = r_anal_get_function_at (core->anal, pcv);
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
				r_strbuf_appendf (sb, "%s%s%s(", r_str_getf (fcn_type),
						(*fcn_type && fcn_type[strlen (fcn_type) - 1] == '*') ? "" : " ",
						r_str_getf (key));
				if (!nargs) {
					r_strbuf_append (sb, "void)\n");
				}
			} else {
				R_LOG_ERROR ("Cannot find any function signature");
			}
			free (key);
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
		ut64 s_width = (core->anal->config->bits == 64)? 8: 4;
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
			r_strbuf_append (sb, ")");
		} else {
			// function name not resolved
			int i, nargs = 4; // DEFAULT_NARGS;
			if (fcn) {
				// @TODO: fcn->nargs should be updated somewhere and used here instead
				nargs = r_anal_var_count_args (fcn);
			}
			if (nargs > 0) {
				if (fcn_name) {
					r_strbuf_appendf (sb, "; %s(", fcn_name);
				} else {
					r_strbuf_appendf (sb, "; 0x%"PFMT64x"(", pcv);
				}
				for (i = 0; i < nargs; i++) {
					ut64 v = r_debug_arg_get (core->dbg, cc, i);
					r_strbuf_appendf (sb, "%s0x%"PFMT64x, i?", ":"", v);
				}
				r_strbuf_append (sb, ")");
			}
		}
		r_list_free (list);
		r_reg_setv (core->anal->reg, sp, spv); // reset stack ptr
	}
	r_anal_op_free (op);
	char *s = r_strbuf_drain (sb);
	if (is_aCer) {
		char *u = r_base64_encode_dyn (s, -1);
		if (u) {
			r_cons_printf ("CCu base64:%s\n", u);
			free (u);
		}
	} else {
		r_cons_println (s);
	}
	free (s);
}

static bool core_anal_abf(RCore *core, const char* input) {
	if (strchr (input, '?')) {
		r_core_cmd_help_match (core, help_msg_ab, "abf", true);
		return false;
	}
	ut64 addr = r_num_math (core->num, input);
	if (!addr || addr == UT64_MAX) {
		addr = core->offset;
	}

	RAnalBlock *bb, *bb2;
	RListIter *iter, *iter2, *bbiter;
	RAnalFunction *fcn;
	RList *bbs = r_anal_get_blocks_in (core->anal, addr);
	r_list_foreach (bbs, bbiter, bb) {
		if (!bb) {
			R_LOG_ERROR ("Cannot find basic block");
			return false;
		}
		r_list_foreach (bb->fcns, iter, fcn) {
			r_list_foreach (fcn->bbs, iter2, bb2) {
				if (bb == bb2) {
					continue;
				}
				if (bb2->jump != UT64_MAX && bb2->jump == bb->addr) {
					r_cons_printf ("0x%"PFMT64x"\n", bb2->addr);
				}
				if (bb2->fail != UT64_MAX && bb2->fail == bb->addr) {
					r_cons_printf ("0x%"PFMT64x"\n", bb2->addr);
				}
			}
			break;
		}
	}
	return true;
}

static void match_prelude(RCore *core, const char *input) {
	const ut8 *prelude = (const ut8*)"\xe9\x2d"; //:fffff000";
	const int prelude_sz = 2;
	const int bufsz = 4096;
	ut8 *buf = calloc (1, bufsz);
	ut64 off = core->offset;
	if (input[1] == ' ') {
		off = r_num_math (core->num, input + 1);
	}
	r_io_read_at (core->io, off - bufsz + prelude_sz, buf, bufsz);
	//const char *prelude = "\x2d\xe9\xf0\x47"; //:fffff000";
	r_mem_reverse (buf, bufsz);
	//r_print_hexdump (NULL, off, buf, bufsz, 16, -16);
	const ut8 *pos = r_mem_mem (buf, bufsz, prelude, prelude_sz);
	if (pos) {
		int delta = (size_t)(pos - buf);
		// R_LOG_DEBUG ("POS = %d", delta);
		// R_LOG_DEBUG ("HIT = 0x%"PFMT64x, off - delta);
		r_cons_printf ("0x%08"PFMT64x"\n", off - delta);
	} else {
		R_LOG_ERROR ("Cannot find prelude");
	}
	free (buf);
}

static int cmd_apt(RCore *core, const char *input) {
	switch (*input) {
	case '?':
		r_core_cmd_help_match (core, help_msg_ap, "apt", false);
		break;
	case '=':
	case ' ':
		r_anal_tid_select (core->anal, atoi (input + 1));
		core->dbg->reg = core->anal->reg;
		break;
	case '+':
		{
			int tid = r_anal_tid_add (core->anal, atoi (input + 1));
			if (tid != -1) {
				core->anal->thread = tid;
			}
		}
		break;
	case '-':
		r_anal_tid_kill (core->anal, atoi (input + 1));
		break;
	case 0:
		{
			RListIter *iter;
			RAnalThread *t;
			r_list_foreach (core->anal->threads, iter, t) {
				const int diff = (r_time_now () - t->birth) / 1000000;
				const char cur = (t->id == core->anal->thread)? '*': '-';
				r_cons_printf ("%c %d map=%d age=%ds\n", cur, t->id, t->map, diff);
			}
		}
		break;
	}
	return 0;
}

static int cmd_anal(void *data, const char *input) {
	const char *r;
	RCore *core = (RCore *)data;
	ut32 tbs = core->blocksize;
	switch (input[0]) {
	case 'p': // "ap"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_ap);
			break;
		case 'l': // "apl"
			// list function preludes
			{
				RSearchKeyword *k;
				RListIter *iter;
				RList *list = r_anal_preludes (core->anal);
				r_list_foreach (list, iter, k) {
					char *hex0 = r_hex_bin2strdup (k->bin_keyword, k->keyword_length);
					char *hex1 = r_hex_bin2strdup (k->bin_binmask, k->binmask_length);
					// XXX must add an align field
					r_cons_printf ("ap+ %s %s\n", hex0, hex1);
					free (hex0);
					free (hex1);
				}
			}
			break;
		case 't': // "apt"
			cmd_apt (core, input + 2);
			break;
		case ' ':
		case 0:
			match_prelude (core, r_str_trim_head_ro (input));
			break;
		default:
			r_core_cmd_help (core, help_msg_ap);
			break;
		}
		break;
	case '8':  // "a8"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_a8);
			break;
		}
		ut8 *buf = malloc (strlen (input) + 1);
		if (buf) {
			int len = r_hex_str2bin (input + 1, buf);
			if (len > 0) {
				core_anal_bytes (core, buf, len, 0, input[1]);
			}
			free (buf);
		}
		break;
	case 'b': // "ab"
		switch (input[1]) {
		case '.': // "ab."
			r_core_cmd_call (core, "ab $$");
			break;
		case 'a': // "aba"
			r_core_cmdf (core, "aeab%s", input + 1);
			break;
		case 'b': // "abb"
			core_anal_bbs (core, input + 2);
			break;
		case 'c': // "abc"
			cmd_afbc (core, r_str_trim_head_ro (input + 2));
			break;
		case 'o': // "abo"
			abo (core);
			break;
		case 'e': // "abe"
			{
				const char *arg = r_str_trim_head_ro (input + 2);
				if (*arg == '?') {
					r_core_cmd_help_match (core, help_msg_ab, "abe", true);
				} else {
					RListIter *iter;
					RAnalBlock *bb;
					RList *blocks = r_anal_get_blocks_in (core->anal, core->offset);
					r_list_foreach (blocks, iter, bb) {
						if (arg && *arg) {
							free (bb->esil);
							bb->esil = strdup (arg);
						} else {
							if (bb->esil) {
								r_cons_printf ("%s\n", bb->esil);
							}
						}
					}
				}
			}
			// OLD not confuse with aeb: r_core_cmdf (core, "aeb%s", input + 2);
			break;
		case 'f': // "abf"
			core_anal_abf (core, input + 2);
			break;
		case 'r': // "abr"
			core_anal_bbs_range (core, input + 2);
			break;
		case 't':
			cmd_anal_abt (core, input + 2);
			break;
		case ',': // "ab,"
		case 'p': // "abp"
			cmd_anal_abp (core, input + 2);
			break;
		case 'l': // "abl"
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_abl);
			} else {
				anal_bb_list (core, input + 2);
			}
			break;
		case 'j': { // "abj"
			ut64 addr = core->offset;
			if (input[2] && input[2] != '.') {
				addr = r_num_math (core->num, input + 2);
			}
			r_core_cmd_call_at (core, addr, "afbij");
			break;
		}
		case '-': // "ab-"
			  if (input[2] == '*') {
				  r_anal_block_reset (core->anal);
			  } else {
				  ut64 addr = core->offset;
				  if (input[2] == ' ') {
					  addr = r_num_math (core->num, input + 1);
				  }
				  r_anal_delete_block_at (core->anal, addr);
			  }
			  break;
		case 0:
		case ' ': // "ab "
			{
				// find block
				ut64 addr = core->offset;
				if (input[1] && input[1] != '.') {
					addr = r_num_math (core->num, input + 1);
				}
				r_core_cmd_call_at (core, addr, "afbi");
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_ab);
			break;
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
	case 'e': cmd_anal_esil (core, input + 1, true); break; // "ae"
	case 'L':
		switch (input[1]) {
		case 'j':
		case 'q':
		case 0:
			ranal2_list (core, NULL, input[1]);
			break;
		default:
			// help
			r_core_cmd_help (core, help_msg_La);
			break;
		}
		break;
	case 'o': // "ao"
		cmd_anal_opcode (core, input + 1);
		break;
	case 'O': // "aO"
		cmd_anal_bytes (core, input + 1);
		break;
	case 'F': // "aF"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_aF);
			break;
		}
		r_core_anal_fcn (core, core->offset, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
		break;
	case 'l':
		{
			RList *l = r_asm_cpus (core->rasm);
			RListIter *iter;
			char *c;
			r_list_foreach (l, iter, c) {
				r_cons_printf ("- %s\n", c);
			}
			r_list_free (l);
		}
		break;
	case 'f': // "af"
		if (!cmd_af (core, input)) {
			return false;
		}
		break;
	case 'n': // "an"
		{
		const char *name = "";
		int mode = 0;
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_an);
			mode = -1;
			break;
		case 'j':
		case '*':
			mode = input[1];
			input++;
			break;
		}
		if (mode >= 0) {
			if (input[1] == ' ') {
				name = input + 1;
				while (name[0] == ' ') {
					name++;
				}
				char *end = strchr (name, ' ');
				if (end) {
					*end = '\0';
				}
			}
			if (R_STR_ISEMPTY (name)) {
				name = NULL;
			}
			cmd_an (core, name, mode);
		}
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
		r_core_cmd_call (core, "afl*");
		r_core_cmd_call (core, "ah*");
		r_core_cmd_call (core, "ax*");
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
				anal_fcn_data_gaps (core, r_str_trim_head_ro (input + 1));
			} else {
				anal_fcn_data (core, input + 1);
			}
			break;
		case 't': // "adt"
			cmd_anal_trampoline (core, input + 2);
			break;
		case '.': // "ad."
		case ' ': { // "ad" // asm describe maybe? see aod instead
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
			r = r_anal_data_kind (core->anal, core->offset, core->block, core->blocksize);
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
	case ':': // "a:"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_acolon);
		} else if (input[1] == 'l' || !input[1]) {
			RListIter *iter;
			RAnalPlugin *ap;
			r_list_foreach (core->anal->plugins, iter, ap) {
				r_cons_println (ap->meta.name);
			}
		} else {
			r_anal_cmd (core->anal, r_str_trim_head_ro (input + 1));
		}
		break;
	case 'j': // "aj"
		r_core_cmd_call (core, "aflj");
		break;
	case 0: // "a"
		r_core_cmd_call (core, "aai");
		break;
	case '?':
		if (input[1] == 'j') {
			r_cons_cmd_help_json (help_msg_a);
		} else {
			r_core_cmd_help (core, help_msg_a);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_a);
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
