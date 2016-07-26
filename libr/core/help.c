/* radare - LGPLv3 - Copyright 2014 Jody Frankowski */
/* This file holds help messages relative functions */

#include <r_core.h>

// CMD_ANAL
const char* help_msg_u[] = {
	"Usage: u", "", "uname or undo write/seek",
	"u", "", "Show system uname",
	"us", "", "Alias for s- (seek history)",
	"uw", "", "Alias for wc (requires: e io.cache=true)",
	NULL
};

const char *help_msg_ad[] = {
	"Usage: ad[fkt]", "[...]", "Analyze data",
	"ad", " [N] [D]", "Analyze N data words at D depth",
	"adf", "", "Analyze data in function (use like .adf @@=`afl~[0]`",
	"adfg", "", "Analyze data in function gaps",
	"adk", "", "Analyze data kind (code, text, data, invalid, ...)",
	"adt", "", "Analyze data trampolines (wip)",
	NULL
};

const char *help_msg_a[] = {
	"Usage: a[abcdefFghoprstx]", "[...]", "Analysis commands",
	"ab", " [hexpairs]", "Analyze bytes",
	"aa", "", "Analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
	"ac", " [cycles]", "Analyze which op could be executed in [cycles]",
	"ad", "", "Analyze data trampoline (wip)",
	"ad", " [from] [to]", "Analyze data pointers to (from-to)",
	"ae", " [expr]", "Analyze opcode eval expression (see ao)",
	"af", "[rnbcsl?+-*]", "Analyze functions",
	"aF", "", "Same as above, but using anal.depth=1",
	"ag", "[?acgdlf]", "Output Graphviz code",
	"ah", "[?lba-]", "Analysis hints (force opcode size, ...)",
	"ai", " [addr]", "Address information (show perms, stack, heap, ...)",
	"an", "[an-] [...]", "Manage no-return addresses/symbols/functions",
	"ao", "[e?] [len]", "Analyze opcode (or emulate it)",
	"ap", "", "Find prelude for current offset",
	"ar", "", "Like 'dr' but for the ESIL VM (registers)",
	"as", " [num]", "Analyze syscall using dbg.reg",
	"at", "[trd+-%*?] [.]", "Analyze execution traces",
	"ax", "[?ld-*]", "Manage refs/xrefs (see also afx?)",
	//"ax", " [-cCd] [f] [t]", "manage code/call/data xrefs",
	NULL
};

const char *help_msg_aa[] = {
	"Usage: aa[0*?]", "", "See also 'af' and 'afna'",
	"aa", "", "Alias for 'af@@ sym.*;af@entry0;afva'", //;.afna @@ fcn.*'",
	"aa*", "", "Analyze all flags starting with sym. (af @@ sym.*)",
	"aaa", "", "Autoname functions after aa (see afna)",
	"aac", " [len]", "Analyze function calls (af @@ `pi len~call[1]`)",
	"aae", " [len] ([addr])", "Analyze references with ESIL (optionally to address)",
	"aai", "[j]", "Show info of all analysis parameters",
	"aan", "", "Autoname functions that either start with fcn.* or sym.func.*",
	"aap", "", "Find and analyze function preludes",
	"aar", " [len]", "Analyze len bytes of instructions for references",
	"aas", " [len]", "Analyze symbols (af @@= `isq~[0]`)",
	"aat", " [len]", "Analyze all consecutive functions in section",
	"aau", " [len]", "List mem areas (larger than len bytes) not covered by functions",
	"aav", " [sat]", "Find values referencing a specific section or map",
	NULL
};

const char *help_msg_aar[] = {
	"Usage: aar[j*]", "[N]", "Search and analyze xrefs",
	"aar", " [N]", "Analyze xrefs in current section or N bytes of code",
	"aarj", " [N]", "List found xrefs in JSON format",
	"aar*", " [N]", "List found xrefs in radare commands format",
	NULL
};

const char *help_msg_at[] = {
	"Usage: at[*]", "[addr]", "Analyze tracing information",
	"at", "", "List all traced opcode ranges",
	"at", " [addr]", "Show trace info at address",
	"at-", "", "Reset the tracing information",
	"at*", "", "List all traced opcode offsets",
	"at+", " [addr] [N]", "Add trace for address N times",
	"ata", " 0x804020 ...", "Only trace given addresses",
	"atd", "", "Show disassembly trace (use .atd)",
	"ate", "", "Show esil trace logs (anal.trace)",
	"ate", " [N]", "Show commands to restore to this trace index N",
	"ate", "-", "Clear esil trace logs",
	"atl", "", "List all traced addresses (useful for @@= `atl`)",
	"atr", "", "Show traces as range commands (ar+)",
	"att", " [tag]", "Select trace tag (no arg unsets)",
	//"at%", "", "TODO",
	"atD", "", "Show dwarf trace (at*|rsc dwarf-traces $FILE)",
	NULL
};

const char *help_msg_ate[] = {
	"Usage: ate[ilk-]", "[arg]", "Analyze ESIL traces",
	"ate", "", "ESIL trace log single instruction",
	"ate", " [idx]", "Show commands for that index log",
	"ate-*", "", "Delete all ESIL traces",
	"atei", "", "ESIL trace log single instruction",
	"atek", " [sdbq]", "ESIL trace log single instruction",
	NULL
};

const char *help_msg_ae[] = {
	"Usage: ae[idesr?]", "[arg]", "ESIL code emulation",
	"ae?", "", "Show this help",
	"ae??", "", "Show ESIL help",
	"ae", " [expr]", "Evaluate ESIL expression",
	"ae[aA]", "[f] [count]", "Analyse ESIL accesses (regs, mem..)",
	"aec", "", "Continue until ^C",
	"aecs", " [N]", "Continue until syscall number",
	"aecu", " [addr]", "Continue until address",
	"aecue", " [esil]", "Continue until ESIL expression match",
	"aef", " [addr]", "Emulate function",
	"aei", "", "Initialize ESIL VM state (aei- to deinitialize)",
	"aeim", "", "Initialize ESIL VM stack (aeim- remove)",
	"aeip", "", "Initialize ESIL program counter to curseek",
	"aek", " [query]", "Perform sdb query on ESIL.info",
	"aek-", "", "Resets the ESIL.info sdb instance",
	"aep", " [addr]", "Change ESIL PC to this address",
	"aer", " [..]", "Handle ESIL registers like 'ar' or 'dr' does",
	"aes", "", "Perform emulated debugger step",
	"aeso", " ", "Step over",
	"aesu", " [addr]", "Step until given address",
	"aesue", " [esil]", "Step until ESIL expression match",
	"aetr", "[esil]", "Convert an ESIL Expression to REIL",
	"aex", " [hex]", "Evaluate opcode expression",
	NULL
};

const char* help_msg_alias[] = {
	"Usage: $alias[=cmd]", "[args...]", "Alias commands",
	"$", "", "List all defined aliases",
	"$*", "", "Same as above, but using r2 commands",
	"$", "dis='af;pdf'", "Create command - analyze to show function",
	"$", "test=#!pipe node /tmp/test.js", "Create command - rlangpipe script",
	"$", "dis=", "Undefine alias",
	"$", "dis", "Execute the previously defined alias",
	"$", "dis?", "Show commands aliased by 'analyze'",
	NULL
};

const char* help_msg_remotecmd_alias[] = {
	"Usage: =$[-]","[remotecmd]", "Remote command alias",
	"=$dr", "", "Makes 'dr' alias for =!dr",
	"=$-dr", "", "Unset 'dr' alias",
	NULL
};

const char* help_msg_yank[] = {
	"Usage: y[ptxy]", "[len] [[@]addr]", "See wd? for memcpy, same as 'yf'",
	"y", "", "Show yank buffer information (srcoff len bytes)",
	"y", " 16", "Copy 16 bytes into clipboard",
	"y", " 16 0x200", "Copy 16 bytes into clipboard from 0x200",
	"y", " 16 @ 0x200", "Copy 16 bytes into clipboard from 0x200",
	"yf", " 64 0x200", "File copy 64 bytes from 0x200 from file (opens w/ io), use -1 for all bytes",
	"yfa", " file copy", "Copy all bytes from file (opens w/ io)",
	"yp", "", "Print contents of clipboard",
	"ys", "", "Print contents of clipboard as string",
	"yt", " 64 0x200", "Copy 64 bytes from current seek to 0x200",
	"yx", "", "Print contents of clipboard in hexadecimal",
	"yy", " 0x3344", "Paste clipboard",
	"yz", "", "Copy up to blocksize zero terminated string bytes into clipboard",
	"yz", " 16", "Copy up to 16 zero terminated string bytes into clipboard",
	"yz", " @ 0x200", "Copy up to blocksize zero terminated string bytes into clipboard from 0x200",
	"yz", " 16 @ 0x200", "Copy up to 16 zero terminated string bytes into clipboard from 0x200",
	NULL
};

const char* help_msg_dot[] = {
	"Usage: .[r2cmd]", "| [file] | [!command] | [(macro)]", "Define macro or load r2, cparse or rlang file",
	".", "", "Repeat last command backward",
	".", "r2cmd", "Interpret the output of the command as r2 commands",
	"..", "", "Repeat last command forward (same as \\n)",
	".:", "8080", "Listen for commands on given tcp port",
	".", " foo.r2", "Interpret r2 script",
	".-", "", "Open cfg.editor and interpret tmp file",
	".!", "rabin -ri $FILE", "Interpret output of command",
	".", "(foo 1 2 3)", "Run macro 'foo' with args 1, 2, 3",
	"./", " ELF", "Interpret output of command /m ELF as r. commands",
	NULL
};

const char* help_msg_k[] = {
	"Usage: k[s]", "[key[=value]]", "Sdb query",
	"k", " foo=bar", "Set value",
	"k", " foo", "Show value",
	"k", "", "List keys",
	"k", " anal/meta/*", "List kv from anal > meta namespaces",
	"k", " anal/**", "List namespaces under anal",
	"k", " anal/meta/meta.0x80404", "Get value for meta.0x80404 key",
	"kd", " [file.sdb] [ns]", "Dump namespace to disk",
	"ko", " [file.sdb] [ns]", "Open file into namespace",
	"ks", " [ns]", "Enter the Sdb query shell",
	//"kl", " ha.sdb", "load keyvalue from ha.sdb",
	//"ks", " ha.sdb", "save keyvalue to ha.sdb",
	NULL
};

const char* help_msg_b[] = {
	"Usage: b[f]", "[arg]", "Get/Set block size",
	"b", "", "Display current block size",
	"b", " 33", "Set block size to 33",
	"b", "+3", "Increase blocksize by 3",
	"b", "-16", "Decrease blocksize by 16",
	"b", " eip+4", "Numeric argument can be an expression",
	"bf", " foo", "Set block size to flag size",
	"bm", " 1M", "Set max block size",
	NULL
};

const char* help_msg_r[] = {
	"Usage: r[+-]", "[size]", "Resize file",
	"r", "", "Display file size",
	"r", " [size]", "Expand or truncate file to given size",
	"r-", "[N]", "Remove N bytes, move following data down",
	"r+", "[N]", "Insert N bytes, move following data up",
	"rm" ," [file]", "Remove file",
	"r2" ," [file]", "Launch r2",
	NULL
};

const char* help_msg_ampersand[] = {
	"Usage: &[-|[cmd]]", "", "Manage tasks",
	"&", "", "List all running threads",
	"&=", "", "Show output of all tasks",
	"&=", " 3", "Show output of task 3",
	"&j", "", "List all running threads (in JSON)",
	"&?", "", "Show this help",
	"&+", " aa", "Push to the task list",
	"&-", " 1", "Delete task #1",
	"&", "-*", "Delete all threads",
	"&", " aa", "Run analysis in background",
	"&", " &&", "Run all tasks in background",
	"&&", "", "Run all pendings tasks (and join threads)",
	"&&&", "", "Run all pendings tasks until ^C",
	"","","TODO: last command should honor asm.bits",
	"","","WARN: this feature is very experimental. Use it with caution",
	NULL
};

const char* help_msg_star[] = {
	"Usage: *[addr][=[0x]value]", "", "Pointer read/write data/values",
	"*", "entry0=cc", "Write trap in entrypoint",
	"*", "entry0+10=0x804800", "Write value in delta address",
	"*", "entry0", "Read byte at given address",
	"TODO: last command should honor asm.bits", "", "",
	NULL
};

const char* help_msg_3at[] = {
	"Usage: @@@", "[type]", "Run command on every [type]",
	"Types:", "", "",
	" symbols", "", "",
	" imports", "" , "",
	" regs", "", "",
	" threads", "", "",
	" comments", "", "",
	" functions", "", "",
	" flags", "", "",
	NULL
};

const char* help_msg_2at[] = {
	"Usage: command @@", "[iterable]", "'Foreach' iterator command",
	"Repeat a command over a list of offsets", "", "",
	"Examples:", "", "",
	"x", " @@ sym.*", "Run 'x' over all flags matching 'sym.' in current flagspace",
	"x", " @@dbt[abs]", "Run a command on every backtrace address, bp or sp",
	"x", " @@.file", "\"\" over the offsets specified in the file (one offset per line)",
	"x", " @@=off1 off2 ..", "Manual list of offsets",
	"x", " @@k sdbquery", "\"\" on all offsets returned by that sdbquery",
	"x", " @@t", "\"\" on all threads (see dp)",
	"x", " @@=`pdf~call[0]`", "Run 'x' at every call offset of the current function",
	// TODO: Add @@k sdb-query-expression-here
	NULL
};

const char* help_msg_arf[] = {
	"Usage: arf", "[flag-str-filter]", "",
	NULL
};

const char *help_msg_af[] = {
	"Usage: af", "", "Function analysis",
	"af", " ([name]) ([addr])", "Analyze functions (start at addr or $$)",
	"af+", " addr size name [type] [diff]", "Hand craft a function (requires afb+)",
	"af-", " [addr]", "Clean all function analysis data (or function at addr)",
	"afb", " [addr]", "List basic blocks of given function",
	"afb+", " fa a sz [j] [f] ([t] ([d]))", "Add bb to function @ fcnaddr",
	"afc", "@[addr]", "Calculate the Cyclomatic Complexity (starting at addr)",
	"aff", "", "Re-adjust function boundaries to fit",
	"afg", "", "Non-interactive ascii-art basic-block graph (See VV)",
	"afi", " [addr|fcn.name]", "Show function(s) information (verbose afl)",
	"afl", "[l*] [fcn name]", "List functions (addr, size, bbs, name) (see afll)",
	"afn", " name [addr]", "Rename name for function at address (change flag too)",
	"afna", "", "Suggest automatic name for current offset",
	"afo", " [fcn.name]", "Show address for the function named like this",
	"afr", " ([name]) ([addr])", "Analyze functions recursively",
	"afs", " [addr] [fcnsign]", "Get/set function signature at current address",
	"afv[bsra]", "?", "Manipulate args, registers and variables in function",
	"afx", "[cCd-] src dst", "Add/remove code/Call/data/string reference",
	"afB", " 16", "Set current function as thumb (change asm.bits)",
	"afC[?]", " type @[addr]", "Set calling convention for function",
	"afF", "[1|0|]", "Fold/unfold/toggle",
	NULL
};

const char *help_msg_ar[] = {
	"Usage: ar", "", "Analysis Registers",
	"ar", "", "Show 'gpr' registers",
	"ar", " 16", "Show 16 bit registers",
	"ar", " 32", "Show 32 bit registers",
	"ar", " all", "Show all bit registers",
	"ar", " [type]", "Show all registers of given type",
	"ar?", " [reg]", "Show register value",
	"ar=", "", "Show register values in columns",
	"ar0", "", "Reset register arenas to 0",
	"ara", "", "Manage register arenas",
	"arb", " [type]", "Display hexdump of the given arena",
	"arc", " [name]", "Conditional flag registers",
	"ard", " [name]", "Show only different registers",
	"arn", " [regalias]", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
	"aro", "", "Show old (previous) register values",
	"arp", " [file]", "Load register profile from file",
	"arr", "", "Show register references (telescoping)",
	"ars", "", "Stack register state",
	"art", "", "List all register types",
	"arw", " [val]", "Set contents of the register arena (val is hex)",
	"arC", "", "Display register profile comments",
	".ar*", "", "Import register values as flags",
	".ar-", "", "Unflag all registers",
	NULL
};

const char *help_msg_ara[] = {
	"Usage: ara[+-s]", "", "Register Arena Push/Pop/Swap",
	"ara", "", "Show all register arenas allocated",
	"ara", "+", "Push a new register arena for each type",
	"ara", "-", "Pop last register arena",
	"aras", "", "Swap last two register arenas",
	NULL
};

const char *help_msg_arw[] = {
	"Usage: arw", "[val]", "Set contents of the register arena",
	"arw", " [val]", "Set contents of the register arena (val in hex)",
	NULL
};

const char *help_msg_aea[] = {
	"Usage: aea", "", " Show regs used in a range",
	"aea", " [N]", "Show regs used in N instructions",
	"aeaf", "", "Show regs used in current function",
	"aear", " [N]", "Show regs read in N instructions",
	"aeaw", " [N]", "Show regs written in N instructions",
	"aean", " [N]", "Show regs not written in N instructions",
	"aeA", " [N]", "Show regs used in N bytes (subcommands are the same)",
	NULL
};

const char *help_msg_aec[] = {
	"Usage: aec[sue]", "", "Continue emulation until condition",
	"aec", "", "Continue until exception",
	"aecs", "", "Continue until syscall",
	"aecu", " [addr]", "Continue untill address",
	"aecue", " [expr]", "Continue until ESIL expression",
	NULL
};

const char *help_msg_aep[] = {
	"Usage: aep[-c]", "[...]", "ESIL VM pin management",
	"aep", "-[addr]", "Remove pin",
	"aep", " [name] @ [addr]", "Set pin",
	"aep", "", "List pins",
	"aepc", " [addr]", "Change program counter for ESIL VM",
	NULL
};

const char* help_msg_afvs[] = {
	"Usage: afvs", "[idx] [type] [name]", "",
	"afvs", "", "List stack based arguments and variables",
	"afvs*", "", "Same as afvs but in r2 commands",
	"afvs", " [idx] [name] [type]", "Define stack based arguments,variables",
	"afvs-", " [name]", "Delete stack based argument or variables with the given name",
	"afvsj", "", "Return list of stack based arguments and variables in JSON format",
	"afvsn", " [old_name] [new_name]", "Rename stack based argument or variable",
	"afvst", " [name] [new_type]", "Change type for given argument or variable",
	"afvsg", " [idx] [addr]", "Define var get reference",
	"afvss", " [idx] [addr]", "Define var set reference",
	NULL
};

const char* help_msg_afvb[] = {
	"Usage: afvb", "[idx] [type] [name]", "",
	"afvb", "", "List base pointer based arguments, variables",
	"afvb*", "", "Same as afvb but in r2 commands",
	"afvb", " [idx] [name] ([type])", "Define base pointer based argument, variable",
	"afvb-", " [name]", "Delete argument/ variables at the given name",
	"afvbj", "", "Return list of base pointer based arguments, variables in JSON format",
	"afvbn", " [old_name] [new_name]", "Rename base pointer based argument or variable",
	"afvbt", " [name] [new_type]", "Change type for given base pointer based argument or variable",
	"afvbg", " [idx] [addr]", "Define var get reference",
	"afvbs", " [idx] [addr]", "Define var set reference",
	NULL
};

const char* help_msg_afvr[] = {
	"Usage: afvr", "[reg] [type] [name]", "",
	"afvr", "", "List register based arguments",
	"afvr*", "", "Same as afvr but in r2 commands",
	"afvr", " [reg] [name] ([type])", "Define register arguments",
	"afvr-", " [name]", "Delete register arguments at the given index",
	"afvrj", "", "Return list of register arguments in JSON format",
	"afvrn", " [old_name] [new_name]", "Rename argument",
	"afvrt", " [name] [new_type]", "Change type for given argument",
	"afvrg", " [reg] [addr]", "Define var get reference",
	"afvrs", " [reg] [addr]", "Define var set reference",
	NULL
};

const char* help_msg_afv[] = {
	"Usage: afv[rbsa]", "", "",
	"afva", "", "Analyze function arguments/vars",
	"afvb", "?", "Manipulate bp based arguments/vars",
	"afvr", "?", "Manipulate register based arguments",
	"afvs", "?", "Manipulate sp based arguments/vars",
	NULL
};

const char* help_msg_afi[] = {
	"Usage: afi[jl*]", "[addr|fcn.name]", "Show function information (verbose afl)",
	"afij", "", "Function info in JSON format",
	"afil", "", "Verbose function info",
	"afi*", "", "Function, variables and arguments",
	NULL
};

const char* help_msg_afl[] = {
	"Usage: afl[jlqs*]", "", "List all functions in quiet, commands or JSON format",
	"afl", "", "List functions",
	"aflj", "", "List functions in JSON format",
	"afll", "", "List functions in verbose mode",
	"aflq", "", "List functions in 'quiet' mode",
	"afls", "", "print sum of sizes of all functions",
	NULL
};

const char *help_afC[] = {
	"Usage: afC[agl?]", "", "Analyze calling convention",
	"afC", " [convention]", "Manually set calling convention for current function",
	"afC", "", "Show calling convention for the current function",
	"afCa", "", "Analyse function for finding the current calling convention",
	"afCl", "", "List all available calling conventions",
	NULL
};

const char *help_msg_afb[] = {
	"Usage: afb[+b][-*j]", "", "",
	"afb", " [addr]", "List basic blocks of function (see afbq, afbj, afb*)",
	"afb+", " fcn_at bbat bbsz [jump] [fail] ([type] ([diff]))", "Add bb to function @ fcnaddr",
	"afbj", "", "Show basic blocks information in JSON",
	"afbr", "", "Show addresses of instructions which leave the function",
	".afbr*", "", "Set breakpoint on every return address of the fcn",
	".afbr-*", "", "Undo the above operation",
	"afB", " [bits]", "Define asm.bits for given function",
	NULL
};

const char *help_msg_afn[] = {
	"Usage: afn[sa]", "", "Analyze function names",
	"afn", " [name]", "Rename function",
	"afna", "", "Construct a function name for the current offset",
	"afns", "", "List all strings associated with the current function",
	NULL
};

const char *help_msg_afx[] = {
	"Usage: afx[-cCd?]", "[src] [dst]", "Manage function references (see also ar?)",
	"afxc", " sym.main+0x38 sym.printf", "Add code ref",
	"afxC", " sym.main sym.puts", "Add call ref",
	"afxd", " sym.main str.helloworld", "Add data ref",
	"afx-", " sym.main str.helloworld", "Remove reference",
	NULL
};

const char *help_msg_esil[] = {
	"Examples:", "ESIL", "instructions, examples and documentation",
	"+", "=", "A+=B => B,A,+=",
	"+", "", "A=A+B => B,A,+,A,=",
	"*", "=", "A*=B => B,A,*=",
	"/", "=", "A/=B => B,A,/=",
	"&", "=", "and ax, bx => bx,ax,&=",
	"|", "", "or r0, r1, r2 => r2,r1,|,r0,=",
	"^", "=", "xor ax, bx => bx,ax,^=",
	">>", "=", "shr ax, bx => bx,ax,>>=  # shift right",
	"<<", "=", "shr ax, bx => bx,ax,<<=  # shift left",
	"", "[]", "mov eax,[eax] => eax,[],eax,=",
	"=", "[]", "mov [eax+3], 1 => 1,3,eax,+,=[]",
	"=", "[1]", "mov byte[eax],1 => 1,eax,=[1]",
	"=", "[8]", "mov [rax],1 => 1,rax,=[8]",
	"$", "", "int 0x80 => 0x80,$",
	"$$", "", "Simulate a hardware trap",
	"==", "", "Pops twice, compare and update esil flags",
	"<", "", "Compare for smaller",
	"<", "=", "Compare for smaller or equal",
	">", "", "Compare for bigger",
	">", "=", "Compare bigger for or equal",
	"?{", "", "If popped value != 0 run the block until }",
	"POP", "", "Drops last element in the esil stack",
	"TODO", "", "The instruction is not yet esilized",
	"STACK", "", "Show contents of stack",
	"CLEAR", "", "Clears the esil stack",
	"BREAK", "", "Terminates the string parsing",
	"GOTO", "", "Jump to the Nth word popped from the stack",
	NULL
};

const char *help_msg_an[] = {
	"Usage: an[an]", "[-][0xaddr|symname]", "Manage no-return marks",
	"an", "", "List all no-return references",
	"an", "-*", "Remove all no-return references",
	"an[a]", " 0x3000", "Stop function analysis if call/jmp to this address",
	"an[n]", " sym.imp.exit", "Same as above but for flag/fcn names",
	NULL
};

const char *help_msg_ao[] = {
	"Usage: ao[e?]", "[len]", "Analyze opcodes",
	"ao", " 5", "Display opcode analysis of 5 opcodes",
	"ao*", "", "Display opcode in r commands",
	"aoe", " [N]", "Display esil form for N opcodes",
	"aoj", " [N]", "Display opcode analysis information in JSON for N opcodes",
	"aor", " [N]", "Display reil form for N opcodes",
	"aos", " [esil]", "Show Sdb representation of ESIL expression (TODO)",
	NULL
};

const char *help_msg_as[] = {
	"Usage: as[ljk?]", "", "System call analysis, listing and translation",
	"as", "", "Show current syscall and arguments",
	"as", " 4", "Show syscall 4 based on asm.os and current regs/mem",
	"asf", " [k[=[v]]]", "List/set/unset pf function signatures (see fcnsign)",
	"asj", "", "List of syscalls in JSON",
	"ask", " [query]", "Perform syscall/queries",
	"asl", "", "List of syscalls by asm.os and asm.arch",
	"asl", " close", "Returns the syscall number for close",
	"asl", " 4", "Returns the name of the syscall number 4",
	NULL
};

const char *help_msg_ah[] = {
	"Usage: ah[lba-]", "", "Analysis hints",
	"ah?", "", "Show this help",
	"ah?", " offset", "Show hint of given offset",
	"ah", "", "List hints in human-readable format",
	"ah.", "", "List hints in human-readable format from current offset",
	"ah-", "", "Remove all hints",
	"ah-", " offset [size]", "Remove hints at given offset",
	"ah*", " offset", "List hints in radare commands format",
	"aha", " ppc 51", "Set arch for a range of N bytes",
	"ahb", " 16 @ $$", "Force 16bit for current instruction",
	"ahc", " 0x804804", "Override call/jump address",
	"ahe", " eax+=3", "Set VM analysis string",
	"ahf", " 0x804840", "Override fallback address for call",
	"ahi", " 10", "Define numeric base for immediates (1, 8, 10, 16, s)",
	"ahs", " 4", "Set opcode size=4",
	"ahS", " jz", "Set asm.syntax=jz for this opcode",
	"aho", " foo a0,33", "Replace opcode string",
	NULL
};

const char* help_msg_ahi[] = {
	"Usage: ahi", "[sbodh] [@ offset]", "Define numeric base",
	"ahi", " [base]", "Set numeric base (1, 2, 8, 10, 16)",
	"ahi", " b", "Set base to binary (1)",
	"ahi", " d", "Set base to decimal (10)",
	"ahi", " h", "Set base to hexadecimal (16)",
	"ahi", " o", "Set base to octal (8)",
	"ahi", " i", "Set base to IP address (32)",
	"ahi", " S", "Set base to syscall (80)",
	"ahi", " s", "Set base to string (2)",
	NULL
};

const char *help_msg_ax[] = {
	"Usage: ax[?d-l*]", "", "See also 'afx?'",
	"ax", " addr [at]", "Add code ref pointing to addr (from curseek)",
	"axc", " addr [at]", "Add code jmp ref // unused?",
	"axC", " addr [at]", "Add code call ref",
	"axg", " addr", "Show xrefs graph to reach current function",
	"axd", " addr [at]", "Add data ref",
	"axj", "", "List refs in json format",
	"axF", " [flg-glob]", "Find data/code references of flags",
	"axt", " [addr]", "Find data/code references to this address",
	"axf", " [addr]", "Find data/code references from this address",
	"ax-", " [at]", "Clean all refs (or refs from addr)",
	"ax", "", "List refs",
	"axk", " [query]", "Perform Sdb query",
	"ax*", "", "Output radare commands",
	NULL
};

const char *help_msg_ag[] = {
	"Usage: ag[?f]", "", "Graphviz/graph code",
	"ag", " [addr]", "Output graphviz code (bb at addr and children)",
	"ag-", "", "Reset the current ASCII art graph (see agn, age, agg?)",
	"aga", " [addr]", "Idem, but only addresses",
	"agc", "[j] [addr]", "Output graphviz call graph of function",
	"agC", "[j]", "Same as agc -1. full program callgraph",
	"agd", " [fcn name]", "Output graphviz code of diffed function",
	"age", "[?] title1 title2", "Add an edge to the current graph",
	"agf", " [addr]", "Show ASCII art graph of given function",
	"agg", "[kdi*]", "Print graph in ASCII-Art, graphviz, k=v, r2 or visual",
	"agj", " [addr]", "Idem, but in JSON format",
	"agk", " [addr]", "Idem, but in SDB key-value format",
	"agl", " [fcn name]", "Output graphviz code using meta-data",
	"agn", "[?] title body", "Add a node to the current graph",
	"ags", " [addr]", "Output simple graphviz call graph of function (only bb offset)",
	"agt", " [addr]", "Find paths from current offset to given address",
	"agv", "[acdltfl] [a]", "View function using graphviz",
	NULL};

const char *help_msg_agn[] = {
	"Usage: agn", "[title] [body]", "",
	"Examples:", "", "",
	"agn", " title1 body1", "Add a node with title \"title1\" and body \"body1\"",
	"agn", " \"title with space\" \"body with space\"", "Add a node with spaces in the title and in the body",
	"agn", " title1 base64:Ym9keTE=", "Add a node with the body specified as base64",
	"agn-", " title1", "Remove a node with title \"title1\"",
	"agn?", "", "Show this help",
	NULL
};

const char *help_msg_age[] = {
	"Usage: age", "[title1] [title2]", "",
	"Examples:", "", "",
	"age", " title1 title2", "Add an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age", " \"title1 with spaces\" title2", "Add an edge from node \"title1 with spaces\" to node \"title2\"",
	"age-", " title1 title2", "Remove an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age?", "", "Show this help",
	NULL
};

const char *help_msg_agg[] = {
	"Usage: agg[kid?*]", "", "Print graph",
	"agg", "", "Show current graph in ascii art",
	"aggk", "", "Show graph in key=value form",
	"aggd", "", "Print the current graph in GRAPHVIZ dot format",
	"aggi", "", "Enter interactive mode for the current graph",
	"aggd", "", "Print the current graph in GRAPHVIZ dot format",
	"agg*", "", "In r2 commands, to save in projects, etc",
	NULL
};

// CMD_CMP
const char* help_msg_c[] = {
	"Usage: c[?dfx]", "[arg]", "Comparison operations",
	"c", " [string]", "Compare a plain with escaped chars string",
	"c*", " [string]", "Compare a plain with escaped chars string (output r2 commands)",
	"c4", " [value]", "Compare a doubleword from a math expression",
	"c8", " [value]", "Compare a quadword from a math expression",
	"cat", " [file]", "Show contents of file (see pwd, ls)",
	"cc", " [at] [(at)]", "Compares in two hexdump columns of block size",
	"ccc", " [at] [(at)]", "Same as above, but only showing different lines",
	"ccd", " [at] [(at)]", "Compares in two disasm columns of block size",
	//"cc", " [offset]", "code bindiff current block against offset"
	//"cD", " [file]", "like above, but using radiff -b",
	"cf", " [file]", "Compare contents of file at current seek",
	"cg", "[o] [file]","Graphdiff current file and [file]",
	"cl|cls|clear", "", "Clear screen, (clear0 to goto 0, 0 only)",
	"cu", " [addr] @at", "Compare memory hexdumps of $$ and dst in unified diff",
	"cud", " [addr] @at", "Unified diff disasm from $$ and given address",
	"cv", "[1248] [addr] @at", "Compare 1,2,4,8-byte value",
	"cw", "[us?] [...]", "Compare memory watchers",
	"cx", " [hexpair]", "Compare hexpair string (use '.' as nibble wildcard)",
	"cx*", " [hexpair]", "Compare hexpair string (output r2 commands)",
	"cX", " [addr]", "Like 'cc' but using hexdiff output",
	NULL
};
const char *help_msg_cw[] = {
	"Usage: cw", "", "Watcher commands",
	"cw", "", "List all compare watchers",
	"cw", " addr", "List all compare watchers",
	"cw", " addr sz cmd", "Add a memory watcher",
	//"cws", " [addr]", "Show watchers",
	"cw", "*", "List compare watchers in r2 cmds",
	"cwr", " [addr]", "Reset/revert watchers",
	"cwu", " [addr]", "Update watchers",
	NULL
};

const char *help_msg_cg[] = {
	"Usage: cg", "", "Graph code commands",
	"cg",  "", "Diff ratio among functions (columns: off-A, match-ratio, off-B)",
	"cgf", "[fcn]", "Compare functions (curseek vs fcn)",
	"cgo", "", "Opcode-bytes code graph diff",
	NULL
};
const char* help_msg_cu[] = {
	"Usage: cu",  "[offset]", "Creates a unified hex patch",
	"cu", " $$+1 > p", "Compare current seek and +1",
	"cud", " $$+1 > p", "Compare disasm current seek and +1",
	"wu", " p", "Apply unified hex patch",
	NULL
};

const char* help_msg_cv[] = {
	"Usage: cv[1248]", "[num]", "Show offset if current value equals to the one specified",
	"Example:", "", "",
	"/v", " [val]", "Search for a known value",
	"dc", "", "Continue execution",
	"cv4", " [val] @@ hit*", "Show offset",
	"dc", "", "Continue execution",
	NULL
};

// CMD_DBG
const char* help_msg_d[] = {
	"Usage: d", "", "Debug commands",
	"db", "[?]", "Breakpoints commands",
	"dbt", "", "Display backtrace based on dbg.btdepth and dbg.btalgo",
	"dc", "[?]", "Continue execution",
	"dd", "[?]", "File descriptors (!fd in r1)",
	"de", "[-sc] [rwx] [rm] [e]", "Debug with ESIL (see de?)",
	"dg", " <file>", "Generate a core-file (WIP)",
	"dh", " [handler]", "List or set debugger handler",
	"dH", " [handler]", "Transplant process to a new handler",
	"di", "", "Show debugger backend information (See dh)",
	"dk", "[?]", "List, send, get, set, signal handlers of child",
	"dm", "[?]", "Show memory maps",
	"do", "", "Open process (reload, alias for 'oo')",
	"doo", "[args]", "Reopen in debugger mode with args (alias for 'ood')",
	"dp", "[?]", "List, attach to process or thread id",
	"dr", "[?]", "Cpu registers",
	"ds", "[?]", "Step, over, source line",
	"dt", "[?]", "Display instruction traces (dtr=reset)",
	"dw", " <pid>", "Block prompt until pid dies",
	"dx", "[?]", "Inject and run code on target process (See gs)",
	NULL
};

const char* help_msg_db[] = {
	"Usage: db", "", "Breakpoints commands",
	"db", "", "List breakpoints",
	"db", " sym.main", "Add breakpoint into sym.main",
	"db", " [addr]", "Add breakpoint",
	"db", " -[addr]", "Remove breakpoint",
	"db.", "", "Show breakpoint info in current offset",
	// "dbi", " 0x848 ecx=3", "stop execution when condition matches",
	"dbc", " [addr] [cmd]", "Run command when breakpoint is hit",
	"dbd", " [addr]", "Disable breakpoint",
	"dbe", " [addr]", "Enable breakpoint",
	"dbh", " x86", "Set/list breakpoint plugin handlers",
	"dbi", "", "List breakpoint indexes",
	"dbic", " [index] [cmd]", "Run command at breakpoint index",
	"dbie", " [index]", "Enable breakpoint by index",
	"dbid", " [index]", "Disable breakpoint by index",
	"dbis", " [index]", "Swap Nth breakpoint",
	"dbite", " [index]", "Enable breakpoint Trace by index",
	"dbitd", " [index]", "Disable breakpoint Trace by index",
	"dbits", " [index]", "Swap Nth breakpoint trace",
	"dbj", "", "List breakpoints in JSON format",
	"dbm", " [module] [offset]", "Add a breakpoint at an offset from a module's base",
	"dbn", " [name]", "Show or set name for current breakpoint",
	"dbs", " [addr]", "Toggle breakpoint",
	"dbt", "", "Display backtrace based on dbg.btdepth and dbg.btalgo",
	"dbt*", "", "Display backtrace in flags",
	"dbt=", "", "Display backtrace in one line (see dbt=s and dbt=b for sp or bp)",
	"dbtj", "", "Display backtrace in JSON",
	"dbte", " [addr]", "Enable Breakpoint Trace",
	"dbtd", " [addr]", "Disable Breakpoint Trace",
	"dbts", " [addr]", "Swap Breakpoint Trace",
	"drx", " number addr len rwx", "Modify hardware breakpoint",
	"drx-", "number", "Clear hardware breakpoint",
	NULL
};

const char * help_msg_dc[] = {
	"Usage: dc", "", "Execution continuation commands",
	"dc", "", "Continue execution of all children",
	"dc", " [pid]", "Continue execution of pid",
	"dc", "-[pid]", "Stop execution of pid",
	"dca", " [sym] [sym].", "Continue at every hit on any given symbol",
	"dcc", "", "Continue until call (use step into)",
	"dccu", "", "Continue until unknown call (call reg)",
	"dcf", "", "Continue until fork (TODO)",
	"dck", " [signal] [pid]", "Continue sending signal to process",
	"dco", " [N]", "Step over N instructions",
	"dcp", "", "Continue until program code (mapped io section)",
	"dcr", "", "Continue until ret (uses step over)",
	"dcs", " [N|syscall]", "Continue until syscall number/name",
	"dct", " [len]", "Traptrace from curseek to len, no argument to list",
	"dcu", "[..end|addr] ([end])", "Continue until address (or range)",
	NULL
};

const char *help_msg_dcs[] = {
	"Usage: dcs", "[syscall-name-or-number]", "",
	"dcs", "", "Continue until next syscall",
	"dcs mmap", "", "Continue until next call to mmap",
	"dcs*", "", "Trace all syscalls (strace)",
	"dcs?", "", "Show this help",
	NULL
};

const char *help_msg_dd[] = {
	"Usage: dd", "", "Descriptors commands",
	"dd", "", "List file descriptors",
	"dd", " [file]", "Open and map that file into the UI",
	"dd-", "[fd]", "Close stdout fd",
	"dd*", "", "List file descriptors (in radare commands)",
	NULL
};

const char *help_msg_de[] = {
	"Usage: de[-sc]", "[rwx] [rm] [expr]", "",
	"de", "", "List ESIL watchpoints",
	"de-*", "", "Delete all ESIL watchpoints",
	"de", " [rwx] [rm] [addr|reg|from..to]", "Stop on condition",
	"dec", "", "Continue execution until matching expression",
	"des", " [N]", "Step-in N instructions with ESIL debug",
	"desu", " [addr]", "ESIL debug until specific address",
	"", "", "",
	"Examples:", "", "",
	" de", " r r rip", "Stop when rip is read",
	" de", " rw m [addr]", "Stop when read or write in [addr]",
	" de", " w r rdx", "Stop when rdx register is modified",
	" de", " x m FROM..TO", "Stop when rip is in specified range",
	NULL
};

const char *help_msg_des[] = {
	"Usage: des[u]", "[arg]", "ESIL debug stepping",
	"des", " [N]", "Step-in N instructions with ESIL debug",
	"desu", " [addr]", "ESIL debug until specific address",
	NULL
};

const char *help_msg_di[] = {
	"Usage: di", "", "Debugger target information",
	"di", "", "Show debugger target information",
	"dij", "", "Same as above, but in JSON format",
	NULL
};

const char *help_msg_dk[] = {
	"Usage: dk", "", "Signal commands",
	"dk", "", "List all signal handlers of child process",
	"dk", " [signal]", "Send KILL signal to child",
	"dk", " [signal]=1", "Set signal handler for <signal> in child",
	"dk?", "[signal]", "Name/signum resolver",
	"dkj", "", "List all signal handlers in JSON",
	"dko", " [signal]", "Reset skip or cont options for given signal",
	"dko", " [signal] [skip|cont]", "On signal SKIP handler or CONT into",
	NULL
};

const char *help_msg_dko[] = {
	"Usage: dko", "", "Signal handling commands",
	"dko", "", "List existing signal handling",
	"dko", " [signal]", "Clear handling for a signal",
	"dko", " [signal] [skip|cont]", "Set handling for a signal",
	"NOTE: [signal] can be a number or a string that resolves with dk?", "", "",
	" skip means do not enter into the signal handler", "", "",
	" continue means enter into the signal handler", "", "",
	NULL
};

const char* help_msg_dm[] = {
	"Usage: dm", "", "Memory maps commands",
	"dm", "", "List memory maps of target process",
	"dm=", "", "List memory maps of target process (ascii-art bars)",
	"dm", " [address] [size]", "Allocate [size] bytes at [address] (anywhere if address is -1) in child process",
	"dm.", "", "Show map name of current address",
	"dm*", "", "List memmaps in radare commands",
	"dm-", "[address]", "Deallocate memory map of [address]",
	"dmd", "[a] [file]", "Dump current (all) debug map region to a file (from-to.dmp) (see Sd)",
	"dmh", "", "Show map of heap",
	"dmi", " [addr|libname] [symname]", "List symbols of target lib",
	"dmi*", " [addr|libname] [symname]", "List symbols of target lib in radare commands",
	"dmj", "", "List memmaps in JSON format",
	"dml", " [file]", "Load contents of file into the current map region (see Sl)",
	"dmm", "[j*]", "List modules (libraries, binaries loaded in memory)",
	"dmp", " [address] [size] [perms]", "Change page at [address] with [size], protection [perms] (rwx)",
	"dms", " [id] [mapaddr]", "Take memory snapshot",
	"dms-", " [id] [mapaddr]", "Restore memory snapshot",
	//"dm, " rw- esp 9K", "set 9KB of the stack as read+write (no exec)",
	//"TODO:", "", "map files in process memory. (dmf file @ [addr])",
	NULL
};

const char* help_msg_dmh[] = {
	"Usage: dmh", "", "Memory map heap info glibc",
	"dmha", "", "Struct Malloc State (main_arena)",
	"dmhb", "", "Show bins information",
	"dmhb", " [bin_num]", "Print double linked list of the number of bin",
	"dmhc", " @[malloc_addr]", "Print malloc_chunk struct for a given malloc chunk",
	"dmhf", "", "Show fastbins information",
	"dmhf", " [fastbin_num]", "Print single linked list of the number of fastbin",
	"dmh?", "", "Show map heap help",
	NULL
};
const char* help_msg_dmm[] = {
	"Usage: dmm", "", "Module memory maps commands",
	"dmm", "", "List modules of target process",
	"dmm.", "", "List memory map of current module",
	"dmmj", "", "List modules of target process (JSON)",
	"dmm*", "", "List modules of target process (r2 commands)",
	NULL
};

const char* help_msg_dms[] = {
	"Usage: dms", "", "Memory map snapshots manangement",
	"dms", "", "List memory snapshots",
	"dmsj", "", "List snapshots in JSON",
	"dms*", "", "List snapshots in r2 commands",
	"dms", " [addr]", "Take snapshot with given id of map at address",
	"dms", "- [id]", "Delete memory snapshot",
	"dmsC", " [id] comment", "Add comment for given snapshot",
	"dmsd", " [id]", "Hexdiff given snapshot. See `ccc`.",
	"dmsw", "", "Snapshot of the writable maps",
	"dmsa", "", "Full snapshot of all `dm` maps",
	"dmsf", " [file] @ addr", "Read snapshot from disk",
	"dmst", " [file] @ addr", "Dump snapshot to disk",
	// TODO: dmsj - for json
	NULL
};

const char* help_msg_do[] = {
	"Usage: do", "", "Debug open commands",
	"do", "", "Open process (reload, alias for 'oo')",
	"doo", "[args]", "Reopen in debugger mode with args (alias for 'ood')",
	NULL
};

const char *help_msg_dp[] = {
	"Usage: dp", "", "Process commands",
	"dp", "", "List current pid and children",
	"dp", " [pid]", "List children of pid",
	"dp*", "", "List all attachable pids",
	"dp=", "[pid]", "Select pid",
	"dp-", " [pid]", "Dettach select pid",
	"dpa", " [pid]", "Attach and select pid",
	"dpc", "", "Select forked pid (see dbg.forks)",
	"dpc*", "", "Display forked pid (see dbg.forks)",
	"dpe", "", "Show path to executable",
	"dpf", "", "Attach to pid like file fd // HACK",
	"dpk", " [pid] [signal]", "Send signal to process (default 0)",
	"dpn", "", "Create new process (fork)",
	"dptn", "", "Create new thread (clone)",
	"dpt", "", "List threads of current pid",
	"dpt", " [pid]", "List threads of process",
	"dpt=", "[thread]", "Attach to thread",
	NULL
};

const char *help_msg_dr[] = {
	"Usage: dr", "", "Registers commands",
	"dr", "", "Show 'gpr' registers",
	"dr", " [register]=[val]", "Set register value",
	"dr=", "", "Show registers in columns",
	"dr?", "[register]", "Show value of given register",
	"drb", " [type]", "Display hexdump of gpr arena (WIP)",
	"drC", "", "Show register profile comments",
	"drc", " [name]", "Related to conditional flag registers",
	"drd", "", "Show only different registers",
	"drl", "", "List all register names",
	"drn", " [pc]", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
	"dro", "", "Show previous (old) values of registers",
	"drp", " [file]", "Load register metadata file",
	"drp", "", "Display current register profile",
	"drps", "", "Fake register profile size",
	"drr", "", "Show registers references (telescoping)",
	"drs", " [?]", "Stack register states",
	"drt", "", "Show all register types",
	"drt", " flg", "Show flag registers",
	"drt", " all", "Show all registers",
	"drt", " 16", "Show 16 bit registers",
	"drt", " 32", "Show 32 bit registers",
	"drt", " 80", "Show 80 bit registers (long double)",
	"drx", "", "Show all debug registers",
	"drx", " [idx] [addr] [len] [rwx]", "Modify hardware breakpoint",
	"drx-", "[idx]", "Clear hardware breakpoint",
	"drf","","show fpu registers (80 bit long double)",
	"drm","","show multimedia packed registers",
	"drm"," mmx0 0 32 = 12","set the first 32 bit word of the mmx reg to 12",
	"drw"," [val]", "Set contents of the register arena (val in hex)",
	".dr", "*", "Include common register values in flags",
	".dr", "-", "Unflag all registers",
	NULL
};

const char *help_msg_drf[] = {
	"Usage: drf", "[fpureg] [= value]", "",
	NULL
};
const char *help_msg_drm[] = {
	"Usage: drm", "[reg] [idx] [wordsize] [= value]", "",
	NULL
};
const char *help_msg_drp[] = {
	"Usage: drp", "", "Register profile commands",
	"drp", "", "Show the current register profile",
	"drp", " [regprofile-file]", "Set the current register profile",
	"drp.", "", "Show the current fake size",
	"drpj", "", "Show the current register profile (JSON)",
	"drps", " [new fake size]", "Set the fake size",
	NULL
};

const char *help_msg_drs[] = {
	"Usage: drs", "", "Register states commands",
	"drs", "", "List register stack",
	"drs", "+", "Push register state",
	"drs", "-", "Pop register state",
	NULL
};

const char *help_msg_drt[] = {
	"Usage: drt", "[type] [size]", "Debug register types",
	"drt", "", "List all available register types",
	"drt", " [size]", "Show all regs in the profile of size",
	"drt", " [type]", "Show all regs in the profile of this type",
	"drt", " [type] [size]", "Same as above for type and size",
	NULL
};

const char *help_msg_drx[] = {
  "Usage: drx", "", "Hardware breakpoints commands",
  "drx", "", "List all (x86?) hardware breakpoints",
  "drx", " [idx] [address] [len] [perms]", "Modify hardware breakpoint",
  "drx-", "[idx]", "Clear hardware breakpoint",
  NULL
};

const char *help_msg_ds[] = {
	"Usage: ds", "", "Step commands",
	"ds", "", "Step one instruction",
	"ds", " [N]", "Step N instructions",
	"dsf", "", "Step until end of frame",
	"dsi", " [cond]", "Continue until condition matches",
	"dsl", "", "Step one source line",
	"dsl", " [N]", "Step N source lines",
	"dso", " [N]", "Step over N instructions",
	"dsp", "", "Step into program (skip libs)",
	"dss", " [N]", "Skip N step instructions",
	"dsu", " [address]", "Step until address",
	"dsui", " [instr]", "Step until an instruction that matches `instr`",
	"dsue", " [esil]", "Step until ESIL expression matches",
	"dsuf", " [flag]", "Step until pc == flag matching name",
	NULL
};

const char *help_msg_dt[] = {
	"Usage: dt", "", "Trace commands",
	"dt", "", "List all traces ",
	"dtd", "", "List all traced disassembled",
	"dtc [addr]|([from] [to] [addr])", "", "Trace call/ret",
	"dtg", "", "Graph call/ret trace",
	"dtg*", "", "Graph in agn/age commands. use .dtg*;aggi for visual",
	"dtgi", "", "Interactive debug trace",
	"dt-", "", "Reset traces (instruction/calls)",
	NULL
};

const char *help_msg_dtc[] = {
	"Usage: dtc", "[addr] ([from] [to] [addr])", "Trace calls in debugger",
	NULL
};

const char *help_msg_dx[] = {
	"Usage: dx", "", " # Code injection commands",
	"dx", " [opcode]...", "Inject opcodes",
	"dxa", " nop", "Assemble code and inject",
	"dxe", " egg-expr", "Compile egg expression and inject it",
	"dxr", " [opcode]...", "Inject opcodes and restore state",
	"dxs", " write 1, 0x8048, 12", "Syscall injection (see gs)",
	"\nExamples:", "", "",
	"dx", " 9090", "Inject two x86 nop",
	"\"dxa mov eax,6;mov ebx,0;int 0x80\"", "", "Inject and restore state",
	NULL
};

// CMD_EGG
const char *help_msg_g[] = {
	"Usage: g[wcilper]", "[arg]", "Go compile shellcodes",
	"g", " foo.r", "Compile r_egg source file",
	"gw", "", "Compile and write",
	"gc", " cmd=/bin/ls", "Set config option for shellcodes and encoders",
	"gc", "", "List all config options",
	"gl", "", "List plugins (shellcodes, encoders)",
	"gs", " name args", "Compile syscall name(args)",
	"gi", " exec", "Compile shellcode. like ragg2 -i",
	"gp", " padding", "Define padding for command",
	"ge", " xor", "Specify an encoder",
	"gr", "", "Reset r_egg",
	"EVAL VARS:", "", "asm.arch, asm.bits, asm.os",
	NULL
};

// CMD_EVAL

const char* help_msg_e[] = {
	"Usage: e[?]", "[var[=value]]", "Evaluable variables",
	"e","?asm.bytes", "Show description",
	"e", "??", "List config vars with description",
	"e", "", "List config vars",
	"e-", "", "Reset config vars",
	"e*", "", "Dump config vars in r commands",
	"e!", "a", "Invert the boolean value of 'a' var",
	"ee", "var", "Open editor to change the value of var",
	"er", " [key]", "Set config key as readonly. no way back",
	"ec", " [k] [color]", "Set color for given key (prompt, offset, ...)",
	"et", " [key]", "Show type of given config variable",
	"e", " a", "Get value of var 'a'",
	"e", " a=b", "Set var 'a' the 'b' value",
	"env", " [k[=v]]", "Get/set environment variable",
	NULL
};

const char *help_msg_ec[] = {
	"Usage: ec[s?]", "[key][[=| ]fg] [bg]", "Color configuration",
	"ec", "", "List all color keys",
	"ec*", "", "Same as above, but using r2 commands",
	"ecd", "", "Set default palette",
	"ecr", "", "Set random palette",
	"ecs", "", "Show a colorful palette",
	"ecj", "", "Show palette in JSON",
	"ecc", " [prefix]", "Show palette in CSS",
	"eco", " dark|white", "Load white color scheme template",
	"ecp", "", "Load previous color theme",
	"ecn", "", "Load next color theme",
	"ec", " prompt red", "Change color of prompt",
	"ec", " prompt red blue", "Change color and background of prompt",
	"", "", "",
	"colors:", "", "rgb:000, red, green, blue, ...",
	"e scr.rgbcolor", "=1|0", "for 256 color cube (boolean)",
	"e scr.truecolor", "=1|0", "for 256*256*256 colors (boolean)",
	"$DATADIR/radare2/cons","","~/.config/radare2/cons ./",
	NULL
};

const char *help_msg_et[] = {
	"Usage: et", "[varname]", "Show type of eval var",
	NULL
};

// CMD_FLAG

const char *help_msg_f[] = {
	"Usage: f[?]","[flagname]", "Manage offset-name flags",
	"f","","List flags (will only list flags from selected flagspaces)",
	"f."," [*[*]]","List local per-function flags (*) as r2 commands",
	"f.","blah=$$+12","Set local function label named 'blah'",
	"f*","","List flags in r commands",
	"f"," name 12 @ 33","Set flag 'name' with length 12 at offset 33",
	"f"," name = 33","Alias for 'f name @ 33' or 'f name 1 33'",
	"f"," name 12 33 [cmt]","Same as above + optional comment",
	"f-",".blah@fcn.foo","Delete local label from function at current seek (also f.-)",
	"f--","","Delete all flags and flagspaces (deinit)",
	"f+","name 12 @ 33","Like above but creates new one if doesnt exist",
	"f-","name","Remove flag 'name'",
	"f-","@addr","Remove flag at address expression",
	"f."," fname","List all local labels for the given function",
	"fa"," [name] [alias]","Alias a flag to evaluate an expression",
	"fb"," [addr]","Set base address for new flags",
	"fb"," [addr] [flag*]","Move flags matching 'flag' to relative addr",
	"fc"," [name] [color]","Set color for given flag",
	"fC"," [name] [cmt]","Set comment for given flag",
	"fd"," addr","Return flag+delta",
	"fe-","","Resets the enumerator counter",
	"fe"," [name]","Create flag name.#num# enumerated flag. See fe?",
	"fi"," [size] | [from] [to]","Show flags in current block or range",
	"fg","","Bring visual mode to foreground",
	"fj","","List flags in JSON format",
	"fl"," [flag] [size]","Show or set flag length (size)",
	"fm"," addr","Move flag at current offset to new address",
	"fn","","List flags displaying the real name (demangled)",
	"fo","","Show fortunes",
	//" fc [name] [cmt]  ; set execution command for a specific flag"
	"fr"," [old] [[new]]","Rename flag (if no new flag current seek one is used)",
	"fR"," [f] [t] [m]","Relocate all flags matching f&~m 'f'rom, 't'o, 'm'ask",
	"fs"," ?+-*","Manage flagspaces",
	"fS","[on]","Sort flags by offset or name",
	"fx","[d]","Show hexdump (or disasm) of flag:flagsize",
	NULL
};

const char *help_msg_fb[] = {
	"Usage: fb", "[addr] [[flags*]]", "",
	NULL
};

const char *help_msg_fc[] = {
	"Usage: fc", "[flagname] [color]", "List colors with 'ecs'",
	"fc", " flagname", "Get current color for given flagname",
	"fc", " flagname color", "Set color to a flag",
	NULL
};

const char *help_msg_fC[] = {
	"Usage: fC", " [name] [comment]", "Set comment for given flag",
	NULL
};

const char *help_msg_fd[] = {
	"Usage: fd", " [offset|flag|expression]", "Return flag+delta",
	NULL
};

const char *help_msg_fe[] = {
	"Usage: fe", "[-| name] @@= 1 2 3 4", "",
	NULL
};

const char *help_msg_fequals[] = {
	"Usage: f= or f== to display flag bars", "", "",
	NULL
};

const char *help_msg_fR[] = {
	"Usage: fR", "[from] [to] ([mask])", "",
	"\nExample: Relocate PIE flags on debugger", "", "",
	" fR entyr0 `dm~:1[1]`", "", "",
	NULL
};

const char *help_msg_fs[] = {
	"Usage: fs[mr*+-]","[flagspace|addr]", "Manage flagspaces",
	"fs","","Display flagspaces",
	"fs"," *","Select all flagspaces",
	"fs"," flagspace","Select flagspace or create if it doesn't exist",
	"fs","-flagspace","Remove flagspace",
	"fs","-*","Remove all flagspaces",
	"fs","+foo","Push previous flagspace and set",
	"fs","-","Pop to the previous flagspace",
	"fs","-.","Remove the current flagspace",
	"fsm"," [addr]","Move flags at given address to the current flagspace",
	"fsr"," newname","Rename selected flagspace",
	NULL
};

const char *help_msg_fV[] = {
	"Usage: fV[+-]", "[nkey] [offset]", "Dump/Restore visual marks (mK/'K)",
	NULL
};

// CMD_HASH

const char *help_msg_hash[] = {
	"Usage: #!interpreter", "[args] [<file] [<<eof]","",
	" #", "", "Comment - do nothing",
	" #!","","List all available interpreters",
	" #!python","","Run python commandline",
	" #!python"," foo.py","Run foo.py python script (same as '. foo.py')",
	//" #!python <<EOF        get python code until 'EOF' mark\n"
	" #!python"," arg0 a1 <<q","Set arg0 and arg1 and read until 'q'",
	NULL
};

// CMD_HELP
const char *help_msg_colon[] = {
	"Usage: :[plugin]", "[args]", "",
	":", "", "List RCore plugins",
	":java", "", "Run Java plugin",
	NULL
};

const char *help_msg_quev[] = {
	"Usage: ?v[id]", "[val]", "Show value",
	"?vi1 200", "", "1 byte suze value (char)",
	"?vi2 0xffff", "", "2 byte size value (short)",
	"?vi4 0xffff", "", "4 byte size value (int)",
	"?vi8 0xffff", "", "8 byte size value (st64)",
	"No argument shows $? value", "", "",
	"?vi will show in decimal instead of hex", "", "",
	NULL
};

const char *help_msg_at_general[] = {
	"Usage: [.][#][cmd][*]", "[`cmd`] [@ addr] [~grep] [|syscmd] [>[>]file]", "",
	"0", "", "Alias for 's 0'",
	"0x", "addr", "Alias for 's 0x..'",
	"#", "cmd", "If # is a number repeat the command # times",
	"/*", "", "Start multiline comment",
	"*/", "", "End multiline comment",
	".", "cmd", "Execute output of command as r2 script",
	".:", "8080", "Wait for commands on port 8080",
	".!", "rabin2 -re $FILE", "Run command output as r2 script",
	"*", "", "Output of command in r2 script format (CC*)",
	"j", "", "Output of command in JSON format (pdj)",
	"~", "?", "Count number of lines (like wc -l)",
	"~", "??", "Show internal grep help",
	"~", "..", "Internal less",
	"~", "{}", "JSON indent",
	"~", "{}..", "JSON indent and less",
	"~", "word", "Grep for lines matching word",
	"~", "!word", "Grep for lines NOT matching word",
	"~", "word[2]", "Grep 3rd column of lines matching word",
	"~", "word:3[0]", "Grep 1st column from the 4th line matching mov",
	"@", " 0x1024", "Temporary seek to this address (sym.main+3",
	"@", " addr[!blocksize]", "Temporary set a new blocksize",
	"@a:", "arch[:bits]", "Temporary set arch and bits",
	"@b:", "bits", "Temporary set asm.bits",
	"@e:", "k=v,k=v", "Temporary change eval vars",
	"@r:", "reg", "Tmp seek to reg value (f.ex pd@r:PC)",
	"@f:", "file", "Temporary replace block with file contents",
	"@o:", "fd", "Temporary switch to another fd",
	"@s:", "string", "Same as above but from a string",
	"@x:", "909192", "From hex pairs string",
	"@..", "from to", "Temporary set from and to for commands supporting ranges",
	"@@=", "1 2 3", "Run the previous command at offsets 1, 2 and 3",
	"@@", " hit*", "Run the command on every flag matching 'hit*'",
	"@@@", " [type]", "Run a command on every [type] (see @@@? for help)",
	">", "file", "Pipe output of command to file",
	">>", "file", "Append to file",
	"`", "pdi~push:0[0]`", "Replace output of command inside the line",
	"|", "cmd", "Pipe output to command (pd|less) (.dr*)",
	NULL
};

const char *help_msg_dollar_sign[] = {
	"Usage: ?v [$.]","","",
	"$$", "", "Here (current virtual seek)",
	"$?", "", "Last comparison value",
	"$alias", "=value", "Alias commands (simple macros)",
	"$b", "", "Block size",
	"$B", "", "Base address (aligned lowest map address)",
	"$F", "", "Current function size",
	"$FB", "", "Begin of function",
	"$FE", "", "End of function",
	"$FS", "", "Function size",
	"$FI", "", "Function instructions",
	"$c,$r", "", "Get width and height of terminal",
	"$Cn", "", "Get nth call of function",
	"$Dn", "", "Get nth data reference in function",
	"$D", "", "Current debug map base address ?v $D @ rsp",
	"$DD", "", "Current debug map size",
	"$e", "", "1 if end of block, else 0",
	"$f", "", "Jump fail address (e.g. jz 0x10 => next instruction)",
	"$j", "", "Jump address (e.g. jmp 0x10, jz 0x10 => 0x10)",
	"$Ja", "", "Get nth jump of function",
	"$Xn", "", "Get nth xref of function",
	"$l", "", "Opcode length",
	"$m", "", "Opcode memory reference (e.g. mov eax,[0x10] => 0x10)",
	"$M", "", "Map address (lowest map address)",
	"$o", "", "Here (current disk io offset)",
	"$p", "", "Getpid()",
	"$P", "", "PID of children (only in debug)",
	"$s", "", "File size",
	"$S", "", "Section offset",
	"$SS", "", "Section size",
	"$v", "", "Opcode immediate value (e.g. lui a0,0x8010 => 0x8010)",
	"$w", "", "Get word size, 4 if asm.bits=32, 8 if 64, ...",
	"${ev}", "", "Get value of eval config variable",
	"$k{kv}", "", "Get value of an sdb query value",
	"RNum", "", "$variables usable in math expressions",
	NULL
};

const char *help_msg_queV[] = {
	"Usage: ?V[jq]","","",
	"?V", "", "Show version information",
	"?Vj", "", "Same as above but in JSON",
	"?Vq", "", "Quiet mode, just show the version number",
	NULL
};

const char *help_msg_queque[] = {
	"Usage: ?[?[?]] expression", "", "",
	"?", " eip-0x804800", "Show hex and dec result for this math expr",
	"?:", "", "List core cmd plugins",
	"?!", " [cmd]", "? != 0",
	"?+", " [cmd]", "? > 0",
	"?-", " [cmd]", "? < 0",
	"?=", " eip-0x804800", "Hex and dec result for this math expr",
	"??", "", "Show value of operation",
	"??", " [cmd]", "? == 0 run command when math matches",
	"?B", " [elem]", "Show range boundaries like 'e?search.in",
	"?P", " paddr", "Get virtual address for given physical one",
	"?S", " addr", "Return section name of given address",
	"?T", "", "Show loading times",
	"?V", "", "Show library version of r_core",
	"?X", " num|expr", "Returns the hexadecimal value numeric expr",
	"?_", " hudfile", "Load hud menu with given file",
	"?b", " [num]", "Show binary value of number",
	"?b64[-]", " [str]", "Encode/decode in base64",
	"?d[.]", " opcode", "Describe opcode for asm.arch",
	"?e", " string", "Echo string",
	"?f", " [num] [str]", "Map each bit of the number as flag string index",
	"?h", " [str]", "Calculate hash for given string",
	"?i", "[ynmkp] arg", "Prompt for number or Yes,No,Msg,Key,Path and store in $$?",
	"?ik", "", "Press any key input dialog",
	"?im", " message", "Show message centered in screen",
	"?in", " prompt", "No/yes input prompt",
	"?iy", " prompt", "Yes/no input prompt",
	"?l", " str", "Returns the length of string",
	"?o", " num", "Get octal value",
	"?p", " vaddr", "Get physical address for given virtual address",
	"?r", " [from] [to]", "Generate random number between from-to",
	"?s", " from to step", "Sequence of numbers from to by steps",
	"?t", " cmd", "Returns the time to run a command",
	"?u", " num", "Get value in human units (KB, MB, GB, TB)",
	"?v", " eip-0x804800", "Show hex value of math expr",
	"?vi", " rsp-rbp", "Show decimal value of math expr",
	"?x", " num|str|-hexst", "Returns the hexpair of number or string",
	"?y", " [str]", "Show contents of yank buffer, or set with string",
	NULL
};

const char* help_msg_que[] = {
	"Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...", "", "",
	"Append '?' to any char command to get detailed help", "", "",
	"Prefix with number to repeat command N times (f.ex: 3x)", "", "",
	"%var", "=value", "Alias for 'env' command",
	"*", "off[=[0x]value]", "Pointer read/write data/values (see ?v, wx, wv)",
	"(macro arg0 arg1)",  "", "Manage scripting macros",
	".", "[-|(m)|f|!sh|cmd]", "Define macro or load r2, cparse or rlang file",
	"="," [cmd]", "Run this command via rap://",
	"/","", "Search for bytes, regexps, patterns, ..",
	"!"," [cmd]", "Run given command as in system(3)",
	"#"," [algo] [len]", "Calculate hash checksum of current block",
	"#","!lang [..]", "Hashbang to run an rlang script",
	"a","", "Perform analysis of code",
	"b","", "Get or change block size",
	"c"," [arg]", "Compare block with given data",
	"C","", "Code metadata management",
	"d","", "Debugger commands",
	"e"," [a[=b]]", "List/get/set config evaluable vars",
	"f"," [name][sz][at]", "Set flag at current address",
	"g"," [arg]", "Go compile shellcodes with r_egg",
	"i"," [file]", "Get info about opened file",
	"k"," [sdb-query]", "Run sdb-query. see k? for help, 'k *', 'k **' ...",
	"m","", "Mountpoints commands",
	"o"," [file] ([offset])", "Open file at optional address",
	"p"," [len]", "Print current block with format and length",
	"P","", "Project management utilities",
	"q"," [ret]", "Quit program with a return value",
	"r"," [len]", "Resize file",
	"s"," [addr]", "Seek to address (also for '0x', '0x1' == 's 0x1')",
	"S","", "Io section manipulation information",
	"t","", "Cparse types management",
	"T"," [-] [num|msg]", "Text log utility",
	"u","", "uname/undo seek/write",
	"V","", "Enter visual mode (vcmds=visualvisual  keystrokes)",
	"w"," [str]", "Multiple write operations",
	"x"," [len]", "Alias for 'px' (print hexadecimal)",
	"y"," [len] [[[@]addr", "Yank/paste bytes from/to memory",
	"z", "", "Zignatures management",
	"?[??]","[expr]", "Help or evaluate math expression",
	"?$?", "", "Show available '$' variables and aliases",
	"?@?", "", "Misc help for '@' (seek), '~' (grep) (see ~?""?)",
	"?:?", "", "List and manage core plugins",
	NULL
};

// CMD INFO
const char *help_msg_i[] = {
	"Usage: i", "", "Get info from opened file",
	"Output mode:", "", "",
	"'*'", "", "Output in radare commands",
	"'j'", "", "Output in json",
	"'q'", "", "Simple quiet output",
	"Actions:", "", "",
	"i|ij", "", "Show info of current file (in JSON)",
	"iA", "", "List archs",
	"ia", "", "Show all info (imports, exports, sections..)",
	"ib", "", "Reload the current buffer for setting of the bin (use once only)",
	"ic", "", "List classes, methods and fields",
	"iC", "", "Show signature info (entitlements, ...)",
	"id", "", "Debug information (source lines)",
	"iD", " lang sym", "demangle symbolname for given language",
	"ie", "", "Entrypoint",
	"iE", "", "Exports (global symbols)",
	"ih", "", "Headers",
	"ii", "", "Imports",
	"iI", "", "Binary info",
	"ik", " [query]", "Key-value database from RBinObject",
	"il", "", "Libraries",
	"iL", "", "List all RBin plugins loaded",
	"im", "", "Show info about predefined memory allocation",
	"iM", "", "Show main address",
	"io", " [file]", "Load info from file (or last opened) use bin.baddr",
	"ir|iR", "", "Relocs",
	"is", "", "Symbols",
	"iS ", "[entropy,sha1]", "Sections (choose which hash algorithm to use)",
	"iV", "", "Display file version info",
	"iz", "", "Strings in data sections",
	"izz", "", "Search for strings in the whole binary",
	"iZ", "", "Guess size of binary program",
	NULL
};

// CMD_LOG
const char *help_msg_T[] = {
	"Usage:", "T","[-][ num|msg]",
	"T", "", "List all Text log messages",
	"T", " message", "Add new log message",
	"T", " 123", "List log from 123",
	"T", " 10 3", "List 3 log messages starting from 10",
	"T*", "", "List in radare commands",
	"T-", "", "Delete all logs",
	"T-", " 123", "Delete logs before 123",
	"Tl", "", "Get last log message id",
	"Tj", "", "List in json format",
	"Tm", " [idx]", "Display log messages without index",
	"Ts", "", "List files in current directory (see pwd, cd)",
	"Tp", "[-plug]", "Tist, load, unload plugins",
	"TT", "", "Enter into the text log chat console",
	NULL
};

const char *help_msg_Tp[] = {
	"Usage:", "Tp", "[-name][ file]",
	"Tp", "", "List all plugins loaded by RCore.lib",
	"Tp-", "duk", "Unload plugin matching in filename",
	"Tp", " blah."R_LIB_EXT, "Load plugin file",
	NULL
};

// CMD_MACRO
const char *help_msg_paren[] = {
	"Usage:", "(foo args,cmd1,cmd2,..)", "Macro management",
	"(foo args,..,..)", "", "Define a macro named 'foo'",
	"(foo args,..,..)()", "", "Define and call a macro",
	"(-foo)", "", "Remove a macro",
	".(foo)", "", "Call macro named 'foo'",
	"()", "", "Break inside macro",
	"(*", "", "List all defined macros",
	"", "Argument support:", "",
	"(foo x y\\n$0 @ $1)", "", "Define fun with args",
	".(foo 128 0x804800)", "", "Call it with args",
	"", "Iterations:", "",
	".(foo\\n() $@)", "", "Define iterator returning iter index",
	"x @@ .(foo)", "", "Iterate over macros",
	NULL
};

// CMD_META
const char* help_msg_C[] = {
	"Usage: C[-LCvsdfm*?][*?]", "[...]", "Metadata management",
	"C*", "", "List meta info in r2 commands",
	"C-", " [len] [[@]addr]", "Delete metadata at given address range",
	"CL", "[-][*] [file:line] [addr]", "Show or add 'code line' information (bininfo)",
	"CS", "[-][space]", "Manage meta-spaces to filter comments, etc..",
	"CC", "[-] [comment-text] [@addr]", "Add/remove comment",
	"CC!", " [@addr]", "Edit comment with $EDITOR",
	"CCa", "[-at]|[at] [text] [@addr]", "Add/remove comment at given address",
	"CCu", " [comment-text] [@addr]", "Add unique comment",
	"Ca", "[?]", "Add comments to base pointer bases args/vars",
	"Ce", "[?]", "Add comments to stack pointer based args/vars",
	"Cv", "[?]", "Add comments to register based args",
	"Cs", "[-] [size] [@addr]", "Add string",
	"Cz", "[@addr]", "Add zero-terminated string",
	"Ch", "[-] [size] [@addr]", "Hide data",
	"Cd", "[-] [size] [repeat] [@addr]", "Hexdump data array (Cd 4 10 == dword [10])",
	"Cf", "[-] [sz] [fmt..] [@addr]", "Format memory (see pf?)",
	"Cm", "[-] [sz] [fmt..] [@addr]", "Magic parse (see pm?)",
	NULL
};

const char *help_msg_CC[] = {
	"Usage: CC[-+!*au]", "[base64:..|str] @ addr", "",
	"CC", "", "List all comments in human friendly form",
	"CC*", "", "List all comments in r2 commands",
	"CC.", "", "Show comment at current offset",
	"CC,", " [file]", "Show or set comment file",
	"CC", " [comment]", "Append comment at current address",
	"CC+", " [comment]", "Append comment at current address",
	"CC!", "", "Edit comment using cfg.editor (vim, ..)",
	"CC-", " @ cmt_addr", "Remove comment at given address",
	"CCu", " good boy @ addr", "Add 'good boy' comment at given address",
	"CCu", " base64:AA== @ addr", "Add comment in base64",
	NULL
};

const char *help_msg_CS[] = {
	"Usage: CS[*]", "[+-][metaspace|addr]", "Manage metaspaces",
	"CS","","Display metaspaces",
	"CS","*","Select all metaspaces",
	"CS"," metaspace","Select metaspace or create if it doesn't exist",
	"CS","-metaspace","Remove metaspace",
	"CS","-*","Remove all metaspaces",
	"CS","+foo","Push previous metaspace and set",
	"CS","-","Pop to the previous metaspace",
	//	"CSm"," [addr]","move metas at given address to the current metaspace",
	"CSr"," newname","Rename selected metaspace",
	NULL
};

const char *help_msg_Cvb[] = {
	"Usage: Cvb", "[name] [comment]", "",
	"Cvb?", "", "show this help",
	"Cvb", "", "List all base pointer args/vars comments in human friendly format",
	"Cvb*", "", "List all base pointer args/vars comments in r2 format",
	"Cvb-", "[name]", "Delete comments for var/arg at current offset for base pointer",
	"Cvb", "[name]", "Show comments for var/arg at current offset for base pointer",
	"Cvb", "[name] [comment]", "Add/append comment for the variable with the current name",
	"Cvb!", "[name]", "Edit comment using cfg editor",
	NULL
};

const char *help_msg_Cvs[] = {
	"Usage: Cvs", "[name] [comment]", "",
	"Cvs?", "", "Show this help",
	"Cvs", "", "List all stack based args/vars comments in human friendly format",
	"Cvs*", "", "List all stack based args/vars comments in r2 format",
	"Cvs-", "[name]", "Delete comments for stack pointer var/arg with that name",
	"Cvs", "[name]", "Show comments for stack pointer var/arg with that name",
	"Cvs", "[name] [comment]", "Add/append comment for the variable",
	"Cvs!", "[name]", "Edit comment using cfg editor",
	NULL
};

const char *help_msg_Cvr[] = {
	"Usage: Cvr", "[name] [comment]", "",
	"Cvr?", "", "Show this help",
	"Cvr", "", "List all register based args comments in human friendly format",
	"Cvr*", "", "List all register based args comments in r2 format",
	"Cvr-", "[name]", "Delete comments for register based arg for that name",
	"Cvr", "[name]", "Show comments for register based arg for that name",
	"Cvr", "[name] [comment]", "Add/append comment for the variable",
	"Cvr!", "[name]", "Edit comment using cfg editor",
	NULL
};

// CMD_MOUNT

const char* help_msg_m[] = {
	"Usage: m[-?*dgy]", "[...]", "Mountpoints management",
	"m", "", "List all mountpoints in human readable format",
	"m*", "", "Same as above, but in r2 commands",
	"ml", "", "List filesystem plugins",
	"m", " /mnt", "Mount fs at /mnt with autodetect fs and current offset",
	"m", " /mnt ext2 0", "Mount ext2 fs at /mnt with delta 0 on IO",
	"m-/", "", "Umount given path (/)",
	"my", "", "Yank contents of file into clipboard",
	"mo", " /foo", "Get offset and size of given file",
	"mg", " /foo", "Get contents of file/dir dumped to disk (XXX?)",
	"mf", "[o|n]", "Search files for given filename or for offset",
	"md", " /", "List directory contents for path",
	"mp", "", "List all supported partition types",
	"mp", " msdos 0", "Show partitions in msdos format at offset 0",
	"ms", " /mnt", "Open filesystem prompt at /mnt",
	NULL
};

const char *help_msg_mf[] = {
	"Usage: mf", "[no] [...]", "",
	"mfn /foo *.c", "", "Search files by name in /foo path",
	"mfn /foo 0x5e91", "", "Search files by offset in /foo path",
	NULL
};

// CMD_OPEN

const char *help_msg_o[] = {
	"Usage: o[com-]","[file] ([offset])","File management commands",
	"o","","List opened files",
	"o*","","List opened files in r2 commands",
	"oa"," [addr]","Open bin info from the given address",
	"ob","[lbdos] [...]","List open binary files backed by fd",
	"ob"," 4","Prioritize io and fd on 4 (bring to binfile to front)",
	"oc"," [file]","Open core file, like relaunching r2",
	"oj","","List opened files in JSON format",
	"oL","","List all IO plugins registered",
	"om","[?]","Create, list, remove IO maps",
	"on"," [file] 0x4000","Map raw file at 0x4000 (no r_bin involved)",
	"oo","","Reopen current file (kill+fork in debugger)",
	"oo","+","Reopen current file in read-write",
	"ood"," [args]","Reopen in debugger mode (with args)",
	"op"," ["R_LIB_EXT"]","Open r2 native plugin (asm, bin, core, ..)",
	"o"," 4","Priorize io on fd 4 (bring to front)",
	"o","-1","Close file descriptor 1",
	"o-","*","Close all opened files",
	"o--","","Close all files, analysis, binfiles, flags, same as !r2 --",
	"o"," [file]","Open [file] file in read-only",
	"o","+[file]","Open file in read-write mode",
	"o"," [file] 0x4000","Map file at 0x4000",
	NULL
};

const char *help_msg_oa[] = {
	"Usage:", "oa [addr]", "",
	"oa", " [addr]", "Open bin info from the given address",
	NULL
};

const char* help_msg_ob[] = {
	"Usage:", "ob", " # List open binary files backed by fd",
	"ob", "", "List opened binfiles and bin objects",
	"ob", " [fd # bobj #]", "Prioritize by fd number and object number",
	"obb", " [fd #]", "Prioritize by fd number with current selected object",
	"ob-", " [fd #]", "Delete binfile by fd",
	"obd", " [binobject #]", "Delete binfile object numbers, if more than 1 object is loaded",
	"obo", " [binobject #]", "Prioritize by bin object number",
	NULL
};

const char *help_msg_oc[] = {
	"Usage: oc","[file]","Open core file, like relaunching r2",
	NULL
};

const char *help_msg_oj[] = {
	"Usage: oj", "[~{}]", "Use ~{} to indent the JSON",
	"oj", "", "List opened files in JSON format",
	NULL
};

const char* help_msg_om[] = {
	"Usage: om[-]", "[arg]", "Map opened files",
	"om", "", "List all defined IO maps",
	"om", "-0x10000", "Remove the map at given address",
	"om", " fd addr [size]", "Create new io map",
	"omr", " fd|0xADDR ADDR", "Relocate current map",
	"om*", "", "Show r2 commands to restore mapaddr",
	NULL
};

const char* help_msg_oo[] = {
	"Usage: oo[-]", "[arg]", "Map opened files",
	"oo", "", "Reopen current file",
	"oo+", "", "Reopen in read-write",
	"oob", "", "Reopen loading rbin info",
	"ood", "", "Reopen in debug mode",
	"oon", "", "Reopen without loading rbin info",
	"oon+", "", "Reopen in read-write mode without loading rbin info",
	"oonn", "", "Reopen without loading rbin info, but with header flags",
	"oonn+", "", "Reopen in read-write mode without loading rbin info, but with",
	NULL
};

const char *help_msg_oob[] = {
	"Usage: oob", "", "Reopen loading rbin info",
	NULL
};

const char *help_msg_ood[] = {
	"Usage: ood"," [args]","Reopen in debugger mode (with args)",
	NULL
};

const char *help_msg_oon[] = {
	"Usage: oon", "", "Reopen without loading rbin info",
	NULL
};

const char *help_msg_oonn[] = {
	"Usage: oonn", "", "Reopen without loading rbin info, but with header flags",
	NULL
};

const char *help_msg_ostar[] = {
	"Usage: o*", "[> files.r2]", "",
	"o*", "", "List opened files in r2 commands",
	NULL
};

const char *help_msg_ooplus[] = {
	"Usage: oo+", "", "Reopen in read-write",
	NULL
};

// CMD_PRINT

const char *help_msg_p[] = {
	"Usage:", "p[=68abcdDfiImrstuxz] [arg|len] [@addr]", "",
	"p=","[bep?] [blks] [len] [blk]","Show entropy/printable chars/chars bars",
	"p2"," [N]","8x8 2bpp-tiles",
	"p3"," [file]","Print stereogram (3D)",
	"p6","[de] [N]", "base64 decode/encode",
	"p8","[j] [N]","8bit hexpair list of bytes",
	"pa","[edD] [arg]", "pa:assemble  pa[dD]:disasm or pae: ESIL from hexpairs",
	"pA","[n_ops]", "Show n_ops address and type",
	"p","[b|B|xb] [N] ([skip])", "Bindump N bits skipping M",
	"p","[bB] [N]","Bitstream of N bytes",
	"pc","[p] [N]","Output C (or python) format",
	"p","[dD][?] [N] [a] [b]","Disassemble N opcodes/bytes for arch/bits (see pd?)",
	"pf","[?|.nam] [fmt]","Print formatted data (pf.name, pf.name $<expr>)",
	"ph","[?=|hash] ([len])","Calculate hash for a block",
	"p","[iI][df] [N]", "Print N ops/bytes (f=func) (see pi? and pdi)",
	"pm"," [magic]","Print libmagic data (see pm? and /m?)",
	"pr","[glx] [N]","Print N raw bytes (in lines or hexblocks, 'g'unzip)",
	"p","[kK] [N]","Print key in randomart (K is for mosaic)",
	"ps","[pwz] [N]","Print pascal/wide/zero-terminated strings",
	"pt","[dn?] [N]","Print different timestamps",
	"pu","[w] [N]","Print N url encoded bytes (w=wide)",
	"pv","[jh] [mode]","Show variable/pointer/value in memory",
	"p-","[jh] [mode]","Bar|JSON|histogram blocks (mode: e?search.in)",
	"px","[owq] [N]","Hexdump of N bytes (o=octal, w=32bit, q=64bit)",
	"pz"," [N]","Print zoom view (see pz? for help)",
	"pwd","","Display current working directory",
	NULL
};

const char *help_msg_p2[] = {
	"Usage: p2", "[N]", "N is the number of bytes represeting tiles",
	"NOTE: Only full tiles will be printed", "", "",
	NULL
};

const char *help_msg_p3[] = {
	"Usage: p3", "[file]", "Print 3D stereogram image of current block",
	NULL
};

const char *help_msg_p6d[] = {
	"Usage: p6d", "[N]", "base64 decode",
	NULL
};

const char *help_msg_p6e[] = {
	"Usage: p6e", "[N]", "base64 encode",
	NULL
};

const char *help_msg_p6ed[] = {
	"Usage: p6[ed]", "[N]", "base64 encode/decode",
	NULL
};

const char *help_msg_p8[] = {
	"Usage: p8[fj]", "[N]", "8bit hexpair list of bytes (see pcj)",
	NULL
};

const char *help_msg_pad[] = {
	"Usage: pad", "[hex]", "Diassemble",
	NULL
};

const char *help_msg_pae[] = {
	"Usage: pae", "[hex]", "Assemble from hexpairs",
	NULL
};

const char *help_msg_paed[] = {
	"Usage: pa[ed]", "[hex|asm]", "Assemble/Disassemble (ESIL - pae) from hexpairs",
	NULL
};

const char *help_msg_paD[] = {
	"Usage: paD", "[hex]", "Disasm like in pdi",
	NULL
};

const char *help_msg_pb[] = {
	"Usage: p[bB]", "[N] ([skip])", "See also pB and pxb",
	NULL
};

const char *help_msg_pB[] = {
	"Usage: p[bB]", "[N]", "Bitstream of N bytes",
	NULL
};

const char* help_msg_pd[] = {
	"Usage: p[dD][ajbrfils]", "[N] [arch] [bits]", "Print disassembly",
	"NOTE: ", "N", "Parameter can be negative",
	"NOTE: ", "", "Pressing ENTER on empty command will repeat last pd command and also seek to end of disassembled range.",
	"pd", " N", "Disassemble N instructions",
	"pd", " -N", "Disassemble N instructions backward",
	"pD", " N", "Disassemble N bytes",
	"pda", "", "Disassemble all possible opcodes (byte per byte)",
	"pdb", "", "Disassemble basic block",
	"pdc", "", "Pseudo disassembler output in C-like syntax",
	"pdj", "", "Disassemble to json",
	"pdr", "", "Recursive disassemble across the function graph",
	"pdf", "", "Disassemble function",
	"pdi", "", "Like 'pi', with offset and bytes",
	"pdl", "", "Show instruction sizes",
	//"pds", "", "disassemble with back sweep (greedy disassembly backwards)",
	"pds", "", "Disassemble summary (strings, calls, jumps, refs) (see pdsf and pdfs)",
	"pdt", "", "Disassemble the debugger traces (see atd)",
	NULL
};

const char *help_msg_pdfs[] = {
	"Usage: pdf[sj]", "", "Disassemble function (summary + cjmp), JSON",
	NULL
};

const char *help_msg_pds[] = {
	"Usage: pds[f]", "[N]", "Summarize N bytes of function (pdfs)",
	NULL
};

const char *help_msg_pf[] = {
	"Usage: pf[.k[.f[=v]]|[v]]|[n]|[0]", "[[size] fmt] [a0 a1 ...]", "Print formatted data",
	"Commands:","","",
	"pf", "?", "Show this help",
	"pf", "??", "Format characters",
	"pf", "???", "pf usage examples",
	"pf", " xsi foo bar cow", "Format named hex str and int (see `pf??`)",
	"pf.", "", "List all formats",
	"pf?", "fmt_name", "Show format of that stored one",
	"pfs", " fmt_name", "Print the size of the format in bytes",
	"pfo", "", "List all format files",
	"pfo", " elf32", "Load the elf32 format definition file",
	"pf.", "fmt_name", "Run stored format",
	"pf.", "fmt_name.field_name", "Show specific field inside format",
	"pf.", "fmt_name.size=33", "Set new value for the size field in obj",
	"pfj.", "fmt_name", "Print format in JSON",
	"pfv.", "fmt_name", "Print the value(s) only. Useful for one-liners",
	"pf*.", "fmt_name", "Display flag commands",
	"pfd.", "fmt_name", "Display graphviz commands",
	NULL
};

const char *help_msg_pfque[] = {
	"Usage: pf[.k[.f[=v]]|[v]]|[n]|[0]", "[[size] fmt] [a0 a1 ...]", "",
	"Format:", "", "",
	" ", "b", "byte (unsigned)",
	" ", "B", "Resolve enum bitfield (see t?)",
	" ", "c", "char (signed byte)",
	" ", "d", "0x%%08x hexadecimal value (4 bytes)",
	" ", "D", "Disassemble one opcode",
	" ", "e", "Temporally swap endian",
	" ", "E", "Resolve enum name (see t?)",
	" ", "f", "float value (4 bytes)",
	" ", "i", "%%i integer value (4 bytes)",
	" ", "o", "0x%%08o octal value (4 byte)",
	" ", "p", "Pointer reference (2, 4 or 8 bytes)",
	" ", "q", "quadword (8 bytes)",
	" ", "r", "CPU register `pf r (eax)plop`",
	" ", "s", "32bit pointer to string (4 bytes)",
	" ", "S", "64bit pointer to string (8 bytes)",
	" ", "t", "UNIX timestamp (4 bytes)",
	" ", "T", "Show ten first bytes of buffer",
	" ", "u", "uleb128 (variable length)",
	" ", "w", "word (2 bytes unsigned short in hex)",
	" ", "x", "0x%%08x hex value and flag (fd @ addr)",
	" ", "X", "Show formatted hexpairs",
	" ", "z", "\\0 terminated string",
	" ", "Z", "\\0 terminated wide string",
	" ", "?", "Data structure `pf ? (struct_name)example_name`",
	" ", "*", "Next char is pointer (honors asm.bits)",
	" ", "+", "Toggle show flags for each offset",
	" ", ":", "Skip 4 bytes",
	" ", ".", "Skip 1 byte",
	NULL
};

const char *help_msg_pfqueque[] = {
	"Usage: pf[.k[.f[=v]]|[v]]|[n]|[0]", "[[size] fmt] [a0 a1 ...]", "",
	"Examples:","","",
	"pf", " B (BitFldType)arg_name`", "bitfield type",
	"pf", " E (EnumType)arg_name`", "enum type",
	"pf.", "obj xxdz prev next size name", "Define the obj format as xxdz",
	"pf",  " obj=xxdz prev next size name", "Same as above",
	"pf", " iwq foo bar troll", "Print the iwq format with foo, bar, troll as the respective names for the fields",
	"pf", " 0iwq foo bar troll", "Same as above, but considered as a union (all fields at offset 0)",
	"pf.", "plop ? (troll)mystruct", "Use structure troll previously defined",
	"pf", " 10xiz pointer length string", "Print a size 10 array of the xiz struct with its field names",
	"pf", " {integer}bifc", "Print integer times the following format (bifc)",
	"pf", " [4]w[7]i", "Print an array of 4 words and then an array of 7 integers",
	NULL
};

const char *help_msg_pfquequeque[] = {
	"    STAHP IT!!!", "", "",
	NULL
};

const char *help_msg_pi[] = {
	"Usage: pi[defj]", "[num]", "",
	NULL
};

const char *help_msg_pI[] = {
	"Usage: p[iI][df]", "[N]", "Print N instructions/bytes (f=func) see pi and pdi",
	NULL
};

const char *help_msg_pk[] = {
	"Usage: pk", "[N]", "Print key in randomart",
	NULL
};

const char *help_msg_pK[] = {
	"Usage: pK", "[N]", "Print key in randomart mosaic",
	NULL
};

const char *help_msg_pm[] = {
	"Usage: pm", "[file|directory]", "",
	" r_magic will use given file/dir as reference", "", "",
	" output of those magic can contain expressions like:", "", "",
	"   foo@0x40", "", "Use 'foo' magic file on address 0x40",
	"   @0x40", "", "Use current magic file on address 0x40",
	"   \\n", "", "Append newline",
	" e dir.magic", "", "defaults to "R_MAGIC_PATH"",
	" /m", "", "Search for magic signatures",
	NULL
};

const char* help_msg_pr[] = {
	"Usage: pr[glx]", " [size]", "",
	"prl", "", "Print raw with lines offsets",
	"prx", "", "Printable chars with real offset (hyew)",
	"prg", "", "Print raw GUNZIPped block",
	"prz", "", "Print raw zero-terminated string",
	NULL
};

const char* help_msg_prg[] = {
	"Usage: prg[io]", "", "",
	"prg", "", "Print gunzipped data of current block",
	"prgi", "", "Show consumed bytes when inflating",
	"prgo", "", "Show output bytes after inflating",
	NULL
};

const char* help_msg_ps[] = {
	"Usage: ps[zpw]", " [N]", "Print string",
	"ps", "", "Print string",
	"psi", "", "Print string inside curseek",
	"psb", "", "Print strings in current block",
	"psx", "", "Show string with scaped chars",
	"psz", "", "Print zero terminated string",
	"psp", "", "Print pascal string",
	"psu", "", "Print utf16 unicode (json)",
	"psw", "", "Print wide string",
	"psj", "", "Print string in JSON format",
	NULL
};

const char* help_msg_pt[] = {
	"Usage: pt[dn]", "", "Print timestamps",
	"pt", "", "Print unix time (32 bit `cfg.bigendian`)",
	"ptd","", "Print dos time (32 bit `cfg.bigendian`)",
	"ptn","", "Print ntfs time (64 bit `cfg.bigendian`)",
	NULL
};

const char *help_msg_pu[] = {
	"Usage: pu[w]", "[N]", "Print N url encoded bytes (w=wide)",
	NULL
};

const char *help_msg_pv[] = {
	 "Usage: pv[j][1,2,4,8,z]", "", "",
	 "pv", "",  "Print bytes based on asm.bits",
	 "pv1", "", "Print 1 byte in memory",
	 "pv2", "", "Print 2 bytes in memory",
	 "pv4", "", "Print 4 bytes in memory",
	 "pv8", "", "Print 8 bytes in memory",
	 "pvz", "", "Print value as string (alias for ps)",
	 NULL
};

const char* help_msg_px[] = {
	"Usage: px[afoswqWqQ][f]", "", "Print hexadecimal",
	"px",  "", "Show hexdump",
	"px/", "", "Same as x/ in gdb (help x)",
	"pxa", "", "Show annotated hexdump",
	"pxA", "", "Show op analysis color map",
	"pxb", "", "Dump bits in hexdump form",
	"pxd", "[124]", "Signed integer dump (1 byte, 2 and 4)",
	"pxe", "", "Emoji hexdump! :)",
	"pxi", "", "HexII compact binary representation",
	"pxf", "", "Show hexdump of current function",
	"pxh", "", "Show hexadecimal half-words dump (16bit)",
	"pxH", "", "Same as above, but one per line",
	"pxl", "", "Display N lines (rows) of hexdump",
	"pxo", "", "Show octal dump",
	"pxq", "", "Show hexadecimal quad-words dump (64bit)",
	"pxQ", "", "Same as above, but one per line",
	"pxr", "[j]", "Show words with references to flags and code",
	"pxs", "", "Show hexadecimal in sparse mode",
	"pxt", "[*.] [origin]", "Show delta pointer table in r2 commands",
	"pxw", "", "Show hexadecimal words dump (32bit)",
	"pxW", "", "Same as above, but one per line",
	NULL
};

const char *help_msg_pxA[] = {
	"Usage: pxA", "[N]", "Print op analysis colormap",
	"Legend:", "", "",
	" mv", "", "move,lea,li",
	" ->", "", "push",
	" <-", "", "pop",
	" io", "", "in/out ops",
	" $$", "", "int/swi/trap/new",
	" ..", "", "nop",
	" +-*/", "", "math ops",
	" |&^", "", "bin ops",
	" <<>>", "", "shift ops",
	" _J", "", "jump",
	" cJ", "", "conditional jump",
	" _C", "", "call",
	" _R", "", "ret",
	" ==", "", "cmp/test",
	" XX", "", "invalid",
    NULL
};

const char *help_msg_pxt[] = {
	"Usage: pxt[.*]", "", "Print delta pointer table",
	NULL
};

const char *help_msg_pz[] = {
	"Usage: pz", "[N]", "Print zoomed blocks (filesize/N)",
	"e ","zoom.maxsz","Max size of block",
	"e ","zoom.from","Start address",
	"e ","zoom.to","End address",
	"e ","zoom.byte","Specify how to calculate each byte",
	"pzp","","Number of printable chars",
	"pzf","","Count of flags in block",
	"pzs","","Strings in range",
	"pz0","","Number of bytes with value '0'",
	"pzF","","Number of bytes with value 0xFF",
	"pze","","Calculate entropy and expand to 0-255 range",
	"pzh","","Head (first byte value); This is the default mode",
	//"WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
	NULL
};

const char *help_msg_pequals[] = {
	"Usage: p=[bep?][qj]", "[num-of-blocks] ([len]) ([block-offset]) ", "Show entropy/printable chars/chars bars",
	"p=", "", "Print bytes of current block in bars",
	"p=", "b", "Same as above",
	"p=", "d", "Print different bytes from block",
	"p=", "e", "Print entropy for each filesize/blocksize",
	"p=", "p", "Print number of printable bytes for each filesize/blocksize",
	NULL
};

const char *help_msg_pminus[] = {
	"Usage: p-[jh]", "[pieces]", "Bar|JSON|histogram blocks",
	"p-", "", "Show ascii-art bar of metadata in file boundaries",
	"p-j", "", "Show JSON format",
	"p-h", "", "Show histogram analysis of metadata per block",
	NULL
};

// CMD_PROJECT
const char* help_msg_P[] = {
	"Usage: P[?osi]", "[file]", "Project management",
	"Pc", " [file]", "Show project script to console",
	"Pd", " [file]", "Delete project",
	"Pi", " [file]", "Show project information",
	"Pl", "", "List all projects",
	"Pn", "[j]", "Show project notes (Pnj for json)",
	"Pn", " [base64]", "Set notes text",
	"Pn", " -", "Edit notes with cfg.editor",
	"Po", " [file]", "Open project",
	"Ps", " [file]", "Save project",
	"PS", " [file]", "Save script file",
	"NOTE:", "", "See 'e file.project'",
	"NOTE:", "", "Project files are stored in ~/.config/radare2/projects",
	NULL
};

const char *help_msg_Pc[] = {
	"Usage: Pc", "[prjname]", "",
	NULL
};

const char *help_msg_PS[] = {
	"Usage: PS", "[file]", "",
	NULL
};

const char* help_msg_Pn[] = {
	"Usage: Pn[j-?]", "[...]", "Project notes",
	"Pn", "", "Show project notes",
	"Pn", " -", "Edit notes with cfg.editor",
	"Pn-", "", "Delete notes",
	"Pn-", "str", "Delete lines matching /str/ in notes",
	"Pnj", "", "Show notes in base64",
	"Pnj", " [base64]", "Set notes in base64",
	NULL
};

const char *help_msg_Pnj[] = {
	"Usage: Pnj", "[base64]", "Show or save notes in base64",
	NULL
};

// CMD_QUIT

const char *help_msg_q[] = {
	"Usage: q[!][!]",  "[retval]", "Quit commands",
	"q","","Quit program",
	"q!","","Force quit (no questions)",
	"q!!","","Force quit without saving history",
	"q"," 1","Quit with return value 1",
	"q"," a-b","Quit with return value a-b",
	"q[y/n][y/n]","","Quit, auto-yes to kill process, auto-yes to save project ",
	NULL
};

// CMD_SEARCH
const char* help_msg_slash[] = {
	"Usage: /[amx/]", "[arg]", "Search commands (see 'e??search' for options)",
	"/"," foo\\x00", "Search for string 'foo\\0'",
	"/j"," foo\\x00", "Search for string 'foo\\0' (json output)",
	"/!", " ff", "Search for first occurrence not matching",
	"/+", " /bin/sh", "Construct the string with chunks",
	"/!x", " 00", "Inverse hexa search (find first byte != 0x00)",
	"//", "", "Repeat last search",
	"/h", "[t] [hash] [len]", "Find block matching this hash. See /#?",
	"/a", " jmp eax", "Assemble opcode and search its bytes",
	"/A", " jmp", "Find analyzed instructions of this type (/A? for help)",
	"/b", "", "Search backwards",
	"/B", "", "Search recognized RBin headers",
	"/c", " jmp [esp]", "Search for asm code",
	"/C", "[ar]", "Search for crypto materials",
	"/d", " 101112", "Search for a deltified sequence of bytes",
	"/e", " /E.F/i", "Match regular expression",
	"/E", " esil-expr", "Offset matching given esil expressions %%= here ",
	"/i", " foo", "Search for string 'foo' ignoring case",
	"/m", " magicfile", "Search for matching magic file (use blocksize)",
	"/p", " patternsize", "Search for pattern of given size",
	"/P", "", "Show offset of previous instruction",
	"/r", " sym.printf", "Analyze opcode reference an offset",
	"/R", " [grepopcode]", "Search for matching ROP gadgets, semicolon-separated",
	"/v", "[1248] value", "Look for an `asm.bigendian` 32bit value",
	"/V", "[1248] min max", "Look for an `asm.bigendian` 32bit value in range",
	"/w", " foo", "Search for wide string 'f\\0o\\0o\\0'",
	"/wi", " foo", "Search for wide string ignoring case 'f\\0o\\0o\\0'",
	"/x"," ff..33", "Search for hex string ignoring some nibbles",
	"/x"," ff0033", "Search for hex string",
	"/x"," ff43 ffd0", "Search for hexpair with mask",
	"/z"," min max", "Search for strings of given size",
#if 0
	"\nConfiguration:", "", " (type `e??search.` for a complete list)",
	"e", " cmd.hit = x", "command to execute on every search hit",
	"e", " search.in = ?", "specify where to search stuff (depends on .from/.to)",
	"e", " search.align = 4", "only catch aligned search hits",
	"e", " search.from = 0", "start address",
	"e", " search.to = 0", "end address",
	"e", " search.flags = true", "if enabled store flags on keyword hits",
#endif
	NULL
};

const char *help_msg_slashb[] = {
	"Usage: /b[command]", "[value]", "Backward search, see '/?'",
	NULL
};

const char* help_msg_slashc[] = {
	"Usage: /c", "[instr]", "Search for asm",
	"/c ", "instr", "Search for instruction 'instr'",
	"/c/ ", "instr", "Search for instruction that matches regexp 'instr'",
	"/c ", "instr1;instr2", "Search for instruction 'instr1' followed by 'instr2'",
	"/c/ ", "instr1;instr2", "Search for regex instruction 'instr1' followed by regex 'instr2'",
	"/cj ", "instr", "JSON output",
	"/c/j ", "instr", "Regex search with JSON output",
	"/c* ", "instr", "r2 command output",
	NULL
};

const char *help_msg_slashC[] = {
	"Usage: /C", "", "Search for crypto materials",
	"/Ca", "" , "Search for AES keys",
	"/Cr", "", "Search for private RSA keys",
	NULL
};

const char *help_msg_slashR[] = {
	"Usage: /R", "", "Search for ROP gadgets",
	"/R", " [filter-by-string]" , "Show gadgets",
	"/R/", " [filter-by-regexp]" , "Show gadgets [regular expression]",
	"/Rl", " [filter-by-string]" , "Show gadgets in a linear manner",
	"/R/l", " [filter-by-regexp]" , "Show gadgets in a linear manner [regular expression]",
	"/Rj", " [filter-by-string]", "JSON output",
	"/R/j", " [filter-by-regexp]", "JSON output [regular expression]",
	NULL
};

const char* help_msg_slashx[] = {
	"Usage: /x", "[hexpairs]:[binmask]", "Search in memory",
	"/x ", "9090cd80", "search for those bytes",
	"/x ", "9090cd80:ffff7ff0", "search with binary mask",
	NULL
};

// CMD_SECTION

const char* help_msg_S[] = {
	"Usage: S[?-.*=adlr]","[...]","Section-related commands",
	"S","","List sections",
	"S.","","Show current section name",
	"S*","","List sections (in radare commands)",
	"S=","","List sections (ascii-art bars) (io.va to display paddr or vaddr)",
	"Sa","[-] [A] [B] [[off]]","Specify arch and bits for given section",
	"Sd[a]"," [file]","Dump current (all) section to a file (see dmd)",
	"Sl"," [file]","Load contents of file into current section (see dml)",
	"Sj","","List sections in JSON (alias for iSj)",
	"Sr"," [name]","Rename section on current seek",
	"S"," off va sz vsz name mrwx","Add new section (if(!vsz)vsz=sz)",
	"S-","[id|0xoff|*]","Remove this section definition",
	NULL
};

// CMD_SEEK

const char *help_msg_s[] = {
	"Usage: s", "", "Seek commands",
	"s", "", "Print current address",
	"s", " addr", "Seek to address",
	"s-", "", "Undo seek",
	"s-", " n", "Seek n bytes backward",
	"s--", "", "Seek blocksize bytes backward",
	"s+", "", "Redo seek",
	"s+", " n", "Seek n bytes forward",
	"s++", "", "Seek blocksize bytes forward",
	"s[j*=]", "", "List undo seek history (JSON, =list, *r2)",
	"s/", " DATA", "Search for next occurrence of 'DATA'",
	"s/x", " 9091", "Search for next occurrence of \\x90\\x91",
	"s.", "hexoff", "Seek honoring a base from core->offset",
	"sa", " [[+-]a] [asz]", "Seek asz (or bsize) aligned to addr",
	"sb", "", "Seek aligned to bb start",
	"sC", " string", "Seek to comment matching given string",
	"sf", "", "Seek to next function (f->addr+f->size)",
	"sf", " function", "Seek to address of specified function",
	"sg/sG", "", "Seek begin (sg) or end (sG) of section or file",
	"sl", "[+-]line", "Seek to line",
	"sn/sp", "", "Seek next/prev scr.nkey",
	"so", " [N]", "Seek to N next opcode(s)",
	"sr", " pc", "Seek to register",
	//"sp [page]  seek page N (page = block)",
	NULL
};

const char *help_msg_sC[] = {
	"Usage: sC[?*]", "", "Comment grep",
	"sC*", "", "List all comments",
	"sC", " [const]", "Seek to comment matching [const]",
	NULL
};
const char *help_msg_sl[] = {
	"Usage: sl[c+-]", "", "",
	"sl", " [line]", "Seek to absolute line",
	"sl", "[+-][line]", "Seek to relative line",
	"slc", "", "Clear line cache",
	"sll", "", "Show total number of lines",
	NULL
};

// CMD_TYPE

const char *help_msg_t[] = {
	"Usage: t", "", "cparse types commands",
	"t", "", "List all loaded types",
	"t", " [type]", "Show type in 'pf' syntax",
	"t*", "", "List types info in r2 commands",
	"t-", " [name]", "Delete types by its name",
	"t-*", "", "Remove all types",
	//"t-!", "",          "Use to open $EDITOR",
	"tb", " [enum] [val]", "Show matching enum bitfield for given number",
	"te", "", "List all loaded enums",
	"te", " [enum] [val]", "Show name for given enum number",
	"td", " [string]", "Load types from string",
	"tf", "", "List all loaded functions signatures",
	"tk", " [sdb-query]", "Perform sdb query",
	"tl", "[?]", "Show/Link type to an address",
	//"to",  "",         "List opened files",
	"to", " -", "Open cfg.editor to load types",
	"to", " [path]", "Load types from C header file",
	"tp", " [type]  = [address]", "cast data at [adress] to [type] and print it",
	"ts", "", "print loaded struct types",
	"tu", "", "print loaded union types",
	//"| ts k=v k=v @ link.addr set fields at given linked type\n"
	NULL
};

const char *help_msg_td[] = {
	"Usage: \"td", "[...]\"", "",
	"td", "[string]", "Load types from string",
	"NOTE: The td command should be put between double quotes", "", "",
	"Example: \" td struct foo {int bar; int cow};\"", "", "",
	NULL
};

const char *help_msg_te[] = {
	"USAGE te[...]", "", "",
	"te", "", "List all loaded enums",
	"te", " [enum] [val]", "Show name for given enum number",
	"te?", "", "Show this help",
	NULL
};

const char *help_msg_tl[] = {
	"Usage: tl[s-*?]", "", "",
	"tl", "", "List all links in readable format",
	"tl", "[typename]", "Link a type to current adress.",
	"tl", "[typename] = [address]", "Link type to given address.",
	"tls", "[address]", "Show link at given address",
	"tl-*", "", "Delete all links.",
	"tl-", "[address]", "Delete link at given address.",
	"tl*", "", "List all links in radare2 command format",
	"tl?", "", "Print this help.",
	NULL
};

const char *help_msg_ts[] = {
	"Usage: ts[?]", "", "",
	"ts", "", "List all loaded structs",
	"ts?", "", "Show this help",
	NULL
};

const char *help_msg_tu[] = {
	"Usage: tu[?]", "", "",
	"tu", "", "List all loaded unions",
	"tu?", "", "Show this help",
	NULL
};

const char *help_msg_tminus[] = {
	"Usage: t-", "[type]", "Delete type by its name",
	NULL
};
// CMD_WRITE

const char* help_msg_w[] = {
	"Usage: w[x]", "[str] [<file] [<<EOF] [@addr]","",
	"w","[1248][+-][n]","Increment/decrement byte,word..",
	"w"," foobar","Write string 'foobar'",
	"w0"," [len]","Write 'len' bytes with value 0x00",
	"w6","[de] base64/hex","Write base64 [d]ecoded or [e]ncoded string",
	"wa"," push ebp","Write opcode, separated by ';' (use '\"' around the command)",
	"waf"," file","Assemble file and write bytes",
	"wao"," op","Modify opcode (change conditional of jump. nop, etc)",
	"wA"," r 0","Alter/modify opcode at current seek (see wA?)",
	"wb"," 010203","Fill current block with cyclic hexpairs",
	"wB","[-]0xVALUE","Set or unset bits with given value",
	"wc","","List all write changes",
	"wc","[ir*?]","Write cache undo/commit/reset/list (io.cache)",
	"wd"," [off] [n]","Duplicate N bytes from offset at current seek (memcpy) (see y?)",
	"we","[nNsxX] [arg]","Extend write operations (insert instead of replace)",
	"wf"," -|file","Write contents of file at current offset",
	"wh"," r2","Whereis/which shell command",
	"wm"," f0ff","Set binary mask hexpair to be used as cyclic write mask",
	"wo?"," hex","Write in block with operation. 'wo?' fmi",
	"wp"," -|file","Apply radare patch file. See wp? fmi",
	"wr"," 10","Write 10 random bytes",
	"ws"," pstring","Write 1 byte for length and then the string",
	"wt"," file [sz]","Write to file (from current seek, blocksize or sz bytes)",
	"ww"," foobar","Write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'",
	"wx[fs]"," 9090","Write two intel nops (from wxfile or wxseek)",
	"wv"," eip+34","Write 32-64 bit value",
	"wz"," string","Write zero terminated string (like w + \\x00)",
	NULL
};

const char* help_msg_wa[] = {
	"Usage: Wa[of*]", "[arg]", "",
	"wa", " nop", "Write nopcode using asm.arch and asm.bits",
	"wa*", " mov eax, 33", "Show 'wx' op with hexpair bytes of assembled opcode",
	"\"wa nop;nop\"", "" , "Assemble more than one instruction (note the quotes)",
	"waf", "foo.asm" , "Assemble file and write bytes",
	"wao?", "", "Show help for assembler operation on current opcode (hack)",
	NULL
};

const char* help_msg_wA[] = {
	"Usage: wA", "[type] [value]", "",
	"Types:", "", "",
	"r", "", "Raw write value",
	"v", "", "Set value (taking care of current address)",
	"d", "", "Destination register",
	"0", "", "1st src register",
	"1", "", "2nd src register",
	"Example:",  "wA r 0", "# e800000000",
	NULL
};

const char* help_msg_wc[] = {
	"Usage: wc[ir+-*?]", "", "Write cache; NOTE: Uses io.cache=true",
	"wc","","List all write changes",
	"wc-"," [from] [to]","Remove write op at curseek or given addr",
	"wc+"," [addr]","Commit change from cache to io",
	"wc*","","\"\" in radare commands",
	"wcr","","Reset all write changes in cache",
	"wci","","Commit write cache",
	NULL
};

const char *help_msg_wd[] = {
	"Usage: wd", "[src-offset] [length] @ [dest-offset]", "",
	NULL
};

const char* help_msg_we[] = {
	"Usage: we", "", "Write extend",
	"wen", " [num]", "Insert num null bytes at current offset",
	"wex", " [hex_bytes]", "Insert bytes at current offset",
	"weN", " [addr] [len]", "Insert bytes at address",
	"weX", " [addr] [hex]", "Insert bytes at address",
	"wes", " [addr] [dist] [block_size]", "Shift a blocksize left or write in the editor",
	NULL
};

const char* help_msg_wo[] = {
	"Usage: wo[asmdxoArl24]","[hexpairs] @ addr[!bsize]","",
	"wo[aAdlmorwx24]","", "Without hexpair values, clipboard is used",
	"woa"," [val]", "+=  addition (f.ex: woa 0102)",
	"woA"," [val]","&=  and",
	"wod"," [val]", "/=  divide",
	"woD","[algo] [key] [IV]","Decrypt current block with given algo and key",
	"woe"," [from to] [step] [wsz=1]","Create increasing/decreasing sequence",
	"woE"," [algo] [key] [IV]", "Encrypt current block with given algo and key",
	"wol"," [val]", "<<= shift left",
	"wom"," [val]", "*= multiply",
	"woo"," [val]", "|= or",
	"wop[DO]"," [arg]","De Bruijn Patterns",
	"wor"," [val]", ">>= shift right",
	"woR","","Random bytes (alias for 'wr $b')",
	"wos"," [val]", "-= substraction",
	"wow"," [val]", "== write looped value (alias for 'wb')",
	"wox"," [val]", "^= xor  (f.ex: wox 0x90)",
	"wo2"," [val]", "2= 2 byte endian swap",
	"wo4"," [val]", "4= 4 byte endian swap",
	NULL
};

const char* help_msg_wop[] = {
	"Usage: wop[DO]", "[len] [@ addr | value]", "De Bruijin Pattern generation and offset",
	"wopD"," [len] [@ addr]", "Write a De Bruijn Pattern of length 'len' at address 'addr'",
	"wopO"," [value]", "Finds the given value into a De Bruijn Pattern at current offset",
	NULL
};

// TODO rapatch format documentation
const char* help_msg_wp[] = {
	"Usage: wp", "[-|rapatch-file]", "",
	NULL
};

const char* help_msg_wt[] = {
	"Usage: wt[a]", "file [size]", "Write 'size' bytes in current block to file",
	NULL
};

const char* help_msg_wv[] = {
	"Usage: wv[size]", "[val]", "Write value of given size",
	"wv1", " 234", "Write one byte with this value",
	"wv", " 0x834002", "Write dword with this value",
	"Supported sizes are:", "1, 2, 4, 8", "",
	NULL
};

const char* help_msg_wx[] = {
	"Usage: wx[f]", "[hex]", "",
	"wx", " 9090", "Write two intel nops",
	"wxf", " -|file", "Write contents of hexpairs file here",
	"wxs", " 9090", "Write hexpairs and seek at the end",
	NULL
};

// CMD_ZIGN
const char* help_msg_z[] = {
	"Usage: z[abcp/*-]", "[arg]", "Zignatures commands",
	"z", "", "Show status of zignatures",
	"z*", "", "Display all zignatures",
	"z-", " namespace", "Unload zignatures in namespace",
	"z-*", "", "Unload all zignatures",
	"z/", " [ini] [end]", "Search zignatures between these regions",
	"za", " ...", "Define new zignature for analysis",
	"zb", " name bytes", "Define zignature for bytes",
	"zB", " size", "Generate zignatures for current offset/flag",
	"zc", " @ fcn.foo", "Flag signature if matching (.zc@@fcn)",
	"zf", " name fmt", "Define function zignature (fast/slow, args, types)",
	"zF", " file", "Open a FLIRT signature file and scan opened file",
	"zFd", " file", "Dump a FLIRT signature",
	"zg", " namespace [file]", "Generate zignatures for current file",
	"zh", " name bytes", "Define function header zignature",
	"zn", " namespace", "Define namespace for following zignatures (until zn-)",
	"zn", "", "Display current namespace",
	"zn-", "", "Unset namespace",
	"zp", " name bytes", "Define new zignature for function body",
	"NOTE:", "", "bytes can contain '.' (dots) to specify a binary mask",
	NULL
};

/* Prints a coloured help message.
 * help should be an array of the following form:
 * {"command", "args", "description",
 * "command2", "args2", "description"}; */
R_API void r_core_cmd_help(const RCore *core, const char * help[]) {
	int i, max_length, padding_length,
		use_colors = core->print->flags & R_PRINT_FLAGS_COLOR;
	RCons *cons = r_cons_singleton ();
	char const *args_color_start;
	char const *help_color_start;
	char const *reset_colors;
	char padding[256];

	args_color_start = use_colors? cons->pal.args: "";
	help_color_start = use_colors? cons->pal.help: "";
	reset_colors     = use_colors? cons->pal.reset: "";

	max_length = 0;
	for (i = 0; help[i]; i += 3) {
		int len0 = strlen (help[i]);
		int len1 = strlen (help[i+1]);
		if (i) max_length = R_MAX (len0+len1, max_length);
	}

	for (i = 0; help[i]; i += 3) {
		padding_length = max_length - \
			(strlen (help[i]) + strlen (help[i+1]));
		if (padding_length >0) {
			memset (padding, ' ', padding_length);
			padding[padding_length] = '\0';
		} else padding[0] = 0;
		if (i) {
			r_cons_printf("|%s%s%s%s%s%s  %s%s%s\n",
				" ",
				help[i], args_color_start,
				help[i+1], reset_colors,
				padding, help_color_start,
				help[i+2], reset_colors);
		} else {
			// no need to indent the first line
			r_cons_printf ("|%s%s %s%s%s\n",
				help_color_start,
				help[i], help[i+1], help[i+2],
				reset_colors);
		}
	}
}
