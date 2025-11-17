/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

#include <sdb/sdb.h>
#define TN_KEY_LEN 32
#define TN_KEY_FMT "%"PFMT64u
#ifndef SIGKILL
#define SIGKILL 9
#endif

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#include "r_heap_glibc.h"
#endif

#if HAVE_JEMALLOC
#include "r_heap_jemalloc.h"
#include "dmh_jemalloc.inc.c"
#endif

void cmd_anal_reg (RCore *core, const char *str);

static RCoreHelpMessage help_msg_d = {
	"Usage:", "d", " # Debug commands",
	"d:", "[?] [cmd]", "run custom debug plugin command",
	"db", "[?]", "breakpoints commands",
	"dbt", "[?]", "display backtrace based on dbg.btdepth and dbg.btalgo",
	"dc", "[?]", "continue execution",
	"dd", "[?][*+-tsdfrw]", "manage file descriptors for child process",
	"de", "[-sc] [perm] [rm] [e]", "debug with ESIL (see de?)",
	"dg", " <file>", "generate a core-file (WIP)",
	"dh", " [plugin-name]", "select a new debug handler plugin (see dbh)",
	"dH", " [handler]", "transplant process to a new handler",
	"di", "[?]", "show debugger backend information (See dh)",
	"dk", "[?]", "list, send, get, set, signal handlers of child",
	"dL", "[?]", "list or set debugger handler",
	"dm", "[?]", "show memory maps",
	"do", "[?]", "open process (reload, alias for 'oo')",
	"doo", "[args]", "reopen in debug mode with args (alias for 'ood')",
	"doof", "[file]", "reopen in debug mode from file (alias for 'oodf')",
	"doc", "", "close debug session",
	"dp", "[?]", "list, attach to process or thread id",
	"dr", "[?]", "cpu registers",
	"ds", "[?]", "step, over, source line",
	"dt", "[?]", "display instruction traces",
	"dw", " <pid>", "block prompt until pid dies",
#if R2__WINDOWS__
	"dW", "", "list process windows",
	"dWi", "", "identify window under cursor",
#endif
	"dx", "[?][aers]", "execute code in the child process",
	"date", " [-b]", "use -b for beat time",
	NULL
};

static RCoreHelpMessage help_msg_dbi = {
	"Usage: dbi", "", " # Manipulate breakpoints by index",
	"dbi", "", "list breakpoint indexes",
	"dbi", " <addr>", "show breakpoint index in givengiven  offset",
	"dbi.", "", "show breakpoint index in current offset",
	"dbi-", " <idx>", "remove breakpoint by index",
	"dbix", " <idx> [expr]", "set expression for bp at given index",
	"dbic", " <idx> <cmd>", "run command at breakpoint index",
	"dbie", " <idx>", "enable breakpoint by index",
	"dbid", " <idx>", "disable breakpoint by index",
	"dbis", " <idx>", "swap Nth breakpoint",
	"dbite", " <idx>", "enable breakpoint Trace by index",
	"dbitd", " <idx>", "disable breakpoint Trace by index",
	"dbits", " <idx>", "swap Nth breakpoint trace",
	NULL
};

static RCoreHelpMessage help_msg_db = {
	"Usage: db", "", " # Breakpoints commands",
	"db", "", "list breakpoints",
	"db", " addr", "add breakpoint (see dbg.hwbp)",
	"db-", "*|addr", "remove breakpoint at address (or all breakpoints*)",
	"db.", "", "show breakpoint details in current address",
	"db*", "", "list breakpoints in radare commands",
	"dbj", "", "list breakpoints in JSON format",
	// "dbi", " 0x848 ecx=3", "stop execution when condition matches",
	"db", "[c|C] addr cmd", "run command when breakpoint is hit (dbC, continue after hit)",
	"db", "[d|e] addr", "disable or enable a breakpoint by address",
	"dbf", "", "put a breakpoint into every no-return function", // XXX very bad name
	"dbh", "[-| x86]", "use/remove/list breakpoint plugin handlers",
	"dbH", " [addr]", "add hardware breakpoint",
	"dbi", "[?]", "manipulate breakpoints by index",
	"dbm", " <module> <offset>", "add a breakpoint at an offset from a module's base",
	"dbn", " [<name>]", "show or set name for current breakpoint",
	"dbs", " <addr>", "toggle breakpoint",
	"dbt", "[?]", "show backtrace. See dbt? for more details",
	"dbx", " [expr]", "set expression for bp in current offset",
	"dbw", " <addr> <r/w/rw>", "add watchpoint",
#if __WINDOWS__
	"dbW", " <WM_DEFINE> [?|handle|name]", "set cond. breakpoint on a window message handler",
#endif
	"dbx", " number addr len perm", "modify hardware breakpoint",
	"dbx-", "number", "clear hardware breakpoint",
	NULL
};

static RCoreHelpMessage help_msg_dbt = {
	"Usage: dbt", "", " # Backtrace commands",
	"dbt", "", "display backtrace based on dbg.btdepth and dbg.btalgo",
	"dbt*", "", "display backtrace in flags",
	"dbt=", "", "display backtrace in one line (see dbt=s and dbt=b for sp or bp)",
	"dbtv", "", "display backtrace with local vars if any",
	"dbtj", "", "display backtrace in JSON",
	"dbta", "", "display ascii-art representation of the stack backtrace",
	"dbte", " <addr>", "enable Breakpoint Trace",
	"dbtd", " <addr>", "disable Breakpoint Trace",
	"dbts", " <addr>", "swap Breakpoint Trace",
	NULL
};

static RCoreHelpMessage help_msg_drr = {
	"Usage: drr", "", " # Show references to registers (see pxr?)",
	"drr", "", "periscope register values",
	"drrj", "", "same, but output in JSON",
	NULL
};

static RCoreHelpMessage help_msg_dbw = {
	"Usage: dbw", "<addr> <r/w/rw>", " # Add watchpoint",
	NULL
};

static RCoreHelpMessage help_msg_dc = {
	"Usage: dc", "", "Execution continuation commands",
	"dc", "", "continue execution of all children",
	"dc", " <pid>", "continue execution of pid",
	"dc", "[-pid]", "stop execution of pid",
	"dcb", "", "continue back until breakpoint",
	"dcc", "", "continue until call (use step into)",
	"dcco", "", "continue until call (use step over)",
	"dccu", "", "continue until unknown call (call reg)",
	"dce", "", "continue execution (pass exception to program)",
	"dcf", "", "continue until fork (TODO)",
	"dck", " <signal> <pid>", "continue sending signal to process",
	"dcp", "", "continue until program code (mapped io section)",
	"dcr", "", "continue until ret (uses step over)",
	"dcs", "[?] <num>", "continue until syscall",
	"dct", " <len>", "traptrace from curseek to len, no argument to list",
	"dcu", "[?] [..end|addr] ([end])", "continue until address (or range)",
	/*"TODO: dcu/dcr needs dbg.untilover=true??",*/
	/*"TODO: same for only user/libs side, to avoid steping into libs",*/
	/*"TODO: support for threads?",*/
	NULL
};

static RCoreHelpMessage help_msg_dcs = {
	"Usage:", "dcs", " Continue until syscall",
	"dcs", "", "continue until next syscall",
	"dcs [str]", "", "continue until next call to the 'str' syscall",
	"dcs", "*", "trace all syscalls, a la strace",
	NULL
};

static RCoreHelpMessage help_msg_dcu = {
	"Usage:", "dcu", " Continue until address",
	"dcu.", "", "alias for dcu $$ (continue until current address)",
	"dcu", " address", "continue until address",
	"dcu", " [..tail]", "continue until the range",
	"dcu", " [from] [to]", "continue until the range",
	NULL
};

static RCoreHelpMessage help_msg_dd = {
	"Usage: dd", "", "Manage file descriptors for child process (* to show r2 commands)",
	"dd", "[*]", "list file descriptors",
	"dd", "[*] <file|addr>", "open file as read-only (r--); addr = use as char* for path",
	"dd+", "[*] <file|addr>", "open/create file as read-write (rw-); addr = use as char* for path",
	"dd-", "[*] <fd>", "close fd",
	"ddt", "[*]", "close terminal fd (alias for `dd- 0`)",
	"dds", "[*] <fd> [offset]", "seek fd to offset (no offset = seek to beginning)",
	"ddd", "[*] <oldfd> <newfd>", "copy oldfd to newfd with dup2",
	"ddf", "[*] <addr>", "create pipe and write fds to (int[2])addr",
	"ddr", "[*] <fd> <addr> <size>", "read bytes from fd into (char*)addr",
	"ddw", "[*] <fd> <addr> <size>", "write bytes from (const char*)addr to fd",
	NULL
};

static RCoreHelpMessage help_msg_de = {
	"Usage:", "de", "[-sc] [perm] [rm] [expr]",
	"de", "", "list esil watchpoints",
	"de-*", "", "delete all esil watchpoints",
	"de ", "[perm] [rm] [addr|reg|from..to]", "stop on condition",
	"dec", "", "continue execution until matching expression",
	"des", "[?] [N]", "step-in N instructions with esildebug",
	"desu", " [addr]", "esildebug until specific address",
	NULL
};

static RCoreHelpMessage help_msg_des = {
	"Usage:", "des", "[u] [arg]",
	"des", " [N]", "step-in N instructions with esildebug",
	"desu", " [addr]", "esildebug until specific address",
	NULL
};

static RCoreHelpMessage help_msg_di = {
	"Usage: di", "", "Debugger target information",
	"di", "", "show debugger target information",
	"di*", "", "same as above, but in r2 commands",
	"dir", "", "alias for 'ls'",
	"diq", "", "same as above, but in one line",
	"dij", "", "same as above, but in JSON format",
	"dif", " [$a] [$b]", "compare two files (or $alias files)",
	NULL
};

static RCoreHelpMessage help_msg_dk = {
	"Usage: dk", "", "Signal commands",
	"dk", "", "list all signal handlers of child process",
	"dk", " <signal>", "send KILL signal to child",
	"dk", " <signal>=1", "set signal handler for <signal> in child",
	"dk?", "<signal>", "name/signum resolver",
	"dko", "[?] <signal>", "reset skip or cont options for given signal",
	"dko", " <signal> [|skip|cont]", "on signal SKIP handler or CONT into",
	"dkj", "", "list all signal handlers in JSON",
	NULL
};

static RCoreHelpMessage help_msg_dko = {
	"Usage:", "dko", " # Signal handling commands",
	"dko", "", "list existing signal handling",
	"dko", " [signal]", "clear handling for a signal",
	"dko", " [signal] [skip|cont]", "set handling for a signal",
	NULL
};

static RCoreHelpMessage help_msg_dm = {
	"Usage:", "dm", " # Memory maps commands",
	"dm", "", "list memory maps of target process",
	"dm", " address size", "allocate <size> bytes at <address> (anywhere if address is -1) in child process",
	"dm=", "", "list memory maps of target process (ascii-art bars)",
	"dm.", "", "show map name of current address",
	"dm*", "[-*]", "list memmaps in radare commands (dm** ioMap every debugMap, dm*- undoes)",
	"dm-", " address", "deallocate memory map of <address>",
	"dmd", "[aw] [file]", "dump current (all or writable) debug map region to a file (from-to.dmp) (see Sd)",
	"dmh", "[?]", "show map of heap",
	"dmi", "[?] ([addr|libname] [symname])", "list or load symbols from library",
	"dmj", "", "list memmaps in JSON format",
	"dml", " <file>", "load contents of file into the current map region",
	"dmm", "[?][j*]", "list modules (libraries, binaries loaded in memory)",
	"dmp", "[?] <address> <size> <perms>", "change page at <address> with <size>, protection <perms> (perm)",
	"dms", "[?] <id> <mapaddr>", "take/store memory snapshot",
	"dms-", " <id> <mapaddr>", "restore memory snapshot",
	"dmS", "[*] [addr|libname] [sectname]", "list sections of target lib",
	"dmL", " address size", "allocate <size> bytes at <address> and promote to huge page",
	//"dm, " rw- esp 9K", "set 9KB of the stack as read+write (no exec)",
	// "TODO:", "", "map files in process memory. (dmf file @ [addr])",
	NULL
};

static RCoreHelpMessage help_msg_dmi = {
	"Usage: dmi", "", " # List/load Symbols",
	"dmi.", "", "list closest symbol to the current address",
	"dmi", "[j|q|*] [libname] [symname]", "list symbols of target lib",
	"dmi*", "", "list symbols of target lib in radare commands",
	"dmia", "[j|q|*] [libname]", "list all info of target lib",
	"dmis", " [libname]", "same as .dmi* - import all symbols from given lib as flags",
	"dmiv", "", "show address of given symbol for given lib",
	NULL
};

static RCoreHelpMessage help_msg_dmm = {
	"Usage:", "dmm", " # Module memory maps commands",
	"dmm", "", "list modules of target process",
	"dmm*", "", "list modules of target process (r2 commands)",
	"dmm.", "", "list memory map of current module",
	"dmmj", "", "list modules of target process (JSON)",
	NULL
};

static RCoreHelpMessage help_msg_dms = {
	"Usage:", "dms", " # Memory map snapshots",
	"dms", "", "list memory snapshots",
	"dms", " addr", "take snapshot with given id of map at address",
	"dms", "-id", "delete memory snapshot",
	"dms.", "", "take snapshot of current map",
	"dms-", "", "revert to previous snapshot",
	"dms+", "", "re-apply snapshot",
	"dms*", "", "list snapshots in r2 commands",
	"dmsj", "", "list snapshots in JSON",
	"dmsC", " id comment", "add comment for given snapshot",
	"dmsd", " id", "hexdiff given snapshot. See `ccc`.",
	"dmsw", "", "snapshot of the writable maps",
	"dmsa", "", "full snapshot of all `dm` maps",
	NULL
};

static RCoreHelpMessage help_msg_dxe = {
	"Usage:", "dxe", " egg-program # see ragg2 and the 'g' command for more details",
	"dxe", " sym.imp.puts(\"foo\")", "call puts with a string argument",
	NULL
};

static RCoreHelpMessage help_msg_dmp = {
	"Usage:", "dmp", " Change page permissions",
	"dmp", " [addr] [size] [perms]", "change permissions",
	"dmp", " [perms]", "change dbg.map permissions",
	"dmp.", "", "show permissions of the current map",
	NULL
};

static RCoreHelpMessage help_msg_do = {
	"Usage:", "do", " # Debug (re)open commands",
	"do", "", "open process (reload, alias for 'oo')",
	"dor", " [rarun2]", "comma separated list of k=v rarun2 profile options (e dbg.profile)",
	"doe", "", "show rarun2 startup profile",
	"doe!", "", "edit rarun2 startup profile with $EDITOR",
	"doo", " [args]", "Reopen in debug mode with args (alias for 'ood')",
	"doof", " [args]", "Reopen in debug mode from file (alias for 'oodf')",
	"doc", "", "close debug session",
	NULL
};

static RCoreHelpMessage help_msg_dp = {
	"Usage:", "dp", " # Process commands",
	"dp", "", "list current pid and children",
	"dp", "q", "same as dp. just show the current process id",
	"dp", " <pid>", "list children of pid",
	"dpj", " <pid>", "list children of pid in JSON format",
	"dpl", "", "list all attachable pids",
	"dplj", "", "list all attachable pids in JSON format",
	"dp-", " <pid>", "detach select pid",
	"dp=", "<pid>", "select pid",
	"dpa", " <pid>", "attach and select pid",
	"dpc", "", "select forked pid (see dbg.forks)",
	"dpc*", "", "display forked pid (see dbg.forks)",
	"dpe", "", "show path to executable",
	"dpf", "", "attach to pid like file fd // HACK",
	"dpk", " <pid> [<signal>]", "send signal to process (default 0)",
	"dpn", "", "create new process (fork)",
	"dpt", "[?][j]", "list threads of current pid",
	"dpt", " <pid>", "list threads of process",
	"dpt.", "", "show current thread id",
	"dptj", "", "list threads of current pid in JSON format",
	"dptn", "", "create new thread (clone)",
	"dptj", " <pid>", "list threads of process in JSON format",
	"dpt=", "<thread>", "attach to thread",
	NULL
};

static RCoreHelpMessage help_msg_dr = {
	"Usage: dr", "", "Registers commands",
	"dr", "", "show 'gpr' registers",
	"dr", " <register>=<val>", "set register value",
	"dr.", " >$snapshot", "capture current register values in r2 alias file",
	"dr,", " [table-query]", "enumerate registers in table format",
	"dr0", "", "zero-fill the register arena, reset their state",
	"dr8", "[1|2|4|8] [type]", "display hexdump of gpr arena (WIP)",
	"dr=", "", "show registers in columns",
	"dr?", "<register>", "show value of given register",
	"dr??", "", "same as dr?`drp~=[0]+` # list all reg roles alias names and values",
	"dra", "[?]", "manage register arenas. see ara?",
	"drb", "[1|2|4|8] [type]", "display hexdump of gpr arena (WIP)",
	"drc", " [name]", "related to conditional flag registers",
	"drC", " [register]", "show register comments",
	"drd", "", "show only different registers",
	"dre", "", "show esil expression to set register values (like dr*)",
	"drf", "", "show fpu registers (80 bit long double)",
	"dri", "", "show inverse registers dump (sorted by value)",
	"drl", "[j]", "list all register names",
	"drv", "[?]", "show vector registers (also known as sve / packed / vector)",
	"dro", "", "show previous (old) values of registers",
	"drn", "", "list, show or change register alias name (PC,A0, defined by the register profile)",
	"drp", "[?] ", "display current register profile",
	"drr", "", "show registers references (telescoping)",
	"drrj", "", "show registers references (telescoping) in JSON format",
	// TODO: 'drs' to swap register arenas and display old register valuez
	"drs", "[?]", "stack register states",
	"drt", "[?]", "show all register types",
	"drw", " <hexnum>", "set contents of the register arena",
	"drx", "[?]", "show debug registers",
	".dr", "*", "include common register values in flags",
	".dr", "-", "unflag all registers",
	NULL
};

static RCoreHelpMessage help_msg_drp = {
	"Usage:", "drp", " # Register profile commands",
	"drp", "", "show the current register profile",
	"drp", " [regprofile-file]", "set the current register profile",
	"drp", " [gdb] [regprofile-file]", "parse gdb register profile and dump an r2 profile string",
	"drp*", "", "print r2 commands creating flags for each register inside the arena offset",
	"drpc", "", "show register profile comments",
	"drpi", "", "show internal representation of the register profile",
	"drp.", "", "show the current fake size",
	"drpj", "", "show the current register profile (JSON)",
	"drps", " [new fake size]", "get or set the register profile size",
	"drpg", "", "show register profile comments",
	"NOTE:", "", "this help will show arp if you run drp? when cfg.debug=0",
	NULL
};

static RCoreHelpMessage help_msg_drs = {
	"Usage:", "drs", "register states commands",
	"drs", "", "list register stack",
	"drs", "+", "push register state",
	"drs", "-", "pop register state",
	NULL
};

static RCoreHelpMessage help_msg_drt = {
	"Usage:", "drt", " [type] [size]    # debug register types",
	"drt", "", "list all available register types",
	"drt", " [size]", "show all regs in the profile of size",
	"drt", " 16", "show 16 bit registers",
	"drt", " [type]", "show all regs in the profile of this type",
	"drt", " all", "show all registers",
	"drt", " fpu", "show fpu registers",
	"drt", " [type] [size]", "same as above for type and size",
	"drt", " [type] [size]", "same as above for type and size",
	"drt*", "", "list flags in r commands",
	NULL
};

static RCoreHelpMessage help_msg_drx = {
	"Usage: drx", "", "Hardware breakpoints commands",
	"drx", "", "list all (x86?) hardware breakpoints",
	"drx", " <number> <address> <length> <perms>", "modify hardware breakpoint",
	"drx-", "<number>", "clear hardware breakpoint",
	NULL
};

static RCoreHelpMessage help_msg_drv = {
	"Usage: drv", " [reg] [idx] [wordsize] [= value]", "Show vector packed registers",
	"drv", "", "show XMM registers",
	"drv", " xmm0", "show all packings of xmm0",
	"drv", " xmm0 0 32 = 12", "set the first 32 bit word of the xmm0 reg to 12",
	"drvb", " [reg]", "show registers as bytes",
	"drvw", " [reg]", "show registers as words",
	"drvd", " [reg]", "show registers as doublewords",
	"drvq", " [reg]", "show registers as quadwords",
	"drvq", " xmm0~[0]", "show first quadword of xmm0",
	"drvf", " [reg]", "show registers as 32-bit floating point",
	"drvl", " [reg]", "show registers as 64-bit floating point",
	"drvyb", " [reg]", "show YMM registers as bytes",
	"drvyw", " [reg]", "show YMM registers as words",
	"drvyd", " [reg]", "show YMM registers as doublewords",
	"drvyq", " [reg]", "show YMM registers as quadwords",
	"drvq", " ymm0~[3]", "show fourth quadword of ymm0",
	"drvyf", " [reg]", "show YMM registers as 32-bit floating point",
	"drvyl", " [reg]", "show YMM registers as 64-bit floating point",
	NULL
};

static RCoreHelpMessage help_msg_ds = {
	"Usage: ds", "", "Step commands",
	"ds", "", "step one instruction",
	"ds", " <num>", "step <num> instructions",
	"dsb", "", "step back one instruction",
	"dsf", "", "step until end of frame",
	"dsi", " <cond>", "continue until condition matches",
	"dsl", "", "step one source line",
	"dsl", " <num>", "step <num> source lines",
	"dso", " <num>", "step over <num> instructions",
	"dsp", "", "step into program (skip libs)",
	"dss", " <num>", "skip <num> step instructions",
	"dsu", "[?] <address>", "step until <address>. See 'dsu?' for other step until cmds.",
	NULL
};

static RCoreHelpMessage help_msg_dsu = {
	"Usage: dsu", "", "Step until commands",
	"dsu ", "<address>", "step until <address>",
	"dsui", " <instr>", "step until an instruction disasm matches",
	"dsuir", " <regex>", "like dsui, but using a regexp",
	"dsuo", " <optype> [<optype> ...]", "step until an instr matches one of the <optype>s.",
	"dsue", " <esil>", "step until <esil> expression matches",
	"dsuf", " <flag>", "step until pc == <flag> matching name",
	NULL
};

static RCoreHelpMessage help_msg_dt = {
	"Usage: dt", "", "Trace commands",
	"dt", "", "list all traces ",
	"dt", " [addr]", "show trace info at address",
	"dt*", "", "list all traced opcode offsets",
	"dtj", "", "list instruction trace logs in json",
	"dt+", " [addr] [times]", "add trace for address N times",
	"dt-", "", "reset traces (instruction/calls)",
	"dt=", "", "show ascii-art color bars with the debug trace ranges",
	"dta", " 0x804020 ...", "only trace given addresses",
	"dtc", "[?][addr]|([from] [to] [addr])", "trace call/ret",
	"dtd", "[qi] [nth-start]", "list all traced disassembled (quiet, instructions)",
	"dte", "[?]", "show esil trace logs",
	"dtg", "", "graph call/ret trace",
	"dtg*", "", "graph in agn/age commands. use .dtg*;aggi for visual",
	"dtgi", "", "interactive debug trace",
	"dts", "[?]", "manage trace sessions, used for step back (EXPERIMENTAL)",
	"dtt", " [tag]", "select trace tag (no arg unsets)",
	"dtt.", "", "show current tag",
	NULL
};

static RCoreHelpMessage help_msg_dte = {
	"Usage: dte", "", "Show esil trace logs",
	"dte", "", "esil trace log for a single instruction",
	"dte", " [idx]", "show commands for that index log",
	"dte", "-*", "delete all the esil traces recorded",
	"dtei", "", "emulate instruction and record a trace their effects",
	"dted", "", "disassemble all traced instructions",
	"dtek", " [sdb query]", "esil trace log single instruction from sdb",
	NULL
};

static RCoreHelpMessage help_msg_dts = {
	"Usage:", "dts[*]", "Trace sessions",
	"dts+", "", "start trace session",
	"dts-", "", "stop trace session",
	"dtst", " [dir] ", "save trace sessions to disk",
	"dtsf", " [dir] ", "read trace sessions from disk",
	"dtsm", "", "list current memory map and hash",
	NULL
};

static RCoreHelpMessage help_msg_dx = {
	"Usage: dx", "[aers]", " Debug execution commands",
	"dx", " <hexpairs>", "execute opcodes",
	"dxa", " <asm>", "assemble code and execute",
	"dxe", "[?] <egg-expr>", "compile egg expression and execute it",
	"dxr", " <hexpairs>", "execute opcodes and restore state",
	"dxrs", " <hexpairs>", "execute opcodes and restore state, excluding the stack",
	"dxs", " <name> [args]", "syscall injection (see gs)",
	"\nExamples:", "", "",
	"dx", " 9090", "execute two x86 nops",
	"\"dxa mov eax,6;mov ebx,0;\"", "", "assemble and execute",
	"dxs", " write 1, 0x8048, 12", "write 12 bytes from 0x8048 into stdout",
	NULL
};

static RCoreHelpMessage help_msg_dL = {
	"Usage: dL", "", " List or set debugger handler",
	"dL", "", "list debugger handlers",
	"dLq", "", "list debugger handlers in quiet mode",
	"dLj", "", "list debugger handlers in json mode",
	"dL", " <handler>", "set debugger handler",
	NULL
};

struct dot_trace_ght {
	RGraph *graph;
	Sdb *graphnodes;
};

struct trace_node {
	ut64 addr;
	int refs;
};

static void cmd_drn(RCore *core, const char *str) {
	RReg *reg = core->dbg->reg;
	char *foo = r_str_trim_dup (str + 1);
	r_str_case (foo, true);
	if (*foo == '?') {
		r_core_cmd_help_match (core, help_msg_dr, "drn");
	} else if (*foo) {
		char *eq = strchr (foo, '=');
		if (eq) {
			*eq++ = 0;
			int type = r_reg_alias_fromstring (foo);
			if (type >= 0) {
				r_reg_alias_setname (reg, type, eq);
			} else {
				R_LOG_ERROR ("Invalid register alias");
			}
		} else {
			const char *name = r_reg_alias_getname (core->dbg->reg, r_reg_alias_fromstring (foo));
			if (R_STR_ISNOTEMPTY (name)) {
				r_cons_println (core->cons, name);
			} else {
				R_LOG_ERROR ("Invalid register alias name");
			}
		}
	} else {
		int i;
		for (i = 0; i < R_REG_ALIAS_LAST; i++) {
			const char *r = r_reg_alias_getname (reg, i);
			const char *a = r_reg_alias_tostring (i);
			if (r && a) {
				r_cons_printf (core->cons, "%s %s\n", a, r);
			}
		}
	}
	free (foo);
}

static void setRarunProfileString(RCore *core, const char *str) {
	char *s = r_str_newf ("%s\n", str);
	r_str_replace_char (s, ',', '\n');
	char *v = r_base64_encode_dyn ((const ut8*)s, -1);
	char *rs = r_str_newf ("base64:%s", v);
	r_config_set (core->config, "dbg.profile", rs);
	free (rs);
	free (v);
	free (s);
}

static void cmd_debug_cont_syscall(RCore *core, const char *_str) {
	// TODO : handle more than one stopping syscall
	int i, *syscalls = NULL;
	int count = 0;
	if (_str && *_str) {
		char *str = strdup (_str);
		count = r_str_word_set0 (str);
		syscalls = calloc (sizeof (int), count);
		for (i = 0; i < count; i++) {
			const char *sysnumstr = r_str_word_get0 (str, i);
			int sig = (int)r_num_math (core->num, sysnumstr);
			if (sig == -1) { // trace ALL syscalls
				syscalls[i] = -1;
			} else if (sig == 0) {
				sig = r_syscall_get_num (core->anal->syscall, sysnumstr);
				if (sig == -1) {
					R_LOG_ERROR ("Unknown syscall number");
					free (str);
					free (syscalls);
					return;
				}
				syscalls[i] = sig;
			}
		}
		eprintf ("Running child until syscalls:");
		for (i = 0; i < count; i++) {
			eprintf ("%d ", syscalls[i]);
		}
		eprintf ("\n");
		free (str);
	} else {
		R_LOG_INFO ("Running child until next syscall");
	}
	r_reg_arena_swap (core->dbg->reg, true);
	r_debug_continue_syscalls (core->dbg, syscalls, count);
	free (syscalls);
}

static int showreg(RCore *core, const char *str) {
	int size = 0;
	RRegItem *r = 0;
#if 0
	const char *rname = str;
	// check for alias reg
	int role = r_reg_get_name_idx (str);
	if (role != -1) {
		rname = r_reg_get_name (core->dbg->reg, role);
	}
	if (!rname) {
		return 0;
	}
#endif
	r = r_reg_get (core->dbg->reg, str, -1);
	if (r) {
		ut64 off;
		utX value;
		if (r->size > 64) {
			off = r_reg_get_value_big (core->dbg->reg, r, &value);
			switch (r->size) {
			case 80:
				r_cons_printf (core->cons, "0x%04x%016"PFMT64x"\n", value.v80.High, value.v80.Low);
				break;
			case 96:
				r_cons_printf (core->cons, "0x%08x%016"PFMT64x"\n", value.v96.High, value.v96.Low);
				break;
			case 128:
				r_cons_printf (core->cons, "0x%016"PFMT64x"%016"PFMT64x"\n", value.v128.High, value.v128.Low);
				break;
			case 256:
				r_cons_printf (core->cons, "0x%016"PFMT64x"%016"PFMT64x"%016"PFMT64x"%016"PFMT64x"\n",
					   value.v256.High.High, value.v256.High.Low, value.v256.Low.High, value.v256.Low.Low);
				break;
			default:
				R_LOG_ERROR ("Cannot retrieve reg '%s' of %i bits", str +1, r->size);
			}
		} else {
			off = r_reg_get_value (core->dbg->reg, r);
			r_cons_printf (core->cons, "0x%08"PFMT64x "\n", off);
		}
		return r->size;
	}
	const char *arg = strchr (str + 1, ' ');
	if (arg && size == 0) {
		str = arg;
	}
	return atoi (str + 1);
}

static RGraphNode *get_graphtrace_node(RGraph *g, Sdb *nodes, struct trace_node *tn) {
	char tn_key[TN_KEY_LEN];
	snprintf (tn_key, TN_KEY_LEN, TN_KEY_FMT, tn->addr);
	RGraphNode *gn = (RGraphNode *)(size_t)sdb_num_get (nodes, tn_key, NULL);
	if (!gn) {
		gn = r_graph_add_node (g, tn);
		sdb_num_set (nodes, tn_key, (ut64)(size_t)gn, 0);
	}
	return gn;
}

static void dot_trace_create_node(RTreeNode *n, RTreeVisitor *vis) {
	struct dot_trace_ght *data = (struct dot_trace_ght *)vis->data;
	struct trace_node *tn = n->data;
	if (tn) {
		get_graphtrace_node (data->graph, data->graphnodes, tn);
	}
}

static void dot_trace_discover_child(RTreeNode *n, RTreeVisitor *vis) {
	struct dot_trace_ght *data = (struct dot_trace_ght *)vis->data;
	RGraph *g = data->graph;
	Sdb *gnodes = data->graphnodes;
	RTreeNode *parent = n->parent;
	struct trace_node *tn = n->data;
	struct trace_node *tn_parent = parent->data;

	if (tn && tn_parent) {
		RGraphNode *gn = get_graphtrace_node (g, gnodes, tn);
		RGraphNode *gn_parent = get_graphtrace_node (g, gnodes, tn_parent);
		if (!r_graph_adjacent (g, gn_parent, gn)) {
			r_graph_add_edge (g, gn_parent, gn);
		}
	}
}

static void dot_trace_traverse(RCore *core, RTree *t, int fmt) {
	const char *gfont = r_config_get (core->config, "graph.font");
	struct dot_trace_ght aux_data;
	RTreeVisitor vis = {0};
	const RList *nodes;
	RListIter *iter;
	RGraphNode *n;

	if (fmt == 'i') {
		r_core_cmd0 (core, "ag-;.dtg*;aggi");
		return;
	}
	aux_data.graph = r_graph_new ();
	aux_data.graphnodes = sdb_new0 ();

	/* build a callgraph from the execution trace */
	vis.data = &aux_data;
	vis.user = core;
	vis.pre_visit = (RTreeNodeVisitCb)dot_trace_create_node;
	vis.discover_child = (RTreeNodeVisitCb)dot_trace_discover_child;
	r_tree_bfs (t, &vis);

	/* traverse the callgraph to print the dot file */
	nodes = r_graph_get_nodes (aux_data.graph);
	if (fmt == 0) {
		r_cons_printf (core->cons, "digraph code {\n"
				"graph [bgcolor=white];\n"
				"    node [color=lightgray, style=filled"
				" shape=box fontname=\"%s\" fontsize=\"8\"];\n", gfont);
	}
	r_list_foreach (nodes, iter, n) {
		struct trace_node *tn = (struct trace_node *)n->data;
		const RList *neighbours = r_graph_get_neighbours (aux_data.graph, n);
		RListIter *it_n;
		RGraphNode *w;

		if (!fmt && tn) {
			r_cons_printf (core->cons, "\"0x%08"PFMT64x"\" [URL=\"0x%08"PFMT64x
					"\" color=\"lightgray\" label=\"0x%08"PFMT64x
					" (%d)\"]\n", tn->addr, tn->addr, tn->addr, tn->refs);
		}
		r_list_foreach (neighbours, it_n, w) {
			struct trace_node *tv = (struct trace_node *)w->data;

			if (tv && tn) {
				if (fmt) {
					r_cons_printf (core->cons, "agn 0x%08"PFMT64x"\n", tn->addr);
					r_cons_printf (core->cons, "agn 0x%08"PFMT64x"\n", tv->addr);
					r_cons_printf (core->cons, "age 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
							tn->addr, tv->addr);
				} else {
					r_cons_printf (core->cons, "\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x
							"\" [color=\"red\"];\n", tn->addr, tv->addr);
				}
			}
		}
	}
	if (!fmt) {
		r_cons_printf (core->cons, "}\n");
	}

	r_graph_free (aux_data.graph);
	sdb_free (aux_data.graphnodes);
}

/* TODO: refactor all those step_until* function into a single one
 * TODO: handle when the process is dead
 * TODO: handle ^C */

static int step_until(RCore *core, ut64 addr) {
	ut64 pc = r_debug_reg_get (core->dbg, "PC");
	if (!pc) {
		R_LOG_ERROR ("Cannot 'drn PC'");
		return false;
	}
	if (!addr) {
		R_LOG_ERROR ("Cannot continue until address 0");
		return false;
	}
	bool honorbps = r_config_get_b (core->config, "dbg.bpforuntil");
	r_cons_break_push (core->cons, NULL, NULL);
	do {
		if (r_cons_is_breaked (core->cons)) {
			core->break_loop = true;
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			core->break_loop = true;
			break;
		}
		r_debug_step (core->dbg, 1);
		pc = r_debug_reg_get (core->dbg, "PC");
		if (honorbps) {
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
			if (bpi) {
				R_LOG_INFO ("Breakpoint hit");
				break;
			}
		}
		// check breakpoint here
	} while (pc != addr);
	r_cons_break_pop (core->cons);
	return true;
}

static int step_until_esil(RCore *core, const char *esilstr) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg && core->dbg->anal && esilstr, false);
	if (!core->dbg->anal->esil) {
		R_LOG_INFO ("esil is not initialized. Run 'aei' first");
		return false;
	}
	r_cons_break_push (core->cons, NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked (core->cons)) {
			core->break_loop = true;
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			core->break_loop = true;
			break;
		}
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
		if (r_esil_condition (core->anal->esil, esilstr)) {
			R_LOG_INFO ("ESIL BREAK!");
			break;
		}
	}
	r_cons_break_pop (core->cons);
	return true;
}

static bool is_repeatable_inst(RCore *core, ut64 addr) {
	// we have read the bytes already
	RAnalOp *op = r_core_op_anal (core, addr, R_ARCH_OP_MASK_ALL);
	bool ret = op && ((op->prefix & R_ANAL_OP_PREFIX_REP) || (op->prefix & R_ANAL_OP_PREFIX_REPNE));
	r_anal_op_free (op);
	return ret;
}

static bool step_until_inst(RCore *core, const char *instr, bool regex) {
	R_RETURN_VAL_IF_FAIL (core && instr && core->dbg, false);
	ut8 buf[32];
	bool is_x86 = r_str_startswith (r_config_get (core->config, "asm.arch"), "x86");
	bool honorbps = r_config_get_b (core->config, "dbg.bpforuntil");

	instr = r_str_trim_head_ro (instr);
	r_cons_break_push (core->cons, NULL, NULL);
	for (;;) {
		RAnalOp asmop;
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			break;
		}
		ut64 pc = r_debug_reg_get (core->dbg, "PC");
		if (is_x86 && is_repeatable_inst (core, pc)) {
			r_debug_step_over (core->dbg, 1);
		} else {
			r_debug_step (core->dbg, 1);
		}
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
		pc = r_debug_reg_get (core->dbg, "PC");
		/* TODO: disassemble instruction and strstr */
		r_asm_set_pc (core->rasm, pc);
		if (honorbps) {
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
			if (bpi) {
				R_LOG_INFO ("Breakpoint hit");
				break;
			}
		}
		// TODO: speedup if instructions are in the same block as the previous
		r_io_read_at (core->io, pc, buf, sizeof (buf));
		int ret = r_asm_disassemble (core->rasm, &asmop, buf, sizeof (buf));
		R_LOG_DEBUG ("0x%08"PFMT64x" %d %s", pc, ret, asmop.mnemonic);
		if (ret > 0) {
			const char *buf_asm = asmop.mnemonic;
			if (regex) {
				if (r_regex_match (instr, "e", buf_asm)) {
					R_LOG_INFO ("Stop");
					r_anal_op_fini (&asmop);
					break;
				}
			} else {
				if (strstr (buf_asm, instr)) {
					R_LOG_INFO ("Stop");
					r_anal_op_fini (&asmop);
					break;
				}
			}
		}
		r_anal_op_fini (&asmop);
	}
	r_cons_break_pop (core->cons);
	return true;
}

static bool step_until_optype(RCore *core, const char *_optypes) {
	R_RETURN_VAL_IF_FAIL (core && core->dbg && _optypes, false);
	RList *optypes_list = NULL;
	RListIter *iter;
	char *optype = NULL;
	char *optypes = strdup (r_str_trim_head_ro (_optypes));
	RAnalOp op;
	ut8 buf[32];
	ut64 pc;
	bool res = true;

	st64 maxsteps = r_config_get_i (core->config, "esil.maxsteps");
	ut64 countsteps = 0;
	if (R_STR_ISEMPTY (optypes)) {
		r_core_cmd_help_match (core, help_msg_dsu, "dsuo");
		res = false;
		goto end;
	}

	bool honorbps = r_config_get_b (core->config, "dbg.bpforuntil");
	const bool debugMode = r_config_get_b (core->config, "cfg.debug");
	optypes_list = r_str_split_list (optypes, " ", 0);

	r_cons_break_push (core->cons, NULL, NULL);
	for (; !maxsteps || countsteps < maxsteps; countsteps++) {
		if (r_cons_is_breaked (core->cons)) {
			core->break_loop = true;
			break;
		}
		if (debugMode) {
			if (r_debug_is_dead (core->dbg)) {
				core->break_loop = true;
				break;
			}
			r_debug_step (core->dbg, 1);
			pc = r_debug_reg_get (core->dbg, "PC");
			// 'Copy' from r_debug_step_soft
			if (!core->dbg->iob.read_at) {
				R_LOG_ERROR ("cannot read");
				res = false;
				goto cleanup_after_push;
			}
			if (!core->dbg->iob.read_at (core->dbg->iob.io, pc, buf, sizeof (buf))) {
				R_LOG_ERROR ("cannot read");
				res = false;
				goto cleanup_after_push;
			}
		} else {
			r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
			pc = r_reg_getv (core->anal->reg, "PC");
			if (pc == UT64_MAX) {
				break;
			}
		}
		if (honorbps) {
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
			if (bpi) {
				R_LOG_INFO ("Breakpoint hit");
				break;
			}
		}
		r_io_read_at (core->io, pc, buf, sizeof (buf));

		if (!r_anal_op (core->dbg->anal, &op, pc, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC)) {
			R_LOG_ERROR ("r_anal_op failed");
			res = false;
			goto cleanup_after_push;
		}

		// This is slow because we do lots of strcmp's.
		// To improve this, the function r_anal_optype_string_to_int should be implemented
		// I also don't check if the opcode type exists.
		const char *optype_str = r_anal_optype_tostring (op.type);
		r_list_foreach (optypes_list, iter, optype) {
			if (!strcmp (optype_str, optype)) {
				goto cleanup_after_push;
			}
		}
	}

cleanup_after_push:
	r_cons_break_pop (core->cons);
end:
	free (optypes);
	r_list_free (optypes_list);
	return res;
}

static bool step_until_flag(RCore *core, const char *instr) {
	R_RETURN_VAL_IF_FAIL (core && instr && core->dbg, false);
	RListIter *iter;
	RFlagItem *f;

	bool honorbps = r_config_get_b (core->config, "dbg.bpforuntil");
	instr = r_str_trim_head_ro (instr);
	r_cons_break_push (core->cons, NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked (core->cons) || r_debug_is_dead (core->dbg)) {
			break;
		}
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
		ut64 pc = r_debug_reg_get (core->dbg, "PC");
		if (honorbps) {
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
			if (bpi) {
				R_LOG_INFO ("Breakpoint hit");
				break;
			}
		}
		const RList *list = r_flag_get_list (core->flags, pc);
		r_list_foreach (list, iter, f) {
			if (R_STR_ISEMPTY (instr) || (f->realname && strstr (f->realname, instr))) {
				r_cons_printf (core->cons, "[ 0x%08"PFMT64x" ] %s\n", f->addr, f->realname);
				r_cons_break_pop (core->cons);
				return true;
			}
		}
	}
	r_cons_break_pop (core->cons);
	return false;
}

/* until end of frame */
static int step_until_eof(RCore *core) {
	int maxLoops = 200000;
	ut64 off, now = r_debug_reg_get (core->dbg, "SP");
	r_cons_break_push (core->cons, NULL, NULL);
	do {
		// XXX (HACK!)
		r_debug_step_over (core->dbg, 1);
		off = r_debug_reg_get (core->dbg, "SP");
		// check breakpoint here
		if (--maxLoops < 0) {
			R_LOG_ERROR ("Step loop limit exceeded");
			break;
		}
	} while (off <= now);
	r_cons_break_pop (core->cons);
	return true;
}

static int step_line(RCore *core, int times) {
	ut64 off = r_debug_reg_get (core->dbg, "PC");
	if (off == 0LL) {
		R_LOG_ERROR ("Cannot 'drn PC'");
		return false;
	}
	RBinAddrline *al = r_bin_addrline_get (core->bin, off);
	bool find_meta;
	if (al) {
		char* ptr = r_file_slurp_line (al->file, al->line, 0);
		R_LOG_DEBUG ("addrline 0x%08"PFMT64x" %s : %d (%s)", off, al->file, al->line, ptr);
		find_meta = false;
		free (ptr);
	} else {
		R_LOG_DEBUG ("Stepping until the next addrline reference");
		find_meta = true;
	}
	RBinAddrline *al2 = NULL;
	do {
		r_debug_step (core->dbg, 1);
		off = r_debug_reg_get (core->dbg, "PC");
		r_bin_addrline_free (al2);
		al2 = r_bin_addrline_get (core->bin, off);
		if (!al2) {
			if (find_meta) {
				continue;
			}
			R_LOG_ERROR ("Cannot retrieve addrline info at 0x%08"PFMT64x, off);
			r_bin_addrline_free (al);
			return false;
		}
	} while (al && al2 && !strcmp (al->file, al2->file) && al->line == al2->line);

	if (al2) {
		char *tmp_ptr = r_file_slurp_line (al2->file, al2->line, 0);
		R_LOG_DEBUG ("addrline 0x%08"PFMT64x" %s : %d (%s)", off, al2->file, al2->line, tmp_ptr);
		free (tmp_ptr);
		r_bin_addrline_free (al2);
	}
	r_bin_addrline_free (al);

	return true;
}

static void cmd_debug_pid(RCore *core, const char *input) {
	int pid, sig;
	const char *ptr;
	switch (input[1]) {
	case '\0': // "dp"
		R_LOG_INFO ("Selected: %d %d", core->dbg->pid, core->dbg->tid);
		r_debug_pid_list (core->dbg, core->dbg->pid, 0);
		break;
	case '-': // "dp-"
		if (input[2]== ' ') {
			r_debug_detach (core->dbg, r_num_math (core->num, input + 2));
		} else {
			r_debug_detach (core->dbg, core->dbg->pid);
		}
		break;
	case 'c': // "dpc"
		if (core->dbg->forked_pid != -1) {
			if (input[2] == '*') {
				eprintf ("dp %d\n", core->dbg->forked_pid);
			} else {
				r_debug_select (core->dbg, core->dbg->forked_pid, core->dbg->tid);
				core->dbg->main_pid = core->dbg->forked_pid;
				core->dbg->n_threads = 0;
				core->dbg->forked_pid = -1;
			}
		} else {
			R_LOG_INFO ("No recently forked children");
		}
		break;
	case 'k': // "dpk"
		/* stop, print, pass -- just use flags*/
		/* XXX: not for threads? signal is for a whole process!! */
		/* XXX: but we want fine-grained access to process resources */
		pid = atoi (input + 2);
		if (pid > 0) {
			ptr = r_str_trim_head_ro (input + 2);
			ptr = strchr (ptr, ' ');
			sig = ptr? atoi (ptr + 1): 0;
			R_LOG_INFO ("Sending signal '%d' to pid '%d'", sig, pid);
			r_debug_kill (core->dbg, pid, false, sig);
		} else {
			R_LOG_INFO ("cmd_debug_pid: Invalid arguments (%s)", input);
		}
		break;
	case 'n': // "dpn"
		R_LOG_ERROR ("TODO: debug_fork is not implemented: %d", r_debug_child_fork (core->dbg));
		break;
	case 't': // "dpt"
		switch (input[2]) {
		case '\0': // "dpt"
			r_debug_thread_list (core->dbg, core->dbg->pid, 0);
			break;
		case '.':
			r_cons_printf (core->cons, "%d\n", core->dbg->tid);
			break;
		case 'j': // "dptj"
			if (input[3] != ' ') { // "dptj"
				r_debug_thread_list (core->dbg, core->dbg->pid, 'j');
			} else { // "dptj "
				r_debug_thread_list (core->dbg, atoi (input + 3), 'j');
			}
			break;
		case ' ': // "dpt "
			r_debug_thread_list (core->dbg, atoi (input + 2), 0);
			break;
		case '=': // "dpt="
			r_debug_select (core->dbg, core->dbg->pid,
					(int) r_num_math (core->num, input + 3));
			break;
		case 'n': // "dptn"
			R_LOG_TODO ("debug_clone: %d", r_debug_child_clone (core->dbg));
			break;
		case '?': // "dpt?"
		default:
			r_core_cmd_help_contains (core, help_msg_dp, "dpt");
			break;
		}
		break;
	case 'a': // "dpa"
		if (input[2]) {
			const int pid = (int) r_num_math (core->num, input + 2);
			r_debug_attach (core->dbg, pid);
		} else {
			if (core->io && core->io->desc) {
				const int pid = r_io_fd_get_pid (core->io, core->io->desc->fd);
				r_debug_attach (core->dbg, pid);
			}
		}
		r_debug_select (core->dbg, core->dbg->pid, core->dbg->tid);
		{
			RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
			const bool canstep = (plugin && plugin->canstep);
			r_config_set_i (core->config, "dbg.swstep", canstep);
		}
		r_core_cmdf (core, ":pid %d", core->dbg->pid);
		break;
	case 'f': // "dpf"
		if (core->io && core->io->desc) {
			r_debug_select (core->dbg, r_io_fd_get_pid (core->io, core->io->desc->fd),
					r_io_fd_get_tid (core->io, core->io->desc->fd));
		}
		break;
	case '=': // "dp="
		r_debug_select (core->dbg,
				(int) r_num_math (core->num, input + 2), core->dbg->tid);
		core->dbg->main_pid = r_num_math (core->num, input + 2);
		break;
	case 'l': // "dpl"
		switch (input[2]) {
		case '\0': // "dpl"
			r_debug_pid_list (core->dbg, 0, 0);
			break;
		case 'j': // "dplj"
			r_debug_pid_list (core->dbg, 0, 'j');
			break;
		}
		break;
	case '.':
	case 'q':
		r_cons_printf (core->cons, "%d\n", core->dbg->pid);
		break;
	case 'j': // "dpj"
		switch (input[2]) {
		case '\0': // "dpj"
			r_debug_pid_list (core->dbg, core->dbg->pid, 'j');
			break;
		case ' ': // "dpj "
			r_debug_pid_list (core->dbg,
					(int) R_MAX (0, (int)r_num_math (core->num, input + 2)), 'j');
			break;
		}
		break;
	case 'e': // "dpe"
		{
			int pid = (input[2] == ' ')? atoi (input + 2): core->dbg->pid;
			char *exe = r_sys_pid_to_path (pid);
			if (exe) {
				r_cons_println (core->cons, exe);
				free (exe);
			} else {
				r_core_cmd0 (core, "o.");
			}
		}
		break;
	case ' ': // "dp "
		r_debug_pid_list (core->dbg,
				(int) R_MAX (0, (int)r_num_math (core->num, input + 2)), 0);
		break;
	case '?': // "dp?"
	default:
		r_core_cmd_help (core, help_msg_dp);
		break;
	}
}

static void cmd_debug_backtrace(RCore *core, const char *input) {
	RAnalOp analop;
	ut64 addr, len = r_num_math (core->num, input);
	if (!len) {
		r_bp_traptrace_list (core->dbg->bp);
	} else {
		ut64 oaddr = 0LL;
		R_LOG_INFO ("Trap tracing 0x%08"PFMT64x"-0x%08"PFMT64x, core->addr, core->addr + len);
		r_reg_arena_swap (core->dbg->reg, true);
		r_bp_traptrace_reset (core->dbg->bp, true);
		r_bp_traptrace_add (core->dbg->bp, core->addr, core->addr+len);
		r_bp_traptrace_enable (core->dbg->bp, true);
		do {
			ut8 buf[32];
			r_debug_continue (core->dbg);
			addr = r_debug_reg_get (core->dbg, "PC");
			if (!addr || addr == UT64_MAX) {
				eprintf ("pc=0\n");
				break;
			}
			if (addr == oaddr) {
				eprintf ("pc=opc\n");
				break;
			}
			oaddr = addr;
			/* XXX Bottleneck..we need to reuse the bytes read by traptrace */
			// XXX Do asm.arch should define the max size of opcode?
			r_io_read_at (core->io, addr, buf, 32); // XXX longer opcodes?
			r_anal_op (core->anal, &analop, addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
		} while (r_bp_traptrace_at (core->dbg->bp, addr, analop.size));
		r_bp_traptrace_enable (core->dbg->bp, false);
	}
}

static int grab_bits(RCore *core, const char *arg, int *pcbits2) {
	int pcbits = atoi (arg);
	if (pcbits2) {
		*pcbits2 = 0;
	}
	if (pcbits < 1) {
		int rpbits = r_reg_default_bits (core->anal->reg);
		if (rpbits) {
			pcbits = rpbits;
			if (pcbits2) {
				*pcbits2 = 32;
			}
		} else if (!strcmp (r_config_get (core->config, "asm.arch"), "avr")) {
			pcbits = 8;
			if (pcbits2) {
				*pcbits2 = 32;
			}
		} else {
			RRegItem *reg = r_reg_get (core->anal->reg, "PC", 0);
			if (reg) {
				if (core->rasm->config->bits != reg->size)
					pcbits = reg->size;
			}
		}
	}
	return pcbits ? pcbits : core->anal->config->bits;
}

#define MAX_MAP_SIZE 1024*1024*512
static int dump_maps(RCore *core, int perm, const char *filename) {
	RDebugMap *map;
	RListIter *iter;
	r_debug_map_sync (core->dbg); // update process memory maps
	ut64 addr = core->addr;
	int do_dump = false;
	int ret = !r_list_empty (core->dbg->maps);
	r_list_foreach (core->dbg->maps, iter, map) {
		do_dump = false;
		if (perm == -1) {
			if (addr >= map->addr && addr < map->addr_end) {
				do_dump = true;
			}
		} else if (perm == 0) {
			do_dump = true;
		} else if (perm == (map->perm & perm)) {
			do_dump = true;
		}
		if (do_dump) {
			ut8 *buf = malloc (map->size);
			//TODO: use mmap here. we need a portable implementation
			if (!buf) {
				R_LOG_ERROR ("Cannot allocate 0x%08"PFMT64x" bytes", map->size);
				free (buf);
				/// XXX: TODO: read by blocks!!1
				continue;
			}
			if (map->size > MAX_MAP_SIZE) {
				R_LOG_INFO ("Not dumping 0x%08"PFMT64x" because it's too large (%"PFMT64d")", map->addr, map->size);
				free (buf);
				continue;
			}
			r_io_read_at (core->io, map->addr, buf, map->size);
			char *file = filename
			? strdup (filename)
			: r_str_newf ("0x%08"PFMT64x"-0x%08"PFMT64x"-%s.dmp",
					map->addr, map->addr_end, r_str_rwx_i (map->perm));
			if (!r_file_dump (file, buf, map->size, 0)) {
				R_LOG_ERROR ("Cannot write '%s'", file);
				ret = 0;
			} else {
				R_LOG_INFO ("Dumped %d byte(s) into %s", (int)map->size, file);
			}
			free (file);
			free (buf);
		}
	}
	//eprintf ("No debug region found here\n");
	return ret;
}

static void cmd_debug_modules(RCore *core, int mode) { // "dmm"
	ut64 addr = core->addr;
	RDebugMap *map;
	RList *list;
	RListIter *iter;

	/* avoid processing the list if the user only wants help */
	if (mode == '?') {
show_help:
		r_core_cmd_help (core, help_msg_dmm);
		return;
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	// TODO: honor mode
	list = r_debug_modules_list (core->dbg);
	r_list_foreach (list, iter, map) {
		switch (mode) {
		case 0:
			r_cons_printf (core->cons, "0x%08"PFMT64x" 0x%08"PFMT64x"  %s\n", map->addr, map->addr_end, map->file);
			break;
		case '.':
			if (addr >= map->addr && addr < map->addr_end) {
				r_cons_printf (core->cons, "0x%08"PFMT64x" 0x%08"PFMT64x"  %s\n", map->addr, map->addr_end, map->file);
				goto beach;
			}
			break;
		case 'j':
			{
				/* Escape backslashes (e.g. for Windows). */
				pj_o (pj);
				pj_kn (pj, "addr", map->addr);
				pj_kn (pj, "addr_end", map->addr_end);
				pj_ks (pj, "file", map->file);
				pj_ks (pj, "name", map->name);
				pj_end (pj);
			}
			break;
		case ':':
		case '*':
			if (mode == '*' || (mode == ':' && R_BETWEEN (map->addr, addr, map->addr_end))) {
				/* Escape backslashes (e.g. for Windows). */
				char *escaped_path = r_str_escape (map->file);
				char *filtered_name = strdup (map->name);
				r_name_filter (filtered_name, 0);
				r_cons_printf (core->cons, "f mod.%s = 0x%08"PFMT64x"\n",
					filtered_name, map->addr);
				r_cons_printf (core->cons, "oba 0x%08"PFMT64x" %s\n", map->addr, escaped_path);
				// r_cons_printf (core->cons, ".!rabin2 -rsB 0x%08"PFMT64x" \"%s\"\n", map->addr, escaped_path);
				free (escaped_path);
				free (filtered_name);
			}
			break;
		default:
			pj_free (pj);
			r_list_free (list);
			goto show_help;
			/* not reached */
		}
	}
beach:
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
	}
	pj_free (pj);
	r_list_free (list);
}

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__

static int dmh_glibc_32(RCore *core, const char *input);
static int dmh_glibc_64(RCore *core, const char *input);
#endif // __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#if R2__WINDOWS__
static int dmh_windows(RCore *core, const char *input);
#endif // R2__WINDOWS__


static ut64 addroflib(RCore *core, const char *libname) {
	RListIter *iter;
	RDebugMap *map;
	if (!core || !libname) {
		return UT64_MAX;
	}
	r_debug_map_sync (core->dbg);
	// RList *list = r_debug_native_modules_get (core->dbg);
	RList *list = r_debug_modules_list (core->dbg);
	r_list_foreach (list, iter, map) {
		if (strstr (r_file_basename(map->name), libname)) {
			return map->addr;
		}
	}
	r_list_foreach (core->dbg->maps, iter, map) {
		if (strstr (r_file_basename(map->name), libname)) {
			return map->addr;
		}
	}
	return UT64_MAX;
}

static RDebugMap *get_closest_map(RCore *core, ut64 addr) {
	RListIter *iter;
	RDebugMap *map;

	r_debug_map_sync (core->dbg);
	RList *list = r_debug_modules_list (core->dbg);
	r_list_foreach (list, iter, map) {
		if (addr != UT64_MAX && (addr >= map->addr && addr < map->addr_end)) {
			return map;
		}
	}
	r_list_foreach (core->dbg->maps, iter, map) {
		if (addr != UT64_MAX && (addr >= map->addr && addr < map->addr_end)) {
			return map;
		}
	}
	return NULL;
}

#if __APPLE__
#include "dmh_macos.inc.c"
#elif __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#include "dmh_glibc.inc.c"
#elif R2__WINDOWS__
#include "dmh_windows.inc.c"
#undef R_LOG_ORIGIN
#define R_LOG_ORIGIN "cmd.debug"
#endif

static bool cmd_dmh(RCore *core, const char *input) {
	const char *m = r_config_get (core->config, "dbg.malloc");
	if (!m || R_STR_ISEMPTY (input)) {
		return false;
	}
	if (!strcmp ("glibc", m)) {
#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
		if (core->rasm->config->bits == 64) {
			return dmh_glibc_64 (core, input + 1);
		}
		return dmh_glibc_32 (core, input + 1);
#else
		R_LOG_WARN ("glibc is not supported for this platform");
#endif
#if HAVE_JEMALLOC
	} else if (!strcmp ("jemalloc", m)) {
		if (core->rasm->config->bits == 64) {
			dmh_jemalloc_64 (core, input + 1);
		} else {
			dmh_jemalloc_32 (core, input + 1);
		}
#endif
	} else {
#if __APPLE__
		dmh_macos (core, input + 1);
#elif R2__WINDOWS__
		dmh_windows (core, input + 1);
#else
		R_LOG_WARN ("No heap allocation support");
		return false;
#endif
	}
	if (input[1] == 'j') {
		r_cons_println (core->cons, "{}");
	}
	return true;
}

static bool get_bin_info(RCore *core, const char *file, ut64 baseaddr, PJ *pj, int mode, bool symbols_only, RCoreBinFilter *filter) {
#if __APPLE__
	switch (mode) {
	case R_MODE_SET:
		r_core_cmdf (core, ".dmi* 0x%08"PFMT64x" %s", baseaddr, file);
		break;
	case R_MODE_RADARE:
		r_core_cmdf (core, "!!rabin2 -rsEB 0x%08"PFMT64x" %s", baseaddr, file);
		break;
	default:
		r_core_cmdf (core, "!!rabin2 -E -B 0x%08"PFMT64x" %s", baseaddr, file);
		break;
	}
	return true;
#else
	int fd = r_io_fd_open (core->io, file, R_PERM_R, 0);
	if (fd == -1) {
		return false;
	}
	RBinFileOptions opt = {0};
	opt.fd = fd;
	opt.sz = r_io_fd_size (core->io, fd);
	opt.baseaddr = baseaddr;
	RBinFile *obf = r_bin_cur (core->bin);
	if (!r_bin_open_io (core->bin, &opt)) {
		r_io_fd_close (core->io, fd);
		return false;
	}
	int action = R_CORE_BIN_ACC_ALL & ~R_CORE_BIN_ACC_INFO;
	if (symbols_only || filter->name) {
		action = R_CORE_BIN_ACC_SYMBOLS;
	} else if (mode == R_MODE_SET || mode == R_MODE_RADARE) {
		action &= ~R_CORE_BIN_ACC_ENTRIES & ~R_CORE_BIN_ACC_MAIN;
	}
	r_core_bin_info (core, action, pj, mode, 1, filter, NULL);
	RBinFile *bf = r_bin_cur (core->bin);
	if (bf) {
		r_bin_file_delete (core->bin, bf->id);
	}
	if (obf) {
		r_bin_file_set_cur_binfile (core->bin, obf);
	}
	r_io_fd_close (core->io, fd);
	return true;
#endif
}

static int __r_debug_snap_diff(RCore *core, int idx) {
	ut32 count = 0;
	RDebug *dbg = core->dbg;
	ut32 oflags = core->print->flags;
	bool col = core->cons->columns > 123;
	RDebugSnap *snap;
	RListIter *iter;
	core->print->flags |= R_PRINT_FLAGS_DIFFOUT;
	r_list_foreach (dbg->snaps, iter, snap) {
		if (count == idx) {
			ut8 *b = malloc (snap->size);
			if (R_LIKELY (b)) {
				dbg->iob.read_at (dbg->iob.io, snap->addr, b , snap->size);
				r_print_hexdiff (core->print,
						snap->addr, snap->data,
						snap->addr, b,
						snap->size, col);
				free (b);
			} else {
				R_LOG_ERROR ("Cannot allocate snapshot");
			}
		}
		count ++;
	}
	core->print->flags = oflags;
	return 0;
}

static int cmd_debug_map_snapshot(RCore *core, const char *input) {
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_dms);
		break;
	case '-':
		if (input[1] == '*') {
			r_debug_snap_delete (core->dbg, -1);
		} else {
			r_debug_snap_delete (core->dbg, r_num_math (core->num, input + 1));
		}
		break;
	case ' ':
		r_debug_snap (core->dbg, r_num_math (core->num, input + 1));
		break;
	case '.':
		r_debug_snap (core->dbg, core->addr);
		break;
	case 'C':
		r_debug_snap_comment (core->dbg, atoi (input + 1), strchr (input, ' '));
		break;
	case 'd':
		__r_debug_snap_diff (core, atoi (input + 1));
		break;
	case 'a':
		r_debug_snap_all (core->dbg, 0);
		break;
	case 'w': // "dmsw"
		r_debug_snap_all (core->dbg, R_PERM_RW);
		break;
	case 0:
	case 'j':
	case '*':
		r_debug_snap_list (core->dbg, -1, input[0]);
		break;
	default:
		r_core_return_invalid_command (core, "dms", input[0]);
		break;
	}
	return 0;
}

static int cmd_debug_map(RCore *core, const char *input) {
	RListIter *iter;
	RDebugMap *map;
	ut64 addr = core->addr;

	switch (input[0]) {
	case 's': // "dms"
		if (strchr (input, '?')) {
			r_core_cmd_help_contains (core, help_msg_dm, "dms");
		}
		cmd_debug_map_snapshot (core, input + 1);
		break;
	case '.': // "dm."
		r_debug_map_list (core->dbg, addr, input);
		break;
	case 'm': // "dmm"
		if (!strcmp (input + 1, ".*")) {
			cmd_debug_modules (core, ':');
		} else {
			cmd_debug_modules (core, input[1]);
		}
		break;
	case '?': // "dm?"
		r_core_cmd_help (core, help_msg_dm);
		break;
	case 'p': // "dmp"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_dmp);
		} else if (input[1] == '.' || !input[1]) {
			ut64 addr = core->addr;
			RList *list = core->dbg->maps;
			if (list) {
				r_list_foreach (list, iter, map) {
					if (addr >= map->addr && addr < map->addr_end) {
						r_cons_println (core->cons, r_str_rwx_i (map->perm));
						break;
					}
				}
			} else {
				R_LOG_ERROR ("Try with omp instead");
			}
		} else if (input[1] == ' ') {
			int perms;
			ut64 size = 0, addr;
			char *p = strchr (input + 2, ' ');
			if (p) {
				bool failed_somehow = false;
				*p++ = 0;
				char *q = strchr (p, ' ');
				if (q) {
					*q++ = 0;
					addr = r_num_math (core->num, input + 2);
					if (core->num->nc.errors != 0) {
						failed_somehow = true;
						R_LOG_ERROR ("Invalid address (%s)", input + 2);
					}
					size = r_num_math (core->num, p);
					if (core->num->nc.errors != 0) {
						failed_somehow = true;
						R_LOG_ERROR ("Invalid size (%s)", p);
					}
					perms = r_str_rwx (q);
					if (perms < 1) {
						failed_somehow = true;
						R_LOG_ERROR ("Invalid perms (%s)", q);
					}
				} else {
					failed_somehow = true;
				}
				if (failed_somehow) {
					R_LOG_ERROR ("Invalid arguments. See dmp?");
				} else {
					r_debug_map_protect (core->dbg, addr, size, perms);
				}
			} else {
				r_debug_map_sync (core->dbg); // update process memory maps
				addr = UT64_MAX;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (core->addr >= map->addr  && core->addr < map->addr_end) {
						addr = map->addr;
						size = map->size;
						break;
					}
				}
				perms = r_str_rwx (input + 2);
				if (addr != UT64_MAX && perms >= 0) {
					r_debug_map_protect (core->dbg, addr, size, perms);
				} else {
					R_LOG_WARN ("See dmp?");
				}
			}
		} else {
			r_core_return_invalid_command (core, "dmp", input[1]);
		}
		break;
	case 'd': // "dmd"
		switch (input[1]) {
		case 'a': return dump_maps (core, 0, NULL);
		case 'w': return dump_maps (core, R_PERM_RW, NULL);
		case ' ': return dump_maps (core, -1, input + 2);
		case 0: return dump_maps (core, -1, NULL);
		case '?':
		default:
			r_core_cmd_help_match (core, help_msg_dm, "dmd");
			break;
		}
		break;
	case 'l': // "dml"
		if (input[1] != ' ') {
			r_core_cmd_help_match (core, help_msg_dm, "dml");
			return false;
		}
		r_debug_map_sync (core->dbg); // update process memory maps
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				const char *filename = r_str_trim_head_ro (input + 2);
				size_t sz;
				char *buf = r_file_slurp (filename, &sz);
				//TODO: use mmap here. we need a portable implementation
				if (!buf) {
					R_LOG_ERROR ("Cannot read %s", filename);
					return false;
				}
				r_io_write_at (core->io, map->addr, (const ut8*)buf, sz);
				if (sz != map->size) {
					R_LOG_INFO ("File size differs from region size "
							"(%" PFMT64u " vs %" PFMT64d ")",
							(ut64)sz, map->size);
				}
				R_LOG_INFO ("Loaded %"PFMT64u" byte(s) into the map region at 0x%08"PFMT64x, (ut64)sz, map->addr);
				free (buf);
				return true;
			}
		}
		R_LOG_WARN ("Not in a matching debug region");
		return false;
	case 'i': // "dmi"
		switch (input[1]) {
		case '\0': // "dmi" alias of "dmm"
			r_core_cmd (core, "dmm", 0);
			break;
		case 's': // "dmis"
			r_core_cmdf (core, ".dmi* %s", input + 2);
			break;
		case ' ': // "dmi "
		case '*': // "dmi*"
		case 'v': // "dmiv"
		case 'j': // "dmij"
		case 'q': // "dmiq"
		case 'a': // "dmia"
			{
				const char *libname = NULL, *symname = NULL, *a0;
				int mode;
				ut64 baddr = 0LL;
				char *ptr;
				int i = 1;
				bool symbols_only = true;
				if (input[1] == 'a') {
					symbols_only = false;
					input++;
				}
				PJ *pj = NULL;
				switch (input[1]) {
				case 's':
					mode = R_MODE_SET;
					break;
				case '*':
					mode = R_MODE_RADARE;
					break;
				case 'j':
					mode = R_MODE_JSON;
					pj = r_core_pj_new (core);
					if (!pj) {
						return false;
					}
					break;
				case 'q':
					mode = input[2] == 'q' ? input++, R_MODE_SIMPLEST : R_MODE_SIMPLE;
					break;
				default:
					mode = R_MODE_PRINT;
					break;
				}
				ptr = r_str_trim_dup (input + 2);
				if (!ptr || !*ptr) {
					r_core_cmd (core, "dmm", 0);
					free (ptr);
					break;
				}
				if (symbols_only) {
					i = r_str_word_set0 (ptr);
				}
				switch (i) {
				case 2:
					symname = r_str_word_get0 (ptr, 1);
					// fall through
				case 1:
					a0 = r_str_word_get0 (ptr, 0);
					addr = r_num_get (core->num, a0);
					if (!addr || addr == UT64_MAX) {
						libname = r_str_word_get0 (ptr, 0);
					}
					break;
				}
				if (libname && !addr) {
					addr = addroflib (core, r_file_basename (libname));
					if (addr == UT64_MAX) {
						R_LOG_ERROR ("Unknown library, or not found in dm");
					}
				}
				map = get_closest_map (core, addr);
				if (map) {
					RCoreBinFilter filter;
					filter.addr = 0LL;
					filter.name = (char *)symname;
					baddr = map->addr;

					if (libname) {
						const char *file = map->file? map->file: map->name;
						char *newfile = NULL;
						if (!r_file_exists (file)) {
							newfile = r_file_temp ("memlib");
							if (newfile) {
								file = newfile;
								r_core_cmdf (core, "wtf %s 0x%" PFMT64x " @ 0x%" PFMT64x " 2> %s",
										file, map->size, baddr, R_SYS_DEVNULL);
							}
						}
						get_bin_info (core, file, baddr, pj, mode, symbols_only, &filter);
						if (newfile) {
							if (!r_file_rm (newfile)) {
								R_LOG_ERROR ("Cannot remove %s", newfile);
							}
							free (newfile);
						}
					} else {
						r_bin_set_baddr (core->bin, map->addr);
						r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, pj, input[1] == '*', true, &filter, NULL);
						r_bin_set_baddr (core->bin, baddr);
					}
				}
				if (mode == R_MODE_JSON) {
					r_cons_println (core->cons, pj_string (pj));
					pj_free (pj);
				}
				free (ptr);
			}
			break;
		case '.': // "dmi."
			if (r_config_get_b (core->config, "cfg.debug")) {
				ut64 addr = core->addr;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (!map->shared) {
						continue;
					}
					if (addr >= map->addr && addr < map->addr_end) {
						r_cons_printf (core->cons, "%s\n", map->name);
				//		break;
					}
				}
			} else {
				map = get_closest_map (core, addr);
				if (map) {
					ut64 closest_addr = UT64_MAX;
					RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
					RBinSymbol *symbol, *closest_symbol = NULL;
					R_VEC_FOREACH (symbols, symbol) {
						if (symbol->vaddr > addr) {
							if (symbol->vaddr - addr < closest_addr) {
								closest_addr = symbol->vaddr - addr;
								closest_symbol = symbol;
							}
						} else {
							if (addr - symbol->vaddr < closest_addr) {
								closest_addr = addr - symbol->vaddr;
								closest_symbol = symbol;
							}
						}
					}
					if (closest_symbol) {
						RCoreBinFilter filter = {
							.addr = 0LL,
							.name = (char *) closest_symbol->name
						};
						r_bin_set_baddr (core->bin, map->addr);
						r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, NULL, false, true, &filter, NULL);
					}
				}
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_dmi);
			break;
		default:
			r_core_return_invalid_command (core, "dmi", input[1]);
			break;
		}
		break;
	case 'S': // "dmS"
		{ // Move to a separate function
			const char *libname = NULL, *sectname = NULL, *mode = "";
			ut64 baddr = 0LL;
			char *ptr;

			if (input[1] == '*') {
				ptr = strdup (r_str_trim_head_ro ((char*)input + 2));
				mode = "-r ";
			} else {
				ptr = strdup (r_str_trim_head_ro ((char*)input + 1));
			}
			int i = r_str_word_set0 (ptr);

			addr = UT64_MAX;
			switch (i) {
			case 2: // get section name
				sectname = r_str_word_get0 (ptr, 1);
				/* fallthrou */
			case 1: // get addr|libname
				if (isdigit (*ptr)) {
					const char *a0 = r_str_word_get0 (ptr, 0);
					addr = r_num_math (core->num, a0);
				} else {
					addr = UT64_MAX;
				}
				if (!addr || addr == UT64_MAX) {
					libname = r_str_word_get0 (ptr, 0);
				}
				break;
			}
			r_debug_map_sync (core->dbg); // update process memory maps
			RList *list = r_debug_modules_list (core->dbg);
			r_list_foreach (list, iter, map) {
				if ((!libname ||
					 (addr != UT64_MAX && (addr >= map->addr && addr < map->addr_end)) ||
					 (libname && (strstr (map->name, libname))))) {
					baddr = map->addr;
					char *res;
					const char *file = map->file? map->file: map->name;
					char *name = r_str_escape ((char *)r_file_basename (file));
					char *filesc = r_str_escape (file);
					/* TODO: do not spawn. use RBin API */
					if (sectname) {
						char *sect = r_str_escape (sectname);
						res  = r_sys_cmd_strf ("env RABIN2_PREFIX=\"%s\" rabin2 %s-B 0x%08"
							PFMT64x" -S \"%s\" | grep \"%s\"", name, mode, baddr, filesc, sect);
						free (sect);
					} else {
						res = r_sys_cmd_strf ("env RABIN2_PREFIX=\"%s\" rabin2 %s-B 0x%08"
							PFMT64x" -S \"%s\"", name, mode, baddr, filesc);
					}
					free (filesc);
					r_cons_println (core->cons, res);
					free (name);
					free (res);
					if (libname || addr != UT64_MAX) { //only single match requested
						break;
					}
				}
			}
			free (ptr);
		}
		break;
	case ' ': // "dm "
		{
			int size;
			char *p = strchr (input + 2, ' ');
			if (p) {
				*p++ = 0;
				addr = r_num_math (core->num, input + 1);
				size = r_num_math (core->num, p);
				r_debug_map_alloc (core->dbg, addr, size, false);
			} else {
				r_core_cmd_help_match (core, help_msg_dm, "dm");
				return false;
			}
		}
		break;
	case '-': // "dm-"
		if (input[1] != ' ') {
			r_core_cmd_help_match (core, help_msg_dm, "dm-");
			break;
		}
		addr = r_num_math (core->num, input + 2);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				r_debug_map_dealloc(core->dbg, map);
				r_debug_map_sync (core->dbg);
				return true;
			}
		}
		R_LOG_ERROR ("The address doesn't match with any map");
		break;
	case 'L': // "dmL"
		{
			int size;
			char *p = strchr (input + 2, ' ');
			if (p) {
				*p++ = 0;
				addr = r_num_math (core->num, input + 1);
				size = r_num_math (core->num, p);
				r_debug_map_alloc (core->dbg, addr, size, true);
			} else {
				r_core_cmd_help_match (core, help_msg_dm, "dmL");
				return false;
			}
		}
		break;
	case '\0': // "dm"
	case '*': // "dm*"
	case 'j': // "dmj"
	case 'q': // "dmq"
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_debug_map_sync (core->dbg); // update process memory maps
			r_debug_map_list (core->dbg, core->addr, input);
		} else {
			R_LOG_INFO ("dm requires the debugger or use `om` instead");
			if (*input == 'j') {
				r_cons_println (core->cons, "{}");
			}
		}
		break;
	case '=': // "dm="
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_debug_map_sync (core->dbg);
			r_debug_map_list_visual (core->dbg, core->addr, input,
					r_config_get_i (core->config, "scr.color"));
		} else {
			R_LOG_WARN ("Memory Maps require to be (cfg.debug/-d) in debugger mode. Otherwise use 'om'");
		}
		break;
	case 'h': // "dmh"
		return cmd_dmh (core, input);
	}
	return true;
}

HEAPTYPE(ut64);

static int regcmp(const void *a, const void *b) {
	const ut64 *A = (const ut64*)a;
	const ut64 *B = (const ut64*)b;
	if (*A > *B) {
		return 1;
	}
	if (*A == *B) {
		return 0;
	}
	return -1;
}

static bool regcb(void *u, const ut64 k, const void *v) {
	RList *sorted = (RList*) u;
	ut64 *n = ut64_new (k);
	r_list_add_sorted (sorted, n, regcmp);
	return true;
}

R_API void r_core_debug_ri(RCore *core, RReg *reg, int mode) {
	R_RETURN_IF_FAIL (core && reg);
	RList *list = r_reg_get_list (reg, R_REG_TYPE_GPR);
	RListIter *iter;
	RRegItem *r;
	HtUP *db = ht_up_new0 ();

	r_list_foreach (list, iter, r) {
		if (r->size != core->rasm->config->bits) {
			continue;
		}
		ut64 value = r_reg_get_value (reg, r);
		RList *list = ht_up_find (db, value, NULL);
		if (!list) {
			list = r_list_newf (NULL);
			ht_up_update (db, value, list);
		}
		r_list_append (list, r->name);
	}

	RList *sorted = r_list_newf (free);
	ht_up_foreach (db, regcb, sorted);
	ut64 *addr;
	r_list_foreach (sorted, iter, addr) {
		int rwx = 0;
		RDebugMap *map = r_debug_map_get (core->dbg, *addr);
		if (map) {
			rwx = map->perm;
		}
		r_cons_printf (core->cons, " %s  ", r_str_rwx_i (rwx));

		r_cons_printf (core->cons, "0x%08"PFMT64x" ", *addr);
		RList *list = ht_up_find (db, *addr, NULL);
		if (list) {
			RListIter *iter;
			const char *r;
			r_cons_print (core->cons, Color_YELLOW);
			r_list_foreach (list, iter, r) {
				r_cons_printf (core->cons, " %s", r);
			}
			r_cons_print (core->cons, Color_RESET);
			ut64 o_offset = core->addr;
			char *rrstr = r_core_anal_hasrefs (core, *addr, true);
			core->addr = o_offset;
			if (R_STR_ISNOTEMPTY (rrstr) && strchr (rrstr, 'R')) {
				r_cons_printf (core->cons, "    ;%s"Color_RESET, rrstr);
			}
			r_cons_newline (core->cons);
		}
	}
	r_list_free (sorted);
	ht_up_free (db);
}

static const char *mode_to_bitstr(int mode) {
	switch (mode) {
	case '3': return "32";
	case '6': return "64";
	case '8': return "8";
	case '1': return "16";
	}
	return "";
}

R_API void r_core_debug_rr(RCore *core, RReg *reg, int mode) {
	R_RETURN_IF_FAIL (core && reg);
	char *color = "";
	char *colorend = "";
	const int scr_color = r_config_get_i (core->config, "scr.color");
	bool use_colors = scr_color != 0;
	int delta = 0;
	ut64 diff, value;
	RList *list = r_reg_get_list (reg, R_REG_TYPE_GPR);
	RListIter *iter;
	RRegItem *r;
	RTable *t = r_core_table_new (core, "regs");

	if (mode == 'j') {
		r_config_set_i (core->config, "scr.color", 0);
		use_colors = 0;
	}

	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->context->pal.x) ? core->cons->context->pal.x
		color = ConsP(creg): Color_BWHITE;
		colorend = Color_RESET;
	}

	r_table_set_columnsf (t, "ssss", "role", "reg", "value", "refstr");
	const char *str = mode_to_bitstr (mode);
	const int pcbits = grab_bits (core, str, NULL);
	r_list_foreach (list, iter, r) {
		if (r->size != pcbits) {
			continue;
		}

		value = r_reg_get_value (core->dbg->reg, r);
		delta = 0;
		int regSize = r->size;
		//XXX: support larger regSize
		if (regSize < 80) {
			r_reg_arena_swap (core->dbg->reg, false);
			diff = r_reg_get_value (core->dbg->reg, r);
			r_reg_arena_swap (core->dbg->reg, false);
			delta = value-diff;
		}

		const char *role = "";
		int i;
		for (i = 0; i < R_REG_ALIAS_LAST; i++) {
			const char *t = r_reg_alias_getname (reg, i);
			if (t && !strcmp (t, r->name)) {
				role = r_reg_alias_tostring (i);
			}
		}

		char *namestr = NULL;
		char *valuestr = NULL;
		if (delta && use_colors) {
			namestr = r_str_newf ("%s%s%s", color, r->name, colorend);
			valuestr = r_str_newf ("%s0x%"PFMT64x"%s", color, value, colorend);
			r_cons_print (core->cons, Color_RESET);
		} else {
			namestr = strdup (r->name);
			valuestr = r_str_newf ("0x%"PFMT64x, value);
		}
		ut64 o_offset = core->addr;
		char *rrstr = r_core_anal_hasrefs (core, value, true);
		core->addr = o_offset;
		if (!rrstr) {
			rrstr = strdup ("");
		}

		r_table_add_rowf (t, "ssss", role, namestr, valuestr, rrstr);
		free (namestr);
		free (valuestr);
		free (rrstr);
	}

	char *s = (mode == 'j')? r_table_tojson (t): r_table_tostring (t);
	r_cons_print (core->cons, s);
	free (s);
	r_table_free (t);
	if (scr_color) {
		r_config_set_i (core->config, "scr.color", scr_color);
	}
}

static void cmd_drpi(RCore *core) {
	int i;
	RListIter *iter;
	RRegItem *ri;
	r_cons_printf (core->cons, "Aliases (Reg->name)\n");
	for (i = 0; i < R_REG_ALIAS_LAST; i++) {
		const char *v = r_str_get_fail (r_reg_alias_getname (core->anal->reg, i), "?");
		r_cons_printf (core->cons, "%d %s %s\n", i, r_reg_alias_tostring (i), v);
	}
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		const char *nmi = r_reg_type_tostring (i);
		r_cons_printf (core->cons, "regset %d (%s)\n", i, nmi);
		RRegSet *rs = &core->anal->reg->regset[i];
		if (!rs || !rs->arena) {
			r_cons_printf (core->cons, "* arena %s no\n", r_reg_type_tostring (i));
			continue;
		}
		r_cons_printf (core->cons, "* arena %s size %d\n", r_reg_type_tostring (i), rs->arena->size);
		r_list_foreach (rs->regs, iter, ri) {
			const char *tpe = r_reg_type_tostring (ri->type);
			const char *arn = r_reg_type_tostring (ri->arena);
			r_cons_printf (core->cons, "   %s %s @ %s (offset: %d  size: %d)", ri->name, tpe, arn, ri->offset / 8, ri->size / 8);
			if ((ri->offset / 8) + (ri->size / 8) > rs->arena->size) {
				r_cons_printf (core->cons, " *OVERFLOW*");
			}
			r_cons_newline (core->cons);
		}
	}
}

/* XXX "from" is irrelevant, control flow into here is determined by cfg.debug
 * right now, i.e.: if cfg.debug == 1, arp -> drp, so from == 'd' despite
 * entering arp, so you still get the wrong help for your input.
 */
static void cmd_reg_profile(RCore *core, char from, const char *str) { // "arp" and "drp"
	const char *ptr;
	const bool cfg_debug = r_config_get_b (core->config, "cfg.debug");
	if (cfg_debug) {
		// XXX bas practice
		RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
		if (plugin && plugin->reg_profile) {
			char *rp = plugin->reg_profile (core->dbg);
			r_reg_set_profile_string (core->dbg->reg, rp);
			free (rp);
		}
	}
	RReg *r = cfg_debug? core->dbg->reg: core->anal->reg;
	switch (str[1]) {
	case '\0': // "drp" "arp"
		if (r->reg_profile_str) {
			r_cons_println (core->cons, r->reg_profile_str);
		} else {
			R_LOG_ERROR ("No register profile defined. Try 'dr.'");
		}
		break;
	case 'c': // "drpc" "arpc"
		if (core->dbg->reg->reg_profile_cmt) {
			r_cons_println (core->cons, r->reg_profile_cmt);
		}
		break;
	case '*': // "drp*"
		{
			RList *list = r_reg_get_list (core->anal->reg, R_REG_TYPE_GPR);
			RListIter *iter;
			RRegItem *ri;
			r_list_foreach (list, iter, ri) {
				if (ri->type != R_REG_TYPE_GPR) {
					continue;
				}
				r_cons_printf (core->cons, "f %s.%s=%d\n", "gpr", ri->name, ri->offset / 8);
			}
		}
		break;
	case 'g': // "drpg" "arpg"
		ptr = r_str_trim_head_ro (str + 2);
		if (!R_STR_ISEMPTY (ptr)) {
			char *r2profile = r_reg_parse_gdb_profile (ptr);
			if (r2profile) {
				r_cons_println (core->cons, r2profile);
				r_core_return_value (core, R_CMD_RC_SUCCESS);
				free (r2profile);
			} else {
				r_core_return_value (core, R_CMD_RC_FAILURE);
				R_LOG_WARN ("Cannot parse gdb profile");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_drp, "drpg");
		}
		break;
	case ' ': // "drp " "arp "
		ptr = r_str_trim_head_ro (str + 2);
		r_reg_set_profile (r, ptr);
		r_debug_plugin_set_reg_profile (core->dbg, ptr);
		break;
	case '.': { // "drp."
		RRegSet *rs = r_reg_regset_get (r, R_REG_TYPE_GPR);
		if (rs) {
			eprintf ("size = %d\n", rs->arena->size);
		}
		}
		break;
	case 'i': // "drpi" "arpi"
		cmd_drpi (core);
		break;
	case 's': // "drps" "arps"
		if (str[2] == ' ') {
			ut64 n = r_num_math (core->num, str+2);
			// TODO: move this thing into the r_reg API
			RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
			if (rs && n>0) {
				RListIter *iter;
				RRegArena *arena;
				r_list_foreach (rs->pool, iter, arena) {
					ut8 *newbytes = calloc (1, n);
					if (newbytes) {
						free (arena->bytes);
						arena->bytes = newbytes;
						arena->size = n;
					} else {
						R_LOG_ERROR ("Cannot allocate %d", (int)n);
					}
				}
			} else {
				R_LOG_ERROR ("Invalid arena size");
			}
		} else {
			RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
			if (rs) {
				r_cons_printf (core->cons, "%d\n", rs->arena->size);
			} else {
				R_LOG_ERROR ("Cannot find GPR register arena");
			}
		}
		break;
	case 'j': // "drpj" "arpj"
		{
			// "drpj" .. dup from "arpj"
			RListIter *iter;
			RRegItem *ri;
			int i;
			PJ *pj = r_core_pj_new (core);
			if (!pj) {
				return;
			}
			pj_o (pj);
			pj_k (pj, "alias_info");
			pj_a (pj);
			for (i = 0; i < R_REG_ALIAS_LAST; i++) {
				if (core->dbg->reg->alias[i]) {
					pj_o (pj);
					pj_kn (pj, "role", i);
					pj_ks (pj, "role_str", r_reg_alias_tostring (i));
					pj_ks (pj, "reg", r_reg_alias_getname (core->dbg->reg, i));
					pj_end (pj);
				}
			}
			pj_end (pj);
			pj_k (pj, "reg_info");
			pj_a (pj);
			for (i = 0; i < R_REG_TYPE_LAST; i++) {
				r_list_foreach (core->dbg->reg->regset[i].regs, iter, ri) {
					pj_o (pj);
					pj_kn (pj, "type", ri->type);
					pj_ks (pj, "type_str", r_reg_type_tostring (ri->type));
					pj_ks (pj, "name", ri->name);
					pj_kn (pj, "size", ri->size);
					pj_kn (pj, "offset", ri->offset);
					pj_end (pj);
				}
			}
			pj_end (pj); // "]"
			pj_end (pj); // "}"
			r_cons_printf (core->cons, "%s", pj_string (pj));
			pj_free (pj);
		}
		break;
	case '?': // "drp?" "arp?"
	default:
		{
			// i hate this so much
			int i;
			int num_strings = 0;
			char **help_msg;
			const char * const *p = help_msg_drp;
			while (*p) {
				num_strings += 3;
				p = &p[3];
			}

			help_msg = R_NEWS (char *, num_strings+1);
			help_msg[num_strings] = NULL;
			for (i = 0; i < num_strings; i++) {
				help_msg[i] = strdup (help_msg_drp[i]);
			}

			// see function comment
			// eprintf ("%c\n", from);
			if (from == 'a') {
				for (i = 0; !r_str_startswith (help_msg[i], "NOTE:"); i++) {
					help_msg[i] = r_str_replace (help_msg[i], "drp", "arp", true);
				}
			}
			r_core_cmd_help (core, (const char * const *)help_msg);

			for (i = 0; i < num_strings; i++) {
				free (help_msg[i]);
			}
			free (help_msg);
		}
		break;
	}
}


// helpers for packed registers
#define NUM_PACK_TYPES 6
#define NUM_INT_PACK_TYPES 4
static const int pack_sizes[NUM_PACK_TYPES] = { 8, 16, 32, 64, 32, 64 };
static const char *pack_format[NUM_PACK_TYPES] = {
	"%s0x%02" PFMT64x, "%s0x%04" PFMT64x, "%s0x%08" PFMT64x,
	"%s0x%016" PFMT64x, "%s%lf" , "%s%lf"
};

#define pack_print(i, reg, pack_type_index) r_cons_printf (core->cons, pack_format[pack_type_index], i != 0 ? " " : "", reg);

static void cmd_debug_reg_print_packed_reg(RCore *core, RRegItem *item, char explicit_size, char* pack_show)	{
	int pi, i;
	for (pi = 0; pi < NUM_PACK_TYPES; pi++) {
		if (!explicit_size || pack_show[pi]) {
			for (i = 0; i < item->packed_size / pack_sizes[pi]; i++) {
				ut64 res = r_reg_get_pack(core->dbg->reg, item, i, pack_sizes[pi]);
				if (pi > NUM_INT_PACK_TYPES-1)	{ // are we printing int or double?
					if (pack_sizes[pi] == 64)	{
						double dres;
						memcpy ((void*)&dres, (void*)&res, 8);
						pack_print (i, dres, pi);
					} else if (pack_sizes[pi] == 32) {
						float fres;
						memcpy ((void*)&fres, (void*)&res, 4);
						pack_print (i, fres, pi);
					}
				} else {
					pack_print (i, res, pi);
				}
			}
			r_cons_newline (core->cons);
		}
	}
}

static char *__table_format_string(RTable *t, int fmt) {
	switch (fmt) {
	case 'j': return r_table_tojson (t);
	case 's': return r_table_tostring (t);
	}
	return r_table_tostring (t);
}

static void __tableRegList(RCore *core, RReg *reg, const char *str) {
	int i;
	RRegItem *e;
	RTable *t = r_core_table_new (core, "regprofile");
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	RTableColumnType *typeBoolean = r_table_type ("boolean");
	r_table_add_column (t, typeNumber, "offset", 0);
	r_table_add_column (t, typeNumber, "size", 0);
	r_table_add_column (t, typeNumber, "psize", 0);
	r_table_add_column (t, typeNumber, "index", 0);
	r_table_add_column (t, typeNumber, "arena", 0);
	r_table_add_column (t, typeBoolean, "float", 0);
	r_table_add_column (t, typeString, "name", 0);
	r_table_add_column (t, typeString, "flags", 0);
	r_table_add_column (t, typeString, "comment", 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RList *list = r_reg_get_list (reg, i);
		RListIter *iter;
		r_list_foreach (list, iter, e) {
			r_strf_var (s_off, 32, "%d", e->offset);
			r_strf_var (s_siz, 32, "%d", e->size);
			r_strf_var (s_psz, 32, "%d", e->packed_size);
			r_strf_var (s_idx, 32, "%d", e->index);
			r_strf_var (s_iii, 32, "%d", i);
			r_table_add_row (t,
					s_off, s_siz, s_psz, s_idx, s_iii,
					r_str_bool (e->is_float),
					r_str_get (e->name),
					r_str_get (e->flags),
					r_str_get (e->comment),
					NULL
					);
		}
	}
	const char fmt = *str++;
	const char *q = str;
	if (r_table_query (t, q)) {
		char *s = __table_format_string (t, fmt);
		r_cons_printf (core->cons, "%s\n", s);
		free (s);
	}
	r_table_free (t);
}

static void cmd_debug_reg(RCore *core, const char *str) {
	size_t i;
	char *arg;
	RRegItem *r;
	const char *name;
	int size, type = R_REG_TYPE_GPR;
	int bits = R_SYS_BITS_CHECK (core->dbg->bits, 64)? 64: 32;
	const bool use_colors = r_config_get_i (core->config, "scr.color") > 0;
	int newbits = atoi (R_STR_ISNOTEMPTY (str)? str + 1: "");
	if (newbits > 0) {
		bits = newbits;
	}
#undef ConsP
#define ConsP(x) (core->cons && core->cons->context->pal.x)? core->cons->context->pal.x
	const char *use_color = use_colors? (ConsP(creg): Color_BWHITE): NULL;
	if (!str) {
		str = "";
	}
	switch (str[0]) {
	case 'C': // "drC"
		{
			const bool json_out = str[1] == 'j';
			name = r_str_trim_head_ro (json_out ? str + 3 : str + 2);
			if (name) {
				r = r_reg_get (core->dbg->reg, name , -1);
				if (r) {
					if (json_out) {
						PJ *pj = r_core_pj_new (core);
						if (!pj) {
							return;
						}
						pj_o (pj);
						if (r->comment) {
							pj_ks (pj, r->name, r->comment);
						} else {
							pj_knull (pj, r->name);
						}
						pj_end (pj);
						const char *s = pj_string (pj);
						r_cons_println (core->cons, s);
						pj_free (pj);
					} else {
						if (r->comment) {
							r_cons_printf (core->cons, "%s\n", r->comment);
						} else {
							R_LOG_ERROR ("Register %s doesn't have any comments", name);
						}
					}
				} else {
					R_LOG_ERROR ("Register %s not found", name);
				}
			} else {
			}
		}
		break;
	case 'a':
		r_core_cmdf (core, "ara%s", str + 1);
		break;
	case '-': // "dr-"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, NULL, '-', 0);
		break;
	case '?': // "dr?"
		if (str[1]) {
			RListIter *iter;
			char *all = (char *)r_str_trim_head_ro (str + 1);
			if (!strcmp (all, "?")) { // "dr??"
				all = r_core_cmd_str (core, "drp~=[0]");
				all = r_str_replace (all, "\n", " ", 1);
			} else {
				all = strdup (all);
			}
			char *arg;
			RList *args = r_str_split_list (all, " ", 0);
			r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false); //R_REG_TYPE_GPR, false);
			int count = r_list_length (args);
			r_list_foreach (args, iter, arg) {
				r = r_reg_get (core->dbg->reg, arg, -1);
				if (!r) {
					continue;
				}
				ut64 off = r_debug_reg_get (core->dbg, arg);
				if (count == 1) {
					r_cons_printf (core->cons, "0x%08"PFMT64x"\n", off);
				} else {
					int type = r_reg_alias_fromstring (arg);
					const char *r = arg;
					if (type != -1) {
						r = r_reg_alias_getname (core->dbg->reg, type);
					}
					r_cons_printf (core->cons, "%3s %3s 0x%08"PFMT64x"\n", arg, r, off);
				}
				core->num->value = off;
			}
			free (all);
			r_list_free (args);
		} else {
			r_core_cmd_help (core, help_msg_dr);
		}
		break;
	case 'l': // "drl[j]"
		{
			const bool json_out = str[1] == 'j';
			RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
			if (rs) {
				RRegItem *r;
				RListIter *iter;
				i = 0;
				PJ *pj = NULL;
				if (json_out) {
					pj = r_core_pj_new (core);
					if (!pj) {
						return;
					}
					pj_a (pj);
				}
				r_list_foreach (rs->regs, iter, r) {
					if (json_out) {
						pj_s (pj, r->name);
						i++;
					} else {
						r_cons_println (core->cons, r->name);
					}
				}
				if (json_out) {
					pj_end (pj);
					const char *s = pj_string (pj);
					r_cons_println (core->cons, s);
					pj_free (pj);
				}
			}
		}
		break;
	case '8': // "dr8"
	case 'b': // "drb"
		{
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
			if (str[0] == '8') {
				r_print_bytes (core->print, buf, len, "%02x", 0);
			} else {
				switch (str[1]) {
				case '1':
					r_print_hexdump (core->print, 0ll, buf, len, 8, 1, 1);
					break;
				case '2':
					r_print_hexdump (core->print, 0ll, buf, len, 16, 2, 1);
					break;
				case '4':
					r_print_hexdump (core->print, 0ll, buf, len, 32, 4, 1);
					break;
				case '8':
					r_print_hexdump (core->print, 0ll, buf, len, 64, 8, 1);
					break;
				default:
					if (core->rasm->config->bits == 64) {
						r_print_hexdump (core->print, 0ll, buf, len, 64, 8, 1);
					} else {
						r_print_hexdump (core->print, 0ll, buf, len, 32, 4, 1);
					}
					break;
				}
			}
			free (buf);
		}
		break;
	case 'e': // "dre"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, NULL, 'e', NULL);
		break;
	case 'c': // "drc"
		// todo: set flag values with drc zf=1
		if (str[1] == 'q') { // "drcq"
			RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
			if (rf) {
				r_cons_printf (core->cons, "s:%d z:%d c:%d o:%d p:%d\n",
						rf->s, rf->z, rf->c, rf->o, rf->p);
				free (rf);
			}
			break;
		}
		if (str[1] == '=') { // "drc="
			RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
			if (rf) {
				r_cons_printf (core->cons, "s:%d z:%d c:%d o:%d p:%d\n",
						rf->s, rf->z, rf->c, rf->o, rf->p);
				free (rf);
			}
		} else if (strchr (str, '=')) {
			char *a = strdup (r_str_trim_head_ro (str + 1));
			char *eq = strchr (a, '=');
			if (eq) {
				*eq++ = 0;
				char *k = a;
				r_str_trim (a);
				bool v = !strcmp (eq, "true") || atoi (eq);
				int type = r_reg_cond_from_string (k);
				if (type != -1) {
					RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						r_reg_cond_bits_set (core->dbg->reg, type, rf, v);
						r_reg_cond_apply (core->dbg->reg, rf);
						r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
						free (rf);
					}
				} else {
					R_LOG_ERROR ("Unknown condition register");
				}
			}
			free (a);
		} else {
			RRegItem *r;
			const char *name = r_str_trim_head_ro (str + 1);
			if (*name && name[1]) {
				r = r_reg_cond_get (core->dbg->reg, name);
				if (r) {
					r_cons_println (core->cons, r->name);
				} else {
					int id = r_reg_cond_from_string (name);
					RRegFlags* rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						int o = r_reg_cond_bits (core->dbg->reg, id, rf);
						r_core_return_value (core, o);
						// orly?
						r_cons_printf (core->cons, "%d\n", o);
						free (rf);
					} else {
						R_LOG_ERROR ("unknown conditional or flag register");
					}
				}
			} else {
				RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
				if (rf) {
					if (*name == '=') {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf (core->cons, "%s:%d ",
									r_reg_cond_tostring (i),
									r_reg_cond_bits (core->dbg->reg, i, rf));
						}
						r_cons_newline (core->cons);
					} else {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf (core->cons, "%d %s\n",
									r_reg_cond_bits (core->dbg->reg, i, rf),
									r_reg_cond_tostring (i));
						}
					}
					free (rf);
				}
			}
		}
		break;
	case 'x': // "drx"
		switch (str[1]) {
		case '\0':
			r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, false);
			r_debug_drx_list (core->dbg);
			break;
		case '-':
			r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, false);
			r_debug_drx_unset (core->dbg, atoi (str + 2));
			r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, true);
			break;
		case ' ': {
			char *s = strdup (str + 2);
			char sl, n, perm;
			int len;
			ut64 off;

			sl = r_str_word_set0 (s);
			if (sl == 4) {
#define arg(x) r_str_word_get0 (s,x)
			        n = (char)r_num_math (core->num, arg (0));
			        off = r_num_math (core->num, arg (1));
			        len = (int)r_num_math (core->num, arg (2));
			        if (len == -1) {
					r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, false);
					r_debug_drx_set (core->dbg, n, 0, 0, 0, 0);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, true);
			        } else {
					perm = (char)r_str_rwx (arg (3));
					if (perm < 0) {
						R_LOG_ERROR ("Invalid permissions string (%s)", arg (3));
					} else {
						r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, false);
						r_debug_drx_set (core->dbg, n, off, len, perm, 0);
						r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, true);
					}
			        }
			} else {
				r_core_cmd_help_match (core, help_msg_dr, "drx");
			}
			free (s);
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_drx);
			break;
		default:
			r_core_return_invalid_command (core, "drx", str[1]);
			break;
		}
		break;
	case 's': // "drs"
		switch (str[1]) {
		case '\0': // "drs"
			r_cons_printf (core->cons, "%d\n", r_list_length (core->dbg->reg->regset[0].pool));
			break;
		case '-': // "drs-"
			r_reg_arena_pop (core->dbg->reg);
			// restore debug registers if in debugger mode
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, true);
			break;
		case '+': // "drs+"
			r_reg_arena_push (core->dbg->reg);
			break;
		case '?': // "drs?"
			r_core_cmd_help (core, help_msg_drs);
			break;
		default:
			r_core_return_invalid_command (core, "drs", str[1]);
			break;
		}
		break;
	case 'v': // "drv"
		if (str[1] == '?') {
			r_core_cmd_help (core, help_msg_drv);
		} else if (str[1] == ' ' || str[1] == 'b' || str[1] == 'd' || str[1] == 'w' || str[1] == 'q' || str[1] == 'l'
				   || str[1] == 'f' || (str[1] == 'y' && str[2] != '\x00')) {
			char explicit_index = 0;
			char explicit_size = 0;
			char explicit_name = 0;
			char pack_show[NUM_PACK_TYPES] = { 0, 0, 0, 0, 0, 0};
			int index = 0;
			int size = 0; // auto
			char *q, *p, *name;
			char *eq = NULL;
			RRegType reg_type = R_REG_TYPE_VEC128;
			if ((str[1] == ' ' && str[2] != '\x00') || (str[1] == 'y' && str[2] == ' ' && str[3] != '\x00')) {
				if (str[1] == 'y') { // support `drvy ymm0` and `drv ymm0`
					str = str + 1;
				}
				name = strdup (str + 2);
				explicit_name = 1;
				eq = strchr (name, '=');
				if (eq) {
					*eq++ = 0;
				}
				p = strchr (name, ' ');
				if (p) {
					*p++ = 0;
					q = strchr (p, ' ');
					if (p[0] != '*') {
						// do not show whole register
						explicit_index = 1;
						index = r_num_math (core->num, p);
					}
					if (q) {
						*q++ = 0;
						size = r_num_math (core->num, q);
						for (i = 0; i < NUM_PACK_TYPES; i++) {
							if (size == pack_sizes[i]) {
								explicit_size = 1;
								pack_show[i] = 1;
							}
						}
						if (!explicit_size) {
							R_LOG_ERROR ("Unsupported wordsize %d", size);
							break;
						}
					}
				}
			} else {
				explicit_size = 1;
				if (str[1] == 'y') {
					reg_type = R_REG_TYPE_VEC256;
					str = str + 1;
				}
				if (str[2] == ' ' && str[3] != '\x00') {
					name = strdup (str + 3);
					explicit_name = 1;
				}
				switch (str[1])	{
				case 'b': // "drvb"
					size = pack_sizes[0];
					pack_show[0] = 1;
					break;
				case 'w': // "drvw"
					size = pack_sizes[1];
					pack_show[1] = 1;
					break;
				case 'd': // "drvd"
					size = pack_sizes[2];
					pack_show[2] = 1;
					break;
				case 'q': // "drvq"
					size = pack_sizes[3];
					pack_show[3] = 1;
					break;
				case 'f': // "drvf"
					size = pack_sizes[4];
					pack_show[4] = 1;
					break;
				case 'l': // "drvl"
					size = pack_sizes[5];
					pack_show[5] = 1;
					break;
				default:
					R_LOG_ERROR ("Unknown command");
					return;
				}
			}
			if (explicit_name) {
				RRegItem *item = r_reg_get (core->dbg->reg, name, -1);
				if (item) {
					if (eq) {
						// TODO: support setting YMM registers
						if (reg_type == R_REG_TYPE_VEC256) {
							R_LOG_WARN ("Setting ymm registers not supported yet!");
						} else {
							ut64 val = r_num_math (core->num, eq);
							r_reg_set_pack (core->dbg->reg, item, index, size, val);
							r_debug_reg_sync (core->dbg, reg_type, true);
						}
					} else {
						r_debug_reg_sync (core->dbg, reg_type, false);
						if (!explicit_index) {
							cmd_debug_reg_print_packed_reg (core, item, explicit_size, pack_show);
						} else {
							ut64 res = r_reg_get_pack (core->dbg->reg, item, index, size);
							// print selected index / wordsize
							r_cons_printf (core->cons, "0x%08" PFMT64x "\n", res);
						}
					}
				} else {
					R_LOG_ERROR ("Cannot find vector register '%s'", name);
				}
				free (name);
			} else {
				// explicit size no name
				RListIter *iter;
				RRegItem *item;
				RList *head;
				r_debug_reg_sync (core->dbg, reg_type, false);
				head = r_reg_get_list (core->dbg->reg, reg_type);
				if (head) {
					r_list_foreach (head, iter, item) {
						if (item->type != reg_type) {
							continue;
						}
						r_cons_printf (core->cons, "%-5s = ", item->name);
						cmd_debug_reg_print_packed_reg (core, item, explicit_size, pack_show);
					}
				}
			}
		} else { // drv # no arg
			if (str[1] == 'y') { // drvy
				r_debug_reg_sync (core->dbg, R_REG_TYPE_VEC256, false);
				r_debug_reg_list (core->dbg, R_REG_TYPE_VEC256, 256, NULL, 0, 0);
			} else { // drv
				r_debug_reg_sync (core->dbg, R_REG_TYPE_VEC128, false);
				r_debug_reg_list (core->dbg, R_REG_TYPE_VEC128, 128, NULL, 0, 0);
			}
		}
		//r_debug_drx_list (core->dbg);
		break;
	case 'f': // "drf"
		// r_debug_drx_list (core->dbg);
		if (str[1] == '?') {
			r_core_cmd_help_match (core, help_msg_dr, "drf");
		} else if (str[1] == ' ') {
			char *p, *name = strdup (str + 2);
			char *eq = strchr (name, '=');
			if (eq) {
				*eq++ = 0;
			}
			p = strchr (name, ' ');
			if (p) {
				*p++ = 0;
			}
			RRegItem *item = r_reg_get (core->dbg->reg, name, -1);
			if (item) {
				if (eq) {
					long double val = 0.0f;
					double dval = 0.0;
					if (r_str_scanf (eq, "%lf", &dval) == 1) {
						val = (long double)dval;
						if (item->size >= 80) {
							r_reg_set_longdouble (core->dbg->reg, item, val);
						} else {
							r_reg_set_double (core->dbg->reg, item, (double)val);
						}
						r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, true);
						r_debug_reg_sync (core->dbg, R_REG_TYPE_FPU, true);
					} else {
						R_LOG_WARN ("Cannot parse floating value '%s'", eq);
					}
				} else {
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_FPU, false);
					long double res = r_reg_get_longdouble (core->dbg->reg, item);
#if R2_NO_LONG_DOUBLE
					r_cons_printf (core->cons, "%f\n", (double)res);
#else
					r_cons_printf (core->cons, "%Lf\n", res);
#endif
				}
			} else {
				/* note, that negative type forces sync to print the regs from the backend */
				R_LOG_ERROR ("cannot find vector register '%s'", name);
			}
			free (name);
		} else if (!str[1]) {
			//TODO: Do not use this hack to print fpu register
			r_debug_reg_sync (core->dbg, -R_REG_TYPE_FPU, false);
		} else {
			r_core_return_invalid_command (core, "drf", str[1]);
			break;
		}
		break;
	case 'p': // "drp"
		// this is only ever reached if cdg.debug=1
		// ("from" == d) == cfg.debug
		cmd_reg_profile (core, 'd', str);
		break;
	case 't': { // "drt"
		char rad = 0;
		switch (str[1]) {
		case '\0': // "drt"
			for (i = 0; (name = r_reg_type_tostring (i)); i++) {
				r_cons_println (core->cons, name);
			}
			break;
		case 'j': // "drtj"
		case '*': // "drt*"
			rad = str[1];
			str++;
			if (rad == 'j' && !str[1]) {
				PJ *pj = r_core_pj_new (core);
				if (!pj) {
					break;
				}
				pj_a (pj);
				for (i = 0; (name = r_reg_type_tostring (i)); i++) {
					pj_s (pj, name);
				}
				pj_end (pj);
				r_cons_println (core->cons, pj_string (pj));
				pj_free (pj);
				break;
			}
			// fallthrough
		case ' ': // "drt "
		{
			int role = r_reg_alias_fromstring (str + 2);
			const char *regname = r_reg_alias_getname (core->dbg->reg, role);
			if (!regname) {
				regname = str + 2;
			}
			size = atoi (regname);
			if (size < 1) {
				char *arg = strchr (str + 2, ' ');
				size = 0;
				if (arg) {
					*arg++ = 0;
					size = atoi (arg);
				}
				type = r_reg_type_by_name (str + 2);
				r_debug_reg_sync (core->dbg, type, false);
				PJ *pj = (tolower (rad) == 'j')? r_core_pj_new (core): NULL;
				r_debug_reg_list (core->dbg, type, size, pj, rad, use_color);
				if (pj) {
					char *s = pj_drain (pj);
					r_cons_printf (core->cons, "%s\n", s);
					free (s);
				}
			} else {
				if (type != R_REG_TYPE_LAST) {
					r_debug_reg_sync (core->dbg, type, false);
					r_debug_reg_list (core->dbg, type, size, NULL, rad, use_color);
				} else {
					R_LOG_ERROR ("unknown type");
				}
			}
			break;
		}
		case '?': // "drt?"
		default:
			r_core_cmd_help (core, help_msg_drt);
			break;
		}
		}
		break;
	case 'n': // "drn"
		cmd_drn (core, str);
		break;
	case 'd': // "drd"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, NULL, 3, use_color); // xxx detect which one is current usage
		break;
	case 'o': // "dro"
		r_reg_arena_swap (core->dbg->reg, false);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, NULL, 0, use_color); // xxx detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, false);
		break;
	case ',': // "dr,"
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
			__tableRegList (core, core->dbg->reg, str + 1);
		} else {
			R_LOG_ERROR ("cannot retrieve registers from pid %d", core->dbg->pid);
		}
		break;
	case '=': // "dr="
		{
			int pcbits2, pcbits = grab_bits (core, str + 1, &pcbits2);
			if (r_config_get_b (core->config, "cfg.debug")) {
				if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
					if (pcbits && pcbits != bits) {
						r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, NULL, '=', use_color); // xxx detect which one is current usage
					}
					r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, NULL, '=', use_color); // xxx detect which one is current usage
					if (pcbits2) {
						r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits2, NULL, '=', use_color); // xxx detect which one is current usage
					}
				} //else eprintf ("cannot retrieve registers from pid %d\n", core->dbg->pid);
			} else {
				RReg *orig = core->dbg->reg;
				core->dbg->reg = core->anal->reg;
				if (pcbits && pcbits != bits) {
					r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, NULL, '=', use_color); // xxx detect which one is current usage
				}
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, NULL, '=', use_color); // xxx detect which one is current usage
#if 0
				if (pcbits2) {
					r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits2, NULL, '=', use_color); // xxx detect which one is current usage
				}
#endif
				core->dbg->reg = orig;
			}
		}
		break;
	case '.':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
			int pcbits2, pcbits = grab_bits (core, str + 1, &pcbits2);
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, NULL, '.', use_color);
			if (pcbits2) {
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits2, NULL, '.', use_color);
			}
		}
		break;
	case '*': // "dr*"
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
			int pcbits2, pcbits = grab_bits (core, str + 1, &pcbits2);
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, NULL, '*', use_color);
			if (pcbits2) {
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits2, NULL, '*', use_color);
			}
			r_flag_space_pop (core->flags);
		}
		break;
	case 'i': // "dri"
		r_core_debug_ri (core, core->dbg->reg, 0);
		break;
	case 'r': // "drr"
		switch (str[1]) {
		case '?': // "drr?"
			r_core_cmd_help (core, help_msg_drr);
			break;
		case 'j': // "drrj"
			r_core_debug_rr (core, core->dbg->reg, 'j');
			break;
		case ' ':
			if (isdigit (str[2])) {
				r_core_debug_rr (core, core->dbg->reg, str[2]);
			} else {
				r_core_debug_rr (core, core->dbg->reg, 0);
			}
			break;
		default:
			r_core_debug_rr (core, core->dbg->reg, 0);
			break;
		}
		break;
	case 'j': // "drj"
	case '\0': // "dr"
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
			int pcbits = core->anal->config->bits;
			RRegItem *reg = r_reg_get (core->anal->reg, "PC", 0);
			if (reg) {
				if (core->rasm->config->bits != reg->size) {
					pcbits = reg->size;
				}
			}
			if (str[0] == 'j') {
				PJ *pj = r_core_pj_new (core);
				if (!pj) {
					return;
				}
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, pj, 'j', use_color);
				char *s = pj_drain (pj);
				if (s) {
					r_cons_printf (core->cons, "%s\n", s);
					free (s);
				}
			} else {
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, NULL, 0, use_color);
			}
		} else {
			R_LOG_ERROR ("Cannot retrieve registers from pid %d", core->dbg->pid);
		}
		break;
	case ' ': // "dr"
		arg = strchr (str + 1, '=');
		if (arg) {
			*arg = 0;
			char *string = r_str_trim_dup (str + 1);
			r = r_reg_get (core->dbg->reg, string, -1);
			if (r) {
				if (r->flags) {
					r_cons_printf (core->cons, "0x%08"PFMT64x" ->",
							r_reg_get_value (core->dbg->reg, r));
					r_reg_set_bvalue (core->dbg->reg, r, arg+1);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
					r_cons_printf (core->cons, "0x%08"PFMT64x"\n",
							r_reg_get_value (core->dbg->reg, r));
				} else {
					ut64 oval = r_reg_get_value (core->dbg->reg, r);
					ut64 wval = r_num_math (core->num, arg + 1);

					r_reg_set_value (core->dbg->reg, r, wval);
					bool sync_works = r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
					if (!sync_works) {
						// read them back
						r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
					}
					ut64 nval = r_reg_get_value (core->dbg->reg, r);
					if (nval == wval) {
						r_cons_printf (core->cons, "0x%08"PFMT64x" -> 0x%08"PFMT64x"\n", oval, nval);
					} else {
						r_cons_printf (core->cons, "0x%08"PFMT64x" -> 0x%08"PFMT64x" -> 0x%08"PFMT64x"\n", oval, wval, nval);
					}
				}
			} else {
				R_LOG_ERROR ("unknown register '%s'", string);
			}
			free (string);
			// update flags here
			r_core_cmdf (core, ".dr*%d", bits);
			return;
		}

		size = atoi (str + 1);
		if (size) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, size, NULL, str[0], use_color);
		} else {
			char *comma = strchr (str + 1, ',');
			if (comma) {
				char *args = strdup (str + 1);
				char argc = r_str_split (args, ',');
				for (i = 0; i < argc; i++) {
					showreg (core, r_str_word_get0 (args, i));
				}
				free (args);
			} else {
				showreg (core, str + 1);
			}
		}
		break;
	default:
		r_core_return_invalid_command (core, "dr", str[0]);
		break;
	}
}

static void backtrace_vars(RCore *core, RList *frames) {
	RDebugFrame *f;
	RListIter *iter;
	RReg *r = core->anal->reg;
	ut64 dsp = r_reg_getv (r, "SP");
	ut64 dbp = r_reg_getv (r, "BP");
	int n = 0;
	r_list_foreach (frames, iter, f) {
		ut64 s = f->sp ? f->sp : dsp;
		ut64 b = f->bp ? f->bp : dbp;
		r_reg_setv (r, "BP", s);
		r_reg_setv (r, "SP", b);
//////////
		char flagdesc[1024], flagdesc2[1024];
		RFlagItem *fi = r_flag_get_at (core->flags, f->addr, true);
		flagdesc[0] = flagdesc2[0] = 0;
		if (fi) {
			if (fi->addr != f->addr) {
				int delta = (int)(f->addr - fi->addr);
				if (delta > 0) {
					snprintf (flagdesc, sizeof (flagdesc),
							"%s+%d", fi->name, delta);
				} else if (delta < 0) {
					snprintf (flagdesc, sizeof (flagdesc),
							"%s%d", fi->name, delta);
				} else {
					snprintf (flagdesc, sizeof (flagdesc),
							"%s", fi->name);
				}
			} else {
				snprintf (flagdesc, sizeof (flagdesc),
						"%s", fi->name);
			}
		}
//////////
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, f->addr, 0);
		// char *str = r_str_newf ("[frame %d]", n);
		r_cons_printf (core->cons, "%d  0x%08"PFMT64x" sp: 0x%08"PFMT64x" %-5d"
				"[%s]  %s %s\n", n, f->addr, f->sp, (int)f->size,
				fcn ? fcn->name : "??", flagdesc, flagdesc2);
		eprintf ("afvd @ 0x%"PFMT64x"\n", f->addr);
		r_cons_push (core->cons);
		char *res = r_core_cmd_strf (core, "afvd@0x%"PFMT64x, f->addr);
		r_cons_pop (core->cons);
		r_cons_printf (core->cons, "%s", res);
		free (res);
		n++;
	}
	r_reg_setv (r, "BP", dbp);
	r_reg_setv (r, "SP", dsp);
}

static void asciiart_backtrace(RCore *core, RList *frames) {
	// TODO: show local variables
	// TODO: show function/flags/symbols related
	// TODO: show contents of stack
	// TODO: honor scr.color
	RDebugFrame *f;
	RListIter *iter;
	bool mymap = false;
	const char *spreg = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_SP);
	ut64 dsp = r_reg_getv (core->anal->reg, spreg);
	ut64 dbp = r_reg_getv (core->anal->reg, "BP");
	RDebugMap *map = r_debug_map_get (core->dbg, dsp);
	if (!map) {
		mymap = true;
		map = R_NEW0 (RDebugMap);
		map->addr = UT64_MAX;
		map->addr_end = UT64_MAX;
	}

	r_cons_printf (core->cons, "0x%016"PFMT64x"  STACK END  ^^^\n", map->addr);
	r_cons_printf (core->cons, "0x%016"PFMT64x"  STACK POINTER: %s\n", dsp, spreg);
	r_cons_printf (core->cons, "                    .------------------------.\n");
	int n = 0;
	r_list_foreach (frames, iter, f) {
		ut64 s = f->sp ? f->sp : dsp;
		ut64 b = f->bp ? f->bp : dbp;
		char *str = r_str_newf ("[frame %d]", n);
		r_cons_printf (core->cons, "0x%016"PFMT64x"  |%4s    %10s      | ; size %" PFMTDPTR "\n", s, "SP", str, (ptrdiff_t)(s - b));
		free (str);
		r_cons_printf (core->cons, "                    |            ...         |\n");
		r_cons_printf (core->cons, "0x%016"PFMT64x"  |%4s 0x%016"PFMT64x" | %s\n", b, "BP", f->addr, "; return address");
		r_cons_printf (core->cons, "                    )------------------------(\n");
		// eprintf ("0x%08llx 0x%08llx 0x%08llx\n", f->addr, s, b);
		n++;
	}
	r_cons_printf (core->cons, "                    |           ...          |\n");
	r_cons_printf (core->cons, "                    `------------------------'\n");
	r_cons_printf (core->cons, "0x%016"PFMT64x"  STACK BOTTOM\n", map->addr_end);
	if (mymap) {
		r_debug_map_free (map);
	}
}

static void get_backtrace_info(RCore* core, RDebugFrame* frame, ut64 addr, char** flagdesc, char** flagdesc2, char** pcstr, char** spstr) {
	RFlagItem *f = r_flag_get_at (core->flags, frame->addr, true);
	*flagdesc = NULL;
	*flagdesc2 = NULL;
	if (f) {
		if (f->addr != addr) {
			int delta = (int)(frame->addr - f->addr);
			if (delta > 0) {
				*flagdesc = r_str_newf ("%s+%d", f->name, delta);
			} else if (delta < 0) {
				*flagdesc = r_str_newf ("%s%d", f->name, delta);
			} else {
				*flagdesc = r_str_newf ("%s", f->name);
			}
		} else {
			*flagdesc = r_str_newf ("%s", f->name);
		}
	}
	f = r_flag_get_at (core->flags, frame->addr, true);
	if (f && !strchr (f->name, '.')) {
		f = r_flag_get_at (core->flags, frame->addr - 1, true);
	}
	if (f) {
		if (f->addr != addr) {
			int delta = (int)(frame->addr - 1 - f->addr);
			if (delta > 0) {
				*flagdesc2 = r_str_newf ("%s+%d", f->name, delta + 1);
			} else if (delta < 0) {
				*flagdesc2 = r_str_newf ("%s%d", f->name, delta + 1);
			} else {
				*flagdesc2 = r_str_newf ("%s+1", f->name);
			}
		} else {
			*flagdesc2 = r_str_newf ("%s", f->name);
		}
	}
	if (*flagdesc && *flagdesc2) {
		if (!strcmp (*flagdesc, *flagdesc2)) {
			free (*flagdesc2);
			*flagdesc2 = NULL;
		}
	}
	if (pcstr && spstr) {
		if (R_SYS_BITS_CHECK (core->dbg->bits, 64)) {
			*pcstr = r_str_newf ("0x%-16" PFMT64x, frame->addr);
			*spstr = r_str_newf ("0x%-16" PFMT64x, frame->sp);
		} else if (R_SYS_BITS_CHECK (core->dbg->bits, 32)) {
			*pcstr = r_str_newf ("0x%-8" PFMT64x, frame->addr);
			*spstr = r_str_newf ("0x%-8" PFMT64x, frame->sp);
		} else {
			*pcstr = r_str_newf ("0x%" PFMT64x, frame->addr);
			*spstr = r_str_newf ("0x%" PFMT64x, frame->sp);
		}
	}
}

static void static_debug_stop(void *u) {
	RDebug *dbg = (RDebug *)u;
	r_debug_stop (dbg);
}

static void core_cmd_dbi(RCore *core, const char *input, const ut64 idx) {
	int i;
	char *p;
	RBreakpointItem *bpi;
	switch (input[2]) {
	case ' ': // "dbi."
		{
			const int index = r_bp_get_index_at (core->dbg->bp, idx);
			if (index != -1) {
				r_cons_printf (core->cons, "%d\n", index);
			}
		}
		break;
	case '-': // "dbi-"
		{
			if (!r_bp_del_index (core->dbg->bp, idx)) {
				R_LOG_ERROR ("Breakpoint with index %d not found", (int)idx);
			}
		}
		break;
	case '.': // "dbi."
		{
			const int index = r_bp_get_index_at (core->dbg->bp, core->addr);
			if (index != -1) {
				r_cons_printf (core->cons, "%d\n", index);
			}
		}
		break;
	case 0: // "dbi"
		for (i = 0; i < core->dbg->bp->bps_idx_count; i++) {
			if ((bpi = core->dbg->bp->bps_idx[i])) {
				r_cons_printf (core->cons, "%d 0x%08"PFMT64x" E:%d T:%d\n",
						i, bpi->addr, bpi->enabled, bpi->trace);
			}
		}
		break;
	case 'x': // "dbix"
		if (input[3] == ' ') {
			if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
				char *expr = strchr (input + 4, ' ');
				if (expr) {
					free (bpi->expr);
					bpi->expr = strdup (expr);
				}
			}
			r_cons_printf (core->cons, "%d\n", (int)idx);
		} else {
			for (i = 0; i < core->dbg->bp->bps_idx_count; i++) {
				RBreakpointItem *bp = core->dbg->bp->bps_idx[i];
				if (bp) {
					r_cons_printf (core->cons, "%d 0x%08"PFMT64x" %s\n", i, bp->addr, bp->expr);
				}
			}
		}
		break;
	case 'c': // "dbic"
		p = strchr (input + 3, ' ');
		if (p) {
			char *q = strchr (p + 1, ' ');
			if (q) {
				*q++ = 0;
				ut64 addr = r_num_math (core->num, p);
				bpi = r_bp_get_index (core->dbg->bp, addr);
				if (bpi) {
					bpi->data = strdup (q);
				} else {
					R_LOG_ERROR ("Cannot set command");
				}
			} else {
				r_core_cmd_help_match (core, help_msg_db, "dbic");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_db, "dbic");
		}
		break;
	case 'e': // "dbie"
		if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
			bpi->enabled = true;
		} else {
			R_LOG_ERROR ("Cannot unset tracepoint");
		}
		break;
	case 'd': // "dbid"
		if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
			bpi->enabled = false;
		} else {
			R_LOG_ERROR ("Cannot unset tracepoint");
		}
		break;
	case 's': // "dbis"
		if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
			bpi->enabled = !!!bpi->enabled;
		} else {
			R_LOG_ERROR ("Cannot unset tracepoint");
		}
		break;
	case 't': // "dbite" "dbitd" ...
		switch (input[3]) {
		case 'e':
			if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
				bpi->trace = true;
			} else {
				R_LOG_ERROR ("Cannot unset tracepoint");
			}
			break;
		case 'd':
			if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
				bpi->trace = false;
			} else {
				R_LOG_ERROR ("Cannot unset tracepoint");
			}
			break;
		case 's':
			if ((bpi = r_bp_get_index (core->dbg->bp, idx))) {
				bpi->trace = !!!bpi->trace;
			} else {
				R_LOG_ERROR ("Cannot unset tracepoint");
			}
			break;
		}
		break;
	}
}

#if R2__WINDOWS__
#include "../debug/p/native/windows/windows_message.h"
#endif

#define DB_ARG(x) r_str_word_get0(str, x)
static void add_breakpoint(RCore *core, const char *input, bool hwbp, bool watch) {
	RBreakpointItem *bpi;
	ut64 addr;
	int i = 0;

	char *str = strdup (r_str_trim_head_ro (input + 1));
	int sl = r_str_word_set0 (str);
	// For dbw every second argument is 'rw', so we need to skip it.
	for (; i < sl; i += 1 + (watch ? 1 : 0)) {
		if (*DB_ARG (i) == '-') {
			r_bp_del (core->dbg->bp, r_num_math (core->num, DB_ARG (i) + 1));
		} else {
			int rw = 0;
			if (watch) {
				if (sl % 2 == 0) {
					if (!strcmp (DB_ARG (i + 1), "r")) {
						rw = R_BP_PROT_READ;
					} else if (!strcmp (DB_ARG (i + 1), "w")) {
						rw = R_BP_PROT_WRITE;
					} else if (!strcmp (DB_ARG (i + 1), "rw")) {
						rw = R_BP_PROT_ACCESS;
					} else {
						r_core_cmd_help (core, help_msg_dbw);
						break;
					}
				} else {
					r_core_cmd_help (core, help_msg_dbw);
					break;
				}
			}
			addr = r_num_math (core->num, DB_ARG (i));
			bpi = r_debug_bp_add (core->dbg, addr, hwbp, watch, rw, NULL, 0);
			if (bpi) {
				free (bpi->name);
				if (!strcmp (DB_ARG (i), "$$")) {
					RFlagItem *f = r_core_flag_get_by_spaces (core->flags, false, addr);
					if (f) {
						if (addr > f->addr) {
							bpi->name = r_str_newf ("%s+0x%" PFMT64x, f->name, addr - f->addr);
						} else {
							bpi->name = strdup (f->name);
						}
					} else {
						bpi->name = r_str_newf ("0x%08" PFMT64x, addr);
					}
				} else {
					bpi->name = strdup (DB_ARG (i));
				}
			} else {
				R_LOG_ERROR ("Cannot set breakpoint at '%s'", DB_ARG (i));
			}
		}
	}

	free (str);
}

static void r_core_cmd_bp(RCore *core, const char *input) {
	RBreakpointItem *bpi;
	int i;
	bool hwbp = r_config_get_b (core->config, "dbg.hwbp");
	RDebugFrame *frame;
	RListIter *iter;
	const char *p;
	bool watch = false;
	RList *list;
	ut64 addr, idx;
	p = strchr (input, ' ');
	addr = p? r_num_math (core->num, p + 1): UT64_MAX;
	idx = addr; // 0 is valid index
	if (!addr) {
		addr = UT64_MAX;
	}
	char *str = NULL;

	switch (input[1]) {
	case '.':
		if (input[2]) {
			ut64 addr = r_num_tail (core->num, core->addr, input + 2);
			bpi = r_debug_bp_add (core->dbg, addr, hwbp, false, 0, NULL, 0);
			if (!bpi) {
				R_LOG_ERROR ("Unable to add breakpoint (%s)", input + 2);
			}
		} else {
			bpi = r_bp_get_at (core->dbg->bp, core->addr);
			if (bpi) {
				r_cons_printf (core->cons, "breakpoint %s %s %s\n",
						r_str_rwx_i (bpi->perm),
						bpi->enabled ?  "enabled" : "disabled",
						r_str_get (bpi->name));
			}
		}
		break;
	case 'f':
		{
		RVecRBinSymbol *symbols = r_bin_get_symbols_vec (core->bin);
		RBinSymbol *symbol;
		R_VEC_FOREACH (symbols, symbol) {
			if (symbol->type && !strcmp (symbol->type, R_BIN_TYPE_FUNC_STR)) {
				if (r_anal_noreturn_at (core->anal, symbol->vaddr)) {
					bpi = r_debug_bp_add (core->dbg, symbol->vaddr, hwbp, false, 0, NULL, 0);
					const char *name = r_bin_name_tostring (symbol->name);
					if (bpi) {
						bpi->name = r_str_newf ("%s.%s", "sym", name);
					} else {
						R_LOG_ERROR ("Failed to breakpoint on a noreturn function %s at addr 0x%"PFMT64x, name, symbol->vaddr);
					}
				}
			}
		}
		}
		break;
	case 'x': // "dbx"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_db, "dbx");
		} else if (input[2] == ' ') {
			if (addr == UT64_MAX) {
				addr = core->addr;
			}
			bpi = r_bp_get_at (core->dbg->bp, addr);
			if (bpi) {
				free (bpi->expr);
				bpi->expr = strdup (input + 3);
			}
		} else if (!input[2]) {
			RBreakpointItem *bp;
			r_list_foreach (core->dbg->bp->bps, iter, bp) {
				r_cons_printf (core->cons, "0x%08"PFMT64x" %s\n", bp->addr, r_str_get (bp->expr));
			}
		} else {
			r_core_return_invalid_command (core, "dbx", input[2]);
		}
		break;
	case 't': // "dbt"
		switch (input[2]) {
		case 'v': // "dbtv"
			list = r_debug_frames (core->dbg, addr);
			backtrace_vars (core, list);
			r_list_free (list);
			break;
		case 'a': // "dbta"
			list = r_debug_frames (core->dbg, addr);
			asciiart_backtrace (core, list);
			r_list_free (list);
			break;
		case 'e': // "dbte"
			for (p = input + 3; *p == ' '; p++) {
				/* nothing to do here */
			}
			if (*p == '*') {
				r_bp_set_trace_all (core->dbg->bp,true);
			} else if (!r_bp_set_trace (core->dbg->bp, addr, true)) {
				R_LOG_ERROR ("Cannot set tracepoint");
			}
			break;
		case 'd': // "dbtd"
			for (p = input + 3; *p == ' ';p++) {
				//nothing to see here
			}
			if (*p == '*') {
				r_bp_set_trace_all (core->dbg->bp, false);
			} else if (!r_bp_set_trace (core->dbg->bp, addr, false)) {
				R_LOG_ERROR ("Cannot unset tracepoint");
			}
			break;
		case 's': // "dbts"
			bpi = r_bp_get_at (core->dbg->bp, addr);
			if (bpi) {
				bpi->trace = !!!bpi->trace;
			} else {
				R_LOG_ERROR ("Cannot unset tracepoint");
			}
			break;
		case 'j': { // "dbtj"
			PJ *pj = r_core_pj_new (core);
			if (!pj) {
				return;
			}
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = r_num_math (core->num, input + 2);
			}
			i = 0;
			list = r_debug_frames (core->dbg, addr);
			pj_a (pj);
			r_list_foreach (list, iter, frame) {
				char *flagdesc, *flagdesc2, *desc;
				get_backtrace_info (core, frame, addr, &flagdesc, &flagdesc2, NULL, NULL);
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, frame->addr, 0);
				desc = r_str_newf ("%s%s", r_str_get (flagdesc), r_str_get (flagdesc2));
				pj_o (pj);
				pj_ki (pj, "idx", i);
				pj_kn (pj, "pc", frame->addr);
				pj_kn (pj, "sp", frame->sp);
				pj_ki (pj, "frame_size", frame->size);
				pj_ks (pj, "fname", fcn ? fcn->name : "");
				pj_ks (pj, "desc", desc);
				pj_end (pj);
				i++;
				free (flagdesc);
				free (flagdesc2);
				free (desc);
			}
			pj_end (pj);
			r_cons_println (core->cons, pj_string (pj));
			pj_free (pj);
			r_list_free (list);
			break;
		}
		case '=': // dbt=
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = r_num_math (core->num, input + 2);
			}
			i = 0;
			list = r_debug_frames (core->dbg, addr);
			r_list_reverse (list);
			r_list_foreach (list, iter, frame) {
				switch (input[3]) {
				case 0:
					r_cons_printf (core->cons, "%s0x%08"PFMT64x,
							(i ? " " : ""), frame->addr);
					break;
				case 's':
					r_cons_printf (core->cons, "%s0x%08"PFMT64x,
							(i ? " " : ""), frame->sp);
					break;
				case 'b':
					r_cons_printf (core->cons, "%s0x%08"PFMT64x,
							(i ? " " : ""), frame->bp);
					break;
				case '?':
				default:
					r_core_cmd0 (core, "db?~dbt");
					break;
				}
				i++;
			}
			r_cons_newline (core->cons);
			r_list_free (list);
			break;
		case '*': // dbt*
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = r_num_math (core->num, input + 2);
			}
			i = 0;
			list = r_debug_frames (core->dbg, addr);
			r_list_reverse (list);
			r_cons_printf (core->cons, "f-bt.*\n");
			r_list_foreach (list, iter, frame) {
				r_cons_printf (core->cons, "f bt.frame%d = 0x%08"PFMT64x"\n", i, frame->addr);
				r_cons_printf (core->cons, "f bt.frame%d.stack %d 0x%08"PFMT64x"\n", i, frame->size, frame->sp);
				i++;
			}
			r_list_free (list);
			break;
		case 0: // "dbt" -- backtrace
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = r_num_math (core->num, input + 2);
			}
			i = 0;
			list = r_debug_frames (core->dbg, addr);
			r_list_foreach (list, iter, frame) {
				char *flagdesc, *flagdesc2, *pcstr, *spstr;
				get_backtrace_info (core, frame, addr, &flagdesc, &flagdesc2, &pcstr, &spstr);
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, frame->addr, 0);
				r_cons_printf (core->cons, "%d  %s sp: %s  %-5d"
						"[%s]  %s %s\n", i++,
						pcstr, spstr,
						(int)frame->size,
						fcn ? fcn->name : "??",
						r_str_get (flagdesc),
						r_str_get (flagdesc2));
				free (flagdesc);
				free (flagdesc2);
				free (pcstr);
				free (spstr);
			}
			r_list_free (list);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_dbt);
			break;
		default:
			r_core_return_invalid_command (core, "dbt", input[2]);
			break;
		}
		break;
	case 'b': // "dbb"
		if (input[2]) {
			core->dbg->bp->delta = (st64)r_num_math (core->num, input + 2);
		} else {
			r_cons_printf (core->cons, "%"PFMT64d"\n", core->dbg->bp->delta);
		}
		break;
	case 'm': // "dbm"
		if (input[2] && input[3]) {
			char *module = r_str_trim_dup (input + 3);
			st64 delta = 0;
			char *sdelta = (char *)r_str_lchr (module, ' ');
			if (!sdelta) {
				r_core_cmd_help_match (core, help_msg_db, "dbm");
				free (module);
				break;
			}
			*sdelta++ = 0;
			delta = (ut64)r_num_math (core->num, sdelta);
			bpi = r_debug_bp_add (core->dbg, 0, hwbp, false, 0, module, delta);
			if (!bpi) {
				R_LOG_ERROR ("Cannot set breakpoint");
			}
			free (module);
		} else if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_db, "dbm");
		} else {
			R_LOG_INFO ("Missing argument for dbm");
		}
		break;
	case '*':
		{
			char *s = r_bp_list (core->dbg->bp, 1);
			r_cons_print (core->cons, s);
			free (s);
		}
		break;
	case 0:
		{
			char *s = r_bp_list (core->dbg->bp, 0);
			r_cons_print (core->cons, s);
			free (s);
		}
		break;
	case 'j':
		{
			char *s = r_bp_list (core->dbg->bp, 'j');
			r_cons_println (core->cons, s);
			free (s);
		}
		break;
	case '-': // "db-"
		if (input[2] == '*') {
			r_bp_del_all (core->dbg->bp);
		} else if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_db);
		} else {
			#define DB_ARG(x) r_str_word_get0(str, x)
			char *str = strdup (r_str_trim_head_ro (input +2));
			int i = 0;
			int sl = r_str_word_set0 (str);
			for ( ; i < sl; i++) {
				const ut64 addr = r_num_math (core->num, DB_ARG (i));
				r_bp_del (core->dbg->bp, addr);
			}
			free (str);
		}
		break;
	case 'c': // "dbc"
		if (input[2] == ' ') {
			char *inp = r_str_trim_dup (input + 3);
			char *arg = strchr (inp, ' ');
			if (arg) {
				*arg++ = 0;
				addr = r_num_math (core->num, inp);
				bpi = r_bp_get_at (core->dbg->bp, addr);
				if (bpi) {
					free (bpi->data);
					bpi->data = strdup (arg);
				} else {
					R_LOG_ERROR ("No breakpoint defined at 0x%08"PFMT64x, addr);
				}
			} else {
				R_LOG_ERROR ("Missing argument");
			}
			free (inp);
		} else if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_db, "dbc");
		} else {
			r_core_return_invalid_command (core, "dbc", input[2]);
		}
		break;
	case 'C': // "dbC"
		if (input[2] == ' ') {
			char *inp = r_str_trim_dup (input + 3);
			char *arg = strchr (inp, ' ');
			if (arg) {
				*arg++ = 0;
				addr = r_num_math (core->num, inp);
				bpi = r_bp_get_at (core->dbg->bp, addr);
				if (bpi) {
					free (bpi->cond);
					bpi->cond = strdup (arg);
				} else {
					R_LOG_ERROR ("No breakpoint defined at 0x%08"PFMT64x, addr);
				}
			} else {
				R_LOG_ERROR ("Missing argument");
			}
			free (inp);
		} else if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_db, "dbC");
		} else {
			r_core_return_invalid_command (core, "dbC", input[2]);
		}
		break;
	case 's': // "dbs"
		addr = r_num_math (core->num, input + 2);
		bpi = r_bp_get_at (core->dbg->bp, addr);
		if (bpi) {
			//bp->enabled = !bp->enabled;
			// XXX(jjd): this ^^ is what I would think toggling means...
			r_bp_del (core->dbg->bp, addr);
		} else {
			// XXX(jjd): does t his need an address validity check??
			bpi = r_debug_bp_add (core->dbg, addr, hwbp, false, 0, NULL, 0);
			if (!bpi) {
				R_LOG_ERROR ("Cannot set breakpoint (%s)", input + 2);
			}
		}
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input + 2), true, 0);
		break;
	case 'n': // "dbn"
		bpi = r_bp_get_at (core->dbg->bp, core->addr);
		if (input[2] == ' ') {
			if (bpi) {
				free (bpi->name);
				bpi->name = strdup (input + 3);
			} else {
				R_LOG_ERROR ("Cannot find breakpoint at 0x%08"PFMT64x, core->addr);
			}
		} else {
			if (bpi && bpi->name) {
				r_cons_println (core->cons, bpi->name);
			}
		}
		break;
	case 'e': // "dbe"
		p = r_str_trim_head_ro (input + 2);
		if (*p == '*') {
			r_bp_enable_all (core->dbg->bp,true);
		} else {
			for (; *p && *p != ' '; p++);
			r_bp_enable (core->dbg->bp, r_num_math (core->num, input + 2), true, r_num_math (core->num, p));
		}
		break;
	case 'd': // "dbd"
		p = r_str_trim_head_ro (input + 2);
		if (*p == '*') {
			r_bp_enable_all (core->dbg->bp, false);
		} else {
			for (; *p && *p != ' '; p++);
			r_bp_enable (core->dbg->bp, r_num_math (core->num, input + 2), false, r_num_math (core->num, p));
		}
		break;
	case 'h': // "dbh"
		switch (input[2]) {
		case 0:
			{
				char *s = r_bp_plugin_list (core->dbg->bp);
				r_cons_print (core->cons, s);
				free (s);
			}
			break;
		case ' ':
			if (input[3]) {
				if (!r_bp_use (core->dbg->bp, input + 3, core->anal->config->bits)) {
					R_LOG_ERROR ("Invalid name: '%s'", input + 3);
				}
			}
			break;
		case '-':
			if (input[3]) {
				if (!r_bp_plugin_del (core->dbg->bp, input + 3)) {
					R_LOG_ERROR ("Invalid name: '%s'", input + 3);
				}
			}
			break;
		case '?':
			r_core_cmd_help_match (core, help_msg_db, "dbh");
			break;
		default:
			r_core_return_invalid_command (core, "dh", input[2]);
			break;
		}
		break;
#if R2__WINDOWS__
	case 'W': // "dbW"
		if (input[2] == ' ') {
			if (r_w32_add_winmsg_breakpoint (core->dbg, input + 3)) {
				R_LOG_INFO ("Breakpoint set");
			} else {
				R_LOG_INFO ("Breakpoint not set");
			}
		} else if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_db, "dbW");
		} else {
			R_LOG_ERROR ("Missing argument");
		}
		break;
#endif
	case 'w': // "dbw"
		add_breakpoint (core, input + 1, hwbp, true);
		break;
	case 'H': // "dbH"
		add_breakpoint (core, input + 1, true, watch);
		break;
	case ' ': // "db"
		add_breakpoint (core, input + 1, hwbp, watch);
		break;
	case 'i':
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_dbi);
		} else {
			core_cmd_dbi (core, input, idx);
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_db);
		break;
	default:
		r_core_return_invalid_command (core, "db", input[1]);
		break;
	}
	free (str);
}

static RTreeNode *add_trace_tree_child(Sdb *db, RTree *t, RTreeNode *cur, ut64 addr) {
	struct trace_node *t_node;
	char dbkey[TN_KEY_LEN];

	snprintf (dbkey, TN_KEY_LEN, TN_KEY_FMT, addr);
	t_node = (struct trace_node *)(size_t)sdb_num_get (db, dbkey, NULL);
	if (!t_node) {
		t_node = R_NEW0 (struct trace_node);
		t_node->addr = addr;
		t_node->refs = 1;
		sdb_num_set (db, dbkey, (ut64)(size_t)t_node, 0);
	} else {
		t_node->refs++;
	}
	return r_tree_add_node (t, cur, t_node);
}

// swap args for consistency
static void trace_traverse_pre(RTreeNode *n, RTreeVisitor *vis) {
	const char *name = "";
	struct trace_node *tn = n->data;
	unsigned int i;
	if (!tn) {
		return;
	}
	RCore *core = (RCore *)vis->user;
	RCons *cons = core->cons;
	for (i = 0; i < n->depth - 1; i++) {
		r_cons_printf (cons, "  ");
	}
	RFlagItem *f = r_flag_get_at (core->flags, tn->addr, true);
	if (f) {
		name = f->name;
	}
	r_cons_printf (cons, " 0x%08"PFMT64x" refs %d %s\n", tn->addr, tn->refs, name);
}

static void trace_traverse(RCore *core, RTree *t) {
	RTreeVisitor vis = {0};

	/* clear the line on stderr, because somebody has written there */
	eprintf (R_CONS_CLEAR_LINE"\r");
	fflush (stderr);
	vis.user = core;
	vis.pre_visit = (RTreeNodeVisitCb)trace_traverse_pre;
	r_tree_dfs (t, &vis);
}

static void do_debug_trace_calls(RCore *core, ut64 from, ut64 to, ut64 final_addr) {
	bool trace_libs = r_config_get_i (core->config, "dbg.trace.libs");
	bool shallow_trace = r_config_get_i (core->config, "dbg.trace.inrange");
	Sdb *tracenodes = core->dbg->tracenodes;
	RTree *tr = core->dbg->tree;
	RDebug *dbg = core->dbg;
	ut64 debug_to = UT64_MAX;
	RTreeNode *cur;
	ut64 addr = 0;
	int n = 0;

	if (!trace_libs) {
#if NOOP
		RList *bounds = r_core_get_boundaries_prot (core, -1, "dbg.program", "search");
		r_list_free (bounds);
#endif
	}

	/* set root if not already present */
	r_tree_add_node (tr, NULL, NULL);
	cur = tr->root;

	while (true) {
		ut8 buf[32];
		RAnalOp aop;
		int addr_in_range;

		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (r_debug_is_dead (dbg)) {
			break;
		}
		if (debug_to != UT64_MAX && !r_debug_continue_until (dbg, debug_to)) {
			break;
		}
		if (!r_debug_step (dbg, 1)) {
			break;
		}
		debug_to = UT64_MAX;
		if (!r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false)) {
			break;
		}
		addr = r_debug_reg_get (dbg, "PC");
		if (addr == final_addr) {
			//we finished the tracing so break the loop
			break;
		}
		addr_in_range = addr >= from && addr < to;

		r_io_read_at (core->io, addr, buf, sizeof (buf));
		r_anal_op (core->anal, &aop, addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
		eprintf ("%d %"PFMT64x"\r", n++, addr);
		switch (aop.type) {
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_IRCALL:
			{
				ut64 called_addr;
				int called_in_range;
				// store regs
				// step into
				// get pc
				r_debug_step (dbg, 1);
				r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
				called_addr = r_debug_reg_get (dbg, "PC");
				called_in_range = called_addr >= from && called_addr < to;
				if (!called_in_range && addr_in_range && !shallow_trace) {
					debug_to = addr + aop.size;
				}
				if (addr_in_range || shallow_trace) {
					cur = add_trace_tree_child (tracenodes, tr, cur, addr);
					if (debug_to != UT64_MAX) {
						cur = cur->parent;
					}
				}
				// TODO: push pc+aop.length into the call path stack
				break;
			}
		case R_ANAL_OP_TYPE_CALL:
			{
				int called_in_range = aop.jump >= from && aop.jump < to;
				if (!called_in_range && addr_in_range && !shallow_trace) {
					debug_to = aop.addr + aop.size;
				}
				if (addr_in_range || shallow_trace) {
					cur = add_trace_tree_child (tracenodes, tr, cur, addr);
					if (debug_to != UT64_MAX) {
						cur = cur->parent;
					}
				}
				break;
			}
		case R_ANAL_OP_TYPE_RET:
#if 0
			// TODO: we must store ret value for each call in the graph path to do this check
			r_debug_step (dbg, 1);
			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
			addr = r_debug_reg_get (dbg, "PC");
			// TODO: step into and check return address if correct
			// if not correct we are hijacking the control flow (exploit!)
#endif
			if (cur != tr->root) {
				cur = cur->parent;
			}
#if 0
			if (addr != gn->addr) {
				eprintf ("Oops. invalid return address 0x%08"PFMT64x
						"\n0x%08"PFMT64x"\n", addr, gn->addr);
			}
#endif
			break;
		}
	}
}

static void debug_trace_calls(RCore *core, const char *input) {
	RBreakpointItem *bp_final = NULL;
	int t = core->dbg->trace->enabled;
	ut64 from = 0, to = UT64_MAX, final_addr = UT64_MAX;

	if (r_debug_is_dead (core->dbg)) {
		R_LOG_ERROR ("No process to debug");
		return;
	}
	if (*input == ' ') {
		input = r_str_trim_head_ro (input);
		ut64 first_n = r_num_math (core->num, input);
		input = strchr (input, ' ');
		if (input) {
			input = r_str_trim_head_ro (input);
			from = first_n;
			to = r_num_math (core->num, input);
			input = strchr (input, ' ');
			if (input) {
				input = r_str_trim_head_ro (input);
				final_addr = r_num_math (core->num, input);
			}
		} else {
			final_addr = first_n;
		}
	}
	core->dbg->trace->enabled = 0;
	r_cons_break_push (core->cons, static_debug_stop, core->dbg);
	r_reg_arena_swap (core->dbg->reg, true);
	if (final_addr != UT64_MAX) {
		bool hwbp = r_config_get_b (core->config, "dbg.hwbp");
		bp_final = r_debug_bp_add (core->dbg, final_addr, hwbp, false, 0, NULL, 0);
		if (!bp_final) {
			R_LOG_ERROR ("Cannot set breakpoint at final address (%"PFMT64x")", final_addr);
		}
	}
	do_debug_trace_calls (core, from, to, final_addr);
	if (bp_final) {
		r_bp_del (core->dbg->bp, final_addr);
	}
	trace_traverse (core, core->dbg->tree);
	core->dbg->trace->enabled = t;
	r_cons_break_pop (core->cons);
}

static void r_core_debug_esil(RCore *core, const char *input) {
	switch (input[0]) {
	case '\0': // "de"
		// list
		r_debug_esil_watch_list (core->dbg);
		break;
	case ' ': // "de "
		{
			char *line = strdup (input + 1);
			char *p, *q;
			int perm = 0, dev = 0;
			p = strchr (line, ' ');
			if (p) {
				*p++ = 0;
				if (strchr (line, 'r')) perm |= R_PERM_R;
				if (strchr (line, 'w')) perm |= R_PERM_W;
				if (strchr (line, 'x')) perm |= R_PERM_X;
				q = strchr (p, ' ');
				if (q) {
					*q++ = 0;
					dev = p[0];
					r_debug_esil_watch (core->dbg, perm, dev, q);
				} else {
					r_core_cmd_help_match (core, help_msg_de, "de ");
				}
			} else {
				r_core_cmd_help_match (core, help_msg_de, "de ");
			}
			free (line);
		}
		break;
	case '-': // "de-"
		r_debug_esil_watch_reset (core->dbg);
		break;
	case 'c': // "dec"
		if (r_str_startswith (input, "cai")) {
			R_LOG_ERROR ("r2pm -ci decai");
			break;
		}
		if (r_debug_esil_watch_empty (core->dbg)) {
			R_LOG_ERROR ("no esil watchpoints defined");
		} else {
			cmd_aei (core);
			r_debug_esil_prestep (core->dbg, r_config_get_i (core->config, "esil.prestep"));
			r_debug_esil_continue (core->dbg);
		}
		break;
	case 's': // "des"
		if (input[1] == 'u' && input[2] == ' ') { // "desu"
			ut64 addr, naddr, fin = r_num_math (core->num, input + 2);
			cmd_aei (core);
			addr = r_debug_reg_get (core->dbg, "PC");
			while (addr != fin) {
				r_debug_esil_prestep (core->dbg, r_config_get_i (
							core->config, "esil.prestep"));
				r_debug_esil_step (core->dbg, 1);
				naddr = r_debug_reg_get (core->dbg, "PC");
				if (naddr == addr) {
					R_LOG_ERROR ("Detected loophole");
					break;
				}
				addr = naddr;
			}
		} else if (input[1] == '?' || !input[1]) {
			r_core_cmd_help (core, help_msg_des);
		} else {
			cmd_aei (core);
			r_debug_esil_prestep (core->dbg, r_config_get_i (core->config, "esil.prestep"));
			// continue
			r_debug_esil_step (core->dbg, r_num_math (core->num, input + 1));
		}
		break;
	case '?': // "de?"
	default:
		{
			r_core_cmd_help (core, help_msg_de);
			// TODO #7967 help refactor: move to detail
			r_cons_printf (core->cons, "Examples:\n"
					" de r r rip       # stop when reads rip\n"
					" de rw m ADDR     # stop when read or write in ADDR\n"
					" de w r rdx       # stop when rdx register is modified\n"
					" de x m FROM..TO  # stop when rip in range\n");
		}
		break;
	}
}

static void r_core_debug_kill(RCore *core, const char *input) {
	if (!input || *input == '?') {
		if (input && input[1]) {
			const char *arg = input + 1;
			int signum = atoi (arg);
			if (signum > 0) {
				const char *signame = r_signal_tostring (signum);
				if (signame) {
					r_cons_println (core->cons, signame);
				}
			} else {
				signum = r_signal_from_string (arg);
				if (signum > 0) {
					r_cons_printf (core->cons, "%d\n", signum);
				}
			}
		} else {
			r_core_cmd_help (core, help_msg_dk);
		}
	} else if (*input == 'o') {
		switch (input[1]) {
		case 0: // "dko" - list signal skip/conts
			{
				char *s = r_debug_signal_list (core->dbg, 1);
				r_cons_print (core->cons, s);
				free (s);
			}
			break;
		case ' ': // dko SIGNAL
			if (input[2]) {
				char *name = strdup (input + 2);
				int signum = atoi (name);
				char *p = strchr (name, ' ');
				if (p) *p++ = 0; /* got SIGNAL and an action */
				// Actions:
				//  - pass
				//  - trace
				//  - stop
				if (signum<1) signum = r_signal_from_string (name);
				if (signum>0) {
					if (!p || !p[0]) { // stop (the usual)
						r_debug_signal_setup (core->dbg, signum, 0);
					} else if (*p == 's') { // skip
						r_debug_signal_setup (core->dbg, signum, R_DBG_SIGNAL_SKIP);
					} else if (*p == 'c') { // cont
						r_debug_signal_setup (core->dbg, signum, R_DBG_SIGNAL_CONT);
					} else {
						R_LOG_ERROR ("Invalid option: %s", p);
					}
				} else {
					R_LOG_ERROR ("Invalid signal: %s", input + 2);
				}
				free (name);
				break;
			}
			/* fall through */
		case '?':
		default:
			{
				r_core_cmd_help (core, help_msg_dko);
				// TODO #7967 help refactor: move to detail
				r_cons_println (core->cons, "NOTE: [signal] can be a number or a string that resolves with dk?\n"
						"  skip means do not enter into the signal handler\n"
						"  continue means enter into the signal handler");
			}
			break;
		}
	} else if (*input == 'j') {
		core->dbg->pj = r_core_pj_new (core); /// XXX dbg->pj is an antipattern R2_600
		char *s = r_debug_signal_list (core->dbg, 2);
		r_cons_print (core->cons, s);
		free (s);
		pj_free (core->dbg->pj);
		core->dbg->pj = NULL;
	} else if (!*input) {
		char *s = r_debug_signal_list (core->dbg, 0);
		r_cons_print (core->cons, s);
		free (s);
#if 0
		RListIter *iter;
		RDebugSignal *ds;
		R_LOG_TODO ("list signal handlers of child");
		RList *list = r_debug_kill_list (core->dbg);
		r_list_foreach (list, iter, ds) {
			// TODO: resolve signal name by number and show handler offset
			R_LOG_TODO ("--> %d", ds->num);
		}
		r_list_free (list);
#endif
	} else {
		int sig = atoi (input);
		char *p = strchr (input, '=');
		if (p) {
			r_debug_kill_setup (core->dbg, sig, r_num_math (core->num, p+1));
		} else {
			r_debug_kill (core->dbg, core->dbg->pid, core->dbg->tid, sig);
		}
	}
}

static bool is_x86_call(RDebug *dbg, ut64 addr) {
	ut8 buf[3];
	ut8 *op = buf;
	(void)dbg->iob.read_at (dbg->iob.io, addr, buf, R_ARRAY_SIZE (buf));
	switch (buf[0]) {  /* Segment override prefixes */
	case 0x65:
	case 0x64:
	case 0x26:
	case 0x3e:
	case 0x36:
	case 0x2e:
		op++;
	}
	if (op[0] == 0xe8) {
		return true;
	}
	if (op[0] == 0xff  /* bits 4-5 (from right) of next byte must be 01 */
	    && (op[1] & 0x30) == 0x10) {
		return true;
	}
	/* ... */
	return false;
}

static bool is_x86_ret(RDebug *dbg, ut64 addr) {
	ut8 buf[1];
	(void)dbg->iob.read_at (dbg->iob.io, addr, buf, R_ARRAY_SIZE (buf));
	switch (buf[0]) {
	case 0xc3:
	case 0xcb:
	case 0xc2:
	case 0xca:
		return true;
	default:
		return false;
	}
	/* Possibly incomplete with regard to instruction prefixes */
}

static ut64 getnum(RCore *core, const char *a) {
	if (r_str_startswith (a, "..")) {
		return r_num_tail (core->num, core->addr, a + 2);
	}
	return r_num_math (core->num, a);
}

static bool cmd_dcu(RCore *core, const char *input) {
	ut64 pc;
	bool invalid = (!input[0] || !input[1] || !input[2]);
	if (invalid || (input[2] != ' ' && input[2] != '.')) {
		r_core_return_invalid_command (core, "dcu", input[2]);
		return false;
	}
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	char *addrstr = r_str_trim_dup (input + 2);
	char *space = strchr (addrstr, ' ');
	bool dcu_range = false;
	if (space) {
		dcu_range = true; // implicit if from != -1?
		*space = 0;
		from = getnum (core, addrstr);
		to = getnum (core, space + 1);
		if (from == UT64_MAX) {
			// error
			R_LOG_ERROR ("Invalid range from address");
			return false;
		}
	} else {
		from = to = getnum (core, addrstr);
	}
	free (addrstr);
	if (to == UT64_MAX) {
		// error
		R_LOG_ERROR ("Invalid range to address");
		return false;
	}
	if (core->num->nc.errors && r_cons_is_interactive (core->cons)) {
		R_LOG_ERROR ("Cannot continue until unknown address");
		return false;
	}
	bool honorbps = r_config_get_b (core->config, "dbg.bpforuntil");
	if (dcu_range) {
		r_cons_break_push (core->cons, NULL, NULL);
		do {
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			r_debug_step (core->dbg, 1);
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
			pc = r_debug_reg_get (core->dbg, "PC");
			if (honorbps) {
				RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
				if (bpi) {
					R_LOG_INFO ("Breakpoint hit");
					break;
				}
			}
			R_LOG_INFO ("Continue 0x%08"PFMT64x" > 0x%08"PFMT64x" < 0x%08"PFMT64x, from, pc, to);
		} while (pc < from || pc > to);
		r_cons_break_pop (core->cons);
	} else {
		bool honorbps = r_config_get_b (core->config, "dbg.bpforuntil");
		ut64 addr = from;
		if (!strcmp (core->dbg->btalgo, "trace") && core->dbg->arch
		    && !strcmp (core->dbg->arch, "x86") && core->dbg->bits == 4) {
			unsigned long steps = 0;
			long level = 0;
			ut64 prev_pc = UT64_MAX;
			bool prev_call = false;
			bool prev_ret = false;
			ut64 old_sp, cur_sp;
			r_cons_break_push (core->cons, NULL, NULL);
			r_list_free (core->dbg->call_frames);
			core->dbg->call_frames = r_list_new ();
			core->dbg->call_frames->free = free;
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
			old_sp = r_debug_reg_get (core->dbg, "SP");
			while (true) {
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
				pc = r_debug_reg_get (core->dbg, "PC");
				if (honorbps) {
					RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
					if (bpi) {
						R_LOG_INFO ("Breakpoint hit");
						break;
					}
				}
				if (prev_call) {
					ut32 ret_addr;
					RDebugFrame *frame = R_NEW0 (RDebugFrame);
					cur_sp = r_debug_reg_get (core->dbg, "SP");
					(void)core->dbg->iob.read_at (core->dbg->iob.io, cur_sp,
							(ut8 *)&ret_addr, sizeof (ret_addr));
					frame->addr = ret_addr;
					frame->size = old_sp - cur_sp;
					frame->sp = cur_sp;
					frame->bp = old_sp;
					r_list_prepend (core->dbg->call_frames, frame);
					eprintf ("%ld call from 0x%08" PFMT64x " to 0x%08" PFMT64x " ret 0x%08" PFMT32x "\n",
							level, prev_pc, pc, ret_addr);
					level++;
					old_sp = cur_sp;
					prev_call = false;
				} else if (prev_ret) {
					RDebugFrame *head = r_list_first (core->dbg->call_frames);
					if (head && head->addr != pc) {
						eprintf ("*");
					} else {
						r_list_pop_head (core->dbg->call_frames);
						eprintf ("%ld", level);
						level--;
					}
					R_LOG_INFO (" Ret from 0x%08" PFMT64x " to 0x%08" PFMT64x, prev_pc, pc);
					prev_ret = false;
				}
				if (steps % 500 == 0 || pc == addr) {
					R_LOG_INFO ("At 0x%08" PFMT64x " after %lu steps", pc, steps);
				}
				if (r_cons_is_breaked (core->cons) || r_debug_is_dead (core->dbg) || pc == addr) {
					break;
				}
				if (is_x86_call (core->dbg, pc)) {
					prev_pc = pc;
					prev_call = true;
				} else if (is_x86_ret (core->dbg, pc)) {
					prev_pc = pc;
					prev_ret = true;
				}
				r_debug_step (core->dbg, 1);
				steps++;
			}
			r_cons_break_pop (core->cons);
			return true;
		}
		RBreakpointItem *bp = r_bp_get_at (core->dbg->bp, addr);
		bool bpset = false;
		if (bp) {
			// theres a breakpoint already so no need to set
		} else {
			bool works = false;
			if (r_config_get_b (core->config, "dbg.hwbp")) {
				works = r_bp_add_hw (core->dbg->bp, addr, core->dbg->bpsize, R_BP_PROT_EXEC);
			} else {
				works = r_bp_add_sw (core->dbg->bp, addr, core->dbg->bpsize, R_BP_PROT_EXEC);
			}
			if (works) {
				bpset = true;
				// ok go on!
			} else {
				R_LOG_ERROR ("Cannot set breakpoint of size %d at 0x%08"PFMT64x,
					core->dbg->bpsize, addr);
				return false;
			}
		}
		R_LOG_INFO ("Continue until 0x%08"PFMT64x" using %d bpsize", addr, core->dbg->bpsize);
		r_reg_arena_swap (core->dbg->reg, true);

		if (r_debug_is_dead (core->dbg)) {
			R_LOG_ERROR ("Cannot continue, run ood?");
		} else {
			r_debug_continue (core->dbg);
		}
		if (bpset) {
			r_bp_del (core->dbg->bp, addr);
		}
	}
	return true;
}

static int cmd_debug_continue(RCore *core, const char *input) {
	int pid, old_pid, signum;
	char *ptr;
	// TODO: we must use this for step 'ds' too maybe...
	switch (input[1]) {
	case 0: // "dc"
		r_reg_arena_swap (core->dbg->reg, true);
#if 0
		// This has been disabled as it caused `dc; dc; ood; dc` to
		// hang on all binaries. TODO: Find the actual root cause and
		// fix it.
		core->dbg->continue_all_threads = true;
#endif
		if (r_debug_is_dead (core->dbg)) {
			R_LOG_ERROR ("Cannot continue, run ood?");
			break;
		}
		r_debug_continue (core->dbg);
		break;
	case 'b': // "dcb"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dcb");
		} else {
			if (!core->dbg->session) {
				R_LOG_ERROR ("Session has not started");
			} else if (!r_debug_continue_back (core->dbg)) {
				R_LOG_ERROR ("cannot continue back");
			}
			break;
		}
	case 'e': // "dce"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dce");
		} else {
			r_reg_arena_swap (core->dbg->reg, true);
			r_debug_continue_with_signal (core->dbg);
		}
		break;
	case 'f': // "dcf"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dcf");
		} else {
			// we should stop in fork and vfork syscalls
			//TODO: multiple syscalls not handled yet
			r_core_cmd_call (core, "dcs vfork fork clone");
		}
		break;
	case 'c': // "dcc"
		switch (input[2]) {
		case 'o': // "dcco"
			r_reg_arena_swap (core->dbg->reg, true);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_CALL, 1);
			break;
		case 'u': // "dccu"
			r_reg_arena_swap (core->dbg->reg, true);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_UCALL, 0);
			break;
		case 0: // "dcc"
			r_reg_arena_swap (core->dbg->reg, true);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_CALL, 0);
			break;
		default: // "dcc?"
			r_core_cmd_help_match (core, help_msg_dc, "dcc");
			break;
		}
		break;
	case 'r': // "dcr"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dcr");
		} else {
			r_reg_arena_swap (core->dbg->reg, true);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_RET, 1);
		}
		break;
	case 'k':
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dck");
		} else {
			// select pid and r_debug_continue_kill (core->dbg,
			r_reg_arena_swap (core->dbg->reg, true);
			signum = r_num_math (core->num, input + 2);
			ptr = strchr (input + 3, ' ');
			if (ptr) {
				int old_pid = core->dbg->pid;
				int old_tid = core->dbg->tid;
				int pid = atoi (ptr+1);
				int tid = pid; // XXX
				*ptr = 0;
				r_debug_select (core->dbg, pid, tid);
				r_debug_continue_kill (core->dbg, signum);
				r_debug_select (core->dbg, old_pid, old_tid);
			} else {
				r_debug_continue_kill (core->dbg, signum);
			}
		}
		break;
	case 's': // "dcs"
		switch (input[2]) {
		case '*':
			cmd_debug_cont_syscall (core, "-1");
			break;
		case ' ':
			cmd_debug_cont_syscall (core, input + 3);
			break;
		case '\0':
			cmd_debug_cont_syscall (core, NULL);
			break;
		default:
		case '?':
			r_core_cmd_help (core, help_msg_dcs);
			break;
		}
		break;
	case 'p': // "dcp"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dcp");
		} else {
			// XXX: this is very slow
			RIOMap *s;
			ut64 pc;
			int n = 0;
			bool t = core->dbg->trace->enabled;
			core->dbg->trace->enabled = false;
			r_cons_break_push (core->cons, static_debug_stop, core->dbg);
			do {
				r_debug_step (core->dbg, 1);
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
				pc = r_debug_reg_get (core->dbg, "PC");
				eprintf (" %d %"PFMT64x"\r", n++, pc);
				s = r_io_map_get_at (core->io, pc);
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
			} while (!s);
			eprintf ("\n");
			core->dbg->trace->enabled = t;
			r_cons_break_pop (core->cons);
			return 1;
		}
		break;
	case 'u': // "dcu"
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_dcu);
		} else {
			cmd_dcu (core, input);
		}
		break;
	case ' ':
		const char *pidstr = r_str_trim_head_ro (input + 2);
		if (!pidstr || !*pidstr) {
			R_LOG_ERROR ("Missing pid argument");
			break;
		}
		if (!r_num_is_valid_input (core->num, pidstr)) {
			R_LOG_ERROR ("Invalid pid argument: %s", pidstr);
			break;
		}
		old_pid = core->dbg->pid;
		pid = (int)r_num_math (core->num, pidstr);
		r_reg_arena_swap (core->dbg->reg, true);
		r_debug_select (core->dbg, pid, core->dbg->tid);
		r_debug_continue (core->dbg);
		r_debug_select (core->dbg, old_pid, core->dbg->tid);
		break;
	case 't':
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_dc, "dct");
		} else {
			cmd_debug_backtrace (core, input + 2);
		}
		break;
	case '?': // "dc?"
	default:
		r_core_cmd_help (core, help_msg_dc);
		return 0;
	}

	if (strchr (input, '?')) {
		return 0;
	}

	return 1;
}

static char *get_corefile_name(const char *raw_name, int pid) {
	return (!*raw_name)?
		r_str_newf ("core.%u", pid) :
		r_str_trim_dup (raw_name);
}

static int cmd_debug_step(RCore *core, const char *input) {
	ut64 addr = core->addr;
	ut8 buf[64];
	RAnalOp aop;
	int i, times = 1;
	char *ptr = strchr (input, ' ');
	if (ptr) {
		times = r_num_math (core->num, ptr + 1);
	}
	if (times < 1) {
		times = 1;
	}
	switch (input[1]) {
	case 0: // "ds"
	case ' ':
		if (r_config_get_b (core->config, "cfg.debug")) {
			r_reg_arena_swap (core->dbg->reg, true);
			// sync registers for BSD PT_STEP/PT_CONT
			// XXX(jjd): is this necessary?
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
			ut64 pc = r_debug_reg_get (core->dbg, "PC");
			r_debug_trace_pc (core->dbg, pc);
			if (!r_debug_step (core->dbg, times)) {
				R_LOG_ERROR ("Step failed");
				core->break_loop = true;
			}
		} else {
			if (core->dbg->anal->esil->trace) {
				ut64 pc = r_debug_reg_get (core->dbg, "PC");
				ut64 mask = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_VAL;
				RAnalOp *op = r_core_anal_op (core, pc, mask);
				r_esil_trace_op (core->dbg->anal->esil, op);
			}
			r_core_cmdf (core, "%daes", R_MAX (1, times));
		}
		break;
	case 'i': // "dsi"
		if (input[2] == ' ') {
			int n = 0;
			r_cons_break_push (core->cons, static_debug_stop, core->dbg);
			do {
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				r_debug_step (core->dbg, 1);
				if (r_debug_is_dead (core->dbg)) {
					core->break_loop = true;
					break;
				}
				r_core_cmd0 (core, ".dr*");
				n++;
			} while (!r_num_conditional (core->num, input + 3));
			r_cons_break_pop (core->cons);
			R_LOG_INFO ("Stopped after %d instructions", n);
		} else {
			R_LOG_ERROR ("Three missing argument");
		}
		break;
	case 'f': // "dsf"
		step_until_eof (core);
		break;
	case 'u': // "dsu"
		if (input[3] == '?') {
			r_core_cmd_help_match_spec (core, help_msg_dsu, "dsu", input[2]);
			return 0;
		}
		switch (input[2]) {
		case 'f': // dsuf
			step_until_flag (core, input + 3);
			break;
		case 'i': // dsui
			if (input[3] == 'r') {
				if (input[4] == '?') {
					r_core_cmd_help_match (core, help_msg_dsu, "dsuir");
				}
				step_until_inst (core, input + 4, true);
			} else {
				step_until_inst (core, input + 3, false);
			}
			break;
		case 'e': // dsue
			step_until_esil (core, input + 3);
			break;
		case 'o': // dsuo
			step_until_optype (core, input + 3);
			break;
		case ' ': // dsu <address>
			r_reg_arena_swap (core->dbg->reg, true);
			step_until (core, r_num_math (core->num, input + 2)); // XXX dupped by times
			break;
		default:
			r_core_cmd_help (core, help_msg_dsu);
			return 0;
		}
		break;
	case 'p': // "dsp"
		r_reg_arena_swap (core->dbg->reg, true);
		for (i = 0; i < times; i++) {
			ut8 buf[64];
			ut64 addr;
			RAnalOp aop;
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
			addr = r_debug_reg_get (core->dbg, "PC");
			r_io_read_at (core->io, addr, buf, sizeof (buf));
			r_anal_op (core->anal, &aop, addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
			if (aop.type == R_ANAL_OP_TYPE_CALL) {
				RBinObject *o = r_bin_cur_object (core->bin);
				RBinSection *s = r_bin_get_section_at (o, aop.jump, true);
				if (!s) {
					r_debug_step_over (core->dbg, times);
					continue;
				}
			}
			r_debug_step (core->dbg, 1);
		}
		break;
	case 's': // "dss"
		{
			addr = r_debug_reg_get (core->dbg, "PC");
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, addr);
			char *cmd = r_str_newf ("db 0x%"PFMT64x, addr);
			r_reg_arena_swap (core->dbg->reg, true);
			for (i = 0; i < times; i++) {
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
				r_io_read_at (core->io, addr, buf, sizeof (buf));
				r_anal_op (core->anal, &aop, addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
#if 0
				if (aop.jump != UT64_MAX && aop.fail != UT64_MAX) {
					eprintf ("Don't know how to skip this instruction\n");
					if (bpi) r_core_cmd0 (core, cmd);
					break;
				}
#endif
				addr += aop.size;
			}
			r_debug_reg_set (core->dbg, "PC", addr);
			r_reg_setv (core->anal->reg, "PC", addr);
			r_core_cmd0 (core, ".dr*");
			if (bpi) {
				r_core_cmd0 (core, cmd);
			}
			free (cmd);
			break;
		}
	case 'o': // "dso"
		if (r_config_get_i (core->config, "dbg.skipover")) {
			r_core_cmdf (core, "dss%s", input + 2);
		} else {
			if (r_config_get_b (core->config, "cfg.debug")) {
				addr = r_debug_reg_get (core->dbg, "PC");
				RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, addr);
				char *cmd = r_str_newf ("db 0x%"PFMT64x, addr);
				r_bp_del (core->dbg->bp, addr);
				r_reg_arena_swap (core->dbg->reg, true);
				r_debug_step_over (core->dbg, times);
				if (bpi) {
					r_core_cmd0 (core, cmd);
				}
				free (cmd);
			} else {
				r_core_cmdf (core, "aeso%s", input + 2);
			}
		}
		break;
	case 'b': // "dsb"
		if (r_config_get_b (core->config, "cfg.debug")) {
			if (!core->dbg->session) {
				R_LOG_ERROR ("Session has not started");
			} else if (r_debug_step_back (core->dbg, times) < 0) {
				R_LOG_ERROR ("stepping back failed");
			}
		} else {
			if (r_core_esil_step_back (core)) {
				r_core_cmd0 (core, ".dr*");
			} else {
				R_LOG_ERROR ("cannot step back");
			}
		}
		break;
	case 'l': // "dsl"
		r_reg_arena_swap (core->dbg->reg, true);
		step_line (core, times);
		break;
	case '?': // "ds?"
	default:
		r_core_cmd_help (core, help_msg_ds);
		return 0;
	}
	return 1;
}

static int run_buffer_dxr(RCore *core, RBuffer *buf, bool print, bool ignore_stack) {
	ut8 *raw;
	int raw_len;
	char *hexpairs;
	const char *cmd = ignore_stack? "dxrs": "dxr";
	int ret = 0;
	R_RETURN_VAL_IF_FAIL (core && buf, 1);

	r_buf_seek (buf, 0, R_BUF_SET);
	raw = r_buf_read_all (buf, &raw_len);
	if (!raw) {
		return 1;
	}

	hexpairs = malloc ((raw_len * 2) + 1);
	if (!hexpairs) {
		free (raw);
		return 1;
	}
	r_hex_bin2str (raw, raw_len, hexpairs);
	if (print) {
		r_cons_printf (core->cons, "%s %s\n", cmd, hexpairs);
	} else {
		ret = r_core_cmdf (core, "%s %s", cmd, hexpairs);
	}
	free (hexpairs);
	free (raw);

	return ret;
}

// TODO: dd commands need tests in archos/linux-x64/cmd_dd
// TODO: update the book page at src/debugger/files.html
static int cmd_debug_desc(RCore *core, const char *input) {
	int argc;
	char **argv;
	bool needs_live_process = false;
	bool print = false; // enabled with *, print the command instead of running it
	int ret = 0;

	if (input[1] == '?') { // "dd?"
		r_core_cmd_help (core, help_msg_dd);
		return 0;
	}

	if (!strncmp (input, "d*?", 3)) { // "dd*?"
		r_core_cmd_help_match (core, help_msg_dd, "dd");
		return 0;
	}

	argv = r_str_argv (input, &argc);
	if (!argv) {
		return 1;
	}

	/* Wait to move the first arg forward past the first 'd' until after argv creation.
	 * "dd filename" results in { "", "filename" } instead of { "filename" }.
	 *
	 * This mimics passing input+1 but allows a possible empty argv[0]
	 * to preserve argument positions.
	 * NOTE: we cannot move argv[0] forward, since it needs to be freed
	 * later, so input borrows instead */

	// Process modifiers
	for (input = argv[0] + 1; *input; input++) {
		// Need to know if we're printing help before the cfg.debug check
		// NB: input[0] will never start at '?', handled above
		if (*input && input[1] == '?') {
			if (*input == '*') {
				/* "ddt*?" -> "ddt?" */
				input--;
			}
			r_core_cmd_help_match_spec (core, help_msg_dd, "dd", input[0]);
			goto out_free_argv;
		}

		if (*input == '*') {
			print = true;
		}
	}

	// See the comment above
	input = R_BORROW argv[0] + 1;

	// "dd" and "dd*" always need a live process
	if (!print || !input[0] || (input[0] == '*' && !input[1])) {
		needs_live_process = true;
	}

	// Error out if we need a live process and there isn't one
	if (needs_live_process && !r_config_get_b (core->config, "cfg.debug")) {
		R_LOG_ERROR ("No child process to manage files for");
		ret = 1;
		goto out_free_argv;
	}

	// All ? help is handled in the modifier check
	switch (input[0]) {
	case '\0': // "dd"
	case '*': // "dd*"
	case '+': // "dd+"
	case ' ': // "dd"
		if (r_config_get_b (core->config, "cfg.debug")) {
			R_LOG_WARN ("Child file descriptors require the debugger. No alternative for static yet");
		} else {
			RBuffer *buf;
			char *filename;
			ut64 addr;
			int flags;

			if (argc < 2) {
				// only dd and dd* can have 1 arg here, others should error out
				if (!input[0] || input[0] == '*') {
					ret = r_debug_desc_list (core->dbg, print);
				} else {
					r_core_cmd_help_match_spec (core, help_msg_dd, "dd", input[0]);
				}
				break;
			}

			if (input[0] == '+') {
				flags = O_RDWR | O_CREAT;
			} else {
				flags = O_RDONLY;
			}

			// Filename can be a given string or char* address in memory
			addr = r_num_math (core->num, argv[1]);
			if (addr) {
				filename = r_core_cmd_strf (core, "ps @%" PFMT64x, addr);
			} else {
				filename = r_str_escape (argv[1]);
			}

			if (!(flags & O_CREAT) && !r_file_exists (filename)) {
				R_LOG_ERROR ("File %s does not exist", filename);
				free (filename);
				ret = 1;
				break;
			}

			if (print || flags != O_RDONLY || !r_debug_desc_open (core->dbg, filename)) {
				buf = r_core_syscallf (core, "open", "\"%s\", %d, 0644", filename, flags);
				if (buf) {
					ret = run_buffer_dxr (core, buf, print, false);
				} else {
					R_LOG_ERROR ("Cannot open");
				}
			}
			free (filename);
		}
		break;
	case 's': { // "dds"
		int fd;
		ut64 offset;

		if (argc < 2) {
			r_core_cmd_help_match (core, help_msg_dd, "dds");
			break;
		}

		fd = (int) r_num_math (core->num, argv[1]);
		if (argc > 2) {
			offset = r_num_math (core->num, argv[2]);
		} else {
			// default to 0 if not given
			offset = 0;
		}

		if (print || !r_debug_desc_seek (core->dbg, fd, offset)) {
			RBuffer *buf = r_core_syscallf (core, "lseek",
					"%d, 0x%" PFMT64x ", 0",
					fd, offset);
			if (buf) {
				ret = run_buffer_dxr (core, buf, print, true);
			} else {
				R_LOG_ERROR ("Cannot seek %d to %" PFMT64x, fd, offset);
			}
		}
		break;
	}
	case 'd': { // "ddd"
		int oldfd;
		int newfd;

		if (argc < 3) {
			r_core_cmd_help_match (core, help_msg_dd, "ddd");
			break;
		}

		oldfd = (int) r_num_math (core->num, argv[1]);
		newfd = (int) r_num_math (core->num, argv[2]);

		if (print || !r_debug_desc_dup (core->dbg, oldfd, newfd)) {
			RBuffer *buf = r_core_syscallf (core, "dup2",
					"%d, %d",
					oldfd, newfd);
			if (buf) {
				ret = run_buffer_dxr (core, buf, print, false);
			} else {
				R_LOG_ERROR ("Cannot dup %d -> %d", oldfd, newfd);
			}
		}
		break;
	}
	case 'r': { // "ddr"
		int fd;
		ut64 addr;
		ut64 count;
		char *perms;

		if (argc < 4) {
			r_core_cmd_help_match (core, help_msg_dd, "ddr");
			break;
		}

		fd = (int) r_num_math (core->num, argv[1]);
		addr = r_num_math (core->num, argv[2]);
		count = r_num_math (core->num, argv[3]);
		perms = r_core_cmd_strf (core, "dd~^%d[2]", fd);
		int nperm = r_str_rwx (perms);
		if (!print && nperm > 0 && !(nperm & 4)) {
			R_LOG_ERROR ("fd %d is not readable", fd);
			free (perms);
			ret = 1;
			break;
		}
		free (perms);

		if (print || !r_debug_desc_read (core->dbg, fd, addr, count)) {
			RBuffer *buf = r_core_syscallf (core, "read",
					"%d, 0x%" PFMT64x ", %" PFMT64u,
					fd, addr, count);
			if (buf) {
				ret = run_buffer_dxr (core, buf, print, true);
			} else {
				R_LOG_ERROR ("Cannot read %" PFMT64d "bytes from %d into 0x%" PFMT64x,
						count, fd, addr);
			}
		}
		break;
	}
	case 'w': { // "ddw"
		int fd;
		ut64 addr;
		ut64 count;
		char *perms;

		if (argc < 4) {
			r_core_cmd_help_match (core, help_msg_dd, "ddw");
			break;
		}

		fd = (int) r_num_math (core->num, argv[1]);
		addr = r_num_math (core->num, argv[2]);
		count = r_num_math (core->num, argv[3]);
		perms = r_core_cmd_strf (core, "dd~^%d[2]", fd);
		int nperm = r_str_rwx (perms);
		if (!print && nperm > 0 && !(nperm & 2)) {
			R_LOG_ERROR ("fd %d is not writable", fd);
			free (perms);
			ret = 1;
			break;
		}
		free (perms);

		if (print || !r_debug_desc_write (core->dbg, fd, addr, count)) {
			RBuffer *buf = r_core_syscallf (core, "write",
					"%d, 0x%" PFMT64x ", %" PFMT64d,
					fd, addr, count);
			if (buf) {
				ret = run_buffer_dxr (core, buf, print, true);
			} else {
				R_LOG_ERROR ("Cannot write %" PFMT64d "bytes into %d from 0x%" PFMT64x,
						count, fd, addr);
			}
		}
		break;
	}
	case 't': // "ddt"
	case '-': { // "dd-"
		int fd;

		if (input[0] == 't') {
			fd = 0;
		} else {
			if (argc < 2) {
				r_core_cmd_help_match (core, help_msg_dd, "dd-");
				break;
			}
			fd = (int) r_num_math (core->num, argv[1]);
		}

		if (print || !r_debug_desc_close (core->dbg, fd)) {
			RBuffer *buf = r_core_syscallf (core, "close", "%d", fd);
			if (buf) {
				ret = run_buffer_dxr (core, buf, print, false);
			} else {
				R_LOG_ERROR ("Cannot close %d", fd);
			}
		}
		break;
	}
	case 'f': { // "ddf"
		RBuffer *buf;
		ut64 addr;

		if (argc < 2) {
			r_core_cmd_help_match (core, help_msg_dd, "ddf");
			break;
		}

		addr = r_num_math (core->num, argv[1]);
		if (!addr) {
			R_LOG_ERROR ("%s is not a valid address", argv[1]);
			break;
		}

		buf = r_core_syscallf (core, "pipe", "0x%" PFMT64x, addr);
		if (buf) {
			ret = run_buffer_dxr (core, buf, print, true);
		} else {
			R_LOG_ERROR ("Cannot open pipe and write fd to %" PFMT64x, addr);
		}
		break;
	}
	default:
		r_core_cmd_help (core, help_msg_dd);
		break;
	}

out_free_argv:
	r_str_argv_free (argv);
	return ret;
}

static ut8 *getFileData(RCore *core, const char *arg, int *sz) {
	ut8 *out = NULL;
	int size = 0;
	if (*arg == '$' && !arg[1]) {
		R_LOG_ERROR ("No alias name given");
	} else if (*arg == '$') {
		RCmdAliasVal *v  = r_cmd_alias_get (core->rcmd, arg+1);
		if (v) {
			out = malloc (v->sz);
			if (out) {
				memcpy (out, v->data, v->sz);
				size = v->sz;
			}
		} else {
			R_LOG_ERROR ("No such alias \"$%s\"", arg + 1);
		}
	} else {
		size_t file_sz;
		out = (ut8*) r_file_slurp (arg, &file_sz);
		size = file_sz;
	}

	if (sz) {
		*sz = size;
	}

	return out;
}

R_VEC_TYPE(RVecDebugTracepoint, RDebugTracepointItem);

static int cmd_debug(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RDebugTracepointItem *t;
	bool do_follow = false;
	const char *ptr;
	ut64 addr;
	int min;
	RListIter *iter;
	RList *list;
	RDebugPid *p;
	RDebugTracepointItem *trace;
	RAnalOp *op;
	int ret = 0;
	ut64 old_seek = core->addr;

	if (r_sandbox_enable (0)) {
		R_LOG_INFO ("Debugger commands disabled in sandbox mode");
		return 0;
	}
	if (!strncmp (input, "ate", 3)) { // "date" -- same as pt.
		if (strstr (input, "-h") || strstr (input, "?")) {
			r_core_cmd_help_match (core, help_msg_d, "date");
			return 0;
		}
		bool use_beat = strstr (input, "-b");
		if (use_beat) {
			int sub_beats = 0;
			int beats = r_time_beats (r_time_now (), &sub_beats);
			r_cons_printf (core->cons, "@%03d.%d\n", beats, sub_beats);
		} else {
			char *nostr = r_time_secs_tostring (r_time_today ());
			r_cons_println (core->cons, nostr);
			free (nostr);
		}
		return 0;
	}

	switch (input[0]) {
	case 't':
		// TODO: define ranges? to display only some traces, allow to scroll on this disasm? ~.. ?
		switch (input[1]) {
		case '\0': // "dt"
		case '=': // "dt="
		case 'q': // "dtq"
		case 'j': // "dtj"
			r_debug_trace_list (core->dbg, input[1], core->addr, NULL);
			break;
		case '*': // "dt*"
			r_debug_trace_list (core->dbg, 1, core->addr, NULL);
			break;
		case ',': // "dt,"
			{
				RTable *t = r_core_table_new (core, "traces");
				r_debug_trace_list (core->dbg, ',', core->addr, t);
			}
			break;
		case ' ': // "dt [addr]"
			if ((t = r_debug_trace_get (core->dbg,
					r_num_math (core->num, input + 3)))) {
				r_cons_printf (core->cons, "offset = 0x%" PFMT64x "\n", t->addr);
				r_cons_printf (core->cons, "opsize = %d\n", t->size);
				r_cons_printf (core->cons, "times = %d\n", t->times);
				r_cons_printf (core->cons, "count = %d\n", t->count);
				//TODO cons_printf("time = %d\n", t->tm);
			}
			break;
		case 'a': // "dta"
			if (input[2]) {
				r_debug_trace_at (core->dbg, input + 3);
			} else {
				r_debug_trace_at (core->dbg, "$$");
			}
			break;
		case 't': // "dtt"
			if (input[2] == '.') {
				r_cons_printf (core->cons, "%d\n", core->dbg->trace->tag);
			} else if (input[2]) {
				r_debug_trace_tag (core->dbg, atoi (input + 3));
			} else {
				r_debug_trace_tag (core->dbg, 0);
			}
			break;
		case 'c': // "dtc"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_dt, "dtc");
			} else {
				debug_trace_calls (core, input + 2);
			}
			break;
		case 'd': // "dtd"
			min = r_num_math (core->num, input[2]? input + 3: input + 2);
			if (input[2] == 'q') { // "dtdq"
				int n = 0;
				R_VEC_FOREACH (core->dbg->trace->traces, trace) {
					if (n >= min) {
						r_cons_printf (core->cons, "%d  ", trace->count);
						r_cons_printf (core->cons, "0x%08"PFMT64x"\n", trace->addr);
						break;
					}
					n++;
				}
			} else if (input[2] == 'i') {
				int n = 0;
				R_VEC_FOREACH (core->dbg->trace->traces, trace) {
					op = r_core_anal_op (core, trace->addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
					if (n >= min) {
						r_cons_printf (core->cons, "%d %s\n", trace->count, op->mnemonic);
					}
					n++;
					r_anal_op_free (op);
				}
			} else if (input[2] == ' ') {
				int n = 0;
				R_VEC_FOREACH (core->dbg->trace->traces, trace) {
					op = r_core_anal_op (core, trace->addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
					if (n >= min) {
						const char *opstr = op? op->mnemonic: "?";
						r_cons_printf (core->cons, "0x%08"PFMT64x" %s\n", trace->addr, opstr);
					}
					n++;
					r_anal_op_free (op);
				}
			} else {
				// TODO: reimplement using the api
				//r_core_cmd0 (core, "pd 1 @@= `dtq`");
				R_VEC_FOREACH (core->dbg->trace->traces, trace) {
					op = r_core_anal_op (core, trace->addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
					const char *opstr = op? op->mnemonic: "?";
					r_cons_printf (core->cons, "0x%08"PFMT64x" %s\n", trace->addr, opstr);
					r_anal_op_free (op);
				}
			}
			break;
		case 'g': // "dtg"
			dot_trace_traverse (core, core->dbg->tree, input[2]);
			break;
		case '-': // "dt-"
			r_tree_reset (core->dbg->tree);
			r_debug_trace_free (core->dbg->trace);
			r_debug_tracenodes_reset (core->dbg);
			core->dbg->trace = r_debug_trace_new ();
			break;
		case '+': // "dt+"
			if (input[2] == '+') { // "dt++"
				char *a, *s = r_str_trim_dup (input + 3);
				RList *args = r_str_split_list (s, " ", 0);
				RListIter *iter;
				r_list_foreach (args, iter, a) {
					ut64 addr = r_num_get (NULL, a);
					(void)r_debug_trace_add (core->dbg, addr, 1);
				}
				r_list_free (args);
				free (s);
			} else {
				ptr = input + 2;
				addr = r_num_math (core->num, ptr);
				ptr = strchr (ptr, ' ');
				int count = 1;
				if (ptr) {
					count = r_num_math (core->num, ptr + 1);
				}
				RAnalOp *op = r_core_op_anal (core, addr, R_ARCH_OP_MASK_HINT);
				if (op) {
					RDebugTracepointItem *tp = r_debug_trace_add (core->dbg, addr, op->size);
					if (tp) {
						tp->count = count;
						r_anal_trace_bb (core->anal, addr);
					}
					r_anal_op_free (op);
				} else {
					R_LOG_ERROR ("Cannot analyze opcode at 0x%08" PFMT64x, addr);
				}
			}
			break;
#if 0
		case 'e': // "dte"
			if (!core->anal->esil) {
				int stacksize = r_config_get_i (core->config, "esil.stack.depth");
				int romem = r_config_get_i (core->config, "esil.romem");
				int stats = r_config_get_i (core->config, "esil.stats");
				int iotrap = r_config_get_i (core->config, "esil.iotrap");
				int nonull = r_config_get_i (core->config, "esil.nonull");
				unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
				if (!(core->anal->esil = r_esil_new (stacksize, iotrap, addrsize))) {
					return 0;
				}
				r_esil_setup (core->anal->esil, core->anal, romem, stats, nonull);
			}
			switch (input[2]) {
			case 0: // "dte"
				r_esil_trace_list (core->anal->esil, 0);
				break;
			case '*': // "dte"
				r_esil_trace_list (core->anal->esil, '*');
				break;
			case 'i': { // "dtei"
				ut64 addr = r_num_math (core->num, input + 3);
				if (!addr) {
					addr = core->addr;
				}
				RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_ESIL);
				if (op) {
					r_esil_trace_op (core->anal->esil, op);
					r_anal_op_free (op);
				}
			} break;
			case '-': // "dte-"
				if (!strcmp (input + 3, "*")) {
					r_esil_trace_free (core->anal->esil->trace);
					core->anal->esil->trace = r_esil_trace_new (core->anal->esil);
#if 0
					if (core->anal->esil && core->anal->esil->trace) {
						sdb_free (core->anal->esil->trace->db);
						core->anal->esil->trace->db = sdb_new0 ();
					}
#endif
				} else {
					R_LOG_TODO ("dte- cannot delete specific logs. Use dte-*");
				}
				break;
			case ' ': { // "dte "
					int idx = atoi (input + 3);
					r_esil_trace_show (core->anal->esil, idx, 0);
				}
				break;
			case 'd':
				r_core_cmd0 (core, "pd 1 @@=`dte~addr[1]`");
				break;
#if 0
			case 'k': // "dtek"
				if (input[3] == 0) {
					Sdb *db = core->anal->esil->trace->db;
					char *s = sdb_querys (db, NULL, 0, "*");
					if (s) {
						r_str_trim (s);
						r_cons_println (core->cons, s);
						free (s);
					}
				} else if (input[3] == ' ') {
					if (core->anal->esil->trace) {
						Sdb *db = core->anal->esil->trace->db;
						char *s = sdb_querys (db, NULL, 0, input + 4);
						if (s) {
							r_str_trim (s);
							r_cons_println (core->cons, s);
							free (s);
						}
					} else {
						R_LOG_ERROR ("esil->trace is null. run 'e dbg.trace=true;dtei' to fix that. ");
					}
				} else {
					r_core_cmd_help_match (core, help_msg_dte, "dtek");
				}
				break;
#endif
			default:
				r_core_cmd_help (core, help_msg_dte);
				break;
			}
			break;
#endif
		case 's': // "dts"
			switch (input[2]) {
			case '+': // "dts+"
				if (r_debug_is_dead (core->dbg)) {
					R_LOG_ERROR ("Cannot start session outside of debug mode, run ood?");
					break;
				}
				if (core->dbg->session) {
					R_LOG_INFO ("Session already started");
				} else {
					core->dbg->session = r_debug_session_new ();
					r_debug_add_checkpoint (core->dbg);
				}
				break;
			case '-': // "dts-"
				if (core->dbg->session) {
					r_debug_session_free (core->dbg->session);
					core->dbg->session = NULL;
				} else {
					R_LOG_INFO ("No session started");
				}
				break;
			case 't': // "dtst"
				if (core->dbg->session) {
					const char *sname = r_str_trim_head_ro (input + 3);
					if (R_STR_ISNOTEMPTY (sname)) {
						r_debug_session_save (core->dbg->session, sname);
					} else {
						R_LOG_ERROR ("Missing argument");
					}
				} else {
					R_LOG_INFO ("No session started");
				}
				break;
			case 'f': // "dtsf"
				if (core->dbg->session) {
					r_debug_session_free (core->dbg->session);
					core->dbg->session = NULL;
				}
				{
					const char *sname = r_str_trim_head_ro (input + 3);
					if (R_STR_ISNOTEMPTY (sname)) {
						core->dbg->session = r_debug_session_new ();
						r_debug_session_load (core->dbg, sname);
					} else {
						R_LOG_ERROR ("Missing argument");
					}
				}
				break;
			case 'm': // "dtsm"
				if (core->dbg->session) {
					r_debug_session_list_memory (core->dbg);
				}
				break;
			default:
				r_core_cmd_help (core, help_msg_dts);
			}
			break;
		case '?':
		default:
			r_core_cmd_help (core, help_msg_dt);
			break;
		}
		break;
	case 'd': // "dd"
		ret = cmd_debug_desc (core, input);
		break;
	case 's': // "ds"
		if (cmd_debug_step (core, input)) {
			do_follow = true;
		}
		break;
	case 'b': // "db"
		r_core_cmd_bp (core, input);
		break;
	case 'H': // "dH"
		R_LOG_TODO ("transplant process");
		break;
	case 'c': // "dc"
		r_cons_break_push (core->cons, static_debug_stop, core->dbg);
		if (cmd_debug_continue (core, input)) {
			do_follow = true;
		}
		r_cons_break_pop (core->cons);
		break;
	case 'm': // "dm"
		cmd_debug_map (core, input + 1);
		break;
	case 'r': // "dr"
		if (r_config_get_b (core->config, "cfg.debug") || input[1] == '?') {
			cmd_debug_reg (core, input + 1);
		} else {
			cmd_anal_reg (core, input + 1);
		}
		//r_core_cmd (core, "|reg", 0);
		break;
	case 'p': // "dp"
		cmd_debug_pid (core, input);
		break;
	case 'L': // "dL"
		switch (input[1]) {
		case 'q':
			r_debug_plugin_list (core->dbg, input[1]);
			break;
		case 'j':
			core->dbg->pj = r_core_pj_new (core);
			r_debug_plugin_list (core->dbg, 'j');
			pj_free (core->dbg->pj);
			core->dbg->pj = NULL;
			break;
		case '?':
			r_core_cmd_help (core, help_msg_dL);
			break;
		case ' ': {
			char *str = r_str_trim_dup (input + 2);
			r_config_set (core->config, "dbg.backend", str);
			// implicit by config.set r_debug_use (core->dbg, str);
			free (str);
			}
			break;
		default:
			r_debug_plugin_list (core->dbg, 0);
			break;
		}
		break;
	case 'i': // "di"
		if (input[1] == 'r' ) { // "dir"
			r_core_cmdf (core, "ls%s", input + 2);
		} else {
			RDebugInfo *rdi = r_debug_info (core->dbg, input + 2);
			RDebugReasonType stop = r_debug_stop_reason (core->dbg);
			switch (input[1]) {
			case '\0': // "di"
				if (!r_config_get_b (core->config, "cfg.debug")) {
					R_LOG_WARN ("No debugee information available when not using the debugger");
				} else {
#define P(x,y) r_cons_printf (core->cons, x, y)
					if (stop != -1) {
						if (core->dbg->reason.type == R_DEBUG_REASON_SIGNAL) {
							P ("signalstr=%s\n", r_signal_to_human (core->dbg->reason.signum));
						}
						P ("stopreason=%s\n", r_debug_reason_tostring (stop));
					}
					if (rdi) {
						const char *s = r_signal_tostring (core->dbg->reason.signum);
						P ("type=%s\n", r_debug_reason_tostring (core->dbg->reason.type));
						P ("signal=%s\n", r_str_get_fail (s, "none"));
						P ("sigstr=%s\n", r_signal_to_human (core->dbg->reason.signum));
						P ("signum=%d\n", core->dbg->reason.signum);
						P ("sigpid=%d\n", core->dbg->reason.tid);
						P ("addr=0x%"PFMT64x"\n", core->dbg->reason.addr);
						P ("bp_addr=0x%"PFMT64x"\n", core->dbg->reason.bp_addr);
						P ("inbp=%s\n", r_str_bool (core->dbg->reason.bp_addr));
						P ("baddr=0x%"PFMT64x"\n", r_debug_get_baddr (core->dbg, NULL));
						P ("pid=%d\n", rdi->pid);
						P ("tid=%d\n", rdi->tid);
						P ("stopaddr=0x%"PFMT64x"\n", core->dbg->stopaddr);
						if (rdi->uid != -1) {
							P ("uid=%d\n", rdi->uid);
						}
						if (rdi->gid != -1) {
							P ("gid=%d\n", rdi->gid);
						}
						if (rdi->usr) {
							P ("usr=%s\n", rdi->usr);
						}
						if (rdi->exe && *rdi->exe) {
							P ("exe=%s\n", rdi->exe);
						}
						if (rdi->cmdline && *rdi->cmdline) {
							P ("cmdline=%s\n", rdi->cmdline);
						}
						if (rdi->cwd && *rdi->cwd) {
							P ("cwd=%s\n", rdi->cwd);
						}
						if (rdi->kernel_stack && *rdi->kernel_stack) {
							P ("kernel_stack=\n%s\n", rdi->kernel_stack);
						}
					}
				}
				break;
			case 'f': // "dif" "diff"
				if (input[1] == '?') {
					r_core_cmd_help_match (core, help_msg_di, "dif");
				} else {
					char *arg = strchr (input, ' ');
					if (arg) {
						arg = strdup (r_str_trim_head_ro (arg + 1));
						char *arg2 = strchr (arg, ' ');
						if (arg2) {
							*arg2++ = 0;
							int al;
							int bl;
							ut8 *a = getFileData (core, arg, &al);
							ut8 *b = getFileData (core, arg2, &bl);
							if (a && b) {
								RDiff *d = r_diff_new ();
								char *uni = r_diff_buffers_tostring (d, a, al, b, bl);
								r_cons_printf (core->cons, "%s\n", uni);
								r_diff_free (d);
								free (uni);
							} else {
								R_LOG_ERROR ("Cannot open those alias files");
							}
							free (a);
							free (b);
						}
						free (arg);
					} else {
						r_core_cmd_help_match (core, help_msg_di, "dif");
					}
				}
				break;
			case '*': // "di*"
				if (rdi) {
					r_cons_printf (core->cons, "f dbg.signal = %d\n", core->dbg->reason.signum);
					r_cons_printf (core->cons, "f dbg.sigpid = %d\n", core->dbg->reason.tid);
					r_cons_printf (core->cons, "f dbg.inbp = %d\n", core->dbg->reason.bp_addr? 1: 0);
					r_cons_printf (core->cons, "f dbg.sigaddr = 0x%"PFMT64x"\n", core->dbg->reason.addr);
					r_cons_printf (core->cons, "f dbg.baddr = 0x%"PFMT64x"\n", r_debug_get_baddr (core->dbg, NULL));
					r_cons_printf (core->cons, "f dbg.pid = %d\n", rdi->pid);
					r_cons_printf (core->cons, "f dbg.tid = %d\n", rdi->tid);
					r_cons_printf (core->cons, "f dbg.uid = %d\n", rdi->uid);
					r_cons_printf (core->cons, "f dbg.gid = %d\n", rdi->gid);
				}
				break;
			case 'j': // "dij"
				{
					PJ *pj = r_core_pj_new (core);
					pj_o (pj);
					pj_ks (pj, "stopreason", r_debug_reason_tostring (stop));
				if (rdi) {
					const char *s = r_signal_tostring (core->dbg->reason.signum);
					pj_ks (pj, "type", r_debug_reason_tostring (core->dbg->reason.type));
					pj_ks (pj, "signal", r_str_get_fail (s, "none"));
					pj_kn (pj, "signum", core->dbg->reason.signum);
					pj_ks (pj, "sigstr", r_signal_to_human (core->dbg->reason.signum));
					pj_kn (pj, "sigpid", core->dbg->reason.tid);
					pj_kn (pj, "addr", core->dbg->reason.addr);
					pj_kn (pj, "inbp", core->dbg->reason.bp_addr);
					pj_kn (pj, "baddr", r_debug_get_baddr (core->dbg, NULL));
					pj_kn (pj, "stopaddr", core->dbg->stopaddr);
					pj_kn (pj, "pid", rdi->pid);
					pj_kn (pj, "tid", rdi->tid);
					pj_kn (pj, "uid", rdi->uid);
					pj_kn (pj, "gid", rdi->gid);
					if (rdi->usr) {
						pj_ks (pj, "usr", rdi->usr);
					}
					if (rdi->exe) {
						pj_ks (pj, "exe", rdi->exe);
					}
					if (rdi->cmdline) {
						pj_ks (pj, "cmdline", rdi->cmdline);
					}
					if (rdi->cwd) {
						pj_ks (pj, "cwd", rdi->cwd);
					}
				}
				pj_end (pj);
				char *s = pj_drain (pj);
				P("%s", s);
				free (s);
				}
				break;
#undef P
#undef PS
			case 'q': // "diq"
				{
					const char *r = r_debug_reason_tostring (core->dbg->reason.type);
					if (!r) {
						r = "none";
					}
					r_cons_printf (core->cons, "%s at 0x%08"PFMT64x"\n", r, core->dbg->stopaddr);
				}
				break;
			case '?': // "di?"
			default:
				r_core_cmd_help (core, help_msg_di);
				break;
			}
			r_debug_info_free (rdi);
		}
		break;
	case ':': // "d:"
		r_core_return_value (core,
				r_debug_cmd (core->dbg, input + 1)
				? R_CMD_RC_FAILURE
				: R_CMD_RC_SUCCESS);
		break;
	case 'e': // "de"
		r_core_debug_esil (core, input + 1);
		break;
	case 'g': // "dg"
		if (core->dbg->current && core->dbg->current->plugin && core->dbg->current->plugin->gcore) {
			if (core->dbg->pid == -1) {
				R_LOG_ERROR ("Not debugging, can't write core");
				break;
			}
			char *corefile = get_corefile_name (input + 1, core->dbg->pid);
			R_LOG_INFO ("Writing to file '%s'", corefile);
			r_file_rm (corefile);
			RBuffer *dst = r_buf_new_file (corefile, O_RDWR | O_CREAT, 0644);
			if (dst) {
				if (!core->dbg->current->plugin->gcore (core->dbg, dst)) {
					R_LOG_ERROR ("dg: coredump failed");
				}
				r_buf_free (dst);
			} else {
				perror ("r_buf_new_file");
			}
			free (corefile);
		}
		break;
	case 'k': // "dk"
		r_core_debug_kill (core, input + 1);
		break;
	case 'o': // "do"
		switch (input[1]) {
		case '\0': // "do"
			r_core_file_reopen (core, input[1] ? input + 2: NULL, 0, 1);
			break;
		case 'e': // "doe"
			switch (input[2]) {
			case '\0': // "doe"
				if (core->io->envprofile) {
					r_cons_println (core->cons, core->io->envprofile);
				}
				break;
			case '!': // "doe!"
			{
				char *out = r_core_editor (core, NULL, core->io->envprofile);
				if (out) {
					free (core->io->envprofile);
					core->io->envprofile = out;
					eprintf ("%s\n", core->io->envprofile);
				}
			} break;
			default:
				break;
			}
			break;
		case 'r': // "dor" : rarun profile
			if (input[2] == ' ') {
				setRarunProfileString (core, input + 3);
			} else {
				// TODO use the api
				r_sys_cmd ("rarun2 -h");
			}
			break;
		case 'o': // "doo" : reopen in debug mode
			if (input[2] == 'f') { // "doof" : reopen in debug mode from the given file
				r_config_set_b (core->config, "cfg.debug", true);
				r_core_cmdf (core, "oodf %s", input + 3);
			} else {
				r_core_file_reopen_debug (core, input + 2);
			}
			break;
		case 'c': // "doc" : close current debug session
			if (!core->io->desc || !r_config_get_b (core->config, "cfg.debug")) {
				R_LOG_ERROR ("Not in a debug session (cfg.debug)");
				break;
			}
			// Stop trace session
			if (core->dbg->session) {
				r_debug_session_free (core->dbg->session);
				core->dbg->session = NULL;
			}
			// Kill debugee and all child processes
			RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
			if (plugin && plugin->pids && core->dbg->pid != -1) {
				list = plugin->pids (core->dbg, core->dbg->pid);
				if (list) {
					r_list_foreach (list, iter, p) {
						r_debug_kill (core->dbg, p->pid, p->pid, SIGKILL);
						r_debug_detach (core->dbg, p->pid);
					}
				} else {
					r_debug_kill (core->dbg, core->dbg->pid, core->dbg->pid, SIGKILL);
					r_debug_detach (core->dbg, core->dbg->pid);
				}
			}
			// Remove registers from the flag list
			r_core_cmd0 (core, ".dr-*");
			// Reopen and rebase the original file
			r_core_cmd_call (core, "oo");
			break;
		case '?': // "do?"
		default:
			r_core_cmd_help (core, help_msg_do);
			break;
		}
		break;
#if R2__WINDOWS__
	case 'W': // "dW"
		if (input[1] == 'i') {
			r_w32_identify_window ();
		} else {
			r_w32_print_windows (core->dbg);
		}
		break;
#endif
	case 'w': // "dw"
		r_cons_break_push (core->cons, static_debug_stop, core->dbg);
		for (;!r_cons_is_breaked (core->cons);) {
			int pid = atoi (input + 1);
			//int opid = core->dbg->pid = pid;
			int res = r_debug_kill (core->dbg, pid, 0, 0);
			if (!res) {
				break;
			}
			r_sys_usleep (200);
		}
		r_cons_break_pop (core->cons);
		break;
	case 'x': // "dx"
		switch (input[1]) {
		case 'r':   // "dxr"
			if (input[2] == 's') { // "dxrs"
				if (input[3] != ' ') {
					r_core_cmd_help_match (core, help_msg_dx, "dxrs");
					break;
				}
			} else if (input[2] != ' ') {
				r_core_cmd_help_match (core, help_msg_dx, "dxr");
				break;
			}
			/* fall through */
		case ' ': { // "dx "
			ut8 bytes[4096];
			const bool is_dxr = input[1] == 'r';
			const bool is_dxrs = is_dxr && input[2] == 's';
			const char *hexpairs = input + 2;
			if (is_dxr) {
				hexpairs++;
				if (is_dxrs) {
					hexpairs++;
				}
			}

			if (strlen (hexpairs) < 8192) {
				int bytes_len = r_hex_str2bin (hexpairs, bytes);
				if (bytes_len > 0) {
					if (!r_debug_execute (core->dbg, bytes, bytes_len, NULL, is_dxr, is_dxrs)) {
						R_LOG_ERROR ("Failed to execute code");
					}
				} else {
					R_LOG_ERROR ("Failed to parse hex pairs");
				}
			} else {
				R_LOG_ERROR ("Cannot inject more than 4096 bytes at once");
			}
			break;
		}
		case 'a': { // "dxa"
			RAsmCode *acode;
			if (input[2] == '?' || input[2] != ' ') {
				r_core_cmd_help_match (core, help_msg_dx, "dxa");
				break;
			}
			r_asm_set_pc (core->rasm, core->addr);
			acode = r_asm_assemble (core->rasm, input + 2);
			if (acode) {
				r_reg_arena_push (core->dbg->reg);
				if (!r_debug_execute (core->dbg, acode->bytes, acode->len, NULL, false, false)) {
					R_LOG_ERROR ("Failed to inject code");
				}
				r_reg_arena_pop (core->dbg->reg);
			}
			r_asm_code_free (acode);
			break;
		}
		case 'e': // "dxe"
			if (input[2] == '?' || input[2] != ' ') {
				r_core_cmd_help (core, help_msg_dxe);
			} else { // "dxe"
				const char *program = r_str_trim_head_ro (input + 2);
				REgg *egg = core->egg;
				const char *asm_arch = r_config_get (core->config, "asm.arch");
				int asm_bits = r_config_get_i (core->config, "asm.bits");
				const char *asm_os = r_config_get (core->config, "asm.os");
				r_egg_setup (egg, asm_arch, asm_bits, 0, asm_os);
				r_egg_reset (egg);
				r_egg_load (egg, program, 0);
				if (r_egg_compile (egg)) {
					// assemble the blob
					if (r_egg_assemble (egg)) {
						RBuffer *b = r_egg_get_bin (egg);
						r_asm_set_pc (core->rasm, core->addr);
						r_reg_arena_push (core->dbg->reg);
						ut64 tmpsz;
						const ut8 *tmp = r_buf_data (b, &tmpsz);
						if (tmpsz > 0) {
							if (!r_debug_execute (core->dbg, tmp, tmpsz, NULL, false, false)) {
								R_LOG_ERROR ("Failed to inject code");
							}
						} else {
							R_LOG_ERROR ("No egg program compiled to execute");
						}
						r_reg_arena_pop (core->dbg->reg);
					} else {
						char *code = r_buf_tostring (egg->buf);
						R_LOG_ERROR ("Failed to assemble '%s'", code);
						free (code);
					}
				} else {
					R_LOG_ERROR ("Cannot compile the given egg program");
				}
			}
			break;
		case 's': // "dxs"
			if (input[2]) {
				r_cons_push (core->cons);
				char *cmd = r_str_newf ("gs %s", input + 2);
				char *str = r_core_cmd_str (core, cmd);
				free (cmd);
				r_cons_pop (core->cons);
				r_core_cmdf (core, "dx %s", str); //`gs %s`", input + 2);
				free (str);
			} else {
				R_LOG_ERROR ("Missing parameter used in gs by dxs");
			}
			break;
		case '?': // "dx?"
		default:
			r_core_cmd_help (core, help_msg_dx);
			break;
		}
		break;
	case '?': // "d?"
		r_core_cmd_help (core, help_msg_d);
		break;
	default:
		r_core_return_invalid_command (core, "d", *input);
		break;
	}

	/* RDebug, specifically RDebug.execute() may incorrectly
	 * advance seek, so we force it back here before processing
	 * dbg.follow. */
	if (core->addr != old_seek) {
		r_core_seek (core, old_seek, false);
	}

	if (do_follow) {
		int follow = r_config_get_i (core->config, "dbg.follow");
		ut64 pc = r_debug_reg_get (core->dbg, "PC");
		// Is PC before offset or after the follow cutoff?
		if (!R_BETWEEN (core->addr, pc, core->addr + follow)) {
			r_core_cmd_call (core, "sr PC");
		}
	}

	return ret;
}

#endif
