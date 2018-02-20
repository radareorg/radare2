/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "r_core.h"
#include "r_util.h"
#include "r_cons.h"
#include "sdb/sdb.h"

#define TN_KEY_LEN 32
#define TN_KEY_FMT "%"PFMT64u

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#include "r_heap_glibc.h"
#endif

#if HAVE_JEMALLOC
#include "r_heap_jemalloc.h"
#include "linux_heap_jemalloc.c"
#endif

static const char *help_msg_d[] = {
	"Usage:", "d", " # Debug commands",
	"db", "[?]", "Breakpoints commands",
	"dbt", "[?]", "Display backtrace based on dbg.btdepth and dbg.btalgo",
	"dc", "[?]", "Continue execution",
	"dd", "[?]", "File descriptors (!fd in r1)",
	"de", "[-sc] [rwx] [rm] [e]", "Debug with ESIL (see de?)",
	"dg", " <file>", "Generate a core-file (WIP)",
	"dH", " [handler]", "Transplant process to a new handler",
	"di", "[?]", "Show debugger backend information (See dh)",
	"dk", "[?]", "List, send, get, set, signal handlers of child",
	"dL", " [handler]", "List or set debugger handler",
	"dm", "[?]", "Show memory maps",
	"do", "[?]", "Open process (reload, alias for 'oo')",
	"doo", "[args]", "Reopen in debugger mode with args (alias for 'ood')",
	"dp", "[?]", "List, attach to process or thread id",
	"dr", "[?]", "Cpu registers",
	"ds", "[?]", "Step, over, source line",
	"dt", "[?]", "Display instruction traces (dtr=reset)",
	"dw", " <pid>", "Block prompt until pid dies",
	"dx", "[?]", "Inject and run code on target process (See gs)",
	NULL
};

static const char *help_msg_db[] = {
	"Usage: db", "", " # Breakpoints commands",
	"db", "", "List breakpoints",
	"db", " sym.main", "Add breakpoint into sym.main",
	"db", " <addr>", "Add breakpoint",
	"db-", " <addr>", "Remove breakpoint",
	"db-*", "", "Remove all the breakpoints",
	"db.", "", "Show breakpoint info in current offset",
	"dbj", "", "List breakpoints in JSON format",
	// "dbi", " 0x848 ecx=3", "stop execution when condition matches",
	"dbc", " <addr> <cmd>", "Run command when breakpoint is hit",
	"dbC", " <addr> <cmd>", "Run command but continue until <cmd> returns zero",
	"dbd", " <addr>", "Disable breakpoint",
	"dbe", " <addr>", "Enable breakpoint",
	"dbs", " <addr>", "Toggle breakpoint",
	"dbf", "", "Put a breakpoint into every no-return function",
	//
	"dbm", " <module> <offset>", "Add a breakpoint at an offset from a module's base",
	"dbn", " [<name>]", "Show or set name for current breakpoint",
	//
	"dbi", "", "List breakpoint indexes",
	"dbic", " <index> <cmd>", "Run command at breakpoint index",
	"dbie", " <index>", "Enable breakpoint by index",
	"dbid", " <index>", "Disable breakpoint by index",
	"dbis", " <index>", "Swap Nth breakpoint",
	"dbite", " <index>", "Enable breakpoint Trace by index",
	"dbitd", " <index>", "Disable breakpoint Trace by index",
	"dbits", " <index>", "Swap Nth breakpoint trace",
	//
	"dbh", " x86", "Set/list breakpoint plugin handlers",
	"dbh-", " <name>", "Remove breakpoint plugin handler",
	"dbw", " <addr> <rw>", "Add watchpoint",
	"drx", " number addr len rwx", "Modify hardware breakpoint",
	"drx-", "number", "Clear hardware breakpoint",
	NULL
};

static const char *help_msg_dbt[] = {
	"Usage: dbt", "", " # Backtrace commands",
	"dbt", "", "Display backtrace based on dbg.btdepth and dbg.btalgo",
	"dbt*", "", "Display backtrace in flags",
	"dbt=", "", "Display backtrace in one line (see dbt=s and dbt=b for sp or bp)",
	"dbtv", "", "Display backtrace with local vars if any",
	"dbtj", "", "Display backtrace in JSON",
	"dbta", "", "Display ascii-art representation of the stack backtrace",
	"dbte", " <addr>", "Enable Breakpoint Trace",
	"dbtd", " <addr>", "Disable Breakpoint Trace",
	"dbts", " <addr>", "Swap Breakpoint Trace",
	NULL
};

static const char *help_msg_dc[] = {
	"Usage: dc", "", "Execution continuation commands",
	"dc", "", "Continue execution of all children",
	"dc", " <pid>", "Continue execution of pid",
	"dc", "[-pid]", "Stop execution of pid",
	"dca", " [sym] [sym].", "Continue at every hit on any given symbol",
	"dcb", "", "Continue back until breakpoint",
	"dcc", "", "Continue until call (use step into)",
	"dccu", "", "Continue until unknown call (call reg)",
#if __WINDOWS__ && !__CYGWIN__
	"dce", "", "Continue execution (pass exception to program)",
#endif
	"dcf", "", "Continue until fork (TODO)",
	"dck", " <signal> <pid>", "Continue sending signal to process",
	"dco", " <num>", "Step over <num> instructions",
	"dcp", "", "Continue until program code (mapped io section)",
	"dcr", "", "Continue until ret (uses step over)",
	"dcs", "[?] <num>", "Continue until syscall",
	"dct", " <len>", "Traptrace from curseek to len, no argument to list",
	"dcu", "[?] [..end|addr] ([end])", "Continue until address (or range)",
	/*"TODO: dcu/dcr needs dbg.untilover=true??",*/
	/*"TODO: same for only user/libs side, to avoid steping into libs",*/
	/*"TODO: support for threads?",*/
	NULL
};

static const char *help_msg_dcs[] = {
	"Usage:", "dcs", " Continue until syscall",
	"dcs", "", "Continue until next syscall",
	"dcs [str]", "", "Continue until next call to the 'str' syscall",
	"dcs", "*", "Trace all syscalls, a la strace",
	NULL
};

static const char *help_msg_dcu[] = {
	"Usage:", "dcu", " Continue until address",
	"dcu.", "", "Alias for dcu $$ (continue until current address",
	"dcu", " address", "Continue until address",
	"dcu", " [..tail]", "Continue until the range",
	"dcu", " [from] [to]", "Continue until the range",
	NULL
};

static const char *help_msg_dd[] = {
	"Usage: dd", "", "Descriptors commands",
	"dd", "", "List file descriptors",
	"dd", " <file>", "Open and map that file into the UI",
	"dd-", "<fd>", "Close stdout fd",
	"dd*", "", "List file descriptors (in radare commands)",
	"dds", " <fd> <off>", "Seek given fd)",
	"ddd", " <fd1> <fd2>", "Dup2 from fd1 to fd2",
	"ddr", " <fd> <size>", "Read N bytes from fd",
	"ddw", " <fd> <hexpairs>", "Write N bytes to fd",
	NULL
};

static const char *help_msg_de[] = {
	"Usage:", "de", "[-sc] [rwx] [rm] [expr]",
	"de", "", "List esil watchpoints",
	"de-*", "", "Delete all esil watchpoints",
	"de", " [rwx] [rm] [addr|reg|from..to]", "Stop on condition",
	"dec", "", "Continue execution until matching expression",
	"des", "[?] [N]", "Step-in N instructions with esildebug",
	"desu", " [addr]", "Esildebug until specific address",
	NULL
};

static const char *help_msg_des[] = {
	"Usage:", "des", "[u] [arg]",
	"des", " [N]", "step-in N instructions with esildebug",
	"desu", " [addr]", "esildebug until specific address",
	NULL
};

static const char *help_msg_di[] = {
	"Usage: di", "", "Debugger target information",
	"di", "", "Show debugger target information",
	"di*", "", "Same as above, but in r2 commands",
	"dij", "", "Same as above, but in JSON format",
	NULL
};

static const char *help_msg_dk[] = {
	"Usage: dk", "", "Signal commands",
	"dk", "", "List all signal handlers of child process",
	"dk", " <signal>", "Send KILL signal to child",
	"dk", " <signal>=1", "Set signal handler for <signal> in child",
	"dk?", "<signal>", "Name/signum resolver",
	"dko", "[?] <signal>", "Reset skip or cont options for given signal",
	"dko", " <signal> [|skip|cont]", "On signal SKIP handler or CONT into",
	"dkj", "", "List all signal handlers in JSON",
	NULL
};

static const char *help_msg_dko[] = {
	"Usage:", "dko", " # Signal handling commands",
	"dko", "", "List existing signal handling",
	"dko", " [signal]", "Clear handling for a signal",
	"dko", " [signal] [skip|cont]", "Set handling for a signal",
	NULL
};

static const char *help_msg_dm[] = {
	"Usage:", "dm", " # Memory maps commands",
	"dm", "", "List memory maps of target process",
	"dm", " address size", "Allocate <size> bytes at <address> (anywhere if address is -1) in child process",
	"dm=", "", "List memory maps of target process (ascii-art bars)",
	"dm.", "", "Show map name of current address",
	"dm*", "", "List memmaps in radare commands",
	"dm-", " address", "Deallocate memory map of <address>",
	"dmd", "[a] [file]", "Dump current (all) debug map region to a file (from-to.dmp) (see Sd)",
	"dmh", "[?]", "Show map of heap",
	"dmi", " [addr|libname] [symname]", "List symbols of target lib",
	"dmi*", " [addr|libname] [symname]", "List symbols of target lib in radare commands",
	"dmi.", "", "List closest symbol to the current address",
	"dmiv", "", "Show address of given symbol for given lib",
	"dmj", "", "List memmaps in JSON format",
	"dml", " <file>", "Load contents of file into the current map region (see Sl)",
	"dmm", "[?][j*]", "List modules (libraries, binaries loaded in memory)",
	"dmp", "[?] <address> <size> <perms>", "Change page at <address> with <size>, protection <perms> (rwx)",
	"dms", "[?] <id> <mapaddr>", "Take memory snapshot",
	"dms-", " <id> <mapaddr>", "Restore memory snapshot",
	"dmS", " [addr|libname] [sectname]", "List sections of target lib",
	"dmS*", " [addr|libname] [sectname]", "List sections of target lib in radare commands",
	//"dm, " rw- esp 9K", "set 9KB of the stack as read+write (no exec)",
	"TODO:", "", "map files in process memory. (dmf file @ [addr])",
	NULL
};

static const char *help_msg_dmi[] = {
	"Usage: dmi", "", " # List/Load Symbols",
	"dmi", "[libname] [symname]", "List symbols of target lib",
	"dmi*", "", "List symbols of target lib in radare commands",
	"dmi.", "", "List closest symbol to the current address",
	"dmiv", "", "Show address of given symbol for given lib",
	NULL
};

static const char *help_msg_dmm[] = {
	"Usage:", "dmm", " # Module memory maps commands",
	"dmm", "", "List modules of target process",
	"dmm*", "", "List modules of target process (r2 commands)",
	"dmm.", "", "List memory map of current module",
	"dmmj", "", "List modules of target process (JSON)",
	NULL
};

static const char *help_msg_dmp[] = {
	"Usage:", "dmp", " Change page permissions",
	"dmp", " [addr] [size] [perms]", "Change permissions",
	"dmp", " [perms]", "Change dbg.map permissions",
	NULL
};

static const char *help_msg_dms[] = {
	"Usage:", "dms", " # Memory map snapshots",
	"dms", "", "List memory snapshots",
	"dmsj", "", "List snapshots in JSON",
	"dms*", "", "List snapshots in r2 commands",
	"dms", " addr", "Take snapshot with given id of map at address",
	"dms", "-id", "Delete memory snapshot",
	"dmsA", " id", "Apply memory snapshot",
	"dmsC", " id comment", "Add comment for given snapshot",
	"dmsd", " id", "Hexdiff given snapshot. See `ccc`.",
	"dmsw", "", "Snapshot of the writable maps",
	"dmsa", "", "Full snapshot of all `dm` maps",
	"dmsf", " [file] @ addr", "Read snapshot from disk",
	"dmst", " [file] @ addr", "Dump snapshot to disk",
	// TODO: dmsj - for json
	NULL
};

static const char *help_msg_do[] = {
	"Usage:", "do", " # Debug (re)open commands",
	"do", "", "Open process (reload, alias for 'oo')",
	"dor", " [rarun2]", "Comma separated list of k=v rarun2 profile options (e dbg.profile)",
	"doo", " [args]", "Reopen in debugger mode with args (alias for 'ood')",
	NULL
};

static const char *help_msg_dp[] = {
	"Usage:", "dp", " # Process commands",
	"dp", "", "List current pid and children",
	"dp", " <pid>", "List children of pid",
	"dp*", "", "List all attachable pids",
	"dp-", " <pid>", "Detach select pid",
	"dp=", "<pid>", "Select pid",
	"dpa", " <pid>", "Attach and select pid",
	"dpc", "", "Select forked pid (see dbg.forks)",
	"dpc*", "", "Display forked pid (see dbg.forks)",
	"dpe", "", "Show path to executable",
	"dpf", "", "Attach to pid like file fd // HACK",
	"dpk", " <pid> [<signal>]", "Send signal to process (default 0)",
	"dpn", "", "Create new process (fork)",
	"dptn", "", "Create new thread (clone)",
	"dpt", "", "List threads of current pid",
	"dpt", " <pid>", "List threads of process",
	"dpt=", "<thread>", "Attach to thread",
	NULL
};

static const char *help_msg_dr[] = {
	"Usage: dr", "", "Registers commands",
	"dr", "", "Show 'gpr' registers",
	"dr", " <register>=<val>", "Set register value",
	"dr8", "[1|2|4|8] [type]", "Display hexdump of gpr arena (WIP)",
	"dr=", "", "Show registers in columns",
	"dr?", "<register>", "Show value of given register",
	"drb", "[1|2|4|8] [type]", "Display hexdump of gpr arena (WIP)",
	"drc", " [name]", "Related to conditional flag registers",
	"drC", "", "Show register profile comments",
	"drd", "", "Show only different registers",
	"drf", "", "Show fpu registers (80 bit long double)",
	"drl", "[j]", "List all register names",
	"drm", "", "Show multimedia packed registers",
	"drm", " mmx0 0 32 = 12", "Set the first 32 bit word of the mmx reg to 12",
	"drn", " <pc>", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
	"dro", "", "Show previous (old) values of registers",
	"drp", "", "Display current register profile",
	"drp", "[?] <file>", "Load register metadata file",
	"drpi", "", "Display current internal representation of the register profile",
	"drps", "", "Fake register profile size",
	"drpj", "", "Show the current register profile (JSON)",
	"drr", "", "Show registers references (telescoping)",
	// TODO: 'drs' to swap register arenas and display old register valuez
	"drs", "[?]", "Stack register states",
	"drt", " 16", "Show 16 bit registers",
	"drt", " 32", "Show 32 bit registers",
	"drt", " 80", "Show 80 bit registers (long double)",
	"drt", " all", "Show all registers",
	"drt", " flg", "Show flag registers",
	"drt", "[?]", "Show all register types",
	"drw"," <hexnum>", "Set contents of the register arena",
	"drx", "[?]", "Show all debug registers",
	"drx", " idx addr len rwx", "Modify hardware breakpoint",
	"drx-", "number", "Clear hardware breakpoint",
	".dr", "*", "Include common register values in flags",
	".dr", "-", "Unflag all registers",
	NULL
};

static const char *help_msg_drp[] = {
	"Usage:", "drp", " # Register profile commands",
	"drp", "", "Show the current register profile",
	"drp", " [regprofile-file]", "Set the current register profile",
	"drp", " [gdb] [regprofile-file]", "Parse gdb register profile and dump an r2 profile string",
	"drpi", "", "Show internal representation of the register profile",
	"drp.", "", "Show the current fake size",
	"drpj", "", "Show the current register profile (JSON)",
	"drps", " [new fake size]", "Set the fake size",
	NULL
};

static const char *help_msg_drs[] = {
	"Usage:", "drs", "register states commands",
	"drs", "", "list register stack",
	"drs", "+", "push register state",
	"drs", "-", "pop register state",
	NULL
};

static const char *help_msg_drt[] = {
	"Usage:", "drt", " [type] [size]    # debug register types",
	"drt", "[*j]", "List all available register types",
	"drt", "[*j] [size]", "Show all regs in the profile of size",
	"drt", "[*j] [type]", "Show all regs in the profile of this type",
	"drt", "[*j] [type] [size]", "Same as above for type and size",
	"drt", "[*j] [type] [size]", "Same as above for type and size",
	NULL
};

static const char *help_msg_drx[] = {
	"Usage: drx", "", "Hardware breakpoints commands",
	"drx", "", "List all (x86?) hardware breakpoints",
	"drx", " <number> <address> <length> <perms>", "Modify hardware breakpoint",
	"drx-", "<number>", "Clear hardware breakpoint",
	NULL
};

static const char *help_msg_ds[] = {
	"Usage: ds", "", "Step commands",
	"ds", "", "Step one instruction",
	"ds", " <num>", "Step <num> instructions",
	"dsb", "", "Step back one instruction",
	"dsf", "", "Step until end of frame",
	"dsi", " <cond>", "Continue until condition matches",
	"dsl", "", "Step one source line",
	"dsl", " <num>", "Step <num> source lines",
	"dso", " <num>", "Step over <num> instructions",
	"dsp", "", "Step into program (skip libs)",
	"dss", " <num>", "Skip <num> step instructions",
	"dsu", "[?]<address>", "Step until address",
	"dsui", "[r] <instr>", "Step until an instruction that matches `instr`, use dsuir for regex match",
	"dsue", " <esil>", "Step until esil expression matches",
	"dsuf", " <flag>", "Step until pc == flag matching name",
	NULL
};

static const char *help_msg_dt[] = {
	"Usage: dt", "", "Trace commands",
	"dt", "", "List all traces ",
	"dt", " [addr]", "Show trace info at address",
	"dt%", "", "TODO",
	"dt*", "", "List all traced opcode offsets",
	"dt+"," [addr] [times]", "Add trace for address N times",
	"dt-", "", "Reset traces (instruction/calls)",
	"dtD", "", "Show dwarf trace (at*|rsc dwarf-traces $FILE)",
	"dta", " 0x804020 ...", "Only trace given addresses",
	"dtc[?][addr]|([from] [to] [addr])", "", "Trace call/ret",
	"dtd", "", "List all traced disassembled",
	"dte", "[?]", "Show esil trace logs",
	"dtg", "", "Graph call/ret trace",
	"dtg*", "", "Graph in agn/age commands. use .dtg*;aggi for visual",
	"dtgi", "", "Interactive debug trace",
	"dtr", "", "Show traces as range commands (ar+)",
	"dts", "[?]", "Trace sessions",
	"dtt", " [tag]", "Select trace tag (no arg unsets)",
	NULL
};

static const char *help_msg_dte[] = {
	"Usage:", "dte", " Show esil trace logs",
	"dte", "", "Esil trace log for a single instruction",
	"dte", " [idx]", "Show commands for that index log",
	"dte", "-*", "Delete all esil traces",
	"dtei", "", "Esil trace log single instruction",
	"dtek", " [sdb query]", "Esil trace log single instruction from sdb",
	NULL
};

static const char *help_msg_dts[] = {
	"Usage:", "dts[*]", "",
	"dts", "", "List all trace sessions",
	"dts+", "", "Add trace session",
	"dts-", "id", "Delete trace session",
	"dtsf", " [file] ", "Read trace sessions from disk",
	"dtst", " [file] ", "Save trace sessions to disk",
	"dtsC", " id comment", "Add comment for given trace session",
	NULL
};

static const char *help_msg_dx[] = {
	"Usage: dx", "", " # Code injection commands",
	"dx", " <opcode>...", "Inject opcodes",
	"dxa", " nop", "Assemble code and inject",
	"dxe", " egg-expr", "Compile egg expression and inject it",
	"dxr", " <opcode>...", "Inject opcodes and restore state",
	"dxs", " write 1, 0x8048, 12", "Syscall injection (see gs)",
	"\nExamples:", "", "",
	"dx", " 9090", "Inject two x86 nop",
	"\"dxa mov eax,6;mov ebx,0;int 0x80\"", "", "Inject and restore state",
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

static void cmd_debug_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, d);
	DEFINE_CMD_DESCRIPTOR (core, db);
	DEFINE_CMD_DESCRIPTOR (core, dbt);
	DEFINE_CMD_DESCRIPTOR (core, dc);
	DEFINE_CMD_DESCRIPTOR (core, dcs);
	DEFINE_CMD_DESCRIPTOR (core, dcu);
	DEFINE_CMD_DESCRIPTOR (core, dd);
	DEFINE_CMD_DESCRIPTOR (core, de);
	DEFINE_CMD_DESCRIPTOR (core, des);
	DEFINE_CMD_DESCRIPTOR (core, di);
	DEFINE_CMD_DESCRIPTOR (core, dk);
	DEFINE_CMD_DESCRIPTOR (core, dko);
	DEFINE_CMD_DESCRIPTOR (core, dm);
	DEFINE_CMD_DESCRIPTOR (core, dmi);
	DEFINE_CMD_DESCRIPTOR (core, dmm);
	DEFINE_CMD_DESCRIPTOR (core, dmp);
	DEFINE_CMD_DESCRIPTOR (core, dms);
	DEFINE_CMD_DESCRIPTOR (core, do);
	DEFINE_CMD_DESCRIPTOR (core, dp);
	DEFINE_CMD_DESCRIPTOR (core, dr);
	DEFINE_CMD_DESCRIPTOR (core, drp);
	DEFINE_CMD_DESCRIPTOR (core, drs);
	DEFINE_CMD_DESCRIPTOR (core, drt);
	DEFINE_CMD_DESCRIPTOR (core, drx);
	DEFINE_CMD_DESCRIPTOR (core, ds);
	DEFINE_CMD_DESCRIPTOR (core, dt);
	DEFINE_CMD_DESCRIPTOR (core, dte);
	DEFINE_CMD_DESCRIPTOR (core, dts);
	DEFINE_CMD_DESCRIPTOR (core, dx);
}

// XXX those tmp files are never removed and we shuoldnt use files for this
static void setRarunProfileString(RCore *core, const char *str) {
	char *file = r_file_temp ("rarun2");
	char *s = strdup (str);
	r_config_set (core->config, "dbg.profile", file);
	r_str_replace_char (s, ',', '\n');
	r_file_dump (file, (const ut8*)s, strlen (s), 0);
	r_file_dump (file, (const ut8*)"\n", 1, 1);
	free (file);
}

static void cmd_debug_cont_syscall (RCore *core, const char *_str) {
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
					eprintf ("Unknown syscall number\n");
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
		eprintf ("Running child until next syscall\n");
	}
	r_reg_arena_swap (core->dbg->reg, true);
	r_debug_continue_syscalls (core->dbg, syscalls, count);
	free (syscalls);
}

static int showreg(RCore *core, const char *str) {
	int size = 0;
	RRegItem *r = 0;
	const char *rname = str;
	// check for alias reg
	int role = r_reg_get_name_idx (str);
	if (role != -1) {
		rname = r_reg_get_name (core->dbg->reg, role);
	}
	r = r_reg_get (core->dbg->reg, rname , -1);
	if (r) {
		ut64 off;
		utX value;
		if (r->size > 64) {
			off = r_reg_get_value_big (core->dbg->reg, r, &value);
			switch (r->size) {
			case 80:
				r_cons_printf ("0x%04x%016"PFMT64x"\n", value.v80.High, value.v80.Low);
				break;
			case 96:
				r_cons_printf ("0x%08x%016"PFMT64x"\n", value.v96.High, value.v96.Low);
				break;
			case 128:
				r_cons_printf ("0x%016"PFMT64x"%016"PFMT64x"\n", value.v128.High, value.v128.Low);
				break;
			default:
				r_cons_printf ("Error while retrieving reg '%s' of %i bits\n", str +1, r->size);
			}
		} else {
			off = r_reg_get_value (core->dbg->reg, r);
			r_cons_printf ("0x%08"PFMT64x "\n", off);
		}
		return r->size;
	}
	char *arg = strchr (str + 1, ' ');
	if (arg && size == 0) {
		size = atoi (arg + 1);
	} else {
		size = atoi (str + 1);
	}
	return size;
}

static RGraphNode *get_graphtrace_node (RGraph *g, Sdb *nodes, struct trace_node *tn) {
	RGraphNode *gn;
	char tn_key[TN_KEY_LEN];

	snprintf (tn_key, TN_KEY_LEN, TN_KEY_FMT, tn->addr);
	gn = (RGraphNode *)(size_t)sdb_num_get (nodes, tn_key, NULL);
	if (!gn) {
		gn = r_graph_add_node (g, tn);
		sdb_num_set (nodes, tn_key, (ut64)(size_t)gn, 0);
	}
	return gn;
}

static void dot_trace_create_node (RTreeNode *n, RTreeVisitor *vis) {
	struct dot_trace_ght *data = (struct dot_trace_ght *)vis->data;
	struct trace_node *tn = n->data;
	if (tn) get_graphtrace_node (data->graph, data->graphnodes, tn);
}

static void dot_trace_discover_child (RTreeNode *n, RTreeVisitor *vis) {
	struct dot_trace_ght *data = (struct dot_trace_ght *)vis->data;
	RGraph *g = data->graph;
	Sdb *gnodes = data->graphnodes;
	RTreeNode *parent = n->parent;
	struct trace_node *tn = n->data;
	struct trace_node *tn_parent = parent->data;

	if (tn && tn_parent) {
		RGraphNode *gn = get_graphtrace_node (g, gnodes, tn);
		RGraphNode *gn_parent = get_graphtrace_node (g, gnodes, tn_parent);

		if (!r_graph_adjacent (g, gn_parent, gn))
			r_graph_add_edge (g, gn_parent, gn);
	}
}

static void dot_trace_traverse(RCore *core, RTree *t, int fmt) {
	const char *gfont = r_config_get (core->config, "graph.font");
	struct dot_trace_ght aux_data;
	RTreeVisitor vis = { 0 };
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
	vis.pre_visit = (RTreeNodeVisitCb)dot_trace_create_node;
	vis.discover_child = (RTreeNodeVisitCb)dot_trace_discover_child;
	r_tree_bfs (t, &vis);

	/* traverse the callgraph to print the dot file */
	nodes = r_graph_get_nodes (aux_data.graph);
	if (fmt == 0) {
		r_cons_printf ("digraph code {\n"
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
			r_cons_printf ("\"0x%08"PFMT64x"\" [URL=\"0x%08"PFMT64x
					"\" color=\"lightgray\" label=\"0x%08"PFMT64x
					" (%d)\"]\n", tn->addr, tn->addr, tn->addr, tn->refs);
		}
		r_list_foreach (neighbours, it_n, w) {
			struct trace_node *tv = (struct trace_node *)w->data;

			if (tv && tn) {
				if (fmt) {
					r_cons_printf ("agn 0x%08"PFMT64x"\n", tn->addr);
					r_cons_printf ("agn 0x%08"PFMT64x"\n", tv->addr);
					r_cons_printf ("age 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
							tn->addr, tv->addr);
				} else {
					r_cons_printf ("\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x
							"\" [color=\"red\"];\n", tn->addr, tv->addr);
				}
			}
		}
	}
	if (!fmt) {
		r_cons_printf ("}\n");
	}

	r_graph_free (aux_data.graph);
	sdb_free (aux_data.graphnodes);
}

/* TODO: refactor all those step_until* function into a single one
 * TODO: handle when the process is dead
 * TODO: handle ^C */

static int step_until(RCore *core, ut64 addr) {
	ut64 off = r_debug_reg_get (core->dbg, "PC");
	if (!off) {
		eprintf ("Cannot 'drn pc'\n");
		return false;
	}
	if (!addr) {
		eprintf ("Cannot continue until address 0\n");
		return false;
	}
	r_cons_break_push (NULL, NULL);
	do {
		if (r_cons_is_breaked ()) {
			core->break_loop = true;
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			core->break_loop = true;
			break;
		}
		r_debug_step (core->dbg, 1);
		off = r_debug_reg_get (core->dbg, "PC");
		// check breakpoint here
	} while (off != addr);
	r_cons_break_pop ();
	return true;
}

static int step_until_esil(RCore *core, const char *esilstr) {
	if (!core || !esilstr || !core->dbg || !core->dbg->anal \
			|| !core->dbg->anal->esil) {
		eprintf ("Not initialized %p. Run 'aei' first.\n", core->anal->esil);
		return false;
	}
	r_cons_break_push (NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked ()) {
			core->break_loop = true;
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			core->break_loop = true;
			break;
		}
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
		if (r_anal_esil_condition (core->anal->esil, esilstr)) {
			eprintf ("ESIL BREAK!\n");
			break;
		}
	}
	r_cons_break_pop ();
	return true;
}

static int step_until_inst(RCore *core, const char *instr, bool regex) {
	RAsmOp asmop;
	ut8 buf[32];
	ut64 pc;
	int ret;

	instr = r_str_trim_ro (instr);
	if (!core || !instr|| !core->dbg) {
		eprintf ("Wrong state\n");
		return false;
	}
	r_cons_break_push (NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			break;
		}
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
		/* TODO: disassemble instruction and strstr */
		pc = r_debug_reg_get (core->dbg, "PC");
		r_asm_set_pc (core->assembler, pc);
		// TODO: speedup if instructions are in the same block as the previous
		r_io_read_at (core->io, pc, buf, sizeof (buf));
		ret = r_asm_disassemble (core->assembler, &asmop, buf, sizeof (buf));
		eprintf ("0x%08"PFMT64x" %d %s\n", pc, ret, asmop.buf_asm);
		if (ret > 0) {
			if (regex) {
				if (r_regex_match (instr, "e", asmop.buf_asm)) {
					eprintf ("Stop.\n");
					break;
				}
			} else {
				if (strstr (asmop.buf_asm, instr)) {
					eprintf ("Stop.\n");
					break;
				}
			}
		}
	}
	r_cons_break_pop ();
	return true;
}

static int step_until_flag(RCore *core, const char *instr) {
	const RList *list;
	RListIter *iter;
	RFlagItem *f;
	ut64 pc;

	instr = r_str_trim_ro (instr);
	if (!core || !instr || !core->dbg) {
		eprintf ("Wrong state\n");
		return false;
	}
	r_cons_break_push (NULL, NULL);
	for (;;) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (r_debug_is_dead (core->dbg)) {
			break;
		}
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
		pc = r_debug_reg_get (core->dbg, "PC");
		list = r_flag_get_list (core->flags, pc);
		r_list_foreach (list, iter, f) {
			if (!instr|| !*instr || (f->realname && strstr(f->realname, instr))) {
				r_cons_printf ("[ 0x%08"PFMT64x" ] %s\n",
						f->offset, f->realname);
				goto beach;
			}
		}
	}
beach:
	r_cons_break_pop ();
	return true;
}

/* until end of frame */
static int step_until_eof(RCore *core) {
	int maxLoops = 1024;
	ut64 off, now = r_debug_reg_get (core->dbg, "SP");
	r_cons_break_push (NULL, NULL);
	do {
		// XXX (HACK!)
		r_debug_step_over (core->dbg, 1);
		off = r_debug_reg_get (core->dbg, "SP");
		// check breakpoint here
		if (--maxLoops < 0) {
			eprintf ("Step loop limit exceeded\n");
			break;
		}
	} while (off <= now);
	r_cons_break_pop ();
	return true;
}

static int step_line(RCore *core, int times) {
	char file[512], file2[512];
	int find_meta, line = -1, line2 = -1;
	char *tmp_ptr = NULL;
	ut64 off = r_debug_reg_get (core->dbg, "PC");
	if (off == 0LL) {
		eprintf ("Cannot 'drn pc'\n");
		return false;
	}
	file[0] = 0;
	file2[0] = 0;
	if (r_bin_addr2line (core->bin, off, file, sizeof (file), &line)) {
		char* ptr = r_file_slurp_line (file, line, 0);
		eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file, line);
		eprintf ("--> %s\n", ptr);
		find_meta = false;
		free (ptr);
	} else {
		eprintf ("--> Stepping until dwarf line\n");
		find_meta = true;
	}
	do {
		r_debug_step (core->dbg, 1);
		off = r_debug_reg_get (core->dbg, "PC");
		if (!r_bin_addr2line (core->bin, off, file2, sizeof (file2), &line2)) {
			if (find_meta)
				continue;
			eprintf ("Cannot retrieve dwarf info at 0x%08"PFMT64x"\n", off);
			return false;
		}
	} while (!strcmp (file, file2) && line == line2);

	eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file2, line2);
	tmp_ptr = r_file_slurp_line (file2, line2, 0);
	eprintf ("--> %s\n", tmp_ptr);
	free (tmp_ptr);

	return true;
}

static void cmd_debug_pid(RCore *core, const char *input) {
	int pid, sig;
	const char *ptr;
	switch (input[1]) {
	case '\0': // "dp"
		eprintf ("Selected: %d %d\n", core->dbg->pid, core->dbg->tid);
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
			eprintf ("No recently forked children\n");
		}
		break;
	case 'k': // "dpk"
		/* stop, print, pass -- just use flags*/
		/* XXX: not for threads? signal is for a whole process!! */
		/* XXX: but we want fine-grained access to process resources */
		pid = atoi (input + 2);
		if (pid > 0) {
			ptr = r_str_trim_ro (input + 2);
			ptr = strchr (ptr, ' ');
			sig = ptr? atoi (ptr + 1): 0;
			eprintf ("Sending signal '%d' to pid '%d'\n", sig, pid);
			r_debug_kill (core->dbg, 0, false, sig);
		} else eprintf ("cmd_debug_pid: Invalid arguments (%s)\n", input);
		break;
	case 'n': // "dpn"
		eprintf ("TODO: debug_fork: %d\n", r_debug_child_fork (core->dbg));
		break;
	case 't': // "dpt"
		switch (input[2]) {
		case '\0': // "dpt"
			r_debug_thread_list (core->dbg, core->dbg->pid);
			break;
		case ' ': // "dpt "
			r_debug_thread_list (core->dbg, atoi (input + 2));
			break;
		case '=': // "dpt="
			r_debug_select (core->dbg, core->dbg->pid,
					(int) r_num_math (core->num, input + 3));
			break;
		case 'n': // "dptn"
			eprintf ("TODO: debug_clone: %d\n", r_debug_child_clone (core->dbg));
			break;
		case '?': // "dpt?"
		default:
			r_core_cmd_help (core, help_msg_dp);
			break;
		}
		break;
	case 'a': // "dpa"
		if (input[2]) {
			r_debug_attach (core->dbg, (int) r_num_math (
						core->num, input + 2));
		} else {
			if (core->file && core->io) {
				r_debug_attach (core->dbg,
						r_io_fd_get_pid (core->io, core->file->fd));
			}
		}
		r_debug_select (core->dbg, core->dbg->pid, core->dbg->tid);
		r_config_set_i (core->config, "dbg.swstep",
				(core->dbg->h && !core->dbg->h->canstep));
		r_core_cmdf (core, "=!pid %d", core->dbg->pid);
		break;
	case 'f': // "dpf"
		if (core->file && core->io) {
			r_debug_select (core->dbg, r_io_fd_get_pid (core->io, core->file->fd),
					r_io_fd_get_tid (core->io, core->file->fd));
		}
		break;
	case '=': // "dp="
		r_debug_select (core->dbg,
				(int) r_num_math (core->num, input + 2), core->dbg->tid);
		core->dbg->main_pid = r_num_math (core->num, input + 2);
		break;
	case '*': // "dp*"
		r_debug_pid_list (core->dbg, 0, 0);
		break;
	case 'j': // "dpj"
		r_debug_pid_list (core->dbg, core->dbg->pid, 'j');
		break;
	case 'e': // "dpe"
		{
			int pid = (input[2] == ' ')? atoi (input + 2): core->dbg->pid;
			char *exe = r_sys_pid_to_path (pid);
			if (exe) {
				r_cons_println (exe);
				free (exe);
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
		eprintf ("Trap tracing 0x%08"PFMT64x"-0x%08"PFMT64x"\n",
				core->offset, core->offset+len);
		r_reg_arena_swap (core->dbg->reg, true);
		r_bp_traptrace_reset (core->dbg->bp, true);
		r_bp_traptrace_add (core->dbg->bp, core->offset, core->offset+len);
		r_bp_traptrace_enable (core->dbg->bp, true);
		do {
			ut8 buf[32];
			r_debug_continue (core->dbg);
			addr = r_debug_reg_get (core->dbg, "PC");
			if (!addr) {
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
			r_core_read_at (core, addr, buf, 32); // XXX longer opcodes?
			r_anal_op (core->anal, &analop, addr, buf, sizeof (buf));
		} while (r_bp_traptrace_at (core->dbg->bp, addr, analop.size));
		r_bp_traptrace_enable (core->dbg->bp, false);
	}
}

static int __r_debug_snap_diff(RCore *core, int idx) {
	ut32 count = 0;
	RDebug *dbg = core->dbg;
	ut32 oflags = core->print->flags;
	int col = core->cons->columns>123;
	RDebugSnap *snap;
	RListIter *iter;
	core->print->flags |= R_PRINT_FLAGS_DIFFOUT;
	r_list_foreach (dbg->snaps, iter, snap) {
		if (count == idx) {
			ut8 *b = malloc (snap->size);
			if (!b) {
				eprintf ("Cannot allocate snapshot\n");
				continue;
			}
			dbg->iob.read_at (dbg->iob.io, snap->addr, b , snap->size);
			r_print_hexdiff (core->print,
					snap->addr, snap->data,
					snap->addr, b,
					snap->size, col);
			free (b);
		}
		count ++;
	}
	core->print->flags = oflags;
	return 0;
}

static int cmd_debug_map_snapshot(RCore *core, const char *input) {
	switch (*input) {
	case 'f':
		{
			char *file;
			RDebugSnap *snap;
			if (input[1] == ' ') {
				file = strdup (input + 2);
			} else {
				file = r_str_newf ("0x%08"PFMT64x".dump", core->offset);
			}
			snap = r_debug_snap_get (core->dbg, core->offset);
			if (!snap) {
				r_debug_snap (core->dbg, core->offset);
				snap = r_debug_snap_get (core->dbg, core->offset);
			}
			if (snap) {
				int fsz = 0;
				char *data = r_file_slurp (file, &fsz);
				if (data) {
					if (fsz >= snap->size) {
						memcpy (snap->data, data, snap->size);
					} else {
						eprintf ("This file is smaller than the snapshot size\n");
					}
					free (data);
				} else eprintf ("Cannot slurp '%s'\n", file);
			} else {
				eprintf ("Unable to find a snapshot for 0x%08"PFMT64x"\n", core->offset);
			}
			free (file);
		}
		break;
	case 't':
		{
			char *file;
			RDebugSnap *snap;
			if (input[1] == ' ') {
				file = strdup (input + 2);
			} else {
				file = r_str_newf ("0x%08"PFMT64x".dump", core->offset);
			}
			snap = r_debug_snap_get (core->dbg, core->offset);
			if (snap) {
				if (!r_file_dump (file, snap->data, snap->size, 0)) {
					eprintf ("Cannot slurp '%s'\n", file);
				}
			} else {
				eprintf ("Unable to find a snapshot for 0x%08"PFMT64x"\n", core->offset);
			}
			free (file);
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_dms);
		break;
	case '-':
		if (input[1]=='*') {
			r_debug_snap_delete (core->dbg, -1);
		} else {
			r_debug_snap_delete (core->dbg, r_num_math (core->num, input + 1));
		}
		break;
	case ' ':
		r_debug_snap (core->dbg, r_num_math (core->num, input + 1));
		break;
	case 'A':
		r_debug_snap_set_idx (core->dbg, atoi (input + 1));
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
	case 'w':
		r_debug_snap_all (core->dbg, R_IO_RW);
		break;
	case 0:
	case 'j':
	case '*':
		r_debug_snap_list (core->dbg, -1, input[0]);
		break;
	}
	return 0;
}

static int grab_bits(RCore *core, const char *arg, int *pcbits2) {
	int pcbits = atoi (arg);
	if (pcbits2) {
		*pcbits2 = 0;
	}
	if (pcbits < 1) {
		if (!strcmp (r_config_get (core->config, "asm.arch"), "avr")) {
			pcbits = 8;
			if (pcbits2) {
				*pcbits2 = 32;
			}
		} else {
			const char *pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			RRegItem *reg = r_reg_get (core->anal->reg, pcname, 0);
			if (reg) {
				if (core->assembler->bits != reg->size)
					pcbits = reg->size;
			}
		}
	}
	return pcbits ? pcbits : core->anal->bits;
}

#define MAX_MAP_SIZE 1024*1024*512
static int dump_maps(RCore *core, int perm, const char *filename) {
	RDebugMap *map;
	RListIter *iter;
	r_debug_map_sync (core->dbg); // update process memory maps
	ut64 addr = core->offset;
	int do_dump = false;
	int ret = r_list_empty(core->dbg->maps)? false: true;
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
				eprintf ("Cannot allocate 0x%08"PFMT64x" bytes\n", map->size);
				free (buf);
				/// XXX: TODO: read by blocks!!1
				continue;
			}
			if (map->size > MAX_MAP_SIZE) {
				eprintf ("Do not dumping 0x%08"PFMT64x" because it's too big\n", map->addr);
				free (buf);
				continue;
			}
			r_io_read_at (core->io, map->addr, buf, map->size);
			char *file = filename
			? strdup (filename)
			: r_str_newf ("0x%08"PFMT64x"-0x%08"PFMT64x"-%s.dmp",
					map->addr, map->addr_end, r_str_rwx_i (map->perm));
			if (!r_file_dump (file, buf, map->size, 0)) {
				eprintf ("Cannot write '%s'\n", file);
				ret = 0;
			} else {
				eprintf ("Dumped %d byte(s) into %s\n", (int)map->size, file);
			}
			free (file);
			free (buf);
		}
	}
	//eprintf ("No debug region found here\n");
	return ret;
}

static void cmd_debug_modules(RCore *core, int mode) { // "dmm"
	ut64 addr = core->offset;
	RDebugMap *map;
	RList *list;
	RListIter *iter;

	/* avoid processing the list if the user only wants help */
	if (mode == '?') {
show_help:
		r_core_cmd_help (core, help_msg_dmm);
		return;
	}
	if (mode == 'j') {
		r_cons_print ("[");
	}
	// TODO: honor mode
	list = r_debug_modules_list (core->dbg);
	r_list_foreach (list, iter, map) {
		switch (mode) {
		case 0:
			r_cons_printf ("0x%08"PFMT64x" %s\n", map->addr, map->file);
			break;
		case ':':
			if (addr >= map->addr && addr < map->addr_end) {
#if __WINDOWS__ && !__CYGWIN__
				/* Escape backslashes in the file path on Windows */
				char *escaped_path = r_str_escape (map->file);
				char *escaped_name = r_str_escape (map->name);
				if (escaped_path && escaped_name) {
					r_name_filter (escaped_name, 0);
					r_cons_printf ("f mod.%s = 0x%08"PFMT64x"\n",
							escaped_name, map->addr);
					r_cons_printf (".!rabin2 -rsB 0x%08"PFMT64x" \'%s\'\n",
							map->addr, escaped_path);
				}
				free (escaped_path);
				free (escaped_name);
#else
				char *fn = strdup (map->file);
				r_name_filter (fn, 0);
				//r_cons_printf ("fs+module_%s\n", fn);
				r_cons_printf ("f mod.%s = 0x%08"PFMT64x"\n",
						fn, map->addr);
				r_cons_printf (".!rabin2 -rsB 0x%08"PFMT64x" '%s'\n",
						map->addr, map->file);
				//r_cons_printf ("fs-\n");
				free (fn);
#endif
			}
			break;
		case '.':
			if (addr >= map->addr && addr < map->addr_end) {
				r_cons_printf ("0x%08"PFMT64x" %s\n", map->addr, map->file);
				goto beach;
			}
			break;
		case 'j':
#if __WINDOWS__ && !__CYGWIN__
			{
				/* Single backslashes cause issues when parsing JSON output, so escape them */
				char *escaped_path = r_str_escape (map->file);
				char *escaped_name = r_str_escape (map->name);
				if (escaped_path && escaped_name) {
					r_cons_printf ("{\"address\":%"PFMT64d",\"name\":\"%s\",\"file\":\"%s\"}%s",
							map->addr, escaped_name, escaped_path, iter->n?",":"");
				}
				free (escaped_path);
				free (escaped_name);
			}
#else
			r_cons_printf ("{\"address\":%"PFMT64d",\"name\":\"%s\",\"file\":\"%s\"}%s",
					map->addr, map->name, map->file, iter->n?",":"");
#endif
			break;
		case '*':
			{
#if __WINDOWS__ && !__CYGWIN__
				/* Escape backslashes in the file path on Windows */
				char *escaped_path = r_str_escape (map->file);
				char *escaped_name = r_str_escape (map->name);
				if (escaped_path && escaped_name) {
					r_name_filter (escaped_name, 0);
					r_cons_printf ("f mod.%s = 0x%08"PFMT64x"\n",
							escaped_name, map->addr);
					/* Use double quotes around the file path on Windows to generate valid commands */
					r_cons_printf (".!rabin2 -rsB 0x%08"PFMT64x" \"%s\"\n",
							map->addr, escaped_path);
				}
				free (escaped_path);
				free (escaped_name);
#else
				char *fn = strdup (map->file);
				r_name_filter (fn, 0);
				//r_cons_printf ("fs+module_%s\n", fn);
				r_cons_printf ("f mod.%s = 0x%08"PFMT64x"\n",
						fn, map->addr);
				r_cons_printf (".!rabin2 -rsB 0x%08"PFMT64x" '%s'\n",
						map->addr, map->file);
				//r_cons_printf ("fs-\n");
				free (fn);
#endif
			}
			break;
		default:
			r_list_free (list);
			goto show_help;
			/* not reached */
		}
	}
beach:
	if (mode == 'j') {
		r_cons_print ("]\n");
	}
	r_list_free (list);
}

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__

static int cmd_dbg_map_heap_glibc_32 (RCore *core, const char *input);
static int cmd_dbg_map_heap_glibc_64 (RCore *core, const char *input);

static void get_hash_debug_file(const char *path, char *hash, int hash_len) {
	RListIter *iter;
	RBinSection *s;
	RCore *core = r_core_new ();
	RList * sects = NULL;
	char buf[20] = R_EMPTY;
	int offset, err, i, j = 0;

	if (!core) {
		return;
	}
	r_bin_load (core->bin, path, 0, 0, 0, -1, false);
	sects = r_bin_get_sections (core->bin);
	if (!sects) {
		goto out_error;
	}
	r_list_foreach (sects, iter, s) {
		if (strstr (s->name, ".note.gnu.build-id")) {
			err = r_io_read_at (core->io, s->vaddr + 16, (ut8 *) buf, 20);
			if (!err) {
				eprintf ("Unable to read from memory\n");
				goto out_error;
			}
			break;
		}
	}
	for (i = 0; i < 20; i++) {
		if (i <= 1) {
			hash[i + 2 * j++] = (ut8) '/';
		}
		offset = j + 2 * i;
		snprintf (hash + offset, hash_len - offset, "%02x", (ut8) buf[i]);
	}
	offset = j + 2 * i;
	snprintf (hash + offset, hash_len - offset - strlen (".debug"), ".debug");
out_error:
	r_core_free (core);
}

static int str_start_with(const char *ptr, const char *str) {
	return !strncmp (ptr, str, (size_t)strlen (str));
}

#endif // __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__

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
		if (strstr (map->name, libname)) {
			return map->addr;
		}
	}
	r_list_foreach (core->dbg->maps, iter, map) {
		if (strstr (map->name, libname)) {
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

static int r_debug_heap(RCore *core, const char *input) {
	const char *m = r_config_get (core->config, "dbg.malloc");
	if (m && !strcmp ("glibc", m)) {
#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
		if (core->assembler->bits == 64) {
			cmd_dbg_map_heap_glibc_64 (core, input + 1);
		} else {
			cmd_dbg_map_heap_glibc_32 (core, input + 1);
		}
#else
		eprintf ("glibc not supported for this platform\n");
#endif
#if HAVE_JEMALLOC
	} else if (m && !strcmp ("jemalloc", m)) {
		if (core->assembler->bits == 64) {
			cmd_dbg_map_jemalloc_64 (core, input + 1);
		} else {
			cmd_dbg_map_jemalloc_32 (core, input + 1);
		}
#endif
	} else {
		eprintf ("MALLOC algorithm not supported\n");
		return false;
	}
	return true;
}

static int cmd_debug_map(RCore *core, const char *input) {
	RListIter *iter;
	RDebugMap *map;
	ut64 addr = core->offset;

	switch (input[0]) {
	case 's': // "dms"
		cmd_debug_map_snapshot (core, input + 1);
		break;
	case '.': // "dm."
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				r_cons_println (map->name);
				break;
			}
		}
		break;
	case 'm': // "dmm"
		if (!strcmp (input + 1, ".*")) {
			cmd_debug_modules (core, ':');
		} else cmd_debug_modules (core, input[1]);
		break;
	case '?': // "dm?"
		r_core_cmd_help (core, help_msg_dm);
		break;
	case 'p': // "dmp"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_dmp);
		} else if (input[1] == ' ') {
			int perms;
			char *p, *q;
			ut64 size = 0, addr;
			p = strchr (input + 2, ' ');
			if (p) {
				*p++ = 0;
				q = strchr (p, ' ');
				if (q) {
					*q++ = 0;
					addr = r_num_math (core->num, input + 2);
					size = r_num_math (core->num, p);
					perms = r_str_rwx (q);
				//	eprintf ("(%s)(%s)(%s)\n", input + 2, p, q);
				//	eprintf ("0x%08"PFMT64x" %d %o\n", addr, (int) size, perms);
					r_debug_map_protect (core->dbg, addr, size, perms);
				} else eprintf ("See dmp?\n");
			} else {
				r_debug_map_sync (core->dbg); // update process memory maps
				addr = UT64_MAX;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (core->offset >= map->addr  && core->offset < map->addr_end) {
						addr = map->addr;
						size = map->size;
						break;
					}
				}
				perms = r_str_rwx (input + 2);
				if (addr != UT64_MAX && perms >= 0) {
					r_debug_map_protect (core->dbg, addr, size, perms);
				} else {
					eprintf ("See dmp?\n");
				}
			}
		} else {
			eprintf ("See dmp?\n");
		}
		break;
	case 'd': // "dmd"
		switch (input[1]) {
		case 'a': return dump_maps (core, 0, NULL);
		case 'w': return dump_maps (core, R_IO_RW, NULL);
		case ' ': return dump_maps (core, -1, input + 2);
		case 0: return dump_maps (core, -1, NULL);
		case '?':
		default:
			eprintf ("Usage: dmd[aw]  - dump (all-or-writable) debug maps\n");
			break;
		}
		break;
	case 'l': // "dml"
		if (input[1] != ' ') {
			eprintf ("Usage: dml [file]\n");
			return false;
		}
		r_debug_map_sync (core->dbg); // update process memory maps
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				int sz;
				char *buf = r_file_slurp (input + 2, &sz);
				//TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf ("Cannot allocate 0x%08"PFMT64x" byte(s)\n", map->size);
					return false;
				}
				r_io_write_at (core->io, map->addr, (const ut8*)buf, sz);
				if (sz != map->size)
					eprintf	("File size differs from region size (%d vs %"PFMT64d")\n",
							sz, map->size);
				eprintf ("Loaded %d byte(s) into the map region at 0x%08"PFMT64x"\n",
						sz, map->addr);
				free (buf);
				return true;
			}
		}
		eprintf ("No debug region found here\n");
		return false;
	case 'i': // "dmi"
		switch (input[1]) {
		case '\0': // "dmi" alias of "dmm"
			r_core_cmd (core, "dmm", 0);
			break;
		case ' ': // "dmi "
		case '*': // "dmi*"
		case 'v': // "dmiv"
			{
				const char *libname = NULL, *symname = NULL, *mode = "", *a0;
				ut64 baddr = 0LL;
				char *ptr;
				int i;
				if (input[1]=='*') {
					mode = "-r ";
				}
				ptr = strdup (r_str_trim_ro (input + 2));
				if (!ptr || !*ptr) {
					r_core_cmd (core, "dmm", 0);
					free (ptr);
					break;
				}
				i = r_str_word_set0 (ptr);
				switch (i) {
				case 2:
					symname = r_str_word_get0 (ptr, 1);
					// fall thru
				case 1:
					a0 = r_str_word_get0 (ptr, 0);
					addr = r_num_math (core->num, a0);
					if (!addr || addr == UT64_MAX) {
						libname = r_str_word_get0 (ptr, 0);
					}
					break;
				}
				if (libname && !addr) {
					addr = addroflib (core, libname);
					if (addr == UT64_MAX) {
						eprintf ("Unknown library, or not found in dm\n");
					}
				}
				map = get_closest_map (core, addr);
				if (map) {
					RCoreBinFilter filter;
					filter.offset = 0LL;
					filter.name = (char *)symname;
					baddr = map->addr;

					if (libname) {
						char *cmd, *res;
						const char *file = map->file? map->file: map->name;
						if (symname) {
							cmd = r_str_newf ("rabin2 %s-B 0x%08"PFMT64x" -s %s | grep %s", mode, baddr, file, symname);
						} else {
							cmd = r_str_newf ("rabin2 %s-B 0x%08"PFMT64x" -s %s", mode, baddr, file);
						}
						// eprintf ("CMD (%s)\n", cmd);
						res = r_sys_cmd_str (cmd, NULL, NULL);
						r_cons_println (res);
						free (res);
						free (cmd);
					} else {
						r_bin_set_baddr (core->bin, map->addr);
						r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, (input[1]=='*'), true, &filter, NULL);
						r_bin_set_baddr (core->bin, baddr);
					}
				}
				free (ptr);
			}
			break;
		case '.': // "dmi."
			{
				map = get_closest_map (core, addr);
				if (map) {
					ut64 closest_addr = UT64_MAX;
					RList *symbols = r_bin_get_symbols (core->bin);
					RBinSymbol *symbol, *closest_symbol = NULL;

					r_list_foreach (symbols, iter, symbol) {
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
						RCoreBinFilter filter;
						filter.offset = 0LL;
						filter.name = (char *) closest_symbol->name;

						r_bin_set_baddr (core->bin, map->addr);
						r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, false, true, &filter, NULL);
					}
				}
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_dmi);
			break;
		}
		break;
	case 'S': // "dmS"
		{ // Move to a separate function
			const char *libname = NULL, *sectname = NULL, *mode = "";
			ut64 baddr = 0LL;
			char *ptr;
			int i;

			if (input[1]=='*') {
				ptr = strdup (r_str_trim_head ((char*)input + 2));
				mode = "-r ";
			} else {
				ptr = strdup (r_str_trim_head ((char*)input + 1));
			}
			i = r_str_word_set0 (ptr);

			addr = UT64_MAX;
			switch (i) {
			case 2: // get section name
				sectname = r_str_word_get0 (ptr, 1);
				/* fallthrou */
			case 1: // get addr|libname
				if (IS_DIGIT (*ptr)) {
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
					 (libname != NULL && (strstr (map->name, libname))))) {
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
					r_cons_println (res);
					free(name);
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
				r_debug_map_alloc (core->dbg, addr, size);
			} else {
				eprintf ("Usage: dm addr size\n");
				return false;
			}
		}
		break;
	case '-': // "dm-"
		if (input[1] != ' ') {
			eprintf ("|ERROR| Usage: dm- [addr]\n");
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
		eprintf ("The address doesn't match with any map.\n");
		break;
	case '\0': // "dm"
	case '*': // "dm*"
	case 'j': // "dmj"
	case 'q': // "dmq"
		r_debug_map_sync (core->dbg); // update process memory maps
		r_debug_map_list (core->dbg, core->offset, input[0]);
		break;
	case '=': // "dm="
		r_debug_map_sync (core->dbg);
		r_debug_map_list_visual (core->dbg, core->offset,
				r_config_get_i (core->config, "scr.color"),
				r_cons_get_size (NULL));
		break;
	case 'h': // "dmh"
		(void)r_debug_heap (core, input);
		break;
	}
	return true;
}

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#include "linux_heap_glibc.c"
#endif

R_API void r_core_debug_rr(RCore *core, RReg *reg) {
	char *use_color, *color = "";
	int use_colors = r_config_get_i (core->config, "scr.color");
	int delta = 0;
	ut64 diff, value;
	int bits = core->assembler->bits;
	RList *list = r_reg_get_list (reg, R_REG_TYPE_GPR);
	RListIter *iter;
	RRegItem *r;
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP(creg): Color_BWHITE;
	} else {
		use_color = NULL;
	}
	r_debug_map_sync (core->dbg);
	r_list_foreach (list, iter, r) {
		char *rrstr, *tmp = NULL;
		if (r->size != bits) {
			continue;
		}
		value = r_reg_get_value (core->dbg->reg, r);
		rrstr = r_core_anal_hasrefs (core, value, true);
		delta = 0;
		int regSize = r->size;
		if (regSize < 80) {
			r_reg_arena_swap (core->dbg->reg, false);
			diff = r_reg_get_value (core->dbg->reg, r);
			r_reg_arena_swap (core->dbg->reg, false);
			delta = value-diff;
		}
		if(delta && use_color){
			color = use_color;
		} else {
			color = "";
		}
		if (bits == 64) {
			if (r->flags) {
				tmp = r_reg_get_bvalue (reg, r);
				r_cons_printf ("%s%6s %018s%s", color, r->name, tmp, Color_RESET);
			} else {
				r_cons_printf ("%s%6s 0x%016"PFMT64x"%s", color, r->name, value, Color_RESET);
			}
		} else {
			if (r->flags) {
				tmp = r_reg_get_bvalue (reg, r);
				r_cons_printf ("%6s %010s", r->name, tmp);
			} else {
				r_cons_printf ("%6s 0x%08"PFMT64x, r->name, value);
			}
		}
		if (r->flags) {
			free (tmp);
		}
		if (rrstr) {
			r_cons_printf (" %s\n", rrstr);
			free (rrstr);
		}
	}
}

static void show_drpi(RCore *core) {
	int i;
	RListIter *iter;
	RRegItem *ri;
	r_cons_printf ("Aliases (Reg->name)\n");
	for (i = 0; i < R_REG_NAME_LAST; i++) {
		r_cons_printf ("%d %s %s\n", i, r_reg_get_role (i), core->anal->reg->name[i]);
	}
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		const char *nmi = r_reg_get_type (i);
		r_cons_printf ("regset %d (%s)\n", i, nmi);
		RRegSet *rs = &core->anal->reg->regset[i];
		r_cons_printf ("* arena %s size %d\n", r_reg_get_type (i), rs->arena->size);
		r_list_foreach (rs->regs, iter, ri) {
			const char *tpe = r_reg_get_type (ri->type);
			const char *arn = r_reg_get_type (ri->arena);
			r_cons_printf ("   %s %s @ %s (offset: %d  size: %d)", ri->name, tpe, arn, ri->offset / 8, ri->size / 8);
			if ((ri->offset / 8) + (ri->size / 8) > rs->arena->size) {
				r_cons_printf (" *OVERFLOW*");
			}
			r_cons_newline ();
		}
	}
}

static void cmd_reg_profile (RCore *core, char from, const char *str) { // "arp" and "drp"
	const char *ptr;
	switch (str[1]) {
	case '\0': // "drp"
		if (core->dbg->reg->reg_profile_str) {
			r_cons_println (core->dbg->reg->reg_profile_str);
		} else {
			eprintf ("No register profile defined. Try 'dr.'\n");
		}
		break;
	case ' ': // "drp "
		ptr = str + 2;
		while (isspace (*ptr)) {
			ptr++;
		}
		if (r_str_startswith (ptr, "gdb ")) {
			r_reg_parse_gdb_profile (ptr + 4);
			break;
		}
		r_reg_set_profile (core->dbg->reg, str+2);
		break;
	case '.': { // "drp."
		RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
		if (rs) {
			eprintf ("size = %d\n", rs->arena->size);
		}
		break;
	}
	case 'i': // "drpi"
		show_drpi (core);
		break;
	case 's': // "drps"
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
						eprintf ("Cannot allocate %d\n", (int)n);
					}
				}
			} else {
				eprintf ("Invalid arena size\n");
			}
		} else {
			RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
			if (rs) {
				r_cons_printf ("%d\n", rs->arena->size);
			} else eprintf ("Cannot find GPR register arena.\n");
		}
		break;
	case 'j': // "drpj"
		{
			// "drpj" .. dup from "arpj"
			RListIter *iter;
			RRegItem *r;
			int i;
			int first = 1;
			r_cons_printf ("{\"alias_info\":[");
			for (i = 0; i < R_REG_NAME_LAST; i++) {
				if (core->dbg->reg->name[i]) {
					if (!first) r_cons_printf (",");
					r_cons_printf ("{\"role\":%d,", i);
					r_cons_printf ("\"role_str\":\"%s\",",
							r_reg_get_role (i));
					r_cons_printf ("\"reg\":\"%s\"}",
							core->dbg->reg->name[i]);
					first = 0;
				}
			}
			r_cons_printf ("],\"reg_info\":[");
			first = 1;
			for (i = 0; i < R_REG_TYPE_LAST; i++) {
				r_list_foreach (core->dbg->reg->regset[i].regs, iter, r) {
					if (!first) r_cons_printf (",");
					r_cons_printf ("{\"type\":%d,", r->type);
					r_cons_printf ("\"type_str\":\"%s\",",
							r_reg_get_type (r->type));
					r_cons_printf ("\"name\":\"%s\",", r->name);
					r_cons_printf ("\"size\":%d,", r->size);
					r_cons_printf ("\"offset\":%d}", r->offset);
					first = 0;
				}
			}
			r_cons_printf ("]}");
		}
		break;
	case '?': // "drp?"
	default:
		{
			const char *from_a[] = { "arp", "arpi", "arp.", "arpj", "arps" };
			// TODO #7967 help refactor
			const char **help_msg = help_msg_drp;
			if (from == 'a') {
				help_msg[1] = help_msg[3] = help_msg[6] = help_msg[9] = from_a[0];
				help_msg[12] = from_a[1];
				help_msg[15] = from_a[2];
				help_msg[18] = from_a[3];
				help_msg[21] = from_a[4];
			}
			r_core_cmd_help (core, help_msg);
			break;
		}
	}
}


#if 0
static int showreg(RCore *core, const char *str, bool use_color) {
	ut64 off;
	utX value;
	int err;
	int bits = atoi (str);
	r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false); //R_REG_TYPE_GPR, false);
	if (bits) {
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, str[0], use_color? Color_GREEN: NULL);
	} else {
		off = r_debug_reg_get_err (core->dbg, str + 1, &err, &value);
		core->num->value = off;
		switch (err) {
		case 0:
			r_cons_printf ("0x%08"PFMT64x"\n", off);
			break;
		case 1:
			r_cons_printf ("Unknown register '%s'\n", str + 1);
			break;
		case 80:
			r_cons_printf ("0x%04x%016"PFMT64x"\n", value.v80.High, value.v80.Low);
			break;
		case 96:
			r_cons_printf ("0x%08x%016"PFMT64x"\n", value.v96.High, value.v96.Low);
			break;
		case 128:
			r_cons_printf ("0x%016"PFMT64x"%016"PFMT64x"\n", value.v128.High, value.v128.Low);
			break;
		default:
			r_cons_printf ("Error %i while retrieving '%s' \n", err, str + 1);
			core->num->value = 0;
		}
	}
	return bits;
}
#endif

static void cmd_debug_reg(RCore *core, const char *str) {
	char *arg;
	struct r_reg_item_t *r;
	const char *name, *use_color;
	int size, i, type = R_REG_TYPE_GPR;
	int bits = (core->dbg->bits & R_SYS_BITS_64)? 64: 32;
	int use_colors = r_config_get_i (core->config, "scr.color");
	int newbits = atoi ((str&&*str)? str + 1: "");
	if (newbits > 0) {
		bits = newbits;
	}
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP(creg): Color_BWHITE;
	} else {
		use_color = NULL;
	}
	if (!str) {
		str = "";
	}
	switch (str[0]) {
	case 'C': // "drC"
		if (core->dbg->reg->reg_profile_cmt) {
			r_cons_println (core->dbg->reg->reg_profile_cmt);
		}
		break;
	case '-': // "dr-"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, '-', 0);
		break;
	case '?': // "dr?"
		if (str[1]) {
			const char *p = str+1;
			ut64 off;
			while (IS_WHITESPACE (*p)) {
				p++;
			}
			r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false); //R_REG_TYPE_GPR, false);
			off = r_debug_reg_get (core->dbg, p);
			//		r = r_reg_get (core->dbg->reg, str+1, 0);
			//		if (r == NULL) eprintf ("Unknown register (%s)\n", str+1);
			r_cons_printf ("0x%08"PFMT64x"\n", off);
			core->num->value = off;
			//r_reg_get_value (core->dbg->reg, r));
		} else {
			r_core_cmd_help (core, help_msg_dr);
		}
		break;
	case 'l': // "drl[j]"
		{
			bool json_out = false;
			switch (str[1]) {
			case 'j':
				json_out = true;
				/* fall trhu */
			case 0:
				{
					RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
					if (rs) {
						RRegItem *r;
						RListIter *iter;
						i = 0;
						if (json_out) {
							r_cons_printf ("[");
						}
						r_list_foreach (rs->regs, iter, r) {
							if (json_out) {
								r_cons_printf ("%s\"%s\"",
									(i ? "," : ""),
									r->name);
								i++;
							} else {
								r_cons_println (r->name);
							}
						}
						if (json_out) {
							r_cons_printf ("]");
						}
					}
					break;
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
				char *string = r_str_trim (strdup (arg + 1));
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
				r_print_bytes (core->print, buf, len, "%02x");
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
					if (core->assembler->bits == 64) {
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
	case 'c': // "drc"
		// todo: set flag values with drc zf=1
		{
			RRegItem *r;
			const char *name = str+1;
			while (*name==' ') name++;
			if (*name && name[1]) {
				r = r_reg_cond_get (core->dbg->reg, name);
				if (r) {
					r_cons_println (r->name);
				} else {
					int id = r_reg_cond_from_string (name);
					RRegFlags* rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						int o = r_reg_cond_bits (core->dbg->reg, id, rf);
						core->num->value = o;
						// orly?
						r_cons_printf ("%d\n", o);
						free (rf);
					} else eprintf ("unknown conditional or flag register\n");
				}
			} else {
				RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
				if (rf) {
					r_cons_printf ("| s:%d z:%d c:%d o:%d p:%d\n",
							rf->s, rf->z, rf->c, rf->o, rf->p);
					if (*name=='=') {
						for (i=0; i<R_REG_COND_LAST; i++) {
							r_cons_printf ("%s:%d ",
									r_reg_cond_to_string (i),
									r_reg_cond_bits (core->dbg->reg, i, rf));
						}
						r_cons_newline ();
					} else {
						for (i=0; i<R_REG_COND_LAST; i++) {
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
				  char *s = strdup (str+2);
				  char sl, n, rwx;
				  int len;
				  ut64 off;

				  sl = r_str_word_set0 (s);
				  if (sl == 4) {
#define arg(x) r_str_word_get0(s,x)
					  n = (char)r_num_math (core->num, arg(0));
					  off = r_num_math (core->num, arg(1));
					  len = (int)r_num_math (core->num, arg(2));
					  rwx = (char)r_str_rwx (arg (3));
					  if (len == -1) {
						  r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, false);
						  r_debug_drx_set (core->dbg, n, 0, 0, 0, 0);
						  r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, true);
					  } else {
						  r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, false);
						  r_debug_drx_set (core->dbg, n, off, len, rwx, 0);
						  r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, true);
					  }
				  } else {
					eprintf ("|usage: drx n [address] [length] [rwx]\n");
				  }
				  free (s);
			  } break;
		case '?':
		default:
			r_core_cmd_help (core, help_msg_drx);
			break;
		}
		break;
	case 's': // "drs"
		switch (str[1]) {
		case '\0': // "drs"
			r_cons_printf ("%d\n", r_list_length (
						core->dbg->reg->regset[0].pool));
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
		default:
			r_core_cmd_help (core, help_msg_drs);
			break;
		}
		break;
	case 'm': // "drm"
		if (str[1]=='?') {
			eprintf ("usage: drm [reg] [idx] [wordsize] [= value]\n");
		} else if (str[1]==' ') {
			int word = 0;
			int size = 0; // auto
			char *q, *p, *name = strdup (str+2);
			char *eq = strchr (name, '=');
			if (eq) {
				*eq++ = 0;
			}
			p = strchr (name, ' ');
			if (p) {
				*p++ = 0;
				q = strchr (p, ' ');
				if (q) {
					*q++ = 0;
					size = r_num_math (core->num, q);
				}
				word = r_num_math (core->num, p);
			}
			RRegItem *item = r_reg_get (core->dbg->reg, name, -1);
			if (item) {
				if (eq) {
					ut64 val = r_num_math (core->num, eq);
					r_reg_set_pack (core->dbg->reg, item, word, size, val);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, true);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_MMX, true);
				} else {
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_MMX, false);
					ut64 res = r_reg_get_pack (core->dbg->reg, item, word, size);
					r_cons_printf ("0x%08"PFMT64x"\n", res);
				}
			} else {
				eprintf ("cannot find multimedia register '%s'\n", name);
			}
			free (name);
		} else {
			r_debug_reg_sync (core->dbg, -R_REG_TYPE_MMX, false);
		}
		//r_debug_drx_list (core->dbg);
		break;
	case 'f': // "drf"
		/* note, that negative type forces sync to print the regs from the backend */
		r_debug_reg_sync (core->dbg, -R_REG_TYPE_FPU, false);
		//r_debug_drx_list (core->dbg);
		if (str[1]=='?') {
			eprintf ("usage: drf [fpureg] [= value]\n");
		} else if (str[1]==' ') {
			char *p, *name = strdup (str+2);
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
#if __windows__
					double dval = 0.0f;
					sscanf (eq, "%lf", (double*)&dval);
					val = dval;
#else
					sscanf (eq, "%Lf", &val);
#endif
					r_reg_set_double (core->dbg->reg, item, val);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, true);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_FPU, true);
				} else {
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_FPU, false);
					long double res = r_reg_get_double (core->dbg->reg, item);
					r_cons_printf ("%lf\n", res);
				}
			} else {
				eprintf ("cannot find multimedia register '%s'\n", name);
			}
			free (name);
		} else {
			r_debug_reg_sync (core->dbg, -R_REG_TYPE_FPU, false);
		}
		break;
	case 'p': // "drp"
		cmd_reg_profile (core, 'd', str);
		break;
	case 't': { // "drt"
		char rad = 0;
		switch (str[1]) {
		case '\0': // "drt"
			for (i = 0; (name = r_reg_get_type (i)); i++) {
				r_cons_println (name);
			}
			break;
		case 'j': // "drtj"
		case '*': // "drt*"
			rad = str[1];
			str++;
			if (rad == 'j' && !str[1]) {
				r_cons_print("[");
				for (i = 0; (name = r_reg_get_type (i)); i++) {
					if (i) {
						r_cons_print (",");
					}
					r_cons_printf ("\"%s\"", name);
				}
				r_cons_println ("]");
				break;
			}
			// fallthrough
		case ' ': // "drt "
		{
			int role = r_reg_get_name_idx (str+2);
			const char *regname = r_reg_get_name (core->dbg->reg, role);
			if (!regname) {
				regname = str + 2;
			}
			size = atoi (regname);
			if (size < 1) {
				char *arg = strchr (str + 2, ' ');
				size = -1;
				if (arg) {
					*arg++ = 0;
					size = atoi (arg);
				}
				type = r_reg_type_by_name (str + 2);
				if (size < 0) {
					size = core->dbg->bits * 8;
				}
				r_debug_reg_sync (core->dbg, type, false);
				r_debug_reg_list (core->dbg, type, size, rad, use_color);
			} else {
				if (type != R_REG_TYPE_LAST) {
					r_debug_reg_sync (core->dbg, type, false);
					r_debug_reg_list (core->dbg, type, size, rad, use_color);
				} else {
					eprintf ("cmd_debug_reg: unknown type\n");
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
		{
			char *foo = strdup (str+2);
			r_str_case (foo, true);
			name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (foo));
			if (name && *name) {
				r_cons_println (name);
			} else eprintf ("oops. try drn [pc|sp|bp|a0|a1|a2|a3|a4|r0|r1|zf|sf|nf|of]\n");
			free (foo);
		}
		break;
	case 'd': // "drd"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 3, use_color); // xxx detect which one is current usage
		break;
	case 'o': // "dro"
		r_reg_arena_swap (core->dbg->reg, false);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 0, use_color); // xxx detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, false);
		break;
	case '=': // "dr="
		{
			int pcbits2, pcbits = grab_bits (core, str + 1, &pcbits2);
			if (r_config_get_i (core->config, "cfg.debug")) {
				if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
					if (pcbits && pcbits != bits) {
						r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, 2, use_color); // xxx detect which one is current usage
					}
					r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 2, use_color); // xxx detect which one is current usage
					if (pcbits2) {
						r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits2, 2, use_color); // xxx detect which one is current usage
					}
				} //else eprintf ("cannot retrieve registers from pid %d\n", core->dbg->pid);
			} else {
				RReg *orig = core->dbg->reg;
				core->dbg->reg = core->anal->reg;
				if (pcbits && pcbits != bits)
					r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, 2, use_color); // xxx detect which one is current usage
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 2, use_color); // xxx detect which one is current usage
				core->dbg->reg = orig;
			}
		}
		break;
	case '*': // "dr*"
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
			int pcbits2, pcbits = grab_bits (core, str + 1, &pcbits2);
			r_cons_printf ("fs+regs\n");
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, '*', use_color);
			if (pcbits2) {
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits2, '*', use_color);
			}
			r_flag_space_pop (core->flags);
			r_cons_printf ("fs-\n");
		}
		break;
	case 'r': // "drr"
		r_core_debug_rr (core, core->dbg->reg);
		break;
	case 'j': // "drj"
	case '\0': // "dr"
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
			int pcbits = core->anal->bits;
			const char *pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			RRegItem *reg = r_reg_get (core->anal->reg, pcname, 0);
			if (reg) {
				if (core->assembler->bits != reg->size) {
					pcbits = reg->size;
				}
			}
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, str[0], use_color);
		} else {
			eprintf ("cannot retrieve registers from pid %d\n", core->dbg->pid);
		}
		break;
	case ' ': // "dr"
		arg = strchr (str + 1, '=');
		if (arg) {
			char *string;
			const char *regname;
			*arg = 0;
			string = r_str_trim (strdup (str + 1));
			regname = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (string));
			if (!regname) {
				regname = string;
			}
			r = r_reg_get (core->dbg->reg, regname, -1); //R_REG_TYPE_GPR);
			if (r) {
				if (r->flags) {
					r_cons_printf ("0x%08"PFMT64x" ->",
							r_reg_get_value (core->dbg->reg, r));
					r_reg_set_bvalue (core->dbg->reg, r, arg+1);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
					r_cons_printf ("0x%08"PFMT64x"\n",
							r_reg_get_value (core->dbg->reg, r));
				} else {
					r_cons_printf ("0x%08"PFMT64x" ->",
							r_reg_get_value (core->dbg->reg, r));
					r_reg_set_value (core->dbg->reg, r,
							r_num_math (core->num, arg+1));
					r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
					r_cons_printf ("0x%08"PFMT64x"\n",
							r_reg_get_value (core->dbg->reg, r));
				}
			} else {
				eprintf ("unknown register '%s'\n", string);
			}
			free (string);
			// update flags here
			r_core_cmdf (core, ".dr*%d", bits);
			return;
		}

		int size = atoi (str + 1);
		if (size) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, size, str[0], use_color);
		} else {
			char *comma = strchr (str + 1, ',');
			if (comma) {
				size = 32; // non-zero
				char *args = strdup (str + 1);
				char argc = r_str_split (args, ',');
				for (i = 0; i < argc; i++) {
					showreg (core, r_str_word_get0 (args, i));
				}
				free (args);
			} else {
				size = showreg (core, str + 1);
			}
		}
	}
}

static int validAddress(RCore *core, ut64 addr) {
	RDebugMap *map;
	RListIter *iter;
	if (!r_config_get_i (core->config, "dbg.bpinmaps")) {
		return core->num->value = 1;
	}
	r_debug_map_sync (core->dbg);
	r_list_foreach (core->dbg->maps, iter, map) {
		if (addr >= map->addr && addr < map->addr_end) {
			return core->num->value = 1;
		}
	}
	// TODO: try to read memory, expect no 0xffff
	// TODO: check map permissions
	return core->num->value = 0;
}

static void backtrace_vars(RCore *core, RList *frames) {
	RDebugFrame *f;
	RListIter *iter;
	// anal vs debug ?
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
	if (!sp) {
		sp = "SP";
	}
	if (!bp) {
		bp = "BP";
	}
	RReg *r = core->anal->reg;
	ut64 dsp = r_reg_getv (r, sp);
	ut64 dbp = r_reg_getv (r, bp);
	int n = 0;
	r_list_foreach (frames, iter, f) {
		ut64 s = f->sp ? f->sp : dsp;
		ut64 b = f->bp ? f->bp : dbp;
		r_reg_setv (r, bp, s);
		r_reg_setv (r, sp, b);
//////////
		char flagdesc[1024], flagdesc2[1024];
		RFlagItem *fi = r_flag_get_at (core->flags, f->addr, true);
		flagdesc[0] = flagdesc2[0] = 0;
		if (fi) {
			if (fi->offset != f->addr) {
				int delta = (int)(f->addr - fi->offset);
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
		r_cons_printf ("%d  0x%08"PFMT64x" sp: 0x%08"PFMT64x" %-5d"
				"[%s]  %s %s\n", n, f->addr, f->sp, (int)f->size,
				fcn ? fcn->name : "??", flagdesc, flagdesc2);
		eprintf ("afvd @ 0x%"PFMT64x"\n", f->addr);
		r_cons_push();
		char *res = r_core_cmd_strf (core, "afvd@0x%"PFMT64x, f->addr);
		r_cons_pop();
		r_cons_printf ("%s", res);
		free (res);
		n++;
	}
	r_reg_setv (r, bp, dbp);
	r_reg_setv (r, sp, dsp);
}

static void asciiart_backtrace(RCore *core, RList *frames) {
	// TODO: show local variables
	// TODO: show function/flags/symbols related
	// TODO: show contents of stack
	// TODO: honor scr.color
	RDebugFrame *f;
	RListIter *iter;
	bool mymap = false;
	// anal vs debug ?
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
	if (!sp) {
		sp = "SP";
	}
	if (!bp) {
		bp = "BP";
	}
	ut64 dsp = r_reg_getv (core->anal->reg, sp);
	ut64 dbp = r_reg_getv (core->anal->reg, bp);
	RDebugMap *map = r_debug_map_get (core->dbg, dsp);
	if (!map) {
		mymap = true;
		map = R_NEW0 (RDebugMap);
		map->addr = UT64_MAX;
		map->addr_end = UT64_MAX;
	}

	r_cons_printf ("0x%016"PFMT64x"  STACK END  ^^^\n", map->addr);
	r_cons_printf ("0x%016"PFMT64x"  STACK POINTER: %s\n", dsp, sp);
	r_cons_printf ("                    .------------------------.\n");
	int n = 0;
	r_list_foreach (frames, iter, f) {
		ut64 s = f->sp ? f->sp : dsp;
		ut64 b = f->bp ? f->bp : dbp;
		char *str = r_str_newf ("[frame %d]", n);
		r_cons_printf ("0x%016"PFMT64x"  |%4s    %10s      | ; size %d\n", s, sp, str, s - b);
		free (str);
		r_cons_printf ("                    |            ...         |\n");
		r_cons_printf ("0x%016"PFMT64x"  |%4s 0x%016"PFMT64x" | %s\n", b, bp, f->addr, "; return address");
		r_cons_printf ("                    )------------------------(\n");
		// eprintf ("0x%08llx 0x%08llx 0x%08llx\n", f->addr, s, b);
		n++;
	}
	r_cons_printf ("                    |           ...          |\n");
	r_cons_printf ("                    `------------------------'\n");
	r_cons_printf ("0x%016"PFMT64x"  STACK BOTTOM\n", map->addr_end);
	if (mymap) {
		r_debug_map_free (map);
	}
}

static void static_debug_stop(void *u) {
	RDebug *dbg = (RDebug *)u;
	r_debug_stop (dbg);
}

static void r_core_cmd_bp(RCore *core, const char *input) {
	RBreakpointItem *bpi;
	int i, hwbp = r_config_get_i (core->config, "dbg.hwbp");
	RDebugFrame *frame;
	RListIter *iter;
	const char *p;
	bool watch = false;
	int rw = 0;
	RList *list;
	ut64 addr;
	p = strchr (input, ' ');
	addr = p? r_num_math (core->num, p + 1): UT64_MAX;
	if (!addr) {
		addr = UT64_MAX;
	}

	switch (input[1]) {
	case '.':
		if (input[2]) {
			ut64 addr = r_num_tail (core->num, core->offset, input + 2);
			if (validAddress (core, addr)) {
				bpi = r_debug_bp_add (core->dbg, addr, hwbp, false, 0, NULL, 0);
				if (!bpi) {
					eprintf ("Unable to add breakpoint (%s)\n", input + 2);
				}
			} else {
				eprintf ("Invalid address\n");
			}
		} else {
			bpi = r_bp_get_at (core->dbg->bp, core->offset);
			if (bpi) {
				r_cons_printf ("breakpoint %s %s %s\n",
						r_str_rwx_i (bpi->rwx),
						bpi->enabled ?  "enabled" : "disabled",
						bpi->name ? bpi->name : "");
			}
		}
		break;
	case 'f':
		{
		RList *symbols = r_bin_get_symbols (core->bin);
		RBinSymbol *symbol;
		r_list_foreach (symbols, iter, symbol) {
			if (symbol->type && !strcmp (symbol->type, "FUNC")) {
				if (r_anal_noreturn_at (core->anal, symbol->vaddr)) {
					bpi = r_debug_bp_add (core->dbg, symbol->vaddr, hwbp, false, 0, NULL, 0);
					if (bpi) {
						bpi->name = r_str_newf ("%s.%s", "sym", symbol->name);
					} else {
						eprintf ("Unable to add a breakpoint"
						"into a noreturn function %s at addr 0x%"PFMT64x"\n",
									symbol->name, symbol->vaddr);
					}
				}
			}
		}
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
				eprintf ("Cannot set tracepoint\n");
			}
			break;
		case 'd': // "dbtd"
			for (p = input + 3; *p==' ';p++) {
				//nothing to see here
			}
			if (*p == '*') {
				r_bp_set_trace_all (core->dbg->bp, false);
			} else if (!r_bp_set_trace (core->dbg->bp, addr, false)) {
				eprintf ("Cannot unset tracepoint\n");
			}
			break;
		case 's': // "dbts"
			bpi = r_bp_get_at (core->dbg->bp, addr);
			if (bpi) {
				bpi->trace = !!!bpi->trace;
			} else {
				eprintf ("Cannot unset tracepoint\n");
			}
			break;
		case 'j': // "dbtj"
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = r_num_math (core->num, input + 2);
			}
			i = 0;
			list = r_debug_frames (core->dbg, addr);
			r_cons_printf ("[");
			r_list_foreach (list, iter, frame) {
				r_cons_printf ("%s%08" PFMT64d,
					       (i ? "," : ""),
					       frame->addr);
				i++;
			}
			r_cons_printf ("]\n");
			r_list_free (list);
			break;
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
					r_cons_printf ("%s0x%08"PFMT64x,
							(i ? " " : ""), frame->addr);
					break;
				case 's':
					r_cons_printf ("%s0x%08"PFMT64x,
							(i ? " " : ""), frame->sp);
					break;
				case 'b':
					r_cons_printf ("%s0x%08"PFMT64x,
							(i ? " " : ""), frame->bp);
					break;
				case '?':
				default:
					r_core_cmd0 (core, "db?~dbt");
					break;
				}
				i++;
			}
			r_cons_newline ();
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
			r_cons_printf ("f-bt.*\n");
			r_list_foreach (list, iter, frame) {
				r_cons_printf ("f bt.frame%d = 0x%08"PFMT64x"\n", i, frame->addr);
				r_cons_printf ("f bt.frame%d.stack %d 0x%08"PFMT64x"\n", i, frame->size, frame->sp);
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
				char flagdesc[1024], flagdesc2[1024], pcstr[32], spstr[32];
				RFlagItem *f = r_flag_get_at (core->flags, frame->addr, true);
				flagdesc[0] = flagdesc2[0] = 0;
				if (f) {
					if (f->offset != addr) {
						int delta = (int)(frame->addr - f->offset);
						if (delta > 0) {
							snprintf (flagdesc, sizeof (flagdesc),
									"%s+%d", f->name, delta);
						} else if (delta < 0) {
							snprintf (flagdesc, sizeof (flagdesc),
									"%s%d", f->name, delta);
						} else {
							snprintf (flagdesc, sizeof (flagdesc),
									"%s", f->name);
						}
					} else {
						snprintf (flagdesc, sizeof (flagdesc),
								"%s", f->name);
					}
				}
				f = r_flag_get_at (core->flags, frame->addr, true);
				if (f && !strchr (f->name, '.')) {
					f = r_flag_get_at (core->flags, frame->addr - 1, true);
				}
				if (f) {
					if (f->offset != addr) {
						int delta = (int)(frame->addr - 1 - f->offset);
						if (delta > 0) {
							snprintf (flagdesc2, sizeof (flagdesc2),
									"%s+%d", f->name, delta + 1);
						} else if (delta<0) {
							snprintf (flagdesc2, sizeof (flagdesc2),
									"%s%d", f->name, delta + 1);
						} else {
							snprintf (flagdesc2, sizeof (flagdesc2),
									"%s+1", f->name);
						}
					} else {
						snprintf (flagdesc2, sizeof (flagdesc2),
								"%s", f->name);
					}
				}
				if (!strcmp (flagdesc, flagdesc2)) {
					flagdesc2[0] = 0;
				}

				if (core->dbg->bits & R_SYS_BITS_64) {
					snprintf (pcstr, sizeof (pcstr), "0x%-16" PFMT64x, frame->addr);
					snprintf (spstr, sizeof (spstr), "0x%-16" PFMT64x, frame->sp);
				} else if (core->dbg->bits & R_SYS_BITS_32) {
					snprintf (pcstr, sizeof (pcstr), "0x%-8" PFMT64x, frame->addr);
					snprintf (spstr, sizeof (spstr), "0x%-8" PFMT64x, frame->sp);
				} else {
					snprintf (pcstr, sizeof (pcstr), "0x%" PFMT64x, frame->addr);
					snprintf (spstr, sizeof (spstr), "0x%" PFMT64x, frame->sp);
				}

				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, frame->addr, 0);
				r_cons_printf ("%d  %s sp: %s  %-5d"
						"[%s]  %s %s\n", i++,
						pcstr, spstr,
						(int)frame->size,
						fcn ? fcn->name : "??",
						flagdesc,
						flagdesc2);
			}
			r_list_free (list);
			break;
		case '?':
		default:
			r_core_cmd_help (core, help_msg_dbt);
			break;
		}
		break;
	case 'b': // "dbb"
		if (input[2]) {
			core->dbg->bp->delta = (st64)r_num_math (core->num, input + 2);
		} else {
			r_cons_printf ("%"PFMT64d"\n", core->dbg->bp->delta);
		}
		break;
	case 'm': // "dbm"
		if (input[2] && input[3]) {
			char *string = strdup (input + 3);
			char *module = NULL;
			st64 delta = 0;

			module = strtok (string, " ");
			delta = (ut64)r_num_math (core->num, strtok (NULL, ""));
			bpi = r_debug_bp_add (core->dbg, 0, hwbp, false, 0, module, delta);
			free (string);
		}
		break;
	case 'j': r_bp_list (core->dbg->bp, 'j'); break;
	case '*': r_bp_list (core->dbg->bp, 1); break;
	case '\0': r_bp_list (core->dbg->bp, 0); break;
	case '-': // "db-"
		if (input[2] == '*') r_bp_del_all (core->dbg->bp);
		else r_bp_del (core->dbg->bp, r_num_math (core->num, input + 2));
		break;
	case 'c': // "dbc"
		if (input[2] == ' ') {
			char *inp = strdup (input + 3);
			if (inp) {
				char *arg = strchr (inp, ' ');
				if (arg) {
					*arg++ = 0;
					addr = r_num_math (core->num, inp);
					bpi = r_bp_get_at (core->dbg->bp, addr);
					if (bpi) {
						free (bpi->data);
						bpi->data = strdup (arg);
					} else {
						eprintf ("No breakpoint defined at 0x%08"PFMT64x"\n", addr);
					}
				} else {
					eprintf ("- Missing argument\n");
				}
				free (inp);
			} else {
				eprintf ("Cannot strdup. Your heap is fucked up\n");
			}
		} else {
			eprintf ("Use: dbc [addr] [command]\n");
		}
		break;
	case 'C': // "dbC"
		if (input[2] == ' ') {
			char *inp = strdup (input + 3);
			if (inp) {
				char *arg = strchr (inp, ' ');
				if (arg) {
					*arg++ = 0;
					addr = r_num_math (core->num, inp);
					bpi = r_bp_get_at (core->dbg->bp, addr);
					if (bpi) {
						free (bpi->cond);
						bpi->cond = strdup (arg);
					} else {
						eprintf ("No breakpoint defined at 0x%08"PFMT64x"\n", addr);
					}
				} else {
					eprintf ("1 Missing argument\n");
				}
				free (inp);
			} else {
				eprintf ("Cannot strdup. Your heap is fucked up\n");
			}
		} else {
			eprintf ("Use: dbc [addr] [command]\n");
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
			if (!bpi) eprintf ("Cannot set breakpoint (%s)\n", input + 2);
		}
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input + 2), true);
		break;
	case 'n': // "dbn"
		bpi = r_bp_get_at (core->dbg->bp, core->offset);
		if (input[2] == ' ') {
			if (bpi) {
				free (bpi->name);
				bpi->name = strdup (input + 3);
			} else {
				eprintf ("Cannot find breakpoint at "
						"0x%08"PFMT64x"\n", core->offset);
			}
		} else {
			if (bpi && bpi->name) {
				r_cons_println (bpi->name);
			}
		}
		break;
	case 'e':
		for (p = input + 2; *p == ' '; p++);
		if (*p == '*') r_bp_enable_all (core->dbg->bp,true);
		else r_bp_enable (core->dbg->bp, r_num_math (core->num, input + 2), true);
		break;
	case 'd':
		for (p = input + 2; *p == ' '; p++);
		if (*p == '*') r_bp_enable_all (core->dbg->bp, false);
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input + 2), false);
		break;
	case 'h':
		switch (input[2]) {
		case 0:
			r_bp_plugin_list (core->dbg->bp);
			break;
		case ' ':
			if (input[3]) {
				if (!r_bp_use (core->dbg->bp, input + 3, core->anal->bits)) {
					eprintf ("Invalid name: '%s'.\n", input + 3);
				}
			}
			break;
		case '-':
			if (input[3]) {
				if (!r_bp_plugin_del (core->dbg->bp, input + 3)) {
					eprintf ("Invalid name: '%s'.\n", input + 3);
				}
			}
			break;
		case '?':
		default:
			eprintf ("Usage: dh [plugin-name]  # select a debug handler plugin\n");
			break;
		}
		break;
	case 'w': // "dbw"
		if (input[2] == 'C') { // "dbwC"
			if (input[3] == ' ') {
				char *inp = strdup (input + 4);
				if (inp) {
					char *arg = strchr (inp, ' ');
					if (arg) {
						*arg++ = 0;
						addr = r_num_math (core->num, inp);
						bpi = r_bp_get_at (core->dbg->bp, addr);
						if (bpi) {
							free (bpi->cond);
							bpi->cond = strdup (arg);
						} else {
							eprintf ("No breakpoint defined at 0x%08"PFMT64x"\n", addr);
						}
					} else {
						eprintf ("1 Missing argument\n");
					}
					free (inp);
				} else {
					eprintf ("Cannot strdup. Your heap is fucked up\n");
				}
			} else {
				eprintf ("Use: dbwC [addr] [command]\n");
			}
			break;
		}
		input++; // skip 'w'
		watch = true;
		// passthru
	case ' ': // "db"
		for (p = input + 2; *p == ' '; p++);
		if (*p == '-') {
			r_bp_del (core->dbg->bp, r_num_math (core->num, p + 1));
		} else {
			#define DB_ARG(x) r_str_word_get0(str, x)
			char *str = strdup (p);
			int sl = r_str_word_set0 (str);
			addr = r_num_math (core->num, DB_ARG(0));
			if (watch) {
					if (sl == 2) {
						rw = (strcmp (DB_ARG(1), "r") == 0 ? R_BP_PROT_READ : R_BP_PROT_WRITE);
					} else {
						eprintf ("Usage: dbw <addr> <rw> # Add watchpoint\n");
						free (str);
						break;
					}
			}
			if (validAddress (core, addr)) {
				bpi = r_debug_bp_add (core->dbg, addr, hwbp, watch, rw, NULL, 0);
				if (bpi) {
					free (bpi->name);
					if (!strcmp (input + 2, "$$")) {
						RFlagItem *f = r_flag_get_i2 (core->flags, addr);
						if (f) {
							if (addr > f->offset) {
								bpi->name = r_str_newf ("%s+0x%" PFMT64x, f->name, addr - f->offset);
							} else {
								bpi->name = strdup (f->name);
							}
						} else {
							bpi->name = r_str_newf ("0x%08" PFMT64x, addr);
						}
					} else {
						bpi->name = strdup (input + 2);
					}
				} else {
					eprintf ("Cannot set breakpoint at '%s'\n", input + 2);
				}
			} else {
				eprintf ("Cannot place a breakpoint on 0x%08"PFMT64x" unmapped memory. See e? dbg.bpinmaps\n", addr);
			}
			free (str);
		}
		break;
	case 'i':
		switch (input[2]) {
		case 0: // "dbi"
			for (i = 0;i < core->dbg->bp->bps_idx_count; i++) {
				if ((bpi = core->dbg->bp->bps_idx[i])) {
					r_cons_printf ("%d 0x%08"PFMT64x" E:%d T:%d\n",
							i, bpi->addr, bpi->enabled, bpi->trace);
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
						eprintf ("Cannot set command\n");
					}
				} else {
					eprintf ("|Usage: dbic # cmd\n");
				}
			} else {
				eprintf ("|Usage: dbic # cmd\n");
			}
			break;
		case 'e': // "dbie"
			if ((bpi = r_bp_get_index (core->dbg->bp, addr))) {
				bpi->enabled = true;
			} else eprintf ("Cannot unset tracepoint\n");
			break;
		case 'd': // "dbid"
			if ((bpi = r_bp_get_index (core->dbg->bp, addr))) {
				bpi->enabled = false;
			} else eprintf ("Cannot unset tracepoint\n");
			break;
		case 's': // "dbis"
			if ((bpi = r_bp_get_index (core->dbg->bp, addr))) {
				bpi->enabled = !!!bpi->enabled;
			} else eprintf ("Cannot unset tracepoint\n");
			break;
		case 't': // "dbite" "dbitd" ...
			switch (input[3]) {
			case 'e':
				if ((bpi = r_bp_get_index (core->dbg->bp, addr))) {
					bpi->trace = true;
				} else eprintf ("Cannot unset tracepoint\n");
				break;
			case 'd':
				if ((bpi = r_bp_get_index (core->dbg->bp, addr))) {
					bpi->trace = false;
				} else eprintf ("Cannot unset tracepoint\n");
				break;
			case 's':
				if ((bpi = r_bp_get_index (core->dbg->bp, addr))) {
					bpi->trace = !!!bpi->trace;
				} else {
					eprintf ("Cannot unset tracepoint\n");
				}
				break;
			}
			break;
		}
		break;
	case '?':
	default:
		r_core_cmd_help (core, help_msg_db);
		break;
	}
}

static RTreeNode *add_trace_tree_child (Sdb *db, RTree *t, RTreeNode *cur, ut64 addr) {
	struct trace_node *t_node;
	char dbkey[TN_KEY_LEN];

	snprintf (dbkey, TN_KEY_LEN, TN_KEY_FMT, addr);
	t_node = (struct trace_node *)(size_t)sdb_num_get (db, dbkey, NULL);
	if (!t_node) {
		t_node = (struct trace_node *)malloc (sizeof (*t_node));
		t_node->addr = addr;
		t_node->refs = 1;
		sdb_num_set (db, dbkey, (ut64)(size_t)t_node, 0);
	} else {
		t_node->refs++;
	}
	return r_tree_add_node (t, cur, t_node);
}

static RCore *_core = NULL;

static void trace_traverse_pre (RTreeNode *n, RTreeVisitor *vis) {
	const char *name = "";
	struct trace_node *tn = n->data;
	unsigned int i;
	if (!tn) return;
	for (i = 0; i < n->depth - 1; i++) {
		r_cons_printf ("  ");
	}
	if (_core) {
		RFlagItem *f = r_flag_get_at (_core->flags, tn->addr, true);
		if (f) {
			name = f->name;
		}
	}
	r_cons_printf (" 0x%08"PFMT64x" refs %d %s\n", tn->addr, tn->refs, name);
}

static void trace_traverse (RTree *t) {
	RTreeVisitor vis = { 0 };

	/* clear the line on stderr, because somebody has written there */
	fprintf (stderr, "\x1b[2K\r");
	fflush (stderr);
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

		if (r_cons_is_breaked()) {
			break;
		}
		if (r_debug_is_dead (dbg)) {
			break;
		}
		if (debug_to != UT64_MAX && !r_debug_continue_until (dbg, debug_to)) {
			break;
		} else if (!r_debug_step (dbg, 1)) {
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
		r_anal_op (core->anal, &aop, addr, buf, sizeof (buf));
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
		eprintf ("No process to debug.");
		return;
	}
	if (*input == ' ') {
		input = r_str_trim_ro (input);
		ut64 first_n = r_num_math (core->num, input);
		input = strchr (input, ' ');
		if (input) {
			input = r_str_trim_ro (input);
			from = first_n;
			to = r_num_math (core->num, input);
			input = strchr (input, ' ');
			if (input) {
				input = r_str_trim_ro (input);
				final_addr = r_num_math (core->num, input);
			}
		} else {
			final_addr = first_n;
		}
	}
	core->dbg->trace->enabled = 0;
	r_cons_break_push (static_debug_stop, core->dbg);
	r_reg_arena_swap (core->dbg->reg, true);
	if (final_addr != UT64_MAX) {
		int hwbp = r_config_get_i (core->config, "dbg.hwbp");
		bp_final = r_debug_bp_add (core->dbg, final_addr, hwbp, false, 0, NULL, 0);
		if (!bp_final) {
			eprintf ("Cannot set breakpoint at final address (%"PFMT64x")\n", final_addr);
		}
	}
	do_debug_trace_calls (core, from, to, final_addr);
	if (bp_final) {
		r_bp_del (core->dbg->bp, final_addr);
	}
	_core = core;
	trace_traverse (core->dbg->tree);
	core->dbg->trace->enabled = t;
	r_cons_break_pop ();
}

static void r_core_debug_esil (RCore *core, const char *input) {
	switch (input[0]) {
	case '\0': // "de"
		// list
		r_debug_esil_watch_list (core->dbg);
		break;
	case ' ': // "de "
		{
			char *line = strdup (input + 1);
			char *p, *q;
			int done = 0;
			int rwx = 0, dev = 0;
			p = strchr (line, ' ');
			if (p) {
				*p++ = 0;
				if (strchr (line, 'r')) rwx |= R_IO_READ;
				if (strchr (line, 'w')) rwx |= R_IO_WRITE;
				if (strchr (line, 'x')) rwx |= R_IO_EXEC;
				q = strchr (p, ' ');
				if (q) {
					*q++ = 0;
					dev = p[0];
					if (q) {
						r_debug_esil_watch (core->dbg, rwx, dev, q);
						done = 1;
					}
				}
			}
			if (!done) {
				const char *help_de_msg[] = {
					"Usage:", "de", " [rwx] [reg|mem] [expr]",
					NULL
				};
				r_core_cmd_help (core, help_de_msg);
			}
			free (line);
		}
		break;
	case '-': // "de-"
		r_debug_esil_watch_reset (core->dbg);
		break;
	case 'c': // "dec"
		if (r_debug_esil_watch_empty (core->dbg)) {
			eprintf ("Error: no esil watchpoints defined\n");
		} else {
			r_core_cmd0 (core, "aei");
			r_debug_esil_prestep (core->dbg, r_config_get_i (core->config, "esil.prestep"));
			r_debug_esil_continue (core->dbg);
		}
		break;
	case 's': // "des"
		if (input[1] == 'u' && input[2] == ' ') { // "desu"
			ut64 addr, naddr, fin = r_num_math (core->num, input + 2);
			r_core_cmd0 (core, "aei");
			addr = r_debug_reg_get (core->dbg, "PC");
			while (addr != fin) {
				r_debug_esil_prestep (core->dbg, r_config_get_i (
							core->config, "esil.prestep"));
				r_debug_esil_step (core->dbg, 1);
				naddr = r_debug_reg_get (core->dbg, "PC");
				if (naddr == addr) {
					eprintf ("Detected loophole\n");
					break;
				}
				addr = naddr;
			}
		} else if (input[1] == '?' || !input[1]) {
			r_core_cmd_help (core, help_msg_des);
		} else {
			r_core_cmd0 (core, "aei");
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
			r_cons_printf ("Examples:\n"
					" de r r rip       # stop when reads rip\n"
					" de rw m ADDR     # stop when read or write in ADDR\n"
					" de w r rdx       # stop when rdx register is modified\n"
					" de x m FROM..TO  # stop when rip in range\n");
		}
		break;
	}
}

static void r_core_debug_kill (RCore *core, const char *input) {
	if (!input || *input=='?') {
		if (input && input[1]) {
			const char *signame, *arg = input + 1;
			int signum = atoi (arg);
			if (signum > 0) {
				signame = r_signal_to_string (signum);
				if (signame)
					r_cons_println (signame);
			} else {
				signum = r_signal_from_string (arg);
				if (signum > 0) {
					r_cons_printf ("%d\n", signum);
				}
			}
		} else {
			r_core_cmd_help (core, help_msg_dk);
		}
	} else if (*input=='o') {
		switch (input[1]) {
			case 0: // "dko" - list signal skip/conts
				r_debug_signal_list (core->dbg, 1);
				break;
			case ' ': // dko SIGNAL
				if (input[2]) {
					char *p, *name = strdup (input + 2);
					int signum = atoi (name);
					p = strchr (name, ' ');
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
							eprintf ("Invalid option: %s\n", p);
						}
					} else {
						eprintf ("Invalid signal: %s\n", input + 2);
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
					r_cons_println ("NOTE: [signal] can be a number or a string that resolves with dk?\n"
							"  skip means do not enter into the signal handler\n"
							"  continue means enter into the signal handler");
				}
		}
	} else if (*input == 'j') {
		r_debug_signal_list (core->dbg, 2);
	} else if (!*input) {
		r_debug_signal_list (core->dbg, 0);
#if 0
		RListIter *iter;
		RDebugSignal *ds;
		eprintf ("TODO: list signal handlers of child\n");
		RList *list = r_debug_kill_list (core->dbg);
		r_list_foreach (list, iter, ds) {
			// TODO: resolve signal name by number and show handler offset
			eprintf ("--> %d\n", ds->num);
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

static bool cmd_dcu (RCore *core, const char *input) {
	const char *ptr = NULL;
	ut64 from, to, pc;
	bool dcu_range = false;
	bool invalid = (!input[0] || !input[1] || !input[2]);
	if (invalid || (input[2] != ' ' && input[2] != '.')) {
		r_core_cmd_help (core, help_msg_dcu);
		return false;
	}
	from = UT64_MAX;
	to = UT64_MAX;
	if (input[2] == '.') {
		ptr = strchr (input + 3, ' ');
		if (ptr) { // TODO: put '\0' in *ptr to avoid
			from = r_num_tail (core->num, core->offset, input + 2);
			if (ptr[1]=='.') {
				to = r_num_tail (core->num, core->offset, ptr+2);
			} else {
				to = r_num_math (core->num, ptr+1);
			}
			dcu_range = true;
		} else {
			from = r_num_tail (core->num, core->offset, input + 2);
		}
	} else {
		ptr = strchr (input + 3, ' ');
		if (ptr) { // TODO: put '\0' in *ptr to avoid
			from = r_num_math (core->num, input + 3);
			if (ptr[1]=='.') {
				to = r_num_tail (core->num, core->offset, ptr+2);
			} else {
				to = r_num_math (core->num, ptr+1);
			}
			dcu_range = true;
		} else {
			from = r_num_math (core->num, input + 3);
		}
	}
	if (from == UT64_MAX) {
		eprintf ("Cannot continue until address 0\n");
		return false;
	}
	if (to == UT64_MAX) {
		to = from;
	}
	if (dcu_range) {
		r_cons_break_push (NULL, NULL);
		do {
			if (r_cons_is_breaked ()) {
				break;
			}
			r_debug_step (core->dbg, 1);
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
			pc = r_debug_reg_get (core->dbg, "PC");
			eprintf ("Continue 0x%08"PFMT64x" > 0x%08"PFMT64x" < 0x%08"PFMT64x"\n",
					from, pc, to);
		} while (pc < from || pc > to);
		r_cons_break_pop ();
	} else {
		ut64 addr = from;
		eprintf ("Continue until 0x%08"PFMT64x" using %d bpsize\n", addr, core->dbg->bpsize);
		r_reg_arena_swap (core->dbg->reg, true);
		if (r_bp_add_sw (core->dbg->bp, addr, core->dbg->bpsize, R_BP_PROT_EXEC)) {
			r_debug_continue (core->dbg);
			r_bp_del (core->dbg->bp, addr);
		} else {
			eprintf ("Cannot set breakpoint of size %d at 0x%08"PFMT64x"\n",
				core->dbg->bpsize, addr);
		}
	}
	return true;
}

static int cmd_debug_continue (RCore *core, const char *input) {
	int pid, old_pid, signum;
	char *ptr;
	// TODO: we must use this for step 'ds' too maybe...
	switch (input[1]) {
	case 0: // "dc"
		r_reg_arena_swap (core->dbg->reg, true);
#if __linux__
		core->dbg->continue_all_threads = true;
		r_debug_continue (core->dbg);
#else
		r_debug_continue (core->dbg);
#endif
		break;
	case 'a': // "dca"
		eprintf ("TODO: dca\n");
		break;
	case 'b': // "dcb"
		{
			if (!r_debug_continue_back (core->dbg)) {
				eprintf ("cannot continue back\n");
			}
			break;
		}
#if __WINDOWS__ && !__CYGWIN__
	case 'e': // "dce"
		r_reg_arena_swap (core->dbg->reg, true);
		r_debug_continue_pass_exception (core->dbg);
		break;
#endif
	case 'f': // "dcf"
		eprintf ("[+] Running 'dcs vfork fork clone' behind the scenes...\n");
		// we should stop in fork and vfork syscalls
		//TODO: multiple syscalls not handled yet
		// r_core_cmd0 (core, "dcs vfork fork");
		r_core_cmd0 (core, "dcs vfork fork clone");
		break;
	case 'c': // "dcc"
		r_reg_arena_swap (core->dbg->reg, true);
		if (input[2] == 'u') {
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_UCALL, 0);
		} else {
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_CALL, 0);
		}
		break;
	case 'r':
		r_reg_arena_swap (core->dbg->reg, true);
		r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_RET, 1);
		break;
	case 'k':
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
	case 'p':
		{ // XXX: this is very slow
			RIOSection *s;
			ut64 pc;
			int n = 0;
			int t = core->dbg->trace->enabled;
			core->dbg->trace->enabled = 0;
			r_cons_break_push (static_debug_stop, core->dbg);
			do {
				r_debug_step (core->dbg, 1);
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
				pc = r_debug_reg_get (core->dbg, "PC");
				eprintf (" %d %"PFMT64x"\r", n++, pc);
				s = r_io_section_vget (core->io, pc);
				if (r_cons_is_breaked ()) {
					break;
				}
			} while (!s);
			eprintf ("\n");
			core->dbg->trace->enabled = t;
			r_cons_break_pop ();
			return 1;
		}
	case 'u': // "dcu"
		if (input[2] == '?') {
			r_core_cmd_help (core, help_msg_dcu);
		} else if (input[2] == '.') {
			cmd_dcu (core, "cu $$");
		} else {
			cmd_dcu (core, input);
		}
		break;
	case ' ':
		old_pid = core->dbg->pid;
		pid = atoi (input + 2);
		r_reg_arena_swap (core->dbg->reg, true);
		r_debug_select (core->dbg, pid, core->dbg->tid);
		r_debug_continue (core->dbg);
		r_debug_select (core->dbg, old_pid, core->dbg->tid);
		break;
	case 't':
		cmd_debug_backtrace (core, input + 2);
		break;
	case '?': // "dc?"
	default:
		r_core_cmd_help (core, help_msg_dc);
		return 0;
	}
	return 1;
}

static char *get_corefile_name (const char *raw_name, int pid) {
	return (!*raw_name)?
		r_str_newf ("core.%u", pid) :
		r_str_trim (strdup (raw_name));
}

static int cmd_debug_step (RCore *core, const char *input) {
	ut64 addr;
	ut8 buf[64];
	RAnalOp aop;
	int i, times = 1;
	if (strlen (input) > 2) {
		times = r_num_math (core->num, input + 2);
	}
	if (times < 1) {
		times = 1;
	}
	switch (input[1]) {
	case 0: // "ds"
	case ' ':
		if (r_config_get_i (core->config, "cfg.debug")) {
			r_reg_arena_swap (core->dbg->reg, true);
			// sync registers for BSD PT_STEP/PT_CONT
			// XXX(jjd): is this necessary?
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
			if (!r_debug_step (core->dbg, times)) {
				eprintf ("Step failed\n");
				core->break_loop = true;
			}
		} else {
			r_core_cmdf (core, "%daes", R_MAX (1, times));
		}
		break;
	case 'i': // "dsi"
		if (input[2] == ' ') {
			int n = 0;
			r_cons_break_push (static_debug_stop, core->dbg);
			do {
				if (r_cons_is_breaked ()) {
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
			r_cons_break_pop ();
			eprintf ("Stopped after %d instructions\n", n);
		} else {
			eprintf ("3 Missing argument\n");
		}
		break;
	case 'f': // "dsf"
		step_until_eof (core);
		break;
	case 'u': // "dsu"
		switch (input[2]) {
		case 'f':
			step_until_flag (core, input + 3);
			break;
		case 'i':
			if (input[3] == 'r') {
				step_until_inst (core, input + 4, true);
			}
			else {
				step_until_inst (core, input + 3, false);
			}
			break;
		case 'e':
			step_until_esil (core, input + 3);
			break;
		case ' ':
			r_reg_arena_swap (core->dbg->reg, true);
			step_until (core, r_num_math (core->num, input + 2)); // XXX dupped by times
			break;
		default:
			r_cons_println ("Usage: dsu[fei] [arg]  . step until address ' ',"
					" 'f'lag, 'e'sil or 'i'nstruction matching");
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
			r_anal_op (core->anal, &aop, addr, buf, sizeof (buf));
			if (aop.type == R_ANAL_OP_TYPE_CALL) {
				RIOSection *s = r_io_section_vget (core->io, aop.jump);
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
			char delb[128] = R_EMPTY;
			addr = r_debug_reg_get (core->dbg, "PC");
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, addr);
			sprintf(delb, "db 0x%"PFMT64x"", addr);
			r_reg_arena_swap (core->dbg->reg, true);
			for (i = 0; i < times; i++) {
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false);
				r_io_read_at (core->io, addr, buf, sizeof (buf));
				r_anal_op (core->anal, &aop, addr, buf, sizeof (buf));
				if (aop.jump != UT64_MAX && aop.fail != UT64_MAX) {
					eprintf ("Don't know how to skip this instruction\n");
					if (bpi) r_core_cmd0 (core, delb);
					break;
				}
				addr += aop.size;
			}
			r_debug_reg_set (core->dbg, "PC", addr);
			if (bpi) {
				r_core_cmd0 (core, delb);
			}
			break;
		}
	case 'o': // "dso"
		if (r_config_get_i (core->config, "cfg.debug")) {
			char delb[128] = R_EMPTY;
			addr = r_debug_reg_get (core->dbg, "PC");
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, addr);
			sprintf(delb, "db 0x%"PFMT64x"", addr);
			r_bp_del (core->dbg->bp, addr);
			r_reg_arena_swap (core->dbg->reg, true);
			r_debug_step_over (core->dbg, times);
			if (bpi) r_core_cmd0 (core, delb);
		} else {
			r_core_cmdf (core, "aeso%s", input + 2);
		}
		break;
	case 'b': // "dsb"
		if (r_config_get_i (core->config, "cfg.debug")) {
			if (!r_debug_step_back (core->dbg)) {
				eprintf ("cannot step back\n");
			}
		} else {
			if (r_core_esil_step_back (core)) {
				r_core_cmd0 (core, ".dr*");
			} else {
				eprintf ("cannot step back\n");
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

static void consumeBuffer(RBuffer *buf, const char *cmd, const char *errmsg) {
	if (!buf) {
		if (errmsg) {
			r_cons_printf ("%s\n", errmsg);
		}
		return;
	}
	if (cmd) {
		r_cons_printf ("%s", cmd);
	}
	int i;
	for (i = 0; i < buf->length; i++) {
		r_cons_printf ("%02x", buf->buf[i]);
	}
	r_cons_printf ("\n");
}

static int cmd_debug(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RDebugTracepoint *t;
	int follow = 0;
	const char *ptr;
	ut64 addr;

	if (r_sandbox_enable (0)) {
		eprintf ("Debugger commands disabled in sandbox mode\n");
		return 0;
	}
	if (!strncmp (input, "ate", 3)) {
		char str[128];
		str[0] = 0;
		r_print_date_get_now (core->print, str);
		r_cons_println (str);
		return 0;
	}

	switch (input[0]) {
	case 't':
		// TODO: define ranges? to display only some traces, allow to scroll on this disasm? ~.. ?
		switch (input[1]) {
		case '\0': // "dt"
			r_debug_trace_list (core->dbg, 0);
			break;
		case '*': // "dt*"
			r_debug_trace_list (core->dbg, 1);
			break;
		case ' ': // "dt [addr]"
			if ((t = r_debug_trace_get (core->dbg,
					r_num_math (core->num, input + 3)))) {
				r_cons_printf ("offset = 0x%" PFMT64x "\n", t->addr);
				r_cons_printf ("opsize = %d\n", t->size);
				r_cons_printf ("times = %d\n", t->times);
				r_cons_printf ("count = %d\n", t->count);
				//TODO cons_printf("time = %d\n", t->tm);
			}
			break;
		case 'a': // "dta"
			r_debug_trace_at (core->dbg, input + 3);
			break;
		case 't': // "dtt"
			r_debug_trace_tag (core->dbg, atoi (input + 3));
			break;
		case 'c': // "dtc"
			if (input[2] == '?') {
				r_cons_println ("Usage: dtc [addr] ([from] [to] [addr]) - trace calls in debugger");
			} else {
				debug_trace_calls (core, input + 2);
			}
			break;
		case 'r': // "dtr"
			eprintf ("TODO\n");
			//trace_show(-1, trace_tag_get());
			break;
		case 'd': // "dtd"
			// TODO: reimplement using the api
			r_core_cmd0 (core, "pd 1 @@= `dt~[0]`");
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
			ptr = input + 3;
			addr = r_num_math (core->num, ptr);
			ptr = strchr (ptr, ' ');
			if (ptr) {
				RAnalOp *op = r_core_op_anal (core, addr);
				if (op) {
					RDebugTracepoint *tp = r_debug_trace_add (core->dbg, addr, op->size);
					if (!tp) {
						r_anal_op_free (op);
						break;
					}
					tp->count = r_num_math (core->num, ptr + 1);
					r_anal_trace_bb (core->anal, addr);
					r_anal_op_free (op);
				} else {
					eprintf ("Cannot analyze opcode at 0x%08" PFMT64x "\n", addr);
				}
			}
			break;
		case 'D': // "dtD"
			// XXX: not yet tested..and rsc dwarf-traces comes from r1
			r_core_cmd (core, "dt*|rsc dwarf-traces $FILE", 0);
			break;
		case 'e': // "dte"
			if (!core->anal->esil) {
				int stacksize = r_config_get_i (core->config, "esil.stack.depth");
				int romem = r_config_get_i (core->config, "esil.romem");
				int stats = r_config_get_i (core->config, "esil.stats");
				int iotrap = r_config_get_i (core->config, "esil.iotrap");
				int nonull = r_config_get_i (core->config, "esil.nonull");
				if (!(core->anal->esil = r_anal_esil_new (stacksize, iotrap))) {
					return 0;
				}
				r_anal_esil_setup (core->anal->esil,
						core->anal, romem, stats, nonull);
			}
			switch (input[2]) {
			case 0: // "dte"
				r_anal_esil_trace_list (core->anal->esil);
				break;
			case 'i': { // "dtei"
				RAnalOp *op;
				ut64 addr = r_num_math (core->num, input + 3);
				if (!addr) {
					addr = core->offset;
				}
				op = r_core_anal_op (core, addr);
				if (op) {
					r_anal_esil_trace (core->anal->esil, op);
				}
				r_anal_op_free (op);
			} break;
			case '-': // "dte-"
				if (!strcmp (input + 3, "*")) {
					if (core->anal->esil) {
						sdb_free (core->anal->esil->db_trace);
						core->anal->esil->db_trace = sdb_new0 ();
					}
				} else {
					eprintf ("TODO: dte- cannot delete specific logs. Use dte-*\n");
				}
				break;
			case ' ': { // "dte "
				int idx = atoi (input + 3);
				r_anal_esil_trace_show (
					core->anal->esil, idx);
			} break;
			case 'k': // "dtek"
				if (input[3] == ' ') {
					char *s = sdb_querys (core->anal->esil->db_trace,
							NULL, 0, input + 4);
					r_cons_println (s);
					free (s);
				} else {
					eprintf ("Usage: dtek [query]\n");
				}
				break;
			default:
				r_core_cmd_help (core, help_msg_dte);
			}
			break;
		case 's': // "dts"
			switch (input[2]) {
			case 0: // "dts"
				r_debug_session_list (core->dbg);
				break;
			case '+': // "dts+"
				r_debug_session_add (core->dbg, NULL);
				break;
			case '-': // "dts-"
				if (input[3] == ' ') {
					r_debug_session_delete (core->dbg, r_num_math (core->num, input + 3));
				} else {
					r_cons_println ("Usage: dts- [id] - Delete trace session");
				}
				break;
			case 't': // "dtst"
				if (input[3] == ' ') {
					r_debug_session_save (core->dbg, input + 4);
				} else {
					r_cons_println ("Usage: dtst [file] - save trace sessions to disk");
				}
				break;
			case 'f': // "dtsf"
				if (input[3] == ' ') {
					r_debug_session_restore (core->dbg, input + 4);
				} else {
					r_cons_println ("Usage: dtsf [file] - read trace sessions from disk");
				}
				break;
			case 'C': // "dtsC"
				if (input[3] == ' ') {
					r_debug_session_comment (core->dbg, atoi (input + 3), strchr (input + 4, ' '));
				} else {
					r_cons_println ("Usage: dtsC id comment - add comment for given trace session");
				}
				break;
			case 'A': // "dtsA" for debugging command (private command for developer)
				r_debug_session_set_idx (core->dbg, atoi (input + 4));
				break;
			default:
				r_core_cmd_help (core, help_msg_dts);
			}
			break;
		case '?':
		default:
			{
				r_core_cmd_help (core, help_msg_dt);
				r_cons_printf ("Current Tag: %d\n", core->dbg->trace->tag);
			}
			break;
		}
		break;
	case 'd': // "dtd"
		switch (input[1]) {
		case '\0': // "dtd"
			r_debug_desc_list (core->dbg, 0);
			break;
		case '*': // "dtd*"
			r_debug_desc_list (core->dbg, 1);
			break;
		case 's': // "dtds"
			{
				ut64 off = UT64_MAX;
				int fd = atoi (input + 2);
				char *str = strchr (input + 2, ' ');
				if (str) off = r_num_math (core->num, str+1);
				if (off == UT64_MAX || !r_debug_desc_seek (core->dbg, fd, off)) {
					RBuffer *buf = r_core_syscallf (core, "lseek", "%d, 0x%"PFMT64x", %d", fd, off, 0);
					consumeBuffer (buf, "dx ", "Cannot seek");
				}
			}
			break;
		case 't': // "ddt" <ttypath>
			r_core_cmdf (core, "dd-0");
			break;
		case 'd': // "ddd"
			{
				ut64 newfd = UT64_MAX;
				int fd = atoi (input + 2);
				char *str = strchr (input + 3, ' ');
				if (str) newfd = r_num_math (core->num, str+1);
				if (newfd == UT64_MAX || !r_debug_desc_dup (core->dbg, fd, newfd)) {
					RBuffer *buf = r_core_syscallf (core, "dup2", "%d, %d", fd, (int)newfd);
					if (buf) {
						consumeBuffer (buf, "dx ", NULL);
					} else {
						eprintf ("Cannot dup %d %d\n", fd, (int)newfd);
					}
				}
			}
			break;
		case 'r':
			{
				ut64 off = UT64_MAX;
				ut64 len = UT64_MAX;
				int fd = atoi (input + 2);
				char *str = strchr (input + 2, ' ');
				if (str) off = r_num_math (core->num, str+1);
				if (str) str = strchr (str+1, ' ');
				if (str) len = r_num_math (core->num, str+1);
				if (len == UT64_MAX || off == UT64_MAX || \
						!r_debug_desc_read (core->dbg, fd, off, len)) {
					consumeBuffer (r_core_syscallf (core, "read", "%d, 0x%"PFMT64x", %d",
								fd, off, (int)len), "dx ", "Cannot read");
				}
			}
			break;
		case 'w':
			{
				ut64 off = UT64_MAX;
				ut64 len = UT64_MAX;
				int fd = atoi (input + 2);
				char *str = strchr (input + 2, ' ');
				if (str) off = r_num_math (core->num, str+1);
				if (str) str = strchr (str+1, ' ');
				if (str) len = r_num_math (core->num, str+1);
				if (len == UT64_MAX || off == UT64_MAX || \
						!r_debug_desc_write (core->dbg, fd, off, len)) {
					RBuffer *buf = r_core_syscallf (core, "write", "%d, 0x%"PFMT64x", %d", fd, off, (int)len);
					consumeBuffer (buf, "dx ", "Cannot write");
				}
			}
			break;
		case '-': // "dd-"
			// close file
			//r_core_syscallf (core, "close", "%d", atoi (input + 2));
			{
				int fd = atoi (input + 2);
				//r_core_cmdf (core, "dxs close %d", (int)r_num_math ( core->num, input + 2));
				RBuffer *buf = r_core_syscallf (core, "close", "%d", fd);
				consumeBuffer (buf, "dx ", "Cannot close");
			}
			break;
		case ' ': // "dd"
			// TODO: handle read, readwrite, append
			{
				RBuffer *buf = r_core_syscallf (core, "open", "%s, %d, %d", input + 2, 2, 0644);
				consumeBuffer (buf, "dx ", "Cannot open");
			}
			// open file
			break;
		case '?':
		default:
			r_core_cmd_help (core, help_msg_dd);
			break;
		}
		break;
	case 's':
		if (cmd_debug_step (core, input)) {
			follow = r_config_get_i (core->config, "dbg.follow");
		}
		break;
	case 'b':
		r_core_cmd_bp (core, input);
		break;
	case 'H':
		eprintf ("TODO: transplant process\n");
		break;
	case 'c': // "dc"
		r_cons_break_push (static_debug_stop, core->dbg);
		(void)cmd_debug_continue (core, input);
		follow = r_config_get_i (core->config, "dbg.follow");
		r_cons_break_pop ();
		break;
	case 'm': // "dm"
		cmd_debug_map (core, input + 1);
		break;
	case 'r': // "dr"
		if (core->io->debug || input[1] == '?') {
			cmd_debug_reg (core, input + 1);
		} else {
			void cmd_anal_reg (RCore *core, const char *str);
			cmd_anal_reg (core, input + 1);
		}
		//r_core_cmd (core, "|reg", 0);
		break;
	case 'p': // "dp"
		cmd_debug_pid (core, input);
		break;
	case 'L': // "dL"
		if (input[1]=='q') {
			r_debug_plugin_list (core->dbg, 'q');
		} else if (input[1]==' ') {
			char *str = r_str_trim (strdup (input + 2));
			r_config_set (core->config, "dbg.backend", str);
			// implicit by config.set r_debug_use (core->dbg, str);
			free (str);
		} else {
			r_debug_plugin_list (core->dbg, 0);
		}
		break;
	case 'i': // "di"
		{
			RDebugInfo *rdi = r_debug_info (core->dbg, input + 2);
			RDebugReasonType stop = r_debug_stop_reason (core->dbg);
			char *escaped_str;
			switch (input[1]) {
			case '\0': // "di"
#define P r_cons_printf
#define PS(X, Y) {escaped_str = r_str_escape (Y);r_cons_printf(X, escaped_str);free(escaped_str);}
				if (rdi) {
					const char *s = r_signal_to_string (core->dbg->reason.signum);
					P ("type=%s\n", r_debug_reason_to_string (core->dbg->reason.type));
					P ("signal=%s\n", s? s: "none");
					P ("signum=%d\n", core->dbg->reason.signum);
					P ("sigpid=%d\n", core->dbg->reason.tid);
					P ("addr=0x%"PFMT64x"\n", core->dbg->reason.addr);
					P ("bp_addr=0x%"PFMT64x"\n", core->dbg->reason.bp_addr);
					P ("inbp=%s\n", r_str_bool (core->dbg->reason.bp_addr));
					P ("baddr=0x%"PFMT64x"\n", r_debug_get_baddr (core->dbg, NULL));
					P ("pid=%d\n", rdi->pid);
					P ("tid=%d\n", rdi->tid);
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
				if (stop != -1) P ("stopreason=%d\n", stop);
				break;
			case '*': // "di*"
				if (rdi) {
					r_cons_printf ("f dbg.signal = %d\n", core->dbg->reason.signum);
					r_cons_printf ("f dbg.sigpid = %d\n", core->dbg->reason.tid);
					r_cons_printf ("f dbg.inbp = %d\n", core->dbg->reason.bp_addr? 1: 0);
					r_cons_printf ("f dbg.sigaddr = 0x%"PFMT64x"\n", core->dbg->reason.addr);
					r_cons_printf ("f dbg.baddr = 0x%"PFMT64x"\n", r_debug_get_baddr (core->dbg, NULL));
					r_cons_printf ("f dbg.pid = %d\n", rdi->pid);
					r_cons_printf ("f dbg.tid = %d\n", rdi->tid);
					r_cons_printf ("f dbg.uid = %d\n", rdi->uid);
					r_cons_printf ("f dbg.gid = %d\n", rdi->gid);

				}
				break;
			case 'j': // "dij"
				P ("{");
				if (rdi) {
					const char *s = r_signal_to_string (core->dbg->reason.signum);
					P ("\"type\":\"%s\",", r_debug_reason_to_string (core->dbg->reason.type));
					P ("\"signal\":\"%s\",", s? s: "none");
					P ("\"signum\":%d,", core->dbg->reason.signum);
					P ("\"sigpid\":%d,", core->dbg->reason.tid);
					P ("\"addr\":%"PFMT64d",", core->dbg->reason.addr);
					P ("\"inbp\":%s,", r_str_bool (core->dbg->reason.bp_addr));
					P ("\"baddr\":%"PFMT64d",", r_debug_get_baddr (core->dbg, NULL));
					P ("\"pid\":%d,", rdi->pid);
					P ("\"tid\":%d,", rdi->tid);
					P ("\"uid\":%d,", rdi->uid);
					P ("\"gid\":%d,", rdi->gid);
					if (rdi->usr) {
						PS("\"usr\":\"%s\",", rdi->usr);
					}
					if (rdi->exe) {
						PS("\"exe\":\"%s\",", rdi->exe);
					}
					if (rdi->cmdline) {
						PS ("\"cmdline\":\"%s\",", rdi->cmdline);
					}
					if (rdi->cwd) {
						PS ("\"cwd\":\"%s\",", rdi->cwd);
					}
				}
				P ("\"stopreason\":%d}\n", stop);
				break;
#undef P
#undef PS
			case '?': // "dij"
			default:
				r_core_cmd_help (core, help_msg_di);
			}
			r_debug_info_free (rdi);
		}
		break;
	case 'e': // "de"
		r_core_debug_esil (core, input + 1);
		break;
	case 'g': // "dg"
		if (core->dbg->h && core->dbg->h->gcore) {
			if (core->dbg->pid == -1) {
				eprintf ("Not debugging, can't write core.\n");
				break;
			}
			char *corefile = get_corefile_name (input + 1, core->dbg->pid);
			eprintf ("Writing to file '%s'\n", corefile);
			r_file_rm (corefile);
			RBuffer *dst = r_buf_new ();
			if (dst) {
				if (!core->dbg->h->gcore (core->dbg, dst)) {
					eprintf ("dg: coredump failed\n");
				}
				r_file_dump (corefile, dst->buf, dst->length, 1);
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
		case 'r': //"dor" : rarun profile
			if (input[2] == ' ') {
				setRarunProfileString (core, input + 3);
			} else {
				// TODO use the api
				r_sys_cmd ("rarun2 -h");
			}
			break;
		case 'o': //"doo" : reopen in debugger
			r_core_file_reopen_debug (core, input + 2);
			break;
		case '?': // "do?"
		default:
			r_core_cmd_help (core, help_msg_do);
			break;
		}
		break;
	case 'w': // "dw"
		r_cons_break_push (static_debug_stop, core->dbg);
		for (;!r_cons_is_breaked ();) {
			int pid = atoi (input + 1);
			//int opid = core->dbg->pid = pid;
			int res = r_debug_kill (core->dbg, pid, 0, 0);
			if (!res) {
				break;
			}
			r_sys_usleep (200);
		}
		r_cons_break_pop ();
		break;
	case 'x': // "dx"
		switch (input[1]) {
		case ' ': { // "dx "
			ut8 bytes[4096];
			if (strlen (input + 2) < 4096){
				int bytes_len = r_hex_str2bin (input + 2, bytes);
				if (bytes_len>0) r_debug_execute (core->dbg,
						bytes, bytes_len, 0);
				else eprintf ("Invalid hexpairs\n");
			} else eprintf ("Injection opcodes so long\n");
			break;
		}
		case 'a': { // "dxa"
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, input + 2);
			if (acode && *acode->buf_hex) {
				r_reg_arena_push (core->dbg->reg);
				r_debug_execute (core->dbg, acode->buf,
						acode->len, 0);
				r_reg_arena_pop (core->dbg->reg);
			}
			r_asm_code_free (acode);
			break;
		}
		case 'e': { // "dxe"
			REgg *egg = core->egg;
			RBuffer *b;
			const char *asm_arch = r_config_get (core->config, "asm.arch");
			int asm_bits = r_config_get_i (core->config, "asm.bits");
			const char *asm_os = r_config_get (core->config, "asm.os");
			r_egg_setup (egg, asm_arch, asm_bits, 0, asm_os);
			r_egg_reset (egg);
			r_egg_load (egg, input + 1, 0);
			r_egg_compile (egg);
			b = r_egg_get_bin (egg);
			r_asm_set_pc (core->assembler, core->offset);
			r_reg_arena_push (core->dbg->reg);
			r_debug_execute (core->dbg, b->buf, b->length, 0);
			r_reg_arena_pop (core->dbg->reg);
			break;
		}
		case 'r': // "dxr"
			r_reg_arena_push (core->dbg->reg);
			if (input[2] == ' ') {
				ut8 bytes[4096];
				if (strlen (input + 2) < 4096){
					int bytes_len = r_hex_str2bin (input + 2,
							bytes);
					if (bytes_len > 0) {
						r_debug_execute (core->dbg,
								bytes, bytes_len,
								0);
					} else {
						eprintf ("Invalid hexpairs\n");
					}
				} else eprintf ("Injection opcodes so long\n");
			}
			r_reg_arena_pop (core->dbg->reg);
			break;
		case 's': // "dxs"
			if (input[2]) {
				char *str;
				r_cons_push ();
				str = r_core_cmd_str (core, sdb_fmt (0, "gs %s", input + 2));
				r_cons_pop ();
				r_core_cmdf (core, "dx %s", str); //`gs %s`", input + 2);
				free (str);
			} else {
				eprintf ("Missing parameter used in gs by dxs\n");
			}
			break;
		case '?': // "dx?"
		default:
			r_core_cmd_help (core, help_msg_dx);
			break;
		}
		break;
	case '?': // "d?"
	default:
		r_core_cmd_help (core, help_msg_d);
		break;
	}
	if (follow > 0) {
		ut64 pc = r_debug_reg_get (core->dbg, "PC");
		if ((pc < core->offset) || (pc > (core->offset + follow))) {
			r_core_cmd0 (core, "sr PC");
		}
	}
	return 0;
}
