/* radare - LGPL - Copyright 2009-2018 - pancake */

#include "r_asm.h"
#include "r_core.h"
#include "r_config.h"
#include "r_print.h"
#include "r_types.h"
#include "r_util.h"
#include <limits.h>

#define R_CORE_MAX_DISASM (1024 * 1024 * 8)
#define PF_USAGE_STR "pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]"

static const char *help_msg_amper[] = {
	"Usage:", "&[-|<cmd>]", "Manage tasks ( XXX broken because of mutex in r_core_cmd )",
	"&", "", "list all running threads",
	"&=", "", "show output of all tasks",
	"&=", " 3", "show output of task 3",
	"&j", "", "list all running threads (in JSON)",
	"&?", "", "show this help",
	"&+", " aa", "push to the task list",
	"&-", " 1", "delete task #1",
	"&", "-*", "delete all threads",
	"&", " aa", "run analysis in background",
	"&", " &&", "run all tasks in background",
	"&&", "", "run all pendings tasks (and join threads)",
	"&&&", "", "run all pendings tasks until ^C",
	"", "", "TODO: last command should honor asm.bits",
	"", "", "WARN: this feature is very experimental. Use it with caution",
	NULL
};

static const char *help_msg_at[] = {
	"Usage: [.][#]<cmd>[*] [`cmd`] [@ addr] [~grep] [|syscmd] [>[>]file]", "", "",
	"0", "", "alias for 's 0'",
	"0x", "addr", "alias for 's 0x..'",
	"#", "cmd", "if # is a number repeat the command # times",
	"/*", "", "start multiline comment",
	"*/", "", "end multiline comment",
	".", "cmd", "execute output of command as r2 script",
	".:", "8080", "wait for commands on port 8080",
	".!", "rabin2 -re $FILE", "run command output as r2 script",
	"*", "", "output of command in r2 script format (CC*)",
	"j", "", "output of command in JSON format (pdj)",
	"~", "?", "count number of lines (like wc -l)",
	"~", "??", "show internal grep help",
	"~", "..", "internal less",
	"~", "{}", "json indent",
	"~", "{}..", "json indent and less",
	"~", "word", "grep for lines matching word",
	"~", "!word", "grep for lines NOT matching word",
	"~", "word[2]", "grep 3rd column of lines matching word",
	"~", "word:3[0]", "grep 1st column from the 4th line matching word",
	"@", " 0x1024", "temporary seek to this address (sym.main+3)",
	"@", " [addr]!blocksize", "temporary set a new blocksize",
	"@..", "addr", "temporary partial address seek (see s..)",
	"@(", "from to)", "temporary set from and to for commands supporting ranges",
	"@a:", "arch[:bits]", "temporary set arch and bits",
	"@b:", "bits", "temporary set asm.bits",
	"@e:", "k=v,k=v", "temporary change eval vars",
	"@r:", "reg", "tmp seek to reg value (f.ex pd@r:PC)",
	"@i:", "nth.op", "temporary seek to the Nth relative instruction",
	"@f:", "file", "temporary replace block with file contents",
	"@o:", "fd", "temporary switch to another fd",
	"@s:", "string", "same as above but from a string",
	"@x:", "909192", "from hex pairs string",
	"@@=", "1 2 3", "run the previous command at offsets 1, 2 and 3",
	"@@", " hit*", "run the command on every flag matching 'hit*'",
	"@@?", "[ktfb..]", "show help for the iterator operator",
	"@@@", " [type]", "run a command on every [type] (see @@@? for help)",
	">", "file", "pipe output of command to file",
	">>", "file", "append to file",
	"H>", "file", "pipe output of command to file in HTML",
	"H>>", "file", "append to file with the output of command in HTML",
	"`", "pdi~push:0[0]`", "replace output of command inside the line",
	"|", "cmd", "pipe output to command (pd|less) (.dr*)",
	NULL
};

static const char *help_msg_at_at[] = {
	"@@", "", " # foreach iterator command:",
	"x", " @@ sym.*", "run 'x' over all flags matching 'sym.' in current flagspace",
	"x", " @@dbt[abs]", "run 'x' command on every backtrace address, bp or sp",
	"x", " @@.file", "run 'x' over the offsets specified in the file (one offset per line)",
	"x", " @@=off1 off2 ..", "manual list of offsets",
	"x", " @@/x 9090", "temporary set cmd.hit to run a command on each search result",
	"x", " @@k sdbquery", "run 'x' on all offsets returned by that sdbquery",
	"x", " @@t", "run 'x' on all threads (see dp)",
	"x", " @@b", "run 'x' on all basic blocks of current function (see afb)",
	"x", " @@i", "run 'x' on all instructions of the current function (see pdr)",
	"x", " @@iS", "run 'x' on all sections adjusting blocksize",
	"x", " @@f", "run 'x' on all functions (see aflq)",
	"x", " @@f:write", "run 'x' on all functions matching write in the name",
	"x", " @@s:from to step", "run 'x' on all offsets from, to incrementing by step",
	"x", " @@c:cmd", "the same as @@=`` without the backticks",
	"x", " @@=`pdf~call[0]`", "run 'x' at every call offset of the current function",
	// TODO: Add @@k sdb-query-expression-here
	NULL
};

static const char *help_msg_p[] = {
	"Usage:", "p[=68abcdDfiImrstuxz] [arg|len] [@addr]", "",
	"p-", "[?][jh] [mode]", "bar|json|histogram blocks (mode: e?search.in)",
	"p=", "[?][bep] [blks] [len] [blk]", "show entropy/printable chars/chars bars",
	"p2", " [len]", "8x8 2bpp-tiles",
	"p3", " [file]", "print stereogram (3D)",
	"p6", "[de] [len]", "base64 decode/encode",
	"p8", "[?][j] [len]", "8bit hexpair list of bytes",
	"pa", "[edD] [arg]", "pa:assemble  pa[dD]:disasm or pae: esil from hexpairs",
	"pA", "[n_ops]", "show n_ops address and type",
	"p", "[b|B|xb] [len] ([skip])", "bindump N bits skipping M",
	"pb", "[?] [n]", "bitstream of N bits",
	"pB", "[?] [n]", "bitstream of N bytes",
	"pc", "[?][p] [len]", "output C (or python) format",
	"pC", "[d] [rows]", "print disassembly in columns (see hex.cols and pdi)",
	"pd", "[?] [sz] [a] [b]", "disassemble N opcodes (pd) or N bytes (pD)",
	"pf", "[?][.nam] [fmt]", "print formatted data (pf.name, pf.name $<expr>)",
	"ph", "[?][=|hash] ([len])", "calculate hash for a block",
	"pj", "[?] [len]", "print as indented JSON",
	"p", "[iI][df] [len]", "print N ops/bytes (f=func) (see pi? and pdi)",
	"p", "[kK] [len]", "print key in randomart (K is for mosaic)",
	"pm", "[?] [magic]", "print libmagic data (see pm? and /m?)",
	"pq", "[?][iz] [len]", "print QR code with the first Nbytes of the current block",
	"pr", "[?][glx] [len]", "print N raw bytes (in lines or hexblocks, 'g'unzip)",
	"ps", "[?][pwz] [len]", "print pascal/wide/zero-terminated strings",
	"pt", "[?][dn] [len]", "print different timestamps",
	"pu", "[?][w] [len]", "print N url encoded bytes (w=wide)",
	"pv", "[?][jh] [mode]", "show variable/pointer/value in memory",
	"pwd", "", "display current working directory",
	"px", "[?][owq] [len]", "hexdump of N bytes (o=octal, w=32bit, q=64bit)",
	"pz", "[?] [len]", "print zoom view (see pz? for help)",
	NULL
};

static const char *help_msg_p_equal[] = {
	"Usage:", "p=[=bep?][qj] [nblocks] ([len]) ([offset]) ", "show entropy/printable chars/chars bars",
	"e ", "zoom.in", "specify range for zoom",
	"p=", "", "print bytes of current block in bars",
	"p==", "[..]", "same subcommands as p=, but using flame column graph instead of rows",
	"p=", "b", "same as above",
	"p=", "c", "print number of calls per block",
	"p=", "d", "print min/max/number of unique bytes in block",
	"p=", "e", "print entropy for each filesize/blocksize",
	"p=", "F", "print number of 0xFF bytes for each filesize/blocksize",
	"p=", "i", "print number of invalid instructions per block",
	"p=", "j", "print number of jumps and conditional jumps in block",
	"p=", "m", "print number of flags and marks in block",
	"p=", "p", "print number of printable bytes for each filesize/blocksize",
	"p=", "s", "print number of syscall and priviledged instructions",
	"p=", "z", "print number of chars in strings in block",
	"p=", "0", "print number of 0x00 bytes for each filesize/blocksize",
	NULL
};

static const char *help_msg_pj[] = {
	"Usage:", "pj[..] [size]", "",
	"pj", "", "print current block as indented JSON",
	"pj.", "", "print as indented JSON from 0 to the current offset",
	"pj..", "", "print JSON path from 0 to the current offset",
	NULL
};

static const char *help_msg_p_minus[] = {
	"Usage:", "p-[hj] [pieces]", "bar|json|histogram blocks",
	"p-", "", "show ascii-art bar of metadata in file boundaries",
	"p-h", "", "show histogram analysis of metadata per block",
	"p-j", "", "show json format",
	NULL
};

static const char *help_msg_pd[] = {
	"Usage:", "p[dD][ajbrfils] [sz] [arch] [bits]", " # Print Disassembly",
	"NOTE: ", "len", "parameter can be negative",
	"NOTE: ", "", "Pressing ENTER on empty command will repeat last pd command and also seek to end of disassembled range.",
	"pd", " N", "disassemble N instructions",
	"pd", " -N", "disassemble N instructions backward",
	"pD", " N", "disassemble N bytes",
	"pda", "", "disassemble all possible opcodes (byte per byte)",
	"pdb", "", "disassemble basic block",
	"pdc", "", "pseudo disassembler output in C-like syntax",
	"pdC", "", "show comments found in N instructions",
	"pdf", "", "disassemble function",
	"pdi", "", "like 'pi', with offset and bytes",
	"pdj", "", "disassemble to json",
	"pdJ", "", "formatted disassembly like pd as json",
	"pdk", "", "disassemble all methods of a class",
	"pdl", "", "show instruction sizes",
	"pdr", "", "recursive disassemble across the function graph",
	"pdr.", "", "recursive disassemble across the function graph (from current basic block)",
	"pdR", "", "recursive disassemble block size bytes without analyzing functions",
	// "pds", "", "disassemble with back sweep (greedy disassembly backwards)",
	"pds", "[?]", "disassemble summary (strings, calls, jumps, refs) (see pdsf and pdfs)",
	"pdt", "", "disassemble the debugger traces (see atd)",
	NULL
};

static const char *help_msg_pf[] = {
	"pf:", PF_USAGE_STR, "",
	"Commands:", "", "",
	"pf", "?", "Show this help",
	"pf", "??", "Format characters",
	"pf", "???", "pf usage examples",
	"pf", " fmt", "Show data using the given format-string. See 'pf\?\?' and 'pf\?\?\?'.",
	"pf.", "fmt_name", "Show data using named format",
	"pf.", "fmt_name.field_name", "Show specific data field using named format",
	"pfj ", "fmt_name|fmt", "Show data using (named) format in JSON",
	"pf* ", "fmt_name|fmt", "Show data using (named) format as r2 flag create commands",
	"pfd.", "fmt_name", "Show data using named format as graphviz commands",
	"pf.", "name [0|cnt]fmt", "Define a new named format",
	"pf.", "", "List all format definitions",
	"pf?", "fmt_name", "Show the definition of a named format",
	"pfo", "", "List all format definition files (fdf)",
	"pfo", " fdf_name", "Load a Format Definition File (fdf)",
	"pf.", "fmt_name.field_name=33", "Set new value for the specified field in named format",
	"pfv.", "fmt_name[.field]", "Print value(s) only for named format. Useful for one-liners",
	"pfs", "[.fmt_name| fmt]", "Print the size of (named) format in bytes",
	NULL
};

static const char *help_detail_pf[] = {
	"pf:", PF_USAGE_STR, "",
	"Format:", "", "",
	" ", "b", "byte (unsigned)",
	" ", "B", "resolve enum bitfield (see t?)",
	" ", "c", "char (signed byte)",
	" ", "d", "0x%%08x hexadecimal value (4 bytes) (see %%i and %%x)",
	" ", "D", "disassemble one opcode",
	" ", "e", "temporally swap endian",
	" ", "E", "resolve enum name (see t?)",
	" ", "f", "float value (4 bytes)",
	" ", "F", "double value (8 bytes)",
	" ", "i", "%%i signed integer value (4 bytes) (see %%d and %%x)",
	" ", "n", "next char specifies size of signed value (1, 2, 4 or 8 byte(s))",
	" ", "N", "next char specifies size of unsigned value (1, 2, 4 or 8 byte(s))",
	" ", "o", "0x%%08o octal value (4 byte)",
	" ", "p", "pointer reference (2, 4 or 8 bytes)",
	" ", "q", "quadword (8 bytes)",
	" ", "r", "CPU register `pf r (eax)plop`",
	" ", "s", "32bit pointer to string (4 bytes)",
	" ", "S", "64bit pointer to string (8 bytes)",
	" ", "t", "UNIX timestamp (4 bytes)",
	" ", "T", "show Ten first bytes of buffer",
	" ", "u", "uleb128 (variable length)",
	" ", "w", "word (2 bytes unsigned short in hex)",
	" ", "x", "0x%%08x hex value and flag (fd @ addr) (see %%d and %%i)",
	" ", "X", "show formatted hexpairs",
	" ", "z", "\\0 terminated string",
	" ", "Z", "\\0 terminated wide string",
	" ", "?", "data structure `pf ? (struct_name)example_name`",
	" ", "*", "next char is pointer (honors asm.bits)",
	" ", "+", "toggle show flags for each offset",
	" ", ":", "skip 4 bytes",
	" ", ".", "skip 1 byte",
	NULL
};

static const char *help_detail2_pf[] = {
	"pf:", PF_USAGE_STR, "",
	"Examples:", "", "",
	"pf", " 3xi foo bar", "3-array of struct, each with named fields: 'foo' as hex, and 'bar' as int",
	"pf", " B (BitFldType)arg_name`", "bitfield type",
	"pf", " E (EnumType)arg_name`", "enum type",
	"pf.", "obj xxdz prev next size name", "Define the obj format as xxdz",
	"pf", " obj=xxdz prev next size name", "Same as above",
	"pf", " iwq foo bar troll", "Print the iwq format with foo, bar, troll as the respective names for the fields",
	"pf", " 0iwq foo bar troll", "Same as above, but considered as a union (all fields at offset 0)",
	"pf.", "plop ? (troll)mystruct", "Use structure troll previously defined",
	"pf", " 10xiz pointer length string", "Print a size 10 array of the xiz struct with its field names",
	"pf", " {integer}? (bifc)", "Print integer times the following format (bifc)",
	"pf", " [4]w[7]i", "Print an array of 4 words and then an array of 7 integers",
	"pf", " ic...?i foo bar \"(pf xw yo foo)troll\" yo", "Print nested anonymous structres",
	"pf", "n2", "print signed short (2 bytes) value. Use N insted of n for printing unsigned values",
	NULL
};

static const char *help_msg_pi[] = {
	"Usage:", "pi[bdefrj] [num]", "",
	"pia", "", "print all possible opcodes (byte per byte)",
	"pib", "", "print instructions of basic block",
	"pid", "", "alias for pdi",
	"pie", "", "print offset + esil expression",
	"pif", "", "print instructions of function",
	"pij", "", "print N instructions in JSON",
	"pir", "", "like 'pdr' but with 'pI' output",
	NULL
};

static const char *help_msg_ps[] = {
	"Usage:", "ps[zpw+] [N]", "Print String",
	"ps", "", "print string",
	"psb", "", "print strings in current block",
	"psi", "", "print string inside curseek",
	"psj", "", "print string in JSON format",
	"psp", "", "print pascal string",
	"pss", "", "print string in screen (wrap width)",
	"psu", "", "print utf16 unicode (json)",
	"psw", "", "print 16bit wide string",
	"psW", "", "print 32bit wide string",
	"psx", "", "show string with escaped chars",
	"psz", "", "print zero-terminated string",
	"ps+", "", "print libc++ std::string (same-endian, ascii, zero-terminated)",
	NULL
};

static const char *help_msg_pt[] = {
	"Usage: pt", "[dn]", "print timestamps",
	"pt", "", "print UNIX time (32 bit `cfg.bigendian`)  Since January 1, 1970",
	"ptd", "", "print DOS time (32 bit `cfg.bigendian`)   Since January 1, 1980",
	"pth", "", "print HFS time (32 bit `cfg.bigendian`)   Since January 1, 1904",
	"ptn", "", "print NTFS time (64 bit `cfg.bigendian`)  Since January 1, 1601",
	NULL
};

static const char *help_msg_pv[] = {
	"Usage: pv[j][1,2,4,8,z]", "", "",
	"pv", "", "print bytes based on asm.bits",
	"pv1", "", "print 1 byte in memory",
	"pv2", "", "print 2 bytes in memory",
	"pv4", "", "print 4 bytes in memory",
	"pv8", "", "print 8 bytes in memory",
	"pvz", "", "print value as string (alias for ps)",
	NULL
};

static const char *help_msg_px[] = {
	"Usage:", "px[0afoswqWqQ][f]", " # Print heXadecimal",
	"px", "", "show hexdump",
	"px/", "", "same as x/ in gdb (help x)",
	"px0", "", "8bit hexpair list of bytes until zero byte",
	"pxa", "", "show annotated hexdump",
	"pxA", "", "show op analysis color map",
	"pxb", "", "dump bits in hexdump form",
	"pxc", "", "show hexdump with comments",
	"pxd", "[124]", "signed integer dump (1 byte, 2 and 4)",
	"pxe", "", "emoji hexdump! :)",
	"pxf", "", "show hexdump of current function",
	"pxh", "", "show hexadecimal half-words dump (16bit)",
	"pxH", "", "same as above, but one per line",
	"pxi", "", "HexII compact binary representation",
	"pxl", "", "display N lines (rows) of hexdump",
	"pxo", "", "show octal dump",
	"pxq", "", "show hexadecimal quad-words dump (64bit)",
	"pxQ", "", "same as above, but one per line",
	"pxr", "[j]", "show words with references to flags and code",
	"pxs", "", "show hexadecimal in sparse mode",
	"pxt", "[*.] [origin]", "show delta pointer table in r2 commands",
	"pxw", "", "show hexadecimal words dump (32bit)",
	"pxW", "", "same as above, but one per line",
	"pxx", "", "show N bytes of hex-less hexdump",
	"pxX", "", "show N words of hex-less hexdump",
	NULL
};

const char *help_msg_pz[] = {
	"Usage: pz [len]", "", "print zoomed blocks (filesize/N)",
	"e ", "zoom.maxsz", "max size of block",
	"e ", "zoom.from", "start address",
	"e ", "zoom.to", "end address",
	"e ", "zoom.byte", "specify how to calculate each byte",
	"pzp", "", "number of printable chars",
	"pzf", "", "count of flags in block",
	"pzs", "", "strings in range",
	"pz0", "", "number of bytes with value '0'",
	"pzF", "", "number of bytes with value 0xFF",
	"pze", "", "calculate entropy and expand to 0-255 range",
	"pzh", "", "head (first byte value); This is the default mode",
	// "WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
	NULL
};

static ut32 colormap[256] = {
	0x000000, 0x560000, 0x640000, 0x750000, 0x870000, 0x9b0000, 0xb00000, 0xc60000, 0xdd0000, 0xf50000, 0xff0f0f, 0xff2828, 0xff4343, 0xff5e5e, 0xff7979, 0xfe9595,
  0x4c1600, 0x561900, 0x641e00, 0x752300, 0x872800, 0x9b2e00, 0xb03400, 0xc63b00, 0xdd4200, 0xf54900, 0xff570f, 0xff6928, 0xff7b43, 0xff8e5e, 0xffa179, 0xfeb595,
  0x4c3900, 0x564000, 0x644b00, 0x755700, 0x876500, 0x9b7400, 0xb08400, 0xc69400, 0xdda600, 0xf5b800, 0xffc30f, 0xffc928, 0xffd043, 0xffd65e, 0xffdd79, 0xfee495,
  0x4c4c00, 0x565600, 0x646400, 0x757500, 0x878700, 0x9b9b00, 0xb0b000, 0xc6c600, 0xdddd00, 0xf5f500, 0xffff0f, 0xffff28, 0xffff43, 0xffff5e, 0xffff79, 0xfffe95,
  0x324c00, 0x395600, 0x426400, 0x4e7500, 0x5a8700, 0x679b00, 0x75b000, 0x84c600, 0x93dd00, 0xa3f500, 0xafff0f, 0xb7ff28, 0xc0ff43, 0xc9ff5e, 0xd2ff79, 0xdbfe95,
  0x1f4c00, 0x235600, 0x296400, 0x307500, 0x388700, 0x409b00, 0x49b000, 0x52c600, 0x5cdd00, 0x66f500, 0x73ff0f, 0x82ff28, 0x91ff43, 0xa1ff5e, 0xb1ff79, 0xc1fe95,
  0x004c00, 0x005600, 0x006400, 0x007500, 0x008700, 0x009b00, 0x00b000, 0x00c600, 0x00dd00, 0x00f500, 0x0fff0f, 0x28ff28, 0x43ff43, 0x5eff5e, 0x79ff79, 0x95fe95,
  0x004c19, 0x00561c, 0x006421, 0x007527, 0x00872d, 0x009b33, 0x00b03a, 0x00c642, 0x00dd49, 0x00f551, 0x0fff5f, 0x28ff70, 0x43ff81, 0x5eff93, 0x79ffa6, 0x95feb8,
  0x004c4c, 0x005656, 0x006464, 0x007575, 0x008787, 0x009b9b, 0x00b0b0, 0x00c6c6, 0x00dddd, 0x00f5f5, 0x0ffffe, 0x28fffe, 0x43fffe, 0x5efffe, 0x79ffff, 0x95fffe,
  0x00394c, 0x004056, 0x004b64, 0x005775, 0x006587, 0x00749b, 0x0084b0, 0x0094c6, 0x00a6dd, 0x00b8f5, 0x0fc3ff, 0x28c9ff, 0x43d0ff, 0x5ed6ff, 0x79ddff, 0x95e4fe,
  0x00264c, 0x002b56, 0x003264, 0x003a75, 0x004387, 0x004d9b, 0x0058b0, 0x0063c6, 0x006edd, 0x007af5, 0x0f87ff, 0x2893ff, 0x43a1ff, 0x5eaeff, 0x79bcff, 0x95cafe,
  0x00134c, 0x001556, 0x001964, 0x001d75, 0x002187, 0x00269b, 0x002cb0, 0x0031c6, 0x0037dd, 0x003df5, 0x0f4bff, 0x285eff, 0x4372ff, 0x5e86ff, 0x799aff, 0x95b0fe,
  0x19004c, 0x1c0056, 0x210064, 0x270075, 0x2d0087, 0x33009b, 0x3a00b0, 0x4200c6, 0x4900dd, 0x5100f5, 0x5f0fff, 0x7028ff, 0x8143ff, 0x935eff, 0xa679ff, 0xb895fe,
  0x33004c, 0x390056, 0x420064, 0x4e0075, 0x5a0087, 0x67009b, 0x7500b0, 0x8400c6, 0x9300dd, 0xa300f5, 0xaf0fff, 0xb728ff, 0xc043ff, 0xc95eff, 0xd279ff, 0xdb95fe,
  0x4c004c, 0x560056, 0x640064, 0x750075, 0x870087, 0x9b009b, 0xb000b0, 0xc600c6, 0xdd00dd, 0xf500f5, 0xfe0fff, 0xfe28ff, 0xfe43ff, 0xfe5eff, 0xfe79ff, 0xfe95fe,
  0x4c0032, 0x560039, 0x640042, 0x75004e, 0x87005a, 0x9b0067, 0xb00075, 0xc60084, 0xdd0093, 0xf500a3, 0xff0faf, 0xff28b7, 0xff43c0, 0xff5ec9, 0xff79d2, 0xffffff,
};

static void cmd_print_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, &, amper);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, @, at);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, @@, at_at);
	DEFINE_CMD_DESCRIPTOR (core, p);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, p=, p_equal);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, p-, p_minus);
	DEFINE_CMD_DESCRIPTOR (core, pd);
	DEFINE_CMD_DESCRIPTOR_WITH_DETAIL2 (core, pf);
	DEFINE_CMD_DESCRIPTOR (core, pi);
	DEFINE_CMD_DESCRIPTOR (core, ps);
	DEFINE_CMD_DESCRIPTOR (core, pt);
	DEFINE_CMD_DESCRIPTOR (core, pv);
	DEFINE_CMD_DESCRIPTOR (core, px);
	DEFINE_CMD_DESCRIPTOR (core, pz);
}

// colordump
static void cmd_prc (RCore *core, const ut8* block, int len) {
	const char *chars = " .,:;!O@#";
	bool square = true; //false;
	int i, j;
	char ch, ch2, *color;
	int cols = r_config_get_i (core->config, "hex.pcols") + core->print->cols; // * 3.5;
	bool show_color = r_config_get_i (core->config, "scr.color");
	bool show_flags = r_config_get_i (core->config, "asm.flags");
	bool show_cursor = core->print->cur_enabled;
	if (cols < 1) {
		cols = 1;
	}
	cols /= 2;
	for (i = 0; i < len; i += cols) {
		r_print_addr (core->print, core->offset + i);
		for (j = i; j < i + cols; j ++) {
			if (j >= len) {
				break;
			}
			if (show_color) {
				char *str = r_str_newf ("rgb:fff rgb:%06x", colormap[block[j]]);
				color = r_cons_pal_parse (str, NULL);
				free (str);
				if (show_cursor && core->print->cur == j) {
					ch = '_';
				} else {
					ch = ' ';
				}
			} else {
				color = strdup ("");
				if (show_cursor && core->print->cur == j) {
					ch = '_';
				} else {
					const int idx = ((float)block[j] / 255) * (strlen (chars) - 1);
					ch = chars[idx];
				}
			}
			if (square) {
				if (show_flags) {
					RFlagItem *fi = r_flag_get_i (core->flags, core->offset + j);
					if (fi) {
						ch = fi->name[0];
						ch2 = fi->name[1];
					} else {
						ch2 = ch;
					}
				} else {
					ch2 = ch;
				}
				r_cons_printf ("%s%c%c", color, ch, ch2);
			} else {
				r_cons_printf ("%s%c", color, ch);
			}
			free (color);
		}
		r_cons_printf (Color_RESET);
		r_cons_newline ();
	}
}

static void cmd_pCd(RCore *core, const char *input) {
	int h, w = r_cons_get_size (&h);
	int colwidth = r_config_get_i (core->config, "hex.cols") * 2.5;
	int i, columns = w / colwidth;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = r_num_math (core->num, input);
	bool asm_minicols = r_config_get_i (core->config, "asm.minicols");
	char *o_ao = strdup (r_config_get (core->config, "asm.offset"));
	char *o_ab = strdup (r_config_get (core->config, "asm.bytes"));
	if (asm_minicols) {
		r_config_set (core->config, "asm.offset", "false");
// r_config_set (core->config, "asm.bytes", "false");
	}
	r_config_set (core->config, "asm.bytes", "false");
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	r_cons_push ();
	RConsCanvas *c = r_cons_canvas_new (w, rows);
	ut64 osek = core->offset;
	c->color = r_config_get_i (core->config, "scr.color");
	r_core_block_size (core, rows * 32);
	for (i = 0; i < columns; i++) {
		(void) r_cons_canvas_gotoxy (c, i * (w / columns), 0);
		char *cmd = r_str_newf ("pid %d @i:%d", rows, rows * i);
		char *dis = r_core_cmd_str (core, cmd);
		r_cons_canvas_write (c, dis);
		free (cmd);
		free (dis);
	}
	r_core_block_size (core, obsz);
	r_core_seek (core, osek, 1);

	r_cons_pop ();
	r_cons_canvas_print (c);
	r_cons_canvas_free (c);
	if (asm_minicols) {
		r_config_set (core->config, "asm.offset", o_ao);
		r_config_set (core->config, "asm.bytes", o_ab);
	}
	r_config_set (core->config, "asm.bytes", o_ab);
	free (o_ao);
	free (o_ab);
}

static void findMethodBounds(RList *methods, ut64 *min, ut64 *max) {
	RBinSymbol *sym;
	RListIter *iter;
	ut64 at_min = UT64_MAX;
	ut64 at_max = 0LL;

	r_list_foreach (methods, iter, sym) {
		if (sym->vaddr) {
			if (sym->vaddr < at_min) {
				at_min = sym->vaddr;
			}
			if (sym->vaddr + sym->size > at_max) {
				at_max = sym->vaddr + sym->size;
			}
		}
	}
	*min = at_min;
	*max = at_max;
}

static ut64 findClassBounds(RCore *core, const char *input, int *len) {
	ut64 min = 0, max = 0;
	RListIter *iter;
	RBinClass *c;
	RList *cs = r_bin_get_classes (core->bin);
	if (input && *input) {
		// resolve by name
		r_list_foreach (cs, iter, c) {
			if (!c || !c->name || !c->name[0]) {
				continue;
			}
			findMethodBounds (c->methods, &min, &max);
			if (len) {
				*len = (max - min);
			}
			return min;
		}
	} else {
		// resolve by core->offset
		r_list_foreach (cs, iter, c) {
			if (!c || !c->name || !c->name[0]) {
				continue;
			}
			findMethodBounds (c->methods, &min, &max);
			if (len) {
				*len = (max - min);
			}
			return min;
		}
	}
	return 0;
}

static void cmd_pCD(RCore *core, const char *input) {
	int h, w = r_cons_get_size (&h);
	int colwidth = r_config_get_i (core->config, "hex.cols") * 2.5;
	int i, columns = w / colwidth / 2;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = r_num_math (core->num, input);
	bool asm_minicols = r_config_get_i (core->config, "asm.minicols");
	char *o_ao = strdup (r_config_get (core->config, "asm.offset"));
	char *o_ab = strdup (r_config_get (core->config, "asm.bytes"));
	if (asm_minicols) {
		r_config_set (core->config, "asm.offset", "false");
		r_config_set (core->config, "asm.bytes", "false");
	}
	r_config_set (core->config, "asm.bytes", "false");
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	r_cons_push ();
	RConsCanvas *c = r_cons_canvas_new (w, rows);
	ut64 osek = core->offset;
	c->color = r_config_get_i (core->config, "scr.color");
	r_core_block_size (core, rows * 32);
	char *cmd = NULL;
	columns = 2;
	for (i = 0; i < columns; i++) {
		switch (i) {
		case 0:
			(void) r_cons_canvas_gotoxy (c, 0, 0);
			cmd = r_str_newf ("dr;?e;?e backtrace:;dbt");
			break;
		case 1:
			(void) r_cons_canvas_gotoxy (c, 28, 0);
			// cmd = r_str_newf ("pxw 128@r:SP;pd@r:PC");
			cmd = r_str_newf ("pxq 128@r:SP;pd@ 0x%"PFMT64x, osek);
			break;
		}
		char *dis = r_core_cmd_str (core, cmd);
		r_cons_canvas_write (c, dis);
		free (cmd);
		free (dis);
	}
	r_core_block_size (core, obsz);
	r_core_seek (core, osek, 1);

	r_cons_pop ();
	r_cons_canvas_print (c);
	r_cons_canvas_free (c);
	if (asm_minicols) {
		r_config_set (core->config, "asm.offset", o_ao);
		r_config_set (core->config, "asm.bytes", o_ab);
	}
	r_config_set (core->config, "asm.bytes", o_ab);
	free (o_ao);
	free (o_ab);
}

static void cmd_pCx(RCore *core, const char *input, const char *xcmd) {
	int h, w = r_cons_get_size (&h);
	int hex_cols = r_config_get_i (core->config, "hex.cols");
	int colwidth = hex_cols * 5;
	int i, columns = w / (colwidth * 0.9);
	int rows = h - 2;
	int user_rows = r_num_math (core->num, input);
	r_config_set_i (core->config, "hex.cols", colwidth / 5);
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	r_cons_push ();
	RConsCanvas *c = r_cons_canvas_new (w, rows);
	ut64 tsek = core->offset;
	c->color = r_config_get_i (core->config, "scr.color");
	int bsize = hex_cols * rows;
	if (!strcmp (xcmd, "pxA")) {
		bsize *= 12;
	}
	for (i = 0; i < columns; i++) {
		(void) r_cons_canvas_gotoxy (c, i * (w / columns), 0);
		char *cmd = r_str_newf ("%s %d @ %"PFMT64d, xcmd, bsize, tsek);
		char *dis = r_core_cmd_str (core, cmd);
		r_cons_canvas_write (c, dis);
		free (cmd);
		free (dis);
		tsek += bsize - 32;
	}

	r_cons_pop ();
	r_cons_canvas_print (c);
	r_cons_canvas_free (c);
	r_config_set_i (core->config, "hex.cols", hex_cols);
}

static char get_string_type(const ut8 *buf, ut64 len){
	ut64 needle = 0;
	int rc, i;
	char str_type = 0;

	if (!buf) {
		return '?';
	}
	while (needle < len) {
		rc = r_utf8_decode (buf + needle, len - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (needle + rc + 2 < len &&
		buf[needle + rc + 0] == 0x00 &&
		buf[needle + rc + 1] == 0x00 &&
		buf[needle + rc + 2] == 0x00) {
			str_type = 'w';
		} else {
			str_type = 'a';
		}
		for (rc = i = 0; needle < len; i += rc) {
			RRune r;
			if (str_type == 'w') {
				if (needle + 1 < len) {
					r = buf[needle + 1] << 8 | buf[needle];
					rc = 2;
				} else {
					break;
				}
			} else {
				rc = r_utf8_decode (buf + needle, len - needle, &r);
				if (rc > 1) {
					str_type = 'u';
				}
			}
			/*Invalid sequence detected*/
			if (!rc) {
				needle++;
				break;
			}
			needle += rc;
		}
	}
	return str_type;
}

static void cmd_print_eq_dict(RCore *core, const ut8 *block, int bsz) {
	int i;
	int min = -1;
	int max = 0;
	int dict = 0;
	int range = 0;
	bool histogram[256] = {0};
	for (i = 0; i < bsz; i++) {
		histogram[block[i]] = true;
	}
	for (i = 0; i < 256; i++) {
		if (histogram[i]) {
			if (min == -1) {
				min = i;
			}
			max = i;
			dict++;
		}
	}
	range = max - min;
	r_cons_printf ("min:              %d  0x%x\n", min, min);
	r_cons_printf ("max:              %d  0x%x\n", max, max);
	r_cons_printf ("unique (count):   %d  0x%x\n", dict, dict);
	r_cons_printf ("range (max-min):  %d  0x%x\n", range, range);
	r_cons_printf ("size (of block):  %d  0x%x\n", bsz, bsz);
}

R_API void r_core_set_asm_configs(RCore *core, char *arch, ut32 bits, int segoff){
	r_config_set (core->config, "asm.arch", arch);
	r_config_set_i (core->config, "asm.bits", bits);
	// XXX - this needs to be done here, because
	// if arch == x86 and bits == 16, segoff automatically changes
	r_config_set_i (core->config, "asm.segoff", segoff);
}

static void cmd_pDj(RCore *core, const char *arg) {
	int bsize = r_num_math (core->num, arg);
	if (bsize < 0) {
		bsize = -bsize;
	}
	r_cons_print ("[");
	ut8 *buf = malloc (bsize);
	if (buf) {
		r_io_read_at (core->io, core->offset, buf, bsize);
		r_core_print_disasm_json (core, core->offset, buf, bsize, 0);
		free (buf);
	} else {
		eprintf ("cannot allocate %d byte(s)\n", bsize);
	}
	r_cons_print ("]");
}

static void cmd_pdj(RCore *core, const char *arg, ut8* block) {
	int nblines = r_num_math (core->num, arg);
	r_cons_print ("[");
	r_core_print_disasm_json (core, core->offset, block, core->blocksize, nblines);
	r_cons_print ("]\n");
}

static int process_input(RCore *core, const char *input, ut64 *blocksize, char **asm_arch, ut32 *bits) {
	// input: start of the input string e.g. after the command symbols have been consumed
	// size: blocksize if present, otherwise -1
	// asm_arch: asm_arch to interpret as if present and valid, otherwise NULL;
	// bits: bits to use if present, otherwise -1

	int result = false;
	char *input_one = NULL, *input_two = NULL, *input_three = NULL;
	char *str_clone = NULL, *ptr_str_clone = NULL, *trimmed_clone = NULL;

	if (!input || !blocksize || !asm_arch || !bits) {
		return false;
	}

	str_clone = strdup (input);
	trimmed_clone = r_str_trim_head_tail (str_clone);
	input_one = trimmed_clone;

	ptr_str_clone = strchr (trimmed_clone, ' ');
	// terminate input_one
	if (ptr_str_clone) {
		*ptr_str_clone = '\0';
		input_two = (++ptr_str_clone);
		ptr_str_clone = strchr (input_two, ' ');
	}

	// terminate input_two
	if (ptr_str_clone && input_two) {
		*ptr_str_clone = '\0';
		input_three = (++ptr_str_clone);
		ptr_str_clone = strchr (input_three, ' ');
	}

	// terminate input_three
	if (ptr_str_clone && input_three) {
		*ptr_str_clone = '\0';
		ptr_str_clone = strchr (input_three, ' ');
	}

	// command formats
	// <size> <arch> <bits>
	// <size> <arch>
	// <size> <bits>
	// <arch> <bits>
	// <arch>

	// initialize
	*asm_arch = NULL;
	*blocksize = *bits = -1;

	if (input_one && input_two && input_three) {
		// <size> <arch> <bits>
		*blocksize = r_num_is_valid_input (core->num, input_one)? r_num_get_input_value (core->num, input_one): 0;
		*asm_arch = r_asm_is_valid (core->assembler, input_two)? strdup (input_two): NULL;
		*bits = r_num_get_input_value (core->num, input_three);
		result = true;

	} else if (input_one && input_two) {

		*blocksize = r_num_is_valid_input (core->num, input_one)? r_num_get_input_value (core->num, input_one): 0;

		if (!r_num_is_valid_input (core->num, input_one)) {
			// input_one can only be one other thing
			*asm_arch = r_asm_is_valid (core->assembler, input_one)? strdup (input_one): NULL;
			*bits = r_num_is_valid_input (core->num, input_two)? r_num_get_input_value (core->num, input_two): -1;
		} else {
			if (r_str_contains_macro (input_two)) {
				r_str_truncate_cmd (input_two);
			}
			*bits = r_num_is_valid_input (core->num, input_two)? r_num_get_input_value (core->num, input_two): -1;
			*asm_arch = r_asm_is_valid (core->assembler, input_two)? strdup (input_two): NULL;
		}

		result = true;
	} else if (input_one) {
		*blocksize = r_num_is_valid_input (core->num, input_one)? r_num_get_input_value (core->num, input_one): 0;
		if (!r_num_is_valid_input (core->num, input_one)) {
			// input_one can only be one other thing
			if (r_str_contains_macro (input_one)) {
				r_str_truncate_cmd (input_one);
			}
			*asm_arch = r_asm_is_valid (core->assembler, input_one)? strdup (input_one): NULL;
		}
		result = true;
	}
	free (str_clone);
	return result;
}

/* This function is not necessary anymore, but it's kept for discussion */
R_API int r_core_process_input_pade(RCore *core, const char *input, char **hex, char **asm_arch, ut32 *bits) {
	// input: start of the input string e.g. after the command symbols have been consumed
	// size: hex if present, otherwise -1
	// asm_arch: asm_arch to interpret as if present and valid, otherwise NULL;
	// bits: bits to use if present, otherwise -1

	int result = false;
	char *input_one = NULL, *input_two = NULL, *input_three = NULL;
	char *str_clone = NULL,
	*trimmed_clone = NULL;

	if (!input || !hex || !asm_arch || !bits) {
		return false;
	}

	str_clone = strdup (input);
	trimmed_clone = r_str_trim_head_tail (str_clone);

	input_one = trimmed_clone;

#if 0
	char *ptr_str_clone = NULL;
	ptr_str_clone = strchr (trimmed_clone, ' ');
	// terminate input_one
	if (ptr_str_clone) {
		*ptr_str_clone = '\0';
		input_two = (++ptr_str_clone);
		ptr_str_clone = strchr (input_two, ' ');
	}

	// terminate input_two
	if (ptr_str_clone && input_two) {
		*ptr_str_clone = '\0';
		input_three = (++ptr_str_clone);
		ptr_str_clone = strchr (input_three, ' ');
	}

	// terminate input_three
	if (ptr_str_clone && input_three) {
		*ptr_str_clone = '\0';
		ptr_str_clone = strchr (input_three, ' ');
	}
#endif

	// command formats
	// <hex> <arch> <bits>
	// <hex> <arch>
	// <hex> <bits>
	// <hex>

	// initialize
	*hex = *asm_arch = NULL;
	*bits = -1;

	if (input_one && input_two && input_three) {
		// <size> <arch> <bits>
		*hex = input_one;
		*asm_arch = r_asm_is_valid (core->assembler, input_two)? strdup (input_two): NULL;
		*bits = r_num_get_input_value (core->num, input_three);
		result = true;

	} else if (input_one && input_two) {
		*hex = input_one;
		if (r_str_contains_macro (input_two)) {
			r_str_truncate_cmd (input_two);
		}
		*bits = r_num_is_valid_input (core->num, input_two)? r_num_get_input_value (core->num, input_two): -1;
		*asm_arch = r_asm_is_valid (core->assembler, input_two)? strdup (input_two): NULL;
		result = true;
	} else if (input_one) {
		*hex = input_one;
		result = true;
	} else {
		free (input_one);
	}
	return result;
}

static void helpCmdTasks(RCore *core) {
	// TODO: integrate with =h& and bg anal/string/searchs/..
	r_core_cmd_help (core, help_msg_amper);
}

static void print_format_help_help_help_help(RCore *core) {
	const char *help_msg[] = {
		"    STAHP IT!!!", "", "",
		NULL
	};
	r_core_cmd_help (core, help_msg);
}

static void cmd_print_format(RCore *core, const char *_input, const ut8* block, int len) {
	char *input;
	int mode = R_PRINT_MUSTSEE;
	switch (_input[1]) {
	case '*':
		_input++;
		mode = R_PRINT_SEEFLAGS;
		break;
	case 'd':
		_input++;
		mode = R_PRINT_DOT;
		break;
	case 'j':
		_input++;
		mode = R_PRINT_JSON;
		break;
	case 'v':
		_input++;
		mode = R_PRINT_VALUE | R_PRINT_MUSTSEE;
		break;
	case 's':
	{
		const char *val = NULL;
		_input += 2;
		if (*_input == '.') {
			_input++;
			val = sdb_get (core->print->formats, _input, NULL);
			if (val) {
				r_cons_printf ("%d\n", r_print_format_struct_size (val, core->print, mode, 0));
			} else {
				eprintf ("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') {
				_input++;
			}
			if (*_input) {
				r_cons_printf ("%d\n", r_print_format_struct_size (_input, core->print, mode, 0));
			} else {
				eprintf ("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else {
			eprintf ("Usage: pfs.struct_name | pfs format\n");
		}
	}
		return;
	case '?':
		_input += 2;
		if (*_input) {
			if (*_input == '?') {
				_input++;
				if (_input && *_input == '?') {
					_input++;
					if (_input && *_input == '?') {
						print_format_help_help_help_help (core);
					} else {
						r_core_cmd_help (core, help_detail2_pf);
					}
				} else {
					r_core_cmd_help (core, help_detail_pf);
				}
			} else {
				SdbListIter *iter;
				Sdb *sht = core->print->formats;
				SdbKv *kv;
				SdbList *sdbls = sdb_foreach_list (sht, false);
				ls_foreach (sdbls, iter, kv) {
					r_cons_println (kv->value);
				}
			}
		} else {
			r_core_cmd_help (core, help_msg_pf);
		}
		return;
	}

	input = strdup (_input);
	// "pfo" // open formatted thing
	if (input[1] == 'o') { // "pfo"
		if (input[2] == '?') {
			eprintf ("|Usage: pfo [format-file]\n"
				" ~/.config/radare2/format\n"
				" "R2_DATDIR "/radare2/"R2_VERSION "/format/\n");
		} else if (input[2] == ' ') {
			char *home, path[512];
			// XXX hardcoded path here
			snprintf (path, sizeof (path), ".config/radare2/format/%s", input + 3);
			home = r_str_home (path);
			snprintf (path, sizeof (path), R2_DATDIR "/radare2/"
				R2_VERSION "/format/%s", input + 3);
			if (!r_core_cmd_file (core, home) && !r_core_cmd_file (core, path)) {
				if (!r_core_cmd_file (core, input + 3)) {
					eprintf ("ecf: cannot open colorscheme profile (%s)\n", path);
				}
			}
			free (home);
		} else {
			RList *files;
			RListIter *iter;
			const char *fn;
			char *home = r_str_home (".config/radare2/format/");
			if (home) {
				files = r_sys_dir (home);
				r_list_foreach (files, iter, fn) {
					if (*fn && *fn != '.') {
						r_cons_println (fn);
					}
				}
				r_list_free (files);
				free (home);
			}
			files = r_sys_dir (R2_DATDIR "/radare2/"R2_VERSION "/format/");
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.') {
					r_cons_println (fn);
				}
			}
			r_list_free (files);
		}
		free (input);
		return;
	}
	/* syntax aliasing bridge for 'pf foo=xxd' -> 'pf.foo xxd' */
	if (input[1] == ' ') {
		char *eq = strchr (input + 2, '=');
		if (eq) {
			input[1] = '.';
			*eq = ' ';
		}
	}

	int listFormats = 0;
	if (input[1] == '.') {
		listFormats = 1;
	}
	if (!strcmp (input, "*") && mode == R_PRINT_SEEFLAGS) {
		listFormats = 1;
	}

	core->print->reg = core->dbg->reg;
	core->print->get_register = r_reg_get;
	core->print->get_register_value = r_reg_get_value;

	int o_blocksize = core->blocksize;

	if (listFormats) {
		core->print->num = core->num;
		/* print all stored format */
		if (!input[1] || !input[2]) {
			SdbListIter *iter;
			SdbKv *kv;
			SdbList *sdbls = sdb_foreach_list (core->print->formats, false);
			ls_foreach (sdbls, iter, kv) {
				r_cons_printf ("pf.%s %s\n", kv->key, kv->value);
			}
			/* delete a format */
		} else if (input[1] && input[2] == '-') {
			if (input[3] == '*') {
				sdb_free (core->print->formats);
				core->print->formats = sdb_new0 ();
			} else {
				sdb_unset (core->print->formats, input + 3, 0);
			}
		} else {
			char *name = strdup (input + (input[1]? 2: 1));
			char *space = strchr (name, ' ');
			char *eq = strchr (name, '=');
			char *dot = strchr (name, '.');

			if (eq && !dot) {
				*eq = ' ';
				space = eq;
				eq = NULL;
			}

			/* store a new format */
			if (space && (!eq || space < eq)) {
				// char *fields = NULL;
				*space++ = 0;
				// fields = strchr (space, ' ');
				if (strchr (name, '.')) {// || (fields != NULL && strchr(fields, '.') != NULL)) // if anon struct, then field can have '.'
					eprintf ("Struct or fields name can not contain dot symbol (.)\n");
				} else {
					sdb_set (core->print->formats, name, space, 0);
				}
				free (name);
				free (input);
				return;
			}

			if (!strchr (name, '.') &&
			!sdb_get (core->print->formats, name, NULL)) {
				eprintf ("Cannot find '%s' format.\n", name);
				free (name);
				free (input);
				return;
			}

			/* Load format from name into fmt to get the size */
			/* This make sure the whole structure will be printed */
			const char *fmt = NULL;
			fmt = sdb_get (core->print->formats, name, NULL);
			if (fmt) {
				int size = r_print_format_struct_size (fmt, core->print, mode, 0) + 10;
				if (size > core->blocksize) {
					r_core_block_size (core, size);
				}
			}
			/* display a format */
			if (dot) {
				*dot++ = 0;
				eq = strchr (dot, '=');
				if (eq) { // Write mode (pf.field=value)
					*eq++ = 0;
					mode = R_PRINT_MUSTSET;
					r_print_format (core->print, core->offset,
						block, core->blocksize, name, mode, eq, dot);
				} else {
					r_print_format (core->print, core->offset,
						block, core->blocksize, name, mode, NULL, dot);
				}
			} else {
				r_print_format (core->print, core->offset,
					block, core->blocksize, name, mode, NULL, NULL);
			}
			free (name);
		}
	} else {
		/* This make sure the structure will be printed entirely */
		char *fmt = input + 1;
		while (*fmt && ISWHITECHAR (*fmt)) fmt++;
		int size = r_print_format_struct_size (fmt, core->print, mode, 0) + 10;
		if (size > core->blocksize) {
			r_core_block_size (core, size);
		}
		/* check if fmt is '\d+ \d+<...>', common mistake due to usage string*/
		bool syntax_ok = true;
		char *args = strdup (fmt);
		if (!args) {
			r_cons_printf ("Error: Mem Allocation.");
			free (args);
			goto stage_left;
		}
		const char *arg1 = strtok (args, " ");
		if (arg1 && r_str_isnumber (arg1)) {
			syntax_ok = false;
			r_cons_printf ("Usage: pf [0|cnt][format-string]\n");
		}
		free (args);
		if (syntax_ok) {
			r_print_format (core->print, core->offset,
				core->block, core->blocksize, fmt, mode, NULL, NULL);
		}
	}
stage_left:
	free (input);
	r_core_block_size (core, o_blocksize);
}

// > pxa
/* In this function, most of the buffers have 4 times
 * the required length. This is because we supports colours,
 * that are 4 chars long. */
#define append(x, y) { strcat (x, y); x += strlen (y); }
static void annotated_hexdump(RCore *core, const char *str, int len) {
	const int usecolor = r_config_get_i (core->config, "scr.color");
	int nb_cols = r_config_get_i (core->config, "hex.cols");
	core->print->use_comments = r_config_get_i (core->config, "hex.comments");
	int flagsz = r_config_get_i (core->config, "hex.flagsz");
	const ut8 *buf = core->block;
	ut64 addr = core->offset;
	int color_idx = 0;
	char *bytes, *chars;
	char *ebytes, *echars; // They'll walk over the vars above
	ut64 fend = UT64_MAX;
	char *comment;
	int i, j, low, max, here, rows;
	bool marks = false, setcolor = true, hascolor = false;
	ut8 ch;
	char *colors[10] = {NULL};
	for (i = 0; i < 10; i++) {
		colors[i] = r_cons_rainbow_get (i, 10, false);
	}
	const int col = core->print->col;
	RFlagItem *flag, *current_flag = NULL;
	char **note;
	int html = r_config_get_i (core->config, "scr.html");
	int nb_cons_cols;
	bool compact = false;

	if (core->print) {
		compact = core->print->flags & R_PRINT_FLAGS_COMPACT;
	}
	char *format = compact ? " %X %X" : " %X %X ";
	int step = compact ? 4 : 5;
	
	// Adjust the number of columns
	if (nb_cols < 1) {
		nb_cols = 16;
	}
	nb_cols -= (nb_cols % 2); // nb_cols should be even

	nb_cons_cols = 12 + nb_cols * 2 + (nb_cols / 2);
	nb_cons_cols += 17;
	rows = len / nb_cols;

	chars = calloc (nb_cols * 20, sizeof (char));
	if (!chars) goto err_chars;
	note = calloc (nb_cols, sizeof (char *));
	if (!note) goto err_note;
	bytes = calloc (nb_cons_cols * 20, sizeof (char));
	if (!bytes) goto err_bytes;
#if 1
	int addrpadlen = strlen (sdb_fmt (0, "%08"PFMT64x, addr)) - 8;
	char addrpad[32];
	if (addrpadlen > 0) {
		memset (addrpad, ' ', addrpadlen);
		addrpad[addrpadlen] = 0;

		// Compute, then show the legend
		strcpy (bytes, addrpad);
	} else {
		*addrpad = 0;
		addrpadlen = 0;
	}
	strcpy (bytes + addrpadlen, "- offset -  ");
#endif
	j = strlen (bytes);
	for (i = 0; i < nb_cols; i += 2) {
		sprintf (bytes + j, format, (i & 0xf), (i + 1) & 0xf);
		j += step;
	}
	sprintf (bytes + j + i, " ");
	j++;
	for (i = 0; i < nb_cols; i++) {
		sprintf (bytes + j + i, "%0X", i % 17);
	}
	if (usecolor) {
		r_cons_strcat (Color_GREEN);
	}
	r_cons_strcat (bytes);
	if (usecolor) {
		r_cons_strcat (Color_RESET);
	}
	r_cons_newline ();

	// hexdump
	for (i = 0; i < rows; i++) {
		bytes[0] = '\0';
		chars[0] = '\0';
		ebytes = bytes;
		echars = chars;
		hascolor = false;

		if (usecolor) {
			append (ebytes, core->cons->pal.offset);
		}
		ebytes += sprintf (ebytes, "0x%08"PFMT64x, addr);
		if (usecolor) {
			append (ebytes, Color_RESET);
		}
		append (ebytes, (col == 1)? " |": "  ");

		for (j = 0; j < nb_cols; j++) {
			setcolor = true;
			free (note[j]);
			note[j] = NULL;

			// collect comments
			comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr + j);
			if (comment) {
				comment = r_str_prefix (comment, ";");
				note[j] = comment;
				marks = true;
			}

			// collect flags
			flag = r_flag_get_i (core->flags, addr + j);
			if (flag) { // Beginning of a flag
				if (flagsz) {
					fend = addr + flagsz; // core->blocksize;
				} else {
					fend = addr + j + flag->size;
				}
				note[j] = r_str_prefix (strdup (flag->name), "/");
				marks = true;
				color_idx++;
				color_idx %= 10;
				current_flag = flag;
			} else {
				// Are we past the current flag?
				if (current_flag && addr + j > (current_flag->offset + current_flag->size)) {
					setcolor = false;
					current_flag = NULL;
				}
				// Turn colour off if we're at the end of the current flag
				if (fend == UT64_MAX || fend <= addr + j) {
					setcolor = false;
				}
			}
			if (setcolor && !hascolor) {
				hascolor = true;
				if (usecolor) {
					if (current_flag && current_flag->color) {
						char *ansicolor = r_cons_pal_parse (current_flag->color, NULL);
						append (ebytes, ansicolor);
						append (echars, ansicolor);
						free (ansicolor);
					} else { // Use "random" colours
						append (ebytes, colors[color_idx]);
						append (echars, colors[color_idx]);
					}
				} else {
					if (html) {
						append (ebytes, "[");
					} else {
						append (ebytes, Color_INVERT);
					}
				}
			}
			here = R_MIN ((i * nb_cols) + j, core->blocksize);
			ch = buf[here];
			if (core->print->ocur != -1) {
				low = R_MIN (core->print->cur, core->print->ocur);
				max = R_MAX (core->print->cur, core->print->ocur);
			} else {
				low = max = core->print->cur;
			}
			if (core->print->cur_enabled) {
				if (low == max) {
					if (low == here) {
						if (html) {
							append (ebytes, "[");
							append (echars, "[");
						} else {
							append (echars, Color_INVERT);
							append (ebytes, Color_INVERT);
						}
					}
				} else {
					if (here >= low && here < max) {
						if (html) {
							append (ebytes, "[");
							append (echars, "[");
						} else {
							append (ebytes, Color_INVERT);
							append (echars, Color_INVERT);
						}
					}
				}
			}
			sprintf (ebytes, "%02x", ch);
			ebytes += strlen (ebytes);
			sprintf (echars, "%c", IS_PRINTABLE (ch)? ch: '.');
			echars++;
			if (core->print->cur_enabled && max == here) {
				if (!html) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				hascolor = false;
			}

			if (j < (nb_cols - 1) && (j % 2) && !compact) {
				append (ebytes, " ");
			}

			if (fend != UT64_MAX && fend == addr + j + 1) {
				if (!html) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				fend = UT64_MAX;
				hascolor = false;
			}

		}
		if (!html) {
			append (ebytes, Color_RESET);
			append (echars, Color_RESET);
		}
		append (ebytes, (col == 1)? "| ": (col == 2)? " |": "  ");
		if (col == 2) {
			append (echars, "|");
		}

		if (marks) { // show comments and flags
			int hasline = 0;
			int out_sz = nb_cons_cols + 20;
			char *out = calloc (out_sz, sizeof(char));
			memset (out, ' ', nb_cons_cols - 1);
			for (j = 0; j < nb_cols; j++) {
				if (note[j]) {
					int off = (j * 3) - (j / 2) + 13;
					int notej_len = strlen (note[j]);
					int sz = R_MIN (notej_len, nb_cons_cols - off);
					if (j % 2) {
						off--;
					}
					memcpy (out + off, note[j], sz);
					if (sz < notej_len) {
						out[off + sz - 2] = '.';
						out[off + sz - 1] = '.';
					}
					hasline = (out[off] != ' ');
					R_FREE (note[j]);
				}
			}
			out[out_sz - 1] = 0;
			if (hasline) {
				r_cons_strcat (addrpad);
				r_cons_strcat (out);
				r_cons_newline ();
			}
			marks = false;
			free (out);
		}
		r_cons_strcat (bytes);
		r_cons_strcat (chars);


		if (core->print->use_comments) {
			for (j = 0; j < nb_cols; j++) {
				const char *comment = core->print->get_comments (core->print->user, addr + j);
				if (comment) {
					r_cons_printf (" ; %s", comment);
				}
			}
		}

		r_cons_newline ();
		addr += nb_cols;
	}

	free (bytes);
 err_bytes:
	free (note);
 err_note:
	free (chars);
 err_chars:
	for (i = 0; i < R_ARRAY_SIZE (colors); i++) {
		free (colors[i]);
	}
}

R_API void r_core_print_examine(RCore *core, const char *str) {
	char cmd[128], *p;
	ut64 addr = core->offset;
	int size = (core->anal->bits / 4);
	int count = atoi (str);
	int i, n;
	if (count < 1) {
		count = 1;
	}
	// skipspaces
	while (*str >= '0' && *str <= '9') {
		str++;
	}
	// "px/" alone isn't a full command.
	if (!str[0]) {
		return;
	}
#if 0
	Size letters are b(byte), h (halfword), w (word), g (giant, 8 bytes).
#endif
	switch (str[1]) {
	case 'b': size = 1; break;
	case 'h': size = 2; break;
	case 'd': size = 4; break;
	case 'w': size = 4; break;
	case 'g': size = 8; break;
	}
	if ((p = strchr (str, ' '))) {
		*p++ = 0;
		addr = r_num_math (core->num, p);
	}
	switch (*str) {
	case '?':
		eprintf (
			"Format is x/[num][format][size]\n"
			"Num specifies the number of format elements to display\n"
			"Format letters are o(octal), x(hex), d(decimal), u(unsigned decimal),\n"
			"  t(binary), f(float), a(address), i(instruction), c(char) and s(string),\n"
			"  T(OSType), A(floating point values in hex).\n"
			"Size letters are b(byte), h(halfword), w(word), g(giant, 8 bytes).\n"
			);
		break;
	case 's': // "x/s"
		r_core_cmdf (core, "psb %d @ 0x%"PFMT64x, count * size, addr);
		break;
	case 'o': // "x/o"
		r_core_cmdf (core, "pxo %d @ 0x%"PFMT64x, count * size, addr);
		break;
	case 'f':
	case 'A': // XXX (float in hex wtf)
		n = 3;
		snprintf (cmd, sizeof (cmd), "pxo %d @ 0x%"PFMT64x,
			count * size, addr);
		strcpy (cmd, "pf ");
		for (i = 0; i < count && n < sizeof (cmd); i++) {
			cmd[n++] = 'f';
		}
		cmd[n] = 0;
		r_core_cmd0 (core, cmd);
		break;
	case 'x':
		switch (size) {
		default:
		case 1:
			r_core_cmdf (core, "px %d @ 0x%"PFMT64x, count, addr);
			break;
		case 2:
			r_core_cmdf (core, "px%c %d @ 0x%"PFMT64x,
				'h', count * 2, addr);
			break;
		case 4:
			r_core_cmdf (core, "px%c %d @ 0x%"PFMT64x,
				'w', count * 4, addr);
			break;
		case 8:
			r_core_cmdf (core, "px%c %d @ 0x%"PFMT64x,
				'q', count * 8, addr);
			break;
		}
		break;
	case 'a':
	case 'd':
		r_core_cmdf (core, "pxw %d @ 0x%"PFMT64x, count * size, addr);
		break;
	case 'i':
		r_core_cmdf (core, "pid %d @ 0x%"PFMT64x, count, addr);
		break;
	}
}

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size) {
	RCore *core = (RCore *) user;
	int j, ret = 0;
	RListIter *iter;
	RFlagItem *flag;

	switch (mode) {
	case 'p':
		for (j = 0; j < size; j++) {
			if (IS_PRINTABLE (bufz[j])) {
				ret++;
			}
		}
		break;
	case 'f':
		r_list_foreach (core->flags->flags, iter, flag)
		if (flag->offset <= addr && addr < flag->offset + flag->size) {
			ret++;
		}
		break;
	case 's':
		j = r_flag_space_get (core->flags, "strings");
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->space == j &&
			    ((addr <= flag->offset &&
			      flag->offset < addr + size) ||
			     (addr <= flag->offset + flag->size &&
			      flag->offset + flag->size < addr + size))) {
				ret++;
			}
		}
		break;
	case '0': // 0x00
		for (j = 0; j < size; j++) {
			if (bufz[j] == 0) {
				ret++;
			}
		}
		break;
	case 'F': // 0xFF
		for (j = 0; j < size; j++) {
			if (bufz[j] == 0xff) {
				ret++;
			}
		}
		break;
	case 'e': // entropy
		ret = (ut8) (r_hash_entropy_fraction (bufz, size) * 255);
		break;
	case 'h': // head
	default:
		ret = *bufz;
	}
	return ret;
}

R_API void r_core_print_cmp(RCore *core, ut64 from, ut64 to) {
	long int delta = 0;
	int col = core->cons->columns > 123;
	ut8 *b = malloc (core->blocksize);
	ut64 addr = core->offset;
	memset (b, 0xff, core->blocksize);
	delta = addr - from;
	r_core_read_at (core, to + delta, b, core->blocksize);
	r_print_hexdiff (core->print, core->offset, core->block,
		to + delta, b, core->blocksize, col);
	free (b);
}

static void cmd_print_pwn(const RCore *core) {
	r_cons_printf ("easter egg license has expired\n");
}

static int cmd_print_pxA(RCore *core, int len, const char *data) {
	RConsPrintablePalette *pal = &core->cons->pal;
	int show_offset = true;
	int cols = r_config_get_i (core->config, "hex.cols");
	int show_color = r_config_get_i (core->config, "scr.color");
	int onechar = r_config_get_i (core->config, "hex.onechar");
	int bgcolor_in_heap = false;
	bool show_cursor = core->print->cur_enabled;
	char buf[2];
	char *bgcolor, *fgcolor, *text;
	ut64 i, c, oi;
	RAnalOp op;

	if (len < 0 || len > core->blocksize) {
		eprintf ("Invalid length\n");
		return 0;
	}
	if (onechar) {
		cols *= 4;
	} else {
		cols *= 2;
	}
	if (show_offset) {
		char offstr[128];
		snprintf (offstr, sizeof (offstr),
			"0x%08"PFMT64x "  ", core->offset);
		if (strlen (offstr) > 12) {
			cols -= ((strlen (offstr) - 12) * 2);
		}
	}
	for (oi = i = c = 0; i < len; c++) {
		if (i && (cols != 0) && !(c % cols)) {
			show_offset = true;
			r_cons_printf ("  %d\n", i - oi);
			oi = i;
		}
		if (show_offset) {
			r_cons_printf ("0x%08"PFMT64x "  ", core->offset + i);
			show_offset = false;
		}
		if (bgcolor_in_heap) {
			free (bgcolor);
			bgcolor_in_heap = false;
		}
		bgcolor = Color_BGBLACK;
		fgcolor = Color_WHITE;
		text = NULL;
		if (r_anal_op (core->anal, &op, core->offset + i, core->block + i, len - i) <= 0) {
			op.type = 0;
			bgcolor = Color_BGRED;
			op.size = 1;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_LEA:
		case R_ANAL_OP_TYPE_MOV:
		case R_ANAL_OP_TYPE_CAST:
		case R_ANAL_OP_TYPE_LENGTH:
		case R_ANAL_OP_TYPE_CMOV:
			text = "mv";
			bgcolor = pal->mov;
			fgcolor = Color_YELLOW;
			break;
		case R_ANAL_OP_TYPE_PUSH:
		case R_ANAL_OP_TYPE_UPUSH:
			bgcolor = pal->push;
			fgcolor = Color_WHITE;
			text = "->";
			break;
		case R_ANAL_OP_TYPE_IO:
			bgcolor = pal->swi;
			fgcolor = Color_WHITE;
			text = "io";
			break;
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_SWI:
		case R_ANAL_OP_TYPE_NEW:
			// bgcolor = Color_BGRED;
			bgcolor = pal->trap; // r_cons_swap_ground (pal->trap);
			fgcolor = Color_WHITE;
			text = "$$";
			break;
		case R_ANAL_OP_TYPE_POP:
			text = "<-";
			bgcolor = r_cons_swap_ground (pal->pop);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			break;
		case R_ANAL_OP_TYPE_NOP:
			fgcolor = Color_WHITE;
			bgcolor = r_cons_swap_ground (pal->nop);
			bgcolor_in_heap = true;
			text = "..";
			break;
		case R_ANAL_OP_TYPE_MUL:
			fgcolor = Color_BLACK;
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			text = "_*";
			break;
		case R_ANAL_OP_TYPE_DIV:
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_/";
			break;
		case R_ANAL_OP_TYPE_AND:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_&";
			break;
		case R_ANAL_OP_TYPE_XOR:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_^";
			break;
		case R_ANAL_OP_TYPE_OR:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_|";
			break;
		case R_ANAL_OP_TYPE_SHR:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = ">>";
			break;
		case R_ANAL_OP_TYPE_SHL:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "<<";
			break;
		case R_ANAL_OP_TYPE_SUB:
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "--";
			break;
		case R_ANAL_OP_TYPE_ADD:
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "++";
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_IRJMP:
		case R_ANAL_OP_TYPE_MJMP:
			bgcolor = r_cons_swap_ground (pal->jmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_J";
			break;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_UCJMP:
			bgcolor = r_cons_swap_ground (pal->cjmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "cJ";
			break;
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_IRCALL:
		case R_ANAL_OP_TYPE_UCCALL:
			bgcolor = r_cons_swap_ground (pal->call);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "_C";
			break;
		case R_ANAL_OP_TYPE_ACMP:
		case R_ANAL_OP_TYPE_CMP:
			bgcolor = r_cons_swap_ground (pal->cmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "==";
			break;
		case R_ANAL_OP_TYPE_RET:
			bgcolor = r_cons_swap_ground (pal->ret);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "_R";
			break;
		case -1:
		case R_ANAL_OP_TYPE_ILL:
		case R_ANAL_OP_TYPE_UNK:
			bgcolor = r_cons_swap_ground (pal->invalid);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "XX";
			break;
#if 0
		default:
			color = Color_BGCYAN;
			fgcolor = Color_BLACK;
			break;
#endif
		}
		int opsz = R_MAX (op.size, 1);
		if (show_cursor) {
			if (core->print->cur >= i && core->print->cur < i + opsz) {
				r_cons_invert (1, 1);
			}
		}
		if (onechar) {
			if (text) {
				if (text[0] == '_' || text[0] == '.') {
					buf[0] = text[1];
				} else {
					buf[0] = text[0];
				}
			} else {
				buf[0] = '.';
			}
			buf[1] = 0;
			text = buf;
		}
		if (show_color) {
			if (!text) {
				text = "  ";
			}
			r_cons_printf ("%s%s%s\x1b[0m", bgcolor, fgcolor, text);
		} else {
			if (text) {
				r_cons_print (text);
			} else {
				r_cons_print ("  ");
			}
		}
		if (show_cursor) {
			if (core->print->cur >= i && core->print->cur < i + opsz) {
				r_cons_invert (0, 1);
			}
		}
		i += opsz;
		r_anal_op_fini (&op);
	}
	r_cons_printf ("  %d\n", i - oi);
	if (bgcolor_in_heap) {
		free (bgcolor);
	}

	return true;
}

static void printraw(RCore *core, int len, int mode) {
	int obsz = core->blocksize;
	int restore_obsz = 0;
	if (len != obsz) {
		if (!r_core_block_size (core, len)) {
			len = core->blocksize;
		} else {
			restore_obsz = 1;
		}
	}
	r_print_raw (core->print, core->offset, core->block, len, mode);
	if (restore_obsz) {
		(void) r_core_block_size (core, obsz);
	}
	core->cons->newline = true;
}


static void _handle_call(RCore *core, char *line, char **str) {
	if (!core || !core->assembler || !core->assembler->cur) {
		*str = NULL;
		return;
	}
	if (strstr (core->assembler->cur->arch, "x86")) {
		*str = strstr (line, "call ");
	} else if (strstr (core->assembler->cur->arch, "arm")) {
		*str = strstr (line, " b ");
		if (*str && strstr (*str, " 0x")) {
			/*
			* avoid treating branches to
			* non-symbols as calls
			*/
			*str = NULL;
		}
		if (!*str) {
			*str = strstr (line, "bl ");
		}
		if (!*str) {
			*str = strstr (line, "bx ");
		}
	}
}

// TODO: this is just a PoC, the disasm loop should be rewritten
// TODO: this is based on string matching, it should be written upon RAnalOp to know
// when we have a call and such
static void disasm_strings(RCore *core, const char *input, RAnalFunction *fcn) {
	const char *linecolor = NULL;
	char *ox, *qo, *string = NULL;
	char *line, *s, *str, *string2 = NULL;
	int i, count, use_color = r_config_get_i (core->config, "scr.color");
	bool show_comments = r_config_get_i (core->config, "asm.comments");
	bool show_offset = r_config_get_i (core->config, "asm.offset");
	bool asm_tabs = r_config_get_i (core->config, "asm.tabs");
	bool asm_flags = r_config_get_i (core->config, "asm.flags");
	bool asm_cmt_right = r_config_get_i (core->config, "asm.cmt.right");
	bool asm_emustr = r_config_get_i (core->config, "asm.emu.str");
	r_config_set_i (core->config, "asm.emu.str", true);
	RConsPrintablePalette *pal = &core->cons->pal;
	// force defaults
	r_config_set_i (core->config, "asm.offset", true);
	r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	r_config_set_i (core->config, "asm.tabs", 0);
	r_config_set_i (core->config, "asm.cmt.right", true);
r_cons_push();
	if (!strncmp (input, "dsf", 3) || !strncmp (input, "dsr", 3)) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
		if (fcn) {
			line = s = r_core_cmd_str (core, "pdr");
		} else {
			eprintf ("Cannot find function.\n");
			r_config_set_i (core->config, "scr.color", use_color);
			r_config_set_i (core->config, "asm.cmt.right", asm_cmt_right);
			goto restore_conf;
		}
	} else if (!strncmp (input, "ds ", 3)) {
		char *cmd = r_str_newf ("pD %s", input + 3);
		line = s = r_core_cmd_strf (core, cmd);
		free (cmd);
	} else {
		line = s = r_core_cmd_str (core, "pd");
	}
r_cons_pop();
	r_config_set_i (core->config, "scr.color", use_color);
	r_config_set_i (core->config, "asm.cmt.right", asm_cmt_right);
	count = r_str_split (s, '\n');
	if (!line || !*line || count < 1) {
		free (s);
		goto restore_conf;
	}
	for (i = 0; i < count; i++) {
		ut64 addr = UT64_MAX;
		ox = strstr (line, "0x");
		qo = strstr (line, "\"");
		R_FREE (string);
		if (ox) {
			addr = r_num_get (NULL, ox);
		}
		if (qo) {
			char *qoe = strrchr (qo + 1, '"');
			if (qoe) {
				int raw_len = qoe - qo - 1;
				int actual_len = 0;
				char *ptr = qo + 1;
				for(; ptr < qoe; ptr++) {
					if (*ptr == '\\' && ptr + 1 < qoe) {
						int i, body_len;
						switch (*(ptr + 1)) {
						case 'x':
							body_len = 3;
							break;
						case 'u':
							body_len = 5;
							break;
						case 'U':
							body_len = 9;
							break;
						default:
							body_len = 1;
						}
						for (i = 0; i < body_len && ptr < qoe; i++) {
							ptr++;
						}
					}
					actual_len++;
				}
				if (actual_len > 2) {
					string = r_str_ndup (qo, raw_len + 2);
				}
				linecolor = R_CONS_COLOR (comment);
			}
		}
		ox = strstr (line, "; 0x");
		if (!ox) {
			ox = strstr (line, "@ 0x");
		}
		if (ox) {
			char *qoe = strchr (ox + 3, ' ');
			if (!qoe) {
				qoe = strchr (ox + 3, '\x1b');
			}
			int len = qoe? qoe - ox: strlen (ox + 3);
			string2 = r_str_ndup (ox + 2, len - 1);
			if (r_num_get (NULL, string2) < 0x100) {
				R_FREE (string2);
			}
		}
		if (asm_flags) {
			str = strstr (line, ";-- ");
			if (str) {
				r_cons_printf ("%s\n", str);
			}
		}
		// XXX leak
		str = strstr (line, " str.");
		if (str) {
			str = strdup (str);
			char *qoe = NULL;
			if (!qoe) {
				qoe = strchr (str + 1, '\x1b');
			}
			if (!qoe) {
				qoe = strchr (str + 1, ';');
			}
			if (!qoe) {
				qoe = strchr (str + 1, ' ');
			}
			if (qoe) {
				free (string2);
				string2 = r_str_ndup (str + 1, qoe - str - 1);
			} else {
				free (string2);
				string2 = strdup (str + 1);
			}
			if (string2) {
				R_FREE (string);
				string = string2;
				string2 = NULL;
			}
		}
		R_FREE (string2);
		_handle_call (core, line, &str);
		if (!str) {
			str = strstr (line, "sym.");
			if (!str) {
				str = strstr (line, "fcn.");
			}
		}
		if (str) {
			str = strdup (str);
			char *qoe = strstr (str, ";");
			if (qoe) {
				char* t = str;
				str = r_str_ndup (str, qoe - str);
				free (t);
			}
		}
		if (str) {
			string2 = strdup (str);
			linecolor = R_CONS_COLOR (call);
		}
		if (!string && string2) {
			string = string2;
			string2 = NULL;
		}
		if (strstr (line, "XREF")) {
			addr = UT64_MAX;
		}
		if (addr != UT64_MAX) {
			const char *str = NULL;
			if (show_comments) {
				char *comment = r_core_anal_get_comments (core, addr);
				if (comment) {
					if (show_offset) {
						r_cons_printf ("%s0x%08"PFMT64x" ", use_color? pal->offset: "", addr);
					}
					r_cons_printf ("%s%s\n", use_color? pal->comment: "", comment);
					R_FREE (comment);
				}
			}

			if (fcn) {
				bool label = false;
				/* show labels, basic blocks and (conditional) branches */
				RAnalBlock *bb;
				RListIter *iter;
				r_list_foreach (fcn->bbs, iter, bb) {
					if (addr == bb->jump) {
						if (show_offset) {
							r_cons_printf ("%s0x%08"PFMT64x ":\n", use_color? Color_YELLOW: "", addr);
						}
						label = true;
						break;
					}
				}
				if (!label && strstr (line, "->")) {
					r_cons_printf ("%s0x%08"PFMT64x ":\n", use_color? Color_YELLOW: "", addr);
				}
				if (strstr (line, "=<")) {
					r_list_foreach (fcn->bbs, iter, bb) {
						if (addr >= bb->addr && addr < bb->addr + bb->size) {
							const char *op;
							if (use_color) {
								op = (bb->fail == UT64_MAX)? Color_GREEN "jmp": "cjmp";
							} else {
								op = (bb->fail == UT64_MAX)? "jmp": "cjmp";
							}
							if (show_offset) {
								r_cons_printf ("%s0x%08"PFMT64x" "Color_RESET, use_color? pal->offset: "", addr);
							}
							r_cons_printf ("%s 0x%08"PFMT64x "%s\n",
								op, bb->jump, use_color? Color_RESET: "");
							break;
						}
					}
				}
			}
			if (string && *string) {
				if (string && !strncmp (string, "0x", 2)) {
					str = string;
				}
				if (string2 && !strncmp (string2, "0x", 2)) {
					str = string2;
				}
				ut64 ptr = r_num_math (NULL, str);
				RFlagItem *flag = NULL;
				if (str) {
					flag = r_flag_get_i2 (core->flags, ptr);
				}
				if (!flag) {
					if (string && !strncmp (string, "0x", 2)) {
						R_FREE (string);
					}
					if (string2 && !strncmp (string2, "0x", 2)) {
						R_FREE (string2);
					}
				}
				if (string) {
					string = r_str_trim (string);
					string2 = r_str_trim (string2);
					//// TODO implememnt avoid duplicated strings
					// eprintf ("---> %s\n", string);
					if (use_color) {
						if (show_offset) {
							r_cons_printf ("%s0x%08"PFMT64x" "Color_RESET, use_color? pal->offset: "", addr);
						}
						r_cons_printf ("%s%s%s%s%s%s%s\n",
							linecolor? linecolor: "",
							string2? string2: "", string2? " ": "", string,
							flag? " ": "", flag? flag->name: "", Color_RESET);
					} else {
						if (show_offset) {
							r_cons_printf ("0x%08"PFMT64x" ", addr);
						}
						r_cons_printf ("%s%s%s%s%s\n", 
							string2? string2: "", string2? " ": "", string,
							flag? " ": "", flag? flag->name: "");
					}
				}
			}
		}
		line += strlen (line) + 1;
	}
	// r_cons_printf ("%s", s);
	free (string2);
	free (string);
	free (s);
	free (str);
restore_conf:
	r_config_set_i (core->config, "asm.offset", show_offset);
	r_config_set_i (core->config, "asm.tabs", asm_tabs);
	r_config_set_i (core->config, "asm.emu.str", asm_emustr);
}

static void algolist(int mode) {
	int i;
	for (i = 0; i < R_HASH_NBITS; i++) {
		ut64 bits = 1ULL << i;
		const char *name = r_hash_name (bits);
		if (name && *name) {
			if (mode) {
				r_cons_println (name);
			} else {
				r_cons_printf ("%s ", name);
			}
		}
	}
	if (!mode) {
		r_cons_newline ();
	}
}

static bool cmd_print_ph(RCore *core, const char *input) {
	char algo[128];
	ut32 osize = 0, len = core->blocksize;
	const char *ptr;
	int pos = 0, handled_cmd = false;

	if (!*input || *input == '?') {
		algolist (1);
		return true;
	}
	if (*input == '=') {
		algolist (0);
		return true;
	}
	input = r_str_trim_ro (input);
	ptr = strchr (input, ' ');
	sscanf (input, "%31s", algo);
	if (ptr && ptr[1]) { // && r_num_is_valid_input (core->num, ptr + 1)) {
		int nlen = r_num_math (core->num, ptr + 1);
		if (nlen > 0) {
			len = nlen;
		}
		osize = core->blocksize;
		if (nlen > core->blocksize) {
			r_core_block_size (core, nlen);
			if (nlen != core->blocksize) {
				eprintf ("Invalid block size\n");
				r_core_block_size (core, osize);
				return false;
			}
			r_core_block_read (core);
		}
	} else if (!ptr || !*(ptr + 1)) {
		osize = len;
	}
	/* TODO: Simplify this spaguetti monster */
	while (osize > 0 && hash_handlers[pos].name) {
		if (!r_str_ccmp (hash_handlers[pos].name, input, ' ')) {
			hash_handlers[pos].handler (core->block, len);
			handled_cmd = true;
			break;
		}
		pos++;
	}
	if (osize) {
		r_core_block_size (core, osize);
	}
	return handled_cmd;
}

static void cmd_print_pv(RCore *core, const char *input, const ut8* block) {
	const char *stack[] = {
		"ret", "arg0", "arg1", "arg2", "arg3", "arg4", NULL
	};
	int i, n = core->assembler->bits / 8;
	int type = 'v';
	bool fixed_size = true;
	switch (input[0]) {
	case '1':
		n = 1;
		input++;
		break;
	case '2':
		n = 2;
		input++;
		break;
	case '4':
		n = 4;
		input++;
		break;
	case '8':
		n = 8;
		input++;
		break;
	default:
		fixed_size = false;
		break;
	}
	// variables can be
	switch (input[0]) {
	case 'z': // "pvz"
		type = 'z';
		if (input[1]) {
			input++;
		} else {
			r_core_cmdf (core, "ps");
			break;
		}
	/* fallthrough */
	case ' ':
		for (i = 0; stack[i]; i++) {
			if (!strcmp (input + 1, stack[i])) {
				if (type == 'z') {
					r_core_cmdf (core, "ps @ [`drn sp`+%d]", n * i);
				} else {
					r_core_cmdf (core, "?v [`drn sp`+%d]", n * i);
				}
			}
		}
		break;
	case 'j':
	{
		char *str = r_str_trim (r_core_cmd_str (core, "ps @ [$$]"));
		char *p = str;
		if (p) {
			while (*p) {
				if (*p == '\\' && p[1] == 'x') {
					memmove (p, p + 4, strlen (p + 4) + 1);
				}
			}
		}
		// r_num_get is gonna use a dangling pointer since the internal
		// token that RNum holds ([$$]) has been already freed by r_core_cmd_str
		// r_num_math reload a new token so the dangling pointer is gone
		r_cons_printf ("{\"value\":%"PFMT64d ",\"string\":\"%s\"}\n",
			r_num_math (core->num, "[$$]"),
			str
			);
		free (str);
	}
	break;
	case '?':
		r_core_cmd_help (core, help_msg_pv);
		break;
	default:
	{
		ut64 v;
		if (!fixed_size) {
			n = 0;
		}
		switch (n) {
		case 1:
			v = r_read_ble8 (block);
			r_cons_printf ("0x%02" PFMT64x "\n", v);
			break;
		case 2:
			v = r_read_ble16 (block, core->print->big_endian);
			r_cons_printf ("0x%04" PFMT64x "\n", v);
			break;
		case 4:
			v = r_read_ble32 (block, core->print->big_endian);
			r_cons_printf ("0x%08" PFMT64x "\n", v);
			break;
		case 8:
			v = r_read_ble64 (block, core->print->big_endian);
			r_cons_printf ("0x%016" PFMT64x "\n", v);
			break;
		default:
			v = r_read_ble64 (block, core->print->big_endian);
			switch (core->assembler->bits / 8) {
			case 1: r_cons_printf ("0x%02" PFMT64x "\n", v & UT8_MAX); break;
			case 2: r_cons_printf ("0x%04" PFMT64x "\n", v & UT16_MAX); break;
			case 4: r_cons_printf ("0x%08" PFMT64x "\n", v & UT32_MAX); break;
			case 8: r_cons_printf ("0x%016" PFMT64x "\n", v & UT64_MAX); break;
			default: break;
			}
			break;
		}
	}
		// r_core_cmd0 (core, "?v [$$]");
	break;
	}
}


static bool checkAnalType(RAnalOp *op, int t) {
	if (t == 'c') {
		switch (op->type) {
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_CALL:
			return true;
		}
	} else if (t == 's') {
		if (op->family == R_ANAL_OP_FAMILY_PRIV) {
			return true;
		}
		switch (op->type) {
		case R_ANAL_OP_TYPE_SWI:
			return true;
		}
	} else if (t == 'i') {
		switch (op->type) {
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_ILL:
			return true;
		}
	} else if (t == 'j') {
		switch (op->type) {
		case R_ANAL_OP_TYPE_JMP:
		//case R_ANAL_OP_TYPE_RJMP:
		//case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_CJMP:
			return true;
		}
	}
	return false;
}

static inline void matchBar(ut8 *ptr, int i) {
	if (ptr[i] < 0xff) {
		ptr[i]++;
	}
}

static ut8 *analBars(RCore *core, int type, int nblocks, int blocksize, int skipblocks, ut64 from) {
	ut8 *p;
	int j, i = 0;
	ut8 *ptr = calloc (1, nblocks);
	if (!ptr) {
		eprintf ("Error: failed to malloc memory");
		return NULL;
	}
	p = malloc (blocksize);
	if (!p) {
		R_FREE (ptr);
		eprintf ("Error: failed to malloc memory");
		return NULL;
	}
	for (i = 0; i < nblocks; i++) {
		if (r_cons_is_breaked ()) {
			break;
		}
		ut64 off = from + (i + skipblocks) * blocksize;
		for (j = 0; j < blocksize ; j++) {
			RAnalOp *op = r_core_anal_op (core, off + j);
			if (op) {
				if (op->size < 1) {
					// do nothing
					if (type == 'i') {
						matchBar (ptr, i);
					}
				} else {
					if (checkAnalType (op, type)) {
						matchBar (ptr, i);
					}
				}
				if (op->size > 0) {
					j += op->size - 1;
				}
				r_anal_op_free (op);
			} else {
				if (type == 'i') {
					matchBar (ptr, i);
				}
			}
		}
	}
	free (p);
	return ptr;
}

static void cmd_print_bars(RCore *core, const char *input) {
	bool print_bars = false;
	ut8 *ptr = NULL;
	// p=e [nblocks] [totalsize] [skip]
	int nblocks = -1;
	int totalsize = -1;
	int skipblocks = -1;
	RIOMap* map;
	RListIter *iter;
	ut64 from = 0, to = 0;
	RList *list = r_core_get_boundaries_prot (core, -1, NULL, "zoom");
	ut64 blocksize = 0;
	int mode = 'b'; // e, p, b, ...
	int submode = 0; // q, j, ...
	
	if (input[0]) {
		char *spc = strchr (input, ' ');
		if (spc) {
			nblocks = r_num_math (core->num, spc + 1);
			if (nblocks < 1) {
				nblocks = core->blocksize;
				return;
			}
			spc = strchr (spc + 1, ' ');
			if (spc) {
				totalsize = r_num_math (core->num, spc + 1);
				spc = strchr (spc + 1, ' ');
				if (spc) {
					skipblocks = r_num_math (core->num, spc + 1);
				}
			}
		}
		mode = input[1];
		if (mode && mode != ' ' && input[2]) {
			submode = input[2];
		}
	}
	if (skipblocks < 0) {
		skipblocks = 0;
	}
	if (totalsize == UT64_MAX) {
		if (core->file && core->io) {
			totalsize = r_io_fd_size (core->io, core->file->fd);
			if ((st64) totalsize < 1) {
				totalsize = -1;
			}
		}
		if (totalsize == UT64_MAX) {
			eprintf ("Cannot determine file size\n");
			return;
		}
	}
	blocksize = (blocksize > 0)? (totalsize / blocksize): (core->blocksize);
	if (blocksize < 1) {
		eprintf ("Invalid block size: %d\n", (int)blocksize);
		return;
	}
	if (list) {
		RListIter *iter1 = list->head;
		RIOMap* map1 = iter1->data;
		from = map1->itv.addr;
		r_list_foreach (list, iter, map) {
			to = r_itv_end (map->itv);
		}
		totalsize = to - from;	
	} else {
		from = core->offset;
	}
	if (nblocks < 1) {
		nblocks = totalsize / blocksize;
	} else {
		blocksize = totalsize / nblocks;
	}
	switch (mode) {
	case '?': // bars
		r_core_cmd_help (core, help_msg_p_equal);
		break;
	case '=': // "p=="
		switch (submode) {
		case '?':
			r_core_cmd_help (core, help_msg_p_equal);
			break;
		case '0': // 0x00 bytes
		case 'f': // 0xff bytes
		case 'F': // 0xff bytes
		case 'p': // printable chars
		case 'z': // zero terminated strings
			{
				ut8 *p;
				ut64 i, j, k;
				ptr = calloc (1, nblocks);
				if (!ptr) {
					eprintf ("Error: failed to malloc memory");
					goto beach;
				}
				p = calloc (1, blocksize);
				if (!p) {
					R_FREE (ptr);
					eprintf ("Error: failed to malloc memory");
					goto beach;
				}
				int len = 0;
				for (i = 0; i < nblocks; i++) {
					ut64 off = from + blocksize * (i + skipblocks);
					r_core_read_at (core, off, p, blocksize);
					for (j = k = 0; j < blocksize; j++) {
						switch (submode) {
						case '0':
							if (!p[j]) {
								k++;
							}
							break;
						case 'f':
							if (p[j] == 0xff) {
								k++;
							}
							break;
						case 'z':
							if ((IS_PRINTABLE (p[j]))) {
								if (p[j + 1] == 0) {
									k++;
									j++;
								}
								if (len++ > 8) {
									k++;
								}
							} else {
								len = 0;
							}
							break;
						case 'p':
							if ((IS_PRINTABLE (p[j]))) {
								k++;
							}
							break;
						}
					}
					ptr[i] = 256 * k / blocksize;
				}
				r_print_columns (core->print, ptr, nblocks, 14);
				free (p);
			}
			break;
		case 'e': // "p=e"
		{
			ut8 *p;
			int i = 0;
			ptr = calloc (1, nblocks);
			if (!ptr) {
				eprintf ("Error: failed to malloc memory");
				goto beach;
			}
			p = malloc (blocksize);
			if (!p) {
				R_FREE (ptr);
				eprintf ("Error: failed to malloc memory");
				goto beach;
			}
			for (i = 0; i < nblocks; i++) {
				ut64 off = from + (blocksize * (i + skipblocks));
				r_core_read_at (core, off, p, blocksize);
				ptr[i] = (ut8) (256 * r_hash_entropy_fraction (p, blocksize));
			}
			free (p);
			r_print_columns (core->print, ptr, nblocks, 14);
		}
			break;
		default:
			r_print_columns (core->print, core->block, core->blocksize, 14);
			break;
		}
		break;
	case 'd': // "p=d"
		ptr = NULL;
		if (input[2]) {
			ut64 bufsz = r_num_math (core->num, input + 3);
			ut64 curbsz = core->blocksize;
			if (bufsz < 1) {
				bufsz = curbsz;
			}
			if (bufsz > core->blocksize) {
				r_core_block_size (core, bufsz);
				r_core_block_read (core);
			}
			cmd_print_eq_dict (core, core->block, bufsz);
			if (bufsz != curbsz) {
				r_core_block_size (core, curbsz);
			}
		} else {
			cmd_print_eq_dict (core, core->block, core->blocksize);
		}
		break;
	case 'j': // "p=j" cjmp and jmp
		if ((ptr = analBars (core, 'j', nblocks, blocksize, skipblocks, from))) {
			print_bars = true;
		}
		break;
	case 'c': // "p=c" calls
		if ((ptr = analBars (core, 'c', nblocks, blocksize, skipblocks, from))) {
			print_bars = true;
		}
		break;
	case 'i': // "p=i" invalid
		if ((ptr = analBars (core, 'i', nblocks, blocksize, skipblocks, from))) {
			print_bars = true;
		}
		break;
	case 's': // "p=s" syscalls
		if ((ptr = analBars (core, 's', nblocks, blocksize, skipblocks, from))) {
			print_bars = true;
		}
		break;
	case 'm':
	{
		ut8 *p;
		int j, i = 0;
		ptr = calloc (1, nblocks);
		if (!ptr) {
			eprintf ("Error: failed to malloc memory");
			goto beach;
		}
		p = malloc (blocksize);
		if (!p) {
			R_FREE (ptr);
			eprintf ("Error: failed to malloc memory");
			goto beach;
		}
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + (blocksize * (i + skipblocks));
			for (j = 0; j < blocksize; j++) {
				if (r_flag_get_at (core->flags, off + j, false)) {
					matchBar (ptr, i);
				}
			}
		}
		free (p);
		print_bars = true;
	}
		break;
	case 'e': // "p=e" entropy
	{
		ut8 *p;
		int i = 0;
		ptr = calloc (1, nblocks);
		if (!ptr) {
			eprintf ("Error: failed to malloc memory");
			goto beach;
		}
		p = malloc (blocksize);
		if (!p) {
			R_FREE (ptr);
			eprintf ("Error: failed to malloc memory");
			goto beach;
		}
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + (blocksize * (i + skipblocks));
			r_core_read_at (core, off, p, blocksize);
			ptr[i] = (ut8) (256 * r_hash_entropy_fraction (p, blocksize));
		}
		free (p);
		print_bars = true;
	}
	break;
	case '0': // 0x00 bytes
	case 'F': // 0xff bytes
	case 'p': // printable chars
	case 'z': // zero terminated strings
	if (blocksize > 0) {
		ut8 *p;
		ut64 i, j, k;
		ptr = calloc (1, nblocks);
		if (!ptr) {
			eprintf ("Error: failed to malloc memory");
			goto beach;
		}
		p = calloc (1, blocksize);
		if (!p) {
			R_FREE (ptr);
			eprintf ("Error: failed to malloc memory");
			goto beach;
		}
		int len = 0;
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + blocksize * (i + skipblocks);
			r_core_read_at (core, off, p, blocksize);
			for (j = k = 0; j < blocksize; j++) {
				switch (mode) {
				case '0':
					if (!p[j]) {
						k++;
					}
					break;
				case 'f':
					if (p[j] == 0xff) {
						k++;
					}
					break;
				case 'z':
					if ((IS_PRINTABLE (p[j]))) {
						if (p[j + 1] == 0) {
							k++;
							j++;
						}
						if (len++ > 8) {
							k++;
						}
					} else {
						len = 0;
					}
					break;
				case 'p':
					if ((IS_PRINTABLE (p[j]))) {
						k++;
					}
					break;
				}
			}
			ptr[i] = 256 * k / blocksize;
		}
		free (p);
		print_bars = true;
	} else {
		eprintf ("Invalid blocksize\n");
	}
	break;
	case 'b': // bytes
	case '\0':
		ptr = calloc (1, nblocks);
		r_core_read_at (core, from, ptr, nblocks);
		// TODO: support print_bars
		r_print_fill (core->print, ptr, nblocks, from, blocksize);
		R_FREE (ptr);
		break;
	}
	if (print_bars) {
		int i;
		switch (submode) {
		case 'j':
			r_cons_printf ("{\"blocksize\":%d,\"address\":%"PFMT64d ",\"size\":%"PFMT64d ",\"entropy\":[",
				blocksize, from, totalsize);
			for (i = 0; i < nblocks; i++) {
				ut8 ep = ptr[i];
				ut64 off = blocksize * i;
				const char *comma = (i + 1 < (nblocks))? ",": "";
				off += from;
				r_cons_printf ("{\"addr\":%"PFMT64d ",\"value\":%d}%s",
					off, ep, comma);

			}
			r_cons_printf ("]}\n");
			break;
		case 'q':
			for (i = 0; i < nblocks; i++) {
				ut64 off = from + (blocksize * i);
				if (core->print->cur_enabled) {
					if (i == core->print->cur) {
						r_cons_printf ("> ");
						core->num->value = off;
					} else {
						r_cons_printf ("  ");
					}
				}
				r_cons_printf ("0x%08"PFMT64x " %d %d\n", off, i, ptr[i]);
			}
			break;
		default:
			core->print->num = core->num;
			r_print_fill (core->print, ptr, nblocks, from, blocksize);
			break;
		}
	}
beach:
	free (ptr);
	return;
}

static int bbcmp(RAnalBlock *a, RAnalBlock *b) {
	return a->addr - b->addr;
}

/* TODO: integrate this into r_anal */
static void _pointer_table(RCore *core, ut64 origin, ut64 offset, const ut8 *buf, int len, int step, int mode) {
	int i;
	ut64 addr;
	st32 *delta; // only for step == 4
	if (step < 1) {
		step = 4;
	}
	if (!r_io_is_valid_offset (core->io, origin, 0) ||
	    !r_io_is_valid_offset (core->io, offset, 0)) {
		return;
	}
	if (origin != offset) {
		switch (mode) {
		case '*':
			r_cons_printf ("CC-@ 0x%08"PFMT64x "\n", origin);
			r_cons_printf ("CC switch table @ 0x%08"PFMT64x "\n", origin);
			r_cons_printf ("axd 0x%"PFMT64x " 0x%08"PFMT64x "\n", origin, offset);
			break;
		case '.':
			r_core_cmdf (core, "CC-@ 0x%08"PFMT64x "\n", origin);
			r_core_cmdf (core, "CC switch table @ 0x%08"PFMT64x "\n", origin);
			r_core_cmdf (core, "f switch.0x%08"PFMT64x"=0x%08"PFMT64x"\n", origin, origin);
			r_core_cmdf (core, "f jmptbl.0x%08"PFMT64x"=0x%08"PFMT64x"\n", offset, offset); //origin, origin);
			r_core_cmdf (core, "axd 0x%"PFMT64x " 0x%08"PFMT64x "\n", origin, offset);
			break;
		}
	} else if (mode == '.') {
		r_core_cmdf (core, "CC-@ 0x%08"PFMT64x "\n", origin);
		r_core_cmdf (core, "CC switch basic block @ 0x%08"PFMT64x "\n", offset);
		r_core_cmdf (core, "f switch.0x%08"PFMT64x"=0x%08"PFMT64x"\n", offset, offset); // basic block @ 0x%08"PFMT64x "\n", offset);
	}
	int n = 0;
	for (i = 0; (i + sizeof (st32)) <= len; i += step, n++) {
		delta = (st32 *) (buf + i);
		addr = offset + *delta;
		if (!r_io_is_valid_offset (core->io, addr, 0)) {
			break;
		}
		if (mode == '*') {
			r_cons_printf ("af case.%d.0x%"PFMT64x " 0x%08"PFMT64x "\n", i, offset, addr);
			r_cons_printf ("ax 0x%"PFMT64x " 0x%08"PFMT64x "\n", offset, addr);
			r_cons_printf ("ax 0x%"PFMT64x " 0x%08"PFMT64x "\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			r_cons_printf ("aho case 0x%"PFMT64x " 0x%08"PFMT64x " @ 0x%08"PFMT64x "\n", (ut64)i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			r_cons_printf ("ahs %d @ 0x%08"PFMT64x "\n", step, offset + i);
		} else if (mode == '.') {
			r_core_cmdf (core, "af case.%d.0x%"PFMT64x " @ 0x%08"PFMT64x "\n", n, offset, addr);
			r_core_cmdf (core, "ax 0x%"PFMT64x " 0x%08"PFMT64x "\n", offset, addr);
			r_core_cmdf (core, "ax 0x%"PFMT64x " 0x%08"PFMT64x "\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			// r_core_cmdf (core, "CC+ case %d: 0x%08"PFMT64x " @ 0x%08"PFMT64x "\n", i / step, addr, origin);
			r_core_cmdf (core, "CCu case %d: @ 0x%08"PFMT64x "\n", n, addr); //, origin);
			r_core_cmdf (core, "aho case %d 0x%08"PFMT64x " @ 0x%08"PFMT64x "\n", n, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			r_core_cmdf (core, "ahs %d @ 0x%08"PFMT64x "\n", step, offset + i);
		} else {
			r_cons_printf ("0x%08"PFMT64x " -> 0x%08"PFMT64x "\n", offset + i, addr);
		}
	}
}

// TODO: this function is a temporary fix. All analysis should be based on realsize. However, now for same architectures realisze is not used
static ut32 tmp_get_contsize(RAnalFunction *f) {
	int size = r_anal_fcn_contsize (f);
	size = (size > 0)? size: r_anal_fcn_size (f);
	return (size < 0)? 0: size;
}

static void pr_bb(RCore *core, RAnalFunction *fcn, RAnalBlock *b, bool emu, ut64 saved_gp, ut8 *saved_arena, char p_type, bool fromHere) {
	bool show_flags = r_config_get_i (core->config, "asm.flags");
	core->anal->gp = saved_gp;
	if (fromHere) {
		if (b->addr < core->offset) {
			core->cons->null = true;
		} else {
			core->cons->null = false;
		}
	}
	if (emu) {
		if (b->parent_reg_arena) {
			ut64 gp;
			r_reg_arena_poke (core->anal->reg, b->parent_reg_arena);
			R_FREE (b->parent_reg_arena);
			gp = r_reg_getv (core->anal->reg, "gp");
			if (gp) {
				core->anal->gp = gp;
			}
		} else {
			r_reg_arena_poke (core->anal->reg, saved_arena);
		}
	}
	if (b->parent_stackptr != INT_MAX) {
		core->anal->stackptr = b->parent_stackptr;
	}
	p_type == 'D'
	? r_core_cmdf (core, "pD %d @0x%"PFMT64x, b->size, b->addr)
	: r_core_cmdf (core, "pI %d @0x%"PFMT64x, b->size, b->addr);

	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RAnalBlock *jumpbb = r_anal_bb_get_jumpbb (fcn, b);
			if (jumpbb) {
				if (emu && core->anal->last_disasm_reg && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
				}
				if (jumpbb->parent_stackptr == INT_MAX) {
					jumpbb->parent_stackptr = core->anal->stackptr + b->stackptr;
				}
			}
		}
		if (p_type == 'D' && show_flags) {
			r_cons_printf ("| ----------- true: 0x%08"PFMT64x, b->jump);
		}
	}
	if (b->fail != UT64_MAX) {
		if (b->fail > b->addr) {
			RAnalBlock *failbb = r_anal_bb_get_failbb (fcn, b);
			if (failbb) {
				if (emu && core->anal->last_disasm_reg && !failbb->parent_reg_arena) {
					failbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
				}
				if (failbb->parent_stackptr == INT_MAX) {
					failbb->parent_stackptr = core->anal->stackptr + b->stackptr;
				}
			}
		}
		if (p_type == 'D' && show_flags) {
			r_cons_printf ("  false: 0x%08"PFMT64x, b->fail);
		}
	}
	if (p_type == 'D' && show_flags) {
		r_cons_newline ();
	}
}

#if 0
dsmap {
	r_itv_t addr;
	ut64 size;
	ut8 *dis;
}
#endif

#define P(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
static void disasm_recursive(RCore *core, ut64 addr, char type_print) {
	bool push[512];
	int pushes = 0;
	RAnalOp aop = {0};
	int i, j, ret;
	ut8 *buf = calloc (core->blocksize, 1); // begin of instruction
	if (!buf) {
		return;
	}
	ut8 *raw = calloc (core->blocksize, 1); // instruction coverage
	if (!raw) {
		return;
	}
	int count = 64;
	int base = 0;
	for (i = 0; count > 0 && i < core->blocksize; i++) {
		r_anal_op_fini (&aop);
		ret = r_anal_op (core->anal, &aop, addr + i, core->block + i , core->blocksize - i);
		if (ret < 0 || aop.size < 1) {
			continue;
		}
		buf[i] = 1;
		for (j = i; j < i + aop.size; j++) {
			raw[j] = 1;
		}
	//	r_core_cmdf (core, "pd 1 @ 0x%08"PFMT64x, addr + i);
		switch (aop.type) {
		case R_ANAL_OP_TYPE_JMP:
			r_core_cmdf (core, "pD %d @ 0x%08"PFMT64x, i + aop.size - base, addr + base);
			i = aop.jump - addr - 1;
			base = i + 1;
			count--;
			continue;
			break;
#if 0
		case R_ANAL_OP_TYPE_CJMP:
			if (aop.jump > addr + i) {
				if (pushes > 500) {
					eprintf ("Too deep\n");
				}
				push[pushes++] = i + aop.size;
				i = aop.jump - addr - 1;
				continue;
			}
			break;
#endif
		case R_ANAL_OP_TYPE_UCJMP:
			break;
		}
		i += aop.size - 1;
	}
#if 0
	if (base < i) {
r_cons_printf ("base:\n");
		r_core_cmdf (core, "pD %d @ 0x%08"PFMT64x, i - base, addr + base); //+ aop.size - base, addr + base);
r_cons_printf ("base:\n");
		
	}
#endif
	// unlikely
	int p;
	for (p = 0; p<pushes; p++) {
		r_cons_printf ("PUSH 0x%08"PFMT64x"\n", addr + push[p]);
		for (i = push[p]; i < core->blocksize; i++) {
			if (buf[i]) {
				break;
			}
			buf[i] = 1;
			r_anal_op_fini (&aop);
			ret = r_anal_op (core->anal, &aop, addr + i, core->block + i , core->blocksize - i);
			if (ret < 0 || aop.size < 1) {
				continue;
			}
			// r_core_cmdf (core, "pd 1 @ 0x%08"PFMT64x, addr + i);
			switch (aop.type) {
			case R_ANAL_OP_TYPE_JMP:
				if (aop.jump > addr + i) {
					r_core_cmdf (core, "pD %d @ 0x%08"PFMT64x, i + aop.size - base, addr + base);
					i = aop.jump - addr - 1;
					base = i + 1;
					continue;
				}
				break;
#if 0
			case R_ANAL_OP_TYPE_CJMP:
				if (aop.jump > addr + i) {
					if (pushes > 500) {
						eprintf ("Too deep\n");
					}
					push[pushes++] = i + aop.size;
					i = aop.jump - addr - 1;
					continue;
				}
				break;
#endif
			case R_ANAL_OP_TYPE_UCJMP:
				break;
			}
			i += aop.size - 1;
		}
	}
#if 0
	// linear disasm 
	for (i = 0; i< core->blocksize; i++) {
		if (!buf[i]) {
			continue;
		}
		r_core_cmdf (core, "pd 1 @ 0x%08"PFMT64x, addr + i);
		r_anal_op_fini (&aop);
		ret = r_anal_op (core->anal, &aop, addr + i, core->block + i , core->blocksize - i);
		i += aop.size
	}
#endif
}

#if 0
static void _disasm_recursive(RCore *core, ut64 addr, char type_print) {
	bool show_flags = r_config_get_i (core->config, "asm.flags");
	bool show_bytes = r_config_get_i (core->config, "asm.bytes");
	bool show_offset = r_config_get_i (core->config, "asm.offset");
	bool show_imtrim = r_config_get_i (core->config, "asm.immtrim");
	Sdb *db = sdb_new0 ();
	RAsmOp asmop = {0};
	RAnalOp aop = {0};
	int i, ret;
	ut8 *buf = core->block;
	int loop, len = core->blocksize;
	for (loop = 0; loop < 2 ; loop ++) {
		for (i = 0; i < len; i+= aop.size) {
			r_anal_op_fini (&aop);
			r_asm_set_pc (core->assembler, addr + i);
			//if (i + 8 >= len) {
			//	eprintf ("WARNING: block size is too small\n");
			// TODO: reimplement using dynamic memory accesses, not just the block
			//	break;
			//}
			ret = r_asm_disassemble (core->assembler, &asmop, buf + i, len - i);
			if (ret < 0) {
				asmop.size = 1;
				continue;
			}
			ret = r_anal_op (core->anal, &aop, addr + i, buf + i , len - i);
			if (ret < 0) {
				aop.size = 1;
				continue;
			}
			if (loop > 0) {
				if (show_flags) {
					const char *x = sdb_const_get (db, sdb_fmt (-1, "label.0x%"PFMT64x, addr + i), NULL);
					if (x) {
						r_cons_printf ("%s:\n", x);
					}
				}
				char *asm_str = asmop.buf_asm;
				char *color_reg = P(reg): Color_YELLOW;
				char *color_num = P(num): Color_CYAN;
				asm_str = r_print_colorize_opcode (core->print, asm_str, color_reg, color_num, false);
				if (show_imtrim) {
					r_parse_immtrim (asm_str);
				}
				if (show_offset) {
					r_print_offset (core->print, addr + i, 0, 0, 0, 0, NULL);
				}
				if (show_bytes) {
					char *hexstr = r_print_hexpair (core->print, asmop.buf_hex, -1);
					const char *pad = r_str_pad (' ', 20 - strlen (asmop.buf_hex));
					r_cons_printf (" %s%s %s\n", pad, hexstr, asm_str);
					free (hexstr);
				} else {
					r_cons_printf (" %s\n", asm_str);
				}
			}
			switch (aop.type) {
			case R_ANAL_OP_TYPE_JMP:
				break;
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_CJMP:
				sdb_set (db, sdb_fmt (-1, "label.0x%"PFMT64x, aop.jump),
					sdb_fmt (-1, "from.0x%"PFMT64x, addr + i), 0);
				break;
			}
			if (aop.size < 1) {
				aop.size = 1;
			}
		}
	}
	r_anal_op_fini (&aop);
	sdb_free (db);
}
#endif

static void func_walk_blocks(RCore *core, RAnalFunction *f, char input, char type_print, bool fromHere) {
	RListIter *iter;
	RAnalBlock *b;
	RAnalFunction *tmp_func;
	RListIter *locs_it = NULL;

	if (f->fcn_locs) {
		locs_it = f->fcn_locs->head;
	}
	// XXX: hack must be reviewed/fixed in code analysis
	if (r_list_length (f->bbs) == 1) {
		ut32 fcn_size = r_anal_fcn_realsize (f);
		b = r_list_get_top (f->bbs);
		if (b->size > fcn_size) {
			b->size = fcn_size;
		}
	}
	r_list_sort (f->bbs, (RListComparator) bbcmp);
	if (input == 'j') {
		r_cons_print ("[");
		bool isFirst = true;
		for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (fromHere) {
				if (b->addr < core->offset) {
					core->cons->null = true;
				} else {
					core->cons->null = false;
				}
			}
			if (tmp_func->addr > f->addr) {
				break;
			}
			r_list_foreach (tmp_func->bbs, iter, b) {
				if (isFirst) {
					isFirst = false;
				} else {
					r_cons_print (",");
				}
// const char *cmd = (type_print == 'D')? "pDj": "pIj";
// r_core_cmdf (core, "%s %d @ 0x%"PFMT64x, cmd, b->size, b->addr);
				ut8 *buf = malloc (b->size);
				if (buf) {
					r_io_read_at (core->io, b->addr, buf, b->size);
					r_core_print_disasm_json (core, b->addr, buf, b->size, 0);
					free (buf);
				} else {
					eprintf ("cannot allocate %d byte(s)\n", b->size);
				}
			}
		}
		r_list_foreach (f->bbs, iter, b) {
			if (fromHere) {
				if (b->addr < core->offset) {
					core->cons->null = true;
				} else {
					core->cons->null = false;
				}
			}
			if (isFirst) {
				isFirst = false;
			} else {
				r_cons_print (",");
			}
#if 0
			r_core_print_disasm_json (core, core->offset, buf, bsize, 0);
			const char *cmd = (type_print == 'D')? "pDj": "pIj";
			r_core_cmdf (core, "%s %d @ 0x%"PFMT64x, cmd, b->size, b->addr);
#endif
			ut8 *buf = malloc (b->size);
			if (buf) {
				r_io_read_at (core->io, b->addr, buf, b->size);
				r_core_print_disasm_json (core, b->addr, buf, b->size, 0);
				free (buf);
			} else {
				eprintf ("cannot allocate %d byte(s)\n", b->size);
			}
		}
		for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
			if (r_cons_is_breaked ()) {
				break;
			}
			r_list_foreach (tmp_func->bbs, iter, b) {
				if (fromHere) {
					if (b->addr < core->offset) {
						core->cons->null = true;
					} else {
						core->cons->null = false;
					}
				}
				if (isFirst) {
					isFirst = false;
				} else {
					r_cons_print (",");
				}
#if 0
				const char *cmd = (type_print == 'D')? "pDj": "pIj";
				r_core_cmdf (core, "%s %d @0x%"PFMT64x, cmd, b->size, b->addr);
#endif
				ut8 *buf = malloc (b->size);
				if (buf) {
					r_io_read_at (core->io, b->addr, buf, b->size);
					r_core_print_disasm_json (core, b->addr, buf, b->size, 0);
					free (buf);
				} else {
					eprintf ("cannot allocate %d byte(s)\n", b->size);
				}
			}
		}
		r_cons_print ("]");
	} else {
		bool asm_lines = r_config_get_i (core->config, "asm.lines");
		bool emu = r_config_get_i (core->config, "asm.emu");
		ut64 saved_gp = 0;
		ut8 *saved_arena = NULL;
		int saved_stackptr = core->anal->stackptr;
		if (emu) {
			saved_gp = core->anal->gp;
			saved_arena = r_reg_arena_peek (core->anal->reg);
		}
		r_config_set_i (core->config, "asm.lines", 0);
		for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
			if (tmp_func->addr >= f->addr) {
				break;
			}
			r_list_foreach (tmp_func->bbs, iter, b) {
				pr_bb (core, tmp_func, b, emu, saved_gp, saved_arena, type_print, fromHere);
			}
		}
		r_list_foreach (f->bbs, iter, b) {
			pr_bb (core, f, b, emu, saved_gp, saved_arena, type_print, fromHere);
		}
		for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
			if (r_cons_is_breaked ()) {
				break;
			}
			// this should be more advanced
			r_list_foreach (tmp_func->bbs, iter, b) {
				pr_bb (core, tmp_func, b, emu, saved_gp, saved_arena, type_print, fromHere);
			}
		}
		if (emu) {
			core->anal->gp = saved_gp;
			if (saved_arena) {
				r_reg_arena_poke (core->anal->reg, saved_arena);
				R_FREE (saved_arena);
			}
		}
		core->anal->stackptr = saved_stackptr;
		r_config_set_i (core->config, "asm.lines", asm_lines);
	}
}

static inline const char cmd_pxb_p(char input) {
	return IS_PRINTABLE (input)? input: '.';
}

static inline int cmd_pxb_k(const ut8 *buffer, int x) {
	return buffer[3 - x] << (8 * x);
}

static const char* bits_to_c_code_fmtstr(int bits) {
	switch (bits) {
	case 16:
		return "0x%04x";
	case 32:
		return "0x%08xU";
	case 64:
		return "0x%016" PFMT64x "ULL";
	default:
		return "0x%02x";
	}
}

static void print_c_code(RPrint *p, ut64 addr, ut8 *buf, int len, int ws, int w) {
	const char *fmtstr;
	int i, bits;

	ws = R_MAX (1, R_MIN (ws, 8));
	bits = ws * 8;
	fmtstr = bits_to_c_code_fmtstr (bits);
	len /= ws;

	p->cb_printf ("#define _BUFFER_SIZE %d\n", len);
	p->cb_printf ("const uint%d_t buffer[%d] = {", bits, len);

	p->interrupt = 0;

	for (i = 0; !p->interrupt && i < len; i++) {
		if (!(i % w)) {
			p->cb_printf ("\n  ");
		}
		r_print_cursor (p, i, 1);
		p->cb_printf (fmtstr, r_read_ble (buf, p->big_endian, bits));
		if ((i + 1) < len) {
			p->cb_printf (",");

			if ((i + 1) % w) {
				p->cb_printf (" ");
			}
		}
		r_print_cursor (p, i, 0);
		buf += ws;
	}
	p->cb_printf ("\n};\n");
}

R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len, char lang) {
	int i, w = p->cols * 0.7;
	if (w < 1) {
		w = 1;
	}
	switch (lang) {
	case '?':
		r_cons_println ("Valid print code formats are: JSON, C, Python, Cstring (pcj, pc, pcp, pcs) \n"
		"  pc     C\n"
		"  pc*    print 'wx' r2 commands\n"
		"  pch    C half-words (2 byte)\n"
		"  pcw    C words (4 byte)\n"
		"  pcd    C dwords (8 byte)\n"
		"  pca    GAS .byte blob\n"
		"  pcA    .bytes with instructions in comments\n"
		"  pcs    string\n"
		"  pcS    shellscript that reconstructs the bin\n"
		"  pcj    json\n"
		"  pcJ    javascript\n"
		"  pcp    python");
		break;
	case '*':
		p->cb_printf ("wx ");
		for (i = 0; !p->interrupt && i < len; i++) {
			if (i && !(i % 16)) {
				p->cb_printf (";s+16\nwx ");
			}
			p->cb_printf ("%02x", buf[i]);
		}
		if (i && !(i % 16)) {
			p->cb_printf (";s+16\n");
		} else {
			p->cb_printf (";s+%d\n", (i % 16));
		}
		p->cb_printf ("s-%d\n", len);
		break;
	case 'A': // "pcA"
		/* implemented in core because of disasm :( */
		break;
	case 'a': // "pca"
		p->cb_printf ("shellcode:");
		for (i = 0; !p->interrupt && i < len; i++) {
			if (!(i % 8)) {
				p->cb_printf ("\n.byte ");
			} else {
				p->cb_printf (", ");
			}
			p->cb_printf ("0x%02x", buf[i]);
		}
		p->cb_printf ("\n.equ shellcode_len, %d\n", len);
		break;
	case 's': // "pcs"
		p->cb_printf ("\"");
		for (i = 0; !p->interrupt && i < len; i++) {
			p->cb_printf ("\\x%02x", buf[i]);
		}
		p->cb_printf ("\"\n");
		break;
	case 'S': // "pcS"
	{
		const int trunksize = 16;
		for (i = 0; !p->interrupt && i < len; i++) {
			if (!(i % trunksize)) {
				p->cb_printf ("printf \"");
			}
			p->cb_printf ("\\%03o", buf[i]);
			if ((i % trunksize) == (trunksize - 1)) {
				p->cb_printf ("\" %s bin\n", (i <= trunksize)? ">": ">>");
			}
		}
		if ((i % trunksize)) {
			p->cb_printf ("\" %s bin\n", (i <= trunksize)? ">": ">>");
		}
	} break;
	case 'J': { // "pcJ"
		char *out = malloc (len * 3);
		p->cb_printf ("var buffer = new Buffer(\"");
		out[0] = 0;
		r_base64_encode (out, buf, len);
		p->cb_printf ("%s", out);
		p->cb_printf ("\", 'base64');\n");
		free (out);
	} break;
	case 'j': // "pcj"
		p->cb_printf ("[");
		for (i = 0; !p->interrupt && i < len; i++) {
			r_print_cursor (p, i, 1);
			p->cb_printf ("%d%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 0);
		}
		p->cb_printf ("]\n");
		break;
	case 'P':
	case 'p': // "pcp" "pcP"
		p->cb_printf ("import struct\nbuf = struct.pack (\"%dB\", *[", len);
		for (i = 0; !p->interrupt && i < len; i++) {
			if (!(i % w)) {
				p->cb_printf ("\n");
			}
			r_print_cursor (p, i, 1);
			p->cb_printf ("0x%02x%s", buf[i], (i + 1 < len)? ",": "])");
			r_print_cursor (p, i, 0);
		}
		p->cb_printf ("\n");
		break;
	case 'h': // "pch"
		print_c_code (p, addr, buf, len, 2, p->cols / 2); // 9
		break;
	case 'w': // "pcw"
		print_c_code (p, addr, buf, len, 4, p->cols / 3); // 6);
		break;
	case 'd': // "pcd"
		print_c_code (p, addr, buf, len, 8, p->cols / 5); //3);
		break;
	default:
		print_c_code (p, addr, buf, len, 1, p->cols / 1.5); // 12);
		break;
	}
}

static int cmd_print(void *data, const char *input) {
	RCore *core = (RCore *) data;
	RCoreAnalStats *as;
	RCoreAnalStatsItem total = {0};
	int mode, w, p, i, l, len, ret;
	ut8* block;
	ut32 tbs = core->blocksize;
	ut64 n, off, from, to, at, ate, piece;
	ut64 tmpseek = UT64_MAX;
	const int addrbytes = core->io->addrbytes;
	mode = w = p = i = l = len = ret = 0;
	n = off = from = to = at = ate = piece = 0;

	r_print_init_rowoffsets (core->print);
	off = UT64_MAX;
	l = len = core->blocksize;
	if (input[0] && input[1]) {
		int idx = (input[0] == 'h')? 2: 1;
		const char *p = off? strchr (input + idx, ' '): NULL;
		if (p) {
			l = (int) r_num_math (core->num, p + 1);
			/* except disasm and memoryfmt (pd, pm) */
			if (input[0] != 'd' && input[0] != 'D' && input[0] != 'm' &&
				input[0] != 'a' && input[0] != 'f' && input[0] != 'i' && input[0] != 'I') {
				int n = (st32) l; // r_num_math (core->num, input+1);
				if (l < 0) {
					off = core->offset + n;
					len = l = -n;
					tmpseek = core->offset;
				} else if (l > 0) {
					len = l;
					if (l > tbs) {
						if (input[0] == 'x' && input[1] == 'l') {
							l *= core->print->cols;
						}
						if (!r_core_block_size (core, l)) {
							eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
								*input, input + 2);
							goto beach;
						}
						l = core->blocksize;
					} else {
						l = len;
					}
				}
			}
		}
	} else {
		l = len;
	}

	if (len > core->blocksize) {
		len = core->blocksize;
	}

	if (input[0] != 'd' && input[0] != 'm' && input[0] != 'a' && input[0] != 'f') {
		n = core->blocksize_max;
		i = (int) n;
		if (i != n) {
			i = 0;
		}
		if (i && l > i) {
			eprintf ("This block size is too big (0x%"PFMT64x
				" < 0x%x). Did you mean 'p%c @ %s' instead?\n",
				n, l, *input, input + 2);
			goto beach;
		}
	}
	if (input[0] == 'x' || input[0] == 'D') {
		if (l > 0 && tmpseek == UT64_MAX) {
			if (!r_core_block_size (core, l)) {
				eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
					*input, input + 2);
				goto beach;
			}
		}
	}

	if (input[0] && input[0] != 'z' && input[1] == 'f') {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
		// R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) {
			len = r_anal_fcn_size (f);
		} else {
			eprintf ("p: Cannot find function at 0x%08"PFMT64x "\n", core->offset);
			core->num->value = 0;
			goto beach;
		}
	}
	core->num->value = len;
	if (len > core->blocksize) {
		len = core->blocksize;
	}
	if (off != UT64_MAX) {
		r_core_seek (core, off, SEEK_SET);
		r_core_block_read (core);
	}
	// TODO After core->block is removed, this should be changed to a block read.
	block = core->block;
	switch (*input) {
	case 'w': // "pw"
		if (input[1] == 'n') {
			cmd_print_pwn (core);
		} else if (input[1] == 'd') {
			if (!r_sandbox_enable (0)) {
				char *cwd = r_sys_getdir ();
				if (cwd) {
					r_cons_println (cwd);
					free (cwd);
				}
			}
		} else {
			r_cons_printf ("| pwd               display current working directory\n");
		}
		break;
	case 'j': // "pj"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_pj);
		} else if (input[1] == '.') {
			if (input[2] == '.') {
				ut8 *data = calloc (core->offset + 1, 1);
				if (data) {
					data[core->offset] = 0;
					(void)r_core_read_at (core, 0, data, core->offset);
					char *res = r_print_json_path ((const char *)data, core->offset);
					if (res) {
						eprintf ("-> res(%s)\n", res);
					}
/*
					char *res = r_print_json_indent ((char*)data, false, "  ", NULL);
					print_json_path (core, res);
					free (res);
*/
				} else {
					eprintf ("Cannot allocate %d\n", (int)(core->offset));
				}
			} else {
				r_core_cmdf (core, "pj %"PFMT64d" @ 0", core->offset);
			}
		} else {
			if (core->blocksize < 4 || !memcmp (core->block, "\xff\xff\xff\xff", 4)) {
				eprintf ("Cannot read\n");
			} else {
				char *res = r_print_json_indent ((const char *)core->block, true, "  ", NULL);
				r_cons_printf ("%s\n", res);
				free (res);
			}
		}
		break;
	case 'h': // "ph"
		cmd_print_ph (core, input + 1);
		break;
	case 'v': // "pv"
		cmd_print_pv (core, input + 1, block);
		break;
	case '-': // "p-"
		mode = input[1];
		w = (int)(core->print->cols * 2.7);
		if (mode == 'j') {
			r_cons_strcat ("{");
		}
		off = core->offset;
		{
			RList *list = r_core_get_boundaries_prot (core, -1, NULL, "search");
			RIOMap *map = r_list_first (list);
			if (map) {
				from = map->itv.addr;
				to = r_itv_end (map->itv);
			}
			r_list_free (list);
		}
		piece = R_MAX ((to - from) / w, 1);
		as = r_core_anal_get_stats (core, from, to, piece);
		if (!as && mode != '?') {
			return 0;
		}
		// eprintf ("RANGE = %llx %llx\n", from, to);
		switch (mode) {
		case '?':
			r_core_cmd_help (core, help_msg_p_minus);
			return 0;
		case 'j': // "p-j"
			r_cons_printf (
				"\"from\":%"PFMT64d ","
				"\"to\":%"PFMT64d ","
				"\"blocksize\":%d,"
				"\"blocks\":[", from, to, piece);
			break;
		case 'h': // "p-h"
			r_cons_printf (".-------------.----------------------------.\n");
			r_cons_printf ("|   offset    | flags funcs cmts syms str  |\n");
			r_cons_printf ("|-------------)----------------------------|\n");
			break;
		default:
			r_cons_printf ("0x%"PFMT64x " [", from);
		}

		bool use_color = r_config_get_i (core->config, "scr.color");
		len = 0;
		for (i = 0; i < ((to-from)/piece); i++) {
			at = from + (piece * i);
			ate = at + piece;
			p = (at - from) / piece;
			switch (mode) {
			case 'j':
				r_cons_printf ("%s{", len? ",": "");
				if ((as->block[p].flags)
				|| (as->block[p].functions)
				|| (as->block[p].comments)
				|| (as->block[p].symbols)
				|| (as->block[p].rwx)
				|| (as->block[p].strings)) {
					r_cons_printf ("\"offset\":%"PFMT64d ",", at), l++;
					r_cons_printf ("\"size\":%"PFMT64d ",", piece), l++;
				}
				// TODO: simplify with macro
				l = 0;
				if (as->block[p].flags) {
					r_cons_printf ("%s\"flags\":%d", l? ",": "", as->block[p].flags), l++;
				}
				if (as->block[p].functions) {
					r_cons_printf ("%s\"functions\":%d", l? ",": "", as->block[p].functions), l++;
				}
				if (as->block[p].comments) {
					r_cons_printf ("%s\"comments\":%d", l? ",": "", as->block[p].comments), l++;
				}
				if (as->block[p].symbols) {
					r_cons_printf ("%s\"symbols\":%d", l? ",": "", as->block[p].symbols), l++;
				}
				if (as->block[p].strings) {
					r_cons_printf ("%s\"strings\":%d", l? ",": "", as->block[p].strings), l++;
				}
				if (as->block[p].rwx) {
					r_cons_printf ("%s\"rwx\":\"%s\"", l? ",": "", r_str_rwx_i (as->block[p].rwx)), l++;
				}
				r_cons_strcat ("}");
				len++;
				break;
			case 'h':
				total.flags += as->block[p].flags;
				total.functions += as->block[p].functions;
				total.comments += as->block[p].comments;
				total.symbols += as->block[p].symbols;
				total.strings += as->block[p].strings;
				if ((as->block[p].flags)
				|| (as->block[p].functions)
				|| (as->block[p].comments)
				|| (as->block[p].symbols)
				|| (as->block[p].strings)) {
					r_cons_printf ("| 0x%09"PFMT64x " | %4d %4d %4d %4d %4d   |\n", at,
						as->block[p].flags,
						as->block[p].functions,
						as->block[p].comments,
						as->block[p].symbols,
						as->block[p].strings);
				}
				break;
			default:
				if (off >= at && off < ate) {
					r_cons_memcat ("^", 1);
				} else {
					RIOSection *s = r_io_section_vget (core->io, at);
					if (use_color) {
						if (s) {
							if (s->flags & 1) {
								r_cons_print (Color_BGBLUE);
							} else {
								r_cons_print (Color_BGGREEN);
							}
						} else {
							r_cons_print (Color_BGRED);
						}
					}
					if (as->block[p].strings > 0) {
						r_cons_memcat ("z", 1);
					} else if (as->block[p].symbols > 0) {
						r_cons_memcat ("s", 1);
					} else if (as->block[p].functions > 0) {
						r_cons_memcat ("F", 1);
					} else if (as->block[p].comments > 0) {
						r_cons_memcat ("c", 1);
					} else if (as->block[p].flags > 0) {
						r_cons_memcat (".", 1);
					} else {
						r_cons_memcat ("_", 1);
					}
				}
				break;
			}
		}
		switch (mode) {
		case 'j':
			r_cons_strcat ("]}\n");
			break;
		case 'h':
			// r_cons_printf ("  total    | flags funcs cmts syms str  |\n");
			r_cons_printf ("|-------------)----------------------------|\n");
			r_cons_printf ("|    total    | %4d %4d %4d %4d %4d   |\n",
				total.flags, total.functions, total.comments, total.symbols, total.strings);
			r_cons_printf ("`-------------'----------------------------'\n");
			break;
		default:
			if (use_color) {
				r_cons_print (Color_RESET);
			}
			r_cons_printf ("] 0x%"PFMT64x "\n", to);
		}
		r_core_anal_stats_free (as);
		break;
	case '=': // "p="
		cmd_print_bars (core, input);
		break;
	case 'A': // "pA"
	{
		const ut64 saved_from = r_config_get_i (core->config, "search.from"),
				saved_to = r_config_get_i (core->config, "search.to"),
				saved_maxhits = r_config_get_i (core->config, "search.maxhits");

		int want = r_num_math (core->num, input + 1);
		if (input[1] == '?') {
			r_core_cmd0 (core, "/A?");
		} else {
			r_config_set_i (core->config, "search.maxhits", want);
			r_config_set_i (core->config, "search.from", core->offset);
			r_config_set_i (core->config, "search.to", core->offset + core->blocksize);
			r_core_cmd0 (core, "/A");
			r_config_set_i (core->config, "search.maxhits", saved_maxhits);
			r_config_set_i (core->config, "search.from", saved_from);
			r_config_set_i (core->config, "search.to", saved_to);
		}
	}
	break;
	case 'a': // "pa"
	{
		ut32 new_bits = -1;
		int segoff, old_bits, pos = 0;
		ut8 settings_changed = false;
		char *new_arch = NULL, *old_arch = NULL, *hex = NULL;
		old_arch = strdup (r_config_get (core->config, "asm.arch"));
		old_bits = r_config_get_i (core->config, "asm.bits");
		segoff = r_config_get_i (core->config, "asm.segoff");
		if (input[1] != ' ') {
			if (input[0]) {
				for (pos = 1; pos < R_BIN_SIZEOF_STRINGS && input[pos]; pos++) {
					if (input[pos] == ' ') {
						break;
					}
				}
			}

			if (!r_core_process_input_pade (core, input + pos, &hex, &new_arch, &new_bits)) {
				// XXX - print help message
				// return false;
			}

			if (!new_arch) {
				new_arch = strdup (old_arch);
			}
			if (new_bits == -1) {
				new_bits = old_bits;
			}

			if (strcmp (new_arch, old_arch) != 0 || new_bits != old_bits) {
				r_core_set_asm_configs (core, new_arch, new_bits, segoff);
				r_anal_hint_set_bits (core->anal, core->offset, new_bits);
				settings_changed = true;
			}
		}
		if (input[1] == 'e') { // "pae"
			if (input[2] == '?') {
				r_cons_printf ("|Usage: pae [hex]       assemble esil from hexpairs\n");
			} else {
				int ret, bufsz;
				RAnalOp aop = {
					0
				};
				const char *str;
// char *buf = strdup (input+2);
				bufsz = r_hex_str2bin (hex, (ut8 *) hex);
				ret = r_anal_op (core->anal, &aop, core->offset,
					(const ut8 *) hex, bufsz);
				if (ret > 0) {
					str = R_STRBUF_SAFEGET (&aop.esil);
					r_cons_println (str);
				}
				r_anal_op_fini (&aop);
			}
		} else if (input[1] == 'D') {
			if (input[2] == '?') {
				r_cons_printf ("|Usage: paD [asm]       disasm like in pdi\n");
			} else {
				r_core_cmdf (core, "pdi@x:%s", input + 2);
			}
		} else if (input[1] == 'd') { // "pad"
			if (input[2] == '?') {
				r_cons_printf ("|Usage: pad [asm]       disasm\n");
			} else {
				RAsmCode *c;
				r_asm_set_pc (core->assembler, core->offset);
				c = r_asm_mdisassemble_hexstr (core->assembler, hex);
				if (c) {
					r_cons_print (c->buf_asm);
					r_asm_code_free (c);
				} else {
					eprintf ("Invalid hexstr\n");
				}
			}
		} else if (input[1] == '?') {
			r_cons_printf ("|Usage: pa[ed] [hex|asm]  assemble (pa) disasm (pad)"
				" esil (pae) from hexpairs\n");
		} else {
			RAsmCode *acode;
			int i;
			int bytes;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, input + 1);
			if (acode && *acode->buf_hex) {
				bytes = strlen (acode->buf_hex) >> 1;
				for (i = 0; i < bytes; i++) {
					ut8 b = acode->buf[i]; // core->print->big_endian? (bytes - 1 - i): i ];
					r_cons_printf ("%02x", b);
				}
				r_cons_newline ();
				r_asm_code_free (acode);
			}
		}
		if (settings_changed) {
			r_core_set_asm_configs (core, old_arch, old_bits, segoff);
			r_anal_hint_set_bits (core->anal, core->offset, old_bits);
			r_anal_build_range_on_hints (core->anal);
			r_core_seek_archbits (core, core->offset);
			// r_anal_hint_set_bits (core->anal, core->offset, oldbits);
		}
		free (hex);
		free (old_arch);
		free (new_arch);
	}
	break;
	case 'b': { // "pb"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: p[bB] [len] ([skip])  ; see also pB and pxb\n");
		} else if (l != 0) {
			int from, to;
			const int size = len * 8;
			char *spc, *buf = malloc (size + 1);
			spc = strchr (input, ' ');
			if (spc) {
				len = r_num_math (core->num, spc + 1);
				if (len < 1) {
					len = 1;
				}
				spc = strchr (spc + 1, ' ');
				if (spc) {
					from = r_num_math (core->num, spc + 1);
				} else {
					from = 0;
				}
				to = from + len;
			} else {
				from = 0;
				to = size;
			}
			if (buf) {
				int buf_len;
				r_str_bits (buf, block, size, NULL);
				buf_len = strlen (buf);
				if (from >= buf_len) {
					from = buf_len;
				}
				if (to < buf_len) {
					buf[to] = 0;
				}
				r_cons_println (buf + from);
				free (buf);
			} else {
				eprintf ("ERROR: Cannot malloc %d byte(s)\n", size);
			}
		}
	}
		break;
	case 'B': { // "pB"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: p[bB] [len]       bitstream of N bytes\n");
		} else if (l != 0) {
			int size;
			char *buf;
			if (!r_core_block_size (core, len)) {
				len = core->blocksize;
			}
			size = len * 8;
			buf = malloc (size + 1);
			if (buf) {
				r_str_bits (buf, core->block, size, NULL);
				r_cons_println (buf);
				free (buf);
			} else {
				eprintf ("ERROR: Cannot malloc %d byte(s)\n", size);
			}
		}
	}
		break;
	case 'I': // "pI"
		switch (input[1]) {
		case 'j': // "pIj" is the same as pDj
			if (l != 0) {
				if (input[2]) {
					cmd_pDj (core, input + 2);
				} else {
					cmd_pDj (core, sdb_fmt (0, "%d", core->blocksize));
				}
			}
			break;
		case 'f': // "pIf"
		{
			const RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (f) {
				r_core_print_disasm_instructions (core,
					r_anal_fcn_size (f), 0);
				break;
			}
		}
		case 'd': // "pId" is the same as pDi
			if (l) {
				r_core_disasm_pdi (core, 0, l, 0);
			}
			break;
		case '?': // "pi?"
			r_cons_printf ("|Usage: p[iI][df] [len]   print N instructions/bytes"
				"(f=func) (see pi? and pdi)\n");
			break;
		default:
			if (l) {
				r_core_print_disasm_instructions (core, l, 0);
			}
		}
		break;
	case 'i': // "pi"
		switch (input[1]) {
		case '?':
// r_cons_printf ("|Usage: pi[defj] [num]\n");
			r_core_cmd_help (core, help_msg_pi);
		break;
		case 'a': // "pia" is like "pda", but with "pi" output
			if (l != 0) {
				r_core_print_disasm_all (core, core->offset,
					l, len, 'i');
			}
			break;
		case 'j': // pij is the same as pdj
			if (l != 0) {
				cmd_pdj (core, input + 2, block);
			}
			break;
		case 'd': // "pid" is the same as pdi
			if (l != 0) {
				r_core_disasm_pdi (core, l, 0, 0);
			}
			break;
		case 'e': // "pie"
			if (l != 0) {
				r_core_disasm_pdi (core, l, 0, 'e');
			}
			break;
		case 'f': // "pif"
			if (l != 0) {
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (f) {
					ut32 bsz = core->blocksize;
					// int fsz = r_anal_fcn_realsize (f);
					int fsz = r_anal_fcn_size (f); // we want max-min here
					r_core_block_size (core, fsz);
					r_core_print_disasm_instructions (core, fsz, 0);
					r_core_block_size (core, bsz);
				} else {
					r_core_print_disasm_instructions (core,
						core->blocksize, l);
				}
			}
			break;
		case 'r': // "pir"
		{
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (f) {
				func_walk_blocks (core, f, input[1], 'I', input[2] == '.');
			} else {
				eprintf ("Cannot find function at 0x%08"PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
		}
		break;
		case 'b': // "pib"
		{
			RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->offset);
			if (b) {
					r_core_print_disasm_instructions (core, b->size - (core->offset - b->addr), 0);
			} else {
				eprintf ("Cannot find function at 0x%08"PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
		}
		break;
		default: // "pi"
			if (l != 0) {
				r_core_print_disasm_instructions (core, 0, l);
			}
			break;
		}
		goto beach;
	case 'D': // "pD"
	case 'd': // "pd"
	{
		ut64 current_offset = core->offset;
		ut32 new_bits = -1;
		ut64 use_blocksize = core->blocksize;
		int segoff, old_bits, pos = 0;
		ut8 settings_changed = false, bw_disassemble = false;
		char *new_arch = NULL, *old_arch = NULL;
		ut32 pd_result = false, processed_cmd = false;
		old_arch = strdup (r_config_get (core->config, "asm.arch"));
		segoff = r_config_get_i (core->config, "asm.segoff");
		old_bits = r_config_get_i (core->config, "asm.bits");
		bool formatted_json = false;

		if (input[1] && input[2]) {
			char *p = strchr (input, ' ');
			if (p) {
				int len = (int) r_num_math (core->num, p);
				if (len == 0) {
					break;
				}
			}
		}
		// XXX - this is necessay b/c radare will automatically
		// swap flags if arch is x86 and bits == 16 see: __setsegoff in config.c

		// get to the space
		if (input[0]) {
			for (pos = 1; pos < R_BIN_SIZEOF_STRINGS && input[pos]; pos++) {
				if (input[pos] == ' ') {
					break;
				}
			}
		}

		if (!process_input (core, input + pos, &use_blocksize, &new_arch, &new_bits)) {
			// XXX - print help message
			// return false;
		}
		if (!use_blocksize) {
			use_blocksize = core->blocksize;
		}

		if (core->blocksize_max < use_blocksize && (int) use_blocksize < -core->blocksize_max) {
			eprintf ("This block size is too big (%"PFMT64d "<%"PFMT64d "). Did you mean 'p%c @ 0x%08"PFMT64x "' instead?\n",
				(ut64) core->blocksize_max, (ut64) use_blocksize, input[0], (ut64) use_blocksize);
			free (old_arch);
			free (new_arch);
			goto beach;
		} else if (core->blocksize_max < use_blocksize && (int) use_blocksize > -(int)core->blocksize_max) {
			bw_disassemble = true;
			l = use_blocksize; // negative
			use_blocksize = -use_blocksize;
		} else {
			l = use_blocksize;
		}

		if (!new_arch) {
			new_arch = strdup (old_arch);
		}
		if (new_bits == -1) {
			new_bits = old_bits;
		}

		if (strcmp (new_arch, old_arch) != 0 || new_bits != old_bits) {
			r_core_set_asm_configs (core, new_arch, new_bits, segoff);
			// hints handy for arm
			r_anal_hint_set_bits (core->anal, core->offset, new_bits);
			settings_changed = true;
		}

		switch (input[1]) {
		case 'C': // "pdC"
			r_core_disasm_pdi (core, l, 0, 'C');
			pd_result = 0;
			processed_cmd = true;
			break;
		case 'c': // "pdc" // "pDc"
			r_core_pseudo_code (core, input + 2);
			pd_result = 0;
			processed_cmd = true;
			break;
		case 'k': // "pdk" -print class
		{
			int len = 0;
			ut64 at = findClassBounds (core, r_str_trim_ro (input + 2), &len);
			return r_core_cmdf (core, "pD %d @ %"PFMT64d, len, at);
		}
		case 'i': // "pdi" // "pDi"
			processed_cmd = true;
			if (*input == 'D') {
				r_core_disasm_pdi (core, 0, l, 0);
			} else {
				r_core_disasm_pdi (core, l, 0, 0);
			}
			pd_result = 0;
			break;
		case 'a': // "pda"
			processed_cmd = true;
			r_core_print_disasm_all (core, core->offset, l, len, input[2]);
			pd_result = true;
			break;
		case 'R': // "pdR"
			processed_cmd = true;
			disasm_recursive (core, core->offset, 'D');
			pd_result = true;
			break;
		case 'r': // "pdr"
			processed_cmd = true;
			{
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
				// R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f) {
					func_walk_blocks (core, f, input[2], 'D', input[2] == '.');
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x "\n", core->offset);
				}
				pd_result = true;
			}
			break;
		case 'b': // "pdb"
			processed_cmd = true;
			if (input[2] == '?') {
				r_cons_printf ("Usage: pdb[j]  - disassemble basic block\n");
			} else {
				RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->offset);
				if (b) {
					ut8 *block = malloc (b->size + 1);
					if (block) {
						r_core_read_at (core, b->addr, block, b->size);

						if (input[2] == 'j') {
							r_cons_print ("[");
							r_core_print_disasm_json (core, b->addr, block, b->size, 0);
							r_cons_print ("]\n");
						} else {
							core->num->value = r_core_print_disasm (
								core->print, core, b->addr, block,
								b->size, 9999, 0, 2, input[2] == 'J');
						}
						free (block);
						pd_result = 0;
					}
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x "\n", core->offset);
					core->num->value = 0;
				}
			}
			break;
		case 's': // "pds" and "pdsf"
			processed_cmd = true;
			if (input[2] == '?') {
				r_cons_printf ("Usage: pds[f]  - sumarize N bytes or function (pdfs)\n");
			} else {
				disasm_strings (core, input, NULL);
			}
			break;
		case 'f': // "pdf"
			processed_cmd = true;
			if (input[2] == '?') {
				r_cons_printf ("Usage: pdf[sj]  - disassemble function (summary+cjmp), json)\n");
			} else if (input[2] == 's') { // "pdfs"
				ut64 oseek = core->offset;
				int oblock = core->blocksize;
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (f) {
					r_core_seek (core, oseek, SEEK_SET);
					r_core_block_size (core, r_anal_fcn_size (f));
					disasm_strings (core, input, f);
					r_core_block_size (core, oblock);
					r_core_seek (core, oseek, SEEK_SET);
				}
				processed_cmd = true;
			} else {
				ut32 bsz = core->blocksize;
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
				RAnalFunction *tmp_func;
				ut32 cont_size = 0;
				RListIter *locs_it = NULL;
				if (f && f->fcn_locs) {
					locs_it = f->fcn_locs->head;
				}
				if (f && input[2] == 'j') { // "pdfj"
					ut8 *func_buf = NULL, *loc_buf = NULL;
					ut32 fcn_size = r_anal_fcn_realsize (f);
					cont_size = tmp_get_contsize (f);
					r_cons_printf ("{");
					r_cons_printf ("\"name\":\"%s\"", f->name);
					r_cons_printf (",\"size\":%d", fcn_size);
					r_cons_printf (",\"addr\":%"PFMT64d, f->addr);
					r_cons_printf (",\"ops\":[");
					// instructions are all outputted as a json list
					func_buf = calloc (cont_size, 1);
					bool first = true;
					if (func_buf) {
						// TODO: can loc jump to another locs?
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							if (tmp_func->addr > f->addr) {
								break;
							}
							cont_size = tmp_get_contsize (tmp_func);
							loc_buf = calloc (cont_size, 1);
							r_io_read_at (core->io, tmp_func->addr, loc_buf, cont_size);
							if (!first) {
								r_cons_print (",");
							}
							r_core_print_disasm_json (core, tmp_func->addr, loc_buf, cont_size, 0);
							first = false;
							free (loc_buf);
						}
						cont_size = tmp_get_contsize (f);
						r_io_read_at (core->io, f->addr, func_buf, cont_size);
						if (!first) {
							r_cons_print (",");
						}
						r_core_print_disasm_json (core, f->addr, func_buf, cont_size, 0);
						first = false;
						free (func_buf);
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							cont_size = tmp_get_contsize (tmp_func);
							loc_buf = calloc (cont_size, 1);
							if (loc_buf) {
								r_io_read_at (core->io, tmp_func->addr, loc_buf, cont_size);
								if (!first) {
									r_cons_print (",");
								}
								r_core_print_disasm_json (core, tmp_func->addr, loc_buf, cont_size, 0);
								first = false;
								free (loc_buf);
							}
						}
					} else {
						eprintf ("cannot allocate %d byte(s)\n", fcn_size);
					}
					r_cons_printf ("]}\n");
					pd_result = 0;
				} else if (f) {
#if 0
					for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
						if (tmp_func->addr > f->addr) {
							break;
						}
						cont_size = tmp_get_contsize (tmp_func);
						r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x, cont_size, tmp_func->addr);
					}
					cont_size = tmp_get_contsize (f);
#endif
					ut32 linear = f->_size;
					ut32 bbsum = r_anal_fcn_realsize (f);
					if (bbsum + 4096 < linear) {
						eprintf ("Linear size differs too much from the bbsum, please use pdr instead.\n");
					} else {
						r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x,
							f->_size > 0 ? f->_size: r_anal_fcn_realsize (f), f->addr);
					}
#if 0
					for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
						cont_size = tmp_get_contsize (tmp_func);
						r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x, cont_size, tmp_func->addr);
					}
#endif
					pd_result = 0;
				} else {
					eprintf ("pdf: Cannot find function at 0x%08"PFMT64x "\n", core->offset);
					processed_cmd = true;
					core->num->value = 0;
				}
				if (bsz != core->blocksize) {
					r_core_block_size (core, bsz);
				}
			}
			l = 0;
			break;
		case 'l': // pdl
			processed_cmd = true;
			{
				RAsmOp asmop;
				int j, ret;
				if (!l) {
					l = len;
				}
				r_cons_break_push (NULL, NULL);
				for (i = j = 0; i < core->blocksize && j < l; i += ret, j++) {
					ret = r_asm_disassemble (core->assembler, &asmop, block + i, len - i);
					if (r_cons_is_breaked ()) {
						break;
					}
					r_cons_printf ("%d\n", ret);
					if (ret < 1) {
						ret = 1;
					}
				}
				r_cons_break_pop ();
				pd_result = 0;
			}
			break;
		case 'j': // pdj
			processed_cmd = true;
			if (*input == 'D') {
				cmd_pDj (core, input + 2);
			} else {
				cmd_pdj (core, input + 2, block);
			}
			r_cons_newline ();
			pd_result = 0;
			break;
		case 'J': // pdJ
			formatted_json = true;
			break;
		case 0:
			/* "pd" -> will disassemble blocksize/4 instructions */
			if (*input == 'd' && !core->fixedblock) {
				l /= 4;
			}
			break;
		case '?': // "pd?"
			processed_cmd = true;
			r_core_cmd_help (core, help_msg_pd);
			pd_result = 0;
		}
		if (!processed_cmd) {
			ut64 addr = core->offset;
			ut8 *block1 = NULL;
			ut64 start;

			if (bw_disassemble) {
				block1 = malloc (core->blocksize);
				if (l < 0) {
					l = -l;
				}
				if (block1) {
					if (*input == 'D') { // pD
						free (block1);
						if (!(block1 = malloc (l)))
							break;
						r_core_read_at (core, addr - l, block1, l); // core->blocksize);
						core->num->value = r_core_print_disasm (core->print, core, addr - l, block1, l, l, 0, 1, formatted_json);
					} else { // pd
						int instr_len;
						if (r_core_prevop_addr (core, core->offset, l, &start)) {
							// We have some anal_info.
							instr_len = core->offset - start;
						} else {
							// anal ignorance.
							r_core_asm_bwdis_len (core, &instr_len, &addr, l);
						}
						ut64 prevaddr = core->offset;
						int bs = core->blocksize, bs1 = addrbytes * instr_len;
						if (bs1 > bs) {
							block1 = realloc (block1, bs1);
						}
						r_core_seek (core, prevaddr - instr_len, true);
						memcpy (block1, block, bs);
						if (bs1 > bs) {
							r_core_read_at (core, addr + bs / addrbytes, block1 + (bs - bs % addrbytes),
															bs1 - (bs - bs % addrbytes));
						}

						core->num->value = r_core_print_disasm (core->print,
							core, core->offset, block1, bs1, l, 0, 1, formatted_json);
						r_core_seek (core, prevaddr, true);
					}
				}
			} else {
				const int bs = core->blocksize;
				// XXX: issue with small blocks
				if (*input == 'D' && l > 0) {
					if (l < 1) {
						// eprintf ("Block size too small\n");
						return 1;
					}
					if (l > R_CORE_MAX_DISASM) { // pD
						eprintf ("Block size too big\n");
						return 1;
					}
					block1 = malloc (addrbytes * l);
					if (block1) {
						if (addrbytes * l > core->blocksize) {
							r_core_read_at (core, addr, block1, addrbytes * l); // core->blocksize);
						} else {
							memcpy (block1, block, addrbytes * l);
						}
						core->num->value = r_core_print_disasm (core->print,
							core, addr, block1, addrbytes * l, l, 0, 1, formatted_json);
					} else {
						eprintf ("Cannot allocate %d byte(s)\n", addrbytes * l);
					}
				} else {
					int bs1 = l * 16;
					block1 = malloc (R_MAX (bs, bs1));
					memcpy (block1, block, bs);
					if (bs1 > bs) {
						r_core_read_at (core, addr + bs / addrbytes, block1 + (bs - bs % addrbytes),
													  bs1 - (bs - bs % addrbytes));
					}
					core->num->value = r_core_print_disasm (core->print,
						core, addr, block1, bs1, l, 0, 0, formatted_json);
				}
			}
			free (block1);
			if (formatted_json) {
				r_cons_print ("\n");
			}
		}
		core->offset = current_offset;
		// change back asm setting if they were changed
		if (settings_changed) {
			r_core_set_asm_configs (core, old_arch, old_bits, segoff);
			r_anal_hint_set_bits (core->anal, core->offset, old_bits);
			r_anal_build_range_on_hints (core->anal);
			r_core_seek_archbits (core, core->offset);
		}
		free (old_arch);
		free (new_arch);
		if (processed_cmd) {
			ret = pd_result;
			goto beach;
		}
	}
	break;
	case 's': // "ps"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_ps);
			break;
		case 'j': // "psj"
			if (l > 0) {
				char *str, *type;
				ut64 vaddr = UT64_MAX;
				RBinObject *obj = r_bin_cur_object (core->bin);
				RBinSection *section = NULL;

				if (input[2] == ' ' && input[3]) {
					len = r_num_math (core->num, input + 3);
					len = R_MIN (len, core->blocksize);
				}
				/* try to get the section that contains the
				* string, by considering current offset as
				* paddr and if it isn't, trying to consider it
				* as vaddr. */
				if ((section = r_bin_get_section_at (obj, core->offset, true))) {
					vaddr = core->offset + section->vaddr - section->paddr;
				}

				r_cons_printf ("{\"string\":");
				str = r_str_utf16_encode ((const char *) core->block, len);
				r_cons_printf ("\"%s\"", str);
				r_cons_printf (",\"offset\":%"PFMT64d, core->offset);
				r_cons_printf (",\"section\":\"%s\"", vaddr == UT64_MAX? "unknown": section->name);
				r_cons_printf (",\"length\":%d", len);
				switch (get_string_type (core->block, len)) {
				case 'w': type = "wide"; break;
				case 'a': type = "ascii"; break;
				case 'u': type = "utf"; break;
				default: type = "unknown"; break;
				}
				r_cons_printf (",\"type\":\"%s\"}", type);
				r_cons_newline ();
				free (str);
			}
			break;
		case 'i': // "psi"
			if (l > 0) {
				ut8 *buf = malloc (1024);
				int delta = 512;
				ut8 *p, *e, *b;
				if (!buf) {
					return 0;
				}
				if (core->offset < delta) {
					delta = core->offset;
				}
				p = buf + delta;
				r_core_read_at (core, core->offset - delta, buf, 1024);
				for (b = p; b > buf; b--) {
					if (!IS_PRINTABLE (*b)) {
						b++;
						break;
					}
				}
				for (e = p; e < (buf + 1024); e++) {
					if (!IS_PRINTABLE (*b)) {
						*e = 0;
						e--;
						break;
					}
				}
				r_cons_strcat ((const char *) b);
				r_cons_newline ();
				// r_print_string (core->print, core->offset, b,
				// (size_t)(e-b), 0);
				free (buf);
			}
			break;
		case 'x': // "psx"
			if (l > 0) {
				r_print_string (core->print, core->offset, block, len, 0);
			}
			break;
		case 'b': // "psb"
			if (l > 0) {
				int quiet = input[2] == 'q'; // "psbq"
				char *s = malloc (core->blocksize + 1);
				int i, j, hasnl = 0;
				if (s) {
					memset (s, 0, core->blocksize);
					if (!quiet) {
						r_print_offset (core->print, core->offset, 0, 0, 0, 0, NULL);
					}
					// TODO: filter more chars?
					for (i = j = 0; i < core->blocksize; i++) {
						char ch = (char) block[i];
						if (!ch) {
							if (!hasnl) {
								s[j] = 0;
								if (*s) {
									r_cons_println (s);
									if (!quiet) {
										r_print_offset (core->print, core->offset + i, 0, 0, 0, 0, NULL);
									}
								}
								j = 0;
								s[0] = 0;
							}
							hasnl = 1;
							continue;
						}
						hasnl = 0;
						if (IS_PRINTABLE (ch)) {
							s[j++] = ch;
						}
					}
					s[j] = 0;
					r_cons_print (s); // TODO: missing newline?
					free (s);
				}
			}
			break;
		case 'z': // psz
			if (l > 0) {
				char *s = malloc (core->blocksize + 1);
				int i, j;
				if (s) {
					memset (s, 0, core->blocksize);
					// TODO: filter more chars?
					for (i = j = 0; i < core->blocksize; i++) {
						char ch = (char) core->block[i];
						if (!ch) {
							break;
						}
						if (IS_PRINTABLE (ch)) {
							s[j++] = ch;
						}
					}
					r_cons_println (s);
					free (s);
				}
			}
			break;
		case 'p': // "psp"
			if (l > 0) {
				int mylen = core->block[0];
				// TODO: add support for 2-4 byte length pascal strings
				if (mylen < core->blocksize) {
					r_print_string (core->print, core->offset,
						core->block + 1, mylen, R_PRINT_STRING_ZEROEND);
					core->num->value = mylen;
				} else {
					core->num->value = 0; // error
				}
			}
			break;
		case 'w': // "psw"
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block, len,
					R_PRINT_STRING_WIDE | R_PRINT_STRING_ZEROEND);
			}
			break;
		case 'W': // "psw"
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block, len,
					R_PRINT_STRING_WIDE32 | R_PRINT_STRING_ZEROEND);
			}
			break;
		case ' ': // "ps"
			r_print_string (core->print, core->offset, core->block, l, 0);
			break;
		case 'u': // "psu"
			if (l > 0) {
				char *str = r_str_utf16_encode (
					(const char *) core->block, len);
				r_cons_println (str);
				free (str);
			}
			break;
		case 's': // "pss"
			if (l > 0) {
				int h, w = r_cons_get_size (&h);
				int colwidth = r_config_get_i (core->config, "hex.cols") * 2;
				core->print->width = (colwidth == 32)?w: colwidth; // w;
				int bs = core->blocksize;
				if (len == bs) {
					len = (h * w) / 3;
					r_core_block_size (core, len);
				}
				r_print_string (core->print, core->offset, core->block,
						len, R_PRINT_STRING_WRAP);
				r_core_block_size (core, bs);
			}
			break;
		case '+': // "ps+"
			if (l > 0) {
				ut64 bitness = r_config_get_i (core->config, "asm.bits");
				if (bitness != 32 && bitness != 64) {
					eprintf ("Error: bitness of %" PFMT64u " not supported", bitness);
					break;
				}
				if (*core->block & 0x1) { // "long" string
					if (bitness == 64) {
						r_core_cmdf (core, "ps @ 0x%" PFMT64x, *((ut64 *)core->block + 2));
					} else {
						r_core_cmdf (core, "ps @ 0x%" PFMT32x, *((ut32 *)core->block + 2));
					}
				} else {
					r_print_string (core->print, core->offset, core->block + 1,
					                len, R_PRINT_STRING_ZEROEND);
				}
			}
			break;
		default:
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block,
					len, R_PRINT_STRING_ZEROEND);
			}
			break;
		}
		break;
	case 'm': // "pm"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: pm [file|directory]\n"
				"| r_magic will use given file/dir as reference\n"
				"| output of those magic can contain expressions like:\n"
				"|   foo@0x40   # use 'foo' magic file on address 0x40\n"
				"|   @0x40      # use current magic file on address 0x40\n"
				"|   \\n         # append newline\n"
				"| e dir.magic  # defaults to "R_MAGIC_PATH "\n"
				"| /m           # search for magic signatures\n"
				);
		} else {
			// XXX: need cmd_magic header for r_core_magic
			if (l > 0) {
				r_core_magic (core, input + 1, true);
			}
		}
		break;
	case 'u': // "pu"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: pu[w] [len]       print N url"
				"encoded bytes (w=wide)\n");
		} else {
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block, len,
					R_PRINT_STRING_URLENCODE |
					((input[1] == 'w')? R_PRINT_STRING_WIDE: 0));
			}
		}
		break;
	case 'c': // "pc"
		if (l) {
			const ut8 *buf = core->block;
			int i = 0;
			int j = 0;
			if (input[1] == 'A') { // "pcA"
				r_cons_printf ("sub_0x%08"PFMT64x ":\n", core->offset);
				for (i = 0; i < len; i++) {
					RAsmOp asmop = {
						0
					};
					(void) r_asm_disassemble (core->assembler, &asmop, buf + i, len - i);
					int sz = asmop.size;
					if (sz < 1) {
						sz = 1;
					}
					r_cons_printf (" .byte ");
					for (j = 0; j < sz; j++) {
						r_cons_printf ("%s0x%02x", j? ", ": "", buf[i]);
						i++;
					}
					r_cons_printf ("  // %s\n", asmop.buf_asm);
					i--;
				}
				r_cons_printf (".equ shellcode_len, %d\n", len);
			} else {
				r_print_code (core->print, core->offset, core->block, len, input[1]);
			}
		}
		break;
	case 'C': // "pC"
		switch (input[1]) {
		case 0:
		case ' ':
		case 'd':
			cmd_pCd (core, input + 2);
			break;
		case 'D':
			cmd_pCD (core, input + 2);
			break;
		case 'a':
			cmd_pCx (core, input + 2, "pxa");
			break;
		case 'A':
			cmd_pCx (core, input + 2, "pxA");
			break;
		case 'x':
			cmd_pCx (core, input + 2, "px");
			break;
		case 'w':
			cmd_pCx (core, input + 2, "pxw");
			break;
		case 'c':
			cmd_pCx (core, input + 2, "pc");
			break;
		default:
			eprintf ("Usage: pCd\n");
			break;
		}
		break;
	case 'r': // "pr"
		switch (input[1]) {
		case 'c': // "prc" // color raw dump
			cmd_prc (core, block, len);
			break;
		case '?':
			r_cons_printf ("|Usage: pr[glx] [size]\n"
				"| prc: print bytes as colors in palette\n"
				"| prl: print raw with lines offsets\n"
				"| prx: printable chars with real offset (hyew)\n"
				"| prg[?]: print raw GUNZIPped block\n"
				"| prz: print raw zero terminated string\n");
			break;
		case 'g': // "prg" // gunzip
			switch (input[2]) {
			case '?':
				r_cons_printf ("|Usage: prg[io]\n"
					"| prg: print gunzipped data of current block\n"
					"| prgi: show consumed bytes when inflating\n"
					"| prgo: show output bytes after inflating\n");
				break;
			case 'i': // "prgi"
			{
				int outlen = 0;
				int inConsumed = 0;
				ut8 *out;
				out = r_inflate (block, core->blocksize, &inConsumed, &outlen);
				r_cons_printf ("%d\n", inConsumed);
				free (out);
			}
			break;
			case 'o': // "prgo"
			{
				int outlen = 0;
				ut8 *out;
				out = r_inflate (block, core->blocksize, NULL, &outlen);
				r_cons_printf ("%d\n", outlen);
				free (out);
			}
			break;
			default:
			{
				int outlen = 0;
				ut8 *out;
				out = r_inflate (block, core->blocksize, NULL, &outlen);
				if (out) {
					r_cons_memcat ((const char *) out, outlen);
				}
				free (out);
			}
			}
			break;
		/* TODO: compact */
		case 'l': // "prl"
			if (l != 0) {
				printraw (core, len, 1);
			}
			break;
		case 'x': // "prx"
			if (l != 0) {
				printraw (core, len, 2);
			}
			break;
		case 'z': // "prz"
			if (l != 0) {
				printraw (core, strlen ((const char *) core->block), 0);
			}
			break;
		default:
			if (l != 0) {
				printraw (core, len, 0);
			}
			break;
		}
		break;
	case '3': // "p3" [file]
		if (input[1] == '?') {
			eprintf ("Usage: p3 [file] - print 3D stereogram image of current block\n");
		} else if (input[1] == ' ')          {
			char *data = r_file_slurp (input + 2, NULL);
			char *res = r_print_stereogram (data, 78, 20);
			r_print_stereogram_print (core->print, res);
			// if (data) eprintf ("%s\n", data);
			free (res);
			free (data);
		} else {
			char *res = r_print_stereogram_bytes (block, core->blocksize);
			r_print_stereogram_print (core->print, res);
			free (res);
		}
		break;
	case 'x': // "px"
	{
		int show_offset = r_config_get_i (core->config, "asm.offset");
		if (show_offset) {
			core->print->flags |= R_PRINT_FLAGS_OFFSET;
		} else {
			core->print->flags &= ~R_PRINT_FLAGS_OFFSET;
		}
		if (r_config_get_i (core->config, "hex.header")) {
			core->print->flags |= R_PRINT_FLAGS_HEADER;
		} else {
			core->print->flags &= ~R_PRINT_FLAGS_HEADER;
		}
		/* Don't show comments in default case */
		core->print->use_comments = false;
	}
		r_cons_break_push (NULL, NULL);
		switch (input[1]) {
		case 'j': // "pxj"
			r_print_jsondump (core->print, core->block, core->blocksize, 8);
			break;
		case '/': // "px/"
			r_core_print_examine (core, input + 2);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_px);
			break;
		case '0': // "px0"
			if (l) {
				int len = r_str_nlen ((const char *)core->block, core->blocksize);
				r_print_bytes (core->print, core->block, len, "%02x");
			}
			break;
		case 'a': // "pxa"
			if (l != 0) {
				if (len % 16) {
					len += 16 - (len % 16);
				}
				annotated_hexdump (core, input + 2, len);
			}
			break;
		case 'x': // "pxx"
			if (l != 0) {
				core->print->flags |= R_PRINT_FLAGS_NONHEX;
				r_print_hexdump (core->print, core->offset,
					core->block, len, 8, 1, 1);
				core->print->flags &= ~R_PRINT_FLAGS_NONHEX;
			}
			break;
		case 'X': // "pxX"
			if (l != 0) {
				ut8 *buf = calloc (len, 4);
				if (buf) {
					r_io_read_at (core->io, core->offset, buf, len * 4);
					core->print->flags |= R_PRINT_FLAGS_NONHEX;
					r_print_hexdump (core->print, core->offset, buf, len * 4, 8, 1, 1);
					core->print->flags &= ~R_PRINT_FLAGS_NONHEX;
					free (buf);
				}
			}
			break;
		case 'A': // "pxA"
			if (input[2] == '?') {
				eprintf ("Usage: pxA [len]   # f.ex: pxA 4K\n"
					" mv    move,lea,li\n"
					" ->    push\n"
					" <-    pop\n"
					" io    in/out ops\n"
					" $$    int/swi/trap/new\n"
					" ..    nop\n"
					" +-*/  math ops\n"
					" |&^   bin ops\n"
					" <<>>  shift ops\n"
					" _J    jump\n"
					" cJ    conditional jump\n"
					" _C    call\n"
					" _R    ret\n"
					" ==    cmp/test\n"
					" XX    invalid\n");
			} else if (l) {
				cmd_print_pxA (core, len, input + 1);
			}
			break;
		case 'b': // "pxb"
			if (l) {
				ut32 n;
				int i, c;
				char buf[32];
				for (i = c = 0; i < len; i++, c++) {
					if (c == 0) {
						r_print_offset (core->print,
							core->offset + i, 0, 0, 0, 0, NULL);
					}
					r_str_bits (buf, core->block + i, 8, NULL);

					// split bits
					memmove (buf + 5, buf + 4, 5);
					buf[4] = 0;

					r_cons_printf ("%s.%s  ", buf, buf + 5);
					if (c == 3) {
						const ut8 *b = core->block + i - 3;
						int (*k) (const ut8 *, int) = cmd_pxb_k;
						const char (*p) (char) = cmd_pxb_p;

						n = k (b, 0) | k (b, 1) | k (b, 2) | k (b, 3);
						r_cons_printf ("0x%08x  %c%c%c%c\n",
							n, p (b[0]), p (b[1]), p (b[2]), p (b[3]));
						c = -1;
					}
				}
			}
			break;
		case 'c': // "pxc"
			{
			int ocomments = core->print->use_comments;
			core->print->use_comments = core->print->flags & R_PRINT_FLAGS_COMMENT;
			if (l) {
				ut64 from = r_config_get_i (core->config, "diff.from");
				ut64 to = r_config_get_i (core->config, "diff.to");
				if (from == to && !from) {
					if (!r_core_block_size (core, len)) {
						len = core->blocksize;
					}
					r_print_hexdump (core->print, core->offset,
						core->block, len, 16, 1, 1);
				} else {
					r_core_print_cmp (core, from, to);
				}
				core->num->value = len;
			}
			core->print->use_comments = ocomments;
			}
			break;
		case 'i': // "pxi"
			if (l != 0) {
				r_print_hexii (core->print, core->offset, core->block,
					core->blocksize, r_config_get_i (core->config, "hex.cols"));
			}
			break;
		case 'o': // "pxo"
			if (l != 0) {
				r_print_hexdump (core->print, core->offset,
					core->block, len, 8, 1, 1);
			}
			break;
		case 't': // "pxt"
			if (input[2] == '?') {
				r_cons_printf ("Usage: pxt[.*] - print delta pointer table\n");
			} else {
				ut64 origin = core->offset;
				const char *arg = strchr (input, ' ');
				if (arg) {
					origin = r_num_math (core->num, arg + 1);
				}
				// _pointer_table does r_core_cmd with @, so it modifies core->block
				// and this results in an UAF access when iterating over the jmptable
				// so we do a new allocation to avoid that issue
				ut8 *block = calloc (len, 1);
				if (block) {
					memcpy (block, core->block, len);
					_pointer_table (core, origin, core->offset, block, len, 4, input[2]);
					free (block);
				}
			}
			break;
		case 'd': // "pxd"
			if (l != 0) {
				switch (input[2]) {
				case '1':
					// 1 byte signed words (byte)
					r_print_hexdump (core->print, core->offset,
						core->block, len, -1, 4, 1);
					break;
				case '2':
					// 2 byte signed words (short)
					r_print_hexdump (core->print, core->offset,
						core->block, len, -10, 2, 1);
					break;
				case '8':
					r_print_hexdump (core->print, core->offset,
						core->block, len, -8, 4, 1);
					break;
				case '4':
				default:
					// 4 byte signed words
					r_print_hexdump (core->print, core->offset,
						core->block, len, 10, 4, 1);
				}
			}
			break;
		case 'w': // "pxw"
			if (l != 0) {
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 32);
				} else {
					r_print_hexdump (core->print, core->offset, core->block, len, 32, 4, 1);
				}
			}
			break;
		case 'W': // "pxW"
			if (l) {
				len = len - (len % 4);
				for (i = 0; i < len; i += 4) {
					const char *a, *b;
					char *fn;
					RPrint *p = core->print;
					RFlagItem *f;
					ut32 v = r_read_ble32 (core->block + i, core->print->big_endian);
					if (p && p->colorfor) {
						a = p->colorfor (p->user, v, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					f = r_flag_get_at (core->flags, v, true);
					fn = NULL;
					if (f) {
						st64 delta = (v - f->offset);
						if (delta >= 0 && delta < 8192) {
							if (v == f->offset) {
								fn = strdup (f->name);
							} else {
								fn = r_str_newf ("%s+%d",
									f->name, v - f->offset);
							}
						}
					}
					r_cons_printf ("0x%08"PFMT64x " %s0x%08"PFMT64x "%s%s%s\n",
						(ut64) core->offset + i, a, (ut64) v,
						b,
						fn? " ": "",
						fn? fn: "");
					free (fn);
				}
			}
			break;
		case 'r': // "pxr"
			if (l) {
				if (input[2] == 'j') {
					int base = core->anal->bits;
					r_cons_printf ("[");
					const char *comma = "";
					const ut8 *buf = core->block;
					int withref = 0;
					for (i = 0; i < core->blocksize; i += (base / 4)) {
						ut64 addr = core->offset + i;
						ut64 *foo = (ut64 *) (buf + i);
						ut64 val = *foo;
						if (base == 32) {
							val &= UT32_MAX;
						}
						r_cons_printf ("%s{\"addr\":%"PFMT64d ",\"value\":%"\
							PFMT64d, comma, addr, val);
						comma = ",";
						// XXX: this only works in little endian
						withref = 0;
						if (core->print->hasrefs) {
							const char *rstr = core->print->hasrefs (core->print->user, val, true);
							if (rstr && *rstr) {
								char *ns; // r_str_ansi_trim (ns, -1, 0);
								ns = r_str_escape (rstr);
								r_cons_printf (",\"ref\":\"%s\"}", *ns == ' '? ns + 1: ns);
								free (ns);
								withref = 1;
							}
						}
						if (!withref) {
							r_cons_printf ("}");
						}
					}
					r_cons_printf ("]\n");
				} else {
					const int ocols = core->print->cols;
					int bitsize = core->assembler->bits;
					/* Thumb is 16bit arm but handles 32bit data */
					if (bitsize == 16) {
						bitsize = 32;
					}
					core->print->cols = 1;
					core->print->flags |= R_PRINT_FLAGS_REFS;
					r_cons_break_push (NULL, NULL);
					r_print_hexdump (core->print, core->offset,
						core->block, len,
						bitsize, bitsize / 8, 1);
					r_cons_break_pop ();
					core->print->flags &= ~R_PRINT_FLAGS_REFS;
					core->print->cols = ocols;
				}
			}
			break;
		case 'h': // "pxh"
			if (l) {
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 16);
				} else {
					r_print_hexdump (core->print, core->offset,
						core->block, len, 32, 2, 1);
				}
			}
			break;
		case 'H': // "pxH"
			if (l != 0) {
				len = len - (len % 2);
				for (i = 0; i < len; i += 2) {
					const char *a, *b;
					char *fn;
					RPrint *p = core->print;
					RFlagItem *f;
					ut64 v = (ut64) r_read_ble16 (core->block + i, p->big_endian);
					if (p && p->colorfor) {
						a = p->colorfor (p->user, v, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					f = r_flag_get_at (core->flags, v, true);
					fn = NULL;
					if (f) {
						st64 delta = (v - f->offset);
						if (delta >= 0 && delta < 8192) {
							if (v == f->offset) {
								fn = strdup (f->name);
							} else {
								fn = r_str_newf ("%s+%d", f->name, v - f->offset);
							}
						}
					}
					r_cons_printf ("0x%08"PFMT64x " %s0x%04"PFMT64x "%s %s\n",
						(ut64) core->offset + i, a, v, b, fn? fn: "");
					free (fn);
				}
			}
			break;
		case 'q': // "pxq"
			if (l) {
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 64);
				} else {
					r_print_hexdump (core->print, core->offset, core->block, len, 64, 8, 1);
				}
			}
			break;
		case 'Q': // "pxQ"
			// TODO. show if flag name, or inside function
			if (l) {
				len = len - (len % 8);
				for (i = 0; i < len; i += 8) {
					const char *a, *b;
					char *fn;
					RPrint *p = core->print;
					RFlagItem *f;
					ut64 v = r_read_ble64 (core->block + i, p->big_endian);
					if (p && p->colorfor) {
						a = p->colorfor (p->user, v, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					f = r_flag_get_at (core->flags, v, true);
					fn = NULL;
					if (f) {
						st64 delta = (v - f->offset);
						if (delta >= 0 && delta < 8192) {
							if (v == f->offset) {
								fn = strdup (f->name);
							} else {
								fn = r_str_newf ("%s+%d", f->name, v - f->offset);
							}
						}
					}
					r_cons_printf ("0x%08"PFMT64x " %s0x%016"PFMT64x "%s %s\n",
						(ut64) core->offset + i, a, v, b, fn? fn: "");
					free (fn);
				}
			}
			break;
		case 's': // "pxs"
			if (l) {
				core->print->flags |= R_PRINT_FLAGS_SPARSE;
				r_print_hexdump (core->print, core->offset, core->block, len, 16, 1, 1);
				core->print->flags &= (((ut32) - 1) & (~R_PRINT_FLAGS_SPARSE));
			}
			break;
		case 'e': // "pxe" // emoji dump
			if (l != 0) {
				int j;
				char emoji[] = {
					'\x8c', '\x80', '\x8c', '\x82', '\x8c', '\x85', '\x8c', '\x88',
					'\x8c', '\x99', '\x8c', '\x9e', '\x8c', '\x9f', '\x8c', '\xa0',
					'\x8c', '\xb0', '\x8c', '\xb1', '\x8c', '\xb2', '\x8c', '\xb3',
					'\x8c', '\xb4', '\x8c', '\xb5', '\x8c', '\xb7', '\x8c', '\xb8',
					'\x8c', '\xb9', '\x8c', '\xba', '\x8c', '\xbb', '\x8c', '\xbc',
					'\x8c', '\xbd', '\x8c', '\xbe', '\x8c', '\xbf', '\x8d', '\x80',
					'\x8d', '\x81', '\x8d', '\x82', '\x8d', '\x83', '\x8d', '\x84',
					'\x8d', '\x85', '\x8d', '\x86', '\x8d', '\x87', '\x8d', '\x88',
					'\x8d', '\x89', '\x8d', '\x8a', '\x8d', '\x8b', '\x8d', '\x8c',
					'\x8d', '\x8d', '\x8d', '\x8e', '\x8d', '\x8f', '\x8d', '\x90',
					'\x8d', '\x91', '\x8d', '\x92', '\x8d', '\x93', '\x8d', '\x94',
					'\x8d', '\x95', '\x8d', '\x96', '\x8d', '\x97', '\x8d', '\x98',
					'\x8d', '\x9c', '\x8d', '\x9d', '\x8d', '\x9e', '\x8d', '\x9f',
					'\x8d', '\xa0', '\x8d', '\xa1', '\x8d', '\xa2', '\x8d', '\xa3',
					'\x8d', '\xa4', '\x8d', '\xa5', '\x8d', '\xa6', '\x8d', '\xa7',
					'\x8d', '\xa8', '\x8d', '\xa9', '\x8d', '\xaa', '\x8d', '\xab',
					'\x8d', '\xac', '\x8d', '\xad', '\x8d', '\xae', '\x8d', '\xaf',
					'\x8d', '\xb0', '\x8d', '\xb1', '\x8d', '\xb2', '\x8d', '\xb3',
					'\x8d', '\xb4', '\x8d', '\xb5', '\x8d', '\xb6', '\x8d', '\xb7',
					'\x8d', '\xb8', '\x8d', '\xb9', '\x8d', '\xba', '\x8d', '\xbb',
					'\x8d', '\xbc', '\x8e', '\x80', '\x8e', '\x81', '\x8e', '\x82',
					'\x8e', '\x83', '\x8e', '\x84', '\x8e', '\x85', '\x8e', '\x88',
					'\x8e', '\x89', '\x8e', '\x8a', '\x8e', '\x8b', '\x8e', '\x8c',
					'\x8e', '\x8d', '\x8e', '\x8e', '\x8e', '\x8f', '\x8e', '\x92',
					'\x8e', '\x93', '\x8e', '\xa0', '\x8e', '\xa1', '\x8e', '\xa2',
					'\x8e', '\xa3', '\x8e', '\xa4', '\x8e', '\xa5', '\x8e', '\xa6',
					'\x8e', '\xa7', '\x8e', '\xa8', '\x8e', '\xa9', '\x8e', '\xaa',
					'\x8e', '\xab', '\x8e', '\xac', '\x8e', '\xad', '\x8e', '\xae',
					'\x8e', '\xaf', '\x8e', '\xb0', '\x8e', '\xb1', '\x8e', '\xb2',
					'\x8e', '\xb3', '\x8e', '\xb4', '\x8e', '\xb5', '\x8e', '\xb7',
					'\x8e', '\xb8', '\x8e', '\xb9', '\x8e', '\xba', '\x8e', '\xbb',
					'\x8e', '\xbd', '\x8e', '\xbe', '\x8e', '\xbf', '\x8f', '\x80',
					'\x8f', '\x81', '\x8f', '\x82', '\x8f', '\x83', '\x8f', '\x84',
					'\x8f', '\x86', '\x8f', '\x87', '\x8f', '\x88', '\x8f', '\x89',
					'\x8f', '\x8a', '\x90', '\x80', '\x90', '\x81', '\x90', '\x82',
					'\x90', '\x83', '\x90', '\x84', '\x90', '\x85', '\x90', '\x86',
					'\x90', '\x87', '\x90', '\x88', '\x90', '\x89', '\x90', '\x8a',
					'\x90', '\x8b', '\x90', '\x8c', '\x90', '\x8d', '\x90', '\x8e',
					'\x90', '\x8f', '\x90', '\x90', '\x90', '\x91', '\x90', '\x92',
					'\x90', '\x93', '\x90', '\x94', '\x90', '\x95', '\x90', '\x96',
					'\x90', '\x97', '\x90', '\x98', '\x90', '\x99', '\x90', '\x9a',
					'\x90', '\x9b', '\x90', '\x9c', '\x90', '\x9d', '\x90', '\x9e',
					'\x90', '\x9f', '\x90', '\xa0', '\x90', '\xa1', '\x90', '\xa2',
					'\x90', '\xa3', '\x90', '\xa4', '\x90', '\xa5', '\x90', '\xa6',
					'\x90', '\xa7', '\x90', '\xa8', '\x90', '\xa9', '\x90', '\xaa',
					'\x90', '\xab', '\x90', '\xac', '\x90', '\xad', '\x90', '\xae',
					'\x90', '\xaf', '\x90', '\xb0', '\x90', '\xb1', '\x90', '\xb2',
					'\x90', '\xb3', '\x90', '\xb4', '\x90', '\xb5', '\x90', '\xb6',
					'\x90', '\xb7', '\x90', '\xb8', '\x90', '\xb9', '\x90', '\xba',
					'\x90', '\xbb', '\x90', '\xbc', '\x90', '\xbd', '\x90', '\xbe',
					'\x91', '\x80', '\x91', '\x82', '\x91', '\x83', '\x91', '\x84',
					'\x91', '\x85', '\x91', '\x86', '\x91', '\x87', '\x91', '\x88',
					'\x91', '\x89', '\x91', '\x8a', '\x91', '\x8b', '\x91', '\x8c',
					'\x91', '\x8d', '\x91', '\x8e', '\x91', '\x8f', '\x91', '\x90',
					'\x91', '\x91', '\x91', '\x92', '\x91', '\x93', '\x91', '\x94',
					'\x91', '\x95', '\x91', '\x96', '\x91', '\x97', '\x91', '\x98',
					'\x91', '\x99', '\x91', '\x9a', '\x91', '\x9b', '\x91', '\x9c',
					'\x91', '\x9d', '\x91', '\x9e', '\x91', '\x9f', '\x91', '\xa0',
					'\x91', '\xa1', '\x91', '\xa2', '\x91', '\xa3', '\x91', '\xa4',
					'\x91', '\xa5', '\x91', '\xa6', '\x91', '\xa7', '\x91', '\xa8',
					'\x91', '\xa9', '\x91', '\xaa', '\x91', '\xae', '\x91', '\xaf',
					'\x91', '\xba', '\x91', '\xbb', '\x91', '\xbc', '\x91', '\xbd',
					'\x91', '\xbe', '\x91', '\xbf', '\x92', '\x80', '\x92', '\x81',
					'\x92', '\x82', '\x92', '\x83', '\x92', '\x84', '\x92', '\x85'
				};
				int cols = core->print->cols;
				if (cols < 1) {
					cols = 1;
				}
				for (i = 0; i < len; i += cols) {
					r_print_addr (core->print, core->offset + i);
					for (j = i; j < i + cols; j += 1) {
						ut8 *p = (ut8 *) core->block + j;
						if (j < len) {
							r_cons_printf ("\xf0\x9f%c%c ", emoji[*p * 2], emoji[*p * 2 + 1]);
						} else {
							r_cons_print ("  ");
						}
					}
					r_cons_print (" ");
					for (j = i; j < len && j < i + cols; j += 1) {
						ut8 *p = (ut8 *) core->block + j;
						r_print_byte (core->print, "%c", j, *p);
					}
					r_cons_newline ();
				}
			}
			break;
		case 'l': // "pxl"
			len = core->print->cols * len;
			/* fallthrough */
		default:
			if (l) {
				ut64 from = r_config_get_i (core->config, "diff.from");
				ut64 to = r_config_get_i (core->config, "diff.to");
				if (from == to && !from) {
					if (!r_core_block_size (core, len)) {
						len = core->blocksize;
					}
					r_print_hexdump (core->print, core->offset,
						core->block, len, 16, 1, 1);
				} else {
					r_core_print_cmp (core, from, to);
				}
				core->num->value = len;
			}
			break;
		}
		r_cons_break_pop ();
		break;
	case '2': // "p2"
		if (l) {
			if (input[1] == '?') {
				r_cons_printf ("|Usage: p2 [number of bytes representing tiles]\n"
					"NOTE: Only full tiles will be printed\n");
			} else {
				r_print_2bpp_tiles (core->print, core->block, len / 16);
			}
		}
		break;
	case '6': // "p6"
		if (l) {
			int malen = (core->blocksize * 4) + 1;
			ut8 *buf = malloc (malen);
			if (!buf) {
				break;
			}
			memset (buf, 0, malen);
			switch (input[1]) {
			case 'd': // "p6d"
				if (input[2] == '?') {
					r_cons_printf ("|Usage: p6d [len]    base 64 decode\n");
				} else if (r_base64_decode (buf, (const char *) block, len)) {
					r_cons_println ((const char *) buf);
				} else {
					eprintf ("r_base64_decode: invalid stream\n");
				}
				break;
			case 'e': // "p6e"
				if (input[2] == '?') {
					r_cons_printf ("|Usage: p6e [len]    base 64 encode\n");
					break;
				} else {
					len = len > core->blocksize? core->blocksize: len;
					r_base64_encode ((char *) buf, block, len);
					r_cons_println ((const char *) buf);
				}
				break;
			case '?':
			default:
				r_cons_printf ("|Usage: p6[ed] [len]    base 64 encode/decode\n");
				break;
			}
			free (buf);
		}
		break;
	case '8': // "p8"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: p8[fj] [len]     8bit hexpair list of bytes (see pcj)\n");
		} else if (l) {
			if (!r_core_block_size (core, len)) {
				len = core->blocksize;
			}
			block = core->block;
			if (input[1] == 'j') { // "p8j"
				r_core_cmdf (core, "pcj %s", input + 2);
			} else if (input[1] == 'f') { // "p8f"
				r_core_cmdf (core, "p8 $F @ $B");
			} else {
				r_print_bytes (core->print, block, len, "%02x");
			}
		}
		break;
	case 'f': // "pf"
		cmd_print_format (core, input, block, len);
		break;
	case 'k': // "pk"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: pk [len]       print key in randomart\n");
			r_cons_printf ("|Usage: pkill [process-name]\n");
		} else if (!strncmp (input, "kill", 4)) {
			RListIter *iter;
			RDebugPid *pid;
			const char *arg = strchr (input, ' ');
			RList *pids = (core->dbg->h && core->dbg->h->pids)
			? core->dbg->h->pids (core->dbg, 0): NULL;
			if (arg && *++arg) {
				r_list_foreach (pids, iter, pid) {
					if (strstr (pid->path, arg)) {
						r_cons_printf ("dk 9 %d\n", pid->pid);
					}
					// r_debug_kill (core->dbg, pid->pid, pid->pid, 9); // kill -9
				}
			}
			r_list_free (pids);
		} else if (l > 0) {
			len = len > core->blocksize? core->blocksize: len;
			char *s = r_print_randomart (block, len, core->offset);
			r_cons_println (s);
			free (s);
		}
		break;
	case 'K': // "pK"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: pK [len]       print key in randomart mosaic\n");
		} else if (l > 0) {
			len = len > core->blocksize? core->blocksize: len;
			int w, h;
			RConsCanvas *c;
			w = r_cons_get_size (&h);
			ut64 offset0 = core->offset;
			int cols = (w / 20);
			int rows = (h / 12);
			int i, j;
			char *s;
			if (rows < 1) {
				rows = 1;
			}
			c = r_cons_canvas_new (w, rows * 11);
			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					r_cons_canvas_gotoxy (c, j * 20, i * 11);
					core->offset += len;
					r_core_read_at (core, core->offset, core->block, len);
					s = r_print_randomart (core->block, len, core->offset);
					r_cons_canvas_write (c, s);
					free (s);
				}
			}
			r_cons_canvas_print (c);
			r_cons_canvas_free (c);
			r_core_read_at (core, offset0, core->block, len);
			core->offset = offset0;
			r_cons_printf ("\n");
		}
		break;
	case 'n': // easter
		eprintf ("easter egg license has expired\n");
		break;
	case 't': // "pt"
		switch (input[1]) {
		case ' ':
		case '\0':
			// len must be multiple of 4 since r_mem_copyendian move data in fours - sizeof(ut32)
			if (len < sizeof (ut32)) {
				eprintf ("You should change the block size: b %d\n", (int) sizeof (ut32));
			}
			if (len % sizeof (ut32)) {
				len = len - (len % sizeof (ut32));
			}
			for (l = 0; l < len; l += sizeof (ut32)) {
				r_print_date_unix (core->print, block + l, sizeof (ut32));
			}
			break;
		case 'h': // "pth"
			// len must be multiple of 4 since r_mem_copyendian move data in fours - sizeof(ut32)
			if (len < sizeof (ut32)) {
				eprintf ("You should change the block size: b %d\n", (int) sizeof (ut32));
			}
			if (len % sizeof (ut32)) {
				len = len - (len % sizeof (ut32));
			}
			for (l = 0; l < len; l += sizeof (ut32)) {
				r_print_date_hfs (core->print, block + l, sizeof (ut32));
			}
			break;
		case 'd': // "ptd"
			// len must be multiple of 4 since r_print_date_dos read buf+3
			// if block size is 1 or 5 for example it reads beyond the buffer
			if (len < sizeof (ut32)) {
				eprintf ("You should change the block size: b %d\n", (int) sizeof (ut32));
			}
			if (len % sizeof (ut32)) {
				len = len - (len % sizeof (ut32));
			}
			for (l = 0; l < len; l += sizeof (ut32)) {
				r_print_date_dos (core->print, block + l, sizeof (ut32));
			}
			break;
		case 'n': // "ptn"
			if (len < sizeof (ut64)) {
				eprintf ("You should change the block size: b %d\n", (int) sizeof (ut64));
			}
			if (len % sizeof (ut64)) {
				len = len - (len % sizeof (ut64));
			}
			for (l = 0; l < len; l += sizeof (ut64)) {
				r_print_date_w32 (core->print, block + l, sizeof (ut64));
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_pt);
			break;
		}
		break;
	case 'q': // "pq"
		if (input[1] == '?') {
			eprintf ("Usage: pq[z] [len]\n");
			break;
		}
		if (input[1] == 'z') { // "pqz"
			len = r_str_nlen ((const char *)block, core->blocksize);
		} else {
			if (len < 1) {
				len = 0;
			}
			if (len > core->blocksize) {
				len = core->blocksize;
			}
		}
		bool inverted = (input[1] == 'i'); // pqi -- inverted colors
		char *res = r_qrcode_gen (block, len, r_config_get_i (core->config, "scr.utf8"), inverted);
		if (res) {
			r_cons_printf ("%s\n", res);
			free (res);
		}
		break;
	case 'z': // "pz"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_pz);
		} else {
			RIOMap* map;
			RListIter *iter;
			RList *list = r_core_get_boundaries_prot (core, -1, NULL, "zoom");
			if (list) {
				RListIter *iter1 = list->head;
				RIOMap* map1 = iter1->data;
				from = map1->itv.addr;
				r_list_foreach (list, iter, map) {
					to = r_itv_end (map->itv);
				}	
			} else {
				from = core->offset;
				to = from + core->blocksize;
			}	
			ut64 maxsize = r_config_get_i (core->config, "zoom.maxsz");
			int oldva = core->io->va;
			char *oldmode = NULL;
			bool do_zoom = true;

			core->io->va = 0;
			if (input[1] && input[1] != ' ') {
				oldmode = strdup (r_config_get (core->config, "zoom.byte"));
				if (!r_config_set (core->config, "zoom.byte", input + 1)) {
					eprintf ("Invalid zoom.byte mode (%s)\n", input + 1);
					do_zoom = false;
				}
			}
			if (do_zoom && l > 0) {
				r_print_zoom (core->print, core, printzoomcallback,
					from, to, l, (int) maxsize);
			}

			if (oldmode) {
				r_config_set (core->config, "zoom.byte", oldmode);
			}
			core->io->va = oldva;
			R_FREE (oldmode);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_p);
		break;
	}
beach:
	if (tmpseek != UT64_MAX) {
		r_core_seek (core, tmpseek, SEEK_SET);
		r_core_block_read (core);
	}
	if (tbs != core->blocksize) {
		r_core_block_size (core, tbs);
	}
	return ret;
}

static int cmd_hexdump(void *data, const char *input) {
	return cmd_print (data, input - 1);
}

static int lenof(ut64 off, int two) {
	char buf[64];
	buf[0] = 0;
	if (two) {
		snprintf (buf, sizeof (buf), "+0x%"PFMT64x, off);
	} else {
		snprintf (buf, sizeof (buf), "0x%08"PFMT64x, off);
	}
	return strlen (buf);
}

// TODO : move to r_util? .. depends on r_cons...
// XXX: dupe of r_print_addr
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int offseg, int offdec, int delta, const char *label) {
	char space[32] = {
		0
	};
	const char *white;
	bool show_color = p->flags & R_PRINT_FLAGS_COLOR;
	if (show_color) {
		char rgbstr[32];
		const char *k = r_cons_singleton ()->pal.offset; // TODO etooslow. must cache
		if (p->flags & R_PRINT_FLAGS_RAINBOW) {
			k = r_cons_rgb_str_off (rgbstr, off);
		}
		if (invert) {
			r_cons_invert (true, true);
		}
		if (offseg) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off - a) >> 4;
			if (offdec) {
				snprintf (space, sizeof (space), "%d:%d", s & 0xffff, a & 0xffff);
				white = r_str_pad (' ', 9 - strlen (space));
				r_cons_printf ("%s%s%s"Color_RESET, k, white, space);
			} else {
				r_cons_printf ("%s%04x:%04x"Color_RESET,
					k, s & 0xFFFF, a & 0xFFFF);
			}
		} else {
			int sz = lenof (off, 0);
			int sz2 = lenof (delta, 1);
			if (delta > 0 || label) {
				if (label) {
					const int label_padding = 10;
					if (delta > 0) {
						if (offdec) {
							const char *pad = r_str_pad (' ', sz - sz2 + label_padding);
							r_cons_printf ("%s%s"Color_RESET "+%d%s", k, label, delta, pad);
						} else {
							const char *pad = r_str_pad (' ', sz - sz2 + label_padding);
							r_cons_printf ("%s%s"Color_RESET "+0x%x%s", k, label, delta, pad);
						}
					} else {
						const char *pad = r_str_pad (' ', sz + label_padding);
						r_cons_printf ("%s%s"Color_RESET "%s", k, label, pad);
					}
				} else {
					const char *pad = r_str_pad (' ', sz - sz2);
					if (offdec) {
						r_cons_printf ("%s+%d"Color_RESET, pad, delta);
					} else {
						r_cons_printf ("%s+0x%x"Color_RESET, pad, delta);
					}
				}
			} else {
				if (offdec) {
					snprintf (space, sizeof (space), "%"PFMT64d, off);
					white = r_str_pad (' ', 10 - strlen (space));
					r_cons_printf ("%s%s%s"Color_RESET, k, white, space, off);
				} else {
					r_cons_printf ("%s0x%08"PFMT64x ""Color_RESET, k, off);
				}
			}
		}
		r_cons_print (" ");
	} else {
		if (offseg) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off - a) >> 4;
			if (offdec) {
				snprintf (space, sizeof (space), "%d:%d", s & 0xffff, a & 0xffff);
				white = r_str_pad (' ', 9 - strlen (space));
				r_cons_printf ("%s%s"Color_RESET, white, space);
			} else {
				r_cons_printf ("%04x:%04x", s & 0xFFFF, a & 0xFFFF);
			}
		} else {
			int sz = lenof (off, 0);
			int sz2 = lenof (delta, 1);
			const char *pad = r_str_pad (' ', sz - 5 - sz2 - 3);
			if (delta > 0) {
				if (offdec) {
					r_cons_printf ("%s+%d"Color_RESET, pad, delta);
				} else {
					r_cons_printf ("%s+0x%x"Color_RESET, pad, delta);
				}
			} else {
				if (offdec) {
					snprintf (space, sizeof (space), "%"PFMT64d, off);
					white = r_str_pad (' ', 10 - strlen (space));
					r_cons_printf ("%s%s", white, space);
				} else {
					r_cons_printf ("0x%08"PFMT64x " ", off);
				}
			}
		}
	}
}
