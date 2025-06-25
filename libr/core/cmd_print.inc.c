/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

#define R_CORE_MAX_DISASM (1024 * 1024 * 8)
#define PF_USAGE_STR "pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]"

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size);

static RCoreHelpMessage help_msg_pa = {
	"Usage: pa[edD]", "[asm|hex]", "Print (dis)assembly",
	"pa", " [assembly]", "print hexpairs of the given assembly expression",
	"paD", " [hexpairs]", "print assembly expression from hexpairs and show hexpairs",
	"pad", " [hexpairs]", "print assembly expression from hexpairs (alias for pdx, pix)",
	"pade", " [hexpairs]", "print ESIL expression from hexpairs",
	"pae", " [assembly]", "print ESIL expression of the given assembly expression",
	NULL
};

static RCoreHelpMessage help_msg_psz = {
	"Usage: psz[jl]", "", "Print zero-terminated string",
	"psz", "", "print zero-terminated string",
	"psz*", "", "r2 command to write the null-terminated string in here",
	"pszj", "", "print zero-terminated string as json",
	"pszl", "", "print strlen of zero-terminated string in current address",
	NULL
};

static RCoreHelpMessage help_msg_psp = {
	"Usage: psp[124j]", "", "Print pascal string",
	"psp", "", "print zero-terminated string, taking length defined by the first byte (psp1)",
	"psp1", "", "same as psp",
	"psp2", "", "same as psp, but taking 2 byte for length",
	"psp4", "", "same as psp, but using 4 byte dword (honoring cfg.bigendian) for length",
	"pspj", "", "print pascal string in JSON",
	"pspw", "", "print zero-terminated 16bit wide string, taking length in bytes defined by the first byte (pspw1)",
	"pspw1", "", "same as pspw",
	"pspw2", "", "same as pspw, but taking 2 byte for length",
	"pspw4", "", "same as pspW, but using 4 byte dword (honoring cfg.bigendian) for length",
	"pspwj", "", "print pascal 16bit wide string in JSON",
	"pspW", "", "print zero-terminated 32bit wide string, taking length in bytes defined by the first byte (pspW1)",
	"pspW1", "", "same as pspW",
	"pspW2", "", "same as pspW, but taking 2 byte for length",
	"pspW4", "", "same as pspW, but using 4 byte dword (honoring cfg.bigendian) for length",
	"pspWj", "", "print pascal 32bit wide string in JSON",
	NULL
};

static RCoreHelpMessage help_msg_p8 = {
	"Usage: p8[*fjx]", " [len]", "8bit hexpair list of bytes (see pcj)",
	"p8", " ([len])", "print hexpairs string",
	"p8,", "", "comma separated 0xhexadecimal bytes",
	"p8*", "", "display r2 commands to write this block",
	"p8b", "", "print hexpairs of basic block",
	"p8d", "", "space separated list of byte values in decimal",
	"p8f", "[j]", "print hexpairs of function (linear)",
	"p8fm", "[j]", "print linear function byte:mask pattern (zero-filled bbgaps)",
	"p8j", "", "print hexpairs in JSON array",
	"p8s", "", "space separated hex bytes",
	"p8x", "", "print hexpairs honoring hex.cols",
	NULL
};

static RCoreHelpMessage help_msg_pm = {
	"Usage: pm", "[file|directory]", "Set libmagic reference file or directory (see /m?)",
	"pm", " [file|directory]", "set libmagic reference (see /m?)",
	"e", " dir.magic", "defaults to " R_JOIN_2_PATHS (R2_PREFIX, R2_SDB_MAGIC),
	NULL
};

static RCoreHelpMessage help_msg_pp = {
	"Usage: pp[d]", "", "print patterns",
	"pp0", "", "print buffer filled with zeros",
	"pp1", "", "print incremental byte pattern (honor lower bits of cur address and bsize)",
	"pp2", "", "print incremental word pattern",
	"pp4", "", "print incremental dword pattern",
	"pp8", "", "print incremental qword pattern",
	"ppa", "[lu]", "latin alphabet (lowercase, uppercases restrictions)",
	"ppd", "", "print debruijn pattern (see ragg2 -P, -q and wopD)",
	"ppf", "", "print buffer filled with 0xff",
	"ppn", "", "numeric pin patterns",
	NULL
};

static RCoreHelpMessage help_msg_pc = {
	"Usage:", "pc", " # Print in code",
	"pc",  "", "C",
	"pc*", "", "print 'wx' r2 commands",
	"pcA", "", ".bytes with instructions in comments",
	"pca", "", "GAS .byte blob",
	"pcc", "", "C char * multiline string",
	"pcd", "", "C dwords (8 byte)",
	"pch", "", "C half-words (2 byte)",
	"pci", "", "C array of bytes with instructions",
	"pcJ", "", "javascript",
	"pcj", "", "json",
	"pck", "", "kotlin",
	"pco", "", "Objective-C",
	"pcp", "", "python",
	"pcq", "", "quiet C (include-friendly)",
	"pcr", "", "rust",
	"pcg", "", "Golang",
	"pcS", "", "shellscript that reconstructs the bin",
	"pcs", "", "string",
	"pcn", "", "space separated list of numbers",
	"pcv", "", "JaVa",
	"pcV", "", "V (vlang.io)",
	"pcw", "", "C words (4 byte)",
	"pcy", "", "yara",
	"pcY", "", "quiet yara",
	"pcz", "", "Swift",
	NULL
};

static RCoreHelpMessage help_msg_p6 = {
	"Usage: p6[d|e][s|z]", " [len]", "base64 decoding/encoding",
	"p6d", "[s|z] [len]", "decode current block as base64",
	"p6e", "[s|z][len]", "encode current block in base64",
	"p6ez", "", "encode base64 zero-terminated string",
	"p6es", " hello world", "encode given string to base64",
	"p6ds", " AAA=", "decode given base64 string",
	"p6dz", "", "decode null-terminated base64 string in block",
	NULL
};

static RCoreHelpMessage help_msg_pF = {
	"Usage: pF[apdbA][*vqj]", "[len]", "parse ASN1, PKCS, X509, DER, protobuf, axml",
	"pFa", "[jqt] [len]", "decode ASN1/DER from current block (PEM is B64(DER))",
	"pFA", "[j] [len]", "decode Android Binary XML from current block",
	"pFb", "[vj] [len]", "decode raw proto buffers in (verbose, JSON) format",
	"pFB", "[j] [len]", "decode iOS Binary PLIST from current block",
	"pFo", "[j] [len]", "decode ASN1 OID",
	"pFp", "[j] [len]", "decode PKCS7",
	"pFx", "[j] [len]", "Same with X509",
	"pFX", " [len]", "print decompressed xz block",
	NULL
};

static RCoreHelpMessage help_msg_pri = {
	"Usage: pri", "[n1sg]", "print raw images",
	"prin", "t [msg]", "print a message",
	"pri1", "", "1 bitmap image",
	"pris", "", "sixel image",
	"prig", "", "greyscale image",
	"prir", "", "RGB image (same as pri)",
	"pri4", "", "RGBA image",
	NULL
};
static RCoreHelpMessage help_msg_pr = {
	"Usage: pr[glx]", "[size]", "print N raw bytes",
	"prc", "[=fep..]", "print bytes as colors in palette",
	"prg", "[?]", "print raw GUNZIPped block",
	"pri", "[aA12r]", "print raw image, 1bit image, honor hex.cols",
	"print", "[f][ln]", "print, println, printf, printfln",
	"prl", "", "print raw with lines offsets",
	"prx", "", "printable chars with real offset (hyew)",
	"prz", "", "print raw zero terminated string",
	NULL
};

static RCoreHelpMessage help_msg_prg = {
	"Usage: prg[?ilo]", " [len]", "print raw inflated/decompressed block",
	"prg", "", "print gunzipped data of current block",
	"prgl", "", "decompress current block using LZ4 (adjust blocksize)",
	"prgi", "", "show consumed bytes when inflating",
	"prgo", "", "show output bytes after inflating",
	NULL
};

static RCoreHelpMessage help_msg_amper = {
	"Usage:", "&[-|<cmd>]", "Manage tasks (WARNING: Experimental. Use with caution!)",
	"&", " <cmd>", "run <cmd> in a new background task",
	"&:", "<cmd>", "queue <cmd> to be executed later when possible",
	"&t", " <cmd>", "run <cmd> in a new transient background task (auto-delete when it is finished)",
	"&", "", "list all tasks",
	"&j", "", "list all tasks (in JSON)",
	"&=", " 3", "show output of task 3",
	"&b", " 3", "break task 3",
	"&w", "", "wait for queued commands and execute them (^C to end)",
	"&-", " 1", "delete task #1 or schedule for deletion when it is finished",
	"&", "-*", "delete all done tasks",
	"&?", "", "show this help",
	"&&", " 3", "wait until task 3 is finished",
	"&&", "", "wait until all tasks are finished",
	NULL
};

static RCoreHelpMessage help_msg_p = {
	"Usage:", "p[=68abcdDfiImrstuxz] [arg|len] [@addr]", "",
	// "p", "[b|B|xb] [len] ([S])", "bindump N bits skipping S bytes",
	// "p", "[iI][df] [len]", "print N ops/bytes (f=func) (see pi? and pdi)",
	//"p", "[kK] [len]", "print key in randomart (K is for mosaic)",
	"p-", "[?][jh] [mode]", "bar|json|histogram blocks (mode: e?search.in)",
	"p2", " [len]", "8x8 2bpp-tiles",
	"p3", " [file]", "print 3D stereogram image of current block",
	"p6", "[de] [len]", "base64 decode/encode",
	"p8", "[?][bdfsjx] [len]", "8bit hexpair list of bytes",
	"p=", "[?][bep] [N] [L] [b]", "show entropy/printable chars/chars bars",
	"pa", "[?][edD] [arg]", "pa:assemble  pa[dD]:disasm or pae: esil from hex",
	"pA", "[n_ops]", "show n_ops address and type",
	"pb", "[?] [n]", "bitstream of N bits",
	"pB", "[?] [n]", "bitstream of N bytes",
	"pc", "[?][p] [len]", "output C (or python) format",
	"pC", "[aAcdDxw] [rows]", "print disassembly in columns (see hex.cols and pdi)",
	"pd", "[?] [sz] [a] [b]", "disassemble N opcodes (pd) or N bytes (pD)",
	"pf", "[?][.name] [fmt]", "print formatted data (pf.name, pf.name $<expr>)",
	"pF", "[?][apx]", "print asn1, pkcs7 or x509",
	"pg", "[?][x y w h] [cmd]", "create new visual gadget or print it (see pg? for details)",
	"ph", "[?][=|hash] ([len])", "calculate hash for a block",
	"pi", "[?][bdefrj] [num]", "print instructions",
	"pI", "[?][iI][df] [len]", "print N instructions/bytes (f=func)",
	"pj", "[?] [len]", "print as indented JSON",
	"pk", " [len]", "print key in randomart",
	"pK", " [len]", "print key in randomart whole-screen mosaic",
	"pl", "[?][format] [arg]", "print list of data (pl Ffvc)",
	"pm", "[?] [magic]", "print libmagic data (see pm? and /m?)",
	"po", "[?] hex", "print operation applied to block (see po?)",
	"pp", "[?][sz] [len]", "print patterns, see pp? for more help",
	"pq", "[?][is] [len]", "print QR code with the first Nbytes",
	"pr", "[?][glx] [len]", "print N raw bytes (in lines or hexblocks, 'g'unzip)",
	"ps", "[?][pwz] [len]", "print pascal/wide/zero-terminated strings",
	"pt", "[?][dn] [len]", "print different timestamps",
	"pu", "[w] [len]", "print N url encoded bytes (w=wide)",
	"pv", "[?][ejh] [mode]", "show value of given size (1, 2, 4, 8)",
	"pwd", "", "display current working directory",
	"px", "[?][owq] [len]", "hexdump of N bytes (o=octal, w=32bit, q=64bit)",
	"py", "([-:file]) [expr]", "print clipboard (yp) run python script (py:file) oneliner `py print(1)` or stdin slurp `py-`",
	"pz", "[?] [len]", "print zoom view (see pz? for help)",
	"pkill", " [process-name]", "kill all processes with the given name",
	"pushd", " [dir]", "cd to dir and push current directory to stack",
	"popd", "[-a][-h]", "pop dir off top of stack and cd to it",
	NULL
};

static RCoreHelpMessage help_msg_pxd = {
	"Usage:", "pxd[1248] ([len])", "show decimal byte/short/word/dword dumps",
	"pxd", "", "show base10 signed decimal hexdumps",
	"pxd1", "", "show byte hexdump (int8_t)",
	"pxd2", "", "show short hexdump (int16_t)",
	"pxd4", "", "show dword hexdump (int32_t)",
	"pxd8", "", "show qword hexdump (int64_t)",
	NULL
};

static RCoreHelpMessage help_msg_pxu = {
	"Usage:", "pxu[1248] ([len])", "show unsigned decimal byte/short/word/dword dumps",
	"pxu", "", "show base10 unsigned decimal hexdumps",
	"pxu1", "", "show byte hexdump (int8_t)",
	"pxu2", "", "show short hexdump (int16_t)",
	"pxu4", "", "show dword hexdump (int32_t)",
	"pxu8", "", "show qword hexdump (int64_t)",
	NULL
};

static RCoreHelpMessage help_msg_prc = {
	"Usage:", "prc=[#] ([size]) ", "see p=? to find valid values for #",
	"prc", "", "print bytes as colors in palette",
	"prcb", "", "print nibble bits as colors in palette",
	"prcn", "", "print nibbles as colors in palette",
	"prc=e", "", "entropy",
	NULL
};
static RCoreHelpMessage help_msg_p_equal = {
	"Usage:", "p=[=bep?][qj] [N] ([len]) ([offset]) ", "show entropy/printable chars/chars bars",
	"e ", "zoom.in", "specify range for zoom",
	"p=", "", "print bytes of current block in bars",
	"p==", "[..]", "same subcommands as p=, using column bars instead of rows",
	"p=", "0", "number of 0x00 bytes for each filesize/blocksize",
	"p=", "2", "short (signed int16) bars, good for waves",
	"p=", "a", "analysis bbs maps",
	"p=", "A", "analysis stats maps (see p-)",
	"p=", "b", "same as above",
	"p=", "c", "number of calls per block",
	"p=", "d", "min/max/number of unique bytes in block",
	"p=", "e", "entropy for each filesize/blocksize",
	"p=", "F", "number of 0xFF bytes for each filesize/blocksize",
	"p=", "i", "number of invalid instructions per block",
	"p=", "j", "number of jumps and conditional jumps in block",
	"p=", "m", "number of flags and marks in block",
	"p=", "p", "number of printable bytes for each filesize/blocksize",
	"p=", "s", "number of syscall and privileged instructions",
	"p=", "z", "number of chars in strings in block",
	NULL
};

static RCoreHelpMessage help_msg_pj = {
	"Usage:", "pj[..] [size]", "",
	"pj", "", "print current block as indented JSON",
	"pj.", "", "print as indented JSON from 0 to the current offset",
	"pj..", "", "print JSON path from 0 to the current offset",
	NULL
};

static RCoreHelpMessage help_msg_p_minus = {
	"Usage:", "p-[hej] [nblocks] ", "bar|json|histogram blocks",
	"p-", " [nblocks]", "show ascii-art bar of metadata in file boundaries",
	"p-e", " [nblocks]", "show ascii-art bar of entropy per block",
	"p-h", " [nblocks]", "show histogram analysis of metadata per block",
	"p-j", " [nblocks]", "show json format",
	NULL
};

static RCoreHelpMessage help_msg_pdf = {
	"Usage:", "pdf[sj]", " # disassemble function (needs to be analized with 'af' or so)",
	"pdf", "", "disassemble function in a linear way (see pdfr)",
	"pdfj", "", "disassemble function in json (see pdfJ)",
	"pdfr", "", "disassemble function recursively (alias for pdr)",
	"pdfs", "", "disassemble function summary (see also pdsf)",
	NULL,
};

static RCoreHelpMessage help_msg_pd = {
	"Usage:", "p[dD][ajbrfils] [[-]len]", " # Print N bytes/instructions bw/forward",
	"NOTE: ", "len", "parameter can be negative",
	"NOTE: ", "", "Pressing ENTER on empty command will repeat last print command in next page",
	"pD", " N", "disassemble N bytes",
	"pd", " -N", "disassemble N instructions backwards",
	"pd", " N", "disassemble N instructions",
	"pd--", " N", "context disassembly of N instructions",
	"pda", "", "disassemble all possible opcodes (byte per byte)",
	"pdaj", "", "disassemble all possible opcodes (byte per byte) in JSON",
	"pdb", "[j]", "disassemble basic block (j for JSON)",
	"pdc", "[?][c]", "pseudo disassembler output in C-like syntax",
	"pdC", "", "show comments found in N instructions",
	"pde", "[q|qq|j] N", "disassemble N instructions following execution flow from current PC",
	"pdo", " N", "convert esil expressions of N instructions to C (pdO for bytes)",
	"pdf", "[?]", "disassemble function",
	"pdi", "", "like 'pi', with offset and bytes",
	"pdj", "", "disassemble to json",
	"pdJ", "", "formatted disassembly like pd as json",
	"pdk", "[?]", "disassemble all methods of a class",
	"pdl", "", "show instruction sizes",
	"pdp", "", "disassemble by following pointers to read ropchains",
	"pdr", "", "recursive disassemble across the function graph",
	"pdr.", "", "recursive disassemble across the function graph (from current basic block)",
	"pdR", "", "recursive disassemble block size bytes without analyzing functions",
	"pds", "[?]", "print disasm summary, showing referenced names",
	"pdu", "[aceios?]", "disassemble instructions until condition",
	"pd,", " [n] [query]", "disassemble N instructions in a table (see dtd for debug traces)",
	"pdx", " [hex]", "alias for pad or pix",
	NULL
};

static RCoreHelpMessage help_msg_pds = {
	"Usage:", "pds[*|b|f|s] [N]", "Print strings in the disassembly",
	"pds", "[?]", "print disasm summary, showing referenced names",
	"pds*", "[?]", "print r2 commands addings comments for each string reference",
	"pdsb", " [N]", "basic block summary",
	"pdsf", "[sjq]", "show function summary of strings, calls, variables, references..",
	"pdss", " [N]", "string summary in current function",
	NULL
};

static RCoreHelpMessage help_msg_pde = {
	"Usage:", "pde[q|qq|j] [N]", "Disassemble N instructions following execution flow from current PC",
	"pde", "", "disassemble N instructions following execution flow from current PC",
	"pdeq", "", "disassemble N instructions following execution flow from current PC (like pdi)",
	"pdeqq", "", "disassemble N instructions following execution flow from current PC (like pi)",
	"pdej", "", "disassemble N instructions following execution flow from current PC in JSON",
	NULL
};

static RCoreHelpMessage help_msg_ph = {
	"Usage:", "ph", " [algorithm] ([size])",
	"ph", " md5", "compute md5 hash of current block",
	"ph", ":md5", "same as 'ph md5' (colon acts as a space)",
	"ph", " sha1 32 @ 0x1000", "calculate sha1 of 32 bytes starting at 0x1000",
	"ph", "", "list available hash plugins (same as Lh and phl/phL)",
	"phj", "", "list available hash plugins in json",
	NULL
};

static RCoreHelpMessage help_msg_pdu = {
	"Usage:", "pdu[acios][j]", "Disassemble instructions until condition",
	"pdua", "[j] [addr]", "disassemble until address",
	"pduc", "[j]", "disassemble until call",
	//"pdue", "[j] [expr]", "disassemble until esil expression",
	"pdui", "[j] [inst]", "disassemble until instruction (e.g.: add esp, 0x20)",
	"pduo", "[j] [opcode]", "disassemble until opcode (e.g.: mul)",
	"pdus", "[j]", "disassemble until syscall",
	NULL
};

static RCoreHelpMessage help_msg_pfb = {
	"Usage:", "pfb", "print formatted bitfields",
	"pfb", " [fmt] [fnames]", "print formatted bitfield in ascii art",
	"pfbc", " [fmt] [fnames]", "same as pfb, but using C syntax",
	"pfbj", " [fmt] [fnames]", "same as pfb but in json output",
	"pfbq", " [fmt] [fnames]", "same as pfb, but quieter oneliner",
	"pfbd", " [fmt] [fnames]", "same as pfb, but for debugging reasons",
	"Examples:", "", "",
	" ", "pfb 3b4b foo bar", "2 bitfields, first of 3 bits and second of 4",
	" ", "pfb 3b+4b foo bar", "same as above, the + sign is ignored",
	" ", "pfb 3b..4b foo bar", "same as above, but separated by 2 unused bits",
	" ", "pfb 3b2.4b foo bar", "same as above, you can use digits and dot",
	NULL
};

static RCoreHelpMessage help_msg_pf = {
	"Usage:", PF_USAGE_STR, "",
	"Commands:", "", "",
	"pf", " fmt", "show data using the given format-string. See 'pf\?\?' and 'pf\?\?\?'.",
	"pf", "?", "help on commands",
	"pf", "??", "help on format characters",
	"pf", "???", "show usage examples",
	"pf* ", "fmt_name|fmt", "show data using (named) format as r2 flag create commands",
	"pf.", "", "list all format definitions",
	"pf.", "fmt_name", "show data using named format",
	"pf.", "fmt_name.field_name", "show specific data field using named format",
	"pf.", "fmt_name.field_name=33", "set new value for the specified field in named format",
	"pf.", "fmt_name.field_name[i]", "show element i of array field_name",
	"pf.", "fmt_name [0|cnt]fmt", "define a new named format",
	"pf?", "fmt_name", "show the definition of a named format",
	"pfb", "[?] bitfmt", "print formatted bitfields",
	"pfc", " fmt_name|fmt", "show data using (named) format as C string",
	"pfd.", "fmt_name", "show data using named format as graphviz commands",
	"pfj ", "fmt_name|fmt", "show data using (named) format in JSON",
	"pfo", " fdf_name", "load a Format Definition File (fdf)",
	"pfo", "", "list all format definition files (fdf)",
	"pfq", " fmt ...", "quiet print format (do now show address)",
	"pfs", "[.fmt_name|fmt]", "print the size of (named) format in bytes",
	"pfv.", "fmt_name[.field]", "print value(s) only for named format. Useful for one-liners",
	NULL
};

static RCoreHelpMessage help_detail_pf = {
	"Usage:", PF_USAGE_STR, "",
	"Format:", "", "",
	" ", "b", "byte (unsigned)",
	" ", "B", "resolve enum bitfield (see t?)",
	" ", "c", "char (signed byte)",
	" ", "C", "byte in decimal",
	" ", "d", "dword (4 bytes in hex) (see 'i' and 'x')",
	" ", "D", "disassemble one opcode",
	" ", "e", "temporally swap endian",
	" ", "E", "resolve enum name (see t?)",
	" ", "f", "float value (4 bytes)",
	" ", "F", "double value (8 bytes)",
	" ", "G", "long double value (16 bytes (10 with padding))",
	" ", "i", "signed integer value (4 bytes) (see 'd' and 'x')",
	" ", "n", "next char specifies size of signed value (1, 2, 4 or 8 byte(s))",
	" ", "N", "next char specifies size of unsigned value (1, 2, 4 or 8 byte(s))",
	" ", "o", "octal value (4 byte)",
	" ", "p", "pointer reference (2, 4 or 8 bytes)",
	" ", "q", "quadword (8 bytes)",
	" ", "Q", "uint128_t (16 bytes)",
	" ", "r", "CPU register `pf r (eax)plop`",
	" ", "s", "32bit pointer to string (4 bytes)",
	" ", "S", "64bit pointer to string (8 bytes)",
	" ", "t", "UNIX timestamp (4 bytes)",
	" ", "T", "show Ten first bytes of buffer",
	" ", "u", "uleb128 (variable length)",
	" ", "w", "word (2 bytes unsigned short in hex)",
	" ", "x", "0xHEX value and flag (fd @ addr) (see 'd' and 'i')",
	" ", "X", "show formatted hexpairs",
	" ", "z", "null terminated string",
	" ", "Z", "null terminated wide string",
	" ", "?", "data structure `pf ? (struct_name)example_name`",
	" ", "*", "next char is a pointer (honors asm.bits)",
	" ", "+", "toggle show flags for each offset",
	" ", ":", "skip 4 bytes",
	" ", ".", "skip 1 byte",
	" ", ";", "rewind 4 bytes",
	" ", ",", "rewind 1 byte",
	NULL
};

static RCoreHelpMessage help_detail2_pf = {
	"Usage:", PF_USAGE_STR, "",
	"Examples:", "", "",
	"pf", " 3xi foo bar", "3-array of struct, each with named fields: 'foo' as hex, and 'bar' as int",
	"pf", " B (BitFldType)arg_name`", "bitfield type",
	"pf", " E (EnumType)arg_name`", "enum type",
	"pf", " *z*i*w nb name blob", "print the pointers with given labels",
	"pf", " iwq foo bar troll", "print the iwq format with foo, bar, troll as the respective names for the fields",
	"pf", " 0iwq foo bar troll", "same as above, but considered as a union (all fields at offset 0)",
	"pf.", "obj xxdz prev next size name", "define the obj format as xxdz",
	"pf", " obj=xxdz prev next size name", "same as above",
	"pf.", "plop ? (troll)mystruct", "use structure troll previously defined",
	"pfj.", "plop @ 0x14", "apply format object at the given offset",
	"pf", " 10xiz pointer length string", "print a size 10 array of the xiz struct with its field names",
	"pf", " 5sqw string quad word", "print an array with sqw struct along with its field names",
	"pf", " 3? (bifc)", "print 3 times the following format (bifc)",
	"pf", " [4]w[7]i", "print an array of 4 words and then an array of 7 integers",
	"pf", " ic...?i foo bar \"(pf xw yo foo)troll\" yo", "print nested anonymous structures",
	"pf", " :..x", "print value located 6 bytes from current offset",
	"pf", " \";x\"", "print value located 4 bytes before current offset",
	"pf", " [10]z[3]i[10]Zb", "print an fixed size str, widechar, and var",
	"pfj", " +F @ 0x14", "print the content at given offset with flag",
	"pf", " n2", "print signed short (2 bytes) value. Use N instead of n for printing unsigned values",
	"pf", " [2]? (plop)structname @ 0", "prints an array of structs",
	"pf", " eqew bigWord beef", "swap endianness and print with given labels",
	"pf", ".foo rr (eax)reg1 (eip)reg2", "create object referencing to register values ",
	"pf", " tt troll plop", "print time stamps with labels troll and plop",
	NULL
};

static RCoreHelpMessage help_msg_pi = {
	"Usage:", "pi[bdefrj] [num]", "",
	"pia", "", "print all possible opcodes (byte per byte)",
	"pib", "", "print instructions of basic block",
	"pid", "", "alias for pdi",
	"pie", "[?]", "print offset + esil expression",
	"piE", "[?]", "same as pie but taking an amount of bytes instead of instructions",
	"pif", "[?]", "print instructions of function",
	"pij", "", "print N instructions in JSON",
	"pir", "", "like 'pdr' but with 'pI' output",
	"piu", "[q] [optype]", "disassemble until instruction of given optype is found (See /atl)",
	"pix", "  [hexpairs]", "alias for pdx and pad",
	NULL
};

static RCoreHelpMessage help_msg_piE = {
	"Usage:", "piE[q]", " # print esil of N bytes",
	"piE", "", "print esil of the instructions found in N bytes",
	"piEq", "", "same as above but without displaying the instruction address",
	// "piEj", "", "same but in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_pie = {
	"Usage:", "pie[bqf]", " # print esil of N instructions",
	"pie", "", "print esil of N instructions",
	"pieb", "", "alias for `pie $Fi`",
	"pieq", "", "same as above but hiding the offset",
	"pief", "", "print esil of all the function basic blocks",
	"piefq", "", "same as above but hiding the offset",
	// "piej", "", "same but in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_pif = {
	"Usage:", "pif[cj]", " # print instructions from function",
	"pif", "", "print function instructions",
	"pifj", "", "same as above but in JSON format",
	"pifc", "", "print all calls from this function", // pif~call?
	"pifcj", "", "print all calls from this function in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_po = {
	"Usage:", "po[24aAdlmorsxS]", " [hexpairs] @ addr[!bsize] (see also `poke`)",
	"po[24aAdlmorsx]", "", "without hexpair values, clipboard is used",
	"po2", " [val]", "2=  2 byte endian swap",
	"po4", " [val]", "4=  4 byte endian swap",
	"poa", " [val]", "+=  addition (f.ex: poa 0102)",
	"poA", " [val]", "&=  and",
	"pod", " [val]", "/=  divide",
	"poD", " [algo] [key] [iv]", "Print block decryption",
	"poE", " [algo] [key] [iv]", "Print block encryption",
	"pol", " [val]", "<<= shift left",
	"pom", " [val]", "*=  multiply",
	"poo", " [val]", "|=  or",
	"por", " [val]", ">>= shift right",
	"pos", " [val]", "-=  substraction",
	"pox", " [val]", "^=  xor  (f.ex: pox 0x90)",
	"poS", " [algo] [key]", "Compute and print block signature",
	NULL
};

static RCoreHelpMessage help_msg_pq = {
	"Usage:", "pq[?z] [len]", "generate QR code in ascii art",
	"pq", " 32", "print QR code with the current 32 bytes",
	"pqz", "", "print QR code with current string in current offset",
	NULL
};

static RCoreHelpMessage help_msg_ps = {
	"Usage:", "ps[abijqpsuwWxz+] [len]", "Print String (optionally specify the length)",
	"ps", "[j]", "print string until a first non-printable character",
	"ps+", "[j]", "print libc++ std::string (same-endian, ascii, zero-terminated)",
	"psa", "", "print any type of string (psp/psw/psW/psz/..)",
	"psb", "", "print strings in current block",
	"psi", "", "print string inside curseek",
	"psn", "[l] [len]", "print string until newline",
	"psp", "[?][j]", "print pascal string",
	"psq", "", "alias for pqs",
	"pss", "", "print string in screen (wrap width)",
	"pso", "[j]", "print string constructed with immediates (Swift)",
	"psu", "[zj]", "print utf16 unicode (json)",
	"psw", "[j]", "print 16bit wide string",
	"psW", "[j]", "print 32bit wide string",
	"psx", "", "show string with escaped chars",
	"psz", "[?] [lj]", "print zero-terminated string",
	NULL
};

static RCoreHelpMessage help_msg_pt = {
	"Usage: pt", "[dn]", "print timestamps",
	"pt.", "", "print current time",
	"pt", "", "print UNIX time (32 bit `cfg.bigendian`) Since January 1, 1970",
	"ptb", "", "print BEAT time (Swatch Internet Time)",
	"ptd", "", "print DOS time (32 bit `cfg.bigendian`) Since January 1, 1980",
	"pth", "", "print HFS time (32 bit `cfg.bigendian`) Since January 1, 1904",
	"ptn", "", "print NTFS time (64 bit `cfg.bigendian`) Since January 1, 1601",
	NULL
};

static RCoreHelpMessage help_msg_pv = {
	"Usage: pv[1248z][udj]", "", "Print value(s) given size and endian (u for unsigned, d for signed decimal, j for json)",
	"pv", "", "print bytes based on asm.bits",
	"pv1", "[udj]", "print 1 byte in memory",
	"pv2", "[udj]", "print 2 bytes in memory",
	"pv4", "[udj]", "print 4 bytes in memory",
	"pv8", "[udj]", "print 8 bytes in memory",
	"pvp", "[udj]", "print 4 or 8 bytes depending on asm.bits",
	"pve", " [1234] ([bsize])", "print value with any endian (reorder bytes with the 1234 order)",
	"pvz", "", "print value as string (alias for ps)",
	NULL
};

static RCoreHelpMessage help_msg_px = {
	"Usage:", "px[0afoswqWqQ][f]", " # Print heXadecimal",
	"px", "", "show hexdump",
	"px--", "[n]", "context hexdump (the hexdump version of pd--3)",
	"px/", "", "same as x/ in gdb (help x)",
	"px*", "", "same as pc* or p8*, print r2 commands as in hexdump",
	"px0", "", "8bit hexpair list of bytes until zero byte",
	"px3", "", "24bit hexdump",
	"pxa", "", "show annotated hexdump",
	"pxA", "[?]", "show op analysis color map",
	"pxb", "", "dump bits in hexdump form", // should be px1?
	"pxB", "", "dump bits in bitmap form", // should be something else? :D
	"pxc", "", "show hexdump with comments",
	"pxd", "[?1248]", "signed integer dump (1 byte, 2 and 4)",
	"pxe", "", "emoji hexdump! :)",
	"pxf", "", "show hexdump of current function",
	"pxh", "", "show hexadecimal half-words dump (16bit)",
	"pxH", "", "same as above, but one per line",
	"pxi", "", "HexII compact binary representation",
	"pxl", "", "display N lines (rows) of hexdump",
	"pxo", "", "show octal dump",
	"pxq", "", "show hexadecimal quad-words dump (64bit)",
	"pxQ", "[q]", "same as above, but one per line",
	"pxr", "[1248][qj]", "show hexword references (q=quiet, j=json)",
	"pxs", "", "show hexadecimal in sparse mode",
	"pxt", "[*.] [origin]", "show delta pointer table in r2 commands",
	"pxu", "[?1248]", "unsigned integer dump (1 byte, 2 and 4)",
	"pxw", "", "show hexadecimal words dump (32bit)",
	"pxW", "[q]", "same as above, but one per line (q=quiet)",
	"pxx", "", "show N bytes of hex-less hexdump",
	"pxX", "", "show N words of hex-less hexdump",
	NULL
};

static RCoreHelpMessage help_msg_pz = {
	"Usage: pz [len]", "", "print zoomed blocks (filesize/N)",
	"e ", "zoom.maxsz", "max size of block",
	"e ", "zoom.from", "start address",
	"e ", "zoom.to", "end address",
	"e ", "zoom.byte", "specify how to calculate each byte",
	"pz0", "", "number of bytes with value '0'",
	"pzF", "", "number of bytes with value 0xFF",
	"pze", "", "calculate entropy and expand to 0-255 range",
	"pzf", "", "count of flags in block",
	"pzh", "", "head (first byte value); This is the default mode",
	"pzp", "", "number of printable chars",
	"pzs", "", "strings in range",
	// "WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
	NULL
};

static RCoreHelpMessage help_msg_pxA = {
	"Usage: pxA [len]", "", "show op analysis color map",
	"$$", "", "int/swi/trap/new",
	"+-*/", "", "math ops",
	"->", "", "push",
	"..", "", "nop",
	"<-", "", "pop",
	"<<>>", "", "shift ops",
	"==", "", "cmp/test",
	"XX", "", "invalid",
	"_C", "", "call",
	"_J", "", "jump",
	"_R", "", "ret",
	"cJ", "", "conditional jump",
	"io", "", "in/out ops",
	"mv", "", "move,lea,li",
	"|&^", "", "bin ops",
	NULL
};

static RCoreHelpMessage help_msg_pg = {
	"Usage: pg[-]", "[asm|hex]", "print (dis)assembled",
	"pg", " [x y w h cmd]", "add a new gadget",
	"pg", "", "print them all",
	"pg", "*", "print the gadgets as r2 commands",
	"pg-", "*", "remove all the gadgets",
	NULL
};

static const ut32 colormap16[16] = {
#if 0
	// rainbow from r2ai
	0x303030,
	0xffff00,
	0x00ff00,
	0x00ff00,
	0x00ffff,
	0x0000ff,
	0x8a2be2,
	0x4b0082,
	0x800080,
	0xff00ff,
	0xff69b4,
	0xfa8072,
	0xffdab9,
	0xffd700,
	0xc0c0c0,
	0xff0000,
#else
	0xe71d43, // Dark Red
	0xff0000, // Red
	0xff6e00, // Orange
	0xffc300, // Orange Yellow
	0xffff00, // Yellow
	0xaad500, // Lime
	0x55aa00, // Grass Green
	0x008000, // Forest Green
	0x005555, // Dark Teal
	0x002baa, // Navy
	0x0000ff, // Blue
	0x3200ac, // Purple
	0x4b0082, // Magenta
	0x812ba6, // Dark Pink
	0xb857ca, // Light Pink
	0xd03a87, // Salmon
#endif
};

static const ut32 colormap[256] = {
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

static void __cmd_pad(RCore *core, const char *arg) {
	if (*arg == '?') {
		r_core_cmd_help_contains (core, help_msg_pa, "pad");
		return;
	}
	r_asm_set_pc (core->rasm, core->addr);
	bool is_pseudo = r_config_get_b (core->config, "asm.pseudo");
	RAsmCode *acode = r_asm_mdisassemble_hexstr (core->rasm, is_pseudo ? core->rasm->parse : NULL, arg);
	if (acode) {
		r_kons_print (core->cons, acode->assembly);
		r_asm_code_free (acode);
	} else {
		R_LOG_ERROR ("Invalid hexstr");
	}
}

static void first_flag_chars(const char *name, char *ch, char *ch2) {
	name = r_name_filter_ro (name);
	const bool two = name[0] && name[1];
	*ch = two? name[0]: ' ';
	*ch2 = two? name[1]: name[0]; // two? 1: 0];
}

// nibble-level colordump
static char *get_color(RCons *cons, ut8 ch) {
	ut32 c0 = colormap16[ch];
	const int brightness = ((c0 & 0xff0000) >> 16) + 2 * ((c0 & 0xff00) >> 8) + (c0 & 0xff) / 2;
	// char *str = r_str_newf ("rgb:%s rgb:%06x", brightness <= 0x7f * 3 ? "fff" : "000", c0);
	char *str = r_str_newf ("rgb:%s rgb:%06x", brightness <= 0x40 * 3 ? "aaa" : "222", c0);
	char *res = r_cons_pal_parse (cons, str, NULL);
	free (str);
	return res;
}

static void cmd_prcn(RCore *core, const ut8* block, int len, bool bitsmode) {
	int i, j;
	char *color0;
	char *color1;
	int cols = r_config_get_i (core->config, "hex.cols");
	const bool show_color = r_config_get_b (core->config, "scr.color");
	const bool show_flags = r_config_get_b (core->config, "asm.flags");
	const bool show_section = r_config_get_b (core->config, "hex.section");
	const bool show_offset = r_config_get_b (core->config, "hex.addr");
	// const bool show_cursor = core->print->cur_enabled;
	const bool show_unalloc = core->print->flags & R_PRINT_FLAGS_UNALLOC;
	if (cols < 1 || cols > 0xfffff) {
		cols = 32;
	}
	RCons *cons = core->cons;
	for (i = 0; i < len; i += cols) {
		if (show_section) {
			const char * name = r_core_get_section_name (core, core->addr + i);
			r_kons_printf (cons, "%20s ", r_str_get (name));
		}
		if (show_offset) {
			r_print_addr (core->print, core->addr + i);
		}
		for (j = i; j < i + cols; j ++) {
			if (j >= len) {
				break;
			}
			ut8 ch0 = (block[j] >> 4) & 0xf;
			ut8 ch1 = block[j] & 0xf;
			if (show_unalloc && !core->print->iob.is_valid_offset (core->print->iob.io, core->addr + j, false)) {
				ch0 = core->print->io_unalloc_ch;
				ch1 = core->print->io_unalloc_ch;
			}
			if (show_color) {
				color0 = get_color (cons, ch0);
				color1 = get_color (cons, ch1);
#if 0
				if (show_cursor && core->print->cur == j) {
					ch = '_';
				} else {
					ch = ' ';
				}
#endif
			} else {
				color0 = strdup ("");
				color1 = strdup ("");
#if 0
				if (show_cursor && core->print->cur == j) {
					ch = '_';
				} else {
					const int idx = (int)(((double)block[j] / 255) * (strlen (chars) - 1));
					ch = chars[idx];
				}
#endif
			}
			if (bitsmode) {
				char color0bits[8] = {0};
				char color1bits[8] = {0};
				ut8 b0 = ch0 | ch0 << 4;
				ut8 b1 = ch1 | ch1 << 4;
				r_str_bits (color0bits, &b0, 4, NULL);
				r_str_bits (color1bits, &b1, 4, NULL);
				r_kons_printf (cons, "%s%s%s%s"Color_RESET" ", color0, color0bits, color1, color1bits);
			} else {
				r_kons_printf (cons, "%s%01x%s%01x"Color_RESET, color0, ch0, color1, ch1);
			}
			free (color0);
			free (color1);
		}
		if (show_color) {
			r_kons_printf (cons, Color_RESET);
		}
		if (show_flags) {
			RFlagItem *fi = r_flag_get_in (core->flags, core->addr + j);
			if (fi) {
				r_kons_printf (cons, " ; %s", fi->name);
			}
		}
		r_cons_newline (cons);
	}
}

// colordump
static void cmd_prc(RCore *core, const ut8* block, int len) {
	const char *chars = " .,:;!O@#";
	bool square = r_config_get_i (core->config, "scr.square");
	int i, j;
	char ch, ch2, *color;
	int cols = r_config_get_i (core->config, "hex.cols");
	const bool show_color = r_config_get_b (core->config, "scr.color");
	const bool show_flags = r_config_get_b (core->config, "asm.flags");
	const bool show_section = r_config_get_b (core->config, "hex.section");
	const bool show_offset = r_config_get_b (core->config, "hex.addr");
	const bool show_cursor = core->print->cur_enabled;
	const bool show_unalloc = core->print->flags & R_PRINT_FLAGS_UNALLOC;
	if (cols < 1 || cols > 0xfffff) {
		cols = 32;
	}
	for (i = 0; i < len; i += cols) {
		if (show_section) {
			const char * name = r_core_get_section_name (core, core->addr + i);
			r_cons_printf ("%20s ", r_str_get (name));
		}
		if (show_offset) {
			r_print_addr (core->print, core->addr + i);
		}
		for (j = i; j < i + cols; j ++) {
			if (j >= len) {
				break;
			}
			if (show_color) {
				ut32 color_val = colormap[block[j]];
				int brightness = ((color_val & 0xff0000) >> 16)
					+ 2 * ((color_val & 0xff00) >> 8)
					+ (color_val & 0xff) / 2;
				char *str = r_str_newf ("rgb:%s rgb:%06x",
					brightness <= 0x7f * 3 ? "fff" : "000", color_val);
				color = r_cons_pal_parse (core->cons, str, NULL);
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
					const int idx = (int)(((double)block[j] / 255) * (strlen (chars) - 1));
					ch = chars[idx];
				}
			}
			if (show_unalloc &&
			    !core->print->iob.is_valid_offset (core->print->iob.io, core->addr + j, false)) {
				ch = core->print->io_unalloc_ch;
				if (show_color) {
					free (color);
					color = strdup (Color_RESET);
					if (ch == ' ') {
						ch = '.';
					}
				} else {
					ch = strchr (chars, ch) ? '?' : ch;
				}
			}
			if (square) {
				if (show_flags) {
					RFlagItem *fi = r_flag_get_in (core->flags, core->addr + j);
					if (fi) {
						first_flag_chars (fi->name, &ch, &ch2);
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
		if (show_color) {
			r_cons_printf (Color_RESET);
		}
		r_cons_newline (core->cons);
	}
}

static void cmd_printmsg(RCore *core, const char *input) {
	if (!strcmp (input, "ln")) {
		r_cons_newline (core->cons);
	} else if (r_str_startswith (input, "ln ")) {
		r_cons_println (core->cons, input + 3);
	} else if (r_str_startswith (input, " ")) {
		r_kons_print (core->cons, input + 1);
	} else if (r_str_startswith (input, "f ")) {
		R_LOG_TODO ("printf not implemented. use ?e, echo or print");
	} else if (r_str_startswith (input, "fln ")) {
		R_LOG_TODO ("printfln not implemented. use ?e, echo or print");
	} else {
		r_core_cmd_help_match (core, help_msg_pr, "print");
	}
}

static void cmd_prc_zoom(RCore *core, const char *input) {
	const char *chars = " .,:;!O@#";
	bool square = r_config_get_i (core->config, "scr.square");
	int i, j;
	char ch, ch2, *color;
	int cols = r_config_get_i (core->config, "hex.cols");
	bool show_color = r_config_get_i (core->config, "scr.color");
	bool show_flags = r_config_get_i (core->config, "asm.flags");
	bool show_cursor = core->print->cur_enabled;
	bool show_offset = r_config_get_i (core->config, "hex.addr");
	bool show_unalloc = core->print->flags & R_PRINT_FLAGS_UNALLOC;
	ut8 *block = core->block;
	int len = core->blocksize;
	ut64 from = 0;
	ut64 to = 0;
	RIOMap* map;
	RListIter *iter;

	if (cols < 1 || cols > 0xfffff) {
		cols = 32;
	}
	RList *list = r_core_get_boundaries_prot (core, -1, NULL, "zoom");
	if (list && r_list_length (list) > 0) {
		RListIter *iter1 = list->head;
		RIOMap* map1 = iter1->data;
		from = map1->itv.addr;
		r_list_foreach (list, iter, map) {
			to = r_io_map_end (map);
		}
	} else {
		from = core->addr;
		to = from + core->blocksize;
	}
	if (list) {
		r_list_free (list);
		list = NULL;
	}

	core->print->zoom->mode = (input && *input)? input[1]: 'e';
	r_print_zoom_buf (core->print, printzoomcallback, core, from, to, len, len);
	block = core->print->zoom->buf;

	for (i = 0; i < len; i += cols) {
		ut64 ea = core->addr + i;
		if (show_offset) {
			r_print_addr (core->print, ea);
		}
		for (j = i; j < i + cols; j ++) {
			if (j >= len) {
				break;
			}
			if (show_color) {
				char *str = r_str_newf ("rgb:fff rgb:%06x", colormap[block[j]]);
				color = r_cons_pal_parse (core->cons, str, NULL);
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
					const int idx = (int)(((double)block[j] / 255) * (strlen (chars) - 1));
					ch = chars[idx];
				}
			}
			if (show_unalloc &&
			    !core->print->iob.is_valid_offset (core->print->iob.io, core->addr + j, false)) {
				ch = core->print->io_unalloc_ch;
				if (show_color) {
					free (color);
					color = strdup (Color_RESET);
					if (ch == ' ') {
						ch = '.';
					}
				} else {
					ch = strchr (chars, ch) ? '?' : ch;
				}
			}
			if (square) {
				if (show_flags) {
					RFlagItem *fi = r_flag_get_in (core->flags, core->addr + j);
					if (fi) {
						if (fi->name[1]) {
							ch = fi->name[0];
							ch2 = fi->name[1];
						} else {
							ch = ' ';
							ch2 = fi->name[0];
						}
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
		if (show_color) {
			r_cons_printf (Color_RESET);
		}
		r_cons_newline (core->cons);
	}
}

static void cmd_pCd(RCore *core, const char *input) {
	int h, w = r_cons_get_size (core->cons, &h);
	int colwidth = (int)((double)r_config_get_i (core->config, "hex.cols") * 2.5);
	if (colwidth < 1) {
		colwidth = 16;
	}
	int i, columns = w / colwidth;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = r_num_math (core->num, input);
	char *o_ao = strdup (r_config_get (core->config, "asm.addr"));
	char *o_ab = strdup (r_config_get (core->config, "asm.bytes"));
	r_config_set_b (core->config, "asm.bytes", false);
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	r_kons_push (core->cons);
	int flags = r_cons_canvas_flags (core->cons);
	RConsCanvas *c = r_cons_canvas_new (core->cons, w, rows, flags);
	ut64 osek = core->addr;
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
	r_core_seek (core, osek, true);

	r_kons_pop (core->cons);
	r_cons_canvas_print (c);
	r_cons_canvas_free (c);
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
		if (sym->vaddr && sym->vaddr != UT64_MAX) {
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
	r_list_foreach (cs, iter, c) {
		findMethodBounds (c->methods, &min, &max);
		if (len) {
			*len = (max - min);
		}
		return min;
	}
	return 0;
}

static void cmd_pCD(RCore *core, const char *input) {
	int i, h, w = r_cons_get_size (core->cons, &h);
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = r_num_math (core->num, input);
	char *o_ao = strdup (r_config_get (core->config, "asm.addr"));
	char *o_ab = strdup (r_config_get (core->config, "asm.bytes"));
	r_config_set_b (core->config, "asm.bytes", false);
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	r_kons_push (core->cons);
	int flags = r_cons_canvas_flags (core->cons);
	RConsCanvas *c = r_cons_canvas_new (core->cons, w, rows, flags);
	ut64 osek = core->addr;
	c->color = r_config_get_i (core->config, "scr.color");
	r_core_block_size (core, rows * 32);
	char *cmd = NULL;
	int columns = 2;
	const char *stack_cmd = core->stkcmd;
	if (R_STR_ISEMPTY (stack_cmd)) {
		stack_cmd = "px";
	}
	for (i = 0; i < columns; i++) {
		switch (i) {
		case 0:
			(void) r_cons_canvas_gotoxy (c, 0, 0);
			cmd = r_str_newf ("dr;?e;?e backtrace:;dbt");
			break;
		case 1:
			(void) r_cons_canvas_gotoxy (c, 28, 0);
			// cmd = r_str_newf ("pxw 128@r:SP;pd@r:PC");
			cmd = r_str_newf ("%s 128@r:SP;pd@ 0x%"PFMT64x, stack_cmd, osek);
			break;
		}
		char *dis = r_core_cmd_str (core, cmd);
		r_cons_canvas_write (c, dis);
		free (cmd);
		free (dis);
	}
	r_core_block_size (core, obsz);
	r_core_seek (core, osek, true);

	r_kons_pop (core->cons);
	r_cons_canvas_print (c);
	r_cons_canvas_free (c);
	r_config_set (core->config, "asm.bytes", o_ab);
	free (o_ao);
	free (o_ab);
}

static void cmd_pCx(RCore *core, const char *input, const char *xcmd) {
	int h, w = r_cons_get_size (core->cons, &h);
	int hex_cols = r_config_get_i (core->config, "hex.cols");
	int colwidth = hex_cols * 5;
	int i, columns = (int)((double)w / (colwidth * 0.9));
	int rows = h - 2;
	int user_rows = r_num_math (core->num, input);
	r_config_set_i (core->config, "hex.cols", colwidth / 5);
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	int flags = r_cons_canvas_flags (core->cons);
	RConsCanvas *c = r_cons_canvas_new (core->cons, w, rows, flags);
	if (!c) {
		R_LOG_ERROR ("Couldn't allocate a canvas with %d rows", rows);
		goto err;
	}

	ut64 tsek = core->addr;
	c->color = r_config_get_i (core->config, "scr.color");
	int bsize = hex_cols * rows;
	if (!strcmp (xcmd, "pxA")) {
		bsize *= 12;
	}
	for (i = 0; i < columns; i++) {
		(void) r_cons_canvas_gotoxy (c, i * (w / columns), 0);
		char *cmd = r_str_newf ("%s %d @ %"PFMT64u, xcmd, bsize, tsek);
		char *dis = r_core_cmd_str (core, cmd);
		if (dis) {
			r_cons_canvas_write (c, dis);
			free (dis);
		}
		free (cmd);
		tsek += bsize - 32;
	}

	r_cons_canvas_print (c);
	r_cons_canvas_free (c);
 err:
	r_config_set_i (core->config, "hex.cols", hex_cols);
}

static char get_string_type(const ut8 *buf, ut64 len) {
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

R_API void r_core_set_asm_configs(RCore *core, char *arch, ut32 bits, int segoff) {
	r_config_set (core->config, "asm.arch", arch);
	r_config_set_i (core->config, "asm.bits", bits);
	// XXX - this needs to be done here, because
	// if arch == x86 and bits == 16, segoff automatically changes
	r_config_set_i (core->config, "asm.addr.segment", segoff);
}

static int cmd_pdu(RCore *core, const char *input) {
	int ret = 0;
	const char *sep = strchr (input, ' ');
	if (!sep) {
		sep = strstr (input, "..");
	}
	const char *arg = sep? r_str_trim_head_ro (sep): NULL;

	ut64 addr = core->addr;
	int len = core->blocksize;
	ut8 *buf = malloc (len);
	if (buf) {
		r_io_read_at (core->io, addr, buf, len);
	} else {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", len);
		return 1;
	}

	switch (*input) {
	case 'a': // "pdua"
		{
		if (input[1] == '?' || (input[1] && input[2] == '?') || !arg) {
			r_core_cmd_help_match (core, help_msg_pdu, "pdua");
			break;
		}
		ut64 to = 0;
		if (r_str_startswith (arg, "..")) {
			to = r_num_tail (core->num, core->addr, arg + 2);
			to++; // one more
		} else {
			to = r_num_math (core->num, arg);
		}
		if (!to || r_num_failed (core->num)) {
			R_LOG_ERROR ("Couldn't parse address \"%s\"", arg);
			ret = 1;
			break;
		} else if (to < addr) {
			R_LOG_ERROR ("Can't print until an earlier address");
			ret = 2;
			break;
		} else if (to == addr) {
			R_LOG_ERROR ("Can't print until the start address");
			ret = 2;
			break;
		}

		// pD <count>
		ut64 count = to - core->addr;
		ret = r_core_cmdf (core, "%s %" PFMT64u, (input[1]== 'j')? "pDJ": "pD", count);
		}
		break;
	case 'c': // "pduc"
		if (input[1] == '?' || (input[1] && input[2] == '?')) {
			r_core_cmd_help_match (core, help_msg_pdu, "pduc");
			break;
		}
		ret = r_core_print_disasm (core, addr, buf, len, 0, pdu_opcode, "call", false,
				input[1] == 'j', NULL, NULL);
		break;
#if 0
	case 'e': // "pdue"
		if (input[1] == '?' || input[2] == '?' || !arg) {
			r_core_cmd_help_match (core, help_msg_pdu, "pdue");
			break;
		}
		ret = r_core_print_disasm (core, addr, buf, len, 0, esil, arg, false,
				input[1] == 'j', NULL, NULL);
		break;
#endif
	case 'i': // "pdui"
		if (input[1] == '?' || (input[1] && input[2] == '?') || !arg) {
			r_core_cmd_help_match (core, help_msg_pdu, "pdui");
			break;
		}
		ret = r_core_print_disasm (core, addr, buf, len, 0, pdu_instruction, arg, false,
				input[1] == 'j', NULL, NULL);
		break;
	case 'o': // "pduo"
		if (input[1] == '?' || (input[1] && input[2] == '?') || !arg) {
			r_core_cmd_help_match (core, help_msg_pdu, "pduo");
			break;
		}

		if (input[1] != 'j') { // "pduo"
			ret = r_core_print_disasm (core, addr, buf, len, 0, pdu_opcode, arg, false, false, NULL, NULL);
		} else { // "pduoj"
			PJ *pj = r_core_pj_new (core);
			if (!pj) {
				return 1;
			}
			pj_a (pj);
			ret = r_core_print_disasm_json_ipi (core, addr, buf, len, 0, pj, arg);
			pj_end (pj);
			r_cons_println (core->cons, pj_string (pj));
			pj_free (pj);
		}
		break;
	case 's': // "pdus"
		if (input[1] == '?' || (input[1] && input[2] == '?')) {
			r_core_cmd_help_match (core, help_msg_pdu, "pdus");
			break;
		}
		ret = r_core_print_disasm (core, addr, buf, len, 0, pdu_instruction, "syscall", false,
				input[1] == 'j', NULL, NULL);
		break;
	case '?': // "pdu?"
	default:
		r_core_cmd_help (core, help_msg_pdu);
		break;
	}

	free (buf);
	return ret;
}

static void cmd_pDj(RCore *core, const char *arg) {
	int bsize = r_num_math (core->num, arg);
	if (bsize < 0) {
		bsize = -bsize;
	}
	PJ *pj = r_core_pj_new (core);
	if (!pj) {
		return;
	}
	pj_a (pj);
	ut8 *buf = malloc (bsize);
	if (buf) {
		r_io_read_at (core->io, core->addr, buf, bsize);
		r_core_print_disasm_json_ipi (core, core->addr, buf, bsize, 0, pj, NULL);
		free (buf);
	} else {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
	}
	pj_end (pj);
	r_cons_println (core->cons, pj_string (pj));
	pj_free (pj);
}

static void cmd_pdj(RCore *core, const char *arg, ut8* block) {
	int nblines = r_num_math (core->num, arg);
	PJ *pj = r_core_pj_new (core);
	if (!pj) {
		return;
	}
	pj_a (pj);
	r_core_print_disasm_json_ipi (core, core->addr, block, core->blocksize, nblines, pj, NULL);
	pj_end (pj);
	r_cons_println (core->cons, pj_string (pj));
	pj_free (pj);
}

static void cmd_p_minus_e(RCore *core, ut64 at, ut64 ate) {
	ut8 *blockptr = malloc (ate - at);
	if (!blockptr) {
		return;
	}
	if (r_io_read_at (core->io, at, blockptr, (ate - at))) {
		ut8 entropy = (ut8)(r_hash_entropy_fraction (blockptr, (ate - at)) * 255);
		entropy = 9 * entropy / 200; // normalize entropy from 0 to 9
		if (r_config_get_i (core->config, "scr.color")) {
			const char *color =
				(entropy > 6) ? Color_BGRED :
				(entropy > 3) ? Color_BGGREEN :
				Color_BGBLUE;
			r_cons_printf ("%s%d"Color_RESET, color, entropy);
		} else {
			r_cons_printf ("%d", entropy);
		}
	}
	free (blockptr);
}

static void print_format_help_help_help_help(RCore *core) {
	R_LOG_WARN ("STOP IT");
}

static void cmd_print_fromage(RCore *core, const char *input, const ut8* data, int size) {
	switch (*input) {
	case 'a': // "pFa" // DER/ASN1 encoding
		{
			int fmt = input[1];

			if (fmt == 't' && !r_config_get_b (core->config, "scr.utf8")) {
				R_LOG_ERROR ("Tree view requires utf8 support");
				break;
			}
			RAsn1 *a = r_asn1_new (data, size, fmt);
			// RASN1Object *asn1 = r_asn1_object_parse (data, data, size, fmt);
			if (a) {
				char *res = r_asn1_tostring (a);
				// char *res = r_asn1_object_tostring (asn1, 0, NULL, fmt);
				r_asn1_free (a);
				if (res) {
					r_cons_println (core->cons, res);
					free (res);
				}
			} else {
				R_LOG_ERROR ("Malformed object: did you supply enough data? try to change the block size (see b?)");
			}
		}
		break;
	case 'X': // "pFX" un-xz
		{
			size_t out_len = 0;
			ut8 *out = r_sys_unxz (data, size, &out_len);
			if (out) {
				r_cons_write (core->cons, (const char *)out, out_len);
				free (out);
			}
		}
		break;
	case 'x': // "pFx" x509
		{
			ut8 *buf = (ut8*)data;
			RASN1Object *obj = r_asn1_object_parse (buf, buf, size, input[1]);
			if (!obj) {
				R_LOG_ERROR ("cannot parse asn1 object");
				break;
			}
			RX509Certificate* x509 = r_x509_certificate_parse (obj);
			if (x509) {
				if (input[1] == 'j') { // "pFxj"
					PJ *pj = r_core_pj_new (core);
					r_x509_certificate_json (pj, x509);
					char *res = pj_drain (pj);
					if (res) {
						r_cons_println (core->cons, res);
						free (res);
					}
				} else {
					RStrBuf *sb = r_strbuf_new ("");
					r_x509_certificate_dump (x509, NULL, sb);
					char *res = r_strbuf_drain (sb);
					if (res) {
						r_cons_println (core->cons, res);
						free (res);
					}
				}
				r_x509_certificate_free (x509);
			} else {
				R_LOG_ERROR ("Malformed object: did you supply enough data? try to change the block size (see b?)");
			}
		}
		break;
	case 'o': // "pFo" asn1 oid
		{
			const char fmt = input[1];
			RAsn1 *a = r_asn1_new (data, size, fmt);
			if (a) {
				char *oid = r_asn1_oid (a);
				if (oid) {
					r_cons_println (core->cons, oid);
					free (oid);
				}
				r_asn1_free (a);
			}
		}
		break;
	case 'p': // "pFp"
		{
			RCMS *cms = r_pkcs7_cms_parse (data, size);
			if (cms) {
				if (input[1] == 'j') {
					PJ *pj = r_pkcs7_cms_json (cms);
					if (pj) {
						char *res = pj_drain (pj);
						r_cons_println (core->cons, res);
						free (res);
					}
				} else {
					char *res = r_pkcs7_cms_tostring (cms);
					if (res) {
						r_cons_println (core->cons, res);
						free (res);
					}
				}
				r_pkcs7_cms_free (cms);
			} else {
				R_LOG_ERROR ("Malformed object: did you supply enough data? try to change the block size (see b?)");
			}
		}
		break;
	case 'b': // "pFb"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_pF, "pFb");
		} else {
			char *s = r_protobuf_decode (data, size, input[1]);
			if (s) {
				r_kons_print (core->cons, s);
				free (s);
			}
		}
		break;
	case 'A': // "pFA"
		if (input[1] == 'j') {
			PJ * pj = r_core_pj_new (core);
			char *s = r_axml_decode (data, size, pj);
			if (s) {
				free (s);
			}
			s = pj_drain (pj);
			r_cons_println (core->cons, s);
			free (s);
		} else {
			char *s = r_axml_decode (data, size, NULL);
			if (s) {
				r_kons_print (core->cons, s);
				free (s);
			} else {
				R_LOG_ERROR ("Malformed object: did you supply enough data? try to change the block size (see b?)");
			}
		}
		break;
	case 'B': // "pFB"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_pF, "pFB");
		} else {
			PJ *pj = r_core_pj_new (core);
			if (size > 0) {
				if (!r_bplist_parse (pj, data, size)) {
					R_LOG_ERROR ("bplist parse error");
				}
			} else {
				pj_o (pj);
				pj_end (pj);
			}
			char *s = pj_drain (pj);
			if (input[1] == 'j') {
				r_cons_println (core->cons, s);
			} else {
				char *r = r_print_json_human (s);
				r_cons_println (core->cons, r);
				free (r);
			}
			free (s);
		}
		break;
	case '?': // "pF?"
		r_core_cmd_help (core, help_msg_pF);
		break;
	default:
		r_core_return_invalid_command (core, "pF", input[0]);
		break;
	}
}

R_API void r_core_gadget_free(RCoreGadget *g) {
	if (g) {
		free (g->cmd);
		free (g);
	}
}

static void cmd_print_gadget(RCore *core, const char *_input) {
	if (*_input == '?') { // "pg?"
		r_core_cmd_help (core, help_msg_pg);
		return;
	}
	if (*_input == '-') { // "pg-"
		// TODO support selecting one
		r_list_free (core->gadgets);
		core->gadgets = r_list_newf ((RListFree)r_core_gadget_free);
	} else if (*_input == '*') { // "pg*"
		RCoreGadget *g;
		RListIter *iter;
		r_list_foreach (core->gadgets, iter, g) {
			r_cons_printf ("\"pg %d %d %d %d %s\"\n", g->x, g->y, g->w, g->h, g->cmd);
		}
	} else if (*_input == 'b') { // "pgb"
		R_LOG_TODO ("Change gadget background color");
	} else if (*_input == 'm') { // "pgm"
		int nth = atoi (_input + 1);
		RCoreGadget *g = r_list_get_n (core->gadgets, nth);
		if (g) {
			char *input = strdup (_input);
			char *space = strchr (input, ' ');
			if (space) {
				space++;
			} else {
				space = "";
			}
			RList *args = r_str_split_list (space, " ", 0);
			char *x = r_list_pop_head (args);
			char *y = r_list_pop_head (args);
			char *w = r_list_pop_head (args);
			char *h = r_list_pop_head (args);
			if (x && y && w && h) {
				g->x = r_num_math (core->num, x);
				g->y = r_num_math (core->num, y);
				g->w = r_num_math (core->num, w);
				g->h = r_num_math (core->num, h);
			}
			r_list_free (args);
			free (input);
		}
	} else if (*_input == ' ') { // "pg "
		char *input = strdup (_input);
		RList *args = r_str_split_list (input, " ", 0);
		char *x = r_list_pop_head (args);
		char *y = r_list_pop_head (args);
		char *w = r_list_pop_head (args);
		char *h = r_list_pop_head (args);
		if (x && y && w && h) {
			int X = r_num_math (core->num, x);
			int Y = r_num_math (core->num, y);
			int W = r_num_math (core->num, w);
			int H = r_num_math (core->num, h);
			char *cmd = r_str_list_join (args, " ");
			if (cmd) {
		//		eprintf ("%d %d %d %d (%s)\n", X, Y, W, H, cmd);
				if (*cmd) {
					RCoreGadget *g = R_NEW0 (RCoreGadget);
					g->x = X;
					g->y = Y;
					g->w = W;
					g->h = H;
					g->cmd = cmd;
					r_list_append (core->gadgets, g);
				} else {
					free (cmd);
				}
			}
		}
		r_list_free (args);
		free (input);
	} else if (!*_input) { // "pg"
		RCoreGadget *g;
		RListIter *iter;
		r_list_foreach (core->gadgets, iter, g) {
			char *res = r_core_cmd_str (core, g->cmd);
			if (res) {
				r_cons_print_at (core->cons, res, g->x, g->y, g->w, g->h);
				free (res);
			}
		}
	} else {
		r_core_cmd_help (core, help_msg_pg);
	}
}

static ut64 read_val(RBitmap *bm, int pos, int sz, bool be) {
	int i;
	ut64 n = 0;
#if 0
	0 1 2 3 4 5 6 7
	    ^
	7 6 5 4 3 2 1 0
		  ^
	7-2 = 5
	7-3 = 4
#endif
	// be = true;
	for (i = 0; i < sz; i++) {
		int epos = pos + i;
		if (!be) {
			int w = (pos + i) % 8;
			int bytepos = (pos + i) - w;
			epos = bytepos + (7 - w);
		}
		bool bitset = r_bitmap_test (bm, epos);
		// eprintf ("chk %d %d\n", epos, bitset);
		if (bitset) {
			n += (1ULL << (sz - 1 - i));
		}
	}
	return n;
}

enum {
	PFB_DBG,
	PFB_JSN = 'j',
	PFB_COD = 'c',
	PFB_QUI = 'q',
	PFB_ART
};

typedef struct {
	int sz;
	int pos;
	ut64 value;
	const char *name;
	bool skip;
} RLart;

static RLart *lart_add(RList *list, const char *name, int pos, int sz, ut64 value, bool skip) {
	RLart *la = R_NEW0 (RLart);
	if (la) {
		la->sz = sz;
		la->pos = pos;
		la->name = name;
		la->value = value;
		la->skip = skip;
		r_list_append (list, la);
	}
	return la;
}

static RList *lart_new(void) {
	return r_list_newf (free);
}

static void lart_free(RList *list) {
	r_list_free (list);
}

static int whatbpos(const char *arg) {
	int bpos = 0;
	int n = 0;
	while (*arg && *arg != ' ') {
		if (isdigit (*arg)) {
			n = atoi (arg);
			if (n > 64) {
				R_LOG_ERROR ("Too large. Max is 64");
				return bpos;
			}
			while (isdigit (*arg)) {
				arg += 1;
			}
			arg--;
		} else if (*arg == '.') {
			if (n < 1) {
				n = 1;
			}
			bpos += n;
			n = 0;
		} else if (*arg == '+') {
			// used to separate tokens
			// for example 3+3:4b  -> [0..3] + [6..10]
		} else if (*arg == 'b') {
			bpos += n;
			n = 0;
		}
		arg++;
	}
	return bpos;
}

static void pfb(RCore *core, const char *arg, int mode) {
	const char *fmt = r_str_trim_head_ro (arg);
	int n = 0;
	char *names = strchr (fmt, ' ');
	const bool be = r_config_get_b (core->config, "cfg.bigendian");
	RList *lnames = NULL;
	if (names) {
		names = strdup (names + 1);
		lnames = r_str_split_list (names, " ", 0);
	}
	unsigned int i = 0;
	int bpos = 0;
	ut64 v = 0;
	PJ *pj = NULL;
	if (mode == PFB_JSN) {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}

	RBitmap *bm = r_bitmap_new (core->blocksize * 8);
	r_bitmap_set_bytes (bm, core->block, core->blocksize);
	RList *lart = lart_new ();

	if (mode == PFB_COD) {
		r_cons_printf ("struct bitfield {\n");
	} else if (mode == PFB_QUI) {
		ut64 bv = 0;
		int maxpos = whatbpos (arg);
		if (maxpos < 0 || maxpos > 63) {
			R_LOG_ERROR ("invalid bit position");
			return;
		}
		for (i = 0; i < maxpos; i++) {
			bool v = read_val (bm, i, 1, false);
			if (v) {
				if (be) {
					bv |= (1 << i);
				} else {
					bv |= (1 << (maxpos - i - 1));
				}
			}
		}
		r_cons_printf ("0x%08"PFMT64x":", bv);
	}
	if (!strchr (arg, 'b')) {
		R_LOG_ERROR ("pfb format requires at least one 'b'");
		r_list_free (lart);
		r_bitmap_free (bm);
		pj_free (pj);
		return;
	}
	while (*arg && *arg != ' ') {
		if (isdigit (*arg)) {
			n = atoi (arg);
			if (n > 64) {
				R_LOG_ERROR ("Too large. Max is 64");
				lart_free (lart);
				r_bitmap_free (bm);
				pj_free (pj);
				return;
			}
			while (isdigit (*arg)) {
				arg += 1;
			}
			arg--;
		} else if (*arg == '.') {
			// skip bit
			if (n < 1) {
				n = 1;
			}
			const char *name = lnames? r_list_get_n (lnames, i): "unused";
			if (mode == PFB_COD) {
				r_cons_printf ("    unsigned %s: %d; // 0x%08"PFMT64x"\n", name, n, v);
			}
			lart_add (lart, "?", bpos, n, v, true);
			bpos += n;
			n = 0;
			i++;
		} else if (*arg == '+') {
			// used to separate tokens
			// for example 3+3:4b  -> [0..3] + [6..10]
		} else if (*arg == 'b') {
			if (n < 1) {
				R_LOG_ERROR ("Invalid bitformat string");
				lart_free (lart);
				r_bitmap_free (bm);
				pj_free (pj);
				return;
			}
			const char *name = lnames? r_list_get_n (lnames, i): NULL;
			const bool be = r_config_get_b (core->config, "cfg.bigendian");
			v = read_val (bm, bpos, n, be);
			switch (mode) {
			case PFB_QUI:
				if (R_STR_ISNOTEMPTY (name)) {
					r_cons_printf (" %s[%d..%d]=%"PFMT64d, name, bpos, bpos + n, v);
				} else {
					r_cons_printf (" %s[%d..%d]=%"PFMT64d, "unnamed", bpos, bpos + n, v);
				}
				break;
			case PFB_JSN:
				pj_o (pj);
				if (name) {
					pj_ks (pj, "name", name);
				}
				pj_kn (pj, "off", bpos);
				pj_kn (pj, "size", n);
				pj_kn (pj, "value", v);
				pj_end (pj);
				break;
			case PFB_DBG:
				r_cons_printf ("field: %u\n", i);
				if (R_STR_ISNOTEMPTY (name)) {
					r_cons_printf (" name: %s\n", name);
				}
				r_cons_printf ("  off: %d\n", bpos);
				r_cons_printf ("  siz: %d\n", n);
				r_cons_printf ("  val: %"PFMT64d"\n", v);
				break;
			case PFB_COD:
				if (R_STR_ISNOTEMPTY (name)) {
					r_cons_printf ("    unsigned %s: %d; // 0x%08"PFMT64x"\n", name, n, v);
				} else {
					r_cons_printf ("    unsigned: %d; // 0x%08"PFMT64x"\n", n, v);
				}
				break;
			case PFB_ART:
				lart_add (lart, name, bpos, n, v, false);
				break;
			}
			i++;
			bpos += n;
			n = 0;
		}
		arg++;
	}
	if (mode == PFB_COD) {
		r_cons_printf ("}\n");
	} else if (mode == PFB_QUI) {
		r_cons_newline (core->cons);
	} else if (mode == PFB_JSN) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_printf ("%s\n", s);
		free (s);
	} else if (mode == PFB_ART) {
		ut64 bv = 0;
		for (i = 0; i < bpos; i++) {
			bool v = read_val (bm, i, 1, false);
			r_cons_printf ("%d", v? 1: 0);
			if (v) {
				if (be) {
					bv |= (1 << i);
				} else {
					bv |= (1 << (bpos - i - 1));
				}
			}
		}
		r_cons_printf ("     0x%08"PFMT64x"\n", bv);
		RLart *la;
		RListIter *iter;
		char firstline[1024] = {0};
		memset (firstline, ' ', sizeof (firstline) - 1);
		int padsz = 0;
		r_list_foreach (lart, iter, la) {
			if (la->skip) {
				int i;
				for (i = 0; i < la->sz; i++) {
					r_cons_printf (" ");
				}
			} else if (la->sz == 1) {
				r_cons_printf ("V");
			} else {
				r_cons_printf ("\\");
				int i;
				for (i = 0; i < la->sz - 2; i++) {
					r_cons_printf ("_");
				}
				r_cons_printf ("/");
			}
			padsz = la->pos - 1 + (la->sz / 2);
			if (!la->skip) {
				firstline[padsz + 1] = '|';
			}
		}
		firstline[padsz + 2] = 0;
		int totalpad = padsz + 4;
		r_cons_newline (core->cons);
		r_list_reverse (lart);
		r_list_foreach (lart, iter, la) {
			int padsz = la->pos - 1 + (la->sz / 2);
			char *v = r_str_newf ("%s= %"PFMT64d" (0x%"PFMT64x")",
					la->name? la->name: "", la->value, la->value);
			char *pad2 = strdup (r_str_pad ('-', totalpad - padsz));
			char *pad = r_str_ndup (firstline, padsz + 1);
			if (la->skip) {
				// do nothing here
			} else if (la->value > 0xffff) {
				r_cons_printf ("%s`-%s %8s = 0x%016"PFMT64x" @ %d + %d\n",
						pad? pad: "", pad2,
						la->name? la->name: "",
						la->value,
						la->pos, la->sz
					      );
			} else {
				r_cons_printf ("%s`-%s %8s = %4"PFMT64o"o %5"PFMT64d"   0x%02"PFMT64x" @ %d + %d\n",
						pad? pad: "", pad2,
						la->name? la->name: "",
						la->value, la->value, la->value,
						la->pos, la->sz);
			}
			free (pad);
			free (pad2);
			free (v);
		}
	}
	r_bitmap_free (bm);
	lart_free (lart);
	r_list_free (lnames);
}

static void cmd_pfb(RCore *core, const char *_input) {
	switch (_input[2]) {
	case ' ':
		pfb (core, r_str_trim_head_ro (_input + 2), PFB_ART);
		break;
	case 'q': // "pfbq"
		pfb (core, r_str_trim_head_ro (_input + 3), PFB_QUI);
		break;
	case 'j': // "pfbj"
		pfb (core, r_str_trim_head_ro (_input + 3), PFB_JSN);
		break;
	case 'c': // "pfbc"
		pfb (core, r_str_trim_head_ro (_input + 3), PFB_COD);
		break;
	case 'd': // "pfbd"
		pfb (core, r_str_trim_head_ro (_input + 3), PFB_DBG);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_pfb);
		break;
	case 0:
		R_LOG_ERROR ("pfb requires an argument. Check pfb? for help");
		break;
	default:
		r_core_return_invalid_command (core, "pfb", _input[2]);
		break;
	}
}

static bool is_pfo_file(const char *fn) {
	if (*fn != '.') {
		if (r_str_endswith (fn, ".r2")) {
			return true;
		}
		if (r_str_endswith (fn, ".h")) {
			return true;
		}
	}
	return false;
}
static void cmd_print_format(RCore *core, const char *_input, const ut8* block, int len) {
	char *input = NULL;
	bool v2 = false;
	int mode = R_PRINT_MUSTSEE;
	if (_input[1] == '2') {
		// "pf2"
		_input++;
		v2 = true;
	}
	switch (_input[1]) {
	case '*': // "pf*"
		_input++;
		mode = R_PRINT_SEEFLAGS;
		break;
	case 'q': // "pfq"
		_input++;
		mode = R_PRINT_QUIET | R_PRINT_MUSTSEE;
		break;
	case 'd': // "pfd"
		_input++;
		mode = R_PRINT_DOT;
		break;
	case 'j': // "pfj"
		_input++;
		mode = R_PRINT_JSON;
		break;
	case 'v': // "pfv"
		_input++;
		mode = R_PRINT_VALUE | R_PRINT_MUSTSEE;
		break;
	case 'c': // "pfc"
		_input++;
		mode = R_PRINT_STRUCT;
		break;
	case 's': { // "pfs"
		const char *val = NULL;
		_input += 2;
		if (*_input == '.') {
			_input++;
			val = sdb_get (core->print->formats, _input, NULL);
			if (val) {
				r_cons_printf ("%d\n", r_print_format_struct_size (core->print, val, mode, 0));
			} else {
				R_LOG_WARN ("Struct %s not defined", _input);
				r_core_cmd_help_match (core, help_msg_pf, "pfs");
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') {
				_input++;
			}
			if (*_input) {
				r_cons_printf ("%d\n", r_print_format_struct_size (core->print, _input, mode, 0));
			} else {
				R_LOG_WARN ("Struct %s not defined", _input);
				r_core_cmd_help_match (core, help_msg_pf, "pfs");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_pf, "pfs");
		}
		return;
	}
	case '?': // "pf?"
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
				const char *struct_name = r_str_trim_head_ro (_input);
				const char *val = sdb_const_get (core->print->formats, struct_name, NULL);
				if (val) {
					r_cons_printf ("%s\n", val);
				} else {
					R_LOG_ERROR ("Struct %s is not defined", _input);
				}
			}
		} else {
			r_core_cmd_help (core, help_msg_pf);
		}
		return;
	case 'b': // "pfb"
		cmd_pfb (core, _input);
		return;
	case 'o': // "pfo"
		if (_input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_pf, "pfo");
		} else if (_input[2] == ' ') {
			const char *fname = r_str_trim_head_ro (_input + 3);
			char *tmp = r_str_newf (R_JOIN_2_PATHS (R2_SDB_FORMAT, "%s"), fname);
			char *path = r_str_r2_prefix (tmp);
			if (r_str_endswith (_input, ".h")) {
				char *error_msg = NULL;
				const char *dir = r_config_get (core->config, "dir.types");
				char *out = r_anal_cparse_file (core->anal, path, dir, &error_msg);
				if (out) {
					r_anal_save_parsed_type (core->anal, out);
					r_core_cmd0 (core, ".ts*");
					free (out);
				} else {
					R_LOG_ERROR ("Cannot parse: %s", error_msg);
				}
			} else {
				/// XXX not sure what this code is suposed to be used for
				char *home = r_xdg_datadir ("format");
				if (!r_core_cmd_file (core, home) && !r_core_cmd_file (core, path)) {
					if (!r_core_cmd_file (core, _input + 3)) {
						R_LOG_ERROR ("pfo: cannot open format file at '%s'", path);
					}
				}
				free (home);
			}
			free (path);
			free (tmp);
		} else {
			RList *files;
			RListIter *iter;
			const char *fn;
			char *home = r_xdg_datadir ("format");
			if (home) {
				files = r_sys_dir (home);
				if (files) {
					r_list_sort (files, (RListComparator)strcmp);
					r_list_foreach (files, iter, fn) {
						if (is_pfo_file (fn)) {
							r_cons_println (core->cons, fn);
						}
					}
					r_list_free (files);
				}
				free (home);
			}
			char *path = r_str_r2_prefix (R2_SDB_FORMAT R_SYS_DIR);
			if (path) {
				files = r_sys_dir (path);
				if (files) {
					r_list_sort (files, (RListComparator)strcmp);
					r_list_foreach (files, iter, fn) {
						if (is_pfo_file (fn)) {
							r_cons_println (core->cons, fn);
						}
					}
					r_list_free (files);
				}
				free (path);
			}
		}
		return;
	} // switch

	input = strdup (_input);
	/* syntax aliasing bridge for 'pf foo=xxd' -> 'pf.foo xxd' */
	if (input[1] == ' ') {
		char *eq = strchr (input + 2, '=');
		if (eq) {
			input[1] = '.';
			*eq = ' ';
		}
	}

	bool listFormats = false;
	if (input[1] == '.') {
		listFormats = true;
	} else if (!strcmp (input, "*") && mode == R_PRINT_SEEFLAGS) {
		listFormats = true;
	}

	core->print->reg = core->dbg->reg;
	core->print->get_register = r_reg_get;
	core->print->get_register_value = r_reg_get_value;

	int o_blocksize = core->blocksize;

	if (listFormats) {
		core->print->num = core->num;
		/* print all stored format */
		if (!input[1] || !input[2]) { // "pf."
			SdbListIter *iter;
			SdbKv *kv;
			SdbList *sdbls = sdb_foreach_list (core->print->formats, true);
			ls_foreach (sdbls, iter, kv) {
				r_cons_printf ("pf.%s %s\n", sdbkv_key (kv), sdbkv_value (kv));
			}
			/* delete a format */
		} else if (input[1] && input[2] == '-') { // "pf-"
			if (input[3] == '*') { // "pf-*"
				sdb_free (core->print->formats);
				core->print->formats = sdb_new0 ();
			} else { // "pf-xxx"
				sdb_unset (core->print->formats, input + 3, 0);
			}
		} else {
			char *name = strdup (input + (input[1] ? 2 : 1));
			char *space = strchr (name, ' ');
			char *eq = strchr (name, '=');
			char *dot = strchr (name, '.');
			if (dot) {
				*dot = 0;
			}
			if (!space && !sdb_const_get (core->print->formats, name, NULL)) {
				R_LOG_ERROR ("Unknown format name '%s'", name);
				goto err_name;
			}
			if (dot) {
				*dot = '.';
			}
			if (space) {
				const char *afterspace = r_str_trim_head_ro (space + 1);
				if (*afterspace == '=' && eq) {
					r_str_cpy (space, afterspace);
					space = NULL;
				}
			}

			if (eq && !dot) {
				*eq = ' ';
				space = eq;
				eq = NULL;
			}

			/* store a new format */
			if (space && (!eq || space < eq)) {
				*space++ = 0;
				if (strchr (name, '.')) {
					R_LOG_ERROR ("Struct or fields name can not contain a dot (%s)", name);
				} else {
					// pf.foo=xxx
					sdb_set (core->print->formats, name, space, 0);
				}
				goto err_name;
			}

			if (!strchr (name, '.') && !sdb_const_get (core->print->formats, name, NULL)) {
				R_LOG_ERROR ("Cannot find '%s' format", name);
				goto err_name;
			}

			char *delim = strchr (name, '.');
			if (delim) {
				int len = delim - name;
				if (len > 0) {
					name[len] = '\0';
				}
			}

			/* Load format from name into fmt to get the size */
			/* Make sure the structure will be printed entirely */
			char *fmt = sdb_get (core->print->formats, name, NULL);
			if (fmt) {
				// TODO: what is +10 magic number?
				// Backtracks to commit e5e23c237755cdeb13ba15938c93ada590e453db / issue #2808
				int size = r_print_format_struct_size (core->print, fmt, mode, 0) + 10;
				if (size > core->blocksize) {
					r_core_block_size (core, size);
				}
				free (fmt);
			}
			/* display a format */
			if (dot) {
				*dot++ = 0;
				eq = strchr (dot, '=');
				if (eq) { // Write mode (pf.field=value)
					*eq++ = 0;
					r_str_trim_tail (name);
					mode = R_PRINT_MUSTSET;
					r_print_format (core->print, core->addr,
						core->block, core->blocksize, name, mode, eq, dot);
				} else {
					r_print_format (core->print, core->addr,
						core->block, core->blocksize, name, mode, NULL, dot);
				}
			} else {
				r_print_format (core->print, core->addr,
					core->block, core->blocksize, name, mode, NULL, NULL);
			}
		err_name:
			free (name);
		}
	} else {
		/* Make sure the structure will be printed entirely */
		ut8 *buf = NULL;
		const char *fmt = r_str_trim_head_ro (input + 1);
		int struct_sz = r_print_format_struct_size (core->print, fmt, mode, 0);
		int size = R_MAX (core->blocksize, struct_sz);
		if (size < 1) {
			goto err_buf;
		}
		buf = calloc (1, size);
		if (!buf) {
			goto err_buf;
		}
		memcpy (buf, core->block, core->blocksize);

		char *args = strdup (fmt);
		if (!args) {
			goto err_args;
		}

		/* check if fmt is '\d+ \d+<...>', common mistake due to usage string */
		char *save_ptr = NULL;
		const char *arg1 = r_str_tok_r (args, " ", &save_ptr);
		if (arg1 && r_str_isnumber (arg1)) {
			r_core_cmd_help_match (core, help_msg_pf, "pf");
			goto err_arg1;
		}
		if (v2) {
			r_print_format2 (core->print, core->addr,
				buf, size, fmt, mode, NULL, NULL);
		} else {
			r_print_format (core->print, core->addr,
				buf, size, fmt, mode, NULL, NULL);
		}
	err_arg1:
		free (args);
	err_args:
		free (buf);
	err_buf:
		;
	}
	free (input);
	r_core_block_size (core, o_blocksize);
}

// > pxa
/* In this function, most of the buffers have 4 times
 * the required length. This is because we supports colours,
 * that are 4 chars long. */
#define append(x, y) if (x && y) { strcat (x, y); x += strlen (y); }
static void annotated_hexdump(RCore *core, const char *str, int len) {
	R_RETURN_IF_FAIL (core);
	if (!str || len < 1) {
		return;
	}
	const int usecolor = r_config_get_i (core->config, "scr.color");
	int nb_cols = r_config_get_i (core->config, "hex.cols");
	core->print->use_comments = r_config_get_i (core->config, "hex.comments");
	int flagsz = r_config_get_i (core->config, "hex.flagsz");
	bool show_section = r_config_get_b (core->config, "hex.section");
	bool show_offset = r_config_get_b (core->config, "hex.addr");
	const ut8 *buf = core->block;
	ut64 addr = core->addr;
	int color_idx = 0;
	char *bytes, *chars;
	char *ebytes, *echars; // They'll walk over the vars above
	ut64 fend = UT64_MAX;
	int i, j, low, max, here, rows;
	bool marks = false, setcolor = true, hascolor = false;
	ut8 ch = 0;
	char *colors[10] = { NULL };
	for (i = 0; i < 10; i++) {
		colors[i] = r_cons_rainbow_get (core->cons, i, 10, false);
	}
	const int col = core->print->col;
	RFlagItem *curflag = NULL;
	char **note;
	bool html = r_config_get_b (core->config, "scr.html");
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
	if (nb_cols < 1) {
		return;
	}

	nb_cons_cols = 12 + nb_cols * 2 + (nb_cols / 2);
	nb_cons_cols += 17;
	rows = len / nb_cols;

	chars = calloc (nb_cols * 40, sizeof (char));
	if (!chars) {
		goto err_chars;
	}
	note = calloc (nb_cols, sizeof (char *));
	if (!note) {
		goto err_note;
	}
	size_t bytes_size = (64 + nb_cons_cols * 40);
	bytes = calloc (bytes_size, 1);
	if (!bytes) {
		goto err_bytes;
	}
#if 1
	char addrpad[32];
	int addrpadlen = snprintf (addrpad, 0, "%08"PFMT64x, addr) - 8;
	if (addrpadlen > 0) {
		memset (addrpad, ' ', addrpadlen);
		addrpad[addrpadlen] = 0;
		r_str_ncpy (bytes, addrpad, bytes_size);
	} else {
		*addrpad = 0;
		addrpadlen = 0;
	}
	if (show_offset) {
		r_str_ncpy (bytes + addrpadlen, "- offset -  ", bytes_size - addrpadlen);
	}
#endif
	j = strlen (bytes);
	for (i = 0; i < nb_cols; i += 2) {
		snprintf (bytes + j, bytes_size - j, format, (i & 0xf), (i + 1) & 0xf);
		j += step;
	}
	if (!compact) {
		j--;
	}
	r_str_ncpy (bytes + j, "     ", bytes_size - j);
	j += 2;
	for (i = 0; i < nb_cols; i++) {
		snprintf (bytes + j + i, bytes_size - j - i, "%0X", i % 17);
	}
	if (usecolor) {
		r_kons_print (core->cons, Color_GREEN);
		r_kons_print (core->cons, bytes);
		r_kons_print (core->cons, Color_RESET);
	} else {
		r_kons_print (core->cons, bytes);
	}
	r_cons_newline (core->cons);

	// hexdump
	for (i = 0; i < rows; i++) {
		bytes[0] = '\0';
		chars[0] = '\0';
		ebytes = bytes;
		echars = chars;
		ut64 ea = addr;
		if (core->print->pava) {
			r_io_p2v (core->io, addr, &ea);
		}
		if (usecolor) {
			append (ebytes, core->cons->context->pal.addr);
		}
		if (show_section) {
			const char * name = r_core_get_section_name (core, ea);
			char *s = r_str_newf ("%20s ", name);
			append (ebytes, s);
			free (s);
		}
		ebytes += snprintf (ebytes, 20, "0x%08"PFMT64x, ea);
		if (usecolor) {
			append (ebytes, Color_RESET);
		}
		append (ebytes, (col == 1)? " |": "  ");
		bool hadflag = false;
		for (j = 0; j < nb_cols; j++) {
			setcolor = true;
			R_FREE (note[j]);

			// TODO: in pava mode we should read addr or ea? // imho ea. but wat about hdrs and such
			RIntervalNode *meta_node = r_meta_get_in (core->anal, ea + j, R_META_TYPE_FORMAT);
			RAnalMetaItem *meta = meta_node ? meta_node->data : NULL;
			if (meta && meta->type == R_META_TYPE_FORMAT && meta_node->start == addr + j) {
				r_kons_printf (core->cons, ".format %s ; size=", meta->str);
				r_core_cmd_callf (core, "pfs %s", meta->str);
				r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x, meta->str, meta_node->start);
				if (usecolor) {
					append (ebytes, Color_INVERT);
					append (echars, Color_INVERT);
				}
				hadflag = true;
			}
			if (meta) {
				meta = NULL;
			}
			// collect comments
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr + j);
			if (comment) {
				note[j] = r_str_newf (";%s", comment);
				marks = true;
			}
			const RList *list = r_flag_get_list (core->flags, addr + j);
			RListIter *iter;
			RFlagItem *fi;
			ut64 flagsize = 0;
			ut64 flagaddr = 0;
			bool found = false;
			char *flagname = NULL;
			ut64 at = addr + j;
			if (r_list_empty (list)) {
				// get flag fnear and check for size
				RFlagItem *fnear = r_flag_get_at (core->flags, at, true);
				if (fnear) {
					if (fnear->addr <= at) {
						if (fnear->addr + fnear->size >= at) {
							found = true;
						}
					}
					if (found) {
						flagaddr = fnear->addr;
						if (fnear->addr== at) {
							free (flagname);
							flagname = fnear->name;
						}
#if 0
// TODO missing color here?
						if (fnear->color) {
							curflag = fnear;
						}
#endif
						if (!curflag) {
							curflag = fnear;
						}
						hascolor = false;
					}
				}
			} else {
				r_list_foreach (list, iter, fi) {
					flagsize = R_MAX (flagsize, fi->size);
					const char *fi_color = r_flag_item_set_color (core->flags, fi, NULL);
					if (fi_color) {
						curflag = fi;
					}
					if (!flagaddr || fi_color) {
						flagaddr = fi->addr;
						if (fi->addr == at) {
							free (flagname);
							flagname = strdup (fi->name);
						}
						if (!fi_color) {
							curflag = fi;
						}
					}
				}
				if (curflag) {
					hascolor = false;
					found = true;
				}
			}
			// collect flags
			if (found) {
				if (flagsz) {
					flagsize = flagsz;
				}
				if (flagsize) {
					fend = addr + flagsize;
				} else {
					fend = addr + j + flagsize;
				}
				const char *name = flagname? r_name_filter_ro (flagname): NULL;
				if (name) {
					free (note[j]);
					note[j] = r_str_prepend (strdup (name), "/");
				} else {
					free (note[j]);
					note[j] = NULL;
				}
				marks = true;
				color_idx++;
				color_idx %= 10;
				if (show_section) {
					r_kons_printf (core->cons, "%20s ", "");
				}
				if (flagaddr == addr + j) {
					if (usecolor) {
						append (ebytes, Color_INVERT);
						append (echars, Color_INVERT);
					}
					hadflag = true;
				}
			} else {
				// Are we past the current flag?
				if (curflag && addr + j > (curflag->addr + curflag->size)) {
					setcolor = false;
					curflag = NULL;
				}
				// Turn colour off if we're at the end of the current flag
				if (fend == UT64_MAX || fend <= addr + j) {
					setcolor = false;
				}
			}
			R_FREE (flagname);
			hascolor = false;
			if (usecolor) {
				if (!setcolor) {
					const char *bytecolor = r_print_byte_color (core->print, addr + j, ch);
					if (bytecolor) {
						append (ebytes, bytecolor);
						append (echars, bytecolor);
						hascolor = true;
					}
				} else if (!hascolor) {
					hascolor = true;
					const char *curcolor = NULL;
					if (curflag) {
						const char *fimcolor = r_flag_item_set_color (core->flags, curflag, NULL);
						if (fimcolor) {
							curcolor = fimcolor;
						}
					}
					if (curcolor) {
						char *ansicolor = r_cons_pal_parse (core->cons, curcolor, NULL);
						if (ansicolor) {
							append (ebytes, ansicolor);
							append (echars, ansicolor);
							free (ansicolor);
						}
					} else { // Use "random" colours
						append (ebytes, colors[color_idx]);
						append (echars, colors[color_idx]);
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
						if (html || !usecolor) {
							append (ebytes, "[");
							append (echars, "[");
						} else {
							append (echars, Color_INVERT);
							append (ebytes, Color_INVERT);
						}
					}
				} else {
					if (here >= low && here < max) {
						if (html || !usecolor) {
							append (ebytes, "[");
							append (echars, "[");
						} else {
							if (usecolor) {
								append (ebytes, Color_INVERT);
								append (echars, Color_INVERT);
							}
						}
					}
				}
			}
			r_hex_from_byte (ebytes, ch & 0xff);
			ebytes[2] = 0;
			ebytes += strlen (ebytes);
			if (hadflag) {
				if (usecolor) {
					append (ebytes, Color_INVERT_RESET);
					append (echars, Color_INVERT_RESET);
				}
				hadflag = false;
			}
			*echars++ = IS_PRINTABLE (ch)? ch: '.';
			*echars = 0;
			if (core->print->cur_enabled && max == here) {
				if (!html && usecolor) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				hascolor = false;
			}

			if (j < (nb_cols - 1) && (j % 2) && !compact) {
				append (ebytes, " ");
			}

			if (fend != UT64_MAX && fend == addr + j + 1) {
				if (!html && usecolor) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				fend = UT64_MAX;
				hascolor = false;
			}
		}
		if (!html && usecolor) {
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
			char *out = calloc (out_sz, sizeof (char));
			memset (out, ' ', nb_cons_cols - 1);
			for (j = 0; j < nb_cols; j++) {
				if (note[j]) {
					int off = (j * 3) - (j / 2) + 13;
					int notej_len = strlen (note[j]);
					int sz = R_MIN (notej_len, nb_cons_cols - off);
					if (compact) {
						off -= (j / 2);
					} else {
						if (j % 2) {
							off--;
						}
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
				r_kons_print (core->cons, addrpad);
				r_kons_print (core->cons, out + 1);
				r_cons_newline (core->cons);
			}
			marks = false;
			free (out);
		}
		r_kons_print (core->cons, bytes);
		r_kons_print (core->cons, chars);

		if (core->print->use_comments) {
			for (j = 0; j < nb_cols; j++) {
				char *comment = core->print->get_comments (core->print->user, addr + j);
				if (comment) {
					r_kons_printf (core->cons, " ; %s", comment);
					free (comment);
				}
			}
		}

		r_cons_newline (core->cons);
		addr += nb_cols;
	}

	free (bytes);
 err_bytes:
	free (note);
 err_note:
	free (chars);
 err_chars:
	for (i = 0; i < R_ARRAY_SIZE (colors); i++) {
		R_FREE (colors[i]);
	}
}

R_API void r_core_print_examine(RCore *core, const char *str) {
	char cmd[128], *p;
	ut64 addr = core->addr;
	int size = core->anal->config->bits / 4;
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
	case 'w':
		size = 4;
		// fallthrough
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

struct count_pz_t {
	RSpace *flagspace;
	ut64 addr;
	ut64 size;
	int *ret;
};

static bool count_pzs(RFlagItem *fi, void *u) {
	struct count_pz_t *user = (struct count_pz_t *)u;
	if (fi->space == user->flagspace &&
	    ((user->addr <= fi->addr && fi->addr < user->addr + user->size) ||
	     (user->addr <= fi->addr + fi->size && fi->addr + fi->size < user->addr + user->size))) {
		(*user->ret)++;
	}

	return true;
}
static bool count_pzf(RFlagItem *fi, void *u) {
	struct count_pz_t *user = (struct count_pz_t *)u;
	if (fi->addr <= user->addr && user->addr < fi->addr + fi->size) {
		(*user->ret)++;
	}
	return true;
}

static int printzoomcallback(void *cbarg, int mode, ut64 addr, ut8 *bufz, ut64 size) {
	RCore *core = (RCore *) cbarg;
	int j, ret = 0;
	struct count_pz_t u;

	switch (mode) {
	case 'a':
		{
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
		int value = 0;
		if (fcn) {
			value = r_list_length (fcn->bbs);
		}
		return value;
		}
		break;
	case 'A':
		{
		RCoreAnalStats *as = r_core_anal_get_stats (core, addr, addr + size * 2, size);
		int i;
		int value = 0;
		for (i = 0; i < 1; i++) {
			value += as->block[i].functions;
			value += as->block[i].in_functions;
			value += as->block[i].comments;
			value += as->block[i].symbols;
			value += as->block[i].flags;
			value += as->block[i].strings;
			value += as->block[i].blocks;
			value *= 20;
		}
		r_core_anal_stats_free (as);
		return value;
		}
		break;
	case '0': // "pz0"
		for (j = 0; j < size; j++) {
			if (bufz[j] == 0) {
				ret++;
			}
		}
		break;
	case 'e': // "pze"
		ret = (ut8) (r_hash_entropy_fraction (bufz, size) * 255);
		break;
	case 'f': // "pzf"
		u.addr = addr;
		u.ret = &ret;
		r_flag_foreach (core->flags, count_pzf, &u);
		break;
	case 'F': // "pzF"
		for (j = 0; j < size; j++) {
			if (bufz[j] == 0xff) {
				ret++;
			}
		}
		break;
	case 'p': // "pzp"
		for (j = 0; j < size; j++) {
			if (IS_PRINTABLE (bufz[j])) {
				ret++;
			}
		}
		break;
	case 's': // "pzs"
		u.flagspace = r_flag_space_get (core->flags, R_FLAGS_FS_STRINGS);
		u.addr = addr;
		u.size = size;
		u.ret = &ret;
		r_flag_foreach (core->flags, count_pzs, &u);
		break;
	case 'h': // "pzh" head
	default:
		ret = *bufz;
	}
	return ret;
}

R_API void r_core_print_cmp(RCore *core, ut64 from, ut64 to) {
	long int delta = 0;
	int col = core->cons->columns > 123;
	ut8 *b = malloc (core->blocksize);
	ut64 addr = core->addr;
	memset (b, 0xff, core->blocksize);
	delta = addr - from;
	r_io_read_at (core->io, to + delta, b, core->blocksize);
	r_print_hexdiff (core->print, core->addr, core->block,
		to + delta, b, core->blocksize, col);
	free (b);
}

static void cmd_print_pwn(const RCore *core) {
	r_cons_printf ("easter egg license has expired\n");
}

static int cmd_print_pxA(RCore *core, int len, const char *input) {
	RConsPrintablePalette *pal = &core->cons->context->pal;
	int show_offset = true;
	int cols = r_config_get_i (core->config, "hex.cols");
	int show_color = r_config_get_i (core->config, "scr.color");
	int onechar = r_config_get_i (core->config, "hex.onechar");
	bool hex_offset = r_config_get_i (core->config, "hex.addr");
	int bgcolor_in_heap = false;
	bool show_cursor = core->print->cur_enabled;
	char buf[2];
	char *bgcolor, *fgcolor, *text;
	ut64 i, c, oi;
	RAnalOp op;
	ut8 *data;
	int datalen;
	if (*input == 'v') {
		datalen = cols * 8 * core->cons->rows;
		data = malloc (datalen);
		r_io_read_at (core->io, core->addr, data, datalen);
		len = datalen;
	} else {
		data = core->block;
		datalen = core->blocksize;
	}
	if (len < 1) {
		len = datalen;
	}
	if (len < 0 || len > datalen) {
		R_LOG_ERROR ("Invalid length");
		return 0;
	}
	if (onechar) {
		cols *= 4;
	} else {
		cols *= 2;
	}
	RCons *cons = core->cons;
	if (show_offset) {
		char offstr[128];
		snprintf (offstr, sizeof (offstr),
			"0x%08"PFMT64x "  ", core->addr);
		if (strlen (offstr) > 12) {
			cols -= ((strlen (offstr) - 12) * 2);
		}
	}
	for (oi = i = c = 0; i < len; c++) {
		if (i && (cols != 0) && !(c % cols)) {
			show_offset = true;
			r_cons_printf ("  %" PFMT64u "\n", i - oi);
			oi = i;
		}
		if (show_offset && hex_offset) {
			r_cons_printf ("0x%08"PFMT64x "  ", core->addr + i);
			show_offset = false;
		}
		if (bgcolor_in_heap) {
			free (bgcolor);
			bgcolor_in_heap = false;
		}
		bgcolor = Color_BGBLACK;
		fgcolor = Color_WHITE;
		text = NULL;
		if (r_anal_op (core->anal, &op, core->addr + i, data + i, len - i, R_ARCH_OP_MASK_BASIC) <= 0) {
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
		case R_ANAL_OP_TYPE_RPUSH:
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
				r_cons_invert (cons, 1, 1);
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
				r_kons_print (core->cons, text);
			} else {
				r_kons_print (core->cons, "  ");
			}
		}
		if (show_cursor) {
			if (core->print->cur >= i && core->print->cur < i + opsz) {
				r_cons_invert (cons, 0, 1);
			}
		}
		i += opsz;
		r_anal_op_fini (&op);
	}
	r_cons_printf ("  %" PFMT64d "\n", i - oi);
	if (bgcolor_in_heap) {
		free (bgcolor);
	}
	if (data != core->block) {
		free (data);
	}

	return true;
}

static void print_encrypted_block(RCore *core, const char *algo, const char *key, int direction, const char *iv) {
	int keylen = 0;
	ut8 *binkey = NULL;
	if (!strncmp (key, "s:", 2)) {
		binkey = (ut8 *)strdup (key + 2);
		keylen = strlen (key + 2);
	} else {
		binkey = (ut8 *)strdup (key);
		keylen = r_hex_str2bin (key, binkey);
	}
	if (!binkey) {
		return;
	}
	if (keylen < 1) {
		const char *mode = (!direction)? "Encryption": "Decryption";
		R_LOG_ERROR ("%s key not defined", mode);
		free (binkey);
		return;
	}
	RMutaSession *cj = r_muta_use (core->muta, algo);
	if (cj && cj->h->type == R_MUTA_TYPE_CRYPTO) {
		if (r_muta_session_set_key (cj, binkey, keylen, 0, direction)) {
			if (iv) {
				ut8 *biniv = malloc (strlen (iv) + 1);
				int ivlen = r_hex_str2bin (iv, biniv);
				if (ivlen < 1) {
					ivlen = strlen (iv);
					strcpy ((char *)biniv, iv);
				}
				if (!r_muta_session_set_iv (cj, biniv, ivlen)) {
					R_LOG_ERROR ("Invalid IV");
					return;
				}
			}
			r_muta_session_update (cj, (const ut8 *)core->block, core->blocksize);

			int result_size = 0;
			ut8 *result = r_muta_session_get_output (cj, &result_size);
			if (result) {
				r_print_bytes (core->print, result, result_size, "%02x", 0);
				free (result);
			}
		}
		free (cj);
	} else {
		R_LOG_ERROR ("Unknown %s algorithm '%s'", ((!direction)? "encryption": "decryption"), algo);
	}
	free (binkey);
	return;
}

static void cmd_print_op(RCore *core, const char *input) {
	ut8 *buf = NULL;
	if (!input[0]) {
		return;
	}
	switch (input[1]) {
	case 'a':
	case 's':
	case 'A':
	case 'x':
	case 'r':
	case 'l':
	case 'm':
	case 'd':
	case 'o':
	case '2':
	case '4':
		if (input[2]) {  // parse val from arg
			buf = r_core_transform_op (core, input + 3, input[1]);
		} else {  // use clipboard instead of val
			buf = r_core_transform_op (core, NULL, input[1]);
		}
		break;
	case 'n':
		buf = r_core_transform_op (core, "ff", 'x');
		break;
	case 'k':
		if (input[2] == 'e') { // "poke"
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2poke");
		} else {
			r_core_cmd_help (core, help_msg_po);
		}
		break;
	case 'S': { // "poS"
		char *cmd = strdup (input);
		RList *args = r_str_split_list (cmd, " ", 0);
		char *algo = NULL;
		if (args) {
			algo = r_list_get_n (args, 1);
		}
		if (!args || !algo) {
			char *s = r_muta_list (core->muta, R_MUTA_TYPE_SIGN, 0);
			r_kons_print (core->cons, s);
			free (s);
			r_core_cmd_help_match (core, help_msg_po, "poS");
			break;
		}
		RMutaSession *cj = r_muta_use (core->muta, algo);
		if (cj && cj->h->type == R_MUTA_TYPE_SIGN) {
			char *key = r_list_get_n (args, 2);
			ut8 *binkey = (ut8 *)strdup (key);
			int keylen = r_hex_str2bin (key, binkey);
			if (!keylen) {
				R_LOG_ERROR ("Invalid key");
				break;
			}
			if (!r_muta_session_set_key (cj, binkey, keylen, 0, R_CRYPTO_DIR_ENCRYPT)) {
				break;
			}
			r_muta_session_update (cj, (const ut8 *)core->block, core->blocksize);

			int result_size = 0;
			ut8 *result = r_muta_session_get_output (cj, &result_size);
			if (result) {
				r_print_bytes (core->print, result, result_size, "%02x", 0);
				free (result);
			}
		} else {
			R_LOG_ERROR ("Unsupported signature algorithm: %s", algo);
		}
		break;
	}
	case 'D': // "poD"
	case 'E': { // "poE"
		int direction = (input[1] == 'E')? R_CRYPTO_DIR_ENCRYPT: R_CRYPTO_DIR_DECRYPT;
		char *cmd = strdup (input);
		RList *args = r_str_split_list (cmd, " ", 0);
		char *algo = NULL;
		if (args) {
			algo = r_list_get_n (args, 1);
		}
		if (!args || !algo) {
			char *s = r_muta_list (core->muta, R_MUTA_TYPE_CRYPTO, 0);
			r_kons_print (core->cons, s);
			free (s);
			r_core_cmd_help_match_spec (core, help_msg_po, "po", input[1]);
			break;
		}
		char *key = r_list_get_n (args, 2);
		if (!key) {
			const char *mode = (direction == R_CRYPTO_DIR_ENCRYPT)? "Encryption": "Decryption";
			R_LOG_ERROR ("%s key not defined", mode);
			return;
		}
		char *iv = r_list_get_n (args, 3);
		print_encrypted_block (core, algo, key, direction, iv);
		break;
	}
	case '\0':
	case '?':
	default:
		r_core_cmd_help (core, help_msg_po);
		break;
	}
	if (buf) {
		r_print_hexdump (core->print, core->addr, buf, core->blocksize, 16, 1, 1);
		free (buf);
	}
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
	r_print_raw (core->print, core->addr, core->block, len, mode);
	if (restore_obsz) {
		(void) r_core_block_size (core, obsz);
	}
}

static void _handle_call(RCore *core, char *line, char **str) {
	// XXX: rewrite this function
	R_RETURN_IF_FAIL (core && line && str);
	if (core->rasm && core->rasm->config && !strcmp (core->rasm->config->arch, "x86")) {
		*str = strstr (line, "call ");
		if (!*str) {
			if (strstr (line, "[reloc.")) {
				*str = strstr (line, "jmp ");
				char *bra = strchr (line, ']');
				if (bra) {
					*bra = 0;
				}
			}
		}
	} else if (core->rasm && core->rasm->config && !strcmp (core->rasm->config->arch, "arm")) {
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

static char *strpfx(char *line) {
	char *str = strstr (line, " reloc.");
	if (!str) {
		// XXX leak
		str = strstr (line, " fn.");
		if (str) {
			return str;
		}
		str = strstr (line, " obj.");
		if (!str) {
			str = strstr (line, " str.");
			if (!str) {
				str = strstr (line, " imp.");
				if (!str) {
					str = strstr (line, " fcn.");
					if (!str) {
						str = strstr (line, " hit.");
						if (!str) {
							str = strstr (line, " sub.");
						}
					}
				}
			}
		}
	}
	return str;
}
// TODO: this is just a PoC, the disasm loop should be rewritten
// TODO: this is based on string matching, it should be written upon RAnalOp to know
// when we have a call and such
static void disasm_strings(RCore *core, const char *input, RAnalFunction *fcn) {
	const char *linecolor = NULL;
	char *ox, *qo, *string = NULL;
	char *line, *s, *string2 = NULL;
	char *switchcmp = NULL;
	int i, count;
	int use_color = r_config_get_i (core->config, "scr.color");
	bool show_comments = r_config_get_b (core->config, "asm.comments");
	bool show_offset = r_config_get_b (core->config, "asm.addr");
	bool orig_show_offset = show_offset;
	int asm_tabs = r_config_get_i (core->config, "asm.tabs");
	bool scr_html = r_config_get_b (core->config, "scr.html");
	bool asm_bytes = r_config_get_b (core->config, "asm.bytes");
	bool asm_dwarf = r_config_get_b (core->config, "asm.dwarf");
	bool asm_flags = r_config_get_b (core->config, "asm.flags");
	bool asm_cmt_right = r_config_get_b (core->config, "asm.cmt.right");
	bool asm_emu = r_config_get_b (core->config, "asm.emu");
	bool emu_str = r_config_get_b (core->config, "emu.str");
	r_config_set_i (core->config, "emu.str", true);
	RConsPrintablePalette *pal = &core->cons->context->pal;
	// force defaults
	r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	r_config_set_b (core->config, "asm.dwarf", true);
	r_config_set_i (core->config, "asm.tabs", 0);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "scr.html", false);
	r_config_set_b (core->config, "asm.cmt.right", true);
	r_config_set_b (core->config, "asm.addr", true);

	if (strchr (input, 'q')) { // "pdsfq"
		show_offset = false;
	}
	PJ *pj = NULL;
	if (strchr (input + 2, 'j')) { // "pdsfj"
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	bool pdsfs = false;
	if (strchr (input + 2, 's')) { // "pdsfs"
		pdsfs = true;
	}

	r_kons_push (core->cons);
	line = NULL;
	s = NULL;
	if (r_str_startswith (input, "dsb")) {
		RAnalBlock *bb = r_anal_bb_from_offset (core->anal, core->addr);
		if (bb) {
			line = s = r_core_cmd_strf (core, "pD %"PFMT64u" @ 0x%08"PFMT64x, bb->size, bb->addr);
		}
	} else if (!strncmp (input, "dsf", 3) || !strncmp (input, "dsr", 3)) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
		if (fcn) {
			line = s = r_core_cmd_str (core, "pdr");
		} else {
			R_LOG_ERROR ("Cannot find function");
			r_config_set_i (core->config, "scr.color", use_color);
			r_config_set_i (core->config, "asm.cmt.right", asm_cmt_right);
			goto restore_conf;
		}
	} else if (r_str_startswith (input, "ds ")) {
		line = s = r_core_cmd_strf (core, "pD %s", input + 3);
	} else {
		line = s = r_core_cmd_str (core, "pd");
	}
	r_kons_pop (core->cons);

	r_config_set_b (core->config, "scr.html", scr_html);
	r_config_set_i (core->config, "scr.color", use_color);
	r_config_set_i (core->config, "asm.cmt.right", asm_cmt_right);
	count = r_str_split (s, '\n');
	if (R_STR_ISEMPTY (line) || count < 1) {
	//	R_FREE (s);
		goto restore_conf;
	}
	ut64 addr = UT64_MAX;
	ut64 oaddr = UT64_MAX;
	// r_core_cmd0 (core, "afs"); // TODO include function name
	for (i = 0; i < count; i++) {
		addr = UT64_MAX;
		char *str;
		if (strstr (line, "XREF from")) {
			line += strlen (line) + 1;
			continue;
		}
		ox = strstr (line, "0x");
		qo = strchr (line, '\"');
		R_FREE (string);
		if (ox && ox < line + 20) {
			addr = r_num_get (NULL, ox);
			oaddr = addr;
		}
		if (qo) {
			char *qoe = strrchr (qo + 1, '"');
			if (qoe) {
				int raw_len = qoe - qo - 1;
				int actual_len = 0;
				char *ptr = qo + 1;
				for (; ptr < qoe; ptr++) {
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
		if (asm_flags && pj == NULL && !pdsfs) {
			str = strstr (line, ";-- ");
			if (str) {
				if (!r_str_startswith (str + 4, "case")) {
					r_cons_printf ("%s\n", str);
				}
			}
		}
		// eprintf ("--> (%s)\n", line);
		if (pdsfs) {
			str = strstr (line, " str.");
		} else {
#define USE_PREFIXES 1
#if USE_PREFIXES
			str = strpfx (line);
#else
			if (strchr (line, ';')) {
				const char *dot = r_str_rchr (line, NULL, '.');
				if (dot) {
					const char *o = r_str_rchr (line, dot, ' ');
					if (o) {
						str = (char*)o;
					} else {
						R_LOG_WARN ("missing summary reference: %s", dot);
					}
				}
			}
#endif
		}
		if (str) {
			char *atsign = strchr (str, '@');
			if (atsign) {
				*atsign = 0;
			}
			char *qoe = strchr (str + 1, '\x1b');
			if (!qoe) {
				qoe = strchr (str + 1, ';');
				if (!qoe) {
					qoe = strchr (str + 1, ' ');
				}
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
		if (pdsfs) {
			str = NULL;
		} else {
			_handle_call (core, line, &str);
			if (!str) {
				str = strstr (line, "sym.");
				if (!str) {
					str = strstr (line, "reloc.");
					if (!str) {
						str = strstr (line, "fcn.");
					}
				}
			}
		}
		if (str) {
			char *qoe = strchr (str, ';');
			if (qoe) {
				str = r_str_ndup (str, qoe - str);
			} else {
				str = strdup (str);
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
		if (addr == UT64_MAX) {
			addr = oaddr;
			oaddr = UT64_MAX;
		}
		if (addr != UT64_MAX) {
			const char *str = NULL;
			if (show_comments && !pdsfs) {
				char *comment = r_core_anal_get_comments (core, addr);
				if (R_STR_ISNOTEMPTY (comment)) {
					if (!switchcmp || strcmp (comment, switchcmp)) {
						if (pj) {
							pj_o (pj);
							pj_ki (pj, "addr", addr);
							pj_ks (pj, "comment", comment);
							pj_end (pj);
						} else {
							if (show_offset) {
								r_cons_printf ("%s0x%08"PFMT64x" ", use_color? pal->addr: "", addr);
							}
							r_cons_printf ("%s%s\n", use_color? pal->comment: "", comment);
						}
					}
					if (r_str_startswith (comment, "switch table")) {
						free (switchcmp);
						switchcmp = strdup (comment);
					}
					R_FREE (comment);
				}
			}

			if (fcn && !pj) {
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
								r_cons_printf ("%s0x%08"PFMT64x" "Color_RESET, use_color? pal->addr: "", addr);
							}
							r_cons_printf ("%s 0x%08"PFMT64x "%s\n",
								op, bb->jump, use_color? Color_RESET: "");
							break;
						}
					}
				}
			}
			if (R_STR_ISNOTEMPTY (string)) {
				if (string && r_str_startswith (string, "0x")) {
					str = string;
				}
				if (string2 && r_str_startswith (string2, "0x")) {
					str = string2;
				}
				ut64 ptr = r_num_math (NULL, str);
				RFlagItem *flag = NULL;
				if (str) {
					flag = r_core_flag_get_by_spaces (core->flags, false, ptr);
				}
				if (!flag) {
					if (string && r_str_startswith (string, "0x")) {
						R_FREE (string);
					}
					if (string2 && r_str_startswith (string2, "0x")) {
						R_FREE (string2);
					}
				}
				if (string && addr != UT64_MAX && addr != UT32_MAX) {
					r_str_trim (string);
					if (string2) {
						r_str_trim (string2);
					}
					if (pdsfs) {
						if (r_str_startswith (string, "str.")) {
							char *ns = r_core_cmd_strf (core, "psj @ %s~{string}", string);
							r_str_trim (ns);
							ns = r_str_replace_all (ns, "\n", "\\n");
							ns = r_str_replace_all (ns, "\r", "\\r");
							ns = r_str_replace_all (ns, "\t", "\\t");
							free (string);
							string = ns;
						}
					}
					//// TODO implememnt avoid duplicated strings
					// eprintf ("---> %s\n", string);
					if (pj) {
						pj_o (pj);
						pj_ki (pj, "addr", addr);
						if (flag) {
							pj_ks (pj, "name", flag->name);
						}
						if (R_STR_ISNOTEMPTY (string)) {
							pj_ks (pj, "text", string);
						}
						pj_end (pj);
					} else if (use_color) {
						if (show_offset) {
							r_cons_printf ("%s0x%08"PFMT64x" "Color_RESET, use_color? pal->addr: "", addr);
						}
						if (string2) {
							if (!strcmp (string, string2)) {
								string2 = NULL;
							}
						}
						r_kons_printf (core->cons, "%s%s%s%s%s%s%s\n",
							r_str_get (linecolor),
							r_str_get (string2), string2? " ": "", string,
							flag? " ": "", flag? flag->name: "", Color_RESET);
					} else {
						if (show_offset) {
							r_kons_printf (core->cons, "0x%08"PFMT64x" ", addr);
						}
						r_kons_printf (core->cons, "%s%s%s%s%s\n",
							r_str_get (string2), string2? " ": "", string,
							flag? " ": "", flag? flag->name: "");
					}
				}
			}
		}
		free (str);
		line += strlen (line) + 1;
	}
	// r_cons_printf ("%s", s);
	R_FREE (string2);
	R_FREE (string);
	R_FREE (s);
	R_FREE (switchcmp);
restore_conf:
	r_config_set_b (core->config, "asm.addr", orig_show_offset);
	r_config_set_b (core->config, "asm.dwarf", asm_dwarf);
	r_config_set_b (core->config, "asm.bytes", asm_bytes);
	r_config_set_i (core->config, "asm.tabs", asm_tabs);
	r_config_set_b (core->config, "scr.html", scr_html);
	r_config_set_b (core->config, "asm.emu", asm_emu);
	r_config_set_b (core->config, "emu.str", emu_str);
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	}
}

static bool cmd_print_ph(RCore *core, const char *input) {
	char *algo = NULL;
	ut32 osize = 0, len = core->blocksize;
	int handled_cmd = false;

	const char i0 = input[0];
	if (i0 == '?') {
		r_core_cmd_help (core, help_msg_ph);
		return true;
	}
	if (!i0 || i0 == 'l' || i0 == 'L') {
		RMuta *cry = r_muta_new ();
		char *s = r_muta_list (cry, R_MUTA_TYPE_HASH, 'q');
		r_kons_print (core->cons, s);
		free (s);
		r_muta_free (cry);
		return true;
	}
	if (i0 == 'j') { // "phj"
		RMuta *cry = r_muta_new ();
		char *s = r_muta_list (cry, R_MUTA_TYPE_ALL, 'j');
		r_kons_print (core->cons, s);
		free (s);
		r_muta_free (cry);
		return true;
	}
	if (i0 == 'J') { // "phJ"
		RMuta *cry = r_muta_new ();
		char *s = r_muta_list (cry, R_MUTA_TYPE_HASH, 'J');
		r_kons_print (core->cons, s);
		free (s);
		r_muta_free (cry);
		return true;
	}
	if (i0 == ':') {
		input++;
	}
	input = r_str_trim_head_ro (input);
	char *cmd = strdup (input);
	RList *args = r_str_split_list (cmd, " ", 0);
	if (args) {
		algo = r_list_get_n (args, 0);
	}
	char *len_str = r_list_get_n (args, 1);
	if (len_str) {
		len = r_num_math (core->num, len_str);
		osize = core->blocksize;
		if (len > core->blocksize) {
			r_core_block_size (core, len);
			if (len != core->blocksize) {
				R_LOG_ERROR ("Invalid block size");
				r_core_block_size (core, osize);
				return false;
			}
			r_core_block_read (core);
		}
	} else {
		osize = len;
	}
	r_cons_printf ("%s\n", r_hash_tostring (NULL, algo, core->block, len));
	return handled_cmd;
}

static ut32 convert(ut8 *data, const char *bo) {
	ut32 n = 0;
	while (*bo) {
		int i = *bo - '0';
		if (i < 1 || i > 4) {
			break;
		}
		n <<= 8;
		n |= (data[i - 1] & 0xff);
		bo++;
	}
	return n;
}

static void cmd_print_pv(RCore *core, const char *input, bool useBytes) {
	const char *stack[] = {
		"ret", "arg0", "arg1", "arg2", "arg3", "arg4", NULL
	};
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->print->config);
	ut8 *block = core->block;
	int blocksize = core->blocksize;
	ut8 *heaped_block = NULL;
	ut8 *block_end = core->block + blocksize;
	int i, n = core->rasm->config->bits / 8;
	int type = 'v';
	bool fixed_size = true;
	switch (input[0]) {
	case 'p': // "pvp"
		input++;
		break;
	case '0':
		// pvp0 == 'pvp 0'
		return;
	case '1': // "pv1"
		n = 1;
		input++;
		break;
	case '2': // "pv2"
		n = 2;
		input++;
		break;
	case '4': // "pv4"
		n = 4;
		input++;
		break;
	case '8': // "pv8"
		n = 8;
		input++;
		break;
	default:
		if (*input && input[1] == 'j') {
			input++;
		}
		fixed_size = false;
		break;
	}
	const char *arg = strchr (input, ' ');
	arg = arg? r_str_trim_head_ro (arg + 1): input;

	ut64 repeat = r_num_math (core->num, arg);
	if (repeat < 0) {
		repeat = 1;
	}
	if (useBytes && n > 0 && repeat > 0) {
		repeat /= n;
	}
	if (repeat < 1) {
		repeat = 1;
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
	case '*': { // "pv*"
		for (i = 0; i < repeat; i++) {
			const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config);
			ut64 at = core->addr + (i * n);
			ut8 buf[8];
			r_io_read_at (core->io, at, buf, sizeof (buf));
			ut8 *b = buf;
			switch (n) {
			case 1:
				r_cons_printf ("f pval.0x%08"PFMT64x"=%d\n", at, r_read_ble8 (b));
				break;
			case 2:
				r_cons_printf ("f pval.0x%08"PFMT64x"=%d\n", at, r_read_ble16 (b, be));
				break;
			case 4:
				r_cons_printf ("f pval.0x%08"PFMT64x"=%d\n", at, r_read_ble32 (b, be));
				break;
			case 8:
			default:
				r_cons_printf ("f pval.0x%08"PFMT64x"=%"PFMT64d"\n", at, r_read_ble64 (b, be));
				break;
			}
		}
		break;
		  }
	case 'u': // "pvu" // unsigned
	case 'd': // "pvd" // signed
		do {
			repeat--;
			const int p_bits = core->rasm->config->bits / 8;
			if (block + 8 >= block_end) {
				int blockdelta = block - core->block;
				if (heaped_block) {
					blockdelta = block - heaped_block;
					free (heaped_block);
				}
				blocksize = ((1 + repeat) * 8) + 8;
				block_end = block + blocksize;
				heaped_block = calloc (blocksize, 1);
				if (!heaped_block) {
					break;
				}
				r_io_read_at (core->io, core->addr + blockdelta, heaped_block, blocksize);
				block = heaped_block;
			}
			ut64 v;
			if (!fixed_size) {
				n = 0;
			}
			switch (n) {
			case 1:
				v = r_read_ble8 (block);
				if (*input == 'u') {
					r_cons_printf ("%u\n", (unsigned char)v);
				} else {
					r_cons_printf ("%d\n", (signed char)v);
				}
				block += 1;
				break;
			case 2:
				v = r_read_ble16 (block, be);
				if (*input == 'u') {
					r_cons_printf ("%u\n", (unsigned short)v);
				} else {
					r_cons_printf ("%d\n", (short)v);
				}
				block += 2;
				break;
			case 4:
				v = r_read_ble32 (block, be);
				if (*input == 'u') {
					r_cons_printf ("%u\n", (ut32)v);
				} else {
					r_cons_printf ("%d\n", (st32)v);
				}
				block += 4;
				break;
			case 8:
				v = r_read_ble64 (block, be);
				if (*input == 'u') {
					r_cons_printf ("%" PFMT64u "\n", (ut64)v);
				} else {
					r_cons_printf ("%" PFMT64d "\n", (st64)v);
				}
				block += 8;
				break;
			default:
				v = r_read_ble64 (block, be);
				switch (p_bits) { // core->rasm->config->bits / 8) {
				case 1: r_cons_printf ("%" PFMT64d "\n", v & UT8_MAX); break;
				case 2: r_cons_printf ("%" PFMT64d "\n", v & UT16_MAX); break;
				case 4: r_cons_printf ("%" PFMT64d "\n", v & UT32_MAX); break;
				case 8: r_cons_printf ("%" PFMT64d "\n", v & UT64_MAX); break;
				default: break;
				}
				block += p_bits;
				break;
			}
		} while (repeat > 0);
		free (heaped_block);
		break;
	case 'j': { // "pvj"
		PJ *pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
		ut64 at = core->addr;
		for (i = 0; i < repeat; i++) {
			ut8 buf[8];
			r_io_read_at (core->io, at, buf, sizeof (buf));
			char *str = r_core_cmd_strf (core, "ps@0x%"PFMT64x, at);
			r_str_trim (str);
			char *p = str;
			if (p) {
				while (*p) {
					if (*p == '\\' && p[1] == 'x') {
						memmove (p, p + 4, strlen (p + 4) + 1);
					}
					p++;
				}
			}
			// r_num_get is gonna use a dangling pointer since the internal
			// token that RNum holds ([$$]) has been already freed by r_core_cmd_str
			// r_num_math reload a new token so the dangling pointer is gone
			pj_o (pj);
			pj_k (pj, "value");
			switch (n) {
			case 1:
				pj_i (pj, r_read_ble8 (buf));
				break;
			case 2:
				pj_n (pj, r_read_ble16 (buf, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config)));
				break;
			case 4:
				pj_n (pj, r_read_ble32 (buf, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config)));
				break;
			case 8:
			default:
				pj_n (pj, r_read_ble64 (buf, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config)));
				break;
			}
			pj_ks (pj, "string", str);
			pj_kn (pj, "address", at);
			pj_end (pj);
			free (str);
			at += n;
		}
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
		break;
	}
	case 'e': // "pve"
		{
			int size = 4; // default is 4.. or asm.bits?
			const char *byteorder = r_config_get_b (core->config, "cfg.bigendian")
				? "1234": "4321";
			if (strchr (input, ' ')) {
				size = atoi (input + 1);
				byteorder = r_str_trim_head_ro (input + 2);
			} else {
				size = strlen (byteorder);
			}
			int length = size;
			char *space = strchr (byteorder, ' ');
			if (space) {
				length = atoi (space + 1);
			}
			int i = 0;
			if (length + size > 0xfffff) {
				R_LOG_ERROR ("Too large");
				break;
			}
			ut8 * data = calloc (length + size, 1);
			if (data) {
				(void)r_io_read_at (core->io, core->addr, data, length + size);
				while (i < length) {
					ut32 n = convert (data + i, byteorder);
					r_cons_printf ("0x%08"PFMT64x"  %d (0x%08x)\n", core->addr + i, n, n);
					i += size;
				}
				free (data);
			}
		}
		break;
	case '?': // "pv?"
		r_core_cmd_help (core, help_msg_pv);
		break;
	default:;
		// ut64 delta = 0;
		size_t bs = ((repeat + 8) * n);
		heaped_block = calloc (repeat + 8, n);
		r_io_read_at (core->io, core->addr, heaped_block, bs);
		block = heaped_block;
		do {
			repeat--;
			const int p_bits = core->rasm->config->bits / 8;
#if 0
			if (block + 8 >= block_end) {
				if (heaped_block) {
					free (heaped_block);
				}
				blocksize = ((1 + repeat) * 8) + 8;
				block_end = block + blocksize;
				heaped_block = calloc (blocksize, 1);
				if (!heaped_block) {
					R_LOG_ERROR ("invalid block size");
					break;
				}
				r_io_read_at (core->io, core->addr + delta, heaped_block, blocksize);
				block = heaped_block;
			}
#endif
			ut64 v;
			// delta += n;
			if (!fixed_size) {
				n = 0;
			}
			switch (n) {
			case 1:
				v = r_read_ble8 (block);
				r_cons_printf ("0x%02" PFMT64x "\n", v);
				block += 1;
				break;
			case 2:
				v = r_read_ble16 (block, be);
				r_cons_printf ("0x%04" PFMT64x "\n", v);
				block += 2;
				break;
			case 4:
				v = r_read_ble32 (block, be);
				r_cons_printf ("0x%08" PFMT64x "\n", v);
				block += 4;
				break;
			case 8:
				v = r_read_ble64 (block, be);
				r_cons_printf ("0x%016" PFMT64x "\n", v);
				block += 8;
				break;
			default:
				v = r_read_ble64 (block, be);
				switch (p_bits) { // core->rasm->config->bits / 8)
				case 1: r_cons_printf ("0x%02" PFMT64x "\n", v & UT8_MAX); break;
				case 2: r_cons_printf ("0x%04" PFMT64x "\n", v & UT16_MAX); break;
				case 4: r_cons_printf ("0x%08" PFMT64x "\n", v & UT32_MAX); break;
				case 8: r_cons_printf ("0x%016" PFMT64x "\n", v & UT64_MAX); break;
				default: break;
				}
				block += p_bits;
				break;
			}
		} while (repeat > 0);
		free (heaped_block);
		break;
	}
}

static bool cmd_print_blocks(RCore *core, const char *input) {
	bool result = false;
	char mode = input[0];
	RList *list = NULL;
	RCoreAnalStats *as = NULL;
	RTable *t = NULL;
	PJ *pj = NULL;
	if (mode == '?') {
		r_core_cmd_help (core, help_msg_p_minus);
		return false;
	}

	if (mode && mode != ' ') {
		input++;
	}

	int w = (input[0] == ' ')
		? (int)r_num_math (core->num, input + 1)
		: (int)(core->print->cols * 2.7);

	if (w == 0) {
		r_core_cmd_help (core, help_msg_p_minus);
		return false;
	}
	int cols = r_config_get_i (core->config, "hex.cols");
	//int cols = r_cons_get_size (core->cons, NULL) - 30;
	ut64 off = core->addr;
	ut64 from = UT64_MAX;
	ut64 to = 0;

	list = r_core_get_boundaries_prot (core, -1, NULL, "search");
	if (!list) {
		result = true;
		if (mode == 'j') {
			r_cons_println (core->cons, "{}");
		}
		goto cleanup;
	}
	RListIter *iter;
	RIOMap *map;
	r_list_foreach (list, iter, map) {
		ut64 f = r_io_map_begin (map);
		ut64 t = r_io_map_end (map);
		if (f < from) {
			from = f;
		}
		if (t > to) {
			to = t;
		}
	}
	r_list_free (list);
	list = NULL;
	ut64 piece = R_MAX ((to - from) / R_MAX (cols, w), 1);
	as = r_core_anal_get_stats (core, from, to, piece);
	if (!as) {
		if (mode == 'j') {
			r_cons_println (core->cons, "{}");
		}
		goto cleanup;
	}

	switch (mode) {
	case '-': // "p--"
#if 0
		{
			RConsPixel *p = r_cons_pixel_new (80, 80);
			r_cons_pixel_set (p, 5, 5, 1);
			r_cons_pixel_fill (p, 10, 10, 30, 30, 1);
			char *s = r_cons_pixel_drain (p);
			r_cons_printf ("%s%c", s, 10);
			free (s);
		}
#else
		r_print_graphline (core->print, core->block, core->blocksize);
#endif
		goto cleanup;
	case 'j': // "p-j"
		pj = r_core_pj_new (core);
		if (!pj) {
			goto cleanup;
		}
		pj_o (pj);
		pj_kn (pj, "from", from);
		pj_kn (pj, "to", to);
		pj_ki (pj, "blocksize", piece);
		pj_k (pj, "blocks");
		pj_a (pj);
		break;
	case 'h': { // "p-h"
		t = r_core_table_new (core, "navbar");
		if (!t) {
			goto cleanup;
		}
		t->showMode |= SHOW_SUM;
		r_table_set_columnsf (t, "sddddd", "offset", "flags", "funcs", "cmts", "syms", "str");
		break;
	}
	case 'e':
	default:
		r_cons_printf ("0x%08"PFMT64x " [", from);
	}

	const bool use_color = r_config_get_i (core->config, "scr.color");
	int i;
	for (i = 0; i < ((to - from) / piece); i++) {
		ut64 at = from + (piece * i);
		ut64 ate = at + piece;
		ut64 p = (at - from) / piece;
		switch (mode) {
		case 'j':
			pj_o (pj);
			if ((as->block[p].flags)
				|| (as->block[p].functions)
				|| (as->block[p].comments)
				|| (as->block[p].symbols)
				|| (as->block[p].perm)
				|| (as->block[p].strings)) {
				pj_kn (pj, "offset", at);
				pj_kn (pj, "size", piece);
			}
			if (as->block[p].flags) {
				pj_ki (pj, "flags", as->block[p].flags);
			}
			if (as->block[p].functions) {
				pj_ki (pj, "functions", as->block[p].functions);
			}
			if (as->block[p].in_functions) {
				pj_ki (pj, "in_functions", as->block[p].in_functions);
			}
			if (as->block[p].comments) {
				pj_ki (pj, "comments", as->block[p].comments);
			}
			if (as->block[p].symbols) {
				pj_ki (pj, "symbols", as->block[p].symbols);
			}
			if (as->block[p].strings) {
				pj_ki (pj, "strings", as->block[p].strings);
			}
			if (as->block[p].perm) {
				pj_ks (pj, "perm", r_str_rwx_i (as->block[p].perm));
			}
			pj_end (pj);
			break;
		case 'h':
			if ((as->block[p].flags)
				|| (as->block[p].functions)
				|| (as->block[p].comments)
				|| (as->block[p].symbols)
				|| (as->block[p].strings)) {
				r_strf_var (atstr, 32, "0x%09"PFMT64x, at);
				r_table_add_rowf (t, "sddddd", atstr, as->block[p].flags,
						  as->block[p].functions, as->block[p].comments, as->block[p].symbols,  as->block[p].strings);
			}
			break;
		case 'e': // p-e
			cmd_p_minus_e (core, at, ate);
			break;
		default:{ // p--
			RCons *cons = core->cons;
			if (off >= at && off < ate) {
				r_cons_write (cons, "^", 1);
			} else {
				RIOMap *s = r_io_map_get_at (core->io, at);
				if (use_color) {
					if (s) {
						if (s->perm & R_PERM_X) {
							r_kons_print (cons, cons->context->pal.graph_trufae);
						} else {
							r_kons_print (cons, cons->context->pal.graph_true);
						}
					} else {
						r_kons_print (cons, cons->context->pal.graph_false);
					}
				}
				if (as->block[p].strings > 0) {
					r_cons_write (cons, "z", 1);
				} else if (as->block[p].symbols > 0) {
					r_cons_write (cons, "s", 1);
				} else if (as->block[p].functions > 0) {
					r_cons_write (cons, "F", 1);
				} else if (as->block[p].comments > 0) {
					r_cons_write (cons, "c", 1);
				} else if (as->block[p].flags > 0) {
					r_cons_write (cons, ".", 1);
				} else if (as->block[p].in_functions > 0) {
					r_cons_write (cons, "f", 1);
				} else {
					r_cons_write (cons, "_", 1);
				}
			}
		}
		break;
		}
	}
	switch (mode) {
	case 'j':
		pj_end (pj);
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		break;
	case 'h': {
		char *table_string = r_table_tostring (t);
		if (!table_string) {
			goto cleanup;
		}
		r_kons_printf (core->cons, "\n%s\n", table_string);
		free (table_string);
		break;
	}
	case 'e':
	default:
		if (use_color) {
			r_kons_print (core->cons, Color_RESET);
		}
		r_kons_printf (core->cons, "] 0x%08"PFMT64x "\n", to);
		break;
	}
	result = true;
cleanup:
	pj_free (pj);
	r_table_free (t);
	r_list_free (list);
	r_core_anal_stats_free (as);
	return result;
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
		default:
			break;
		}
	}
	return false;
}

static inline void matchBar(ut8 *ptr, int i) {
	if (ptr[i] < 0xff) {
		ptr[i]++;
	}
}

static ut8 *analBars(RCore *core, size_t type, size_t nblocks, size_t blocksize, size_t skipblocks, ut64 from) {
	size_t j, i = 0;
	ut8 *ptr = calloc (1, nblocks);
	if (!ptr) {
		R_LOG_ERROR ("failed to malloc memory");
		return NULL;
	}
	// XXX: unused memblock
	ut8 *p = malloc (blocksize);
	if (!p) {
		R_FREE (ptr);
		R_LOG_ERROR ("failed to malloc");
		return NULL;
	}
	if (type == 'A') {
		ut64 to = from + (blocksize * nblocks);
		RCoreAnalStats *as = r_core_anal_get_stats (core, from, to, blocksize);
		for (i = 0; i < nblocks; i++) {
			int value = 0;
			value += as->block[i].functions;
			value += as->block[i].in_functions;
			value += as->block[i].comments;
			value += as->block[i].symbols;
			value += as->block[i].flags;
			value += as->block[i].strings;
			value += as->block[i].blocks;
			ptr[i] = R_MIN (255, value);
		}
		r_core_anal_stats_free (as);
		free (p);
		return ptr;
	}
	for (i = 0; i < nblocks; i++) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		ut64 off = from + (i + skipblocks) * blocksize;
		for (j = 0; j < blocksize ; j++) {
			if (type == 'a') {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off + j, 0);
				if (fcn) {
					ptr[i] = r_list_length (fcn->bbs);
				}
				continue;
			}
			RAnalOp *op = r_core_anal_op (core, off + j, R_ARCH_OP_MASK_BASIC);
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
	if (r_str_endswith (input, "?")) {
		r_core_cmd_help (core, help_msg_p_equal);
		return;
	}
	bool print_bars = false;
	ut8 *ptr = NULL;
	// p=e [nblocks] [totalsize] [skip]
	int nblocks = -1;
	ut64 totalsize = UT64_MAX;
	int skipblocks = -1;
	RIOMap* map;
	RListIter *iter;
	ut64 from = 0, to = 0;
	RList *list = r_core_get_boundaries_prot (core, -1, NULL, "zoom");
	if (!list) {
		goto beach;
	}

	ut64 blocksize = 0;
	int mode = 'b'; // e, p, b, ...
	int submode = 0; // q, j, ...

	if (input[0]) {
		char *spc = strchr (input, ' ');
		if (spc) {
			nblocks = r_num_math (core->num, spc + 1);
			if (nblocks < 1) {
				goto beach;
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
		if (r_config_get_b (core->config, "cfg.debug")) {
			RDebugMap *map = r_debug_map_get (core->dbg, core->addr);
			if (map) {
				totalsize = map->addr_end - map->addr;
				from = map->addr;
			}
		} else {
			if (core->io && core->io->desc) {
				totalsize = r_io_fd_size (core->io, core->io->desc->fd);
				if ((st64) totalsize < 1) {
					totalsize = UT64_MAX;
				}
			}
			if (totalsize == UT64_MAX) {
				R_LOG_ERROR ("Cannot determine file size");
				goto beach;
			}
		}
	}
	blocksize = (blocksize > 0)? (totalsize / blocksize): (core->blocksize);
	if (blocksize < 1) {
		R_LOG_ERROR ("Invalid block size: %d", (int)blocksize);
		goto beach;
	}
	if (!r_config_get_b (core->config, "cfg.debug")) {
		RIOMap* map1 = r_list_first (list);
		if (map1) {
			from = map1->itv.addr;
			r_list_foreach (list, iter, map) {
				to = r_io_map_end (map);
			}
			totalsize = to - from;
		} else {
			from = core->addr;
		}
	}
	if (nblocks < 1) {
		nblocks = totalsize / blocksize;
	} else {
		blocksize = totalsize / nblocks;
		 if (blocksize < 1) {
			R_LOG_ERROR ("Invalid block size: %d", (int)blocksize);
			goto beach;
		}
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
		case 'A': // anal stats
		case 'a': // anal bb
		case 'p': // printable chars
		case 'z': // zero terminated strings
		case 'b': // zero terminated strings
			{
				ut64 i, j, k;
				ptr = calloc (1, nblocks);
				if (!ptr) {
					goto beach;
				}
				ut8 *p = calloc (1, blocksize);
				if (!p) {
					R_FREE (ptr);
					goto beach;
				}
				int len = 0;
				if (submode == 'A') {
					ut64 to = from + totalsize; //  (blocksize * nblocks);
					RCoreAnalStats *as = r_core_anal_get_stats (core, from, to, blocksize);
					for (i = 0; i < nblocks; i++) {
						int value = 0;
						value += as->block[i].functions;
						value += as->block[i].in_functions;
						value += as->block[i].comments;
						value += as->block[i].symbols;
						value += as->block[i].flags;
						value += as->block[i].strings;
						value += as->block[i].blocks;
						ptr[i] = 256 * value / blocksize;
						ptr[i] *= 3;
					}
					r_core_anal_stats_free (as);
				} else for (i = 0; i < nblocks; i++) {
					ut64 off = from + blocksize * (i + skipblocks);
					r_io_read_at (core->io, off, p, blocksize);
					for (j = k = 0; j < blocksize; j++) {
						switch (submode) {
						case 'a':
							{
								RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off + j, 0);
								if (fcn) {
									k += r_list_length (fcn->bbs);
									k = R_MAX (255, k);
								}
							}
							break;
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
								if ((j + 1) < blocksize && p[j + 1] == 0) {
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
				goto beach;
			}
			p = malloc (blocksize);
			if (!p) {
				R_FREE (ptr);
				goto beach;
			}
			for (i = 0; i < nblocks; i++) {
				ut64 off = from + (blocksize * (i + skipblocks));
				r_io_read_at (core->io, off, p, blocksize);
				ptr[i] = (ut8) (255 * r_hash_entropy_fraction (p, blocksize));
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
	case '2': // "p=2"
		{
			short *word = (short*) core->block;
			int i, words = core->blocksize / 2;
			int step = r_num_math (core->num, input + 2);
			ut64 oldword = 0;
			for (i = 0; i < words; i++) {
				ut64 word64 = word[i] + ST16_MAX;
				r_cons_printf ("0x%08"PFMT64x" %8d  ", core->addr + (i * 2), word[i]);
				r_print_progressbar (core->print, word64 * 100 / UT16_MAX, 60, NULL);
				r_cons_printf (" %" PFMT64d, word64 - oldword);
				oldword = word64;
				r_cons_newline (core->cons);
				i += step;
			}
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
	case 'A': // "p=A" anal info
	case 'a': // "p=a" bb info
	case 'c': // "p=c" calls
	case 'i': // "p=i" invalid
	case 's': // "p=s" syscalls
		if ((ptr = analBars (core, mode, nblocks, blocksize, skipblocks, from))) {
			print_bars = true;
		}
		break;
	case 'm':
	{
		ut8 *p;
		int j, i = 0;
		ptr = calloc (1, nblocks);
		if (!ptr) {
			goto beach;
		}
		p = malloc (blocksize);
		if (!p) {
			R_FREE (ptr);
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
			goto beach;
		}
		p = malloc (blocksize);
		if (!p) {
			R_FREE (ptr);
			goto beach;
		}
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + (blocksize * (i + skipblocks));
			r_io_read_at (core->io, off, p, blocksize);
			ptr[i] = (ut8) (255 * r_hash_entropy_fraction (p, blocksize));
		}
		free (p);
		print_bars = true;
	}
	break;
	case '0': // 0x00 bytes
	case 'F': // 0xff bytes
	case 'p': // printable chars
	case 'z': // zero terminated strings
	{
		ut8 *p;
		ut64 i, j, k;
		ptr = calloc (1, nblocks);
		if (!ptr) {
			goto beach;
		}
		p = calloc (1, blocksize);
		if (!p) {
			R_FREE (ptr);
			goto beach;
		}
		int len = 0;
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + blocksize * (i + skipblocks);
			r_io_read_at (core->io, off, p, blocksize);
			for (j = k = 0; j < blocksize; j++) {
				switch (mode) {
				case '0':
					if (!p[j]) {
						k++;
					}
					break;
				case 'F':
					if (p[j] == 0xff) {
						k++;
					}
					break;
				case 'z':
					if ((IS_PRINTABLE (p[j]))) {
						if ((j + 1) < blocksize && p[j + 1] == 0) {
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
	}
	break;
	case 'b': // bytes
	case '\0':
		ptr = calloc (1, nblocks);
		r_io_read_at (core->io, from, ptr, nblocks);
		// TODO: support print_bars
		r_print_fill (core->print, ptr, nblocks, from, blocksize);
		R_FREE (ptr);
		break;
	}
	if (print_bars) {
		bool hex_offset = r_config_get_i (core->config, "hex.addr");
		if (hex_offset) {
			core->print->flags |= R_PRINT_FLAGS_OFFSET;
		} else {
			core->print->flags &= ~R_PRINT_FLAGS_OFFSET;
		}
		int i;
		switch (submode) {
		case 'j': {
			PJ *pj = r_core_pj_new (core);
			if (!pj) {
				return;
			}

			pj_o (pj);
			pj_kn (pj, "blocksize", blocksize);
			pj_kn (pj, "address", from);
			pj_kn (pj, "size", totalsize);
			pj_k (pj, "entropy");
			pj_a (pj);

			for (i = 0; i < nblocks; i++) {
				ut8 ep = ptr[i];
				ut64 off = blocksize * i;
				off += from;
				pj_o (pj);
				pj_kn (pj, "addr", off);
				pj_ki (pj, "value", ep);
				pj_end (pj);

			}
			pj_end (pj);
			pj_end (pj);
			r_cons_println (core->cons, pj_string (pj));
			pj_free (pj);
		}	break;
		case 'q':
			for (i = 0; i < nblocks; i++) {
				ut64 off = from + (blocksize * i);
				if (core->print->cur_enabled) {
					if (i == core->print->cur) {
						r_cons_printf ("> ");
						r_core_return_value (core, off);
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
	r_list_free (list);
	free (ptr);
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
			r_core_cmdf (core, "CC-@ 0x%08"PFMT64x, origin);
			r_core_cmdf (core, "CC switch table @ 0x%08"PFMT64x, origin);
			r_core_cmdf (core, "f switch.0x%08"PFMT64x"=0x%08"PFMT64x, origin, origin);
			r_core_cmdf (core, "f jmptbl.0x%08"PFMT64x"=0x%08"PFMT64x, offset, offset); //origin, origin);
			r_core_cmdf (core, "axd 0x%"PFMT64x " 0x%08"PFMT64x, origin, offset);
			break;
		}
	} else if (mode == '.') {
		r_core_cmdf (core, "CC-@ 0x%08"PFMT64x, origin);
		r_core_cmdf (core, "CC switch basic block @ 0x%08"PFMT64x, offset);
		r_core_cmdf (core, "f switch.0x%08"PFMT64x"=0x%08"PFMT64x, offset, offset);
	}
	int n = 0;
	for (i = 0; (i + sizeof (st32)) <= len; i += step, n++) {
		delta = (st32 *) (buf + i);
		addr = offset + *delta;
		if (!r_io_is_valid_offset (core->io, addr, 0)) {
			// Lets check for jmptbl with not relative addresses
			// Like: jmp dword [eax*4 + jmptbl.0x5435345]
			if (!r_io_is_valid_offset (core->io, *delta, 0)) {
				break;
			}
			addr = *delta;
		}
		if (mode == '*') {
			r_cons_printf ("af case.%d.0x%"PFMT64x " 0x%08"PFMT64x "\n", n, offset, addr);
			r_cons_printf ("ax 0x%"PFMT64x " 0x%08"PFMT64x "\n", offset, addr);
			r_cons_printf ("ax 0x%"PFMT64x " 0x%08"PFMT64x "\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			r_cons_printf ("aho case 0x%"PFMT64x " 0x%08"PFMT64x " @ 0x%08"PFMT64x "\n", (ut64)i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			r_cons_printf ("ahs %d @ 0x%08"PFMT64x "\n", step, offset + i);
		} else if (mode == '.') {
			r_core_cmdf (core, "af case.%d.0x%"PFMT64x " @ 0x%08"PFMT64x, n, offset, addr);
			r_core_cmdf (core, "ax 0x%"PFMT64x " 0x%08"PFMT64x, offset, addr);
			r_core_cmdf (core, "ax 0x%"PFMT64x " 0x%08"PFMT64x, addr, offset); // wrong, but useful because forward xrefs dont work :?
			// r_core_cmdf (core, "CC+ case %d: 0x%08"PFMT64x " @ 0x%08"PFMT64x, i / step, addr, origin);
			r_core_cmdf (core, "CCu case %d: @ 0x%08"PFMT64x, n, addr); //, origin);
			r_core_cmdf (core, "aho case %d 0x%08"PFMT64x " @ 0x%08"PFMT64x, n, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			r_core_cmdf (core, "ahs %d @ 0x%08"PFMT64x, step, offset + i);
		} else {
			r_cons_printf ("0x%08"PFMT64x " -> 0x%08"PFMT64x "\n", offset + i, addr);
		}
	}
}

static void __printPattern(RCore *core, const char *_input) {
	char *input = strdup (_input);
	const char *arg = r_str_nextword (input, ' ');
	size_t i, j;
	st64 len = arg? r_num_math (core->num, arg): core->blocksize;
	if (len < 1) {
		R_LOG_ERROR ("Invalid length");
		return;
	}
	switch (input[0]) {
	case 'd': // "ppd"
		// debruijn pattern
		{
			ut8 *buf = (ut8*)r_debruijn_pattern (len, 0, NULL);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%02x", buf[i]);
			}
			r_cons_newline (core->cons);
			free (buf);
		}
		break;
	case '1': // "pp1"
		// incremental byte sequence
		{
			int min = (core->addr & 0xff);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%02x", (int)(i + min));
			}
			r_cons_newline (core->cons);
		}
		break;
	case '2': // "pp2"
		// incremental half word sequences
		{
			// TODO: honor cfg.bigendian
			int min = (core->addr & 0xffff);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%04x", (int)(i + min));
			}
			r_cons_newline (core->cons);
		}
		break;
	case '4': // "pp4"
		// incremental half word sequences
		{
			// TODO: honor cfg.bigendian
			int min = (core->addr & UT32_MAX);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%08x", (int)(i + min));
			}
			r_cons_newline (core->cons);
		}
		break;
	case '8': // "pp8"
		// incremental half word sequences
		{
			// TODO: honor cfg.bigendian
			ut64 min = (core->addr);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%016"PFMT64x, i + min);
			}
			r_cons_newline (core->cons);
		}
		break;
	case 'f': // "ppf"
		// zero ssled
		{
			ut8 *buf = (ut8*)r_debruijn_pattern (len, 0, NULL);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%02x", 0xff);
			}
			r_cons_newline (core->cons);
			free (buf);
		}
		break;
	case '0': // "pp0"
		// zero ssled
		{
			ut8 *buf = (ut8*)r_debruijn_pattern (len, 0, NULL);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%02x", 0);
			}
			r_cons_newline (core->cons);
			free (buf);
		}
		break;
	case 'a':
		// TODO
		{
			i = core->addr;
			size_t bs = 4; // XXX hardcoded
			ut8 *buf = calloc (bs, 1);
			// for (;i>0;i--) { incDigitBuffer (buf, bs); }
			for (i = 0; i < len; i++) {
				incAlphaBuffer (buf, bs);
				for (j = 0; j < bs; j++) {
					r_cons_printf ("%c", buf[j]?buf[j]:'A');
				}
				r_cons_printf (" ");
			}
			r_cons_newline (core->cons);
			free (buf);
		}
		break;
	case 'n': // "ppn"
		{
			i = core->addr;
			size_t bs = 4; // XXX hardcoded
			ut8 *buf = calloc (bs, 1);
			// for (;i>0;i--) { incDigitBuffer (buf, bs); }
			for (i = 0; i < len; i++) {
				incDigitBuffer (buf, bs);
				for (j = 0; j < bs; j++) {
					r_cons_printf ("%c", buf[j]?buf[j]:'0');
				}
				r_cons_printf (" ");
			}
			r_cons_newline (core->cons);
			free (buf);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_pp);
		break;
	}
	free (input);
}

static void pr_bb(RCore *core, RAnalFunction *fcn, RAnalBlock *b, bool emu, ut64 saved_gp, ut8 *saved_arena, int saved_arena_size, char p_type, bool fromHere) {
	bool show_flags = r_config_get_b (core->config, "asm.flags");
	const char *orig_bb_middle = r_config_get (core->config, "asm.bbmiddle");
	core->anal->gp = saved_gp;
	if (fromHere) {
		if (b->addr < core->addr) {
			core->cons->null = true;
		} else {
			core->cons->null = false;
		}
	}
	if (emu) {
		if (b->parent_reg_arena) {
			ut64 gp;
			r_reg_arena_poke (core->anal->reg, b->parent_reg_arena, b->parent_reg_arena_size);
			R_FREE (b->parent_reg_arena);
			gp = r_reg_getv (core->anal->reg, "gp");
			if (gp) {
				core->anal->gp = gp;
			}
		} else {
			r_reg_arena_poke (core->anal->reg, saved_arena, saved_arena_size);
		}
	}
	if (b->parent_stackptr != INT_MAX) {
		core->anal->stackptr = b->parent_stackptr;
	}
	r_config_set_i (core->config, "asm.bbmiddle", false);
	// r_cons_printf ("| loc_0x%08"PFMT64x":", b->addr);
	ut8 *buf = malloc (b->size);
	if (!buf) {
		r_cons_printf ("Failed to allocate %"PFMT64u" bytes", b->size);
		return;
	}

	if (r_io_nread_at (core->io, b->addr, buf, b->size) < 0) {
		r_cons_printf ("Failed to read %" PFMT64u " bytes at 0x%" PFMT64x "\n",
				b->size, b->addr);
		return;
	}

	if (p_type == 'D') {
		r_core_cmdf (core, "pD %" PFMT64u " @0x%" PFMT64x, b->size, b->addr);
	} else {
		r_core_cmdf (core, "pI %" PFMT64u " @0x%" PFMT64x, b->size, b->addr);
	}
	free (buf);

	r_config_set (core->config, "asm.bbmiddle", orig_bb_middle);

	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RAnalBlock *jumpbb = r_anal_get_block_at (b->anal, b->jump);
			if (jumpbb && r_list_contains (jumpbb->fcns, fcn)) {
				if (emu && core->anal->last_disasm_reg && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
				}
				if (jumpbb->parent_stackptr == INT_MAX) {
					jumpbb->parent_stackptr = core->anal->stackptr + b->stackptr;
				}
			}
		}
		if (p_type == 'D' && show_flags) {
			r_cons_printf ("| // true: 0x%08"PFMT64x, b->jump);
		}
	}
	if (b->fail != UT64_MAX) {
		if (b->fail > b->addr) {
			RAnalBlock *failbb = r_anal_get_block_at (b->anal, b->fail);
			if (failbb && r_list_contains (failbb->fcns, fcn)) {
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
		r_cons_newline (core->cons);
	}
}

static void disasm_until_optype(RCore *core, ut64 addr, char type_print, int optype, int limit) {
	int p = 0;
	const bool show_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	int i;
	for (i = 0; i < limit; i++) {
		RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
		if (op) {
			char *mnem = op->mnemonic;
			char *m = malloc ((strlen (mnem) * 2) + 32);
			strcpy (m, mnem);
			if (type_print == 'q') {
				r_cons_printf ("%s\n", m);
			} else {
				if (show_color) {
					const char *offsetColor = core->cons->context->pal.addr; // TODO etooslow. must cache
					r_cons_printf ("%s0x%08"PFMT64x Color_RESET"  %10s %s\n",
							offsetColor, addr + p, "", m);
				} else {
					r_cons_printf ("0x%08"PFMT64x"  %10s %s\n", addr + p, "", m);
				}
			}
			if ((op->type & 0xfffff) == optype) {
				goto beach;
			}
			if (op->type == R_ANAL_OP_TYPE_JMP) {
				addr = op->jump;
			} else {
				addr += op->size;
			}
		} else {
			R_LOG_ERROR ("[pdp] Cannot get op at 0x%08"PFMT64x, addr + p);
			r_anal_op_free (op);
			break;
		}
		//r_io_read_at (core->io, n, rbuf, 512);
		r_anal_op_free (op);
	}
beach:
	return;
}

static void disasm_ropchain(RCore *core, ut64 addr, char type_print) {
	int p = 0;
	ut64 n = 0;
	ut8 *buf = calloc (core->blocksize, 1);
	(void)r_io_read_at (core->io, addr, buf, core->blocksize);
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->print->config);
	while (p + 4 < core->blocksize) {
		if (core->rasm->config->bits == 64) {
			n = r_read_ble64 (buf + p, be);
		} else {
			n = r_read_ble32 (buf + p, be);
		}
		r_cons_printf ("[0x%08"PFMT64x"] 0x%08"PFMT64x"\n", addr + p, n);
		disasm_until_optype (core, n, type_print, R_ANAL_OP_TYPE_RET, 1024);
		if (core->rasm->config->bits == 64) {
			p += 8;
		} else {
			p += 4;
		}
	}
	free (buf);
}

static void disasm_recursive(RCore *core, ut64 addr, int count, char type_print) {
	RAnalOp aop = {0};
	int ret;
	ut8 buf[128];
	PJ *pj = NULL;
	if (type_print == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	while (count-- > 0) {
		r_io_read_at (core->io, addr, buf, sizeof (buf));
		r_anal_op_fini (&aop);
		ret = r_anal_op (core->anal, &aop, addr, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC);
		if (ret < 0 || aop.size < 1) {
			addr++;
			continue;
		}
	//	r_core_cmdf (core, "pD %d @ 0x%08"PFMT64x, aop.size, addr);
		if (type_print == 'j') {
			r_core_print_disasm_json_ipi (core, addr, buf, sizeof (buf), 1, pj, NULL);
		} else {
			r_core_cmdf (core, "pd 1 @ 0x%08"PFMT64x, addr);
		}
		switch (aop.type) {
		case R_ANAL_OP_TYPE_JMP:
			addr = aop.jump;
			continue;
		case R_ANAL_OP_TYPE_UCJMP:
			break;
		case R_ANAL_OP_TYPE_RET:
			count = 0;	// stop disassembling when hitting RET
			break;
		default:
			break;
		}
		addr += aop.size;
	}
	if (type_print == 'j') {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static void func_walk_blocks(RCore *core, RAnalFunction *f, char input, char type_print, bool fromHere) {
	RListIter *iter;
	RAnalBlock *b = NULL;
	const char *orig_bb_middle = r_config_get (core->config, "asm.bbmiddle");
	r_config_set_i (core->config, "asm.bbmiddle", false);
	PJ *pj = NULL;
	ut64 oseek = core->addr;

	// XXX: hack must be reviewed/fixed in code analysis
	if (!b) {
		if (r_list_length (f->bbs) >= 1) {
			ut32 fcn_size = r_anal_function_realsize (f);
			b = r_list_last (f->bbs);
			if (b->size > fcn_size) {
				b->size = fcn_size;
			}
		}
	}
	r_list_sort (f->bbs, (RListComparator) bbcmp);
	if (input == 'j' && b) { // "pdrj"
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ks (pj, "name", f->name);
		pj_ka (pj, "bbs");
		r_list_foreach (f->bbs, iter, b) {
			pj_o (pj);
			pj_kn (pj, "addr", b->addr);
			pj_ka (pj, "ops");
			if (fromHere) {
				core->cons->null = (b->addr < core->addr);
			}
			ut8 *buf = malloc (b->size);
			if (buf) {
				r_io_read_at (core->io, b->addr, buf, b->size);
				r_core_print_disasm_json_ipi (core, b->addr, buf, b->size, 0, pj, NULL);
				free (buf);
			} else {
				R_LOG_ERROR ("Cannot allocate %"PFMT64u" byte(s)", b->size);
			}
			pj_end (pj);
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		bool asm_lines = r_config_get_b (core->config, "asm.lines.jmp");
		bool emu = r_config_get_b (core->config, "asm.emu");
		ut64 saved_gp = 0;
		int saved_arena_size = 0;
		ut8 *saved_arena = NULL;
		int saved_stackptr = core->anal->stackptr;
		if (emu) {
			saved_gp = core->anal->gp;
			saved_arena = r_reg_arena_peek (core->anal->reg, &saved_arena_size);
		}
		r_config_set_i (core->config, "asm.lines.jmp", 0);
		r_list_foreach (f->bbs, iter, b) {
			pr_bb (core, f, b, emu, saved_gp, saved_arena, saved_arena_size, type_print, fromHere);
		}
		if (emu) {
			core->anal->gp = saved_gp;
			if (saved_arena) {
				r_reg_arena_poke (core->anal->reg, saved_arena, saved_arena_size);
				R_FREE (saved_arena);
			}
		}
		core->anal->stackptr = saved_stackptr;
		r_config_set_i (core->config, "asm.lines.jmp", asm_lines);
	}
	r_config_set (core->config, "asm.bbmiddle", orig_bb_middle);
	r_core_seek (core, oseek, SEEK_SET);
}

static inline char cmd_pxb_p(char input) {
	return IS_PRINTABLE (input)? input: '.';
}

static inline ut64 cmd_pxb_k(const ut8 *buffer, int x) {
	return (ut64)(buffer[3 - x]) << (8 * x);
}

static void print_json_string(RCore *core, const char* block, int len, const char* type) {
	const char* section_name = r_core_get_section_name (core, core->addr);
	if (section_name && strlen (section_name) < 1) {
		section_name = "unknown";
	} else if (section_name) {
		// cleaning useless spaces in section name in json data.
		section_name = r_str_trim_head_ro (section_name);
		char* p;
		for (p = (char*) section_name; *p && *p != ' '; p++) {}
		*p = '\0';
	}
	if (!section_name) {
		section_name = "unknown";
	}
	if (!type) {
		switch (get_string_type (core->block, len)) {
		case 'w': type = "wide"; break;
		case 'a': type = "ascii"; break;
		case 'u': type = "utf"; break;
		default: type = "unknown"; break;
		}
	}
	bool is_wide = !strcmp (type, "wide");
	size_t slen = r_str_nlen (block, len);
	char *tblock = (char *)block;
	if (is_wide) {
		int i;
		// dewide
		tblock = r_mem_dup (block, len);
		for (i = 0; i < len; i++) {
			if (tblock[i] && !tblock[i + 1]) {
				memmove (tblock + i + 1, tblock + i + 2, len - i - 2);
			} else {
				tblock[i] = 0;
				break;
			}
		}
		slen = strlen (tblock);
	}
	PJ *pj = r_core_pj_new (core);
	if (pj) {
		pj_o (pj);
		pj_k (pj, "string");
		// TODO: add pj_kd for data to pass key(string) and value(data,len) instead of pj_ks which null terminates
		char *str = r_str_utf16_encode (tblock, slen); // XXX just block + len should be fine, pj takes care of this
		pj_raw (pj, "\"");
		pj_raw (pj, str);
		free (str);
		pj_raw (pj, "\"");
		pj_kn (pj, "offset", core->addr);
		pj_ks (pj, "section", section_name);
		pj_ki (pj, "length", slen);
		pj_ks (pj, "type", type);
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
	if (tblock != block) {
		free (tblock);
	}
}

static char *__op_refs(RCore *core, RAnalOp *op, int n) {
	RStrBuf *sb = r_strbuf_new ("");
	if (n) {
		// RList *list = r_anal_xrefs_get_from (core->anal, op->addr);
		RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, op->addr);
		if (xrefs) {
			RAnalRef *ref;
			R_VEC_FOREACH (xrefs, ref) {
				r_strbuf_appendf (sb, "0x%08"PFMT64x" ", ref->at);
			}
			RVecAnalRef_free (xrefs);
		}
	} else {
		if (op->jump != UT64_MAX) {
			r_strbuf_appendf (sb, "0x%08"PFMT64x" ", op->jump);
		}
		if (op->fail != UT64_MAX) {
			r_strbuf_appendf (sb, "0x%08"PFMT64x" ", op->fail);
		}
		if (op->ptr != UT64_MAX) {
			if (r_io_is_valid_offset (core->io, op->ptr, false)) {
				r_strbuf_appendf (sb, "0x%08"PFMT64x" ", op->ptr);
			}
		}
	}
	char *res = r_strbuf_drain (sb);
	r_str_trim (res);
	return res;
}

static void r_core_disasm_table(RCore *core, int l, const char *input) {
	int i;
	RTable *t = r_core_table_new (core, "disasm");
	char *arg = strchr (input, ' ');
	if (arg) {
		input = arg + 1;
	}
	r_table_set_columnsf (t, "snssssss", "name", "addr", "bytes", "disasm", "comment", "esil", "refs", "xrefs");
	const int minopsz = 1;
	const int options = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_DISASM | R_ARCH_OP_MASK_ESIL;
	ut64 ea = core->addr;
	for (i = 0; i < l; i++) {
		RAnalOp *op = r_core_anal_op (core, ea, options);
		if (!op || op->size < 1) {
			i += minopsz;
			ea += minopsz;
			continue;
		}
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ea);
		// TODO parse/filter op->mnemonic for better disasm
		ut8 *bytes = malloc (op->size);
		if (!bytes) {
			break;
		}
		r_io_read_at (core->io, ea, bytes, op->size); // XXX ranalop should contain the bytes like rasmop do
		char *sbytes = r_hex_bin2strdup (bytes, op->size);
		RFlagItem *fi = r_flag_get_in (core->flags, ea);
		char *fn = fi? fi->name: "";
		const char *esil = R_STRBUF_SAFEGET (&op->esil);
		char *refs = __op_refs (core, op, 0);
		char *xrefs = __op_refs (core, op, 1);
		r_table_add_rowf (t, "sXssssss", fn, ea, sbytes, op->mnemonic, r_str_get (comment), esil, refs, xrefs);
		free (sbytes);
		free (bytes);
		free (xrefs);
		free (refs);
		ea += op->size;
		r_anal_op_free (op);
	}
	bool show_table = true;
	if (R_STR_ISNOTEMPTY (input)) {
		show_table = r_table_query (t, input);
	}
	if (show_table) {
		char *ts = r_table_tostring (t);
		r_cons_printf ("%s", ts); // \n?
		free (ts);
	}
	r_table_free (t);
}

// the caller controls the size of the buffer is enough for the base wordsize
static ut64 read_value(const ut8 *buf, int base, int be) {
	if (base == 8) {
		return r_read_ble64 (buf, be);
	}
	if (base == 4) {
		return r_read_ble32 (buf, be) & UT32_MAX;
	}
	if (base == 2) {
		return r_read_ble16 (buf, be) & UT16_MAX;
	}
	return *buf;
}

static void cmd_pxr(RCore *core, int len, int mode, int wordsize, const char *arg) {
	PJ *pj = NULL;
	RTable *t = NULL;
	if (mode == ',') {
		t = r_table_new ("pxr");
		RTableColumnType *n = r_table_type ("number");
		RTableColumnType *s = r_table_type ("string");
		r_table_add_column (t, n, "addr", 0);
		r_table_add_column (t, n, "value", 0);
		r_table_add_column (t, s, "refs", 0);
	}
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
	}
	RCons *cons = core->cons;
	ut64 o_offset = core->addr;
	if (mode == 'j' || mode == ',' || mode == '*' || mode == 'q') {
		size_t i;
		const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config);
		if (pj) {
			pj_a (pj);
		}
		const ut8 *buf = core->block;

		bool withref = false;
		int end = R_MIN (core->blocksize, len);
		ut64 at = o_offset;
		for (i = 0; i + wordsize < end; i += wordsize) {
			ut64 addr = o_offset + i;
			ut64 val = read_value (buf + i, wordsize, be);
			if (pj) {
				pj_o (pj);
				pj_kn (pj, "addr", addr);
				pj_kn (pj, "value", val);
			}

			// XXX: this only works in little endian
			withref = false;
			char *refs = NULL;
			core->addr = at + i;
			if (core->print->hasrefs) {
				char *rstr = core->print->hasrefs (core->print->user, val, true);
				if (R_STR_ISNOTEMPTY (rstr)) {
					r_str_trim (rstr);
					if (pj) {
						char *ns = r_str_escape (rstr);
						pj_ks (pj, "refstr", r_str_trim_head_ro (ns));
						pj_k (pj, "ref");
						const int hex_depth = r_config_get_i (core->config, "hex.depth");
						free (r_core_anal_hasrefs_to_depth (core, val, pj, hex_depth));
						pj_end (pj);
						free (ns);
					}
					withref = true;
				}
				refs = rstr;
			}
			if (mode == '*' && R_STR_ISNOTEMPTY (refs)) {
				// Show only the mapped ones?
				r_cons_printf ("'f pxr.%"PFMT64x"=0x%"PFMT64x"\n", val, addr);
			} else if (mode == 'q' && R_STR_ISNOTEMPTY (refs)) {
				r_cons_printf ("%s\n", refs);
			}
			if (t) {
				r_table_add_rowf (t, "xxs", addr, val, refs);
			}
			R_FREE (refs);
			if (!withref && pj) {
				pj_end (pj);
			}
		}
		core->addr = at;
		if (t) {
			if (r_table_query (t, arg? arg + 1: NULL)) {
				char *s = r_table_tostring (t);
				r_cons_println (cons, s);
				free (s);
			}
			r_table_free (t);
		}
		if (pj) {
			pj_end (pj);
			r_cons_println (cons, pj_string (pj));
			pj_free (pj);
		}
	} else {
		const int ocols = core->print->cols;
		int bitsize = core->rasm->config->bits;
		/* Thumb is 16bit arm but handles 32bit data */
		if (bitsize == 16) {
			bitsize = 32;
		}
		core->print->cols = 1;
		core->print->flags |= R_PRINT_FLAGS_REFS;
		r_cons_break_push (cons, NULL, NULL);
		r_print_hexdump (core->print, core->addr,
				core->block, R_MIN (len, core->blocksize),
				wordsize * 8, bitsize / 8, 1);
		r_cons_break_pop (cons);
		core->print->flags &= ~R_PRINT_FLAGS_REFS;
		core->print->cols = ocols;
	}
	core->addr = o_offset;
}

static ut8 *decode_text(RCore *core, ut64 offset, size_t len, bool zeroend) {
	const char *current_charset = r_config_get (core->config, "cfg.charset");
	ut8 *out = calloc (len, 10);
	if (out) {
		r_io_read_at (core->io, core->addr, out, len);
		if (zeroend) {
			len = (size_t)r_str_nlen ((const char*)out, len);
		}
		if (!R_STR_ISEMPTY (current_charset)) {
			size_t out_len = len * 10;
			ut8 *data = out;
			out = calloc (len, 10);
			if (out) {
				r_io_read_at (core->io, core->addr, data, len);
				r_charset_encode_str (core->print->charset, out, out_len, data, len, false);
				free (data);
			}
		}
	}
	return out;
}

static bool cmd_pi(RCore *core, const char *input, int len, int l, ut8 *block) {
	// len is block_len
	char ch = input[1];
	if (ch == '+' || ch == '-' || isdigit (ch)) {
		ch = ' ';
		l = r_num_math (core->num, input + 1);
	}
	switch (ch) {
	case '?':
		r_core_cmd_help (core, help_msg_pi);
		break;
	case 'u': // "piu" disasm until given optype
		{
			int optype = -1;
			char print_type = 0;
			const char *_input = input;
			if (_input[2] && _input[2] != ' ') {
				print_type = _input[2];
				_input++;
			}
			if (_input[2] && _input[3]) {
				// TODO: add limit as arg
				char *instruction = r_str_word_get_first (_input + 3);
				optype = r_anal_optype_from_string (instruction);
				free (instruction);
				if (optype == -1) {
					optype = R_ANAL_OP_TYPE_RET;
				}
			} else {
				optype = R_ANAL_OP_TYPE_RET;
			}
			disasm_until_optype (core, core->addr, print_type, optype, 1024);
		} break;
	case 'x': // "pix"
		__cmd_pad (core, r_str_trim_head_ro (input + 2));
		break;
	case 'a': // "pia" is like "pda", but with "pi" output
		if (l != 0) {
			r_core_print_disasm_all (core, core->addr, l, len, 'i');
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
	case 'E': // "piE"
		switch (input[2]) {
		case 0:
		case ' ':
			if (l != 0) {
				r_core_disasm_pdi (core, 0, l, 'e');
			}
			break;
		case 'q':
			{
				const bool orig = r_config_get_b (core->config, "asm.addr");
				r_config_set_b (core->config, "asm.addr", false);
				if (l != 0) {
					r_core_disasm_pdi (core, 0, l, 'e');
				}
				r_config_set_b (core->config, "asm.addr", orig);
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_piE);
			break;
		}
		break;
	case 'e': // "pie"
		if (strchr (input + 2, '?')) { // "pie?"
			r_core_cmd_help (core, help_msg_pie);
		} else if (input[2] == 'b') { // "pieb"
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
			if (fcn) {
				r_core_cmd0 (core, "pie $Fi");
			} else {
				R_LOG_ERROR ("no function to pieb in 0x%08"PFMT64x, core->addr);
			}
		} else if (input[2] == 'f') { // "pief"
			const bool asm_addr = r_config_get_b (core->config, "asm.addr");
			if (input[3] == 'q') { // "piefq"
				r_config_set_b (core->config, "asm.addr", false);
			}
			ut64 orig = core->addr;
			RAnalBlock *bb;
			RListIter *iter;
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, orig, 0);
			if (fcn) {
				r_list_foreach (fcn->bbs, iter, bb) {
					r_core_seek (core, orig, true);
					r_core_disasm_pdi (core, bb->ninstr, 0, 'e');
				}
				r_core_seek (core, orig, true);
			}
			r_config_set_b (core->config, "asm.addr", asm_addr);
		} else if (input[2] == 'q') { // "pieq"
			const bool orig = r_config_get_b (core->config, "asm.addr");
			r_config_set_b (core->config, "asm.addr", false);
			if (l != 0) {
				r_core_disasm_pdi (core, l, 0, 'e');
			}
			r_config_set_b (core->config, "asm.addr", orig);
		} else {
			if (l != 0) {
				r_core_disasm_pdi (core, l, 0, 'e');
			}
		}
		break;
	case 'f': // "pif"
		if (input[2] == '?') { // "pif?"
			r_core_cmd_help (core, help_msg_pif);
		} else if (input[2] == 'j') {
			r_core_cmdf (core, "pdfj%s", input + 3);
		} else if (input[2] == 'c') { // "pifc"
			PJ *pj = NULL;

			// check for bounds
			if (input[3] != 0) {
				if (input[3] == 'j') { // "pifcj"
					pj = r_core_pj_new (core);
					pj_a (pj);
				}
			}
			// get function in current offset
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr,
					R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);

			// validate that a function was found in the given address
			if (!f) {
				// print empty json object
				if (pj) {
					pj_end (pj);
					r_cons_println (core->cons, pj_string (pj));
					pj_free (pj);
				}
				break;
			}

			// get all the calls of the function
			RVecAnalRef *refs = r_core_anal_fcn_get_calls (core, f);

			// sanity check
			if (refs && !RVecAnalRef_empty (refs)) {
				// store current configurations
				RConfigHold *hc = r_config_hold_new (core->config);
				r_config_hold (hc, "asm.addr", "asm.comments", "asm.tabs", "asm.bytes", "emu.str", NULL);

				// temporarily replace configurations
				r_config_set_b (core->config, "asm.addr", false);
				r_config_set_b (core->config, "asm.comments", false);
				r_config_set_i (core->config, "asm.tabs", 0);
				r_config_set_b (core->config, "asm.bytes", false);
				r_config_set_b (core->config, "emu.str", false);

				// iterate over all call references
				RAnalRef *refi;
				R_VEC_FOREACH (refs, refi) {
					if (pj) {
						RAnalFunction *f = r_anal_get_fcn_in (core->anal, refi->addr,
								R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
						char *dst = r_str_newf ((f? f->name: "0x%08"PFMT64x), refi->addr);
						char *dst2 = NULL;
						RAnalOp *op = r_core_anal_op (core, refi->addr, R_ARCH_OP_MASK_BASIC);
						RBinReloc *rel = r_core_getreloc (core, refi->addr, op->size);
						if (rel) {
							if (rel && rel->import) {
								dst2 = r_bin_name_tostring (rel->import->name);
							} else if (rel && rel->symbol) {
								dst2 = r_bin_name_tostring (rel->symbol->name);
							}
						} else {
							dst2 = dst;
						}
						pj_o (pj);
						pj_ks (pj, "dest", dst2);
						pj_kn (pj, "addr", refi->addr);
						pj_kn (pj, "at", refi->at);
						pj_end (pj);
						r_anal_op_free (op);
						free (dst);
					} else {
						char *s = r_core_cmd_strf (core, "pdi %i @ 0x%08"PFMT64x, 1, refi->at);
						r_kons_printf (core->cons, "%s", s);
						free (s);
					}
				}

				// restore saved configuration
				r_config_hold_restore (hc);
				r_config_hold_free (hc);
			}
			RVecAnalRef_free (refs);

			// print json object
			if (pj) {
				pj_end (pj);
				r_cons_println (core->cons, pj_string (pj));
				pj_free (pj);
			}
		} else if (l != 0) {
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr,
					R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (f) {
				ut32 bsz = core->blocksize;
				// int fsz = r_anal_function_realsize (f);
				int fsz = r_anal_function_linear_size (f); // we want max-min here
				r_core_block_size (core, fsz);
				r_core_print_disasm_instructions (core, fsz, 0);
				r_core_block_size (core, bsz);
			} else {
				r_core_print_disasm_instructions (core, core->blocksize, l);
			}
		}
		break;
	case 'r': // "pir"
		{
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr,
					R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (f) {
				func_walk_blocks (core, f, input[2], 'I', input[2] == '.');
			} else {
				R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, core->addr);
				r_core_return_value (core, 0);
			}
		}
		break;
	case 'b': // "pib"
		{
			RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->addr);
			if (b) {
				r_core_print_disasm_instructions (core, b->size - (core->addr - b->addr), 0);
			} else {
				R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, core->addr);
				r_core_return_value (core, 0);
			}
		}
		break;
	default: // "pi"
		if (l != 0) {
			r_core_print_disasm_instructions (core, 0, l);
		}
		break;
	}
	return false;
}

static void core_print_decompile(RCore *core, const char *input) {
	int i, count = r_num_get (core->num, input);
	if (count < 1) {
		count = 1;
	}
	ut64 addr = core->addr;
	int minopsize = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	const int bits = r_config_get_i (core->config, "asm.bits");
	RCons *cons = core->cons;
	REsilC *ec = r_esil_toc_new (core->anal, bits);
	for (i = 0; i < count; i++) {
		RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL);
		if (!op) {
			addr += minopsize;
			continue;
		}
		const char *es = R_STRBUF_SAFEGET (&op->esil);
		r_esil_set_pc (ec->esil, addr);
		r_kons_printf (cons, "addr_0x%08"PFMT64x"_0: // %s\n", addr, es);
		char *cstr = r_esil_toc (ec, es);
		if (cstr) {
			r_kons_printf (cons, "%s", cstr);
			free (cstr);
		}
		addr += (op->size > 0)? op->size: minopsize;
		r_anal_op_free (op);
	}
	r_esil_toc_free (ec);
}

static void cmd_print_pxb(RCore *core, int len, const char *input) {
	const int cols = r_config_get_i (core->config, "hex.cols");
	ut32 n;
	ut64 n64;
	int columns = cols / 4;
	if (columns % 2) {
		columns++;
	}
	switch (columns) {
	case 3:
	case 5:
		columns = 4;
		break;
	case 6:
	case 7:
		columns = 8;
		break;
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		if (columns < 1) {
			columns = 1;
		} else {
			columns = 4;
		}
		break;
	}
	int lastc = columns - 1;
	int i, c;
	char buf[32];
	const bool be = r_config_get_b (core->config, "cfg.bigendian");
	for (i = c = 0; i < len; i++, c++) {
		if (c == 0) {
			ut64 ea = core->addr + i;
			if (core->print->pava) {
				r_io_p2v (core->io, ea, &ea);
			}
			r_print_section (core->print, ea);
			r_print_offset (core->print, ea, 0, 0, NULL);
		}
		r_str_bits (buf, core->block + i, 8, NULL);

		// split bits
		memmove (buf + 5, buf + 4, 5);
		buf[4] = 0;
		r_print_cursor (core->print, i, 1, 1);
		if (input[1] == 'B') {
			r_str_replace_ch (buf, '0', '.', true);
			r_str_replace_ch (buf + 5, '0', '.', true);
		}
		r_kons_printf (core->cons, "%s_%s  ", buf, buf + 5);
		r_print_cursor (core->print, i, 1, 0);
		if (c == lastc) {
			const ut8 *b = core->block + i - 3;
			ut64 (*k) (const ut8 *, int) = cmd_pxb_k;
			char (*p) (char) = cmd_pxb_p;
			switch (columns) {
			case 1:
				n = k (b, 0);
				r_cons_printf ("0x%02x  %c\n", n, p (b[0]));
				break;
			case 2:
				n = k (b, 0) | k (b, 1);
				r_cons_printf ("0x%04x  %c%c\n", n, p (b[0]), p (b[1]));
				break;
			case 4:
				n = k (b, 0) | k (b, 1) | k (b, 2) | k (b, 3);
				if (be) {
					n = r_read_be32 (&n);
				}
				r_cons_printf ("0x%08x  %c%c%c%c\n",
					n, p (b[0]), p (b[1]), p (b[2]), p (b[3]));
				break;
			case 8:
				n64 = k (b, 0) | k (b, 1) | k (b, 2) | k (b, 3)
					  | k (b, 4) | k (b, 5) | k (b, 6) | k (b, 7);
				if (be) {
					n64 = r_read_be64 (&n64);
				}
				r_cons_printf ("0x%016"PFMT64x"  %c%c%c%c%c%c%c%c\n", n64,
					p (b[0]), p (b[1]), p (b[2]), p (b[3]),
					p (b[4]), p (b[5]), p (b[6]), p (b[7]));
				break;
			}
			c = -1;
		}
	}
}

static void bitimage(RCore *core, int cols) {
	int stride = r_config_get_i (core->config, "hex.stride");
	if (stride < 1) {
		stride = 16;
	}
	const ut8 *b = core->block;
	const int s = core->blocksize;
	int x, y;
	for (y = 0; y < 8; y++) {
		size_t pos = y * stride;
		if (pos >= s) {
			break;
		}
		ut8 byte = b[pos];
		for (x = 7; x >= 0; x--) {
			bool pixel = byte & (1 << x);
			r_cons_printf ("%s", pixel? "##": "--");
		}
		r_cons_printf ("\n");
	}
}

static void cmd_pri(RCore *core, const char *input) {
	int cols = r_config_get_i (core->config, "hex.cols");
	bool has_color = r_config_get_i (core->config, "scr.color") > 0;
	switch (input[2]) {
	case '?':
		r_core_cmd_help (core, help_msg_pri);
		break;
	case 'n':
		cmd_printmsg (core, input + 4);
		break;
	case '1':
		bitimage (core, 1);
		break;
	case 'g': // gresycale
		r_cons_image (core->block, core->blocksize, cols, 'g', 3);
		break;
	case 's': // sixel
		r_cons_image (core->block, core->blocksize, cols, 's', 3);
		break;
	case '4':
		r_cons_image (core->block, core->blocksize, cols, 'r', 4);
		break;
	case 'r':
	default:
		// int mode = r_config_get_i (core->config, "scr.color")? 0: 'a';
		r_cons_image (core->block, core->blocksize, cols, has_color? 'r': 'a', 3);
		break;
	}
}

#if 0
static void bitimage0(RCore *core, int cols) {
	int stride = r_config_get_i (core->config, "hex.stride");
	if (stride < 1) {
		stride = 16;
	}
	stride = 1;
	const ut8 *b = core->block;
	int x, y;
	for (y = 0; y < 8; y++) {
		ut8 byte = b[y * stride];
		for (x = 8; x > 0; x--) {
			bool pixel = byte & (1 << x);
			r_cons_printf ("%s", pixel? "##": "--");
		}
		r_cons_printf ("\n");
	}
}
#endif

static bool check_string_pointer(RCore *core, ut64 addr) {
	ut8 buf[16];
	r_io_read_at (core->io, addr, buf, sizeof (buf));
	// check for 64bit pointer to string
	ut64 p1 = r_read_le64 (buf);
	if (check_string_at (core, p1, true)) {
		return true;
	}
	// check for 32bit pointer to string
	ut64 p2 = (ut64)r_read_le32 (buf);
	if (check_string_at (core, p2, true)) {
		return true;
	}
	// check for self reference pointer to string used by swift
	st32 p3 = (st32)r_read_le32 (buf);
	ut64 dst = core->addr + p3;
	if (check_string_at (core, dst, true)) {
		return true;
	}
	return false;
}

static void cmd_psa(RCore *core, const char *_) {
	bool found = true;
	if (!check_string_at (core, core->addr, true)) {
		if (!check_string_pointer (core, core->addr)) {
			found = false;
		}
	}
	RCmdReturnCode rc = found? R_CMD_RC_SUCCESS: R_CMD_RC_FAILURE;
	r_core_return_value (core, rc);
}

static void print_pascal_string(RCore *core, const char *input, int len) {
	int disp = 1;
	int slen = -1;
	int options = R_PRINT_STRING_ZEROEND;
	bool dojson = false;
	switch (input[0]) {
	case 'w': //pspw
		options |= R_PRINT_STRING_WIDE;
		input++;
		break;
	case 'W': //pspW
		options |= R_PRINT_STRING_WIDE32;
		input++;
		break;
	}
	switch (input[0]) {
	case 'j': // "pspj"
		dojson = true;
		break;
	case '?': // "psp?"
		r_core_cmd_help (core, help_msg_psp);
		return;
	case '0': // "psp0"
		return;
	case '1': // "psp1"
		disp = 1;
		break;
	case '2': // "psp2"
		disp = 2;
		break;
	case '4': // "psp4"
		disp = 4;
		break;
	case ' ':
		input++;
		break;
	}
	if (len < 1) {
		return;
	}
	if (input[0] && input[1] != ' ' && input[3] == 'j') {
		dojson = true;
	}
	ut8 buf[4];
	if (core->blocksize < sizeof (buf)) {
		return;
	}
	memcpy (buf, core->block, 4);
	const bool be = r_config_get_b (core->config, "cfg.bigendian");
	slen = core->block[0];
	switch (disp) {
	case 2:
		slen = r_read_ble16 (buf, be);
		break;
	case 4:
		slen = r_read_ble32 (buf, be);
		break;
	default:
		slen = buf[0];
		break;
	}
	if (slen + disp < core->blocksize) {
		if (dojson) {
			print_json_string (core, (const char *) core->block + disp, slen,
				((options & R_PRINT_STRING_WIDE) == R_PRINT_STRING_WIDE)? "wide":
				((options & R_PRINT_STRING_WIDE32) == R_PRINT_STRING_WIDE32)? "wide32": NULL);
		} else {
			r_print_string (core->print, core->addr, core->block + disp, slen, options);
		}
		core->num->value = slen;
	} else {
		R_LOG_WARN ("String longer than current block");
		core->num->value = 0; // error
	}
}

static ut64 find_nextop(RCore *core, ut64 addr) {
	RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
	if (op && (int)op->size > 0) {
		return addr + op->size;
	}
	const int minopsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	// Check for possible integer overflow
	if (UT64_MAX - (ut64)minopsz < addr) {
		return UT64_MAX;
	}
	return addr + minopsz;
}

// problematic for non-linear functions
// TODO: resort all lines from the decompiler by offset and then use that as guide
static ut64 find_endfunc(RCore *core, ut64 addr) {
	ut64 res = UT64_MAX;
	RList *funcs = r_anal_get_functions_in (core->anal, addr);
	if (funcs) {
		RAnalFunction *f = (RAnalFunction *)r_list_get_n (funcs, 0);
		if (f) {
			res = r_anal_function_max_addr (f);
		}
		r_list_free (funcs);
	}
	return res;
}
static ut64 find_nextfunc(RCore *core, ut64 addr, int range) {
	while (range-- > 0) {
#if 0
		RList *funcs = r_anal_get_functions_in (core->anal, addr);
		if (funcs) {
			RAnalFunction *f = r_list_get_n (funcs, 0);
			if (f) {
				return addr;
			}
		}
#else
		RAnalFunction *f = r_anal_get_function_at (core->anal, addr);
		if (f) {
			return addr;
		}
#endif
		addr = find_nextop (core, addr);
	}
	return UT64_MAX;
}

static void linear_pseudo(RCore *core, const char *arg) {
	int rows = (int)r_num_math (core->num, arg);
	int h;
	r_cons_get_size (core->cons, &h);
	if (rows < 1) {
		rows = h;
	}
	char *offpos = NULL;
	int lines = 0;
	RStrBuf *sb = r_strbuf_new ("");
	ut64 nextaddr = UT64_MAX;
	ut64 initial_addr = core->addr;
	ut64 addr = initial_addr;
repeat:;
	offpos = NULL;
	char *cur = r_core_cmd_str (core, "pdco");
	if (cur) {
		// we have a function, but we need to find the
		// current offset inside the output of the decompiler
		int retries = 10;
repeat_inside:;
		char *off = r_str_newf ("0x%08"PFMT64x, addr);
		offpos = strstr (cur, off);
		if (!offpos) {
			addr = find_nextop (core, addr);
			if (retries > 0) {
				retries--;
				free (off);
				off = r_str_newf ("0x%08"PFMT64x, addr);
				goto repeat_inside;
			}
			R_FREE (cur);
		}
		R_FREE (off);
	}
	if (offpos) {
		while (offpos > cur) {
			if (*offpos == '\n') {
				offpos++;
				break;
			}
			offpos--;
		}
		r_strbuf_append (sb, offpos);
		lines += r_str_char_count (offpos, '\n');
#if 0
		char *lastoff = r_str_rstr (offpos, "0x");
		nextaddr = r_num_get (core->num, lastoff);
#else
		ut64 eof = find_endfunc (core, addr);
		if (eof != UT64_MAX) {
			nextaddr = find_nextop (core, eof);
		}
#endif
	} else {
		nextaddr = addr;
	}
				free (cur);
				cur = NULL;
	ut64 nextfunc = find_nextfunc (core, nextaddr, 128);
	if (lines < rows) {
		if (nextfunc == UT64_MAX) {
			char *res = r_core_cmd_strf (core, "pd %d @0x%08"PFMT64x"@e:asm.lines=0@e:asm.pseudo=true@e:asm.bytes=0@e:emu.str=true", rows-lines, addr);
			r_strbuf_append (sb, res);
			free (res);
		} else {
			char *res = r_core_cmd_strf (core, "pD %"PFMT64d" @0x%08"PFMT64x"@e:asm.lines=0@e:asm.pseudo=true@e:asm.bytes=0@e:emu.str=true", nextfunc - addr, addr);
			r_strbuf_append (sb, res);
			lines += r_str_char_count (res, '\n');
			free (res);
			addr = nextfunc;
			r_core_seek (core, nextfunc, true);
			goto repeat;
		}
	}
	char *s = r_strbuf_drain (sb);
	r_kons_print (core->cons, s);
	free (s);
	r_core_seek (core, initial_addr, true);
}

static void p8fm(RCore *core, ut64 addr, int mode) {
	if (mode == '?') {
		r_core_cmd_help_contains (core, help_msg_p8, "p8fm");
		return;
	}
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	if (!fcn) {
		R_LOG_ERROR ("Cannot p8fm at 0x%08"PFMT64x, addr);
		return;
	}
	RStrBuf *sbb = r_strbuf_new (""); // bytes
	RStrBuf *sbm = r_strbuf_new (""); // mask
	ut64 minat = r_anal_function_min_addr (fcn);
	ut64 maxat = r_anal_function_max_addr (fcn);
	bool linear = true;
	ut64 at;
	for (at = minat; at < maxat; at++) {
		RAnalBlock *bb = r_anal_bb_from_offset (core->anal, at);
		if (bb) {
			char *bbdata = r_core_cmd_strf (core, "'0x%"PFMT64x"'abm", at);
			r_str_trim (bbdata);
			char *bbmask = strchr (bbdata, ':');
			if (bbmask) {
				*bbmask++ = 0;
				r_strbuf_append (sbb, bbdata);
				r_strbuf_append (sbm, bbmask);
			} else {
				R_LOG_ERROR ("Unexpected output from abm: (0x%08"PFMT64x")=(%s)", at, bbdata);
			}
			free (bbdata);
			at = bb->addr + bb->size - 1;
		} else {
			// data gap.. skipping byte
			r_strbuf_append (sbb, "00");
			r_strbuf_append (sbm, "00");
			linear = false;
		}
	}

	char *sb = r_strbuf_drain (sbb);
	char *sm = r_strbuf_drain (sbm);
	if (mode == 'j') {
		PJ *pj = r_core_pj_new (core);
		pj_o (pj);
		pj_ks (pj, "type", "function");
		pj_kb (pj, "linear", linear);
		pj_kn (pj, "addr", fcn->addr);
		pj_kn (pj, "size", maxat - minat);
		pj_ks (pj, "data", sb);
		pj_ks (pj, "mask", sm);
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	} else {
		r_kons_printf (core->cons, "%s:%s\n", sb, sm);
	}
	free (sb);
	free (sm);
}

static int cmd_print(void *data, const char *input) {
	RCore *core = (RCore *) data;
	st64 l;
	int i, len, ret;
	ut8* block = NULL;
	bool myblock = false;
	ut32 tbs = core->blocksize;
	ut64 n, off, from, to, at, ate, piece;
	ut64 tmpseek = UT64_MAX;
	const size_t addrbytes = core->io->addrbytes;
	i = l = len = ret = 0;
	n = off = from = to = at = ate = piece = 0;
	PJ *pj = NULL;

	/* !strncmp (input, "du", 2) */
	if (input[0] == 'd' && input[1] == 'u') { // "pdu"
		/* hijack here for now, idk how to more cleanly integrate it */
		return cmd_pdu (core, input + 2);
	}
	if (r_str_startswith (input, "ushd")) { // "pushd"
		bool halp = true;
		const char *arg = strchr (input, ' ');
		if (arg) {
			arg = r_str_trim_head_ro (arg + 1);
			if (*arg) {
				halp = false;
				if (r_syscmd_pushd (arg)) {
					r_core_return_value (core, 0);
				} else {
					r_core_return_value (core, 1);
				}
			}
		}
		if (halp) {
			r_core_cmd_help_match (core, help_msg_p, "pushd");
			r_core_return_value (core, 1);
		}
		return 0;
	}
	if (r_str_startswith (input, "opd")) { // "popd"
		bool all = strstr (input, "-a");
		bool halp = strstr (input, "-h");
		if (halp) {
			r_core_cmd_help_match (core, help_msg_p, "popd");
			r_core_return_value (core, 1);
		} else {
			bool suc = all
				? r_syscmd_popalld ()
				: r_syscmd_popd ();
			if (suc) {
				r_core_return_value (core, 0);
			} else {
				R_LOG_ERROR ("Nothing was pushd. Cannot popd");
				r_core_return_value (core, 1);
			}
		}
		return 0;
	}

	r_print_init_rowoffsets (core->print);
	off = UT64_MAX;
	l = len = core->blocksize;
	if (input[0] && input[1]) {
		int idx = (input[0] == 'h')? 2: 1;
		const char *p = off? strchr (input + idx, ' '): NULL;
		if (!p) {
			p = strchr (input, '-');
			if (p) {
				p--;
			}
		}
		if (p) {
			l = (int) r_num_math (core->num, p + 1);
			/* except disasm and memoryfmt (pd, pm) and overlay (po) */
			if (input[0] != 'd' && input[0] != 't' && input[0] != 'D' && input[0] != 'm' &&
				input[0] != 'a' && input[0] != 'f' && input[0] != 'i' &&
				input[0] != 'I' && input[0] != 'o') {
				if (l < 0) {
					off = core->addr + l;
					len = l = -l;
					tmpseek = core->addr;
				} else {
					len = l;
					if (l > core->blocksize) {
						if (!r_core_block_size (core, l)) {
							goto beach;
						}
					}
				}
			} else {
				len = l;
			}
		}
	}
	if (len < 0) {
		len = -len;
	}
	if (len > core->blocksize) {
		block = calloc (1, len);
		if (block) {
			r_io_read_at (core->io, core->addr - len, block, len);
			myblock = true;
		} else {
			len = core->blocksize;
			block = core->block;
		}
	} else {
		block = core->block;
	}

	if (input[0] != 'd' && input[0] != 'm' && input[0] != 'a' && input[0] != 'f' && input[0] != 'i') {
		n = core->blocksize_max;
		i = (int) n;
		if (i != n) {
			i = 0;
		}
		if (i && l > i) {
			R_LOG_ERROR ("Block size is too large (0x%"PFMT64x " < 0x%" PFMT64x "). Did you mean 'p%c @ %s' instead?",
				n, l, *input, *input? r_str_trim_head_ro (input + 1): "");
			goto beach;
		}
	}
	if (input[0] == 'x' || input[0] == 'D') {
		if (l > 0 && tmpseek == UT64_MAX) {
			if (!r_core_block_size (core, l)) {
				R_LOG_ERROR ("This block size is too big. Did you mean 'p%c @ %s' instead?", *input, input + 2);
				goto beach;
			}
		}
	}

	if (input[0] && input[0] != 'z' && input[1] == 'f' && input[2]!='?') {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, 0);
		// R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) {
			len = r_anal_function_linear_size (f);
			if (len > core->blocksize) {
				len = core->blocksize;
			}
		} else {
			R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, core->addr);
			r_core_return_value (core, 0);
			goto beach;
		}
	}
	// TODO figure out why `f eax=33; f test=eax; pa call test` misassembles if len is 0
	r_core_return_value (core, len ? len : core->blocksize);
	if (off != UT64_MAX) {
		r_core_seek (core, off, SEEK_SET);
		r_core_block_read (core);
	}
	const char ch0 = *input;
	switch (ch0) {
	case 'w': // "pw"
		if (input[1] == 'n') {
			cmd_print_pwn (core);
		} else if (input[1] == 'd') {
			if (!r_sandbox_enable (0)) {
				char *cwd = r_sys_getdir ();
				if (cwd) {
					r_cons_println (core->cons, cwd);
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
				ut8 *data = calloc (core->addr + 1, 1);
				if (data) {
					data[core->addr] = 0;
					(void)r_io_read_at (core->io, 0, data, core->addr);
					char *res = r_print_json_path ((const char *)data, core->addr);
					if (res) {
						r_cons_println (core->cons, res);
					}
				} else {
					R_LOG_ERROR ("Cannot allocate %d", (int)(core->addr));
				}
			} else {
				r_core_cmdf (core, "pj %"PFMT64u" @ 0", core->addr);
			}
		} else {
			if (core->blocksize < 4 || !memcmp (core->block, "\xff\xff\xff\xff", 4)) {
				R_LOG_ERROR ("Cannot read");
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
		cmd_print_pv (core, input + 1, false);
		break;
	case 'V': // "pv"
		cmd_print_pv (core, input + 1, true);
		break;
	case '-': // "p-"
		return cmd_print_blocks (core, input + 1);
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
			r_core_cmd_help_contains (core, help_msg_p, "pA");
		} else {
			r_config_set_i (core->config, "search.maxhits", want);
			r_config_set_i (core->config, "search.from", core->addr);
			r_config_set_i (core->config, "search.to", core->addr + core->blocksize);
			r_core_cmd0 (core, "/a");
			r_config_set_i (core->config, "search.maxhits", saved_maxhits);
			r_config_set_i (core->config, "search.from", saved_from);
			r_config_set_i (core->config, "search.to", saved_to);
		}
	}
	break;
	case 'a': // "pa"
	{
		const char *arg = NULL;
		if (input[1] != '\0') {
			arg = r_str_trim_head_ro (input + 2);
		}
		if (input[1] == 'e') { // "pae"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pa, "pae");
			} else {
				int printed = 0;
				int bufsz;
				RAnalOp aop = {0};
				r_asm_set_pc (core->rasm, core->addr);
				RAsmCode *acode = r_asm_massemble (core->rasm, input + 2);
				if (acode) {
					bufsz = acode->len;
					while (printed < bufsz) {
						aop.size = 0;
						if (r_anal_op (core->anal, &aop, core->addr,
							    (const ut8 *)acode->bytes + printed, bufsz - printed, R_ARCH_OP_MASK_ESIL) > 0) {
							const char *str = R_STRBUF_SAFEGET (&aop.esil);
							r_cons_println (core->cons, str);
						} else {
							R_LOG_ERROR ("Cannot decode instruction");
							break;
						}
						if (aop.size < 1) {
							R_LOG_ERROR ("Cannot decode instruction");
							break;
						}
						printed += aop.size;
						r_anal_op_fini (&aop);
					}
				}
			}
		} else if (input[1] == 'D') { // "paD"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pa, "paD");
			} else {
				r_core_cmdf (core, "pdi@x:%s", input + 2);
			}
		} else if (input[1] == 'd') { // "pad*"
			switch (input[2]) {
			case 'e': // "pade"
				if (input[3] == '?') {
					r_core_cmd_help_match (core, help_msg_pa, "pade");
				} else {
					int printed = 0;
					int bufsz;
					RAnalOp aop = {0};
					char *hex_arg = calloc (1, strlen (arg) + 1);
					if (hex_arg) {
						bufsz = r_hex_str2bin (arg + 1, (ut8 *)hex_arg);
						while (printed < bufsz) {
							aop.size = 0;
							if (r_anal_op (core->anal, &aop, core->addr,
								    (const ut8 *)hex_arg + printed, bufsz - printed, R_ARCH_OP_MASK_ESIL) > 0) {
								const char *str = R_STRBUF_SAFEGET (&aop.esil);
								r_cons_println (core->cons, str);
							} else {
								R_LOG_ERROR ("Cannot decode instruction");
								break;
							}
							if (aop.size < 1) {
								R_LOG_ERROR ("Cannot decode instruction");
								break;
							}
							printed += aop.size;
							r_anal_op_fini (&aop);
						}
						free (hex_arg);
					}
				}
				break;
			case ' ': // "pad"
				__cmd_pad (core, arg);
				break;
			case '?': // "pad?"
				r_core_cmd_help_contains (core, help_msg_pa, "pad");
				break;
			default:
				r_core_cmd_help (core, help_msg_pa);
				break;
			}
		} else if (input[1] == '?') {
			if (input[2] == 'j') {
				r_core_cmd_help_json (core, help_msg_pa);
			} else {
				r_core_cmd_help (core, help_msg_pa);
			}
		} else {
			r_asm_set_pc (core->rasm, core->addr);
			RAsmCode *acode = r_asm_massemble (core->rasm, input + 1);
			if (acode) {
				if (!acode->len) {
					r_core_cmd_help_contains (core, help_msg_pa, "pa");
				} else {
					size_t i;
					for (i = 0; i < acode->len; i++) {
						ut8 b = acode->bytes[i];
						r_cons_printf ("%02x", b);
					}
					r_cons_newline (core->cons);
					r_asm_code_free (acode);
				}
			}
		}
	}
	break;
	case 'b': { // "pb"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_p, "pb");
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
				if (from >= 0 && to >= 0) {
					if (from >= buf_len) {
						from = buf_len;
					}
					if (to < buf_len) {
						buf[to] = 0;
						//buf[buf_len - 1] = 0;
					}
					r_cons_println (core->cons, buf + from);
				}
				free (buf);
			} else {
				R_LOG_ERROR ("Cannot allocate %d byte(s)", size);
			}
		}
	}
		break;
	case 'B': { // "pB"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_p, "pB");
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
				r_cons_println (core->cons, buf);
				free (buf);
			} else {
				R_LOG_ERROR ("Cannot allocate %d byte(s)", size);
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
					r_strf_var (numstr, 32, "%d", core->blocksize);
					cmd_pDj (core, numstr);
				}
			}
			break;
		case 'f': // "pIf"
		{
			const RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr,
				R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (f) {
				r_core_print_disasm_instructions (core,
					r_anal_function_linear_size ((RAnalFunction *) f), 0);
				break;
			}
		}
		case 'd': // "pId" is the same as pDi
			if (l) {
				r_core_disasm_pdi (core, 0, l, 0);
			}
			break;
		case '?': // "pi?"
			r_core_cmd_help (core, help_msg_pi);
			break;
		default:
			if (l) {
				r_core_print_disasm_instructions (core, l, 0);
			}
			break;
		}
		break;
	case 'i': // "pi"
		if (cmd_pi (core, input, len, l, block)) {
			break;
		}
		goto beach;
	case 'D': // "pD"
	case 'd': // "pd"
	{
		ut64 use_blocksize = core->blocksize;
		ut8 bw_disassemble = false;
		ut32 pd_result = false, processed_cmd = false;
		bool formatted_json = false;
	        const bool asm_addr_segment = r_config_get_b (core->config, "asm.addr.segment");
		if (input[1] && input[2]) {
			// "pd--" // context disasm
			if (!strncmp (input + 1, "--", 2)) {
				char *offs = r_str_newf ("%s", input + 2);
				if (offs) {
					ut64 sz = r_num_math (core->num, offs);
					char *fmt;
					if (((st64)sz * -1) > core->addr) {
						// the offset is smaller than the negative value
						// so only print -offset
						fmt = r_str_newf ("d %"PFMT64d, -1 * core->addr);
					} else {
						fmt = r_str_newf ("d %s", input + 2);
					}
					if (fmt) {
						cmd_print (core, fmt);
						strcpy (fmt + 2, input + 3);
						cmd_print (core, fmt);
						free (fmt);
					}
					free (offs);
				}
				ret = 0;
				goto beach;
			}
		}

		if (input[1] == 'x') { // pdx
			__cmd_pad (core, r_str_trim_head_ro (input + 2));
			return 0;
		}

		const char *sp = (input[1] == '.' || input[1] == '+')
			? input + 2: strchr (input + 1, ' ');

		if (isdigit (input[1])) {
			sp = input + 1;
		} else if (!sp && input[1] == '-') {
			sp = input + 1;
		}
		if (sp) {
			int n = (int) r_num_math (core->num, r_str_trim_head_ro (sp));
			if (!n) {
				goto beach;
			}
			use_blocksize = n;
		}

		int mbs = core->blocksize_max;
		if (core->blocksize_max < use_blocksize && (int) use_blocksize < -mbs) {
			R_LOG_ERROR ("Block size is too large (%"PFMT64u "<%"PFMT64u "). Did you mean 'p%c @ 0x%08"PFMT64x "' instead?",
				(ut64) core->blocksize_max, (ut64) use_blocksize, input[0], (ut64) use_blocksize);
			goto beach;
		} else if (core->blocksize_max < use_blocksize && (int) use_blocksize > -mbs) {
			bw_disassemble = true;
			l = use_blocksize; // negative
			use_blocksize = (ut64)-(st64)use_blocksize;
		} else {
			l = use_blocksize;
		}
		// may be unnecessary, fixes 'pd 1;pdj 100;pd 1' bug
#if 0
		core->addr = at; // "pd" doesnt know about the current offset for pd -X
#endif
		r_core_block_read (core);

		switch (input[1]) {
		case 'C': // "pdC"
			r_core_disasm_pdi (core, l, 0, 'C');
			pd_result = false;
			processed_cmd = true;
			break;
		case 'v': // "pdv" // east decompiler
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci east");
			processed_cmd = true;
			break;
		case 'd': // "pdd" // r2dec
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2dec");
			r_core_return_code (core, 1);
			processed_cmd = true;
			break;
		case 'z': // "pdz" // retdec
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2retdec");
			r_core_return_code (core, 1);
			processed_cmd = true;
			break;
		case 'g': // "pdg" // r2ghidra
			R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2ghidra");
			r_core_return_code (core, 1);
			processed_cmd = true;
			break;
		case 'c': // "pdc" // "pDc"
			if (input[2] == 'l') {
				linear_pseudo (core, input + 3);
			} else {
				r_core_pseudo_code (core, input + 2);
			}
			pd_result = false;
			processed_cmd = true;
			break;
		case ',': // "pd,"
		case 't': // "pdt" // R_DEPRECATE pdt imho
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pd,");
				return 0;
			} else {
				r_core_disasm_table (core, l, r_str_trim_head_ro (input + 2));
				pd_result = 0;
				processed_cmd = true;
			}
			break;
		case 'k': // "pdk" -print class
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdk");
				return 0;
			} else {
				int len = 0;
				ut64 at = findClassBounds (core, r_str_trim_head_ro (input + 2), &len);
				return r_core_cmdf (core, "pD %d @ %"PFMT64u, len, at);
			}
			break;
		case 'i': // "pdi" // "pDi"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdi");
				return 0;
			} else {
				processed_cmd = true;
				if (*input == 'D') {
					r_core_disasm_pdi (core, 0, l, 0);
				} else {
					r_core_disasm_pdi (core, l, 0, 0);
				}
				pd_result = false;
			}
			break;
		case 'a': // "pda"
			processed_cmd = true;
			if (input[2] == '?') {
				r_core_cmd_help_contains (core, help_msg_pd, "pda");
			} else if (input[2] == 'j' && input[3] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdaj");
			} else {
				r_core_print_disasm_all (core, core->addr, l, len, input[2]);
				pd_result = true;
			}
			break;
		case 'o': // "pdo"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdo");
				return 0;
			}
			core_print_decompile (core, input + 2);
			pd_result = true;
			processed_cmd = true;
			break;
		case 'e': // "pde"
			processed_cmd = true;
			if (!core->fixedblock && !sp) {
				l /= 4;
			}
			if (input[2] == '?') { // "pde?"
				r_core_cmd_help (core, help_msg_pde);
				return 0;
			};
			int mode = R_MODE_PRINT;
			if (input[2] == 'j') {
				if (input[3] == '?') {
					r_core_cmd_help_match (core, help_msg_pde, "pdej");
					return 0;
				}
				mode = R_MODE_JSON;
			} else if (input[2] == 'q') {
				if (input[3] == 'q') { // "pdeqq"
					if (input[4] == '?') {
						r_core_cmd_help_match (core, help_msg_pde, "pdeqq");
						return 0;
					}
					mode = R_MODE_SIMPLEST; // Like pi
				} else { // "pdeq"
					if (input[3] == '?') {
						r_core_cmd_help_contains (core, help_msg_pde, "pdeq");
						return 0;
					}
					mode = R_MODE_SIMPLE; // Like pdi
				}
			}
			r_core_disasm_pde (core, l, mode);
			pd_result = true;
			break;
		case 'R': // "pdR"
			processed_cmd = true;
			if (input[2] == 'j') {
				disasm_recursive (core, core->addr, use_blocksize, 'j');
			} else {
				disasm_recursive (core, core->addr, use_blocksize, 'D');
			}
			pd_result = true;
			break;
		case 'r': // "pdr"
			processed_cmd = true;
			if (input[2] == '?') { // "pdr?"
				r_core_cmd_help_contains (core, help_msg_pd, "pdr");
				pd_result = true;
				break;
			} else if (input[2] == '.' && input[3] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdr.");
			} else {
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, 0);
				// R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f) {
					func_walk_blocks (core, f, input[2], 'D', input[2] == '.');
				} else {
					R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, core->addr);
				}
				pd_result = true;
			}
			break;
		case 'b': // "pdb"
			processed_cmd = true;
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdb");
			} else {
				RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->addr);
				if (b) {
					ut8 *block = malloc (b->size + 1);
					if (block) {
						r_io_read_at (core->io, b->addr, block, b->size);

						if (input[2] == 'j') {
							pj = r_core_pj_new (core);
							if (!pj) {
								break;
							}
							pj_a (pj);
							r_core_print_disasm_json_ipi (core, b->addr, block, b->size, 0, pj, NULL);
							pj_end (pj);
							r_cons_printf ("%s\n", pj_string (pj));
							pj_free (pj);
						} else {
							int dislen = r_core_print_disasm (
								core, b->addr, block,
								b->size, b->size, 0, NULL, true,
								input[2] == 'J', NULL, NULL);
							r_core_return_value (core, dislen);
						}
						free (block);
						pd_result = false;
					}
				} else {
					R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, core->addr);
					r_core_return_value (core, 0);
				}
			}
			break;
		case 's': // "pds"
			processed_cmd = true;
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_pds);
			} else if (input[2] == '*') {
				if (input[3] == '?') {
					r_core_cmd_help_contains (core, help_msg_pds, "pds*");
					break;
				}
				char *s = r_core_cmd_str (core, "pdsf@e:scr.color=0");
				r_str_ansi_filter (s, NULL, NULL, strlen (s));
				RList *items = r_str_split_list (s, "\n", 0);
				char *it;
				RListIter *iter;
				r_list_foreach (items, iter, it) {
					if (r_str_startswith (it, "0x") && strchr (it, '"')) {
						char *sp = strchr (it, ' ');
						if (sp) {
							*sp = 0;
							r_cons_printf ("'@%s'CC string: %s\n", it, sp + 1);
						}
					}
				}
				r_list_free (items);
				free (s);
			} else {
				if (input[2] && input[3] == '?') {
					r_core_cmd_help (core, help_msg_pds);
				} else {
					disasm_strings (core, input, NULL);
				}
			}
			break;
		case 'f': // "pdf"
			processed_cmd = true;
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_pdf);
			} else if (input[2] == 's') { // "pdfs"
				ut64 oseek = core->addr;
				int oblock = core->blocksize;
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr,
					R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (f) {
					ut32 rs = r_anal_function_realsize (f);
					ut32 fs = r_anal_function_linear_size (f);
					r_core_seek (core, oseek, SEEK_SET);
					r_core_block_size (core, R_MAX (rs, fs));
					disasm_strings (core, input, f);
					r_core_block_size (core, oblock);
					r_core_seek (core, oseek, SEEK_SET);
				}
				processed_cmd = true;
			} else if (input[2] == 0 || input[2] == 'j' || input[2] == 'r') {
				ut32 bsz = core->blocksize;
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_ROOT);
				if (!f) {
					f = r_anal_get_fcn_in (core->anal, core->addr, 0);
				}
				RListIter *locs_it = NULL;
				if (f) {
					if (input[2] == 'r') { // "pdfr"
						r_core_cmd0 (core, "pdr");
					} else if (input[2] == 'j') { // "pdfj"
						RAnalBlock *b;
						ut32 fcn_size = r_anal_function_realsize (f);
						const char *orig_bb_middle = r_config_get (core->config, "asm.bbmiddle");
						r_config_set_i (core->config, "asm.bbmiddle", false);
						pj = r_core_pj_new (core);
						if (!pj) {
							break;
						}
						pj_o (pj);
						pj_ks (pj, "name", f->name);
						pj_kn (pj, "size", fcn_size);
						pj_kn (pj, "addr", f->addr);
						pj_k (pj, "ops");
						pj_a (pj);
						r_list_sort (f->bbs, bb_cmpaddr);
						r_list_foreach (f->bbs, locs_it, b) {
							ut8 *buf = malloc (b->size);
							if (buf) {
								r_io_read_at (core->io, b->addr, buf, b->size);
								r_core_print_disasm_json_ipi (core, b->addr, buf, b->size, 0, pj, NULL);
								free (buf);
							} else {
								R_LOG_ERROR ("Cannot allocate %"PFMT64u" byte(s)", b->size);
							}
						}
						pj_end (pj);
						pj_end (pj);
						r_cons_printf ("%s\n", pj_string (pj));
						pj_free (pj);
						pd_result = false;
						r_config_set (core->config, "asm.bbmiddle", orig_bb_middle);
					} else {
						ut64 linearsz = r_anal_function_linear_size (f);
						ut64 realsz = r_anal_function_realsize (f);
						if (realsz + 4096 < linearsz) {
							R_LOG_ERROR ("Linear size differs too much from the bbsum, please use pdr instead");
						} else {
							ut64 at = f->addr; // TODO: should be min from r_anal_function_get_range()?
							ut64 sz = R_MAX (linearsz, realsz);
							ut8 *buf = calloc (sz, 1);
							if (buf) {
								(void)r_io_read_at (core->io, at, buf, sz);
								int dislen = r_core_print_disasm (core, at, buf, sz, sz, 0, NULL, true, false, NULL, f);
								r_core_return_value (core, dislen);
								free (buf);
								// r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x, f->_size > 0 ? f->_size: r_anal_function_realsize (f), f->addr);
							}
						}
						pd_result = false;
					}
				} else {
					R_LOG_ERROR ("pdf: Cannot find function at 0x%08"PFMT64x, core->addr);
					processed_cmd = true;
					r_core_return_value (core, 0);
				}
				if (bsz != core->blocksize) {
					r_core_block_size (core, bsz);
				}
			} else {
				r_core_return_invalid_command (core, "pdf", input[2]);
			}
			l = 0;
			break;
		case 'p': // "pdp"
			processed_cmd = true;
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_pd, "pdp");
				pd_result = true;
				break;
			};
			disasm_ropchain (core, core->addr, 'D');
			pd_result = true;
			break;
		case 'l': // "pdl"
			processed_cmd = true;
			{
				RAnalOp asmop;
				int j, ret;
				if (!l) {
					l = len;
				}
				r_cons_break_push (core->cons, NULL, NULL);
				for (i = j = 0; i < core->blocksize && j < l; i += ret, j++) {
					ret = r_asm_disassemble (core->rasm, &asmop, block + i, len - i);
					if (r_cons_is_breaked (core->cons)) {
						break;
					}
					r_kons_printf (core->cons, "%d\n", ret);
					if (ret < 1) {
						ret = 1;
					}
				}
				r_cons_break_pop (core->cons);
				pd_result = false;
			}
			break;
		case 'j': // "pdj"
			processed_cmd = true;
			if (*input == 'D') {
				cmd_pDj (core, input + 2);
			} else {
				cmd_pdj (core, input + 2, block);
			}
			pd_result = false;
			break;
		case 'J': // pdJ
			formatted_json = true;
			break;
		case 0: // "pd"
			/* "pd" -> will disassemble blocksize/4 instructions */
			if (!core->fixedblock && *input == 'd') {
				l /= 4;
			}
			break;
		case '?': // "pd?"
			processed_cmd = true;
			r_core_cmd_help (core, help_msg_pd);
			pd_result = false;
		case '.':
		case '-':
		case '+':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '$':
		case '9':
		case ' ':
			break;
		default:
			R_LOG_ERROR ("Invalid pd subcommand");
			return 0;
		}
		if (formatted_json) {
			RConsContext *c = core->cons->context;
			if (c->is_html) {
				c->is_html = false;
				c->was_html = true;
			}
		}
		if (!processed_cmd) {
			ut64 addr = core->addr;
			ut8 *block1 = NULL;
			ut64 start;

			if (bw_disassemble) {
				int bs1 = (core->blocksize * 2) + 64;
				block1 = malloc (bs1);
				if (l < 0) {
					l = -l;
				}
				if (block1) {
					if (*input == 'D') { // pD
						free (block1);
						if (!(block1 = malloc (bs1))) {
							break;
						}
						r_io_read_at (core->io, addr - l, block1, bs1);
						int dislen = r_core_print_disasm (core, addr - l, block1, l, l, 0, NULL, true, formatted_json, NULL, NULL);
						r_core_return_value (core, dislen);
					} else { // pd
						if (!r_core_prevop_addr (core, core->addr, l, &start)) {
							// anal ignorance.
							start = r_core_prevop_addr_force (core, core->addr, l);
						}
						int instr_len = core->addr - start;
						ut64 prevaddr = core->addr;
						int bs = core->blocksize;
						int bs2 = addrbytes * instr_len;
						if (bs2 > bs) {
							bs1 += bs2 + 32;
							bs2 = bs1;
							bs = bs2;
							ut8 *tmpblock = realloc (block1, bs1);
							if (!tmpblock) {
								R_LOG_ERROR ("Memory reallocation failed");
								free (block1);
								break;
							}
							block1 = tmpblock;
						}
						r_io_read_at (core->io, prevaddr - instr_len, block1, bs1);
						r_core_seek (core, prevaddr - instr_len, true);
						int dislen = r_core_print_disasm (core,
								core->addr, block1,
								R_MAX (bs, bs1), l, 0, NULL,
								false, formatted_json, NULL,
								NULL);
						r_core_return_value (core, dislen);
						r_core_seek (core, prevaddr, true);
					}
				}
			} else {
				// XXX: issue with small blocks
				if (*input == 'D' && use_blocksize > 0) {
					l = use_blocksize;
					if (l > R_CORE_MAX_DISASM) { // pD
						R_LOG_ERROR ("Block size too big");
						return 1;
					}
					block1 = malloc (addrbytes * l);
					if (block1) {
						r_io_read_at (core->io, addr, block1, addrbytes * l);
						int dislen = r_core_print_disasm (core,
								addr, block1, addrbytes * l, l,
								0, NULL, true, formatted_json,
								NULL, NULL);
						r_core_return_value (core, dislen);
					} else {
						R_LOG_ERROR ("Cannot allocate %" PFMT64d " byte(s)", addrbytes * l);
					}
				} else {
					ut8 *buf = core->block;
					const int buf_size = core->blocksize;
					if (buf) {
						if (!l) {
							l = use_blocksize;
							if (!core->fixedblock) {
								l /= 4;
							}
						}
						core->num->value = r_core_print_disasm (core,
								addr, buf, buf_size, l,	0, NULL,
								false, formatted_json, NULL, NULL);
					}
				}
			}
			free (block1);
			if (formatted_json) {
				r_cons_newline (core->cons);
			}
		}
		r_config_set_b (core->config, "asm.addr.segment", asm_addr_segment);
		if (processed_cmd) {
			ret = pd_result;
			goto beach;
		}
	}
	break;
	case 'p': // "pp"
		__printPattern (core, input + 1);
		break;
	case 's': // "ps"
		switch (input[1]) {
		case '?': // "ps?"
			r_core_cmd_help (core, help_msg_ps);
			break;
		case 'o':
			{
				char *s = print_analstr (core, core->addr, 128);
				if (s) {
					if (input[2] == 'j') {
						PJ *pj = r_core_pj_new (core);
						pj_o (pj);
						pj_kn (pj, "addr", core->addr);
						pj_ks (pj, "text", s);
						pj_end (pj);
						free (s);
						s = pj_drain (pj);
					}
					r_cons_printf ("%s\n", s);
					free (s);
					r_core_return_code (core, 0);
				} else {
					// do nothing, just return error code
					r_core_return_code (core, 1);
				}
			}
			break;
		case 'i': // "psi"
			if (l > 0) {
				ut8 *buf = malloc (1024 + 1);
				int delta = 512;
				ut8 *p, *e, *b;
				if (!buf) {
					return 0;
				}
				buf[1024] = 0;
				if (core->addr < delta) {
					delta = core->addr;
				}
				p = buf + delta;
				r_io_read_at (core->io, core->addr - delta, buf, 1024);
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
				r_cons_println (core->cons, (const char *) b);
				// r_print_string (core->print, core->addr, b,
				// (size_t)(e-b), 0);
				free (buf);
			}
			break;
		case 'n': // "psn"
			if (input[1] == '?') {
				r_cons_printf ("Usage: psn[l] [len] - print string until newline or maxlen\n");
			} else {
				int len = core->blocksize;
				if (input[2] == ' ') {
					len = r_num_math (core->num, input + 2);
				}
				char *buf = malloc (len);
				if (!buf) {
					break;
				}
				if (r_io_read_at (core->io, core->addr, (ut8*)buf, len) < 1) {
					R_LOG_ERROR ("cannot read");
					break;
				}

				char *nl = (char *)r_str_nchr ((const char *)buf, '\n', len);
				if (nl) {
					size_t len = nl - (char *)buf;
					if (input[2] == 'l') { // "psnl"
						r_cons_printf ("%d\n", (int)len);
					} else {
						r_cons_write (core->cons, (const char *)buf, len);
						r_cons_newline (core->cons);
					}
				} else {
					if (input[2] == 'l') { // "psnl"
						r_kons_print (core->cons, "0\n");
					} else {
						// cant find newline, print block
						r_cons_write (core->cons, (const char *)core->block, core->blocksize);
						r_cons_newline (core->cons);
					}
				}
				free (buf);
			}
			break;
		case 'x': // "psx"
			if (l > 0) {
				r_print_string (core->print, core->addr, block, len, R_PRINT_STRING_ESC_NL);
			}
			break;
		case 'a': // "psa"
			cmd_psa (core, input + 1);
			break;
		case 'b': // "psb"
			if (l > 0) {
				int quiet = input[2] == 'q'; // "psbq"
				RStrBuf *sb = r_strbuf_new ("");
				int i, hasnl = 0;
				if (sb) {
					if (!quiet) {
						r_print_offset (core->print, core->addr, 0, 0, NULL);
					}
					// TODO: filter more chars?
					for (i = 0; i < core->blocksize; i++) {
						char ch = (char) block[i];
						if (ch == 0xa) {
							char *s = r_strbuf_drain (sb);
							r_kons_print (core->cons, s); // TODO: missing newline?
							free (s);
							sb = r_strbuf_new ("");
							r_cons_newline (core->cons);
							if (!quiet) {
								r_print_offset (core->print, core->addr + i, 0, 0, NULL);
							}
							hasnl = 1;
							continue;
						}
						if (!ch) {
							if (core->print->cur_enabled && core->print->cur == i) {
								r_strbuf_append (sb, Color_INVERT"."Color_RESET);
							}
							if (!hasnl) {
								char *s = r_strbuf_drain (sb);
								r_cons_println (core->cons, s); // TODO: missing newline?
								free (s);
								sb = r_strbuf_new ("");
								if (!quiet) {
									r_print_offset (core->print, core->addr + i, 0, 0, NULL);
								}
							}
							hasnl = true;
							continue;
						}
						hasnl = 0;
						if (IS_PRINTABLE (ch)) {
							if (core->print->cur_enabled && core->print->cur == i) {
								r_strbuf_appendf (sb, Color_INVERT"%c"Color_RESET, ch);
							} else {
								r_strbuf_appendf (sb, "%c", ch);
							}
						} else {
							if (core->print->cur_enabled && core->print->cur == i) {
								r_strbuf_append (sb, Color_INVERT"."Color_RESET);
							}
						}
					}
					char *s = r_strbuf_drain (sb);
					r_kons_print (core->cons, s); // TODO: missing newline?
					free (s);
				}
			}
			break;
		case 'z': // "psz"
			if (l > 0) {
				ut8 *s = decode_text (core, core->addr, l, true);
				if (input[2] == 'j') { // pszj
					print_json_string (core, (const char *) s,
						r_str_nlen ((const char*)s, l), NULL);
				} else if (input[2] == '*') {
					char *a = r_str_ndup ((const char*)s, l);
					char *b = (char *)r_base64_encode_dyn ((const ut8 *)a, -1);
					r_kons_printf (core->cons, "w6e %s\n", b);
					free (b);
					free (a);
				} else if (input[2] == '?') {
					r_core_cmd_help (core, help_msg_psz);
				} else if (input[2] == 'c' || input[2] == 'l') {
					r_cons_printf ("%d\n", (int)r_str_nlen ((const char*)s, l));
				} else {
					r_print_string (core->print, core->addr, s, l, R_PRINT_STRING_ZEROEND);
				}
				free (s);
			}
			break;
		case 'p': // "psp"
			print_pascal_string (core, input + 2, l);
			break;
		case 'w': // "psw"
			if (l > 0) {
				if (input[2] == 'j') { // pswj
					print_json_string (core, (const char *) core->block, len, "wide");
				} else {
					r_print_string (core->print, core->addr, core->block, len,
						R_PRINT_STRING_WIDE | R_PRINT_STRING_ZEROEND);
				}
			}
			break;
		case 'W': // "psW"
			if (l > 0) {
				if (input[2] == 'j') { // psWj
					print_json_string (core, (const char *) core->block, len, "wide32");
				} else {
					r_print_string (core->print, core->addr, core->block, len,
						R_PRINT_STRING_WIDE32 | R_PRINT_STRING_ZEROEND);
				}
			}
			break;
		case 'j': // "psj"
			{
				ut8 *s = decode_text (core, core->addr, l, false);
				print_json_string (core, (const char *) s, l, NULL);
				free (s);
			}
			break;
		case ' ': // "ps"
		{
			ut8 *s = decode_text (core, core->addr, l, false);
			r_print_string (core->print, core->addr, s, l, 0);
			free (s);
			break;
		}
		case 'u': // "psu"
			if (l > 0) {
				bool json = input[2] == 'j'; // "psuj"
				if (input[2] == 'z') { // "psuz"
					int i, z;
					const char* p = (const char *) core->block;
					for (i = 0, z = 0; i < len; i++) {
						// looking for double zeros '\0\0'.
						if (!p[i] && !z) z = 1;
						else if (!p[i] && z) {
							len = i - 1;
							break;
						}
					}
					json = input[3] == 'j'; // "psuzj"
				}
				if (json) { // psuj
					print_json_string (core, (const char *) core->block, len, "utf16");
				} else {
					char *str = r_str_utf16_encode ((const char *) core->block, len);
					r_cons_println (core->cons, str);
					free (str);
				}
			}
			break;
		case 'q': // "psq"
			r_core_cmd0 (core, "pqs");
			break;
		case 's': // "pss"
			if (l > 0) {
				int h, w = r_cons_get_size (core->cons, &h);
				int colwidth = r_config_get_i (core->config, "hex.cols") * 2;
				core->print->width = (colwidth == 32)?w: colwidth; // w;
				int bs = core->blocksize;
				if (len == bs) {
					len = (h * w) / 3;
					r_core_block_size (core, len);
				}
				r_print_string (core->print, core->addr, core->block,
						len, R_PRINT_STRING_WRAP);
				r_core_block_size (core, bs);
			}
			break;
		case '+': // "ps+"
			if (l > 0) {
				const bool json = input[2] == 'j'; // ps+j
				ut64 bitness = r_config_get_i (core->config, "asm.bits");
				if (bitness != 32 && bitness != 64) {
					R_LOG_ERROR ("bitness of %" PFMT64u " not supported", bitness);
					break;
				}
				if (*core->block & 0x1) { // "long" string
					if (bitness == 64) {
						r_core_cmdf (core, "ps%c @ 0x%" PFMT64x, json ? 'j' : ' ', *((ut64 *)core->block + 2));
					} else {
						r_core_cmdf (core, "ps%c @ 0x%" PFMT32x, json ? 'j' : ' ', *((ut32 *)core->block + 2));
					}
				} else if (json) {
					print_json_string (core, (const char *) core->block + 1, len, NULL);
				} else {
					r_print_string (core->print, core->addr, core->block + 1,
						len, R_PRINT_STRING_ZEROEND);
				}
			}
			break;
		default: // "ps"
			{
				const char *current_charset = r_config_get (core->config, "cfg.charset");
				if (R_STR_ISEMPTY (current_charset)) {
					r_print_string (core->print, core->addr, core->block, len, R_PRINT_STRING_ZEROEND | R_PRINT_STRING_ONLY_PRINTABLE);
				} else {
					if (len > 0) {
						size_t out_len = len * 10;
						ut8 *out = calloc (len, 10);
						if (out) {
							ut8 *data = malloc (len);
							if (data) {
								r_io_read_at (core->io, core->addr, data, len);
								(void)r_charset_encode_str (core->print->charset, out, out_len, data, len, true);
								r_print_string (core->print, core->addr,
									out, len, R_PRINT_STRING_ZEROEND);
								free (data);
							}
							free (out);
						}
					}
				}
				break;
			}
		}
		break;
	case 'm': // "pm"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_pm);
		} else if (input[1] == 'j') { // "pmj"
			const char *filename = r_str_trim_head_ro (input + 2);
			PJ *pj = r_core_pj_new (core);
			r_core_magic (core, filename, true, pj);
			r_cons_println (core->cons, pj_string (pj));
			pj_free (pj);
		} else {
			// XXX: need cmd_magic header for r_core_magic
			const char *filename = r_str_trim_head_ro (input + 1);
			r_core_magic (core, filename, true, NULL);
		}
		break;
	case 'u': // "pu"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_p, "pu");
		} else {
			if (l > 0) {
				r_print_string (core->print, core->addr, core->block, len,
					R_PRINT_STRING_URLENCODE |
					((input[1] == 'w')? R_PRINT_STRING_WIDE: 0));
			}
		}
		break;
	case 'c': // "pc"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_pc);
		} else if (l) {
			const ut8 *buf = core->block;
			int i = 0;
			int j = 0;
			if (input[1] == 'A') { // "pcA"
				r_cons_printf ("sub_0x%08"PFMT64x ":\n", core->addr);
				for (i = 0; i < len; i++) {
					RAnalOp asmop = {
						0
					};
					(void) r_asm_disassemble (core->rasm, &asmop, buf + i, len - i);
					int sz = asmop.size;
					if (sz < 1) {
						sz = 1;
					}
					r_cons_printf (" .byte ");
					for (j = 0; j < sz; j++) {
						r_cons_printf ("%s0x%02x", j? ", ": "", buf[i]);
						i++;
					}
					r_cons_printf ("  // %s\n", asmop.mnemonic);
					i--;
					r_asm_op_fini (&asmop);
				}
				r_cons_printf (".equ shellcode_len, %d\n", len);
			} else {
				r_print_code (core->print, core->addr, core->block, len, input[1]);
			}
		}
		break;
	case 'C': // "pC"
		switch (input[1]) {
		case 0:
			cmd_pCd (core, "");
			break;
		case ' ':
		case 'd': // "pCd"
			cmd_pCd (core, input + 2);
			break;
		case 'D': // "pCD"
			cmd_pCD (core, input + 2);
			break;
		case 'a': // "pCa"
			cmd_pCx (core, input + 2, "pxa");
			break;
		case 'A': // pCA"
			cmd_pCx (core, input + 2, "pxA");
			break;
		case 'x': // "pCx"
			cmd_pCx (core, input + 2, "px");
			break;
		case 'w': // "pCw"
			cmd_pCx (core, input + 2, "pxw");
			break;
		case 'c': // "pCc"
			cmd_pCx (core, input + 2, "pc");
			break;
		default:
			r_core_cmd_help_match (core, help_msg_p, "pC");
			break;
		}
		break;
	case 'r': // "pr"
		switch (input[1]) {
		case 'i':
			cmd_pri (core, input);
			break;
		case 'c': // "prc" // color raw dump
			switch (input[2]) {
			case '?':
				// TODO: change =e to colorized =mode
				R_LOG_INFO ("See pz? and p=?");
				// TODO: replace pz? help text with "See also"
				r_core_cmd_help (core, help_msg_prc);
				break;
			case '=': // "prc="
				if (input[3] == '?') {
					r_core_cmd_help (core, help_msg_p_equal);
				} else {
					cmd_prc_zoom (core, input + 2);
				}
				break;
			case 'b': // "prcb"
				cmd_prcn (core, block, len, true);
				break;
			case 'n': // "prcn"
				cmd_prcn (core, block, len, false);
				break;
			default:
				cmd_prc (core, block, len);
				break;
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_pr);
			break;
		case 'g': // "prg" // gunzip
			switch (input[2]) {
			default:
			case '?':
				r_core_cmd_help (core, help_msg_prg);
				break;
			case 'l': // "prgl" // lz4
				{
					ut8 *dst = calloc (len, 4);
					if (dst) {
						// TODO. hack into lz4 to make it work without knowing the input
						int consumed = 0;
						int olen = 0;
						ut8 *obuf = r_inflate_lz4 (core->block, len, &consumed, &olen);
						if (obuf) {
							for (i = 0; i < olen; i += 32) {
								int left = R_MIN (olen - i, 32);
								r_cons_printf ("wx+");
								r_print_bytes (core->print, obuf + i, left, "%02x", 0);
							}
						} else {
							R_LOG_ERROR ("Invalid input size %d", olen);
						}
						free (dst);
					}
				}
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
			case 0:
			case ' ':
			{
				int outlen = 0;
				ut8 *out;
				out = r_inflate (block, core->blocksize, NULL, &outlen);
				if (out) {
					r_cons_write (core->cons, (const char *) out, outlen);
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
#if 0
			if (l != 0) {
				printraw (core, len, 2);
			}
#else
			{
				int a = r_config_get_i (core->config, "hex.bytes");
				r_config_set_i (core->config, "hex.bytes", false);
				r_core_cmdf (core, "px%s", input + 1);
				r_config_set_i (core->config, "hex.bytes", a);
			}
#endif
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
			r_core_cmd_help_match (core, help_msg_p, "p3");
		} else if (input[1] == ' ') {
			char *data = r_file_slurp (input + 2, NULL);
			if (!data) {
				R_LOG_ERROR ("Could not open '%s'", input + 2);
				break;
			}
			char *res = r_print_stereogram (data, 78, 20);
			char *out = r_print_stereogram_render (core->print, res);
			r_cons_println (core->cons, out);
			free (out);
			free (res);
			free (data);
		} else {
			char *res = r_print_stereogram_bytes (block, core->blocksize);
			char *out = r_print_stereogram_render (core->print, res);
			r_cons_println (core->cons, out);
			free (out);
			free (res);
		}
		break;
	case 'y': // "py"
		switch (input[1]) {
		case '?':
			r_core_cmd_help_contains (core, help_msg_p, "py");
			break;
		case '-':
			if (r_config_get_b (core->config, "scr.interactive")) {
				int sz;
				char *data = r_stdin_slurp (&sz);
				if (data) {
					const char *const fn = ".tmp.py";
					r_file_dump (fn, (ut8*)data, sz, false);
					r_core_cmd_callf (core, ". %s", fn);
					r_file_rm (fn);
					free (data);
				}
			} else {
				R_LOG_ERROR ("requires interactive shell");
			}
			break;
		case ':':
			r_core_cmd_callf (core, "#!python %s", input + 2);
			break;
		case ' ':
			{
				char *data = (char *)r_str_trim_head_ro (input + 2);
				int sz = strlen (data);
				if (R_STR_ISNOTEMPTY (data)) {
					const char *const fn = ".tmp.py";
					if (r_file_dump (fn, (ut8*)data, sz, false)) {
						r_core_cmd_callf (core, ". %s", fn);
					}
					r_file_rm (fn);
				}
			}
			break;
		case 0:
			r_core_cmd_call (core, "yp");
			break;
		}
		break;
	case 'o': // "po"
		cmd_print_op (core, input);
		break;
	case 'x': // "px"
		if (input[1] == '-' && input[2] == '-') {
			int rowsize = r_config_get_i (core->config, "hex.cols");
			int ctxlines = r_num_math (core->num, input + 3);
			if (ctxlines < 0) {
				ctxlines = 0;
			}
			int size = rowsize + (rowsize * ctxlines * 2);
			ut64 addr = core->addr - (rowsize * ctxlines);
			r_core_cmdf (core, "px %d@0x%08"PFMT64x, size, addr);
			break;
		} else {
			bool show_offset = r_config_get_i (core->config, "hex.addr");
			if (show_offset) {
				core->print->flags |= R_PRINT_FLAGS_OFFSET;
			} else {
				core->print->flags &= ~R_PRINT_FLAGS_OFFSET;
			}
			int show_header = r_config_get_i (core->config, "hex.header");
			if (show_header) {
				core->print->flags |= R_PRINT_FLAGS_HEADER;
			} else {
				core->print->flags &= ~R_PRINT_FLAGS_HEADER;
			}
			/* Don't show comments in default case */
			core->print->use_comments = false;
		}
		r_cons_break_push (core->cons, NULL, NULL);
		switch (input[1]) {
		case 'j': // "pxj"
			if (len < core->blocksize) {
				r_print_jsondump (core->print, core->block, R_MIN (core->blocksize, len), 8);
			} else {
				ut8 *data = malloc (len + 1);
				if (data) {
					memset (data, core->io->Oxff, len + 1);
					r_io_read_at (core->io, core->addr, data, len);
					r_print_jsondump (core->print, data, len, 8);
					free (data);
				}
			}
			break;
		case '*': // "px*"
			r_core_cmd0 (core, "pc*");
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
				r_print_bytes (core->print, core->block, len, "%02x", 0);
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
				r_print_hexdump (core->print, core->addr,
					core->block, len, 8, 1, 1);
				core->print->flags &= ~R_PRINT_FLAGS_NONHEX;
			}
			break;
		case 'X': // "pxX"
			if (l != 0) {
				ut8 *buf = calloc (len, 4);
				if (buf) {
					r_io_read_at (core->io, core->addr, buf, len * 4);
					core->print->flags |= R_PRINT_FLAGS_NONHEX;
					r_print_hexdump (core->print, core->addr, buf, len * 4, 8, 1, 1);
					core->print->flags &= ~R_PRINT_FLAGS_NONHEX;
					free (buf);
				}
			}
			break;
		case 'A': // "pxA"
			if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_pxA);
			} else if (l) {
				cmd_print_pxA (core, len, input + 2);
			}
			break;
		case 'b': // "pxb"
		case 'B': // "pxB"
			if (l) {
				cmd_print_pxb (core, len, input);
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
					r_core_block_size (core, len);
					len = core->blocksize;
					r_print_hexdump (core->print, core->addr,
						core->block, core->blocksize, 16, 1, 1);
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
				core->print->show_offset = r_config_get_i (core->config, "hex.addr");
				r_print_hexii (core->print, core->addr, core->block,
					core->blocksize, r_config_get_i (core->config, "hex.cols"));
			}
			break;
		case 'o': // "pxo"
			if (l != 0) {
				r_print_hexdump (core->print, core->addr,
					core->block, len, 8, 1, 1);
			}
			break;
		case 't': // "pxt"
			{
			ut64 origin = core->addr;
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
				_pointer_table (core, origin, core->addr, block, len, 4, input[2]);
				free (block);
			}
			}
			break;
		case 'u': // "pxu" // unsigned numbers
		case 'd': // "pxd" // signed numbers
			if (input[2] == '?') {
				if (input[1] == 'u') {
					r_core_cmd_help (core, help_msg_pxu);
				} else {
					r_core_cmd_help (core, help_msg_pxd);
				}
			} else if (l != 0) {
				switch (input[2]) {
				case '1': // "pxd1"
					// 1 byte signed words (byte)
					if (input[3] == 'j') {
						r_print_jsondump (core->print, core->block, len, 8);
					} else {
						const int nfmt = (input[1] == 'u')? -2: -1;
						r_print_hexdump (core->print, core->addr,
								 core->block, len, nfmt, 4, 1);
					}
					break;
				case '2': // "pxd2"
					// 2 byte signed words (short)
					if (input[3] == 'j') {
						r_print_jsondump (core->print, core->block,
							len, 16);
					} else {
						const int nfmt = (input[1] == 'u')? -11: -10;
						r_print_hexdump (core->print, core->addr,
								 core->block, len, nfmt, 2, 1);
					}
					break;
				case '8':
					if (input[3] == 'j') {
						r_print_jsondump (core->print, core->block,
							len, 64);
					} else {
						const int nfmt = (input[1] == 'u')? -9: -8;
						r_print_hexdump (core->print, core->addr,
								 core->block, len, nfmt, 4, 1);
					}
					break;
				case '4':
				case ' ':
				case 'j':
				case 0:
					// 4 byte signed words
					if (input[2] == 'j' || (input[2] && input[3] == 'j')) {
						r_print_jsondump (core->print, core->block,
							len, 32);
					} else {
						const int nfmt = (input[1] == 'u')? 11: 10;
						r_print_hexdump (core->print, core->addr,
								 core->block, len, nfmt, 4, 1);
					}
					break;
				default:
					r_core_cmd_help (core, help_msg_pxd);
					break;
				}
			}
			break;
		case '3': // "px3"
			if (l != 0) {
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 24);
				} else {
					r_print_hexdump (core->print, core->addr, core->block, len, 48, 3, 1);
				}
			}
			break;
		case 'w': // "pxw"
			if (l != 0) {
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 32);
				} else {
					r_print_hexdump (core->print, core->addr, core->block, len, 32, 4, 1);
				}
			}
			break;
		case 'W': // "pxW"
			if (l) {
				bool printOffset = (input[2] != 'q' && r_config_get_i (core->config, "hex.addr"));
				bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->print->config);
				len = len - (len % 4);
				for (i = 0; i < len; i += 4) {
					const char *a, *b;
					char *fn;
					RPrint *p = core->print;
					RFlagItem *f;
					ut32 v = r_read_ble32 (core->block + i, be);
					if (p && p->colorfor) {
						a = p->colorfor (p->user, core->addr + i, v, true);
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
						st64 delta = (v - f->addr);
						if (delta >= 0 && delta < 8192) {
							if (v == f->addr) {
								fn = strdup (f->name);
							} else {
								fn = r_str_newf ("%s+%" PFMT64d,
									f->name, v - f->addr);
							}
						}
					}
					if (printOffset) {
						r_print_section (core->print, core->addr +i);
						r_cons_printf ("0x%08"PFMT64x " %s0x%08"PFMT64x "%s%s%s\n",
								(ut64) core->addr + i, a, (ut64) v,
								b, fn? " ": "", r_str_get (fn));
					} else {
						r_cons_printf ("%s0x%08"PFMT64x "%s\n", a, (ut64) v, b);
					}
					free (fn);
				}
			}
			break;
		case 'r': // "pxr"
			if (l) {
				int mode = input[2];
				int wordsize = core->anal->config->bits / 8;
				if (mode == '?') {
					r_core_cmd_help_contains (core, help_msg_px, "pxr");
					break;
				}
				if (mode && isdigit (mode)) {
					char tmp[2] = {input[2], 0};
					wordsize = atoi (tmp);
					mode = input[3];
				}
				switch (wordsize) {
				case 1:
				case 2:
				case 4:
				case 8:
					cmd_pxr (core, len, mode, wordsize, mode? strchr (input, mode): NULL);
					break;
				default:
					R_LOG_ERROR ("Invalid word size. Use 1, 2, 4 or 8");
					break;
				}
			}
			break;
		case 'h': // "pxh"
			if (l) {
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 16);
				} else {
					r_print_hexdump (core->print, core->addr,
						core->block, len, 32, 2, 1);
				}
			}
			break;
		case 'H': // "pxH"
			if (l != 0) {
				const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
				len = len - (len % 2);
				for (i = 0; i < len; i += 2) {
					const char *a, *b;
					char *fn;
					RPrint *p = core->print;
					RFlagItem *f;
					ut64 v = (ut64) r_read_ble16 (core->block + i, be);
					if (p && p->colorfor) {
						a = p->colorfor (p->user, core->addr + i, v, true);
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
						st64 delta = (v - f->addr);
						if (delta >= 0 && delta < 8192) {
							if (v == f->addr) {
								fn = strdup (f->name);
							} else {
								fn = r_str_newf ("%s+%"PFMT64d, f->name, v - f->addr);
							}
						}
					}
					r_cons_printf ("0x%08"PFMT64x " %s0x%04"PFMT64x "%s %s\n",
						(ut64) core->addr + i, a, v, b, r_str_get (fn));
					free (fn);
				}
			}
			break;
		case 'q': // "pxq"
			if (l) {
				int bs = core->blocksize;
				if (r_core_block_size (core, len)) {
					r_core_block_read (core);
				}
				if (input[2] == 'j') {
					r_print_jsondump (core->print, core->block, len, 64);
				} else {
					r_print_hexdump (core->print, core->addr, core->block, len, 64, 8, 1);
				}
				if (bs != core->blocksize) {
					r_core_block_size (core, bs);
				}
			}
			break;
		case 'Q': // "pxQ"
			// TODO. show if flag name, or inside function
			if (l) {
				bool printOffset = (input[2] != 'q' && r_config_get_i (core->config, "hex.addr"));
				const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
				len = len - (len % 8);
				for (i = 0; i < len; i += 8) {
					const char *a, *b;
					char *fn;
					RPrint *p = core->print;
					RFlagItem *f;
					ut64 v = r_read_ble64 (core->block + i, be);
					if (p && p->colorfor) {
						a = p->colorfor (p->user, core->addr + i, v, true);
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
						st64 delta = (v - f->addr);
						if (delta >= 0 && delta < 8192) {
							if (v == f->addr) {
								fn = strdup (f->name);
							} else {
								fn = r_str_newf ("%s+%" PFMT64d, f->name, v - f->addr);
							}
						}
					}
					if (printOffset) {
						r_print_section (core->print, core->addr +i);
						r_cons_printf ("0x%08"PFMT64x " %s0x%016"PFMT64x "%s %s\n",
								(ut64) core->addr + i, a, v, b, r_str_get (fn));
					} else {
						r_cons_printf ("%s0x%016"PFMT64x "%s\n", a, v, b);
					}
					free (fn);
				}
			}
			break;
		case 's': // "pxs"
			if (l) {
				core->print->flags |= R_PRINT_FLAGS_SPARSE;
				r_print_hexdump (core->print, core->addr, core->block, len, 16, 1, 1);
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
					r_print_addr (core->print, core->addr + i);
					for (j = i; j < i + cols; j += 1) {
						ut8 *p = (ut8 *) core->block + j;
						if (j < len) {
							r_cons_printf ("\xf0\x9f%c%c ", emoji[*p * 2], emoji[*p * 2 + 1]);
						} else {
							r_kons_print (core->cons, "  ");
						}
					}
					r_kons_print (core->cons, " ");
					for (j = i; j < len && j < i + cols; j += 1) {
						ut8 *p = (ut8 *) core->block + j;
						r_print_byte (core->print, core->addr + j, "%c", j, *p);
					}
					r_cons_newline (core->cons);
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
					const char *sp = NULL;
					if (input[1] == '.') {
						sp = input + 2;
					}
					if (isdigit (input[1])) {
						sp = input + 1;
					}
					if (sp) {
						int n = (int) r_num_math (core->num, r_str_trim_head_ro (sp));
						if (!n) {
							goto beach;
						}
						len = n;
					}
					if (!r_core_block_size (core, len)) {
						len = core->blocksize;
					}
					r_core_block_read (core);
					r_print_hexdump (core->print, r_core_pava (core, core->addr),
						core->block, len, 16, 1, 1);
				} else {
					r_core_print_cmp (core, from, to);
				}
				core->num->value = len;
			}
			break;
		}
		r_cons_break_pop (core->cons);
		break;
	case '2': // "p2"
		if (l) {
			if (input[1] == '?') {
				r_core_cmd_help_match (core, help_msg_p, "p2");
			} else {
				RConsContext *c = core->cons->context;
				const char **colors = (const char *[]) {
					c->pal.mov, //black
					c->pal.nop, //dark
					c->pal.cmp, //light
					c->pal.jmp, //white
				};
				const int cols = r_config_get_i (core->config, "hex.cols");
				r_print_2bpp_tiles (core->print, core->block, len - 1, cols / 4, colors);
			}
		}
		break;
	case '6': // "p6"
		if (1) {
			int malen = (core->blocksize * 4) + 1;
			ut8 *buf = malloc (malen);
			if (!buf) {
				break;
			}
			memset (buf, 0, malen);
			switch (input[1]) {
			case 'd': // "p6d"
				switch (input[2]) {
				case '?':
					r_core_cmd_help_match (core, help_msg_p6, "p6d");
					break;
				case 's': // "p6ds"
					if (input[3] == '?') {
						r_core_cmd_help_match (core, help_msg_p6, "p6ds");
					} else {
						char *a = r_str_trim_dup (input + 3);
						char *out = malloc ((4 + strlen (a)) * 4);
						if (r_base64_decode ((ut8 *)out,(const char *) a, strlen (a))) {
							r_cons_println (core->cons, (const char *) out);
						} else {
							R_LOG_ERROR ("r_base64_decode: invalid stream");
						}
						free (a);
						free (out);
					}
					break;
				case 'z': // "p6dz"
					if (input[3] == '?') {
						r_core_cmd_help_match (core, help_msg_p6, "p6dz");
					} else {
						len = r_str_nlen ((const char *)block, len);
						if (r_base64_decode (buf, (const char *) block, len)) {
							r_cons_println (core->cons, (const char *) buf);
						} else {
							R_LOG_ERROR ("r_base64_decode: invalid stream");
						}
						r_cons_println (core->cons, (const char *) buf);
					}
					break;
				default:
					len = len > core->blocksize? core->blocksize: len;
					if (r_base64_decode (buf, (const char *) block, len)) {
						r_cons_println (core->cons, (const char *) buf);
					} else {
						R_LOG_ERROR ("r_base64_decode: invalid stream");
					}
					break;
				}
				break;
			case 'e': // "p6e"
				switch (input[2]) {
				case '?':
					r_core_cmd_help_match (core, help_msg_p6, "p6e");
					break;
				case 's': // "p6es"
					if (input[3] == '?') {
						r_core_cmd_help_match (core, help_msg_p6, "p6es");
					} else {
						char *a = r_str_trim_dup (input + 3);
						char *out = calloc ((4 + strlen (a)), 4);
						r_base64_encode ((char *) out, (const ut8*)a, strlen (a));
						r_cons_println (core->cons, (const char *) out);
						free (a);
						free (out);
					}
					break;
				case 'z': // "p6ez"
					if (input[3] == '?') {
						r_core_cmd_help_match (core, help_msg_p6, "p6ez");
					} else {
						len = r_str_nlen ((const char *)block, len);
						r_base64_encode ((char *) buf, block, len);
						r_cons_println (core->cons, (const char *) buf);
					}
					break;
				default:
					len = len > core->blocksize? core->blocksize: len;
					r_base64_encode ((char *) buf, block, len);
					r_cons_println (core->cons, (const char *) buf);
					break;
				}
				break;
			case '?':
			default:
				r_core_cmd_help (core, help_msg_p6);
				break;
			}
			free (buf);
		}
		break;
	case '8': // "p8"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_p8);
		} else if (l) {
			bool rad = strchr (input, '*');
			if (!r_core_block_size (core, len)) {
				len = core->blocksize;
			}
			if (input[1] == 'j') { // "p8j"
				r_core_cmdf (core, "pcj %s", input + 2);
			} else if (input[1] == 's') { // "p8s"
				r_core_block_read (core);
				block = core->block;
				r_print_bytes (core->print, block, l, "%02x", ' ');
			} else if (input[1] == ',') { // "p8,"
				r_core_block_read (core);
				block = core->block;
				r_print_bytes (core->print, block, l, "%02x", ',');
			} else if (input[1] == 'x') { // "p8x"
				r_core_block_read (core);
				block = core->block;
				int cols = r_config_get_i (core->config, "hex.cols");
				if (cols < 1) {
					cols = 1;
				}
				int i;
				for (i = 0; i < len; i += cols) {
					if (rad) {
						r_kons_printf (core->cons, "wx+ ");
					}
					r_print_bytes (core->print, block + i, R_MIN (cols, len - cols), "%02x", 0);
				}
			} else if (input[1] == 'd') { // "p8d"
				int i;
				for (i = 0; i < len; i ++) {
					r_kons_printf (core->cons, "%d ", block[i]);
				}
				r_cons_newline (core->cons);
			} else if (input[1] == 'b') { // "p8b"
				r_core_cmdf (core, "p8 $BS @ $BB");
			} else if (input[1] == 'f') { // "p8f"
				ut64 at = core->addr;
				switch (input[2]) {
				case 'm':
					p8fm (core, at, input[3]);
					break;
				case 'j':
				case 0:
					if (r_anal_get_function_at (core->anal, at)) {
						r_core_cmdf (core, "p8%c $FS @ $FB", input[2]);
					} else {
						R_LOG_ERROR ("Cannot find function here");
					}
					break;
				case '?':
					r_core_cmd_help_contains (core, help_msg_p8, "p8f");
					break;
				default:
					r_core_return_invalid_command (core, "p8f", input[2]);
					break;
				}
			} else {
				r_core_block_read (core);
				block = core->block;
				if (rad) {
					r_kons_printf (core->cons, "wx+ ");
				}
				r_print_bytes (core->print, block, len, "%02x", 0);
			}
		}
		break;
	case 'g': // "pg"
		cmd_print_gadget (core, input + 1);
		break;
	case 'f': // "pf"
		cmd_print_format (core, input, block, len);
		break;
	case 'F': // "pF"
		cmd_print_fromage (core, input + 1, block, len);
		break;
	case 'k': // "pk"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_p, "pk");
		} else if (r_str_startswith (input, "kill")) {
			RListIter *iter;
			RDebugPid *pid;
			const char *arg = strchr (input, ' ');
			RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
			if (plugin && plugin->pids) {
				RList *pids = plugin->pids (core->dbg, 0);
				if (pids && R_STR_ISNOTEMPTY (arg)) {
					arg++;
					r_list_foreach (pids, iter, pid) {
						if (strstr (pid->path, arg)) {
							r_cons_printf ("dk 9 %d\n", pid->pid);
						}
						// r_debug_kill (core->dbg, pid->pid, pid->pid, 9); // kill -9
					}
				}
				r_list_free (pids);
			}
		} else if (l > 0) {
			len = len > core->blocksize? core->blocksize: len;
			char *s = r_print_randomart (block, len, core->addr);
			r_cons_println (core->cons, s);
			free (s);
		}
		break;
	case 'K': // "pK"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_p, "pK");
		} else if (l > 0) {
			len = len > core->blocksize? core->blocksize: len;
			int w, h;
			RConsCanvas *c;
			w = r_cons_get_size (core->cons, &h);
			ut64 offset0 = core->addr;
			int cols = (w / 20);
			int rows = (h / 12);
			int i, j;
			char *s;
			if (rows < 1) {
				rows = 1;
			}
			int flags = r_cons_canvas_flags (core->cons);
			c = r_cons_canvas_new (core->cons, w, rows * 11, flags);
			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					r_cons_canvas_gotoxy (c, j * 20, i * 11);
					core->addr += len;
					r_io_read_at (core->io, core->addr, core->block, len);
					s = r_print_randomart (core->block, len, core->addr);
					r_cons_canvas_write (c, s);
					free (s);
				}
			}
			r_cons_canvas_print (c);
			r_cons_canvas_free (c);
			r_io_read_at (core->io, offset0, core->block, len);
			core->addr = offset0;
			r_cons_printf ("\n");
		}
		break;
	case 'n': // easter
		R_LOG_ERROR ("easter egg license has expired");
		break;
	case 'l': // "pl"
		r_print_list (core, r_str_trim_head_ro (input + 1));
		break;
	case 't': // "pt"
		switch (input[1]) {
		case '.': // "pt." same as "date"
			{
				char *nostr = r_time_secs_tostring (r_time_today ());
				r_cons_println (core->cons, nostr);
				free (nostr);
			}
			break;
		case ' ':
		case '\0':
#if 0
			// len must be multiple of 4 since r_mem_copyendian move data in fours - sizeof (ut32)
			if (len < sizeof (ut32)) {
				R_LOG_WARN ("You should change the block size: b %d", (int) sizeof (ut32));
			}
			if (len % sizeof (ut32)) {
				len = len - (len % sizeof (ut32));
			}
			for (l = 0; l < len; l += sizeof (ut32)) {
				r_print_date_unix (core->print, block + l, sizeof (ut32));
			}
#else
			if (len < sizeof (ut32)) {
				R_LOG_WARN ("You should change the block size: b %d", (int) sizeof (ut32));
			} else {
				RPrint *p = core->print;
				const bool be = (p && p->config)? R_ARCH_CONFIG_IS_BIG_ENDIAN (p->config): R_SYS_ENDIAN;
				for (l = 0; l + sizeof (ut32) <= len; l += sizeof (ut32)) {
					ut32 hnxts = r_read_ble32 (block + l, be);
					ut64 ts = r_time_unix_today (hnxts, p->datezone);
					char *s = r_time_secs_tostring (ts);
					r_cons_printf ("%s\n", s);
					free (s);
				}
			}
#endif
			break;
		case 'h': // "pth"
#if 1
			// len must be multiple of 4 since r_mem_copyendian move data in fours - sizeof (ut32)
			if (len < sizeof (ut32)) {
				R_LOG_WARN ("We need at least 4 bytes");
			} else {
				RPrint *p = core->print;
				const bool be = (p && p->config)? R_ARCH_CONFIG_IS_BIG_ENDIAN (p->config): R_SYS_ENDIAN;
				for (l = 0; l + sizeof (ut32) <= len; l += sizeof (ut32)) {
					ut32 hfsts = r_read_ble32 (block + l, be);
					ut64 ts = r_time_hfs_today (hfsts, p->datezone);
					char *s = r_time_secs_tostring (ts);
					r_cons_printf ("%s\n", s);
					free (s);
				}
			}
#else
			// len must be multiple of 4 since r_mem_copyendian move data in fours - sizeof (ut32)
			if (len < sizeof (ut32)) {
				R_LOG_WARN ("Change the block size: b %d", (int) sizeof (ut32));
			}
			for (l = 0; l < len; l += sizeof (ut32)) {
				r_print_date_hfs (core->print, block + l, sizeof (ut32));
			}
#endif
			break;
		case 'b': // "ptb"
			if (len < sizeof (ut32)) {
				R_LOG_WARN ("Change the block size: b %d", (int) sizeof (ut32));
			}
			if (len % sizeof (ut32)) {
				len = len - (len % sizeof (ut32));
			}
			for (l = 0; l < len; l += sizeof (ut64)) {
				ut64 ts = r_read_le64 (block + l);
				int sb, beats = r_time_beats (ts, &sb);
				r_cons_printf ("@%03d.%d\n", beats, sb);
			}
			break;
		case 'd': // "ptd"
			// len must be multiple of 4 since r_print_date_dos read buf+3
			// if block size is 1 or 5 for example it reads beyond the buffer
			if (len < sizeof (ut32)) {
				R_LOG_WARN ("Change the block size: b %d", (int) sizeof (ut32));
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
				R_LOG_WARN ("Change the block size: b %d", (int) sizeof (ut64));
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
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_pq);
			len = 0;
			break;
		case 's': // "pqs" // TODO pqs or pqz or pq0 :D
		case 'z': // for backward compat
			len = r_str_nlen ((const char *)block, core->blocksize);
			break;
		default:
			if (len < 1) {
				len = 0;
			}
			if (len > core->blocksize) {
				len = core->blocksize;
			}
			break;
		}
		if (len > 0) {
			bool inverted = (input[1] == 'i'); // pqi -- inverted colors
			char *res = r_qrcode_gen (block, len, r_config_get_i (core->config, "scr.utf8"), inverted);
			if (res) {
				r_cons_printf ("%s\n", res);
				free (res);
			}
		}
		break;
	case 'z': // "pz"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_pz);
		} else {
			RIOMap* map;
			RListIter *iter;
			RList *list = r_core_get_boundaries_prot (core, -1, NULL, "zoom");
			if (list && r_list_length (list) > 0) {
				RListIter *iter1 = list->head;
				RIOMap* map1 = iter1->data;
				from = map1->itv.addr;
				r_list_foreach (list, iter, map) {
					to = r_io_map_end (map);
				}
			} else {
				from = core->addr;
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
					do_zoom = false;
				}
			}
			if (do_zoom && l > 0) {
				r_print_zoom (core->print, printzoomcallback, core,
					from, to, l, (int) maxsize);
			}
			if (oldmode) {
				r_config_set (core->config, "zoom.byte", oldmode);
			}
			core->io->va = oldva;
			R_FREE (oldmode);
			r_list_free (list);
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_p);
		break;
	default:
		if (*input && input[1] == 'j') {
			r_core_cmd_help_json (core, help_msg_p);
		} else {
			r_core_return_invalid_command (core, "p", ch0);
		}
		break;
	}
beach:
	if (myblock) {
		free (block);
	}
	if (tmpseek != UT64_MAX && tmpseek != core->addr) {
		r_core_seek (core, tmpseek, SEEK_SET);
		r_core_block_read (core);
	}
	if (tbs != core->blocksize) {
		r_core_block_size (core, tbs);
	}
	return ret;
}

static int cmd_hexdump(void *data, const char *input) {
	char *pcmd = r_str_newf ("x%s", input);
	int rc = cmd_print (data, pcmd);
	free (pcmd);
	return rc;
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

// R2_600 - TODO: move into util/print.c
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int delta, const char *label) {
	int offdec = (p->flags & R_PRINT_FLAGS_ADDRDEC) != 0;
	const int segbas = p->config->segbas;
	const int seggrn = p->config->seggrn;
	const int offseg = (p->flags & R_PRINT_FLAGS_SEGOFF) != 0;
#if R2_590
	const bool base36 = p->config->base36;
#else
	RCore *core = p->user;
	const bool base36 = r_config_get_b (core->config, "asm.addr.base36");
#endif
	char space[32] = {
		0
	};
	const char *reset = p->resetbg? Color_RESET: Color_RESET_NOBG;
	bool show_color = p->flags & R_PRINT_FLAGS_COLOR;
	if (show_color) {
		char rgbstr[32];
		const char *k = core->cons->context->pal.addr; // TODO etooslow. must cache
		const char *inv = invert ? R_CONS_INVERT (true, true) : "";
		if (p->flags & R_PRINT_FLAGS_RAINBOW) {
			k = r_cons_rgb_str_off (core->cons, rgbstr, sizeof (rgbstr), off);
		}
		if (!k) {
			k = "";
		}
		if (base36) {
			char b36str[16];
			b36_fromnum (b36str, off);
			r_cons_printf ("%s%s%s%s", k, inv, b36str, reset);
		} else if (offseg) {
			ut32 s, a;
			r_num_segaddr (off, segbas, seggrn, &s, &a);
			if (offdec) {
				snprintf (space, sizeof (space), "%d:%d", s, a);
				r_cons_printf ("%s%s%9s%s", k, inv, space, reset);
			} else {
				r_cons_printf ("%s%s%04x:%04x%s", k, inv, s, a, reset);
			}
		} else {
			int sz = lenof (off, 0);
			int sz2 = lenof (delta, 1);
			if (delta > 0 || label) {
				if (label) {
					const int label_padding = 10;
					if (delta > 0) {
						const char *pad = r_str_pad (' ', sz - sz2 + label_padding);
						if (offdec) {
							r_cons_printf ("%s%s%s%s+%d%s", k, inv, label, reset, delta, pad);
						} else {
							r_cons_printf ("%s%s%s%s+0x%x%s", k, inv, label, reset, delta, pad);
						}
					} else {
						const char *pad = r_str_pad (' ', sz + label_padding);
						r_cons_printf ("%s%s%s%s%s", k, inv, label, reset, pad);
					}
				} else {
					const char *pad = r_str_pad (' ', sz - sz2);
					if (offdec) {
						r_cons_printf ("%s+%d%s", pad, delta, reset);
					} else {
						r_cons_printf ("%s+0x%x%s", pad, delta, reset);
					}
				}
			} else {
				if (offdec) {
					snprintf (space, sizeof (space), "%"PFMT64u, off);
					r_cons_printf ("%s%s%10s%s", k, inv, space, reset);
				} else {
					if (p->wide_offsets) {
						r_cons_printf ("%s%s0x%016"PFMT64x "%s", k, inv, off, reset);
					} else {
						r_cons_printf ("%s%s0x%08"PFMT64x "%s", k, inv, off, reset);
					}
				}
			}
		}
		r_kons_print (core->cons, " ");
	} else {
		if (offseg) {
			ut32 s, a;
			r_num_segaddr (off, segbas, seggrn, &s, &a);
			if (offdec) {
				snprintf (space, sizeof (space), "%d:%d", s & 0xffff, a & 0xffff);
				r_cons_printf ("%9s%s", space, reset);
			} else {
				r_cons_printf ("%04x:%04x", s & 0xFFFF, a & 0xFFFF);
			}
		} else {
			int sz = lenof (off, 0);
			int sz2 = lenof (delta, 1);
			const char *pad = r_str_pad (' ', sz - 5 - sz2 - 3);
			if (delta > 0 || label) {
				if (label) {
					const int label_padding = 10;
					if (delta > 0) {
						const char *pad = r_str_pad (' ', sz - sz2 + label_padding);
						if (offdec) {
							r_cons_printf ("%s+%d%s", label, delta, pad);
						} else {
							r_cons_printf ("%s+0x%x%s", label, delta, pad);
						}
					} else {
						const char *pad = r_str_pad (' ', sz + label_padding);
						r_cons_printf ("%s%s", label, pad);
					}
				} else {
					if (offdec) {
						r_cons_printf ("%s+%d%s", pad, delta, reset);
					} else {
						r_cons_printf ("%s+0x%x%s", pad, delta, reset);
					}
				}
			} else {
				if (offdec) {
					snprintf (space, sizeof (space), "%"PFMT64u, off);
					r_cons_printf ("%10s", space);
				} else {
					r_cons_printf ("0x%08"PFMT64x " ", off);
				}
			}
		}
	}
}

#endif
