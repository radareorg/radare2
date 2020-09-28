#include "cmd_helps.h"

// root helps

const RCmdDescHelp system_help = {
	.summary = "run given command as in system(3)",
};
const RCmdDescHelp underscore_help = {
	.summary = "Print last output",
};

const RCmdDescHelp hash_help = {
	.summary = "Hashbang to run an rlang script",
};

const RCmdDescHelp alias_help = {
	.summary = "Alias commands and strings",
};

const RCmdDescHelp env_help = {
	.summary = "get/set environment variable",
};

const RCmdDescHelp tasks_help = {
	.summary = "Manage tasks (WARNING: Experimental. Use with caution!)",
};

const RCmdDescHelp macro_help = {
	.summary = "manage scripting macros",
};

const RCmdDescHelp pointer_help = {
	.summary = "alias for 'env' command",
};

const RCmdDescHelp stdin_help = {
	.summary = "",
};

const RCmdDescHelp interpret_help = {
	.summary = "Define macro or load r2, cparse or rlang file",
};

const RCmdDescHelp search_help = {
	.summary = "search for bytes, regexps, patterns, ..",
};

const RCmdDescHelp rap_help = {
	.summary = "connect with other instances of r2",
};

const RCmdDescHelp help_help = {
	.summary = "Help or evaluate math expression",
};

const RCmdDescHelp rap_run_help = {
	.summary = "alias for =!",
};

const RCmdDescHelp zero_help = {
	.summary = "alias for `s 0x...`",
};

const RCmdDescHelp anal_help = {
	.summary = "analysis commands",
};

const RCmdDescHelp b_help = {
	.summary = "display or change the block size",
};

const RCmdDescHelp c_help = {
	.summary = "compare block with given data",
};

const RCmdDescHelp C_help = {
	.summary = "code metadata (comments, format, hints, ..)",
};

const RCmdDescHelp d_help = {
	.summary = "debugger commands",
};

const RCmdDescHelp e_help = {
	.summary = "list/get/set config evaluable vars",
};

const RCmdDescHelp f_help = {
	.summary = "add flag at current address",
};

const RCmdDescHelp g_help = {
	.summary = "generate shellcodes with r_egg",
};

const RCmdDescHelp i_help = {
	.summary = "get info about opened file from r_bin",
};

const RCmdDescHelp k_help = {
	.summary = "run sdb-query",
};

const RCmdDescHelp l_help = {
	.summary = "list files and directories",
};

const RCmdDescHelp j_help = {
	.summary = "join the contents of the two files",
};

const RCmdDescHelp h_help = {
	.summary = "show the top n number of line in file",
};

const RCmdDescHelp L_help = {
	.summary = "list, unload, load r2 plugins",
};

const RCmdDescHelp m_help = {
	.summary = "mountpoints commands",
};

const RCmdDescHelp o_help = {
	.summary = "open file at optional address",
};

const RCmdDescHelp p_help = {
	.summary = "print commands",
};

const RCmdDescHelp P_help = {
	.summary = "project management utilities",
};

const RCmdDescHelp q_help = {
	.summary = "quit program with a return value",
};

const RCmdDescHelp Q_help = {
	.summary = "quick quit",
};

const RCmdDescHelp colon_help = {
	.summary = "long commands (experimental)",
};

const RCmdDescHelp r_help = {
	.summary = "resize file",
};

const RCmdDescHelp s_help = {
	.summary = "seek to address",
};

const RCmdDescHelp t_help = {
	.summary = "types, noreturn, signatures, C parser and more",
};

const RCmdDescHelp T_help = {
	.summary = "Text log utility (used to chat, sync, log, ...)",
};

const RCmdDescHelp u_help = {
	.summary = "uname/undo seek/write",
};

const RCmdDescHelp pipein_help = {
	.summary = "push escaped string into the RCons.readChar buffer",
};

const RCmdDescHelp V_help = {
	.summary = "enter visual mode",
};

const RCmdDescHelp v_help = {
	.summary = "enter visual panels mode",
};

const RCmdDescHelp w_group_help = {
	.summary = "write commands",
};

const RCmdDescHelp w_help = {
	.args_str = " <string>",
	.summary = "write string",
};

const RCmdDescHelp x_help = {
	.summary = "alias for 'px' (print hexadecimal)",
};

const RCmdDescHelp y_help = {
	.summary = "Yank/paste bytes from/to memory",
};

const RCmdDescHelp z_help = {
	.summary = "zignatures management",
};

// w0 helps

const RCmdDescHelp w0_help = {
	.summary = "Write 'len' bytes with value 0x00",
	.args_str = " [len]",
	.description = "Fill len bytes starting from the current offset with the value 0.",
};

// w[1248][+-] helps

const RCmdDescExample w_incdec_help_examples[] = {
	{ .example = "w1+", .comment = "Add 1 to the byte at the current offset." },
	{ .example = "w2-", .comment = "Subtract 1 to the word at the current offset." },
	{ .example = "w4+ 0xdeadbeef", .comment = "Add 0xdeadbeef to the dword at the current offset." },
	{ .example = "w8- 10", .comment = "Subtract 10 to the qword at the current offset." },
	{ 0 },
};

const RCmdDescHelp w_incdec_help = {
	.summary = "increment/decrement byte,word..",
	.args_str = " [n]",
	.options = "<1248><+->",
};

const RCmdDescHelp w1_incdec_help = {
	.summary = "Increment/decrement a byte",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a byte at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w1_inc_help = {
	.summary = "Increment a byte",
	.args_str = " [n]",
	.description = "Increment a byte at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w1_dec_help = {
	.summary = "Decrement a byte",
	.args_str = " [n]",
	.description = "Decrement a byte at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w2_incdec_help = {
	.summary = "Increment/decrement a word",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a word at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w2_inc_help = {
	.summary = "Increment a word",
	.args_str = " [n]",
	.description = "Increment a word at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w2_dec_help = {
	.summary = "Decrement a word",
	.args_str = " [n]",
	.description = "Decrement a word at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w4_incdec_help = {
	.summary = "Increment/decrement a dword",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a dword at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w4_inc_help = {
	.summary = "Increment a dword",
	.args_str = " [n]",
	.description = "Increment a dword at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w4_dec_help = {
	.summary = "Decrement a dword",
	.args_str = " [n]",
	.description = "Decrement a dword at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w8_incdec_help = {
	.summary = "Increment/decrement a qword",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a qword at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w8_inc_help = {
	.summary = "Increment a qword",
	.args_str = " [n]",
	.description = "Increment a qword at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

const RCmdDescHelp w8_dec_help = {
	.summary = "Decrement a qword",
	.args_str = " [n]",
	.description = "Decrement a qword at the current offset by 1 or n, if specified",
	.examples = w_incdec_help_examples,
};

// wB helps

const RCmdDescExample wB_help_examples[] = {
	{ .example = "wB 0x20", .comment = "Sets the 5th bit at current offset, leaving all other bits intact." },
	{ 0 },
};

const RCmdDescHelp wB_group_help = {
	.args_str = " [value]",
	.summary = "Set or unset bits with given value",
};

const RCmdDescHelp wB_help = {
	.summary = "Set bits with given value",
	.args_str = " [value]",
	.description = "Set the bits that are set in the value passed as arguments. 0 bits in the value argument are ignored, while the others are set at the current offset",
	.examples = wB_help_examples,
};

const RCmdDescHelp wB_minus_help = {
	.summary = "Unset bits with given value",
	.args_str = " [value]",
	.description = "Unset the bits that are set in the value passed as arguments. 0 bits in the value argument are ignored, while the others are unset at the current offset"
};

// wv helps

const RCmdDescExample wv_help_examples[] = {
	{ .example = "wv 0xdeadbeef", .comment = "Write the value 0xdeadbeef at current offset" },
	{ 0 },
};

const RCmdDescHelp wv_group_help = {
	.args_str = " [value]",
	.summary = "Write value of given size",
};

const RCmdDescHelp wv_help = {
	.summary = "Write value as 4 - bytes / 8 - bytes based on value",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as a 4 - bytes value or 8 - bytes value if the input is bigger than UT32_MAX, respecting the cfg.bigendian variable",
	.examples = wv_help_examples,
};

const RCmdDescHelp wv1_help = {
	.summary = "Write value of 1 byte",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 1 - byte, respecting the cfg.bigendian variable",
};
const RCmdDescHelp wv2_help = {
	.summary = "Write value of 2 bytes",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 2 - bytes, respecting the cfg.bigendian variable",
};
const RCmdDescHelp wv4_help = {
	.summary = "Write value of 4 bytes",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 4 - bytes, respecting the cfg.bigendian variable",
};
const RCmdDescHelp wv8_help = {
	.summary = "Write value of 8 byte",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 8 - bytes, respecting the cfg.bigendian variable",
};

const RCmdDescHelp w6_help = {
	.args_str = " <base64>|<hexstring>",
	.summary = "write base64 [d]ecoded or [e]ncoded string",
};

const RCmdDescHelp wh_help = {
	.args_str = " <command>",
	.summary = "whereis/which shell command",
};

const RCmdDescHelp we_help = {
	.summary = "extend write operations (insert bytes instead of replacing)",
};

const RCmdDescHelp wp_help = {
	.args_str = " -|<file>",
	.summary = "apply radare patch file. See wp? fmi",
};

const RCmdDescHelp wu_help = {
	.summary = "Apply unified hex patch (see output of cu)",
};

const RCmdDescHelp wr_help = {
	.args_str = " <num>",
	.summary = "write <num> random bytes",
};

const RCmdDescHelp wA_help = {
	.args_str = " <type> <value>",
	.summary = "alter/modify opcode at current seek (see wA?)",
};

const RCmdDescHelp wc_help = {
	.summary = "write cache commands",
};

const RCmdDescHelp wz_help = {
	.args_str = " <string>",
	.summary = "write zero terminated string (like w + \x00)",
};

const RCmdDescHelp wt_help = {
	.summary = "write to file (from current seek, blocksize or sz bytes)",
};

const RCmdDescHelp wf_help = {
	.summary = "write data from file, socket, offset",
};

const RCmdDescHelp ww_help = {
	.args_str = " <string>",
	.summary = "write wide string",
};

const RCmdDescHelp wx_help = {
	.args_str = " <hexstring>",
	.summary = "write two intel nops (from wxfile or wxseek)",
};

const RCmdDescHelp wa_help = {
	.summary = "write opcode, separated by ';' (use '\"' around the command)",
};

const RCmdDescHelp wb_help = {
	.args_str = " <hexstring>",
	.summary = "fill current block with cyclic hexstring",
};

const RCmdDescHelp wm_help = {
	.args_str = " <hexstring>",
	.summary = "set binary mask hexpair to be used as cyclic write mask",
};

const RCmdDescHelp wo_help = {
	.summary = "write in block with operation. 'wo?' fmi",
};

const RCmdDescHelp wd_help = {
	.summary = "duplicate N bytes from offset at current seek (memcpy) (see y?)",
};

const RCmdDescHelp ws_help = {
	.summary = "write 1 byte for length and then the string",
};
