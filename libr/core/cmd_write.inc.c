/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_w = {
	"Usage:", "w[x] [str] [<file] [<<EOF] [@addr]", "",
	"w ", "foobar", "write string 'foobar'",
	"w+", "string", "write string and seek to its null terminator",
	"w0", " [len]", "write 'len' bytes with value 0x00",
	"w6", "[d|e|x] base64/string/hex", "write base64 [d]ecoded or [e]ncoded string",
	"w8", " [hexpairs]", "alias for wx",
	"wa", "[?] push ebp", "write opcode, separated by ';' (use '\"' around the command)",
	"waf", " f.asm", "assemble file and write bytes",
	"waF", " f.asm", "assemble file and write bytes and show 'wx' op with hexpair bytes of assembled code",
	"wao", "[?] op", "modify opcode (change conditional of jump. nop, etc) (RArch.patch)",
	//"wA", "[?] r 0", "alter/modify opcode at current seek (see wA?)",
	"wb", " 011001", "write bits in bit big endian (see pb)",
	"wB", "[-]0xVALUE", "set or unset bits with given value (also wB-0x2000)",
	"wc", "[?][jir+-*?]", "write cache list/undo/commit/reset (io.cache)",
	"wd", " [off] [n]", "copy N bytes from OFF to $$ (memcpy) (see y?)",
	"we", "[?] [nNsxX] [arg]", "extend write operations (insert instead of replace)",
	"wf", "[fs] -|file", "write contents of file at current offset",
	"wg", "[et] [http://host/file]", "download file from http server and save it to disk (wget)",
	"wh", " r2", "whereis/which shell command",
	"wi", "[1248][+-][n]", "increment/decrement byte,word..",
	"wm", " f0ff", "set binary mask hexpair to be used as cyclic write mask",
	"wo", "[?] hex", "write in block with operation. 'wo?' fmi",
	"wp", "[?] -|file", "apply radare patch file. See wp? fmi",
	"wr", " 10", "write 10 random bytes",
	"ws", "[?] pstring", "write pascal string: 1 byte for length + N for the string",
	"wt", "[?][afs] [filename] [size]", "write to file (from current seek, blocksize or sz bytes)",
	"ww", " foobar", "write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'",
	"wx", "[?][fs] 9090", "write two intel nops (from wxfile or wxseek)",
	"wX", " 1b2c3d", "fill current block with cyclic hexpairs",
	"wv", "[?] [expr]", "write [1,2,4,8]-byte size using cfg.bigendian",
	"wu", " [unified-diff-patch]", "see 'cu'",
	"wz", " string", "write zero terminated string (like w + \\x00)",
	NULL
};

static RCoreHelpMessage help_msg_wao = {
	"wao", " [op]", "performs a modification on current opcode",
	"waol", " [op]", "length of the patch in bytes (f.example an intel nop is 1 byte)",
	"wao*", " [op]", "show the commands that will be executed to apply the patch",
	"wao+", " [op]", "same as 'wao', but seeks forward after writing",
	"wao", " nop", "nop current opcode",
	"wao", " jinf", "assemble an infinite loop",
	"wao", " jz", "make current opcode conditional (same as je) (zero)",
	"wao", " jnz", "make current opcode conditional (same as jne) (not zero)",
	"wao", " ret1", "make the current opcode return 1",
	"wao", " ret0", "make the current opcode return 0",
	"wao", " retn", "make the current opcode return -1",
	"wao", " nocj", "remove conditional operation from branch (make it unconditional)",
	"wao", " trap", "make the current opcode a trap",
	"wao", " recj", "reverse (swap) conditional branch instruction",
	"WIP:", "", "not all archs are supported and not all commands work on all archs",
	NULL
};

static RCoreHelpMessage help_msg_ws = {
	"Usage:", "ws[124?] [string]", "Pascal strings are not null terminated and store the length in binary at the beginning",
	"ws", " str", "write pascal string using first byte as length",
	"ws1", " str", "same as above",
	"ws2", " str", "same as above but using ut16 as length (honors cfg.bigendian)",
	"ws4", " str", "same, but using ut32 (honors cfg.bigendian)",
	NULL
};

static RCoreHelpMessage help_msg_wa = {
	"Usage:", "wa[of*] [arg]", "",
	"wa", " nop", "write nopcode using asm.arch and asm.bits",
	"wai", " jmp 0x8080", "write inside this op (fill with nops or error if doesnt fit)",
	"wan", " jmp 0x8080", "write instruction(s) nopping the trailing bytes",
	"wa+", " nop", "write a nop and seek after it (use 7wa+nop to write 7 consecutive nops)",
	"wa*", " mov eax, 33", "show 'wx' op with hexpair bytes of assembled opcode",
	"'wa nop;nop", "" , "assemble more than one instruction (note the single quote)",
	"waf", " f.asm" , "assemble file and write bytes",
	"waF", " f.asm", "assemble file and write bytes and show 'wx' op with hexpair bytes of assembled code",
	"waF*", " f.asm", "assemble file and show 'wx' op with hexpair bytes of assembled code",
	"wao?", "", "show help for assembler operation on current opcode (hack)",
	NULL
};

static RCoreHelpMessage help_msg_wc = {
	"Usage:", "wc[jir+-*?]", "  # See `e io.cache = true`",
	"wc", "", "list all write changes in the current cache layer",
	"wc*", "", "print write commands to replicate the patches in the current cache layer",
	"wc**", "", "same as 'wc*' but for all the cache layers",
	"wc+", " [from] [to]", "commit change from cache to io",
	"wc++", "", "push a new io cache layer",
	"wc-", " [from] [to]", "remove write op at curseek or given addr",
	"wc--", "", "pop (discard) last write cache layer",
	"wcU", "", "redo undone change (TODO)",
	"wca", "", "list all write changes in all the cache layers",
	"wcd", "", "list all write changes in disasm diff format",
	"wcf", " [file]", "commit write cache into given file",
	"wci", "", "commit write cache",
	"wcj", "", "list all write changes in JSON",
	"wcl", "", "list io cache layers",
	"wcp", " [fd]", "list all cached write-operations on p-layer for specified fd or current fd",
	"wcp*", " [fd]", "list all cached write-operations on p-layer in radare commands",
	"wcpi", " [fd]", "commit and invalidate pcache for specified fd or current fd",
	"wcr", "", "revert all writes in the cache",
	"wcs", "", "squash the consecutive write ops",
	"wcu", "", "undo last change",
	NULL
};

static RCoreHelpMessage help_msg_we = {
	"Usage", "", "write extend # resize the file",
	"wen", " <num>", "extend the underlying file inserting NUM null bytes at current offset",
	"weN", " <addr> <len>", "extend current file and insert bytes at address",
	"wes", " <addr>  <dist> <block_size>", "shift a blocksize left or write in the editor",
	"wex", " <hex_bytes>", "insert bytes at current offset by extending the file",
	"weX", " <addr> <hex_bytes>", "insert bytes at address by extending the file",
	NULL
};

static RCoreHelpMessage help_msg_wo = {
	"Usage:", "wo[asmdxoArl24]", " [hexpairs] @ addr[!bsize] write operation in current block",
	"wo2", "", "2= 2 byte endian swap (word)",
	"wo4", "", "4= 4 byte endian swap (dword)",
	"wo8", "", "8= 8 byte endian swap (qword)",
	"woa", " [hexpair]", "+= addition (f.ex: woa 0102)",
	"woA", " [hexpair]", "&= and",
	"wod", " [hexpair]", "/= divide",
	"woD", " [algo] [key] [IV]", "decrypt current block with given algo and key",
	"woE", " [algo] [key] [IV]", "encrypt current block with given algo and key",
	"woe", " [from] ([to] [step] [wsz=1])", "write enumeration sequence i0 01 02 ..",
	"woi", "", "inverse bytes in current block",
	"wol", " [val]", "<<= shift left",
	"wom", " [val]", "*= multiply",
	"woo", " [val]", "|= or",
	"wop[DO]", " [arg]", "De Bruijn Patterns",
	"wor", " [val]", ">>= shift right",
	"woR", "", "random bytes (alias for 'wr $b')",
	"wos", " [val]", "-= substraction",
	"woS", " [algo] [key]", "sign the current block with given algo and key",
	"wow", " [val]", "== write looped value (alias for 'wb')",
	"wox", " [val]", "^= xor (f.ex: wox 0x90)",
	NULL
};

static RCoreHelpMessage help_msg_wop = {
	"Usage:", "wop[DO]", " len @ addr | value",
	"wopD", " len [@ addr]", "write a De Bruijn Pattern of length 'len' at address 'addr'",
	"wopD*", " len [@ addr]", "show wx command that creates a debruijn pattern of a specific length",
	"wopO", " value", "finds the given value into a De Bruijn Pattern at current offset",
	NULL
};

// TODO
static RCoreHelpMessage help_msg_wp = {
	"Usage:", "wp", "[-|r2patch-file]",
	"^#", "", "comments",
	".", "", "execute command",
	"!", "", "execute command",
	"", "", "OFFSET { code block }",
	"", "", "OFFSET \"string\"",
	"", "", "OFFSET 01020304",
	"", "", "OFFSET : assembly",
	"", "", "+ {code}|\"str\"|0210|: asm",
	NULL
};

static RCoreHelpMessage help_msg_wt = {
	"Usage:", "wt[afs] [filename] [size]", " Write current block or [size] bytes from offset to file",
	"wta", " [filename]", "append to 'filename'",
	"wtf", " [filename] [size]", "write to file (see also 'wxf' and 'wf?')",
	"wtf!", " [filename]", "write to file from current address to eof (ignores given size)",
	"wtff", " [prefix] [size]", "write block from current seek to \"<prefix>-<offset>\"",
	"wts", " host:port [size]", "send data to remote socket at tcp://host:port",
	"NOTE:", "", "filename defaults to \"<cfg.prefixdump>.<offset>\"",
	NULL
};

static RCoreHelpMessage help_msg_wf = {
	"Usage:", "wf[fs] [-|args ..]", " Write from (file, swap, offset)",
	"wf", " 10 20", "write 20 bytes from offset 10 into current seek",
	"wff", " file [len]", "write contents of file into current offset",
	"wfs", " host:port [len]", "write from socket (tcp listen in port for N bytes)",
	"wfx", " 10 20", "exchange 20 bytes betweet current offset and 10",
	NULL
};

static RCoreHelpMessage help_msg_wv = {
	"Usage:", "wv[size] [value]", " Write value of given size",
	"wv", " 0x834002", "write dword with this value",
	"wv1", " 234", "write one byte with this value",
	"wv2", " 234", "write unsigned short (2 bytes) with this number",
	"wv4", " 1 2 3", "write N space-separated dword (4 bytes)",
	"wv8", " 234", "write qword (8 bytes) with this number",
	"wvF", " 3.14", "write double value (8 bytes)",
	"wvf", " 3.14", "write float value (4 bytes)",
	"wvg", " 3.14", "write custom float (see cfg.float)",
	"wvG", " 3.14", "write long double value (10/16 bytes)",
	"wvp", " 934", "write 4 or 8 byte pointer, depending on asm.bits",
	"Supported sizes: ", "1, 2, 4, 8", "",
	NULL
};

static RCoreHelpMessage help_msg_wx = {
	"Usage:", "wx[f] [arg]", "",
	"wx", " 3.", "write the left nibble of the current byte",
	"wx", " .5", "write the right nibble of the current byte",
	"wx+", " 9090", "write hexpairs and seek forward",
	"wxf", " -|file", "write contents of hexpairs file here",
	NULL
};

static void cmd_write_fail(RCore *core) {
	R_LOG_ERROR ("Cannot write. Use `omp`, `io.cache` or reopen the file in rw with `oo+`");
	r_core_return_value (core, R_CMD_RC_FAILURE);
}

R_API int cmd_write_hexpair(RCore* core, const char* pairs) {
	R_RETURN_VAL_IF_FAIL (core && pairs, 0);
	ut8 *buf = malloc (strlen (pairs) + 1);
	if (!buf) {
		return 0;
	}
	int len = r_hex_str2bin (pairs, buf);
	if (len != 0) {
		if (len < 0) {
			len = -len;
			if (len < core->blocksize) {
				buf[len - 1] |= core->block[len - 1] & 0xf;
			}
		}
		r_core_return_value (core, R_CMD_RC_SUCCESS);
		if (!r_core_write_at (core, core->addr, buf, len)) {
			cmd_write_fail (core);
			r_core_return_value (core, R_CMD_RC_FAILURE);
		}
		// call WSEEK for consistency?
		if (r_config_get_b (core->config, "cfg.wseek")) {
			r_core_seek_delta (core, len);
		}
		r_core_block_read (core);
	} else {
		R_LOG_ERROR ("invalid hexpair string");
		r_core_return_value (core, R_CMD_RC_FAILURE);
	}
	free (buf);
	return len;
}

static void write_encrypted_block(RCore *core, const char *algo, const char *key, int direction, const char *iv) {
	int keylen = 0;
	ut8 *binkey = NULL;
	if (!strncmp (key, "s:", 2)) {
		binkey = (ut8*)strdup (key + 2);
		keylen = strlen (key + 2);
	} else {
		binkey = (ut8 *)strdup (key);
		keylen = r_hex_str2bin (key, binkey);
	}
	if (!binkey) {
		return;
	}
	if (keylen < 1) {
		const char *mode = (direction == R_CRYPTO_DIR_ENCRYPT)? "Encryption": "Decryption";
		R_LOG_ERROR ("%s key not defined. Use -S [key]", mode);
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
					ivlen = strlen(iv);
					strcpy ((char *)biniv, iv);
				}
				if (!r_muta_session_set_iv (cj, biniv, ivlen)) {
					R_LOG_ERROR ("Invalid IV");
					return;
				}
			}
			r_muta_session_update (cj, (const ut8*)core->block, core->blocksize);

			int result_size = 0;
			ut8 *result = r_muta_session_get_output (cj, &result_size);
			if (result) {
				if (!r_core_write_at (core, core->addr, result, result_size)) {
					R_LOG_ERROR ("write failed at 0x%08"PFMT64x, core->addr);
				}
				R_LOG_INFO ("Written %d byte(s)", result_size);
				free (result);
			}
		}
		free (cj);
	} else {
		R_LOG_ERROR ("Unknown %s algorithm '%s'", ((direction == R_CRYPTO_DIR_ENCRYPT)? "encryption": "decryption"), algo);
	}
	free (binkey);
	return;
}

static void write_block_signature(RCore *core, const char *algo, const char *key) {
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
		R_LOG_ERROR ("Private key not defined");
		free (binkey);
		return;
	}
	RMutaSession *cj = r_muta_use (core->muta, algo);
	if (cj && cj->h->type == R_MUTA_TYPE_SIGN) {
		if (r_muta_session_set_key (cj, binkey, keylen, 0, R_CRYPTO_DIR_ENCRYPT)) {
			r_muta_session_update (cj, (const ut8 *)core->block, core->blocksize);
			int result_size = 0;
			ut8 *result = r_muta_session_get_output (cj, &result_size);
			if (result) {
				if (!r_core_write_at (core, core->addr, result, result_size)) {
					R_LOG_ERROR ("write failed at 0x%08" PFMT64x, core->addr);
				}
				R_LOG_INFO ("Written %d byte(s)", result_size);
				free (result);
			}
		}
		free (binkey);
		return;
	} else {
		R_LOG_ERROR ("Unknown signature algorithm '%s'", algo);
	}
	return;
}

static void cmd_write_bits(RCore *core, int set, ut64 val) {
	ut64 ret, orig;
	// used to set/unset bit in current address
	r_io_read_at (core->io, core->addr, (ut8*)&orig, sizeof (orig));
	if (set) {
		ret = orig | val;
	} else {
		ret = orig & (~(val));
	}
	if (!r_core_write_at (core, core->addr, (const ut8*)&ret, sizeof (ret))) {
		cmd_write_fail (core);
	}
}

static void cmd_write_inc(RCore *core, int size, st64 num) {
	ut64 *v64;
	ut32 *v32;
	ut16 *v16;
	ut8 *v8;
	switch (size) {
	case 1: v8 = (ut8*)core->block; *v8 += num; break;
	case 2: v16 = (ut16*)core->block; *v16 += num; break;
	case 4: v32 = (ut32*)core->block; *v32 += num; break;
	case 8: v64 = (ut64*)core->block; *v64 += num; break;
	}
	// TODO: obey endian here
	if (!r_core_write_at (core, core->addr, core->block, size)) {
		cmd_write_fail (core);
	}
}

static int cmd_wo(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut8 *buf;
	int len;
	int value;
	switch (input[0]) {
	case 'e': // "woe"
		if (input[1]!=' ') {
			r_core_cmd_help_match (core, help_msg_wo, "woe");
			return -1;
		}
		/* fallthrough */
	case 'a': // "woa"
	case 's': // "wos"
	case 'A': // "woA"
	case 'x': // "wox"
	case 'r': // "wor"
	case 'l': // "wol"
	case 'm': // "wom"
	case 'i': // "woi"
	case 'd': // "wod"
	case 'o': // "woo"
	case 'w': // "wow"
	case '2': // "wo2"
	case '4': // "wo4"
	case '8': // "wo8"
		if (input[1] == '?') {  // parse val from arg
			r_core_cmd_help_match_spec (core, help_msg_wo, "wo", input[0]);
		} else if (input[1]) {  // parse val from arg
			r_core_write_op (core, r_str_trim_head_ro (input + 1), input[0]);
		} else {  // use clipboard instead of val
			r_core_write_op (core, NULL, input[0]);
		}
		r_core_block_read (core);
		break;
	case 'R':
		r_core_cmd_call (core, "wr $b");
		break;
	case 'n':
		r_core_write_op (core, "ff", 'x');
		r_core_block_read (core);
		break;
	case 'E': // "woE" encrypt
	case 'D': // "woD" decrypt
		{
			int direction = (input[0] == 'E') ? R_CRYPTO_DIR_ENCRYPT : R_CRYPTO_DIR_DECRYPT;
			const char *algo = NULL;
			const char *key = NULL;
			const char *iv = NULL;
			char *space, *args = strdup (r_str_trim_head_ro (input+1));
			space = strchr (args, ' ');
			if (space) {
				*space++ = 0;
				key = space;
				space = strchr (key, ' ');
				if (space) {
					*space++ = 0;
					iv = space;
				}
			}
			algo = args;
			if (R_STR_ISNOTEMPTY (algo) && key) {
				write_encrypted_block (core, algo, key, direction, iv);
			} else {
				char *s = r_muta_list (core->muta, R_MUTA_TYPE_CRYPTO, 0);
				r_cons_print (core->cons, s);
				free (s);
				r_core_cmd_help_match_spec (core, help_msg_wo, "wo", input[0]);
			}
			free (args);
		}
		break;
		case 'S': // "woS" sign
		{
			const char *algo = NULL;
			const char *key = NULL;
			char *space, *args = strdup (r_str_trim_head_ro (input + 1));
			space = strchr (args, ' ');
			if (space) {
				*space++ = 0;
				key = space;
				space = strchr (key, ' ');
			}
			algo = args;
			if (R_STR_ISNOTEMPTY (algo) && key) {
				write_block_signature (core, algo, key);
			} else {
				char *s = r_muta_list (core->muta, R_MUTA_TYPE_SIGN, 0);
				r_cons_print (core->cons, s);
				free (s);
				r_core_cmd_help_match_spec (core, help_msg_wo, "wo", input[0]);
			}
			free (args);
		} break;
	case 'p': // debruijn patterns
		switch (input[1]) {
		case 'D': // "wopD"
			{
				char *sp = strchr (input, ' ');
				len = sp? r_num_math (core->num, sp + 1): core->blocksize;
			}
			if (len > 0) {
				/* XXX This seems to fail at generating long patterns (wopD 512K) */
				buf = (ut8*)r_debruijn_pattern (len, 0, NULL); //debruijn_charset);
				if (buf) {
					const ut8 *ptr = buf;
					ut64 addr = core->addr;
					if (input[2] == '*') {
						int i;
						r_cons_printf (core->cons, "wx ");
						for (i = 0; i < len; i++) {
							r_cons_printf (core->cons, "%02x", buf[i]);
						}
						r_cons_newline (core->cons);
					} else {
						if (!r_core_write_at (core, addr, ptr, len)) {
							cmd_write_fail (core);
						}
					}
					free (buf);
				} else {
					R_LOG_ERROR ("Couldn't generate pattern of length %d", len);
				}
			}
			break;
		case 'O': // "wopO"
			if (strlen (input) > 3 && strncmp (input + 3, "0x", 2)) {
				R_LOG_ERROR ("Need hex value with `0x' prefix e.g. 0x41414142");
			} else if (input[2] == ' ') {
				value = r_num_get (core->num, input + 3);
				int offset = r_debruijn_offset (value, r_config_get_i (core->config, "cfg.bigendian"));
				r_core_return_value (core, offset);
				r_cons_printf (core->cons, "%"PFMT64d"\n", core->num->value);
			}
			break;
		case '\0':
		case '?':
		default:
			r_core_cmd_help (core, help_msg_wop);
			break;
		}
		break;
	case '\0':
	case '?':
	default:
		r_core_cmd_help (core, help_msg_wo);
		break;
	}
	return 0;
}

#define WSEEK(x,y) if (r_config_get_b (core->config, "cfg.wseek")) { r_core_seek_delta ((x),(y)); }

static void cmd_write_value_float(RCore *core, const char *input) {
	float v = 0.0;
	sscanf (input, "%f", &v);
	r_io_write_at (core->io, core->addr, (const ut8*)&v, sizeof (float));
}

static void cmd_write_value_long_double(RCore *core, const char *input) {
	long double v = 0.0;
#if R2_NO_LONG_DOUBLE
	double tmp = strtod (input, NULL);
	v = (long double)tmp;
#else
	sscanf (input, "%Lf", &v);
#endif
	r_io_write_at (core->io, core->addr, (const ut8*)&v, sizeof (long double));
}

static void cmd_write_value_double(RCore *core, const char *input) {
	double v = 0.0;
	sscanf (input, "%lf", &v);
	r_io_write_at (core->io, core->addr, (const ut8*)&v, sizeof (double));
}

static const char *fpuhelp = \
	"Available FPU profiles:\n"
	"  ieee754 - IEEE 754 standard (binary64)\n"
	"  binary16, binary32, binary64, binary128, bfloat16, x87_80, etc.\n"
	"  custom:sign,exp,mant,bias,endian,explicit - specify custom parameters\n"
	"Use: wvg [value] to write with current profile\n"
	"Use: -e cfg.float=profile to set profile\n";

static void cmd_write_value(RCore *core, const char *input) {
	int type = 0;
	ut64 off = 0LL;
	ut8 buf[sizeof (ut64)];
	bool be = r_config_get_b (core->config, "cfg.bigendian");

	r_core_return_value (core, R_CMD_RC_SUCCESS);
	char op = input[0];
	if (op == 'p') {
		op = (r_config_get_i (core->config, "asm.bits") == 64)? '8': '4';
	}

	switch (op) {
	case '?': // "wv?"
		r_core_cmd_help (core, help_msg_wv);
		return;
	case 'f': // "wvf"
		cmd_write_value_float (core, r_str_trim_head_ro (input + 1));
		return;
	case 'F': // "wvF"
		cmd_write_value_double (core, r_str_trim_head_ro (input + 1));
		return;
	case 'G': // "wvG"
		cmd_write_value_long_double (core, r_str_trim_head_ro (input + 1));
		return;
	case 'd': // "wvd"
		cmd_write_value_double (core, r_str_trim_head_ro (input + 1));
		return;
	case 'g': // "wvg"
		{
			if (input[1] == '?') {
				r_cons_printf (core->cons, fpuhelp);
			} else {
				const RCFloatProfile *profile = &core->rasm->config->cfloat_profile;
				double value = strtod (r_str_trim_head_ro (input + 1), NULL);
				ut8 buf[16];
				size_t buf_size = (profile->sign_bits + profile->exp_bits + profile->mant_bits + 7) / 8;
				if (buf_size > sizeof (buf)) {
					R_LOG_ERROR ("Float size too large");
				} else if (!r_cfloat_write (value, profile, buf, buf_size)) {
					R_LOG_ERROR ("Failed to write float");
				} else {
					r_io_write_at (core->io, core->addr, buf, buf_size);
				}
			}
		}
		return;
	case '1': type = 1; break;
	case '2': type = 2; break;
	case '4': type = 4; break;
	case '8': type = 8; break;
	}

	// second step to write
	ut64 addr = core->addr;
	char *inp = r_str_trim_dup (input[0] ? input + 1: input);
	RList *list = r_str_split_list (inp, " ", 0); // or maybe comma :?
	char *cinp;
	RListIter *iter;
	r_list_foreach (list, iter, cinp) {
		if (input[0] && input[1]) {
			off = r_num_math (core->num, cinp);
		}
		if (core->io->desc) {
			r_io_use_fd (core->io, core->io->desc->fd);
		}
		ut64 res = r_io_seek (core->io, addr, R_IO_SEEK_SET);
		if (res == UT64_MAX) {
			return;
		}
		if (type == 0) {
			type = (off & UT64_32U)? 8: 4;
		}
		switch (type) {
		case 1:
			r_write_ble8 (buf, (ut8)(off & UT8_MAX));
			if (!r_io_write (core->io, buf, 1)) {
				cmd_write_fail (core);
			} else {
				WSEEK (core, 1);
			}
			break;
		case 2:
			r_write_ble16 (buf, (ut16)(off & UT16_MAX), be);
			if (!r_io_write (core->io, buf, 2)) {
				cmd_write_fail (core);
			} else {
				WSEEK (core, 2);
			}
			break;
		case 4:
			r_write_ble32 (buf, (ut32)(off & UT32_MAX), be);
			if (!r_io_write (core->io, buf, 4)) {
				cmd_write_fail (core);
			} else {
				WSEEK (core, 4);
			}
			break;
		case 8:
			r_write_ble64 (buf, off, be);
			if (!r_io_write (core->io, buf, 8)) {
				cmd_write_fail (core);
			} else {
				WSEEK (core, 8);
			}
			break;
		}
		addr += type;
	}
	r_list_free (list);
	free (inp);
	r_core_block_read (core);
}

static bool cmd_wff(RCore *core, const char *input) {
	ut8 *buf = NULL;
	size_t size = 0;
	const char *arg = input + ((input[0] == ' ') ? 1 : 0);
	char *p, *a = r_str_trim_dup (arg);
	p = strchr (a, ' ');
	if (p) {
		*p++ = 0;
	}

	if (*arg == '?' || !*arg) {
		r_core_cmd_help_contains (core, help_msg_w, "wf");
	} else if (!strcmp (arg, "-")) {
		char *out = r_core_editor (core, NULL, NULL);
		if (out) {
			if (!r_io_write_at (core->io, core->addr, (ut8*)out, strlen (out))) {
				R_LOG_ERROR ("write fail at 0x%08"PFMT64x, core->addr);
			}
			r_core_block_read (core);
			free (out);
		}
	}

	if (*a == '$' && !a[1]) {
		R_LOG_ERROR ("No alias name given");
	} else if (*a == '$') {
		RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, a+1);
		if (v) {
			buf = malloc (v->sz);
			if (buf) {
				size = v->sz;
				memcpy (buf, v->data, size);
			} else {
				size = 0;
			}
		} else {
			R_LOG_ERROR ("No such alias \"$%s\"", a + 1);
		}
	} else {
		buf = (ut8*) r_file_slurp (a, &size);
	}
	if (size < 1) {
		// nothing to write
	} else if (buf) {
		int u_offset = 0;
		ut64 u_size = r_num_math (core->num, p);
		if (u_size < 1) u_size = (ut64)size;
		if (p) {
			*p++ = 0;
			u_offset = r_num_math (core->num, p);
			if (u_offset > size) {
				R_LOG_ERROR ("Invalid offset");
				free (a);
				free (buf);
				return false;
			}
		}
		r_io_use_fd (core->io, core->io->desc->fd);
		if (!r_io_write_at (core->io, core->addr, buf + u_offset, (int)u_size)) {
			R_LOG_ERROR ("write fail at 0x%08"PFMT64x, core->addr);
		}
		WSEEK (core, size);
		r_core_block_read (core);
	} else {
		R_LOG_ERROR ("Cannot open file '%s'", arg);
	}
	free (a);
	free (buf);
	return true;
}

static bool ioMemcpy(RCore *core, ut64 dst, ut64 src, int len) {
	bool ret = false;
	if (len > 0) {
		ut8 * buf = calloc (1, len);
		if (buf) {
			if (r_io_read_at (core->io, src, buf, len)) {
				if (r_io_write_at (core->io, dst, buf, len)) {
					r_core_block_read (core);
					ret = true;
				} else {
					R_LOG_ERROR ("write failed at 0x%08"PFMT64x, dst);
				}
			} else {
				R_LOG_ERROR ("write failed at 0x%08"PFMT64x, src);
			}
			free (buf);
		}
	}
	return ret;
}

static bool cmd_wfx(RCore *core, const char *input) {
	char * args = r_str_trim_dup (input);
	char *arg = strchr (args, ' ');
	int len = core->blocksize;
	if (arg) {
		*arg = 0;
		len = r_num_math (core->num, arg + 1);
	}
	ut64 dst = core->addr;
	ut64 src = r_num_math (core->num, args);
	if (len > 0) {
		// cache dest, memcpy, write cache
		ut8 *buf = calloc (1, len);
		if (buf) {
			if (r_io_read_at (core->io, dst, buf, len)) {
				ioMemcpy (core, core->addr, src, len);
				if (r_io_write_at (core->io, src, buf, len)) {
					r_core_block_read (core);
				} else {
					R_LOG_ERROR ("Failed to write at 0x%08"PFMT64x, src);
				}
			} else {
				R_LOG_ERROR ("cmd_wfx: failed to read at 0x%08"PFMT64x, dst);
			}
			free (buf);
		}
	}
	free (args);
	return true;
}

static bool cmd_wfs(RCore *core, const char *input) {
	char *str = strdup (input);
	if (str[0] != ' ') {
		r_core_cmd_help_contains (core, help_msg_wf, "wfs");
		free (str);
		return false;
	}
	ut64 addr = 0;
	char *host = str + 1;
	char *port = strchr (host, ':');
	if (!port) {
		r_core_cmd_help_match (core, help_msg_wf, "wfs");
		free (str);
		return false;
	}
	ut64 sz = core->blocksize;
	*port ++= 0;
	char *space = strchr (port, ' ');
	if (space) {
		*space++ = 0;
		sz = r_num_math (core->num, space);
		addr = core->addr;
	}
	ut8 *buf = calloc (1, sz);
	if (!buf) {
		free (str);
		return false;
	}
	r_io_read_at (core->io, addr, buf, sz);
	RSocket *s = r_socket_new (false);
	if (!r_socket_listen (s, port, NULL)) {
		R_LOG_ERROR ("Cannot listen on port %s", port);
		r_socket_free (s);
		free (str);
		free (buf);
		return false;
	}
	int done = 0;
	RSocket *c = r_socket_accept (s);
	if (c) {
		R_LOG_INFO ("Receiving data from client");
		while (done < sz) {
			int rc = r_socket_read (c, buf + done, sz - done);
			if (rc < 1) {
				R_LOG_ERROR ("socket read oops");
				break;
			}
			done += rc;
		}
		r_socket_free (c);
		if (r_io_write_at (core->io, core->addr, buf, done)) {
			R_LOG_INFO ("Written %d bytes", done);
		} else {
			cmd_write_fail (core);
		}
	}
	r_socket_free (s);
	free (buf);
	free (str);
	return true;
}

static int cmd_wf(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (!core || !*input) {
		return -1;
	}
	if (input[0] == '?') {
		r_core_cmd_help (core, help_msg_wf);
		return -1;
	}
	if (input[0] == 's') { // "wfs"
		return cmd_wfs (core, input + 1);
	}
	if (input[0] == 'x') { // "wfx"
		return cmd_wfx (core, input + 1);
	}
	if (input[0] == 'f') { // "wff"
		return cmd_wff (core, input + 1);
	}
	char *args = r_str_trim_dup (input);
	char *arg = strchr (args, ' ');
	int len = core->blocksize;
	if (arg) {
		*arg++ = 0;
		len = r_num_math (core->num, arg);
	}
	ut64 addr = r_num_math (core->num, args);
	ioMemcpy (core, core->addr, addr, len);
	free (args);
	r_core_block_read (core);
	return 0;
}

static void squash_write_cache(RCore *core, const char *input) {
	R_LOG_TODO ("Squash is not implemented for the for the new io-cache");
#if 0
	void **iter;
	RPVector *v = &core->io->cache;
	ut64 end = UT64_MAX;
	RIOCache *oc = NULL;
	RPVector *nv = r_pvector_new (NULL);
	int pos = 0;
	int squashed = 0;
	r_pvector_foreach (v, iter) {
		RIOCache *c = *iter;
		const ut64 a = r_itv_begin (c->itv);
		const ut64 s = r_itv_size (c->itv);
		if (oc && end == a) {
			squashed ++;
			oc->itv.size += s;
		} else {
			r_pvector_insert (nv, pos, c);
			oc = c;
			pos++;
		}
		end = a + s;
	}
	R_LOG_INFO ("Squashed %d write caches", squashed);
	// r_pvector_clear (&core->io->cache);
	memcpy (&(core->io->cache), nv, sizeof (RIOCache));
#endif
}

static void cmd_write_pcache(RCore *core, const char *input) {
	RIODesc *desc;
	RList *caches;
	int fd;
	bool rad = false;
	if (core && core->io && core->io->p_cache && core->print) {
		switch (input[0]) {
		case 'i' :
			if (input[1]) {
				fd = (int)r_num_math (core->num, input + 1);
				desc = r_io_desc_get (core->io, fd);
			} else {
				desc = core->io->desc;
			}
			r_io_desc_cache_commit (desc);
			break;
		case '*':
			rad = true;
		case ' ': // fall-o-through
		case '\0':
			if (input[0] && input[1]) {
				fd = (int)r_num_math (core->num, input + 1);
				desc = r_io_desc_get (core->io, fd);
			} else {
				desc = core->io->desc;
			}
			if ((caches = r_io_desc_cache_list (desc))) {
				R_LOG_TODO ("pcache listing not working for the new io-cache (%d)", rad);
#if 0
				int i;
				RIOCache *c;
				RListIter *iter;
				if (rad) {
					core->print->cb_printf ("e io.va = false\n");
					r_list_foreach (caches, iter, c) {
						core->print->cb_printf ("wx %02x", c->data[0]);
						const int cacheSize = r_itv_size (c->itv);
						for (i = 1; i < cacheSize; i++) {
							core->print->cb_printf ("%02x", c->data[i]);
						}
						core->print->cb_printf (" @ 0x%08"PFMT64x" \n", r_itv_begin (c->itv));
					}
				} else {
					r_list_foreach (caches, iter, c) {
						core->print->cb_printf ("0x%08"PFMT64x": %02x",
							r_itv_begin (c->itv), c->odata[0]);
						const int cacheSize = r_itv_size (c->itv);
						for (i = 1; i < cacheSize; i++) {
							core->print->cb_printf ("%02x", c->odata[i]);
						}
						core->print->cb_printf (" -> %02x", c->data[0]);
						for (i = 1; i < cacheSize; i++) {
							core->print->cb_printf ("%02x", c->data[i]);
						}
						core->print->cb_printf ("\n");
					}
				}
#endif
				r_list_free (caches);
			}
			break;
		default:
			break;
		}
	}
}

static int cmd_wB(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ':
		cmd_write_bits (core, 1, r_num_math (core->num, input + 1));
		break;
	case '-':
		cmd_write_bits (core, 0, r_num_math (core->num, input + 1));
		break;
	default:
		r_core_cmd_help_match (core, help_msg_w, "wB");
		break;
	}
	return 0;
}

static int cmd_w0(void *data, const char *input) {
	int res = 0;
	RCore *core = (RCore *)data;
	ut64 len = r_num_math (core->num, input);
	if ((st64)len > 0 && len < ALLOC_SIZE_LIMIT) {
		ut8 *buf = calloc (1, len);
		if (buf) {
			if (!r_io_write_at (core->io, core->addr, buf, len)) {
				R_LOG_ERROR ("write failed at 0x%08" PFMT64x, core->addr);
				res = -1;
			}
			r_core_block_read (core);
			free (buf);
		} else {
			res = -1;
		}
	} else {
		R_LOG_ERROR ("invalid length");
	}
	return res;
}

static int w_incdec_handler(void *data, const char *input, int inc) {
	RCore *core = (RCore *)data;
	st64 num = 1;
	if (input[0] && input[1]) {
		num = r_num_math (core->num, input + 1);
	}
	switch (input[0]) {
	case '+':
		cmd_write_inc (core, inc, num);
		break;
	case '-':
		cmd_write_inc (core, inc, -num);
		break;
	default:
		r_core_cmd_help_match (core, help_msg_w, "w");
		break;
	}
	return 0;
}

static int cmd_w6(void *data, const char *input) {
	RCore *core = (RCore *)data;
	bool fail = false;
	ut8 *buf = NULL;
	int len = 0, str_len;

	if (input[0] && input[1] != ' ') {
		if (input[0] != 'e' && input[0] != 'd') {
			fail = true;
		}
	}
	const char *str = (input[0] && input[1] && input[2])? input + 2: "";
	str_len = strlen (str) + 1;
	if (!fail) {
		switch (input[0]) {
		case 'd': // "w6d"
			buf = malloc (str_len);
			if (buf) {
				len = r_base64_decode (buf, str, -1);
				if (len < 0) {
					R_LOG_WARN ("Invalid hexpair string");
					R_FREE (buf);
					fail = true;
				}
			}
			break;
		case 'x': { // "w6x"
			ut8 *bin_buf = malloc (str_len);
			if (!bin_buf) {
				break;
			}
			const int bin_len = r_hex_str2bin (str, bin_buf);
			if (bin_len <= 0) {
				fail = true;
			} else {
				buf = calloc (str_len + 1, 4);
				len = r_base64_encode ((char *)buf, bin_buf, bin_len);
				if (len == 0) {
					R_FREE (buf);
					fail = true;
				}
			}
			free (bin_buf);
			}
			break;
		case 'e': { // "w6e"
			ut8 *bin_buf = malloc (str_len);
			if (!bin_buf) {
				break;
			}
			char *s = r_str_trim_dup (input + 1);
			int slen = strlen (s);
			free (buf);
			buf = malloc ((4+slen) * 4);
			len = r_base64_encode ((char *)buf, (const ut8*)s, slen);
			if (len == 0) {
				R_FREE (buf);
				fail = true;
			}
			free (bin_buf);
			free (s);
			break;
		}
		default:
			fail = 1;
			break;
		}
	}
	if (!fail) {
		if (!r_core_write_at (core, core->addr, buf, len)) {
			cmd_write_fail (core);
		}
		WSEEK (core, len);
		r_core_block_read (core);
		free (buf);
	} else {
		r_core_cmd_help_match (core, help_msg_w, "w6");
	}
	return 0;
}

static int cmd_wh(RCore *core, const char *input) {
	R_RETURN_VAL_IF_FAIL (core && input, -1);
	char *space = strchr (input, ' ');
	const char *arg = space? r_str_trim_head_ro (space): NULL;
	if (arg) {
		char *path = r_file_path (arg);
		if (path) {
			r_cons_println (core->cons, path);
			free (path);
			return 0;
		}
	}
	return 1;
}

static int cmd_we(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 addr = 0, len = 0, b_size = 0;
	st64 dist = 0;
	ut8* bytes = NULL;
	int cmd_suc = false;
	char *input_shadow = NULL, *p = NULL;
	char *save_ptr = NULL;

	switch (input[0]) {
	case 'n': // "wen"
		if (input[1] == ' ') {
			len = *input ? r_num_math (core->num, input + 2) : 0;
			if (len > 0) {
				const ut64 cur_off = core->addr;
				cmd_suc = r_core_extend_at (core, core->addr, len);
				if (cmd_suc) {
					core->addr = cur_off;
					r_core_block_read (core);
				} else {
					R_LOG_ERROR ("r_io_extend failed");
					cmd_suc = true;
				}
			}
		} else {
			r_core_cmd_help_match (core, help_msg_we, "wen");
			cmd_suc = true;
		}
		break;
	case 'N': // "weN"
		if (input[1] == ' ') {
			input = r_str_trim_head_ro (input + 2);
			addr = r_num_math (core->num, input);
			while (*input && *input != ' ') {
				input++;
			}
			if (*input) {
				input++;
			}
			len = *input ? r_num_math (core->num, input) : 0;
			if (len > 0) {
				ut64 cur_off = core->addr;
				cmd_suc = r_core_extend_at (core, addr, len);
				if (cmd_suc) {
					r_core_seek (core, cur_off, true);
					core->addr = addr;
					r_core_block_read (core);
				} else {
					R_LOG_ERROR ("r_io_extend failed");
				}
			}
			cmd_suc = true;
		}
		break;
	case 'x': // "wex"
		if (input[1] == ' ') {
			input += 1;
			len = *input ? strlen (input) : 0;
			bytes = len > 1? malloc (len+1) : NULL;
			len = bytes ? r_hex_str2bin (input, bytes) : 0;
			if (len > 0) {
				ut64 cur_off = core->addr;
				cmd_suc = r_core_extend_at (core, cur_off, len);
				if (cmd_suc) {
					if (!r_core_write_at (core, cur_off, bytes, len)) {
						cmd_write_fail (core);
					}
				}
				core->addr = cur_off;
				r_core_block_read (core);
			}
			free (bytes);
		}
		break;
	case 's': // "wes"
		input += 2;
		while (*input && *input == ' ') {
			input++;
		}
		len = strlen (input);

		// since the distance can be negative,
		// the r_num_math will perform an unwanted operation
		// the solution is to tokenize the string :/
		if (len > 0) {
			input_shadow = strdup (input);
			p = r_str_tok_r (input_shadow, " ", &save_ptr);
			addr = p && *p ? r_num_math (core->num, p) : 0;

			p = r_str_tok_r (NULL, " ", &save_ptr);
			dist = p && *p ? r_num_math (core->num, p) : 0;

			p = r_str_tok_r (NULL, " ", &save_ptr);
			b_size = p && *p ? r_num_math (core->num, p) : 0;
			if (dist != 0) {
				r_core_shift_block (core, addr, b_size, dist);
				r_core_seek (core, addr, true);
				cmd_suc = true;
			}
		}
		free (input_shadow);
		break;
	case 'X': // "weX"
		if (input[1] == ' ') {
			input = r_str_trim_head_ro (input + 2);
			addr = r_num_math (core->num, input);
			while (*input && *input != ' ') {
				input++;
			}
			if (*input) {
				input++;
			}
			len = *input ? strlen (input) : 0;
			bytes = (len > 1)? malloc (len + 1) : NULL;
			len = bytes ? r_hex_str2bin (input, bytes) : 0;
			if (len > 0) {
				//ut64 cur_off = core->addr;
				cmd_suc = r_core_extend_at (core, addr, len);
				if (cmd_suc) {
					if (!r_core_write_at (core, addr, bytes, len)) {
						cmd_write_fail (core);
					}
				} else {
					R_LOG_ERROR ("r_io_extend failed");
				}
				core->addr = addr;
				r_core_block_read (core);
			}
			free (bytes);
		}
		break;
	case '?': // "we?"
	default:
		cmd_suc = false;
		break;
	}
	if (cmd_suc == false) {
		r_core_cmd_help (core, help_msg_we);
	}
	return 0;
}

static int cmd_wp(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] == '-' || (input[0] == ' ' && input[1] == '-')) {
		char *out = r_core_editor (core, NULL, NULL);
		if (out) {
			r_core_patch (core, out);
			free (out);
		}
	} else {
		if (input[0] == ' ' && input[1]) {
			char *data = r_file_slurp (input + 1, NULL);
			if (data) {
				r_core_patch (core, data);
				free (data);
			}
		} else {
			r_core_cmd_help (core, help_msg_wp);
		}
	}
	return 0;
}

static int cmd_wu(RCore *core, const char *input) {
	// TODO: implement it in an API RCore.write_unified_hexpatch() is ETOOLONG
	if (input[0] == ' ') {
		char *data = r_file_slurp (input + 1, NULL);
		if (data) {
			int i;
			char sign = ' ';
			int line = 0, offs = 0, hexa = 0;
			int newline = 1;
			for (i = 0; data[i]; i++) {
				switch (data[i]) {
				case '+':
					if (newline)
						sign = 1;
					break;
				case '-':
					if (newline) {
						sign = 0;
						offs = i + ((data[i + 1] == ' ')? 2: 1);
					}
					break;
				case ' ':
					data[i] = 0;
					if (sign) {
						if (!line) {
							line = i + 1;
						} else if (!hexa) {
							hexa = i + 1;
						}
					}
					break;
				case '\r':
					break;
				case '\n':
					newline = 1;
					if (sign == ' ') {
						offs = 0;
						line = 0;
						hexa = 0;
					} else if (sign) {
						if (offs && hexa) {
							r_cons_printf (core->cons, "wx %s @ %s\n", data+hexa, data+offs);
						} else {
							R_LOG_ERROR ("Oops");
						}
						offs = 0;
						line = 0;
					} else {
						hexa = 0;
					}
					sign = -1;
					continue;
				}
				newline = 0;
			}
			free (data);
		}
	} else {
		r_core_cmd_help_match (core, help_msg_we, "wu");
	}
	return 0;
}

static int cmd_wr(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 off = r_num_math (core->num, input);
	int len = (int)off;
	if (len > 0) {
		ut8 *buf = malloc (len);
		if (buf) {
			int i;
			r_num_irand ();
			for (i = 0; i < len; i++)
				buf[i] = r_num_rand (256);
			if (!r_core_write_at (core, core->addr, buf, len)) {
				cmd_write_fail (core);
			}
			WSEEK (core, len);
			free (buf);
		} else {
			R_LOG_ERROR ("Cannot allocate %d byte(s)", len);
		}
	}
	return 0;
}

#if 0
static RCoreHelpMessage help_msg_wA = {
	"Usage:", " wA", "[type] [value]",
	"Types", "", "",
	"r", "", "raw write value",
	"v", "", "set value (taking care of current address)",
	"d", "", "destination register",
	"0", "", "1st src register",
	"1", "", "2nd src register",
	"Example:",  "wA r 0", "# e800000000",
	NULL
};

// RAsm.modify() was unused therefor this is kind of attempt to move the asmhacks into the arch plugins
static int cmd_wA(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int len;
	switch (input[0]) {
	case ' ':
		if (input[1] && input[2] == ' ') {
			r_asm_set_pc (core->rasm, core->addr);
			eprintf ("modify (%c)=%s\n", input[1], input + 3);
			len = r_asm_modify (core->rasm, core->block, input[1],
				r_num_math (core->num, input + 3));
			eprintf ("len=%d\n", len);
			if (len > 0) {
				if (!r_core_write_at (core, core->addr, core->block, len)) {
					cmd_write_fail (core);
				}
				WSEEK (core, len);
			} else {
				eprintf ("r_asm_modify = %d\n", len);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_w, "wA");
		}
		break;
	case '?':
	default:
		r_core_cmd_help (core, help_msg_wA);
		break;
	}
	return 0;
}
#endif

static char *__current_filename(RCore *core) {
	RIOMap *map = r_io_map_get_at (core->io, core->addr);
	if (map) {
		RIODesc *desc = r_io_desc_get (core->io, map->fd);
		if (desc) {
			return strdup (desc->uri);
		}
	}
	return NULL;
}

static ut64 __va2pa(RCore *core, ut64 va) {
	RIOMap *map = r_io_map_get_at (core->io, va);
	if (map) {
		return va - map->itv.addr + map->delta;
	}
	return va;
}

static void cmd_wcf(RCore *core, const char *dfn) {
	char *sfn = __current_filename (core);
	if (!sfn) {
		R_LOG_ERROR ("Cannot determine source file");
		return;
	}
	// XXX. apply all layers?
	RIOCacheLayer *layer = r_list_last (core->io->cache.layers);
	if (!layer) {
		R_LOG_ERROR ("Cache is empty");
		return;
	}
	ut64 sfs = r_io_desc_size (core->io->desc);
	ut8 *sfb = malloc (sfs);
	if (!sfb) {
		R_LOG_ERROR ("Cannot allocate %"PFMT64d" descsize", sfs);
		return;
	}
	int res = r_io_pread_at (core->io, 0, sfb, sfs);
	if (res > 0) {
		void **iter;
		r_pvector_foreach (layer->vec, iter) {
			RIOCacheItem *c = *iter;
			const ut64 ps = r_itv_size (c->itv);
			const ut64 va = r_itv_begin (c->itv);
			const ut64 pa = __va2pa (core, va);
			if (pa + ps < sfs) {
				memcpy (sfb + pa, c->data, ps);
			} else {
				R_LOG_ERROR ("Out of bounds patch at 0x%08"PFMT64x, pa);
			}
		}
		// patch buffer
		r_file_dump (dfn, sfb, sfs, false);
	} else {
		R_LOG_ERROR ("Cannot read source data");
	}
	free (sfb);
	free (sfn);
}

static int cmd_wc(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0': // "wc"
		{
			char *res = r_io_cache_list (core->io, 0, false);
			r_cons_print (core->cons, res);
			free (res);
		}
		break;
	case 'd':
		{
			RIOCacheLayer *layer;
			RListIter *liter;
			r_list_foreach (core->io->cache.layers, liter, layer) {
				void **iter;
				// list (io, layer, pj, rad);
				r_pvector_foreach (layer->vec, iter) {
					RIOCacheItem *ci = *iter;
					r_cons_printf (core->cons, "0x%08"PFMT64x":\n", ci->itv.addr);
					char *a = r_hex_bin2strdup (ci->data, ci->itv.size);
					char *b = r_hex_bin2strdup (ci->odata, ci->itv.size);
					char *a0 = r_core_cmd_strf (core, "pad %s", b);
					char *b0 = r_core_cmd_strf (core, "pad %s", a);
					char *a1 = r_str_prefix_all (a0, "- ");
					char *b1 = r_str_prefix_all (b0, "+ ");
					r_str_trim (a1);
					r_str_trim (b1);
					if (r_config_get_i (core->config, "scr.color") > 0) {
						r_cons_printf (core->cons, Color_RED"%s\n"Color_GREEN"%s\n"Color_RESET, a1, b1);
					} else {
						r_cons_printf (core->cons, "%s\n%s\n", a1, b1);
					}
					free (a);
					free (b);
					free (a0);
					free (b0);
					free (a1);
					free (b1);
				}
			}
		}
		break;
	case 'a':
		{
			char *res;
			if (input[1] == 'j') {
				res = r_io_cache_list (core->io, 'j', true);
			} else {
				res = r_io_cache_list (core->io, 0, true);
			}
			r_cons_print (core->cons, res);
			free (res);
		}
		break;
	case 'l': // "wcl"
		if (r_list_empty (core->io->cache.layers)) {
			R_LOG_INFO ("No layers");
		} else {
			RIOCacheLayer *layer;
			RListIter *iter;
			int i = 0;
			int last = r_list_length (core->io->cache.layers) - 1;
			r_list_foreach (core->io->cache.layers, iter, layer) {
				int count = r_pvector_length (layer->vec);
				const char ch = (i == last)? '*': '-';
				r_cons_printf (core->cons, "%c %d cache layer with %d patches\n", ch, i, count);
				i++;
			}
		}
		break;
	case '?': // "wc?"
		r_core_cmd_help (core, help_msg_wc);
		break;
	case 'u': // "wcu"
		r_io_cache_undo (core->io);
		break;
	case 'U': // "wcU"
		r_io_cache_redo (core->io);
		break;
	case 'f': // "wcf"
		if (input[1] == ' ') {
			cmd_wcf (core, r_str_trim_head_ro (input + 1));
		} else {
			r_core_cmd_help_match (core, help_msg_wc, "wcf");
		}
		break;
	case '*': // "wc*"
		{
			char *res = r_io_cache_list (core->io, 1, input[1] == '*');
			r_cons_print (core->cons, res);
			free (res);
		}
		break;
	case '+': // "wc+"
		if (input[1] == '+') { // "wc++"
			r_io_cache_push (core->io);
		} else if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_wc, "wc+");
		} else if (input[1] == ' ') { // "wc+ "
			ut64 to;
			ut64 from = r_num_math (core->num, input + 2);
			char *p = strchr (input + 2, ' ');
			if (p) {
				*p = 0;
				to = r_num_math (core->num, input + 2);
				if (to < from) {
					R_LOG_ERROR ("Invalid range (from > to)");
					return 0;
				}
			} else {
				to = from + core->blocksize;
			}
			r_io_cache_commit (core->io, from, to, false);
		} else {
			R_LOG_ERROR ("Invalidate write cache at 0x%08"PFMT64x, core->addr);
			r_io_cache_commit (core->io, core->addr, core->addr + 1, false);
		}
		break;
	case '-': // "wc-"
		if (input[1] == '-') { // "wc--"
			if (input[2] == '*') {
				while (r_io_cache_pop (core->io)) {
					// nothing here
				}
			} else {
				r_io_cache_pop (core->io);
			}
		} else if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_wc, "wc-");
		} else {
			ut64 from, to;
			if (input[1] == ' ') { // "wc- "
				char *p = strchr (input + 2, ' ');
				if (p) {
					*p = 0;
					from = r_num_math (core->num, input+2);
					to = r_num_math (core->num, p+1);
					if (to < from) {
						R_LOG_ERROR ("Invalid range (from > to)");
						return 0;
					}
				} else {
					from = r_num_math (core->num, input+2);
					to = from + core->blocksize;
				}
			} else {
				R_LOG_INFO ("Invalidate write cache at 0x%08"PFMT64x, core->addr);
				from = core->addr;
				to = core->addr + core->blocksize;
			}
			R_LOG_INFO ("Invalidated %d cache(s)", r_io_cache_invalidate (core->io, from, to, false));
			r_core_block_read (core);
		}
		break;
	case 'i': // "wci"
		r_io_cache_commit (core->io, 0, UT64_MAX, false);
		r_core_block_read (core);
		break;
	case 'j': // "wcj"
		{
			char *res = r_io_cache_list (core->io, 2, false);
			r_cons_print (core->cons, res);
			free (res);
		}
		break;
	case 'p': // "wcp"
		cmd_write_pcache (core, &input[1]);
		break;
	case 'r': // "wcr"
		r_io_cache_reset (core->io);
		/* Before loading the core block we have to make sure that if
		 * the cache wrote past the original EOF these changes are no
		 * longer displayed. */
		memset (core->block, 0xff, core->blocksize);
		r_core_block_read (core);
		break;
	case 's': // "wcs" -- write cache squash
		squash_write_cache (core, input + 1);
		break;
	default:
		r_core_return_invalid_command (core, "wc", input[0]);
		break;
	}
	return 0;
}

static int cmd_w(RCore *core, const char *input) {
	char *str = strdup (input);
	/* write string */
	int len = r_str_unescape (str);
	if (r_config_get_b (core->config, "cmd.undo")) {
		ut8 *buf = malloc (len);
		r_io_read_at (core->io, core->addr, buf, len);
		char *bufstr = r_hex_bin2strdup (buf, len);
		char *a = r_str_newf ("wx %s", bufstr);
		char *b = r_str_newf ("w %s", str);
		RCoreUndo *uc = r_core_undo_new (core->addr, b, a);
		r_core_undo_push (core, uc);
		free (a);
		free (b);
		free (bufstr);
		free (buf);
	}
	// handle charset logic here
	if (!r_core_write_at (core, core->addr, (const ut8 *)str, len)) {
		cmd_write_fail (core);
	}
	free (str);
	WSEEK (core, len);
	r_core_block_read (core);
	r_core_return_value (core, len);
	return 0;
}

static int cmd_wget(RCore *core, const char *input) {
	while (*input && *input != ' ') {
		input++;
	}
	input = r_str_trim_head_ro (input);
	if (!r_str_startswith (input, "http://")) {
		R_LOG_ERROR ("wget/wg command only accepts http:// urls");
		return 0;
	}
	const char *fname = r_str_lchr (input, '/');
	if (!fname || !*fname) {
		fname = "index.html";
	} else {
		fname ++;
	}
	int len = 0;
	char *data = r_socket_http_get (input, NULL, NULL, &len);
	if (data) {
		if (!r_file_dump (fname, (const ut8*)data, len, 0)) {
			R_LOG_ERROR ("Cannot save file to disk");
			r_core_return_value (core, 1);
		} else {
			r_core_return_value (core, 0);
			R_LOG_INFO ("Saved %d bytes in %s", len, fname);
		}
		free (data);
	} else {
		R_LOG_ERROR ("Cannot retrieve file");
		r_core_return_value (core, 1);
	}
	return 0;
}

static int cmd_wz(RCore *core, const char *input) {
	char *str = strdup (input + 1);
	int len = r_str_unescape (str) + 1;

	/* write zero-terminated string */
	if (*input == '?' || *input != ' ' || len < 1) {
		free (str);
		r_core_cmd_help_match (core, help_msg_w, "wz");
		r_core_return_value (core, 0);
		return 0;
	}
	if (!r_core_write_at (core, core->addr, (const ut8 *)str, len)) {
		cmd_write_fail (core);
	}
	r_core_return_value (core, len);
	WSEEK (core, len + 1);
	r_core_block_read (core);
	free (str);
	return 0;
}

static int cmd_wt(RCore *core, const char *input) {
	const char *prefix = r_config_get (core->config, "cfg.prefixdump");
	char default_filename_sep = '.';
	int ret = 0;

	bool append = false;
	st64 sz = core->blocksize;
	ut64 poff = core->addr; // physical address; for writing arbitrary sizes

	int argc;
	char **argv = r_str_argv (input, &argc);

	char *ofilename = argc > 1? strdup (argv[1]): NULL; // NULL if argc < 2
	char *filename = ofilename;

	input++;
	switch (*input) {
	case 's': { // "wts"
		ut64 addr = 0;
		char *host_port;
		R_BORROW char *host;
		R_BORROW char *port;
		ut8 *buf;
		RSocket *sock;

		if (argc < 2) {
			r_core_cmd_help_match (core, help_msg_wt, "wts");
			ret = 1;
			goto leave;
		}

		sz = r_io_size (core->io);
		if (sz < 0) {
			R_LOG_ERROR ("Unknown file size");
			ret = 1;
			goto leave;
		}

		host_port = strdup (argv[1]);

		host = host_port;
		port = strchr (host_port, ':');
		if (!port) {
			r_core_cmd_help_match (core, help_msg_wt, "wts");
			free (host_port);
			ret = 1;
			goto leave;
		}

		*port++ = 0;

		if (argc > 2) {
			sz = r_num_math (core->num, argv[2]);
			if (sz < 0) {
				R_LOG_ERROR ("%s is not a valid size", argv[2]);
				free (host_port);
				ret = 1;
				goto leave;
			}
			addr = core->addr;
		}

		buf = malloc (sz);
		r_io_read_at (core->io, addr, buf, sz);

		sock = r_socket_new (false);
		if (r_socket_connect (sock, host, port, R_SOCKET_PROTO_TCP, 0)) {
			ut64 sent = 0;
			R_LOG_INFO ("Connection created. Sending data to TCP socket");
			while (sent < sz) {
				bool sockret = r_socket_write (sock, buf + sent, sz - sent);
				if (!sockret) {
					R_LOG_ERROR ("Socket write error");
					ret = 1;
					break;
				}
			}
		} else {
			R_LOG_ERROR ("Connection to %s failed", host_port);
			ret = 1;
		}

		free (host_port);
		free (buf);
		r_socket_free (sock);
		goto leave;
	}
	case 'f': // "wtf"
		switch (input[1]) {
		case '\0':
		case '?': // "wtf?"
			r_core_cmd_help_match (core, help_msg_wt, "wtf");
			ret = 1;
			goto leave;
		case '!': { // "wtf!"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_wt, "wtf!");
				ret = 1;
				goto leave;
			}
			RIOMap *map = r_io_map_get_at (core->io, poff);
			if (map) {
				// convert vaddr to paddr
				poff = poff - r_io_map_begin (map) + map->delta;
			}
			sz = r_io_fd_size (core->io, core->io->desc->fd) - core->addr;
			// ignore given size
			if (argc > 2) {
				argc = 2;
			}
			break;
		}
		case 'f': // "wtff"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_wt, "wtff");
				ret = 1;
				goto leave;
			}

			if (argc > 1) {
				prefix = argv[1];
			}

			default_filename_sep = '-';
			break;
		default: // "wtf"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_wt, "wtf");
				ret = 1;
				goto leave;
			}

			if (r_str_startswith (filename, "base64:")) {
				const char *b64str = filename + strlen ("base64:");
				ut8 *decoded = r_base64_decode_dyn (b64str , strlen (b64str), NULL);
				if (!decoded) {
					R_LOG_ERROR ("Couldn't decode b64 filename");
					ret = 1;
					goto leave;
				}
				free (filename);
				ofilename = (char *)decoded;
				filename = ofilename;
			}
			break;
		}
		break;
	case 'a':
		append = true;
		break;
	case '\0': // "wt"
	case ' ': // "wt "
		break;
	case '?': // "wt?"
	default:
		r_core_cmd_help (core, help_msg_wt);
		goto leave;
	}

	// default filename is prefix.addr
	if (R_STR_ISEMPTY (filename)) {
		free (filename);
		ofilename = r_str_newf ("%s%c0x%08" PFMT64x,
				prefix, default_filename_sep, poff);
		filename = ofilename;
	}

	// don't overwrite forced size
	if (sz == core->blocksize && argc > 2) {
		sz = (st64)r_num_math (core->num, argv[2]);
	}

	// Don't attempt to write 0 bytes
	if (sz < 1) {
		R_LOG_ERROR ("%s is not a valid size", argv[2]);
		goto leave;
	}

	if (*filename == '$') {
		ut8 *buf = core->block;
		bool free_buf = false;

		filename++;

		// manual buffer if given arbitrary size
		if (sz > core->blocksize) {
			buf = malloc (sz);
			if (!buf) {
				R_LOG_ERROR ("malloc() failure");
				ret = 1;
				goto leave;
			}
			r_io_read_at (core->io, poff, buf, sz);
			free_buf = true;
		}

		if (append) {
			if (r_cmd_alias_append_raw (core->rcmd, filename, buf, sz)) {
				R_LOG_ERROR ("Will not append to command alias \"$%s\"", filename);
				ret = 1;
			}
		} else {
			r_cmd_alias_set_raw (core->rcmd, filename, buf, sz);
		}

		if (free_buf) {
			free (buf);
		}

		if (!ret) {
			R_LOG_INFO ("Dumped %" PFMT64d " bytes from 0x%08" PFMT64x" into $%s",
					sz, poff, filename);
		}
		goto leave;
	}

	// use core if reading past end of block
	if (sz <= core->blocksize) {
		ret = r_file_dump (filename, core->block, sz, append);
	} else {
		ret = r_core_dump (core, filename, poff, (ut64)sz, append);
	}
	if (ret) {
		R_LOG_INFO ("Dumped %" PFMT64d " bytes from 0x%08" PFMT64x" into %s",
				sz, poff, filename);
		ret = 0;
	}

leave:
	free (ofilename);
	r_str_argv_free (argv);
	return ret;
}

static int cmd_ww(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *ostr = strdup (input);
	char *str = ostr;
	int len = r_str_unescape (str);
	if (len < 1) {
		free (ostr);
		return 0;
	}
	len++;
	str++;
	len = (len - 1) << 1;
	char *tmp = (len > 0) ? malloc (len + 1) : NULL;
	bool be = r_config_get_b (core->config, "cfg.bigendian");
	if (tmp) {
		int i;
		for (i = 0; i < len; i++) {
			bool match = i % 2;
			if (be) {
				match = !match;
			}
			if (match) {
				tmp[i] = 0;
			} else {
				tmp[i] = str[i >> 1];
			}
		}
		str = tmp;
		if (core->io->desc) {
			r_io_use_fd (core->io, core->io->desc->fd);
		}
		if (!r_io_write_at (core->io, core->addr, (const ut8 *)str, len)) {
			R_LOG_ERROR ("write failed at 0x%08" PFMT64x, core->addr);
		}
		WSEEK (core, len);
		r_core_block_read (core);
		free (tmp);
	} else {
		R_LOG_ERROR ("Cannot malloc %d", len);
	}
	free (ostr);
	return 0;
}

static int cmd_wx(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *arg;
	ut8 *buf;
	int size;
	switch (input[0]) {
	case ' ': // "wx "
		cmd_write_hexpair (core, r_str_trim_head_ro (input));
		break;
	case 'f': // "wxf"
		arg = (const char *)(input + ((input[1] == ' ')? 2: 1));
		if (!strcmp (arg, "-")) {
			int len;
			ut8 *out;
			char *in = r_core_editor (core, NULL, NULL);
			if (in) {
				out = (ut8 *)strdup (in);
				if (out) {
					len = r_hex_str2bin (in, out);
					if (len > 0) {
						if (!r_io_write_at (core->io, core->addr, out, len)) {
							R_LOG_ERROR ("r_io_write_at failed at 0x%08"PFMT64x, core->addr);
						}
						r_core_return_value (core, len);
					} else {
						r_core_return_value (core, 0);
					}
					free (out);
				}
				free (in);
			}
		} else if (r_file_exists (arg)) {
			if ((buf = r_file_slurp_hexpairs (arg, &size))) {
				r_io_use_fd (core->io, core->io->desc->fd);
				if (r_io_write_at (core->io, core->addr, buf, size) > 0) {
					r_core_return_value (core, size);
					WSEEK (core, size);
				} else {
					R_LOG_ERROR ("r_io_write_at failed at 0x%08"PFMT64x, core->addr);
				}
				free (buf);
				r_core_block_read (core);
			} else {
				R_LOG_ERROR ("This file doesnt contains hexpairs");
			}
		} else {
			R_LOG_ERROR ("Cannot open file '%s'", arg);
		}
		break;
	case 's': // "wxs"
		R_LOG_WARN ("wxs has been renamed to wx+");
		// fallthrough
	case '+': // "wx+"
		{
			int len = cmd_write_hexpair (core, input + 1);
			if (len > 0) {
				r_core_seek_delta (core, len);
				r_core_return_value (core, len);
			} else {
				r_core_return_value (core, 0);
			}
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_wx);
		break;
	}
	return 0;
}

static bool asm_patch(RCore *core, const char *op, int mode) {
	R_RETURN_VAL_IF_FAIL (core && op, false);
	const char *asmarch = r_config_get (core->config, "asm.arch");
	const bool doseek = (*op == '+');
	if (doseek) {
		op++;
		mode = *op;
	}
	if (!asmarch) {
		return false;
	}
	if (core->blocksize < 4) {
		return false;
	}
	{
		RAnalOp aop = { .addr = core->addr };
		r_anal_op_set_bytes (&aop, core->addr, core->block, 4);
		// TODO: use r_arch_decode
		if (!r_anal_op (core->anal, &aop, core->addr, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC)) {
			R_LOG_ERROR ("anal op fail");
			r_anal_op_fini (&aop);
			return false;
		}
		char *cmd = r_asm_parse_patch (core->rasm, &aop, op);
		if (cmd) {
			switch (mode) {
			case '*': r_cons_println (core->cons, cmd); break;
			case 'l': r_cons_printf (core->cons, "%d\n", (int)(strlen (cmd) - 3)/2); break;
			default: r_core_cmd0 (core, cmd); break;
			}
			free (cmd);
		} else {
			R_LOG_ERROR ("No asm.patch possible");
		}
		r_anal_op_fini (&aop);
		if (doseek) {
			r_core_seek (core, core->addr + aop.size, 1);
		}
		return true;
	}
	return false;
}

static int cmd_wa(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'o': // "wao"
		switch (input[1]) {
		case ' ':
		case '*':
		case 'l':
		case '+':
			asm_patch (core, r_str_trim_head_ro (input + 1), input[1]);
			break;
		default:
			r_core_cmd_help (core, help_msg_wao);
			break;
		}
		break;
	case ' ':
	case '+':
	case 'i':
	case 'n':
	case '*': {
		const char *file = r_str_trim_head_ro (input + 1);
		r_asm_set_pc (core->rasm, core->addr);
		RAsmCode *acode = r_asm_assemble (core->rasm, file);
		if (acode) {
			if (input[0] == 'n') { // "wan"
				int delta = 0;
				RAnalOp analop;
				ut64 at = core->addr;
repeat:
				if (!r_anal_op (core->anal, &analop, at, core->block + delta, core->blocksize - delta, R_ARCH_OP_MASK_BASIC)) {
					R_LOG_ERROR ("Invalid instruction?");
					r_anal_op_fini (&analop);
					r_asm_code_free (acode);
					break;
				}
				if (delta < acode->len) {
					delta += analop.size;
					at += analop.size;
					r_anal_op_fini (&analop);
					r_core_cmdf (core, "wao nop @ 0x%08"PFMT64x, at);
					goto repeat;
				}
				r_anal_op_fini (&analop);
				r_core_cmd_call (core, "wao nop");
				input++;
			} else if (input[0] == 'i') { // "wai"
				RAnalOp analop;
				if (!r_anal_op (core->anal, &analop, core->addr, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC)) {
					R_LOG_ERROR ("Invalid instruction?");
					r_anal_op_fini (&analop);
					r_asm_code_free (acode);
					break;
				}
				if (analop.size < acode->len) {
					R_LOG_ERROR ("Patch doesnt fit");
					r_anal_op_fini (&analop);
					r_asm_code_free (acode);
					break;
				}
				r_anal_op_fini (&analop);
				r_core_cmd_call (core, "wao nop");
			}
			if (acode->len > 0) {
				char* hex = r_asm_code_get_hex (acode);
				if (input[0] == '*') {
					r_cons_printf (core->cons, "wx %s\n", hex);
				} else {
					if (!r_core_write_at (core, core->addr, acode->bytes, acode->len)) {
						cmd_write_fail (core);
					} else {
						if (r_config_get_b (core->config, "scr.prompt")) { // maybe check interactive?
							const char *arg = r_str_trim_head_ro (input + 1);
							R_LOG_INFO ("Written %d byte(s) (%s) = wx %s @ 0x%08"PFMT64x, acode->len, arg, hex, core->addr);
						}
						WSEEK (core, acode->len);
					}
					r_core_block_read (core);
				}
				free (hex);
			} else {
				R_LOG_WARN ("Nothing to do");
			}
			if (*input == '+') {
				r_core_seek (core, core->addr + acode->len, true);
			}
			r_asm_code_free (acode);
		}
		}
		break;
	case 'f': // "waf"
		if ((input[1] == ' ' || input[1] == '*')) {
			const char *file = input + ((input[1] == '*')? 3: 2);
			r_asm_set_pc (core->rasm, core->addr);

			char *src = r_file_slurp (file, NULL);
			if (src) {
				ut64 addr = core->addr, nextaddr = addr;
				char *a, *b = src;
				do {
					a = strstr (b, ".offset ");
					if (a) {
						*a = 0;
						a += strlen (".offset ");
						nextaddr = r_num_math (core->num, a);
						char *nl = strchr (a, '\n');
						if (nl) {
							*nl = 0;
							a = nl + 1;
						} else {
							break;
						}
					}
					if (*b) {
						RAsmCode *ac = r_asm_assemble (core->rasm, b);
						if (ac) {
							r_io_write_at (core->io, addr, ac->bytes, ac->len);
							r_asm_code_free (ac);
						}
					}
					b = a;
					addr = nextaddr;
				} while (a);
				free (src);
			} else {
				R_LOG_ERROR ("Cannot open '%s'", file);
			}
		} else {
			R_LOG_ERROR ("Wrong argument");
		}
		break;
	case 'F': // "waF"
		if ((input[1] == ' ' || input[1] == '*')) {
			const char *file = input + ((input[1] == '*')? 3: 2);
			r_asm_set_pc (core->rasm, core->addr);
			char *f = r_file_slurp (file, NULL);
			if (f) {
				RAsmCode *acode = r_asm_assemble (core->rasm, f);
				if (acode) {
					char* hex = r_asm_code_get_hex (acode);
					if (input[1] == '*') {
						r_cons_printf (core->cons, "wx %s\n", hex);
					} else {
						if (r_config_get_b (core->config, "scr.prompt")) {
							R_LOG_INFO ("Written %d byte(s) (%s)=wx %s", acode->len, input, hex);
						}
						if (!r_core_write_at (core, core->addr, acode->bytes, acode->len)) {
							cmd_write_fail (core);
						} else {
							WSEEK (core, acode->len);
						}
						r_core_block_read (core);
					}
					free (hex);
					r_asm_code_free (acode);
				} else {
					R_LOG_ERROR ("Cannot assemble file");
				}
			} else {
				R_LOG_ERROR ("Cannot slurp '%s'", file);
			}
		} else {
			R_LOG_ERROR ("Wrong argument");
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_wa);
		break;
	}
	return 0;
}

static int cmd_wb(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int uil = strlen (input);
	char c;
	int i;

	// Check that user provided some input
	if (uil == 0) {
		r_core_cmd_help_match (core, help_msg_w, "wb");
		return 0;
	}

	// Check that user input only contains binary data
	for (i = 0; i < uil; i++) {
		c = input[i];
		// Ignore whitespaces
		if (isspace(c)) {
			continue;
		}
		// Check that user input only contains ones and zeros
		if (c != '0' && c != '1') {
			R_LOG_ERROR ("wb operates only on binary data");
			return 0;
		}
	}

	// Iterate user input bitwise and write output every 8 bits
	int bits_read = 0;
	int block_offset = 0;
	ut8 byte = 0;
	for (i = 0; i < uil; i++) {
		// Read a bit
		c = input[i];

		// Ignore whitespaces
		if (isspace(c)) {
			continue;
		}

		if (c == '1') {
			// Bits are read and bytes constructed from most to
			// least significant.
			byte |= (1 << (7 - bits_read));
		}
		bits_read++;

		// Write a byte if we've read 8 bits
		if (bits_read % 8 == 0) {
			r_io_write_at (
				core->io,
				core->addr + block_offset,
				&byte,
				1
			);
			block_offset++;
			bits_read = 0;
			byte = 0;
		}
	}

	// Write any possible remaining ui bits
	if (bits_read != 0) {
		ut8 b = core->block[block_offset];
		// Shift left and right to zero bits_read most significant bits
		b <<= bits_read;
		b >>= bits_read;
		// Overwrite bits_read most significant bits and keep the rest
		b |= byte;
		r_io_write_at (core->io, core->addr + block_offset, &b, 1);
	}

	return 0;
}

static int cmd_wX(void *data, const char *input) {
	RCore *core = (RCore *)data;
	size_t len = strlen (input);
	const size_t buf_size = len + 2;
	ut8 *buf = malloc (buf_size);
	if (!buf) {
		return 0;
	}
	int slen = r_hex_str2bin (input, buf);
	if (slen > 0) {
		r_mem_copyloop (core->block, buf, core->blocksize, slen);
		if (!r_core_write_at (core, core->addr, core->block, core->blocksize)) {
			cmd_write_fail (core);
		} else {
			WSEEK (core, core->blocksize);
		}
		r_core_block_read (core);
	} else {
		R_LOG_ERROR ("Wrong argument");
	}
	free (buf);
	return 0;
}

static int cmd_wm(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *str = strdup (input);
	int size = r_hex_str2bin (input, (ut8 *)str);
	switch (input[0]) {
	case '\0':
		R_LOG_TODO ("Display current write mask");
		break;
	case '?':
		break;
	case '-':
		r_io_set_write_mask (core->io, 0, 0);
		R_LOG_INFO ("Write mask disabled");
		break;
	case ' ':
		if (size > 0) {
			r_io_use_fd (core->io, core->io->desc->fd);
			r_io_set_write_mask (core->io, (const ut8 *)str, size);
			WSEEK (core, size);
			eprintf ("Write mask set to '");
			size_t i;
			for (i = 0; i < size; i++) {
				eprintf ("%02x", str[i]);
			}
			eprintf ("'\n");
		} else {
			R_LOG_ERROR ("Invalid string");
		}
		break;
	}
	free (str);
	return 0;
}

static int cmd_wd(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] && input[0] == ' ') {
		char *arg, *inp = strdup (input + 1);
		arg = strchr (inp, ' ');
		if (arg) {
			*arg = 0;
			ut64 addr = r_num_math (core->num, input + 1);
			st64 len = r_num_math (core->num, arg + 1);
			if (len < 1) {
				R_LOG_ERROR ("Invalid length for wd");
				return 0;
			}
			if (len > 0xfffff) {
				R_LOG_TODO ("Region is too large for wd, implement block copy");
				return 0;
			}
			ut8 *data = malloc (len);
			if (data) {
				if (r_io_read_at (core->io, addr, data, len)) {
					if (!r_io_write_at (core->io, core->addr, data, len)) {
						R_LOG_ERROR ("r_io_write_at failed at 0x%08" PFMT64x, core->addr);
					}
				} else {
					R_LOG_ERROR ("r_io_read_at: cannot read bytes");
				}
				free (data);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_w, "wd");
		}
		free (inp);
	} else {
		r_core_cmd_help_match (core, help_msg_w, "wd");
	}
	return 0;
}

static int cmd_ws(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *str = strdup (input);
	if (str && *str) {
		char *arg = str;
		int pss = 1;
		int maxlen = 255;
		if (*str == ' ') {
			arg++;
		} else switch (*str) {
		case '1':
			pss = 1;
			break;
		case '2':
			pss = 2;
			maxlen = UT16_MAX;
			break;
		case '4':
			pss = 4;
			maxlen = UT32_MAX;
			break;
		default:
			pss = 0;
			break;
		}
		arg = strchr (str, ' ');
		if (!arg || !pss) {
			r_core_cmd_help (core, help_msg_ws);
			free (str);
			return 0;
		}
		arg = (char *)r_str_trim_head_ro (arg + 1);
		ut64 len = r_str_unescape ((char *)arg);
		if (len > maxlen) {
			R_LOG_ERROR ("Too large");
		} else {
			ut8 lenbuf[4] = {0};
			// write string length
			switch (pss) {
			case 1:
				r_write_ble8 (lenbuf, len);
				r_io_write_at (core->io, core->addr, lenbuf, 1);
				break;
			case 2:
				r_write_ble16 (lenbuf, len, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config));
				r_io_write_at (core->io, core->addr, lenbuf, 2);
				break;
			case 4:
				r_write_ble32 (lenbuf, len, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->anal->config));
				r_io_write_at (core->io, core->addr, lenbuf, 4);
				break;
			}
			if (!r_core_write_at (core, core->addr + pss, (const ut8 *)arg, len)) {
				cmd_write_fail (core);
			}
			WSEEK (core, len);
			r_core_block_read (core);
		}
	} else {
		r_core_cmd_help (core, help_msg_ws);
	}
	free (str);
	return 0;
}

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input) {
	RCore *core = (RCore *)data;

	if (!input) {
		return 0;
	}

	switch (*input) {
	case '0': // "w0"
		cmd_w0 (data, input + 1);
		break;
	case '8':
		cmd_wx (core, input + 1);
		break;
	case 'i':
		switch (input[1]) {
		case '1': // "w1"
		case '2': // "w2"
		case '4': // "w4"
		case '8': // "w8"
			w_incdec_handler (data, input + 2, input[1] - '0');
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_w, "wi");
			break;
		default:
			r_core_return_invalid_command (core, "wi", input[1]);
			break;
		}
		break;
	case '6': // "w6"
		cmd_w6 (core, input + 1);
		break;
	case 'a': // "wa"
		cmd_wa (core, input + 1);
		break;
	case 'b': // "wb"
		cmd_wb (core, input + 1);
		break;
	case 'X': // "wX"
		cmd_wX (core, input + 1);
		break;
	case 'B': // "wB"
		cmd_wB (data, input + 1);
		break;
	case 'c': // "wc"
		cmd_wc (core, input + 1);
		break;
	case 'h': // "wh"
		if (!strcmp (input, "hoami")) {
			char *ui = r_sys_whoami ();
			r_cons_printf (core->cons, "%s\n", ui);
			free (ui);
		} else {
			cmd_wh (core, input + 1);
		}
		break;
	case 'e': // "we"
		cmd_we (core, input + 1);
		break;
	case 'p': // "wp"
		cmd_wp (core, input + 1);
		break;
	case 'u': // "wu"
		cmd_wu (core, input + 1);
		break;
	case 'r': // "wr"
		cmd_wr (core, input + 1);
		break;
#if 0
	case 'A': // "wA"
		cmd_wA (core, input + 1);
		break;
#endif
	case ' ': // "w"
	case '+': // "w+"
	{
		size_t len = core->blocksize;
		const char *curcs = r_config_get (core->config, "cfg.charset");
		char *str = strdup (input);

#if !SHELLFILTER
		r_str_trim_args (str);
#endif
		r_str_trim_tail (str);

		ut64 addr = core->addr;
		if (R_STR_ISEMPTY (curcs)) {
			r_core_return_value (core, 0);
			cmd_w (core, str + 1);
			addr += core->num->value;
		} else {
			if (len > 0) {
				size_t in_len = strlen (str + 1);
				int max = core->print->charset->encode_maxkeylen;
				int out_len = in_len * max;
				int new_len = 0;
				ut8 *out = malloc (in_len * max); //suppose in len = out len TODO: change it
				if (out) {
					*out = 0;
					new_len = r_charset_decode_str (core->print->charset, out, out_len, (const ut8*) str + 1, in_len);
					cmd_w (core, (const char *)out);
					free (out);
				}
				addr += new_len;
			}
		}
		free (str);
		if (*input == '+') {
			r_core_seek (core, addr, true);
		}
		break;
	}
	case 'g': // "wg"
		cmd_wget (core, input + 1);
		break;
	case 'z': // "wz"
		cmd_wz (core, input + 1);
		break;
	case 't': // "wt"
		cmd_wt (core, input);
		break;
	case 'f': // "wf"
		cmd_wf (core, input + 1);
		break;
	case 'w': // "ww"
		cmd_ww (core, input + 1);
		break;
	case 'x': // "wx"
		cmd_wx (core, input + 1);
		break;
	case 'm': // "wm"
		cmd_wm (core, input + 1);
		break;
	case 'v': // "wv"
		cmd_write_value (core, input + 1);
		break;
	case 'o': // "wo"
		cmd_wo (core, input + 1);
		break;
	case 'd': // "wd"
		cmd_wd (core, input + 1);
		break;
	case 's': // "ws"
		cmd_ws (core, input + 1);
		break;
	case '?': // "w?"
		r_core_cmd_help (core, help_msg_w);
		break;
	default:
		r_core_return_invalid_command (core, "w", *input);
		break;
	}
	r_core_block_read (core);
	return 0;
}

#endif
