/* radare - LGPL - Copyright 2009-2021 - pancake */

#include "r_crypto.h"
#include "r_config.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_io.h"

static const char *help_msg_w[] = {
	"Usage:","w[x] [str] [<file] [<<EOF] [@addr]","",
	"w","[1248][+-][n]","increment/decrement byte,word..",
	"w"," foobar","write string 'foobar'",
	"w0"," [len]","write 'len' bytes with value 0x00",
	"w6","[de] base64/hex","write base64 [d]ecoded or [e]ncoded string",
	"wa","[?] push ebp","write opcode, separated by ';' (use '\"' around the command)",
	"waf"," f.asm","assemble file and write bytes",
	"waF"," f.asm","assemble file and write bytes and show 'wx' op with hexpair bytes of assembled code",
	"wao","[?] op","modify opcode (change conditional of jump. nop, etc)",
	"wA","[?] r 0","alter/modify opcode at current seek (see wA?)",
	"wb"," 010203","fill current block with cyclic hexpairs",
	"wB","[-]0xVALUE","set or unset bits with given value",
	"wc","[?][jir+-*?]","write cache list/undo/commit/reset (io.cache)",
	"wd"," [off] [n]","duplicate N bytes from offset at current seek (memcpy) (see y?)",
	"we","[?] [nNsxX] [arg]","extend write operations (insert instead of replace)",
	"wf","[fs] -|file","write contents of file at current offset",
	"wh"," r2","whereis/which shell command",
	"wm"," f0ff","set binary mask hexpair to be used as cyclic write mask",
	"wo","[?] hex","write in block with operation. 'wo?' fmi",
	"wp","[?] -|file","apply radare patch file. See wp? fmi",
	"wr"," 10","write 10 random bytes",
	"ws"," pstring","write 1 byte for length and then the string",
	"wt","[?] file [sz]","write to file (from current seek, blocksize or sz bytes)",
	"ww"," foobar","write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'",
	"wx","[?][fs] 9090","write two intel nops (from wxfile or wxseek)",
	"wv","[?] eip+34","write 32-64 bit value honoring cfg.bigendian",
	"wz"," string","write zero terminated string (like w + \\x00)",
	NULL
};

static const char *help_msg_wa[] = {
	"Usage:", "wa[of*] [arg]", "",
	"wa", " nop", "write nopcode using asm.arch and asm.bits",
	"wai", " jmp 0x8080", "write inside this op (fill with nops or error if doesnt fit)",
	"wan", " jmp 0x8080", "write instruction(s) nopping the trailing bytes",
	"wa*", " mov eax, 33", "show 'wx' op with hexpair bytes of assembled opcode",
	"\"wa nop;nop\"", "" , "assemble more than one instruction (note the quotes)",
	"waf", " f.asm" , "assemble file and write bytes",
	"waF"," f.asm","assemble file and write bytes and show 'wx' op with hexpair bytes of assembled code",
	"waF*"," f.asm","assemble file and show 'wx' op with hexpair bytes of assembled code",
	"wao?", "", "show help for assembler operation on current opcode (hack)",
	NULL
};

static const char *help_msg_wA[] = {
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

static const char *help_msg_wc[] = {
	"Usage:", "wc[jir+-*?]","  # NOTE: Uses io.cache=true",
	"wc","","list all write changes",
	"wcj","","list all write changes in JSON",
	"wc-"," [from] [to]","remove write op at curseek or given addr",
	"wc+"," [from] [to]","commit change from cache to io",
	"wc*","","\"\" in radare commands",
	"wcr","","reset all write changes in cache",
	"wci","","commit write cache",
	"wcf"," [file]","commit write cache into given file",
	"wcp"," [fd]", "list all cached write-operations on p-layer for specified fd or current fd",
	"wcp*"," [fd]","list all cached write-operations on p-layer in radare commands",
	"wcpi"," [fd]", "commit and invalidate pcache for specified fd or current fd",
	NULL
};

static const char *help_msg_we[] = {
	"Usage", "", "write extend # resize the file",
	"wen", " <num>", "extend the underlying file inserting NUM null bytes at current offset",
	"weN", " <addr> <len>", "extend current file and insert bytes at address",
	"wes", " <addr>  <dist> <block_size>", "shift a blocksize left or write in the editor",
	"wex", " <hex_bytes>", "insert bytes at current offset by extending the file",
	"weX", " <addr> <hex_bytes>", "insert bytes at address by extending the file",
	NULL
};

static const char *help_msg_wo[] = {
	"Usage:","wo[asmdxoArl24]"," [hexpairs] @ addr[!bsize]",
	"wo[24aAdlmorwx]","", "without hexpair values, clipboard is used",
	"wo2"," [val]","2=  2 byte endian swap (word)",
	"wo4"," [val]", "4=  4 byte endian swap (dword)",
	"wo8"," [val]", "8=  8 byte endian swap (qword)",
	"woa"," [val]", "+=  addition (f.ex: woa 0102)",
	"woA"," [val]","&=  and",
	"wod"," [val]", "/=  divide",
	"woD","[algo] [key] [IV]","decrypt current block with given algo and key",
	"woe"," [from to] [step] [wsz=1]","..  create sequence",
	"woE"," [algo] [key] [IV]", "encrypt current block with given algo and key",
	"woi","", "inverse bytes in current block",
	"wol"," [val]","<<= shift left",
	"wom"," [val]", "*=  multiply",
	"woo"," [val]","|=  or",
	"wop[DO]"," [arg]","De Bruijn Patterns",
	"wor"," [val]", ">>= shift right",
	"woR","","random bytes (alias for 'wr $b')",
	"wos"," [val]", "-=  substraction",
	"wow"," [val]", "==  write looped value (alias for 'wb')",
	"wox"," [val]","^=  xor  (f.ex: wox 0x90)",
	NULL
};

static const char *help_msg_wop[] = {
	"Usage:","wop[DO]"," len @ addr | value",
	"wopD"," len [@ addr]","Write a De Bruijn Pattern of length 'len' at address 'addr'",
	"wopD*"," len [@ addr]","Show wx command that creates a debruijn pattern of a specific length",
	"wopO"," value", "Finds the given value into a De Bruijn Pattern at current offset",
	NULL
};

// TODO
static const char *help_msg_wp[] = {
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

static const char *help_msg_wt[] = {
	"Usage:", "wt[a] file [size]", " Write 'size' bytes in current block to 'file'",
	"wta", " [filename]", "append to 'filename'",
	"wtf", " [filename] [size]", "write to file (see also 'wxf' and 'wf?')",
	"wtf!", " [filename]", "write to file from current address to eof",
	"wtff", " [prefix]", "write block from current seek to [prefix]-[offset]",
	"wts"," host:port [sz]", "send data to remote host:port via tcp://",
	NULL
};

static const char *help_msg_wf[] = {
	"Usage:", "wf[fs] [-|args ..]", " Write from (file, swap, offset)",
	"wf", " 10 20", "write 20 bytes from offset 10 into current seek",
	"wff", " file [len]", "write contents of file into current offset",
	"wfs", " host:port [len]", "write from socket (tcp listen in port for N bytes)",
	"wfx", " 10 20", "exchange 20 bytes betweet current offset and 10",
	NULL
};

static const char *help_msg_wv[] = {
	"Usage:", "wv[size] [value]", " Write value of given size",
	"wv", " 0x834002", "write dword with this value",
	"wv1", " 234", "write one byte with this value",
	"wv2", " 234", "write unsigned short (2 bytes) with this number",
	"wv4", " 1 2 3", "write N space-separated dword (4 bytes)",
	"wv8", " 234", "write qword (8 bytes) with this number",
	"wvf", " 3.14", "write float value (4 bytes)",
	"wvF", " 3.14", "write double value (8 bytes)",
	"wvG", " 3.14", "write long double value (10/16 bytes)",
	"Supported sizes are:", "1, 2, 4, 8", "",
	NULL
};

static const char *help_msg_wx[] = {
	"Usage:", "wx[f] [arg]", "",
	"wx", " 9090", "write two intel nops",
	"wxf", " -|file", "write contents of hexpairs file here",
	"wxs", " 9090", "write hexpairs and seek at the end",
	NULL
};

static void cmd_write_fail(RCore *core) {
	eprintf ("ERROR: Cannot write in here, check map permissions or reopen the file with oo+\n");
	core->num->value = 1;
}

R_API int cmd_write_hexpair(RCore* core, const char* pairs) {
	r_return_val_if_fail (core && pairs, 0);
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
		core->num->value = 0;
		if (!r_core_write_at (core, core->offset, buf, len)) {
			cmd_write_fail (core);
			core->num->value = 1;
		}
		if (r_config_get_i (core->config, "cfg.wseek")) {
			r_core_seek_delta (core, len);
		}
		r_core_block_read (core);
	} else {
		eprintf ("Error: invalid hexpair string\n");
		core->num->value = 1;
	}
	free (buf);
	return len;
}

static bool encrypt_or_decrypt_block(RCore *core, const char *algo, const char *key, int direction, const char *iv) {
	//TODO: generalise no_key_mode for all non key encoding/decoding.
	int keylen = 0;
	bool no_key_mode = !strcmp ("base64", algo) || !strcmp ("base91", algo) || !strcmp ("punycode", algo);
	ut8 *binkey = NULL;
	if (!strncmp (key, "s:", 2)) {
		binkey = (ut8*)strdup (key + 2);
		keylen = strlen (key + 2);
	} else {
		binkey = (ut8 *)strdup (key);
		keylen = r_hex_str2bin (key, binkey);
	}
	if (!binkey) {
		eprintf ("Cannot allocate %d byte(s)\n", keylen);
		return false;
	}
	if (!no_key_mode && keylen < 1) {
		eprintf ("%s key not defined. Use -S [key]\n", ((!direction)? "Encryption": "Decryption"));
		free (binkey);
		return false;
	}
	RCrypto *cry = r_crypto_new ();
	if (r_crypto_use (cry, algo)) {
		if (r_crypto_set_key (cry, binkey, keylen, 0, direction)) {
			if (iv) {
				ut8 *biniv = malloc (strlen (iv) + 1);
				int ivlen = r_hex_str2bin (iv, biniv);
				if (ivlen < 1) {
					ivlen = strlen(iv);
					strcpy ((char *)biniv, iv);
				}
				if (!r_crypto_set_iv (cry, biniv, ivlen)) {
					eprintf ("Invalid IV.\n");
					return 0;
				}
			}
			r_crypto_update (cry, (const ut8*)core->block, core->blocksize);

			int result_size = 0;
			ut8 *result = r_crypto_get_output (cry, &result_size);
			if (result) {
				if (!r_core_write_at (core, core->offset, result, result_size)) {
					eprintf ("r_core_write_at failed at 0x%08"PFMT64x"\n", core->offset);
				}
				eprintf ("Written %d byte(s)\n", result_size);
				free (result);
			}
		} else {
			eprintf ("Invalid key\n");
		}
		free (binkey);
		r_crypto_free (cry);
		return 0;
	} else {
		eprintf ("Unknown %s algorithm '%s'\n", ((!direction) ? "encryption" : "decryption") ,algo);
	}
	r_crypto_free (cry);
	return 1;
}

static void cmd_write_bits(RCore *core, int set, ut64 val) {
	ut64 ret, orig;
	// used to set/unset bit in current address
	r_io_read_at (core->io, core->offset, (ut8*)&orig, sizeof (orig));
	if (set) {
		ret = orig | val;
	} else {
		ret = orig & (~(val));
	}
	if (!r_core_write_at (core, core->offset, (const ut8*)&ret, sizeof (ret))) {
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
	if (!r_core_write_at (core, core->offset, core->block, size)) {
		cmd_write_fail (core);
	}
}

static int wo_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut8 *buf;
	int len;
	int value;
	switch (input[0]) {
	case 'e': // "woe"
		if (input[1]!=' ') {
			r_cons_printf ("Usage: 'woe from-to step'\n");
			return -1;
		}
		/* fallthru */
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
		if (input[1]) {  // parse val from arg
			r_core_write_op (core, r_str_trim_head_ro (input + 2), input[0]);
		} else {  // use clipboard instead of val
			r_core_write_op (core, NULL, input[0]);
		}
		r_core_block_read (core);
		break;
	case 'R':
		r_core_cmd0 (core, "wr $b");
		break;
	case 'n':
		r_core_write_op (core, "ff", 'x');
		r_core_block_read (core);
		break;
	case 'E': // "woE" encrypt
	case 'D': // "woD" decrypt
		{
			int direction = (input[0] == 'E') ? 0 : 1;
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
			if (algo && *algo && key) {
				encrypt_or_decrypt_block (core, algo, key, direction, iv);
			} else {
				eprintf ("Usage: wo%c [algo] [key] [IV]\n", ((!direction)?'E':'D'));
				eprintf ("Currently supported hashes:\n");
				ut64 bits;
				int i;
				for (i = 0; ; i++) {
					bits = ((ut64)1) << i;
					const char *name = r_hash_name (bits);
					if R_STR_ISEMPTY (name) {
						break;
					}
					printf ("  %s\n", name);
				}
				eprintf ("Available Encoders/Decoders: \n");
				for (i = 0; ; i++) {
					bits = (1ULL) << i;
					const char *name = r_crypto_codec_name ((const RCryptoSelector)bits);
					if (R_STR_ISEMPTY (name)) {
						break;
					}
					printf ("  %s\n", name);
				}
				eprintf ("Currently supported crypto algos:\n");
				for (i = 0; ; i++) {
					bits = (1ULL) << i;
					const char *name = r_crypto_name ((const RCryptoSelector)bits);
					if R_STR_ISEMPTY (name) {
						break;
					}
					printf ("  %s\n", name);
				}
			}
			free (args);
		}
		break;
	case 'p': // debrujin patterns
		switch (input[1]) {
		case 'D': // "wopD"
			{
				char *sp = strchr (input, ' ');
				len = sp?  r_num_math (core->num, sp + 1): core->blocksize;
			}
			if (len > 0) {
				/* XXX This seems to fail at generating long patterns (wopD 512K) */
				buf = (ut8*)r_debruijn_pattern (len, 0, NULL); //debruijn_charset);
				if (buf) {
					const ut8 *ptr = buf;
					ut64 addr = core->offset;
					if (input[2] == '*') {
						int i;
						r_cons_printf ("wx ");
						for (i = 0; i < len; i++) {
							r_cons_printf ("%02x", buf[i]);
						}
						r_cons_newline ();
					} else {
						if (!r_core_write_at (core, addr, ptr, len)) {
							cmd_write_fail (core);
						}
					}
					free (buf);
				} else {
					eprintf ("Couldn't generate pattern of length %d\n", len);
				}
			}
			break;
		case 'O': // "wopO"
			if (strlen (input) > 3 && strncmp (input + 3, "0x", 2)) {
				eprintf ("Need hex value with `0x' prefix e.g. 0x41414142\n");
			} else if (input[2] == ' ') {
				value = r_num_get (core->num, input + 3);
				core->num->value = r_debruijn_offset (value, r_config_get_i (core->config, "cfg.bigendian"));
				r_cons_printf ("%"PFMT64d"\n", core->num->value);
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

#define WSEEK(x,y) if (wseek)r_core_seek_delta (x,y)
static void cmd_write_value_float(RCore *core, const char *input) {
	float v = 0.0;
	sscanf (input, "%f", &v);
	r_io_write_at (core->io, core->offset, (const ut8*)&v, sizeof (float));
}

static void cmd_write_value_long_double(RCore *core, const char *input) {
	long double v = 0.0;
	sscanf (input, "%Lf", &v);
	r_io_write_at (core->io, core->offset, (const ut8*)&v, sizeof (long double));
}

static void cmd_write_value_double(RCore *core, const char *input) {
	double v = 0.0;
	sscanf (input, "%lf", &v);
	r_io_write_at (core->io, core->offset, (const ut8*)&v, sizeof (double));
}

static void cmd_write_value(RCore *core, const char *input) {
	int type = 0;
	ut64 off = 0LL;
	ut8 buf[sizeof(ut64)];
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	bool be = r_config_get_i (core->config, "cfg.bigendian");

	core->num->value = 0;

	switch (input[0]) {
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
	case '1': type = 1; break;
	case '2': type = 2; break;
	case '4': type = 4; break;
	case '8': type = 8; break;
	}
	ut64 addr = core->offset;
	char *inp = r_str_trim_dup (input + 1);
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
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	char *p, *a = r_str_trim_dup (arg);
	p = strchr (a, ' ');
	if (p) {
		*p++ = 0;
	}

	if (*arg =='?' || !*arg) {
		eprintf ("Usage: wf [file] ([size] ([offset]))\n");
	} else if (!strcmp (arg, "-")) {
		char *out = r_core_editor (core, NULL, NULL);
		if (out) {
			if (!r_io_write_at (core->io, core->offset,
				(ut8*)out, strlen (out))) {
					eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
			}
			r_core_block_read (core);
			free (out);
		}
	}
	
	if (*a == '$') {
		const char *res = r_cmd_alias_get (core->rcmd, a, 1);
		if (res) {
			buf = (ut8*)strdup (res);
			size = strlen (res);
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
				eprintf ("Invalid offset\n");
				free (a);
				free (buf);
				return false;
			}
		}
		r_io_use_fd (core->io, core->io->desc->fd);
		if (!r_io_write_at (core->io, core->offset, buf + u_offset, (int)u_size)) {
			eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
		}
		WSEEK (core, size);
		r_core_block_read (core);
	} else {
		eprintf ("Cannot open file '%s'\n", arg);
	}
	free (a);
	free (buf);
	return true;
}

static bool ioMemcpy (RCore *core, ut64 dst, ut64 src, int len) {
	bool ret = false;
	if (len > 0) {
		ut8 * buf = calloc (1, len);
		if (buf) {
			if (r_io_read_at (core->io, src, buf, len)) {
				if (r_io_write_at (core->io, dst, buf, len)) {
					r_core_block_read (core);
					ret = true;
				} else {
					eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", dst);
				}
			} else {
				eprintf ("r_io_read_at failed at 0x%08"PFMT64x"\n", src);
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
	ut64 dst = core->offset;
	ut64 src = r_num_math (core->num, args);
	if (len > 0) {
		// cache dest, memcpy, write cache
		ut8 *buf = calloc (1, len);
		if (buf) {
			if (r_io_read_at (core->io, dst, buf, len)) {
				ioMemcpy (core, core->offset, src, len);
				if (r_io_write_at (core->io, src, buf, len)) {
					r_core_block_read (core);
				} else {
					eprintf ("Failed to write at 0x%08"PFMT64x"\n", src);
				}
			} else {
				eprintf ("cmd_wfx: failed to read at 0x%08"PFMT64x"\n", dst);
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
		eprintf ("Usage wfs host:port [sz]\n");
		free (str);
		return false;
	}
	ut64 addr = 0;
	char *host = str + 1;
	char *port = strchr (host, ':');
	if (!port) {
		eprintf ("Usage wfs host:port [sz]\n");
		free (str);
		return false;
	}
	ut64 sz = core->blocksize;
	*port ++= 0;
	char *space = strchr (port, ' ');
	if (space) {
		*space++ = 0;
		sz = r_num_math (core->num, space);
		addr = core->offset;
	}
	ut8 *buf = calloc (1, sz);
	if (!buf) {
		free (str);
		return false;
	}
	r_io_read_at (core->io, addr, buf, sz);
	RSocket *s = r_socket_new (false);
	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Cannot listen on port %s\n", port);
		r_socket_free (s);
		free (str);
		free (buf);
		return false;
	}
	int done = 0;
	RSocket *c = r_socket_accept (s);
	if (c) {
		eprintf ("Receiving data from client...\n");
		while (done < sz) {
			int rc = r_socket_read (c, buf + done, sz - done);
			if (rc < 1) {
				eprintf ("oops\n");
				break;
			}
			done += rc;
		}
		r_socket_free (c);
		if (r_io_write_at (core->io, core->offset, buf, done)) {
			eprintf ("Written %d bytes\n", done);
		} else {
			cmd_write_fail (core);
		}
	}
	r_socket_free (s);
	free (buf);
	free (str);
	return true;
}

static int wf_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (!core || !*input) {
		return -1;
	}
	if (input[0] == '?') {
		eprintf ("Usage: wf [file] ([size] ([offset]))\n");
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
	ioMemcpy (core, core->offset, addr, len);
	free (args);
	r_core_block_read (core);
	return 0;
}

static void cmd_write_pcache(RCore *core, const char *input) {
	RIODesc *desc;
	RIOCache *c;
	RList *caches;
	RListIter *iter;
	int fd, i;
	bool rad = false;
	if (core && core->io && core->io->p_cache && core->print && core->print->cb_printf) {
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
		case ' ':	//fall-o-through
		case '\0':
			if (input[0] && input[1]) {
				fd = (int)r_num_math (core->num, input + 1);
				desc = r_io_desc_get (core->io, fd);
			} else {
				desc = core->io->desc;
			}
			if ((caches = r_io_desc_cache_list (desc))) {
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
				r_list_free (caches);
			}
			break;
		default:
			break;
		}
	}
}

static int wB_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ':
		cmd_write_bits (core, 1, r_num_math (core->num, input + 1));
		break;
	case '-':
		cmd_write_bits (core, 0, r_num_math (core->num, input + 1));
		break;
	default:
		eprintf ("Usage: wB 0x2000  # or wB-0x2000\n");
		break;
	}
	return 0;
}

static int w0_handler_common(RCore *core, ut64 len) {
	int res = 0;
	if (len > 0) {
		ut8 *buf = calloc (1, len);
		if (buf) {
			if (!r_io_write_at (core->io, core->offset, buf, len)) {
				eprintf ("r_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
				res = -1;
			}
			r_core_block_read (core);
			free (buf);
		} else {
			eprintf ("Cannot allocate %d byte(s)\n", (int)len);
			res = -1;
		}
	}
	return res;
}

static int w0_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 len = r_num_math (core->num, input);
	return w0_handler_common (core, len);
}

static int w_incdec_handler_old(void *data, const char *input, int inc) {
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
		eprintf ("Usage: w[1248][+-][num]   # inc/dec byte/word/..\n");
	}
	return 0;
}

static int w6_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	int fail = 0;
	ut8 *buf = NULL;
	int len = 0, str_len;
	const char *str;

	if (input[0] && input[1] != ' ')
		fail = 1;

	if (input[0] && input[1] && input[2])
		str = input + 2;
	else
		str = "";
	str_len = strlen (str) + 1;
	if (!fail) {
		switch (input[0]) {
		case 'd': // "w6d"
			buf = malloc (str_len);
			if (!buf) {
				eprintf ("Error: failed to malloc memory");
				break;
			}
			len = r_base64_decode (buf, str, -1);
			if (len < 0) {
				free (buf);
				fail = 1;
			}
			break;
		case 'e': { // "w6e"
			ut8 *bin_buf = malloc (str_len);
			if (!bin_buf) {
				eprintf ("Error: failed to malloc memory");
				break;
			}
			const int bin_len = r_hex_str2bin (str, bin_buf);
			if (bin_len <= 0) {
				fail = 1;
			} else {
				buf = calloc (str_len + 1, 4);
				len = r_base64_encode ((char *)buf, bin_buf, bin_len);
				if(len == 0) {
					free (buf);
					fail = 1;
				}
			}
			free (bin_buf);
			break;
		}
		default:
			fail = 1;
			break;
		}
	}
	if (!fail) {
		if (!r_core_write_at (core, core->offset, buf, len)) {
			cmd_write_fail (core);
		}
		WSEEK (core, len);
		r_core_block_read (core);
		free (buf);
	} else {
		eprintf ("Usage: w6[de] base64/hex\n");
	}
	return 0;
}

static int wh_handler_old(void *data, const char *input) {
	char *p = strchr (input, ' ');
	if (p) {
		while (*p == ' ')
			p++;
		p = r_file_path (p);
		if (p) {
			r_cons_println (p);
			free (p);
		}
	}
	return 0;
}

static int we_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 addr = 0, len = 0, b_size = 0;
	st64 dist = 0;
	ut8* bytes = NULL;
	int cmd_suc = false;
	char *input_shadow = NULL, *p = NULL;

	switch (input[0]) {
	case 'n': // "wen"
		if (input[1] == ' ') {
			len = *input ? r_num_math (core->num, input + 2) : 0;
			if (len > 0) {
				const ut64 cur_off = core->offset;
				cmd_suc = r_core_extend_at (core, core->offset, len);
				if (cmd_suc) {
					core->offset = cur_off;
					r_core_block_read (core);
				} else {
					eprintf ("r_io_extend failed\n");
					cmd_suc = true;
				}
			}
		} else {
			eprintf ("Usage: wen [len]\n");
			cmd_suc = true;
		}
		break;
	case 'N': // "weN"
		if (input[1] == ' ') {
			input += 2;
			while (*input && *input == ' ') input++;
			addr = r_num_math (core->num, input);
			while (*input && *input != ' ') input++;
			input++;
			len = *input ? r_num_math (core->num, input) : 0;
			if (len > 0){
				ut64 cur_off = core->offset;
				cmd_suc = r_core_extend_at (core, addr, len);
				if (cmd_suc) {
					r_core_seek (core, cur_off, true);
					core->offset = addr;
					r_core_block_read (core);
				} else {
					eprintf ("r_io_extend failed\n");
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
				ut64 cur_off = core->offset;
				cmd_suc = r_core_extend_at (core, cur_off, len);
				if (cmd_suc) {
					if (!r_core_write_at (core, cur_off, bytes, len)) {
						cmd_write_fail (core);
					}
				}
				core->offset = cur_off;
				r_core_block_read (core);
			}
			free (bytes);
		}
		break;
	case 's': // "wes"
		input +=  2;
		while (*input && *input == ' ') {
			input++;
		}
		len = strlen (input);

		// since the distance can be negative,
		// the r_num_math will perform an unwanted operation
		// the solution is to tokenize the string :/
		if (len > 0) {
			input_shadow = strdup (input);
			p = strtok (input_shadow, " ");
			addr = p && *p ? r_num_math (core->num, p) : 0;

			p = strtok (NULL, " ");
			dist = p && *p ? r_num_math (core->num, p) : 0;

			p = strtok (NULL, " ");
			b_size = p && *p ? r_num_math (core->num, p) : 0;
			if (dist != 0){
				r_core_shift_block (core, addr, b_size, dist);
				r_core_seek (core, addr, true);
				cmd_suc = true;
			}
		}
		free (input_shadow);
		break;
	case 'X': // "weX"
		if (input[1] == ' ') {
			addr = r_num_math (core->num, input+2);
			input += 2;
			while (*input && *input != ' ') input++;
			input++;
			len = *input ? strlen (input) : 0;
			bytes = len > 1? malloc (len+1) : NULL;
			len = bytes ? r_hex_str2bin (input, bytes) : 0;
			if (len > 0) {
				//ut64 cur_off = core->offset;
				cmd_suc = r_core_extend_at (core, addr, len);
				if (cmd_suc) {
					if (!r_core_write_at (core, addr, bytes, len)) {
						cmd_write_fail (core);
					}
				} else {
					eprintf ("r_io_extend failed\n");
				}
				core->offset = addr;
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

static int wp_handler_old(void *data, const char *input) {
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

static int wu_handler_old(void *data, const char *input) {
	// TODO: implement it in an API RCore.write_unified_hexpatch() is ETOOLONG
	if (input[0]==' ') {
		char *data = r_file_slurp (input+1, NULL);
		if (data) {
			int i;
			char sign = ' ';
			int line = 0, offs = 0, hexa = 0;
			int newline = 1;
			for (i=0; data[i]; i++) {
				switch (data[i]) {
				case '+':
					if (newline)
						sign = 1;
					break;
				case '-':
					if (newline) {
						sign = 0;
						offs = i + ((data[i+1]==' ')?2:1);
					}
					break;
				case ' ':
					data[i] = 0;
					if (sign) {
						if (!line) line = i+1;
						else
						if (!hexa) hexa = i+1;
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
							r_cons_printf ("wx %s @ %s\n", data+hexa, data+offs);
						} else eprintf ("food\n");
						offs = 0;
						line = 0;
					} else hexa = 0;
					sign = -1;
					continue;
				}
				newline = 0;
			}
			free (data);
		}
	} else {
		eprintf ("|Usage: wu [unified-diff-patch]    # see 'cu'\n");
	}
	return 0;
}

static int wr_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	ut64 off = r_num_math (core->num, input);
	int len = (int)off;
	if (len > 0) {
		ut8 *buf = malloc (len);
		if (buf != NULL) {
			int i;
			r_num_irand ();
			for (i = 0; i < len; i++)
				buf[i] = r_num_rand (256);
			if (!r_core_write_at (core, core->offset, buf, len)) {
				cmd_write_fail (core);
			}
			WSEEK (core, len);
			free (buf);
		} else
			eprintf ("Cannot allocate %d byte(s)\n", len);
	}
	return 0;
}

static int wA_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	int len;
	switch (input[0]) {
	case ' ':
		if (input[1] && input[2] == ' ') {
			r_asm_set_pc (core->rasm, core->offset);
			eprintf ("modify (%c)=%s\n", input[1], input + 3);
			len = r_asm_modify (core->rasm, core->block, input[1],
				r_num_math (core->num, input + 3));
			eprintf ("len=%d\n", len);
			if (len > 0) {
				if (!r_core_write_at (core, core->offset, core->block, len)) {
					cmd_write_fail (core);
				}
				WSEEK (core, len);
			} else
				eprintf ("r_asm_modify = %d\n", len);
		} else
			eprintf ("Usage: wA [type] [value]\n");
		break;
	case '?':
	default:
		r_core_cmd_help (core, help_msg_wA);
		break;
	}
	return 0;
}

static char *__current_filename(RCore *core) {
	RIOMap *map = r_io_map_get_at (core->io, core->offset);
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
		eprintf ("Cannot determine source file.\n");
		return;
	}
	size_t sfs;
	ut8 *sfb = (ut8*)r_file_slurp (sfn, &sfs);
	if (sfb) {
		void **iter;
		r_pvector_foreach (&core->io->cache, iter) {
			RIOCache *c = *iter;
			const ut64 ps = r_itv_size (c->itv);
			const ut64 va = r_itv_begin (c->itv);
			const ut64 pa = __va2pa (core, va);
			if (pa + ps < sfs) {
				memcpy (sfb + pa, c->data, ps);
			} else {
				eprintf ("Out of bounds patch at 0x%08"PFMT64x"\n", pa);
			}
		}
		// patch buffer
		r_file_dump (dfn, sfb, sfs, false);
		free (sfb);
	}
	free (sfn);
}

static int wc_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0': // "wc"
		//if (!r_config_get_i (core->config, "io.cache"))
		//	eprintf ("[warning] e io.cache must be true\n");
		r_io_cache_list (core->io, 0);
		break;
	case '?': // "wc?"
		r_core_cmd_help (core, help_msg_wc);
		break;
	case 'f': // "wcf"
		if (input[1] == ' ') {
			cmd_wcf (core, r_str_trim_head_ro (input + 1));
		} else {
			eprintf ("Usage: wcf [file]\n");
		}
		break;
	case '*': // "wc*"
		r_io_cache_list (core->io, 1);
		break;
	case '+': // "wc+"
		if (input[1]=='*') { // "wc+*"
			//r_io_cache_reset (core->io, core->io->cached);
			eprintf ("TODO\n");
		} else if (input[1]==' ') { // "wc+ "
			char *p = strchr (input + 2, ' ');
			ut64 to, from;
			from = r_num_math (core->num, input+2);
			if (p) {
				*p = 0;
				to = r_num_math (core->num, input+2);
				if (to < from) {
					eprintf ("Invalid range (from>to)\n");
					return 0;
				}
			} else {
				to = from + core->blocksize;
			}
			r_io_cache_commit (core->io, from, to);
		} else {
			eprintf ("Invalidate write cache at 0x%08"PFMT64x"\n", core->offset);
			r_io_cache_commit (core->io, core->offset, core->offset+1);
		}
		break;
	case '-': { // "wc-"
		if (input[1]=='*') { // "wc-*"
			r_io_cache_reset (core->io, core->io->cached);
			break;
		}
		ut64 from, to;
		if (input[1]==' ') { // "wc- "
			char *p = strchr (input+2, ' ');
			if (p) {
				*p = 0;
				from = r_num_math (core->num, input+2);
				to = r_num_math (core->num, p+1);
				if (to < from) {
					eprintf ("Invalid range (from>to)\n");
					return 0;
				}
			} else {
				from = r_num_math (core->num, input+2);
				to = from + core->blocksize;
			}
		} else {
			eprintf ("Invalidate write cache at 0x%08"PFMT64x"\n", core->offset);
			from = core->offset;
			to = core->offset + core->blocksize;
		}
		eprintf("invalidated %d cache(s)\n",
			r_io_cache_invalidate (core->io, from, to));
		r_core_block_read (core);
		break;
	}
	case 'i': // "wci"
		r_io_cache_commit (core->io, 0, UT64_MAX);
		r_core_block_read (core);
		break;
	case 'j': // "wcj"
		r_io_cache_list (core->io, 2);
		break;
	case 'p': // "wcp"
		cmd_write_pcache (core, &input[1]);
		break;
	case 'r': // "wcr"
		r_io_cache_reset (core->io, core->io->cached);
		/* Before loading the core block we have to make sure that if
			* the cache wrote past the original EOF these changes are no
			* longer displayed. */
		memset (core->block, 0xff, core->blocksize);
		r_core_block_read (core);
		break;
	}
	return 0;
}

static void w_handler_common(RCore *core, const char *input) {
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	char *str = strdup (input);
	/* write string */
	int len = r_str_unescape (str);
	if (!r_core_write_at (core, core->offset, (const ut8 *)str, len)) {
		cmd_write_fail (core);
	}
	free (str);
	WSEEK (core, len);
	r_core_block_read (core);
}

static int w_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	w_handler_common (core, input);
	return 0;
}

static int wz_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	char *str = strdup (input);
	/* write zero-terminated string */
	int len = r_str_unescape (str);
	if (!r_core_write_at (core, core->offset, (const ut8 *)str + 1, len)) {
		cmd_write_fail (core);
	}
	if (len > 0) {
		core->num->value = len;
	} else {
		core->num->value = 0;
	}
#if 0
		r_io_use_desc (core->io, core->file->desc);
#endif
	WSEEK (core, len + 1);
	r_core_block_read (core);
	return 0;
}

static int wt_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *str = strdup (input);
	char *ostr = str;
	const char *filename = "";
	char _fn[32];
	_fn[0] = 0;
	char *tmp;
	if (*str == 's') { // "wts"
		if (str[1] == ' ') {
			eprintf ("Write to server\n");
			st64 sz = r_io_size (core->io);
			if (sz > 0) {
				ut64 addr = 0;
				char *host = str + 2;
				char *port = strchr (host, ':');
				if (port) {
					*port ++= 0;
					char *space = strchr (port, ' ');
					if (space) {
						*space++ = 0;
						sz = r_num_math (core->num, space);
						addr = core->offset;
					}
					ut8 *buf = calloc (1, sz);
					r_io_read_at (core->io, addr, buf, sz);
					RSocket *s = r_socket_new (false);
					if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
						int done = 0;
						eprintf ("Transfering file to the end-point...\n");
						while (done < sz) {
							int rc = r_socket_write (s, buf + done, sz - done);
							if (rc <1) {
								eprintf ("oops\n");
								break;
							}
							done += rc;
						}
					} else {
						eprintf ("Cannot connect\n");
					}
					r_socket_free (s);
					free (buf);
				} else {
					eprintf ("Usage wts host:port [sz]\n");
				}
			} else {
				eprintf ("Unknown file size\n");
			}
		} else {
			eprintf ("Usage wts host:port [sz]\n");
		}
	} else if (*str == '?' || *str == '\0') {
		r_core_cmd_help (core, help_msg_wt);
		free (ostr);
		return 0;
	} else {
		bool append = false;
		bool toend = false;
		st64 sz = core->blocksize;
		ut64 poff = core->offset;
		if (*str == 'f') { // "wtf"
			str++;
			if (*str == '?') {
				r_core_cmd_help (core, help_msg_wt);
				return 0;
			}
			if (*str == '!') {
				if (str[1] == '?') {
					r_core_cmd_help (core, help_msg_wt);
					return 0;
				}
				RIOMap *map = r_io_map_get_at (core->io, poff);
				toend = true;
				//use physical address
				poff = map ? poff - r_io_map_begin (map) + map->delta : poff;
				str++;
			}
			if (*str == 'f') { // "wtff"
				if (str[1] == '?') {
					r_core_cmd_help (core, help_msg_wt);
					return 0;
				}
				const char *prefix = r_str_trim_head_ro (str + 2);
				if (!*prefix) {
					prefix = "dump";
				}
				str++;
				filename = r_str_newf ("%s-0x%08"PFMT64x, prefix, core->offset);
			} else {
				if (*str) {
					if (str[1] == '?') {
						r_core_cmd_help (core, help_msg_wt);
						return 0;
					}
					filename = r_str_trim_head_ro (str);
				} else {
					filename = "";
				}
			}
		} else if (*str == 'a') { // "wta"
			append = 1;
			str++;
			if (str[0] == ' ') {
				filename = str + 1;
			} else {
				const char* prefix = r_config_get (core->config, "cfg.prefixdump");
				snprintf (_fn, sizeof (_fn), "%s.0x%08"PFMT64x, prefix, poff);
				filename = _fn;
			}
		} else if (*str != ' ') {
			const char* prefix = r_config_get (core->config, "cfg.prefixdump");
			snprintf (_fn, sizeof (_fn), "%s.0x%08"PFMT64x, prefix, poff);
			filename = _fn;
		} else {
			filename = str + 1;
		}
		tmp = *str? strchr (str + 1, ' ') : NULL;
		if (!filename || !*filename) {
			const char* prefix = r_config_get (core->config, "cfg.prefixdump");
			snprintf (_fn, sizeof (_fn), "%s.0x%08"PFMT64x, prefix, poff);
			filename = _fn;
		}
		if (tmp) {
			if (toend) {
				sz = r_io_fd_size (core->io, core->io->desc->fd) - core->offset;
				if (sz < 0) {
					eprintf ("Warning: File size is unknown.");
				}
			} else {
				sz = (st64) r_num_math (core->num, tmp + 1);
				*tmp = 0;
			}
			if ((st64)sz < 1) {
				// wtf?
				sz = 0;
			} else if (!r_core_dump (core, filename, poff, (ut64)sz, append)) {
				sz = -1;
			}
		} else {
			if (toend) {
				sz = r_io_fd_size (core->io, core->io->desc->fd);
				if (sz < 0) {
					eprintf ("Warning: File size is unknown.");
				}
				if (sz != -1 && core->offset <= sz) {
					sz -= core->offset;
					if (!r_core_dump (core, filename, core->offset, (ut64)sz, append)) {
						sz = -1;
					}
				} else {
					sz = -1;
				}
			} else {
				sz = core->blocksize;
				if (*filename == '$') {
					char *data = r_str_ndup ((const char *)core->block, sz);
					r_cmd_alias_set (core->rcmd, filename, data, 1);
					free (data);
				} else {
					if (!r_file_dump (filename, core->block, sz, append)) {
						sz = -1;
					}
				}
			}
		}
		if (sz >= 0) {
			eprintf ("Dumped %"PFMT64d" bytes from 0x%08"PFMT64x" into %s\n",
					sz, poff, filename);
		}
	}
	return 0;
}

static int ww_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	char *str = strdup (input);
	int len = r_str_unescape (str);
	if (len < 1) {
		return 0;
	}
	len++;
	str++;
	len = (len - 1) << 1;
	char *tmp = (len > 0) ? malloc (len + 1) : NULL;
	if (tmp) {
		int i;
		for (i = 0; i < len; i++) {
			if (i % 2)
				tmp[i] = 0;
			else
				tmp[i] = str[i >> 1];
		}
		str = tmp;
		if (core->io->desc) {
			r_io_use_fd (core->io, core->io->desc->fd);
		}
		if (!r_io_write_at (core->io, core->offset, (const ut8 *)str, len)) {
			eprintf ("r_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
		}
		WSEEK (core, len);
		r_core_block_read (core);
		free (tmp);
	} else {
		eprintf ("Cannot malloc %d\n", len);
	}
	return 0;
}

static int wx_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	const char *arg;
	ut8 *buf;
	int size;
	switch (input[0]) {
	case ' ': // "wx "
		cmd_write_hexpair (core, input + 0);
		break;
	case 'f': // "wxf"
		arg = (const char *)(input + ((input[1]==' ')? 2: 1));
		if (!strcmp (arg, "-")) {
			int len;
			ut8 *out;
			char *in = r_core_editor (core, NULL, NULL);
			if (in) {
				out = (ut8 *)strdup (in);
				if (out) {
					len = r_hex_str2bin (in, out);
					if (len > 0) {
						if (!r_io_write_at (core->io, core->offset, out, len)) {
							eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
						}
						core->num->value = len;
					} else {
						core->num->value = 0;
					}
					free (out);
				}
				free (in);
			}
		} else if (r_file_exists (arg)) {
			if ((buf = r_file_slurp_hexpairs (arg, &size))) {
				r_io_use_fd (core->io, core->io->desc->fd);
				if (r_io_write_at (core->io, core->offset, buf, size) > 0) {
					core->num->value = size;
					WSEEK (core, size);
				} else {
					eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
				}
				free (buf);
				r_core_block_read (core);
			} else {
				eprintf ("This file doesnt contains hexpairs\n");
			}
		} else {
			eprintf ("Cannot open file '%s'\n", arg);
		}
		break;
	case 's': // "wxs"
		{
			int len = cmd_write_hexpair (core, input + 1);
			if (len > 0) {
				r_core_seek_delta (core, len);
				core->num->value = len;
			} else {
				core->num->value = 0;
			}
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_wx);
		break;
	}
	return 0;
}

static int wa_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	switch (input[0]) {
	case 'o': // "wao"
		if (input[1] == ' ') {
			char *op = r_str_trim_dup (input + 2);
			if (op) {
				r_core_hack (core, op);
				free (op);
			}
		} else {
			r_core_hack_help (core);
		}
		break;
	case ' ':
	case 'i':
	case 'n':
	case '*': {
		const char *file = r_str_trim_head_ro (input + 1);
		RAsmCode *acode;
		r_asm_set_pc (core->rasm, core->offset);
		acode = r_asm_massemble (core->rasm, file);
		if (acode) {
			if (input[0] == 'n') { // "wan"
				int patchsize = acode->len;
				int delta = 0;
				RAnalOp analop;
				ut64 at = core->offset;
repeat:
				if (!r_anal_op (core->anal, &analop, at, core->block + delta, core->blocksize - delta, R_ANAL_OP_MASK_BASIC)) {
					eprintf ("Invalid instruction?\n");
					break;
				}
				if (delta < acode->len) {
					delta += analop.size;
					at += analop.size;
					patchsize += analop.size;
					r_anal_op_fini (&analop);
					r_core_cmdf (core, "wao nop @ 0x%08"PFMT64x, at);
					goto repeat;
				}
				r_anal_op_fini (&analop);
				r_core_cmd0 (core, "wao nop");
				input++;
			} else if (input[0] == 'i') { // "wai"
				RAnalOp analop;
				if (!r_anal_op (core->anal, &analop, core->offset, core->block, core->blocksize, R_ANAL_OP_MASK_BASIC)) {
					eprintf ("Invalid instruction?\n");
					break;
				}
				if (analop.size < acode->len) {
					eprintf ("Doesnt fit\n");
					r_anal_op_fini (&analop);
					r_asm_code_free (acode);
					break;
				}
				r_anal_op_fini (&analop);
				r_core_cmd0 (core, "wao nop");
			}
			if (acode->len > 0) {
				char* hex = r_asm_code_get_hex (acode);
				if (input[0] == '*') {
					r_cons_printf ("wx %s\n", hex);
				} else {
					if (!r_core_write_at (core, core->offset, acode->bytes, acode->len)) {
						cmd_write_fail (core);
					} else {
						if (r_config_get_i (core->config, "scr.prompt")) {
							eprintf ("Written %d byte(s) (%s) = wx %s\n", acode->len, input+1, hex);
						}
						WSEEK (core, acode->len);
					}
					r_core_block_read (core);
				}
				free (hex);
			} else {
				eprintf ("Nothing to do.\n");
			}
			r_asm_code_free (acode);
		}
	}
		break;
	case 'f': // "waf"
		if ((input[1] == ' ' || input[1] == '*')) {
			const char *file = input + ((input[1] == '*')? 3: 2);
			r_asm_set_pc (core->rasm, core->offset);

			char *src = r_file_slurp (file, NULL);
			if (src) {
				ut64 addr = core->offset, nextaddr = addr;
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
						RAsmCode *ac = r_asm_massemble (core->rasm, b);
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
				eprintf ("Cannot open '%s'\n", file);
			}
		} else {
			eprintf ("Wrong argument\n");
		}
		break;
	case 'F': // "waF"
		if ((input[1] == ' ' || input[1] == '*')) {
			const char *file = input + ((input[1] == '*')? 3: 2);
			r_asm_set_pc (core->rasm, core->offset);
			char *f = r_file_slurp (file, NULL);
			if (f) {
				RAsmCode *acode = r_asm_massemble (core->rasm, f);
				if (acode) {
					char* hex = r_asm_code_get_hex (acode);
					if (input[1] == '*') {
						r_cons_printf ("wx %s\n", hex);
					} else {
						if (r_config_get_i (core->config, "scr.prompt")) {
							eprintf ("Written %d byte(s) (%s)=wx %s\n", acode->len, input, hex);
						}
						if (!r_core_write_at (core, core->offset, acode->bytes, acode->len)) {
							cmd_write_fail (core);
						} else {
							WSEEK (core, acode->len);
						}
						r_core_block_read (core);
					}
					free (hex);
					r_asm_code_free (acode);
				} else {
					eprintf ("Cannot assemble file\n");
				}
			} else {
				eprintf ("Cannot slurp '%s'\n", file);
			}
		} else {
			eprintf ("Wrong argument\n");
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_wa);
		break;
	}
	return 0;
}

static int wb_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	size_t len = strlen (input);
	const size_t buf_size = len + 2;
	ut8 *buf = malloc (buf_size);
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	if (buf) {
		len = r_hex_str2bin (input, buf);
		if (len > 0) {
			r_mem_copyloop (core->block, buf, core->blocksize, len);
			if (!r_core_write_at (core, core->offset, core->block, core->blocksize)) {
				cmd_write_fail (core);
			} else {
				WSEEK (core, core->blocksize);
			}
			r_core_block_read (core);
		} else {
			eprintf ("Wrong argument\n");
		}
		free (buf);
	} else {
		eprintf ("Cannot malloc %zd\n", buf_size);
	}
	return 0;
}

static int wm_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *str = strdup (input);
	int size = r_hex_str2bin (input, (ut8 *)str);
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	switch (input[0]) {
	case '\0':
		eprintf ("TODO: Display current write mask");
		break;
	case '?':
		break;
	case '-':
		r_io_set_write_mask (core->io, 0, 0);
		eprintf ("Write mask disabled\n");
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
			eprintf ("Invalid string\n");
		}
		break;
	}
	return 0;
}

static int wd_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input[0] && input[0] == ' ') {
		char *arg, *inp = strdup (input + 1);
		arg = strchr (inp, ' ');
		if (arg) {
			*arg = 0;
			ut64 addr = r_num_math (core->num, input + 1);
			ut64 len = r_num_math (core->num, arg + 1);
			ut8 *data = malloc (len);
			r_io_read_at (core->io, addr, data, len);
			if (!r_io_write_at (core->io, core->offset, data, len)) {
				eprintf ("r_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
			}
			free (data);
		} else {
			eprintf ("See wd?\n");
		}
		free (inp);
	} else
		eprintf ("Usage: wd [source-offset] [length] @ [dest-offset]\n");
	return 0;
}

static int ws_handler_old(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	char *str = strdup (input);
	if (str && *str && str[1]) {
		int len = r_str_unescape (str + 1);
		if (len > 255) {
			eprintf ("Too large\n");
		} else {
			ut8 ulen = (ut8)len;
			if (!r_core_write_at (core, core->offset, &ulen, 1) ||
				!r_core_write_at (core, core->offset + 1, (const ut8 *)str + 1, len)) {
				cmd_write_fail (core);
			} else {
				WSEEK (core, len);
			}
			r_core_block_read (core);
		}
	} else {
		eprintf ("Too short.\n");
	}
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
		w0_handler_old (data, input + 1);
		break;
	case '1': // "w1"
	case '2': // "w2"
	case '4': // "w4"
	case '8': // "w8"
		w_incdec_handler_old (data, input + 1, *input - '0');
		break;
	case '6': // "w6"
		w6_handler_old (core, input + 1);
		break;
	case 'a': // "wa"
		wa_handler_old (core, input + 1);
		break;
	case 'b': // "wb"
		wb_handler_old (core, input + 1);
		break;
	case 'B': // "wB"
		wB_handler_old (data, input + 1);
		break;
	case 'c': // "wc"
		wc_handler_old (core, input + 1);
		break;
	case 'h': // "wh"
		if (!strcmp (input, "hoami")) {
			char *ui = r_sys_whoami ();
			r_cons_printf ("%s\n", ui);
			free (ui);
		} else {
			wh_handler_old (core, input + 1);
		}
		break;
	case 'e': // "we"
		we_handler_old (core, input + 1);
		break;
	case 'p': // "wp"
		wp_handler_old (core, input + 1);
		break;
	case 'u': // "wu"
		wu_handler_old (core, input + 1);
		break;
	case 'r': // "wr"
		wr_handler_old (core, input + 1);
		break;
	case 'A': // "wA"
		wA_handler_old (core, input + 1);
		break;
	case ' ': // "w"
	{
		size_t len = core->blocksize;
		const char *curcs = r_config_get (core->config, "cfg.charset");
		char *str = strdup (input);

		r_str_trim_args (str);
		r_str_trim_tail (str);

		if (R_STR_ISEMPTY (curcs)) {
			w_handler_old (core, str + 1);
		} else {
			if (len > 0) {
				size_t in_len = strlen (str + 1);
				int max = core->print->charset->encode_maxkeylen;
				int out_len = in_len * max;
				ut8 *out = malloc (in_len * max); //suppose in len = out len TODO: change it
				if (out) {
					*out = 0;
					r_charset_decode_str (core->print->charset, out, out_len, (const ut8*) str + 1, in_len);
					w_handler_old (core, (const char *)out);
					free (out);
				}
			}
		}
		free (str);
		break;
	}
	case 'z': // "wz"
		wz_handler_old (core, input + 1);
		break;
	case 't': // "wt"
		wt_handler_old (core, input + 1);
		break;
	case 'f': // "wf"
		wf_handler_old (core, input + 1);
		break;
	case 'w': // "ww"
		ww_handler_old (core, input + 1);
		break;
	case 'x': // "wx"
		wx_handler_old (core, input + 1);
		break;
	case 'm': // "wm"
		wm_handler_old (core, input + 1);
		break;
	case 'v': // "wv"
		cmd_write_value (core, input + 1);
		break;
	case 'o': // "wo"
		wo_handler_old (core, input + 1);
		break;
	case 'd': // "wd"
		wd_handler_old (core, input + 1);
		break;
	case 's': // "ws"
		ws_handler_old (core, input + 1);
		break;
	default:
	case '?': // "w?"
		r_core_cmd_help (core, help_msg_w);
		break;
	}
	r_core_block_read (core);
	return 0;
}
