/* radare - LGPL - Copyright 2009-2019 - pancake */

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
	"wc","","list all write changes",
	"wc","[?][jir+-*?]","write cache undo/commit/reset/list (io.cache)",
	"wd"," [off] [n]","duplicate N bytes from offset at current seek (memcpy) (see y?)",
	"we","[?] [nNsxX] [arg]","extend write operations (insert instead of replace)",
	"wf","[fs] -|file","write contents of file at current offset",
	"wh"," r2","whereis/which shell command",
	"wm"," f0ff","set binary mask hexpair to be used as cyclic write mask",
	"wo","[?] hex","write in block with operation. 'wo?' fmi",
	"wp","[?] -|file","apply radare patch file. See wp? fmi",
	"wr"," 10","write 10 random bytes",
	"ws"," pstring","write 1 byte for length and then the string",
	"wt[f]","[?] file [sz]","write to file (from current seek, blocksize or sz bytes)",
	"wts"," host:port [sz]", "send data to remote host:port via tcp://",
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
	"wcp"," [fd]", "list all cached write-operations on p-layer for specified fd or current fd",
	"wcp*"," [fd]","list all cached write-operations on p-layer in radare commands",
	"wcpi"," [fd]", "commit and invalidate pcache for specified fd or current fd",
	NULL
};

static const char *help_msg_we[] = {
	"Usage", "", "write extend",
	"wen", " <num>", "insert num null bytes at current offset",
	"weN", " <addr> <len>", "insert bytes at address",
	"wes", " <addr>  <dist> <block_size>", "shift a blocksize left or write in the editor",
	"wex", " <hex_bytes>", "insert bytes at current offset",
	"weX", " <addr> <hex_bytes>", "insert bytes at address",
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
	"wfs", " 10 20", "swap 20 bytes betweet current offset and 10",
	NULL
};

static const char *help_msg_wv[] = {
	"Usage:", "wv[size] [value]", " Write value of given size",
	"wv", " 0x834002", "write dword with this value",
	"wv1", " 234", "write one byte with this value",
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

static void cmd_write_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, w);
	DEFINE_CMD_DESCRIPTOR (core, wa);
	DEFINE_CMD_DESCRIPTOR (core, wA);
	DEFINE_CMD_DESCRIPTOR (core, wc);
	DEFINE_CMD_DESCRIPTOR (core, we);
	DEFINE_CMD_DESCRIPTOR (core, wo);
	DEFINE_CMD_DESCRIPTOR (core, wop);
	DEFINE_CMD_DESCRIPTOR (core, wp);
	DEFINE_CMD_DESCRIPTOR (core, wt);
	DEFINE_CMD_DESCRIPTOR (core, wv);
	DEFINE_CMD_DESCRIPTOR (core, wx);
}

static void cmd_write_fail(RCore *core) {
	eprintf ("Failed to write\n");
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
	if (!no_key_mode && keylen < 1) {
		eprintf ("%s key not defined. Use -S [key]\n", ((!direction) ? "Encryption" : "Decryption"));
		free (binkey);
		return false;
	}
	RCrypto *cry = r_crypto_new ();
	if (r_crypto_use (cry, algo)) {
		if (!binkey) {
			eprintf ("Cannot allocate %d byte(s)\n", keylen);
			r_crypto_free (cry);
			return false;
		}
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
			r_crypto_final (cry, NULL, 0);

			int result_size = 0;
			ut8 *result = r_crypto_get_output (cry, &result_size);
			if (result) {
				if (!r_io_write_at (core->io, core->offset, result, result_size)) {
					eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
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

static void cmd_write_op (RCore *core, const char *input) {
	ut8 *buf;
	int len;
	int value;
	if (!input[0])
		return;
	switch (input[1]) {
	case 'e':
		if (input[2]!=' ') {
			r_cons_printf ("Usage: 'woe from-to step'\n");
			return;
		}
		/* fallthru */
	case 'a':
	case 's':
	case 'A':
	case 'x':
	case 'r':
	case 'l':
	case 'm':
	case 'd':
	case 'o':
	case 'w':
	case '2': // "wo2"
	case '4': // "wo4"
	case '8': // "wo8"
		if (input[2]) {  // parse val from arg
			r_core_write_op (core, input + 3, input[1]);
		} else {  // use clipboard instead of val
			r_core_write_op (core, NULL, input[1]);
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
			int direction = (input[1] == 'E') ? 0 : 1;
			const char *algo = NULL;
			const char *key = NULL;
			const char *iv = NULL;
			char *space, *args = strdup (r_str_trim_head_ro (input+2));
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
					if (!name || !*name) break;
					printf ("  %s\n", name);
				}
				eprintf ("Available Encoders/Decoders: \n");
				// TODO: do not hardcode
				eprintf ("  base64\n");
				eprintf ("  base91\n");
				eprintf ("  punycode\n");
				eprintf ("Currently supported crypto algos:\n");
				for (i = 0; ; i++) {
					bits = ((ut64)1) << i;
					const char *name = r_crypto_name (bits);
					if (!name || !*name) break;
					printf ("  %s\n", name);
				}
			}
			free (args);
		}
		break;
	case 'p': // debrujin patterns
		switch (input[2]) {
		case 'D': // "wopD"
			len = (int)(input[3]==' ')
				? r_num_math (core->num, input + 3)
				: core->blocksize;
			if (len > 0) {
				/* XXX This seems to fail at generating long patterns (wopD 512K) */
				buf = (ut8*)r_debruijn_pattern (len, 0, NULL); //debruijn_charset);
				if (buf) {
					const ut8 *ptr = buf;
					ut64 addr = core->offset;
					if (input[3] == '*') {
						int i;
						r_cons_printf ("wx ");
						for (i = 0; i < len; i++) {
							r_cons_printf ("%02x", buf[i]);
						}
						r_cons_newline ();
					} else {
						while (true) {
							int res = r_core_write_at (core, addr, ptr, len);
							if (res != 0) {
								cmd_write_fail (core);
							}
							if (res < 1 || len == res) {
								break;
							}
							if (res < len) {
								ptr += res;
								len -= res;
								addr += res;
							}
						} 
					}
					free (buf);
				} else {
					eprintf ("Couldn't generate pattern of length %d\n", len);
				}
			}
			break;
		case 'O': // "wopO"
			if (strlen (input) > 4 && strncmp (input + 4, "0x", 2)) {
				eprintf ("Need hex value with `0x' prefix e.g. 0x41414142\n");
			} else if (input[3] == ' ') {
				value = r_num_get (core->num, input + 4);
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
}

#define WSEEK(x,y) if (wseek)r_core_seek_delta (x,y)
static void cmd_write_value (RCore *core, const char *input) {
	int type = 0;
	ut64 off = 0LL;
	ut8 buf[sizeof(ut64)];
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	bool be = r_config_get_i (core->config, "cfg.bigendian");

	core->num->value = 0;
	if (!input) {
		return;
	}

	if (input[0])
	switch (input[1]) {
	case '?':
		r_core_cmd_help (core, help_msg_wv);
		return;
	case '1': type = 1; break;
	case '2': type = 2; break;
	case '4': type = 4; break;
	case '8': type = 8; break;
	}
	if (input && input[0] && input[1] && input[2]) {
		off = r_num_math (core->num, input+2);
	}
	if (core->file) {
		r_io_use_fd (core->io, core->file->fd);
	}
	ut64 res = r_io_seek (core->io, core->offset, R_IO_SEEK_SET);
	if (res == UT64_MAX) return;
	if (type == 0)
		type = (off&UT64_32U)? 8: 4;
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
	r_core_block_read (core);
}

static bool cmd_wff(RCore *core, const char *input) {
	ut8 *buf;
	int size;
	// XXX: file names cannot contain spaces
	const char *arg = input + ((input[1] == ' ') ? 2 : 1);
	int wseek = r_config_get_i (core->config, "cfg.wseek");
	char *p, *a = r_str_trim_dup (arg);
	p = strchr (a, ' ');
	if (p) {
		*p++ = 0;
	}

	if (*arg =='?' || !*arg) {
		eprintf ("Usage: wf [file] ([size] ([offset]))\n");
	}
	if (!strcmp (arg, "-")) {
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
	if ((buf = (ut8*) r_file_slurp (a, &size))) {
		int u_offset = 0;
		int u_size = r_num_math (core->num, p);
		if (u_size < 1) u_size = size;
		if (p) {
			*p++ = 0;
			u_offset = r_num_math (core->num, p);
			if (u_offset > size) {
				eprintf ("Invalid offset\n");
				free (buf);
				return false;
			}
		}
		r_io_use_fd (core->io, core->file->fd);
		if (!r_io_write_at (core->io, core->offset, buf + u_offset, u_size)) {
			eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
		}
		WSEEK (core, size);
		free (buf);
		r_core_block_read (core);
	} else {
		eprintf ("Cannot open file '%s'\n", arg);
	}
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

static bool cmd_wfs(RCore *core, const char *input) {
	char * args = r_str_trim_dup (input + 1);
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
				eprintf ("cmd_wfs: failed to read at 0x%08"PFMT64x"\n", dst);
			}
			free (buf);
		}
	}
	free (args);
	return true;
}

static bool cmd_wf(RCore *core, const char *input) {
	if (!core || !*input) {
		return false;
	}
	if (input[1] == '?') {
		eprintf ("Usage: wf [file] ([size] ([offset]))\n");
		r_core_cmd_help (core, help_msg_wf);
		return false;
	}
	if (input[1] == 's') { // "wfs"
		return cmd_wfs (core, input + 1);
	}
	if (input[1] == 'f') { // "wff"
		return cmd_wff (core, input + 1);
	}
	char *args = r_str_trim_dup (input + 1);
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
	return true;
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

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input) {
	int wseek, i, size, len;
	RCore *core = (RCore *)data;
	char *tmp, *str, *ostr;
	const char *arg, *filename = "";
	char _fn[32];
	ut64 off;
	ut8 *buf;
	st64 num = 0;

	if (!input) {
		return 0;
	}

	len = strlen (input);
	wseek = r_config_get_i (core->config, "cfg.wseek");
	str = ostr = strdup (*input? input + 1: "");
	_fn[0] = 0;

	switch (*input) {
	case 'B': // "wB"
		switch (input[1]) {
		case ' ':
			cmd_write_bits (core, 1, r_num_math (core->num, input + 2));
			break;
		case '-':
			cmd_write_bits (core, 0, r_num_math (core->num, input + 2));
			break;
		default:
			eprintf ("Usage: wB 0x2000  # or wB-0x2000\n");
			break;
		}
		break;
	case '0': // "w0"
		{
			ut64 len = r_num_math (core->num, input+1);
			if (len>0) {
				ut8 *buf = calloc (1, len);
				if (buf) {
					if (!r_io_write_at (core->io, core->offset, buf, len)) {
						eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
					}
					r_core_block_read (core);
					free (buf);
				} else eprintf ("Cannot allocate %d byte(s)\n", (int)len);
			}
		}
		break;
	case '1': // "w1"
	case '2': // "w2"
	case '4': // "w4"
	case '8': // "w8"
		if (input[1] && input[2]) {
			if (input[1]==input[2]) {
				num = 1;
			} else num = r_num_math (core->num, input+2);
		}
		switch (input[2] ? input[1] : 0) {
		case '+':
			cmd_write_inc (core, *input-'0', num);
			break;
		case '-':
			cmd_write_inc (core, *input-'0', -num);
			break;
		default:
			eprintf ("Usage: w[1248][+-][num]   # inc/dec byte/word/..\n");
		}
		break;
	case '6': // "w6"
		{
		int fail = 0;
		ut8 *buf = NULL;
		int len = 0, str_len;
		const char *str;

		if (input[1] && input[2] != ' ')
			fail = 1;

		if (input[1] && input[2] && input[3])
			str = input + 3;
		else
			str = "";
		str_len = strlen (str) + 1;
		if (!fail) {
			switch (input[1]) {
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
		break;
		}
	case 'h': // "wh"
		{
		char *p = strchr (input, ' ');
		if (p) {
			while (*p==' ') p++;
			p = r_file_path (p);
			if (p) {
				r_cons_println (p);
				free (p);
			}
		}
		}
		break;
	case 'e': { // "we"
		ut64 addr = 0, len = 0, b_size = 0;
		st64 dist = 0;
		ut8* bytes = NULL;
		int cmd_suc = false;
		char *input_shadow = NULL, *p = NULL;

		switch (input[1]) {
		case 'n': // "wen"
			if (input[2] == ' ') {
				len = *input ? r_num_math (core->num, input+3) : 0;
				if (len > 0) {
					const ut64 cur_off = core->offset;
					cmd_suc = r_core_extend_at (core, core->offset, len);
					core->offset = cur_off;
					r_core_block_read (core);
				}
			}
			break;
		case 'N': // "weN"
			if (input[2] == ' ') {
				input += 3;
				while (*input && *input == ' ') input++;
				addr = r_num_math (core->num, input);
				while (*input && *input != ' ') input++;
				input++;
				len = *input ? r_num_math (core->num, input) : 0;
				if (len > 0){
					ut64 cur_off = core->offset;
					cmd_suc = r_core_extend_at (core, addr, len);
					r_core_seek (core, cur_off, 1);
					core->offset = addr;
					r_core_block_read (core);
				}
				cmd_suc = true;
			}
			break;
		case 'x': // "wex"
			if (input[2] == ' ') {
				input += 2;
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
			input +=  3;
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
					r_core_seek (core, addr, 1);
					cmd_suc = true;
				}
			}
			free (input_shadow);
			break;
		case 'X': // "weX"
			if (input[2] == ' ') {
				addr = r_num_math (core->num, input+3);
				input += 3;
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
		}
		break;
	case 'p': // "wp"
		if (input[1]=='-' || (input[1]==' ' && input[2]=='-')) {
			char *out = r_core_editor (core, NULL, NULL);
			if (out) {
				r_core_patch (core, out);
				free (out);
			}
		} else {
			if (input[1]==' ' && input[2]) {
				char *data = r_file_slurp (input+2, NULL);
				if (data) {
					r_core_patch (core, data);
					free (data);
				}
			} else {
				r_core_cmd_help (core, help_msg_wp);
			}
		}
		break;
	case 'u': // "wu"
		// TODO: implement it in an API RCore.write_unified_hexpatch() is ETOOLONG
		if (input[1]==' ') {
			char *data = r_file_slurp (input+2, NULL);
			if (data) {
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
		break;
	case 'r': // "wr"
		off = r_num_math (core->num, input+1);
		len = (int)off;
		if (len > 0) {
			buf = malloc (len);
			if (buf != NULL) {
				r_num_irand ();
				for (i=0; i<len; i++)
					buf[i] = r_num_rand (256);
				if (!r_core_write_at (core, core->offset, buf, len)) {
					cmd_write_fail (core);
				}
				WSEEK (core, len);
				free (buf);
			} else eprintf ("Cannot allocate %d byte(s)\n", len);
		}
		break;
	case 'A': // "wA"
		switch (input[1]) {
		case ' ':
			if (input[2] && input[3]==' ') {
				r_asm_set_pc (core->assembler, core->offset);
				eprintf ("modify (%c)=%s\n", input[2], input+4);
				len = r_asm_modify (core->assembler, core->block, input[2],
					r_num_math (core->num, input+4));
				eprintf ("len=%d\n", len);
				if (len>0) {
					if (!r_core_write_at (core, core->offset, core->block, len)) {
						cmd_write_fail (core);
					}
					WSEEK (core, len);
				} else eprintf ("r_asm_modify = %d\n", len);
			} else eprintf ("Usage: wA [type] [value]\n");
			break;
		case '?':
		default:
			r_core_cmd_help (core, help_msg_wA);
			break;
		}
		break;
	case 'c': // "wc"
		switch (input[1]) {
		case '\0': // "wc"
			//if (!r_config_get_i (core->config, "io.cache"))
			//	eprintf ("[warning] e io.cache must be true\n");
			r_io_cache_list (core->io, 0);
			break;
		case '?': // "wc?"
			r_core_cmd_help (core, help_msg_wc);
			break;
		case '*': // "wc*"
			r_io_cache_list (core->io, 1);
			break;
		case '+': // "wc+"
			if (input[2]=='*') { // "wc+*"
				//r_io_cache_reset (core->io, core->io->cached);
				eprintf ("TODO\n");
			} else if (input[2]==' ') { // "wc+ "
				char *p = strchr (input+3, ' ');
				ut64 to, from;
				from = r_num_math (core->num, input+3);
				if (p) {
					*p = 0;
					to = r_num_math (core->num, input+3);
					if (to<from) {
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
			if (input[2]=='*') { // "wc-*"
				r_io_cache_reset (core->io, core->io->cached);
				break;
			}
			ut64 from, to;
			if (input[2]==' ') { // "wc- "
				char *p = strchr (input+3, ' ');
				if (p) {
					*p = 0;
					from = r_num_math (core->num, input+3);
					to = r_num_math (core->num, p+1);
					if (to < from) {
						eprintf ("Invalid range (from>to)\n");
						return 0;
					}
				} else {
					from = r_num_math (core->num, input+3);
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
			cmd_write_pcache (core, &input[2]);
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
		break;
	case ' ': // "w"
		/* write string */
		len = r_str_unescape (str);
		if (!r_core_write_at (core, core->offset, (const ut8*)str, len)) {
			cmd_write_fail (core);
		}
#if 0
		r_io_use_desc (core->io, core->file->desc);
		r_io_write_at (core->io, core->offset, (const ut8*)str, len);
#endif
		WSEEK (core, len);
		r_core_block_read (core);
		break;
	case 'z': // "wz"
		/* write zero-terminated string */
		len = r_str_unescape (str);
		if (!r_core_write_at (core, core->offset, (const ut8*)str + 1, len)) {
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
		break;
	case 't': // "wt"
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
					RIOMap *map = r_io_map_get (core->io, poff);
					toend = true;
					//use physical address
					poff = map ? poff - map->itv.addr + map->delta : poff;
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
					sz = r_io_fd_size (core->io, core->file->fd) - core->offset;
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
					sz = r_io_fd_size (core->io, core->file->fd);
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
					if (!r_file_dump (filename, core->block, sz, append)) {
						sz = -1;
					}
				}
			}
			if (sz >= 0) {
				eprintf ("Dumped %"PFMT64d" bytes from 0x%08"PFMT64x" into %s\n",
						sz, poff, filename);
			}
		}
		break;
	case 'f': // "wf"
		cmd_wf (core, input);
		break;
	case 'w': // "ww"
		len = r_str_unescape (str);
		if (len < 1) {
			break;
		}
		len++;
		str++;
		len = (len - 1) << 1;
		tmp = (len > 0) ? malloc (len + 1) : NULL;
		if (tmp) {
			for (i=0; i<len; i++) {
				if (i%2) tmp[i] = 0;
				else tmp[i] = str[i>>1];
			}
			str = tmp;
			if (core->file) {
				r_io_use_fd (core->io, core->file->fd);
			}
			if (!r_io_write_at (core->io, core->offset, (const ut8*)str, len)) {
				eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
			}
			WSEEK (core, len);
			r_core_block_read (core);
			free (tmp);
		} else {
			eprintf ("Cannot malloc %d\n", len);
		}
		break;
	case 'x': // "wx"
		switch (input[1]) {
		case ' ': // "wx "
			cmd_write_hexpair (core, input + 1);
			break;
		case 'f': // "wxf"
			arg = (const char *)(input + ((input[2]==' ')? 3: 2));
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
					r_io_use_fd (core->io, core->file->fd);
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
				int len = cmd_write_hexpair (core, input + 2);
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
		break;
	case 'a': // "wa"
		switch (input[1]) {
		case 'o': // "wao"
			if (input[2] == ' ') {
				char *op = r_str_trim_dup (input + 3);
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
		case '*': {
			const char *file = r_str_trim_head_ro (input + 2);
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, file);
			if (acode) {
				if (input[1] == 'i') { // "wai"
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
					if (input[1] == '*') {
						r_cons_printf ("wx %s\n", hex);
					} else {
						if (!r_core_write_at (core, core->offset, acode->bytes, acode->len)) {
							cmd_write_fail (core);
						} else {
							if (r_config_get_i (core->config, "scr.prompt")) {
								eprintf ("Written %d byte(s) (%s) = wx %s\n", acode->len, input+2, hex);
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
			if ((input[2] == ' ' || input[2] == '*')) {
				const char *file = input + ((input[2] == '*')? 4: 3);
				r_asm_set_pc (core->assembler, core->offset);

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
							RAsmCode *ac = r_asm_massemble (core->assembler, b);
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
			if ((input[2] == ' ' || input[2] == '*')) {
				const char *file = input + ((input[2] == '*')? 4: 3);
				r_asm_set_pc (core->assembler, core->offset);
				char *f = r_file_slurp (file, NULL);
				if (f) {
					RAsmCode *acode = r_asm_massemble (core->assembler, f);
					if (acode) {
						char* hex = r_asm_code_get_hex (acode);
						if (input[2] == '*') {
							r_cons_printf ("wx %s\n", hex);
						} else {
							if (r_config_get_i (core->config, "scr.prompt")) {
								eprintf ("Written %d byte(s) (%s)=wx %s\n", acode->len, input+1, hex);
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
		break;
	case 'b': { // "wb"
		int len = strlen (input);
		ut8 *buf = malloc (len+1);
		if (buf) {
			len = r_hex_str2bin (input+1, buf);
			if (len > 0) {
				r_mem_copyloop (core->block, buf, core->blocksize, len);
				if (!r_core_write_at (core, core->offset, core->block, core->blocksize)) {
					cmd_write_fail (core);
				} else {
					WSEEK (core, core->blocksize);
				}
				r_core_block_read (core);
			} else eprintf ("Wrong argument\n");
			free (buf);
		} else eprintf ("Cannot malloc %d\n", len+1);
		break;
	}
	case 'm': // "wm"
		size = r_hex_str2bin (input+1, (ut8*)str);
		switch (input[1]) {
		case '\0':
			eprintf ("Current write mask: TODO\n");
			// TODO
			break;
		case '?':
			break;
		case '-':
			r_io_set_write_mask (core->io, 0, 0);
			eprintf ("Write mask disabled\n");
			break;
		case ' ':
			if (size>0) {
				r_io_use_fd (core->io, core->file->fd);
				r_io_set_write_mask (core->io, (const ut8*)str, size);
				WSEEK (core, size);
				eprintf ("Write mask set to '");
				for (i=0; i<size; i++)
					eprintf ("%02x", str[i]);
				eprintf ("'\n");
			} else eprintf ("Invalid string\n");
			break;
		}
		break;
	case 'v': // "wv"
		cmd_write_value (core, input);
		break;
	case 'o': // "wo"
		cmd_write_op (core, input);
		break;
	case 'd': // "wd"
		if (input[1] && input[1]==' ') {
			char *arg, *inp = strdup (input+2);
			arg = strchr (inp, ' ');
			if (arg) {
				*arg = 0;
				ut64 addr = r_num_math (core->num, input+2);
				ut64 len = r_num_math (core->num, arg+1);
				ut8 *data = malloc (len);
				r_io_read_at (core->io, addr, data, len);
				if (!r_io_write_at (core->io, core->offset, data, len)) {
					eprintf ("r_io_write_at failed at 0x%08"PFMT64x"\n", core->offset);
				}
				free (data);
			} else eprintf ("See wd?\n");
			free (inp);
		} else eprintf ("Usage: wd [source-offset] [length] @ [dest-offset]\n");
		break;
	case 's': // "ws"
		if (str && *str && str[1]) {
			len = r_str_unescape (str+1);
			if (len>255) {
				eprintf ("Too large\n");
			} else {
				ut8 ulen = (ut8)len;
				if (!r_core_write_at (core, core->offset, &ulen, 1) ||
				!r_core_write_at (core, core->offset + 1, (const ut8*)str + 1, len)) {
					cmd_write_fail (core);
				} else {
					WSEEK (core, len);
				}
				r_core_block_read (core);
			}
		} else eprintf ("Too short.\n");
		break;
	default:
	case '?': // "w?"
		r_core_cmd_help (core, help_msg_w);
		break;
	}
	R_FREE (ostr);
	return 0;
}
