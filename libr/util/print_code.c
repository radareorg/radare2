/* radare - LGPL - Copyright 2007-2024 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>

static const char* bits_to_c_code_fmtstr(int bits) {
	switch (bits) {
	case 16:
		return "0x%04" PFMT64x;
	case 32:
		return "0x%08" PFMT64x "U";
	case 64:
		return "0x%016" PFMT64x "ULL";
	}
	return "0x%02" PFMT64x;
}

static int get_instruction_size(RPrint *p, ut64 at) {
	char *is = p->coreb.cmdStrF (p->coreb.core, "ao @ 0x%08" PFMT64x "~^size[1]", at);
	int res = atoi (is);
	free (is);
	return res;
}

static void print_c_instructions(RPrint *p, ut64 addr, const ut8 *buf, int len) {
	const char *fmtstr = bits_to_c_code_fmtstr (8);
	const char *namenm = p->codevarname;
	char *namesz = NULL;
	if (R_STR_ISEMPTY (namenm)) {
		namenm = "buffer";
		namesz = strdup ("_BUFFER_SIZE");
	} else {
		namesz = r_str_newf ("_%s_SIZE", namenm);
		r_str_case (namesz, true);
	}

	// p->consb.cb_printf (p->consb.cons,"#define %s %d\n", namesz, len); 
	p->cb_printf ("#define %s %d\n", namesz, len);
	p->cb_printf ("const uint8_t %s[%s] = {\n", namenm, namesz);
	free (namesz);

	const int orig_align = p->coreb.cfgGetI (p->coreb.core, "asm.cmt.col") - 40;
	size_t k, i = 0;
	bool be = (p && p->config)? R_ARCH_CONFIG_IS_BIG_ENDIAN (p->config): R_SYS_ENDIAN;

	while (!r_print_is_interrupted () && i < len) {
		ut64 at = addr + i;
		int inst_size = get_instruction_size (p, at);
		if (inst_size <= 0) {
			// some times the instruction size is reported as zero,
			// just skip the current instruction and go ahead
			inst_size = 1;
		}
		p->cb_printf (" ");
		size_t limit = R_MIN (i + inst_size, len);
		for (k = i; k < limit; k++) {
			r_print_cursor (p, k, 1, true);
			p->cb_printf (fmtstr, r_read_ble (buf++, be, 8));
			r_print_cursor (p, k, 1, false);
			p->cb_printf (", ");
		}
		size_t j = k - i;
		int pad = orig_align - ((j - 1) * 6);
		p->cb_printf ("%*s", R_MAX (pad, 0), "");

		if (j == inst_size) {
			char *instr = p->coreb.cmdStrF (p->coreb.core, "pi 1 @ 0x%08" PFMT64x, at);
			r_str_trim (instr);
			p->cb_printf (" /* %s */\n", instr);
			free (instr);
		} else {
			p->cb_printf (" /* invalid */\n");
		}
		i += j;
	}
	p->cb_printf ("};\n");
}

static void print_c_code(RPrint *p, ut64 addr, const ut8 *buf, int len, int ws, int w, bool headers) {
	R_RETURN_IF_FAIL (p && p->cb_printf);
	size_t i;

	ws = R_MAX (1, R_MIN (ws, 8));
	bool be = (p && p->config)? R_ARCH_CONFIG_IS_BIG_ENDIAN (p->config): R_SYS_ENDIAN;
	int bits = ws * 8;
	const char *fmtstr = bits_to_c_code_fmtstr (bits);
	len /= ws;

	if (headers) {
		const char *namenm = p->codevarname;
		char *namesz = NULL;
		if (R_STR_ISEMPTY (namenm)) {
			namenm = "buffer";
			namesz = strdup ("_BUFFER_SIZE");
		} else {
			namesz = r_str_newf ("_%s_SIZE", namenm);
			r_str_case (namesz, true);
		}
		p->cb_printf ("#define %s %d\n", namesz, len);
		p->cb_printf ("const uint%d_t %s[%s] = {", bits, namenm, namesz);
		free (namesz);
	}

	for (i = 0; !r_print_is_interrupted () && i < len; i++) {
		if (headers) {
			if (!(i % w)) {
				p->cb_printf ("\n  ");
			}
		} else {
			if (i == 0) {
				p->cb_printf ("  ");
			} else if (!(i % w)) {
				p->cb_printf ("\n  ");
			}
		}
		r_print_cursor (p, i, 1, 1);
		p->cb_printf (fmtstr, r_read_ble (buf, be, bits));
		if ((i + 1) < len) {
			p->cb_printf (",");

			if ((i + 1) % w) {
				p->cb_printf (" ");
			}
		}
		r_print_cursor (p, i, 1, 0);
		buf += ws;
	}
	if (headers) {
		p->cb_printf ("\n};\n");
	}
}

R_API void r_print_code(RPrint *p, ut64 addr, const ut8 *buf, int len, char lang) {
	R_RETURN_IF_FAIL (p && buf);
	int i, w = (int)(p->cols * 0.7);
	if (w < 1) {
		w = 1;
	}
	switch (lang) {
	case 'q':
		print_c_code (p, addr, buf, len, 1, (int)(p->cols / 1.5), false);
		break;
	case '*':
		p->cb_printf ("wx+");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (i && !(i % 32)) {
				p->cb_printf (";\nwx+");
			}
			p->cb_printf ("%02x", buf[i]);
		}
		p->cb_printf (";\ns-%d\n", len);
		break;
	case 'A': // "pcA"
		/* implemented in core because of disasm :( */
		break;
	case 'c': // "pcc"
		{
			int col = 0;
			const int max_cols = 60;

			p->cb_printf ("const unsigned char cstr[%d] = \"", len);
			for (i = 0; !r_print_is_interrupted () && i < len; i++) {
				if (col == 0 || col > max_cols) {
					p->cb_printf ("\"\\\n  \"");
					col = 0;
				}
				ut8 ch = buf[i];
				switch (ch) {
				case '\\':
					p->cb_printf ("\\\\");
					break;
				case '\t':
					p->cb_printf ("\\t");
					break;
				case '\r':
					p->cb_printf ("\\r");
					break;
				case '\n':
					p->cb_printf ("\\n");
					break;
				case '"':
					p->cb_printf ("\\\"");
					break;
				default:
					if (IS_PRINTABLE (ch)) {
						p->cb_printf ("%c", buf[i]);
					} else {
						p->cb_printf ("\"\"\\x%02x\"\"", buf[i]);
						col += 3;
					}
					break;
				}
				col += 1;
			}
			p->cb_printf ("\";\n");
		}
		break;
	case 'a': // "pca"
		p->cb_printf ("shellcode:");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (!(i % 8)) {
				p->cb_printf ("\n.byte ");
			} else {
				p->cb_printf (", ");
			}
			p->cb_printf ("0x%02x", buf[i]);
		}
		p->cb_printf ("\n.equ shellcode_len, %d\n", len);
		break;
	case 'g': // "pcg"
		p->cb_printf ("var BUFF = [%d]byte{", len);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("}\n");
		break;
	case 's': // "pcs"
		p->cb_printf ("\"");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			p->cb_printf ("\\x%02x", buf[i]);
		}
		p->cb_printf ("\"\n");
		break;
	case 'S': // "pcS"
	{
		const int trunksize = 16;
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
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
	case 'n': // "pcn"
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("%d%s", buf[i], (i + 1 < len)? " ": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("\n");
		break;
	case 'k': // "pck" kotlin
		p->cb_printf ("val arr = byteArrayOfInts(");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf (")\n");
		break;
	case 'z': // "pcz" // swift
		p->cb_printf ("let byteArray : [UInt8] = [");

		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("0x%x%s", buf[i], (i + 1 < len)? ", ": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("]\n");
		break;
	case 'r': // "pcr" // Rust
		p->cb_printf ("let _: [u8; %d] = [\n", len);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("];\n");
		break;
	case 'o': // "pco" // Objective-C
		p->cb_printf ("NSData *endMarker = [[NSData alloc] initWithBytes:{\n");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("}];\n");
		break;
	case 'v': // "pcv" // JaVa
		p->cb_printf ("byte[] ba = {");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("%d%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("};\n");
		break;
	case 'V': // "pcV" // vlang.io
		p->cb_printf ("const data = [ byte(%d),\n  ", buf[0]);
		for (i = 1; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("%d%s", buf[i], (i + 1 < len)? ", ": "");
			r_print_cursor (p, i, 1, 0);
			if ((i %10) == 0) {
				p->cb_printf ("\n  ");
			}
		}
		p->cb_printf ("\n]\n");
		break;
	case 'y': // "pcy"
		p->cb_printf ("{");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf (" %02x", buf[i] & 0xff);
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf (" }\n");
		break;
	case 'Y': // "pcY"
		p->cb_printf ("$hex_%"PFMT64x" = {", addr);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf (" %02x", buf[i] & 0xff);
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf (" }\n");
		break;
	case 'j': // "pcj"
		p->cb_printf ("[");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("%d%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("]\n");
		break;
	case 'P':
	case 'p': // "pcp" "pcP"
		p->cb_printf ("import struct\nbuf = struct.pack (\"%dB\", *[", len);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (!(i % w)) {
				p->cb_printf ("\n");
			}
			r_print_cursor (p, i, 1, 1);
			p->cb_printf ("0x%02x%s", buf[i], (i + 1 < len)? ",": "])");
			r_print_cursor (p, i, 1, 0);
		}
		p->cb_printf ("\n");
		break;
	case 'h': // "pch"
		print_c_code (p, addr, buf, len, 2, p->cols / 2, true); // 9
		break;
	case 'w': // "pcw"
		print_c_code (p, addr, buf, len, 4, p->cols / 3, true); // 6);
		break;
	case 'i': // "pci"
		print_c_instructions (p, addr, buf, len);
		break;
	case 'd': // "pcd"
		print_c_code (p, addr, buf, len, 8, p->cols / 5, true); //3);
		break;
	default:
		print_c_code (p, addr, buf, len, 1, (int)(p->cols / 1.5), true); // 12);
		break;
	}
}

R_API char *r_print_code_indent(const char *s) {
	// honors {} not implemented
	return NULL;
}

R_API char *r_print_code_tocolor(const char *o) {
	char *s = strdup (o);
	s = r_str_replace (s, "\r", "", 1);
	s = r_str_replace (s, "goto ", Color_GREEN"goto "Color_RESET, 1);
	s = r_str_replace (s, "(byte)", Color_RED"(byte)"Color_RESET, 1);

	RStrBuf *sb = r_strbuf_new ("");
	const char *p = s;
	while (*p) {
		if (r_str_startswith (p, "\n\n")) {
			p++;
			continue;
		}
		const char *nl = strchr (p, '\n');
		const char *cm = strstr (p, "//");
		const char *ox = strstr (p, "0x");
		const char *lb = strchr (p, ':');
		const char *cl = strstr (p, " ()");
		const char *st = strstr (p, " str.");
		const char *w = r_str_trim_head_ro (p);
		if (st > cm && st < nl) {
			st = NULL;
		}
		if (w == nl) {
			p = w;
			continue;
		}
		if (lb && lb > p) {
			const char *prev = lb - 1;
			if (*prev == ' ') {
				lb = 0;
			}
		}
		if (r_str_startswith (w, "(byte)")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_RED "(byte)"Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 6;
		} else if (r_str_startswith (w, "if ")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_YELLOW"if "Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 3;
		} else if (r_str_startswith (w, "do {")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_YELLOW"do {"Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 4;
		} else if (r_str_startswith (w, "int ")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_CYAN"int "Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 4;
		} else if (r_str_startswith (w, "return;")) {
			r_strbuf_append_n (sb, p, w - p);
			r_strbuf_append (sb, Color_CYAN"return;"Color_RESET);
			p = w + 7;
		} else if (r_str_startswith (w, "return ")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_CYAN"return "Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 7;
		} else if (r_str_startswith (w, "break;")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_GREEN "break;"Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 6;
		} else if (r_str_startswith (w, "while ")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_GREEN "while "Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 6;
		} else if (r_str_startswith (w, "goto ")) {
			r_strbuf_append_n (sb, p, w - p);
			const char *msg = Color_GREEN "goto "Color_RESET;
			r_strbuf_append (sb, msg);
			p = w + 5;
		} else if (ox > 0 && ox < nl) {
			const char *eos = ox + 2;
			while (eos && *eos) {
				char ch = *eos;
				if (IS_HEXCHAR (ch)) {
					eos++;
				} else {
					break;
				}
			}
			r_strbuf_append_n (sb, p, ox - p); // pre
			r_strbuf_append (sb, Color_YELLOW); // numbers in yellow
			r_strbuf_append_n (sb, ox, eos - ox); // number
			r_strbuf_append (sb, Color_RESET);
			r_strbuf_append_n (sb, eos, 2); // number
			p = eos + 2;
		} else if (st > 0 && st < nl) {
			const char *eos = R_MIN (nl, cm);
			if (eos < st) {
				eos = nl;
			}
			st += 5;
			r_strbuf_append_n (sb, p, st - p); // pre
			r_strbuf_append (sb, Color_CYAN);
			r_strbuf_append (sb, " \"");
			char *trim = r_str_ndup (st, eos - st);
			r_str_trim (trim);
			r_strbuf_append (sb, trim);
			free (trim);
			r_strbuf_append (sb, "\"");
			r_strbuf_append (sb, Color_RESET);
			p = eos;
		} else if (cl > 0 && cl < nl && cl < cm) {
			// colorize calls
			r_strbuf_append (sb, Color_GREEN);
			if (cm > 0 && cm < nl) {
				r_strbuf_append_n (sb, p, cm - p);
				p = cm;
			} else {
				r_strbuf_append_n (sb, p, nl - p);
				p = nl;
			}
			r_strbuf_append (sb, Color_RESET);
		} else if (cm > 0 && cm < nl) {
			// colorize comments
			if (cm > p) {
				r_strbuf_append_n (sb, p, cm - p);
			} else {
				r_strbuf_append_n (sb, " ", 1);
			}
			r_strbuf_append (sb, Color_MAGENTA);
			r_strbuf_append_n (sb, cm, nl - cm);
			r_strbuf_append (sb, Color_RESET);
			p = nl;
		} else if (lb > 0 && lb < nl && lb < cm && (lb[1] == ' ' || lb[1] == '\n')) {
			// colorize labels
			size_t len = lb - p + 1;
			r_strbuf_append (sb, Color_YELLOW);
			r_strbuf_append_n (sb, p, len);
			r_strbuf_append (sb, Color_RESET);
			p = lb + 1;
		} else {
			r_strbuf_append_n (sb, p, 1);
			p++;
		}
	}
	free (s);
	char *r = r_strbuf_drain (sb);
	r_str_trim_emptylines (r);
	return r;
}
