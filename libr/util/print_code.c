/* radare - LGPL - Copyright 2007-2025 - pancake */

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
	r_print_printf (p, "#define %s %d\n", namesz, len);
	r_print_printf (p, "const uint8_t %s[%s] = {\n", namenm, namesz);
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
		r_print_printf (p, " ");
		size_t limit = R_MIN (i + inst_size, len);
		for (k = i; k < limit; k++) {
			r_print_cursor (p, k, 1, true);
			r_print_printf (p, fmtstr, r_read_ble (buf++, be, 8));
			r_print_cursor (p, k, 1, false);
			r_print_printf (p, ", ");
		}
		size_t j = k - i;
		int pad = orig_align - ((j - 1) * 6);
		r_print_printf (p, "%*s", R_MAX (pad, 0), "");

		if (j == inst_size) {
			char *instr = p->coreb.cmdStrF (p->coreb.core, "pi 1 @ 0x%08" PFMT64x, at);
			r_str_trim (instr);
			r_print_printf (p, " /* %s */\n", instr);
			free (instr);
		} else {
			r_print_printf (p, " /* invalid */\n");
		}
		i += j;
	}
	r_print_printf (p, "};\n");
}

static void print_c_code(RPrint *p, ut64 addr, const ut8 *buf, int len, int ws, int w, bool headers) {
	R_RETURN_IF_FAIL (p);
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
		r_print_printf (p, "#define %s %d\n", namesz, len);
		r_print_printf (p, "const uint%d_t %s[%s] = {", bits, namenm, namesz);
		free (namesz);
	}

	for (i = 0; !r_print_is_interrupted () && i < len; i++) {
		if (headers) {
			if (!(i % w)) {
				r_print_printf (p, "\n  ");
			}
		} else {
			if (i == 0) {
				r_print_printf (p, "  ");
			} else if (!(i % w)) {
				r_print_printf (p, "\n  ");
			}
		}
		r_print_cursor (p, i, 1, 1);
		r_print_printf (p, fmtstr, r_read_ble (buf, be, bits));
		if ((i + 1) < len) {
			r_print_printf (p, ",");

			if ((i + 1) % w) {
				r_print_printf (p, " ");
			}
		}
		r_print_cursor (p, i, 1, 0);
		buf += ws;
	}
	if (headers) {
		r_print_printf (p, "\n};\n");
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
		r_print_printf (p, "wx+");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (i && !(i % 32)) {
				r_print_printf (p, ";\nwx+");
			}
			r_print_printf (p, "%02x", buf[i]);
		}
		r_print_printf (p, ";\ns-%d\n", len);
		break;
	case 'A': // "pcA"
		/* implemented in core because of disasm :( */
		break;
	case 'c': // "pcc"
		{
			int col = 0;
			const int max_cols = 60;

			r_print_printf (p, "const unsigned char cstr[%d] = \"", len);
			for (i = 0; !r_print_is_interrupted () && i < len; i++) {
				if (col == 0 || col > max_cols) {
					r_print_printf (p, "\"\\\n  \"");
					col = 0;
				}
				ut8 ch = buf[i];
				switch (ch) {
				case '\\':
					r_print_printf (p, "\\\\");
					break;
				case '\t':
					r_print_printf (p, "\\t");
					break;
				case '\r':
					r_print_printf (p, "\\r");
					break;
				case '\n':
					r_print_printf (p, "\\n");
					break;
				case '"':
					r_print_printf (p, "\\\"");
					break;
				default:
					if (IS_PRINTABLE (ch)) {
						r_print_printf (p, "%c", buf[i]);
					} else {
						r_print_printf (p, "\"\"\\x%02x\"\"", buf[i]);
						col += 3;
					}
					break;
				}
				col += 1;
			}
			r_print_printf (p, "\";\n");
		}
		break;
	case 'a': // "pca"
		r_print_printf (p, "shellcode:");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (!(i % 8)) {
				r_print_printf (p, "\n.byte ");
			} else {
				r_print_printf (p, ", ");
			}
			r_print_printf (p, "0x%02x", buf[i]);
		}
		r_print_printf (p, "\n.equ shellcode_len, %d\n", len);
		break;
	case 'g': // "pcg"
		r_print_printf (p, "var BUFF = [%d]byte{", len);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "}\n");
		break;
	case 's': // "pcs"
		r_print_printf (p, "\"");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_printf (p, "\\x%02x", buf[i]);
		}
		r_print_printf (p, "\"\n");
		break;
	case 'S': // "pcS"
	{
		const int trunksize = 16;
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (!(i % trunksize)) {
				r_print_printf (p, "printf \"");
			}
			r_print_printf (p, "\\%03o", buf[i]);
			if ((i % trunksize) == (trunksize - 1)) {
				r_print_printf (p, "\" %s bin\n", (i <= trunksize)? ">": ">>");
			}
		}
		if ((i % trunksize)) {
			r_print_printf (p, "\" %s bin\n", (i <= trunksize)? ">": ">>");
		}
	} break;
	case 'J': { // "pcJ"
		char *out = malloc (len * 3);
		r_print_printf (p, "var buffer = new Buffer(\"");
		out[0] = 0;
		r_base64_encode (out, buf, len);
		r_print_printf (p, "%s", out);
		r_print_printf (p, "\", 'base64');\n");
		free (out);
	} break;
	case 'n': // "pcn"
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "%d%s", buf[i], (i + 1 < len)? " ": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "\n");
		break;
	case 'k': // "pck" kotlin
		r_print_printf (p, "val arr = byteArrayOfInts(");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, ")\n");
		break;
	case 'z': // "pcz" // swift
		r_print_printf (p, "let byteArray : [UInt8] = [");

		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "0x%x%s", buf[i], (i + 1 < len)? ", ": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "]\n");
		break;
	case 'r': // "pcr" // Rust
		r_print_printf (p, "let _: [u8; %d] = [\n", len);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "];\n");
		break;
	case 'o': // "pco" // Objective-C
		r_print_printf (p, "NSData *endMarker = [[NSData alloc] initWithBytes:{\n");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "0x%x%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "}];\n");
		break;
	case 'v': // "pcv" // JaVa
		r_print_printf (p, "byte[] ba = {");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "%d%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "};\n");
		break;
	case 'V': // "pcV" // vlang.io
		r_print_printf (p, "const data = [ byte(%d),\n  ", buf[0]);
		for (i = 1; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "%d%s", buf[i], (i + 1 < len)? ", ": "");
			r_print_cursor (p, i, 1, 0);
			if ((i %10) == 0) {
				r_print_printf (p, "\n  ");
			}
		}
		r_print_printf (p, "\n]\n");
		break;
	case 'y': // "pcy"
		r_print_printf (p, "{");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, " %02x", buf[i] & 0xff);
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, " }\n");
		break;
	case 'Y': // "pcY"
		r_print_printf (p, "$hex_%"PFMT64x" = {", addr);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, " %02x", buf[i] & 0xff);
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, " }\n");
		break;
	case 'j': // "pcj"
		r_print_printf (p, "[");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "%d%s", buf[i], (i + 1 < len)? ",": "");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "]\n");
		break;
	case 'P':
	case 'p': // "pcp" "pcP"
		r_print_printf (p, "import struct\nbuf = struct.pack (\"%dB\", *[", len);
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
			if (!(i % w)) {
				r_print_printf (p, "\n");
			}
			r_print_cursor (p, i, 1, 1);
			r_print_printf (p, "0x%02x%s", buf[i], (i + 1 < len)? ",": "])");
			r_print_cursor (p, i, 1, 0);
		}
		r_print_printf (p, "\n");
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

static bool is_identifier_char(char c) {
	return c == '_' || isalnum(c);
}

R_API char *r_print_code_tocolor(const char *o) {
	if (!o) return NULL;

	static const char *keywords[] = {
		"if", "else", "while", "for", "switch", "case", "break",
		"continue", "return", "goto", "do", "sizeof", "typedef",
		"struct", "union", "enum", "const", "volatile", "static",
		"inline", "extern", NULL
	};

	static const char *types[] = {
		"int", "char", "short", "long", "void", "float", "double",
		"bool", "signed", "unsigned", NULL
	};

	const char *p = o;
	RStrBuf *out = r_strbuf_new ("");
	bool in_string = false;
	bool in_char = false;
	bool in_comment = false;
	bool in_line_comment = false;
	bool in_preproc = false;

	while (*p) {
		if (!in_string && !in_char && !in_comment && *p == '#' && (p == o || *(p - 1) == '\n')) {
			// Preprocessor
			in_preproc = true;
			r_strbuf_append (out, Color_CYAN);
			r_strbuf_append_n (out, p, 1);
			p++;
			continue;
		}

		if (in_preproc) {
			if (*p == '\n') {
				in_preproc = false;
				r_strbuf_append (out, Color_RESET);
			}
			r_strbuf_append_n (out, p++, 1);
			continue;
		}

		if (!in_string && !in_char && !in_line_comment && !in_comment && *p == '/' && *(p + 1) == '/') {
			in_line_comment = true;
			r_strbuf_append (out, Color_GREEN);
			r_strbuf_append_n (out, p, 2);
			p += 2;
			continue;
		}
		if (in_line_comment) {
			r_strbuf_append_n (out, p, 1);
			if (*p == '\n') {
				in_line_comment = false;
				r_strbuf_append (out, Color_RESET);
			}
			p++;
			continue;
		}

		if (!in_string && !in_char && !in_comment && *p == '/' && *(p + 1) == '*') {
			in_comment = true;
			r_strbuf_append (out, Color_GREEN);
			r_strbuf_append_n (out, p, 2);
			p += 2;
			continue;
		}
		if (in_comment) {
			r_strbuf_append_n (out, p, 1);
			if (*p == '*' && *(p + 1) == '/') {
				r_strbuf_append_n (out, p + 1, 1);
				p += 2;
				in_comment = false;
				r_strbuf_append (out, Color_RESET);
			} else {
				p++;
			}
			continue;
		}

		if (!in_char && *p == '"') {
			in_string = !in_string;
			r_strbuf_append (out, Color_YELLOW);
			r_strbuf_append_n (out, p++, 1);
			if (!in_string) {
			       r_strbuf_append (out, Color_RESET);
			}
			continue;
		}
		if (!in_string && *p == '\'') {
			in_char = !in_char;
			r_strbuf_append (out, Color_YELLOW);
			r_strbuf_append_n (out, p++, 1);
			if (!in_char) {
				r_strbuf_append (out, Color_RESET);
			}
			continue;
		}
		if (in_string || in_char) {
			r_strbuf_append_n (out, p++, 1);
			continue;
		}

		// Highlight numbers
		if (IS_DIGIT (*p)) {
			r_strbuf_append (out, Color_BLUE);
			while (IS_DIGIT (*p) || *p == 'x' || IS_HEXCHAR (*p)) {
				r_strbuf_append_n (out, p++, 1);
			}
			r_strbuf_append (out, Color_RESET);
			continue;
		}

		// Highlight keywords and types
		if (is_identifier_char (*p)) {
			const char *start = p;
			while (is_identifier_char (*p)) {
				p++;
			}
			int len = p - start;
			char *word = r_str_ndup (start, len);
			bool matched = false;

			const char **kw;
			for (kw = keywords; *kw; kw++) {
				if (!strcmp (word, *kw)) {
					r_strbuf_append (out, Color_MAGENTA);
					r_strbuf_append_n (out, start, len);
					r_strbuf_append (out, Color_RESET);
					matched = true;
					break;
				}
			}
			if (!matched) {
				const char **tp;
				for (tp = types; *tp; tp++) {
					if (!strcmp (word, *tp)) {
						r_strbuf_append (out, Color_RED);
						r_strbuf_append_n (out, start, len);
						r_strbuf_append (out, Color_RESET);
						matched = true;
						break;
					}
				}
			}
			if (!matched) {
				r_strbuf_append_n (out, start, len);
			}
			free (word);
			continue;
		}

		r_strbuf_append_n (out, p++, 1);
	}

	return r_strbuf_drain (out);
}
