/* radare - LGPL - Copyright 2007-2020 - pancake */

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
	char *is = p->coreb.cmdstrf (p->coreb.core, "ao @ 0x%08" PFMT64x "~^size[1]", at);
	int res = atoi (is);
	free (is);
	return res;
}

static void print_c_instructions(RPrint *p, ut64 addr, const ut8 *buf, int len) {
	const char *fmtstr = bits_to_c_code_fmtstr (8);

	p->cb_printf ("#define _BUFFER_SIZE %d\n", len);
	p->cb_printf ("const uint8_t buffer[_BUFFER_SIZE] = {\n");

	const int orig_align = p->coreb.cfggeti (p->coreb.core, "asm.cmt.col") - 40;
	size_t k, i = 0;

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
			p->cb_printf (fmtstr, r_read_ble (buf++, p->big_endian, 8));
			r_print_cursor (p, k, 1, false);
			p->cb_printf (", ");
		}
		size_t j = k - i;
		int pad = orig_align - ((j - 1) * 6);
		p->cb_printf ("%*s", R_MAX (pad, 0), "");

		if (j == inst_size) {
			char *instr = p->coreb.cmdstrf (p->coreb.core, "pi 1 @ 0x%08" PFMT64x, at);
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

static void print_c_code(RPrint *p, ut64 addr, const ut8 *buf, int len, int ws, int w) {
	size_t i;

	ws = R_MAX (1, R_MIN (ws, 8));
	int bits = ws * 8;
	const char *fmtstr = bits_to_c_code_fmtstr (bits);
	len /= ws;

	p->cb_printf ("#define _BUFFER_SIZE %d\n", len);
	p->cb_printf ("const uint%d_t buffer[_BUFFER_SIZE] = {", bits);

	for (i = 0; !r_print_is_interrupted () && i < len; i++) {
		if (!(i % w)) {
			p->cb_printf ("\n  ");
		}
		r_print_cursor (p, i, 1, 1);
		p->cb_printf (fmtstr, r_read_ble (buf, p->big_endian, bits));
		if ((i + 1) < len) {
			p->cb_printf (",");

			if ((i + 1) % w) {
				p->cb_printf (" ");
			}
		}
		r_print_cursor (p, i, 1, 0);
		buf += ws;
	}
	p->cb_printf ("\n};\n");
}

R_API void r_print_code(RPrint *p, ut64 addr, const ut8 *buf, int len, char lang) {
	int i, w = (int)(p->cols * 0.7);
	if (w < 1) {
		w = 1;
	}
	switch (lang) {
	case '*':
		p->cb_printf ("wx ");
		for (i = 0; !r_print_is_interrupted () && i < len; i++) {
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
		p->cb_printf ("data := [ byte(%d),\n  ", buf[0]);
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
		print_c_code (p, addr, buf, len, 2, p->cols / 2); // 9
		break;
	case 'w': // "pcw"
		print_c_code (p, addr, buf, len, 4, p->cols / 3); // 6);
		break;
	case 'i': // "pci"
		print_c_instructions (p, addr, buf, len);
		break;
	case 'd': // "pcd"
		print_c_code (p, addr, buf, len, 8, p->cols / 5); //3);
		break;
	default:
		print_c_code (p, addr, buf, len, 1, p->cols / 1.5); // 12);
		break;
	}
}

