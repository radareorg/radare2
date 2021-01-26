/* radare - LGPL - Copyright 2014-2020 - condret, eagleoflqj	*/

// http://datasheets.chipdb.org/Intel/MCS-4/datashts/MCS4_Data_Sheet_Nov71.pdf
// note: OPR of LD should be 1010 in the datasheet

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <ctype.h>
#include "../arch/i4004/i4004dis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return i4004dis (op,buf,len);
}

static int get_decimal(const char *s, int limit) {
	int i, n;
	if (sscanf (s, "%d%n", &i, &n) == 1 && n == strlen (s) && i >= 0 && i <= limit) {
		return i;
	}
	return -1;
}

static int get_int(const char *s, int limit) {
	int i = get_decimal (s, limit), n;
	if (i >= 0) {
		return i;
	}
	if (!strncmp (s, "0x", 2) && sscanf (s, "%x%n", &i, &n) == 1 && n == strlen (s) && i <= limit) {
		return i;
	}
	return -1;
}

static int get_reg(const char *s, int limit) {
	if (s[0] != 'r') {
		return -1;
	}
	return get_decimal (s + 1, limit);
}

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	ut8 buf[2];
	int len = 0;
	char *p = strchr(str, ' ');
	if (p) { // has arguments
		char mnemonic[4] = {0}, arg0[6] = {0}, arg1[5] = {0};
		size_t n = p - str;
		if (n > sizeof (mnemonic) - 1) {
			goto beach;
		}
		strncpy (mnemonic, str, n);
		while (*++p && isspace ((unsigned char)*p));
		n = strcspn (p, ", "); // next separator
		if (n > sizeof (arg0) - 1) {
			goto beach;
		}
		strncpy (arg0, p, n);
		p += n;
		if (*p) { // 2 arguments
			int comma = *p == ',';
			while (*++p) {
				if (*p == ',') {
					comma++;
				} else if (!isspace((unsigned char)*p)) {
					break;
				}
			}
			if (comma > 1 || strlen (p) > sizeof (arg1) - 1) {
				goto beach;
			}
			strcpy (arg1, p);
		}
		if (!strcmp (mnemonic, "jcn")) {
			int condition, address;
			if ((condition = get_int (arg0, 0xf)) < 0
				|| (address = get_int (arg1, 0xff)) < 0) {
				goto beach;
			}
			buf[0] = 0x10 | condition;
			buf[1] = address;
			len = 2;
		} else if (!strcmp (mnemonic, "fim")) {
			int reg, data;
			if ((reg = get_reg (arg0, 0xf)) < 0 || reg & 1 // reg pair => even index
				|| (data = get_int (arg1, 0xff)) < 0) {
				goto beach;
			}
			buf[0] = 0x20 | reg;
			buf[1] = data;
			len = 2;
		} else if (!strcmp (mnemonic, "isz")) {
			int reg, address;
			if ((reg = get_reg (arg0, 0xf)) < 0
				|| (address = get_int (arg1, 0xff)) < 0) {
				goto beach;
			}
			buf[0] = 0x70 | reg;
			buf[1] = address;
			len = 2;
		} else if (arg1[0]) { // must be one argument
			goto beach;
		}
		if (!strcmp (mnemonic, "src") || !strcmp (mnemonic, "fin") || !strcmp (mnemonic, "jin")) {
			int reg;
			if ((reg = get_reg (arg0, 0xf)) < 0 || reg & 1) {
				goto beach;
			}
			buf[0] = (mnemonic[0] == 's' ? 0x21 : mnemonic[0] == 'f' ? 0x30 : 0x31) | reg;
			len = 1;
		} else if (!strcmp (mnemonic, "jun") || !strcmp (mnemonic, "jms")) {
			int address;
			if ((address = get_int (arg0, 0xfff)) < 0) {
				goto beach;
			}
			buf[0] = (mnemonic[1] == 'u' ? 0x40 : 0x50) | (address >> 8);
			buf[1] = address & 0xff;
			len = 2;
		} else if (!strcmp (mnemonic, "bbl") || !strcmp (mnemonic, "ldm")) {
			int data;
			if ((data = get_int (arg0, 0xff)) < 0) {
				goto beach;
			}
			buf[0] = (mnemonic[0] == 'b' ? 0xc0 : 0xd0) | data;
			len = 1;
		} else {
			int reg;
			if ((reg = get_reg (arg0, 0xf)) < 0) {
				goto beach;
			}
			if (!strcmp (mnemonic, "inc")) {
				buf[0] = 0x60;
			} else if (!strcmp (mnemonic, "add")) {
				buf[0] = 0x80;
			} else if (!strcmp (mnemonic, "sub")) {
				buf[0] = 0x90;
			} else if (!strcmp (mnemonic, "ld")) {
				buf[0] = 0xa0;
			} else if (!strcmp (mnemonic, "xch")) {
				buf[0] = 0xb0;
			} else {
				goto beach;
			}
			buf[0] |= reg;
			len = 1;
		}
	} else if (!strcmp (str, "nop")) {
		buf[0] = 0x00;
		len = 1;
	} else {
		int i;
		for (i = 0; i < 16; i++) {
			if (!strcmp (str, i4004_e[i])) {
				buf[0] = 0xe0 | i;
				len = 1;
				goto beach;
			}
		}
		for (i = 0; i < 16; i++) {
			if (!strcmp (str, i4004_f[i])) {
				buf[0] = 0xf0 | i;
				len = 1;
				goto beach;
			}
		}
	}
beach:
	if (len) {
		r_strbuf_setbin (&op->buf, buf, len);
	}
	return op->size = len;
}

RAsmPlugin r_asm_plugin_i4004 = {
	.name = "i4004",
	.desc = "Intel 4004 microprocessor",
	.arch = "i4004",
	.license = "LGPL3",
	.bits = 4,
	.endian = R_SYS_ENDIAN_NONE,
	.assemble = &assemble,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_i4004,
	.version = R2_VERSION
};
#endif
