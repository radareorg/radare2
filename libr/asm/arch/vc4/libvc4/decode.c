#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>

#include "eval.h"
#include "vc4.h"

void decode(const struct vc4_info *info, uint32_t addr, const uint8_t *buf, size_t len)
{
	char *ll;
	char cc[2*5+1];
	char ww[5*5+2];

	while (len >= 2) {

		const struct vc4_opcode *op = vc4_get_opcode(info, buf, len);
		assert(op != NULL);

		size_t i;
		int j;

		for (i = 0, j = 0; i < op->length; i++)
			j += sprintf(ww + j, "%s%04X", i?" ":"", vc4_get_le16(buf + i * 2));

		for (i = 0; i < op->length * 2; i++)
			cc[i] = isprint(buf[i]) ? buf[i] : '.';
		cc[i] = 0;

		ll = vc4_display(info, op, addr, buf, len);

		printf("%08X:  %-24s  %-10s  %s\n", addr, ww, cc, ll);

		free(ll);

		if (op->length * 2 >= len)
			break;

		buf += op->length * 2;
		len -= op->length * 2;
		addr += op->length * 2;
	}
}


int main(int argc, char *argv[])
{
	char *arch = getenv("VC4_ARCH");
	if (arch == NULL)
		arch = "/home/marmar01/src/rpi/videocoreiv/videocoreiv.arch";

	struct vc4_info *info = vc4_read_arch_file(arch);

	if (info == NULL) {
		perror("Can't open videocoreiv.arch");
		return 1;
	}

	vc4_get_opcodes(info);

	FILE *fp;
	uint8_t buf[0x10000*8];
	size_t len;
	long off = 0;
	char *name = "bootcode.bin";

	if (argc > 2)
		off = strtol(argv[2], NULL, 0);
	if (argc > 1)
		name = argv[1];
	fp = fopen(name, "r");
	if (fp == NULL) {
		perror("Can't open file");
		return 1;
	}

	if (off != 0)
		fseek(fp, off, SEEK_SET);

	len = fread(buf, 1, 0x10000*8, fp);

	decode(info, off, buf, len);
	
	fclose(fp);

	vc4_free_info(info);

	return 0;
}

