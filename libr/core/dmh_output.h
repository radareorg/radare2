/* radare2 - LGPL - Copyright 2026 - pancake */

#ifndef R2_DMH_OUTPUT_H
#define R2_DMH_OUTPUT_H

static void hprint(RStrBuf *sb, const char *fmt, ...) R_PRINTF_CHECK(2, 3);

static void hprint(RStrBuf *sb, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_strbuf_vappendf (sb, fmt, ap);
	va_end (ap);
}

#endif
