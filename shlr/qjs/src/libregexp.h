/*
 * Regular Expression Engine
 * 
 * Copyright (c) 2017-2018 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef LIBREGEXP_H
#define LIBREGEXP_H

#include <stddef.h>

#include "libunicode.h"

#define LRE_BOOL  int       /* for documentation purposes */

#define LRE_FLAG_GLOBAL     (1 << 0)
#define LRE_FLAG_IGNORECASE (1 << 1)
#define LRE_FLAG_MULTILINE  (1 << 2)
#define LRE_FLAG_DOTALL     (1 << 3)
#define LRE_FLAG_UTF16      (1 << 4)
#define LRE_FLAG_STICKY     (1 << 5)

#define LRE_FLAG_NAMED_GROUPS (1 << 7) /* named groups are present in the regexp */

uint8_t *lre_compile(int *plen, char *error_msg, int error_msg_size,
                     const char *buf, size_t buf_len, int re_flags,
                     void *opaque);
int lre_get_capture_count(const uint8_t *bc_buf);
int lre_get_flags(const uint8_t *bc_buf);
const char *lre_get_groupnames(const uint8_t *bc_buf);
int lre_exec(uint8_t **capture,
             const uint8_t *bc_buf, const uint8_t *cbuf, int cindex, int clen,
             int cbuf_type, void *opaque);
void lre_byte_swap(uint8_t *bc_buf, int bc_buf_len);

int lre_parse_escape(const uint8_t **pp, int allow_utf16);
LRE_BOOL lre_is_space(int c);

/* must be provided by the user */
LRE_BOOL lre_check_stack_overflow(void *opaque, size_t alloca_size); 
void *lre_realloc(void *opaque, void *ptr, size_t size);

/* JS identifier test */
extern uint32_t const lre_id_start_table_ascii[4];
extern uint32_t const lre_id_continue_table_ascii[4];

static inline int lre_js_is_ident_first(int c)
{
    if ((uint32_t)c < 128) {
        return (lre_id_start_table_ascii[c >> 5] >> (c & 31)) & 1;
    } else {
#ifdef CONFIG_ALL_UNICODE
        return lre_is_id_start(c);
#else
        return !lre_is_space(c);
#endif
    }
}

static inline int lre_js_is_ident_next(int c)
{
    if ((uint32_t)c < 128) {
        return (lre_id_continue_table_ascii[c >> 5] >> (c & 31)) & 1;
    } else {
        /* ZWNJ and ZWJ are accepted in identifiers */
#ifdef CONFIG_ALL_UNICODE
        return lre_is_id_continue(c) || c == 0x200C || c == 0x200D;
#else
        return !lre_is_space(c) || c == 0x200C || c == 0x200D;
#endif
    }
}

#undef LRE_BOOL

#endif /* LIBREGEXP_H */
