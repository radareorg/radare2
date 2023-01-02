/*
 * Unicode utilities
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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include "cutils.h"
#include "libunicode.h"
#include "libunicode-table.h"

enum {
    RUN_TYPE_U,
    RUN_TYPE_L,
    RUN_TYPE_UF,
    RUN_TYPE_LF,
    RUN_TYPE_UL,
    RUN_TYPE_LSU,
    RUN_TYPE_U2L_399_EXT2,
    RUN_TYPE_UF_D20,
    RUN_TYPE_UF_D1_EXT,
    RUN_TYPE_U_EXT,
    RUN_TYPE_LF_EXT,
    RUN_TYPE_U_EXT2,
    RUN_TYPE_L_EXT2,
    RUN_TYPE_U_EXT3,
};

/* conv_type:
   0 = to upper 
   1 = to lower
   2 = case folding (= to lower with modifications) 
*/
int lre_case_conv(uint32_t *res, uint32_t c, int conv_type)
{
    if (c < 128) {
        if (conv_type) {
            if (c >= 'A' && c <= 'Z') {
                c = c - 'A' + 'a';
            }
        } else {
            if (c >= 'a' && c <= 'z') {
                c = c - 'a' + 'A';
            }
        }
    } else {
        uint32_t v, code, data, type, len, a, is_lower;
        int idx, idx_min, idx_max;
        
        is_lower = (conv_type != 0);
        idx_min = 0;
        idx_max = countof(case_conv_table1) - 1;
        while (idx_min <= idx_max) {
            idx = (unsigned)(idx_max + idx_min) / 2;
            v = case_conv_table1[idx];
            code = v >> (32 - 17);
            len = (v >> (32 - 17 - 7)) & 0x7f;
            if (c < code) {
                idx_max = idx - 1;
            } else if (c >= code + len) {
                idx_min = idx + 1;
            } else {
                type = (v >> (32 - 17 - 7 - 4)) & 0xf;
                data = ((v & 0xf) << 8) | case_conv_table2[idx];
                switch(type) {
                case RUN_TYPE_U:
                case RUN_TYPE_L:
                case RUN_TYPE_UF:
                case RUN_TYPE_LF:
                    if (conv_type == (type & 1) ||
                        (type >= RUN_TYPE_UF && conv_type == 2)) {
                        c = c - code + (case_conv_table1[data] >> (32 - 17));
                    }
                    break;
                case RUN_TYPE_UL:
                    a = c - code;
                    if ((a & 1) != (1 - is_lower))
                        break;
                    c = (a ^ 1) + code;
                    break;
                case RUN_TYPE_LSU:
                    a = c - code;
                    if (a == 1) {
                        c += 2 * is_lower - 1;
                    } else if (a == (1 - is_lower) * 2) {
                        c += (2 * is_lower - 1) * 2;
                    }
                    break;
                case RUN_TYPE_U2L_399_EXT2:
                    if (!is_lower) {
                        res[0] = c - code + case_conv_ext[data >> 6];
                        res[1] = 0x399;
                        return 2;
                    } else {
                        c = c - code + case_conv_ext[data & 0x3f];
                    }
                    break;
                case RUN_TYPE_UF_D20:
                    if (conv_type == 1)
                        break;
                    c = data + (conv_type == 2) * 0x20;
                    break;
                case RUN_TYPE_UF_D1_EXT:
                    if (conv_type == 1)
                        break;
                    c = case_conv_ext[data] + (conv_type == 2);
                    break;
                case RUN_TYPE_U_EXT:
                case RUN_TYPE_LF_EXT:
                    if (is_lower != (type - RUN_TYPE_U_EXT))
                        break;
                    c = case_conv_ext[data];
                    break;
                case RUN_TYPE_U_EXT2:
                case RUN_TYPE_L_EXT2:
                    if (conv_type != (type - RUN_TYPE_U_EXT2))
                        break;
                    res[0] = c - code + case_conv_ext[data >> 6];
                    res[1] = case_conv_ext[data & 0x3f];
                    return 2;
                default:
                case RUN_TYPE_U_EXT3:
                    if (conv_type != 0)
                        break;
                    res[0] = case_conv_ext[data >> 8];
                    res[1] = case_conv_ext[(data >> 4) & 0xf];
                    res[2] = case_conv_ext[data & 0xf];
                    return 3;
                }
                break;
            }
        }
    }
    res[0] = c;
    return 1;
}

static uint32_t get_le24(const uint8_t *ptr)
{
#if defined(__x86__) || defined(__x86_64__)
    return *(uint16_t *)ptr | (ptr[2] << 16);
#else
    return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16);
#endif
}

#define UNICODE_INDEX_BLOCK_LEN 32

/* return -1 if not in table, otherwise the offset in the block */
static int get_index_pos(uint32_t *pcode, uint32_t c,
                         const uint8_t *index_table, int index_table_len)
{
    uint32_t code, v;
    int idx_min, idx_max, idx;

    idx_min = 0;
    v = get_le24(index_table);
    code = v & ((1 << 21) - 1);
    if (c < code) {
        *pcode = 0;
        return 0;
    }
    idx_max = index_table_len - 1;
    code = get_le24(index_table + idx_max * 3);
    if (c >= code)
        return -1;
    /* invariant: tab[idx_min] <= c < tab2[idx_max] */
    while ((idx_max - idx_min) > 1) {
        idx = (idx_max + idx_min) / 2;
        v = get_le24(index_table + idx * 3);
        code = v & ((1 << 21) - 1);
        if (c < code) {
            idx_max = idx;
        } else {
            idx_min = idx;
        }
    }
    v = get_le24(index_table + idx_min * 3);
    *pcode = v & ((1 << 21) - 1);
    return (idx_min + 1) * UNICODE_INDEX_BLOCK_LEN + (v >> 21);
}

static BOOL lre_is_in_table(uint32_t c, const uint8_t *table,
                            const uint8_t *index_table, int index_table_len)
{
    uint32_t code, b, bit;
    int pos;
    const uint8_t *p;
    
    pos = get_index_pos(&code, c, index_table, index_table_len);
    if (pos < 0)
        return FALSE; /* outside the table */
    p = table + pos;
    bit = 0;
    for(;;) {
        b = *p++;
        if (b < 64) {
            code += (b >> 3) + 1;
            if (c < code)
                return bit;
            bit ^= 1;
            code += (b & 7) + 1;
        } else if (b >= 0x80) {
            code += b - 0x80 + 1;
        } else if (b < 0x60) {
            code += (((b - 0x40) << 8) | p[0]) + 1;
            p++;
        } else {
            code += (((b - 0x60) << 16) | (p[0] << 8) | p[1]) + 1;
            p += 2;
        }
        if (c < code)
            return bit;
        bit ^= 1;
    }
}

BOOL lre_is_cased(uint32_t c)
{
    uint32_t v, code, len;
    int idx, idx_min, idx_max;
        
    idx_min = 0;
    idx_max = countof(case_conv_table1) - 1;
    while (idx_min <= idx_max) {
        idx = (unsigned)(idx_max + idx_min) / 2;
        v = case_conv_table1[idx];
        code = v >> (32 - 17);
        len = (v >> (32 - 17 - 7)) & 0x7f;
        if (c < code) {
            idx_max = idx - 1;
        } else if (c >= code + len) {
            idx_min = idx + 1;
        } else {
            return TRUE;
        }
    }
    return lre_is_in_table(c, unicode_prop_Cased1_table,
                           unicode_prop_Cased1_index,
                           sizeof(unicode_prop_Cased1_index) / 3);
}

BOOL lre_is_case_ignorable(uint32_t c)
{
    return lre_is_in_table(c, unicode_prop_Case_Ignorable_table,
                           unicode_prop_Case_Ignorable_index,
                           sizeof(unicode_prop_Case_Ignorable_index) / 3);
}

/* character range */

static __maybe_unused void cr_dump(CharRange *cr)
{
    int i;
    for(i = 0; i < cr->len; i++)
        printf("%d: 0x%04x\n", i, cr->points[i]);
}

static void *cr_default_realloc(void *opaque, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void cr_init(CharRange *cr, void *mem_opaque, DynBufReallocFunc *realloc_func)
{
    cr->len = cr->size = 0;
    cr->points = NULL;
    cr->mem_opaque = mem_opaque;
    cr->realloc_func = realloc_func ? realloc_func : cr_default_realloc;
}

void cr_free(CharRange *cr)
{
    cr->realloc_func(cr->mem_opaque, cr->points, 0);
}

int cr_realloc(CharRange *cr, int size)
{
    int new_size;
    uint32_t *new_buf;
    
    if (size > cr->size) {
        new_size = max_int(size, cr->size * 3 / 2);
        new_buf = cr->realloc_func(cr->mem_opaque, cr->points,
                                   new_size * sizeof(cr->points[0]));
        if (!new_buf)
            return -1;
        cr->points = new_buf;
        cr->size = new_size;
    }
    return 0;
}

int cr_copy(CharRange *cr, const CharRange *cr1)
{
    if (cr_realloc(cr, cr1->len))
        return -1;
    memcpy(cr->points, cr1->points, sizeof(cr->points[0]) * cr1->len);
    cr->len = cr1->len;
    return 0;
}

/* merge consecutive intervals and remove empty intervals */
static void cr_compress(CharRange *cr)
{
    int i, j, k, len;
    uint32_t *pt;
    
    pt = cr->points;
    len = cr->len;
    i = 0;
    j = 0;
    k = 0;
    while ((i + 1) < len) {
        if (pt[i] == pt[i + 1]) {
            /* empty interval */
            i += 2;
        } else {
            j = i;
            while ((j + 3) < len && pt[j + 1] == pt[j + 2])
                j += 2;
            /* just copy */
            pt[k] = pt[i];
            pt[k + 1] = pt[j + 1];
            k += 2;
            i = j + 2;
        }
    }
    cr->len = k;
}

/* union or intersection */
int cr_op(CharRange *cr, const uint32_t *a_pt, int a_len,
          const uint32_t *b_pt, int b_len, int op)
{
    int a_idx, b_idx, is_in;
    uint32_t v;
    
    a_idx = 0;
    b_idx = 0;
    for(;;) {
        /* get one more point from a or b in increasing order */
        if (a_idx < a_len && b_idx < b_len) {
            if (a_pt[a_idx] < b_pt[b_idx]) {
                goto a_add;
            } else if (a_pt[a_idx] == b_pt[b_idx]) {
                v = a_pt[a_idx];
                a_idx++;
                b_idx++;
            } else {
                goto b_add;
            }
        } else if (a_idx < a_len) {
        a_add:
            v = a_pt[a_idx++];
        } else if (b_idx < b_len) {
        b_add:
            v = b_pt[b_idx++];
        } else {
            break;
        }
        /* add the point if the in/out status changes */
        switch(op) {
        case CR_OP_UNION:
            is_in = (a_idx & 1) | (b_idx & 1);
            break;
        case CR_OP_INTER:
            is_in = (a_idx & 1) & (b_idx & 1);
            break;
        case CR_OP_XOR:
            is_in = (a_idx & 1) ^ (b_idx & 1);
            break;
        default:
            abort();
        }
        if (is_in != (cr->len & 1)) {
            if (cr_add_point(cr, v))
                return -1;
        }
    }
    cr_compress(cr);
    return 0;
}

int cr_union1(CharRange *cr, const uint32_t *b_pt, int b_len)
{
    CharRange a = *cr;
    int ret;
    cr->len = 0;
    cr->size = 0;
    cr->points = NULL;
    ret = cr_op(cr, a.points, a.len, b_pt, b_len, CR_OP_UNION);
    cr_free(&a);
    return ret;
}

int cr_invert(CharRange *cr)
{
    int len;
    len = cr->len;
    if (cr_realloc(cr, len + 2))
        return -1;
    memmove(cr->points + 1, cr->points, len * sizeof(cr->points[0]));
    cr->points[0] = 0;
    cr->points[len + 1] = UINT32_MAX;
    cr->len = len + 2;
    cr_compress(cr);
    return 0;
}

#ifdef CONFIG_ALL_UNICODE

BOOL lre_is_id_start(uint32_t c)
{
    return lre_is_in_table(c, unicode_prop_ID_Start_table,
                           unicode_prop_ID_Start_index,
                           sizeof(unicode_prop_ID_Start_index) / 3);
}

BOOL lre_is_id_continue(uint32_t c)
{
    return lre_is_id_start(c) ||
        lre_is_in_table(c, unicode_prop_ID_Continue1_table,
                        unicode_prop_ID_Continue1_index,
                        sizeof(unicode_prop_ID_Continue1_index) / 3);
}

#define UNICODE_DECOMP_LEN_MAX 18

typedef enum {
    DECOMP_TYPE_C1, /* 16 bit char */
    DECOMP_TYPE_L1, /* 16 bit char table */
    DECOMP_TYPE_L2,
    DECOMP_TYPE_L3,
    DECOMP_TYPE_L4,
    DECOMP_TYPE_L5, /* XXX: not used */
    DECOMP_TYPE_L6, /* XXX: could remove */
    DECOMP_TYPE_L7, /* XXX: could remove */
    DECOMP_TYPE_LL1, /* 18 bit char table */
    DECOMP_TYPE_LL2,
    DECOMP_TYPE_S1, /* 8 bit char table */
    DECOMP_TYPE_S2,
    DECOMP_TYPE_S3,
    DECOMP_TYPE_S4,
    DECOMP_TYPE_S5,
    DECOMP_TYPE_I1, /* increment 16 bit char value */
    DECOMP_TYPE_I2_0,
    DECOMP_TYPE_I2_1,
    DECOMP_TYPE_I3_1,
    DECOMP_TYPE_I3_2,
    DECOMP_TYPE_I4_1,
    DECOMP_TYPE_I4_2,
    DECOMP_TYPE_B1, /* 16 bit base + 8 bit offset */
    DECOMP_TYPE_B2,
    DECOMP_TYPE_B3,
    DECOMP_TYPE_B4,
    DECOMP_TYPE_B5,
    DECOMP_TYPE_B6,
    DECOMP_TYPE_B7,
    DECOMP_TYPE_B8,
    DECOMP_TYPE_B18,
    DECOMP_TYPE_LS2,
    DECOMP_TYPE_PAT3,
    DECOMP_TYPE_S2_UL,
    DECOMP_TYPE_LS2_UL,
} DecompTypeEnum;

static uint32_t unicode_get_short_code(uint32_t c)
{
    static const uint16_t unicode_short_table[2] = { 0x2044, 0x2215 };

    if (c < 0x80)
        return c;
    else if (c < 0x80 + 0x50)
        return c - 0x80 + 0x300;
    else
        return unicode_short_table[c - 0x80 - 0x50];
}

static uint32_t unicode_get_lower_simple(uint32_t c)
{
    if (c < 0x100 || (c >= 0x410 && c <= 0x42f))
        c += 0x20;
    else
        c++;
    return c;
}

static uint16_t unicode_get16(const uint8_t *p)
{
    return p[0] | (p[1] << 8);
}

static int unicode_decomp_entry(uint32_t *res, uint32_t c,
                                int idx, uint32_t code, uint32_t len,
                                uint32_t type)
{
    uint32_t c1;
    int l, i, p;
    const uint8_t *d;

    if (type == DECOMP_TYPE_C1) {
        res[0] = unicode_decomp_table2[idx];
        return 1;
    } else {
        d = unicode_decomp_data + unicode_decomp_table2[idx];
        switch(type) {
        case DECOMP_TYPE_L1:
        case DECOMP_TYPE_L2:
        case DECOMP_TYPE_L3:
        case DECOMP_TYPE_L4:
        case DECOMP_TYPE_L5:
        case DECOMP_TYPE_L6:
        case DECOMP_TYPE_L7:
            l = type - DECOMP_TYPE_L1 + 1;
            d += (c - code) * l * 2;
            for(i = 0; i < l; i++) {
                if ((res[i] = unicode_get16(d + 2 * i)) == 0)
                    return 0;
            }
            return l;
        case DECOMP_TYPE_LL1:
        case DECOMP_TYPE_LL2:
            {
                uint32_t k, p;
                l = type - DECOMP_TYPE_LL1 + 1;
                k = (c - code) * l;
                p = len * l * 2;
                for(i = 0; i < l; i++) {
                    c1 = unicode_get16(d + 2 * k) |
                        (((d[p + (k / 4)] >> ((k % 4) * 2)) & 3) << 16);
                    if (!c1)
                        return 0;
                    res[i] = c1;
                    k++;
                }
            }
            return l;
        case DECOMP_TYPE_S1:
        case DECOMP_TYPE_S2:
        case DECOMP_TYPE_S3:
        case DECOMP_TYPE_S4:
        case DECOMP_TYPE_S5:
            l = type - DECOMP_TYPE_S1 + 1;
            d += (c - code) * l;
            for(i = 0; i < l; i++) {
                if ((res[i] = unicode_get_short_code(d[i])) == 0)
                    return 0;
            }
            return l;
        case DECOMP_TYPE_I1:
            l = 1;
            p = 0;
            goto decomp_type_i;
        case DECOMP_TYPE_I2_0:
        case DECOMP_TYPE_I2_1:
        case DECOMP_TYPE_I3_1:
        case DECOMP_TYPE_I3_2:
        case DECOMP_TYPE_I4_1:
        case DECOMP_TYPE_I4_2:
            l = 2 + ((type - DECOMP_TYPE_I2_0) >> 1);
            p = ((type - DECOMP_TYPE_I2_0) & 1) + (l > 2);
        decomp_type_i:
            for(i = 0; i < l; i++) {
                c1 = unicode_get16(d + 2 * i);
                if (i == p)
                    c1 += c - code;
                res[i] = c1;
            }
            return l;
        case DECOMP_TYPE_B18:
            l = 18;
            goto decomp_type_b;
        case DECOMP_TYPE_B1:
        case DECOMP_TYPE_B2:
        case DECOMP_TYPE_B3:
        case DECOMP_TYPE_B4:
        case DECOMP_TYPE_B5:
        case DECOMP_TYPE_B6:
        case DECOMP_TYPE_B7:
        case DECOMP_TYPE_B8:
            l = type - DECOMP_TYPE_B1 + 1;
        decomp_type_b:
            {
                uint32_t c_min;
                c_min = unicode_get16(d);
                d += 2 + (c - code) * l;
                for(i = 0; i < l; i++) {
                    c1 = d[i];
                    if (c1 == 0xff)
                        c1 = 0x20;
                    else
                        c1 += c_min;
                    res[i] = c1;
                }
            }
            return l;
        case DECOMP_TYPE_LS2:
            d += (c - code) * 3;
            if (!(res[0] = unicode_get16(d)))
                return 0;
            res[1] = unicode_get_short_code(d[2]);
            return 2;
        case DECOMP_TYPE_PAT3:
            res[0] = unicode_get16(d);
            res[2] = unicode_get16(d + 2);
            d += 4 + (c - code) * 2;
            res[1] = unicode_get16(d);
            return 3;
        case DECOMP_TYPE_S2_UL:
        case DECOMP_TYPE_LS2_UL:
            c1 = c - code;
            if (type == DECOMP_TYPE_S2_UL) {
                d += c1 & ~1;
                c = unicode_get_short_code(*d);
                d++;
            } else {
                d += (c1 >> 1) * 3;
                c = unicode_get16(d);
                d += 2;
            }
            if (c1 & 1)
                c = unicode_get_lower_simple(c);
            res[0] = c;
            res[1] = unicode_get_short_code(*d);
            return 2;
        }
    }
    return 0;
}


/* return the length of the decomposition (length <=
   UNICODE_DECOMP_LEN_MAX) or 0 if no decomposition */
static int unicode_decomp_char(uint32_t *res, uint32_t c, BOOL is_compat1)
{
    uint32_t v, type, is_compat, code, len;
    int idx_min, idx_max, idx;
    
    idx_min = 0;
    idx_max = countof(unicode_decomp_table1) - 1;
    while (idx_min <= idx_max) {
        idx = (idx_max + idx_min) / 2;
        v = unicode_decomp_table1[idx];
        code = v >> (32 - 18);
        len = (v >> (32 - 18 - 7)) & 0x7f;
        //        printf("idx=%d code=%05x len=%d\n", idx, code, len);
        if (c < code) {
            idx_max = idx - 1;
        } else if (c >= code + len) {
            idx_min = idx + 1;
        } else {
            is_compat = v & 1;
            if (is_compat1 < is_compat)
                break;
            type = (v >> (32 - 18 - 7 - 6)) & 0x3f;
            return unicode_decomp_entry(res, c, idx, code, len, type);
        }
    }
    return 0;
}

/* return 0 if no pair found */
static int unicode_compose_pair(uint32_t c0, uint32_t c1)
{
    uint32_t code, len, type, v, idx1, d_idx, d_offset, ch;
    int idx_min, idx_max, idx, d;
    uint32_t pair[2];
    
    idx_min = 0;
    idx_max = countof(unicode_comp_table) - 1;
    while (idx_min <= idx_max) {
        idx = (idx_max + idx_min) / 2;
        idx1 = unicode_comp_table[idx];

        /* idx1 represent an entry of the decomposition table */
        d_idx = idx1 >> 6;
        d_offset = idx1 & 0x3f;
        v = unicode_decomp_table1[d_idx];
        code = v >> (32 - 18);
        len = (v >> (32 - 18 - 7)) & 0x7f;
        type = (v >> (32 - 18 - 7 - 6)) & 0x3f;
        ch = code + d_offset;
        unicode_decomp_entry(pair, ch, d_idx, code, len, type);
        d = c0 - pair[0];
        if (d == 0)
            d = c1 - pair[1];
        if (d < 0) {
            idx_max = idx - 1;
        } else if (d > 0) {
            idx_min = idx + 1;
        } else {
            return ch;
        }
    }
    return 0;
}

/* return the combining class of character c (between 0 and 255) */
static int unicode_get_cc(uint32_t c)
{
    uint32_t code, n, type, cc, c1, b;
    int pos;
    const uint8_t *p;
    
    pos = get_index_pos(&code, c,
                        unicode_cc_index, sizeof(unicode_cc_index) / 3);
    if (pos < 0)
        return 0;
    p = unicode_cc_table + pos;
    for(;;) {
        b = *p++;
        type = b >> 6;
        n = b & 0x3f;
        if (n < 48) {
        } else if (n < 56) {
            n = (n - 48) << 8;
            n |= *p++;
            n += 48;
        } else {
            n = (n - 56) << 8;
            n |= *p++ << 8;
            n |= *p++;
            n += 48 + (1 << 11);
        }
        if (type <= 1)
            p++;
        c1 = code + n + 1;
        if (c < c1) {
            switch(type) {
            case 0:
                cc = p[-1];
                break;
            case 1:
                cc = p[-1] + c - code;
                break;
            case 2:
                cc = 0;
                break;
            default:
            case 3:
                cc = 230;
                break;
            }
            return cc;
        }
        code = c1;
    }
}

static void sort_cc(int *buf, int len)
{
    int i, j, k, cc, cc1, start, ch1;
    
    for(i = 0; i < len; i++) {
        cc = unicode_get_cc(buf[i]);
        if (cc != 0) {
            start = i;
            j = i + 1;
            while (j < len) {
                ch1 = buf[j];
                cc1 = unicode_get_cc(ch1);
                if (cc1 == 0)
                    break;
                k = j - 1;
                while (k >= start) {
                    if (unicode_get_cc(buf[k]) <= cc1)
                        break;
                    buf[k + 1] = buf[k];
                    k--;
                }
                buf[k + 1] = ch1;
                j++;
            }
#if 0
            printf("cc:");
            for(k = start; k < j; k++) {
                printf(" %3d", unicode_get_cc(buf[k]));
            }
            printf("\n");
#endif
            i = j;
        }
    }
}

static void to_nfd_rec(DynBuf *dbuf,
                       const int *src, int src_len, int is_compat)
{
    uint32_t c, v;
    int i, l;
    uint32_t res[UNICODE_DECOMP_LEN_MAX];
    
    for(i = 0; i < src_len; i++) {
        c = src[i];
        if (c >= 0xac00 && c < 0xd7a4) {
            /* Hangul decomposition */
            c -= 0xac00;
            dbuf_put_u32(dbuf, 0x1100 + c / 588);
            dbuf_put_u32(dbuf, 0x1161 + (c % 588) / 28);
            v = c % 28;
            if (v != 0)
                dbuf_put_u32(dbuf, 0x11a7 + v);
        } else {
            l = unicode_decomp_char(res, c, is_compat);
            if (l) {
                to_nfd_rec(dbuf, (int *)res, l, is_compat);
            } else {
                dbuf_put_u32(dbuf, c);
            }
        }
    }
}

/* return 0 if not found */
static int compose_pair(uint32_t c0, uint32_t c1)
{
    /* Hangul composition */
    if (c0 >= 0x1100 && c0 < 0x1100 + 19 &&
        c1 >= 0x1161 && c1 < 0x1161 + 21) {
        return 0xac00 + (c0 - 0x1100) * 588 + (c1 - 0x1161) * 28;
    } else if (c0 >= 0xac00 && c0 < 0xac00 + 11172 &&
               (c0 - 0xac00) % 28 == 0 &&
               c1 >= 0x11a7 && c1 < 0x11a7 + 28) {
        return c0 + c1 - 0x11a7;
    } else {
        return unicode_compose_pair(c0, c1);
    }
}

int unicode_normalize(uint32_t **pdst, const uint32_t *src, int src_len,
                      UnicodeNormalizationEnum n_type,
                      void *opaque, DynBufReallocFunc *realloc_func)
{
    int *buf, buf_len, i, p, starter_pos, cc, last_cc, out_len;
    BOOL is_compat;
    DynBuf dbuf_s, *dbuf = &dbuf_s;
    
    is_compat = n_type >> 1;

    dbuf_init2(dbuf, opaque, realloc_func);
    if (dbuf_realloc(dbuf, sizeof(int) * src_len))
        goto fail;

    /* common case: latin1 is unaffected by NFC */
    if (n_type == UNICODE_NFC) {
        for(i = 0; i < src_len; i++) {
            if (src[i] >= 0x100)
                goto not_latin1;
        }
        buf = (int *)dbuf->buf;
        memcpy(buf, src, src_len * sizeof(int));
        *pdst = (uint32_t *)buf;
        return src_len;
    not_latin1: ;
    }

    to_nfd_rec(dbuf, (const int *)src, src_len, is_compat);
    if (dbuf_error(dbuf)) {
    fail:
        *pdst = NULL;
        return -1;
    }
    buf = (int *)dbuf->buf;
    buf_len = dbuf->size / sizeof(int);
        
    sort_cc(buf, buf_len);
    
    if (buf_len <= 1 || (n_type & 1) != 0) {
        /* NFD / NFKD */
        *pdst = (uint32_t *)buf;
        return buf_len;
    }
    
    i = 1;
    out_len = 1;
    while (i < buf_len) {
        /* find the starter character and test if it is blocked from
           the character at 'i' */
        last_cc = unicode_get_cc(buf[i]);
        starter_pos = out_len - 1;
        while (starter_pos >= 0) {
            cc = unicode_get_cc(buf[starter_pos]);
            if (cc == 0)
                break;
            if (cc >= last_cc)
                goto next;
            last_cc = 256;
            starter_pos--;
        }
        if (starter_pos >= 0 &&
            (p = compose_pair(buf[starter_pos], buf[i])) != 0) {
            buf[starter_pos] = p;
            i++;
        } else {
        next:
            buf[out_len++] = buf[i++];
        }
    }
    *pdst = (uint32_t *)buf;
    return out_len;
}

/* char ranges for various unicode properties */

static int unicode_find_name(const char *name_table, const char *name)
{
    const char *p, *r;
    int pos;
    size_t name_len, len;
    
    p = name_table;
    pos = 0;
    name_len = strlen(name);
    while (*p) {
        for(;;) {
            r = strchr(p, ',');
            if (!r)
                len = strlen(p);
            else
                len = r - p;
            if (len == name_len && !memcmp(p, name, name_len))
                return pos;
            p += len + 1;
            if (!r)
                break;
        }
        pos++;
    }
    return -1;
}

/* 'cr' must be initialized and empty. Return 0 if OK, -1 if error, -2
   if not found */
int unicode_script(CharRange *cr,
                   const char *script_name, BOOL is_ext)
{
    int script_idx;
    const uint8_t *p, *p_end;
    uint32_t c, c1, b, n, v, v_len, i, type;
    CharRange cr1_s, *cr1;
    CharRange cr2_s, *cr2 = &cr2_s;
    BOOL is_common;
    
    script_idx = unicode_find_name(unicode_script_name_table, script_name);
    if (script_idx < 0)
        return -2;
    /* Note: we remove the "Unknown" Script */
    script_idx += UNICODE_SCRIPT_Unknown + 1;
        
    is_common = (script_idx == UNICODE_SCRIPT_Common ||
                 script_idx == UNICODE_SCRIPT_Inherited);
    if (is_ext) {
        cr1 = &cr1_s;
        cr_init(cr1, cr->mem_opaque, cr->realloc_func);
        cr_init(cr2, cr->mem_opaque, cr->realloc_func);
    } else {
        cr1 = cr;
    }

    p = unicode_script_table;
    p_end = unicode_script_table + countof(unicode_script_table);
    c = 0;
    while (p < p_end) {
        b = *p++;
        type = b >> 7;
        n = b & 0x7f;
        if (n < 96) {
        } else if (n < 112) {
            n = (n - 96) << 8;
            n |= *p++;
            n += 96;
        } else {
            n = (n - 112) << 16;
            n |= *p++ << 8;
            n |= *p++;
            n += 96 + (1 << 12);
        }
        if (type == 0)
            v = 0;
        else
            v = *p++;
        c1 = c + n + 1;
        if (v == script_idx) {
            if (cr_add_interval(cr1, c, c1))
                goto fail;
        }
        c = c1;
    }

    if (is_ext) {
        /* add the script extensions */
        p = unicode_script_ext_table;
        p_end = unicode_script_ext_table + countof(unicode_script_ext_table);
        c = 0;
        while (p < p_end) {
            b = *p++;
            if (b < 128) {
                n = b;
            } else if (b < 128 + 64) {
                n = (b - 128) << 8;
                n |= *p++;
                n += 128;
            } else {
                n = (b - 128 - 64) << 16;
                n |= *p++ << 8;
                n |= *p++;
                n += 128 + (1 << 14);
            }
            c1 = c + n + 1;
            v_len = *p++;
            if (is_common) {
                if (v_len != 0) {
                    if (cr_add_interval(cr2, c, c1))
                        goto fail;
                }
            } else {
                for(i = 0; i < v_len; i++) {
                    if (p[i] == script_idx) {
                        if (cr_add_interval(cr2, c, c1))
                            goto fail;
                        break;
                    }
                }
            }
            p += v_len;
            c = c1;
        }
        if (is_common) {
            /* remove all the characters with script extensions */
            if (cr_invert(cr2))
                goto fail;
            if (cr_op(cr, cr1->points, cr1->len, cr2->points, cr2->len,
                      CR_OP_INTER))
                goto fail;
        } else {
            if (cr_op(cr, cr1->points, cr1->len, cr2->points, cr2->len,
                      CR_OP_UNION))
                goto fail;
        }
        cr_free(cr1);
        cr_free(cr2);
    }
    return 0;
 fail:
    if (is_ext) {
        cr_free(cr1);
        cr_free(cr2);
    }
    goto fail;
}

#define M(id) (1U << UNICODE_GC_ ## id)

static int unicode_general_category1(CharRange *cr, uint32_t gc_mask)
{
    const uint8_t *p, *p_end;
    uint32_t c, c0, b, n, v;

    p = unicode_gc_table;
    p_end = unicode_gc_table + countof(unicode_gc_table);
    c = 0;
    while (p < p_end) {
        b = *p++;
        n = b >> 5;
        v = b & 0x1f;
        if (n == 7) {
            n = *p++;
            if (n < 128) {
                n += 7;
            } else if (n < 128 + 64) {
                n = (n - 128) << 8;
                n |= *p++;
                n += 7 + 128;
            } else {
                n = (n - 128 - 64) << 16;
                n |= *p++ << 8;
                n |= *p++;
                n += 7 + 128 + (1 << 14);
            }
        }
        c0 = c;
        c += n + 1;
        if (v == 31) {
            /* run of Lu / Ll */
            b = gc_mask & (M(Lu) | M(Ll));
            if (b != 0) {
                if (b == (M(Lu) | M(Ll))) {
                    goto add_range;
                } else {
                    c0 += ((gc_mask & M(Ll)) != 0);
                    for(; c0 < c; c0 += 2) {
                        if (cr_add_interval(cr, c0, c0 + 1))
                            return -1;
                    }
                }
            }
        } else if ((gc_mask >> v) & 1) {
        add_range:
            if (cr_add_interval(cr, c0, c))
                return -1;
        }
    }
    return 0;
}

static int unicode_prop1(CharRange *cr, int prop_idx)
{
    const uint8_t *p, *p_end;
    uint32_t c, c0, b, bit;

    p = unicode_prop_table[prop_idx];
    p_end = p + unicode_prop_len_table[prop_idx];
    c = 0;
    bit = 0;
    while (p < p_end) {
        c0 = c;
        b = *p++;
        if (b < 64) {
            c += (b >> 3) + 1;
            if (bit)  {
                if (cr_add_interval(cr, c0, c))
                    return -1;
            }
            bit ^= 1;
            c0 = c;
            c += (b & 7) + 1;
        } else if (b >= 0x80) {
            c += b - 0x80 + 1;
        } else if (b < 0x60) {
            c += (((b - 0x40) << 8) | p[0]) + 1;
            p++;
        } else {
            c += (((b - 0x60) << 16) | (p[0] << 8) | p[1]) + 1;
            p += 2;
        }
        if (bit)  {
            if (cr_add_interval(cr, c0, c))
                return -1;
        }
        bit ^= 1;
    }
    return 0;
}

#define CASE_U (1 << 0)
#define CASE_L (1 << 1)
#define CASE_F (1 << 2)

/* use the case conversion table to generate range of characters.
   CASE_U: set char if modified by uppercasing,
   CASE_L: set char if modified by lowercasing,
   CASE_F: set char if modified by case folding,
 */
static int unicode_case1(CharRange *cr, int case_mask)
{
#define MR(x) (1 << RUN_TYPE_ ## x)
    const uint32_t tab_run_mask[3] = {
        MR(U) | MR(UF) | MR(UL) | MR(LSU) | MR(U2L_399_EXT2) | MR(UF_D20) |
        MR(UF_D1_EXT) | MR(U_EXT) | MR(U_EXT2) | MR(U_EXT3),

        MR(L) | MR(LF) | MR(UL) | MR(LSU) | MR(U2L_399_EXT2) | MR(LF_EXT) | MR(L_EXT2),

        MR(UF) | MR(LF) | MR(UL) | MR(LSU) | MR(U2L_399_EXT2) | MR(LF_EXT) | MR(UF_D20) | MR(UF_D1_EXT) | MR(LF_EXT),
    };
#undef MR
    uint32_t mask, v, code, type, len, i, idx;

    if (case_mask == 0)
        return 0;
    mask = 0;
    for(i = 0; i < 3; i++) {
        if ((case_mask >> i) & 1)
            mask |= tab_run_mask[i];
    }
    for(idx = 0; idx < countof(case_conv_table1); idx++) {
        v = case_conv_table1[idx];
        type = (v >> (32 - 17 - 7 - 4)) & 0xf;
        code = v >> (32 - 17);
        len = (v >> (32 - 17 - 7)) & 0x7f;
        if ((mask >> type) & 1) {
            //            printf("%d: type=%d %04x %04x\n", idx, type, code, code + len - 1);
            switch(type) {
            case RUN_TYPE_UL:
                if ((case_mask & CASE_U) && (case_mask & (CASE_L | CASE_F)))
                    goto def_case;
                code += ((case_mask & CASE_U) != 0);
                for(i = 0; i < len; i += 2) {
                    if (cr_add_interval(cr, code + i, code + i + 1))
                        return -1;
                }
                break;
            case RUN_TYPE_LSU:
                if ((case_mask & CASE_U) && (case_mask & (CASE_L | CASE_F)))
                    goto def_case;
                if (!(case_mask & CASE_U)) {
                    if (cr_add_interval(cr, code, code + 1))
                        return -1;
                }
                if (cr_add_interval(cr, code + 1, code + 2))
                    return -1;
                if (case_mask & CASE_U) {
                    if (cr_add_interval(cr, code + 2, code + 3))
                        return -1;
                }
                break;
            default:
            def_case:
                if (cr_add_interval(cr, code, code + len))
                    return -1;
                break;
            }
        }
    }
    return 0;
}
        
typedef enum {
    POP_GC,
    POP_PROP,
    POP_CASE,
    POP_UNION,
    POP_INTER,
    POP_XOR,
    POP_INVERT,
    POP_END,
} PropOPEnum;

#define POP_STACK_LEN_MAX 4

static int unicode_prop_ops(CharRange *cr, ...)
{
    va_list ap;
    CharRange stack[POP_STACK_LEN_MAX];
    int stack_len, op, ret, i;
    uint32_t a;
    
    va_start(ap, cr);
    stack_len = 0;
    for(;;) {
        op = va_arg(ap, int);
        switch(op) {
        case POP_GC:
            assert(stack_len < POP_STACK_LEN_MAX);
            a = va_arg(ap, int);
            cr_init(&stack[stack_len++], cr->mem_opaque, cr->realloc_func);
            if (unicode_general_category1(&stack[stack_len - 1], a))
                goto fail;
            break;
        case POP_PROP:
            assert(stack_len < POP_STACK_LEN_MAX);
            a = va_arg(ap, int);
            cr_init(&stack[stack_len++], cr->mem_opaque, cr->realloc_func);
            if (unicode_prop1(&stack[stack_len - 1], a))
                goto fail;
            break;
        case POP_CASE:
            assert(stack_len < POP_STACK_LEN_MAX);
            a = va_arg(ap, int);
            cr_init(&stack[stack_len++], cr->mem_opaque, cr->realloc_func);
            if (unicode_case1(&stack[stack_len - 1], a))
                goto fail;
            break;
        case POP_UNION:
        case POP_INTER:
        case POP_XOR:
            {
                CharRange *cr1, *cr2, *cr3;
                assert(stack_len >= 2);
                assert(stack_len < POP_STACK_LEN_MAX);
                cr1 = &stack[stack_len - 2];
                cr2 = &stack[stack_len - 1];
                cr3 = &stack[stack_len++];
                cr_init(cr3, cr->mem_opaque, cr->realloc_func);
                if (cr_op(cr3, cr1->points, cr1->len,
                          cr2->points, cr2->len, op - POP_UNION + CR_OP_UNION))
                    goto fail;
                cr_free(cr1);
                cr_free(cr2);
                *cr1 = *cr3;
                stack_len -= 2;
            }
            break;
        case POP_INVERT:
            assert(stack_len >= 1);
            if (cr_invert(&stack[stack_len - 1]))
                goto fail;
            break;
        case POP_END:
            goto done;
        default:
            abort();
        }
    }
 done:
    assert(stack_len == 1);
    ret = cr_copy(cr, &stack[0]);
    cr_free(&stack[0]);
    return ret;
 fail:
    for(i = 0; i < stack_len; i++)
        cr_free(&stack[i]);
    return -1;
}

static const uint32_t unicode_gc_mask_table[] = {
    M(Lu) | M(Ll) | M(Lt), /* LC */
    M(Lu) | M(Ll) | M(Lt) | M(Lm) | M(Lo), /* L */
    M(Mn) | M(Mc) | M(Me), /* M */
    M(Nd) | M(Nl) | M(No), /* N */
    M(Sm) | M(Sc) | M(Sk) | M(So), /* S */
    M(Pc) | M(Pd) | M(Ps) | M(Pe) | M(Pi) | M(Pf) | M(Po), /* P */
    M(Zs) | M(Zl) | M(Zp), /* Z */
    M(Cc) | M(Cf) | M(Cs) | M(Co) | M(Cn), /* C */
};

/* 'cr' must be initialized and empty. Return 0 if OK, -1 if error, -2
   if not found */
int unicode_general_category(CharRange *cr, const char *gc_name)
{
    int gc_idx;
    uint32_t gc_mask;
    
    gc_idx = unicode_find_name(unicode_gc_name_table, gc_name);
    if (gc_idx < 0)
        return -2;
    if (gc_idx <= UNICODE_GC_Co) {
        gc_mask = (uint64_t)1 << gc_idx;
    } else {
        gc_mask = unicode_gc_mask_table[gc_idx - UNICODE_GC_LC];
    }
    return unicode_general_category1(cr, gc_mask);
}


/* 'cr' must be initialized and empty. Return 0 if OK, -1 if error, -2
   if not found */
int unicode_prop(CharRange *cr, const char *prop_name)
{
    int prop_idx, ret;
    
    prop_idx = unicode_find_name(unicode_prop_name_table, prop_name);
    if (prop_idx < 0)
        return -2;
    prop_idx += UNICODE_PROP_ASCII_Hex_Digit;

    ret = 0;
    switch(prop_idx) {
    case UNICODE_PROP_ASCII:
        if (cr_add_interval(cr, 0x00, 0x7f + 1))
            return -1;
        break;
    case UNICODE_PROP_Any:
        if (cr_add_interval(cr, 0x00000, 0x10ffff + 1))
            return -1;
        break;
    case UNICODE_PROP_Assigned:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Cn),
                               POP_INVERT,
                               POP_END);
        break;
    case UNICODE_PROP_Math:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Sm),
                               POP_PROP, UNICODE_PROP_Other_Math,
                               POP_UNION,
                               POP_END);
        break;
    case UNICODE_PROP_Lowercase:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Ll),
                               POP_PROP, UNICODE_PROP_Other_Lowercase,
                               POP_UNION,
                               POP_END);
        break;
    case UNICODE_PROP_Uppercase:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu),
                               POP_PROP, UNICODE_PROP_Other_Uppercase,
                               POP_UNION,
                               POP_END);
        break;
    case UNICODE_PROP_Cased:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu) | M(Ll) | M(Lt),
                               POP_PROP, UNICODE_PROP_Other_Uppercase,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Other_Lowercase,
                               POP_UNION,
                               POP_END);
        break;
    case UNICODE_PROP_Alphabetic:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu) | M(Ll) | M(Lt) | M(Lm) | M(Lo) | M(Nl),
                               POP_PROP, UNICODE_PROP_Other_Uppercase,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Other_Lowercase,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Other_Alphabetic,
                               POP_UNION,
                               POP_END);
        break;
    case UNICODE_PROP_Grapheme_Base:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Cc) | M(Cf) | M(Cs) | M(Co) | M(Cn) | M(Zl) | M(Zp) | M(Me) | M(Mn),
                               POP_PROP, UNICODE_PROP_Other_Grapheme_Extend,
                               POP_UNION,
                               POP_INVERT,
                               POP_END);
        break;
    case UNICODE_PROP_Grapheme_Extend:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Me) | M(Mn),
                               POP_PROP, UNICODE_PROP_Other_Grapheme_Extend,
                               POP_UNION,
                               POP_END);
        break;
    case UNICODE_PROP_XID_Start:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu) | M(Ll) | M(Lt) | M(Lm) | M(Lo) | M(Nl),
                               POP_PROP, UNICODE_PROP_Other_ID_Start,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Pattern_Syntax,
                               POP_PROP, UNICODE_PROP_Pattern_White_Space,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_XID_Start1,
                               POP_UNION,
                               POP_INVERT,
                               POP_INTER,
                               POP_END);
        break;
    case UNICODE_PROP_XID_Continue:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu) | M(Ll) | M(Lt) | M(Lm) | M(Lo) | M(Nl) |
                               M(Mn) | M(Mc) | M(Nd) | M(Pc),
                               POP_PROP, UNICODE_PROP_Other_ID_Start,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Other_ID_Continue,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Pattern_Syntax,
                               POP_PROP, UNICODE_PROP_Pattern_White_Space,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_XID_Continue1,
                               POP_UNION,
                               POP_INVERT,
                               POP_INTER,
                               POP_END);
        break;
    case UNICODE_PROP_Changes_When_Uppercased:
        ret = unicode_case1(cr, CASE_U);
        break;
    case UNICODE_PROP_Changes_When_Lowercased:
        ret = unicode_case1(cr, CASE_L);
        break;
    case UNICODE_PROP_Changes_When_Casemapped:
        ret = unicode_case1(cr, CASE_U | CASE_L | CASE_F);
        break;
    case UNICODE_PROP_Changes_When_Titlecased:
        ret = unicode_prop_ops(cr,
                               POP_CASE, CASE_U,
                               POP_PROP, UNICODE_PROP_Changes_When_Titlecased1,
                               POP_XOR,
                               POP_END);
        break;
    case UNICODE_PROP_Changes_When_Casefolded:
        ret = unicode_prop_ops(cr,
                               POP_CASE, CASE_F,
                               POP_PROP, UNICODE_PROP_Changes_When_Casefolded1,
                               POP_XOR,
                               POP_END);
        break;
    case UNICODE_PROP_Changes_When_NFKC_Casefolded:
        ret = unicode_prop_ops(cr,
                               POP_CASE, CASE_F,
                               POP_PROP, UNICODE_PROP_Changes_When_NFKC_Casefolded1,
                               POP_XOR,
                               POP_END);
        break;
#if 0
    case UNICODE_PROP_ID_Start:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu) | M(Ll) | M(Lt) | M(Lm) | M(Lo) | M(Nl),
                               POP_PROP, UNICODE_PROP_Other_ID_Start,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Pattern_Syntax,
                               POP_PROP, UNICODE_PROP_Pattern_White_Space,
                               POP_UNION,
                               POP_INVERT,
                               POP_INTER,
                               POP_END);
        break;
    case UNICODE_PROP_ID_Continue:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Lu) | M(Ll) | M(Lt) | M(Lm) | M(Lo) | M(Nl) |
                               M(Mn) | M(Mc) | M(Nd) | M(Pc),
                               POP_PROP, UNICODE_PROP_Other_ID_Start,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Other_ID_Continue,
                               POP_UNION,
                               POP_PROP, UNICODE_PROP_Pattern_Syntax,
                               POP_PROP, UNICODE_PROP_Pattern_White_Space,
                               POP_UNION,
                               POP_INVERT,
                               POP_INTER,
                               POP_END);
        break;
    case UNICODE_PROP_Case_Ignorable:
        ret = unicode_prop_ops(cr,
                               POP_GC, M(Mn) | M(Cf) | M(Lm) | M(Sk),
                               POP_PROP, UNICODE_PROP_Case_Ignorable1,
                               POP_XOR,
                               POP_END);
        break;
#else
        /* we use the existing tables */
    case UNICODE_PROP_ID_Continue:
        ret = unicode_prop_ops(cr,
                               POP_PROP, UNICODE_PROP_ID_Start,
                               POP_PROP, UNICODE_PROP_ID_Continue1,
                               POP_XOR,
                               POP_END);
        break;
#endif
    default:
        if (prop_idx >= countof(unicode_prop_table))
            return -2;
        ret = unicode_prop1(cr, prop_idx);
        break;
    }
    return ret;
}

#endif /* CONFIG_ALL_UNICODE */
