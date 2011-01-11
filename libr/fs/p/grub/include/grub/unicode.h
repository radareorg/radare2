/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_BIDI_HEADER
#define GRUB_BIDI_HEADER	1

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>

struct grub_unicode_bidi_pair
{
  grub_uint32_t key;
  grub_uint32_t replace;
};

struct grub_unicode_compact_range
{
  grub_uint32_t start:21;
  grub_uint32_t end:21;
  grub_uint8_t bidi_type:5;
  grub_uint8_t comb_type;
  grub_uint8_t bidi_mirror:1;
  grub_uint8_t join_type:3;
} __attribute__ ((packed));

/* Old-style Arabic shaping. Used for "visual UTF-8" and
   in grub-mkfont to find variant glyphs in absence of GPOS tables.  */
struct grub_unicode_arabic_shape
{
  grub_uint32_t code;
  grub_uint32_t isolated;
  grub_uint32_t right_linked;
  grub_uint32_t both_linked;
  grub_uint32_t left_linked;
};

extern struct grub_unicode_arabic_shape grub_unicode_arabic_shapes[];

enum grub_bidi_type
  {
    GRUB_BIDI_TYPE_L = 0,
    GRUB_BIDI_TYPE_LRE,
    GRUB_BIDI_TYPE_LRO,
    GRUB_BIDI_TYPE_R,
    GRUB_BIDI_TYPE_AL,
    GRUB_BIDI_TYPE_RLE,
    GRUB_BIDI_TYPE_RLO,
    GRUB_BIDI_TYPE_PDF,
    GRUB_BIDI_TYPE_EN,
    GRUB_BIDI_TYPE_ES,
    GRUB_BIDI_TYPE_ET,
    GRUB_BIDI_TYPE_AN,
    GRUB_BIDI_TYPE_CS,
    GRUB_BIDI_TYPE_NSM,
    GRUB_BIDI_TYPE_BN,
    GRUB_BIDI_TYPE_B,
    GRUB_BIDI_TYPE_S,
    GRUB_BIDI_TYPE_WS,
    GRUB_BIDI_TYPE_ON
  };

enum grub_join_type
  {
    GRUB_JOIN_TYPE_NONJOINING = 0,
    GRUB_JOIN_TYPE_LEFT = 1,
    GRUB_JOIN_TYPE_RIGHT = 2,
    GRUB_JOIN_TYPE_DUAL = 3,
    GRUB_JOIN_TYPE_CAUSING = 4,
    GRUB_JOIN_TYPE_TRANSPARENT = 5
  };

enum grub_comb_type
  {
    GRUB_UNICODE_COMB_NONE = 0,
    GRUB_UNICODE_COMB_OVERLAY = 1,
    GRUB_UNICODE_COMB_HEBREW_SHEVA = 10,
    GRUB_UNICODE_COMB_HEBREW_HATAF_SEGOL = 11,
    GRUB_UNICODE_COMB_HEBREW_HATAF_PATAH = 12,
    GRUB_UNICODE_COMB_HEBREW_HATAF_QAMATS = 13,
    GRUB_UNICODE_COMB_HEBREW_HIRIQ = 14,
    GRUB_UNICODE_COMB_HEBREW_TSERE = 15,
    GRUB_UNICODE_COMB_HEBREW_SEGOL = 16,
    GRUB_UNICODE_COMB_HEBREW_PATAH = 17,
    GRUB_UNICODE_COMB_HEBREW_QAMATS = 18,
    GRUB_UNICODE_COMB_HEBREW_HOLAM = 19,
    GRUB_UNICODE_COMB_HEBREW_QUBUTS = 20,
    GRUB_UNICODE_COMB_HEBREW_DAGESH = 21,
    GRUB_UNICODE_COMB_HEBREW_METEG = 22,
    GRUB_UNICODE_COMB_HEBREW_RAFE = 23,
    GRUB_UNICODE_COMB_HEBREW_SHIN_DOT = 24,
    GRUB_UNICODE_COMB_HEBREW_SIN_DOT = 25,
    GRUB_UNICODE_COMB_HEBREW_VARIKA = 26,
    GRUB_UNICODE_COMB_ARABIC_FATHATAN = 27,
    GRUB_UNICODE_COMB_ARABIC_DAMMATAN = 28,
    GRUB_UNICODE_COMB_ARABIC_KASRATAN = 29,
    GRUB_UNICODE_COMB_ARABIC_FATHAH = 30,
    GRUB_UNICODE_COMB_ARABIC_DAMMAH = 31,
    GRUB_UNICODE_COMB_ARABIC_KASRA = 32,
    GRUB_UNICODE_COMB_ARABIC_SHADDA = 33,
    GRUB_UNICODE_COMB_ARABIC_SUKUN = 34,
    GRUB_UNICODE_COMB_ARABIC_SUPERSCRIPT_ALIF = 35,
    GRUB_UNICODE_COMB_SYRIAC_SUPERSCRIPT_ALAPH = 36,
    GRUB_UNICODE_STACK_ATTACHED_BELOW = 202,
    GRUB_UNICODE_STACK_ATTACHED_ABOVE = 214,
    GRUB_UNICODE_COMB_ATTACHED_ABOVE_RIGHT = 216,
    GRUB_UNICODE_STACK_BELOW = 220,
    GRUB_UNICODE_COMB_BELOW_RIGHT = 222,
    GRUB_UNICODE_COMB_ABOVE_LEFT = 228,
    GRUB_UNICODE_STACK_ABOVE = 230,
    GRUB_UNICODE_COMB_ABOVE_RIGHT = 232,
    GRUB_UNICODE_COMB_YPOGEGRAMMENI = 240,
    /* If combining nature is indicated only by class and
       not "combining type".  */
    GRUB_UNICODE_COMB_ME = 253,
    GRUB_UNICODE_COMB_MC = 254,
    GRUB_UNICODE_COMB_MN = 255,
  };

/* This structure describes a glyph as opposed to character.  */
struct grub_unicode_glyph
{
  grub_uint32_t base;
  grub_uint16_t variant:9;
  grub_uint8_t attributes:5;
  grub_size_t ncomb;
  struct grub_unicode_combining {
    grub_uint32_t code;
    enum grub_comb_type type;
  } *combining;
  /* Hint by unicode subsystem how wide this character usually is.
     Real width is determined by font. Set only in UTF-8 stream.  */
  int estimated_width;
};

#define GRUB_UNICODE_GLYPH_ATTRIBUTE_MIRROR 0x1
#define GRUB_UNICODE_GLYPH_ATTRIBUTES_JOIN_LEFT_TO_RIGHT_SHIFT 1
#define GRUB_UNICODE_GLYPH_ATTRIBUTE_LEFT_JOINED 0x2
#define GRUB_UNICODE_GLYPH_ATTRIBUTE_RIGHT_JOINED \
  (GRUB_UNICODE_GLYPH_ATTRIBUTE_LEFT_JOINED \
   << GRUB_UNICODE_GLYPH_ATTRIBUTES_JOIN_LEFT_TO_RIGHT_SHIFT)
/* Set iff the corresponding joining flags come from ZWJ or ZWNJ.  */
#define GRUB_UNICODE_GLYPH_ATTRIBUTE_LEFT_JOINED_EXPLICIT 0x8
#define GRUB_UNICODE_GLYPH_ATTRIBUTE_RIGHT_JOINED_EXPLICIT \
  (GRUB_UNICODE_GLYPH_ATTRIBUTE_LEFT_JOINED_EXPLICIT \
   << GRUB_UNICODE_GLYPH_ATTRIBUTES_JOIN_LEFT_TO_RIGHT_SHIFT)
#define GRUB_UNICODE_GLYPH_ATTRIBUTES_JOIN \
  (GRUB_UNICODE_GLYPH_ATTRIBUTE_LEFT_JOINED \
   | GRUB_UNICODE_GLYPH_ATTRIBUTE_RIGHT_JOINED \
   | GRUB_UNICODE_GLYPH_ATTRIBUTE_LEFT_JOINED_EXPLICIT \
   | GRUB_UNICODE_GLYPH_ATTRIBUTE_RIGHT_JOINED_EXPLICIT)

enum
  {
    GRUB_UNICODE_COMBINING_GRAPHEME_JOINER = 0x034f,
    GRUB_UNICODE_HEBREW_WAW                = 0x05d5,
    GRUB_UNICODE_ARABIC_START              = 0x0600,
    GRUB_UNICODE_ARABIC_END                = 0x0700,
    GRUB_UNICODE_THAANA_ABAFILI            = 0x07a6,
    GRUB_UNICODE_THAANA_AABAAFILI          = 0x07a7,
    GRUB_UNICODE_THAANA_IBIFILI            = 0x07a8,
    GRUB_UNICODE_THAANA_EEBEEFILI          = 0x07a9,
    GRUB_UNICODE_THAANA_UBUFILI            = 0x07aa,
    GRUB_UNICODE_THAANA_OOBOOFILI          = 0x07ab,
    GRUB_UNICODE_THAANA_EBEFILI            = 0x07ac,
    GRUB_UNICODE_THAANA_EYBEYFILI          = 0x07ad,
    GRUB_UNICODE_THAANA_OBOFILI            = 0x07ae,
    GRUB_UNICODE_THAANA_OABOAFILI          = 0x07af,
    GRUB_UNICODE_THAANA_SUKUN              = 0x07b0,
    GRUB_UNICODE_ZWNJ                      = 0x200c,
    GRUB_UNICODE_ZWJ                       = 0x200d,
    GRUB_UNICODE_LEFTARROW                 = 0x2190,
    GRUB_UNICODE_UPARROW                   = 0x2191,
    GRUB_UNICODE_RIGHTARROW                = 0x2192,
    GRUB_UNICODE_DOWNARROW                 = 0x2193,
    GRUB_UNICODE_LIGHT_HLINE               = 0x2500,
    GRUB_UNICODE_HLINE                     = 0x2501,
    GRUB_UNICODE_LIGHT_VLINE               = 0x2502,
    GRUB_UNICODE_VLINE                     = 0x2503,
    GRUB_UNICODE_LIGHT_CORNER_UL           = 0x250c,
    GRUB_UNICODE_CORNER_UL                 = 0x250f,
    GRUB_UNICODE_LIGHT_CORNER_UR           = 0x2510,
    GRUB_UNICODE_CORNER_UR                 = 0x2513,
    GRUB_UNICODE_LIGHT_CORNER_LL           = 0x2514,
    GRUB_UNICODE_CORNER_LL                 = 0x2517,
    GRUB_UNICODE_LIGHT_CORNER_LR           = 0x2518,
    GRUB_UNICODE_CORNER_LR                 = 0x251b,
    GRUB_UNICODE_BLACK_UP_TRIANGLE         = 0x25b2,
    GRUB_UNICODE_BLACK_RIGHT_TRIANGLE      = 0x25ba,
    GRUB_UNICODE_BLACK_DOWN_TRIANGLE       = 0x25bc,
    GRUB_UNICODE_BLACK_LEFT_TRIANGLE       = 0x25c4,
    GRUB_UNICODE_VARIATION_SELECTOR_1      = 0xfe00,
    GRUB_UNICODE_VARIATION_SELECTOR_16     = 0xfe0f,
    GRUB_UNICODE_VARIATION_SELECTOR_17     = 0xe0100,
    GRUB_UNICODE_VARIATION_SELECTOR_256    = 0xe01ef
  };

extern struct grub_unicode_compact_range grub_unicode_compact[];
extern struct grub_unicode_bidi_pair grub_unicode_bidi_pairs[];

#define GRUB_UNICODE_MAX_CACHED_CHAR 0x20000
/*  Unicode mandates an arbitrary limit.  */
#define GRUB_BIDI_MAX_EXPLICIT_LEVEL 61

grub_ssize_t
grub_bidi_logical_to_visual (const grub_uint32_t *logical,
			     grub_size_t logical_len,
			     struct grub_unicode_glyph **visual_out,
			     grub_ssize_t (*getcharwidth) (const struct grub_unicode_glyph *visual),
			     grub_size_t max_width,
			     grub_size_t start_width);

enum grub_comb_type
grub_unicode_get_comb_type (grub_uint32_t c);
grub_size_t
grub_unicode_aglomerate_comb (const grub_uint32_t *in, grub_size_t inlen,
			      struct grub_unicode_glyph *out);

static inline struct grub_unicode_glyph *
grub_unicode_glyph_dup (const struct grub_unicode_glyph *in)
{
  struct grub_unicode_glyph *out = grub_malloc (sizeof (*out));
  if (!out)
    return NULL;
  grub_memcpy (out, in, sizeof (*in));
  if (in->combining)
    {
      out->combining = grub_malloc (in->ncomb * sizeof (*in));
      if (!out->combining)
	{
	  grub_free (out);
	  return NULL;
	}
      grub_memcpy (out->combining, in->combining, in->ncomb * sizeof (*in));
    }
  return out;
}

static inline struct grub_unicode_glyph *
grub_unicode_glyph_from_code (grub_uint32_t code)
{
  struct grub_unicode_glyph *ret;
  ret = grub_zalloc (sizeof (*ret));
  if (!ret)
    return NULL;

  ret->base = code;

  return ret;
}

grub_uint32_t
grub_unicode_mirror_code (grub_uint32_t in);
grub_uint32_t
grub_unicode_shape_code (grub_uint32_t in, grub_uint8_t attr);

#endif
