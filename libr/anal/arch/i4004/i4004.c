/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: gperf -aclEDCIG --null-strings -H sdb_hash_c_i4004 -N sdb_get_c_i4004 -t i4004.gperf  */
/* Computed positions: -k'1-2,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "i4004.gperf"

// gperf -aclEDCIG --null-strings -H sdb_hash_c_i4004 -N sdb_get_c_i4004 -t i4004.gperf > i4004.c
// gcc -DMAIN=1 i4004.c ; ./a.out > i4004.h
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#line 9 "i4004.gperf"
struct i4004_kv { const char *name; const char *value; };
#include <string.h>
enum
  {
    i4004_TOTAL_KEYWORDS = 167,
    i4004_i4004_MIN_WORD_LENGTH = 3,
    i4004_MAX_WORD_LENGTH = 10,
    i4004_MIN_HASH_VALUE = 7,
    i4004_MAX_HASH_VALUE = 477
  };

/* maximum key range = 471, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
sdb_hash_c_i4004 (register const char *str, register size_t len)
{
  static const unsigned short asso_values[] =
    {
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 150,  55,
      140,  45, 230,  85,   8, 194,  99,   3, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478,   5,  15,  10,
       75,   0, 245, 478, 478,   0,   0,   0,   0, 155,
        0, 240,  20,   5,  60,  25,  25,   0, 100,  60,
        0, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478, 478, 478, 478,
      478, 478, 478, 478, 478, 478, 478
    };
  return len + asso_values[(unsigned char)str[1]+1] + asso_values[(unsigned char)str[0]] + asso_values[(unsigned char)str[len - 1]];
}

static const unsigned char i4004_lengthtable[] =
  {
     7,  5,  7,  8,  7,  5,  6,  7,  7,  3,  6,  7,  3,  3,
     7,  3,  7,  7,  3,  7,  7,  3,  7,  5,  6,  7,  8, 10,
     6,  7,  5,  6,  7,  8,  6, 10,  6,  7,  7,  3,  7,  3,
     6,  7,  6,  5,  6,  7,  8, 10,  6,  7,  3,  6,  3,  5,
     7,  7,  3,  6,  6,  3,  7,  3,  3,  6,  7,  3,  7,  3,
     6,  6,  7,  3,  6,  6,  3,  5,  6,  7,  3,  6,  7,  3,
     5,  6,  7,  6,  7,  3,  6,  7,  7,  6,  7,  3,  6,  7,
     3,  6,  7,  3,  6,  5,  7,  8,  3,  6,  6,  3,  6,  7,
     3,  6,  7,  3,  7,  3,  6,  6,  7,  5,  6,  7,  3,  6,
     7,  3,  6,  6,  7,  6,  8,  7,  6,  7,  6,  7,  6,  7,
     6,  6,  7,  8, 10,  6,  7,  8, 10,  6,  7,  6,  6,  7,
     8, 10,  6,  6,  7,  6,  7,  6,  7,  6,  8,  6,  7
  };

static const struct i4004_kv i4004_wordlist[] =
  {
#line 146 "i4004.gperf"
    {"ldm 0xe","de"},
#line 93 "i4004.gperf"
    {"ld r9","a9"},
#line 141 "i4004.gperf"
    {"ldm 0x9","d9"},
#line 29 "i4004.gperf"
    {"jin r8r9","39"},
#line 142 "i4004.gperf"
    {"ldm 0xa","da"},
#line 90 "i4004.gperf"
    {"ld r6","a6"},
#line 61 "i4004.gperf"
    {"add r9","89"},
#line 138 "i4004.gperf"
    {"ldm 0x6","d6"},
#line 144 "i4004.gperf"
    {"ldm 0xc","dc"},
#line 168 "i4004.gperf"
    {"cma","f4"},
#line 58 "i4004.gperf"
    {"add r6","86"},
#line 143 "i4004.gperf"
    {"ldm 0xb","db"},
#line 167 "i4004.gperf"
    {"cmc","f3"},
#line 166 "i4004.gperf"
    {"iac","f2"},
#line 130 "i4004.gperf"
    {"bbl 0xe","ce"},
#line 176 "i4004.gperf"
    {"kbp","fc"},
#line 125 "i4004.gperf"
    {"bbl 0x9","c9"},
#line 126 "i4004.gperf"
    {"bbl 0xa","ca"},
#line 174 "i4004.gperf"
    {"stc","fa"},
#line 122 "i4004.gperf"
    {"bbl 0x6","c6"},
#line 128 "i4004.gperf"
    {"bbl 0xc","cc"},
#line 11 "i4004.gperf"
    {"nop","00"},
#line 127 "i4004.gperf"
    {"bbl 0xb","cb"},
#line 87 "i4004.gperf"
    {"ld r3","a3"},
#line 97 "i4004.gperf"
    {"ld r13","ad"},
#line 135 "i4004.gperf"
    {"ldm 0x3","d3"},
#line 23 "i4004.gperf"
    {"jin r2r3","33"},
#line 33 "i4004.gperf"
    {"jin r12r13","3d"},
#line 55 "i4004.gperf"
    {"add r3","83"},
#line 65 "i4004.gperf"
    {"add r13","8d"},
#line 85 "i4004.gperf"
    {"ld r1","a1"},
#line 95 "i4004.gperf"
    {"ld r11","ab"},
#line 133 "i4004.gperf"
    {"ldm 0x1","d1"},
#line 21 "i4004.gperf"
    {"jin r0r1","31"},
#line 18 "i4004.gperf"
    {"src r6","2d"},
#line 31 "i4004.gperf"
    {"jin r10r11","3b"},
#line 53 "i4004.gperf"
    {"add r1","81"},
#line 63 "i4004.gperf"
    {"add r11","8b"},
#line 119 "i4004.gperf"
    {"bbl 0x3","c3"},
#line 169 "i4004.gperf"
    {"ral","f5"},
#line 145 "i4004.gperf"
    {"ldm 0xd","dd"},
#line 149 "i4004.gperf"
    {"wmp","e1"},
#line 109 "i4004.gperf"
    {"xch r9","b9"},
#line 117 "i4004.gperf"
    {"bbl 0x1","c1"},
#line 106 "i4004.gperf"
    {"xch r6","b6"},
#line 89 "i4004.gperf"
    {"ld r5","a5"},
#line 99 "i4004.gperf"
    {"ld r15","af"},
#line 137 "i4004.gperf"
    {"ldm 0x5","d5"},
#line 25 "i4004.gperf"
    {"jin r4r5","35"},
#line 35 "i4004.gperf"
    {"jin r14r15","3f"},
#line 57 "i4004.gperf"
    {"add r5","85"},
#line 67 "i4004.gperf"
    {"add r15","8f"},
#line 175 "i4004.gperf"
    {"daa","fb"},
#line 15 "i4004.gperf"
    {"src r3","27"},
#line 172 "i4004.gperf"
    {"dac","f8"},
#line 92 "i4004.gperf"
    {"ld r8","a8"},
#line 140 "i4004.gperf"
    {"ldm 0x8","d8"},
#line 129 "i4004.gperf"
    {"bbl 0xd","cd"},
#line 163 "i4004.gperf"
    {"rd3","ef"},
#line 60 "i4004.gperf"
    {"add r8","88"},
#line 13 "i4004.gperf"
    {"src r1","23"},
#line 171 "i4004.gperf"
    {"tcc","f7"},
#line 121 "i4004.gperf"
    {"bbl 0x5","c5"},
#line 161 "i4004.gperf"
    {"rd1","ed"},
#line 158 "i4004.gperf"
    {"rdr","ea"},
#line 103 "i4004.gperf"
    {"xch r3","b3"},
#line 113 "i4004.gperf"
    {"xch r13","bd"},
#line 173 "i4004.gperf"
    {"tcs","f9"},
#line 124 "i4004.gperf"
    {"bbl 0x8","c8"},
#line 155 "i4004.gperf"
    {"wr3","e7"},
#line 77 "i4004.gperf"
    {"sub r9","99"},
#line 101 "i4004.gperf"
    {"xch r1","b1"},
#line 111 "i4004.gperf"
    {"xch r11","bb"},
#line 170 "i4004.gperf"
    {"rar","f6"},
#line 74 "i4004.gperf"
    {"sub r6","96"},
#line 17 "i4004.gperf"
    {"src r5","2b"},
#line 153 "i4004.gperf"
    {"wr1","e5"},
#line 86 "i4004.gperf"
    {"ld r2","a2"},
#line 96 "i4004.gperf"
    {"ld r12","ac"},
#line 134 "i4004.gperf"
    {"ldm 0x2","d2"},
#line 150 "i4004.gperf"
    {"wrr","e2"},
#line 54 "i4004.gperf"
    {"add r2","82"},
#line 64 "i4004.gperf"
    {"add r12","8c"},
#line 177 "i4004.gperf"
    {"dcl","fd"},
#line 84 "i4004.gperf"
    {"ld r0","a0"},
#line 94 "i4004.gperf"
    {"ld r10","aa"},
#line 132 "i4004.gperf"
    {"ldm 0x0","d0"},
#line 52 "i4004.gperf"
    {"add r0","80"},
#line 62 "i4004.gperf"
    {"add r10","8a"},
#line 159 "i4004.gperf"
    {"adm","eb"},
#line 105 "i4004.gperf"
    {"xch r5","b5"},
#line 115 "i4004.gperf"
    {"xch r15","bf"},
#line 118 "i4004.gperf"
    {"bbl 0x2","c2"},
#line 71 "i4004.gperf"
    {"sub r3","93"},
#line 81 "i4004.gperf"
    {"sub r13","9d"},
#line 165 "i4004.gperf"
    {"clc","f1"},
#line 108 "i4004.gperf"
    {"xch r8","b8"},
#line 116 "i4004.gperf"
    {"bbl 0x0","c0"},
#line 164 "i4004.gperf"
    {"clb","f0"},
#line 69 "i4004.gperf"
    {"sub r1","91"},
#line 79 "i4004.gperf"
    {"sub r11","9b"},
#line 156 "i4004.gperf"
    {"sbm","e8"},
#line 14 "i4004.gperf"
    {"src r2","25"},
#line 91 "i4004.gperf"
    {"ld r7","a7"},
#line 139 "i4004.gperf"
    {"ldm 0x7","d7"},
#line 27 "i4004.gperf"
    {"jin r6r7","37"},
#line 162 "i4004.gperf"
    {"rd2","ee"},
#line 59 "i4004.gperf"
    {"add r7","87"},
#line 12 "i4004.gperf"
    {"src r0","21"},
#line 160 "i4004.gperf"
    {"rd0","ec"},
#line 73 "i4004.gperf"
    {"sub r5","95"},
#line 83 "i4004.gperf"
    {"sub r15","9f"},
#line 157 "i4004.gperf"
    {"rdm","e9"},
#line 102 "i4004.gperf"
    {"xch r2","b2"},
#line 112 "i4004.gperf"
    {"xch r12","bc"},
#line 151 "i4004.gperf"
    {"wpm","e3"},
#line 123 "i4004.gperf"
    {"bbl 0x7","c7"},
#line 154 "i4004.gperf"
    {"wr2","e6"},
#line 76 "i4004.gperf"
    {"sub r8","98"},
#line 100 "i4004.gperf"
    {"xch r0","b0"},
#line 110 "i4004.gperf"
    {"xch r10","ba"},
#line 88 "i4004.gperf"
    {"ld r4","a4"},
#line 98 "i4004.gperf"
    {"ld r14","ae"},
#line 136 "i4004.gperf"
    {"ldm 0x4","d4"},
#line 152 "i4004.gperf"
    {"wr0","e4"},
#line 56 "i4004.gperf"
    {"add r4","84"},
#line 66 "i4004.gperf"
    {"add r14","8e"},
#line 148 "i4004.gperf"
    {"wrm","e0"},
#line 45 "i4004.gperf"
    {"inc r9","69"},
#line 19 "i4004.gperf"
    {"src r7","2f"},
#line 147 "i4004.gperf"
    {"ldm 0xf","df"},
#line 42 "i4004.gperf"
    {"inc r6","66"},
#line 28 "i4004.gperf"
    {"fin r8r9","38"},
#line 120 "i4004.gperf"
    {"bbl 0x4","c4"},
#line 70 "i4004.gperf"
    {"sub r2","92"},
#line 80 "i4004.gperf"
    {"sub r12","9c"},
#line 107 "i4004.gperf"
    {"xch r7","b7"},
#line 131 "i4004.gperf"
    {"bbl 0xf","cf"},
#line 68 "i4004.gperf"
    {"sub r0","90"},
#line 78 "i4004.gperf"
    {"sub r10","9a"},
#line 16 "i4004.gperf"
    {"src r4","29"},
#line 39 "i4004.gperf"
    {"inc r3","63"},
#line 49 "i4004.gperf"
    {"inc r13","6d"},
#line 22 "i4004.gperf"
    {"fin r2r3","32"},
#line 32 "i4004.gperf"
    {"fin r12r13","3c"},
#line 37 "i4004.gperf"
    {"inc r1","61"},
#line 47 "i4004.gperf"
    {"inc r11","6b"},
#line 20 "i4004.gperf"
    {"fin r0r1","30"},
#line 30 "i4004.gperf"
    {"fin r10r11","3a"},
#line 104 "i4004.gperf"
    {"xch r4","b4"},
#line 114 "i4004.gperf"
    {"xch r14","be"},
#line 75 "i4004.gperf"
    {"sub r7","97"},
#line 41 "i4004.gperf"
    {"inc r5","65"},
#line 51 "i4004.gperf"
    {"inc r15","6f"},
#line 24 "i4004.gperf"
    {"fin r4r5","34"},
#line 34 "i4004.gperf"
    {"fin r14r15","3e"},
#line 44 "i4004.gperf"
    {"inc r8","68"},
#line 72 "i4004.gperf"
    {"sub r4","94"},
#line 82 "i4004.gperf"
    {"sub r14","9e"},
#line 38 "i4004.gperf"
    {"inc r2","62"},
#line 48 "i4004.gperf"
    {"inc r12","6c"},
#line 36 "i4004.gperf"
    {"inc r0","60"},
#line 46 "i4004.gperf"
    {"inc r10","6a"},
#line 43 "i4004.gperf"
    {"inc r7","67"},
#line 26 "i4004.gperf"
    {"fin r6r7","36"},
#line 40 "i4004.gperf"
    {"inc r4","64"},
#line 50 "i4004.gperf"
    {"inc r14","6e"}
  };

static const short i4004_lookup[] =
  {
     -1,  -1,  -1,  -1,  -1,  -1,  -1,   0,   1,  -1,
      2,   3,   4,   5,   6,   7,  -1,   8,   9,  10,
     -1,  -1,  11,  12,  -1,  -1,  -1,  -1,  13,  -1,
     -1,  -1,  14,  15,  -1,  16,  -1,  17,  18,  -1,
     19,  -1,  20,  21,  -1,  -1,  -1,  22,  -1,  -1,
     23,  24,  25,  26,  -1,  27,  28,  29,  -1,  -1,
     30,  31,  32,  33,  34,  35,  36,  37,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  38,  39,  -1,
     -1,  -1,  40,  41,  42,  -1,  -1,  43,  -1,  44,
     45,  46,  47,  48,  -1,  49,  50,  51,  52,  -1,
     -1,  53,  -1,  54,  55,  -1,  56,  57,  58,  -1,
     59,  60,  -1,  61,  -1,  -1,  -1,  62,  63,  -1,
     -1,  -1,  -1,  64,  -1,  -1,  65,  66,  67,  -1,
     -1,  68,  -1,  69,  70,  -1,  71,  72,  73,  74,
     -1,  75,  -1,  76,  -1,  77,  78,  79,  80,  -1,
     -1,  81,  82,  83,  -1,  84,  85,  86,  -1,  -1,
     -1,  87,  88,  89,  -1,  -1,  90,  91,  -1,  -1,
     -1,  -1,  92,  -1,  -1,  -1,  93,  94,  95,  -1,
     96,  -1,  97,  98,  -1,  -1,  99, 100,  -1,  -1,
     -1,  -1,  -1, 101,  -1,  -1, 102,  -1,  -1, 103,
     -1, 104, 105, 106,  -1, 107, 108,  -1,  -1,  -1,
     -1,  -1,  -1, 109,  -1,  -1, 110, 111, 112,  -1,
     -1, 113, 114, 115,  -1,  -1, 116,  -1, 117,  -1,
    118, 119, 120,  -1,  -1, 121, 122, 123, 124,  -1,
     -1, 125, 126, 127,  -1,  -1,  -1,  -1,  -1, 128,
    129,  -1, 130,  -1, 131,  -1, 132,  -1,  -1,  -1,
     -1,  -1, 133,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 134, 135,  -1,  -1, 136,  -1, 137,  -1,  -1,
     -1, 138, 139,  -1,  -1,  -1, 140,  -1,  -1,  -1,
     -1, 141, 142,  -1,  -1,  -1,  -1,  -1, 143,  -1,
    144, 145, 146,  -1,  -1,  -1,  -1,  -1, 147,  -1,
    148, 149, 150,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1, 151,  -1,  -1,  -1,  -1,
     -1, 152, 153,  -1,  -1,  -1,  -1,  -1, 154,  -1,
    155,  -1,  -1,  -1,  -1, 156,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 157, 158,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1, 159, 160,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1, 161, 162,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    163,  -1,  -1,  -1,  -1,  -1,  -1, 164,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1, 165, 166
  };

const struct i4004_kv *
sdb_get_c_i4004 (register const char *str, register size_t len)
{
  if (len <= i4004_MAX_WORD_LENGTH && len >= i4004_i4004_MIN_WORD_LENGTH)
    {
      register unsigned int key = sdb_hash_c_i4004 (str, len);

      if (key <= i4004_MAX_HASH_VALUE)
        {
          register int index = i4004_lookup[key];

          if (index >= 0)
            {
              if (len == i4004_lengthtable[index])
                {
                  register const char *s = i4004_wordlist[index].name;

                  if (*str == *s && !memcmp (str + 1, s + 1, len - 1))
                    return &i4004_wordlist[index];
                }
            }
        }
    }
  return 0;
}
#line 178 "i4004.gperf"

// SDB-CGEN V1.9.0
// 0x5646ad24c160
typedef int (*GperfForeachCallback)(void *user, const char *k, const char *v);
int gperf_i4004_foreach(GperfForeachCallback cb, void *user) {
	int i;for (i=0;i<i4004_TOTAL_KEYWORDS;i++) {
	const struct i4004_kv *w = &i4004_wordlist[i];
	if (!cb (user, w->name, w->value)) return 0;
}
return 1;}
const char* gperf_i4004_get(const char *s) {
	const struct i4004_kv *o = sdb_get_c_i4004 (s, strlen(s));
	return o? o->value: NULL;
}
const unsigned int gperf_i4004_hash(const char *s) {
	return sdb_hash_c_i4004(s, strlen (s));
}
struct {const char*name;void*get;void*hash;void *foreach;} gperf_i4004 = {
	.name = "i4004",
	.get = &gperf_i4004_get,
	.hash = &gperf_i4004_hash,
	.foreach = &gperf_i4004_foreach
};

#if MAIN
int main () {
	char line[1024];
	FILE *fd = fopen ("i4004.gperf", "r");
	if (!fd) {
		fprintf (stderr, "Cannot open i4004.gperf\n");
		return 1;
	}
	int mode = 0;
	printf ("#ifndef INCLUDE_i4004_H\n");
	printf ("#define INCLUDE_i4004_H 1\n");
	while (!feof (fd)) {
		*line = 0;
		fgets (line, sizeof (line), fd);
		if (mode == 1) {
			char *comma = strchr (line, ',');
			if (comma) {
				*comma = 0;
				char *up = strdup (line);
				char *p = up; while (*p) { *p = toupper (*p); p++; }
				printf ("#define GPERF_i4004_%s %d\n",
					line, sdb_hash_c_i4004 (line, comma - line));
			}
		}
		if (*line == '%' && line[1] == '%')
			mode++;
	}
	printf ("#endif\n");
}
#endif

