/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef YR_YARA_H
#define YR_YARA_H

#include <stdio.h>
#include <stdint.h>
#include <setjmp.h>

#ifdef WIN32
#include <windows.h>
typedef HANDLE mutex_t;
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
#endif

typedef int32_t tidx_mask_t;

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

#define FAIL_ON_ERROR(x) { \
  int result = (x); \
  if (result != ERROR_SUCCESS) \
    return result; \
}

#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS                           0
#endif

#define ERROR_INSUFICIENT_MEMORY                1
#define ERROR_COULD_NOT_ATTACH_TO_PROCESS       2
#define ERROR_COULD_NOT_OPEN_FILE               3
#define ERROR_COULD_NOT_MAP_FILE                4
#define ERROR_ZERO_LENGTH_FILE                  5
#define ERROR_INVALID_FILE                      6
#define ERROR_CORRUPT_FILE                      7
#define ERROR_UNSUPPORTED_FILE_VERSION          8
#define ERROR_INVALID_REGULAR_EXPRESSION        9
#define ERROR_INVALID_HEX_STRING                10
#define ERROR_SYNTAX_ERROR                      11
#define ERROR_LOOP_NESTING_LIMIT_EXCEEDED       12
#define ERROR_DUPLICATE_LOOP_IDENTIFIER         13
#define ERROR_DUPLICATE_RULE_IDENTIFIER         14
#define ERROR_DUPLICATE_TAG_IDENTIFIER          15
#define ERROR_DUPLICATE_META_IDENTIFIER         16
#define ERROR_DUPLICATE_STRING_IDENTIFIER       17
#define ERROR_UNREFERENCED_STRING               18
#define ERROR_UNDEFINED_STRING                  19
#define ERROR_UNDEFINED_IDENTIFIER              20
#define ERROR_MISPLACED_ANONYMOUS_STRING        21
#define ERROR_INCLUDES_CIRCULAR_REFERENCE       22
#define ERROR_INCLUDE_DEPTH_EXCEEDED            23
#define ERROR_INCORRECT_VARIABLE_TYPE           24
#define ERROR_EXEC_STACK_OVERFLOW               25
#define ERROR_SCAN_TIMEOUT                      26
#define ERROR_TOO_MANY_SCAN_THREADS             27
#define ERROR_CALLBACK_ERROR                    28
#define ERROR_INVALID_ARGUMENT                  29
#define ERROR_TOO_MANY_MATCHES                  30
#define ERROR_INTERNAL_FATAL_ERROR              31


#define CALLBACK_MSG_RULE_MATCHING              1
#define CALLBACK_MSG_RULE_NOT_MATCHING          2
#define CALLBACK_MSG_SCAN_FINISHED              3

#define CALLBACK_CONTINUE   0
#define CALLBACK_ABORT      1
#define CALLBACK_ERROR      2

#define MAX_ATOM_LENGTH     4
#define LOOP_LOCAL_VARS     4
#define MAX_LOOP_NESTING    4
#define MAX_INCLUDE_DEPTH   16
#define MAX_STRING_MATCHES  1000000

#define STRING_CHAINING_THRESHOLD 200
#define LEX_BUF_SIZE  1024

// MAX_THREADS is the number of threads that can use a YR_RULES
// object simultaneosly. This value is limited by the number of
// bits in tidx_mask.

#define MAX_THREADS sizeof(tidx_mask_t) * 8


#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

/*
    Mask examples:

    string : B1 (  01 02 |  03 04 )  3? ?? 45
    mask:    FF AA FF FF AA FF FF BB F0 00 FF

    string : C5 45 [3]   00 45|
    mask:    FF FF CC 03 FF FF

    string : C5 45 [2-5]    00 45
    mask:    FF FF DD 02 03 FF FF

*/

#define MASK_OR            0xAA
#define MASK_OR_END        0xBB
#define MASK_EXACT_SKIP    0xCC
#define MASK_RANGE_SKIP    0xDD
#define MASK_END           0xEE

#define MASK_MAX_SKIP      255

#define META_TYPE_NULL                  0
#define META_TYPE_INTEGER               1
#define META_TYPE_STRING                2
#define META_TYPE_BOOLEAN               3

#define META_IS_NULL(x) \
    ((x) != NULL ? (x)->type == META_TYPE_NULL : TRUE)

#define EXTERNAL_VARIABLE_TYPE_NULL          0
#define EXTERNAL_VARIABLE_TYPE_ANY           1
#define EXTERNAL_VARIABLE_TYPE_INTEGER       2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN       3
#define EXTERNAL_VARIABLE_TYPE_FIXED_STRING  4
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING 5

#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : TRUE)


#define STRING_TFLAGS_FOUND             0x01

#define STRING_GFLAGS_REFERENCED        0x01
#define STRING_GFLAGS_HEXADECIMAL       0x02
#define STRING_GFLAGS_NO_CASE           0x04
#define STRING_GFLAGS_ASCII             0x08
#define STRING_GFLAGS_WIDE              0x10
#define STRING_GFLAGS_REGEXP            0x20
#define STRING_GFLAGS_FAST_HEX_REGEXP   0x40
#define STRING_GFLAGS_FULL_WORD         0x80
#define STRING_GFLAGS_ANONYMOUS         0x100
#define STRING_GFLAGS_SINGLE_MATCH      0x200
#define STRING_GFLAGS_LITERAL           0x400
#define STRING_GFLAGS_FITS_IN_ATOM      0x800
#define STRING_GFLAGS_NULL              0x1000
#define STRING_GFLAGS_CHAIN_PART        0x2000
#define STRING_GFLAGS_CHAIN_TAIL        0x4000
#define STRING_GFLAGS_REGEXP_DOT_ALL    0x8000

#define STRING_IS_HEX(x) \
    (((x)->g_flags) & STRING_GFLAGS_HEXADECIMAL)

#define STRING_IS_NO_CASE(x) \
    (((x)->g_flags) & STRING_GFLAGS_NO_CASE)

#define STRING_IS_ASCII(x) \
    (((x)->g_flags) & STRING_GFLAGS_ASCII)

#define STRING_IS_WIDE(x) \
    (((x)->g_flags) & STRING_GFLAGS_WIDE)

#define STRING_IS_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP)

#define STRING_IS_REGEXP_DOT_ALL(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP_DOT_ALL)

#define STRING_IS_FULL_WORD(x) \
    (((x)->g_flags) & STRING_GFLAGS_FULL_WORD)

#define STRING_IS_ANONYMOUS(x) \
    (((x)->g_flags) & STRING_GFLAGS_ANONYMOUS)

#define STRING_IS_REFERENCED(x) \
    (((x)->g_flags) & STRING_GFLAGS_REFERENCED)

#define STRING_IS_SINGLE_MATCH(x) \
    (((x)->g_flags) & STRING_GFLAGS_SINGLE_MATCH)

#define STRING_IS_LITERAL(x) \
    (((x)->g_flags) & STRING_GFLAGS_LITERAL)

#define STRING_IS_FAST_HEX_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_FAST_HEX_REGEXP)

#define STRING_IS_CHAIN_PART(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_PART)

#define STRING_IS_CHAIN_TAIL(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_TAIL)

#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->g_flags) & STRING_GFLAGS_NULL)

#define STRING_FITS_IN_ATOM(x) \
    (((x)->g_flags) & STRING_GFLAGS_FITS_IN_ATOM)

#define STRING_FOUND(x) \
    ((x)->matches[r_yr_get_tidx()].tail != NULL)


#define RULE_TFLAGS_MATCH                0x01

#define RULE_GFLAGS_PRIVATE              0x01
#define RULE_GFLAGS_GLOBAL               0x02
#define RULE_GFLAGS_REQUIRE_EXECUTABLE   0x04
#define RULE_GFLAGS_REQUIRE_FILE         0x08
#define RULE_GFLAGS_NULL                 0x1000

#define RULE_IS_PRIVATE(x) \
    (((x)->g_flags) & RULE_GFLAGS_PRIVATE)

#define RULE_IS_GLOBAL(x) \
    (((x)->g_flags) & RULE_GFLAGS_GLOBAL)

#define RULE_IS_NULL(x) \
    (((x)->g_flags) & RULE_GFLAGS_NULL)

#define RULE_MATCHES(x) \
    ((x)->t_flags[r_yr_get_tidx()] & RULE_TFLAGS_MATCH)



#define NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL      0x01

#define NAMESPACE_HAS_UNSATISFIED_GLOBAL(x) \
    ((x)->t_flags[r_yr_get_tidx()] & NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL)



#define MAX_ARENA_PAGES 32

#define EOL ((size_t) -1)

#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; }


#define UINT64_TO_PTR(type, x)  ((type)(size_t) x)

#define PTR_TO_UINT64(x)  ((uint64_t) (size_t) x)

#define STRING_MATCHES(x) (x->matches[r_yr_get_tidx()])


typedef struct _YR_RELOC
{
  int32_t offset;
  struct _YR_RELOC* next;

} YR_RELOC;


typedef struct _YR_ARENA_PAGE
{

  uint8_t* new_address;
  uint8_t* address;

  size_t size;
  size_t used;

  YR_RELOC* reloc_list_head;
  YR_RELOC* reloc_list_tail;

  struct _YR_ARENA_PAGE* next;
  struct _YR_ARENA_PAGE* prev;

} YR_ARENA_PAGE;


typedef struct _YR_ARENA
{
  int flags;

  YR_ARENA_PAGE* page_list_head;
  YR_ARENA_PAGE* current_page;

} YR_ARENA;


#pragma pack(push)
#pragma pack(1)


typedef struct _YR_MATCH
{
  int64_t offset;
  int32_t length;

  union {
    uint8_t* data;            // Confirmed matches use "data",
    int32_t chain_length;    // unconfirmed ones use "chain_length"
  };

  struct _YR_MATCH*  prev;
  struct _YR_MATCH*  next;

} YR_MATCH;


typedef struct _YR_NAMESPACE
{
  int32_t t_flags[MAX_THREADS];     // Thread-specific flags
  DECLARE_REFERENCE(char*, name);

} YR_NAMESPACE;


typedef struct _YR_META
{
  int32_t type;
  int32_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} YR_META;


typedef struct _YR_MATCHES
{
  int32_t count;

  DECLARE_REFERENCE(YR_MATCH*, head);
  DECLARE_REFERENCE(YR_MATCH*, tail);

} YR_MATCHES;


typedef struct _YR_STRING
{
  int32_t g_flags;
  int32_t length;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(uint8_t*, string);
  DECLARE_REFERENCE(struct _YR_STRING*, chained_to);

  int32_t chain_gap_min;
  int32_t chain_gap_max;

  YR_MATCHES matches[MAX_THREADS];
  YR_MATCHES unconfirmed_matches[MAX_THREADS];

} YR_STRING;


typedef struct _YR_RULE
{
  int32_t g_flags;               // Global flags
  int32_t t_flags[MAX_THREADS];  // Thread-specific flags

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, tags);
  DECLARE_REFERENCE(YR_META*, metas);
  DECLARE_REFERENCE(YR_STRING*, strings);
  DECLARE_REFERENCE(YR_NAMESPACE*, ns);

} YR_RULE;


typedef struct _YR_EXTERNAL_VARIABLE
{
  int32_t type;
  int64_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} YR_EXTERNAL_VARIABLE;


typedef struct _YR_AC_MATCH
{
  uint16_t backtrack;

  DECLARE_REFERENCE(YR_STRING*, string);
  DECLARE_REFERENCE(uint8_t*, forward_code);
  DECLARE_REFERENCE(uint8_t*, backward_code);
  DECLARE_REFERENCE(struct _YR_AC_MATCH*, next);

} YR_AC_MATCH;


typedef struct _YR_AC_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(struct _YR_AC_STATE*, failure);
  DECLARE_REFERENCE(YR_AC_MATCH*, matches);

} YR_AC_STATE;


typedef struct _YR_AC_STATE_TRANSITION
{
  uint8_t input;

  DECLARE_REFERENCE(YR_AC_STATE*, state);
  DECLARE_REFERENCE(struct _YR_AC_STATE_TRANSITION*, next);

} YR_AC_STATE_TRANSITION;


typedef struct _YR_AC_TABLE_BASED_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(YR_AC_STATE*, failure);
  DECLARE_REFERENCE(YR_AC_MATCH*, matches);
  DECLARE_REFERENCE(YR_AC_STATE*, state) transitions[256];

} YR_AC_TABLE_BASED_STATE;


typedef struct _YR_AC_LIST_BASED_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(YR_AC_STATE*, failure);
  DECLARE_REFERENCE(YR_AC_MATCH*, matches);
  DECLARE_REFERENCE(YR_AC_STATE_TRANSITION*, transitions);

} YR_AC_LIST_BASED_STATE;


typedef struct _YR_AC_AUTOMATON
{
  DECLARE_REFERENCE(YR_AC_STATE*, root);

} YR_AC_AUTOMATON;


typedef struct _YARA_RULES_FILE_HEADER
{
  uint32_t version;

  DECLARE_REFERENCE(YR_RULE*, rules_list_head);
  DECLARE_REFERENCE(YR_EXTERNAL_VARIABLE*, externals_list_head);
  DECLARE_REFERENCE(uint8_t*, code_start);
  DECLARE_REFERENCE(YR_AC_AUTOMATON*, automaton);

} YARA_RULES_FILE_HEADER;

#pragma pack(pop)


typedef struct _YR_HASH_TABLE_ENTRY
{
  char* key;
  char* ns;
  void* value;

  struct _YR_HASH_TABLE_ENTRY* next;

} YR_HASH_TABLE_ENTRY;


typedef struct _YR_HASH_TABLE
{
  int size;

  YR_HASH_TABLE_ENTRY* buckets[0];

} YR_HASH_TABLE;


typedef struct _YR_ATOM_LIST_ITEM
{
  uint8_t atom_length;
  uint8_t atom[MAX_ATOM_LENGTH];

  uint16_t backtrack;

  void* forward_code;
  void* backward_code;

  struct _YR_ATOM_LIST_ITEM* next;

} YR_ATOM_LIST_ITEM;


#define YARA_ERROR_LEVEL_ERROR   0
#define YARA_ERROR_LEVEL_WARNING 1


typedef void (*YR_REPORT_FUNC)(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message);


typedef int (*YR_CALLBACK_FUNC)(
    int message,
    YR_RULE* rule,
    void* data);


typedef struct _YR_COMPILER
{
  int                 last_result;
  YR_REPORT_FUNC      error_report_function;
  int                 errors;
  int                 error_line;
  int                 last_error;
  int                 last_error_line;

  jmp_buf             error_recovery;

  YR_ARENA*           sz_arena;
  YR_ARENA*           rules_arena;
  YR_ARENA*           strings_arena;
  YR_ARENA*           code_arena;
  YR_ARENA*           re_code_arena;
  YR_ARENA*           automaton_arena;
  YR_ARENA*           compiled_rules_arena;
  YR_ARENA*           externals_arena;
  YR_ARENA*           namespaces_arena;
  YR_ARENA*           metas_arena;

  YR_AC_AUTOMATON*    automaton;
  YR_HASH_TABLE*      rules_table;
  YR_NAMESPACE*       current_namespace;
  YR_STRING*          current_rule_strings;

  int                 current_rule_flags;
  int                 externals_count;
  int                 namespaces_count;

  int8_t*             loop_address[MAX_LOOP_NESTING];
  char*               loop_identifier[MAX_LOOP_NESTING];
  int                 loop_depth;

  int                 allow_includes;

  char*               file_name_stack[MAX_INCLUDE_DEPTH];
  int                 file_name_stack_ptr;

  FILE*               file_stack[MAX_INCLUDE_DEPTH];
  int                 file_stack_ptr;

  char                last_error_extra_info[256];

  char                lex_buf[LEX_BUF_SIZE];
  char*               lex_buf_ptr;
  unsigned short      lex_buf_len;

  char                include_base_dir[MAX_PATH];

} YR_COMPILER;


typedef struct _YR_MEMORY_BLOCK
{
  uint8_t* data;
  size_t size;
  size_t base;

  struct _YR_MEMORY_BLOCK* next;

} YR_MEMORY_BLOCK;


typedef struct _YR_RULES {

  tidx_mask_t tidx_mask;
  uint8_t* code_start;

  mutex_t mutex;

  YR_ARENA* arena;
  YR_RULE* rules_list_head;
  YR_EXTERNAL_VARIABLE* externals_list_head;
  YR_AC_AUTOMATON* automaton;

} YR_RULES;


extern char lowercase[256];
extern char altercase[256];

void yr_initialize(void);


void yr_finalize(void);


void yr_finalize_thread(void);


int yr_get_tidx(void);


void yr_set_tidx(int);


int yr_compiler_create(
    YR_COMPILER** compiler);


void yr_compiler_destroy(
    YR_COMPILER* compiler);


int yr_compiler_add_file(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_);


int yr_compiler_add_string(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_);


int yr_compiler_push_file_name(
    YR_COMPILER* compiler,
    const char* file_name);


void yr_compiler_pop_file_name(
    YR_COMPILER* compiler);


char* yr_compiler_get_error_message(
    YR_COMPILER* compiler,
    char* buffer,
    int buffer_size);


char* yr_compiler_get_current_file_name(
    YR_COMPILER* context);


int yr_compiler_define_integer_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int64_t value);


int yr_compiler_define_boolean_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    int value);


int yr_compiler_define_string_variable(
    YR_COMPILER* compiler,
    const char* identifier,
    const char* value);


int yr_compiler_get_rules(
    YR_COMPILER* compiler,
    YR_RULES** rules);


int yr_rules_scan_mem(
    YR_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_scan_file(
    YR_RULES* rules,
    const char* filename,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_scan_proc(
    YR_RULES* rules,
    int pid,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_save(
    YR_RULES* rules,
    const char* filename);


int yr_rules_load(
    const char* filename,
    YR_RULES** rules);


int yr_rules_destroy(
    YR_RULES* rules);


int yr_rules_define_integer_variable(
    YR_RULES* rules,
    const char* identifier,
    int64_t value);


int yr_rules_define_boolean_variable(
    YR_RULES* rules,
    const char* identifier,
    int value);


int yr_rules_define_string_variable(
    YR_RULES* rules,
    const char* identifier,
    const char* value);

#endif

