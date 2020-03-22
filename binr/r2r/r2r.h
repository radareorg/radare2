/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#ifndef RADARE2_R2R_H
#define RADARE2_R2R_H

#include <r_util.h>

typedef struct r2r_cmd_test_string_record {
	char *value;
	ut64 line_begin; // inclusive
	ut64 line_end; // exclusive
} R2RCmdTestStringRecord;

typedef struct r2r_cmd_test_bool_record {
	bool value;
	ut64 line; // bools are always oneliners (e.g. BROKEN=1)
	bool set;
} R2RCmdTestBoolRecord;

typedef struct r2r_cmd_test_t {
	R2RCmdTestStringRecord name;
	R2RCmdTestStringRecord file;
	R2RCmdTestStringRecord args;
	R2RCmdTestStringRecord source;
	R2RCmdTestStringRecord cmds;
	R2RCmdTestStringRecord expect;
	R2RCmdTestStringRecord expect_err;
	R2RCmdTestBoolRecord broken;
} R2RCmdTest;

#define R2R_CMD_TEST_FOREACH_RECORD_NOP(name, field)
#define R2R_CMD_TEST_FOREACH_RECORD(macro_str, macro_bool) \
	macro_str ("NAME", name) \
	macro_str ("FILE", file) \
	macro_str ("ARGS", args) \
	macro_str ("SOURCE", source) \
	macro_str ("CMDS", cmds) \
	macro_str ("EXPECT", expect) \
	macro_str ("EXPECT_ERR", expect_err) \
	macro_bool ("BROKEN", broken)

typedef enum r2r_asm_test_mode_t {
	R2R_ASM_TEST_MODE_ASSEMBLE = 1,
	R2R_ASM_TEST_MODE_DISASSEMBLE = (1 << 1),
	R2R_ASM_TEST_MODE_BIG_ENDIAN = (1 << 2),
	R2R_ASM_TEST_MODE_BROKEN = (1 << 3)
} R2RAsmTestMode;

typedef struct r2r_asm_test_t {
	ut64 line;
	const char *arch;
	const char *cpu;
	int bits;
	int mode;
	ut64 offset;
	char *disasm;
	ut8 *bytes;
	size_t bytes_size;
} R2RAsmTest;

typedef struct r2r_json_test_t {
	ut64 line;
	char *cmd;
	bool broken;
} R2RJsonTest;

typedef enum r2r_test_type_t {
	R2R_TEST_TYPE_CMD,
	R2R_TEST_TYPE_ASM,
	R2R_TEST_TYPE_JSON
} R2RTestType;

typedef struct r2r_test_t {
	const char *path;
	R2RTestType type;
	union {
		R2RCmdTest *cmd_test;
		R2RAsmTest *asm_test;
		R2RJsonTest *json_test;
	};
} R2RTest;

typedef struct r2r_test_database_t {
	RPVector tests;
	RStrConstPool strpool;
} R2RTestDatabase;

typedef struct r2r_run_config_t {
	const char *r2_cmd;
} R2RRunConfig;

typedef struct r2r_test_output_t {
	char *out; // stdout
	char *err; // stderr
	int ret; // exit code of the process
} R2RTestOutput;

typedef enum r2r_test_result_t {
	R2R_TEST_RESULT_OK,
	R2R_TEST_RESULT_FAILED,
	R2R_TEST_RESULT_BROKEN,
	R2R_TEST_RESULT_FIXED
} R2RTestResult;

R_API R2RCmdTest *r2r_cmd_test_new();
R_API void r2r_cmd_test_free(R2RCmdTest *test);
R_API RPVector *r2r_load_cmd_test_file(const char *file);

R_API R2RAsmTest *r2r_asm_test_new();
R_API void r2r_asm_test_free(R2RAsmTest *test);
R_API RPVector *r2r_load_asm_test_file(RStrConstPool *strpool, const char *file);

R_API R2RJsonTest *r2r_json_test_new();
R_API void r2r_json_test_free(R2RJsonTest *test);
R_API RPVector *r2r_load_json_test_file(const char *file);

R_API R2RTestDatabase *r2r_test_database_new();
R_API void r2r_test_database_free(R2RTestDatabase *db);
R_API bool r2r_test_database_load(R2RTestDatabase *db, const char *path);

R_API bool r2r_subprocess_init();
R_API void r2r_subprocess_fini();

R_API R2RTestOutput *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test);
R_API void r2r_test_output_free(R2RTestOutput *out);
R_API R2RTestResult r2r_test_output_check(R2RTestOutput *out, R2RCmdTest *test);

#endif //RADARE2_R2R_H
