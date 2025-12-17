/* radare - LGPL - Copyright 2020-2025 - pancake, thestr4ng3r */

#ifndef RADARE2_R2R_H
#define RADARE2_R2R_H

#include <r_util.h>
#include <r_vec.h>

typedef struct r2r_cmd_test_t R2RCmdTest;
typedef struct r2r_asm_test_t R2RAsmTest;
typedef struct r2r_test_to_skip_t R2RTestToSkip;
typedef struct r2r_json_test_t R2RJsonTest;
typedef struct r2r_fuzz_test_t R2RFuzzTest;
typedef struct r2r_test_t R2RTest;
typedef struct r2r_asm_test_output_t R2RAsmTestOutput;
typedef struct r2r_test_result_info_t R2RTestResultInfo;
typedef struct r2r_subprocess_t R2RSubprocess;
typedef struct r2r_state_t R2RState;

R_VEC_TYPE(RVecR2RCmdTestPtr, R2RCmdTest *);
R_VEC_TYPE(RVecR2RAsmTestPtr, R2RAsmTest *);
R_VEC_TYPE(RVecR2RJsonTestPtr, R2RJsonTest *);
R_VEC_TYPE(RVecR2RFuzzTestPtr, R2RFuzzTest *);
R_VEC_TYPE(RVecR2RTestPtr, R2RTest *);
R_VEC_TYPE(RVecR2RTestResultInfoPtr, R2RTestResultInfo *);
R_VEC_TYPE(RVecR2RSubprocessPtr, R2RSubprocess *);
R_VEC_TYPE(RVecRThreadPtr, RThread *);
R_VEC_TYPE(RVecConstCharPtr, const char *);

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

typedef struct r2r_cmd_test_num_record {
	ut64 value;
	ut64 line; // nums are always oneliners (e.g. TIMEOUT=10)
	bool set;
} R2RCmdTestNumRecord;

typedef struct r2r_cmd_test_t {
	R2RCmdTestStringRecord name;
	R2RCmdTestStringRecord file;
	R2RCmdTestStringRecord args;
	R2RCmdTestStringRecord require;
	R2RCmdTestStringRecord source;
	R2RCmdTestStringRecord cmds;
	R2RCmdTestNumRecord repeat;
	R2RCmdTestStringRecord expect;
	R2RCmdTestStringRecord expect_err;
	R2RCmdTestStringRecord regexp_out;
	R2RCmdTestStringRecord regexp_err;
	R2RCmdTestStringRecord env;
	R2RCmdTestBoolRecord broken;
	R2RCmdTestBoolRecord oldabi;
	R2RCmdTestBoolRecord newabi;
	R2RCmdTestNumRecord timeout;
	ut64 run_line;
	bool load_plugins;
} R2RCmdTest;

#define R2R_CMD_TEST_FOREACH_RECORD_NOP(name, field)
#define R2R_CMD_TEST_FOREACH_RECORD(macro_str, macro_bool, macro_int) \
	macro_str ("NAME", name) \
	macro_str ("FILE", file) \
	macro_str ("ARGS", args) \
	macro_str ("REQUIRE", require) \
	macro_int ("REPEAT", repeat) \
	macro_int ("TIMEOUT", timeout) \
	macro_str ("SOURCE", source) \
	macro_str ("CMDS", cmds) \
	macro_str ("EXPECT", expect) \
	macro_str ("EXPECT_ERR", expect_err) \
	macro_str ("REGEXP_OUT", regexp_out) \
	macro_str ("REGEXP_ERR", regexp_err) \
	macro_str ("ENV", env) \
	macro_bool ("BROKEN", broken) \
	macro_bool ("OLDABI", oldabi) \
	macro_bool ("NEWABI", newabi) \

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

typedef struct r2r_test_to_skip_t {
	const char *dir;
	const char *name;
} R2RTestToSkip;

typedef struct r2r_json_test_t {
	ut64 line;
	char *cmd;
	bool broken;
	bool load_plugins;
} R2RJsonTest;

typedef struct r2r_fuzz_test_t {
	char *file;
} R2RFuzzTest;

typedef enum r2r_test_type_t {
	R2R_TEST_TYPE_CMD,
	R2R_TEST_TYPE_ASM,
	R2R_TEST_TYPE_JSON,
	R2R_TEST_TYPE_FUZZ
} R2RTestType;

typedef struct r2r_test_from_t {
	R2RTestType type;
	bool load_plugins;
	bool archos;
} R2RTestFrom;

typedef struct r2r_test_t {
	const char *path;
	R2RTestType type;
	union {
		R2RCmdTest *cmd_test;
		R2RAsmTest *asm_test;
		R2RJsonTest *json_test;
		R2RFuzzTest *fuzz_test;
	};
} R2RTest;

typedef struct r2r_test_database_t {
	RVecR2RTestPtr tests;
	RStrConstPool strpool;
} R2RTestDatabase;

typedef struct r2r_run_config_t {
	char *r2_cmd;
	char *rasm2_cmd;
	const char *json_test_file;
	ut64 timeout_ms;
	int shallow;
	bool skip_cmd;
	bool skip_fuzz;
	bool skip_asm;
	bool skip_json;
} R2RRunConfig;

typedef struct r2r_process_output_t {
	char *out; // stdout
	char *err; // stderr
	int ret; // exit code of the process
	bool timeout;
} R2RProcessOutput;

typedef struct r2r_asm_test_output_t {
	char *disasm;
	ut8 *bytes;
	size_t bytes_size;
	bool as_timeout;
	bool disas_timeout;
} R2RAsmTestOutput;

typedef enum r2r_test_result_t {
	R2R_TEST_RESULT_OK = 0,
	R2R_TEST_RESULT_FAILED = 1,
	R2R_TEST_RESULT_BROKEN = 2,
	R2R_TEST_RESULT_FIXED = 3
} R2RTestResult;

typedef struct r2r_test_result_info_t {
	R2RTest *test;
	R2RTestResult result;
	bool timeout;
	bool run_failed; // something went seriously wrong (e.g. r2 not found)
	bool run_skipped; // run was skipped due to e.g. R2R_SHALLOW
	ut64 time_elapsed;
	union {
		R2RProcessOutput *proc_out; // for test->type == R2R_TEST_TYPE_CMD, R2R_TEST_TYPE_JSON or R2R_TEST_TYPE_FUZZ
		R2RAsmTestOutput *asm_out;  // for test->type == R2R_TEST_TYPE_ASM
	};
} R2RTestResultInfo;

static inline const char *shortpath (const char *testpath) {
	char *shorter = strstr (testpath, "/db/");
	if (shorter) {
		return shorter + 1;
	}
	shorter = strstr (testpath, "/bins/fuzzed");
	if (shorter) {
		return shorter + 6;
	}
	return testpath;
}


R_API R2RCmdTest *r2r_cmd_test_new(void);
R_API void r2r_cmd_test_free(R2RCmdTest *test);
R_API RVecR2RCmdTestPtr *r2r_load_cmd_test_file(const char *file);

R_API R2RAsmTest *r2r_asm_test_new(void);
R_API void r2r_asm_test_free(R2RAsmTest *test);
R_API RVecR2RAsmTestPtr *r2r_load_asm_test_file(RStrConstPool *strpool, const char *file);

R_API R2RJsonTest *r2r_json_test_new(void);
R_API void r2r_json_test_free(R2RJsonTest *test);
R_API RVecR2RJsonTestPtr *r2r_load_json_test_file(const char *file);

R_API R2RTestDatabase *r2r_test_database_new(void);
R_API void r2r_test_database_free(R2RTestDatabase *db);
R_API bool r2r_test_database_load(R2RTestDatabase *db, const char *path, bool skip_json_tests);
R_API bool r2r_test_database_load_fuzz(R2RTestDatabase *db, const char *path);

typedef struct r2r_subprocess_t R2RSubprocess;

R_API bool r2r_subprocess_init(void);
R_API void r2r_subprocess_fini(void);
R_API R2RSubprocess *r2r_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size);
R_API bool r2r_subprocess_wait(R2RSubprocess *proc, ut64 timeout_ms);
R_API void r2r_subprocess_free(R2RSubprocess *proc);

typedef R2RProcessOutput *(*R2RCmdRunner)(const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user);

R_API void r2r_process_output_free(R2RProcessOutput *out);
R_API R2RProcessOutput *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test, R2RCmdRunner runner, void *user);
R_API bool r2r_check_cmd_test(R2RProcessOutput *out, R2RCmdTest *test);
R_API bool r2r_check_jq_available(void);
R_API R2RProcessOutput *r2r_run_json_test(R2RRunConfig *config, R2RJsonTest *test, R2RCmdRunner runner, void *user);
R_API bool r2r_check_json_test(R2RProcessOutput *out, R2RJsonTest *test);
R_API R2RAsmTestOutput *r2r_run_asm_test(R2RRunConfig *config, R2RAsmTest *test);
R_API bool r2r_check_asm_test(R2RAsmTestOutput *out, R2RAsmTest *test);
R_API void r2r_asm_test_output_free(R2RAsmTestOutput *out);
R_API R2RProcessOutput *r2r_run_fuzz_test(R2RRunConfig *config, const char *file, R2RCmdRunner runner, void *user);
R_API bool r2r_check_fuzz_test(R2RProcessOutput *out);

R_API void r2r_test_free(R2RTest *test);
R_API char *r2r_test_name(R2RTest *test);
R_API bool r2r_test_broken(R2RTest *test);
R_API R2RTestResultInfo *r2r_run_test(R2RRunConfig *config, R2RTest *test);
R_API void r2r_test_result_info_free(R2RTestResultInfo *result);
R_IPI const char *getarchos(void);

#endif //RADARE2_R2R_H
