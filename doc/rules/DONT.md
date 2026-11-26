# DONTS — what radare2 reviewers reject

These rules come from about 5,100 human inline review comments on
radareorg/radare2 pull requests (Dec 2020 to Nov 2026). Rules inside each
section are ordered roughly by how often reviewers flagged them, and the
`#NNNNN` numbers are PRs where the comment appears. For the positive rules see
[DOES.md](DOES.md).

## Style and formatting

- **Don't write calls without a space before `(`**: `foo(x)`, `sizeof(x)`,
  `R_LOG_ERROR("..")`, `if(`. This is the top review comment (~260 hits).
  (#18723, #20460, #24587)
- **Don't put a space before `(` in function definitions, prototypes or
  `#define` names**, and don't wrap a signature over several lines.
  `static void handle_xxhash (const ut8 *b, int len) {` → `handle_xxhash(const ut8 *b, int len)`
  (#18729, #22984, #18794)
- **Don't indent with spaces or a mix of tabs and spaces.** This applies to
  Makefiles too. Don't indent preprocessor directives or top-level
  definitions. (#18659, #23429, #20443)
- **Don't use `else` after `return`, `continue`, `break` or `goto`.**
  `if (x) { return a; } else { return b; }` → `if (x) { return a; } return b;`
  (~30 hits, #19539, #21313, #23430)
- **Don't write brace-less one-line ifs or loops**, and don't put the opening
  brace on its own line. (#18103, #19539, #24479)
- **Don't leave debug prints, commented-out code, `#if DEBUG` blocks, dead
  branches, unused variables or stray blank lines** in a PR (~60 hits).
  `eprintf ("lewhite%c", 10);` → delete (#19146, #20243, #25135)
- **Don't compare explicitly with `NULL`, `true`, `false`, `0` or `'\0'`.**
  `if (name == NULL)`, `if (found == true)`, `strcmp (a, b) == 0` →
  `if (!name)`, `if (found)`, `!strcmp (a, b)` (#19432, #18420, #20454)
- **Don't declare loop variables inside `for ()`**; old toolchains reject it.
  (#19157, #21344, #24727)
- **Don't split declaration and first assignment** across statements without
  a reason. (#18499, #25552)
- **Don't copy-paste blocks that differ in one value.** Merge them with a
  ternary, a table or a helper. (#19487, #25789, #26175)
- **Don't use magic numbers.** Use `sizeof`, `UT32_MAX`, named defines or
  runtime values such as the console width. (#24727, #25897, #26894)
- **Don't put assignments inside conditions**, and don't put two statements
  on one line. (#27204, #23359)
- **Don't add unnecessary casts**, especially function-pointer casts that hide
  signature mismatches, or casts that strip `const`. Copy the data instead.
  (#21939, #21799, #18483)
- **Don't use rizin macros or idioms** (`RZ_STR_DEF`, `RZ_*`).
  (#22562)
- **Don't write explicit NUL terminators in string literals** (`"adch\0"`).
  (#19022)
- **Don't run `clang-format-radare2` over existing files unless asked.**
  Reviewers only suggest it for new files.

## Comments and docs

- **Don't write multi-line comments, rationale walls, comments that restate
  the code or commit message, or references to line numbers.** Keep at most one
  short line and rename things instead (~35 hits).
  `// P is already correctly computed via p2v (see lines 458-462)` → delete
  (#27471, #26436, #26676)
- **Don't add Doxygen-style API docs.** r2 doesn't use them.
  (#19543, #22510)
- **Don't put license walls in `.h` or `.mk` files**, or ship extra LICENSE
  files. One header line in the `.c` file is enough. Never relicense existing
  code. (#21344, #22125, #20450)

## Memory

- **Don't NULL-check `R_NEW`/`R_NEW0`, `r_list_new`/`newf`, `r_str_newf`,
  `r_strbuf_*`, `pj_new` or `r_buf_new` results** (~45 hits).
  `T *x = R_NEW0 (T); if (!x) { return NULL; }` → `T *x = R_NEW0 (T);`
  (#25612, #24284, #25552)
- **Don't guard `free` or NULL-accepting destructors with `if (p)`.**
  `if (pool != NULL) free (pool);` → `free (pool);` (~35 hits, #22227, #18545, #24215)
- **Don't NULL out a pointer that is about to go out of scope**, and don't use
  `R_FREE` or `r_free` where plain `free` is enough. (#18521, #25275, #19511)
- **Don't use `R_STR_DUP` or `r_str_new` where the value cannot be NULL.** Use
  `strdup`. (#23119, #24585)
- **Don't use fixed-size or oversized stack buffers** for formatted strings,
  don't use VLAs, and don't use `alloca`. Use `r_str_newf` or RStrBuf.
  (#18723, #25879, #19418)
- **Don't use `strcpy`, `strcat`, `sprintf`, or `strncpy` into fixed
  buffers.** Use `r_str_ncpy` when the destination size is fixed by a struct
  or format, and heap strings (`r_str_newf`, RStrBuf) otherwise.
  (#19022, #19889, #20612)
- **Don't call `realloc (p, 0)`, don't pass signed sizes to allocators, and
  don't assign the `realloc` result straight back to the pointer.**
  (#22694, #19157)
- **Don't use `sdb_fmt`.** It isn't thread safe. (#19418, #19412)
- **Don't use zero-size trailing array fields** in structs.
  (#18545)
- **Don't cast pointers to integers of a different width** (`(int *)&size_t_var`).
  (#26459)
- **Don't store raw pointers as sdb or ht keys.** Use stable ids or addresses
  with `set_u` or `HtUP`. (#18104, #26251)

## Error handling and logging

- **Don't NULL-check internal arguments or core fields that cannot be NULL**
  (`core->io`, `bf->bo`, a static handler's `core`). A crash there is better
  than hiding the bug (~25 hits). (#24899, #25653, #27496)
- **Don't use `R_RETURN_*` in static or internal functions, or for runtime
  failures** such as malloc results or malformed input. They are compiled out
  of release builds. (#18552, #25362, #26594)
- **Don't use `assert ()` or `abort ()` in library code.**
  (#22125, #23466)
- **Don't end `R_LOG_*` messages with `\n` or a period, or start them with
  "Warning:", "Error:" or leading spaces** (~45 hits).
  `R_LOG_WARN ("Warning: bad header.\n")` → `R_LOG_WARN ("bad header")`
  (#20367, #21344, #24284)
- **Don't commit `eprintf`.** It is only for local debugging. Don't use
  `printf` for diagnostics either; use `R_LOG_*`. Don't turn
  `eprintf ("Usage: ...")` into `R_LOG_ERROR`; show help with
  `r_core_cmd_help_match`. (#21002, #20968, #22036)
- **Don't build one log line from several `R_LOG` calls.** Each call is its
  own line and hook event. (#20292)
- **Don't log on every small allocation failure** (no `r_sys_perror` after
  `r_list_newf`). (#20524, #21344)
- **Don't use ERROR for conditions where parsing continues.** Use WARN or
  DEBUG. (#20513, #20214)
- **Don't print to `r_cons` from library code for errors.**
  (#18895, #25789)

## API usage

- **Don't use `strncmp` with hand-counted lengths for prefix checks.** Use
  `r_str_startswith`. `memcmp` against a short input reads out of bounds
  (~30 hits). (#21632, #20333, #24284)
- **Don't use `strtok` or `strtok_r`.** They are non-portable and mutate their
  input. (#19022, #19358, #25377)
- **Don't use `sscanf` scansets, the GNU-only `%*s`, or `PFMT64x` inside
  scanf formats.** Use `r_str_scanf`. (#22562)
- **Don't use `strndup`, `strcasecmp`, `bzero`, `mkstemp`, `getenv ("EDITOR")`
  or `uint32_t`/`unsigned char`/`%llx`.** See the replacement table in
  DOES.md. (#18760, #25154, #18620)
- **Don't ignore the return value of `r_str_replace`**; it may reallocate.
  (#19633, #20401)
- **Don't write one-line forwarding wrappers, getters or setters, or custom
  list-free wrappers.** Call the real API. (#25654, #25270, #26890)
- **Don't add new `R_API` functions or public headers for plugin-only
  logic.** Use `static` or `R_IPI`, or call the plugin command. (#25275, #26320, #24977)
- **Don't access another module's struct internals.** Use its API, for
  example `r_strbuf_drain` or `r_list_length`. (#19022, #18359)
- **Don't call plugin function pointers directly** when a public wrapper
  exists. (#20176)
- **Don't run r2 commands from C to change config.** Use `r_config_set`.
  (#22227)
- **Don't use `r_num_get` for user-facing arguments** (use `r_num_math`),
  don't use `r_num_math` or `r_num_math_err` to parse plain data numbers, and
  don't use `r_num_math` when invalid input must be reported; it ignores parse
  errors, while `r_num_math_err` returns them. (#19889, #19593)
- **Don't hand-roll JSON with printf and comma state.** Use PJ.
  (#18578, #18270)
- **Don't use `strstr` for exact token matching**; it gives false positives.
  (#19165)

## Performance

- **Don't do redundant work**: computing `strlen` twice, calling `strlen` in a
  loop condition, checking a pointer twice, setting a field the callee
  already sets, or `strdup` followed by `free`. (#26393, #18600, #19577)
- **Don't call `strcmp` or `strcasecmp` repeatedly or do linear scans in hot
  loops.** Compare integers. (#26490, #18371)
- **Don't re-derive per-file invariants per item**, and don't reload plugins
  or recreate RBin/RIO per call. (#26435, #25379)
- **Don't cache data that already lives in sdb or another database.** Build it
  on demand to avoid invalidation bugs. (#25552, #25612)
- **Don't put endian ternaries inside loops.** Use `r_read_ble32 (p, be)`.
  (#26070, #25484)

## Security

- **Don't embed names from binaries in r2 commands without a `'` prefix or
  `r_name_filter`**, because that allows command injection. (#19353, #25731, #20239)
- **Don't pass user strings to `r_sys_cmdf`.** (#21974, #21006)
- **Don't trust header counts and sizes.** Never multiply them, or loop over
  them, without overflow checks against the file size. (#21344, #24585, #26717)
- **Don't write `off + size > len` bounds checks**; they can overflow.
  (#25286)
- **Don't return `a - b` from comparators** on unsigned or 64-bit values.
  (#25768)
- **Don't read `input[N]` or dereference a `strstr` result** without a length
  or NULL check. (#18253, #18196)

## Architecture

- **Don't use globals or mutable function-local statics.** They break threads
  and plugin reloads ("globals must die"). (#19511, #25789, #24587)
- **Don't over-engineer.** Avoid index tables, clone machinery, extra flags,
  float formatters and features nobody asked for. (#25653, #25320, #26116)
- **Don't break the ABI in patch releases.** Don't change `R_API` signatures or
  public struct layouts without an `R2_5xx` marker.
  (#20654, #23611, #21632)
- **Don't make libraries depend upward** (util→core/cons, cons→core,
  fs→io directly), and don't use `r_cons_singleton ()` in new code.
  (#18915, #20333, #26527)
- **Don't print from library code.** Return a string or PJ.
  (#25789, #25970)
- **Don't add unrelated fields to core structs** (RBuffer, RIO, RAnalOp) to
  smuggle state. (#20548, #20542)
- **Don't `chdir` or change the core seek inside helpers**; it breaks threads
  and async operations. (#18552, #25925)
- **Don't keep two compile-time variants of the same logic.**
  (#23307)
- **Don't let bin plugins modify the underlying data or user config.**
  (#21889, #24927)
- **Don't silently change ESIL semantics** that downstream tools rely on.
  (#26543, #20662)
- **Don't remove `R_TH_LOCAL` or `R_CRITICAL_*` pairs** while refactoring.
  (#20447, #20813)

## Commands and user experience

- **Don't add commands without `?` help.** Don't let a `j` subcommand emit
  non-JSON. (#20886, #25653)
- **Don't print tabs in r2 output**; they break visual mode, panels and
  JSON. Align with spaces. (#19224, #27471)
- **Don't emit UTF-8 box drawing or ANSI escapes** unless `scr.utf8` or
  `scr.color` allows it. (#23478, #20478)
- **Don't use emojis in tool output.** Use `[OK]` and `[XX]` like r2r.
  (#24741)

## Tests

- **Don't change existing expected output to make a patch pass.** A changed
  EXPECT is usually a regression. Fix the code. (#19893, #21171, #22268)
- **Don't shell out in r2r tests** (`!python`, `!sh -c`, `!rm`, `mktemp`,
  `| grep`) or create temp files. Run `rax2` and `rahash2` inside r2 without
  `!`. (#25830, #26474, #27131)
- **Don't write tests that only cover the happy path or help text.**
  (#26115, #18064)
- **Don't pin `ARGS` that already match the default**, or add unneeded
  flags. (#27223, #19042)
- **Don't let parallel tests share scratch paths.** (#26103, #26372)

## Commits and PRs

- **Don't mix unrelated changes in one PR** (refactors, reindents, CI, r2r,
  URL sweeps). (#24951, #25991, #26440)
- **Don't blanket-replace `http://` with `https://`** in protocol code or test
  data. (#20944, #22312)
- **Don't commit merge-conflict markers, temporary or generated files**
  (`test/.null.bin`, `.orig`, `.rej`). (#20944, #18636)
- **Don't resolve review suggestions without applying them.**
  (#19022)
- **Don't patch vendored `shlr/sdb` only in r2.** Send the fix upstream.
  (#18574)

## Build and portability

- **Don't add includes already provided by `r_types.h`, `r_util.h` or
  `r_core.h`** (stdio, stdint, stdbool). They can cause `R_LOG_ORIGIN`
  redefinition errors. (#24602, #26145, #20626)
- **Don't use `double`, `round ()` or `-lm`** for version numbers. Use scaled
  integers. (#22517)
- **Don't use bashisms**, `export` in Makefile recipes, `exit -1`, or
  `${VAR}` for make variables. (#19705, #20018, #19764)
- **Don't use `__linux__` where `R2__UNIX__` applies**, and don't use
  `ssize_t`, `static_assert` or `INT_MAX` in portable code. (#18505, #18579, #20531)
- **Don't call `r_lib_dl_sym (NULL, ...)`.** Pass the handle from
  `r_lib_dl_open`. (#18505)
- **Don't put shell logic inline** in Makefiles or `configure.acr`. Use a
  script or acr commands. (#24741, #26033)
