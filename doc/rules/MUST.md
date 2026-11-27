# DOES — patterns radare2 reviewers ask for

These rules come from about 5,100 human inline review comments on
radareorg/radare2 pull requests (Dec 2020 to Nov 2026). Rules inside each
section are ordered roughly by how often reviewers asked for them, and the
`#NNNNN` numbers are PRs where the comment appears. For the inverse rules see
[DONTS.md](DONTS.md). For the baseline rules see `AGENTS.md`, `DEVELOPERS.md`
and `doc/indent-example.c`.

## Style and formatting

- **Put a space before `(` at every call site**: functions, macros,
  `sizeof`, foreach macros, `R_MIN`, `R_LOG_*`, and control keywords. This is
  the most frequent review comment by far (~260 hits).
  `free(key); sizeof(buf); if(!op){` → `free (key); sizeof (buf); if (!op) {`
  (#18723, #20460, #22452, #24587)
- **Keep function definitions and prototypes on one line with no space before
  `(`** so they stay greppable. Use `(void)` for empty parameter lists.
  `R_API RIOBank *r_io_bank_new() {` → `R_API RIOBank *r_io_bank_new(void) {`
  (#18429, #20699, #22984)
- **Indent with tabs only.** Use one tab per level and two tabs for
  continuation lines. Spaces are only for alignment inside a line. Leave no
  trailing whitespace and no tab-only blank lines. (#18659, #24958, #23429)
- **Always use braces** on if/else/for/while bodies, even for a single
  `return` or `break`. Open them on the same line and write `} else {` on one
  line. (#18307, #22227, #24479)
- **Put spaces around binary operators**, `=`, `<<`, after commas and inside
  subscripts. `malloc (len+1)` → `malloc (len + 1)`; `n<<shift` → `n << shift`
  (#18659, #20626, #22227)
- **Align `case` labels with `switch`** and put `default` last. Wrap
  declarations inside a `case` in a block, or declare them before the switch.
  (#19515, #24494, #24854)
- **Declare and assign in the same statement, close to first use.**
  `char *p; ... p = r_str_newf (...);` → `char *p = r_str_newf (...);`
  (#18499, #25552, #19957)
- **Declare loop counters before the `for`**, and hoist the loop bound into a
  variable when it is computed. `for (int i = 0; ...)` → `int i;\nfor (i = 0; ...)`
  (#21557, #24113, #25427)
- **Mark locals and pointers `const` when they don't change**, especially
  borrowed strings, config values and cached flags (~60 hits). Keep heap
  strings that must be freed non-const.
  `bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config);` → `const bool be = ...;`
  (#20126, #22439, #25377)
- **Use implicit truthiness.** `if (!p)`, `if (found)`, `if (*s)`,
  `!strcmp (a, b)`. Don't compare with `NULL`, `false`, `0` or `'\0'`.
  (#19432, #18420, #20454)
- **Prefer a ternary or one call over duplicated branches.**
  `if (rel) x = f (a); else x = f (b);` → `x = f (rel? a: b);`
  (#18763, #20301, #23119)
- **Write positive conditions and exit early** with `continue` or `return` to
  avoid nesting. Hoist a check that every branch repeats.
  (#24284, #25552, #19487)
- **Use `switch`** instead of long if/else-if chains or linear table dispatch.
  Group repeated conditions under one `if`. (#25320, #21967, #26234)
- **Make small private helpers `static inline`**, and file-scope lookup tables
  `static const`. (#25552, #20490, #23281)
- **Use compound assignment** (`s += n`), postfix `i++`, and decimal for
  small constants (`addr += 4`, not `0x4`). (#20699, #18794, #22362)
- **Initialize with `= {0}`** rather than `{}` or a later `memset`.
  (#20299, #18184, #22517)
- **Write one statement per line**, and keep side effects out of expressions.
  `switch (*(src++))` → `src++; switch (*src)` (#20626, #23359)
- **Parenthesize macro arguments and arithmetic or bitwise precedence**.
  `#define R_DIRTY(x) x->is_dirty = true` → `(x)->is_dirty = true`
  (#19577, #26166)
- **Delete dead code.** If it must stay disabled, use `#if 0`, not block
  comments. Keep `#` at column 0.
  (#18392, #20441, #23429)
- **Use `R_UNUSED`** on unused parameters instead of `(void)param;`.
  (#21344, #21221)
- **Sort case lists and plugin lists alphabetically.** (#18784, #19543)
- **End files with a newline**, and separate functions with a single blank
  line. (#19370, #18499)

## Naming

- **Use short, descriptive names** so comments aren't needed. Rename rather
  than explain, and drop prefixes that repeat the file or dir name
  (~40 hits). `fcn_context_is_default_arg_name` → `is_default_name`;
  `r_debug_init_debug_plugins` → `r_debug_init_plugins` (#25612, #22011, #19539)
- **Follow r2 naming:** public functions are `R_API r_<module>_<object>_<action>`
  with the action last and `new`/`free` for constructors and destructors.
  Typedefs are CamelCase with an R prefix, and struct tags are `r_foo_t`.
  `r_debug_session_cp_list_replays` → `..._cp_replay_list`;
  `r_agraph_create_from_graph` → `r_agraph_new_from_graph` (#18499, #20921, #24884)
- **Don't give static or internal helpers the `r_` prefix.**
  (#19477, #26436, #27154)
- **Use lowercase register names** in register profiles, and lowercase
  command suffix letters unless none are left. (#20223, #26621)
- **Don't name variables after libc symbols** (`log`, `syscall`).
  (#18144, #20176)

## Memory and ownership

- **Check allocations whose size comes from input** (file headers, counts,
  user-given lengths), and always use a temporary for `realloc`: `p = realloc (p, n)` → `tmp = realloc (p, n); if (!tmp) {...} p = tmp;`
  Reject size 0 and signed sizes. (#19157, #21889, #22694)
- **Free every owned allocation on every error path.** Check each early return
  for leaks of buffers that were already allocated. (#19374, #18723, #19889)
- **Use `R_NEW0 (T)`** instead of `calloc (1, sizeof (T))` or `R_NEW`
  followed by `memset`. (#21396, #18371)
- **Use `R_FREE (p)` only when the pointer is used again afterwards.** Use
  plain `free` before a return or when the owner is freed next.
  (#18521, #21344, #25275)
- **Size bounded copies with `sizeof (dst)`**, never a magic length or the
  source size. If a function takes a `char *` buffer, also pass its size,
  because `sizeof` on a pointer gives 4 or 8. (#22526, #19022, #24587)
- **Follow ownership contracts.** Free RBuffer with `r_unref` or
  `r_buf_free`, use `sdb_const_get` when you don't take ownership, drain
  RStrBuf and PJ with `*_drain`, use `r_json_parsedup`, and annotate
  transferred arguments with `R_OWNED`. (#25789, #18794, #23090)
- **Use `RFreeze` for stable iteration when callbacks can change a
  collection.** Use helpers such as `r_anal_function_freeze_blocks` and
  `r_anal_freeze_functions`, iterate with `r_freeze_foreach`, and release
  each view with `r_freeze_release`. Owners using `r_freeze_vec` must call
  `r_freeze_detach` before mutating or freeing the backing vector. Keep the
  view on one thread and use ref-counted elements when the view must keep
  them alive. See [r_freeze.h](../../libr/include/r_util/r_freeze.h).
- **Zero-initialize** stack buffers and scalars that may be read before they
  are written. (#22517, #20835)
- **When unsure between a leak and a double free, reproduce with ASAN**
  (`sys/sanitize.sh`). A leak is better than a double free. (#22127, #22629)

## Error handling and logging

- **Use `R_RETURN_VAL_IF_FAIL` / `R_RETURN_IF_FAIL` for preconditions of
  public `R_API` functions.** Combine them into one statement and put them
  before any allocation. `if (!io || !io->banks) return NULL;` →
  `R_RETURN_VAL_IF_FAIL (io && io->banks, NULL);` (#18016, #20631, #24587)
- **Handle runtime and input errors with a plain `if`.** This covers
  allocation results, short reads and malformed files. (#18552, #20628, #26594)
- **Report diagnostics with `R_LOG_*`**, not `eprintf` or `printf`.
  `eprintf` is only for local debugging and must not be committed. Usage text
  is not a diagnostic; show it with `r_core_cmd_help_match`.
  `eprintf ("map failed!\n")` → `R_LOG_ERROR ("map failed!")`
  (#20689, #22036, #24587)
- **Pick the log level by meaning:** ERROR when processing stops, WARN when
  it continues, INFO for normal status the user wants to see, TODO for
  unimplemented features, and DEBUG for verbose details. Code inside an
  `if (anal->verbose)` block becomes `R_LOG_DEBUG`. (#20513, #20968, #27547)
- **Define `R_LOG_ORIGIN` before any include** in plugins and formats so
  their logs can be filtered. (#21344, #24113)
- **Check reads against the expected size**, not just `< 0`.
  `if (r_buf_read_at (b, p, buf, n) != n)` (#22562, #21344, #26436)
- **For malformed binaries, warn and keep loading** what you can instead of
  failing hard. (#24268)
- **Return NULL or an error value when data is missing.** Don't invent
  defaults such as address 0, and never return a pointer to a stack
  temporary. (#22362, #22518)
- **Report failure to the caller** with `false`, `NULL` or an error value,
  and let the command handler set the exit code with `r_core_return_code`.
  CLI tools exit nonzero on failure.
  (#19881, #21959)

## Preferred r2 APIs

| Instead of | Use |
|---|---|
| `strncmp (s, "pfx", 3)`, `memcmp` prefix, manual suffix checks | `r_str_startswith`, `r_str_endswith`, `R_STR_STARTSWITH_ANY` |
| `!s \|\| !*s`, `s && *s`, `!R_STR_ISEMPTY` | `R_STR_ISEMPTY (s)`, `R_STR_ISNOTEMPTY (s)` |
| `strndup`, `malloc`+`strncpy`, `strcpy` | `r_str_ndup`, `r_str_ncpy` (always NUL-terminates), `strdup` |
| fixed `char buf[N]` + `snprintf`, `malloc(strlen+..)+sprintf` | `r_str_newf`, `r_strbuf_appendf`, `r_str_appendf` |
| `sscanf`, `%[^\n]` | `r_str_scanf` with `%.s` sizes and `%*` skips |
| `strtok`/`strtok_r` | `r_str_split_list`, `r_str_split_duplist`, `r_str_argv` |
| `strcasecmp`, `strrchr` | `r_str_casecmp`, `r_str_rchr` |
| char loop replacing chars | `r_str_replace_char`; **assign** the result of `r_str_replace` |
| manual `"%s/%s"` paths | `r_file_new (a, b, NULL)`, `R_SYS_DIR` |
| `getenv` + compare | `r_sys_getenv_asbool` |
| `mkstemp`, `$EDITOR` | `r_file_tmpfile`, `r_cons_editor` |
| byte shifting, struct casts on raw data | `r_read_le32`, `r_read_ble32 (p, be)`, `r_buf_read_be32`, `r_buf_fread_at` |
| manual range checks `c >= 'a' && ...` | `isalpha ((ut8)c)`, `isspace`, `IS_PRINTABLE` |
| manual clamp branches | `R_MIN`, `R_MAX` |
| `0xffffffff`, `(ut32)-1`, `INT_MAX` | `UT32_MAX`, `ST32_MAX`, `UT64_MAX` (also as "unset" sentinels instead of an extra bool) |
| `r_list_length (l) == 0`, `l->free = free` | `r_list_empty`, `r_list_newf (free)`, `r_list_get_at`, `r_list_first` |
| push+memcpy into vectors | `RVec` reserve plus `emplace_back`, `r_vector_end`; RVec sort API instead of `qsort` |
| `pj_new` in core, `strdup (pj_string)` | `r_core_pj_new (core)`, `pj_drain` |
| `r_cons_printf ("%s\n", s)` | `r_cons_println (s)` |
| `r_config_get_i` for booleans | `r_config_get_b` / `r_config_set_b` |
| `r_core_cmd0 (core, "e x=y")` | `r_config_set (core->config, "x", "y")` |
| `sdb_get` without taking ownership | `sdb_const_get` |
| numbers formatted into sdb keys | `sdb_num_*`, `sdb_nset`, `HtUU`, `set_u` |
| `a && a->b && a->b->c` chains | `R_UNWRAP3/4` |
| `uint32_t`, `unsigned char`, `%llx` | `ut32`, `ut8`, `"%"PFMT64x` with a `(ut64)` cast |
| `int` flags or status | `bool`; `size_t` for lengths, indexes and `strlen` results |

- **Parse user arguments with `r_num_math`** so that flags and expressions
  work. It only logs parse errors at debug level, so use `r_num_math_err` when
  invalid input must be reported. Use `r_num_get` only for plain numbers that
  must not be evaluated. (#19889, #19593, #26070)
- **Reuse existing helpers before writing new ones**: base64, binstr, escapes,
  type helpers, addrline and the rest. Merge duplicate static helpers
  (~40 hits). (#18499, #22452, #25612)
- **Use accessor APIs** instead of reaching into another module's struct
  internals. (#19022, #18359, #20176)
- **Annotate printf-style APIs** with `R_PRINTF_CHECK`. (#20704)

## Performance

- **Cache repeated dereferences and invariants in `const` locals** before the
  loop: endianness, `obj->field`, config lookups, loop bounds (~30 hits).
  (#22436, #27453, #21587)
- **Keep `strcmp`, `strlen`, config lookups and linear scans out of hot
  loops.** Parse into an int or enum once, check the first char cheaply, or
  use a hashtable. (#26490, #18600, #18371)
- **Compute per-file or per-session invariants once** and cache them in the
  object, but only values that never change after loading (bits, endianness,
  parsed headers). Create expensive objects such as RBin and RIO once and
  reuse them.
  (#26435, #25379)
- **Read a block once** instead of one I/O call per iteration.
  (#22362, #22517)
- **Check for cancellation in long-running loops.** Use `RBreakBind` to
  pass cancellation into library code and `r_cons_break_bind (cons)` to
  create the binding for console callers. Poll with `r_break_check` and
  pair each successful `r_break_begin` with `r_break_end` on every exit.
  A NULL binding disables cancellation. In console-only code that uses
  `r_cons_is_breaked (cons)` directly, balance each `r_cons_break_push` with
  `r_cons_break_pop`. (#19511, #19757) See
  [r_bind.h](../../libr/include/r_bind.h).

## Security and robustness

- **Guard size arithmetic from file headers** with `r_mul_overflow_*` and
  `r_add_overflow_*`, and clamp counts to `r_buf_size` before allocating or
  looping. (#21344, #21837, #24585)
- **Write bounds checks that cannot overflow.** `off + sz > size` →
  `off > size || sz > size - off` (#25286, #27135)
- **Watch signed and unsigned edges.** Validate before subtracting, reject
  `<= 0`, and never return a raw subtraction from a comparator. (#25768, #26205)
- **Check `strchr`/`strstr` for NULL, and check length before indexing
  `input[N]`.** Never index `s[strlen (s) - 1]` on a string that may be empty.
  (#18196, #25789, #20626)
- **Bound input-driven loops and recursion**, and make sure every loop step is
  at least 1. (#18356, #24268, #26717)
- **Quote generated r2 commands** with a `'` prefix
  (`"'@0x%08"PFMT64x"'f sym.%s"`), use `r_core_call_strf`, or filter names with
  `r_name_filter`, so that names from binaries cannot inject commands.
  (#19353, #25731, #27271)
- **Never build shell commands from user strings** with `r_sys_cmdf`. Write a
  native implementation instead. (#21974, #21006)

## Architecture

- **Keep it minimal.** Aim for a negative LOC diff and drop features,
  formatters and flags nobody asked for (~30 hits). (#26116, #25320, #26796)
- **Keep helpers private.** Use `static` for file-local code and `R_IPI` for
  library-internal code, and add `R_API` only when it is truly public.
  (#23964, #26320, #25275)
- **Respect library layering.** r_util must not depend on core, config or
  cons. r_cons must not reach RCore. Cross library boundaries through the
  iob, coreb and consb bindings. (#18915, #20333, #26527)
- **Library code returns data; RCore prints it.** Build output with RStrBuf or
  PJ and return a `char *`. (#25789, #25970)
- **Put logic in the module that owns the data** (`r_charset_open`, `r_type`,
  the bin object), and pass the whole struct rather than its internals.
  (#18303, #20548, #26070)
- **Keep state in the session or instance struct**, not in globals. Use
  `R_TH_LOCAL` only if a global is unavoidable, and never remove an existing
  `R_TH_LOCAL`. (#20443, #25789, #24753)
- **Keep functions to about 6 parameters or fewer.** Group the rest into a
  context struct passed as the first argument, and return results instead of
  filling out-parameters. (#25942, #20539, #25552)
- **Extract long `case` bodies into `cmd_xxx ()` static functions**, and pull
  duplicated logic into one helper. (#25653, #26157, #26490)
- **Protect the ABI.** Mark struct or signature changes with a `R2_5xx`
  comment, and bump `R2_ABIVERSION` when a public layout changes.
  (#23611, #21632, #26890)
- **Fix the existing API** instead of adding a parallel variant.
  (#26508)
- **Keep paired locks balanced** (`R_CRITICAL_ENTER`/`LEAVE`).
  (#20813)

## Commands and user experience

- **Give every new command and modifier a `?` help entry.** Use a
  `RCoreHelpMessage` array, put `[?]` first in the flags, mark optional
  arguments with brackets, keep text under 80 columns, and show usage with
  `r_core_cmd_help_match`. (#20886, #25789, #19889)
- **Follow command conventions**: the `j` suffix always emits JSON, `*` emits
  r2 commands, and path config lives under `dir.*`. (#25653, #25379)
- **Print through `r_cons_*` or `RTable`**, never `printf` or
  `fflush (stdout)`. (#23040, #22227, #24573)
- **Align output with spaces** (`r_str_pad`), and use UTF-8 or ANSI only when
  `scr.utf8` or `scr.color` is set. (#19224, #23478, #20478)
- **Write short, clear, lowercase messages.** (#18958, #18784)

## Plugins

- **Write one arch plugin per architecture**, as `p/<name>/plugin.c`
  implementing `RArchPlugin` with `info` and `regs`. Honor
  `R_ARCH_OP_MASK_DISASM`, read bytes from `op->bytes`, never do I/O, and read
  the cpu from `RArchConfig`. (#19515, #21532, #22436, #24753)
- **Register new plugins everywhere they apply**: `plugins.def.cfg`, the
  static cfgs, the Makefile and `meson.build`. Also update plugin-list goldens
  such as `test/db/cmd/cmd_list`. (#26741, #21344, #21702)
- **Keep license metadata accurate.** Use a one-line header in the `.c` file,
  a `.license` field that matches it (capstone is BSD), keep GPL code out of
  nogpl cfgs, and set the `.author` field. (#19764, #23466, #25079)
- **Give alternative plugins a suffix** (`bpf.cs`) so they don't take over as
  the default. (#20212)
- **Keep bin plugins to parsing.** Leave patching and heavy scanning to io and
  analysis. (#21889, #25726)

## Tests

- **Add an r2r test in `test/db/` for every fix or behavior change**, with
  edge cases (~60 hits). Prefer r2r over unit tests when behavior is
  reachable through commands. (#19627, #26676, #27392)
- **Add unit tests for pure parsing logic** such as regexes and scanf formats.
  (#22517, #22562)
- **Keep r2r tests lean and portable.** Merge tests that share a fixture,
  terminate expectations with `EOF`, use `FILE=malloc://N` when no file is
  needed, put options in `ARGS=`, separate command output with `?e`, and give
  each test a unique `NAME`.
  (#19042, #26588, #26559)
- **Mark failing tests `BROKEN=1`** instead of deleting them.
  (#18763, #25094)
- **Commit binary fixtures to radare2-testbins** (`test/bins`).
  (#19515)

## Commits and PRs

- **Keep each PR to one topic.** Move unrelated refactors, reindents, CI and
  test-harness changes to separate PRs (~45 hits). (#24951, #25991, #26440)
- **Use the established `##tag`s** (`##analysis`, `##arch`, `##disasm`,
  `##abi`), because release notes are generated from them. (#19543, #26440)
- **Add or update the copyright header** with the current year and the real
  author: `/* radare - LGPL - Copyright 2026 - name */`. (#25275, #18499)
- **Apply review suggestions** instead of marking them resolved, and rebase
  cleanly onto master. (#19022, #20944)
- **Send fixes to vendored code (`shlr/sdb`) upstream** first.
  (#18574, #18120)

## Build and portability

- **Include only the umbrella header** (`r_core.h`, `r_util.h`, `r_bin.h`).
  (#24602, #22562, #26145)
- **Update both Make and Meson** for new files and dependencies. Use `$(VAR)`
  for make variables, `$(SHELL)` to run scripts, and acr commands in
  `configure.acr`. (#21344, #19764, #26033)
- **Write POSIX shell, not bash**, and move complex logic into `sys/*.sh`.
  (#19705, #20018)
- **Use portable guards** such as `R2__UNIX__`, `R2__WINDOWS__` and
  `#if __wasi__ ... #else ... #endif`, with the canonical `__macro__` names.
  (#18784, #24685)
- **Use `memset`** instead of `bzero`, and pass a real handle to
  `r_lib_dl_sym`. (#18620, #18505)
