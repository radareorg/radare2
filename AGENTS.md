# Agentic Coding Guidelines for radare2

## Work and references

Make the smallest coherent fix. Reuse existing helpers; avoid unrelated cleanup,
speculative abstractions and repeated scans in hot paths. Extract helpers when
they simplify logic; comment on non-obvious intent.

Search symbols and paths first; read only relevant sections:

- APIs: `libr/include/` declarations, corresponding `libr/` implementations and callers. Verify signatures and ownership against current code.
- Layout: libraries in `libr/`, CLI tools in `binr/`, plugins in `libr/*/p/`.
- Style/build details: `DEVELOPERS.md` and `doc/indent-example.c`; public API/ABI changes: `doc/abi.md`.
- Commands: `man/`, `r2 -h` and `<command>?`; test formats: `test/README.md` and nearby `test/db/` cases.

## Style

- Match nearby code: tabs, no trailing whitespace, braces even for single statements, and `case` labels aligned with `switch`.
- Space before calls/control parentheses: `foo ()`, `if (x)`, `sizeof (int)`. Keep function signatures on one line without a space before `(`.
- Initialize variables near first use; declare loop variables before `for`, not inside it.
- Use `<r_types.h>` integer types (`ut8`, `ut32`, etc.), `PFMT64` formatting and `R_PACKED` for packed structures.
- Do not run `clang-format-radare2` unless requested. `sys/lint.sh` provides style diagnostics for the whole tree; distinguish pre-existing findings.

## Memory and APIs

- Project convention omits NULL checks for small constant `R_NEW`/`R_NEW0` allocations.
- Check runtime-sized allocations for failure; guard size arithmetic with `r_mul_overflow_*`/`r_add_overflow_*` before allocating. Check bounds before buffer access; endian helpers do not.
- Never use `alloca` or variable-length stack arrays. Avoid NULL guards around `free` and destructors that accept NULL.
- Use `R_RETURN_*` for public API preconditions; ordinary `if` for runtime/input errors. Use `r_util/r_assert.h` instead of `<assert.h>`.
- Prefer `!strcmp ()`, `r_str_newf`, `r_str_pad` and endian helpers such as `r_read_le32`. Use `r_strbuf_*` for concatenation in loops to avoid repeated copying.
- Use annotations from `libr/include/r_types.h` and `libr/include/r_types_null.h`; ownership macros are `R_OWNED`/`R_UNOWNED`.
- Prefer `r_json_parsedup`; when borrowing buffers, follow the lifetime rules in `libr/include/r_util/r_json.h`.
- New commands need `?` help. Use `R_LOG_*` for diagnostics and the existing console APIs for command output; remove debugging `eprintf` calls.

## Build

- For code changes, build from the root: `./configure` if needed, then `make -j2` (adjust jobs to available resources). Keep failure output. Do not compile individual `.c`/`.o` files directly.
- Edit `configure.acr` and regenerate `configure` with `acr`; do not edit generated `configure` directly.
- Update both Make and Meson for library dependencies. Register new plugins in `dist/plugins-cfg/plugins.def.cfg`, `dist/plugins-cfg/plugins.static.cfg` and the relevant `libr/*/meson.build`.

## Verify

- Prefer focused `r2r` regressions in existing `test/db/` files, reusing fixtures. Cover the reported behavior and relevant edge cases; do not blindly accept changed expected output.
- Build and install this checkout before running `r2r -C test db/...` from the root. See [Regression testing](DEVELOPERS.md#regression-testing) for library/plugin paths, absolute executable overrides and `test/unit/`.
- Keep the filename last in `r2` invocations. Use `-n` only for raw input: it skips binary loading. `io.va=false` changes addressing, not binary loading.
- Binary fixtures belong in `radare2-testbins` (`test/bins/`), not this repository. `// R2R` comments can link source files to tests.
- For memory debugging, see `DEVELOPERS.md` (Error diagnosis): `R2_DEBUG=1` and `sys/sanitize.sh`.
- Run `git diff --check`; report what was tested and any blockers. Documentation-only changes need reference checks, not a full build.

## Commits

Commit only when requested or needed for a requested PR; otherwise suggest a one-line message.
Follow [Commit messages](DEVELOPERS.md#commit-messages) for subject style, issue references and changelog tags.
