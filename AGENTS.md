# Agentic Coding Guidelines for radare2

radare2 is a modular reverse engineering framework.

## Locations

- **Header files**: `./libr/include`
- **Manpages**: `./man/`
- **Plugins**: `./libr/*/p/` subdirectories
- **Test binaries**: Separate `radare2-testbins` repository (cloned into `./test/bins` by r2r)
- **Test files**: `./test/db/`. Source files can use `// R2R` comments to reference tests

## Formatting

Run `clang-format-radare2` on modified files before submitting.

- Indent code with **tabs**, spaces for comments and no trailing spaces
- Space before opening parenthesis: `if (a)`, `foo ()`, `sizeof (int)`
- Function signatures do not require a space before `(` and must fit in one line
- Always use braces `{}` for conditionals, even single statements
- Switch `case` labels column-aligned with the `switch` keyword
- Declare and assign variables in the same line if possible (No K&R style)
- No C99 `for (int i = ...)` declarations; declare variables before the loop
- Use `R_PACKED()` macro for packed structures for portability
- Use types from `<r_types.h>` (`ut8`, `ut16`, `ut32`, `ut64`) instead of `<stdint.h>`
- Use `PFMT64` macros instead of `%lld` for portable formatting

The `sys/lint.sh` script enforces additional style rules including:
- No `for (int ...)` declarations
- No trailing whitespace or tabs
- Proper spacing around keywords and parentheses
- No `eprintf` with "Error:" prefix (use `R_LOG_ERROR` instead)
- Strings passed to `R_LOG_` can't have newlines
- No direct `free()` calls on expressions (assign to variable first)

## Coding Rules

### Memory Management

- `R_NEW`/`R_NEW0` never return NULL; no null checks needed for small constant allocations
- Check for integer overflow before large allocations using `r_mul_overflow_*`
- Never use `alloca()` or variable-length stack arrays
- Do not check for NULL before calling `free()` or `*_free` functions
- `r_json_parse` does not own the input string; free it after freeing the parser

### API Usage

- Use `R_RETURN_*` macros in public `R_API` functions for programming error checks
- Use standard `if` statements for runtime error checks (e.g., malloc failures)
- Never use `<assert.h>`; use `"r_util/r_assert.h"`
- Prefer `!strcmp ()` over `strcmp () == 0`
- Use string and memory parsing functions from `libr/util` before libc if possible:
  - Use `r_str_newf` instead of manual malloc + snprintf
  - Use `r_strbuf_*` for string concatenation in loops; avoid `r_str_append`
  - Use `r_str_pad2` to create repeated character strings
  - Use `r_read_be32`/`r_read_le32` for endian-safe reads

### Commands

- Handle the `?` subcommand to display help
- Keep functions short; split complex logic into helper functions

### Logging

- Use `R_LOG_*` APIs for user-facing messages
- Only use `eprintf` during draft/wip development for debugging purposes
- Use the `R2_DEBUG=1` environment to catch bugs during testing

### Parameter Annotations

Use these macros to document function parameters:
- `R_OUT`: output parameter (written to)
- `R_INOUT`: read/write parameter
- `R_OWN`: ownership transferred to callee
- `R_BORROW`: caller retains ownership
- `R_NONNULL`: pointer must not be null
- `R_NULLABLE`: pointer may be null
- `R_DEPRECATED`: do not use in new code

## Building

- Never run `gcc` directly; always use `make -j > /dev/null`
- Do not build `.o` files separately
- `sudo make symstall` creates symlinked system-wide installation
- Symlinks ensure working directory builds work as system installations
- For new library dependencies, update both `Makefile` and `meson.build`
- For new plugins, register in:
  - `dist/plugins-cfg/plugins.def.cfg`
  - `dist/plugins-cfg/plugins.static.cfg`
  - Relevant `libr/*/meson.build` plugin list

## Testing

- When running `r2` oneliners take this into account:
  - The filename to open must be always the last argument
  - Use the `-n` flag to avoid loading binary headers and read the plain file
    - Similar IO behaviour can be achieved with `-e io.va=false`
- Run the `test/db` tests with `r2r <path/to/db/..>`
- Source files can reference tests with `// R2R` comments
- Large test binaries belong in `radare2-testbins` repository, not this repo
- Run `sys/sanitize.sh` to compile with address sanitizer for memory debugging

## Commits

Do not create commits by yourself. Instead, at the end of your work suggest a one-line commit message following these conventions:

- Start with a capital letter
- If the change is relevant for the users and must be listed in the release changelog:
  - Append one double-hash tag as the **last word** in the message
  - Tags are lowercase, alphabetic only (no numbers or symbols)
  - When in doubt; check `git log` to find examples of other commits.
  - Security vulnerabilities must be tagged with `##crash`
  - Available tags: `abi`, `analysis`, `arch`, `asm`, `bin`, `ci`, `cons`, `core`, `crash`, `debug`, `doc`, `esil`, `fs`, `http`, `io`, `r2js`, `lang`, `print`, `project`, `r2pipe`, `r2r`, `search`, `shell`, `threads`, `tools`, `trace`, `types`, `util`, `visual`, `zign`
