# Agentic Coding Guidelines for the radare2 project

## Locations

- Header files are located in the `./libr/include` directory
- API manpages in the `./man/3` directory provide a good quick start
- Plugins are located under the `/p` subdirectories on each `./libr/*`

## Coding Rules

- `R_NEW`/`R_NEW0` macros never return NULL
- Do not check for NULL before calling `free` or any other `*_free` function
- The `r_json_parse` does not own the string passed, we must free it after freeing the parser
- Function calls require a space before the parenthesis. (p.ex: Use `foo ()` instead of `foo()`)
- Use tabs instead of spaces to indent the code
- Follow the `radare2` coding style (see `./third_party/radare2/DEVELOPERS.md`)
- Prefer `!strcmp ()` over `strcmp () == 0`
- Always use `{}` braces, even one line conditionals
- Use `R_RETURN_*` macros in the public APIs (those marked with `R_API` to specify preconditions for null parameters.
- The `case` lines under the `switch` statements must be indented at the same column.

## Actions

- Compile your changes with: `make -j > /dev/null`
  - Run `make` in the working directory where you made the changes to avoid recompiling everything
  - We assume system-wide installations via symlinks by default, so there's no need to install after compiling for testing
- Run tests with `r2r`. For example: `r2r test/db/cmd/cmd_print`
  - Source files can reference tests with `// R2R` comments (so you can also run against C files: `r2r foo.c`)
- When implementing assembler/disassemblers use `rasm2` oneliners
  - To assemble `rasm2 -a ARCH -b BITS 'nop'`
  - To disassemble `rasm2 -a ARCH -b BITS -d '909090'`
- Run radare2 oneliners to test commands in batch: `r2 -qc 'COMMAND' FILEPATH`
- Using the `R2_DEBUG=1` environment is preferible to catch bugs
