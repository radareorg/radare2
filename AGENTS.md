# Agentic Coding Guidelines for the radare2 project

## Locations

- Header files are located in the `./libr/include` directory
- Manpages documenting the most common APIs in radare2 are in `./man/3`
- Plugins are located under the `/p` subdirectories on each `./libr/*`
- Large test binaries are located in the separate `radare2-testbins` repository (cloned in ./test/bins by the r2r during the test execution)

## Formatting Style

- Follow the `radare2` coding style (run `clang-format-radare2 file.c`)
- Indent with **TABS** for code and spaces for comments
- Function calls require a space before the parenthesis. (p.ex: Use `foo ()` instead of `foo()`)
- Prefer `!strcmp ()` over `strcmp () == 0`
- Always use `{}` braces, even one line conditionals
- The `case` lines under the `switch` statements must be indented at the same column.
- Do not define variables inside for parenthesis, do it like this: `int i;\nfor (i = 0; i ..)`

## Coding Rules

- The `r_json_parse` does not own the string passed, we must free it after freeing the parser
- Use `R_RETURN_*` macros in the public `R_API` functions
- Never use `alloca` or other unsafe functions from the libc
- Do not check for NULL before calling `free` or any other `*_free` function
- The `R_NEW`/`R_NEW0` macros **NEVER** return NULL, there is no need to check allocation
- Keep changes minimal and take smart decisions
- When implementing commands, handle the `?` subcommand to show its help
- Define and assign the variables in the same line if possible
- Struct typedefs must use CamelCase names
- Do not use `r_str_append`, better use an `r_strbuf_new` and concatenate for loops
- Use `r_str_newf` instead of manual malloc+snprintf
- Use `r_str_pad2` to create a string containing a character repeated many times

## Actions

- Compile your changes with: `make -j > /dev/null`
  - Never run 'gcc' directly, always use 'make -C path/to/directory'
  - Do not build the .o files separately
  - Run `make` in the working directory to compile just this part.
  - Assume system-wide installations via symlinks (do not install after every change)
- If you add new library dependencies, update both `Makefile` and `meson.build` (and pkg-config `requires`)
- If you add a new plugin, register it in:
  - `dist/plugins-cfg/plugins.def.cfg`
  - `dist/plugins-cfg/plugins.static.cfg`
  - the relevant `libr/*/meson.build` plugin list
- Keep large/binary fixtures out of this repo; add them to `radare2-testbins` and reference them in tests
- Run tests with `r2r`. For example: `r2r test/db/cmd/cmd_print`
  - Source files can reference tests with `// R2R` comments (so you can also run against C files: `r2r foo.c`)
- Verify syntax and indentation with `sys/lint.sh` and `clang-format-radare2`
- When implementing assembler/disassemblers use `rasm2` oneliners
  - To assemble `rasm2 -a ARCH -b BITS 'nop'`
  - To disassemble `rasm2 -a ARCH -b BITS -d '909090'`
- Run radare2 oneliners to test commands in batch: `r2 -qc 'COMMAND' FILEPATH`
- Using the `R2_DEBUG=1` environment is preferible to catch bugs
