# Development information

This file aims to introduce developers to conventions for working on the code
base of radare2.

The GitHub issues page contains a list of all the bugs that have been reported,
with labels to classify them by difficulty, type, milestone, etc. It is a good
place to start if you are looking to contribute.

For information about the git process, see
[CONTRIBUTING.md](CONTRIBUTING.md#How_to_contribute).

## IDE settings
### generate compile_commands.json
compile_commands.json records the dependency relationship between `.c/.h` file.
It is used by language server(ccls, clang, e.g.) to provide accurate code
completion, syntax highlighting, and other intelligent code analysis features.

If you haven't built the project yet, you can do the following:
```
sudo apt-get install bear
bear -- ./sys/install.sh
```
If you have built the project:
```
make clean
bear -- make install
```
`bear` is tool that will hook the usage of gcc and generate `compile_commands.json`.

### language server
Both of `ccls` and `clangd` supports `compile_commands.json`. You can add
corresponding plugin for your IDE.

## Documentation

Functions should have descriptive names and parameters. It should be clear what
the function and its arguments do from the declaration. Comments should be used
to explain purpose or clarify something that may not be immediately apparent or
relatively complicated.

```c
/* Find the min and max addresses in an RList of maps. Returns (max-min)/width. */
static int findMinMax(RList *maps, ut64 *min, ut64 *max, int skip, int width);
```

## Error diagnosis

There are several utilities that can be used to diagnose errors in r2, whether
they are related to memory (segfaults, uninitialized read, etc.) or problems
with features.

### Compilation options

* `sys/sanitize.sh`: Compile with address sanitizer support.
* `R2_DEBUG=1`: Set `R2_DEBUG_ASSERT`, setup just-in-time debugger and max `R2_LOG_LEVEL`
  * `R2_DEBUG_ASSERT=1`: Show backtrace and trap when assert checks fail.
  * `R2_LOG_LEVEL=10`: Show debug log messages, Used for plugin loading issues.

### ABI stability and versioning

During abi-stable seassons [x.y.0-x.y.8] it is not allowed to break the abi, this
is checked in the CI using the `abidiff` tool on every commit. Sometimes keeping
the abi/api stable implies doing ugly hacks. Those must be marked with the
corresponding to the next MAJOR.MINOR release of r2.


For example, during the development of 5.8.x we add a comment or use `#if R2_590`
code blocks to specify those lines need to be changed when 5.8.9 in git.

Only the even patch version numbers are considered a release. This means that if
you have an odd patch version of r2 it was built from git instead of the release
tarball or binaries.

For more details read [doc/abi.md](doc/abi.md)

### Useful macros from [r\_types.h](libr/include/r_types.h)

* `EPRINT_*`: Allows you to quickly add or remove a debug print without
  worrying about format specifiers.

#### Parameter marking

r2 provides several empty macros to make function signatures more informative.

* `R_OUT`: Parameter is output - written to instead of read.
* `R_INOUT`: Parameter is read/write.
* `R_OWN`: Pointer ownership is transferred from the caller.
* `R_BORROW`: The caller retains ownership of the pointer - the reciever must
  not free it.
* `R_NONNULL`: Pointer must not be null.
* `R_NULLABLE`: Pointer may ne null.
* `R_DEPRECATE`: Do not use in new code and will be removed in the future.
* `R_IFNULL(x)`: Default value for a pointer when null.
* `R_UNUSED`: Not used.

## Code style

### C

In order to contribute patches or plugins, we encourage you to use the same
coding style as the rest of the code base.

* Please use `./sys/clang-format-diff.py` before submitting a PR to be sure you
  are following the coding style, as described in
  [CONTRIBUTING.md](CONTRIBUTING.md#Getting Started). If you find a bug in this
  script, please submit a bug report issue. A detailed style guide can be found
  below.

* See `sys/indent.sh` for indenting your code automatically.

* A pre-commit hook to check coding style is located at
  `sys/pre-commit-indent.sh`. You can install it by copying it to
  `.git/hooks/pre-commit`. To preserve your existing pre-commit hook, use
  `cat sys/pre-commit-indent.sh >> .git/hooks/pre-commit` instead.

* For a premade `.vimrc`, see `doc/vim`.

* See `.clang-format` for work-in-progress support for automated indentation.

#### Guidelines

The following guidelines apply to code that we must maintain. Generally, they
will not apply to copy-paste external code that will not be touched.

* Tabs are used for indentation. In a switch statement, the cases are indented
  at the switch level.

* Switch-cases where local variables are needed should be refactored into
  separate functions instead of using braces. If braced scope syntax is used,
  put `break;` statements inside the scope.

```c
switch (n) {
case 1:
        break;
case 2: {
        break;
}
default:
}
```

* Lines should be at most 140 characters in length. Considering tabs are 8
  characters long. Originally this limit was 78, and it's still considered
  as a good practice, try to keep your functions short and readable, with
  minimum number of function arguments and not much nesting.

* Braces open on the same line as the for/while/if/else/function/etc. Closing
  braces are put on a line of their own, except in the else of an if statement
  or in the while of a do-while statement.

```c
if (a == b) {
        ...
}

if (a == b) {
        ...
} else if (a > b) {
        ...
}

if (a == b) {
        ...
} else {
        do_something_else ();
}

do {
        do_something ();
} while (cond);

if (a == b) {
        b = 3;
}
```

* Always use braces for if and while.

```diff
-if (a == b)
-        return;
+if (a == b) {
+        return;
+}
```

* In general, avoid `goto`. The `goto` statement only comes in handy when a
  function exits from multiple locations and some common work such as cleanup
  has to be done. If there is no cleanup needed, then just return directly.

  Choose label names which say what the `goto` does or why it exists.  An
  example of a good name could be `out_buffer:` if the `goto` frees `buffer`.
  Avoid using GW-BASIC names like `err1:` and `err2:`.

* Use `R_RETURN_*` macros to check for conditions that are caused by
  programming errors or bugs; i.e.: conditions that should **never** happen. Do
  not use them when checking for runtime error conditions, such as a `NULL`
  value being returned from `malloc()`. Use a standard if statement for these
  cases.

```c
int check(RCore *c, int a, int b) {
        /* check for programming errors */
        R_RETURN_VAL_IF_FAIL (c, false);
        R_RETURN_VAL_IF_FAIL (a >= 0, b >= 1, false);

        /* check for runtime errors */
        ut8 *buf = calloc (b, sizeof (a));
        if (!buf) {
                return -1;
        }

        /* continue... */
}
```

* Use spaces after keywords and around operators.

```c
a = b + 3;
a = (b << 3) * 5;
a = sizeof (b) * 4;
```

* Multiline ternary operator conditionals are indented in JavaScript style:

```diff
-ret = over ?
-        r_debug_step_over (dbg, 1) :
-        r_debug_step (dbg, 1);
+ret = over
+        ? r_debug_step_over (dbg, 1)
+        : r_debug_step (dbg, 1);
```

* When breaking up a long line, use a single additional tab if the current and
  next lines are aligned. Do not align start of line using spaces.

```diff
-x = function_with_long_signature_and_many_args (arg1, arg2, arg3, arg4, arg5,
-                                                arg6, arg7, arg8);
-y = z;
+x = function_with_long_signature_and_many_args (arg1, arg2, arg3, arg4, arg5,
+        arg6, arg7, arg8);
+y = z;
```

* Use two additional tabs if the next line is indented to avoid confusion with
  control flow.

```diff
 if (function_with_long_signature_and_many_args (arg1, arg2, arg3, arg4, arg5,
-        arg6, arg7, arg8)) {
+                arg6, arg7, arg8)) {
         do_stuff ();
 }
```

* When following the above guideline, if additional indentation is needed on
  consecutive lines, use a single tab for each nested level. Avoid heavy
  nesting in this manner.

```diff
 if (condition_1 && condition_2 && condition_3
                 && (condition_4
-                                || condition_5)) {
+                        || condition_5)) {
         do_stuff ();
 }
```

* Split long conditional expressions into small `static inline` functions to
  make them more readable.

```diff
+static inline bool inRange(RBreakpointItem *b, ut64 addr) {
+        return (addr >= b->addr && addr < (b->addr + b->size));
+}
+
+static inline bool matchProt(RBreakpointItem *b, int rwx) {
+        return (!rwx || (rwx && b->rwx));
+}
+
 R_API RBreakpointItem *r_bp_get_in(RBreakpoint *bp, ut64 addr, int rwx) {
         RBreakpointItem *b;
         RListIter *iter;
         r_list_foreach (bp->bps, iter, b) {
-                if (addr >= b->addr && addr < (b->addr+b->size) && \
-                        (!rwx || rwx&b->rwx)) {
+                if (inRange (b, addr) && matchProt (b, rwx)) {
                         return b;
                 }
         }
         return NULL;
 }
```

* Use `R_API` to mark exportable (public) methods for module APIs.

* Use `R_IPI` to mark functions internal to a library.

* Other functions should be `static` to avoid polluting the global namespace.

* The structure of C files in r2 should be as follows:

```c
/* Copyright ... */           // copyright
#include <r_core.h>           // includes
static int globals            // const, define, global variables
static void helper(void) {}   // static functions
R_IPI void internal(void) {}  // internal apis (used only inside the library)
R_API void public(void) {}    // public apis starting with constructor/destructor
```

* Why do we return `int` instead of `enum`?

  The reason why many r2 functions return int instead of an enum type is
  because enums can't be OR'ed; additionally, it breaks the usage within a
  switch statement and swig can't handle it.

```
r_core_wrap.cxx:28612:60: error: assigning to 'RRegisterType' from incompatible type 'long'
  arg2 = static_cast< long >(val2); if (arg1) (arg1)->type = arg2; resultobj = SWIG_Py_Void(); return resultobj; fail:
                                                           ^ ~~~~
r_core_wrap.cxx:32103:61: error: assigning to 'RDebugReasonType' from incompatible type 'int'
    arg2 = static_cast< int >(val2); if (arg1) (arg1)->type = arg2; resultobj = SWIG_Py_Void(); return resultobj; fail:
                                                            ^ ~~~~
```

* Do not leave trailing whitespaces at end-of-line.

* Do not use `<assert.h>`. Use `"r_util/r_assert.h"` instead.

* You can use `export R2_DEBUG_ASSERT=1` to set a breakpoint when hitting an assert.

* Declare variables at the beginning of code blocks - use C89 declaration
  instead of C99. In other words, do not mix declarations and code. This helps
  reduce the number of local variables per function and makes it easier to find
  which variables are used where.

* Always put a space before an opening parenthesis (function calls, conditionals,
  for loops, etc.) except when defining a function signature. This is useful
  for searching the code base with `grep`.

```c
-if(a == b){
+if (a == b) {
```

```c
-static int check(RCore *core, int a);
+static int check (RCore *core, int a);
```

* Where is `function_name()` defined?

```sh
grep -R 'function_name(' libr
```

* Where is `function_name()` used?

```sh
grep -R 'function_name (' libr
```

* Function names should be explicit enough to not require a comment explaining
  what it does when seen elsewhere in code.

* **Do not use global variables**. The only acceptable time to use them is for
  singletons and WIP code. Make a comment explaining why it is needed.

* Commenting out code should be avoided because it reduces readability. If you
  *really* need to comment out code, use `#if 0` and `#endif`.

* Avoid very long functions; split it into multiple sub-functions or simplify
  your approach.

* Use types from `<r_types.h>` instead of the ones in `<stdint.h>`, which are
  known to cause some portability issues. Replace `uint8_t` with `ut8`, etc.

* Never use `%lld` or `%llx`, which are not portable. Use the `PFMT64` macros
  from `<r_types.h>`.

### Shell scripts

* Use `#!/bin/sh`.

* Do not use BASH-only features; `[[`, `$'...'`, etc.

* Use `sys/shellcheck.sh` to check for problems and BASH-only features.

## Managing endianness

Endianness is a common stumbling block when processing buffers or streams and
storing intermediate values as integers larger than one byte.

### Problem

The following code may seem intuitively correct:

```c
ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
ut32 value = *(ut32*)opcode;
```

However, when `opcode` is cast to `ut32`, the compiler interprets the memory
layout based on the host CPU's endianness. On little-endian architectures such
as x86, the least-signficiant byte comes first, so `value` contains
`0x40302010`. On a big-endian architecture, the most-significant byte comes
first, so `value` contains `0x10203040`. This implementation-defined behavior
is inherently unstable and should be avoided.

### Solution

To avoid dependency on endianness, use bit-shifting and bitwise OR
instructions. Instead of casting streams of bytes to larger width integers, do
the following for little endian:

```c
ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
ut32 value = opcode[0] | opcode[1] << 8 | opcode[2] << 16 | opcode[3] << 24;
```

And do the following for big endian:

```c
ut32 value = opcode[3] | opcode[2] << 8 | opcode[1] << 16 | opcode[0] << 24;
```

This behavior is not dependent on architecture, and will act consistently
between any standard compilers regardless of host endianness.

### Endian helper functions

The above is not very easy to read. Within radare2, use endianness helper
functions to interpret byte streams in a given endianness.

```c
val32 = r_read_be32 (buffer)         // reads 4 bytes from a stream in BE
val32 = r_read_le32 (buffer)         // reads 4 bytes from a stream in LE
val32 = r_read_ble32 (buffer, isbig) // reads 4 bytes from a stream:
                                     //   if isbig is true, reads in BE
                                     //   otherwise reads in LE
```

Such helper functions exist for 64, 32, 16, and 8 bit reads and writes.

* Note that 8 bit reads are equivalent to casting a single byte of the buffer
  to a `ut8` value, i.e.: endian is irrelevant.

## Allocations

Instantiating structures in memory ends up depending on the standard malloc/free
provided by your system's libc. But radare2 provides some helper macros in order
to simplify the use of it.

Instead of:

```c
Foo *foo = malloc (sizeof (Foo));
memset (foo, 0, sizeof (Foo));
```

Use the following:

```c
Foo *foo = R_NEW0 (Foo);
```

Note that we could use `calloc` instead of the  malloc+memset, but we can
avoid handwriting the sizeof byjust using `R_NEW` or `R_NEW0`.

### Null checks

When calling malloc we want to check if the allocation worked or not. But
checking for every allocation is kind of expensive and boring, we (recently)
decided to reduce the amount of valid allocations.

* If the allocation size is known at compile time we won't check for null.

This is, most mallocs of small sizes won't fail, and actually, most modern
libcs will never return null.

The only reason for a heap allocator to fail is when we are requesting large
areas or negative sizes, therefor, check for multiplication overflows before
computing the amount of memory necessary (see the integer overflow section)
and then check for null.

For example:

```c
if (ST32_ADD_OVFCHK (sizeof (Object), counter)) {
	void *amount = calloc (sizeof (Object), counter);
	if (!amount) {
		R_LOG_DEBUG ("Cannot allocate %d objects", counter);
		return;
	}
```

### Stack allocations

Never ever do dynamic size stack allocations. With this I mean that it is
forbidden in r2land to use code like this:

```c
void foo(int amount) {
	int array[amount];
}
```

Or constructions like this:

```c
void foo(int amount) {
	int *array = alloca (amount * sizeof (int));
}
```

Instead you must use the heap. The reason is because there's no way to determine
if alloca is exhausting the stack given by the system. Also there's no portable
way to know how big the system stack is and the final reason is because you can
pass negative values to alloca, some implementations will decrement the frame
pointer causing a fatal corruption.

### Freeing nulls

Yes, this is totally legit and valid posix. Please don't submit code like this:

```c
if (maybenull) {
	free (maybenull);
}
```

Just remove the conditional block, free is already checking for null and it's
not necessary to compare it two times.

## Editor setup

Vim/Neovim:

```vim
setl cindent
setl tabstop=8
setl noexpandtab
setl cino=:0,+0,(2,J0,{1,}0,>8,)1,m1
```

Emacs:

```elisp
(c-add-style "radare2"
             '((c-basic-offset . 8)
               (tab-width . 8)
               (indent-tabs-mode . t)
               ;;;; You would need (put 'c-auto-align-backslashes 'safe-local-variable 'booleanp) to enable this
               ;; (c-auto-align-backslashes . nil)
               (c-offsets-alist
                (arglist-intro . ++)
                (arglist-cont . ++)
                (arglist-cont-nonempty . ++)
                (statement-cont . ++)
                )))
```

You may use directory-local variables by adding the following to
`.dir-locals.el`.

```elisp
((c-mode .  ((c-file-style . "radare2"))))
```

## Packed structures

Due to standards differing between compilers, radare2 provides a portable
helper macro for packed structures: `R_PACKED()`, which will automatically
utilize the correct compiler-dependent macro. Do not use `#pragma pack` or
`__attribute__((packed))`. Place the packed structure inside `R_PACKED()` like
so:

```c
R_PACKED (struct mystruct {
        int a;
        char b;
});
```

If you are using `typedef`, do not encapsulate the type name.

```c
R_PACKED (typedef struct mystruct_t {
        int a;
        char b;
}) mystruct;
```

Note that we also have the `R_ALIGN` macro to define the alignment
requirements for struct fields or local stack variables. Use `git grep`
for some examples.

## Logging Messages

Use the `R_LOG_` APIs to display error, tracing, information or other
information to the user via the stderr file descriptor.

* Only use `eprintf` for draft/wip development reasons.

The `R_LOG` macros will end up calling the `r_log` functions which can
be configured with eval variables.

```console
[0x00000000]> e??log.
           log.color: Should the log output use colors
            log.cons: Log messages using rcons (handy for monochannel r2pipe)
            log.file: Save log messages to given filename
          log.filter: Filter only messages matching given origin
           log.level: Target log level/severity (0:FATAL 1:ERROR 2:INFO 3:WARN 4:TODO 5:DEBUG)
          log.origin: Show [origin] in log messages
           log.quiet: Be quiet, dont log anything to console
          log.source: Show source [file:line] in the log message
       log.traplevel: Log level for trapping R2 when hit
              log.ts: Show timestamp in log messages
[0x00000000]>
```

## Modules

radare2 is split into modular libraries in the `libr/` directory. The `binr/`
directory contains programs which use these libraries.

The libraries can be built individually, PIC or non-PIC. You can also create a
single static library archive (`.a`) which you can link your own programs
against to use radare2's libraries without depending on an existing system
installation. See [doc/static.md](doc/static.md) for more info.

[This presentation](http://radare.org/get/lacon-radare-2009/) gives a good
overview of the libraries. //Link not working temporarily.

## API

The external API is maintained in a different repository. The API function
definitions in C header files are derived from and documented in the
`radare2-bindings` repository, found
[here](https://github.com/radareorg/radare2-bindings).

Currently, the process of updating the header files from changed API bindings
requires human intervention, to ensure that proper review occurs. Incorrect
definitions in the C header files will trigger a build failure in the bindings
repository.

If you are able to write a plugin for various IDE that can associate the
bindings with the header files, such a contribution would be very welcome.

## Dependencies and installation

radare2 does not require external dependencies. On \*nix-like systems, it
requires only a standard C compiler and GNU `make`. For compiling on Windows,
see [doc/windows.md](doc/windows.md). Browse the [doc/](doc/) folder for other
architectures. For cross-compilation, see
[doc/cross-compile.md](doc/cross-compile.md).

## Recompiling and Outdated Dependencies

When recompiling code, ensure that you recompile all dependent modules (or
simply recompile the entire project). If a module's dependency is not
recompiled and relinked, it may cause segmentation faults due to outdated
structures and libraries. Such errors are not handles automatically, so if you
are not sure, recompile all modules.

To speed up frequent recompilation, you can use `ccache` like so:

```sh
export CC="ccache gcc"
```

This will automatically detect when files do not need to recompiled and avoid
unnecessary work.

It is not necessary to recompile the whole project everytime. Just run make in
the directory you are working on to compile these parts only by using:

```sh
make
```

while inside a modified module (eg: `libr/core`).

Note that if you have radare2 already installed, you don't have to reinstall it
again after recompilation, as the compiled libraries are connected through the symlinks.

## Repeated installation

There is an alternative installation method for radare2 to make it easier to
repeatedly install while making changes. The `symstall` target creates a single
system-wide installation using symlinks instead of copies, making repeated
builds faster.

```sh
sudo make symstall
```

## Source repository

The source for radare2 can be found in the following GitHub repository:

```sh
git clone https://github.com/radareorg/radare2
```

Other packages radare2 depends on, such as Capstone, are pulled from
their git repository as required.

To get an up-to-date copy of the repository, you should perform the
following while on the `master` branch:

```sh
git pull
```

If your local git repository is not tracking upstream, you may need to use the
following:

```sh
git pull https://github.com:radareorg/radare2 master
```

The installation scripts `sys/user.sh`, `sys/install.sh`, `sys/meson.py`, and
`sys/termux.sh` will automatically identify and update using an existing
upstream remote, if one exists. If not, it will pull using a direct URL.

If you have modified files on the `master` branch, you may encounter conflicts
that must be resolved manually. To save your changes, work on a different
branch as described in [CONTRIBUTING.md](CONTRIBUTING.md). If you wish to
discard your current work, use the following commands:

```sh
git clean -xdf
git reset --hard
rm -rf shlr/capstone
```

## Regression testing

Use `r2r` to run the radare2 regression test suite, e.g.:

```sh
sys/install.sh
r2r
```

r2r's source can be found in the `test/` directory, while binaries used for
tests are located in the following GitHub repository:

```sh
git clone https://github.com/radareorg/radare2-testbins
```

These can be found in `test/bins/` after being downloaded by r2r.

For more information, see [r2r's
README](https://github.com/radareorg/radare2-testbins/blob/master/README).

The test files can be found in `test/db/`. Each test consists of a unique name,
an input file, a list of input commands, and the expected output. The test must
be terminated with a line consisting only of `RUN`.

Testing can always be improved. If you can contribute additional tests or fix
existing tests, it is greatly appreciated.

## Reporting bugs

If you encounter a broken feature, issue, error, problem, or it is unclear how
to do something that should be covered by radare2's functionality, report an
issue on the GitHub repository
[here](https://github.com/radareorg/radare2/issues).

If you are looking for feedback, check out the [Community section in the
README](README.md#Community) for places where you can contact other r2 devs.

# HOW TO RELEASE

 - Set `RELEASE=1` in global.mk and r2-bindings/config.mk.acr.
 - Use `bsdtar` from libarchive package. GNU tar is broken.

  RADARE2
  ---
   - bump revision
   - `./configure`
   - `make dist`

  R2-BINDINGS
  ---
   - `./configure --enable-devel`
   - `make`
   - `make dist`

  - Update the [paths on the website](https://github.com/radareorg/radareorg/blob/master/source/download_paths.rst)

# Additional resources

 * [CONTRIBUTING.md](CONTRIBUTING.md)
 * [README.md](README.md)
 * [USAGE.md](USAGE.md)
