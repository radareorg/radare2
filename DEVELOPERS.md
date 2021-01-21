# DEVELOPERS

This file aims to describe an introduction for developers to work
on the code base of radare2 project.

## Documentation
There is support for Doxygen document generation in this repo.
By running `doxygen` in the root of this repository, it will autodetect the
Doxyfile and generate HTML documentation into
[doc/doxygen/html/index.html](./doc/doxygen/html/index.html)

If you're contributing code or willing to update existing code, you can use the
doxygen C-style comments to improve documentation and comments in code.
See the [Doxygen Manual](http://www.doxygen.nl/manual/index.html)
for more info. Example usage can be found [here](http://www.doxygen.nl/manual/docblocks.html)
```c
/**
 * \brief Find the min and max addresses in an RList of maps.
 * \param maps RList of maps that will be searched through
 * \param min Pointer to a ut64 that the min will be stored in
 * \param max Pointer to a ut64 that the max will be stored in
 * \param skip How many maps to skip at the start of an iteration
 * \param width Divisor for the return value
 * \return (max-min)/width
 *
 * Used to determine the min & max addresses of maps and
 * scale the ascii bar to the width of the terminal
 */
static int findMinMax(RList *maps, ut64 *min, ut64 *max, int skip, int width);
```

## Code style

### C

In order to contribute with patches or plugins, we encourage you to
use the same coding style as the rest of the code base.

Please use `./sys/clang-format-diff.py` before submitting a PR to be sure you
are following the coding style. If you find a bug in this script, please create
an issue on GitHub. You can also install the pre-commit hook
`./sys/pre-commit-indent.sh` by copying it in `.git/hooks/pre-commit` which
will check the coding style of the modified lines before committing them.

You may find some additional notes on this topic in doc/vim.

* Tabs are used for indentation. In a switch statement, the
  cases are indented at the switch level.

* Switch-cases where local variables are needed should be refactored into
  separate functions instead of using braces. Even so, if braced scope syntax
  is used, put `break;` statement inside the scope.

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

* Lines should be at most 78 chars. A tab is considered as 8 chars.

* Braces open on the same line as the for/while/if/else/function/etc. Closing
  braces are put on a line of their own, except in the else of an if statement
  or in a while of a do-while statement. Always use braces for if and while.

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

* In general, don't use goto. The goto statement only comes in handy when a
  function exits from multiple locations and some common work such as cleanup
  has to be done. If there is no cleanup needed, then just return directly.

  Choose label names which say what the goto does or why the goto exists.  An
  example of a good name could be "out_buffer:" if the goto frees "buffer".
  Avoid using GW-BASIC names like "err1:" and "err2:".

* Use `r_return_*` macros to check preconditions that are caused by
  programmers' errors. Please, keep in mind:
  * conditions that should never happen should be handled through
    `r_return_*` macros;
  * runtime conditions (e.g. malloc returns NULL, input coming from user,
    etc.) should be handled in the usual way through if-else.

```c
int check(RCore *c, int a, int b) {
	r_return_val_if_fail (c, false);
	r_return_val_if_fail (a >= 0, b >= 1, false);

	if (a == 0) {
		/* do something */
		...
	}
	... /* do something else */
}
```

* Use a space after most of the keyword and around operators.

```c
a = b + 3;
a = (b << 3) * 5;
```

* Multiline ternary operator conditionals must be indented a-la JS way:

```diff
- ret = over ?
-         r_debug_step_over (dbg, 1) :
-         r_debug_step (dbg, 1);
+ ret = over
+         ? r_debug_step_over (dbg, 1)
+         : r_debug_step (dbg, 1);
```

* Split long conditional expressions into small `static inline` functions to make them more readable:

```diff
+static inline bool inRange(RBreakpointItem *b, ut64 addr) {
+       return (addr >= b->addr && addr < (b->addr + b->size));
+}
+
+static inline bool matchProt(RBreakpointItem *b, int rwx) {
+       return (!rwx || (rwx && b->rwx));
+}
+
 R_API RBreakpointItem *r_bp_get_in(RBreakpoint *bp, ut64 addr, int rwx) {
        RBreakpointItem *b;
        RListIter *iter;
        r_list_foreach (bp->bps, iter, b) {
-               if (addr >= b->addr && addr < (b->addr+b->size) && \
-                       (!rwx || rwx&b->rwx))
+               if (inRange (b, addr) && matchProt (b, rwx)) {
                        return b;
+               }
        }
        return NULL;
 }
```

* Structure in the C files

The structure of the C files in r2 must be like this:

```c
/* Copyright ... */           ## copyright
#include <r_core.h>           ## includes
static int globals            ## const, define, global variables
static void helper(void) {}   ## static functions
R_IPI void internal(void) {}  ## internal apis (used only inside the library)
R_API void public(void) {}    ## public apis starting with constructor/destructor

```


* Why return int vs enum

The reason why many places in r2land functions return int instead of an enum type is because enums can't be OR'ed; otherwise, it breaks the usage within a switch statement and swig can't handle that stuff.

```
r_core_wrap.cxx:28612:60: error: assigning to 'RRegisterType' from incompatible type 'long'
  arg2 = static_cast< long >(val2); if (arg1) (arg1)->type = arg2; resultobj = SWIG_Py_Void(); return resultobj; fail:
                                                           ^ ~~~~
r_core_wrap.cxx:32103:61: error: assigning to 'RDebugReasonType' from incompatible type 'int'
    arg2 = static_cast< int >(val2); if (arg1) (arg1)->type = arg2; resultobj = SWIG_Py_Void(); return resultobj; fail:
                                                            ^ ~~~~
3 warnings and 2 errors generated.
````

* Do not leave trailing whitespaces at the end of line

* Do not use assert.h, use r_util/r_assert.h instead.

* You can use `export R2_DEBUG_ASSERT=1` to set a breakpoint when hitting an assert.

* Do not use C99 variable declaration
    - This way we reduce the number of local variables per function
    and it's easier to find which variables are used, where and so on.

* Always put a space before every parenthesis (function calls, conditionals,
  fors, etc, ...) except when defining the function signature. This is
  useful for grepping.

* Function names should be explicit enough to not require a comment
  explaining what it does when seen elsewhere in code.

* Use 'R_API' define to mark exportable (public) methods only for module APIs

* The rest of functions must be static, to avoid polluting the global space.

* Avoid using global variables, they are evil. Only use them for singletons
  and WIP code, placing a comment explaining the reason for them to stay there.

* If you *really* need to comment out some code, use #if 0 (...) #endif. In
  general, don't comment out code because it makes the code less readable.

* Do not write ultra-large functions: split them into multiple or simplify
  the algorithm, only external-copy-pasted-not-going-to-be-maintained code
  can be accepted in this way (gnu code, external disassemblers, etc..)

* See sys/indent.sh for indenting your code automatically

* See doc/vim for vimrc

* See .clang-format for work-in-progress support for automated indentation

* Use the r2 types instead of the ones in stdint, which are known to cause some
  portability issues. So, instead of uint8_t, use ut8, etc..

* Never ever use %lld or %llx. This is not portable. Always use the PFMT64x
  macros. Those are similar to the ones in GLIB.

### Shell Scripts

* Use `#!/bin/sh`

* Do not use bashisms `[[`, `$'...'` etc.

* Use our [shellcheck.sh](https://github.com/radareorg/radare2/blob/master/sys/shellcheck.sh) script to check for problems and for bashisms

# Manage Endianness

As hackers, we need to be aware of endianness.

Endianness can become a problem when you try to process buffers or streams
of bytes and store intermediate values as integers with width larger than
a single byte.

It can seem very easy to write the following code:

```c
ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
ut32 value = *(ut32*)opcode;
```

... and then continue to use "value" in the code to represent the opcode.

This needs to be avoided!

Why? What is actually happening?

When you cast the opcode stream to a unsigned int, the compiler uses the endianness
of the host to interpret the bytes and stores it in host endianness.  This leads to
very unportable code, because if you compile on a different endian machine, the
value stored in "value" might be 0x40302010 instead of 0x10203040.

## Solution

Use bitshifts and OR instructions to interpret bytes in a known endian.
Instead of casting streams of bytes to larger width integers, do the following:

```c
ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
ut32 value = opcode[0] | opcode[1] << 8 | opcode[2] << 16 | opcode[3] << 24;
```

or if you prefer the other endian:

```c
ut32 value = opcode[3] | opcode[2] << 8 | opcode[1] << 16 | opcode[0] << 24;
```

This is much better because you actually know which endian your bytes are stored in
within the integer value, REGARDLESS of the host endian of the machine.

## Endian helper functions

Radare2 now uses helper functions to interpret all byte streams in a known endian.

Please use these at all times, eg:

```c
val32 = r_read_be32(buffer)         // reads 4 bytes from a stream in BE
val32 = r_read_le32(buffer)         // reads 4 bytes from a stream in LE
val32 = r_read_ble32(buffer, isbig) // reads 4 bytes from a stream:
                                    //   if isbig is true, reads in BE
                                    //   otherwise reads in LE
```

There are a number of helper functions for 64, 32, 16, and 8 bit reads and writes.

(Note that 8 bit reads are equivalent to casting a single byte of the buffer
to a ut8 value, ie endian is irrelevant).

### Editor configuration

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

You may use directory-local variables by putting
```elisp
((c-mode .  ((c-file-style . "radare2"))))
```

into `.dir-locals.el`.

## Packed structures

Due to the various differences between platforms and compilers radare2
has a special helper macro - `R_PACKED()`. Instead of non-portable
`#pragma pack` or `__attribute__((packed))` it is advised to use this macro
instead. To wrap the code inside of it you just need to write:
```c
R_PACKED (union mystruct {
	int a;
	char b;
})
```
or in case of typedef:
```c
R_PACKED (typedef structmystruct {
	int a;
	char b;
})
```

## Modules

The radare2 code base is modularized into different libraries that are
found in libr/ directory. The binr/ directory contains the programs
which use the libraries.

It is possible to generate PIC/nonPIC builds of the libraries and also
to create a single static library so you can use a single library
archive (.a) to link your programs and get your programs using radare
framework libraries without depending on them. See doc/static for more info.

The following presentation gives a good overview of the libraries:

   http://radare.org/get/lacon-radare-2009/

## API

As mentioned in README.md, the API itself is maintained in a different
repository. The API function definitions in C header files are derived
from and documented in the radare2-bindings repository, found at:
```sh
git clone git://github.com/radareorg/radare2-bindings
```

Currently the process of updating the header files from changed API
bindings requires human intervention, to ensure that proper review
occurs.  Incorrect definitions in the C header files will trigger
a build failure in the bindings repository.

If you are able to write a plugin for various IDE that can associate
the bindings with the header files, such a contribution would be
very welcome.

## Dependencies

radare2 can be built without any special dependency. It just requires
a C compiler, a GNU make and a unix-like system.

## Cross compilation

The instructions to crosscompile r2 to Windows are in doc/windows.

You may find other documents in doc/ explaining how to build it on iOS,
linux-arm and others, but the procedure is like this:

 - define `CC`
 - use a different compiler profile with `--with-compiler`
 - use a different OS with `--with-ostype`
 - type `make`
 - install in `DESTDIR`

## Source repository

The source of radare2 can be found in the following GitHub repository.
```sh
git clone git://github.com/radareorg/radare2
```
Other packages radare2 depends on, such as Capstone, are pulled from
their git repository as required.

To get an up-to-date copy of the repository, you should perform the
following steps:
```sh
git pull
```

If you have conflicts in your local copy, it's because you have modified
files which are conflicting with the incoming patchsets. To get a clean
source directory, type the following command:
```sh
git clean -xdf
git reset --hard
```

## Compilation

Inter-module rebuild dependencies are not handled automatically and
require human interaction to recompile the affected modules.

This is a common issue and can end up having outdated libraries trying
to use deprecated structures which may result into segfaults.

You have to make clean on the affected modules. If you are not
sure enough that everything is OK, just make clean the whole project.

If you want to accelerate the build process after full make cleans,
you should use ccache in this way:
```
  export CC="ccache gcc"
```

## Installation

Developers use to modify the code, type make and then try.

radare2 has a specific makefile target that allows you to install
system wide but using symlinks instead of hard copies.
```sh
sudo make symstall
```
This kind of installation is really helpful if you do lot of changes
in the code for various reasons.

  - only one install is required across multiple builds
  - installation time is much faster

## Regression testing

The source of the radare2 regression test suite can be found in the
 `test/` directory, while binaries for this test are located in the
 following GitHub repository.
```sh
git clone git://github.com/radareorg/radare2-testbins
```

See the `README.md` file in that repository for further information.

The existing test coverage can always do with improvement. So if you can
contribute additional tests, that would be gratefully accepted.

## Reporting bugs

If you notice any misfeature, issue, error, problem or you just
don't know how to do something which is supposed to be covered
by this framework.

You should report it into the GitHub issues page.
   https://github.com/radareorg/radare2/issues

Otherwise, if you are looking for some more feedback, I will
encourage you to send an email to any of the emails enumerated
in the AUTHORS file.

Anyway, if you want to get even more feedback and discuss this
in a public place: join the #radare channel on irc.freenode.net.

The issues page of GitHub contains a list of all the bugs that
have been reported classified with labels by difficulty, type,
milestone, etc. It is a good place to start if you are looking
to contribute.

## HOW TO RELEASE

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

--pancake
