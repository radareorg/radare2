# How to report issues

Before reporting an issue with GitHub, be sure that:
* you are using the git version of radare2
* you are using a clean installation
* the issue was not already reported

When the above conditions are satisfied, feel free to submit an issue,
trying to be as precise as possible. If you can, provide the problematic
binary, the steps to reproduce the error and a backtrace in case of SEGFAULTs.
Any information will help to fix the problem.

# How to contribute

There are a few guidelines that we need contributors to follow so that we can
try to keep the codebase consistent and clean.

## Getting Started

* Make sure you have a GitHub account.
* Fork the repository on GitHub.
* Create a topic branch from master. Please avoid working directly on the ```master``` branch.
* Make commits of logical units.
* Check for unnecessary whitespace with ```git diff --check``` and be sure to follow the CODINGSTYLE (more on this in the next section).
* Submit the Pull Request(PR) on Github.
* When relevant, write a test for
  [radare2-regressions](https://github.com/radare/radare2-regressions) and
  submit a PR also there. Use the same branch name in both repositories, so
  Travis will be able to use your new tests together with new changes. 
  AppVeyor (for now) still uses radare/radare2-regressions repo with branch
  master. NOTE: when merging PRs, *always* merge the radare2-regressions PR
  first.

## Coding Style guidelines

* Tabs are used for indentation. In a switch statement, the
  cases are indentend at the switch level.

```c
switch(n) {
case 1:
case 2:
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
  has to be done.  If there is no cleanup needed then just return directly.

  Choose label names which say what the goto does or why the goto exists.  An
  example of a good name could be "out_buffer:" if the goto frees "buffer".
  Avoid using GW-BASIC names like "err1:" and "err2:".

* Use early returns instead of if-else when you need to filter out some bad
  value at the start of a function.

```c
int check(RCore *c, int a, int b) {
	if (!c) return false;
	if (a < 0 || b < 1) return false;

	... /* do something else */
}
```

* Use a space after most of the keyword and around operators.

```c
a = b + 3;
a = (b << 3) * 5;
```

* Multiline ternary operator conditionals must be indented a-la JS way:

```c
- ret = over ?
-         r_debug_step_over (dbg, 1) :
-         r_debug_step (dbg, 1);
+ ret = over
+         ? r_debug_step_over (dbg, 1)
+         : r_debug_step (dbg, 1);
```

* Split long conditional expressions into small `static inline` functions to make them more readable:

```c
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

* Why return int vs enum

The reason why many places in r2land functions return int instead of an enum type is because enums cant be OR'ed because it breaks the usage within a switch statement and also because swig cant handle that stuff.

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

* Do not use C99 variable declaration
  - This way we reduce the number of local variables per function
    and it's easier to find which variables are used, where and so on.

* Always put a space before every parenthesis (function calls, conditionals,
  fors, etc, ...) except when defining the function signature. This is
  useful for grepping.

* Comments should be smart. Function names should be explicit enough
  to not require a comment to explain what it does. If this is not
  possible at all, we can still use a comment. But it is a bad idea
  to rely on comments to make the code readable.

* Use 'R_API' define to mark exportable (public) methods only for module APIs

* The rest of functions must be static, to avoid polluting the global space.

* Avoid using global variables, they are evil. Only use them for singletons
  and wip code, placing a comment explaining the reason for them to stay there.

* If you *really* need to comment out some code, use #if 0 (...) #endif. In
  general, don't comment out code because it makes the code less readable.

* Do not write ultra-large functions, split them into multiple or simplify
  the algorithm, only external-copy-pasted-not-going-to-be-maintained code
  can be accepted in this way (gnu code, external disassemblers, etc..)

* See doc/vim for vimrc

* See doc/clang-format for work-in-progress support for automated indentation

* Use the r2 types instead of the ones in stdint, which are known to cause some
  portability issues. So, instead of uint8_t, use ut8, etc..

* Never ever use %lld or %llx. This is not portable. Always use the PFMT64x
  macros. Those are similar to the ones in GLIB.

# Manage Endianness

As hackers, we need to be aware of endianness.

Endianness can become a problem when you try to process buffers or streams
of bytes and store intermediate values as integers with width larger than
a single byte.

It can seem very easy to write the following code:

  	ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
  	ut32 value = *(ut32*)opcode;

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

ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
ut32 value = opcode[0] | opcode[1] << 8 | opcode[2] << 16 | opcode[3] << 24;

or if you prefer the other endian:

ut32 value = opcode[3] | opcode[2] << 8 | opcode[1] << 16 | opcode[0] << 24;

This is much better because you actually know which endian your bytes are stored in
within the integer value, REGARDLESS of the host endian of the machine.

## Endian helper functions

Radare2 now uses helper functions to interpret all byte streams in a known endian.

Please use these at all times, eg:

  	val32 = r_read_be32(buffer)		// reads 4 bytes from a stream in BE
  	val32 = r_read_le32(buffer)		// reads 4 bytes from a stream in LE
  	val32 = r_read_ble32(buffer, isbig)	// reads 4 bytes from a stream:
  						//   if isbig is true, reads in BE
  						//   otherwise reads in LE

There are a number of helper functions for 64, 32, 16, and 8 bit reads and writes.

(Note that 8 bit reads are equivalent to casting a single byte of the buffer
to a ut8 value, ie endian is irrelevant).

# Additional resources

* [README.md](https://github.com/radare/radare2/blob/master/README.md)
* [DEVELOPERS.md](https://github.com/radare/radare2/blob/master/DEVELOPERS.md)
