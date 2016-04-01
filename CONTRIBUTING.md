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
* Makes commits of logical units.
* Check for unnecessary whitespace with ```git diff --check``` and be sure to follow the CODINGSTYLE (more on this in the next section).
* Submit the Pull Request(PR) on Github.
* When relevant, write a test for [radare2-regressions](https://github.com/radare/radare2-regressions) and submit a PR also there.

## Coding Style guidelines

* Tabs are used for indentation. In a switch statement, the
  cases are indentend at the switch level.

```
switch(n) {
case 1:
case 2:
default:
}
```

* Lines should be at most 78 chars. A tab is considered as 8 chars.

* Braces open on the same line as the for/while/if/else/function/etc. Closing
  braces are put on a line of their own, except in the else of an if statement
  or in a while of a do-while statement. Always use braces for if and while,
  except when the expressions are very simple and they can fit in a one-line.

```
if (a == b) {
	...
}

if (a == b) {
	...
} else if (a > b) {
	...
}

if (a == b) do_something ();

if (a == b) do_something ();
else do_something_else ();

if (!ok) return R_FALSE;

if (!buf) goto err_buf;

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

```
int check(RCore *c, int a, int b) {
	if (!c) return R_FALSE;
	if (a < 0 || b < 1) return R_FALSE;

	... /* do something else */
}
```

* Use a space after most of the keyword and around operators.

```
a = b + 3;
a = (b << 3) * 5;
```

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
  to relay on comment to make the code readable.

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

# Additional resources

* [README.md](https://github.com/radare/radare2/blob/master/README.md)
* [DEVELOPERS.md](https://github.com/radare/radare2/blob/master/DEVELOPERS.md)
