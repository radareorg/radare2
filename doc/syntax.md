Syntax coding style guidelines
==============================

* Tabs are used for indentation. They are 8 chars. In a switch statement, the
  cases are indentend at the switch level.

```
switch(n) {
case 1:
case 2:
default:
}
```

* Lines should be at most 78 chars

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
