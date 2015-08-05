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

* Lines should be at most 80 chars

* Braces open on the same line as the for/while/if/else/function/etc. Closing
  braces are put on a line of its own, except in the else of an if statement or
  in a while of a do-while statement. If you have a one line statement, don't
  use braces (except for do-while).

```
if (a == b) {
	...
}

if (a == b) {
	...
} else if (a > b) {
	...
}

if (a == b)
	do_something ();

if (a == b)
	do_something ();
else
	do_something_else ();

if (a == b) {
	...
} else {
	do_something_else ();
}

do {
	do_something ();
} while (cond);
```

* Use a space after most of the keyword and around operators.

```
a = b + 3;
a = (b << 3) * 5;
```

* Do not leave trailing whitespaces at the end of line

* Before sending a patch, run clang-format using the style provided in
  doc/clang-format

* Do not use C99 variable declaration
  - This way we reduce the number of local variables per function
    and it's easier to find which variables are used, where and so on.

* Comments should be smart. Function names should be enought explicit
  to not require a comment to explain what it does. If this is not
  possible at all, we can still use a comment. But it is a bad idea
  to relay on comment to make the code readable.

* Use 'R_API' define to mark exportable methods

* Try not using oneline comments '//'. Use /* */ instead
* If you *really* need to comment out some code, use #if 0 (...) #endif. In
  general, don't comment out code because it makes the code less readable.

* Do not write ultra-large functions, split them into multiple or simplify
  the algorithm, only external-copy-pasted-not-going-to-be-maintained code
  can be accepted in this way (gnu code, external disassemblers, etc..)

* See doc/vim for vimrc
