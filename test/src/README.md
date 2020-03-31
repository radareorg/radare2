r2r rewrite in V
================

This is the full rewrite of the r2 regressions testsuite in the V programming language.

Reasons behind using V are:

* Go-like syntax: Easy to maintain and for newcomers
* Portability: Compiles to C with no dependencies
* Speed: Just use native apis instead of spawn all the things

The current testsuite is written in NodeJS and have some issues:

* Hard to architect structured js, ts helps, but its just layers on layers
* Some lost promises happen in travis which are hard to debug
* Simplify the testsuite to cleanup broken or badly written tests
* Have a single entrypoint to run ALL the tests (unit, fuzz, asm, ..)
* Latest versions of NodeJS don't run on net/open/free-BSD

Things to be done:

* Implement the interactive mode to fix failing tests
* Clone+build V if not in the $PATH

Stuff to improve:

* Proper error handling
* Timeouts without using rarun2
* Improve r2pipe.v performance

--pancake
