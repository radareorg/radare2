r2r rewrite in V
================

This is the full rewrite of the r2 regressions testsuite in the V programming language.

Reasons behind using V are:

* Go-like syntax: Easy to maintain and for newcomers
* Portability: Compiles to C with no dependencies
* Speed: Just use native apis instead of spawn all the things

The current testsuite is written in NodeJS and have some issues:

* Few people write decent js code, few contributors and lot of crap
* Some lost promises happen
* Simplify the testsuite to cleanup broken or badly written tests
* Have a single entrypoint to run ALL the tests (unit, fuzz, asm, ..)
* Latest versions of NodeJS don't run on net/open/free-BSD

Pending things

* the fuzz suite
* proper error handling
* timeouts without using rarun2
* improve r2pipe.v performance

--pancake
