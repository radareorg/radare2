Radare2 Regression Test Suite
=============================

A set of regression tests for Radare2 (http://radare.org).

Originally based on work by and now in collaboration with pancake.

Directory Hierarchy
-------------------

 * t.anal/:      Test scripts covering code analysis within radare2
 * t.asm/:       Test scripts covering assembly within radare2
 * t.esil/:      Test scripts covering use of ESIL within radare2
 * t.formats/:   Test scripts covering detection of binaries within radare2
 * t.archos/:    Platform specific test scripts
 * t/:           Test scripts (presently uncategorised)
 * unit/:        Unit tests (written in C, using minunit).
 * bins/:        Sample binaries.
 * test.sh:      Test driver script sourced by tests (not to be run manually).
 * run_tests.sh: Run tests for the core features.
 * run_unit.sh:  Run unit tests for the library functions.

Requirements
------------

 * Radare2 installed (and in $PATH or set the R2 environment).
 * Valgrind (optional).

Usage
-----

 * Run './run_tests.sh' in the top level directory to run the core tests
   (alternatively you can use 'make').
 * To run *all* tests, use 'make all'.
 * To run individual tests, type 'cd t; ./testname'.
 * To remove old test results run 'make clean'.

Options
-------

The following options can be passed to run_tests.sh or the individual tests
(environment variables).

 * To run tests with valgrind, use 'VALGRIND=1'.
 * To get verbose output, use 'VERBOSE=1' (always enabled for individual
   tests).

Failure Levels
--------------

A test can have one of the following results:
* success: The test passed, and that was expected.
* fixed: The test passed, but failure was expeced.
* broken: Failure was expected, and happened.
* failed: The test failed unexpectedly. This is a regression.

Exit code
---------

run_tests.sh exits with the following exit codes:

* 0: all tests passed
* 1: at least one essential test failed
* 2: no essential tests, but at least one regular one failed

Reporting Radare2 Bugs
----------------------

Please to not post Radare2 bugs on the r2-regressions github tracker. Instead
use the official r2 tracker:

https://github.com/radare/radare2/issues?state=open

Writing test cases
------------------

Test cases are simple shell scripts (POSIX compliant) and either run by
run_tests.sh or manually in t/.

The following variables are available:

 * NAME (string, recommend):       radare2 command being tested (e.g. px).
 * FILE (path, optional):          File argument for radare2 (defaults to '-')
 * ARGS (string, optional):        Additional arguments for radare2. If not
                                   present no additional arguments are used.
 * CMDS (string, required):        Commands to run,  one per line. Just like
                                   in interactive mode.
 * EXPECT (string, required):      Expected stdout output.
 * EXPECT_ERR (string, optional):  Expected stderr output.
 * IGNORE_ERR (boolean, optional): Ignore stderr output.
 * FILTER (string, optional):      Filter program (like grep or sed) to filter
                                   radare2's output before comparing it with
                                   EXPECT. Useful to fix random output to
                                   generate stable tests.
 * BROKEN (boolean, optional):     This tests documents a bug which is not yet
                                   fixed.
 * ESSENTIAL (boolean, optional):  A failure of this test is treated as fatal.
 * EXITCODE (number, optional):    Check the exit code of radare2 matches.
                                   Can be used to check handling of invalid
                                   arguments.

In this case, "boolean" means 1 for "true" or nothing for "false". Not setting
the variable has the same effect as setting it to an empty value.

All uppercase variable names are reserved for the test system.

The following functions are available:

 * run_test(): Run the test with the variables. Can be called multiple times
               in one test file.

The test files should be named according to the following convention:

 * cmd_*: For each command (see libr/core/cmd.c).
 * feat_*: For features not tied to a single command, like grep or
           redirection.
 * file_*: For each supported file format.

Advices
------------------

* Never use shell pipes, use `~`
* dont use `pd` if not necessary, use `pi`


License
-------

The test files are licensed under GPL 3 (or later).
