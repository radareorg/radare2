Releasing rules
=======================

The objective of this paper is to determine a set of rules to be done before
each release and define the instructions for generating the distribution
tarball together with a scheduler.

* We try to release every 1/2 months
* Version numbering (actually we dont follow any rules for this)
* Codenames for releases MUST be funny (until we didnt get a name that can make
  me laugh, we should not release anything!)

Before any release we have to:

 - Remove warnings

   We dont want to fall in the warning nightmare of r1. Releases should contain
   no warnings with `gcc -Wall` or at least no dangerous ones.

 - Sync Vala APIs

   Keeping the VAPI files the last ones to be developed between release cycles
   we ensure that we do not have to maintain synced the code with the vapis
   and it is possible to easily draw the LIBR API evolution by just diffing
   the vapi directory.

 - Unit test programs

   If available, it would be good to have some unit tests to check nothing is
   broken. Maybe Vala is the way to go when writing tests, because this way
   we ensure that pkg-config, libr and vapis works in a shot.

 - Test build on different platforms

   The same codebase should be compilable on *nix and w32 systems without
   modifications. It should be also possible to build it with make threads,
   so using quadcore boxes with `-j8` should be a good place for finding
   race conditions in the build system.

 - Remove commented code and review TODO/BUG/XXX comments

   While developing a new release, it's pretty common to keep old versions of
   the code for testing parts of libraries and be able to go back or find bugs
   while refactoring code or re-doing-it from scratch. This code, should be
   reviewed and removed if necessary.

       $ grep -r -e TODO -e XXX -e FIX libr

 - Graph per symbol-module dependency graph to identify unused/dupped/-
   simplificable use cases of the API for every module.

FUTURE
------

 - Commands should be handled in a structural way, not by a bunch of switch/cases
