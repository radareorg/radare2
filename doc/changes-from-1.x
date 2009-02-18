Changes from radare 1.x
=======================

There are some changes between 1.x and 2.x branches, they are
obviously structurally completely different. But in essence
the user interface has been keeped as much as similar but
some changes have been done to fit better the new possibilities
of the refactor.

List of things that has changed:

- Debugger interface is no longer depending on the io layer

  Now, r_core ships the 'd' command that stands for 'debug'.
  'ds' for step, 'db' for breakpoint, 'dr' for registers...

- Everything is a module

  As we have splitted all the basic elements into libraries and
  all the extensions for each module as plugins we can either
  extend the program and allow any module directly interact
  with each other. This fixes the limitation of symbol visibilty
  between plugins allowing for example to use libr-py from inside
  the core reusing the already loaded libraries in memory.

- Source address is now accessible from lot of commands

  To speed up the execution of some commands that dont need to
  read memory to get a source address they now receive an
  optional argument to specify the offset. Here's a simple
  example: "f foo @ 0x300" can be now expressed as "f foo 0x300"
