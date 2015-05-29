Sandboxing r2
=============

radare2 supports sandboxing natively by wrapping all attempts
to access the filesystem, network or run programs.

But for some platforms, the kernel provides a native sandboxing
experience. ATM only OSX and OpenBSD are supported by r2, feel
free to extend the support to Linux and Windows.

OSX
---

OSX Seatbelt implements a system-level sandbox for applications,
the rules are described in a lispy .sb file:

	$ sandbox-exec -f radare2.sb r2 -S /bin/ls

**NOTE**: r2 -S is an alias for -e cfg.sandbox=true


OpenBSD
-------

OpenBSD comes with support for sandboxing using the systrace utility.

	$ man systrace

Generate default profile

	$ systrace -A r2 /bin/ls

Run with the generated profile

	$ systrace -a r2 -S /bin/ls

Other
-----

Only r2's sandbox is supported.

- disables file system access
- disables network connectivity
- disables forks (no shell escapes or debugger)
- activated before showing the prompt

	$ r2 -S /bin/ls
