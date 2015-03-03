Sandboxing r2
=============

OSX:

	OSX Seatbelt implements a system-level sandbox for applications,
	it's rules are defined in lispy .sb file:

	sandbox-exec -f radare2.sb r2 -S /bin/ls

	NOTE: r2 -S is an alias for -e cfg.sandbox=true


OpenBSD:

	$ man systrace

	Generate default profile

		$ systrace -A r2 /bin/ls

	Run with the generated profile

		$ systrace -a r2 -S /bin/ls

Windows:
Linux:
	Only r2's sandbox is supported.
	- disables file system access
	- disables network connectivity
	- disables forks (no shell escapes or debugger)
	- activated before showing the prompt

	$ r2 -S /bin/ls
