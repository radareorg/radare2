# Sandboxing r2

radare2 supports sandboxing natively by wrapping all attempts
to access the filesystem, network or run programs.

But for some platforms, the kernel provides a native sandboxing
experience. ATM only OSX and OpenBSD are supported by r2, feel
free to extend the support to Linux and Windows.

## OSX

OSX Seatbelt implements a system-level sandbox for applications,
the rules are described in a lispy .sb file:

	$ sandbox-exec -f radare2.sb r2 -S /bin/ls

**NOTE**: r2 -S is an alias for -e cfg.sandbox=true


## OpenBSD (from 5.9)

OpenBSD comes with support for sandboxing using the pledge(2) syscall.

Only the following are allowed:

- stdio and tty manipulation
- filesystem reading
- mmap(2) `PROT_EXEC` manipulation

## OpenBSD (until 5.9)

OpenBSD comes with support for sandboxing using the systrace utility.

	$ man systrace

Generate default profile

	$ systrace -A r2 /bin/ls

Run with the generated profile

	$ systrace -a r2 -S /bin/ls

## FreeBSD (from 10.0)

FreeBSD comes with the Capsicum framework support,
 using cap_enter(2).

Operations limited on what basic capability mode support.

## Other

Only r2's sandbox is supported.

- disables file system access
- disables network connectivity
- disables forks (no shell escapes or debugger)
- activated before showing the prompt

	$ r2 -S /bin/ls

## Permission expressions

`cfg.sandbox.grain` and `http.sandbox.grain` accept comma-separated permission
names. Prefix a name with `!` to remove it. If the first option is negative,
evaluation starts with all permissions; otherwise it starts with none. Options
apply from left to right, and `all` or `none` resets the mask at that point.

For example, `!disk,!exec` allows everything except disk access and process
execution. `disk,files,!disk` allows only `files`, while `all,!exec` allows
everything except execution. Whitespace around options is ignored. Unknown
names and empty options are rejected without changing the current permissions.

## HTTP command sandbox

`http.sandbox=true` and `http.sandbox.grain=none` are the defaults. GET, POST
and output-free `/cmd/:` commands use the configured HTTP permissions,
intersected with any enabled local sandbox permissions. The default blocks
process execution, new sockets, network requests, filesystem access through
the sandbox wrappers, environment access and hidden paths. Commands can still
inspect and modify the loaded
analysis state. For example, set `http.sandbox.grain=environ` before starting
the server to permit environment access while keeping the other restrictions.

When started from an unsandboxed local session, HTTP also permits file access
inside `dir.projects`, captured as a canonical path at startup. Its default is
the user's XDG `radare2/projects` directory. Projects can be
listed, saved and loaded there; loading reuses the current binary and maps,
and project scripts retain the HTTP sandbox restrictions. An already enabled
local sandbox gains no additional filesystem access. This uses the existing
path-based whitelist model and cannot prevent races with another local process
replacing directories while a file is opened. The writable exception is currently
available on UNIX only.

Projects use `rc.r2` scripts by default (`prj.new=false`). Sandboxed HTTP
saves and loads use these scripts even when `prj.new=true`; the optional
`prj.bin` artifact is neither saved nor loaded in this mode.

The HTTP session's sandbox settings are fixed when the server starts. Remote
commands cannot disable them or reset the configuration. `cfg.sandbox` and
`cfg.sandbox.grain` retain their local values and are read-only in this session;
`dir.projects` is also fixed. The separate `http.sandbox` settings describe the
HTTP policy. Queuing commands
for later execution remains blocked, including when `exec` is permitted.
Restrictions apply only to the executing thread for the duration of each
command, without changing the local sandbox state, permissions, or
operating-system sandbox. Command output is captured in memory without
temporary files or redirecting process-wide stdout. Platforms
without compiler thread-local storage use operating-system thread storage.

These are permissions enforced by radare2 wrappers, not operating-system
confinement. Granting filesystem permissions retains the existing path and
symlink limitations. Grant `exec` only to trusted clients: external programs
can access resources without going through radare2's wrappers.

These permission restrictions do not synchronize access to the analysis state.
The background HTTP server (`=h&`) shares that state with the local session;
avoid concurrent analysis commands against the same core.

Set `http.sandbox=false` before starting the server only when clients should
have the local session's permissions; an enabled local sandbox still applies,
including in a background HTTP server. The HTTP sandbox is not authentication;
configure `http.bind`, `http.auth` and network access for the intended clients.
These command restrictions do not change the separate static-file and upload
endpoints.

Outside HTTP, `cfg.sandbox.grain` still defaults to `all`. Configure the desired
permissions before enabling `cfg.sandbox`; once enabled, commands can reduce
permissions but cannot grant additional ones. Operating-system sandboxes may
impose further, irreversible restrictions.
