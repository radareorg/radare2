
# ptrace-wrap

ptrace on Linux has one major issue: When one process attaches to another, the tracer's pid is
associated to the tracee's pid.
However, because different threads in the tracer have different tids, which are actually just
pids on Linux, only the one thread that started the trace can continue to call ptrace for
the tracee.

This small library solves this issue by providing a thin wrapper around ptrace, executing
all ptrace calls on a single thread.
Thus, it is possible to create multi-threaded applications that use ptrace.

## Usage

Initialize a ptrace-wrap instance:

```
ptrace_wrap_instance inst;
int r = ptrace_wrap_instance_start (&inst);
if (r != 0) {
    // fail
}
```

Then, simply use the `ptrace_wrap()` function instead of `ptrace()` for your calls.

```
long pr = ptrace_wrap (&inst, <request>, <pid>, <addr>, <data>);
if (pr < 0) {
    perror ("ptrace");
}
```

If a child process should be spawned with `fork()` and traced by calling `PTRACE_TRACEME`
from inside of it, `ptrace_wrap_fork()` has to be used instead of plain `fork()`.
The behaviour in the child process is slightly different then. Instead of returning 0,
`ptrace_wrap_fork()` calls a callback in the child process. Example:

```
void child_callback(void *user) {
    const char *file = user;
    ptrace (PTRACE_TRACEME, 0, NULL, NULL);
    execl (file, file, NULL);
    perror ("execl");
    exit (1);
}

// ...

pid_t pid = ptrace_wrap_fork (&inst, child_callback, "<path to an executable>");
if (pid < 0) {
    perror ("fork");
}
```

Finally, stop the ptrace-wrap instance:
```
ptrace_wrap_instance_stop (&inst);
```

Please note that ptrace-wrap is **absolutely not thread-safe**!
It is only a solution for specific the pid/tid issue of ptrace.
If you need thread-safety, you must synchronize the access yourself.

## About

Created by Florian Märkl for [radare2](https://github.com/radare/radare2) and [Cutter](https://github.com/radareorg/cutter/).

```
ptrace-wrap is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptrace-wrap is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with ptrace-wrap.  If not, see <http://www.gnu.org/licenses/>.
```