```
 ___  __  ___  __ ___  ___   ____
| _ \/  \|   \/  \ _ \/ _ \ (__  \
|   (  - | |  ) - |  (   _/ /  __/
|_\__|_|_|___/__|_|_\_|___| |____|

      https://www.radare.org

                        --pancake
```

# Usage

All r2 tools and commands support printing the output in different formats by
appending a character at the end or using the `-r` (\*r2) and `-j` (json)
flags.

### radare2

```
r2 -       # same as r2 malloc://4096; "the playground"
r2 /bin/ls # standard way to run r2
r2 -w ls   # open in read-write
r2 -d ls   # start debugging the ls in PATH
```

### rasm2

```
rasm2 -L                 # list all supported assembler/disassembler/emulator plugins
rasm2 -a arm -b 64 'nop' # assemble a nop in 64-bit ARM
rasm2 -d 90              # disassemble 0x90; nop, if you're using x86
```

### rabin2

```
rabin2 -s /bin/ls # list symbols in a binary
rabin2 -z /bin/ls # find strings
```

### rax2
```
rax2 '10+0x20' # compute the result
rax2 -k 10+32  # keep the same base as input (10)
rax2 -h        # convert between (hex, octal, decimal.. bases)
```

### Other tools

Check out the [manpages](https://github.com/radareorg/radare2/blob/master/man)
and help messages for more information.

## Scripting

There are native API bindings available for many programming languages,
but it is recommended to use [r2pipe](https://github.com/radareorg/radare2-r2pipe) which is a simple interface to
execute r2 commands and get the output in result. Appending a `j` in the
commands the output will be in JSON, so it can be parsed with `.cmdj()`

Some of the languages supported by r2 are: Python, Ruby, JavaScript,
Lua, Perl, PHP, V, Go, Rust, Swift, C#, Java, Shell, OCaml, Haskell,
Scheme (Guile), Common Lisp, Clojure, Erlang, D, Vala/Genie, Prolog,
Nim, Newlisp...

```python
import r2pipe
r2 = r2pipe.open("/bin/ls")
print(r2.cmd("pd 10"))
r2.quit()
```
