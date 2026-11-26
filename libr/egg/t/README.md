Example .r programs for the r_egg compiler (ragg2)
===================================================

These are short, self contained .r programs that showcase the syntax
accepted by ragg2. They are intended as both documentation and as a
quick sandbox for experimenting with the compiler.

Most files can be compiled with:

    ragg2 -a <arch> -b <bits> -k <os> -s FILE.r

Useful backends for experimenting:

    -a trace           pseudo-assembly that mirrors the IR the parser
                       emits (great for understanding the compiler)
    -a esil            stack based intermediate language, readable
                       and directly consumable by the r2 ESIL VM
    -a llvm            textual LLVM IR for Clang
    -a x86 -b 32/64    native x86 / x86-64 assembly
    -a arm -b 32/64    native ARM / AArch64 assembly

Files
-----

- hello-linux-x64.r  loop that writes "Hello World" using Linux x86-64 syscalls
- hello-darwin-arm64.r  macOS arm64 hello world using Darwin syscalls
- hello-llvm.r      native hello world linked with the C runtime by Clang
- fib.r            first seven Fibonacci numbers with native or libc I/O
- exit.r            inline assembly for the Linux i386 exit syscall
- arith.r           arithmetic expressions and operator precedence
- regs.r            direct native-register access via the `.regname` syntax
- alias.r           register aliases defined with the `@alias` directive
- cond.r            conditional statements: if, if/else style, while
- customsyscall.r   overriding the `@syscall` body with inline asm

Language cheat sheet
--------------------

    /* comment */  //comment    #comment
    : raw asm line                   ; any line starting with ":" is passed
                                      through verbatim to the assembler

    name@global(S,F) { body }        ; function with S byte stackframe
                                      and F bytes reserved for constants
    name@syscall(N);                 ; declare name as a syscall number
    name@syscall(write);             ; resolve a syscall name for the native target
    file.r@include("");              ; load relative to this file or the include path
    name@alias(value)                ; textual alias: .name -> value
    name@fastcall(addr)              ; call a function at addr via fastcall
    @syscall() { body }              ; override the generated syscall body

    .var0, .var4, .varN              ; local variables at frame offset N
    .arg0, .arg4                     ; function arguments
    .ret                             ; return register (retvar)
    .regN                            ; generic register by index
    .%rax, .%ecx, .%x0, ...          ; raw native register (verbatim)
    .foo (after foo@alias(...))      ; alias-resolved register/symbol
    (any other .name raises an error)

    var = expr                       ; assignment
    var += expr, -=, *=, /=          ; compound assignment
    var = *addr                      ; dereference (read)
    fn(arg1, arg2, ...)              ; function / syscall call

Example compile and inspect
---------------------------

    ragg2 -a esil  -s t/hello-linux-x64.r
    ragg2 -a trace -s t/arith.r
    ragg2 -a x86 -b 64 -s t/regs.r

Run the Fibonacci example from the repository root
--------------------------------------------------

`fib.r` includes `io/libc64/io.r` relative to its source file. The header uses
`#if LLVM` to select libc imports for `read(fd, buf, count)`,
`write(fd, buf, count)`, and `exit(status)`. The `#else` branch uses named
syscalls and the native target's return conventions. The program writes
`0`, `1`, `1`, `2`, `3`, `5`, and `8` on separate lines.

On macOS ARM64, run with native Darwin syscalls.

```sh
ragg2 -x libr/egg/t/fib.r
```

Build a standalone Mach-O executable with `-F`.

```sh
ragg2 -F -o fib libr/egg/t/fib.r
./fib
```

On a 64-bit macOS or Linux host, generate LLVM IR and link with Clang.

```sh
ragg2 -a llvm -o fib.ll libr/egg/t/fib.r
clang -Wno-override-module fib.ll -o fib
./fib
```

Build and run the LLVM example from the repository root
-------------------------------------------------------

```sh
ragg2 -a llvm -o hello.ll libr/egg/t/hello-llvm.r
clang -Wno-override-module hello.ll -o hello
./hello
```

Clang selects the target and links the C runtime. Use `clang --target=TRIPLE`
with a toolchain and libraries for that target to cross-link the same IR.

An external call needs a declaration before its first use. In
`puts@extern(i32, ptr);`, the first type is the return type and the remaining
types are the fixed argument types. The supported types are `i32`, `i64`,
`ptr`, and `void` for a return value. Use `main@global()` to define the program
entry point and a final `0;` for a successful exit status.

RCC functions use 64-bit values and refer to parameters by index starting
with `.arg0`. Each `.varN` identifies an independent slot. Locals and string
literals are allocated by the backend. The LLVM backend supports arithmetic,
direct calls, `if` and `else`, and `while`. Using native registers as RCC
variables and overriding the `@syscall()` body require a native backend.

For `name@syscall(N)`, LLVM passes the literal number `N` to the target's
libc `syscall()` on Linux and macOS. Match the numbers to the target OS and
architecture, and use `-k` and `-b` to select its libc calling convention.
With neither option, `ragg2` uses the host OS and bit width. These defaults
apply to the Darwin example on macOS arm64.

```sh
ragg2 -a llvm -o hello.ll libr/egg/t/hello-darwin-arm64.r
clang -Wno-override-module hello.ll -o hello
./hello
```

On Linux x86-64, use `hello-linux-x64.r` instead. Use the `@extern` example
for portable C runtime calls across targets with different syscall numbers.

Consecutive `:` lines inside a function are assembled together with the same
assembler as `rasm2` and emitted as LLVM `.byte` directives. The assembler
defaults to the host architecture. Pass `-c llvm.asm.arch=x86 -b 32` for an
i386 block and select `i386-linux-gnu` in Clang.

```sh
ragg2 -a llvm -k linux -c llvm.asm.arch=x86 -b 32 -o exit.ll libr/egg/t/exit.r
clang -Wno-override-module --target=i386-linux-gnu -c exit.ll -o exit.o
```

Assembly blocks use block-local labels and need to preserve the stack pointer,
frame pointer, and registers outside the emitted clobber list. They
cannot reference the compiler's RCC variables by name.

From the library, select `"llvm"` in `r_egg_setup()`, load the RCC source,
call `r_egg_compile()`, and read the text using `r_egg_get_assembly()`.
