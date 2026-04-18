Example .r programs for the r_egg compiler (ragg2)
===================================================

These are short, self contained .r programs that showcase the syntax
accepted by ragg2. They are intended as both documentation and as a
quick sandbox for experimenting with the compiler.

Each file can be compiled with:

    ragg2 -a <arch> -b <bits> -k <os> -s FILE.r

Useful backends for experimenting:

    -a trace           pseudo-assembly that mirrors the IR the parser
                       emits (great for understanding the compiler)
    -a esil            stack based intermediate language, readable
                       and directly consumable by the r2 ESIL VM
    -a x86 -b 32/64    native x86 / x86-64 assembly
    -a arm -b 32/64    native ARM / AArch64 assembly

Files
-----

- hi.r              smallest possible "write then exit" program
- hello.r           loop that repeatedly writes "Hello World"
- exit.r            raw inline assembly mixed with the high-level language
- write.r           syscall declarations with string literals
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

    ragg2 -a esil  -s t/hi.r
    ragg2 -a trace -s t/arith.r
    ragg2 -a x86 -b 64 -s t/regs.r
