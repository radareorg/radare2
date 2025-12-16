# ESIL

ESIL stands for 'Evaluable Strings Intermediate Language'. It is used to
describe in a Forth-like syntax the behaviour of every opcode.

These strings can be evaluated in order to emulate code.

Each element of an esil expression is separated by a comma. The VM can be described as this:

    while ((word = haveCommand())) {
      if (word.isKeyword()) {
        esilCommands[word](esil);
      } else {
        esil.push (evaluateToNumber(word));
      }
      nextCommand();
    }

The esil commands are operations that pop values from the stack, performs some
calculations and pushes the result in the stack (if any). They aim to cover all
common operations done by CPUs, permitting to do binary operations, memory
peeks and pokes, spawning a syscall, etc.

## Use ESIL

To display the esil expression associated with each instruction you must set this
config variable:

```
[0x00000000]> e asm.esil = true
```

Note that this information is provided by RArch, as part of the instruction details.

The `ae` command have subcommands act as a debugger, for stepping, changing registers, etc.

You can evaluate a string using this command:

```
[0x000048a0]> ""ae 1024,rax,:=
```

The double quote tells the command parser to ignore the rest of the line, it's handy
to avoid undesired effects when not escaping the `|` or `>` operators.

### Debugging ESIL

In visual mode, `V`, one can iterate through the instructions via the `s` (step) key
and see how registers are changing interactively as `;-- pc` (program counter) advances,
just like in r2's debug facilities:

```
[0x00100004 [xaDvc]0 2% 395 bin/ired_v850]> diq;?t0;f .. @ entry0+4 # 0x100004
dead at 0x00000000
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00200000  ffff ffff ffff ffff ffff ffff ffff ffff  ................
0x00200010  ffff ffff ffff ffff ffff ffff ffff ffff  ................
0x00200020  ffff ffff ffff ffff ffff ffff ffff ffff  ................
0x00200030  ffff ffff ffff ffff ffff ffff ffff ffff  ................
   zero 0x00000000       r0 0x00000000       r1 0x00000000       r2 0x00000000
     r3 0x00200000       sp 0x00200000       r4 0x00116eb8       gp 0x00116eb8
     r5 0x00000000       tp 0x00000000       r6 0x0010ef0a       r7 0x0010ef34
     r8 0x00000000       r9 0x00000000      r10 0x00000000      r11 0x00000000
    r12 0x00000000      r13 0x00000000      r14 0x00000000      r15 0x00000000
    r16 0x00000000      r17 0x00000000      r18 0x00000000      r19 0x00000000
    r20 0x000000ff      r21 0x0000ffff      r22 0x00000000      r23 0x00000000
    r24 0x00000000      r25 0x00000000      r26 0x00000000      r27 0x00000000
    r28 0x00000000      r29 0x00000000      r30 0x0010eeb8       ep 0x0010eeb8
    r31 0x00000000       lp 0x00000000       pc 0x00100032      psw 0x00000000
s:0 z:0 c:0 o:0 p:0
            0x00100004      00a8           mov r0,  r21                ; r0,r21,=
            0x00100006      80aeffff       ori 65535,  r0,  r21        ; 65535,r0,|,r21,=
            0x0010000a      401e2000       movhi 32,  r0,  sp          ; 16,32,<<,r0,+,sp,=
            0x0010000e      231e0000       movea 0,  sp,  sp           ; 0,sp,+,sp,=
            0x00100012      40f61100       movhi 17,  r0,  ep          ; 16,17,<<,r0,+,ep,=
            0x00100016      3ef6b8ee       movea -4424,  ep,  ep       ; -4424,ep,+,ep,=
            0x0010001a      40261100       movhi 17,  r0,  gp          ; 16,17,<<,r0,+,gp,=
            0x0010001e      2426b86e       movea 28344,  gp,  gp       ; 28344,gp,+,gp,=
            0x00100022      40361100       movhi 17,  r0,  r6          ; 16,17,<<,r0,+,r6,=
            0x00100026      2636c0ee       movea -4416,  r6,  r6       ; -4416,r6,+,r6,=
            0x0010002a      403e1100       movhi 17,  r0,  r7          ; 16,17,<<,r0,+,r7,=
            0x0010002e      273e34ef       movea -4300,  r7,  r7       ; -4300,r7,+,r7,=
            ;-- pc:
        ┌─> 0x00100032      46070000       st.b r0,  0[r6]             ; r0,0,r6,+,=[4]
        ╎   0x00100036      06360100       addi 1,  r6,  r6            ; 1,r6,+,r6,=
        ╎   0x0010003a      e731           cmp r7,  r6                 ; r7,r6,==,$z,z,:=,$s,s,:=,$c,c,:=
        └─< 0x0010003c      b1fd           bl 0x100032                 ; 0x100032,PC,=
            0x0010003e      80ff666f       jarl sym.___main,  lp       ;[1] ; PC,lp,=,0x106fa4,PC,=
            0x00100042      031ef0ff       addi -16,  sp,  sp          ; -16,sp,+,sp,=
```

There's also an ESIL expression debugger which can be accessed via the `aev` command

## Syntax

An opcode is translated into a comma separated list of ESIL expressions.

    xor eax, eax    ->    0,eax,=,1,zf,=

Memory access is defined by brackets.

    mov eax, [0x80480]   ->   0x80480,[4],eax,=

Default size is the destination of the operation. In this case 8bits, aka 1 byte.

    movb $0, 0x80480     ->   0,0x80480,=[1]

Conditionals are expressed with the '?' char at the beginning of the expression. This checks if the rest of the expression is 0 or not and skips the next expression if doesn't matches. `$` is the prefix for internal vars.

    cmp eax, 123  ->   123,eax,==,$z,zf,=
    jz eax        ->   zf,?{,eax,eip,=,}

So.. if you want to run more than one expression under a conditional, you'll have to write it

    zf,?{,eip,esp,=[],eax,eip,=,$r,esp,-=,}


The whitespace, newlines and other chars are ignored in esil, so the first thing to do is:

    esil = r_str_replace (esil, " ", "", true);

Syscalls are specially handled by '$' at the beginning of the expression. After that char you have an optional numeric value that specifies the number of syscall. The emulator must handle those expressions and 'simulate' the syscalls. (`r_esil_syscall`)

## Order of arguments

As discussed on irc, current implementation works like this:

    a,b,-      b - a
    a,b,/=     b /= a

This approach is more readable, but it's less stack-friendly

# Special instructions

NOPs are represented as empty strings. Unknown or invalid instructions

Syscalls are implemented with the '0x80,$' command. It delegates the execution
of the esil vm into a callback that implements the syscall for a specific
kernel.

Traps are implemented with the `<trap>,<code>,$$` command. They are used to
throw exceptions like invalid instructions, division by zero, memory read
error, etc.

# Quick analysis

Here's a list of some quick checks to retrieve information from an esil string.
Relevant information will be probably found in the first expression of the
list.

    indexOf('[')       ->    have memory references
    indexOf("=[")      ->    write in memory
    indexOf("pc,=")    ->    modifies program counter (branch, jump, call)
    indexOf("sp,=")    ->    modifies the stack (what if we found sp+= or sp-=?)
    indexOf("=")       ->    retrieve src and dst
    indexOf(":")       ->    unknown esil, raw opcode ahead
    indexOf("$")       ->    accesses internal esil vm flags
    indexOf("$")       ->    syscall
    indexOf("$$")      ->    can trap
    indexOf('++')      ->    has iterator
    indexOf('--')      ->    count to zero
    indexOf("?{")      ->    conditional
    indexOf("LOOP")    ->    is a loop (rep?)
    equalsTo("")       ->    empty string, means: nop (wrong, if we append pc+=x)

## Common operations:

 * Check dstreg
 * Check srcreg
 * Get destination
 * Is jump
 * Is conditional
 * Evulate
 * Is syscall

# CPU Flags

CPU flags are usually defined as 1 bit registers in the RReg profile. and sometimes under the 'flg' register type.

# ESIL Flags

ESIL VM have an internal state flags that can are read only and can be used to
export those values to the underlying CPU flags. This is because the ESIL vm
defines all the flag changes, while the CPUs only update the flags under
certain conditions or specific instructions.

Those internal flags are prefixed by the '$' character.

```
z - zero flag, only set if the result of an operation is 0
b - borrow, this requires to specify from which bit (example: $b4 - checks if borrow from bit 4)
c - carry, same like above (example: $c7 - checks if carry from bit 7)
p - parity
r - regsize ( asm.bits/8 )
```

# Variables

1. No predefined bitness (should be easy to extend them to 128,256 and 512bits, e.g. for MMX, SSE, AVX, Neon)
2. Infinite number (for SSA-form compatibility)
3. Register names have no specific syntax. They are just strings
4. Numbers can be specified in any base supported by RNum (dec, hex, oct, binary ...)
5. Each ESIL backend should have an associated RReg profile to describe the esil register specs

# Bitarrays

What to do with them? What about bit arithmetic if use variables instead of registers?

# Arithmetic

1. ADD ("+")
2. MUL ("*")
3. SUB ("-")
4. DIV ("/")
5. MOD ("%")


# Bit arithmetic

1. AND  "&"
2. OR   "|"
3. XOR  "^"
4. LSL  "LSL" (alias: "<<")
5. LSR  "LSR" (alias: ">>")
6. ASR  "ASR"
7. ROL  "ROL"
8. ROR  "ROR"
9. NEG  "!"

# Floating point

_TODO_

## The x86 REP prefix in ESIL

ESIL specifies that the parsing control-flow commands are in uppercase. Bear in
mind that some archs have uppercase register names. The register profile should
take care to not reuse any of the following:

	3,GOTO   - goto instruction 3
	LOOP     - alias for 0,GOTO
	BREAK    - stop evaluating the expression
	STACK    - dump stack contents to screen
	CLEAR    - clear stack


Usage example:

### rep cmpsb

```
ecx,!,?{,BREAK,},edi,[1],esi,[1],==,$z,zf,:=,8,$b,cf,:=,$p,pf,:=,7,$s,sf,:=,edi,[1],0x80,-,!,7,$o,^,of,:=,3,$b,af,:=,df,?{,1,edi,-=,1,esi,-=,}{,1,edi,+=,1,esi,+=,},ecx,--=,zf,!,?{,BREAK,},0,GOTO
```

## Executing r2 commands


## Unimplemented/unhandled instructions

Those are expressed with the 'TODO' command. which acts as a 'BREAK', but
displaying a warning message describing which instruction is not implemented
and will not be emulated.

For example:

	fmulp ST(1), ST(0)      =>      TODO,fmulp ST(1),ST(0)

## Disassembly example:

```
[0x1000010f8]> e asm.esil=true
[0x1000010f8]> pd $r @ entry0
   ;      [0] va=0x1000010f8 pa=0x000010f8 sz=13299 vsz=13299 rwx=-r-x 0.__text
            ;-- section.0.__text:
            0x1000010f8    55           8,rsp,-=,rbp,rsp,=[8]
            0x1000010f9    4889e5       rsp,rbp,=
            0x1000010fc    4883c768     104,rdi,+=
            0x100001100    4883c668     104,rsi,+=
            0x100001104    5d           rsp,[8],rbp,=,8,rsp,+=                                          ┌─< 0x100001105    e950350000   0x465a,rip,= ;[1]
        │   0x10000110a    55           8,rsp,-=,rbp,rsp,=[8]
        │   0x10000110b    4889e5       rsp,rbp,=                                                       │   0x10000110e    488d4668     rsi,104,+,rax,=
        │   0x100001112    488d7768     rdi,104,+,rsi,=
        │   0x100001116    4889c7       rax,rdi,=
        │   0x100001119    5d           rsp,[8],rbp,=,8,rsp,+=                                         ┌──< 0x10000111a    e93b350000   0x465a,rip,= ;[1]
       ││   0x10000111f    55           8,rsp,-=,rbp,rsp,=[8]
       ││   0x100001120    4889e5       rsp,rbp,=
       ││   0x100001123    488b4f60     rdi,96,+,[8],rcx,=
       ││   0x100001127    4c8b4130     rcx,48,+,[8],r8,=                                              ││   0x10000112b    488b5660     rsi,96,+,[8],rdx,=
       ││   0x10000112f    b801000000   1,eax,= ;  0x00000001
       ││   0x100001134    4c394230     rdx,48,+,[8],r8,==,cz,?=
      ┌───< 0x100001138    7f1a         sf,of,!,^,zf,!,&,?{,0x1154,rip,=,} ;[2]
     ┌────< 0x10000113a    7d07         of,!,sf,^,?{,0x1143,rip,} ;[3]
     ││││   0x10000113c    b8ffffffff   0xffffffff,eax,= ;  0xffffffff                              ┌─────< 0x100001141    eb11         0x1154,rip,= ;[2]
    │└────> 0x100001143    488b4938     rcx,56,+,[8],rcx,=
    │ │││   0x100001147    48394a38     rdx,56,+,[8],rcx,==,cz,?=
```

# Radare anal ESIL code example

As an example implementation of ESIL analysis for the AVR family of
microcontrollers there is a `avr_op` function in `/libr/arch/p/avr/plugin.c`
which contains information on how the instructions are expressed in ESIL and
other opcode information such as cycle counts per instruction:

````
static int avr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
  short ofst;
    int d, r, k;
    (...)
````

Variables d, r and k refer to "destination", "register" and "(k)onstant", respectively. They
are used later on by ESIL string formatting function like for instance:

    r_strbuf_setf (&op->esil, "0x%x,r%d,=", k, d);

Which in this case corresponds to the LDI (LoaD with immediate) instruction in
AVR. As an example, the above ESIL string template will translate into the
following when reversing in radare:

    0x00000080      30e0           0x0,r19,=                   ; LDI Rd,K. load immediate

Or in non-ESIL format:

    0x00000080      30e0           ldi r19, 0x00               ; LDI Rd,K. load immediate


Looking at other architectures which already have mature ESIL support such as
x86 can help in understanding the syntax and conventions of radare's ESIL.


# Introspection

To ease esil parsing we should have a way to express introspection expressions
to extract the data we want. For example. We want to get the target address of
a jmp.

The parser for the esil expressions should be implemented in an API to make it
possible to extract information by analyzing the expressions easily.

  >  ao~esil,opcode
  opcode: jmp 0x10000465a
  esil: 0x10000465a,rip,=

We need a way to retrieve the numeric value of 'rip'. This is a very simple
example, but there will be more complex, like conditional ones and we need
expressions to get:

- opcode type
- destination of jump
- condition depends on
- all regs modified (write)
- all regs accessed (read)

# API HOOKS

It is important for emulation to be able to setup hooks in the parser, so we
can extend the parser to implement the analysis without having to write the
parser again and again. This is, every time an operation is going to be
executed we call a user hook which can be used to determine if rip is changing
or if the instruction updates the stack.

Later, at this level we can split that callback into several ones to have an
event based analysis api that may be extended in js like this:

	esil.on('regset', function(){..
	esil.on('syscall', function(){esil.regset('rip'

we have already them. see `hook_flag_read()` `hook_execute()` `hook_mem_read()` ...

* return true if you want to override the action taken for a callback. for
  example. avoid mem reads in a region or mem writes to make all memory read
  only.
* return false or 0 if you want to trace esil expression parsing. aka emulation ..

Other operations that require bindings to external functionalities to work. In
this case `r_ref` and `r_io`. This must be defined when initializing the esil vm.

* Io Get/Set

      Out ax, 44
      44,ax,:ou

* Selectors (cs,ds,gs...)

      Mov eax, ds:[ebp+8]
      Ebp,8,+,:ds,eax,=
