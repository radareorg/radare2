ESIL
====

# source https://github.com/radare/radare2/wiki/ESIL

ESIL stands for 'Evaluable Strings Intermedate Language'. It aims to describe a
Forth-like representation for every opcode. Those representations can be
evaluated in order to emulate code. Each element of an esil expression is
separated by a comma. The VM can be described as this:

    while ((word=haveCommand())) {
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

#### Use ESIL

    [0x00000000]> e asm.esil = true

Syntax
======
An opcode is translated into a comma separated list of ESIL expressions.

    xor eax, eax    ->    0,eax,=,1,zf,=

Memory access is defined by brackets.

    mov eax, [0x80480]   ->   0x80480,[],eax,=

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

Order of arguments
==================
As discussed on irc, current implementation works like this:

    a,b,-      b - a
    a,b,/=     b /= a

This approach is more readable, but it's less stack-friendly

Special instructions
====================

NOPs are represented as empty strings. Unknown or invalid instructions

Syscalls are implemented with the '0x80,$' command. It delegates the execution
of the esil vm into a callback that implements the syscall for a specific
kernel.

Traps are implemented with the `<trap>,<code>,$$` command. They are used to
throw exceptions like invalid instructions, division by zero, memory read
error, etc.

Quick analysis
==============

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

Common operations:

 * Check dstreg
 * Check srcreg
 * Get destinaion
 * Is jump
 * Is conditional
 * Evulate
 * Is syscall

CPU Flags
=========

CPU flags are usually defined as 1 bit registers in the RReg profile. and sometimes under the 'flg' register type.

ESIL Flags
==========

ESIL VM have an internal state flags that can are read only and can be used to
export those values to the underlaying CPU flags. This is because the ESIL vm
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

Variables
=========

1. No predefined bitness (should be easy to extend them to 128,256 and 512bits, e.g. for MMX, SSE, AVX, Neon)
2. Infinite number (for SSA-form compatibility)
3. Register names have no specific syntax. They are just strings
4. Numbers can be specified in any base supported by RNum (dec, hex, oct, binary ...)
5. Each ESIL backend should have an associated RReg profile to describe the esil register specs

Bitarrays
=========
What to do with them? What about bit arithmetics if use variables instead of registers?

Arithmetics
===========
1. ADD ("+")
2. MUL ("*")
3. SUB ("-")
4. DIV ("/")
5. MOD ("%")


Bit arithmetics
===============
1. AND  "&"
2. OR   "|"
3. XOR  "^"
4. SHL  "<<"
5. SHR  ">>"
6. ROL  "<<<"
7. ROR  ">>>"
8. NEG  "!"

Floating point
==============

_TODO_

The x86 REP prefix in ESIL
==========================

ESIL specifies that the parsing control-flow commands are in uppercase. Bear in
mind that some archs have uppercase register names. The register profile should
take care to not reuse any of the following:

	3,SKIP   - skip N instructions. used to make relative forward GOTOs
	3,GOTO   - goto instruction 3
	LOOP     - alias for 0,GOTO
	BREAK    - stop evaluating the expression
	STACK    - dump stack contents to screen
	CLEAR    - clear stack


Usage example:

rep cmpsb
---------

	cx,!,?{,BREAK,},esi,[1],edi,[1],==,?{,BREAK,},esi,++,edi,++,cx,--,LOOP


Unimplemented/unhandled instructions
====================================

Those are expressed with the 'TODO' command. which acts as a 'BREAK', but
displaying a warning message describing which instruction is not implemented
and will not be emulated.

For example:

	fmulp ST(1), ST(0)      =>      TODO,fmulp ST(1),ST(0)

Disassembly example:
====================

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

Radare anal ESIL code example
==============================

As an example implementation of ESIL analysis for the AVR family of
microcontrollers there is a `avr_op` function in `/libr/anal/p/anal_avr.c`
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


Introspection
=============

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

API HOOKS
=========

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
