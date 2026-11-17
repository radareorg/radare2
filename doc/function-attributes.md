# Function attributes

Function attributes use one bit mask internally and one compact string in
`afij`, `aflj` and `afiaj`. Each letter appears at most once, in the order below.
An absent letter means the attribute is unset; the empty string means none.

| Letter | Attribute | Meaning |
| --- | --- | --- |
| N | noreturn | Never returns to the caller |
| I | inline | Inlined at call sites |
| P | pure | Does not access outside state |
| V | variadic | Takes a variable number of arguments |
| T | thunk | Only jumps to another function |
| L | library | Import stub or library code |
| S | static | Internal linkage |
| C | constructor | Runs before main |
| D | destructor | Runs at exit |
| K | naked | No compiler prologue or epilogue |
| Q | interrupt | Interrupt handler |
| E | lineal | Contiguous basic blocks |
| R | recursive | Calls its own entry directly |
| M | method | Calling convention defines a receiver/self role |

For example, `{"attrs":"PERM"}` describes a pure, lineal, recursive method.
Callers can check letter membership without parsing additional objects or
converting boolean strings. Consumers should ignore unknown letters.

`afia` lists the letters, names and current values. `afiaq` prints only the
string. `afia+ NT` and `afia+ noreturn,thunk` enable the same attributes;
`afia-` clears them, and `afia=` replaces the settable attributes. Pure,
variadic, lineal, recursive and method are derived and cannot be set by `afia`.

Entry-point analysis (`aa` and `aaa`) sets constructor and destructor attributes
from the RBin entries shown by `iee`. Init and preinit entries set constructor;
fini entries set destructor. These attributes remain editable through `afia`.

Recursive describes a direct self-call, not a loop back to the entry or an
indirect cycle through other functions. It is refreshed with reference counts
and when printing function references. Method is set when assigning a calling
convention with a `T` role in dyncc or a `self` role in a static profile.
The receiver position is defined by the convention: `!T0`, `!T1` and `!Tx20`
all mark methods. See [Dynamic calling conventions](dyncc.md).

JSON consumers migrating from the previous output must read `attrs` instead
of `is-pure`, `is-lineal`, `noreturn`, `inline`, `thunk` and `recursive` in
`afij`/`aflj`. `afiaj` now contains only `attrs`, without duplicate booleans.
