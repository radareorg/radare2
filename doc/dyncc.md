# Dynamic Calling Conventions

Dynamic calling conventions describe per-function argument and return locations
without registering one SDB calling convention per function.

Use `anal.cc=dyncc` for binaries whose bin plugin can provide per-function
dynamic calling conventions. Function creation only records the bare `dyncc`
marker in `RAnalFunction.callconv`; the concrete expression is resolved lazily
the first time a calling convention is actually needed. See "Resolution and
Memory" below.

Also, use this syntax to specify custom calling conventions without having to
register them globally.

## Syntax

The canonical syntax is:

```
dyncc:<arg-map>:<i|s>:<ret-map>[!attr...]
```

Fields:

- `arg-map`: comma-separated argument location maps
- `i`: instance method; `self` defaults to argument `0`
- `s`: static/free function; there is no implicit `self`
- `ret-map`: comma-separated return locations; empty means void
- `!caller`: caller cleans stack arguments, or there is no fixed callee pop
- `!callee`: callee cleans stack arguments, but the byte count is not known from
  the calling convention alone
- `!pop=N`: callee returns after popping `N` argument bytes from the caller stack
- `!clobber=(regs)`: call-clobbered registers
- `!preserve=(regs)`: call-preserved registers
- `!self=N`: `self`/`this` is logical ABI argument `N`
- `!sret=N`: structure/indirect return storage is logical ABI argument `N`
- `!vtt=N`: Itanium C++ VTT pointer is logical ABI argument `N`
- `!error=<loc>`: sideband error-result location
- `!context=<loc>`: sideband context location
- `!role.<name>=N|<loc>`: provider-specific ABI role

The common compact location form is:

```
<pfx><base><+|-><count>
```

Examples:

```
v6+1        # v6
v1-2        # v1, v0
l0+3        # l0, l1, l2
m0+3        # stack/memory slots 0, 1, 2
m2-3        # reverse stack/memory slots 2, 1, 0
m0+         # unbounded stack/memory tail
```

`pfx` is one ASCII letter. `v`, `l`, and `a` are not magic dyncc types; they
are register-name prefixes from the active register profile:

- `v` usually means virtual register, as in DEX registers
- `l` usually means local slot, as in JVM locals and wasm locals
- `a` usually means argument slot, as in CIL metadata arguments
- `m` means memory/stack argument slots

Use linear ranges whenever the register profile has indexed names. Use explicit
register lists only for non-linear architecture registers:

```
(ecx,edx)
(eax)
```

Use braces to group several physical pieces into one logical argument or return
slot. The CC API exposes both the original grouped location and parsed pieces,
so consumers can treat the group as one storage unit while still seeing its
register or stack fragments:

```
{edx:eax}            # one value in a register pair
{0:rdi,8:rsi.4}      # one value scattered by byte offsets
{0:rdi,8:m0.4}       # one value split across a register and stack
```

Unlike `(ecx,edx)`, which means two logical locations, `{ecx:edx}` means one
logical location. `r_anal_cc_location_pieces` splits grouped locations into
piece records containing byte offset, optional byte size, and physical location.
`r_anal_cc_location_uses` lets argument recovery match a use of `eax` back to
the logical `{edx:eax}` argument.

Memory ranges default to the ABI stack pointer. A memory range can name a
different base register when the ABI passes a pointer to an argument area:

```
m(ecx)0+
```

Argument maps normally append to the next logical argument. These are compact
forms for the common cases:

```
dyncc:v6+1:s:          # one DEX argument in v6, void return
dyncc:v0+1:i:v0+1      # instance method, self in v0, return in v0
dyncc:l0+3:s:r0+3      # wasm-style locals and multi-return
dyncc:(ecx,edx),m0+:s:(eax)
```

Use an explicit logical argument range on the left side of `=` when locations do
not simply append, or when a logical argument has more than one home:

```
<arg-base><+|-><count>=<location-range>
<arg-base><+|->=<location-tail>
```

Examples:

```
dyncc:a0+4,4+=m4+:s:r0+1
dyncc:a0+4,0+4=m0+4,4+=m4+:s:r0+1
dyncc:0+4=(a0,a1,a2,a3),0+4=m0+4,4+=m4+:s:(v0,v1)
```

The second example maps arguments `0..3` to both `a0..a3` and memory home slots
`m0..m3`, then maps later arguments to memory. Commas always separate maps;
overlapping logical argument ranges are how dyncc expresses multiple homes for
the same logical argument.

Use `&name` to reference a static calling convention profile when that profile
already describes a non-linear register order:

```
dyncc:&cdecl:s:&cdecl
dyncc:&fastcall:s:&fastcall
```

Bare `&name` delegates the argument or return lookup to the named static
profile, including its `argn` stack tail and multi-return slots. Referenced
profiles must already exist in `anal->sdb_cc`; `r_anal_cc_exist` rejects dyncc
expressions that reference unknown profiles.

Use an explicit logical argument range to apply only part of a static profile.
The referenced profile is indexed relative to the range, so `2+3=&amd64` maps
logical arguments 2, 3, and 4 to `amd64` arguments 0, 1, and 2:

```
dyncc:0+4=&fastcall,4+=m4+:s:&fastcall
dyncc:2+3=&amd64:s:&amd64
```

Additional maps can be added next to a reference. The first matching home is
the primary location returned by `r_anal_cc_arg`; later homes are available
through home-indexed accessors:

```
dyncc:&amd64,0+6=m0+6,6+=m6+:s:&amd64
```

Use `!pop=N` when the callee removes a fixed number of stack-argument bytes.
This is caller-visible metadata used by function analysis to rebase stack
variable recovery after calls.

Examples:

```
dyncc:m0+2:s:(eax)!pop=8       # stdcall-like two 32-bit stack args
dyncc:(ecx,edx),m0+1:s:(eax)!pop=4
dyncc:m0+:s:(eax)!caller       # cdecl-like caller cleanup
dyncc:m0+:s:(eax)!callee       # callee cleanup, unknown fixed byte count
```

Static SDB profiles can use the same metadata with `cc.<name>.pop`. The value
can be `caller`, `callee`, or a fixed byte count. Only fixed byte counts are
currently used to rebase caller stack variables.

Use `!clobber=(...)` and `!preserve=(...)` to describe call effects on
registers:

```
dyncc:x0+8,m0+:s:x0+1!clobber=(x0,x1,x2,x3,x4,x5,x6,x7)!preserve=(x15,x21,x26,x27,x28)
```

The register sets are stored as metadata and are intentionally independent from
argument and return locations. A register can be an argument home and still be
call-clobbered after the call returns. Static SDB profiles use
`cc.<name>.clobber` and `cc.<name>.preserve`.

### ABI Roles

Dyncc names describe finalized ABI locations, not source-language signatures.
All source-level type classification, argument directions (`in`, `out`,
`inout`), ownership, exception declarations, and C++ aggregate lowering must be
handled before producing the dyncc string. Hidden ABI inputs that really cross
the call boundary should be present in the argument map and may be tagged with a
role suffix.

Built-in roles are:

```
!self=N         # self/this is logical ABI argument N
!sret=N         # caller-provided indirect return storage argument
!vtt=N          # Itanium C++ VTT pointer argument
!error=<loc>    # sideband error result location
!context=<loc>  # sideband context location
```

Numeric role values refer to logical ABI arguments and resolve through the same
maps as `r_anal_cc_arg`. Non-numeric values are concrete locations:

```
dyncc:0+4=&ms:i:&ms!sret=0!self=1
dyncc:x0+8,m0+:s:x0+1!self=x20!error=x21
```

The `i` kind is only a default: without `!self=...`, `r_anal_cc_self` returns
argument `0`. Use `!self=N` when a hidden ABI argument, such as `sret`, precedes
`this`. Use `!self=<loc>` for sideband receiver/context registers that are not
ordinary positional arguments.

Providers can attach a provider-specific ABI role with `!role.<name>=N` or
`!role.<name>=<loc>`. For example, an IL2CPP provider may tag the hidden
`RuntimeMethod *` argument with `!role.method=N` after it has emitted the full
per-method argument map.

Static SDB profiles use the same role names as `cc.<name>.<role>`, for example
`cc.swift.error=x21` or `cc.dlang.self=x20`.

### Stack Cleanup

The stack-cleanup suffix describes the stack effect that is visible to the
caller after the callee returns. This is separate from argument placement:
`m0+2` says where two stack arguments live, while `!pop=8` says that the callee
removes those eight bytes before control returns to the caller.

Supported forms:

```
!caller       # caller cleanup; no implicit rebasing
!callee       # callee cleanup exists, but the byte count is unknown
!pop=8        # callee pops 8 argument bytes
!8            # shorthand accepted by the parser for cc.<name>.pop and dyncc
```

Analysis consumes fixed values from either metadata or callee-body inference.
When a direct call targets an analyzed function whose calling convention has
`!pop=N` or `cc.<name>.pop=N`, the function-analysis loop applies that stack
delta after the call. If no fixed metadata exists, the callee's return
instructions are inspected; x86-style `ret 0x10` is cached as a 16-byte
callee-pop and applied by callers. This keeps the existing `sp`/`bp`-relative
variable recovery model; it does not introduce a new variable location kind.
Later stack accesses are simply interpreted using the rebased tracked stack
pointer.

On architectures where the call instruction itself is modeled as pushing a
return address, analysis also removes that transient call push while applying
the callee pop. This avoids making the return address look like caller-owned
argument or local storage.

`!callee` is intentionally weaker than `!pop=N`: it records that the convention
is callee-cleaned, but without a byte count there is no deterministic stack delta
to apply at the caller. Body inference can still provide a fixed value when the
return instruction encodes one.

## Semantics

The bare `dyncc` name is only a marker/default convention. Concrete `dyncc:`
names are virtual. They are not inserted into `anal->sdb_cc`; the
`r_anal_cc_*` accessors parse the name directly:

- `r_anal_cc_exist` validates the syntax
- `r_anal_cc_arg` returns the primary home for a logical argument
- `r_anal_cc_arg_home` returns a specific home for a logical argument
- `r_anal_cc_ret` returns the `n`th return location
- `r_anal_cc_stack_pop` returns fixed callee-popped stack bytes, `0` for caller
  cleanup/no fixed pop, or `R_ANAL_CC_STACK_POP_UNKNOWN` for `!callee`
- `r_anal_cc_clobbers` returns the call-clobbered register set
- `r_anal_cc_preserves` returns the call-preserved register set
- `r_anal_cc_role` returns a built-in or provider-specific ABI role location
- `r_anal_cc_location_pieces` parses grouped/scattered locations
- `r_anal_cc_location_uses` tests whether a grouped location contains a register
- `r_anal_cc_self` returns `!self`, or argument `0` for instance conventions
  without an explicit self role
- `r_anal_cc_max_arg` returns the finite mapped argument count; unbounded memory
  tails are not counted

For memory locations, `m...+` resolves to the existing `stack` location class and
`m...-` resolves to `stack_rev` when no explicit base register is supplied.
Memory ranges with an explicit base, such as `m(ecx)0+`, resolve to named memory
locations because they are not the canonical ABI stack.

RBin owns only the metadata used to build the name; it must not mutate analysis
state directly.

## Resolution and Memory

Concrete `dyncc:` expressions are not built eagerly. When `anal.cc` is `dyncc`,
function creation stores the bare `dyncc` marker in `RAnalFunction.callconv`.
The concrete expression is produced on demand:

- `r_anal_function_cc(fcn)` returns the function's calling convention. When
  `callconv` still holds the bare marker, it calls `RBinPlugin.get_cc` once,
  interns the result in `anal->constpool`, and writes it back into
  `fcn->callconv`. Functions whose calling convention is never queried never
  pay the `get_cc` lookup or the string interning.
- Consumers that need a function's calling convention (argument recovery,
  call-site effects, `afi`, `afc`, signature export) call `r_anal_function_cc`
  rather than reading `fcn->callconv` directly. External code that reads the
  field directly may observe the unresolved `dyncc` marker.

Parsing is cached too. The `r_anal_cc_*` accessors parse a `dyncc:` expression
through a small per-`RAnal` round-robin cache keyed by interned-pointer
identity, so the same expression is parsed at most once even though analysis
queries it many times per call site. The parsed form references spans of the
interned expression instead of copying register and group names, which keeps
each cached entry small. The cache is released by `r_anal_cc_reset` and
`r_anal_free`.

The `afch` command prints the `dyncc` syntax reference and, for the current
function, resolves and shows its concrete `dyncc:` expression with argument,
return, and ABI-role homes. `afchj` emits the same information as JSON.

## Stack VM Metadata

For stack-VM formats, keep two concepts separate:

- variable recovery slots: the register/local window analysis should materialize
- calling convention slots: the callable argument and return locations exposed by
  `RBinPlugin.get_cc`

These are often the same, but not always. JVM `Code.max_locals`, for example,
can include compiler temporaries that are not method parameters. Java therefore
uses `RBinSymbol.arg_count` to recover the local window as `l0..lN`, while its
`get_cc` callback derives the callable argument count from the method
descriptor. A static `()V` method with four locals should recover `l0..l3`, but
its concrete dyncc is `dyncc::s:`.

Other current providers use callable argument slots directly:

- DEX: `arg_first = registers_size - ins_size`, `arg_count = ins_size`
- pyc: `arg_count = argcount + kwonlyargcount`
- wasm: `arg_count` and `ret_count` come from the function type
- CIL: `arg_count = param_count + HASTHIS`, with `i` set for instance methods

## Language and VM Examples

These examples show how existing language and VM conventions fit in the
current syntax. They are convention shapes, not global names; a bin plugin
should still build the concrete expression from per-function metadata when the
argument count, first argument slot, or return count changes.

### Dart / Flutter

r2flutter documents the ARM64 Dart AOT convention as a native-looking ABI with
Dart-specific preserved context registers:

- `x0..x7`: parameter passing and `x0` return
- `x15`: Dart stack cache / shadow stack pointer
- `x21`: dispatch table pointer
- `x26`: thread pointer (`THR`)
- `x27`: object pool pointer (`PP`)
- `x28`: heap base for compressed pointers

The callable part can be described as:

```
dyncc:x0+8,m(x15)0+:s:x0+1
```

This describes arguments in `x0..x7`, a Dart-stack tail based on `x15`, and a
return value in `x0`. The fixed runtime registers are not formal arguments, so
they should be attached as preserved call-effect metadata:

```
dyncc:x0+8,m(x15)0+:s:x0+1!preserve=(x15,x21,x26,x27,x28)
```

In r2flutter's Ghidra spec, these registers are marked as unaffected by calls;
`!preserve` is the dyncc-side equivalent. If a Dart profile also knows the
scratch set, add it separately with `!clobber=(...)`.

Variable recovery consumes these sets at call sites. With `!clobber`, only
listed caller argument registers are invalidated. With only `!preserve`, all
caller argument registers except the preserved set are invalidated. With neither
metadata field, r2 keeps the conservative legacy behavior and treats caller
argument registers as clobbered by the call.

If a Dart provider can recover a function-specific virtual argument window from
snapshot metadata, that window can be described directly:

```
dyncc:v4+3:s:v0+1      # args v4, v5, v6; return v0
dyncc:v4+3:i:v0+1      # same, with self/receiver in v4
```

### Hermes

r2hermes function metadata exposes `param_count`. The bytecode does not start
with arguments already housed in fixed VM registers; `LoadParam` and
`LoadParamLong` copy logical `argN` slots into ordinary `r0..r255` registers,
and `Ret` copies a selected register into the ESIL pseudo-slot `ret`.

If the HBC register profile grows compact indexed pseudo-argument registers,
the natural per-function expression is:

```
dyncc:a0+3:s:(ret)     # params a0, a1, a2; logical return slot ret
```

With today's ESIL names (`arg0`, `arg1`, ...), a provider can still emit an
explicit list because compact dyncc ranges only have one-letter prefixes:

```
dyncc:(arg0,arg1,arg2):s:(ret)
```

If the importer decodes the initial `LoadParam` destinations and wants concrete
register homes instead of logical slots, it can emit those registers:

```
dyncc:(r1,r2,r3):s:(ret)
```

`this`, `new.target`, and the reified `arguments` object are Hermes semantic
values, not ordinary positional parameters in every function. Model them as
normal arguments only when the bytecode metadata or the load sequence makes that
true for the function being analyzed.

### Unity IL2CPP

r2unity recovers managed method metadata (`parameterCount`, method flags, and
method pointer tables), but IL2CPP methods are native C++ functions. The dyncc
expression therefore has to combine managed metadata with the target native ABI.

For ARM64, an instance method with one managed parameter usually looks like:

```
// C++ shape: Health_Damage(Health *__this, int amount, const RuntimeMethod *method)
dyncc:0+3=&arm64:i:&arm64!role.method=2
```

For a static ARM64 method with two managed parameters and the hidden
`RuntimeMethod *` tail:

```
dyncc:0+3=&arm64:s:&arm64!role.method=2
```

For x86-64 SysV and Windows x64 targets, use explicit static-profile references
or explicit register lists:

```
dyncc:0+3=&amd64:i:&amd64!role.method=2   # SysV-like instance shape
dyncc:0+3=&ms:i:&ms!role.method=2         # Windows x64 instance shape
```

The important part is that `i` is appropriate for ordinary instance methods
where logical argument `0` is `__this`. If C++ ABI lowering inserts an ABI
argument before `this`, tag both roles explicitly:

```
dyncc:0+4=&ms:i:&ms!sret=0!self=1!role.method=3
```

The final hidden `RuntimeMethod *` is not expressible as "always append this
after the managed parameter count" in a single static dyncc string; an r2unity
`get_cc` provider should build the full per-method expression after reading
`parameterCount` and method flags. P/Invoke, reverse P/Invoke, invoker thunks,
and generic sharing wrappers may need separate profiles because they are ABI
bridges rather than plain generated C++ methods.

### D

For the existing D profiles, the shortest dyncc form reuses the static profile:

```
dyncc:&dlang:s:&dlang
```

For the existing x86-64 D profile in `libr/anal/d/cc-x86-64.sdb.txt`, the
expanded argument and return locations are:

```
dyncc:(rdi,rsi,rdx,rcx,r8d,r9d),m0+:s:(rax,rdx)
```

For the existing x86-32 D profile, including its reverse stack tail:

```
dyncc:(edi,esi,edx,ecx,r8d,r9d),m0-:s:(eax,edx)
```

For the existing ARM64 D profile, the callable argument and return part is:

```
dyncc:x0+8,m0+:s:x0+1
```

The ARM64 D profile also defines `self=x20` and `error=x21`. Those are sideband
calling-convention fields in the static profile. A concrete dyncc replacement
can expose them as explicit ABI roles:

```
dyncc:x0+8,m0+:s:x0+1!self=x20!error=x21
```

### Swift

For existing Swift profiles, the shortest dyncc form reuses the static profile:

```
dyncc:&swift:s:&swift
```

For the existing ARM64 Swift profile, the expanded callable argument and return
part is:

```
dyncc:x0+8,m0+:s:x0+1
```

For the existing x86-64 Swift profile:

```
dyncc:(rdi,rsi,rdx,rcx,r8,r9,xmm0,xmm1,xmm2,xmm3,xmm4),m0+:s:(rax)
```

The static Swift profiles also carry sideband registers (`self=x20`,
`error=x21` on ARM64; `self=r13`, `error=r12` on x86-64). A concrete dyncc
replacement can expose those sideband fields explicitly:

```
dyncc:x0+8,m0+:s:x0+1!self=x20!error=x21
dyncc:(rdi,rsi,rdx,rcx,r8,r9,xmm0,xmm1,xmm2,xmm3,xmm4),m0+:s:(rax)!self=r13!error=r12
```

This reuses the static profile's arguments and returns while making `self` and
`error` visible through `r_anal_cc_self` and `r_anal_cc_error`.

When adding a dyncc provider, add tests for both paths:

- `afi~callconv,args` or `afch` to verify the concrete calling convention
- `afv` or `pdf~args` after a plain `af` to verify recovered argument variables
