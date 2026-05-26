# Dynamic Calling Conventions

`dyncc:` describes a per-function calling convention without registering a
static SDB profile.

The grammar is intentionally flat:

```text
dyncc:<args>:<rets>[!<attr>...]
```

`dyncc:` is the fixed namespace prefix. Do not replace it with `@`; `@`
conflicts with r2 command syntax.

## Fields

`<args>` is a comma-separated list of logical argument locations. It can be
empty.

`<rets>` is a comma-separated list of return locations. It can be empty, which
means `void`.

Attributes are optional. Every attribute starts with `!`, then a one-character
tag, then its value. Attribute values run until the next `!` or the end of the
string.

```text
dyncc:rdi,rsi:rax
dyncc:rdi,rsi,rdx:rax!T1
dyncc::rax!Tx20!Ex21
```

## Locations

Plain locations are register tokens. They may use letters, numbers, `_`, and
`.`. The `-` character is reserved for reverse ranges, so plain register tokens
cannot contain it.

```text
rN        numbered return/value register class
aN        numbered argument register class
vN        generic value register class
lN        local/temp class
rax       concrete register name
x0        concrete register name
^         call-frame argument tail
^-        reverse call-frame argument tail
^N        fixed call-frame slot N
^-N       fixed reverse call-frame slot N
&name     delegate the whole args or rets field to a static cc profile
_         skipped logical argument slot
```

Indexed register and call-frame locations can be written as ranges:

```text
a0+4      a0, a1, a2, a3
a3-4      a3, a2, a1, a0
v0+2      v0, v1
^0+4      ^0, ^1, ^2, ^3
^3-4      ^3, ^2, ^1, ^0
^-0+2     ^-0, ^-1
```

## Multiple Homes

Use a single quote to describe multiple homes for the same logical argument:

```text
dyncc:a0'^0,a1'^1,a2'^2,a3'^3,^:v0
```

The same ABI can be written more compactly with parallel ranges:

```text
dyncc:a0+4'^0+4,^:v0
```

For the example above:

```text
arg0 home0 = a0
arg0 home1 = ^0
arg1 home0 = a1
arg1 home1 = ^1
arg4+      = ^
ret0       = v0
```

This is useful for ABIs such as MIPS o32, where register arguments also have
call-frame home slots.

## Attributes

```text
!pN       callee pops N bytes
!p0       caller cleanup / callee pops 0 bytes
!p?       callee pop amount is unknown

!C(...)   call-clobbered registers
!P(...)   call-preserved registers

!TN       T role is logical argument N
!Tloc     T role is concrete location loc

!RN       R role is logical argument N
!Rloc     R role is concrete location loc

!VN       V role is logical argument N
!Vloc     V role is concrete location loc

!EN       E role is logical argument N
!Eloc     E role is concrete location loc

!XN       X role is logical argument N
!Xloc     X role is concrete location loc

!xN       custom lowercase one-letter role x is logical argument N
!xloc     custom lowercase one-letter role x is concrete location loc
```

There is no separate static/instance mode. Instance-ness is represented by the
presence of the `T` role.

Role names in dyncc syntax are one-character tags only. Old word names are not
accepted.

## Register-Name Conflicts

Control syntax uses non-register characters: `:`, `,`, `!`, `'`, `&`, `_`, `^`,
`+`, and `-`. Attribute tags are only meaningful immediately after `!`, so a
register named `T0` is still a location while `!T0` is a role attribute.

The call-frame marker is `^` because previous spellings such as `s0` collide
with real register names.

## Examples

### MIPS o32

MIPS o32 passes the first four logical arguments in `a0` through `a3` while
also reserving call-frame home slots for them. Later arguments continue in the
call-frame tail:

```text
dyncc:a0+4'^0+4,^:v0
```

```text
arg0 home0 = a0
arg0 home1 = ^0
arg1 home0 = a1
arg1 home1 = ^1
arg2 home0 = a2
arg2 home1 = ^2
arg3 home0 = a3
arg3 home1 = ^3
arg4+      = ^
ret0       = v0
```

### Windows x86-32 MessageBoxA

`MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)` uses
Win32 `stdcall`: call-frame arguments, return in `eax`, callee pops 16 bytes.

```text
dyncc:^0,^1,^2,^3:eax!p16
```

The pushes happen right-to-left at the machine-code level, but logical
arguments are still listed left-to-right:

```text
arg0 hWnd      = ^0
arg1 lpText    = ^1
arg2 lpCaption = ^2
arg3 uType     = ^3
ret0           = eax
callee pop     = 16 bytes
```

### Swift Reverse Args

Swift-like reverse register order with sideband role registers:

```text
dyncc:x3-4:x0!Tx20!Ex21
```

```text
arg0  = x3
arg1  = x2
arg2  = x1
arg3  = x0
ret0  = x0
T     = x20
E     = x21
```

### Dalvik Instance Method

Dalvik-style instance method where the immediate receiver parameter is the first
logical parameter register:

```text
dyncc:p0+3:v0!T0
```

```text
arg0 = p0
arg1 = p1
arg2 = p2
ret0 = v0
T    = arg0
```

### Delegation

Whole-field delegation to an existing static profile:

```text
dyncc:&cdecl:&cdecl
```

## Removed Syntax

The dyncc parser rejects the older nested and wordy PoC grammar: memory-base
ranges, parenthesized location lists, grouped return pieces, explicit
static/instance modes, word attributes, and named roles.

Use explicit comma lists, compact ranges, the `^` call-frame marker, and the
one-character attribute tags documented above.
