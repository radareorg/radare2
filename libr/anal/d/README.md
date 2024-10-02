# anal/d

This directory contains k=v files that are compiled into sdb databases or gperf
structures and this is used for the code analysis and type propagation logic.

## Files of interest

* spec.sdb.txt = format modifiers like %p %d %s its used for type propagation
* types.sdb.txt = basic C-like types
* $os-$bits.sdb.txt = os-arch-bits structs and enums

## Types: structs / enums / constants

## Calling Conventions

Those are defined in the `cc-${arch}-${bits}.sdb.txt` files.

### dlang calling convention

* narg = 1 : edi
* narg = 2 : esi, edi
* narg = 3 : edx, esi, edi
* narg = 4 : ecx, edx, esi, edi
* narg = 5 : r8d, ecx, edx, esi, edi
* narg = 6 : r9d, r8d, ecx, edx, esi, edi
* narg = 7 : push, r9d, r8d, ecx, edx, esi, edi

```asm
mov     R9D,1
mov     R8D,2
mov     ECX,3
mov     EDX,4
mov     ESI,5
mov     EDI,6

mov     R8D,1
mov     ECX,2
mov     EDX,3
mov     ESI,4
mov     EDI,5

push    1
push    2
mov     R9D,3
mov     R8D,4
mov     ECX,5
mov     EDX,6
mov     ESI,7
mov     EDI,8
call      int example.square(int, int, int, int, int, int, int, int)@PLT32
add     RSP,010h
```
