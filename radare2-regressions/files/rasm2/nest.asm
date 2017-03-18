.arch x86
.bits 32

.set yes 1
.set no 0

.ifeq yes 1
  add ecx, 0x2
  .if no
    nop
  .endif
.endif

.if no
  add ecx, 0x5
.else
  .warning WARN
  sub ecx, 0x5
.endif

.set xxx add ebx, 1
.get xxx

.error ERR

mov ecx, 2
nop