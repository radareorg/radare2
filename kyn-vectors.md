```
20:27 <@r2tg> <Maijin> koyaan: x86.nz (x86 handmade assembler) is one of the many x86 assemblers 
              available in radare2 and is updated frequently.
20:27 <@r2tg> <Maijin> You can contribute to x86.nz by completing the following file 
              https://github.com/radare/radare2/blob/master/libr/asm/p/asm_x86_nz.c.
20:27 <@r2tg> <Maijin> You can also use keystone(http://keystone-engine.org) within radare2/rasm2 by 
              installing the radare2 plugin via r2pm :
20:27 <@r2tg> <Maijin> r2pm -i keystone-lib
20:27 <@r2tg> <Maijin> r2pm -i keystone
20:27 <@r2tg> <Maijin> then
20:27 <@r2tg> <Maijin> rasm2 -a x86.ks…
20:27 <@r2tg> <Maijin> or in radare2 session
20:27 <@r2tg> <Maijin> e asm.assembler = x86.ks
20:27 <@r2tg> <Maijin> Others x86 assemblers are also available trough r2pm or master (see rasm2 -L 
              list):
20:27 <@r2tg> <Maijin>
20:27 <@r2tg> <Maijin> a___  16 32 64   x86.as      LGPL3   Intel X86 GNU Assembler
20:27 <@r2tg> <Maijin> a___  16 32 64   x86.nasm    LGPL3   X86 nasm assembler
20:27 <@r2tg> <Maijin> a___  16 32 64   x86.nz      LGPL3   x86 handmade assembler
20:27 <@r2tg> <Maijin> ad__  32         x86.olly    GPL2    OllyDBG X86 disassembler
20:27 < wasamasa> you should be able to find that somewhere around libr/asm/x86 or so
20:27 <@r2tg> <Maijin> and similarly
20:27 <@r2tg> <Maijin> http://radare.today/posts/radare2-capstone/
20:27 <@r2tg> <Maijin> r2 have multiple x86 disassembler available
20:27 < koyaan> oh very cool thank you i was just diving down starting from rasm2_main but getting 
                nowhere
20:28 <@r2tg> <Maijin> rasm2 exposes the functionnalities
20:28 <@r2tg> <Maijin> but that’s not where the actual code is
20:28 < wasamasa> you have a binr for the binaries, libr for the shared functionality, sys for scripts, 
                  etc.
20:28 < koyaan> yeah was following the dependencies but it was not too easy
20:29 -!- teroshan [~teroshan@51.15.130.5] has joined #radare
20:31 <@r2tg> <Maijin> Usually easier to go from a core/cmd_XXX
20:31 <@r2tg> <Maijin> and then go back to the implementation
```
### reference
https://software.intel.com/sites/landingpage/IntrinsicsGuide/#expand=0
https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
https://en.wikipedia.org/wiki/VEX_prefix
https://stackoverflow.com/questions/51773399/vex-prefixes-encoding-and-sse-avx-movupd-s-instructions
 > There is a difference between the VEX encoded instruction and its legacy SSE encoded version. VEX encoded 128-bit instructions set the upper half of the 256-bit ymm vector (or the upper 3/4 of zmm...) to zero, avoiding partial register write stalls. In contrast, the legacy encoding leaves the upper part unchanged, causing severe slowdown when mixing AVX-256 code and SSE code on some microarchitectures.

https://www.radare.org/get/33c3-r2demystified.pdf

So i guess we should assemble to VEX form?

https://bananamafia.dev/post/r2wars-2019/
printing __m128i: https://stackoverflow.com/questions/13257166/print-a-m128i-variable

#### wig w-ignored 
https://sourceware.org/binutils/docs/as/i386_002dOptions.html
 >These options control how the assembler should encode VEX.W-ignored (WIG) VEX instructions. -mvexwig=0 will encode WIG VEX instructions with vex.w = 0, which is the default. -mvexwig=1 will encode WIG EVEX instructions with vex.w = 1.
 
#### keystone handling of AVX

https://github.com/keystone-engine/keystone/blob/master/llvm/lib/Target/X86/AsmParser/X86AsmParser.cpp#L2795

### clion support

https://github.com/STKFLT/radare2-clion

```
If you want to debug with CLion, just build radare2 with ./sys/build.sh CFLAGS='-g' and then add binr/radare2/radare2 as an debug configuration.

It is possible that the list of directories containing header files in CMakeLists.txt is out of date. If so, just run

for file in $(find . -name '*.h'); do dirname $file; done | sort | uniq
```

Start in /home/koyaan/code/radare2/libr/asm/p/asm_x86_nz.c by adding vmovdqu to assembler

# 4 possible forms:
VMOVDQU xmm1, xmm2/m128 VEX.128.F3.0F.WIG 6F /r
VMOVDQU xmm2/m128, xmm1 VEX.128.F3.0F.WIG 7F /r
VMOVDQU ymm1, ymm2/m256 VEX.256.F3.0F.WIG 6F /r
VMOVDQU ymm2/m256, ymm1 VEX.256.F3.0F.WIG 7F /r

C5 FE 6F 00                                         vmovdqu ymm0, ymmword ptr [rax]
C5 FE 7F 45 20                                      vmovdqu [rbp+40h+var_20], ymm0
C5 FE 7F 84 01 00 08 00 00                          vmovdqu ymmword ptr [rcx+rax+800h], ymm0


### stepping through:

main > assemble >  parseOpcode >  parseOperand >  parseReg


## regression test assembler

    koyaan@moldo: ~/code/radare2/radare2-regressions/new  [master !?]
    $ node node_modules/node-r2r/bin/r2r.js -i db/asm/x86_64

# changing some magic
since we need room for the new ymmreg and soon zmmreg?

    #define OPTYPE_SHIFT   4

# runconfigs 
    -b 64 -a x86.nz "vmovdqu ymm0, ymmword [rax]"
# shits broken YO!

```bash
$ rasm2 -a x86.nasm -b 64 "fmul   st2, st0"
dcca
koyaan@moldo: ~/code/radare2  [master !?]
$ rasm2 -a x86 -b 64 -d "dcca"
fmul st(2), st(0)
koyaan@moldo: ~/code/radare2  [master !?]
$ rasm2 -a x86.nz -b 64 "fmul   st2, st0"
dcff
```    

## 2 pulls out weeeh!

# start on mmx

https://en.wikipedia.org/wiki/MMX_(instruction_set)

## issue: mm register are not shown and cannot be selected
[0x7f4a1882bc20]> drm mm0
cannot find multimedia register 'mm0'

- add register in `libr/debug/p/native/linux/reg/linux-x64.h`


## issue drf st0 prints all registers not only selected one


# netbsd can do YMM https://reviews.llvm.org/D63545


# rebase feature

```bash
git checkout your-feature-name
git merge-base master/your-feature-name // returns {hash}
git rebase -i {hash}
```

# angr pull also wants some stuff from this :D

https://github.com/angr/angr-targets/pull/1
