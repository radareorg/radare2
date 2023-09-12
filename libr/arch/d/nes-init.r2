# https://www.nesdev.org/wiki/CPU_memory_map
# $0000–$07FF	$0800	2 KB internal RAM
# $0800–$0FFF	$0800	Mirrors of $0000–$07FF
# $1000–$17FF	$0800   ""
# $1800–$1FFF	$0800   ""
# $2000–$2007	$0008	NES PPU registers
# $2008–$3FFF	$1FF8	Mirrors of $2000–$2007 (repeats every 8 bytes)
# $4000–$4017	$0018	NES APU and I/O registers
# $4018–$401F	$0008	APU and I/O functionality that is normally disabled. See CPU Test Mode.
# $4020–$FFFF	$BFE0	Cartridge space: PRG ROM, PRG RAM, and mapper registers

f fd.old=`oqq`

of malloc://0x800 # 2 KB interal ram
f fd.ram=`oqq`
om . 0x0000 0x0800 0 rwx iram
om . 0x0800 0x1000 0 rwx mirror0
om . 0x1000 0x1800 0 rwx mirror1
om . 0x1800 0x2000 0 rwx mirror2

## the cylic uri creates an infinite file containing a loop of the N bytes
of cyclic://8 # ppu
f fd.ppu=`oqq`
om . 0x2000 0x4000 0 rwx ppuregs

of malloc://8
om . 0x00002000 0x0008 0 rwx PPU_REG
f oldfd=`oqq`

o=oldfd;f-oldfd
of malloc://32
om . 0x00004000 0x0020 0 rwx APU_AND_IOREGS
of malloc://8192
om . 0x00006000 0x2000 0 rwx SRAM
o=oldfd;f-oldfd

of malloc://0x20
f fd.apu=`oqq`
om . 0x4000 0x4020 0 rwx apu

of malloc://0x2000
f fd.sram=`oqq`
om . 0x6000 0x8000 0 sram

f PPU_REG_MIRROR_1020=0x3fe0
f APU_AND_IOREGS=0x4000

.o**
.om**
# .im*

o=fd.old
f-fd.old
