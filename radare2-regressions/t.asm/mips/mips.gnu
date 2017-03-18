#!/bin/sh
for a in . .. ../.. ; do [ -e $a/tests.sh ] && . $a/tests.sh ; done

PLUGIN=mips.gnu

# Tests only whole disassembly opcode
test_vector() {
NAME="${1}: [${2}]"
FILE=malloc://32
if [ "${5}" = "br" ]; then
	BROKEN=1
fi
CMDS='
e asm.arch='${1}'
s 4
wx '${3}'
pi 1
'
EXPECT="${4}
"
run_test
}

test_vector "${PLUGIN}" "ADD.S" 00000046 'add.s $f0, $f0, $f0'
test_vector "${PLUGIN}" "ADDI" 00000020 "addi zero, zero, 0"
test_vector "${PLUGIN}" "ADDIU" 00000025 "addiu zero, t0, 0"
test_vector "${PLUGIN}" "ADDIU -offset" e7ff0025 "addiu zero, t0, -25"
test_vector "${PLUGIN}" "ANDI" 00000030 "andi zero, zero, 0x0"
test_vector "${PLUGIN}" "B" 00000010 "b 0x00000008"
test_vector "${PLUGIN}" "BC0F" 00000041 "bc0f 0x00000008"
test_vector "${PLUGIN}" "BC1F" 00000045 "bc1f 0x00000008"
test_vector "${PLUGIN}" "BC2F" 00000049 'bc2f 0x00000008'
test_vector "${PLUGIN}" "BC3F" 0000004d 'bc3f 0x00000008'
test_vector "${PLUGIN}" "BEQ" 11111011 "beq t0, s0, 0x0000444c"
test_vector "${PLUGIN}" "BEQL" 0050b853 "beql sp, t8, 0x00014008"
test_vector "${PLUGIN}" "BEQZL" 00000050 'beqzl zero, 0x00000008'
test_vector "${PLUGIN}" "BEZQ" 00000011 "beqz t0, 0x00000008"
test_vector "${PLUGIN}" "BGEZ" 02004104 "bgez v0, 0x00000010"
test_vector "${PLUGIN}" "BGEZL" 4800c305 "bgezl t6, 0x00000128"
test_vector "${PLUGIN}" "BGEZAL" 40003106 "bgezal s1, 0x00000108"
test_vector "${PLUGIN}" "BGEZALL" 48007305 "bgezall t3, 0x00000128"
test_vector "${PLUGIN}" "BGTZ" 0000001c "bgtz zero, 0x00000008"
test_vector "${PLUGIN}" "BGTZL" 0000005c 'bgtzl zero, 0x00000008'
test_vector "${PLUGIN}" "BLEZ" 00000018 "blez zero, 0x00000008"
test_vector "${PLUGIN}" "BLEZL" 00000058 'blezl zero, 0x00000008'
test_vector "${PLUGIN}" "BLTZ" 00000004 "bltz zero, 0x00000008"
test_vector "${PLUGIN}" "BLTZL" 4400c206 "bltzl s6, 0x00000118"
test_vector "${PLUGIN}" "BNE" 01111015 "bne t0, s0, 0x0000440c"
test_vector "${PLUGIN}" "BNEL" 00d01056 "bnel s0, s0, 0xffffffffffff4008"
test_vector "${PLUGIN}" "BNEZ" 00000014 "bnez zero, 0x00000008"
test_vector "${PLUGIN}" "BNEZL" 00000055 'bnezl t0, 0x00000008'
test_vector "${PLUGIN}" "C0" 00000042 "c0 0x0"
test_vector "${PLUGIN}" "C1" 00000047 'c1 0x1000000'
test_vector "${PLUGIN}" "C2" 0000004a 'c2 0x0'
test_vector "${PLUGIN}" "C3" 0000004e 'c3 0x0'
test_vector "${PLUGIN}" "CACHE" 000000bc 'cache 0x0, 0(zero)'
test_vector "${PLUGIN}" "DADDI" 00000060 'daddi zero, zero, 0'
test_vector "${PLUGIN}" "DADDIU" 00000064 'daddiu zero, zero, 0'
test_vector "${PLUGIN}" "J" 00000008 "j 0x00000000"
test_vector "${PLUGIN}" "JAL" 0000000c "jal 0x00000000"
test_vector "${PLUGIN}" "JALX" 00000074 'jalx 0x00000000'
test_vector "${PLUGIN}" "JALX" 01000074 'jalx 0x00000004'
test_vector "${PLUGIN}" "LB" 00000080 'lb zero, 0(zero)'
test_vector "${PLUGIN}" "LBU" 00000090 'lbu zero, 0(zero)'
test_vector "${PLUGIN}" "LD" 000000dc 'ld zero, 0(zero)'
test_vector "${PLUGIN}" "LDC1" 000000d4 'ldc1 $f0, 0(zero)'
test_vector "${PLUGIN}" "LDC2" 000000d8 'ldc2 $0, 0(zero)'
test_vector "${PLUGIN}" "LDL" 00000068 'ldl zero, 0(zero)'
test_vector "${PLUGIN}" "LDR" 0000006c 'ldr zero, 0(zero)'
test_vector "${PLUGIN}" "LH" 00000084 'lh zero, 0(zero)'
test_vector "${PLUGIN}" "LHU" 00000094 'lhu zero, 0(zero)'
test_vector "${PLUGIN}" "LI" 00000024 "li zero, 0"
test_vector "${PLUGIN}" "LI" 00000034 "li zero, 0x0"
test_vector "${PLUGIN}" "LL" 000000c0 'll zero, 0(zero)'
test_vector "${PLUGIN}" "LLD" 000000d0 'lld zero, 0(zero)'
test_vector "${PLUGIN}" "LUI" 0000003c "lui zero, 0x0"
test_vector "${PLUGIN}" "LW" 0000008c 'lw zero, 0(zero)'
test_vector "${PLUGIN}" "LWC1" 000000c4 'lwc1 $f0, 0(zero)'
test_vector "${PLUGIN}" "LWC2" 000000c8 'lwc2 $0, 0(zero)'
test_vector "${PLUGIN}" "LWC3" 000000cc 'lwc3 $0, 0(zero)'
test_vector "${PLUGIN}" "LWL" 00000088 'lwl zero, 0(zero)'
test_vector "${PLUGIN}" "LWR" 00000098 'lwr zero, 0(zero)'
test_vector "${PLUGIN}" "LWU" 0000009c 'lwu zero, 0(zero)'
test_vector "${PLUGIN}" "MFC0" 00000040 'mfc0 zero, $0'
test_vector "${PLUGIN}" "MFC1" 00000044 'mfc1 zero, $f0'
test_vector "${PLUGIN}" "MFC2" 00000048 'mfc2 zero, $0'
test_vector "${PLUGIN}" "MFC3" 0000004c 'mfc3 zero, $0'
test_vector "${PLUGIN}" "NOP" 00000000 "nop"
test_vector "${PLUGIN}" "ORI" 00000035 "ori zero, t0, 0x0"
test_vector "${PLUGIN}" "PADDSH" 0000004b 'paddsh $f0, $f0, $f0'
test_vector "${PLUGIN}" "SB" 000000a0 'sb zero, 0(zero)'
test_vector "${PLUGIN}" "SC" 000000e0 'sc zero, 0(zero)'
test_vector "${PLUGIN}" "SCD" 000000f0 'scd zero, 0(zero)'
test_vector "${PLUGIN}" "SD" 000000fc 'sd zero, 0(zero)'
test_vector "${PLUGIN}" "SDC1" 000000f4 'sdc1 $f0, 0(zero)'
test_vector "${PLUGIN}" "SDC2" 000000f8 'sdc2 $0, 0(zero)'
test_vector "${PLUGIN}" "SDL" 000000b0 'sdl zero, 0(zero)'
test_vector "${PLUGIN}" "SDR" 000000b4 'sdr zero, 0(zero)'
test_vector "${PLUGIN}" "SH" 000000a4 'sh zero, 0(zero)'
test_vector "${PLUGIN}" "SLTI" 00000028 "slti zero, zero, 0"
test_vector "${PLUGIN}" "SLTIU" 0000002c "sltiu zero, zero, 0"
test_vector "${PLUGIN}" "SW" 000000ac 'sw zero, 0(zero)'
test_vector "${PLUGIN}" "SWC1" 000000e4 'swc1 $f0, 0(zero)'
test_vector "${PLUGIN}" "SWC2" 000000e8 'swc2 $0, 0(zero)'
test_vector "${PLUGIN}" "SWC2" 000000ec 'swc3 $0, 0(zero)'
test_vector "${PLUGIN}" "SWL" 000000a8 'swl zero, 0(zero)'
test_vector "${PLUGIN}" "SWR" 000000b8 'swr zero, 0(zero)'
test_vector "${PLUGIN}" "XORI" 00000038 "xori zero, zero, 0x0"
