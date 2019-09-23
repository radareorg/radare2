#!/bin/sed -f
s/&kv3_/kv3_decode/g;
s/registera[0123]/registerap/g;

s/register\(.[pq]\?\)[hlxyzt]\?_opnd/_r\1/g;
s/register\([bc]\)o_opnd/_r\1_odd/g;
s/register\([bc]\)e_opnd/_r\1_even/g;
s/system[^_]*_opnd/_rs/g;
s/extend27_offset27_opnd/_off54/;
s/offset27_opnd/_off27/;

s/extend27_upper27_lower10_opnd/_imm64/;
s/extend6_upper27_lower10_opnd/_imm43/;
s/upper27_lower10_opnd/_imm37/;
s/upper27_lower5_opnd/_imm32/;
s/stopbit2_stopbit4_opnd/_stop_bit/;
s/startbit_opnd/_start_bit/;
s/sysnumber_opnd/_sys/;

s/signed10_opnd/_s10/;
s/signed16_opnd/_s16/;
s/unsigned6_opnd/_u6/;

s/pcrel17_opnd/_pcrel17/;
s/pcrel27_opnd/_pcrel27/;
s/byteshift_opnd/_shift/;

# REG_A  ARF[23:18]
# REG_Al BRF[23:18]
# REG_Ah BRF[23:18]
# REG_?  CRF x,y,z,t
# REG_B  ARF[17:12]
# REG_C  ARF[11:6]
# REG_D  ARF[5:0]
# REG_Ap WRF[23:19]
# REG_Bp WRF[17:13]
# REG_Aq XRF[23:20]
# REG_Bq XRF[17:14]
# REG_E  ARF[23:18]
# REG_M  PRF[23:19]
# REG_N  QRF[23:20]
# REG_O  PRF[11:7]
# REG_P  PRF[5:1]
# REG_Q  QRF[5:2]
# REG_T  DRF[23:18]
# REG_U  PRF[23:19]
# REG_V  QRF[23:20]
# REG_W  DRF[23:18]
# REG_Y  DRF[11:6]
# REG_Z  DRF[5:0]
# KV3_SRF system  reg file
# KV3_GRF general reg file
# KV3_PRF paired  reg file
# KV3_QRF quad reg file
# KV3_CRF coproc reg file (48 reg of 256 bits)
