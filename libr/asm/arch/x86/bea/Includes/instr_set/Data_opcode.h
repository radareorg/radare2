// Copyright 2006-2009, BeatriX
// File coded by BeatriX
//
// This file is part of BeaEngine.
//
//    BeaEngine is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    BeaEngine is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with BeaEngine.  If not, see <http://www.gnu.org/licenses/>.

/* ===============================================================================  */
/*														                            */
/*														                            */
/*					            1 BYTE_OPCODE MAP							        */
/*														                            */
/*														                            */
/* ===============================================================================  */

void __stdcall (*opcode_map1[])(PDISASM) = {
    add_EbGb  , add_EvGv  , add_GbEb  , add_GvEv  , add_ALIb  , add_eAX_Iv, push_es   , pop_es    , or_EbGb   , or_EvGv   , or_GbEb   , or_GvEv   , or_ALIb   , or_eAX_Iv , push_cs   , Esc_2byte ,
    adc_EbGb  , adc_EvGv  , adc_GbEb  , adc_GvEv  , adc_ALIb  , adc_eAX_Iv, push_ss   , pop_ss    , sbb_EbGb  , sbb_EvGv  , sbb_GbEb  , sbb_GvEv  , sbb_ALIb  , sbb_eAX_Iv, push_ds   , pop_ds    ,
    and_EbGb  , and_EvGv  , and_GbEb  , and_GvEv  , and_ALIb  , and_eAX_Iv, PrefSEGES , daa_      , sub_EbGb  , sub_EvGv  , sub_GbEb  , sub_GvEv  , sub_ALIb  , sub_eAX_Iv, PrefSEGCS , das_      ,
    xor_EbGb  , xor_EvGv  , xor_GbEb  , xor_GvEv  , xor_ALIb  , xor_eAX_Iv, PrefSEGSS , aaa_      , cmp_EbGb  , cmp_EvGv  , cmp_GbEb  , cmp_GvEv  , cmp_ALIb  , cmp_eAX_Iv, PrefSEGDS , aas_      ,
    inc_eax   , inc_ecx   , inc_edx   , inc_ebx   , inc_esp   , inc_ebp   , inc_esi   , inc_edi   , dec_eax   , dec_ecx   , dec_edx   , dec_ebx   , dec_esp   , dec_ebp   , dec_esi   , dec_edi   ,
    push_eax  , push_ecx  , push_edx  , push_ebx  , push_esp  , push_ebp  , push_esi  , push_edi  , pop_eax   , pop_ecx   , pop_edx   , pop_ebx   , pop_esp   , pop_ebp   , pop_esi   , pop_edi   ,
    pushad_   , popad_    , bound_    , arpl_     , PrefSEGFS , PrefSEGGS , PrefOpSize, PrefAdSize, push_Iv   ,imul_GvEvIv, push_Ib   ,imul_GvEvIb, insb_     , ins_      , outsb_    , outsw_    ,
    jo_       , jno_      , jc_       , jnc_      , je_       , jne_      , jbe_      , jnbe_     , js_       , jns_      , jp_       , jnp_      , jl_       , jnl_      , jle_      , jnle_     ,
    G1_EbIb   , G1_EvIv   , G1_EbIb2  , G1_EvIb   , test_EbGb , test_EvGv , xchg_EbGb , xchg_EvGv , mov_EbGb  , mov_EvGv  , mov_GbEb  , mov_GvEv  , mov_EwSreg, lea_GvM   , mov_SregEw, pop_Ev    ,
    nop_      , xchg_ecx  , xchg_edx  , xchg_ebx  , xchg_esp  , xchg_ebp  , xchg_esi  , xchg_edi  , cwde_     , cdq_      , callf_    , wait_     , pushfd_   , popfd_    , sahf_     , lahf_     ,
    mov_ALOb  , mov_eAXOv , mov_ObAL  , mov_OveAX , movs_     , movsw_    , cmpsb_    , cmps_     , test_ALIb ,test_eAX_Iv, stos_     , stosw_    , lodsb_    , lodsw_    , scasb_    , scas_     ,
    mov_ALIb  , mov_CLIb  , mov_DLIb  , mov_BLIb  , mov_AHIb  , mov_CHIb  , mov_DHIb  , mov_BHIb  , mov_EAX   , mov_ECX   , mov_EDX   , mov_EBX   , mov_ESP   , mov_EBP   , mov_ESI   , mov_EDI   ,
    G2_EbIb   , G2_EvIb   , retn_     , ret_      , les_GvM   , lds_GvM   , mov_EbIb  , mov_EvIv  , enter_    , leave_    , retf_Iw   , retf_     , int3_     , int_      , into_     , iret_     ,
    G2_Eb1    , G2_Ev1    , G2_EbCL   , G2_EvCL   , aam_      , aad_      , salc_     , xlat_     , D8_       , D9_       , DA_       , DB_       , DC_       , DD_       , DE_       , DF_       ,
    loopne_   , loope_    , loop_     , jecxz_    , in_ALIb   , in_eAX_Ib , out_IbAL  , out_Ib_eAX, call_     , jmp_near  , jmp_far   , jmp_short , in_ALDX   , in_eAX    , out_DXAL  , out_DXeAX ,
    PrefLock  , int1_     , PrefREPNE , PrefREPE  , hlt_      , cmc_      , G3_Eb     , G3_Ev     , clc_      , stc_      , cli_      , sti_      , cld_      , std_      , G4_Eb     , G5_Ev     ,
 };

/* ===============================================================================  */
/*														                            */
/*														                            */
/*					            2 BYTE_OPCODE MAP --> 0F xx					        */
/*														                            */
/*														                            */
/* ===============================================================================  */
void __stdcall (*opcode_map2[])(PDISASM) = {
    G6_       , G7_       , lar_GvEw  , lsl_GvEw  , FailDecode, syscall_  , clts_     , sysret_   , invd_     , wbinvd_   , FailDecode, ud2_      , FailDecode, nop_Ev    , femms_    , FailDecode,
    movups_VW , movups_WV , movlps_VM , movlps_MV , unpcklps_ , unpckhps_ , movhps_VM , movhps_MV , G16_      , hint_nop  , hint_nop  , hint_nop  , hint_nop  , hint_nop  , hint_nop  , nop_Ev    ,
    mov_RdCd  , mov_RdDd  , mov_CdRd  , mov_DdRd  , FailDecode, FailDecode, FailDecode, FailDecode, movaps_VW , movaps_WV , cvtpi2ps_ , movntps_  , cvttps2pi_, cvtps2pi_ , ucomiss_VW, comiss_VW ,
    wrmsr_    , rdtsc_    , rdmsr_    , rdpmc_    , sysenter_ , sysexit_  , FailDecode, FailDecode,Esc_tableA4, FailDecode,Esc_tableA5, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    cmovo_    , cmovno_   , cmovb_    , cmovnb_   , cmove_    , cmovne_   , cmovbe_   , cmovnbe_  , cmovs_    , cmovns_   , cmovp_    , cmovnp_   , cmovl_    , cmovnl_   , cmovle_   , cmovnle_  ,
    movmskps_ , sqrtps_VW , rsqrtps_  , rcpps_    , andps_VW  , andnps_VW , orps_VW   , xorps_VW  , addps_VW  , mulps_VW  , cvtps2pd_ , cvtdq2ps_ , subps_VW  , minps_VW  , divps_VW  , maxps_VW  ,
    punpcklbw_, punpcklwd_, punpckldq_, packsswb_ , pcmpgtb_  , pcmpgtw_  , pcmpgtd_  , packuswb_ , punpckhbw_, punpckhwd_, punpckhdq_, packssdw_ ,punpcklqdq_,punpckhqdq_, movd_PE   , movq_PQ   ,
    pshufw_   , G12_      , G13_      , G14_      , pcmpeqb_  , pcmpeqw_  , pcmpeqd_  , emms_     , vmread_   , vmwrite_  , FailDecode, FailDecode, haddpd_VW , hsubpd_VW , movd_EP   , movq_QP   ,
    jo_near   , jno_near  , jc_near   , jnc_near  , je_near   , jne_near  , jbe_near  , ja_near   , js_near   , jns_near  , jp_near   , jnp_near  , jl_near   , jnl_near  , jle_near  , jnle_near ,
    seto_     , setno_    , setb_     , setnb_    , sete_     , setne_    , setbe_    , setnbe_   , sets_     , setns_    , setp_     , setnp_    , setnge_   , setge_    , setle_    , setnle_   ,
    push_fs   , pop_fs    , cpuid_    , bt_EvGv   ,shld_EvGvIb,shld_EvGvCL, FailDecode, FailDecode, push_gs   , pop_gs    , rsm_      , bts_EvGv  ,shrd_EvGvIb,shrd_EvGvIb, G15_      , imul_GvEv ,
    cmpx_EbGb , cmpx_EvGv , lss_Mp    , btr_EvGv  , lfs_Mp    , lgs_Mp    , movzx_GvEb, movzx_GvEw, popcnt_   , ud2_      , G8_EvIb   , btc_EvGv  , bsf_GvEv  , bsr_GvEv  , movsx_GvEb, movsx_GvEw,
    xadd_EbGb , xadd_EvGv , cmpps_VW  , movnti_   , pinsrw_   , pextrw_   , shufps_   , G9_       , bswap_eax , bswap_ecx , bswap_edx , bswap_ebx , bswap_esp , bswap_ebp , bswap_esi , bswap_edi ,
    addsubpd_ , psrlw_    , psrld_    , psrlq_    , paddq_    , pmullw_   , movq_WV   , pmovmskb_ , psubusb_  , psubusw_  , pminub_   , pand_     , paddusb_  , paddusw_  , pmaxub_   , pandn_    ,
    pavgb_    , psraw_    , psrad_    , pavgw_    , pmulhuw_  , pmulhw_   , cvtpd2dq_ , movntq_   , psubsb_   , psubsw_   , pminsw_   , por_      , paddsb_   , paddsw_   , pmaxsw_   , pxor_     ,
    lddqu_    , psllw_    , pslld_    , psllq_    , pmuludq_  , pmaddwd_  , psadbw_   , maskmovq_ , psubb_    , psubw_    , psubd_    , psubq_    , paddb_    , paddw_    , paddd_    , FailDecode,
 };

/* ===============================================================================  */
/*														                            */
/*														                            */
/*					            3 BYTE_OPCODE MAP --> 0F 38 xx				        */
/*														                            */
/*														                            */
/* ===============================================================================  */
 void __stdcall (*opcode_map3[])(PDISASM) = {
    pshufb_   , phaddw_   , phaddd_   , phaddsw_  , pmaddubsw_, phsubw_   , phsubd_   , phsubsw_  , psignb_   , psignw_   , psignd_   , pmulhrsw_ , FailDecode, FailDecode, FailDecode, FailDecode,
    pblendvb_ , FailDecode, FailDecode, FailDecode, blendvps_ , blendvpd_ , FailDecode, ptest_    , FailDecode, FailDecode, FailDecode, FailDecode, pabsb_    , pabsw_    , pabsd_    , FailDecode,
    pmovsxbw_ , pmovsxbd_ , pmovsxbq_ , pmovsxwd_ , pmovsxwq_ , pmovsxdq_ , FailDecode, FailDecode, pmuldq_   , pcmpeqq_  , movntdqa_ , packusdw_ , FailDecode, FailDecode, FailDecode, FailDecode,
    pmovzxbw_ , pmovzxbd_ , pmovzxbq_ , pmovzxwd_ , pmovzxwq_ , pmovzxdq_ , FailDecode, pcmpgtq_  , pminsb_   , pminsd_   , pminuw_   , pminud_   , pmaxsb_   , pmaxsd_   , pmaxuw_   , pmaxud_   ,
    pmulld_   ,phminposuw_, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    crc32_GvEb, crc32_GvEv, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
 };

/* ===============================================================================  */
/*														                            */
/*														                            */
/*					            3 BYTE_OPCODE MAP --> 0F 3A xx				        */
/*														                            */
/*														                            */
/* ===============================================================================  */
 void __stdcall (*opcode_map4[])(PDISASM) = {
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, roundps_  , roundpd_  , roundss_  , roundsd_  , blendps_  , blendpd_  , pblendw_  , palignr_  ,
    FailDecode, FailDecode, FailDecode, FailDecode, pextrb_   , pextrw2_  , pextrd_   , extractps_, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    pinsrb_   , insertps_ , pinsrd_   , FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    dpps_     , dppd_     , mpsadbw_  , FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    pcmpestrm_, pcmpestri_, pcmpistrm_, pcmpistri_, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
    FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode, FailDecode,
 };


void __stdcall (*ModRM_0[])(ARGTYPE*) = {
     Addr_EAX,
     Addr_ECX,
     Addr_EDX,
     Addr_EBX,
     Addr_SIB,
     Addr_disp32,
     Addr_ESI,
     Addr_EDI,
 };

 void __stdcall (*ModRM_1[])(ARGTYPE*) = {
     Addr_EAX_disp8,
     Addr_ECX_disp8,
     Addr_EDX_disp8,
     Addr_EBX_disp8,
     Addr_SIB_disp8,
     Addr_EBP_disp8,
     Addr_ESI_disp8,
     Addr_EDI_disp8,
 };

 void __stdcall (*ModRM_2[])(ARGTYPE*) = {
     Addr_EAX_disp32,
     Addr_ECX_disp32,
     Addr_EDX_disp32,
     Addr_EBX_disp32,
     Addr_SIB_disp32,
     Addr_EBP_disp32,
     Addr_ESI_disp32,
     Addr_EDI_disp32,
 };

 void __stdcall (*ModRM_3[])(ARGTYPE*) = {
     _EAX,
     _ECX,
     _EDX,
     _EBX,
     _ESP,
     _EBP,
     _ESI,
     _EDI,
 };

int __stdcall (*SIB[])(ARGTYPE*, int) = {
     SIB_0,
     SIB_1,
     SIB_2,
     SIB_3,
 };
