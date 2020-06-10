/* AArch64 relocs.  */

#define R_AARCH64_NONE            0	/* No relocation.  */

/* ILP32 AArch64 relocs.  */
#define R_AARCH64_P32_ABS32		  1	/* Direct 32 bit.  */
#define R_AARCH64_P32_COPY		180	/* Copy symbol at runtime.  */
#define R_AARCH64_P32_GLOB_DAT		181	/* Create GOT entry.  */
#define R_AARCH64_P32_JUMP_SLOT		182	/* Create PLT entry.  */
#define R_AARCH64_P32_RELATIVE		183	/* Adjust by program base.  */
#define R_AARCH64_P32_TLS_DTPMOD	184	/* Module number, 32 bit.  */
#define R_AARCH64_P32_TLS_DTPREL	185	/* Module-relative offset, 32 bit.  */
#define R_AARCH64_P32_TLS_TPREL		186	/* TP-relative offset, 32 bit.  */
#define R_AARCH64_P32_TLSDESC		187	/* TLS Descriptor.  */
#define R_AARCH64_P32_IRELATIVE		188	/* STT_GNU_IFUNC relocation. */
#define R_AARCH64_COPY                  1024

/* LP64 AArch64 relocs.  */
#define R_AARCH64_ABS64         257	/* Direct 64 bit. */
#define R_AARCH64_ABS32         258	/* Direct 32 bit.  */
#define R_AARCH64_ABS16		259	/* Direct 16-bit.  */
#define R_AARCH64_PREL64	260	/* PC-relative 64-bit.	*/
#define R_AARCH64_PREL32	261	/* PC-relative 32-bit.	*/
#define R_AARCH64_PREL16	262	/* PC-relative 16-bit.	*/
#define R_AARCH64_MOVW_UABS_G0	263	/* Dir. MOVZ imm. from bits 15:0.  */
#define R_AARCH64_MOVW_UABS_G0_NC 264	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_UABS_G1	265	/* Dir. MOVZ imm. from bits 31:16.  */
#define R_AARCH64_MOVW_UABS_G1_NC 266	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_UABS_G2	267	/* Dir. MOVZ imm. from bits 47:32.  */
#define R_AARCH64_MOVW_UABS_G2_NC 268	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_UABS_G3	269	/* Dir. MOV{K,Z} imm. from 63:48.  */
#define R_AARCH64_MOVW_SABS_G0	270	/* Dir. MOV{N,Z} imm. from 15:0.  */
#define R_AARCH64_MOVW_SABS_G1	271	/* Dir. MOV{N,Z} imm. from 31:16.  */
#define R_AARCH64_MOVW_SABS_G2	272	/* Dir. MOV{N,Z} imm. from 47:32.  */
#define R_AARCH64_LD_PREL_LO19	273	/* PC-rel. LD imm. from bits 20:2.  */
#define R_AARCH64_ADR_PREL_LO21	274	/* PC-rel. ADR imm. from bits 20:0.  */
#define R_AARCH64_ADR_PREL_PG_HI21 275	/* Page-rel. ADRP imm. from 32:12.  */
#define R_AARCH64_ADR_PREL_PG_HI21_NC 276 /* Likewise; no overflow check.  */
#define R_AARCH64_ADD_ABS_LO12_NC 277	/* Dir. ADD imm. from bits 11:0.  */
#define R_AARCH64_LDST8_ABS_LO12_NC 278	/* Likewise for LD/ST; no check. */
#define R_AARCH64_TSTBR14	279	/* PC-rel. TBZ/TBNZ imm. from 15:2.  */
#define R_AARCH64_CONDBR19	280	/* PC-rel. cond. br. imm. from 20:2. */
#define R_AARCH64_JUMP26	282	/* PC-rel. B imm. from bits 27:2.  */
#define R_AARCH64_CALL26	283	/* Likewise for CALL.  */
#define R_AARCH64_LDST16_ABS_LO12_NC 284 /* Dir. ADD imm. from bits 11:1.  */
#define R_AARCH64_LDST32_ABS_LO12_NC 285 /* Likewise for bits 11:2.  */
#define R_AARCH64_LDST64_ABS_LO12_NC 286 /* Likewise for bits 11:3.  */
#define R_AARCH64_MOVW_PREL_G0	287	/* PC-rel. MOV{N,Z} imm. from 15:0.  */
#define R_AARCH64_MOVW_PREL_G0_NC 288	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_PREL_G1	289	/* PC-rel. MOV{N,Z} imm. from 31:16. */
#define R_AARCH64_MOVW_PREL_G1_NC 290	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_PREL_G2	291	/* PC-rel. MOV{N,Z} imm. from 47:32. */
#define R_AARCH64_MOVW_PREL_G2_NC 292	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_PREL_G3	293	/* PC-rel. MOV{N,Z} imm. from 63:48. */
#define R_AARCH64_LDST128_ABS_LO12_NC 299 /* Dir. ADD imm. from bits 11:4.  */
#define R_AARCH64_MOVW_GOTOFF_G0 300	/* GOT-rel. off. MOV{N,Z} imm. 15:0. */
#define R_AARCH64_MOVW_GOTOFF_G0_NC 301	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_GOTOFF_G1 302	/* GOT-rel. o. MOV{N,Z} imm. 31:16.  */
#define R_AARCH64_MOVW_GOTOFF_G1_NC 303	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_GOTOFF_G2 304	/* GOT-rel. o. MOV{N,Z} imm. 47:32.  */
#define R_AARCH64_MOVW_GOTOFF_G2_NC 305	/* Likewise for MOVK; no check.  */
#define R_AARCH64_MOVW_GOTOFF_G3 306	/* GOT-rel. o. MOV{N,Z} imm. 63:48.  */
#define R_AARCH64_GOTREL64	307	/* GOT-relative 64-bit.  */
#define R_AARCH64_GOTREL32	308	/* GOT-relative 32-bit.  */
#define R_AARCH64_GOT_LD_PREL19	309	/* PC-rel. GOT off. load imm. 20:2.  */
#define R_AARCH64_LD64_GOTOFF_LO15 310	/* GOT-rel. off. LD/ST imm. 14:3.  */
#define R_AARCH64_ADR_GOT_PAGE	311	/* P-page-rel. GOT off. ADRP 32:12.  */
#define R_AARCH64_LD64_GOT_LO12_NC 312	/* Dir. GOT off. LD/ST imm. 11:3.  */
#define R_AARCH64_LD64_GOTPAGE_LO15 313	/* GOT-page-rel. GOT off. LD/ST 14:3 */
#define R_AARCH64_TLSGD_ADR_PREL21 512	/* PC-relative ADR imm. 20:0.  */
#define R_AARCH64_TLSGD_ADR_PAGE21 513	/* page-rel. ADRP imm. 32:12.  */
#define R_AARCH64_TLSGD_ADD_LO12_NC 514	/* direct ADD imm. from 11:0.  */
#define R_AARCH64_TLSGD_MOVW_G1	515	/* GOT-rel. MOV{N,Z} 31:16.  */
#define R_AARCH64_TLSGD_MOVW_G0_NC 516	/* GOT-rel. MOVK imm. 15:0.  */
#define R_AARCH64_TLSLD_ADR_PREL21 517	/* Like 512; local dynamic model.  */
#define R_AARCH64_TLSLD_ADR_PAGE21 518	/* Like 513; local dynamic model.  */
#define R_AARCH64_TLSLD_ADD_LO12_NC 519	/* Like 514; local dynamic model.  */
#define R_AARCH64_TLSLD_MOVW_G1	520	/* Like 515; local dynamic model.  */
#define R_AARCH64_TLSLD_MOVW_G0_NC 521	/* Like 516; local dynamic model.  */
#define R_AARCH64_TLSLD_LD_PREL19 522	/* TLS PC-rel. load imm. 20:2.  */
#define R_AARCH64_TLSLD_MOVW_DTPREL_G2 523 /* TLS DTP-rel. MOV{N,Z} 47:32.  */
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1 524 /* TLS DTP-rel. MOV{N,Z} 31:16.  */
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC 525 /* Likewise; MOVK; no check.  */
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0 526 /* TLS DTP-rel. MOV{N,Z} 15:0.  */
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC 527 /* Likewise; MOVK; no check.  */
#define R_AARCH64_TLSLD_ADD_DTPREL_HI12 528 /* DTP-rel. ADD imm. from 23:12. */
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12 529 /* DTP-rel. ADD imm. from 11:0.  */
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC 530 /* Likewise; no ovfl. check.  */
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12 531 /* DTP-rel. LD/ST imm. 11:0.  */
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC 532 /* Likewise; no check.  */
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12 533 /* DTP-rel. LD/ST imm. 11:1.  */
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC 534 /* Likewise; no check.  */
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12 535 /* DTP-rel. LD/ST imm. 11:2.  */
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC 536 /* Likewise; no check.  */
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12 537 /* DTP-rel. LD/ST imm. 11:3.  */
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC 538 /* Likewise; no check.  */
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 539 /* GOT-rel. MOV{N,Z} 31:16.  */
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC 540 /* GOT-rel. MOVK 15:0.  */
#define R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 541 /* Page-rel. ADRP 32:12.  */
#define R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 542 /* Direct LD off. 11:3.  */
#define R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 543 /* PC-rel. load imm. 20:2.  */
#define R_AARCH64_TLSLE_MOVW_TPREL_G2 544 /* TLS TP-rel. MOV{N,Z} 47:32.  */
#define R_AARCH64_TLSLE_MOVW_TPREL_G1 545 /* TLS TP-rel. MOV{N,Z} 31:16.  */
#define R_AARCH64_TLSLE_MOVW_TPREL_G1_NC 546 /* Likewise; MOVK; no check.  */
#define R_AARCH64_TLSLE_MOVW_TPREL_G0 547 /* TLS TP-rel. MOV{N,Z} 15:0.  */
#define R_AARCH64_TLSLE_MOVW_TPREL_G0_NC 548 /* Likewise; MOVK; no check.  */
#define R_AARCH64_TLSLE_ADD_TPREL_HI12 549 /* TP-rel. ADD imm. 23:12.  */
#define R_AARCH64_TLSLE_ADD_TPREL_LO12 550 /* TP-rel. ADD imm. 11:0.  */
#define R_AARCH64_TLSLE_ADD_TPREL_LO12_NC 551 /* Likewise; no ovfl. check.  */
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12 552 /* TP-rel. LD/ST off. 11:0.  */
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC 553 /* Likewise; no ovfl. check. */
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12 554 /* TP-rel. LD/ST off. 11:1.  */
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC 555 /* Likewise; no check.  */
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12 556 /* TP-rel. LD/ST off. 11:2.  */
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC 557 /* Likewise; no check.  */
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12 558 /* TP-rel. LD/ST off. 11:3.  */
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC 559 /* Likewise; no check.  */
#define R_AARCH64_TLSDESC_LD_PREL19 560	/* PC-rel. load immediate 20:2.  */
#define R_AARCH64_TLSDESC_ADR_PREL21 561 /* PC-rel. ADR immediate 20:0.  */
#define R_AARCH64_TLSDESC_ADR_PAGE21 562 /* Page-rel. ADRP imm. 32:12.  */
#define R_AARCH64_TLSDESC_LD64_LO12 563	/* Direct LD off. from 11:3.  */
#define R_AARCH64_TLSDESC_ADD_LO12 564	/* Direct ADD imm. from 11:0.  */
#define R_AARCH64_TLSDESC_OFF_G1 565	/* GOT-rel. MOV{N,Z} imm. 31:16.  */
#define R_AARCH64_TLSDESC_OFF_G0_NC 566	/* GOT-rel. MOVK imm. 15:0; no ck.  */
#define R_AARCH64_TLSDESC_LDR	567	/* Relax LDR.  */
#define R_AARCH64_TLSDESC_ADD	568	/* Relax ADD.  */
#define R_AARCH64_TLSDESC_CALL	569	/* Relax BLR.  */
#define R_AARCH64_TLSLE_LDST128_TPREL_LO12 570 /* TP-rel. LD/ST off. 11:4.  */
#define R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC 571 /* Likewise; no check.  */
#define R_AARCH64_TLSLD_LDST128_DTPREL_LO12 572 /* DTP-rel. LD/ST imm. 11:4. */
#define R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC 573 /* Likewise; no check.  */
#define R_AARCH64_COPY         1024	/* Copy symbol at runtime.  */
#define R_AARCH64_GLOB_DAT     1025	/* Create GOT entry.  */
#define R_AARCH64_JUMP_SLOT    1026	/* Create PLT entry.  */
#define R_AARCH64_RELATIVE     1027	/* Adjust by program base.  */
#define R_AARCH64_TLS_DTPMOD   1028	/* Module number, 64 bit.  */
#define R_AARCH64_TLS_DTPREL   1029	/* Module-relative offset, 64 bit.  */
#define R_AARCH64_TLS_TPREL    1030	/* TP-relative offset, 64 bit.  */
#define R_AARCH64_TLSDESC      1031	/* TLS Descriptor.  */
// #define R_AARCH64_TLS_TPREL64           1030
// #define R_AARCH64_TLS_DTPREL32          1031
#define R_AARCH64_IRELATIVE	1032	/* STT_GNU_IFUNC relocation.  */

