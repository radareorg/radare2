/*
 * Binary loader for Plan 9's a.out executable format
 * 
 * Copyright (C) 2008 Anant Narayanan
 */
struct plan9_exec {
	unsigned long magic;	/* magic number */
	unsigned long text;	/* size of text segment */
	unsigned long data;	/* size of initialized data */
	unsigned long bss;	/* size of uninitialized data */
	unsigned long syms;	/* size of symbol table */
	unsigned long entry;	/* entry point */
	unsigned long spsz;	/* size of pc/sp offset table */
	unsigned long pcsz;	/* size of pc/line number table */
};

#define HDR_MAGIC	0x00008000	/* header expansion */

#define	_MAGIC(f, b)	((f)|((((4*(b))+0)*(b))+7))
#define	A_MAGIC		_MAGIC(0, 8)	/* 68020 */
#define	I_MAGIC		_MAGIC(0, 11)	/* intel 386 */
#define	J_MAGIC		_MAGIC(0, 12)	/* intel 960 (retired) */
#define	K_MAGIC		_MAGIC(0, 13)	/* sparc */
#define	V_MAGIC		_MAGIC(0, 16)	/* mips 3000 BE */
#define	X_MAGIC		_MAGIC(0, 17)	/* att dsp 3210 (retired) */
#define	M_MAGIC		_MAGIC(0, 18)	/* mips 4000 BE */
#define	D_MAGIC		_MAGIC(0, 19)	/* amd 29000 (retired) */
#define	E_MAGIC		_MAGIC(0, 20)	/* arm */
#define	Q_MAGIC		_MAGIC(0, 21)	/* powerpc */
#define	N_MAGIC		_MAGIC(0, 22)	/* mips 4000 LE */
#define	L_MAGIC		_MAGIC(0, 23)	/* dec alpha */
#define	P_MAGIC		_MAGIC(0, 24)	/* mips 3000 LE */
#define	U_MAGIC		_MAGIC(0, 25)	/* sparc64 */
#define	S_MAGIC		_MAGIC(HDR_MAGIC, 26)	/* amd64 */
#define	T_MAGIC		_MAGIC(HDR_MAGIC, 27)	/* powerpc64 */

#define TOS_SIZE	14	/* Size of Top of Stack: 56 / 4 */
#define HDR_SIZE	0x20
#define STR_ADDR	0x1000	/* Start Address */
#define TXT_ADDR	HDR_SIZE + ex.text	/* TEXT Address */
#define DAT_ADDR	STR_ADDR + PAGE_ALIGN(TXT_ADDR)	/* DATA&BSS Address */

/*---*/

#define p9bin_open(x) fopen(x,"r")
#define p9bin_close(x) fclose(x)

/* Reads four bytes from b. */
int r_bin_p9_get_arch(const unsigned char *b, int *bits, int *big_endian);
