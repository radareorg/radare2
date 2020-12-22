/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#ifndef MDMP_WINDEFS_H
#define MDMP_WINDEFS_H

#define EXCEPTION_MAXIMUM_PARAMETERS 15

#define MAXIMUM_SUPPORTED_EXTENSION 512

#define SIZE_OF_80387_REGISTERS 80

#define ARM_MAX_BREAKPOINTS 8
#define ARM_MAX_WATCHPOINTS 1

R_PACKED (
struct windows_floating_save_area {
	ut32	control_word;
	ut32	status_word;
	ut32	tag_word;
	ut32	error_offset;
	ut32	error_selector;
	ut32	data_offset;
	ut32	data_selector;
	ut8	register_area[SIZE_OF_80387_REGISTERS];
	ut32	spare_0;
});

R_PACKED (
struct windows_systemtime {
	ut16	w_year;
	ut16	w_month;
	ut16	w_day_of_week;
	ut16	w_day;
	ut16	w_hour;
	ut16	w_minute;
	ut16	w_second;
	ut16	w_milliseconds;
});

R_PACKED (
struct windows_timezone_information {
	ut32	bias;
	ut16	standard_name[32];
	struct windows_systemtime standard_date;
	ut32	standard_bias;
	ut16	daylight_name[32];
	struct windows_systemtime daylight_date;
	ut32	daylight_bias;
});

R_PACKED (
struct windows_m128a {
	ut64	low;
	st64	high;
});

R_PACKED (
struct windows_neon128 {
	ut64	low;
	st64	high;
});

R_PACKED (
struct windows_float128 {
	ut64 low;
	st64 high;
});

R_PACKED (
struct context_type_i386 {
	ut32	context_flags;

	ut32	dr0;
	ut32	dr1;
	ut32	dr2;
	ut32	dr3;
	ut32	dr6;
	ut32	dr7;

	struct windows_floating_save_area float_save;

	ut32	seg_gs;
	ut32	seg_fs;
	ut32	seg_es;
	ut32	seg_ds;

	ut32	edi;
	ut32	esi;
	ut32	ebx;
	ut32	edx;
	ut32	ecx;
	ut32	eax;

	ut32	ebp;
	ut32	eip;
	ut32	seg_cs;
	ut32	e_flags;
	ut32	esp;
	ut32	seg_ss;

	ut8	extended_registers[MAXIMUM_SUPPORTED_EXTENSION];
});

R_PACKED (
struct context_type_ia64 {
	ut32	context_flags;
	ut32	fill_1[3];

	ut64	db_i0;
	ut64	db_i1;
	ut64	db_i2;
	ut64	db_i3;
	ut64	db_i4;
	ut64	db_i5;
	ut64	db_i6;
	ut64	db_i7;

	ut64	db_d0;
	ut64	db_d1;
	ut64	db_d2;
	ut64	db_d3;
	ut64	db_d4;
	ut64	db_d5;
	ut64	db_d6;
	ut64	db_d7;

	struct windows_float128 flt_s0;
	struct windows_float128 flt_s1;
	struct windows_float128 flt_s2;
	struct windows_float128 flt_s3;
	struct windows_float128 flt_t0;
	struct windows_float128 flt_t1;
	struct windows_float128 flt_t2;
	struct windows_float128 flt_t3;
	struct windows_float128 flt_t4;
	struct windows_float128 flt_t5;
	struct windows_float128 flt_t6;
	struct windows_float128 flt_t7;
	struct windows_float128 flt_t8;
	struct windows_float128 flt_t9;

	struct windows_float128 flt_s4;
	struct windows_float128 flt_s5;
	struct windows_float128 flt_s6;
	struct windows_float128 flt_s7;
	struct windows_float128 flt_s8;
	struct windows_float128 flt_s9;
	struct windows_float128 flt_s10;
	struct windows_float128 flt_s11;
	struct windows_float128 flt_s12;
	struct windows_float128 flt_s13;
	struct windows_float128 flt_s14;
	struct windows_float128 flt_s15;
	struct windows_float128 flt_s16;
	struct windows_float128 flt_s17;
	struct windows_float128 flt_s18;
	struct windows_float128 flt_s19;

	struct windows_float128 flt_f32;
	struct windows_float128 flt_f33;
	struct windows_float128 flt_f34;
	struct windows_float128 flt_f35;
	struct windows_float128 flt_f36;
	struct windows_float128 flt_f37;
	struct windows_float128 flt_f38;
	struct windows_float128 flt_f39;

	struct windows_float128 flt_f40;
	struct windows_float128 flt_f41;
	struct windows_float128 flt_f42;
	struct windows_float128 flt_f43;
	struct windows_float128 flt_f44;
	struct windows_float128 flt_f45;
	struct windows_float128 flt_f46;
	struct windows_float128 flt_f47;
	struct windows_float128 flt_f48;
	struct windows_float128 flt_f49;

	struct windows_float128 flt_f50;
	struct windows_float128 flt_f51;
	struct windows_float128 flt_f52;
	struct windows_float128 flt_f53;
	struct windows_float128 flt_f54;
	struct windows_float128 flt_f55;
	struct windows_float128 flt_f56;
	struct windows_float128 flt_f57;
	struct windows_float128 flt_f58;
	struct windows_float128 flt_f59;

	struct windows_float128 flt_f60;
	struct windows_float128 flt_f61;
	struct windows_float128 flt_f62;
	struct windows_float128 flt_f63;
	struct windows_float128 flt_f64;
	struct windows_float128 flt_f65;
	struct windows_float128 flt_f66;
	struct windows_float128 flt_f67;
	struct windows_float128 flt_f68;
	struct windows_float128 flt_f69;

	struct windows_float128 flt_f70;
	struct windows_float128 flt_f71;
	struct windows_float128 flt_f72;
	struct windows_float128 flt_f73;
	struct windows_float128 flt_f74;
	struct windows_float128 flt_f75;
	struct windows_float128 flt_f76;
	struct windows_float128 flt_f77;
	struct windows_float128 flt_f78;
	struct windows_float128 flt_f79;

	struct windows_float128 flt_f80;
	struct windows_float128 flt_f81;
	struct windows_float128 flt_f82;
	struct windows_float128 flt_f83;
	struct windows_float128 flt_f84;
	struct windows_float128 flt_f85;
	struct windows_float128 flt_f86;
	struct windows_float128 flt_f87;
	struct windows_float128 flt_f88;
	struct windows_float128 flt_f89;

	struct windows_float128 flt_f90;
	struct windows_float128 flt_f91;
	struct windows_float128 flt_f92;
	struct windows_float128 flt_f93;
	struct windows_float128 flt_f94;
	struct windows_float128 flt_f95;
	struct windows_float128 flt_f96;
	struct windows_float128 flt_f97;
	struct windows_float128 flt_f98;
	struct windows_float128 flt_f99;

	struct windows_float128 flt_f100;
	struct windows_float128 flt_f101;
	struct windows_float128 flt_f102;
	struct windows_float128 flt_f103;
	struct windows_float128 flt_f104;
	struct windows_float128 flt_f105;
	struct windows_float128 flt_f106;
	struct windows_float128 flt_f107;
	struct windows_float128 flt_f108;
	struct windows_float128 flt_f109;

	struct windows_float128 flt_f110;
	struct windows_float128 flt_f111;
	struct windows_float128 flt_f112;
	struct windows_float128 flt_f113;
	struct windows_float128 flt_f114;
	struct windows_float128 flt_f115;
	struct windows_float128 flt_f116;
	struct windows_float128 flt_f117;
	struct windows_float128 flt_f118;
	struct windows_float128 flt_f119;

	struct windows_float128 flt_f120;
	struct windows_float128 flt_f121;
	struct windows_float128 flt_f122;
	struct windows_float128 flt_f123;
	struct windows_float128 flt_f124;
	struct windows_float128 flt_f125;
	struct windows_float128 flt_f126;
	struct windows_float128 flt_f127;

	ut64	st_fpsr;

	ut64	int_gp;
	ut64	int_t0;
	ut64	int_t1;
	ut64	int_s0;
	ut64	int_s1;
	ut64	int_s2;
	ut64	int_s3;
	ut64	int_v0;
	ut64	int_t2;
	ut64	int_t3;
	ut64	int_t4;
	ut64	int_sp;
	ut64	int_teb;
	ut64	int_t5;
	ut64	int_t6;
	ut64	int_t7;
	ut64	int_t8;
	ut64	int_t9;
	ut64	int_t10;
	ut64	int_t11;
	ut64	int_t12;
	ut64	int_t13;
	ut64	int_t14;
	ut64	int_t15;
	ut64	int_t16;
	ut64	int_t17;
	ut64	int_t18;
	ut64	int_t19;
	ut64	int_t20;
	ut64	int_t21;
	ut64	int_t22;

	ut64	int_nats;

	ut64	preds;

	ut64	br_rp;
	ut64	br_s0;
	ut64	br_s1;
	ut64	br_s2;
	ut64	br_s3;
	ut64	br_s4;
	ut64	br_t0;
	ut64	br_t1;

	ut64	ap_unat;
	ut64	ap_lc;
	ut64	ap_ec;
	ut64	ap_ccv;
	ut64	ap_dcr;

	ut64	rs_pfs;
	ut64	rs_bsp;
	ut64	rs_bspstore;
	ut64	rs_rsc;
	ut64	rs_rnat;

	ut64	st_ipsr;
	ut64	st_iip;
	ut64	st_ifs;

	ut64	st_fcr;
	ut64	eflag;
	ut64	seg_csd;
	ut64	seg_ssd;
	ut64	cflag;
	ut64	st_fsr;
	ut64	st_fir;
	ut64	st_fdr;

	ut64	unusedpack;
});

R_PACKED (
struct context_type_arm {
	ut32	context_flags;

	ut32	r0;
	ut32	r1;
	ut32	r2;
	ut32	r3;
	ut32	r4;
	ut32	r5;
	ut32	r6;
	ut32	r7;
	ut32	r8;
	ut32	r9;
	ut32	r10;
	ut32	r11;
	ut32	r12;

	ut32	sp;
	ut32	lr;
	ut32	pc;
	ut32	cpsr;

	ut32	fpscr;
	ut32	padding;
	union {
		struct windows_neon128 q[16];
		ut64 d[32];
		ut32 s[32];
	};

	ut32 bvr[ARM_MAX_BREAKPOINTS];
	ut32 bcr[ARM_MAX_BREAKPOINTS];
	ut32 wvr[ARM_MAX_WATCHPOINTS];
	ut32 wcr[ARM_MAX_WATCHPOINTS];
	ut32 padding_2[2];
});

R_PACKED (
struct windows_xsave_format32 {
	ut16	control_word;
	ut16	status_word;
	ut8	tag_word;
	ut8	reserved_1;
	ut16	error_opcode;
	ut32	error_offset;
	ut16	error_selector;
	ut16	reserved_2;
	ut32	data_offset;
	ut16	data_selector;
	ut16	reserved3;
	ut32	mx_csr;
	ut32	mx_csr_mask;
	struct windows_m128a float_registers[8];
	struct windows_m128a xmm_registers[8];
	ut8 reserved_4[224];
});

R_PACKED (
struct context_type_amd64 {
	ut64	p1_home;
	ut64	p2_home;
	ut64	p3_home;
	ut64	p4_home;
	ut64	p5_home;
	ut64	p6_home;

	ut32	context_flags;
	ut32	mx_csr;

	ut16	seg_cs;
	ut16	seg_ds;
	ut16	seg_es;
	ut16	seg_fs;
	ut16	seg_gs;
	ut16	seg_ss;
	ut32	e_flags;

	ut64	dr0;
	ut64	dr1;
	ut64	dr2;
	ut64	dr3;
	ut64	dr6;
	ut64	dr7;

	ut64	rax;
	ut64	rcx;
	ut64	rdx;
	ut64	rbx;
	ut64	rsp;
	ut64	rbp;
	ut64	rsi;
	ut64	rdi;
	ut64	r8;
	ut64	r9;
	ut64	r10;
	ut64	r11;
	ut64	r12;
	ut64	r13;
	ut64	r14;
	ut64	r15;

	ut64	rip;

	union {
		struct windows_xsave_format32 flt_save;
		struct {
			struct windows_m128a header[2];
			struct windows_m128a legacy[8];
			struct windows_m128a xmm_0;
			struct windows_m128a xmm_1;
			struct windows_m128a xmm_2;
			struct windows_m128a xmm_3;
			struct windows_m128a xmm_4;
			struct windows_m128a xmm_5;
			struct windows_m128a xmm_6;
			struct windows_m128a xmm_7;
			struct windows_m128a xmm_8;
			struct windows_m128a xmm_9;
			struct windows_m128a xmm_10;
			struct windows_m128a xmm_11;
			struct windows_m128a xmm_12;
			struct windows_m128a xmm_13;
			struct windows_m128a xmm_14;
			struct windows_m128a xmm_15;
		};
	};

	struct windows_m128a vector_register[26];
	ut64	vector_control;

	ut64	debugcontrol;
	ut64	last_branch_to_rip;
	ut64	last_branch_from_rip;
	ut64	last_exception_to_rip;
	ut64	last_exception_from_rip;
});

R_PACKED (
struct windows_exception_record32 {
	ut32	exception_code;
	ut32	exception_flags;
	struct windows_exception_record32 *exception_record;
	ut32	exception_address;
	ut32	number_parameters;
	ut32	exception_information[EXCEPTION_MAXIMUM_PARAMETERS];
});

R_PACKED (
struct windows_exception_record64 {
	ut32 exception_code;
	ut32 exception_flags;
	ut64 exception_record;
	ut64 exception_address;
	ut32 number_parameters;
	ut32 __unusedAlignment;
	ut64 exception_information[EXCEPTION_MAXIMUM_PARAMETERS];
});

R_PACKED (
struct exception_pointers_i386 {
	struct windows_exception_record32 *exception_record;
	void /*struct context*/ *context_record;
});

#endif /* MDMP_WINDEFS_H */
