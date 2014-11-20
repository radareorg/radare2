// Copyright (c) 2014, The Lemon Man, All rights reserved.

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

// Some documentation of the data structures has been kindly ripped off ReactOS project.

#ifndef KD_H
#define KD_H

enum {
	KD_E_OK			=  0,
	KD_E_BADCHKSUM	= -1,
	KD_E_TIMEOUT	= -2,
	KD_E_MALFORMED	= -3,
	KD_E_IOERR		= -4,
};

#define KD_PACKET_DATA 0x30303030
#define KD_PACKET_CTRL 0x69696969

#define KD_MAX_PAYLOAD	0x800

#define KD_PACKET_TYPE_MANIP	2
#define KD_PACKET_TYPE_ACK		4
#define KD_PACKET_TYPE_RESEND	5
#define KD_PACKET_TYPE_RESET	6
#define KD_PACKET_TYPE_STATE_CHANGE 7
#define KD_PACKET_TYPE_IO		11

// http://msdn.microsoft.com/en-us/library/cc704588.aspx
#define KD_RET_OK		0x00000000
#define KD_RET_ERR		0xC0000001
#define KD_RET_ENOENT	0xC000000F
#define KD_DBG_CONT		0x00010001

#define KD_MACH_I386	 0x014C
#define KD_MACH_IA64	 0x0200
#define KD_MACH_AMD64	 0x8664
#define KD_MACH_ARM		 0x01c0
#define KD_MACH_EBC		 0x0EBC

#define DBGKD_VERS_FLAG_DATA	0x0002
#define DBGKD_VERS_FLAG_PTR64	0x0004

typedef struct kd_req_t {
	ut32 req;
	ut16 cpu_level;
	ut16 cpu;
	ut32 ret;
	// Pad to 16-byte boundary (?)
	ut32 pad;
	union {
		struct {
			ut64 addr;
			ut32 length;
			ut32 read;
		} __attribute__((packed)) r_mem;
		struct {
			ut16 major;
			ut16 minor;
			ut8  proto_major;
			ut8  proto_minor;
			ut16 flags;
			ut16 machine;
			ut8  misc[6];
			ut64 kernel_base;
			ut64 mod_addr;
			ut64 dbg_addr;
		} __attribute__((packed)) r_ver;
		struct {
			ut32 reason;
			ut32 ctrl_set[4];
		} r_cont;
		struct {
			ut64 addr;
			ut32 handle;
		} r_set_bp;
		struct {
			ut32 handle;
		} r_del_bp;
		struct {
			ut64 addr;
			ut32 flags;
		} r_set_ibp;
		struct {
			ut64 addr;
			ut32 flags;
			ut32 calls;
		} r_get_ibp;
		struct {
			ut32 flags;
		} r_ctx;

		// Pad the struct to 56 bytes
		ut8 raw[40];
	};
	ut8 data[0];
} __attribute__((packed)) kd_req_t;

#define KD_EXC_BKPT 0x80000003

typedef struct kd_stc_64 {
	ut32 state;
	ut16 cpu_level;
	ut16 cpu;
	ut32 cpu_count;
	ut32 pad1;
	ut64 kthread;
	ut64 pc;
	union {
		struct {
			ut32 code;
			ut32 flags;
			ut64 ex_record;
			ut64 ex_addr;
		} __attribute__((packed)) exception;
	};
} __attribute__((packed)) kd_stc_64;

typedef struct kd_ioc_t {
	ut32 req;
	ut32 ret;
	ut64 pad[7];
} kd_ioc_t;

typedef struct kd_packet_t {
	ut32 leader;
	ut16 type;
	ut16 length;
	ut32 id;
	ut32 checksum;
	ut8 data[0];
} __attribute__((packed)) kd_packet_t;

// Compile time assertions macros taken from :
// http://www.pixelbeat.org/programming/gcc/static_assert.html
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define ct_assert(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }

ct_assert(sizeof(kd_packet_t)==16);
ct_assert(sizeof(kd_req_t)==56);
ct_assert(sizeof(kd_ioc_t)==64);

int kd_send_ctrl_packet (void *fp, const ut32 type, const ut32 id);
int kd_send_data_packet (void *fp, const ut32 type, const ut32 id, const ut8 *req, const int req_len, const ut8 *buf, const ut32 buf_len);

int kd_read_packet (void *fp, kd_packet_t **p);

int kd_packet_is_valid (const kd_packet_t *p);
int kd_packet_is_ack (const kd_packet_t *p);

ut32 kd_data_checksum (const ut8 *buf, const ut64 buf_len);

#endif
