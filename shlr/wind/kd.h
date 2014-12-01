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
	uint32_t req;
	uint16_t cpu_level;
	uint16_t cpu;
	uint32_t ret;
	// Pad to 16-byte boundary (?)
	uint32_t pad;
	union {
		struct {
			uint64_t addr;
			uint32_t length;
			uint32_t read;
		} __attribute__((packed)) r_mem;
		struct {
			uint16_t major;
			uint16_t minor;
			uint8_t  proto_major;
			uint8_t  proto_minor;
			uint16_t flags;
			uint16_t machine;
			uint8_t  misc[6];
			uint64_t kernel_base;
			uint64_t mod_addr;
			uint64_t dbg_addr;
		} __attribute__((packed)) r_ver;
		struct {
			uint32_t reason;
			uint32_t tf;
			uint32_t dr7;
			uint32_t css;
			uint32_t cse;
		} r_cont;
		struct {
			uint64_t addr;
			uint32_t handle;
		} r_set_bp;
		struct {
			uint32_t handle;
		} r_del_bp;
		struct {
			uint64_t addr;
			uint32_t flags;
		} r_set_ibp;
		struct {
			uint64_t addr;
			uint32_t flags;
			uint32_t calls;
		} r_get_ibp;
		struct {
			uint32_t flags;
		} r_ctx;
		struct {
			uint64_t addr;
			uint64_t reserved;
			uint32_t address_space;
			uint32_t flags;
		} r_query_mem;

		// Pad the struct to 56 bytes
		uint8_t raw[40];
	};
	uint8_t data[0];
} __attribute__((packed)) kd_req_t;

#define KD_EXC_BKPT 0x80000003

typedef struct kd_stc_64 {
	uint32_t state;
	uint16_t cpu_level;
	uint16_t cpu;
	uint32_t cpu_count;
	uint32_t pad1;
	uint64_t kthread;
	uint64_t pc;
	union {
		struct {
			uint32_t code;
			uint32_t flags;
			uint64_t ex_record;
			uint64_t ex_addr;
		} __attribute__((packed)) exception;
	};
} __attribute__((packed)) kd_stc_64;

typedef struct kd_ioc_t {
	uint32_t req;
	uint32_t ret;
	uint64_t pad[7];
} kd_ioc_t;

typedef struct kd_packet_t {
	uint32_t leader;
	uint16_t type;
	uint16_t length;
	uint32_t id;
	uint32_t checksum;
	uint8_t data[0];
} __attribute__((packed)) kd_packet_t;

// Compile time assertions macros taken from :
// http://www.pixelbeat.org/programming/gcc/static_assert.html
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define ct_assert(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }

ct_assert(sizeof(kd_packet_t)==16);
ct_assert(sizeof(kd_req_t)==56);
ct_assert(sizeof(kd_ioc_t)==64);

int kd_send_ctrl_packet (void *fp, const uint32_t type, const uint32_t id);
int kd_send_data_packet (void *fp, const uint32_t type, const uint32_t id, const uint8_t *req, const int req_len, const uint8_t *buf, const uint32_t buf_len);

int kd_read_packet (void *fp, kd_packet_t **p);

int kd_packet_is_valid (const kd_packet_t *p);
int kd_packet_is_ack (const kd_packet_t *p);

uint32_t kd_data_checksum (const uint8_t *buf, const uint64_t buf_len);

#endif
