// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3
#ifndef KD_H
#define KD_H
#include <r_types_base.h>
#include "transport.h"

enum {
	KD_E_OK			=  0,
	KD_E_BADCHKSUM	= -1,
	KD_E_TIMEOUT	= -2,
	KD_E_MALFORMED	= -3,
	KD_E_IOERR		= -4,
};

enum KD_PACKET_TYPE {
	KD_PACKET_TYPE_UNUSED = 0,
	KD_PACKET_TYPE_STATE_CHANGE32 = 1,
	KD_PACKET_TYPE_STATE_MANIPULATE = 2,
	KD_PACKET_TYPE_DEBUG_IO = 3,
	KD_PACKET_TYPE_ACKNOWLEDGE = 4,
	KD_PACKET_TYPE_RESEND = 5,
	KD_PACKET_TYPE_RESET = 6,
	KD_PACKET_TYPE_STATE_CHANGE64 = 7,
	KD_PACKET_TYPE_POLL_BREAKIN = 8,
	KD_PACKET_TYPE_TRACE_IO = 9,
	KD_PACKET_TYPE_CONTROL_REQUEST = 10,
	KD_PACKET_TYPE_FILE_IO = 11
};

enum KD_PACKET_WAIT_STATE_CHANGE {
	DbgKdMinimumStateChange             = 0x00003030,
	DbgKdExceptionStateChange           = 0x00003030,
	DbgKdLoadSymbolsStateChange         = 0x00003031,
	DbgKdCommandStringStateChange       = 0x00003032,
	DbgKdMaximumStateChange             = 0x00003033
};

enum KD_PACKET_MANIPULATE_TYPE {
	DbgKdMinimumManipulate              = 0x00003130,
	DbgKdReadVirtualMemoryApi           = 0x00003130,
	DbgKdWriteVirtualMemoryApi          = 0x00003131,
	DbgKdGetContextApi                  = 0x00003132,
	DbgKdSetContextApi                  = 0x00003133,
	DbgKdWriteBreakPointApi             = 0x00003134,
	DbgKdRestoreBreakPointApi           = 0x00003135,
	DbgKdContinueApi                    = 0x00003136,
	DbgKdReadControlSpaceApi            = 0x00003137,
	DbgKdWriteControlSpaceApi           = 0x00003138,
	DbgKdReadIoSpaceApi                 = 0x00003139,
	DbgKdWriteIoSpaceApi                = 0x0000313A,
	DbgKdRebootApi                      = 0x0000313B,
	DbgKdContinueApi2                   = 0x0000313C,
	DbgKdReadPhysicalMemoryApi          = 0x0000313D,
	DbgKdWritePhysicalMemoryApi         = 0x0000313E,
	DbgKdQuerySpecialCallsApi           = 0x0000313F,
	DbgKdSetSpecialCallApi              = 0x00003140,
	DbgKdClearSpecialCallsApi           = 0x00003141,
	DbgKdSetInternalBreakPointApi       = 0x00003142,
	DbgKdGetInternalBreakPointApi       = 0x00003143,
	DbgKdReadIoSpaceExtendedApi         = 0x00003144,
	DbgKdWriteIoSpaceExtendedApi        = 0x00003145,
	DbgKdGetVersionApi                  = 0x00003146,
	DbgKdWriteBreakPointExApi           = 0x00003147,
	DbgKdRestoreBreakPointExApi         = 0x00003148,
	DbgKdCauseBugCheckApi               = 0x00003149,
	DbgKdSwitchProcessor                = 0x00003150,
	DbgKdPageInApi                      = 0x00003151,
	DbgKdReadMachineSpecificRegister    = 0x00003152,
	DbgKdWriteMachineSpecificRegister   = 0x00003153,
	OldVlm1                             = 0x00003154,
	OldVlm2                             = 0x00003155,
	DbgKdSearchMemoryApi                = 0x00003156,
	DbgKdGetBusDataApi                  = 0x00003157,
	DbgKdSetBusDataApi                  = 0x00003158,
	DbgKdCheckLowMemoryApi              = 0x00003159,
	DbgKdClearAllInternalBreakpointsApi = 0x0000315A,
	DbgKdFillMemoryApi                  = 0x0000315B,
	DbgKdQueryMemoryApi                 = 0x0000315C,
	DbgKdSwitchPartition                = 0x0000315D,
	DbgKdMaximumManipulate              = 0x0000315E
};

#define KD_PACKET_UNUSED 0x00000000
#define KD_PACKET_DATA 0x30303030
#define KD_PACKET_CTRL 0x69696969

#define KD_MAX_PAYLOAD	0x800
#define KD_PACKET_MAX_SIZE 4000 // Not used ? What is max payload ?

// http://msdn.microsoft.com/en-us/library/cc704588.aspx
#define KD_RET_OK		0x00000000
#define KD_RET_ERR		0xC0000001
#define KD_RET_ENOENT	0xC000000F

#define KD_MACH_I386	 0x014C
#define KD_MACH_IA64	 0x0200
#define KD_MACH_AMD64	 0x8664
#define KD_MACH_ARM		 0x01c0
#define KD_MACH_EBC		 0x0EBC

#define DBGKD_VERS_FLAG_DATA	0x0002
#define DBGKD_VERS_FLAG_PTR64	0x0004

R_PACKED (
typedef struct kd_req_t {
	uint32_t req;
	uint16_t cpu_level;
	uint16_t cpu;
	uint32_t ret;
	// Pad to 16-byte boundary (?)
	uint32_t pad;
	union {
		R_PACKED(
		struct {
			uint64_t addr;
			uint32_t length;
			uint32_t read;
		}) r_mem;
		R_PACKED (
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
		}) r_ver;
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
}) kd_req_t;

#define KD_EXC_BKPT 0x80000003
R_PACKED (
typedef struct kd_stc_64 {
	uint32_t state;
	uint16_t cpu_level;
	uint16_t cpu;
	uint32_t cpu_count;
	uint32_t pad1;
	uint64_t kthread;
	uint64_t pc;
	union {
		R_PACKED (
		struct {
			uint32_t code;
			uint32_t flags;
			uint64_t ex_record;
			uint64_t ex_addr;
		}) exception;
	};
}) kd_stc_64;

typedef struct kd_ioc_t {
	uint32_t req;
	uint32_t ret;
	uint64_t pad[7];
} kd_ioc_t;

R_PACKED (
typedef struct kd_packet_t {
	uint32_t leader;
	uint16_t type;
	uint16_t length;
	uint32_t id;
	uint32_t checksum;
	uint8_t data[0];
}) kd_packet_t;

// KDNET

#define KDNET_MAGIC 0x4d444247 // MDBG
#define KDNET_HMACKEY_SIZE 32
#define KDNET_HMAC_SIZE 16

#define KDNET_PACKET_TYPE_DATA 0
#define KDNET_PACKET_TYPE_CONTROL 1

R_PACKED (
typedef struct kdnet_packet_t {
	ut32 magic; // KDNET_MAGIC
	ut8 version; // Protocol Number
	ut8 type; // Channel Type - 0 Data, 1 Control
}) kdnet_packet_t;

// KDNet Data mask
#define KDNET_DATA_SIZE 8
#define KDNET_DATA_DIRECTION_MASK 0x80
#define KDNET_DATA_PADSIZE_MASK 0x7F
#define KDNET_DATA_SEQNO_MASK 0xFFFFFF00

// Compile time assertions macros taken from :
// http://www.pixelbeat.org/programming/gcc/static_assert.html
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define ct_assert(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }

ct_assert(sizeof(kd_packet_t)==16);
ct_assert(sizeof(kd_req_t)==56);
ct_assert(sizeof(kd_ioc_t)==64);

int kd_send_ctrl_packet(io_desc_t *desc, const uint32_t type, const uint32_t id);
int kd_send_data_packet(io_desc_t *desc, const uint32_t type, const uint32_t id, const uint8_t *req, const int req_len, const uint8_t *buf, const uint32_t buf_len);

int kd_read_packet(io_desc_t *desc, kd_packet_t **p);

bool kd_packet_is_valid(const kd_packet_t *p);
int kd_packet_is_ack(const kd_packet_t *p);

uint32_t kd_data_checksum(const uint8_t *buf, const uint64_t buf_len);

#endif
