/*
 * $QNXtpLicenseC:
 * Copyright 2005, QNX Software Systems. All Rights Reserved.
 *
 * This source code may contain confidential information of QNX Software
 * Systems (QSS) and its licensors.  Any use, reproduction, modification,
 * disclosure, distribution or transfer of this software, or any software
 * that includes or is based upon any of this code, is prohibited unless
 * expressly authorized by QSS by written agreement.  For more information
 * (including whether this source code file has been published) please
 * email licensing@qnx.com. $
*/

/*

   Copyright 2003 Free Software Foundation, Inc.

   Contributed by QNX Software Systems Ltd.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef __DSMSGS_H__
#define __DSMSGS_H__

/* These are the protocol versioning numbers.
   Update them with changes that introduce potential
   compatibility issues.  */
#define PDEBUG_PROTOVER_MAJOR 0x00000000
#define PDEBUG_PROTOVER_MINOR 0x00000003

#include <stddef.h>

/* These are pdebug specific errors, sent sometimes with the errno after
   an action failed.  Simply provides additional info on the reason for the
   error.  Sent in the DSrMsg_err_t.hdr.subcmd byte.  */

#define PDEBUG_ENOERR 0     /* No error.  */
#define PDEBUG_ENOPTY 1     /* No Pseudo Terminals found.  */
#define PDEBUG_ETHREAD 2    /* Thread Create error.  */
#define PDEBUG_ECONINV 3    /* Invalid Console number.  */
#define PDEBUG_ESPAWN 4     /* Spawn error.  */
#define PDEBUG_EPROCFS 5    /* NTO Proc File System error.  */
#define PDEBUG_EPROCSTOP 6  /* NTO Process Stop error.  */
#define PDEBUG_EQPSINFO 7   /* QNX4 PSINFO error.  */
#define PDEBUG_EQMEMMODEL 8 /* QNX4 - Flat Memory Model only supported.  */
#define PDEBUG_EQPROXY 9    /* QNX4 Proxy error.  */
#define PDEBUG_EQDBG 10     /* QNX4 qnx_debug_* error.  */

/* There is room for pdebugerrnos up to sizeof(ut8).

   We are moving away from the channel commands - only the RESET
   and NAK are required.  The DEBUG and TEXT channels are now part
   of the DShdr and TShdr structs, 4th byte.  GP June 1 1999.
   They are still supported, but not required.

   A packet containg a single byte is a set channel command.
   IE:  7e xx chksum 7e

   After a set channel all following packets are in the format
   for the specified channel.  Currently three channels are defined.
   The raw channel has no structure.  The other channels are all framed.
   The contents of each channel is defined by structures below.

   0 - Reset channel. Used when either end starts.

   1 - Debug channel with the structure which follows below.
       Uses DS (Debug Services) prefix.

   2 - Text channel with the structure which follows below.
       Uses TS (Text Services) prefix.

   0xff - Negative acknowledgment of a packet transmission.  */

#define SET_CHANNEL_RESET 0
#define SET_CHANNEL_DEBUG 1
#define SET_CHANNEL_TEXT 2
#define SET_CHANNEL_NAK 0xff

/* Debug channel Messages:   DS - Debug services.  */

/* Defines and structures for the debug channel.  */

#define DS_DATA_MAX_SIZE 1024
#define DS_DATA_RCV_SIZE(msg, total) \
	((total) - (sizeof(*(msg)) - DS_DATA_MAX_SIZE))
#define DS_MSG_OKSTATUS_FLAG 0x20000000
#define DS_MSG_OKDATA_FLAG 0x40000000
#define DS_MSG_NO_RESPONSE 0x80000000

#define QNXNTO_NSIG 57 /* From signals.h NSIG.  */

/* Common message header. It must be 32 or 64 bit aligned.
   The top bit of cmd is 1 for BIG endian data format.  */
#define DSHDR_MSG_BIG_ENDIAN 0x80
struct DShdr {
	ut8 cmd;
	ut8 subcmd;
	ut8 mid;
	ut8 channel;
};

/* Command types.  */
enum {
	DStMsg_connect,      /*  0  0x0 */
	DStMsg_disconnect,   /*  1  0x1 */
	DStMsg_select,       /*  2  0x2 */
	DStMsg_mapinfo,      /*  3  0x3 */
	DStMsg_load,	 /*  4  0x4 */
	DStMsg_attach,       /*  5  0x5 */
	DStMsg_detach,       /*  6  0x6 */
	DStMsg_kill,	 /*  7  0x7 */
	DStMsg_stop,	 /*  8  0x8 */
	DStMsg_memrd,	/*  9  0x9 */
	DStMsg_memwr,	/* 10  0xA */
	DStMsg_regrd,	/* 11  0xB */
	DStMsg_regwr,	/* 12  0xC */
	DStMsg_run,	  /* 13  0xD */
	DStMsg_brk,	  /* 14  0xE */
	DStMsg_fileopen,     /* 15  0xF */
	DStMsg_filerd,       /* 16  0x10 */
	DStMsg_filewr,       /* 17  0x11 */
	DStMsg_fileclose,    /* 18  0x12 */
	DStMsg_pidlist,      /* 19  0x13 */
	DStMsg_cwd,	  /* 20  0x14 */
	DStMsg_env,	  /* 21  0x15 */
	DStMsg_base_address, /* 22  0x16 */
	DStMsg_protover,     /* 23  0x17 */
	DStMsg_handlesig,    /* 24  0x18 */
	DStMsg_cpuinfo,      /* 25  0x19 */
	DStMsg_tidnames,     /* 26  0x1A */
	DStMsg_procfsinfo,   /* 27  0x1B */
	/* Room for new codes here.  */
	DSrMsg_err = 32, /* 32  0x20 */
	DSrMsg_ok,       /* 33  0x21 */
	DSrMsg_okstatus, /* 34  0x22 */
	DSrMsg_okdata,   /* 35  0x23 */
	/* Room for new codes here.  */
	DShMsg_notify = 64 /* 64  0x40 */
};

/* Subcommand types.  */
enum {
	DSMSG_LOAD_DEBUG,
	DSMSG_LOAD_RUN,
	DSMSG_LOAD_RUN_PERSIST,
	DSMSG_LOAD_INHERIT_ENV = 0x80
};

enum {
	DSMSG_ENV_CLEARARGV,
	DSMSG_ENV_ADDARG,
	DSMSG_ENV_CLEARENV,
	DSMSG_ENV_SETENV,
	DSMSG_ENV_SETENV_MORE
};

enum { DSMSG_STOP_PID,
       DSMSG_STOP_PIDS };

enum { DSMSG_SELECT_SET,
       DSMSG_SELECT_QUERY };

enum { DSMSG_KILL_PIDTID,
       DSMSG_KILL_PID,
       DSMSG_KILL_PIDS };

enum { DSMSG_MEM_VIRTUAL,
       DSMSG_MEM_PHYSICAL,
       DSMSG_MEM_IO,
       DSMSG_MEM_BASEREL };

enum {
	DSMSG_REG_GENERAL,
	DSMSG_REG_FLOAT,
	DSMSG_REG_SYSTEM,
	DSMSG_REG_ALT,
	DSMSG_REG_END
};

enum {
	DSMSG_RUN,
	DSMSG_RUN_COUNT,
	DSMSG_RUN_RANGE,
};

enum {
	DSMSG_PIDLIST_BEGIN,
	DSMSG_PIDLIST_NEXT,
	DSMSG_PIDLIST_SPECIFIC,
	DSMSG_PIDLIST_SPECIFIC_TID, /* *_TID - send starting tid for the request, */
};				    /* and the response will have total to be sent.  */

enum {
	DSMSG_CWD_QUERY,
	DSMSG_CWD_SET,
};

enum {
	DSMSG_MAPINFO_BEGIN = 0x01,
	DSMSG_MAPINFO_NEXT = 0x02,
	DSMSG_MAPINFO_SPECIFIC = 0x04,
	DSMSG_MAPINFO_ELF = 0x80,
};

enum {
	DSMSG_PROTOVER_MINOR =
		0x000000FF, /* bit field (status & DSMSG_PROTOVER_MAJOR) */
	DSMSG_PROTOVER_MAJOR =
		0x0000FF00, /* bit field (status & DSMSG_PROTOVER_MINOR) */
};

enum {
	DSMSG_BRK_EXEC = 0x0001,   /* Execution breakpoint.  */
	DSMSG_BRK_RD = 0x0002,     /* Read access (fail if not supported).  */
	DSMSG_BRK_WR = 0x0004,     /* Write access (fail if not supported).  */
	DSMSG_BRK_RW = 0x0006,     /* Read or write access (fail if not supported).  */
	DSMSG_BRK_MODIFY = 0x0008, /* Memory modified.  */
	DSMSG_BRK_RDM = 0x000a,    /* Read access if suported otherwise modified.  */
	DSMSG_BRK_WRM = 0x000c,    /* Write access if suported otherwise modified.  */
	DSMSG_BRK_RWM =
		0x000e,	/* Read or write access if suported otherwise modified.  */
	DSMSG_BRK_HW = 0x0010, /* Only use hardware debugging (i.e. no singlestep). */
};

enum {
	DSMSG_NOTIFY_PIDLOAD,   /* 0 */
	DSMSG_NOTIFY_TIDLOAD,   /* 1 */
	DSMSG_NOTIFY_DLLLOAD,   /* 2 */
	DSMSG_NOTIFY_PIDUNLOAD, /* 3 */
	DSMSG_NOTIFY_TIDUNLOAD, /* 4 */
	DSMSG_NOTIFY_DLLUNLOAD, /* 5 */
	DSMSG_NOTIFY_BRK,       /* 6 */
	DSMSG_NOTIFY_STEP,      /* 7 */
	DSMSG_NOTIFY_SIGEV,     /* 8 */
	DSMSG_NOTIFY_STOPPED    /* 9 */
};

/* Messages sent to the target. DStMsg_* (t - for target messages).  */

/* Connect to the agent running on the target.  */
typedef struct {
	struct DShdr hdr;
	ut8 major;
	ut8 minor;
	ut8 spare[2];
} DStMsg_connect_t;

/* Disconnect from the agent running on the target. */
typedef struct { struct DShdr hdr; } DStMsg_disconnect_t;

/* Select a pid, tid for subsequent messages or query their validity.  */
typedef struct {
	struct DShdr hdr;
	st32 pid;
	st32 tid;
} DStMsg_select_t;

/* Return information on what is at the specified virtual address.
   If nothing is there we return info on the next thing in the address.  */
typedef struct {
	struct DShdr hdr;
	st32 pid;
	st32 addr;
} DStMsg_mapinfo_t;

/* Load a new process into memory for a filesystem. */
typedef struct {
	struct DShdr hdr;
	st32 argc;
	st32 envc;
	char cmdline[DS_DATA_MAX_SIZE];
} DStMsg_load_t;

/* Attach to an already running process.  */
typedef struct {
	struct DShdr hdr;
	st32 pid;
} DStMsg_attach_t;

typedef DStMsg_attach_t DStMsg_procfsinfo_t;

/* Detach from a running process which was attached to or loaded.  */
typedef struct {
	struct DShdr hdr;
	st32 pid;
} DStMsg_detach_t;

/* Set a signal on a process.  */
typedef struct {
	struct DShdr hdr;
	st32 signo;
} DStMsg_kill_t;

/* Stop one or more processes/threads.  */
typedef struct { struct DShdr hdr; } DStMsg_stop_t;

/* Memory read request.  */
typedef struct {
	struct DShdr hdr;
	ut32 spare0;
	ut64 addr;
	ut16 size;
} DStMsg_memrd_t;

/* Memory write request.  */
typedef struct {
	struct DShdr hdr;
	ut32 spare0;
	ut64 addr;
	ut8 data[DS_DATA_MAX_SIZE];
} DStMsg_memwr_t;

/* Register read request.  */
typedef struct {
	struct DShdr hdr;
	ut16 offset;
	ut16 size;
} DStMsg_regrd_t;

/* Register write request.  */
typedef struct {
	struct DShdr hdr;
	ut16 offset;
	ut8 data[DS_DATA_MAX_SIZE];
} DStMsg_regwr_t;

/* Run.  */
typedef struct {
	struct DShdr hdr;
	union {
		ut32 count;
		ut32 addr[2];
	} step;
} DStMsg_run_t;

/* Break.  */
typedef struct {
	struct DShdr hdr;
	ut32 addr;
	ut32 size;
} DStMsg_brk_t;

/* Open a file on the target.  */
typedef struct {
	struct DShdr hdr;
	st32 mode;
	st32 perms;
	char pathname[DS_DATA_MAX_SIZE];
} DStMsg_fileopen_t;

/* Read a file on the target.  */
typedef struct {
	struct DShdr hdr;
	ut16 size;
} DStMsg_filerd_t;

/* Write a file on the target.  */
typedef struct {
	struct DShdr hdr;
	ut8 data[DS_DATA_MAX_SIZE];
} DStMsg_filewr_t;

/* Close a file on the target.  */
typedef struct {
	struct DShdr hdr;
	st32 mtime;
} DStMsg_fileclose_t;

/* Get pids and process names in the system.  */
typedef struct {
	struct DShdr hdr;
	st32 pid; /* Only valid for type subtype SPECIFIC.  */
	st32 tid; /* Tid to start reading from.  */
} DStMsg_pidlist_t;

/* Set current working directory of process.  */
typedef struct {
	struct DShdr hdr;
	ut8 path[DS_DATA_MAX_SIZE];
} DStMsg_cwd_t;

/* Clear, set, get environment for new process.  */
typedef struct {
	struct DShdr hdr;
	char data[DS_DATA_MAX_SIZE];
} DStMsg_env_t;

/* Get the base address of a process.  */
typedef struct { struct DShdr hdr; } DStMsg_baseaddr_t;

/* Send pdebug protocol version info, get the same in response_ok_status.  */
typedef struct {
	struct DShdr hdr;
	ut8 major;
	ut8 minor;
} DStMsg_protover_t;

/* Handle signal message.  */
typedef struct {
	struct DShdr hdr;
	ut8 signals[QNXNTO_NSIG];
	ut32 sig_to_pass;
} DStMsg_handlesig_t;

/* Get some cpu info.  */
typedef struct {
	struct DShdr hdr;
	ut32 spare;
} DStMsg_cpuinfo_t;

/* Get the names of the threads */
typedef struct {
	struct DShdr hdr;
	ut32 spare;
} DStMsg_tidnames_t;

/* Messages sent to the host. DStMsg_* (h - for host messages).  */

/* Notify host that something happened it needs to know about.  */
#define NOTIFY_HDR_SIZE offsetof (DShMsg_notify_t, un)
#define NOTIFY_MEMBER_SIZE(member) sizeof(member)

typedef struct {
	struct DShdr hdr;
	st32 pid;
	st32 tid;
	union {
		struct {
			ut32 codeoff;
			ut32 dataoff;
			ut16 ostype;
			ut16 cputype;
			ut32 cpuid; /* CPU dependant value.  */
			char name[DS_DATA_MAX_SIZE];
		} pidload;
		struct {
			st32 status;
		} pidunload;
		struct {
			st32 status;
			ut8 faulted;
			ut8 reserved[3];
		} pidunload_v3;
		struct {
			ut32 ip;
			ut32 dp;
			ut32 flags; /* Defined in <sys/debug.h>. */
		} brk;
		struct {
			ut32 ip;
			ut32 lastip;
		} step;
		struct {
			st32 signo;
			st32 code;
			st32 value;
		} sigev;
	} un;
} DShMsg_notify_t;

/* Responses to a message. DSrMsg_* (r - for response messages).  */

/* Error response packet.  */
typedef struct {
	struct DShdr hdr;
	st32 err;
} DSrMsg_err_t;

/* Simple OK response.  */
typedef struct { struct DShdr hdr; } DSrMsg_ok_t;

/* Simple OK response with a result.  Used where limited data needs
   to be returned.  For example, if the number of bytes which were
   successfully written was less than requested on any write cmd the
   status will be the number actually written.
   The 'subcmd' will always be zero.  */
typedef struct {
	struct DShdr hdr;
	st32 status;
} DSrMsg_okstatus_t;

/* The following structures overlay data[..] on a DSrMsg_okdata_t.  */
struct dslinkmap {
	ut32 addr;
	ut32 size;
	ut32 flags;
	ut32 debug_vaddr;
	ut64 offset;
};

struct dsmapinfo {
	struct dsmapinfo *next;
	ut32 spare0;
	ut64 ino;
	ut32 dev;
	ut32 spare1;
	struct dslinkmap text;
	struct dslinkmap data;
	char name[256];
};

struct dspidlist {
	st32 pid;
	st32 num_tids; /* Num of threads this pid has.  */
	st32 spare[6];
	struct tidinfo {
		st16 tid;
		ut8 state;
		ut8 flags;
	} tids[1];    /* Variable length terminated by tid==0.  */
	char name[1]; /* Variable length terminated by \0.  */
};

struct dscpuinfo {
	ut32 cpuflags;
	ut32 spare1;
	ut32 spare2;
	ut32 spare3;
};

struct dstidnames {
	ut32 numtids;
	ut32 numleft;
	ut32 spare1;
	ut32 spare2;
	char data[1]; /* A bunch of string data tidNULLnameNULL... */
};

/* Long OK response with 0..DS_DATA_MAX_SIZE data.
   The 'subcmd' will always be zero.  */
typedef struct {
	struct DShdr hdr;
	ut8 data[DS_DATA_MAX_SIZE];
} DSrMsg_okdata_t;

/* A union of all possible messages and responses.  */
typedef union {
	struct DShdr hdr;
	DStMsg_connect_t connect;
	DStMsg_disconnect_t disconnect;
	DStMsg_select_t select;
	DStMsg_load_t load;
	DStMsg_attach_t attach;
	DStMsg_procfsinfo_t procfsinfo;
	DStMsg_detach_t detach;
	DStMsg_kill_t kill;
	DStMsg_stop_t stop;
	DStMsg_memrd_t memrd;
	DStMsg_memwr_t memwr;
	DStMsg_regrd_t regrd;
	DStMsg_regwr_t regwr;
	DStMsg_run_t run;
	DStMsg_brk_t brk;
	DStMsg_fileopen_t fileopen;
	DStMsg_filerd_t filerd;
	DStMsg_filewr_t filewr;
	DStMsg_fileclose_t fileclose;
	DStMsg_pidlist_t pidlist;
	DStMsg_mapinfo_t mapinfo;
	DStMsg_cwd_t cwd;
	DStMsg_env_t env;
	DStMsg_baseaddr_t baseaddr;
	DStMsg_protover_t protover;
	DStMsg_handlesig_t handlesig;
	DStMsg_cpuinfo_t cpuinfo;
	DStMsg_tidnames_t tidnames;
	DShMsg_notify_t notify;
	DSrMsg_err_t err;
	DSrMsg_ok_t ok;
	DSrMsg_okstatus_t okstatus;
	DSrMsg_okdata_t okdata;
} DSMsg_union_t;

/* Text channel Messages:   TS - Text services.  */
#define TS_TEXT_MAX_SIZE 100

/* Command types.  */
enum {
	TSMsg_text,  /* 0 */
	TSMsg_done,  /* 1 */
	TSMsg_start, /* 2 */
	TSMsg_stop,  /* 3 */
	TSMsg_ack,   /* 4 */
};

struct TShdr {
	ut8 cmd;
	ut8 console;
	ut8 spare1;
	ut8 channel;
};

/* Deliver text.  This message can be sent by either side.
   The debugger displays it in a window.  The agent gives it to a pty
   which a program may be listening on.  */
typedef struct {
	struct TShdr hdr;
	char text[TS_TEXT_MAX_SIZE];
} TSMsg_text_t;

/* There is no longer a program connected to this console. */
typedef struct { struct TShdr hdr; } TSMsg_done_t;

/* TextStart or TextStop flow control. */
typedef struct { struct TShdr hdr; } TSMsg_flowctl_t;

/* Ack a flowctl message. */
typedef struct { struct TShdr hdr; } TSMsg_ack_t;

#endif
