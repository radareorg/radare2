// XXX: This file describes too many things and some of them are not portable.
/*
 * sftypes.h -- shellforge lib types
 *              see http://www.cartel-securite.net/pbiondi/shellforge.html
 *              for more informations
 *
 * Copyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/* $Id$ */

#ifndef SFTYPES_H
#define SFTYPES_H


#define NULL ((void*)0)


/* XXX this is far from true on every architecture! */
typedef unsigned long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long int64_t;
typedef int int32_t;
typedef short int16_t;
typedef char int8_t;


typedef int pid_t;
typedef int ssize_t;
typedef int size_t;
typedef int off_t;
typedef int mode_t;
typedef int clock_t;
typedef int uid_t;
typedef int gid_t;
typedef void (*sighandler_t)(int);

struct dirent {
    int d_ino;
    int d_off;
    unsigned short int d_reclen;
    char d_name[256];
};

struct tms {
       clock_t tms_utime;  /* user time */
       clock_t tms_stime;  /* system time */
       clock_t tms_cutime; /* user time of children */
       clock_t tms_cstime; /* system time of children */
};
typedef int dev_t;
typedef int caddr_t;
typedef int sigset_t;
typedef int cap_user_header_t;
typedef int cap_user_data_t;
typedef int time_t;
struct vm86plus_struct {};
typedef int ptrdiff_t;
struct utimbuf {};
struct __sysctl_args {};
struct timezone {};
struct sysinfo{};
struct iovec {};
struct statfs {};
struct pollfd {};
struct kernel_sym {};
struct module {};
struct utsname {};
struct ustat {};
struct stat {};
struct sched_param {};
struct timeval 
{
	long    tv_sec;         /* seconds */
	long    tv_usec;        /* microseconds */
};
struct timespec
{
	time_t  tv_sec;         /* seconds */
	long    tv_nsec;        /* nanoseconds */
};



#define PROT_READ       0x1             /* Page can be read.  */
#define PROT_WRITE      0x2             /* Page can be written.  */
#define PROT_EXEC       0x4             /* Page can be executed.  */
#define PROT_NONE       0x0             /* Page can not be accessed.  */

/* Sharing types (must choose one and only one of these).  */
#define MAP_SHARED      0x01            /* Share changes.  */
#define MAP_PRIVATE     0x02            /* Changes are private.  */
#define MAP_TYPE       0x0f            /* Mask for type of mapping.  */
#define MAP_FIXED       0x10            /* Interpret addr exactly.  */
#define MAP_FILE       0
#define MAP_ANONYMOUS  0x20            /* Don't use a file.  */
#define MAP_ANON       MAP_ANONYMOUS

/**************** Error codes *****************/

#define EPERM            1      /* Operation not permitted */
#define ENOENT           2      /* No such file or directory */
#define ESRCH            3      /* No such process */
#define EINTR            4      /* Interrupted system call */
#define EIO              5      /* I/O error */
#define ENXIO            6      /* No such device or address */
#define E2BIG            7      /* Argument list too long */
#define ENOEXEC          8      /* Exec format error */
#define EBADF            9      /* Bad file number */
#define ECHILD          10      /* No child processes */
#define EAGAIN          11      /* Try again */
#define ENOMEM          12      /* Out of memory */
#define EACCES          13      /* Permission denied */
#define EFAULT          14      /* Bad address */
#define ENOTBLK         15      /* Block device required */
#define EBUSY           16      /* Device or resource busy */
#define EEXIST          17      /* File exists */
#define EXDEV           18      /* Cross-device link */
#define ENODEV          19      /* No such device */
#define ENOTDIR         20      /* Not a directory */
#define EISDIR          21      /* Is a directory */
#define EINVAL          22      /* Invalid argument */
#define ENFILE          23      /* File table overflow */
#define EMFILE          24      /* Too many open files */
#define ENOTTY          25      /* Not a typewriter */
#define ETXTBSY         26      /* Text file busy */
#define EFBIG           27      /* File too large */
#define ENOSPC          28      /* No space left on device */
#define ESPIPE          29      /* Illegal seek */
#define EROFS           30      /* Read-only file system */
#define EMLINK          31      /* Too many links */
#define EPIPE           32      /* Broken pipe */
#define EDOM            33      /* Math argument out of domain of func */
#define ERANGE          34      /* Math result not representable */

#define ESTRPIPE        86      /* Streams pipe error */
#define EUSERS          87      /* Too many users */
#define ENOTSOCK        88      /* Socket operation on non-socket */
#define EDESTADDRREQ    89      /* Destination address required */
#define EMSGSIZE        90      /* Message too long */
#define EPROTOTYPE      91      /* Protocol wrong type for socket */
#define ENOPROTOOPT     92      /* Protocol not available */
#define EPROTONOSUPPORT 93      /* Protocol not supported */
#define ESOCKTNOSUPPORT 94      /* Socket type not supported */
#define EOPNOTSUPP      95      /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT    96      /* Protocol family not supported */
#define EAFNOSUPPORT    97      /* Address family not supported by protocol */
#define EADDRINUSE      98      /* Address already in use */
#define EADDRNOTAVAIL   99      /* Cannot assign requested address */
#define ENETDOWN        100     /* Network is down */
#define ENETUNREACH     101     /* Network is unreachable */
#define ENETRESET       102     /* Network dropped connection because of reset */
#define ECONNABORTED    103     /* Software caused connection abort */
#define ECONNRESET      104     /* Connection reset by peer */
#define ENOBUFS         105     /* No buffer space available */
#define EISCONN         106     /* Transport endpoint is already connected */
#define ENOTCONN        107     /* Transport endpoint is not connected */
#define ESHUTDOWN       108     /* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS    109     /* Too many references: cannot splice */
#define ETIMEDOUT       110     /* Connection timed out */
#define ECONNREFUSED    111     /* Connection refused */
#define EHOSTDOWN       112     /* Host is down */
#define EHOSTUNREACH    113     /* No route to host */
#define EALREADY        114     /* Operation already in progress */
#define EINPROGRESS     115     /* Operation now in progress */
#define ESTALE          116     /* Stale NFS file handle */
#define EUCLEAN         117     /* Structure needs cleaning */
#define ENOTNAM         118     /* Not a XENIX named type file */
#define ENAVAIL         119     /* No XENIX semaphores available */
#define EISNAM          120     /* Is a named type file */
#define EREMOTEIO       121     /* Remote I/O error */
#define EDQUOT          122     /* Quota exceeded */



/**************** Select *******************************/

typedef long int fd_mask;

#define FD_SETSIZE 1024

#define NFDBITS       (8 * sizeof (fd_mask))
#define __FDELT(d)      ((d) / NFDBITS)
#define FDMASK(d)     ((fd_mask) 1 << ((d) % NFDBITS))

typedef struct
  {
    fd_mask fds_bits[FD_SETSIZE / NFDBITS];
  } fd_set;

# define __FDS_BITS(set) ((set)->fds_bits)


#define FD_ZERO(set)  \
  do {                                                                   \
    unsigned int __i;                                                    \
    fd_set *__arr = (set);                                               \
    for (__i = 0; __i < sizeof (fd_set) / sizeof (fd_mask); ++__i)       \
      __FDS_BITS (__arr)[__i] = 0;                                       \
  } while (0)

#define FD_SET(d, set)    (__FDS_BITS (set)[__FDELT (d)] |= FDMASK (d))
#define FD_CLR(d, set)    (__FDS_BITS (set)[__FDELT (d)] &= ~FDMASK (d))
#define FD_ISSET(d, set)  (__FDS_BITS (set)[__FDELT (d)] & FDMASK (d))

/**************** Sockets and network *******************/


typedef unsigned int socklen_t;

/* SOCK_ constants */
enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,               /* Connectionless, unreliable datagrams
                                   of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,                 /* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,                 /* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,           /* Sequenced, reliable, connection-based,
                                   datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_PACKET = 10              /* Linux specific way of getting packets
                                   at the dev level.  For writing rarp and
                                   other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET
};
	
/* Protocol families.  */
#define PF_UNSPEC       0       /* Unspecified.  */
#define PF_LOCAL        1       /* Local to host (pipes and file-domain).  */
#define PF_UNIX         PF_LOCAL /* Old BSD name for PF_LOCAL.  */
#define PF_FILE         PF_LOCAL /* Another non-standard name for PF_LOCAL.  */
#define PF_INET         2       /* IP protocol family.  */
#define PF_AX25         3       /* Amateur Radio AX.25.  */
#define PF_IPX          4       /* Novell Internet Protocol.  */
#define PF_APPLETALK    5       /* Appletalk DDP.  */
#define PF_NETROM       6       /* Amateur radio NetROM.  */
#define PF_BRIDGE       7       /* Multiprotocol bridge.  */
#define PF_ATMPVC       8       /* ATM PVCs.  */
#define PF_X25          9       /* Reserved for X.25 project.  */
#if __linux__
#define PF_INET6        28      /* IP version 6 on linux.  */
#endif

#if __FreeBSD__
#define PF_INET6        10      /* IP version 6.  */
#endif

#define PF_ROSE         11      /* Amateur Radio X.25 PLP.  */
#define PF_DECnet       12      /* Reserved for DECnet project.  */
#define PF_NETBEUI      13      /* Reserved for 802.2LLC project.  */
#define PF_SECURITY     14      /* Security callback pseudo AF.  */
#define PF_KEY          15      /* PF_KEY key management API.  */
#define PF_NETLINK      16
#define PF_ROUTE        PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define PF_PACKET       17      /* Packet family.  */
#define PF_ASH          18      /* Ash.  */
#define PF_ECONET       19      /* Acorn Econet.  */
#define PF_ATMSVC       20      /* ATM SVCs.  */
#define PF_SNA          22      /* Linux SNA Project */
#define PF_IRDA         23      /* IRDA sockets.  */
#define PF_PPPOX        24      /* PPPoX sockets.  */
#define PF_WANPIPE      25      /* Wanpipe API sockets.  */
#define PF_BLUETOOTH    31      /* Bluetooth sockets.  */
#define PF_MAX          32      /* For now..  */

	/* Address families.  */
#define AF_UNSPEC       PF_UNSPEC
#define AF_LOCAL        PF_LOCAL
#define AF_UNIX         PF_UNIX
#define AF_FILE         PF_FILE
#define AF_INET         PF_INET
#define AF_AX25         PF_AX25
#define AF_IPX          PF_IPX
#define AF_APPLETALK    PF_APPLETALK
#define AF_NETROM       PF_NETROM
#define AF_BRIDGE       PF_BRIDGE
#define AF_ATMPVC       PF_ATMPVC
#define AF_X25          PF_X25
#define AF_INET6        PF_INET6
#define AF_ROSE         PF_ROSE
#define AF_DECnet       PF_DECnet
#define AF_NETBEUI      PF_NETBEUI
#define AF_SECURITY     PF_SECURITY
#define AF_KEY          PF_KEY
#define AF_NETLINK      PF_NETLINK
#define AF_ROUTE        PF_ROUTE
#define AF_PACKET       PF_PACKET
#define AF_ASH          PF_ASH
#define AF_ECONET       PF_ECONET
#define AF_ATMSVC       PF_ATMSVC
#define AF_SNA          PF_SNA
#define AF_IRDA         PF_IRDA
#define AF_PPPOX        PF_PPPOX
#define AF_WANPIPE      PF_WANPIPE
#define AF_BLUETOOTH    PF_BLUETOOTH
#define AF_MAX          PF_MAX

#define SOL_RAW         255
#define SOL_DECNET      261
#define SOL_X25         262
#define SOL_PACKET      263
#define SOL_ATM         264     /* ATM layer (cell level).  */
#define SOL_AAL         265     /* ATM Adaption Layer (packet level).  */
#define SOL_IRDA        266

typedef unsigned short int sa_family_t;
#define __SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family
#define __SOCKADDR_COMMON_SIZE  (sizeof (unsigned short int))

struct sockaddr
  {
     __SOCKADDR_COMMON (sa_);    /* Common data: address family and length.  */
     char sa_data[14];           /* Address data.  */
  };

typedef unsigned int in_addr_t;
typedef unsigned short in_port_t;
struct in_addr
  {
    in_addr_t s_addr;
  };

struct sockaddr_in
  {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;                 /* Port number.  */
    struct in_addr sin_addr;            /* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr) -
                           __SOCKADDR_COMMON_SIZE -
                           sizeof (in_port_t) -
                           sizeof (struct in_addr)];
  };

struct sockaddr_un
{
  __SOCKADDR_COMMON (sun_);
  char sun_path[108];         /* Path name.  */
};

struct in6_addr
{
	union
	{
		uint8_t __u6_addr8[16];
	} __in6_u;
};

#define IN6ADDR_ANY_INIT {{{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}}
static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

struct sockaddr_in6
{
	__SOCKADDR_COMMON (sin6_);
	in_port_t sin6_port;    /* Transport layer port # */
	uint32_t sin6_flowinfo; /* IPv6 flow information */
	struct in6_addr sin6_addr;  /* IPv6 address */
	uint32_t sin6_scope_id; /* IPv6 scope-id */
};

/**** Ancillairy messages ****/

enum
  {
    SCM_RIGHTS = 0x01,          /* Transfer file descriptors.  */
#define SCM_RIGHTS SCM_RIGHTS
#ifdef __USE_BSD
    SCM_CREDENTIALS = 0x02,     /* Credentials passing.  */
# define SCM_CREDENTIALS SCM_CREDENTIALS
#endif
    __SCM_CONNECT = 0x03        /* Data array is `struct scm_connect'.  */
  };

struct msghdr
  {
    void *msg_name;             /* Address to send to/receive from.  */
    socklen_t msg_namelen;      /* Length of address data.  */

    struct iovec *msg_iov;      /* Vector of data to send/receive into.  */
    size_t msg_iovlen;          /* Number of elements in the vector.  */

    void *msg_control;          /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;      /* Ancillary data buffer length.  */

    int msg_flags;              /* Flags on received message.  */
  };

/* Structure used for storage of ancillary data object information.  */
struct cmsghdr
  {
    size_t cmsg_len;            /* Length of data in cmsg_data plus length
                                   of cmsghdr structure.  */
    int cmsg_level;             /* Originating protocol.  */
    int cmsg_type;              /* Protocol specific type.  */
  };


# define CMSG_DATA(cmsg) ((unsigned char *) ((struct cmsghdr *) (cmsg) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr (mhdr, cmsg)
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr)                 \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) NULL)
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
                         & (size_t) ~(sizeof (size_t) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN (len) \
                         + CMSG_ALIGN (sizeof (struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))

#define SOL_SOCKET      1

#define SO_DEBUG        1
#define SO_REUSEADDR    2
#define SO_TYPE         3
#define SO_ERROR        4
#define SO_DONTROUTE    5
#define SO_BROADCAST    6
#define SO_SNDBUF       7
#define SO_RCVBUF       8
#define SO_KEEPALIVE    9
#define SO_OOBINLINE    10
#define SO_NO_CHECK     11
#define SO_PRIORITY     12
#define SO_LINGER       13
#define SO_BSDCOMPAT    14
/* To add :#define SO_REUSEPORT 15 */
#define SO_PASSCRED     16
#define SO_PEERCRED     17
#define SO_RCVLOWAT     18
#define SO_SNDLOWAT     19
#define SO_RCVTIMEO     20
#define SO_SNDTIMEO     21

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION              22
#define SO_SECURITY_ENCRYPTION_TRANSPORT        23
#define SO_SECURITY_ENCRYPTION_NETWORK          24

#define SO_BINDTODEVICE 25

/* Socket filtering */
#define SO_ATTACH_FILTER        26
#define SO_DETACH_FILTER        27

#define SO_PEERNAME             28
#define SO_TIMESTAMP            29
#define SCM_TIMESTAMP           SO_TIMESTAMP

#define SO_ACCEPTCONN           30



#ifdef SF_BIGENDIAN
#define IP(t,z,y,x)  ((x)|(y)<<8|(z)<<16|(t)<<24)
#define htons(x) (x)
#else
#define IP(x,y,z,t)  ((x)|(y)<<8|(z)<<16|(t)<<24)
#define htons(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#endif

#define ntohs(x) htons(x)
#define SA_IN(sa, ip, port) do{ (sa).sin_family=PF_INET; \
	                        (sa).sin_port=(htons(port)); \
				(sa).sin_addr.s_addr=(ip); \
			    }while(0)


#define O_ACCMODE          0003
#define O_RDONLY             00
#define O_WRONLY             01
#define O_RDWR               02
#define O_CREAT            0100 /* not fcntl */
#define O_EXCL             0200 /* not fcntl */
#define O_NOCTTY           0400 /* not fcntl */
#define O_TRUNC           01000 /* not fcntl */
#define O_APPEND          02000
#define O_NONBLOCK        04000
#define O_NDELAY        O_NONBLOCK
#define O_SYNC           010000
#define FASYNC           020000 /* fcntl, for BSD compatibility */
#define O_DIRECT         040000 /* direct disk access hint */
#define O_LARGEFILE     0100000
#define O_DIRECTORY     0200000 /* must be a directory */
#define O_NOFOLLOW      0400000 /* don't follow links */

#define F_DUPFD         0       /* dup */
#define F_GETFD         1       /* get close_on_exec */
#define F_SETFD         2       /* set/clear close_on_exec */
#define F_GETFL         3       /* get file->f_flags */
#define F_SETFL         4       /* set file->f_flags */
#define F_GETLK         5
#define F_SETLK         6
#define F_SETLKW        7

#define F_SETOWN        8       /*  for sockets. */
#define F_GETOWN        9       /*  for sockets. */
#define F_SETSIG        10      /*  for sockets. */
#define F_GETSIG        11      /*  for sockets. */

#define F_GETLK64       12      /*  using 'struct flock64' */
#define F_SETLK64       13
#define F_SETLKW64      14

/* for F_[GET|SET]FL */
#define FD_CLOEXEC      1       /* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK         0
#define F_WRLCK         1
#define F_UNLCK         2

/* for old implementation of bsd flock () */
#define F_EXLCK         4       /* or 3 */
#define F_SHLCK         8       /* or 4 */

/* for leases */
#define F_INPROGRESS    16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH         1       /* shared lock */
#define LOCK_EX         2       /* exclusive lock */
#define LOCK_NB         4       /* or'd with one of the above to prevent
				                                      blocking */
#define LOCK_UN         8       /* remove lock */

#define LOCK_MAND       32      /* This is a mandatory flock */
#define LOCK_READ       64      /* ... Which allows concurrent read operations */
#define LOCK_WRITE      128     /* ... Which allows concurrent write operations */
#define LOCK_RW         192     /* ... Which allows concurrent read & write ops */

		
/**************** from ptrace.h *********/


enum __ptrace_request
{
  /* Indicate that the process making this request should be traced.
     All signals received by this process can be intercepted by its
     parent, and its parent can use the other `ptrace' requests.  */
  PTRACE_TRACEME = 0,
#define PT_TRACE_ME PTRACE_TRACEME

  /* Return the word in the process's text space at address ADDR.  */
  PTRACE_PEEKTEXT = 1,
#define PT_READ_I PTRACE_PEEKTEXT

  /* Return the word in the process's data space at address ADDR.  */
  PTRACE_PEEKDATA = 2,
#define PT_READ_D PTRACE_PEEKDATA

  /* Return the word in the process's user area at offset ADDR.  */
  PTRACE_PEEKUSER = 3,
#define PT_READ_U PTRACE_PEEKUSER

  /* Write the word DATA into the process's text space at address ADDR.  */
  PTRACE_POKETEXT = 4,
#define PT_WRITE_I PTRACE_POKETEXT

  /* Write the word DATA into the process's data space at address ADDR.  */
  PTRACE_POKEDATA = 5,
#define PT_WRITE_D PTRACE_POKEDATA

  /* Write the word DATA into the process's user area at offset ADDR.  */
  PTRACE_POKEUSER = 6,
#define PT_WRITE_U PTRACE_POKEUSER

  /* Continue the process.  */
  PTRACE_CONT = 7,
#define PT_CONTINUE PTRACE_CONT

  /* Kill the process.  */
  PTRACE_KILL = 8,
#define PT_KILL PTRACE_KILL

  /* Single step the process.
     This is not supported on all machines.  */
  PTRACE_SINGLESTEP = 9,
#define PT_STEP PTRACE_SINGLESTEP

  /* Get all general purpose registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_GETREGS = 12,
#define PT_GETREGS PTRACE_GETREGS

  /* Set all general purpose registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_SETREGS = 13,
#define PT_SETREGS PTRACE_SETREGS

  /* Get all floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_GETFPREGS = 14,
#define PT_GETFPREGS PTRACE_GETFPREGS

  /* Set all floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_SETFPREGS = 15,
#define PT_SETFPREGS PTRACE_SETFPREGS

  /* Attach to a process that is already running. */
  PTRACE_ATTACH = 16,
#define PT_ATTACH PTRACE_ATTACH

  /* Detach from a process attached to with PTRACE_ATTACH.  */
  PTRACE_DETACH = 17,
#define PT_DETACH PTRACE_DETACH

  /* Get all extended floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_GETFPXREGS = 18,
#define PT_GETFPXREGS PTRACE_GETFPXREGS

  /* Set all extended floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_SETFPXREGS = 19,
#define PT_SETFPXREGS PTRACE_SETFPXREGS

  /* Continue and stop at the next (return from) syscall.  */
  PTRACE_SYSCALL = 24
#define PT_SYSCALL PTRACE_SYSCALL
};


/************************ ioctl ******************/
/* from asm/ioctl.h */

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8
#define _IOC_SIZEBITS   14
#define _IOC_DIRBITS    2

#define _IOC_NRMASK     ((1 << _IOC_NRBITS)-1)
#define _IOC_TYPEMASK   ((1 << _IOC_TYPEBITS)-1)
#define _IOC_SIZEMASK   ((1 << _IOC_SIZEBITS)-1)
#define _IOC_DIRMASK    ((1 << _IOC_DIRBITS)-1)

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

/*
 *  * Direction bits.
 *   */
#define _IOC_NONE       0U
#define _IOC_WRITE      1U
#define _IOC_READ       2U

#define _IOC(dir,type,nr,size) \
	        (((dir)  << _IOC_DIRSHIFT) | \
		          ((type) << _IOC_TYPESHIFT) | \
		          ((nr)   << _IOC_NRSHIFT) | \
		          ((size) << _IOC_SIZESHIFT))

/* provoke compile error for invalid uses of size argument */
extern unsigned int __invalid_size_argument_for_IOC;
#define _IOC_TYPECHECK(t) \
	        ((sizeof(t) == sizeof(t[1]) && \
		            sizeof(t) < (1 << _IOC_SIZEBITS)) ? \
		           sizeof(t) : __invalid_size_argument_for_IOC)

				       /* used to create numbers */
#define _IO(type,nr)            _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)      _IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)      _IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)     _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOR_BAD(type,nr,size)  _IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW_BAD(type,nr,size)  _IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR_BAD(type,nr,size) _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))

				       /* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)            (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)           (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)             (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)           (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/* ...and for the drivers/sound files... */

#define IOC_IN          (_IOC_WRITE << _IOC_DIRSHIFT)
#define IOC_OUT         (_IOC_READ << _IOC_DIRSHIFT)
#define IOC_INOUT       ((_IOC_WRITE|_IOC_READ) << _IOC_DIRSHIFT)
#define IOCSIZE_MASK    (_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT   (_IOC_SIZESHIFT)

/* from asm/ioctls.h */

#define TCGETS          0x5401
#define TCSETS          0x5402 /* Clashes with SNDCTL_TMR_START sound ioctl */
#define TCSETSW         0x5403
#define TCSETSF         0x5404
#define TCGETA          0x5405
#define TCSETA          0x5406
#define TCSETAW         0x5407
#define TCSETAF         0x5408
#define TCSBRK          0x5409
#define TCXONC          0x540A
#define TCFLSH          0x540B
#define TIOCEXCL        0x540C
#define TIOCNXCL        0x540D
#define TIOCSCTTY       0x540E
#define TIOCGPGRP       0x540F
#define TIOCSPGRP       0x5410
#define TIOCOUTQ        0x5411
#define TIOCSTI         0x5412
#define TIOCGWINSZ      0x5413
#define TIOCSWINSZ      0x5414
#define TIOCMGET        0x5415
#define TIOCMBIS        0x5416
#define TIOCMBIC        0x5417
#define TIOCMSET        0x5418
#define TIOCGSOFTCAR    0x5419
#define TIOCSSOFTCAR    0x541A
#define FIONREAD        0x541B
#define TIOCINQ         FIONREAD
#define TIOCLINUX       0x541C
#define TIOCCONS        0x541D
#define TIOCGSERIAL     0x541E
#define TIOCSSERIAL     0x541F
#define TIOCPKT         0x5420
#define FIONBIO         0x5421
#define TIOCNOTTY       0x5422
#define TIOCSETD        0x5423
#define TIOCGETD        0x5424
#define TCSBRKP         0x5425  /* Needed for POSIX tcsendbreak() */
/* #define TIOCTTYGSTRUCT 0x5426 - Former debugging-only ioctl */
#define TIOCSBRK        0x5427  /* BSD compatibility */
#define TIOCCBRK        0x5428  /* BSD compatibility */
#define TIOCGSID        0x5429  /* Return the session ID of FD */
#define TIOCGPTN        _IOR('T',0x30, unsigned int) /* Get Pty Number (of pty-mux device) */
#define TIOCSPTLCK      _IOW('T',0x31, int)  /* Lock/unlock Pty */

#define FIONCLEX        0x5450
#define FIOCLEX         0x5451
#define FIOASYNC        0x5452
#define TIOCSERCONFIG   0x5453
#define TIOCSERGWILD    0x5454
#define TIOCSERSWILD    0x5455
#define TIOCGLCKTRMIOS  0x5456
#define TIOCSLCKTRMIOS  0x5457
#define TIOCSERGSTRUCT  0x5458 /* For debugging only */
#define TIOCSERGETLSR   0x5459 /* Get line status register */
#define TIOCSERGETMULTI 0x545A /* Get multiport config  */
#define TIOCSERSETMULTI 0x545B /* Set multiport config */

#define TIOCMIWAIT      0x545C  /* wait for a change on serial input line(s) */
#define TIOCGICOUNT     0x545D  /* read serial port inline interrupt counts */
#define TIOCGHAYESESP   0x545E  /* Get Hayes ESP configuration */
#define TIOCSHAYESESP   0x545F  /* Set Hayes ESP configuration */
#define FIOQSIZE        0x5460

/* Used for packet mode */
#define TIOCPKT_DATA             0
#define TIOCPKT_FLUSHREAD        1
#define TIOCPKT_FLUSHWRITE       2
#define TIOCPKT_STOP             4
#define TIOCPKT_START            8
#define TIOCPKT_NOSTOP          16
#define TIOCPKT_DOSTOP          32

#define TIOCSER_TEMT    0x01    /* Transmitter physically empty */



/********************** termio *******************/
/* from /usr/include/asm/termios.h */

struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

#define NCC 8
struct termio {
	unsigned short c_iflag;         /* input mode flags */
	unsigned short c_oflag;         /* output mode flags */
	unsigned short c_cflag;         /* control mode flags */
	unsigned short c_lflag;         /* local mode flags */
	unsigned char c_line;           /* line discipline */
	unsigned char c_cc[NCC];        /* control characters */
};

/* modem lines */
#define TIOCM_LE        0x001
#define TIOCM_DTR       0x002
#define TIOCM_RTS       0x004
#define TIOCM_ST        0x008
#define TIOCM_SR        0x010
#define TIOCM_CTS       0x020
#define TIOCM_CAR       0x040
#define TIOCM_RNG       0x080
#define TIOCM_DSR       0x100
#define TIOCM_CD        TIOCM_CAR
#define TIOCM_RI        TIOCM_RNG
#define TIOCM_OUT1      0x2000
#define TIOCM_OUT2      0x4000
#define TIOCM_LOOP      0x8000

/* ioctl (fd, TIOCSERGETLSR, &result) where result may be as below */

/* line disciplines */
#define N_TTY           0
#define N_SLIP          1
#define N_MOUSE         2
#define N_PPP           3
#define N_STRIP         4
#define N_AX25          5
#define N_X25           6       /* X.25 async */
#define N_6PACK         7
#define N_MASC          8       /* Reserved for Mobitex module <kaz@cafe.net> */
#define N_R3964         9       /* Reserved for Simatic R3964 module */
#define N_PROFIBUS_FDL  10      /* Reserved for Profibus <Dave@mvhi.com> */
#define N_IRDA          11      /* Linux IR - http://irda.sourceforge.net/ */
#define N_SMSBLOCK      12      /* SMS block mode - for talking to GSM data cards about SMS messages */
#define N_HDLC          13      /* synchronous HDLC */
#define N_SYNC_PPP      14      /* synchronous PPP */
#define N_HCI           15  /* Bluetooth HCI UART */

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

#define NCCS 19
struct termios {
	tcflag_t c_iflag;               /* input mode flags */
	tcflag_t c_oflag;               /* output mode flags */
	tcflag_t c_cflag;               /* control mode flags */
	tcflag_t c_lflag;               /* local mode flags */
	cc_t c_line;                    /* line discipline */
	cc_t c_cc[NCCS];                /* control characters */
};

/* c_cc characters */
#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VTIME 5
#define VMIN 6
#define VSWTC 7
#define VSTART 8
#define VSTOP 9
#define VSUSP 10
#define VEOL 11
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE 14
#define VLNEXT 15
#define VEOL2 16

/* c_iflag bits */
#define IGNBRK  0000001
#define BRKINT  0000002
#define IGNPAR  0000004
#define PARMRK  0000010
#define INPCK   0000020
#define ISTRIP  0000040
#define INLCR   0000100
#define IGNCR   0000200
#define ICRNL   0000400
#define IUCLC   0001000
#define IXON    0002000
#define IXANY   0004000
#define IXOFF   0010000
#define IMAXBEL 0020000

/* c_oflag bits */
#define OPOST   0000001
#define OLCUC   0000002
#define ONLCR   0000004
#define OCRNL   0000010
#define ONOCR   0000020
#define ONLRET  0000040
#define OFILL   0000100
#define OFDEL   0000200
#define NLDLY   0000400
#define   NL0   0000000
#define   NL1   0000400
#define CRDLY   0003000
#define   CR0   0000000
#define   CR1   0001000
#define   CR2   0002000
#define   CR3   0003000
#define TABDLY  0014000
#define   TAB0  0000000
#define   TAB1  0004000
#define   TAB2  0010000
#define   TAB3  0014000
#define   XTABS 0014000
#define BSDLY   0020000
#define   BS0   0000000
#define   BS1   0020000
#define VTDLY   0040000
#define   VT0   0000000
#define   VT1   0040000
#define FFDLY   0100000
#define   FF0   0000000
#define   FF1   0100000

/* c_cflag bit meaning */
#define CBAUD   0010017
#define  B0     0000000         /* hang up */
#define  B50    0000001
#define  B75    0000002
#define  B110   0000003
#define  B134   0000004
#define  B150   0000005
#define  B200   0000006
#define  B300   0000007
#define  B600   0000010
#define  B1200  0000011
#define  B1800  0000012
#define  B2400  0000013
#define  B4800  0000014
#define  B9600  0000015
#define  B19200 0000016
#define  B38400 0000017
#define EXTA B19200
#define EXTB B38400
#define CSIZE   0000060
#define   CS5   0000000
#define   CS6   0000020
#define   CS7   0000040
#define   CS8   0000060
#define CSTOPB  0000100
#define CREAD   0000200
#define PARENB  0000400
#define PARODD  0001000
#define HUPCL   0002000
#define CLOCAL  0004000
#define CBAUDEX 0010000
#define    B57600 0010001
#define   B115200 0010002
#define   B230400 0010003
#define   B460800 0010004
#define   B500000 0010005
#define   B576000 0010006
#define   B921600 0010007
#define  B1000000 0010010
#define  B1152000 0010011
#define  B1500000 0010012
#define  B2000000 0010013
#define  B2500000 0010014
#define  B3000000 0010015
#define  B3500000 0010016
#define  B4000000 0010017
#define CIBAUD    002003600000  /* input baud rate (not used) */
#define CMSPAR    010000000000          /* mark or space (stick) parity */
#define CRTSCTS   020000000000          /* flow control */

/* c_lflag bits */
#define ISIG    0000001
#define ICANON  0000002
#define XCASE   0000004
#define ECHO    0000010
#define ECHOE   0000020
#define ECHOK   0000040
#define ECHONL  0000100
#define NOFLSH  0000200
#define TOSTOP  0000400
#define ECHOCTL 0001000
#define ECHOPRT 0002000
#define ECHOKE  0004000
#define FLUSHO  0010000
#define PENDIN  0040000
#define IEXTEN  0100000

/* tcflow() and TCXONC use these */
#define TCOOFF          0
#define TCOON           1
#define TCIOFF          2
#define TCION           3

/* tcflush() and TCFLSH use these */
#define TCIFLUSH        0
#define TCOFLUSH        1
#define TCIOFLUSH       2

/* tcsetattr uses these */
#define TCSANOW         0
#define TCSADRAIN       1
#define TCSAFLUSH       2



#endif /* SFTYPES_H */

/****************** Elf headers ***************/
/*  From /usr/include/elf.h */



/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef	int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef	int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Type for version symbol information.  */
typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;


/* The ELF file header.  This appears at the start of every ELF file.  */

#define EI_NIDENT (16)

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf32_Half	e_type;			/* Object file type */
  Elf32_Half	e_machine;		/* Architecture */
  Elf32_Word	e_version;		/* Object file version */
  Elf32_Addr	e_entry;		/* Entry point virtual address */
  Elf32_Off	e_phoff;		/* Program header table file offset */
  Elf32_Off	e_shoff;		/* Section header table file offset */
  Elf32_Word	e_flags;		/* Processor-specific flags */
  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
  Elf32_Half	e_phentsize;		/* Program header table entry size */
  Elf32_Half	e_phnum;		/* Program header table entry count */
  Elf32_Half	e_shentsize;		/* Section header table entry size */
  Elf32_Half	e_shnum;		/* Section header table entry count */
  Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;

/* Fields in the e_ident array.  The EI_* macros are indices into the
   array.  The macros under each EI_* macro are the values the byte
   may have.  */

#define EI_MAG0		0		/* File identification byte 0 index */
#define ELFMAG0		0x7f		/* Magic number byte 0 */

#define EI_MAG1		1		/* File identification byte 1 index */
#define ELFMAG1		'E'		/* Magic number byte 1 */

#define EI_MAG2		2		/* File identification byte 2 index */
#define ELFMAG2		'L'		/* Magic number byte 2 */

#define EI_MAG3		3		/* File identification byte 3 index */
#define ELFMAG3		'F'		/* Magic number byte 3 */

/* Conglomeration of the identification bytes, for easy testing as a word.  */
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4

#define EI_CLASS	4		/* File class byte index */
#define ELFCLASSNONE	0		/* Invalid class */
#define ELFCLASS32	1		/* 32-bit objects */
#define ELFCLASS64	2		/* 64-bit objects */
#define ELFCLASSNUM	3

#define EI_DATA		5		/* Data encoding byte index */
#define ELFDATANONE	0		/* Invalid data encoding */
#define ELFDATA2LSB	1		/* 2's complement, little endian */
#define ELFDATA2MSB	2		/* 2's complement, big endian */
#define ELFDATANUM	3

#define EI_VERSION	6		/* File version byte index */
					/* Value must be EV_CURRENT */

#define EI_OSABI	7		/* OS ABI identification */
#define ELFOSABI_NONE		0	/* UNIX System V ABI */
#define ELFOSABI_SYSV		0	/* Alias.  */
#define ELFOSABI_HPUX		1	/* HP-UX */
#define ELFOSABI_NETBSD		2	/* NetBSD.  */
#define ELFOSABI_LINUX		3	/* Linux.  */
#define ELFOSABI_SOLARIS	6	/* Sun Solaris.  */
#define ELFOSABI_AIX		7	/* IBM AIX.  */
#define ELFOSABI_IRIX		8	/* SGI Irix.  */
#define ELFOSABI_FREEBSD	9	/* FreeBSD.  */
#define ELFOSABI_TRU64		10	/* Compaq TRU64 UNIX.  */
#define ELFOSABI_MODESTO	11	/* Novell Modesto.  */
#define ELFOSABI_OPENBSD	12	/* OpenBSD.  */
#define ELFOSABI_ARM		97	/* ARM */
#define ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

#define EI_ABIVERSION	8		/* ABI version */

#define EI_PAD		9		/* Byte index of padding bytes */

/* Legal values for e_type (object file type).  */

#define ET_NONE		0		/* No file type */
#define ET_REL		1		/* Relocatable file */
#define ET_EXEC		2		/* Executable file */
#define ET_DYN		3		/* Shared object file */
#define ET_CORE		4		/* Core file */
#define	ET_NUM		5		/* Number of defined types */
#define ET_LOOS		0xfe00		/* OS-specific range start */
#define ET_HIOS		0xfeff		/* OS-specific range end */
#define ET_LOPROC	0xff00		/* Processor-specific range start */
#define ET_HIPROC	0xffff		/* Processor-specific range end */

/* Legal values for e_machine (architecture).  */

#define EM_NONE		 0		/* No machine */
#define EM_M32		 1		/* AT&T WE 32100 */
#define EM_SPARC	 2		/* SUN SPARC */
#define EM_386		 3		/* Intel 80386 */
#define EM_68K		 4		/* Motorola m68k family */
#define EM_88K		 5		/* Motorola m88k family */
#define EM_860		 7		/* Intel 80860 */
#define EM_MIPS		 8		/* MIPS R3000 big-endian */
#define EM_S370		 9		/* IBM System/370 */
#define EM_MIPS_RS3_LE	10		/* MIPS R3000 little-endian */

#define EM_PARISC	15		/* HPPA */
#define EM_VPP500	17		/* Fujitsu VPP500 */
#define EM_SPARC32PLUS	18		/* Sun's "v8plus" */
#define EM_960		19		/* Intel 80960 */
#define EM_PPC		20		/* PowerPC */
#define EM_PPC64	21		/* PowerPC 64-bit */
#define EM_S390		22		/* IBM S390 */

#define EM_V800		36		/* NEC V800 series */
#define EM_FR20		37		/* Fujitsu FR20 */
#define EM_RH32		38		/* TRW RH-32 */
#define EM_RCE		39		/* Motorola RCE */
#define EM_ARM		40		/* ARM */
#define EM_FAKE_ALPHA	41		/* Digital Alpha */
#define EM_SH		42		/* Hitachi SH */
#define EM_SPARCV9	43		/* SPARC v9 64-bit */
#define EM_TRICORE	44		/* Siemens Tricore */
#define EM_ARC		45		/* Argonaut RISC Core */
#define EM_H8_300	46		/* Hitachi H8/300 */
#define EM_H8_300H	47		/* Hitachi H8/300H */
#define EM_H8S		48		/* Hitachi H8S */
#define EM_H8_500	49		/* Hitachi H8/500 */
#define EM_IA_64	50		/* Intel Merced */
#define EM_MIPS_X	51		/* Stanford MIPS-X */
#define EM_COLDFIRE	52		/* Motorola Coldfire */
#define EM_68HC12	53		/* Motorola M68HC12 */
#define EM_MMA		54		/* Fujitsu MMA Multimedia Accelerator*/
#define EM_PCP		55		/* Siemens PCP */
#define EM_NCPU		56		/* Sony nCPU embeeded RISC */
#define EM_NDR1		57		/* Denso NDR1 microprocessor */
#define EM_STARCORE	58		/* Motorola Start*Core processor */
#define EM_ME16		59		/* Toyota ME16 processor */
#define EM_ST100	60		/* STMicroelectronic ST100 processor */
#define EM_TINYJ	61		/* Advanced Logic Corp. Tinyj emb.fam*/
#define EM_X86_64	62		/* AMD x86-64 architecture */
#define EM_PDSP		63		/* Sony DSP Processor */

#define EM_FX66		66		/* Siemens FX66 microcontroller */
#define EM_ST9PLUS	67		/* STMicroelectronics ST9+ 8/16 mc */
#define EM_ST7		68		/* STmicroelectronics ST7 8 bit mc */
#define EM_68HC16	69		/* Motorola MC68HC16 microcontroller */
#define EM_68HC11	70		/* Motorola MC68HC11 microcontroller */
#define EM_68HC08	71		/* Motorola MC68HC08 microcontroller */
#define EM_68HC05	72		/* Motorola MC68HC05 microcontroller */
#define EM_SVX		73		/* Silicon Graphics SVx */
#define EM_ST19		74		/* STMicroelectronics ST19 8 bit mc */
#define EM_VAX		75		/* Digital VAX */
#define EM_CRIS		76		/* Axis Communications 32-bit embedded processor */
#define EM_JAVELIN	77		/* Infineon Technologies 32-bit embedded processor */
#define EM_FIREPATH	78		/* Element 14 64-bit DSP Processor */
#define EM_ZSP		79		/* LSI Logic 16-bit DSP Processor */
#define EM_MMIX		80		/* Donald Knuth's educational 64-bit processor */
#define EM_HUANY	81		/* Harvard University machine-independent object files */
#define EM_PRISM	82		/* SiTera Prism */
#define EM_AVR		83		/* Atmel AVR 8-bit microcontroller */
#define EM_FR30		84		/* Fujitsu FR30 */
#define EM_D10V		85		/* Mitsubishi D10V */
#define EM_D30V		86		/* Mitsubishi D30V */
#define EM_V850		87		/* NEC v850 */
#define EM_M32R		88		/* Mitsubishi M32R */
#define EM_MN10300	89		/* Matsushita MN10300 */
#define EM_MN10200	90		/* Matsushita MN10200 */
#define EM_PJ		91		/* picoJava */
#define EM_OPENRISC	92		/* OpenRISC 32-bit embedded processor */
#define EM_ARC_A5	93		/* ARC Cores Tangent-A5 */
#define EM_XTENSA	94		/* Tensilica Xtensa Architecture */
#define EM_NUM		95

/* If it is necessary to assign new unofficial EM_* values, please
   pick large random numbers (0x8523, 0xa7f2, etc.) to minimize the
   chances of collision with official or non-GNU unofficial values.  */

#define EM_ALPHA	0x9026

/* Legal values for e_version (version).  */

#define EV_NONE		0		/* Invalid ELF version */
#define EV_CURRENT	1		/* Current version */
#define EV_NUM		2

/* Section header.  */

typedef struct
{
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off	sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;		/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
} Elf32_Shdr;

typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;		/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;

/* Special section indices.  */

#define SHN_UNDEF	0		/* Undefined section */
#define SHN_LORESERVE	0xff00		/* Start of reserved indices */
#define SHN_LOPROC	0xff00		/* Start of processor-specific */
#define SHN_BEFORE	0xff00		/* Order section before all others
					   (Solaris).  */
#define SHN_AFTER	0xff01		/* Order section after all others
					   (Solaris).  */
#define SHN_HIPROC	0xff1f		/* End of processor-specific */
#define SHN_LOOS	0xff20		/* Start of OS-specific */
#define SHN_HIOS	0xff3f		/* End of OS-specific */
#define SHN_ABS		0xfff1		/* Associated symbol is absolute */
#define SHN_COMMON	0xfff2		/* Associated symbol is common */
#define SHN_XINDEX	0xffff		/* Index is in extra table.  */
#define SHN_HIRESERVE	0xffff		/* End of reserved indices */

/* Legal values for sh_type (section type).  */

#define SHT_NULL	  0		/* Section header table entry unused */
#define SHT_PROGBITS	  1		/* Program data */
#define SHT_SYMTAB	  2		/* Symbol table */
#define SHT_STRTAB	  3		/* String table */
#define SHT_RELA	  4		/* Relocation entries with addends */
#define SHT_HASH	  5		/* Symbol hash table */
#define SHT_DYNAMIC	  6		/* Dynamic linking information */
#define SHT_NOTE	  7		/* Notes */
#define SHT_NOBITS	  8		/* Program space with no data (bss) */
#define SHT_REL		  9		/* Relocation entries, no addends */
#define SHT_SHLIB	  10		/* Reserved */
#define SHT_DYNSYM	  11		/* Dynamic linker symbol table */
#define SHT_INIT_ARRAY	  14		/* Array of constructors */
#define SHT_FINI_ARRAY	  15		/* Array of destructors */
#define SHT_PREINIT_ARRAY 16		/* Array of pre-constructors */
#define SHT_GROUP	  17		/* Section group */
#define SHT_SYMTAB_SHNDX  18		/* Extended section indeces */
#define	SHT_NUM		  19		/* Number of defined types.  */
#define SHT_LOOS	  0x60000000	/* Start OS-specific */
#define SHT_GNU_LIBLIST	  0x6ffffff7	/* Prelink library list */
#define SHT_CHECKSUM	  0x6ffffff8	/* Checksum for DSO content.  */
#define SHT_LOSUNW	  0x6ffffffa	/* Sun-specific low bound.  */
#define SHT_SUNW_move	  0x6ffffffa
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_GNU_verdef	  0x6ffffffd	/* Version definition section.  */
#define SHT_GNU_verneed	  0x6ffffffe	/* Version needs section.  */
#define SHT_GNU_versym	  0x6fffffff	/* Version symbol table.  */
#define SHT_HISUNW	  0x6fffffff	/* Sun-specific high bound.  */
#define SHT_HIOS	  0x6fffffff	/* End OS-specific type */
#define SHT_LOPROC	  0x70000000	/* Start of processor-specific */
#define SHT_HIPROC	  0x7fffffff	/* End of processor-specific */
#define SHT_LOUSER	  0x80000000	/* Start of application-specific */
#define SHT_HIUSER	  0x8fffffff	/* End of application-specific */

/* Legal values for sh_flags (section flags).  */

#define SHF_WRITE	     (1 << 0)	/* Writable */
#define SHF_ALLOC	     (1 << 1)	/* Occupies memory during execution */
#define SHF_EXECINSTR	     (1 << 2)	/* Executable */
#define SHF_MERGE	     (1 << 4)	/* Might be merged */
#define SHF_STRINGS	     (1 << 5)	/* Contains nul-terminated strings */
#define SHF_INFO_LINK	     (1 << 6)	/* `sh_info' contains SHT index */
#define SHF_LINK_ORDER	     (1 << 7)	/* Preserve order after combining */
#define SHF_OS_NONCONFORMING (1 << 8)	/* Non-standard OS specific handling
					   required */
#define SHF_GROUP	     (1 << 9)	/* Section is member of a group.  */
#define SHF_TLS		     (1 << 10)	/* Section hold thread-local data.  */
#define SHF_MASKOS	     0x0ff00000	/* OS-specific.  */
#define SHF_MASKPROC	     0xf0000000	/* Processor-specific */
#define SHF_ORDERED	     (1 << 30)	/* Special ordering requirement
					   (Solaris).  */
#define SHF_EXCLUDE	     (1 << 31)	/* Section is excluded unless
					   referenced or allocated (Solaris).*/

/* Section group handling.  */
#define GRP_COMDAT	0x1		/* Mark group as COMDAT.  */

/* Symbol table entry.  */

typedef struct
{
  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
  Elf32_Addr	st_value;		/* Symbol value */
  Elf32_Word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char	st_other;		/* Symbol visibility */
  Elf32_Section	st_shndx;		/* Section index */
} Elf32_Sym;

typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;

/* The syminfo section if available contains additional information about
   every dynamic symbol.  */

typedef struct
{
  Elf32_Half si_boundto;		/* Direct bindings, symbol bound to */
  Elf32_Half si_flags;			/* Per symbol flags */
} Elf32_Syminfo;

typedef struct
{
  Elf64_Half si_boundto;		/* Direct bindings, symbol bound to */
  Elf64_Half si_flags;			/* Per symbol flags */
} Elf64_Syminfo;

/* Possible values for si_boundto.  */
#define SYMINFO_BT_SELF		0xffff	/* Symbol bound to self */
#define SYMINFO_BT_PARENT	0xfffe	/* Symbol bound to parent */
#define SYMINFO_BT_LOWRESERVE	0xff00	/* Beginning of reserved entries */

/* Possible bitmasks for si_flags.  */
#define SYMINFO_FLG_DIRECT	0x0001	/* Direct bound symbol */
#define SYMINFO_FLG_PASSTHRU	0x0002	/* Pass-thru symbol for translator */
#define SYMINFO_FLG_COPY	0x0004	/* Symbol is a copy-reloc */
#define SYMINFO_FLG_LAZYLOAD	0x0008	/* Symbol bound to object to be lazy
					   loaded */
/* Syminfo version values.  */
#define SYMINFO_NONE		0
#define SYMINFO_CURRENT		1
#define SYMINFO_NUM		2


/* How to extract and insert information held in the st_info field.  */

#define ELF32_ST_BIND(val)		(((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val)		((val) & 0xf)
#define ELF32_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))

/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
#define ELF64_ST_BIND(val)		ELF32_ST_BIND (val)
#define ELF64_ST_TYPE(val)		ELF32_ST_TYPE (val)
#define ELF64_ST_INFO(bind, type)	ELF32_ST_INFO ((bind), (type))

/* Legal values for ST_BIND subfield of st_info (symbol binding).  */

#define STB_LOCAL	0		/* Local symbol */
#define STB_GLOBAL	1		/* Global symbol */
#define STB_WEAK	2		/* Weak symbol */
#define	STB_NUM		3		/* Number of defined types.  */
#define STB_LOOS	10		/* Start of OS-specific */
#define STB_HIOS	12		/* End of OS-specific */
#define STB_LOPROC	13		/* Start of processor-specific */
#define STB_HIPROC	15		/* End of processor-specific */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_NOTYPE	0		/* Symbol type is unspecified */
#define STT_OBJECT	1		/* Symbol is a data object */
#define STT_FUNC	2		/* Symbol is a code object */
#define STT_SECTION	3		/* Symbol associated with a section */
#define STT_FILE	4		/* Symbol's name is file name */
#define STT_COMMON	5		/* Symbol is a common data object */
#define STT_TLS		6		/* Symbol is thread-local data object*/
#define	STT_NUM		7		/* Number of defined types.  */
#define STT_LOOS	10		/* Start of OS-specific */
#define STT_HIOS	12		/* End of OS-specific */
#define STT_LOPROC	13		/* Start of processor-specific */
#define STT_HIPROC	15		/* End of processor-specific */


/* Symbol table indices are found in the hash buckets and chain table
   of a symbol hash table section.  This special index value indicates
   the end of a chain, meaning no further symbols are found in that bucket.  */

#define STN_UNDEF	0		/* End of a chain.  */


/* How to extract and insert information held in the st_other field.  */

#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)

/* For ELF64 the definitions are the same.  */
#define ELF64_ST_VISIBILITY(o)	ELF32_ST_VISIBILITY (o)

/* Symbol visibility specification encoded in the st_other field.  */
#define STV_DEFAULT	0		/* Default symbol visibility rules */
#define STV_INTERNAL	1		/* Processor specific hidden class */
#define STV_HIDDEN	2		/* Sym unavailable in other modules */
#define STV_PROTECTED	3		/* Not preemptible, not exported */


/* Relocation table entry without addend (in section of type SHT_REL).  */

typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
} Elf32_Rel;

/* I have seen two different definitions of the Elf64_Rel and
   Elf64_Rela structures, so we'll leave them out until Novell (or
   whoever) gets their act together.  */
/* The following, at least, is used on Sparc v9, MIPS, and Alpha.  */

typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
} Elf64_Rel;

/* Relocation table entry with addend (in section of type SHT_RELA).  */

typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
  Elf32_Sword	r_addend;		/* Addend */
} Elf32_Rela;

typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;

/* How to extract and insert information held in the r_info field.  */

#define ELF32_R_SYM(val)		((val) >> 8)
#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))

/* Program segment header.  */

typedef struct
{
  Elf32_Word	p_type;			/* Segment type */
  Elf32_Off	p_offset;		/* Segment file offset */
  Elf32_Addr	p_vaddr;		/* Segment virtual address */
  Elf32_Addr	p_paddr;		/* Segment physical address */
  Elf32_Word	p_filesz;		/* Segment size in file */
  Elf32_Word	p_memsz;		/* Segment size in memory */
  Elf32_Word	p_flags;		/* Segment flags */
  Elf32_Word	p_align;		/* Segment alignment */
} Elf32_Phdr;

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

/* Legal values for p_type (segment type).  */

#define	PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved */
#define PT_PHDR		6		/* Entry for header table itself */
#define PT_TLS		7		/* Thread-local storage segment */
#define	PT_NUM		8		/* Number of defined types */
#define PT_LOOS		0x60000000	/* Start of OS-specific */
#define PT_GNU_EH_FRAME	0x6474e550	/* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK	0x6474e551	/* Indicates stack executability */
#define PT_GNU_RELRO	0x6474e552	/* Read-only after relocation */
#define PT_LOSUNW	0x6ffffffa
#define PT_SUNWBSS	0x6ffffffa	/* Sun Specific segment */
#define PT_SUNWSTACK	0x6ffffffb	/* Stack segment */
#define PT_HISUNW	0x6fffffff
#define PT_HIOS		0x6fffffff	/* End of OS-specific */
#define PT_LOPROC	0x70000000	/* Start of processor-specific */
#define PT_HIPROC	0x7fffffff	/* End of processor-specific */

/* Legal values for p_flags (segment flags).  */

#define PF_X		(1 << 0)	/* Segment is executable */
#define PF_W		(1 << 1)	/* Segment is writable */
#define PF_R		(1 << 2)	/* Segment is readable */
#define PF_MASKOS	0x0ff00000	/* OS-specific */
#define PF_MASKPROC	0xf0000000	/* Processor-specific */

/* Legal values for note segment descriptor types for core files. */

#define NT_PRSTATUS	1		/* Contains copy of prstatus struct */
#define NT_FPREGSET	2		/* Contains copy of fpregset struct */
#define NT_PRPSINFO	3		/* Contains copy of prpsinfo struct */
#define NT_PRXREG	4		/* Contains copy of prxregset struct */
#define NT_TASKSTRUCT	4		/* Contains copy of task structure */
#define NT_PLATFORM	5		/* String from sysinfo(SI_PLATFORM) */
#define NT_AUXV		6		/* Contains copy of auxv array */
#define NT_GWINDOWS	7		/* Contains copy of gwindows struct */
#define NT_ASRS		8		/* Contains copy of asrset struct */
#define NT_PSTATUS	10		/* Contains copy of pstatus struct */
#define NT_PSINFO	13		/* Contains copy of psinfo struct */
#define NT_PRCRED	14		/* Contains copy of prcred struct */
#define NT_UTSNAME	15		/* Contains copy of utsname struct */
#define NT_LWPSTATUS	16		/* Contains copy of lwpstatus struct */
#define NT_LWPSINFO	17		/* Contains copy of lwpinfo struct */
#define NT_PRFPXREG	20		/* Contains copy of fprxregset struct*/

/* Legal values for the note segment descriptor types for object files.  */

#define NT_VERSION	1		/* Contains a version string.  */


/* Dynamic section entry.  */

typedef struct
{
  Elf32_Sword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;

typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;

/* Legal values for d_tag (dynamic entry type).  */

#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
#define DT_RELA		7		/* Address of Rela relocs */
#define DT_RELASZ	8		/* Total size of Rela relocs */
#define DT_RELAENT	9		/* Size of one Rela reloc */
#define DT_STRSZ	10		/* Size of string table */
#define DT_SYMENT	11		/* Size of one symbol table entry */
#define DT_INIT		12		/* Address of init function */
#define DT_FINI		13		/* Address of termination function */
#define DT_SONAME	14		/* Name of shared object */
#define DT_RPATH	15		/* Library search path (deprecated) */
#define DT_SYMBOLIC	16		/* Start symbol search here */
#define DT_REL		17		/* Address of Rel relocs */
#define DT_RELSZ	18		/* Total size of Rel relocs */
#define DT_RELENT	19		/* Size of one Rel reloc */
#define DT_PLTREL	20		/* Type of reloc in PLT */
#define DT_DEBUG	21		/* For debugging; unspecified */
#define DT_TEXTREL	22		/* Reloc might modify .text */
#define DT_JMPREL	23		/* Address of PLT relocs */
#define	DT_BIND_NOW	24		/* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		/* Library search path */
#define DT_FLAGS	30		/* Flags for the object being loaded */
#define DT_ENCODING	32		/* Start of encoded range */
#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
#define	DT_NUM		34		/* Number used */
#define DT_LOOS		0x6000000d	/* Start of OS-specific */
#define DT_HIOS		0x6ffff000	/* End of OS-specific */
#define DT_LOPROC	0x70000000	/* Start of processor-specific */
#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */

/* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
   Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
   approach.  */
#define DT_VALRNGLO	0x6ffffd00
#define DT_GNU_PRELINKED 0x6ffffdf5	/* Prelinking timestamp */
#define DT_GNU_CONFLICTSZ 0x6ffffdf6	/* Size of conflict section */
#define DT_GNU_LIBLISTSZ 0x6ffffdf7	/* Size of library list */
#define DT_CHECKSUM	0x6ffffdf8
#define DT_PLTPADSZ	0x6ffffdf9
#define DT_MOVEENT	0x6ffffdfa
#define DT_MOVESZ	0x6ffffdfb
#define DT_FEATURE_1	0x6ffffdfc	/* Feature selection (DTF_*).  */
#define DT_POSFLAG_1	0x6ffffdfd	/* Flags for DT_* entries, effecting
					   the following DT_* entry.  */
#define DT_SYMINSZ	0x6ffffdfe	/* Size of syminfo table (in bytes) */
#define DT_SYMINENT	0x6ffffdff	/* Entry size of syminfo */
#define DT_VALRNGHI	0x6ffffdff
#define DT_VALTAGIDX(tag)	(DT_VALRNGHI - (tag))	/* Reverse order! */
#define DT_VALNUM 12

/* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
   Dyn.d_un.d_ptr field of the Elf*_Dyn structure.

   If any adjustment is made to the ELF object after it has been
   built these entries will need to be adjusted.  */
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_GNU_CONFLICT	0x6ffffef8	/* Start of conflict section */
#define DT_GNU_LIBLIST	0x6ffffef9	/* Library list */
#define DT_CONFIG	0x6ffffefa	/* Configuration information.  */
#define DT_DEPAUDIT	0x6ffffefb	/* Dependency auditing.  */
#define DT_AUDIT	0x6ffffefc	/* Object auditing.  */
#define	DT_PLTPAD	0x6ffffefd	/* PLT padding.  */
#define	DT_MOVETAB	0x6ffffefe	/* Move table.  */
#define DT_SYMINFO	0x6ffffeff	/* Syminfo table.  */
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_ADDRTAGIDX(tag)	(DT_ADDRRNGHI - (tag))	/* Reverse order! */
#define DT_ADDRNUM 10

/* The versioning entry types.  The next are defined as part of the
   GNU extension.  */
#define DT_VERSYM	0x6ffffff0

#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa

/* These were chosen by Sun.  */
#define DT_FLAGS_1	0x6ffffffb	/* State flags, see DF_1_* below.  */
#define	DT_VERDEF	0x6ffffffc	/* Address of version definition
					   table */
#define	DT_VERDEFNUM	0x6ffffffd	/* Number of version definitions */
#define	DT_VERNEED	0x6ffffffe	/* Address of table with needed
					   versions */
#define	DT_VERNEEDNUM	0x6fffffff	/* Number of needed versions */
#define DT_VERSIONTAGIDX(tag)	(DT_VERNEEDNUM - (tag))	/* Reverse order! */
#define DT_VERSIONTAGNUM 16

/* Sun added these machine-independent extensions in the "processor-specific"
   range.  Be compatible.  */
#define DT_AUXILIARY    0x7ffffffd      /* Shared object to load before self */
#define DT_FILTER       0x7fffffff      /* Shared object to get values from */
#define DT_EXTRATAGIDX(tag)	((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
#define DT_EXTRANUM	3

/* Values of `d_un.d_val' in the DT_FLAGS entry.  */
#define DF_ORIGIN	0x00000001	/* Object may use DF_ORIGIN */
#define DF_SYMBOLIC	0x00000002	/* Symbol resolutions starts here */
#define DF_TEXTREL	0x00000004	/* Object contains text relocations */
#define DF_BIND_NOW	0x00000008	/* No lazy binding for this object */
#define DF_STATIC_TLS	0x00000010	/* Module uses the static TLS model */

/* State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
   entry in the dynamic section.  */
#define DF_1_NOW	0x00000001	/* Set RTLD_NOW for this object.  */
#define DF_1_GLOBAL	0x00000002	/* Set RTLD_GLOBAL for this object.  */
#define DF_1_GROUP	0x00000004	/* Set RTLD_GROUP for this object.  */
#define DF_1_NODELETE	0x00000008	/* Set RTLD_NODELETE for this object.*/
#define DF_1_LOADFLTR	0x00000010	/* Trigger filtee loading at runtime.*/
#define DF_1_INITFIRST	0x00000020	/* Set RTLD_INITFIRST for this object*/
#define DF_1_NOOPEN	0x00000040	/* Set RTLD_NOOPEN for this object.  */
#define DF_1_ORIGIN	0x00000080	/* $ORIGIN must be handled.  */
#define DF_1_DIRECT	0x00000100	/* Direct binding enabled.  */
#define DF_1_TRANS	0x00000200
#define DF_1_INTERPOSE	0x00000400	/* Object is used to interpose.  */
#define DF_1_NODEFLIB	0x00000800	/* Ignore default lib search path.  */
#define DF_1_NODUMP	0x00001000	/* Object can't be dldump'ed.  */
#define DF_1_CONFALT	0x00002000	/* Configuration alternative created.*/
#define DF_1_ENDFILTEE	0x00004000	/* Filtee terminates filters search. */
#define	DF_1_DISPRELDNE	0x00008000	/* Disp reloc applied at build time. */
#define	DF_1_DISPRELPND	0x00010000	/* Disp reloc applied at run-time.  */

/* Flags for the feature selection in DT_FEATURE_1.  */
#define DTF_1_PARINIT	0x00000001
#define DTF_1_CONFEXP	0x00000002

/* Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry.  */
#define DF_P1_LAZYLOAD	0x00000001	/* Lazyload following object.  */
#define DF_P1_GROUPPERM	0x00000002	/* Symbols from next object are not
					   generally available.  */

/* Version definition sections.  */

typedef struct
{
  Elf32_Half	vd_version;		/* Version revision */
  Elf32_Half	vd_flags;		/* Version information */
  Elf32_Half	vd_ndx;			/* Version Index */
  Elf32_Half	vd_cnt;			/* Number of associated aux entries */
  Elf32_Word	vd_hash;		/* Version name hash value */
  Elf32_Word	vd_aux;			/* Offset in bytes to verdaux array */
  Elf32_Word	vd_next;		/* Offset in bytes to next verdef
					   entry */
} Elf32_Verdef;

typedef struct
{
  Elf64_Half	vd_version;		/* Version revision */
  Elf64_Half	vd_flags;		/* Version information */
  Elf64_Half	vd_ndx;			/* Version Index */
  Elf64_Half	vd_cnt;			/* Number of associated aux entries */
  Elf64_Word	vd_hash;		/* Version name hash value */
  Elf64_Word	vd_aux;			/* Offset in bytes to verdaux array */
  Elf64_Word	vd_next;		/* Offset in bytes to next verdef
					   entry */
} Elf64_Verdef;


/* Legal values for vd_version (version revision).  */
#define VER_DEF_NONE	0		/* No version */
#define VER_DEF_CURRENT	1		/* Current version */
#define VER_DEF_NUM	2		/* Given version number */

/* Legal values for vd_flags (version information flags).  */
#define VER_FLG_BASE	0x1		/* Version definition of file itself */
#define VER_FLG_WEAK	0x2		/* Weak version identifier */

/* Versym symbol index values.  */
#define	VER_NDX_LOCAL		0	/* Symbol is local.  */
#define	VER_NDX_GLOBAL		1	/* Symbol is global.  */
#define	VER_NDX_LORESERVE	0xff00	/* Beginning of reserved entries.  */
#define	VER_NDX_ELIMINATE	0xff01	/* Symbol is to be eliminated.  */

/* Auxialiary version information.  */

typedef struct
{
  Elf32_Word	vda_name;		/* Version or dependency names */
  Elf32_Word	vda_next;		/* Offset in bytes to next verdaux
					   entry */
} Elf32_Verdaux;

typedef struct
{
  Elf64_Word	vda_name;		/* Version or dependency names */
  Elf64_Word	vda_next;		/* Offset in bytes to next verdaux
					   entry */
} Elf64_Verdaux;


/* Version dependency section.  */

typedef struct
{
  Elf32_Half	vn_version;		/* Version of structure */
  Elf32_Half	vn_cnt;			/* Number of associated aux entries */
  Elf32_Word	vn_file;		/* Offset of filename for this
					   dependency */
  Elf32_Word	vn_aux;			/* Offset in bytes to vernaux array */
  Elf32_Word	vn_next;		/* Offset in bytes to next verneed
					   entry */
} Elf32_Verneed;

typedef struct
{
  Elf64_Half	vn_version;		/* Version of structure */
  Elf64_Half	vn_cnt;			/* Number of associated aux entries */
  Elf64_Word	vn_file;		/* Offset of filename for this
					   dependency */
  Elf64_Word	vn_aux;			/* Offset in bytes to vernaux array */
  Elf64_Word	vn_next;		/* Offset in bytes to next verneed
					   entry */
} Elf64_Verneed;


/* Legal values for vn_version (version revision).  */
#define VER_NEED_NONE	 0		/* No version */
#define VER_NEED_CURRENT 1		/* Current version */
#define VER_NEED_NUM	 2		/* Given version number */

/* Auxiliary needed version information.  */

typedef struct
{
  Elf32_Word	vna_hash;		/* Hash value of dependency name */
  Elf32_Half	vna_flags;		/* Dependency specific information */
  Elf32_Half	vna_other;		/* Unused */
  Elf32_Word	vna_name;		/* Dependency name string offset */
  Elf32_Word	vna_next;		/* Offset in bytes to next vernaux
					   entry */
} Elf32_Vernaux;

typedef struct
{
  Elf64_Word	vna_hash;		/* Hash value of dependency name */
  Elf64_Half	vna_flags;		/* Dependency specific information */
  Elf64_Half	vna_other;		/* Unused */
  Elf64_Word	vna_name;		/* Dependency name string offset */
  Elf64_Word	vna_next;		/* Offset in bytes to next vernaux
					   entry */
} Elf64_Vernaux;


/* Legal values for vna_flags.  */
#define VER_FLG_WEAK	0x2		/* Weak version identifier */


/* Auxiliary vector.  */

/* This vector is normally only used by the program interpreter.  The
   usual definition in an ABI supplement uses the name auxv_t.  The
   vector is not usually defined in a standard <elf.h> file, but it
   can't hurt.  We rename it to avoid conflicts.  The sizes of these
   types are an arrangement between the exec server and the program
   interpreter, so we don't fully specify them here.  */

typedef struct
{
  int a_type;			/* Entry type */
  union
    {
      long int a_val;		/* Integer value */
      void *a_ptr;		/* Pointer value */
      void (*a_fcn) (void);	/* Function pointer value */
    } a_un;
} Elf32_auxv_t;

typedef struct
{
  long int a_type;		/* Entry type */
  union
    {
      long int a_val;		/* Integer value */
      void *a_ptr;		/* Pointer value */
      void (*a_fcn) (void);	/* Function pointer value */
    } a_un;
} Elf64_auxv_t;

/* Legal values for a_type (entry type).  */

#define AT_NULL		0		/* End of vector */
#define AT_IGNORE	1		/* Entry should be ignored */
#define AT_EXECFD	2		/* File descriptor of program */
#define AT_PHDR		3		/* Program headers for program */
#define AT_PHENT	4		/* Size of program header entry */
#define AT_PHNUM	5		/* Number of program headers */
#define AT_PAGESZ	6		/* System page size */
#define AT_BASE		7		/* Base address of interpreter */
#define AT_FLAGS	8		/* Flags */
#define AT_ENTRY	9		/* Entry point of program */
#define AT_NOTELF	10		/* Program is not ELF */
#define AT_UID		11		/* Real uid */
#define AT_EUID		12		/* Effective uid */
#define AT_GID		13		/* Real gid */
#define AT_EGID		14		/* Effective gid */
#define AT_CLKTCK	17		/* Frequency of times() */

/* Some more special a_type values describing the hardware.  */
#define AT_PLATFORM	15		/* String identifying platform.  */
#define AT_HWCAP	16		/* Machine dependent hints about
					   processor capabilities.  */

/* This entry gives some information about the FPU initialization
   performed by the kernel.  */
#define AT_FPUCW	18		/* Used FPU control word.  */

/* Cache block sizes.  */
#define AT_DCACHEBSIZE	19		/* Data cache block size.  */
#define AT_ICACHEBSIZE	20		/* Instruction cache block size.  */
#define AT_UCACHEBSIZE	21		/* Unified cache block size.  */

/* A special ignored value for PPC, used by the kernel to control the
   interpretation of the AUXV. Must be > 16.  */
#define AT_IGNOREPPC	22		/* Entry should be ignored.  */

#define	AT_SECURE	23		/* Boolean, was exec setuid-like?  */

/* Pointer to the global system page used for system calls and other
   nice things.  */
#define AT_SYSINFO	32
#define AT_SYSINFO_EHDR	33

/* Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
   log2 of line size; mask those to get cache size.  */
#define AT_L1I_CACHESHAPE	34
#define AT_L1D_CACHESHAPE	35
#define AT_L2_CACHESHAPE	36
#define AT_L3_CACHESHAPE	37

/* Note section contents.  Each entry in the note section begins with
   a header of a fixed form.  */

typedef struct
{
  Elf32_Word n_namesz;			/* Length of the note's name.  */
  Elf32_Word n_descsz;			/* Length of the note's descriptor.  */
  Elf32_Word n_type;			/* Type of the note.  */
} Elf32_Nhdr;

typedef struct
{
  Elf64_Word n_namesz;			/* Length of the note's name.  */
  Elf64_Word n_descsz;			/* Length of the note's descriptor.  */
  Elf64_Word n_type;			/* Type of the note.  */
} Elf64_Nhdr;

/* Known names of notes.  */

/* Solaris entries in the note section have this name.  */
#define ELF_NOTE_SOLARIS	"SUNW Solaris"

/* Note entries for GNU systems have this name.  */
#define ELF_NOTE_GNU		"GNU"


/* Defined types of notes for Solaris.  */

/* Value of descriptor (one word) is desired pagesize for the binary.  */
#define ELF_NOTE_PAGESIZE_HINT	1


/* Defined note types for GNU systems.  */

/* ABI information.  The descriptor consists of words:
   word 0: OS descriptor
   word 1: major version of the ABI
   word 2: minor version of the ABI
   word 3: subminor version of the ABI
*/
#define ELF_NOTE_ABI		1

/* Known OSes.  These value can appear in word 0 of an ELF_NOTE_ABI
   note section entry.  */
#define ELF_NOTE_OS_LINUX	0
#define ELF_NOTE_OS_GNU		1
#define ELF_NOTE_OS_SOLARIS2	2
#define ELF_NOTE_OS_FREEBSD	3


/* Move records.  */
typedef struct
{
  Elf32_Xword m_value;		/* Symbol value.  */
  Elf32_Word m_info;		/* Size and index.  */
  Elf32_Word m_poffset;		/* Symbol offset.  */
  Elf32_Half m_repeat;		/* Repeat count.  */
  Elf32_Half m_stride;		/* Stride info.  */
} Elf32_Move;

typedef struct
{
  Elf64_Xword m_value;		/* Symbol value.  */
  Elf64_Xword m_info;		/* Size and index.  */
  Elf64_Xword m_poffset;	/* Symbol offset.  */
  Elf64_Half m_repeat;		/* Repeat count.  */
  Elf64_Half m_stride;		/* Stride info.  */
} Elf64_Move;

/* Macro to construct move records.  */
#define ELF32_M_SYM(info)	((info) >> 8)
#define ELF32_M_SIZE(info)	((unsigned char) (info))
#define ELF32_M_INFO(sym, size)	(((sym) << 8) + (unsigned char) (size))

#define ELF64_M_SYM(info)	ELF32_M_SYM (info)
#define ELF64_M_SIZE(info)	ELF32_M_SIZE (info)
#define ELF64_M_INFO(sym, size)	ELF32_M_INFO (sym, size)


/* Motorola 68k specific definitions.  */

/* Values for Elf32_Ehdr.e_flags.  */
#define EF_CPU32	0x00810000

/* m68k relocs.  */

#define R_68K_NONE	0		/* No reloc */
#define R_68K_32	1		/* Direct 32 bit  */
#define R_68K_16	2		/* Direct 16 bit  */
#define R_68K_8		3		/* Direct 8 bit  */
#define R_68K_PC32	4		/* PC relative 32 bit */
#define R_68K_PC16	5		/* PC relative 16 bit */
#define R_68K_PC8	6		/* PC relative 8 bit */
#define R_68K_GOT32	7		/* 32 bit PC relative GOT entry */
#define R_68K_GOT16	8		/* 16 bit PC relative GOT entry */
#define R_68K_GOT8	9		/* 8 bit PC relative GOT entry */
#define R_68K_GOT32O	10		/* 32 bit GOT offset */
#define R_68K_GOT16O	11		/* 16 bit GOT offset */
#define R_68K_GOT8O	12		/* 8 bit GOT offset */
#define R_68K_PLT32	13		/* 32 bit PC relative PLT address */
#define R_68K_PLT16	14		/* 16 bit PC relative PLT address */
#define R_68K_PLT8	15		/* 8 bit PC relative PLT address */
#define R_68K_PLT32O	16		/* 32 bit PLT offset */
#define R_68K_PLT16O	17		/* 16 bit PLT offset */
#define R_68K_PLT8O	18		/* 8 bit PLT offset */
#define R_68K_COPY	19		/* Copy symbol at runtime */
#define R_68K_GLOB_DAT	20		/* Create GOT entry */
#define R_68K_JMP_SLOT	21		/* Create PLT entry */
#define R_68K_RELATIVE	22		/* Adjust by program base */
/* Keep this the last entry.  */
#define R_68K_NUM	23

/* Intel 80386 specific definitions.  */

/* i386 relocs.  */

#define R_386_NONE	   0		/* No reloc */
#define R_386_32	   1		/* Direct 32 bit  */
#define R_386_PC32	   2		/* PC relative 32 bit */
#define R_386_GOT32	   3		/* 32 bit GOT entry */
#define R_386_PLT32	   4		/* 32 bit PLT address */
#define R_386_COPY	   5		/* Copy symbol at runtime */
#define R_386_GLOB_DAT	   6		/* Create GOT entry */
#define R_386_JMP_SLOT	   7		/* Create PLT entry */
#define R_386_RELATIVE	   8		/* Adjust by program base */
#define R_386_GOTOFF	   9		/* 32 bit offset to GOT */
#define R_386_GOTPC	   10		/* 32 bit PC relative offset to GOT */
#define R_386_32PLT	   11
#define R_386_TLS_TPOFF	   14		/* Offset in static TLS block */
#define R_386_TLS_IE	   15		/* Address of GOT entry for static TLS
					   block offset */
#define R_386_TLS_GOTIE	   16		/* GOT entry for static TLS block
					   offset */
#define R_386_TLS_LE	   17		/* Offset relative to static TLS
					   block */
#define R_386_TLS_GD	   18		/* Direct 32 bit for GNU version of
					   general dynamic thread local data */
#define R_386_TLS_LDM	   19		/* Direct 32 bit for GNU version of
					   local dynamic thread local data
					   in LE code */
#define R_386_16	   20
#define R_386_PC16	   21
#define R_386_8		   22
#define R_386_PC8	   23
#define R_386_TLS_GD_32	   24		/* Direct 32 bit for general dynamic
					   thread local data */
#define R_386_TLS_GD_PUSH  25		/* Tag for pushl in GD TLS code */
#define R_386_TLS_GD_CALL  26		/* Relocation for call to
					   __tls_get_addr() */
#define R_386_TLS_GD_POP   27		/* Tag for popl in GD TLS code */
#define R_386_TLS_LDM_32   28		/* Direct 32 bit for local dynamic
					   thread local data in LE code */
#define R_386_TLS_LDM_PUSH 29		/* Tag for pushl in LDM TLS code */
#define R_386_TLS_LDM_CALL 30		/* Relocation for call to
					   __tls_get_addr() in LDM code */
#define R_386_TLS_LDM_POP  31		/* Tag for popl in LDM TLS code */
#define R_386_TLS_LDO_32   32		/* Offset relative to TLS block */
#define R_386_TLS_IE_32	   33		/* GOT entry for negated static TLS
					   block offset */
#define R_386_TLS_LE_32	   34		/* Negated offset relative to static
					   TLS block */
#define R_386_TLS_DTPMOD32 35		/* ID of module containing symbol */
#define R_386_TLS_DTPOFF32 36		/* Offset in TLS block */
#define R_386_TLS_TPOFF32  37		/* Negated offset in static TLS block */
/* Keep this the last entry.  */
#define R_386_NUM	   38

/* SUN SPARC specific definitions.  */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_SPARC_REGISTER	13	/* Global register reserved to app. */

/* Values for Elf64_Ehdr.e_flags.  */

#define EF_SPARCV9_MM		3
#define EF_SPARCV9_TSO		0
#define EF_SPARCV9_PSO		1
#define EF_SPARCV9_RMO		2
#define EF_SPARC_LEDATA		0x800000 /* little endian data */
#define EF_SPARC_EXT_MASK	0xFFFF00
#define EF_SPARC_32PLUS		0x000100 /* generic V8+ features */
#define EF_SPARC_SUN_US1	0x000200 /* Sun UltraSPARC1 extensions */
#define EF_SPARC_HAL_R1		0x000400 /* HAL R1 extensions */
#define EF_SPARC_SUN_US3	0x000800 /* Sun UltraSPARCIII extensions */

/* SPARC relocs.  */

#define R_SPARC_NONE		0	/* No reloc */
#define R_SPARC_8		1	/* Direct 8 bit */
#define R_SPARC_16		2	/* Direct 16 bit */
#define R_SPARC_32		3	/* Direct 32 bit */
#define R_SPARC_DISP8		4	/* PC relative 8 bit */
#define R_SPARC_DISP16		5	/* PC relative 16 bit */
#define R_SPARC_DISP32		6	/* PC relative 32 bit */
#define R_SPARC_WDISP30		7	/* PC relative 30 bit shifted */
#define R_SPARC_WDISP22		8	/* PC relative 22 bit shifted */
#define R_SPARC_HI22		9	/* High 22 bit */
#define R_SPARC_22		10	/* Direct 22 bit */
#define R_SPARC_13		11	/* Direct 13 bit */
#define R_SPARC_LO10		12	/* Truncated 10 bit */
#define R_SPARC_GOT10		13	/* Truncated 10 bit GOT entry */
#define R_SPARC_GOT13		14	/* 13 bit GOT entry */
#define R_SPARC_GOT22		15	/* 22 bit GOT entry shifted */
#define R_SPARC_PC10		16	/* PC relative 10 bit truncated */
#define R_SPARC_PC22		17	/* PC relative 22 bit shifted */
#define R_SPARC_WPLT30		18	/* 30 bit PC relative PLT address */
#define R_SPARC_COPY		19	/* Copy symbol at runtime */
#define R_SPARC_GLOB_DAT	20	/* Create GOT entry */
#define R_SPARC_JMP_SLOT	21	/* Create PLT entry */
#define R_SPARC_RELATIVE	22	/* Adjust by program base */
#define R_SPARC_UA32		23	/* Direct 32 bit unaligned */

/* Additional Sparc64 relocs.  */

#define R_SPARC_PLT32		24	/* Direct 32 bit ref to PLT entry */
#define R_SPARC_HIPLT22		25	/* High 22 bit PLT entry */
#define R_SPARC_LOPLT10		26	/* Truncated 10 bit PLT entry */
#define R_SPARC_PCPLT32		27	/* PC rel 32 bit ref to PLT entry */
#define R_SPARC_PCPLT22		28	/* PC rel high 22 bit PLT entry */
#define R_SPARC_PCPLT10		29	/* PC rel trunc 10 bit PLT entry */
#define R_SPARC_10		30	/* Direct 10 bit */
#define R_SPARC_11		31	/* Direct 11 bit */
#define R_SPARC_64		32	/* Direct 64 bit */
#define R_SPARC_OLO10		33	/* 10bit with secondary 13bit addend */
#define R_SPARC_HH22		34	/* Top 22 bits of direct 64 bit */
#define R_SPARC_HM10		35	/* High middle 10 bits of ... */
#define R_SPARC_LM22		36	/* Low middle 22 bits of ... */
#define R_SPARC_PC_HH22		37	/* Top 22 bits of pc rel 64 bit */
#define R_SPARC_PC_HM10		38	/* High middle 10 bit of ... */
#define R_SPARC_PC_LM22		39	/* Low miggle 22 bits of ... */
#define R_SPARC_WDISP16		40	/* PC relative 16 bit shifted */
#define R_SPARC_WDISP19		41	/* PC relative 19 bit shifted */
#define R_SPARC_7		43	/* Direct 7 bit */
#define R_SPARC_5		44	/* Direct 5 bit */
#define R_SPARC_6		45	/* Direct 6 bit */
#define R_SPARC_DISP64		46	/* PC relative 64 bit */
#define R_SPARC_PLT64		47	/* Direct 64 bit ref to PLT entry */
#define R_SPARC_HIX22		48	/* High 22 bit complemented */
#define R_SPARC_LOX10		49	/* Truncated 11 bit complemented */
#define R_SPARC_H44		50	/* Direct high 12 of 44 bit */
#define R_SPARC_M44		51	/* Direct mid 22 of 44 bit */
#define R_SPARC_L44		52	/* Direct low 10 of 44 bit */
#define R_SPARC_REGISTER	53	/* Global register usage */
#define R_SPARC_UA64		54	/* Direct 64 bit unaligned */
#define R_SPARC_UA16		55	/* Direct 16 bit unaligned */
#define R_SPARC_TLS_GD_HI22	56
#define R_SPARC_TLS_GD_LO10	57
#define R_SPARC_TLS_GD_ADD	58
#define R_SPARC_TLS_GD_CALL	59
#define R_SPARC_TLS_LDM_HI22	60
#define R_SPARC_TLS_LDM_LO10	61
#define R_SPARC_TLS_LDM_ADD	62
#define R_SPARC_TLS_LDM_CALL	63
#define R_SPARC_TLS_LDO_HIX22	64
#define R_SPARC_TLS_LDO_LOX10	65
#define R_SPARC_TLS_LDO_ADD	66
#define R_SPARC_TLS_IE_HI22	67
#define R_SPARC_TLS_IE_LO10	68
#define R_SPARC_TLS_IE_LD	69
#define R_SPARC_TLS_IE_LDX	70
#define R_SPARC_TLS_IE_ADD	71
#define R_SPARC_TLS_LE_HIX22	72
#define R_SPARC_TLS_LE_LOX10	73
#define R_SPARC_TLS_DTPMOD32	74
#define R_SPARC_TLS_DTPMOD64	75
#define R_SPARC_TLS_DTPOFF32	76
#define R_SPARC_TLS_DTPOFF64	77
#define R_SPARC_TLS_TPOFF32	78
#define R_SPARC_TLS_TPOFF64	79
/* Keep this the last entry.  */
#define R_SPARC_NUM		80

/* For Sparc64, legal values for d_tag of Elf64_Dyn.  */

#define DT_SPARC_REGISTER 0x70000001
#define DT_SPARC_NUM	2

/* Bits present in AT_HWCAP, primarily for Sparc32.  */

#define HWCAP_SPARC_FLUSH	1	/* The cpu supports flush insn.  */
#define HWCAP_SPARC_STBAR	2
#define HWCAP_SPARC_SWAP	4
#define HWCAP_SPARC_MULDIV	8
#define HWCAP_SPARC_V9		16	/* The cpu is v9, so v8plus is ok.  */
#define HWCAP_SPARC_ULTRA3	32

/* MIPS R3000 specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

#define EF_MIPS_NOREORDER   1		/* A .noreorder directive was used */
#define EF_MIPS_PIC	    2		/* Contains PIC code */
#define EF_MIPS_CPIC	    4		/* Uses PIC calling sequence */
#define EF_MIPS_XGOT	    8
#define EF_MIPS_64BIT_WHIRL 16
#define EF_MIPS_ABI2	    32
#define EF_MIPS_ABI_ON32    64
#define EF_MIPS_ARCH	    0xf0000000	/* MIPS architecture level */

/* Legal values for MIPS architecture level.  */

#define EF_MIPS_ARCH_1	    0x00000000	/* -mips1 code.  */
#define EF_MIPS_ARCH_2	    0x10000000	/* -mips2 code.  */
#define EF_MIPS_ARCH_3	    0x20000000	/* -mips3 code.  */
#define EF_MIPS_ARCH_4	    0x30000000	/* -mips4 code.  */
#define EF_MIPS_ARCH_5	    0x40000000	/* -mips5 code.  */
#define EF_MIPS_ARCH_32	    0x60000000	/* MIPS32 code.  */
#define EF_MIPS_ARCH_64	    0x70000000	/* MIPS64 code.  */

/* The following are non-official names and should not be used.  */

#define E_MIPS_ARCH_1	  0x00000000	/* -mips1 code.  */
#define E_MIPS_ARCH_2	  0x10000000	/* -mips2 code.  */
#define E_MIPS_ARCH_3	  0x20000000	/* -mips3 code.  */
#define E_MIPS_ARCH_4	  0x30000000	/* -mips4 code.  */
#define E_MIPS_ARCH_5	  0x40000000	/* -mips5 code.  */
#define E_MIPS_ARCH_32	  0x60000000	/* MIPS32 code.  */
#define E_MIPS_ARCH_64	  0x70000000	/* MIPS64 code.  */

/* Special section indices.  */

#define SHN_MIPS_ACOMMON    0xff00	/* Allocated common symbols */
#define SHN_MIPS_TEXT	    0xff01	/* Allocated test symbols.  */
#define SHN_MIPS_DATA	    0xff02	/* Allocated data symbols.  */
#define SHN_MIPS_SCOMMON    0xff03	/* Small common symbols */
#define SHN_MIPS_SUNDEFINED 0xff04	/* Small undefined symbols */

/* Legal values for sh_type field of Elf32_Shdr.  */

#define SHT_MIPS_LIBLIST       0x70000000 /* Shared objects used in link */
#define SHT_MIPS_MSYM	       0x70000001
#define SHT_MIPS_CONFLICT      0x70000002 /* Conflicting symbols */
#define SHT_MIPS_GPTAB	       0x70000003 /* Global data area sizes */
#define SHT_MIPS_UCODE	       0x70000004 /* Reserved for SGI/MIPS compilers */
#define SHT_MIPS_DEBUG	       0x70000005 /* MIPS ECOFF debugging information*/
#define SHT_MIPS_REGINFO       0x70000006 /* Register usage information */
#define SHT_MIPS_PACKAGE       0x70000007
#define SHT_MIPS_PACKSYM       0x70000008
#define SHT_MIPS_RELD	       0x70000009
#define SHT_MIPS_IFACE         0x7000000b
#define SHT_MIPS_CONTENT       0x7000000c
#define SHT_MIPS_OPTIONS       0x7000000d /* Miscellaneous options.  */
#define SHT_MIPS_SHDR	       0x70000010
#define SHT_MIPS_FDESC	       0x70000011
#define SHT_MIPS_EXTSYM	       0x70000012
#define SHT_MIPS_DENSE	       0x70000013
#define SHT_MIPS_PDESC	       0x70000014
#define SHT_MIPS_LOCSYM	       0x70000015
#define SHT_MIPS_AUXSYM	       0x70000016
#define SHT_MIPS_OPTSYM	       0x70000017
#define SHT_MIPS_LOCSTR	       0x70000018
#define SHT_MIPS_LINE	       0x70000019
#define SHT_MIPS_RFDESC	       0x7000001a
#define SHT_MIPS_DELTASYM      0x7000001b
#define SHT_MIPS_DELTAINST     0x7000001c
#define SHT_MIPS_DELTACLASS    0x7000001d
#define SHT_MIPS_DWARF         0x7000001e /* DWARF debugging information.  */
#define SHT_MIPS_DELTADECL     0x7000001f
#define SHT_MIPS_SYMBOL_LIB    0x70000020
#define SHT_MIPS_EVENTS	       0x70000021 /* Event section.  */
#define SHT_MIPS_TRANSLATE     0x70000022
#define SHT_MIPS_PIXIE	       0x70000023
#define SHT_MIPS_XLATE	       0x70000024
#define SHT_MIPS_XLATE_DEBUG   0x70000025
#define SHT_MIPS_WHIRL	       0x70000026
#define SHT_MIPS_EH_REGION     0x70000027
#define SHT_MIPS_XLATE_OLD     0x70000028
#define SHT_MIPS_PDR_EXCEPTION 0x70000029

/* Legal values for sh_flags field of Elf32_Shdr.  */

#define SHF_MIPS_GPREL	 0x10000000	/* Must be part of global data area */
#define SHF_MIPS_MERGE	 0x20000000
#define SHF_MIPS_ADDR	 0x40000000
#define SHF_MIPS_STRINGS 0x80000000
#define SHF_MIPS_NOSTRIP 0x08000000
#define SHF_MIPS_LOCAL	 0x04000000
#define SHF_MIPS_NAMES	 0x02000000
#define SHF_MIPS_NODUPE	 0x01000000


/* Symbol tables.  */

/* MIPS specific values for `st_other'.  */
#define STO_MIPS_DEFAULT		0x0
#define STO_MIPS_INTERNAL		0x1
#define STO_MIPS_HIDDEN			0x2
#define STO_MIPS_PROTECTED		0x3
#define STO_MIPS_SC_ALIGN_UNUSED	0xff

/* MIPS specific values for `st_info'.  */
#define STB_MIPS_SPLIT_COMMON		13

/* Entries found in sections of type SHT_MIPS_GPTAB.  */

typedef union
{
  struct
    {
      Elf32_Word gt_current_g_value;	/* -G value used for compilation */
      Elf32_Word gt_unused;		/* Not used */
    } gt_header;			/* First entry in section */
  struct
    {
      Elf32_Word gt_g_value;		/* If this value were used for -G */
      Elf32_Word gt_bytes;		/* This many bytes would be used */
    } gt_entry;				/* Subsequent entries in section */
} Elf32_gptab;

/* Entry found in sections of type SHT_MIPS_REGINFO.  */

typedef struct
{
  Elf32_Word	ri_gprmask;		/* General registers used */
  Elf32_Word	ri_cprmask[4];		/* Coprocessor registers used */
  Elf32_Sword	ri_gp_value;		/* $gp register value */
} Elf32_RegInfo;

/* Entries found in sections of type SHT_MIPS_OPTIONS.  */

typedef struct
{
  unsigned char kind;		/* Determines interpretation of the
				   variable part of descriptor.  */
  unsigned char size;		/* Size of descriptor, including header.  */
  Elf32_Section section;	/* Section header index of section affected,
				   0 for global options.  */
  Elf32_Word info;		/* Kind-specific information.  */
} Elf_Options;

/* Values for `kind' field in Elf_Options.  */

#define ODK_NULL	0	/* Undefined.  */
#define ODK_REGINFO	1	/* Register usage information.  */
#define ODK_EXCEPTIONS	2	/* Exception processing options.  */
#define ODK_PAD		3	/* Section padding options.  */
#define ODK_HWPATCH	4	/* Hardware workarounds performed */
#define ODK_FILL	5	/* record the fill value used by the linker. */
#define ODK_TAGS	6	/* reserve space for desktop tools to write. */
#define ODK_HWAND	7	/* HW workarounds.  'AND' bits when merging. */
#define ODK_HWOR	8	/* HW workarounds.  'OR' bits when merging.  */

/* Values for `info' in Elf_Options for ODK_EXCEPTIONS entries.  */

#define OEX_FPU_MIN	0x1f	/* FPE's which MUST be enabled.  */
#define OEX_FPU_MAX	0x1f00	/* FPE's which MAY be enabled.  */
#define OEX_PAGE0	0x10000	/* page zero must be mapped.  */
#define OEX_SMM		0x20000	/* Force sequential memory mode?  */
#define OEX_FPDBUG	0x40000	/* Force floating point debug mode?  */
#define OEX_PRECISEFP	OEX_FPDBUG
#define OEX_DISMISS	0x80000	/* Dismiss invalid address faults?  */

#define OEX_FPU_INVAL	0x10
#define OEX_FPU_DIV0	0x08
#define OEX_FPU_OFLO	0x04
#define OEX_FPU_UFLO	0x02
#define OEX_FPU_INEX	0x01

/* Masks for `info' in Elf_Options for an ODK_HWPATCH entry.  */

#define OHW_R4KEOP	0x1	/* R4000 end-of-page patch.  */
#define OHW_R8KPFETCH	0x2	/* may need R8000 prefetch patch.  */
#define OHW_R5KEOP	0x4	/* R5000 end-of-page patch.  */
#define OHW_R5KCVTL	0x8	/* R5000 cvt.[ds].l bug.  clean=1.  */

#define OPAD_PREFIX	0x1
#define OPAD_POSTFIX	0x2
#define OPAD_SYMBOL	0x4

/* Entry found in `.options' section.  */

typedef struct
{
  Elf32_Word hwp_flags1;	/* Extra flags.  */
  Elf32_Word hwp_flags2;	/* Extra flags.  */
} Elf_Options_Hw;

/* Masks for `info' in ElfOptions for ODK_HWAND and ODK_HWOR entries.  */

#define OHWA0_R4KEOP_CHECKED	0x00000001
#define OHWA1_R4KEOP_CLEAN	0x00000002

/* MIPS relocs.  */

#define R_MIPS_NONE		0	/* No reloc */
#define R_MIPS_16		1	/* Direct 16 bit */
#define R_MIPS_32		2	/* Direct 32 bit */
#define R_MIPS_REL32		3	/* PC relative 32 bit */
#define R_MIPS_26		4	/* Direct 26 bit shifted */
#define R_MIPS_HI16		5	/* High 16 bit */
#define R_MIPS_LO16		6	/* Low 16 bit */
#define R_MIPS_GPREL16		7	/* GP relative 16 bit */
#define R_MIPS_LITERAL		8	/* 16 bit literal entry */
#define R_MIPS_GOT16		9	/* 16 bit GOT entry */
#define R_MIPS_PC16		10	/* PC relative 16 bit */
#define R_MIPS_CALL16		11	/* 16 bit GOT entry for function */
#define R_MIPS_GPREL32		12	/* GP relative 32 bit */

#define R_MIPS_SHIFT5		16
#define R_MIPS_SHIFT6		17
#define R_MIPS_64		18
#define R_MIPS_GOT_DISP		19
#define R_MIPS_GOT_PAGE		20
#define R_MIPS_GOT_OFST		21
#define R_MIPS_GOT_HI16		22
#define R_MIPS_GOT_LO16		23
#define R_MIPS_SUB		24
#define R_MIPS_INSERT_A		25
#define R_MIPS_INSERT_B		26
#define R_MIPS_DELETE		27
#define R_MIPS_HIGHER		28
#define R_MIPS_HIGHEST		29
#define R_MIPS_CALL_HI16	30
#define R_MIPS_CALL_LO16	31
#define R_MIPS_SCN_DISP		32
#define R_MIPS_REL16		33
#define R_MIPS_ADD_IMMEDIATE	34
#define R_MIPS_PJUMP		35
#define R_MIPS_RELGOT		36
#define R_MIPS_JALR		37
/* Keep this the last entry.  */
#define R_MIPS_NUM		38

/* Legal values for p_type field of Elf32_Phdr.  */

#define PT_MIPS_REGINFO	0x70000000	/* Register usage information */
#define PT_MIPS_RTPROC  0x70000001	/* Runtime procedure table. */
#define PT_MIPS_OPTIONS 0x70000002

/* Special program header types.  */

#define PF_MIPS_LOCAL	0x10000000

/* Legal values for d_tag field of Elf32_Dyn.  */

#define DT_MIPS_RLD_VERSION  0x70000001	/* Runtime linker interface version */
#define DT_MIPS_TIME_STAMP   0x70000002	/* Timestamp */
#define DT_MIPS_ICHECKSUM    0x70000003	/* Checksum */
#define DT_MIPS_IVERSION     0x70000004	/* Version string (string tbl index) */
#define DT_MIPS_FLAGS	     0x70000005	/* Flags */
#define DT_MIPS_BASE_ADDRESS 0x70000006	/* Base address */
#define DT_MIPS_MSYM	     0x70000007
#define DT_MIPS_CONFLICT     0x70000008	/* Address of CONFLICT section */
#define DT_MIPS_LIBLIST	     0x70000009	/* Address of LIBLIST section */
#define DT_MIPS_LOCAL_GOTNO  0x7000000a	/* Number of local GOT entries */
#define DT_MIPS_CONFLICTNO   0x7000000b	/* Number of CONFLICT entries */
#define DT_MIPS_LIBLISTNO    0x70000010	/* Number of LIBLIST entries */
#define DT_MIPS_SYMTABNO     0x70000011	/* Number of DYNSYM entries */
#define DT_MIPS_UNREFEXTNO   0x70000012	/* First external DYNSYM */
#define DT_MIPS_GOTSYM	     0x70000013	/* First GOT entry in DYNSYM */
#define DT_MIPS_HIPAGENO     0x70000014	/* Number of GOT page table entries */
#define DT_MIPS_RLD_MAP	     0x70000016	/* Address of run time loader map.  */
#define DT_MIPS_DELTA_CLASS  0x70000017	/* Delta C++ class definition.  */
#define DT_MIPS_DELTA_CLASS_NO    0x70000018 /* Number of entries in
						DT_MIPS_DELTA_CLASS.  */
#define DT_MIPS_DELTA_INSTANCE    0x70000019 /* Delta C++ class instances.  */
#define DT_MIPS_DELTA_INSTANCE_NO 0x7000001a /* Number of entries in
						DT_MIPS_DELTA_INSTANCE.  */
#define DT_MIPS_DELTA_RELOC  0x7000001b /* Delta relocations.  */
#define DT_MIPS_DELTA_RELOC_NO 0x7000001c /* Number of entries in
					     DT_MIPS_DELTA_RELOC.  */
#define DT_MIPS_DELTA_SYM    0x7000001d /* Delta symbols that Delta
					   relocations refer to.  */
#define DT_MIPS_DELTA_SYM_NO 0x7000001e /* Number of entries in
					   DT_MIPS_DELTA_SYM.  */
#define DT_MIPS_DELTA_CLASSSYM 0x70000020 /* Delta symbols that hold the
					     class declaration.  */
#define DT_MIPS_DELTA_CLASSSYM_NO 0x70000021 /* Number of entries in
						DT_MIPS_DELTA_CLASSSYM.  */
#define DT_MIPS_CXX_FLAGS    0x70000022 /* Flags indicating for C++ flavor.  */
#define DT_MIPS_PIXIE_INIT   0x70000023
#define DT_MIPS_SYMBOL_LIB   0x70000024
#define DT_MIPS_LOCALPAGE_GOTIDX 0x70000025
#define DT_MIPS_LOCAL_GOTIDX 0x70000026
#define DT_MIPS_HIDDEN_GOTIDX 0x70000027
#define DT_MIPS_PROTECTED_GOTIDX 0x70000028
#define DT_MIPS_OPTIONS	     0x70000029 /* Address of .options.  */
#define DT_MIPS_INTERFACE    0x7000002a /* Address of .interface.  */
#define DT_MIPS_DYNSTR_ALIGN 0x7000002b
#define DT_MIPS_INTERFACE_SIZE 0x7000002c /* Size of the .interface section. */
#define DT_MIPS_RLD_TEXT_RESOLVE_ADDR 0x7000002d /* Address of rld_text_rsolve
						    function stored in GOT.  */
#define DT_MIPS_PERF_SUFFIX  0x7000002e /* Default suffix of dso to be added
					   by rld on dlopen() calls.  */
#define DT_MIPS_COMPACT_SIZE 0x7000002f /* (O32)Size of compact rel section. */
#define DT_MIPS_GP_VALUE     0x70000030 /* GP value for aux GOTs.  */
#define DT_MIPS_AUX_DYNAMIC  0x70000031 /* Address of aux .dynamic.  */
#define DT_MIPS_NUM	     0x32

/* Legal values for DT_MIPS_FLAGS Elf32_Dyn entry.  */

#define RHF_NONE		   0		/* No flags */
#define RHF_QUICKSTART		   (1 << 0)	/* Use quickstart */
#define RHF_NOTPOT		   (1 << 1)	/* Hash size not power of 2 */
#define RHF_NO_LIBRARY_REPLACEMENT (1 << 2)	/* Ignore LD_LIBRARY_PATH */
#define RHF_NO_MOVE		   (1 << 3)
#define RHF_SGI_ONLY		   (1 << 4)
#define RHF_GUARANTEE_INIT	   (1 << 5)
#define RHF_DELTA_C_PLUS_PLUS	   (1 << 6)
#define RHF_GUARANTEE_START_INIT   (1 << 7)
#define RHF_PIXIE		   (1 << 8)
#define RHF_DEFAULT_DELAY_LOAD	   (1 << 9)
#define RHF_REQUICKSTART	   (1 << 10)
#define RHF_REQUICKSTARTED	   (1 << 11)
#define RHF_CORD		   (1 << 12)
#define RHF_NO_UNRES_UNDEF	   (1 << 13)
#define RHF_RLD_ORDER_SAFE	   (1 << 14)

/* Entries found in sections of type SHT_MIPS_LIBLIST.  */

typedef struct
{
  Elf32_Word l_name;		/* Name (string table index) */
  Elf32_Word l_time_stamp;	/* Timestamp */
  Elf32_Word l_checksum;	/* Checksum */
  Elf32_Word l_version;		/* Interface version */
  Elf32_Word l_flags;		/* Flags */
} Elf32_Lib;

typedef struct
{
  Elf64_Word l_name;		/* Name (string table index) */
  Elf64_Word l_time_stamp;	/* Timestamp */
  Elf64_Word l_checksum;	/* Checksum */
  Elf64_Word l_version;		/* Interface version */
  Elf64_Word l_flags;		/* Flags */
} Elf64_Lib;


/* Legal values for l_flags.  */

#define LL_NONE		  0
#define LL_EXACT_MATCH	  (1 << 0)	/* Require exact match */
#define LL_IGNORE_INT_VER (1 << 1)	/* Ignore interface version */
#define LL_REQUIRE_MINOR  (1 << 2)
#define LL_EXPORTS	  (1 << 3)
#define LL_DELAY_LOAD	  (1 << 4)
#define LL_DELTA	  (1 << 5)

/* Entries found in sections of type SHT_MIPS_CONFLICT.  */

typedef Elf32_Addr Elf32_Conflict;


/* HPPA specific definitions.  */

/* Legal values for e_flags field of Elf32_Ehdr.  */

#define EF_PARISC_TRAPNIL	0x00010000 /* Trap nil pointer dereference.  */
#define EF_PARISC_EXT		0x00020000 /* Program uses arch. extensions. */
#define EF_PARISC_LSB		0x00040000 /* Program expects little endian. */
#define EF_PARISC_WIDE		0x00080000 /* Program expects wide mode.  */
#define EF_PARISC_NO_KABP	0x00100000 /* No kernel assisted branch
					      prediction.  */
#define EF_PARISC_LAZYSWAP	0x00400000 /* Allow lazy swapping.  */
#define EF_PARISC_ARCH		0x0000ffff /* Architecture version.  */

/* Defined values for `e_flags & EF_PARISC_ARCH' are:  */

#define EFA_PARISC_1_0		    0x020b /* PA-RISC 1.0 big-endian.  */
#define EFA_PARISC_1_1		    0x0210 /* PA-RISC 1.1 big-endian.  */
#define EFA_PARISC_2_0		    0x0214 /* PA-RISC 2.0 big-endian.  */

/* Additional section indeces.  */

#define SHN_PARISC_ANSI_COMMON	0xff00	   /* Section for tenatively declared
					      symbols in ANSI C.  */
#define SHN_PARISC_HUGE_COMMON	0xff01	   /* Common blocks in huge model.  */

/* Legal values for sh_type field of Elf32_Shdr.  */

#define SHT_PARISC_EXT		0x70000000 /* Contains product specific ext. */
#define SHT_PARISC_UNWIND	0x70000001 /* Unwind information.  */
#define SHT_PARISC_DOC		0x70000002 /* Debug info for optimized code. */

/* Legal values for sh_flags field of Elf32_Shdr.  */

#define SHF_PARISC_SHORT	0x20000000 /* Section with short addressing. */
#define SHF_PARISC_HUGE		0x40000000 /* Section far from gp.  */
#define SHF_PARISC_SBP		0x80000000 /* Static branch prediction code. */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_PARISC_MILLICODE	13	/* Millicode function entry point.  */

#define STT_HP_OPAQUE		(STT_LOOS + 0x1)
#define STT_HP_STUB		(STT_LOOS + 0x2)

/* HPPA relocs.  */

#define R_PARISC_NONE		0	/* No reloc.  */
#define R_PARISC_DIR32		1	/* Direct 32-bit reference.  */
#define R_PARISC_DIR21L		2	/* Left 21 bits of eff. address.  */
#define R_PARISC_DIR17R		3	/* Right 17 bits of eff. address.  */
#define R_PARISC_DIR17F		4	/* 17 bits of eff. address.  */
#define R_PARISC_DIR14R		6	/* Right 14 bits of eff. address.  */
#define R_PARISC_PCREL32	9	/* 32-bit rel. address.  */
#define R_PARISC_PCREL21L	10	/* Left 21 bits of rel. address.  */
#define R_PARISC_PCREL17R	11	/* Right 17 bits of rel. address.  */
#define R_PARISC_PCREL17F	12	/* 17 bits of rel. address.  */
#define R_PARISC_PCREL14R	14	/* Right 14 bits of rel. address.  */
#define R_PARISC_DPREL21L	18	/* Left 21 bits of rel. address.  */
#define R_PARISC_DPREL14R	22	/* Right 14 bits of rel. address.  */
#define R_PARISC_GPREL21L	26	/* GP-relative, left 21 bits.  */
#define R_PARISC_GPREL14R	30	/* GP-relative, right 14 bits.  */
#define R_PARISC_LTOFF21L	34	/* LT-relative, left 21 bits.  */
#define R_PARISC_LTOFF14R	38	/* LT-relative, right 14 bits.  */
#define R_PARISC_SECREL32	41	/* 32 bits section rel. address.  */
#define R_PARISC_SEGBASE	48	/* No relocation, set segment base.  */
#define R_PARISC_SEGREL32	49	/* 32 bits segment rel. address.  */
#define R_PARISC_PLTOFF21L	50	/* PLT rel. address, left 21 bits.  */
#define R_PARISC_PLTOFF14R	54	/* PLT rel. address, right 14 bits.  */
#define R_PARISC_LTOFF_FPTR32	57	/* 32 bits LT-rel. function pointer. */
#define R_PARISC_LTOFF_FPTR21L	58	/* LT-rel. fct ptr, left 21 bits. */
#define R_PARISC_LTOFF_FPTR14R	62	/* LT-rel. fct ptr, right 14 bits. */
#define R_PARISC_FPTR64		64	/* 64 bits function address.  */
#define R_PARISC_PLABEL32	65	/* 32 bits function address.  */
#define R_PARISC_PCREL64	72	/* 64 bits PC-rel. address.  */
#define R_PARISC_PCREL22F	74	/* 22 bits PC-rel. address.  */
#define R_PARISC_PCREL14WR	75	/* PC-rel. address, right 14 bits.  */
#define R_PARISC_PCREL14DR	76	/* PC rel. address, right 14 bits.  */
#define R_PARISC_PCREL16F	77	/* 16 bits PC-rel. address.  */
#define R_PARISC_PCREL16WF	78	/* 16 bits PC-rel. address.  */
#define R_PARISC_PCREL16DF	79	/* 16 bits PC-rel. address.  */
#define R_PARISC_DIR64		80	/* 64 bits of eff. address.  */
#define R_PARISC_DIR14WR	83	/* 14 bits of eff. address.  */
#define R_PARISC_DIR14DR	84	/* 14 bits of eff. address.  */
#define R_PARISC_DIR16F		85	/* 16 bits of eff. address.  */
#define R_PARISC_DIR16WF	86	/* 16 bits of eff. address.  */
#define R_PARISC_DIR16DF	87	/* 16 bits of eff. address.  */
#define R_PARISC_GPREL64	88	/* 64 bits of GP-rel. address.  */
#define R_PARISC_GPREL14WR	91	/* GP-rel. address, right 14 bits.  */
#define R_PARISC_GPREL14DR	92	/* GP-rel. address, right 14 bits.  */
#define R_PARISC_GPREL16F	93	/* 16 bits GP-rel. address.  */
#define R_PARISC_GPREL16WF	94	/* 16 bits GP-rel. address.  */
#define R_PARISC_GPREL16DF	95	/* 16 bits GP-rel. address.  */
#define R_PARISC_LTOFF64	96	/* 64 bits LT-rel. address.  */
#define R_PARISC_LTOFF14WR	99	/* LT-rel. address, right 14 bits.  */
#define R_PARISC_LTOFF14DR	100	/* LT-rel. address, right 14 bits.  */
#define R_PARISC_LTOFF16F	101	/* 16 bits LT-rel. address.  */
#define R_PARISC_LTOFF16WF	102	/* 16 bits LT-rel. address.  */
#define R_PARISC_LTOFF16DF	103	/* 16 bits LT-rel. address.  */
#define R_PARISC_SECREL64	104	/* 64 bits section rel. address.  */
#define R_PARISC_SEGREL64	112	/* 64 bits segment rel. address.  */
#define R_PARISC_PLTOFF14WR	115	/* PLT-rel. address, right 14 bits.  */
#define R_PARISC_PLTOFF14DR	116	/* PLT-rel. address, right 14 bits.  */
#define R_PARISC_PLTOFF16F	117	/* 16 bits LT-rel. address.  */
#define R_PARISC_PLTOFF16WF	118	/* 16 bits PLT-rel. address.  */
#define R_PARISC_PLTOFF16DF	119	/* 16 bits PLT-rel. address.  */
#define R_PARISC_LTOFF_FPTR64	120	/* 64 bits LT-rel. function ptr.  */
#define R_PARISC_LTOFF_FPTR14WR	123	/* LT-rel. fct. ptr., right 14 bits. */
#define R_PARISC_LTOFF_FPTR14DR	124	/* LT-rel. fct. ptr., right 14 bits. */
#define R_PARISC_LTOFF_FPTR16F	125	/* 16 bits LT-rel. function ptr.  */
#define R_PARISC_LTOFF_FPTR16WF	126	/* 16 bits LT-rel. function ptr.  */
#define R_PARISC_LTOFF_FPTR16DF	127	/* 16 bits LT-rel. function ptr.  */
#define R_PARISC_LORESERVE	128
#define R_PARISC_COPY		128	/* Copy relocation.  */
#define R_PARISC_IPLT		129	/* Dynamic reloc, imported PLT */
#define R_PARISC_EPLT		130	/* Dynamic reloc, exported PLT */
#define R_PARISC_TPREL32	153	/* 32 bits TP-rel. address.  */
#define R_PARISC_TPREL21L	154	/* TP-rel. address, left 21 bits.  */
#define R_PARISC_TPREL14R	158	/* TP-rel. address, right 14 bits.  */
#define R_PARISC_LTOFF_TP21L	162	/* LT-TP-rel. address, left 21 bits. */
#define R_PARISC_LTOFF_TP14R	166	/* LT-TP-rel. address, right 14 bits.*/
#define R_PARISC_LTOFF_TP14F	167	/* 14 bits LT-TP-rel. address.  */
#define R_PARISC_TPREL64	216	/* 64 bits TP-rel. address.  */
#define R_PARISC_TPREL14WR	219	/* TP-rel. address, right 14 bits.  */
#define R_PARISC_TPREL14DR	220	/* TP-rel. address, right 14 bits.  */
#define R_PARISC_TPREL16F	221	/* 16 bits TP-rel. address.  */
#define R_PARISC_TPREL16WF	222	/* 16 bits TP-rel. address.  */
#define R_PARISC_TPREL16DF	223	/* 16 bits TP-rel. address.  */
#define R_PARISC_LTOFF_TP64	224	/* 64 bits LT-TP-rel. address.  */
#define R_PARISC_LTOFF_TP14WR	227	/* LT-TP-rel. address, right 14 bits.*/
#define R_PARISC_LTOFF_TP14DR	228	/* LT-TP-rel. address, right 14 bits.*/
#define R_PARISC_LTOFF_TP16F	229	/* 16 bits LT-TP-rel. address.  */
#define R_PARISC_LTOFF_TP16WF	230	/* 16 bits LT-TP-rel. address.  */
#define R_PARISC_LTOFF_TP16DF	231	/* 16 bits LT-TP-rel. address.  */
#define R_PARISC_HIRESERVE	255

/* Legal values for p_type field of Elf32_Phdr/Elf64_Phdr.  */

#define PT_HP_TLS		(PT_LOOS + 0x0)
#define PT_HP_CORE_NONE		(PT_LOOS + 0x1)
#define PT_HP_CORE_VERSION	(PT_LOOS + 0x2)
#define PT_HP_CORE_KERNEL	(PT_LOOS + 0x3)
#define PT_HP_CORE_COMM		(PT_LOOS + 0x4)
#define PT_HP_CORE_PROC		(PT_LOOS + 0x5)
#define PT_HP_CORE_LOADABLE	(PT_LOOS + 0x6)
#define PT_HP_CORE_STACK	(PT_LOOS + 0x7)
#define PT_HP_CORE_SHM		(PT_LOOS + 0x8)
#define PT_HP_CORE_MMF		(PT_LOOS + 0x9)
#define PT_HP_PARALLEL		(PT_LOOS + 0x10)
#define PT_HP_FASTBIND		(PT_LOOS + 0x11)
#define PT_HP_OPT_ANNOT		(PT_LOOS + 0x12)
#define PT_HP_HSL_ANNOT		(PT_LOOS + 0x13)
#define PT_HP_STACK		(PT_LOOS + 0x14)

#define PT_PARISC_ARCHEXT	0x70000000
#define PT_PARISC_UNWIND	0x70000001

/* Legal values for p_flags field of Elf32_Phdr/Elf64_Phdr.  */

#define PF_PARISC_SBP		0x08000000

#define PF_HP_PAGE_SIZE		0x00100000
#define PF_HP_FAR_SHARED	0x00200000
#define PF_HP_NEAR_SHARED	0x00400000
#define PF_HP_CODE		0x01000000
#define PF_HP_MODIFY		0x02000000
#define PF_HP_LAZYSWAP		0x04000000
#define PF_HP_SBP		0x08000000


/* Alpha specific definitions.  */

/* Legal values for e_flags field of Elf64_Ehdr.  */

#define EF_ALPHA_32BIT		1	/* All addresses must be < 2GB.  */
#define EF_ALPHA_CANRELAX	2	/* Relocations for relaxing exist.  */

/* Legal values for sh_type field of Elf64_Shdr.  */

/* These two are primerily concerned with ECOFF debugging info.  */
#define SHT_ALPHA_DEBUG		0x70000001
#define SHT_ALPHA_REGINFO	0x70000002

/* Legal values for sh_flags field of Elf64_Shdr.  */

#define SHF_ALPHA_GPREL		0x10000000

/* Legal values for st_other field of Elf64_Sym.  */
#define STO_ALPHA_NOPV		0x80	/* No PV required.  */
#define STO_ALPHA_STD_GPLOAD	0x88	/* PV only used for initial ldgp.  */

/* Alpha relocs.  */

#define R_ALPHA_NONE		0	/* No reloc */
#define R_ALPHA_REFLONG		1	/* Direct 32 bit */
#define R_ALPHA_REFQUAD		2	/* Direct 64 bit */
#define R_ALPHA_GPREL32		3	/* GP relative 32 bit */
#define R_ALPHA_LITERAL		4	/* GP relative 16 bit w/optimization */
#define R_ALPHA_LITUSE		5	/* Optimization hint for LITERAL */
#define R_ALPHA_GPDISP		6	/* Add displacement to GP */
#define R_ALPHA_BRADDR		7	/* PC+4 relative 23 bit shifted */
#define R_ALPHA_HINT		8	/* PC+4 relative 16 bit shifted */
#define R_ALPHA_SREL16		9	/* PC relative 16 bit */
#define R_ALPHA_SREL32		10	/* PC relative 32 bit */
#define R_ALPHA_SREL64		11	/* PC relative 64 bit */
#define R_ALPHA_GPRELHIGH	17	/* GP relative 32 bit, high 16 bits */
#define R_ALPHA_GPRELLOW	18	/* GP relative 32 bit, low 16 bits */
#define R_ALPHA_GPREL16		19	/* GP relative 16 bit */
#define R_ALPHA_COPY		24	/* Copy symbol at runtime */
#define R_ALPHA_GLOB_DAT	25	/* Create GOT entry */
#define R_ALPHA_JMP_SLOT	26	/* Create PLT entry */
#define R_ALPHA_RELATIVE	27	/* Adjust by program base */
#define R_ALPHA_TLS_GD_HI	28
#define R_ALPHA_TLSGD		29
#define R_ALPHA_TLS_LDM		30
#define R_ALPHA_DTPMOD64	31
#define R_ALPHA_GOTDTPREL	32
#define R_ALPHA_DTPREL64	33
#define R_ALPHA_DTPRELHI	34
#define R_ALPHA_DTPRELLO	35
#define R_ALPHA_DTPREL16	36
#define R_ALPHA_GOTTPREL	37
#define R_ALPHA_TPREL64		38
#define R_ALPHA_TPRELHI		39
#define R_ALPHA_TPRELLO		40
#define R_ALPHA_TPREL16		41
/* Keep this the last entry.  */
#define R_ALPHA_NUM		46

/* Magic values of the LITUSE relocation addend.  */
#define LITUSE_ALPHA_ADDR	0
#define LITUSE_ALPHA_BASE	1
#define LITUSE_ALPHA_BYTOFF	2
#define LITUSE_ALPHA_JSR	3
#define LITUSE_ALPHA_TLS_GD	4
#define LITUSE_ALPHA_TLS_LDM	5


/* PowerPC specific declarations */

/* Values for Elf32/64_Ehdr.e_flags.  */
#define EF_PPC_EMB		0x80000000	/* PowerPC embedded flag */

/* Cygnus local bits below */
#define EF_PPC_RELOCATABLE	0x00010000	/* PowerPC -mrelocatable flag*/
#define EF_PPC_RELOCATABLE_LIB	0x00008000	/* PowerPC -mrelocatable-lib
						   flag */

/* PowerPC relocations defined by the ABIs */
#define R_PPC_NONE		0
#define R_PPC_ADDR32		1	/* 32bit absolute address */
#define R_PPC_ADDR24		2	/* 26bit address, 2 bits ignored.  */
#define R_PPC_ADDR16		3	/* 16bit absolute address */
#define R_PPC_ADDR16_LO		4	/* lower 16bit of absolute address */
#define R_PPC_ADDR16_HI		5	/* high 16bit of absolute address */
#define R_PPC_ADDR16_HA		6	/* adjusted high 16bit */
#define R_PPC_ADDR14		7	/* 16bit address, 2 bits ignored */
#define R_PPC_ADDR14_BRTAKEN	8
#define R_PPC_ADDR14_BRNTAKEN	9
#define R_PPC_REL24		10	/* PC relative 26 bit */
#define R_PPC_REL14		11	/* PC relative 16 bit */
#define R_PPC_REL14_BRTAKEN	12
#define R_PPC_REL14_BRNTAKEN	13
#define R_PPC_GOT16		14
#define R_PPC_GOT16_LO		15
#define R_PPC_GOT16_HI		16
#define R_PPC_GOT16_HA		17
#define R_PPC_PLTREL24		18
#define R_PPC_COPY		19
#define R_PPC_GLOB_DAT		20
#define R_PPC_JMP_SLOT		21
#define R_PPC_RELATIVE		22
#define R_PPC_LOCAL24PC		23
#define R_PPC_UADDR32		24
#define R_PPC_UADDR16		25
#define R_PPC_REL32		26
#define R_PPC_PLT32		27
#define R_PPC_PLTREL32		28
#define R_PPC_PLT16_LO		29
#define R_PPC_PLT16_HI		30
#define R_PPC_PLT16_HA		31
#define R_PPC_SDAREL16		32
#define R_PPC_SECTOFF		33
#define R_PPC_SECTOFF_LO	34
#define R_PPC_SECTOFF_HI	35
#define R_PPC_SECTOFF_HA	36

/* PowerPC relocations defined for the TLS access ABI.  */
#define R_PPC_TLS		67 /* none	(sym+add)@tls */
#define R_PPC_DTPMOD32		68 /* word32	(sym+add)@dtpmod */
#define R_PPC_TPREL16		69 /* half16*	(sym+add)@tprel */
#define R_PPC_TPREL16_LO	70 /* half16	(sym+add)@tprel@l */
#define R_PPC_TPREL16_HI	71 /* half16	(sym+add)@tprel@h */
#define R_PPC_TPREL16_HA	72 /* half16	(sym+add)@tprel@ha */
#define R_PPC_TPREL32		73 /* word32	(sym+add)@tprel */
#define R_PPC_DTPREL16		74 /* half16*	(sym+add)@dtprel */
#define R_PPC_DTPREL16_LO	75 /* half16	(sym+add)@dtprel@l */
#define R_PPC_DTPREL16_HI	76 /* half16	(sym+add)@dtprel@h */
#define R_PPC_DTPREL16_HA	77 /* half16	(sym+add)@dtprel@ha */
#define R_PPC_DTPREL32		78 /* word32	(sym+add)@dtprel */
#define R_PPC_GOT_TLSGD16	79 /* half16*	(sym+add)@got@tlsgd */
#define R_PPC_GOT_TLSGD16_LO	80 /* half16	(sym+add)@got@tlsgd@l */
#define R_PPC_GOT_TLSGD16_HI	81 /* half16	(sym+add)@got@tlsgd@h */
#define R_PPC_GOT_TLSGD16_HA	82 /* half16	(sym+add)@got@tlsgd@ha */
#define R_PPC_GOT_TLSLD16	83 /* half16*	(sym+add)@got@tlsld */
#define R_PPC_GOT_TLSLD16_LO	84 /* half16	(sym+add)@got@tlsld@l */
#define R_PPC_GOT_TLSLD16_HI	85 /* half16	(sym+add)@got@tlsld@h */
#define R_PPC_GOT_TLSLD16_HA	86 /* half16	(sym+add)@got@tlsld@ha */
#define R_PPC_GOT_TPREL16	87 /* half16*	(sym+add)@got@tprel */
#define R_PPC_GOT_TPREL16_LO	88 /* half16	(sym+add)@got@tprel@l */
#define R_PPC_GOT_TPREL16_HI	89 /* half16	(sym+add)@got@tprel@h */
#define R_PPC_GOT_TPREL16_HA	90 /* half16	(sym+add)@got@tprel@ha */
#define R_PPC_GOT_DTPREL16	91 /* half16*	(sym+add)@got@dtprel */
#define R_PPC_GOT_DTPREL16_LO	92 /* half16*	(sym+add)@got@dtprel@l */
#define R_PPC_GOT_DTPREL16_HI	93 /* half16*	(sym+add)@got@dtprel@h */
#define R_PPC_GOT_DTPREL16_HA	94 /* half16*	(sym+add)@got@dtprel@ha */

/* Keep this the last entry.  */
#define R_PPC_NUM		95

/* The remaining relocs are from the Embedded ELF ABI, and are not
   in the SVR4 ELF ABI.  */
#define R_PPC_EMB_NADDR32	101
#define R_PPC_EMB_NADDR16	102
#define R_PPC_EMB_NADDR16_LO	103
#define R_PPC_EMB_NADDR16_HI	104
#define R_PPC_EMB_NADDR16_HA	105
#define R_PPC_EMB_SDAI16	106
#define R_PPC_EMB_SDA2I16	107
#define R_PPC_EMB_SDA2REL	108
#define R_PPC_EMB_SDA21		109	/* 16 bit offset in SDA */
#define R_PPC_EMB_MRKREF	110
#define R_PPC_EMB_RELSEC16	111
#define R_PPC_EMB_RELST_LO	112
#define R_PPC_EMB_RELST_HI	113
#define R_PPC_EMB_RELST_HA	114
#define R_PPC_EMB_BIT_FLD	115
#define R_PPC_EMB_RELSDA	116	/* 16 bit relative offset in SDA */

/* Diab tool relocations.  */
#define R_PPC_DIAB_SDA21_LO	180	/* like EMB_SDA21, but lower 16 bit */
#define R_PPC_DIAB_SDA21_HI	181	/* like EMB_SDA21, but high 16 bit */
#define R_PPC_DIAB_SDA21_HA	182	/* like EMB_SDA21, adjusted high 16 */
#define R_PPC_DIAB_RELSDA_LO	183	/* like EMB_RELSDA, but lower 16 bit */
#define R_PPC_DIAB_RELSDA_HI	184	/* like EMB_RELSDA, but high 16 bit */
#define R_PPC_DIAB_RELSDA_HA	185	/* like EMB_RELSDA, adjusted high 16 */

/* This is a phony reloc to handle any old fashioned TOC16 references
   that may still be in object files.  */
#define R_PPC_TOC16		255


/* PowerPC64 relocations defined by the ABIs */
#define R_PPC64_NONE		R_PPC_NONE
#define R_PPC64_ADDR32		R_PPC_ADDR32 /* 32bit absolute address */
#define R_PPC64_ADDR24		R_PPC_ADDR24 /* 26bit address, word aligned */
#define R_PPC64_ADDR16		R_PPC_ADDR16 /* 16bit absolute address */
#define R_PPC64_ADDR16_LO	R_PPC_ADDR16_LO	/* lower 16bits of address */
#define R_PPC64_ADDR16_HI	R_PPC_ADDR16_HI	/* high 16bits of address. */
#define R_PPC64_ADDR16_HA	R_PPC_ADDR16_HA /* adjusted high 16bits.  */
#define R_PPC64_ADDR14		R_PPC_ADDR14 /* 16bit address, word aligned */
#define R_PPC64_ADDR14_BRTAKEN	R_PPC_ADDR14_BRTAKEN
#define R_PPC64_ADDR14_BRNTAKEN	R_PPC_ADDR14_BRNTAKEN
#define R_PPC64_REL24		R_PPC_REL24 /* PC-rel. 26 bit, word aligned */
#define R_PPC64_REL14		R_PPC_REL14 /* PC relative 16 bit */
#define R_PPC64_REL14_BRTAKEN	R_PPC_REL14_BRTAKEN
#define R_PPC64_REL14_BRNTAKEN	R_PPC_REL14_BRNTAKEN
#define R_PPC64_GOT16		R_PPC_GOT16
#define R_PPC64_GOT16_LO	R_PPC_GOT16_LO
#define R_PPC64_GOT16_HI	R_PPC_GOT16_HI
#define R_PPC64_GOT16_HA	R_PPC_GOT16_HA

#define R_PPC64_COPY		R_PPC_COPY
#define R_PPC64_GLOB_DAT	R_PPC_GLOB_DAT
#define R_PPC64_JMP_SLOT	R_PPC_JMP_SLOT
#define R_PPC64_RELATIVE	R_PPC_RELATIVE

#define R_PPC64_UADDR32		R_PPC_UADDR32
#define R_PPC64_UADDR16		R_PPC_UADDR16
#define R_PPC64_REL32		R_PPC_REL32
#define R_PPC64_PLT32		R_PPC_PLT32
#define R_PPC64_PLTREL32	R_PPC_PLTREL32
#define R_PPC64_PLT16_LO	R_PPC_PLT16_LO
#define R_PPC64_PLT16_HI	R_PPC_PLT16_HI
#define R_PPC64_PLT16_HA	R_PPC_PLT16_HA

#define R_PPC64_SECTOFF		R_PPC_SECTOFF
#define R_PPC64_SECTOFF_LO	R_PPC_SECTOFF_LO
#define R_PPC64_SECTOFF_HI	R_PPC_SECTOFF_HI
#define R_PPC64_SECTOFF_HA	R_PPC_SECTOFF_HA
#define R_PPC64_ADDR30		37 /* word30 (S + A - P) >> 2 */
#define R_PPC64_ADDR64		38 /* doubleword64 S + A */
#define R_PPC64_ADDR16_HIGHER	39 /* half16 #higher(S + A) */
#define R_PPC64_ADDR16_HIGHERA	40 /* half16 #highera(S + A) */
#define R_PPC64_ADDR16_HIGHEST	41 /* half16 #highest(S + A) */
#define R_PPC64_ADDR16_HIGHESTA	42 /* half16 #highesta(S + A) */
#define R_PPC64_UADDR64		43 /* doubleword64 S + A */
#define R_PPC64_REL64		44 /* doubleword64 S + A - P */
#define R_PPC64_PLT64		45 /* doubleword64 L + A */
#define R_PPC64_PLTREL64	46 /* doubleword64 L + A - P */
#define R_PPC64_TOC16		47 /* half16* S + A - .TOC */
#define R_PPC64_TOC16_LO	48 /* half16 #lo(S + A - .TOC.) */
#define R_PPC64_TOC16_HI	49 /* half16 #hi(S + A - .TOC.) */
#define R_PPC64_TOC16_HA	50 /* half16 #ha(S + A - .TOC.) */
#define R_PPC64_TOC		51 /* doubleword64 .TOC */
#define R_PPC64_PLTGOT16	52 /* half16* M + A */
#define R_PPC64_PLTGOT16_LO	53 /* half16 #lo(M + A) */
#define R_PPC64_PLTGOT16_HI	54 /* half16 #hi(M + A) */
#define R_PPC64_PLTGOT16_HA	55 /* half16 #ha(M + A) */

#define R_PPC64_ADDR16_DS	56 /* half16ds* (S + A) >> 2 */
#define R_PPC64_ADDR16_LO_DS	57 /* half16ds  #lo(S + A) >> 2 */
#define R_PPC64_GOT16_DS	58 /* half16ds* (G + A) >> 2 */
#define R_PPC64_GOT16_LO_DS	59 /* half16ds  #lo(G + A) >> 2 */
#define R_PPC64_PLT16_LO_DS	60 /* half16ds  #lo(L + A) >> 2 */
#define R_PPC64_SECTOFF_DS	61 /* half16ds* (R + A) >> 2 */
#define R_PPC64_SECTOFF_LO_DS	62 /* half16ds  #lo(R + A) >> 2 */
#define R_PPC64_TOC16_DS	63 /* half16ds* (S + A - .TOC.) >> 2 */
#define R_PPC64_TOC16_LO_DS	64 /* half16ds  #lo(S + A - .TOC.) >> 2 */
#define R_PPC64_PLTGOT16_DS	65 /* half16ds* (M + A) >> 2 */
#define R_PPC64_PLTGOT16_LO_DS	66 /* half16ds  #lo(M + A) >> 2 */

/* PowerPC64 relocations defined for the TLS access ABI.  */
#define R_PPC64_TLS		67 /* none	(sym+add)@tls */
#define R_PPC64_DTPMOD64	68 /* doubleword64 (sym+add)@dtpmod */
#define R_PPC64_TPREL16		69 /* half16*	(sym+add)@tprel */
#define R_PPC64_TPREL16_LO	70 /* half16	(sym+add)@tprel@l */
#define R_PPC64_TPREL16_HI	71 /* half16	(sym+add)@tprel@h */
#define R_PPC64_TPREL16_HA	72 /* half16	(sym+add)@tprel@ha */
#define R_PPC64_TPREL64		73 /* doubleword64 (sym+add)@tprel */
#define R_PPC64_DTPREL16	74 /* half16*	(sym+add)@dtprel */
#define R_PPC64_DTPREL16_LO	75 /* half16	(sym+add)@dtprel@l */
#define R_PPC64_DTPREL16_HI	76 /* half16	(sym+add)@dtprel@h */
#define R_PPC64_DTPREL16_HA	77 /* half16	(sym+add)@dtprel@ha */
#define R_PPC64_DTPREL64	78 /* doubleword64 (sym+add)@dtprel */
#define R_PPC64_GOT_TLSGD16	79 /* half16*	(sym+add)@got@tlsgd */
#define R_PPC64_GOT_TLSGD16_LO	80 /* half16	(sym+add)@got@tlsgd@l */
#define R_PPC64_GOT_TLSGD16_HI	81 /* half16	(sym+add)@got@tlsgd@h */
#define R_PPC64_GOT_TLSGD16_HA	82 /* half16	(sym+add)@got@tlsgd@ha */
#define R_PPC64_GOT_TLSLD16	83 /* half16*	(sym+add)@got@tlsld */
#define R_PPC64_GOT_TLSLD16_LO	84 /* half16	(sym+add)@got@tlsld@l */
#define R_PPC64_GOT_TLSLD16_HI	85 /* half16	(sym+add)@got@tlsld@h */
#define R_PPC64_GOT_TLSLD16_HA	86 /* half16	(sym+add)@got@tlsld@ha */
#define R_PPC64_GOT_TPREL16_DS	87 /* half16ds*	(sym+add)@got@tprel */
#define R_PPC64_GOT_TPREL16_LO_DS 88 /* half16ds (sym+add)@got@tprel@l */
#define R_PPC64_GOT_TPREL16_HI	89 /* half16	(sym+add)@got@tprel@h */
#define R_PPC64_GOT_TPREL16_HA	90 /* half16	(sym+add)@got@tprel@ha */
#define R_PPC64_GOT_DTPREL16_DS	91 /* half16ds*	(sym+add)@got@dtprel */
#define R_PPC64_GOT_DTPREL16_LO_DS 92 /* half16ds (sym+add)@got@dtprel@l */
#define R_PPC64_GOT_DTPREL16_HI	93 /* half16	(sym+add)@got@dtprel@h */
#define R_PPC64_GOT_DTPREL16_HA	94 /* half16	(sym+add)@got@dtprel@ha */
#define R_PPC64_TPREL16_DS	95 /* half16ds*	(sym+add)@tprel */
#define R_PPC64_TPREL16_LO_DS	96 /* half16ds	(sym+add)@tprel@l */
#define R_PPC64_TPREL16_HIGHER	97 /* half16	(sym+add)@tprel@higher */
#define R_PPC64_TPREL16_HIGHERA	98 /* half16	(sym+add)@tprel@highera */
#define R_PPC64_TPREL16_HIGHEST	99 /* half16	(sym+add)@tprel@highest */
#define R_PPC64_TPREL16_HIGHESTA 100 /* half16	(sym+add)@tprel@highesta */
#define R_PPC64_DTPREL16_DS	101 /* half16ds* (sym+add)@dtprel */
#define R_PPC64_DTPREL16_LO_DS	102 /* half16ds	(sym+add)@dtprel@l */
#define R_PPC64_DTPREL16_HIGHER	103 /* half16	(sym+add)@dtprel@higher */
#define R_PPC64_DTPREL16_HIGHERA 104 /* half16	(sym+add)@dtprel@highera */
#define R_PPC64_DTPREL16_HIGHEST 105 /* half16	(sym+add)@dtprel@highest */
#define R_PPC64_DTPREL16_HIGHESTA 106 /* half16	(sym+add)@dtprel@highesta */

/* Keep this the last entry.  */
#define R_PPC64_NUM		107

/* PowerPC64 specific values for the Dyn d_tag field.  */
#define DT_PPC64_GLINK  (DT_LOPROC + 0)
#define DT_PPC64_OPD	(DT_LOPROC + 1)
#define DT_PPC64_OPDSZ	(DT_LOPROC + 2)
#define DT_PPC64_NUM    3


/* ARM specific declarations */

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_ARM_RELEXEC     0x01
#define EF_ARM_HASENTRY    0x02
#define EF_ARM_INTERWORK   0x04
#define EF_ARM_APCS_26     0x08
#define EF_ARM_APCS_FLOAT  0x10
#define EF_ARM_PIC         0x20
#define EF_ARM_ALIGN8      0x40		/* 8-bit structure alignment is in use */
#define EF_ARM_NEW_ABI     0x80
#define EF_ARM_OLD_ABI     0x100

/* Other constants defined in the ARM ELF spec. version B-01.  */
/* NB. These conflict with values defined above.  */
#define EF_ARM_SYMSARESORTED	0x04
#define EF_ARM_DYNSYMSUSESEGIDX 0x08
#define EF_ARM_MAPSYMSFIRST	0x10
#define EF_ARM_EABIMASK		0XFF000000

#define EF_ARM_EABI_VERSION(flags) ((flags) & EF_ARM_EABIMASK)
#define EF_ARM_EABI_UNKNOWN  0x00000000
#define EF_ARM_EABI_VER1     0x01000000
#define EF_ARM_EABI_VER2     0x02000000

/* Additional symbol types for Thumb */
#define STT_ARM_TFUNC      0xd

/* ARM-specific values for sh_flags */
#define SHF_ARM_ENTRYSECT  0x10000000   /* Section contains an entry point */
#define SHF_ARM_COMDEF     0x80000000   /* Section may be multiply defined
					   in the input to a link step */

/* ARM-specific program header flags */
#define PF_ARM_SB          0x10000000   /* Segment contains the location
					   addressed by the static base */

/* ARM relocs.  */
#define R_ARM_NONE		0	/* No reloc */
#define R_ARM_PC24		1	/* PC relative 26 bit branch */
#define R_ARM_ABS32		2	/* Direct 32 bit  */
#define R_ARM_REL32		3	/* PC relative 32 bit */
#define R_ARM_PC13		4
#define R_ARM_ABS16		5	/* Direct 16 bit */
#define R_ARM_ABS12		6	/* Direct 12 bit */
#define R_ARM_THM_ABS5		7
#define R_ARM_ABS8		8	/* Direct 8 bit */
#define R_ARM_SBREL32		9
#define R_ARM_THM_PC22		10
#define R_ARM_THM_PC8		11
#define R_ARM_AMP_VCALL9	12
#define R_ARM_SWI24		13
#define R_ARM_THM_SWI8		14
#define R_ARM_XPC25		15
#define R_ARM_THM_XPC22		16
#define R_ARM_COPY		20	/* Copy symbol at runtime */
#define R_ARM_GLOB_DAT		21	/* Create GOT entry */
#define R_ARM_JUMP_SLOT		22	/* Create PLT entry */
#define R_ARM_RELATIVE		23	/* Adjust by program base */
#define R_ARM_GOTOFF		24	/* 32 bit offset to GOT */
#define R_ARM_GOTPC		25	/* 32 bit PC relative offset to GOT */
#define R_ARM_GOT32		26	/* 32 bit GOT entry */
#define R_ARM_PLT32		27	/* 32 bit PLT address */
#define R_ARM_ALU_PCREL_7_0	32
#define R_ARM_ALU_PCREL_15_8	33
#define R_ARM_ALU_PCREL_23_15	34
#define R_ARM_LDR_SBREL_11_0	35
#define R_ARM_ALU_SBREL_19_12	36
#define R_ARM_ALU_SBREL_27_20	37
#define R_ARM_GNU_VTENTRY	100
#define R_ARM_GNU_VTINHERIT	101
#define R_ARM_THM_PC11		102	/* thumb unconditional branch */
#define R_ARM_THM_PC9		103	/* thumb conditional branch */
#define R_ARM_RXPC25		249
#define R_ARM_RSBREL32		250
#define R_ARM_THM_RPC22		251
#define R_ARM_RREL32		252
#define R_ARM_RABS22		253
#define R_ARM_RPC24		254
#define R_ARM_RBASE		255
/* Keep this the last entry.  */
#define R_ARM_NUM		256

/* IA-64 specific declarations.  */

/* Processor specific flags for the Ehdr e_flags field.  */
#define EF_IA_64_MASKOS		0x0000000f	/* os-specific flags */
#define EF_IA_64_ABI64		0x00000010	/* 64-bit ABI */
#define EF_IA_64_ARCH		0xff000000	/* arch. version mask */

/* Processor specific values for the Phdr p_type field.  */
#define PT_IA_64_ARCHEXT	(PT_LOPROC + 0)	/* arch extension bits */
#define PT_IA_64_UNWIND		(PT_LOPROC + 1)	/* ia64 unwind bits */
#define PT_IA_64_HP_OPT_ANOT	(PT_LOOS + 0x12)
#define PT_IA_64_HP_HSL_ANOT	(PT_LOOS + 0x13)
#define PT_IA_64_HP_STACK	(PT_LOOS + 0x14)

/* Processor specific flags for the Phdr p_flags field.  */
#define PF_IA_64_NORECOV	0x80000000	/* spec insns w/o recovery */

/* Processor specific values for the Shdr sh_type field.  */
#define SHT_IA_64_EXT		(SHT_LOPROC + 0) /* extension bits */
#define SHT_IA_64_UNWIND	(SHT_LOPROC + 1) /* unwind bits */

/* Processor specific flags for the Shdr sh_flags field.  */
#define SHF_IA_64_SHORT		0x10000000	/* section near gp */
#define SHF_IA_64_NORECOV	0x20000000	/* spec insns w/o recovery */

/* Processor specific values for the Dyn d_tag field.  */
#define DT_IA_64_PLT_RESERVE	(DT_LOPROC + 0)
#define DT_IA_64_NUM		1

/* IA-64 relocations.  */
#define R_IA64_NONE		0x00	/* none */
#define R_IA64_IMM14		0x21	/* symbol + addend, add imm14 */
#define R_IA64_IMM22		0x22	/* symbol + addend, add imm22 */
#define R_IA64_IMM64		0x23	/* symbol + addend, mov imm64 */
#define R_IA64_DIR32MSB		0x24	/* symbol + addend, data4 MSB */
#define R_IA64_DIR32LSB		0x25	/* symbol + addend, data4 LSB */
#define R_IA64_DIR64MSB		0x26	/* symbol + addend, data8 MSB */
#define R_IA64_DIR64LSB		0x27	/* symbol + addend, data8 LSB */
#define R_IA64_GPREL22		0x2a	/* @gprel(sym + add), add imm22 */
#define R_IA64_GPREL64I		0x2b	/* @gprel(sym + add), mov imm64 */
#define R_IA64_GPREL32MSB	0x2c	/* @gprel(sym + add), data4 MSB */
#define R_IA64_GPREL32LSB	0x2d	/* @gprel(sym + add), data4 LSB */
#define R_IA64_GPREL64MSB	0x2e	/* @gprel(sym + add), data8 MSB */
#define R_IA64_GPREL64LSB	0x2f	/* @gprel(sym + add), data8 LSB */
#define R_IA64_LTOFF22		0x32	/* @ltoff(sym + add), add imm22 */
#define R_IA64_LTOFF64I		0x33	/* @ltoff(sym + add), mov imm64 */
#define R_IA64_PLTOFF22		0x3a	/* @pltoff(sym + add), add imm22 */
#define R_IA64_PLTOFF64I	0x3b	/* @pltoff(sym + add), mov imm64 */
#define R_IA64_PLTOFF64MSB	0x3e	/* @pltoff(sym + add), data8 MSB */
#define R_IA64_PLTOFF64LSB	0x3f	/* @pltoff(sym + add), data8 LSB */
#define R_IA64_FPTR64I		0x43	/* @fptr(sym + add), mov imm64 */
#define R_IA64_FPTR32MSB	0x44	/* @fptr(sym + add), data4 MSB */
#define R_IA64_FPTR32LSB	0x45	/* @fptr(sym + add), data4 LSB */
#define R_IA64_FPTR64MSB	0x46	/* @fptr(sym + add), data8 MSB */
#define R_IA64_FPTR64LSB	0x47	/* @fptr(sym + add), data8 LSB */
#define R_IA64_PCREL60B		0x48	/* @pcrel(sym + add), brl */
#define R_IA64_PCREL21B		0x49	/* @pcrel(sym + add), ptb, call */
#define R_IA64_PCREL21M		0x4a	/* @pcrel(sym + add), chk.s */
#define R_IA64_PCREL21F		0x4b	/* @pcrel(sym + add), fchkf */
#define R_IA64_PCREL32MSB	0x4c	/* @pcrel(sym + add), data4 MSB */
#define R_IA64_PCREL32LSB	0x4d	/* @pcrel(sym + add), data4 LSB */
#define R_IA64_PCREL64MSB	0x4e	/* @pcrel(sym + add), data8 MSB */
#define R_IA64_PCREL64LSB	0x4f	/* @pcrel(sym + add), data8 LSB */
#define R_IA64_LTOFF_FPTR22	0x52	/* @ltoff(@fptr(s+a)), imm22 */
#define R_IA64_LTOFF_FPTR64I	0x53	/* @ltoff(@fptr(s+a)), imm64 */
#define R_IA64_LTOFF_FPTR32MSB	0x54	/* @ltoff(@fptr(s+a)), data4 MSB */
#define R_IA64_LTOFF_FPTR32LSB	0x55	/* @ltoff(@fptr(s+a)), data4 LSB */
#define R_IA64_LTOFF_FPTR64MSB	0x56	/* @ltoff(@fptr(s+a)), data8 MSB */
#define R_IA64_LTOFF_FPTR64LSB	0x57	/* @ltoff(@fptr(s+a)), data8 LSB */
#define R_IA64_SEGREL32MSB	0x5c	/* @segrel(sym + add), data4 MSB */
#define R_IA64_SEGREL32LSB	0x5d	/* @segrel(sym + add), data4 LSB */
#define R_IA64_SEGREL64MSB	0x5e	/* @segrel(sym + add), data8 MSB */
#define R_IA64_SEGREL64LSB	0x5f	/* @segrel(sym + add), data8 LSB */
#define R_IA64_SECREL32MSB	0x64	/* @secrel(sym + add), data4 MSB */
#define R_IA64_SECREL32LSB	0x65	/* @secrel(sym + add), data4 LSB */
#define R_IA64_SECREL64MSB	0x66	/* @secrel(sym + add), data8 MSB */
#define R_IA64_SECREL64LSB	0x67	/* @secrel(sym + add), data8 LSB */
#define R_IA64_REL32MSB		0x6c	/* data 4 + REL */
#define R_IA64_REL32LSB		0x6d	/* data 4 + REL */
#define R_IA64_REL64MSB		0x6e	/* data 8 + REL */
#define R_IA64_REL64LSB		0x6f	/* data 8 + REL */
#define R_IA64_LTV32MSB		0x74	/* symbol + addend, data4 MSB */
#define R_IA64_LTV32LSB		0x75	/* symbol + addend, data4 LSB */
#define R_IA64_LTV64MSB		0x76	/* symbol + addend, data8 MSB */
#define R_IA64_LTV64LSB		0x77	/* symbol + addend, data8 LSB */
#define R_IA64_PCREL21BI	0x79	/* @pcrel(sym + add), 21bit inst */
#define R_IA64_PCREL22		0x7a	/* @pcrel(sym + add), 22bit inst */
#define R_IA64_PCREL64I		0x7b	/* @pcrel(sym + add), 64bit inst */
#define R_IA64_IPLTMSB		0x80	/* dynamic reloc, imported PLT, MSB */
#define R_IA64_IPLTLSB		0x81	/* dynamic reloc, imported PLT, LSB */
#define R_IA64_COPY		0x84	/* copy relocation */
#define R_IA64_SUB		0x85	/* Addend and symbol difference */
#define R_IA64_LTOFF22X		0x86	/* LTOFF22, relaxable.  */
#define R_IA64_LDXMOV		0x87	/* Use of LTOFF22X.  */
#define R_IA64_TPREL14		0x91	/* @tprel(sym + add), imm14 */
#define R_IA64_TPREL22		0x92	/* @tprel(sym + add), imm22 */
#define R_IA64_TPREL64I		0x93	/* @tprel(sym + add), imm64 */
#define R_IA64_TPREL64MSB	0x96	/* @tprel(sym + add), data8 MSB */
#define R_IA64_TPREL64LSB	0x97	/* @tprel(sym + add), data8 LSB */
#define R_IA64_LTOFF_TPREL22	0x9a	/* @ltoff(@tprel(s+a)), imm2 */
#define R_IA64_DTPMOD64MSB	0xa6	/* @dtpmod(sym + add), data8 MSB */
#define R_IA64_DTPMOD64LSB	0xa7	/* @dtpmod(sym + add), data8 LSB */
#define R_IA64_LTOFF_DTPMOD22	0xaa	/* @ltoff(@dtpmod(sym + add)), imm22 */
#define R_IA64_DTPREL14		0xb1	/* @dtprel(sym + add), imm14 */
#define R_IA64_DTPREL22		0xb2	/* @dtprel(sym + add), imm22 */
#define R_IA64_DTPREL64I	0xb3	/* @dtprel(sym + add), imm64 */
#define R_IA64_DTPREL32MSB	0xb4	/* @dtprel(sym + add), data4 MSB */
#define R_IA64_DTPREL32LSB	0xb5	/* @dtprel(sym + add), data4 LSB */
#define R_IA64_DTPREL64MSB	0xb6	/* @dtprel(sym + add), data8 MSB */
#define R_IA64_DTPREL64LSB	0xb7	/* @dtprel(sym + add), data8 LSB */
#define R_IA64_LTOFF_DTPREL22	0xba	/* @ltoff(@dtprel(s+a)), imm22 */

/* SH specific declarations */

/* SH relocs.  */
#define	R_SH_NONE		0
#define	R_SH_DIR32		1
#define	R_SH_REL32		2
#define	R_SH_DIR8WPN		3
#define	R_SH_IND12W		4
#define	R_SH_DIR8WPL		5
#define	R_SH_DIR8WPZ		6
#define	R_SH_DIR8BP		7
#define	R_SH_DIR8W		8
#define	R_SH_DIR8L		9
#define	R_SH_SWITCH16		25
#define	R_SH_SWITCH32		26
#define	R_SH_USES		27
#define	R_SH_COUNT		28
#define	R_SH_ALIGN		29
#define	R_SH_CODE		30
#define	R_SH_DATA		31
#define	R_SH_LABEL		32
#define	R_SH_SWITCH8		33
#define	R_SH_GNU_VTINHERIT	34
#define	R_SH_GNU_VTENTRY	35
#define	R_SH_TLS_GD_32		144
#define	R_SH_TLS_LD_32		145
#define	R_SH_TLS_LDO_32		146
#define	R_SH_TLS_IE_32		147
#define	R_SH_TLS_LE_32		148
#define	R_SH_TLS_DTPMOD32	149
#define	R_SH_TLS_DTPOFF32	150
#define	R_SH_TLS_TPOFF32	151
#define	R_SH_GOT32		160
#define	R_SH_PLT32		161
#define	R_SH_COPY		162
#define	R_SH_GLOB_DAT		163
#define	R_SH_JMP_SLOT		164
#define	R_SH_RELATIVE		165
#define	R_SH_GOTOFF		166
#define	R_SH_GOTPC		167
/* Keep this the last entry.  */
#define	R_SH_NUM		256

/* Additional s390 relocs */

#define R_390_NONE		0	/* No reloc.  */
#define R_390_8			1	/* Direct 8 bit.  */
#define R_390_12		2	/* Direct 12 bit.  */
#define R_390_16		3	/* Direct 16 bit.  */
#define R_390_32		4	/* Direct 32 bit.  */
#define R_390_PC32		5	/* PC relative 32 bit.	*/
#define R_390_GOT12		6	/* 12 bit GOT offset.  */
#define R_390_GOT32		7	/* 32 bit GOT offset.  */
#define R_390_PLT32		8	/* 32 bit PC relative PLT address.  */
#define R_390_COPY		9	/* Copy symbol at runtime.  */
#define R_390_GLOB_DAT		10	/* Create GOT entry.  */
#define R_390_JMP_SLOT		11	/* Create PLT entry.  */
#define R_390_RELATIVE		12	/* Adjust by program base.  */
#define R_390_GOTOFF32		13	/* 32 bit offset to GOT.	 */
#define R_390_GOTPC		14	/* 32 bit PC relative offset to GOT.  */
#define R_390_GOT16		15	/* 16 bit GOT offset.  */
#define R_390_PC16		16	/* PC relative 16 bit.	*/
#define R_390_PC16DBL		17	/* PC relative 16 bit shifted by 1.  */
#define R_390_PLT16DBL		18	/* 16 bit PC rel. PLT shifted by 1.  */
#define R_390_PC32DBL		19	/* PC relative 32 bit shifted by 1.  */
#define R_390_PLT32DBL		20	/* 32 bit PC rel. PLT shifted by 1.  */
#define R_390_GOTPCDBL		21	/* 32 bit PC rel. GOT shifted by 1.  */
#define R_390_64		22	/* Direct 64 bit.  */
#define R_390_PC64		23	/* PC relative 64 bit.	*/
#define R_390_GOT64		24	/* 64 bit GOT offset.  */
#define R_390_PLT64		25	/* 64 bit PC relative PLT address.  */
#define R_390_GOTENT		26	/* 32 bit PC rel. to GOT entry >> 1. */
#define R_390_GOTOFF16		27	/* 16 bit offset to GOT. */
#define R_390_GOTOFF64		28	/* 64 bit offset to GOT. */
#define R_390_GOTPLT12		29	/* 12 bit offset to jump slot.	*/
#define R_390_GOTPLT16		30	/* 16 bit offset to jump slot.	*/
#define R_390_GOTPLT32		31	/* 32 bit offset to jump slot.	*/
#define R_390_GOTPLT64		32	/* 64 bit offset to jump slot.	*/
#define R_390_GOTPLTENT		33	/* 32 bit rel. offset to jump slot.  */
#define R_390_PLTOFF16		34	/* 16 bit offset from GOT to PLT. */
#define R_390_PLTOFF32		35	/* 32 bit offset from GOT to PLT. */
#define R_390_PLTOFF64		36	/* 16 bit offset from GOT to PLT. */
#define R_390_TLS_LOAD		37	/* Tag for load insn in TLS code.  */
#define R_390_TLS_GDCALL	38	/* Tag for function call in general
					   dynamic TLS code. */
#define R_390_TLS_LDCALL	39	/* Tag for function call in local
					   dynamic TLS code. */
#define R_390_TLS_GD32		40	/* Direct 32 bit for general dynamic
					   thread local data.  */
#define R_390_TLS_GD64		41	/* Direct 64 bit for general dynamic
					  thread local data.  */
#define R_390_TLS_GOTIE12	42	/* 12 bit GOT offset for static TLS
					   block offset.  */
#define R_390_TLS_GOTIE32	43	/* 32 bit GOT offset for static TLS
					   block offset.  */
#define R_390_TLS_GOTIE64	44	/* 64 bit GOT offset for static TLS
					   block offset. */
#define R_390_TLS_LDM32		45	/* Direct 32 bit for local dynamic
					   thread local data in LE code.  */
#define R_390_TLS_LDM64		46	/* Direct 64 bit for local dynamic
					   thread local data in LE code.  */
#define R_390_TLS_IE32		47	/* 32 bit address of GOT entry for
					   negated static TLS block offset.  */
#define R_390_TLS_IE64		48	/* 64 bit address of GOT entry for
					   negated static TLS block offset.  */
#define R_390_TLS_IEENT		49	/* 32 bit rel. offset to GOT entry for
					   negated static TLS block offset.  */
#define R_390_TLS_LE32		50	/* 32 bit negated offset relative to
					   static TLS block.  */
#define R_390_TLS_LE64		51	/* 64 bit negated offset relative to
					   static TLS block.  */
#define R_390_TLS_LDO32		52	/* 32 bit offset relative to TLS
					   block.  */
#define R_390_TLS_LDO64		53	/* 64 bit offset relative to TLS
					   block.  */
#define R_390_TLS_DTPMOD	54	/* ID of module containing symbol.  */
#define R_390_TLS_DTPOFF	55	/* Offset in TLS block.	 */
#define R_390_TLS_TPOFF		56	/* Negated offset in static TLS
					   block.  */
#define R_390_20		57	/* Direct 20 bit.  */
#define R_390_GOT20		58	/* 20 bit GOT offset.  */
#define R_390_GOTPLT20		59	/* 20 bit offset to jump slot.  */
#define R_390_TLS_GOTIE20	60	/* 20 bit GOT offset for static TLS
					   block offset.  */
/* Keep this the last entry.  */
#define R_390_NUM		61


/* CRIS relocations.  */
#define R_CRIS_NONE		0
#define R_CRIS_8		1
#define R_CRIS_16		2
#define R_CRIS_32		3
#define R_CRIS_8_PCREL		4
#define R_CRIS_16_PCREL		5
#define R_CRIS_32_PCREL		6
#define R_CRIS_GNU_VTINHERIT	7
#define R_CRIS_GNU_VTENTRY	8
#define R_CRIS_COPY		9
#define R_CRIS_GLOB_DAT		10
#define R_CRIS_JUMP_SLOT	11
#define R_CRIS_RELATIVE		12
#define R_CRIS_16_GOT		13
#define R_CRIS_32_GOT		14
#define R_CRIS_16_GOTPLT	15
#define R_CRIS_32_GOTPLT	16
#define R_CRIS_32_GOTREL	17
#define R_CRIS_32_PLT_GOTREL	18
#define R_CRIS_32_PLT_PCREL	19

#define R_CRIS_NUM		20


/* AMD x86-64 relocations.  */
#define R_X86_64_NONE		0	/* No reloc */
#define R_X86_64_64		1	/* Direct 64 bit  */
#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
#define R_X86_64_PLT32		4	/* 32 bit PLT address */
#define R_X86_64_COPY		5	/* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
#define R_X86_64_RELATIVE	8	/* Adjust by program base */
#define R_X86_64_GOTPCREL	9	/* 32 bit signed PC relative
					   offset to GOT */
#define R_X86_64_32		10	/* Direct 32 bit zero extended */
#define R_X86_64_32S		11	/* Direct 32 bit sign extended */
#define R_X86_64_16		12	/* Direct 16 bit zero extended */
#define R_X86_64_PC16		13	/* 16 bit sign extended pc relative */
#define R_X86_64_8		14	/* Direct 8 bit sign extended  */
#define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64	16	/* ID of module containing symbol */
#define R_X86_64_DTPOFF64	17	/* Offset in module's TLS block */
#define R_X86_64_TPOFF64	18	/* Offset in initial TLS block */
#define R_X86_64_TLSGD		19	/* 32 bit signed PC relative offset
					   to two GOT entries for GD symbol */
#define R_X86_64_TLSLD		20	/* 32 bit signed PC relative offset
					   to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32	21	/* Offset in TLS block */
#define R_X86_64_GOTTPOFF	22	/* 32 bit signed PC relative offset
					   to GOT entry for IE symbol */
#define R_X86_64_TPOFF32	23	/* Offset in initial TLS block */

#define R_X86_64_NUM		24


/* AM33 relocations.  */
#define R_MN10300_NONE		0	/* No reloc.  */
#define R_MN10300_32		1	/* Direct 32 bit.  */
#define R_MN10300_16		2	/* Direct 16 bit.  */
#define R_MN10300_8		3	/* Direct 8 bit.  */
#define R_MN10300_PCREL32	4	/* PC-relative 32-bit.  */
#define R_MN10300_PCREL16	5	/* PC-relative 16-bit signed.  */
#define R_MN10300_PCREL8	6	/* PC-relative 8-bit signed.  */
#define R_MN10300_GNU_VTINHERIT	7	/* Ancient C++ vtable garbage... */
#define R_MN10300_GNU_VTENTRY	8	/* ... collection annotation.  */
#define R_MN10300_24		9	/* Direct 24 bit.  */
#define R_MN10300_GOTPC32	10	/* 32-bit PCrel offset to GOT.  */
#define R_MN10300_GOTPC16	11	/* 16-bit PCrel offset to GOT.  */
#define R_MN10300_GOTOFF32	12	/* 32-bit offset from GOT.  */
#define R_MN10300_GOTOFF24	13	/* 24-bit offset from GOT.  */
#define R_MN10300_GOTOFF16	14	/* 16-bit offset from GOT.  */
#define R_MN10300_PLT32		15	/* 32-bit PCrel to PLT entry.  */
#define R_MN10300_PLT16		16	/* 16-bit PCrel to PLT entry.  */
#define R_MN10300_GOT32		17	/* 32-bit offset to GOT entry.  */
#define R_MN10300_GOT24		18	/* 24-bit offset to GOT entry.  */
#define R_MN10300_GOT16		19	/* 16-bit offset to GOT entry.  */
#define R_MN10300_COPY		20	/* Copy symbol at runtime.  */
#define R_MN10300_GLOB_DAT	21	/* Create GOT entry.  */
#define R_MN10300_JMP_SLOT	22	/* Create PLT entry.  */
#define R_MN10300_RELATIVE	23	/* Adjust by program base.  */

#define R_MN10300_NUM		24


/* M32R relocs.  */
#define R_M32R_NONE		0	/* No reloc. */
#define R_M32R_16		1	/* Direct 16 bit. */
#define R_M32R_32		2	/* Direct 32 bit. */
#define R_M32R_24		3	/* Direct 24 bit. */
#define R_M32R_10_PCREL		4	/* PC relative 10 bit shifted. */
#define R_M32R_18_PCREL		5	/* PC relative 18 bit shifted. */
#define R_M32R_26_PCREL		6	/* PC relative 26 bit shifted. */
#define R_M32R_HI16_ULO		7	/* High 16 bit with unsigned low. */
#define R_M32R_HI16_SLO		8	/* High 16 bit with signed low. */
#define R_M32R_LO16		9	/* Low 16 bit. */
#define R_M32R_SDA16		10	/* 16 bit offset in SDA. */
#define R_M32R_GNU_VTINHERIT	11
#define R_M32R_GNU_VTENTRY	12
/* M32R relocs use SHT_RELA.  */
#define R_M32R_16_RELA		33	/* Direct 16 bit. */
#define R_M32R_32_RELA		34	/* Direct 32 bit. */
#define R_M32R_24_RELA		35	/* Direct 24 bit. */
#define R_M32R_10_PCREL_RELA	36	/* PC relative 10 bit shifted. */
#define R_M32R_18_PCREL_RELA	37	/* PC relative 18 bit shifted. */
#define R_M32R_26_PCREL_RELA	38	/* PC relative 26 bit shifted. */
#define R_M32R_HI16_ULO_RELA	39	/* High 16 bit with unsigned low */
#define R_M32R_HI16_SLO_RELA	40	/* High 16 bit with signed low */
#define R_M32R_LO16_RELA	41	/* Low 16 bit */
#define R_M32R_SDA16_RELA	42	/* 16 bit offset in SDA */
#define R_M32R_RELA_GNU_VTINHERIT	43
#define R_M32R_RELA_GNU_VTENTRY	44

#define R_M32R_GOT24		48	/* 24 bit GOT entry */
#define R_M32R_26_PLTREL	49	/* 26 bit PC relative to PLT shifted */
#define R_M32R_COPY		50	/* Copy symbol at runtime */
#define R_M32R_GLOB_DAT		51	/* Create GOT entry */
#define R_M32R_JMP_SLOT		52	/* Create PLT entry */
#define R_M32R_RELATIVE		53	/* Adjust by program base */
#define R_M32R_GOTOFF		54	/* 24 bit offset to GOT */
#define R_M32R_GOTPC24		55	/* 24 bit PC relative offset to GOT */
#define R_M32R_GOT16_HI_ULO	56	/* High 16 bit GOT entry with unsigned
					   low */
#define R_M32R_GOT16_HI_SLO	57	/* High 16 bit GOT entry with signed
					   low */
#define R_M32R_GOT16_LO		58	/* Low 16 bit GOT entry */
#define R_M32R_GOTPC_HI_ULO	59	/* High 16 bit PC relative offset to
					   GOT with unsigned low */
#define R_M32R_GOTPC_HI_SLO	60	/* High 16 bit PC relative offset to
					   GOT with signed low */
#define R_M32R_GOTPC_LO		61	/* Low 16 bit PC relative offset to
					   GOT */
#define R_M32R_GOTOFF_HI_ULO	62	/* High 16 bit offset to GOT
					   with unsigned low */
#define R_M32R_GOTOFF_HI_SLO	63	/* High 16 bit offset to GOT
					   with signed low */
#define R_M32R_GOTOFF_LO	64	/* Low 16 bit offset to GOT */
#define R_M32R_NUM		256	/* Keep this the last entry. */


struct rusage {
    struct timeval ru_utime; /* user time used */
    struct timeval ru_stime; /* system time used */
    long   ru_maxrss;        /* maximum resident set size */
    long   ru_ixrss;         /* integral shared memory size */
    long   ru_idrss;         /* integral unshared data size */
    long   ru_isrss;         /* integral unshared stack size */
    long   ru_minflt;        /* page reclaims */
    long   ru_majflt;        /* page faults */
    long   ru_nswap;         /* swaps */
    long   ru_inblock;       /* block input operations */
    long   ru_oublock;       /* block output operations */
    long   ru_msgsnd;        /* messages sent */
    long   ru_msgrcv;        /* messages received */
    long   ru_nsignals;      /* signals received */
    long   ru_nvcsw;         /* voluntary context switches */
    long   ru_nivcsw;        /* involuntary context switches */
};

/** OpenBSD only ? for getdirentries **/

#define    MAXNAMLEN       255
struct bsd_dirent {
           uint32_t       d_fileno;
           uint16_t       d_reclen;
           uint8_t        d_type;
           uint8_t        d_namlen;
           char           d_name[MAXNAMLEN + 1]; 
};

/* semop system calls takes an array of these. */
struct sembuf {
	unsigned short  sem_num;    /* semaphore index in array */
	short       sem_op;     /* semaphore operation */
	short       sem_flg;    /* operation flags */
};
