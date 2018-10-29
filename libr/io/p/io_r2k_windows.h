#ifndef __IO_R2k_WINDOWS_H__
#define __IO_R2k_WINDOWS_H__

#include <r_io.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_util.h>
#include <sys/types.h>

typedef struct {
	HANDLE hnd;
} RIOW32;
typedef  struct _PPA {
	LARGE_INTEGER address;
	DWORD len;
	unsigned char buffer;
} PA, * PPA;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define R2K_DEVICE "\\\\.\\r2k\\"

#define IOCTL_CODE(DeviceType, Function, Method, Access) \
	(((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#if 0
FILE_DEVICE_UNKNOWN 0x22
FILE_READ_ACCESS 1
FILE_WRITE_ACCESS 2
#endif
#define CLOSE_DRIVER IOCTL_CODE(0x22, 0x803, 0, 1 | 2)
#define IOCTL_READ_PHYS_MEM IOCTL_CODE(0x22, 0x807, 0, 1 | 2)
#define IOCTL_READ_KERNEL_MEM IOCTL_CODE(0x22, 0x804, 0, 1 | 2)
#define IOCTL_WRITE_KERNEL_MEM IOCTL_CODE(0x22, 0x805, 0, 1 | 2)
#define IOCTL_GET_PHYSADDR IOCTL_CODE(0x22, 0x809, 0, 1 | 2)
#define IOCTL_WRITE_PHYS_MEM IOCTL_CODE(0x22, 0x808, 0, 1 | 2)
#define IOCTL_GET_SYSTEM_MODULES IOCTL_CODE(0x22, 0x80a, 0, 1 | 2)

extern HANDLE gHandleDriver;

BOOL StartStopService(LPCTSTR lpServiceName, BOOL bStop);
int GetSystemModules(RIO *io);
int ReadKernelMemory (ut64 address, ut8 *buf, int len);
int WriteKernelMemory (ut64 address, const ut8 *buf, int len);
int Init (const char * driverPath);

#endif
