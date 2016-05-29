/* io_r2k- LGPL - Copyright SkUaTeR */

#include "r_io.h"
#include "r_lib.h"

#if __WINDOWS__
#include <sys/types.h>

typedef struct {
	HANDLE hnd;
} RIOW32;
typedef  struct _PPA {
	LARGE_INTEGER address;
	DWORD len;
	unsigned char buffer;
} PA, * PPA;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
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

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define strDeviceName     "\\\\.\\r2k\\"
#define		CLOSE_DRIVER	    	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_READ_PHYS_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_READ_KERNEL_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_WRITE_KERNEL_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_GET_PHYSADDR	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_WRITE_PHYS_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_GET_SYSTEM_MODULES	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

static HANDLE gHandleDriver = NULL;

BOOL InstallService(const char * rutaDriver, LPCSTR  lpServiceName, LPCSTR  lpDisplayName) {
	HANDLE hSCManager;
	HANDLE hService;
	BOOL ret = FALSE;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = CreateServiceA(hSCManager, lpServiceName, lpDisplayName, SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, rutaDriver, NULL, NULL, NULL, NULL, NULL);
		if (hService) {
			CloseServiceHandle(hService);
			ret = TRUE;
		}
		CloseServiceHandle(hSCManager);
	}
	return ret;
}
BOOL RemoveService(LPCSTR  lpServiceName) {
	HANDLE hSCManager;
	HANDLE hService;
	BOOL ret = FALSE;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if (hService) {
			DeleteService(hService);
			CloseServiceHandle(hService);
			ret = TRUE;
		}
		CloseServiceHandle(hSCManager);
	}
	return ret;
}
BOOL StartStopService(LPCSTR  lpServiceName, BOOL bStop) {
	HANDLE hSCManager;
	HANDLE hService;
	SERVICE_STATUS ssStatus;
	BOOL ret = FALSE;
	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if (hService) {
			if (!bStop) {
				if (StartServiceA(hService, 0, NULL)) {
					eprintf("Service started [OK]\n");
					ret = TRUE;
				}
				else {
					eprintf("Service started [FAIL]\n");
				}
			}
			else {
				if (ControlService(hService, SERVICE_CONTROL_STOP, &ssStatus)) {
					printf("Service Stopped [OK]\n");
					ret = TRUE;
				}
				else {
					printf("Service Stopped [FAIL]\n");
				}
			}
			CloseServiceHandle(hService);
			DeleteService(hService);
		}
		CloseServiceHandle(hSCManager);
	}
	return ret;
}
BOOL InitDriver(VOID)
{
	gHandleDriver = CreateFileA(strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_DIRECTORY, 0);
	if (gHandleDriver != INVALID_HANDLE_VALUE)
	{
		return TRUE;
	}
	return(FALSE);
}
char *GetFileName(unsigned char *path)
{
	char *pfile;
	pfile = path + strlen(path);
	for (; pfile > path; pfile--)
	{
		if ((*pfile == '\\') || (*pfile == '/'))
		{
			pfile++;
			break;
		}
	}
	return pfile;
}
static int GetSystemModules(RIO *io) {
	DWORD bRead = 0;
	int i;
	LPVOID	lpBufMods = NULL;
	int bufmodsize = 1024 * 1024;
	if(gHandleDriver) {
		if (!(lpBufMods = malloc(bufmodsize))) {
			eprintf("[r2k] GetSystemModules: Error cant allocate %i bytes of memory.\n", bufmodsize);
			return -1;
		}
		if (DeviceIoControl(gHandleDriver, IOCTL_GET_SYSTEM_MODULES, lpBufMods, bufmodsize, lpBufMods, bufmodsize, &bRead, NULL)) {
			PRTL_PROCESS_MODULES pm = (PRTL_PROCESS_MODULES)lpBufMods;
			PRTL_PROCESS_MODULE_INFORMATION pMod = pm->Modules;
			for (i = 0; i < pm->NumberOfModules; i++)
			{
				//eprintf("%p %x = %-50s \n", pMod[i].ImageBase, pMod[i].ImageBase, GetFileName(pMod[i].FullPathName));
				io->cb_printf("f nt.%s 0x%x @ 0x%p\n", GetFileName(pMod[i].FullPathName), pMod[i].ImageSize, pMod[i].ImageBase);
			}
		}
	} else {
		eprintf("Driver not initialized.\n");
	}
	return 1;
}
static int ReadKernelMemory(ut64 address, ut8 *buf, int len) {
	DWORD ret = -1, bRead = 0;
	LPVOID	lpBuffer = NULL;
	int bufsize;
	PPA p;
	memset(buf, '\xff', len);
	if(gHandleDriver) {
		bufsize = sizeof(PA) + len;
		if (!(lpBuffer = malloc(bufsize))) {
			eprintf("[r2k] ReadKernelMemory: Error cant allocate %i bytes of memory.\n", bufsize);
			return -1;
		}
		p = (PPA)lpBuffer;
		p->address.QuadPart = address;
		p->len = len;
		if (DeviceIoControl(gHandleDriver, IOCTL_READ_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)) {
			memcpy(buf, lpBuffer, len);
			ret = len;
		}
		else {
			ret = -1;
			//eprintf("[r2k] ReadKernelMemory: Error IOCTL_READ_KERNEL_MEM.\n");
		}
		free(lpBuffer);
	} else {
		eprintf("Driver not initialized.\n");
	}
	return ret;
}

static int WriteKernelMemory(ut64 address, const ut8 *buf, int len) {
	DWORD ret = -1, bRead = 0;
	LPVOID	lpBuffer = NULL;
	int bufsize;
	PPA p;
	if(gHandleDriver) {
		bufsize = sizeof(PA) + len;
		if (!(lpBuffer = malloc(bufsize))) {
			eprintf("[r2k] WriteKernelMemory: Error cant allocate %i bytes of memory.\n", bufsize);
			return -1;
		}
		p = (PPA)lpBuffer;
		p->address.QuadPart = address;
		p->len = len;
		memcpy(&p->buffer, buf, len);
		if (DeviceIoControl(gHandleDriver, IOCTL_WRITE_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)) {
			ret = len;
		}
		else {
			eprintf("[r2k] WriteKernelMemory: Error IOCTL_WRITE_KERNEL_MEM.\n");
			ret = -1;
		}
		free(lpBuffer);
	} else {
		eprintf("Driver not initialized.\n");
	}
	return ret;
}

static int Init(const char * driverPath) {
	BOOL ret = FALSE;
	if (InitDriver() == FALSE) {
		if (strlen(driverPath))
		{
			StartStopService("r2k",TRUE);
			RemoveService("r2k");
			eprintf("Installing driver: %s\n", driverPath);
			if (InstallService(driverPath, "r2k", "r2k")) {
				StartStopService("r2k",FALSE);
				ret = InitDriver();
			}
		} else {
			eprintf("Error initalizating driver, try r2k://pathtodriver\nEx: radare2.exe r2k://c:\\r2k.sys");
		
		}
	}
	else {
		eprintf("Driver present [OK]\n");
		ret = TRUE;
	} 
	return ret;
}
#endif

int r2k__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
#if __WINDOWS__
	//eprintf("writing to: 0x%"PFMT64x" len: %x\n",io->off, count);
	return WriteKernelMemory(io->off, buf, count);
#else
	eprintf("TODO: r2k not implemented for this plataform.\n");
	return -1;
#endif
}

static int r2k__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
#if __WINDOWS__
	return ReadKernelMemory(io->off, buf, count);
#else
	eprintf("TODO: r2k not implemented for this plataform.\n");
	memset(buf, '\xff', len);
	return len;
#endif
}

static int r2k__close(RIODesc *fd) {
	if(gHandleDriver) {
		CloseHandle(gHandleDriver);
		StartStopService("r2k",TRUE);
	}
	return 0;
}

static ut64 r2k__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
        return (!whence)?offset:whence==1?io->off+offset:UT64_MAX;
}

static int r2k__plugin_open(RIO *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "r2k://", 6));
}
static int r2k__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!strncmp(cmd, "mod", 3)) {
		GetSystemModules(io);
		if (cmd[3] == ' ') {
			//int pid = atoi(cmd + 3);
		}
		else {
		}
	}
	else {
		eprintf("Try: '=!?'\n");
	}
	return -1;
}
static RIODesc *r2k__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp (pathname, "r2k://", 6)) {
		RIOW32 *w32 = R_NEW0 (RIOW32);
		if(Init(&pathname[6]) == FALSE) {
			eprintf("r2k__open: Error cant init driver: %s\n", &pathname[6]);
		}
		return r_io_desc_new(&r_io_plugin_r2k, -1, pathname, rw, mode, w32);
		free (w32);
	}
	return NULL;
}

RIOPlugin r_io_plugin_r2k = {
	.name = "r2k",
        .desc = "kernel access API io (r2k://)",
	.license = "LGPL3",
	.open = r2k__open,
	.close = r2k__close,
	.read = r2k__read,
	.check = r2k__plugin_open,
	.lseek = r2k__lseek,
	.system = r2k__system,
	.write = r2k__write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2k,
	.version = R2_VERSION
};
#endif

