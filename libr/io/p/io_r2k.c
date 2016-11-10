/* io_r2k - radare2 - LGPL - Copyright 2016 - SkUaTeR + panda */

#include <r_io.h>
#include <r_lib.h>
#include <r_types.h>
#include <sys/types.h>

#if __WINDOWS__

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

static HANDLE gHandleDriver = NULL;

static BOOL InstallService(const char * rutaDriver, LPCSTR  lpServiceName, LPCSTR  lpDisplayName) {
	HANDLE hService;
	BOOL ret = FALSE;
	HANDLE hSCManager = OpenSCManagerA (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = CreateServiceA (hSCManager, lpServiceName, lpDisplayName, SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, rutaDriver, NULL, NULL, NULL, NULL, NULL);
		if (hService) {
			CloseServiceHandle (hService);
			ret = TRUE;
		}
		CloseServiceHandle (hSCManager);
	}
	return ret;
}

static BOOL RemoveService(LPCSTR lpServiceName) {
	HANDLE hService;
	BOOL ret = FALSE;
	HANDLE hSCManager = OpenSCManagerA (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager) {
		hService = OpenServiceA (hSCManager, lpServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if (hService) {
			DeleteService (hService);
			CloseServiceHandle (hService);
			ret = TRUE;
		}
		CloseServiceHandle (hSCManager);
	}
	return ret;
}

static BOOL StartStopService(LPCSTR lpServiceName, BOOL bStop) {
	HANDLE hSCManager;
	HANDLE hService;
	SERVICE_STATUS ssStatus;
	BOOL ret = FALSE;
	hSCManager = OpenSCManagerA (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = OpenServiceA (hSCManager, lpServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if (hService) {
			if (!bStop) {
				if (StartServiceA (hService, 0, NULL)) {
					eprintf ("Service started [OK]\n");
					ret = TRUE;
				} else {
					eprintf ("Service started [FAIL]\n");
				}
			} else {
				if (ControlService (hService, SERVICE_CONTROL_STOP, &ssStatus)) {
					eprintf ("Service Stopped [OK]\n");
					ret = TRUE;
				} else {
					eprintf ("Service Stopped [FAIL]\n");
				}
			}
			CloseServiceHandle (hService);
			DeleteService (hService);
		}
		CloseServiceHandle (hSCManager);
	}
	return ret;
}

static BOOL InitDriver(VOID) {
	const int genericFlags = GENERIC_READ | GENERIC_WRITE;
	const int shareFlags = FILE_SHARE_READ | FILE_SHARE_WRITE;
	gHandleDriver = CreateFileA (R2K_DEVICE, genericFlags, shareFlags,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_DIRECTORY, 0);
	return (gHandleDriver != INVALID_HANDLE_VALUE);
}

static const char *GetFileName(const char *path) {
	const char *pfile = path + strlen (path);
	for (; pfile > path; pfile--) {
		if ((*pfile == '\\') || (*pfile == '/')) {
			pfile++;
			break;
		}
	}
	return pfile;
}

static int GetSystemModules(RIO *io) {
	DWORD bRead = 0;
	int i;
	LPVOID lpBufMods = NULL;
	int bufmodsize = 1024 * 1024;
	if(gHandleDriver) {
		if (!(lpBufMods = malloc (bufmodsize))) {
			eprintf ("[r2k] GetSystemModules: Error cant allocate %i bytes of memory.\n", bufmodsize);
			return -1;
		}
		if (DeviceIoControl (gHandleDriver, IOCTL_GET_SYSTEM_MODULES, lpBufMods, bufmodsize, lpBufMods, bufmodsize, &bRead, NULL)) {
			PRTL_PROCESS_MODULES pm = (PRTL_PROCESS_MODULES)lpBufMods;
			PRTL_PROCESS_MODULE_INFORMATION pMod = pm->Modules;
			for (i = 0; i < pm->NumberOfModules; i++) {
				const char *fileName = GetFileName((const char*)pMod[i].FullPathName);
				io->cb_printf ("f nt.%s 0x%x @ 0x%p\n", fileName, pMod[i].ImageSize, pMod[i].ImageBase);
			}
		}
	} else {
		eprintf ("Driver not initialized.\n");
	}
	return 1;
}

static int ReadKernelMemory (ut64 address, ut8 *buf, int len) {
	DWORD ret = -1, bRead = 0;
	LPVOID lpBuffer = NULL;
	int bufsize;
	PPA p;
	memset (buf, '\xff', len);
	if(gHandleDriver) {
		bufsize = sizeof (PA) + len;
		if (!(lpBuffer = malloc (bufsize))) {
			eprintf ("[r2k] ReadKernelMemory: Error cant allocate %i bytes of memory.\n", bufsize);
			return -1;
		}
		p = (PPA)lpBuffer;
		p->address.QuadPart = address;
		p->len = len;
		if (DeviceIoControl (gHandleDriver, IOCTL_READ_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)) {
			memcpy (buf, lpBuffer, len);
			ret = len;
		} else {
			ret = -1;
			//eprintf("[r2k] ReadKernelMemory: Error IOCTL_READ_KERNEL_MEM.\n");
		}
		free (lpBuffer);
	} else {
		eprintf ("Driver not initialized.\n");
	}
	return ret;
}

static int WriteKernelMemory (ut64 address, const ut8 *buf, int len) {
	DWORD ret = -1, bRead = 0;
	LPVOID lpBuffer = NULL;
	int bufsize;
	PPA p;
	if(gHandleDriver) {
		bufsize = sizeof (PA) + len;
		if (!(lpBuffer = malloc (bufsize))) {
			eprintf ("[r2k] WriteKernelMemory: Error cant allocate %i bytes of memory.\n", bufsize);
			return -1;
		}
		p = (PPA)lpBuffer;
		p->address.QuadPart = address;
		p->len = len;
		memcpy (&p->buffer, buf, len);
		if (DeviceIoControl (gHandleDriver, IOCTL_WRITE_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)) {
			ret = len;
		} else {
			eprintf ("[r2k] WriteKernelMemory: Error IOCTL_WRITE_KERNEL_MEM.\n");
			ret = -1;
		}
		free (lpBuffer);
	} else {
		eprintf ("Driver not initialized.\n");
	}
	return ret;
}

static int Init (const char * driverPath) {
	BOOL ret = FALSE;
	if (InitDriver () == FALSE) {
		if (strlen (driverPath)) {
			StartStopService ("r2k",TRUE);
			RemoveService ("r2k");
			eprintf ("Installing driver: %s\n", driverPath);
			if (InstallService (driverPath, "r2k", "r2k")) {
				StartStopService ("r2k",FALSE);
				ret = InitDriver ();
			}
		} else {
			eprintf ("Error initalizating driver, try r2k://pathtodriver\nEx: radare2.exe r2k://c:\\r2k.sys");
		
		}
	} else {
		eprintf ("Driver present [OK]\n");
		ret = TRUE;
	} 
	return ret;
}
#endif

#if __linux__
#include <sys/ioctl.h>
#include <errno.h>

struct r2k_data {
	int pid;
	ut64 addr;
	ut64 len;
	ut8 *buff;
};

#define R2_TYPE 0x69

#define READ_KERNEL_MEMORY  0x1
#define WRITE_KERNEL_MEMORY 0x2

#define IOCTL_READ_KERNEL_MEMORY  _IOR (R2_TYPE, READ_KERNEL_MEMORY, struct r2k_data)
#define IOCTL_WRITE_KERNEL_MEMORY _IOR (R2_TYPE, WRITE_KERNEL_MEMORY, struct r2k_data)

static int ReadKernelMemory_linux (RIODesc *iodesc, ut64 address,  ut8 *buf, int len) {
	if (iodesc && iodesc->fd > 0) {
		struct r2k_data data;
		int ret, ioctl_n;

		data.pid = 0;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len + 1, 1);
		if (!data.buff) {
			return -1;
		}

		ioctl_n = IOCTL_READ_KERNEL_MEMORY;
		ret = ioctl (iodesc->fd, ioctl_n, &data);
		if (!ret) {
			memcpy (buf, data.buff, len);
			ret = len;
		} else {
			//eprintf ("Read failed. ioctl err: %s\n", strerror (errno));
			ret = -1;
		}

		free (data.buff);
		return ret;
	} else {
		eprintf ("IOCTL device not initialized.\n");
		return -1;
	}
}

static int WriteKernelMemory_linux (RIODesc *iodesc, ut64 address, const ut8 *buf, int len) {
	if (iodesc && iodesc->fd > 0) {
		struct r2k_data data;
		int ret, ioctl_n;

		data.pid = 0;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len + 1, 1);
		if (!data.buff) {
			return -1;
		}

		ioctl_n = IOCTL_WRITE_KERNEL_MEMORY;
		memcpy (data.buff, buf, len);
		ret = ioctl (iodesc->fd, ioctl_n, &data);
		if (!ret) {
			ret = len;
		} else {
			eprintf ("Write failed. ioctl err: %s\n", strerror (errno));
			ret = -1;
		}

		free (data.buff);
		return ret;
	} else {
		eprintf ("IOCTL device not initialized.\n");
		return -1;
	}
}
#endif

int r2k__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
#if __WINDOWS__
	//eprintf("writing to: 0x%"PFMT64x" len: %x\n",io->off, count);
	return WriteKernelMemory (io->off, buf, count);
#elif __linux__
	return WriteKernelMemory_linux (fd, io->off, buf, count);
#else
	eprintf ("TODO: r2k not implemented for this plataform.\n");
	return -1;
#endif
}

static int r2k__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
#if __WINDOWS__
	return ReadKernelMemory (io->off, buf, count);
#elif __linux__
	return ReadKernelMemory_linux (fd, io->off, buf, count);
#else
	eprintf ("TODO: r2k not implemented for this plataform.\n");
	memset (buf, '\xff', count);
	return count;
#endif
}

static int r2k__close(RIODesc *fd) {
#if __WINDOWS__
	if (gHandleDriver) {
		CloseHandle (gHandleDriver);
		StartStopService ("r2k",TRUE);
	}
#elif __linux__
	if (fd) {
		close (fd->fd);
	}
#else
	eprintf ("TODO: r2k not implemented for this plataform.\n");
#endif
	return 0;
}

static ut64 r2k__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
        return (!whence) ? offset : whence == 1
		? io->off + offset : UT64_MAX;
}

static bool r2k__plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "r2k://", 6));
}

static int r2k__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!strncmp (cmd, "mod", 3)) {
#if __WINDOWS__
		GetSystemModules (io);
#endif
	} else {
		eprintf ("Try: '=!mod'\n    '.=!mod'\n");
	}
	return -1;
}

static RIODesc *r2k__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp (pathname, "r2k://", 6)) {
#if __WINDOWS__
		RIOW32 *w32 = R_NEW0 (RIOW32);
		if (Init (&pathname[6]) == FALSE) {
			eprintf ("r2k__open: Error cant init driver: %s\n", &pathname[6]);
			free (w32);
			return NULL;
		}
		return r_io_desc_new (&r_io_plugin_r2k, -1, pathname, rw, mode, w32);
#elif __linux__
		int fd = open ("/dev/r2k", O_RDONLY);
		if (fd == -1) {
			eprintf ("r2k__open: Error in opening /dev/r2k.");
			return NULL;
		}
		return r_io_desc_new (&r_io_plugin_r2k, fd, pathname, rw, mode, NULL);
#else
		eprintf ("Not supported on this platform\n");
#endif
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

