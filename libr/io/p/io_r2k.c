/* io_r2k - radare2 - LGPL - Copyright 2016 - SkUaTeR + panda */

#include <r_io.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_print.h>
#include <r_util.h>
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
#define READ_PROCESS_ADDR   0x3
#define WRITE_PROCESS_ADDR  0X4
#define READ_PHYSICAL_ADDR  0x5
#define WRITE_PHYSICAL_ADDR 0x6
#define GET_PROC_MAPS       0x7
#define GET_KERNEL_MAP      0x8

#define IOCTL_READ_KERNEL_MEMORY  _IOR (R2_TYPE, READ_KERNEL_MEMORY, sizeof (struct r2k_data))
#define IOCTL_WRITE_KERNEL_MEMORY _IOR (R2_TYPE, WRITE_KERNEL_MEMORY, sizeof (struct r2k_data))
#define IOCTL_READ_PROCESS_ADDR   _IOR (R2_TYPE, READ_PROCESS_ADDR, sizeof (struct r2k_data))
#define IOCTL_WRITE_PROCESS_ADDR  _IOR (R2_TYPE, WRITE_PROCESS_ADDR, sizeof (struct r2k_data))
#define IOCTL_READ_PHYSICAL_ADDR  _IOR (R2_TYPE, READ_PHYSICAL_ADDR, sizeof (struct r2k_data))
#define IOCTL_WRITE_PHYSICAL_ADDR _IOR (R2_TYPE, WRITE_PHYSICAL_ADDR, sizeof (struct r2k_data))
#define IOCTL_GET_PROC_MAPS       _IOR (R2_TYPE, GET_PROC_MAPS, sizeof (struct r2k_data))
#define IOCTL_GET_KERNEL_MAP      _IOR (R2_TYPE, GET_KERNEL_MAP, sizeof (struct r2k_data))

static char* getargpos (const char *buf, int pos) {
	int i;
	for (i = 0; i < pos; i++) {
		buf = strchr (buf, ' ');
		buf = r_str_ichr ((char *) buf, ' ');
	}
	return buf;
}

static ut64 getvalue (const char *buf, int pos) {
	//TODO: Add checks if the particular position exist or not.
	ut64 ret;
	buf = getargpos (buf, pos);
	ret = strtoull (buf, 0, 0);
	return ret;
}

static int ReadMemory (RIO *io, RIODesc *iodesc, int ioctl_n, ut64 pid, ut64 address, ut8 *buf, int len) {
	int ret = -1;
	if (iodesc && iodesc->fd > 0 && buf) {
		struct r2k_data data;

		data.pid = pid;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len + 1, 1);
		if (!data.buff) {
			return -1;
		}

		ret = ioctl (iodesc->fd, ioctl_n, &data);
		if (!ret) {
			memcpy (buf, data.buff, len);
			ret = len;
		} else {
			//eprintf ("Read failed. ioctl err: %s\n", strerror (errno));
			ret = -1;
		}

		free (data.buff);
	} else if (!buf) {
		io->cb_printf ("Invalid input buffer.\n");
	} else {
		io->cb_printf ("IOCTL device not initialized.\n");
	}
	return ret;
}

static int WriteMemory (RIO *io, RIODesc *iodesc, int ioctl_n, ut64 pid, ut64 address, const ut8 *buf, int len) {
	int ret = -1;
	if (iodesc && iodesc->fd > 0 && buf) {
		struct r2k_data data;

		data.pid = pid;
		data.addr = address;
		data.len = len;
		data.buff = (ut8 *) calloc (len + 1, 1);
		if (!data.buff) {
			return -1;
		}

		memcpy (data.buff, buf, len);
		ret = ioctl (iodesc->fd, ioctl_n, &data);
		if (!ret) {
			ret = len;
		} else {
			io->cb_printf ("Write failed. ioctl err: %s\n", strerror (errno));
			ret = -1;
		}

		free (data.buff);
	} else if (!buf) {
		io->cb_printf ("Invalid input buffer.\n");
	} else {
		io->cb_printf ("IOCTL device not initialized.\n");
	}
	return ret;
}

static int run_ioctl_command (RIO *io, RIODesc *iodesc, const char *buf) {
	int ret, inphex, ioctl_n;
	ut64 pid, addr, len;
	ut8 *databuf = NULL;
	buf = r_str_ichr ((char *) buf, ' ');

	switch (*buf) {
	case 'r':
		{
			switch (buf[1]) {
			case 'l':
				//read linear address
				//=! rl addr len
				pid = 0;
				addr = getvalue (buf, 1);
				len = getvalue (buf, 2);
				ioctl_n = IOCTL_READ_KERNEL_MEMORY;
				break;
			case 'p':
				//read process address
				//=! rp pid address len
				pid = getvalue (buf, 1);
				addr = getvalue (buf, 2);
				len = getvalue (buf, 3);
				ioctl_n = IOCTL_READ_PROCESS_ADDR;
				break;
			case 'P':
				//read physical address
				//=! rP address len
				pid = 0;
				addr = getvalue (buf, 1);
				len = getvalue (buf, 2);
				ioctl_n = IOCTL_READ_PHYSICAL_ADDR;
				break;
			default:
				goto end;
			}
			databuf = (ut8 *) calloc (len + 1, 1);
			ret = ReadMemory (io, iodesc, ioctl_n, pid, addr, databuf, len);
			if (ret > 0) {
				r_print_hexdump (NULL, addr, (const ut8 *) databuf, ret, 16, 1); //TODO: Fix this. Not to use r_print_hexdump
			}
		}
		break;
	case 'w':
		{
			inphex = (buf[2] == 'x') ? 1 : 0;
			switch (buf[1]) {
			case 'l':
				//write linear address
				//=! wl addr str
				pid = 0;
				addr = getvalue (buf, 1);
				buf = getargpos (buf, 2);
				ioctl_n = IOCTL_WRITE_KERNEL_MEMORY;
				break;
			case 'p':
				//write process address
				//=! wp pid address str
				pid = getvalue (buf, 1);
				addr = getvalue (buf, 2);
				buf = getargpos (buf, 3);
				ioctl_n = IOCTL_WRITE_PROCESS_ADDR;
				break;
			case 'P':
				//write physical address
				//=! wP address str
				pid = 0;
				addr = getvalue (buf, 1);
				buf = getargpos (buf, 2);
				ioctl_n = IOCTL_WRITE_PHYSICAL_ADDR;
				break;
			default:
				goto end;
			}
			len = strlen (buf);
			databuf = (ut8 *) calloc (len + 1, 1);
			if (databuf) {
				if (inphex) {
					len = r_hex_str2bin (buf, databuf);
				} else {
					memcpy (databuf, buf, strlen (buf) + 1);
					len = r_str_unescape ((char *) databuf);
				}
				ret = WriteMemory (io, iodesc, ioctl_n, pid, addr, (const ut8 *) databuf, len);
			} else {
			    io->cb_printf ("Failed to allocate buffer.\n");
			}
		}
		break;
	case 'g':
		break;
	default:
		{
			const char* help_msg = "Usage:   =![rw][lpP] [args...]\n" \
				"=!rl     addr len        Read from linear address\n" \
				"=!rp     pid addr len    Read from process address\n" \
				"=!rP     addr len        Read physical address\n" \
				"=!wl[x]  addr input      Write at linear address. Use =!wlx for input in hex\n" \
				"=!wp[x]  pid addr input  Write at process address. Use =!wpx for input in hex\n" \
				"=!wP[x]  addr input      Write at physical address. Use =!wPx for input in hex\n";
			io->cb_printf ("%s", help_msg);
		}
	}
 end:
	return 0;
}

#endif

int r2k__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
#if __WINDOWS__
	//eprintf("writing to: 0x%"PFMT64x" len: %x\n",io->off, count);
	return WriteKernelMemory (io->off, buf, count);
#elif __linux__
	return WriteMemory (io, fd, IOCTL_WRITE_KERNEL_MEMORY, 0, io->off, buf, count);
#else
	io->cb_printf ("TODO: r2k not implemented for this plataform.\n");
	return -1;
#endif
}

static int r2k__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
#if __WINDOWS__
	return ReadKernelMemory (io->off, buf, count);
#elif __linux__
	return ReadMemory (io, fd, IOCTL_READ_KERNEL_MEMORY, 0, io->off, buf, count);
#else
	io->cb_printf ("TODO: r2k not implemented for this plataform.\n");
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
#if __linux__
		run_ioctl_command (io, fd, cmd);
#else
		eprintf ("Try: '=!mod'\n    '.=!mod'\n");
#endif
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
			io->cb_printf ("r2k__open: Error in opening /dev/r2k.");
			return NULL;
		}
		return r_io_desc_new (&r_io_plugin_r2k, fd, pathname, rw, mode, NULL);
#else
		io->cb_printf ("Not supported on this platform\n");
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

