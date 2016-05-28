/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

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

#define strDeviceName     "\\\\.\\r2Mem\\"
#define		CLOSE_DRIVER	    	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_READ_PHYS_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_READ_KERNEL_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_GET_PHYSADDR	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define		IOCTL_WRITE_PHYS_MEM	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

static HANDLE gHandleDriver = NULL;

BOOL InstallService(char * rutaDriver, LPCSTR  lpServiceName, LPCSTR  lpDisplayName, BOOL bStop) {
	HANDLE hSCManager;
	HANDLE hService;
	SERVICE_STATUS ss;
	BOOL ret = FALSE;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = CreateServiceA(hSCManager, lpServiceName, lpDisplayName, SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, rutaDriver, NULL, NULL, NULL, NULL, NULL);
		if (!hService) {
			hService = OpenServiceA(hSCManager, "test", SERVICE_START | DELETE | SERVICE_STOP);
		}
		if (hService) {
			if (!bStop) {
				if (StartServiceA(hService, 0, NULL)) {
					eprintf("Service installed [OK]\n");
					ret = TRUE;
				}
				else {
					eprintf("Service installed [FAIL]\n");
				}
			}
			else {
				if (ControlService(hService, SERVICE_CONTROL_STOP, &ss)) {
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
	BOOL	Ret = FALSE;
	gHandleDriver = CreateFileA(strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_DIRECTORY, 0);
	if (gHandleDriver != INVALID_HANDLE_VALUE)
		Ret = TRUE;
	return(Ret);
}
/*void GetDriverInfo(VOID)
{
	LPVOID		lpBuffer = NULL;
	HANDLE		hDevice = INVALID_HANDLE_VALUE;
	DWORD		Status = 1;
	ULONG		bRead;
	PPA         t;
	PA			direccion;
	CHAR *      buffer;
	do	// no es un loop , es para evitar gotos ;)
	{
		#define bufsize 256
		if (!(lpBuffer = malloc(bufsize)))
			break;

		hDevice = CreateFile(strDeviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
		if (hDevice == INVALID_HANDLE_VALUE)
			break;
		direccion.address.QuadPart = 0xfffff80002a1d013;

		t = (PPA)lpBuffer;
		t->address.HighPart = direccion.address.HighPart;
		t->address.LowPart = direccion.address.LowPart;
		t->len = 256;
		if (!(DeviceIoControl(hDevice, IOCTL_READ_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
			break;

		ULONGLONG addr = direccion.address.QuadPart;
		if (!(DeviceIoControl(hDevice, IOCTL_GET_PHYSADDR, &addr, sizeof(ULONGLONG), lpBuffer, bufsize, &bRead, NULL)))
			break;

		t = (PPA)lpBuffer;
		//t->address.HighPart = 0;
		//t->address.LowPart = 0x02a1d013;
		t->len = 256;
		if (!(DeviceIoControl(hDevice, IOCTL_READ_PHYS_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
			break;

		t = (PPA)lpBuffer;
		t->address.HighPart = 0;
		t->address.LowPart = 0x02a1d013;
		t->len = 5;
		strcpy(&t->buffer, "abel1");
		if (!(DeviceIoControl(hDevice, IOCTL_WRITE_PHYS_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)))
			break;
		printf("[ok] GetDriverInfo: Resultado = %s \n", lpBuffer);
		Status = NO_ERROR;

	} while (FALSE);
	if (Status != NO_ERROR)
	{
		Status = GetLastError();
		printf("[x] GetDriverInfo: Error %x\n", Status);
	}
	if (lpBuffer)
		free(lpBuffer);
	if (hDevice != INVALID_HANDLE_VALUE)
		CloseHandle(hDevice);
}
*/
int w32__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return -1;
}

static int w32__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	DWORD ret = 0, bRead = 0;
	LPVOID	lpBuffer = NULL;
	int bufsize;
	PPA p;

	memset(buf,'\xff',count);

	bufsize=sizeof(PA) + count;
	if (!(lpBuffer = malloc(bufsize))) {
		eprintf("io_w32r0: read: Error cant allocate memory.\n");
		return -1;
	}
	p = (PPA)lpBuffer;
	p->address.QuadPart= io->off;
	p->len = count;
	if (DeviceIoControl(gHandleDriver, IOCTL_READ_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)) {
		memcpy(buf,lpBuffer,count);
		ret = count;
	}
	free(lpBuffer);
	return ret;
}

static int w32__close(RIODesc *fd) {
	if(gHandleDriver) {
		CloseHandle(gHandleDriver);
	}
	return 0;
}

static ut64 w32__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
        return (!whence)?offset:whence==1?io->off+offset:UT64_MAX;
}

static int w32__plugin_open(RIO *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "w32r0://", 8));
}

static RIODesc *w32__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp (pathname, "w32r0://", 8)) {
		RIOW32 *w32 = R_NEW0 (RIOW32);
		eprintf("Iniciando driver: %s\n", &pathname[8]);
		InstallService(&pathname[8], "test", "test", TRUE);
		if (InstallService(&pathname[8], "test", "test", FALSE)) {
			if (InitDriver()) {
				eprintf("Driver present [OK]\n");
			}
			else {
				eprintf("Driver preset [FAIL]\n");
			}
		}
		else {
			eprintf("Error cant init: %s\n", &pathname[8]);
		}
		return r_io_desc_new (&r_io_plugin_w32r0, -1, pathname, rw, mode, w32);
		free (w32);
	}
	return NULL;
}

RIOPlugin r_io_plugin_w32r0 = {
	.name = "w32r0",
        .desc = "w32 r0 API io (w32r0://)",
	.license = "LGPL3",
        .open = w32__open,
        .close = w32__close,
	.read = w32__read,
        .check = w32__plugin_open,
	.lseek = w32__lseek,
	.system = NULL, // w32__system,
	.write = w32__write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32r0,
	.version = R2_VERSION
};
#endif

#else
struct r_io_plugin_t r_io_plugin_w32r0 = {
	.name = (void*)0 
};

#endif
