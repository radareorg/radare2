#include "io_r2k_windows.h"

HANDLE gHandleDriver = NULL;

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

BOOL StartStopService(LPCSTR lpServiceName, BOOL bStop) {
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

int GetSystemModules(RIO *io) {
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

int ReadKernelMemory (ut64 address, ut8 *buf, int len) {
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

int WriteKernelMemory (ut64 address, const ut8 *buf, int len) {
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

int Init (const char * driverPath) {
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
