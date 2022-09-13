#define R_LOG_ORIGIN "r2k"

#include "io_r2k_windows.h"

HANDLE gHandleDriver = NULL;

static BOOL InstallService(const char *rutaDriver, LPCTSTR  lpServiceName, LPCTSTR  lpDisplayName) {
	HANDLE hService;
	BOOL ret = FALSE;
	HANDLE hSCManager = OpenSCManager (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		LPTSTR rutaDriver_ = r_sys_conv_utf8_to_win (rutaDriver);
		hService = CreateService (hSCManager, lpServiceName, lpDisplayName, SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, rutaDriver_, NULL, NULL, NULL, NULL, NULL);
		if (hService) {
			CloseServiceHandle (hService);
			ret = TRUE;
		}
		free (rutaDriver_);
		CloseServiceHandle (hSCManager);
	}
	return ret;
}

static BOOL RemoveService(LPCTSTR lpServiceName) {
	HANDLE hService;
	BOOL ret = FALSE;
	HANDLE hSCManager = OpenSCManager (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager) {
		hService = OpenService (hSCManager, lpServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if (hService) {
			DeleteService (hService);
			CloseServiceHandle (hService);
			ret = TRUE;
		}
		CloseServiceHandle (hSCManager);
	}
	return ret;
}

BOOL StartStopService(LPCTSTR lpServiceName, BOOL bStop) {
	HANDLE hSCManager;
	HANDLE hService;
	SERVICE_STATUS ssStatus;
	BOOL ret = FALSE;
	hSCManager = OpenSCManager (NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager)	{
		hService = OpenService (hSCManager, lpServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if (hService) {
			if (!bStop) {
				if (StartService (hService, 0, NULL)) {
					R_LOG_DEBUG ("Service started [OK]");
					ret = TRUE;
				} else {
					R_LOG_DEBUG ("Service started [FAIL]");
				}
			} else {
				if (ControlService (hService, SERVICE_CONTROL_STOP, &ssStatus)) {
					R_LOG_DEBUG ("Service Stopped [OK]");
					ret = TRUE;
				} else {
					R_LOG_DEBUG ("Service Stopped [FAIL]");
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
	gHandleDriver = CreateFile (TEXT (R2K_DEVICE), genericFlags, shareFlags,
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
	if (gHandleDriver) {
		if (!(lpBufMods = malloc (bufmodsize))) {
			R_LOG_ERROR ("GetSystemModules: Cannot allocate %i bytes of memory", bufmodsize);
			return -1;
		}
		if (DeviceIoControl (gHandleDriver, IOCTL_GET_SYSTEM_MODULES, lpBufMods, bufmodsize, lpBufMods, bufmodsize, &bRead, NULL)) {
			PRTL_PROCESS_MODULES pm = (PRTL_PROCESS_MODULES)lpBufMods;
			PRTL_PROCESS_MODULE_INFORMATION pMod = pm->Modules;
			for (i = 0; i < pm->NumberOfModules; i++) {
				const char *fileName = GetFileName((const char*)pMod[i].FullPathName);
				io->cb_printf ("f nt.%s 0x%"PFMT64x" @ 0x"PFMT64x"\n", fileName, (ut64)pMod[i].ImageSize, (ut64)pMod[i].ImageBase);
			}
		}
	} else {
		R_LOG_ERROR ("Driver not initialized");
	}
	return 1;
}

int ReadKernelMemory (ut64 address, ut8 *buf, int len) {
	DWORD ret = -1, bRead = 0;
	LPVOID lpBuffer = NULL;
	int bufsize;
	PPA p;
	memset (buf, '\xff', len);
	if (gHandleDriver) {
		bufsize = sizeof (PA) + len;
		if (!(lpBuffer = malloc (bufsize))) {
			R_LOG_ERROR ("ReadKernelMemory: Cannot allocate %i bytes of memory", bufsize);
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
		}
		free (lpBuffer);
	} else {
		R_LOG_ERROR ("Driver not initialized");
	}
	return ret;
}

int WriteKernelMemory(ut64 address, const ut8 *buf, int len) {
	DWORD ret = -1, bRead = 0;
	LPVOID lpBuffer = NULL;
	int bufsize;
	PPA p;
	if (gHandleDriver) {
		bufsize = sizeof (PA) + len;
		if (!(lpBuffer = malloc (bufsize))) {
			return -1;
		}
		p = (PPA)lpBuffer;
		p->address.QuadPart = address;
		p->len = len;
		memcpy (&p->buffer, buf, len);
		if (DeviceIoControl (gHandleDriver, IOCTL_WRITE_KERNEL_MEM, lpBuffer, bufsize, lpBuffer, bufsize, &bRead, NULL)) {
			ret = len;
		} else {
			R_LOG_ERROR ("WriteKernelMemory: IOCTL_WRITE_KERNEL_MEM");
			ret = -1;
		}
		free (lpBuffer);
	} else {
		R_LOG_ERROR ("Driver not initialized");
	}
	return ret;
}

int Init (const char * driverPath) {
	BOOL ret = FALSE;
	if (InitDriver () == FALSE) {
		if (R_STR_ISNOTEMPTY (driverPath)) {
			StartStopService (TEXT ("r2k"),TRUE);
			RemoveService (TEXT ("r2k"));
			R_LOG_INFO ("Installing driver: %s", driverPath);
			if (InstallService (driverPath, TEXT ("r2k"), TEXT ("r2k"))) {
				StartStopService (TEXT ("r2k"),FALSE);
				ret = InitDriver ();
			}
		} else {
			R_LOG_ERROR ("Cannot load the r2k driver, try `r2 r2k://path/to/r2k.sys`");
		}
	} else {
		R_LOG_DEBUG ("Driver was already present [OK]");
		ret = TRUE;
	}
	return ret;
}
