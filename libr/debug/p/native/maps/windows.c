
static RList *w32_dbg_modules(RDebug *dbg) {
	HANDLE hProcess = 0;
	HANDLE hModuleSnap = 0;
	MODULEENTRY32 me32;
	RDebugMap *mr;
	char *mapname = NULL;
	int pid = dbg->pid;
	RList *list = r_list_new ();

	hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid );
	if (!hModuleSnap) {
		print_lasterr ((char *)__FUNCTION__, "CreateToolhelp32Snapshot");
		CloseHandle (hModuleSnap);
		return NULL;
	}
	me32.dwSize = sizeof (MODULEENTRY32);
	if (!Module32First (hModuleSnap, &me32)) {
		CloseHandle (hModuleSnap);
		return NULL;
	}
	hProcess = w32_openprocess (PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, pid );
	do {
		ut64 baddr = (ut64)(size_t)me32.modBaseAddr;
		mapname = (char *)malloc(MAX_PATH);
		snprintf (mapname, MAX_PATH, "%s\\%s", me32.szExePath, me32.szModule);
		mr = r_debug_map_new (mapname, baddr, baddr + me32.modBaseSize, 0, 0);
		if (mr != NULL) {
			mr->file=strdup(mapname);
			r_list_append (list, mr);
		}
		free(mapname);
	} while(Module32Next (hModuleSnap, &me32));
	CloseHandle (hModuleSnap);
	CloseHandle (hProcess);
	return list;
}

static RList *w32_dbg_maps(RDebug *dbg) {
	HANDLE hProcess = 0;
	HANDLE hModuleSnap = 0;
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_SECTION_HEADER *SectionHeader;
	SIZE_T ret_len;
	MODULEENTRY32 me32;
	RDebugMap *mr;
	ut8 PeHeader[1024];
	char *mapname = NULL;
	int NumSections, i;
	//int tid = dbg->tid;
	int pid = dbg->pid;
	RList *list = r_debug_map_list_new();
	if (!list) return NULL;

	hModuleSnap = CreateToolhelp32Snapshot (TH32CS_SNAPMODULE, pid);
	if(!hModuleSnap ) {
		print_lasterr ((char *)__FUNCTION__, "CreateToolhelp32Snapshot");
		CloseHandle( hModuleSnap );
		return NULL;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First (hModuleSnap, &me32))	{
		CloseHandle (hModuleSnap);
		return NULL;
	}
	hProcess=w32_openprocess (PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,
				FALSE, pid );
	do {
		ReadProcessMemory (WIN32_PI (hProcess),
				(const void *)me32.modBaseAddr,
				(LPVOID)PeHeader, sizeof(PeHeader), &ret_len);

		if (ret_len == sizeof (PeHeader) && CheckValidPE (PeHeader)) {
			dos_header = (IMAGE_DOS_HEADER *)PeHeader;
			if (!dos_header) continue;
			nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header \
							+ dos_header->e_lfanew);
			if (!nt_headers) continue;
			NumSections = nt_headers->FileHeader.NumberOfSections;
			SectionHeader = (IMAGE_SECTION_HEADER *) ((char *)nt_headers \
								+ sizeof(IMAGE_NT_HEADERS));
			mr = r_debug_map_new (me32.szModule,
					(ut64)(size_t) (me32.modBaseAddr),
					(ut64)(size_t) (me32.modBaseAddr + \
					SectionHeader->VirtualAddress),
					SectionHeader->Characteristics,
					0);
			if (mr != NULL) r_list_append (list, mr);
			if (NumSections <= 0) continue;
			mapname = (char *)malloc(MAX_PATH);
			if (!mapname) continue;
			for (i = 0; i < NumSections; i++) {
				if (SectionHeader->Misc.VirtualSize <= 0)
					continue;
				sprintf(mapname,"%s | %s",
					me32.szModule,
					SectionHeader->Name);

				mr = r_debug_map_new (mapname,
					(ut64)(size_t)(SectionHeader->VirtualAddress +\
					me32.modBaseAddr),
					(ut64)(size_t)(SectionHeader->VirtualAddress + \
					me32.modBaseAddr + SectionHeader->Misc.VirtualSize),
					SectionHeader->Characteristics, // XXX?
					0);
				if (mr != NULL) r_list_append (list, mr);
				SectionHeader++;
			}
			free (mapname);
		}
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle (hModuleSnap);
	CloseHandle (hProcess);
	return list;
/*
	SYSTEM_INFO SysInfo;
	LPBYTE page;
	MODULEINFO ModInfo;
	MEMORY_BASIC_INFORMATION mbi;
	memset (&SysInfo, 0, sizeof (SysInfo));
	GetSystemInfo (&SysInfo); // TODO: check return value
	if (!gmi) {
		eprintf ("w32dbg: no gmi\n");
		return 0;
	}
	if (!gmbn) {
		eprintf ("w32dbg: no gmn\n");
		return 0;
	}

#if !__MINGW64__	// TODO: Fix this , for win64 cant walk over all process memory, use psapi.dll to get modules
	for (page=(LPBYTE)SysInfo.lpMinimumApplicationAddress;
			page<(LPBYTE)SysInfo.lpMaximumApplicationAddress;) {
		if (!VirtualQueryEx (WIN32_PI (hProcess), page, &mbi, sizeof (mbi)))  {
	//		eprintf ("VirtualQueryEx ERROR, address = 0x%08X\n", page);
			page += SysInfo.dwPageSize;
			continue;
			//return NULL;
		}
		if (mbi.Type == MEM_IMAGE) {
			eprintf ("MEM_IMAGE  address = 0x%08X\n", page);
			ReadProcessMemory (WIN32_PI (hProcess), (const void *)page,
				(LPVOID)PeHeader, sizeof (PeHeader), &ret_len);

			if (ret_len == sizeof (PeHeader) && CheckValidPE (PeHeader)) {
				dos_header = (IMAGE_DOS_HEADER *)PeHeader;
				if (!dos_header)
					break;
				nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
						+ dos_header->e_lfanew);
				if (!nt_headers) {
					// skip before failing
					break;
				}
				NumSections = nt_headers->FileHeader.NumberOfSections;
				SectionHeader = (IMAGE_SECTION_HEADER *) ((char *)nt_headers
					+ sizeof(IMAGE_NT_HEADERS));
				if(NumSections > 0) {
					mapname = (char *)malloc(MAX_PATH);
					if (!mapname) {
						perror (":map_reg alloc");
						return NULL;
					}
					gmbn (WIN32_PI(hProcess), (HMODULE) page,
						(LPTSTR)mapname, MAX_PATH);

					for (i=0; i<NumSections; i++) {
						mr = r_debug_map_new (mapname,
							(ut64)(size_t) (SectionHeader->VirtualAddress + page),
							(ut64)(size_t) (SectionHeader->VirtualAddress + page + SectionHeader->Misc.VirtualSize),
							SectionHeader->Characteristics, // XXX?
							0);
						if (!mr)
							return NULL;
						r_list_append (list, mr);
						SectionHeader++;
					}
					free (mapname);
				}
			} else {
				eprintf ("Invalid read\n");
				return NULL;
			}

			if (gmi (WIN32_PI (hProcess), (HMODULE) page,
					(LPMODULEINFO) &ModInfo, sizeof(MODULEINFO)) == 0)
				return NULL;
// THIS CODE SEGFAULTS WITH NO REASON. BYPASS IT!
#if 0
		eprintf("--> 0x%08x\n", ModInfo.lpBaseOfDll);
		eprintf("sz> 0x%08x\n", ModInfo.SizeOfImage);
		eprintf("rs> 0x%08x\n", mbi.RegionSize);
		//	 avoid infinite loops
		//	if (ModInfo.SizeOfImage == 0)
		//		return 0;
		//	page += ModInfo.SizeOfImage;
#endif
			page +=  mbi.RegionSize;
		} else {
			mr = r_debug_map_new ("unk", (ut64)(size_t)(page),
				(ut64)(size_t)(page+mbi.RegionSize), mbi.Protect, 0);
			if (!mr) {
				eprintf ("Cannot create r_debug_map_new\n");
				// XXX leak
				return NULL;
			}
			r_list_append (list, mr);
			page += mbi.RegionSize;
		}
	}
#endif
	return list;
*/
}
