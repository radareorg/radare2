#include "windows_maps.h"
#include "../windows/windows_debug.h"

typedef struct {
	RDebugMap *map;
	IMAGE_SECTION_HEADER *sect_hdr;
	int sect_count;
} RWinModInfo;

static char *get_map_type(MEMORY_BASIC_INFORMATION *mbi) {
	char *type;
	switch (mbi->Type) {
	case MEM_IMAGE:
		type = "IMAGE";
		break;
	case MEM_MAPPED:
		type = "MAPPED";
		break;
	case MEM_PRIVATE:
		type = "PRIVATE";
		break;
	default:
		type = "UNKNOWN";
	}
	return type;
}

static RDebugMap *add_map(RList *list, const char *name, ut64 addr, ut64 len, MEMORY_BASIC_INFORMATION *mbi) {
	int perm;
	char *map_type = get_map_type (mbi);

	switch (mbi->Protect) {
	case PAGE_EXECUTE:
		perm = R_PERM_X;
		break;
	case PAGE_EXECUTE_READ:
		perm = R_PERM_RX;
		break;
	case PAGE_EXECUTE_READWRITE:
		perm = R_PERM_RWX;
		break;
	case PAGE_READONLY:
		perm = R_PERM_R;
		break;
	case PAGE_READWRITE:
		perm = R_PERM_RW;
		break;
	case PAGE_WRITECOPY:
		perm = R_PERM_W;
		break;
	case PAGE_EXECUTE_WRITECOPY:
		perm = R_PERM_X;
		break;
	default:
		perm = 0;
	}
	char *map_name = r_str_newf ("%-8s %s", map_type, name);
	if (!map_name) {
		return NULL;
	}
	RDebugMap *mr = r_debug_map_new (map_name, addr, addr + len, perm, mbi->Type == MEM_PRIVATE);
	free (map_name);
	if (mr) {
		r_list_append (list, mr);
	}
	return mr;
}

static inline RDebugMap *add_map_reg(RList *list, const char *name, MEMORY_BASIC_INFORMATION *mbi) {
	return add_map (list, name, (ut64)(size_t)mbi->BaseAddress, (ut64)mbi->RegionSize, mbi);
}

R_API RList *r_w32_dbg_modules(RDebug *dbg) {
	if (dbg->main_pid == -1) {
		return NULL;
	}
	MODULEENTRY32 me;
	RList *list = r_list_newf (free);
	DWORD flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
	HANDLE h_mod_snap = w32_CreateToolhelp32Snapshot (flags, dbg->pid);

	if (h_mod_snap == INVALID_HANDLE_VALUE) {
		r_sys_perror ("r_w32_dbg_modules/CreateToolhelp32Snapshot");
		goto err_w32_dbg_modules;
	}
	me.dwSize = sizeof (MODULEENTRY32);
	if (!Module32First (h_mod_snap, &me)) {
		r_sys_perror ("r_w32_dbg_modules/Module32First");
		goto err_w32_dbg_modules;
	}
	do {
		ut64 baddr = (ut64)(size_t)me.modBaseAddr;
		char *mod_name = r_sys_conv_win_to_utf8 (me.szModule);
		RDebugMap *dbgmap = r_debug_map_new (mod_name, baddr, baddr + me.modBaseSize, 0, 0);
		free (mod_name);
		if (dbgmap) {
			dbgmap->file = r_sys_conv_win_to_utf8 (me.szExePath);
			if (dbgmap->file) {
				r_list_append (list, dbgmap);
			}
		}
	} while (Module32Next (h_mod_snap, &me));
err_w32_dbg_modules:
	if (h_mod_snap) {
		CloseHandle (h_mod_snap);
	}
	return list;
}

static bool is_pe_hdr(unsigned char *pe_hdr) {
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)pe_hdr;
	IMAGE_NT_HEADERS *nt_headers;

	if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
		nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
				+ dos_header->e_lfanew);
		// TODO: Check boundaries first, before the dereference
		if (nt_headers->Signature == IMAGE_NT_SIGNATURE)
			return true;
	}
	return false;
}

static int set_mod_inf(HANDLE h_proc, RDebugMap *map, RWinModInfo *mod) {
	IMAGE_DOS_HEADER *dos_hdr;
	IMAGE_NT_HEADERS *nt_hdrs;
	IMAGE_NT_HEADERS32 *nt_hdrs32;
	IMAGE_SECTION_HEADER *sect_hdr;
	ut8 pe_hdr[0x1000];
	SIZE_T len;
	int mod_inf_fill;

	len = 0;
	sect_hdr = NULL;
	mod_inf_fill = -1;
	ReadProcessMemory (h_proc, (LPCVOID)(size_t)map->addr, (LPVOID)pe_hdr, sizeof (pe_hdr), &len);
	if (len == (SIZE_T)sizeof (pe_hdr) && is_pe_hdr (pe_hdr)) {
		dos_hdr = (IMAGE_DOS_HEADER *)pe_hdr;
		nt_hdrs = (IMAGE_NT_HEADERS *)((char *)dos_hdr + dos_hdr->e_lfanew);
		if (nt_hdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) { // check for x32 pefile
			nt_hdrs32 = (IMAGE_NT_HEADERS32 *)((char *)dos_hdr + dos_hdr->e_lfanew);
			mod->sect_count = nt_hdrs32->FileHeader.NumberOfSections;
			sect_hdr = (IMAGE_SECTION_HEADER *)((char *)nt_hdrs32 + sizeof (IMAGE_NT_HEADERS32));
		} else {
			mod->sect_count = nt_hdrs->FileHeader.NumberOfSections;
			sect_hdr = (IMAGE_SECTION_HEADER *)((char *)nt_hdrs + sizeof (IMAGE_NT_HEADERS));
		}
		if ((char *)sect_hdr + (sizeof (IMAGE_SECTION_HEADER) * mod->sect_count) < ((char *)pe_hdr + sizeof (pe_hdr))) {
			mod->sect_hdr = (IMAGE_SECTION_HEADER *)malloc (sizeof (IMAGE_SECTION_HEADER) * mod->sect_count);
			if (mod->sect_hdr) {
				memcpy (mod->sect_hdr, sect_hdr, sizeof (IMAGE_SECTION_HEADER) * mod->sect_count);
				mod_inf_fill = 0;
			} else {
				perror ("malloc set_mod_inf()");
			}
		}
	}
	if (mod_inf_fill == -1) {
		R_FREE (mod->sect_hdr);
	}
	return mod_inf_fill;
}

static void proc_mem_img(HANDLE h_proc, RList *map_list, RList *mod_list, RWinModInfo *mod, SYSTEM_INFO *si, MEMORY_BASIC_INFORMATION *mbi) {
	ut64 addr = (ut64)(size_t)mbi->BaseAddress;
	ut64 len = (ut64)mbi->RegionSize;
	if (!mod->map || addr < mod->map->addr || (addr + len) > mod->map->addr_end) {
		RListIter *iter;
		RDebugMap *map;

		free (mod->sect_hdr);
		memset (mod, 0, sizeof (RWinModInfo));
		r_list_foreach (mod_list, iter, map) {
			if (addr >= map->addr && addr <= map->addr_end) {
				mod->map = map;
				set_mod_inf (h_proc, map, mod);
				break;
			}
		}
	}
	if (mod->map && mod->sect_hdr && mod->sect_count > 0) {
		int sect_count;
		int i, p_mask;

		sect_count = 0;
		p_mask = si->dwPageSize - 1;
		for (i = 0; i < mod->sect_count; i++) {
			IMAGE_SECTION_HEADER *sect_hdr = &mod->sect_hdr[i];
			ut64 sect_addr = mod->map->addr + (ut64)sect_hdr->VirtualAddress;
			ut64 sect_len = (((ut64)sect_hdr->Misc.VirtualSize) + p_mask) & ~p_mask;
			int sect_found = 0;

			/* section in memory region? */
			if (sect_addr >= addr && (sect_addr + sect_len) <= (addr + len)) {
				sect_found = 1;
			/* memory region in section? */
			} else if (addr >= sect_addr && (addr + len) <= (sect_addr + sect_len)) {
				sect_found = 2;
			}
			if (sect_found) {
				char *map_name = r_str_newf ("%s | %s", mod->map->name, sect_hdr->Name);
				if (!map_name) {
					perror ("r_str_newf");
					return;
				}
				if (sect_found == 1) {
					add_map (map_list, map_name, sect_addr, sect_len, mbi);
				} else {
					add_map_reg (map_list, map_name, mbi);
				}
				free (map_name);
				sect_count++;
			}
		}
		if (sect_count == 0) {
			add_map_reg (map_list, mod->map->name, mbi);
		}
	} else {
		if (!mod->map) {
			add_map_reg (map_list, "", mbi);
		} else {
			add_map_reg (map_list, mod->map->name, mbi);
		}
	}
}

static void proc_mem_map(HANDLE h_proc, RList *map_list, MEMORY_BASIC_INFORMATION *mbi) {
	TCHAR f_name[MAX_PATH + 1];

	DWORD len = GetMappedFileName (h_proc, mbi->BaseAddress, f_name, MAX_PATH);
	if (len > 0) {
		char *f_name_ = r_sys_conv_win_to_utf8 (f_name);
		add_map_reg (map_list, f_name_, mbi);
		free (f_name_);
	} else {
		add_map_reg (map_list, "", mbi);
	}
}

R_API RList *r_w32_dbg_maps(RDebug *dbg) {
	if (dbg->pid == -1) {
		return NULL;
	}
	SYSTEM_INFO si = {0};
	LPVOID cur_addr;
	MEMORY_BASIC_INFORMATION mbi;
	RWinModInfo mod_inf = {0};
	RList *map_list = r_list_new (), *mod_list = NULL;
	RIOW32Dbg *rio = dbg->user;

	GetSystemInfo (&si);
	cur_addr = si.lpMinimumApplicationAddress;
	/* get process modules list */
	mod_list = r_w32_dbg_modules (dbg);
	/* process memory map */
	while (cur_addr < si.lpMaximumApplicationAddress &&
		VirtualQueryEx (rio->pi.hProcess, cur_addr, &mbi, sizeof (mbi)) != 0) {
		if (mbi.State != MEM_FREE) {
			switch (mbi.Type) {
			case MEM_IMAGE:
				proc_mem_img (rio->pi.hProcess, map_list, mod_list, &mod_inf, &si, &mbi);
				break;
			case MEM_MAPPED:
				proc_mem_map (rio->pi.hProcess, map_list, &mbi);
				break;
			default:
				add_map_reg (map_list, "", &mbi);
			}
		}
		cur_addr = (LPVOID)(size_t)((ut64)(size_t)mbi.BaseAddress + mbi.RegionSize);
	}
	free (mod_inf.sect_hdr);
	r_list_free (mod_list);
	return map_list;
}
