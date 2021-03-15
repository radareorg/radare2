/* radare2 - LGPL - Copyright 2019 - GustavoLCR */
#include <r_debug.h>
#include "windows_message.h"

static char *msg_types_arr[] = {
	"WM_NULL=0x0000",
	"WM_CREATE=0x0001",
	"WM_DESTROY=0x0002",
	"WM_MOVE=0x0003",
	"WM_SIZE=0x0005",
	"WM_ACTIVATE=0x0006",
	"WM_SETFOCUS=0x0007",
	"WM_KILLFOCUS=0x0008",
	"WM_ENABLE=0x000A",
	"WM_SETREDRAW=0x000B",
	"WM_SETTEXT=0x000C",
	"WM_GETTEXT=0x000D",
	"WM_GETTEXTLENGTH=0x000E",
	"WM_PAINT=0x000F",
	"WM_CLOSE=0x0010",
	"WM_QUERYENDSESSION=0x0011",
	"WM_QUIT=0x0012",
	"WM_QUERYOPEN=0x0013",
	"WM_ERASEBKGND=0x0014",
	"WM_SYSCOLORCHANGE=0x0015",
	"WM_ENDSESSION=0x0016",
	"WM_SHOWWINDOW=0x0018",
	"WM_WININICHANGE=0x001A",
	"WM_DEVMODECHANGE=0x001B",
	"WM_ACTIVATEAPP=0x001C",
	"WM_FONTCHANGE=0x001D",
	"WM_TIMECHANGE=0x001E",
	"WM_CANCELMODE=0x001F",
	"WM_SETCURSOR=0x0020",
	"WM_MOUSEACTIVATE=0x0021",
	"WM_CHILDACTIVATE=0x0022",
	"WM_QUEUESYNC=0x0023",
	"WM_GETMINMAXINFO=0x0024",
	"WM_PAINTICON=0x0026",
	"WM_ICONERASEBKGND=0x0027",
	"WM_NEXTDLGCTL=0x0028",
	"WM_SPOOLERSTATUS=0x002A",
	"WM_DRAWITEM=0x002B",
	"WM_MEASUREITEM=0x002C",
	"WM_DELETEITEM=0x002D",
	"WM_VKEYTOITEM=0x002E",
	"WM_CHARTOITEM=0x002F",
	"WM_SETFONT=0x0030",
	"WM_GETFONT=0x0031",
	"WM_SETHOTKEY=0x0032",
	"WM_GETHOTKEY=0x0033",
	"WM_QUERYDRAGICON=0x0037",
	"WM_COMPAREITEM=0x0039",
	"WM_GETOBJECT=0x003D",
	"WM_COMPACTING=0x0041",
	"WM_COMMNOTIFY=0x0044",
	"WM_WINDOWPOSCHANGING=0x0046",
	"WM_WINDOWPOSCHANGED=0x0047",
	"WM_POWER=0x0048",
	"WM_COPYDATA=0x004A",
	"WM_CANCELJOURNAL=0x004B",
	"WM_NOTIFY=0x004E",
	"WM_INPUTLANGCHANGEREQUEST=0x0050",
	"WM_INPUTLANGCHANGE=0x0051",
	"WM_TCARD=0x0052",
	"WM_HELP=0x0053",
	"WM_USERCHANGED=0x0054",
	"WM_NOTIFYFORMAT=0x0055",
	"WM_CONTEXTMENU=0x007B",
	"WM_STYLECHANGING=0x007C",
	"WM_STYLECHANGED=0x007D",
	"WM_DISPLAYCHANGE=0x007E",
	"WM_GETICON=0x007F",
	"WM_SETICON=0x0080",
	"WM_NCCREATE=0x0081",
	"WM_NCDESTROY=0x0082",
	"WM_NCCALCSIZE=0x0083",
	"WM_NCHITTEST=0x0084",
	"WM_NCPAINT=0x0085",
	"WM_NCACTIVATE=0x0086",
	"WM_GETDLGCODE=0x0087",
	"WM_SYNCPAINT=0x0088",
	"WM_NCMOUSEMOVE=0x00A0",
	"WM_NCLBUTTONDOWN=0x00A1",
	"WM_NCLBUTTONUP=0x00A2",
	"WM_NCLBUTTONDBLCLK=0x00A3",
	"WM_NCRBUTTONDOWN=0x00A4",
	"WM_NCRBUTTONUP=0x00A5",
	"WM_NCRBUTTONDBLCLK=0x00A6",
	"WM_NCMBUTTONDOWN=0x00A7",
	"WM_NCMBUTTONUP=0x00A8",
	"WM_NCMBUTTONDBLCLK=0x00A9",
	"WM_NCXBUTTONDOWN=0x00AB",
	"WM_NCXBUTTONUP=0x00AC",
	"WM_NCXBUTTONDBLCLK=0x00AD",
	"WM_INPUT=0x00FF",
	"WM_KEYFIRST=0x0100",
	"WM_KEYDOWN=0x0100",
	"WM_KEYUP=0x0101",
	"WM_CHAR=0x0102",
	"WM_DEADCHAR=0x0103",
	"WM_SYSKEYDOWN=0x0104",
	"WM_SYSKEYUP=0x0105",
	"WM_SYSCHAR=0x0106",
	"WM_SYSDEADCHAR=0x0107",
	"WM_UNICHAR=0x0109",
	"WM_KEYLAST=0x0109",
	"WM_KEYLAST=0x0108",
	"WM_INITDIALOG=0x0110",
	"WM_COMMAND=0x0111",
	"WM_SYSCOMMAND=0x0112",
	"WM_TIMER=0x0113",
	"WM_HSCROLL=0x0114",
	"WM_VSCROLL=0x0115",
	"WM_INITMENU=0x0116",
	"WM_INITMENUPOPUP=0x0117",
	"WM_GESTURE=0x0119",
	"WM_GESTURENOTIFY=0x011A",
	"WM_MENUSELECT=0x011F",
	"WM_MENUCHAR=0x0120",
	"WM_ENTERIDLE=0x0121",
	"WM_MENURBUTTONUP=0x0122",
	"WM_MENUDRAG=0x0123",
	"WM_MENUGETOBJECT=0x0124",
	"WM_UNINITMENUPOPUP=0x0125",
	"WM_MENUCOMMAND=0x0126",
	"WM_CHANGEUISTATE=0x0127",
	"WM_UPDATEUISTATE=0x0128",
	"WM_QUERYUISTATE=0x0129",
	"WM_CTLCOLORMSGBOX=0x0132",
	"WM_CTLCOLOREDIT=0x0133",
	"WM_CTLCOLORLISTBOX=0x0134",
	"WM_CTLCOLORBTN=0x0135",
	"WM_CTLCOLORDLG=0x0136",
	"WM_CTLCOLORSCROLLBAR=0x0137",
	"WM_CTLCOLORSTATIC=0x0138",
	"WM_MOUSEFIRST=0x0200",
	"WM_MOUSEMOVE=0x0200",
	"WM_LBUTTONDOWN=0x0201",
	"WM_LBUTTONUP=0x0202",
	"WM_LBUTTONDBLCLK=0x0203",
	"WM_RBUTTONDOWN=0x0204",
	"WM_RBUTTONUP=0x0205",
	"WM_RBUTTONDBLCLK=0x0206",
	"WM_MBUTTONDOWN=0x0207",
	"WM_MBUTTONUP=0x0208",
	"WM_MBUTTONDBLCLK=0x0209",
	"WM_MOUSEWHEEL=0x020A",
	"WM_XBUTTONDOWN=0x020B",
	"WM_XBUTTONUP=0x020C",
	"WM_XBUTTONDBLCLK=0x020D",
	"WM_MOUSEHWHEEL=0x020E",
	"WM_MOUSELAST=0x020E",
	"WM_MOUSELAST=0x020D",
	"WM_MOUSELAST=0x020A",
	"WM_MOUSELAST=0x0209",
	"WM_PARENTNOTIFY=0x0210",
	"WM_ENTERMENULOOP=0x0211",
	"WM_EXITMENULOOP=0x0212",
	"WM_NEXTMENU=0x0213",
	"WM_SIZING=0x0214",
	"WM_CAPTURECHANGED=0x0215",
	"WM_MOVING=0x0216",
	"WM_POWERBROADCAST=0x0218",
	"WM_DEVICECHANGE=0x0219",
	"WM_MDICREATE=0x0220",
	"WM_MDIDESTROY=0x0221",
	"WM_MDIACTIVATE=0x0222",
	"WM_MDIRESTORE=0x0223",
	"WM_MDINEXT=0x0224",
	"WM_MDIMAXIMIZE=0x0225",
	"WM_MDITILE=0x0226",
	"WM_MDICASCADE=0x0227",
	"WM_MDIICONARRANGE=0x0228",
	"WM_MDIGETACTIVE=0x0229",
	"WM_MDISETMENU=0x0230",
	"WM_ENTERSIZEMOVE=0x0231",
	"WM_EXITSIZEMOVE=0x0232",
	"WM_DROPFILES=0x0233",
	"WM_MDIREFRESHMENU=0x0234",
	"WM_POINTERDEVICECHANGE=0x238",
	"WM_POINTERDEVICEINRANGE=0x239",
	"WM_POINTERDEVICEOUTOFRANGE=0x23A",
	"WM_TOUCH=0x0240",
	"WM_NCPOINTERUPDATE=0x0241",
	"WM_NCPOINTERDOWN=0x0242",
	"WM_NCPOINTERUP=0x0243",
	"WM_POINTERUPDATE=0x0245",
	"WM_POINTERDOWN=0x0246",
	"WM_POINTERUP=0x0247",
	"WM_POINTERENTER=0x0249",
	"WM_POINTERLEAVE=0x024A",
	"WM_POINTERACTIVATE=0x024B",
	"WM_POINTERCAPTURECHANGED=0x024C",
	"WM_TOUCHHITTESTING=0x024D",
	"WM_POINTERWHEEL=0x024E",
	"WM_POINTERHWHEEL=0x024F",
	"WM_POINTERROUTEDTO=0x0251",
	"WM_POINTERROUTEDAWAY=0x0252",
	"WM_POINTERROUTEDRELEASED=0x0253",
	"WM_MOUSEHOVER=0x02A1",
	"WM_MOUSELEAVE=0x02A3",
	"WM_NCMOUSEHOVER=0x02A0",
	"WM_NCMOUSELEAVE=0x02A2",
	"WM_DPICHANGED=0x02E0",
	"WM_GETDPISCALEDSIZE=0x02E4",
	"WM_CUT=0x0300",
	"WM_COPY=0x0301",
	"WM_PASTE=0x0302",
	"WM_CLEAR=0x0303",
	"WM_UNDO=0x0304",
	"WM_RENDERFORMAT=0x0305",
	"WM_RENDERALLFORMATS=0x0306",
	"WM_DESTROYCLIPBOARD=0x0307",
	"WM_DRAWCLIPBOARD=0x0308",
	"WM_PAINTCLIPBOARD=0x0309",
	"WM_VSCROLLCLIPBOARD=0x030A",
	"WM_SIZECLIPBOARD=0x030B",
	"WM_ASKCBFORMATNAME=0x030C",
	"WM_CHANGECBCHAIN=0x030D",
	"WM_HSCROLLCLIPBOARD=0x030E",
	"WM_QUERYNEWPALETTE=0x030F",
	"WM_PALETTEISCHANGING=0x0310",
	"WM_PALETTECHANGED=0x0311",
	"WM_HOTKEY=0x0312",
	"WM_PRINT=0x0317",
	"WM_PRINTCLIENT=0x0318",
	"WM_APPCOMMAND=0x0319",
	"WM_THEMECHANGED=0x031A",
	"WM_CLIPBOARDUPDATE=0x031D",
	"WM_DWMCOMPOSITIONCHANGED=0x031E",
	"WM_DWMNCRENDERINGCHANGED=0x031F",
	"WM_DWMCOLORIZATIONCOLORCHANGED=0x0320",
	"WM_DWMWINDOWMAXIMIZEDCHANGE=0x0321",
	"WM_DWMSENDICONICTHUMBNAIL=0x0323",
	"WM_DWMSENDICONICLIVEPREVIEWBITMAP=0x0326",
	"WM_GETTITLEBARINFOEX=0x033F",
	"WM_HANDHELDFIRST=0x0358",
	"WM_HANDHELDLAST=0x035F",
	"WM_AFXFIRST=0x0360",
	"WM_AFXLAST=0x037F",
	"WM_PENWINFIRST=0x0380",
	"WM_PENWINLAST=0x038F",
	"WM_APP=0x8000",
	"WM_USER=0x0400",
	NULL
};

void __free_window (void *ptr) {
	window *win = ptr;
	free (win->name);
	free (win);
}

static window *__window_from_handle(HANDLE hwnd) {
	r_return_val_if_fail (hwnd, NULL);
	window *win = R_NEW0 (window);
	if (!win) {
		return NULL;
	}
	win->h = hwnd;
	win->tid = GetWindowThreadProcessId (hwnd, &win->pid);
	win->proc = GetClassLongPtrW (hwnd, GCLP_WNDPROC);
	const size_t sz = MAX_CLASS_NAME * sizeof (WCHAR);
	wchar_t *tmp = malloc (sz);
	if (!tmp) {
		free (win);
		return NULL;
	}
	GetClassNameW (hwnd, tmp, MAX_CLASS_NAME);
	win->name = r_utf16_to_utf8 (tmp);
	free (tmp);
	if (!win->name) {
		win->name = strdup ("");
	}
	return win;
}

static RTable *__create_window_table(void) {
	RTable *tbl = r_table_new ("windows");
	if (!tbl) {
		return NULL;
	}
	r_table_add_column (tbl, r_table_type ("number"), "Handle", ST32_MAX);
	r_table_add_column (tbl, r_table_type ("number"), "PID", ST32_MAX);
	r_table_add_column (tbl, r_table_type ("number"), "TID", ST32_MAX);
	r_table_add_column (tbl, r_table_type ("string"), "Class Name", ST32_MAX);
	return tbl;
}

static void __add_window_to_table(RTable *tbl, window *win) {
	r_return_if_fail (tbl && win);
	char *handle = r_str_newf ("0x%08"PFMT64x"", (ut64)win->h);
	char *pid = r_str_newf ("%lu", win->pid);
	char *tid = r_str_newf ("%lu", win->tid);
	r_table_add_row (tbl, handle, pid, tid, win->name, NULL);
	free (handle);
	free (tid);
	free (pid);
}

R_API void r_w32_identify_window(void) {
	while (!r_cons_yesno ('y', "Move cursor to the window to be identified. Ready?"));
	POINT p;
	GetCursorPos (&p);
	HANDLE hwnd = WindowFromPoint (p);
	window *win = NULL;
	if (hwnd) {
		if (r_cons_yesno ('y', "Try to get the child?")) {
			HANDLE child = ChildWindowFromPoint (hwnd, p);
			hwnd = child ? child : hwnd;
		}
		win = __window_from_handle (hwnd);
	} else {
		eprintf ("No window found\n");
		return;
	}
	if (!win) {
		eprintf ("Error trying to get information from 0x%08"PFMT64x"\n", (ut64)hwnd);
		return;
	}
	RTable *tbl = __create_window_table ();
	if (!tbl) {
		return;
	}
	__add_window_to_table (tbl, win);
	char *tbl_str = r_table_tofancystring (tbl);
	r_cons_print (tbl_str);
	free (tbl_str);
	r_table_free (tbl);
}

static BOOL CALLBACK __enum_childs(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
) {
	RList *windows = (RList *)lParam;
	window *win = __window_from_handle (hwnd);
	if (!win) {
		return false;
	}
	r_list_push (windows, win);
	return true;
}

static RList *__get_windows(RDebug *dbg) {
	RList *windows = r_list_newf ((RListFree)__free_window);
	HWND hCurWnd = NULL;
	do {
		hCurWnd = FindWindowEx (NULL, hCurWnd, NULL, NULL);
		DWORD dwProcessID = 0;
		GetWindowThreadProcessId (hCurWnd, &dwProcessID);
		if (dbg->pid == dwProcessID) {
			EnumChildWindows (hCurWnd, __enum_childs, (LPARAM)windows);
			window *win = __window_from_handle (hCurWnd);
			if (!win) {
				r_list_free (windows);
				return NULL;
			}
			r_list_push (windows, win);
		}
	} while (hCurWnd != NULL);
	return windows;
}

static ut64 __get_dispatchmessage_offset(RDebug *dbg) {
	RList *modlist = r_debug_modules_list (dbg);
	RListIter *it;
	RDebugMap *mod;
	bool found = false;
	r_list_foreach (modlist, it, mod) {
		if (!strnicmp (mod->name, "user32.dll", sizeof ("user32.dll"))) {
			found = true;
			break;
		}
	}
	if (!found) {
		return 0;
	}
	char *res = dbg->corebind.cmdstr (dbg->corebind.core, "f~DispatchMessageW");
	if (!*res) {
		free (res);
		return 0;
	}
	char *line = strtok (res, "\n");
	ut64 offset = 0;
	do  {
		char *sym = strrchr (line, ' ');
		if (sym && r_str_startswith (sym + 1, "sym.imp")) {
			offset = r_num_math (NULL, line);
			dbg->iob.read_at (dbg->iob.io, offset, (ut8 *)&offset, sizeof (offset));
			break;
		}
	} while ((line = strtok (NULL, "\n")));
	free (res);
	return offset;
}

static void __init_msg_types(Sdb **msg_types) {
	*msg_types = sdb_new0 ();
	int i;
	char *cur_type;
	for (i = 0; (cur_type = msg_types_arr[i]); i++) {
		sdb_query (*msg_types, cur_type);
	}
}

static DWORD __get_msg_type(char *name) {
	static Sdb *msg_types = NULL;
	if (!msg_types) {
		__init_msg_types (&msg_types);
	}
	ut32 found;
	const char *type_str = sdb_const_get (msg_types, name, &found);
	if (found) {
		int type = r_num_math (NULL, type_str);
		return type;
	}
	return 0;
}

static void __print_windows(RDebug *dbg, RList *windows) {
	RTable *tbl = __create_window_table ();
	if (!tbl) {
		return;
	}
	RListIter *it;
	window *win;
	r_list_foreach (windows, it, win) {
		__add_window_to_table (tbl, win);
	}
	char *t = r_table_tofancystring (tbl);
	dbg->cb_printf (t);
	free (t);
	r_table_free (tbl);
}

R_API void r_w32_print_windows(RDebug *dbg) {
	RList *windows = __get_windows (dbg);
	if (windows) {
		if (!windows->length) {
			dbg->cb_printf ("No windows for this process.\n");
			return;
		}
		__print_windows (dbg, windows);
	}
	r_list_free (windows);
}

R_API bool r_w32_add_winmsg_breakpoint(RDebug *dbg, const char *input) {
	r_return_val_if_fail (dbg && input, false);
	char *name = strdup (input);
	r_str_trim (name);
	char *window_id = strchr (name, ' ');
	if (window_id) {
		*window_id = 0;
		window_id++;
	}
	DWORD type = __get_msg_type (name);
	if (!type) {
		free (name);
		return false;
	}
	ut64 offset = 0;
	if (window_id) {
		RList *windows = __get_windows (dbg);
		if (windows && !windows->length) {
			dbg->cb_printf ("No windows for this process.\n");
		}
		ut64 win_h = r_num_math (NULL, window_id);
		RListIter *it;
		window *win;
		r_list_foreach (windows, it, win) {
			if ((ut64)win->h == win_h || !strnicmp (win->name, window_id, strlen (window_id))) {
				offset = win->proc;
				break;
			}
		}
		if (!offset) {
			dbg->cb_printf ("Window not found, try these:\n");
			__print_windows (dbg, windows);
		}
		r_list_free (windows);
	} else {
		offset = __get_dispatchmessage_offset (dbg);
	}
	if (!offset) {
		free (name);
		return false;
	}
	r_debug_bp_add (dbg, offset, 0, 0, 0, NULL, 0);
	char *cond;
	if (window_id) {
		cond = r_str_newf ("?= `ae %lu,edx,-`", type);
	} else {
		char *reg;
		if (dbg->bits == R_SYS_BITS_64) {
			reg = "rcx";
		} else {
			reg = "ecx";
		}
		cond = r_str_newf ("?= `ae %lu,%s,%d,+,[4],-`", type, reg, dbg->bits);
	}
	dbg->corebind.cmdf (dbg->corebind.core, "\"dbC 0x%"PFMT64x" %s\"", offset, cond);
	free (name);
	return true;
}
