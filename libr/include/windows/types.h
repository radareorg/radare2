#ifndef WINDOWS_TYPES_H
#define WINDOWS_TYPES_H

#ifndef _WINNT_
#ifndef _WINDEF_
#ifndef _MINWINDEF_

#define CONST	const

#define WINDOWS_MAX_PATH	260

#define MINCHAR		0x80
#define MAXCHAR		0x7f
#define MINSHORT	0x8000
#define MAXSHORT	0x7fff
#define MINLONG		0x80000000
#define MAXLONG		0x7fffffff
#define MAXBYTE		0xff
#define MAXWORD		0xffff
#define MAXDWORD	0xffffffff

typedef ut8 BYTE;
typedef ut8 UCHAR;
typedef ut8 BOOLEAN;

typedef st16 SHORT;

typedef ut16 WORD;
typedef ut16 USHORT;
typedef ut16 WCHAR; // NOT wchar_t
// typedef ut16 TCHAR;

typedef st32 BOOL;
typedef st32 INT;
typedef st32 LONG;
typedef st32 HRESULT;

typedef ut32 DWORD;
typedef ut32 UINT;
typedef ut32 ULONG;
typedef ut32 ULONG32;

typedef st64 LONGLONG;

typedef ut64 DWORD64;
typedef ut64 ULONG64;
typedef ut64 ULONGLONG;
typedef ut64 DWORDLONG;

typedef void VOID;
typedef float FLOAT;
typedef double DOUBLE;

typedef VOID      *PVOID;
typedef UINT      *UINT_PTR;
typedef LONG      *LONG_PTR;
typedef ULONG     *ULONG_PTR;
typedef DWORDLONG *PDWORDLONG;
typedef LONGLONG  *PLONGLONG;
typedef ULONGLONG *PULONGLONG;

typedef PVOID HANDLE;

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;
typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;

typedef UINT_PTR  WPARAM;
typedef LONG_PTR  LPARAM;
typedef LONG_PTR  LRESULT;

typedef struct _FLOAT128 {
	st64 LowPart;
	st64 HighPart;
} FLOAT128, *PFLOAT128;

#endif /* _WINDEF_ */
#endif /* _MINWINDEF_ */
#endif /* _WINNT_ */

#endif /* WINDOWS_TYPES_H */
