#ifndef WINDOWS_TIME_H
#define WINDOWS_TIME_H


#ifndef _WINBASE_
#ifndef _MINWINBASE_
#ifndef __wtypesbase_h__


#ifndef _FILETIME_

typedef struct _FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
} 	FILETIME;

typedef struct _FILETIME *PFILETIME;
typedef struct _FILETIME *LPFILETIME;

#endif /* _FILETIME_ */


#ifndef _SYSTEMTIME_

typedef struct _SYSTEMTIME {
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
} 	SYSTEMTIME;

typedef struct _SYSTEMTIME *PSYSTEMTIME;
typedef struct _SYSTEMTIME *LPSYSTEMTIME;

#endif /* _SYSTEMTIME_ */


#endif /* __wtypesbase_h__ */
#endif /* _MINWINBASE_ */
#endif /* _WINBASE_ */


#endif /* WINDOWS_TIME_H */
