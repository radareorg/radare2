#ifndef WINDOWS_TIMEZONE_H
#define WINDOWS_TIMEZONE_H

#ifndef _TIMEZONEAPI_H_


typedef struct _TIME_ZONE_INFORMATION {
	LONG Bias;
	WCHAR StandardName[32];
	SYSTEMTIME StandardDate;
	LONG StandardBias;
	WCHAR DaylightName[32];
	SYSTEMTIME DaylightDate;
	LONG DaylightBias;
} TIME_ZONE_INFORMATION, *PTIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION;

typedef struct _TIME_DYNAMIC_ZONE_INFORMATION {
	LONG Bias;
	WCHAR StandardName[32];
	SYSTEMTIME StandardDate;
	LONG StandardBias;
	WCHAR DaylightName[ 32 ];
	SYSTEMTIME DaylightDate;
	LONG DaylightBias;
	WCHAR TimeZoneKeyName[128];
	BOOLEAN DynamicDaylightTimeDisabled;
} DYNAMIC_TIME_ZONE_INFORMATION, *PDYNAMIC_TIME_ZONE_INFORMATION;


#endif /* _TIMEZONEAPI_H_ */

#endif /* WINDOWS_TIMEZONE_H */
