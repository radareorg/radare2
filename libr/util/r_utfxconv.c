#include <r_types.h>
#include <r_util.h>

R_API char *r_utf16_to_utf8 (const wchar_t *wc) {
	char *rutf8;
	int csize;

	if ((csize = WideCharToMultiByte (CP_UTF8, 0, wc, -1, NULL, 0, NULL, NULL))) {
		if ((rutf8 = malloc (csize))) {
			WideCharToMultiByte (CP_UTF8, 0, wc, -1, rutf8, csize, NULL, NULL);
		}
	}
	return rutf8;
}

R_API wchar_t *r_utf8_to_utf16 (const char *cstring) {
	wchar_t *rutf16;
	int wcsize;

	if ((wcsize = MultiByteToWideChar (CP_UTF8, 0, cstring, -1, NULL, 0))) {
		if ((rutf16 = (wchar_t *) calloc (wcsize, sizeof (wchar_t)))) {
			MultiByteToWideChar (CP_UTF8, 0, cstring, -1, rutf16, wcsize);
		}
	}
	return rutf16;
}
