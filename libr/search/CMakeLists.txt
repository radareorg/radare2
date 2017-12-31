cmake_minimum_required(VERSION 3.8)

set(files
	aes-find.c
	bytepat.c
	keyword.c
	#old_xrefs.c
	regexp.c
	rsa-find.c
	search.c
	strings.c
	xrefs.c)

add_library(r_search ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_search
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r_search r_util)

