cmake_minimum_required(VERSION 3.8)

set(files
	flag.c
	sort.c
	spaces.c
	zones.c)

add_library(r_flag ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2sdb>)
target_include_directories(r_flag
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r_flag r_util)

