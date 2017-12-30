cmake_minimum_required(VERSION 3.8)

set(files
	arena.c
	cond.c
	double.c
	profile.c
	reg.c
	value.c)

add_library(r_reg ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_reg
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r_reg r_util)
