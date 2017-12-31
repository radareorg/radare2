cmake_minimum_required(VERSION 3.8)

set(files
	syscall.c
	ioports.c)

add_library(r_syscall ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_syscall
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r_syscall r_util)

