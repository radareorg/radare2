cmake_minimum_required(VERSION 3.8)

set(files
	apprentice.c
	ascmagic.c
	fsmagic.c
	funcs.c
	is_tar.c
	magic.c
	# XXX not used? print.c
	softmagic.c)

add_library(r_magic ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_magic
		PUBLIC
		${PLATFORM_INC})
set(R_MAGIC_COMPILE_FLAGS 
	"-DCORELIB=1")
target_compile_options(r_magic PUBLIC ${R_MAGIC_COMPILE_FLAGS})
target_link_libraries(r_magic r_util)
