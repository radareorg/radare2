cmake_minimum_required(VERSION 3.8)

set(files
	bp.c
	bp_io.c
	bp_plugin.c
	bp_traptrace.c
	bp_watch.c
	p/bp_arm.c
	p/bp_bf.c
	p/bp_mips.c
	p/bp_ppc.c
	p/bp_sh.c
	p/bp_x86.c)

add_library(r_bp ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_bp 
		PUBLIC
		${PLATFORM_INC})
set(R_BP_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_bp PUBLIC ${R_BP_COMPILE_FLAGS})
target_link_libraries(r_bp r_util)
