cmake_minimum_required(VERSION 3.8)

set(files
	egg.c
	egg_lang.c
	emit_arm.c
	emit_trace.c
	emit_x64.c
	emit_x86.c
	#p/egg_bind.c
	#p/egg_cb.c
	p/egg_exec.c
	#p/egg_reverse.c
	#p/egg_shya.c
	p/egg_xor.c)

add_library(r_egg ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2sdb>)
target_include_directories(r_egg
		PUBLIC
		${PLATFORM_INC})
set(R_EGG_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_egg PUBLIC ${R_EGG_COMPILE_FLAGS})
target_link_libraries(r_egg r_util r_asm r_syscall)
