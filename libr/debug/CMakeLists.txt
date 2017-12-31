cmake_minimum_required(VERSION 3.8)

set(files
	arg.c
	ddesc.c
	debug.c
	dreg.c
	esil.c
	map.c
	p/bfvm.c
	p/debug_bf.c
	#p/debug_bochs.c
	p/debug_esil.c
	p/debug_gdb.c
	p/debug_io.c
	p/debug_native.c
	#p/debug_qnx.c
	p/debug_rap.c
	p/debug_windbg.c
	#p/native/arm.c
	#p/native/bt/fuzzy-all.c
	#p/native/bt/generic-x64.c
	#p/native/bt/generic-x86.c
	#p/native/bt.c
	#p/native/darwin.c
	#p/native/drx.c
	#p/native/maps/darwin.c
	pid.c
	plugin.c
	session.c
	signal.c
	snap.c
	trace.c)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	list(APPEND files
	p/native/linux/linux_debug.c
	p/native/linux/linux_coredump.c)
endif()
if(UNIX)
	list(APPEND files
	p/native/procfs.c)
endif(UNIX)
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	list(APPEND files
	p/native/xnu/xnu_debug.c)
	#p/native/xnu/trap_arm.c
	#p/native/xnu/trap_x86.c
	#p/native/xnu/xnu_excthreads.c
	#p/native/xnu/xnu_threads.c)
endif()

add_library(r_debug ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2sdb>
		$<TARGET_OBJECTS:libr2gdb>
		$<TARGET_OBJECTS:libr2windbg>)
target_include_directories(r_debug
		PUBLIC
		${PLATFORM_INC}
		../bin/format/elf
		../../shlr/gdb/include
	    ../../shlr/windbg)
set(R_DEBUG_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_debug PUBLIC ${R_DEBUG_COMPILE_FLAGS})
target_link_libraries(r_debug r_util r_hash r_reg r_syscall r_anal r_flag r_io r_bp r_search r_cons r_lang r_egg r_socket)
