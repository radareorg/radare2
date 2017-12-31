cmake_minimum_required(VERSION 3.8)

set(files
	iobuf.c
	cache.c
	desc.c
	fd.c
	io.c
	ioutils.c
	map.c
	plugin.c
	section.c
	undo.c
	p_cache.c
	p/io_rbuf.c
	p/io_ar.c
	p/io_bfdbg.c
	p/io_bochs.c
	p/io_debug.c
	p/io_default.c
	p/io_gdb.c
	p/io_gzip.c
	p/io_http.c
	p/io_ihex.c
	p/io_mach.c
	p/io_malloc.c
	p/io_mmap.c
	p/io_null.c
	p/io_procpid.c
	p/io_ptrace.c
	p/io_qnx.c
	p/io_r2k.c
	p/io_r2pipe.c
	p/io_r2web.c
	p/io_rap.c
	p/io_self.c
	p/io_shm.c
	p/io_sparse.c
	p/io_tcp.c
	p/io_windbg.c
	p/io_winedbg.c
	p/io_zip.c)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	list(APPEND files
		p/io_r2k_linux.c)
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	list(APPEND files 
		p/io_r2k_windows.c
  		p/io_w32.c
  		p/io_w32dbg.c)
endif()

add_library(r_io ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2sdb>
		$<TARGET_OBJECTS:libr2qnx>
		$<TARGET_OBJECTS:libr2bochs>
		$<TARGET_OBJECTS:libr2windbg>
		$<TARGET_OBJECTS:libr2gdb>
		$<TARGET_OBJECTS:libr2zip>
		$<TARGET_OBJECTS:libr2ar>)
target_include_directories(r_io
		PUBLIC
		${PLATFORM_INC}
		../../shlr/bochs/include
		../../shlr/gdb/include
		../../shlr/qnx/include
		../../shlr/windbg
		../../shlr/ar
		../../shlr/zip/include)
set(R_IO_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_io PUBLIC ${R_IO_COMPILE_FLAGS})
target_link_libraries(r_io r_util r_socket) # libr2qnx libr2bochs libr2windbg libr2gdb libr2zip libr2ar)
