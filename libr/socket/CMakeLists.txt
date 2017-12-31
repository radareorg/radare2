cmake_minimum_required(VERSION 3.8)

set(files
	http.c
	http_server.c
	proc.c
	r2pipe.c
	rap_server.c
	run.c
	socket.c
	serial.c)

add_library(r_socket ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_socket
		PUBLIC
		${PLATFORM_INC})
set(R_SOCKET_COMPILE_FLAGS 
	"-DCORELIB=1")
target_compile_options(r_socket PUBLIC ${R_SOCKET_COMPILE_FLAGS})
target_link_libraries(r_socket r_util r_bin ws2_32)
