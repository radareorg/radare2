cmake_minimum_required(VERSION 3.8)

add_executable(rahash2 rahash2.c)
target_include_directories(rahash2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(rahash2 r_util r_hash r_bin r_io r_crypto r_socket)
