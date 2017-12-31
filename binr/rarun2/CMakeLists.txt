cmake_minimum_required(VERSION 3.8)

add_executable(rarun2  rarun2.c)
target_include_directories(rarun2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(rarun2 r_util r_socket)
