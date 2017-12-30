cmake_minimum_required(VERSION 3.8)

add_executable(rax2 rax2.c)
target_include_directories(rax2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(rax2 r_util)
