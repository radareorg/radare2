cmake_minimum_required(VERSION 3.8)

add_executable(rasm2 rasm2.c)
target_include_directories(rasm2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(rasm2 r_util r_asm r_anal r_syscall)
