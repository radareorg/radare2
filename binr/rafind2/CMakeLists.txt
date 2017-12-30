cmake_minimum_required(VERSION 3.8)

add_executable(rafind2 rafind2.c)
target_include_directories(rafind2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(rafind2 r_util r_search r_io r_cons)
