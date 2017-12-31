cmake_minimum_required(VERSION 3.8)

add_executable(r2agent r2agent.c)
target_include_directories(r2agent
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r2agent r_util r_socket r_cons)
