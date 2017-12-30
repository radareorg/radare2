cmake_minimum_required(VERSION 3.8)

add_executable(radiff2 radiff2.c)
target_include_directories(radiff2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(radiff2 r_util r_io r_search r_cons r_core r_bin r_anal r_asm r_hash r_config)
