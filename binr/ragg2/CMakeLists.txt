cmake_minimum_required(VERSION 3.8)

add_executable(ragg2 ragg2.c)
target_include_directories(ragg2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(ragg2 r_util r_egg r_bin r_core r_hash r_debug r_fs r_config r_bp r_crypto)
