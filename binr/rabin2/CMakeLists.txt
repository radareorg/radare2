cmake_minimum_required(VERSION 3.8)

add_executable(rabin2 rabin2.c
		$<TARGET_OBJECTS:libr2sdb>
		$<TARGET_OBJECTS:libr2java>)
target_include_directories(rabin2
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(rabin2 r_util r_bin r_cons r_config r_hash r_io r_crypto r_core r_magic)
