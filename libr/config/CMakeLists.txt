cmake_minimum_required(VERSION 3.8)

set(files
	callback.c
	config.c)

add_library(r_config ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2sdb>)
target_include_directories(r_config
		PUBLIC
		${PLATFORM_INC})
set(R_CONFIG_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_config PUBLIC ${R_CONFIG_COMPILE_FLAGS})
target_link_libraries(r_config r_util)
