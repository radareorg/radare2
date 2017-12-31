cmake_minimum_required(VERSION 3.8)

set(files
	lang.c
	p/c.c
	#p/cpipe.c
	p/lib.c
	p/pipe.c
	p/rust.c
	p/vala.c)

add_library(r_lang ${LIBR_LIB_TYPE} ${files})
target_include_directories(r_lang
		PUBLIC
		${PLATFORM_INC})
set(R_LANG_COMPILE_FLAGS 
	"-DCORELIB=1")
target_compile_options(r_lang PUBLIC ${R_LANG_COMPILE_FLAGS})
target_link_libraries(r_lang r_util r_cons)
