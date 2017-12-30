cmake_minimum_required(VERSION 3.8)

set(files
	2048.c
	canvas.c
	canvas_line.c
	cons.c
	#dietline.c
	editor.c
	grep.c
	hud.c
	input.c
	less.c
	line.c
	output.c
	pal.c
	pipe.c
	rgb.c
	utf8.c)

add_library(r_cons ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2sdb>)
target_include_directories(r_cons
		PUBLIC
		${PLATFORM_INC})
target_link_libraries(r_cons r_util)
