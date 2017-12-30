cmake_minimum_required(VERSION 3.8)

set(files
	file.c
	fs.c
	#p/fs_cpio.c
	p/fs_ext2.c
	p/fs_fat.c
	p/fs_fb.c
	#p/fs_grub_base.c
	p/fs_hfs.c
	p/fs_hfsplus.c
	p/fs_iso9660.c
	p/fs_jfs.c
	p/fs_minix.c
	p/fs_ntfs.c
	p/fs_posix.c
	p/fs_reiserfs.c
	p/fs_sfs.c
	p/fs_tar.c
	p/fs_udf.c
	p/fs_ufs.c
	p/fs_ufs2.c
	p/fs_xfs.c
	p/part_dos.c)

add_library(r_fs ${LIBR_LIB_TYPE} ${files}
		$<TARGET_OBJECTS:libr2grub>)
target_include_directories(r_fs
		PUBLIC
		${PLATFORM_INC}
		../../shlr/grub/include)
set(R_FS_COMPILE_FLAGS 
	"-DCORELIB=1"
	"-I${CMAKE_CURRENT_BINARY_DIR}/../..")
target_compile_options(r_fs PUBLIC ${R_FS_COMPILE_FLAGS})
target_link_libraries(r_fs r_util)
