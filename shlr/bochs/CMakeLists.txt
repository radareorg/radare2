cmake_minimum_required(VERSION 3.9)

set(bochs_files src/libbochs.c)
add_library(libr2bochs ${SHLR_LIB_TYPE} ${bochs_files})
target_include_directories(libr2bochs
        PUBLIC
        ${PLATFORM_INC}
        include)