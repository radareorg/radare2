cmake_minimum_required(VERSION 3.9)

set(lz4_files lz4.c)
add_library(libr2lz4 ${SHLR_LIB_TYPE} ${lz4_files})
target_include_directories(libr2lz4
        PUBLIC
        ${PLATFORM_INC})