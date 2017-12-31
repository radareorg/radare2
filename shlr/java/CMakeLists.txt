cmake_minimum_required(VERSION 3.9)

set(java_files
    class.c
    code.c
    dsojson.c
    ops.c)
add_library(libr2java ${SHLR_LIB_TYPE} ${java_files})
target_include_directories(libr2java
        PUBLIC
        ${PLATFORM_INC})