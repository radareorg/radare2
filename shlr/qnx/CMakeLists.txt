cmake_minimum_required(VERSION 3.9)

set(qnx_files
    src/core.c
    src/libqnxr.c
    src/packet.c
    src/sigutil.c
    src/utils.c)
add_library(libr2qnx ${SHLR_LIB_TYPE} ${qnx_files})
target_include_directories(libr2qnx
        PUBLIC
        ${PLATFORM_INC}
        include)