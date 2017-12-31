cmake_minimum_required(VERSION 3.9)

set(gdb_files
    src/arch.c
    src/common.c
    src/packet.c
    src/utils.c
    src/libgdbr.c
    src/gdbclient/core.c
    src/gdbclient/responses.c
    src/gdbclient/xml.c
    src/gdbserver/core.c)
add_library(libr2gdb ${SHLR_LIB_TYPE} ${gdb_files})
target_include_directories(libr2gdb
        PUBLIC
        ${PLATFORM_INC}
        include
        include/gdbclient
        include/gdbserver)