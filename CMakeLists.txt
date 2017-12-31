cmake_minimum_required(VERSION 3.9)
project(radare2)

# Options
set(CMAKE_CXX_STANDARD 11)
set(LIBR_LIB_TYPE STATIC)
set(SHLR_LIB_TYPE OBJECT)

set(PLATFORM_INC
        ${PROJECT_BINARY_DIR}
        ../../libr/include)

# Get radare version
execute_process(COMMAND "python" "sys\\version.py"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE COMMAND_CODE
        OUTPUT_VARIABLE R2VERSION)
string(COMPARE EQUAL ${COMMAND_CODE} "0" res)
if(NOT res)
    message(FATAL_ERROR " Could not find sys\\version.py or python is not in the PATH")
endif()

# Get version commit
execute_process(COMMAND "git" "rev-list" "--all" "--count"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE COMMAND_CODE
        OUTPUT_VARIABLE VERSION_COMMIT)

# Get gittap
execute_process(COMMAND "git" "describe" "--tags" "--match" "[0-9]*"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE COMMAND_CODE
        OUTPUT_VARIABLE GIT_TAP)

# Get gittip
execute_process(COMMAND "git" "rev-parse" "HEAD"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE COMMAND_CODE
        OUTPUT_VARIABLE GIT_TIP)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    execute_process(COMMAND "cmd" "/c" "echo %date%__%time%"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE COMMAND_CODE
            OUTPUT_VARIABLE R2BIRTH)
else()
    execute_process(COMMAND "date" "+%Y-%m-%d__%H:%M:%S"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE COMMAND_CODE
            OUTPUT_VARIABLE R2BIRTH)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND PLATFORM_INC ../../libr/include/msvc)
    find_library(WS2_32_LIB ws2_32)
    if(NOT WS2_32_LIB)
        message(FATAL_ERROR "ws2_32 library not found")
    endif()
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
# TODO
endif()

add_subdirectory(libr)
function(SURROUND outVar prefix postfix)
    set(listVar "")
    foreach(f ${ARGN})
        list(APPEND listVar "${prefix}${f}${postfix}")
    endforeach(f)
    set(${outVar} "${listVar}" PARENT_SCOPE)
endfunction(SURROUND)

SURROUND(CORE_LN "&r_core_plugin_" "," ${CORE_L})
string(CONCAT CORE_LNS ${CORE_LN} " 0")
SURROUND(ANAL_LN "&r_anal_plugin_" "," ${ANAL_L})
string(CONCAT ANAL_LNS ${ANAL_LN} " 0")
SURROUND(ASM_LN "&r_asm_plugin_" "," ${ASM_L})
string(CONCAT ASM_LNS ${ASM_LN} " 0")
SURROUND(BP_LN "&r_bp_plugin_" "," ${BP_L})
string(CONCAT BP_LNS ${BP_LN} " 0")
SURROUND(BIN_LN "&r_bin_plugin_" "," ${BIN_L})
string(CONCAT BIN_LNS ${BIN_LN} " 0")
SURROUND(CRYPTO_LN "&r_crypto_plugin_" "," ${CRYPTO_L})
string(CONCAT CRYPTO_LNS ${CRYPTO_LN} " 0")
SURROUND(IO_LN "&r_io_plugin_" "," ${IO_L})
string(CONCAT IO_LNS ${IO_LN} " 0")
SURROUND(FS_LN "&r_fs_plugin_" "," ${FS_L})
string(CONCAT FS_LNS ${FS_LN} " 0")
SURROUND(DEGUG_LN "&r_debug_plugin_" "," ${DEBUG_L})
string(CONCAT DEBUG_LNS ${DEBUG_LN} " 0")
SURROUND(EGG_LN "&r_egg_plugin_" "," ${EGG_L})
string(CONCAT EGG_LNS ${EGG_LN} " 0")
SURROUND(LANG_LN "&r_lang_plugin_" "," ${LANG_L})
string(CONCAT LANG_LNS ${LANG_LN} " 0")
SURROUND(PARSE_LN "&r_parse_plugin_" "," ${PARSE_L})
string(CONCAT PARSE_LNS ${PARSE_LN} " 0")

set(plugins_core ${CORE_LNS})
set(plugins_anal ${ANAL_LNS})
set(plugins_asm ${ASM_LNS})
set(plugins_bp ${BP_LNS})
set(plugins_bin ${BIN_LNS})
set(plugins_crypto ${CRYPTO_LNS})
set(plugins_io ${IO_LNS})
set(plugins_fs ${FS_LNS})
set(plugins_debug ${DEBUG_LNS})
set(plugins_egg ${EGG_LNS})
set(plugins_lang ${LANG_LNS})
set(plugins_parse ${PARSE_LNS})
configure_file(libr/config.h.in config.h @ONLY)

set(prefix /usr/local)
set(DEBUGGER 1)
set(PREFIX ${prefix})
set(LIBDIR ${prefix}/lib)
set(INCLUDEDIR ${prefix}/include)
set(DATADIR ${prefix}/share)
set(HAVE_LIB_MAGIC 0)
set(USE_LIB_MAGIC 0)
set(HAVE_OPENSSL 0)
set(HAVE_FORK 1)
set(WITH_GPL 1)
if(WIN32)
    set(HAVE_JEMALLOC 0)
else()
    set(HAVE_JEMALLOC 1)
endif()
configure_file(libr/include/r_userconf.h.in r_userconf.h)

string(STRIP ${VERSION_COMMIT} VERSIONCOMMIT)
string(STRIP ${R2VERSION} R2_VERSION)
string(STRIP ${GIT_TAP} R2_GITTAP)
string(STRIP ${GIT_TIP} R2_GITTIP)
string(STRIP ${R2BIRTH} R2_BIRTH)
configure_file(libr/include/r_version.h.in r_version.h)

# Copy missing header
execute_process(COMMAND "python" "-c" "__import__(\"shutil\").copyfile(\"shlr/spp/config.def.h\", \"shlr/spp/config.h\")"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(shlr)
add_subdirectory(shlr/ar)
add_subdirectory(shlr/bochs)
add_subdirectory(shlr/gdb)
add_subdirectory(shlr/grub)
add_subdirectory(shlr/java)
add_subdirectory(shlr/lz4)
add_subdirectory(shlr/qnx)
add_subdirectory(shlr/sdb)
add_subdirectory(shlr/spp)
add_subdirectory(shlr/tcc)
add_subdirectory(shlr/udis86)
add_subdirectory(shlr/windbg)
add_subdirectory(shlr/zip)

add_subdirectory(libr/util)
add_subdirectory(libr/hash)
add_subdirectory(libr/crypto)
add_subdirectory(libr/socket)
add_subdirectory(libr/io)
add_subdirectory(libr/bp)
add_subdirectory(libr/syscall)
add_subdirectory(libr/cons)
add_subdirectory(libr/search)
add_subdirectory(libr/magic)
add_subdirectory(libr/flag)
add_subdirectory(libr/reg)
add_subdirectory(libr/bin)
add_subdirectory(libr/config)
add_subdirectory(libr/parse)
add_subdirectory(libr/lang)
add_subdirectory(libr/asm)
add_subdirectory(libr/anal)
add_subdirectory(binr/rasm2)
add_subdirectory(libr/egg)
add_subdirectory(libr/fs)
add_subdirectory(libr/debug)
add_subdirectory(libr/core)

add_subdirectory(binr/rahash2)
add_subdirectory(binr/rarun2)
add_subdirectory(binr/rabin2)
add_subdirectory(binr/radare2)
add_subdirectory(binr/ragg2)
add_subdirectory(binr/r2agent)
add_subdirectory(binr/radiff2)
add_subdirectory(binr/rafind2)
add_subdirectory(binr/rax2)



