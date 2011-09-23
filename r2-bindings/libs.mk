WIP=1
ifeq (${WIP},1)
LIBS=r_util.${SOEXT} r_bp.${SOEXT} r_asm.${SOEXT} r_diff.${SOEXT}
LIBS+=r_bin.${SOEXT} r_cons.${SOEXT} r_anal.${SOEXT} r_cmd.${SOEXT}
LIBS+=r_debug.${SOEXT} r_config.${SOEXT} r_io.${SOEXT} r_syscall.${SOEXT}
LIBS+=r_search.${SOEXT} r_lib.${SOEXT} r_flags.${SOEXT} r_fs.${SOEXT}
LIBS+=r_parse.${SOEXT} r_lang.${SOEXT} r_core.${SOEXT} r_magic.${SOEXT}
else
LIBS=r_asm.${SOEXT} r_bin.${SOEXT} r_cons.${SOEXT} 
LIBS+=r_debug.${SOEXT} r_syscall.${SOEXT}
LIBS+=r_search.${SOEXT} r_fs.${SOEXT}
LIBS+=r_core.${SOEXT} 
endif
