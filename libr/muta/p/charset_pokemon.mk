OBJ_POKEMON=muta_charset_pokemon.o

R2DEPS+=r_util
# DEPFLAGS=-L../../util -lr_util -L.. -lr_codec

STATIC_OBJ+=${OBJ_POKEMON}
TARGET_POKEMON=muta_charset_pokemon.${EXT_SO}

ALL_TARGETS+=${TARGET_POKEMON}

${TARGET_POKEMON}: ${OBJ_POKEMON}
	${CC} $(call libname,muta_charset_pokemon) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_POKEMON} ${OBJ_POKEMON} $(DEPFLAGS)

