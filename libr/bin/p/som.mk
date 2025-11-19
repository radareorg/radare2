OBJ_SOM=bin_som.o
OBJ_SOM+=../format/som/som.o

STATIC_OBJ+=${OBJ_SOM}
TARGET_SOM=bin_som.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_SOM}

${TARGET_SOM}: ${OBJ_SOM}
	-${CC} $(call libname,bin_som) ${CFLAGS} ${OBJ_SOM} $(LINK) $(LDFLAGS)
endif
