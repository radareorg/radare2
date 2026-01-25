OBJ_NAME=bin_gns1

STATIC_OBJ+=${OBJ_GNS1}
OBJ_GNS1+=bin_gns1.o

${TARGET_GNS1}: ${OBJ_GNS1}
	${CC} $(call libname,bin_gns1) -shared ${CFLAGS} \
		-o ${TARGET_GNS1} ${OBJ_GNS1} $(LINK) $(LDFLAGS)
