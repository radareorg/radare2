diff --git a/libr/rules.mk b/libr/rules.mk
index a9e47e6c39..4b16ff5ab2 100644
--- a/libr/rules.mk
+++ b/libr/rules.mk
@@ -87,8 +87,8 @@ $(LIBSO): $(EXTRA_TARGETS) ${WFD} ${OBJS} ${SHARED_OBJ}
 	  if [ $$do = 1 ]; then \
 	    [ -n "${SILENT}" ] && \
 	    echo "LD $(LIBSO)" || \
-	    echo "\"${CC_LIB} ${LIBNAME} ${OBJS} ${SHARED_OBJ} ${LINK} ${LDFLAGS}\"" ; \
-	    ${CC_LIB} ${LIBNAME} ${CFLAGS} ${OBJS} ${SHARED_OBJ} ${LINK} ${LDFLAGS} || exit 1; \
+	    echo "\"${CC_LIB} $(LINK) ${LIBNAME} ${OBJS} ${SHARED_OBJ} ${LDFLAGS}\"" ; \
+	    ${CC_LIB} $(LINK) ${LIBNAME} ${CFLAGS} ${OBJS} ${SHARED_OBJ} ${LDFLAGS} || exit 1; \
 	    [ -f "$(LIBR)/stripsyms.sh" ] && sh "$(LIBR)/stripsyms.sh" "${LIBSO}" ${NAME} ; \
 	  break ; \
 	fi ; done
