LANG=java
LANG_EXT=java
LIBS_PFX=
RADARE_JPKG_DIR=org/radare/radare2
JAVA_INSTALL_DIR=/share/radare2/java
JAVA_INSTALL_JNI=${JAVA_INSTALL_DIR}/jni
JAVA_INSTALL_JNI_SO=${JAVA_INSTALL_JNI}/lib
JAVA_INSTALL_JNI_JAR=${JAVA_INSTALL_JNI}/jar
JAR=jar cf

include ../rules.mk

install:
	echo "Compiling java classes"
	javac ${RADARE_JPKG_DIR}/*.java
	echo "Creating radare2.jar"
	${JAR} radare2.jar ${RADARE_JPKG_DIR}/*.class
	${INSTALL_DIR} ${DESTDIR}${PREFIX}${JAVA_INSTALL_JNI_SO}
	${INSTALL_DIR} ${DESTDIR}${PREFIX}${JAVA_INSTALL_JNI_JAR}
	${INSTALL_DATA} radare2.jar ${DESTDIR}${PREFIX}${JAVA_INSTALL_JNI_JAR}
	echo "Installing so libraries"
	for i in `ls *.so`; do \
		${INSTALL_LIB} $${i} ${DESTDIR}${PREFIX}${JAVA_INSTALL_JNI_SO}/lib$$i; \
	done

purge:
	rm -rf ${DESTDIR}${PREFIX}${JAVA_INSTALL_DIR}
