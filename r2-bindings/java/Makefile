LANG=java
LANG_EXT=java
LIBS_PFX=
R2_JAVA_DIR=org/radare/radare2
JAVA_INSTALL_DIR=${DESTDIR}${DATADIR}/radare2/java
JAVA_INSTALL_JNI=${JAVA_INSTALL_DIR}/jni
JAVA_INSTALL_JNI_SO=${JAVA_INSTALL_JNI}/lib
JAVA_INSTALL_JNI_JAR=${JAVA_INSTALL_JNI}/jar
JAR=jar cf

include ../rules.mk

install:
	echo "Compiling java classes"
	javac ${R2_JAVA_DIR}/*.java
	echo "Creating radare2.jar"
	${JAR} radare2.jar ${R2_JAVA_DIR}/*.class
	${INSTALL_DIR} ${JAVA_INSTALL_JNI_SO}
	${INSTALL_DIR} ${JAVA_INSTALL_JNI_JAR}
	${INSTALL_DATA} radare2.jar ${JAVA_INSTALL_JNI_JAR}
	echo "Installing so libraries"
	for i in `ls *.${SOEXT}`; do \
		${INSTALL_LIB} $${i} ${JAVA_INSTALL_JNI_SO}/lib$$i; \
	done

purge:
	rm -rf ${JAVA_INSTALL_DIR}
