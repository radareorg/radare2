# ####################################################################
# Plugin for XTA cache file - Makefile
#
# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.
#
# Copyright (c) 2020. FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ####################################################################
OBJ_XTAC=../format/xtac/bin_xtac.o

STATIC_OBJ+=${OBJ_XTAC}
TARGET_XTAC=bin_xtac.${EXT_SO}

ALL_TARGETS+=${TARGET_XTAC}

${TARGET_XTAC}: ${OBJ_XTAC}
	${CC} $(call libname,bin_xtac) -shared ${CFLAGS} \
		-o ${TARGET_XTAC} ${OBJ_XTAC} ${LINK} ${LDFLAGS}
