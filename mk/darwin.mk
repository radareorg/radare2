ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)

MACOS_VERSION="10.5"
MACOS_SDK_VERSION="10.5"

XCODE_VERSION=$(shell xcodebuild -version|grep Xcode|grep -o "[\.0-9]\+")
XCODE_VERSION_MAJOR=$(word 1, $(subst ., ,$(XCODE_VERSION)))
ifeq ($(XCODE_VERSION_MAJOR),11)
PARTIALLD+=-arch ${ARCH} -platform_version macos $(MACOS_VERSION) $(MACOS_SDK_VERSION)
endif
endif
