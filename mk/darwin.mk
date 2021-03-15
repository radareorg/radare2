ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)

XCODE_VERSION=$(shell xcodebuild -version|grep Xcode|grep -o "[\.0-9]\+")
XCODE_VERSION_MAJOR=$(word 1, $(subst ., ,$(XCODE_VERSION)))

ifeq ($(COMPILER),ios-sdk)

IOS_VERSION="9.0"
IOS_SDK_VERSION="9.0"

else

ifeq ($(shell test $(XCODE_VERSION_MAJOR) -gt 10;echo $$?),0)
MACOS_VERSION="10.5"
MACOS_SDK_VERSION="10.5"
PARTIALLD+=-arch ${ARCH} -platform_version macos $(MACOS_VERSION) $(MACOS_SDK_VERSION)
endif

endif

endif
