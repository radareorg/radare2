ifeq ($(OSTYPE),darwin)
ARCH=$(shell uname -m)

XCODE_VERSION=$(shell xcodebuild -version|grep Xcode|grep -o "[\.0-9]\+")
XCODE_VERSION_MAJOR=$(word 1, $(subst ., ,$(XCODE_VERSION)))

ifeq (,$(findstring ios-sdk,$(COMPILER)))

ifeq ($(XCODE_VERSION_MAJOR),)
XCODE_VERSION_MAJOR=0
endif

ifeq ($(shell test $(XCODE_VERSION_MAJOR) -gt 10;echo $$?),0)
MACOSVER?=10.10
PARTIALLD+=-arch ${ARCH} -platform_version macos $(MACOSVER) $(shell xcrun --sdk macosx --show-sdk-version)
endif

endif

endif
