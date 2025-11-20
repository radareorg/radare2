.PHONY: build configure install amalgamate clean test doc doc-plain doc-themed

BUILD_DIR ?= build
CSS_DIR   ?= ../doxygen-awesome-css

build: configure
	cmake --build $(BUILD_DIR) -j$(nproc)

configure: dependencies/zycore/CMakeLists.txt
	@if ! command -v cmake > /dev/null; then \
		echo >&2 "ERROR: cmake is not installed. Please install it first."; \
	fi
	cmake -B $(BUILD_DIR) -DZYDIS_BUILD_TESTS=ON

install: build
	cmake --install $(BUILD_DIR)

amalgamate:
	assets/amalgamate.py

clean:
	rm -rf $(BUILD_DIR)
	rm -rf doc
	rm -rf amalgamated-dist

test: build
	cd $(BUILD_DIR) && ctest

doc: configure
	cmake --build $(BUILD_DIR) --target ZydisDoc

dependencies/zycore/CMakeLists.txt:
	@if ! command -v git > /dev/null; then \
		echo >&2 -n "ERROR: git is not installed. Please either manually place all"; \
		echo >&2    "dependencies in their respective paths or install git first."; \
		exit 1; \
	fi
	git submodule update --init --recursive
