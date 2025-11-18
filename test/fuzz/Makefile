include config.mk

R2_ROOT = ../..
BUILD_DIR = $(R2_ROOT)/build
FUZZ_DIR = $(BUILD_DIR)/test/fuzz
CORPUS_DIR = corpus

FUZZER_OPTS=-detect_leaks=0
# Useful for scripts or types parser
# FUZZER_OPTS+=-only_ascii=1
FUZZER_OPTS+=-timeout=10
FUZZER_OPTS+=--mutate_depth=1 -len_control=50 -reduce_inputs=0 -keep_seed=1 -prefer_small=0

# Fuzzing targets
FUZZ_TARGETS = fuzz_anal fuzz_bin fuzz_bin2 fuzz_fs fuzz_dwarf fuzz_bin_demangle \
               fuzz_ia fuzz_cmd fuzz_pdb_parse fuzz_pkcs7_parse fuzz_protobuf_decode \
               fuzz_punycode_decode fuzz_run_parseline fuzz_types_parser fuzz_x509_parse

all: usage

do: setup build

setup:
	$(MAKE) config
	@echo "Checking compiler availability..."
	@which $(CC) || (echo "Error: $(CC) not found in PATH" && exit 1)
	@which $(CXX) || (echo "Error: $(CXX) not found in PATH" && exit 1)
	@echo ""
	@echo "Testing compiler version..."
	@$(CC) --version | head -1
	@echo ""
	@echo "Testing fuzzer support..."
	@echo '#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size){return 0;}' | $(CC) -fsanitize=fuzzer -x c - -o /tmp/test_fuzzer && echo "✓ Fuzzer support detected" && rm -f /tmp/test_fuzzer || (echo "✗ No fuzzer support" && exit 1)
	@echo ""
	@echo "Testing coverage support..."
	@echo 'int main(){return 0;}' | $(CC) -fsanitize-coverage=trace-pc -c -x c - -o /tmp/test_cov.o && echo "✓ Coverage support detected" && rm -f /tmp/test_cov.o || (echo "✗ No coverage support" && exit 1)
	@echo ""
	@echo "All checks passed!"

# Build with meson (recommended method)
build:
	@echo "Building radare2 with fuzzing support..."
	@echo "Using compiler: $(CC)"
	@echo "Checking compiler availability..."
	@which $(CC) > /dev/null || (echo "Error: $(CC) not found. Please install clang-18 or set CC variable." && exit 1)
	@echo "Testing compiler supports fuzzer..."
	@echo '#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size){return 0;}' | $(CC) -fsanitize=fuzzer -x c - -o /dev/null || (echo "Error: $(CC) doesn't support fuzzer. Please install clang-18 or newer." && exit 1)
	@echo "Building radare2 with libFuzzer support (via meson option)..."
	cd $(R2_ROOT) && \
		unset CFLAGS && \
		unset CXXFLAGS && \
		unset LDFLAGS && \
		export CC=$(CC) && \
		export CXX=$(CXX) && \
		python3 ./sys/meson.py --fuzz
	@echo "Build completed. Fuzzing binaries are in $(FUZZ_DIR)/"

run-fuzzer run:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make run-fuzzer TARGET=<fuzzer_name>"; \
		echo "Available targets:"; \
		$(MAKE) list ; \
		exit 1; \
	fi
	@echo "Running $(TARGET)..."
	@mkdir -p $(CORPUS_DIR)/$(TARGET)
	@ASAN_OPTIONS=detect_leaks=0 R2_DEBUG_ASSERT=1 $(FUZZ_DIR)/$(TARGET) $(FUZZER_OPTS) $(EXTRA_FUZZER_OPTS) $(CORPUS_DIR)/$(TARGET)

# Build custom mutator version
build-custom:
	@echo "Building custom mutator for $(TARGET)..."
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make build-custom TARGET=<fuzzer_name>"; \
		exit 1; \
	fi
	@mkdir -p $(FUZZ_DIR)
	@fuzz_name=$$(echo "$(TARGET)" | sed 's/^fuzz_//'); \
	if [ -f "fuzz_$${fuzz_name}_custom.c" ]; then \
		echo "Building custom mutator for $$fuzz_name..."; \
		$(CC) $(CFLAGS) \
			-I$(BUILD_DIR) \
			-I$(R2_ROOT)/libr/include \
			-I$(R2_ROOT)/shlr \
			-I$(R2_ROOT)/shlr/capstone/include \
			-I$(R2_ROOT)/subprojects/sdb/src \
			-I$(R2_ROOT)/subprojects/sdb/include \
			-D__LIBR_CORE__ -D__LIBR_BIN__ -D__LIBR_IO__ -D__LIBR_ANAL__ -D__LIBR_UTIL__ -D__LIBR_CONS__ -D__LIBR_SOCKET__ \
			fuzz_$${fuzz_name}_custom.c \
			$(BUILD_DIR)/libr/core/libr_core.a \
			$(BUILD_DIR)/libr/bin/libr_bin.a \
			$(BUILD_DIR)/libr/io/libr_io.a \
			$(BUILD_DIR)/libr/anal/libr_anal.a \
			$(BUILD_DIR)/libr/util/libr_util.a \
			$(BUILD_DIR)/libr/cons/libr_cons.a \
			$(BUILD_DIR)/libr/socket/libr_socket.a \
			$(BUILD_DIR)/libr/config/libr_config.a \
			$(BUILD_DIR)/libr/egg/libr_egg.a \
			$(BUILD_DIR)/libr/esil/libr_esil.a \
			$(BUILD_DIR)/libr/flag/libr_flag.a \
			$(BUILD_DIR)/libr/fs/libr_fs.a \
			$(BUILD_DIR)/libr/bp/libr_bp.a \
			$(BUILD_DIR)/libr/debug/libr_debug.a \
			$(BUILD_DIR)/libr/lang/libr_lang.a \
			$(BUILD_DIR)/libr/magic/libr_magic.a \
			$(BUILD_DIR)/libr/regex/libr_regex.a \
			$(BUILD_DIR)/libr/search/libr_search.a \
			$(BUILD_DIR)/libr/syscall/libr_syscall.a \
			$(BUILD_DIR)/libr/db/libr_db.a \
			$(BUILD_DIR)/libr/hash/libr_hash.a \
			$(BUILD_DIR)/libr/crypto/libr_crypto.a \
			$(BUILD_DIR)/libr/arch/libr_arch.a \
			$(BUILD_DIR)/subprojects/sdb/liblibsdb_static.a \
			$(BUILD_DIR)/shlr/zip/libr2zip.a \
			$(BUILD_DIR)/shlr/zip/libr2zlib.a \
			$(BUILD_DIR)/shlr/capstone/libcapstone-static.a \
			$(BUILD_DIR)/subprojects/qjs/libquickjs.a \
			-lm -lpthread -ldl \
			$(LDFLAGS) -o $(FUZZ_DIR)/$(TARGET)_custom || echo "Failed to build $(TARGET)_custom"; \
	else \
		echo "No custom mutator found for $(TARGET)"; \
	fi

# Run with custom mutator
run-custom:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make run-custom TARGET=<fuzzer_name>"; \
		exit 1; \
	fi
	@if [ ! -f "$(FUZZ_DIR)/$(TARGET)_custom" ]; then \
		echo "Custom mutator not built. Run 'make build-custom TARGET=$(TARGET)' first."; \
		exit 1; \
	fi
	@echo "Running $(TARGET) with custom mutator..."
	@mkdir -p $(CORPUS_DIR)/$(TARGET)
	@corpus_source=""; \
	if [ "$(TARGET)" = "fuzz_types_parser" ] && [ -d "types_parser_corpus" ]; then \
		corpus_source="types_parser_corpus"; \
	elif [ -d "$(TARGET)_corpus" ]; then \
		corpus_source="$(TARGET)_corpus"; \
	fi; \
	if [ -n "$$corpus_source" ]; then \
		echo "Corpus source directory: $$corpus_source"; \
		echo "Copying corpus files from $$corpus_source to $(CORPUS_DIR)/$(TARGET)..."; \
		cp $$corpus_source/* $(CORPUS_DIR)/$(TARGET)/ 2>/dev/null || true; \
	else \
		echo "No corpus source directory found, starting with empty corpus"; \
	fi
	@ASAN_OPTIONS=detect_leaks=0 $(FUZZ_DIR)/$(TARGET)_custom $(FUZZER_OPTS) $(EXTRA_FUZZER_OPTS) $(CORPUS_DIR)/$(TARGET)

# Generate completely new C constructions
generate-new:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make generate-new TARGET=<fuzzer_name> COUNT=<number>"; \
		exit 1; \
	fi
	@echo "Generating new C constructions for $(TARGET)..."
	@mkdir -p $(CORPUS_DIR)/$(TARGET)
	@corpus_source=""; \
	if [ "$(TARGET)" = "fuzz_types_parser" ] && [ -d "types_parser_corpus" ]; then \
		corpus_source="types_parser_corpus"; \
	elif [ -d "$(TARGET)_corpus" ]; then \
		corpus_source="$(TARGET)_corpus"; \
	fi; \
	if [ -n "$$corpus_source" ]; then \
		echo "Copying original corpus from $$corpus_source..."; \
		cp $$corpus_source/* $(CORPUS_DIR)/$(TARGET)/ 2>/dev/null || true; \
	fi; \
	count=$${COUNT:-100}; \
	echo "Generating $$count new C constructions..."; \
	for i in $$(seq 1 $$count); do \
		python3 scripts/mutate_c.py /dev/null "$(CORPUS_DIR)/$(TARGET)/new_construction_$$i.h" --generate-new; \
	done; \
	echo "New construction generation complete."

# Generate C-aware mutations
generate-mutations:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make generate-mutations TARGET=<fuzzer_name> COUNT=<number>"; \
		exit 1; \
	fi
	@echo "Generating C-aware mutations for $(TARGET)..."
	@mkdir -p $(CORPUS_DIR)/$(TARGET)
	@corpus_source=""; \
	if [ "$(TARGET)" = "fuzz_types_parser" ] && [ -d "types_parser_corpus" ]; then \
		corpus_source="types_parser_corpus"; \
	elif [ -d "$(TARGET)_corpus" ]; then \
		corpus_source="$(TARGET)_corpus"; \
	fi; \
	if [ -n "$$corpus_source" ]; then \
		echo "Copying original corpus from $$corpus_source..."; \
		cp $$corpus_source/* $(CORPUS_DIR)/$(TARGET)/ 2>/dev/null || true; \
		count=$${COUNT:-50}; \
		echo "Generating $$count C-aware mutations..."; \
		for file in $$corpus_source/*.h; do \
			if [ -f "$$file" ]; then \
				basename=$$(basename "$$file"); \
				for i in $$(seq 1 $$count); do \
					if [ $$((i % 3)) -eq 0 ]; then \
						python3 scripts/mutate_c.py "$$file" "$(CORPUS_DIR)/$(TARGET)/mut_$${basename}_$$i" --generate-new; \
					else \
						python3 scripts/mutate_c.py "$$file" "$(CORPUS_DIR)/$(TARGET)/mut_$${basename}_$$i"; \
					fi; \
				done; \
			fi; \
		done; \
		echo "Mutation generation complete."; \
	else \
		echo "No corpus source directory found"; \
		exit 1; \
	fi

# Run corpus only (no mutations)
run-corpus:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make run-corpus TARGET=<fuzzer_name>"; \
		exit 1; \
	fi
	@echo "Running $(TARGET) with corpus only (no mutations)..."
	@mkdir -p $(CORPUS_DIR)/$(TARGET)
	@corpus_source=""; \
	if [ "$(TARGET)" = "fuzz_types_parser" ] && [ -d "types_parser_corpus" ]; then \
		corpus_source="types_parser_corpus"; \
	elif [ -d "$(TARGET)_corpus" ]; then \
		corpus_source="$(TARGET)_corpus"; \
	fi; \
	if [ -n "$$corpus_source" ]; then \
		echo "Corpus source directory: $$corpus_source"; \
		echo "Copying corpus files from $$corpus_source to $(CORPUS_DIR)/$(TARGET)..."; \
		cp $$corpus_source/* $(CORPUS_DIR)/$(TARGET)/ 2>/dev/null || true; \
	else \
		echo "No corpus source directory found"; \
		exit 1; \
	fi
	@ASAN_OPTIONS=detect_leaks=0 $(FUZZ_DIR)/$(TARGET) $(FUZZER_OPTS) -runs=0 $(CORPUS_DIR)/$(TARGET)

help:
	$(MAKE) list
	@$(FUZZ_DIR)/$(TARGET) -help=1

# Replay crashes
replay:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make replay TARGET=<fuzzer_name> CRASH_FILES=\"crash-*\""; \
		exit 1; \
	fi
	@if [ -z "$(CRASH_FILES)" ]; then \
		echo "Usage: make replay TARGET=<fuzzer_name> CRASH_FILES=\"crash-*\""; \
		exit 1; \
	fi
	@echo "Replaying crashes for $(TARGET)..."
	@$(FUZZ_DIR)/$(TARGET) $(CRASH_FILES)

list:
	@cd $(FUZZ_DIR) && ls fuzz_* | grep fuzz | grep -v '\.' 2>/dev/null

clean:
	cd $(R2_ROOT) && rm -rf build
	rm -rf $(CORPUS_DIR)_*
	rm -rf $(CORPUS_DIR)

mrproper distclean: clean
	cd $(R2_ROOT) && rm -rf shlr/capstone

test:
	@echo "Running quick test with fuzz_anal..."
	$(MAKE) run-fuzzer TARGET=fuzz_anal FUZZER_OPTS="-runs=1000 -timeout=1"

# Continuous fuzzing
fuzz-continuous:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make fuzz-continuous TARGET=<fuzzer_name>"; \
		exit 1; \
	fi
	@echo "Starting continuous fuzzing for $(TARGET)..."
	@mkdir -p $(CORPUS_DIR)/$(TARGET)
	@corpus_source=""; \
	if [ "$(TARGET)" = "fuzz_types_parser" ] && [ -d "types_parser_corpus" ]; then \
		corpus_source="types_parser_corpus"; \
	elif [ -d "$(TARGET)_corpus" ]; then \
		corpus_source="$(TARGET)_corpus"; \
	fi; \
	if [ -n "$$corpus_source" ]; then \
		echo "Corpus source directory: $$corpus_source"; \
		echo "Copying corpus files from $$corpus_source to $(CORPUS_DIR)/$(TARGET)..."; \
		cp $$corpus_source/* $(CORPUS_DIR)/$(TARGET)/ 2>/dev/null || true; \
	else \
		echo "No corpus source directory found, starting with empty corpus"; \
	fi
	@while true; do \
		echo "Running fuzzing session..."; \
		$(FUZZ_DIR)/$(TARGET) -max_total_time=300 -jobs=4 $(CORPUS_DIR)/$(TARGET); \
		echo "Session completed. Restarting in 10 seconds..."; \
		sleep 10; \
	done

env config:
	@echo "export CC='$(CC)'"
	@echo "export CXX='$(CXX)'"
	@echo "export CFLAGS='$(CFLAGS)'"
	@echo "export CXXFLAGS='$(CXXFLAGS)'"
	@echo "export LDFLAGS='$(LDFLAGS)'"
	@echo "# Build Directory: $(BUILD_DIR)"
	@echo "# Fuzz Directory: $(FUZZ_DIR)"

# Help target
usage:
	@echo "Radare2 libFuzzer Makefile"
	@echo ""
	@echo "Basic usage:"
	@echo "  make setup           - Check compiler from config.mk"
	@echo "  make build           - Build with meson (recommended)"
	@echo "  make build-simple    - Build radare2 normally, then fuzzing targets"
	@echo "  make build-configure - Build with configure+make"
	@echo "  make run-fuzzer TARGET=<name> - Run specific fuzzer"
	@echo "  make run-corpus TARGET=<name> - Run corpus only (no mutations)"
	@echo "  make generate-mutations TARGET=<name> COUNT=<n> - Generate C-aware mutations"
	@echo "  make generate-new TARGET=<name> COUNT=<n> - Generate new C constructions"
	@echo "  make list            - List available fuzzers"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make test            - Quick test build and run"
	@echo ""
	@echo "Examples:"
	@echo "  make setup && make build"
	@echo "  make run-fuzzer TARGET=fuzz_run_parseline"
	@echo "  make run-fuzzer TARGET=fuzz_run_parseline EXTRA_FUZZER_OPTS=\"-runs=10000\""
	@echo "  make run-corpus TARGET=fuzz_types_parser"
	@echo "  make generate-mutations TARGET=fuzz_types_parser COUNT=50"
	@echo "  make generate-new TARGET=fuzz_types_parser COUNT=100"
	@echo "  make replay TARGET=fuzz_run_parseline CRASH_FILES=\"crash-*\""
	@echo "  make fuzz-continuous TARGET=fuzz_run_parseline"
	@echo ""
	@echo "Configuration:"
	@echo "  make config          - Show current configuration"

.PHONY: all setup build clean run help do run-fuzzer run-corpus list test
