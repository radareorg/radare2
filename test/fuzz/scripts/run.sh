#!/bin/bash
# Setup the libfuzzer environment and starts fuzzing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Radare2 libFuzzer Quick Start${NC}"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "Makefile" ] || [ ! -f "README.md" ]; then
    echo -e "${RED}Error: Please run this script from test/fuzz directory${NC}"
    exit 1
fi

# Check for clang-18
if ! command -v clang-18 &> /dev/null; then
    echo -e "${YELLOW}Warning: clang-18 not found. You may need to install it or adjust CC variable${NC}"
fi

echo -e "${GREEN}Step 1: Setting up environment...${NC}"
# Set environment variables explicitly for this script
export CC=clang-18
export CXX=clang++-18
export CFLAGS="-g -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc"
export CXXFLAGS="-g -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc"
export LDFLAGS="-fsanitize=fuzzer,address,undefined"

make setup

echo -e "${GREEN}Step 2: Building radare2 with fuzzing support...${NC}"
make build

echo -e "${GREEN}Step 3: Running quick test...${NC}"
make test

echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "To run specific fuzzers:"
echo "  make run-fuzzer TARGET=fuzz_anal"
echo "  make run-fuzzer TARGET=fuzz_bin"
echo "  make run-fuzzer TARGET=fuzz_cmd"
echo "  make run-fuzzer TARGET=fuzz_fs"
echo ""
echo "To see all available targets:"
echo "  make list"
echo ""
echo "For continuous fuzzing:"
echo "  make fuzz-continuous TARGET=fuzz_anal"
echo ""
echo "For help:"
echo "  make help-usage"
