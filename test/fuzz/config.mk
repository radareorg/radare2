
CC= clang-22
# CXX= clang++-22
CFLAGS= -g -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc
CXXFLAGS = -g -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc
LDFLAGS = -fsanitize=fuzzer,address,undefined

