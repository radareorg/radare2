
CC= clang-18
CXX= clang++-18
CFLAGS= -g -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc
CXXFLAGS = -g -fsanitize=fuzzer,address,undefined -fsanitize-coverage=trace-pc
LDFLAGS = -fsanitize=fuzzer,address,undefined

