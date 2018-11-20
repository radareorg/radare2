all:
	emcc -z -o cxx.js -I. *.c -s EXPORTED_FUNCTIONS='["_cxx","cwrap"]' -DMY_EMSCRIPTEN=1 -s MODULARIZE=1 -s EXPORT_NAME=Demangle -s "EXTRA_EXPORTED_RUNTIME_METHODS=['cwrap']" 
