cd ..
make
cd t
make clean
make
cp /bin/ls l
./data_resize l .data `rax 0x9000`
./l
