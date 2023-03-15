typedef unsigned char (*GET_BYTE)  (void* userPtr);
typedef void          (*SEND_BYTES)(const unsigned char*, unsigned int, void* userPtr);
int unlz4Block_userPtr (GET_BYTE getByte, SEND_BYTES sendBytes, void *userPtr, unsigned int blockSize, unsigned int *position, unsigned char *hist);
