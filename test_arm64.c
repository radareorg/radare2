#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t a = 0x0000c8f8;
    uint32_t b = 0xf9408b60;
    
    printf("Current: %08x\n", a);
    printf("Expected: %08x\n", b);
    
    uint8_t* p = (uint8_t*)&b;
    printf("Expected little endian: %02x%02x%02x%02x\n", p[0], p[1], p[2], p[3]);
    
    return 0;
}