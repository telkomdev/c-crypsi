### AES Encrypt Decrypt example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int main(int argc, char** argv) {
    char* message = "wuriyanto";

    unsigned char key_128[17] = "abc$#128djdyAgbj";
    key_128[sizeof(key_128)-1] = 0x0; 

    unsigned char key_192[25] = "abc$#128djdyAgbjau&YAnmc";
    key_192[sizeof(key_192)-1] = 0x0; 

    unsigned char key_256[33] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    key_256[sizeof(key_256)-1] = 0x0; 

    unsigned char* plain_data = "Hello World 😋";
    printf("plain_data: %ld\n", strlen(plain_data));

    unsigned char* dst;
    int dst_len;

    if(crypsi_aes_128_gcm_encrypt(key_128, plain_data, strlen(plain_data), &dst, &dst_len) != 0) {
        printf("encrypt with aes error\n");
        return -1;
    }

    printf("encrypt result: %s\n", dst);
    printf("encrypt result len: %d\n", dst_len);

    printf("-----------------------------------------\n");

    unsigned char* dst_decrypt;
    int dst_decrypt_len;

    if(crypsi_aes_128_gcm_decrypt(key_128, dst, dst_len, &dst_decrypt, &dst_decrypt_len) != 0) {
        printf("decrypt with aes error\n");
        return -1;
    }

    printf("decrypt result: %s\n", dst_decrypt);
    printf("decrypt result len: %ld\n", strlen(dst_decrypt));
    printf("decrypt result len: %d\n", dst_decrypt_len);

    
    free((void*) dst_decrypt);
    free((void*) dst);


    return 0;
}
```