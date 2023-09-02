### HMAC example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int main(int argc, char** argv) {
    unsigned char key_256[33] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    key_256[sizeof(key_256)-1] = 0x0; 

    char* message = "wuriyanto";

    unsigned char* dst_digest_hmac;
    int dst_digets_len_hmac;

    if(crypsi_hmac_sha256(key_256, message, strlen(message), &dst_digest_hmac, &dst_digets_len_hmac) != 0) {
        printf("hmac error\n");
        return -1;
    }

    printf("hmac message len: %d\n", dst_digets_len_hmac);

    printf("hmac result: %s\n", dst_digest_hmac);

    free((void*) dst_digest_hmac);

    return 0;
}
```