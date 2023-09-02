### Message Digest example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int main(int argc, char** argv) {
    char* message = "wuriyanto";

    unsigned char* dst_digest;
    int dst_digets_len;

    if(crypsi_sha512(message, strlen(message), &dst_digest, &dst_digets_len) != 0) {
        printf("digest error\n");
        return -1;
    }

    printf("message len: %d\n", dst_digets_len);

    printf("digest result: %s\n", dst_digest); // 5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206

    free((void*) dst_digest);

    return 0;
}
```