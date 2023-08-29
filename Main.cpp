#include <iostream>
#include "crypsi.h"

int main(int argc, char** argv)
{

    const char* message = "wuriyanto";

    unsigned char* dst_digest;
    unsigned int dst_digets_len;

    if(crypsi_sha512((const unsigned char*) message, strlen(message), &dst_digest, &dst_digets_len) != 0) {
        printf("digest error\n");
        return -1;
    }

    printf("message len: %d\n", dst_digets_len);

    printf("digest result: %s\n", dst_digest);
    
    printf("__cplusplus: %ld\n", __cplusplus);

    delete dst_digest;

    return 0;
}