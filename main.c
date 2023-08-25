#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

// https://cpp.hotexamples.com/examples/-/-/RAND_bytes/cpp-rand_bytes-function-examples.html
// https://doctrina.org/Base64-With-OpenSSL-C-API.html
// https://wiki.openssl.org/index.php/EVP_Message_Digests
int main(int argc, char** argv) {
    printf("hello\n");

    // unsigned char rand_buf[16];
    // int rand_res = RAND_bytes(rand_buf, sizeof(rand_buf));
    // if (rand_res != 1) {
    //     printf("RAND_bytes error\n");
    //     return -1;
    // }


    // char* message = "wuriyanto";

    // unsigned char* dst;
    // int dst_len;

    // if(sha384(message, strlen(message), &dst, &dst_len) != 0) {
    //     printf("sha256 error\n");
    //     return -1;
    // }

    // unsigned char* dst_encode;
    // int dst_encode_len;

    // if(hexencode(rand_buf, sizeof(rand_buf), &dst_encode, &dst_encode_len) != 0) {
    //     printf("hexencode error\n");
    //     return -1;
    // }

    // printf("message len: %d\n", dst_encode_len);

    // printf("hex result: %s\n", dst_encode);

    // // free((void*) dst);
    // free((void*) dst_encode);

    // --------------------------------------------------------------------------
    
    // unsigned char* dst_encode;
    // int dst_encode_len;

    // unsigned char* dst_decode;
    // int dst_decode_len;

    // if(hexencode(message, strlen(message), &dst_encode, &dst_encode_len) != 0) {
    //     printf("hexencode error\n");
    //     return -1;
    // }

    // printf("message len: %d\n", dst_encode_len);

    // printf("hex result: %s\n", dst_encode);

    // if(hexdecode(dst_encode, dst_encode_len, &dst_decode, &dst_decode_len) != 0) {
    //     printf("hexdecode error\n");
    //     return -1;
    // }

    // printf("message len: %d\n", dst_decode_len);

    // printf("hex result: %s\n", dst_decode);

    // free((void*) dst_encode);
    // free((void*) dst_decode);

    // -----------------------------------------
    char key[32] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    char* plain_data = "wuriyanto";

    unsigned char* dst;
    int dst_len;

    if(encrypt_with_aes_256cbc(key, plain_data, strlen(plain_data), &dst, &dst_len) != 0) {
        printf("encrypt_with_aes_256cbc error\n");
        return -1;
    }

    printf("hex result: %s\n", dst);

    free((void*) dst);

    return 0;
}