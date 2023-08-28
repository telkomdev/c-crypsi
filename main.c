#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int main(int argc, char** argv) {
    printf("hello\n");

    char* message = "wuriyanto";

    unsigned char* dst_digest;
    int dst_digets_len;

    if(crypsi_sha512(message, strlen(message), &dst_digest, &dst_digets_len) != 0) {
        printf("digest error\n");
        return -1;
    }

    printf("message len: %d\n", dst_digets_len);

    printf("digest result: %s\n", dst_digest);

    free((void*) dst_digest);

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
    unsigned char key_128[17] = "abc$#128djdyAgbj";
    key_128[sizeof(key_128)-1] = 0x0; 

    unsigned char key_192[25] = "abc$#128djdyAgbjau&YAnmc";
    key_192[sizeof(key_192)-1] = 0x0; 

    unsigned char key_256[33] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    key_256[sizeof(key_256)-1] = 0x0; 

    unsigned char* plain_data = "wuriyanto";

    unsigned char* dst;
    int dst_len;

    if(crypsi_aes_192_cbc_encrypt(key_192, plain_data, strlen(plain_data), &dst, &dst_len) != 0) {
        printf("encrypt with aes error\n");
        return -1;
    }

    printf("encrypt result: %s\n", dst);
    printf("encrypt result len: %d\n", dst_len);

    printf("-----------------------------------------\n");

    unsigned char* dst_decrypt;
    int dst_decrypt_len;

    if(crypsi_aes_192_cbc_decrypt(key_192, "6417737cf9e0a929a6b12d3d79d4ecad0186609f62adb46fef73900400ff5c6b", strlen("6417737cf9e0a929a6b12d3d79d4ecad0186609f62adb46fef73900400ff5c6b"), &dst_decrypt, &dst_decrypt_len) != 0) {
        printf("decrypt with aes error\n");
        return -1;
    }

    printf("decrypt result: %s\n", dst_decrypt);
    printf("decrypt result len: %ld\n", strlen(dst_decrypt));
    printf("decrypt result len: %d\n", dst_decrypt_len);

    
    free((void*) dst_decrypt);
    free((void*) dst);

    // hmac --------------------------------------------
    char* message_hmac = "wuriyanto";

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