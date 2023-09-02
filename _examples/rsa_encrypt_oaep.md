### RSA Encrypt OAEP example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path);

int main(int argc, char** argv) {
    printf("hello\n");

    char* message = "xxx6253ieie**77ekekekek";

    // load public key
    unsigned char* rsa_public_key_char = load_file("public_key.txt");
    EVP_PKEY* public_key = NULL;
    if (crypsi_rsa_load_public_key(rsa_public_key_char, &public_key) != 0) {
        printf("crypsi_rsa_load_public_key failed\n");
        exit(1);
    }

    free((void*) rsa_public_key_char);

    // load private key
    unsigned char* rsa_private_key_char = load_file("private_key.txt");
    EVP_PKEY* private_key = NULL;
    if (crypsi_rsa_load_private_key(rsa_private_key_char, &private_key) != 0) {
        printf("crypsi_rsa_load_private_key failed\n");
        exit(1);
    }

    free((void*) rsa_private_key_char);
    
    if (private_key == NULL) {
        printf("private_key null\n");
    }

    // encrypt
    unsigned int dst_encrypt_len;
    unsigned char* dst_encrypt;

    // Determine the size of the output
    if (crypsi_rsa_encrypt_oaep_md5(private_key, message, strlen(message), &dst_encrypt, &dst_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_md5 failed\n");
        exit(1);
    }

    printf("rsa encrypt result: %s\n", dst_encrypt);

    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    free((void*) dst_encrypt);

    return 0;
}

char* load_file(char const* path)
{
    char* buffer = 0;
    long length;
    FILE * f = fopen (path, "rb");

    if (f != NULL) {
      fseek (f, 0, SEEK_END);
      length = ftell (f);
      fseek (f, 0, SEEK_SET);
      buffer = (char*) malloc((length+1)*sizeof(char));
      if (buffer) {
        fread(buffer, sizeof(char), length, f);
      }

      fclose(f);
    }
    buffer[length] = 0x0;

    return buffer;
}
```