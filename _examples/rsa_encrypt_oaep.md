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

    // encrypt
    unsigned int dst_encrypt_len;
    unsigned char* dst_encrypt;

    if (crypsi_rsa_encrypt_oaep_md5(rsa_public_key_char, message, strlen(message), &dst_encrypt, &dst_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_md5 failed\n");
        exit(1);
    }

    printf("rsa encrypt result: %s\n", dst_encrypt);

    free((void*) dst_encrypt);
    free((void*) rsa_public_key_char);

    return 0;
}

char* load_file(char const* path) {
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