### RSA Digital Signature PSS padding example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path);

int main(int argc, char** argv) {
    printf("hello\n");

    char* message = "wuriyanto87e7d";

    // load private key
    unsigned char* rsa_private_key_char = load_file("private_key.txt");

    unsigned int dst_signature_len;
    unsigned char* dst_signature;

    if (crypsi_rsa_sign_pss_sha256(rsa_private_key_char, message, strlen(message), &dst_signature, &dst_signature_len) != 0) {
        printf("crypsi_rsa_sign_pss_sha256 failed\n");
        exit(1);
    }

    printf("rsa signature result: %s\n", dst_signature);

    free((void*) dst_signature);
    free((void*) rsa_private_key_char);

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