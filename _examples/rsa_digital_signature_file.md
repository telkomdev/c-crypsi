### RSA Create Digital Signature PSS padding from File example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path, long* length_dst);

int main(int argc, char** argv) {
    printf("hello\n");

    long key_length = 0;
    long burger_stream_length = 0;
    // load private key
    unsigned char* rsa_private_key_char = load_file("./testdata/private_key.txt", &key_length);

    // load file
    unsigned char* burger_stream = load_file("./testdata/burger.png", &burger_stream_length);

    unsigned int dst_signature_len;
    unsigned char* dst_signature;

    if (crypsi_rsa_sign_pss_sha256(rsa_private_key_char, burger_stream, burger_stream_length, &dst_signature, &dst_signature_len) != 0) {
        printf("crypsi_rsa_sign_pss_sha256 failed\n");
        exit(1);
    }

    printf("rsa signature result: %s\n", dst_signature);

    free((void*) dst_signature);
    free((void*) rsa_private_key_char);
    free((void*) burger_stream);

    return 0;
}

char* load_file(char const* path, long* length_dst) {
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
    *length_dst = length;

    return buffer;
}
```