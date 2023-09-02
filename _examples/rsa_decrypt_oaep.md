### RSA Decrypt OAEP example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path);

int main(int argc, char** argv) {
    printf("hello\n");

    char* message = "215588a0635f0409441240b92ef38cc7dbade2de1ce0f9a366cce32649cc7650d92b0932346615e8efb03276db46a1c964e45161978bcd6095ef98a7bc6f26329fd48a9a83d226ad039e8552b4ec0ea642b9cf7952314592264622471cfbde5057317c0fedfa412c7ec09a4883f0b7084db95298f7bad7d95a23990379046d9810255a42a00b710770a71cfc66b9ec1803f2df5a3c7551b594531215a75f9099980918374cb9d534074173a3fd2e5cd199264b7732452300c61e1589b3d6f3c26255ad47c2f8a521ba238d90e3a2348384be2de17c3a54abb55fe59509d2d1a29c922fb55b063651502e1e5cb272f40096bf6dd49c6a885bcbff938fe0c2ab84";

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

    // decrypt
    unsigned int dst_decrypt_len;
    unsigned char* dst_decrypt;

    // Determine the size of the output
    if (crypsi_rsa_decrypt_oaep_sha256(private_key, message, strlen(message), &dst_decrypt, &dst_decrypt_len) != 0) {
        printf("crypsi_rsa_decrypt_oaep_sha256 failed\n");
        exit(1);
    }

    printf("rsa decrypt result: %s\n", dst_decrypt);

    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    free((void*) dst_decrypt);

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