### Generate RSA Key example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int main(int argc, char** argv) {
    printf("hello\n");

    char* message = "wuriyanto";

    // generate private and public key
    // int modulus_bits = 512;
    int modulus_bits = 2048;
    
    int private_key_len = 0;
    unsigned char *private_key_char;

    int public_key_len = 0;
    unsigned char* public_key_char;

    if (crypsi_rsa_generate_key_pairs(modulus_bits, &private_key_char, &private_key_len, &public_key_char, &public_key_len)) {
        printf("crypsi_rsa_generate_key_pairs error\n");
        exit(1);
    }

    // ------------------------------ write key to file ------------------------------
    // write private key to file
    FILE* private_key_file = fopen("private_key.txt", "w");
    if (private_key_file == NULL) {
        printf("error create private_key_file\n");
        exit(1);
    }
    printf("private_key_len: %d\n", private_key_len);

    for (int i = 0; i < private_key_len; i++) {
        fputc(private_key_char[i], private_key_file);
    }

    fclose(private_key_file);

    // write public key to file
    FILE* public_key_file = fopen("public_key.txt", "w");
    if (public_key_file == NULL) {
        printf("error create public_key_file\n");
        exit(1);
    }

    for (int i = 0; i < public_key_len; i++) {
        fputc(public_key_char[i], public_key_file);
    }

    fclose(public_key_file);

    // ------------------------------ end write key to file ------------------------------

    free((void*) private_key_char);
    free((void*) public_key_char);
    return 0;
}
```