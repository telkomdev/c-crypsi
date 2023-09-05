### RSA Verify Digital Signature PSS padding from File example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path, long* length_dst);

int main(int argc, char** argv) {
    printf("hello\n");

    char* signature = "8041cad4c4ac4c96fd54b42dc199f72535c60645a2e6b293018d9973f7241dc92485fdeda54a22dc733d1a9213a3bc6992150ae7ecb567a2f54779c7605a19af48562ef23064246e3db1631fa55e4c318c44d8c9be1b5dd8fe4f3b20d46d1e332f8d55aa845b430bb7d98766acc51c747b77e8e8ba62116ffd817a1c8e9f0636bf11498ea25b52d455c1b8baa72edc710598dba7a5f55b41fe2f3bb1c298a5785e12db5e6658da0d2dc42ab2850ee95c1ddabc8834e71c4588d67c1fd88be42c912bbe8bdd9cbcccdb60cbfe9a9f144df834b34f2d438ddfe7ab9dca1883928e6db200864dd479c396f4023972c2f7fb05049b475aabe1df1d42c8cdf3259881";

    long key_length = 0;
    long burger_stream_length = 0;

    unsigned char* rsa_public_key_char = load_file("./testdata/public_key.key", &key_length);

    // load file
    unsigned char* burger_stream = load_file("./testdata/burger.png", &burger_stream_length);

    int verify_result = crypsi_rsa_verify_sign_pss_md5(rsa_public_key_char, burger_stream, burger_stream_length, signature, strlen(signature));

    printf("rsa verify result: %d\n", verify_result);

    free((void*) rsa_public_key_char);
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