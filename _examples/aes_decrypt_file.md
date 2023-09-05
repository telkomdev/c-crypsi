### AES Decrypt File example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int write_file(char const* path, unsigned char* buffer, int buffer_size);
char* load_file(char const* path, long* length_dst);

int main(int argc, char** argv) {

    unsigned char key_128[17] = "abc$#128djdyAgbj";
    key_128[sizeof(key_128)-1] = 0x0; 

    unsigned char key_192[25] = "abc$#128djdyAgbjau&YAnmc";
    key_192[sizeof(key_192)-1] = 0x0; 

    unsigned char key_256[33] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    key_256[sizeof(key_256)-1] = 0x0; 

    long burger_encrypted_stream_length = 0;

    // load file
    unsigned char* burger_encrypted_stream = load_file("./testdata/burger_aes_128_gcm_encrypted.bin", &burger_encrypted_stream_length);

    unsigned char* dst;
    int dst_len;

    if(crypsi_aes_128_gcm_decrypt(key_128, burger_encrypted_stream, burger_encrypted_stream_length, &dst, &dst_len) != 0) {
        printf("decrypt with aes error\n");
        free((void*) dst);
        free((void*) burger_encrypted_stream);
        return -1;
    }

    if (write_file("./testdata/burger_out.png", dst, dst_len) != 0) {
      printf("writing decrypted data to file error\n");
      free((void*) dst);
      free((void*) burger_encrypted_stream);
      return -1;
    }

    printf("decrypted data written to the file\n");

    free((void*) dst);
    free((void*) burger_encrypted_stream);

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

int write_file(char const* path, unsigned char* buffer, int buffer_size) {
    long length;
    FILE * f = fopen (path, "wb");

    if (f != NULL) {
      if (buffer) {
        fwrite(buffer, sizeof(char), buffer_size, f);
      }

      fclose(f);
      return 0;
    }

    return -1;
}
```