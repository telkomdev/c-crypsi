### Message Digest File Stream example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path, long* length_dst);

int main(int argc, char** argv) {
    char* message = "wuriyanto";

    long burger_stream_length = 0;

    // load file
    unsigned char* burger_stream = load_file("./testdata/burger.png", &burger_stream_length);

    unsigned char* dst_digest;
    int dst_digets_len;

    if(crypsi_sha256(burger_stream, burger_stream_length, &dst_digest, &dst_digets_len) != 0) {
        printf("digest error\n");
        return -1;
    }

    printf("message len: %d\n", dst_digets_len);

    printf("digest result: %s\n", dst_digest); // 6519949bc95c5f8bce78e08fffd0a8b0c7fb34514a565a09751ba58aa7be77d288a1fe17704a5b961b02f25e4186a463bd50b7ab86422d1c35fc5fdd1208c4a4

    free((void*) dst_digest);
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