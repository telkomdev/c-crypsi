### RSA Verify Digital Signature PSS padding example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

char* load_file(char const* path);

int main(int argc, char** argv) {
    printf("hello\n");

    char* signature = "6165a4f87f4300f7fef3f57623c1d778bcc0ef308eaa01332b1d28b0a0f61807130b4a63dfbac6f9ff7c8c6232b08a700435830818aeefb648da36d061d09debff32a793da0668af88cdcc06977d1c771e1ce2471162545025b913585152d84b3c895528e942811011f82652b28d83434bdd598ffa9bdd5284f56e2b231a17dde6ebacf19d392509f55e0c221b6daf4699041ab2ef63bcd01c12fcbb5f0063fa03f80bcb76c4bb13e1c38e835bd6e6f4eb4df3e074104e143a16b138b2675d54b019e617a2d4f465232019836af0ecd2e3b19b26b3c88f5235e8f89796d87eb8824feb9de14b70c07d8295c545a9859e56a4eb13e3d3edae3bd72484150d3972";
    char* message = "wuriyanto";

    unsigned char* rsa_public_key_char = load_file("public_key.txt");

    int verify_result = crypsi_rsa_verify_sign_pss_sha256(rsa_public_key_char, message, strlen(message), signature, strlen(signature));

    printf("rsa verify result: %d\n", verify_result);

    free((void*) rsa_public_key_char);

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