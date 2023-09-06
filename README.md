## c-crypsi (Crypto Utility for C and C++)

Custom crypto utility for C/C++ based on `openssl` crypto library to make life easier

[![c-crypsi CI](https://github.com/telkomdev/c-crypsi/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/telkomdev/c-crypsi/actions/workflows/ci.yml)

### Install

Its `header only`, just import to your project
```c
#include "crypsi.h"

int main(int argc, char** argv) {

}
```

### c-crypsi is compatible with each other with the following libraries
- NodeJs https://github.com/telkomdev/crypsi
- Golang https://github.com/telkomdev/go-crypsi
- Python https://github.com/telkomdev/pycrypsi
- C# (.NET) https://github.com/telkomdev/NetCrypsi
- Java/JVM https://github.com/telkomdev/jcrypsi
- Javascript (React and Browser) https://github.com/telkomdev/crypsi.js
- PostgreSQL https://github.com/telkomdev/pgcrypsi
- MySQL https://github.com/telkomdev/crypsi-mysql-udf

### Features
- Asymmetric encryption with RSA ✔️
- Generate RSA private and public key ✔️
- Digital Signature with RSA private and public key using PSS ✔️
- Symmetric encryption with AES (GCM, CBC) ✔️
- Message authentication code with HMAC ✔️
- Generate Hash with Common DIGEST Algorithm ✔️

#### Usage
C
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypsi.h"

int main(int argc, char** argv) {
    printf("hello\n");

    char* message = "wuriyanto";

    unsigned char* dst_digest;
    int dst_digets_len;

    if(crypsi_sha512(message, strlen(message), &dst_digest, &dst_digets_len) != 0) {
        printf("digest error\n");
        return -1;
    }

    printf("message len: %d\n", dst_digets_len);

    printf("digest result: %s\n", dst_digest);

    free((void*) dst_digest);

    return 0;
}
```

C++
```CPP
#include <iostream>
#include "crypsi.h"

int main(int argc, char** argv)
{

    const char* message = "wuriyanto";

    unsigned char* dst_digest;
    unsigned int dst_digets_len;

    if(crypsi_sha512((const unsigned char*) message, strlen(message), &dst_digest, &dst_digets_len) != 0) {
        printf("digest error\n");
        return -1;
    }

    printf("message len: %d\n", dst_digets_len);

    printf("digest result: %s\n", dst_digest);
    
    delete dst_digest;

    return 0;
}
```