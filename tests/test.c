#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crypsi.h"

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

char* load_file_with_size(char const* path, long* length_dst) {
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

void test_digest() {
    printf("test Digest\n");

    char* data = "wuriyanto";

    // ------------------- MD5 test -------------------
    printf("test MD5 Digest\n");
    char* md5_expected = "60e1bc04fa194a343b50ce67f4afcff8";
    unsigned char* md5_dst_digest;
    int md5_dst_digets_len;

    if(crypsi_md5(data, strlen(data), &md5_dst_digest, &md5_dst_digets_len) != 0) {
        printf("md5 digest error\n");
        free((void*) md5_dst_digest);
        exit(-1);
    }

    if (strcmp(md5_expected, md5_dst_digest) != 0) {
        printf("md5 digest test failed\n");
        free((void*) md5_dst_digest);
        exit(-1);
    }

    free((void*) md5_dst_digest);
    printf("\n");
    // ------------------- MD5 test end-------------------

    // ------------------- SHA1 test -------------------
    printf("test SHA1 Digest\n");
    char* sha1_expected = "afd2bd72af0c346a2ab14d50746835d3ccd1dd5f";
    unsigned char* sha1_dst_digest;
    int sha1_dst_digets_len;

    if(crypsi_sha1(data, strlen(data), &sha1_dst_digest, &sha1_dst_digets_len) != 0) {
        printf("sha1 digest error\n");
        free((void*) sha1_dst_digest);
        exit(-1);
    }

    if (strcmp(sha1_expected, sha1_dst_digest) != 0) {
        printf("sha1 digest test failed\n");
        free((void*) sha1_dst_digest);
        exit(-1);
    }

    free((void*) sha1_dst_digest);
    printf("\n");
    // ------------------- SHA1 test end-------------------

    // ------------------- SHA256 test -------------------
    printf("test SHA256 Digest\n");
    char* sha256_expected = "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87";
    unsigned char* sha256_dst_digest;
    int sha256_dst_digets_len;

    if(crypsi_sha256(data, strlen(data), &sha256_dst_digest, &sha256_dst_digets_len) != 0) {
        printf("sha256 digest error\n");
        free((void*) sha256_dst_digest);
        exit(-1);
    }

    if (strcmp(sha256_expected, sha256_dst_digest) != 0) {
        printf("sha256 digest test failed\n");
        free((void*) sha256_dst_digest);
        exit(-1);
    }

    free((void*) sha256_dst_digest);
    printf("\n");
    // ------------------- SHA256 test end-------------------

    // ------------------- SHA384 test -------------------
    printf("test SHA384 Digest\n");
    char* sha384_expected = "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1";
    unsigned char* sha384_dst_digest;
    int sha384_dst_digets_len;

    if(crypsi_sha384(data, strlen(data), &sha384_dst_digest, &sha384_dst_digets_len) != 0) {
        printf("sha384 digest error\n");
        free((void*) sha384_dst_digest);
        exit(-1);
    }

    if (strcmp(sha384_expected, sha384_dst_digest) != 0) {
        printf("sha384 digest test failed\n");
        free((void*) sha384_dst_digest);
        exit(-1);
    }

    free((void*) sha384_dst_digest);
    printf("\n");
    // ------------------- SHA384 test end-------------------

    // ------------------- SHA512 test -------------------
    printf("test SHA512 Digest\n");
    char* sha512_expected = "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206";
    unsigned char* sha512_dst_digest;
    int sha512_dst_digets_len;

    if(crypsi_sha512(data, strlen(data), &sha512_dst_digest, &sha512_dst_digets_len) != 0) {
        printf("sha512 digest error\n");
        free((void*) sha512_dst_digest);
        exit(-1);
    }

    if (strcmp(sha512_expected, sha512_dst_digest) != 0) {
        printf("sha512 digest test failed\n");
        free((void*) sha512_dst_digest);
        exit(-1);
    }

    free((void*) sha512_dst_digest);
    printf("\n");
    // ------------------- SHA512 test end-------------------
}

void test_hmac() {
    printf("test HMAC\n");
    
    char* data = "wuriyanto";
    unsigned char key_256[33] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    key_256[sizeof(key_256)-1] = 0x0; 

        // ------------------- MD5 test -------------------
    printf("test HMAC MD5 Digest\n");
    char* md5_expected = "d213b2e973c1a5d704255518af6d073c";
    unsigned char* md5_dst_digest;
    int md5_dst_digets_len;

    if(crypsi_hmac_md5(key_256, data, strlen(data), &md5_dst_digest, &md5_dst_digets_len) != 0) {
        printf("hmac md5 digest error\n");
        free((void*) md5_dst_digest);
        exit(-1);
    }

    if (strcmp(md5_expected, md5_dst_digest) != 0) {
        printf("hmac md5 digest test failed\n");
        free((void*) md5_dst_digest);
        exit(-1);
    }

    free((void*) md5_dst_digest);
    printf("\n");
    // ------------------- MD5 test end-------------------

    // ------------------- SHA1 test -------------------
    printf("test HMAC SHA1 Digest\n");
    char* sha1_expected = "69fa82ae1f1398e6e570a4780df908adad3998df";
    unsigned char* sha1_dst_digest;
    int sha1_dst_digets_len;

    if(crypsi_hmac_sha1(key_256, data, strlen(data), &sha1_dst_digest, &sha1_dst_digets_len) != 0) {
        printf("hmac sha1 digest error\n");
        free((void*) sha1_dst_digest);
        exit(-1);
    }

    if (strcmp(sha1_expected, sha1_dst_digest) != 0) {
        printf("hmac sha1 digest test failed\n");
        free((void*) sha1_dst_digest);
        exit(-1);
    }

    free((void*) sha1_dst_digest);
    printf("\n");
    // ------------------- SHA1 test end-------------------

    // ------------------- SHA256 test -------------------
    printf("test HMAC SHA256 Digest\n");
    char* sha256_expected = "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240";
    unsigned char* sha256_dst_digest;
    int sha256_dst_digets_len;

    if(crypsi_hmac_sha256(key_256, data, strlen(data), &sha256_dst_digest, &sha256_dst_digets_len) != 0) {
        printf("hmac sha256 digest error\n");
        free((void*) sha256_dst_digest);
        exit(-1);
    }

    if (strcmp(sha256_expected, sha256_dst_digest) != 0) {
        printf("hmac sha256 digest test failed\n");
        free((void*) sha256_dst_digest);
        exit(-1);
    }

    free((void*) sha256_dst_digest);
    printf("\n");
    // ------------------- SHA256 test end-------------------

    // ------------------- SHA384 test -------------------
    printf("test HMAC SHA384 Digest\n");
    char* sha384_expected = "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4";
    unsigned char* sha384_dst_digest;
    int sha384_dst_digets_len;

    if(crypsi_hmac_sha384(key_256, data, strlen(data), &sha384_dst_digest, &sha384_dst_digets_len) != 0) {
        printf("hmac sha384 digest error\n");
        free((void*) sha384_dst_digest);
        exit(-1);
    }

    if (strcmp(sha384_expected, sha384_dst_digest) != 0) {
        printf("hmac sha384 digest test failed\n");
        free((void*) sha384_dst_digest);
        exit(-1);
    }

    free((void*) sha384_dst_digest);
    printf("\n");
    // ------------------- SHA384 test end-------------------

    // ------------------- SHA512 test -------------------
    printf("test HMAC SHA512 Digest\n");
    char* sha512_expected = "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8";
    unsigned char* sha512_dst_digest;
    int sha512_dst_digets_len;

    if(crypsi_hmac_sha512(key_256, data, strlen(data), &sha512_dst_digest, &sha512_dst_digets_len) != 0) {
        printf("hmac sha512 digest error\n");
        free((void*) sha512_dst_digest);
        exit(-1);
    }

    if (strcmp(sha512_expected, sha512_dst_digest) != 0) {
        printf("hmac sha512 digest test failed\n");
        free((void*) sha512_dst_digest);
        exit(-1);
    }

    free((void*) sha512_dst_digest);
    printf("\n");
    // ------------------- SHA512 test end-------------------
}

void test_aes_encryption() {
    printf("test AES encryption\n");
    
    unsigned char key_128[17] = "abc$#128djdyAgbj";
    key_128[sizeof(key_128)-1] = 0x0; 

    unsigned char key_192[25] = "abc$#128djdyAgbjau&YAnmc";
    key_192[sizeof(key_192)-1] = 0x0; 

    unsigned char key_256[33] = "abc$#128djdyAgbjau&YAnmcbagryt5x";
    key_256[sizeof(key_256)-1] = 0x0; 

    unsigned char* plain_data = "Hello World 😋";
    unsigned char* expected = "Hello World 😋";

    // ------------------- AES 128 CBC test -------------------
    printf("test AES 128 CBC\n");
    unsigned char* dst_aes_128_cbc;
    int dst_aes_128_cbc_len;

    unsigned char* dst_aes_128_cbc_decrypt;
    int dst_aes_128_cbc_decrypt_len;

    if(crypsi_aes_128_cbc_encrypt(key_128, plain_data, strlen(plain_data), &dst_aes_128_cbc, &dst_aes_128_cbc_len) != 0) {
        printf("crypsi_aes_128_cbc_encrypt error\n");
        free((void*) dst_aes_128_cbc_decrypt);
        free((void*) dst_aes_128_cbc);
        exit(-1);
    }

    if(crypsi_aes_128_cbc_decrypt(key_128, dst_aes_128_cbc, dst_aes_128_cbc_len, &dst_aes_128_cbc_decrypt, &dst_aes_128_cbc_decrypt_len) != 0) {
        printf("crypsi_aes_128_cbc_decrypt error\n");
        free((void*) dst_aes_128_cbc_decrypt);
        free((void*) dst_aes_128_cbc);
        exit(-1);
    }

    if (strcmp(expected, dst_aes_128_cbc_decrypt) != 0) {
        printf("crypsi_aes_128_cbc encrypt decrypt failed\n");
        free((void*) dst_aes_128_cbc_decrypt);
        free((void*) dst_aes_128_cbc);
        exit(-1);
    }
    
    free((void*) dst_aes_128_cbc_decrypt);
    free((void*) dst_aes_128_cbc);
    printf("\n");
    // ------------------- AES 128 CBC test end -------------------

    // ------------------- AES 192 CBC test -------------------
    printf("test AES 192 CBC\n");
    unsigned char* dst_aes_192_cbc;
    int dst_aes_192_cbc_len;

    unsigned char* dst_aes_192_cbc_decrypt;
    int dst_aes_192_cbc_decrypt_len;

    if(crypsi_aes_192_cbc_encrypt(key_192, plain_data, strlen(plain_data), &dst_aes_192_cbc, &dst_aes_192_cbc_len) != 0) {
        printf("crypsi_aes_192_cbc_encrypt error\n");
        free((void*) dst_aes_192_cbc_decrypt);
        free((void*) dst_aes_192_cbc);
        exit(-1);
    }

    if(crypsi_aes_192_cbc_decrypt(key_192, dst_aes_192_cbc, dst_aes_192_cbc_len, &dst_aes_192_cbc_decrypt, &dst_aes_192_cbc_decrypt_len) != 0) {
        printf("crypsi_aes_192_cbc_decrypt error\n");
        free((void*) dst_aes_192_cbc_decrypt);
        free((void*) dst_aes_192_cbc);
        exit(-1);
    }

    if (strcmp(expected, dst_aes_192_cbc_decrypt) != 0) {
        printf("crypsi_aes_192_cbc encrypt decrypt failed\n");
        free((void*) dst_aes_192_cbc_decrypt);
        free((void*) dst_aes_192_cbc);
        exit(-1);
    }
    
    free((void*) dst_aes_192_cbc_decrypt);
    free((void*) dst_aes_192_cbc);
    printf("\n");
    // ------------------- AES 192 CBC test end -------------------

    // ------------------- AES 256 CBC test -------------------
    printf("test AES 256 CBC\n");
    unsigned char* dst_aes_256_cbc;
    int dst_aes_256_cbc_len;

    unsigned char* dst_aes_256_cbc_decrypt;
    int dst_aes_256_cbc_decrypt_len;

    if(crypsi_aes_256_cbc_encrypt(key_256, plain_data, strlen(plain_data), &dst_aes_256_cbc, &dst_aes_256_cbc_len) != 0) {
        printf("crypsi_aes_256_cbc_encrypt error\n");
        free((void*) dst_aes_256_cbc_decrypt);
        free((void*) dst_aes_256_cbc);
        exit(-1);
    }

    if(crypsi_aes_256_cbc_decrypt(key_256, dst_aes_256_cbc, dst_aes_256_cbc_len, &dst_aes_256_cbc_decrypt, &dst_aes_256_cbc_decrypt_len) != 0) {
        printf("crypsi_aes_256_cbc_decrypt error\n");
        free((void*) dst_aes_256_cbc_decrypt);
        free((void*) dst_aes_256_cbc);
        exit(-1);
    }

    if (strcmp(expected, dst_aes_256_cbc_decrypt) != 0) {
        printf("crypsi_aes_256_cbc encrypt decrypt failed\n");
        free((void*) dst_aes_256_cbc_decrypt);
        free((void*) dst_aes_256_cbc);
        exit(-1);
    }
    
    free((void*) dst_aes_256_cbc_decrypt);
    free((void*) dst_aes_256_cbc);
    printf("\n");
    // ------------------- AES 256 CBC test end -------------------

    // ------------------- AES 128 GCM test -------------------
    printf("test AES 128 GCM\n");
    unsigned char* dst_aes_128_gcm;
    int dst_aes_128_gcm_len;

    unsigned char* dst_aes_128_gcm_decrypt;
    int dst_aes_128_gcm_decrypt_len;

    if(crypsi_aes_128_gcm_encrypt(key_128, plain_data, strlen(plain_data), &dst_aes_128_gcm, &dst_aes_128_gcm_len) != 0) {
        printf("crypsi_aes_128_gcm_encrypt error\n");
        free((void*) dst_aes_128_gcm_decrypt);
        free((void*) dst_aes_128_gcm);
        exit(-1);
    }

    if(crypsi_aes_128_gcm_decrypt(key_128, dst_aes_128_gcm, dst_aes_128_gcm_len, &dst_aes_128_gcm_decrypt, &dst_aes_128_gcm_decrypt_len) != 0) {
        printf("crypsi_aes_128_gcm_decrypt error\n");
        free((void*) dst_aes_128_gcm_decrypt);
        free((void*) dst_aes_128_gcm);
        exit(-1);
    }

    if (strcmp(expected, dst_aes_128_gcm_decrypt) != 0) {
        printf("crypsi_aes_128_gcm encrypt decrypt failed\n");
        free((void*) dst_aes_128_gcm_decrypt);
        free((void*) dst_aes_128_gcm);
        exit(-1);
    }
    
    free((void*) dst_aes_128_gcm_decrypt);
    free((void*) dst_aes_128_gcm);
    printf("\n");
    // ------------------- AES 128 GCM test end -------------------

    // ------------------- AES 192 GCM test -------------------
    printf("test AES 192 GCM\n");
    unsigned char* dst_aes_192_gcm;
    int dst_aes_192_gcm_len;

    unsigned char* dst_aes_192_gcm_decrypt;
    int dst_aes_192_gcm_decrypt_len;

    if(crypsi_aes_192_gcm_encrypt(key_192, plain_data, strlen(plain_data), &dst_aes_192_gcm, &dst_aes_192_gcm_len) != 0) {
        printf("crypsi_aes_192_gcm_encrypt error\n");
        free((void*) dst_aes_192_gcm_decrypt);
        free((void*) dst_aes_192_gcm);
        exit(-1);
    }

    if(crypsi_aes_192_gcm_decrypt(key_192, dst_aes_192_gcm, dst_aes_192_gcm_len, &dst_aes_192_gcm_decrypt, &dst_aes_192_gcm_decrypt_len) != 0) {
        printf("crypsi_aes_192_gcm_decrypt error\n");
        free((void*) dst_aes_192_gcm_decrypt);
        free((void*) dst_aes_192_gcm);
        exit(-1);
    }

    if (strcmp(expected, dst_aes_192_gcm_decrypt) != 0) {
        printf("crypsi_aes_192_gcm encrypt decrypt failed\n");
        free((void*) dst_aes_192_gcm_decrypt);
        free((void*) dst_aes_192_gcm);
        exit(-1);
    }
    
    free((void*) dst_aes_192_gcm_decrypt);
    free((void*) dst_aes_192_gcm);
    printf("\n");
    // ------------------- AES 192 GCM test end -------------------

    // ------------------- AES 256 GCM test -------------------
    printf("test AES 256 GCM\n");
    unsigned char* dst_aes_256_gcm;
    int dst_aes_256_gcm_len;

    unsigned char* dst_aes_256_gcm_decrypt;
    int dst_aes_256_gcm_decrypt_len;

    if(crypsi_aes_256_gcm_encrypt(key_256, plain_data, strlen(plain_data), &dst_aes_256_gcm, &dst_aes_256_gcm_len) != 0) {
        printf("crypsi_aes_256_gcm_encrypt error\n");
        free((void*) dst_aes_256_gcm_decrypt);
        free((void*) dst_aes_256_gcm);
        exit(-1);
    }

    if(crypsi_aes_256_gcm_decrypt(key_256, dst_aes_256_gcm, dst_aes_256_gcm_len, &dst_aes_256_gcm_decrypt, &dst_aes_256_gcm_decrypt_len) != 0) {
        printf("crypsi_aes_256_gcm_decrypt error\n");
        free((void*) dst_aes_256_gcm_decrypt);
        free((void*) dst_aes_256_gcm);
        exit(-1);
    }

    if (strcmp(expected, dst_aes_256_gcm_decrypt) != 0) {
        printf("crypsi_aes_256_gcm encrypt decrypt failed\n");
        free((void*) dst_aes_256_gcm_decrypt);
        free((void*) dst_aes_256_gcm);
        exit(-1);
    }
    
    free((void*) dst_aes_256_gcm_decrypt);
    free((void*) dst_aes_256_gcm);
    printf("\n");
    // ------------------- AES 256 GCM test end -------------------
}

void test_rsa_encryption() {
    printf("test RSA encryption\n");
    
    unsigned char* plain_data = "Hello World 😋";
    unsigned char* expected = "Hello World 😋";

    // load public key
    unsigned char* rsa_public_key_char = load_file("./testdata/public_key.key");

    // load private key
    unsigned char* rsa_private_key_char = load_file("./testdata/private_key.key");

    // ------------------- RSA OAEP MD5 encryption test -------------------
    printf("test RSA OAEP MD5 encryption\n");
    unsigned char* dst_oaep_md5_encrypt;
    int dst_oaep_md5_encrypt_len;

    unsigned char* dst_oaep_md5_decrypt;
    int dst_oaep_md5_decrypt_len;

    if(crypsi_rsa_encrypt_oaep_md5(rsa_public_key_char, plain_data, strlen(plain_data), &dst_oaep_md5_encrypt, &dst_oaep_md5_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_md5 error\n");
        free((void*) dst_oaep_md5_encrypt);
        free((void*) dst_oaep_md5_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_decrypt_oaep_md5(rsa_private_key_char, dst_oaep_md5_encrypt, dst_oaep_md5_encrypt_len, &dst_oaep_md5_decrypt, &dst_oaep_md5_decrypt_len) != 0) {
        printf("crypsi_rsa_decrypt_oaep_md5 error\n");
        free((void*) dst_oaep_md5_encrypt);
        free((void*) dst_oaep_md5_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if (memcmp(expected, dst_oaep_md5_decrypt, dst_oaep_md5_decrypt_len) != 0) {
        printf("RSA OAEP MD5 encryption encrypt decrypt test failed\n");
        free((void*) dst_oaep_md5_encrypt);
        free((void*) dst_oaep_md5_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }
    
    free((void*) dst_oaep_md5_encrypt);
    free((void*) dst_oaep_md5_decrypt);
    printf("\n");
    // ------------------- RSA OAEP MD5 encryption test end -------------------

    // ------------------- RSA OAEP SHA1 encryption test -------------------
    printf("test RSA OAEP sha1 encryption\n");
    unsigned char* dst_oaep_sha1_encrypt;
    int dst_oaep_sha1_encrypt_len;

    unsigned char* dst_oaep_sha1_decrypt;
    int dst_oaep_sha1_decrypt_len;

    if(crypsi_rsa_encrypt_oaep_sha1(rsa_public_key_char, plain_data, strlen(plain_data), &dst_oaep_sha1_encrypt, &dst_oaep_sha1_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_sha1 error\n");
        free((void*) dst_oaep_sha1_encrypt);
        free((void*) dst_oaep_sha1_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_decrypt_oaep_sha1(rsa_private_key_char, dst_oaep_sha1_encrypt, dst_oaep_sha1_encrypt_len, &dst_oaep_sha1_decrypt, &dst_oaep_sha1_decrypt_len) != 0) {
        printf("crypsi_rsa_decrypt_oaep_sha1 error\n");
        free((void*) dst_oaep_sha1_encrypt);
        free((void*) dst_oaep_sha1_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if (memcmp(expected, dst_oaep_sha1_decrypt, dst_oaep_sha1_decrypt_len) != 0) {
        printf("RSA OAEP sha1 encryption encrypt decrypt test failed\n");
        free((void*) dst_oaep_sha1_encrypt);
        free((void*) dst_oaep_sha1_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }
    
    free((void*) dst_oaep_sha1_encrypt);
    free((void*) dst_oaep_sha1_decrypt);
    printf("\n");
    // ------------------- RSA OAEP SHA1 encryption test end -------------------

    // ------------------- RSA OAEP SHA256 encryption test -------------------
    printf("test RSA OAEP sha256 encryption\n");
    unsigned char* dst_oaep_sha256_encrypt;
    int dst_oaep_sha256_encrypt_len;

    unsigned char* dst_oaep_sha256_decrypt;
    int dst_oaep_sha256_decrypt_len;

    if(crypsi_rsa_encrypt_oaep_sha256(rsa_public_key_char, plain_data, strlen(plain_data), &dst_oaep_sha256_encrypt, &dst_oaep_sha256_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_sha256 error\n");
        free((void*) dst_oaep_sha256_encrypt);
        free((void*) dst_oaep_sha256_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_decrypt_oaep_sha256(rsa_private_key_char, dst_oaep_sha256_encrypt, dst_oaep_sha256_encrypt_len, &dst_oaep_sha256_decrypt, &dst_oaep_sha256_decrypt_len) != 0) {
        printf("crypsi_rsa_decrypt_oaep_sha256 error\n");
        free((void*) dst_oaep_sha256_encrypt);
        free((void*) dst_oaep_sha256_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if (memcmp(expected, dst_oaep_sha256_decrypt, dst_oaep_sha256_decrypt_len) != 0) {
        printf("RSA OAEP sha256 encryption encrypt decrypt test failed\n");
        free((void*) dst_oaep_sha256_encrypt);
        free((void*) dst_oaep_sha256_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }
    
    free((void*) dst_oaep_sha256_encrypt);
    free((void*) dst_oaep_sha256_decrypt);
    printf("\n");
    // ------------------- RSA OAEP SHA256 encryption test end -------------------

    // ------------------- RSA OAEP SHA384 encryption test -------------------
    printf("test RSA OAEP sha384 encryption\n");
    unsigned char* dst_oaep_sha384_encrypt;
    int dst_oaep_sha384_encrypt_len;

    unsigned char* dst_oaep_sha384_decrypt;
    int dst_oaep_sha384_decrypt_len;

    if(crypsi_rsa_encrypt_oaep_sha384(rsa_public_key_char, plain_data, strlen(plain_data), &dst_oaep_sha384_encrypt, &dst_oaep_sha384_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_sha384 error\n");
        free((void*) dst_oaep_sha384_encrypt);
        free((void*) dst_oaep_sha384_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_decrypt_oaep_sha384(rsa_private_key_char, dst_oaep_sha384_encrypt, dst_oaep_sha384_encrypt_len, &dst_oaep_sha384_decrypt, &dst_oaep_sha384_decrypt_len) != 0) {
        printf("crypsi_rsa_decrypt_oaep_sha384 error\n");
        free((void*) dst_oaep_sha384_encrypt);
        free((void*) dst_oaep_sha384_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if (memcmp(expected, dst_oaep_sha384_decrypt, dst_oaep_sha384_decrypt_len) != 0) {
        printf("RSA OAEP sha384 encryption encrypt decrypt test failed\n");
        free((void*) dst_oaep_sha384_encrypt);
        free((void*) dst_oaep_sha384_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }
    
    free((void*) dst_oaep_sha384_encrypt);
    free((void*) dst_oaep_sha384_decrypt);
    printf("\n");
    // ------------------- RSA OAEP SHA384 encryption test end -------------------

    // ------------------- RSA OAEP SHA512 encryption test -------------------
    printf("test RSA OAEP sha512 encryption\n");
    unsigned char* dst_oaep_sha512_encrypt;
    int dst_oaep_sha512_encrypt_len;

    unsigned char* dst_oaep_sha512_decrypt;
    int dst_oaep_sha512_decrypt_len;

    if(crypsi_rsa_encrypt_oaep_sha512(rsa_public_key_char, plain_data, strlen(plain_data), &dst_oaep_sha512_encrypt, &dst_oaep_sha512_encrypt_len) != 0) {
        printf("crypsi_rsa_encrypt_oaep_sha512 error\n");
        free((void*) dst_oaep_sha512_encrypt);
        free((void*) dst_oaep_sha512_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_decrypt_oaep_sha512(rsa_private_key_char, dst_oaep_sha512_encrypt, dst_oaep_sha512_encrypt_len, &dst_oaep_sha512_decrypt, &dst_oaep_sha512_decrypt_len) != 0) {
        printf("crypsi_rsa_decrypt_oaep_sha512 error\n");
        free((void*) dst_oaep_sha512_encrypt);
        free((void*) dst_oaep_sha512_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if (memcmp(expected, dst_oaep_sha512_decrypt, dst_oaep_sha512_decrypt_len) != 0) {
        printf("RSA OAEP sha512 encryption encrypt decrypt test failed\n");
        free((void*) dst_oaep_sha512_encrypt);
        free((void*) dst_oaep_sha512_decrypt);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }
    
    free((void*) dst_oaep_sha512_encrypt);
    free((void*) dst_oaep_sha512_decrypt);
    free((void*) rsa_public_key_char);
    free((void*) rsa_private_key_char);
    printf("\n");
    // ------------------- RSA OAEP SHA512 encryption test end -------------------
}

void test_rsa_digital_signature() {
    printf("test RSA digital signature\n");
    
    unsigned char* plain_data = "Hello World 😋";

    // load public key
    unsigned char* rsa_public_key_char = load_file("./testdata/public_key.key");

    // load private key
    unsigned char* rsa_private_key_char = load_file("./testdata/private_key.key");

    // ------------------- RSA PSS MD5 signature test -------------------
    printf("test RSA digital signature PSS MD5\n");
    unsigned char* dst_signature_md5;
    unsigned int dst_signature_md5_len;

    if(crypsi_rsa_sign_pss_md5(rsa_private_key_char, plain_data, strlen(plain_data), &dst_signature_md5, &dst_signature_md5_len) != 0) {
        printf("crypsi_rsa_sign_pss_md5 error\n");
        free((void*) dst_signature_md5);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_verify_sign_pss_md5(rsa_public_key_char, plain_data, strlen(plain_data), dst_signature_md5, dst_signature_md5_len) != 1) {
        printf("crypsi_rsa_sign_pss_md5 sign and verify test failed\n");
        free((void*) dst_signature_md5);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    free((void*) dst_signature_md5);
    printf("\n");
    // ------------------- RSA PSS MD5 signature test end -------------------

    // ------------------- RSA PSS SHA1 signature test -------------------
    printf("test RSA digital signature PSS sha1\n");
    unsigned char* dst_signature_sha1;
    unsigned int dst_signature_sha1_len;

    if(crypsi_rsa_sign_pss_sha1(rsa_private_key_char, plain_data, strlen(plain_data), &dst_signature_sha1, &dst_signature_sha1_len) != 0) {
        printf("crypsi_rsa_sign_pss_sha1 error\n");
        free((void*) dst_signature_sha1);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_verify_sign_pss_sha1(rsa_public_key_char, plain_data, strlen(plain_data), dst_signature_sha1, dst_signature_sha1_len) != 1) {
        printf("crypsi_rsa_sign_pss_sha1 sign and verify test failed\n");
        free((void*) dst_signature_sha1);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    free((void*) dst_signature_sha1);
    printf("\n");
    // ------------------- RSA PSS SHA1 signature test end -------------------

    // ------------------- RSA PSS SHA256 signature test -------------------
    printf("test RSA digital signature PSS sha256\n");
    unsigned char* dst_signature_sha256;
    unsigned int dst_signature_sha256_len;

    if(crypsi_rsa_sign_pss_sha256(rsa_private_key_char, plain_data, strlen(plain_data), &dst_signature_sha256, &dst_signature_sha256_len) != 0) {
        printf("crypsi_rsa_sign_pss_sha256 error\n");
        free((void*) dst_signature_sha256);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_verify_sign_pss_sha256(rsa_public_key_char, plain_data, strlen(plain_data), dst_signature_sha256, dst_signature_sha256_len) != 1) {
        printf("crypsi_rsa_sign_pss_sha256 sign and verify test failed\n");
        free((void*) dst_signature_sha256);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    free((void*) dst_signature_sha256);
    printf("\n");
    // ------------------- RSA PSS SHA256 signature test end -------------------

    // ------------------- RSA PSS SHA384 signature test -------------------
    printf("test RSA digital signature PSS sha384\n");
    unsigned char* dst_signature_sha384;
    unsigned int dst_signature_sha384_len;

    if(crypsi_rsa_sign_pss_sha384(rsa_private_key_char, plain_data, strlen(plain_data), &dst_signature_sha384, &dst_signature_sha384_len) != 0) {
        printf("crypsi_rsa_sign_pss_sha384 error\n");
        free((void*) dst_signature_sha384);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_verify_sign_pss_sha384(rsa_public_key_char, plain_data, strlen(plain_data), dst_signature_sha384, dst_signature_sha384_len) != 1) {
        printf("crypsi_rsa_sign_pss_sha384 sign and verify test failed\n");
        free((void*) dst_signature_sha384);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    free((void*) dst_signature_sha384);
    printf("\n");
    // ------------------- RSA PSS SHA384 signature test end -------------------

    // ------------------- RSA PSS SHA512 signature test -------------------
    printf("test RSA digital signature PSS sha512\n");
    unsigned char* dst_signature_sha512;
    unsigned int dst_signature_sha512_len;

    if(crypsi_rsa_sign_pss_sha512(rsa_private_key_char, plain_data, strlen(plain_data), &dst_signature_sha512, &dst_signature_sha512_len) != 0) {
        printf("crypsi_rsa_sign_pss_sha512 error\n");
        free((void*) dst_signature_sha512);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    if(crypsi_rsa_verify_sign_pss_sha512(rsa_public_key_char, plain_data, strlen(plain_data), dst_signature_sha512, dst_signature_sha512_len) != 1) {
        printf("crypsi_rsa_sign_pss_sha512 sign and verify test failed\n");
        free((void*) dst_signature_sha512);
        free((void*) rsa_public_key_char);
        free((void*) rsa_private_key_char);
        exit(-1);
    }

    free((void*) dst_signature_sha512);

    free((void*) rsa_public_key_char);
    free((void*) rsa_private_key_char);
    printf("\n");
    // ------------------- RSA PSS SHA512 signature test end -------------------
}

void test_rsa_digital_signature_file_stream() {
    printf("test RSA digital signature file stream\n");

    long burger_stream_md5_length = 0;

    // load public key
    unsigned char* rsa_public_key_char = load_file("./testdata/public_key.key");

    // load file
    unsigned char* burger_stream_md5 = load_file_with_size("./testdata/burger.png", &burger_stream_md5_length);

    // ------------------- RSA PSS MD5 signature test -------------------
    printf("test RSA digital signature PSS MD5 file stream\n");
    unsigned char* dst_signature_md5 = "8041cad4c4ac4c96fd54b42dc199f72535c60645a2e6b293018d9973f7241dc92485fdeda54a22dc733d1a9213a3bc6992150ae7ecb567a2f54779c7605a19af48562ef23064246e3db1631fa55e4c318c44d8c9be1b5dd8fe4f3b20d46d1e332f8d55aa845b430bb7d98766acc51c747b77e8e8ba62116ffd817a1c8e9f0636bf11498ea25b52d455c1b8baa72edc710598dba7a5f55b41fe2f3bb1c298a5785e12db5e6658da0d2dc42ab2850ee95c1ddabc8834e71c4588d67c1fd88be42c912bbe8bdd9cbcccdb60cbfe9a9f144df834b34f2d438ddfe7ab9dca1883928e6db200864dd479c396f4023972c2f7fb05049b475aabe1df1d42c8cdf3259881";

    if(crypsi_rsa_verify_sign_pss_md5(rsa_public_key_char, burger_stream_md5, burger_stream_md5_length, dst_signature_md5, strlen(dst_signature_md5)) != 1) {
        printf("crypsi_rsa_sign_pss_md5 sign and verify file stream test failed\n");
        free((void*) rsa_public_key_char);
        free((void*) burger_stream_md5);
        exit(-1);
    }

    free((void*) burger_stream_md5);
    printf("\n");
    // ------------------- RSA PSS MD5 signature test end -------------------

    free((void*) rsa_public_key_char);
} 

int main(int argc, char** argv) {
    test_digest();
    test_hmac();
    test_aes_encryption();
    test_rsa_encryption();
    test_rsa_digital_signature();
    test_rsa_digital_signature_file_stream();
    return 0;
}