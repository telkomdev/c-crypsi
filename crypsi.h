#ifndef CRYPSI_H
#define CRYPSI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#define HEX_STRINGS "0123456789abcdef"

static const unsigned char HEX_TABLE[][2] = {
    {0x30, 0}, {0x31, 1}, {0x32, 2}, {0x33, 3}, 
    {0x34, 4}, {0x35, 5}, {0x36, 6}, {0x37, 7}, 
    {0x38, 8}, {0x39, 9}, {0x61, 10}, {0x62, 11}, 
    {0x63, 12}, {0x64, 13}, {0x65, 14}, {0x66, 15}, 
    {0x41, 10}, {0x42, 11}, {0x43, 12}, {0x44, 13}, 
    {0x45, 14}, {0x46, 15}};

enum crypsi_aes_key {
    CRYPSI_AES_128_KEY = 16,
    CRYPSI_AES_192_KEY = 24,
    CRYPSI_AES_256_KEY = 32
};

enum crypsi_aes_mode {
    CRYPSI_AES_CBC_MODE,
    CRYPSI_AES_GCM_MODE,
};

enum crypsi_digest_alg {
    CRYPSI_MD5,
    CRYPSI_SHA1,
    CRYPSI_SHA256,
    CRYPSI_SHA384,
    CRYPSI_SHA512,
};

// utilties
int hexencode(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int hexdecode(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
unsigned char find_hex_val(unsigned char hx);

// AES
int encrypt_with_aes_256cbc(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);
int decrypt_with_aes_256cbc(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);

// message digest
static int crypsi_digest(enum crypsi_digest_alg alg, const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_md5(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha1(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int crypsi_sha512(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);

unsigned char find_hex_val(unsigned char hx) {
    char c = 0x0;
     for (int j = 0; j < sizeof(HEX_TABLE); j++) {
        if (hx == HEX_TABLE[j][0]) {
            c = HEX_TABLE[j][1];
            break;
        }
    }
    return c;
}

int hexencode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len) {
    int result_len = message_len*2+1;
    unsigned char* _dst = (unsigned char*) malloc(result_len);
    if (_dst == NULL) {
        return -1;
    }

    *dst_len = result_len-1;

    for (int i = 0; i < message_len; i++ ) {
        _dst[i+i] = HEX_STRINGS[message[i] >> 0x4];
        _dst[i+i+1] = HEX_STRINGS[message[i] & 0xf];
    }

    _dst[result_len-1] = 0x0;
    *dst = _dst;

    return 0;
}

int hexdecode(const unsigned char* message, size_t message_len, 
    unsigned char** dst, unsigned int* dst_len) {
    int result_len = message_len/2+1;
    unsigned char* _dst = (unsigned char*) malloc(result_len);
    if (_dst == NULL) {
        return -1;
    }

    *dst_len = result_len-1;

    for (int i = 0; i < result_len - 1; i++ ) {
        unsigned char ca = find_hex_val(message[i+i]);
        unsigned char cb = find_hex_val(message[i+i+1]);

        _dst[i] = (ca << 4) | cb;
    }

    _dst[result_len-1] = 0x0;
    *dst = _dst;

    return 0;
}

static int crypsi_digest(enum crypsi_digest_alg alg, const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_MD_CTX* mdctx;
    EVP_MD* md;

    int dst_len_tmp = 0;
    unsigned char* dst_tmp;

    switch (alg) {
    case CRYPSI_MD5:
        md = (EVP_MD*) EVP_md5();
        break;
    case CRYPSI_SHA1:
        md = (EVP_MD*) EVP_sha1();
        break;
    case CRYPSI_SHA256:
        md = (EVP_MD*) EVP_sha256();
        break;
    case CRYPSI_SHA384:
        md = (EVP_MD*) EVP_sha384();
        break;
    case CRYPSI_SHA512:
        md = (EVP_MD*) EVP_sha512();
        break;
    default:
        return -1;
    }

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		return -1;

	if(1 != EVP_DigestInit_ex(mdctx, md, NULL))
		return -1;

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		return -1;

	if((dst_tmp = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md))) == NULL)
		return -1;

	if(1 != EVP_DigestFinal_ex(mdctx, dst_tmp, &dst_len_tmp))
		return -1;

        // encode to hex
    if(hexencode(dst_tmp, dst_len_tmp, dst, dst_len) != 0)
        return -1;

	EVP_MD_CTX_free(mdctx);

    return 0;
}

int crypsi_md5(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_MD5, message, message_len, dst, dst_len);
}

int crypsi_sha1(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA1, message, message_len, dst, dst_len);
}

int crypsi_sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA256, message, message_len, dst, dst_len);
}

int crypsi_sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA384, message, message_len, dst, dst_len);
}

int crypsi_sha512(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    return crypsi_digest(CRYPSI_SHA512, message, message_len, dst, dst_len);
}

int encrypt_with_aes_256cbc(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;

    int dst_len_tmp = 0;
    int ciphertext_len = 0;
    unsigned char* dst_tmp_raw; 
    unsigned char* dst_tmp;

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = data_len + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE) + 1;

    // printf("raw_ciphertext_len: %d\n", raw_ciphertext_len);
    if((dst_tmp_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL)
		return -1;


    if(!(ctx = EVP_CIPHER_CTX_new())) 
        return -1;
    
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        return -1;
    
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if(EVP_EncryptUpdate(ctx, dst_tmp_raw, &dst_len_tmp, data, data_len) != 1)
        return -1;
    
    ciphertext_len = dst_len_tmp;
    printf("ciphertext_len: %d\n", ciphertext_len);

    if(EVP_EncryptFinal_ex(ctx, dst_tmp_raw + dst_len_tmp, &dst_len_tmp) != 1)
        return -1;

    ciphertext_len += dst_len_tmp;
    dst_tmp_raw[raw_ciphertext_len-1] = 0x0;

    int result_len_raw = ciphertext_len + sizeof(iv) + 1;

    printf("raw_ciphertext_len: %d\n", raw_ciphertext_len);
    printf("data_len: %ld\n", data_len);
    printf("ciphertext_len: %d\n", ciphertext_len);
    printf("result_len_raw: %d\n", result_len_raw);
    printf("strlen dst_tmp_raw: %ld\n", strlen(dst_tmp_raw));

    if((dst_tmp = (unsigned char*) malloc(result_len_raw)) == NULL)
        return -1;

    for(int i = 0; i < raw_ciphertext_len-1; i++) {
        printf("%d ", dst_tmp_raw[i]);
    }

    printf("\n");

    for(int i = 0; i < sizeof(iv); i++) {
        printf("%d ", iv[i]);
    }

    printf("\n");

    // concat iv with cipher text
    memcpy(dst_tmp, iv, sizeof(iv));
    memcpy(dst_tmp+sizeof(iv), dst_tmp_raw, raw_ciphertext_len-1);

    dst_tmp[result_len_raw-1] = 0x0;
    
    // encode to hex
    if(hexencode(dst_tmp, result_len_raw-1, dst, dst_len) != 0)
        return -1;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    free((void*) dst_tmp);
    free((void*) dst_tmp_raw);

    return 0;
}

int decrypt_with_aes_256cbc(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;

    int dst_len_tmp = 0;
    int plaintext_len = 0;
    unsigned char* ciphertext_raw; 
    unsigned char* dst_tmp;

    unsigned char* dst_decode;
    unsigned  dst_decode_len;
    if(hexdecode(data, data_len, &dst_decode, &dst_decode_len) != 0)
        return -1;
    printf("here\n");
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, dst_decode, sizeof(iv));
    
    for(int i = 0; i < sizeof(iv); i++) {
        printf("%d ", iv[i]);
    }

    printf("\n");

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = (dst_decode_len - sizeof(iv)) + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE) + 1;
    raw_ciphertext_len = raw_ciphertext_len-sizeof(iv);

    if((ciphertext_raw = (unsigned char*) malloc(raw_ciphertext_len)) == NULL)
		return -1;

    memcpy(ciphertext_raw, dst_decode+sizeof(iv), raw_ciphertext_len);
    ciphertext_raw[raw_ciphertext_len-1] = 0x0;

    printf("raw_ciphertext_len: %d\n", raw_ciphertext_len);
    for(int i = 0; i < raw_ciphertext_len-1; i++) {
        printf("%d ", ciphertext_raw[i]);
    }

    printf("\n");

    if((dst_tmp = (unsigned char*) malloc(raw_ciphertext_len)) == NULL)
		return -1;

    if(!(ctx = EVP_CIPHER_CTX_new())) 
        return -1;
    
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if(EVP_DecryptUpdate(ctx, dst_tmp, &dst_len_tmp, ciphertext_raw, raw_ciphertext_len-1) != 1)
        return -1;
    
    plaintext_len = dst_len_tmp;
    

    if(EVP_DecryptFinal_ex(ctx, dst_tmp + dst_len_tmp, &dst_len_tmp) != 1)
        return -1;
    plaintext_len += dst_len_tmp;

    printf("plaintext_len: %d\n", plaintext_len);

    if((*dst = (unsigned char*) malloc(plaintext_len+1)) == NULL)
		return -1;
   
    memcpy(*dst, dst_tmp, plaintext_len);
    // *dst[plaintext_len] = 0x0;

    *dst_len = plaintext_len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    free((void*) dst_decode);
    free((void*) ciphertext_raw);
    free((void*) dst_tmp);
    

    return 0;
}

#endif