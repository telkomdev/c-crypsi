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
    {0x41, 10}, {0x64, 11}, {0x43, 12}, {0x44, 13}, 
    {0x45, 14}, {0x46, 15}};

int hexencode(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int hexdecode(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);

int encrypt_with_aes_256cbc(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len);

unsigned char find_hex_val(unsigned char hx);

int sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);
int sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len);

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

int sha256(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		return -1;

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		return -1;

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		return -1;

	if((*dst = (unsigned char *) OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		return -1;

	if(1 != EVP_DigestFinal_ex(mdctx, *dst, dst_len))
		return -1;

	EVP_MD_CTX_free(mdctx);

    return 0;
}

int sha384(const unsigned char* message, size_t message_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		return -1;

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL))
		return -1;

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		return -1;

	if((*dst = (unsigned char *) OPENSSL_malloc(EVP_MD_size(EVP_sha384()))) == NULL)
		return -1;

	if(1 != EVP_DigestFinal_ex(mdctx, *dst, dst_len))
		return -1;

	EVP_MD_CTX_free(mdctx);

    return 0;
}

int encrypt_with_aes_256cbc(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char** dst, unsigned int* dst_len) {
    EVP_CIPHER_CTX *ctx;

    int dst_len_tmp;
    int ciphertext_len;
    char* dst_tmp_raw; 
    char* dst_tmp;

    // After padding and encrypting data, the size of the ciphertext is plaintext_size + (block_size - plaintext_size % block_size)
    int raw_ciphertext_len = data_len + (AES_BLOCK_SIZE - data_len%AES_BLOCK_SIZE);

    printf("raw_ciphertext_len: %d\n", raw_ciphertext_len);
    if((dst_tmp_raw = (unsigned char *) malloc(raw_ciphertext_len)) == NULL)
		return -1;

    if(!(ctx = EVP_CIPHER_CTX_new())) 
        return -1;
    
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        return -1;
    
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if(EVP_EncryptUpdate(ctx, dst_tmp_raw, &dst_len_tmp, data, data_len) != 1)
        return -1;
    
    ciphertext_len = dst_len_tmp;

    if(1 != EVP_EncryptFinal_ex(ctx, dst_tmp_raw + dst_len_tmp, &dst_len_tmp))
        return -1;

    ciphertext_len += dst_len_tmp;

    int result_len_raw = ciphertext_len + sizeof(iv) + 1;

    printf("result_len_raw: %d\n", result_len_raw);
    printf("strlen dst_tmp_raw: %ld\n", strlen(dst_tmp_raw));

    if((dst_tmp = (char*) malloc(result_len_raw)) == NULL)
        return -1;

    // concat iv with cipher text
    strncpy(dst_tmp, iv, sizeof(iv));
    strcat(dst_tmp, dst_tmp_raw);

    dst_tmp[result_len_raw-1] = 0x0;

    // encode to hex
    if(hexencode(dst_tmp, result_len_raw-1, dst, dst_len) != 0) {
        return -1;
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    free((void*) dst_tmp);
    free((void*) dst_tmp_raw);

    return 0;
}

#endif