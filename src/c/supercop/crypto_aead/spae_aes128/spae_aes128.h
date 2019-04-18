#ifndef __SPAE_AES128_H__
#define __SPAE_AES128_H__

#include <stdint.h>
#include <limits.h>
#include <string.h>

#ifdef __cplusplus
extern "C"{
#endif

#define SPAE_PASS 0
#define SPAE_BLOCKSIZE 16
#define SPAE_KEYSIZE 16
#define SPAE_BLOCKSIZE64 2

void spae_sle_aes128_enc(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
);

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
int spae_sle_aes128_dec(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message,
    size_t mlen
);


void spae_small_aes128_enc(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
){
    spae_sle_aes128_enc(key,nonce,message,mlen,ad,alen,ciphertext,clen);
}

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
int spae_small_aes128_dec(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message,
    size_t mlen
){
    return spae_sle_aes128_dec(key,nonce,ciphertext,clen,ad,alen,message,mlen);
}
/*
void spae_k64f_aes128_enc(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
);

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
int spae_k64f_aes128_dec(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message,
    size_t mlen
);
*/

void spae_fle_aes128_enc(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
);

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
int spae_fle_aes128_dec(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message,
    size_t mlen
);

void spae_fast_aes128_enc(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
){
    spae_fle_aes128_enc(key,nonce,message,mlen,ad,alen,ciphertext,clen);
}

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
int spae_fast_aes128_dec(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message,
    size_t mlen
){
    return spae_fle_aes128_dec(key,nonce,ciphertext,clen,ad,alen,message,mlen);
}


#ifdef __cplusplus
}
#endif




#endif
