#ifndef __SPAE_AES128_H__
#define __SPAE_AES128_H__

#include <stdint.h>
#include "spae_aes128_fle_impl.h"

#define SPAE_PASS SPAE_FLE_PASS
#define SPAE_BLOCKSIZE SPAE_FLE_BLOCKSIZE
#define SPAE_KEYSIZE SPAE_FLE_KEYSIZE
#define SPAE_BLOCKSIZE64 SPAE_FLE_BLOCKSIZE64



void spae_aes128_enc(
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
int spae_aes128_dec(
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

#endif
