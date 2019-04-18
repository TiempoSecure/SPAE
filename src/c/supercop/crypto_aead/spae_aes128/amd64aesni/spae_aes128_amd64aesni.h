/**
SPAE Single Pass Authenticated Encryption v0.12
Sebastien Riou, November 15th 2018

c99 AES-NI implementation meant to fit in the supercop framework
*/

#ifndef __SPAE_AES128_H__
#define __SPAE_AES128_H__

#define SPAE_AESNI

#include <stdint.h>
#include <string.h>
#include "aes_ni.h"
#include <stdio.h>

#define SPAE_PASS 0
#define SPAE_BLOCKSIZE 16
#define SPAE_KEYSIZE 16
#define SPAE_BLOCKSIZE64 2

typedef struct spae_aes128_struct_t spae_aes128_t;
typedef void (*spae_aes128_enc_core_t)(spae_aes128_t *const ctx, const uint8_t *const ib);


typedef struct spae_aes128_struct_t {
    __m128i key[20];
    __m128i kn[20];
    __m128i ct[1];
    __m128i pt[1];
    __m128i at[1];
    __m128i buf[1];
    size_t mlen;
    size_t alen;
    __m128i *obuf128;
    uint8_t*obuf;
    int decrypt;
    spae_aes128_enc_core_t enc_core;
} spae_aes128_t;

//static __m128i RR32(__m128i in){
//    const uint8_t sel0 = 1;
//    const uint8_t sel1 = 2;
//    const uint8_t sel2 = 3;
//    const uint8_t sel3 = 0;
//    const uint8_t sel = (sel3<<6)|(sel2<<4)|(sel1<<2)|sel0;
//    return _mm_shuffle_epi32(in,sel);
//}
//
//static void spae_rr32(uint32_t*b){
//    uint32_t buf = b[0];
//    b[0] = b[1];
//    b[1] = b[2];
//    b[2] = b[3];
//    b[3] = buf;
//}


static void spae_hswap64(const uint64_t*const src,uint64_t*const dst){
    dst[1] = src[0];
    dst[0] = src[1];
}

static void spae_aes128_ek(
    spae_aes128_t *const ctx,
    const void *const i,
    void *const o
){
    const uint8_t *const ib=(const uint8_t *const)i;
    uint8_t *const ob=(uint8_t *const)o;
    aes_ni_enc128_block(ob,ib,ctx->key);
}

static void spae_aes128_ekn(
    spae_aes128_t *const ctx,
    const void *const i,
    void *const o
){
    const uint8_t *const ib=(const uint8_t *const)i;
    uint8_t *const ob=(uint8_t *const)o;
    aes_ni_enc128_block(ob,ib,ctx->kn);
}

static void spae_aes128_dkn(
    spae_aes128_t *const ctx,
    const void *const i,
    void *const o
){
    const uint8_t *const ib=(const uint8_t *const)i;
    uint8_t *const ob=(uint8_t *const)o;
    aes_ni_dec128_block(ob,ib,ctx->kn);
}

static void spae_aes128_xor(
    const void *const a,//exactly one block of input
    const void *const b,
    void *const y
){
    const uint8_t *const ab = (const uint8_t *const)a;
    const uint8_t *const bb = (const uint8_t *const)b;
    uint8_t *const yb = (uint8_t *const)y;
    for(unsigned int i=0;i<SPAE_BLOCKSIZE;i++){
        yb[i] = ab[i] ^ bb[i];
    }
}

static void spae_aes128_enc_core(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input, WARNING: may also be the output
){
    uint64_t buf[SPAE_BLOCKSIZE64];
    uint64_t buf2[SPAE_BLOCKSIZE64];
    uint64_t*ct64 = (uint64_t*)ctx->ct;
    buf[0]=ct64[0];
    buf[1]=ct64[1];
    spae_aes128_xor(ctx->ct,ctx->pt,ctx->ct);
    spae_aes128_xor(ctx->pt,ib,buf2);
    spae_aes128_ekn(ctx,buf2,buf2);
    spae_aes128_xor(buf2,ib,ctx->pt);
    spae_aes128_xor(buf2,buf,ctx->obuf);
    ctx->obuf+=SPAE_BLOCKSIZE;
}

#include <assert.h>

static void spae_aes128_enc_core_aligned(
    spae_aes128_t *const ctx,
    const __m128i *const ib//exactly one block of input, WARNING: may also be the output
){
    __m128i buf[1];
    __m128i buf2[1];
    buf[0] = ctx->ct[0];
    ctx->ct[0] = _mm_xor_si128(ctx->pt[0],ctx->ct[0]);
    buf2[0] = _mm_xor_si128(ctx->pt[0],ib[0]);
    DO_ENC_BLOCK_ALIGNED(buf2[0],buf2[0],ctx->kn);
    ctx->pt[0] = _mm_xor_si128(buf2[0],ib[0]);
    ctx->obuf128[0] = _mm_xor_si128(buf[0],buf2[0]);
    ctx->obuf128++;
}

void spae_aes128_enc_blocks(
    spae_aes128_t *const ctx,
    const __m128i *const ib,//exactly one block of input, WARNING: may also be the output
    size_t m
){
    for(size_t i = 0; i<m; i++){//process all blocks
        __m128i buf[1];
        __m128i buf2[1];
        buf[0] = ctx->ct[0];
        ctx->ct[0] = _mm_xor_si128(ctx->pt[0],ctx->ct[0]);
        buf2[0] = _mm_xor_si128(ctx->pt[0],ib[i]);
        DO_ENC_BLOCK_ALIGNED(buf2[0],buf2[0],ctx->kn);
        ctx->pt[0] = _mm_xor_si128(buf2[0],ib[i]);
        ctx->obuf128[i] = _mm_xor_si128(buf[0],buf2[0]);
    }
    ctx->obuf128+=m;
}

static void spae_aes128_dec_core(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    __m128i buf[1];
    spae_aes128_xor(ctx->ct,ib,buf);
    spae_aes128_xor(ctx->ct,ctx->pt,ctx->ct);
    spae_aes128_dkn(ctx,buf,ctx->obuf);
    spae_aes128_xor(ctx->pt,ctx->obuf,ctx->obuf);
    spae_aes128_xor(buf,ctx->obuf,ctx->pt);
    ctx->obuf+=SPAE_BLOCKSIZE;
}

static void spae_aes128_process_ad(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    spae_aes128_xor(ctx->at,ib,ctx->at);
    spae_aes128_ek(ctx,ctx->at,ctx->at);
}

static void spae_aes128_init(
    spae_aes128_t *const ctx,
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const uint8_t *const ad,
    int decrypt,
    uint8_t *out_buffer//output buffer
){
    (void) aes_ni_self_test128;//remove warning
    //ctx->key = key;
    aes_ni_load_key128(key,ctx->key);
    ctx->obuf = out_buffer;
    if((0==(((uint64_t)ctx->obuf)%16)) && (0==(((uint64_t)message)%16)) && (0==(((uint64_t)ad)%16))){
        ctx->obuf128 = (__m128i *)out_buffer;
    } else {
        ctx->obuf128 = 0;
    }

    ctx->mlen=0;
    ctx->alen=0;
    ctx->decrypt = decrypt;

    DO_ENC_BLOCK_ALIGNED(ctx->ct[0],ctx->key[0],ctx->key);
    __m128i nonce128 = _mm_loadu_si128((__m128i *) nonce);
    ctx->pt[0]  = _mm_xor_si128(ctx->ct[0],ctx->key[0]);
    ctx->kn[0]  = _mm_xor_si128(ctx->key[0],nonce128);
    aes_ni_load_key128((uint8_t*)ctx->kn,ctx->kn);
    ctx->at[0] = _mm_setzero_si128();
}


static void spae_compute_tag(
    spae_aes128_t *const ctx,
    unsigned int m,//length of message in blocks
    unsigned int a,//length of associated data in blocks
    unsigned int mlen,//length of message in bytes
    unsigned int alen,//length of associated data in bytes
    uint8_t *out
){
    (void)(a);
    __m128i buf[1];
    uint64_t*buf64 = (uint64_t*)buf;
    if(m){
        spae_hswap64((uint64_t*)(ctx->ct),buf64);
        spae_aes128_xor(ctx->pt,buf,buf);
    }else{
        spae_aes128_xor(ctx->pt,ctx->ct,buf);//ct0^pt0=key
        for(unsigned int i=0;i<SPAE_BLOCKSIZE64;i++){buf64[i] = ~buf64[i];}
    }
    spae_aes128_xor(ctx->at,buf,buf);

    uint64_t padinfo64[SPAE_BLOCKSIZE64] = {0};
    uint32_t mlen32[2];
    uint32_t alen32[2];
    mlen32[0]=mlen*8;
    mlen32[1]=0;
    alen32[0]=alen*8;
    alen32[1]=0;
    uint32_t *padinfo32 = (uint32_t*)padinfo64;
    padinfo32[0] = mlen32[0];
    padinfo32[1] = alen32[0];
    padinfo32[2] = alen32[1] ^ mlen32[0];
    padinfo32[3] = alen32[0] ^ mlen32[1];

    spae_aes128_xor(padinfo64,buf,buf);
    spae_aes128_ekn(ctx,(uint8_t*)buf,(uint8_t*)buf);
    if(m){
        spae_aes128_xor(ctx->ct,buf,out);
    }else{
        spae_aes128_xor(ctx->pt,buf,out);
    }
}

static void spae_aes128_enc(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
){
    const uint8_t *in = message;
    const uint8_t *iad = ad;
    spae_aes128_t ctx_storage;
    spae_aes128_t *const ctx = &ctx_storage;

    spae_aes128_init(
        ctx,
        key,
        nonce,
        message,
        ad,
        0,//int decrypt,
        ciphertext
    );

    size_t m = (mlen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;
    size_t a = (alen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;

    if(ctx->obuf128){
        if(a){
            for(size_t i = 0; i<a-1; i++){//process all blocks except last one
                spae_aes128_process_ad(ctx,iad);
                iad+=SPAE_BLOCKSIZE;
            }
            const uint8_t *last_block = iad;
            ctx->buf[0] = _mm_setzero_si128();
            unsigned int remaining = alen % SPAE_BLOCKSIZE;
            if(remaining){//need to pad the last block
                memcpy(ctx->buf,iad,remaining);
                last_block = (const uint8_t *)ctx->buf;
            }
            spae_aes128_process_ad(ctx,last_block);
        }

        if(m){
            unsigned int remaining = mlen % SPAE_BLOCKSIZE;
            __m128i last_p[1];
            if(remaining){//need to pad the last block
                for(size_t i = 0; i<m-1; i++){//process all blocks except last one
                    spae_aes128_enc_core_aligned(ctx,(__m128i *)in);
                    in+=SPAE_BLOCKSIZE;
                }
                if(remaining==0) remaining = SPAE_BLOCKSIZE;//copy always last block into a buffer to support out=in case
                else last_p[0] = _mm_setzero_si128();
                memcpy(last_p,in,remaining);
                spae_aes128_enc_core_aligned(ctx,last_p);
            } else {
                spae_aes128_enc_blocks(ctx,(__m128i *)in,m);
            }
        }
        __m128i buf;
        uint64_t*buf64 = (uint64_t*)&buf;
        if(m){
            spae_hswap64((uint64_t*)ctx->ct,(uint64_t*)&buf);
            buf = _mm_xor_si128(ctx->pt[0],buf);
        } else {
            buf = _mm_xor_si128(ctx->pt[0],ctx->ct[0]);
            for(unsigned int i=0;i<SPAE_BLOCKSIZE64;i++){buf64[i] = ~buf64[i];}
        }
        buf = _mm_xor_si128(buf,ctx->at[0]);
        __m128i padinfo128[1];
        uint64_t *padinfo64 = (uint64_t*)padinfo128;

        uint32_t mlen32[2];
        uint32_t alen32[2];
        mlen32[0]=mlen*8;
        mlen32[1]=0;
        alen32[0]=alen*8;
        alen32[1]=0;
        uint32_t *padinfo32 = (uint32_t*)padinfo64;
        padinfo32[0] = mlen32[0];
        padinfo32[1] = alen32[0];
        padinfo32[2] = alen32[1] ^ mlen32[0];
        padinfo32[3] = alen32[0] ^ mlen32[1];


        buf = _mm_xor_si128(padinfo128[0],buf);
        DO_ENC_BLOCK_ALIGNED(buf,buf,ctx->kn);
        if(m){
            ctx->obuf128[0] = _mm_xor_si128(ctx->ct[0],buf);
        }else{
            ctx->obuf128[0] = _mm_xor_si128(ctx->pt[0],buf);
        }
        ctx->obuf = (uint8_t*)ctx->obuf128;
    }else{
        if(a){
            for(size_t i = 0; i<a-1; i++){//process all blocks except last one
                spae_aes128_process_ad(ctx,iad);
                iad+=SPAE_BLOCKSIZE;
            }
            const uint8_t *last_block = iad;
            uint8_t buf[SPAE_BLOCKSIZE] = {0};
            unsigned int remaining = alen % SPAE_BLOCKSIZE;
            if(remaining){//need to pad the last block
                memcpy(buf,iad,remaining);
                last_block = buf;
            }
            spae_aes128_process_ad(ctx,last_block);
        }
        if(m){
            for(size_t i = 0; i<m-1; i++){//process all blocks except last one
                spae_aes128_enc_core(ctx,in);
                in+=SPAE_BLOCKSIZE;
            }
            __m128i last_p[1];
            unsigned int remaining = mlen % SPAE_BLOCKSIZE;
            if(remaining==0) remaining = SPAE_BLOCKSIZE;//copy always last block into a buffer to support out=in case
            else last_p[0] = _mm_setzero_si128();
            memcpy(last_p,in,remaining);
            spae_aes128_enc_core(ctx,(uint8_t*)last_p);
        }
        spae_compute_tag(ctx,m,a,mlen,alen,ctx->obuf);
    }

    ctx->obuf+=SPAE_BLOCKSIZE;
    *clen = ctx->obuf - ciphertext;
}

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
static int spae_aes128_dec(
    const uint8_t *const key,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message,
    size_t mlen
){
    if(clen<SPAE_BLOCKSIZE) return -1;

    const uint8_t *in = ciphertext;
    const uint8_t *iad = ad;
    spae_aes128_t ctx_storage;
    spae_aes128_t *const ctx = &ctx_storage;

    spae_aes128_init(
        ctx,
        key,
        nonce,
        message,
        ad,
        1,//int decrypt,
        message
    );

    size_t m = (mlen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;
    size_t a = (alen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;

    if(m){
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            spae_aes128_dec_core(ctx,in);
            in+=SPAE_BLOCKSIZE;
        }
        unsigned int remaining = mlen % SPAE_BLOCKSIZE;
        if(remaining){//last block was padded
            __m128i buf[1];
            uint8_t*last_obuf = ctx->obuf;
            ctx->obuf = (uint8_t*)buf;
            spae_aes128_dec_core(ctx,in);
            memcpy(last_obuf,buf,remaining);
        }else{
            spae_aes128_dec_core(ctx,in);
        }
        in+=SPAE_BLOCKSIZE;
    }
    if(a){
        for(size_t i = 0; i<a-1; i++){//process all blocks except last one
            spae_aes128_process_ad(ctx,iad);
            iad+=SPAE_BLOCKSIZE;
        }
        const uint8_t *last_block = iad;
        uint8_t buf[SPAE_BLOCKSIZE] = {0};
        unsigned int remaining = alen % SPAE_BLOCKSIZE;
        if(remaining){//need to pad the last block
            memcpy(buf,iad,remaining);
            last_block = buf;
        }
        spae_aes128_process_ad(ctx,last_block);
    }

    uint8_t buf[SPAE_BLOCKSIZE];
    spae_compute_tag(ctx,m,a,mlen,alen,buf);

    if(memcmp(buf,in,SPAE_BLOCKSIZE)){
        memset(message,0,mlen);//erase all output
        return ~SPAE_PASS;
    }

    return SPAE_PASS;
}

#endif
