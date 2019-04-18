/**
SPAE Single Pass Authenticated Encryption v0.12
Sebastien Riou, November 18th 2018

Reference implementation meant to be portable on any platform with a c99 compiler
It is meant to fit in the supercop framework
*/


#ifndef __SPAE_AES128_H__
#define __SPAE_AES128_H__



#define SPAE_DBG_EN 0

#if SPAE_DBG_EN
    #define SPAE_DBG(a) a;
#else
    #define SPAE_DBG(a)
#endif


#include <stdint.h>
#include <string.h>
#include "aes_ref.h"

#define SPAE_PASS 0
#define SPAE_BLOCKSIZE 16
#define SPAE_KEYSIZE 16

typedef struct spae_aes128_struct_t {
    const uint8_t * key;
    uint8_t kn[SPAE_BLOCKSIZE];
    uint8_t pt[SPAE_BLOCKSIZE];
    uint8_t ct[SPAE_BLOCKSIZE];
    size_t mlen;
    uint8_t at[SPAE_BLOCKSIZE];
    size_t alen;
    uint8_t *obuf;
    int decrypt;
} spae_aes128_t;

#if SPAE_DBG_EN
#include <stdio.h>
#include <assert.h>
#include "bytes_utils.h"

static void spae_print_state(
    spae_aes128_t *const ctx
){
    (void)xor_bytes;
    (void)println_bytes;
    println_128("pt=",ctx->pt);
    println_128("ct=",ctx->ct);
    println_128("at=",ctx->at);
}
#endif

static void spae_hswap(uint8_t*b){
    const unsigned int half_len = SPAE_BLOCKSIZE/2;
    for(unsigned int i=0;i<half_len;i++){
        uint8_t buf = b[i];
        b[i] = b[half_len+i];
        b[half_len+i] = buf;
    }
}

static void spae_aes128_ek(
    spae_aes128_t *const ctx,
    const uint8_t *const ib,
    uint8_t *const ob
){
    aes_ref_enc128_block(ob,0,ib,ctx->key);
}

static void spae_aes128_ekn(
    spae_aes128_t *const ctx,
    const uint8_t *const ib,
    uint8_t *const ob
){
    aes_ref_enc128_block(ob,0,ib,ctx->kn);
}

static void spae_aes128_dkn(
    spae_aes128_t *const ctx,
    const uint8_t *const ib,
    uint8_t *const ob
){
    aes_ref_dec128_block(ob,0,ib,ctx->kn);
}

static void spae_aes128_xor(
    const uint8_t *const a,//exactly one block of input
    const uint8_t *const b,
    uint8_t *const y
){
    for(unsigned int i=0;i<SPAE_BLOCKSIZE;i++){
        y[i] = a[i] ^ b[i];
    }
}

static void spae_aes128_init(
    spae_aes128_t *const ctx,
    const uint8_t *const key,
    const uint8_t *const nonce,
    int decrypt,
    uint8_t *out_buffer//output buffer
){
    ctx->key = key;

    ctx->obuf = out_buffer;

    ctx->mlen=0;
    ctx->alen=0;
    ctx->decrypt = decrypt;

    //memcpy(ctx->ct,ctx->key,SPAE_KEYSIZE);
    spae_aes128_ek(ctx,ctx->key,ctx->ct);
    spae_aes128_xor(ctx->key,ctx->ct,ctx->pt);
    spae_aes128_xor(ctx->key,nonce,ctx->kn);
    memset(ctx->at,0x00,SPAE_BLOCKSIZE);
    SPAE_DBG(spae_print_state(ctx);)
}

static void spae_aes128_enc_core(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input, WARNING: may also be the output
){
    uint8_t buf[SPAE_BLOCKSIZE];
    uint8_t buf2[SPAE_BLOCKSIZE];
    memcpy(buf,ctx->ct,SPAE_BLOCKSIZE);
    spae_aes128_xor(ctx->ct,ctx->pt,ctx->ct);
    spae_aes128_xor(ctx->pt,ib,buf2);
    spae_aes128_ekn(ctx,buf2,buf2);
    spae_aes128_xor(buf2,ib,ctx->pt);
    spae_aes128_xor(buf2,buf,ctx->obuf);
    ctx->obuf+=SPAE_BLOCKSIZE;
    SPAE_DBG(spae_print_state(ctx);)
}

static void spae_aes128_dec_core(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input, WARNING: may also be the output
){
    uint8_t buf[SPAE_BLOCKSIZE];
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

static void spae_compute_tag(
    spae_aes128_t *const ctx,
    unsigned int m,//length of message in blocks
    unsigned int a,//length of associated data in blocks
    unsigned int mlen,//length of message in bytes
    unsigned int alen,//length of associated data in bytes
    uint8_t *out
){
    (void)(a);
    uint8_t buf[SPAE_BLOCKSIZE];
    if(m){
        memcpy(buf,ctx->ct,SPAE_BLOCKSIZE);
        spae_hswap(buf);
        spae_aes128_xor(ctx->pt,buf,buf);
    }else{
        spae_aes128_xor(ctx->pt,ctx->ct,buf);//ct0^pt0=key
        for(unsigned int i=0;i<SPAE_BLOCKSIZE;i++){buf[i] = ~buf[i];}
    }
    spae_aes128_xor(ctx->at,buf,buf);
    uint8_t padinfo[SPAE_BLOCKSIZE] = {0};
    uint64_t mpadinfo = mlen*8;
    uint64_t apadinfo = alen*8;
    for(unsigned int i=0;i<4;i++){padinfo[i+0] = mpadinfo>>(8*i);}
    for(unsigned int i=0;i<4;i++){padinfo[i+4] = apadinfo>>(8*i);}
    uint64_t apadinfo_swap = (apadinfo>>32)^((apadinfo & 0xFFFFFFFF)<<32);
    uint64_t x = apadinfo_swap ^ mpadinfo;
    for(unsigned int i=0;i<8;i++){padinfo[i+8] = x>>(8*i);}
    spae_aes128_xor(padinfo,buf,buf);
    spae_aes128_ekn(ctx,buf,buf);
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

    size_t m = (mlen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;
    size_t a = (alen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;

    #if SPAE_DBG_EN
        println_128("key=",key);
        println_128("nonce=",nonce);
        printf("mlen=%lu\n",mlen)
        for(int i = 0;i<((int)m)-1;i++){println_128("m=",message+SPAE_BLOCKSIZE*i);}
        printf("m=");for(int i = (m-1)*SPAE_BLOCKSIZE;i<mlen;i++){printf("%02X",*(message+i));};printf("\n")
        printf("alen=%lu\n",alen)
        for(int i = 0;i<((int)a)-1;i++){println_128("a=",ad+SPAE_BLOCKSIZE*i);}
        printf("a=");for(int i = (a-1)*SPAE_BLOCKSIZE;i<alen;i++){printf("%02X",*(ad+i));};printf("\n");
    #endif


    spae_aes128_init(
        ctx,
        key,
        nonce,
        0,//int decrypt,
        ciphertext
    );

    if(m){
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            spae_aes128_enc_core(ctx,in);
            in+=SPAE_BLOCKSIZE;
        }
        uint8_t buf[SPAE_BLOCKSIZE] = {0};
        unsigned int remaining = mlen % SPAE_BLOCKSIZE;
        if(remaining==0) remaining = SPAE_BLOCKSIZE;//copy always last block into a buffer to support out=in case
        memcpy(buf,in,remaining);
        spae_aes128_enc_core(ctx,buf);
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
    spae_compute_tag(ctx,m,a,mlen,alen,ctx->obuf);
    ctx->obuf+=SPAE_BLOCKSIZE;

    *clen = ctx->obuf - ciphertext;

    SPAE_DBG(printf("clen=%lu\n",*clen));
    SPAE_DBG(for(int i = 0;i<(*clen/SPAE_BLOCKSIZE);i++){println_128("c=",ciphertext+SPAE_BLOCKSIZE*i);});
    SPAE_DBG(printf("\n"));
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

    size_t m = (mlen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;
    size_t a = (alen + SPAE_BLOCKSIZE - 1) / SPAE_BLOCKSIZE;

    SPAE_DBG(println_128("key=",key);)
    SPAE_DBG(println_128("nonce=",nonce);)

    SPAE_DBG(printf("clen=%lu\n",clen));
    SPAE_DBG(assert(0==(clen%SPAE_BLOCKSIZE)));
    SPAE_DBG(for(int i = 0;i<(clen/SPAE_BLOCKSIZE);i++){println_128("c=",ciphertext+SPAE_BLOCKSIZE*i);});
    SPAE_DBG(printf("mlen=%lu\n",mlen));
    SPAE_DBG(printf("alen=%lu\n",alen));
    SPAE_DBG(for(int i = 0;i<((int)a)-1;i++){println_128("a=",ad+SPAE_BLOCKSIZE*i);});
    SPAE_DBG(printf("a=");for(int i = (a-1)*SPAE_BLOCKSIZE;i<alen;i++){printf("%02X",*(ad+i));};printf("\n"));


    spae_aes128_init(
        ctx,
        key,
        nonce,
        1,//int decrypt,
        message
    );

    if(m){
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            spae_aes128_dec_core(ctx,in);
            in+=SPAE_BLOCKSIZE;
        }
        unsigned int remaining = mlen % SPAE_BLOCKSIZE;
        uint8_t buf[SPAE_BLOCKSIZE];
        uint8_t *last_block = ctx->obuf;
        if(remaining){//last block was padded
            ctx->obuf = buf;
            spae_aes128_dec_core(ctx,in);
            memcpy(last_block,buf,remaining);
            last_block = buf;
        }else{
            spae_aes128_dec_core(ctx,in);
        }
        in+=SPAE_BLOCKSIZE;
        SPAE_DBG(println_128("last_block=",last_block););
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

    SPAE_DBG(for(int i = 0;i<((int)m)-1;i++){println_128("m=",message+SPAE_BLOCKSIZE*i);});
    SPAE_DBG(printf("m=");for(int i = (m-1)*SPAE_BLOCKSIZE;i<mlen;i++){printf("%02X",*(message+i));};printf("\n"));
    SPAE_DBG(printf("\n"));

    if(memcmp(buf,in,SPAE_BLOCKSIZE)){
        memset(message,0,mlen);//erase all output
        SPAE_DBG("tag mismatch!\n");
        SPAE_DBG(println_128("computed tag=",buf));
        SPAE_DBG(println_128("expected tag=",in));
        SPAE_DBG(printf("\n"));
        return ~SPAE_PASS;
    }

    return SPAE_PASS;
}

#endif
