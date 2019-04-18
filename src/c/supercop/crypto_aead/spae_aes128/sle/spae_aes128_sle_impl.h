/**
SPAE Single Pass Authenticated Encryption v0.12
Sebastien Riou, November 15th 2018

"Small Little Endian" implementation: favor code size over speed
TODO: decryption still use "ref" AES, switch to optimized one
It is meant to fit in the supercop framework
*/


#ifndef __SPAE_SLE_H__
#define __SPAE_SLE_H__

#include <limits.h>
#include <stdint.h>

//#if UINT_MAX == UINT32_MAX
//    #define SPAE_SLE_ALIGNEMENT_MASK 0x03
//#endif
//#if UINT_MAX == UINT64_MAX
//    #define SPAE_SLE_ALIGNEMENT_MASK 0x07
//#endif
//TODO: fix this, on x86_64 we get 0x03 and then run time errors...
#define SPAE_SLE_ALIGNEMENT_MASK 0x07

#define SPAE_SLE_IS_ALIGNED(a) (0==(((size_t)a)&SPAE_SLE_ALIGNEMENT_MASK))

#define SPAE_SLE_DBG_EN 0

#if SPAE_SLE_DBG_EN
    #define SPAE_SLE_DBG(a) a;
#else
    #define SPAE_SLE_DBG(a)
#endif

#include <string.h>
#include "aes_ref.h"

#define SPAE_SLE_PASS 0
#define SPAE_SLE_BLOCKSIZE 16
#define SPAE_SLE_KEYSIZE 16

#define SPAE_SLE_BLOCKSIZE64 2

typedef struct spae_aes128_struct_t spae_aes128_t;

typedef void (*spae_xor_t)(const void*const a,const void*const b,void*const out);

struct spae_aes128_struct_t {
    uint64_t pt[SPAE_SLE_BLOCKSIZE64];
    uint64_t ct[SPAE_SLE_BLOCKSIZE64];
    uint64_t at[SPAE_SLE_BLOCKSIZE64];
    uint64_t kn[SPAE_SLE_BLOCKSIZE64];
    spae_xor_t xor_block;
    size_t mlen;
    size_t alen;
    uint8_t *obuf;
    int decrypt;
};


#if SPAE_SLE_DBG_EN
#include <stdio.h>
#include <assert.h>
#include "bytes_utils.h"
static void spae_print_state(
    spae_aes128_t *const ctx
){
    (void)xor_bytes;
    (void)println_bytes;
    (void) bytes_utils_remove_unused_warnings;

    println_128("pt=",ctx->pt);
    println_128("ct=",ctx->ct);
    println_128("at=",ctx->at);
}
#endif

static void spae_hswap64(const uint64_t*const src,uint64_t*const dst){
    dst[1] = src[0];
    dst[0] = src[1];
}

static void spae_aes128_xor(
    const void*const a,//exactly one block of input
    const void*const b,
    void *const y
){
    const uint8_t *const ab=(const uint8_t *const)a;
    const uint8_t *const bb=(const uint8_t *const)b;
    uint8_t *const yb=(uint8_t *const)y;
    for(unsigned int i=0;i<SPAE_SLE_BLOCKSIZE;i++){
        yb[i] = ab[i] ^ bb[i];
    }
}

static void spae_aes128_xor_64(
    const uint64_t*const a,//exactly one block of input
    const uint64_t*const b,
    uint64_t *const y
){
    y[0] = a[0] ^ b[0];
    y[1] = a[1] ^ b[1];
}

//equivalent to CortexM0 ror instruction
static uint32_t ror(uint32_t in, uint32_t shift){return (in>>shift) ^ (in<<(32-shift));}

static uint32_t aes_xtime2_le32(uint32_t x){
	uint32_t a = ((x & 0x7f7f7f7f) << 1);
	uint32_t b = (x & 0x80808080) >> 7;
    uint32_t c = b * 0x1b;
    uint32_t out = a ^ c;
    return out;
}

static void spae_mixcolumn_quarter_opt2(uint32_t in, uint32_t *out){
  uint32_t x2 = aes_xtime2_le32(in);
  uint32_t x3 = in ^ x2;
  *out = x2 ^ ror(x3, 8) ^ ror(in, 16) ^ ror(in, 24);
}

#define SPAE_SLE_AES_SB_S(src,dst) (((uint32_t)(aes_ref_sbox[sbin_bytes[src]]))<<(dst*8))
#define SPAE_SLE_AES_MIXCOL_IN(b0,b1,b2,b3) (SPAE_SLE_AES_SB_S(b0,0) | SPAE_SLE_AES_SB_S(b1,1) | SPAE_SLE_AES_SB_S(b2,2) | SPAE_SLE_AES_SB_S(b3,3))

static void aes_enc128_round_le32(uint64_t *state, uint64_t *round_key){
    uint32_t* state_dwords = (uint32_t*)state;

    uint64_t sbin[2];
    uint8_t* sbin_bytes = (uint8_t*)sbin;
    sbin[0] = state[0]^round_key[0];
    sbin[1] = state[1]^round_key[1];

	uint32_t work;
	work = SPAE_SLE_AES_MIXCOL_IN( 0, 5,10,15);
	spae_mixcolumn_quarter_opt2(work,state_dwords+0);
	work = SPAE_SLE_AES_MIXCOL_IN( 4, 9,14, 3);
	spae_mixcolumn_quarter_opt2(work,state_dwords+1);
	work = SPAE_SLE_AES_MIXCOL_IN( 8,13, 2, 7);
	spae_mixcolumn_quarter_opt2(work,state_dwords+2);
	work = SPAE_SLE_AES_MIXCOL_IN(12, 1, 6,11);
	spae_mixcolumn_quarter_opt2(work,state_dwords+3);
}

//should be static but in this case gcc seems to skip it entirely with -Os optimization!
void spae_sle_aes_enc128_last_round_le32(uint64_t *state, uint64_t *round_key){
    uint32_t* state_dwords = (uint32_t*)state;

    uint64_t sbin[2];
    uint8_t* sbin_bytes = (uint8_t*)sbin;
    sbin[0] = state[0]^round_key[0];
    sbin[1] = state[1]^round_key[1];

	state_dwords[0] = SPAE_SLE_AES_MIXCOL_IN( 0, 5,10,15);
	state_dwords[1] = SPAE_SLE_AES_MIXCOL_IN( 4, 9,14, 3);
	state_dwords[2] = SPAE_SLE_AES_MIXCOL_IN( 8,13, 2, 7);
	state_dwords[3] = SPAE_SLE_AES_MIXCOL_IN(12, 1, 6,11);
}


static uint64_t round_keys[11][2];

static void aes_enc128_init(const void *const keyv){
    const uint8_t *const key = (const uint8_t *const )keyv;
	uint32_t round_key[4];
	uint8_t* round_key_bytes = (uint8_t*)round_key;
	uint8_t r, rc = 1;

	memcpy(round_key,key,16);
	memcpy(round_keys[0],round_key,16);
	for( r = 1 ; r <= 10 ; r++ ){
        aes_ref_update_encrypt_key_128( round_key_bytes, &rc );
        memcpy(round_keys[r],round_key,16);
    }
}

static void aes_enc128_block_le32(const uint64_t *const in,uint64_t *const out){
	uint64_t *const state=out;
	uint8_t r;

    state[0] = in[0];
    state[1] = in[1];
	for( r = 0 ; r < 9 ; r++ ){
        SPAE_SLE_DBG(println_128("state=",state);)
        SPAE_SLE_DBG(println_128("key  =",round_keys[r]);)
		aes_enc128_round_le32(state,round_keys[r]);
	}
    SPAE_SLE_DBG(println_128("state=",state);)
    SPAE_SLE_DBG(println_128("key  =",round_keys[9]);)

	spae_sle_aes_enc128_last_round_le32(state,round_keys[9]);
    SPAE_SLE_DBG(println_128("state=",state);)
    SPAE_SLE_DBG(println_128("key  =",round_keys[10]);)

    state[0] ^= round_keys[10][0];
    state[1] ^= round_keys[10][1];
    SPAE_SLE_DBG(println_128("final state=",state);)
}

static void spae_aes128_enc_core(
    spae_aes128_t *const ctx,
    const void *const ib//exactly one block of input, WARNING: may also be the output
){
    uint64_t buf[SPAE_SLE_BLOCKSIZE64];
    uint64_t buf2[SPAE_SLE_BLOCKSIZE64];
    buf[0]=ctx->ct[0];
    buf[1]=ctx->ct[1];
    spae_aes128_xor_64(ctx->ct,ctx->pt,ctx->ct);
    ctx->xor_block(ctx->pt,ib,buf2);
    aes_enc128_block_le32(buf2,buf2);
    ctx->xor_block(buf2,ib,ctx->pt);
    ctx->xor_block(buf2,buf,ctx->obuf);
    ctx->obuf+=SPAE_SLE_BLOCKSIZE;
}

static void spae_aes128_dkn(
    spae_aes128_t *const ctx,
    const void *const i,
    void *const o
){
    const uint8_t *const ib=(const uint8_t *const)i;
    uint8_t *const ob=(uint8_t *const)o;
    aes_ref_dec128_block(ob,0,ib,(uint8_t*)ctx->kn);
}
#include <assert.h>

static void spae_aes128_init(
    spae_aes128_t *const ctx,
    const uint8_t *const key,
    const uint8_t *const nonce,
    int decrypt,
    uint8_t *out_buffer//output buffer
){
    //ctx->key = key;
    (void)aes_ref_enc128_block;

    ctx->obuf = out_buffer;

    ctx->mlen=0;
    ctx->alen=0;
    ctx->decrypt = decrypt;
    uint64_t k[2];
    memcpy(k,key,16);
    aes_enc128_init(k);
    aes_enc128_block_le32(k,ctx->ct);
    spae_aes128_xor_64(ctx->ct,k,ctx->pt);

    spae_aes128_xor(k,nonce,ctx->kn);
    memset(ctx->at,0x00,SPAE_SLE_BLOCKSIZE);
}

static void spae_aes128_dec_core(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    uint8_t buf[SPAE_SLE_BLOCKSIZE];
    spae_aes128_xor(ctx->ct,ib,buf);
    spae_aes128_xor(ctx->ct,ctx->pt,ctx->ct);
    spae_aes128_dkn(ctx,buf,ctx->obuf);
    spae_aes128_xor(ctx->pt,ctx->obuf,ctx->obuf);
    spae_aes128_xor(buf,ctx->obuf,ctx->pt);
    ctx->obuf+=SPAE_SLE_BLOCKSIZE;
}

static void spae_aes128_process_ad(
    spae_aes128_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    ctx->xor_block(ctx->at,ib,ctx->at);
    aes_enc128_block_le32(ctx->at,ctx->at);
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
    uint64_t buf[SPAE_SLE_BLOCKSIZE64];
    if(m){
        spae_hswap64(ctx->ct,buf);
        spae_aes128_xor_64(ctx->pt,buf,buf);
    }else{
        spae_aes128_xor_64(ctx->pt,ctx->ct,buf);//ct0^pt0=key
        for(unsigned int i=0;i<SPAE_SLE_BLOCKSIZE64;i++){buf[i] = ~buf[i];}
    }
    spae_aes128_xor_64(ctx->at,buf,buf);

    uint64_t padinfo64[SPAE_SLE_BLOCKSIZE64] = {0};
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


    SPAE_SLE_DBG(println_128("PADINFO=",(uint8_t*)padinfo64));

    spae_aes128_xor_64(padinfo64,buf,buf);
    aes_enc128_block_le32(buf,buf);
    if(m){
        ctx->xor_block(ctx->ct,buf,out);
    }else{
        ctx->xor_block(ctx->pt,buf,out);
    }
}

void spae_sle_aes128_enc(
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

    size_t m = (mlen + SPAE_SLE_BLOCKSIZE - 1) / SPAE_SLE_BLOCKSIZE;
    size_t a = (alen + SPAE_SLE_BLOCKSIZE - 1) / SPAE_SLE_BLOCKSIZE;

    SPAE_SLE_DBG((void)spae_print_state;)
    SPAE_SLE_DBG(println_128("key=",key);)
    SPAE_SLE_DBG(println_128("nonce=",nonce);)
    SPAE_SLE_DBG(printf("mlen=%lu\n",mlen));
    if(m){
        SPAE_SLE_DBG(for(unsigned int i = 0;i<((unsigned int)m)-1;i++){println_128("m=",message+SPAE_SLE_BLOCKSIZE*i);});
        SPAE_SLE_DBG(printf("m=");for(unsigned int i = (m-1)*SPAE_SLE_BLOCKSIZE;i<mlen;i++){printf("%02X",*(message+i));};printf("\n"));
    }
    SPAE_SLE_DBG(printf("alen=%lu\n",alen));
    if(a){
        SPAE_SLE_DBG(for(unsigned int i = 0;i<((unsigned int)a)-1;i++){println_128("a=",ad+SPAE_SLE_BLOCKSIZE*i);});
        SPAE_SLE_DBG(printf("a=");for(unsigned int i = (a-1)*SPAE_SLE_BLOCKSIZE;i<alen;i++){printf("%02X",*(ad+i));};printf("\n"));
    }

    spae_aes128_init(
        ctx,
        key,
        nonce,
        0,//int decrypt,
        ciphertext
    );

    if(a){
        if(SPAE_SLE_IS_ALIGNED(iad)){
            ctx->xor_block = (spae_xor_t)spae_aes128_xor_64;
        } else {
            ctx->xor_block = (spae_xor_t)spae_aes128_xor;
        }
        for(size_t i = 0; i<a-1; i++){//process all blocks except last one
            spae_aes128_process_ad(ctx,iad);
            iad+=SPAE_SLE_BLOCKSIZE;
        }
        const uint8_t *last_block = iad;
        uint64_t buf64[SPAE_SLE_BLOCKSIZE64] = {0};
        uint8_t*buf=(uint8_t*)buf64;
        unsigned int remaining = alen % SPAE_SLE_BLOCKSIZE;
        if(remaining){//need to pad the last block
            memcpy(buf,iad,remaining);
            last_block = buf;
        }
        spae_aes128_process_ad(ctx,last_block);
    }

    if(SPAE_SLE_IS_ALIGNED(in) && SPAE_SLE_IS_ALIGNED(ctx->obuf)){
        ctx->xor_block = (spae_xor_t)spae_aes128_xor_64;
    } else {
        ctx->xor_block = (spae_xor_t)spae_aes128_xor;
    }
    aes_enc128_init(ctx->kn);

    if(m){
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            spae_aes128_enc_core(ctx,(const uint64_t*const)in);
            in+=SPAE_SLE_BLOCKSIZE;
        }
        uint64_t buf64[SPAE_SLE_BLOCKSIZE64] = {0};
        uint8_t *buf = (uint8_t *)buf64;
        unsigned int remaining = mlen % SPAE_SLE_BLOCKSIZE;
        if(remaining==0) remaining = SPAE_SLE_BLOCKSIZE;//copy always last block into a buffer to support out=in case
        memcpy(buf,in,remaining);
        spae_aes128_enc_core(ctx,buf64);
    }
    spae_compute_tag(ctx,m,a,mlen,alen,ctx->obuf);
    ctx->obuf+=SPAE_SLE_BLOCKSIZE;

    *clen = ctx->obuf - ciphertext;

    SPAE_SLE_DBG(printf("clen=%lu\n",*clen));
    SPAE_SLE_DBG(for(unsigned int i = 0;i<(*clen/SPAE_SLE_BLOCKSIZE);i++){println_128("c=",ciphertext+SPAE_SLE_BLOCKSIZE*i);});
    SPAE_SLE_DBG(printf("\n"));
}

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
){
    if(clen<SPAE_SLE_BLOCKSIZE) return -1;

    const uint8_t *in = ciphertext;
    const uint8_t *iad = ad;
    spae_aes128_t ctx_storage;
    spae_aes128_t *const ctx = &ctx_storage;

    size_t m = (mlen + SPAE_SLE_BLOCKSIZE - 1) / SPAE_SLE_BLOCKSIZE;
    size_t a = (alen + SPAE_SLE_BLOCKSIZE - 1) / SPAE_SLE_BLOCKSIZE;

    SPAE_SLE_DBG(println_128("key=",key);)
    SPAE_SLE_DBG(println_128("nonce=",nonce);)

    SPAE_SLE_DBG(printf("clen=%lu\n",clen));
    SPAE_SLE_DBG(assert(0==(clen%SPAE_SLE_BLOCKSIZE)));
    SPAE_SLE_DBG(for(unsigned int i = 0;i<(clen/SPAE_SLE_BLOCKSIZE);i++){println_128("c=",ciphertext+SPAE_SLE_BLOCKSIZE*i);});
    SPAE_SLE_DBG(printf("mlen=%lu\n",mlen));
    SPAE_SLE_DBG(printf("alen=%lu\n",alen));
    if(a){
        SPAE_SLE_DBG(for(unsigned int i = 0;i<((unsigned int)a)-1;i++){println_128("a=",ad+SPAE_SLE_BLOCKSIZE*i);});
        SPAE_SLE_DBG(printf("a=");for(unsigned int i = (a-1)*SPAE_SLE_BLOCKSIZE;i<alen;i++){printf("%02X",*(ad+i));};printf("\n"));
    }

    spae_aes128_init(
        ctx,
        key,
        nonce,
        1,//int decrypt,
        message
    );

    if(a){
        if(SPAE_SLE_IS_ALIGNED(iad)){
            ctx->xor_block = (spae_xor_t)spae_aes128_xor_64;
        } else {
            ctx->xor_block = (spae_xor_t)spae_aes128_xor;
        }
        for(size_t i = 0; i<a-1; i++){//process all blocks except last one
            spae_aes128_process_ad(ctx,iad);
            iad+=SPAE_SLE_BLOCKSIZE;
        }
        const uint8_t *last_block = iad;
        uint64_t buf64[SPAE_SLE_BLOCKSIZE64] = {0};
        uint8_t*buf=(uint8_t*)buf64;
        unsigned int remaining = alen % SPAE_SLE_BLOCKSIZE;
        if(remaining){//need to pad the last block
            memcpy(buf,iad,remaining);
            last_block = buf;
        }
        spae_aes128_process_ad(ctx,last_block);
    }
    if(SPAE_SLE_IS_ALIGNED(in) && SPAE_SLE_IS_ALIGNED(ctx->obuf)){
        ctx->xor_block = (spae_xor_t)spae_aes128_xor_64;
    } else {
        ctx->xor_block = (spae_xor_t)spae_aes128_xor;
    }
    aes_enc128_init(ctx->kn);

    if(m){
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            spae_aes128_dec_core(ctx,in);
            in+=SPAE_SLE_BLOCKSIZE;
        }
        unsigned int remaining = mlen % SPAE_SLE_BLOCKSIZE;
        uint64_t buf64[SPAE_SLE_BLOCKSIZE64] = {0};
        uint8_t*buf=(uint8_t*)buf64;
        uint8_t *last_block = ctx->obuf;
        if(remaining){//last block was padded
            last_block = ctx->obuf;
            ctx->obuf = buf;
            spae_aes128_dec_core(ctx,in);
            memcpy(last_block,buf,remaining);
            last_block = buf;
        }else{
            spae_aes128_dec_core(ctx,in);
        }
        in+=SPAE_SLE_BLOCKSIZE;
    }

    uint64_t buf[SPAE_SLE_BLOCKSIZE64];
    spae_compute_tag(ctx,m,a,mlen,alen,(uint8_t*)buf);

    if(m){
        SPAE_SLE_DBG(for(unsigned int i = 0;i<((unsigned int)m)-1;i++){println_128("m=",message+SPAE_SLE_BLOCKSIZE*i);});
        SPAE_SLE_DBG(printf("m=");for(unsigned int i = (m-1)*SPAE_SLE_BLOCKSIZE;i<mlen;i++){printf("%02X",*(message+i));};printf("\n"));
    }
    SPAE_SLE_DBG(printf("\n"));

    if(memcmp(buf,in,SPAE_SLE_BLOCKSIZE)){
        memset(message,0,mlen);//erase all output
        SPAE_SLE_DBG(printf("tag mismatch!\n"));
        SPAE_SLE_DBG(println_128("computed tag=",buf));
        SPAE_SLE_DBG(println_128("expected tag=",in));
        SPAE_SLE_DBG(printf("\n"));
        return ~SPAE_SLE_PASS;
    }

    return SPAE_SLE_PASS;
}

#endif
