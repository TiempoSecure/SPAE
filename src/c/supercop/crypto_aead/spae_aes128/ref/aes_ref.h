/**
AES-128 functions
Sebastien Riou, September 24th 2018

Reference implementation meant to be portable on any platform with a c99 compiler
"Reference" here just means it is trusted to produce correct results and is not optimized in any way

The useful functions are:
void aes_ref_enc128_block(uint8_t *out, uint8_t *key_out, const uint8_t *in, const uint8_t *key)
void aes_ref_dec128_block(uint8_t *out, uint8_t *key_out, const uint8_t *in, const uint8_t *key)

set key_out to 0 if you don't need the last round key (typically you don't)

*/
#ifndef __AES_REF_H__
#define __AES_REF_H__

static uint8_t aes_ref_inv_xtime2(uint8_t x){
	return (((x) >> 1) ^ ((x) & 1 ? 0x8D : 0));
}

static uint8_t aes_ref_xtime2(uint8_t in){
	uint8_t out = in<<1;
	if(in &  0x80)
		out ^= 0x1B;
	return out;
}
static uint8_t aes_ref_xtime3(uint8_t in){
	return aes_ref_xtime2(in) ^ in;
}
static uint8_t aes_ref_xtime4(uint8_t in){
	return aes_ref_xtime2(aes_ref_xtime2(in));
}
static uint8_t aes_ref_xtime8(uint8_t in){
	return aes_ref_xtime2(aes_ref_xtime4(in));
}
static uint8_t aes_ref_xtime9(uint8_t in){
	return aes_ref_xtime8(in)^in;
}
static uint8_t aes_ref_xtimeB(uint8_t in){
	return aes_ref_xtime9(in) ^ aes_ref_xtime2(in);
}
static uint8_t aes_ref_xtimeD(uint8_t in){
	return aes_ref_xtime9(in) ^ aes_ref_xtime4(in);
}
static uint8_t aes_ref_xtimeE(uint8_t in){
	return aes_ref_xtime8(in) ^ aes_ref_xtime4(in) ^ aes_ref_xtime2(in);
}

static const uint8_t aes_ref_sbox[256] = {
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t aes_ref_inv_sbox[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static void aes_ref_update_encrypt_key_128( uint8_t k[16], uint8_t *rc ){
	uint8_t cc;

    k[0] ^= aes_ref_sbox[k[13]] ^ *rc;
    k[1] ^= aes_ref_sbox[k[14]];
    k[2] ^= aes_ref_sbox[k[15]];
    k[3] ^= aes_ref_sbox[k[12]];
    *rc = aes_ref_xtime2( *rc );

    for(cc = 4; cc < 16; cc += 4 )
    {
        k[cc + 0] ^= k[cc - 4];
        k[cc + 1] ^= k[cc - 3];
        k[cc + 2] ^= k[cc - 2];
        k[cc + 3] ^= k[cc - 1];
    }
}

//expect *rc=0x36 at the beginning
static void aes_ref_update_decrypt_key_128( uint8_t k[16], uint8_t *rc ){
	uint8_t cc;

    for( cc = 12; cc > 0; cc -= 4 )
    {
        k[cc + 0] ^= k[cc - 4];
        k[cc + 1] ^= k[cc - 3];
        k[cc + 2] ^= k[cc - 2];
        k[cc + 3] ^= k[cc - 1];
    }
    k[0] ^= aes_ref_sbox[k[13]] ^ *rc;
    k[1] ^= aes_ref_sbox[k[14]];
    k[2] ^= aes_ref_sbox[k[15]];
    k[3] ^= aes_ref_sbox[k[12]];
	*rc = aes_ref_inv_xtime2(*rc);
}

static void aes_ref_mixcolumn_quarter(uint8_t *in, uint8_t *out){
	uint8_t in_buf[4];
	memcpy(in_buf,in,4);//just in case out=in
	for(int i=0;i<4;i++)
		out[i] =  aes_ref_xtime2(in_buf[i]) ^ aes_ref_xtime3(in_buf[(i+1)%4]) ^ in_buf[(i+2)%4] ^ in_buf[(i+3)%4];
}

static void aes_ref_mixcolumns(uint8_t *in, uint8_t *out){
	for(int i=0;i<4;i++)
		aes_ref_mixcolumn_quarter(out+i*4,in+i*4);
}

static void aes_ref_inv_mixcolumn_quarter(uint8_t *in, uint8_t *out){
	uint8_t in_buf[4];
	memcpy(in_buf,in,4);//just in case out=in
	for(int i=0;i<4;i++)
		out[i] =  aes_ref_xtimeE(in_buf[i]) ^ aes_ref_xtimeB(in_buf[(i+1)%4]) ^ aes_ref_xtimeD(in_buf[(i+2)%4]) ^ aes_ref_xtime9(in_buf[(i+3)%4]);
}

static void aes_ref_inv_mixcolumns(uint8_t *in, uint8_t *out){
	for(int i=0;i<4;i++)
		aes_ref_inv_mixcolumn_quarter(out+i*4,in+i*4);
}

static void aes_ref_shiftRow(uint8_t *in) {
    uint8_t offset=0;
	uint8_t b = in[offset+2];
    in[offset+2]  = in[offset+10];
    in[offset+10] = b;

    b = in[offset+6];
    in[offset+6]  = in[offset+14];
    in[offset+14] = b;

    b = in[offset+1];
    in[offset+1]  = in[offset+5];
    in[offset+5]  = in[offset+9];
    in[offset+9]  = in[offset+13];
    in[offset+13] = b;

    b = in[offset+3];
    in[offset+3] = in[offset+15];
    in[offset+15] = in[offset+11];
    in[offset+11] = in[offset+7];
    in[offset+7] = b;
}

static void aes_ref_shift_rows(uint8_t *out, uint8_t *in){
	if(out!=in)
		memcpy(out,in,16);
	aes_ref_shiftRow(out);
}

static void aes_ref_InvShiftRow (uint8_t *in)  {
	uint8_t inOff=0;
    uint8_t b = in[inOff+10];
    in[inOff+10]  = in[inOff+2];
    in[inOff+2] = b;

    b = in[inOff+14];
    in[inOff+14]  = in[inOff+6];
    in[inOff+6] = b;

    b = in[inOff+13];
    in[inOff+13]  = in[inOff+9];
    in[inOff+9]  = in[inOff+5];
    in[inOff+5]  = in[inOff+1];
    in[inOff+1] = b;

    b = in[inOff+7];
    in[inOff+7] = in[inOff+11];
    in[inOff+11] = in[inOff+15];
    in[inOff+15] = in[inOff+3];
    in[inOff+3] = b;
}
static void aes_ref_inv_shift_rows(uint8_t *out, uint8_t *in){
	if(out!=in)
		memcpy(out,in,16);
	aes_ref_InvShiftRow(out);
}
static void aes_ref_sub_bytes(uint8_t *out, const uint8_t *in){
	uint8_t in_buf[16];
	memcpy(in_buf,in,16);//just in case out=in
	for(unsigned int i=0;i<16;i++){
		out[i]=aes_ref_sbox[in_buf[i]];
	}
}

static void aes_ref_inv_sub_bytes(uint8_t *out, const uint8_t *in){
	uint8_t in_buf[16];
	memcpy(in_buf,in,16);//just in case out=in
	for(unsigned int i=0;i<16;i++){
		out[i]=aes_ref_inv_sbox[in_buf[i]];
	}
}

static void aes_ref_xor_block( uint32_t *d, const uint32_t *s ){
    d[ 0] ^= s[ 0];
    d[ 1] ^= s[ 1];
    d[ 2] ^= s[ 2];
    d[ 3] ^= s[ 3];
}

static void aes_ref_encrypt_key_schedule_128(uint8_t *key){
	uint8_t r, rc = 1;
    for( r = 1 ; r <= 10 ; ++r ){
		aes_ref_update_encrypt_key_128( key, &rc );
    }
}

static void aes_ref_enc128_block(uint8_t *out, uint8_t *key_out, const uint8_t *in, const uint8_t *key){
	uint32_t state[4];
	uint32_t round_key[4];
	uint8_t* state_bytes = (uint8_t*)state;
	uint8_t* round_key_bytes = (uint8_t*)round_key;
	uint8_t r, rc = 1;

	memcpy(round_key,key,16);
	memcpy(state,in,16);

	for( r = 1 ; r <= 10 ; r++ ){
        aes_ref_xor_block(state, round_key);
		aes_ref_sub_bytes(state_bytes,state_bytes);
		aes_ref_shift_rows(state_bytes,state_bytes);
		if(r<=9){
			aes_ref_mixcolumns(state_bytes,state_bytes);
		}
        aes_ref_update_encrypt_key_128( round_key_bytes, &rc );
    }
    aes_ref_xor_block(state, round_key);
	memcpy(out,state_bytes,16);
    if(key_out) memcpy(key_out,round_key_bytes,16);
}

static void aes_ref_dec128_block(uint8_t *out, uint8_t *key_out, const uint8_t *in, const uint8_t *key){
	uint32_t state[4];
	uint32_t round_key[4];
	uint8_t* state_bytes = (uint8_t*)state;
	uint8_t* round_key_bytes = (uint8_t*)round_key;
	uint8_t r, rc = 0x36;

	memcpy(round_key,key,16);
	memcpy(state,in,16);

    aes_ref_encrypt_key_schedule_128(round_key_bytes);

	for( r = 10 ; r >=1 ; r-- ){
        aes_ref_xor_block(state, round_key);
		if(r<=9){
			aes_ref_inv_mixcolumns(state_bytes,state_bytes);
		}
		aes_ref_inv_shift_rows(state_bytes,state_bytes);
		aes_ref_inv_sub_bytes(state_bytes,state_bytes);
		aes_ref_update_decrypt_key_128( round_key_bytes, &rc );
    }
    aes_ref_xor_block(state, round_key);
	memcpy(out,state_bytes,16);
	if(key_out) memcpy(key_out,round_key_bytes,16);
}

#ifdef AES_REF_TEST

#include "bytes_utils.h"

static void aes_ref_test(void){
    uint8_t key128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t key192[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    uint8_t key256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    			   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

	uint8_t in[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	uint8_t cy[] = {0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32};
	uint8_t out[16];
	uint8_t key_out[16];
	println_128("dat:",in);
	println_128("key:",key128);
	aes_ref_enc128_block(out,key_out,in,key128);
	println_128("out:",out);
	if(memcmp(out,cy,16)){
		println_128("exp:",cy);
		printf("Encryption failed.\n");
	}
	aes_ref_dec128_block(out,key_out,out,key128);
	println_128("out:",out);
	if(memcmp(out,in,16)){
		println_128("exp:",in);
		printf("Decryption failed.\n");
	}
    printf("AES test passed\n");
    while(1);
}
#endif

#endif
