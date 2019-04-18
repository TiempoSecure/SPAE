
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include "bytes_utils.h"

//#include "crypto_hash.h"
//#include "api.h"
#ifdef SPAE_REF
    #include "spae_aes128_ref.h"
#else
    #ifdef SPAE_FLE
        #include "spae_aes128.h"
    #else
        #ifdef SPAE_SLE
            #include "spae_aes128.h"
        #else
            #include "spae_aes128_amd64aesni.h"
        #endif
    #endif
#endif

void bstr(const void *const data, unsigned long long length){
    const unsigned char *const databytes = (const unsigned char *const)data;
    for (unsigned long long i = 0; i < length; i++)
		printf("%02X", databytes[i]);

    printf("\n");
}




#include <sys/times.h>
#include <signal.h>
#include <unistd.h>
#define TM_START	0
#define TM_STOP		1
double app_tminterval(int stop, int usertime){
	double ret = 0;
	struct tms rus;
	clock_t now = times(&rus);
	static clock_t tmstart;

	if (usertime)
		now = rus.tms_utime;

	if (stop == TM_START)
		tmstart = now;
	else {
		long int tck = sysconf(_SC_CLK_TCK);
		ret = (now - tmstart) / (double) tck;
	}

	return (ret);
}

#define SECONDS		3

#define BUFSIZE	(1024*8+64)
int run = 0;
static void sig_done(int sig);

static void sig_done(int sig){
    (void)sig;
	signal(SIGALRM, sig_done);
	run = 0;
}

#define START	0
#define STOP	1

static double Time_F(int s){
	return app_tminterval(s, 1);
}



int main(int argc, char *argv[]){
    (void)spae_aes128_dec;
    (void)bytes_utils_remove_unused_warnings;

    if((argc!=5) && (argc!=3) && (argc!=2)){
        printf("ERROR: need 1, 2 or 4 arguments.\n");
        printf("1 argument: 'O' for speed benchmark mode, openssl style, 'M' for mbedtls benchmark ref values\n");
        printf("2 arguments: length of message in 32 bit words, length of associated data in 32 bit words (speed benchmark mode, processing 32 bit count values)\n");
        printf("4 arguments: key,nonce,message,associatedData (test vector generator mode)\n");
        printf("examples:\n");
        printf("\t%s 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F\n",argv[0]);
        printf("\t%s 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F \"\"\n",argv[0]);
        printf("\t%s 000102030405060708090A0B0C0D0E0F 000102030405060708090A0B0C0D0E0F \"\" 000102030405060708090A0B0C0D0E0F\n",argv[0]);
        return -1;
    }

    if(argc==2){
        if(strcmp(argv[1],"O")==0){//openssl style benchmark
            #ifndef SPAE_AESNI
                uint8_t nonce[SPAE_BLOCKSIZE] = {0};
                uint8_t key[SPAE_BLOCKSIZE] = {0};
            #else
        		__m128i nonce[1];
                __m128i key[1];
                nonce[0] = _mm_setzero_si128();
                key[0] = _mm_setzero_si128();
            #endif
    		//size_t buf_len;//, nonce_len;
            #define SIZE_NUM 5
            int lengths[SIZE_NUM] = {16, 64, 256, 1024, 8 * 1024};
            #define COND(c)	(run && count<0x7fffffff)
            long count = 0;
            signal(SIGALRM, sig_done);

            uint8_t*buf = (uint8_t*)aligned_alloc(SPAE_BLOCKSIZE,BUFSIZE+2*SPAE_BLOCKSIZE);
            if(0==buf){
                printf("ERROR: could not allocate memory (%u bytes requested)\n",BUFSIZE+2*SPAE_BLOCKSIZE);
                return -5;
            }
            uint8_t*message=buf;
            uint8_t*c=buf;
            uint8_t*ad=0;
            size_t alen = 0;
            size_t clen;
    		for (unsigned int j = 0; j < SIZE_NUM; j++) {
    			printf("Doing SPAE_AES128 for 3s on %u size blocks: ",lengths[j]);
                alarm(SECONDS);
                size_t mlen = lengths[j];
                Time_F(START);
                //clock_t start, end;
                //start = clock();
    			for (count = 0, run = 1; COND(count); count++){
    				//EVP_AEAD_CTX_seal(&ctx, buf, &buf_len, BUFSIZE, nonce,nonce_len, buf, lengths[j], NULL, 0);
                    spae_aes128_enc((const uint8_t*const)key,(const uint8_t*const)nonce,message,mlen,ad,alen,c,&clen);
                }
                //end = clock();
                //double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    			double d=Time_F(STOP);
                printf("%lu SPAE_AES128's in %fs\n",count,d);
    		}
        } else if(strcmp(argv[1],"M")==0){//mbedtls
            #ifndef SPAE_AESNI
                uint8_t nonce[SPAE_BLOCKSIZE] = {0};
                uint8_t key[SPAE_BLOCKSIZE] = {0};
            #else
        		__m128i nonce[1];
                __m128i key[1];
                nonce[0] = _mm_setzero_si128();
                key[0] = _mm_setzero_si128();
            #endif
            uint8_t*buf = (uint8_t*)aligned_alloc(SPAE_BLOCKSIZE,1024+2*SPAE_BLOCKSIZE);

            memset( buf, 0, 1024 );
            uint8_t*message=buf;
            size_t mlen = 1024;
            uint8_t*c=buf;
            uint8_t*ad=0;
            size_t alen = 0;
            size_t clen;
            bstr(key,16);
            bstr(nonce,16);
            bstr(message,1024);
            for(unsigned int i=0;i<1024;i++){
                spae_aes128_enc((const uint8_t*const)key,(const uint8_t*const)nonce,message,mlen,ad,alen,c,&clen);
                //bstr(c,1024+SPAE_BLOCKSIZE);
               //for(unsigned int i=0;i<=1024/16;i++) bstr(c+i*16,16);
                //exit(-1);
                //bstr(c+1024,SPAE_BLOCKSIZE);
            }
            bstr(c+1024,SPAE_BLOCKSIZE);
        }
        exit(0);
	}

    uint8_t*key=0;
    uint8_t*nonce=0;
    uint8_t*message=0;
    uint8_t*ad=0;
    size_t mlen = 0;
    size_t alen = 0;
    uint8_t *msg = 0;
    if(argc==3){
        uint8_t null_block[16] = {0};
        key = null_block;
        nonce = null_block;
        size_t mlen32 = strtol(argv[1], 0, 0);
        size_t alen32 = strtol(argv[2], 0, 0);
        mlen = mlen32*4;
        alen = alen32*4;
        msg = (uint8_t*)aligned_alloc(SPAE_BLOCKSIZE,mlen+alen);
        if(0==msg){
            printf("ERROR: could not allocate memory (%lu bytes requested)\n",mlen+alen);
            return -4;
        }
        message = msg;
        ad = msg+mlen;
        uint32_t *msg32 = (uint32_t*)msg;
        for(size_t cnt=0;cnt<mlen32+alen32;cnt++){msg32[cnt] = cnt;}
    } else {
        size_t mlenmax = 0;//high bound for mlen
        for(int i=1;i<argc;i++){
            mlenmax += (strlen(argv[i]))/2;
        }
        //printf("mlenmax=%lu\n",mlenmax);
        msg = (uint8_t*)aligned_alloc(SPAE_BLOCKSIZE,mlenmax);
        if(0==msg){
            printf("ERROR: could not allocate memory (%lu bytes requested)\n",mlenmax);
            return -2;
        }
        uint8_t *m=msg;

        size_t remaining=mlenmax;
        for(int i=1;i<5;i++){
            //printf("remaining=%lu\n",remaining);
            size_t bufsize = strlen(argv[i])+1;
            char *buf = malloc(bufsize);
            if(0==buf){
                printf("ERROR: could not allocate memory (%lu bytes requested)\n",bufsize);
                return -3;
            }
            strcpy(buf,argv[i]);
            size_t nbytes = user_hexstr_to_bytes(m,remaining,buf,bufsize);
            //size_t nbytes = 0;//hexstr_to_bytes(m,remaining,buf);
            switch(i){
                case 1: key = m;assert(nbytes==16);break;
                case 2: nonce = m;assert(nbytes==16);break;
                case 3: message = m;mlen=nbytes;break;
                case 4: ad = m;alen=nbytes;break;
            }
            m+=nbytes;
            remaining-=nbytes;
            free(buf);
        }
        //printf("mlen=%lu\n",mlen);
    }

    uint8_t *c = (uint8_t*)aligned_alloc(SPAE_BLOCKSIZE,mlen+32);
    size_t clen=0;
    clock_t start, end;
    start = clock();
    spae_aes128_enc(key,nonce,message,mlen,ad,alen,c,&clen);
    end = clock();
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    if(argc==3){
        bstr(c+clen-16, 16);
        size_t total_bytes = mlen+alen;
        printf("%f seconds, %lu bytes, %f MBytes/s\n",cpu_time_used,total_bytes, total_bytes/(1024*1024*cpu_time_used));
        printf("%f ns/byte\n",cpu_time_used*1000000000 / (mlen+alen));
    } else {
        bstr(c, clen);
    }

    free(msg);
    free(c);
    return 0;
}
