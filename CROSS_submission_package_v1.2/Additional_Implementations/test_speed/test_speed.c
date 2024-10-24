#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "api.h"
#include "csprng_hash.h"

#define NUM_TESTS 1000000 //100000
#define PROGRESS 300
#define PRINTARRAY 1000001

void simple_randombytes(unsigned char *x, unsigned long long xlen) {
    for (unsigned long long i = 0; i < xlen; i++) {
        x[i] = (unsigned char) (rand() % 256);
    }
}

static void print_array(const char *name, unsigned char *array, unsigned long long len) {
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++) {
        if(i < 3) printf("%02x", array[i]);
        else if(i == len/2) printf(" ... ");
        else if(i > (len-4)) printf("%02x", array[i]);
    }
    printf("\n");
}

static void print_array_full(const char *name, unsigned char *array, unsigned long long len) {
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
    printf("\n");
}

int main() {
    
    unsigned char       *m, *sm, *m1;
    unsigned char       *sig;
    unsigned long long  siglen;
    unsigned long long  mlen;
    unsigned long long  smlen;
    unsigned long long  mlen1;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

    unsigned char       entropy_input[48] = {0};

    mlen = 50;

    m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
    m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sig = (unsigned char *)calloc(CRYPTO_BYTES, sizeof(unsigned char));

    setbuf(stdout, NULL);

    // TODO: move initialization inside/outside the for loop
    simple_randombytes(m, mlen); 

    // TODO: move initialization inside/outside the for loop
    simple_randombytes(entropy_input, 48);
    initialize_csprng(&platform_csprng_state, entropy_input, 48);

    printf("\nRunning %d keypair+sign+open with MLEN=%lld\n", NUM_TESTS, mlen);

    int failures = 0;

    //////////////////////////////////////
    uint8_t discarded_sk_seed[KEYPAIR_SEED_LENGTH_BYTES];
    uint8_t discarded_seed[SEED_LENGTH_BYTES];
    uint8_t discarded_salt[SALT_LENGTH_BYTES];
    //////////////////////////////////////

    for(int i=0; i<NUM_TESTS; i++) {

        // if(i > 382900){
        if(i > 0){
            if ( crypto_sign_keypair(pk, sk) != 0) {
                printf("\n\n **** KEYPAIR ERROR ****\n\n");
                exit(-1);         
            }
            if ( crypto_sign(sm, &smlen, m, mlen, sk) != 0) {
                printf("\n\n **** SIGN ERROR ****\n\n");
                exit(-1);
            }
            if ( crypto_sign_open(m1, &mlen1, sm, smlen, pk) != 0) {
                printf("\n\n **** VERIFY ERROR ****\n\n");
                //////////////////////////////
                printf("\n");
                print_array_full("pk\t", pk, CRYPTO_PUBLICKEYBYTES);
                print_array_full("sk\t", sk, CRYPTO_SECRETKEYBYTES);
                print_array_full("m\t", m, mlen);
                print_array_full("m1\t", m1, mlen1);
                print_array_full("sm\t", sm, smlen);
                //////////////////////////////
                exit(-1);
                failures++;
            }
        }
        else {
            randombytes(discarded_sk_seed,KEYPAIR_SEED_LENGTH_BYTES);
            randombytes(discarded_seed,SEED_LENGTH_BYTES);
            randombytes(discarded_salt,SALT_LENGTH_BYTES);
        }

        if((i%PROGRESS == 0) && i) {
            printf(".");
            fflush(stdout);
        }
        if((i%PRINTARRAY == 0) && i) {
            printf("\n");
            print_array("pk\t", pk, CRYPTO_PUBLICKEYBYTES);
            print_array("sk\t", sk, CRYPTO_SECRETKEYBYTES);
            print_array("m\t", m, mlen);
            print_array("m1\t", m1, mlen1);
            print_array("sm\t", sm, smlen);
            fflush(stdout);
        }
    }
    if(failures) printf("\nFailure rate: %f\n", (float)failures/(float)NUM_TESTS);
    printf("\n");

    free(m);
    free(m1);
    free(sm);
    free(sig);

}
