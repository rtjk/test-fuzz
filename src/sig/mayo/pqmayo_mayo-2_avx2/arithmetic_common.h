// SPDX-License-Identifier: Apache-2.0

#ifndef ARITHMETIC_COMMON_H
#define ARITHMETIC_COMMON_H

#include <stdint.h>
#include <immintrin.h>

#define K_OVER_2 ((K_MAX+1)/2)

static const unsigned char __gf16_mulbase[128] __attribute__((aligned(32))) = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d,
    0x00, 0x04, 0x08, 0x0c, 0x03, 0x07, 0x0b, 0x0f, 0x06, 0x02, 0x0e, 0x0a, 0x05, 0x01, 0x0d, 0x09, 0x00, 0x04, 0x08, 0x0c, 0x03, 0x07, 0x0b, 0x0f, 0x06, 0x02, 0x0e, 0x0a, 0x05, 0x01, 0x0d, 0x09,
    0x00, 0x08, 0x03, 0x0b, 0x06, 0x0e, 0x05, 0x0d, 0x0c, 0x04, 0x0f, 0x07, 0x0a, 0x02, 0x09, 0x01, 0x00, 0x08, 0x03, 0x0b, 0x06, 0x0e, 0x05, 0x0d, 0x0c, 0x04, 0x0f, 0x07, 0x0a, 0x02, 0x09, 0x01
};

//
// generate multiplication table for '4-bit' variable 'b'. Taken from OV paper!
//
static inline __m256i tbl32_gf16_multab2( uint8_t b ) {

    __m256i bx = _mm256_set1_epi16( b & 0xf );
    __m256i b1 = _mm256_srli_epi16( bx, 1 );

    const __m256i tab0 = _mm256_load_si256((__m256i const *) (__gf16_mulbase + 32 * 0));
    const __m256i tab1 = _mm256_load_si256((__m256i const *) (__gf16_mulbase + 32 * 1));
    const __m256i tab2 = _mm256_load_si256((__m256i const *) (__gf16_mulbase + 32 * 2));
    const __m256i tab3 = _mm256_load_si256((__m256i const *) (__gf16_mulbase + 32 * 3));

    __m256i mask_1  = _mm256_set1_epi16(1);
    __m256i mask_4  = _mm256_set1_epi16(4);
    __m256i mask_0  = _mm256_setzero_si256();

    return ( tab0 & _mm256_cmpgt_epi16( bx & mask_1, mask_0) )
           ^ ( tab1 & _mm256_cmpgt_epi16( b1 & mask_1, mask_0) )
           ^ ( tab2 & _mm256_cmpgt_epi16( bx & mask_4, mask_0) )
           ^ ( tab3 & _mm256_cmpgt_epi16( b1 & mask_4, mask_0) );
}

static inline __m256i linear_transform_8x8_256b( __m256i tab_l, __m256i tab_h, __m256i v, __m256i mask_f ) {
    return _mm256_shuffle_epi8(tab_l, v & mask_f)^_mm256_shuffle_epi8(tab_h, _mm256_srli_epi16(v, 4)&mask_f);
}

static inline __m256i gf16v_mul_avx2( __m256i a, uint8_t b ) {
    __m256i multab_l = tbl32_gf16_multab2( b );
    __m256i multab_h = _mm256_slli_epi16( multab_l, 4 );

    return linear_transform_8x8_256b( multab_l, multab_h, a, _mm256_set1_epi8(0xf) );
}

static 
inline void mayo_O_multabs_avx2(const unsigned char *O, __m256i *O_multabs){
    // build multiplication tables 
    for (size_t r = 0; r < V_MAX; r++)
    {
        for (size_t c = 0; c < O_MAX; c+=2)
        {
            O_multabs[O_MAX/2*r + c/2] = tbl32_gf16_multab2(O[O_MAX*r + c]) ^ _mm256_slli_epi16(tbl32_gf16_multab2(O[O_MAX*r + c + 1]), 4);
        }
    }
}


static 
inline void mayo_V_multabs_avx2(const unsigned char *V, __m256i *V_multabs){
    // build multiplication tables 
    size_t r;
    for (size_t c = 0; c < V_MAX; c++)
    {
        for (r = 0; r+1 < K_MAX; r+= 2)
        {
            V_multabs[K_OVER_2*c +  r/2] = tbl32_gf16_multab2(V[V_MAX*r + c]) ^ _mm256_slli_epi16(tbl32_gf16_multab2(V[V_MAX*(r+1) + c]), 4);
        }
#if K_MAX % 2 == 1
        V_multabs[K_OVER_2*c + r/2] = tbl32_gf16_multab2(V[V_MAX*r + c]);
#endif
    }
}

static const unsigned char mayo_gf16_mul[512] __attribute__((aligned(32))) = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, 
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d, 
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d,
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09, 0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02, 
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09, 0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,
    0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09, 
    0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09,
    0x00,0x05,0x0a,0x0f,0x07,0x02,0x0d,0x08, 0x0e,0x0b,0x04,0x01,0x09,0x0c,0x03,0x06, 
    0x00,0x05,0x0a,0x0f,0x07,0x02,0x0d,0x08, 0x0e,0x0b,0x04,0x01,0x09,0x0c,0x03,0x06,
    0x00,0x06,0x0c,0x0a,0x0b,0x0d,0x07,0x01, 0x05,0x03,0x09,0x0f,0x0e,0x08,0x02,0x04, 
    0x00,0x06,0x0c,0x0a,0x0b,0x0d,0x07,0x01, 0x05,0x03,0x09,0x0f,0x0e,0x08,0x02,0x04,
    0x00,0x07,0x0e,0x09,0x0f,0x08,0x01,0x06, 0x0d,0x0a,0x03,0x04,0x02,0x05,0x0c,0x0b, 
    0x00,0x07,0x0e,0x09,0x0f,0x08,0x01,0x06, 0x0d,0x0a,0x03,0x04,0x02,0x05,0x0c,0x0b,
    0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01, 
    0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01,
    0x00,0x09,0x01,0x08,0x02,0x0b,0x03,0x0a, 0x04,0x0d,0x05,0x0c,0x06,0x0f,0x07,0x0e, 
    0x00,0x09,0x01,0x08,0x02,0x0b,0x03,0x0a, 0x04,0x0d,0x05,0x0c,0x06,0x0f,0x07,0x0e,
    0x00,0x0a,0x07,0x0d,0x0e,0x04,0x09,0x03, 0x0f,0x05,0x08,0x02,0x01,0x0b,0x06,0x0c, 
    0x00,0x0a,0x07,0x0d,0x0e,0x04,0x09,0x03, 0x0f,0x05,0x08,0x02,0x01,0x0b,0x06,0x0c,
    0x00,0x0b,0x05,0x0e,0x0a,0x01,0x0f,0x04, 0x07,0x0c,0x02,0x09,0x0d,0x06,0x08,0x03, 
    0x00,0x0b,0x05,0x0e,0x0a,0x01,0x0f,0x04, 0x07,0x0c,0x02,0x09,0x0d,0x06,0x08,0x03,
    0x00,0x0c,0x0b,0x07,0x05,0x09,0x0e,0x02, 0x0a,0x06,0x01,0x0d,0x0f,0x03,0x04,0x08, 
    0x00,0x0c,0x0b,0x07,0x05,0x09,0x0e,0x02, 0x0a,0x06,0x01,0x0d,0x0f,0x03,0x04,0x08,
    0x00,0x0d,0x09,0x04,0x01,0x0c,0x08,0x05, 0x02,0x0f,0x0b,0x06,0x03,0x0e,0x0a,0x07, 
    0x00,0x0d,0x09,0x04,0x01,0x0c,0x08,0x05, 0x02,0x0f,0x0b,0x06,0x03,0x0e,0x0a,0x07,
    0x00,0x0e,0x0f,0x01,0x0d,0x03,0x02,0x0c, 0x09,0x07,0x06,0x08,0x04,0x0a,0x0b,0x05, 
    0x00,0x0e,0x0f,0x01,0x0d,0x03,0x02,0x0c, 0x09,0x07,0x06,0x08,0x04,0x0a,0x0b,0x05,
    0x00,0x0f,0x0d,0x02,0x09,0x06,0x04,0x0b, 0x01,0x0e,0x0c,0x03,0x08,0x07,0x05,0x0a, 
    0x00,0x0f,0x0d,0x02,0x09,0x06,0x04,0x0b, 0x01,0x0e,0x0c,0x03,0x08,0x07,0x05,0x0a};


static 
inline void mayo_S1_multabs_avx2(const unsigned char *S1, __m256i *S1_multabs) {
    size_t r;
    for (size_t c = 0; c < V_MAX; c++)
    {
        for (r = 0; r+1 < K_MAX; r+= 2)
        {
            S1_multabs[K_OVER_2*c +  r/2] = _mm256_load_si256((__m256i *)(mayo_gf16_mul + 32*S1[V_MAX*r + c])) 
                                          ^ _mm256_slli_epi16(_mm256_load_si256((__m256i *)(mayo_gf16_mul + 32*S1[V_MAX*(r+1) + c])), 4);
        }
#if K_MAX % 2 == 1
        S1_multabs[K_OVER_2*c +  r/2] = _mm256_load_si256((__m256i *)(mayo_gf16_mul + 32*S1[V_MAX*r + c]));
#endif
    }
}

static 
inline void mayo_S2_multabs_avx2(const unsigned char *S2, __m256i *S2_multabs) {
    // build multiplication tables 
    size_t r;
    for (size_t c = 0; c < O_MAX; c++)
    {
        for (r = 0; r+1 < K_MAX; r+= 2)
        {
            S2_multabs[K_OVER_2*c +  r/2] = _mm256_load_si256((__m256i *)(mayo_gf16_mul + 32*S2[O_MAX*r + c])) 
                                          ^ _mm256_slli_epi16(_mm256_load_si256((__m256i *)(mayo_gf16_mul + 32*S2[O_MAX*(r+1) + c])), 4);
        }
#if K_MAX % 2 == 1
        S2_multabs[K_OVER_2*c +  r/2] = _mm256_load_si256((__m256i *)(mayo_gf16_mul + 32*S2[O_MAX*r + c])) ;
#endif
    }
}

static inline uint64_t gf16v_mul_u64( uint64_t a, uint8_t b ) {
    uint64_t mask_msb = 0x8888888888888888ULL;
    uint64_t a_msb;
    uint64_t a64 = a;
    uint64_t b32 = b;
    uint64_t r64 = a64 * (b32 & 1);

    a_msb = a64 & mask_msb; // MSB, 3rd bits
    a64 ^= a_msb;   // clear MSB
    a64 = (a64 << 1) ^ ((a_msb >> 3) * 3);
    r64 ^= (a64) * ((b32 >> 1) & 1);

    a_msb = a64 & mask_msb; // MSB, 3rd bits
    a64 ^= a_msb;   // clear MSB
    a64 = (a64 << 1) ^ ((a_msb >> 3) * 3);
    r64 ^= (a64) * ((b32 >> 2) & 1);

    a_msb = a64 & mask_msb; // MSB, 3rd bits
    a64 ^= a_msb;   // clear MSB
    a64 = (a64 << 1) ^ ((a_msb >> 3) * 3);
    r64 ^= (a64) * ((b32 >> 3) & 1);

    return r64;
}

#endif

