/* integer.h
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 * Based on public domain LibTomMath 0.38 by Tom St Denis, tomstdenis@iahu.ca,
 * http://math.libtomcrypt.com
 */


#ifndef CTAO_CRYPT_INTEGER_H
#define CTAO_CRYPT_INTEGER_H

#if defined(WORDS_BIGENDIAN) || (defined(__MWERKS__) && !defined(__INTEL__))
    #define BIG_ENDIAN_ORDER
#endif

#ifndef BIG_ENDIAN_ORDER
    #define LITTLE_ENDIAN_ORDER
#endif


/* some default configurations.
 *
 * A "mp_digit" must be able to hold DIGIT_BIT + 1 bits
 * A "mp_word" must be able to hold 2*DIGIT_BIT + 1 bits
 *
 * At the very least a mp_digit must be able to hold 7 bits
 * [any size beyond that is ok provided it doesn't overflow the data type]
 */

#define CHAR_BIT 8
//#define MP_16BIT
#ifdef MP_8BIT
   #warning 8-bit mode is untested!
   typedef unsigned char      mp_digit;
   typedef unsigned short     mp_word;
   #define DIGIT_BIT          7
#elif defined(MP_16BIT)
   typedef unsigned short     mp_digit;
   typedef unsigned int       mp_word;
   #define DIGIT_BIT          14
#else
   /* this is the default case, 28-bit digits */
   
   typedef unsigned int       mp_digit;  /* long could be 64 now, changed TAO */
   typedef unsigned long long      mp_word;
   #define DIGIT_BIT          28
#endif



#define MP_DIGIT_BIT     DIGIT_BIT
#define MP_MASK          ((((mp_digit)1)<<((mp_digit)DIGIT_BIT))-((mp_digit)1))
#define MP_DIGIT_MAX     MP_MASK


enum {
    WORD_SIZE  = sizeof(mp_word),
    BIT_SIZE   = 8,
    WORD_BITS  = WORD_SIZE * BIT_SIZE
};


/* use inlining if compiler allows */
#ifndef INLINE
#ifndef NO_INLINE
    #ifdef _MSC_VER
        #define INLINE __inline
    #elif defined(__GNUC__)
        #define INLINE inline
    #elif defined(THREADX)
        #define INLINE _Inline
    #else
        #define INLINE 
    #endif
#else
    #define INLINE 
#endif
#endif


/* set up rotate style */
#if defined(_MSC_VER) || defined(__BCPLUSPLUS__)
	#define INTEL_INTRINSICS
	#define FAST_ROTATE
#elif defined(__MWERKS__) && TARGET_CPU_PPC
	#define PPC_INTRINSICS
	#define FAST_ROTATE
#elif defined(__GNUC__) && defined(__i386__)
        /* GCC does peephole optimizations which should result in using rotate
           instructions  */
	#define FAST_ROTATE
#endif

#ifndef MIN
   #define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#ifndef MAX
   #define MAX(x,y) ((x)>(y)?(x):(y))
#endif



/* equalities */
#define MP_LT        -1   /* less than */
#define MP_EQ         0   /* equal to */
#define MP_GT         1   /* greater than */

#define MP_ZPOS       0   /* positive integer */
#define MP_NEG        1   /* negative */

#define MP_OKAY       0   /* ok result */
#define MP_MEM        -2  /* out of mem */
#define MP_VAL        -3  /* invalid input */
#define MP_RANGE      MP_VAL

#define MP_YES        1   /* yes response */
#define MP_NO         0   /* no response */

/* Primality generation flags */
#define LTM_PRIME_BBS      0x0001 /* BBS style prime */
#define LTM_PRIME_SAFE     0x0002 /* Safe prime (p-1)/2 == prime */
#define LTM_PRIME_2MSB_ON  0x0008 /* force 2nd MSB to 1 */

typedef int           mp_err;

/* define this to use lower memory usage routines (exptmods mostly) */
#define MP_LOW_MEM

#ifndef MP_PREC
	#define MP_PREC                 (272 / sizeof(mp_digit))     /* default length of big integers */
#endif
#define MP_PREC_HIGH			MP_PREC*2 //need double the space for internal computations


/* size of comba arrays, should be at least 2 * 2**(BITS_PER_WORD - 
   BITS_PER_DIGIT*2) */
#define MP_WARRAY  (1 << (sizeof(mp_word) * CHAR_BIT - 2 * DIGIT_BIT + 1))

/* the infamous mp_int structure */
typedef struct  {
    int used, alloc, sign;
    mp_digit *dp;
} mp_int;


#define USED(m)    ((m)->used)
#define DIGIT(m,k) ((m)->dp[(k)])
#define SIGN(m)    ((m)->sign)


/* ---> Basic Manipulations <--- */
#define mp_iszero(a) (((a)->used == 0) ? MP_YES : MP_NO)
#define mp_iseven(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1) == 0)) ? MP_YES : MP_NO)
#define mp_isodd(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1) == 1)) ? MP_YES : MP_NO)

#define mp_read_raw(mp, str, len) mp_read_signed_bin((mp), (str), (len))
#define mp_raw_size(mp)           mp_signed_bin_size(mp)
#define mp_toraw(mp, str)         mp_to_signed_bin((mp), (str))
#define mp_read_mag(mp, str, len) mp_read_unsigned_bin((mp), (str), (len))
#define mp_mag_size(mp)           mp_unsigned_bin_size(mp)
#define mp_tomag(mp, str)         mp_to_unsigned_bin((mp), (str))

#define mp_tobinary(M, S)  mp_toradix((M), (S), 2)
#define mp_tooctal(M, S)   mp_toradix((M), (S), 8)
#define mp_todecimal(M, S) mp_toradix((M), (S), 10)
#define mp_tohex(M, S)     mp_toradix((M), (S), 16)

#define s_mp_mul(a, b, c) s_mp_mul_digs(a, b, c, (a)->used + (b)->used + 1)

extern const char *mp_s_rmap;

/* 6 functions needed by Rsa */
int  mp_init (mp_int * a, mp_digit* buff, mp_digit len);
void mp_clear (mp_int * a);
int  mp_unsigned_bin_size(mp_int * a);
int  mp_read_unsigned_bin (mp_int * a, const unsigned char *b, int c);
int  mp_to_unsigned_bin (mp_int * a, unsigned char *b);
int  mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y);
/* end functions needed by Rsa */

/* functions added to support above needed, removed TOOM and KARATSUBA */
int  mp_count_bits (mp_int * a);
int  mp_init_copy (mp_int * a, mp_int * b, mp_digit* buff, mp_digit len);
int  mp_copy (mp_int * a, mp_int * b);
int  mp_grow (mp_int * a, int size);
void bn_reverse (unsigned char *s, int len);
int  mp_div_2d (mp_int * a, int b, mp_int * c, mp_int * d);
void mp_zero (mp_int * a);
void mp_clamp (mp_int * a);
void mp_exch (mp_int * a, mp_int * b);
void mp_rshd (mp_int * a, int b);
int  mp_mod_2d (mp_int * a, int b, mp_int * c);
int  mp_mul_2d (mp_int * a, int b, mp_int * c);
int  mp_lshd (mp_int * a, int b);
int  mp_abs (mp_int * a, mp_int * b);
int  mp_invmod (mp_int * a, mp_int * b, mp_int * c);
int  fast_mp_invmod (mp_int * a, mp_int * b, mp_int * c);
int  mp_invmod_slow (mp_int * a, mp_int * b, mp_int * c);
int  mp_cmp_mag (mp_int * a, mp_int * b);
int  mp_cmp (mp_int * a, mp_int * b);
int  mp_cmp_d(mp_int * a, mp_digit b);
void mp_set (mp_int * a, mp_digit b);
int  mp_mod (mp_int * a, mp_int * b, mp_int * c);
int  mp_div(mp_int * a, mp_int * b, mp_int * c, mp_int * d);
int  mp_div_2(mp_int * a, mp_int * b);
int  mp_add (mp_int * a, mp_int * b, mp_int * c);
int  s_mp_add (mp_int * a, mp_int * b, mp_int * c);
int  s_mp_sub (mp_int * a, mp_int * b, mp_int * c);
int  mp_sub (mp_int * a, mp_int * b, mp_int * c);
int  mp_reduce_is_2k_l(mp_int *a);
int  mp_reduce_is_2k(mp_int *a);
int  mp_dr_is_modulus(mp_int *a);
int  mp_exptmod_fast (mp_int * G, mp_int * X, mp_int * P, mp_int * Y, int);
int  mp_montgomery_setup (mp_int * n, mp_digit * rho);
int  fast_mp_montgomery_reduce (mp_int * x, mp_int * n, mp_digit rho);
int  mp_montgomery_reduce (mp_int * x, mp_int * n, mp_digit rho);
void mp_dr_setup(mp_int *a, mp_digit *d);
int  mp_dr_reduce (mp_int * x, mp_int * n, mp_digit k);
int  mp_reduce_2k(mp_int *a, mp_int *n, mp_digit d);
int  fast_s_mp_mul_high_digs (mp_int * a, mp_int * b, mp_int * c, int digs);
int  s_mp_mul_high_digs (mp_int * a, mp_int * b, mp_int * c, int digs);
int  mp_reduce_2k_setup_l(mp_int *a, mp_int *d);
int  mp_reduce_2k_l(mp_int *a, mp_int *n, mp_int *d);
int  mp_reduce (mp_int * x, mp_int * m, mp_int * mu);
int  mp_reduce_setup (mp_int * a, mp_int * b);
int  s_mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y, int redmode);
int  mp_montgomery_calc_normalization (mp_int * a, mp_int * b);
int  s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs);
int  s_mp_sqr (mp_int * a, mp_int * b);
int  fast_s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs);
int  fast_s_mp_sqr (mp_int * a, mp_int * b);
int  mp_div_3 (mp_int * a, mp_int *c, mp_digit * d);
int  mp_mul_2(mp_int * a, mp_int * b);
int  mp_mul (mp_int * a, mp_int * b, mp_int * c);
int  mp_sqr (mp_int * a, mp_int * b);
int  mp_mulmod (mp_int * a, mp_int * b, mp_int * c, mp_int * d);
int  mp_mul_d (mp_int * a, mp_digit b, mp_int * c);
int  mp_2expt (mp_int * a, int b);
int  mp_reduce_2k_setup(mp_int *a, mp_digit *d);
int  mp_add_d (mp_int* a, mp_digit b, mp_int* c);
int mp_set_int (mp_int * a, unsigned long b);
/* end support added functions */

#if defined(HAVE_ECC)
    int mp_sqrmod(mp_int* a, mp_int* b, mp_int* c);
    int mp_sub_d (mp_int * a, mp_digit b, mp_int * c);
    int mp_read_radix(mp_int* a, const char* str, int radix);
#endif
int get_max_size();
mp_digit get_min_stack();
mp_digit get_max_stack();
void reset_stack_counter();
#endif  /* CTAO_CRYPT_INTEGER_H */

