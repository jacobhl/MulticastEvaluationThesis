/* ecc.h
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


#ifndef CTAO_CRYPT_ECC_H
#define CTAO_CRYPT_ECC_H

#include "integer.h"

#define MEMORY_E		-125
#define BUFFER_E 		-132
#define ASN_PARSE_E     -140
#define ECC_BAD_ARG_E 	-170
#define ASN_ECC_KEY_E   -171

enum {
    ECC_PUBLICKEY  = 1,
    ECC_PRIVATEKEY = 2,
    ECC_MAXNAME    = 16,     /* MAX CURVE NAME LENGTH */
    SIG_HEADER_SZ  =  6,     /* ECC signature header size */
    ECC_BUFSIZE    = 256,    /* for exported keys temp buffer */
    ECC_MINSIZE    = 20,     /* MIN Private Key size */
    ECC_MAXSIZE    = 66      /* MAX Private Key size */
};


/* ECC set type defined a NIST GF(p) curve */
typedef struct {
    int size;       /* The size of the curve in octets */
    const char* name;     /* name of this curve */
    const char* prime;    /* prime that defines the field, curve is in (hex) */
    const char* B;        /* fields B param (hex) */
    const char* order;    /* order of the curve (hex) */
    const char* Gx;       /* x coordinate of the base point on curve (hex) */
    const char* Gy;       /* y coordinate of the base point on curve (hex) */
} ecc_set_type;


/* A point on an ECC curve, stored in Jacbobian format such that (x,y,z) =>
   (x/z^2, y/z^3, 1) when interpreted as affine */
typedef struct {
    mp_int x;        /* The x coordinate */
    mp_int y;        /* The y coordinate */
    mp_int z;        /* The z coordinate */
} ecc_point;


/* An ECC Key */
typedef struct {
    int type;           /* Public or Private */
    int idx;            /* Index into the ecc_sets[] for the parameters of
                           this curve if -1, this key is using user supplied
                           curve in dp */
    const ecc_set_type* dp;     /* domain parameters, either points to NIST
                                   curves (idx >= 0) or user supplied */
    ecc_point pubkey;   /* public key */  
    mp_int    k;        /* private key */
} ecc_key;


/* ECC predefined curve sets  */
//#define ECC112
//#define ECC128
//#define ECC160
//#define ECC192
#define ECC224
//#define ECC256
//#define ECC384
//#define ECC521



/* This holds the key settings.  ***MUST*** be organized by size from
   smallest to largest. */

const ecc_set_type ecc_sets[] = {
#ifdef ECC112
{
        14,
        "SECP112R1",
        "DB7C2ABF62E35E668076BEAD208B",
        "659EF8BA043916EEDE8911702B22",
        "DB7C2ABF62E35E7628DFAC6561C5",
        "09487239995A5EE76B55F9C2F098",
        "A89CE5AF8724C0A23E0E0FF77500"
},
#endif
#ifdef ECC128
{
        16,
        "SECP128R1",
        "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
        "E87579C11079F43DD824993C2CEE5ED3",
        "FFFFFFFE0000000075A30D1B9038A115",
        "161FF7528B899B2D0C28607CA52C5B86",
        "CF5AC8395BAFEB13C02DA292DDED7A83",
},
#endif
#ifdef ECC160
{
        20,
        "SECP160R1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
        "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
        "0100000000000000000001F4C8F927AED3CA752257",
        "4A96B5688EF573284664698968C38BB913CBFC82",
        "23A628553168947D59DCC912042351377AC5FB32",
},
#endif
#ifdef ECC192
{
        24,
        "ECC-192", //NIST-P192
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
        "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
},
#endif
#ifdef ECC224
{
        28,
        "ECC-224", //NIST-P224
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
},
#endif
#ifdef ECC256
{
        32,
        "ECC-256", //NIST-P256
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
},
#endif
#ifdef ECC384
{
        48,
        "ECC-384", //NIST-P384
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
},
#endif
#ifdef ECC521
{
        66,
        "ECC-521", //NIST-P521
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
},
#endif
{
   0,
   NULL, NULL, NULL, NULL, NULL, NULL
}
};

#ifdef ECC_TEST_VALUES

	#ifdef ECC224
		#define MY_ECC_PUBLIC_LEN		57
		#define MY_ECC_PUBLIC 			(uint8_t[]) {0x04, 0xa7, 0x78, 0x49, 0x24, 0x93, 0x61, 0xe5, 0xb8, 0x86, 0x59, 0x6a, 0xf5, 0x66, 0x79, 0x1f, 0x73, 0xe4, 0x74, 0x32, 0x67, 0xbe, 0x21, 0x94, 0x9e, 0x6c, 0xa9, 0x70, 0x58, 0x10, 0xc5, 0x78, 0xed, 0x30, 0x46, 0xb6, 0x2b, 0xa8, 0xc2, 0x8f, 0x47, 0xfd, 0x2c, 0xe0, 0xf7, 0x26, 0x8a, 0xec, 0x75, 0x26, 0xb6, 0x72, 0x7d, 0xbd, 0xf0, 0x7e, 0xc7}

		#define MY_ECC_PRIVATE_LEN		28
		#define MY_ECC_PRIVATE 			(uint8_t[]) {0x06, 0x25, 0x10, 0x94, 0x29, 0x42, 0xdd, 0xee, 0x0d, 0xe3, 0xc9, 0xaf, 0xa8, 0xc6, 0xcc, 0xbe, 0xe4, 0x49, 0x66, 0x0e, 0x18, 0x53, 0x6b, 0xde, 0xa6, 0x0c, 0x78, 0xec}
	
		#define OTHER_ECC_PUBLIC_LEN	57
		#define OTHER_ECC_PUBLIC 		(uint8_t[]) {0x04, 0x57, 0xa5, 0xde, 0xca, 0xd2, 0x1f, 0x2c, 0x75, 0xdc, 0x60, 0x8b, 0xde, 0x1c, 0xbd, 0xec, 0xca, 0xa9, 0x19, 0x93, 0x0e, 0x35, 0x5a, 0xbf, 0x07, 0xa5, 0xd4, 0x17, 0x1f, 0x5f, 0xf3, 0xdc, 0xcf, 0x87, 0x9f, 0x3d, 0xd1, 0x5e, 0x91, 0x58, 0x25, 0xd2, 0xe8, 0xef, 0x7b, 0x70, 0x36, 0x63, 0xb8, 0x6e, 0x17, 0x2a, 0x63, 0x5b, 0x5b, 0xe8, 0x9f}
	#endif /* ECC192 */

	#ifdef ECC192
		#define MY_ECC_PUBLIC_LEN		49
		#define MY_ECC_PUBLIC 			(uint8_t[]) {0x04, 0xcf, 0xa3, 0x2f, 0xc7, 0xf8, 0x76, 0x9f, 0x44, 0x1b, 0xb8, 0xf8, 0x0a, 0x75, 0x4c, 0x45, 0x4f, 0xdd, 0x60, 0x85, 0xdf, 0x37, 0x31, 0xb5, 0xda, 0x97, 0xd8, 0xe6, 0x4c, 0x54, 0x9e, 0x24, 0x56, 0x1c, 0x96, 0xf9, 0xc9, 0xd2, 0xf0, 0x68, 0x5a, 0x94, 0x70, 0xd0, 0x74, 0x68, 0xd6, 0x9a, 0x50}

		#define MY_ECC_PRIVATE_LEN		24
		#define MY_ECC_PRIVATE 			(uint8_t[]) {0x0a, 0xe5, 0x4e, 0x12, 0x42, 0xf7, 0x54, 0x6b, 0x4c, 0x77, 0xdb, 0x21, 0x6b, 0x47, 0xb8, 0xa6, 0x5d, 0x0c, 0xfa, 0xf6, 0xa2, 0xa4, 0x92, 0x10}
	
		#define OTHER_ECC_PUBLIC_LEN	49
		#define OTHER_ECC_PUBLIC 		(uint8_t[]) {0x04, 0xde, 0x68, 0x3c, 0x23, 0x4d, 0x1e, 0xed, 0xf8, 0xfe, 0x02, 0x11, 0x9e, 0x0a, 0x58, 0x7c, 0xb5, 0x46, 0x62, 0xc7, 0x58, 0xb4, 0x3d, 0x3f, 0x22, 0x36, 0xb5, 0x7e, 0xaf, 0x0a, 0x48, 0x5a, 0xca, 0xf9, 0x9a, 0x69, 0x35, 0xbb, 0x61, 0x23, 0x47, 0xf3, 0xc7, 0x1a, 0x5e, 0x1c, 0xbb, 0x71, 0x2d}
	#endif /* ECC192 */
	
	#ifdef ECC160
		#define MY_ECC_PUBLIC_LEN		41
		#define MY_ECC_PUBLIC 			(uint8_t[]) {0x04, 0x51, 0xb4, 0x49, 0x6f, 0xec, 0xc4, 0x06, 0xed, 0x0e, 0x75, 0xa2, 0x4a, 0x3c, 0x03, 0x20, 0x62, 0x51, 0x41, 0x9d, 0xc0, 0xc2, 0x8d, 0xcb, 0x4b, 0x73, 0xa5, 0x14, 0xb4, 0x68, 0xd7, 0x93, 0x89, 0x4f, 0x38, 0x1c, 0xcc, 0x17, 0x56, 0xaa, 0x6c}

		#define MY_ECC_PRIVATE_LEN		20
		#define MY_ECC_PRIVATE 			(uint8_t[]) {0xaa, 0x37, 0x4f, 0xfc, 0x3c, 0xe1, 0x44, 0xe6, 0xb0, 0x73, 0x30, 0x79, 0x72, 0xcb, 0x6d, 0x57, 0xb2, 0xa4, 0xe9, 0x82 }
	
		#define OTHER_ECC_PUBLIC_LEN	41
		#define OTHER_ECC_PUBLIC 		(uint8_t[]) {0x04, 0x49, 0xb4, 0x1e, 0x0e, 0x9c, 0x03, 0x69, 0xc2, 0x32, 0x87, 0x39, 0xd9, 0x0f, 0x63, 0xd5, 0x67, 0x07, 0xc6, 0xe5, 0xbc, 0x26, 0xe0, 0x08, 0xb5, 0x67, 0x01, 0x5e, 0xd9, 0x6d, 0x23, 0x2a, 0x03, 0x11, 0x1c, 0x3e, 0xdc, 0x0e, 0x9c, 0x8f, 0x83}
	
		#define ECDH_OUTPUT				(uint8_t[]) {0xca, 0x7c, 0x0f, 0x8c, 0x3f, 0xfa, 0x87, 0xa9, 0x6e, 0x1b, 0x74, 0xac, 0x8e, 0x6a, 0xf5, 0x94, 0x34, 0x7b, 0xb4, 0x0a}
	#endif /* ECC160 */

#endif /* ECC_TEST_VALUES*/

/* ASN Tags   */
enum ASN_Tags {        
    ASN_BOOLEAN           = 0x01,
    ASN_INTEGER           = 0x02,
    ASN_BIT_STRING        = 0x03,
    ASN_OCTET_STRING      = 0x04,
    ASN_TAG_NULL          = 0x05,
    ASN_OBJECT_ID         = 0x06,
    ASN_ENUMERATED        = 0x0a,
    ASN_SEQUENCE          = 0x10,
    ASN_SET               = 0x11,
    ASN_UTC_TIME          = 0x17,
    ASN_GENERALIZED_TIME  = 0x18,
    CRL_EXTENSIONS        = 0xa0,
    ASN_EXTENSIONS        = 0xa3,
    ASN_LONG_LENGTH       = 0x80
};

enum  ASN_Flags{
    ASN_CONSTRUCTED       = 0x20,
    ASN_CONTEXT_SPECIFIC  = 0x80
};

#endif /* CTAO_CRYPT_ECC_H */
