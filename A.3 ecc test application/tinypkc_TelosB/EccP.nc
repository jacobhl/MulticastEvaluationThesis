/* 
 * This file is based on a CyaSSL file: (cyassl-2.2.0/ctaocrypt/src/ecc.c)
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
 
/**
 * TinyOS Port of CyaSSL ECC implementation
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	27/8/2012
 */
 
#include "ecc.h"
#include "integer.h"

#ifdef DO_PRINTF
	#include "printf.h"
#endif
 
module EccP {
	provides interface ECC;
	
	uses interface Random;
	uses interface ParameterInit<uint16_t> as SeedInit;
	uses interface LocalTime<TMicro> as MicroTime;
} implementation {


	int _ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* modulus, int map);
	int _ecc_projective_dbl_point(ecc_point *P, ecc_point *R, mp_int* modulus, mp_digit* mp);
	int _ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R, mp_int* modulus, mp_digit* mp);
	int _ecc_map(ecc_point* P, mp_int* modulus, mp_digit* mp);
	int _ecc_make_key_ex(ecc_key* key, const ecc_set_type* dp);
	int _storeECC_DSA_Sig(uint8_t* out, uint16_t* outLen, mp_int* r, mp_int* s);
	int _decodeECC_DSA_Sig(uint8_t* sig, uint16_t sigLen, mp_int* r, mp_int* s);
	
	/* helper for either lib */
	static int get_digit_count(mp_int* a){
		if (a == NULL) return 0;
		
		return a->used;
	}

	/* helper for either lib */
	static unsigned long get_digit(mp_int* a, int n){
		if (a == NULL) return 0;
		
		return (n >= a->used || n < 0) ? 0 : a->dp[n];
	}
	
	/** Returns whether an ECC idx is valid or not
	  n      The idx number to check
	  return 1 if valid, 0 if not
	*/  
	static int ecc_is_valid_idx(int n){
	   int x;

	   for (x = 0; ecc_sets[x].size != 0; x++){}
	   /* -1 is a valid index --- indicating that the domain params
		  were supplied by the user */
	   if ((n >= -1) && (n < x)) {
		  return 1;
	   }
	   return 0;
	}
	
	static uint16_t BytePrecision(uint16_t value){
		uint16_t i;
		for (i = sizeof(value); i; --i)
		    if (value >> (i - 1) * 8)
		        break;

		return i;
    }
	
	static uint32_t SetLength(uint16_t length, uint8_t* output){
		uint32_t i = 0, j;

		if (length < ASN_LONG_LENGTH)
		    output[i++] = (uint8_t)length;
		else {
		    output[i++] = (uint8_t)(BytePrecision(length) | ASN_LONG_LENGTH);
		  
		    for (j = BytePrecision(length); j; --j) {
		        output[i] = (uint8_t)(length >> (j - 1) * 8);
		        i++;
		    }
		}

		return i;
	}
	
	static uint32_t SetSequence(uint16_t len, uint8_t* output){
    	output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    	return SetLength(len, output + 1) + 1;
	}
	
	static int GetLength(uint8_t* input, uint16_t* inOutIdx, int* len, uint16_t maxIdx){
		int     length = 0;
		uint16_t  i = *inOutIdx;
		uint8_t    b;

		if ( (i+1) > maxIdx) {   /* for first read */
		    return BUFFER_E;
		}

		b = input[i++];
		if (b >= ASN_LONG_LENGTH) {        
		    uint16_t bytes = b & 0x7F;

		    if ( (i+bytes) > maxIdx) {   /* for reading bytes */
		        return BUFFER_E;
		    }

		    while (bytes--) {
		        b = input[i++];
		        length = (length << 8) | b;
		    }
		}
		else
		    length = b;
		
		if ( (i+length) > maxIdx) {   /* for user of length */
		    return BUFFER_E;
		}

		*inOutIdx = i;
		*len      = length;

		return length;
	}


	static int GetSequence(uint8_t* input, uint16_t* inOutIdx, int* len, uint16_t maxIdx){
		int    length = -1;
		uint16_t idx    = *inOutIdx;

		if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) || GetLength(input, &idx, &length, maxIdx) < 0)
		    return ASN_PARSE_E;

		*len      = length;
		*inOutIdx = idx;

		return length;
	}
	
	static int GetInt(mp_int* mpi, uint8_t* input, uint16_t* inOutIdx, uint16_t maxIdx){
		uint16_t i = *inOutIdx;
		uint8_t   b = input[i++];
		int    length;

		if (b != ASN_INTEGER)
		    return ASN_PARSE_E;

		if (GetLength(input, &i, &length, maxIdx) < 0)
		    return ASN_PARSE_E;

		if ( (b = input[i++]) == 0x00)
		    length--;
		else
		    i--;

		if (mp_read_unsigned_bin(mpi, (uint8_t*)input + i, length) != 0) {
		    return ASN_PARSE_E;
		}

		*inOutIdx = i + length;
		return 0;
	}
	
	void mp_print(mp_int* x, const char* str){
	  unsigned char strbuff[1000];
	  unsigned int i;

	  memset (&strbuff, 0 , 1000);
	  mp_to_unsigned_bin(x, strbuff);
	  for(i=0; strbuff[i] != 0; i++){
	  	printf("%02x:",strbuff[i] );
	  }

	  printf("%s", str);
	}
	
	command error_t ECC.init_key(mp_digit* memory, uint16_t memSize, ecc_key* key){
		int err;
		if(memSize < 4 * MP_PREC)
			return EINVAL;
			
		if ((err = mp_init(&(key->k), memory, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
		}
		
		if ((err = mp_init(&(key->pubkey.x), &memory[MP_PREC * 1], MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
		}
		
		if ((err = mp_init(&(key->pubkey.y), &memory[MP_PREC * 2], MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
		}
		
		if ((err = mp_init(&(key->pubkey.z), &memory[MP_PREC * 3], MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
		}
		return SUCCESS;
	}
	
	/* import public ECC key in ANSI X9.63 format. Key must already be initialized */
	command error_t ECC.import_x963(uint8_t* in, uint16_t inLen, ecc_key* key){
	   int x, err;

	   
	   if (in == NULL || key == NULL)
		   return EINVAL;

	   /* must be odd */
	   if ((inLen & 1) == 0) {
		  return EINVAL;
	   }

	   
	   err = MP_OKAY;

	   /* check for 4, 6 or 7 */
	   if (in[0] != 4 && in[0] != 6 && in[0] != 7) {
		  err = ASN_PARSE_E;
	   }

	   /* read data */
	   if (err == MP_OKAY) 
		   err = mp_read_unsigned_bin(&key->pubkey.x, (uint8_t*)in+1, (inLen-1)>>1);

	   if (err == MP_OKAY) 
		   err = mp_read_unsigned_bin(&key->pubkey.y, (uint8_t*)in+1+((inLen-1)>>1),
		                              (inLen-1)>>1);
	   
	   if (err == MP_OKAY) 
		   mp_set(&key->pubkey.z, 1);

	   if (err == MP_OKAY) {
		 /* determine the idx */
		  for (x = 0; ecc_sets[x].size != 0; x++) {
		     if ((unsigned)ecc_sets[x].size >= ((inLen-1)>>1)) {
		        break;
		     }
		  }
		  if (ecc_sets[x].size == 0) {
		     err = ASN_PARSE_E;
		  } else {
		      /* set the idx */
		      key->idx  = x;
		      key->dp = &ecc_sets[x];
		      key->type = ECC_PUBLICKEY;
		  }
	   }

	   if (err != MP_OKAY) {
		   return FAIL;
	   }

	   return SUCCESS;
	}
	
	/* ecc private key import, public key in ANSI X9.63 format, private raw */
	command error_t ECC.import_private_key(uint8_t* priv, uint16_t privSz, uint8_t* pub, uint16_t pubSz, ecc_key* key){
		error_t ret = call ECC.import_x963(pub, pubSz, key);
		if (ret != SUCCESS)
		    return ret;

		key->type = ECC_PRIVATEKEY;

		if(MP_OKAY != mp_read_unsigned_bin(&key->k, priv, privSz)){
			return FAIL;
		}
		
		return SUCCESS;
	}

	/**
	  Create an ECC shared secret between two keys
	  private_key      The private ECC key
	  public_key       The public key
	  out              [out] Destination of the shared secret
		               Conforms to EC-DH from ANSI X9.63
	  outlen           [in/out] The max size and resulting size of the shared secret
	  return           SUCCESS if successful
	*/
	command error_t ECC.shared_secret(ecc_key* private_key, ecc_key* public_key, uint8_t *out, uint16_t *outlen) {
	   uint32_t         x = 0;
	   ecc_point      result;
	   mp_int         prime;
	   int            err;
	   mp_digit bufferPrime[MP_PREC];
	   mp_digit bufferresultX[MP_PREC];
	   mp_digit bufferresultY[MP_PREC];
	   mp_digit bufferresultZ[MP_PREC];

	   if (private_key == NULL || public_key == NULL || out == NULL || outlen == NULL){
			#ifdef DO_PRINTF
			printf("parameter null, ");
			printfflush();
			#endif
		   return EINVAL;
	   
	   }
	   /* type valid? */
	   if (private_key->type != ECC_PRIVATEKEY) {
	   		#ifdef DO_PRINTF
			printf("not a valid private key, ");
			printfflush();
			#endif
		  return EINVAL;
	   }

	   if (ecc_is_valid_idx(private_key->idx) == 0 || ecc_is_valid_idx(public_key->idx)  == 0){
	   		#ifdef DO_PRINTF
			printf("curve index mismatch, ");
			printfflush();
			#endif
		  return EINVAL;
	   }	  

	   if (memcmp(private_key->dp->name, public_key->dp->name, ECC_MAXNAME) != 0){
	   		#ifdef DO_PRINTF
			printf("curve name mismatch, ");
			printfflush();
			#endif
		  return EINVAL;
	   }
	   /* make new point */
	   if ((err = mp_init(&(result.x), bufferresultX, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&(result.y), bufferresultY, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&(result.z), bufferresultZ, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }

	   if ((err = mp_init(&prime, bufferPrime, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }

	   err = mp_read_radix(&prime, (char *)private_key->dp->prime, 16);
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("read radix  ", err);
			printfflush();
		#endif
	   }
	   if (err == MP_OKAY)
		   err = _ecc_mulmod(&private_key->k, &public_key->pubkey, &result, &prime, 1);
		
		if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("ecc_mulmod  ", err);
			printfflush();
		#endif
	   }
		
	   if (err == MP_OKAY) {
		   x = (uint16_t)mp_unsigned_bin_size(&prime);
		   if (*outlen < x){
		      err = BUFFER_E;
		   #ifdef DO_PRINTF
			printf("ouput length missmatch, ");
			printfflush();
			#endif
		   }
	   }

	   if (err == MP_OKAY) {
		   memset(out, 0, x);
		   err = mp_to_unsigned_bin(&result.x,out + (x - mp_unsigned_bin_size(&result.x)));
		   *outlen = x;
		   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("to_unsigned_bin  ", err);
			printfflush();
		#endif
	   }
	   }
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("computation issue %d, ", err);
			printfflush();
		#endif
	   }	
	   return err;
	}
	
	/**
	  Sign a message digest
	  in        The message digest to sign
	  inlen     The length of the digest
	  out       [out] The destination for the signature
	  outlen    [in/out] The max size and resulting size of the signature
	  key       A private ECC key
	  return    SUCCESS if successful
	*/
	
	command error_t ECC.sign_hash(const uint8_t *in, uint16_t inlen, uint8_t *out, uint16_t *outlen, ecc_key *key){
	   mp_int        r;
	   mp_int        s;
	   mp_int        e;
	   mp_int        p;
	   int           err;
	   mp_digit bufferP[MP_PREC];
	   mp_digit bufferR[MP_PREC];
	   mp_digit bufferS[MP_PREC];
	   mp_digit bufferE[MP_PREC];

	   if (in == NULL || out == NULL || outlen == NULL || key == NULL)
		   return EINVAL;

	   // is this a private key? 
	   if (key->type != ECC_PRIVATEKEY) {
		  return EINVAL;
	   }
	   
	   // is the IDX valid ? 
	   if (ecc_is_valid_idx(key->idx) != 1) {
		  return EINVAL;
	   }

	   // get the hash and load it as a bignum into 'e' 
	   // init the bignums 
	   if ((err = mp_init(&p, bufferP, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&r, bufferR, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&s, bufferS, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&e, bufferE, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   err = mp_read_radix(&p, (char *)key->dp->order, 16);

	   if (err == MP_OKAY) {
		   int truncLen = (int)inlen;
		   if (truncLen > key->dp->size)
		       truncLen = key->dp->size;
		   err = mp_read_unsigned_bin(&e, (uint8_t*)in, truncLen);
	   }

	   // make up a key and export the public copy 
	   if (err == MP_OKAY) {
	   	   mp_digit pubkeybuff[MP_PREC*4];
		   ecc_key pubkey;
		   
		   if (SUCCESS != call ECC.init_key(pubkeybuff, MP_PREC*4, &pubkey)){
		   		return ENOMEM;
		   }
		   for (;;) {
		       err = _ecc_make_key_ex(&pubkey, key->dp);
		       if (err != MP_OKAY) break;

		       // find r = x1 mod n 
		       err = mp_mod(&pubkey.pubkey.x, &p, &r);
		       if (err != MP_OKAY) break;

		       if (mp_iszero(&r) != MP_YES) { 
		           // find s = (e + xr)/k 
		           err = mp_invmod(&pubkey.k, &p, &pubkey.k);
		           if (err != MP_OKAY) break;

		           err = mp_mulmod(&key->k, &r, &p, &s);   // s = xr 
		           if (err != MP_OKAY) break;
		       
		           err = mp_add(&e, &s, &s);               // s = e +  xr 
		           if (err != MP_OKAY) break;

		           err = mp_mod(&s, &p, &s);               // s = e +  xr 
		           if (err != MP_OKAY) break;

		           err = mp_mulmod(&s, &pubkey.k, &p, &s); // s = (e + xr)/k 
		           if (err != MP_OKAY) break;

		           if (mp_iszero(&s) == MP_NO)
		               break;
		        }
		   }
	   }

	   // store as SEQUENCE { r, s -- integer }
	   if (err == MP_OKAY)
		   err = _storeECC_DSA_Sig(out, outlen, &r, &s);
	   
	   return err;
	}
	
	/**
   Verify an ECC signature
   sig         The signature to verify
   siglen      The length of the signature (octets)
   hash        The hash (message digest) that was signed
   hashlen     The length of the hash (octets)
   stat        Result of signature, 1==valid, 0==invalid
   key         The corresponding public ECC key
   return      MP_OKAY if successful (even if the signature is not valid)
	*/
	command error_t ECC.verify(uint8_t* sig, uint16_t siglen, uint8_t* hash, uint16_t hashlen, int* stat, ecc_key* key){
	   ecc_point    mG, mQ;
	   mp_digit bufferMgx[MP_PREC];
	   mp_digit bufferMgy[MP_PREC];
	   mp_digit bufferMgz[MP_PREC];
	   mp_digit bufferMqx[MP_PREC];
	   mp_digit bufferMqy[MP_PREC];
	   mp_digit bufferMqz[MP_PREC];
	   
	   mp_int        r;
	   mp_digit bufferR[MP_PREC];
	   mp_int        s;
	   mp_digit bufferS[MP_PREC];
	   mp_int        v;
	   mp_digit bufferV[MP_PREC];
	   mp_int        w;
	   mp_digit bufferW[MP_PREC];
	   mp_int        u1;
	   mp_digit bufferU1[MP_PREC];
	   mp_int        u2;
	   mp_digit bufferU2[MP_PREC];
	   mp_int        e;
	   mp_digit bufferE[MP_PREC];
	   mp_int        p;
	   mp_digit bufferP[MP_PREC];
	   mp_int        m;
	   mp_digit bufferM[MP_PREC];
	   mp_digit      mp;
	   int           err;

	   if (sig == NULL || hash == NULL || stat == NULL || key == NULL)
		   return EINVAL; 

	   /* default to invalid signature */
	   *stat = 0;

	   /* is the IDX valid ?  */
	   if (ecc_is_valid_idx(key->idx) != 1) {
		  return EINVAL;
	   }

	   /* allocate ints */
	   if ((err = mp_init(&r, bufferR, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&s, bufferS, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&v, bufferV, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&w, bufferW, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&u1, bufferU1, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&u2, bufferU2, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&e, bufferE, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&p, bufferP, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&m, bufferM, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }

	   /* allocate points */
	   if ((err = mp_init(&(mG.x), bufferMgx, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&(mG.y), bufferMgy, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&(mG.z), bufferMgz, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   
	   if ((err = mp_init(&(mQ.x), bufferMqx, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&(mQ.y), bufferMqy, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   if ((err = mp_init(&(mQ.z), bufferMqz, MP_PREC)) != MP_OKAY) {
		  return ENOMEM;
	   }
	   

	   if (err == MP_OKAY) 
		   err = _decodeECC_DSA_Sig(sig, siglen, &r, &s);

	   /* get the order */
	   if (err == MP_OKAY)
		   err = mp_read_radix(&p, (char *)key->dp->order, 16);

	   /* get the modulus */
	   if (err == MP_OKAY)
		   err = mp_read_radix(&m, (char *)key->dp->prime, 16);

	   /* check for zero */
	   if (err == MP_OKAY) {
		   if (mp_iszero(&r) || mp_iszero(&s) || mp_cmp(&r, &p) != MP_LT || mp_cmp(&s, &p) != MP_LT)
		       err = EINVAL; 
	   }
	   /* read hash */
	   if (err == MP_OKAY) {
		   int truncLen = (int)hashlen;
		   if (truncLen > key->dp->size)
		       truncLen = key->dp->size;
		   err = mp_read_unsigned_bin(&e, (uint8_t*)hash, truncLen);
	   }

	   /*  w  = s^-1 mod n */
	   if (err == MP_OKAY)
		   err = mp_invmod(&s, &p, &w);

	   /* u1 = ew */
	   if (err == MP_OKAY)
		   err = mp_mulmod(&e, &w, &p, &u1);

	   /* u2 = rw */
	   if (err == MP_OKAY)
		   err = mp_mulmod(&r, &w, &p, &u2);

	   /* find mG and mQ */
	   if (err == MP_OKAY)
		   err = mp_read_radix(&(mG.x), (char *)key->dp->Gx, 16);

	   if (err == MP_OKAY)
		   err = mp_read_radix(&(mG.y), (char *)key->dp->Gy, 16);
	   if (err == MP_OKAY)
		   mp_set(&(mG.z), 1);

	   if (err == MP_OKAY)
		   err = mp_copy(&key->pubkey.x, &(mQ.x));
	   if (err == MP_OKAY)
		   err = mp_copy(&key->pubkey.y, &(mQ.y));
	   if (err == MP_OKAY)
		   err = mp_copy(&key->pubkey.z, &(mQ.z));

	#ifndef ECC_SHAMIR
		   /* compute u1*mG + u2*mQ = mG */
		   if (err == MP_OKAY)
		       err = _ecc_mulmod(&u1, &mG, &mG, &m, 0);
		   if (err == MP_OKAY)
		       err = _ecc_mulmod(&u2, &mQ, &mQ, &m, 0);
	  
		   /* find the montgomery mp */
		   if (err == MP_OKAY)
		       err = mp_montgomery_setup(&m, &mp);

		   /* add them */
		   if (err == MP_OKAY)
		       err = _ecc_projective_add_point(&mQ, &mG, &mG, &m, &mp);
	   
		   /* reduce */
		   if (err == MP_OKAY)
		       err = _ecc_map(&mG, &m, &mp);
	#else
		   /* use Shamir's trick to compute u1*mG + u2*mQ using half the doubles */
		   if (err == MP_OKAY)
		       err = ecc_mul2add(&mG, &u1, &mQ, &u2, &mG, &m);
	#endif /* ECC_SHAMIR */ 

	   /* v = X_x1 mod n */
	   if (err == MP_OKAY)
		   err = mp_mod(&(mG.x), &p, &v);

	   /* does v == r */
	   if (err == MP_OKAY) {
		   if (mp_cmp(&v, &r) == MP_EQ)
		       *stat = 1;
	   }
	   
	   return err;
	}
	
	
	/* size of sliding window, don't change this! */
	#define WINSIZE 4

	/**
	   Perform a point multiplication 
	   k    The scalar to multiply by
	   G    The base point
	   R    [out] Destination for kG
	   modulus  The modulus of the field the ECC curve is in
	   map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
	   return MP_OKAY on success
	*/
	int _ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* modulus, int map){
	   ecc_point tG, M[8];
	   int           i, j, err;
	   mp_int        mu;
	   mp_digit      mp;
	   unsigned long buf;
	   int           first, bitbuf, bitcpy, bitcnt, mode, digidx;
	   mp_digit bufferMu[MP_PREC];
	   mp_digit bufferMx[MP_PREC * 8];
	   mp_digit bufferMy[MP_PREC * 8];
	   mp_digit bufferMz[MP_PREC * 8];
	   mp_digit bufferTgx[MP_PREC];
	   mp_digit bufferTgy[MP_PREC];
	   mp_digit bufferTgz[MP_PREC];

	   if (k == NULL || G == NULL || R == NULL || modulus == NULL){
	   	#ifdef DO_PRINTF
			printf("bad arg ");
			printfflush();
		#endif
		   return ECC_BAD_ARG_E;
	   }	   

	   /* init montgomery reduction */
	   if ((err = mp_montgomery_setup(modulus, &mp)) != MP_OKAY) {
	   	#ifdef DO_PRINTF
			printf("mg setup ", err);
			printfflush();
		#endif
		  return err;
	   }
	   if ((err = mp_init(&mu, bufferMu, MP_PREC)) != MP_OKAY) {
	   	#ifdef DO_PRINTF
			printf("mu init ", err);
			printfflush();
		#endif
		  return err;
	   }
	   if ((err = mp_montgomery_calc_normalization(&mu, modulus)) != MP_OKAY) {
	   	#ifdef DO_PRINTF
			printf("mg calc normalization ", err);
			printfflush();
		#endif
		  return err;
	   }
	   
	  
	  /* alloc ram for window temps */
	  for (i = 0; i < 8; i++) {
		  if ((err = mp_init(&M[i].x, &bufferMx[MP_PREC * i], MP_PREC)) != MP_OKAY) 
		  		return MEMORY_E;
	   
		  if ((err = mp_init(&M[i].y, &bufferMy[MP_PREC * i], MP_PREC)) != MP_OKAY) 
		  		return MEMORY_E;
		  		
		  if ((err = mp_init(&M[i].z, &bufferMz[MP_PREC * i], MP_PREC)) != MP_OKAY) 
		  		return MEMORY_E;
	  }

	   /* make a copy of G incase R==G */
	   if ((err = mp_init(&tG.x, bufferTgx, MP_PREC)) != MP_OKAY) 
		  		return MEMORY_E;
	   
	   if ((err = mp_init(&tG.y, bufferTgy, MP_PREC)) != MP_OKAY) 
		  		return MEMORY_E;
		  		
	   if ((err = mp_init(&tG.z, bufferTgz, MP_PREC)) != MP_OKAY) 
		  		return MEMORY_E;

	   /* tG = G  and convert to montgomery */
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&mu, 1) == MP_EQ) {
		       err = mp_copy(&G->x, &tG.x);
		       if (err == MP_OKAY)
		           err = mp_copy(&G->y, &tG.y);
		       if (err == MP_OKAY)
		           err = mp_copy(&G->z, &tG.z);
		           if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("mp_copy ", err);
			printfflush();
		#endif
	   }
		   } else {
		       err = mp_mulmod(&G->x, &mu, modulus, &tG.x);
		       if (err == MP_OKAY)
		           err = mp_mulmod(&G->y, &mu, modulus, &tG.y);
		       if (err == MP_OKAY)
		           err = mp_mulmod(&G->z, &mu, modulus, &tG.z);
		           if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("mp_mulmod ", err);
			printfflush();
		#endif
	   }
		   }
	   }
	   
	   
	   /* calc the M tab, which holds kG for k==8..15 */
	   /* M[0] == 8G */
	   if (err == MP_OKAY)
		   err = _ecc_projective_dbl_point(&tG, &M[0], modulus, &mp);
	   if (err == MP_OKAY)
		   err = _ecc_projective_dbl_point(&M[0], &M[0], modulus, &mp);
	   if (err == MP_OKAY)
		   err = _ecc_projective_dbl_point(&M[0], &M[0], modulus, &mp);
	
		   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("projective_dbl_point  ", err);
			printfflush();
		#endif
	   }

	   /* now find (8+k)G for k=1..7 */
	   if (err == MP_OKAY)
		   for (j = 9; j < 16; j++) {
		       err = _ecc_projective_add_point(&M[j-9], &tG, &M[j-8], modulus, &mp);
		       if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("projective_add_point  ", err);
			printfflush();
		#endif
	   }
		       if (err != MP_OKAY) break;
	}
	
	   /* setup sliding window */
	   if (err == MP_OKAY) {
		   mode   = 0;
		   bitcnt = 1;
		   buf    = 0;
		   digidx = get_digit_count(k) - 1;
		   bitcpy = bitbuf = 0;
		   first  = 1;

		   /* perform ops */
		   for (;;) {
		       /* grab next digit as required */
		       if (--bitcnt == 0) {
		           if (digidx == -1) {
		               break;
		           }
		           buf    = get_digit(k, digidx);
		           bitcnt = (int) DIGIT_BIT; 
		           --digidx;
		       }

		       /* grab the next msb from the ltiplicand */
		       i = (buf >> (DIGIT_BIT - 1)) & 1;
		       buf <<= 1;

		       /* skip leading zero bits */
		       if (mode == 0 && i == 0)
		           continue;

		       /* if the bit is zero and mode == 1 then we double */
		       if (mode == 1 && i == 0) {
		           err = _ecc_projective_dbl_point(R, R, modulus, &mp);
		           if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("ecc_projective2  ", err);
			printfflush();
		#endif
	   }
		           if (err != MP_OKAY) break;
		           continue;
		       }

		       /* else we add it to the window */
		       bitbuf |= (i << (WINSIZE - ++bitcpy));
		       mode = 2;

		       if (bitcpy == WINSIZE) {
		           /* if this is the first window we do a simple copy */
		           if (first == 1) {
		               /* R = kG [k = first window] */
		               err = mp_copy(&M[bitbuf-8].x, &R->x);
		               if (err != MP_OKAY) break;

		               err = mp_copy(&M[bitbuf-8].y, &R->y);
		               if (err != MP_OKAY) break;

		               err = mp_copy(&M[bitbuf-8].z, &R->z);
		               first = 0;
		           } else {
		               /* normal window */
		               /* ok window is filled so double as required and add  */
		               /* double first */
		               for (j = 0; j < WINSIZE; j++) {
		                   err = _ecc_projective_dbl_point(R, R, modulus, &mp);
		                   if (err != MP_OKAY) break;
		               }
		               if (err != MP_OKAY) break;  /* out of first for(;;) */

		               /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranted */
		               err = _ecc_projective_add_point(R, &M[bitbuf-8], R, modulus, &mp);
		               if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("projective_add_point 2  ", err);
			printfflush();
		#endif
	   }
		           }
		           if (err != MP_OKAY) break;
		           /* empty window and reset */
		           bitcpy = bitbuf = 0;
		           mode = 1;
		       }
		   }
	   }

	   /* if bits remain then double/add */
	   if (err == MP_OKAY) {
		   if (mode == 2 && bitcpy > 0) {
		       /* double then add */
		       for (j = 0; j < bitcpy; j++) {
		           /* only double if we have had at least one add first */
		           if (first == 0) {
		               err = _ecc_projective_dbl_point(R, R, modulus, &mp);
		               if (err != MP_OKAY) break;
		           }

		           bitbuf <<= 1;
		           if ((bitbuf & (1 << WINSIZE)) != 0) {
		               if (first == 1) {
		                   /* first add, so copy */
		                   err = mp_copy(&tG.x, &R->x);
		                   if (err != MP_OKAY) break;

		                   err = mp_copy(&tG.y, &R->y);
		                   if (err != MP_OKAY) break;

		                   err = mp_copy(&tG.z, &R->z);
		                   if (err != MP_OKAY) break;
		                   first = 0;
		               } else {
		                   /* then add */
		                   err = _ecc_projective_add_point(R, &tG, R, modulus, &mp);
		                   if (err != MP_OKAY) break;
		               }
		           }
		       }
		   }
	   }

		
	   /* map R back from projective space */
	   
	   if (err == MP_OKAY && map)
		   err = _ecc_map(R, modulus, &mp);
	   	if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("ecc_map  ", err);
			printfflush();
		#endif
	   }
	   return err;
	}
	#undef WINSIZE

	/**
	   Double an ECC point
	   P   The point to double
	   R   [out] The destination of the double
	   modulus  The modulus of the field the ECC curve is in
	   mp       The "b" value from montgomery_setup()
	   return   MP_OKAY on success
	*/
	int _ecc_projective_dbl_point(ecc_point *P, ecc_point *R, mp_int* modulus, mp_digit* mp){
	   mp_int t1;
	   mp_int t2;
	   int    err;
	   mp_digit bufferT1[MP_PREC];
	   mp_digit bufferT2[MP_PREC];

	   if (P == NULL || R == NULL || modulus == NULL || mp == NULL)
		   return ECC_BAD_ARG_E;

	   if ((err = mp_init(&t1, bufferT1, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   
	   if ((err = mp_init(&t2, bufferT2, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   

	   if (P != R) {
		  err = mp_copy(&P->x, &R->x);
		  if (err == MP_OKAY)
			  err = mp_copy(&P->y, &R->y);
		  if (err == MP_OKAY)
			  err = mp_copy(&P->z, &R->z);
	   }

	   /* t1 = Z * Z */
	   if (err == MP_OKAY)
		   err = mp_sqr(&R->z, &t1);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t1, modulus, *mp);
	   	   
		if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("t1 = Z*Z ", err);
			printfflush();
		#endif
	   }
	   
	   /* Z = Y * Z */
	   if (err == MP_OKAY)
		   err = mp_mul(&R->z, &R->y, &R->z);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&R->z, modulus, *mp);

if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Z=Y*Z ", err);
			printfflush();
		#endif
	   }

	   /* Z = 2Z */
	   if (err == MP_OKAY)
		   err = mp_add(&R->z, &R->z, &R->z);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&R->z, modulus) != MP_LT)
			   err = mp_sub(&R->z, modulus, &R->z);
	   }
if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Z=2Z ", err);
			printfflush();
		#endif
	   }

	   /* T2 = X - T1 */
	   if (err == MP_OKAY)
		   err = mp_sub(&R->x, &t1, &t2);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&t2, 0) == MP_LT)
			   err = mp_add(&t2, modulus, &t2);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T2 = X-T1 ", err);
			printfflush();
		#endif
	   }
	   /* T1 = X + T1 */
	   if (err == MP_OKAY)
		   err = mp_add(&t1, &R->x, &t1);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t1, modulus) != MP_LT)
			   err = mp_sub(&t1, modulus, &t1);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T1 = X+ T1 ", err);
			printfflush();
		#endif
	   }
	   
	   /* T2 = T1 * T2 */
	   if (err == MP_OKAY)
		   err = mp_mul(&t1, &t2, &t2);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t2, modulus, *mp);

if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T2 = T1 * T2 ", err);
			printfflush();
		#endif
	   }

	   /* T1 = 2T2 */
	   if (err == MP_OKAY)
		   err = mp_add(&t2, &t2, &t1);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t1, modulus) != MP_LT)
			   err = mp_sub(&t1, modulus, &t1);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T1 = 2T2 ", err);
			printfflush();
		#endif
	   }
	   
	   /* T1 = T1 + T2 */
	   if (err == MP_OKAY)
		   err = mp_add(&t1, &t2, &t1);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t1, modulus) != MP_LT)
			   err = mp_sub(&t1, modulus, &t1);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T1 = T1 + T2 ", err);
			printfflush();
		#endif
	   }
	   
	   /* Y = 2Y */
	   if (err == MP_OKAY)
		   err = mp_add(&R->y, &R->y, &R->y);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&R->y, modulus) != MP_LT)
			   err = mp_sub(&R->y, modulus, &R->y);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Y = 2Y ", err);
			printfflush();
		#endif
	   }
	   
	   /* Y = Y * Y */
	   if (err == MP_OKAY)
		   err = mp_sqr(&R->y, &R->y);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&R->y, modulus, *mp);
	   
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Y = Y*Y ", err);
			printfflush();
		#endif
	   }
	   
	   /* T2 = Y * Y */
	   if (err == MP_OKAY)
		   err = mp_sqr(&R->y, &t2);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t2, modulus, *mp);

		if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T2 = Y*Y ", err);
			printfflush();
		#endif
	   }

	   /* T2 = T2/2 */
	   if (err == MP_OKAY) {
		   if (mp_isodd(&t2))
			   err = mp_add(&t2, modulus, &t2);
	   }
	   if (err == MP_OKAY)
		   err = mp_div_2(&t2, &t2);
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("T2 = T2/2 ", err);
			printfflush();
		#endif
	   }
	   
	   /* Y = Y * X */
	   if (err == MP_OKAY)
		   err = mp_mul(&R->y, &R->x, &R->y);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&R->y, modulus, *mp);

if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Y=Y*X ", err);
			printfflush();
		#endif
	   }

	   /* X  = T1 * T1 */
	   if (err == MP_OKAY)
		   err = mp_sqr(&t1, &R->x);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&R->x, modulus, *mp);

if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("X = T1*T1 ", err);
			printfflush();
		#endif
	   }

	   /* X = X - Y */
	   if (err == MP_OKAY)
		   err = mp_sub(&R->x, &R->y, &R->x);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&R->x, 0) == MP_LT)
			   err = mp_add(&R->x, modulus, &R->x);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("X = X-Y ", err);
			printfflush();
		#endif
	   }
	   
	   /* X = X - Y */
	   if (err == MP_OKAY)
		   err = mp_sub(&R->x, &R->y, &R->x);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&R->x, 0) == MP_LT)
			   err = mp_add(&R->x, modulus, &R->x);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("X = X-Y ", err);
			printfflush();
		#endif
	   }
	   /* Y = Y - X */     
	   if (err == MP_OKAY)
		   err = mp_sub(&R->y, &R->x, &R->y);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&R->y, 0) == MP_LT)
			   err = mp_add(&R->y, modulus, &R->y);
	   }
	   
	   if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Y = Y-X ", err);
			printfflush();
		#endif
	   }
	   
	   /* Y = Y * T1 */
	   if (err == MP_OKAY)
		   err = mp_mul(&R->y, &t1, &R->y);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&R->y, modulus, *mp);

if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Y = Y*T1 ", err);
			printfflush();
		#endif
	   }

	   /* Y = Y - T2 */
	   if (err == MP_OKAY)
		   err = mp_sub(&R->y, &t2, &R->y);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&R->y, 0) == MP_LT)
			   err = mp_add(&R->y, modulus, &R->y);
	   }

if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("Y = Y-T2 ", err);
			printfflush();
		#endif
	   }

	   return err;
	}



	/**
	   Add two ECC points
	   P        The point to add
	   Q        The point to add
	   R        [out] The destination of the double
	   modulus  The modulus of the field the ECC curve is in
	   mp       The "b" value from montgomery_setup()
	   return   MP_OKAY on success
	*/
	int _ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R, mp_int* modulus, mp_digit* mp){
	   mp_int t1;
	   mp_int t2;
	   mp_int x;
	   mp_int y;
	   mp_int z;
	   int    err;
	   mp_digit bufferT1[MP_PREC];
	   mp_digit bufferT2[MP_PREC];
	   mp_digit bufferX[MP_PREC];
	   mp_digit bufferY[MP_PREC];
	   mp_digit bufferZ[MP_PREC];

	   if (P == NULL || Q == NULL || R == NULL || modulus == NULL || mp == NULL)
		   return ECC_BAD_ARG_E;

	   if ((err = mp_init(&t1, bufferT1, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   
	   if ((err = mp_init(&t2, bufferT2, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   
	   if ((err = mp_init(&x, bufferX, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   
	   if ((err = mp_init(&y, bufferY, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   
	   if ((err = mp_init(&z, bufferZ, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   
	   /* should we dbl instead? */
	   err = mp_sub(modulus, &Q->y, &t1);

	   if (err == MP_OKAY) {
		   if ( (mp_cmp(&P->x, &Q->x) == MP_EQ) && 
		        (get_digit_count(&Q->z) && mp_cmp(&P->z, &Q->z) == MP_EQ) &&
		        (mp_cmp(&P->y, &Q->y) == MP_EQ || mp_cmp(&P->y, &t1) == MP_EQ)) {
		            return _ecc_projective_dbl_point(P, R, modulus, mp);
		   }
	   }

	   if (err == MP_OKAY)
		   err = mp_copy(&P->x, &x);
	   if (err == MP_OKAY)
		   err = mp_copy(&P->y, &y);
	   if (err == MP_OKAY)
		   err = mp_copy(&P->z, &z);

	   /* if Z is one then these are no-operations */
	   if (err == MP_OKAY) {
		   if (get_digit_count(&Q->z)) {
		       /* T1 = Z' * Z' */
		       err = mp_sqr(&Q->z, &t1);
		       if (err == MP_OKAY)
		           err = mp_montgomery_reduce(&t1, modulus, *mp);

		       /* X = X * T1 */
		       if (err == MP_OKAY)
		           err = mp_mul(&t1, &x, &x);
		       if (err == MP_OKAY)
		           err = mp_montgomery_reduce(&x, modulus, *mp);

		       /* T1 = Z' * T1 */
		       if (err == MP_OKAY)
		           err = mp_mul(&Q->z, &t1, &t1);
		       if (err == MP_OKAY)
		           err = mp_montgomery_reduce(&t1, modulus, *mp);

		       /* Y = Y * T1 */
		       if (err == MP_OKAY)
		           err = mp_mul(&t1, &y, &y);
		       if (err == MP_OKAY)
		           err = mp_montgomery_reduce(&y, modulus, *mp);
		   }
	   }

	   /* T1 = Z*Z */
	   if (err == MP_OKAY)
		   err = mp_sqr(&z, &t1);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t1, modulus, *mp);

	   /* T2 = X' * T1 */
	   if (err == MP_OKAY)
		   err = mp_mul(&Q->x, &t1, &t2);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t2, modulus, *mp);

	   /* T1 = Z * T1 */
	   if (err == MP_OKAY)
		   err = mp_mul(&z, &t1, &t1);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t1, modulus, *mp);

	   /* T1 = Y' * T1 */
	   if (err == MP_OKAY)
		   err = mp_mul(&Q->y, &t1, &t1);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t1, modulus, *mp);

	   /* Y = Y - T1 */
	   if (err == MP_OKAY)
		   err = mp_sub(&y, &t1, &y);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&y, 0) == MP_LT)
		       err = mp_add(&y, modulus, &y);
	   }
	   /* T1 = 2T1 */
	   if (err == MP_OKAY)
		   err = mp_add(&t1, &t1, &t1);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t1, modulus) != MP_LT)
		       err = mp_sub(&t1, modulus, &t1);
	   }
	   /* T1 = Y + T1 */
	   if (err == MP_OKAY)
		   err = mp_add(&t1, &y, &t1);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t1, modulus) != MP_LT)
		       err = mp_sub(&t1, modulus, &t1);
	   }
	   /* X = X - T2 */
	   if (err == MP_OKAY)
		   err = mp_sub(&x, &t2, &x);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&x, 0) == MP_LT)
		       err = mp_add(&x, modulus, &x);
	   }
	   /* T2 = 2T2 */
	   if (err == MP_OKAY)
		   err = mp_add(&t2, &t2, &t2);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t2, modulus) != MP_LT)
		       err = mp_sub(&t2, modulus, &t2);
	   }
	   /* T2 = X + T2 */
	   if (err == MP_OKAY)
		   err = mp_add(&t2, &x, &t2);
	   if (err == MP_OKAY) {
		   if (mp_cmp(&t2, modulus) != MP_LT)
		       err = mp_sub(&t2, modulus, &t2);
	   }

	   if (err == MP_OKAY) {
		   if (get_digit_count(&Q->z)) {
		       /* Z = Z * Z' */
		       err = mp_mul(&z, &Q->z, &z);
		       if (err == MP_OKAY)
		           err = mp_montgomery_reduce(&z, modulus, *mp);
		   }
	   }

	   /* Z = Z * X */
	   if (err == MP_OKAY)
		   err = mp_mul(&z, &x, &z);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&z, modulus, *mp);

	   /* T1 = T1 * X  */
	   if (err == MP_OKAY)
		   err = mp_mul(&t1, &x, &t1);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t1, modulus, *mp);

	   /* X = X * X */
	   if (err == MP_OKAY)
		   err = mp_sqr(&x, &x);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&x, modulus, *mp);
	   
	   /* T2 = T2 * x */
	   if (err == MP_OKAY)
		   err = mp_mul(&t2, &x, &t2);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t2, modulus, *mp);

	   /* T1 = T1 * X  */
	   if (err == MP_OKAY)
		   err = mp_mul(&t1, &x, &t1);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t1, modulus, *mp);
	 
	   /* X = Y*Y */
	   if (err == MP_OKAY)
		   err = mp_sqr(&y, &x);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&x, modulus, *mp);

	   /* X = X - T2 */
	   if (err == MP_OKAY)
		   err = mp_sub(&x, &t2, &x);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&x, 0) == MP_LT)
		       err = mp_add(&x, modulus, &x);
	   }
	   /* T2 = T2 - X */
	   if (err == MP_OKAY)
		   err = mp_sub(&t2, &x, &t2);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&t2, 0) == MP_LT)
		       err = mp_add(&t2, modulus, &t2);
	   } 
	   /* T2 = T2 - X */
	   if (err == MP_OKAY)
		   err = mp_sub(&t2, &x, &t2);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&t2, 0) == MP_LT)
		       err = mp_add(&t2, modulus, &t2);
	   }
	   /* T2 = T2 * Y */
	   if (err == MP_OKAY)
		   err = mp_mul(&t2, &y, &t2);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&t2, modulus, *mp);

	   /* Y = T2 - T1 */
	   if (err == MP_OKAY)
		   err = mp_sub(&t2, &t1, &y);
	   if (err == MP_OKAY) {
		   if (mp_cmp_d(&y, 0) == MP_LT)
		       err = mp_add(&y, modulus, &y);
	   }
	   /* Y = Y/2 */
	   if (err == MP_OKAY) {
		   if (mp_isodd(&y))
		       err = mp_add(&y, modulus, &y);
	   }
	   if (err == MP_OKAY)
		   err = mp_div_2(&y, &y);

	   if (err == MP_OKAY)
		   err = mp_copy(&x, &R->x);
	   if (err == MP_OKAY)
		   err = mp_copy(&y, &R->y);
	   if (err == MP_OKAY)
		   err = mp_copy(&z, &R->z);
	   return err;
	}

	/**
	  Map a projective jacbobian point back to affine space
	  P        [in/out] The point to map
	  modulus  The modulus of the field the ECC curve is in
	  mp       The "b" value from montgomery_setup()
	  return   MP_OKAY on success
	*/
	int _ecc_map(ecc_point* P, mp_int* modulus, mp_digit* mp){
	   mp_int t1;
	   mp_int t2;
	   int    err;
	   mp_digit bufferT1[MP_PREC];
	   mp_digit bufferT2[MP_PREC];	   

	   if (P == NULL || mp == NULL || modulus == NULL)
		   return ECC_BAD_ARG_E;

	   if ((err = mp_init(&t1, bufferT1, MP_PREC)) != MP_OKAY){
	       return err;
	   }
	   if ((err = mp_init(&t2, bufferT2, MP_PREC)) != MP_OKAY){
	       return err;
	   }

	   /* first map z back to normal */
	   err = mp_montgomery_reduce(&P->z, modulus, *mp);
	   
		if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("montgomery_reduce ", err);
			printfflush();
		#endif
	   }
	   
	   /* get 1/z */
	   if (err == MP_OKAY)
		   err = mp_invmod(&P->z, modulus, &t1);
		   
	if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("1/z ", err);
			printfflush();
		#endif
	   }	   
	 
	   /* get 1/z^2 and 1/z^3 */
	   if (err == MP_OKAY)
		   err = mp_sqr(&t1, &t2);
	   if (err == MP_OKAY)
		   err = mp_mod(&t2, modulus, &t2);
	   if (err == MP_OKAY)
		   err = mp_mul(&t1, &t2, &t1);
	   if (err == MP_OKAY)
		   err = mp_mod(&t1, modulus, &t1);


		if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("1/z^2 and 1/z^3 ", err);
			printfflush();
		#endif
	   }
	   /* multiply against x/y */
	   if (err == MP_OKAY)
		   err = mp_mul(&P->x, &t2, &P->x);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&P->x, modulus, *mp);
	   if (err == MP_OKAY)
		   err = mp_mul(&P->y, &t1, &P->y);
	   if (err == MP_OKAY)
		   err = mp_montgomery_reduce(&P->y, modulus, *mp);
		   
	if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("multiply against x/y ", err);
			printfflush();
		#endif
	   }
	   
	   if (err == MP_OKAY)
		   mp_set(&P->z, 1);
		if(err != MP_OKAY){
	   	#ifdef DO_PRINTF
			printf("mp_set ", err);
			printfflush();
		#endif
	   }

	   return err;
	}
	
	int _ecc_make_key_ex(ecc_key* key, const ecc_set_type* dp){
	   int            err;
	   ecc_point      base;
	   mp_int         prime;
	   mp_int         order;
	   uint8_t        buf[ECC_MAXSIZE];
	   int            keysize;
	   int		  	  have_rnd = 0;
	   mp_digit		  bufferPrime[MP_PREC];
	   mp_digit		  bufferOrder[MP_PREC];	
	   mp_digit 		bufferbaseX[MP_PREC];
	   mp_digit 		bufferbaseY[MP_PREC];
	   mp_digit 		bufferbaseZ[MP_PREC];   
		uint8_t* _rngoutput = buf;

	   if (key == NULL || dp == NULL)
		   return ECC_BAD_ARG_E;

	   key->idx = -1;
	   key->dp  = dp;
	   keysize  = dp->size;


	   /* make up random string */
	   //RNG_GenerateBlock(rng, buf, keysize);
	   call SeedInit.init((uint16_t) call MicroTime.get());
	   
	   while(have_rnd < keysize){
		   	uint32_t cur_secret = call Random.rand32();
		
			uint8_t i;
			uint8_t* p = (uint8_t*)&cur_secret;

			for(i = 0; i < MIN(4,(keysize - have_rnd)); i++){
				//we cannot write a zero, lest it gets mistaken for the separator!
				if (p[i] == 0) p[i]++;
				_rngoutput[i] = p[i];			
			}
			_rngoutput += MIN(4,(keysize - have_rnd));
	
		
			have_rnd += 4;
	   }
	   
	   buf[0] |= 0x0c;

	   /* setup the key variables */
	   if ((err = mp_init(&prime, bufferPrime, MP_PREC)) != MP_OKAY){
	       return MEMORY_E;
	   }
	   if ((err = mp_init(&order, bufferOrder, MP_PREC)) != MP_OKAY){
	       return MEMORY_E;
	   }

	   if ((err = mp_init(&(base.x), bufferbaseX, MP_PREC)) != MP_OKAY){
	       return MEMORY_E;
	   }
	   if ((err = mp_init(&(base.y), bufferbaseY, MP_PREC)) != MP_OKAY){
	       return MEMORY_E;
	   }
	   if ((err = mp_init(&(base.z), bufferbaseZ, MP_PREC)) != MP_OKAY){
	       return MEMORY_E;
	   }

	   /* read in the specs for this key */
	   if (err == MP_OKAY) 
		   err = mp_read_radix(&prime,   (char *)key->dp->prime, 16);
	   if (err == MP_OKAY) 
		   err = mp_read_radix(&order,   (char *)key->dp->order, 16);
	   if (err == MP_OKAY) 
		   err = mp_read_radix(&(base.x), (char *)key->dp->Gx, 16);
	   if (err == MP_OKAY) 
		   err = mp_read_radix(&(base.y), (char *)key->dp->Gy, 16);
	   
	   if (err == MP_OKAY) 
		   mp_set(&(base.z), 1);
	   if (err == MP_OKAY) 
		   err = mp_read_unsigned_bin(&key->k, (uint8_t*)buf, keysize);

	   /* the key should be smaller than the order of base point */
	   if (err == MP_OKAY) { 
		   if (mp_cmp(&key->k, &order) != MP_LT)
		       err = mp_mod(&key->k, &order, &key->k);
	   }
	   /* make the public key */
	   if (err == MP_OKAY)
		   err = _ecc_mulmod(&key->k, &base, &key->pubkey, &prime, 1);
	   if (err == MP_OKAY)
		   key->type = ECC_PRIVATEKEY;

	   return err;
	}
	
	/* Der Encode r & s ints into out, outLen is (in/out) size */
	int _storeECC_DSA_Sig(uint8_t* out, uint16_t* outLen, mp_int* r, mp_int* s){
		uint16_t idx = 0;
		uint16_t rSz;                           /* encoding size */
		uint16_t sSz;
		uint16_t headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

		int rLen = mp_unsigned_bin_size(r);   /* big int size */
		int sLen = mp_unsigned_bin_size(s);
		int err;

		if (*outLen < (rLen + sLen + headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
		    return ECC_BAD_ARG_E;

		idx = SetSequence(rLen + sLen + headerSz, out);

		/* store r */
		out[idx++] = ASN_INTEGER;
		rSz = SetLength(rLen, &out[idx]);
		idx += rSz;
		err = mp_to_unsigned_bin(r, &out[idx]);
		if (err != MP_OKAY) return err;
		idx += rLen;

		/* store s */
		out[idx++] = ASN_INTEGER;
		sSz = SetLength(sLen, &out[idx]);
		idx += sSz;
		err = mp_to_unsigned_bin(s, &out[idx]);
		if (err != MP_OKAY) return err;
		idx += sLen;

		*outLen = idx;

		return 0;
	}
	
	/* Der Decode ECC-DSA Signautre, r & s stored as big ints */
	int _decodeECC_DSA_Sig(uint8_t* sig, uint16_t sigLen, mp_int* r, mp_int* s){
		uint16_t idx = 0;
		int      len = 0;

		if (GetSequence(sig, &idx, &len, sigLen) < 0)
		    return ASN_ECC_KEY_E;

		if ((uint16_t)len > (sigLen - idx))
		    return ASN_ECC_KEY_E;

		if (GetInt(r, sig, &idx, sigLen) < 0)
		    return ASN_ECC_KEY_E;

		if (GetInt(s, sig, &idx, sigLen) < 0)
		    return ASN_ECC_KEY_E;

		return 0;
	}
}
