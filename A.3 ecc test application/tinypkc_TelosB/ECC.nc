#include "ecc.h"
#include "integer.h"
interface ECC {
	
	  command error_t init_key(mp_digit* memory, uint16_t memSize, ecc_key* key);
	  /**
	  Import Public Key in x9.63 Format.
	  in		byte array containing public key
	  inLen		Length of input
	  ecc_key	already initialized ecc_key
	  return	SUCCESS if successfull
	  */	
      command error_t import_x963(uint8_t* in, uint16_t inLen, ecc_key* key);
      
      command error_t import_private_key(uint8_t* priv, uint16_t privSz, uint8_t* pub, uint16_t pubSz, ecc_key* key);
      
	  /**
	  Create an ECC shared secret between two keys
	  private_key      The private ECC key
	  public_key       The public key
	  out              [out] Destination of the shared secret
		               Conforms to EC-DH from ANSI X9.63
	  outlen           [in/out] The max size and resulting size of the shared secret
	  return           SUCCESS if successful
	  */	
	  command error_t shared_secret(ecc_key* private_key, ecc_key* public_key, uint8_t *out, uint16_t *outlen);
	  
	  /**
	  Sign a message digest
	  in        The message digest to sign
	  inlen     The length of the digest
	  out       [out] The destination for the signature
	  outlen    [in/out] The max size and resulting size of the signature
	  key       A private ECC key
	  return    SUCCESs if successful
	  */
      command error_t sign_hash(const uint8_t *in, uint16_t inlen, uint8_t *out, uint16_t *outlen, ecc_key *key);
	  
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
	  command error_t verify(uint8_t* sig, uint16_t siglen, uint8_t* hash, uint16_t hashlen, int* stat, ecc_key* key);
}
