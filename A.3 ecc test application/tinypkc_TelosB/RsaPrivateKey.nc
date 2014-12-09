/**
 * Sets the RSA Private Key for software RSA operations
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	27/7/2012
*/

interface RsaPrivateKey
{
	
	#ifdef RSA_LOW_MEM
	/**
	 * Set the public key used in the RSA encryption.
	 *
	 * @param privKey	A pointer to the private key exponent to use.
	 * @param len		Length of the private key.
	 * @return			SUCCESS if the key can be set.
	*/
	command error_t setPrivateKey (const uint8_t* privExponent, const uint8_t* privModulus, uint16_t len);

	#else
	
	command error_t setPrivateKey (const uint8_t* dP, uint16_t dP_len, 
								   const uint8_t* dQ, uint16_t dQ_len, 
								   const uint8_t* p, uint16_t p_len, 
								   const uint8_t* q, uint16_t q_len, 
								   const uint8_t* u, uint16_t u_len);
	
	#endif
	
	command bool havePrivateKeySet();
}	
