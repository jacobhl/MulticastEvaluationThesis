/* 
 * This file is based on a CyaSSL file: (cyassl-2.2.0/ctaocrypt/src/rsa.c)
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
 * TinyOS Port of CyaSSL RSA implementation
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	27/8/2012
 */


#include "RsaTK.h"

#include "integer.h"

module RsaTKP {
	provides interface Rsa;
	provides interface RsaPrivateKey;
	provides interface Signature;
	
	uses interface RsaPadding;
} implementation {
	
	mp_int pubModulus;
	mp_int pubExponent;
	#ifdef RSA_LOW_MEM
		mp_int privExponent;
		mp_int privModulus;
	#else
		mp_int privdP, privP;
		mp_int privdQ, privQ;
		mp_int privU;
	#endif
	
	mp_digit bufferPubMod[MP_PREC];
	mp_digit bufferPubExp[EXP_LEN];
	
	#ifdef RSA_LOW_MEM
		mp_digit bufferPrivMod[MP_PREC];
		mp_digit bufferPrivExp[MP_PREC];
	#else
		mp_digit bufferPrivdP[MP_PREC / 2 +1];
		mp_digit bufferPrivP[MP_PREC / 2 +1];
		mp_digit bufferPrivdQ[MP_PREC / 2 +1];
		mp_digit bufferPrivQ[MP_PREC / 2 +1];
		mp_digit bufferPrivU[MP_PREC / 2 +1];
	#endif
	
	uint8_t buff[RSA_MAX_MSG_LEN];
	uint8_t digestBuff[SHA1_HASH_LEN];

	uint8_t state = RSA_MODE_IDLE;
	
	uint16_t workMsgLen, workOutLen;
	
	task void readPubKeyTask();
	task void setPubKeyTask();
	task void privDecryptTask();
	task void verifyTask();
	
	static error_t _setPubKey(const uint8_t* key, uint16_t len);
	static error_t _pubKeyOp(const uint8_t* msg, uint16_t len, uint16_t *outlen);
	static error_t _privKeyOp(const uint8_t* msg, uint16_t len, uint16_t *outlen);
	static error_t _keyPrepareOp(mp_int* tmp, mp_digit* buffer, uint16_t buffLen, const uint8_t* msg, uint16_t len);
	static error_t _keyFinishOp(mp_int* tmp, uint16_t len, uint16_t *outLen);

	command error_t Rsa.setPublicKey (const uint8_t* publicKey, uint16_t len) {
		return _setPubKey(publicKey, len);
	}

	command error_t Rsa.getPublicKey (){
	// we don't return the actual key later on, instead this call can be used to check if a key has been set.
		if((&pubModulus == NULL) || (pubModulus.dp == NULL) || (pubModulus.used == 0)){
			return FAIL;
		}
		
		post readPubKeyTask();
		
		return SUCCESS;
	}

	command error_t Rsa.encrypt (const uint8_t* msg, uint16_t len){
		//Public Key encryption
		
		if(state != RSA_MODE_IDLE || len > RSA_MAX_MSG_LEN){
			return FAIL;
		}
		state = RSA_MODE_ENC_PUBLIC;
		
		memcpy(buff, msg, len);
		
		
        //do PCKS#1 v1.5 padding
        return call RsaPadding.rsaPad(buff, len, buff, RSA_MAX_MSG_LEN, FALSE);
	}

	command error_t Rsa.decrypt (const uint8_t* msg, uint16_t len){
		//Private Key decryption
		if(state != RSA_MODE_IDLE || len > RSA_MAX_MSG_LEN){
			return FAIL;
		}
		
		state = RSA_MODE_DEC_PRIV;
		
		//take it from the stack, just to be sure
		memcpy(buff, msg, len);
		
		workMsgLen = len;
		workOutLen = 0;
		post privDecryptTask();
		return SUCCESS;
	}
	
	command error_t Signature.setPublicKey (const uint8_t* publicKey, uint16_t len){
		return _setPubKey(publicKey, len);
	}

	
	command error_t Signature.getPublicKey (){
		return FAIL;
	}
	
	command error_t Signature.sign (const uint8_t* digest, uint16_t len){
		//Private Key encryption
		
		if(state != RSA_MODE_IDLE || len > SHA1_HASH_LEN){
			return FAIL;
		}
		
		state = RSA_MODE_ENC_PRIV;
		
		memcpy(buff, digest, len);
		
        //do PCKS#1 v1.5 padding
        return call RsaPadding.rsaPad(buff, len, buff, RSA_MAX_MSG_LEN, TRUE);
	}
	
	command error_t Signature.verify (const uint8_t* digest, uint16_t digestLen, const uint8_t* signature, uint16_t signatureLen){
		if(state != RSA_MODE_IDLE || digestLen != SHA1_HASH_LEN || signatureLen != RSA_MAX_MSG_LEN){
			return FAIL;
		}
		
		state = RSA_MODE_DEC_PUBLIC;
		
		//take it from the stack, just to be sure
		memcpy(buff, signature, signatureLen);
		memcpy(digestBuff, digest, digestLen);

		workMsgLen = signatureLen;
		workOutLen = 0;
		post verifyTask();

		return SUCCESS;
	}
	
#ifdef RSA_LOW_MEM
	command error_t RsaPrivateKey.setPrivateKey (const uint8_t* privExp,const uint8_t* privMod, uint16_t len){
		if(state != RSA_MODE_IDLE){
			return FAIL;
		}
		state = RSA_MODE_OTHER;
				
		//set the private Exponent
		if(mp_init(&privExponent, bufferPrivExp, MP_PREC) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privExponent, privExp, len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		if(mp_init(&privModulus, bufferPrivMod, MP_PREC) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privModulus, privMod, len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}

		state = RSA_MODE_IDLE;
		return SUCCESS;
	}
#else
	command error_t RsaPrivateKey.setPrivateKey (const uint8_t* dP, uint16_t dP_len, 
								   const uint8_t* dQ, uint16_t dQ_len, 
								   const uint8_t* p, uint16_t p_len, 
								   const uint8_t* q, uint16_t q_len, 
								   const uint8_t* u, uint16_t u_len){
	   	
	   	if(state != RSA_MODE_IDLE){
			return FAIL;
		}
		state = RSA_MODE_OTHER;
				
		//set the private Key
		if(mp_init(&privdP, bufferPrivdP, MP_PREC / 2 +1) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privdP, dP, dP_len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		if(mp_init(&privdQ, bufferPrivdQ, MP_PREC / 2 +1) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privdQ, dQ, dQ_len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		if(mp_init(&privP, bufferPrivP, MP_PREC / 2 +1) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privP, p, p_len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		if(mp_init(&privQ, bufferPrivQ, MP_PREC / 2 +1) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privQ, q, q_len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		if(mp_init(&privU, bufferPrivU, MP_PREC / 2 +1) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&privU, u, u_len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		state = RSA_MODE_IDLE;
		return SUCCESS;
    }
#endif

	command bool RsaPrivateKey.havePrivateKeySet(){
#ifdef RSA_LOW_MEM
		if(&privModulus == NULL || privModulus.dp == NULL || privModulus.used == 0){
				return FALSE;
		}
#else
		if(&privdP == NULL || privdP.dp == NULL || privdP.used == 0){
				return FALSE;
		}
	
		if(&privdQ== NULL || privdQ.dp == NULL || privdQ.used == 0){
				return FALSE;
		}
	
		if(&privP == NULL || privP.dp == NULL || privP.used == 0){
				return FALSE;
		}
	
		if(&privQ == NULL || privQ.dp == NULL || privQ.used == 0){
				return FALSE;
		}
	
		if(&privU == NULL || privU.dp == NULL || privU.used == 0){
				return FALSE;
		}
#endif

		return TRUE;
	}
	
	event void RsaPadding.padDone (uint8_t* msg, uint16_t len, error_t error){
		uint16_t outlen = 0;
		
		if(error != SUCCESS){
		    goto error_exit;
		}
		
		if(state == RSA_MODE_ENC_PUBLIC){
			
			if(_pubKeyOp(msg, len, &outlen) != SUCCESS){
				goto error_exit;
			}
		    
		    //all done
		    state = RSA_MODE_IDLE;
		    signal Rsa.encryptDone (buff, outlen, SUCCESS);
		    return;
		    
        } else if(state == RSA_MODE_ENC_PRIV){
        	
        	if(_privKeyOp(msg, len, &outlen) != SUCCESS){
				goto error_exit;
			}
		    
		    //all done
		    state = RSA_MODE_IDLE;
		    signal Signature.signDone (buff, outlen, SUCCESS);
		    return;
			
        } //Fallthrough case: error_exit
        
        error_exit:
        if(state == RSA_MODE_ENC_PUBLIC){
       		signal Rsa.encryptDone (NULL, 0, FAIL);
		}else if(state == RSA_MODE_ENC_PRIV){
			signal Signature.signDone (NULL, 0, FAIL);
		}
        state = RSA_MODE_IDLE;
	}
	
	event void RsaPadding.unPadDone (uint8_t* msg, uint16_t len, error_t error){
		if (state == RSA_MODE_DEC_PUBLIC){
		    //verify if msg == digest
		    if(len != SHA1_HASH_LEN){
				//not a proper SHA1 hash
		    	goto error_exit;
		    }
		    
		    if(memcmp(msg, digestBuff, SHA1_HASH_LEN) != 0){
				//hashes differ
		    	goto error_exit;
		    }
		    
		    //successfull verification
		    state = RSA_MODE_IDLE;
		    signal Signature.verifyDone (SUCCESS);
		    return;
		} else if (state == RSA_MODE_DEC_PRIV){
		    state = RSA_MODE_IDLE;
		    signal Rsa.decryptDone (buff, len, SUCCESS);
		    return;
		}
	
		error_exit:
        if(state == RSA_MODE_DEC_PUBLIC){
			signal Signature.verifyDone (FAIL);
		}else if(state == RSA_MODE_DEC_PRIV){
       		signal Rsa.decryptDone (NULL, 0, FAIL);
		}
		state = RSA_MODE_IDLE;
	}
	
	task void readPubKeyTask(){
	/* this would require another statically allocated buffer, because the command 
	 * Rsa.getPublicKey() does not specify a user allocated buffer, and is not worth
	 * the memory in my opinion. The key was set by the user anyway and is stored 
	 * in the mp_int, so it would require a conversion back into an unsigned raw value.
	 */
		signal Rsa.getPublicKeyDone(NULL, 0, FAIL);
	}
	
	task void setPubKeyTask(){
		signal Rsa.setPublicKeyDone(SUCCESS);
	}
	
	task void privDecryptTask(){
		error_t privError;

		privError = _privKeyOp(buff, workMsgLen, &workOutLen);

		if(privError == SUCCESS){
			privError = call RsaPadding.rsaUnPad(buff, workMsgLen, buff, RSA_MAX_MSG_LEN, FALSE);
		}
		if(privError != SUCCESS){
			signal Rsa.decryptDone(NULL, 0, FAIL);
		}
	}
	
	task void verifyTask(){
		error_t err;
		
		err = _pubKeyOp(buff, workMsgLen, &workOutLen);
		
		if(err == SUCCESS){
			err = call RsaPadding.rsaUnPad(buff, workOutLen, buff, RSA_MAX_MSG_LEN, TRUE);
		}
		
		if(err != SUCCESS){
			state = RSA_MODE_IDLE;
		    signal Signature.verifyDone (FAIL);
		}
	}
	
	
	static error_t _setPubKey(const uint8_t* key, uint16_t len){
		if(state != RSA_MODE_IDLE){
			return FAIL;
		}
		state = RSA_MODE_OTHER;
		
		//Exponent is hardcoded to 65537 (0x010001)
		if(mp_init(&pubExponent, bufferPubExp, EXP_LEN) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&pubExponent, expo, 3) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		
		//set the public Key
		if(mp_init(&pubModulus, bufferPubMod, MP_PREC) != MP_OKAY){
			state = RSA_MODE_IDLE;	
			return (FAIL);
		}
		
		if(mp_read_unsigned_bin(&pubModulus, key, len) != MP_OKAY){
			state = RSA_MODE_IDLE;
			return (FAIL);
		}
		state = RSA_MODE_IDLE;
		post setPubKeyTask();
		return SUCCESS;
	}
	
	static error_t _pubKeyOp(const uint8_t* msg, uint16_t len, uint16_t* outlen){
		mp_int tmp;
		mp_digit bufferTmp[MP_PREC];
		
		//initialize buffer with message
		if(_keyPrepareOp(&tmp, bufferTmp, MP_PREC, msg, len) != SUCCESS){
			goto error_exit;
		}
		
		//perform msg ^ e mod n
		if (mp_exptmod(&tmp, &pubExponent, &pubModulus, &tmp) != MP_OKAY){
	    	goto error_exit;
	    }
 		return _keyFinishOp(&tmp, len, outlen);
		
		error_exit:
		state = RSA_MODE_IDLE;
		return FAIL;
	}
	
	static error_t _privKeyOp(const uint8_t* msg, uint16_t len, uint16_t* outlen){
		mp_int tmp;
		mp_digit bufferTmp[MP_PREC];
		
		//initialize buffer with message
		if(_keyPrepareOp(&tmp, bufferTmp, MP_PREC, msg, len) != SUCCESS){
			goto error_exit;
		}
		
		#ifdef RSA_LOW_MEM       /* half as much memory but twice as slow */
			//perform msg ^ d mod n
        	if (mp_exptmod(&tmp, &privExponent, &privModulus, &tmp) != MP_OKAY){
            	goto error_exit;
            }
    	#else
    	{
	        mp_int tmpa, tmpb;
			mp_digit bufferTmpA[MP_PREC];
			mp_digit bufferTmpB[MP_PREC];
			
	        if (mp_init(&tmpa, bufferTmpA, MP_PREC) != MP_OKAY){
	            goto error_exit;
	       }

	        if (mp_init(&tmpb, bufferTmpB, MP_PREC) != MP_OKAY){
	            goto error_exit;
	        }

	        /* tmpa = tmp^dP mod p */
	        if (mp_exptmod(&tmp, &privdP, &privP, &tmpa) != MP_OKAY){
	            goto error_exit;
	        }

	        /* tmpb = tmp^dQ mod q */
	        if (mp_exptmod(&tmp, &privdQ, &privQ, &tmpb) != MP_OKAY){
	            goto error_exit;
	        }

	        /* tmp = (tmpa - tmpb) * qInv (mod p) */
	        if (mp_sub(&tmpa, &tmpb, &tmp) != MP_OKAY){
	            goto error_exit;
	        }

	        if (mp_mulmod(&tmp, &privU, &privP, &tmp) != MP_OKAY){
	            goto error_exit;
	        }

	        /* tmp = tmpb + q * tmp */
	        if (mp_mul(&tmp, &privQ, &tmp) != MP_OKAY){
	            goto error_exit;
	        }

	        if (mp_add(&tmp, &tmpb, &tmp) != MP_OKAY){
	            goto error_exit;
	        }
        }
    #endif   /* RSA_LOW_MEM */
    
	 	return _keyFinishOp(&tmp, len, outlen);
        	 	
        error_exit:
		state = RSA_MODE_IDLE;
		return FAIL;
	
	}
	
	static error_t _keyPrepareOp(mp_int* tmp, mp_digit* buffer, uint16_t buffLen, const uint8_t* msg, uint16_t len){
		//buffer for message
		if(mp_init(tmp, buffer, buffLen) != MP_OKAY){
	    	return FAIL;
		}
	
		//read from input
		if(mp_read_unsigned_bin(tmp, msg, len) != MP_OKAY){
	    	return FAIL;
		}
		
		return SUCCESS;
	}
	
	static error_t _keyFinishOp( mp_int* tmp, uint16_t len, uint16_t* outLen){
		uint16_t i = 0;
		
		*outLen = mp_unsigned_bin_size(tmp);
	    
	    if(*outLen > RSA_MAX_MSG_LEN){
	    	goto error_exit;
	    }

		/* pad front w/ zeros to match key length */
		while (len < RSA_MAX_MSG_LEN) {
			buff[i++] = 0x00;
			*outLen++;
		}

		*outLen = RSA_MAX_MSG_LEN;

		/* convert */
		if (mp_to_unsigned_bin(tmp, &buff[i]) != MP_OKAY){
			goto error_exit;
		}
		
		return SUCCESS;
		
		error_exit:
		state = RSA_MODE_IDLE;
		return FAIL;
	}
}

