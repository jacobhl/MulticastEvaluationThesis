 /*
 * This file is based on a CyaSSL file: (cyassl-2.2.0/ctaocrypt/src/rsa.h).
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
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
 
enum {
	RSA_BLOCK_TYPE_1 = 1,
    RSA_BLOCK_TYPE_2 = 2,
};

#include "RsaTK.h"

module RsaPaddingP{

	provides interface RsaPadding;
	
	uses interface Random;
	uses interface ParameterInit<uint16_t> as SeedInit;
	uses interface LocalTime<TMicro> as MicroTime;
	
} implementation {
	uint8_t *_input, *_output, *_outStart;
	uint16_t inLen, maxOutLen, outLen;
	bool busy = FALSE;
	uint8_t	padType;
	int16_t padLen;
	
	task void padTask();
	task void unPadTask();
	task void rndTask(); // fill padding buffer with random values
	

	command error_t RsaPadding.rsaPad (uint8_t* input, uint16_t len, uint8_t* output, uint16_t maxlen, bool signature){
		uint16_t newLen = len;		
			
		if(busy)
			return FAIL;
		
		newLen = RSA_MAX_MSG_LEN;
		
		if(maxlen < newLen)
			return FAIL;
			
		if(len > newLen -3)	
			return FAIL;
			
		busy = TRUE;			
		memmove(output + (newLen - len), input, len);

		_input = input;
		_output = output;
		_outStart = output;
		inLen = len;
		maxOutLen = maxlen;
		outLen = RSA_MAX_MSG_LEN;
		
		if(signature == TRUE){
			padType = RSA_BLOCK_TYPE_1;
		} else{
			padType = RSA_BLOCK_TYPE_2;
		}
		
		_output[0] = 0x0;       /* set first byte to zero and advance */
		_output[1] = padType;  /* insert padType */
		_output+=2;
		outLen-=2;
		
		
		if(signature == TRUE){
			//set everything else to 0xFF
			memset(_output, 0xFF, outLen - inLen - 1);
			_output +=  outLen - inLen - 1;
			post padTask();
		} else {
			//seed the RNG with the Microtime (should have quite some entrophy)
			call SeedInit.init((uint16_t) call MicroTime.get());
			
			padLen = outLen - inLen - 1;
			post rndTask();
		}
		return SUCCESS;
	}

	command error_t RsaPadding.rsaUnPad (uint8_t* input, uint16_t len, uint8_t* output, uint16_t maxlen, bool signature){
		uint8_t invalid = 0;
		uint16_t i = 1;
		
		if(busy)
			return FAIL;
			
		_input = input;
		inLen = len;
		_output = output;
		maxOutLen = maxlen;
		
		if(RSA_MAX_MSG_LEN > 10){
			maxOutLen = RSA_MAX_MSG_LEN - 10;
		} else { 
			maxOutLen = 0;
		}
		       

		if (_input[0] == 0x0){ /* skip past zero */
			_input++; 
			inLen--;
		}else{
			//invalid = 1;
		}
		
		if(signature == TRUE){
			padType = RSA_BLOCK_TYPE_1;
		} else{
			padType = RSA_BLOCK_TYPE_2;
		}

		/* Require block type padValue */
		invalid = (_input[0] != padType) || invalid;

		/* skip past the padding until we find the separator */
		while (i<inLen && _input[i++]) {/* null body */}
		
		if(!(i==inLen || _input[i-1]==0)) {
		    //RsaUnPad error, bad formatting
			signal RsaPadding.unPadDone(NULL, 0, FAIL);
			return FAIL;
		}

		outLen = inLen - i;
		invalid = (outLen > maxOutLen) || invalid;

		if (invalid) {
		    //RsaUnPad error, bad formatting
			signal RsaPadding.unPadDone(NULL, 0, FAIL);
			return FAIL;
		}
		
		if(outLen > maxlen){
			//Output buffer not large enough!
			signal RsaPadding.unPadDone(NULL, 0, FAIL);
			return FAIL;
		}

		memcpy(_output, (uint8_t *)(_input + i), outLen);
		post unPadTask();
		return SUCCESS;
	}

	task void rndTask(){
		uint32_t cur_secret = call Random.rand32();
		
		
		uint8_t i;
		uint8_t* p = (uint8_t*)&cur_secret;

		for(i = 0; i < MIN(4,padLen); i++){
			//we cannot write a zero, lest it gets mistaken for the separator!
			if (p[i] == 0) p[i]++;
			_output[i] = p[i];			
		}
		_output += MIN(4,padLen);
	
		
		padLen -= 4;
		
		if(padLen > 0){
			post rndTask();
		} else{
			post padTask();
		}
	}
	
	task void padTask(){
		_output[0] = 0;     /* separator */
		busy = FALSE;
		signal RsaPadding.padDone(_outStart, RSA_MAX_MSG_LEN, SUCCESS);
	}
	task void unPadTask(){
		busy = FALSE;
		signal RsaPadding.unPadDone(_output, outLen, SUCCESS);
	}
}
