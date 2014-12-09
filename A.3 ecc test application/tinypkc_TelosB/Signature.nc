/*
 * Copyright (c) 2011 CSIRO Australia
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the CSIRO nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/**
 * Digitally sign and verify data.
 *
 * @author	Adrian Herrera <adrian.herrera@csiro.au>
 * @date	15/1/2011
*/

interface Signature
{
	/**
	 * Set the public key used in the verifcation of the signature.
	 *
	 * @param publicKey	A pointer to the public key to use in the encryption
	 * 					process.
	 * @param len		Length of the public key.
	 * @return			SUCCESS if the key can be set.
	*/
	command error_t setPublicKey (const uint8_t* publicKey, uint16_t len);

	/**
	 * Get the public key used in the verification of the signature
	 *
	 * @return			SUCCESS if the key can be read.
	*/
	command error_t getPublicKey ();

	/**
	 * Sign a message using the stored private key.
	 *
	 * @param digest	A pointer to the digest to be signed.
	 * @param len		Length of the digest to be signed.
	 * @return			SUCCESS if the signature can be generated.
	*/
	command error_t sign (const uint8_t* digest, uint16_t len);

	/**
	 * Verify the signature of a signed message.
	 *
	 * @param digest		A pointer to the digest that was signed.
	 * @param digestLen		Length of the digest that was signed.
	 * @param signature		A pointer to the message's signature.
	 * @param signatureLen	Length of the signature.
	 * @return				SUCCESS if the signature can be verified.
	*/
	command error_t verify (const uint8_t* digest, uint16_t digestLen,
							const uint8_t* signature, uint16_t signatureLen);

	/**
	 * Notification that the public key was initialised.
	 *
	 * @param error		SUCCESS if the operation completed successfully,
	 * 					FAIL otherwise.
	*/
	event void setPublicKeyDone (error_t error);

	/**
	 * Notification that the public key was retrieved.
	 *
	 * @param publicKey	A pointer to the public key.
	 * @param len		Length of the public key.
	 * @param error		SUCCESS if the operation completed successfully,
	 *					FAIL otherwise.
	*/
	event void getPublicKeyDone (uint8_t* publicKey, uint16_t len,
								error_t error);

	/**
	 * Notification that the sign command has completed.
	 *
	 * @param signature	A pointer to the digital signature.
	 * @param len		Length of the signature.
	 * @param error		SUCCESS if the operation complated successfully,
	 * 					FAIL otherwise.
	*/
	event void signDone (uint8_t* signature, uint16_t len, error_t error);

	/**
	 * Notification that the verify signature command has completed.
	 *
	 * @param error		SUCCESS if the operation completed successfully,
	 * 					FAIL otherwise.
	*/
	event void verifyDone (error_t error);
}

