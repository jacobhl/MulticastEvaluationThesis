/*
 * Copyright (c) 2010 CSIRO Australia
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
 * Perform RSA encryption/decryption using a public/private key pair.
 *
 * @author	Adrian Herrera <adrian.herrera@csiro.au>
 * @date	8/12/2010
*/

interface Rsa
{
	/**
	 * Set the public key used in the RSA encryption.
	 *
	 * @param publicKey	A pointer to the public key to use in the encryption
	 *					process.
	 * @param len		Length of the public key.
	 * @return			SUCCESS if the key can be set.
	*/
	command error_t setPublicKey (const uint8_t* publicKey, uint16_t len);

	/**
	 * Get the public key used in the RSA encryption.
	 *
	 * @return			SUCCESS if the key can be read.
	*/
	command error_t getPublicKey ();

	/**
	 * Perform encryption of a message using the stored public key.
	 *
	 * @param msg	A pointer to the message to be encrypted.
	 * @param len	Length of the message to be encrypted.
	 * @return		SUCCESS if the message can be encrypted.
	*/
	command error_t encrypt (const uint8_t* msg, uint16_t len);

	/**
	 * Perform decryption of a message using the stored private key.
	 *
	 * @param msg	A pointer to the message to be decrypted.
	 * @param len	Length of the message to be decrypted.
	 * @return		SUCCESS if the message can be decrypted.
	*/
	command error_t decrypt (const uint8_t* msg, uint16_t len);

	/**
	 * Notification that the public key was initialised.
	 *
	 * @param error		SUCCESS if the operation completed successfully,
	 *					FAIL otherwise.
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
	 * Notification that the encrypt command has completed.
	 *
	 * @param encryptedMsg	A pointer to the encrypted message.
	 * @param error			SUCCESS if the operation completed successfully,
	 *						FAIL otherwise.
	*/
	event void encryptDone (uint8_t* encryptedMsg, uint16_t len, error_t error);

	/**
	 * Notification that the decrypt command was completed.
	 *
	 * @param decryptedMsg	A pointer to the decrypted message.
	 * @param error			SUCCESS if the operation completed successfully,
	 *						FAIL otherwise.
	*/
	event void decryptDone (uint8_t* decryptedMsg, uint16_t len, error_t error);
}

