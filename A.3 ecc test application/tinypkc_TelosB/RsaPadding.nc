
/**
 * Perform padding with PKCS#1 v1.5 encoding.
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	26/7/2012
*/

interface RsaPadding
{
	/**
	 * Pad a Message with PKCS#1 v1.5 encoding. Input and output can be the same buffer
	 *
	 * @param input		Pointer to the input
	 * @param len		Length of the input.
	 * @param output	Pointer to where the output should be written.
	 * @param maxlen	maximum length of the output
	 * @param signature	TRUE if padding should be done for a signature, FALSE for normal encryption
	 * @return			SUCCESS if the padding can be written to the output.
	*/
	command error_t rsaPad (uint8_t* input, uint16_t len, uint8_t* output, uint16_t maxlen, bool signature);

	/**
	 * Unpad a Message with PKCS#1 v1.5 encoding. Input and output can be the same buffer
	 *
	 * @param input		Pointer to the input containing the padded message
	 * @param len		Length of the input.
	 * @param output	Pointer to where the output should be written.
	 * @param maxlen	maximum length of the output
	 * @param signature	TRUE if unpadding should be done for a signature, FALSE for normal encryption
	 * @return			SUCCESS if the depadded message can be written to the output.
	*/
	command error_t rsaUnPad (uint8_t* input, uint16_t len, uint8_t* output, uint16_t maxlen, bool signature);


	/**
	 * Notification that the padding has been performed and written to the specified buffer.
	 *
	 * @param msg			A pointer to the padded message.
	 * @param len			Length of the padded message
	 * @param error			SUCCESS if the operation completed successfully,
	 *						FAIL otherwise.
	*/
	event void padDone (uint8_t* msg, uint16_t len, error_t error);
	
	/**
	 * Notification that the depadding has been performed and written to the specified buffer.
	 *
	 * @param msg			A pointer to the depadded message.
	 * @param len			Length of the depadded message
	 * @param error			SUCCESS if the operation completed successfully,
	 *						FAIL otherwise.
	*/
	event void unPadDone (uint8_t* msg, uint16_t len, error_t error);
}

