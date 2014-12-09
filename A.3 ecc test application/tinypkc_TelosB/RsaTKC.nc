/**
 * Configuration for the software-based RSA operations.
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	26/7/2012
*/

configuration RsaTKC
{
	provides interface Rsa;
	provides interface RsaPrivateKey;
	provides interface Signature;
}
implementation
{
	components RsaTKP;

	Rsa = RsaTKP;
	RsaPrivateKey = RsaTKP;
	Signature = RsaTKP;
	
	components RsaPaddingC;
	
	RsaTKP.RsaPadding -> RsaPaddingC;
}

