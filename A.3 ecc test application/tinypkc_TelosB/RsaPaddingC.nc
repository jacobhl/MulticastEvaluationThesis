/**
 * Configuration for RSA PKCS#1 v1.5 padding.
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	26/7/2012
*/

configuration RsaPaddingC{
	provides interface RsaPadding;
} implementation {
	components RsaPaddingP;
	
	RsaPadding = RsaPaddingP;
	
	components RandomMlcgC as Random;
	RsaPaddingP.Random -> Random;
	RsaPaddingP.SeedInit -> Random;
	
	components LocalTimeMicroC;
	RsaPaddingP.MicroTime -> LocalTimeMicroC;
}
