/**
 * Configuration for the software-based RSA operations.
 *
 * @author	Thomas Kothmayr <kothmayr@in.tum.de>
 * @date	26/7/2012
*/

configuration EccC
{
	provides interface ECC;
	
}
implementation
{
	components EccP;
	ECC = EccP;
	
	components RandomMlcgC as Random;
	EccP.Random -> Random;
	EccP.SeedInit -> Random;
	
	components LocalTimeMicroC;
	EccP.MicroTime -> LocalTimeMicroC;
}

