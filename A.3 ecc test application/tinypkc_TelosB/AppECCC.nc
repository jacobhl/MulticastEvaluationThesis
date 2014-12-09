configuration AppECCC{
}
implementation{
	components AppECCP as App;
	components MainC as Boot;
	components new TimerMilliC() as Timer1;
	components new TimerMilliC() as Timer2;
	components LedsC;
	
	
	#ifdef DO_PRINTF	
		components PrintfC;
 		components SerialStartC;
	#endif
	
	App.Boot -> Boot;
	App.ConnectionDelay -> Timer1;
	App.Count-> Timer2;
	App.Leds -> LedsC;
	
	components LocalTimeMilliC;
	App.LocalTime -> LocalTimeMilliC;

	components EccC;
	App.ECC -> EccC;
	
}
