#include "ecc.h"
#include "integer.h"

#ifdef DO_PRINTF
	#include "printf.h"
#endif

#define 	DELAY_INITIAL	5000
#define		DELAY_RETRY	2000


#define BUFFLEN 500
//#define DO_INT_TEST
module AppECCP{
	uses interface Boot;
	uses interface Timer<TMilli> as ConnectionDelay;
	uses interface Timer<TMilli> as Count;
	uses interface Leds;
	uses interface LocalTime<TMilli>;
	
	uses interface ECC;
}

implementation{
	mp_digit	key_buff[4* MP_PREC];
	ecc_key		my_key;
	mp_digit	key_buff2[4* MP_PREC];
	ecc_key		other_key;
	
	uint8_t		buff[192];
	uint16_t	outputLen = 192;
	uint8_t 	hash[20] = {0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd};
	
	void printArray(uint8_t* start, uint16_t len){
		#ifdef DO_PRINTF
		uint16_t i = 0;
		printf("Dumping Array:\n");
		for(i = 0; i < len; i++){
			printf("%02X:", start[i]);
		}
		printf("\nDone.\n");
		printfflush();
		#endif
	}

	event void Boot.booted(){
		call Leds.led1Off();
		call Leds.led2On();
		call Leds.led0On();
		
		call ConnectionDelay.startOneShot(DELAY_INITIAL);
	}

	event void ConnectionDelay.fired(){
		uint32_t oldtime, newtime;
		int stat = 0;
		error_t err;
		//call RadioControl.start();
		call Leds.led1Off();
		call Leds.led2Off();
		call Leds.led0Off();
		
		#ifdef DO_PRINTF
		printf("lalala\n");
		printfflush();
		#endif
		
		#ifdef DO_PRINTF
		printf("Reading ECC Private Key...");
		printfflush();
		#endif
		oldtime = call LocalTime.get();
		err = call ECC.init_key(key_buff, 4 * MP_PREC, &my_key);
		
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed initializing.\n");
			printfflush();
			#endif
			return;
		}
		
		err = call ECC.import_private_key(MY_ECC_PRIVATE, MY_ECC_PRIVATE_LEN, MY_ECC_PUBLIC, MY_ECC_PUBLIC_LEN, &my_key);
		
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed private import.\n");
			printfflush();
			#endif
			return;
		}
		
		newtime = call LocalTime.get();
		#ifdef DO_PRINTF
		printf("success %d ms.\n", newtime - oldtime);
		printfflush();
		#endif
		call Leds.led0On();
		
		#ifdef DO_PRINTF
		printf("Reading ECC Public Key...");
		printfflush();
		#endif
		oldtime = call LocalTime.get();
		err = call ECC.init_key(key_buff2, 4 * MP_PREC, &other_key);
		
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed initializing.\n");
			printfflush();
			#endif
			return;
		}
		
		err = call ECC.import_x963(OTHER_ECC_PUBLIC, OTHER_ECC_PUBLIC_LEN, &other_key);
		
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed public import.\n");
			printfflush();
			#endif
			return;
		}

		newtime = call LocalTime.get();
		
		#ifdef DO_PRINTF
		printf("success %d ms.\n", newtime - oldtime);
		printfflush();
		#endif
		call Leds.led1On();	
		
		//*
		#ifdef DO_PRINTF
		printf("EC-DH key agreement...");
		printfflush();
		#endif
		
		oldtime = call LocalTime.get();
		err = call ECC.shared_secret(&my_key, &other_key, buff, &outputLen);
		newtime = call LocalTime.get();
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed.\n");
			printfflush();
			#endif
			return;
		}
		
		#ifdef DO_PRINTF
		printf("success, length %d, %d ms.\n", outputLen, newtime - oldtime);
		printfflush();
		printArray(buff, outputLen);
		#ifdef ECC160
		printf("Expected: \n");
		printArray(ECDH_OUTPUT, 20);
		#endif
		#endif
		
		call Leds.led2On();
		/**/
		
		
		//*
		#ifdef DO_PRINTF
		printf("ECDSA sign...");
		printfflush();
		#endif
		
		outputLen = 192;
		oldtime = call LocalTime.get();
		err = call ECC.sign_hash(hash, 20, buff, &outputLen, &my_key);
		newtime = call LocalTime.get();
		
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed.\n");
			printfflush();
			#endif
			return;
		}
		
		#ifdef DO_PRINTF
		printf("success, length %d, %d ms.\n", outputLen, newtime - oldtime);
		printfflush();
		printArray(buff, outputLen);
		#endif
		
		call Leds.led0Off();
		/**/
		
		//*
		#ifdef DO_PRINTF
		printf("ECDSA verify...");
		printfflush();
		#endif
		
		oldtime = call LocalTime.get();
		err = call ECC.verify(buff, outputLen, hash, 20, &stat, &my_key);
		newtime = call LocalTime.get();
		
		if(err != SUCCESS){
			#ifdef DO_PRINTF
			printf("failed.\n");
			printfflush();
			#endif
			return;
		}
		
		#ifdef DO_PRINTF
		printf("success, stat %d, time %d ms.\n", stat, newtime - oldtime);
		printfflush();
		#endif
		
		call Leds.led1Off();
		/**/
	}

	event void Count.fired(){
	
	}
	
}
