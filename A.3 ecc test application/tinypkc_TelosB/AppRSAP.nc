#include "RsaTK.h"
#include "integer.h"

#ifdef DO_PRINTF
	#include "printf.h"
#endif

#define 	DELAY_INITIAL	5000
#define		DELAY_RETRY	2000


#define BUFFLEN 500
//#define DO_INT_TEST
module AppRSAP{
	uses interface Boot;
	uses interface Timer<TMilli> as ConnectionDelay;
	uses interface Timer<TMilli> as Count;
	uses interface Leds;
	uses interface LocalTime<TMilli>;
	
	uses interface Rsa;
	uses interface Signature;
	uses interface RsaPrivateKey;
	uses interface RsaPadding;
}

implementation{
	uint8_t					buff[BUFFLEN] = {0xff, 0xff, 0xff, 0xaa,0xaa,0xaa, 0xff, 0xff, 0xff, 0xaa,0xaa,0xaa, 0xff, 0xff, 0xff, 0xaa,0xaa,0xaa, 0xbb, 0xbb};
  bool first = TRUE;
  uint32_t timePub, timePriv;
#if defined(DO_INT_TEST) && defined(DO_PRINTF)
void mp_print(mp_int* x, const char* str){
  unsigned char strbuff[1000];
  unsigned int i;
  

  memset (&strbuff, 0 , 1000);
  mp_to_unsigned_bin(x, strbuff);
  for(i=0; strbuff[i] != 0; i++){
  	printf("%02x:",strbuff[i] );
  }

  printf("%s", str);
}

void test_mp_read_radix(){
  mp_int t;
  mp_digit buffer [MP_PREC]; 


  printf("------test_mp_read------\n");
  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "12345678", 10);
  mp_print(&t, " == bc:61:4e?\n");
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "a1B69b4bacd05f15a1B69b4bacd05f15", 16);
  mp_print(&t, " == a1:B6:9b:4b:ac:d0:5f:15:a1:B6:9b:4b:ac:d0:5f:15?\n");
  printfflush();
}

void test_mp_cmp(){
  mp_int t, r;
  mp_digit buffer [MP_PREC]; 
  mp_digit buffer2 [MP_PREC];


  printf("------test_cmp_d------\n");
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "693", 10);
  printf(" 693 == 693 ? %d\n",mp_cmp_d(&t, 693));
  printfflush();

  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "693", 10);
  printf(" 693 == 694 ? %d\n",mp_cmp_d(&t, 694));
  printfflush();
  
  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "-12", 10);
  printf(" -12 == -12 ? %d\n",mp_cmp_d(&t, -12));
  printfflush();
  
  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "-12", 10);
  printf(" -12 == -1024 ? %d\n",mp_cmp_d(&t, -1024));
  printfflush();
  
  mp_init(&t, buffer, MP_PREC);
  mp_read_radix(&t, "123456789123456789123456789", 10);
  printf(" 123456789123456789123456789 == 5 ? %d\n",mp_cmp_d(&t, 5));
  printfflush();
  
  printf("------test_cmp------\n");
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_init(&r, buffer2, MP_PREC);
  mp_read_radix(&t, "693", 10);
  mp_read_radix(&r, "693", 10);
  printf(" 693 == 693 ? %d\n",mp_cmp(&t, &r));
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_init(&r, buffer2, MP_PREC);
  mp_read_radix(&t, "693", 10);
  mp_read_radix(&r, "694", 10);
  printf(" 693 == 694 ? %d\n",mp_cmp(&t, &r));
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_init(&r, buffer2, MP_PREC);
  mp_read_radix(&t, "-12", 10);
  mp_read_radix(&r, "-12", 10);
  printf(" -12 == -12 ? %d\n",mp_cmp(&t, &r));
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_init(&r, buffer2, MP_PREC);
  mp_read_radix(&t, "-12", 10);
  mp_read_radix(&r, "-1024", 10);
  printf(" -12 == -1024 ? %d\n",mp_cmp(&t, &r));
  printfflush();
  mp_init(&t, buffer, MP_PREC);
  mp_init(&r, buffer2, MP_PREC);
  mp_read_radix(&t, "123456789123456789123456789", 10);
  mp_read_radix(&r, "123456789123456789123456789", 10);
  printf(" 123456789123456789123456789 == 123456789123456789123456789 ? %d\n",mp_cmp(&t, &r));
  printfflush();
}

void test_mp_exp_mod(){
  mp_int A, E, N, RR, Z, X;
  mp_digit bufferA [MP_PREC]; 
  mp_digit bufferE [MP_PREC];
  mp_digit bufferN [MP_PREC]; 
  mp_digit bufferRR [MP_PREC]; 
  mp_digit bufferX [MP_PREC]; 
  mp_digit bufferZ [MP_PREC];  


  printf("------test_exptmod------\n");
  printfflush();
  mp_init(&A, bufferA, MP_PREC);
  mp_init(&E, bufferE, MP_PREC);
  mp_init(&N, bufferN, MP_PREC);
  mp_init(&RR, bufferRR, MP_PREC);
  mp_init(&X, bufferX, MP_PREC);
  mp_init(&Z, bufferZ, MP_PREC);

  mp_read_radix(&A, "23", 10);
  mp_read_radix(&E, "13", 10);
  mp_read_radix(&N, "29", 10);
  mp_read_radix(&X, "24", 10);
  
  printf ("errcode %d: ", mp_exptmod(&A, &E, &N, &Z));
  printfflush();
  printf(" 23^13 mod 29 --- "); mp_print(&X," == "); mp_print(&Z, "?\n");
  printfflush();
  mp_init(&A, bufferA, MP_PREC);
  mp_init(&E, bufferE, MP_PREC);
  mp_init(&N, bufferN, MP_PREC);
  mp_init(&RR, bufferRR, MP_PREC);
  mp_init(&X, bufferX, MP_PREC);
  mp_init(&Z, bufferZ, MP_PREC);

  mp_read_radix(&A, "23", 10);
  mp_read_radix(&E, "13", 10);
  mp_read_radix(&N, "23", 10);
  mp_read_radix(&X, "0", 10);
  
  printf ("errcode %d: ", mp_exptmod(&A, &E, &N, &Z));
  printfflush();
  printf(" 23^13 mod 30 --- "); mp_print(&X," == "); mp_print(&Z, "?\n");
  printfflush();
  mp_init(&A, bufferA, MP_PREC);
  mp_init(&E, bufferE, MP_PREC);
  mp_init(&N, bufferN, MP_PREC);
  mp_init(&RR, bufferRR, MP_PREC);
  mp_init(&X, bufferX, MP_PREC);
  mp_init(&Z, bufferZ, MP_PREC);

  mp_read_radix(&A, "23", 10);
  mp_read_radix(&E, "13", 10);
  mp_read_radix(&N, "-29", 10);
  mp_read_radix(&X, "24", 10);
  
  printf ("errcode %d: ", mp_exptmod(&A, &E, &N, &Z));
  printfflush();
  printf(" 23^13 mod -29 --- "); mp_print(&X," == "); mp_print(&Z, "?\n");
  printfflush();
  mp_init(&A, bufferA, MP_PREC);
  mp_init(&E, bufferE, MP_PREC);
  mp_init(&N, bufferN, MP_PREC);
  mp_init(&RR, bufferRR, MP_PREC);
  mp_init(&X, bufferX, MP_PREC);
  mp_init(&Z, bufferZ, MP_PREC);

  mp_read_radix(&A, "433019240910377478217373572959560109819648647016096560523769010881172869083338285573756574557395862965095016483867813043663981946477698466501451832407592327356331263124555137732393938242285782144928753919588632679050799198937132922145084847", 10);
  mp_read_radix(&E, "5781538327977828897150909166778407659250458379645823062042492461576758526757490910073628008613977550546382774775570888130029763571528699574717583228939535960234464230882573615930384979100379102915657483866755371559811718767760594919456971354184113721", 10);
  mp_read_radix(&N, "583137007797276923956891216216022144052044091311388601652961409557516421612874571554415606746479105795833145583959622117418531166391184939066520869800857530421873250114773204354963864729386957427276448683092491947566992077136553066273207777134303397724679138833126700957", 10);
  mp_read_radix(&X, "114597449276684355144920670007147953232659436380163461553186940113929777196018164149703566472936578890991049344459204199888254907113495794730452699842273939581048142004834330369483813876618772578869083248061616444392091693787039636316845512292127097865026290173004860736", 10);
  
  printf ("errcode %d: ", mp_exptmod(&A, &E, &N, &Z));
  printfflush();
  printf(" large mod large --- "); mp_print(&X," == "); mp_print(&Z, "?\n");
  
  
}
#endif 
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
		//call Leds.led1Off();
		//call Leds.led2On();
		//call Leds.led0On();
		
		call ConnectionDelay.startOneShot(DELAY_INITIAL);
	}

	event void ConnectionDelay.fired(){
		//call RadioControl.start();
		//call Leds.led1Off();
		//call Leds.led2Off();
		//call Leds.led0On();
		
		#ifdef DO_PRINTF
		//call Leds.led2On();
		printf("lalala\n");
		printfflush();
		#endif
		#ifdef DO_PRINTF
		//call Leds.led1On();
		//printf("sizeof(mp_word) = %lu\nsizeof(mp_digit) = %lu\nMP_PREC = %lu\nDIGIT_BIT  = %u\nEXP_LEN = %d\n",sizeof(mp_word), sizeof(mp_digit), MP_PREC, DIGIT_BIT,EXP_LEN);
		//printfflush();
		#endif
		#if defined(DO_INT_TEST) && defined(DO_PRINTF)
		test_mp_read_radix();
		//call Leds.led0Toggle();
	    test_mp_cmp();
   		//call Leds.led0Toggle();
	    test_mp_exp_mod();
		//call Leds.led0Toggle();
		#endif

		
		/*//test padding for non-signature
		call RsaPadding.rsaPad(buff, 20, buff, BUFFLEN, FALSE);
		call Leds.led0Toggle();
		*/
		
		//test public key stuff
		//call Leds.led1Toggle();
		if (SUCCESS != call Rsa.setPublicKey(MY_RSA_PUBLIC, RSA_MAX_MSG_LEN)){
			#ifdef DO_PRINTF
			printf(" setting key failed, probably need more memory for the RSA public Key!");
			printfflush();
			#endif
		}
		#ifdef DO_PRINTF
			printf(" setting key should work!");
			printfflush();
			#endif
	}

	event void Count.fired(){
	uint8_t hash[SHA1_HASH_LEN] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x0A, 0x6C};
		if(first){
			first = FALSE;
		} else {
			return;
		}
#ifdef RSA_LOW_MEM		
		//proceed setting Private Key to uncrypt.... !!!
		if(SUCCESS == call RsaPrivateKey.setPrivateKey(MY_RSA_PRIVATE, MY_RSA_PUBLIC, RSA_MAX_MSG_LEN)){
			#ifdef DO_PRINTF
			printf("SUCCESS setting private key!\n");
			printfflush();
			#endif
			//call Leds.led0On();
			timePriv = call LocalTime.get();
			
			if (SUCCESS == call Signature.sign(hash, SHA1_HASH_LEN)){
				#ifdef DO_PRINTF
				printf("SUCCESS calling RSA sign operation\n");
				printfflush();
				#endif
			}
		}else{
		#ifdef DO_PRINTF
			printf("FAILED setting private key!\n");
			printfflush();
		#endif
		}
#else 
		//proceed setting Private Key to uncrypt.... !!!
		if(SUCCESS == call RsaPrivateKey.setPrivateKey (MY_RSA_EXPO1, RSA_MAX_MSG_LEN / 2, 
								   MY_RSA_EXPO2, RSA_MAX_MSG_LEN / 2, 
								   MY_RSA_PRIME1, RSA_MAX_MSG_LEN / 2, 
								   MY_RSA_PRIME2, RSA_MAX_MSG_LEN / 2, 
								   MY_RSA_COEFFICIENT, RSA_MAX_MSG_LEN / 2)){
			#ifdef DO_PRINTF
			printf("SUCCESS setting private key!\n");
			printfflush();
			#endif
			//call Leds.led0On();
			timePriv = call LocalTime.get();
			if (SUCCESS == call Signature.sign(hash, SHA1_HASH_LEN)){
				#ifdef DO_PRINTF
				printf("SUCCESS calling RSA sign operation\n");
				printfflush();
				#endif
			}
		}else{
		#ifdef DO_PRINTF
			printf("FAILED setting private key!\n");
			printfflush();
		#endif
		}
#endif
	}

	
	event void Rsa.setPublicKeyDone (error_t error){
		uint8_t cert[RSA_MAX_MSG_LEN] = {0x65, 0x91, 0xf3, 0xc9, 0x6a, 0x2f, 0x6e, 0x4d, 0x37, 0x62, 0xa3, 0x90, 0x8a, 0x5e, 0x44, 0x46, 0x46, 0x25, 0x35, 0xa1, 0xfd, 0xc7, 0x8a, 0xaf, 0x21, 0xda, 0x82, 0x12, 0x57, 0xe8, 0xfd, 0x9f, 0x86, 0x5e, 0xda, 0xd3, 0x9b, 0x08, 0x4e, 0xa6, 0x9c, 0x0f, 0x65, 0x98, 0x5f, 0xd1, 0x8a, 0x0b, 0x8a, 0xff, 0xad, 0x69, 0xb0, 0x20, 0x04, 0x66, 0x2c, 0x76, 0xb4, 0xd9, 0x33, 0x55, 0x0b, 0x61, 0x0b, 0x3c, 0x08, 0xcc, 0x22, 0x58, 0xae, 0x2e, 0x2d, 0x99, 0xf7, 0x8b, 0xb4, 0x90, 0x3d, 0x63, 0x27, 0xad, 0x3e, 0x16, 0xbd, 0xab, 0xb9, 0xe1, 0xd8, 0x90, 0x94, 0x83, 0x25, 0xc1, 0xab, 0x3d, 0x6c, 0x4d, 0xba, 0x93, 0xaa, 0x56, 0x2c, 0x79, 0x80, 0xa4, 0xf1, 0xdf, 0x82, 0x4d, 0xa6, 0x9b, 0x12, 0x20, 0xad, 0x57, 0xc4, 0xe8, 0x4a, 0x97, 0xe0, 0xd7, 0xff, 0x57, 0xc7, 0xd3, 0x00, 0xdb, 0x5a, 0x00, 0xe3, 0xf6, 0x08, 0x6a, 0xb7, 0x57, 0xf2, 0x27, 0xb0, 0x11, 0xaa, 0xc2, 0xed, 0x2f, 0x71, 0x8f, 0x93, 0x96, 0x8c, 0xff, 0xed, 0x9f, 0xf1, 0x29, 0x3c, 0xd9, 0xea, 0x47, 0xd5, 0xee, 0x87, 0xf0, 0xc9, 0x0f, 0x39, 0x4c, 0x77, 0x98, 0xd3, 0x6d, 0x57, 0xd4, 0xfa, 0xd9, 0xb0, 0x9a, 0x5c, 0xdc, 0x42, 0x1c, 0x61, 0x18, 0x20, 0xf5, 0x25, 0x09, 0xfd, 0x90, 0x23, 0xd2, 0x32, 0x51, 0x91, 0x1d, 0xb4, 0x01, 0x62, 0x2a, 0x1f, 0xcd, 0x5d, 0xd5, 0x52, 0x59, 0x27, 0xf6, 0x84, 0x19, 0xe9, 0x67, 0xeb, 0xde, 0xb8, 0xe8, 0x67, 0x47, 0xa4, 0x16, 0x27, 0x63, 0x9c, 0xca, 0x0a, 0x62, 0xf1, 0x79, 0x0b, 0x77, 0x09, 0xa6, 0x43, 0x6b, 0xa1, 0x46, 0xb3, 0xc6, 0x19, 0x6b, 0xfa, 0x21, 0xb8, 0x39, 0xb0, 0x22, 0xe0, 0x53, 0x96, 0x67, 0x91, 0xa7, 0x2a, 0x22, 0x07, 0xe3, 0x2f, 0x6c};
		uint8_t hash[SHA1_HASH_LEN] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x0A, 0x6C};
		#ifdef DO_PRINTF
		printf("Public Key set: ");
		if(error == SUCCESS){
			printf("SUCCESS\n");
			printfflush();
		}else
			printf("FAIL\n");
		printfflush();
		#endif
		//call Leds.led0Toggle();
		if(error == SUCCESS){
			memcpy(buff, cert, RSA_MAX_MSG_LEN);
			//call Leds.led1On();
			timePub = call LocalTime.get();
			call Signature.verify(hash, SHA1_HASH_LEN, buff, RSA_MAX_MSG_LEN);
		}
	}
	
	event void Rsa.getPublicKeyDone (uint8_t* publicKey, uint16_t len, error_t error){
		
	}
	
	event void Rsa.encryptDone (uint8_t* encryptedMsg, uint16_t len, error_t error){
		//call Leds.led2Off();
		#ifdef DO_PRINTF
		//printf("Public Key encryption: ");
		if(error == SUCCESS){
			//printf("SUCCESS, len %d\n",len);
			//printfflush();
			//printArray(encryptedMsg, len);
			//copy that shit in the buffer
			memcpy(buff, encryptedMsg, len);
			call Count.startOneShot(1024);
		}else
			printf("FAIL\n");
		printfflush();
		#endif
		
		if(error == SUCCESS){
			
		}
	}
	
	event void Rsa.decryptDone (uint8_t* decryptedMsg, uint16_t len, error_t error){	
		//call Leds.led1Off();
		
		#ifdef DO_PRINTF
		printf("Private Key decryption: ");
		if(error == SUCCESS){
			//printf("SUCCESS, len %d\n",len);
			//printfflush();
			//printArray(decryptedMsg, len);
		}else
			printf("FAIL\n");
		printfflush();
		#endif
	}
	
	event void Signature.setPublicKeyDone (error_t error){	
	}
	
	event void Signature.getPublicKeyDone (uint8_t* publicKey, uint16_t len, error_t error){
	}
	
	event void Signature.signDone (uint8_t* signature, uint16_t len, error_t error){
	uint8_t hash[SHA1_HASH_LEN] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x0A, 0x6C};
	uint32_t now = call LocalTime.get();
	//call Leds.led0Off();
	#ifdef DO_PRINTF
		printf("Signature done: in %d ms(binary)", now - timePriv);
		printf(" integer max size %d ", get_max_size());
		if(error == SUCCESS){
			//printf("SUCCESS, len %d\n",len);
			//printfflush();
			//printArray(signature, len);
		}else
			printf("FAIL\n");
		printfflush();
	#endif
		timePub = call LocalTime.get();	
		
		
		#ifdef DO_PRINTF
		printf("max stack %x, min stack %x, difference %lu\n",get_max_stack(), get_min_stack(), get_max_stack() - get_min_stack()); 
		printfflush();
		#endif
		call Signature.verify(hash, SHA1_HASH_LEN, signature, len);
	}	
	
	event void Signature.verifyDone (error_t error){
		uint32_t now = call LocalTime.get();
		//call Leds.led1Off();
		#ifdef DO_PRINTF
		printf("signature done in %d ms(binary), error %d\n",now - timePub, error); 
		printfflush();
		#endif
		call Count.startOneShot(1024);
	}	
	
	event void RsaPadding.padDone (uint8_t* msg, uint16_t len, error_t error){
		/*#ifdef DO_PRINTF
		printf("pad done: ");
		if(error == SUCCESS)
			printf("msg has length %d, error code SUCCESS\n", len);
		else
			printf("msg has length %d, error code FAIL\n", len);
		printfflush();
		printArray(msg, len);
		#endif
		
		if(error == SUCCESS){
			call RsaPadding.rsaUnPad(msg, len, buff, BUFFLEN, FALSE);
		}*/
	}
	
	event void RsaPadding.unPadDone (uint8_t* msg, uint16_t len, error_t error){
		/*#ifdef DO_PRINTF
		printf("Unpad done: ");
		if(error == SUCCESS)
			printf("msg has length %d, error code SUCCESS\n", len);
		else
			printf("msg has length %d, error code FAIL\n", len);
		printfflush();
		printArray(msg, len);
		#endif*/
		
	}
	
}
