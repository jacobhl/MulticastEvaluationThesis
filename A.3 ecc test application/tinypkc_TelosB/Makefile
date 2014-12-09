include $(MAKERULES)

#COMPONENT=./AppRSAC
COMPONENT=./AppECCC


PFLAGS += ./integer.c

CFLAGS += -I$(TOSROOT)/tos/lib/printf


#CFLAGS += -DMP_PREC=128 	# For RSA
CFLAGS += -DMP_PREC=40		# For ECC
CFLAGS += -DRSA_TEST_VALUES # a hardcoded RSA Public / private key pair for testing
CFLAGS += -DECC_TEST_VALUES # hardcoded ECC values for testing
CFLAGS += -DHAVE_ECC 		# for the read radix function
#CFLAGS += -DRSA_LOW_MEM
