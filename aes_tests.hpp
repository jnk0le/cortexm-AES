#ifndef AES_TESTS_HPP
#define AES_TESTS_HPP

#include <string.h>
#include <stdint.h>

uint8_t key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t key_192[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
uint8_t key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

uint8_t expected_plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};


uint8_t expected_ciphertext_128[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
uint8_t expected_ciphertext_192[16] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};
uint8_t expected_ciphertext_256[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};


uint8_t tmp[16];

aes::CipherContext<128, aes::target::CM7_1T> t128;
aes::CipherContext<192, aes::target::CM7_1T> t192;
aes::CipherContext<256, aes::target::CM7_1T> t256;

//just a dirty function in a header

//__attribute__ ((section(".itcm.text")))
void aes_ecb_test()
{
	uint32_t tick, tock;
	uint32_t cycles[5];

	printf("func --- run1/run2/run3/run4/run5 --- (enc/dec matching expected results)\n");

	printf("\n----------------aes_128------------------\n\n");

	printf("setEncKey --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t128.setEncKey(key_128);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/\n", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	printf("encrypt --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t128.encrypt(expected_plaintext, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	if(memcmp(expected_ciphertext_128, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("setDecKey --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t128.setDecKey(); // reuse context
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/\n", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	printf("decrypt --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t128.decrypt(expected_ciphertext_128, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	if(memcmp(expected_plaintext, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("\n----------------aes_192------------------\n\n");

	printf("setEncKey --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t192.setEncKey(key_192);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/\n", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	printf("encrypt --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t192.encrypt(expected_plaintext, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

    if(memcmp(expected_ciphertext_192, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("setDecKey --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t192.setDecKey(); // reuse context
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/\n", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	printf("decrypt --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t192.decrypt(expected_ciphertext_192, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	if(memcmp(expected_plaintext, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("\n----------------aes_256------------------\n\n");

	printf("setEncKey --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t256.setEncKey(key_256);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/\n", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	printf("encrypt --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t256.encrypt(expected_plaintext, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

    if(memcmp(expected_ciphertext_256, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("setDecKey --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t256.setDecKey(); // reuse context
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/\n", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	printf("decrypt --- ");
	for(int i = 0; i<5; i++)
	{
		tick = DWT->CYCCNT;
		t256.decrypt(expected_ciphertext_256, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles[i] = tock;
	}
	printf("%lu/%lu/%lu/%lu/%lu/", cycles[0],cycles[1],cycles[2],cycles[3],cycles[4]);

	if(memcmp(expected_plaintext, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }
}

#endif
