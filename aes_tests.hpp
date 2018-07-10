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

//__attribute__ ((section(".itcm.text"), noinline))
void aes_ecb_test()
{
	uint32_t tick, tock;
	uint32_t cycles_sum = 0;

	printf("func --- averaged run (without first run) --- (enc/dec matching expected results)\n");

	printf("\n----------------aes_128------------------\n\n");

	printf("setEncKey --- ");
	t128.setEncKey(key_128); // cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t128.setEncKey(key_128);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f\n", (double)cycles_sum/1024.0f);
	cycles_sum = 0;

	printf("encrypt --- ");
	t128.encrypt(expected_plaintext, tmp); // cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t128.encrypt(expected_plaintext, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f", (double)cycles_sum/1024.0f);

	if(memcmp(expected_ciphertext_128, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	cycles_sum = 0;

	printf("setDecKey --- ");
	t128.setDecKey(); //cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t128.setDecKey();
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f\n", (double)cycles_sum/1024.0f);

	cycles_sum = 0;

	t128.setDecKey(key_128); // no idea how it worked with an 5x context reuse

	printf("decrypt --- ");
	t128.decrypt(expected_ciphertext_128, tmp); //cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t128.decrypt(expected_ciphertext_128, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f", (double)cycles_sum/1024.0f);

	if(memcmp(expected_plaintext, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("\n----------------aes_192------------------\n\n");

	cycles_sum = 0;

	printf("setEncKey --- ");
	t192.setEncKey(key_192); // cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t192.setEncKey(key_192);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f\n", (double)cycles_sum/1024.0f);
	cycles_sum = 0;

	printf("encrypt --- ");
	t192.encrypt(expected_plaintext, tmp); // cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t192.encrypt(expected_plaintext, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f", (double)cycles_sum/1024.0f);

	if(memcmp(expected_ciphertext_192, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	cycles_sum = 0;

	printf("setDecKey --- ");
	t192.setDecKey(); //cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t192.setDecKey();
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f\n", (double)cycles_sum/1024.0f);

	t192.setDecKey(key_192); // no idea how it worked with an 5x context reuse

	cycles_sum = 0;

	printf("decrypt --- ");
	t192.decrypt(expected_ciphertext_192, tmp); //cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t192.decrypt(expected_ciphertext_192, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f", (double)cycles_sum/1024.0f);

	if(memcmp(expected_plaintext, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	printf("\n----------------aes_256------------------\n\n");

	cycles_sum = 0;

	printf("setEncKey --- ");
	t256.setEncKey(key_256); // cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t256.setEncKey(key_256);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f\n", (double)cycles_sum/1024.0f);
	cycles_sum = 0;

	cycles_sum = 0;

	printf("encrypt --- ");
	t256.encrypt(expected_plaintext, tmp); // cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t256.encrypt(expected_plaintext, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f", (double)cycles_sum/1024.0f);

	if(memcmp(expected_ciphertext_256, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }

	cycles_sum = 0;

	printf("setDecKey --- ");
	t256.setDecKey(); //cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t256.setDecKey();
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f\n", (double)cycles_sum/1024.0f);

	t256.setDecKey(key_256); // no idea how it worked with an 5x context reuse

	cycles_sum = 0;

	printf("decrypt --- ");
	t256.decrypt(expected_ciphertext_256, tmp); //cache train run
	for(int i = 0; i<1024; i++)
	{
		tick = DWT->CYCCNT;
		t256.decrypt(expected_ciphertext_256, tmp);
		tock = DWT->CYCCNT - tick - 1;

		cycles_sum += tock;
	}
	printf("%f", (double)cycles_sum/1024.0f);

	if(memcmp(expected_plaintext, tmp, 16) != 0)
    	printf(" --- incorrect\n");
    else
    {
    	printf(" --- ok\n");
    }
}

uint8_t cbc_iv[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

uint8_t cbc_expected_plaintext[64] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

uint8_t cbc_expected_ciphertext[64] = {
		0x36, 0x74, 0x69, 0x6D, 0x1A, 0x47, 0x1A, 0x53, 0xAF, 0xEB, 0x8F, 0xD2, 0x17, 0xB6, 0x75, 0xD4,
		0xB4, 0xE9, 0x96, 0xB6, 0x43, 0xF9, 0x90, 0x2E, 0xC5, 0xBD, 0x8C, 0xC0, 0x68, 0x9E, 0x29, 0x2A,
		0x7C, 0x35, 0xD2, 0x7F, 0x86, 0xB7, 0x42, 0xF2, 0x69, 0x00, 0xA5, 0x0B, 0x08, 0xE6, 0x3C, 0x4E,
		0x2D, 0xF1, 0x46, 0x1E, 0x41, 0x1C, 0x15, 0x19, 0xF2, 0x23, 0x78, 0x24, 0x23, 0x52, 0xEB, 0x43
};

uint8_t cbc_tmp[64];

aes::mode::CBC<256, aes::target::CM7_1T, aes::mode::target::CBC_GENERIC> tcbc;

void aes_cbc_test()
{
	tcbc.setEncKey(key_256);
	tcbc.setIv(cbc_iv);

	tcbc.encrypt(cbc_expected_plaintext, cbc_tmp, 32);
	tcbc.encrypt(cbc_expected_plaintext+32, cbc_tmp+32, 32);

	if(memcmp(cbc_expected_ciphertext, cbc_tmp, 64) != 0)
		printf("cbc enc incorrect\n");
	else
	{
		printf("cbc enc ok\n");
	}

	tcbc.setDecKey(key_256);
	tcbc.setIv(cbc_iv);

	tcbc.decrypt(cbc_expected_ciphertext, cbc_tmp, 32);
	tcbc.decrypt(cbc_expected_ciphertext+32, cbc_tmp+32, 32);

	if(memcmp(cbc_expected_plaintext, cbc_tmp, 64) != 0)
		printf("cbc dec incorrect\n");
	else
	{
		printf("cbc dec ok\n");
	}
}

#endif
