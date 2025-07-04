//This api is unversioned
//will be replaced by proper implementation

#ifdef __arm__

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <cmsis_device.h>

#include "aes_deprecated_tests.hpp"

#include "../cipher.hpp"
#include "../modes.hpp"

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

aes::CipherContext<128, aes::target::CM3_1T> t128;
aes::CipherContext<192, aes::target::CM3_1T> t192;
aes::CipherContext<256, aes::target::CM3_1T> t256;

#if defined(__ARM_ARCH_7EM__)||defined(__ARM_ARCH_7M__)||defined(__ARM_ARCH_8M_MAIN__)||defined(__ARM_ARCH_8_1M_MAIN__)

//__attribute__ ((section(".itcm.text"), noinline))
void aes_ecb_test(void)
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
    else {
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

	t128.setDecKey(key_128);

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
    else {
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
    else {
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

	t192.setDecKey(key_192);

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
    else {
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
    else {
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

	t256.setDecKey(key_256);

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
    else {
    	printf(" --- ok\n");
    }
}

/*uint8_t cbc_iv[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

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

aes::mode::CBC<256, aes::target::CM3_1T_unrolled, aes::mode::target::CBC_GENERIC> tcbc;

void aes_cbc_test(void)
{
	tcbc.setEncKey(key_256);
	tcbc.setIv(cbc_iv);

	tcbc.encrypt(cbc_expected_plaintext, cbc_tmp, 32);
	tcbc.encrypt(cbc_expected_plaintext+32, cbc_tmp+32, 32);

	if(memcmp(cbc_expected_ciphertext, cbc_tmp, 64) != 0)
		printf("cbc enc incorrect\n");
	else {
		printf("cbc enc ok\n");
	}

	tcbc.setDecKey(key_256);
	tcbc.setIv(cbc_iv);

	tcbc.decrypt(cbc_expected_ciphertext, cbc_tmp, 32);
	tcbc.decrypt(cbc_expected_ciphertext+32, cbc_tmp+32, 32);

	if(memcmp(cbc_expected_plaintext, cbc_tmp, 64) != 0)
		printf("cbc dec incorrect\n");
	else {
		printf("cbc dec ok\n");
	}
}*/

uint8_t cbc_iv[16] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

uint8_t cbc_expected_plaintext[16] = {
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
};

uint8_t cbc_expected_ciphertext[32] = {
		0x35, 0xd1, 0x4e, 0x6d, 0x3e, 0x3a, 0x27, 0x9c, 0xf0, 0x1e, 0x34, 0x3e, 0x34, 0xe7, 0xde, 0xd3,
		0x62, 0xc8, 0xb7, 0x5b, 0x73, 0x6c, 0xcc, 0x4a, 0x58, 0x85, 0x32, 0x2a, 0xb9, 0x27, 0x31, 0x9e
};

uint8_t cbc_expected_plaintext2[5] = {
		0x11, 0x22, 0x33, 0x44, 0x55
};

uint8_t cbc_expected_ciphertext2[16] = {
		0xeb, 0x56, 0xe6, 0xf3, 0x58, 0x62, 0x66, 0xcd, 0x57, 0xb4, 0x3f, 0x02, 0x1f, 0xdf, 0xea, 0xa3
};

aes::mode::CBC_PKCS7<128, aes::target::CM85_1T, aes::mode::target::CBC_GENERIC> tcbc;
uint8_t cbc_tmp[64];

void aes_cbc_test(void)
{
	tcbc.setEncKey(key_128);
	tcbc.setIv(cbc_iv);

	int enc_len = tcbc.encryptAppendFinalize(cbc_expected_plaintext, cbc_tmp, 16);

	if(memcmp(cbc_expected_ciphertext, cbc_tmp, 32) != 0)
		printf("cbc enc incorrect\n");
	else {
		if(enc_len != 32)
			printf("cbc enc len incorrect: %d\n", enc_len);
		else
			printf("cbc enc ok\n");
	}

	tcbc.setDecKey(key_128);
	tcbc.setIv(cbc_iv);

	int dec_len = tcbc.decryptAppendFinalize(cbc_expected_ciphertext, cbc_tmp, 32);

	if(memcmp(cbc_expected_plaintext, cbc_tmp, 16) != 0)
		printf("cbc dec incorrect\n");
	else {
		if(dec_len != 16)
			printf("cbc dec len incorrect: %d\n", dec_len);
		else
			printf("cbc dec ok\n");
	}

	printf("cbc pad non power of 2\n");

	tcbc.setEncKey(key_128);
	tcbc.setIv(cbc_iv);

	enc_len = tcbc.encryptAppendFinalize(cbc_expected_plaintext2, cbc_tmp, 5);

	if(memcmp(cbc_expected_ciphertext2, cbc_tmp, 16) != 0)
		printf("cbc2 enc incorrect\n");
	else {
		if(enc_len != 16)
			printf("cbc2 enc len incorrect: %d\n", enc_len);
		else
			printf("cbc2 enc ok\n");
	}

	tcbc.setDecKey(key_128);
	tcbc.setIv(cbc_iv);

	dec_len = tcbc.decryptAppendFinalize(cbc_expected_ciphertext2, cbc_tmp, 16);

	if(memcmp(cbc_expected_plaintext2, cbc_tmp, 5) != 0)
		printf("cbc2 dec incorrect\n");
	else {
		if(dec_len != 5)
			printf("cbc2 dec len incorrect: %d\n", dec_len);
		else
			printf("cbc2 dec ok\n");
	}
}


uint8_t nist_256_key[32] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

uint8_t ctr_nonce[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

uint8_t ctr_expected_plaintext[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

uint8_t ctr_expected_ciphertext[64] = {
		0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
		0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
		0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
		0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
};

uint8_t ctr_tmp[64];

aes::mode::CTR32<256, aes::target::CM3_1T, aes::mode::target::CTR32_CM3_1T_unrolled> tctr;

void aes_ctr_nist_test(void)
{
	tctr.setEncKey(nist_256_key);
	tctr.setNonce(ctr_nonce, 16);

	tctr.encrypt(ctr_expected_plaintext, ctr_tmp, 32);
	tctr.encrypt(ctr_expected_plaintext+32, ctr_tmp+32, 32);

	if(memcmp(ctr_expected_ciphertext, ctr_tmp, 64) != 0)
		printf("ctr enc incorrect\n");
	else {
		printf("ctr enc ok\n");
	}

	//tctr.setEncKey(nist_256_key); // no need to change key
	tctr.setNonce(ctr_nonce, 16);

	tctr.decrypt(ctr_expected_ciphertext, ctr_tmp, 32);
	tctr.decrypt(ctr_expected_ciphertext+32, ctr_tmp+32, 32);

	if(memcmp(ctr_expected_plaintext, ctr_tmp, 64) != 0)
		printf("ctr dec incorrect\n");
	else {
		printf("ctr dec ok\n");
	}

}

uint8_t dummy_8k[8192]; // we don't care about content, just performance

/*aes::mode::CBC<128, aes::target::CM3_1T, aes::mode::target::CBC_GENERIC> tcbc128;
aes::mode::CBC<192, aes::target::CM3_1T, aes::mode::target::CBC_GENERIC> tcbc192;
aes::mode::CBC<256, aes::target::CM3_1T, aes::mode::target::CBC_GENERIC> tcbc256;

void aes_cbc_perf_test(void)
{
	uint32_t tick, tock;

	tcbc128.setEncKey(key_128);
	tcbc128.setIv(cbc_iv);

	tcbc128.encrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tcbc128.encrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("cbc enc 128: %f cycles per byte\n", (double)tock/8192.0);

	tcbc128.setDecKey();

	tcbc128.decrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tcbc128.decrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("cbc dec 128: %f cycles per byte\n", (double)tock/8192.0);

	tcbc192.setEncKey(key_192);
	tcbc192.setIv(cbc_iv);

	tcbc192.encrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tcbc192.encrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("cbc enc 192: %f cycles per byte\n", (double)tock/8192.0);

	tcbc192.setDecKey();

	tcbc192.decrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tcbc192.decrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("cbc dec 192: %f cycles per byte\n", (double)tock/8192.0);

	tcbc256.setEncKey(key_128);
	tcbc256.setIv(cbc_iv);

	tcbc256.encrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tcbc256.encrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("cbc enc 256: %f cycles per byte\n", (double)tock/8192.0);

	tcbc256.setDecKey();

	tcbc256.decrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tcbc256.decrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("cbc dec 256: %f cycles per byte\n", (double)tock/8192.0);

}*/

aes::mode::CTR32<128, aes::target::CM85_1T, aes::mode::target::CTR32_CM7_1T> tctr128;
aes::mode::CTR32<192, aes::target::CM85_1T, aes::mode::target::CTR32_CM7_1T> tctr192;
aes::mode::CTR32<256, aes::target::CM85_1T, aes::mode::target::CTR32_CM7_1T> tctr256;

void aes_ctr_perf_test(void)
{
	uint32_t tick, tock;

	tctr128.setEncKey(key_128);
	tctr128.setNonce(ctr_nonce, 12);

	tctr128.encrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tctr128.encrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("ctr 128 total: %d \n", tock);
	printf("ctr 128: %f cycles per byte\n", (double)tock/8192.0);

	tctr192.setEncKey(key_192);
	tctr192.setNonce(ctr_nonce, 12);

	tctr192.encrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tctr192.encrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("ctr 192 total: %d \n", tock);
	printf("ctr 192: %f cycles per byte\n", (double)tock/8192.0);

	tctr256.setEncKey(key_256);
	tctr256.setNonce(ctr_nonce, 12);

	tctr256.encrypt(dummy_8k, dummy_8k, 8192); // icache pre-run

	tick = DWT->CYCCNT;
	tctr256.encrypt(dummy_8k, dummy_8k, 8192);
	tock = DWT->CYCCNT - tick - 1;

	printf("ctr 256 total: %d \n", tock);
	printf("ctr 256: %f cycles per byte\n", (double)tock/8192.0);

}


// test case 4 from
//https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

uint8_t gcm_key[16] = {
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

uint8_t gcm_iv[12] = {
		0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};

uint8_t gcm_aad[20] = {
		0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
		0xab, 0xad, 0xda, 0xd2
};

uint8_t gcm_expected_plaintext[60] = {
		0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
		0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
		0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
		0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
};

uint8_t gcm_expected_ciphertext[60] = {
		0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
		0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
		0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
		0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
};

uint8_t gcm_expected_tag[16] = {
		0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

uint8_t gcm_tmp[64];
uint8_t gcm_tmp2[16];



aes::mode::GCM<128,
		aes::target::CM7_1T,
		aes::mode::target::CTR32_CM7_1T,
		aes::mode::target::gcm::GHASH_GENERIC_FULL_M8> tgcm128;




void aes_gcm_test(void)
{
	tgcm128.setEncKey(gcm_key);
	tgcm128.setIv(gcm_iv, 12);

	tgcm128.aadAppend(gcm_aad, sizeof(gcm_aad));

	tgcm128.encryptAppend(gcm_expected_plaintext, gcm_tmp, sizeof(gcm_expected_plaintext));

	tgcm128.finalizeTag(gcm_tmp2);

	if(memcmp(gcm_expected_ciphertext, gcm_tmp, sizeof(gcm_expected_ciphertext)) != 0)
		printf("gcm enc incorrect\n");
	else {
		printf("gcm enc ok\n");
	}

	if(memcmp(gcm_expected_tag, gcm_tmp2, sizeof(gcm_expected_tag)) != 0)
		printf("gcm tag incorrect\n");
	else {
		printf("gcm tag ok\n");
	}

	tgcm128.aadAppend(gcm_aad, sizeof(gcm_aad));

	tgcm128.decryptAppend(gcm_expected_ciphertext, gcm_tmp, sizeof(gcm_expected_ciphertext));

	bool tagcheck = tgcm128.verifyTag(gcm_expected_tag);

	if(memcmp(gcm_expected_plaintext, gcm_tmp, sizeof(gcm_expected_plaintext)) != 0)
		printf("gcm dec incorrect\n");
	else {
		printf("gcm dec ok\n");
	}

	if(tagcheck) {
		printf("gcm tag verify ok\n");
	} else {
		printf("gcm tag verify failed\n");
	}
}



void aes_gcm_perf_test(void)
{
	uint32_t t1, t2;

	//dummy_8k
	tgcm128.setEncKey(gcm_key);
	tgcm128.setIv(gcm_iv, 12);

	tgcm128.encryptAppend(dummy_8k, dummy_8k, sizeof(dummy_8k));
	tgcm128.finalizeTag(gcm_tmp2);

	t1 = DWT->CYCCNT;
	tgcm128.encryptAppend(dummy_8k, dummy_8k, sizeof(dummy_8k));
	tgcm128.finalizeTag(gcm_tmp2); // should it be measured ? // insignificant at large sizes
	t2 = DWT->CYCCNT - t1 - 1;

	printf("gcm 128 total: %d \n", t2);
	printf("gcm 128: %f cycles per byte\n", (double)t2/8192.0);
}



#endif

#endif //__arm__
