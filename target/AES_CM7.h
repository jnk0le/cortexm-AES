/*!
 * \file AES_CM7.h
 * \version 2.4.0
 * \brief FIPS 197 compliant software AES implementation optimized for cortex-m7 utilizing a single T table
 *
 * LUT tables are occupying 1 kB + 1.25 kB of memory for encryption + decryption
 *
 * \warning Only DTCM memory can be used for LUT tables, since everything else is cached through AXI bus.
 * \warning Effects of DMA access to DTCM when core have equal priority is unknown.
 *
 * This part is based on CM34 implementation, carefully reordered for dual issue pipeline, with 2x32 bit DTCM
 * interface, to avoid data dependent stalls when two neighbouring loads both accesses data on even/odd location
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM7_1T_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM7_1T_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM7_1T_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM7_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);

	void CM7_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM7_1T_AES_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM7_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM7_1T_AES_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM7_1T_AES_128_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM7_1T_AES_192_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM7_1T_AES_256_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

	void CM7_1T_AES_128_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM7_1T_AES_192_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM7_1T_AES_256_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

#ifdef __cplusplus
	}
#endif
