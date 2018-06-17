/*!
 * \file AES_CM34.h
 * \version 2.0.0
 * \brief FIPS 197 compliant software AES implementation optimized for cortex-m3/4 utilizing a single T table
 *
 * LUT tables are occupying 1 kB + 1.25 kB of memory for encryption + decryption
 *
 * This part is based on "Peter Schwabe and Ko Stoffelen" AES implementation:
 * https://github.com/Ko-/aes-armcortexm
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM34_1T_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_1T_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_1T_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);

	void CM34_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM34_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	//+unrolled

#ifdef __cplusplus
	}
#endif
