/*!
 * \file AES_CM34.h
 * \version 1.0.0
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

	extern void AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	extern void AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	extern void AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	extern void AES_keyschedule_dec(uint8_t* rk, size_t rounds);

	extern void AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	extern void AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif
