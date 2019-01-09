/*!
 * \file CM34.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m3/4
 *
 * Utilizes a 1K T table per cipher occupying 1 kB + 1.25 kB of memory for encryption + decryption
 *
 * This part is based on "Peter Schwabe and Ko Stoffelen" AES implementation:
 * https://github.com/Ko-/aes-armcortexm
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#ifndef AES_CM34_H
#define AES_CM34_H

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM34_sBOX_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_sBOX_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_sBOX_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM34_1T_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_1T_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_1T_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM34_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);

	void CM34_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM34_1T_AES_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM34_1T_AES_128_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM34_1T_AES_192_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM34_1T_AES_256_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

	void CM34_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM34_1T_AES_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM34_1T_AES_128_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM34_1T_AES_192_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM34_1T_AES_256_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM34_H
