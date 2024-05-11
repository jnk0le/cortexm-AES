/*!
 * \file CM3.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m3/4
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_CM3_H
#define AES_CM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM3_sBOX_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_sBOX_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_sBOX_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM3_1T_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_1T_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_1T_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM3_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);
	void CM3_1T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds);

	void CM3_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM3_1T_AES128_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES192_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES256_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

	void CM3_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM3_1T_AES128_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES192_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES256_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM3_H
