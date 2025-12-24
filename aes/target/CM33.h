/*!
 * \file CM33.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m33
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_TARGET_CM33_H
#define AES_TARGET_CM33_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM33_1T_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	//void CM33_1T_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM33_1T_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	//void CM33_d4T_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	//void CM33_d4T_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	//void CM33_d4T_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	//void CM33_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);
	//void CM33_1T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds);

	//void CM33_d4T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);
	//void CM33_d4T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds);

	void CM33_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM33_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM33_d4T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	//void CM33_d4T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);


#ifdef __cplusplus
	}
#endif

#endif // AES_TARGET_CM33_H
