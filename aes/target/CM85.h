/*!
 * \file CM85.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m85
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_CM85_H
#define AES_CM85_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM85_1T_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	//void CM85_1T_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	//void CM85_1T_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM85_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	//void CM85_d4T_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM85_d4T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM85_d4T_alt1_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM85_H
