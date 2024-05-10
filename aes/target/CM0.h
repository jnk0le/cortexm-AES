/*!
 * \file CM0.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m0/m0+
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date 16 Oct 2021
 */

#ifndef AES_CM0_H
#define AES_CM0_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM0_sBOX_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM0_sBOX_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM0_sBOX_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM0_sBOX_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM0_sBOX_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM0_FASTMULsBOX_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM0_FASTMULsBOX_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM0_H
