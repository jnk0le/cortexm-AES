/*!
 * \file QKv2.h
 * \brief FIPS 197 compliant software AES implementations optimized for QingKe v2 core (ch32v003)
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date 24 Apr 2024
 */

#ifndef AES_QKV2_H
#define AES_QKV2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void QKv2_sBOX_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void QKv2_sBOX_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void QKv2_sBOX_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void QKv2_sBOX_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void QKv2_sBOX_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif

#endif // AES_QKV2_H
