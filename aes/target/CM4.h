/*!
 * \file CM4.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m4
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_TARGET_CM4_H
#define AES_TARGET_CM4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM4_DSPsBOX_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	void CM4_DSPsBOX_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif

#endif // AES_TARGET_CM4_H
