/*!
 * \file CM7.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m7
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_TARGET_CM7_H
#define AES_TARGET_CM7_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM7_sBOX_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key); // __attribute__ ((section(".itcm.text")));
	void CM7_sBOX_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key); // __attribute__ ((section(".itcm.text")));
	void CM7_sBOX_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key); // __attribute__ ((section(".itcm.text")));

	void CM7_1T_AES128_keyschedule_enc(uint8_t* rk, const uint8_t* key); // __attribute__ ((section(".itcm.text")));
	void CM7_1T_AES192_keyschedule_enc(uint8_t* rk, const uint8_t* key); // __attribute__ ((section(".itcm.text")));
	void CM7_1T_AES256_keyschedule_enc(uint8_t* rk, const uint8_t* key); // __attribute__ ((section(".itcm.text")));

	void CM7_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds); // __attribute__ ((section(".itcm.text")));
	void CM7_1T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds); // __attribute__ ((section(".itcm.text")));

	void CM7_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds); // __attribute__ ((section(".itcm.text")));

	void CM7_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds); // __attribute__ ((section(".itcm.text")));

	void CM7_DSPsBOX_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	//void CM7_DSPsBOX_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif

#endif // AES_TARGET_CM7_H
