/*!
 * \file CM4.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m4
 *
 * Utilizes a simple sbox/invsbox for encryption/decryption
 *
 * Uses cortex-m4 dsp instructions to perform optimized mixcolumns stage described in this paper:
 * http://www.wseas.us/e-library/conferences/2009/moscow/AIC/AIC44.pdf
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Dec 2018
 */

#ifndef AES_CM4_H
#define AES_CM4_H

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	//sboxed key expander here ?

	void CM4_DSPsBOX_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);
	//void CM4_DSPsBOX_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM4_H
