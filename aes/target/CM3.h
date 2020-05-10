/*!
 * \file CM3.h
 * \brief FIPS 197 compliant software AES implementations optimized for cortex-m3/4
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#ifndef AES_CM3_H
#define AES_CM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	void CM3_sBOX_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_sBOX_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_sBOX_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM3_1T_AES_128_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_1T_AES_192_keyschedule_enc(uint8_t* rk, const uint8_t* key);
	void CM3_1T_AES_256_keyschedule_enc(uint8_t* rk, const uint8_t* key);

	void CM3_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds);
	void CM3_1T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds);

	void CM3_1T_AES_encrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM3_1T_AES_128_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES_192_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES_256_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

	void CM3_1T_AES_decrypt(const uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds);

	void CM3_1T_AES_128_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES_192_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);
	void CM3_1T_AES_256_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM3_H
