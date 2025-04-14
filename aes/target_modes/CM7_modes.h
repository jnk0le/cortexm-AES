/*!
 * \file CM7_modes.h
 * \brief AES block mode implementations optimized for cortex-m7
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_TARGET_MODES_CM7_MODES_H
#define AES_TARGET_MODES_CM7_MODES_H

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	// currently requires pointer to ctx struct in form:

	//typedef struct {
	//    uint8_t nonce[16];
	//    uint8_t rk[(n+1)*16];
	//} ctx;

	void CM7_1T_AES_CTR32_enc(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt);

	void CM7_1T_AES128_CTR32_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);
	void CM7_1T_AES192_CTR32_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);
	void CM7_1T_AES256_CTR32_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);

#ifdef __cplusplus
	}
#endif

#endif // AES_TARGET_MODES_CM7_MODES_H
