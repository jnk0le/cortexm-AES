/*!
 * \file CM3_modes.h
 * \brief AES block mode implementations optimized for cortex-m3/4
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Aug 2018
 */

#ifndef AES_CM3_MODES_H
#define AES_CM3_MODES_H

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	// currently requires pointer to ctx struct in form:

	//typedef struct {
	//    uint8_t nonce[16];
	//    uint8_t rk[(n+1)*16];
	//} ctx;

	void CM3_1T_AES_CTR_enc(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt);

	void CM3_1T_AES_128_CTR_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);
	void CM3_1T_AES_192_CTR_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);
	void CM3_1T_AES_256_CTR_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);

#ifdef __cplusplus
	}
#endif

#endif // AES_CM3_MODES_H
