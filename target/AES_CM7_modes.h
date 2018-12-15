/*!
 * \file AES_CM7_modes.h
 * \brief SP 800-38A compliant, software AES block modes implementations optimized for cortex-m3/4
 *
 * ctr encryption can be recycled for decryption thus requiring only 1K T table for encryption
 *
 * This part is based on CM34 implementation, carefully reordered for dual issue pipeline, with 2x32 bit DTCM
 * interface, to avoid data dependent stalls when two neighbouring loads both accesses data on even/odd location
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Aug 2018
 */

#include <stdint.h>

#ifdef __cplusplus
	extern "C" {
#endif

	// currently requires pointer to ctx struct in form:

	//typedef struct {
	//    uint8_t nonce[16];
	//    uint8_t rk[(n+1)*16];
	//} ctx;


	void CM7_1T_AES_CTR_enc(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt);

	void CM7_1T_AES_128_CTR_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);
	void CM7_1T_AES_192_CTR_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);
	void CM7_1T_AES_256_CTR_enc_unrolled(void* ctx, const uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt);

#ifdef __cplusplus
	}
#endif
