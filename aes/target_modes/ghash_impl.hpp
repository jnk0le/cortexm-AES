/*!
 * \file aes_modes.hpp
 * \brief block mode implementations
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_TARGET_MODES_GHASH_IMPL_HPP
#define AES_TARGET_MODES_GHASH_IMPL_HPP

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "generic_external/bear_ghash.h"

namespace aes {
namespace mode {
namespace target {


	class GCM_GHASH_GENERIC_BEAR_CT
	{
	public:
		// init H for precomputed ??

		/*!
		 * \brief multiplies 128 bit blocks by H (ghash)
		 *
		 * \param[in/out] partial_tag
		 * \param[in] data pointer to data to hash
		 * \param  blocks_cnt number of blocks to hash from source
		 */
		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			br_ghash_ctmul(partial_tag, H, data, blocks_cnt*16);
		}

		uint8_t H[16];
	};

	// for cortex m0 and m3 which can't do long multiplication in constant time
	class GCM_GHASH_GENERIC_BEAR_CT32
	{
	public:
		// init H for precomputed ??

		/*!
		 * \brief multiplies 128 bit blocks by H (ghash)
		 *
		 * \param[in/out] partial_tag
		 * \param[in] data pointer to data to hash
		 * \param  blocks_cnt number of blocks to hash from source
		 */
		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			br_ghash_ctmul32(partial_tag, H, data, blocks_cnt*16);
		}

		uint8_t H[16];
	};


}
}
}

#endif //AES_TARGET_MODES_GHASH_IMPL_HPP
