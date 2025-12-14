
/*!
 * \file ghash_common.hpp
 * \brief common ghash functions
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_TARGET_MODES_GHASH_COMMON_HPP
#define AES_TARGET_MODES_GHASH_COMMON_HPP

#include <stdint.h>
#include <stddef.h>

#include "../common.hpp"

namespace aes {
namespace mode {
namespace target {
namespace gcm {

namespace common {
	inline void ghashSetM0_4bit(const uint8_t* H, uint32_t* M) {
		const uint32_t* H32 = reinterpret_cast<const uint32_t*>(H);
		uint32_t t0, t1, t2, t3; // code gets messy without temporaries

		// algorithm 3 in https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
		M[0 + 0] = 0;
		M[0 + 1] = 0;
		M[0 + 2] = 0;
		M[0 + 3] = 0;

		// need endian swap to handle P (page 9)
		t0 = aes::common::byteswap(H32[0]);
		t1 = aes::common::byteswap(H32[1]);
		t2 = aes::common::byteswap(H32[2]);
		t3 = aes::common::byteswap(H32[3]);

		M[(8 * 4) + 0] = t0;
		M[(8 * 4) + 1] = t1;
		M[(8 * 4) + 2] = t2;
		M[(8 * 4) + 3] = t3;

		for(int i = 4; i > 0; i >>= 1) {
			// M[i] ← M[2i] · P
			uint32_t carry = t3 & 1;

			t3 = (t3 >> 1) | (t2 << 31);
			t2 = (t2 >> 1) | (t1 << 31);
			t1 = (t1 >> 1) | (t0 << 31);
			t0 = (t0 >> 1) ^ (0xe1000000 * carry); // R

			M[(i * 4) + 0] = t0;
			M[(i * 4) + 1] = t1;
			M[(i * 4) + 2] = t2;
			M[(i * 4) + 3] = t3;
		}

		for(int i = 2; i < 16; i *= 2) {
			t0 = M[(i * 4) + 0];
			t1 = M[(i * 4) + 1];
			t2 = M[(i * 4) + 2];
			t3 = M[(i * 4) + 3];

			for(int j = 1; j < i; j++) {
				M[((j+i) * 4) + 0] = t0 ^ M[(j * 4) + 0];
				M[((j+i) * 4) + 1] = t1 ^ M[(j * 4) + 1];
				M[((j+i) * 4) + 2] = t2 ^ M[(j * 4) + 2];
				M[((j+i) * 4) + 3] = t3 ^ M[(j * 4) + 3];
			}
		}
	}

	inline void ghashSetM0_8bit(const uint8_t* H, uint32_t* M) {
		const uint32_t* H32 = reinterpret_cast<const uint32_t*>(H);
		uint32_t t0, t1, t2, t3; // code gets messy without temporaries

		// algorithm 3 in https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
		M[0 + 0] = 0;
		M[0 + 1] = 0;
		M[0 + 2] = 0;
		M[0 + 3] = 0;

		// need endian swap to handle P (page 9)
		t0 = aes::common::byteswap(H32[0]);
		t1 = aes::common::byteswap(H32[1]);
		t2 = aes::common::byteswap(H32[2]);
		t3 = aes::common::byteswap(H32[3]);

		M[(128 * 4) + 0] = t0;
		M[(128 * 4) + 1] = t1;
		M[(128 * 4) + 2] = t2;
		M[(128 * 4) + 3] = t3;

		for(int i = 64; i > 0; i >>= 1) {
			// M[i] ← M[2i] · P
			uint32_t carry = t3 & 1;

			t3 = (t3 >> 1) | (t2 << 31);
			t2 = (t2 >> 1) | (t1 << 31);
			t1 = (t1 >> 1) | (t0 << 31);
			t0 = (t0 >> 1) ^ (0xe1000000 * carry); // R

			M[(i * 4) + 0] = t0;
			M[(i * 4) + 1] = t1;
			M[(i * 4) + 2] = t2;
			M[(i * 4) + 3] = t3;
		}

		for(int i = 2; i < 256; i *= 2) {
			t0 = M[(i * 4) + 0];
			t1 = M[(i * 4) + 1];
			t2 = M[(i * 4) + 2];
			t3 = M[(i * 4) + 3];

			for(int j = 1; j < i; j++) {
				M[((j+i) * 4) + 0] = t0 ^ M[(j * 4) + 0];
				M[((j+i) * 4) + 1] = t1 ^ M[(j * 4) + 1];
				M[((j+i) * 4) + 2] = t2 ^ M[(j * 4) + 2];
				M[((j+i) * 4) + 3] = t3 ^ M[(j * 4) + 3];
			}
		}
	}

}


}
}
}
}

#endif
