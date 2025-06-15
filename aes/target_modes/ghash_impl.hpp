/*!
 * \file ghash_impl.hpp
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
namespace gcm {

	//definitions are in dedicated file
	extern "C" uint32_t ghash_shoup4_R[]; //put in header ?
	extern "C" uint32_t ghash_shoup8_R[];

	class GHASH_GENERIC_BEAR_CT
	{
	public:
		void setH(const uint8_t* H_in) {
			memcpy(H, H_in, 16);
		}

		/*!
		 * \brief multiplies 128 bit blocks by H (ghash)
		 *
		 * \param[in/out] partial_tag
		 * \param[in] data pointer to data to hash
		 * \param blocks_cnt number of blocks to hash from source
		 */
		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			br_ghash_ctmul(partial_tag, H, data, blocks_cnt*16);
		}

		uint8_t H[16];
	};

	// for cortex m0 and m3 which can't do long multiplication in constant time
	class GHASH_GENERIC_BEAR_CT32
	{
	public:
		void setH(const uint8_t* H_in) {
			memcpy(H, H_in, 16);
		}

		/*!
		 * \brief multiplies 128 bit blocks by H (ghash)
		 *
		 * \param[in/out] partial_tag
		 * \param[in] data pointer to data to hash
		 * \param blocks_cnt number of blocks to hash from source
		 */
		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			br_ghash_ctmul32(partial_tag, H, data, blocks_cnt*16);
		}

	private:
		uint8_t H[16];
	};

	//move aux to separate file??
	namespace aux2 {
	#if __cplusplus >= 202302L
		using std::byteswap;
	#else
		constexpr uint32_t byteswap(uint32_t value) {
			return __builtin_bswap32(value);
		}
		constexpr uint64_t byteswap(uint64_t value) {
			return __builtin_bswap64(value);
		}
	#endif
	}

	// separate file?
	namespace generic {
		inline void ghashSetM0_4bit(const uint8_t* H, uint32_t* M) {
			const uint32_t* H32 = reinterpret_cast<const uint32_t*>(H);
			uint32_t t0, t1, t2, t3; // code gets messy without temporaries

			// algorithm 3 in https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
			M[0 + 0] = 0;
			M[0 + 1] = 0;
			M[0 + 2] = 0;
			M[0 + 3] = 0;

			// need endian swap to handle P (page 9)
			t0 = aux2::byteswap(H32[0]);
			t1 = aux2::byteswap(H32[1]);
			t2 = aux2::byteswap(H32[2]);
			t3 = aux2::byteswap(H32[3]);

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
			t0 = aux2::byteswap(H32[0]);
			t1 = aux2::byteswap(H32[1]);
			t2 = aux2::byteswap(H32[2]);
			t3 = aux2::byteswap(H32[3]);

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

	class GHASH_GENERIC_SHOUP_M4
	{
	public:
		void setH(const uint8_t* H) {
			generic::ghashSetM0_4bit(H, M);
		}

		/*!
		 * \brief multiplies 128 bit blocks by H (ghash)
		 *
		 * \param[in/out] partial_tag
		 * \param[in] data pointer to data to hash
		 * \param blocks_cnt number of blocks to hash from source
		 */
		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			uint32_t Z[4];
			uint8_t lo, hi, rem;

			uint32_t* partial_tag32 = reinterpret_cast<uint32_t*>(partial_tag);
			const uint32_t* data32 = reinterpret_cast<const uint32_t*>(data);

			for(uint32_t n = 0; n < blocks_cnt; n++) {
				partial_tag32[0] ^= data32[0];
				partial_tag32[1] ^= data32[1];
				partial_tag32[2] ^= data32[2];
				partial_tag32[3] ^= data32[3];
				data32 += 4; // advance input // don't use 8bit pointer from now

				//algorithm 2 is probably incorrect with use of X instead of Z in 2 lines
				lo = partial_tag[15] & 0x0f;

				Z[0] = M[(lo * 4) + 0];
				Z[1] = M[(lo * 4) + 1];
				Z[2] = M[(lo * 4) + 2];
				Z[3] = M[(lo * 4) + 3];

				hi = partial_tag[15] >> 4;

				rem = Z[3] & 0xf;

				Z[3] = (Z[3] >> 4) | (Z[2] << 28);
				Z[2] = (Z[2] >> 4) | (Z[1] << 28);
				Z[1] = (Z[1] >> 4) | (Z[0] << 28);
				Z[0] = (Z[0] >> 4) ^ ghash_shoup4_R[rem];

				Z[0] ^= M[(hi * 4) + 0];
				Z[1] ^= M[(hi * 4) + 1];
				Z[2] ^= M[(hi * 4) + 2];
				Z[3] ^= M[(hi * 4) + 3];

				for(int i = 14; i >= 0; i--) {
					lo = partial_tag[i] & 0x0f;

					rem = Z[3] & 0xf;

					Z[3] = (Z[3] >> 4) | (Z[2] << 28);
					Z[2] = (Z[2] >> 4) | (Z[1] << 28);
					Z[1] = (Z[1] >> 4) | (Z[0] << 28);
					Z[0] = (Z[0] >> 4) ^ ghash_shoup4_R[rem];

					Z[0] ^= M[(lo * 4) + 0];
					Z[1] ^= M[(lo * 4) + 1];
					Z[2] ^= M[(lo * 4) + 2];
					Z[3] ^= M[(lo * 4) + 3];

					hi = partial_tag[i] >> 4;

					rem = Z[3] & 0xf;

					Z[3] = (Z[3] >> 4) | (Z[2] << 28);
					Z[2] = (Z[2] >> 4) | (Z[1] << 28);
					Z[1] = (Z[1] >> 4) | (Z[0] << 28);
					Z[0] = (Z[0] >> 4) ^ ghash_shoup4_R[rem];

					Z[0] ^= M[(hi * 4) + 0];
					Z[1] ^= M[(hi * 4) + 1];
					Z[2] ^= M[(hi * 4) + 2];
					Z[3] ^= M[(hi * 4) + 3];
				}

				partial_tag32[0] = aux2::byteswap(Z[0]);
				partial_tag32[1] = aux2::byteswap(Z[1]);
				partial_tag32[2] = aux2::byteswap(Z[2]);
				partial_tag32[3] = aux2::byteswap(Z[3]);
			}
		}

	private:
		// M is generated from byte reversed state
		uint32_t M[16*4]; // 16 elements * 16 byte entries
	};

	class GHASH_GENERIC_SHOUP_M8
	{
	public:
		void setH(const uint8_t* H) {
			generic::ghashSetM0_8bit(H, M);
		}

		/*!
		 * \brief multiplies 128 bit blocks by H (ghash)
		 *
		 * \param[in/out] partial_tag
		 * \param[in] data pointer to data to hash
		 * \param blocks_cnt number of blocks to hash from source
		 */
		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			uint32_t Z[4];
			uint8_t in, rem;

			uint32_t* partial_tag32 = reinterpret_cast<uint32_t*>(partial_tag);
			const uint32_t* data32 = reinterpret_cast<const uint32_t*>(data);

			for(uint32_t n = 0; n < blocks_cnt; n++) {
				partial_tag32[0] ^= data32[0];
				partial_tag32[1] ^= data32[1];
				partial_tag32[2] ^= data32[2];
				partial_tag32[3] ^= data32[3];
				data32 += 4; // advance input // don't use 8bit pointer from now

				//algorithm 2 is probably incorrect with use of X instead of Z in 2 lines
				in = partial_tag[15];

				Z[0] = M[(in * 4) + 0];
				Z[1] = M[(in * 4) + 1];
				Z[2] = M[(in * 4) + 2];
				Z[3] = M[(in * 4) + 3];

				for(int i = 14; i >= 0; i--) {
					in = partial_tag[i];

					rem = Z[3] & 0xff;

					Z[3] = (Z[3] >> 8) | (Z[2] << 24);
					Z[2] = (Z[2] >> 8) | (Z[1] << 24);
					Z[1] = (Z[1] >> 8) | (Z[0] << 24);
					Z[0] = (Z[0] >> 8) ^ ghash_shoup8_R[rem];

					Z[0] ^= M[(in * 4) + 0];
					Z[1] ^= M[(in * 4) + 1];
					Z[2] ^= M[(in * 4) + 2];
					Z[3] ^= M[(in * 4) + 3];
				}

				partial_tag32[0] = aux2::byteswap(Z[0]);
				partial_tag32[1] = aux2::byteswap(Z[1]);
				partial_tag32[2] = aux2::byteswap(Z[2]);
				partial_tag32[3] = aux2::byteswap(Z[3]);
			}

		}

	private:
		// M is generated from byte reversed state
		uint32_t M[256*4]; // 256 elements * 16 byte entries
	};


	class GHASH_GENERIC_FULL_M4
	{
	public:
		void setH(const uint8_t* H) {
			generic::ghashSetM0_4bit(H, M); // M0

			// M[i] = M[i-1] · P^4
			// P^4 is P applied 4 times, P is shift + reduction by polynomial, can be also seen
			// as multiplication (with reduction) by another polynomial where n (from P^n) bit is set

			// P has been applied 3 times already in M0, accessible at M[1]
			// one more P needs to be applied here

			uint32_t* Mcur = M;

			for(int i = 1; i < 32; i++) {
				uint32_t next_H[4];

				uint32_t carry = Mcur[(1 * 4) + 3] & 1;

				next_H[3] = (Mcur[(1 * 4) + 3] >> 1) | (Mcur[(1 * 4) + 2] << 31);
				next_H[2] = (Mcur[(1 * 4) + 2] >> 1) | (Mcur[(1 * 4) + 1] << 31);
				next_H[1] = (Mcur[(1 * 4) + 1] >> 1) | (Mcur[(1 * 4) + 0] << 31);
				next_H[0] = (Mcur[(1 * 4) + 0] >> 1) ^ (0xe1000000 * carry); // R;

				// H input is byte reversed in M0 gen, so unreverse it
				// fix later
				next_H[0] = aux2::byteswap(next_H[0]);
				next_H[1] = aux2::byteswap(next_H[1]);
				next_H[2] = aux2::byteswap(next_H[2]);
				next_H[3] = aux2::byteswap(next_H[3]);

				Mcur += 256/4; // 256 bytes per M[i]
				generic::ghashSetM0_4bit((uint8_t*)next_H, Mcur); // repeat algorithm 3
			}

		}

		void gmulH(uint8_t* partial_tag, const uint8_t* data, uint32_t blocks_cnt) {
			uint32_t Z[4];
			uint8_t lo, hi; // low part is extracted from the top 4 bits

			uint32_t* partial_tag32 = reinterpret_cast<uint32_t*>(partial_tag);
			const uint32_t* data32 = reinterpret_cast<const uint32_t*>(data);

			for(uint32_t n = 0; n < blocks_cnt; n++) {
				partial_tag32[0] ^= data32[0];
				partial_tag32[1] ^= data32[1];
				partial_tag32[2] ^= data32[2];
				partial_tag32[3] ^= data32[3];
				data32 += 4; // advance input // don't use 8bit pointer from now

				uint32_t* Mcur = M; // current M, incremented as there are 32 M tables

				lo = partial_tag[0] >> 4;

				Z[0] = Mcur[(lo * 4) + 0];
				Z[1] = Mcur[(lo * 4) + 1];
				Z[2] = Mcur[(lo * 4) + 2];
				Z[3] = Mcur[(lo * 4) + 3];

				Mcur += 256/4; // 256 bytes per M[i]
				hi = partial_tag[0] & 0x0f;

				Z[0] ^= Mcur[(hi * 4) + 0];
				Z[1] ^= Mcur[(hi * 4) + 1];
				Z[2] ^= Mcur[(hi * 4) + 2];
				Z[3] ^= Mcur[(hi * 4) + 3];

				for(int i = 1; i < 16; i++) {
					Mcur += 256/4; // 256 bytes per M[i]
					lo = partial_tag[i] >> 4;

					Z[0] ^= Mcur[(lo * 4) + 0];
					Z[1] ^= Mcur[(lo * 4) + 1];
					Z[2] ^= Mcur[(lo * 4) + 2];
					Z[3] ^= Mcur[(lo * 4) + 3];

					Mcur += 256/4; // 256 bytes per M[i]
					hi = partial_tag[i] & 0x0f;

					Z[0] ^= Mcur[(hi * 4) + 0];
					Z[1] ^= Mcur[(hi * 4) + 1];
					Z[2] ^= Mcur[(hi * 4) + 2];
					Z[3] ^= Mcur[(hi * 4) + 3];
				}

				partial_tag32[0] = aux2::byteswap(Z[0]);
				partial_tag32[1] = aux2::byteswap(Z[1]);
				partial_tag32[2] = aux2::byteswap(Z[2]);
				partial_tag32[3] = aux2::byteswap(Z[3]);
			}
		}

	private:
		// M is generated from byte reversed state, M[i] is placed after M[i-1]
		uint32_t M[32*16*4]; // 32 tables * 16 elements * 16 byte entries (8 KiB total)
	};

}
}
}
}

#endif //AES_TARGET_MODES_GHASH_IMPL_HPP
