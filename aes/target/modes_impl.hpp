/*!
 * \file modes_impl.hpp
 * \brief wrappers for block mode ciphers
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date 10 Jul 2018
 */

#ifndef AES_MODES_IMPL_HPP
#define AES_MODES_IMPL_HPP

#include <stdint.h>
#include <stddef.h>

#include "CM3_modes.h"
#include "CM7_modes.h"

namespace aes
{
namespace mode
{
namespace target
{
	template<size_t key_length, template<size_t> class base_impl>
		class CBC_GENERIC : private CipherContext<key_length, base_impl>
		{
		public:
			using CipherContext<key_length, base_impl>::setEncKey;
			using CipherContext<key_length, base_impl>::setDecKey;

			uint32_t* encrypt(const uint8_t* data_in, uint8_t* data_out, const void* iv, uint32_t blocks_cnt)
			{
				uint32_t* data_in_p = (uint32_t*)data_in;
				uint32_t* data_out_p = (uint32_t*)data_out;
				uint32_t* iv_p = (uint32_t*)iv;

				for(uint32_t i = 0; i<blocks_cnt; i++)
				{
					data_out_p[0] = data_in_p[0] ^ iv_p[0];
					data_out_p[1] = data_in_p[1] ^ iv_p[1];
					data_out_p[2] = data_in_p[2] ^ iv_p[2];
					data_out_p[3] = data_in_p[3] ^ iv_p[3];

					CipherContext<key_length, base_impl>::encrypt((uint8_t*)data_out_p);

					iv_p = data_out_p;
					data_out_p += 4;
					data_in_p += 4;
				}

				return iv_p;
			}

			uint32_t* decrypt(const uint8_t* data_in, uint8_t* data_out, void* iv, uint32_t blocks_cnt)
			{
				uint32_t* data_out_p = (uint32_t*)data_out;
				uint32_t* iv_p = (uint32_t*)iv;

				for(uint32_t i = 0; i<blocks_cnt; i++)
				{
					CipherContext<key_length, base_impl>::decrypt(data_in, (uint8_t*)data_out_p);

					data_out_p[0] ^= iv_p[0];
					data_out_p[1] ^= iv_p[1];
					data_out_p[2] ^= iv_p[2];
					data_out_p[3] ^= iv_p[3];

					iv_p = (uint32_t*)data_in;
					data_out_p += 4;
					data_in += 16;
				}

				return iv_p;
			}

		};

	//SP 800-38A compliant
	template<size_t key_length, template<size_t> class base_impl>
		class CTR32_GENERIC : private CipherContext<key_length, base_impl>
		{
		public:
			using CipherContext<key_length, base_impl>::setEncKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, void* nonce, uint32_t blocks_cnt)
			{
				uint32_t* data_in_p = (uint32_t*)data_in;
				uint32_t* data_out_p = (uint32_t*)data_out;
				uint32_t* nonce_p = (uint32_t*)nonce;

				uint32_t tmp_ctr = nonce_p[3];

				tmp_ctr = __builtin_bswap32(tmp_ctr); // initially swap to little endian format

				for(uint32_t i = 0; i<blocks_cnt; i++)
				{
					CipherContext<key_length, base_impl>::encrypt((uint8_t*)nonce_p, (uint8_t*)data_out_p);

					data_out_p[0] ^= data_in_p[0];
					data_out_p[1] ^= data_in_p[1];
					data_out_p[2] ^= data_in_p[2];
					data_out_p[3] ^= data_in_p[3];

					tmp_ctr++;

					nonce_p[3] = __builtin_bswap32(tmp_ctr); // SP 800-38A compliant format

					data_out_p += 4;
					data_in_p += 4;
				}
			}
		};

	template<size_t key_length, template<size_t> class base_impl>
		class CTR32_CM3_1T : private CipherContext<key_length, base_impl>
		{
		public:
			using CipherContext<key_length, base_impl>::setEncKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, void* nonce, uint32_t blocks_cnt)
			{
				//nonce should be placed right before expanded key
				CM3_1T_AES_CTR32_enc(nonce, data_in, data_out, this->key_rounds, blocks_cnt);
			}
		};

	template<size_t key_length, template<size_t> class base_impl>
		class CTR32_CM3_1T_unrolled : private CipherContext<key_length, base_impl>
		{
		public:
			using CipherContext<key_length, base_impl>::setEncKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, void* nonce, uint32_t blocks_cnt)
			{
				//nonce should be placed right before expanded key

				switch(key_length)
				{
				case 128:
					CM3_1T_AES_128_CTR32_enc_unrolled(nonce, data_in, data_out, blocks_cnt);
					break;
				case 192:
					CM3_1T_AES_192_CTR32_enc_unrolled(nonce, data_in, data_out, blocks_cnt);
					break;
				case 256:
					CM3_1T_AES_256_CTR32_enc_unrolled(nonce, data_in, data_out, blocks_cnt);
					break;
				}

			}
		};

	template<size_t key_length, template<size_t> class base_impl>
		class CTR32_CM7_1T : private CipherContext<key_length, base_impl>
		{
		public:
			using CipherContext<key_length, base_impl>::setEncKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, void* nonce, uint32_t blocks_cnt)
			{
				//nonce should be placed right before expanded key
				CM7_1T_AES_CTR32_enc(nonce, data_in, data_out, this->key_rounds, blocks_cnt);
			}
		};

	template<size_t key_length, template<size_t> class base_impl>
		class CTR32_CM7_1T_unrolled : private CipherContext<key_length, base_impl>
		{
		public:
			using CipherContext<key_length, base_impl>::setEncKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, void* nonce, uint32_t blocks_cnt)
			{
				//nonce should be placed right before expanded key

				switch(key_length)
				{
				case 128:
					CM7_1T_AES_128_CTR32_enc_unrolled(nonce, data_in, data_out, blocks_cnt);
					break;
				case 192:
					CM7_1T_AES_192_CTR32_enc_unrolled(nonce, data_in, data_out, blocks_cnt);
					break;
				case 256:
					CM7_1T_AES_256_CTR32_enc_unrolled(nonce, data_in, data_out, blocks_cnt);
					break;
				}

			}
		};

}
}
}

#endif //AES_MODES_IMPL_HPP
