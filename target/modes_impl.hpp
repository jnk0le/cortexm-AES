/*!
 * \file modes_impl.hpp
 * \version 3.0.0
 * \brief wrappers for block mode ciphers
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jul 2018
 */

#include <stdint.h>

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

	/*template<size_t key_length, template<size_t> class base_impl>
		class CTR_LE32NONCE_GENERIC : public CipherContext<key_length, base_impl>
		{
		public:


		private:


		};*/

}
}
}
