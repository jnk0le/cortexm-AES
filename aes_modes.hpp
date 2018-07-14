/*!
 * \file aes_modes.hpp
 * \version 3.0.0
 * \brief block mode implementations
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jul 2018
 */

#include <stdint.h>
#include <string.h>

#include "aes_cipher.hpp"
#include "target/modes_impl.hpp"

namespace aes
{
namespace mode
{
	template<size_t key_length, template<size_t> class base_impl = aes::target::CM34_1T, template<size_t key_len, template<size_t> class base> class mode_impl = aes::mode::target::CBC_GENERIC>
		class CBC : protected mode_impl<key_length, base_impl>
		{
		public:
			CBC() {}
			~CBC() {}

			void setIv(void* n_iv) {
				memcpy(this->iv, n_iv, 16);
			}

			void setIv(uint32_t iv0, uint32_t iv1, uint32_t iv2, uint32_t iv3) {
				this->iv[0] = iv0;
				this->iv[1] = iv1;
				this->iv[2] = iv2;
				this->iv[3] = iv3;
			}

			using mode_impl<key_length, base_impl>::setEncKey;
			using mode_impl<key_length, base_impl>::setDecKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
				this->setIv(mode_impl<key_length, base_impl>::encrypt(data_in, data_out, iv, (len+15)/16));
			}

			void decrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
				this->setIv(mode_impl<key_length, base_impl>::decrypt(data_in, data_out, iv, (len+15)/16));
			}

		private:
			uint32_t iv[4];
		};

}
}

