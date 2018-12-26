/*!
 * \file aes_modes.hpp
 * \brief block mode implementations
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jul 2018
 */

#ifndef AES_MODES_HPP
#define AES_MODES_HPP

#include "cipher.hpp"
#include <stdint.h>
#include <string.h>

#include "target/modes_impl.hpp"

namespace aes
{
namespace mode
{
	template<size_t key_length, template<size_t> class base_impl = aes::target::CM34_1T, template<size_t key_len, template<size_t> class base> class mode_impl = aes::mode::target::CBC_GENERIC>
		class CBC : private mode_impl<key_length, base_impl>
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


	namespace ctr
	{
		// workaround
		class Nonce
		{
		public:
			uint32_t nonce[4];
		};
	}

	//SP 800-38A compliant, 32 bit counter
	template<size_t key_length, template<size_t> class base_impl = aes::target::CM34_1T, template<size_t key_len, template<size_t> class base> class mode_impl = aes::mode::target::CTR_GENERIC>
		class CTR : protected ctr::Nonce, private mode_impl<key_length, base_impl> // put the nonce before rk, to be compatible with current implementations
		{
		public:
			CTR() {}
			~CTR() {}

			void setNonce(void* n_nonce, size_t len = 12) {
				memcpy(this->nonce, n_nonce, len);

				if(len <= 12)
					this->nonce[3] = 0;
			}

			void setNonce(uint32_t nonce0, uint32_t nonce1, uint32_t nonce2, uint32_t nonce3 = 0) {
				this->nonce[0] = nonce0;
				this->nonce[1] = nonce1;
				this->nonce[2] = nonce2;
				this->nonce[3] = nonce3;
			}

			using mode_impl<key_length, base_impl>::setEncKey;

			void encrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
				mode_impl<key_length, base_impl>::encrypt(data_in, data_out, this->nonce, (len+15)/16);
			}

			void decrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
				mode_impl<key_length, base_impl>::encrypt(data_in, data_out, this->nonce, (len+15)/16);
			}

		private:
			//uint32_t nonce[4];
		};

}
}

#endif //AES_MODES_HPP
