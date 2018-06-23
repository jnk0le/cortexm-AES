/*!
 * \file aes_cipher.hpp
 * \version 2.0.1
 * \brief basic ECB cipher context class
 *
 * \warning Do not use ECB mode for more than 16 bytes of plaintext data per key.
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#ifndef AES_HPP
#define AES_HPP

#include <stdint.h>

#include "target/cipher_impl.hpp"

namespace aes
{
	template<size_t key_length, template<size_t> class impl = target::CM34_1T>
		class CipherContext : protected impl<key_length>
		{
		public:
			CipherContext() {}
			//copy constructor ??
			~CipherContext() {}

			void setEncKey(const uint8_t* key) {
				impl<key_length>::key_schedule_enc(this->round_key, key);
			}

			void setDecKey(const uint8_t* key) {
				impl<key_length>::key_schedule_enc(this->round_key, key);
				impl<key_length>::key_schedule_dec(this->round_key);
			}

			void setDecKey(void) {
				impl<key_length>::key_schedule_dec(this->round_key);
			}

			void encrypt(uint8_t* data) const {
				encrypt(data, data);
			}

			void encrypt(const uint8_t* data_in, uint8_t* data_out) {
				impl<key_length>::encrypt(this->round_key, data_in, data_out);
			}
			void decrypt(uint8_t* data) const {
				decrypt(data, data);
			}

			void decrypt(const uint8_t* data_in, uint8_t* data_out) {
				impl<key_length>::decrypt(this->round_key, data_in, data_out);
			}

		private:
			uint8_t round_key[(impl<key_length>::key_rounds+1)*16];

			static_assert(key_length == 128 || key_length == 192 || key_length == 256,
					"non standard key lengths are not supported");
		};

}


#endif // AES_HPP
