/*!
 * \file aes_cipher.hpp
 * \brief basic cipher context class
 *
 * \warning Do not use directly, use modes other than ECB instaed
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_CIPHER_HPP
#define AES_CIPHER_HPP

#include <stdint.h>
#include <stddef.h>

#include "common.hpp"
#include "target/cipher_impl.hpp"

namespace aes
{
	template<size_t key_length, template<size_t> class impl = target::CM3_1T>
	class CipherContext : protected impl<key_length>
	{
	public:
		CipherContext() {}
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

		void encrypt(uint8_t* data) {
			encrypt(data, data);
		}

		void encrypt(const uint8_t* data_in, uint8_t* data_out) {
			impl<key_length>::encrypt(this->round_key, data_in, data_out);
		}

		void decrypt(uint8_t* data) {
			decrypt(data, data);
		}

		void decrypt(const uint8_t* data_in, uint8_t* data_out) {
			impl<key_length>::decrypt(this->round_key, data_in, data_out);
		}

	protected:
		uint8_t round_key[(impl<key_length>::key_rounds+1)*16];

	private:
		static_assert(key_length == 128 || key_length == 192 || key_length == 256,
				"non standard key lengths are not supported");
	};

}

#endif // AES_CIPHER_HPP
