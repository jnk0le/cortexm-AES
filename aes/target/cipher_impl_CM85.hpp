/*!
 * \file cipher_impl_CM85.hpp
 * \brief implementation wrappers of AES implementations for cortex-m85
 *
 * don't use directly
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 */

#ifndef AES_TARGET_CIPHER_IMPL_CM85_HPP
#define AES_TARGET_CIPHER_IMPL_CM85_HPP

#include <stdint.h>
#include <stddef.h>

#include "CM7.h"
#include "CM85.h"

namespace aes {
namespace target {

	template<size_t key_length>
	class CM85_1T
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM85_1T_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM7_1T_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM7_1T_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM7_1T_AES_keyschedule_dec(rk, this->key_rounds);
		}

		void encrypt(uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM85_1T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM7_1T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}
	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	template<size_t key_length>
	class CM85_d4T : public CM85_1T<key_length>  //reuse
	{
	public:
		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM85_d4T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}
	protected:
		//static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

} //namespace target
} //namespace aes

#endif //AES_TARGET_CIPHER_IMPL_CM85_HPP
