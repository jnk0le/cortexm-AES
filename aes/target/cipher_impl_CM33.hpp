/*!
 * \file cipher_impl_CM33.hpp
 * \brief implementation wrappers of AES implementations for cortex-m33
 *
 * don't use this file directly
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \copyright MIT License
 */

#ifndef AES_TARGET_CIPHER_IMPL_CM33_HPP
#define AES_TARGET_CIPHER_IMPL_CM33_HPP

#include <stdint.h>
#include <stddef.h>

#include "CM33.h"

namespace aes {
namespace target {

	template<size_t key_length>
	class CM33_1T
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM33_1T_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM3_1T_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM33_1T_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM3_1T_AES_keyschedule_dec(rk, this->key_rounds);
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM33_1T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM33_1T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	// deconly??


	template<size_t key_length>
	class CM33_d4T
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM33_1T_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM3_1T_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM33_1T_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM3_1T_AES_keyschedule_dec(rk, this->key_rounds);
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM33_d4T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM33_1T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};



} //namespace target
} //namespace aes


#endif //AES_TARGET_CIPHER_IMPL_CM33_HPP
