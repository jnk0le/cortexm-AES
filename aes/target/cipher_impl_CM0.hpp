/*!
 * \file cipher_impl_CM0.hpp
 * \brief implementation wrappers of AES implementations for cortex-m0
 *
 * don't use directly
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 */

#ifndef AES_TARGET_CIPHER_IMPL_CM0_HPP
#define AES_TARGET_CIPHER_IMPL_CM0_HPP

#include <stdint.h>
#include <stddef.h>

#include "CM0.h"

namespace aes {
namespace target {

	template<size_t key_length>
	class CM0_sBOX
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM0_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM0_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM0_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			(void)rk; //nothing to expand, the addroundkey stage is its own inverse
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_sBOX_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_sBOX_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	template<size_t key_length>
	class CM0_FASTMULsBOX
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM0_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM0_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM0_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			(void)rk; //nothing to expand, the addroundkey stage is its own inverse
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_FASTMULsBOX_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_FASTMULsBOX_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	template<size_t key_length>
	class CM0_d4T
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM0_d4T_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM0_d4T_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM0_d4T_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM0_d4T_AES_keyschedule_dec(rk, this->key_rounds);
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_d4T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_d4T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	template<size_t key_length>
	class CM0_d4T_FAST : public CM0_d4T<key_length>
	{
	public:
		void key_schedule_dec(uint8_t* rk) {
			CM0_d4T_AES_keyschedule_dec(rk, this->key_rounds); // recycle for now
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_d4T_FAST_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM0_d4T_FAST_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

} //namespace target
} //namespace aes

#endif //AES_TARGET_CIPHER_IMPL_CM0_HPP
