/*!
 * \file cipher_impl_QKv2.hpp
 * \brief implementation wrappers of AES implementations for WCH's QuingKe v2
 *
 * don't use directly
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 */

#ifndef AES_TARGET_CIPHER_IMPL_QKv2_HPP
#define AES_TARGET_CIPHER_IMPL_QKv2_HPP

#include <stdint.h>
#include <stddef.h>

#include "QKv2.h"

namespace aes {
namespace target {

	template<size_t key_length>
	class QKv2_sBOX
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				QKv2_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				QKv2_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				QKv2_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			(void)rk; //nothing to expand, the addroundkey stage is its own inverse
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			QKv2_sBOX_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			QKv2_sBOX_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

} //namespace target
} //namespace aes

#endif //AES_TARGET_CIPHER_IMPL_QKv2_HPP
