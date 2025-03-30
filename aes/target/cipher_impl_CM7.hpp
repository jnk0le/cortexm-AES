/*!
 * \file cipher_impl_CM7.hpp
 * \brief implementation wrappers of AES implementations for cortex-m7
 *
 * don't use directly
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 */

#ifndef AES_TARGET_CIPHER_IMPL_CM7_HPP
#define AES_TARGET_CIPHER_IMPL_CM7_HPP

#include <stdint.h>
#include <stddef.h>

#include "CM7.h"

namespace aes {
namespace target {

	template<size_t key_length>
	class CM7_1T
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM7_1T_AES128_keyschedule_enc(rk, key);
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
			CM7_1T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM7_1T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	template<size_t key_length>
	class CM7_1T_deconly : public CM7_1T<key_length>
	{
	public: // override only key expansions (encryption will take extra 256 bytes more than normally, if used)
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM7_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM7_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM7_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM7_1T_AES_keyschedule_dec_noTe(rk, this->key_rounds);
		}
	};

	template<size_t key_length>
	class CM7_DSPsBOX : public CM7_1T_deconly<key_length>  //reuse existing decryption for now
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM7_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM7_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM7_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		//void key_schedule_dec(uint8_t* rk) {
		//	(void)rk; //nothing to expand, the addroundkey stage is its own inverse
		//}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM7_DSPsBOX_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		//void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			//CM7_DSPsBOX_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		//}

	protected:
		//static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

} //namespace target
} //namespace aes


#endif //AES_TARGET_CIPHER_IMPL_CM7_HPP
