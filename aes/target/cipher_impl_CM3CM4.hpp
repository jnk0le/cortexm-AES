/*!
 * \file cipher_impl_CM3CM4.hpp
 * \brief implementation wrappers of AES implementations for cortex-m3/4
 *
 * don't use directly
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 */

#ifndef AES_TARGET_CIPHER_IMPL_CM3CM4_HPP
#define AES_TARGET_CIPHER_IMPL_CM3CM4_HPP

#include <stdint.h>
#include <stddef.h>

#include "CM3.h"
#include "CM4.h"

namespace aes {
namespace target {

	template<size_t key_length>
	class CM3_1T
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM3_1T_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM3_1T_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM3_1T_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM3_1T_AES_keyschedule_dec(rk, this->key_rounds);
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM3_1T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM3_1T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

	template<size_t key_length>
	class CM3_1T_deconly : public CM3_1T<key_length>
	{
	public: // override only key expansions (encryption will take extra 256 bytes more than normally, if used)
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM3_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM3_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM3_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM3_1T_AES_keyschedule_dec_noTe(rk, this->key_rounds);
		}
	};

	template<size_t key_length>
	class CM3_1T_unrolled : public CM3_1T<key_length>
	{
	public: // override only unrolled functions
		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			//CM3_1T_AES_encrypt_unrolled(rk, data_in, data_out, this->key_rounds);
			switch(key_length)
			{
			case 128:
				CM3_1T_AES128_encrypt_unrolled(rk, data_in, data_out);
				break;
			case 192:
				CM3_1T_AES192_encrypt_unrolled(rk, data_in, data_out);
				break;
			case 256:
				CM3_1T_AES256_encrypt_unrolled(rk, data_in, data_out);
				break;
			}
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			//CM3_1T_AES_decrypt_unrolled(rk, data_in, data_out, this->key_rounds);
			switch(key_length)
			{
			case 128:
				CM3_1T_AES128_decrypt_unrolled(rk, data_in, data_out);
				break;
			case 192:
				CM3_1T_AES192_decrypt_unrolled(rk, data_in, data_out);
				break;
			case 256:
				CM3_1T_AES256_decrypt_unrolled(rk, data_in, data_out);
				break;
			}
		}
	};

	template<size_t key_length>
	class CM3_1T_unrolled_deconly : public CM3_1T_unrolled<key_length>
	{
	public: // override only key expansions (encryption will take extra 256 bytes more than normally, if used)
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM3_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM3_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM3_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			CM3_1T_AES_keyschedule_dec_noTe(rk, this->key_rounds);
		}
	};

	template<size_t key_length>
	class CM4_DSPsBOX
	{
	public:
		void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
			switch(key_length)
			{
			case 128:
				CM3_sBOX_AES128_keyschedule_enc(rk, key);
				break;
			case 192:
				CM3_sBOX_AES192_keyschedule_enc(rk, key);
				break;
			case 256:
				CM3_sBOX_AES256_keyschedule_enc(rk, key);
				break;
			}
		}

		void key_schedule_dec(uint8_t* rk) {
			(void)rk; //nothing to expand, the addroundkey stage is its own inverse
		}

		void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM4_DSPsBOX_AES_encrypt(rk, data_in, data_out, this->key_rounds);
		}

		void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
			CM4_DSPsBOX_AES_decrypt(rk, data_in, data_out, this->key_rounds);
		}

	protected:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
	};

} //namespace target
} //namespace aes


#endif //AES_TARGET_CIPHER_IMPL_CM3CM4_HPP
