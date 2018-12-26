/*!
 * \file cipher_impl.hpp
 * \brief implementation wrappers of aes ciphers
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#ifndef AES_CIPHER_IMPL_HPP
#define AES_CIPHER_IMPL_HPP

#include "CM34.h"
#include "CM7.h"

namespace aes
{
namespace target
{

	//generic?

	template<size_t key_length>
		class CM34_1T
		{
		public:
			void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
				switch(key_length)
				{
				case 128:
					CM34_1T_AES_128_keyschedule_enc(rk, key);
					break;
				case 192:
					CM34_1T_AES_192_keyschedule_enc(rk, key);
					break;
				case 256:
					CM34_1T_AES_256_keyschedule_enc(rk, key);
					break;
				}
			}

			void key_schedule_dec(uint8_t* rk) {
				CM34_1T_AES_keyschedule_dec(rk, this->key_rounds);
			}

			void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				CM34_1T_AES_encrypt(rk, data_in, data_out, this->key_rounds);
			}

			void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				CM34_1T_AES_decrypt(rk, data_in, data_out, this->key_rounds);
			}

		protected:
			static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);
		};

	template<size_t key_length>
		class CM34_1T_dense : public CM34_1T<key_length>
		{
		public:
			void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				CM34_1T_AES_encrypt_d(rk, data_in, data_out, this->key_rounds);
			}

			void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				CM34_1T_AES_decrypt_d(rk, data_in, data_out, this->key_rounds);
			}
		};

	template<size_t key_length>
		class CM34_1T_unrolled : public CM34_1T<key_length>
		{
		public: // override only unrolled functions
			void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				//CM34_1T_AES_encrypt_unrolled(rk, data_in, data_out, this->key_rounds);
				switch(key_length)
				{
				case 128:
					CM34_1T_AES_128_encrypt_unrolled(rk, data_in, data_out);
					break;
				case 192:
					CM34_1T_AES_192_encrypt_unrolled(rk, data_in, data_out);
					break;
				case 256:
					CM34_1T_AES_256_encrypt_unrolled(rk, data_in, data_out);
					break;
				}
			}

			void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				//CM34_1T_AES_decrypt_unrolled(rk, data_in, data_out, this->key_rounds);
				switch(key_length)
				{
				case 128:
					CM34_1T_AES_128_decrypt_unrolled(rk, data_in, data_out);
					break;
				case 192:
					CM34_1T_AES_192_decrypt_unrolled(rk, data_in, data_out);
					break;
				case 256:
					CM34_1T_AES_256_decrypt_unrolled(rk, data_in, data_out);
					break;
				}
			}
		};

	template<size_t key_length>
		class CM7_1T
		{
		public:
			void key_schedule_enc(uint8_t* rk, const uint8_t* key) {
				switch(key_length)
				{
				case 128:
					CM7_1T_AES_128_keyschedule_enc(rk, key);
					break;
				case 192:
					CM7_1T_AES_192_keyschedule_enc(rk, key);
					break;
				case 256:
					CM7_1T_AES_256_keyschedule_enc(rk, key);
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
		class CM7_1T_unrolled : public CM7_1T<key_length>
		{
		public: // override only unrolled functions
			void encrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				//CM7_1T_AES_encrypt_unrolled(rk, data_in, data_out, this->key_rounds);
				switch(key_length)
				{
				case 128:
					CM7_1T_AES_128_encrypt_unrolled(rk, data_in, data_out);
					break;
				case 192:
					CM7_1T_AES_192_encrypt_unrolled(rk, data_in, data_out);
					break;
				case 256:
					CM7_1T_AES_256_encrypt_unrolled(rk, data_in, data_out);
					break;
				}

			}

			void decrypt(const uint8_t* rk, const uint8_t* data_in, uint8_t* data_out) {
				//CM7_1T_AES_decrypt_unrolled(rk, data_in, data_out, this->key_rounds);
				switch(key_length)
				{
				case 128:
					CM7_1T_AES_128_decrypt_unrolled(rk, data_in, data_out);
					break;
				case 192:
					CM7_1T_AES_192_decrypt_unrolled(rk, data_in, data_out);
					break;
				case 256:
					CM7_1T_AES_256_decrypt_unrolled(rk, data_in, data_out);
					break;
				}
			}
		};

} //namespace target
} //namespace aes


#endif //AES_CIPHER_IMPL_HPP
