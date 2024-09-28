/*!
 * \file aes_modes.hpp
 * \brief block mode implementations
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_MODES_HPP
#define AES_MODES_HPP

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cipher.hpp"
#include "target_modes/modes_impl.hpp"

namespace aes
{
namespace mode
{
	template<size_t key_length, template<size_t> class base_impl = aes::target::CM3_1T,
			template<size_t key_len, template<size_t> class base> class mode_impl = aes::mode::target::CBC_GENERIC>
	class CBC_PKCS7 : private mode_impl<key_length, base_impl>
	{
	public:
		CBC_PKCS7() {}
		~CBC_PKCS7() {}

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

		/*!
		 * \brief Encrypts the plaintext data
		 *
		 * Updates the IV cache after execution.
		 * Can be used to achieve unpadded CBC mode.
		 *
		 * \param data_in pointer to palaintext to encrypt
		 * \param data_out pointer to (append) output ciphertext, allocated area must equal to the input
		 * \param len length in bytes of plaintext to encrypt, must be multiple of 16
		 */

		void encryptAppend(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			this->setIv(mode_impl<key_length, base_impl>::encrypt(data_in, data_out, iv, len/16));
		}

		/*!
		 * \brief Encrypts and pads the plaintext data
		 *
		 * Doesn't update the IV cache after execution
		 *
		 * \param data_in pointer to palaintext to encrypt, it is not read past the specified length
		 * \param data_out pointer to (append) output ciphertext, allocated area must be 16 bytes larger than input
		 * \param len length in bytes of plaintext to encrypt
		 * \return size of encrypted (appended) ciphertext including padding, in bytes
		 */

		uint32_t encryptAppendFinalize(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			uint8_t tmp[16]; // last block

			uint32_t initial_block_len = len >> 4; // div by 16, will truncate last block if not multiple of 16 bytes
			uint32_t last_block_len = len & 15;
			uint32_t pkcs_padding_cnt = 16 - last_block_len;

			this->setIv(mode_impl<key_length, base_impl>::encrypt(data_in, data_out, iv, initial_block_len));

			memcpy(tmp, &data_in[len - last_block_len], last_block_len);

			for(uint32_t i = last_block_len; i < 16; i++) {
				tmp[i] = (uint8_t)pkcs_padding_cnt; // padding
			}

			mode_impl<key_length, base_impl>::encrypt(tmp, &data_out[initial_block_len*16], iv, 1);

			return (initial_block_len * 16) + 16;
		}

		/*!
		 * \brief Decrypts the ciphertext data
		 *
		 * Updates the IV cache after execution.
		 * Can be used to achieve unpadded CBC mode.
		 *
		 * \param data_in pointer to ciphertext to decrypt
		 * \param data_out pointer to (append) output plaintext, allocated area must equal to the input
		 * \param len length in bytes of ciphertext to decrypt, must be multiple of 16
		 */

		void decryptAppend(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			this->setIv(mode_impl<key_length, base_impl>::decrypt(data_in, data_out, iv, (len+15)/16));
		}

		/*!
		 * \brief Decryptss and unpads the ciphertext data
		 * \warning This functio  is not protected against padding oracle attack
		 *
		 * Doesn't update the IV cache after execution
		 *
		 * \param data_in pointer to ciphertext to decrypt
		 * \param data_out pointer to (append) output plaintext, allocated area must equal to the input
		 * \param len length in bytes of ciphertext to decrypt, must be multiple of 16
		 * \return size of decrypted (appended) plaintext (stripped from padding), 0 if message is malformed
		 */

		uint32_t decryptAppendFinalize(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			mode_impl<key_length, base_impl>::decrypt(data_in, data_out, iv, (len >> 4));

			uint32_t last_pad = data_out[len - 1];

			if(last_pad > 16)
				return 0;

			uint32_t padding_sum = 0;

			for(uint32_t i = (len - last_pad); i < len; i++) {
				padding_sum += data_out[i];
			}

			if(last_pad*last_pad != padding_sum)
				return 0;

			return len - last_pad;
		}

	private:
		uint32_t iv[4];
	};

	namespace ctr // workaround
	{
		class Nonce
		{
		public:
			uint32_t nonce[4];
		};
	}

	//SP 800-38A compliant, 32 bit counter
	template<size_t key_length, template<size_t> class base_impl = aes::target::CM3_1T, template<size_t key_len, template<size_t> class base> class mode_impl = aes::mode::target::CTR32_GENERIC>
	class CTR32 : protected ctr::Nonce, private mode_impl<key_length, base_impl> // put the nonce before rk, to be compatible with current implementations
	{
	public:
		CTR32() {}
		~CTR32() {}

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
			uint32_t block_len = len >> 4; // div by 16

			mode_impl<key_length, base_impl>::encrypt(data_in, data_out, this->nonce, block_len);

			uint32_t bytes_remaining = len & 15;

			//handle the truncation aka padding
			if(bytes_remaining) {
				uint8_t tmp[16]; // uninitialized part will go through encryption but won't be sent out.

				memcpy(tmp, &data_in[len - bytes_remaining], bytes_remaining);
				mode_impl<key_length, base_impl>::encrypt(tmp, tmp, this->nonce, 1); // finish with same function
				memcpy(&data_out[len - bytes_remaining], tmp, bytes_remaining);
			}
		}

		void decrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			encrypt(data_in, data_out, len);
		}

	private:
		//uint32_t nonce[4];
	};

}
}

#endif //AES_MODES_HPP
