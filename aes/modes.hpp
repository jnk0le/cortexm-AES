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

#if __cplusplus >= 202302L
	#include <bit>
#endif

#include "cipher.hpp"
#include "target_modes/modes_impl.hpp"
#include "target_modes/ghash_impl.hpp"
#include "target_modes/gcm_impl.hpp"

namespace aes {
namespace mode {

	namespace aux {
	#if __cplusplus >= 202302L
		using std::byteswap;
	#else
		constexpr uint32_t byteswap(uint32_t value) {
			return __builtin_bswap32(value);
		}
		constexpr uint64_t byteswap(uint64_t value) {
			return __builtin_bswap64(value);
		}
	#endif
	}

	template<size_t key_length,
			template<size_t> class base_impl = aes::target::CM3_1T,
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
		 * \param data_out pointer to (append) output ciphertext, allocated area must be up to 16 bytes larger than input (for padding)
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
		 * \brief Decrypts and unpads the ciphertext data
		 * \warning This function was not protected/analyzed against padding oracle attacks
		 *
		 * Doesn't update the IV cache after execution
		 *
		 * \param data_in pointer to ciphertext to decrypt
		 * \param data_out pointer to (append) output plaintext, allocated area must equal to the input
		 * \param len length in bytes of ciphertext to decrypt, must be multiple of 16
		 * \return size of decrypted (appended) plaintext (stripped from padding), -1 if ciphertext is malformed
		 */

		int32_t decryptAppendFinalize(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			mode_impl<key_length, base_impl>::decrypt(data_in, data_out, iv, (len >> 4));

			uint32_t last_pad = data_out[len - 1];

			if(last_pad > 16)
				return -1;

			uint32_t padding_sum = 0;

			for(uint32_t i = (len - last_pad); i < len; i++) {
				padding_sum += data_out[i];
			}

			if(last_pad*last_pad != padding_sum)
				return -1;

			return (int)(len - last_pad);
		}

	private:
		uint32_t iv[4];
	};

	//SP 800-38A compliant, 32 bit counter
	template<size_t key_length,
			template<size_t> class base_impl = aes::target::CM3_1T,
			template<size_t key_len, template<size_t> class base> class mode_impl = aes::mode::target::CTR32_GENERIC>
	class CTR32
	{
	public:
		CTR32() {}
		~CTR32() {}

		void setNonce(void* n_nonce, size_t len = 12) {
			memcpy(this->nonce, n_nonce, len);
		}

		void setNonce(uint32_t nonce0, uint32_t nonce1, uint32_t nonce2, uint32_t nonce3 = 0) {
			this->nonce[0] = nonce0;
			this->nonce[1] = nonce1;
			this->nonce[2] = nonce2;
			this->nonce[3] = nonce3;
		}

		void setNonce(uint32_t nonce0) {
			this->nonce[0] = nonce0;
		}

		void setNonceCtr(void* ctr) {
			nonce[3] = (uint32_t)ctr;
		}

		void setNonceCtr(uint32_t ctr) {
			nonce[3] = ctr;
		}

		void setEncKey(const uint8_t* key) {
			ctx.setEncKey(key);
		}

		uint32_t* getNoncePtr() {
			return nonce;
		}

		void encrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			uint32_t block_len = len >> 4; // div by 16

			ctx.encrypt(data_in, data_out, this->nonce, block_len);

			uint32_t bytes_remaining = len & 15;

			//handle the truncation aka padding
			if(bytes_remaining) {
				uint8_t tmp[16]; // uninitialized part will go through encryption but won't be sent out.

				memcpy(tmp, &data_in[len - bytes_remaining], bytes_remaining);
				ctx.encrypt(tmp, tmp, this->nonce, 1); // finish with same function
				memcpy(&data_out[len - bytes_remaining], tmp, bytes_remaining);
			}
		}

		void decrypt(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			encrypt(data_in, data_out, len);
		}

		void encryptByExposedBase(const uint8_t* data_in, uint8_t* data_out) {
			ctx.encryptByExposedBase(data_in, data_out);
		}

	private:
		uint32_t nonce[4]; // nonce must be placed before expanded key
		mode_impl<key_length, base_impl> ctx;
	};


	//designed for typical TLS usage where "internal" CTR is not continued throughout session

	//SP 800-38D compliant
	template<size_t key_length,
			template<size_t> class base_impl = aes::target::CM3_1T,
			template<size_t key_len, template<size_t> class base> class ctr_mode_impl = aes::mode::target::CTR32_GENERIC,
			class ghash_impl = aes::mode::target::gcm::GHASH_GENERIC_BEAR_CT32>
	class GCM
	{
	public:
		GCM() {}
		~GCM() {}

		/*!
		 * \brief expands the key, precomputes H and resets counters
		 *
		 * to begin TLS encryption, after this, you only need to set iv (+ sequence number)
		 *
		 * \param[in] key pointer to the key to expand
		 */
		void setEncKey(const uint8_t* key) {
			ctr_ctx.setEncKey(key);

			memset(partial_tag_cache, 0, 16); // recycle for H
			ctr_ctx.encryptByExposedBase(partial_tag_cache, partial_tag_cache); // H
			g_ctx.setH(partial_tag_cache);

			// prepare for first encryption
			reinitInternalState();
		}

		/*!
		 * \brief sets the iv
		 *
		 * \warning only 12 byte iv's are supported
		 *
		 * \param[in] iv pointer to new iv
		 * \param len length in bytes of iv to copy, typical values are 4 and 12
		 */
		void setIv(void* iv, size_t len = 12) {
			ctr_ctx.setNonce(iv, len);
		}

		/*!
		 * \brief sets first word of iv, sequence number must be set separately
		 *
		 * \param iv0 first word of iv, endianess is not swapped
		 */
		void setIv(uint32_t iv0) {
			ctr_ctx.setNonce(iv0);
		}

		/*!
		 * \brief sets 12 byte gcm iv
		 *
		 * \param iv0 first word of iv, endianess is not swapped
		 * \param iv1 second word of iv, endianess is not swapped
		 * \param iv2 third word of iv, endianess is not swapped
		 */
		void setIv(uint32_t iv0, uint32_t iv1, uint32_t iv2) {
			ctr_ctx.setNonce(iv0, iv1, iv2);
		}

		/*!
		 * \brief sets new TLS sequence number
		 *
		 * It's not recommended to use fully random sequence numbers (in TLS 1.2) due to birthday paradox.
		 * Instead you can use a counter (initialized with random data). Endianess doesn't matter
		 * (as per the TLS 1.2) as long as it's kept consistent with the sequence fields in transmitted packets.
		 *
		 * \param[in] seq sequence to be written into nonce
		 */
		void setTlsSeq(const uint8_t* seq) {
			uint32_t* nonce = ctr_ctx.getNoncePtr();
			memcpy(&nonce[1], seq, 8);
		}

		/*!
		 * \brief sets new TLS sequence number
		 *
		 * It's not recommended to use fully random sequence numbers (in TLS 1.2) due to birthday paradox.
		 * Instead you can use a counter (initialized with random data). Endianess doesn't matter
		 * (as per the TLS 1.2) as long as it's kept consistent with the sequence fields in transmitted records.
		 *
		 * \param seq sequence to be written into nonce, endianess is not swapped
		 */
		void setTlsSeq(uint64_t seq) {
			uint32_t* nonce = ctr_ctx.getNoncePtr();
			*reinterpret_cast<uint64_t*>(&nonce[1]) = seq;
		}

		/*!
		 * \brief increments TLS 1.3 sequence number, it is capable of only incrementing by one
		 *
		 * A new sequence number is assumed to be 1 more than the previous one as per the TLS 1.3
		 *
		 * \param new_seq_cnt new sequence number to be xored into nonce, must be in machine native endianess (little endian)
		 */
		void incTlsSeq(uint64_t new_seq_cnt) {
			uint64_t prev_seq_cnt = new_seq_cnt - 1;

			uint32_t* nonce = ctr_ctx.getNoncePtr();

			// need to unxor previous seq number
			*reinterpret_cast<uint64_t*>(&nonce[1]) ^= aux::byteswap(prev_seq_cnt ^ new_seq_cnt);
		}

		/*!
		 * \brief hashes in additional authenication data, must be called befor encryption
		 *
		 * allows streaming type of operation, all but last block must be in multiplies of 16
		 *
		 * \param[in] aad_in pointer to additional auth data
		 * \param len length of additional auth data
		 */
		void aadAppend(const uint8_t* aad_in, uint32_t len) {
			len_A += len*8; // counting bits
			ghashData(aad_in, len);
		}

		/*!
		 * \brief encrypts the plaintext and hashes in for authentication
		 *
		 * allows streaming type of operation, all but last block must be in multiplies of 16
		 *
		 * \param[in] data_in plaintext to encrypt
		 * \param[out] data_out encrypted ciphertext
		 * \param len length in bytes of data to encrypt
		 */
		void encryptAppend(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			len_C += len*8; // counting bits
			ctr_ctx.encrypt(data_in, data_out, len);
			ghashData(data_out, len);
		}

		/*!
		 * \brief decrypts the ciphertext and hashes in for authentication
		 *
		 * allows streaming type of operation, all but last block must be in multiplies of 16
		 *
		 * \warning the tag must be verified before decrypted data is consumed
		 *
		 * \param[in] data_in ciphertext to decrypt
		 * \param[out] data_out decrypted plaintext
		 * \param len length in bytes of data to decrypt
		 */
		void decryptAppend(const uint8_t* data_in, uint8_t* data_out, uint32_t len) {
			ghashData(data_in, len);

			len_C += len*8; // counting bits
			ctr_ctx.encrypt(data_in, data_out, len);
		}

		/*!
		 * \brief generates GCM tag
		 *
		 * \param[out] tag pointer to write the tag
		 */
		void finalizeTagLast(uint8_t* tag) {
			uint8_t lenAC[16];

			*reinterpret_cast<uint64_t*>(&lenAC[0]) = aux::byteswap(len_A);
			*reinterpret_cast<uint64_t*>(&lenAC[8]) = aux::byteswap(len_C);

			g_ctx.gmulH(lenAC, partial_tag_cache, 1);

			// handle "counter 0" aka J0 aka HF, recycle partial_tag_cache for output
			ctr_ctx.setNonceCtr(aux::byteswap((uint32_t)1));

			ctr_ctx.encryptByExposedBase((uint8_t*)ctr_ctx.getNoncePtr(), partial_tag_cache);
			// "counter 1" is set later

			uint32_t* tag32 = reinterpret_cast<uint32_t*>(tag);
			uint32_t* partial_tag_cache32 = reinterpret_cast<uint32_t*>(partial_tag_cache);
			uint32_t* lenAC32 = reinterpret_cast<uint32_t*>(lenAC);

			tag32[0] = partial_tag_cache32[0] ^ lenAC32[0];
			tag32[1] = partial_tag_cache32[1] ^ lenAC32[1];
			tag32[2] = partial_tag_cache32[2] ^ lenAC32[2];
			tag32[3] = partial_tag_cache32[3] ^ lenAC32[3];
		}

		/*!
		 * \brief generates GCM tag and prepares for new encryption
		 *
		 * \warning in order to continue TLS encryption under the same key, the sequence field must be changed
		 *
		 * \param[out] tag pointer to write the tag
		 */
		void finalizeTag(uint8_t* tag) {
			finalizeTagLast(tag);
			reinitInternalState();
		}

		/*!
		 * \brief generates GCM tag and prepares for new encryption
		 *
		 * use when tag is trimmed/truncated, otherwise it costs additional memcpy
		 *
		 * \warning in order to continue encryption under the same key, the sequence field must be changed
		 *
		 * \param[out] tag pointer to write the tag
		 * \param len length of the tag to generate, allows non standard lengths
		 */
		void finalizeTagLast(uint8_t* tag, uint32_t len) {
			uint8_t full_tag[16];
			finalizeTagLast(full_tag);

			memcpy(tag, full_tag, len); // output tag
		}

		/*!
		 * \brief generates GCM tag and prepares for new encryption
		 *
		 * use when tag is trimmed/truncated, otherwise it costs additional memcpy
		 *
		 * \warning in order to continue TLS encryption under the same key, the sequence field must be changed
		 *
		 * \param[out] tag pointer to write the tag
		 * \param len length of the tag to generate, allows non standard lengths
		 */
		void finalizeTag(uint8_t* tag, uint32_t len) {
			finalizeTagLast(tag, len);
			reinitInternalState();
		}

		/*!
		 * \brief verifies provided tag against internal state
		 *
		 * \param[in] tag to verify
		 * \return true if tag was validated correctly
		 */
		bool verifyTagLast(uint8_t* tag) {
			uint8_t internal_tag[16];

			finalizeTagLast(internal_tag);

			uint32_t* internal_tag32 = reinterpret_cast<uint32_t*>(internal_tag);
			uint32_t* tag32 = reinterpret_cast<uint32_t*>(tag);

			uint32_t tag_diff = internal_tag32[0] ^ tag32[0];
			tag_diff |= internal_tag32[1] ^ tag32[1];
			tag_diff |= internal_tag32[2] ^ tag32[2];
			tag_diff |= internal_tag32[3] ^ tag32[3];

			if(tag_diff != 0)
				return false;
			else
				return true;
		}

		/*!
		 * \brief verifies provided tag and prepares for new encryption
		 *
		 * \param[in] tag to verify
		 * \return true if tag was validated correctly
		 */
		bool verifyTag(uint8_t* tag) {
			bool ret = verifyTagLast(tag);
			reinitInternalState();

			return ret;
		}

		/*!
		 * \brief verifies provided tag against internal state
		 *
		 * \param[in] tag to verify
		 * \param len tag length
		 * \return true if tag was validated correctly
		 */
		bool verifyTagLast(uint8_t* tag, uint32_t len) {
			uint8_t internal_tag[16];

			finalizeTagLast(internal_tag);
			memset(&internal_tag[len], 0, (16-len));

			uint8_t external_tag[16];
			memcpy(external_tag, tag, len);
			memset(external_tag, 0, (16-len));

			uint32_t* internal_tag32 = reinterpret_cast<uint32_t*>(internal_tag);
			uint32_t* external_tag32 = reinterpret_cast<uint32_t*>(external_tag);

			uint32_t tag_diff = internal_tag32[0] ^ external_tag32[0];
			tag_diff |= internal_tag32[1] ^ external_tag32[1];
			tag_diff |= internal_tag32[2] ^ external_tag32[2];
			tag_diff |= internal_tag32[3] ^ external_tag32[3];

			if(tag_diff != 0)
				return false;
			else
				return true;
		}

		/*!
		 * \brief verifies provided tag and prepares for new encryption
		 *
		 * \param[in] tag to verify
		 * \param len tag length
		 * \return true if tag was validated correctly
		 */
		bool verifyTag(uint8_t* tag, uint32_t len) {
			bool ret = verifyTagLast(tag, len);
			reinitInternalState();

			return ret;
		}

	private:
		void reinitInternalState() {
			len_A = 0;
			len_C = 0;

			memset(partial_tag_cache, 0, 16);

			ctr_ctx.setNonceCtr(aux::byteswap((uint32_t)2)); // set to "counter 1"
		}

		void ghashData(const uint8_t* data_in, uint32_t len) {
			uint32_t block_len = len >> 4; // div by 16
			uint32_t bytes_remaining = len & 15;

			g_ctx.gmulH(partial_tag_cache, data_in, block_len);

			if(bytes_remaining) {
				uint8_t tmp[16];

				memcpy(tmp, &data_in[len - bytes_remaining], bytes_remaining);
				memset(&tmp[bytes_remaining], 0, (16-bytes_remaining));
				g_ctx.gmulH(partial_tag_cache, tmp, 1);
			}
		}

		uint8_t partial_tag_cache[16];

		uint64_t len_A;
		uint64_t len_C;

		CTR32<key_length, base_impl, ctr_mode_impl> ctr_ctx;
		ghash_impl g_ctx;
	};



	/*template<size_t key_length,
			template<size_t> class base_impl = aes::target::CM3_1T,
			template<size_t key_len, template<size_t> class base> class gcm_impl = aes::mode::target::GCM_CM3_FUSED_SHOUP_M4>
	class GCM_FUSED
	{
	public:
		GCM_FUSED() {}
		~GCM_FUSED() {}

	private:
		gcm_impl<key_length, base_impl> gcm_ctx;
	};*/

}
}

#endif //AES_MODES_HPP
